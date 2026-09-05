//! Explicit, read-only uplink observation and first socket-interface binding.
//!
//! A live link plus a default route is not an end-to-end Internet reachability probe. The
//! operator declares which independently connected interface is permitted; this module never
//! substitutes another interface, alters routing, or enables an Exit role.

use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, getsockname,
        recvmsg, sendto, socket,
    },
};
use socket2::{Domain, SockRef};

const OBSERVATION_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_BYTES: usize = 1_048_576;
const MAX_FRAMES: usize = 4_096;
const MAX_DATAGRAM: usize = 65_536;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP_INTR: u16 = 16;
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Operator-selected, independently connected Exit uplink; construction never opens sockets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentEgress {
    interface: String,
}

/// Consistently observed link and main-table default-route availability, not Internet uptime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressObservation {
    /// Current exact interface index; a recreated interface is a different observation.
    pub ifindex: u32,
    /// A usable IPv4 address and unique IPv4 default exist on the selected interface.
    pub ipv4: bool,
    /// A usable IPv6 address and unique IPv6 default exist on the selected interface.
    pub ipv6: bool,
}

impl IndependentEgress {
    /// Validate one explicit interface name without performing I/O or granting participation.
    ///
    /// # Errors
    /// Rejects invalid, overlong, empty or loopback names.
    pub fn new(interface: &str) -> io::Result<Self> {
        if interface.is_empty()
            || interface.len() > 15
            || matches!(interface, "." | ".." | "lo")
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid egress interface",
            ));
        }
        Ok(Self {
            interface: interface.into(),
        })
    }

    /// Read two consistent bounded kernel snapshots, without sending network traffic.
    ///
    /// Returns `None` for an absent/down/non-independent interface or missing usable default.
    /// Physical links and explicitly named VLAN/bond/bridge/macvlan/ipvlan/veth links are
    /// supported. Tunnel, dummy, loopback and VOLPAROSSA-owned interfaces are not uplinks.
    ///
    /// # Errors
    /// Returns an error for malformed/ambiguous kernel facts, changed snapshots, exceeded
    /// message bounds or the shared 500-ms observation deadline.
    pub fn observe(&self) -> io::Result<Option<EgressObservation>> {
        let mut reader = Reader::new()?;
        let first = reader.snapshot(&self.interface)?;
        let second = reader.snapshot(&self.interface)?;
        if first != second {
            return Err(invalid("egress changed during observation"));
        }
        first.observation()
    }

    /// Bind a new, unconnected INET socket to this exact available interface before `connect`.
    ///
    /// A wildcard local UDP port may already be bound. Existing device bindings or connected
    /// sockets are refused. Linux 6.12 permits this first device bind without `CAP_NET_RAW`;
    /// changing an existing binding requires privilege and is deliberately not attempted.
    /// On failure the caller must close the socket; no unbound or alternate-interface fallback
    /// is allowed. Existing bound sockets remain pinned during subsequent uplink loss.
    ///
    /// # Errors
    /// Returns an error if the socket is ineligible, its family has no usable uplink, binding
    /// fails, or immediate readback no longer proves the same interface/availability.
    pub fn bind_new_socket<F: AsFd + ?Sized>(&self, socket: &F) -> io::Result<()> {
        let borrowed = socket.as_fd();
        let socket = SockRef::from(&borrowed);
        let family = socket.domain()?;
        if !matches!(family, Domain::IPV4 | Domain::IPV6)
            || socket.device()?.is_some()
            || socket.peer_addr().is_ok()
            || socket
                .local_addr()?
                .as_socket()
                .is_none_or(|address| !address.ip().is_unspecified())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "egress needs a new wildcard INET socket",
            ));
        }
        let before = self.observe()?.ok_or_else(unavailable)?;
        if !(if family == Domain::IPV4 {
            before.ipv4
        } else {
            before.ipv6
        }) {
            return Err(unavailable());
        }
        socket.bind_device(Some(self.interface.as_bytes()))?;
        if socket.device()?.as_deref() != Some(self.interface.as_bytes())
            || self.observe()? != Some(before)
        {
            return Err(invalid("egress binding changed during socket setup"));
        }
        Ok(())
    }
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "configured independent uplink unavailable",
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Link {
    ifindex: u32,
    flags: u32,
    kind: Option<String>,
    alias: Option<String>,
}

impl Link {
    fn usable(&self) -> bool {
        self.flags & 1 != 0 // IFF_UP
            && self.flags & 0x1_0000 != 0 // IFF_LOWER_UP: carrier, not merely administrative UP.
            && self.flags & 8 == 0 // IFF_LOOPBACK
            && !self.alias.as_deref().is_some_and(|alias| alias.starts_with("volparossa:"))
            && matches!(self.kind.as_deref(), None | Some("vlan" | "bond" | "bridge" | "macvlan" | "ipvlan" | "veth"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Snapshot {
    link: Option<Link>,
    addresses: Vec<IpAddr>,
    defaults: Vec<(u8, Option<IpAddr>, u32)>,
}

impl Snapshot {
    fn observation(&self) -> io::Result<Option<EgressObservation>> {
        let Some(link) = self.link.as_ref().filter(|link| link.usable()) else {
            return Ok(None);
        };
        let mut observation = EgressObservation {
            ifindex: link.ifindex,
            ipv4: false,
            ipv6: false,
        };
        for (family, usable) in [(2, &mut observation.ipv4), (10, &mut observation.ipv6)] {
            let count = self
                .defaults
                .iter()
                .filter(|route| route.0 == family)
                .count();
            if count > 1 {
                return Err(invalid("multiple default routes on configured egress"));
            }
            *usable = count == 1
                && self
                    .addresses
                    .iter()
                    .any(|ip| ip.is_ipv4() == (family == 2));
        }
        Ok((observation.ipv4 || observation.ipv6).then_some(observation))
    }
}

struct Reader {
    fd: OwnedFd,
    port: u32,
    sequence: u32,
    deadline: Instant,
    bytes: usize,
    frames: usize,
}

impl Reader {
    fn new() -> io::Result<Self> {
        let deadline = Instant::now() + OBSERVATION_TIMEOUT;
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkRoute,
        )?;
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
        let local: NetlinkAddr = getsockname(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            port: local.pid(),
            sequence: 0,
            deadline,
            bytes: 0,
            frames: 0,
        })
    }

    fn snapshot(&mut self, interface: &str) -> io::Result<Snapshot> {
        let mut snapshot = Snapshot::default();
        self.dump(18, 16, 16, |payload| {
            if let Some(link) = decode_link(payload, interface)? {
                if snapshot.link.replace(link).is_some() {
                    return Err(invalid("duplicate configured interface"));
                }
            }
            Ok(())
        })?;
        let Some(link) = &snapshot.link else {
            return Ok(snapshot);
        };
        if !link.usable() {
            return Ok(snapshot);
        }
        let ifindex = link.ifindex;
        self.dump(22, 20, 8, |payload| {
            if let Some(address) = decode_address(payload, ifindex)? {
                snapshot.addresses.push(address);
            }
            Ok(())
        })?;
        self.dump(26, 24, 12, |payload| {
            if let Some(route) = decode_default(payload, ifindex)? {
                snapshot.defaults.push(route);
            }
            Ok(())
        })?;
        snapshot.addresses.sort_unstable();
        snapshot.defaults.sort_unstable();
        Ok(snapshot)
    }

    fn dump(
        &mut self,
        request_type: u16,
        response_type: u16,
        payload_len: usize,
        mut consume: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.sequence += 1;
        let mut request = Vec::with_capacity(16 + payload_len);
        request.extend_from_slice(&u32::try_from(16 + payload_len).unwrap_or(0).to_ne_bytes());
        request.extend_from_slice(&request_type.to_ne_bytes());
        request.extend_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | ROOT | MATCH.
        request.extend_from_slice(&self.sequence.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes());
        request.resize(16 + payload_len, 0);
        if sendto(
            self.fd.as_raw_fd(),
            &request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::MSG_DONTWAIT,
        )? != request.len()
        {
            return Err(invalid("short egress dump request"));
        }
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "egress observation deadline")
                })?;
            let timeout = u16::try_from(remaining.as_millis().max(1)).unwrap_or(500);
            let mut polls = [PollFd::new(self.fd.as_fd(), PollFlags::POLLIN)];
            if poll(&mut polls, timeout)? == 0 {
                continue;
            }
            let mut slices = [IoSliceMut::new(&mut buffer)];
            let received = recvmsg::<NetlinkAddr>(
                self.fd.as_raw_fd(),
                &mut slices,
                None,
                MsgFlags::MSG_DONTWAIT,
            )?;
            if received.address != Some(NetlinkAddr::new(0, 0))
                || received
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                || received.bytes == 0
            {
                return Err(invalid("invalid egress dump sender or length"));
            }
            let length = received.bytes;
            self.bytes += length;
            if self.bytes > MAX_BYTES {
                return Err(invalid("egress dump byte limit"));
            }
            let mut input = &buffer[..length];
            while !input.is_empty() {
                self.frames += 1;
                if self.frames > MAX_FRAMES {
                    return Err(invalid("egress dump frame limit"));
                }
                let (kind, flags, payload, rest) = frame(input, self.sequence, self.port)?;
                input = rest;
                if flags & NLM_F_DUMP_INTR != 0 {
                    return Err(invalid("interrupted egress dump"));
                }
                match kind {
                    3 if input.is_empty() && flags == NLM_F_MULTI && payload == [0; 4] => {
                        return Ok(());
                    }
                    2 => return Err(invalid("kernel rejected egress dump")),
                    kind if kind == response_type && flags == NLM_F_MULTI => consume(payload)?,
                    _ => return Err(invalid("unexpected egress dump message")),
                }
            }
        }
    }
}

fn frame(input: &[u8], sequence: u32, port: u32) -> io::Result<(u16, u16, &[u8], &[u8])> {
    let length = usize::try_from(u32_at(input, 0)?).map_err(|_| invalid("message length"))?;
    let aligned = align4(length);
    if length < 16
        || aligned > input.len()
        || u32_at(input, 8)? != sequence
        || u32_at(input, 12)? != port
    {
        return Err(invalid("invalid egress dump header"));
    }
    Ok((
        u16_at(input, 4)?,
        u16_at(input, 6)?,
        &input[16..length],
        &input[aligned..],
    ))
}

fn attrs(mut input: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !input.is_empty() {
        let length = usize::from(u16_at(input, 0)?);
        let aligned = align4(length);
        if length < 4 || aligned > input.len() || result.len() >= 128 {
            return Err(invalid("invalid egress netlink attribute"));
        }
        result.push((u16_at(input, 2)? & NLA_TYPE_MASK, &input[4..length]));
        input = &input[aligned..];
    }
    Ok(result)
}

fn one<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> io::Result<Option<&'a [u8]>> {
    let mut matching = attributes.iter().filter(|attr| attr.0 == kind);
    let first = matching.next().map(|attr| attr.1);
    if matching.next().is_some() {
        return Err(invalid("duplicate egress netlink attribute"));
    }
    Ok(first)
}

fn decode_link(input: &[u8], interface: &str) -> io::Result<Option<Link>> {
    let attributes = attrs(input.get(16..).ok_or_else(|| invalid("short link"))?)?;
    let name = string(one(&attributes, 3)?.ok_or_else(|| invalid("missing interface name"))?)?;
    if name != interface {
        return Ok(None);
    }
    let ifindex = u32_at(input, 4)?;
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(invalid("invalid interface index"));
    }
    let kind = one(&attributes, 18)?
        .map(attrs)
        .transpose()?
        .map(|info| one(&info, 1)?.map(string).transpose())
        .transpose()?
        .flatten();
    Ok(Some(Link {
        ifindex,
        flags: u32_at(input, 8)?,
        kind,
        alias: one(&attributes, 20)?.map(string).transpose()?,
    }))
}

fn decode_address(input: &[u8], ifindex: u32) -> io::Result<Option<IpAddr>> {
    let attributes = attrs(input.get(8..).ok_or_else(|| invalid("short address"))?)?;
    if u32_at(input, 4)? != ifindex || !matches!(input[0], 2 | 10) {
        return Ok(None);
    }
    let flags = one(&attributes, 8)?
        .map(|value| u32_at(value, 0))
        .transpose()?
        .unwrap_or(u32::from(input[2]));
    if input[3] != 0 || flags & (0x08 | 0x20 | 0x40) != 0 {
        return Ok(None);
    }
    let raw = one(&attributes, 2)?
        .or(one(&attributes, 1)?)
        .ok_or_else(|| invalid("missing source address"))?;
    let address = ip(input[0], raw)?;
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(value) if value.is_link_local() || value.is_broadcast())
        || matches!(address, IpAddr::V6(value) if value.is_unicast_link_local())
    {
        return Ok(None);
    }
    Ok(Some(address))
}

fn decode_default(input: &[u8], ifindex: u32) -> io::Result<Option<(u8, Option<IpAddr>, u32)>> {
    let attributes = attrs(input.get(12..).ok_or_else(|| invalid("short route"))?)?;
    if !matches!(input[0], 2 | 10) || input[1] != 0 || input[2] != 0 {
        return Ok(None);
    }
    let table = one(&attributes, 15)?
        .map(|value| u32_at(value, 0))
        .transpose()?
        .unwrap_or(u32::from(input[4]));
    let output = one(&attributes, 4)?
        .map(|value| u32_at(value, 0))
        .transpose()?;
    if table != 254 || output != Some(ifindex) || input[6] != 0 || input[7] != 1 {
        return Ok(None);
    }
    if input[3] != 0
        || u32_at(input, 8)? != 0
        || one(&attributes, 9)?.is_some()
        || one(&attributes, 30)?.is_some()
        || one(&attributes, 18)?.is_some()
    {
        return Err(invalid("unsupported egress default route"));
    }
    let gateway = one(&attributes, 5)?
        .map(|value| ip(input[0], value))
        .transpose()?;
    if gateway.is_some_and(|ip| ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()) {
        return Err(invalid("invalid egress gateway"));
    }
    let metric = one(&attributes, 6)?
        .map(|value| u32_at(value, 0))
        .transpose()?
        .unwrap_or(0);
    Ok(Some((input[0], gateway, metric)))
}

fn ip(family: u8, input: &[u8]) -> io::Result<IpAddr> {
    match family {
        2 => Ok(
            Ipv4Addr::from(<[u8; 4]>::try_from(input).map_err(|_| invalid("IPv4 length"))?).into(),
        ),
        10 => Ok(
            Ipv6Addr::from(<[u8; 16]>::try_from(input).map_err(|_| invalid("IPv6 length"))?).into(),
        ),
        _ => Err(invalid("unsupported address family")),
    }
}

fn string(input: &[u8]) -> io::Result<String> {
    let Some(value) = input.strip_suffix(&[0]) else {
        return Err(invalid("unterminated netlink string"));
    };
    if value.contains(&0) || value.len() > 256 {
        return Err(invalid("invalid netlink string"));
    }
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| invalid("non-UTF8 netlink string"))
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}
fn u16_at(input: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        input
            .get(at..at + 2)
            .ok_or_else(|| invalid("short u16"))?
            .try_into()
            .map_err(|_| invalid("u16"))?,
    ))
}
fn u32_at(input: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        input
            .get(at..at + 4)
            .ok_or_else(|| invalid("short u32"))?
            .try_into()
            .map_err(|_| invalid("u32"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut output = u16::try_from(value.len() + 4)
            .unwrap()
            .to_ne_bytes()
            .to_vec();
        output.extend_from_slice(&kind.to_ne_bytes());
        output.extend_from_slice(value);
        output.resize(align4(output.len()), 0);
        output
    }

    #[test]
    fn egress_parser_observes_real_family_encodings_and_rejects_overlay() {
        let mut link = vec![0_u8; 16];
        link[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        link[8..12].copy_from_slice(&0x1_0001_u32.to_ne_bytes());
        link.extend(attribute(3, b"wan0\0"));
        link.extend(attribute(18, &attribute(1, b"veth\0")));
        let mut snapshot = Snapshot {
            link: decode_link(&link, "wan0").unwrap(),
            ..Snapshot::default()
        };
        for (family, address, gateway) in [
            (
                2,
                "192.168.50.2".parse::<IpAddr>().unwrap(),
                "192.168.50.1".parse::<IpAddr>().unwrap(),
            ),
            (10, "fd50::2".parse().unwrap(), "fe80::1".parse().unwrap()),
        ] {
            let raw = |ip| match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut addr = vec![family, 24, 0x80, 0];
            addr.extend(7_u32.to_ne_bytes());
            addr.extend(attribute(1, &raw(address)));
            snapshot
                .addresses
                .push(decode_address(&addr, 7).unwrap().unwrap());
            let mut route = vec![family, 0, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0];
            route.extend(attribute(4, &7_u32.to_ne_bytes()));
            route.extend(attribute(5, &raw(gateway)));
            snapshot
                .defaults
                .push(decode_default(&route, 7).unwrap().unwrap());
        }
        assert_eq!(
            snapshot.observation().unwrap(),
            Some(EgressObservation {
                ifindex: 7,
                ipv4: true,
                ipv6: true
            })
        );
        for kind in ["wireguard", "tun", "dummy", "vxlan", "gre", "vrf"] {
            let mut overlay = snapshot.clone();
            overlay.link.as_mut().unwrap().kind = Some(kind.into());
            assert_eq!(overlay.observation().unwrap(), None);
        }
        let mut owned = snapshot.clone();
        owned.link.as_mut().unwrap().alias = Some("volparossa:wireguard:ownership-v1:test".into());
        assert_eq!(owned.observation().unwrap(), None);
        let mut down = snapshot.clone();
        down.link.as_mut().unwrap().flags = 1;
        assert_eq!(down.observation().unwrap(), None);
        let mut ambiguous = snapshot;
        ambiguous.defaults.push(ambiguous.defaults[0]);
        assert!(ambiguous.observation().is_err());
    }

    #[test]
    fn egress_rejects_names_and_malformed_netlink_without_io() {
        for name in ["", "lo", ".", "..", "../eth0", "eth 0", "1234567890123456"] {
            assert!(IndependentEgress::new(name).is_err());
        }
        assert!(IndependentEgress::new("enp3s0.10").is_ok());
        for length in 0..16 {
            assert!(decode_link(&vec![0; length], "wan0").is_err());
            assert!(frame(&vec![0; length], 1, 1).is_err());
        }
        assert!(attrs(&[3, 0, 1, 0]).is_err());
        assert!(one(&[(3, b"a".as_slice()), (3, b"b")], 3).is_err());
    }

    #[test]
    fn egress_disposable_link_loss_return_and_capless_first_bind() {
        const STAGE: &str = "VOLPAROSSA_EGRESS_NETNS_STAGE";
        const TEST: &str =
            "egress::tests::egress_disposable_link_loss_return_and_capless_first_bind";
        let stage = std::env::var(STAGE).unwrap_or_default();
        if stage.is_empty() {
            eprintln!(
                "Independent egress smoke: create a disposable user+network namespace, two veth pairs and two default routes; bind sockets, take only wan0 down/up, then namespace teardown. No host network changes."
            );
            let routes = std::fs::read("/proc/net/route").unwrap();
            let dns = std::fs::read("/etc/resolv.conf").unwrap();
            let status = Command::new("/usr/bin/unshare")
                .args(["--user", "--map-root-user", "--net", "--fork"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(STAGE, "setup")
                .env(
                    "VOLPAROSSA_EGRESS_PARENT_NETNS",
                    std::fs::read_link("/proc/self/ns/net").unwrap(),
                )
                .status()
                .unwrap();
            assert_eq!(std::fs::read("/proc/net/route").unwrap(), routes);
            assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), dns);
            assert!(
                status.success(),
                "disposable egress smoke must run, not skip"
            );
            return;
        }
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(std::env::var_os("VOLPAROSSA_EGRESS_PARENT_NETNS").unwrap())
        );
        let egress = IndependentEgress::new("wan0").unwrap();
        if stage == "capless" {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            assert!(
                status
                    .lines()
                    .any(|line| line == "CapEff:\t0000000000000000")
            );
            let socket = socket2::Socket::new(Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
            egress
                .bind_new_socket(&socket)
                .expect("first device binding needs no capabilities");
            assert_eq!(
                socket.device().unwrap().as_deref(),
                Some(b"wan0".as_slice())
            );
            assert!(
                egress.bind_new_socket(&socket).is_err(),
                "never rebind an existing socket"
            );
            return;
        }
        assert_eq!(stage, "setup");
        let ip = |args: &[&str]| {
            let result = Command::new("/usr/sbin/ip").args(args).output().unwrap();
            assert!(
                result.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        ip(&["link", "set", "lo", "up"]);
        for (uplink, peer, source, gateway, metric) in [
            ("wan0", "peer0", "192.0.2.2/24", "192.0.2.1", "100"),
            (
                "fallback0",
                "peer1",
                "198.51.100.2/24",
                "198.51.100.1",
                "200",
            ),
        ] {
            ip(&["link", "add", uplink, "type", "veth", "peer", "name", peer]);
            ip(&["link", "set", uplink, "up"]);
            ip(&["link", "set", peer, "up"]);
            ip(&["address", "add", source, "dev", uplink]);
            ip(&[
                "route", "add", "default", "via", gateway, "dev", uplink, "metric", metric,
            ]);
        }
        let before = egress
            .observe()
            .unwrap()
            .expect("selected independent default");
        assert!(before.ipv4 && !before.ipv6);
        let capless = Command::new("/usr/bin/setpriv")
            .args([
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(STAGE, "capless")
            .status()
            .unwrap();
        assert!(capless.success());
        let pinned = socket2::Socket::new(Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        egress.bind_new_socket(&pinned).unwrap();
        ip(&["link", "set", "wan0", "down"]);
        assert_eq!(egress.observe().unwrap(), None);
        assert!(
            IndependentEgress::new("fallback0")
                .unwrap()
                .observe()
                .unwrap()
                .is_some()
        );
        let rejected = socket2::Socket::new(Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        assert!(egress.bind_new_socket(&rejected).is_err());
        assert_eq!(rejected.device().unwrap(), None);
        assert_eq!(
            pinned.device().unwrap().as_deref(),
            Some(b"wan0".as_slice())
        );
        ip(&["link", "set", "wan0", "up"]);
        // Bringing a device administratively down removes its gateway route. Recreate the
        // actual uplink route as the link manager would; link state alone is insufficient.
        ip(&[
            "route",
            "replace",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "wan0",
            "metric",
            "100",
        ]);
        assert_eq!(egress.observe().unwrap(), Some(before));
        let restored = socket2::Socket::new(Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        egress.bind_new_socket(&restored).unwrap();
        ip(&[
            "route",
            "del",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "wan0",
            "metric",
            "100",
        ]);
        assert_eq!(
            egress.observe().unwrap(),
            None,
            "an alternative default is never substituted"
        );
        ip(&["link", "add", "fake0", "type", "dummy"]);
        ip(&["link", "set", "fake0", "up"]);
        ip(&["address", "add", "203.0.113.2/24", "dev", "fake0"]);
        ip(&["route", "add", "default", "dev", "fake0", "metric", "300"]);
        assert_eq!(
            IndependentEgress::new("fake0").unwrap().observe().unwrap(),
            None
        );
    }
}
