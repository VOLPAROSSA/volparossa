//! Bounded, read-only `NETLINK_ROUTE` snapshot collection.
//!
//! The production functional-alpha backend uses this collector before its single Client-lease
//! Prepare transaction. The collector cannot activate routes, links, addresses, DNS or firewall
//! state.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::poll::PollFlags;
use thiserror::Error;
use volparossa_routing::is_public_routable_ip;

use crate::deadline::{HardDeadline, wait_for_fd};

use super::{
    UnderlayAddress, UnderlayCandidate, UnderlayFamily, UnderlayLink, UnderlayRoute,
    UnderlaySelectionError, select_direct_underlay,
};

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_FRAMES: usize = 8 * 1024;

const NLMSG_HEADER_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const IFADDR_LEN: usize = 8;
const RTMSG_LEN: usize = 12;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const IFLA_IFNAME: u16 = 3;
const IFLA_IFALIAS: u16 = 20;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;
const IFA_ANYCAST: u16 = 5;
const IFA_MULTICAST: u16 = 7;
const IFA_FLAGS: u16 = 8;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;
const RTA_PREF: u16 = 20;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_PAD: u16 = 24;
const RTA_UID: u16 = 25;
const RTA_TTL_PROPAGATE: u16 = 26;
const RTA_IP_PROTO: u16 = 27;
const RTA_SPORT: u16 = 28;
const RTA_DPORT: u16 = 29;
const RTA_NH_ID: u16 = 30;

const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u32 = 254;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

const HELPER_ALIAS_PREFIX: &[u8] = b"volparossa:";
const HELPER_OWNERSHIP_V1_ALIAS_PREFIX: &[u8] = b"volparossa:wireguard:ownership-v1:";
const OWNERSHIP_DIGEST_HEX_BYTES: usize = 64;
const MAX_IFALIAS_BYTES: usize = 255;

/// A fixed, non-sensitive failure produced by the read-only collector.
#[derive(Debug, Error)]
pub(crate) enum UnderlayNetlinkError {
    /// The netlink socket or bounded wait failed.
    #[error("underlay netlink I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a dump request.
    #[error("underlay netlink dump was rejected")]
    Kernel(i32),
    /// A response was truncated, malformed or ambiguous.
    #[error("underlay netlink response was malformed or ambiguous")]
    Malformed,
    /// A response exceeded a fixed byte or frame bound.
    #[error("underlay netlink response exceeded its fixed bound")]
    Limit,
    /// Two consecutive snapshots differed.
    #[error("underlay netlink snapshot changed during collection")]
    Inconsistent,
    /// No safe direct underlay exists.
    #[error("no safe direct underlay candidate exists")]
    NoCandidate,
    /// More than one safe direct underlay exists.
    #[error("direct underlay selection is ambiguous")]
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DumpKind {
    Link,
    Address,
    Route,
}

impl DumpKind {
    const fn request_type(self) -> u16 {
        match self {
            Self::Link => RTM_GETLINK,
            Self::Address => RTM_GETADDR,
            Self::Route => RTM_GETROUTE,
        }
    }

    const fn response_type(self) -> u16 {
        match self {
            Self::Link => RTM_NEWLINK,
            Self::Address => RTM_NEWADDR,
            Self::Route => RTM_NEWROUTE,
        }
    }

    fn request_payload(self) -> Vec<u8> {
        match self {
            Self::Link => vec![0; IFINFO_LEN],
            Self::Address => vec![0; IFADDR_LEN],
            Self::Route => vec![0; RTMSG_LEN],
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct UnderlaySnapshot {
    links: Vec<UnderlayLink>,
    addresses: Vec<UnderlayAddress>,
    routes: Vec<UnderlayRoute>,
}

impl UnderlaySnapshot {
    fn canonicalize(&mut self) -> Result<(), UnderlayNetlinkError> {
        self.links.sort_unstable();
        self.addresses.sort_unstable();
        self.routes.sort_unstable();
        if self
            .links
            .windows(2)
            .any(|pair| pair[0].ifindex == pair[1].ifindex)
            || self.addresses.windows(2).any(|pair| {
                pair[0].ifindex == pair[1].ifindex && pair[0].address == pair[1].address
            })
            || self.routes.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(UnderlayNetlinkError::Malformed);
        }
        Ok(())
    }
}

struct CollectionBudget {
    bytes: usize,
    frames: usize,
    max_bytes: usize,
    max_frames: usize,
}

impl CollectionBudget {
    const fn production() -> Self {
        Self {
            bytes: 0,
            frames: 0,
            max_bytes: MAX_TOTAL_BYTES,
            max_frames: MAX_TOTAL_FRAMES,
        }
    }

    fn can_receive(&self, length: usize) -> Result<(), UnderlayNetlinkError> {
        if !(NLMSG_HEADER_LEN..=MAX_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(UnderlayNetlinkError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), UnderlayNetlinkError> {
        self.can_receive(length)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or(UnderlayNetlinkError::Limit)?;
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), UnderlayNetlinkError> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(UnderlayNetlinkError::Limit)?;
        if self.frames > self.max_frames {
            return Err(UnderlayNetlinkError::Limit);
        }
        Ok(())
    }
}

struct DumpState {
    kind: DumpKind,
    sequence: u32,
    done: bool,
    snapshot: UnderlaySnapshot,
}

impl DumpState {
    fn new(kind: DumpKind, sequence: u32) -> Self {
        Self {
            kind,
            sequence,
            done: false,
            snapshot: UnderlaySnapshot::default(),
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), UnderlayNetlinkError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(UnderlayNetlinkError::Malformed);
        }
        budget.record_datagram(bytes.len())?;
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            if remaining.len() < NLMSG_HEADER_LEN {
                return Err(UnderlayNetlinkError::Malformed);
            }
            let length =
                usize::try_from(read_u32(remaining, 0).ok_or(UnderlayNetlinkError::Malformed)?)
                    .map_err(|_| UnderlayNetlinkError::Malformed)?;
            let aligned = align4(length);
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(UnderlayNetlinkError::Malformed);
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(UnderlayNetlinkError::Malformed);
            }
            budget.record_frame()?;
            let frame = &remaining[..length];
            self.ingest_frame(frame)?;
            offset = offset
                .checked_add(aligned)
                .ok_or(UnderlayNetlinkError::Limit)?;
            if self.done && offset != bytes.len() {
                return Err(UnderlayNetlinkError::Malformed);
            }
        }
        Ok(())
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), UnderlayNetlinkError> {
        if read_u32(frame, 8) != Some(self.sequence) || read_u32(frame, 12) != Some(0) {
            return Err(UnderlayNetlinkError::Malformed);
        }
        let message_type = read_u16(frame, 4).ok_or(UnderlayNetlinkError::Malformed)?;
        let flags = read_u16(frame, 6).ok_or(UnderlayNetlinkError::Malformed)?;
        if message_type == NLMSG_DONE {
            parse_done(flags, &frame[NLMSG_HEADER_LEN..])?;
            self.done = true;
            return Ok(());
        }
        if message_type == NLMSG_ERROR {
            return Err(parse_dump_error(
                frame,
                flags,
                self.kind.request_type(),
                self.sequence,
            )?);
        }
        if message_type != self.kind.response_type() || flags != NLM_F_MULTI {
            return Err(UnderlayNetlinkError::Malformed);
        }
        match self.kind {
            DumpKind::Link => self.snapshot.links.push(decode_link(frame)?),
            DumpKind::Address => {
                if let Some(address) = decode_address(frame)? {
                    self.snapshot.addresses.push(address);
                }
            }
            DumpKind::Route => {
                if let Some(route) = decode_route(frame)? {
                    self.snapshot.routes.push(route);
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<UnderlaySnapshot, UnderlayNetlinkError> {
        if !self.done {
            return Err(UnderlayNetlinkError::Malformed);
        }
        Ok(self.snapshot)
    }
}

struct NetlinkCollector {
    socket: Socket,
    sequence: u32,
}

impl NetlinkCollector {
    fn connect(deadline: HardDeadline) -> Result<Self, UnderlayNetlinkError> {
        deadline.ensure_remaining()?;
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        deadline.ensure_remaining()?;
        socket.bind_auto()?;
        deadline.ensure_remaining()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        socket.set_non_blocking(true)?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        sequence
    }

    fn collect_snapshot(
        &mut self,
        deadline: HardDeadline,
        budget: &mut CollectionBudget,
    ) -> Result<UnderlaySnapshot, UnderlayNetlinkError> {
        let mut snapshot = UnderlaySnapshot::default();
        for kind in [DumpKind::Link, DumpKind::Address, DumpKind::Route] {
            let part = self.collect_dump(kind, deadline, budget)?;
            match kind {
                DumpKind::Link => snapshot.links = part.links,
                DumpKind::Address => snapshot.addresses = part.addresses,
                DumpKind::Route => snapshot.routes = part.routes,
            }
        }
        snapshot.canonicalize()?;
        Ok(snapshot)
    }

    fn collect_dump(
        &mut self,
        kind: DumpKind,
        deadline: HardDeadline,
        budget: &mut CollectionBudget,
    ) -> Result<UnderlaySnapshot, UnderlayNetlinkError> {
        let sequence = self.next_sequence();
        let request = encode_dump_request(kind, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let mut state = DumpState::new(kind, sequence);
        while !state.done {
            let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
            state.ingest(sender, &bytes, budget)?;
        }
        deadline.ensure_remaining()?;
        state.finish()
    }
}

/// Collect two identical bounded snapshots, then make the pure fail-closed selection.
///
/// The production functional-alpha backend calls this before any mutation. It is read-only, opens
/// only `NETLINK_ROUTE`, and uses one deadline for all six dumps. Its result proves only local
/// assignment plus an unambiguous main-table default route; it never infers NAT behaviour or global
/// reachability.
pub(crate) fn collect_consistent_direct_underlay(
    deadline: HardDeadline,
) -> Result<UnderlayCandidate, UnderlayNetlinkError> {
    deadline.ensure_remaining()?;
    let mut collector = NetlinkCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let first = collector.collect_snapshot(deadline, &mut budget)?;
    let second = collector.collect_snapshot(deadline, &mut budget)?;
    deadline.ensure_remaining()?;
    let selected = select_consistent(&first, &second)?;
    let selected = deadline.complete(selected)?;
    Ok(selected)
}

fn select_consistent(
    first: &UnderlaySnapshot,
    second: &UnderlaySnapshot,
) -> Result<UnderlayCandidate, UnderlayNetlinkError> {
    if first != second {
        return Err(UnderlayNetlinkError::Inconsistent);
    }
    select_direct_underlay(&first.links, &first.addresses, &first.routes).map_err(|error| {
        match error {
            UnderlaySelectionError::NoCandidate => UnderlayNetlinkError::NoCandidate,
            UnderlaySelectionError::Ambiguous => UnderlayNetlinkError::Ambiguous,
        }
    })
}

fn send_bounded(
    socket: &Socket,
    request: &[u8],
    deadline: HardDeadline,
) -> Result<(), UnderlayNetlinkError> {
    loop {
        deadline.ensure_remaining()?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => {
                deadline.complete(())?;
                return Ok(());
            }
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short netlink write").into());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_fd(socket, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_bounded(
    socket: &Socket,
    deadline: HardDeadline,
    budget: &CollectionBudget,
) -> Result<(Vec<u8>, SocketAddr), UnderlayNetlinkError> {
    loop {
        wait_for_fd(socket, PollFlags::POLLIN, deadline)?;
        deadline.ensure_remaining()?;
        let mut probe = Vec::new();
        let (peek_length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(UnderlayNetlinkError::Malformed);
        }
        budget.can_receive(peek_length)?;
        deadline.ensure_remaining()?;
        let mut bytes = Vec::with_capacity(peek_length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        deadline.ensure_remaining()?;
        if received != peek_length || bytes.len() != received || sender != peek_sender {
            return Err(UnderlayNetlinkError::Malformed);
        }
        return Ok((bytes, sender));
    }
}

fn encode_dump_request(kind: DumpKind, sequence: u32) -> Result<Vec<u8>, UnderlayNetlinkError> {
    if sequence == 0 {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let payload = kind.request_payload();
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(UnderlayNetlinkError::Limit)?;
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| UnderlayNetlinkError::Limit)?
            .to_ne_bytes(),
    );
    request.extend_from_slice(&kind.request_type().to_ne_bytes());
    request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&payload);
    Ok(request)
}

fn parse_done(flags: u16, payload: &[u8]) -> Result<(), UnderlayNetlinkError> {
    if flags != NLM_F_MULTI {
        return Err(UnderlayNetlinkError::Malformed);
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_i32(bytes, 0) {
            Some(0) => Ok(()),
            Some(errno) if errno < 0 => Err(UnderlayNetlinkError::Kernel(errno.saturating_abs())),
            _ => Err(UnderlayNetlinkError::Malformed),
        },
        _ => Err(UnderlayNetlinkError::Malformed),
    }
}

fn parse_dump_error(
    frame: &[u8],
    flags: u16,
    request_type: u16,
    sequence: u32,
) -> Result<UnderlayNetlinkError, UnderlayNetlinkError> {
    if flags != 0 || frame.len() < NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let errno = read_i32(frame, NLMSG_HEADER_LEN).ok_or(UnderlayNetlinkError::Malformed)?;
    let embedded = NLMSG_HEADER_LEN + 4;
    let embedded_length =
        usize::try_from(read_u32(frame, embedded).ok_or(UnderlayNetlinkError::Malformed)?)
            .map_err(|_| UnderlayNetlinkError::Malformed)?;
    if errno >= 0
        || embedded_length < NLMSG_HEADER_LEN
        || frame.len() != embedded + embedded_length
        || read_u16(frame, embedded + 4) != Some(request_type)
        || read_u16(frame, embedded + 6) != Some(NLM_F_REQUEST | NLM_F_DUMP)
        || read_u32(frame, embedded + 8) != Some(sequence)
        || read_u32(frame, embedded + 12) != Some(0)
    {
        return Err(UnderlayNetlinkError::Malformed);
    }
    Ok(UnderlayNetlinkError::Kernel(errno.saturating_abs()))
}

fn decode_link(frame: &[u8]) -> Result<UnderlayLink, UnderlayNetlinkError> {
    let payload = frame
        .get(NLMSG_HEADER_LEN..)
        .ok_or(UnderlayNetlinkError::Malformed)?;
    if payload.len() < IFINFO_LEN || payload[0] != 0 {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let signed_index = read_i32(payload, 4).ok_or(UnderlayNetlinkError::Malformed)?;
    let ifindex = u32::try_from(signed_index).map_err(|_| UnderlayNetlinkError::Malformed)?;
    if ifindex == 0 {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let flags = read_u32(payload, 8).ok_or(UnderlayNetlinkError::Malformed)?;
    let attributes = parse_attributes(&payload[IFINFO_LEN..])?;
    let mut ifname = None;
    let mut alias = None;
    for attribute in attributes {
        match attribute.kind {
            IFLA_IFNAME => set_once(
                &mut ifname,
                parse_nul_string(attribute.value, false, 15)?,
                attribute.flags,
            )?,
            IFLA_IFALIAS => set_once(
                &mut alias,
                parse_nul_string(attribute.value, true, MAX_IFALIAS_BYTES)?,
                attribute.flags,
            )?,
            _ => reject_unknown_flags(attribute.flags)?,
        }
    }
    let ifname = ifname.ok_or(UnderlayNetlinkError::Malformed)?;
    let helper_owned = alias
        .as_deref()
        .is_some_and(|value| value.starts_with(HELPER_ALIAS_PREFIX));
    if helper_owned
        && !is_exact_helper_ownership_v1_alias(&ifname, alias.as_deref().unwrap_or_default())
    {
        return Err(UnderlayNetlinkError::Ambiguous);
    }
    Ok(UnderlayLink {
        ifindex,
        up: flags & u32::try_from(libc::IFF_UP).unwrap_or(1) != 0,
        loopback: flags & u32::try_from(libc::IFF_LOOPBACK).unwrap_or(8) != 0,
        helper_owned,
    })
}

fn decode_address(frame: &[u8]) -> Result<Option<UnderlayAddress>, UnderlayNetlinkError> {
    let payload = frame
        .get(NLMSG_HEADER_LEN..)
        .ok_or(UnderlayNetlinkError::Malformed)?;
    if payload.len() < IFADDR_LEN {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let family = address_family(payload[0])?;
    let maximum_prefix = match family {
        UnderlayFamily::Ipv4 => 32,
        UnderlayFamily::Ipv6 => 128,
    };
    let prefix_length = payload[1];
    if prefix_length > maximum_prefix {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let header_flags = u32::from(payload[2]);
    let scope = payload[3];
    let ifindex = read_u32(payload, 4).ok_or(UnderlayNetlinkError::Malformed)?;
    if ifindex == 0 {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let mut address = None;
    let mut local = None;
    let mut broadcast = None;
    let mut anycast = None;
    let mut multicast = None;
    let mut extended_flags = None;
    for attribute in parse_attributes(&payload[IFADDR_LEN..])? {
        match attribute.kind {
            IFA_ADDRESS => set_once(
                &mut address,
                parse_ip(attribute.value, family)?,
                attribute.flags,
            )?,
            IFA_LOCAL => set_once(
                &mut local,
                parse_ip(attribute.value, family)?,
                attribute.flags,
            )?,
            IFA_BROADCAST => set_once(
                &mut broadcast,
                parse_ip(attribute.value, family)?,
                attribute.flags,
            )?,
            IFA_ANYCAST => set_once(
                &mut anycast,
                parse_ip(attribute.value, family)?,
                attribute.flags,
            )?,
            IFA_MULTICAST => set_once(
                &mut multicast,
                parse_ip(attribute.value, family)?,
                attribute.flags,
            )?,
            IFA_FLAGS => set_once(
                &mut extended_flags,
                exact_u32(attribute.value)?,
                attribute.flags,
            )?,
            _ => reject_unknown_flags(attribute.flags)?,
        }
    }
    let value = local.or(address).ok_or(UnderlayNetlinkError::Malformed)?;
    if address.is_some_and(|candidate| candidate != value)
        || local.is_some_and(|candidate| candidate != value)
    {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let flags = extended_flags.unwrap_or(header_flags);
    if flags & 0xff != header_flags {
        return Err(UnderlayNetlinkError::Malformed);
    }
    if scope != RT_SCOPE_UNIVERSE || !is_public_routable_ip(value) {
        return Ok(None);
    }
    let unsafe_kind = value.is_multicast()
        || anycast.is_some()
        || multicast.is_some()
        || broadcast == Some(value)
        || is_ipv4_subnet_broadcast(value, prefix_length);
    Ok(Some(UnderlayAddress {
        ifindex,
        address: value,
        tentative: flags & IFA_F_TENTATIVE != 0,
        dad_failed: flags & IFA_F_DADFAILED != 0,
        deprecated: flags & IFA_F_DEPRECATED != 0,
        broadcast: unsafe_kind,
    }))
}

fn decode_route(frame: &[u8]) -> Result<Option<UnderlayRoute>, UnderlayNetlinkError> {
    let payload = frame
        .get(NLMSG_HEADER_LEN..)
        .ok_or(UnderlayNetlinkError::Malformed)?;
    if payload.len() < RTMSG_LEN {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let family = address_family(payload[0])?;
    let maximum_prefix = match family {
        UnderlayFamily::Ipv4 => 32,
        UnderlayFamily::Ipv6 => 128,
    };
    if payload[1] > maximum_prefix || payload[2] > maximum_prefix {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let attributes = parse_attributes(&payload[RTMSG_LEN..])?;
    if payload[1] != 0 {
        return Ok(None);
    }
    if payload[2] != 0 || payload[3] != 0 || read_u32(payload, 8) != Some(0) {
        return Err(UnderlayNetlinkError::Ambiguous);
    }
    let mut destination = None;
    let mut output = None;
    let mut table = None;
    let mut seen = 0_u64;
    for attribute in attributes {
        reject_unknown_flags(attribute.flags)?;
        if attribute.kind < 64 {
            let bit = 1_u64 << attribute.kind;
            if seen & bit != 0 {
                return Err(UnderlayNetlinkError::Malformed);
            }
            seen |= bit;
        }
        match attribute.kind {
            RTA_DST => destination = Some(parse_ip(attribute.value, family)?),
            RTA_OIF => output = Some(exact_u32(attribute.value)?),
            RTA_TABLE => table = Some(exact_u32(attribute.value)?),
            RTA_GATEWAY | RTA_PREFSRC => {
                let _ = parse_ip(attribute.value, family)?;
            }
            RTA_PRIORITY | RTA_EXPIRES | RTA_UID => {
                let _ = exact_u32(attribute.value)?;
            }
            RTA_PREF | RTA_TTL_PROPAGATE => {
                if attribute.value.len() != 1 {
                    return Err(UnderlayNetlinkError::Malformed);
                }
            }
            RTA_PAD if attribute.value.is_empty() => {}
            RTA_SRC | RTA_IIF | RTA_METRICS | RTA_MULTIPATH | RTA_VIA | RTA_NEWDST
            | RTA_ENCAP_TYPE | RTA_ENCAP | RTA_IP_PROTO | RTA_SPORT | RTA_DPORT | RTA_NH_ID => {
                return Err(UnderlayNetlinkError::Ambiguous);
            }
            _ => return Err(UnderlayNetlinkError::Ambiguous),
        }
    }
    if destination.is_some_and(|value| !ip_is_unspecified(value)) {
        return Err(UnderlayNetlinkError::Ambiguous);
    }
    let ifindex = output.ok_or(UnderlayNetlinkError::Ambiguous)?;
    if ifindex == 0 {
        return Err(UnderlayNetlinkError::Ambiguous);
    }
    let header_table = payload[4];
    if header_table != RT_TABLE_UNSPEC
        && table.is_some_and(|value| value != u32::from(header_table))
    {
        return Err(UnderlayNetlinkError::Malformed);
    }
    let effective_table = table.unwrap_or(u32::from(header_table));
    if effective_table != RT_TABLE_MAIN {
        return Ok(None);
    }
    if payload[7] != RTN_UNICAST || payload[6] != RT_SCOPE_UNIVERSE {
        return Err(UnderlayNetlinkError::Ambiguous);
    }
    Ok(Some(UnderlayRoute {
        ifindex,
        family,
        default: true,
        unicast: true,
        main_table: true,
        universe_scope: true,
    }))
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    value: &'a [u8],
}

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, UnderlayNetlinkError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(UnderlayNetlinkError::Malformed);
        }
        let length = usize::from(read_u16(bytes, 0).ok_or(UnderlayNetlinkError::Malformed)?);
        let raw_kind = read_u16(bytes, 2).ok_or(UnderlayNetlinkError::Malformed)?;
        let aligned = align4(length);
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(UnderlayNetlinkError::Malformed);
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(UnderlayNetlinkError::Malformed);
        }
        attributes.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags: raw_kind & !NLA_TYPE_MASK,
            value: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(attributes)
}

fn set_once<T>(target: &mut Option<T>, value: T, flags: u16) -> Result<(), UnderlayNetlinkError> {
    reject_unknown_flags(flags)?;
    if target.replace(value).is_some() {
        return Err(UnderlayNetlinkError::Malformed);
    }
    Ok(())
}

fn reject_unknown_flags(flags: u16) -> Result<(), UnderlayNetlinkError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(UnderlayNetlinkError::Ambiguous)
    }
}

fn parse_nul_string(
    value: &[u8],
    allow_empty: bool,
    maximum: usize,
) -> Result<Vec<u8>, UnderlayNetlinkError> {
    let bytes = value
        .strip_suffix(&[0])
        .ok_or(UnderlayNetlinkError::Malformed)?;
    if (!allow_empty && bytes.is_empty())
        || bytes.len() > maximum
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        return Err(UnderlayNetlinkError::Malformed);
    }
    Ok(bytes.to_vec())
}

fn is_exact_helper_ownership_v1_alias(ifname: &[u8], alias: &[u8]) -> bool {
    if !safe_helper_interface(ifname) {
        return false;
    }
    let Some(suffix) = alias.strip_prefix(HELPER_OWNERSHIP_V1_ALIAS_PREFIX) else {
        return false;
    };
    if suffix.len() != ifname.len() + 1 + OWNERSHIP_DIGEST_HEX_BYTES {
        return false;
    }
    let (bound_ifname, digest) = suffix.split_at(ifname.len());
    bound_ifname == ifname
        && digest.first() == Some(&b':')
        && digest[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_helper_interface(name: &[u8]) -> bool {
    name.len() == 12
        && name.starts_with(b"vp")
        && matches!(name[2], b'c' | b'r' | b's' | b'e')
        && matches!(name[3], b'1'..=b'8')
        && name[4..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn address_family(value: u8) -> Result<UnderlayFamily, UnderlayNetlinkError> {
    if i32::from(value) == libc::AF_INET {
        Ok(UnderlayFamily::Ipv4)
    } else if i32::from(value) == libc::AF_INET6 {
        Ok(UnderlayFamily::Ipv6)
    } else {
        Err(UnderlayNetlinkError::Malformed)
    }
}

fn parse_ip(value: &[u8], family: UnderlayFamily) -> Result<IpAddr, UnderlayNetlinkError> {
    match family {
        UnderlayFamily::Ipv4 => <[u8; 4]>::try_from(value)
            .map(Ipv4Addr::from)
            .map(IpAddr::V4)
            .map_err(|_| UnderlayNetlinkError::Malformed),
        UnderlayFamily::Ipv6 => <[u8; 16]>::try_from(value)
            .map(Ipv6Addr::from)
            .map(IpAddr::V6)
            .map_err(|_| UnderlayNetlinkError::Malformed),
    }
}

fn exact_u32(value: &[u8]) -> Result<u32, UnderlayNetlinkError> {
    value
        .try_into()
        .map(u32::from_ne_bytes)
        .map_err(|_| UnderlayNetlinkError::Malformed)
}

fn ip_is_unspecified(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(value) => value.is_unspecified(),
        IpAddr::V6(value) => value.is_unspecified(),
    }
}

fn is_ipv4_subnet_broadcast(value: IpAddr, prefix_length: u8) -> bool {
    let IpAddr::V4(value) = value else {
        return false;
    };
    if prefix_length == 0 || prefix_length == 32 {
        return false;
    }
    let host_mask = u32::MAX >> prefix_length;
    u32::from(value) & host_mask == host_mask
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

const fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQ: u32 = 41;

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + value.len();
        let mut bytes = Vec::with_capacity(align4(length));
        bytes.extend_from_slice(&u16::try_from(length).expect("small attr").to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align4(length), 0);
        bytes
    }

    fn nul(value: &[u8]) -> Vec<u8> {
        let mut bytes = value.to_vec();
        bytes.push(0);
        bytes
    }

    fn msg(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = Vec::with_capacity(align4(length));
        bytes.extend_from_slice(&u32::try_from(length).expect("small msg").to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(align4(length), 0);
        bytes
    }

    fn done() -> Vec<u8> {
        msg(NLMSG_DONE, NLM_F_MULTI, SEQ, &0_i32.to_ne_bytes())
    }

    fn link(index: u32, name: &[u8], alias: Option<&[u8]>) -> Vec<u8> {
        let mut payload = vec![0; IFINFO_LEN];
        payload[4..8].copy_from_slice(&i32::try_from(index).expect("index").to_ne_bytes());
        payload[8..12].copy_from_slice(&u32::try_from(libc::IFF_UP).expect("flag").to_ne_bytes());
        payload.extend_from_slice(&attr(IFLA_IFNAME, &nul(name)));
        if let Some(alias) = alias {
            payload.extend_from_slice(&attr(IFLA_IFALIAS, &nul(alias)));
        }
        msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &payload)
    }

    fn link_with_raw_alias(index: u32, name: &[u8], raw_alias: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; IFINFO_LEN];
        payload[4..8].copy_from_slice(&i32::try_from(index).expect("index").to_ne_bytes());
        payload[8..12].copy_from_slice(&u32::try_from(libc::IFF_UP).expect("flag").to_ne_bytes());
        payload.extend_from_slice(&attr(IFLA_IFNAME, &nul(name)));
        payload.extend_from_slice(&attr(IFLA_IFALIAS, raw_alias));
        msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &payload)
    }

    fn ownership_alias(ifname: &[u8], digest: &[u8]) -> Vec<u8> {
        let mut alias = Vec::with_capacity(
            HELPER_OWNERSHIP_V1_ALIAS_PREFIX.len() + ifname.len() + 1 + digest.len(),
        );
        alias.extend_from_slice(HELPER_OWNERSHIP_V1_ALIAS_PREFIX);
        alias.extend_from_slice(ifname);
        alias.push(b':');
        alias.extend_from_slice(digest);
        alias
    }

    fn raw_ip(value: &str) -> Vec<u8> {
        match value.parse::<IpAddr>().expect("IP") {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        }
    }

    fn address(value: &str, flags: u32) -> Vec<u8> {
        let parsed = value.parse::<IpAddr>().expect("IP");
        let mut payload = vec![0; IFADDR_LEN];
        payload[0] = u8::try_from(match parsed {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        })
        .expect("family");
        payload[1] = if parsed.is_ipv4() { 24 } else { 64 };
        payload[2] = u8::try_from(flags & 0xff).expect("low flags");
        payload[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        payload.extend_from_slice(&attr(IFA_ADDRESS, &raw_ip(value)));
        if parsed.is_ipv4() {
            payload.extend_from_slice(&attr(IFA_LOCAL, &raw_ip(value)));
        }
        payload.extend_from_slice(&attr(IFA_FLAGS, &flags.to_ne_bytes()));
        msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &payload)
    }

    fn route(family: UnderlayFamily, extra: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; RTMSG_LEN];
        payload[0] = u8::try_from(match family {
            UnderlayFamily::Ipv4 => libc::AF_INET,
            UnderlayFamily::Ipv6 => libc::AF_INET6,
        })
        .expect("family");
        payload[4] = u8::try_from(RT_TABLE_MAIN).expect("table");
        payload[6] = RT_SCOPE_UNIVERSE;
        payload[7] = RTN_UNICAST;
        payload.extend_from_slice(&attr(RTA_OIF, &7_u32.to_ne_bytes()));
        payload.extend_from_slice(extra);
        msg(RTM_NEWROUTE, NLM_F_MULTI, SEQ, &payload)
    }

    fn parse(
        kind: DumpKind,
        datagrams: &[Vec<u8>],
    ) -> Result<UnderlaySnapshot, UnderlayNetlinkError> {
        let mut state = DumpState::new(kind, SEQ);
        let mut budget = CollectionBudget::production();
        for datagram in datagrams {
            state.ingest(SocketAddr::new(0, 0), datagram, &mut budget)?;
        }
        let mut snapshot = state.finish()?;
        snapshot.canonicalize()?;
        Ok(snapshot)
    }

    fn stable(address: &str, family: UnderlayFamily) -> UnderlaySnapshot {
        UnderlaySnapshot {
            links: vec![UnderlayLink {
                ifindex: 7,
                up: true,
                loopback: false,
                helper_owned: false,
            }],
            addresses: vec![UnderlayAddress {
                ifindex: 7,
                address: address.parse().expect("IP"),
                tentative: false,
                dad_failed: false,
                deprecated: false,
                broadcast: false,
            }],
            routes: vec![UnderlayRoute {
                ifindex: 7,
                family,
                default: true,
                unicast: true,
                main_table: true,
                universe_scope: true,
            }],
        }
    }

    #[test]
    fn requests_are_exact_typed_dumps() {
        for (kind, message_type, payload_length) in [
            (DumpKind::Link, RTM_GETLINK, IFINFO_LEN),
            (DumpKind::Address, RTM_GETADDR, IFADDR_LEN),
            (DumpKind::Route, RTM_GETROUTE, RTMSG_LEN),
        ] {
            let request = encode_dump_request(kind, SEQ).expect("request");
            assert_eq!(read_u32(&request, 0), u32::try_from(request.len()).ok());
            assert_eq!(read_u16(&request, 4), Some(message_type));
            assert_eq!(read_u16(&request, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
            assert_eq!(read_u32(&request, 8), Some(SEQ));
            assert_eq!(read_u32(&request, 12), Some(0));
            assert_eq!(request.len(), NLMSG_HEADER_LEN + payload_length);
        }
        assert!(encode_dump_request(DumpKind::Link, 0).is_err());
    }

    #[test]
    fn multipart_reordering_is_canonical_but_identity_errors_fail() {
        let first = link(8, b"eth8", None);
        let second = link(7, b"eth7", None);
        let mut forward_end = second.clone();
        forward_end.extend_from_slice(&done());
        let mut reverse_end = first.clone();
        reverse_end.extend_from_slice(&done());
        let forward = parse(DumpKind::Link, &[first.clone(), forward_end]).expect("forward");
        let reverse = parse(DumpKind::Link, &[second, reverse_end]).expect("reverse");
        assert_eq!(forward, reverse);

        for sender in [SocketAddr::new(1, 0), SocketAddr::new(0, 1)] {
            let mut state = DumpState::new(DumpKind::Link, SEQ);
            let mut budget = CollectionBudget::production();
            assert!(matches!(
                state.ingest(sender, &first, &mut budget),
                Err(UnderlayNetlinkError::Malformed)
            ));
        }
        for (offset, replacement) in [(8, (SEQ + 1).to_ne_bytes()), (12, 1_u32.to_ne_bytes())] {
            let mut invalid = first.clone();
            invalid[offset..offset + 4].copy_from_slice(&replacement);
            assert!(parse(DumpKind::Link, &[invalid, done()]).is_err());
        }
        assert!(
            parse(
                DumpKind::Link,
                &[msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &[]), done()]
            )
            .is_err()
        );
        assert!(parse(DumpKind::Link, &[msg(RTM_NEWLINK, 0, SEQ, &[]), done()]).is_err());
    }

    #[test]
    fn done_error_alignment_and_duplicate_scalars_are_strict() {
        let data = link(7, b"eth7", None);
        assert!(parse(DumpKind::Link, &[data.clone()]).is_err());
        let mut double_done = done();
        double_done.extend_from_slice(&done());
        assert!(parse(DumpKind::Link, &[data.clone(), double_done]).is_err());
        let request = encode_dump_request(DumpKind::Link, SEQ).expect("request");
        let mut error_payload = (-libc::EPERM).to_ne_bytes().to_vec();
        error_payload.extend_from_slice(&request);
        assert!(matches!(
            parse(DumpKind::Link, &[msg(NLMSG_ERROR, 0, SEQ, &error_payload)]),
            Err(UnderlayNetlinkError::Kernel(value)) if value == libc::EPERM
        ));
        error_payload[..4].copy_from_slice(&0_i32.to_ne_bytes());
        assert!(parse(DumpKind::Link, &[msg(NLMSG_ERROR, 0, SEQ, &error_payload)]).is_err());
        assert!(matches!(
            parse(
                DumpKind::Link,
                &[msg(
                    NLMSG_DONE,
                    NLM_F_MULTI,
                    SEQ,
                    &(-libc::EINTR).to_ne_bytes()
                )]
            ),
            Err(UnderlayNetlinkError::Kernel(value)) if value == libc::EINTR
        ));

        let mut duplicate = vec![0; IFINFO_LEN];
        duplicate[4..8].copy_from_slice(&7_i32.to_ne_bytes());
        duplicate.extend_from_slice(&attr(IFLA_IFNAME, &nul(b"eth7")));
        duplicate.extend_from_slice(&attr(IFLA_IFNAME, &nul(b"eth8")));
        assert!(
            parse(
                DumpKind::Link,
                &[msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &duplicate), done()]
            )
            .is_err()
        );
        let mut malformed = vec![0; IFINFO_LEN];
        malformed[4..8].copy_from_slice(&7_i32.to_ne_bytes());
        malformed.extend_from_slice(&[3, 0, 99, 0]);
        assert!(
            parse(
                DumpKind::Link,
                &[msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &malformed), done()]
            )
            .is_err()
        );
        let mut padding = attr(99, &[1]);
        *padding.last_mut().expect("padding") = 1;
        let mut payload = vec![0; IFINFO_LEN];
        payload[4..8].copy_from_slice(&7_i32.to_ne_bytes());
        payload.extend_from_slice(&attr(IFLA_IFNAME, &nul(b"eth7")));
        payload.extend_from_slice(&padding);
        assert!(
            parse(
                DumpKind::Link,
                &[msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &payload), done()]
            )
            .is_err()
        );
    }

    #[test]
    fn caps_apply_before_allocation_and_per_frame() {
        let budget = CollectionBudget::production();
        assert!(matches!(
            budget.can_receive(MAX_DATAGRAM_BYTES + 1),
            Err(UnderlayNetlinkError::Limit)
        ));
        let mut bytes = link(7, b"eth7", None);
        bytes.extend_from_slice(&done());
        let mut frame_budget = CollectionBudget {
            bytes: 0,
            frames: 0,
            max_bytes: MAX_DATAGRAM_BYTES,
            max_frames: 1,
        };
        let mut state = DumpState::new(DumpKind::Link, SEQ);
        assert!(matches!(
            state.ingest(SocketAddr::new(0, 0), &bytes, &mut frame_budget),
            Err(UnderlayNetlinkError::Limit)
        ));
        let mut byte_budget = CollectionBudget {
            bytes: 0,
            frames: 0,
            max_bytes: NLMSG_HEADER_LEN,
            max_frames: MAX_TOTAL_FRAMES,
        };
        let mut state = DumpState::new(DumpKind::Link, SEQ);
        assert!(matches!(
            state.ingest(SocketAddr::new(0, 0), &bytes, &mut byte_budget),
            Err(UnderlayNetlinkError::Limit)
        ));
    }

    #[test]
    fn address_families_flags_and_unsafe_kinds_fail_closed() {
        let ipv4 = parse(
            DumpKind::Address,
            &[address("8.8.8.8", IFA_F_TENTATIVE), done()],
        )
        .expect("IPv4");
        assert!(ipv4.addresses[0].tentative);
        let flags = IFA_F_DADFAILED | IFA_F_DEPRECATED;
        let ipv6 = parse(
            DumpKind::Address,
            &[address("2606:4700:4700::1111", flags), done()],
        )
        .expect("IPv6");
        assert!(ipv6.addresses[0].dad_failed && ipv6.addresses[0].deprecated);
        assert!(
            parse(DumpKind::Address, &[address("192.0.2.1", 0), done()])
                .expect("filtered")
                .addresses
                .is_empty()
        );

        let frame = address("8.8.8.8", 0);
        let payload_length = usize::try_from(read_u32(&frame, 0).expect("length")).expect("usize")
            - NLMSG_HEADER_LEN;
        let mut mismatch = frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + payload_length].to_vec();
        mismatch.extend_from_slice(&attr(IFA_LOCAL, &raw_ip("1.1.1.1")));
        assert!(
            parse(
                DumpKind::Address,
                &[msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &mismatch), done()]
            )
            .is_err()
        );
        let mut anycast = frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + payload_length].to_vec();
        anycast.extend_from_slice(&attr(IFA_ANYCAST, &raw_ip("8.8.8.7")));
        assert!(
            parse(
                DumpKind::Address,
                &[msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &anycast), done()]
            )
            .expect("anycast")
            .addresses[0]
                .broadcast
        );
    }

    #[test]
    fn routes_reject_table_oif_destination_and_nexthop_ambiguity() {
        assert!(
            parse(DumpKind::Route, &[route(UnderlayFamily::Ipv6, &[]), done()])
                .expect("route")
                .routes[0]
                .main_table
        );
        for extra in [
            attr(RTA_OIF, &8_u32.to_ne_bytes()),
            attr(RTA_MULTIPATH, &[0; 8]),
            attr(RTA_NH_ID, &1_u32.to_ne_bytes()),
            attr(RTA_DST, &raw_ip("1.0.0.0")),
        ] {
            assert!(
                parse(
                    DumpKind::Route,
                    &[route(UnderlayFamily::Ipv4, &extra), done()]
                )
                .is_err()
            );
        }
        assert!(matches!(
            parse(
                DumpKind::Route,
                &[
                    route(
                        UnderlayFamily::Ipv4,
                        &attr(RTA_TABLE, &253_u32.to_ne_bytes())
                    ),
                    done()
                ]
            ),
            Err(UnderlayNetlinkError::Malformed)
        ));
    }

    #[test]
    fn helper_ownership_alias_grammar_is_exact() {
        const IFNAME: &[u8] = b"vpc1deadbeef";
        const OTHER_IFNAME: &[u8] = b"vpc1feedface";
        const DIGEST: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let exact = ownership_alias(IFNAME, DIGEST);
        let owned = link(7, IFNAME, Some(&exact));
        assert!(
            parse(DumpKind::Link, &[owned, done()])
                .expect("owned")
                .links[0]
                .helper_owned
        );

        let mut uppercase = exact.clone();
        *uppercase.last_mut().expect("non-empty alias") = b'F';
        let mut non_hex = exact.clone();
        *non_hex.last_mut().expect("non-empty alias") = b'g';
        let mut digest_65 = DIGEST.to_vec();
        digest_65.push(b'0');
        let adversarial = [
            ownership_alias(OTHER_IFNAME, DIGEST),
            uppercase,
            non_hex,
            ownership_alias(IFNAME, &DIGEST[..63]),
            ownership_alias(IFNAME, &digest_65),
            b"volparossa:wireguard:v3:vpc1deadbeef".to_vec(),
        ];
        for alias in adversarial {
            assert!(matches!(
                parse(DumpKind::Link, &[link(7, IFNAME, Some(&alias)), done()]),
                Err(UnderlayNetlinkError::Ambiguous)
            ));
        }

        let mut embedded_nul = exact.clone();
        *embedded_nul.last_mut().expect("non-empty alias") = 0;
        assert!(matches!(
            parse(
                DumpKind::Link,
                &[link(7, IFNAME, Some(&embedded_nul)), done()]
            ),
            Err(UnderlayNetlinkError::Malformed)
        ));
        assert!(matches!(
            parse(
                DumpKind::Link,
                &[link_with_raw_alias(7, IFNAME, &exact), done()]
            ),
            Err(UnderlayNetlinkError::Malformed)
        ));

        let maximum = vec![b'x'; MAX_IFALIAS_BYTES];
        assert!(
            !parse(DumpKind::Link, &[link(7, IFNAME, Some(&maximum)), done()])
                .expect("255-byte non-helper alias")
                .links[0]
                .helper_owned
        );
        let mut maximum_helper_alias = HELPER_ALIAS_PREFIX.to_vec();
        maximum_helper_alias.resize(MAX_IFALIAS_BYTES, b'x');
        assert!(matches!(
            parse(
                DumpKind::Link,
                &[link(7, IFNAME, Some(&maximum_helper_alias)), done()]
            ),
            Err(UnderlayNetlinkError::Ambiguous)
        ));
        let oversized = vec![b'x'; MAX_IFALIAS_BYTES + 1];
        assert!(matches!(
            parse(DumpKind::Link, &[link(7, IFNAME, Some(&oversized)), done()]),
            Err(UnderlayNetlinkError::Malformed)
        ));
    }

    #[test]
    fn double_snapshot_policy_is_exact() {
        let first = stable("8.8.8.8", UnderlayFamily::Ipv4);
        assert_eq!(
            select_consistent(&first, &first)
                .expect("candidate")
                .address,
            "8.8.8.8".parse::<IpAddr>().expect("IP")
        );
        let changed = stable("1.1.1.1", UnderlayFamily::Ipv4);
        assert!(matches!(
            select_consistent(&first, &changed),
            Err(UnderlayNetlinkError::Inconsistent)
        ));
        let empty = UnderlaySnapshot::default();
        assert!(matches!(
            select_consistent(&empty, &empty),
            Err(UnderlayNetlinkError::NoCandidate)
        ));
        let mut ambiguous = first.clone();
        ambiguous.addresses.push(UnderlayAddress {
            address: "1.1.1.1".parse().expect("IP"),
            ..ambiguous.addresses[0]
        });
        assert!(matches!(
            select_consistent(&ambiguous, &ambiguous),
            Err(UnderlayNetlinkError::Ambiguous)
        ));
    }

    #[test]
    fn truncation_unknown_critical_flags_and_family_lengths_fail_closed() {
        let mut truncated = link(7, b"eth7", None);
        let claimed_length = u32::try_from(truncated.len() + 4).expect("small transcript");
        truncated[0..4].copy_from_slice(&claimed_length.to_ne_bytes());
        assert!(parse(DumpKind::Link, &[truncated, done()]).is_err());

        let mut critical_payload = vec![0; IFINFO_LEN];
        critical_payload[4..8].copy_from_slice(&7_i32.to_ne_bytes());
        critical_payload.extend_from_slice(&attr(IFLA_IFNAME, &nul(b"eth7")));
        critical_payload.extend_from_slice(&attr(63 | NLA_F_NESTED, &[0; 4]));
        assert!(matches!(
            parse(
                DumpKind::Link,
                &[
                    msg(RTM_NEWLINK, NLM_F_MULTI, SEQ, &critical_payload),
                    done()
                ]
            ),
            Err(UnderlayNetlinkError::Ambiguous)
        ));

        let address_frame = address("8.8.8.8", 0);
        let payload_length = usize::try_from(read_u32(&address_frame, 0).expect("length"))
            .expect("usize")
            - NLMSG_HEADER_LEN;
        let mut short_address =
            address_frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + payload_length].to_vec();
        short_address[IFADDR_LEN..IFADDR_LEN + 2].copy_from_slice(&7_u16.to_ne_bytes());
        assert!(
            parse(
                DumpKind::Address,
                &[msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &short_address), done()]
            )
            .is_err()
        );
    }

    #[test]
    fn address_and_route_edge_values_are_explicitly_rejected() {
        let frame = address("8.8.8.8", 0);
        let payload_length = usize::try_from(read_u32(&frame, 0).expect("length")).expect("usize")
            - NLMSG_HEADER_LEN;
        let mut multicast = frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + payload_length].to_vec();
        multicast.extend_from_slice(&attr(IFA_MULTICAST, &raw_ip("8.8.8.7")));
        assert!(
            parse(
                DumpKind::Address,
                &[msg(RTM_NEWADDR, NLM_F_MULTI, SEQ, &multicast), done()]
            )
            .expect("multicast marker")
            .addresses[0]
                .broadcast
        );
        assert!(
            parse(DumpKind::Address, &[address("8.8.8.255", 0), done()])
                .expect("subnet broadcast")
                .addresses[0]
                .broadcast
        );

        let route_frame = route(UnderlayFamily::Ipv4, &[]);
        let route_length = usize::try_from(read_u32(&route_frame, 0).expect("length"))
            .expect("usize")
            - NLMSG_HEADER_LEN;
        let base = route_frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + route_length].to_vec();
        let mut zero_oif = base.clone();
        zero_oif[RTMSG_LEN + ATTRIBUTE_HEADER_LEN..RTMSG_LEN + ATTRIBUTE_HEADER_LEN + 4].fill(0);
        assert!(matches!(
            parse(
                DumpKind::Route,
                &[msg(RTM_NEWROUTE, NLM_F_MULTI, SEQ, &zero_oif), done()]
            ),
            Err(UnderlayNetlinkError::Ambiguous)
        ));
        let mut table_attribute = base.clone();
        table_attribute[4] = RT_TABLE_UNSPEC;
        table_attribute.extend_from_slice(&attr(RTA_TABLE, &RT_TABLE_MAIN.to_ne_bytes()));
        assert!(
            parse(
                DumpKind::Route,
                &[
                    msg(RTM_NEWROUTE, NLM_F_MULTI, SEQ, &table_attribute),
                    done()
                ]
            )
            .expect("explicit main table")
            .routes[0]
                .main_table
        );
        let mut blackhole = base;
        blackhole[7] = 6;
        assert!(matches!(
            parse(
                DumpKind::Route,
                &[msg(RTM_NEWROUTE, NLM_F_MULTI, SEQ, &blackhole), done()]
            ),
            Err(UnderlayNetlinkError::Ambiguous)
        ));
    }
}
