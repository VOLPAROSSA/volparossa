//! Strict bounded `WireGuard` `GET_DEVICE` transaction and parser.
//!
//! The parser treats the kernel response as security evidence, not as a best-effort status dump.
//! It accepts only the documented Linux `WireGuard` UAPI tree, coalesces only the continuation form
//! explicitly allowed by that UAPI, and never retains private or preshared key attributes.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use nix::poll::PollFlags;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::deadline::{HardDeadline, wait_for_fd};

use super::{
    ATTRIBUTE_HEADER_LEN, GENL_HEADER_LEN, KernelError, NLA_F_NESTED, NLA_TYPE_MASK,
    NLMSG_HEADER_LEN, NetlinkClient, NetlinkReply, WG_GENL_VERSION, attributes,
    build_netlink_message, push_string_attribute, read_i32, read_u16, read_u32,
    validate_kernel_header, validate_kernel_sender,
};

const WG_CMD_GET_DEVICE: u8 = 0;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_DONE: u16 = 3;
const MAX_WIREGUARD_DUMP_FRAMES: usize = 8;
const MAX_WIREGUARD_DUMP_BYTES: usize = 128 * 1024;
const MAX_WIREGUARD_PEERS: usize = 8;
const MAX_WIREGUARD_ALLOWED_IPS: usize = 8;

const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// Exact state proven by one complete bounded `GET_DEVICE` dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireguardDeviceState {
    pub(crate) ifindex: u32,
    pub(crate) interface_name: String,
    pub(crate) public_key: [u8; 32],
    pub(crate) listen_port: u16,
    pub(crate) firewall_mark: u32,
    pub(crate) peers: Vec<WireguardPeerState>,
}

impl WireguardDeviceState {
    /// Return the only peer, rejecting absent or ambiguous peer state.
    pub(crate) fn single_peer(&self) -> Result<&WireguardPeerState, KernelError> {
        let [peer] = self.peers.as_slice() else {
            return Err(KernelError::Malformed);
        };
        Ok(peer)
    }
}

/// One complete peer from a `GET_DEVICE` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireguardPeerState {
    pub(crate) public_key: [u8; 32],
    pub(crate) endpoint: SocketAddr,
    pub(crate) persistent_keepalive_seconds: u16,
    pub(crate) last_handshake_seconds: u64,
    pub(crate) last_handshake_nanoseconds: u32,
    pub(crate) received_bytes: u64,
    pub(crate) transmitted_bytes: u64,
    pub(crate) allowed_ips: Vec<WireguardAllowedIp>,
    pub(crate) protocol_version: Option<u32>,
}

/// One exact peer allowed prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct WireguardAllowedIp {
    pub(crate) address: IpAddr,
    pub(crate) prefix_length: u8,
}

pub(super) fn probe_device(
    netlink: &mut NetlinkClient,
    family_id: u16,
    interface: &str,
    deadline: HardDeadline,
) -> Result<WireguardDeviceState, KernelError> {
    if family_id == 0
        || interface.is_empty()
        || interface.len() > libc::IFNAMSIZ.saturating_sub(1)
        || interface.as_bytes().contains(&0)
    {
        return Err(KernelError::Invalid);
    }
    let mut request_attributes = Zeroizing::new(Vec::with_capacity(32));
    push_string_attribute(&mut request_attributes, WGDEVICE_A_IFNAME, interface)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(
        GENL_HEADER_LEN + request_attributes.len(),
    ));
    payload.push(WG_CMD_GET_DEVICE);
    payload.push(WG_GENL_VERSION);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&request_attributes);
    netlink.request_wireguard_dump(family_id, interface, &payload, deadline)
}

impl NetlinkClient {
    fn request_wireguard_dump(
        &mut self,
        family_id: u16,
        interface: &str,
        payload: &[u8],
        deadline: HardDeadline,
    ) -> Result<WireguardDeviceState, KernelError> {
        let sequence = self.next_sequence();
        let request = Zeroizing::new(build_netlink_message(
            family_id,
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            payload,
        )?);
        self.send(&request, deadline)?;

        let mut parser =
            WireguardDumpParser::new(sequence, family_id, interface, self.local_port_id)?;
        while !parser.done() {
            wait_for_fd(&self.socket, PollFlags::POLLIN, deadline)?;
            deadline.ensure_remaining()?;
            let mut bytes = Zeroizing::new(vec![0_u8; MAX_WIREGUARD_DUMP_BYTES + 1]);
            let (received, sender) =
                match self.socket.recv_from(&mut &mut bytes[..], libc::MSG_TRUNC) {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
            deadline.ensure_remaining()?;
            if !(NLMSG_HEADER_LEN..=MAX_WIREGUARD_DUMP_BYTES).contains(&received) {
                return Err(KernelError::Malformed);
            }
            bytes.truncate(received);
            parser.ingest(&NetlinkReply {
                message: bytes,
                sender,
            })?;
        }
        deadline.ensure_remaining()?;
        let state = parser.finish()?;
        let state = deadline.complete(state)?;
        Ok(state)
    }
}

struct WireguardDumpParser {
    expected_sequence: u32,
    expected_family: u16,
    expected_interface: String,
    expected_local_port_id: u32,
    frame_count: usize,
    byte_count: usize,
    done: bool,
    device: DeviceAccumulator,
}

impl WireguardDumpParser {
    fn new(
        expected_sequence: u32,
        expected_family: u16,
        expected_interface: &str,
        expected_local_port_id: u32,
    ) -> Result<Self, KernelError> {
        if expected_sequence == 0
            || expected_family == 0
            || expected_local_port_id == 0
            || expected_interface.is_empty()
            || expected_interface.len() > libc::IFNAMSIZ.saturating_sub(1)
            || expected_interface.as_bytes().contains(&0)
        {
            return Err(KernelError::Invalid);
        }
        Ok(Self {
            expected_sequence,
            expected_family,
            expected_interface: expected_interface.to_owned(),
            expected_local_port_id,
            frame_count: 0,
            byte_count: 0,
            done: false,
            device: DeviceAccumulator::default(),
        })
    }

    const fn done(&self) -> bool {
        self.done
    }

    fn ingest(&mut self, reply: &NetlinkReply) -> Result<(), KernelError> {
        validate_kernel_sender(&reply.sender)?;
        if self.done || reply.message.is_empty() {
            return Err(KernelError::Malformed);
        }
        self.byte_count = self
            .byte_count
            .checked_add(reply.message.len())
            .ok_or(KernelError::Malformed)?;
        if self.byte_count > MAX_WIREGUARD_DUMP_BYTES {
            return Err(KernelError::Malformed);
        }

        let mut bytes = reply.message.as_slice();
        while !bytes.is_empty() {
            if self.done || bytes.len() < NLMSG_HEADER_LEN {
                return Err(KernelError::Malformed);
            }
            self.frame_count = self
                .frame_count
                .checked_add(1)
                .ok_or(KernelError::Malformed)?;
            if self.frame_count > MAX_WIREGUARD_DUMP_FRAMES {
                return Err(KernelError::Malformed);
            }

            let length = usize::try_from(read_u32(bytes, 0).ok_or(KernelError::Malformed)?)
                .map_err(|_| KernelError::Malformed)?;
            if length < NLMSG_HEADER_LEN || length > bytes.len() {
                return Err(KernelError::Malformed);
            }
            let aligned = align4(length);
            if aligned > bytes.len() || bytes[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(KernelError::Malformed);
            }
            let frame = &bytes[..length];
            self.ingest_frame(frame)?;
            bytes = &bytes[aligned..];
        }
        Ok(())
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), KernelError> {
        if read_u32(frame, 8) != Some(self.expected_sequence)
            || read_u32(frame, 12) != Some(self.expected_local_port_id)
        {
            return Err(KernelError::Malformed);
        }
        if read_u16(frame, 6) != Some(NLM_F_MULTI) {
            return Err(KernelError::Malformed);
        }
        match read_u16(frame, 4) {
            Some(NLMSG_DONE) => {
                if frame.len() != NLMSG_HEADER_LEN + 4 {
                    return Err(KernelError::Malformed);
                }
                let error = read_i32(frame, NLMSG_HEADER_LEN).ok_or(KernelError::Malformed)?;
                if error > 0 {
                    return Err(KernelError::Malformed);
                }
                if error < 0 {
                    return Err(KernelError::Errno(error.saturating_abs()));
                }
                self.done = true;
                Ok(())
            }
            Some(message_type) if message_type == self.expected_family => {
                validate_kernel_header(
                    frame,
                    self.expected_sequence,
                    self.expected_family,
                    self.expected_local_port_id,
                )?;
                if frame.len() < NLMSG_HEADER_LEN + GENL_HEADER_LEN
                    || frame[NLMSG_HEADER_LEN] != WG_CMD_GET_DEVICE
                    || frame[NLMSG_HEADER_LEN + 1] != WG_GENL_VERSION
                    || read_u16(frame, NLMSG_HEADER_LEN + 2) != Some(0)
                {
                    return Err(KernelError::Malformed);
                }
                self.device.parse_frame(
                    &frame[NLMSG_HEADER_LEN + GENL_HEADER_LEN..],
                    &self.expected_interface,
                )
            }
            _ => Err(KernelError::Malformed),
        }
    }

    fn finish(self) -> Result<WireguardDeviceState, KernelError> {
        if !self.done {
            return Err(KernelError::Malformed);
        }
        self.device.finish(&self.expected_interface)
    }
}

#[derive(Default)]
struct DeviceAccumulator {
    ifindex: Option<u32>,
    interface_name: Option<String>,
    private_key_seen: bool,
    public_key: Option<[u8; 32]>,
    listen_port: Option<u16>,
    firewall_mark: Option<u32>,
    peers: Vec<PeerAccumulator>,
}

impl DeviceAccumulator {
    fn parse_frame(&mut self, bytes: &[u8], expected_interface: &str) -> Result<(), KernelError> {
        let mut frame_name_seen = false;
        let mut peers_seen = false;
        for (raw_kind, value) in attributes(bytes)? {
            let kind = if raw_kind & NLA_TYPE_MASK == WGDEVICE_A_PEERS {
                if raw_kind != WGDEVICE_A_PEERS | NLA_F_NESTED {
                    return Err(KernelError::Malformed);
                }
                WGDEVICE_A_PEERS
            } else {
                plain_attribute_kind(raw_kind)?
            };
            match kind {
                WGDEVICE_A_IFINDEX => {
                    let value = exact_u32(value)?;
                    if value == 0 || self.ifindex.replace(value).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGDEVICE_A_IFNAME => {
                    if frame_name_seen {
                        return Err(KernelError::Malformed);
                    }
                    frame_name_seen = true;
                    let value = strict_interface_name(value)?;
                    if value != expected_interface {
                        return Err(KernelError::Malformed);
                    }
                    match &self.interface_name {
                        None => self.interface_name = Some(value),
                        Some(existing) if existing == &value => {}
                        Some(_) => return Err(KernelError::Malformed),
                    }
                }
                WGDEVICE_A_PRIVATE_KEY => {
                    if self.private_key_seen {
                        return Err(KernelError::Malformed);
                    }
                    exact_nonzero_private_key(value)?;
                    self.private_key_seen = true;
                }
                WGDEVICE_A_PUBLIC_KEY => {
                    let key = exact_key(value)?;
                    if self.public_key.replace(key).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGDEVICE_A_LISTEN_PORT => {
                    let port = exact_u16(value)?;
                    if self.listen_port.replace(port).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGDEVICE_A_FWMARK => {
                    if self.firewall_mark.replace(exact_u32(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGDEVICE_A_PEERS => {
                    if peers_seen {
                        return Err(KernelError::Malformed);
                    }
                    peers_seen = true;
                    self.parse_peers(value)?;
                }
                _ => return Err(KernelError::Malformed),
            }
        }
        if !frame_name_seen {
            return Err(KernelError::Malformed);
        }
        Ok(())
    }

    fn parse_peers(&mut self, bytes: &[u8]) -> Result<(), KernelError> {
        for (kind, value) in attributes(bytes)? {
            if kind & !NLA_TYPE_MASK != NLA_F_NESTED {
                return Err(KernelError::Malformed);
            }
            let fragment = PeerFragment::parse(value)?;
            if let Some(last) = self.peers.last_mut() {
                if last.public_key == fragment.public_key {
                    if fragment.has_non_continuation_fields() {
                        return Err(KernelError::Malformed);
                    }
                    last.merge_allowed_ips(fragment.allowed_ips)?;
                    continue;
                }
            }
            if self
                .peers
                .iter()
                .any(|peer| peer.public_key == fragment.public_key)
                || self.peers.len() >= MAX_WIREGUARD_PEERS
            {
                return Err(KernelError::Malformed);
            }
            self.peers.push(PeerAccumulator::from_initial(fragment)?);
        }
        Ok(())
    }

    fn finish(self, expected_interface: &str) -> Result<WireguardDeviceState, KernelError> {
        let ifindex = self.ifindex.ok_or(KernelError::Malformed)?;
        let interface_name = self.interface_name.ok_or(KernelError::Malformed)?;
        // Linux omits both device-key attributes until the WireGuard device has an identity.
        // They are emitted as one pair once configured; a one-sided response is never canonical.
        let public_key = match (self.private_key_seen, self.public_key) {
            (false, None) => [0; 32],
            (true, Some(key)) if key.iter().any(|byte| *byte != 0) => key,
            _ => return Err(KernelError::Malformed),
        };
        let listen_port = self.listen_port.ok_or(KernelError::Malformed)?;
        let firewall_mark = self.firewall_mark.ok_or(KernelError::Malformed)?;
        if interface_name != expected_interface {
            return Err(KernelError::Malformed);
        }
        let peers = self
            .peers
            .into_iter()
            .map(PeerAccumulator::finish)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WireguardDeviceState {
            ifindex,
            interface_name,
            public_key,
            listen_port,
            firewall_mark,
            peers,
        })
    }
}

fn exact_nonzero_private_key(value: &[u8]) -> Result<(), KernelError> {
    if value.len() != 32 || bool::from(value.ct_eq(&[0_u8; 32])) {
        return Err(KernelError::Malformed);
    }
    Ok(())
}

struct PeerFragment {
    public_key: [u8; 32],
    preshared_key_seen: bool,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    handshake: Option<(u64, u32)>,
    received_bytes: Option<u64>,
    transmitted_bytes: Option<u64>,
    allowed_ips: Vec<WireguardAllowedIp>,
    protocol_version: Option<u32>,
}

impl PeerFragment {
    fn parse(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut public_key = None;
        let mut preshared_key_seen = false;
        let mut endpoint = None;
        let mut keepalive = None;
        let mut handshake = None;
        let mut received_bytes = None;
        let mut transmitted_bytes = None;
        let mut allowed_ips = None;
        let mut protocol_version = None;

        for (raw_kind, value) in attributes(bytes)? {
            let kind = if raw_kind & NLA_TYPE_MASK == WGPEER_A_ALLOWEDIPS {
                if raw_kind != WGPEER_A_ALLOWEDIPS | NLA_F_NESTED {
                    return Err(KernelError::Malformed);
                }
                WGPEER_A_ALLOWEDIPS
            } else {
                plain_attribute_kind(raw_kind)?
            };
            match kind {
                WGPEER_A_PUBLIC_KEY => {
                    if public_key.replace(exact_key(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_PRESHARED_KEY => {
                    exact_key(value)?;
                    if preshared_key_seen {
                        return Err(KernelError::Malformed);
                    }
                    preshared_key_seen = true;
                }
                WGPEER_A_ENDPOINT => {
                    if endpoint.replace(parse_endpoint(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                    if keepalive.replace(exact_u16(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_LAST_HANDSHAKE_TIME => {
                    if handshake.replace(parse_handshake(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_RX_BYTES => {
                    if received_bytes.replace(exact_u64(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_TX_BYTES => {
                    if transmitted_bytes.replace(exact_u64(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_ALLOWEDIPS => {
                    if allowed_ips.replace(parse_allowed_ips(value)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGPEER_A_PROTOCOL_VERSION => {
                    let version = exact_u32(value)?;
                    if version > 1 || protocol_version.replace(version).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                _ => return Err(KernelError::Malformed),
            }
        }

        let public_key = public_key.ok_or(KernelError::Malformed)?;
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(KernelError::Malformed);
        }
        Ok(Self {
            public_key,
            preshared_key_seen,
            endpoint,
            keepalive,
            handshake,
            received_bytes,
            transmitted_bytes,
            allowed_ips: allowed_ips.unwrap_or_default(),
            protocol_version,
        })
    }

    fn has_non_continuation_fields(&self) -> bool {
        self.preshared_key_seen
            || self.endpoint.is_some()
            || self.keepalive.is_some()
            || self.handshake.is_some()
            || self.received_bytes.is_some()
            || self.transmitted_bytes.is_some()
            || self.protocol_version.is_some()
    }
}

struct PeerAccumulator {
    public_key: [u8; 32],
    endpoint: SocketAddr,
    keepalive: u16,
    handshake: (u64, u32),
    received_bytes: u64,
    transmitted_bytes: u64,
    allowed_ips: Vec<WireguardAllowedIp>,
    protocol_version: Option<u32>,
}

impl PeerAccumulator {
    fn from_initial(fragment: PeerFragment) -> Result<Self, KernelError> {
        if !fragment.preshared_key_seen
            || fragment.allowed_ips.is_empty()
            || fragment.allowed_ips.len() > MAX_WIREGUARD_ALLOWED_IPS
        {
            return Err(KernelError::Malformed);
        }
        Ok(Self {
            public_key: fragment.public_key,
            endpoint: fragment.endpoint.ok_or(KernelError::Malformed)?,
            keepalive: fragment.keepalive.ok_or(KernelError::Malformed)?,
            handshake: fragment.handshake.ok_or(KernelError::Malformed)?,
            received_bytes: fragment.received_bytes.ok_or(KernelError::Malformed)?,
            transmitted_bytes: fragment.transmitted_bytes.ok_or(KernelError::Malformed)?,
            allowed_ips: fragment.allowed_ips,
            protocol_version: fragment.protocol_version,
        })
    }

    fn merge_allowed_ips(
        &mut self,
        continuation: Vec<WireguardAllowedIp>,
    ) -> Result<(), KernelError> {
        if continuation.is_empty()
            || self
                .allowed_ips
                .len()
                .checked_add(continuation.len())
                .is_none_or(|length| length > MAX_WIREGUARD_ALLOWED_IPS)
        {
            return Err(KernelError::Malformed);
        }
        for prefix in continuation {
            if self.allowed_ips.contains(&prefix) {
                return Err(KernelError::Malformed);
            }
            self.allowed_ips.push(prefix);
        }
        Ok(())
    }

    fn finish(self) -> Result<WireguardPeerState, KernelError> {
        if self.allowed_ips.is_empty() {
            return Err(KernelError::Malformed);
        }
        Ok(WireguardPeerState {
            public_key: self.public_key,
            endpoint: self.endpoint,
            persistent_keepalive_seconds: self.keepalive,
            last_handshake_seconds: self.handshake.0,
            last_handshake_nanoseconds: self.handshake.1,
            received_bytes: self.received_bytes,
            transmitted_bytes: self.transmitted_bytes,
            allowed_ips: self.allowed_ips,
            protocol_version: self.protocol_version,
        })
    }
}

fn parse_allowed_ips(bytes: &[u8]) -> Result<Vec<WireguardAllowedIp>, KernelError> {
    let mut result = Vec::new();
    for (kind, value) in attributes(bytes)? {
        if kind & !NLA_TYPE_MASK != NLA_F_NESTED || result.len() >= MAX_WIREGUARD_ALLOWED_IPS {
            return Err(KernelError::Malformed);
        }
        let mut family = None;
        let mut address = None;
        let mut prefix_length = None;
        for (raw_kind, attribute) in attributes(value)? {
            match plain_attribute_kind(raw_kind)? {
                WGALLOWEDIP_A_FAMILY => {
                    if family.replace(exact_u16(attribute)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGALLOWEDIP_A_IPADDR => {
                    if address.replace(attribute).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                WGALLOWEDIP_A_CIDR_MASK => {
                    if prefix_length.replace(exact_u8(attribute)?).is_some() {
                        return Err(KernelError::Malformed);
                    }
                }
                _ => return Err(KernelError::Malformed),
            }
        }
        let prefix = match (
            family.ok_or(KernelError::Malformed)?,
            address.ok_or(KernelError::Malformed)?,
            prefix_length.ok_or(KernelError::Malformed)?,
        ) {
            (family, address, prefix_length)
                if family == u16::try_from(libc::AF_INET).unwrap_or(u16::MAX)
                    && address.len() == 4
                    && prefix_length <= 32 =>
            {
                WireguardAllowedIp {
                    address: IpAddr::V4(Ipv4Addr::new(
                        address[0], address[1], address[2], address[3],
                    )),
                    prefix_length,
                }
            }
            (family, address, prefix_length)
                if family == u16::try_from(libc::AF_INET6).unwrap_or(u16::MAX)
                    && address.len() == 16
                    && prefix_length <= 128 =>
            {
                let octets: [u8; 16] = address.try_into().map_err(|_| KernelError::Malformed)?;
                WireguardAllowedIp {
                    address: IpAddr::V6(Ipv6Addr::from(octets)),
                    prefix_length,
                }
            }
            _ => return Err(KernelError::Malformed),
        };
        if result.contains(&prefix) {
            return Err(KernelError::Malformed);
        }
        result.push(prefix);
    }
    if result.is_empty() {
        return Err(KernelError::Malformed);
    }
    Ok(result)
}

fn parse_endpoint(value: &[u8]) -> Result<SocketAddr, KernelError> {
    let family = exact_u16(value.get(..2).ok_or(KernelError::Malformed)?)?;
    if family == u16::try_from(libc::AF_INET).unwrap_or(u16::MAX) && value.len() == 16 {
        let port = u16::from_be_bytes([value[2], value[3]]);
        let address = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
        if port == 0 || address.is_unspecified() || address.is_multicast() {
            return Err(KernelError::Malformed);
        }
        return Ok(SocketAddr::V4(SocketAddrV4::new(address, port)));
    }
    if family == u16::try_from(libc::AF_INET6).unwrap_or(u16::MAX) && value.len() == 28 {
        let port = u16::from_be_bytes([value[2], value[3]]);
        let flow_info = read_u32(value, 4).ok_or(KernelError::Malformed)?;
        let octets: [u8; 16] = value[8..24]
            .try_into()
            .map_err(|_| KernelError::Malformed)?;
        let address = Ipv6Addr::from(octets);
        let scope_id = read_u32(value, 24).ok_or(KernelError::Malformed)?;
        if port == 0 || address.is_unspecified() || address.is_multicast() {
            return Err(KernelError::Malformed);
        }
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            address, port, flow_info, scope_id,
        )));
    }
    Err(KernelError::Malformed)
}

fn parse_handshake(value: &[u8]) -> Result<(u64, u32), KernelError> {
    if value.len() != 16 {
        return Err(KernelError::Malformed);
    }
    let seconds = i64::from_ne_bytes(value[..8].try_into().map_err(|_| KernelError::Malformed)?);
    let nanoseconds =
        i64::from_ne_bytes(value[8..].try_into().map_err(|_| KernelError::Malformed)?);
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(KernelError::Malformed);
    }
    Ok((
        u64::try_from(seconds).map_err(|_| KernelError::Malformed)?,
        u32::try_from(nanoseconds).map_err(|_| KernelError::Malformed)?,
    ))
}

fn plain_attribute_kind(kind: u16) -> Result<u16, KernelError> {
    if kind & !NLA_TYPE_MASK != 0 {
        return Err(KernelError::Malformed);
    }
    Ok(kind)
}

fn strict_interface_name(value: &[u8]) -> Result<String, KernelError> {
    let bytes = value.strip_suffix(&[0]).ok_or(KernelError::Malformed)?;
    if bytes.is_empty()
        || bytes.len() > libc::IFNAMSIZ.saturating_sub(1)
        || bytes.contains(&0)
        || !bytes.is_ascii()
    {
        return Err(KernelError::Malformed);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| KernelError::Malformed)
}

fn exact_key(value: &[u8]) -> Result<[u8; 32], KernelError> {
    value.try_into().map_err(|_| KernelError::Malformed)
}

fn exact_u8(value: &[u8]) -> Result<u8, KernelError> {
    let [value] = value else {
        return Err(KernelError::Malformed);
    };
    Ok(*value)
}

fn exact_u16(value: &[u8]) -> Result<u16, KernelError> {
    let bytes: [u8; 2] = value.try_into().map_err(|_| KernelError::Malformed)?;
    Ok(u16::from_ne_bytes(bytes))
}

fn exact_u32(value: &[u8]) -> Result<u32, KernelError> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| KernelError::Malformed)?;
    Ok(u32::from_ne_bytes(bytes))
}

fn exact_u64(value: &[u8]) -> Result<u64, KernelError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| KernelError::Malformed)?;
    Ok(u64::from_ne_bytes(bytes))
}

const fn align4(value: usize) -> usize {
    (value + ATTRIBUTE_HEADER_LEN - 1) & !(ATTRIBUTE_HEADER_LEN - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::push_attribute;

    const TEST_SEQUENCE: u32 = 71;
    const TEST_FAMILY: u16 = 0x43;
    const TEST_PORT_ID: u32 = 7_171;
    const TEST_INTERFACE: &str = "vpwg-test";

    fn requires_zeroizing(_: &Zeroizing<Vec<u8>>) {}

    fn allowed_ip(address: &[u8], prefix_length: u8) -> Vec<u8> {
        let mut value = Vec::new();
        let family = if address.len() == 4 {
            u16::try_from(libc::AF_INET).expect("family")
        } else {
            u16::try_from(libc::AF_INET6).expect("family")
        };
        push_attribute(&mut value, WGALLOWEDIP_A_FAMILY, &family.to_ne_bytes())
            .expect("family attribute");
        push_attribute(&mut value, WGALLOWEDIP_A_IPADDR, address).expect("address attribute");
        push_attribute(&mut value, WGALLOWEDIP_A_CIDR_MASK, &[prefix_length])
            .expect("prefix attribute");
        value
    }

    fn allowed_ip_list(entries: &[(&[u8], u8)]) -> Vec<u8> {
        let mut value = Vec::new();
        for (position, (address, prefix_length)) in entries.iter().enumerate() {
            push_attribute(
                &mut value,
                u16::try_from(position + 1).expect("position") | NLA_F_NESTED,
                &allowed_ip(address, *prefix_length),
            )
            .expect("allowed IP wrapper");
        }
        value
    }

    fn endpoint() -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&u16::try_from(libc::AF_INET).expect("family").to_ne_bytes());
        value.extend_from_slice(&51_820_u16.to_be_bytes());
        value.extend_from_slice(&[8, 8, 8, 8]);
        value.extend_from_slice(&[0; 8]);
        value
    }

    fn full_peer(allowed: &[(&[u8], u8)]) -> Vec<u8> {
        let mut peer = Vec::new();
        push_attribute(&mut peer, WGPEER_A_PUBLIC_KEY, &[5; 32]).expect("peer public key");
        push_attribute(&mut peer, WGPEER_A_PRESHARED_KEY, &[0; 32]).expect("preshared key");
        push_attribute(&mut peer, WGPEER_A_ENDPOINT, &endpoint()).expect("endpoint");
        push_attribute(
            &mut peer,
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
            &15_u16.to_ne_bytes(),
        )
        .expect("keepalive");
        let mut handshake = Vec::new();
        handshake.extend_from_slice(&123_i64.to_ne_bytes());
        handshake.extend_from_slice(&456_i64.to_ne_bytes());
        push_attribute(&mut peer, WGPEER_A_LAST_HANDSHAKE_TIME, &handshake).expect("handshake");
        push_attribute(&mut peer, WGPEER_A_RX_BYTES, &11_u64.to_ne_bytes()).expect("rx");
        push_attribute(&mut peer, WGPEER_A_TX_BYTES, &12_u64.to_ne_bytes()).expect("tx");
        push_attribute(
            &mut peer,
            WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            &allowed_ip_list(allowed),
        )
        .expect("allowed IPs");
        push_attribute(&mut peer, WGPEER_A_PROTOCOL_VERSION, &1_u32.to_ne_bytes())
            .expect("protocol");
        peer
    }

    fn continuation_peer(allowed: &[(&[u8], u8)]) -> Vec<u8> {
        let mut peer = Vec::new();
        push_attribute(&mut peer, WGPEER_A_PUBLIC_KEY, &[5; 32]).expect("peer public key");
        push_attribute(
            &mut peer,
            WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            &allowed_ip_list(allowed),
        )
        .expect("allowed IPs");
        peer
    }

    fn peers_attribute(peer: &[u8]) -> Vec<u8> {
        let mut peers = Vec::new();
        push_attribute(&mut peers, 1 | NLA_F_NESTED, peer).expect("peer wrapper");
        peers
    }

    fn device_attributes(peer: Option<&[u8]>) -> Vec<u8> {
        let mut value = Vec::new();
        push_attribute(&mut value, WGDEVICE_A_IFINDEX, &17_u32.to_ne_bytes()).expect("ifindex");
        push_string_attribute(&mut value, WGDEVICE_A_IFNAME, TEST_INTERFACE).expect("ifname");
        push_attribute(&mut value, WGDEVICE_A_PRIVATE_KEY, &[3; 32]).expect("private key");
        push_attribute(&mut value, WGDEVICE_A_PUBLIC_KEY, &[4; 32]).expect("public key");
        push_attribute(
            &mut value,
            WGDEVICE_A_LISTEN_PORT,
            &51_820_u16.to_ne_bytes(),
        )
        .expect("listen port");
        push_attribute(&mut value, WGDEVICE_A_FWMARK, &0_u32.to_ne_bytes()).expect("fwmark");
        if let Some(peer) = peer {
            push_attribute(
                &mut value,
                WGDEVICE_A_PEERS | NLA_F_NESTED,
                &peers_attribute(peer),
            )
            .expect("peers");
        }
        value
    }

    fn continuation_attributes(peer: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        push_string_attribute(&mut value, WGDEVICE_A_IFNAME, TEST_INTERFACE).expect("ifname");
        push_attribute(
            &mut value,
            WGDEVICE_A_PEERS | NLA_F_NESTED,
            &peers_attribute(peer),
        )
        .expect("peers");
        value
    }

    fn data_frame(value: &[u8]) -> Vec<u8> {
        let mut payload = vec![WG_CMD_GET_DEVICE, WG_GENL_VERSION, 0, 0];
        payload.extend_from_slice(value);
        let mut frame = build_netlink_message(TEST_FAMILY, NLM_F_MULTI, TEST_SEQUENCE, &payload)
            .expect("data frame");
        frame[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        frame
    }

    fn done_frame(error: i32) -> Vec<u8> {
        let mut frame =
            build_netlink_message(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, &error.to_ne_bytes())
                .expect("done frame");
        frame[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        frame
    }

    fn reply(frames: &[Vec<u8>]) -> NetlinkReply {
        let mut message = Vec::new();
        for frame in frames {
            assert_eq!(frame.len(), align4(frame.len()));
            message.extend_from_slice(frame);
        }
        NetlinkReply {
            message: Zeroizing::new(message),
            sender: netlink_sys::SocketAddr::new(0, 0),
        }
    }

    fn parse(frames: &[Vec<u8>]) -> Result<WireguardDeviceState, KernelError> {
        let mut parser =
            WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)?;
        parser.ingest(&reply(frames))?;
        parser.finish()
    }

    fn valid_frames() -> Vec<Vec<u8>> {
        let overlay = [0xfd, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        vec![
            data_frame(&device_attributes(Some(&full_peer(&[(&overlay, 112)])))),
            done_frame(0),
        ]
    }

    #[test]
    fn complete_dump_extracts_public_state_from_zeroizing_buffers() {
        let state = parse(&valid_frames()).expect("valid state");
        assert_eq!(state.ifindex, 17);
        assert_eq!(state.interface_name, TEST_INTERFACE);
        assert_eq!(state.public_key, [4; 32]);
        assert_eq!(state.listen_port, 51_820);
        let peer = state.single_peer().expect("single peer");
        assert_eq!(peer.public_key, [5; 32]);
        assert_eq!(peer.endpoint, "8.8.8.8:51820".parse().expect("endpoint"));
        assert_eq!(peer.persistent_keepalive_seconds, 15);
        assert_eq!(
            (peer.last_handshake_seconds, peer.last_handshake_nanoseconds),
            (123, 456)
        );
        assert_eq!((peer.received_bytes, peer.transmitted_bytes), (11, 12));
        assert_eq!(peer.protocol_version, Some(1));
        assert_eq!(peer.allowed_ips.len(), 1);

        requires_zeroizing(&reply(&valid_frames()).message);
    }

    #[test]
    fn complete_peerless_dump_can_represent_a_fresh_unconfigured_device() {
        let mut fresh = Vec::new();
        push_attribute(&mut fresh, WGDEVICE_A_IFINDEX, &17_u32.to_ne_bytes()).expect("ifindex");
        push_string_attribute(&mut fresh, WGDEVICE_A_IFNAME, TEST_INTERFACE).expect("ifname");
        push_attribute(&mut fresh, WGDEVICE_A_LISTEN_PORT, &0_u16.to_ne_bytes())
            .expect("listen port");
        push_attribute(&mut fresh, WGDEVICE_A_FWMARK, &0_u32.to_ne_bytes()).expect("fwmark");
        let state = parse(&[data_frame(&fresh), done_frame(0)]).expect("fresh state");
        assert_eq!(state.public_key, [0; 32]);
        assert_eq!(state.listen_port, 0);
        assert_eq!(state.firewall_mark, 0);
        assert!(state.peers.is_empty());
    }

    #[test]
    fn continuation_coalesces_only_adjacent_allowed_ips() {
        let first = [0xfd, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let second = [0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frames = [
            data_frame(&device_attributes(Some(&full_peer(&[(&first, 112)])))),
            data_frame(&continuation_attributes(&continuation_peer(&[(
                &second, 112,
            )]))),
            done_frame(0),
        ];
        assert_eq!(
            parse(&frames)
                .expect("coalesced")
                .single_peer()
                .expect("peer")
                .allowed_ips
                .len(),
            2
        );

        let mut invalid = continuation_peer(&[(&second, 112)]);
        push_attribute(&mut invalid, WGPEER_A_ENDPOINT, &endpoint()).expect("endpoint");
        assert!(
            parse(&[
                data_frame(&device_attributes(Some(&full_peer(&[(&first, 112)])))),
                data_frame(&continuation_attributes(&invalid)),
                done_frame(0),
            ])
            .is_err()
        );
    }

    #[test]
    fn header_is_bound_to_sender_sequence_pid_family_command_version_and_flags() {
        let reject = |response: NetlinkReply| {
            let mut parser =
                WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                    .expect("parser");
            assert!(parser.ingest(&response).is_err());
        };
        let mut response = reply(&valid_frames());
        response.sender = netlink_sys::SocketAddr::new(7, 0);
        reject(response);
        response = reply(&valid_frames());
        response.sender = netlink_sys::SocketAddr::new(0, 1);
        reject(response);

        for (offset, bytes) in [
            (8, (TEST_SEQUENCE + 1).to_ne_bytes().to_vec()),
            (4, (TEST_FAMILY + 1).to_ne_bytes().to_vec()),
            (6, 0_u16.to_ne_bytes().to_vec()),
            (NLMSG_HEADER_LEN, vec![WG_CMD_GET_DEVICE + 1]),
            (NLMSG_HEADER_LEN + 1, vec![WG_GENL_VERSION + 1]),
            (NLMSG_HEADER_LEN + 2, 1_u16.to_ne_bytes().to_vec()),
        ] {
            response = reply(&valid_frames());
            response.message[offset..offset + bytes.len()].copy_from_slice(&bytes);
            reject(response);
        }
        for wrong_port_id in [0, 1, TEST_PORT_ID + 1] {
            response = reply(&valid_frames());
            response.message[12..16].copy_from_slice(&wrong_port_id.to_ne_bytes());
            reject(response);

            let mut frames = valid_frames();
            frames[1][12..16].copy_from_slice(&wrong_port_id.to_ne_bytes());
            reject(reply(&frames));
        }
        assert!(WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, 0).is_err());
    }

    #[test]
    fn dump_requires_clean_done_and_processes_done_error() {
        let frames = valid_frames();
        let mut parser =
            WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                .expect("parser");
        parser.ingest(&reply(&frames[..1])).expect("data");
        assert!(parser.finish().is_err());

        for (error, expected_errno) in [(-libc::EPERM, true), (libc::EPERM, false)] {
            let mut parser =
                WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                    .expect("parser");
            let result = parser.ingest(&reply(&[frames[0].clone(), done_frame(error)]));
            if expected_errno {
                assert!(matches!(result, Err(KernelError::Errno(libc::EPERM))));
            } else {
                assert!(matches!(result, Err(KernelError::Malformed)));
            }
        }

        let mut parser =
            WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                .expect("parser");
        assert!(
            parser
                .ingest(&reply(&[
                    frames[0].clone(),
                    done_frame(0),
                    frames[0].clone()
                ]))
                .is_err()
        );
    }

    #[test]
    fn duplicate_unknown_and_conflicting_attribute_flags_fail_closed() {
        let base_peer = full_peer(&[(&[10, 0, 0, 0], 8)]);
        let mut duplicate = device_attributes(Some(&base_peer));
        push_attribute(&mut duplicate, WGDEVICE_A_IFINDEX, &17_u32.to_ne_bytes())
            .expect("duplicate");
        assert!(parse(&[data_frame(&duplicate), done_frame(0)]).is_err());

        let mut unknown = device_attributes(Some(&base_peer));
        push_attribute(&mut unknown, 99, &[1]).expect("unknown");
        assert!(parse(&[data_frame(&unknown), done_frame(0)]).is_err());

        let mut duplicate_peer = base_peer;
        push_attribute(
            &mut duplicate_peer,
            WGPEER_A_RX_BYTES,
            &11_u64.to_ne_bytes(),
        )
        .expect("duplicate rx");
        assert!(
            parse(&[
                data_frame(&device_attributes(Some(&duplicate_peer))),
                done_frame(0)
            ])
            .is_err()
        );

        let mut flagged = Vec::new();
        push_string_attribute(&mut flagged, WGDEVICE_A_IFNAME, TEST_INTERFACE).expect("ifname");
        push_attribute(&mut flagged, WGDEVICE_A_PUBLIC_KEY | NLA_F_NESTED, &[4; 32])
            .expect("flagged");
        assert!(parse(&[data_frame(&flagged), done_frame(0)]).is_err());
    }

    #[test]
    fn exact_interface_key_port_and_peer_completeness_are_required() {
        let device = device_attributes(Some(&full_peer(&[(&[10, 0, 0, 0], 8)])));
        for missing in [
            WGDEVICE_A_IFINDEX,
            WGDEVICE_A_LISTEN_PORT,
            WGDEVICE_A_FWMARK,
        ] {
            let mut filtered = Vec::new();
            for (kind, value) in attributes(&device).expect("attributes") {
                if kind & NLA_TYPE_MASK != missing {
                    push_attribute(&mut filtered, kind, value).expect("copy");
                }
            }
            assert!(
                parse(&[data_frame(&filtered), done_frame(0)]).is_err(),
                "attribute {missing} must be required"
            );
        }

        for missing_key in [WGDEVICE_A_PRIVATE_KEY, WGDEVICE_A_PUBLIC_KEY] {
            let mut one_sided = Vec::new();
            for (kind, value) in attributes(&device).expect("attributes") {
                if kind & NLA_TYPE_MASK != missing_key {
                    push_attribute(&mut one_sided, kind, value).expect("copy");
                }
            }
            assert!(
                parse(&[data_frame(&one_sided), done_frame(0)]).is_err(),
                "one-sided key attribute {missing_key} must fail closed"
            );
        }

        let mut zero_public_key = Vec::new();
        for (kind, value) in attributes(&device).expect("attributes") {
            let value = if kind & NLA_TYPE_MASK == WGDEVICE_A_PUBLIC_KEY {
                &[0; 32][..]
            } else {
                value
            };
            push_attribute(&mut zero_public_key, kind, value).expect("copy");
        }
        assert!(parse(&[data_frame(&zero_public_key), done_frame(0)]).is_err());

        let mut zero_private_key = Vec::new();
        for (kind, value) in attributes(&device).expect("attributes") {
            let value = if kind & NLA_TYPE_MASK == WGDEVICE_A_PRIVATE_KEY {
                &[0; 32][..]
            } else {
                value
            };
            push_attribute(&mut zero_private_key, kind, value).expect("copy");
        }
        assert!(parse(&[data_frame(&zero_private_key), done_frame(0)]).is_err());

        let mut zero_key_pair = Vec::new();
        for (kind, value) in attributes(&device).expect("attributes") {
            let value = if matches!(
                kind & NLA_TYPE_MASK,
                WGDEVICE_A_PRIVATE_KEY | WGDEVICE_A_PUBLIC_KEY
            ) {
                &[0; 32][..]
            } else {
                value
            };
            push_attribute(&mut zero_key_pair, kind, value).expect("copy");
        }
        assert!(parse(&[data_frame(&zero_key_pair), done_frame(0)]).is_err());

        let state = parse(&[data_frame(&device_attributes(None)), done_frame(0)])
            .expect("peerless prepare proof");
        assert!(state.single_peer().is_err());
    }

    #[test]
    fn frame_and_byte_bounds_are_fail_closed() {
        let mut parser =
            WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                .expect("parser");
        let mut name_only = Vec::new();
        push_string_attribute(&mut name_only, WGDEVICE_A_IFNAME, TEST_INTERFACE).expect("ifname");
        for _ in 0..MAX_WIREGUARD_DUMP_FRAMES {
            parser
                .ingest(&reply(&[data_frame(&name_only)]))
                .expect("bounded frame");
        }
        assert!(parser.ingest(&reply(&[done_frame(0)])).is_err());

        let mut oversized = reply(&[data_frame(&name_only)]);
        oversized.message.resize(MAX_WIREGUARD_DUMP_BYTES + 1, 0);
        let mut parser =
            WireguardDumpParser::new(TEST_SEQUENCE, TEST_FAMILY, TEST_INTERFACE, TEST_PORT_ID)
                .expect("parser");
        assert!(parser.ingest(&oversized).is_err());
    }
}
