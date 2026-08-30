//! Strict Debian 13 IPv6-forwarding readback for one authenticated worker namespace.
//!
//! Linux 6.12 exposes forwarding state through `RTM_GETNETCONF`, but it has no
//! corresponding rtnetlink setter. Mutation therefore belongs to the worker's
//! still-root, post-`CLONE_NEWNET` sandbox transition. This module contains the
//! canonical query/response codec and a fresh, bounded read-only client used
//! after the identity drop; it cannot request a forwarding change or turn an
//! unsupported request into success.

use std::{io, num::NonZeroI32};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{libc, poll::PollFlags};
use thiserror::Error;

use crate::deadline::{HardDeadline, wait_for_fd};

const MAX_DATAGRAM_BYTES: usize = 256;
const MAX_FRAME_BYTES: usize = 256;
const NLMSG_HEADER_LEN: usize = 16;
const NLM_F_REQUEST: u16 = 0x0001;
const NLMSG_ERROR: u16 = 2;
const OBSERVATION_SEQUENCE: u32 = 1;

const AF_INET6_UAPI: u8 = 10;
const NETCONFMSG_ALIGNED_LEN: usize = 4;
const NLA_HEADER_LEN: usize = 4;
const NLA_ALIGN_TO: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
const NETCONFA_IFINDEX: u16 = 1;
const NETCONFA_FORWARDING: u16 = 2;
const NETCONFA_MC_FORWARDING: u16 = 4;
const NETCONFA_PROXY_NEIGH: u16 = 5;
const NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN: u16 = 6;
const NETCONFA_IFINDEX_ALL: i32 = -1;
const NETCONFA_IFINDEX_DEFAULT: i32 = -2;

/// Debian 13 Linux UAPI message type for one exact IPv6 netconf query.
const RTM_GETNETCONF: u16 = 82;

/// Debian 13 Linux UAPI response type for one IPv6 netconf observation.
const RTM_NEWNETCONF: u16 = 80;

/// Fixed, non-sensitive failure while observing one IPv6-forwarding selector.
#[derive(Debug, Error)]
pub(super) enum Ipv6ForwardingObservationError {
    /// Socket setup, bounded I/O or the caller-supplied deadline failed.
    #[error("IPv6 netconf observation I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected the exact read-only request.
    #[error("IPv6 netconf observation was rejected by the kernel")]
    Kernel(i32),
    /// Sender, correlation, framing or the response shape was ambiguous.
    #[error("IPv6 netconf observation was malformed or ambiguous")]
    Malformed,
    /// A datagram or frame exceeded its fixed production bound.
    #[error("IPv6 netconf observation exceeded its fixed bound")]
    Limit,
    /// The exact netconf payload was invalid for Debian 13.
    #[error("IPv6 netconf observation payload was invalid")]
    Codec(Ipv6NetconfCodecError),
}

impl From<Ipv6NetconfCodecError> for Ipv6ForwardingObservationError {
    fn from(error: Ipv6NetconfCodecError) -> Self {
        Self::Codec(error)
    }
}

/// Exact forwarding selector supported by the Linux 6.12 IPv6 netconf API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Ipv6NetconfSelector(Ipv6NetconfSelectorKind);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ipv6NetconfSelectorKind {
    All,
    Default,
    Interface(NonZeroI32),
}

impl Ipv6NetconfSelector {
    /// Select global `conf/all/forwarding` state.
    pub(super) const fn all() -> Self {
        Self(Ipv6NetconfSelectorKind::All)
    }

    /// Select inheritance state for interfaces created later in this namespace.
    pub(super) const fn default() -> Self {
        Self(Ipv6NetconfSelectorKind::Default)
    }

    /// Construct an interface selector without accepting zero or signed overflow.
    pub(super) fn interface(ifindex: u32) -> Result<Self, Ipv6NetconfCodecError> {
        let ifindex = i32::try_from(ifindex).map_err(|_| Ipv6NetconfCodecError::InvalidSelector)?;
        NonZeroI32::new(ifindex)
            .map(|ifindex| Self(Ipv6NetconfSelectorKind::Interface(ifindex)))
            .ok_or(Ipv6NetconfCodecError::InvalidSelector)
    }

    const fn encoded_ifindex(self) -> i32 {
        match self.0 {
            Ipv6NetconfSelectorKind::All => NETCONFA_IFINDEX_ALL,
            Ipv6NetconfSelectorKind::Default => NETCONFA_IFINDEX_DEFAULT,
            Ipv6NetconfSelectorKind::Interface(ifindex) => ifindex.get(),
        }
    }
}

/// Canonical forwarding state accepted from kernel readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ipv6ForwardingState {
    /// IPv6 forwarding is disabled.
    Disabled,
    /// IPv6 forwarding is enabled, subject to the separately proven nftables fence.
    Enabled,
}

impl Ipv6ForwardingState {
    fn from_i32(value: i32) -> Result<Self, Ipv6NetconfCodecError> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Enabled),
            _ => Err(Ipv6NetconfCodecError::NonCanonical),
        }
    }
}

/// Strict failure while encoding or parsing one IPv6 netconf payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ipv6NetconfCodecError {
    /// An interface selector was zero or exceeded Linux's signed ifindex range.
    InvalidSelector,
    /// A required header or attribute was truncated.
    Truncated,
    /// A length, flag, order, duplicate, value, or padding byte was malformed.
    Malformed,
    /// The pinned Debian 13 response contained an unknown attribute.
    Unsupported,
    /// The response described another address family or selector.
    Mismatch,
    /// The authoritative forwarding value was not exactly zero or one.
    NonCanonical,
}

/// Encode one exact, non-dump `RTM_GETNETCONF` request payload.
///
/// The bounded route-netlink client supplies `NLM_F_REQUEST`, sequence and
/// port-ID correlation, kernel-unicast sender validation, the outer deadline,
/// and an exact-one-frame response requirement.
fn encode_ipv6_forwarding_query(selector: Ipv6NetconfSelector) -> Vec<u8> {
    let mut payload = Vec::with_capacity(NETCONFMSG_ALIGNED_LEN + 8);
    payload.extend_from_slice(&[AF_INET6_UAPI, 0, 0, 0]);
    push_i32_attribute(&mut payload, NETCONFA_IFINDEX, selector.encoded_ifindex());
    payload
}

/// Decode one exact Debian 13 `RTM_NEWNETCONF` payload.
///
/// Linux 6.12 emits the selector, forwarding, proxy-neighbour and
/// ignore-routes-with-linkdown attributes. Multicast forwarding is emitted only
/// when the kernel was built with IPv6 multicast routing. Non-authoritative
/// fields are parsed exactly but their integer values do not affect the result.
/// Unknown fields fail closed against the pinned kernel.
fn decode_ipv6_forwarding_response(
    payload: &[u8],
    expected: Ipv6NetconfSelector,
) -> Result<Ipv6ForwardingState, Ipv6NetconfCodecError> {
    if payload.len() < NETCONFMSG_ALIGNED_LEN {
        return Err(Ipv6NetconfCodecError::Truncated);
    }
    if payload[0] != AF_INET6_UAPI {
        return Err(Ipv6NetconfCodecError::Mismatch);
    }
    if payload[1..NETCONFMSG_ALIGNED_LEN] != [0, 0, 0] {
        return Err(Ipv6NetconfCodecError::Malformed);
    }

    let mut remaining = &payload[NETCONFMSG_ALIGNED_LEN..];
    let mut previous_kind = 0_u16;
    let mut observed_ifindex = None;
    let mut forwarding = None;
    let mut observed_proxy_neigh = false;
    let mut observed_ignore_routes_with_linkdown = false;
    while !remaining.is_empty() {
        if remaining.len() < NLA_HEADER_LEN {
            return Err(Ipv6NetconfCodecError::Truncated);
        }
        let length = usize::from(u16::from_ne_bytes([remaining[0], remaining[1]]));
        let raw_kind = u16::from_ne_bytes([remaining[2], remaining[3]]);
        if length < NLA_HEADER_LEN || length > remaining.len() {
            return Err(Ipv6NetconfCodecError::Malformed);
        }
        if raw_kind & !NLA_TYPE_MASK != 0 {
            return Err(Ipv6NetconfCodecError::Malformed);
        }
        let kind = raw_kind & NLA_TYPE_MASK;
        if kind <= previous_kind {
            return Err(Ipv6NetconfCodecError::Malformed);
        }
        previous_kind = kind;

        let aligned = nla_align(length).ok_or(Ipv6NetconfCodecError::Malformed)?;
        if aligned > remaining.len() {
            return Err(Ipv6NetconfCodecError::Truncated);
        }
        if remaining[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(Ipv6NetconfCodecError::Malformed);
        }
        let value = exact_i32(&remaining[NLA_HEADER_LEN..length])?;
        match kind {
            NETCONFA_IFINDEX => observed_ifindex = Some(value),
            NETCONFA_FORWARDING => {
                forwarding = Some(Ipv6ForwardingState::from_i32(value)?);
            }
            NETCONFA_MC_FORWARDING => {}
            NETCONFA_PROXY_NEIGH => observed_proxy_neigh = true,
            NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN => {
                observed_ignore_routes_with_linkdown = true;
            }
            _ => return Err(Ipv6NetconfCodecError::Unsupported),
        }
        remaining = &remaining[aligned..];
    }

    if observed_ifindex != Some(expected.encoded_ifindex()) {
        return Err(Ipv6NetconfCodecError::Mismatch);
    }
    if !observed_proxy_neigh || !observed_ignore_routes_with_linkdown {
        return Err(Ipv6NetconfCodecError::Malformed);
    }
    forwarding.ok_or(Ipv6NetconfCodecError::Malformed)
}

/// Observe one exact IPv6-forwarding selector through a fresh route-netlink socket.
///
/// This is a single non-dump request. The client accepts only one kernel-unicast
/// `RTM_NEWNETCONF` response (or its exact correlated `NLMSG_ERROR`) under the
/// caller's unchanged deadline. It has no mutation operation.
pub(super) fn observe_ipv6_forwarding(
    selector: Ipv6NetconfSelector,
    deadline: HardDeadline,
) -> Result<Ipv6ForwardingState, Ipv6ForwardingObservationError> {
    deadline.ensure_remaining()?;
    let client = NetconfObservationClient::connect(deadline)?;
    observe_with_transport(&client, selector, deadline)
}

trait NetconfObservationTransport {
    fn local_port_id(&self) -> u32;

    fn send_request(
        &self,
        request: &[u8],
        deadline: HardDeadline,
    ) -> Result<(), Ipv6ForwardingObservationError>;

    fn receive_response(
        &self,
        deadline: HardDeadline,
    ) -> Result<(Vec<u8>, SocketAddr), Ipv6ForwardingObservationError>;
}

struct NetconfObservationClient {
    socket: Socket,
    local_port_id: u32,
}

impl NetconfObservationClient {
    fn connect(deadline: HardDeadline) -> Result<Self, Ipv6ForwardingObservationError> {
        deadline.ensure_remaining()?;
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        deadline.ensure_remaining()?;
        socket.set_non_blocking(true)?;
        deadline.ensure_remaining()?;
        // Debian 13 supports strict request validation. Failure to enable it is
        // not silently downgraded to a less strict observation.
        socket.set_netlink_get_strict_chk(true)?;
        deadline.ensure_remaining()?;
        let address = socket.bind_auto()?;
        let local_port_id = address.port_number();
        if local_port_id == 0 || address.multicast_groups() != 0 {
            return Err(Ipv6ForwardingObservationError::Malformed);
        }
        deadline.ensure_remaining()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
            local_port_id,
        })
    }
}

impl NetconfObservationTransport for NetconfObservationClient {
    fn local_port_id(&self) -> u32 {
        self.local_port_id
    }

    fn send_request(
        &self,
        request: &[u8],
        deadline: HardDeadline,
    ) -> Result<(), Ipv6ForwardingObservationError> {
        loop {
            deadline.ensure_remaining()?;
            match self.socket.send(request, 0) {
                Ok(written) if written == request.len() => return Ok(deadline.complete(())?),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short IPv6 netconf request",
                    )
                    .into());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_for_fd(&self.socket, PollFlags::POLLOUT, deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn receive_response(
        &self,
        deadline: HardDeadline,
    ) -> Result<(Vec<u8>, SocketAddr), Ipv6ForwardingObservationError> {
        loop {
            wait_for_fd(&self.socket, PollFlags::POLLIN, deadline)?;
            deadline.ensure_remaining()?;
            let mut probe = Vec::new();
            let (length, peek_sender) = match self
                .socket
                .recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC)
            {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if peek_sender != SocketAddr::new(0, 0) {
                return Err(Ipv6ForwardingObservationError::Malformed);
            }
            if length > MAX_DATAGRAM_BYTES {
                return Err(Ipv6ForwardingObservationError::Limit);
            }
            if length < NLMSG_HEADER_LEN {
                return Err(Ipv6ForwardingObservationError::Malformed);
            }
            deadline.ensure_remaining()?;
            let mut bytes = Vec::with_capacity(length);
            let (received, sender) = match self.socket.recv_from(&mut bytes, 0) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            deadline.ensure_remaining()?;
            if received != length || bytes.len() != received || sender != peek_sender {
                return Err(Ipv6ForwardingObservationError::Malformed);
            }
            return Ok((bytes, sender));
        }
    }
}

fn observe_with_transport<T: NetconfObservationTransport>(
    transport: &T,
    selector: Ipv6NetconfSelector,
    deadline: HardDeadline,
) -> Result<Ipv6ForwardingState, Ipv6ForwardingObservationError> {
    deadline.ensure_remaining()?;
    let local_port_id = transport.local_port_id();
    if local_port_id == 0 {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    let request = encode_netlink_query(selector, OBSERVATION_SEQUENCE)?;
    transport.send_request(&request, deadline)?;
    let (datagram, sender) = transport.receive_response(deadline)?;
    let observed = decode_observation_datagram(
        sender,
        &datagram,
        selector,
        OBSERVATION_SEQUENCE,
        local_port_id,
        &request,
    )?;
    Ok(deadline.complete(observed)?)
}

fn encode_netlink_query(
    selector: Ipv6NetconfSelector,
    sequence: u32,
) -> Result<Vec<u8>, Ipv6ForwardingObservationError> {
    if sequence == 0 {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    let payload = encode_ipv6_forwarding_query(selector);
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Ipv6ForwardingObservationError::Limit)?;
    if length > MAX_FRAME_BYTES {
        return Err(Ipv6ForwardingObservationError::Limit);
    }
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| Ipv6ForwardingObservationError::Limit)?
            .to_ne_bytes(),
    );
    request.extend_from_slice(&RTM_GETNETCONF.to_ne_bytes());
    request.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&payload);
    Ok(request)
}

fn decode_observation_datagram(
    sender: SocketAddr,
    datagram: &[u8],
    selector: Ipv6NetconfSelector,
    sequence: u32,
    local_port_id: u32,
    request: &[u8],
) -> Result<Ipv6ForwardingState, Ipv6ForwardingObservationError> {
    if sender != SocketAddr::new(0, 0) || sequence == 0 || local_port_id == 0 {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    if datagram.len() > MAX_DATAGRAM_BYTES {
        return Err(Ipv6ForwardingObservationError::Limit);
    }
    let frame = exact_single_frame(datagram)?;
    if read_u32(frame, 8)? != sequence
        || read_u32(frame, 12)? != local_port_id
        || read_u16(frame, 6)? != 0
    {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    match read_u16(frame, 4)? {
        RTM_NEWNETCONF => Ok(decode_ipv6_forwarding_response(
            &frame[NLMSG_HEADER_LEN..],
            selector,
        )?),
        NLMSG_ERROR => decode_correlated_error(&frame[NLMSG_HEADER_LEN..], request),
        _ => Err(Ipv6ForwardingObservationError::Malformed),
    }
}

fn exact_single_frame(datagram: &[u8]) -> Result<&[u8], Ipv6ForwardingObservationError> {
    if datagram.len() < NLMSG_HEADER_LEN {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    let frame_length = usize::try_from(read_u32(datagram, 0)?)
        .map_err(|_| Ipv6ForwardingObservationError::Limit)?;
    if !(NLMSG_HEADER_LEN..=MAX_FRAME_BYTES).contains(&frame_length)
        || frame_length > datagram.len()
    {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    let aligned = align4(frame_length)?;
    if aligned != datagram.len() || datagram[frame_length..].iter().any(|byte| *byte != 0) {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    Ok(&datagram[..frame_length])
}

fn decode_correlated_error(
    payload: &[u8],
    request: &[u8],
) -> Result<Ipv6ForwardingState, Ipv6ForwardingObservationError> {
    if payload.len() != 4 + request.len() || payload[4..] != *request {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    let errno = read_i32(payload, 0)?;
    if errno >= 0 {
        return Err(Ipv6ForwardingObservationError::Malformed);
    }
    Err(Ipv6ForwardingObservationError::Kernel(
        errno.saturating_abs(),
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Ipv6ForwardingObservationError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(Ipv6ForwardingObservationError::Malformed)?;
    Ok(u16::from_ne_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Ipv6ForwardingObservationError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(Ipv6ForwardingObservationError::Malformed)?
        .try_into()
        .map_err(|_| Ipv6ForwardingObservationError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, Ipv6ForwardingObservationError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(Ipv6ForwardingObservationError::Malformed)?
        .try_into()
        .map_err(|_| Ipv6ForwardingObservationError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn align4(length: usize) -> Result<usize, Ipv6ForwardingObservationError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(Ipv6ForwardingObservationError::Limit)
}

fn push_i32_attribute(payload: &mut Vec<u8>, kind: u16, value: i32) {
    payload.extend_from_slice(&8_u16.to_ne_bytes());
    payload.extend_from_slice(&kind.to_ne_bytes());
    payload.extend_from_slice(&value.to_ne_bytes());
}

fn exact_i32(value: &[u8]) -> Result<i32, Ipv6NetconfCodecError> {
    let value: [u8; 4] = value
        .try_into()
        .map_err(|_| Ipv6NetconfCodecError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn nla_align(length: usize) -> Option<usize> {
    length
        .checked_add(NLA_ALIGN_TO - 1)
        .map(|value| value & !(NLA_ALIGN_TO - 1))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, time::Duration};

    use super::*;

    const CLIENT_IFINDEX: u32 = 7;
    const TEST_PORT_ID: u32 = 41;

    fn selector() -> Ipv6NetconfSelector {
        Ipv6NetconfSelector::interface(CLIENT_IFINDEX).expect("valid test ifindex")
    }

    fn append_attr(payload: &mut Vec<u8>, kind: u16, value: i32) {
        push_i32_attribute(payload, kind, value);
    }

    fn response_without_multicast(selector: Ipv6NetconfSelector, forwarding: i32) -> Vec<u8> {
        let mut payload = vec![AF_INET6_UAPI, 0, 0, 0];
        append_attr(&mut payload, NETCONFA_IFINDEX, selector.encoded_ifindex());
        append_attr(&mut payload, NETCONFA_FORWARDING, forwarding);
        append_attr(&mut payload, NETCONFA_PROXY_NEIGH, 0);
        append_attr(&mut payload, NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN, 0);
        payload
    }

    fn response(selector: Ipv6NetconfSelector, forwarding: i32) -> Vec<u8> {
        let mut payload = vec![AF_INET6_UAPI, 0, 0, 0];
        append_attr(&mut payload, NETCONFA_IFINDEX, selector.encoded_ifindex());
        append_attr(&mut payload, NETCONFA_FORWARDING, forwarding);
        append_attr(&mut payload, NETCONFA_MC_FORWARDING, 0);
        append_attr(&mut payload, NETCONFA_PROXY_NEIGH, 0);
        append_attr(&mut payload, NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN, 0);
        payload
    }

    fn netlink_frame(
        message_type: u16,
        flags: u16,
        sequence: u32,
        port_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut frame = Vec::with_capacity(align4(length).expect("bounded test frame"));
        frame.extend_from_slice(
            &u32::try_from(length)
                .expect("bounded test frame")
                .to_ne_bytes(),
        );
        frame.extend_from_slice(&message_type.to_ne_bytes());
        frame.extend_from_slice(&flags.to_ne_bytes());
        frame.extend_from_slice(&sequence.to_ne_bytes());
        frame.extend_from_slice(&port_id.to_ne_bytes());
        frame.extend_from_slice(payload);
        frame.resize(align4(length).expect("bounded test frame"), 0);
        frame
    }

    fn observation_datagram(
        selected: Ipv6NetconfSelector,
        forwarding: i32,
        sequence: u32,
        port_id: u32,
    ) -> Vec<u8> {
        netlink_frame(
            RTM_NEWNETCONF,
            0,
            sequence,
            port_id,
            &response(selected, forwarding),
        )
    }

    fn assert_malformed(result: &Result<Ipv6ForwardingState, Ipv6ForwardingObservationError>) {
        assert!(matches!(
            result,
            Err(Ipv6ForwardingObservationError::Malformed)
        ));
    }

    struct InjectedTransport {
        local_port_id: u32,
        response: RefCell<Option<(Vec<u8>, SocketAddr)>>,
        sent: RefCell<Vec<Vec<u8>>>,
        deadlines: RefCell<Vec<HardDeadline>>,
        time_out_send: bool,
    }

    impl InjectedTransport {
        fn responding(bytes: Vec<u8>) -> Self {
            Self {
                local_port_id: TEST_PORT_ID,
                response: RefCell::new(Some((bytes, SocketAddr::new(0, 0)))),
                sent: RefCell::new(Vec::new()),
                deadlines: RefCell::new(Vec::new()),
                time_out_send: false,
            }
        }
    }

    impl NetconfObservationTransport for InjectedTransport {
        fn local_port_id(&self) -> u32 {
            self.local_port_id
        }

        fn send_request(
            &self,
            request: &[u8],
            deadline: HardDeadline,
        ) -> Result<(), Ipv6ForwardingObservationError> {
            self.deadlines.borrow_mut().push(deadline);
            if self.time_out_send {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "injected timeout").into());
            }
            self.sent.borrow_mut().push(request.to_vec());
            Ok(())
        }

        fn receive_response(
            &self,
            deadline: HardDeadline,
        ) -> Result<(Vec<u8>, SocketAddr), Ipv6ForwardingObservationError> {
            self.deadlines.borrow_mut().push(deadline);
            self.response
                .borrow_mut()
                .take()
                .ok_or(Ipv6ForwardingObservationError::Malformed)
        }
    }

    #[test]
    fn selectors_reject_zero_and_signed_overflow() {
        assert_eq!(
            Ipv6NetconfSelector::interface(0),
            Err(Ipv6NetconfCodecError::InvalidSelector)
        );
        assert_eq!(
            Ipv6NetconfSelector::interface(i32::MAX as u32 + 1),
            Err(Ipv6NetconfCodecError::InvalidSelector)
        );
        assert_eq!(
            selector().encoded_ifindex(),
            i32::try_from(CLIENT_IFINDEX).expect("bounded test ifindex")
        );
        assert_eq!(Ipv6NetconfSelector::all().encoded_ifindex(), -1);
        assert_eq!(Ipv6NetconfSelector::default().encoded_ifindex(), -2);
    }

    #[test]
    fn queries_are_exact_for_all_default_and_interface() {
        for selected in [
            Ipv6NetconfSelector::all(),
            Ipv6NetconfSelector::default(),
            selector(),
        ] {
            let mut expected = vec![AF_INET6_UAPI, 0, 0, 0];
            append_attr(&mut expected, NETCONFA_IFINDEX, selected.encoded_ifindex());
            assert_eq!(encode_ipv6_forwarding_query(selected), expected);
        }
        assert_eq!(RTM_GETNETCONF, 82);
        assert_eq!(RTM_NEWNETCONF, 80);
    }

    #[test]
    fn netlink_query_has_only_the_exact_request_header_and_payload() {
        let selected = selector();
        let request = encode_netlink_query(selected, OBSERVATION_SEQUENCE).expect("query");
        assert_eq!(
            usize::try_from(read_u32(&request, 0).expect("length")).expect("usize"),
            request.len()
        );
        assert_eq!(read_u16(&request, 4).expect("type"), RTM_GETNETCONF);
        assert_eq!(read_u16(&request, 6).expect("flags"), NLM_F_REQUEST);
        assert_eq!(
            read_u32(&request, 8).expect("sequence"),
            OBSERVATION_SEQUENCE
        );
        assert_eq!(read_u32(&request, 12).expect("port"), 0);
        assert_eq!(
            &request[NLMSG_HEADER_LEN..],
            encode_ipv6_forwarding_query(selected)
        );
        assert!(matches!(
            encode_netlink_query(selected, 0),
            Err(Ipv6ForwardingObservationError::Malformed)
        ));
    }

    #[test]
    fn injected_client_uses_one_unchanged_deadline_and_one_exact_reply() {
        let selected = selector();
        let transport = InjectedTransport::responding(observation_datagram(
            selected,
            1,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
        ));
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("deadline");
        assert!(matches!(
            observe_with_transport(&transport, selected, deadline),
            Ok(Ipv6ForwardingState::Enabled)
        ));
        assert_eq!(
            transport.deadlines.borrow().as_slice(),
            &[deadline, deadline]
        );
        assert_eq!(transport.sent.borrow().len(), 1);
        assert_eq!(
            transport.sent.borrow()[0],
            encode_netlink_query(selected, OBSERVATION_SEQUENCE).expect("query")
        );
        assert!(transport.response.borrow().is_none());
    }

    #[test]
    fn injected_deadline_failure_is_not_refreshed_or_reclassified() {
        let selected = selector();
        let mut transport = InjectedTransport::responding(observation_datagram(
            selected,
            1,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
        ));
        transport.time_out_send = true;
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("deadline");
        let error = observe_with_transport(&transport, selected, deadline)
            .expect_err("injected send must time out");
        match error {
            Ipv6ForwardingObservationError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(transport.deadlines.borrow().as_slice(), &[deadline]);
        assert!(transport.response.borrow().is_some());
    }

    #[test]
    fn observer_rejects_wrong_sender_sequence_port_type_and_flags() {
        let selected = selector();
        let request = encode_netlink_query(selected, OBSERVATION_SEQUENCE).expect("query");
        let valid = observation_datagram(selected, 1, OBSERVATION_SEQUENCE, TEST_PORT_ID);

        assert_malformed(&decode_observation_datagram(
            SocketAddr::new(9, 0),
            &valid,
            selected,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
            &request,
        ));
        assert_malformed(&decode_observation_datagram(
            SocketAddr::new(0, 1),
            &valid,
            selected,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
            &request,
        ));

        for (offset, bytes) in [
            (8, 2_u32.to_ne_bytes().to_vec()),
            (12, (TEST_PORT_ID + 1).to_ne_bytes().to_vec()),
            (4, (RTM_NEWNETCONF + 1).to_ne_bytes().to_vec()),
            (6, 2_u16.to_ne_bytes().to_vec()),
        ] {
            let mut malformed = valid.clone();
            malformed[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert_malformed(&decode_observation_datagram(
                SocketAddr::new(0, 0),
                &malformed,
                selected,
                OBSERVATION_SEQUENCE,
                TEST_PORT_ID,
                &request,
            ));
        }
    }

    #[test]
    fn observer_accepts_only_an_exact_correlated_negative_kernel_error() {
        let selected = selector();
        let request = encode_netlink_query(selected, OBSERVATION_SEQUENCE).expect("query");
        let mut payload = (-libc::EPERM).to_ne_bytes().to_vec();
        payload.extend_from_slice(&request);
        let valid = netlink_frame(NLMSG_ERROR, 0, OBSERVATION_SEQUENCE, TEST_PORT_ID, &payload);
        assert!(matches!(
            decode_observation_datagram(
                SocketAddr::new(0, 0),
                &valid,
                selected,
                OBSERVATION_SEQUENCE,
                TEST_PORT_ID,
                &request,
            ),
            Err(Ipv6ForwardingObservationError::Kernel(libc::EPERM))
        ));

        let mut zero_errno = valid.clone();
        zero_errno[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4].copy_from_slice(&0_i32.to_ne_bytes());
        assert_malformed(&decode_observation_datagram(
            SocketAddr::new(0, 0),
            &zero_errno,
            selected,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
            &request,
        ));

        let mut wrong_embedded_sequence = valid;
        let embedded_sequence = NLMSG_HEADER_LEN + 4 + 8;
        wrong_embedded_sequence[embedded_sequence..embedded_sequence + 4]
            .copy_from_slice(&2_u32.to_ne_bytes());
        assert_malformed(&decode_observation_datagram(
            SocketAddr::new(0, 0),
            &wrong_embedded_sequence,
            selected,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
            &request,
        ));
    }

    #[test]
    fn observer_rejects_multiple_frames_every_truncation_and_oversize() {
        let selected = selector();
        let request = encode_netlink_query(selected, OBSERVATION_SEQUENCE).expect("query");
        let valid = observation_datagram(selected, 1, OBSERVATION_SEQUENCE, TEST_PORT_ID);
        let mut multiple = valid.clone();
        multiple.extend_from_slice(&valid);
        assert_malformed(&decode_observation_datagram(
            SocketAddr::new(0, 0),
            &multiple,
            selected,
            OBSERVATION_SEQUENCE,
            TEST_PORT_ID,
            &request,
        ));

        for length in 0..valid.len() {
            assert!(
                decode_observation_datagram(
                    SocketAddr::new(0, 0),
                    &valid[..length],
                    selected,
                    OBSERVATION_SEQUENCE,
                    TEST_PORT_ID,
                    &request,
                )
                .is_err(),
                "truncation at {length}"
            );
        }

        let oversized = vec![0_u8; MAX_DATAGRAM_BYTES + 1];
        assert!(matches!(
            decode_observation_datagram(
                SocketAddr::new(0, 0),
                &oversized,
                selected,
                OBSERVATION_SEQUENCE,
                TEST_PORT_ID,
                &request,
            ),
            Err(Ipv6ForwardingObservationError::Limit)
        ));
    }

    #[test]
    fn single_frame_parser_allows_only_alignment_sized_zero_padding() {
        let mut canonical = vec![0_u8; 20];
        canonical[..4].copy_from_slice(&17_u32.to_ne_bytes());
        assert_eq!(
            exact_single_frame(&canonical).expect("canonical zero padding"),
            &canonical[..17]
        );

        let mut nonzero_padding = canonical.clone();
        nonzero_padding[19] = 1;
        assert!(matches!(
            exact_single_frame(&nonzero_padding),
            Err(Ipv6ForwardingObservationError::Malformed)
        ));

        canonical.push(0);
        assert!(matches!(
            exact_single_frame(&canonical),
            Err(Ipv6ForwardingObservationError::Malformed)
        ));
    }

    #[test]
    fn decoder_accepts_only_zero_or_one_for_every_selector() {
        for selected in [
            Ipv6NetconfSelector::all(),
            Ipv6NetconfSelector::default(),
            selector(),
        ] {
            assert_eq!(
                decode_ipv6_forwarding_response(&response(selected, 0), selected),
                Ok(Ipv6ForwardingState::Disabled)
            );
            assert_eq!(
                decode_ipv6_forwarding_response(&response(selected, 1), selected),
                Ok(Ipv6ForwardingState::Enabled)
            );
            for value in [-1, 2, i32::MAX] {
                assert_eq!(
                    decode_ipv6_forwarding_response(&response(selected, value), selected),
                    Err(Ipv6NetconfCodecError::NonCanonical)
                );
            }
        }
    }

    #[test]
    fn decoder_accepts_kernel_without_multicast_routing_and_opaque_integer_fields() {
        let expected = selector();
        assert_eq!(
            decode_ipv6_forwarding_response(&response_without_multicast(expected, 1), expected),
            Ok(Ipv6ForwardingState::Enabled)
        );

        let mut opaque_values = response(expected, 1);
        let multicast_value_offset = NETCONFMSG_ALIGNED_LEN + 2 * 8 + NLA_HEADER_LEN;
        opaque_values[multicast_value_offset..multicast_value_offset + 4]
            .copy_from_slice(&2_i32.to_ne_bytes());
        let proxy_value_offset = NETCONFMSG_ALIGNED_LEN + 3 * 8 + NLA_HEADER_LEN;
        opaque_values[proxy_value_offset..proxy_value_offset + 4]
            .copy_from_slice(&i32::MAX.to_ne_bytes());
        let ignore_value_offset = NETCONFMSG_ALIGNED_LEN + 4 * 8 + NLA_HEADER_LEN;
        opaque_values[ignore_value_offset..ignore_value_offset + 4]
            .copy_from_slice(&(-1_i32).to_ne_bytes());
        assert_eq!(
            decode_ipv6_forwarding_response(&opaque_values, expected),
            Ok(Ipv6ForwardingState::Enabled)
        );
    }

    #[test]
    fn decoder_rejects_family_selector_header_and_required_field_substitution() {
        let expected = selector();
        let valid = response(expected, 1);

        let mut wrong_family = valid.clone();
        wrong_family[0] = u8::try_from(libc::AF_INET).expect("AF_INET fits in u8");
        assert_eq!(
            decode_ipv6_forwarding_response(&wrong_family, expected),
            Err(Ipv6NetconfCodecError::Mismatch)
        );

        let mut nonzero_header = valid.clone();
        nonzero_header[1] = 1;
        assert_eq!(
            decode_ipv6_forwarding_response(&nonzero_header, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );

        assert_eq!(
            decode_ipv6_forwarding_response(&response(Ipv6NetconfSelector::all(), 1), expected),
            Err(Ipv6NetconfCodecError::Mismatch)
        );

        let only_ifindex = &valid[..NETCONFMSG_ALIGNED_LEN + 8];
        assert_eq!(
            decode_ipv6_forwarding_response(only_ifindex, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );
    }

    #[test]
    fn decoder_rejects_unknown_duplicate_reordered_and_flagged_attributes() {
        let expected = selector();
        let valid = response(expected, 1);

        let mut unknown = valid.clone();
        append_attr(&mut unknown, 7, 0);
        assert_eq!(
            decode_ipv6_forwarding_response(&unknown, expected),
            Err(Ipv6NetconfCodecError::Unsupported)
        );

        let mut duplicate = valid.clone();
        append_attr(&mut duplicate, NETCONFA_FORWARDING, 1);
        assert_eq!(
            decode_ipv6_forwarding_response(&duplicate, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );

        let mut reordered = vec![AF_INET6_UAPI, 0, 0, 0];
        append_attr(&mut reordered, NETCONFA_FORWARDING, 1);
        append_attr(&mut reordered, NETCONFA_IFINDEX, expected.encoded_ifindex());
        assert_eq!(
            decode_ipv6_forwarding_response(&reordered, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );

        let mut flagged = valid;
        let flagged_kind = (NETCONFA_IFINDEX | NLA_F_NESTED).to_ne_bytes();
        flagged[NETCONFMSG_ALIGNED_LEN + 2..NETCONFMSG_ALIGNED_LEN + 4]
            .copy_from_slice(&flagged_kind);
        assert_eq!(
            decode_ipv6_forwarding_response(&flagged, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );
    }

    #[test]
    fn decoder_requires_always_emitted_fields_and_rejects_every_truncation() {
        let expected = selector();
        let without_proxy =
            &response_without_multicast(expected, 1)[..NETCONFMSG_ALIGNED_LEN + 2 * 8];
        assert_eq!(
            decode_ipv6_forwarding_response(without_proxy, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );

        let mut without_ignore = response_without_multicast(expected, 1);
        without_ignore.truncate(without_ignore.len() - 8);
        assert_eq!(
            decode_ipv6_forwarding_response(&without_ignore, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );

        let valid = response(expected, 1);
        for length in 0..valid.len() {
            assert!(
                decode_ipv6_forwarding_response(&valid[..length], expected).is_err(),
                "truncation at {length}"
            );
        }
    }

    #[test]
    fn decoder_rejects_nonzero_attribute_padding() {
        let expected = selector();
        let mut payload = vec![AF_INET6_UAPI, 0, 0, 0];
        payload.extend_from_slice(&5_u16.to_ne_bytes());
        payload.extend_from_slice(&NETCONFA_IFINDEX.to_ne_bytes());
        payload.push(expected.encoded_ifindex().to_ne_bytes()[0]);
        payload.extend_from_slice(&[1, 0, 0]);
        append_attr(&mut payload, NETCONFA_FORWARDING, 1);
        assert_eq!(
            decode_ipv6_forwarding_response(&payload, expected),
            Err(Ipv6NetconfCodecError::Malformed)
        );
    }
}
