//! One bounded, run-bound raw `ICMPv4` echo exchange in endpoint A.
//!
//! Preparation opens one nonblocking close-on-exec raw ICMP socket, binds it
//! to endpoint A's fixed address and `eth0`, enables `IP_PKTINFO`, and connects
//! it to endpoint B. The affine prepared value permits exactly one send syscall
//! and one receive syscall. A successful result proves that the socket received
//! one exact 60-byte IPv4 echo reply with the expected source, destination,
//! interface, run-derived identifier, fixed sequence, payload, and checksums.
//! It does not claim packet absence or exclude packets observed elsewhere.

use std::{
    io::{self, IoSlice, IoSliceMut},
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::{AsFd, AsRawFd},
    rc::Rc,
    time::Instant,
};

use nix::{
    errno::Errno,
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn, getsockopt, recvmsg, sendmsg,
        setsockopt, sockopt,
    },
};
use rustix::{
    fs::{OFlags, fcntl_getfl},
    io::{FdFlags, fcntl_getfd},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use volparossa_test_support::RunId;

use crate::topology::{ipv4::FixedIpv4Address, veth::FIXED_VETH_PEER_NAME};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_CODE_ZERO: u8 = 0;
const ICMP_HEADER_BYTES: usize = 8;
const IPV4_HEADER_BYTES: usize = 20;
const RUN_ID_ASCII_BYTES: usize = 32;
const FIXED_ICMP_SEQUENCE: u16 = 1;
const IPPROTO_ICMP: u8 = 1;
const RAW_SOCKET_PORT: u16 = 1;
const IPV4_VERSION_IHL: u8 = 0x45;
const IPV4_DONT_FRAGMENT: u16 = 0x4000;

/// Exact ICMP header plus canonical run-ID payload length.
pub(crate) const ICMP_ECHO_MESSAGE_BYTES: usize = ICMP_HEADER_BYTES + RUN_ID_ASCII_BYTES;
/// Exact IPv4 header plus ICMP echo message length.
pub(crate) const IPV4_ECHO_PACKET_BYTES: usize = IPV4_HEADER_BYTES + ICMP_ECHO_MESSAGE_BYTES;
/// Exact Ethernet frame length expected for the fixed IPv4 echo packet.
pub(crate) const ETHERNET_ECHO_FRAME_BYTES: u64 = 14 + IPV4_ECHO_PACKET_BYTES as u64;

/// The exact ICMP identifier and sequence encoded on the wire.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct IcmpEchoTag {
    identifier: u16,
    sequence: u16,
}

impl IcmpEchoTag {
    /// Return the identifier formed from the first two run-ID ASCII bytes.
    pub(crate) const fn identifier(self) -> u16 {
        self.identifier
    }

    /// Return the sole admitted ICMP sequence.
    pub(crate) const fn sequence(self) -> u16 {
        self.sequence
    }

    /// Return identifier and sequence in exact network byte order.
    pub(crate) fn network_bytes(self) -> [u8; 4] {
        let mut bytes = [0; 4];
        bytes[..2].copy_from_slice(&self.identifier().to_be_bytes());
        bytes[2..].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ProbeIdentity {
    tag: IcmpEchoTag,
    payload: [u8; RUN_ID_ASCII_BYTES],
}

impl ProbeIdentity {
    fn from_run_id(run_id: &RunId) -> Result<Self, IcmpEchoError> {
        let payload: [u8; RUN_ID_ASCII_BYTES] = run_id
            .as_str()
            .as_bytes()
            .try_into()
            .map_err(|_| IcmpEchoError::InvalidRunBinding)?;
        let identifier = u16::from_be_bytes(
            payload[..2]
                .try_into()
                .map_err(|_| IcmpEchoError::InvalidRunBinding)?,
        );
        Ok(Self {
            tag: IcmpEchoTag {
                identifier,
                sequence: FIXED_ICMP_SEQUENCE,
            },
            payload,
        })
    }

    fn request(&self) -> [u8; ICMP_ECHO_MESSAGE_BYTES] {
        let mut request = [0; ICMP_ECHO_MESSAGE_BYTES];
        request[0] = ICMP_ECHO_REQUEST;
        request[1] = ICMP_CODE_ZERO;
        request[4..8].copy_from_slice(&self.tag.network_bytes());
        request[ICMP_HEADER_BYTES..].copy_from_slice(&self.payload);
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        request
    }
}

/// Affine plan for one run-bound endpoint-A echo exchange.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct IcmpEchoProbePlan {
    identity: ProbeIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

impl IcmpEchoProbePlan {
    /// Bind an echo plan to one canonical lifecycle run identifier.
    pub(crate) fn for_run(run_id: &RunId) -> Result<Self, IcmpEchoError> {
        Ok(Self {
            identity: ProbeIdentity::from_run_id(run_id)?,
            _thread_bound: PhantomData,
        })
    }

    /// Return the exact identifier and sequence admitted by this plan.
    pub(crate) const fn tag(&self) -> IcmpEchoTag {
        self.identity.tag
    }

    /// Return the complete canonical run-ID bytes carried by the packet.
    pub(crate) const fn run_id_ascii(&self) -> &[u8; RUN_ID_ASCII_BYTES] {
        &self.identity.payload
    }

    /// Open and exactly validate the sole raw socket before any packet send.
    pub(crate) fn prepare(
        self,
        endpoint_a_ifindex: u32,
        deadline: Instant,
    ) -> Result<PreparedIcmpEcho, IcmpEchoError> {
        let deadline = Deadline(deadline);
        deadline.ensure_unexpired()?;
        validate_ifindex(endpoint_a_ifindex)?;
        let socket = open_exact_socket(deadline)?;
        Ok(PreparedIcmpEcho {
            socket,
            identity: self.identity,
            endpoint_a_ifindex,
            deadline,
            _thread_bound: PhantomData,
        })
    }
}

/// One open, fully validated socket carrying exactly one send authority.
#[derive(Debug)]
#[must_use = "the sole ICMP send authority must be consumed or deliberately dropped"]
pub(crate) struct PreparedIcmpEcho {
    socket: Socket,
    identity: ProbeIdentity,
    endpoint_a_ifindex: u32,
    deadline: Deadline,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PreparedIcmpEcho {
    /// Consume the sole send authority and receive at most one reply datagram.
    ///
    /// Every failure conservatively returns an attempted marker because the
    /// caller can no longer distinguish interruption around the send boundary.
    pub(crate) fn attempt_once(self) -> Result<ExactIcmpEchoReply, IcmpEchoAttemptFailure> {
        let attempted = AttemptedIcmpEcho {
            tag: self.identity.tag,
            run_id_ascii: self.identity.payload,
            endpoint_a_ifindex: self.endpoint_a_ifindex,
            _thread_bound: PhantomData,
        };
        match perform_attempt(
            &self.socket,
            &self.identity,
            self.endpoint_a_ifindex,
            self.deadline,
        ) {
            Ok(()) => Ok(ExactIcmpEchoReply { attempted }),
            Err(source) => Err(IcmpEchoAttemptFailure { source, attempted }),
        }
    }
}

/// Conservative evidence that the sole send authority has been consumed.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "attempt evidence is required to reconcile packet counters"]
pub(crate) struct AttemptedIcmpEcho {
    tag: IcmpEchoTag,
    run_id_ascii: [u8; RUN_ID_ASCII_BYTES],
    endpoint_a_ifindex: u32,
    _thread_bound: PhantomData<Rc<()>>,
}

impl AttemptedIcmpEcho {
    /// Return the exact attempted echo identifier and sequence.
    pub(crate) const fn tag(&self) -> IcmpEchoTag {
        self.tag
    }

    /// Return the complete canonical run ID retained across the send boundary.
    pub(crate) const fn run_id_ascii(&self) -> &[u8; RUN_ID_ASCII_BYTES] {
        &self.run_id_ascii
    }

    /// Return the exact endpoint-A receive/transmit interface index.
    pub(crate) const fn endpoint_a_ifindex(&self) -> u32 {
        self.endpoint_a_ifindex
    }
}

/// Evidence for one exact run-bound IPv4 echo reply received by endpoint A.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the exact reply evidence must be joined with counter and topology evidence"]
pub(crate) struct ExactIcmpEchoReply {
    attempted: AttemptedIcmpEcho,
}

impl ExactIcmpEchoReply {
    /// Return the exact run-bound echo tag proved by the reply.
    pub(crate) const fn tag(&self) -> IcmpEchoTag {
        self.attempted.tag()
    }

    /// Return the complete canonical run ID validated in the exact reply.
    pub(crate) const fn run_id_ascii(&self) -> &[u8; RUN_ID_ASCII_BYTES] {
        self.attempted.run_id_ascii()
    }
}

/// Failure after the sole send authority was consumed.
#[derive(Debug, Error)]
#[error("the sole ICMP echo attempt failed: {source}")]
pub(crate) struct IcmpEchoAttemptFailure {
    source: IcmpEchoError,
    attempted: AttemptedIcmpEcho,
}

impl IcmpEchoAttemptFailure {
    /// Recover the exact error and conservative attempted-send evidence.
    pub(crate) fn into_parts(self) -> (IcmpEchoError, AttemptedIcmpEcho) {
        (self.source, self.attempted)
    }
}

/// Exact-reply validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ExactIcmpEchoReplyError {
    /// The raw IPv4 packet length was not exactly 60 bytes.
    #[error("the raw IPv4 echo reply length is not exact")]
    Length,
    /// The IPv4 header was not the fixed, unfragmented `ICMPv4` form.
    #[error("the IPv4 echo reply header is not exact")]
    Ipv4Header,
    /// The IPv4 header checksum did not validate.
    #[error("the IPv4 echo reply checksum is invalid")]
    Ipv4Checksum,
    /// The IPv4 source or destination address was not exact.
    #[error("the IPv4 echo reply addresses are not exact")]
    Ipv4Addresses,
    /// The ICMP type, code, identifier, or sequence was not exact.
    #[error("the ICMP echo reply header is not exact")]
    IcmpHeader,
    /// The ICMP checksum did not validate.
    #[error("the ICMP echo reply checksum is invalid")]
    IcmpChecksum,
    /// The exact canonical run-ID payload was not returned.
    #[error("the ICMP echo reply payload is not exact")]
    Payload,
}

/// Bounded raw-socket preparation or exchange failure.
#[derive(Debug, Error)]
pub(crate) enum IcmpEchoError {
    /// A canonical run identifier could not be represented by the fixed packet.
    #[error("the run identifier cannot bind the fixed ICMP packet")]
    InvalidRunBinding,
    /// An interface index or time conversion exceeded a fixed kernel bound.
    #[error("the ICMP operation exceeded a fixed bound")]
    Limit,
    /// The single absolute operation deadline expired.
    #[error("the ICMP operation deadline expired")]
    Timeout,
    /// The current namespace lacks the capability required by a raw operation.
    #[error("permission denied while attempting to {operation}: {source}")]
    PermissionDenied {
        /// Fixed operation label.
        operation: &'static str,
        /// Kernel error.
        #[source]
        source: io::Error,
    },
    /// A bounded socket operation failed.
    #[error("failed to {operation}: {source}")]
    Io {
        /// Fixed operation label.
        operation: &'static str,
        /// Kernel error.
        #[source]
        source: io::Error,
    },
    /// A created socket did not retain every required property.
    #[error("raw ICMP socket contract failed: {0}")]
    SocketContract(&'static str),
    /// Poll returned an ambiguous event set.
    #[error("raw ICMP poll state is ambiguous")]
    PollContract,
    /// The sole send syscall did not accept exactly 40 bytes.
    #[error("the sole ICMP send accepted {actual} bytes instead of 40")]
    ShortSend {
        /// Kernel-reported accepted byte count.
        actual: usize,
    },
    /// The sole receive syscall did not return exact metadata.
    #[error("raw ICMP receive contract failed: {0}")]
    ReceiveContract(&'static str),
    /// The returned raw packet failed exact semantic validation.
    #[error(transparent)]
    Reply(#[from] ExactIcmpEchoReplyError),
}

impl IcmpEchoError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::PermissionDenied {
            Self::PermissionDenied { operation, source }
        } else {
            Self::Io { operation, source }
        }
    }

    fn errno(operation: &'static str, source: Errno) -> Self {
        Self::io(operation, io::Error::from_raw_os_error(source as i32))
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline(Instant);

impl Deadline {
    fn ensure_unexpired(self) -> Result<(), IcmpEchoError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(IcmpEchoError::Timeout)
        }
    }

    fn poll_timeout(self) -> Result<PollTimeout, IcmpEchoError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or(IcmpEchoError::Timeout)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(IcmpEchoError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| IcmpEchoError::Limit)
    }
}

fn endpoint_a_address() -> Ipv4Addr {
    Ipv4Addr::from(FixedIpv4Address::EndpointA.octets())
}

fn endpoint_b_address() -> Ipv4Addr {
    Ipv4Addr::from(FixedIpv4Address::EndpointB.octets())
}

fn validate_ifindex(ifindex: u32) -> Result<i32, IcmpEchoError> {
    let ifindex = i32::try_from(ifindex).map_err(|_| IcmpEchoError::Limit)?;
    if ifindex > 1 {
        Ok(ifindex)
    } else {
        Err(IcmpEchoError::Limit)
    }
}

fn open_exact_socket(deadline: Deadline) -> Result<Socket, IcmpEchoError> {
    let socket = Socket::new_raw(
        Domain::IPV4,
        Type::RAW.nonblocking().cloexec(),
        Some(Protocol::ICMPV4),
    )
    .map_err(|source| IcmpEchoError::io("open a raw ICMPv4 socket", source))?;
    verify_descriptor_flags(&socket)?;
    verify_socket_type(&socket)?;
    socket
        .set_header_included_v4(false)
        .map_err(|source| IcmpEchoError::io("disable IP_HDRINCL", source))?;

    socket
        .bind_device(Some(FIXED_VETH_PEER_NAME.as_bytes()))
        .map_err(|source| IcmpEchoError::io("bind the ICMP socket to eth0", source))?;
    setsockopt(&socket, sockopt::Ipv4PacketInfo, &true)
        .map_err(|source| IcmpEchoError::errno("enable IP_PKTINFO", source))?;

    socket
        .bind(&SockAddr::from(SocketAddrV4::new(endpoint_a_address(), 0)))
        .map_err(|source| IcmpEchoError::io("bind the ICMP socket to endpoint A", source))?;
    verify_local_address(&socket)?;

    socket
        .connect(&SockAddr::from(SocketAddrV4::new(endpoint_b_address(), 0)))
        .map_err(|source| IcmpEchoError::io("connect the ICMP socket to endpoint B", source))?;
    deadline.ensure_unexpired()?;
    verify_socket_contract(&socket)?;
    Ok(socket)
}

fn verify_socket_contract(socket: &Socket) -> Result<(), IcmpEchoError> {
    verify_descriptor_flags(socket)?;
    verify_socket_type(socket)?;
    verify_local_address(socket)?;
    if socket
        .header_included_v4()
        .map_err(|source| IcmpEchoError::io("read IP_HDRINCL", source))?
    {
        return Err(IcmpEchoError::SocketContract(
            "IP_HDRINCL was unexpectedly enabled",
        ));
    }
    let device = socket
        .device()
        .map_err(|source| IcmpEchoError::io("read the ICMP socket device", source))?;
    if device.as_deref() != Some(FIXED_VETH_PEER_NAME.as_bytes()) {
        return Err(IcmpEchoError::SocketContract(
            "SO_BINDTODEVICE did not retain eth0",
        ));
    }
    let packet_info = getsockopt(socket, sockopt::Ipv4PacketInfo)
        .map_err(|source| IcmpEchoError::errno("read IP_PKTINFO", source))?;
    if !packet_info {
        return Err(IcmpEchoError::SocketContract("IP_PKTINFO was not retained"));
    }
    Ok(())
}

fn verify_descriptor_flags(socket: &Socket) -> Result<(), IcmpEchoError> {
    let fd_flags = fcntl_getfd(socket)
        .map_err(io::Error::from)
        .map_err(|source| IcmpEchoError::io("read ICMP descriptor flags", source))?;
    if fd_flags != FdFlags::CLOEXEC {
        return Err(IcmpEchoError::SocketContract(
            "the raw socket is not exactly close-on-exec",
        ));
    }
    let status_flags = fcntl_getfl(socket)
        .map_err(io::Error::from)
        .map_err(|source| IcmpEchoError::io("read ICMP status flags", source))?;
    if !status_flags.contains(OFlags::NONBLOCK) {
        return Err(IcmpEchoError::SocketContract(
            "the raw socket is not nonblocking",
        ));
    }
    Ok(())
}

fn verify_socket_type(socket: &Socket) -> Result<(), IcmpEchoError> {
    if socket
        .r#type()
        .map_err(|source| IcmpEchoError::io("read ICMP socket type", source))?
        != Type::RAW
        || !socket
            .nonblocking()
            .map_err(|source| IcmpEchoError::io("read ICMP nonblocking state", source))?
    {
        return Err(IcmpEchoError::SocketContract(
            "the raw socket type or nonblocking state changed",
        ));
    }
    Ok(())
}

fn verify_local_address(socket: &Socket) -> Result<(), IcmpEchoError> {
    let local = socket
        .local_addr()
        .map_err(|source| IcmpEchoError::io("read the ICMP local address", source))?
        .as_socket_ipv4();
    if local != Some(SocketAddrV4::new(endpoint_a_address(), RAW_SOCKET_PORT)) {
        return Err(IcmpEchoError::SocketContract(
            "the raw socket local address is not endpoint A and protocol one",
        ));
    }
    Ok(())
}

fn perform_attempt(
    socket: &Socket,
    identity: &ProbeIdentity,
    ifindex: u32,
    deadline: Deadline,
) -> Result<(), IcmpEchoError> {
    wait_for_socket(socket, PollFlags::POLLOUT, deadline)?;
    let request = identity.request();
    let kernel_ifindex = validate_ifindex(ifindex)?;
    let packet_info = send_packet_info(kernel_ifindex);
    issue_single_send(|| {
        let iov = [IoSlice::new(&request)];
        let control = [ControlMessage::Ipv4PacketInfo(&packet_info)];
        sendmsg::<()>(
            socket.as_raw_fd(),
            &iov,
            &control,
            MsgFlags::MSG_DONTWAIT,
            None,
        )
    })?;
    deadline.ensure_unexpired()?;
    wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
    receive_exact_reply(socket, identity, kernel_ifindex, deadline)
}

fn send_packet_info(ifindex: i32) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: ifindex,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(endpoint_a_address().octets()),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    }
}

fn issue_single_send<F>(send_once: F) -> Result<(), IcmpEchoError>
where
    F: FnOnce() -> nix::Result<usize>,
{
    match send_once() {
        Ok(ICMP_ECHO_MESSAGE_BYTES) => Ok(()),
        Ok(actual) => Err(IcmpEchoError::ShortSend { actual }),
        Err(source) => Err(IcmpEchoError::errno("send the sole ICMP request", source)),
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), IcmpEchoError> {
    loop {
        let mut descriptors = [PollFd::new(socket.as_fd(), expected)];
        match poll(&mut descriptors, deadline.poll_timeout()?) {
            Ok(0) => return Err(IcmpEchoError::Timeout),
            Ok(_) => {
                deadline.ensure_unexpired()?;
                let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(IcmpEchoError::PollContract);
                }
                return Ok(());
            }
            Err(Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(source) => return Err(IcmpEchoError::errno("poll the raw ICMP socket", source)),
        }
    }
}

fn receive_exact_reply(
    socket: &Socket,
    identity: &ProbeIdentity,
    ifindex: i32,
    deadline: Deadline,
) -> Result<(), IcmpEchoError> {
    let mut packet = [0; IPV4_ECHO_PACKET_BYTES];
    let mut control_space = nix::cmsg_space!(libc::in_pktinfo);
    let (bytes, flags, address, packet_info) = {
        let mut iov = [IoSliceMut::new(&mut packet)];
        let message = recvmsg::<SockaddrIn>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control_space),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        )
        .map_err(|source| IcmpEchoError::errno("receive the sole ICMP reply", source))?;
        let packet_info = exact_packet_info(message.cmsgs().map_err(|source| {
            IcmpEchoError::errno("parse ICMP reply control messages", source)
        })?)?;
        (message.bytes, message.flags, message.address, packet_info)
    };
    deadline.ensure_unexpired()?;
    if bytes != IPV4_ECHO_PACKET_BYTES || !flags.is_empty() {
        return Err(IcmpEchoError::ReceiveContract(
            "the reply length or receive flags were not exact",
        ));
    }
    let expected_sender = SockaddrIn::new(10, 241, 2, 2, 0);
    if address != Some(expected_sender) {
        return Err(IcmpEchoError::ReceiveContract(
            "the reply sender was not endpoint B",
        ));
    }
    validate_packet_info(packet_info, ifindex)?;
    parse_exact_reply(&packet, identity)?;
    Ok(())
}

fn exact_packet_info<I>(messages: I) -> Result<libc::in_pktinfo, IcmpEchoError>
where
    I: IntoIterator<Item = ControlMessageOwned>,
{
    let mut packet_info = None;
    for message in messages {
        match message {
            ControlMessageOwned::Ipv4PacketInfo(info) if packet_info.is_none() => {
                packet_info = Some(info);
            }
            _ => {
                return Err(IcmpEchoError::ReceiveContract(
                    "reply control messages were not exactly one IP_PKTINFO",
                ));
            }
        }
    }
    packet_info.ok_or(IcmpEchoError::ReceiveContract(
        "the reply omitted IP_PKTINFO",
    ))
}

fn validate_packet_info(info: libc::in_pktinfo, ifindex: i32) -> Result<(), IcmpEchoError> {
    let endpoint_a = endpoint_a_address().octets();
    if info.ipi_ifindex != ifindex
        || info.ipi_spec_dst.s_addr.to_ne_bytes() != endpoint_a
        || info.ipi_addr.s_addr.to_ne_bytes() != endpoint_a
    {
        return Err(IcmpEchoError::ReceiveContract(
            "reply IP_PKTINFO did not bind endpoint A and eth0",
        ));
    }
    Ok(())
}

fn parse_exact_reply(
    packet: &[u8],
    identity: &ProbeIdentity,
) -> Result<(), ExactIcmpEchoReplyError> {
    if packet.len() != IPV4_ECHO_PACKET_BYTES {
        return Err(ExactIcmpEchoReplyError::Length);
    }
    let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if packet[0] != IPV4_VERSION_IHL
        || packet[1] != 0
        || usize::from(total_length) != IPV4_ECHO_PACKET_BYTES
        || fragment & !IPV4_DONT_FRAGMENT != 0
        || packet[8] == 0
        || packet[9] != IPPROTO_ICMP
    {
        return Err(ExactIcmpEchoReplyError::Ipv4Header);
    }
    if internet_checksum(&packet[..IPV4_HEADER_BYTES]) != 0 {
        return Err(ExactIcmpEchoReplyError::Ipv4Checksum);
    }
    if packet[12..16] != endpoint_b_address().octets()
        || packet[16..20] != endpoint_a_address().octets()
    {
        return Err(ExactIcmpEchoReplyError::Ipv4Addresses);
    }
    let icmp = &packet[IPV4_HEADER_BYTES..];
    if icmp[0] != ICMP_ECHO_REPLY
        || icmp[1] != ICMP_CODE_ZERO
        || icmp[4..8] != identity.tag.network_bytes()
    {
        return Err(ExactIcmpEchoReplyError::IcmpHeader);
    }
    if internet_checksum(icmp) != 0 {
        return Err(ExactIcmpEchoReplyError::IcmpChecksum);
    }
    if icmp[ICMP_HEADER_BYTES..] != identity.payload {
        return Err(ExactIcmpEchoReplyError::Payload);
    }
    Ok(())
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(byte) = words.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded Internet checksum fits in 16 bits")
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io, time::Duration};

    use super::*;
    use crate::nftables::FixedIcmpEchoTag;

    const FIXED_RUN_ID: &str = "0123456789abcdef0123456789abcdef";

    fn identity() -> ProbeIdentity {
        let run_id = RunId::parse(FIXED_RUN_ID).expect("fixed canonical run ID");
        ProbeIdentity::from_run_id(&run_id).expect("run-bound probe identity")
    }

    fn exact_reply() -> [u8; IPV4_ECHO_PACKET_BYTES] {
        let identity = identity();
        let mut packet = [0; IPV4_ECHO_PACKET_BYTES];
        packet[0] = IPV4_VERSION_IHL;
        packet[2..4].copy_from_slice(
            &u16::try_from(IPV4_ECHO_PACKET_BYTES)
                .expect("fixed packet length")
                .to_be_bytes(),
        );
        packet[8] = 64;
        packet[9] = IPPROTO_ICMP;
        packet[12..16].copy_from_slice(&endpoint_b_address().octets());
        packet[16..20].copy_from_slice(&endpoint_a_address().octets());
        let ipv4_checksum = internet_checksum(&packet[..IPV4_HEADER_BYTES]);
        packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

        let icmp = &mut packet[IPV4_HEADER_BYTES..];
        icmp[0] = ICMP_ECHO_REPLY;
        icmp[4..8].copy_from_slice(&identity.tag.network_bytes());
        icmp[ICMP_HEADER_BYTES..].copy_from_slice(&identity.payload);
        let icmp_checksum = internet_checksum(icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        packet
    }

    fn rewrite_ipv4_checksum(packet: &mut [u8; IPV4_ECHO_PACKET_BYTES]) {
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..IPV4_HEADER_BYTES]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    fn rewrite_icmp_checksum(packet: &mut [u8; IPV4_ECHO_PACKET_BYTES]) {
        packet[IPV4_HEADER_BYTES + 2..IPV4_HEADER_BYTES + 4].fill(0);
        let checksum = internet_checksum(&packet[IPV4_HEADER_BYTES..]);
        packet[IPV4_HEADER_BYTES + 2..IPV4_HEADER_BYTES + 4]
            .copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn run_binding_encodes_the_exact_request() {
        let identity = identity();
        assert_eq!(identity.tag.identifier(), 0x3031);
        assert_eq!(identity.tag.sequence(), 1);
        assert_eq!(identity.tag.network_bytes(), [b'0', b'1', 0, 1]);
        assert_eq!(identity.payload, *FIXED_RUN_ID.as_bytes());

        let request = identity.request();
        assert_eq!(request.len(), 40);
        assert_eq!(&request[..2], &[8, 0]);
        assert_eq!(&request[2..4], &[0x69, 0x5f]);
        assert_eq!(&request[4..8], &[b'0', b'1', 0, 1]);
        assert_eq!(&request[8..], FIXED_RUN_ID.as_bytes());
        assert_eq!(internet_checksum(&request), 0);
    }

    #[test]
    fn run_binding_matches_the_nftables_packet_contract() {
        let run_id = RunId::parse(FIXED_RUN_ID).expect("fixed canonical run ID");
        let probe = ProbeIdentity::from_run_id(&run_id).expect("probe identity");
        let policy = FixedIcmpEchoTag::from_run_id(&run_id).expect("policy identity");
        assert_eq!(probe.tag.identifier(), policy.identifier());
        assert_eq!(probe.tag.sequence(), policy.sequence());
        assert_eq!(&probe.payload, policy.payload());
    }

    #[test]
    fn attempted_and_reply_evidence_retain_the_complete_run_binding() {
        let first_run =
            RunId::parse("01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("first same-prefix run ID");
        let second_run =
            RunId::parse("01bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").expect("second same-prefix run ID");
        let first = ProbeIdentity::from_run_id(&first_run).expect("first identity");
        let second = ProbeIdentity::from_run_id(&second_run).expect("second identity");
        assert_eq!(
            first.tag, second.tag,
            "the short wire tag intentionally collides"
        );
        assert_ne!(first.payload, second.payload);

        let attempted = AttemptedIcmpEcho {
            tag: first.tag,
            run_id_ascii: first.payload,
            endpoint_a_ifindex: 2,
            _thread_bound: PhantomData,
        };
        assert_eq!(attempted.run_id_ascii(), first_run.as_str().as_bytes());
        assert_ne!(attempted.run_id_ascii(), second_run.as_str().as_bytes());

        let reply = ExactIcmpEchoReply { attempted };
        assert_eq!(reply.run_id_ascii(), first_run.as_str().as_bytes());
        assert_ne!(reply.run_id_ascii(), second_run.as_str().as_bytes());
    }

    #[test]
    fn fixed_lengths_match_the_packet_and_frame_contract() {
        assert_eq!(ICMP_ECHO_MESSAGE_BYTES, 40);
        assert_eq!(IPV4_ECHO_PACKET_BYTES, 60);
        assert_eq!(ETHERNET_ECHO_FRAME_BYTES, 74);
    }

    #[test]
    fn checksum_handles_odd_lengths_and_detects_corruption() {
        assert_eq!(internet_checksum(&[]), 0xffff);
        assert_eq!(internet_checksum(&[0x01]), 0xfeff);
        assert_eq!(internet_checksum(&[0x01, 0x02, 0x03]), 0xfbfd);

        let request = identity().request();
        for index in 0..request.len() {
            let mut corrupt = request;
            corrupt[index] ^= 1;
            assert_ne!(internet_checksum(&corrupt), 0, "byte {index}");
        }
    }

    #[test]
    fn exact_reply_parser_accepts_only_the_fixed_reply() {
        let identity = identity();
        let packet = exact_reply();
        assert_eq!(parse_exact_reply(&packet, &identity), Ok(()));
        assert_eq!(
            parse_exact_reply(&packet[..IPV4_ECHO_PACKET_BYTES - 1], &identity),
            Err(ExactIcmpEchoReplyError::Length)
        );

        let mut dont_fragment = packet;
        dont_fragment[6..8].copy_from_slice(&IPV4_DONT_FRAGMENT.to_be_bytes());
        rewrite_ipv4_checksum(&mut dont_fragment);
        assert_eq!(parse_exact_reply(&dont_fragment, &identity), Ok(()));
    }

    #[test]
    fn ipv4_reply_contract_fails_closed_on_semantic_mutations() {
        let identity = identity();
        let mutations = [
            (0, 0x65),
            (1, 1),
            (3, 59),
            (6, 0x20),
            (7, 1),
            (8, 0),
            (9, 17),
        ];
        for (index, value) in mutations {
            let mut packet = exact_reply();
            packet[index] = value;
            rewrite_ipv4_checksum(&mut packet);
            assert_eq!(
                parse_exact_reply(&packet, &identity),
                Err(ExactIcmpEchoReplyError::Ipv4Header),
                "IPv4 byte {index}"
            );
        }
    }

    #[test]
    fn reply_addresses_and_ipv4_checksum_are_exact() {
        let identity = identity();
        for index in 12..20 {
            let mut packet = exact_reply();
            packet[index] ^= 1;
            rewrite_ipv4_checksum(&mut packet);
            assert_eq!(
                parse_exact_reply(&packet, &identity),
                Err(ExactIcmpEchoReplyError::Ipv4Addresses),
                "address byte {index}"
            );
        }
        let mut bad_checksum = exact_reply();
        bad_checksum[10] ^= 1;
        assert_eq!(
            parse_exact_reply(&bad_checksum, &identity),
            Err(ExactIcmpEchoReplyError::Ipv4Checksum)
        );
    }

    #[test]
    fn icmp_reply_header_payload_and_checksum_are_exact() {
        let identity = identity();
        for index in [20, 21, 24, 25, 26, 27] {
            let mut packet = exact_reply();
            packet[index] ^= 1;
            rewrite_icmp_checksum(&mut packet);
            assert_eq!(
                parse_exact_reply(&packet, &identity),
                Err(ExactIcmpEchoReplyError::IcmpHeader),
                "ICMP header byte {index}"
            );
        }
        let mut payload = exact_reply();
        payload[IPV4_HEADER_BYTES + ICMP_HEADER_BYTES] ^= 1;
        rewrite_icmp_checksum(&mut payload);
        assert_eq!(
            parse_exact_reply(&payload, &identity),
            Err(ExactIcmpEchoReplyError::Payload)
        );
        let mut checksum = exact_reply();
        checksum[IPV4_HEADER_BYTES + 2] ^= 1;
        assert_eq!(
            parse_exact_reply(&checksum, &identity),
            Err(ExactIcmpEchoReplyError::IcmpChecksum)
        );
    }

    #[test]
    fn packet_info_requires_exact_endpoint_and_interface() {
        let exact = libc::in_pktinfo {
            ipi_ifindex: 2,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(endpoint_a_address().octets()),
            },
            ipi_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(endpoint_a_address().octets()),
            },
        };
        assert!(validate_packet_info(exact, 2).is_ok());
        for bad in [
            libc::in_pktinfo {
                ipi_ifindex: 3,
                ..exact
            },
            libc::in_pktinfo {
                ipi_spec_dst: libc::in_addr { s_addr: 0 },
                ..exact
            },
            libc::in_pktinfo {
                ipi_addr: libc::in_addr { s_addr: 0 },
                ..exact
            },
        ] {
            assert!(matches!(
                validate_packet_info(bad, 2),
                Err(IcmpEchoError::ReceiveContract(_))
            ));
        }
    }

    #[test]
    fn packet_info_list_requires_one_ipv4_record() {
        let info = send_packet_info(2);
        assert!(matches!(
            exact_packet_info(Vec::<ControlMessageOwned>::new()),
            Err(IcmpEchoError::ReceiveContract(_))
        ));
        assert!(exact_packet_info([ControlMessageOwned::Ipv4PacketInfo(info)]).is_ok());
        assert!(matches!(
            exact_packet_info([
                ControlMessageOwned::Ipv4PacketInfo(info),
                ControlMessageOwned::Ipv4PacketInfo(info),
            ]),
            Err(IcmpEchoError::ReceiveContract(_))
        ));
    }

    #[test]
    fn sole_send_boundary_never_retries() {
        for result in [
            Ok(ICMP_ECHO_MESSAGE_BYTES),
            Ok(ICMP_ECHO_MESSAGE_BYTES - 1),
            Err(Errno::EINTR),
            Err(Errno::EAGAIN),
            Err(Errno::EPERM),
        ] {
            let calls = Cell::new(0);
            let outcome = issue_single_send(|| {
                calls.set(calls.get() + 1);
                result
            });
            assert_eq!(calls.get(), 1);
            if result == Ok(ICMP_ECHO_MESSAGE_BYTES) {
                assert!(outcome.is_ok());
            } else {
                assert!(outcome.is_err());
            }
        }
    }

    #[test]
    fn interface_and_deadline_bounds_fail_before_socket_creation() {
        assert!(validate_ifindex(0).is_err());
        assert!(validate_ifindex(1).is_err());
        assert_eq!(validate_ifindex(2).expect("eth0 ifindex"), 2);
        assert!(validate_ifindex(u32::MAX).is_err());
        assert!(matches!(
            Deadline(
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .expect("one millisecond before now"),
            )
            .ensure_unexpired(),
            Err(IcmpEchoError::Timeout)
        ));
    }

    #[test]
    fn permission_errors_remain_distinct() {
        let denied = IcmpEchoError::io(
            "open test socket",
            io::Error::from_raw_os_error(libc::EPERM),
        );
        assert!(matches!(denied, IcmpEchoError::PermissionDenied { .. }));
        let other = IcmpEchoError::io(
            "open test socket",
            io::Error::from_raw_os_error(libc::EINVAL),
        );
        assert!(matches!(other, IcmpEchoError::Io { .. }));
    }

    #[test]
    fn socket_descriptor_flags_are_exact_and_wrong_type_is_rejected() {
        let socket = Socket::new(
            Domain::IPV4,
            Type::DGRAM.nonblocking().cloexec(),
            Some(Protocol::UDP),
        )
        .expect("open unbound test datagram socket");
        verify_descriptor_flags(&socket).expect("nonblocking close-on-exec flags");
        assert!(matches!(
            verify_socket_type(&socket),
            Err(IcmpEchoError::SocketContract(_))
        ));
    }
}
