//! Bounded read-only observation of the empty nftables baseline.
//!
//! The collector sends only fixed `GETGEN` and all-family `GETTABLE` requests
//! over `NETLINK_NETFILTER`. It brackets the empty table dump with generation
//! observations and accepts only the initial, stable nftables generation. No
//! mutation message has an encoder or API in this module.

use std::{io, marker::PhantomData, os::fd::AsFd, rc::Rc, time::Instant};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use thiserror::Error;

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_DATAGRAMS: usize = 64;
const MAX_FRAMES: usize = 256;
const MAX_GENERATION_ATTRIBUTES: usize = 3;
const MAX_TABLE_ATTRIBUTES: usize = 7;
const MAX_PROCESS_NAME_BYTES: usize = 16;
const MAX_TABLE_NAME_BYTES: usize = 256;
const MAX_TABLE_USERDATA_BYTES: usize = 256;

const NLMSG_HEADER_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const REQUEST_LEN: usize = NLMSG_HEADER_LEN + NFGENMSG_LEN;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWTABLE: u16 = NFNL_SUBSYS_NFTABLES << 8;
const NFT_MSG_GETTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 1;
const NFT_MSG_NEWGEN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 15;
const NFT_MSG_GETGEN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 16;

const AF_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFNETLINK_V0: u8 = 0;
const INITIAL_GENERATION: u32 = 1;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_TABLE_USE: u16 = 3;
const NFTA_TABLE_HANDLE: u16 = 4;
const NFTA_TABLE_PAD: u16 = 5;
const NFTA_TABLE_USERDATA: u16 = 6;
const NFTA_TABLE_OWNER: u16 = 7;
const NFT_TABLE_F_MASK: u32 = 0x0007;

const NFTA_GEN_ID: u16 = 1;
const NFTA_GEN_PROC_PID: u16 = 2;
const NFTA_GEN_PROC_NAME: u16 = 3;

/// A fixed, non-sensitive nftables-baseline failure.
#[derive(Debug, Error)]
pub(crate) enum NftablesError {
    /// A netlink socket operation or bounded wait failed.
    #[error("nftables proof netlink I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a fixed read-only request.
    #[error("nftables proof netlink request was rejected")]
    Kernel(i32),
    /// A response was malformed, ambiguous, or did not match its request.
    #[error("nftables proof netlink response was malformed or ambiguous")]
    Malformed,
    /// A response or sequence exceeded a fixed resource bound.
    #[error("nftables proof netlink response exceeded its fixed bound")]
    Limit,
    /// The generation changed while the table dump was being observed.
    #[error("nftables generation changed during proof")]
    Inconsistent,
    /// The stable observation was not the initial empty nftables baseline.
    #[error("nftables state is not the initial empty baseline")]
    NotPristine,
}

/// An affine observation of the initial, stable, empty nftables baseline.
///
/// The token is deliberately neither cloneable nor transferable to another
/// thread. A caller can compare it with a fresh observation made under a later
/// composite network-proof deadline.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NftablesBaseline {
    generation: u32,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Observe one stable empty nftables baseline before the supplied deadline.
///
/// The deadline is absolute so a composite network proof can place this
/// collector and its other read-only observations under one time bound.
pub(crate) fn observe_empty_nftables(deadline: Instant) -> Result<NftablesBaseline, NftablesError> {
    let deadline = Deadline(deadline);
    deadline.ensure_unexpired()?;
    let mut collector = NetfilterCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let before = collector.collect_generation(deadline, &mut budget)?;
    collector.collect_empty_table_dump(before, deadline, &mut budget)?;
    let after = collector.collect_generation(deadline, &mut budget)?;
    deadline.ensure_unexpired()?;
    classify_observation(before, after)
}

#[derive(Clone, Copy, Debug)]
struct Deadline(Instant);

impl Deadline {
    fn poll_timeout(self) -> Result<PollTimeout, NftablesError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(NftablesError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| NftablesError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), NftablesError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error().into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestKind {
    Generation,
    TableDump,
}

impl RequestKind {
    const fn message_type(self) -> u16 {
        match self {
            Self::Generation => NFT_MSG_GETGEN,
            Self::TableDump => NFT_MSG_GETTABLE,
        }
    }

    const fn flags(self) -> u16 {
        match self {
            Self::Generation => NLM_F_REQUEST,
            Self::TableDump => NLM_F_REQUEST | NLM_F_DUMP,
        }
    }
}

struct CollectionBudget {
    bytes: usize,
    datagrams: usize,
    frames: usize,
    max_bytes: usize,
    max_datagrams: usize,
    max_frames: usize,
}

impl CollectionBudget {
    const fn production() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_TOTAL_BYTES,
            max_datagrams: MAX_DATAGRAMS,
            max_frames: MAX_FRAMES,
        }
    }

    fn can_receive(&self, length: usize) -> Result<(), NftablesError> {
        if !(NLMSG_HEADER_LEN..=MAX_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(NftablesError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), NftablesError> {
        self.can_receive(length)?;
        self.bytes = self.bytes.checked_add(length).ok_or(NftablesError::Limit)?;
        self.datagrams = self.datagrams.checked_add(1).ok_or(NftablesError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(NftablesError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), NftablesError> {
        self.frames = self.frames.checked_add(1).ok_or(NftablesError::Limit)?;
        if self.frames > self.max_frames {
            return Err(NftablesError::Limit);
        }
        Ok(())
    }
}

struct GenerationState {
    sequence: u32,
    local_port: u32,
    request: [u8; REQUEST_LEN],
    reply: Option<u32>,
}

impl GenerationState {
    const fn new(sequence: u32, local_port: u32, request: [u8; REQUEST_LEN]) -> Self {
        Self {
            sequence,
            local_port,
            request,
            reply: None,
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), NftablesError> {
        if self.reply.is_some() || sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if self.reply.is_some()
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
        }
        let message_type = read_ne_u16(frame, 4)?;
        let flags = read_ne_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        if message_type == NLMSG_OVERRUN {
            return Err(NftablesError::Malformed);
        }
        match message_type {
            NFT_MSG_NEWGEN if flags == 0 => {
                self.reply = Some(parse_generation_payload(payload)?);
                Ok(())
            }
            NLMSG_ERROR => Err(parse_request_error(flags, payload, &self.request)?),
            _ => Err(NftablesError::Malformed),
        }
    }

    fn finish(self) -> Result<u32, NftablesError> {
        self.reply.ok_or(NftablesError::Malformed)
    }
}

struct TableDumpState {
    sequence: u32,
    local_port: u32,
    expected_generation: u32,
    request: [u8; REQUEST_LEN],
    done: bool,
}

impl TableDumpState {
    const fn new(
        sequence: u32,
        local_port: u32,
        expected_generation: u32,
        request: [u8; REQUEST_LEN],
    ) -> Self {
        Self {
            sequence,
            local_port,
            expected_generation,
            request,
            done: false,
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), NftablesError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if self.done
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
        }
        let message_type = read_ne_u16(frame, 4)?;
        let flags = read_ne_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        match message_type {
            NLMSG_DONE => {
                parse_done(flags, payload)?;
                self.done = true;
                Ok(())
            }
            NLMSG_ERROR => Err(parse_request_error(flags, payload, &self.request)?),
            NFT_MSG_NEWTABLE if flags == NLM_F_MULTI => {
                validate_table_payload(payload, self.expected_generation)?;
                Err(NftablesError::NotPristine)
            }
            _ => Err(NftablesError::Malformed),
        }
    }

    fn finish(self) -> Result<(), NftablesError> {
        if self.done {
            Ok(())
        } else {
            Err(NftablesError::Malformed)
        }
    }
}

struct NetfilterCollector {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetfilterCollector {
    fn connect(deadline: Deadline) -> Result<Self, NftablesError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(NftablesError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn collect_generation(
        &mut self,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<u32, NftablesError> {
        let sequence = self.next_sequence()?;
        let request = encode_request(RequestKind::Generation, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
        let mut state = GenerationState::new(sequence, self.local_port, request);
        state.ingest(sender, &bytes, budget)?;
        deadline.ensure_unexpired()?;
        state.finish()
    }

    fn collect_empty_table_dump(
        &mut self,
        expected_generation: u32,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<(), NftablesError> {
        let sequence = self.next_sequence()?;
        let request = encode_request(RequestKind::TableDump, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let mut state =
            TableDumpState::new(sequence, self.local_port, expected_generation, request);
        while !state.done {
            let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
            state.ingest(sender, &bytes, budget)?;
        }
        deadline.ensure_unexpired()?;
        state.finish()
    }

    fn next_sequence(&mut self) -> Result<u32, NftablesError> {
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or(NftablesError::Limit)?;
        if sequence == 0 {
            Err(NftablesError::Malformed)
        } else {
            Ok(sequence)
        }
    }
}

fn classify_observation(before: u32, after: u32) -> Result<NftablesBaseline, NftablesError> {
    if before != after {
        return Err(NftablesError::Inconsistent);
    }
    if before != INITIAL_GENERATION {
        return Err(NftablesError::NotPristine);
    }
    Ok(NftablesBaseline {
        generation: before,
        _thread_bound: PhantomData,
    })
}

fn encode_request(kind: RequestKind, sequence: u32) -> Result<[u8; REQUEST_LEN], NftablesError> {
    if sequence == 0 {
        return Err(NftablesError::Malformed);
    }
    let mut request = [0_u8; REQUEST_LEN];
    request[0..4].copy_from_slice(
        &u32::try_from(REQUEST_LEN)
            .map_err(|_| NftablesError::Limit)?
            .to_ne_bytes(),
    );
    request[4..6].copy_from_slice(&kind.message_type().to_ne_bytes());
    request[6..8].copy_from_slice(&kind.flags().to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    Ok(request)
}

fn parse_generation_payload(payload: &[u8]) -> Result<u32, NftablesError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    if header.family != AF_UNSPEC || header.version != NFNETLINK_V0 {
        return Err(NftablesError::Malformed);
    }
    let attributes = parse_attributes(attributes, MAX_GENERATION_ATTRIBUTES)?;
    let mut generation = None;
    let mut process_id = None;
    let mut process_name = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_GEN_ID => set_once(&mut generation, read_exact_be_u32(attribute.payload)?)?,
            NFTA_GEN_PROC_PID => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value == 0 {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut process_id, value)?;
            }
            NFTA_GEN_PROC_NAME => {
                validate_nul_string(attribute.payload, MAX_PROCESS_NAME_BYTES)?;
                set_once(&mut process_name, ())?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    let generation = generation.ok_or(NftablesError::Malformed)?;
    process_id.ok_or(NftablesError::Malformed)?;
    process_name.ok_or(NftablesError::Malformed)?;
    if header.resource_id != generation_resource_id(generation) {
        return Err(NftablesError::Malformed);
    }
    Ok(generation)
}

fn validate_table_payload(payload: &[u8], expected_generation: u32) -> Result<(), NftablesError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    if !matches!(
        header.family,
        NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_ARP | NFPROTO_NETDEV | NFPROTO_BRIDGE | NFPROTO_IPV6
    ) || header.version != NFNETLINK_V0
        || header.resource_id != generation_resource_id(expected_generation)
    {
        return Err(NftablesError::Malformed);
    }
    let attributes = parse_attributes(attributes, MAX_TABLE_ATTRIBUTES)?;
    let mut name = None;
    let mut flags = None;
    let mut use_count = None;
    let mut handle = None;
    let mut pad = None;
    let mut userdata = None;
    let mut owner = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_TABLE_NAME => {
                validate_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?;
                set_once(&mut name, ())?;
            }
            NFTA_TABLE_FLAGS => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value & !NFT_TABLE_F_MASK != 0 {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut flags, value)?;
            }
            NFTA_TABLE_USE => {
                set_once(&mut use_count, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_TABLE_HANDLE => {
                set_once(&mut handle, read_exact_be_u64(attribute.payload)?)?;
            }
            NFTA_TABLE_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut pad, ())?;
            }
            NFTA_TABLE_USERDATA => {
                if attribute.payload.len() > MAX_TABLE_USERDATA_BYTES {
                    return Err(NftablesError::Limit);
                }
                set_once(&mut userdata, ())?;
            }
            NFTA_TABLE_OWNER => {
                set_once(&mut owner, read_exact_be_u32(attribute.payload)?)?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    name.ok_or(NftablesError::Malformed)?;
    flags.ok_or(NftablesError::Malformed)?;
    use_count.ok_or(NftablesError::Malformed)?;
    handle.ok_or(NftablesError::Malformed)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct NfgenHeader {
    family: u8,
    version: u8,
    resource_id: u16,
}

fn split_nfgenmsg(payload: &[u8]) -> Result<(NfgenHeader, &[u8]), NftablesError> {
    let header = payload
        .get(..NFGENMSG_LEN)
        .ok_or(NftablesError::Malformed)?;
    Ok((
        NfgenHeader {
            family: header[0],
            version: header[1],
            resource_id: u16::from_be_bytes([header[2], header[3]]),
        },
        &payload[NFGENMSG_LEN..],
    ))
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

fn parse_attributes(mut bytes: &[u8], maximum: usize) -> Result<Vec<Attribute<'_>>, NftablesError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(NftablesError::Malformed);
        }
        if attributes.len() >= maximum {
            return Err(NftablesError::Limit);
        }
        let length = usize::from(read_ne_u16(bytes, 0)?);
        let raw_kind = read_ne_u16(bytes, 2)?;
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(NftablesError::Malformed);
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(NftablesError::Malformed);
        }
        attributes.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags: raw_kind & !NLA_TYPE_MASK,
            payload: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(attributes)
}

fn walk_datagram(
    bytes: &[u8],
    budget: &mut CollectionBudget,
    mut consume: impl FnMut(&[u8]) -> Result<(), NftablesError>,
) -> Result<(), NftablesError> {
    budget.record_datagram(bytes.len())?;
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NLMSG_HEADER_LEN {
            return Err(NftablesError::Malformed);
        }
        let length =
            usize::try_from(read_ne_u32(remaining, 0)?).map_err(|_| NftablesError::Malformed)?;
        let aligned = align4(length)?;
        if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
            return Err(NftablesError::Malformed);
        }
        if remaining[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(NftablesError::Malformed);
        }
        budget.record_frame()?;
        consume(&remaining[..length])?;
        offset = offset.checked_add(aligned).ok_or(NftablesError::Limit)?;
    }
    Ok(())
}

fn parse_done(flags: u16, payload: &[u8]) -> Result<(), NftablesError> {
    if flags != NLM_F_MULTI {
        return Err(NftablesError::Malformed);
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_ne_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 => Err(NftablesError::Kernel(errno.saturating_abs())),
            _ => Err(NftablesError::Malformed),
        },
        _ => Err(NftablesError::Malformed),
    }
}

fn parse_request_error(
    flags: u16,
    payload: &[u8],
    request: &[u8; REQUEST_LEN],
) -> Result<NftablesError, NftablesError> {
    if flags != 0 || payload.len() != 4 + request.len() {
        return Err(NftablesError::Malformed);
    }
    let errno = read_ne_i32(payload, 0)?;
    if payload[4..] != *request {
        return Err(NftablesError::Malformed);
    }
    if errno < 0 {
        Ok(NftablesError::Kernel(errno.saturating_abs()))
    } else {
        Err(NftablesError::Malformed)
    }
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), NftablesError> {
    loop {
        deadline.ensure_unexpired()?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return deadline.ensure_unexpired(),
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short netlink write").into());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_socket(socket, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_bounded(
    socket: &Socket,
    deadline: Deadline,
    budget: &CollectionBudget,
) -> Result<(Vec<u8>, SocketAddr), NftablesError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        budget.can_receive(length)?;
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != received || sender != peek_sender {
            return Err(NftablesError::Malformed);
        }
        return Ok((bytes, sender));
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), NftablesError> {
    loop {
        let mut descriptor = [PollFd::new(socket.as_fd(), expected)];
        match poll(&mut descriptor, deadline.poll_timeout()?) {
            Ok(0) => return Err(timeout_error().into()),
            Ok(_) => {
                deadline.ensure_unexpired()?;
                let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(NftablesError::Malformed);
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }
}

fn validate_nul_string(bytes: &[u8], maximum: usize) -> Result<(), NftablesError> {
    if !(2..=maximum).contains(&bytes.len())
        || bytes.last() != Some(&0)
        || bytes[..bytes.len() - 1].contains(&0)
    {
        return Err(NftablesError::Malformed);
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NftablesError> {
    if slot.replace(value).is_some() {
        Err(NftablesError::Malformed)
    } else {
        Ok(())
    }
}

fn read_ne_u16(bytes: &[u8], offset: usize) -> Result<u16, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(u16::from_ne_bytes(value))
}

fn read_ne_u32(bytes: &[u8], offset: usize) -> Result<u32, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

fn read_ne_i32(bytes: &[u8], offset: usize) -> Result<i32, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_be_u32(bytes: &[u8]) -> Result<u32, NftablesError> {
    let value = bytes.try_into().map_err(|_| NftablesError::Malformed)?;
    Ok(u32::from_be_bytes(value))
}

fn read_exact_be_u64(bytes: &[u8]) -> Result<u64, NftablesError> {
    let value = bytes.try_into().map_err(|_| NftablesError::Malformed)?;
    Ok(u64::from_be_bytes(value))
}

fn align4(length: usize) -> Result<usize, NftablesError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(NftablesError::Limit)
}

const fn generation_resource_id(generation: u32) -> u16 {
    let bytes = generation.to_be_bytes();
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "nftables proof deadline expired")
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::Command,
        time::{Duration, Instant},
    };

    use super::*;

    const LIVE_COLLECTOR_CHILD_ENV: &str = "VOLPAROSSA_NFTABLES_COLLECTOR_CHILD";
    const TEST_SEQUENCE: u32 = 7;
    const TEST_PORT: u32 = 41;

    #[test]
    fn fixed_requests_have_exact_headers_and_no_attributes() {
        for (kind, expected_type, expected_flags) in [
            (RequestKind::Generation, NFT_MSG_GETGEN, NLM_F_REQUEST),
            (
                RequestKind::TableDump,
                NFT_MSG_GETTABLE,
                NLM_F_REQUEST | NLM_F_DUMP,
            ),
        ] {
            let request = encode_request(kind, TEST_SEQUENCE).expect("fixed request");
            assert_eq!(
                usize::try_from(read_ne_u32(&request, 0).expect("length"))
                    .expect("request length fits"),
                REQUEST_LEN
            );
            assert_eq!(read_ne_u16(&request, 4).expect("type"), expected_type);
            assert_eq!(read_ne_u16(&request, 6).expect("flags"), expected_flags);
            assert_eq!(read_ne_u32(&request, 8).expect("sequence"), TEST_SEQUENCE);
            assert_eq!(read_ne_u32(&request, 12).expect("port"), 0);
            assert_eq!(&request[NLMSG_HEADER_LEN..], &[0; NFGENMSG_LEN]);
        }
        assert!(matches!(
            encode_request(RequestKind::Generation, 0),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn generation_reply_accepts_exact_attributes_in_any_order() {
        for order in [
            [NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
            [NFTA_GEN_PROC_NAME, NFTA_GEN_ID, NFTA_GEN_PROC_PID],
        ] {
            let payload = generation_payload(INITIAL_GENERATION, &order);
            let mut state = generation_state();
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT, &payload),
                    &mut CollectionBudget::production(),
                )
                .expect("canonical generation reply");
            assert_eq!(state.finish().expect("generation"), INITIAL_GENERATION);
        }
    }

    #[test]
    fn generation_payload_rejects_header_and_attribute_ambiguity() {
        let canonical = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
        );
        let mut wrong_family = canonical.clone();
        wrong_family[0] = NFPROTO_IPV4;
        let mut wrong_version = canonical.clone();
        wrong_version[1] = 1;
        let mut wrong_resource = canonical.clone();
        wrong_resource[2..4].copy_from_slice(&2_u16.to_be_bytes());
        let missing_name =
            generation_payload(INITIAL_GENERATION, &[NFTA_GEN_ID, NFTA_GEN_PROC_PID]);
        let duplicate_id = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_ID, NFTA_GEN_PROC_PID],
        );
        let unknown = generation_payload(INITIAL_GENERATION, &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, 4]);
        let mut flagged = canonical.clone();
        let offset = NFGENMSG_LEN;
        flagged[offset + 2..offset + 4]
            .copy_from_slice(&(NFTA_GEN_ID | NLA_F_NET_BYTEORDER).to_ne_bytes());
        let zero_pid = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &0_u32.to_be_bytes(),
            b"test\0",
        );
        let nonterminated_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            b"test",
        );
        let interior_nul_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            b"te\0st\0",
        );
        let mut overlong_process_name = vec![b'x'; MAX_PROCESS_NAME_BYTES + 1];
        *overlong_process_name.last_mut().expect("process-name byte") = 0;
        let overlong_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            &overlong_process_name,
        );
        let wrong_id_length = generation_payload_with(
            INITIAL_GENERATION,
            &[0, 0, 1],
            &123_u32.to_be_bytes(),
            b"test\0",
        );
        for payload in [
            wrong_family,
            wrong_version,
            wrong_resource,
            missing_name,
            duplicate_id,
            unknown,
            flagged,
            zero_pid,
            nonterminated_name,
            interior_nul_name,
            overlong_name,
            wrong_id_length,
        ] {
            assert!(matches!(
                parse_generation_payload(&payload),
                Err(NftablesError::Malformed | NftablesError::Limit)
            ));
        }
    }

    #[test]
    fn generation_state_rejects_untrusted_envelope_and_extra_frames() {
        let payload = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
        );
        let good = netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT, &payload);
        let mut doubled = good.clone();
        doubled.extend(&good);
        for (sender, frame) in [
            (SocketAddr::new(9, 0), good.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE + 1, TEST_PORT, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT + 1, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWGEN,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NLMSG_OVERRUN, 0, TEST_SEQUENCE, TEST_PORT, &[]),
            ),
            (SocketAddr::new(0, 0), doubled),
        ] {
            assert!(matches!(
                generation_state().ingest(sender, &frame, &mut CollectionBudget::production()),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn generation_parser_accepts_its_exact_string_boundary() {
        let mut maximum_process_name = vec![b'x'; MAX_PROCESS_NAME_BYTES];
        *maximum_process_name.last_mut().expect("process-name byte") = 0;
        let payload = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            &maximum_process_name,
        );
        assert_eq!(
            parse_generation_payload(&payload).expect("maximum process name"),
            INITIAL_GENERATION
        );
    }

    #[test]
    fn table_dump_accepts_only_exact_empty_terminal() {
        for payload in [Vec::new(), 0_i32.to_ne_bytes().to_vec()] {
            let mut state = table_state(INITIAL_GENERATION);
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &payload),
                    &mut CollectionBudget::production(),
                )
                .expect("empty table dump");
            state.finish().expect("terminal");
        }
        for (flags, payload) in [
            (0, Vec::new()),
            (NLM_F_MULTI | 0x10, Vec::new()),
            (NLM_F_MULTI | 0x20, Vec::new()),
            (NLM_F_MULTI, 1_i32.to_ne_bytes().to_vec()),
            (NLM_F_MULTI, vec![0; 8]),
        ] {
            let mut state = table_state(INITIAL_GENERATION);
            assert!(
                state
                    .ingest(
                        SocketAddr::new(0, 0),
                        &netlink_frame(NLMSG_DONE, flags, TEST_SEQUENCE, TEST_PORT, &payload,),
                        &mut CollectionBudget::production(),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn any_well_formed_table_is_not_pristine() {
        let payload = table_payload(INITIAL_GENERATION);
        let result = table_state(INITIAL_GENERATION).ingest(
            SocketAddr::new(0, 0),
            &netlink_frame(
                NFT_MSG_NEWTABLE,
                NLM_F_MULTI,
                TEST_SEQUENCE,
                TEST_PORT,
                &payload,
            ),
            &mut CollectionBudget::production(),
        );
        assert!(matches!(result, Err(NftablesError::NotPristine)));
    }

    #[test]
    fn table_dump_rejects_untrusted_envelope_controls_and_trailing_frames() {
        let payload = table_payload(INITIAL_GENERATION);
        let good_table = netlink_frame(
            NFT_MSG_NEWTABLE,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &payload,
        );
        let done = netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[]);
        let mut doubled_done = done.clone();
        doubled_done.extend(&done);
        let mut nonzero_frame_padding =
            netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[0]);
        *nonzero_frame_padding.last_mut().expect("frame padding") = 1;
        for (sender, frame) in [
            (SocketAddr::new(9, 0), done.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE + 1,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT + 1,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWTABLE, 0, TEST_SEQUENCE, TEST_PORT, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NLMSG_OVERRUN, 0, TEST_SEQUENCE, TEST_PORT, &[]),
            ),
            (SocketAddr::new(0, 0), doubled_done),
            (SocketAddr::new(0, 0), nonzero_frame_padding),
        ] {
            assert!(
                table_state(INITIAL_GENERATION)
                    .ingest(sender, &frame, &mut CollectionBudget::production())
                    .is_err()
            );
        }
        assert!(matches!(
            table_state(INITIAL_GENERATION).ingest(
                SocketAddr::new(0, 0),
                &good_table,
                &mut CollectionBudget::production()
            ),
            Err(NftablesError::NotPristine)
        ));
    }

    #[test]
    fn table_payload_validation_is_exact_and_bounded() {
        let canonical = table_payload(INITIAL_GENERATION);
        validate_table_payload(&canonical, INITIAL_GENERATION).expect("canonical table");
        let mut wrong_family = canonical.clone();
        wrong_family[0] = AF_UNSPEC;
        let mut wrong_version = canonical.clone();
        wrong_version[1] = 1;
        let mut wrong_resource = canonical.clone();
        wrong_resource[2..4].copy_from_slice(&2_u16.to_be_bytes());
        let missing_name = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let duplicate = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_NAME, b"duplicate\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let unknown = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(99, &[]),
            ],
        );
        let mut flagged = canonical.clone();
        let offset = NFGENMSG_LEN;
        flagged[offset + 2..offset + 4]
            .copy_from_slice(&(NFTA_TABLE_NAME | NLA_F_NESTED).to_ne_bytes());
        let bad_flags = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &8_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let mut overlong_table_name = vec![b'x'; MAX_TABLE_NAME_BYTES + 1];
        *overlong_table_name.last_mut().expect("table-name byte") = 0;
        let overlong_name = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, &overlong_table_name),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let overlong_userdata = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_USERDATA, &[0; MAX_TABLE_USERDATA_BYTES + 1]),
            ],
        );
        for payload in [
            wrong_family,
            wrong_version,
            wrong_resource,
            missing_name,
            duplicate,
            unknown,
            flagged,
            bad_flags,
            overlong_name,
            overlong_userdata,
        ] {
            assert!(validate_table_payload(&payload, INITIAL_GENERATION).is_err());
        }

        let mut maximum_table_name = vec![b'x'; MAX_TABLE_NAME_BYTES];
        *maximum_table_name.last_mut().expect("table-name byte") = 0;
        let maximums = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, &maximum_table_name),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_USERDATA, &[0; MAX_TABLE_USERDATA_BYTES]),
            ],
        );
        validate_table_payload(&maximums, INITIAL_GENERATION).expect("maximum table attributes");
    }

    #[test]
    fn generation_bracket_must_be_initial_and_stable() {
        let baseline = classify_observation(INITIAL_GENERATION, INITIAL_GENERATION)
            .expect("initial generation");
        assert_eq!(baseline.generation, INITIAL_GENERATION);
        assert!(matches!(
            classify_observation(INITIAL_GENERATION, INITIAL_GENERATION + 1),
            Err(NftablesError::Inconsistent)
        ));
        assert!(matches!(
            classify_observation(INITIAL_GENERATION + 1, INITIAL_GENERATION + 1),
            Err(NftablesError::NotPristine)
        ));
    }

    #[test]
    fn error_echo_framing_padding_and_budgets_fail_closed() {
        let request = encode_request(RequestKind::TableDump, TEST_SEQUENCE).expect("table request");
        let mut error_payload = (-libc::EINVAL).to_ne_bytes().to_vec();
        error_payload.extend(request);
        assert!(matches!(
            parse_request_error(0, &error_payload, &request),
            Ok(NftablesError::Kernel(code)) if code == libc::EINVAL
        ));
        error_payload[4] ^= 1;
        assert!(matches!(
            parse_request_error(0, &error_payload, &request),
            Err(NftablesError::Malformed)
        ));

        let mut nonzero_padding = attribute(NFTA_GEN_PROC_NAME, b"x\0");
        *nonzero_padding.last_mut().expect("alignment padding") = 1;
        assert!(matches!(
            parse_attributes(&nonzero_padding, 1),
            Err(NftablesError::Malformed)
        ));
        let mut too_many_attributes = Vec::new();
        for _ in 0..=MAX_GENERATION_ATTRIBUTES {
            too_many_attributes.extend(attribute(1, &[]));
        }
        assert!(matches!(
            parse_attributes(&too_many_attributes, MAX_GENERATION_ATTRIBUTES),
            Err(NftablesError::Limit)
        ));

        let mut bytes = CollectionBudget {
            bytes: MAX_TOTAL_BYTES,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_TOTAL_BYTES,
            max_datagrams: MAX_DATAGRAMS,
            max_frames: MAX_FRAMES,
        };
        assert!(matches!(
            bytes.record_datagram(NLMSG_HEADER_LEN),
            Err(NftablesError::Limit)
        ));
        let mut datagrams = CollectionBudget::production();
        datagrams.datagrams = MAX_DATAGRAMS;
        assert!(matches!(
            datagrams.record_datagram(NLMSG_HEADER_LEN),
            Err(NftablesError::Limit)
        ));
        let mut frames = CollectionBudget::production();
        frames.frames = MAX_FRAMES;
        assert!(matches!(frames.record_frame(), Err(NftablesError::Limit)));
        assert!(matches!(
            CollectionBudget::production().can_receive(MAX_DATAGRAM_BYTES + 1),
            Err(NftablesError::Limit)
        ));
    }

    #[test]
    fn expired_deadline_fails_before_opening_a_socket() {
        assert!(matches!(
            observe_empty_nftables(Instant::now()),
            Err(NftablesError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn collector_observes_real_empty_namespace_without_mutating_it() {
        if env::var_os(LIVE_COLLECTOR_CHILD_ENV).is_some() {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(2))
                .expect("test deadline");
            let first = observe_empty_nftables(deadline).expect("empty nftables baseline");
            let second = observe_empty_nftables(deadline).expect("stable nftables baseline");
            assert_eq!(first, second);
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("nftables::tests::collector_observes_real_empty_namespace_without_mutating_it")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_COLLECTOR_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated empty-nftables collector test");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live nftables proof: user namespaces denied by policy");
            return;
        }
        assert!(output.status.success(), "isolated nftables proof failed");
    }

    #[test]
    fn user_namespace_policy_skip_is_exact() {
        for error in [
            b"unshare: unshare failed: Operation not permitted\n".as_slice(),
            b"unshare: write failed /proc/self/uid_map: Operation not permitted\n".as_slice(),
            b"unshare: write failed /proc/self/gid_map: Operation not permitted\n".as_slice(),
        ] {
            assert!(unprivileged_user_namespace_policy_denied(
                Some(1),
                &[],
                error
            ));
            assert!(!unprivileged_user_namespace_policy_denied(
                Some(2),
                &[],
                error
            ));
            assert!(!unprivileged_user_namespace_policy_denied(
                Some(1),
                b"unexpected",
                error
            ));
        }
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(1),
            &[],
            b"unshare: unexpected failure\n"
        ));
    }

    fn generation_state() -> GenerationState {
        let request =
            encode_request(RequestKind::Generation, TEST_SEQUENCE).expect("generation request");
        GenerationState::new(TEST_SEQUENCE, TEST_PORT, request)
    }

    fn table_state(generation: u32) -> TableDumpState {
        let request = encode_request(RequestKind::TableDump, TEST_SEQUENCE).expect("table request");
        TableDumpState::new(TEST_SEQUENCE, TEST_PORT, generation, request)
    }

    fn generation_payload(generation: u32, order: &[u16]) -> Vec<u8> {
        let mut payload = nfgenmsg(AF_UNSPEC, generation);
        for kind in order {
            match *kind {
                NFTA_GEN_ID => payload.extend(attribute(*kind, &generation.to_be_bytes())),
                NFTA_GEN_PROC_PID => {
                    payload.extend(attribute(*kind, &123_u32.to_be_bytes()));
                }
                NFTA_GEN_PROC_NAME => payload.extend(attribute(*kind, b"test\0")),
                _ => payload.extend(attribute(*kind, &[])),
            }
        }
        payload
    }

    fn generation_payload_with(
        generation: u32,
        id: &[u8],
        process_id: &[u8],
        process_name: &[u8],
    ) -> Vec<u8> {
        let mut payload = nfgenmsg(AF_UNSPEC, generation);
        payload.extend(attribute(NFTA_GEN_ID, id));
        payload.extend(attribute(NFTA_GEN_PROC_PID, process_id));
        payload.extend(attribute(NFTA_GEN_PROC_NAME, process_name));
        payload
    }

    fn table_payload(generation: u32) -> Vec<u8> {
        table_payload_from_attributes(
            generation,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_PAD, &[]),
                attribute(NFTA_TABLE_USERDATA, &[1, 2]),
                attribute(NFTA_TABLE_OWNER, &123_u32.to_be_bytes()),
            ],
        )
    }

    fn table_payload_from_attributes<const N: usize>(
        generation: u32,
        attributes: [Vec<u8>; N],
    ) -> Vec<u8> {
        let mut payload = nfgenmsg(NFPROTO_IPV4, generation);
        for attribute in attributes {
            payload.extend(attribute);
        }
        payload
    }

    fn nfgenmsg(family: u8, generation: u32) -> Vec<u8> {
        let mut payload = vec![family, NFNETLINK_V0];
        payload.extend(generation_resource_id(generation).to_be_bytes());
        payload
    }

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut bytes = Vec::with_capacity(aligned);
        bytes.extend(
            u16::try_from(length)
                .expect("test attribute length")
                .to_ne_bytes(),
        );
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(aligned, 0);
        bytes
    }

    fn netlink_frame(
        message_type: u16,
        flags: u16,
        sequence: u32,
        port: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut bytes = Vec::with_capacity(aligned);
        bytes.extend(
            u32::try_from(length)
                .expect("test frame length")
                .to_ne_bytes(),
        );
        bytes.extend(message_type.to_ne_bytes());
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(sequence.to_ne_bytes());
        bytes.extend(port.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(aligned, 0);
        bytes
    }

    fn unprivileged_user_namespace_policy_denied(
        status_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> bool {
        status_code == Some(1)
            && stdout.is_empty()
            && matches!(
                stderr,
                b"unshare: unshare failed: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
            )
    }
}
