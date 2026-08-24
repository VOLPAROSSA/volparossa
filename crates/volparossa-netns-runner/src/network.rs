//! Bounded proof of the enumerated read-only pre-`GO` network baseline.
//!
//! The collector opens only `NETLINK_ROUTE`, issues fixed dump requests, and
//! requires two identical canonical snapshots under one absolute deadline. It
//! pins the enumerated loopback configuration, including its mutable offload
//! limits, and the empty address, route, ordinary/proxy-neighbour, and nexthop
//! object sets plus the default rules. The composite proof also pins one fixed
//! namespace-local IPv4-forwarding proc record and a read-only generation-1
//! empty nftables-table observation. It exposes no network-state writer or
//! nftables mutation API; fixed GETs may trigger ordinary kernel module loading.

use std::{
    io,
    marker::PhantomData,
    os::fd::AsFd,
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use thiserror::Error;

use crate::{
    mounts::{Ipv4ForwardingRecordSnapshot, PrivateMountSetupError, PrivateMounts},
    nftables::{NftablesBaseline, NftablesError, observe_empty_nftables},
};

const NETWORK_PROOF_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_DATAGRAMS: usize = 64;
const MAX_FRAMES: usize = 256;
const MAX_ATTRIBUTES_PER_RECORD: usize = 128;
const MAX_LINKS: usize = 8;
const MAX_ADDRESSES: usize = 64;
const MAX_ROUTES: usize = 64;
const MAX_NEIGHBOURS: usize = 64;
const MAX_RULES: usize = 16;

const NLMSG_HEADER_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const IFADDR_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const NDMSG_LEN: usize = 12;
const NDMSG_FLAGS_OFFSET: usize = 10;
const NHMSG_LEN: usize = 8;
const FIB_RULE_HEADER_LEN: usize = 12;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWRULE: u16 = 32;
const RTM_GETRULE: u16 = 34;
const RTM_NEWNEXTHOP: u16 = 104;
const RTM_GETNEXTHOP: u16 = 106;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_QDISC: u16 = 6;
const IFLA_MASTER: u16 = 10;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_GROUP: u16 = 27;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_XDP: u16 = 43;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;

const IFF_LOOPBACK: u32 = 0x0008;
const ARPHRD_LOOPBACK: u16 = 772;
const IF_OPER_DOWN: u8 = 2;
const IN6_ADDR_GEN_MODE_EUI64: u8 = 0;
const LOOPBACK_MTU: u32 = 65_536;
const LOOPBACK_TX_QUEUE_LENGTH: u32 = 1_000;
const LOOPBACK_GSO_MAX_SEGMENTS: u32 = 65_535;
const LOOPBACK_OFFLOAD_MAX_SIZE: u32 = 65_536;
const LOOPBACK_OFFLOAD_LIMITS: [u32; 5] = [
    LOOPBACK_GSO_MAX_SEGMENTS,
    LOOPBACK_OFFLOAD_MAX_SIZE,
    LOOPBACK_OFFLOAD_MAX_SIZE,
    LOOPBACK_OFFLOAD_MAX_SIZE,
    LOOPBACK_OFFLOAD_MAX_SIZE,
];

const FRA_PRIORITY: u16 = 6;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_PROTOCOL: u16 = 21;

const RT_TABLE_DEFAULT: u32 = 253;
const RT_TABLE_MAIN: u32 = 254;
const RT_TABLE_LOCAL: u32 = 255;
const RTPROT_KERNEL: u8 = 2;
const FR_ACT_TO_TBL: u8 = 1;
const NTF_PROXY: u8 = 0x08;

/// A fixed, non-sensitive network-baseline failure.
#[derive(Debug, Error)]
pub(crate) enum NetworkError {
    /// A netlink socket operation or bounded wait failed.
    #[error("network proof netlink I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a fixed dump request.
    #[error("network proof netlink dump was rejected")]
    Kernel(i32),
    /// A response was malformed, ambiguous, or did not match its request.
    #[error("network proof netlink response was malformed or ambiguous")]
    Malformed,
    /// A response exceeded a fixed resource bound.
    #[error("network proof netlink response exceeded its fixed bound")]
    Limit,
    /// The two snapshots, or a later verification, differed.
    #[error("network namespace changed during proof")]
    Inconsistent,
    /// The stable snapshot was not the fixed pristine namespace baseline.
    #[error("network namespace is not pristine")]
    NotPristine,
    /// The fixed private-proc observation failed.
    #[error("network proof could not read the fixed private proc record")]
    PrivateProc(#[source] PrivateMountSetupError),
    /// The fixed read-only nftables observation failed.
    #[error("network proof could not establish the nftables baseline")]
    Nftables(#[source] NftablesError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ipv4ForwardingState {
    Disabled,
    Enabled,
}

#[derive(Debug, Eq, PartialEq)]
struct Ipv4ForwardingBaseline {
    record: Ipv4ForwardingRecordSnapshot,
    state: Ipv4ForwardingState,
}

#[derive(Debug, Eq, PartialEq)]
struct PreGoNetworkBaseline {
    rtnl: NetworkSnapshot,
    ipv4_forwarding: Ipv4ForwardingBaseline,
    nftables: NftablesBaseline,
}

/// An affine proof that the current thread observed the enumerated pre-`GO` network baseline.
///
/// The token is deliberately neither cloneable nor transferable to another
/// thread. [`Self::verify`] performs a fresh double snapshot before the proof is
/// used at a later protocol barrier.
pub(crate) struct PreGoNetworkProof {
    baseline: PreGoNetworkBaseline,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine baseline retained across one authorized, fully rolled-back mutation.
///
/// Construction revalidates the pristine observation immediately before the
/// mutation boundary. The token is neither cloneable nor transferable and is
/// consumed by the post-rollback verification.
pub(crate) struct MutationRollbackNetworkProof {
    baseline: PreGoNetworkBaseline,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PreGoNetworkProof {
    /// Consume the affine proof, re-prove the baseline, and require equality.
    pub(crate) fn verify(self, mounts: &PrivateMounts) -> Result<(), NetworkError> {
        require_current_baseline(mounts, &self.baseline)
    }

    /// Revalidate immediately before one authorized mutation and retain the
    /// exact baseline for a later rollback proof.
    pub(crate) fn authorize_mutation(
        self,
        mounts: &PrivateMounts,
    ) -> Result<MutationRollbackNetworkProof, NetworkError> {
        require_current_baseline(mounts, &self.baseline)?;
        Ok(MutationRollbackNetworkProof {
            baseline: self.baseline,
            _thread_bound: PhantomData,
        })
    }
}

impl MutationRollbackNetworkProof {
    /// Consume the retained baseline and prove exact restoration after rollback.
    pub(crate) fn verify_rollback(self, mounts: &PrivateMounts) -> Result<(), NetworkError> {
        require_current_baseline(mounts, &self.baseline)
    }
}

fn require_current_baseline(
    mounts: &PrivateMounts,
    expected: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    if collect_pre_go_network_baseline(mounts)? == *expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

/// Prove the enumerated read-only pre-`GO` network baseline without mutating it.
pub(crate) fn prove_pre_go_network_baseline(
    mounts: &PrivateMounts,
) -> Result<PreGoNetworkProof, NetworkError> {
    Ok(PreGoNetworkProof {
        baseline: collect_pre_go_network_baseline(mounts)?,
        _thread_bound: PhantomData,
    })
}

#[derive(Clone, Copy, Debug)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, NetworkError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(NetworkError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, NetworkError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(NetworkError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| NetworkError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), NetworkError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error().into())
        }
    }

    const fn instant(self) -> Instant {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DumpKind {
    Link,
    Address,
    Route,
    Neighbour,
    ProxyNeighbour,
    Nexthop,
    RuleV4,
    RuleV6,
}

impl DumpKind {
    const ALL: [Self; 8] = [
        Self::Link,
        Self::Address,
        Self::Route,
        Self::Neighbour,
        Self::ProxyNeighbour,
        Self::Nexthop,
        Self::RuleV4,
        Self::RuleV6,
    ];

    const fn request_type(self) -> u16 {
        match self {
            Self::Link => RTM_GETLINK,
            Self::Address => RTM_GETADDR,
            Self::Route => RTM_GETROUTE,
            Self::Neighbour | Self::ProxyNeighbour => RTM_GETNEIGH,
            Self::Nexthop => RTM_GETNEXTHOP,
            Self::RuleV4 | Self::RuleV6 => RTM_GETRULE,
        }
    }

    const fn response_type(self) -> u16 {
        match self {
            Self::Link => RTM_NEWLINK,
            Self::Address => RTM_NEWADDR,
            Self::Route => RTM_NEWROUTE,
            Self::Neighbour | Self::ProxyNeighbour => RTM_NEWNEIGH,
            Self::Nexthop => RTM_NEWNEXTHOP,
            Self::RuleV4 | Self::RuleV6 => RTM_NEWRULE,
        }
    }

    fn request_payload(self) -> Vec<u8> {
        match self {
            Self::Link => vec![0; IFINFO_LEN],
            Self::Address => vec![0; IFADDR_LEN],
            Self::Route => vec![0; RTMSG_LEN],
            Self::Neighbour => vec![0; NDMSG_LEN],
            Self::ProxyNeighbour => {
                let mut payload = vec![0; NDMSG_LEN];
                payload[NDMSG_FLAGS_OFFSET] = NTF_PROXY;
                payload
            }
            Self::Nexthop => vec![0; NHMSG_LEN],
            Self::RuleV4 => {
                let mut payload = vec![0; FIB_RULE_HEADER_LEN];
                payload[0] = AF_INET;
                payload
            }
            Self::RuleV6 => {
                let mut payload = vec![0; FIB_RULE_HEADER_LEN];
                payload[0] = AF_INET6;
                payload
            }
        }
    }

    const fn fixed_header_len(self) -> usize {
        match self {
            Self::Link => IFINFO_LEN,
            Self::Address => IFADDR_LEN,
            Self::Route => RTMSG_LEN,
            Self::Neighbour | Self::ProxyNeighbour => NDMSG_LEN,
            Self::Nexthop => NHMSG_LEN,
            Self::RuleV4 | Self::RuleV6 => FIB_RULE_HEADER_LEN,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NetworkSnapshot {
    links: Vec<Vec<u8>>,
    addresses: Vec<Vec<u8>>,
    routes: Vec<Vec<u8>>,
    neighbours: Vec<Vec<u8>>,
    proxy_neighbours: Vec<Vec<u8>>,
    nexthops: Vec<Vec<u8>>,
    rules_v4: Vec<Vec<u8>>,
    rules_v6: Vec<Vec<u8>>,
}

impl NetworkSnapshot {
    fn records_mut(&mut self, kind: DumpKind) -> &mut Vec<Vec<u8>> {
        match kind {
            DumpKind::Link => &mut self.links,
            DumpKind::Address => &mut self.addresses,
            DumpKind::Route => &mut self.routes,
            DumpKind::Neighbour => &mut self.neighbours,
            DumpKind::ProxyNeighbour => &mut self.proxy_neighbours,
            DumpKind::Nexthop => &mut self.nexthops,
            DumpKind::RuleV4 => &mut self.rules_v4,
            DumpKind::RuleV6 => &mut self.rules_v6,
        }
    }

    fn canonicalize(&mut self) -> Result<(), NetworkError> {
        for records in [
            &mut self.links,
            &mut self.addresses,
            &mut self.routes,
            &mut self.neighbours,
            &mut self.proxy_neighbours,
            &mut self.nexthops,
            &mut self.rules_v4,
            &mut self.rules_v6,
        ] {
            records.sort_unstable();
            if records.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(NetworkError::Malformed);
            }
        }
        Ok(())
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

    fn can_receive(&self, length: usize) -> Result<(), NetworkError> {
        if !(NLMSG_HEADER_LEN..=MAX_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(NetworkError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), NetworkError> {
        self.can_receive(length)?;
        self.bytes = self.bytes.checked_add(length).ok_or(NetworkError::Limit)?;
        self.datagrams = self.datagrams.checked_add(1).ok_or(NetworkError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(NetworkError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), NetworkError> {
        self.frames = self.frames.checked_add(1).ok_or(NetworkError::Limit)?;
        if self.frames > self.max_frames {
            return Err(NetworkError::Limit);
        }
        Ok(())
    }
}

struct DumpState {
    kind: DumpKind,
    sequence: u32,
    local_port: u32,
    request: Vec<u8>,
    done: bool,
    records: Vec<Vec<u8>>,
}

impl DumpState {
    fn new(kind: DumpKind, sequence: u32, local_port: u32, request: Vec<u8>) -> Self {
        Self {
            kind,
            sequence,
            local_port,
            request,
            done: false,
            records: Vec::new(),
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), NetworkError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(NetworkError::Malformed);
        }
        budget.record_datagram(bytes.len())?;
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            if remaining.len() < NLMSG_HEADER_LEN {
                return Err(NetworkError::Malformed);
            }
            let length =
                usize::try_from(read_u32(remaining, 0)?).map_err(|_| NetworkError::Malformed)?;
            let aligned = align4(length)?;
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(NetworkError::Malformed);
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(NetworkError::Malformed);
            }
            budget.record_frame()?;
            self.ingest_frame(&remaining[..length])?;
            offset = offset.checked_add(aligned).ok_or(NetworkError::Limit)?;
            if self.done && offset != bytes.len() {
                return Err(NetworkError::Malformed);
            }
        }
        Ok(())
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
        if read_u32(frame, 8)? != self.sequence || read_u32(frame, 12)? != self.local_port {
            return Err(NetworkError::Malformed);
        }
        let message_type = read_u16(frame, 4)?;
        let flags = read_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        match message_type {
            NLMSG_DONE => {
                parse_done(flags, payload)?;
                self.done = true;
            }
            NLMSG_ERROR => {
                return Err(parse_dump_error(flags, payload, &self.request)?);
            }
            NLMSG_OVERRUN => return Err(NetworkError::Malformed),
            message_type if message_type == self.kind.response_type() && flags == NLM_F_MULTI => {
                validate_record(self.kind, payload)?;
                let maximum = record_limit(self.kind);
                if self.records.len() >= maximum {
                    return Err(NetworkError::Limit);
                }
                self.records.push(payload.to_vec());
            }
            _ => return Err(NetworkError::Malformed),
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<Vec<u8>>, NetworkError> {
        if self.done {
            Ok(self.records)
        } else {
            Err(NetworkError::Malformed)
        }
    }
}

struct NetlinkCollector {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkCollector {
    fn connect(deadline: Deadline) -> Result<Self, NetworkError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(NetworkError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn collect_snapshot(
        &mut self,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<NetworkSnapshot, NetworkError> {
        let mut snapshot = NetworkSnapshot::default();
        for kind in DumpKind::ALL {
            *snapshot.records_mut(kind) = self.collect_dump(kind, deadline, budget)?;
        }
        snapshot.canonicalize()?;
        Ok(snapshot)
    }

    fn collect_dump(
        &mut self,
        kind: DumpKind,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<Vec<Vec<u8>>, NetworkError> {
        let sequence = self.next_sequence()?;
        let request = encode_dump_request(kind, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let mut state = DumpState::new(kind, sequence, self.local_port, request);
        while !state.done {
            let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
            state.ingest(sender, &bytes, budget)?;
        }
        deadline.ensure_unexpired()?;
        state.finish()
    }

    fn next_sequence(&mut self) -> Result<u32, NetworkError> {
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or(NetworkError::Limit)?;
        if sequence == 0 {
            Err(NetworkError::Malformed)
        } else {
            Ok(sequence)
        }
    }
}

#[cfg(test)]
fn collect_consistent_pristine_snapshot() -> Result<NetworkSnapshot, NetworkError> {
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    collect_consistent_pristine_snapshot_before(deadline)
}

fn collect_consistent_pristine_snapshot_before(
    deadline: Deadline,
) -> Result<NetworkSnapshot, NetworkError> {
    let mut collector = NetlinkCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let first = collector.collect_snapshot(deadline, &mut budget)?;
    let second = collector.collect_snapshot(deadline, &mut budget)?;
    deadline.ensure_unexpired()?;
    verify_consistent_pristine(&first, &second)?;
    deadline.ensure_unexpired()?;
    Ok(first)
}

fn collect_pre_go_network_baseline(
    mounts: &PrivateMounts,
) -> Result<PreGoNetworkBaseline, NetworkError> {
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    let forwarding_before = mounts
        .read_ipv4_forwarding_record()
        .map_err(NetworkError::PrivateProc)?;
    let rtnl = collect_consistent_pristine_snapshot_before(deadline)?;
    let nftables = observe_empty_nftables(deadline.instant()).map_err(NetworkError::Nftables)?;
    let forwarding_after = mounts
        .read_ipv4_forwarding_record()
        .map_err(NetworkError::PrivateProc)?;
    deadline.ensure_unexpired()?;
    if forwarding_before != forwarding_after {
        return Err(NetworkError::Inconsistent);
    }
    let state =
        classify_ipv4_forwarding_records(forwarding_before.bytes(), forwarding_after.bytes())?;
    Ok(PreGoNetworkBaseline {
        rtnl,
        ipv4_forwarding: Ipv4ForwardingBaseline {
            record: forwarding_before,
            state,
        },
        nftables,
    })
}

fn classify_ipv4_forwarding_records(
    before: &[u8],
    after: &[u8],
) -> Result<Ipv4ForwardingState, NetworkError> {
    if before != after {
        return Err(NetworkError::Inconsistent);
    }
    match before {
        b"0\n" => Ok(Ipv4ForwardingState::Disabled),
        b"1\n" => Ok(Ipv4ForwardingState::Enabled),
        _ => Err(NetworkError::Malformed),
    }
}

fn verify_consistent_pristine(
    first: &NetworkSnapshot,
    second: &NetworkSnapshot,
) -> Result<(), NetworkError> {
    if first == second {
        verify_pristine_snapshot(first)
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn verify_pristine_snapshot(snapshot: &NetworkSnapshot) -> Result<(), NetworkError> {
    if snapshot.links.len() != 1
        || !snapshot.addresses.is_empty()
        || !snapshot.routes.is_empty()
        || !snapshot.neighbours.is_empty()
        || !snapshot.proxy_neighbours.is_empty()
        || !snapshot.nexthops.is_empty()
    {
        return Err(NetworkError::NotPristine);
    }
    verify_loopback(&snapshot.links[0])?;
    verify_rules(AF_INET, &snapshot.rules_v4, &expected_ipv4_rules())?;
    verify_rules(AF_INET6, &snapshot.rules_v6, &expected_ipv6_rules())
}

fn verify_loopback(payload: &[u8]) -> Result<(), NetworkError> {
    verify_loopback_header(payload)?;
    let attributes = parse_attributes(&payload[IFINFO_LEN..])?;
    let mut name = None;
    let mut operstate = None;
    let mut address = None;
    let mut broadcast = None;
    let mut mtu = None;
    let mut queue_length = None;
    let mut qdisc = None;
    let mut linkmode = None;
    let mut group = None;
    let mut promiscuity = None;
    let mut allmulti = None;
    let mut protocol_down = None;
    let mut offload_limits = [None; LOOPBACK_OFFLOAD_LIMITS.len()];
    let mut address_families_seen = false;
    let mut xdp_seen = false;
    for attribute in attributes {
        match attribute.kind {
            IFLA_ADDRESS => set_once(&mut address, attribute.unflagged_payload()?)?,
            IFLA_BROADCAST => set_once(&mut broadcast, attribute.unflagged_payload()?)?,
            IFLA_IFNAME => set_once(&mut name, attribute.unflagged_payload()?)?,
            IFLA_MTU => set_once(&mut mtu, read_exact_u32(attribute.unflagged_payload()?)?)?,
            IFLA_QDISC => set_once(&mut qdisc, attribute.unflagged_payload()?)?,
            IFLA_TXQLEN => set_once(
                &mut queue_length,
                read_exact_u32(attribute.unflagged_payload()?)?,
            )?,
            IFLA_OPERSTATE => set_once(&mut operstate, attribute.unflagged_payload()?)?,
            IFLA_LINKMODE => set_once(
                &mut linkmode,
                read_exact_u8(attribute.unflagged_payload()?)?,
            )?,
            IFLA_AF_SPEC => {
                if address_families_seen {
                    return Err(NetworkError::NotPristine);
                }
                address_families_seen = true;
                verify_address_family_spec(attribute)?;
            }
            IFLA_GROUP => set_once(&mut group, read_exact_u32(attribute.unflagged_payload()?)?)?,
            IFLA_PROMISCUITY => set_once(
                &mut promiscuity,
                read_exact_u32(attribute.unflagged_payload()?)?,
            )?,
            IFLA_PROTO_DOWN => set_once(
                &mut protocol_down,
                read_exact_u8(attribute.unflagged_payload()?)?,
            )?,
            kind @ (IFLA_GSO_MAX_SEGS
            | IFLA_GSO_MAX_SIZE
            | IFLA_GRO_MAX_SIZE
            | IFLA_GSO_IPV4_MAX_SIZE
            | IFLA_GRO_IPV4_MAX_SIZE) => {
                let index = offload_limit_index(kind).ok_or(NetworkError::Malformed)?;
                set_once(
                    &mut offload_limits[index],
                    read_exact_u32(attribute.unflagged_payload()?)?,
                )?;
            }
            IFLA_ALLMULTI => set_once(
                &mut allmulti,
                read_exact_u32(attribute.unflagged_payload()?)?,
            )?,
            IFLA_LINK | IFLA_MASTER | IFLA_LINKINFO | IFLA_IFALIAS | IFLA_ALT_IFNAME => {
                return Err(NetworkError::NotPristine);
            }
            IFLA_PROP_LIST if !attribute.payload.is_empty() => {
                return Err(NetworkError::NotPristine);
            }
            IFLA_XDP => {
                if xdp_seen {
                    return Err(NetworkError::NotPristine);
                }
                xdp_seen = true;
                verify_xdp(attribute)?;
            }
            _ => {}
        }
    }
    if name == Some(&b"lo\0"[..])
        && operstate == Some(&[IF_OPER_DOWN][..])
        && address == Some(&[0; 6][..])
        && broadcast == Some(&[0; 6][..])
        && mtu == Some(LOOPBACK_MTU)
        && queue_length == Some(LOOPBACK_TX_QUEUE_LENGTH)
        && qdisc == Some(&b"noop\0"[..])
        && linkmode == Some(0)
        && group == Some(0)
        && promiscuity == Some(0)
        && allmulti == Some(0)
        && protocol_down == Some(0)
        && offload_limits == LOOPBACK_OFFLOAD_LIMITS.map(Some)
        && address_families_seen
    {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn verify_loopback_header(payload: &[u8]) -> Result<(), NetworkError> {
    if payload.len() < IFINFO_LEN
        || payload[0] != AF_UNSPEC
        || payload[1] != 0
        || read_u16(payload, 2)? != ARPHRD_LOOPBACK
        || read_i32(payload, 4)? != 1
        || read_u32(payload, 8)? != IFF_LOOPBACK
        || read_u32(payload, 12)? != 0
    {
        Err(NetworkError::NotPristine)
    } else {
        Ok(())
    }
}

const fn offload_limit_index(kind: u16) -> Option<usize> {
    match kind {
        IFLA_GSO_MAX_SEGS => Some(0),
        IFLA_GSO_MAX_SIZE => Some(1),
        IFLA_GRO_MAX_SIZE => Some(2),
        IFLA_GSO_IPV4_MAX_SIZE => Some(3),
        IFLA_GRO_IPV4_MAX_SIZE => Some(4),
        _ => None,
    }
}

fn verify_address_family_spec(attribute: Attribute<'_>) -> Result<(), NetworkError> {
    if attribute.flags != 0 {
        return Err(NetworkError::NotPristine);
    }
    let mut ipv4_seen = false;
    let mut ipv6 = None;
    for family in parse_attributes(attribute.payload)? {
        if family.flags != 0 {
            return Err(NetworkError::NotPristine);
        }
        match family.kind {
            family_kind if family_kind == u16::from(AF_INET) => {
                if ipv4_seen {
                    return Err(NetworkError::NotPristine);
                }
                ipv4_seen = true;
                parse_attributes(family.payload)?;
            }
            family_kind if family_kind == u16::from(AF_INET6) => {
                set_once(&mut ipv6, family.payload)?;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    let mut address_generation_mode = None;
    for ipv6_attribute in parse_attributes(ipv6.ok_or(NetworkError::NotPristine)?)? {
        if ipv6_attribute.kind == IFLA_INET6_ADDR_GEN_MODE {
            set_once(
                &mut address_generation_mode,
                read_exact_u8(ipv6_attribute.unflagged_payload()?)?,
            )?;
        }
    }
    if ipv4_seen && address_generation_mode == Some(IN6_ADDR_GEN_MODE_EUI64) {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn verify_xdp(attribute: Attribute<'_>) -> Result<(), NetworkError> {
    if attribute.flags != 0 {
        return Err(NetworkError::NotPristine);
    }
    let mut attached_seen = false;
    for nested in parse_attributes(attribute.payload)? {
        if nested.kind != IFLA_XDP_ATTACHED || nested.flags != 0 || nested.payload != [0] {
            return Err(NetworkError::NotPristine);
        }
        if attached_seen {
            return Err(NetworkError::NotPristine);
        }
        attached_seen = true;
    }
    if attached_seen {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Rule {
    priority: u32,
    table: u32,
}

const fn expected_ipv4_rules() -> [Rule; 3] {
    [
        Rule {
            priority: 0,
            table: RT_TABLE_LOCAL,
        },
        Rule {
            priority: 32_766,
            table: RT_TABLE_MAIN,
        },
        Rule {
            priority: 32_767,
            table: RT_TABLE_DEFAULT,
        },
    ]
}

const fn expected_ipv6_rules() -> [Rule; 2] {
    [
        Rule {
            priority: 0,
            table: RT_TABLE_LOCAL,
        },
        Rule {
            priority: 32_766,
            table: RT_TABLE_MAIN,
        },
    ]
}

fn verify_rules(family: u8, payloads: &[Vec<u8>], expected: &[Rule]) -> Result<(), NetworkError> {
    if payloads.len() != expected.len() {
        return Err(NetworkError::NotPristine);
    }
    let mut actual = payloads
        .iter()
        .map(|payload| decode_rule(family, payload))
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_unstable();
    if actual == expected {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn decode_rule(expected_family: u8, payload: &[u8]) -> Result<Rule, NetworkError> {
    if payload.len() < FIB_RULE_HEADER_LEN
        || payload[0] != expected_family
        || payload[1..4] != [0, 0, 0]
        || payload[5..7] != [0, 0]
        || payload[7] != FR_ACT_TO_TBL
        || payload[8..12] != [0, 0, 0, 0]
    {
        return Err(NetworkError::NotPristine);
    }
    let header_table = u32::from(payload[4]);
    let mut priority = None;
    let mut table = None;
    let mut suppress_prefix = None;
    let mut protocol = None;
    for attribute in parse_attributes(&payload[FIB_RULE_HEADER_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            FRA_PRIORITY => set_once(&mut priority, read_exact_u32(value)?)?,
            FRA_SUPPRESS_PREFIXLEN => set_once(&mut suppress_prefix, read_exact_u32(value)?)?,
            FRA_TABLE => set_once(&mut table, read_exact_u32(value)?)?,
            FRA_PROTOCOL => {
                let [value] = value else {
                    return Err(NetworkError::NotPristine);
                };
                set_once(&mut protocol, *value)?;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    let table = table.ok_or(NetworkError::NotPristine)?;
    let priority = priority.unwrap_or(0);
    if header_table != table
        || suppress_prefix != Some(u32::MAX)
        || protocol != Some(RTPROT_KERNEL)
        || (priority == 0 && payload_has_attribute(payload, FRA_PRIORITY)?)
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(Rule { priority, table })
}

fn payload_has_attribute(payload: &[u8], kind: u16) -> Result<bool, NetworkError> {
    Ok(parse_attributes(&payload[FIB_RULE_HEADER_LEN..])?
        .iter()
        .any(|attribute| attribute.kind == kind))
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

impl<'a> Attribute<'a> {
    fn unflagged_payload(self) -> Result<&'a [u8], NetworkError> {
        if self.flags == 0 {
            Ok(self.payload)
        } else {
            Err(NetworkError::NotPristine)
        }
    }
}

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, NetworkError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(NetworkError::Malformed);
        }
        if attributes.len() >= MAX_ATTRIBUTES_PER_RECORD {
            return Err(NetworkError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let raw_kind = read_u16(bytes, 2)?;
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(NetworkError::Malformed);
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(NetworkError::Malformed);
        }
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(NetworkError::Malformed);
        }
        attributes.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags,
            payload: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(attributes)
}

fn validate_record(kind: DumpKind, payload: &[u8]) -> Result<(), NetworkError> {
    if payload.len() < kind.fixed_header_len() {
        return Err(NetworkError::Malformed);
    }
    parse_attributes(&payload[kind.fixed_header_len()..])?;
    if matches!(kind, DumpKind::RuleV4) && payload[0] != AF_INET
        || matches!(kind, DumpKind::RuleV6) && payload[0] != AF_INET6
    {
        return Err(NetworkError::Malformed);
    }
    Ok(())
}

const fn record_limit(kind: DumpKind) -> usize {
    match kind {
        DumpKind::Link => MAX_LINKS,
        DumpKind::Address => MAX_ADDRESSES,
        DumpKind::Route => MAX_ROUTES,
        DumpKind::Neighbour | DumpKind::ProxyNeighbour | DumpKind::Nexthop => MAX_NEIGHBOURS,
        DumpKind::RuleV4 | DumpKind::RuleV6 => MAX_RULES,
    }
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), NetworkError> {
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
) -> Result<(Vec<u8>, SocketAddr), NetworkError> {
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
            return Err(NetworkError::Malformed);
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
            return Err(NetworkError::Malformed);
        }
        return Ok((bytes, sender));
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), NetworkError> {
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
                    return Err(NetworkError::Malformed);
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }
}

fn encode_dump_request(kind: DumpKind, sequence: u32) -> Result<Vec<u8>, NetworkError> {
    if sequence == 0 {
        return Err(NetworkError::Malformed);
    }
    let payload = kind.request_payload();
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(NetworkError::Limit)?;
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| NetworkError::Limit)?
            .to_ne_bytes(),
    );
    request.extend_from_slice(&kind.request_type().to_ne_bytes());
    request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&payload);
    Ok(request)
}

fn parse_done(flags: u16, payload: &[u8]) -> Result<(), NetworkError> {
    if flags != NLM_F_MULTI {
        return Err(NetworkError::Malformed);
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 => Err(NetworkError::Kernel(errno.saturating_abs())),
            _ => Err(NetworkError::Malformed),
        },
        _ => Err(NetworkError::Malformed),
    }
}

fn parse_dump_error(
    flags: u16,
    payload: &[u8],
    request: &[u8],
) -> Result<NetworkError, NetworkError> {
    if flags != 0 || payload.len() != 4 + request.len() {
        return Err(NetworkError::Malformed);
    }
    let errno = read_i32(payload, 0)?;
    if payload[4..] != *request {
        return Err(NetworkError::Malformed);
    }
    if errno < 0 {
        Ok(NetworkError::Kernel(errno.saturating_abs()))
    } else {
        Err(NetworkError::Malformed)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NetworkError> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or(NetworkError::Limit)?)
        .ok_or(NetworkError::Malformed)?
        .try_into()
        .map_err(|_| NetworkError::Malformed)?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NetworkError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NetworkError::Limit)?)
        .ok_or(NetworkError::Malformed)?
        .try_into()
        .map_err(|_| NetworkError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, NetworkError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NetworkError::Limit)?)
        .ok_or(NetworkError::Malformed)?
        .try_into()
        .map_err(|_| NetworkError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, NetworkError> {
    if bytes.len() == 4 {
        read_u32(bytes, 0)
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn read_exact_u8(bytes: &[u8]) -> Result<u8, NetworkError> {
    let [value] = bytes else {
        return Err(NetworkError::NotPristine);
    };
    Ok(*value)
}

fn align4(length: usize) -> Result<usize, NetworkError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(NetworkError::Limit)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NetworkError> {
    if slot.replace(value).is_some() {
        Err(NetworkError::NotPristine)
    } else {
        Ok(())
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "network proof deadline expired")
}

#[cfg(test)]
mod tests {
    use std::{env, process::Command};

    use super::*;

    const LIVE_COLLECTOR_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_COLLECTOR_CHILD";
    const LIVE_MUTATION_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_MUTATION_CHILD";
    const TEST_SEQUENCE: u32 = 7;
    const TEST_PORT: u32 = 41;

    #[test]
    fn fixed_requests_have_exact_headers_and_payloads() {
        for kind in DumpKind::ALL {
            let request = encode_dump_request(kind, TEST_SEQUENCE).expect("request");
            assert_eq!(
                read_u32(&request, 0).expect("length") as usize,
                request.len()
            );
            assert_eq!(read_u16(&request, 4).expect("type"), kind.request_type());
            assert_eq!(
                read_u16(&request, 6).expect("flags"),
                NLM_F_REQUEST | NLM_F_DUMP
            );
            assert_eq!(read_u32(&request, 8).expect("sequence"), TEST_SEQUENCE);
            assert_eq!(read_u32(&request, 12).expect("port"), 0);
            assert_eq!(&request[NLMSG_HEADER_LEN..], kind.request_payload());
        }
        assert!(matches!(
            encode_dump_request(DumpKind::Link, 0),
            Err(NetworkError::Malformed)
        ));
        let ordinary = encode_dump_request(DumpKind::Neighbour, TEST_SEQUENCE).expect("ordinary");
        let proxy =
            encode_dump_request(DumpKind::ProxyNeighbour, TEST_SEQUENCE).expect("proxy request");
        assert_eq!(ordinary[NLMSG_HEADER_LEN + NDMSG_FLAGS_OFFSET], 0);
        assert_eq!(proxy[NLMSG_HEADER_LEN + NDMSG_FLAGS_OFFSET], NTF_PROXY);
    }

    #[test]
    fn exact_pristine_snapshot_is_accepted() {
        let snapshot = pristine_snapshot();
        verify_pristine_snapshot(&snapshot).expect("pristine baseline");
        verify_consistent_pristine(&snapshot, &snapshot).expect("consistent pristine baseline");
    }

    #[test]
    fn ipv4_forwarding_baseline_is_canonical_and_stable() {
        assert_eq!(
            classify_ipv4_forwarding_records(b"0\n", b"0\n").expect("disabled baseline"),
            Ipv4ForwardingState::Disabled
        );
        assert_eq!(
            classify_ipv4_forwarding_records(b"1\n", b"1\n").expect("enabled baseline"),
            Ipv4ForwardingState::Enabled
        );
        for malformed in [
            b"".as_slice(),
            b"0",
            b"00\n",
            b"2\n",
            b"0\r\n",
            b"0\0",
            b"0\nextra",
        ] {
            assert!(matches!(
                classify_ipv4_forwarding_records(malformed, malformed),
                Err(NetworkError::Malformed)
            ));
        }
        assert!(matches!(
            classify_ipv4_forwarding_records(b"0\n", b"1\n"),
            Err(NetworkError::Inconsistent)
        ));
        assert!(matches!(
            classify_ipv4_forwarding_records(b"1\n", b"0\n"),
            Err(NetworkError::Inconsistent)
        ));
    }

    #[test]
    fn distinct_snapshots_are_rejected_before_baseline_classification() {
        let first = pristine_snapshot();
        let mut second = first.clone();
        second.addresses.push(vec![0; IFADDR_LEN]);
        assert!(matches!(
            verify_consistent_pristine(&first, &second),
            Err(NetworkError::Inconsistent)
        ));
    }

    #[test]
    fn loopback_identity_and_state_are_exact() {
        for mutate in [
            mutate_link_index as fn(&mut [u8]),
            mutate_link_flags,
            mutate_link_type,
            mutate_link_name,
            mutate_link_operstate,
        ] {
            let mut snapshot = pristine_snapshot();
            mutate(snapshot.links[0].as_mut_slice());
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn loopback_relationship_attributes_are_rejected() {
        for kind in [
            IFLA_LINK,
            IFLA_MASTER,
            IFLA_LINKINFO,
            IFLA_IFALIAS,
            IFLA_ALT_IFNAME,
        ] {
            let mut snapshot = pristine_snapshot();
            snapshot.links[0].extend(attribute(kind, &[1, 0, 0, 0]));
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn loopback_mutable_defaults_are_exact() {
        let mut wrong_address_families = attribute(u16::from(AF_INET), &[]);
        let wrong_ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[1]);
        wrong_address_families.extend(attribute(u16::from(AF_INET6), &wrong_ipv6));
        for (kind, replacement) in [
            (IFLA_ADDRESS, vec![1; 6]),
            (IFLA_BROADCAST, vec![1; 6]),
            (IFLA_MTU, 1_400_u32.to_ne_bytes().to_vec()),
            (IFLA_TXQLEN, 123_u32.to_ne_bytes().to_vec()),
            (IFLA_QDISC, b"noqueue\0".to_vec()),
            (IFLA_LINKMODE, vec![1]),
            (IFLA_GROUP, 42_u32.to_ne_bytes().to_vec()),
            (IFLA_PROMISCUITY, 1_u32.to_ne_bytes().to_vec()),
            (IFLA_ALLMULTI, 1_u32.to_ne_bytes().to_vec()),
            (IFLA_PROTO_DOWN, vec![1]),
            (IFLA_GSO_MAX_SEGS, 1_u32.to_ne_bytes().to_vec()),
            (IFLA_GSO_MAX_SIZE, 70_000_u32.to_ne_bytes().to_vec()),
            (IFLA_GRO_MAX_SIZE, 70_000_u32.to_ne_bytes().to_vec()),
            (IFLA_GSO_IPV4_MAX_SIZE, 70_000_u32.to_ne_bytes().to_vec()),
            (IFLA_GRO_IPV4_MAX_SIZE, 70_000_u32.to_ne_bytes().to_vec()),
            (IFLA_AF_SPEC, wrong_address_families),
        ] {
            let mut snapshot = pristine_snapshot();
            snapshot.links[0] = replace_link_attribute(&snapshot.links[0], kind, &replacement);
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn loopback_duplicate_identity_and_attached_xdp_are_rejected() {
        let mut duplicate_name = pristine_snapshot();
        duplicate_name.links[0].extend(attribute(IFLA_IFNAME, b"lo\0"));
        let mut attached_xdp = pristine_snapshot();
        attached_xdp.links[0].extend(attribute(IFLA_XDP, &attribute(IFLA_XDP_ATTACHED, &[1])));
        let mut duplicate_xdp = pristine_snapshot();
        let unattached = attribute(IFLA_XDP, &attribute(IFLA_XDP_ATTACHED, &[0]));
        duplicate_xdp.links[0].extend(&unattached);
        duplicate_xdp.links[0].extend(unattached);
        for snapshot in [duplicate_name, attached_xdp, duplicate_xdp] {
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn any_network_object_or_extra_link_is_rejected() {
        let mut variants = Vec::new();
        let mut address = pristine_snapshot();
        address.addresses.push(vec![0; IFADDR_LEN]);
        variants.push(address);
        let mut route = pristine_snapshot();
        route.routes.push(vec![0; RTMSG_LEN]);
        variants.push(route);
        let mut neighbour = pristine_snapshot();
        neighbour.neighbours.push(vec![0; NDMSG_LEN]);
        variants.push(neighbour);
        let mut proxy_neighbour = pristine_snapshot();
        proxy_neighbour.proxy_neighbours.push(vec![0; NDMSG_LEN]);
        variants.push(proxy_neighbour);
        let mut nexthop = pristine_snapshot();
        nexthop.nexthops.push(vec![0; NHMSG_LEN]);
        variants.push(nexthop);
        let mut link = pristine_snapshot();
        link.links.push(link.links[0].clone());
        variants.push(link);
        for snapshot in variants {
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn routing_policy_database_is_exact() {
        let mut missing = pristine_snapshot();
        missing.rules_v4.pop();
        let mut extra = pristine_snapshot();
        extra
            .rules_v6
            .push(rule_payload(AF_INET6, 32_767, RT_TABLE_DEFAULT));
        let mut wrong_table = pristine_snapshot();
        wrong_table.rules_v4[1] = rule_payload(AF_INET, 32_766, RT_TABLE_DEFAULT);
        let mut wrong_priority = pristine_snapshot();
        wrong_priority.rules_v6[1] = rule_payload(AF_INET6, 12, RT_TABLE_MAIN);
        let mut wrong_flags = pristine_snapshot();
        wrong_flags.rules_v4[0][8] = 1;
        let mut wrong_protocol = pristine_snapshot();
        let last = wrong_protocol.rules_v6[0].len() - 4;
        wrong_protocol.rules_v6[0][last] = 3;
        let mut unknown_attribute = pristine_snapshot();
        unknown_attribute.rules_v4[0].extend(attribute(99, &[]));
        for snapshot in [
            missing,
            extra,
            wrong_table,
            wrong_priority,
            wrong_flags,
            wrong_protocol,
            unknown_attribute,
        ] {
            assert!(matches!(
                verify_pristine_snapshot(&snapshot),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn dump_parser_accepts_data_then_exact_done() {
        let request = encode_dump_request(DumpKind::Link, TEST_SEQUENCE).expect("request");
        let mut state = DumpState::new(DumpKind::Link, TEST_SEQUENCE, TEST_PORT, request);
        let mut datagram = netlink_frame(
            RTM_NEWLINK,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &link_payload(),
        );
        datagram.extend(netlink_frame(
            NLMSG_DONE,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &0_i32.to_ne_bytes(),
        ));
        state
            .ingest(
                SocketAddr::new(0, 0),
                &datagram,
                &mut CollectionBudget::production(),
            )
            .expect("dump");
        assert_eq!(state.finish().expect("finished"), vec![link_payload()]);
    }

    #[test]
    fn dump_parser_rejects_untrusted_envelope_fields() {
        let good = netlink_frame(
            RTM_NEWLINK,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &link_payload(),
        );
        for (sender, bytes) in [
            (SocketAddr::new(9, 0), good.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    RTM_NEWLINK,
                    NLM_F_MULTI,
                    TEST_SEQUENCE + 1,
                    TEST_PORT,
                    &link_payload(),
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    RTM_NEWLINK,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT + 1,
                    &link_payload(),
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(RTM_NEWLINK, 0, TEST_SEQUENCE, TEST_PORT, &link_payload()),
            ),
        ] {
            let mut state = link_state();
            assert!(matches!(
                state.ingest(sender, &bytes, &mut CollectionBudget::production()),
                Err(NetworkError::Malformed)
            ));
        }
    }

    #[test]
    fn framing_rejects_short_lengths_padding_and_trailing_after_done() {
        let mut short = vec![0; NLMSG_HEADER_LEN];
        short[0..4].copy_from_slice(&8_u32.to_ne_bytes());
        let mut padded = netlink_frame(
            RTM_NEWLINK,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &link_payload(),
        );
        let declared = read_u32(&padded, 0).expect("declared") as usize;
        if declared % 4 == 0 {
            padded[0..4].copy_from_slice(&u32::try_from(declared - 1).expect("fits").to_ne_bytes());
            padded[declared - 1] = 1;
        }
        let mut trailing = netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[]);
        trailing.extend(netlink_frame(
            NLMSG_DONE,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &[],
        ));
        for bytes in [short, padded, trailing] {
            let mut state = link_state();
            assert!(matches!(
                state.ingest(
                    SocketAddr::new(0, 0),
                    &bytes,
                    &mut CollectionBudget::production()
                ),
                Err(NetworkError::Malformed)
            ));
        }
    }

    #[test]
    fn done_and_error_controls_fail_closed() {
        for (flags, payload) in [
            (0, Vec::new()),
            (NLM_F_MULTI | 0x10, Vec::new()),
            (NLM_F_MULTI, 1_i32.to_ne_bytes().to_vec()),
            (NLM_F_MULTI, vec![0; 8]),
        ] {
            assert!(parse_done(flags, &payload).is_err());
        }
        let request = encode_dump_request(DumpKind::Link, TEST_SEQUENCE).expect("request");
        let mut payload = (-libc::EINVAL).to_ne_bytes().to_vec();
        payload.extend(&request);
        assert!(matches!(
            parse_dump_error(0, &payload, &request),
            Ok(NetworkError::Kernel(code)) if code == libc::EINVAL
        ));
        payload[4] ^= 1;
        assert!(matches!(
            parse_dump_error(0, &payload, &request),
            Err(NetworkError::Malformed)
        ));
    }

    #[test]
    fn attribute_parser_enforces_lengths_flags_padding_and_count() {
        assert!(matches!(
            parse_attributes(&[3, 0, 1, 0]),
            Err(NetworkError::Malformed)
        ));
        assert!(matches!(
            parse_attributes(&[1]),
            Err(NetworkError::Malformed)
        ));
        let mut nonzero_padding = attribute(1, &[1]);
        *nonzero_padding.last_mut().expect("padding") = 1;
        assert!(matches!(
            parse_attributes(&nonzero_padding),
            Err(NetworkError::Malformed)
        ));
        let conflicting_flags = attribute(NLA_F_NESTED | NLA_F_NET_BYTEORDER | 1, &[]);
        assert!(matches!(
            parse_attributes(&conflicting_flags),
            Err(NetworkError::Malformed)
        ));
        let mut too_many = Vec::new();
        for _ in 0..=MAX_ATTRIBUTES_PER_RECORD {
            too_many.extend(attribute(1, &[]));
        }
        assert!(matches!(
            parse_attributes(&too_many),
            Err(NetworkError::Limit)
        ));
    }

    #[test]
    fn collection_budget_enforces_every_bound() {
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
            Err(NetworkError::Limit)
        ));
        let mut datagrams = CollectionBudget::production();
        datagrams.datagrams = MAX_DATAGRAMS;
        assert!(matches!(
            datagrams.record_datagram(NLMSG_HEADER_LEN),
            Err(NetworkError::Limit)
        ));
        let mut frames = CollectionBudget::production();
        frames.frames = MAX_FRAMES;
        assert!(matches!(frames.record_frame(), Err(NetworkError::Limit)));
        assert!(matches!(
            CollectionBudget::production().can_receive(MAX_DATAGRAM_BYTES + 1),
            Err(NetworkError::Limit)
        ));
    }

    #[test]
    fn canonicalization_rejects_duplicate_records() {
        let mut snapshot = pristine_snapshot();
        snapshot.rules_v4.push(snapshot.rules_v4[0].clone());
        assert!(matches!(
            snapshot.canonicalize(),
            Err(NetworkError::Malformed)
        ));
    }

    #[test]
    fn collector_proves_real_pristine_namespace_in_isolated_subprocess() {
        if env::var_os(LIVE_COLLECTOR_CHILD_ENV).is_some() {
            collect_consistent_pristine_snapshot().expect("pristine network namespace");
            collect_consistent_pristine_snapshot().expect("stable pristine network namespace");
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("network::tests::collector_proves_real_pristine_namespace_in_isolated_subprocess")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_COLLECTOR_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated pristine-network collector test");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live pristine-network proof: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated pristine-network proof failed"
        );
    }

    #[test]
    fn collector_rejects_live_link_and_routing_object_mutations() {
        if let Some(scenario) = env::var_os(LIVE_MUTATION_CHILD_ENV) {
            let selected_dump = match scenario.to_str().expect("ASCII scenario") {
                "mtu" => {
                    run_ip(&["link", "set", "lo", "mtu", "1400"]);
                    None
                }
                "gso-max-size" => {
                    run_ip(&["link", "set", "lo", "gso_max_size", "70000"]);
                    None
                }
                "proxy-neighbour" => {
                    run_ip(&["neigh", "add", "proxy", "192.0.2.1", "dev", "lo"]);
                    Some(DumpKind::ProxyNeighbour)
                }
                "nexthop" => {
                    run_ip(&["link", "set", "lo", "up"]);
                    run_ip(&["nexthop", "add", "id", "10", "blackhole"]);
                    run_ip(&["address", "flush", "dev", "lo"]);
                    run_ip(&["link", "set", "lo", "down"]);
                    Some(DumpKind::Nexthop)
                }
                _ => panic!("unknown live mutation scenario"),
            };
            if let Some(kind) = selected_dump {
                assert!(
                    !collect_live_dump(kind).is_empty(),
                    "selected RTNL dump did not expose its live mutation"
                );
            }
            assert!(matches!(
                collect_consistent_pristine_snapshot(),
                Err(NetworkError::NotPristine)
            ));
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        for scenario in ["mtu", "gso-max-size", "proxy-neighbour", "nexthop"] {
            let output = Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(&executable)
                .arg("--exact")
                .arg("network::tests::collector_rejects_live_link_and_routing_object_mutations")
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env(LIVE_MUTATION_CHILD_ENV, scenario)
                .env("LC_ALL", "C")
                .output()
                .expect("spawn isolated mutated-network collector test");
            if unprivileged_user_namespace_policy_denied(
                output.status.code(),
                &output.stdout,
                &output.stderr,
            ) {
                eprintln!("skipped live network-mutation proofs: user namespaces denied by policy");
                return;
            }
            assert!(
                output.status.success(),
                "live {scenario} mutation was not rejected"
            );
        }
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

    fn run_ip(arguments: &[&str]) {
        let status = Command::new("ip")
            .args(arguments)
            .status()
            .expect("execute iproute diagnostic mutation");
        assert!(status.success(), "iproute diagnostic mutation failed");
    }

    fn collect_live_dump(kind: DumpKind) -> Vec<Vec<u8>> {
        let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT).expect("live dump deadline");
        let mut collector = NetlinkCollector::connect(deadline).expect("live dump collector");
        collector
            .collect_dump(kind, deadline, &mut CollectionBudget::production())
            .expect("live dump")
    }

    fn pristine_snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            links: vec![link_payload()],
            addresses: Vec::new(),
            routes: Vec::new(),
            neighbours: Vec::new(),
            proxy_neighbours: Vec::new(),
            nexthops: Vec::new(),
            rules_v4: expected_ipv4_rules()
                .into_iter()
                .map(|rule| rule_payload(AF_INET, rule.priority, rule.table))
                .collect(),
            rules_v6: expected_ipv6_rules()
                .into_iter()
                .map(|rule| rule_payload(AF_INET6, rule.priority, rule.table))
                .collect(),
        }
    }

    fn link_payload() -> Vec<u8> {
        let mut payload = vec![0; IFINFO_LEN];
        payload[2..4].copy_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
        payload[4..8].copy_from_slice(&1_i32.to_ne_bytes());
        payload[8..12].copy_from_slice(&IFF_LOOPBACK.to_ne_bytes());
        payload.extend(attribute(IFLA_IFNAME, b"lo\0"));
        payload.extend(attribute(IFLA_OPERSTATE, &[IF_OPER_DOWN]));
        payload.extend(attribute(IFLA_ADDRESS, &[0; 6]));
        payload.extend(attribute(IFLA_BROADCAST, &[0; 6]));
        payload.extend(attribute(IFLA_MTU, &LOOPBACK_MTU.to_ne_bytes()));
        payload.extend(attribute(
            IFLA_TXQLEN,
            &LOOPBACK_TX_QUEUE_LENGTH.to_ne_bytes(),
        ));
        payload.extend(attribute(IFLA_QDISC, b"noop\0"));
        payload.extend(attribute(IFLA_LINKMODE, &[0]));
        payload.extend(attribute(IFLA_GROUP, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_PROMISCUITY, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_ALLMULTI, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_PROTO_DOWN, &[0]));
        payload.extend(attribute(
            IFLA_GSO_MAX_SEGS,
            &LOOPBACK_GSO_MAX_SEGMENTS.to_ne_bytes(),
        ));
        for kind in [
            IFLA_GSO_MAX_SIZE,
            IFLA_GRO_MAX_SIZE,
            IFLA_GSO_IPV4_MAX_SIZE,
            IFLA_GRO_IPV4_MAX_SIZE,
        ] {
            payload.extend(attribute(kind, &LOOPBACK_OFFLOAD_MAX_SIZE.to_ne_bytes()));
        }
        let mut address_families = attribute(u16::from(AF_INET), &[]);
        let ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[IN6_ADDR_GEN_MODE_EUI64]);
        address_families.extend(attribute(u16::from(AF_INET6), &ipv6));
        payload.extend(attribute(IFLA_AF_SPEC, &address_families));
        payload
    }

    fn rule_payload(family: u8, priority: u32, table: u32) -> Vec<u8> {
        let mut payload = vec![0; FIB_RULE_HEADER_LEN];
        payload[0] = family;
        payload[4] = u8::try_from(table).expect("fixed table fits");
        payload[7] = FR_ACT_TO_TBL;
        if priority != 0 {
            payload.extend(attribute(FRA_PRIORITY, &priority.to_ne_bytes()));
        }
        payload.extend(attribute(FRA_TABLE, &table.to_ne_bytes()));
        payload.extend(attribute(FRA_SUPPRESS_PREFIXLEN, &u32::MAX.to_ne_bytes()));
        payload.extend(attribute(FRA_PROTOCOL, &[RTPROT_KERNEL]));
        payload
    }

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut bytes = Vec::with_capacity(aligned);
        bytes.extend_from_slice(&u16::try_from(length).expect("fixture fits").to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
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
        let mut frame = Vec::with_capacity(aligned);
        frame.extend_from_slice(&u32::try_from(length).expect("fixture fits").to_ne_bytes());
        frame.extend_from_slice(&message_type.to_ne_bytes());
        frame.extend_from_slice(&flags.to_ne_bytes());
        frame.extend_from_slice(&sequence.to_ne_bytes());
        frame.extend_from_slice(&port.to_ne_bytes());
        frame.extend_from_slice(payload);
        frame.resize(aligned, 0);
        frame
    }

    fn link_state() -> DumpState {
        DumpState::new(
            DumpKind::Link,
            TEST_SEQUENCE,
            TEST_PORT,
            encode_dump_request(DumpKind::Link, TEST_SEQUENCE).expect("request"),
        )
    }

    fn replace_link_attribute(payload: &[u8], kind: u16, replacement: &[u8]) -> Vec<u8> {
        let mut rebuilt = payload[..IFINFO_LEN].to_vec();
        let mut remaining = &payload[IFINFO_LEN..];
        let mut replaced = false;
        while !remaining.is_empty() {
            let length = usize::from(read_u16(remaining, 0).expect("fixture length"));
            let aligned = align4(length).expect("fixture alignment");
            let observed_kind = read_u16(remaining, 2).expect("fixture kind") & NLA_TYPE_MASK;
            if observed_kind == kind {
                assert!(!replaced, "fixture attribute must be unique");
                rebuilt.extend(attribute(kind, replacement));
                replaced = true;
            } else {
                rebuilt.extend_from_slice(&remaining[..aligned]);
            }
            remaining = &remaining[aligned..];
        }
        assert!(replaced, "fixture attribute must exist");
        rebuilt
    }

    fn mutate_link_index(payload: &mut [u8]) {
        payload[4..8].copy_from_slice(&2_i32.to_ne_bytes());
    }

    fn mutate_link_flags(payload: &mut [u8]) {
        payload[8..12].copy_from_slice(&(IFF_LOOPBACK | 1).to_ne_bytes());
    }

    fn mutate_link_type(payload: &mut [u8]) {
        payload[2..4].copy_from_slice(&1_u16.to_ne_bytes());
    }

    fn mutate_link_name(payload: &mut [u8]) {
        let name_offset = IFINFO_LEN + ATTRIBUTE_HEADER_LEN;
        payload[name_offset..name_offset + 3].copy_from_slice(b"xx\0");
    }

    fn mutate_link_operstate(payload: &mut [u8]) {
        let operstate_offset = IFINFO_LEN + attribute(IFLA_IFNAME, b"lo\0").len();
        payload[operstate_offset + ATTRIBUTE_HEADER_LEN] = 6;
    }
}
