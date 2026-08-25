//! Bounded proof of the enumerated read-only pre-`GO` network baseline.
//!
//! The collector opens only `NETLINK_ROUTE`, issues fixed dump requests, and
//! requires two identical canonical snapshots under one absolute deadline. It
//! pins the enumerated loopback configuration, including its mutable offload
//! limits, and the empty address, route, ordinary/proxy-neighbour, and nexthop
//! object sets plus the default rules. The composite proof also pins one fixed
//! namespace-local IPv4-forwarding proc record and a read-only generation-1
//! empty nftables-table observation. After authorization, the RTNL/proc
//! baseline remains independent from the affine nftables policy lineage so a
//! semantically empty generation-3 ruleset can be proven without pretending
//! that the kernel generation returned to one. This module exposes no proc or
//! network-state writer; fixed GETs may trigger ordinary kernel module loading.

use std::{
    io,
    marker::PhantomData,
    mem::size_of,
    os::fd::AsFd,
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use rustix::fs::{FsWord, Mode, OFlags, fstat, fstatfs, open};
use thiserror::Error;
use volparossa_linux_uapi::namespace_type;

use crate::{
    mounts::{Ipv4ForwardingRecordSnapshot, PrivateMountSetupError, PrivateMounts},
    nftables::{
        ActiveNftablesPolicy, NftablesBaseline, NftablesError, SemanticallyEmptyNftables,
        observe_empty_nftables, verify_empty_nftables, verify_exact_forward_policy,
        verify_semantically_empty_after_forward_policy,
    },
    topology::veth::VethTargetNamespaceIdentity,
};

const NETWORK_PROOF_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(1);

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
const MAX_QDISCS: usize = 8;

const NLMSG_HEADER_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const IFADDR_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const NDMSG_LEN: usize = 12;
const NDMSG_FLAGS_OFFSET: usize = 10;
const NHMSG_LEN: usize = 8;
const FIB_RULE_HEADER_LEN: usize = 12;
const TCMSG_LEN: usize = 20;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_DUMP_FILTERED: u16 = 0x0020;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
#[cfg(test)]
const NLM_F_EXCL: u16 = 0x0200;
#[cfg(test)]
const NLM_F_CREATE: u16 = 0x0400;

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
const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
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
const IFLA_STATS: u16 = 7;
const IFLA_MASTER: u16 = 10;
const IFLA_TXQLEN: u16 = 13;
const IFLA_MAP: u16 = 14;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_STATS64: u16 = 23;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_GROUP: u16 = 27;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_XDP: u16 = 43;
const IFLA_EVENT: u16 = 44;
const IFLA_CARRIER_UP_COUNT: u16 = 47;
const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_PERM_ADDRESS: u16 = 54;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_DEVLINK_PORT: u16 = 62;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const IFLA_DPLL_PIN: u16 = 65;
const MAX_DEBIAN13_LINK_ATTRIBUTE: usize = IFLA_DPLL_PIN as usize;
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INET_CONF: u16 = 1;
const IFLA_INET6_FLAGS: u16 = 1;
const IFLA_INET6_CONF: u16 = 2;
const IFLA_INET6_STATS: u16 = 3;
const IFLA_INET6_MCAST: u16 = 4;
const IFLA_INET6_CACHEINFO: u16 = 5;
const IFLA_INET6_ICMP6STATS: u16 = 6;
const IFLA_INET6_TOKEN: u16 = 7;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
const IFLA_INET6_RA_MTU: u16 = 9;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_F_PERMANENT_U8: u8 = 0x80;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_CACHEINFO_LEN: usize = 16;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_PREF: u16 = 20;

const TCA_KIND: u16 = 1;
const TCA_STATS: u16 = 3;
const TCA_STATS2: u16 = 7;
const TCA_HW_OFFLOAD: u16 = 12;
const TCA_STATS_BASIC: u16 = 1;
const TCA_STATS_QUEUE: u16 = 3;

const IFF_UP: u32 = 0x0001;
const IFF_BROADCAST: u32 = 0x0002;
const IFF_LOOPBACK: u32 = 0x0008;
const IFF_RUNNING: u32 = 0x0040;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x1_0000;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const IF_OPER_DOWN: u8 = 2;
const IF_OPER_UP: u8 = 6;
const IN6_ADDR_GEN_MODE_EUI64: u8 = 0;
const IN6_ADDR_GEN_MODE_NONE: u8 = 1;
const VETH_MTU: u32 = 1_500;
const VETH_TX_QUEUE_LENGTH: u32 = 1_000;
const VETH_FLAGS: u32 = IFF_BROADCAST | IFF_MULTICAST;
const VETH_UP_FLAGS: u32 = VETH_FLAGS | IFF_UP | IFF_RUNNING | IFF_LOWER_UP;
const VETH_QUEUE_COUNT: u32 = 1;
const VETH_MIN_MTU: u32 = 68;
const VETH_MAX_MTU: u32 = 65_535;
const VETH_LINK_STATS_BYTES: usize = 24 * size_of::<u32>();
const VETH_LINK_STATS64_BYTES: usize = 25 * size_of::<u64>();
const VETH_LINK_IFMAP_BYTES: usize = 32;
const VETH_STATS_SEEN: u8 = 1 << 0;
const VETH_STATS64_SEEN: u8 = 1 << 1;
const VETH_IFMAP_SEEN: u8 = 1 << 2;
const VETH_ZEROED_STRUCTS_SEEN: u8 = VETH_STATS_SEEN | VETH_STATS64_SEEN | VETH_IFMAP_SEEN;
const VETH_ENDPOINT_NAME: &[u8] = b"eth0";
const ETHERNET_ADDRESS_BYTES: usize = 6;
const MAX_INTERFACE_NAME_BYTES: usize = 15;
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;
const TC_H_ROOT: u32 = u32::MAX;
const NOQUEUE_REFERENCE_COUNT: u32 = 2;
const TC_STATS_BYTES: usize = 40;
const TC_STATS_BASIC_BYTES: usize = 16;
const TC_STATS_QUEUE_BYTES: usize = 20;
const IPV6_ROUTE_CACHEINFO_BYTES: usize = 32;
#[cfg(test)]
const TC_H_CLSACT: u32 = 0xffff_fff1;
const LOOPBACK_MTU: u32 = 65_536;
const LOOPBACK_TX_QUEUE_LENGTH: u32 = 1_000;
const LOOPBACK_GSO_MAX_SEGMENTS: u32 = 65_535;
const LOOPBACK_OFFLOAD_MAX_SIZE: u32 = 65_536;
const DEFAULT_TSO_MAX_SIZE: u32 = 524_280;
const DEFAULT_TSO_MAX_SEGMENTS: u32 = 65_535;
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
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BROADCAST: u8 = 3;
const RTN_MULTICAST: u8 = 5;
const IPV6_DEFAULT_PREFERENCE: u8 = 0;
const FR_ACT_TO_TBL: u8 = 1;
const NTF_PROXY: u8 = 0x08;

const FIXED_IPV4_PREFIX_LENGTH: u8 = 30;
const FIXED_IPV4_ADDRESSES: [[u8; 4]; 4] = [
    [10, 241, 1, 1],
    [10, 241, 1, 2],
    [10, 241, 2, 1],
    [10, 241, 2, 2],
];

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
    /// A caller supplied an impossible or ambiguous fixed-veth expectation.
    #[error("fixed-veth observation expectation was invalid")]
    InvalidVethExpectation,
    /// A caller supplied an impossible or ambiguous fixed-IPv4 expectation.
    #[error("fixed-IPv4 observation expectation was invalid")]
    InvalidIpv4Expectation,
    /// A caller supplied an endpoint route outside the fixed A/B route set.
    #[error("fixed endpoint IPv4 route expectation was invalid")]
    InvalidIpv4RouteExpectation,
    /// The expected destination existed with non-exact route semantics.
    #[error("fixed endpoint IPv4 route destination had a conflicting route")]
    ConflictingIpv4EndpointRoute,
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
struct RtnlProcNetworkBaseline {
    rtnl: NetworkSnapshot,
    ipv4_forwarding: Ipv4ForwardingBaseline,
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
/// thread. Mutation authorization performs a fresh double snapshot before the
/// proof is consumed at the `GO` boundary.
pub(crate) struct PreGoNetworkProof {
    baseline: PreGoNetworkBaseline,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine RTNL/proc baseline retained across one authorized mutation.
///
/// Construction revalidates the pristine observation immediately before the
/// mutation boundary. Nftables generation-one authority is deliberately split
/// into [`AuthorizedNetworkMutationProof`] so later parent observations can
/// remain valid under the exact active generation-two policy.
pub(crate) struct MutationRollbackNetworkProof {
    baseline: RtnlProcNetworkBaseline,
    _thread_bound: PhantomData<Rc<()>>,
}

/// The exact parent authorities released by the pre-`GO` proof at mutation authorization.
///
/// The split is affine: the caller receives one RTNL/proc rollback proof and
/// the sole initial empty nftables authority. Canonical inherited
/// `ip_forward` may be either `0\n` or `1\n`; its record identity and bytes must
/// remain exactly unchanged throughout the lineage.
pub(crate) struct AuthorizedNetworkMutationProof {
    rollback: MutationRollbackNetworkProof,
    nftables: NftablesBaseline,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact post-policy parent proof retaining semantic-empty generation-three lineage.
///
/// This is not a pre-`GO` proof: nftables generation is monotonic and remains
/// three after the exact generation-one to generation-two to generation-three
/// policy transaction. Reverification therefore checks semantics and lineage,
/// not equality with the original generation number.
pub(crate) struct FinalNetworkProof {
    baseline: RtnlProcNetworkBaseline,
    nftables: SemanticallyEmptyNftables,
    _thread_bound: PhantomData<Rc<()>>,
}

/// A consuming lineage transition failed without discarding either affine authority.
#[must_use = "a failed network-lineage transition returns mandatory proof authority"]
pub(crate) struct NetworkLineageFailure<Authority> {
    source: NetworkError,
    authority: Authority,
}

/// Fixed identity supplied by the veth owner for one read-only pair observation.
///
/// The indices are namespace-local: the parent index identifies the underlay
/// end, while the endpoint index identifies `eth0` in A or B. Equal numeric
/// values across those two namespaces are valid. This value owns no link and
/// grants no mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedVethPair {
    parent_name: Vec<u8>,
    parent_ifindex: u32,
    endpoint_ifindex: u32,
    target_namespace: NetworkNamespaceIdentity,
}

/// Fixed address identity supplied by the affine address owner for observation.
///
/// The prefix is always `/30`; the address is restricted to the four values in
/// the pinned lifecycle specification. This value grants no mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedIpv4Address {
    interface_name: Vec<u8>,
    ifindex: u32,
    address: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

/// Exact pristine observation retained for one future endpoint excursion.
///
/// The observation is thread-bound because its meaning is tied to the network
/// namespace visited by the current task. It owns no namespace or link.
pub(crate) struct PristineNetworkNamespaceObservation {
    baseline: PreGoNetworkBaseline,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

#[derive(Debug, Eq, PartialEq)]
struct VethLinkObservation {
    identity: ExpectedVethPair,
    mac: [u8; ETHERNET_ADDRESS_BYTES],
    peer_netnsid: i32,
}

/// Read-only exact-delta observation of both parent-side veth links.
pub(crate) struct ExactVethParentObservation {
    active: RtnlProcNetworkBaseline,
    links: [VethLinkObservation; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Read-only exact-delta observation of one endpoint-side `eth0` veth link.
pub(crate) struct ExactVethEndpointObservation {
    active: PreGoNetworkBaseline,
    link: VethLinkObservation,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Read-only exact-delta observation of the two addressed parent-side veths.
pub(crate) struct ExactIpv4AddressParentObservation {
    active: RtnlProcNetworkBaseline,
    links: [VethLinkObservation; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Read-only exact-delta observation of one addressed endpoint-side veth.
pub(crate) struct ExactIpv4AddressEndpointObservation {
    active: PreGoNetworkBaseline,
    link: VethLinkObservation,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact addressed-down parent observation after the IPv6-addrgen barrier.
pub(crate) struct ExactIpv4AddrgenNoneParentObservation {
    active: RtnlProcNetworkBaseline,
    links: [VethLinkObservation; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact addressed-down endpoint observation after the IPv6-addrgen barrier.
pub(crate) struct ExactIpv4AddrgenNoneEndpointObservation {
    active: PreGoNetworkBaseline,
    link: VethLinkObservation,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact fully activated parent observation for both fixed IPv4 veth ends.
pub(crate) struct ExactActivatedIpv4ParentObservation {
    active: RtnlProcNetworkBaseline,
    links: [VethLinkObservation; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact fully activated endpoint observation for one fixed IPv4 veth end.
pub(crate) struct ExactActivatedIpv4EndpointObservation {
    active: PreGoNetworkBaseline,
    link: VethLinkObservation,
    address: ExpectedIpv4Address,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Fixed endpoint route identity derived from an exact activated observation.
///
/// The namespace identity is part of the expectation, so equal numeric `eth0`
/// indices in A and B are not interchangeable. This value owns no route and
/// grants no mutation authority. Its route is an IPv4 main-table `/32`,
/// `RTPROT_STATIC`, universe-scope unicast with exactly `RTA_TABLE`, `RTA_DST`,
/// `RTA_GATEWAY`, and `RTA_OIF`; metrics, sources, multipath, and unknown
/// attributes are rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedIpv4EndpointRoute {
    namespace: NetworkNamespaceIdentity,
    ifindex: u32,
    local_address: [u8; 4],
    destination: [u8; 4],
    gateway: [u8; 4],
}

/// Exact proof that the parent retained its complete activated snapshot while
/// endpoint routes were configured elsewhere.
///
/// This is configuration evidence only. It does not observe packets, prove
/// forwarding, establish a datapath, or establish readiness.
pub(crate) struct ExactIpv4EndpointRouteParentObservation {
    active: RtnlProcNetworkBaseline,
    links: [VethLinkObservation; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact proof of one activated endpoint plus its one fixed explicit route.
///
/// This is configuration evidence only. It does not observe packets, prove
/// forwarding, establish a datapath, or establish readiness.
pub(crate) struct ExactIpv4EndpointRouteEndpointObservation {
    active: PreGoNetworkBaseline,
    link: VethLinkObservation,
    address: ExpectedIpv4Address,
    route: ExpectedIpv4EndpointRoute,
    namespace: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ExpectedVethPair {
    /// Construct one exact observation expectation from owner-retained identity.
    pub(crate) fn new(
        parent_name: &str,
        parent_ifindex: u32,
        endpoint_ifindex: u32,
        target_namespace: VethTargetNamespaceIdentity,
    ) -> Result<Self, NetworkError> {
        let target_namespace = NetworkNamespaceIdentity {
            device: target_namespace.device(),
            inode: target_namespace.inode(),
        };
        Self::new_with_namespace_identity(
            parent_name,
            parent_ifindex,
            endpoint_ifindex,
            target_namespace,
        )
    }

    fn new_with_namespace_identity(
        parent_name: &str,
        parent_ifindex: u32,
        endpoint_ifindex: u32,
        target_namespace: NetworkNamespaceIdentity,
    ) -> Result<Self, NetworkError> {
        let parent_name = parent_name.as_bytes();
        if parent_name.is_empty()
            || parent_name.len() > MAX_INTERFACE_NAME_BYTES
            || !parent_name.is_ascii()
            || parent_name.contains(&0)
            || matches!(parent_name, b"lo" | VETH_ENDPOINT_NAME)
            || !(2..=i32::MAX as u32).contains(&parent_ifindex)
            || !(2..=i32::MAX as u32).contains(&endpoint_ifindex)
            || target_namespace.device == 0
            || target_namespace.inode == 0
        {
            return Err(NetworkError::InvalidVethExpectation);
        }
        Ok(Self {
            parent_name: parent_name.to_vec(),
            parent_ifindex,
            endpoint_ifindex,
            target_namespace,
        })
    }
}

impl ExpectedIpv4Address {
    /// Construct one exact `/30` observation expectation.
    pub(crate) fn new(
        interface_name: &str,
        ifindex: u32,
        address: [u8; 4],
    ) -> Result<Self, NetworkError> {
        let interface_name = interface_name.as_bytes();
        let is_endpoint = address[3] == 2;
        if interface_name.is_empty()
            || interface_name.len() > MAX_INTERFACE_NAME_BYTES
            || !interface_name.is_ascii()
            || interface_name.contains(&0)
            || interface_name == b"lo"
            || !(2..=i32::MAX as u32).contains(&ifindex)
            || !FIXED_IPV4_ADDRESSES.contains(&address)
            || (is_endpoint && interface_name != VETH_ENDPOINT_NAME)
            || (!is_endpoint && interface_name == VETH_ENDPOINT_NAME)
        {
            return Err(NetworkError::InvalidIpv4Expectation);
        }
        Ok(Self {
            interface_name: interface_name.to_vec(),
            ifindex,
            address,
        })
    }
}

#[cfg(test)]
impl ExpectedIpv4EndpointRoute {
    /// Namespace-local output interface retained from the activated endpoint.
    pub(crate) const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The fixed remote endpoint `/32` destination.
    pub(crate) const fn destination(&self) -> [u8; 4] {
        self.destination
    }

    /// The fixed same-subnet parent-side gateway.
    pub(crate) const fn gateway(&self) -> [u8; 4] {
        self.gateway
    }
}

impl PreGoNetworkProof {
    /// Revalidate immediately before one authorized mutation and retain the
    /// exact baseline for a later rollback proof.
    pub(crate) fn authorize_mutation(
        self,
        mounts: &PrivateMounts,
    ) -> Result<AuthorizedNetworkMutationProof, NetworkError> {
        require_current_baseline(mounts, &self.baseline)?;
        let PreGoNetworkBaseline {
            rtnl,
            ipv4_forwarding,
            nftables,
        } = self.baseline;
        Ok(AuthorizedNetworkMutationProof {
            rollback: MutationRollbackNetworkProof {
                baseline: RtnlProcNetworkBaseline {
                    rtnl,
                    ipv4_forwarding,
                },
                _thread_bound: PhantomData,
            },
            nftables,
            _thread_bound: PhantomData,
        })
    }
}

impl AuthorizedNetworkMutationProof {
    /// Split the sole initial nftables authority from the retained RTNL/proc rollback proof.
    pub(crate) fn into_parts(self) -> (MutationRollbackNetworkProof, NftablesBaseline) {
        (self.rollback, self.nftables)
    }
}

impl<Authority> NetworkLineageFailure<Authority> {
    /// Recover the fixed failure and every affine input authority for fail-closed handling.
    pub(crate) fn into_parts(self) -> (NetworkError, Authority) {
        (self.source, self.authority)
    }
}

impl MutationRollbackNetworkProof {
    /// Observe the exact parent delta for two owner-retained, down veth pairs.
    ///
    /// Every non-link RTNL record and the IPv4-forwarding record must still
    /// equal the retained pristine baseline. Nftables lineage is verified by
    /// its separate affine authority. The only admitted link delta is the two
    /// expected parent-side veth observations.
    pub(crate) fn observe_exact_veth_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected: [&ExpectedVethPair; 2],
    ) -> Result<ExactVethParentObservation, NetworkError> {
        validate_parent_expectations(expected)?;
        let active = collect_stable_rtnl_proc_baseline(mounts)?;
        let links = verify_exact_parent_veth_delta(&self.baseline, &active, expected)?;
        Ok(ExactVethParentObservation {
            active,
            links,
            _thread_bound: PhantomData,
        })
    }

    /// Observe the exact parent delta for two addressed, still-down veth pairs.
    ///
    /// The only additional RTNL objects admitted beyond the veth skeleton are
    /// the two fixed IPv4 address records and their two kernel-owned local
    /// `/32` routes. No connected route exists while the links remain down.
    pub(crate) fn observe_exact_ipv4_address_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pairs: [&ExpectedVethPair; 2],
        expected_addresses: [&ExpectedIpv4Address; 2],
    ) -> Result<ExactIpv4AddressParentObservation, NetworkError> {
        validate_parent_expectations(expected_pairs)?;
        validate_parent_ipv4_expectations(expected_pairs, expected_addresses)?;
        let active = collect_stable_rtnl_proc_baseline(mounts)?;
        let links = verify_exact_parent_ipv4_address_delta(
            &self.baseline,
            &active,
            expected_pairs,
            expected_addresses,
        )?;
        Ok(ExactIpv4AddressParentObservation {
            active,
            links,
            _thread_bound: PhantomData,
        })
    }

    /// Observe both addressed, still-down parent veths after the mandatory
    /// IPv6 address-generation barrier.
    ///
    /// This admits exactly the existing addressed-down object set while
    /// requiring `addrgenmode none` on both expected links. It admits no qdisc,
    /// connected, broadcast, IPv6-address, or IPv6-route object.
    pub(crate) fn observe_exact_ipv4_addrgen_none_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pairs: [&ExpectedVethPair; 2],
        expected_addresses: [&ExpectedIpv4Address; 2],
    ) -> Result<ExactIpv4AddrgenNoneParentObservation, NetworkError> {
        validate_parent_expectations(expected_pairs)?;
        validate_parent_ipv4_expectations(expected_pairs, expected_addresses)?;
        let (active, links) = collect_exact_stable_parent_delta(mounts, |active| {
            verify_exact_parent_ipv4_addrgen_none_delta(
                &self.baseline,
                active,
                expected_pairs,
                expected_addresses,
            )
        })?;
        Ok(ExactIpv4AddrgenNoneParentObservation {
            active,
            links,
            _thread_bound: PhantomData,
        })
    }

    /// Observe both fixed parent veths after complete link activation.
    ///
    /// Every expected link must be carrier-up with `addrgenmode none` and
    /// `noqueue`. The only admitted new objects are the fixed IPv4 addresses,
    /// their exact kernel local/connected/high-broadcast routes, one root
    /// `noqueue` qdisc, and one local-table IPv6 multicast route per link.
    pub(crate) fn observe_exact_activated_ipv4_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pairs: [&ExpectedVethPair; 2],
        expected_addresses: [&ExpectedIpv4Address; 2],
    ) -> Result<ExactActivatedIpv4ParentObservation, NetworkError> {
        validate_parent_expectations(expected_pairs)?;
        validate_parent_ipv4_expectations(expected_pairs, expected_addresses)?;
        let (active, links) = collect_exact_stable_parent_delta(mounts, |active| {
            verify_exact_parent_activated_ipv4_delta(
                &self.baseline,
                active,
                expected_pairs,
                expected_addresses,
            )
        })?;
        Ok(ExactActivatedIpv4ParentObservation {
            active,
            links,
            _thread_bound: PhantomData,
        })
    }

    /// Re-prove pristine parent RTNL/proc state and the untouched empty generation-one lineage.
    pub(crate) fn verify_pristine_with_initial_nftables<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        nftables: &NftablesBaseline,
    ) -> Result<(), NetworkError> {
        require_current_pristine_rtnl_proc_with_nftables(mounts, &self.baseline, |deadline| {
            verify_empty_nftables(nftables, deadline).map_err(NetworkError::Nftables)
        })
    }

    /// Re-prove pristine parent RTNL/proc state while the exact drop policy remains active.
    ///
    /// Callers use this after deletion-only B/A veth retirement and before
    /// `DELTABLE`; endpoint absence is proved separately through the retained
    /// endpoint observations.
    pub(crate) fn verify_pristine_with_active_policy<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        policy: &ActiveNftablesPolicy,
    ) -> Result<(), NetworkError> {
        require_current_pristine_rtnl_proc_with_nftables(mounts, &self.baseline, |deadline| {
            verify_exact_forward_policy(policy, deadline).map_err(NetworkError::Nftables)
        })
    }

    /// Consume rollback and semantic-empty authorities into the reusable final parent proof.
    pub(crate) fn finish_after_semantically_empty<RunState>(
        self,
        mounts: &PrivateMounts<RunState>,
        nftables: SemanticallyEmptyNftables,
    ) -> Result<FinalNetworkProof, NetworkLineageFailure<Box<(Self, SemanticallyEmptyNftables)>>>
    {
        match require_current_pristine_rtnl_proc_with_nftables(mounts, &self.baseline, |deadline| {
            verify_semantically_empty_after_forward_policy(&nftables, deadline)
                .map_err(NetworkError::Nftables)
        }) {
            Ok(()) => Ok(FinalNetworkProof {
                baseline: self.baseline,
                nftables,
                _thread_bound: PhantomData,
            }),
            Err(source) => Err(NetworkLineageFailure {
                source,
                authority: Box::new((self, nftables)),
            }),
        }
    }
}

impl FinalNetworkProof {
    /// Re-prove pristine RTNL/proc state plus the same semantic-empty generation-three lineage.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_pristine_rtnl_proc_with_nftables(mounts, &self.baseline, |deadline| {
            verify_semantically_empty_after_forward_policy(&self.nftables, deadline)
                .map_err(NetworkError::Nftables)
        })
    }
}

impl PristineNetworkNamespaceObservation {
    /// Borrowingly re-prove the exact endpoint baseline while retaining it for final retirement.
    ///
    /// Endpoint nftables is never part of the parent policy transaction and
    /// therefore remains the original empty generation-one lineage.
    pub(crate) fn verify_pristine_state<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_baseline(mounts, &self.baseline)?;
        require_current_network_namespace(self.namespace)
    }

    /// Observe one exact endpoint delta consisting only of down veth `eth0`.
    pub(crate) fn observe_exact_veth_endpoint<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected: &ExpectedVethPair,
    ) -> Result<ExactVethEndpointObservation, NetworkError> {
        require_current_network_namespace(self.namespace)?;
        if self.namespace != expected.target_namespace {
            return Err(NetworkError::Inconsistent);
        }
        let active = collect_stable_network_baseline(mounts)?;
        require_current_network_namespace(self.namespace)?;
        let link = verify_exact_endpoint_veth_delta(&self.baseline, &active, expected)?;
        Ok(ExactVethEndpointObservation {
            active,
            link,
            namespace: self.namespace,
            _thread_bound: PhantomData,
        })
    }

    /// Observe one exact endpoint delta consisting of addressed, down `eth0`.
    pub(crate) fn observe_exact_ipv4_address_endpoint<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pair: &ExpectedVethPair,
        expected_address: &ExpectedIpv4Address,
    ) -> Result<ExactIpv4AddressEndpointObservation, NetworkError> {
        require_current_network_namespace(self.namespace)?;
        if self.namespace != expected_pair.target_namespace {
            return Err(NetworkError::Inconsistent);
        }
        validate_endpoint_ipv4_expectation(expected_pair, expected_address)?;
        let active = collect_stable_network_baseline(mounts)?;
        require_current_network_namespace(self.namespace)?;
        let link = verify_exact_endpoint_ipv4_address_delta(
            &self.baseline,
            &active,
            expected_pair,
            expected_address,
        )?;
        Ok(ExactIpv4AddressEndpointObservation {
            active,
            link,
            namespace: self.namespace,
            _thread_bound: PhantomData,
        })
    }

    /// Observe one addressed, still-down endpoint after its mandatory IPv6
    /// address-generation barrier.
    pub(crate) fn observe_exact_ipv4_addrgen_none_endpoint<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pair: &ExpectedVethPair,
        expected_address: &ExpectedIpv4Address,
    ) -> Result<ExactIpv4AddrgenNoneEndpointObservation, NetworkError> {
        require_current_network_namespace(self.namespace)?;
        if self.namespace != expected_pair.target_namespace {
            return Err(NetworkError::Inconsistent);
        }
        validate_endpoint_ipv4_expectation(expected_pair, expected_address)?;
        let (active, link) = collect_exact_stable_network_delta(mounts, |active| {
            require_current_network_namespace(self.namespace)?;
            verify_exact_endpoint_ipv4_addrgen_none_delta(
                &self.baseline,
                active,
                expected_pair,
                expected_address,
            )
        })?;
        Ok(ExactIpv4AddrgenNoneEndpointObservation {
            active,
            link,
            namespace: self.namespace,
            _thread_bound: PhantomData,
        })
    }

    /// Observe one fixed endpoint after complete carrier-up activation.
    pub(crate) fn observe_exact_activated_ipv4_endpoint<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        expected_pair: &ExpectedVethPair,
        expected_address: &ExpectedIpv4Address,
    ) -> Result<ExactActivatedIpv4EndpointObservation, NetworkError> {
        require_current_network_namespace(self.namespace)?;
        if self.namespace != expected_pair.target_namespace {
            return Err(NetworkError::Inconsistent);
        }
        validate_endpoint_ipv4_expectation(expected_pair, expected_address)?;
        let (active, link) = collect_exact_stable_network_delta(mounts, |active| {
            require_current_network_namespace(self.namespace)?;
            verify_exact_endpoint_activated_ipv4_delta(
                &self.baseline,
                active,
                expected_pair,
                expected_address,
            )
        })?;
        Ok(ExactActivatedIpv4EndpointObservation {
            active,
            link,
            address: expected_address.clone(),
            namespace: self.namespace,
            _thread_bound: PhantomData,
        })
    }

    /// Consume the retained observation and prove exact pristine restoration.
    pub(crate) fn verify_pristine_rollback<RunState>(
        self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        self.verify_pristine_state(mounts)
    }
}

impl ExactVethParentObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)
    }
}

impl ExactVethEndpointObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_stable_baseline(mounts, &self.active)?;
        require_current_network_namespace(self.namespace)
    }
}

impl ExactIpv4AddressParentObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)
    }
}

impl ExactIpv4AddressEndpointObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_stable_baseline(mounts, &self.active)?;
        require_current_network_namespace(self.namespace)
    }
}

impl ExactIpv4AddrgenNoneParentObservation {
    /// Reobserve and require byte-exact equality with the retained barrier state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)
    }
}

impl ExactIpv4AddrgenNoneEndpointObservation {
    /// Reobserve and require byte-exact equality with the retained barrier state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_stable_baseline(mounts, &self.active)?;
        require_current_network_namespace(self.namespace)
    }
}

impl ExactActivatedIpv4ParentObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)
    }

    /// Consume the activated observation after re-proving that the parent has
    /// no route-state delta at the endpoint-route barrier.
    pub(crate) fn observe_exact_ipv4_endpoint_route_parent<RunState>(
        self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<ExactIpv4EndpointRouteParentObservation, NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)?;
        Ok(ExactIpv4EndpointRouteParentObservation {
            active: self.active,
            links: self.links,
            _thread_bound: PhantomData,
        })
    }
}

impl ExactActivatedIpv4EndpointObservation {
    /// Reobserve and require byte-exact equality with the retained active state.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_stable_baseline(mounts, &self.active)?;
        require_current_network_namespace(self.namespace)
    }

    /// Derive the only fixed explicit route admitted for this exact endpoint.
    pub(crate) fn expected_ipv4_endpoint_route(
        &self,
    ) -> Result<ExpectedIpv4EndpointRoute, NetworkError> {
        expected_ipv4_endpoint_route(&self.link.identity, &self.address, self.namespace)
    }

    /// Consume the activated observation after proving its one exact explicit
    /// peer-endpoint route and no other state delta.
    pub(crate) fn observe_exact_ipv4_endpoint_route_endpoint<RunState>(
        self,
        mounts: &PrivateMounts<RunState>,
        expected: &ExpectedIpv4EndpointRoute,
    ) -> Result<ExactIpv4EndpointRouteEndpointObservation, NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_ipv4_endpoint_route_expectation(
            expected,
            &self.link.identity,
            &self.address,
            self.namespace,
        )?;
        let (active, ()) = collect_exact_stable_network_delta(mounts, |active| {
            require_current_network_namespace(self.namespace)?;
            verify_exact_endpoint_ipv4_route_delta(&self.active, active, expected)
        })?;
        require_current_network_namespace(self.namespace)?;
        Ok(ExactIpv4EndpointRouteEndpointObservation {
            active,
            link: self.link,
            address: self.address,
            route: expected.clone(),
            namespace: self.namespace,
            _thread_bound: PhantomData,
        })
    }
}

impl ExactIpv4EndpointRouteParentObservation {
    /// Reobserve and require exact equality with the retained activated parent.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_stable_rtnl_proc_baseline(mounts, &self.active)
    }
}

impl ExactIpv4EndpointRouteEndpointObservation {
    /// Reobserve and require exact equality with the retained routed endpoint.
    pub(crate) fn verify<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
    ) -> Result<(), NetworkError> {
        require_current_network_namespace(self.namespace)?;
        require_current_stable_baseline(mounts, &self.active)?;
        require_current_network_namespace(self.namespace)
    }
}

/// Cross-check owner-retained atomic-target facts against independent observations.
///
/// The caller supplies A then B in the same order used for the parent
/// expectations. Numeric ifindex collisions across namespaces remain valid.
/// This proves consistency with the owner's retained name/index result and two
/// distinct observed endpoint nsfs objects; per-namespace link-netns IDs are
/// observations and are not durable namespace identities.
pub(crate) fn verify_exact_veth_pair_observations(
    parent: &ExactVethParentObservation,
    endpoints: [&ExactVethEndpointObservation; 2],
) -> Result<(), NetworkError> {
    verify_veth_observation_relations(
        &parent.links,
        [&endpoints[0].link, &endpoints[1].link],
        [endpoints[0].namespace, endpoints[1].namespace],
    )
}

/// Cross-check the addressed observations against the same retained pair facts.
pub(crate) fn verify_exact_ipv4_address_observations(
    parent: &ExactIpv4AddressParentObservation,
    endpoints: [&ExactIpv4AddressEndpointObservation; 2],
) -> Result<(), NetworkError> {
    verify_veth_observation_relations(
        &parent.links,
        [&endpoints[0].link, &endpoints[1].link],
        [endpoints[0].namespace, endpoints[1].namespace],
    )
}

/// Cross-check all four addressed-down observations at the addrgen barrier.
pub(crate) fn verify_exact_ipv4_addrgen_none_observations(
    parent: &ExactIpv4AddrgenNoneParentObservation,
    endpoints: [&ExactIpv4AddrgenNoneEndpointObservation; 2],
) -> Result<(), NetworkError> {
    verify_veth_observation_relations(
        &parent.links,
        [&endpoints[0].link, &endpoints[1].link],
        [endpoints[0].namespace, endpoints[1].namespace],
    )
}

/// Cross-check all four observations after complete link activation.
pub(crate) fn verify_exact_activated_ipv4_observations(
    parent: &ExactActivatedIpv4ParentObservation,
    endpoints: [&ExactActivatedIpv4EndpointObservation; 2],
) -> Result<(), NetworkError> {
    verify_veth_observation_relations(
        &parent.links,
        [&endpoints[0].link, &endpoints[1].link],
        [endpoints[0].namespace, endpoints[1].namespace],
    )
}

/// Cross-check the unchanged parent and both routed endpoints against retained
/// A/B namespace lineage.
///
/// This proves only the enumerated link/address/route configuration. It makes
/// no forwarding, packet, datapath, or readiness claim.
pub(crate) fn verify_exact_ipv4_endpoint_route_observations(
    parent: &ExactIpv4EndpointRouteParentObservation,
    endpoints: [&ExactIpv4EndpointRouteEndpointObservation; 2],
) -> Result<(), NetworkError> {
    verify_veth_observation_relations(
        &parent.links,
        [&endpoints[0].link, &endpoints[1].link],
        [endpoints[0].namespace, endpoints[1].namespace],
    )?;
    for endpoint in endpoints {
        require_ipv4_endpoint_route_expectation(
            &endpoint.route,
            &endpoint.link.identity,
            &endpoint.address,
            endpoint.namespace,
        )?;
    }
    Ok(())
}

fn verify_veth_observation_relations(
    parent: &[VethLinkObservation; 2],
    endpoints: [&VethLinkObservation; 2],
    endpoint_namespaces: [NetworkNamespaceIdentity; 2],
) -> Result<(), NetworkError> {
    if endpoint_namespaces[0] == endpoint_namespaces[1]
        || parent[0].peer_netnsid == parent[1].peer_netnsid
    {
        return Err(NetworkError::NotPristine);
    }
    for (parent_link, endpoint) in parent.iter().zip(endpoints) {
        if parent_link.identity != endpoint.identity {
            return Err(NetworkError::Inconsistent);
        }
    }
    let macs = [
        parent[0].mac,
        endpoints[0].mac,
        parent[1].mac,
        endpoints[1].mac,
    ];
    if macs
        .iter()
        .enumerate()
        .any(|(index, mac)| macs[index + 1..].contains(mac))
    {
        Err(NetworkError::NotPristine)
    } else {
        Ok(())
    }
}

fn require_current_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
    expected: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    if collect_pre_go_network_baseline(mounts)? == *expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn require_current_stable_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
    expected: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    if collect_stable_network_baseline(mounts)? == *expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn require_current_stable_rtnl_proc_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
    expected: &RtnlProcNetworkBaseline,
) -> Result<(), NetworkError> {
    if collect_stable_rtnl_proc_baseline(mounts)? == *expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn require_current_pristine_rtnl_proc_with_nftables<RunState, VerifyNftables>(
    mounts: &PrivateMounts<RunState>,
    expected: &RtnlProcNetworkBaseline,
    verify_nftables: VerifyNftables,
) -> Result<(), NetworkError>
where
    VerifyNftables: FnOnce(Instant) -> Result<(), NetworkError>,
{
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    let active = collect_rtnl_proc_before_with(
        mounts,
        deadline,
        collect_consistent_snapshot_before,
        verify_nftables,
    )?;
    verify_pristine_snapshot(&active.rtnl)?;
    if active == *expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn current_network_namespace_identity() -> Result<NetworkNamespaceIdentity, NetworkError> {
    let descriptor = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(rustix_network_io)?;
    if fstatfs(&descriptor).map_err(rustix_network_io)?.f_type != NSFS_MAGIC
        || namespace_type(&descriptor)? != libc::CLONE_NEWNET
    {
        return Err(NetworkError::NotPristine);
    }
    let metadata = fstat(&descriptor).map_err(rustix_network_io)?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(NetworkError::NotPristine);
    }
    Ok(NetworkNamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn require_current_network_namespace(
    expected: NetworkNamespaceIdentity,
) -> Result<(), NetworkError> {
    if current_network_namespace_identity()? == expected {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn rustix_network_io(source: rustix::io::Errno) -> NetworkError {
    NetworkError::Io(io::Error::from_raw_os_error(source.raw_os_error()))
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

/// Retain the exact composite pristine observation for a later veth delta and
/// exact rollback proof in the same visited namespace.
pub(crate) fn observe_current_pristine_network_namespace<RunState>(
    mounts: &PrivateMounts<RunState>,
) -> Result<PristineNetworkNamespaceObservation, NetworkError> {
    let namespace = current_network_namespace_identity()?;
    let baseline = collect_pre_go_network_baseline(mounts)?;
    require_current_network_namespace(namespace)?;
    Ok(PristineNetworkNamespaceObservation {
        baseline,
        namespace,
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
    Qdisc,
    Address,
    Route,
    Neighbour,
    ProxyNeighbour,
    Nexthop,
    RuleV4,
    RuleV6,
}

impl DumpKind {
    const ALL: [Self; 9] = [
        Self::Link,
        Self::Qdisc,
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
            Self::Qdisc => RTM_GETQDISC,
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
            Self::Qdisc => RTM_NEWQDISC,
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
            Self::Qdisc => vec![0; TCMSG_LEN],
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
            Self::Qdisc => TCMSG_LEN,
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
    qdiscs: Vec<Vec<u8>>,
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
            DumpKind::Qdisc => &mut self.qdiscs,
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
            &mut self.qdiscs,
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
            message_type
                if message_type == self.kind.response_type()
                    && (flags == NLM_F_MULTI || flags == (NLM_F_MULTI | NLM_F_DUMP_FILTERED)) =>
            {
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

#[cfg(test)]
fn collect_consistent_pristine_snapshot_before(
    deadline: Deadline,
) -> Result<NetworkSnapshot, NetworkError> {
    let snapshot = collect_consistent_snapshot_before(deadline)?;
    verify_pristine_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn collect_consistent_snapshot_before(deadline: Deadline) -> Result<NetworkSnapshot, NetworkError> {
    let mut collector = NetlinkCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let first = collector.collect_snapshot(deadline, &mut budget)?;
    let second = collector.collect_snapshot(deadline, &mut budget)?;
    deadline.ensure_unexpired()?;
    if first != second {
        return Err(NetworkError::Inconsistent);
    }
    deadline.ensure_unexpired()?;
    Ok(first)
}

fn collect_converged_snapshot_before(deadline: Deadline) -> Result<NetworkSnapshot, NetworkError> {
    let mut collector = NetlinkCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let mut previous = collector.collect_snapshot(deadline, &mut budget)?;
    loop {
        let current = collector.collect_snapshot(deadline, &mut budget)?;
        deadline.ensure_unexpired()?;
        if previous == current {
            return Ok(current);
        }
        previous = current;
    }
}

fn collect_pre_go_network_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
) -> Result<PreGoNetworkBaseline, NetworkError> {
    let baseline = collect_stable_network_baseline(mounts)?;
    verify_pristine_snapshot(&baseline.rtnl)?;
    Ok(baseline)
}

fn collect_stable_rtnl_proc_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
) -> Result<RtnlProcNetworkBaseline, NetworkError> {
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    collect_stable_rtnl_proc_baseline_before(mounts, deadline)
}

fn collect_stable_rtnl_proc_baseline_before<RunState>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
) -> Result<RtnlProcNetworkBaseline, NetworkError> {
    collect_rtnl_proc_before_with(mounts, deadline, collect_consistent_snapshot_before, |_| {
        Ok(())
    })
}

fn collect_converged_rtnl_proc_baseline_before<RunState>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
) -> Result<RtnlProcNetworkBaseline, NetworkError> {
    collect_rtnl_proc_before_with(mounts, deadline, collect_converged_snapshot_before, |_| {
        Ok(())
    })
}

fn collect_rtnl_proc_before_with<RunState, Collect, VerifyNftables>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
    collect_rtnl: Collect,
    verify_nftables: VerifyNftables,
) -> Result<RtnlProcNetworkBaseline, NetworkError>
where
    Collect: FnOnce(Deadline) -> Result<NetworkSnapshot, NetworkError>,
    VerifyNftables: FnOnce(Instant) -> Result<(), NetworkError>,
{
    let forwarding_before = mounts
        .read_ipv4_forwarding_record()
        .map_err(NetworkError::PrivateProc)?;
    let rtnl = collect_rtnl(deadline)?;
    verify_nftables(deadline.instant())?;
    let forwarding_after = mounts
        .read_ipv4_forwarding_record()
        .map_err(NetworkError::PrivateProc)?;
    deadline.ensure_unexpired()?;
    if forwarding_before != forwarding_after {
        return Err(NetworkError::Inconsistent);
    }
    let state =
        classify_ipv4_forwarding_records(forwarding_before.bytes(), forwarding_after.bytes())?;
    Ok(RtnlProcNetworkBaseline {
        rtnl,
        ipv4_forwarding: Ipv4ForwardingBaseline {
            record: forwarding_before,
            state,
        },
    })
}

fn collect_stable_network_baseline<RunState>(
    mounts: &PrivateMounts<RunState>,
) -> Result<PreGoNetworkBaseline, NetworkError> {
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    collect_stable_network_baseline_before(mounts, deadline)
}

fn collect_stable_network_baseline_before<RunState>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
) -> Result<PreGoNetworkBaseline, NetworkError> {
    collect_network_baseline_before_with(mounts, deadline, collect_consistent_snapshot_before)
}

fn collect_converged_network_baseline_before<RunState>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
) -> Result<PreGoNetworkBaseline, NetworkError> {
    collect_network_baseline_before_with(mounts, deadline, collect_converged_snapshot_before)
}

fn collect_network_baseline_before_with<RunState, Collect>(
    mounts: &PrivateMounts<RunState>,
    deadline: Deadline,
    collect_rtnl: Collect,
) -> Result<PreGoNetworkBaseline, NetworkError>
where
    Collect: FnOnce(Deadline) -> Result<NetworkSnapshot, NetworkError>,
{
    let forwarding_before = mounts
        .read_ipv4_forwarding_record()
        .map_err(NetworkError::PrivateProc)?;
    let rtnl = collect_rtnl(deadline)?;
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

/// Reobserve a newly staged kernel state until its complete exact object set
/// has converged, under one absolute deadline. A stable but incomplete
/// intermediate snapshot is never accepted, and ambiguity outside the exact
/// expected delta is never retried.
fn collect_exact_stable_network_delta<RunState, Output, Verify>(
    mounts: &PrivateMounts<RunState>,
    verify: Verify,
) -> Result<(PreGoNetworkBaseline, Output), NetworkError>
where
    Verify: FnMut(&PreGoNetworkBaseline) -> Result<Output, NetworkError>,
{
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    retry_exact_observation_before(
        deadline,
        || collect_converged_network_baseline_before(mounts, deadline),
        verify,
    )
}

fn collect_exact_stable_parent_delta<RunState, Output, Verify>(
    mounts: &PrivateMounts<RunState>,
    verify: Verify,
) -> Result<(RtnlProcNetworkBaseline, Output), NetworkError>
where
    Verify: FnMut(&RtnlProcNetworkBaseline) -> Result<Output, NetworkError>,
{
    let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT)?;
    retry_exact_observation_before(
        deadline,
        || collect_converged_rtnl_proc_baseline_before(mounts, deadline),
        verify,
    )
}

fn retry_exact_observation_before<State, Output, Collect, Verify>(
    deadline: Deadline,
    mut collect: Collect,
    mut verify: Verify,
) -> Result<(State, Output), NetworkError>
where
    Collect: FnMut() -> Result<State, NetworkError>,
    Verify: FnMut(&State) -> Result<Output, NetworkError>,
{
    loop {
        let state = collect()?;
        match verify(&state) {
            Ok(output) => return Ok((state, output)),
            Err(NetworkError::NotPristine) => {
                deadline.ensure_unexpired()?;
                std::thread::sleep(NETWORK_CONVERGENCE_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
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

#[cfg(test)]
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
        || !snapshot.qdiscs.is_empty()
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

fn validate_parent_expectations(expected: [&ExpectedVethPair; 2]) -> Result<(), NetworkError> {
    if expected[0].parent_name == expected[1].parent_name
        || expected[0].parent_ifindex == expected[1].parent_ifindex
        || expected[0].target_namespace == expected[1].target_namespace
    {
        Err(NetworkError::InvalidVethExpectation)
    } else {
        Ok(())
    }
}

fn validate_parent_ipv4_expectations(
    pairs: [&ExpectedVethPair; 2],
    addresses: [&ExpectedIpv4Address; 2],
) -> Result<(), NetworkError> {
    for index in 0..2 {
        let expected_value = fixed_parent_ipv4(pairs[index])?;
        if addresses[index].interface_name != pairs[index].parent_name
            || addresses[index].ifindex != pairs[index].parent_ifindex
            || addresses[index].address != expected_value
        {
            return Err(NetworkError::InvalidIpv4Expectation);
        }
    }
    Ok(())
}

fn fixed_parent_ipv4(pair: &ExpectedVethPair) -> Result<[u8; 4], NetworkError> {
    fixed_pair_subnet(pair).map(|subnet| [10, 241, subnet, 1])
}

fn validate_endpoint_ipv4_expectation(
    pair: &ExpectedVethPair,
    address: &ExpectedIpv4Address,
) -> Result<(), NetworkError> {
    if address.interface_name != VETH_ENDPOINT_NAME
        || address.ifindex != pair.endpoint_ifindex
        || address.address != fixed_endpoint_ipv4(pair)?
    {
        Err(NetworkError::InvalidIpv4Expectation)
    } else {
        Ok(())
    }
}

fn fixed_endpoint_ipv4(pair: &ExpectedVethPair) -> Result<[u8; 4], NetworkError> {
    fixed_pair_subnet(pair).map(|subnet| [10, 241, subnet, 2])
}

fn expected_ipv4_endpoint_route(
    pair: &ExpectedVethPair,
    address: &ExpectedIpv4Address,
    namespace: NetworkNamespaceIdentity,
) -> Result<ExpectedIpv4EndpointRoute, NetworkError> {
    if namespace != pair.target_namespace
        || validate_endpoint_ipv4_expectation(pair, address).is_err()
    {
        return Err(NetworkError::InvalidIpv4RouteExpectation);
    }
    let subnet = fixed_pair_subnet(pair).map_err(|_| NetworkError::InvalidIpv4RouteExpectation)?;
    let remote_subnet = match subnet {
        1 => 2,
        2 => 1,
        _ => return Err(NetworkError::InvalidIpv4RouteExpectation),
    };
    Ok(ExpectedIpv4EndpointRoute {
        namespace,
        ifindex: address.ifindex,
        local_address: address.address,
        destination: [10, 241, remote_subnet, 2],
        gateway: [10, 241, subnet, 1],
    })
}

fn require_ipv4_endpoint_route_expectation(
    expected: &ExpectedIpv4EndpointRoute,
    pair: &ExpectedVethPair,
    address: &ExpectedIpv4Address,
    namespace: NetworkNamespaceIdentity,
) -> Result<(), NetworkError> {
    let canonical = expected_ipv4_endpoint_route(pair, address, namespace)?;
    if *expected == canonical {
        Ok(())
    } else {
        Err(NetworkError::InvalidIpv4RouteExpectation)
    }
}

fn fixed_pair_subnet(pair: &ExpectedVethPair) -> Result<u8, NetworkError> {
    let name = pair.parent_name.as_slice();
    if name.len() != 11
        || !name[3..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(NetworkError::InvalidIpv4Expectation);
    }
    match &name[..3] {
        b"vpa" => Ok(1),
        b"vpb" => Ok(2),
        _ => Err(NetworkError::InvalidIpv4Expectation),
    }
}

fn verify_exact_parent_veth_delta(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
    expected: [&ExpectedVethPair; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_parent_except_links(pristine, active)?;
    verify_exact_parent_veth_snapshot_delta(&pristine.rtnl, &active.rtnl, expected)
}

fn verify_exact_parent_veth_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: [&ExpectedVethPair; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_rtnl_except_links(pristine, active)?;
    if active.links.len() != 3 {
        return Err(NetworkError::NotPristine);
    }
    require_exact_loopback_snapshot_delta(pristine, active)?;
    let first = find_and_verify_veth_link(&active.links, expected[0], VethLinkSide::Parent)?;
    let second = find_and_verify_veth_link(&active.links, expected[1], VethLinkSide::Parent)?;
    if first.peer_netnsid == second.peer_netnsid {
        return Err(NetworkError::NotPristine);
    }
    Ok([first, second])
}

fn verify_exact_endpoint_veth_delta(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
    expected: &ExpectedVethPair,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_composite_except_links(pristine, active)?;
    verify_exact_endpoint_veth_snapshot_delta(&pristine.rtnl, &active.rtnl, expected)
}

fn verify_exact_endpoint_veth_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: &ExpectedVethPair,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_rtnl_except_links(pristine, active)?;
    if active.links.len() != 2 {
        return Err(NetworkError::NotPristine);
    }
    require_exact_loopback_snapshot_delta(pristine, active)?;
    find_and_verify_veth_link(&active.links, expected, VethLinkSide::Endpoint)
}

fn verify_exact_parent_ipv4_address_delta(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
    expected_pairs: [&ExpectedVethPair; 2],
    expected_addresses: [&ExpectedIpv4Address; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_parent_except_links_and_fixed_ipv4(pristine, active)?;
    let links = verify_exact_parent_veth_links_only(&pristine.rtnl, &active.rtnl, expected_pairs)?;
    verify_exact_fixed_ipv4_objects(&active.rtnl, &expected_addresses)?;
    Ok(links)
}

fn verify_exact_endpoint_ipv4_address_delta(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
    expected_pair: &ExpectedVethPair,
    expected_address: &ExpectedIpv4Address,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_composite_except_links_and_fixed_ipv4(pristine, active)?;
    let link = verify_exact_endpoint_veth_links_only(&pristine.rtnl, &active.rtnl, expected_pair)?;
    verify_exact_fixed_ipv4_objects(&active.rtnl, &[expected_address])?;
    Ok(link)
}

fn verify_exact_parent_ipv4_addrgen_none_delta(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
    expected_pairs: [&ExpectedVethPair; 2],
    expected_addresses: [&ExpectedIpv4Address; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_parent_except_links_and_fixed_ipv4(pristine, active)?;
    verify_exact_parent_ipv4_addrgen_none_snapshot_delta(
        &pristine.rtnl,
        &active.rtnl,
        expected_pairs,
        expected_addresses,
    )
}

fn verify_exact_parent_ipv4_addrgen_none_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected_pairs: [&ExpectedVethPair; 2],
    expected_addresses: [&ExpectedIpv4Address; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_rtnl_except_links_and_fixed_ipv4(pristine, active)?;
    let links = verify_exact_parent_veth_links_in_profile(
        pristine,
        active,
        expected_pairs,
        VethLinkProfile::DownAddrgenNone,
    )?;
    verify_exact_fixed_ipv4_objects(active, &expected_addresses)?;
    Ok(links)
}

fn verify_exact_endpoint_ipv4_addrgen_none_delta(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
    expected_pair: &ExpectedVethPair,
    expected_address: &ExpectedIpv4Address,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_composite_except_links_and_fixed_ipv4(pristine, active)?;
    verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
        &pristine.rtnl,
        &active.rtnl,
        expected_pair,
        expected_address,
    )
}

fn verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected_pair: &ExpectedVethPair,
    expected_address: &ExpectedIpv4Address,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_rtnl_except_links_and_fixed_ipv4(pristine, active)?;
    let link = verify_exact_endpoint_veth_links_in_profile(
        pristine,
        active,
        expected_pair,
        VethLinkProfile::DownAddrgenNone,
    )?;
    verify_exact_fixed_ipv4_objects(active, &[expected_address])?;
    Ok(link)
}

fn verify_exact_parent_activated_ipv4_delta(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
    expected_pairs: [&ExpectedVethPair; 2],
    expected_addresses: [&ExpectedIpv4Address; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_parent_except_activated_ipv4(pristine, active)?;
    verify_exact_parent_activated_ipv4_snapshot_delta(
        &pristine.rtnl,
        &active.rtnl,
        expected_pairs,
        expected_addresses,
    )
}

fn verify_exact_parent_activated_ipv4_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected_pairs: [&ExpectedVethPair; 2],
    expected_addresses: [&ExpectedIpv4Address; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_unchanged_rtnl_except_activated_ipv4(pristine, active)?;
    let links = verify_exact_parent_veth_links_in_profile(
        pristine,
        active,
        expected_pairs,
        VethLinkProfile::ActivatedAddrgenNone,
    )?;
    verify_exact_activated_ipv4_objects(active, &expected_addresses)?;
    Ok(links)
}

fn verify_exact_endpoint_activated_ipv4_delta(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
    expected_pair: &ExpectedVethPair,
    expected_address: &ExpectedIpv4Address,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_composite_except_activated_ipv4(pristine, active)?;
    verify_exact_endpoint_activated_ipv4_snapshot_delta(
        &pristine.rtnl,
        &active.rtnl,
        expected_pair,
        expected_address,
    )
}

fn verify_exact_endpoint_activated_ipv4_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected_pair: &ExpectedVethPair,
    expected_address: &ExpectedIpv4Address,
) -> Result<VethLinkObservation, NetworkError> {
    verify_unchanged_rtnl_except_activated_ipv4(pristine, active)?;
    let link = verify_exact_endpoint_veth_links_in_profile(
        pristine,
        active,
        expected_pair,
        VethLinkProfile::ActivatedAddrgenNone,
    )?;
    verify_exact_activated_ipv4_objects(active, &[expected_address])?;
    Ok(link)
}

fn verify_exact_endpoint_ipv4_route_delta(
    activated: &PreGoNetworkBaseline,
    routed: &PreGoNetworkBaseline,
    expected: &ExpectedIpv4EndpointRoute,
) -> Result<(), NetworkError> {
    if routed.ipv4_forwarding != activated.ipv4_forwarding || routed.nftables != activated.nftables
    {
        return Err(NetworkError::Inconsistent);
    }
    verify_exact_endpoint_ipv4_route_snapshot_delta(&activated.rtnl, &routed.rtnl, expected)
}

fn verify_exact_endpoint_ipv4_route_snapshot_delta(
    activated: &NetworkSnapshot,
    routed: &NetworkSnapshot,
    expected: &ExpectedIpv4EndpointRoute,
) -> Result<(), NetworkError> {
    if routed.links != activated.links
        || routed.qdiscs != activated.qdiscs
        || routed.addresses != activated.addresses
        || routed.neighbours != activated.neighbours
        || routed.proxy_neighbours != activated.proxy_neighbours
        || routed.nexthops != activated.nexthops
        || routed.rules_v4 != activated.rules_v4
        || routed.rules_v6 != activated.rules_v6
    {
        return Err(NetworkError::Inconsistent);
    }
    let added_routes =
        require_route_additions_preserve_baseline(&activated.routes, &routed.routes)?;
    let mut destination_routes = added_routes
        .iter()
        .filter(|route| route_has_ipv4_destination(route, expected.destination));
    let destination_route = destination_routes.next();
    if destination_routes.next().is_some() {
        return Err(NetworkError::ConflictingIpv4EndpointRoute);
    }
    let Some(destination_route) = destination_route else {
        if added_routes.is_empty() {
            return Err(NetworkError::NotPristine);
        }
        return Err(NetworkError::Inconsistent);
    };
    if added_routes.len() != 1 {
        return Err(NetworkError::Inconsistent);
    }
    let Ok(actual) = decode_fixed_ipv4_endpoint_route(destination_route) else {
        return Err(NetworkError::ConflictingIpv4EndpointRoute);
    };
    let expected = FixedIpv4EndpointRouteRecord {
        ifindex: expected.ifindex,
        destination: expected.destination,
        gateway: expected.gateway,
    };
    if actual == expected {
        Ok(())
    } else if actual.destination == expected.destination {
        Err(NetworkError::ConflictingIpv4EndpointRoute)
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn route_has_ipv4_destination(payload: &[u8], expected: [u8; 4]) -> bool {
    payload.len() >= RTMSG_LEN
        && payload[0] == AF_INET
        && payload[1] == 32
        && parse_attributes(&payload[RTMSG_LEN..]).is_ok_and(|attributes| {
            attributes.iter().any(|attribute| {
                attribute.kind == RTA_DST && attribute.flags == 0 && attribute.payload == expected
            })
        })
}

fn require_route_additions_preserve_baseline(
    activated: &[Vec<u8>],
    routed: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, NetworkError> {
    let mut additions = routed.to_vec();
    for retained in activated {
        let Some(index) = additions.iter().position(|candidate| candidate == retained) else {
            return Err(NetworkError::Inconsistent);
        };
        additions.remove(index);
    }
    Ok(additions)
}

fn verify_exact_parent_veth_links_only(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: [&ExpectedVethPair; 2],
) -> Result<[VethLinkObservation; 2], NetworkError> {
    verify_exact_parent_veth_links_in_profile(
        pristine,
        active,
        expected,
        VethLinkProfile::DownEui64,
    )
}

fn verify_exact_parent_veth_links_in_profile(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: [&ExpectedVethPair; 2],
    profile: VethLinkProfile,
) -> Result<[VethLinkObservation; 2], NetworkError> {
    if active.links.len() != 3 {
        return Err(NetworkError::NotPristine);
    }
    require_exact_loopback_snapshot_delta(pristine, active)?;
    let first = find_and_verify_veth_link_with_profile(
        &active.links,
        expected[0],
        VethLinkSide::Parent,
        profile,
    )?;
    let second = find_and_verify_veth_link_with_profile(
        &active.links,
        expected[1],
        VethLinkSide::Parent,
        profile,
    )?;
    if first.peer_netnsid == second.peer_netnsid {
        return Err(NetworkError::NotPristine);
    }
    Ok([first, second])
}

fn verify_exact_endpoint_veth_links_only(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: &ExpectedVethPair,
) -> Result<VethLinkObservation, NetworkError> {
    verify_exact_endpoint_veth_links_in_profile(
        pristine,
        active,
        expected,
        VethLinkProfile::DownEui64,
    )
}

fn verify_exact_endpoint_veth_links_in_profile(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
    expected: &ExpectedVethPair,
    profile: VethLinkProfile,
) -> Result<VethLinkObservation, NetworkError> {
    if active.links.len() != 2 {
        return Err(NetworkError::NotPristine);
    }
    require_exact_loopback_snapshot_delta(pristine, active)?;
    find_and_verify_veth_link_with_profile(&active.links, expected, VethLinkSide::Endpoint, profile)
}

fn verify_unchanged_composite_except_links(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_links(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding != pristine.ipv4_forwarding || active.nftables != pristine.nftables {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn verify_unchanged_parent_except_links(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_links(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding == pristine.ipv4_forwarding {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn verify_unchanged_composite_except_links_and_fixed_ipv4(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_links_and_fixed_ipv4(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding != pristine.ipv4_forwarding || active.nftables != pristine.nftables {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn verify_unchanged_parent_except_links_and_fixed_ipv4(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_links_and_fixed_ipv4(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding == pristine.ipv4_forwarding {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn verify_unchanged_composite_except_activated_ipv4(
    pristine: &PreGoNetworkBaseline,
    active: &PreGoNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_activated_ipv4(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding != pristine.ipv4_forwarding || active.nftables != pristine.nftables {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn verify_unchanged_parent_except_activated_ipv4(
    pristine: &RtnlProcNetworkBaseline,
    active: &RtnlProcNetworkBaseline,
) -> Result<(), NetworkError> {
    verify_unchanged_rtnl_except_activated_ipv4(&pristine.rtnl, &active.rtnl)?;
    if active.ipv4_forwarding == pristine.ipv4_forwarding {
        Ok(())
    } else {
        Err(NetworkError::Inconsistent)
    }
}

fn verify_unchanged_rtnl_except_links(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
) -> Result<(), NetworkError> {
    verify_pristine_snapshot(pristine)?;
    if active.qdiscs != pristine.qdiscs {
        return Err(NetworkError::NotPristine);
    }
    if active.addresses != pristine.addresses
        || active.routes != pristine.routes
        || active.neighbours != pristine.neighbours
        || active.proxy_neighbours != pristine.proxy_neighbours
        || active.nexthops != pristine.nexthops
        || active.rules_v4 != pristine.rules_v4
        || active.rules_v6 != pristine.rules_v6
    {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn verify_unchanged_rtnl_except_links_and_fixed_ipv4(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
) -> Result<(), NetworkError> {
    verify_pristine_snapshot(pristine)?;
    if active.qdiscs != pristine.qdiscs
        || active.neighbours != pristine.neighbours
        || active.proxy_neighbours != pristine.proxy_neighbours
        || active.nexthops != pristine.nexthops
        || active.rules_v4 != pristine.rules_v4
        || active.rules_v6 != pristine.rules_v6
    {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn verify_unchanged_rtnl_except_activated_ipv4(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
) -> Result<(), NetworkError> {
    verify_pristine_snapshot(pristine)?;
    if active.neighbours != pristine.neighbours
        || active.proxy_neighbours != pristine.proxy_neighbours
        || active.nexthops != pristine.nexthops
        || active.rules_v4 != pristine.rules_v4
        || active.rules_v6 != pristine.rules_v6
    {
        Err(NetworkError::Inconsistent)
    } else {
        Ok(())
    }
}

fn require_exact_loopback_snapshot_delta(
    pristine: &NetworkSnapshot,
    active: &NetworkSnapshot,
) -> Result<(), NetworkError> {
    let [expected_loopback] = pristine.links.as_slice() else {
        return Err(NetworkError::NotPristine);
    };
    if active
        .links
        .iter()
        .filter(|payload| *payload == expected_loopback)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FixedIpv4AddressRecord {
    interface_name: Vec<u8>,
    ifindex: u32,
    address: [u8; 4],
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FixedIpv4LocalRouteRecord {
    ifindex: u32,
    address: [u8; 4],
}

#[derive(Debug, Eq, PartialEq)]
struct FixedIpv4EndpointRouteRecord {
    ifindex: u32,
    destination: [u8; 4],
    gateway: [u8; 4],
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NoqueueQdiscRecord {
    ifindex: u32,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ActivatedRouteRecord {
    Ipv4Local {
        ifindex: u32,
        address: [u8; 4],
    },
    Ipv4Connected {
        ifindex: u32,
        network: [u8; 4],
        preferred_source: [u8; 4],
    },
    Ipv4HighBroadcast {
        ifindex: u32,
        broadcast: [u8; 4],
        preferred_source: [u8; 4],
    },
    Ipv6Multicast {
        ifindex: u32,
    },
}

fn verify_exact_fixed_ipv4_objects(
    snapshot: &NetworkSnapshot,
    expected: &[&ExpectedIpv4Address],
) -> Result<(), NetworkError> {
    if snapshot.addresses.len() != expected.len() || snapshot.routes.len() != expected.len() {
        return Err(NetworkError::NotPristine);
    }
    verify_exact_fixed_ipv4_addresses(snapshot, expected)?;

    let mut expected_routes = expected
        .iter()
        .map(|value| FixedIpv4LocalRouteRecord {
            ifindex: value.ifindex,
            address: value.address,
        })
        .collect::<Vec<_>>();
    let mut actual_routes = snapshot
        .routes
        .iter()
        .map(|payload| decode_fixed_ipv4_local_route(payload))
        .collect::<Result<Vec<_>, _>>()?;
    expected_routes.sort_unstable();
    actual_routes.sort_unstable();
    if actual_routes == expected_routes {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn verify_exact_fixed_ipv4_addresses(
    snapshot: &NetworkSnapshot,
    expected: &[&ExpectedIpv4Address],
) -> Result<(), NetworkError> {
    if snapshot.addresses.len() != expected.len() {
        return Err(NetworkError::NotPristine);
    }
    let mut expected_addresses = expected
        .iter()
        .map(|value| FixedIpv4AddressRecord {
            interface_name: value.interface_name.clone(),
            ifindex: value.ifindex,
            address: value.address,
        })
        .collect::<Vec<_>>();
    let mut actual_addresses = snapshot
        .addresses
        .iter()
        .map(|payload| decode_fixed_ipv4_address(payload))
        .collect::<Result<Vec<_>, _>>()?;
    expected_addresses.sort_unstable();
    actual_addresses.sort_unstable();
    if actual_addresses != expected_addresses {
        return Err(NetworkError::NotPristine);
    }
    Ok(())
}

fn verify_exact_activated_ipv4_objects(
    snapshot: &NetworkSnapshot,
    expected: &[&ExpectedIpv4Address],
) -> Result<(), NetworkError> {
    let expected_route_count = expected.len().checked_mul(4).ok_or(NetworkError::Limit)?;
    if snapshot.qdiscs.len() != expected.len() || snapshot.routes.len() != expected_route_count {
        return Err(NetworkError::NotPristine);
    }
    verify_exact_fixed_ipv4_addresses(snapshot, expected)?;

    let mut expected_qdiscs = expected
        .iter()
        .map(|value| NoqueueQdiscRecord {
            ifindex: value.ifindex,
        })
        .collect::<Vec<_>>();
    let mut actual_qdiscs = snapshot
        .qdiscs
        .iter()
        .map(|payload| decode_noqueue_qdisc(payload))
        .collect::<Result<Vec<_>, _>>()?;
    expected_qdiscs.sort_unstable();
    actual_qdiscs.sort_unstable();
    if actual_qdiscs != expected_qdiscs {
        return Err(NetworkError::NotPristine);
    }

    let mut expected_routes = Vec::with_capacity(expected_route_count);
    for value in expected {
        let [first, second, subnet, _host] = value.address;
        expected_routes.extend([
            ActivatedRouteRecord::Ipv4Local {
                ifindex: value.ifindex,
                address: value.address,
            },
            ActivatedRouteRecord::Ipv4Connected {
                ifindex: value.ifindex,
                network: [first, second, subnet, 0],
                preferred_source: value.address,
            },
            ActivatedRouteRecord::Ipv4HighBroadcast {
                ifindex: value.ifindex,
                broadcast: [first, second, subnet, 3],
                preferred_source: value.address,
            },
            ActivatedRouteRecord::Ipv6Multicast {
                ifindex: value.ifindex,
            },
        ]);
    }
    let mut actual_routes = snapshot
        .routes
        .iter()
        .map(|payload| decode_activated_route(payload))
        .collect::<Result<Vec<_>, _>>()?;
    expected_routes.sort_unstable();
    actual_routes.sort_unstable();
    if actual_routes == expected_routes {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn decode_fixed_ipv4_address(payload: &[u8]) -> Result<FixedIpv4AddressRecord, NetworkError> {
    if payload.len() < IFADDR_LEN
        || payload[0] != AF_INET
        || payload[1] != FIXED_IPV4_PREFIX_LENGTH
        || payload[2] != IFA_F_PERMANENT_U8
        || payload[3] != RT_SCOPE_UNIVERSE
    {
        return Err(NetworkError::NotPristine);
    }
    let ifindex = read_u32(payload, 4)?;
    if !(2..=i32::MAX as u32).contains(&ifindex) {
        return Err(NetworkError::NotPristine);
    }
    let mut address = None;
    let mut local = None;
    let mut label = None;
    let mut flags = None;
    let mut cacheinfo = None;
    for attribute in parse_attributes(&payload[IFADDR_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            IFA_ADDRESS => set_once(&mut address, read_exact_ipv4(value)?)?,
            IFA_LOCAL => set_once(&mut local, read_exact_ipv4(value)?)?,
            IFA_LABEL => set_once(&mut label, parse_interface_label(value)?)?,
            IFA_FLAGS => set_once(&mut flags, read_exact_u32(value)?)?,
            IFA_CACHEINFO => {
                if value.len() != IFA_CACHEINFO_LEN
                    || read_u32(value, 0)? != u32::MAX
                    || read_u32(value, 4)? != u32::MAX
                {
                    return Err(NetworkError::NotPristine);
                }
                set_once(&mut cacheinfo, ())?;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    let address = address.ok_or(NetworkError::NotPristine)?;
    if local != Some(address)
        || flags != Some(IFA_F_PERMANENT)
        || cacheinfo.is_none()
        || !FIXED_IPV4_ADDRESSES.contains(&address)
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(FixedIpv4AddressRecord {
        interface_name: label.ok_or(NetworkError::NotPristine)?,
        ifindex,
        address,
    })
}

fn decode_fixed_ipv4_local_route(
    payload: &[u8],
) -> Result<FixedIpv4LocalRouteRecord, NetworkError> {
    if payload.len() < RTMSG_LEN
        || payload[0] != AF_INET
        || payload[1] != 32
        || payload[2] != 0
        || payload[3] != 0
        || u32::from(payload[4]) != RT_TABLE_LOCAL
        || payload[5] != RTPROT_KERNEL
        || payload[6] != RT_SCOPE_HOST
        || payload[7] != RTN_LOCAL
        || read_u32(payload, 8)? != 0
    {
        return Err(NetworkError::NotPristine);
    }
    let mut destination = None;
    let mut preferred_source = None;
    let mut output_interface = None;
    let mut table = None;
    for attribute in parse_attributes(&payload[RTMSG_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            RTA_DST => set_once(&mut destination, read_exact_ipv4(value)?)?,
            RTA_OIF => set_once(&mut output_interface, read_exact_u32(value)?)?,
            RTA_PREFSRC => set_once(&mut preferred_source, read_exact_ipv4(value)?)?,
            RTA_TABLE => set_once(&mut table, read_exact_u32(value)?)?,
            _ => return Err(NetworkError::NotPristine),
        }
    }
    let address = destination.ok_or(NetworkError::NotPristine)?;
    let ifindex = output_interface.ok_or(NetworkError::NotPristine)?;
    if preferred_source != Some(address)
        || table != Some(RT_TABLE_LOCAL)
        || !(2..=i32::MAX as u32).contains(&ifindex)
        || !FIXED_IPV4_ADDRESSES.contains(&address)
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(FixedIpv4LocalRouteRecord { ifindex, address })
}

fn decode_fixed_ipv4_endpoint_route(
    payload: &[u8],
) -> Result<FixedIpv4EndpointRouteRecord, NetworkError> {
    if payload.len() < RTMSG_LEN
        || payload[0] != AF_INET
        || payload[1] != 32
        || payload[2] != 0
        || payload[3] != 0
        || u32::from(payload[4]) != RT_TABLE_MAIN
        || payload[5] != RTPROT_STATIC
        || payload[6] != RT_SCOPE_UNIVERSE
        || payload[7] != RTN_UNICAST
        || read_u32(payload, 8)? != 0
    {
        return Err(NetworkError::NotPristine);
    }
    let mut destination = None;
    let mut gateway = None;
    let mut output_interface = None;
    let mut table = None;
    for attribute in parse_attributes(&payload[RTMSG_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            RTA_DST => set_once(&mut destination, read_exact_ipv4(value)?)?,
            RTA_GATEWAY => set_once(&mut gateway, read_exact_ipv4(value)?)?,
            RTA_OIF => set_once(&mut output_interface, read_exact_u32(value)?)?,
            RTA_TABLE => set_once(&mut table, read_exact_u32(value)?)?,
            _ => return Err(NetworkError::NotPristine),
        }
    }
    if table != Some(RT_TABLE_MAIN) {
        return Err(NetworkError::NotPristine);
    }
    Ok(FixedIpv4EndpointRouteRecord {
        ifindex: required_route_ifindex(output_interface)?,
        destination: destination.ok_or(NetworkError::NotPristine)?,
        gateway: gateway.ok_or(NetworkError::NotPristine)?,
    })
}

fn decode_noqueue_qdisc(payload: &[u8]) -> Result<NoqueueQdiscRecord, NetworkError> {
    if payload.len() < TCMSG_LEN
        || payload[0] != AF_UNSPEC
        || payload[1..4] != [0, 0, 0]
        || read_u32(payload, 8)? != 0
        || read_u32(payload, 12)? != TC_H_ROOT
        || read_u32(payload, 16)? != NOQUEUE_REFERENCE_COUNT
    {
        return Err(NetworkError::NotPristine);
    }
    let ifindex = read_i32(payload, 4)?;
    if !(2..=i32::MAX).contains(&ifindex) {
        return Err(NetworkError::NotPristine);
    }
    let mut kind_seen = false;
    let mut hardware_offload_seen = false;
    let mut legacy_stats_seen = false;
    let mut stats2_seen = false;
    for attribute in parse_attributes(&payload[TCMSG_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            TCA_KIND if !kind_seen && value == b"noqueue\0" => kind_seen = true,
            TCA_HW_OFFLOAD if !hardware_offload_seen && value == [0] => {
                hardware_offload_seen = true;
            }
            TCA_STATS
                if !legacy_stats_seen
                    && value.len() == TC_STATS_BYTES
                    && value.iter().all(|byte| *byte == 0) =>
            {
                legacy_stats_seen = true;
            }
            TCA_STATS2 if !stats2_seen => {
                verify_zero_noqueue_stats2(value)?;
                stats2_seen = true;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    if !(kind_seen && hardware_offload_seen && legacy_stats_seen && stats2_seen) {
        return Err(NetworkError::NotPristine);
    }
    Ok(NoqueueQdiscRecord {
        ifindex: u32::try_from(ifindex).map_err(|_| NetworkError::NotPristine)?,
    })
}

fn verify_zero_noqueue_stats2(payload: &[u8]) -> Result<(), NetworkError> {
    let mut basic_seen = false;
    let mut queue_seen = false;
    for statistic in parse_attributes(payload)? {
        let value = statistic.unflagged_payload()?;
        match statistic.kind {
            TCA_STATS_BASIC
                if !basic_seen
                    && value.len() == TC_STATS_BASIC_BYTES
                    && value.iter().all(|byte| *byte == 0) =>
            {
                basic_seen = true;
            }
            TCA_STATS_QUEUE
                if !queue_seen
                    && value.len() == TC_STATS_QUEUE_BYTES
                    && value.iter().all(|byte| *byte == 0) =>
            {
                queue_seen = true;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    if basic_seen && queue_seen {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn decode_activated_route(payload: &[u8]) -> Result<ActivatedRouteRecord, NetworkError> {
    if payload.len() < RTMSG_LEN {
        return Err(NetworkError::NotPristine);
    }
    match (payload[0], payload[7]) {
        (AF_INET, RTN_LOCAL) => {
            let record = decode_fixed_ipv4_local_route(payload)?;
            Ok(ActivatedRouteRecord::Ipv4Local {
                ifindex: record.ifindex,
                address: record.address,
            })
        }
        (AF_INET, RTN_UNICAST) => decode_activated_ipv4_connected_route(payload),
        (AF_INET, RTN_BROADCAST) => decode_activated_ipv4_broadcast_route(payload),
        (AF_INET6, RTN_MULTICAST) => decode_activated_ipv6_multicast_route(payload),
        _ => Err(NetworkError::NotPristine),
    }
}

fn decode_activated_ipv4_connected_route(
    payload: &[u8],
) -> Result<ActivatedRouteRecord, NetworkError> {
    verify_activated_route_header(
        payload,
        AF_INET,
        FIXED_IPV4_PREFIX_LENGTH,
        RT_TABLE_MAIN,
        RT_SCOPE_LINK,
        RTN_UNICAST,
    )?;
    let (destination, preferred_source, output_interface, table, priority, preference, cacheinfo) =
        decode_activated_route_attributes(payload, true)?;
    let network = read_exact_ipv4(destination.ok_or(NetworkError::NotPristine)?)?;
    let preferred_source = read_exact_ipv4(preferred_source.ok_or(NetworkError::NotPristine)?)?;
    let ifindex = required_route_ifindex(output_interface)?;
    if table != Some(RT_TABLE_MAIN)
        || priority.is_some()
        || preference.is_some()
        || cacheinfo.is_some()
        || network[3] != 0
        || !FIXED_IPV4_ADDRESSES.contains(&preferred_source)
        || network[..3] != preferred_source[..3]
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(ActivatedRouteRecord::Ipv4Connected {
        ifindex,
        network,
        preferred_source,
    })
}

fn decode_activated_ipv4_broadcast_route(
    payload: &[u8],
) -> Result<ActivatedRouteRecord, NetworkError> {
    verify_activated_route_header(
        payload,
        AF_INET,
        32,
        RT_TABLE_LOCAL,
        RT_SCOPE_LINK,
        RTN_BROADCAST,
    )?;
    let (destination, preferred_source, output_interface, table, priority, preference, cacheinfo) =
        decode_activated_route_attributes(payload, true)?;
    let broadcast = read_exact_ipv4(destination.ok_or(NetworkError::NotPristine)?)?;
    let preferred_source = read_exact_ipv4(preferred_source.ok_or(NetworkError::NotPristine)?)?;
    let ifindex = required_route_ifindex(output_interface)?;
    if table != Some(RT_TABLE_LOCAL)
        || priority.is_some()
        || preference.is_some()
        || cacheinfo.is_some()
        || broadcast[3] != 3
        || !FIXED_IPV4_ADDRESSES.contains(&preferred_source)
        || broadcast[..3] != preferred_source[..3]
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(ActivatedRouteRecord::Ipv4HighBroadcast {
        ifindex,
        broadcast,
        preferred_source,
    })
}

fn decode_activated_ipv6_multicast_route(
    payload: &[u8],
) -> Result<ActivatedRouteRecord, NetworkError> {
    verify_activated_route_header(
        payload,
        AF_INET6,
        8,
        RT_TABLE_LOCAL,
        RT_SCOPE_UNIVERSE,
        RTN_MULTICAST,
    )?;
    let (destination, preferred_source, output_interface, table, priority, preference, cacheinfo) =
        decode_activated_route_attributes(payload, false)?;
    let destination = read_exact_ipv6(destination.ok_or(NetworkError::NotPristine)?)?;
    let ifindex = required_route_ifindex(output_interface)?;
    if destination != [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        || preferred_source.is_some()
        || table != Some(RT_TABLE_LOCAL)
        || priority != Some(256)
        || preference != Some(IPV6_DEFAULT_PREFERENCE)
        || cacheinfo != Some(())
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(ActivatedRouteRecord::Ipv6Multicast { ifindex })
}

fn verify_activated_route_header(
    payload: &[u8],
    family: u8,
    prefix_length: u8,
    table: u32,
    scope: u8,
    route_type: u8,
) -> Result<(), NetworkError> {
    if payload.len() < RTMSG_LEN
        || payload[0] != family
        || payload[1] != prefix_length
        || payload[2] != 0
        || payload[3] != 0
        || u32::from(payload[4]) != table
        || payload[5] != RTPROT_KERNEL
        || payload[6] != scope
        || payload[7] != route_type
        || read_u32(payload, 8)? != 0
    {
        Err(NetworkError::NotPristine)
    } else {
        Ok(())
    }
}

type ActivatedRouteAttributes<'a> = (
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u8>,
    Option<()>,
);

fn decode_activated_route_attributes(
    payload: &[u8],
    allow_preferred_source: bool,
) -> Result<ActivatedRouteAttributes<'_>, NetworkError> {
    let mut destination = None;
    let mut preferred_source = None;
    let mut output_interface = None;
    let mut table = None;
    let mut priority = None;
    let mut preference = None;
    let mut cacheinfo = None;
    for attribute in parse_attributes(&payload[RTMSG_LEN..])? {
        let value = attribute.unflagged_payload()?;
        match attribute.kind {
            RTA_DST => set_once(&mut destination, value)?,
            RTA_OIF => set_once(&mut output_interface, read_exact_u32(value)?)?,
            RTA_PREFSRC if allow_preferred_source => {
                set_once(&mut preferred_source, value)?;
            }
            RTA_TABLE => set_once(&mut table, read_exact_u32(value)?)?,
            RTA_PRIORITY => set_once(&mut priority, read_exact_u32(value)?)?,
            RTA_PREF => set_once(&mut preference, read_exact_u8(value)?)?,
            RTA_CACHEINFO
                if value.len() == IPV6_ROUTE_CACHEINFO_BYTES
                    && value.iter().all(|byte| *byte == 0) =>
            {
                set_once(&mut cacheinfo, ())?;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    Ok((
        destination,
        preferred_source,
        output_interface,
        table,
        priority,
        preference,
        cacheinfo,
    ))
}

fn required_route_ifindex(value: Option<u32>) -> Result<u32, NetworkError> {
    let value = value.ok_or(NetworkError::NotPristine)?;
    if (2..=i32::MAX as u32).contains(&value) {
        Ok(value)
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn parse_interface_label(payload: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let Some((&0, name)) = payload.split_last() else {
        return Err(NetworkError::NotPristine);
    };
    if name.is_empty()
        || name.len() > MAX_INTERFACE_NAME_BYTES
        || !name.is_ascii()
        || name.contains(&0)
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(name.to_vec())
}

fn read_exact_ipv4(bytes: &[u8]) -> Result<[u8; 4], NetworkError> {
    bytes.try_into().map_err(|_| NetworkError::NotPristine)
}

fn read_exact_ipv6(bytes: &[u8]) -> Result<[u8; 16], NetworkError> {
    bytes.try_into().map_err(|_| NetworkError::NotPristine)
}

#[derive(Clone, Copy)]
enum VethLinkSide {
    Parent,
    Endpoint,
}

#[derive(Clone, Copy)]
enum VethLinkProfile {
    DownEui64,
    DownAddrgenNone,
    ActivatedAddrgenNone,
}

impl VethLinkProfile {
    const fn flags(self) -> u32 {
        match self {
            Self::DownEui64 | Self::DownAddrgenNone => VETH_FLAGS,
            Self::ActivatedAddrgenNone => VETH_UP_FLAGS,
        }
    }

    const fn qdisc(self) -> &'static [u8] {
        match self {
            Self::DownEui64 | Self::DownAddrgenNone => b"noop\0",
            Self::ActivatedAddrgenNone => b"noqueue\0",
        }
    }

    const fn operstate(self) -> u8 {
        match self {
            Self::DownEui64 | Self::DownAddrgenNone => IF_OPER_DOWN,
            Self::ActivatedAddrgenNone => IF_OPER_UP,
        }
    }

    const fn addrgen_mode(self) -> u8 {
        match self {
            Self::DownEui64 => IN6_ADDR_GEN_MODE_EUI64,
            Self::DownAddrgenNone | Self::ActivatedAddrgenNone => IN6_ADDR_GEN_MODE_NONE,
        }
    }

    const fn telemetry(self) -> LinkTelemetryProfile {
        match self {
            Self::DownEui64 | Self::DownAddrgenNone => LinkTelemetryProfile::Veth,
            Self::ActivatedAddrgenNone => LinkTelemetryProfile::ActivatedVeth,
        }
    }
}

fn find_and_verify_veth_link(
    links: &[Vec<u8>],
    expected: &ExpectedVethPair,
    side: VethLinkSide,
) -> Result<VethLinkObservation, NetworkError> {
    find_and_verify_veth_link_with_profile(links, expected, side, VethLinkProfile::DownEui64)
}

fn find_and_verify_veth_link_with_profile(
    links: &[Vec<u8>],
    expected: &ExpectedVethPair,
    side: VethLinkSide,
    profile: VethLinkProfile,
) -> Result<VethLinkObservation, NetworkError> {
    let expected_index = match side {
        VethLinkSide::Parent => expected.parent_ifindex,
        VethLinkSide::Endpoint => expected.endpoint_ifindex,
    };
    let mut matching = links.iter().filter_map(|payload| {
        let index = read_i32(payload, 4).ok()?;
        (index == i32::try_from(expected_index).ok()?).then_some(payload.as_slice())
    });
    let payload = matching.next().ok_or(NetworkError::NotPristine)?;
    if matching.next().is_some() {
        return Err(NetworkError::NotPristine);
    }
    verify_veth_link_with_profile(payload, expected, side, profile)
}

#[derive(Default)]
struct VethLinkAttributes<'a> {
    name: Option<&'a [u8]>,
    peer_index: Option<u32>,
    peer_netnsid: Option<i32>,
    address: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    broadcast: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    mtu: Option<u32>,
    queue_length: Option<u32>,
    transmit_queues: Option<u32>,
    receive_queues: Option<u32>,
    permanent_address: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    qdisc: Option<&'a [u8]>,
    operstate: Option<&'a [u8]>,
    linkmode: Option<u8>,
    group: Option<u32>,
    promiscuity: Option<u32>,
    allmulti: Option<u32>,
    protocol_down: Option<u8>,
    carrier: Option<u8>,
    carrier_changes: Option<u32>,
    carrier_up_count: Option<u32>,
    carrier_down_count: Option<u32>,
    zeroed_structs_seen: u8,
    link_info_seen: bool,
    address_families_seen: bool,
}

#[cfg(test)]
fn verify_veth_link(
    payload: &[u8],
    expected: &ExpectedVethPair,
    side: VethLinkSide,
) -> Result<VethLinkObservation, NetworkError> {
    verify_veth_link_with_profile(payload, expected, side, VethLinkProfile::DownEui64)
}

fn verify_veth_link_with_profile(
    payload: &[u8],
    expected: &ExpectedVethPair,
    side: VethLinkSide,
    profile: VethLinkProfile,
) -> Result<VethLinkObservation, NetworkError> {
    let (expected_index, expected_peer_index, expected_name) = match side {
        VethLinkSide::Parent => (
            expected.parent_ifindex,
            expected.endpoint_ifindex,
            expected.parent_name.as_slice(),
        ),
        VethLinkSide::Endpoint => (
            expected.endpoint_ifindex,
            expected.parent_ifindex,
            VETH_ENDPOINT_NAME,
        ),
    };
    verify_veth_link_header(payload, expected_index, profile)?;
    let observed = parse_veth_link_attributes(&payload[IFINFO_LEN..], profile)?;
    let address = observed.address.ok_or(NetworkError::NotPristine)?;
    if !interface_name_is_exact(observed.name, expected_name)
        || observed.peer_index != Some(expected_peer_index)
        || observed.peer_netnsid.is_none_or(|value| value < 0)
        || observed.mtu != Some(VETH_MTU)
        || observed.queue_length != Some(VETH_TX_QUEUE_LENGTH)
        || observed.transmit_queues != Some(VETH_QUEUE_COUNT)
        || observed.receive_queues != Some(VETH_QUEUE_COUNT)
        || observed.qdisc != Some(profile.qdisc())
        || observed.operstate != Some(&[profile.operstate()][..])
        || observed.linkmode != Some(0)
        || observed.group != Some(0)
        || observed.promiscuity != Some(0)
        || observed.allmulti != Some(0)
        || observed.protocol_down != Some(0)
        || !veth_carrier_telemetry_matches(&observed, profile)
        || observed.zeroed_structs_seen != VETH_ZEROED_STRUCTS_SEEN
        || observed.broadcast != Some([u8::MAX; ETHERNET_ADDRESS_BYTES])
        || address == [0; ETHERNET_ADDRESS_BYTES]
        || address[0] & 0b11 != 0b10
        || observed
            .permanent_address
            .is_some_and(|permanent| permanent != address)
        || !observed.link_info_seen
        || !observed.address_families_seen
    {
        return Err(NetworkError::NotPristine);
    }
    Ok(VethLinkObservation {
        identity: expected.clone(),
        mac: address,
        peer_netnsid: observed.peer_netnsid.ok_or(NetworkError::NotPristine)?,
    })
}

fn verify_veth_link_header(
    payload: &[u8],
    expected_index: u32,
    profile: VethLinkProfile,
) -> Result<(), NetworkError> {
    if payload.len() < IFINFO_LEN
        || payload[0] != AF_UNSPEC
        || payload[1] != 0
        || read_u16(payload, 2)? != ARPHRD_ETHER
        || read_i32(payload, 4)?
            != i32::try_from(expected_index).map_err(|_| NetworkError::Limit)?
        || read_u32(payload, 8)? != profile.flags()
        || read_u32(payload, 12)? != 0
    {
        Err(NetworkError::NotPristine)
    } else {
        Ok(())
    }
}

fn parse_veth_link_attributes(
    bytes: &[u8],
    profile: VethLinkProfile,
) -> Result<VethLinkAttributes<'_>, NetworkError> {
    let mut observed = VethLinkAttributes::default();
    let mut attributes_seen = [false; MAX_DEBIAN13_LINK_ATTRIBUTE + 1];
    for attribute in parse_attributes(bytes)? {
        let kind_index = usize::from(attribute.kind);
        if kind_index >= attributes_seen.len() || attributes_seen[kind_index] {
            return Err(NetworkError::NotPristine);
        }
        attributes_seen[kind_index] = true;
        apply_veth_link_attribute(&mut observed, attribute, profile)?;
    }
    Ok(observed)
}

fn apply_veth_link_attribute<'a>(
    observed: &mut VethLinkAttributes<'a>,
    attribute: Attribute<'a>,
    profile: VethLinkProfile,
) -> Result<(), NetworkError> {
    match attribute.kind {
        IFLA_ADDRESS => set_once(
            &mut observed.address,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_BROADCAST => set_once(
            &mut observed.broadcast,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_IFNAME => set_once(&mut observed.name, attribute.unflagged_payload()?),
        IFLA_MTU => set_once(
            &mut observed.mtu,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINK => set_once(
            &mut observed.peer_index,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_QDISC => set_once(&mut observed.qdisc, attribute.unflagged_payload()?),
        IFLA_MASTER | IFLA_IFALIAS | IFLA_ALT_IFNAME => Err(NetworkError::NotPristine),
        IFLA_TXQLEN => set_once(
            &mut observed.queue_length,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_NUM_TX_QUEUES => set_once(
            &mut observed.transmit_queues,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_NUM_RX_QUEUES => set_once(
            &mut observed.receive_queues,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_STATS => {
            verify_zeroed_attribute(attribute, VETH_LINK_STATS_BYTES)?;
            observed.zeroed_structs_seen |= VETH_STATS_SEEN;
            Ok(())
        }
        IFLA_STATS64 => {
            verify_zeroed_attribute(attribute, VETH_LINK_STATS64_BYTES)?;
            observed.zeroed_structs_seen |= VETH_STATS64_SEEN;
            Ok(())
        }
        IFLA_MAP => {
            verify_zeroed_attribute(attribute, VETH_LINK_IFMAP_BYTES)?;
            observed.zeroed_structs_seen |= VETH_IFMAP_SEEN;
            Ok(())
        }
        IFLA_PERM_ADDRESS => set_once(
            &mut observed.permanent_address,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_OPERSTATE => set_once(&mut observed.operstate, attribute.unflagged_payload()?),
        IFLA_LINKMODE => set_once(
            &mut observed.linkmode,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINKINFO => {
            verify_veth_link_info(attribute)?;
            observed.link_info_seen = true;
            Ok(())
        }
        IFLA_AF_SPEC => {
            verify_address_family_spec(attribute, profile.addrgen_mode())?;
            observed.address_families_seen = true;
            Ok(())
        }
        IFLA_GROUP => set_once(
            &mut observed.group,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROMISCUITY => set_once(
            &mut observed.promiscuity,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINK_NETNSID => set_once(
            &mut observed.peer_netnsid,
            read_exact_i32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROTO_DOWN => set_once(
            &mut observed.protocol_down,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_CARRIER | IFLA_CARRIER_CHANGES | IFLA_CARRIER_UP_COUNT | IFLA_CARRIER_DOWN_COUNT => {
            apply_veth_carrier_attribute(observed, attribute)
        }
        IFLA_ALLMULTI => set_once(
            &mut observed.allmulti,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROP_LIST if !attribute.payload.is_empty() => Err(NetworkError::NotPristine),
        IFLA_XDP => verify_xdp(attribute),
        _ => verify_allowed_link_telemetry(attribute, profile.telemetry()),
    }
}

fn apply_veth_carrier_attribute(
    observed: &mut VethLinkAttributes<'_>,
    attribute: Attribute<'_>,
) -> Result<(), NetworkError> {
    let payload = attribute.unflagged_payload()?;
    match attribute.kind {
        IFLA_CARRIER => set_once(&mut observed.carrier, read_exact_u8(payload)?),
        IFLA_CARRIER_CHANGES => set_once(&mut observed.carrier_changes, read_exact_u32(payload)?),
        IFLA_CARRIER_UP_COUNT => set_once(&mut observed.carrier_up_count, read_exact_u32(payload)?),
        IFLA_CARRIER_DOWN_COUNT => {
            set_once(&mut observed.carrier_down_count, read_exact_u32(payload)?)
        }
        _ => Err(NetworkError::NotPristine),
    }
}

fn veth_carrier_telemetry_matches(
    observed: &VethLinkAttributes<'_>,
    profile: VethLinkProfile,
) -> bool {
    let expected = match profile {
        VethLinkProfile::DownEui64 | VethLinkProfile::DownAddrgenNone => (0, 1, 0, 1),
        VethLinkProfile::ActivatedAddrgenNone => (1, 2, 1, 1),
    };
    let values = (
        observed.carrier,
        observed.carrier_changes,
        observed.carrier_up_count,
        observed.carrier_down_count,
    );
    match profile {
        VethLinkProfile::DownEui64 | VethLinkProfile::DownAddrgenNone => {
            values.0.is_none_or(|value| value == expected.0)
                && values.1.is_none_or(|value| value == expected.1)
                && values.2.is_none_or(|value| value == expected.2)
                && values.3.is_none_or(|value| value == expected.3)
        }
        VethLinkProfile::ActivatedAddrgenNone => {
            values
                == (
                    Some(expected.0),
                    Some(expected.1),
                    Some(expected.2),
                    Some(expected.3),
                )
        }
    }
}

fn interface_name_is_exact(observed: Option<&[u8]>, expected: &[u8]) -> bool {
    observed.is_some_and(|observed| {
        observed.len() == expected.len() + 1
            && observed.ends_with(&[0])
            && &observed[..expected.len()] == expected
    })
}

fn verify_veth_link_info(attribute: Attribute<'_>) -> Result<(), NetworkError> {
    let mut kind = None;
    for nested in parse_attributes(attribute.unflagged_payload()?)? {
        match nested.kind {
            IFLA_INFO_KIND => set_once(&mut kind, nested.unflagged_payload()?)?,
            _ => return Err(NetworkError::NotPristine),
        }
    }
    if kind == Some(&b"veth\0"[..]) {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

#[derive(Default)]
struct LoopbackLinkAttributes<'a> {
    name: Option<&'a [u8]>,
    operstate: Option<&'a [u8]>,
    address: Option<&'a [u8]>,
    broadcast: Option<&'a [u8]>,
    mtu: Option<u32>,
    queue_length: Option<u32>,
    qdisc: Option<&'a [u8]>,
    linkmode: Option<u8>,
    group: Option<u32>,
    promiscuity: Option<u32>,
    allmulti: Option<u32>,
    protocol_down: Option<u8>,
    offload_limits: [Option<u32>; LOOPBACK_OFFLOAD_LIMITS.len()],
    address_families_seen: bool,
}

fn verify_loopback(payload: &[u8]) -> Result<(), NetworkError> {
    verify_loopback_header(payload)?;
    let observed = parse_loopback_link_attributes(&payload[IFINFO_LEN..])?;
    if observed.name == Some(&b"lo\0"[..])
        && observed.operstate == Some(&[IF_OPER_DOWN][..])
        && observed.address == Some(&[0; 6][..])
        && observed.broadcast == Some(&[0; 6][..])
        && observed.mtu == Some(LOOPBACK_MTU)
        && observed.queue_length == Some(LOOPBACK_TX_QUEUE_LENGTH)
        && observed.qdisc == Some(&b"noop\0"[..])
        && observed.linkmode == Some(0)
        && observed.group == Some(0)
        && observed.promiscuity == Some(0)
        && observed.allmulti == Some(0)
        && observed.protocol_down == Some(0)
        && observed.offload_limits == LOOPBACK_OFFLOAD_LIMITS.map(Some)
        && observed.address_families_seen
    {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn parse_loopback_link_attributes(
    bytes: &[u8],
) -> Result<LoopbackLinkAttributes<'_>, NetworkError> {
    let mut observed = LoopbackLinkAttributes::default();
    let mut attributes_seen = [false; MAX_DEBIAN13_LINK_ATTRIBUTE + 1];
    for attribute in parse_attributes(bytes)? {
        let kind_index = usize::from(attribute.kind);
        if kind_index >= attributes_seen.len() || attributes_seen[kind_index] {
            return Err(NetworkError::NotPristine);
        }
        attributes_seen[kind_index] = true;
        apply_loopback_link_attribute(&mut observed, attribute)?;
    }
    Ok(observed)
}

fn apply_loopback_link_attribute<'a>(
    observed: &mut LoopbackLinkAttributes<'a>,
    attribute: Attribute<'a>,
) -> Result<(), NetworkError> {
    match attribute.kind {
        IFLA_ADDRESS => set_once(&mut observed.address, attribute.unflagged_payload()?),
        IFLA_BROADCAST => set_once(&mut observed.broadcast, attribute.unflagged_payload()?),
        IFLA_IFNAME => set_once(&mut observed.name, attribute.unflagged_payload()?),
        IFLA_MTU => set_once(
            &mut observed.mtu,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_QDISC => set_once(&mut observed.qdisc, attribute.unflagged_payload()?),
        IFLA_TXQLEN => set_once(
            &mut observed.queue_length,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_OPERSTATE => set_once(&mut observed.operstate, attribute.unflagged_payload()?),
        IFLA_LINKMODE => set_once(
            &mut observed.linkmode,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_AF_SPEC => {
            verify_address_family_spec(attribute, IN6_ADDR_GEN_MODE_EUI64)?;
            observed.address_families_seen = true;
            Ok(())
        }
        IFLA_GROUP => set_once(
            &mut observed.group,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROMISCUITY => set_once(
            &mut observed.promiscuity,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROTO_DOWN => set_once(
            &mut observed.protocol_down,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        kind @ (IFLA_GSO_MAX_SEGS
        | IFLA_GSO_MAX_SIZE
        | IFLA_GRO_MAX_SIZE
        | IFLA_GSO_IPV4_MAX_SIZE
        | IFLA_GRO_IPV4_MAX_SIZE) => {
            let index = offload_limit_index(kind).ok_or(NetworkError::Malformed)?;
            set_once(
                &mut observed.offload_limits[index],
                read_exact_u32(attribute.unflagged_payload()?)?,
            )
        }
        IFLA_ALLMULTI => set_once(
            &mut observed.allmulti,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINK | IFLA_MASTER | IFLA_LINKINFO | IFLA_IFALIAS | IFLA_ALT_IFNAME => {
            Err(NetworkError::NotPristine)
        }
        IFLA_PROP_LIST if !attribute.payload.is_empty() => Err(NetworkError::NotPristine),
        IFLA_XDP => verify_xdp(attribute),
        _ => verify_allowed_link_telemetry(attribute, LinkTelemetryProfile::Loopback),
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

#[derive(Clone, Copy)]
enum LinkTelemetryProfile {
    Loopback,
    Veth,
    ActivatedVeth,
}

fn verify_allowed_link_telemetry(
    attribute: Attribute<'_>,
    profile: LinkTelemetryProfile,
) -> Result<(), NetworkError> {
    if matches!(
        attribute.kind,
        IFLA_PROP_LIST | IFLA_DEVLINK_PORT | IFLA_DPLL_PIN
    ) && attribute.flags == NLA_F_NESTED
        && attribute.payload.is_empty()
    {
        return Ok(());
    }
    let payload = attribute.unflagged_payload()?;
    let (queues, carrier, carrier_changes, carrier_up, carrier_down, minimum_mtu, maximum_mtu) =
        match profile {
            LinkTelemetryProfile::Loopback => (1, 1, 0, 0, 0, 0, 0),
            LinkTelemetryProfile::Veth => {
                (VETH_QUEUE_COUNT, 0, 1, 0, 1, VETH_MIN_MTU, VETH_MAX_MTU)
            }
            LinkTelemetryProfile::ActivatedVeth => {
                (VETH_QUEUE_COUNT, 1, 2, 1, 1, VETH_MIN_MTU, VETH_MAX_MTU)
            }
        };
    match attribute.kind {
        IFLA_STATS => verify_profile_statistics(payload, profile, VETH_LINK_STATS_BYTES),
        IFLA_STATS64 => verify_profile_statistics(payload, profile, VETH_LINK_STATS64_BYTES),
        IFLA_MAP => verify_profile_statistics(payload, profile, VETH_LINK_IFMAP_BYTES),
        IFLA_NUM_TX_QUEUES | IFLA_NUM_RX_QUEUES if read_exact_u32(payload)? == queues => Ok(()),
        IFLA_CARRIER if read_exact_u8(payload)? == carrier => Ok(()),
        IFLA_CARRIER_CHANGES if read_exact_u32(payload)? == carrier_changes => Ok(()),
        IFLA_CARRIER_UP_COUNT if read_exact_u32(payload)? == carrier_up => Ok(()),
        IFLA_CARRIER_DOWN_COUNT if read_exact_u32(payload)? == carrier_down => Ok(()),
        IFLA_EVENT if read_exact_u32(payload)? == 0 => Ok(()),
        IFLA_MIN_MTU if read_exact_u32(payload)? == minimum_mtu => Ok(()),
        IFLA_MAX_MTU if read_exact_u32(payload)? == maximum_mtu => Ok(()),
        IFLA_GSO_MAX_SEGS if read_exact_u32(payload)? == LOOPBACK_GSO_MAX_SEGMENTS => Ok(()),
        IFLA_GSO_MAX_SIZE | IFLA_GRO_MAX_SIZE | IFLA_GSO_IPV4_MAX_SIZE | IFLA_GRO_IPV4_MAX_SIZE
            if read_exact_u32(payload)? == LOOPBACK_OFFLOAD_MAX_SIZE =>
        {
            Ok(())
        }
        IFLA_TSO_MAX_SIZE if read_exact_u32(payload)? == DEFAULT_TSO_MAX_SIZE => Ok(()),
        IFLA_TSO_MAX_SEGS if read_exact_u32(payload)? == DEFAULT_TSO_MAX_SEGMENTS => Ok(()),
        IFLA_PERM_ADDRESS => {
            let address = read_exact_ethernet_address(payload)?;
            match profile {
                LinkTelemetryProfile::Loopback if address == [0; ETHERNET_ADDRESS_BYTES] => Ok(()),
                LinkTelemetryProfile::Veth | LinkTelemetryProfile::ActivatedVeth
                    if address != [0; ETHERNET_ADDRESS_BYTES] && address[0] & 0b11 == 0b10 =>
                {
                    Ok(())
                }
                _ => Err(NetworkError::NotPristine),
            }
        }
        _ => Err(NetworkError::NotPristine),
    }
}

fn verify_profile_statistics(
    payload: &[u8],
    profile: LinkTelemetryProfile,
    veth_length: usize,
) -> Result<(), NetworkError> {
    match profile {
        LinkTelemetryProfile::Loopback if !payload.is_empty() => Ok(()),
        LinkTelemetryProfile::Veth | LinkTelemetryProfile::ActivatedVeth
            if payload.len() == veth_length && payload.iter().all(|b| *b == 0) =>
        {
            Ok(())
        }
        _ => Err(NetworkError::NotPristine),
    }
}

fn verify_zeroed_attribute(
    attribute: Attribute<'_>,
    exact_length: usize,
) -> Result<(), NetworkError> {
    let payload = attribute.unflagged_payload()?;
    if payload.len() == exact_length && payload.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn verify_address_family_spec(
    attribute: Attribute<'_>,
    expected_addrgen_mode: u8,
) -> Result<(), NetworkError> {
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
                let mut configuration_seen = false;
                for ipv4_attribute in parse_attributes(family.payload)? {
                    if ipv4_attribute.kind != IFLA_INET_CONF
                        || ipv4_attribute.flags != 0
                        || ipv4_attribute.payload.is_empty()
                        || ipv4_attribute.payload.len() % 4 != 0
                        || configuration_seen
                    {
                        return Err(NetworkError::NotPristine);
                    }
                    configuration_seen = true;
                }
            }
            family_kind if family_kind == u16::from(AF_INET6) => {
                set_once(&mut ipv6, family.payload)?;
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    let mut address_generation_mode = None;
    let mut seen = [false; 10];
    for ipv6_attribute in parse_attributes(ipv6.ok_or(NetworkError::NotPristine)?)? {
        if ipv6_attribute.flags != 0
            || usize::from(ipv6_attribute.kind) >= seen.len()
            || ipv6_attribute.kind == 0
            || seen[usize::from(ipv6_attribute.kind)]
        {
            return Err(NetworkError::NotPristine);
        }
        seen[usize::from(ipv6_attribute.kind)] = true;
        let payload = ipv6_attribute.payload;
        match ipv6_attribute.kind {
            IFLA_INET6_FLAGS | IFLA_INET6_RA_MTU => {
                read_exact_u32(payload)?;
            }
            IFLA_INET6_CONF
            | IFLA_INET6_STATS
            | IFLA_INET6_MCAST
            | IFLA_INET6_CACHEINFO
            | IFLA_INET6_ICMP6STATS
                if !payload.is_empty() && payload.len() % 4 == 0 => {}
            IFLA_INET6_TOKEN if payload.len() == 16 => {}
            IFLA_INET6_ADDR_GEN_MODE => {
                address_generation_mode = Some(read_exact_u8(payload)?);
            }
            _ => return Err(NetworkError::NotPristine),
        }
    }
    if ipv4_seen && address_generation_mode == Some(expected_addrgen_mode) {
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
        DumpKind::Qdisc => MAX_QDISCS,
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

fn read_exact_i32(bytes: &[u8]) -> Result<i32, NetworkError> {
    if bytes.len() == 4 {
        read_i32(bytes, 0)
    } else {
        Err(NetworkError::NotPristine)
    }
}

fn read_exact_ethernet_address(bytes: &[u8]) -> Result<[u8; ETHERNET_ADDRESS_BYTES], NetworkError> {
    bytes.try_into().map_err(|_| NetworkError::NotPristine)
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
    use std::{
        cell::Cell,
        env,
        io::Read,
        process::{Command, Stdio},
    };

    use nix::sched::{CloneFlags, setns};

    use super::*;

    const LIVE_COLLECTOR_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_COLLECTOR_CHILD";
    const LIVE_MUTATION_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_MUTATION_CHILD";
    const LIVE_VETH_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_VETH_CHILD";
    const LIVE_IPV4_ROLLBACK_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_IPV4_ROLLBACK_CHILD";
    const LIVE_LINK_ACTIVATION_CHILD_ENV: &str = "VOLPAROSSA_NETWORK_LINK_ACTIVATION_CHILD";
    const TEST_SEQUENCE: u32 = 7;
    const TEST_PORT: u32 = 41;

    #[test]
    fn network_lineage_failure_returns_authority_without_substitution() {
        let authority = Box::new([0x5a_u8; 32]);
        let expected = std::ptr::from_ref::<[u8; 32]>(authority.as_ref());
        let failure = NetworkLineageFailure {
            source: NetworkError::Inconsistent,
            authority,
        };
        let (source, authority) = failure.into_parts();
        assert!(matches!(source, NetworkError::Inconsistent));
        assert_eq!(std::ptr::from_ref::<[u8; 32]>(authority.as_ref()), expected);
    }

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
    fn exact_observation_retry_accepts_only_not_pristine_convergence() {
        let attempts = Cell::new(0_u8);
        let (_, observed) = retry_exact_observation_before(
            Deadline::after(Duration::from_millis(100)).expect("retry deadline"),
            || {
                attempts.set(attempts.get() + 1);
                Ok(attempts.get())
            },
            |state| {
                if *state < 3 {
                    Err(NetworkError::NotPristine)
                } else {
                    Ok(*state)
                }
            },
        )
        .expect("bounded convergence");
        assert_eq!(attempts.get(), 3);
        assert_eq!(observed, 3);

        let inconsistent_attempts = Cell::new(0_u8);
        assert!(matches!(
            retry_exact_observation_before(
                Deadline::after(Duration::from_millis(100)).expect("fail-closed deadline"),
                || {
                    inconsistent_attempts.set(inconsistent_attempts.get() + 1);
                    Ok(())
                },
                |()| Err::<(), _>(NetworkError::Inconsistent),
            ),
            Err(NetworkError::Inconsistent)
        ));
        assert_eq!(inconsistent_attempts.get(), 1);
    }

    #[test]
    fn fixed_veth_expectations_are_bounded_and_unambiguous() {
        let first = expected_pair("vpa01234567", 2, 2, 11);
        let second = expected_pair("vpb01234567", 3, 2, 12);
        validate_parent_expectations([&first, &second]).expect("distinct parent identities");
        assert_eq!(first.parent_name, b"vpa01234567");
        assert_eq!(first.parent_ifindex, 2);
        assert_eq!(first.endpoint_ifindex, 2);

        for (name, parent, endpoint) in [
            ("", 2, 2),
            ("lo", 2, 2),
            ("eth0", 2, 2),
            ("abcdefghijklmnop", 2, 2),
            ("vpa01234567", 1, 2),
            ("vpa01234567", 2, 1),
        ] {
            assert!(matches!(
                ExpectedVethPair::new_with_namespace_identity(
                    name,
                    parent,
                    endpoint,
                    test_namespace_identity(11),
                ),
                Err(NetworkError::InvalidVethExpectation)
            ));
        }
        let duplicate_name = expected_pair("vpa01234567", 4, 3, 13);
        let duplicate_index = expected_pair("vpc01234567", 2, 3, 14);
        assert!(matches!(
            validate_parent_expectations([&first, &duplicate_name]),
            Err(NetworkError::InvalidVethExpectation)
        ));
        assert!(matches!(
            validate_parent_expectations([&first, &duplicate_index]),
            Err(NetworkError::InvalidVethExpectation)
        ));
    }

    #[test]
    fn endpoint_namespace_identity_is_fresh_and_exact() {
        let identity = current_network_namespace_identity().expect("current network nsfs identity");
        require_current_network_namespace(identity).expect("same network namespace");
        let swapped = NetworkNamespaceIdentity {
            device: identity.device,
            inode: identity.inode.checked_add(1).expect("nonzero test inode"),
        };
        assert!(matches!(
            require_current_network_namespace(swapped),
            Err(NetworkError::Inconsistent)
        ));
    }

    #[test]
    fn exact_veth_parent_and_endpoint_deltas_are_accepted() {
        let pristine = pristine_snapshot();
        let first = expected_pair("vpa01234567", 2, 2, 11);
        let second = expected_pair("vpb01234567", 3, 2, 12);
        let mut parent = pristine.clone();
        parent.links.extend([
            veth_link_payload(
                &first.parent_name,
                first.parent_ifindex,
                first.endpoint_ifindex,
                0,
                [0x02, 1, 2, 3, 4, 5],
            ),
            veth_link_payload(
                &second.parent_name,
                second.parent_ifindex,
                second.endpoint_ifindex,
                1,
                [0x06, 1, 2, 3, 4, 5],
            ),
        ]);
        let parent_links =
            verify_exact_parent_veth_snapshot_delta(&pristine, &parent, [&first, &second])
                .expect("exact parent delta");

        let mut endpoint_a = pristine.clone();
        endpoint_a.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            first.endpoint_ifindex,
            first.parent_ifindex,
            0,
            [0x0a, 1, 2, 3, 4, 5],
        ));
        let endpoint_a = verify_exact_endpoint_veth_snapshot_delta(&pristine, &endpoint_a, &first)
            .expect("exact A delta");
        let mut endpoint_b = pristine.clone();
        endpoint_b.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            second.endpoint_ifindex,
            second.parent_ifindex,
            0,
            [0x0e, 1, 2, 3, 4, 5],
        ));
        let endpoint_b = verify_exact_endpoint_veth_snapshot_delta(&pristine, &endpoint_b, &second)
            .expect("exact B delta");
        let namespace_a = NetworkNamespaceIdentity {
            device: 7,
            inode: 11,
        };
        let namespace_b = NetworkNamespaceIdentity {
            device: 7,
            inode: 12,
        };
        verify_veth_observation_relations(
            &parent_links,
            [&endpoint_a, &endpoint_b],
            [namespace_a, namespace_b],
        )
        .expect("owner-target relations and distinct endpoint identities");
        assert!(matches!(
            verify_veth_observation_relations(
                &parent_links,
                [&endpoint_b, &endpoint_a],
                [namespace_b, namespace_a],
            ),
            Err(NetworkError::Inconsistent)
        ));
        assert!(matches!(
            verify_veth_observation_relations(
                &parent_links,
                [&endpoint_a, &endpoint_b],
                [namespace_a, namespace_a],
            ),
            Err(NetworkError::NotPristine)
        ));

        let mut duplicate_parent_netnsid = parent.clone();
        duplicate_parent_netnsid.links[2] = replace_link_attribute(
            &duplicate_parent_netnsid.links[2],
            IFLA_LINK_NETNSID,
            &0_i32.to_ne_bytes(),
        );
        assert!(matches!(
            verify_exact_parent_veth_snapshot_delta(
                &pristine,
                &duplicate_parent_netnsid,
                [&first, &second],
            ),
            Err(NetworkError::NotPristine)
        ));
    }

    #[test]
    fn fixed_ipv4_expectations_and_exact_down_link_deltas_are_accepted() {
        let pristine = pristine_snapshot();
        let first = expected_pair("vpa01234567", 2, 2, 11);
        let second = expected_pair("vpb01234567", 3, 2, 12);
        let parent_a = expected_ipv4("vpa01234567", 2, [10, 241, 1, 1]);
        let endpoint_a = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let parent_b = expected_ipv4("vpb01234567", 3, [10, 241, 2, 1]);
        let endpoint_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);
        validate_parent_ipv4_expectations([&first, &second], [&parent_a, &parent_b])
            .expect("fixed parent address binding");

        let mut parent = pristine.clone();
        parent.links.extend([
            veth_link_payload(
                &first.parent_name,
                first.parent_ifindex,
                first.endpoint_ifindex,
                0,
                [0x02, 1, 2, 3, 4, 5],
            ),
            veth_link_payload(
                &second.parent_name,
                second.parent_ifindex,
                second.endpoint_ifindex,
                1,
                [0x06, 1, 2, 3, 4, 5],
            ),
        ]);
        add_fixed_ipv4_fixture(&mut parent, &parent_a);
        add_fixed_ipv4_fixture(&mut parent, &parent_b);
        let parent_links =
            verify_exact_parent_veth_links_only(&pristine, &parent, [&first, &second])
                .expect("exact addressed parent links");
        verify_exact_fixed_ipv4_objects(&parent, &[&parent_a, &parent_b])
            .expect("exact addressed parent objects");

        let mut active_a = pristine.clone();
        active_a.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            first.endpoint_ifindex,
            first.parent_ifindex,
            0,
            [0x0a, 1, 2, 3, 4, 5],
        ));
        add_fixed_ipv4_fixture(&mut active_a, &endpoint_a);
        let alpha_endpoint_link =
            verify_exact_endpoint_veth_links_only(&pristine, &active_a, &first)
                .expect("exact addressed A link");
        verify_exact_fixed_ipv4_objects(&active_a, &[&endpoint_a])
            .expect("exact addressed A objects");

        let mut active_b = pristine.clone();
        active_b.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            second.endpoint_ifindex,
            second.parent_ifindex,
            0,
            [0x0e, 1, 2, 3, 4, 5],
        ));
        add_fixed_ipv4_fixture(&mut active_b, &endpoint_b);
        let omega_endpoint_link =
            verify_exact_endpoint_veth_links_only(&pristine, &active_b, &second)
                .expect("exact addressed B link");
        verify_exact_fixed_ipv4_objects(&active_b, &[&endpoint_b])
            .expect("exact addressed B objects");

        verify_veth_observation_relations(
            &parent_links,
            [&alpha_endpoint_link, &omega_endpoint_link],
            [test_namespace_identity(11), test_namespace_identity(12)],
        )
        .expect("addressed pair relations");
    }

    #[test]
    fn addrgen_none_barrier_deltas_are_accepted() {
        let pristine = pristine_snapshot();
        let first = expected_pair("vpa01234567", 2, 2, 11);
        let second = expected_pair("vpb01234567", 3, 2, 12);
        let parent_a = expected_ipv4("vpa01234567", 2, [10, 241, 1, 1]);
        let endpoint_a = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let parent_b = expected_ipv4("vpb01234567", 3, [10, 241, 2, 1]);
        let endpoint_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);

        let mut parent_barrier = pristine.clone();
        parent_barrier.links.extend([
            veth_link_payload_with_profile(
                &first.parent_name,
                first.parent_ifindex,
                first.endpoint_ifindex,
                0,
                [0x02, 1, 2, 3, 4, 5],
                VethLinkProfile::DownAddrgenNone,
            ),
            veth_link_payload_with_profile(
                &second.parent_name,
                second.parent_ifindex,
                second.endpoint_ifindex,
                1,
                [0x06, 1, 2, 3, 4, 5],
                VethLinkProfile::DownAddrgenNone,
            ),
        ]);
        add_fixed_ipv4_fixture(&mut parent_barrier, &parent_a);
        add_fixed_ipv4_fixture(&mut parent_barrier, &parent_b);
        let barrier_parent = verify_exact_parent_ipv4_addrgen_none_snapshot_delta(
            &pristine,
            &parent_barrier,
            [&first, &second],
            [&parent_a, &parent_b],
        )
        .expect("exact parent addrgen barrier");

        let mut first_endpoint_barrier = pristine.clone();
        first_endpoint_barrier
            .links
            .push(veth_link_payload_with_profile(
                VETH_ENDPOINT_NAME,
                first.endpoint_ifindex,
                first.parent_ifindex,
                0,
                [0x0a, 1, 2, 3, 4, 5],
                VethLinkProfile::DownAddrgenNone,
            ));
        add_fixed_ipv4_fixture(&mut first_endpoint_barrier, &endpoint_a);
        let barrier_a = verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
            &pristine,
            &first_endpoint_barrier,
            &first,
            &endpoint_a,
        )
        .expect("exact A addrgen barrier");

        let mut second_endpoint_barrier = pristine.clone();
        second_endpoint_barrier
            .links
            .push(veth_link_payload_with_profile(
                VETH_ENDPOINT_NAME,
                second.endpoint_ifindex,
                second.parent_ifindex,
                0,
                [0x0e, 1, 2, 3, 4, 5],
                VethLinkProfile::DownAddrgenNone,
            ));
        add_fixed_ipv4_fixture(&mut second_endpoint_barrier, &endpoint_b);
        let barrier_b = verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
            &pristine,
            &second_endpoint_barrier,
            &second,
            &endpoint_b,
        )
        .expect("exact B addrgen barrier");
        verify_veth_observation_relations(
            &barrier_parent,
            [&barrier_a, &barrier_b],
            [test_namespace_identity(11), test_namespace_identity(12)],
        )
        .expect("barrier pair relations");
    }

    #[test]
    fn fully_activated_deltas_are_accepted() {
        let pristine = pristine_snapshot();
        let first = expected_pair("vpa01234567", 2, 2, 11);
        let second = expected_pair("vpb01234567", 3, 2, 12);
        let parent_a = expected_ipv4("vpa01234567", 2, [10, 241, 1, 1]);
        let endpoint_a = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let parent_b = expected_ipv4("vpb01234567", 3, [10, 241, 2, 1]);
        let endpoint_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);

        let mut parent_active = pristine.clone();
        parent_active.links.extend([
            veth_link_payload_with_profile(
                &first.parent_name,
                first.parent_ifindex,
                first.endpoint_ifindex,
                0,
                [0x02, 1, 2, 3, 4, 5],
                VethLinkProfile::ActivatedAddrgenNone,
            ),
            veth_link_payload_with_profile(
                &second.parent_name,
                second.parent_ifindex,
                second.endpoint_ifindex,
                1,
                [0x06, 1, 2, 3, 4, 5],
                VethLinkProfile::ActivatedAddrgenNone,
            ),
        ]);
        add_activated_ipv4_fixture(&mut parent_active, &parent_a);
        add_activated_ipv4_fixture(&mut parent_active, &parent_b);
        let active_parent = verify_exact_parent_activated_ipv4_snapshot_delta(
            &pristine,
            &parent_active,
            [&first, &second],
            [&parent_a, &parent_b],
        )
        .expect("exact activated parent");

        let mut first_endpoint_active = pristine.clone();
        first_endpoint_active
            .links
            .push(veth_link_payload_with_profile(
                VETH_ENDPOINT_NAME,
                first.endpoint_ifindex,
                first.parent_ifindex,
                0,
                [0x0a, 1, 2, 3, 4, 5],
                VethLinkProfile::ActivatedAddrgenNone,
            ));
        add_activated_ipv4_fixture(&mut first_endpoint_active, &endpoint_a);
        let active_a = verify_exact_endpoint_activated_ipv4_snapshot_delta(
            &pristine,
            &first_endpoint_active,
            &first,
            &endpoint_a,
        )
        .expect("exact activated A");

        let mut second_endpoint_active = pristine.clone();
        second_endpoint_active
            .links
            .push(veth_link_payload_with_profile(
                VETH_ENDPOINT_NAME,
                second.endpoint_ifindex,
                second.parent_ifindex,
                0,
                [0x0e, 1, 2, 3, 4, 5],
                VethLinkProfile::ActivatedAddrgenNone,
            ));
        add_activated_ipv4_fixture(&mut second_endpoint_active, &endpoint_b);
        let active_b = verify_exact_endpoint_activated_ipv4_snapshot_delta(
            &pristine,
            &second_endpoint_active,
            &second,
            &endpoint_b,
        )
        .expect("exact activated B");
        verify_veth_observation_relations(
            &active_parent,
            [&active_a, &active_b],
            [test_namespace_identity(11), test_namespace_identity(12)],
        )
        .expect("activated pair relations");
    }

    #[test]
    fn fixed_endpoint_route_expectations_bind_namespace_lineage() {
        let pair_a = expected_pair("vpa01234567", 2, 2, 11);
        let pair_b = expected_pair("vpb01234567", 3, 2, 12);
        let address_a = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let address_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);
        let route_a =
            expected_ipv4_endpoint_route(&pair_a, &address_a, test_namespace_identity(11))
                .expect("fixed A route");
        let route_b =
            expected_ipv4_endpoint_route(&pair_b, &address_b, test_namespace_identity(12))
                .expect("fixed B route");

        assert_eq!(route_a.ifindex(), route_b.ifindex());
        assert_eq!(route_a.destination(), [10, 241, 2, 2]);
        assert_eq!(route_a.gateway(), [10, 241, 1, 1]);
        assert_eq!(route_b.destination(), [10, 241, 1, 2]);
        assert_eq!(route_b.gateway(), [10, 241, 2, 1]);
        assert_ne!(route_a, route_b);

        let mut swapped_namespace = route_a.clone();
        swapped_namespace.namespace = route_b.namespace;
        assert!(matches!(
            require_ipv4_endpoint_route_expectation(
                &swapped_namespace,
                &pair_a,
                &address_a,
                test_namespace_identity(11),
            ),
            Err(NetworkError::InvalidIpv4RouteExpectation)
        ));
        assert!(matches!(
            expected_ipv4_endpoint_route(&pair_a, &address_a, test_namespace_identity(12)),
            Err(NetworkError::InvalidIpv4RouteExpectation)
        ));
    }

    #[test]
    fn exact_fixed_endpoint_route_deltas_are_accepted() {
        let (_pristine_a, pair_a, address_a, active_a) = valid_activated_endpoint_fixture();
        let expected_a =
            expected_ipv4_endpoint_route(&pair_a, &address_a, test_namespace_identity(11))
                .expect("fixed A route");
        let mut routed_a = active_a.clone();
        routed_a.routes.push(ipv4_endpoint_route_payload(
            expected_a.ifindex(),
            expected_a.destination(),
            expected_a.gateway(),
        ));
        verify_exact_endpoint_ipv4_route_snapshot_delta(&active_a, &routed_a, &expected_a)
            .expect("exact routed A delta");

        let active_b = pristine_snapshot();
        let pair_b = expected_pair("vpb01234567", 3, 2, 12);
        let address_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);
        let mut activated_b = active_b.clone();
        activated_b.links.push(veth_link_payload_with_profile(
            VETH_ENDPOINT_NAME,
            pair_b.endpoint_ifindex,
            pair_b.parent_ifindex,
            0,
            [0x06, 1, 2, 3, 4, 5],
            VethLinkProfile::ActivatedAddrgenNone,
        ));
        add_activated_ipv4_fixture(&mut activated_b, &address_b);
        let expected_b =
            expected_ipv4_endpoint_route(&pair_b, &address_b, test_namespace_identity(12))
                .expect("fixed B route");
        let mut routed_b = activated_b.clone();
        routed_b.routes.push(ipv4_endpoint_route_payload(
            expected_b.ifindex(),
            expected_b.destination(),
            expected_b.gateway(),
        ));
        verify_exact_endpoint_ipv4_route_snapshot_delta(&activated_b, &routed_b, &expected_b)
            .expect("exact routed B delta");
    }

    #[test]
    fn same_destination_nonexact_route_is_reported_as_conflicting() {
        let (_pristine, pair, address, active) = valid_activated_endpoint_fixture();
        let expected = expected_ipv4_endpoint_route(&pair, &address, test_namespace_identity(11))
            .expect("fixed route");
        let mut routed = active.clone();
        routed.routes.push(ipv4_endpoint_route_payload(
            expected.ifindex(),
            expected.destination(),
            [10, 241, 1, 2],
        ));
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &routed, &expected),
            Err(NetworkError::ConflictingIpv4EndpointRoute)
        ));

        let mut wrong_destination = active.clone();
        wrong_destination.routes.push(ipv4_endpoint_route_payload(
            expected.ifindex(),
            [10, 241, 2, 1],
            expected.gateway(),
        ));
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &wrong_destination, &expected,),
            Err(NetworkError::Inconsistent)
        ));
    }

    #[test]
    fn fixed_endpoint_route_delta_rejects_header_and_attribute_ambiguity() {
        let (_pristine, pair, address, active) = valid_activated_endpoint_fixture();
        let expected = expected_ipv4_endpoint_route(&pair, &address, test_namespace_identity(11))
            .expect("fixed route");
        let valid_route = ipv4_endpoint_route_payload(
            expected.ifindex(),
            expected.destination(),
            expected.gateway(),
        );
        let mut variants = Vec::new();
        for (offset, replacement) in [
            (0, AF_INET6),
            (1, 31),
            (2, 1),
            (3, 1),
            (4, u8::try_from(RT_TABLE_LOCAL).expect("local table byte")),
            (5, RTPROT_KERNEL),
            (6, RT_SCOPE_LINK),
            (7, RTN_LOCAL),
            (8, 1),
        ] {
            let mut route = valid_route.clone();
            route[offset] = replacement;
            variants.push(route);
        }
        for kind in [RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_TABLE] {
            variants.push(without_record_attribute(&valid_route, RTMSG_LEN, kind));
        }
        variants.push(replace_record_attribute(
            &valid_route,
            RTMSG_LEN,
            RTA_DST,
            &[10, 241, 2, 1],
        ));
        variants.push(replace_record_attribute(
            &valid_route,
            RTMSG_LEN,
            RTA_GATEWAY,
            &[10, 241, 1, 2],
        ));
        variants.push(replace_record_attribute(
            &valid_route,
            RTMSG_LEN,
            RTA_OIF,
            &3_u32.to_ne_bytes(),
        ));
        variants.push(replace_record_attribute(
            &valid_route,
            RTMSG_LEN,
            RTA_TABLE,
            &RT_TABLE_LOCAL.to_ne_bytes(),
        ));
        for (kind, value) in [
            (RTA_PRIORITY, 7_u32.to_ne_bytes().to_vec()),
            (RTA_PREFSRC, [10, 241, 1, 2].to_vec()),
            (RTA_TABLE, RT_TABLE_MAIN.to_ne_bytes().to_vec()),
            (9, vec![0; 8]),
            (99, vec![1]),
        ] {
            let mut route = valid_route.clone();
            route.extend(attribute(kind, &value));
            variants.push(route);
        }
        let mut duplicate_destination = valid_route.clone();
        duplicate_destination.extend(attribute(RTA_DST, &expected.destination()));
        variants.push(duplicate_destination);
        let mut flagged_destination = valid_route.clone();
        flagged_destination = replace_record_attribute_with_raw_kind(
            &flagged_destination,
            RTMSG_LEN,
            RTA_DST,
            RTA_DST | NLA_F_NESTED,
            &expected.destination(),
        );
        variants.push(flagged_destination);

        for route in variants {
            let mut routed = active.clone();
            routed.routes.push(route);
            assert!(
                verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &routed, &expected)
                    .is_err()
            );
        }
    }

    #[test]
    fn fixed_endpoint_route_delta_rejects_every_extra_or_changed_object() {
        let (_pristine, pair, address, active) = valid_activated_endpoint_fixture();
        let expected = expected_ipv4_endpoint_route(&pair, &address, test_namespace_identity(11))
            .expect("fixed route");
        let mut routed = active.clone();
        routed.routes.push(ipv4_endpoint_route_payload(
            expected.ifindex(),
            expected.destination(),
            expected.gateway(),
        ));

        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &active, &expected),
            Err(NetworkError::NotPristine)
        ));
        let mut second_route = routed.clone();
        second_route.routes.push(ipv4_endpoint_route_payload(
            expected.ifindex(),
            [10, 241, 2, 1],
            expected.gateway(),
        ));
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &second_route, &expected),
            Err(NetworkError::Inconsistent)
        ));
        let mut same_destination_sibling = routed.clone();
        same_destination_sibling
            .routes
            .push(ipv4_endpoint_route_payload(
                expected.ifindex(),
                expected.destination(),
                [10, 241, 1, 2],
            ));
        let sibling_additions = require_route_additions_preserve_baseline(
            &active.routes,
            &same_destination_sibling.routes,
        )
        .expect("baseline-preserving sibling additions");
        assert_eq!(sibling_additions.len(), 2);
        assert!(
            sibling_additions
                .iter()
                .all(|route| route_has_ipv4_destination(route, expected.destination())),
            "both sibling fixtures must target the expected destination",
        );
        let sibling_result = verify_exact_endpoint_ipv4_route_snapshot_delta(
            &active,
            &same_destination_sibling,
            &expected,
        );
        assert!(
            matches!(
                sibling_result,
                Err(NetworkError::ConflictingIpv4EndpointRoute)
            ),
            "same-destination sibling result: {sibling_result:?}",
        );
        let mut changed_baseline_route = routed.clone();
        changed_baseline_route
            .routes
            .iter_mut()
            .find(|route| route[0] == AF_INET && route[7] == RTN_BROADCAST)
            .expect("broadcast route")[6] = RT_SCOPE_UNIVERSE;
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(
                &active,
                &changed_baseline_route,
                &expected,
            ),
            Err(NetworkError::Inconsistent)
        ));
        let mut changed_link = routed.clone();
        changed_link.links[1][8] ^= 1;
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &changed_link, &expected),
            Err(NetworkError::Inconsistent)
        ));
        let mut neighbour = routed;
        neighbour.neighbours.push(vec![0; NDMSG_LEN]);
        assert!(matches!(
            verify_exact_endpoint_ipv4_route_snapshot_delta(&active, &neighbour, &expected),
            Err(NetworkError::Inconsistent)
        ));
    }

    #[test]
    fn addrgen_none_barrier_rejects_every_state_or_object_substitution() {
        let pristine = pristine_snapshot();
        let pair = expected_pair("vpa01234567", 2, 2, 11);
        let address = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let valid_link = veth_link_payload_with_profile(
            VETH_ENDPOINT_NAME,
            pair.endpoint_ifindex,
            pair.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
            VethLinkProfile::DownAddrgenNone,
        );
        let mut valid = pristine.clone();
        valid.links.push(valid_link.clone());
        add_fixed_ipv4_fixture(&mut valid, &address);
        verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(&pristine, &valid, &pair, &address)
            .expect("valid barrier");

        let mut variants = Vec::new();
        let mut eui64 = valid.clone();
        eui64.links[1] = veth_link_payload(
            VETH_ENDPOINT_NAME,
            pair.endpoint_ifindex,
            pair.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
        );
        variants.push(eui64);
        let mut activated = valid.clone();
        activated.links[1] = veth_link_payload_with_profile(
            VETH_ENDPOINT_NAME,
            pair.endpoint_ifindex,
            pair.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
            VethLinkProfile::ActivatedAddrgenNone,
        );
        variants.push(activated);
        let mut qdisc = valid.clone();
        qdisc.qdiscs.push(noqueue_qdisc_payload(2));
        variants.push(qdisc);
        let mut connected = valid.clone();
        connected
            .routes
            .push(ipv4_connected_route_payload(2, address.address));
        variants.push(connected);
        let mut ipv6_route = valid.clone();
        ipv6_route.routes.push(ipv6_multicast_route_payload(2));
        variants.push(ipv6_route);
        let mut ipv6_address = valid.clone();
        let mut record = vec![AF_INET6, 64, 0, RT_SCOPE_UNIVERSE];
        record.extend_from_slice(&2_u32.to_ne_bytes());
        ipv6_address.addresses.push(record);
        variants.push(ipv6_address);

        for variant in variants {
            assert!(matches!(
                verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
                    &pristine, &variant, &pair, &address,
                ),
                Err(NetworkError::NotPristine | NetworkError::Inconsistent)
            ));
        }
    }

    #[test]
    fn activated_delta_rejects_link_and_qdisc_ambiguity() {
        let (pristine, pair, address, valid) = valid_activated_endpoint_fixture();
        verify_exact_endpoint_activated_ipv4_snapshot_delta(&pristine, &valid, &pair, &address)
            .expect("valid activation");

        let mut variants = Vec::new();
        let mut down = valid.clone();
        down.links[1] = veth_link_payload_with_profile(
            VETH_ENDPOINT_NAME,
            pair.endpoint_ifindex,
            pair.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
            VethLinkProfile::DownAddrgenNone,
        );
        variants.push(down);
        let mut missing_running = valid.clone();
        let flags = read_u32(&missing_running.links[1], 8).expect("active flags") & !IFF_RUNNING;
        missing_running.links[1][8..12].copy_from_slice(&flags.to_ne_bytes());
        variants.push(missing_running);
        let mut eui64 = valid.clone();
        let mut address_families = attribute(u16::from(AF_INET), &[]);
        let ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[IN6_ADDR_GEN_MODE_EUI64]);
        address_families.extend(attribute(u16::from(AF_INET6), &ipv6));
        eui64.links[1] = replace_link_attribute(&eui64.links[1], IFLA_AF_SPEC, &address_families);
        variants.push(eui64);
        for (kind, replacement) in [
            (IFLA_CARRIER, vec![0]),
            (IFLA_CARRIER_CHANGES, 3_u32.to_ne_bytes().to_vec()),
            (IFLA_CARRIER_UP_COUNT, 0_u32.to_ne_bytes().to_vec()),
            (IFLA_CARRIER_DOWN_COUNT, 0_u32.to_ne_bytes().to_vec()),
        ] {
            let mut wrong = valid.clone();
            wrong.links[1] = replace_link_attribute(&wrong.links[1], kind, &replacement);
            variants.push(wrong);
            let mut missing = valid.clone();
            missing.links[1] = without_link_attribute(&missing.links[1], kind);
            variants.push(missing);
        }
        let mut missing_qdisc = valid.clone();
        missing_qdisc.qdiscs.clear();
        variants.push(missing_qdisc);
        let mut wrong_qdisc = valid.clone();
        wrong_qdisc.qdiscs[0] = qdisc_payload(2, b"clsact\0");
        variants.push(wrong_qdisc);
        let mut wrong_qdisc_info = valid.clone();
        wrong_qdisc_info.qdiscs[0][16..20].copy_from_slice(&1_u32.to_ne_bytes());
        variants.push(wrong_qdisc_info);
        let mut unknown_qdisc_attribute = valid.clone();
        unknown_qdisc_attribute.qdiscs[0].extend(attribute(99, &[1]));
        variants.push(unknown_qdisc_attribute);

        for variant in variants {
            assert!(
                verify_exact_endpoint_activated_ipv4_snapshot_delta(
                    &pristine, &variant, &pair, &address,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn activated_delta_rejects_route_and_policy_ambiguity() {
        let (pristine, pair, address, valid) = valid_activated_endpoint_fixture();
        let mut variants = Vec::new();
        for route_index in 0..valid.routes.len() {
            let mut missing = valid.clone();
            missing.routes.remove(route_index);
            variants.push(missing);
        }
        let mut wrong_route_scope = valid.clone();
        let connected = wrong_route_scope
            .routes
            .iter_mut()
            .find(|route| route[0] == AF_INET && route[7] == RTN_UNICAST)
            .expect("connected fixture");
        connected[6] = RT_SCOPE_UNIVERSE;
        variants.push(wrong_route_scope);
        let mut base_broadcast_substitution = valid.clone();
        let broadcast = base_broadcast_substitution
            .routes
            .iter_mut()
            .find(|route| route[0] == AF_INET && route[7] == RTN_BROADCAST)
            .expect("broadcast fixture");
        *broadcast = replace_record_attribute(broadcast, RTMSG_LEN, RTA_DST, &[10, 241, 1, 0]);
        variants.push(base_broadcast_substitution);
        let mut route_flags = valid.clone();
        route_flags
            .routes
            .iter_mut()
            .find(|route| route[0] == AF_INET6)
            .expect("IPv6 multicast fixture")[8] = 1;
        variants.push(route_flags);
        let mut unknown_route_attribute = valid.clone();
        unknown_route_attribute
            .routes
            .iter_mut()
            .find(|route| route[0] == AF_INET6)
            .expect("IPv6 multicast fixture")
            .extend(attribute(99, &[1]));
        variants.push(unknown_route_attribute);
        let mut ipv6_address = valid.clone();
        let mut record = vec![AF_INET6, 64, 0, RT_SCOPE_UNIVERSE];
        record.extend_from_slice(&2_u32.to_ne_bytes());
        ipv6_address.addresses.push(record);
        variants.push(ipv6_address);
        let mut neighbour = valid.clone();
        neighbour.neighbours.push(vec![0; NDMSG_LEN]);
        variants.push(neighbour);
        let mut changed_rules = valid.clone();
        changed_rules.rules_v4.pop();
        variants.push(changed_rules);

        for variant in variants {
            assert!(
                verify_exact_endpoint_activated_ipv4_snapshot_delta(
                    &pristine, &variant, &pair, &address,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn fixed_ipv4_proof_rejects_wrong_or_additional_objects() {
        let expected = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let mut valid = pristine_snapshot();
        add_fixed_ipv4_fixture(&mut valid, &expected);
        verify_exact_fixed_ipv4_objects(&valid, &[&expected]).expect("exact fixed address");

        let mut variants = Vec::new();
        let mut extra_address = valid.clone();
        extra_address
            .addresses
            .push(ipv4_address_payload("eth0", 2, [10, 241, 2, 2]));
        variants.push(extra_address);
        let mut extra_route = valid.clone();
        extra_route
            .routes
            .push(ipv4_local_route_payload(2, [10, 241, 2, 2]));
        variants.push(extra_route);
        let mut missing_route = valid.clone();
        missing_route.routes.clear();
        variants.push(missing_route);
        let mut wrong_index = valid.clone();
        wrong_index.addresses[0][4..8].copy_from_slice(&3_u32.to_ne_bytes());
        variants.push(wrong_index);
        let mut wrong_prefix = valid.clone();
        wrong_prefix.addresses[0][1] = 32;
        variants.push(wrong_prefix);
        let mut wrong_route_type = valid.clone();
        wrong_route_type.routes[0][7] = 1;
        variants.push(wrong_route_type);
        let mut unknown_address_attribute = valid.clone();
        unknown_address_attribute.addresses[0].extend(attribute(99, &[0]));
        variants.push(unknown_address_attribute);
        let mut unknown_route_attribute = valid.clone();
        unknown_route_attribute.routes[0].extend(attribute(99, &[0]));
        variants.push(unknown_route_attribute);

        for variant in variants {
            assert!(verify_exact_fixed_ipv4_objects(&variant, &[&expected]).is_err());
        }
    }

    #[test]
    fn fixed_ipv4_expectation_rejects_non_spec_or_wrong_side_identity() {
        for (name, ifindex, address) in [
            ("", 2, [10, 241, 1, 1]),
            ("lo", 2, [10, 241, 1, 1]),
            ("eth0", 2, [10, 241, 1, 1]),
            ("vpa01234567", 2, [10, 241, 1, 2]),
            ("eth0", 1, [10, 241, 1, 2]),
            ("eth0", 2, [192, 0, 2, 1]),
        ] {
            assert!(matches!(
                ExpectedIpv4Address::new(name, ifindex, address),
                Err(NetworkError::InvalidIpv4Expectation)
            ));
        }

        let pair_a = expected_pair("vpa01234567", 2, 2, 11);
        let pair_b = expected_pair("vpb01234567", 3, 2, 12);
        let address_a = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let address_b = expected_ipv4("eth0", 2, [10, 241, 2, 2]);
        validate_endpoint_ipv4_expectation(&pair_a, &address_a).expect("endpoint A binding");
        validate_endpoint_ipv4_expectation(&pair_b, &address_b).expect("endpoint B binding");
        assert!(matches!(
            validate_endpoint_ipv4_expectation(&pair_a, &address_b),
            Err(NetworkError::InvalidIpv4Expectation)
        ));
        assert!(matches!(
            validate_endpoint_ipv4_expectation(&pair_b, &address_a),
            Err(NetworkError::InvalidIpv4Expectation)
        ));
    }

    #[test]
    fn exact_veth_profile_rejects_identity_state_and_relationship_changes() {
        let pristine = pristine_snapshot();
        let expected = expected_pair("vpa01234567", 2, 2, 11);
        let valid = veth_link_payload(
            VETH_ENDPOINT_NAME,
            expected.endpoint_ifindex,
            expected.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
        );
        let mut variants = Vec::new();
        for (kind, replacement) in [
            (IFLA_IFNAME, b"wrong\0".to_vec()),
            (IFLA_LINK, 99_u32.to_ne_bytes().to_vec()),
            (IFLA_MTU, 1_400_u32.to_ne_bytes().to_vec()),
            (IFLA_TXQLEN, 0_u32.to_ne_bytes().to_vec()),
            (IFLA_NUM_TX_QUEUES, 2_u32.to_ne_bytes().to_vec()),
            (IFLA_NUM_RX_QUEUES, 2_u32.to_ne_bytes().to_vec()),
            (IFLA_OPERSTATE, vec![6]),
            (IFLA_ADDRESS, vec![0; ETHERNET_ADDRESS_BYTES]),
            (IFLA_PERM_ADDRESS, vec![0x06, 1, 2, 3, 4, 5]),
        ] {
            variants.push(replace_link_attribute(&valid, kind, &replacement));
        }
        let mut wrong_flags = valid.clone();
        wrong_flags[8..12].copy_from_slice(&(VETH_FLAGS | 1).to_ne_bytes());
        variants.push(wrong_flags);
        let mut wrong_type = valid.clone();
        wrong_type[2..4].copy_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
        variants.push(wrong_type);
        for kind in [IFLA_MASTER, IFLA_IFALIAS, IFLA_ALT_IFNAME] {
            let mut variant = valid.clone();
            variant.extend(attribute(kind, &1_u32.to_ne_bytes()));
            variants.push(variant);
        }
        let mut attached_xdp = valid.clone();
        attached_xdp.extend(attribute(IFLA_XDP, &attribute(IFLA_XDP_ATTACHED, &[1])));
        variants.push(attached_xdp);
        let mut unknown_attribute = valid.clone();
        unknown_attribute.extend(attribute(99, &[1]));
        variants.push(unknown_attribute);

        for payload in variants {
            let mut active = pristine.clone();
            active.links.push(payload);
            assert!(matches!(
                verify_exact_endpoint_veth_snapshot_delta(&pristine, &active, &expected),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn exact_veth_profile_rejects_ambiguous_queues_and_nonzero_fresh_telemetry() {
        let pristine = pristine_snapshot();
        let expected = expected_pair("vpa01234567", 2, 2, 11);
        let valid = veth_link_payload(
            VETH_ENDPOINT_NAME,
            expected.endpoint_ifindex,
            expected.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
        );
        let mut variants = Vec::new();
        for kind in [IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES] {
            variants.push(without_link_attribute(&valid, kind));
            variants.push(replace_link_attribute_with_raw_kind(
                &valid,
                kind,
                kind | NLA_F_NET_BYTEORDER,
                &VETH_QUEUE_COUNT.to_ne_bytes(),
            ));
            let mut duplicate = valid.clone();
            duplicate.extend(attribute(kind, &VETH_QUEUE_COUNT.to_ne_bytes()));
            variants.push(duplicate);
        }
        for (kind, length) in [
            (IFLA_STATS, VETH_LINK_STATS_BYTES),
            (IFLA_STATS64, VETH_LINK_STATS64_BYTES),
            (IFLA_MAP, VETH_LINK_IFMAP_BYTES),
        ] {
            variants.push(without_link_attribute(&valid, kind));
            let mut nonzero = vec![0; length];
            nonzero[length - 1] = 1;
            variants.push(replace_link_attribute(&valid, kind, &nonzero));
            variants.push(replace_link_attribute(&valid, kind, &vec![0; length - 1]));
            variants.push(replace_link_attribute_with_raw_kind(
                &valid,
                kind,
                kind | NLA_F_NET_BYTEORDER,
                &vec![0; length],
            ));
        }

        for payload in variants {
            let mut active = pristine.clone();
            active.links.push(payload);
            assert!(matches!(
                verify_exact_endpoint_veth_snapshot_delta(&pristine, &active, &expected),
                Err(NetworkError::NotPristine)
            ));
        }
    }

    #[test]
    fn exact_veth_delta_rejects_every_other_network_object_and_policy_change() {
        let pristine = pristine_snapshot();
        let expected = expected_pair("vpa01234567", 2, 2, 11);
        let mut active = pristine.clone();
        active.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            expected.endpoint_ifindex,
            expected.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
        ));
        let mut variants = Vec::new();
        let mut address = active.clone();
        address.addresses.push(vec![0]);
        variants.push(address);
        let mut route = active.clone();
        route.routes.push(vec![0]);
        variants.push(route);
        let mut neighbour = active.clone();
        neighbour.neighbours.push(vec![0]);
        variants.push(neighbour);
        let mut proxy_neighbour = active.clone();
        proxy_neighbour.proxy_neighbours.push(vec![0]);
        variants.push(proxy_neighbour);
        let mut nexthop = active.clone();
        nexthop.nexthops.push(vec![0]);
        variants.push(nexthop);
        let mut changed_rules = active.clone();
        changed_rules.rules_v4.pop();
        variants.push(changed_rules);
        let mut changed_loopback = active.clone();
        mutate_link_operstate(&mut changed_loopback.links[0]);
        variants.push(changed_loopback);
        let mut extra_link = active.clone();
        extra_link.links.push(valid_extra_veth_link());
        variants.push(extra_link);
        for variant in variants {
            assert!(
                verify_exact_endpoint_veth_snapshot_delta(&pristine, &variant, &expected).is_err()
            );
        }
    }

    #[test]
    fn qdisc_delta_rejects_clsact_ingress_and_unknown_records() {
        let pristine = pristine_snapshot();
        let expected = expected_pair("vpa01234567", 2, 2, 11);
        let mut active = pristine.clone();
        active.links.push(veth_link_payload(
            VETH_ENDPOINT_NAME,
            expected.endpoint_ifindex,
            expected.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
        ));
        verify_exact_endpoint_veth_snapshot_delta(&pristine, &active, &expected)
            .expect("kernel-default empty qdisc dump");

        for kind in [b"clsact\0".as_slice(), b"ingress\0".as_slice()] {
            let mut changed = active.clone();
            changed
                .qdiscs
                .push(qdisc_payload(expected.endpoint_ifindex, kind));
            assert!(matches!(
                verify_exact_endpoint_veth_snapshot_delta(&pristine, &changed, &expected),
                Err(NetworkError::NotPristine)
            ));
        }
        let mut unknown = active;
        let mut unknown_record = qdisc_payload(expected.endpoint_ifindex, b"unknown\0");
        unknown_record.extend(attribute(99, &[1]));
        unknown.qdiscs.push(unknown_record);
        assert!(matches!(
            verify_exact_endpoint_veth_snapshot_delta(&pristine, &unknown, &expected),
            Err(NetworkError::NotPristine)
        ));
    }

    #[test]
    fn ipv4_forwarding_baseline_accepts_both_canonical_inherited_values_unchanged() {
        for (record, expected) in [
            (b"0\n".as_slice(), Ipv4ForwardingState::Disabled),
            (b"1\n".as_slice(), Ipv4ForwardingState::Enabled),
        ] {
            assert_eq!(
                classify_ipv4_forwarding_records(record, record)
                    .expect("stable canonical inherited baseline"),
                expected
            );
        }
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
        let mut unknown = pristine_snapshot();
        unknown.links[0].extend(attribute(99, &[1]));
        assert!(matches!(
            verify_pristine_snapshot(&unknown),
            Err(NetworkError::NotPristine)
        ));
    }

    #[test]
    fn loopback_mutable_defaults_are_exact() {
        let mut wrong_address_families = attribute(u16::from(AF_INET), &[]);
        let wrong_ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[1]);
        wrong_address_families.extend(attribute(u16::from(AF_INET6), &wrong_ipv6));
        let mut unknown_address_family_attribute = attribute(u16::from(AF_INET), &[]);
        let mut ipv6_unknown = attribute(IFLA_INET6_ADDR_GEN_MODE, &[IN6_ADDR_GEN_MODE_EUI64]);
        ipv6_unknown.extend(attribute(99, &[0]));
        unknown_address_family_attribute.extend(attribute(u16::from(AF_INET6), &ipv6_unknown));
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
            (IFLA_AF_SPEC, unknown_address_family_attribute),
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
        let mut qdisc = pristine_snapshot();
        qdisc.qdiscs.push(qdisc_payload(1, b"clsact\0"));
        variants.push(qdisc);
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
    fn dump_parser_accepts_kernel_filtered_data_marker() {
        let request = encode_dump_request(DumpKind::Route, TEST_SEQUENCE).expect("request");
        let mut state = DumpState::new(DumpKind::Route, TEST_SEQUENCE, TEST_PORT, request);
        let route = vec![0; RTMSG_LEN];
        let mut datagram = netlink_frame(
            RTM_NEWROUTE,
            NLM_F_MULTI | NLM_F_DUMP_FILTERED,
            TEST_SEQUENCE,
            TEST_PORT,
            &route,
        );
        datagram.extend(netlink_frame(
            NLMSG_DONE,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &[],
        ));
        state
            .ingest(
                SocketAddr::new(0, 0),
                &datagram,
                &mut CollectionBudget::production(),
            )
            .expect("filtered route dump");
        assert_eq!(state.finish().expect("finished"), vec![route]);
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
                kind @ ("clsact" | "ingress") => {
                    add_live_qdisc(1, kind.as_bytes());
                    Some(DumpKind::Qdisc)
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
        for scenario in [
            "mtu",
            "gso-max-size",
            "proxy-neighbour",
            "nexthop",
            "clsact",
            "ingress",
        ] {
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

    fn prove_live_down_veth_parent_profile() {
        let mut target = Command::new("unshare")
            .args(["--net", "sh", "-c", "printf ready; read value"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn synchronized target network namespace");
        let mut ready = [0; 5];
        target
            .stdout
            .as_mut()
            .expect("target readiness pipe")
            .read_exact(&mut ready)
            .expect("target readiness");
        assert_eq!(&ready, b"ready");
        let target_path = format!("/proc/{}/ns/net", target.id());
        let descriptor = open(
            target_path.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("open target network namespace");
        let metadata = fstat(&descriptor).expect("target namespace identity");
        let target_identity = NetworkNamespaceIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        };
        let pid = target.id().to_string();
        let pristine = collect_consistent_pristine_snapshot().expect("live pristine baseline");
        run_ip(&[
            "link",
            "add",
            "vpa01234567",
            "numtxqueues",
            "1",
            "numrxqueues",
            "1",
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "numtxqueues",
            "1",
            "numrxqueues",
            "1",
            "netns",
            &pid,
        ]);
        let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT).expect("live proof deadline");
        let snapshot = collect_consistent_snapshot_before(deadline).expect("stable veth state");
        assert!(
            snapshot.qdiscs.is_empty(),
            "default veth qdisc must be empty"
        );
        let payload = snapshot
            .links
            .iter()
            .find(|payload| link_fixture_has_name(payload, b"vpa01234567"))
            .expect("parent veth observation");
        let parent_ifindex =
            u32::try_from(read_i32(payload, 4).expect("parent ifindex")).expect("positive index");
        let peer_ifindex = parse_attributes(&payload[IFINFO_LEN..])
            .expect("parent attributes")
            .into_iter()
            .find(|attribute| attribute.kind == IFLA_LINK)
            .map(|attribute| read_exact_u32(attribute.payload).expect("peer ifindex"))
            .expect("peer relation");
        let expected = ExpectedVethPair::new_with_namespace_identity(
            "vpa01234567",
            parent_ifindex,
            peer_ifindex,
            target_identity,
        )
        .expect("live pair expectation");
        let result = verify_veth_link(payload, &expected, VethLinkSide::Parent);
        let summary = link_attribute_summary(payload);
        let component_failures = veth_component_failures(payload);
        assert!(
            result.is_ok(),
            "live veth profile rejected: {result:?}; header={:?}; components={component_failures:?}; attributes={summary:?}",
            &payload[..IFINFO_LEN]
        );

        add_live_qdisc(parent_ifindex, b"clsact");
        let mutated = collect_consistent_snapshot_before(
            Deadline::after(NETWORK_PROOF_TIMEOUT).expect("mutated collector deadline"),
        )
        .expect("stable live qdisc mutation");
        assert!(!mutated.qdiscs.is_empty(), "live clsact must be observable");
        assert!(matches!(
            verify_unchanged_rtnl_except_links(&pristine, &mutated),
            Err(NetworkError::NotPristine)
        ));

        drop(target.stdin.take());
        target.wait().expect("reap target namespace");
    }

    #[test]
    fn collector_accepts_exact_live_down_veth_parent_profile() {
        if env::var_os(LIVE_VETH_CHILD_ENV).is_some() {
            prove_live_down_veth_parent_profile();
            return;
        }
        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("network::tests::collector_accepts_exact_live_down_veth_parent_profile")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_VETH_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated live-veth collector test");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live veth-profile proof: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated live-veth proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn live_down_veth_ipv4_address_round_trip_is_byte_exact() {
        if env::var_os(LIVE_IPV4_ROLLBACK_CHILD_ENV).is_some() {
            let pristine = collect_consistent_pristine_snapshot().expect("pristine baseline");
            run_ip(&[
                "link",
                "add",
                "vpa01234567",
                "numtxqueues",
                "1",
                "numrxqueues",
                "1",
                "type",
                "veth",
                "peer",
                "name",
                "eth0",
                "numtxqueues",
                "1",
                "numrxqueues",
                "1",
            ]);
            let veth_baseline = collect_consistent_snapshot_before(
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("veth baseline deadline"),
            )
            .expect("stable veth baseline");
            let neighbour_parameters = run_ip_capture(&["-details", "-json", "ntable", "show"]);
            let endpoint = veth_baseline
                .links
                .iter()
                .find(|payload| link_fixture_has_name(payload, VETH_ENDPOINT_NAME))
                .expect("endpoint link");
            let ifindex =
                u32::try_from(read_i32(endpoint, 4).expect("endpoint ifindex")).expect("positive");
            let expected = expected_ipv4("eth0", ifindex, [10, 241, 1, 2]);

            run_ip(&["address", "add", "10.241.1.2/30", "dev", "eth0"]);
            let active = collect_consistent_snapshot_before(
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("addressed deadline"),
            )
            .expect("stable addressed state");
            assert_eq!(active.links, veth_baseline.links);
            assert_eq!(active.qdiscs, veth_baseline.qdiscs);
            assert_eq!(active.neighbours, veth_baseline.neighbours);
            assert_eq!(active.proxy_neighbours, veth_baseline.proxy_neighbours);
            assert_eq!(active.nexthops, veth_baseline.nexthops);
            assert_eq!(active.rules_v4, veth_baseline.rules_v4);
            assert_eq!(active.rules_v6, veth_baseline.rules_v6);
            verify_exact_fixed_ipv4_objects(&active, &[&expected])
                .expect("exact kernel address and local route");

            run_ip(&["address", "del", "10.241.1.2/30", "dev", "eth0"]);
            let rolled_back = collect_consistent_snapshot_before(
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("rollback deadline"),
            )
            .expect("stable address rollback");
            assert_eq!(rolled_back, veth_baseline);
            assert_eq!(
                run_ip_capture(&["-details", "-json", "ntable", "show"]),
                neighbour_parameters
            );

            run_ip(&["link", "del", "vpa01234567"]);
            assert_eq!(
                collect_consistent_snapshot_before(
                    Deadline::after(NETWORK_PROOF_TIMEOUT).expect("pristine deadline")
                )
                .expect("restored pristine state"),
                pristine
            );
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("network::tests::live_down_veth_ipv4_address_round_trip_is_byte_exact")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_IPV4_ROLLBACK_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated live IPv4 rollback proof");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live IPv4 rollback proof: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated live IPv4 rollback proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    // Keeping the complete four-namespace mutation order visible in one live
    // proof makes the teardown and host-safety boundary auditable.
    #[allow(clippy::too_many_lines)]
    fn live_four_end_addrgen_barrier_activation_and_deletion_are_exact() {
        if env::var_os(LIVE_LINK_ACTIVATION_CHILD_ENV).is_some() {
            let mut targets = [
                spawn_synchronized_network_namespace(),
                spawn_synchronized_network_namespace(),
            ];
            let target_pids = [targets[0].id(), targets[1].id()];
            let endpoint_descriptors = target_pids.map(|pid| {
                open(
                    format!("/proc/{pid}/ns/net").as_str(),
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .expect("open endpoint network namespace")
            });
            let endpoint_identities = endpoint_descriptors.each_ref().map(|descriptor| {
                let metadata = fstat(descriptor).expect("endpoint namespace identity");
                NetworkNamespaceIdentity {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                }
            });
            let parent_descriptor = open(
                CURRENT_NETWORK_NAMESPACE,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .expect("open parent network namespace");
            let parent_pristine = collect_consistent_pristine_snapshot().expect("parent pristine");
            let endpoint_pristine = endpoint_descriptors.each_ref().map(|descriptor| {
                collect_snapshot_in_network_namespace(descriptor, &parent_descriptor)
            });

            for (name, pid) in [
                ("vpa01234567", target_pids[0]),
                ("vpb01234567", target_pids[1]),
            ] {
                let pid = pid.to_string();
                run_ip(&[
                    "link",
                    "add",
                    name,
                    "numtxqueues",
                    "1",
                    "numrxqueues",
                    "1",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    "eth0",
                    "numtxqueues",
                    "1",
                    "numrxqueues",
                    "1",
                    "netns",
                    &pid,
                ]);
            }

            let skeleton_parent = collect_consistent_snapshot_before(
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("parent skeleton deadline"),
            )
            .expect("stable parent skeleton");
            let parent_indices = [b"vpa01234567".as_slice(), b"vpb01234567".as_slice()]
                .map(|name| live_link_ifindex(&skeleton_parent, name));
            let endpoint_skeletons = endpoint_descriptors.each_ref().map(|descriptor| {
                collect_snapshot_in_network_namespace(descriptor, &parent_descriptor)
            });
            let endpoint_indices = endpoint_skeletons
                .each_ref()
                .map(|snapshot| live_link_ifindex(snapshot, VETH_ENDPOINT_NAME));
            let pairs = [
                ExpectedVethPair::new_with_namespace_identity(
                    "vpa01234567",
                    parent_indices[0],
                    endpoint_indices[0],
                    endpoint_identities[0],
                )
                .expect("pair A expectation"),
                ExpectedVethPair::new_with_namespace_identity(
                    "vpb01234567",
                    parent_indices[1],
                    endpoint_indices[1],
                    endpoint_identities[1],
                )
                .expect("pair B expectation"),
            ];
            let parent_addresses = [
                expected_ipv4("vpa01234567", parent_indices[0], [10, 241, 1, 1]),
                expected_ipv4("vpb01234567", parent_indices[1], [10, 241, 2, 1]),
            ];
            let endpoint_addresses = [
                expected_ipv4("eth0", endpoint_indices[0], [10, 241, 1, 2]),
                expected_ipv4("eth0", endpoint_indices[1], [10, 241, 2, 2]),
            ];

            run_ip(&["address", "add", "10.241.1.1/30", "dev", "vpa01234567"]);
            run_ip_in(
                target_pids[0],
                &["address", "add", "10.241.1.2/30", "dev", "eth0"],
            );
            run_ip(&["address", "add", "10.241.2.1/30", "dev", "vpb01234567"]);
            run_ip_in(
                target_pids[1],
                &["address", "add", "10.241.2.2/30", "dev", "eth0"],
            );

            run_ip(&["link", "set", "dev", "vpa01234567", "addrgenmode", "none"]);
            run_ip(&["link", "set", "dev", "vpb01234567", "addrgenmode", "none"]);
            run_ip_in(
                target_pids[0],
                &["link", "set", "dev", "eth0", "addrgenmode", "none"],
            );
            run_ip_in(
                target_pids[1],
                &["link", "set", "dev", "eth0", "addrgenmode", "none"],
            );

            let barrier_parent = collect_consistent_snapshot_before(
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("barrier parent deadline"),
            )
            .expect("stable parent addrgen barrier");
            let barrier_parent_links = verify_exact_parent_ipv4_addrgen_none_snapshot_delta(
                &parent_pristine,
                &barrier_parent,
                [&pairs[0], &pairs[1]],
                [&parent_addresses[0], &parent_addresses[1]],
            )
            .unwrap_or_else(|error| {
                panic!(
                    "live parent addrgen barrier rejected: {error:?}; links={:?}",
                    live_link_debug(&barrier_parent)
                )
            });
            let barrier_endpoints = endpoint_descriptors.each_ref().map(|descriptor| {
                collect_snapshot_in_network_namespace(descriptor, &parent_descriptor)
            });
            let barrier_a = verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
                &endpoint_pristine[0],
                &barrier_endpoints[0],
                &pairs[0],
                &endpoint_addresses[0],
            )
            .expect("live endpoint A addrgen barrier");
            let barrier_b = verify_exact_endpoint_ipv4_addrgen_none_snapshot_delta(
                &endpoint_pristine[1],
                &barrier_endpoints[1],
                &pairs[1],
                &endpoint_addresses[1],
            )
            .expect("live endpoint B addrgen barrier");
            verify_veth_observation_relations(
                &barrier_parent_links,
                [&barrier_a, &barrier_b],
                endpoint_identities,
            )
            .expect("live four-end addrgen relations");

            run_ip(&["link", "set", "dev", "vpa01234567", "up"]);
            run_ip(&["link", "set", "dev", "vpb01234567", "up"]);
            run_ip_in(target_pids[0], &["link", "set", "dev", "eth0", "up"]);
            run_ip_in(target_pids[1], &["link", "set", "dev", "eth0", "up"]);

            let active_parent_deadline =
                Deadline::after(NETWORK_PROOF_TIMEOUT).expect("active parent deadline");
            let (active_parent, active_parent_links) = retry_exact_observation_before(
                active_parent_deadline,
                || collect_converged_snapshot_before(active_parent_deadline),
                |active| {
                    verify_exact_parent_activated_ipv4_snapshot_delta(
                        &parent_pristine,
                        active,
                        [&pairs[0], &pairs[1]],
                        [&parent_addresses[0], &parent_addresses[1]],
                    )
                },
            )
            .unwrap_or_else(|error| {
                let active = collect_consistent_snapshot_before(
                    Deadline::after(NETWORK_PROOF_TIMEOUT).expect("parent diagnostic deadline"),
                )
                .expect("stable parent diagnostic");
                panic!(
                    "live active parent rejected: {error:?}; links={:?}; qdiscs={:?}; routes={:?}",
                    live_link_debug(&active),
                    active.qdiscs,
                    active.routes,
                )
            });
            let active_endpoint_deadlines = [(); 2]
                .map(|()| Deadline::after(NETWORK_PROOF_TIMEOUT).expect("endpoint deadline"));
            let (active_endpoint_a, active_a) = retry_exact_observation_before(
                active_endpoint_deadlines[0],
                || {
                    collect_converged_snapshot_in_network_namespace(
                        &endpoint_descriptors[0],
                        &parent_descriptor,
                        active_endpoint_deadlines[0],
                    )
                },
                |active| {
                    verify_exact_endpoint_activated_ipv4_snapshot_delta(
                        &endpoint_pristine[0],
                        active,
                        &pairs[0],
                        &endpoint_addresses[0],
                    )
                },
            )
            .expect("live endpoint A converged active proof");
            let (active_endpoint_b, active_b) = retry_exact_observation_before(
                active_endpoint_deadlines[1],
                || {
                    collect_converged_snapshot_in_network_namespace(
                        &endpoint_descriptors[1],
                        &parent_descriptor,
                        active_endpoint_deadlines[1],
                    )
                },
                |active| {
                    verify_exact_endpoint_activated_ipv4_snapshot_delta(
                        &endpoint_pristine[1],
                        active,
                        &pairs[1],
                        &endpoint_addresses[1],
                    )
                },
            )
            .expect("live endpoint B converged active proof");
            verify_veth_observation_relations(
                &active_parent_links,
                [&active_a, &active_b],
                endpoint_identities,
            )
            .expect("live four-end activation relations");

            let expected_routes = [
                expected_ipv4_endpoint_route(
                    &pairs[0],
                    &endpoint_addresses[0],
                    endpoint_identities[0],
                )
                .expect("fixed endpoint A route"),
                expected_ipv4_endpoint_route(
                    &pairs[1],
                    &endpoint_addresses[1],
                    endpoint_identities[1],
                )
                .expect("fixed endpoint B route"),
            ];
            run_ip_in(
                target_pids[0],
                &[
                    "route",
                    "add",
                    "10.241.2.2/32",
                    "via",
                    "10.241.1.1",
                    "dev",
                    "eth0",
                    "table",
                    "main",
                    "protocol",
                    "static",
                    "scope",
                    "global",
                ],
            );
            run_ip_in(
                target_pids[1],
                &[
                    "route",
                    "add",
                    "10.241.1.2/32",
                    "via",
                    "10.241.2.1",
                    "dev",
                    "eth0",
                    "table",
                    "main",
                    "protocol",
                    "static",
                    "scope",
                    "global",
                ],
            );

            assert_eq!(
                collect_consistent_snapshot_before(
                    Deadline::after(NETWORK_PROOF_TIMEOUT)
                        .expect("routed parent equality deadline"),
                )
                .expect("stable routed parent observation"),
                active_parent,
                "endpoint route creation must not change the parent snapshot",
            );
            for (index, activated) in [active_endpoint_a, active_endpoint_b].iter().enumerate() {
                let deadline =
                    Deadline::after(NETWORK_PROOF_TIMEOUT).expect("routed endpoint deadline");
                retry_exact_observation_before(
                    deadline,
                    || {
                        collect_converged_snapshot_in_network_namespace(
                            &endpoint_descriptors[index],
                            &parent_descriptor,
                            deadline,
                        )
                    },
                    |routed| {
                        verify_exact_endpoint_ipv4_route_snapshot_delta(
                            activated,
                            routed,
                            &expected_routes[index],
                        )
                    },
                )
                .unwrap_or_else(|error| {
                    panic!("live endpoint {index} exact route rejected: {error:?}")
                });
            }

            run_ip(&["link", "delete", "dev", "vpb01234567"]);
            assert_eq!(
                collect_snapshot_in_network_namespace(&endpoint_descriptors[1], &parent_descriptor,),
                endpoint_pristine[1],
                "pair B deletion must restore endpoint B exactly"
            );
            run_ip(&["link", "delete", "dev", "vpa01234567"]);
            assert_eq!(
                collect_consistent_snapshot_before(
                    Deadline::after(NETWORK_PROOF_TIMEOUT).expect("parent teardown deadline")
                )
                .expect("stable parent teardown"),
                parent_pristine,
                "pair B/A deletion must restore parent exactly"
            );
            for index in 0..2 {
                assert_eq!(
                    collect_snapshot_in_network_namespace(
                        &endpoint_descriptors[index],
                        &parent_descriptor,
                    ),
                    endpoint_pristine[index],
                    "pair B/A deletion must restore each endpoint exactly"
                );
            }

            for target in &mut targets {
                drop(target.stdin.take());
                target.wait().expect("reap endpoint namespace");
            }
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("network::tests::live_four_end_addrgen_barrier_activation_and_deletion_are_exact")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_LINK_ACTIVATION_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated live link-activation proof");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live link-activation proof: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated live link-activation proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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

    fn run_ip_in(namespace_pid: u32, arguments: &[&str]) {
        let namespace_pid = namespace_pid.to_string();
        let status = Command::new("nsenter")
            .args(["-t", namespace_pid.as_str(), "-n", "--", "ip"])
            .args(arguments)
            .status()
            .expect("execute namespaced iproute diagnostic mutation");
        assert!(
            status.success(),
            "namespaced iproute diagnostic mutation failed"
        );
    }

    fn spawn_synchronized_network_namespace() -> std::process::Child {
        let mut target = Command::new("unshare")
            .args(["--net", "sh", "-c", "printf ready; read value"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn synchronized endpoint network namespace");
        let mut ready = [0; 5];
        target
            .stdout
            .as_mut()
            .expect("endpoint readiness pipe")
            .read_exact(&mut ready)
            .expect("endpoint readiness");
        assert_eq!(&ready, b"ready");
        target
    }

    fn collect_snapshot_in_network_namespace<Target: AsFd, Parent: AsFd>(
        target: &Target,
        parent: &Parent,
    ) -> NetworkSnapshot {
        setns(target, CloneFlags::CLONE_NEWNET).expect("enter endpoint network namespace");
        let result = collect_consistent_snapshot_before(
            Deadline::after(NETWORK_PROOF_TIMEOUT).expect("visited collector deadline"),
        );
        setns(parent, CloneFlags::CLONE_NEWNET).expect("restore parent network namespace");
        result.expect("stable visited network snapshot")
    }

    fn collect_converged_snapshot_in_network_namespace<Target: AsFd, Parent: AsFd>(
        target: &Target,
        parent: &Parent,
        deadline: Deadline,
    ) -> Result<NetworkSnapshot, NetworkError> {
        setns(target, CloneFlags::CLONE_NEWNET).expect("enter endpoint network namespace");
        let result = collect_converged_snapshot_before(deadline);
        setns(parent, CloneFlags::CLONE_NEWNET).expect("restore parent network namespace");
        result
    }

    fn live_link_ifindex(snapshot: &NetworkSnapshot, name: &[u8]) -> u32 {
        let payload = snapshot
            .links
            .iter()
            .find(|payload| link_fixture_has_name(payload, name))
            .expect("live expected link");
        u32::try_from(read_i32(payload, 4).expect("live link ifindex"))
            .expect("positive live link ifindex")
    }

    type LiveLinkAttributeDebug = (u16, u16, usize, Vec<u8>);
    type LiveLinkDebug = (Vec<u8>, Vec<u8>, Vec<LiveLinkAttributeDebug>);

    fn live_link_debug(snapshot: &NetworkSnapshot) -> Vec<LiveLinkDebug> {
        snapshot
            .links
            .iter()
            .map(|payload| {
                let name = parse_attributes(payload.get(IFINFO_LEN..).unwrap_or_default())
                    .ok()
                    .and_then(|attributes| {
                        attributes
                            .into_iter()
                            .find(|attribute| attribute.kind == IFLA_IFNAME)
                            .map(|attribute| attribute.payload.to_vec())
                    })
                    .unwrap_or_default();
                (
                    payload[..IFINFO_LEN.min(payload.len())].to_vec(),
                    name,
                    link_attribute_summary(payload),
                )
            })
            .collect()
    }

    fn run_ip_capture(arguments: &[&str]) -> Vec<u8> {
        let output = Command::new("ip")
            .args(arguments)
            .env("LC_ALL", "C")
            .output()
            .expect("execute iproute diagnostic observation");
        assert!(output.status.success(), "iproute observation failed");
        assert!(output.stderr.is_empty(), "iproute observation warned");
        output.stdout
    }

    fn add_live_qdisc(ifindex: u32, kind: &[u8]) {
        let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT).expect("qdisc mutation deadline");
        let mut client = NetlinkCollector::connect(deadline).expect("qdisc mutation socket");
        let sequence = client.next_sequence().expect("qdisc mutation sequence");
        let mut payload = vec![0; TCMSG_LEN];
        payload[4..8].copy_from_slice(
            &i32::try_from(ifindex)
                .expect("qdisc ifindex fits")
                .to_ne_bytes(),
        );
        payload[12..16].copy_from_slice(&TC_H_CLSACT.to_ne_bytes());
        let mut nul_kind = kind.to_vec();
        nul_kind.push(0);
        payload.extend(attribute(TCA_KIND, &nul_kind));
        let request = netlink_frame(
            RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
            sequence,
            0,
            &payload,
        );
        send_bounded(&client.socket, &request, deadline).expect("create disposable qdisc");
    }

    fn collect_live_dump(kind: DumpKind) -> Vec<Vec<u8>> {
        let deadline = Deadline::after(NETWORK_PROOF_TIMEOUT).expect("live dump deadline");
        let mut collector = NetlinkCollector::connect(deadline).expect("live dump collector");
        collector
            .collect_dump(kind, deadline, &mut CollectionBudget::production())
            .expect("live dump")
    }

    fn link_fixture_has_name(payload: &[u8], expected: &[u8]) -> bool {
        parse_attributes(payload.get(IFINFO_LEN..).unwrap_or_default())
            .ok()
            .is_some_and(|attributes| {
                attributes.into_iter().any(|attribute| {
                    attribute.kind == IFLA_IFNAME
                        && interface_name_is_exact(Some(attribute.payload), expected)
                })
            })
    }

    fn link_attribute_summary(payload: &[u8]) -> Vec<(u16, u16, usize, Vec<u8>)> {
        parse_attributes(payload.get(IFINFO_LEN..).unwrap_or_default())
            .map(|attributes| {
                attributes
                    .into_iter()
                    .map(|attribute| {
                        (
                            attribute.kind,
                            attribute.flags,
                            attribute.payload.len(),
                            attribute.payload.iter().copied().take(16).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn veth_component_failures(payload: &[u8]) -> Vec<(u16, String)> {
        parse_attributes(payload.get(IFINFO_LEN..).unwrap_or_default()).map_or_else(
            |error| vec![(0, format!("{error:?}"))],
            |attributes| {
                attributes
                    .into_iter()
                    .filter_map(|attribute| {
                        let result = match attribute.kind {
                            IFLA_AF_SPEC => {
                                verify_address_family_spec(attribute, IN6_ADDR_GEN_MODE_EUI64)
                            }
                            IFLA_LINKINFO => verify_veth_link_info(attribute),
                            IFLA_STATS
                            | IFLA_STATS64
                            | IFLA_MAP
                            | IFLA_NUM_TX_QUEUES
                            | IFLA_NUM_RX_QUEUES
                            | IFLA_CARRIER
                            | IFLA_CARRIER_CHANGES
                            | IFLA_CARRIER_UP_COUNT
                            | IFLA_CARRIER_DOWN_COUNT
                            | IFLA_EVENT
                            | IFLA_MIN_MTU
                            | IFLA_MAX_MTU
                            | IFLA_GSO_MAX_SEGS
                            | IFLA_GSO_MAX_SIZE
                            | IFLA_GRO_MAX_SIZE
                            | IFLA_GSO_IPV4_MAX_SIZE
                            | IFLA_GRO_IPV4_MAX_SIZE
                            | IFLA_TSO_MAX_SIZE
                            | IFLA_TSO_MAX_SEGS
                            | IFLA_PERM_ADDRESS
                            | IFLA_PROP_LIST
                            | IFLA_DEVLINK_PORT
                            | IFLA_DPLL_PIN => {
                                verify_allowed_link_telemetry(attribute, LinkTelemetryProfile::Veth)
                            }
                            _ => Ok(()),
                        };
                        result
                            .err()
                            .map(|error| (attribute.kind, format!("{error:?}")))
                    })
                    .collect()
            },
        )
    }

    fn test_namespace_identity(inode: u64) -> NetworkNamespaceIdentity {
        NetworkNamespaceIdentity { device: 7, inode }
    }

    fn expected_pair(
        name: &str,
        parent_ifindex: u32,
        endpoint_ifindex: u32,
        namespace_inode: u64,
    ) -> ExpectedVethPair {
        ExpectedVethPair::new_with_namespace_identity(
            name,
            parent_ifindex,
            endpoint_ifindex,
            test_namespace_identity(namespace_inode),
        )
        .expect("valid fixed-veth expectation")
    }

    fn expected_ipv4(name: &str, ifindex: u32, address: [u8; 4]) -> ExpectedIpv4Address {
        ExpectedIpv4Address::new(name, ifindex, address).expect("valid fixed-IPv4 expectation")
    }

    fn valid_activated_endpoint_fixture() -> (
        NetworkSnapshot,
        ExpectedVethPair,
        ExpectedIpv4Address,
        NetworkSnapshot,
    ) {
        let pristine = pristine_snapshot();
        let pair = expected_pair("vpa01234567", 2, 2, 11);
        let address = expected_ipv4("eth0", 2, [10, 241, 1, 2]);
        let mut active = pristine.clone();
        active.links.push(veth_link_payload_with_profile(
            VETH_ENDPOINT_NAME,
            pair.endpoint_ifindex,
            pair.parent_ifindex,
            0,
            [0x02, 1, 2, 3, 4, 5],
            VethLinkProfile::ActivatedAddrgenNone,
        ));
        add_activated_ipv4_fixture(&mut active, &address);
        (pristine, pair, address, active)
    }

    fn add_fixed_ipv4_fixture(snapshot: &mut NetworkSnapshot, expected: &ExpectedIpv4Address) {
        snapshot.addresses.push(ipv4_address_payload(
            std::str::from_utf8(&expected.interface_name).expect("ASCII interface"),
            expected.ifindex,
            expected.address,
        ));
        snapshot
            .routes
            .push(ipv4_local_route_payload(expected.ifindex, expected.address));
    }

    fn add_activated_ipv4_fixture(snapshot: &mut NetworkSnapshot, expected: &ExpectedIpv4Address) {
        snapshot.addresses.push(ipv4_address_payload(
            std::str::from_utf8(&expected.interface_name).expect("ASCII interface"),
            expected.ifindex,
            expected.address,
        ));
        snapshot
            .qdiscs
            .push(noqueue_qdisc_payload(expected.ifindex));
        snapshot
            .routes
            .push(ipv4_local_route_payload(expected.ifindex, expected.address));
        snapshot.routes.push(ipv4_connected_route_payload(
            expected.ifindex,
            expected.address,
        ));
        snapshot.routes.push(ipv4_high_broadcast_route_payload(
            expected.ifindex,
            expected.address,
        ));
        snapshot
            .routes
            .push(ipv6_multicast_route_payload(expected.ifindex));
    }

    fn ipv4_address_payload(name: &str, ifindex: u32, address: [u8; 4]) -> Vec<u8> {
        let mut payload = vec![
            AF_INET,
            FIXED_IPV4_PREFIX_LENGTH,
            IFA_F_PERMANENT_U8,
            RT_SCOPE_UNIVERSE,
        ];
        payload.extend_from_slice(&ifindex.to_ne_bytes());
        payload.extend(attribute(IFA_ADDRESS, &address));
        payload.extend(attribute(IFA_LOCAL, &address));
        let mut label = name.as_bytes().to_vec();
        label.push(0);
        payload.extend(attribute(IFA_LABEL, &label));
        payload.extend(attribute(IFA_FLAGS, &IFA_F_PERMANENT.to_ne_bytes()));
        let mut cacheinfo = Vec::with_capacity(IFA_CACHEINFO_LEN);
        cacheinfo.extend_from_slice(&u32::MAX.to_ne_bytes());
        cacheinfo.extend_from_slice(&u32::MAX.to_ne_bytes());
        cacheinfo.extend_from_slice(&17_u32.to_ne_bytes());
        cacheinfo.extend_from_slice(&17_u32.to_ne_bytes());
        payload.extend(attribute(IFA_CACHEINFO, &cacheinfo));
        payload
    }

    fn ipv4_local_route_payload(ifindex: u32, address: [u8; 4]) -> Vec<u8> {
        let mut payload = vec![
            AF_INET,
            32,
            0,
            0,
            u8::MAX,
            RTPROT_KERNEL,
            RT_SCOPE_HOST,
            RTN_LOCAL,
        ];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload.extend(attribute(RTA_TABLE, &RT_TABLE_LOCAL.to_ne_bytes()));
        payload.extend(attribute(RTA_DST, &address));
        payload.extend(attribute(RTA_PREFSRC, &address));
        payload.extend(attribute(RTA_OIF, &ifindex.to_ne_bytes()));
        payload
    }

    fn ipv4_endpoint_route_payload(
        ifindex: u32,
        destination: [u8; 4],
        gateway: [u8; 4],
    ) -> Vec<u8> {
        let mut payload = vec![
            AF_INET,
            32,
            0,
            0,
            u8::try_from(RT_TABLE_MAIN).expect("main table byte"),
            RTPROT_STATIC,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        ];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload.extend(attribute(RTA_TABLE, &RT_TABLE_MAIN.to_ne_bytes()));
        payload.extend(attribute(RTA_DST, &destination));
        payload.extend(attribute(RTA_GATEWAY, &gateway));
        payload.extend(attribute(RTA_OIF, &ifindex.to_ne_bytes()));
        payload
    }

    fn ipv4_connected_route_payload(ifindex: u32, address: [u8; 4]) -> Vec<u8> {
        let mut network = address;
        network[3] = 0;
        let mut payload = vec![
            AF_INET,
            FIXED_IPV4_PREFIX_LENGTH,
            0,
            0,
            u8::try_from(RT_TABLE_MAIN).expect("main table fits"),
            RTPROT_KERNEL,
            RT_SCOPE_LINK,
            RTN_UNICAST,
        ];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload.extend(attribute(RTA_TABLE, &RT_TABLE_MAIN.to_ne_bytes()));
        payload.extend(attribute(RTA_DST, &network));
        payload.extend(attribute(RTA_PREFSRC, &address));
        payload.extend(attribute(RTA_OIF, &ifindex.to_ne_bytes()));
        payload
    }

    fn ipv4_high_broadcast_route_payload(ifindex: u32, address: [u8; 4]) -> Vec<u8> {
        let mut broadcast = address;
        broadcast[3] = 3;
        let mut payload = vec![
            AF_INET,
            32,
            0,
            0,
            u8::MAX,
            RTPROT_KERNEL,
            RT_SCOPE_LINK,
            RTN_BROADCAST,
        ];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload.extend(attribute(RTA_TABLE, &RT_TABLE_LOCAL.to_ne_bytes()));
        payload.extend(attribute(RTA_DST, &broadcast));
        payload.extend(attribute(RTA_PREFSRC, &address));
        payload.extend(attribute(RTA_OIF, &ifindex.to_ne_bytes()));
        payload
    }

    fn ipv6_multicast_route_payload(ifindex: u32) -> Vec<u8> {
        let mut payload = vec![
            AF_INET6,
            8,
            0,
            0,
            u8::MAX,
            RTPROT_KERNEL,
            RT_SCOPE_UNIVERSE,
            RTN_MULTICAST,
        ];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload.extend(attribute(RTA_TABLE, &RT_TABLE_LOCAL.to_ne_bytes()));
        payload.extend(attribute(
            RTA_DST,
            &[0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ));
        payload.extend(attribute(RTA_OIF, &ifindex.to_ne_bytes()));
        payload.extend(attribute(RTA_PRIORITY, &256_u32.to_ne_bytes()));
        payload.extend(attribute(RTA_CACHEINFO, &[0; IPV6_ROUTE_CACHEINFO_BYTES]));
        payload.extend(attribute(RTA_PREF, &[IPV6_DEFAULT_PREFERENCE]));
        payload
    }

    fn pristine_snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            links: vec![link_payload()],
            qdiscs: Vec::new(),
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

    fn qdisc_payload(ifindex: u32, kind: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; TCMSG_LEN];
        payload[4..8].copy_from_slice(
            &i32::try_from(ifindex)
                .expect("fixture qdisc ifindex fits")
                .to_ne_bytes(),
        );
        payload[12..16].copy_from_slice(&TC_H_ROOT.to_ne_bytes());
        payload.extend(attribute(TCA_KIND, kind));
        payload
    }

    fn noqueue_qdisc_payload(ifindex: u32) -> Vec<u8> {
        let mut payload = qdisc_payload(ifindex, b"noqueue\0");
        payload[16..20].copy_from_slice(&NOQUEUE_REFERENCE_COUNT.to_ne_bytes());
        payload.extend(attribute(TCA_HW_OFFLOAD, &[0]));
        let mut stats2 = attribute(TCA_STATS_BASIC, &[0; TC_STATS_BASIC_BYTES]);
        stats2.extend(attribute(TCA_STATS_QUEUE, &[0; TC_STATS_QUEUE_BYTES]));
        payload.extend(attribute(TCA_STATS2, &stats2));
        payload.extend(attribute(TCA_STATS, &[0; TC_STATS_BYTES]));
        payload
    }

    fn veth_link_payload(
        name: &[u8],
        ifindex: u32,
        peer_ifindex: u32,
        peer_netnsid: i32,
        mac: [u8; ETHERNET_ADDRESS_BYTES],
    ) -> Vec<u8> {
        veth_link_payload_with_profile(
            name,
            ifindex,
            peer_ifindex,
            peer_netnsid,
            mac,
            VethLinkProfile::DownEui64,
        )
    }

    fn veth_link_payload_with_profile(
        name: &[u8],
        ifindex: u32,
        peer_ifindex: u32,
        peer_netnsid: i32,
        mac: [u8; ETHERNET_ADDRESS_BYTES],
        profile: VethLinkProfile,
    ) -> Vec<u8> {
        let mut payload = vec![0; IFINFO_LEN];
        payload[2..4].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        payload[4..8].copy_from_slice(
            &i32::try_from(ifindex)
                .expect("fixture ifindex fits")
                .to_ne_bytes(),
        );
        payload[8..12].copy_from_slice(&profile.flags().to_ne_bytes());
        let mut nul_name = name.to_vec();
        nul_name.push(0);
        payload.extend(attribute(IFLA_IFNAME, &nul_name));
        payload.extend(attribute(IFLA_LINK, &peer_ifindex.to_ne_bytes()));
        payload.extend(attribute(IFLA_LINK_NETNSID, &peer_netnsid.to_ne_bytes()));
        payload.extend(attribute(IFLA_OPERSTATE, &[profile.operstate()]));
        payload.extend(attribute(IFLA_ADDRESS, &mac));
        payload.extend(attribute(
            IFLA_BROADCAST,
            &[u8::MAX; ETHERNET_ADDRESS_BYTES],
        ));
        payload.extend(attribute(IFLA_MTU, &VETH_MTU.to_ne_bytes()));
        payload.extend(attribute(IFLA_TXQLEN, &VETH_TX_QUEUE_LENGTH.to_ne_bytes()));
        payload.extend(attribute(
            IFLA_NUM_TX_QUEUES,
            &VETH_QUEUE_COUNT.to_ne_bytes(),
        ));
        payload.extend(attribute(
            IFLA_NUM_RX_QUEUES,
            &VETH_QUEUE_COUNT.to_ne_bytes(),
        ));
        payload.extend(attribute(IFLA_STATS, &[0; VETH_LINK_STATS_BYTES]));
        payload.extend(attribute(IFLA_STATS64, &[0; VETH_LINK_STATS64_BYTES]));
        payload.extend(attribute(IFLA_MAP, &[0; VETH_LINK_IFMAP_BYTES]));
        payload.extend(attribute(IFLA_PERM_ADDRESS, &mac));
        payload.extend(attribute(IFLA_QDISC, profile.qdisc()));
        payload.extend(attribute(IFLA_LINKMODE, &[0]));
        payload.extend(attribute(IFLA_GROUP, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_PROMISCUITY, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_ALLMULTI, &0_u32.to_ne_bytes()));
        payload.extend(attribute(IFLA_PROTO_DOWN, &[0]));
        payload.extend(attribute(
            IFLA_LINKINFO,
            &attribute(IFLA_INFO_KIND, b"veth\0"),
        ));
        let mut address_families = attribute(u16::from(AF_INET), &[]);
        let ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[profile.addrgen_mode()]);
        address_families.extend(attribute(u16::from(AF_INET6), &ipv6));
        payload.extend(attribute(IFLA_AF_SPEC, &address_families));
        if matches!(profile, VethLinkProfile::ActivatedAddrgenNone) {
            payload.extend(attribute(IFLA_CARRIER, &[1]));
            payload.extend(attribute(IFLA_CARRIER_CHANGES, &2_u32.to_ne_bytes()));
            payload.extend(attribute(IFLA_CARRIER_UP_COUNT, &1_u32.to_ne_bytes()));
            payload.extend(attribute(IFLA_CARRIER_DOWN_COUNT, &1_u32.to_ne_bytes()));
        }
        payload
    }

    fn valid_extra_veth_link() -> Vec<u8> {
        veth_link_payload(b"extra0", 4, 2, 2, [0x12, 1, 2, 3, 4, 5])
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
        rebuild_link_attribute(payload, kind, Some((kind, replacement)))
    }

    fn replace_link_attribute_with_raw_kind(
        payload: &[u8],
        kind: u16,
        raw_kind: u16,
        replacement: &[u8],
    ) -> Vec<u8> {
        rebuild_link_attribute(payload, kind, Some((raw_kind, replacement)))
    }

    fn without_link_attribute(payload: &[u8], kind: u16) -> Vec<u8> {
        rebuild_link_attribute(payload, kind, None)
    }

    fn rebuild_link_attribute(
        payload: &[u8],
        kind: u16,
        replacement: Option<(u16, &[u8])>,
    ) -> Vec<u8> {
        let mut rebuilt = payload[..IFINFO_LEN].to_vec();
        let mut remaining = &payload[IFINFO_LEN..];
        let mut replaced = false;
        while !remaining.is_empty() {
            let length = usize::from(read_u16(remaining, 0).expect("fixture length"));
            let aligned = align4(length).expect("fixture alignment");
            let observed_kind = read_u16(remaining, 2).expect("fixture kind") & NLA_TYPE_MASK;
            if observed_kind == kind {
                assert!(!replaced, "fixture attribute must be unique");
                replaced = true;
                if let Some((raw_kind, replacement)) = replacement {
                    rebuilt.extend(attribute(raw_kind, replacement));
                }
            } else {
                rebuilt.extend_from_slice(&remaining[..aligned]);
            }
            remaining = &remaining[aligned..];
        }
        assert!(replaced, "fixture attribute must exist");
        rebuilt
    }

    fn replace_record_attribute(
        payload: &[u8],
        header_length: usize,
        kind: u16,
        replacement: &[u8],
    ) -> Vec<u8> {
        let mut rebuilt = payload[..header_length].to_vec();
        let mut replaced = false;
        for attribute_value in
            parse_attributes(&payload[header_length..]).expect("valid fixture attributes")
        {
            if attribute_value.kind == kind {
                assert!(!replaced, "fixture attribute must be unique");
                replaced = true;
                rebuilt.extend(attribute(kind, replacement));
            } else {
                rebuilt.extend(attribute(
                    attribute_value.kind | attribute_value.flags,
                    attribute_value.payload,
                ));
            }
        }
        assert!(replaced, "fixture attribute must exist");
        rebuilt
    }

    fn without_record_attribute(payload: &[u8], header_length: usize, kind: u16) -> Vec<u8> {
        rebuild_record_attribute(payload, header_length, kind, None)
    }

    fn replace_record_attribute_with_raw_kind(
        payload: &[u8],
        header_length: usize,
        kind: u16,
        raw_kind: u16,
        replacement: &[u8],
    ) -> Vec<u8> {
        rebuild_record_attribute(payload, header_length, kind, Some((raw_kind, replacement)))
    }

    fn rebuild_record_attribute(
        payload: &[u8],
        header_length: usize,
        kind: u16,
        replacement: Option<(u16, &[u8])>,
    ) -> Vec<u8> {
        let mut rebuilt = payload[..header_length].to_vec();
        let mut replaced = false;
        for attribute_value in
            parse_attributes(&payload[header_length..]).expect("valid fixture attributes")
        {
            if attribute_value.kind == kind {
                assert!(!replaced, "fixture attribute must be unique");
                replaced = true;
                if let Some((raw_kind, replacement)) = replacement {
                    rebuilt.extend(attribute(raw_kind, replacement));
                }
            } else {
                rebuilt.extend(attribute(
                    attribute_value.kind | attribute_value.flags,
                    attribute_value.payload,
                ));
            }
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
