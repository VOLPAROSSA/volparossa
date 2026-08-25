//! Fixed link-state mutation and deletion-only rollback for the disposable topology.
//!
//! The production API has no free-form interface name, index, flag, address-
//! generation mode, or operation selector. Every binding is derived from one of
//! the two already-authorized [`FixedVethPair`] owners. The only forward path is
//! exactly four `EUI64 -> NONE` updates while every link is down, a fresh all-
//! `NONE` proof barrier, and then exactly four independent `IFF_UP` updates.
//!
//! The first request that may have reached the kernel makes the transaction
//! deletion-only. From that boundary neither `IFF_DOWN`, `RTM_DELADDR`, nor an
//! `EUI64` restoration is encoded. Failure and `Drop` cleanup delete parent-side
//! pair B followed by pair A and fail closed unless exact absence is established.

use std::{
    io,
    marker::PhantomData,
    mem::size_of,
    os::fd::{AsFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sched::{CloneFlags, setns},
};
use rustix::fs::{FsWord, Mode, OFlags, fstat, fstatfs, open};
use thiserror::Error;
use volparossa_linux_uapi::namespace_type;

use super::{
    ipv4::{FixedIpv4Address, Ipv4NamespaceIdentity},
    veth::{
        FIXED_VETH_MTU, FIXED_VETH_PEER_NAME, FIXED_VETH_QUEUE_COUNT, FIXED_VETH_TX_QUEUE_LENGTH,
        FixedVethEndpoint, FixedVethPair, VethTargetNamespaceIdentity,
    },
};

const LINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;

const MAX_NETLINK_DATAGRAM_BYTES: usize = 16 * 1024;
const MAX_ATTRIBUTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 64;
const MAX_RECONCILIATION_DELETE_ATTEMPTS: usize = 2;

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CAPPED: u16 = 0x0100;
const NLM_F_ACK_TLVS: u16 = 0x0200;

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;

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
const MAX_DEBIAN13_LINK_ATTRIBUTE: usize = 65;

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
const IFLA_XDP_ATTACHED: u16 = 2;

const AF_UNSPEC: u8 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const ARPHRD_ETHER: u16 = 1;

const IFF_UP: u32 = 0x0001;
const IFF_BROADCAST: u32 = 0x0002;
const IFF_RUNNING: u32 = 0x0040;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x1_0000;
const FIXED_DOWN_FLAGS: u32 = IFF_BROADCAST | IFF_MULTICAST;
const FIXED_UP_NO_CARRIER_FLAGS: u32 = FIXED_DOWN_FLAGS | IFF_UP;
const FIXED_UP_CARRIER_FLAGS: u32 = FIXED_UP_NO_CARRIER_FLAGS | IFF_RUNNING | IFF_LOWER_UP;

const IF_OPER_DOWN: u8 = 2;
const IF_OPER_LOWERLAYERDOWN: u8 = 3;
const IF_OPER_UP: u8 = 6;
const IN6_ADDR_GEN_MODE_EUI64: u8 = 0;
const IN6_ADDR_GEN_MODE_NONE: u8 = 1;

const ETHERNET_ADDRESS_BYTES: usize = 6;
const VETH_LINK_STATS_BYTES: usize = 24 * size_of::<u32>();
const VETH_LINK_STATS64_BYTES: usize = 25 * size_of::<u64>();
const VETH_LINK_IFMAP_BYTES: usize = 32;
const VETH_STATS_SEEN: u8 = 1 << 0;
const VETH_STATS64_SEEN: u8 = 1 << 1;
const VETH_IFMAP_SEEN: u8 = 1 << 2;
const VETH_REQUIRED_STRUCTS_SEEN: u8 = VETH_STATS_SEEN | VETH_STATS64_SEEN | VETH_IFMAP_SEEN;
const FIXED_ICMP_ECHO_PACKETS: u64 = 1;
const FIXED_ICMP_ECHO_ETHERNET_BYTES: u64 = crate::icmp::ETHERNET_ECHO_FRAME_BYTES;
const VETH_MIN_MTU: u32 = 68;
const VETH_MAX_MTU: u32 = 65_535;
const VETH_GSO_MAX_SEGMENTS: u32 = 65_535;
const VETH_OFFLOAD_MAX_SIZE: u32 = 65_536;
const DEFAULT_TSO_MAX_SIZE: u32 = 524_280;
const DEFAULT_TSO_MAX_SEGMENTS: u32 = 65_535;

/// One of the four fixed veth ends, in the canonical parent-A, parent-B,
/// endpoint-A, endpoint-B mutation order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedLinkEnd {
    /// Parent side of pair A.
    ParentA,
    /// Parent side of pair B.
    ParentB,
    /// Endpoint side of pair A.
    EndpointA,
    /// Endpoint side of pair B.
    EndpointB,
}

impl FixedLinkEnd {
    const fn index(self) -> usize {
        match self {
            Self::ParentA => 0,
            Self::ParentB => 1,
            Self::EndpointA => 2,
            Self::EndpointB => 3,
        }
    }

    const fn pair_index(self) -> usize {
        match self {
            Self::ParentA | Self::EndpointA => 0,
            Self::ParentB | Self::EndpointB => 1,
        }
    }

    const fn endpoint(self) -> FixedVethEndpoint {
        match self {
            Self::ParentA | Self::EndpointA => FixedVethEndpoint::A,
            Self::ParentB | Self::EndpointB => FixedVethEndpoint::B,
        }
    }

    const fn is_parent(self) -> bool {
        matches!(self, Self::ParentA | Self::ParentB)
    }
}

/// Bounded link mutation, readback, reconciliation, or deletion failure.
#[derive(Debug, Error)]
pub(crate) enum FixedLinkOperationError {
    /// A descriptor, socket, send, receive, wait, or namespace operation failed.
    #[error("fixed link operation {operation} failed: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Kernel or standard-library error.
        #[source]
        source: io::Error,
    },
    /// The kernel returned an exact negative ACK.
    #[error("kernel rejected fixed link operation {operation} with errno {errno}")]
    Kernel {
        /// Static operation label.
        operation: &'static str,
        /// Positive Linux errno.
        errno: i32,
    },
    /// A response, binding, phase, or retained object contradicted the protocol.
    #[error("fixed link proof was unsafe: {0}")]
    Unsafe(&'static str),
    /// A request or response exceeded a fixed resource bound.
    #[error("fixed link operation exceeded its resource bound")]
    Limit,
}

impl FixedLinkOperationError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn errno(operation: &'static str, errno: i32) -> Self {
        Self::Kernel { operation, errno }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NamespaceIdentity {
    const fn from_ipv4(value: Ipv4NamespaceIdentity) -> Self {
        Self {
            device: value.device(),
            inode: value.inode(),
        }
    }

    const fn from_veth(value: VethTargetNamespaceIdentity) -> Self {
        Self {
            device: value.device(),
            inode: value.inode(),
        }
    }
}

struct RetainedParentNamespace {
    descriptor: OwnedFd,
    identity: NamespaceIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinkBinding {
    ifindex: u32,
    peer_ifindex: u32,
    name: String,
    namespace: NamespaceIdentity,
    mac: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    peer_netnsid: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PairBinding {
    endpoint: FixedVethEndpoint,
    parent_name: String,
    parent_ifindex: u32,
    peer_ifindex: u32,
    target_namespace: NamespaceIdentity,
    parent_peer_netnsid: i32,
    parent_mac: [u8; ETHERNET_ADDRESS_BYTES],
    endpoint_mac: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    endpoint_peer_netnsid: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PairAuthorityIdentity {
    endpoint: FixedVethEndpoint,
    parent_name: String,
    parent_ifindex: u32,
    peer_ifindex: u32,
    target_namespace: NamespaceIdentity,
}

impl PairAuthorityIdentity {
    fn from_pair(pair: &FixedVethPair) -> Self {
        Self {
            endpoint: pair.endpoint(),
            parent_name: pair.parent_name().to_owned(),
            parent_ifindex: pair.parent_ifindex(),
            peer_ifindex: pair.peer_ifindex(),
            target_namespace: NamespaceIdentity::from_veth(pair.target_namespace_identity()),
        }
    }

    fn from_binding(binding: &PairBinding) -> Self {
        Self {
            endpoint: binding.endpoint,
            parent_name: binding.parent_name.clone(),
            parent_ifindex: binding.parent_ifindex,
            peer_ifindex: binding.peer_ifindex,
            target_namespace: binding.target_namespace,
        }
    }
}

/// Compact retained provenance for one endpoint route and both activated pairs.
///
/// This value can only be minted by an exact all-UP authority after both pair
/// arguments match its retained pair set. It also carries that authority's
/// retained parent namespace, so a different topology's post-delete proof
/// cannot retire the route journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FixedEndpointRoutePairLineage {
    parent_namespace: NamespaceIdentity,
    local_endpoint: FixedVethEndpoint,
    pairs: [PairBinding; 2],
}

/// Compact retained provenance for one activated pair used by the fixed
/// permanent-neighbour transaction.
///
/// Only [`AllLinksUp`] can mint this value, and only after the supplied affine
/// pair owner matches its exact retained pair binding. The endpoint MAC must
/// already have been pinned by the all-UP barrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FixedPermanentNeighbourPairLineage {
    parent_namespace: NamespaceIdentity,
    pair: PairBinding,
}

impl FixedPermanentNeighbourPairLineage {
    pub(super) fn endpoint(&self) -> FixedVethEndpoint {
        self.pair.endpoint
    }

    pub(super) fn parent_name(&self) -> &str {
        &self.pair.parent_name
    }

    pub(super) fn parent_ifindex(&self) -> u32 {
        self.pair.parent_ifindex
    }

    pub(super) fn endpoint_ifindex(&self) -> u32 {
        self.pair.peer_ifindex
    }

    pub(super) fn parent_namespace_parts(&self) -> (u64, u64) {
        (self.parent_namespace.device, self.parent_namespace.inode)
    }

    pub(super) fn endpoint_namespace_parts(&self) -> (u64, u64) {
        (
            self.pair.target_namespace.device,
            self.pair.target_namespace.inode,
        )
    }

    pub(super) fn parent_mac(&self) -> [u8; ETHERNET_ADDRESS_BYTES] {
        self.pair.parent_mac
    }

    pub(super) fn endpoint_mac(
        &self,
    ) -> Result<[u8; ETHERNET_ADDRESS_BYTES], FixedLinkOperationError> {
        self.pair
            .endpoint_mac
            .ok_or(FixedLinkOperationError::Unsafe(
                "all-UP pair lineage lacks a pinned endpoint MAC",
            ))
    }

    #[cfg(test)]
    pub(super) fn from_test_parts(endpoint: FixedVethEndpoint) -> Self {
        let (parent_ifindex, target_inode, parent_mac, endpoint_mac) = match endpoint {
            FixedVethEndpoint::A => (2, 20, [0x02, 1, 2, 3, 4, 5], [0x02, 6, 7, 8, 9, 10]),
            FixedVethEndpoint::B => (
                4,
                30,
                [0x02, 11, 12, 13, 14, 15],
                [0x02, 16, 17, 18, 19, 20],
            ),
        };
        Self {
            parent_namespace: NamespaceIdentity {
                device: 1,
                inode: 10,
            },
            pair: PairBinding {
                endpoint,
                parent_name: match endpoint {
                    FixedVethEndpoint::A => "vpa01234567",
                    FixedVethEndpoint::B => "vpb01234567",
                }
                .to_owned(),
                parent_ifindex,
                peer_ifindex: if endpoint == FixedVethEndpoint::A {
                    3
                } else {
                    5
                },
                target_namespace: NamespaceIdentity {
                    device: if endpoint == FixedVethEndpoint::A {
                        2
                    } else {
                        3
                    },
                    inode: target_inode,
                },
                parent_peer_netnsid: i32::from(endpoint == FixedVethEndpoint::B),
                parent_mac,
                endpoint_mac: Some(endpoint_mac),
                endpoint_peer_netnsid: Some(0),
            },
        }
    }
}

impl FixedEndpointRoutePairLineage {
    #[cfg(test)]
    pub(super) fn from_test_parts(local_endpoint: FixedVethEndpoint) -> Self {
        Self {
            parent_namespace: NamespaceIdentity {
                device: 1,
                inode: 10,
            },
            local_endpoint,
            pairs: [
                PairBinding {
                    endpoint: FixedVethEndpoint::A,
                    parent_name: "vpa01234567".to_owned(),
                    parent_ifindex: 2,
                    peer_ifindex: 3,
                    target_namespace: NamespaceIdentity {
                        device: 2,
                        inode: 20,
                    },
                    parent_peer_netnsid: 0,
                    parent_mac: [0x02, 1, 2, 3, 4, 5],
                    endpoint_mac: Some([0x02, 6, 7, 8, 9, 10]),
                    endpoint_peer_netnsid: Some(0),
                },
                PairBinding {
                    endpoint: FixedVethEndpoint::B,
                    parent_name: "vpb01234567".to_owned(),
                    parent_ifindex: 4,
                    peer_ifindex: 3,
                    target_namespace: NamespaceIdentity {
                        device: 3,
                        inode: 30,
                    },
                    parent_peer_netnsid: 1,
                    parent_mac: [0x02, 11, 12, 13, 14, 15],
                    endpoint_mac: Some([0x02, 16, 17, 18, 19, 20]),
                    endpoint_peer_netnsid: Some(0),
                },
            ],
        }
    }

    pub(super) fn local_endpoint(&self) -> FixedVethEndpoint {
        self.local_endpoint
    }

    pub(super) fn local_parent_name(&self) -> &str {
        &self.local_pair().parent_name
    }

    pub(super) fn local_parent_ifindex(&self) -> u32 {
        self.local_pair().parent_ifindex
    }

    pub(super) fn local_peer_ifindex(&self) -> u32 {
        self.local_pair().peer_ifindex
    }

    pub(super) fn local_target_namespace_matches(
        &self,
        identity: VethTargetNamespaceIdentity,
    ) -> bool {
        self.local_pair().target_namespace == NamespaceIdentity::from_veth(identity)
    }

    pub(super) fn remote_parent_name(&self) -> &str {
        &self.remote_pair().parent_name
    }

    pub(super) fn remote_parent_ifindex(&self) -> u32 {
        self.remote_pair().parent_ifindex
    }

    pub(super) fn remote_peer_ifindex(&self) -> u32 {
        self.remote_pair().peer_ifindex
    }

    pub(super) fn remote_target_namespace_matches(
        &self,
        identity: VethTargetNamespaceIdentity,
    ) -> bool {
        self.remote_pair().target_namespace == NamespaceIdentity::from_veth(identity)
    }

    fn local_pair(&self) -> &PairBinding {
        &self.pairs[endpoint_index(self.local_endpoint)]
    }

    fn remote_pair(&self) -> &PairBinding {
        &self.pairs[endpoint_index(opposite_endpoint(self.local_endpoint))]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkStage {
    DownEui64,
    AddrgenAmbiguous,
    DownNone,
    UpAmbiguous,
    UpObserved,
}

struct JournalCore {
    parent: RetainedParentNamespace,
    pairs: [PairBinding; 2],
    links: [LinkBinding; 4],
    stages: [LinkStage; 4],
    none_proofs: [bool; 4],
    up_proofs: [bool; 4],
    mutation_possible: bool,
    pairs_deleted: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine first-phase journal for four fixed `addrgenmode none` updates.
///
/// Dropping this value after any request could have reached the kernel performs
/// deletion-only B-then-A cleanup. Before that boundary it has no mutation to
/// clean and leaves the lower owners untouched.
#[must_use = "an armed fixed link mutation journal must be advanced or deleted"]
pub(crate) struct FixedLinkMutationJournal {
    core: Option<JournalCore>,
}

/// Affine proof that all four fixed ends were freshly observed down with IPv6
/// address generation disabled. Only this type exposes the link-up operation.
#[must_use = "the all-NONE barrier owns deletion-only rollback authority"]
pub(crate) struct AllLinksAddrgenNone {
    core: Option<JournalCore>,
}

/// Affine proof that all four fixed ends were freshly observed carrier-up with
/// `addrgenmode none` after four separate `IFF_UP` requests.
#[must_use = "the activated fixed links retain deletion-only rollback authority"]
pub(crate) struct AllLinksUp {
    core: Option<JournalCore>,
}

/// Consumer-visible cleanup boundary after a fallible fixed-link operation.
///
/// `Untouched` proves no request entered the possibly-sent boundary, so the
/// existing address/veth rollback path remains valid. `Deleted` proves the
/// transaction crossed that boundary and therefore performed the sole allowed
/// recovery: direct B-then-A pair deletion.
#[must_use = "link retirement determines whether lower rollback remains legal"]
pub(crate) enum FixedLinkRetirement {
    /// No link-state request could have reached the kernel.
    Untouched,
    /// Both parent-side pairs were deleted; endpoint and parent absence still
    /// need their explicit proof barrier.
    Deleted(PendingFixedPairAbsenceProof),
}

/// Post-delete proof builder. Parent-side pair absence is already exact; the
/// two endpoint namespaces still have to be visited and proven separately.
#[must_use = "both endpoint absences and parent restoration must be proven"]
pub(crate) struct PendingFixedPairAbsenceProof {
    parent_namespace: NamespaceIdentity,
    pairs: [PairBinding; 2],
    endpoint_absent: [bool; 2],
    parent_absent: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine proof that both exact fixed pairs were deleted B then A and that the
/// parent plus both retained endpoint namespaces contain neither fixed end.
///
/// This is the only token accepted by the proof-bound IPv4 and veth retirement
/// APIs. It deliberately exposes no raw deletion or disarm authority.
#[must_use = "the exact absence proof must retire its backing owners"]
pub(crate) struct FixedPairAbsenceProof {
    parent_namespace: NamespaceIdentity,
    pairs: [PairBinding; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedLinkMutationJournal {
    /// Freshly bind exact pair A and pair B while current in their parent
    /// namespace. No mutation occurs here.
    pub(crate) fn begin(
        pair_a: &FixedVethPair,
        pair_b: &FixedVethPair,
    ) -> Result<Self, FixedLinkOperationError> {
        let core = JournalCore::capture(pair_a, pair_b)?;
        Ok(Self { core: Some(core) })
    }

    /// Set one fixed end from EUI64 to NONE using an exact standalone SETLINK,
    /// ACK, and fresh readback. The caller must already be in that end's
    /// namespace and supply its exact pair owner.
    pub(crate) fn set_addrgen_none(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.core_mut().set_addrgen_none(end, pair)
    }

    /// Freshly re-prove one fixed end down with addrgen NONE. Calling this for
    /// all four ends is mandatory even when every SETLINK ACK was received.
    pub(crate) fn prove_addrgen_none(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.core_mut().prove_addrgen_none(end, pair)
    }

    /// Consume the first-phase journal only after all four independent proof
    /// bits are exact. The returned token is the sole link-up authority.
    pub(crate) fn finish_all_none_barrier(mut self) -> AllLinksAddrgenNone {
        let core = self.take_core();
        if core.require_all_none().is_err() {
            std::process::abort();
        }
        AllLinksAddrgenNone { core: Some(core) }
    }

    /// Consume the journal after success or failure and return the exact side of
    /// the irreversible boundary. Post-boundary cleanup is always B then A.
    pub(crate) fn into_retirement(mut self) -> FixedLinkRetirement {
        let core = self.take_core();
        if core.mutation_possible {
            FixedLinkRetirement::Deleted(core.delete_into_proof())
        } else {
            FixedLinkRetirement::Untouched
        }
    }

    fn core_mut(&mut self) -> &mut JournalCore {
        self.core.as_mut().unwrap_or_else(|| std::process::abort())
    }

    fn take_core(&mut self) -> JournalCore {
        self.core.take().unwrap_or_else(|| std::process::abort())
    }
}

impl AllLinksAddrgenNone {
    /// Verify the retained four-end barrier token before an independent network
    /// proof is attached by the enclosing typestate.
    pub(crate) fn verify(&self) -> Result<(), FixedLinkOperationError> {
        self.core().require_all_none()
    }

    /// Set one fixed end up through an attribute-free SETLINK whose change mask
    /// contains exactly `IFF_UP`, followed by fresh reconciliation.
    pub(crate) fn set_link_up(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.core_mut().set_link_up(end, pair)
    }

    /// Freshly prove one fixed end in the final carrier-up/NONE profile. This is
    /// intentionally separate from the per-request transitional readback.
    pub(crate) fn prove_link_up(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.core_mut().prove_link_up(end, pair)
    }

    /// Consume the barrier token only after all four exact final proofs.
    pub(crate) fn finish_all_up(mut self) -> AllLinksUp {
        let core = self.take_core();
        if core.require_all_up().is_err() {
            std::process::abort();
        }
        AllLinksUp { core: Some(core) }
    }

    /// Consume the post-barrier state through mandatory B-then-A deletion.
    pub(crate) fn into_retirement(mut self) -> FixedLinkRetirement {
        FixedLinkRetirement::Deleted(self.take_core().delete_into_proof())
    }

    fn core(&self) -> &JournalCore {
        self.core.as_ref().unwrap_or_else(|| std::process::abort())
    }

    fn core_mut(&mut self) -> &mut JournalCore {
        self.core.as_mut().unwrap_or_else(|| std::process::abort())
    }

    fn take_core(&mut self) -> JournalCore {
        self.core.take().unwrap_or_else(|| std::process::abort())
    }
}

impl AllLinksUp {
    /// Re-prove all four per-end final proof bits have been retained.
    pub(crate) fn verify(&self) -> Result<(), FixedLinkOperationError> {
        self.core().require_all_up()
    }

    /// Bind both caller-retained pair owners and the retained parent
    /// namespace to one compact endpoint-route lineage.
    pub(super) fn bind_endpoint_route_pairs(
        &self,
        local_pair: &FixedVethPair,
        remote_pair: &FixedVethPair,
    ) -> Result<FixedEndpointRoutePairLineage, FixedLinkOperationError> {
        let core = self.core();
        core.require_all_up()?;
        core.parent.verify()?;
        bind_endpoint_route_pair_lineage(
            core.parent.identity,
            &core.pairs,
            &[
                PairAuthorityIdentity::from_pair(local_pair),
                PairAuthorityIdentity::from_pair(remote_pair),
            ],
        )
    }

    /// Bind one caller-retained pair owner to its exact all-UP MAC, namespace,
    /// and interface lineage for permanent-neighbour derivation.
    pub(super) fn bind_permanent_neighbour_pair(
        &self,
        pair: &FixedVethPair,
    ) -> Result<FixedPermanentNeighbourPairLineage, FixedLinkOperationError> {
        let core = self.core();
        core.require_all_up()?;
        core.parent.verify()?;
        let index = endpoint_index(pair.endpoint());
        let retained = &core.pairs[index];
        if PairAuthorityIdentity::from_pair(pair) != PairAuthorityIdentity::from_binding(retained)
            || retained.endpoint_mac.is_none()
        {
            return Err(FixedLinkOperationError::Unsafe(
                "all-UP authority does not bind the permanent-neighbour pair argument",
            ));
        }
        Ok(FixedPermanentNeighbourPairLineage {
            parent_namespace: core.parent.identity,
            pair: retained.clone(),
        })
    }

    /// Consume the activated state through mandatory B-then-A deletion.
    pub(crate) fn into_retirement(mut self) -> FixedLinkRetirement {
        FixedLinkRetirement::Deleted(self.take_core().delete_into_proof())
    }

    /// Consume the activated state after the one fixed ICMP echo proof.
    ///
    /// This is the sole lifecycle entry point whose pre-delete readbacks admit
    /// the exact one-packet/74-byte RX and TX statistics profile. Ordinary
    /// retirement remains strictly bound to zero statistics.
    pub(crate) fn into_fixed_icmp_echo_retirement(mut self) -> FixedLinkRetirement {
        FixedLinkRetirement::Deleted(self.take_core().delete_fixed_icmp_echo_into_proof())
    }

    /// Consume the activated state after a fixed ICMP send might have occurred.
    ///
    /// Each RX/TX direction must be coherently untouched (`0/0`) or carry the
    /// sole allowed echo frame (`1/74`). No other counters are admitted.
    pub(crate) fn into_fixed_icmp_cleanup_retirement(mut self) -> FixedLinkRetirement {
        FixedLinkRetirement::Deleted(self.take_core().delete_fixed_icmp_cleanup_into_proof())
    }

    fn core(&self) -> &JournalCore {
        self.core.as_ref().unwrap_or_else(|| std::process::abort())
    }

    fn take_core(&mut self) -> JournalCore {
        self.core.take().unwrap_or_else(|| std::process::abort())
    }
}

impl PendingFixedPairAbsenceProof {
    /// In the currently visited endpoint namespace, prove that its exact peer
    /// name and ifindex are both absent.
    pub(crate) fn prove_endpoint_absence(
        &mut self,
        endpoint: FixedVethEndpoint,
    ) -> Result<(), FixedLinkOperationError> {
        let index = endpoint_index(endpoint);
        if (endpoint == FixedVethEndpoint::A && !self.endpoint_absent[1]) || self.endpoint_absent[0]
        {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed endpoint absence proof order is not B then A",
            ));
        }
        require_current_namespace(self.pairs[index].target_namespace)?;
        require_link_absent(
            self.pairs[index].peer_ifindex,
            FIXED_VETH_PEER_NAME,
            "prove deleted fixed endpoint",
        )?;
        self.endpoint_absent[index] = true;
        Ok(())
    }

    /// In the retained parent namespace, re-prove B/A absence and finish the
    /// affine proof only after both endpoint visits succeeded.
    pub(crate) fn prove_parent_absence(&mut self) -> Result<(), FixedLinkOperationError> {
        require_current_namespace(self.parent_namespace)?;
        if self.endpoint_absent != [true, true] {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed endpoint absence proof is incomplete",
            ));
        }
        for pair in self.pairs.iter().rev() {
            require_link_absent(
                pair.parent_ifindex,
                &pair.parent_name,
                "reprove deleted fixed parent",
            )?;
        }
        self.parent_absent = true;
        Ok(())
    }

    /// Infallibly consume a fully prevalidated parent/A/B absence builder.
    /// External failures occur in the preceding borrowed proof methods, so the
    /// builder remains available for retry until this point.
    pub(crate) fn finish(self) -> FixedPairAbsenceProof {
        if self.endpoint_absent != [true, true] || !self.parent_absent {
            std::process::abort();
        }
        FixedPairAbsenceProof {
            parent_namespace: self.parent_namespace,
            pairs: self.pairs,
            _thread_bound: PhantomData,
        }
    }
}

impl FixedPairAbsenceProof {
    pub(super) fn validates_veth_pair(
        &self,
        endpoint: FixedVethEndpoint,
        parent_name: &str,
        parent_ifindex: u32,
        peer_ifindex: u32,
        peer_netnsid: i32,
        target_namespace: VethTargetNamespaceIdentity,
    ) -> bool {
        let pair = &self.pairs[endpoint_index(endpoint)];
        pair.endpoint == endpoint
            && pair.parent_name == parent_name
            && pair.parent_ifindex == parent_ifindex
            && pair.peer_ifindex == peer_ifindex
            && pair.parent_peer_netnsid == peer_netnsid
            && pair.target_namespace == NamespaceIdentity::from_veth(target_namespace)
    }

    pub(super) fn validates_ipv4_address(
        &self,
        address: FixedIpv4Address,
        ifindex: u32,
        interface_name: &str,
        mutation_namespace: Ipv4NamespaceIdentity,
        target_namespace: Ipv4NamespaceIdentity,
    ) -> bool {
        let end = fixed_link_end_for_address(address);
        let pair = &self.pairs[end.pair_index()];
        let expected_index = if end.is_parent() {
            pair.parent_ifindex
        } else {
            pair.peer_ifindex
        };
        let expected_name = if end.is_parent() {
            pair.parent_name.as_str()
        } else {
            FIXED_VETH_PEER_NAME
        };
        let expected_namespace = if end.is_parent() {
            self.parent_namespace
        } else {
            pair.target_namespace
        };
        pair.endpoint == end.endpoint()
            && ifindex == expected_index
            && interface_name == expected_name
            && NamespaceIdentity::from_ipv4(mutation_namespace) == expected_namespace
            && NamespaceIdentity::from_ipv4(target_namespace) == pair.target_namespace
    }

    pub(super) fn validates_endpoint_route(&self, lineage: &FixedEndpointRoutePairLineage) -> bool {
        self.parent_namespace == lineage.parent_namespace && self.pairs == lineage.pairs
    }

    pub(super) fn validates_permanent_neighbour(
        &self,
        lineage: &FixedPermanentNeighbourPairLineage,
    ) -> bool {
        self.parent_namespace == lineage.parent_namespace
            && self.pairs[endpoint_index(lineage.pair.endpoint)] == lineage.pair
    }
}

const fn fixed_link_end_for_address(address: FixedIpv4Address) -> FixedLinkEnd {
    match address {
        FixedIpv4Address::ParentA => FixedLinkEnd::ParentA,
        FixedIpv4Address::ParentB => FixedLinkEnd::ParentB,
        FixedIpv4Address::EndpointA => FixedLinkEnd::EndpointA,
        FixedIpv4Address::EndpointB => FixedLinkEnd::EndpointB,
    }
}

const fn endpoint_index(endpoint: FixedVethEndpoint) -> usize {
    match endpoint {
        FixedVethEndpoint::A => 0,
        FixedVethEndpoint::B => 1,
    }
}

const fn opposite_endpoint(endpoint: FixedVethEndpoint) -> FixedVethEndpoint {
    match endpoint {
        FixedVethEndpoint::A => FixedVethEndpoint::B,
        FixedVethEndpoint::B => FixedVethEndpoint::A,
    }
}

fn bind_endpoint_route_pair_lineage(
    parent_namespace: NamespaceIdentity,
    retained_pairs: &[PairBinding; 2],
    supplied_pairs: &[PairAuthorityIdentity; 2],
) -> Result<FixedEndpointRoutePairLineage, FixedLinkOperationError> {
    let local_endpoint = supplied_pairs[0].endpoint;
    if supplied_pairs[1].endpoint != opposite_endpoint(local_endpoint)
        || supplied_pairs[0]
            != PairAuthorityIdentity::from_binding(&retained_pairs[endpoint_index(local_endpoint)])
        || supplied_pairs[1]
            != PairAuthorityIdentity::from_binding(
                &retained_pairs[endpoint_index(opposite_endpoint(local_endpoint))],
            )
    {
        return Err(FixedLinkOperationError::Unsafe(
            "all-UP authority does not bind both endpoint-route pair arguments",
        ));
    }
    Ok(FixedEndpointRoutePairLineage {
        parent_namespace,
        local_endpoint,
        pairs: retained_pairs.clone(),
    })
}

fn capture_pair_binding(
    pair: &FixedVethPair,
    endpoint: FixedVethEndpoint,
) -> Result<PairBinding, FixedLinkOperationError> {
    require_pair_endpoint(pair, endpoint)?;
    pair.verify().map_err(|_| {
        FixedLinkOperationError::Unsafe("fixed pair failed its pre-link-state proof")
    })?;
    let observed = require_expected_link(
        observe_link_by_ifindex(pair.parent_ifindex())?,
        pair.parent_ifindex(),
        pair.peer_ifindex(),
        pair.parent_name(),
        None,
        None,
        &[ObservedProfile::DownEui64],
    )?;
    Ok(PairBinding {
        endpoint,
        parent_name: pair.parent_name().to_owned(),
        parent_ifindex: pair.parent_ifindex(),
        peer_ifindex: pair.peer_ifindex(),
        target_namespace: NamespaceIdentity::from_veth(pair.target_namespace_identity()),
        parent_peer_netnsid: observed.peer_netnsid,
        parent_mac: observed.mac,
        endpoint_mac: None,
        endpoint_peer_netnsid: None,
    })
}

fn require_distinct_pair_bindings(pairs: &[PairBinding; 2]) -> Result<(), FixedLinkOperationError> {
    if pairs[0].parent_peer_netnsid == pairs[1].parent_peer_netnsid
        || pairs[0].parent_mac == pairs[1].parent_mac
        || pairs[0].parent_ifindex == pairs[1].parent_ifindex
        || pairs[0].parent_name == pairs[1].parent_name
    {
        Err(FixedLinkOperationError::Unsafe(
            "fixed pair bindings are not distinct",
        ))
    } else {
        Ok(())
    }
}

fn link_bindings(pairs: &[PairBinding; 2], parent: NamespaceIdentity) -> [LinkBinding; 4] {
    [
        parent_link_binding(&pairs[0], parent),
        parent_link_binding(&pairs[1], parent),
        endpoint_link_binding(&pairs[0]),
        endpoint_link_binding(&pairs[1]),
    ]
}

fn parent_link_binding(pair: &PairBinding, namespace: NamespaceIdentity) -> LinkBinding {
    LinkBinding {
        ifindex: pair.parent_ifindex,
        peer_ifindex: pair.peer_ifindex,
        name: pair.parent_name.clone(),
        namespace,
        mac: Some(pair.parent_mac),
        peer_netnsid: Some(pair.parent_peer_netnsid),
    }
}

fn endpoint_link_binding(pair: &PairBinding) -> LinkBinding {
    LinkBinding {
        ifindex: pair.peer_ifindex,
        peer_ifindex: pair.parent_ifindex,
        name: FIXED_VETH_PEER_NAME.to_owned(),
        namespace: pair.target_namespace,
        mac: None,
        peer_netnsid: None,
    }
}

impl JournalCore {
    fn capture(
        pair_a: &FixedVethPair,
        pair_b: &FixedVethPair,
    ) -> Result<Self, FixedLinkOperationError> {
        let parent = RetainedParentNamespace::capture_current()?;
        let pairs = [
            capture_pair_binding(pair_a, FixedVethEndpoint::A)?,
            capture_pair_binding(pair_b, FixedVethEndpoint::B)?,
        ];
        if pairs[0].target_namespace == pairs[1].target_namespace
            || pairs[0].target_namespace == parent.identity
            || pairs[1].target_namespace == parent.identity
        {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed link namespaces are not three distinct nsfs objects",
            ));
        }
        require_distinct_pair_bindings(&pairs)?;
        let links = link_bindings(&pairs, parent.identity);
        Ok(Self {
            parent,
            pairs,
            links,
            stages: [LinkStage::DownEui64; 4],
            none_proofs: [false; 4],
            up_proofs: [false; 4],
            mutation_possible: false,
            pairs_deleted: false,
            _thread_bound: PhantomData,
        })
    }

    fn set_addrgen_none(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.require_next_addrgen_end(end)?;
        self.verify_pair_argument(end, pair)?;
        self.observe_and_pin(end, &[ObservedProfile::DownEui64])?;

        let index = end.index();
        let binding = self.links[index].clone();
        let deadline = Deadline::after(LINK_OPERATION_TIMEOUT)?;
        let mut client = NetlinkClient::connect(deadline)?;
        let sequence = client.next_sequence()?;
        let request = encode_addrgen_none_request(sequence, binding.ifindex)?;

        // The irreversible boundary is crossed only once a complete datagram
        // was sent or a short write made kernel receipt ambiguous. A definite
        // pre-send failure on the first update remains `Untouched` so the
        // enclosing owner may still use the ordinary lower rollback path.
        let acknowledgement = match send_bounded(&client.socket, &request, deadline) {
            Ok(()) => {
                self.mutation_possible = true;
                self.stages[index] = LinkStage::AddrgenAmbiguous;
                receive_one(&client.socket, deadline)
                    .and_then(|reply| parse_ack(&reply, client.local_port, &request))
            }
            Err(SendFailure::NotSent(source)) => Err(source),
            Err(SendFailure::PossiblySent(source)) => {
                self.mutation_possible = true;
                self.stages[index] = LinkStage::AddrgenAmbiguous;
                Err(source)
            }
        };
        drop(client);
        let observed = self.observe_and_pin(
            end,
            &[ObservedProfile::DownEui64, ObservedProfile::DownNone],
        );
        match (acknowledgement, observed) {
            (_, Ok(ObservedProfile::DownNone)) => {
                self.stages[index] = LinkStage::DownNone;
                Ok(())
            }
            (Ok(Ack::Rejected(errno)), Ok(ObservedProfile::DownEui64)) => Err(
                FixedLinkOperationError::errno("set fixed addrgenmode none", errno),
            ),
            (Err(source), Ok(ObservedProfile::DownEui64)) | (_, Err(source)) => Err(source),
            (Ok(Ack::Success), Ok(ObservedProfile::DownEui64)) => {
                Err(FixedLinkOperationError::Unsafe(
                    "ACKed addrgenmode NONE update did not take effect",
                ))
            }
            (_, Ok(_)) => Err(FixedLinkOperationError::Unsafe(
                "addrgenmode reconciliation returned an impossible profile",
            )),
        }
    }

    fn prove_addrgen_none(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        let index = end.index();
        if self.stages[index] != LinkStage::DownNone {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed addrgenmode proof preceded its exact update",
            ));
        }
        let expected_proof_index = self.none_proofs.iter().position(|proved| !proved).ok_or(
            FixedLinkOperationError::Unsafe("fixed addrgenmode proof barrier is already complete"),
        )?;
        if index != expected_proof_index {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed addrgenmode proof order changed",
            ));
        }
        self.verify_pair_argument(end, pair)?;
        self.observe_and_pin(end, &[ObservedProfile::DownNone])?;
        self.none_proofs[index] = true;
        Ok(())
    }

    fn require_all_none(&self) -> Result<(), FixedLinkOperationError> {
        if self.mutation_possible
            && self.stages == [LinkStage::DownNone; 4]
            && self.none_proofs == [true; 4]
            && self.up_proofs == [false; 4]
        {
            Ok(())
        } else {
            Err(FixedLinkOperationError::Unsafe(
                "all-NONE link barrier is incomplete",
            ))
        }
    }

    fn set_link_up(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        self.require_up_staging_authority()?;
        self.require_next_up_end(end)?;
        self.verify_pair_argument(end, pair)?;
        self.observe_and_pin(end, &[ObservedProfile::DownNone])?;

        let index = end.index();
        let binding = self.links[index].clone();
        let deadline = Deadline::after(LINK_OPERATION_TIMEOUT)?;
        let mut client = NetlinkClient::connect(deadline)?;
        let sequence = client.next_sequence()?;
        let request = encode_link_up_request(sequence, binding.ifindex)?;
        self.stages[index] = LinkStage::UpAmbiguous;
        let acknowledgement = transact_ack(&client.socket, client.local_port, &request, deadline);
        drop(client);
        let transitioned = match end {
            FixedLinkEnd::ParentA => ObservedProfile::UpNoCarrierDownNone,
            FixedLinkEnd::ParentB => ObservedProfile::UpNoCarrierLowerLayerDownNone,
            FixedLinkEnd::EndpointA | FixedLinkEnd::EndpointB => ObservedProfile::UpCarrierNone,
        };
        let observed = self.observe_and_pin(end, &[ObservedProfile::DownNone, transitioned]);
        match (acknowledgement, observed) {
            (_, Ok(profile)) if profile == transitioned => {
                self.stages[index] = LinkStage::UpObserved;
                Ok(())
            }
            (Ok(Ack::Rejected(errno)), Ok(ObservedProfile::DownNone)) => {
                Err(FixedLinkOperationError::errno("set fixed link up", errno))
            }
            (Err(source), Ok(ObservedProfile::DownNone)) | (_, Err(source)) => Err(source),
            (Ok(Ack::Success), Ok(ObservedProfile::DownNone)) => Err(
                FixedLinkOperationError::Unsafe("ACKed IFF_UP update did not take effect"),
            ),
            (_, Ok(_)) => Err(FixedLinkOperationError::Unsafe(
                "IFF_UP reconciliation returned an impossible profile",
            )),
        }
    }

    fn prove_link_up(
        &mut self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        let index = end.index();
        if self.stages != [LinkStage::UpObserved; 4] {
            return Err(FixedLinkOperationError::Unsafe(
                "final link-up proof began before four observed updates",
            ));
        }
        let expected_proof_index = self.up_proofs.iter().position(|proved| !proved).ok_or(
            FixedLinkOperationError::Unsafe("final fixed link-up proof is already complete"),
        )?;
        if index != expected_proof_index {
            return Err(FixedLinkOperationError::Unsafe(
                "final fixed link-up proof order changed",
            ));
        }
        self.verify_pair_argument(end, pair)?;
        self.observe_and_pin(end, &[ObservedProfile::UpCarrierNone])?;
        self.up_proofs[index] = true;
        Ok(())
    }

    fn require_all_up(&self) -> Result<(), FixedLinkOperationError> {
        if self.mutation_possible
            && self.stages == [LinkStage::UpObserved; 4]
            && self.none_proofs == [true; 4]
            && self.up_proofs == [true; 4]
        {
            Ok(())
        } else {
            Err(FixedLinkOperationError::Unsafe(
                "all-UP link proof barrier is incomplete",
            ))
        }
    }

    fn require_next_addrgen_end(&self, end: FixedLinkEnd) -> Result<(), FixedLinkOperationError> {
        let next = self
            .stages
            .iter()
            .position(|stage| *stage == LinkStage::DownEui64)
            .ok_or(FixedLinkOperationError::Unsafe(
                "four fixed addrgenmode updates are already staged",
            ))?;
        if end.index() != next
            || self.stages[..next]
                .iter()
                .any(|stage| *stage != LinkStage::DownNone)
        {
            Err(FixedLinkOperationError::Unsafe(
                "fixed addrgenmode mutation order changed",
            ))
        } else {
            Ok(())
        }
    }

    fn require_next_up_end(&self, end: FixedLinkEnd) -> Result<(), FixedLinkOperationError> {
        let next = self
            .stages
            .iter()
            .position(|stage| *stage == LinkStage::DownNone)
            .ok_or(FixedLinkOperationError::Unsafe(
                "four fixed IFF_UP updates are already staged",
            ))?;
        if end.index() != next
            || self.stages[..next]
                .iter()
                .any(|stage| *stage != LinkStage::UpObserved)
        {
            Err(FixedLinkOperationError::Unsafe(
                "fixed IFF_UP mutation order changed",
            ))
        } else {
            Ok(())
        }
    }

    fn require_up_staging_authority(&self) -> Result<(), FixedLinkOperationError> {
        if has_up_staging_authority(
            self.mutation_possible,
            self.stages,
            self.none_proofs,
            self.up_proofs,
        ) {
            Ok(())
        } else {
            Err(FixedLinkOperationError::Unsafe(
                "fixed IFF_UP staging authority is incomplete",
            ))
        }
    }

    fn verify_pair_argument(
        &self,
        end: FixedLinkEnd,
        pair: &FixedVethPair,
    ) -> Result<(), FixedLinkOperationError> {
        let retained = &self.pairs[end.pair_index()];
        if pair.endpoint() != end.endpoint()
            || pair.parent_name() != retained.parent_name
            || pair.parent_ifindex() != retained.parent_ifindex
            || pair.peer_ifindex() != retained.peer_ifindex
            || NamespaceIdentity::from_veth(pair.target_namespace_identity())
                != retained.target_namespace
        {
            Err(FixedLinkOperationError::Unsafe(
                "fixed link operation received a different pair authority",
            ))
        } else {
            Ok(())
        }
    }

    fn observe_and_pin(
        &mut self,
        end: FixedLinkEnd,
        allowed_profiles: &[ObservedProfile],
    ) -> Result<ObservedProfile, FixedLinkOperationError> {
        let index = end.index();
        let pair_index = end.pair_index();
        let binding = &self.links[index];
        require_current_namespace(binding.namespace)?;
        let observed = require_expected_link(
            observe_link_by_ifindex(binding.ifindex)?,
            binding.ifindex,
            binding.peer_ifindex,
            &binding.name,
            binding.mac,
            binding.peer_netnsid,
            allowed_profiles,
        )?;
        if !end.is_parent() && self.links[index].mac.is_none() {
            self.links[index].mac = Some(observed.mac);
            self.links[index].peer_netnsid = Some(observed.peer_netnsid);
            self.pairs[pair_index].endpoint_mac = Some(observed.mac);
            self.pairs[pair_index].endpoint_peer_netnsid = Some(observed.peer_netnsid);
        }
        Ok(observed.profile)
    }

    fn delete_into_proof(mut self) -> PendingFixedPairAbsenceProof {
        self.delete_into_proof_with_statistics(RequiredLinkStatistics::Zero)
    }

    fn delete_fixed_icmp_echo_into_proof(mut self) -> PendingFixedPairAbsenceProof {
        self.delete_into_proof_with_statistics(RequiredLinkStatistics::FixedIcmpEcho)
    }

    fn delete_fixed_icmp_cleanup_into_proof(mut self) -> PendingFixedPairAbsenceProof {
        self.delete_into_proof_with_statistics(RequiredLinkStatistics::FixedIcmpCleanup)
    }

    fn delete_into_proof_with_statistics(
        &mut self,
        required_statistics: RequiredLinkStatistics,
    ) -> PendingFixedPairAbsenceProof {
        if !self.mutation_possible {
            std::process::abort();
        }
        if self
            .ensure_deleted_with_statistics(required_statistics)
            .is_err()
        {
            std::process::abort();
        }
        let proof = PendingFixedPairAbsenceProof {
            parent_namespace: self.parent.identity,
            pairs: self.pairs.clone(),
            endpoint_absent: [false, false],
            parent_absent: false,
            _thread_bound: PhantomData,
        };
        self.pairs_deleted = true;
        proof
    }

    fn ensure_deleted(&mut self) -> Result<(), FixedLinkOperationError> {
        self.ensure_deleted_with_statistics(RequiredLinkStatistics::Zero)
    }

    fn ensure_deleted_with_statistics(
        &mut self,
        required_statistics: RequiredLinkStatistics,
    ) -> Result<(), FixedLinkOperationError> {
        self.parent.make_current()?;
        for index in (0..2).rev() {
            self.reconcile_pair_deletion(index, required_statistics)?;
        }
        for pair in self.pairs.iter().rev() {
            require_link_absent(
                pair.parent_ifindex,
                &pair.parent_name,
                "prove fixed parent deletion",
            )?;
        }
        self.pairs_deleted = true;
        Ok(())
    }

    fn reconcile_pair_deletion(
        &self,
        pair_index: usize,
        required_statistics: RequiredLinkStatistics,
    ) -> Result<(), FixedLinkOperationError> {
        let pair = &self.pairs[pair_index];
        let parent_end = if pair_index == 0 {
            FixedLinkEnd::ParentA
        } else {
            FixedLinkEnd::ParentB
        };
        let allowed = deletion_profiles(self.stages[parent_end.index()]);
        for _ in 0..MAX_RECONCILIATION_DELETE_ATTEMPTS {
            let Some(observed) =
                observe_link_by_ifindex_with_statistics(pair.parent_ifindex, required_statistics)?
            else {
                require_link_absent(
                    pair.parent_ifindex,
                    &pair.parent_name,
                    "reconcile absent fixed parent",
                )?;
                return Ok(());
            };
            require_expected_link(
                Some(observed),
                pair.parent_ifindex,
                pair.peer_ifindex,
                &pair.parent_name,
                Some(pair.parent_mac),
                Some(pair.parent_peer_netnsid),
                allowed,
            )?;
            let deadline = Deadline::after(LINK_OPERATION_TIMEOUT)?;
            let mut client = NetlinkClient::connect(deadline)?;
            let sequence = client.next_sequence()?;
            let request = encode_delete_link_request(sequence, pair.parent_ifindex)?;
            let _ = transact_ack(&client.socket, client.local_port, &request, deadline);
            drop(client);
            if observe_link_by_ifindex_with_statistics(pair.parent_ifindex, required_statistics)?
                .is_none()
            {
                require_link_absent(
                    pair.parent_ifindex,
                    &pair.parent_name,
                    "reconcile deleted fixed parent",
                )?;
                return Ok(());
            }
        }
        match observe_link_by_ifindex_with_statistics(pair.parent_ifindex, required_statistics)? {
            None => require_link_absent(
                pair.parent_ifindex,
                &pair.parent_name,
                "final fixed parent absence",
            ),
            Some(observed) => {
                require_expected_link(
                    Some(observed),
                    pair.parent_ifindex,
                    pair.peer_ifindex,
                    &pair.parent_name,
                    Some(pair.parent_mac),
                    Some(pair.parent_peer_netnsid),
                    allowed,
                )?;
                Err(FixedLinkOperationError::Unsafe(
                    "fixed pair deletion could not prove absence",
                ))
            }
        }
    }
}

fn has_up_staging_authority(
    mutation_possible: bool,
    stages: [LinkStage; 4],
    none_proofs: [bool; 4],
    up_proofs: [bool; 4],
) -> bool {
    if !mutation_possible || none_proofs != [true; 4] || up_proofs != [false; 4] {
        return false;
    }
    let completed = stages
        .iter()
        .position(|stage| *stage != LinkStage::UpObserved)
        .unwrap_or(stages.len());
    stages[..completed]
        .iter()
        .all(|stage| *stage == LinkStage::UpObserved)
        && stages[completed..]
            .iter()
            .all(|stage| *stage == LinkStage::DownNone)
}

impl Drop for JournalCore {
    fn drop(&mut self) {
        if self.mutation_possible && !self.pairs_deleted && self.ensure_deleted().is_err() {
            std::process::abort();
        }
    }
}

fn deletion_profiles(stage: LinkStage) -> &'static [ObservedProfile] {
    match stage {
        LinkStage::DownEui64 => &[ObservedProfile::DownEui64],
        LinkStage::AddrgenAmbiguous => &[ObservedProfile::DownEui64, ObservedProfile::DownNone],
        LinkStage::DownNone => &[ObservedProfile::DownNone],
        LinkStage::UpAmbiguous => &[
            ObservedProfile::DownNone,
            ObservedProfile::UpNoCarrierDownNone,
            ObservedProfile::UpNoCarrierLowerLayerDownNone,
            ObservedProfile::UpCarrierNone,
        ],
        LinkStage::UpObserved => &[
            ObservedProfile::UpNoCarrierDownNone,
            ObservedProfile::UpNoCarrierLowerLayerDownNone,
            ObservedProfile::UpCarrierNone,
        ],
    }
}

fn require_pair_endpoint(
    pair: &FixedVethPair,
    expected: FixedVethEndpoint,
) -> Result<(), FixedLinkOperationError> {
    if pair.endpoint() == expected {
        Ok(())
    } else {
        Err(FixedLinkOperationError::Unsafe(
            "fixed pair order changed before link-state capture",
        ))
    }
}

impl RetainedParentNamespace {
    fn capture_current() -> Result<Self, FixedLinkOperationError> {
        let descriptor = open_current_network_namespace()?;
        let identity = object_identity(&descriptor)?;
        Ok(Self {
            descriptor,
            identity,
        })
    }

    fn verify(&self) -> Result<(), FixedLinkOperationError> {
        validate_namespace_descriptor(&self.descriptor)?;
        if object_identity(&self.descriptor)? != self.identity {
            return Err(FixedLinkOperationError::Unsafe(
                "retained parent network namespace identity changed",
            ));
        }
        Ok(())
    }

    fn make_current(&self) -> Result<(), FixedLinkOperationError> {
        self.verify()?;
        if current_namespace_identity()? != self.identity {
            setns(&self.descriptor, CloneFlags::CLONE_NEWNET).map_err(|source| {
                FixedLinkOperationError::io(
                    "restore retained parent network namespace",
                    io::Error::from_raw_os_error(source as i32),
                )
            })?;
        }
        require_current_namespace(self.identity)
    }
}

fn validate_namespace_descriptor<Fd: AsFd>(descriptor: &Fd) -> Result<(), FixedLinkOperationError> {
    if fstatfs(descriptor)
        .map_err(|source| rustix_io("inspect network namespace filesystem", source))?
        .f_type
        != NSFS_MAGIC
        || namespace_type(descriptor).map_err(|source| {
            FixedLinkOperationError::io("inspect network namespace type", source)
        })? != libc::CLONE_NEWNET
    {
        return Err(FixedLinkOperationError::Unsafe(
            "network namespace descriptor is not exact nsfs CLONE_NEWNET",
        ));
    }
    Ok(())
}

fn open_current_network_namespace() -> Result<OwnedFd, FixedLinkOperationError> {
    let descriptor = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| rustix_io("open current network namespace", source))?;
    validate_namespace_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn current_namespace_identity() -> Result<NamespaceIdentity, FixedLinkOperationError> {
    object_identity(&open_current_network_namespace()?)
}

fn object_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<NamespaceIdentity, FixedLinkOperationError> {
    let metadata = fstat(descriptor)
        .map_err(|source| rustix_io("measure network namespace identity", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "network namespace identity is zero",
        ));
    }
    Ok(NamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn require_current_namespace(expected: NamespaceIdentity) -> Result<(), FixedLinkOperationError> {
    if current_namespace_identity()? == expected {
        Ok(())
    } else {
        Err(FixedLinkOperationError::Unsafe(
            "fixed link operation is in the wrong network namespace",
        ))
    }
}

fn rustix_io(operation: &'static str, source: rustix::io::Errno) -> FixedLinkOperationError {
    FixedLinkOperationError::io(
        operation,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedProfile {
    DownEui64,
    DownNone,
    UpNoCarrierDownNone,
    UpNoCarrierLowerLayerDownNone,
    UpCarrierNone,
}

/// Statistics profile admitted by one exact link readback path.
///
/// The two fixed-ICMP variants are private to explicitly named post-send
/// retirement transitions. All ordinary activation, reconciliation, rollback,
/// and drop paths continue to select `Zero`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequiredLinkStatistics {
    Zero,
    FixedIcmpEcho,
    FixedIcmpCleanup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedLink {
    ifindex: u32,
    peer_ifindex: u32,
    name: String,
    mac: [u8; ETHERNET_ADDRESS_BYTES],
    peer_netnsid: i32,
    profile: ObservedProfile,
}

#[derive(Default)]
struct LinkAttributes<'a> {
    name: Option<&'a [u8]>,
    peer_ifindex: Option<u32>,
    peer_netnsid: Option<i32>,
    address: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    broadcast: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    permanent_address: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    mtu: Option<u32>,
    queue_length: Option<u32>,
    transmit_queues: Option<u32>,
    receive_queues: Option<u32>,
    qdisc: Option<&'a [u8]>,
    operstate: Option<u8>,
    carrier: Option<u8>,
    carrier_changes: Option<u32>,
    carrier_up_count: Option<u32>,
    carrier_down_count: Option<u32>,
    linkmode: Option<u8>,
    group: Option<u32>,
    promiscuity: Option<u32>,
    allmulti: Option<u32>,
    protocol_down: Option<u8>,
    addrgen_mode: Option<u8>,
    fixed_icmp_cleanup_statistics32: Option<[bool; 2]>,
    fixed_icmp_cleanup_statistics64: Option<[bool; 2]>,
    required_structs_seen: u8,
    link_info_seen: bool,
    xdp_seen: bool,
}

fn require_expected_link(
    observed: Option<ObservedLink>,
    ifindex: u32,
    peer_ifindex: u32,
    name: &str,
    mac: Option<[u8; ETHERNET_ADDRESS_BYTES]>,
    peer_netnsid: Option<i32>,
    allowed_profiles: &[ObservedProfile],
) -> Result<ObservedLink, FixedLinkOperationError> {
    let observed = observed.ok_or(FixedLinkOperationError::Unsafe(
        "fixed link is absent from fresh readback",
    ))?;
    if observed.ifindex != ifindex
        || observed.peer_ifindex != peer_ifindex
        || observed.name != name
        || mac.is_some_and(|expected| observed.mac != expected)
        || peer_netnsid.is_some_and(|expected| observed.peer_netnsid != expected)
        || !allowed_profiles.contains(&observed.profile)
    {
        Err(FixedLinkOperationError::Unsafe(
            "fresh fixed link readback changed identity or profile",
        ))
    } else {
        Ok(observed)
    }
}

fn observe_link_by_ifindex(ifindex: u32) -> Result<Option<ObservedLink>, FixedLinkOperationError> {
    observe_link_by_ifindex_with_statistics(ifindex, RequiredLinkStatistics::Zero)
}

fn observe_link_by_ifindex_with_statistics(
    ifindex: u32,
    required_statistics: RequiredLinkStatistics,
) -> Result<Option<ObservedLink>, FixedLinkOperationError> {
    let payload = encode_get_link_payload(ifindex)?;
    query_one_link_with_statistics(&payload, "query fixed link by ifindex", required_statistics)
}

fn observe_link_by_name(name: &str) -> Result<Option<ObservedLink>, FixedLinkOperationError> {
    let payload = encode_get_link_name_payload(name)?;
    query_one_link(&payload, "query fixed link by name")
}

fn query_one_link(
    payload: &[u8],
    operation: &'static str,
) -> Result<Option<ObservedLink>, FixedLinkOperationError> {
    query_one_link_with_statistics(payload, operation, RequiredLinkStatistics::Zero)
}

fn query_one_link_with_statistics(
    payload: &[u8],
    operation: &'static str,
    required_statistics: RequiredLinkStatistics,
) -> Result<Option<ObservedLink>, FixedLinkOperationError> {
    let deadline = Deadline::after(LINK_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(RTM_GETLINK, NLM_F_REQUEST, sequence, payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let reply = receive_one(&client.socket, deadline)?;
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? == NLMSG_ERROR {
        return match parse_ack(&reply, client.local_port, &request)? {
            Ack::Rejected(libc::ENODEV | libc::ENOENT) => Ok(None),
            Ack::Rejected(errno) => Err(FixedLinkOperationError::errno(operation, errno)),
            Ack::Success => Err(FixedLinkOperationError::Unsafe(
                "RTM_GETLINK returned a success ACK without link data",
            )),
        };
    }
    match required_statistics {
        RequiredLinkStatistics::Zero => {
            parse_link_reply(&reply, client.local_port, sequence).map(Some)
        }
        RequiredLinkStatistics::FixedIcmpEcho => {
            parse_fixed_icmp_echo_link_reply(&reply, client.local_port, sequence).map(Some)
        }
        RequiredLinkStatistics::FixedIcmpCleanup => {
            parse_fixed_icmp_cleanup_link_reply(&reply, client.local_port, sequence).map(Some)
        }
    }
}

fn require_link_absent(
    ifindex: u32,
    name: &str,
    _operation: &'static str,
) -> Result<(), FixedLinkOperationError> {
    if observe_link_by_ifindex(ifindex)?.is_some() || observe_link_by_name(name)?.is_some() {
        Err(FixedLinkOperationError::Unsafe(
            "deleted fixed link name or ifindex was replaced",
        ))
    } else {
        Ok(())
    }
}

fn parse_link_reply(
    reply: &NetlinkReply,
    local_port: u32,
    sequence: u32,
) -> Result<ObservedLink, FixedLinkOperationError> {
    parse_link_reply_with_statistics(reply, local_port, sequence, RequiredLinkStatistics::Zero)
}

fn parse_fixed_icmp_echo_link_reply(
    reply: &NetlinkReply,
    local_port: u32,
    sequence: u32,
) -> Result<ObservedLink, FixedLinkOperationError> {
    parse_link_reply_with_statistics(
        reply,
        local_port,
        sequence,
        RequiredLinkStatistics::FixedIcmpEcho,
    )
}

fn parse_fixed_icmp_cleanup_link_reply(
    reply: &NetlinkReply,
    local_port: u32,
    sequence: u32,
) -> Result<ObservedLink, FixedLinkOperationError> {
    parse_link_reply_with_statistics(
        reply,
        local_port,
        sequence,
        RequiredLinkStatistics::FixedIcmpCleanup,
    )
}

fn parse_link_reply_with_statistics(
    reply: &NetlinkReply,
    local_port: u32,
    sequence: u32,
    required_statistics: RequiredLinkStatistics,
) -> Result<ObservedLink, FixedLinkOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(FixedLinkOperationError::Unsafe(
            "RTM_GETLINK response sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? != RTM_NEWLINK
        || read_u16(frame, 6)? != 0
        || read_u32(frame, 8)? != sequence
        || read_u32(frame, 12)? != local_port
        || frame.len() < NLMSG_HEADER_LEN + IFINFO_LEN
    {
        return Err(FixedLinkOperationError::Unsafe(
            "RTM_GETLINK response header is not exact",
        ));
    }
    let info = &frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + IFINFO_LEN];
    if info[0] != AF_UNSPEC
        || info[1] != 0
        || read_u16(info, 2)? != ARPHRD_ETHER
        || read_u32(info, 12)? != 0
    {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifinfomsg is not canonical",
        ));
    }
    let raw_ifindex = read_i32(info, 4)?;
    if raw_ifindex <= 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is not positive",
        ));
    }
    let ifindex = u32::try_from(raw_ifindex).map_err(|_| FixedLinkOperationError::Limit)?;
    let flags = read_u32(info, 8)?;
    let attributes =
        parse_link_attributes(&frame[NLMSG_HEADER_LEN + IFINFO_LEN..], required_statistics)?;
    let name = parse_interface_name(attributes.name.ok_or(FixedLinkOperationError::Unsafe(
        "fixed link lacks IFLA_IFNAME",
    ))?)?;
    let address = attributes.address.ok_or(FixedLinkOperationError::Unsafe(
        "fixed link lacks IFLA_ADDRESS",
    ))?;
    if address == [0; ETHERNET_ADDRESS_BYTES]
        || address[0] & 0b11 != 0b10
        || attributes.broadcast != Some([u8::MAX; ETHERNET_ADDRESS_BYTES])
        || attributes
            .permanent_address
            .is_some_and(|permanent| permanent != address)
        || attributes.mtu != Some(FIXED_VETH_MTU)
        || attributes.queue_length != Some(FIXED_VETH_TX_QUEUE_LENGTH)
        || attributes.transmit_queues != Some(FIXED_VETH_QUEUE_COUNT)
        || attributes.receive_queues != Some(FIXED_VETH_QUEUE_COUNT)
        || attributes.linkmode != Some(0)
        || attributes.group != Some(0)
        || attributes.promiscuity != Some(0)
        || attributes.allmulti != Some(0)
        || attributes.protocol_down != Some(0)
        || attributes.required_structs_seen != VETH_REQUIRED_STRUCTS_SEEN
        || !required_link_statistics_match(&attributes, required_statistics)
        || !attributes.link_info_seen
        || !attributes.xdp_seen
    {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link static attributes changed",
        ));
    }
    let profile = classify_profile(flags, &attributes)?;
    if !carrier_telemetry_matches(&attributes, profile) {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link carrier counters changed outside the fixed lifecycle",
        ));
    }
    let peer_ifindex = attributes
        .peer_ifindex
        .ok_or(FixedLinkOperationError::Unsafe(
            "fixed link lacks its peer ifindex",
        ))?;
    let peer_netnsid = attributes
        .peer_netnsid
        .ok_or(FixedLinkOperationError::Unsafe(
            "fixed link lacks its peer network namespace ID",
        ))?;
    if peer_ifindex == 0 || peer_netnsid < 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link peer binding is not canonical",
        ));
    }
    Ok(ObservedLink {
        ifindex,
        peer_ifindex,
        name,
        mac: address,
        peer_netnsid,
        profile,
    })
}

fn carrier_telemetry_matches(attributes: &LinkAttributes<'_>, profile: ObservedProfile) -> bool {
    let observed = (
        attributes.carrier_changes,
        attributes.carrier_up_count,
        attributes.carrier_down_count,
    );
    match profile {
        ObservedProfile::DownEui64
        | ObservedProfile::DownNone
        | ObservedProfile::UpNoCarrierDownNone
        | ObservedProfile::UpNoCarrierLowerLayerDownNone => {
            observed.0.is_none_or(|value| value == 1)
                && observed.1.is_none_or(|value| value == 0)
                && observed.2.is_none_or(|value| value == 1)
        }
        ObservedProfile::UpCarrierNone => observed == (Some(2), Some(1), Some(1)),
    }
}

fn required_link_statistics_match(
    attributes: &LinkAttributes<'_>,
    required_statistics: RequiredLinkStatistics,
) -> bool {
    match required_statistics {
        RequiredLinkStatistics::Zero | RequiredLinkStatistics::FixedIcmpEcho => {
            attributes.fixed_icmp_cleanup_statistics32.is_none()
                && attributes.fixed_icmp_cleanup_statistics64.is_none()
        }
        RequiredLinkStatistics::FixedIcmpCleanup => {
            attributes.fixed_icmp_cleanup_statistics32.is_some()
                && attributes.fixed_icmp_cleanup_statistics32
                    == attributes.fixed_icmp_cleanup_statistics64
        }
    }
}

fn classify_profile(
    flags: u32,
    attributes: &LinkAttributes<'_>,
) -> Result<ObservedProfile, FixedLinkOperationError> {
    match (
        flags,
        attributes.qdisc,
        attributes.operstate,
        attributes.carrier,
        attributes.addrgen_mode,
    ) {
        (FIXED_DOWN_FLAGS, Some(b"noop\0"), Some(IF_OPER_DOWN), Some(0), Some(0)) => {
            Ok(ObservedProfile::DownEui64)
        }
        (FIXED_DOWN_FLAGS, Some(b"noop\0"), Some(IF_OPER_DOWN), Some(0), Some(1)) => {
            Ok(ObservedProfile::DownNone)
        }
        (
            FIXED_UP_NO_CARRIER_FLAGS,
            Some(b"noqueue\0"),
            Some(IF_OPER_DOWN),
            Some(0),
            Some(IN6_ADDR_GEN_MODE_NONE),
        ) => Ok(ObservedProfile::UpNoCarrierDownNone),
        (
            FIXED_UP_NO_CARRIER_FLAGS,
            Some(b"noqueue\0"),
            Some(IF_OPER_LOWERLAYERDOWN),
            Some(0),
            Some(IN6_ADDR_GEN_MODE_NONE),
        ) => Ok(ObservedProfile::UpNoCarrierLowerLayerDownNone),
        (
            FIXED_UP_CARRIER_FLAGS,
            Some(b"noqueue\0"),
            Some(IF_OPER_UP),
            Some(1),
            Some(IN6_ADDR_GEN_MODE_NONE),
        ) => Ok(ObservedProfile::UpCarrierNone),
        _ => Err(FixedLinkOperationError::Unsafe(
            "fixed link state, qdisc, carrier, or addrgen mode is not exact",
        )),
    }
}

fn parse_link_attributes(
    bytes: &[u8],
    required_statistics: RequiredLinkStatistics,
) -> Result<LinkAttributes<'_>, FixedLinkOperationError> {
    let mut result = LinkAttributes::default();
    let mut seen = [false; MAX_DEBIAN13_LINK_ATTRIBUTE + 1];
    for attribute in parse_attributes(bytes)? {
        let index = usize::from(attribute.kind);
        if index >= seen.len() || seen[index] {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed link attribute is unknown or duplicated",
            ));
        }
        seen[index] = true;
        apply_link_attribute(&mut result, attribute, required_statistics)?;
    }
    Ok(result)
}

fn apply_link_attribute<'a>(
    result: &mut LinkAttributes<'a>,
    attribute: Attribute<'a>,
    required_statistics: RequiredLinkStatistics,
) -> Result<(), FixedLinkOperationError> {
    match attribute.kind {
        IFLA_ADDRESS => set_once(
            &mut result.address,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_BROADCAST => set_once(
            &mut result.broadcast,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_IFNAME => set_once(&mut result.name, attribute.unflagged_payload()?),
        IFLA_MTU => set_once(
            &mut result.mtu,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINK => set_once(
            &mut result.peer_ifindex,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_QDISC => set_once(&mut result.qdisc, attribute.unflagged_payload()?),
        IFLA_TXQLEN => set_once(
            &mut result.queue_length,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_OPERSTATE => set_once(
            &mut result.operstate,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINKMODE => set_once(
            &mut result.linkmode,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINKINFO => {
            verify_veth_link_info(attribute)?;
            require_unset_flag(&mut result.link_info_seen)?;
            result.link_info_seen = true;
            Ok(())
        }
        IFLA_AF_SPEC => set_once(
            &mut result.addrgen_mode,
            parse_address_family_spec(attribute)?,
        ),
        IFLA_GROUP => set_once(
            &mut result.group,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROMISCUITY => set_once(
            &mut result.promiscuity,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_NUM_TX_QUEUES => set_once(
            &mut result.transmit_queues,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_NUM_RX_QUEUES => set_once(
            &mut result.receive_queues,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_CARRIER => set_once(
            &mut result.carrier,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_LINK_NETNSID => set_once(
            &mut result.peer_netnsid,
            read_exact_i32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PROTO_DOWN => set_once(
            &mut result.protocol_down,
            read_exact_u8(attribute.unflagged_payload()?)?,
        ),
        IFLA_ALLMULTI => set_once(
            &mut result.allmulti,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_PERM_ADDRESS => set_once(
            &mut result.permanent_address,
            read_exact_ethernet_address(attribute.unflagged_payload()?)?,
        ),
        IFLA_XDP => {
            verify_xdp(attribute)?;
            require_unset_flag(&mut result.xdp_seen)?;
            result.xdp_seen = true;
            Ok(())
        }
        IFLA_MASTER | IFLA_IFALIAS | IFLA_ALT_IFNAME => Err(FixedLinkOperationError::Unsafe(
            "fixed link acquired a forbidden relationship or alias",
        )),
        _ => apply_link_telemetry_attribute(result, attribute, required_statistics),
    }
}

fn apply_link_telemetry_attribute(
    result: &mut LinkAttributes<'_>,
    attribute: Attribute<'_>,
    required_statistics: RequiredLinkStatistics,
) -> Result<(), FixedLinkOperationError> {
    match attribute.kind {
        IFLA_CARRIER_CHANGES => set_once(
            &mut result.carrier_changes,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_CARRIER_UP_COUNT => set_once(
            &mut result.carrier_up_count,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_CARRIER_DOWN_COUNT => set_once(
            &mut result.carrier_down_count,
            read_exact_u32(attribute.unflagged_payload()?)?,
        ),
        IFLA_STATS => verify_required_telemetry(
            result,
            attribute,
            VETH_LINK_STATS_BYTES,
            VETH_STATS_SEEN,
            required_statistics,
        ),
        IFLA_STATS64 => verify_required_telemetry(
            result,
            attribute,
            VETH_LINK_STATS64_BYTES,
            VETH_STATS64_SEEN,
            required_statistics,
        ),
        IFLA_MAP => verify_required_telemetry(
            result,
            attribute,
            VETH_LINK_IFMAP_BYTES,
            VETH_IFMAP_SEEN,
            RequiredLinkStatistics::Zero,
        ),
        _ => verify_known_telemetry(attribute),
    }
}

fn verify_required_telemetry(
    result: &mut LinkAttributes<'_>,
    attribute: Attribute<'_>,
    exact_length: usize,
    marker: u8,
    required_statistics: RequiredLinkStatistics,
) -> Result<(), FixedLinkOperationError> {
    let payload = attribute.unflagged_payload()?;
    if payload.len() != exact_length || result.required_structs_seen & marker != 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link statistics or ifmap telemetry has the wrong shape",
        ));
    }
    let exact = match (required_statistics, marker) {
        (RequiredLinkStatistics::Zero, _) => payload.iter().all(|byte| *byte == 0),
        (RequiredLinkStatistics::FixedIcmpEcho, VETH_STATS_SEEN) => {
            fixed_icmp_echo_statistics32_match(payload)?
        }
        (RequiredLinkStatistics::FixedIcmpEcho, VETH_STATS64_SEEN) => {
            fixed_icmp_echo_statistics64_match(payload)?
        }
        (RequiredLinkStatistics::FixedIcmpCleanup, VETH_STATS_SEEN) => {
            result.fixed_icmp_cleanup_statistics32 =
                Some(fixed_icmp_cleanup_statistics32(payload)?);
            true
        }
        (RequiredLinkStatistics::FixedIcmpCleanup, VETH_STATS64_SEEN) => {
            result.fixed_icmp_cleanup_statistics64 =
                Some(fixed_icmp_cleanup_statistics64(payload)?);
            true
        }
        (RequiredLinkStatistics::FixedIcmpEcho | RequiredLinkStatistics::FixedIcmpCleanup, _) => {
            false
        }
    };
    if !exact {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link statistics or ifmap telemetry does not match the required lifecycle",
        ));
    }
    result.required_structs_seen |= marker;
    Ok(())
}

fn fixed_icmp_echo_statistics32_match(payload: &[u8]) -> Result<bool, FixedLinkOperationError> {
    for index in 0..(VETH_LINK_STATS_BYTES / size_of::<u32>()) {
        if u64::from(read_u32(payload, index * size_of::<u32>())?)
            != fixed_icmp_echo_statistic(index)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_icmp_echo_statistics64_match(payload: &[u8]) -> Result<bool, FixedLinkOperationError> {
    for index in 0..(VETH_LINK_STATS64_BYTES / size_of::<u64>()) {
        if read_u64(payload, index * size_of::<u64>())? != fixed_icmp_echo_statistic(index) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_icmp_cleanup_statistics32(payload: &[u8]) -> Result<[bool; 2], FixedLinkOperationError> {
    let mut statistics = [0_u64; VETH_LINK_STATS_BYTES / size_of::<u32>()];
    for (index, value) in statistics.iter_mut().enumerate() {
        *value = u64::from(read_u32(payload, index * size_of::<u32>())?);
    }
    fixed_icmp_cleanup_directions(&statistics)
}

fn fixed_icmp_cleanup_statistics64(payload: &[u8]) -> Result<[bool; 2], FixedLinkOperationError> {
    let mut statistics = [0_u64; VETH_LINK_STATS64_BYTES / size_of::<u64>()];
    for (index, value) in statistics.iter_mut().enumerate() {
        *value = read_u64(payload, index * size_of::<u64>())?;
    }
    fixed_icmp_cleanup_directions(&statistics)
}

fn fixed_icmp_cleanup_directions(statistics: &[u64]) -> Result<[bool; 2], FixedLinkOperationError> {
    if statistics.len() < 4 || statistics[4..].iter().any(|value| *value != 0) {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed ICMP cleanup link statistics contain another counter",
        ));
    }
    let mut directions = [false; 2];
    for (direction, (packet_index, byte_index)) in [(0, 2), (1, 3)].into_iter().enumerate() {
        directions[direction] = match (statistics[packet_index], statistics[byte_index]) {
            (0, 0) => false,
            (FIXED_ICMP_ECHO_PACKETS, FIXED_ICMP_ECHO_ETHERNET_BYTES) => true,
            _ => {
                return Err(FixedLinkOperationError::Unsafe(
                    "fixed ICMP cleanup link statistics are incoherent",
                ));
            }
        };
    }
    Ok(directions)
}

const fn fixed_icmp_echo_statistic(index: usize) -> u64 {
    match index {
        0 | 1 => FIXED_ICMP_ECHO_PACKETS,
        2 | 3 => FIXED_ICMP_ECHO_ETHERNET_BYTES,
        _ => 0,
    }
}

fn verify_known_telemetry(attribute: Attribute<'_>) -> Result<(), FixedLinkOperationError> {
    if matches!(
        attribute.kind,
        IFLA_PROP_LIST | IFLA_DEVLINK_PORT | IFLA_DPLL_PIN
    ) && attribute.flags == NLA_F_NESTED
        && attribute.payload.is_empty()
    {
        return Ok(());
    }
    let payload = attribute.unflagged_payload()?;
    match attribute.kind {
        IFLA_EVENT if read_exact_u32(payload)? == 0 => Ok(()),
        IFLA_MIN_MTU if read_exact_u32(payload)? == VETH_MIN_MTU => Ok(()),
        IFLA_MAX_MTU if read_exact_u32(payload)? == VETH_MAX_MTU => Ok(()),
        IFLA_GSO_MAX_SEGS if read_exact_u32(payload)? == VETH_GSO_MAX_SEGMENTS => Ok(()),
        IFLA_GSO_MAX_SIZE | IFLA_GRO_MAX_SIZE | IFLA_GSO_IPV4_MAX_SIZE | IFLA_GRO_IPV4_MAX_SIZE
            if read_exact_u32(payload)? == VETH_OFFLOAD_MAX_SIZE =>
        {
            Ok(())
        }
        IFLA_TSO_MAX_SIZE if read_exact_u32(payload)? == DEFAULT_TSO_MAX_SIZE => Ok(()),
        IFLA_TSO_MAX_SEGS if read_exact_u32(payload)? == DEFAULT_TSO_MAX_SEGMENTS => Ok(()),
        _ => Err(FixedLinkOperationError::Unsafe(
            "fixed link contains an unknown kernel attribute",
        )),
    }
}

fn verify_veth_link_info(attribute: Attribute<'_>) -> Result<(), FixedLinkOperationError> {
    let mut kind = None;
    for nested in parse_attributes(attribute.unflagged_payload()?)? {
        if nested.kind != IFLA_INFO_KIND {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed link info contains an unexpected attribute",
            ));
        }
        set_once(&mut kind, nested.unflagged_payload()?)?;
    }
    if kind == Some(&b"veth\0"[..]) {
        Ok(())
    } else {
        Err(FixedLinkOperationError::Unsafe(
            "fixed link kind is not veth",
        ))
    }
}

fn parse_address_family_spec(attribute: Attribute<'_>) -> Result<u8, FixedLinkOperationError> {
    if attribute.flags != 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "IFLA_AF_SPEC readback has noncanonical flags",
        ));
    }
    let mut ipv4_seen = false;
    let mut ipv6 = None;
    for family in parse_attributes(attribute.payload)? {
        if family.flags != 0 {
            return Err(FixedLinkOperationError::Unsafe(
                "address-family readback has noncanonical flags",
            ));
        }
        match family.kind {
            AF_INET => {
                if ipv4_seen {
                    return Err(FixedLinkOperationError::Unsafe(
                        "IPv4 link configuration is duplicated",
                    ));
                }
                ipv4_seen = true;
                let attributes = parse_attributes(family.payload)?;
                if attributes.len() != 1
                    || attributes[0].kind != IFLA_INET_CONF
                    || attributes[0].flags != 0
                    || attributes[0].payload.is_empty()
                    || attributes[0].payload.len() % 4 != 0
                {
                    return Err(FixedLinkOperationError::Unsafe(
                        "IPv4 link configuration is not canonical",
                    ));
                }
            }
            AF_INET6 => set_once(&mut ipv6, family.payload)?,
            _ => {
                return Err(FixedLinkOperationError::Unsafe(
                    "link readback contains an unknown address family",
                ));
            }
        }
    }
    if !ipv4_seen {
        return Err(FixedLinkOperationError::Unsafe(
            "link readback lacks IPv4 configuration",
        ));
    }
    let mut mode = None;
    let mut seen = [false; 10];
    for ipv6_attribute in parse_attributes(ipv6.ok_or(FixedLinkOperationError::Unsafe(
        "link readback lacks IPv6 configuration",
    ))?)? {
        let index = usize::from(ipv6_attribute.kind);
        if ipv6_attribute.flags != 0 || index == 0 || index >= seen.len() || seen[index] {
            return Err(FixedLinkOperationError::Unsafe(
                "IPv6 link configuration is malformed or duplicated",
            ));
        }
        seen[index] = true;
        match ipv6_attribute.kind {
            IFLA_INET6_FLAGS | IFLA_INET6_RA_MTU => {
                let _ = read_exact_u32(ipv6_attribute.payload)?;
            }
            IFLA_INET6_CONF
            | IFLA_INET6_STATS
            | IFLA_INET6_MCAST
            | IFLA_INET6_CACHEINFO
            | IFLA_INET6_ICMP6STATS
                if !ipv6_attribute.payload.is_empty() && ipv6_attribute.payload.len() % 4 == 0 => {}
            IFLA_INET6_TOKEN if ipv6_attribute.payload.len() == 16 => {}
            IFLA_INET6_ADDR_GEN_MODE => {
                set_once(&mut mode, read_exact_u8(ipv6_attribute.payload)?)?;
            }
            _ => {
                return Err(FixedLinkOperationError::Unsafe(
                    "IPv6 link configuration contains an unknown attribute",
                ));
            }
        }
    }
    match mode {
        Some(IN6_ADDR_GEN_MODE_EUI64 | IN6_ADDR_GEN_MODE_NONE) => mode.ok_or(
            FixedLinkOperationError::Unsafe("IPv6 address-generation mode is absent"),
        ),
        Some(_) => Err(FixedLinkOperationError::Unsafe(
            "IPv6 address-generation mode is outside the fixed transition",
        )),
        None => Err(FixedLinkOperationError::Unsafe(
            "IPv6 address-generation mode is absent",
        )),
    }
}

fn verify_xdp(attribute: Attribute<'_>) -> Result<(), FixedLinkOperationError> {
    let mut attached = None;
    for nested in parse_attributes(attribute.unflagged_payload()?)? {
        if nested.kind != IFLA_XDP_ATTACHED || nested.flags != 0 {
            return Err(FixedLinkOperationError::Unsafe(
                "fixed link XDP readback is not canonical",
            ));
        }
        set_once(&mut attached, read_exact_u8(nested.payload)?)?;
    }
    if attached == Some(0) {
        Ok(())
    } else {
        Err(FixedLinkOperationError::Unsafe(
            "fixed link has an attached XDP program",
        ))
    }
}

fn require_unset_flag(flag: &mut bool) -> Result<(), FixedLinkOperationError> {
    if *flag {
        Err(FixedLinkOperationError::Unsafe(
            "fixed link proof marker is duplicated",
        ))
    } else {
        Ok(())
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), FixedLinkOperationError> {
    if slot.replace(value).is_some() {
        Err(FixedLinkOperationError::Unsafe(
            "netlink attribute is duplicated",
        ))
    } else {
        Ok(())
    }
}

fn parse_interface_name(payload: &[u8]) -> Result<String, FixedLinkOperationError> {
    let bytes = payload
        .strip_suffix(&[0])
        .ok_or(FixedLinkOperationError::Unsafe(
            "fixed interface name is not NUL terminated",
        ))?;
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) || !bytes.is_ascii()
    {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed interface name is not canonical",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| FixedLinkOperationError::Unsafe("fixed interface name is not valid UTF-8"))
}

fn read_exact_ethernet_address(
    bytes: &[u8],
) -> Result<[u8; ETHERNET_ADDRESS_BYTES], FixedLinkOperationError> {
    bytes
        .try_into()
        .map_err(|_| FixedLinkOperationError::Unsafe("Ethernet address length is not exact"))
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, FixedLinkOperationError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(FixedLinkOperationError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, FixedLinkOperationError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis
                .checked_add(1)
                .ok_or(FixedLinkOperationError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| FixedLinkOperationError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), FixedLinkOperationError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error())
        }
    }
}

fn timeout_error() -> FixedLinkOperationError {
    FixedLinkOperationError::io(
        "wait for fixed link RTNETLINK response",
        io::Error::new(io::ErrorKind::TimedOut, "fixed link deadline expired"),
    )
}

struct NetlinkClient {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkClient {
    fn connect(deadline: Deadline) -> Result<Self, FixedLinkOperationError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|source| FixedLinkOperationError::io("open RTNETLINK socket", source))?;
        socket.set_netlink_get_strict_chk(true).map_err(|source| {
            FixedLinkOperationError::io("enable strict RTNETLINK checking", source)
        })?;
        socket
            .set_non_blocking(true)
            .map_err(|source| FixedLinkOperationError::io("harden RTNETLINK socket", source))?;
        let address = socket
            .bind_auto()
            .map_err(|source| FixedLinkOperationError::io("bind RTNETLINK socket", source))?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(FixedLinkOperationError::Unsafe(
                "RTNETLINK socket binding is not exact",
            ));
        }
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|source| FixedLinkOperationError::io("connect RTNETLINK socket", source))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> Result<u32, FixedLinkOperationError> {
        let current = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(FixedLinkOperationError::Limit)?;
        if current == 0 {
            Err(FixedLinkOperationError::Unsafe(
                "RTNETLINK sequence is zero",
            ))
        } else {
            Ok(current)
        }
    }
}

enum SendFailure {
    NotSent(FixedLinkOperationError),
    PossiblySent(FixedLinkOperationError),
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), SendFailure> {
    loop {
        deadline.ensure_unexpired().map_err(SendFailure::NotSent)?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return Ok(()),
            Ok(_) => {
                return Err(SendFailure::PossiblySent(FixedLinkOperationError::io(
                    "send complete RTNETLINK datagram",
                    io::Error::new(io::ErrorKind::WriteZero, "short RTNETLINK datagram write"),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_socket(socket, PollFlags::POLLOUT, deadline)
                    .map_err(SendFailure::NotSent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(SendFailure::NotSent(FixedLinkOperationError::io(
                    "send RTNETLINK request",
                    error,
                )));
            }
        }
    }
}

fn send_failure_source(failure: SendFailure) -> FixedLinkOperationError {
    match failure {
        SendFailure::NotSent(source) | SendFailure::PossiblySent(source) => source,
    }
}

struct NetlinkReply {
    sender: SocketAddr,
    bytes: Vec<u8>,
}

fn receive_one(
    socket: &Socket,
    deadline: Deadline,
) -> Result<NetlinkReply, FixedLinkOperationError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(FixedLinkOperationError::io(
                        "measure RTNETLINK response",
                        error,
                    ));
                }
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(FixedLinkOperationError::Unsafe(
                "RTNETLINK response sender is not the kernel",
            ));
        }
        if length == 0 {
            return Err(FixedLinkOperationError::Unsafe(
                "RTNETLINK response is empty",
            ));
        }
        if length > MAX_NETLINK_DATAGRAM_BYTES {
            return Err(FixedLinkOperationError::Limit);
        }
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(FixedLinkOperationError::io(
                    "receive RTNETLINK response",
                    error,
                ));
            }
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != length || sender != peek_sender {
            return Err(FixedLinkOperationError::Unsafe(
                "RTNETLINK response changed during bounded receive",
            ));
        }
        return Ok(NetlinkReply { sender, bytes });
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), FixedLinkOperationError> {
    loop {
        let mut descriptors = [PollFd::new(socket.as_fd(), expected)];
        match poll(&mut descriptors, deadline.poll_timeout()?) {
            Ok(0) => return Err(timeout_error()),
            Ok(_) => {
                deadline.ensure_unexpired()?;
                let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(FixedLinkOperationError::Unsafe(
                        "RTNETLINK poll state is ambiguous",
                    ));
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(source) => {
                return Err(FixedLinkOperationError::io(
                    "poll RTNETLINK socket",
                    io::Error::from_raw_os_error(source as i32),
                ));
            }
        }
    }
}

fn transact_ack(
    socket: &Socket,
    local_port: u32,
    request: &[u8],
    deadline: Deadline,
) -> Result<Ack, FixedLinkOperationError> {
    send_bounded(socket, request, deadline).map_err(send_failure_source)?;
    let reply = receive_one(socket, deadline)?;
    parse_ack(&reply, local_port, request)
}

fn interface_info(
    ifindex: u32,
    flags: u32,
    change: u32,
) -> Result<Vec<u8>, FixedLinkOperationError> {
    if ifindex > i32::MAX as u32 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is not representable",
        ));
    }
    let mut payload = Vec::with_capacity(IFINFO_LEN);
    payload.push(AF_UNSPEC);
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&change.to_ne_bytes());
    Ok(payload)
}

fn encode_addrgen_none_request(
    sequence: u32,
    ifindex: u32,
) -> Result<Vec<u8>, FixedLinkOperationError> {
    if ifindex == 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is zero",
        ));
    }
    let mut mode = Vec::new();
    push_attribute(
        &mut mode,
        IFLA_INET6_ADDR_GEN_MODE,
        &[IN6_ADDR_GEN_MODE_NONE],
    )?;
    let mut family = Vec::new();
    push_attribute(&mut family, AF_INET6, &mode)?;
    let mut payload = interface_info(ifindex, 0, 0)?;
    push_attribute(&mut payload, IFLA_AF_SPEC, &family)?;
    encode_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)
}

fn encode_link_up_request(sequence: u32, ifindex: u32) -> Result<Vec<u8>, FixedLinkOperationError> {
    if ifindex == 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is zero",
        ));
    }
    let payload = interface_info(ifindex, IFF_UP, IFF_UP)?;
    encode_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)
}

fn encode_delete_link_request(
    sequence: u32,
    ifindex: u32,
) -> Result<Vec<u8>, FixedLinkOperationError> {
    if ifindex == 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is zero",
        ));
    }
    let payload = interface_info(ifindex, 0, 0)?;
    encode_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)
}

fn encode_get_link_payload(ifindex: u32) -> Result<Vec<u8>, FixedLinkOperationError> {
    if ifindex == 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link ifindex is zero",
        ));
    }
    interface_info(ifindex, 0, 0)
}

fn encode_get_link_name_payload(name: &str) -> Result<Vec<u8>, FixedLinkOperationError> {
    let mut payload = interface_info(0, 0, 0)?;
    push_string_attribute(&mut payload, IFLA_IFNAME, name)?;
    Ok(payload)
}

fn encode_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, FixedLinkOperationError> {
    if sequence == 0 {
        return Err(FixedLinkOperationError::Unsafe("netlink sequence is zero"));
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedLinkOperationError::Limit)?;
    if length > MAX_REQUEST_BYTES {
        return Err(FixedLinkOperationError::Limit);
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| FixedLinkOperationError::Limit)?
            .to_ne_bytes(),
    );
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn push_string_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    value: &str,
) -> Result<(), FixedLinkOperationError> {
    if value.is_empty()
        || value.len() >= libc::IFNAMSIZ
        || value.as_bytes().contains(&0)
        || !value.is_ascii()
    {
        return Err(FixedLinkOperationError::Unsafe(
            "fixed link string attribute is invalid",
        ));
    }
    let mut encoded = value.as_bytes().to_vec();
    encoded.push(0);
    push_attribute(buffer, kind, &encoded)
}

fn push_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    payload: &[u8],
) -> Result<(), FixedLinkOperationError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedLinkOperationError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| FixedLinkOperationError::Limit)?;
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len())?, 0);
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(FixedLinkOperationError::Limit);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ack {
    Success,
    Rejected(i32),
}

fn parse_ack(
    reply: &NetlinkReply,
    local_port: u32,
    request: &[u8],
) -> Result<Ack, FixedLinkOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink ACK sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    let flags = read_u16(frame, 6)?;
    if read_u16(frame, 4)? != NLMSG_ERROR
        || read_u32(frame, 8)? != read_u32(request, 8)?
        || read_u32(frame, 12)? != local_port
    {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink ACK header is not exact",
        ));
    }
    let payload = &frame[NLMSG_HEADER_LEN..];
    let embedded_length = NLMSG_ERROR_CODE_LEN
        .checked_add(NLMSG_HEADER_LEN)
        .ok_or(FixedLinkOperationError::Limit)?;
    if payload.len() < embedded_length
        || payload[NLMSG_ERROR_CODE_LEN..embedded_length] != request[..NLMSG_HEADER_LEN]
    {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink ACK does not bind the exact request header",
        ));
    }
    let trailing = &payload[embedded_length..];
    let errno = read_i32(payload, 0)?;
    if flags & NLM_F_ACK_TLVS != 0 {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink ACK unexpectedly carries extended ACK attributes",
        ));
    }
    match errno {
        0 if flags == NLM_F_CAPPED && trailing.is_empty() => Ok(Ack::Success),
        errno
            if errno < 0
                && errno != i32::MIN
                && flags == 0
                && trailing == &request[NLMSG_HEADER_LEN..] =>
        {
            Ok(Ack::Rejected(-errno))
        }
        0 => Err(FixedLinkOperationError::Unsafe(
            "successful netlink ACK is not the canonical capped form",
        )),
        errno if errno < 0 => Err(FixedLinkOperationError::Unsafe(
            "negative netlink ACK does not exactly echo the request",
        )),
        _ => Err(FixedLinkOperationError::Unsafe(
            "netlink ACK errno is not canonical",
        )),
    }
}

fn single_frame(bytes: &[u8]) -> Result<&[u8], FixedLinkOperationError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink datagram lacks a complete header",
        ));
    }
    let length =
        usize::try_from(read_u32(bytes, 0)?).map_err(|_| FixedLinkOperationError::Limit)?;
    let aligned = align4(length)?;
    if length < NLMSG_HEADER_LEN || aligned != bytes.len() {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink datagram does not contain exactly one frame",
        ));
    }
    if bytes[length..aligned].iter().any(|byte| *byte != 0) {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink frame padding is nonzero",
        ));
    }
    Ok(&bytes[..length])
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

impl<'a> Attribute<'a> {
    fn unflagged_payload(self) -> Result<&'a [u8], FixedLinkOperationError> {
        if self.flags == 0 {
            Ok(self.payload)
        } else {
            Err(FixedLinkOperationError::Unsafe(
                "netlink attribute carries unexpected flags",
            ))
        }
    }
}

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, FixedLinkOperationError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if result.len() >= MAX_ATTRIBUTES || bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(FixedLinkOperationError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(FixedLinkOperationError::Unsafe(
                "netlink attribute length is invalid",
            ));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(FixedLinkOperationError::Unsafe(
                "netlink attribute padding is nonzero",
            ));
        }
        let raw_kind = read_u16(bytes, 2)?;
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(FixedLinkOperationError::Unsafe(
                "netlink attribute flags are contradictory",
            ));
        }
        result.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags,
            payload: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FixedLinkOperationError> {
    let end = offset
        .checked_add(2)
        .ok_or(FixedLinkOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedLinkOperationError::Unsafe("truncated netlink u16"))?
        .try_into()
        .map_err(|_| FixedLinkOperationError::Unsafe("invalid netlink u16"))?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FixedLinkOperationError> {
    let end = offset
        .checked_add(4)
        .ok_or(FixedLinkOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedLinkOperationError::Unsafe("truncated netlink u32"))?
        .try_into()
        .map_err(|_| FixedLinkOperationError::Unsafe("invalid netlink u32"))?;
    Ok(u32::from_ne_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FixedLinkOperationError> {
    let end = offset
        .checked_add(8)
        .ok_or(FixedLinkOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedLinkOperationError::Unsafe("truncated netlink u64"))?
        .try_into()
        .map_err(|_| FixedLinkOperationError::Unsafe("invalid netlink u64"))?;
    Ok(u64::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, FixedLinkOperationError> {
    let end = offset
        .checked_add(4)
        .ok_or(FixedLinkOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedLinkOperationError::Unsafe("truncated netlink i32"))?
        .try_into()
        .map_err(|_| FixedLinkOperationError::Unsafe("invalid netlink i32"))?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_u8(bytes: &[u8]) -> Result<u8, FixedLinkOperationError> {
    match bytes {
        [value] => Ok(*value),
        _ => Err(FixedLinkOperationError::Unsafe(
            "netlink u8 attribute has the wrong size",
        )),
    }
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, FixedLinkOperationError> {
    if bytes.len() != 4 {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink u32 attribute has the wrong size",
        ));
    }
    read_u32(bytes, 0)
}

fn read_exact_i32(bytes: &[u8]) -> Result<i32, FixedLinkOperationError> {
    if bytes.len() != 4 {
        return Err(FixedLinkOperationError::Unsafe(
            "netlink i32 attribute has the wrong size",
        ));
    }
    read_i32(bytes, 0)
}

fn align4(length: usize) -> Result<usize, FixedLinkOperationError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(FixedLinkOperationError::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEQUENCE: u32 = 0x1122_3344;
    const TEST_PORT: u32 = 0x5566_7788;
    const TEST_IFINDEX: u32 = 7;
    const TEST_PEER_IFINDEX: u32 = 11;
    const TEST_NAME: &str = "vpa01234567";
    const TEST_MAC: [u8; ETHERNET_ADDRESS_BYTES] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn attribute(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + payload.len();
        let mut bytes = Vec::with_capacity((length + 3) & !3);
        bytes.extend_from_slice(
            &u16::try_from(length)
                .expect("test attribute length")
                .to_ne_bytes(),
        );
        bytes.extend_from_slice(&(kind | flags).to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    fn append_attribute(buffer: &mut Vec<u8>, kind: u16, flags: u16, payload: &[u8]) {
        buffer.extend(attribute(kind, flags, payload));
    }

    fn address_family_payload(mode: u8) -> Vec<u8> {
        let ipv4 = attribute(IFLA_INET_CONF, 0, &[0; 4]);
        let ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, 0, &[mode]);
        let mut families = attribute(AF_INET, 0, &ipv4);
        families.extend(attribute(AF_INET6, 0, &ipv6));
        families
    }

    fn profile_fields(profile: ObservedProfile) -> (u32, &'static [u8], u8, u8, u8) {
        match profile {
            ObservedProfile::DownEui64 => (
                FIXED_DOWN_FLAGS,
                b"noop\0",
                IF_OPER_DOWN,
                0,
                IN6_ADDR_GEN_MODE_EUI64,
            ),
            ObservedProfile::DownNone => (
                FIXED_DOWN_FLAGS,
                b"noop\0",
                IF_OPER_DOWN,
                0,
                IN6_ADDR_GEN_MODE_NONE,
            ),
            ObservedProfile::UpNoCarrierDownNone => (
                FIXED_UP_NO_CARRIER_FLAGS,
                b"noqueue\0",
                IF_OPER_DOWN,
                0,
                IN6_ADDR_GEN_MODE_NONE,
            ),
            ObservedProfile::UpNoCarrierLowerLayerDownNone => (
                FIXED_UP_NO_CARRIER_FLAGS,
                b"noqueue\0",
                IF_OPER_LOWERLAYERDOWN,
                0,
                IN6_ADDR_GEN_MODE_NONE,
            ),
            ObservedProfile::UpCarrierNone => (
                FIXED_UP_CARRIER_FLAGS,
                b"noqueue\0",
                IF_OPER_UP,
                1,
                IN6_ADDR_GEN_MODE_NONE,
            ),
        }
    }

    fn append_static_link_attributes(attributes: &mut Vec<u8>) {
        append_attribute(attributes, IFLA_ADDRESS, 0, &TEST_MAC);
        append_attribute(
            attributes,
            IFLA_BROADCAST,
            0,
            &[u8::MAX; ETHERNET_ADDRESS_BYTES],
        );
        let mut name = TEST_NAME.as_bytes().to_vec();
        name.push(0);
        append_attribute(attributes, IFLA_IFNAME, 0, &name);
        append_attribute(attributes, IFLA_MTU, 0, &FIXED_VETH_MTU.to_ne_bytes());
        append_attribute(attributes, IFLA_LINK, 0, &TEST_PEER_IFINDEX.to_ne_bytes());
        append_attribute(attributes, IFLA_STATS, 0, &[0; VETH_LINK_STATS_BYTES]);
        append_attribute(
            attributes,
            IFLA_TXQLEN,
            0,
            &FIXED_VETH_TX_QUEUE_LENGTH.to_ne_bytes(),
        );
        append_attribute(attributes, IFLA_MAP, 0, &[0; VETH_LINK_IFMAP_BYTES]);
        append_attribute(attributes, IFLA_LINKMODE, 0, &[0]);
        let kind = attribute(IFLA_INFO_KIND, 0, b"veth\0");
        append_attribute(attributes, IFLA_LINKINFO, 0, &kind);
        append_attribute(attributes, IFLA_STATS64, 0, &[0; VETH_LINK_STATS64_BYTES]);
        append_attribute(attributes, IFLA_GROUP, 0, &0_u32.to_ne_bytes());
        append_attribute(attributes, IFLA_PROMISCUITY, 0, &0_u32.to_ne_bytes());
        append_attribute(
            attributes,
            IFLA_NUM_TX_QUEUES,
            0,
            &FIXED_VETH_QUEUE_COUNT.to_ne_bytes(),
        );
        append_attribute(
            attributes,
            IFLA_NUM_RX_QUEUES,
            0,
            &FIXED_VETH_QUEUE_COUNT.to_ne_bytes(),
        );
        append_attribute(attributes, IFLA_LINK_NETNSID, 0, &0_i32.to_ne_bytes());
        append_attribute(attributes, IFLA_PROTO_DOWN, 0, &[0]);
        append_attribute(attributes, IFLA_EVENT, 0, &0_u32.to_ne_bytes());
        append_attribute(attributes, IFLA_MIN_MTU, 0, &VETH_MIN_MTU.to_ne_bytes());
        append_attribute(attributes, IFLA_MAX_MTU, 0, &VETH_MAX_MTU.to_ne_bytes());
        append_attribute(
            attributes,
            IFLA_GSO_MAX_SEGS,
            0,
            &VETH_GSO_MAX_SEGMENTS.to_ne_bytes(),
        );
        for kind in [
            IFLA_GSO_MAX_SIZE,
            IFLA_GRO_MAX_SIZE,
            IFLA_GSO_IPV4_MAX_SIZE,
            IFLA_GRO_IPV4_MAX_SIZE,
        ] {
            append_attribute(attributes, kind, 0, &VETH_OFFLOAD_MAX_SIZE.to_ne_bytes());
        }
        append_attribute(
            attributes,
            IFLA_TSO_MAX_SIZE,
            0,
            &DEFAULT_TSO_MAX_SIZE.to_ne_bytes(),
        );
        append_attribute(
            attributes,
            IFLA_TSO_MAX_SEGS,
            0,
            &DEFAULT_TSO_MAX_SEGMENTS.to_ne_bytes(),
        );
        append_attribute(attributes, IFLA_ALLMULTI, 0, &0_u32.to_ne_bytes());
        let xdp = attribute(IFLA_XDP_ATTACHED, 0, &[0]);
        append_attribute(attributes, IFLA_XDP, 0, &xdp);
    }

    fn valid_link_attributes(profile: ObservedProfile) -> Vec<u8> {
        let (_, qdisc, operstate, carrier, mode) = profile_fields(profile);
        let mut attributes = Vec::new();
        append_static_link_attributes(&mut attributes);
        append_attribute(&mut attributes, IFLA_QDISC, 0, qdisc);
        append_attribute(&mut attributes, IFLA_OPERSTATE, 0, &[operstate]);
        append_attribute(&mut attributes, IFLA_CARRIER, 0, &[carrier]);
        let (changes, up, down) = if profile == ObservedProfile::UpCarrierNone {
            (2_u32, 1_u32, 1_u32)
        } else {
            (1_u32, 0_u32, 1_u32)
        };
        append_attribute(
            &mut attributes,
            IFLA_CARRIER_CHANGES,
            0,
            &changes.to_ne_bytes(),
        );
        append_attribute(&mut attributes, IFLA_CARRIER_UP_COUNT, 0, &up.to_ne_bytes());
        append_attribute(
            &mut attributes,
            IFLA_CARRIER_DOWN_COUNT,
            0,
            &down.to_ne_bytes(),
        );
        append_attribute(
            &mut attributes,
            IFLA_AF_SPEC,
            0,
            &address_family_payload(mode),
        );
        attributes
    }

    fn link_reply(profile: ObservedProfile) -> NetlinkReply {
        let (flags, _, _, _, _) = profile_fields(profile);
        let mut payload = interface_info(TEST_IFINDEX, flags, 0).expect("test ifinfomsg");
        payload[2..4].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        payload.extend(valid_link_attributes(profile));
        let bytes = encode_unbounded_message(RTM_NEWLINK, 0, TEST_SEQUENCE, TEST_PORT, &payload);
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes,
        }
    }

    fn encode_unbounded_message(
        kind: u16,
        flags: u16,
        sequence: u32,
        port: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut message = Vec::with_capacity((length + 3) & !3);
        message.extend_from_slice(
            &u32::try_from(length)
                .expect("test frame length")
                .to_ne_bytes(),
        );
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&sequence.to_ne_bytes());
        message.extend_from_slice(&port.to_ne_bytes());
        message.extend_from_slice(payload);
        message.resize((length + 3) & !3, 0);
        message
    }

    fn ack_reply(request: &[u8], errno: i32, flags: u16, trailing: &[u8]) -> NetlinkReply {
        let mut payload = errno.to_ne_bytes().to_vec();
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        payload.extend_from_slice(trailing);
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: encode_unbounded_message(
                NLMSG_ERROR,
                flags,
                read_u32(request, 8).expect("request sequence"),
                TEST_PORT,
                &payload,
            ),
        }
    }

    #[test]
    fn fixed_setlink_requests_are_byte_exact_and_minimal() {
        let addrgen = encode_addrgen_none_request(TEST_SEQUENCE, TEST_IFINDEX)
            .expect("encode fixed addrgen request");
        let mut expected = vec![48, 0, 0, 0, 16, 0, 5, 0];
        expected.extend_from_slice(&TEST_SEQUENCE.to_ne_bytes());
        expected.extend_from_slice(&[0; 4]);
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(&TEST_IFINDEX.to_ne_bytes());
        expected.extend_from_slice(&[0; 8]);
        expected.extend_from_slice(&[16, 0, 26, 0, 12, 0, 10, 0, 5, 0, 8, 0, 1, 0, 0, 0]);
        assert_eq!(addrgen, expected);

        let up = encode_link_up_request(TEST_SEQUENCE, TEST_IFINDEX).expect("encode fixed UP");
        assert_eq!(up.len(), 32);
        assert_eq!(read_u16(&up, 4).expect("UP type"), RTM_NEWLINK);
        assert_eq!(
            read_u16(&up, 6).expect("UP flags"),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(read_u32(&up, 24).expect("UP ifi_flags"), IFF_UP);
        assert_eq!(read_u32(&up, 28).expect("UP change mask"), IFF_UP);

        let delete =
            encode_delete_link_request(TEST_SEQUENCE, TEST_IFINDEX).expect("encode fixed delete");
        assert_eq!(delete.len(), 32);
        assert_eq!(read_u16(&delete, 4).expect("delete type"), RTM_DELLINK);
        assert_eq!(
            read_u16(&delete, 6).expect("delete flags"),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(&delete[24..32], &[0; 8]);
    }

    #[test]
    fn fixed_encoders_reject_zero_or_unrepresentable_authority() {
        assert!(encode_addrgen_none_request(TEST_SEQUENCE, 0).is_err());
        assert!(encode_link_up_request(TEST_SEQUENCE, 0).is_err());
        assert!(encode_delete_link_request(TEST_SEQUENCE, 0).is_err());
        assert!(encode_get_link_payload(0).is_err());
        assert!(encode_get_link_payload(i32::MAX as u32 + 1).is_err());
        assert!(encode_message(RTM_NEWLINK, NLM_F_REQUEST, 0, &[]).is_err());
        assert!(encode_get_link_name_payload("").is_err());
        assert!(encode_get_link_name_payload("name\0suffix").is_err());
    }

    #[test]
    fn canonical_ack_is_bound_to_exact_request() {
        let request = encode_link_up_request(TEST_SEQUENCE, TEST_IFINDEX).expect("request");
        let success = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        assert_eq!(
            parse_ack(&success, TEST_PORT, &request).expect("success ACK"),
            Ack::Success
        );

        let rejection = ack_reply(&request, -libc::EPERM, 0, &request[NLMSG_HEADER_LEN..]);
        assert_eq!(
            parse_ack(&rejection, TEST_PORT, &request).expect("negative ACK"),
            Ack::Rejected(libc::EPERM)
        );
    }

    #[test]
    fn ack_parser_rejects_sender_header_extack_echo_and_framing_substitution() {
        let request = encode_link_up_request(TEST_SEQUENCE, TEST_IFINDEX).expect("request");
        let mut wrong_sender = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        wrong_sender.sender = SocketAddr::new(1, 0);
        assert!(parse_ack(&wrong_sender, TEST_PORT, &request).is_err());

        let mut wrong_sequence = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        wrong_sequence.bytes[8..12].copy_from_slice(&9_u32.to_ne_bytes());
        assert!(parse_ack(&wrong_sequence, TEST_PORT, &request).is_err());
        let wrong_port = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        assert!(parse_ack(&wrong_port, TEST_PORT + 1, &request).is_err());
        assert!(parse_ack(&ack_reply(&request, 0, 0, &[]), TEST_PORT, &request).is_err());
        assert!(
            parse_ack(
                &ack_reply(&request, 0, NLM_F_CAPPED | NLM_F_ACK_TLVS, &[]),
                TEST_PORT,
                &request,
            )
            .is_err()
        );
        assert!(
            parse_ack(
                &ack_reply(&request, -libc::EPERM, 0, &[]),
                TEST_PORT,
                &request,
            )
            .is_err()
        );
        let mut multiple = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        multiple
            .bytes
            .extend_from_slice(&[16, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(parse_ack(&multiple, TEST_PORT, &request).is_err());
    }

    #[test]
    fn all_five_exact_debian_link_profiles_parse() {
        for profile in [
            ObservedProfile::DownEui64,
            ObservedProfile::DownNone,
            ObservedProfile::UpNoCarrierDownNone,
            ObservedProfile::UpNoCarrierLowerLayerDownNone,
            ObservedProfile::UpCarrierNone,
        ] {
            let observed = parse_link_reply(&link_reply(profile), TEST_PORT, TEST_SEQUENCE)
                .expect("exact profile");
            assert_eq!(observed.profile, profile);
            assert_eq!(observed.ifindex, TEST_IFINDEX);
            assert_eq!(observed.peer_ifindex, TEST_PEER_IFINDEX);
            assert_eq!(observed.name, TEST_NAME);
        }
    }

    fn replace_first_attribute_payload(reply: &mut NetlinkReply, kind: u16, replacement: &[u8]) {
        let start = NLMSG_HEADER_LEN + IFINFO_LEN;
        let attributes = parse_attributes(&reply.bytes[start..]).expect("fixture attributes");
        let target = attributes
            .into_iter()
            .find(|attribute| attribute.kind == kind)
            .expect("fixture target attribute");
        assert_eq!(target.payload.len(), replacement.len());
        let offset = target.payload.as_ptr() as usize - reply.bytes.as_ptr() as usize;
        reply.bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
    }

    fn fixed_icmp_echo_statistics32_payload() -> Vec<u8> {
        (0..(VETH_LINK_STATS_BYTES / size_of::<u32>()))
            .flat_map(|index| {
                u32::try_from(fixed_icmp_echo_statistic(index))
                    .expect("fixed echo statistic fits u32")
                    .to_ne_bytes()
            })
            .collect()
    }

    fn fixed_icmp_echo_statistics64_payload() -> Vec<u8> {
        (0..(VETH_LINK_STATS64_BYTES / size_of::<u64>()))
            .flat_map(|index| fixed_icmp_echo_statistic(index).to_ne_bytes())
            .collect()
    }

    fn replace_link_statistics(reply: &mut NetlinkReply, statistics32: &[u8], statistics64: &[u8]) {
        replace_first_attribute_payload(reply, IFLA_STATS, statistics32);
        replace_first_attribute_payload(reply, IFLA_STATS64, statistics64);
    }

    fn fixed_icmp_echo_link_reply() -> NetlinkReply {
        let mut reply = link_reply(ObservedProfile::UpCarrierNone);
        replace_link_statistics(
            &mut reply,
            &fixed_icmp_echo_statistics32_payload(),
            &fixed_icmp_echo_statistics64_payload(),
        );
        reply
    }

    fn set_statistics32(payload: &mut [u8], index: usize, value: u32) {
        let start = index * size_of::<u32>();
        payload[start..start + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
    }

    fn set_statistics64(payload: &mut [u8], index: usize, value: u64) {
        let start = index * size_of::<u64>();
        payload[start..start + size_of::<u64>()].copy_from_slice(&value.to_ne_bytes());
    }

    fn fixed_icmp_cleanup_link_reply(
        receive: Option<(u64, u64)>,
        transmit: Option<(u64, u64)>,
    ) -> NetlinkReply {
        let mut reply = link_reply(ObservedProfile::UpCarrierNone);
        let mut statistics32 = vec![0; VETH_LINK_STATS_BYTES];
        let mut statistics64 = vec![0; VETH_LINK_STATS64_BYTES];
        for (direction, values) in [receive, transmit].into_iter().enumerate() {
            if let Some((packets, bytes)) = values {
                set_statistics32(
                    &mut statistics32,
                    direction,
                    u32::try_from(packets).expect("test packet count fits u32"),
                );
                set_statistics32(
                    &mut statistics32,
                    direction + 2,
                    u32::try_from(bytes).expect("test byte count fits u32"),
                );
                set_statistics64(&mut statistics64, direction, packets);
                set_statistics64(&mut statistics64, direction + 2, bytes);
            }
        }
        replace_link_statistics(&mut reply, &statistics32, &statistics64);
        reply
    }

    #[test]
    fn ordinary_retirement_profile_rejects_post_echo_statistics() {
        let reply = fixed_icmp_echo_link_reply();
        assert!(parse_link_reply(&reply, TEST_PORT, TEST_SEQUENCE).is_err());
    }

    #[test]
    fn fixed_icmp_echo_retirement_profile_accepts_only_exact_statistics() {
        let exact = fixed_icmp_echo_link_reply();
        let observed = parse_fixed_icmp_echo_link_reply(&exact, TEST_PORT, TEST_SEQUENCE)
            .expect("exact fixed ICMP echo link profile");
        assert_eq!(observed.profile, ObservedProfile::UpCarrierNone);

        let zero = link_reply(ObservedProfile::UpCarrierNone);
        assert!(parse_fixed_icmp_echo_link_reply(&zero, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut overcount = fixed_icmp_echo_link_reply();
        let mut overcount32 = fixed_icmp_echo_statistics32_payload();
        let mut overcount64 = fixed_icmp_echo_statistics64_payload();
        overcount32[..size_of::<u32>()].copy_from_slice(&2_u32.to_ne_bytes());
        overcount64[..size_of::<u64>()].copy_from_slice(&2_u64.to_ne_bytes());
        replace_link_statistics(&mut overcount, &overcount32, &overcount64);
        assert!(parse_fixed_icmp_echo_link_reply(&overcount, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut impossible = fixed_icmp_echo_link_reply();
        let mut impossible32 = fixed_icmp_echo_statistics32_payload();
        let mut impossible64 = fixed_icmp_echo_statistics64_payload();
        impossible32[2 * size_of::<u32>()..3 * size_of::<u32>()]
            .copy_from_slice(&0_u32.to_ne_bytes());
        impossible64[2 * size_of::<u64>()..3 * size_of::<u64>()]
            .copy_from_slice(&0_u64.to_ne_bytes());
        replace_link_statistics(&mut impossible, &impossible32, &impossible64);
        assert!(parse_fixed_icmp_echo_link_reply(&impossible, TEST_PORT, TEST_SEQUENCE).is_err());
    }

    #[test]
    fn fixed_icmp_cleanup_profile_is_bounded_and_cross_width_consistent() {
        for accepted in [
            fixed_icmp_cleanup_link_reply(None, None),
            fixed_icmp_cleanup_link_reply(
                Some((FIXED_ICMP_ECHO_PACKETS, FIXED_ICMP_ECHO_ETHERNET_BYTES)),
                None,
            ),
            fixed_icmp_cleanup_link_reply(
                None,
                Some((FIXED_ICMP_ECHO_PACKETS, FIXED_ICMP_ECHO_ETHERNET_BYTES)),
            ),
            fixed_icmp_echo_link_reply(),
        ] {
            parse_fixed_icmp_cleanup_link_reply(&accepted, TEST_PORT, TEST_SEQUENCE)
                .expect("bounded possible-send cleanup profile");
        }

        let overcount = fixed_icmp_cleanup_link_reply(Some((2, 148)), None);
        assert!(parse_fixed_icmp_cleanup_link_reply(&overcount, TEST_PORT, TEST_SEQUENCE).is_err());

        let impossible = fixed_icmp_cleanup_link_reply(Some((1, 0)), None);
        assert!(
            parse_fixed_icmp_cleanup_link_reply(&impossible, TEST_PORT, TEST_SEQUENCE).is_err()
        );

        let mut inconsistent = fixed_icmp_cleanup_link_reply(
            Some((FIXED_ICMP_ECHO_PACKETS, FIXED_ICMP_ECHO_ETHERNET_BYTES)),
            None,
        );
        replace_first_attribute_payload(&mut inconsistent, IFLA_STATS, &[0; VETH_LINK_STATS_BYTES]);
        assert!(
            parse_fixed_icmp_cleanup_link_reply(&inconsistent, TEST_PORT, TEST_SEQUENCE).is_err()
        );

        let mut other_counter = fixed_icmp_cleanup_link_reply(None, None);
        let mut statistics32 = vec![0; VETH_LINK_STATS_BYTES];
        let mut statistics64 = vec![0; VETH_LINK_STATS64_BYTES];
        set_statistics32(&mut statistics32, 4, 1);
        set_statistics64(&mut statistics64, 4, 1);
        replace_link_statistics(&mut other_counter, &statistics32, &statistics64);
        assert!(
            parse_fixed_icmp_cleanup_link_reply(&other_counter, TEST_PORT, TEST_SEQUENCE).is_err()
        );
    }

    #[test]
    fn readback_rejects_flag_operstate_carrier_and_addrgen_substitutions() {
        let mut missing_running = link_reply(ObservedProfile::UpCarrierNone);
        let wrong_flags = FIXED_UP_CARRIER_FLAGS & !IFF_RUNNING;
        missing_running.bytes[24..28].copy_from_slice(&wrong_flags.to_ne_bytes());
        assert!(parse_link_reply(&missing_running, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut wrong_operstate = link_reply(ObservedProfile::UpNoCarrierDownNone);
        replace_first_attribute_payload(&mut wrong_operstate, IFLA_OPERSTATE, &[IF_OPER_UP]);
        assert!(parse_link_reply(&wrong_operstate, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut wrong_carrier = link_reply(ObservedProfile::DownNone);
        replace_first_attribute_payload(&mut wrong_carrier, IFLA_CARRIER, &[1]);
        assert!(parse_link_reply(&wrong_carrier, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut stable_privacy_mode = link_reply(ObservedProfile::DownNone);
        replace_first_attribute_payload(
            &mut stable_privacy_mode,
            IFLA_AF_SPEC,
            &address_family_payload(2),
        );
        assert!(parse_link_reply(&stable_privacy_mode, TEST_PORT, TEST_SEQUENCE).is_err());
    }

    #[test]
    fn readback_rejects_identity_telemetry_xdp_and_nested_attribute_substitution() {
        let mut wrong_name = link_reply(ObservedProfile::DownNone);
        replace_first_attribute_payload(&mut wrong_name, IFLA_IFNAME, b"vpb01234567\0");
        let observed = parse_link_reply(&wrong_name, TEST_PORT, TEST_SEQUENCE)
            .expect("parser returns changed identity for binding layer");
        assert!(
            require_expected_link(
                Some(observed),
                TEST_IFINDEX,
                TEST_PEER_IFINDEX,
                TEST_NAME,
                Some(TEST_MAC),
                Some(0),
                &[ObservedProfile::DownNone],
            )
            .is_err()
        );

        let mut nonzero_stats = link_reply(ObservedProfile::DownNone);
        let mut stats = [0; VETH_LINK_STATS_BYTES];
        stats[0] = 1;
        replace_first_attribute_payload(&mut nonzero_stats, IFLA_STATS, &stats);
        assert!(parse_link_reply(&nonzero_stats, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut attached_xdp = link_reply(ObservedProfile::DownNone);
        let attached = attribute(IFLA_XDP_ATTACHED, 0, &[1]);
        replace_first_attribute_payload(&mut attached_xdp, IFLA_XDP, &attached);
        assert!(parse_link_reply(&attached_xdp, TEST_PORT, TEST_SEQUENCE).is_err());

        let mut bad_af_flags = link_reply(ObservedProfile::DownNone);
        let flagged = {
            let ipv4 = attribute(IFLA_INET_CONF, 0, &[0; 4]);
            let ipv6 = attribute(IFLA_INET6_ADDR_GEN_MODE, 0, &[IN6_ADDR_GEN_MODE_NONE]);
            let mut families = attribute(AF_INET, NLA_F_NESTED, &ipv4);
            families.extend(attribute(AF_INET6, 0, &ipv6));
            families
        };
        replace_first_attribute_payload(&mut bad_af_flags, IFLA_AF_SPEC, &flagged);
        assert!(parse_link_reply(&bad_af_flags, TEST_PORT, TEST_SEQUENCE).is_err());
    }

    fn proof_fixture() -> FixedPairAbsenceProof {
        let parent_namespace = NamespaceIdentity {
            device: 1,
            inode: 10,
        };
        FixedPairAbsenceProof {
            parent_namespace,
            pairs: [
                PairBinding {
                    endpoint: FixedVethEndpoint::A,
                    parent_name: "vpa01234567".to_owned(),
                    parent_ifindex: 2,
                    peer_ifindex: 3,
                    target_namespace: NamespaceIdentity {
                        device: 2,
                        inode: 20,
                    },
                    parent_peer_netnsid: 0,
                    parent_mac: [0x02, 1, 2, 3, 4, 5],
                    endpoint_mac: Some([0x02, 6, 7, 8, 9, 10]),
                    endpoint_peer_netnsid: Some(0),
                },
                PairBinding {
                    endpoint: FixedVethEndpoint::B,
                    parent_name: "vpb01234567".to_owned(),
                    parent_ifindex: 4,
                    peer_ifindex: 5,
                    target_namespace: NamespaceIdentity {
                        device: 3,
                        inode: 30,
                    },
                    parent_peer_netnsid: 1,
                    parent_mac: [0x02, 11, 12, 13, 14, 15],
                    endpoint_mac: Some([0x02, 16, 17, 18, 19, 20]),
                    endpoint_peer_netnsid: Some(0),
                },
            ],
            _thread_bound: PhantomData,
        }
    }

    const fn ipv4_identity(device: u64, inode: u64) -> Ipv4NamespaceIdentity {
        Ipv4NamespaceIdentity::from_test_parts(device, inode)
    }

    const fn veth_identity(device: u64, inode: u64) -> VethTargetNamespaceIdentity {
        VethTargetNamespaceIdentity::from_test_parts(device, inode)
    }

    #[test]
    fn absence_proof_binds_every_veth_lineage_component() {
        let proof = proof_fixture();
        assert!(proof.validates_veth_pair(
            FixedVethEndpoint::A,
            "vpa01234567",
            2,
            3,
            0,
            veth_identity(2, 20),
        ));
        for valid in [
            proof.validates_veth_pair(
                FixedVethEndpoint::B,
                "vpa01234567",
                2,
                3,
                0,
                veth_identity(2, 20),
            ),
            proof.validates_veth_pair(
                FixedVethEndpoint::A,
                "vpa01234568",
                2,
                3,
                0,
                veth_identity(2, 20),
            ),
            proof.validates_veth_pair(
                FixedVethEndpoint::A,
                "vpa01234567",
                9,
                3,
                0,
                veth_identity(2, 20),
            ),
            proof.validates_veth_pair(
                FixedVethEndpoint::A,
                "vpa01234567",
                2,
                9,
                0,
                veth_identity(2, 20),
            ),
            proof.validates_veth_pair(
                FixedVethEndpoint::A,
                "vpa01234567",
                2,
                3,
                9,
                veth_identity(2, 20),
            ),
            proof.validates_veth_pair(
                FixedVethEndpoint::A,
                "vpa01234567",
                2,
                3,
                0,
                veth_identity(9, 20),
            ),
        ] {
            assert!(!valid);
        }
    }

    #[test]
    fn absence_proof_binds_every_ipv4_lineage_component() {
        let proof = proof_fixture();
        assert!(proof.validates_ipv4_address(
            FixedIpv4Address::ParentA,
            2,
            "vpa01234567",
            ipv4_identity(1, 10),
            ipv4_identity(2, 20),
        ));
        assert!(proof.validates_ipv4_address(
            FixedIpv4Address::EndpointA,
            3,
            FIXED_VETH_PEER_NAME,
            ipv4_identity(2, 20),
            ipv4_identity(2, 20),
        ));
        for valid in [
            proof.validates_ipv4_address(
                FixedIpv4Address::ParentA,
                3,
                "vpa01234567",
                ipv4_identity(1, 10),
                ipv4_identity(2, 20),
            ),
            proof.validates_ipv4_address(
                FixedIpv4Address::ParentA,
                2,
                FIXED_VETH_PEER_NAME,
                ipv4_identity(1, 10),
                ipv4_identity(2, 20),
            ),
            proof.validates_ipv4_address(
                FixedIpv4Address::ParentA,
                2,
                "vpa01234567",
                ipv4_identity(9, 10),
                ipv4_identity(2, 20),
            ),
            proof.validates_ipv4_address(
                FixedIpv4Address::ParentA,
                2,
                "vpa01234567",
                ipv4_identity(1, 10),
                ipv4_identity(9, 20),
            ),
        ] {
            assert!(!valid);
        }
    }

    fn endpoint_route_lineage(
        proof: &FixedPairAbsenceProof,
        local_endpoint: FixedVethEndpoint,
    ) -> FixedEndpointRoutePairLineage {
        FixedEndpointRoutePairLineage {
            parent_namespace: proof.parent_namespace,
            local_endpoint,
            pairs: proof.pairs.clone(),
        }
    }

    #[test]
    fn absence_proof_binds_both_orientations_of_exact_endpoint_route_lineage() {
        let proof = proof_fixture();
        for endpoint in [FixedVethEndpoint::A, FixedVethEndpoint::B] {
            assert!(proof.validates_endpoint_route(&endpoint_route_lineage(&proof, endpoint)));
        }
    }

    #[test]
    fn all_up_binding_rejects_cross_topology_pair_snapshot() {
        let retained = proof_fixture();
        let supplied = [
            PairAuthorityIdentity::from_binding(&retained.pairs[0]),
            PairAuthorityIdentity::from_binding(&retained.pairs[1]),
        ];
        bind_endpoint_route_pair_lineage(retained.parent_namespace, &retained.pairs, &supplied)
            .expect("same all-UP pair snapshot");

        let mut other_topology = retained.pairs.clone();
        other_topology[1].parent_ifindex = 9;
        assert!(
            bind_endpoint_route_pair_lineage(retained.parent_namespace, &other_topology, &supplied)
                .is_err()
        );
    }

    #[test]
    fn endpoint_route_retirement_rejects_wrong_parent_namespace() {
        let proof = proof_fixture();
        let mut lineage = endpoint_route_lineage(&proof, FixedVethEndpoint::A);
        lineage.parent_namespace = NamespaceIdentity {
            device: 9,
            inode: 90,
        };
        assert!(!proof.validates_endpoint_route(&lineage));
    }

    #[test]
    fn endpoint_route_retirement_rejects_changed_pair_lineage() {
        let proof = proof_fixture();
        let exact = endpoint_route_lineage(&proof, FixedVethEndpoint::A);
        let mut variants = Vec::new();

        let mut changed = exact.clone();
        changed.pairs[0].parent_name = "wrong".to_owned();
        variants.push(changed);
        let mut changed = exact.clone();
        changed.pairs[0].target_namespace.inode = 99;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.pairs[1].peer_ifindex = 9;
        variants.push(changed);
        let mut changed = exact;
        changed.pairs[1].endpoint_mac = Some([0x02, 99, 98, 97, 96, 95]);
        variants.push(changed);

        assert!(
            variants
                .iter()
                .all(|lineage| !proof.validates_endpoint_route(lineage))
        );
    }

    #[test]
    fn endpoint_route_proof_allows_equal_peer_indices_in_distinct_namespaces() {
        let mut proof = proof_fixture();
        proof.pairs[1].peer_ifindex = proof.pairs[0].peer_ifindex;
        let lineage = endpoint_route_lineage(&proof, FixedVethEndpoint::A);
        assert!(proof.validates_endpoint_route(&lineage));
    }

    #[test]
    fn permanent_neighbour_lineage_pins_each_exact_pair_and_mac_snapshot() {
        let proof = proof_fixture();
        for endpoint in [FixedVethEndpoint::A, FixedVethEndpoint::B] {
            let lineage = FixedPermanentNeighbourPairLineage::from_test_parts(endpoint);
            let pair = &proof.pairs[endpoint_index(endpoint)];
            assert_eq!(lineage.endpoint(), endpoint);
            assert_eq!(lineage.parent_name(), pair.parent_name);
            assert_eq!(lineage.parent_ifindex(), pair.parent_ifindex);
            assert_eq!(lineage.endpoint_ifindex(), pair.peer_ifindex);
            assert_eq!(lineage.parent_mac(), pair.parent_mac);
            assert_eq!(
                lineage.endpoint_mac().expect("endpoint MAC"),
                pair.endpoint_mac.unwrap()
            );
            assert!(proof.validates_permanent_neighbour(&lineage));
        }
    }

    #[test]
    fn permanent_neighbour_retirement_rejects_changed_pair_or_parent_lineage() {
        let proof = proof_fixture();
        let exact = FixedPermanentNeighbourPairLineage::from_test_parts(FixedVethEndpoint::A);
        let mut variants = Vec::new();

        let mut changed = exact.clone();
        changed.parent_namespace.inode += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.pair.parent_name = "wrong".to_owned();
        variants.push(changed);
        let mut changed = exact.clone();
        changed.pair.peer_ifindex += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.pair.parent_mac[1] ^= 1;
        variants.push(changed);
        let mut changed = exact;
        changed.pair.endpoint_mac = Some([0x02, 99, 98, 97, 96, 95]);
        variants.push(changed);

        assert!(
            variants
                .iter()
                .all(|lineage| !proof.validates_permanent_neighbour(lineage))
        );
    }

    #[test]
    fn attribute_parser_rejects_bad_padding_conflicting_flags_and_resource_exhaustion() {
        let mut nonzero_padding = attribute(IFLA_CARRIER, 0, &[0]);
        *nonzero_padding.last_mut().expect("padding") = 1;
        assert!(parse_attributes(&nonzero_padding).is_err());
        let conflicting = attribute(IFLA_CARRIER, NLA_F_NESTED | NLA_F_NET_BYTEORDER, &[0]);
        assert!(parse_attributes(&conflicting).is_err());
        let mut too_many = Vec::new();
        for _ in 0..=MAX_ATTRIBUTES {
            too_many.extend(attribute(IFLA_CARRIER, 0, &[0]));
        }
        assert!(matches!(
            parse_attributes(&too_many),
            Err(FixedLinkOperationError::Limit)
        ));
    }

    #[test]
    fn link_up_staging_authority_accepts_every_ordered_partial_prefix() {
        for completed in 0..=4 {
            let mut stages = [LinkStage::DownNone; 4];
            stages[..completed].fill(LinkStage::UpObserved);
            assert!(has_up_staging_authority(
                true, stages, [true; 4], [false; 4]
            ));
        }

        assert!(!has_up_staging_authority(
            false,
            [LinkStage::DownNone; 4],
            [true; 4],
            [false; 4]
        ));
        assert!(!has_up_staging_authority(
            true,
            [LinkStage::DownNone; 4],
            [true, true, true, false],
            [false; 4]
        ));
        assert!(!has_up_staging_authority(
            true,
            [
                LinkStage::UpObserved,
                LinkStage::UpAmbiguous,
                LinkStage::DownNone,
                LinkStage::DownNone,
            ],
            [true; 4],
            [false; 4]
        ));
        assert!(!has_up_staging_authority(
            true,
            [
                LinkStage::UpObserved,
                LinkStage::DownNone,
                LinkStage::UpObserved,
                LinkStage::DownNone,
            ],
            [true; 4],
            [false; 4]
        ));
        assert!(!has_up_staging_authority(
            true,
            [LinkStage::UpObserved; 4],
            [true; 4],
            [true, false, false, false]
        ));
    }

    #[test]
    fn distinct_pair_bindings_allow_equal_indices_across_endpoint_namespaces() {
        let mut proof = proof_fixture();
        proof.pairs[1].peer_ifindex = proof.pairs[0].peer_ifindex;
        assert_ne!(
            proof.pairs[0].target_namespace,
            proof.pairs[1].target_namespace
        );
        assert!(require_distinct_pair_bindings(&proof.pairs).is_ok());

        proof.pairs[1].parent_ifindex = proof.pairs[0].parent_ifindex;
        assert!(require_distinct_pair_bindings(&proof.pairs).is_err());
    }
}
