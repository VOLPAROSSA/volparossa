//! Fixed endpoint-route installation with deletion-only affine retirement.
//!
//! This module can install only the two host routes required by the fixed
//! disposable topology:
//!
//! - endpoint A: `10.241.2.2/32 via 10.241.1.1 dev eth0`;
//! - endpoint B: `10.241.1.2/32 via 10.241.2.1 dev eth0`.
//!
//! Route, gateway, output-interface, and namespace facts are derived from the
//! retained veth/address lineage. Callers cannot supply any of those fields.
//! Installation requires the enclosing all-links-up authority and never uses
//! the earlier down-link verification APIs. Every request is an exclusive
//! `RTM_NEWROUTE` with fixed main-table, destination, gateway, and output-
//! interface attributes, an exact ACK, and a fresh bounded route dump.
//!
//! There is deliberately no route-delete operation here. Once a request could
//! have reached the kernel, the returned affine authority remains armed even
//! if reconciliation observes absence. It can be retired only against the
//! existing proof that both veth pairs are absent after direct pair deletion;
//! dropping armed authority aborts fail closed.

use std::{
    io,
    marker::PhantomData,
    os::fd::{AsFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use rustix::fs::{FsWord, Mode, OFlags, fstat, fstatfs, open};
use thiserror::Error;
use volparossa_linux_uapi::namespace_type;

use super::{
    ipv4::{FixedIpv4Address, FixedIpv4AddressOwner, Ipv4NamespaceIdentity},
    link::{AllLinksUp, FixedEndpointRoutePairLineage, FixedPairAbsenceProof},
    veth::{FIXED_VETH_PEER_NAME, FixedVethEndpoint, FixedVethPair, VethTargetNamespaceIdentity},
};

const ROUTE_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;

const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_NETLINK_TOTAL_BYTES: usize = 256 * 1024;
const MAX_NETLINK_DATAGRAMS: usize = 32;
const MAX_NETLINK_FRAMES: usize = 256;
const MAX_ROUTE_RECORDS: usize = 192;
const MAX_ATTRIBUTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 128;

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const RTMSG_LEN: usize = 12;
const ATTRIBUTE_HEADER_LEN: usize = 4;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP_FILTERED: u16 = 0x0020;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_CAPPED: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_ACK_TLVS: u16 = 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;

const AF_INET: u8 = 2;
const FIXED_ROUTE_PREFIX_LENGTH: u8 = 32;
const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

/// Bounded RTNETLINK, namespace, or retained-lineage failure.
#[derive(Debug, Error)]
pub(crate) enum FixedRouteOperationError {
    /// A descriptor, socket, send, receive, or wait operation failed.
    #[error("fixed endpoint-route operation {operation} failed: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Kernel or standard-library error.
        #[source]
        source: io::Error,
    },
    /// The kernel returned an exact negative ACK.
    #[error("kernel rejected fixed endpoint-route operation {operation} with errno {errno}")]
    Kernel {
        /// Static operation label.
        operation: &'static str,
        /// Positive Linux errno.
        errno: i32,
    },
    /// A response, descriptor, or retained fact contradicted the fixed protocol.
    #[error("fixed endpoint-route proof was unsafe: {0}")]
    Unsafe(&'static str),
    /// A main-table sibling uses the fixed destination but is not the exact route.
    #[error("fixed endpoint-route destination has a conflicting main-table sibling")]
    Conflicting,
    /// A response or encoding exceeded a fixed resource limit.
    #[error("fixed endpoint-route operation exceeded its resource bound")]
    Limit,
}

impl FixedRouteOperationError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn errno(operation: &'static str, errno: i32) -> Self {
        Self::Kernel { operation, errno }
    }
}

/// Failure to derive a fixed route plan before any route request exists.
#[derive(Debug, Error)]
#[error("fixed endpoint-route plan derivation failed")]
pub(crate) struct FixedRoutePlanError(#[source] FixedRouteOperationError);

/// Failure to install one fixed endpoint route.
#[derive(Debug, Error)]
pub(crate) enum FixedRouteInstallError {
    /// Failure before any request could have reached the kernel.
    #[error("fixed endpoint-route installation failed before mutation")]
    BeforeMutation(#[source] FixedRouteOperationError),
    /// An exact negative ACK was reconciled to fresh route absence.
    #[error("kernel rejected exclusive fixed endpoint-route installation with errno {0}")]
    Rejected(i32),
    /// A request may have executed; only pair deletion and its absence proof can
    /// retire the included authority.
    #[error("fixed endpoint-route installation crossed the deletion-only boundary")]
    DeletionBound {
        /// Original ambiguity, rejection conflict, or readback failure.
        #[source]
        source: FixedRouteOperationError,
        /// Armed authority that must survive until pair-absence retirement.
        authority: Box<FixedEndpointRouteRetirement>,
    },
}

/// Failure to freshly verify an installed fixed endpoint route.
#[derive(Debug, Error)]
#[error("retained fixed endpoint-route verification failed")]
pub(crate) struct FixedRouteVerifyError(#[source] FixedRouteOperationError);

/// Failure to bind route authority to the full post-delete pair-absence proof.
#[derive(Debug, Error)]
#[error("fixed endpoint-route retirement proof did not match retained lineage")]
pub(crate) struct FixedRouteRetirementError(#[source] FixedRouteOperationError);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NamespaceIdentity {
    const fn from_ipv4(identity: Ipv4NamespaceIdentity) -> Self {
        Self {
            device: identity.device(),
            inode: identity.inode(),
        }
    }
}

#[derive(Debug)]
struct RetainedCurrentNamespace {
    descriptor: OwnedFd,
    identity: NamespaceIdentity,
}

impl RetainedCurrentNamespace {
    fn capture<Fd: AsFd>(supplied: &Fd) -> Result<Self, FixedRouteOperationError> {
        validate_namespace_descriptor(supplied)?;
        let supplied_identity = object_identity(supplied)?;
        let current = open_current_network_namespace()?;
        if object_identity(&current)? != supplied_identity {
            return Err(FixedRouteOperationError::Unsafe(
                "supplied namespace descriptor is not the current thread network namespace",
            ));
        }
        let descriptor = supplied.as_fd().try_clone_to_owned().map_err(|source| {
            FixedRouteOperationError::io("retain current route network namespace", source)
        })?;
        validate_namespace_descriptor(&descriptor)?;
        if object_identity(&descriptor)? != supplied_identity {
            return Err(FixedRouteOperationError::Unsafe(
                "route namespace descriptor changed during cloning",
            ));
        }
        Ok(Self {
            descriptor,
            identity: supplied_identity,
        })
    }

    fn verify_current(&self) -> Result<(), FixedRouteOperationError> {
        validate_namespace_descriptor(&self.descriptor)?;
        if object_identity(&self.descriptor)? != self.identity
            || object_identity(&open_current_network_namespace()?)? != self.identity
        {
            return Err(FixedRouteOperationError::Unsafe(
                "retained route namespace is no longer current",
            ));
        }
        Ok(())
    }

    fn verify_retained(&self) -> Result<(), FixedRouteOperationError> {
        validate_namespace_descriptor(&self.descriptor)?;
        if object_identity(&self.descriptor)? != self.identity {
            return Err(FixedRouteOperationError::Unsafe(
                "retained route namespace identity changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedRouteSpecification {
    endpoint: FixedVethEndpoint,
    local_address: FixedIpv4Address,
    destination: FixedIpv4Address,
    gateway: FixedIpv4Address,
}

impl FixedRouteSpecification {
    const fn for_endpoint(endpoint: FixedVethEndpoint) -> Self {
        match endpoint {
            FixedVethEndpoint::A => Self {
                endpoint,
                local_address: FixedIpv4Address::EndpointA,
                destination: FixedIpv4Address::EndpointB,
                gateway: FixedIpv4Address::ParentA,
            },
            FixedVethEndpoint::B => Self {
                endpoint,
                local_address: FixedIpv4Address::EndpointB,
                destination: FixedIpv4Address::EndpointA,
                gateway: FixedIpv4Address::ParentB,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteLineage {
    specification: FixedRouteSpecification,
    activated_pairs: FixedEndpointRoutePairLineage,
    local_ifindex: u32,
    local_interface_name: String,
    local_namespace: NamespaceIdentity,
    local_address_namespace: Ipv4NamespaceIdentity,
    local_target_namespace: VethTargetNamespaceIdentity,
    remote_namespace: NamespaceIdentity,
    remote_target_namespace: VethTargetNamespaceIdentity,
    remote_peer_ifindex: u32,
    remote_interface_name: String,
    parent_ifindex: u32,
    remote_parent_ifindex: u32,
    parent_name: String,
    remote_parent_name: String,
}

#[derive(Debug)]
struct RouteJournal {
    namespace: RetainedCurrentNamespace,
    lineage: RouteLineage,
}

impl RouteJournal {
    fn verify_context(&self) -> Result<(), FixedRouteOperationError> {
        self.namespace.verify_current()?;
        validate_route_lineage(&self.lineage)?;
        if self.namespace.identity != self.lineage.local_namespace {
            return Err(FixedRouteOperationError::Unsafe(
                "route journal namespace no longer matches local endpoint lineage",
            ));
        }
        Ok(())
    }
}

/// Mutation-free, affine plan for one fixed endpoint route.
///
/// Dropping this value is safe because [`install`](Self::install) is the only
/// method that can cross the possibly-sent boundary.
#[must_use = "a fixed endpoint-route plan has not installed its route"]
pub(crate) struct FixedEndpointRoutePlan {
    journal: Option<RouteJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedEndpointRoutePlan {
    /// Derive one route solely from active-link authority, both pair lineages,
    /// the local endpoint-address owner, and the current endpoint namespace.
    ///
    /// The local pair selects route A or B. The remote pair must be the other
    /// endpoint. Equal `eth0` ifindices are accepted across distinct endpoint
    /// namespaces; parent-namespace interface aliases are rejected.
    pub(crate) fn derive<Fd: AsFd>(
        all_links_up: &AllLinksUp,
        current_namespace: &Fd,
        local_pair: &FixedVethPair,
        remote_pair: &FixedVethPair,
        local_address: &FixedIpv4AddressOwner,
    ) -> Result<Self, FixedRoutePlanError> {
        let activated_pairs = all_links_up
            .bind_endpoint_route_pairs(local_pair, remote_pair)
            .map_err(|_| {
                FixedRoutePlanError(FixedRouteOperationError::Unsafe(
                    "all-links-up authority does not bind the retained route pairs",
                ))
            })?;
        let namespace =
            RetainedCurrentNamespace::capture(current_namespace).map_err(FixedRoutePlanError)?;
        let specification = FixedRouteSpecification::for_endpoint(local_pair.endpoint());
        let local_target = local_pair.target_namespace_identity();
        let remote_target = remote_pair.target_namespace_identity();
        let lineage = RouteLineage {
            specification,
            activated_pairs,
            local_ifindex: local_pair.peer_ifindex(),
            local_interface_name: local_pair.peer_name().to_owned(),
            local_namespace: NamespaceIdentity {
                device: local_target.device(),
                inode: local_target.inode(),
            },
            local_address_namespace: local_address.namespace_identity(),
            local_target_namespace: local_target,
            remote_namespace: NamespaceIdentity {
                device: remote_target.device(),
                inode: remote_target.inode(),
            },
            remote_target_namespace: remote_target,
            remote_peer_ifindex: remote_pair.peer_ifindex(),
            remote_interface_name: remote_pair.peer_name().to_owned(),
            parent_ifindex: local_pair.parent_ifindex(),
            remote_parent_ifindex: remote_pair.parent_ifindex(),
            parent_name: local_pair.parent_name().to_owned(),
            remote_parent_name: remote_pair.parent_name().to_owned(),
        };
        validate_route_lineage(&lineage).map_err(FixedRoutePlanError)?;
        if local_address.address() != specification.local_address
            || local_address.ifindex() != lineage.local_ifindex
            || local_address.interface_name() != lineage.local_interface_name
            || NamespaceIdentity::from_ipv4(local_address.namespace_identity())
                != lineage.local_namespace
            || namespace.identity != lineage.local_namespace
        {
            return Err(FixedRoutePlanError(FixedRouteOperationError::Unsafe(
                "local endpoint address does not bind the retained route pair",
            )));
        }
        Ok(Self {
            journal: Some(RouteJournal { namespace, lineage }),
            _thread_bound: PhantomData,
        })
    }

    /// Send the sole fixed four-attribute `RTM_NEWROUTE`, parse its exact ACK,
    /// and require a fresh exact route-dump observation before returning
    /// installed authority.
    pub(crate) fn install(mut self) -> Result<FixedEndpointRouteOwner, FixedRouteInstallError> {
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        install_route(journal)
    }
}

/// Affine ownership of one freshly read-back fixed endpoint route.
///
/// This authority has no route-delete method. It must be converted to or used
/// as deletion-bound retirement authority and retired only after pair absence.
#[must_use = "an installed fixed endpoint route requires pair-deletion retirement"]
pub(crate) struct FixedEndpointRouteOwner {
    journal: Option<RouteJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedEndpointRouteOwner {
    /// Route-owning endpoint.
    pub(crate) fn endpoint(&self) -> FixedVethEndpoint {
        self.journal().lineage.specification.endpoint
    }

    /// Freshly re-dump and prove the exact retained route while its namespace is current.
    pub(crate) fn verify(&self) -> Result<(), FixedRouteVerifyError> {
        match observe_route(self.journal()).map_err(FixedRouteVerifyError)? {
            RoutePresence::Exact => Ok(()),
            RoutePresence::Absent => Err(FixedRouteVerifyError(FixedRouteOperationError::Unsafe(
                "retained fixed endpoint route is absent",
            ))),
        }
    }

    /// Convert installed ownership into the only permitted cleanup authority.
    pub(crate) fn into_retirement(mut self) -> FixedEndpointRouteRetirement {
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        FixedEndpointRouteRetirement::new(journal)
    }

    fn journal(&self) -> &RouteJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedEndpointRouteOwner {
    fn drop(&mut self) {
        if self.journal.is_some() {
            std::process::abort();
        }
    }
}

/// Deletion-bound authority for a route request that may have executed.
///
/// The token deliberately has no presence precondition and no mutation API:
/// even an ambiguous request freshly reconciled to absence remains armed until
/// direct veth deletion has produced the existing full pair-absence proof.
#[derive(Debug)]
#[must_use = "route authority must be retired against the full pair-absence proof"]
pub(crate) struct FixedEndpointRouteRetirement {
    journal: Option<RouteJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedEndpointRouteRetirement {
    fn new(journal: RouteJournal) -> Self {
        Self {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }

    /// Fallibly bind this route to the exact local address lineage carried by
    /// the full pair-absence proof without consuming or disarming authority.
    pub(super) fn prevalidate_pair_absence_retirement(
        &self,
        proof: &FixedPairAbsenceProof,
        _pristine_network_proof: &crate::mounts::PristineNetworkRetirementProof,
    ) -> Result<(), FixedRouteRetirementError> {
        let journal = self.journal();
        journal
            .namespace
            .verify_retained()
            .map_err(FixedRouteRetirementError)?;
        if !proof.validates_endpoint_route(&journal.lineage.activated_pairs) {
            return Err(FixedRouteRetirementError(FixedRouteOperationError::Unsafe(
                "pair-absence proof does not bind retained endpoint-route lineage",
            )));
        }
        Ok(())
    }

    /// Infallibly disarm after aggregate prevalidation against the same exact
    /// pair-absence proof used for address and veth retirement.
    pub(super) fn retire_after_validated_pair_absence(
        mut self,
        proof: &FixedPairAbsenceProof,
        pristine_network_proof: &crate::mounts::PristineNetworkRetirementProof,
    ) {
        if self
            .prevalidate_pair_absence_retirement(proof, pristine_network_proof)
            .is_err()
        {
            std::process::abort();
        }
        self.journal = None;
    }

    fn journal(&self) -> &RouteJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedEndpointRouteRetirement {
    fn drop(&mut self) {
        if self.journal.is_some() {
            std::process::abort();
        }
    }
}

fn validate_route_lineage(lineage: &RouteLineage) -> Result<(), FixedRouteOperationError> {
    let expected = FixedRouteSpecification::for_endpoint(lineage.specification.endpoint);
    if lineage.specification != expected
        || lineage.activated_pairs.local_endpoint() != lineage.specification.endpoint
        || lineage.activated_pairs.local_parent_name() != lineage.parent_name
        || lineage.activated_pairs.local_parent_ifindex() != lineage.parent_ifindex
        || lineage.activated_pairs.local_peer_ifindex() != lineage.local_ifindex
        || !lineage
            .activated_pairs
            .local_target_namespace_matches(lineage.local_target_namespace)
        || lineage.activated_pairs.remote_parent_name() != lineage.remote_parent_name
        || lineage.activated_pairs.remote_parent_ifindex() != lineage.remote_parent_ifindex
        || lineage.activated_pairs.remote_peer_ifindex() != lineage.remote_peer_ifindex
        || !lineage
            .activated_pairs
            .remote_target_namespace_matches(lineage.remote_target_namespace)
        || lineage.local_ifindex < 2
        || lineage.local_ifindex > i32::MAX as u32
        || lineage.parent_ifindex == 0
        || lineage.parent_ifindex > i32::MAX as u32
        || lineage.remote_parent_ifindex == 0
        || lineage.remote_parent_ifindex > i32::MAX as u32
        || lineage.parent_ifindex == lineage.remote_parent_ifindex
        || lineage.local_interface_name != FIXED_VETH_PEER_NAME
        || lineage.remote_interface_name != FIXED_VETH_PEER_NAME
        || !valid_interface_name(&lineage.parent_name)
        || !valid_interface_name(&lineage.remote_parent_name)
        || lineage.parent_name == lineage.remote_parent_name
        || lineage.parent_name == FIXED_VETH_PEER_NAME
        || lineage.remote_parent_name == FIXED_VETH_PEER_NAME
        || lineage.local_namespace.device == 0
        || lineage.local_namespace.inode == 0
        || lineage.remote_namespace.device == 0
        || lineage.remote_namespace.inode == 0
        || lineage.local_namespace == lineage.remote_namespace
        || lineage.local_target_namespace.device() != lineage.local_namespace.device
        || lineage.local_target_namespace.inode() != lineage.local_namespace.inode
        || lineage.remote_target_namespace.device() != lineage.remote_namespace.device
        || lineage.remote_target_namespace.inode() != lineage.remote_namespace.inode
        || lineage.remote_peer_ifindex < 2
        || lineage.remote_peer_ifindex > i32::MAX as u32
        || NamespaceIdentity::from_ipv4(lineage.local_address_namespace) != lineage.local_namespace
    {
        return Err(FixedRouteOperationError::Unsafe(
            "retained endpoint-route lineage is invalid or aliased",
        ));
    }
    Ok(())
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name.is_ascii()
        && !name.as_bytes().contains(&0)
}

fn install_route(journal: RouteJournal) -> Result<FixedEndpointRouteOwner, FixedRouteInstallError> {
    journal
        .verify_context()
        .map_err(FixedRouteInstallError::BeforeMutation)?;
    match observe_route(&journal).map_err(FixedRouteInstallError::BeforeMutation)? {
        RoutePresence::Absent => {}
        RoutePresence::Exact => {
            return Err(FixedRouteInstallError::BeforeMutation(
                FixedRouteOperationError::Unsafe(
                    "exact fixed endpoint route already exists before installation",
                ),
            ));
        }
    }
    let payload =
        encode_route_payload(&journal.lineage).map_err(FixedRouteInstallError::BeforeMutation)?;
    let deadline =
        Deadline::after(ROUTE_OPERATION_TIMEOUT).map_err(FixedRouteInstallError::BeforeMutation)?;
    let mut client =
        NetlinkClient::connect(deadline).map_err(FixedRouteInstallError::BeforeMutation)?;
    let sequence = client
        .next_sequence()
        .map_err(FixedRouteInstallError::BeforeMutation)?;
    let request = encode_message(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        sequence,
        &payload,
    )
    .map_err(FixedRouteInstallError::BeforeMutation)?;
    let mut guard = ProvisionalRouteGuard::new(journal);
    match send_bounded(&client.socket, &request, deadline) {
        Ok(()) => guard.mark_possibly_applied(),
        Err(SendFailure::NotSent(source)) => {
            return Err(guard.fail_before_mutation(source));
        }
        Err(SendFailure::PossiblySent(source)) => {
            guard.mark_possibly_applied();
            return guard.reconcile_ambiguous(source);
        }
    }
    let reply = match receive_one(&client.socket, deadline) {
        Ok(reply) => reply,
        Err(source) => return guard.reconcile_ambiguous(source),
    };
    let acknowledgement = match parse_ack(&reply, client.local_port, &request) {
        Ok(acknowledgement) => acknowledgement,
        Err(source) => return guard.reconcile_ambiguous(source),
    };
    drop(client);
    match acknowledgement {
        Ack::Success => match observe_route(guard.journal()) {
            Ok(RoutePresence::Exact) => Ok(guard.into_owner()),
            Ok(RoutePresence::Absent) => guard.deletion_bound(FixedRouteOperationError::Unsafe(
                "ACKed fixed endpoint route is absent from exact readback",
            )),
            Err(source) => guard.deletion_bound(source),
        },
        Ack::Rejected(errno) => match observe_route(guard.journal()) {
            Ok(RoutePresence::Absent) => Err(guard.reject_after_fresh_absence(errno)),
            Ok(RoutePresence::Exact) => guard.deletion_bound(FixedRouteOperationError::Unsafe(
                "rejected exclusive route request conflicts with an exact route",
            )),
            Err(source) => guard.deletion_bound(source),
        },
    }
}

struct ProvisionalRouteGuard {
    journal: Option<RouteJournal>,
    possibly_applied: bool,
}

impl ProvisionalRouteGuard {
    fn new(journal: RouteJournal) -> Self {
        Self {
            journal: Some(journal),
            possibly_applied: false,
        }
    }

    fn journal(&self) -> &RouteJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn mark_possibly_applied(&mut self) {
        self.possibly_applied = true;
    }

    fn fail_before_mutation(mut self, source: FixedRouteOperationError) -> FixedRouteInstallError {
        if self.possibly_applied {
            std::process::abort();
        }
        self.journal = None;
        FixedRouteInstallError::BeforeMutation(source)
    }

    fn reject_after_fresh_absence(mut self, errno: i32) -> FixedRouteInstallError {
        if !self.possibly_applied {
            std::process::abort();
        }
        self.possibly_applied = false;
        self.journal = None;
        FixedRouteInstallError::Rejected(errno)
    }

    fn reconcile_ambiguous(
        self,
        source: FixedRouteOperationError,
    ) -> Result<FixedEndpointRouteOwner, FixedRouteInstallError> {
        if !self.possibly_applied {
            std::process::abort();
        }
        match observe_route(self.journal()) {
            Ok(RoutePresence::Exact) => Ok(self.into_owner()),
            Ok(RoutePresence::Absent) | Err(_) => self.deletion_bound(source),
        }
    }

    fn deletion_bound(
        mut self,
        source: FixedRouteOperationError,
    ) -> Result<FixedEndpointRouteOwner, FixedRouteInstallError> {
        if !self.possibly_applied {
            std::process::abort();
        }
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.possibly_applied = false;
        Err(FixedRouteInstallError::DeletionBound {
            source,
            authority: Box::new(FixedEndpointRouteRetirement::new(journal)),
        })
    }

    fn into_owner(mut self) -> FixedEndpointRouteOwner {
        if !self.possibly_applied {
            std::process::abort();
        }
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.possibly_applied = false;
        FixedEndpointRouteOwner {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for ProvisionalRouteGuard {
    fn drop(&mut self) {
        if self.possibly_applied || self.journal.is_some() {
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoutePresence {
    Absent,
    Exact,
}

fn observe_route(journal: &RouteJournal) -> Result<RoutePresence, FixedRouteOperationError> {
    journal.verify_context()?;
    let deadline = Deadline::after(ROUTE_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(
        RTM_GETROUTE,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        &encode_route_dump_payload(),
    )?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let mut state = RouteDumpState::new(sequence, client.local_port, request);
    let mut budget = ReceiveBudget::dump();
    while !state.done {
        let reply = receive_bounded(&client.socket, deadline, &mut budget)?;
        state.ingest(&reply, &mut budget, &journal.lineage)?;
    }
    deadline.ensure_unexpired()?;
    state.finish()
}

fn encode_route_payload(lineage: &RouteLineage) -> Result<Vec<u8>, FixedRouteOperationError> {
    validate_route_lineage(lineage)?;
    let mut payload = route_message();
    push_attribute(
        &mut payload,
        RTA_TABLE,
        &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
    )?;
    push_attribute(
        &mut payload,
        RTA_DST,
        &lineage.specification.destination.octets(),
    )?;
    push_attribute(
        &mut payload,
        RTA_GATEWAY,
        &lineage.specification.gateway.octets(),
    )?;
    push_attribute(&mut payload, RTA_OIF, &lineage.local_ifindex.to_ne_bytes())?;
    if payload.len() > MAX_REQUEST_BYTES - NLMSG_HEADER_LEN {
        return Err(FixedRouteOperationError::Limit);
    }
    Ok(payload)
}

fn route_message() -> Vec<u8> {
    let mut payload = Vec::with_capacity(RTMSG_LEN);
    payload.extend_from_slice(&[
        AF_INET,
        FIXED_ROUTE_PREFIX_LENGTH,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
    ]);
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    payload
}

fn encode_route_dump_payload() -> Vec<u8> {
    let mut payload = vec![AF_INET, 0, 0, 0, RT_TABLE_UNSPEC, 0, 0, 0];
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    payload
}

fn encode_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, FixedRouteOperationError> {
    if sequence == 0 {
        return Err(FixedRouteOperationError::Unsafe("netlink sequence is zero"));
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedRouteOperationError::Limit)?;
    if length > MAX_REQUEST_BYTES {
        return Err(FixedRouteOperationError::Limit);
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| FixedRouteOperationError::Limit)?
            .to_ne_bytes(),
    );
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn push_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    payload: &[u8],
) -> Result<(), FixedRouteOperationError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedRouteOperationError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| FixedRouteOperationError::Limit)?;
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len())?, 0);
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(FixedRouteOperationError::Limit);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, FixedRouteOperationError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(FixedRouteOperationError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, FixedRouteOperationError> {
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
                .ok_or(FixedRouteOperationError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| FixedRouteOperationError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), FixedRouteOperationError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error())
        }
    }
}

fn timeout_error() -> FixedRouteOperationError {
    FixedRouteOperationError::io(
        "wait for RTNETLINK response",
        io::Error::new(
            io::ErrorKind::TimedOut,
            "fixed endpoint-route deadline expired",
        ),
    )
}

struct NetlinkClient {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkClient {
    fn connect(deadline: Deadline) -> Result<Self, FixedRouteOperationError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|source| FixedRouteOperationError::io("open RTNETLINK socket", source))?;
        socket.set_netlink_get_strict_chk(true).map_err(|source| {
            FixedRouteOperationError::io("enable strict RTNETLINK checking", source)
        })?;
        socket
            .set_non_blocking(true)
            .map_err(|source| FixedRouteOperationError::io("harden RTNETLINK socket", source))?;
        let address = socket
            .bind_auto()
            .map_err(|source| FixedRouteOperationError::io("bind RTNETLINK socket", source))?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(FixedRouteOperationError::Unsafe(
                "RTNETLINK socket binding is not exact",
            ));
        }
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|source| FixedRouteOperationError::io("connect RTNETLINK socket", source))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> Result<u32, FixedRouteOperationError> {
        let current = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(FixedRouteOperationError::Limit)?;
        if current == 0 {
            Err(FixedRouteOperationError::Unsafe(
                "RTNETLINK sequence is zero",
            ))
        } else {
            Ok(current)
        }
    }
}

enum SendFailure {
    NotSent(FixedRouteOperationError),
    PossiblySent(FixedRouteOperationError),
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), SendFailure> {
    loop {
        deadline.ensure_unexpired().map_err(SendFailure::NotSent)?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return Ok(()),
            Ok(_) => {
                return Err(SendFailure::PossiblySent(FixedRouteOperationError::io(
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
                return Err(SendFailure::NotSent(FixedRouteOperationError::io(
                    "send RTNETLINK request",
                    error,
                )));
            }
        }
    }
}

fn send_failure_source(failure: SendFailure) -> FixedRouteOperationError {
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
) -> Result<NetlinkReply, FixedRouteOperationError> {
    let mut budget = ReceiveBudget::single();
    receive_bounded(socket, deadline, &mut budget)
}

fn receive_bounded(
    socket: &Socket,
    deadline: Deadline,
    budget: &mut ReceiveBudget,
) -> Result<NetlinkReply, FixedRouteOperationError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(FixedRouteOperationError::io(
                        "measure RTNETLINK response",
                        error,
                    ));
                }
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(FixedRouteOperationError::Unsafe(
                "RTNETLINK response sender is not the kernel",
            ));
        }
        budget.can_receive(length)?;
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(FixedRouteOperationError::io(
                    "receive RTNETLINK response",
                    error,
                ));
            }
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != length || sender != peek_sender {
            return Err(FixedRouteOperationError::Unsafe(
                "RTNETLINK response changed during bounded receive",
            ));
        }
        budget.record_datagram(length)?;
        return Ok(NetlinkReply { sender, bytes });
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), FixedRouteOperationError> {
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
                    return Err(FixedRouteOperationError::Unsafe(
                        "RTNETLINK poll state is ambiguous",
                    ));
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(source) => return Err(errno_io("poll RTNETLINK socket", source)),
        }
    }
}

struct ReceiveBudget {
    bytes: usize,
    datagrams: usize,
    frames: usize,
    max_bytes: usize,
    max_datagrams: usize,
    max_frames: usize,
}

impl ReceiveBudget {
    const fn single() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_NETLINK_DATAGRAM_BYTES,
            max_datagrams: 1,
            max_frames: 1,
        }
    }

    const fn dump() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_NETLINK_TOTAL_BYTES,
            max_datagrams: MAX_NETLINK_DATAGRAMS,
            max_frames: MAX_NETLINK_FRAMES,
        }
    }

    fn can_receive(&self, length: usize) -> Result<(), FixedRouteOperationError> {
        if !(NLMSG_HEADER_LEN..=MAX_NETLINK_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(FixedRouteOperationError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), FixedRouteOperationError> {
        self.can_receive(length)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or(FixedRouteOperationError::Limit)?;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(FixedRouteOperationError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(FixedRouteOperationError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), FixedRouteOperationError> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(FixedRouteOperationError::Limit)?;
        if self.frames > self.max_frames {
            return Err(FixedRouteOperationError::Limit);
        }
        Ok(())
    }
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
) -> Result<Ack, FixedRouteOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink ACK sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    let flags = read_u16(frame, 6)?;
    if read_u16(frame, 4)? != NLMSG_ERROR
        || read_u32(frame, 8)? != read_u32(request, 8)?
        || read_u32(frame, 12)? != local_port
    {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink ACK header is not exact",
        ));
    }
    let payload = &frame[NLMSG_HEADER_LEN..];
    let embedded_length = NLMSG_ERROR_CODE_LEN
        .checked_add(NLMSG_HEADER_LEN)
        .ok_or(FixedRouteOperationError::Limit)?;
    if payload.len() < embedded_length
        || payload[NLMSG_ERROR_CODE_LEN..embedded_length] != request[..NLMSG_HEADER_LEN]
    {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink ACK does not bind the exact route request header",
        ));
    }
    let trailing = &payload[embedded_length..];
    let errno = read_i32(payload, 0)?;
    if flags & NLM_F_ACK_TLVS != 0 {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink ACK unexpectedly carries extended attributes",
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
        0 => Err(FixedRouteOperationError::Unsafe(
            "successful netlink ACK is not canonical and capped",
        )),
        errno if errno < 0 => Err(FixedRouteOperationError::Unsafe(
            "negative netlink ACK does not exactly echo the route request",
        )),
        _ => Err(FixedRouteOperationError::Unsafe(
            "netlink ACK errno is not canonical",
        )),
    }
}

fn single_frame(bytes: &[u8]) -> Result<&[u8], FixedRouteOperationError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink datagram lacks a complete header",
        ));
    }
    let length =
        usize::try_from(read_u32(bytes, 0)?).map_err(|_| FixedRouteOperationError::Limit)?;
    let aligned = align4(length)?;
    if length < NLMSG_HEADER_LEN || aligned != bytes.len() {
        return Err(FixedRouteOperationError::Unsafe(
            "netlink datagram does not contain exactly one frame",
        ));
    }
    if bytes[length..aligned].iter().any(|byte| *byte != 0) {
        return Err(FixedRouteOperationError::Unsafe(
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

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, FixedRouteOperationError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if result.len() >= MAX_ATTRIBUTES || bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(FixedRouteOperationError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(FixedRouteOperationError::Unsafe(
                "netlink route attribute length is invalid",
            ));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(FixedRouteOperationError::Unsafe(
                "netlink route attribute padding is nonzero",
            ));
        }
        let raw_kind = read_u16(bytes, 2)?;
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(FixedRouteOperationError::Unsafe(
                "netlink route attribute flags are contradictory",
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

struct RouteDumpState {
    sequence: u32,
    local_port: u32,
    request: Vec<u8>,
    done: bool,
    records: usize,
    matching: usize,
}

impl RouteDumpState {
    fn new(sequence: u32, local_port: u32, request: Vec<u8>) -> Self {
        Self {
            sequence,
            local_port,
            request,
            done: false,
            records: 0,
            matching: 0,
        }
    }

    fn ingest(
        &mut self,
        reply: &NetlinkReply,
        budget: &mut ReceiveBudget,
        lineage: &RouteLineage,
    ) -> Result<(), FixedRouteOperationError> {
        if self.done || reply.sender != SocketAddr::new(0, 0) {
            return Err(FixedRouteOperationError::Unsafe(
                "route dump sender or completion state is invalid",
            ));
        }
        let mut offset = 0;
        while offset < reply.bytes.len() {
            let remaining = &reply.bytes[offset..];
            if remaining.len() < NLMSG_HEADER_LEN {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump has a truncated frame",
                ));
            }
            let length = usize::try_from(read_u32(remaining, 0)?)
                .map_err(|_| FixedRouteOperationError::Limit)?;
            let aligned = align4(length)?;
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump frame length is invalid",
                ));
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump frame padding is nonzero",
                ));
            }
            budget.record_frame()?;
            self.ingest_frame(&remaining[..length], lineage)?;
            offset = offset
                .checked_add(aligned)
                .ok_or(FixedRouteOperationError::Limit)?;
            if self.done && offset != reply.bytes.len() {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump carries data after completion",
                ));
            }
        }
        Ok(())
    }

    fn ingest_frame(
        &mut self,
        frame: &[u8],
        lineage: &RouteLineage,
    ) -> Result<(), FixedRouteOperationError> {
        if read_u32(frame, 8)? != self.sequence || read_u32(frame, 12)? != self.local_port {
            return Err(FixedRouteOperationError::Unsafe(
                "route dump sequence or port is not exact",
            ));
        }
        let message_type = read_u16(frame, 4)?;
        let flags = read_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        match message_type {
            NLMSG_DONE => {
                parse_dump_done(flags, payload)?;
                self.done = true;
            }
            NLMSG_ERROR => return Err(parse_dump_error(flags, payload, &self.request)?),
            NLMSG_OVERRUN => {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump overrun is ambiguous",
                ));
            }
            RTM_NEWROUTE
                if flags == NLM_F_MULTI || flags == (NLM_F_MULTI | NLM_F_DUMP_FILTERED) =>
            {
                self.records = self
                    .records
                    .checked_add(1)
                    .ok_or(FixedRouteOperationError::Limit)?;
                if self.records > MAX_ROUTE_RECORDS {
                    return Err(FixedRouteOperationError::Limit);
                }
                if parse_route_record(payload, lineage)? {
                    self.matching = self
                        .matching
                        .checked_add(1)
                        .ok_or(FixedRouteOperationError::Limit)?;
                    if self.matching > 1 {
                        return Err(FixedRouteOperationError::Unsafe(
                            "more than one exact fixed endpoint route exists",
                        ));
                    }
                }
            }
            _ => {
                return Err(FixedRouteOperationError::Unsafe(
                    "route dump contains an unexpected message",
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<RoutePresence, FixedRouteOperationError> {
        if !self.done {
            return Err(FixedRouteOperationError::Unsafe(
                "route dump ended without NLMSG_DONE",
            ));
        }
        match self.matching {
            0 => Ok(RoutePresence::Absent),
            1 => Ok(RoutePresence::Exact),
            _ => Err(FixedRouteOperationError::Unsafe(
                "route dump retained an impossible match count",
            )),
        }
    }
}

fn parse_route_record(
    payload: &[u8],
    lineage: &RouteLineage,
) -> Result<bool, FixedRouteOperationError> {
    if payload.len() < RTMSG_LEN {
        return Err(FixedRouteOperationError::Unsafe(
            "route dump record lacks a complete rtmsg",
        ));
    }
    if payload[0] != AF_INET {
        return Err(FixedRouteOperationError::Unsafe(
            "IPv4 route dump contains a non-IPv4 record",
        ));
    }
    let attributes = parse_attributes(&payload[RTMSG_LEN..])?;
    let mut destination = None;
    let mut gateway = None;
    let mut output_interface = None;
    let mut table = None;
    let mut attribute_shape_exact = true;
    for attribute in &attributes {
        if attribute.flags != 0 {
            attribute_shape_exact = false;
        }
        match attribute.kind {
            RTA_DST => set_once(
                &mut destination,
                read_exact_ipv4(attribute.payload).map_err(|_| {
                    FixedRouteOperationError::Unsafe(
                        "route destination attribute is not exact IPv4",
                    )
                })?,
            )?,
            RTA_GATEWAY => set_once(
                &mut gateway,
                read_exact_ipv4(attribute.payload).map_err(|_| {
                    FixedRouteOperationError::Unsafe("route gateway attribute is not exact IPv4")
                })?,
            )?,
            RTA_OIF => set_once(
                &mut output_interface,
                read_exact_u32(attribute.payload).map_err(|_| {
                    FixedRouteOperationError::Unsafe(
                        "route output-interface attribute is not exact u32",
                    )
                })?,
            )?,
            RTA_TABLE => set_once(
                &mut table,
                read_exact_u32(attribute.payload).map_err(|_| {
                    FixedRouteOperationError::Unsafe("route table attribute is not exact u32")
                })?,
            )?,
            _ => attribute_shape_exact = false,
        }
    }
    let expected_destination = lineage.specification.destination.octets();
    if destination.is_none()
        && payload[1] == FIXED_ROUTE_PREFIX_LENGTH
        && (payload[4] == RT_TABLE_MAIN || table == Some(u32::from(RT_TABLE_MAIN)))
    {
        return Err(FixedRouteOperationError::Conflicting);
    }
    if destination != Some(expected_destination) {
        return Ok(false);
    }

    let header_table = u32::from(payload[4]);
    let attribute_table = table;
    let is_main_table = header_table == u32::from(RT_TABLE_MAIN)
        || attribute_table == Some(u32::from(RT_TABLE_MAIN));
    if !is_main_table {
        return Ok(false);
    }
    if payload[1] != FIXED_ROUTE_PREFIX_LENGTH
        || payload[2] != 0
        || payload[3] != 0
        || payload[4] != RT_TABLE_MAIN
        || payload[5] != RTPROT_STATIC
        || payload[6] != RT_SCOPE_UNIVERSE
        || payload[7] != RTN_UNICAST
        || read_u32(payload, 8)? != 0
        || !attribute_shape_exact
        || attributes.len() != 4
        || table != Some(u32::from(RT_TABLE_MAIN))
        || gateway != Some(lineage.specification.gateway.octets())
        || output_interface != Some(lineage.local_ifindex)
    {
        return Err(FixedRouteOperationError::Conflicting);
    }
    Ok(true)
}

fn parse_dump_done(flags: u16, payload: &[u8]) -> Result<(), FixedRouteOperationError> {
    if flags != NLM_F_MULTI {
        return Err(FixedRouteOperationError::Unsafe(
            "route dump completion flags are not exact",
        ));
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 && errno != i32::MIN => {
                Err(FixedRouteOperationError::errno("dump IPv4 routes", -errno))
            }
            _ => Err(FixedRouteOperationError::Unsafe(
                "route dump completion errno is not canonical",
            )),
        },
        _ => Err(FixedRouteOperationError::Unsafe(
            "route dump completion payload is not exact",
        )),
    }
}

fn parse_dump_error(
    flags: u16,
    payload: &[u8],
    request: &[u8],
) -> Result<FixedRouteOperationError, FixedRouteOperationError> {
    if flags != 0 || payload.len() != NLMSG_ERROR_CODE_LEN + request.len() {
        return Err(FixedRouteOperationError::Unsafe(
            "route dump error shape is not exact",
        ));
    }
    let errno = read_i32(payload, 0)?;
    if payload[NLMSG_ERROR_CODE_LEN..] != *request {
        return Err(FixedRouteOperationError::Unsafe(
            "route dump error does not echo the exact request",
        ));
    }
    if errno < 0 && errno != i32::MIN {
        Ok(FixedRouteOperationError::errno("dump IPv4 routes", -errno))
    } else {
        Err(FixedRouteOperationError::Unsafe(
            "route dump error errno is not canonical",
        ))
    }
}

fn validate_namespace_descriptor<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<(), FixedRouteOperationError> {
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFD)
            .map_err(|source| errno_io("read route namespace descriptor flags", source))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFL)
            .map_err(|source| errno_io("read route namespace status flags", source))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC)
        || status_flags & OFlag::O_ACCMODE != OFlag::O_RDONLY
    {
        return Err(FixedRouteOperationError::Unsafe(
            "route namespace descriptor is not read-only and close-on-exec",
        ));
    }
    if fstatfs(descriptor)
        .map_err(|source| rustix_io("identify route namespace filesystem", source))?
        .f_type
        != NSFS_MAGIC
        || namespace_type(descriptor).map_err(|source| {
            FixedRouteOperationError::io("identify route network namespace", source)
        })? != libc::CLONE_NEWNET
    {
        return Err(FixedRouteOperationError::Unsafe(
            "route namespace descriptor is not a network nsfs object",
        ));
    }
    Ok(())
}

fn open_current_network_namespace() -> Result<OwnedFd, FixedRouteOperationError> {
    let descriptor = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| rustix_io("open current route network namespace", source))?;
    validate_namespace_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn object_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<NamespaceIdentity, FixedRouteOperationError> {
    let metadata = fstat(descriptor)
        .map_err(|source| rustix_io("measure route namespace descriptor", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(FixedRouteOperationError::Unsafe(
            "route namespace descriptor identity is zero",
        ));
    }
    Ok(NamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn errno_io(operation: &'static str, source: nix::errno::Errno) -> FixedRouteOperationError {
    FixedRouteOperationError::io(operation, io::Error::from_raw_os_error(source as i32))
}

fn rustix_io(operation: &'static str, source: rustix::io::Errno) -> FixedRouteOperationError {
    FixedRouteOperationError::io(
        operation,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), FixedRouteOperationError> {
    if slot.replace(value).is_some() {
        Err(FixedRouteOperationError::Unsafe(
            "duplicate route attribute is ambiguous",
        ))
    } else {
        Ok(())
    }
}

fn read_exact_ipv4(bytes: &[u8]) -> Result<[u8; 4], FixedRouteOperationError> {
    bytes.try_into().map_err(|_| {
        FixedRouteOperationError::Unsafe("route attribute is not exactly one IPv4 address")
    })
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, FixedRouteOperationError> {
    if bytes.len() != 4 {
        return Err(FixedRouteOperationError::Unsafe(
            "route attribute is not exactly one u32",
        ));
    }
    read_u32(bytes, 0)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FixedRouteOperationError> {
    let end = offset
        .checked_add(2)
        .ok_or(FixedRouteOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedRouteOperationError::Unsafe(
            "netlink u16 field is truncated",
        ))?;
    Ok(u16::from_ne_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FixedRouteOperationError> {
    let end = offset
        .checked_add(4)
        .ok_or(FixedRouteOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedRouteOperationError::Unsafe(
            "netlink u32 field is truncated",
        ))?;
    Ok(u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, FixedRouteOperationError> {
    Ok(i32::from_ne_bytes(read_u32(bytes, offset)?.to_ne_bytes()))
}

fn align4(value: usize) -> Result<usize, FixedRouteOperationError> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or(FixedRouteOperationError::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQUENCE: u32 = 0x1122_3344;
    const PORT: u32 = 0x5566_7788;

    fn identity(device: u64, inode: u64) -> NamespaceIdentity {
        NamespaceIdentity { device, inode }
    }

    fn ipv4_identity(device: u64, inode: u64) -> Ipv4NamespaceIdentity {
        Ipv4NamespaceIdentity::from_test_parts(device, inode)
    }

    fn veth_identity(device: u64, inode: u64) -> VethTargetNamespaceIdentity {
        VethTargetNamespaceIdentity::from_test_parts(device, inode)
    }

    fn lineage(endpoint: FixedVethEndpoint) -> RouteLineage {
        match endpoint {
            FixedVethEndpoint::A => RouteLineage {
                specification: FixedRouteSpecification::for_endpoint(endpoint),
                activated_pairs: FixedEndpointRoutePairLineage::from_test_parts(endpoint),
                local_ifindex: 3,
                local_interface_name: FIXED_VETH_PEER_NAME.to_owned(),
                local_namespace: identity(2, 20),
                local_address_namespace: ipv4_identity(2, 20),
                local_target_namespace: veth_identity(2, 20),
                remote_namespace: identity(3, 30),
                remote_target_namespace: veth_identity(3, 30),
                remote_peer_ifindex: 3,
                remote_interface_name: FIXED_VETH_PEER_NAME.to_owned(),
                parent_ifindex: 2,
                remote_parent_ifindex: 4,
                parent_name: "vpa01234567".to_owned(),
                remote_parent_name: "vpb01234567".to_owned(),
            },
            FixedVethEndpoint::B => RouteLineage {
                specification: FixedRouteSpecification::for_endpoint(endpoint),
                activated_pairs: FixedEndpointRoutePairLineage::from_test_parts(endpoint),
                local_ifindex: 3,
                local_interface_name: FIXED_VETH_PEER_NAME.to_owned(),
                local_namespace: identity(3, 30),
                local_address_namespace: ipv4_identity(3, 30),
                local_target_namespace: veth_identity(3, 30),
                remote_namespace: identity(2, 20),
                remote_target_namespace: veth_identity(2, 20),
                remote_peer_ifindex: 3,
                remote_interface_name: FIXED_VETH_PEER_NAME.to_owned(),
                parent_ifindex: 4,
                remote_parent_ifindex: 2,
                parent_name: "vpb01234567".to_owned(),
                remote_parent_name: "vpa01234567".to_owned(),
            },
        }
    }

    fn raw_attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + value.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &u16::try_from(length)
                .expect("test attribute length")
                .to_ne_bytes(),
        );
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn exact_dump_record(lineage: &RouteLineage) -> Vec<u8> {
        let mut payload = route_message();
        payload.extend(raw_attribute(
            RTA_TABLE,
            &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
        ));
        payload.extend(raw_attribute(
            RTA_DST,
            &lineage.specification.destination.octets(),
        ));
        payload.extend(raw_attribute(
            RTA_GATEWAY,
            &lineage.specification.gateway.octets(),
        ));
        payload.extend(raw_attribute(RTA_OIF, &lineage.local_ifindex.to_ne_bytes()));
        payload
    }

    fn frame(kind: u16, flags: u16, sequence: u32, port: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &u32::try_from(length)
                .expect("test frame length")
                .to_ne_bytes(),
        );
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&port.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn ack_reply(request: &[u8], errno: i32, flags: u16, trailing: &[u8]) -> NetlinkReply {
        let mut payload = errno.to_ne_bytes().to_vec();
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        payload.extend_from_slice(trailing);
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: frame(NLMSG_ERROR, flags, SEQUENCE, PORT, &payload),
        }
    }

    fn remove_attribute(payload: &[u8], kind: u16) -> Vec<u8> {
        let mut output = payload[..RTMSG_LEN].to_vec();
        for attribute in parse_attributes(&payload[RTMSG_LEN..]).expect("test attributes") {
            if attribute.kind != kind {
                output.extend(raw_attribute(
                    attribute.kind | attribute.flags,
                    attribute.payload,
                ));
            }
        }
        output
    }

    fn replace_attribute(payload: &[u8], kind: u16, raw_kind: u16, value: &[u8]) -> Vec<u8> {
        let mut output = payload[..RTMSG_LEN].to_vec();
        for attribute in parse_attributes(&payload[RTMSG_LEN..]).expect("test attributes") {
            if attribute.kind == kind {
                output.extend(raw_attribute(raw_kind, value));
            } else {
                output.extend(raw_attribute(
                    attribute.kind | attribute.flags,
                    attribute.payload,
                ));
            }
        }
        output
    }

    #[test]
    fn route_specs_are_exact_and_symmetric() {
        let a = FixedRouteSpecification::for_endpoint(FixedVethEndpoint::A);
        assert_eq!(a.local_address.octets(), [10, 241, 1, 2]);
        assert_eq!(a.destination.octets(), [10, 241, 2, 2]);
        assert_eq!(a.gateway.octets(), [10, 241, 1, 1]);
        let b = FixedRouteSpecification::for_endpoint(FixedVethEndpoint::B);
        assert_eq!(b.local_address.octets(), [10, 241, 2, 2]);
        assert_eq!(b.destination.octets(), [10, 241, 1, 2]);
        assert_eq!(b.gateway.octets(), [10, 241, 2, 1]);
    }

    #[test]
    fn exclusive_newroute_requests_are_byte_exact_with_four_fixed_attributes() {
        for endpoint in [FixedVethEndpoint::A, FixedVethEndpoint::B] {
            let lineage = lineage(endpoint);
            let payload = encode_route_payload(&lineage).expect("fixed route payload");
            let request = encode_message(
                RTM_NEWROUTE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                SEQUENCE,
                &payload,
            )
            .expect("fixed route request");
            let mut expected_payload = vec![
                AF_INET,
                32,
                0,
                0,
                RT_TABLE_MAIN,
                RTPROT_STATIC,
                RT_SCOPE_UNIVERSE,
                RTN_UNICAST,
                0,
                0,
                0,
                0,
            ];
            expected_payload.extend(raw_attribute(
                RTA_TABLE,
                &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
            ));
            expected_payload.extend(raw_attribute(
                RTA_DST,
                &lineage.specification.destination.octets(),
            ));
            expected_payload.extend(raw_attribute(
                RTA_GATEWAY,
                &lineage.specification.gateway.octets(),
            ));
            expected_payload.extend(raw_attribute(RTA_OIF, &lineage.local_ifindex.to_ne_bytes()));
            let expected = frame(
                RTM_NEWROUTE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                SEQUENCE,
                0,
                &expected_payload,
            );
            assert_eq!(request, expected);
            let kinds: Vec<_> = parse_attributes(&payload[RTMSG_LEN..])
                .expect("request attributes")
                .into_iter()
                .map(|attribute| attribute.kind)
                .collect();
            assert_eq!(kinds, [RTA_TABLE, RTA_DST, RTA_GATEWAY, RTA_OIF]);
        }
    }

    #[test]
    fn lineage_rejects_aliases_but_allows_equal_peer_indices_across_namespaces() {
        let valid = lineage(FixedVethEndpoint::A);
        validate_route_lineage(&valid).expect("distinct route lineage");

        let mut variants = Vec::new();
        let mut value = valid.clone();
        value.local_ifindex = 1;
        variants.push(value);
        let mut value = valid.clone();
        value.parent_ifindex = value.remote_parent_ifindex;
        variants.push(value);
        let mut value = valid.clone();
        value.parent_name = value.remote_parent_name.clone();
        variants.push(value);
        let mut value = valid.clone();
        value.remote_namespace = value.local_namespace;
        value.remote_target_namespace = value.local_target_namespace;
        variants.push(value);
        let mut value = valid.clone();
        value.local_address_namespace = ipv4_identity(9, 20);
        variants.push(value);
        let mut value = valid.clone();
        value.specification.gateway = FixedIpv4Address::ParentB;
        variants.push(value);
        for variant in variants {
            assert!(validate_route_lineage(&variant).is_err());
        }
    }

    #[test]
    fn exact_debian_route_readback_requires_table_destination_gateway_and_oif() {
        for endpoint in [FixedVethEndpoint::A, FixedVethEndpoint::B] {
            let lineage = lineage(endpoint);
            let exact = exact_dump_record(&lineage);
            assert!(matches!(parse_route_record(&exact, &lineage), Ok(true)));
            for missing in [RTA_TABLE, RTA_DST, RTA_GATEWAY, RTA_OIF] {
                let result = parse_route_record(&remove_attribute(&exact, missing), &lineage);
                assert!(matches!(result, Err(FixedRouteOperationError::Conflicting)));
            }
        }
    }

    #[test]
    fn same_destination_main_table_siblings_are_never_absent() {
        let lineage = lineage(FixedVethEndpoint::A);
        let exact = exact_dump_record(&lineage);
        let mut variants = Vec::new();
        for (offset, replacement) in [
            (0, 10_u8),
            (1, 31),
            (2, 1),
            (3, 1),
            (4, 253),
            (5, 2),
            (6, 253),
            (7, 2),
            (8, 1),
        ] {
            let mut value = exact.clone();
            value[offset] = replacement;
            variants.push(value);
        }
        variants.push(replace_attribute(
            &exact,
            RTA_TABLE,
            RTA_TABLE,
            &253_u32.to_ne_bytes(),
        ));
        variants.push(replace_attribute(
            &exact,
            RTA_GATEWAY,
            RTA_GATEWAY,
            &[10, 241, 1, 2],
        ));
        variants.push(replace_attribute(
            &exact,
            RTA_OIF,
            RTA_OIF,
            &9_u32.to_ne_bytes(),
        ));
        variants.push(replace_attribute(
            &exact,
            RTA_DST,
            RTA_DST | NLA_F_NESTED,
            &lineage.specification.destination.octets(),
        ));
        let mut duplicate = exact.clone();
        duplicate.extend(raw_attribute(
            RTA_DST,
            &lineage.specification.destination.octets(),
        ));
        variants.push(duplicate);
        let mut extra = exact.clone();
        extra.extend(raw_attribute(99, &[1, 2, 3, 4]));
        variants.push(extra);
        for variant in variants {
            assert!(parse_route_record(&variant, &lineage).is_err());
        }

        let unrelated = replace_attribute(&exact, RTA_DST, RTA_DST, &[192, 0, 2, 1]);
        assert!(matches!(
            parse_route_record(&unrelated, &lineage),
            Ok(false)
        ));
        let mut other_table = exact.clone();
        other_table[4] = 253;
        other_table = replace_attribute(&other_table, RTA_TABLE, RTA_TABLE, &253_u32.to_ne_bytes());
        assert!(matches!(
            parse_route_record(&other_table, &lineage),
            Ok(false)
        ));
    }

    #[test]
    fn acknowledgements_bind_kernel_sender_sequence_port_and_exact_request() {
        let lineage = lineage(FixedVethEndpoint::A);
        let request = encode_message(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            SEQUENCE,
            &encode_route_payload(&lineage).expect("route payload"),
        )
        .expect("route request");
        let success = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        assert!(matches!(
            parse_ack(&success, PORT, &request),
            Ok(Ack::Success)
        ));
        let rejected = ack_reply(&request, -libc::EEXIST, 0, &request[NLMSG_HEADER_LEN..]);
        assert!(matches!(
            parse_ack(&rejected, PORT, &request),
            Ok(Ack::Rejected(libc::EEXIST))
        ));

        let mut wrong_sender = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        wrong_sender.sender = SocketAddr::new(7, 0);
        assert!(parse_ack(&wrong_sender, PORT, &request).is_err());
        let wrong_sequence = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        assert!(
            parse_ack(&wrong_sequence, PORT, &{
                let mut changed = request.clone();
                changed[8..12].copy_from_slice(&(SEQUENCE + 1).to_ne_bytes());
                changed
            })
            .is_err()
        );
        assert!(parse_ack(&success, PORT + 1, &request).is_err());

        let mut wrong_echo = ack_reply(&request, -libc::EEXIST, 0, &request[NLMSG_HEADER_LEN..]);
        let last = wrong_echo.bytes.len() - 1;
        wrong_echo.bytes[last] ^= 1;
        assert!(parse_ack(&wrong_echo, PORT, &request).is_err());
        assert!(parse_ack(&ack_reply(&request, 0, 0, &[]), PORT, &request).is_err());
        assert!(
            parse_ack(
                &ack_reply(&request, -libc::EEXIST, NLM_F_CAPPED, &[]),
                PORT,
                &request,
            )
            .is_err()
        );
        assert!(
            parse_ack(
                &ack_reply(&request, 0, NLM_F_CAPPED | NLM_F_ACK_TLVS, &[]),
                PORT,
                &request,
            )
            .is_err()
        );
    }

    #[test]
    fn dump_state_requires_exact_multipart_completion_and_counts_one_route() {
        let lineage = lineage(FixedVethEndpoint::B);
        let request = encode_message(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            SEQUENCE,
            &encode_route_dump_payload(),
        )
        .expect("dump request");
        let route = frame(
            RTM_NEWROUTE,
            NLM_F_MULTI,
            SEQUENCE,
            PORT,
            &exact_dump_record(&lineage),
        );
        let done = frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]);
        let mut bytes = route;
        bytes.extend(done);
        let reply = NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes,
        };
        let mut state = RouteDumpState::new(SEQUENCE, PORT, request);
        let mut budget = ReceiveBudget::dump();
        state
            .ingest(&reply, &mut budget, &lineage)
            .expect("exact route dump");
        assert!(matches!(state.finish(), Ok(RoutePresence::Exact)));
    }

    #[test]
    fn dump_state_accepts_exact_kernel_filtered_route_records() {
        let lineage = lineage(FixedVethEndpoint::A);
        let request = encode_message(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            SEQUENCE,
            &encode_route_dump_payload(),
        )
        .expect("dump request");
        let mut bytes = frame(
            RTM_NEWROUTE,
            NLM_F_MULTI | NLM_F_DUMP_FILTERED,
            SEQUENCE,
            PORT,
            &exact_dump_record(&lineage),
        );
        bytes.extend(frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]));
        let mut state = RouteDumpState::new(SEQUENCE, PORT, request);
        let mut budget = ReceiveBudget::dump();
        state
            .ingest(
                &NetlinkReply {
                    sender: SocketAddr::new(0, 0),
                    bytes,
                },
                &mut budget,
                &lineage,
            )
            .expect("filtered route dump");
        assert!(matches!(state.finish(), Ok(RoutePresence::Exact)));
    }

    #[test]
    fn dump_state_rejects_noncanonical_filtered_flags() {
        let lineage = lineage(FixedVethEndpoint::A);
        let request = encode_message(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            SEQUENCE,
            &encode_route_dump_payload(),
        )
        .expect("dump request");
        for flags in [NLM_F_DUMP_FILTERED, NLM_F_MULTI | 0x0040] {
            let reply = NetlinkReply {
                sender: SocketAddr::new(0, 0),
                bytes: frame(
                    RTM_NEWROUTE,
                    flags,
                    SEQUENCE,
                    PORT,
                    &exact_dump_record(&lineage),
                ),
            };
            let mut state = RouteDumpState::new(SEQUENCE, PORT, request.clone());
            let mut budget = ReceiveBudget::dump();
            assert!(state.ingest(&reply, &mut budget, &lineage).is_err());
        }

        let reply = NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: frame(
                NLMSG_DONE,
                NLM_F_MULTI | NLM_F_DUMP_FILTERED,
                SEQUENCE,
                PORT,
                &[],
            ),
        };
        let mut state = RouteDumpState::new(SEQUENCE, PORT, request);
        let mut budget = ReceiveBudget::dump();
        assert!(state.ingest(&reply, &mut budget, &lineage).is_err());
    }

    #[test]
    fn dump_state_rejects_wrong_sender_sequence_flags_and_trailing_data() {
        let lineage = lineage(FixedVethEndpoint::A);
        let request = encode_message(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            SEQUENCE,
            &encode_route_dump_payload(),
        )
        .expect("dump request");
        for reply in [
            NetlinkReply {
                sender: SocketAddr::new(9, 0),
                bytes: frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]),
            },
            NetlinkReply {
                sender: SocketAddr::new(0, 0),
                bytes: frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE + 1, PORT, &[]),
            },
            NetlinkReply {
                sender: SocketAddr::new(0, 0),
                bytes: frame(NLMSG_DONE, 0, SEQUENCE, PORT, &[]),
            },
        ] {
            let mut state = RouteDumpState::new(SEQUENCE, PORT, request.clone());
            let mut budget = ReceiveBudget::dump();
            assert!(state.ingest(&reply, &mut budget, &lineage).is_err());
        }

        let mut bytes = frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]);
        bytes.extend(frame(
            RTM_NEWROUTE,
            NLM_F_MULTI,
            SEQUENCE,
            PORT,
            &exact_dump_record(&lineage),
        ));
        let mut state = RouteDumpState::new(SEQUENCE, PORT, request);
        let mut budget = ReceiveBudget::dump();
        assert!(
            state
                .ingest(
                    &NetlinkReply {
                        sender: SocketAddr::new(0, 0),
                        bytes,
                    },
                    &mut budget,
                    &lineage,
                )
                .is_err()
        );
    }

    #[test]
    fn request_and_parser_bounds_fail_closed() {
        assert!(encode_message(RTM_NEWROUTE, NLM_F_REQUEST, 0, &[]).is_err());
        assert!(parse_attributes(&[0; 3]).is_err());
        let mut bad_length = raw_attribute(RTA_DST, &[10, 241, 2, 2]);
        bad_length[0..2].copy_from_slice(&3_u16.to_ne_bytes());
        assert!(parse_attributes(&bad_length).is_err());
        let mut bad_padding = raw_attribute(99, &[1]);
        *bad_padding.last_mut().expect("padding") = 1;
        assert!(parse_attributes(&bad_padding).is_err());

        let mut budget = ReceiveBudget::dump();
        assert!(budget.can_receive(NLMSG_HEADER_LEN - 1).is_err());
        assert!(budget.can_receive(MAX_NETLINK_DATAGRAM_BYTES + 1).is_err());
        budget.frames = MAX_NETLINK_FRAMES;
        assert!(budget.record_frame().is_err());
    }
}
