//! Exact permanent IPv4 neighbour ownership for the fixed disposable topology.
//!
//! The only admitted records bind each fixed `/30` peer address to the MAC
//! pinned by the all-links-UP barrier. Plans derive every namespace, interface,
//! address, and link-layer field from retained affine topology authority. Each
//! mutation is an exclusive `RTM_NEWNEIGH` with `RTPROT_STATIC`, an exact ACK,
//! and a fresh strict dump. Any post-send install ambiguity remains
//! deletion-bound; an exact readback never turns ambiguous provenance into an
//! owner.
//!
//! Successful teardown freshly proves the exact record immediately before an
//! explicit one-shot `RTM_DELNEIGH` and requires final absence. A same-key
//! non-exact record is never deleted, and an exact record observed after that
//! possibly-applied delete is not deleted a second time because it could be a
//! replacement. Any possibly-sent install and any delete that cannot
//! prove absence, returns deletion-bound authority which has no further delete
//! API and can be retired only against the exact full-pair absence proof.
//!
//! RTNETLINK has no compare-and-delete primitive for neighbour records. The
//! fresh-proof-to-first-delete interval therefore relies on this runner's
//! fixed single-PID-1-task, trusted-launcher model: no other capable writer is
//! admitted to the private network namespace during the transaction.
//!
//! `NDA_CACHEINFO` is validated as exact 16-byte telemetry but its changing
//! values are not configuration identity. `NDA_PROBES` is configuration proof
//! here and must remain the exact native-endian value zero.

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
    link::{AllLinksUp, FixedPairAbsenceProof, FixedPermanentNeighbourPairLineage},
    veth::{FIXED_VETH_PEER_NAME, FixedVethEndpoint, FixedVethPair},
};

const NEIGHBOUR_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;

const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_NETLINK_TOTAL_BYTES: usize = 256 * 1024;
const MAX_NETLINK_DATAGRAMS: usize = 32;
const MAX_NETLINK_FRAMES: usize = 128;
const MAX_NEIGHBOUR_RECORDS: usize = 64;
const MAX_ATTRIBUTES: usize = 64;
const MAX_REQUEST_BYTES: usize = 128;

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const NDMSG_LEN: usize = 12;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const ETHERNET_ADDRESS_BYTES: usize = 6;
const NDA_CACHEINFO_BYTES: usize = 16;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
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
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;
const NDA_PROTOCOL: u16 = 12;

const AF_INET: u8 = 2;
const NUD_PERMANENT: u16 = 0x80;
const RTN_UNICAST: u8 = 1;
const RTPROT_STATIC: u8 = 4;

/// One of the only four permanent neighbour entries admitted by the fixed
/// topology lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedPermanentNeighbour {
    /// Parent A resolves endpoint A on the pair-A parent interface.
    ParentA,
    /// Parent B resolves endpoint B on the pair-B parent interface.
    ParentB,
    /// Endpoint A resolves parent A through its `eth0`.
    EndpointA,
    /// Endpoint B resolves parent B through its `eth0`.
    EndpointB,
}

impl FixedPermanentNeighbour {
    /// Canonical create order: both parent records, then both endpoint records.
    pub(crate) const INSTALL_ORDER: [Self; 4] = [
        Self::ParentA,
        Self::ParentB,
        Self::EndpointA,
        Self::EndpointB,
    ];

    /// Canonical explicit delete order, exactly reversing installation.
    pub(crate) const DELETE_ORDER: [Self; 4] = [
        Self::EndpointB,
        Self::EndpointA,
        Self::ParentB,
        Self::ParentA,
    ];

    /// Pair endpoint represented by this record.
    pub(crate) const fn endpoint(self) -> FixedVethEndpoint {
        match self {
            Self::ParentA | Self::EndpointA => FixedVethEndpoint::A,
            Self::ParentB | Self::EndpointB => FixedVethEndpoint::B,
        }
    }

    /// Whether the record belongs in the parent network namespace.
    pub(crate) const fn is_parent(self) -> bool {
        matches!(self, Self::ParentA | Self::ParentB)
    }

    /// Address already configured on this record's interface.
    pub(crate) const fn local_address(self) -> FixedIpv4Address {
        match self {
            Self::ParentA => FixedIpv4Address::ParentA,
            Self::ParentB => FixedIpv4Address::ParentB,
            Self::EndpointA => FixedIpv4Address::EndpointA,
            Self::EndpointB => FixedIpv4Address::EndpointB,
        }
    }

    /// Same-pair peer address resolved by this record.
    pub(crate) const fn destination_address(self) -> FixedIpv4Address {
        match self {
            Self::ParentA => FixedIpv4Address::EndpointA,
            Self::ParentB => FixedIpv4Address::EndpointB,
            Self::EndpointA => FixedIpv4Address::ParentA,
            Self::EndpointB => FixedIpv4Address::ParentB,
        }
    }
}

/// Bounded RTNETLINK, namespace, or retained-lineage failure.
#[derive(Debug, Error)]
pub(crate) enum FixedNeighbourOperationError {
    /// A descriptor, socket, send, receive, or wait operation failed.
    #[error("fixed permanent-neighbour operation {operation} failed: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Kernel or standard-library error.
        #[source]
        source: io::Error,
    },
    /// The kernel returned an exact negative ACK.
    #[error("kernel rejected fixed permanent-neighbour operation {operation} with errno {errno}")]
    Kernel {
        /// Static operation label.
        operation: &'static str,
        /// Positive Linux errno.
        errno: i32,
    },
    /// A response, descriptor, or retained fact contradicted the fixed protocol.
    #[error("fixed permanent-neighbour proof was unsafe: {0}")]
    Unsafe(&'static str),
    /// A same-key record exists but is not the exact retained record.
    #[error("fixed permanent-neighbour key has a conflicting record")]
    Conflicting,
    /// A request or response exceeded a fixed resource bound.
    #[error("fixed permanent-neighbour operation exceeded its resource bound")]
    Limit,
}

impl FixedNeighbourOperationError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn errno(operation: &'static str, errno: i32) -> Self {
        Self::Kernel { operation, errno }
    }
}

/// Failure to derive a mutation-free fixed neighbour plan.
#[derive(Debug, Error)]
#[error("fixed permanent-neighbour plan derivation failed")]
pub(crate) struct FixedNeighbourPlanError(#[source] FixedNeighbourOperationError);

/// Failure to install one fixed permanent neighbour.
#[derive(Debug, Error)]
pub(crate) enum FixedNeighbourInstallError {
    /// No request could have reached the kernel mutation path.
    #[error("fixed permanent-neighbour installation failed before mutation")]
    BeforeMutation(#[source] FixedNeighbourOperationError),
    /// A request may have executed; only full pair absence may retire the authority.
    #[error("fixed permanent-neighbour installation crossed the deletion-only boundary")]
    DeletionBound {
        /// Original ACK, readback, rejection, or reconciliation failure.
        #[source]
        source: FixedNeighbourOperationError,
        /// Armed authority retained until exact pair-absence retirement.
        authority: Box<FixedPermanentNeighbourRetirement>,
    },
}

/// Failure to freshly prove one retained neighbour owner.
#[derive(Debug, Error)]
#[error("retained fixed permanent-neighbour verification failed")]
pub(crate) struct FixedNeighbourVerifyError(#[source] FixedNeighbourOperationError);

/// Failed explicit deletion carrying mandatory pair-absence retirement authority.
#[derive(Debug, Error)]
#[error("fixed permanent-neighbour deletion could not prove exact absence")]
pub(crate) struct FixedNeighbourDeleteFailure {
    #[source]
    source: FixedNeighbourOperationError,
    authority: Box<FixedPermanentNeighbourRetirement>,
}

impl FixedNeighbourDeleteFailure {
    /// Split the diagnostic from the still-armed retirement authority.
    pub(crate) fn into_parts(
        self,
    ) -> (
        FixedNeighbourOperationError,
        FixedPermanentNeighbourRetirement,
    ) {
        (self.source, *self.authority)
    }
}

/// Failure to bind deletion-bound authority to the exact full pair absence proof.
#[derive(Debug, Error)]
#[error("fixed permanent-neighbour retirement proof did not match retained lineage")]
pub(crate) struct FixedNeighbourRetirementError(#[source] FixedNeighbourOperationError);

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
    fn capture<Fd: AsFd>(supplied: &Fd) -> Result<Self, FixedNeighbourOperationError> {
        validate_namespace_descriptor(supplied)?;
        let supplied_identity = object_identity(supplied)?;
        let current = open_current_network_namespace()?;
        if object_identity(&current)? != supplied_identity {
            return Err(FixedNeighbourOperationError::Unsafe(
                "supplied neighbour namespace is not current on this thread",
            ));
        }
        let descriptor = supplied.as_fd().try_clone_to_owned().map_err(|source| {
            FixedNeighbourOperationError::io("retain current neighbour namespace", source)
        })?;
        validate_namespace_descriptor(&descriptor)?;
        if object_identity(&descriptor)? != supplied_identity {
            return Err(FixedNeighbourOperationError::Unsafe(
                "neighbour namespace descriptor changed during cloning",
            ));
        }
        Ok(Self {
            descriptor,
            identity: supplied_identity,
        })
    }

    fn verify_current(&self) -> Result<(), FixedNeighbourOperationError> {
        self.verify_retained()?;
        if object_identity(&open_current_network_namespace()?)? != self.identity {
            return Err(FixedNeighbourOperationError::Unsafe(
                "retained neighbour namespace is no longer current",
            ));
        }
        Ok(())
    }

    fn verify_retained(&self) -> Result<(), FixedNeighbourOperationError> {
        validate_namespace_descriptor(&self.descriptor)?;
        if object_identity(&self.descriptor)? != self.identity {
            return Err(FixedNeighbourOperationError::Unsafe(
                "retained neighbour namespace identity changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NeighbourLineage {
    specification: FixedPermanentNeighbour,
    pair: FixedPermanentNeighbourPairLineage,
    namespace: NamespaceIdentity,
    ifindex: u32,
    interface_name: String,
    local_address: FixedIpv4Address,
    local_address_namespace: NamespaceIdentity,
    destination_address: FixedIpv4Address,
    destination_address_namespace: NamespaceIdentity,
    link_layer_address: [u8; ETHERNET_ADDRESS_BYTES],
}

#[derive(Debug)]
struct NeighbourJournal {
    namespace: RetainedCurrentNamespace,
    lineage: NeighbourLineage,
}

impl NeighbourJournal {
    fn verify_context(&self) -> Result<(), FixedNeighbourOperationError> {
        self.namespace.verify_current()?;
        validate_lineage(&self.lineage)?;
        if self.namespace.identity != self.lineage.namespace {
            return Err(FixedNeighbourOperationError::Unsafe(
                "neighbour journal namespace does not match retained lineage",
            ));
        }
        Ok(())
    }
}

/// Mutation-free affine plan for one exact fixed permanent neighbour.
#[must_use = "a fixed permanent-neighbour plan has not installed its record"]
pub(crate) struct FixedPermanentNeighbourPlan {
    journal: Option<NeighbourJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedPermanentNeighbourPlan {
    /// Derive one record solely from all-UP pair/MAC lineage, the two retained
    /// same-pair address owners, and the namespace currently active on the task.
    pub(crate) fn derive<Fd: AsFd>(
        specification: FixedPermanentNeighbour,
        all_links_up: &AllLinksUp,
        current_namespace: &Fd,
        pair: &FixedVethPair,
        local_address: &FixedIpv4AddressOwner,
        destination_address: &FixedIpv4AddressOwner,
    ) -> Result<Self, FixedNeighbourPlanError> {
        let namespace = RetainedCurrentNamespace::capture(current_namespace)
            .map_err(FixedNeighbourPlanError)?;
        let pair_lineage = all_links_up
            .bind_permanent_neighbour_pair(pair)
            .map_err(|_| {
                FixedNeighbourPlanError(FixedNeighbourOperationError::Unsafe(
                    "all-UP authority does not bind the neighbour pair",
                ))
            })?;
        let (ifindex, interface_name, link_layer_address) = if specification.is_parent() {
            (
                pair_lineage.parent_ifindex(),
                pair_lineage.parent_name().to_owned(),
                pair_lineage.endpoint_mac().map_err(|_| {
                    FixedNeighbourPlanError(FixedNeighbourOperationError::Unsafe(
                        "all-UP pair lacks an endpoint MAC",
                    ))
                })?,
            )
        } else {
            (
                pair_lineage.endpoint_ifindex(),
                FIXED_VETH_PEER_NAME.to_owned(),
                pair_lineage.parent_mac(),
            )
        };
        let lineage = NeighbourLineage {
            specification,
            pair: pair_lineage,
            namespace: namespace.identity,
            ifindex,
            interface_name,
            local_address: local_address.address(),
            local_address_namespace: NamespaceIdentity::from_ipv4(
                local_address.namespace_identity(),
            ),
            destination_address: destination_address.address(),
            destination_address_namespace: NamespaceIdentity::from_ipv4(
                destination_address.namespace_identity(),
            ),
            link_layer_address,
        };
        validate_lineage(&lineage).map_err(FixedNeighbourPlanError)?;
        if local_address.ifindex() != lineage.ifindex
            || local_address.interface_name() != lineage.interface_name
        {
            return Err(FixedNeighbourPlanError(
                FixedNeighbourOperationError::Unsafe(
                    "local address owner does not bind the neighbour interface",
                ),
            ));
        }
        let expected_destination_ifindex = if specification.is_parent() {
            lineage.pair.endpoint_ifindex()
        } else {
            lineage.pair.parent_ifindex()
        };
        let expected_destination_name = if specification.is_parent() {
            FIXED_VETH_PEER_NAME
        } else {
            lineage.pair.parent_name()
        };
        if destination_address.ifindex() != expected_destination_ifindex
            || destination_address.interface_name() != expected_destination_name
        {
            return Err(FixedNeighbourPlanError(
                FixedNeighbourOperationError::Unsafe(
                    "destination address owner does not bind the opposite pair end",
                ),
            ));
        }
        Ok(Self {
            journal: Some(NeighbourJournal { namespace, lineage }),
            _thread_bound: PhantomData,
        })
    }

    /// Send the exclusive create request, reconcile its ACK, and return exact
    /// ownership or deletion-bound authority.
    pub(crate) fn install(
        mut self,
    ) -> Result<FixedPermanentNeighbourOwner, FixedNeighbourInstallError> {
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        install_neighbour(journal)
    }
}

/// Affine ownership of one exact freshly dumped permanent neighbour.
#[must_use = "an installed permanent neighbour requires explicit deletion"]
pub(crate) struct FixedPermanentNeighbourOwner {
    journal: Option<NeighbourJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedPermanentNeighbourOwner {
    /// Fixed record represented by this owner.
    pub(crate) fn specification(&self) -> FixedPermanentNeighbour {
        self.journal().lineage.specification
    }

    /// Freshly re-dump and prove this exact record while its namespace is current.
    pub(crate) fn verify(&self) -> Result<(), FixedNeighbourVerifyError> {
        match observe_presence(self.journal()).map_err(FixedNeighbourVerifyError)? {
            NeighbourPresence::Exact => Ok(()),
            NeighbourPresence::Absent => Err(FixedNeighbourVerifyError(
                FixedNeighbourOperationError::Unsafe("retained permanent neighbour is absent"),
            )),
            NeighbourPresence::Conflicting => Err(FixedNeighbourVerifyError(
                FixedNeighbourOperationError::Conflicting,
            )),
        }
    }

    /// Explicitly delete this exact owner after a fresh exact conditional proof.
    /// A reconciled final absence is success even if an ACK was lost.
    pub(crate) fn delete(mut self) -> Result<(), FixedNeighbourDeleteFailure> {
        let result = delete_and_reconcile(self.journal());
        match result {
            Ok(()) => {
                self.journal = None;
                Ok(())
            }
            Err(source) => {
                let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
                Err(FixedNeighbourDeleteFailure {
                    source,
                    authority: Box::new(FixedPermanentNeighbourRetirement::new(journal)),
                })
            }
        }
    }

    fn journal(&self) -> &NeighbourJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedPermanentNeighbourOwner {
    fn drop(&mut self) {
        if self.journal.is_some() {
            std::process::abort();
        }
    }
}

/// Deletion-bound authority for a request that may have installed a neighbour
/// or for an owner whose explicit deletion could not prove absence.
///
/// This type intentionally has no delete method. Pair destruction followed by
/// the exact full-pair absence proof is its sole retirement path.
#[derive(Debug)]
#[must_use = "neighbour retirement authority requires full pair-absence proof"]
pub(crate) struct FixedPermanentNeighbourRetirement {
    journal: Option<NeighbourJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedPermanentNeighbourRetirement {
    fn new(journal: NeighbourJournal) -> Self {
        Self {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }

    /// Fixed record represented by this retirement authority.
    pub(crate) fn specification(&self) -> FixedPermanentNeighbour {
        self.journal().lineage.specification
    }

    /// Fallibly bind this authority to the exact retained pair after its full
    /// parent/endpoint absence proof, without consuming it.
    pub(super) fn prevalidate_pair_absence_retirement(
        &self,
        proof: &FixedPairAbsenceProof,
    ) -> Result<(), FixedNeighbourRetirementError> {
        let journal = self.journal();
        journal
            .namespace
            .verify_retained()
            .map_err(FixedNeighbourRetirementError)?;
        validate_lineage(&journal.lineage).map_err(FixedNeighbourRetirementError)?;
        if !proof.validates_permanent_neighbour(&journal.lineage.pair) {
            return Err(FixedNeighbourRetirementError(
                FixedNeighbourOperationError::Unsafe(
                    "pair-absence proof does not bind retained neighbour lineage",
                ),
            ));
        }
        Ok(())
    }

    /// Infallibly disarm after aggregate prevalidation against the same proof.
    pub(super) fn retire_after_validated_pair_absence(mut self, proof: &FixedPairAbsenceProof) {
        if self.prevalidate_pair_absence_retirement(proof).is_err() {
            std::process::abort();
        }
        self.journal = None;
    }

    fn journal(&self) -> &NeighbourJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedPermanentNeighbourRetirement {
    fn drop(&mut self) {
        if self.journal.is_some() {
            std::process::abort();
        }
    }
}

fn validate_lineage(lineage: &NeighbourLineage) -> Result<(), FixedNeighbourOperationError> {
    let specification = lineage.specification;
    let (parent_device, parent_inode) = lineage.pair.parent_namespace_parts();
    let (endpoint_device, endpoint_inode) = lineage.pair.endpoint_namespace_parts();
    let parent_namespace = NamespaceIdentity {
        device: parent_device,
        inode: parent_inode,
    };
    let endpoint_namespace = NamespaceIdentity {
        device: endpoint_device,
        inode: endpoint_inode,
    };
    let expected_namespace = if specification.is_parent() {
        parent_namespace
    } else {
        endpoint_namespace
    };
    let expected_destination_namespace = if specification.is_parent() {
        endpoint_namespace
    } else {
        parent_namespace
    };
    let expected_ifindex = if specification.is_parent() {
        lineage.pair.parent_ifindex()
    } else {
        lineage.pair.endpoint_ifindex()
    };
    let expected_name = if specification.is_parent() {
        lineage.pair.parent_name()
    } else {
        FIXED_VETH_PEER_NAME
    };
    let expected_mac = if specification.is_parent() {
        lineage
            .pair
            .endpoint_mac()
            .map_err(|_| FixedNeighbourOperationError::Unsafe("retained pair lacks endpoint MAC"))?
    } else {
        lineage.pair.parent_mac()
    };
    let parent_mac = lineage.pair.parent_mac();
    let endpoint_mac = lineage
        .pair
        .endpoint_mac()
        .map_err(|_| FixedNeighbourOperationError::Unsafe("retained pair lacks endpoint MAC"))?;
    if lineage.pair.endpoint() != specification.endpoint()
        || lineage.namespace != expected_namespace
        || lineage.local_address_namespace != expected_namespace
        || lineage.destination_address_namespace != expected_destination_namespace
        || lineage.ifindex != expected_ifindex
        || lineage.interface_name != expected_name
        || lineage.local_address != specification.local_address()
        || lineage.destination_address != specification.destination_address()
        || lineage.link_layer_address != expected_mac
        || !(2..=i32::MAX as u32).contains(&lineage.ifindex)
        || lineage.interface_name.is_empty()
        || lineage.interface_name.len() >= libc::IFNAMSIZ
        || !lineage.interface_name.is_ascii()
        || lineage.interface_name.as_bytes().contains(&0)
        || parent_namespace.device == 0
        || parent_namespace.inode == 0
        || endpoint_namespace.device == 0
        || endpoint_namespace.inode == 0
        || parent_namespace == endpoint_namespace
        || !valid_unicast_mac(parent_mac)
        || !valid_unicast_mac(endpoint_mac)
        || parent_mac == endpoint_mac
    {
        return Err(FixedNeighbourOperationError::Unsafe(
            "retained permanent-neighbour lineage is invalid",
        ));
    }
    Ok(())
}

fn valid_unicast_mac(mac: [u8; ETHERNET_ADDRESS_BYTES]) -> bool {
    mac != [0; ETHERNET_ADDRESS_BYTES]
        && mac != [u8::MAX; ETHERNET_ADDRESS_BYTES]
        && mac[0] & 1 == 0
}

fn install_neighbour(
    journal: NeighbourJournal,
) -> Result<FixedPermanentNeighbourOwner, FixedNeighbourInstallError> {
    journal
        .verify_context()
        .map_err(FixedNeighbourInstallError::BeforeMutation)?;
    match observe_presence(&journal).map_err(FixedNeighbourInstallError::BeforeMutation)? {
        NeighbourPresence::Absent => {}
        NeighbourPresence::Exact => {
            return Err(FixedNeighbourInstallError::BeforeMutation(
                FixedNeighbourOperationError::Unsafe(
                    "exact permanent neighbour already exists before installation",
                ),
            ));
        }
        NeighbourPresence::Conflicting => {
            return Err(FixedNeighbourInstallError::BeforeMutation(
                FixedNeighbourOperationError::Conflicting,
            ));
        }
    }
    let payload = encode_create_payload(&journal.lineage)
        .map_err(FixedNeighbourInstallError::BeforeMutation)?;
    let deadline = Deadline::after(NEIGHBOUR_OPERATION_TIMEOUT)
        .map_err(FixedNeighbourInstallError::BeforeMutation)?;
    let mut client =
        NetlinkClient::connect(deadline).map_err(FixedNeighbourInstallError::BeforeMutation)?;
    let sequence = client
        .next_sequence()
        .map_err(FixedNeighbourInstallError::BeforeMutation)?;
    let request = encode_message(
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        sequence,
        &payload,
    )
    .map_err(FixedNeighbourInstallError::BeforeMutation)?;
    let mut guard = ProvisionalNeighbourGuard::new(journal);
    match send_bounded(&client.socket, &request, deadline) {
        Ok(()) => guard.mark_possibly_applied(),
        Err(SendFailure::NotSent(source)) => return Err(guard.before_mutation(source)),
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
        Ack::Success => match observe_presence(guard.journal()) {
            Ok(NeighbourPresence::Exact) => Ok(guard.into_owner()),
            Ok(NeighbourPresence::Absent) => {
                guard.deletion_bound(FixedNeighbourOperationError::Unsafe(
                    "ACKed permanent neighbour is absent from exact readback",
                ))
            }
            Ok(NeighbourPresence::Conflicting) => {
                guard.deletion_bound(FixedNeighbourOperationError::Conflicting)
            }
            Err(source) => guard.deletion_bound(source),
        },
        Ack::Rejected(errno) => guard.deletion_bound(FixedNeighbourOperationError::errno(
            "install exclusive permanent neighbour",
            errno,
        )),
    }
}

struct ProvisionalNeighbourGuard {
    journal: Option<NeighbourJournal>,
    possibly_applied: bool,
}

impl ProvisionalNeighbourGuard {
    fn new(journal: NeighbourJournal) -> Self {
        Self {
            journal: Some(journal),
            possibly_applied: false,
        }
    }

    fn journal(&self) -> &NeighbourJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn mark_possibly_applied(&mut self) {
        self.possibly_applied = true;
    }

    fn before_mutation(
        mut self,
        source: FixedNeighbourOperationError,
    ) -> FixedNeighbourInstallError {
        if self.possibly_applied {
            std::process::abort();
        }
        self.journal = None;
        FixedNeighbourInstallError::BeforeMutation(source)
    }

    fn reconcile_ambiguous(
        self,
        source: FixedNeighbourOperationError,
    ) -> Result<FixedPermanentNeighbourOwner, FixedNeighbourInstallError> {
        if !self.possibly_applied {
            std::process::abort();
        }
        self.deletion_bound(source)
    }

    fn deletion_bound(
        mut self,
        source: FixedNeighbourOperationError,
    ) -> Result<FixedPermanentNeighbourOwner, FixedNeighbourInstallError> {
        if !self.possibly_applied {
            std::process::abort();
        }
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.possibly_applied = false;
        Err(FixedNeighbourInstallError::DeletionBound {
            source,
            authority: Box::new(FixedPermanentNeighbourRetirement::new(journal)),
        })
    }

    fn into_owner(mut self) -> FixedPermanentNeighbourOwner {
        if !self.possibly_applied {
            std::process::abort();
        }
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.possibly_applied = false;
        FixedPermanentNeighbourOwner {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for ProvisionalNeighbourGuard {
    fn drop(&mut self) {
        if self.possibly_applied || self.journal.is_some() {
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NeighbourPresence {
    Absent,
    Exact,
    Conflicting,
}

fn observe_presence(
    journal: &NeighbourJournal,
) -> Result<NeighbourPresence, FixedNeighbourOperationError> {
    journal.verify_context()?;
    let deadline = Deadline::after(NEIGHBOUR_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(
        RTM_GETNEIGH,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        &encode_dump_payload(),
    )?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let mut state = NeighbourDumpState::new(sequence, client.local_port, request);
    let mut budget = ReceiveBudget::dump();
    while !state.done {
        let reply = receive_bounded(&client.socket, deadline, &mut budget)?;
        state.ingest(&reply, &mut budget, &journal.lineage)?;
    }
    deadline.ensure_unexpired()?;
    state.finish()
}

fn delete_and_reconcile(journal: &NeighbourJournal) -> Result<(), FixedNeighbourOperationError> {
    delete_with(|| observe_presence(journal), || transact_delete(journal))
}

fn delete_with<Observe, Delete>(
    mut observe: Observe,
    mut delete: Delete,
) -> Result<(), FixedNeighbourOperationError>
where
    Observe: FnMut() -> Result<NeighbourPresence, FixedNeighbourOperationError>,
    Delete: FnMut() -> Result<(), FixedNeighbourOperationError>,
{
    match observe()? {
        NeighbourPresence::Exact => {}
        NeighbourPresence::Absent => {
            return Err(FixedNeighbourOperationError::Unsafe(
                "owned permanent neighbour is absent before explicit deletion",
            ));
        }
        NeighbourPresence::Conflicting => return Err(FixedNeighbourOperationError::Conflicting),
    }
    let delete_error = delete().err();
    match observe()? {
        NeighbourPresence::Absent => Ok(()),
        NeighbourPresence::Exact => {
            Err(delete_error.unwrap_or(FixedNeighbourOperationError::Unsafe(
                "permanent neighbour remained or was replaced after one-shot deletion",
            )))
        }
        NeighbourPresence::Conflicting => Err(FixedNeighbourOperationError::Conflicting),
    }
}

fn transact_delete(journal: &NeighbourJournal) -> Result<(), FixedNeighbourOperationError> {
    journal.verify_context()?;
    let payload = encode_delete_payload(&journal.lineage)?;
    let deadline = Deadline::after(NEIGHBOUR_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let reply = receive_one(&client.socket, deadline)?;
    match parse_ack(&reply, client.local_port, &request)? {
        Ack::Success => Ok(()),
        Ack::Rejected(errno) => Err(FixedNeighbourOperationError::errno(
            "delete exact permanent neighbour",
            errno,
        )),
    }
}

fn encode_create_payload(
    lineage: &NeighbourLineage,
) -> Result<Vec<u8>, FixedNeighbourOperationError> {
    validate_lineage(lineage)?;
    let mut payload = neighbour_message(lineage.ifindex, NUD_PERMANENT)?;
    push_attribute(&mut payload, NDA_DST, &lineage.destination_address.octets())?;
    push_attribute(&mut payload, NDA_LLADDR, &lineage.link_layer_address)?;
    push_attribute(&mut payload, NDA_PROTOCOL, &[RTPROT_STATIC])?;
    Ok(payload)
}

fn encode_delete_payload(
    lineage: &NeighbourLineage,
) -> Result<Vec<u8>, FixedNeighbourOperationError> {
    validate_lineage(lineage)?;
    let mut payload = neighbour_message(lineage.ifindex, NUD_PERMANENT)?;
    push_attribute(&mut payload, NDA_DST, &lineage.destination_address.octets())?;
    Ok(payload)
}

fn encode_dump_payload() -> Vec<u8> {
    let mut payload = vec![0; NDMSG_LEN];
    payload[0] = AF_INET;
    payload
}

fn neighbour_message(ifindex: u32, state: u16) -> Result<Vec<u8>, FixedNeighbourOperationError> {
    if !(2..=i32::MAX as u32).contains(&ifindex) {
        return Err(FixedNeighbourOperationError::Unsafe(
            "permanent-neighbour ifindex is not representable",
        ));
    }
    let mut payload = Vec::with_capacity(NDMSG_LEN);
    payload.push(AF_INET);
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    payload.extend_from_slice(&state.to_ne_bytes());
    payload.push(0);
    payload.push(0);
    Ok(payload)
}

fn encode_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, FixedNeighbourOperationError> {
    if sequence == 0 {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink sequence is zero",
        ));
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedNeighbourOperationError::Limit)?;
    if length > MAX_REQUEST_BYTES {
        return Err(FixedNeighbourOperationError::Limit);
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| FixedNeighbourOperationError::Limit)?
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
) -> Result<(), FixedNeighbourOperationError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(FixedNeighbourOperationError::Limit)?;
    buffer.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| FixedNeighbourOperationError::Limit)?
            .to_ne_bytes(),
    );
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len())?, 0);
    if buffer.len() > MAX_REQUEST_BYTES - NLMSG_HEADER_LEN {
        return Err(FixedNeighbourOperationError::Limit);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, FixedNeighbourOperationError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(FixedNeighbourOperationError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, FixedNeighbourOperationError> {
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
                .ok_or(FixedNeighbourOperationError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| FixedNeighbourOperationError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), FixedNeighbourOperationError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error())
        }
    }
}

fn timeout_error() -> FixedNeighbourOperationError {
    FixedNeighbourOperationError::io(
        "wait for RTNETLINK response",
        io::Error::new(
            io::ErrorKind::TimedOut,
            "fixed permanent-neighbour deadline expired",
        ),
    )
}

struct NetlinkClient {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkClient {
    fn connect(deadline: Deadline) -> Result<Self, FixedNeighbourOperationError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|source| FixedNeighbourOperationError::io("open RTNETLINK socket", source))?;
        socket.set_netlink_get_strict_chk(true).map_err(|source| {
            FixedNeighbourOperationError::io("enable strict RTNETLINK checking", source)
        })?;
        socket.set_non_blocking(true).map_err(|source| {
            FixedNeighbourOperationError::io("harden RTNETLINK socket", source)
        })?;
        let address = socket
            .bind_auto()
            .map_err(|source| FixedNeighbourOperationError::io("bind RTNETLINK socket", source))?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(FixedNeighbourOperationError::Unsafe(
                "RTNETLINK socket binding is not exact",
            ));
        }
        socket.connect(&SocketAddr::new(0, 0)).map_err(|source| {
            FixedNeighbourOperationError::io("connect RTNETLINK socket", source)
        })?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> Result<u32, FixedNeighbourOperationError> {
        let current = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(FixedNeighbourOperationError::Limit)?;
        if current == 0 {
            Err(FixedNeighbourOperationError::Unsafe(
                "RTNETLINK sequence is zero",
            ))
        } else {
            Ok(current)
        }
    }
}

enum SendFailure {
    NotSent(FixedNeighbourOperationError),
    PossiblySent(FixedNeighbourOperationError),
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), SendFailure> {
    loop {
        deadline.ensure_unexpired().map_err(SendFailure::NotSent)?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return Ok(()),
            Ok(_) => {
                return Err(SendFailure::PossiblySent(FixedNeighbourOperationError::io(
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
                return Err(SendFailure::NotSent(FixedNeighbourOperationError::io(
                    "send RTNETLINK request",
                    error,
                )));
            }
        }
    }
}

fn send_failure_source(failure: SendFailure) -> FixedNeighbourOperationError {
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
) -> Result<NetlinkReply, FixedNeighbourOperationError> {
    let mut budget = ReceiveBudget::single();
    receive_bounded(socket, deadline, &mut budget)
}

fn receive_bounded(
    socket: &Socket,
    deadline: Deadline,
    budget: &mut ReceiveBudget,
) -> Result<NetlinkReply, FixedNeighbourOperationError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(FixedNeighbourOperationError::io(
                        "measure RTNETLINK response",
                        error,
                    ));
                }
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(FixedNeighbourOperationError::Unsafe(
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
                return Err(FixedNeighbourOperationError::io(
                    "receive RTNETLINK response",
                    error,
                ));
            }
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != length || sender != peek_sender {
            return Err(FixedNeighbourOperationError::Unsafe(
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
) -> Result<(), FixedNeighbourOperationError> {
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
                    return Err(FixedNeighbourOperationError::Unsafe(
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

    fn can_receive(&self, length: usize) -> Result<(), FixedNeighbourOperationError> {
        if !(NLMSG_HEADER_LEN..=MAX_NETLINK_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(FixedNeighbourOperationError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), FixedNeighbourOperationError> {
        self.can_receive(length)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or(FixedNeighbourOperationError::Limit)?;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(FixedNeighbourOperationError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(FixedNeighbourOperationError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), FixedNeighbourOperationError> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(FixedNeighbourOperationError::Limit)?;
        if self.frames > self.max_frames {
            return Err(FixedNeighbourOperationError::Limit);
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
) -> Result<Ack, FixedNeighbourOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink ACK sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    let flags = read_u16(frame, 6)?;
    if read_u16(frame, 4)? != NLMSG_ERROR
        || read_u32(frame, 8)? != read_u32(request, 8)?
        || read_u32(frame, 12)? != local_port
    {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink ACK header is not exact",
        ));
    }
    let payload = &frame[NLMSG_HEADER_LEN..];
    let embedded_length = NLMSG_ERROR_CODE_LEN
        .checked_add(NLMSG_HEADER_LEN)
        .ok_or(FixedNeighbourOperationError::Limit)?;
    if payload.len() < embedded_length
        || payload[NLMSG_ERROR_CODE_LEN..embedded_length] != request[..NLMSG_HEADER_LEN]
    {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink ACK does not bind the exact neighbour request header",
        ));
    }
    let trailing = &payload[embedded_length..];
    let errno = read_i32(payload, 0)?;
    if flags & NLM_F_ACK_TLVS != 0 {
        return Err(FixedNeighbourOperationError::Unsafe(
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
        0 => Err(FixedNeighbourOperationError::Unsafe(
            "successful netlink ACK is not canonical and capped",
        )),
        errno if errno < 0 => Err(FixedNeighbourOperationError::Unsafe(
            "negative netlink ACK does not exactly echo the neighbour request",
        )),
        _ => Err(FixedNeighbourOperationError::Unsafe(
            "netlink ACK errno is not canonical",
        )),
    }
}

fn single_frame(bytes: &[u8]) -> Result<&[u8], FixedNeighbourOperationError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink datagram lacks a complete header",
        ));
    }
    let length =
        usize::try_from(read_u32(bytes, 0)?).map_err(|_| FixedNeighbourOperationError::Limit)?;
    let aligned = align4(length)?;
    if length < NLMSG_HEADER_LEN || aligned != bytes.len() {
        return Err(FixedNeighbourOperationError::Unsafe(
            "netlink datagram does not contain exactly one frame",
        ));
    }
    if bytes[length..aligned].iter().any(|byte| *byte != 0) {
        return Err(FixedNeighbourOperationError::Unsafe(
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

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, FixedNeighbourOperationError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if attributes.len() >= MAX_ATTRIBUTES || bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(FixedNeighbourOperationError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(FixedNeighbourOperationError::Unsafe(
                "netlink neighbour attribute length is invalid",
            ));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(FixedNeighbourOperationError::Unsafe(
                "netlink neighbour attribute padding is nonzero",
            ));
        }
        let raw_kind = read_u16(bytes, 2)?;
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(FixedNeighbourOperationError::Unsafe(
                "netlink neighbour attribute flags are contradictory",
            ));
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

struct NeighbourDumpState {
    sequence: u32,
    local_port: u32,
    request: Vec<u8>,
    done: bool,
    records: usize,
    matching: Option<NeighbourPresence>,
}

impl NeighbourDumpState {
    fn new(sequence: u32, local_port: u32, request: Vec<u8>) -> Self {
        Self {
            sequence,
            local_port,
            request,
            done: false,
            records: 0,
            matching: None,
        }
    }

    fn ingest(
        &mut self,
        reply: &NetlinkReply,
        budget: &mut ReceiveBudget,
        lineage: &NeighbourLineage,
    ) -> Result<(), FixedNeighbourOperationError> {
        if self.done || reply.sender != SocketAddr::new(0, 0) {
            return Err(FixedNeighbourOperationError::Unsafe(
                "neighbour dump sender or completion state is invalid",
            ));
        }
        let mut offset = 0;
        while offset < reply.bytes.len() {
            let remaining = &reply.bytes[offset..];
            if remaining.len() < NLMSG_HEADER_LEN {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump has a truncated frame",
                ));
            }
            let length = usize::try_from(read_u32(remaining, 0)?)
                .map_err(|_| FixedNeighbourOperationError::Limit)?;
            let aligned = align4(length)?;
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump frame length is invalid",
                ));
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump frame padding is nonzero",
                ));
            }
            budget.record_frame()?;
            self.ingest_frame(&remaining[..length], lineage)?;
            offset = offset
                .checked_add(aligned)
                .ok_or(FixedNeighbourOperationError::Limit)?;
            if self.done && offset != reply.bytes.len() {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump carries data after completion",
                ));
            }
        }
        Ok(())
    }

    fn ingest_frame(
        &mut self,
        frame: &[u8],
        lineage: &NeighbourLineage,
    ) -> Result<(), FixedNeighbourOperationError> {
        if read_u32(frame, 8)? != self.sequence || read_u32(frame, 12)? != self.local_port {
            return Err(FixedNeighbourOperationError::Unsafe(
                "neighbour dump sequence or port is not exact",
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
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump overrun is ambiguous",
                ));
            }
            RTM_NEWNEIGH if flags == NLM_F_MULTI => {
                self.records = self
                    .records
                    .checked_add(1)
                    .ok_or(FixedNeighbourOperationError::Limit)?;
                if self.records > MAX_NEIGHBOUR_RECORDS {
                    return Err(FixedNeighbourOperationError::Limit);
                }
                match parse_neighbour_record(payload, lineage)? {
                    RecordMatch::Unrelated => {}
                    RecordMatch::Exact => {
                        self.matching = Some(match self.matching {
                            None => NeighbourPresence::Exact,
                            Some(_) => NeighbourPresence::Conflicting,
                        });
                    }
                    RecordMatch::Conflicting => {
                        self.matching = Some(NeighbourPresence::Conflicting);
                    }
                }
            }
            _ => {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour dump contains an unexpected message",
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<NeighbourPresence, FixedNeighbourOperationError> {
        if !self.done {
            return Err(FixedNeighbourOperationError::Unsafe(
                "neighbour dump ended without NLMSG_DONE",
            ));
        }
        Ok(self.matching.unwrap_or(NeighbourPresence::Absent))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordMatch {
    Unrelated,
    Exact,
    Conflicting,
}

fn parse_neighbour_record(
    payload: &[u8],
    lineage: &NeighbourLineage,
) -> Result<RecordMatch, FixedNeighbourOperationError> {
    if payload.len() < NDMSG_LEN || payload[0] != AF_INET {
        return Err(FixedNeighbourOperationError::Unsafe(
            "IPv4 neighbour dump record header is malformed",
        ));
    }
    if payload[1] != 0 || read_u16(payload, 2)? != 0 {
        return Err(FixedNeighbourOperationError::Unsafe(
            "IPv4 neighbour dump padding is nonzero",
        ));
    }
    let ifindex = read_i32(payload, 4)?;
    if !(2..=i32::MAX).contains(&ifindex) {
        return Err(FixedNeighbourOperationError::Unsafe(
            "IPv4 neighbour dump ifindex is invalid",
        ));
    }
    let attributes = parse_attributes(&payload[NDMSG_LEN..])?;
    let mut destination = None;
    for attribute in &attributes {
        if attribute.kind == NDA_DST {
            if attribute.flags != 0 || destination.is_some() {
                return Err(FixedNeighbourOperationError::Unsafe(
                    "neighbour destination is flagged or duplicated",
                ));
            }
            destination = Some(read_exact_ipv4(attribute.payload)?);
        }
    }
    let destination = destination.ok_or(FixedNeighbourOperationError::Unsafe(
        "neighbour dump record lacks a destination",
    ))?;
    if u32::try_from(ifindex).map_err(|_| FixedNeighbourOperationError::Limit)? != lineage.ifindex
        || destination != lineage.destination_address.octets()
    {
        return Ok(RecordMatch::Unrelated);
    }

    let mut exact = read_u16(payload, 8)? == NUD_PERMANENT
        && payload[10] == 0
        && payload[11] == RTN_UNICAST
        && attributes.len() == 5;
    let mut destination_seen = false;
    let mut link_layer_address = None;
    let mut cache_info_seen = false;
    let mut probes = None;
    let mut protocol = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            exact = false;
        }
        match attribute.kind {
            NDA_DST => {
                if destination_seen || attribute.payload != destination {
                    exact = false;
                }
                destination_seen = true;
            }
            NDA_LLADDR => match read_exact_mac(attribute.payload) {
                Ok(value) if link_layer_address.replace(value).is_none() => {}
                _ => exact = false,
            },
            NDA_CACHEINFO => {
                if cache_info_seen || attribute.payload.len() != NDA_CACHEINFO_BYTES {
                    exact = false;
                }
                cache_info_seen = true;
            }
            NDA_PROBES => match read_exact_u32(attribute.payload) {
                Ok(value) if probes.replace(value).is_none() => {}
                _ => exact = false,
            },
            NDA_PROTOCOL => match read_exact_u8(attribute.payload) {
                Ok(value) if protocol.replace(value).is_none() => {}
                _ => exact = false,
            },
            _ => exact = false,
        }
    }
    exact &= destination_seen
        && link_layer_address == Some(lineage.link_layer_address)
        && cache_info_seen
        && probes == Some(0)
        && protocol == Some(RTPROT_STATIC);
    Ok(if exact {
        RecordMatch::Exact
    } else {
        RecordMatch::Conflicting
    })
}

fn parse_dump_done(flags: u16, payload: &[u8]) -> Result<(), FixedNeighbourOperationError> {
    if flags != NLM_F_MULTI {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour dump completion flags are not exact",
        ));
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 && errno != i32::MIN => Err(FixedNeighbourOperationError::errno(
                "dump IPv4 neighbours",
                -errno,
            )),
            _ => Err(FixedNeighbourOperationError::Unsafe(
                "neighbour dump completion errno is not canonical",
            )),
        },
        _ => Err(FixedNeighbourOperationError::Unsafe(
            "neighbour dump completion payload is not exact",
        )),
    }
}

fn parse_dump_error(
    flags: u16,
    payload: &[u8],
    request: &[u8],
) -> Result<FixedNeighbourOperationError, FixedNeighbourOperationError> {
    if flags != 0 || payload.len() != NLMSG_ERROR_CODE_LEN + request.len() {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour dump error shape is not exact",
        ));
    }
    let errno = read_i32(payload, 0)?;
    if payload[NLMSG_ERROR_CODE_LEN..] != *request {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour dump error does not echo the exact request",
        ));
    }
    if errno < 0 && errno != i32::MIN {
        Ok(FixedNeighbourOperationError::errno(
            "dump IPv4 neighbours",
            -errno,
        ))
    } else {
        Err(FixedNeighbourOperationError::Unsafe(
            "neighbour dump error errno is not canonical",
        ))
    }
}

fn validate_namespace_descriptor<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<(), FixedNeighbourOperationError> {
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFD)
            .map_err(|source| errno_io("read neighbour namespace descriptor flags", source))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFL)
            .map_err(|source| errno_io("read neighbour namespace status flags", source))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC)
        || status_flags & OFlag::O_ACCMODE != OFlag::O_RDONLY
    {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour namespace descriptor is not read-only and close-on-exec",
        ));
    }
    if fstatfs(descriptor)
        .map_err(|source| rustix_io("identify neighbour namespace filesystem", source))?
        .f_type
        != NSFS_MAGIC
        || namespace_type(descriptor).map_err(|source| {
            FixedNeighbourOperationError::io("identify neighbour network namespace", source)
        })? != libc::CLONE_NEWNET
    {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour namespace descriptor is not a network nsfs object",
        ));
    }
    Ok(())
}

fn open_current_network_namespace() -> Result<OwnedFd, FixedNeighbourOperationError> {
    let descriptor = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| rustix_io("open current neighbour network namespace", source))?;
    validate_namespace_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn object_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<NamespaceIdentity, FixedNeighbourOperationError> {
    let metadata = fstat(descriptor)
        .map_err(|source| rustix_io("measure neighbour namespace descriptor", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour namespace descriptor identity is zero",
        ));
    }
    Ok(NamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn errno_io(operation: &'static str, source: nix::errno::Errno) -> FixedNeighbourOperationError {
    FixedNeighbourOperationError::io(operation, io::Error::from_raw_os_error(source as i32))
}

fn rustix_io(operation: &'static str, source: rustix::io::Errno) -> FixedNeighbourOperationError {
    FixedNeighbourOperationError::io(
        operation,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

fn read_exact_ipv4(bytes: &[u8]) -> Result<[u8; 4], FixedNeighbourOperationError> {
    bytes.try_into().map_err(|_| {
        FixedNeighbourOperationError::Unsafe(
            "neighbour destination is not exactly one IPv4 address",
        )
    })
}

fn read_exact_mac(
    bytes: &[u8],
) -> Result<[u8; ETHERNET_ADDRESS_BYTES], FixedNeighbourOperationError> {
    bytes.try_into().map_err(|_| {
        FixedNeighbourOperationError::Unsafe("neighbour link-layer address length is not exact")
    })
}

fn read_exact_u8(bytes: &[u8]) -> Result<u8, FixedNeighbourOperationError> {
    match bytes {
        [value] => Ok(*value),
        _ => Err(FixedNeighbourOperationError::Unsafe(
            "neighbour attribute is not exactly one u8",
        )),
    }
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, FixedNeighbourOperationError> {
    if bytes.len() != 4 {
        return Err(FixedNeighbourOperationError::Unsafe(
            "neighbour attribute is not exactly one u32",
        ));
    }
    read_u32(bytes, 0)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FixedNeighbourOperationError> {
    let end = offset
        .checked_add(2)
        .ok_or(FixedNeighbourOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedNeighbourOperationError::Unsafe(
            "netlink u16 field is truncated",
        ))?;
    Ok(u16::from_ne_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FixedNeighbourOperationError> {
    let end = offset
        .checked_add(4)
        .ok_or(FixedNeighbourOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FixedNeighbourOperationError::Unsafe(
            "netlink u32 field is truncated",
        ))?;
    Ok(u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, FixedNeighbourOperationError> {
    Ok(i32::from_ne_bytes(read_u32(bytes, offset)?.to_ne_bytes()))
}

fn align4(value: usize) -> Result<usize, FixedNeighbourOperationError> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or(FixedNeighbourOperationError::Limit)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, env, process::Command};

    use super::*;

    const TEST_SEQUENCE: u32 = 0x1122_3344;
    const TEST_PORT: u32 = 0x5566_7788;
    const ARMED_RETIREMENT_CHILD: &str = "VOLPAROSSA_TEST_ARMED_NEIGHBOUR_RETIREMENT";

    fn test_lineage(specification: FixedPermanentNeighbour) -> NeighbourLineage {
        let pair = FixedPermanentNeighbourPairLineage::from_test_parts(specification.endpoint());
        let (parent_device, parent_inode) = pair.parent_namespace_parts();
        let (endpoint_device, endpoint_inode) = pair.endpoint_namespace_parts();
        let parent_namespace = NamespaceIdentity {
            device: parent_device,
            inode: parent_inode,
        };
        let endpoint_namespace = NamespaceIdentity {
            device: endpoint_device,
            inode: endpoint_inode,
        };
        let namespace = if specification.is_parent() {
            parent_namespace
        } else {
            endpoint_namespace
        };
        let destination_namespace = if specification.is_parent() {
            endpoint_namespace
        } else {
            parent_namespace
        };
        let (ifindex, interface_name, link_layer_address) = if specification.is_parent() {
            (
                pair.parent_ifindex(),
                pair.parent_name().to_owned(),
                pair.endpoint_mac().expect("test endpoint MAC"),
            )
        } else {
            (
                pair.endpoint_ifindex(),
                FIXED_VETH_PEER_NAME.to_owned(),
                pair.parent_mac(),
            )
        };
        NeighbourLineage {
            specification,
            pair,
            namespace,
            ifindex,
            interface_name,
            local_address: specification.local_address(),
            local_address_namespace: namespace,
            destination_address: specification.destination_address(),
            destination_address_namespace: destination_namespace,
            link_layer_address,
        }
    }

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

    fn neighbour_record_payload(
        lineage: &NeighbourLineage,
        state: u16,
        record_type: u8,
        attributes: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut payload = neighbour_message(lineage.ifindex, state).expect("test ndmsg");
        payload[11] = record_type;
        for attribute in attributes {
            payload.extend_from_slice(attribute);
        }
        payload
    }

    fn exact_record_attributes(lineage: &NeighbourLineage) -> Vec<Vec<u8>> {
        vec![
            attribute(NDA_DST, 0, &lineage.destination_address.octets()),
            attribute(NDA_LLADDR, 0, &lineage.link_layer_address),
            attribute(NDA_CACHEINFO, 0, &[0xa5; NDA_CACHEINFO_BYTES]),
            attribute(NDA_PROBES, 0, &0_u32.to_ne_bytes()),
            attribute(NDA_PROTOCOL, 0, &[RTPROT_STATIC]),
        ]
    }

    fn exact_record(lineage: &NeighbourLineage) -> Vec<u8> {
        neighbour_record_payload(
            lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &exact_record_attributes(lineage),
        )
    }

    fn encode_test_message(
        kind: u16,
        flags: u16,
        sequence: u32,
        port: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut message = Vec::with_capacity(aligned);
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
        message.resize(aligned, 0);
        message
    }

    fn ack_reply(request: &[u8], errno: i32, flags: u16, trailing: &[u8]) -> NetlinkReply {
        let mut payload = errno.to_ne_bytes().to_vec();
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        payload.extend_from_slice(trailing);
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: encode_test_message(
                NLMSG_ERROR,
                flags,
                read_u32(request, 8).expect("test request sequence"),
                TEST_PORT,
                &payload,
            ),
        }
    }

    fn dump_state() -> NeighbourDumpState {
        let request = encode_message(
            RTM_GETNEIGH,
            NLM_F_REQUEST | NLM_F_DUMP,
            TEST_SEQUENCE,
            &encode_dump_payload(),
        )
        .expect("test dump request");
        NeighbourDumpState::new(TEST_SEQUENCE, TEST_PORT, request)
    }

    fn dump_reply(kind: u16, flags: u16, payload: &[u8]) -> NetlinkReply {
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: encode_test_message(kind, flags, TEST_SEQUENCE, TEST_PORT, payload),
        }
    }

    fn test_error(label: &'static str) -> FixedNeighbourOperationError {
        FixedNeighbourOperationError::Unsafe(label)
    }

    #[test]
    fn fixed_neighbour_set_and_order_are_exact() {
        assert_eq!(
            FixedPermanentNeighbour::INSTALL_ORDER,
            [
                FixedPermanentNeighbour::ParentA,
                FixedPermanentNeighbour::ParentB,
                FixedPermanentNeighbour::EndpointA,
                FixedPermanentNeighbour::EndpointB,
            ]
        );
        assert_eq!(
            FixedPermanentNeighbour::DELETE_ORDER,
            [
                FixedPermanentNeighbour::EndpointB,
                FixedPermanentNeighbour::EndpointA,
                FixedPermanentNeighbour::ParentB,
                FixedPermanentNeighbour::ParentA,
            ]
        );
        let mappings = [
            (
                FixedPermanentNeighbour::ParentA,
                FixedVethEndpoint::A,
                true,
                FixedIpv4Address::ParentA,
                FixedIpv4Address::EndpointA,
            ),
            (
                FixedPermanentNeighbour::ParentB,
                FixedVethEndpoint::B,
                true,
                FixedIpv4Address::ParentB,
                FixedIpv4Address::EndpointB,
            ),
            (
                FixedPermanentNeighbour::EndpointA,
                FixedVethEndpoint::A,
                false,
                FixedIpv4Address::EndpointA,
                FixedIpv4Address::ParentA,
            ),
            (
                FixedPermanentNeighbour::EndpointB,
                FixedVethEndpoint::B,
                false,
                FixedIpv4Address::EndpointB,
                FixedIpv4Address::ParentB,
            ),
        ];
        for (specification, endpoint, is_parent, local, destination) in mappings {
            assert_eq!(specification.endpoint(), endpoint);
            assert_eq!(specification.is_parent(), is_parent);
            assert_eq!(specification.local_address(), local);
            assert_eq!(specification.destination_address(), destination);
            assert!(validate_lineage(&test_lineage(specification)).is_ok());
        }
    }

    #[test]
    fn retained_lineage_rejects_every_changed_binding_class() {
        let exact = test_lineage(FixedPermanentNeighbour::ParentA);
        let mut variants = Vec::new();

        let mut changed = exact.clone();
        changed.namespace.inode += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.local_address_namespace.device += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.destination_address_namespace.inode += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.ifindex += 1;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.interface_name = FIXED_VETH_PEER_NAME.to_owned();
        variants.push(changed);
        let mut changed = exact.clone();
        changed.local_address = FixedIpv4Address::ParentB;
        variants.push(changed);
        let mut changed = exact.clone();
        changed.destination_address = FixedIpv4Address::EndpointB;
        variants.push(changed);
        let mut changed = exact;
        changed.link_layer_address[1] ^= 1;
        variants.push(changed);

        assert!(
            variants
                .iter()
                .all(|lineage| validate_lineage(lineage).is_err())
        );
    }

    #[test]
    fn create_and_delete_requests_are_minimal_and_byte_exact() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentA);
        let create_payload = encode_create_payload(&lineage).expect("create payload");
        assert_eq!(
            &create_payload[..NDMSG_LEN],
            &[2, 0, 0, 0, 2, 0, 0, 0, 128, 0, 0, 0]
        );
        assert_eq!(
            &create_payload[NDMSG_LEN..],
            [
                attribute(NDA_DST, 0, &FixedIpv4Address::EndpointA.octets()),
                attribute(NDA_LLADDR, 0, &lineage.link_layer_address),
                attribute(NDA_PROTOCOL, 0, &[RTPROT_STATIC]),
            ]
            .concat()
        );
        let create = encode_message(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            TEST_SEQUENCE,
            &create_payload,
        )
        .expect("create request");
        assert_eq!(read_u16(&create, 4).expect("create type"), RTM_NEWNEIGH);
        assert_eq!(
            read_u16(&create, 6).expect("create flags"),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(
            read_u32(&create, 8).expect("create sequence"),
            TEST_SEQUENCE
        );
        assert_eq!(read_u32(&create, 12).expect("create port"), 0);

        let delete_payload = encode_delete_payload(&lineage).expect("delete payload");
        assert_eq!(
            &delete_payload[NDMSG_LEN..],
            attribute(NDA_DST, 0, &FixedIpv4Address::EndpointA.octets())
        );
        let delete = encode_message(
            RTM_DELNEIGH,
            NLM_F_REQUEST | NLM_F_ACK,
            TEST_SEQUENCE,
            &delete_payload,
        )
        .expect("delete request");
        assert_eq!(read_u16(&delete, 4).expect("delete type"), RTM_DELNEIGH);
        assert_eq!(
            read_u16(&delete, 6).expect("delete flags"),
            NLM_F_REQUEST | NLM_F_ACK
        );
    }

    #[test]
    fn dump_request_is_strict_ipv4_and_fully_bounded() {
        let payload = encode_dump_payload();
        assert_eq!(payload, [AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let request = encode_message(
            RTM_GETNEIGH,
            NLM_F_REQUEST | NLM_F_DUMP,
            TEST_SEQUENCE,
            &payload,
        )
        .expect("dump request");
        assert_eq!(read_u16(&request, 4).expect("dump type"), RTM_GETNEIGH);
        assert_eq!(
            read_u16(&request, 6).expect("dump flags"),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert!(request.len() <= MAX_REQUEST_BYTES);
        assert!(encode_message(RTM_GETNEIGH, NLM_F_REQUEST, 0, &payload).is_err());
        assert!(encode_message(RTM_GETNEIGH, NLM_F_REQUEST, 1, &[0; MAX_REQUEST_BYTES]).is_err());
    }

    #[test]
    fn canonical_ack_is_bound_to_the_exact_neighbour_request() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentB);
        let payload = encode_create_payload(&lineage).expect("create payload");
        let request = encode_message(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            TEST_SEQUENCE,
            &payload,
        )
        .expect("create request");
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
        let lineage = test_lineage(FixedPermanentNeighbour::ParentB);
        let payload = encode_create_payload(&lineage).expect("create payload");
        let request = encode_message(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            TEST_SEQUENCE,
            &payload,
        )
        .expect("create request");
        let mut wrong_sender = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        wrong_sender.sender = SocketAddr::new(1, 0);
        assert!(parse_ack(&wrong_sender, TEST_PORT, &request).is_err());

        let mut wrong_sequence = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        wrong_sequence.bytes[8..12].copy_from_slice(&9_u32.to_ne_bytes());
        assert!(parse_ack(&wrong_sequence, TEST_PORT, &request).is_err());
        assert!(
            parse_ack(
                &ack_reply(&request, 0, NLM_F_CAPPED, &[]),
                TEST_PORT + 1,
                &request
            )
            .is_err()
        );
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
        let mut nonzero_padding = ack_reply(&request, 0, NLM_F_CAPPED, &[]);
        nonzero_padding.bytes.push(1);
        assert!(parse_ack(&nonzero_padding, TEST_PORT, &request).is_err());
    }

    #[test]
    fn strict_record_accepts_only_exact_static_permanent_identity() {
        for specification in FixedPermanentNeighbour::INSTALL_ORDER {
            let lineage = test_lineage(specification);
            assert_eq!(
                parse_neighbour_record(&exact_record(&lineage), &lineage).expect("exact record"),
                RecordMatch::Exact
            );
            let mut changed_cache = exact_record_attributes(&lineage);
            changed_cache[2] = attribute(NDA_CACHEINFO, 0, &[0x5a; NDA_CACHEINFO_BYTES]);
            let payload =
                neighbour_record_payload(&lineage, NUD_PERMANENT, RTN_UNICAST, &changed_cache);
            assert_eq!(
                parse_neighbour_record(&payload, &lineage).expect("cache telemetry"),
                RecordMatch::Exact
            );
        }
    }

    #[test]
    fn same_key_nonexact_records_are_conflicts_never_absence() {
        let lineage = test_lineage(FixedPermanentNeighbour::EndpointA);
        let exact = exact_record_attributes(&lineage);
        let mut variants = Vec::new();

        variants.push(neighbour_record_payload(
            &lineage,
            0x02,
            RTN_UNICAST,
            &exact,
        ));
        variants.push(neighbour_record_payload(&lineage, NUD_PERMANENT, 2, &exact));
        let mut changed = exact.clone();
        changed[1] = attribute(NDA_LLADDR, 0, &[0x02, 99, 98, 97, 96, 95]);
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact.clone();
        changed[3] = attribute(NDA_PROBES, 0, &1_u32.to_ne_bytes());
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact.clone();
        changed[4] = attribute(NDA_PROTOCOL, 0, &[3]);
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact.clone();
        changed[4] = attribute(NDA_PROTOCOL, NLA_F_NET_BYTEORDER, &[RTPROT_STATIC]);
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact.clone();
        changed.pop();
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact.clone();
        changed.push(attribute(NDA_PROTOCOL, 0, &[RTPROT_STATIC]));
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));
        let mut changed = exact;
        changed[2] = attribute(NDA_CACHEINFO, 0, &[0; NDA_CACHEINFO_BYTES - 1]);
        variants.push(neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &changed,
        ));

        for payload in variants {
            assert_eq!(
                parse_neighbour_record(&payload, &lineage).expect("same-key record"),
                RecordMatch::Conflicting
            );
        }
    }

    #[test]
    fn structurally_valid_other_keys_are_unrelated() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentA);
        let other = test_lineage(FixedPermanentNeighbour::ParentB);
        assert_eq!(
            parse_neighbour_record(&exact_record(&other), &lineage).expect("other record"),
            RecordMatch::Unrelated
        );

        let mut same_ifindex_other_destination = exact_record_attributes(&lineage);
        same_ifindex_other_destination[0] = attribute(NDA_DST, 0, &[192, 0, 2, 1]);
        let payload = neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &same_ifindex_other_destination,
        );
        assert_eq!(
            parse_neighbour_record(&payload, &lineage).expect("other destination"),
            RecordMatch::Unrelated
        );
    }

    #[test]
    fn malformed_records_fail_closed_even_when_not_the_target() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentA);
        let mut truncated = exact_record(&lineage);
        truncated.truncate(NDMSG_LEN - 1);
        assert!(parse_neighbour_record(&truncated, &lineage).is_err());

        let mut bad_padding = exact_record(&lineage);
        bad_padding[1] = 1;
        assert!(parse_neighbour_record(&bad_padding, &lineage).is_err());

        let no_destination = neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &[attribute(NDA_LLADDR, 0, &lineage.link_layer_address)],
        );
        assert!(parse_neighbour_record(&no_destination, &lineage).is_err());

        let duplicate_destination = neighbour_record_payload(
            &lineage,
            NUD_PERMANENT,
            RTN_UNICAST,
            &[
                attribute(NDA_DST, 0, &lineage.destination_address.octets()),
                attribute(NDA_DST, 0, &lineage.destination_address.octets()),
            ],
        );
        assert!(parse_neighbour_record(&duplicate_destination, &lineage).is_err());
    }

    #[test]
    fn dump_state_proves_absent_exact_and_duplicate_conflict() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentA);

        let mut absent = dump_state();
        let mut budget = ReceiveBudget::dump();
        budget
            .record_datagram(NLMSG_HEADER_LEN)
            .expect("test budget");
        absent
            .ingest(
                &dump_reply(NLMSG_DONE, NLM_F_MULTI, &[]),
                &mut budget,
                &lineage,
            )
            .expect("absent dump");
        assert_eq!(
            absent.finish().expect("absent presence"),
            NeighbourPresence::Absent
        );

        let mut exact = dump_state();
        let mut budget = ReceiveBudget::dump();
        let record = dump_reply(RTM_NEWNEIGH, NLM_F_MULTI, &exact_record(&lineage));
        budget
            .record_datagram(record.bytes.len())
            .expect("test budget");
        exact
            .ingest(&record, &mut budget, &lineage)
            .expect("record");
        let done = dump_reply(NLMSG_DONE, NLM_F_MULTI, &[]);
        budget
            .record_datagram(done.bytes.len())
            .expect("test budget");
        exact.ingest(&done, &mut budget, &lineage).expect("done");
        assert_eq!(
            exact.finish().expect("exact presence"),
            NeighbourPresence::Exact
        );

        let mut duplicate = dump_state();
        let mut budget = ReceiveBudget::dump();
        for _ in 0..2 {
            let record = dump_reply(RTM_NEWNEIGH, NLM_F_MULTI, &exact_record(&lineage));
            budget
                .record_datagram(record.bytes.len())
                .expect("test budget");
            duplicate
                .ingest(&record, &mut budget, &lineage)
                .expect("record");
        }
        let done = dump_reply(NLMSG_DONE, NLM_F_MULTI, &[]);
        budget
            .record_datagram(done.bytes.len())
            .expect("test budget");
        duplicate
            .ingest(&done, &mut budget, &lineage)
            .expect("done");
        assert_eq!(
            duplicate.finish().expect("duplicate presence"),
            NeighbourPresence::Conflicting
        );
    }

    #[test]
    fn dump_parser_rejects_wrong_origin_completion_and_trailing_data() {
        let lineage = test_lineage(FixedPermanentNeighbour::ParentA);
        let mut state = dump_state();
        let mut budget = ReceiveBudget::dump();
        let mut wrong_sender = dump_reply(NLMSG_DONE, NLM_F_MULTI, &[]);
        wrong_sender.sender = SocketAddr::new(9, 0);
        assert!(state.ingest(&wrong_sender, &mut budget, &lineage).is_err());

        let mut state = dump_state();
        assert!(
            state
                .ingest(
                    &dump_reply(NLMSG_DONE, 0, &[]),
                    &mut ReceiveBudget::dump(),
                    &lineage,
                )
                .is_err()
        );

        let mut state = dump_state();
        let mut bytes = dump_reply(NLMSG_DONE, NLM_F_MULTI, &[]).bytes;
        bytes.extend(encode_test_message(
            RTM_NEWNEIGH,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &exact_record(&lineage),
        ));
        assert!(
            state
                .ingest(
                    &NetlinkReply {
                        sender: SocketAddr::new(0, 0),
                        bytes,
                    },
                    &mut ReceiveBudget::dump(),
                    &lineage,
                )
                .is_err()
        );
    }

    #[test]
    fn delete_requires_fresh_exact_proof_before_any_request() {
        for initial in [NeighbourPresence::Absent, NeighbourPresence::Conflicting] {
            let deletes = Cell::new(0);
            let result = delete_with(
                || Ok(initial),
                || {
                    deletes.set(deletes.get() + 1);
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(deletes.get(), 0);
        }
    }

    #[test]
    fn delete_reconciles_lost_ack_to_final_absence() {
        let observations = [NeighbourPresence::Exact, NeighbourPresence::Absent];
        let observation = Cell::new(0);
        let deletes = Cell::new(0);
        let result = delete_with(
            || {
                let index = observation.get();
                observation.set(index + 1);
                Ok(observations[index])
            },
            || {
                deletes.set(deletes.get() + 1);
                Err(test_error("simulated lost delete ACK"))
            },
        );
        assert!(result.is_ok());
        assert_eq!(deletes.get(), 1);
        assert_eq!(observation.get(), 2);
    }

    #[test]
    fn delete_never_retries_an_exact_record_after_one_shot_mutation() {
        let observations = [NeighbourPresence::Exact, NeighbourPresence::Exact];
        let observation = Cell::new(0);
        let deletes = Cell::new(0);
        let result = delete_with(
            || {
                let index = observation.get();
                observation.set(index + 1);
                Ok(observations[index])
            },
            || {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(deletes.get(), 1);
        assert_eq!(observation.get(), 2);
    }

    #[test]
    fn delete_is_one_shot_and_stops_on_replacement_conflict() {
        let deletes = Cell::new(0);
        let observations = Cell::new(0);
        let result = delete_with(
            || {
                observations.set(observations.get() + 1);
                Ok(NeighbourPresence::Exact)
            },
            || {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(deletes.get(), 1);
        assert_eq!(observations.get(), 2);

        let observation = Cell::new(0);
        let deletes = Cell::new(0);
        let result = delete_with(
            || {
                let value = if observation.get() == 0 {
                    NeighbourPresence::Exact
                } else {
                    NeighbourPresence::Conflicting
                };
                observation.set(observation.get() + 1);
                Ok(value)
            },
            || {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(FixedNeighbourOperationError::Conflicting)
        ));
        assert_eq!(deletes.get(), 1);
    }

    #[test]
    fn parser_and_receive_budgets_reject_ambiguity_and_exhaustion() {
        let mut nonzero_padding = attribute(NDA_PROTOCOL, 0, &[RTPROT_STATIC]);
        *nonzero_padding.last_mut().expect("test padding") = 1;
        assert!(parse_attributes(&nonzero_padding).is_err());
        let contradictory = attribute(
            NDA_PROTOCOL,
            NLA_F_NESTED | NLA_F_NET_BYTEORDER,
            &[RTPROT_STATIC],
        );
        assert!(parse_attributes(&contradictory).is_err());
        let mut too_many = Vec::new();
        for _ in 0..=MAX_ATTRIBUTES {
            too_many.extend(attribute(NDA_PROTOCOL, 0, &[RTPROT_STATIC]));
        }
        assert!(matches!(
            parse_attributes(&too_many),
            Err(FixedNeighbourOperationError::Limit)
        ));

        let mut single = ReceiveBudget::single();
        single
            .record_datagram(NLMSG_HEADER_LEN)
            .expect("first datagram");
        assert!(matches!(
            single.record_datagram(NLMSG_HEADER_LEN),
            Err(FixedNeighbourOperationError::Limit)
        ));
        assert!(
            ReceiveBudget::dump()
                .can_receive(MAX_NETLINK_DATAGRAM_BYTES + 1)
                .is_err()
        );
    }

    #[test]
    fn mac_validation_rejects_zero_broadcast_and_multicast() {
        assert!(valid_unicast_mac([0x02, 1, 2, 3, 4, 5]));
        assert!(!valid_unicast_mac([0; ETHERNET_ADDRESS_BYTES]));
        assert!(!valid_unicast_mac([u8::MAX; ETHERNET_ADDRESS_BYTES]));
        assert!(!valid_unicast_mac([0x01, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn armed_retirement_drop_aborts() {
        if env::var_os(ARMED_RETIREMENT_CHILD).is_some() {
            let descriptor = open_current_network_namespace().expect("current namespace");
            let identity = object_identity(&descriptor).expect("namespace identity");
            let retirement = FixedPermanentNeighbourRetirement::new(NeighbourJournal {
                namespace: RetainedCurrentNamespace {
                    descriptor,
                    identity,
                },
                lineage: test_lineage(FixedPermanentNeighbour::ParentA),
            });
            drop(retirement);
            std::process::exit(91);
        }

        let executable = env::current_exe().expect("current unit-test executable");
        let output = Command::new(executable)
            .args([
                "--exact",
                "topology::neighbour::tests::armed_retirement_drop_aborts",
                "--nocapture",
            ])
            .env(ARMED_RETIREMENT_CHILD, "1")
            .output()
            .expect("spawn armed-retirement child");
        assert!(
            !output.status.success(),
            "armed retirement unexpectedly disarmed"
        );
        assert_ne!(output.status.code(), Some(91), "armed Drop did not abort");
    }
}
