use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fs::File,
    io::{self, Read as _},
    mem::MaybeUninit,
    os::fd::OwnedFd,
};

use nix::unistd::{getpid, getppid};
use rustix::{
    fd::AsFd,
    fs::{
        ABS, AtFlags, FileType, FsWord, Mode, OFlags, PROC_SUPER_MAGIC, RawDir, ResolveFlags,
        Statx, StatxFlags, fstatfs, openat2, readlinkat, statx,
    },
    io::Errno,
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags, MoveMountFlags,
        fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change, move_mount,
    },
};
use thiserror::Error;
use volparossa_test_support::MutationAuthorization;

use crate::network::{
    FinalNetworkProof as PolicyFinalNetworkProof,
    ForwardingEnableFailureState as PolicyForwardingEnableFailureState,
    ForwardingEnabledNetworkProof as PolicyEnabledNetworkProof,
    ForwardingRestoreFailureState as PolicyForwardingRestoreFailureState,
    ForwardingRestoredNetworkProof as PolicyRestoredNetworkProof,
    MutationRollbackNetworkProof as PolicyRollbackProof, NetworkError as PolicyNetworkError,
    PristineNetworkNamespaceObservation as EndpointNetworkBaseline,
};
use crate::nftables::{
    ActiveNftablesPolicy, FixedForwardPolicyExpectation, IndeterminateNftablesPolicy,
    NftablesBaseline, NftablesDeleteAuthority, NftablesError, NftablesInstallAuthority,
    SemanticallyEmptyNftables, delete_exact_forward_policy, install_exact_forward_policy,
    mutation_deadline, verify_empty_nftables, verify_exact_forward_policy,
};
use crate::topology::namespaces::{
    AuthorizedActivatedTopology, AuthorizedDeletedTopology, AuthorizedEndpointRoutes,
    AuthorizedIpv4AddrgenNone, FixedEndpointRouteFailure, FixedEndpointRouteSetError,
    FixedEndpointRouteVisitError, FixedForwardPolicyBinding, FixedLinkActivationError,
    FixedLinkActivationFailure, FixedTopologyVisitError,
};
use crate::topology::{
    AuthorizedIpv4Addresses, AuthorizedNamespacePins, AuthorizedVethPairs,
    FixedIpv4AddressSetError, NamespaceEndpoint, NamespacePinError, NamespaceVisitError,
    VethPairError,
    ownership::{AuthorizedPrivateRun, AuthorizedPrivateRunError},
};

/// Exact byte ceiling for one kernel mount-table observation.
pub(crate) const MAX_PRIVATE_MOUNTINFO_BYTES: usize = 1024 * 1024;
/// Exact byte capacity of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_SIZE_BYTES: u64 = 16 * 1024 * 1024;
/// Exact inode capacity of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_INODES: u64 = 4096;
/// Exact root-directory mode of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_MODE: u32 = 0o700;

const MAX_PRIVATE_MOUNTINFO_RECORDS: usize = 4096;
const MAX_PROC_PROOF_BYTES: usize = 4096;
const MAX_IPV4_FORWARDING_RECORD_BYTES: usize = 2;
const DIRECTORY_BUFFER_BYTES: usize = 4096;
const TMPFS_SUPER_MAGIC: FsWord = 0x0102_1994;
const RUN_MOUNT_POINT: &[u8] = b"/run";
const PROC_MOUNT_POINT: &[u8] = b"/proc";
const IPV4_FORWARDING_RECORD_PATH: &str = "sys/net/ipv4/ip_forward";

/// Visible mount identities proven for the private runtime filesystems.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateMountIds {
    run_mount_id: u64,
    proc_mount_id: u64,
}

/// Failure of the fixed PID-1 private-mount setup or its kernel readback.
#[derive(Debug, Error)]
pub(crate) enum PrivateMountSetupError {
    /// An exact mount UAPI operation was denied by kernel policy.
    #[error("kernel policy denied private-mount operation {operation}: {source}")]
    PolicyDenied {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// A setup precondition, mount operation, or proof failed for any other reason.
    #[error("private-mount operation {operation} failed: {source}")]
    HardFailure {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl PrivateMountSetupError {
    /// Whether this error is the narrow EPERM/EACCES policy-denial outcome.
    pub(crate) const fn is_policy_denial(&self) -> bool {
        matches!(self, Self::PolicyDenied { .. })
    }
}

/// Failure while applying the full read-only network proof to both live pins.
#[derive(Debug, Error)]
pub(crate) enum NamespacePinsNetworkProofError {
    /// The mount typestate, namespace visit, or restoration proof failed.
    #[error("authorized namespace-pin mount proof failed: {0}")]
    Mount(#[source] PrivateMountSetupError),
    /// The existing composite pristine-network collector rejected one endpoint.
    #[error("authorized namespace pin is not pristine: {0}")]
    Network(#[source] crate::network::NetworkError),
}

/// Failure source retained alongside an affine mount/topology cleanup state.
#[derive(Debug, Error)]
pub(crate) enum PrivateMountLinkActivationError {
    /// The fixed low-level transition failed before its complete barrier.
    #[error("fixed link transition failed: {0}")]
    Activation(#[source] FixedLinkActivationError),
    /// Exact endpoint-route installation or retained route verification failed.
    #[error("fixed endpoint-route transition failed: {0}")]
    Route(#[source] FixedEndpointRouteSetError),
    /// The private mounts or their retained nsfs attachments failed reproof.
    #[error("fixed topology mount authority failed: {0}")]
    Mount(#[source] PrivateMountSetupError),
    /// The exact parent/A/B network barrier failed.
    #[error("fixed topology network barrier failed: {0}")]
    Proof(#[source] NamespacePinsNetworkProofError),
    /// The original transition failure is retained even when cleanup-authority
    /// mount reproof independently fails.
    #[error("{transition}; retained cleanup-authority reproof also failed: {cleanup}")]
    CleanupReproof {
        /// Original activation, route, mount, or network-proof failure.
        #[source]
        transition: Box<PrivateMountLinkActivationError>,
        /// Independent failure while re-proving the retained mount authority.
        cleanup: PrivateMountSetupError,
    },
}

/// Mount authority retained after a failed activation or route transition.
pub(crate) enum PrivateMountLinkFailureState {
    /// No request crossed the possibly-sent boundary and complete ordinary
    /// unwind was re-proven against the original private-mount baseline.
    Pristine(PrivateMounts<PristineRun>),
    /// SETLINK or NEWROUTE may have executed; B/A deletion is proven, but the
    /// external parent/A/B pristine proof must still authorize owner disarm.
    Deleted(Box<PrivateMounts<AuthorizedDeletedTopology>>),
}

/// Affine topology failure whose mount authority cannot be accidentally lost.
#[must_use = "failed topology transition retains cleanup-bearing private mounts"]
pub(crate) struct PrivateMountLinkActivationFailure {
    source: PrivateMountLinkActivationError,
    state: Box<PrivateMountLinkFailureState>,
}

impl std::fmt::Debug for PrivateMountLinkActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateMountLinkActivationFailure")
            .field("source", &self.source)
            .field(
                "state",
                &match self.state.as_ref() {
                    PrivateMountLinkFailureState::Pristine(_) => "pristine",
                    PrivateMountLinkFailureState::Deleted(_) => "deleted",
                },
            )
            .finish()
    }
}

impl std::fmt::Display for PrivateMountLinkActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for PrivateMountLinkActivationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl PrivateMountLinkActivationFailure {
    /// Recover both the failure and its mandatory affine cleanup state.
    pub(crate) fn into_parts(
        self,
    ) -> (
        PrivateMountLinkActivationError,
        PrivateMountLinkFailureState,
    ) {
        (self.source, *self.state)
    }

    fn pristine(
        source: PrivateMountLinkActivationError,
        mounts: PrivateMounts<PristineRun>,
    ) -> Self {
        Self {
            source,
            state: Box::new(PrivateMountLinkFailureState::Pristine(mounts)),
        }
    }

    fn deleted(
        source: PrivateMountLinkActivationError,
        mounts: PrivateMounts<AuthorizedDeletedTopology>,
    ) -> Self {
        Self {
            source,
            state: Box::new(PrivateMountLinkFailureState::Deleted(Box::new(mounts))),
        }
    }

    fn pristine_after_owned_cleanup(
        source: PrivateMountLinkActivationError,
        backing: PrivateMountBacking,
    ) -> Self {
        let mounts = backing.with_run_state(PristineRun);
        let source = match mounts.verify() {
            Ok(()) => source,
            Err(cleanup) => PrivateMountLinkActivationError::CleanupReproof {
                transition: Box::new(source),
                cleanup,
            },
        };
        Self::pristine(source, mounts)
    }

    fn deleted_after_retirement(
        source: PrivateMountLinkActivationError,
        backing: PrivateMountBacking,
        deleted: AuthorizedDeletedTopology,
    ) -> Self {
        let mounts = backing.with_run_state(deleted);
        let source = match mounts.verify_authorized_deleted_topology() {
            Ok(()) => source,
            Err(cleanup) => PrivateMountLinkActivationError::CleanupReproof {
                transition: Box::new(source),
                cleanup,
            },
        };
        Self::deleted(source, mounts)
    }

    fn from_fixed_failure(
        backing: PrivateMountBacking,
        failure: FixedLinkActivationFailure,
    ) -> Self {
        let (source, deleted) = failure.into_parts();
        let source = PrivateMountLinkActivationError::Activation(source);
        match deleted {
            Some(deleted) => Self::deleted_after_retirement(source, backing, deleted),
            None => Self::pristine_after_owned_cleanup(source, backing),
        }
    }

    fn from_fixed_route_failure(
        backing: PrivateMountBacking,
        failure: FixedEndpointRouteFailure,
    ) -> Self {
        let (source, deleted) = failure.into_parts();
        Self::deleted_after_retirement(
            PrivateMountLinkActivationError::Route(source),
            backing,
            deleted,
        )
    }
}

/// Failure source for the parent-namespace forward-policy lifecycle.
#[derive(Debug, Error)]
pub(crate) enum FixedForwardPolicyError {
    /// The exact nftables generation or fixed policy could not be established.
    #[error("fixed forward policy failed: {0}")]
    Nftables(#[source] NftablesError),
    /// A lower topology transition or its exact parent/A/B proof failed.
    #[error("fixed forward topology failed: {0}")]
    Topology(#[source] PrivateMountLinkActivationError),
    /// The final composite RTNL/proc/nftables lineage proof failed.
    #[error("fixed forward network lineage failed: {0}")]
    Network(#[source] PolicyNetworkError),
    /// The original failure is retained when cleanup-authority reproof also fails.
    #[error("{transition}; retained policy cleanup authority also failed: {cleanup}")]
    CleanupReproof {
        /// Original fixed-policy or topology failure.
        #[source]
        transition: Box<FixedForwardPolicyError>,
        /// Independent failure while re-proving retained mounts/topology.
        cleanup: PrivateMountSetupError,
    },
}

/// Generation-one authority retained after policy installation did not start.
#[must_use = "initial policy cleanup retains the only lower-owner retirement authority"]
pub(crate) struct InitialForwardPolicyCleanup {
    mounts: PrivateMounts<AuthorizedDeletedTopology>,
    rollback: PolicyRollbackProof,
    nftables: NftablesBaseline,
}

/// Armed authority retained when a possibly-sent nftables mutation cannot be classified.
#[must_use = "indeterminate policy cleanup must remain armed and fail closed"]
pub(crate) struct IndeterminateForwardPolicyCleanup {
    mounts: PrivateMounts<AuthorizedDeletedTopology>,
    rollback: PolicyRollbackProof,
    nftables: IndeterminateNftablesPolicy,
    binding: FixedForwardPolicyBinding,
}

/// Indeterminate policy authority after lower ordinary unwind already restored pristine mounts.
#[must_use = "indeterminate policy cleanup must remain armed and fail closed"]
pub(crate) struct IndeterminatePristineForwardPolicyCleanup {
    mounts: PrivateMounts<PristineRun>,
    rollback: PolicyRestoredNetworkProof,
    nftables: IndeterminateNftablesPolicy,
    binding: FixedForwardPolicyBinding,
}

/// Indeterminate policy deletion after forwarding was exactly restored.
#[must_use = "indeterminate policy cleanup must remain armed and fail closed"]
pub(crate) struct IndeterminateRestoredForwardPolicyCleanup {
    mounts: PrivateMounts<AuthorizedDeletedTopology>,
    rollback: PolicyRestoredNetworkProof,
    nftables: IndeterminateNftablesPolicy,
    binding: FixedForwardPolicyBinding,
}

/// Exact generation-two policy coupled to one topology and parent rollback lineage.
#[must_use = "an active policy-bound topology must be retired through its typed lifecycle"]
pub(crate) struct PolicyBoundPrivateMounts<RunState, NetworkAuthority = PolicyRollbackProof> {
    mounts: PrivateMounts<RunState>,
    policy: ActiveNftablesPolicy,
    rollback: NetworkAuthority,
    binding: FixedForwardPolicyBinding,
}

/// Recoverable authority after an all-NONE, activation, or route transition failed.
pub(crate) enum FixedForwardPolicyFailureState {
    /// Nothing was installed; B then A were deleted under the original empty ruleset.
    Initial(Box<InitialForwardPolicyCleanup>),
    /// Generation two is active, but forwarding was proven never enabled.
    InitialDeleted(Box<PolicyBoundPrivateMounts<AuthorizedDeletedTopology>>),
    /// The exact active policy remains armed over a deleted topology.
    ActiveDeleted(
        Box<PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof>>,
    ),
    /// Lower ordinary unwind completed before any link mutation, while policy retirement remains.
    ActivePristine(Box<PolicyBoundPrivateMounts<PristineRun, PolicyEnabledNetworkProof>>),
    /// A possibly-sent nftables transaction remains deliberately indeterminate and armed.
    Indeterminate(Box<IndeterminateForwardPolicyCleanup>),
}

/// Affine transition failure which always returns its cleanup authority.
#[must_use = "failed policy transition retains mandatory cleanup authority"]
pub(crate) struct FixedForwardPolicyFailure {
    source: FixedForwardPolicyError,
    state: FixedForwardPolicyFailureState,
}

impl std::fmt::Debug for FixedForwardPolicyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedForwardPolicyFailure")
            .field("source", &self.source)
            .field("state", &self.state.kind())
            .finish()
    }
}

impl std::fmt::Display for FixedForwardPolicyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for FixedForwardPolicyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl FixedForwardPolicyFailureState {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Initial(_) => "initial",
            Self::InitialDeleted(_) => "initial-deleted",
            Self::ActiveDeleted(_) => "active-deleted",
            Self::ActivePristine(_) => "active-pristine",
            Self::Indeterminate(cleanup) => {
                let _ = cleanup;
                "indeterminate"
            }
        }
    }
}

impl FixedForwardPolicyFailure {
    /// Recover both the bounded failure and every affine cleanup authority.
    pub(crate) fn into_parts(self) -> (FixedForwardPolicyError, FixedForwardPolicyFailureState) {
        (self.source, self.state)
    }

    fn initial(source: FixedForwardPolicyError, cleanup: InitialForwardPolicyCleanup) -> Self {
        Self {
            source,
            state: FixedForwardPolicyFailureState::Initial(Box::new(cleanup)),
        }
    }

    fn active_deleted(
        source: FixedForwardPolicyError,
        cleanup: PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof>,
    ) -> Self {
        Self {
            source,
            state: FixedForwardPolicyFailureState::ActiveDeleted(Box::new(cleanup)),
        }
    }

    fn initial_deleted(
        source: FixedForwardPolicyError,
        cleanup: PolicyBoundPrivateMounts<AuthorizedDeletedTopology>,
    ) -> Self {
        Self {
            source,
            state: FixedForwardPolicyFailureState::InitialDeleted(Box::new(cleanup)),
        }
    }

    fn active_pristine(
        source: FixedForwardPolicyError,
        cleanup: PolicyBoundPrivateMounts<PristineRun, PolicyEnabledNetworkProof>,
    ) -> Self {
        Self {
            source,
            state: FixedForwardPolicyFailureState::ActivePristine(Box::new(cleanup)),
        }
    }

    fn indeterminate(
        source: FixedForwardPolicyError,
        cleanup: IndeterminateForwardPolicyCleanup,
    ) -> Self {
        Self {
            source,
            state: FixedForwardPolicyFailureState::Indeterminate(Box::new(cleanup)),
        }
    }
}

enum RetiredParentNetworkAuthority {
    Pending(PolicyRestoredNetworkProof, SemanticallyEmptyNftables),
    Final(PolicyFinalNetworkProof),
}

/// Deleted topology retained after the exact policy table reached generation three.
#[must_use = "retired policy mounts still retain armed lower topology owners"]
pub(crate) struct RetiredForwardPolicyCleanup {
    mounts: PrivateMounts<AuthorizedDeletedTopology>,
    parent: RetiredParentNetworkAuthority,
    binding: FixedForwardPolicyBinding,
}

/// Pristine mount owner retained while generation-three parent proof is completed.
#[must_use = "retired policy lineage must be completed before ordinary mount reuse"]
pub(crate) struct RetiredPristineForwardPolicyCleanup {
    mounts: PrivateMounts<PristineRun>,
    parent: RetiredParentNetworkAuthority,
}

/// Authority returned by a recoverable deleted-topology teardown failure.
pub(crate) enum FixedForwardPolicyTeardownFailureState {
    /// Forwarding was proven unchanged but the Initial-to-Restored confirmation can be retried.
    Initial {
        /// Active deleted topology and exact generation-two policy authority.
        cleanup: Box<PolicyBoundPrivateMounts<AuthorizedDeletedTopology>>,
        /// Still-affine endpoint baseline observations.
        endpoints: Box<[EndpointNetworkBaseline; 2]>,
    },
    /// Generation two remains active and can be reverified and deleted again.
    Active {
        /// Active deleted topology and exact policy authority.
        cleanup:
            Box<PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof>>,
        /// Still-affine endpoint baseline observations.
        endpoints: Box<[EndpointNetworkBaseline; 2]>,
    },
    /// Forwarding is restored and generation two can be deleted without another sysctl write.
    Restored {
        /// Restored deleted topology and exact policy authority.
        cleanup:
            Box<PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyRestoredNetworkProof>>,
        /// Still-affine endpoint baseline observations.
        endpoints: Box<[EndpointNetworkBaseline; 2]>,
    },
    /// Generation three is semantic-empty; only final proof and owner retirement remain.
    Retired {
        /// Deleted topology plus pending or completed parent lineage proof.
        cleanup: Box<RetiredForwardPolicyCleanup>,
        /// Still-affine endpoint baseline observations.
        endpoints: Box<[EndpointNetworkBaseline; 2]>,
    },
    /// Policy deletion became indeterminate and therefore remains fail-closed armed.
    Indeterminate {
        /// Indeterminate deleted-topology cleanup authority.
        cleanup: Box<IndeterminateRestoredForwardPolicyCleanup>,
        /// Still-affine endpoint baseline observations.
        endpoints: Box<[EndpointNetworkBaseline; 2]>,
    },
    /// Lower ordinary unwind is pristine, but generation two is still active.
    ActivePristine(Box<PolicyBoundPrivateMounts<PristineRun, PolicyEnabledNetworkProof>>),
    /// Lower ordinary unwind is pristine and forwarding is already restored.
    RestoredPristine(Box<PolicyBoundPrivateMounts<PristineRun, PolicyRestoredNetworkProof>>),
    /// Lower ordinary unwind is pristine and generation three awaits final proof.
    RetiredPristine(Box<RetiredPristineForwardPolicyCleanup>),
    /// Lower ordinary unwind is pristine, but DELTABLE authority is indeterminate.
    IndeterminatePristine(Box<IndeterminatePristineForwardPolicyCleanup>),
}

/// Failure after topology deletion which returns policy and endpoint authority.
#[must_use = "failed policy teardown retains mandatory cleanup authority"]
pub(crate) struct FixedForwardPolicyTeardownFailure {
    source: FixedForwardPolicyError,
    state: FixedForwardPolicyTeardownFailureState,
}

impl std::fmt::Debug for FixedForwardPolicyTeardownFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.state {
            FixedForwardPolicyTeardownFailureState::Initial { .. } => "initial",
            FixedForwardPolicyTeardownFailureState::Active { .. } => "active",
            FixedForwardPolicyTeardownFailureState::Restored { .. } => "restored",
            FixedForwardPolicyTeardownFailureState::Retired { .. } => "retired",
            FixedForwardPolicyTeardownFailureState::Indeterminate { cleanup, endpoints } => {
                let _ = (cleanup, endpoints);
                "indeterminate"
            }
            FixedForwardPolicyTeardownFailureState::ActivePristine(_) => "active-pristine",
            FixedForwardPolicyTeardownFailureState::RestoredPristine(_) => "restored-pristine",
            FixedForwardPolicyTeardownFailureState::RetiredPristine(_) => "retired-pristine",
            FixedForwardPolicyTeardownFailureState::IndeterminatePristine(cleanup) => {
                let _ = cleanup;
                "indeterminate-pristine"
            }
        };
        formatter
            .debug_struct("FixedForwardPolicyTeardownFailure")
            .field("source", &self.source)
            .field("state", &kind)
            .finish()
    }
}

impl std::fmt::Display for FixedForwardPolicyTeardownFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for FixedForwardPolicyTeardownFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl FixedForwardPolicyTeardownFailure {
    /// Recover the error and every active, retired, or indeterminate authority.
    pub(crate) fn into_parts(
        self,
    ) -> (
        FixedForwardPolicyError,
        FixedForwardPolicyTeardownFailureState,
    ) {
        (self.source, self.state)
    }
}

impl IndeterminateForwardPolicyCleanup {
    /// Consume every opaque authority and deliberately terminate fail closed.
    pub(crate) fn abort_fail_closed(self) -> ! {
        let Self {
            mounts,
            rollback,
            nftables,
            binding,
        } = self;
        std::mem::forget((mounts, rollback, binding));
        drop(nftables);
        std::process::abort()
    }
}

impl IndeterminatePristineForwardPolicyCleanup {
    /// Consume every opaque authority and deliberately terminate fail closed.
    pub(crate) fn abort_fail_closed(self) -> ! {
        let Self {
            mounts,
            rollback,
            nftables,
            binding,
        } = self;
        std::mem::forget((mounts, rollback, binding));
        drop(nftables);
        std::process::abort()
    }
}

impl IndeterminateRestoredForwardPolicyCleanup {
    /// Consume every opaque authority and deliberately terminate fail closed.
    pub(crate) fn abort_fail_closed(self) -> ! {
        let Self {
            mounts,
            rollback,
            nftables,
            binding,
        } = self;
        std::mem::forget((mounts, rollback, binding));
        drop(nftables);
        std::process::abort()
    }
}

/// Exact addressed parent/A/B observations retained until reverse cleanup.
pub(crate) struct ExactIpv4AddressNetworkProof {
    parent: crate::network::ExactIpv4AddressParentObservation,
    endpoints: [crate::network::ExactIpv4AddressEndpointObservation; 2],
}

/// Exact addressed all-NONE parent/A/B observations retained until activation.
pub(crate) struct ExactIpv4AddrgenNoneNetworkProof {
    parent: crate::network::ExactIpv4AddrgenNoneParentObservation,
    endpoints: [crate::network::ExactIpv4AddrgenNoneEndpointObservation; 2],
}

trait Ipv4AddrgenNoneParentProof {
    fn observe_exact_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        pairs: [&crate::network::ExpectedVethPair; 2],
        addresses: [&crate::network::ExpectedIpv4Address; 2],
    ) -> Result<crate::network::ExactIpv4AddrgenNoneParentObservation, PolicyNetworkError>;
}

impl Ipv4AddrgenNoneParentProof for PolicyRollbackProof {
    fn observe_exact_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        pairs: [&crate::network::ExpectedVethPair; 2],
        addresses: [&crate::network::ExpectedIpv4Address; 2],
    ) -> Result<crate::network::ExactIpv4AddrgenNoneParentObservation, PolicyNetworkError> {
        self.observe_exact_ipv4_addrgen_none_parent(mounts, pairs, addresses)
    }
}

impl Ipv4AddrgenNoneParentProof for PolicyEnabledNetworkProof {
    fn observe_exact_parent<RunState>(
        &self,
        mounts: &PrivateMounts<RunState>,
        pairs: [&crate::network::ExpectedVethPair; 2],
        addresses: [&crate::network::ExpectedIpv4Address; 2],
    ) -> Result<crate::network::ExactIpv4AddrgenNoneParentObservation, PolicyNetworkError> {
        self.observe_exact_ipv4_addrgen_none_parent(mounts, pairs, addresses)
    }
}

/// Exact parent/A/B observations retained after all four links became active.
pub(crate) struct ExactActivatedIpv4NetworkProof {
    parent: crate::network::ExactActivatedIpv4ParentObservation,
    endpoints: [crate::network::ExactActivatedIpv4EndpointObservation; 2],
}

/// Exact unchanged-parent and one-route-per-endpoint observations.
pub(crate) struct ExactIpv4EndpointRouteNetworkProof {
    parent: crate::network::ExactIpv4EndpointRouteParentObservation,
    endpoints: [crate::network::ExactIpv4EndpointRouteEndpointObservation; 2],
}

struct ExactIpv4AddressExpectations {
    pairs: [crate::network::ExpectedVethPair; 2],
    addresses: [crate::network::ExpectedIpv4Address; 4],
}

/// Affine owner of the exact private mounts installed by namespace PID 1.
///
/// The retained root and visible mount descriptors pin the measured objects.
/// Reverification reopens both fixed paths below the pinned root and requires
/// their visible mount IDs to remain unchanged. The state parameter enforces
/// the affine transition from an empty private `/run` through the bounded
/// post-`GO` root-and-slot and two-pin transaction and back to the pristine
/// state.
pub(crate) struct PrivateMounts<RunState = PristineRun> {
    root: OwnedFd,
    run_pin: OwnedFd,
    proc_pin: OwnedFd,
    root_mount_id: u64,
    ids: PrivateMountIds,
    baseline_mountinfo: Vec<u8>,
    run_state: RunState,
}

struct PrivateMountBacking {
    root: OwnedFd,
    run_pin: OwnedFd,
    proc_pin: OwnedFd,
    root_mount_id: u64,
    ids: PrivateMountIds,
    baseline_mountinfo: Vec<u8>,
}

/// Affine proof minted only by this higher mount/network layer after the
/// retained parent and both endpoint baselines were re-proven pristine.
///
/// The lower topology layer must consume this unforgeable safe-Rust token
/// before it can disarm any address or pair owner.
#[must_use = "the pristine-network proof must authorize lower-owner retirement"]
pub(crate) struct PristineNetworkRetirementProof {
    _private: (),
}

impl PrivateMountBacking {
    fn with_run_state<RunState>(self, run_state: RunState) -> PrivateMounts<RunState> {
        PrivateMounts {
            root: self.root,
            run_pin: self.run_pin,
            proc_pin: self.proc_pin,
            root_mount_id: self.root_mount_id,
            ids: self.ids,
            baseline_mountinfo: self.baseline_mountinfo,
            run_state,
        }
    }
}

/// Type-level proof that the private `/run` directory was observed empty.
pub(crate) struct PristineRun;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcRecordIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount_id: u64,
}

/// The only two canonical values accepted by the fixed IPv4-forwarding writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ipv4ForwardingState {
    /// Kernel IPv4 forwarding is disabled (`0\n`).
    Disabled,
    /// Kernel IPv4 forwarding is enabled (`1\n`).
    Enabled,
}

impl Ipv4ForwardingState {
    const fn bytes(self) -> &'static [u8; MAX_IPV4_FORWARDING_RECORD_BYTES] {
        match self {
            Self::Disabled => b"0\n",
            Self::Enabled => b"1\n",
        }
    }
}

/// Opaque observation of the fixed namespace-local IPv4-forwarding record.
///
/// Equality binds both the bounded exact bytes and the procfs object identity
/// observed through the retained private-proc descriptor. No descriptor or
/// write capability leaves the mount owner.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Ipv4ForwardingRecordSnapshot {
    bytes: Vec<u8>,
    identity: ProcRecordIdentity,
}

impl Ipv4ForwardingRecordSnapshot {
    /// Construct one identity-stable canonical fixture for cross-module drop-guard tests.
    #[cfg(test)]
    pub(crate) fn synthetic_for_drop_guard(state: Ipv4ForwardingState) -> Self {
        Self {
            bytes: state.bytes().to_vec(),
            identity: ProcRecordIdentity {
                device_major: 0,
                device_minor: 1,
                inode: 2,
                mount_id: 3,
            },
        }
    }

    /// Return the bounded raw kernel record for canonical parsing by the network proof.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Classify this exact record without accepting any non-canonical spelling.
    pub(crate) fn canonical_state(&self) -> Option<Ipv4ForwardingState> {
        match self.bytes.as_slice() {
            b"0\n" => Some(Ipv4ForwardingState::Disabled),
            b"1\n" => Some(Ipv4ForwardingState::Enabled),
            _ => None,
        }
    }

    /// Whether two bounded observations refer to the same pinned procfs record.
    pub(crate) fn has_same_identity(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

/// Exact pre/post evidence returned by one fixed IPv4-forwarding transition.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the IPv4-forwarding mutation evidence must be retained"]
pub(crate) struct Ipv4ForwardingMutation {
    before: Ipv4ForwardingRecordSnapshot,
    after: Ipv4ForwardingRecordSnapshot,
    previous: Ipv4ForwardingState,
    target: Ipv4ForwardingState,
    write_was_requested: bool,
}

impl Ipv4ForwardingMutation {
    /// Exact snapshot matched immediately before the possible write boundary.
    #[cfg(test)]
    pub(crate) fn before(&self) -> &Ipv4ForwardingRecordSnapshot {
        &self.before
    }

    /// Exact snapshot observed after the no-op or completed write.
    #[cfg(test)]
    pub(crate) fn after(&self) -> &Ipv4ForwardingRecordSnapshot {
        &self.after
    }

    /// Canonical value established by the matched pre-mutation snapshot.
    #[cfg(test)]
    pub(crate) const fn previous(&self) -> Ipv4ForwardingState {
        self.previous
    }

    /// Canonical value freshly re-proven after the transition.
    #[cfg(test)]
    pub(crate) const fn target(&self) -> Ipv4ForwardingState {
        self.target
    }

    /// Whether the target differed and exactly one write syscall was requested.
    #[cfg(test)]
    pub(crate) const fn write_was_requested(&self) -> bool {
        self.write_was_requested
    }

    /// Consume the evidence into its exact snapshots and fixed transition metadata.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Ipv4ForwardingRecordSnapshot,
        Ipv4ForwardingRecordSnapshot,
        Ipv4ForwardingState,
        Ipv4ForwardingState,
        bool,
    ) {
        (
            self.before,
            self.after,
            self.previous,
            self.target,
            self.write_was_requested,
        )
    }
}

/// Phase and retained context for a failed fixed IPv4-forwarding transition.
#[derive(Debug)]
pub(crate) enum Ipv4ForwardingMutationFailureState {
    /// No write syscall was requested, so ordinary affine unwind remains sound.
    BeforeRequest,
    /// One write syscall was requested; fresh reconciliation is mandatory.
    PossiblyWritten {
        /// Exact observed snapshot which matched the caller's expected baseline.
        before: Ipv4ForwardingRecordSnapshot,
        /// Canonical value of the matched snapshot.
        previous: Ipv4ForwardingState,
        /// Canonical value supplied to the one bounded write request.
        target: Ipv4ForwardingState,
    },
}

/// Failure which preserves whether the kernel may have processed a write.
#[derive(Debug)]
#[must_use = "failed IPv4-forwarding mutation retains its request phase and recovery context"]
pub(crate) struct Ipv4ForwardingMutationFailure {
    source: PrivateMountSetupError,
    state: Ipv4ForwardingMutationFailureState,
}

impl std::fmt::Display for Ipv4ForwardingMutationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state {
            Ipv4ForwardingMutationFailureState::BeforeRequest => {
                write!(
                    formatter,
                    "IPv4-forwarding mutation failed before its write request: {}",
                    self.source
                )
            }
            Ipv4ForwardingMutationFailureState::PossiblyWritten { .. } => {
                write!(
                    formatter,
                    "IPv4-forwarding mutation may have reached the kernel: {}",
                    self.source
                )
            }
        }
    }
}

impl std::error::Error for Ipv4ForwardingMutationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Ipv4ForwardingMutationFailure {
    /// Recover the bounded failure source and its exact mutation phase/context.
    pub(crate) fn into_parts(self) -> (PrivateMountSetupError, Ipv4ForwardingMutationFailureState) {
        (self.source, self.state)
    }

    fn before_request(source: PrivateMountSetupError) -> Self {
        Self {
            source,
            state: Ipv4ForwardingMutationFailureState::BeforeRequest,
        }
    }

    fn possibly_written(
        source: PrivateMountSetupError,
        before: Ipv4ForwardingRecordSnapshot,
        previous: Ipv4ForwardingState,
        target: Ipv4ForwardingState,
    ) -> Self {
        Self {
            source,
            state: Ipv4ForwardingMutationFailureState::PossiblyWritten {
                before,
                previous,
                target,
            },
        }
    }
}

impl PrivateMounts<PristineRun> {
    /// Repeat the complete local mount-table and procfs proof.
    pub(crate) fn verify(&self) -> Result<(), PrivateMountSetupError> {
        self.verify_mounts(true)
    }

    /// Consume one pristine mount owner and the affine `GO` authorization to
    /// create exactly one run-bound private directory transaction.
    pub(crate) fn authorize_private_run(
        self,
        authorization: MutationAuthorization,
    ) -> Result<PrivateMounts<AuthorizedPrivateRun>, PrivateMountSetupError> {
        self.verify()?;
        let state = AuthorizedPrivateRun::stage(&self.run_pin, authorization)
            .map_err(|source| private_run_error("create authorized private-run roots", source))?;
        let authorized = self.with_run_state(state);
        authorized.verify_authorized_private_run()?;
        Ok(authorized)
    }
}

impl PrivateMounts<AuthorizedPrivateRun> {
    /// Reprove the private mounts and the exact post-authorization run layout.
    pub(crate) fn verify_authorized_private_run(&self) -> Result<(), PrivateMountSetupError> {
        self.verify_mounts(false)?;
        self.run_state
            .verify()
            .map_err(|source| private_run_error("verify authorized private-run roots", source))
    }

    /// Consume the authorized empty slots and attach exactly two live network
    /// namespaces while retaining the private-run ownership transaction.
    pub(crate) fn pin_network_namespaces(
        self,
    ) -> Result<PrivateMounts<AuthorizedNamespacePins>, PrivateMountSetupError> {
        self.verify_authorized_private_run()?;
        let PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        let run_state = run_state
            .pin_network_namespaces()
            .map_err(|source| namespace_pin_error("pin authorized network namespaces", source))?;
        let pinned = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        };
        pinned.verify_authorized_namespace_pins()?;
        pinned
            .run_state
            .prove_reverse_visit_restoration_after_visitor_error()
            .map_err(|source| {
                namespace_pin_error("prove reverse namespace visitor restoration", source)
            })?;
        pinned.verify_authorized_namespace_pins()?;
        Ok(pinned)
    }

    /// Consume the authorized state, drop its internal token, reverse every
    /// owned creation, and return an exactly pristine mount owner.
    pub(crate) fn rollback_private_run(
        self,
    ) -> Result<PrivateMounts<PristineRun>, PrivateMountSetupError> {
        let PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        run_state.rollback().map_err(|source| {
            private_run_error("roll back authorized private-run roots", source)
        })?;
        let pristine = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state: PristineRun,
        };
        pristine.verify()?;
        Ok(pristine)
    }
}

impl PrivateMounts<AuthorizedNamespacePins> {
    /// Reprove the private mounts, the unchanged baseline mount records, and
    /// exactly two live run-bound nsfs attachments.
    pub(crate) fn verify_authorized_namespace_pins(&self) -> Result<(), PrivateMountSetupError> {
        self.run_state.verify().map_err(|source| {
            namespace_pin_error("verify authorized network namespace pins", source)
        })?;
        let mountinfo = self.observe_visible_private_mounts(false)?;
        verify_authorized_namespace_mountinfo(
            &self.baseline_mountinfo,
            &mountinfo,
            self.ids,
            self.run_state.mount_ids(),
            self.run_state.mount_point_bytes(),
        )
        .map_err(|source| hard_error("verify authorized nsfs mount table", source))?;
        self.run_state.verify().map_err(|source| {
            namespace_pin_error("reverify authorized network namespace pins", source)
        })
    }

    /// Visit A then B and retain their exact pristine composite observations.
    pub(crate) fn observe_pristine_network_namespace_pins(
        &self,
    ) -> Result<
        [crate::network::PristineNetworkNamespaceObservation; 2],
        NamespacePinsNetworkProofError,
    > {
        self.verify_authorized_namespace_pins()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let mut observations = [None, None];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = match endpoint {
                    NamespaceEndpoint::A => 0,
                    NamespaceEndpoint::B => 1,
                };
                if observations[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                observations[index] = Some(
                    crate::network::observe_current_pristine_network_namespace(self)?,
                );
                Ok(())
            })
            .map_err(|error| match error {
                NamespaceVisitError::Namespace(source) => NamespacePinsNetworkProofError::Mount(
                    namespace_pin_error("visit authorized network namespace", source),
                ),
                NamespaceVisitError::Visitor(source) => {
                    NamespacePinsNetworkProofError::Network(source)
                }
            })?;
        self.verify_authorized_namespace_pins()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let [Some(alpha), Some(omega)] = observations else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        Ok([alpha, omega])
    }

    /// Reprove both pristine pins, then atomically create the fixed A/B veth pairs.
    pub(crate) fn create_fixed_veth_pairs(
        self,
    ) -> Result<
        (
            PrivateMounts<AuthorizedVethPairs>,
            [crate::network::PristineNetworkNamespaceObservation; 2],
        ),
        NamespacePinsNetworkProofError,
    > {
        let endpoint_baselines = self.observe_pristine_network_namespace_pins()?;
        let PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        let run_state = run_state.create_fixed_veth_pairs().map_err(|source| {
            NamespacePinsNetworkProofError::Mount(veth_pair_error(
                "create fixed veth pairs",
                source,
            ))
        })?;
        let active = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        };
        active
            .verify_authorized_veth_pairs()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        Ok((active, endpoint_baselines))
    }

    /// Detach both owned nsfs mounts in reverse order, prove that their mount
    /// IDs and path records disappeared, and recover the unchanged authorized
    /// private-run state.
    pub(crate) fn rollback_namespace_pins(
        self,
    ) -> Result<PrivateMounts<AuthorizedPrivateRun>, PrivateMountSetupError> {
        self.verify_authorized_namespace_pins()?;
        let expected_mount_ids = self.run_state.mount_ids();
        let mount_point_bytes = self.run_state.mount_point_bytes();
        let expected_mount_points = [mount_point_bytes[0].to_vec(), mount_point_bytes[1].to_vec()];
        let PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        let run_state = run_state.rollback().map_err(|source| {
            namespace_pin_error("roll back authorized network namespace pins", source)
        })?;
        let authorized = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        };
        let mountinfo = authorized.observe_visible_private_mounts(false)?;
        verify_namespace_mountinfo_rollback(
            &authorized.baseline_mountinfo,
            &mountinfo,
            authorized.ids,
            expected_mount_ids,
            [&expected_mount_points[0], &expected_mount_points[1]],
        )
        .map_err(|source| hard_error("verify reversed nsfs mount table", source))?;
        authorized.verify_authorized_private_run()?;
        Ok(authorized)
    }
}

impl PrivateMounts<AuthorizedVethPairs> {
    /// Reprove private mounts, both live nsfs pins, and both retained veth pairs.
    pub(crate) fn verify_authorized_veth_pairs(&self) -> Result<(), PrivateMountSetupError> {
        self.verify_veth_backed_state(&self.run_state)
    }

    /// Consume both veth pairs into one owned four-address transaction.
    pub(crate) fn configure_fixed_ipv4_addresses(
        self,
    ) -> Result<PrivateMounts<AuthorizedIpv4Addresses>, PrivateMountSetupError> {
        self.verify_authorized_veth_pairs()?;
        let PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        let run_state = run_state
            .configure_fixed_ipv4_addresses()
            .map_err(|source| ipv4_address_set_error("configure fixed IPv4 addresses", source))?;
        let addressed = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        };
        addressed.verify_authorized_ipv4_addresses()?;
        Ok(addressed)
    }

    /// Prove the exact parent/A/B link deltas and reobserve all three active states.
    pub(crate) fn prove_exact_veth_pairs(
        &self,
        parent_baseline: &crate::network::MutationRollbackNetworkProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<(), NamespacePinsNetworkProofError> {
        self.verify_authorized_veth_pairs()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let pairs = self.run_state.fixed_pairs();
        let expectations = [
            crate::network::ExpectedVethPair::new(
                pairs[0].parent_name(),
                pairs[0].parent_ifindex(),
                pairs[0].peer_ifindex(),
                pairs[0].target_namespace_identity(),
            )
            .map_err(NamespacePinsNetworkProofError::Network)?,
            crate::network::ExpectedVethPair::new(
                pairs[1].parent_name(),
                pairs[1].parent_ifindex(),
                pairs[1].peer_ifindex(),
                pairs[1].target_namespace_identity(),
            )
            .map_err(NamespacePinsNetworkProofError::Network)?,
        ];
        let parent_observation = parent_baseline
            .observe_exact_veth_parent(self, [&expectations[0], &expectations[1]])
            .map_err(NamespacePinsNetworkProofError::Network)?;
        let mut endpoint_observations = [None, None];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = match endpoint {
                    NamespaceEndpoint::A => 0,
                    NamespaceEndpoint::B => 1,
                };
                if endpoint_observations[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                endpoint_observations[index] = Some(
                    endpoint_baselines[index]
                        .observe_exact_veth_endpoint(self, &expectations[index])?,
                );
                Ok(())
            })
            .map_err(|error| map_veth_visit_error("observe exact endpoint veth delta", error))?;
        let [Some(alpha), Some(omega)] = &endpoint_observations else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        crate::network::verify_exact_veth_pair_observations(&parent_observation, [alpha, omega])
            .map_err(NamespacePinsNetworkProofError::Network)?;
        parent_observation
            .verify(self)
            .map_err(NamespacePinsNetworkProofError::Network)?;

        let mut reverified = [false, false];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = match endpoint {
                    NamespaceEndpoint::A => 0,
                    NamespaceEndpoint::B => 1,
                };
                if reverified[index] {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                endpoint_observations[index]
                    .as_ref()
                    .ok_or(crate::network::NetworkError::Inconsistent)?
                    .verify(self)?;
                reverified[index] = true;
                Ok(())
            })
            .map_err(|error| map_veth_visit_error("reverify exact endpoint veth delta", error))?;
        if reverified != [true, true] {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        }
        self.verify_authorized_veth_pairs()
            .map_err(NamespacePinsNetworkProofError::Mount)
    }
}

impl PrivateMounts<AuthorizedIpv4Addresses> {
    /// Reprove the owned address set, its veth backing, and both live nsfs pins.
    pub(crate) fn verify_authorized_ipv4_addresses(&self) -> Result<(), PrivateMountSetupError> {
        self.run_state.verify().map_err(|source| {
            ipv4_address_set_error("verify configured fixed IPv4 addresses", source)
        })?;
        self.verify_veth_backed_state(self.run_state.veth_pairs())
    }

    /// Prove the exact parent/A/B delta for all four addressed down-veth ends.
    pub(crate) fn prove_exact_ipv4_addresses(
        &self,
        parent_baseline: &crate::network::MutationRollbackNetworkProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<ExactIpv4AddressNetworkProof, NamespacePinsNetworkProofError> {
        self.verify_veth_backed_state(self.run_state.veth_pairs())
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        self.run_state.verify().map_err(|source| {
            NamespacePinsNetworkProofError::Mount(ipv4_address_set_error(
                "verify fixed IPv4 address owners before observation",
                source,
            ))
        })?;

        let expectations = exact_ipv4_address_expectations(&self.run_state)
            .map_err(NamespacePinsNetworkProofError::Network)?;

        let parent_observation = parent_baseline
            .observe_exact_ipv4_address_parent(
                self,
                [&expectations.pairs[0], &expectations.pairs[1]],
                [&expectations.addresses[0], &expectations.addresses[2]],
            )
            .map_err(NamespacePinsNetworkProofError::Network)?;
        let endpoint_address_expectations =
            [&expectations.addresses[1], &expectations.addresses[3]];
        let mut endpoint_observations = [None, None];
        self.run_state
            .veth_pairs()
            .visit_network_namespaces(|endpoint| {
                let index = match endpoint {
                    NamespaceEndpoint::A => 0,
                    NamespaceEndpoint::B => 1,
                };
                if endpoint_observations[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                endpoint_observations[index] = Some(
                    endpoint_baselines[index].observe_exact_ipv4_address_endpoint(
                        self,
                        &expectations.pairs[index],
                        endpoint_address_expectations[index],
                    )?,
                );
                Ok(())
            })
            .map_err(|error| map_veth_visit_error("observe exact endpoint IPv4 delta", error))?;
        let [Some(alpha), Some(omega)] = &endpoint_observations else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        crate::network::verify_exact_ipv4_address_observations(&parent_observation, [alpha, omega])
            .map_err(NamespacePinsNetworkProofError::Network)?;

        let proof = ExactIpv4AddressNetworkProof {
            parent: parent_observation,
            endpoints: [
                endpoint_observations[0]
                    .take()
                    .unwrap_or_else(|| std::process::abort()),
                endpoint_observations[1]
                    .take()
                    .unwrap_or_else(|| std::process::abort()),
            ],
        };
        self.verify_exact_ipv4_address_state(&proof)?;
        Ok(proof)
    }

    /// Reobserve the exact active addressed state without changing ownership.
    pub(crate) fn verify_exact_ipv4_address_state(
        &self,
        proof: &ExactIpv4AddressNetworkProof,
    ) -> Result<(), NamespacePinsNetworkProofError> {
        self.verify_veth_backed_state(self.run_state.veth_pairs())
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        self.run_state.verify().map_err(|source| {
            NamespacePinsNetworkProofError::Mount(ipv4_address_set_error(
                "reverify fixed IPv4 address owners",
                source,
            ))
        })?;
        proof
            .parent
            .verify(self)
            .map_err(NamespacePinsNetworkProofError::Network)?;
        let mut reverified = [false, false];
        self.run_state
            .veth_pairs()
            .visit_network_namespaces(|endpoint| {
                let index = match endpoint {
                    NamespaceEndpoint::A => 0,
                    NamespaceEndpoint::B => 1,
                };
                if reverified[index] {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                proof.endpoints[index].verify(self)?;
                reverified[index] = true;
                Ok(())
            })
            .map_err(|error| map_veth_visit_error("reverify exact endpoint IPv4 delta", error))?;
        if reverified != [true, true] {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        }
        crate::network::verify_exact_ipv4_address_observations(
            &proof.parent,
            [&proof.endpoints[0], &proof.endpoints[1]],
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        proof
            .parent
            .verify(self)
            .map_err(NamespacePinsNetworkProofError::Network)?;
        self.run_state.verify().map_err(|source| {
            NamespacePinsNetworkProofError::Mount(ipv4_address_set_error(
                "final reverify of fixed IPv4 address owners",
                source,
            ))
        })?;
        self.verify_veth_backed_state(self.run_state.veth_pairs())
            .map_err(NamespacePinsNetworkProofError::Mount)
    }
}

impl PrivateMounts<AuthorizedIpv4AddrgenNone> {
    /// Reprove the all-NONE owner, both live nsfs attachments, and their exact
    /// visible mount-table records without invoking the obsolete DOWN/EUI64
    /// veth parser.
    pub(crate) fn verify_authorized_ipv4_addrgen_none(&self) -> Result<(), PrivateMountSetupError> {
        self.run_state
            .verify()
            .map_err(|source| fixed_link_error("verify all-NONE fixed link authority", source))?;
        self.verify_namespace_backed_mountinfo(
            self.run_state.mount_ids(),
            self.run_state.mount_point_bytes(),
            "verify all-NONE nsfs mount table",
        )?;
        self.run_state
            .verify()
            .map_err(|source| fixed_link_error("reverify all-NONE fixed link authority", source))
    }

    /// Observe the exact addressed all-NONE parent/A/B barrier and bind every
    /// observation to the retained topology and mounts.
    fn prove_exact_ipv4_addrgen_none<ParentProof>(
        &self,
        parent_baseline: &ParentProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<ExactIpv4AddrgenNoneNetworkProof, NamespacePinsNetworkProofError>
    where
        ParentProof: Ipv4AddrgenNoneParentProof,
    {
        self.verify_authorized_ipv4_addrgen_none()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let expectations = exact_ipv4_address_expectations_from(
            self.run_state.fixed_pairs(),
            self.run_state.owners(),
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        let parent = self
            .run_state
            .visit_parent_network_namespace(|| {
                parent_baseline.observe_exact_parent(
                    self,
                    [&expectations.pairs[0], &expectations.pairs[1]],
                    [&expectations.addresses[0], &expectations.addresses[2]],
                )
            })
            .map_err(|error| {
                map_topology_visit_error("observe exact all-NONE parent state", error)
            })?;
        let endpoint_addresses = [&expectations.addresses[1], &expectations.addresses[3]];
        let mut endpoints = [None, None];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if endpoints[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                endpoints[index] = Some(
                    endpoint_baselines[index].observe_exact_ipv4_addrgen_none_endpoint(
                        self,
                        &expectations.pairs[index],
                        endpoint_addresses[index],
                    )?,
                );
                Ok(())
            })
            .map_err(|error| {
                map_topology_visit_error("observe exact all-NONE endpoint state", error)
            })?;
        let [Some(alpha), Some(omega)] = endpoints else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        let proof = ExactIpv4AddrgenNoneNetworkProof {
            parent,
            endpoints: [alpha, omega],
        };
        self.verify_exact_ipv4_addrgen_none_state(&proof)?;
        Ok(proof)
    }

    /// Reobserve the exact all-NONE barrier before any link-UP request.
    fn verify_exact_ipv4_addrgen_none_state(
        &self,
        proof: &ExactIpv4AddrgenNoneNetworkProof,
    ) -> Result<(), NamespacePinsNetworkProofError> {
        self.verify_authorized_ipv4_addrgen_none()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        self.run_state
            .visit_parent_network_namespace(|| proof.parent.verify(self))
            .map_err(|error| {
                map_topology_visit_error("reprove exact all-NONE parent state", error)
            })?;
        let mut visited = [false, false];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if visited[index] {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                proof.endpoints[index].verify(self)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(|error| {
                map_topology_visit_error("reprove exact all-NONE endpoint state", error)
            })?;
        require_complete_endpoint_visit(visited)?;
        crate::network::verify_exact_ipv4_addrgen_none_observations(
            &proof.parent,
            [&proof.endpoints[0], &proof.endpoints[1]],
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        self.verify_authorized_ipv4_addrgen_none()
            .map_err(NamespacePinsNetworkProofError::Mount)
    }
}

impl PolicyBoundPrivateMounts<AuthorizedIpv4AddrgenNone> {
    /// Enable the fixed parent forwarding record only behind the exact policy.
    ///
    /// The pre-enable all-NONE proof is consumed because its parent proc
    /// observation is no longer current. Success returns a freshly observed
    /// all-NONE proof bound to the enabled-record authority.
    pub(crate) fn enable_ipv4_forwarding(
        self,
        none_proof: ExactIpv4AddrgenNoneNetworkProof,
        endpoint_baselines: &[EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PolicyBoundPrivateMounts<AuthorizedIpv4AddrgenNone, PolicyEnabledNetworkProof>,
            ExactIpv4AddrgenNoneNetworkProof,
        ),
        FixedForwardPolicyFailure,
    > {
        if let Err(source) = self.verify_active_policy() {
            return Err(self.into_initial_deleted_failure(source));
        }
        if let Err(source) = self
            .mounts
            .verify_exact_ipv4_addrgen_none_state(&none_proof)
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Proof(source))
            })
        {
            return Err(self.into_initial_deleted_failure(source));
        }
        drop(none_proof);

        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let rollback = match rollback.enable_ipv4_forwarding(&mounts, &policy) {
            Ok(rollback) => rollback,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                let source = FixedForwardPolicyError::Network(source);
                return match authority {
                    PolicyForwardingEnableFailureState::Initial(rollback) => {
                        let initial = PolicyBoundPrivateMounts {
                            mounts,
                            policy,
                            rollback,
                            binding,
                        };
                        Err(initial.into_initial_deleted_failure(source))
                    }
                    PolicyForwardingEnableFailureState::Enabled(rollback) => {
                        let enabled = PolicyBoundPrivateMounts {
                            mounts,
                            policy,
                            rollback,
                            binding,
                        };
                        Err(enabled.into_deleted_failure(source))
                    }
                    PolicyForwardingEnableFailureState::Indeterminate(authority) => {
                        authority.abort_fail_closed()
                    }
                };
            }
        };
        let enabled = PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        };
        if let Err(source) = enabled.verify_active_policy() {
            return Err(enabled.into_deleted_failure(source));
        }
        match enabled
            .mounts
            .prove_exact_ipv4_addrgen_none(&enabled.rollback, endpoint_baselines)
        {
            Ok(proof) => Ok((enabled, proof)),
            Err(source) => Err(
                enabled.into_deleted_failure(FixedForwardPolicyError::Topology(
                    PrivateMountLinkActivationError::Proof(source),
                )),
            ),
        }
    }

    fn into_initial_deleted_failure(
        self,
        source: FixedForwardPolicyError,
    ) -> FixedForwardPolicyFailure {
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let (backing, all_none) = mounts.into_backing_and_run_state();
        let mounts = backing.with_run_state(all_none.begin_retirement());
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::initial_deleted(
            source,
            PolicyBoundPrivateMounts {
                mounts,
                policy,
                rollback,
                binding,
            },
        )
    }
}

impl PolicyBoundPrivateMounts<AuthorizedIpv4AddrgenNone, PolicyEnabledNetworkProof> {
    /// Consume the all-NONE proof and activate all four ends only while the
    /// exact generation-two policy remains freshly observed before and after.
    pub(crate) fn activate_links(
        self,
        none_proof: ExactIpv4AddrgenNoneNetworkProof,
        endpoint_baselines: &[EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PolicyBoundPrivateMounts<AuthorizedActivatedTopology, PolicyEnabledNetworkProof>,
            ExactActivatedIpv4NetworkProof,
        ),
        FixedForwardPolicyFailure,
    > {
        if let Err(source) = self.verify_active_policy() {
            return Err(self.into_deleted_failure(source));
        }
        if let Err(source) = self
            .mounts
            .verify_exact_ipv4_addrgen_none_state(&none_proof)
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Proof(source))
            })
        {
            return Err(self.into_deleted_failure(source));
        }

        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let (mounts, active_proof) =
            match mounts.activate_links_without_policy(none_proof, &rollback, endpoint_baselines) {
                Ok(result) => result,
                Err(failure) => {
                    return Err(policy_failure_from_topology(
                        failure, policy, rollback, binding,
                    ));
                }
            };
        let active = PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        };
        if let Err(source) = active.verify_active_policy() {
            return Err(active.into_deleted_failure(source));
        }
        Ok((active, active_proof))
    }

    fn into_deleted_failure(self, source: FixedForwardPolicyError) -> FixedForwardPolicyFailure {
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let (backing, all_none) = mounts.into_backing_and_run_state();
        let mounts = backing.with_run_state(all_none.begin_retirement());
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::active_deleted(
            source,
            PolicyBoundPrivateMounts {
                mounts,
                policy,
                rollback,
                binding,
            },
        )
    }
}

impl PrivateMounts<AuthorizedActivatedTopology> {
    /// Reprove the all-UP owner, both nsfs attachments, and their exact visible
    /// mount-table records without invoking any lower rollback parser.
    pub(crate) fn verify_authorized_activated_topology(
        &self,
    ) -> Result<(), PrivateMountSetupError> {
        self.run_state
            .verify()
            .map_err(|source| fixed_link_error("verify activated fixed topology", source))?;
        self.verify_namespace_backed_mountinfo(
            self.run_state.mount_ids(),
            self.run_state.mount_point_bytes(),
            "verify activated nsfs mount table",
        )?;
        self.run_state
            .verify()
            .map_err(|source| fixed_link_error("reverify activated fixed topology", source))
    }

    fn prove_exact_activated_ipv4(
        &self,
        parent_baseline: &PolicyEnabledNetworkProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<ExactActivatedIpv4NetworkProof, NamespacePinsNetworkProofError> {
        self.verify_authorized_activated_topology()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let expectations = exact_ipv4_address_expectations_from(
            self.run_state.fixed_pairs(),
            self.run_state.owners(),
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        let parent = self
            .run_state
            .visit_parent_network_namespace(|| {
                parent_baseline.observe_exact_activated_ipv4_parent(
                    self,
                    [&expectations.pairs[0], &expectations.pairs[1]],
                    [&expectations.addresses[0], &expectations.addresses[2]],
                )
            })
            .map_err(|error| {
                map_topology_visit_error("observe exact activated parent state", error)
            })?;
        let endpoint_addresses = [&expectations.addresses[1], &expectations.addresses[3]];
        let mut endpoints = [None, None];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if endpoints[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                endpoints[index] = Some(
                    endpoint_baselines[index].observe_exact_activated_ipv4_endpoint(
                        self,
                        &expectations.pairs[index],
                        endpoint_addresses[index],
                    )?,
                );
                Ok(())
            })
            .map_err(|error| {
                map_topology_visit_error("observe exact activated endpoint state", error)
            })?;
        let [Some(alpha), Some(omega)] = endpoints else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        let proof = ExactActivatedIpv4NetworkProof {
            parent,
            endpoints: [alpha, omega],
        };
        self.verify_exact_activated_ipv4_state(&proof)?;
        Ok(proof)
    }

    fn verify_exact_activated_ipv4_state(
        &self,
        proof: &ExactActivatedIpv4NetworkProof,
    ) -> Result<(), NamespacePinsNetworkProofError> {
        self.verify_authorized_activated_topology()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        self.run_state
            .visit_parent_network_namespace(|| proof.parent.verify(self))
            .map_err(|error| {
                map_topology_visit_error("reprove exact activated parent state", error)
            })?;
        let mut visited = [false, false];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if visited[index] {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                proof.endpoints[index].verify(self)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(|error| {
                map_topology_visit_error("reprove exact activated endpoint state", error)
            })?;
        require_complete_endpoint_visit(visited)?;
        crate::network::verify_exact_activated_ipv4_observations(
            &proof.parent,
            [&proof.endpoints[0], &proof.endpoints[1]],
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        self.verify_authorized_activated_topology()
            .map_err(NamespacePinsNetworkProofError::Mount)
    }
}

impl PrivateMounts<AuthorizedDeletedTopology> {
    /// Reprove the retained nsfs mount authority after raw B/A pair deletion.
    /// No address, veth, DOWN, or EUI64 readback is permitted in this state.
    pub(crate) fn verify_authorized_deleted_topology(&self) -> Result<(), PrivateMountSetupError> {
        verify_deleted_pair_identities(&self.run_state.fixed_pair_identities())?;
        self.run_state
            .visit_parent_network_namespace(|| Ok::<(), Infallible>(()))
            .map_err(|error| {
                map_infallible_topology_visit_error(
                    "verify deleted topology parent namespace",
                    error,
                )
            })?;
        self.verify_namespace_backed_mountinfo(
            self.run_state.mount_ids(),
            self.run_state.mount_point_bytes(),
            "verify deleted-topology nsfs mount table",
        )?;
        self.run_state
            .visit_network_namespaces(|_| Ok::<(), Infallible>(()))
            .map_err(|error| {
                map_infallible_topology_visit_error(
                    "verify deleted topology endpoint namespaces",
                    error,
                )
            })?;
        self.run_state
            .visit_parent_network_namespace(|| Ok::<(), Infallible>(()))
            .map_err(|error| {
                map_infallible_topology_visit_error(
                    "reverify deleted topology parent namespace",
                    error,
                )
            })
    }

    /// Consume the external pristine parent/A/B proof before disarming every
    /// retained route, address, and pair owner and returning ordinary
    /// namespace-pin authority.
    ///
    /// Any failure before the proof token is minted remains intentionally
    /// terminal: dropping the still-armed deleted topology aborts fail-closed.
    /// The returned error path begins only after infallible owner retirement,
    /// when the recovered namespace-pin mount authority is reverified.
    pub(crate) fn finish_after_initial_network_proof(
        self,
        parent_baseline: PolicyRollbackProof,
        nftables: NftablesBaseline,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<PrivateMounts<AuthorizedNamespacePins>, PrivateMountSetupError> {
        self.verify_authorized_deleted_topology()?;
        self.run_state
            .visit_parent_network_namespace(|| {
                parent_baseline.verify_pristine_with_initial_nftables(&self, &nftables)
            })
            .map_err(|error| {
                topology_network_visit_error(
                    "verify deleted topology pristine generation-one parent state",
                    error,
                )
            })?;

        let mut visited = [false, false];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if visited[index] {
                    return Err(PolicyNetworkError::Inconsistent);
                }
                endpoint_baselines[index].verify_pristine_state(&self)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(|error| {
                topology_network_visit_error(
                    "preverify deleted topology pristine endpoint states",
                    error,
                )
            })?;
        if visited != [true, true] {
            return Err(network_proof_setup_error(
                "preverify deleted topology pristine endpoint visit",
                PolicyNetworkError::Inconsistent,
            ));
        }

        let mut endpoint_baselines = endpoint_baselines.map(Some);
        self.run_state
            .visit_network_namespaces(|endpoint| {
                endpoint_baselines[endpoint_index(endpoint)]
                    .take()
                    .ok_or(crate::network::NetworkError::Inconsistent)?
                    .verify_pristine_rollback(&self)
            })
            .map_err(|error| {
                topology_network_visit_error(
                    "verify deleted topology pristine endpoint states",
                    error,
                )
            })?;
        if endpoint_baselines.iter().any(Option::is_some) {
            return Err(network_proof_setup_error(
                "verify deleted topology pristine endpoint visit",
                crate::network::NetworkError::Inconsistent,
            ));
        }

        self.run_state
            .visit_parent_network_namespace(|| {
                parent_baseline.verify_pristine_with_initial_nftables(&self, &nftables)
            })
            .map_err(|error| {
                topology_network_visit_error(
                    "reverify deleted topology pristine generation-one parent state",
                    error,
                )
            })?;
        self.verify_authorized_deleted_topology()?;
        drop((parent_baseline, nftables));
        let proof = PristineNetworkRetirementProof { _private: () };
        let (backing, deleted) = self.into_backing_and_run_state();
        let pins = deleted.finish_after_pristine_network_proof(proof);
        let mounts = backing.with_run_state(pins);
        mounts.verify_authorized_namespace_pins()?;
        Ok(mounts)
    }
}

impl PrivateMounts<AuthorizedIpv4Addresses> {
    /// Consume the exact addressed-DOWN state into the four-end all-NONE
    /// barrier. Every possible SETLINK path returns either an exact all-NONE
    /// proof or deletion-only cleanup authority.
    pub(crate) fn disable_ipv6_address_generation(
        self,
        parent_baseline: &crate::network::MutationRollbackNetworkProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedIpv4AddrgenNone>,
            ExactIpv4AddrgenNoneNetworkProof,
        ),
        PrivateMountLinkActivationFailure,
    > {
        if let Err(source) = self.prove_exact_ipv4_addresses(parent_baseline, endpoint_baselines) {
            let (backing, addressed) = self.into_backing_and_run_state();
            drop(addressed);
            return Err(
                PrivateMountLinkActivationFailure::pristine_after_owned_cleanup(
                    PrivateMountLinkActivationError::Proof(source),
                    backing,
                ),
            );
        }

        let (backing, addressed) = self.into_backing_and_run_state();
        let all_none = match addressed.disable_ipv6_address_generation() {
            Ok(all_none) => all_none,
            Err(failure) => {
                return Err(PrivateMountLinkActivationFailure::from_fixed_failure(
                    backing, failure,
                ));
            }
        };
        let mounts = backing.with_run_state(all_none);
        if let Err(source) = mounts.verify_authorized_ipv4_addrgen_none() {
            return Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Mount(source)));
        }
        match mounts.prove_exact_ipv4_addrgen_none(parent_baseline, endpoint_baselines) {
            Ok(proof) => Ok((mounts, proof)),
            Err(source) => {
                Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Proof(source)))
            }
        }
    }
}

impl PrivateMounts<AuthorizedIpv4AddrgenNone> {
    /// Install and prove the sole exact parent FORWARD drop policy while all
    /// four fixed veth ends remain freshly proven down with addrgenmode NONE.
    pub(crate) fn install_fixed_forward_policy(
        self,
        none_proof: &ExactIpv4AddrgenNoneNetworkProof,
        rollback: PolicyRollbackProof,
        initial: NftablesBaseline,
    ) -> Result<PolicyBoundPrivateMounts<AuthorizedIpv4AddrgenNone>, FixedForwardPolicyFailure>
    {
        if let Err(source) = self.verify_exact_ipv4_addrgen_none_state(none_proof) {
            return Err(self.into_initial_policy_failure(
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Proof(source)),
                rollback,
                initial,
            ));
        }
        let binding = match self.run_state.fixed_forward_policy_binding() {
            Ok(binding) => binding,
            Err(source) => {
                return Err(self.into_initial_policy_failure(
                    FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Activation(
                        source,
                    )),
                    rollback,
                    initial,
                ));
            }
        };
        let parent_ifindices = binding.parent_ifindices();
        let retained_parent_ifindices = binding
            .pair_identities()
            .each_ref()
            .map(crate::topology::namespaces::DeletedVethPairIdentity::parent_ifindex);
        if retained_parent_ifindices != parent_ifindices {
            return Err(self.into_initial_policy_failure(
                policy_binding_error(),
                rollback,
                initial,
            ));
        }
        let expectation = match FixedForwardPolicyExpectation::from_binding(&binding) {
            Ok(expectation) => expectation,
            Err(source) => {
                return Err(self.into_initial_policy_failure(
                    FixedForwardPolicyError::Nftables(source),
                    rollback,
                    initial,
                ));
            }
        };
        let deadline = match mutation_deadline() {
            Ok(deadline) => deadline,
            Err(source) => {
                return Err(self.into_initial_policy_failure(
                    FixedForwardPolicyError::Nftables(source),
                    rollback,
                    initial,
                ));
            }
        };
        if let Err(source) = verify_empty_nftables(&initial, deadline) {
            return Err(self.into_initial_policy_failure(
                FixedForwardPolicyError::Nftables(source),
                rollback,
                initial,
            ));
        }
        let policy = match install_exact_forward_policy(initial, expectation, deadline) {
            Ok(policy) => policy,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                return match authority {
                    NftablesInstallAuthority::Initial(initial, expectation) => {
                        // A fresh generation-one readback proves that the
                        // transaction did not install anything. The returned
                        // expectation carries no cleanup authority; the
                        // independently retained topology binding remains
                        // canonical for any later attempt.
                        drop(expectation);
                        Err(self.into_initial_policy_failure(
                            FixedForwardPolicyError::Nftables(source),
                            rollback,
                            initial,
                        ))
                    }
                    NftablesInstallAuthority::Indeterminate(nftables) => Err(self
                        .into_indeterminate_policy_failure(
                            FixedForwardPolicyError::Nftables(source),
                            rollback,
                            nftables,
                            binding,
                        )),
                };
            }
        };
        let mounts =
            Self::finish_policy_install_reproof(self, none_proof, policy, rollback, binding)?;
        Ok(mounts)
    }

    fn finish_policy_install_reproof(
        self,
        none_proof: &ExactIpv4AddrgenNoneNetworkProof,
        policy: ActiveNftablesPolicy,
        rollback: PolicyRollbackProof,
        binding: FixedForwardPolicyBinding,
    ) -> Result<PolicyBoundPrivateMounts<AuthorizedIpv4AddrgenNone>, FixedForwardPolicyFailure>
    {
        let cleanup = PolicyBoundPrivateMounts {
            mounts: self,
            policy,
            rollback,
            binding,
        };
        if let Err(source) = cleanup.verify_active_policy() {
            return Err(cleanup.into_initial_deleted_failure(source));
        }
        if let Err(source) = cleanup
            .mounts
            .verify_exact_ipv4_addrgen_none_state(none_proof)
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Proof(source))
            })
        {
            return Err(cleanup.into_initial_deleted_failure(source));
        }
        match cleanup.mounts.run_state.fixed_forward_policy_binding() {
            Ok(observed) if observed == cleanup.binding => Ok(cleanup),
            Ok(_) => Err(cleanup.into_initial_deleted_failure(policy_binding_error())),
            Err(source) => Err(cleanup.into_initial_deleted_failure(
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Activation(
                    source,
                )),
            )),
        }
    }

    fn into_initial_policy_failure(
        self,
        source: FixedForwardPolicyError,
        rollback: PolicyRollbackProof,
        nftables: NftablesBaseline,
    ) -> FixedForwardPolicyFailure {
        let (backing, all_none) = self.into_backing_and_run_state();
        let mounts = backing.with_run_state(all_none.begin_retirement());
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::initial(
            source,
            InitialForwardPolicyCleanup {
                mounts,
                rollback,
                nftables,
            },
        )
    }

    fn into_indeterminate_policy_failure(
        self,
        source: FixedForwardPolicyError,
        rollback: PolicyRollbackProof,
        nftables: IndeterminateNftablesPolicy,
        binding: FixedForwardPolicyBinding,
    ) -> FixedForwardPolicyFailure {
        let (backing, all_none) = self.into_backing_and_run_state();
        let mounts = backing.with_run_state(all_none.begin_retirement());
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::indeterminate(
            source,
            IndeterminateForwardPolicyCleanup {
                mounts,
                rollback,
                nftables,
                binding,
            },
        )
    }

    /// Consume the exact all-NONE proof into four link-UP operations and an
    /// exact active parent/A/B barrier.
    fn activate_links_without_policy(
        self,
        none_proof: ExactIpv4AddrgenNoneNetworkProof,
        parent_baseline: &PolicyEnabledNetworkProof,
        endpoint_baselines: &[crate::network::PristineNetworkNamespaceObservation; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedActivatedTopology>,
            ExactActivatedIpv4NetworkProof,
        ),
        PrivateMountLinkActivationFailure,
    > {
        if let Err(source) = self.verify_exact_ipv4_addrgen_none_state(&none_proof) {
            return Err(self.into_deleted_failure(PrivateMountLinkActivationError::Proof(source)));
        }
        drop(none_proof);
        let (backing, all_none) = self.into_backing_and_run_state();
        let activated = match all_none.activate_links() {
            Ok(activated) => activated,
            Err(failure) => {
                return Err(PrivateMountLinkActivationFailure::from_fixed_failure(
                    backing, failure,
                ));
            }
        };
        let mounts = backing.with_run_state(activated);
        if let Err(source) = mounts.verify_authorized_activated_topology() {
            return Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Mount(source)));
        }
        match mounts.prove_exact_activated_ipv4(parent_baseline, endpoint_baselines) {
            Ok(proof) => Ok((mounts, proof)),
            Err(source) => {
                Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Proof(source)))
            }
        }
    }

    fn into_deleted_failure(
        self,
        source: PrivateMountLinkActivationError,
    ) -> PrivateMountLinkActivationFailure {
        let (backing, all_none) = self.into_backing_and_run_state();
        PrivateMountLinkActivationFailure::deleted_after_retirement(
            source,
            backing,
            all_none.begin_retirement(),
        )
    }
}

impl PrivateMounts<AuthorizedActivatedTopology> {
    /// Consume the exact active observations, install route A then B, and
    /// independently prove an unchanged parent plus one exact route in each
    /// retained endpoint namespace.
    fn install_endpoint_routes_without_policy(
        self,
        active_proof: ExactActivatedIpv4NetworkProof,
    ) -> Result<
        (
            PrivateMounts<AuthorizedEndpointRoutes>,
            ExactIpv4EndpointRouteNetworkProof,
        ),
        PrivateMountLinkActivationFailure,
    > {
        if let Err(source) = self.verify_exact_activated_ipv4_state(&active_proof) {
            return Err(self.into_deleted_failure(PrivateMountLinkActivationError::Proof(source)));
        }
        let [alpha, omega] = active_proof.endpoints.each_ref().map(
            crate::network::ExactActivatedIpv4EndpointObservation::expected_ipv4_endpoint_route,
        );
        let alpha = match alpha {
            Ok(expectation) => expectation,
            Err(source) => {
                return Err(
                    self.into_deleted_failure(PrivateMountLinkActivationError::Proof(
                        NamespacePinsNetworkProofError::Network(source),
                    )),
                );
            }
        };
        let omega = match omega {
            Ok(expectation) => expectation,
            Err(source) => {
                return Err(
                    self.into_deleted_failure(PrivateMountLinkActivationError::Proof(
                        NamespacePinsNetworkProofError::Network(source),
                    )),
                );
            }
        };
        let route_expectations = [alpha, omega];

        let (backing, activated) = self.into_backing_and_run_state();
        let routed = match activated.install_endpoint_routes() {
            Ok(routed) => routed,
            Err(failure) => {
                return Err(PrivateMountLinkActivationFailure::from_fixed_route_failure(
                    backing, failure,
                ));
            }
        };
        let mounts = backing.with_run_state(routed);
        if let Err(source) = mounts.verify_authorized_endpoint_routes() {
            return Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Mount(source)));
        }
        match mounts.prove_exact_ipv4_endpoint_routes(active_proof, &route_expectations) {
            Ok(proof) => Ok((mounts, proof)),
            Err(source) => {
                Err(mounts.into_deleted_failure(PrivateMountLinkActivationError::Proof(source)))
            }
        }
    }

    fn into_deleted_failure(
        self,
        source: PrivateMountLinkActivationError,
    ) -> PrivateMountLinkActivationFailure {
        let (backing, activated) = self.into_backing_and_run_state();
        PrivateMountLinkActivationFailure::deleted_after_retirement(
            source,
            backing,
            activated.begin_retirement(),
        )
    }
}

impl PolicyBoundPrivateMounts<AuthorizedActivatedTopology, PolicyEnabledNetworkProof> {
    /// Install the fixed A then B endpoint routes while generation two stays exact.
    pub(crate) fn install_endpoint_routes(
        self,
        active_proof: ExactActivatedIpv4NetworkProof,
    ) -> Result<
        (
            PolicyBoundPrivateMounts<AuthorizedEndpointRoutes, PolicyEnabledNetworkProof>,
            ExactIpv4EndpointRouteNetworkProof,
        ),
        FixedForwardPolicyFailure,
    > {
        if let Err(source) = self.verify_active_policy() {
            return Err(self.into_deleted_failure(source));
        }
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let (mounts, routed_proof) =
            match mounts.install_endpoint_routes_without_policy(active_proof) {
                Ok(result) => result,
                Err(failure) => {
                    return Err(policy_failure_from_topology(
                        failure, policy, rollback, binding,
                    ));
                }
            };
        let routed = PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        };
        if let Err(source) = routed.verify_active_policy() {
            return Err(routed.into_deleted_failure(source));
        }
        Ok((routed, routed_proof))
    }

    fn into_deleted_failure(self, source: FixedForwardPolicyError) -> FixedForwardPolicyFailure {
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let (backing, activated) = mounts.into_backing_and_run_state();
        let mounts = backing.with_run_state(activated.begin_retirement());
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::active_deleted(
            source,
            PolicyBoundPrivateMounts {
                mounts,
                policy,
                rollback,
                binding,
            },
        )
    }
}

impl PrivateMounts<AuthorizedEndpointRoutes> {
    /// Reprove the routed owner, both nsfs attachments, and their exact visible
    /// mount-table records without invoking any rollback parser.
    pub(crate) fn verify_authorized_endpoint_routes(&self) -> Result<(), PrivateMountSetupError> {
        self.run_state
            .verify()
            .map_err(|source| fixed_route_error("verify authorized endpoint routes", source))?;
        self.verify_namespace_backed_mountinfo(
            self.run_state.mount_ids(),
            self.run_state.mount_point_bytes(),
            "verify routed-topology nsfs mount table",
        )?;
        self.run_state
            .verify()
            .map_err(|source| fixed_route_error("reverify authorized endpoint routes", source))
    }

    /// Reobserve the exact unchanged parent and both routed endpoint states.
    pub(crate) fn verify_exact_ipv4_endpoint_route_state(
        &self,
        proof: &ExactIpv4EndpointRouteNetworkProof,
    ) -> Result<(), NamespacePinsNetworkProofError> {
        self.verify_authorized_endpoint_routes()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        self.run_state
            .visit_parent_network_namespace(|| proof.parent.verify(self))
            .map_err(|error| {
                map_endpoint_route_visit_error("reprove exact routed parent state", error)
            })?;
        let mut visited = [false, false];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if visited[index] {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                proof.endpoints[index].verify(self)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(|error| {
                map_endpoint_route_visit_error("reprove exact routed endpoint state", error)
            })?;
        require_complete_endpoint_visit(visited)?;
        crate::network::verify_exact_ipv4_endpoint_route_observations(
            &proof.parent,
            [&proof.endpoints[0], &proof.endpoints[1]],
        )
        .map_err(NamespacePinsNetworkProofError::Network)?;
        self.verify_authorized_endpoint_routes()
            .map_err(NamespacePinsNetworkProofError::Mount)
    }

    fn prove_exact_ipv4_endpoint_routes(
        &self,
        active_proof: ExactActivatedIpv4NetworkProof,
        expectations: &[crate::network::ExpectedIpv4EndpointRoute; 2],
    ) -> Result<ExactIpv4EndpointRouteNetworkProof, NamespacePinsNetworkProofError> {
        self.verify_authorized_endpoint_routes()
            .map_err(NamespacePinsNetworkProofError::Mount)?;
        let ExactActivatedIpv4NetworkProof { parent, endpoints } = active_proof;
        let parent = self
            .run_state
            .visit_parent_network_namespace(|| {
                parent.observe_exact_ipv4_endpoint_route_parent(self)
            })
            .map_err(|error| {
                map_endpoint_route_visit_error("observe exact routed parent state", error)
            })?;
        let mut active_endpoints = endpoints.map(Some);
        let mut routed_endpoints = [None, None];
        self.run_state
            .visit_network_namespaces(|endpoint| {
                let index = endpoint_index(endpoint);
                if routed_endpoints[index].is_some() {
                    return Err(crate::network::NetworkError::Inconsistent);
                }
                let active = active_endpoints[index]
                    .take()
                    .ok_or(crate::network::NetworkError::Inconsistent)?;
                routed_endpoints[index] = Some(
                    active
                        .observe_exact_ipv4_endpoint_route_endpoint(self, &expectations[index])?,
                );
                Ok(())
            })
            .map_err(|error| {
                map_endpoint_route_visit_error("observe exact routed endpoint state", error)
            })?;
        if active_endpoints.iter().any(Option::is_some) {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        }
        let [Some(alpha), Some(omega)] = routed_endpoints else {
            return Err(NamespacePinsNetworkProofError::Network(
                crate::network::NetworkError::Inconsistent,
            ));
        };
        let proof = ExactIpv4EndpointRouteNetworkProof {
            parent,
            endpoints: [alpha, omega],
        };
        self.verify_exact_ipv4_endpoint_route_state(&proof)?;
        Ok(proof)
    }

    /// Directly delete pair B then A and retain route/address/pair authorities
    /// until the existing pristine parent/A/B proof authorizes retirement.
    fn begin_retirement_without_policy(self) -> PrivateMounts<AuthorizedDeletedTopology> {
        let (backing, routed) = self.into_backing_and_run_state();
        let mounts = backing.with_run_state(routed.begin_retirement());
        if mounts.verify_authorized_deleted_topology().is_err() {
            std::process::abort();
        }
        mounts
    }

    fn into_deleted_failure(
        self,
        source: PrivateMountLinkActivationError,
    ) -> PrivateMountLinkActivationFailure {
        let (backing, routed) = self.into_backing_and_run_state();
        PrivateMountLinkActivationFailure::deleted_after_retirement(
            source,
            backing,
            routed.begin_retirement(),
        )
    }
}

impl PolicyBoundPrivateMounts<AuthorizedEndpointRoutes, PolicyEnabledNetworkProof> {
    /// Consume the routed proof, delete pair B then A while the exact policy
    /// stays armed, and return only deleted-topology generation-two authority.
    pub(crate) fn begin_retirement(
        self,
        routed_proof: ExactIpv4EndpointRouteNetworkProof,
    ) -> Result<
        PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof>,
        FixedForwardPolicyFailure,
    > {
        if let Err(source) = self.verify_active_policy() {
            return Err(self.into_deleted_failure(source));
        }
        if let Err(source) = self
            .mounts
            .verify_exact_ipv4_endpoint_route_state(&routed_proof)
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Proof(source))
            })
        {
            return Err(self.into_deleted_failure(source));
        }
        drop(routed_proof);

        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let mounts = mounts.begin_retirement_without_policy();
        let deleted = PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        };
        match deleted.verify_deleted_active_policy_state() {
            Ok(()) => Ok(deleted),
            Err(source) => Err(FixedForwardPolicyFailure::active_deleted(source, deleted)),
        }
    }

    fn into_deleted_failure(self, source: FixedForwardPolicyError) -> FixedForwardPolicyFailure {
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let mounts = mounts.begin_retirement_without_policy();
        let source =
            retain_policy_cleanup_reproof(source, mounts.verify_authorized_deleted_topology());
        FixedForwardPolicyFailure::active_deleted(
            source,
            PolicyBoundPrivateMounts {
                mounts,
                policy,
                rollback,
                binding,
            },
        )
    }
}

impl<NetworkAuthority> PolicyBoundPrivateMounts<AuthorizedDeletedTopology, NetworkAuthority> {
    fn verify_deleted_active_policy_state(&self) -> Result<(), FixedForwardPolicyError> {
        self.mounts
            .verify_authorized_deleted_topology()
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
            })?;
        let observed = self
            .mounts
            .run_state
            .fixed_forward_policy_binding()
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(
                    namespace_pin_error("verify deleted forward-policy binding", source),
                ))
            })?;
        if observed != self.binding {
            return Err(policy_binding_error());
        }
        self.verify_active_policy()?;
        self.mounts
            .verify_authorized_deleted_topology()
            .map_err(|source| {
                FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
            })
    }
}

impl PolicyBoundPrivateMounts<AuthorizedDeletedTopology> {
    /// Confirm that a failed enable never changed the forwarding record, then
    /// continue teardown from the explicit Restored authority.
    pub(crate) fn finish_initial_forward_policy_teardown(
        self,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedNamespacePins>,
            PolicyFinalNetworkProof,
        ),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.verify_deleted_active_policy_state() {
            return Err(initial_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }
        if let Err(source) = verify_deleted_endpoint_baselines(&self.mounts, &endpoint_baselines) {
            return Err(initial_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let rollback = match rollback.confirm_ipv4_forwarding_unmodified(&mounts, &policy) {
            Ok(rollback) => rollback,
            Err(failure) => {
                let (source, rollback) = failure.into_parts();
                return Err(initial_deleted_teardown_failure(
                    FixedForwardPolicyError::Network(source),
                    PolicyBoundPrivateMounts {
                        mounts,
                        policy,
                        rollback,
                        binding,
                    },
                    endpoint_baselines,
                ));
            }
        };
        PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        }
        .finish_restored_forward_policy_teardown(endpoint_baselines)
    }
}

impl PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof> {
    fn verify_generation_two_pristine_barrier(
        &self,
        endpoint_baselines: &[EndpointNetworkBaseline; 2],
    ) -> Result<(), FixedForwardPolicyError> {
        self.verify_deleted_active_policy_state()?;
        self.mounts
            .run_state
            .visit_parent_network_namespace(|| {
                self.rollback
                    .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            })
            .map_err(|error| {
                fixed_policy_network_visit_error(
                    "verify deleted topology pristine generation-two parent state",
                    error,
                )
            })?;

        verify_deleted_endpoint_baselines(&self.mounts, endpoint_baselines)?;

        self.mounts
            .run_state
            .visit_parent_network_namespace(|| {
                self.rollback
                    .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            })
            .map_err(|error| {
                fixed_policy_network_visit_error(
                    "reverify deleted topology pristine generation-two parent state",
                    error,
                )
            })?;
        self.verify_deleted_active_policy_state()
    }

    /// Prove the forwarding-enabled parent and endpoints pristine, then restore
    /// the exact inherited forwarding record while generation two stays active.
    pub(crate) fn finish_forward_policy_teardown(
        self,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedNamespacePins>,
            PolicyFinalNetworkProof,
        ),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.verify_generation_two_pristine_barrier(&endpoint_baselines) {
            return Err(active_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let rollback = match rollback.restore_ipv4_forwarding(&mounts, &policy) {
            Ok(rollback) => rollback,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                let source = FixedForwardPolicyError::Network(source);
                return match authority {
                    PolicyForwardingRestoreFailureState::Enabled(rollback) => {
                        Err(active_deleted_teardown_failure(
                            source,
                            PolicyBoundPrivateMounts {
                                mounts,
                                policy,
                                rollback,
                                binding,
                            },
                            endpoint_baselines,
                        ))
                    }
                    PolicyForwardingRestoreFailureState::Restored(rollback) => {
                        Err(restored_deleted_teardown_failure(
                            source,
                            PolicyBoundPrivateMounts {
                                mounts,
                                policy,
                                rollback,
                                binding,
                            },
                            endpoint_baselines,
                        ))
                    }
                    PolicyForwardingRestoreFailureState::Indeterminate(authority) => {
                        authority.abort_fail_closed()
                    }
                };
            }
        };
        PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        }
        .finish_restored_forward_policy_teardown(endpoint_baselines)
    }
}

impl PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyRestoredNetworkProof> {
    fn verify_generation_two_pristine_barrier(
        &self,
        endpoint_baselines: &[EndpointNetworkBaseline; 2],
    ) -> Result<(), FixedForwardPolicyError> {
        self.verify_deleted_active_policy_state()?;
        self.mounts
            .run_state
            .visit_parent_network_namespace(|| {
                self.rollback
                    .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            })
            .map_err(|error| {
                fixed_policy_network_visit_error(
                    "verify restored generation-two parent state",
                    error,
                )
            })?;
        verify_deleted_endpoint_baselines(&self.mounts, endpoint_baselines)?;
        self.mounts
            .run_state
            .visit_parent_network_namespace(|| {
                self.rollback
                    .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            })
            .map_err(|error| {
                fixed_policy_network_visit_error(
                    "reverify restored generation-two parent state",
                    error,
                )
            })?;
        self.verify_deleted_active_policy_state()
    }

    /// Delete only the observed policy after exact forwarding restoration,
    /// then prove generation three and retire every lower owner.
    pub(crate) fn finish_restored_forward_policy_teardown(
        self,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedNamespacePins>,
            PolicyFinalNetworkProof,
        ),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.verify_generation_two_pristine_barrier(&endpoint_baselines) {
            return Err(restored_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }
        let deadline = match mutation_deadline() {
            Ok(deadline) => deadline,
            Err(source) => {
                return Err(restored_deleted_teardown_failure(
                    FixedForwardPolicyError::Nftables(source),
                    self,
                    endpoint_baselines,
                ));
            }
        };
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let nftables = match delete_exact_forward_policy(policy, deadline) {
            Ok(nftables) => nftables,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                return match authority {
                    NftablesDeleteAuthority::Active(policy) => {
                        Err(restored_deleted_teardown_failure(
                            FixedForwardPolicyError::Nftables(source),
                            PolicyBoundPrivateMounts {
                                mounts,
                                policy,
                                rollback,
                                binding,
                            },
                            endpoint_baselines,
                        ))
                    }
                    NftablesDeleteAuthority::Indeterminate(nftables) => {
                        Err(indeterminate_deleted_teardown_failure(
                            FixedForwardPolicyError::Nftables(source),
                            IndeterminateRestoredForwardPolicyCleanup {
                                mounts,
                                rollback,
                                nftables,
                                binding,
                            },
                            endpoint_baselines,
                        ))
                    }
                };
            }
        };
        RetiredForwardPolicyCleanup {
            mounts,
            parent: RetiredParentNetworkAuthority::Pending(rollback, nftables),
            binding,
        }
        .finish(endpoint_baselines)
    }
}

impl InitialForwardPolicyCleanup {
    /// Consume generation-one parent/endpoint proofs and retire all lower owners.
    pub(crate) fn finish(
        self,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<PrivateMounts<AuthorizedNamespacePins>, PrivateMountSetupError> {
        self.mounts.finish_after_initial_network_proof(
            self.rollback,
            self.nftables,
            endpoint_baselines,
        )
    }
}

impl RetiredForwardPolicyCleanup {
    /// Retry the generation-three proof, then consume endpoint observations and
    /// disarm lower route/address/pair owners only after every final reproof.
    pub(crate) fn finish(
        self,
        endpoint_baselines: [EndpointNetworkBaseline; 2],
    ) -> Result<
        (
            PrivateMounts<AuthorizedNamespacePins>,
            PolicyFinalNetworkProof,
        ),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = verify_retired_deleted_state(&self) {
            return Err(retired_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }
        if let Err(source) = verify_deleted_endpoint_baselines(&self.mounts, &endpoint_baselines) {
            return Err(retired_deleted_teardown_failure(
                source,
                self,
                endpoint_baselines,
            ));
        }

        let Self {
            mounts,
            parent,
            binding,
        } = self;
        let final_proof = match parent {
            RetiredParentNetworkAuthority::Pending(rollback, nftables) => {
                match rollback.finish_after_semantically_empty(&mounts, nftables) {
                    Ok(final_proof) => final_proof,
                    Err(failure) => {
                        let (source, authority) = failure.into_parts();
                        let (rollback, nftables) = *authority;
                        return Err(retired_deleted_teardown_failure(
                            FixedForwardPolicyError::Network(source),
                            RetiredForwardPolicyCleanup {
                                mounts,
                                parent: RetiredParentNetworkAuthority::Pending(rollback, nftables),
                                binding,
                            },
                            endpoint_baselines,
                        ));
                    }
                }
            }
            RetiredParentNetworkAuthority::Final(final_proof) => final_proof,
        };

        if let Err(source) = verify_final_parent_state(&mounts, &final_proof) {
            return Err(retired_deleted_teardown_failure(
                source,
                RetiredForwardPolicyCleanup {
                    mounts,
                    parent: RetiredParentNetworkAuthority::Final(final_proof),
                    binding,
                },
                endpoint_baselines,
            ));
        }
        if let Err(source) = verify_deleted_endpoint_baselines(&mounts, &endpoint_baselines) {
            return Err(retired_deleted_teardown_failure(
                source,
                RetiredForwardPolicyCleanup {
                    mounts,
                    parent: RetiredParentNetworkAuthority::Final(final_proof),
                    binding,
                },
                endpoint_baselines,
            ));
        }

        consume_deleted_endpoint_baselines_or_abort(&mounts, endpoint_baselines);
        if verify_final_parent_state(&mounts, &final_proof).is_err()
            || mounts.verify_authorized_deleted_topology().is_err()
        {
            std::process::abort();
        }
        let proof = PristineNetworkRetirementProof { _private: () };
        let (backing, deleted) = mounts.into_backing_and_run_state();
        let pins = deleted.finish_after_pristine_network_proof(proof);
        let mounts = backing.with_run_state(pins);
        if mounts.verify_authorized_namespace_pins().is_err() {
            std::process::abort();
        }
        Ok((mounts, final_proof))
    }
}

impl PolicyBoundPrivateMounts<PristineRun, PolicyEnabledNetworkProof> {
    /// Restore forwarding after lower ordinary unwind completed before any
    /// link mutation crossed its boundary.
    pub(crate) fn finish_pristine_forward_policy_teardown(
        self,
    ) -> Result<
        (PrivateMounts<PristineRun>, PolicyFinalNetworkProof),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.verify_pristine_generation_two_state() {
            return Err(FixedForwardPolicyTeardownFailure {
                source,
                state: FixedForwardPolicyTeardownFailureState::ActivePristine(Box::new(self)),
            });
        }
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let rollback = match rollback.restore_ipv4_forwarding(&mounts, &policy) {
            Ok(rollback) => rollback,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                let source = FixedForwardPolicyError::Network(source);
                return match authority {
                    PolicyForwardingRestoreFailureState::Enabled(rollback) => {
                        Err(FixedForwardPolicyTeardownFailure {
                            source,
                            state: FixedForwardPolicyTeardownFailureState::ActivePristine(
                                Box::new(PolicyBoundPrivateMounts {
                                    mounts,
                                    policy,
                                    rollback,
                                    binding,
                                }),
                            ),
                        })
                    }
                    PolicyForwardingRestoreFailureState::Restored(rollback) => {
                        Err(FixedForwardPolicyTeardownFailure {
                            source,
                            state: FixedForwardPolicyTeardownFailureState::RestoredPristine(
                                Box::new(PolicyBoundPrivateMounts {
                                    mounts,
                                    policy,
                                    rollback,
                                    binding,
                                }),
                            ),
                        })
                    }
                    PolicyForwardingRestoreFailureState::Indeterminate(authority) => {
                        authority.abort_fail_closed()
                    }
                };
            }
        };
        PolicyBoundPrivateMounts {
            mounts,
            policy,
            rollback,
            binding,
        }
        .finish_restored_pristine_forward_policy_teardown()
    }

    fn verify_pristine_generation_two_state(&self) -> Result<(), FixedForwardPolicyError> {
        self.mounts.verify().map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })?;
        self.rollback
            .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            .map_err(FixedForwardPolicyError::Network)?;
        self.verify_active_policy()?;
        self.mounts.verify().map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })
    }
}

impl PolicyBoundPrivateMounts<PristineRun, PolicyRestoredNetworkProof> {
    /// Delete generation two only after the exact forwarding record is restored.
    pub(crate) fn finish_restored_pristine_forward_policy_teardown(
        self,
    ) -> Result<
        (PrivateMounts<PristineRun>, PolicyFinalNetworkProof),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.verify_pristine_generation_two_state() {
            return Err(FixedForwardPolicyTeardownFailure {
                source,
                state: FixedForwardPolicyTeardownFailureState::RestoredPristine(Box::new(self)),
            });
        }
        let deadline = match mutation_deadline() {
            Ok(deadline) => deadline,
            Err(source) => {
                return Err(FixedForwardPolicyTeardownFailure {
                    source: FixedForwardPolicyError::Nftables(source),
                    state: FixedForwardPolicyTeardownFailureState::RestoredPristine(Box::new(self)),
                });
            }
        };
        let Self {
            mounts,
            policy,
            rollback,
            binding,
        } = self;
        let nftables = match delete_exact_forward_policy(policy, deadline) {
            Ok(nftables) => nftables,
            Err(failure) => {
                let (source, authority) = failure.into_parts();
                return match authority {
                    NftablesDeleteAuthority::Active(policy) => {
                        Err(FixedForwardPolicyTeardownFailure {
                            source: FixedForwardPolicyError::Nftables(source),
                            state: FixedForwardPolicyTeardownFailureState::RestoredPristine(
                                Box::new(PolicyBoundPrivateMounts {
                                    mounts,
                                    policy,
                                    rollback,
                                    binding,
                                }),
                            ),
                        })
                    }
                    NftablesDeleteAuthority::Indeterminate(nftables) => {
                        Err(FixedForwardPolicyTeardownFailure {
                            source: FixedForwardPolicyError::Nftables(source),
                            state: FixedForwardPolicyTeardownFailureState::IndeterminatePristine(
                                Box::new(IndeterminatePristineForwardPolicyCleanup {
                                    mounts,
                                    rollback,
                                    nftables,
                                    binding,
                                }),
                            ),
                        })
                    }
                };
            }
        };
        RetiredPristineForwardPolicyCleanup {
            mounts,
            parent: RetiredParentNetworkAuthority::Pending(rollback, nftables),
        }
        .finish()
    }

    fn verify_pristine_generation_two_state(&self) -> Result<(), FixedForwardPolicyError> {
        self.mounts.verify().map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })?;
        self.rollback
            .verify_pristine_with_active_policy(&self.mounts, &self.policy)
            .map_err(FixedForwardPolicyError::Network)?;
        self.verify_active_policy()?;
        self.mounts.verify().map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })
    }
}

impl RetiredPristineForwardPolicyCleanup {
    /// Retry generation-three parent proof after ordinary lower unwind.
    pub(crate) fn finish(
        self,
    ) -> Result<
        (PrivateMounts<PristineRun>, PolicyFinalNetworkProof),
        FixedForwardPolicyTeardownFailure,
    > {
        if let Err(source) = self.mounts.verify() {
            return Err(FixedForwardPolicyTeardownFailure {
                source: FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(
                    source,
                )),
                state: FixedForwardPolicyTeardownFailureState::RetiredPristine(Box::new(self)),
            });
        }
        let Self { mounts, parent } = self;
        let final_proof = match parent {
            RetiredParentNetworkAuthority::Pending(rollback, nftables) => {
                match rollback.finish_after_semantically_empty(&mounts, nftables) {
                    Ok(final_proof) => final_proof,
                    Err(failure) => {
                        let (source, authority) = failure.into_parts();
                        let (rollback, nftables) = *authority;
                        return Err(FixedForwardPolicyTeardownFailure {
                            source: FixedForwardPolicyError::Network(source),
                            state: FixedForwardPolicyTeardownFailureState::RetiredPristine(
                                Box::new(RetiredPristineForwardPolicyCleanup {
                                    mounts,
                                    parent: RetiredParentNetworkAuthority::Pending(
                                        rollback, nftables,
                                    ),
                                }),
                            ),
                        });
                    }
                }
            }
            RetiredParentNetworkAuthority::Final(final_proof) => final_proof,
        };
        if let Err(source) = final_proof.verify(&mounts) {
            return Err(FixedForwardPolicyTeardownFailure {
                source: FixedForwardPolicyError::Network(source),
                state: FixedForwardPolicyTeardownFailureState::RetiredPristine(Box::new(
                    RetiredPristineForwardPolicyCleanup {
                        mounts,
                        parent: RetiredParentNetworkAuthority::Final(final_proof),
                    },
                )),
            });
        }
        if mounts.verify().is_err() {
            std::process::abort();
        }
        Ok((mounts, final_proof))
    }
}

impl<RunState, NetworkAuthority> PolicyBoundPrivateMounts<RunState, NetworkAuthority> {
    fn verify_active_policy(&self) -> Result<(), FixedForwardPolicyError> {
        let deadline = mutation_deadline().map_err(FixedForwardPolicyError::Nftables)?;
        verify_exact_forward_policy(&self.policy, deadline)
            .map_err(FixedForwardPolicyError::Nftables)
    }
}

fn policy_failure_from_topology(
    failure: PrivateMountLinkActivationFailure,
    policy: ActiveNftablesPolicy,
    rollback: PolicyEnabledNetworkProof,
    binding: FixedForwardPolicyBinding,
) -> FixedForwardPolicyFailure {
    let (source, state) = failure.into_parts();
    let source = FixedForwardPolicyError::Topology(source);
    match state {
        PrivateMountLinkFailureState::Pristine(mounts) => {
            FixedForwardPolicyFailure::active_pristine(
                source,
                PolicyBoundPrivateMounts {
                    mounts,
                    policy,
                    rollback,
                    binding,
                },
            )
        }
        PrivateMountLinkFailureState::Deleted(mounts) => FixedForwardPolicyFailure::active_deleted(
            source,
            PolicyBoundPrivateMounts {
                mounts: *mounts,
                policy,
                rollback,
                binding,
            },
        ),
    }
}

fn retain_policy_cleanup_reproof(
    source: FixedForwardPolicyError,
    cleanup: Result<(), PrivateMountSetupError>,
) -> FixedForwardPolicyError {
    match cleanup {
        Ok(()) => source,
        Err(cleanup) => FixedForwardPolicyError::CleanupReproof {
            transition: Box::new(source),
            cleanup,
        },
    }
}

fn policy_binding_error() -> FixedForwardPolicyError {
    FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(hard_error(
        "verify fixed forward-policy topology binding",
        io::Error::other("fixed forward-policy topology binding changed"),
    )))
}

fn fixed_policy_network_visit_error(
    operation: &'static str,
    error: FixedTopologyVisitError<PolicyNetworkError>,
) -> FixedForwardPolicyError {
    FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(
        topology_network_visit_error(operation, error),
    ))
}

fn verify_deleted_endpoint_baselines(
    mounts: &PrivateMounts<AuthorizedDeletedTopology>,
    endpoint_baselines: &[EndpointNetworkBaseline; 2],
) -> Result<(), FixedForwardPolicyError> {
    let mut visited = [false, false];
    mounts
        .run_state
        .visit_network_namespaces(|endpoint| {
            let index = endpoint_index(endpoint);
            if visited[index] {
                return Err(PolicyNetworkError::Inconsistent);
            }
            endpoint_baselines[index].verify_pristine_state(mounts)?;
            visited[index] = true;
            Ok(())
        })
        .map_err(|error| {
            fixed_policy_network_visit_error(
                "verify deleted topology pristine endpoint state",
                error,
            )
        })?;
    if visited != [true, true] {
        return Err(FixedForwardPolicyError::Network(
            PolicyNetworkError::Inconsistent,
        ));
    }
    Ok(())
}

fn consume_deleted_endpoint_baselines_or_abort(
    mounts: &PrivateMounts<AuthorizedDeletedTopology>,
    endpoint_baselines: [EndpointNetworkBaseline; 2],
) {
    let mut endpoint_baselines = endpoint_baselines.map(Some);
    let consumed = mounts.run_state.visit_network_namespaces(|endpoint| {
        endpoint_baselines[endpoint_index(endpoint)]
            .take()
            .ok_or(PolicyNetworkError::Inconsistent)?
            .verify_pristine_rollback(mounts)
    });
    if consumed.is_err() || endpoint_baselines.iter().any(Option::is_some) {
        std::process::abort();
    }
}

fn verify_retired_deleted_state(
    cleanup: &RetiredForwardPolicyCleanup,
) -> Result<(), FixedForwardPolicyError> {
    cleanup
        .mounts
        .verify_authorized_deleted_topology()
        .map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })?;
    let observed = cleanup
        .mounts
        .run_state
        .fixed_forward_policy_binding()
        .map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(
                namespace_pin_error("verify retired forward-policy binding", source),
            ))
        })?;
    if observed != cleanup.binding {
        return Err(policy_binding_error());
    }
    cleanup
        .mounts
        .verify_authorized_deleted_topology()
        .map_err(|source| {
            FixedForwardPolicyError::Topology(PrivateMountLinkActivationError::Mount(source))
        })
}

fn verify_final_parent_state(
    mounts: &PrivateMounts<AuthorizedDeletedTopology>,
    final_proof: &PolicyFinalNetworkProof,
) -> Result<(), FixedForwardPolicyError> {
    mounts
        .run_state
        .visit_parent_network_namespace(|| final_proof.verify(mounts))
        .map_err(|error| {
            fixed_policy_network_visit_error(
                "verify deleted topology final generation-three parent state",
                error,
            )
        })
}

fn active_deleted_teardown_failure(
    source: FixedForwardPolicyError,
    cleanup: PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyEnabledNetworkProof>,
    endpoints: [EndpointNetworkBaseline; 2],
) -> FixedForwardPolicyTeardownFailure {
    FixedForwardPolicyTeardownFailure {
        source,
        state: FixedForwardPolicyTeardownFailureState::Active {
            cleanup: Box::new(cleanup),
            endpoints: Box::new(endpoints),
        },
    }
}

fn initial_deleted_teardown_failure(
    source: FixedForwardPolicyError,
    cleanup: PolicyBoundPrivateMounts<AuthorizedDeletedTopology>,
    endpoints: [EndpointNetworkBaseline; 2],
) -> FixedForwardPolicyTeardownFailure {
    FixedForwardPolicyTeardownFailure {
        source,
        state: FixedForwardPolicyTeardownFailureState::Initial {
            cleanup: Box::new(cleanup),
            endpoints: Box::new(endpoints),
        },
    }
}

fn restored_deleted_teardown_failure(
    source: FixedForwardPolicyError,
    cleanup: PolicyBoundPrivateMounts<AuthorizedDeletedTopology, PolicyRestoredNetworkProof>,
    endpoints: [EndpointNetworkBaseline; 2],
) -> FixedForwardPolicyTeardownFailure {
    FixedForwardPolicyTeardownFailure {
        source,
        state: FixedForwardPolicyTeardownFailureState::Restored {
            cleanup: Box::new(cleanup),
            endpoints: Box::new(endpoints),
        },
    }
}

fn retired_deleted_teardown_failure(
    source: FixedForwardPolicyError,
    cleanup: RetiredForwardPolicyCleanup,
    endpoints: [EndpointNetworkBaseline; 2],
) -> FixedForwardPolicyTeardownFailure {
    FixedForwardPolicyTeardownFailure {
        source,
        state: FixedForwardPolicyTeardownFailureState::Retired {
            cleanup: Box::new(cleanup),
            endpoints: Box::new(endpoints),
        },
    }
}

fn indeterminate_deleted_teardown_failure(
    source: FixedForwardPolicyError,
    cleanup: IndeterminateRestoredForwardPolicyCleanup,
    endpoints: [EndpointNetworkBaseline; 2],
) -> FixedForwardPolicyTeardownFailure {
    FixedForwardPolicyTeardownFailure {
        source,
        state: FixedForwardPolicyTeardownFailureState::Indeterminate {
            cleanup: Box::new(cleanup),
            endpoints: Box::new(endpoints),
        },
    }
}

impl<RunState> PrivateMounts<RunState> {
    /// Read the current network namespace's fixed IPv4-forwarding record
    /// through the retained private procfs pin in any affine run state.
    pub(crate) fn read_ipv4_forwarding_record(
        &self,
    ) -> Result<Ipv4ForwardingRecordSnapshot, PrivateMountSetupError> {
        read_ipv4_forwarding_record_at(&self.proc_pin, self.ids.proc_mount_id)
    }

    /// Set the fixed namespace-local IPv4-forwarding record through the
    /// retained private procfs pin.
    ///
    /// The caller can supply neither a path nor bytes. The exact expected
    /// snapshot must still match immediately before the write boundary. When
    /// the canonical target already holds, the primitive performs a second
    /// exact readback without issuing any write. Otherwise it issues exactly
    /// one fixed two-byte write and requires a same-object canonical post-read.
    pub(crate) fn set_ipv4_forwarding(
        &self,
        expected_before: &Ipv4ForwardingRecordSnapshot,
        target: Ipv4ForwardingState,
    ) -> Result<Ipv4ForwardingMutation, Ipv4ForwardingMutationFailure> {
        set_ipv4_forwarding_at(
            &self.proc_pin,
            self.ids.proc_mount_id,
            expected_before,
            target,
        )
    }

    fn verify_veth_backed_state(
        &self,
        pairs: &AuthorizedVethPairs,
    ) -> Result<(), PrivateMountSetupError> {
        pairs
            .verify()
            .map_err(|source| veth_pair_error("verify authorized veth pairs", source))?;
        let mountinfo = self.observe_visible_private_mounts(false)?;
        verify_authorized_namespace_mountinfo(
            &self.baseline_mountinfo,
            &mountinfo,
            self.ids,
            pairs.mount_ids(),
            pairs.mount_point_bytes(),
        )
        .map_err(|source| hard_error("verify veth-backed nsfs mount table", source))?;
        pairs
            .verify()
            .map_err(|source| veth_pair_error("reverify authorized veth pairs", source))
    }

    fn verify_namespace_backed_mountinfo(
        &self,
        mount_ids: [u64; 2],
        mount_points: [&[u8]; 2],
        operation: &'static str,
    ) -> Result<(), PrivateMountSetupError> {
        let mountinfo = self.observe_visible_private_mounts(false)?;
        verify_authorized_namespace_mountinfo(
            &self.baseline_mountinfo,
            &mountinfo,
            self.ids,
            mount_ids,
            mount_points,
        )
        .map_err(|source| hard_error(operation, source))
    }

    fn into_backing_and_run_state(self) -> (PrivateMountBacking, RunState) {
        let Self {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        } = self;
        (
            PrivateMountBacking {
                root,
                run_pin,
                proc_pin,
                root_mount_id,
                ids,
                baseline_mountinfo,
            },
            run_state,
        )
    }

    fn with_run_state<NextState>(self, run_state: NextState) -> PrivateMounts<NextState> {
        let Self {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state: _,
        } = self;
        PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids,
            baseline_mountinfo,
            run_state,
        }
    }

    fn verify_mounts(&self, require_pristine_run: bool) -> Result<(), PrivateMountSetupError> {
        let root_stat = hard_rustix(
            "re-read pinned root mount identity",
            statx_fd(&self.root, StatxFlags::TYPE | StatxFlags::MNT_ID),
        )?;
        require_directory_and_mount_id(&root_stat, self.root_mount_id)
            .map_err(|source| hard_error("re-read pinned root mount identity", source))?;

        let pinned_run_id = hard_io(
            "re-read pinned /run mount identity",
            mount_id_for_fd(&self.run_pin),
        )?;
        let pinned_proc_id = hard_io(
            "re-read pinned /proc mount identity",
            mount_id_for_fd(&self.proc_pin),
        )?;
        if pinned_run_id != self.ids.run_mount_id || pinned_proc_id != self.ids.proc_mount_id {
            return Err(hard_error(
                "re-read pinned private mount identities",
                invalid_data("pinned private mount identity changed"),
            ));
        }

        let mountinfo = self.observe_visible_private_mounts(require_pristine_run)?;
        verify_private_mountinfo(&mountinfo, self.ids.run_mount_id, self.ids.proc_mount_id)
            .map_err(|source| hard_error("verify private mount table", source))?;
        verify_unchanged_mountinfo(&self.baseline_mountinfo, &mountinfo)
            .map_err(|source| hard_error("verify unchanged private mount table", source))
    }

    fn observe_visible_private_mounts(
        &self,
        require_pristine_run: bool,
    ) -> Result<Vec<u8>, PrivateMountSetupError> {
        verify_visible_private_mounts(
            &self.root,
            self.root_mount_id,
            self.ids,
            require_pristine_run,
        )
    }
}

struct MountTargets {
    root: OwnedFd,
    run: OwnedFd,
    proc: OwnedFd,
    root_mount_id: u64,
    run_mount_id: u64,
    proc_mount_id: u64,
}

impl MountTargets {
    fn pin() -> Result<Self, PrivateMountSetupError> {
        let root = hard_rustix(
            "pin root mount target",
            openat2(
                ABS,
                "/",
                path_directory_flags(),
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            ),
        )?;
        let run = hard_rustix(
            "pin /run mount target",
            open_beneath(&root, "run", path_directory_flags()),
        )?;
        let proc = hard_rustix(
            "pin /proc mount target",
            open_beneath(&root, "proc", path_directory_flags()),
        )?;
        let root_mount_id = hard_io("measure root mount target", mount_id_for_fd(&root))?;
        let run_mount_id = hard_io("measure /run mount target", mount_id_for_fd(&run))?;
        let proc_mount_id = hard_io("measure /proc mount target", mount_id_for_fd(&proc))?;
        Ok(Self {
            root,
            run,
            proc,
            root_mount_id,
            run_mount_id,
            proc_mount_id,
        })
    }
}

/// Install and prove the fixed private mounts from the real namespace PID 1.
///
/// The function has no caller-selected paths or options. It pins all targets
/// before mutation, recursively makes the inherited tree private, attaches a
/// bounded hardened tmpfs over `/run`, and attaches procfs over `/proc` last.
pub(crate) fn setup_and_verify_private_mounts() -> Result<PrivateMounts, PrivateMountSetupError> {
    if getpid().as_raw() != 1 || getppid().as_raw() != 0 {
        return Err(hard_error(
            "verify namespace PID one",
            invalid_data("private mounts may be installed only by namespace PID 1"),
        ));
    }

    let targets = MountTargets::pin()?;
    mount_uapi(
        "make inherited mount tree recursively private",
        mount_change(
            "/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        ),
    )?;
    install_private_run(&targets.run)?;
    install_private_proc(&targets.proc)?;

    let visible_run = hard_rustix(
        "pin visible private /run",
        open_beneath(&targets.root, "run", path_directory_flags()),
    )?;
    let visible_proc = hard_rustix(
        "pin visible private /proc",
        open_beneath(&targets.root, "proc", path_directory_flags()),
    )?;
    let ids = PrivateMountIds {
        run_mount_id: hard_io(
            "measure visible private /run",
            mount_id_for_fd(&visible_run),
        )?,
        proc_mount_id: hard_io(
            "measure visible private /proc",
            mount_id_for_fd(&visible_proc),
        )?,
    };
    if ids.run_mount_id == targets.run_mount_id
        || ids.proc_mount_id == targets.proc_mount_id
        || ids.run_mount_id == ids.proc_mount_id
    {
        return Err(hard_error(
            "measure newly attached private mounts",
            invalid_data("private mounts did not replace both inherited visible mounts"),
        ));
    }

    let mut mounts = PrivateMounts {
        root: targets.root,
        run_pin: visible_run,
        proc_pin: visible_proc,
        root_mount_id: targets.root_mount_id,
        ids,
        baseline_mountinfo: Vec::new(),
        run_state: PristineRun,
    };
    let baseline_mountinfo = mounts.observe_visible_private_mounts(true)?;
    verify_private_mountinfo(&baseline_mountinfo, ids.run_mount_id, ids.proc_mount_id)
        .map_err(|source| hard_error("capture private mount-table baseline", source))?;
    mounts.baseline_mountinfo = baseline_mountinfo;
    mounts.verify()?;
    Ok(mounts)
}

fn install_private_run(target: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let context = mount_uapi(
        "create private /run tmpfs context",
        fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC),
    )?;
    mount_uapi(
        "set private /run size",
        fsconfig_set_string(&context, "size", PRIVATE_RUN_SIZE_BYTES.to_string()),
    )?;
    mount_uapi(
        "set private /run inode bound",
        fsconfig_set_string(&context, "nr_inodes", PRIVATE_RUN_INODES.to_string()),
    )?;
    mount_uapi(
        "set private /run mode",
        fsconfig_set_string(&context, "mode", "0700"),
    )?;
    mount_uapi(
        "set private /run owner",
        fsconfig_set_string(&context, "uid", "0"),
    )?;
    mount_uapi(
        "set private /run group",
        fsconfig_set_string(&context, "gid", "0"),
    )?;
    mount_uapi("create private /run tmpfs", fsconfig_create(&context))?;
    let mount = mount_uapi(
        "instantiate private /run tmpfs",
        fsmount(
            &context,
            FsMountFlags::FSMOUNT_CLOEXEC,
            hardened_mount_attributes(),
        ),
    )?;
    mount_uapi(
        "attach private /run tmpfs",
        move_mount(
            &mount,
            "",
            target,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        ),
    )
}

fn install_private_proc(target: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let context = mount_uapi(
        "create private /proc context",
        fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC),
    )?;
    mount_uapi("create private /proc filesystem", fsconfig_create(&context))?;
    let mount = mount_uapi(
        "instantiate private /proc filesystem",
        fsmount(
            &context,
            FsMountFlags::FSMOUNT_CLOEXEC,
            hardened_mount_attributes(),
        ),
    )?;
    mount_uapi(
        "attach private /proc filesystem",
        move_mount(
            &mount,
            "",
            target,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        ),
    )
}

fn hardened_mount_attributes() -> MountAttrFlags {
    MountAttrFlags::MOUNT_ATTR_NOSUID
        | MountAttrFlags::MOUNT_ATTR_NODEV
        | MountAttrFlags::MOUNT_ATTR_NOEXEC
}

fn path_directory_flags() -> OFlags {
    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC
}

fn readable_directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

fn open_beneath<Fd: AsFd>(directory: Fd, name: &str, flags: OFlags) -> rustix::io::Result<OwnedFd> {
    openat2(
        directory,
        name,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
}

fn open_ipv4_forwarding_record<Fd: AsFd>(proc: Fd) -> rustix::io::Result<OwnedFd> {
    openat2(
        proc,
        IPV4_FORWARDING_RECORD_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV,
    )
}

fn open_ipv4_forwarding_record_for_mutation<Fd: AsFd>(proc: Fd) -> rustix::io::Result<OwnedFd> {
    openat2(
        proc,
        IPV4_FORWARDING_RECORD_PATH,
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV,
    )
}

fn statx_fd<Fd: AsFd>(fd: Fd, requested: StatxFlags) -> rustix::io::Result<Statx> {
    statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        requested,
    )
}

fn mount_id_for_fd<Fd: AsFd>(fd: Fd) -> io::Result<u64> {
    let observed = statx_fd(fd, StatxFlags::TYPE | StatxFlags::MNT_ID).map_err(errno_io)?;
    require_directory_and_mount_id(&observed, observed.stx_mnt_id)?;
    Ok(observed.stx_mnt_id)
}

fn require_directory_and_mount_id(observed: &Statx, expected_mount_id: u64) -> io::Result<()> {
    let mask = StatxFlags::from_bits_retain(observed.stx_mask);
    if !mask.contains(StatxFlags::TYPE | StatxFlags::MNT_ID)
        || !FileType::from_raw_mode(u32::from(observed.stx_mode)).is_dir()
        || observed.stx_mnt_id == 0
        || observed.stx_mnt_id != expected_mount_id
    {
        return Err(invalid_data(
            "kernel did not return the expected directory mount identity",
        ));
    }
    Ok(())
}

fn proc_record_identity(
    observed: &Statx,
    expected_mount_id: u64,
) -> io::Result<ProcRecordIdentity> {
    let mask = StatxFlags::from_bits_retain(observed.stx_mask);
    if !mask.contains(StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID)
        || !FileType::from_raw_mode(u32::from(observed.stx_mode)).is_file()
        || observed.stx_ino == 0
        || observed.stx_mnt_id == 0
        || observed.stx_mnt_id != expected_mount_id
    {
        return Err(invalid_data(
            "kernel did not return the expected regular proc-record identity",
        ));
    }
    Ok(ProcRecordIdentity {
        device_major: observed.stx_dev_major,
        device_minor: observed.stx_dev_minor,
        inode: observed.stx_ino,
        mount_id: observed.stx_mnt_id,
    })
}

fn verify_visible_private_mounts(
    root: &OwnedFd,
    expected_root_mount_id: u64,
    expected_ids: PrivateMountIds,
    require_pristine_run: bool,
) -> Result<Vec<u8>, PrivateMountSetupError> {
    let run = hard_rustix(
        "open visible private /run",
        open_beneath(root, "run", readable_directory_flags()),
    )?;
    let proc_before = hard_rustix(
        "open visible private /proc",
        open_beneath(root, "proc", readable_directory_flags()),
    )?;
    let root_mount_id = hard_io("re-measure root mount", mount_id_for_fd(root))?;
    let run_mount_id = hard_io("re-measure private /run", mount_id_for_fd(&run))?;
    let proc_mount_id = hard_io("re-measure private /proc", mount_id_for_fd(&proc_before))?;
    if root_mount_id != expected_root_mount_id
        || run_mount_id != expected_ids.run_mount_id
        || proc_mount_id != expected_ids.proc_mount_id
    {
        return Err(hard_error(
            "re-measure visible private mounts",
            invalid_data("visible private mount identity changed"),
        ));
    }

    verify_run_filesystem(&run, require_pristine_run)?;
    verify_proc_filesystem(&proc_before)?;
    verify_exact_proc_state(&proc_before)?;
    let mountinfo = read_proc_record(&proc_before, "1/mountinfo", MAX_PRIVATE_MOUNTINFO_BYTES)?;
    let proc_after = hard_rustix(
        "reopen visible private /proc",
        open_beneath(root, "proc", readable_directory_flags()),
    )?;
    let proc_after_mount_id = hard_io(
        "re-measure private /proc after proof",
        mount_id_for_fd(&proc_after),
    )?;
    if proc_after_mount_id != expected_ids.proc_mount_id {
        return Err(hard_error(
            "re-measure private /proc after proof",
            invalid_data("visible private /proc changed during verification"),
        ));
    }
    verify_exact_proc_state(&proc_after)?;
    Ok(mountinfo)
}

fn verify_run_filesystem(
    run: &OwnedFd,
    require_pristine_run: bool,
) -> Result<(), PrivateMountSetupError> {
    let filesystem = hard_rustix("read private /run filesystem type", fstatfs(run))?;
    let metadata = hard_rustix(
        "read private /run metadata",
        statx_fd(
            run,
            StatxFlags::TYPE
                | StatxFlags::MODE
                | StatxFlags::UID
                | StatxFlags::GID
                | StatxFlags::MNT_ID,
        ),
    )?;
    let mask = StatxFlags::from_bits_retain(metadata.stx_mask);
    if filesystem.f_type != TMPFS_SUPER_MAGIC
        || !mask.contains(
            StatxFlags::TYPE
                | StatxFlags::MODE
                | StatxFlags::UID
                | StatxFlags::GID
                | StatxFlags::MNT_ID,
        )
        || !FileType::from_raw_mode(u32::from(metadata.stx_mode)).is_dir()
        || Mode::from_raw_mode(u32::from(metadata.stx_mode)) != Mode::RWXU
        || metadata.stx_uid != 0
        || metadata.stx_gid != 0
    {
        return Err(hard_error(
            "verify private /run filesystem",
            invalid_data("private /run filesystem or root metadata is not exact"),
        ));
    }
    if require_pristine_run {
        hard_io("verify private /run is empty", verify_empty_directory(run))?;
    }
    Ok(())
}

fn verify_proc_filesystem(proc: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let filesystem = hard_rustix("read private /proc filesystem type", fstatfs(proc))?;
    if filesystem.f_type != PROC_SUPER_MAGIC {
        return Err(hard_error(
            "verify private /proc filesystem",
            invalid_data("private /proc is not procfs"),
        ));
    }
    Ok(())
}

fn verify_exact_proc_state(proc: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let self_link = hard_rustix(
        "read private /proc/self",
        readlinkat(proc, "self", Vec::with_capacity(16)),
    )?;
    let thread_self_link = hard_rustix(
        "read private /proc/thread-self",
        readlinkat(proc, "thread-self", Vec::with_capacity(32)),
    )?;
    if self_link.as_bytes() != b"1" || thread_self_link.as_bytes() != b"1/task/1" {
        return Err(hard_error(
            "verify private procfs PID view",
            invalid_data("private procfs is not bound to the namespace PID-1 view"),
        ));
    }
    verify_exact_numeric_directory(proc, b"1", "verify private procfs process set")?;
    let task = hard_rustix(
        "open private procfs PID-1 task directory",
        open_beneath(proc, "1/task", readable_directory_flags()),
    )?;
    verify_exact_numeric_directory(&task, b"1", "verify private procfs task set")?;
    let children = read_proc_record(proc, "1/task/1/children", MAX_PROC_PROOF_BYTES)?;
    if !children.is_empty() {
        return Err(hard_error(
            "verify private procfs PID-1 child set",
            invalid_data("namespace PID 1 has an unexpected child"),
        ));
    }
    Ok(())
}

fn verify_exact_numeric_directory<Fd: AsFd>(
    directory: Fd,
    expected: &[u8],
    operation: &'static str,
) -> Result<(), PrivateMountSetupError> {
    let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
    let mut entries = RawDir::new(directory, &mut buffer);
    let mut found = false;
    while let Some(entry) = entries.next() {
        let entry = hard_rustix(operation, entry)?;
        let name = entry.file_name().to_bytes();
        if !name.is_empty() && name.iter().all(u8::is_ascii_digit) {
            if found || name != expected {
                return Err(hard_error(
                    operation,
                    invalid_data("procfs numeric directory set is not exact"),
                ));
            }
            found = true;
        }
    }
    if !found {
        return Err(hard_error(
            operation,
            invalid_data("procfs numeric directory set is empty"),
        ));
    }
    Ok(())
}

fn verify_empty_directory<Fd: AsFd>(directory: Fd) -> io::Result<()> {
    let reopened = openat2(
        directory,
        ".",
        readable_directory_flags(),
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(errno_io)?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
    let mut entries = RawDir::new(reopened, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(errno_io)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(invalid_data("private /run contains an unexpected entry"));
        }
    }
    Ok(())
}

fn read_proc_record(
    proc: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, PrivateMountSetupError> {
    let descriptor = hard_rustix(
        "open private procfs proof record",
        open_beneath(proc, name, OFlags::RDONLY | OFlags::CLOEXEC),
    )?;
    read_bounded(&mut File::from(descriptor), maximum)
        .map_err(|source| hard_error("read private procfs proof record", source))
}

fn read_ipv4_forwarding_record_at(
    proc: &OwnedFd,
    expected_proc_mount_id: u64,
) -> Result<Ipv4ForwardingRecordSnapshot, PrivateMountSetupError> {
    let descriptor = hard_rustix(
        "open fixed private IPv4-forwarding record",
        open_ipv4_forwarding_record(proc),
    )?;
    let mut file = File::from(descriptor);
    let before = hard_rustix(
        "measure fixed private IPv4-forwarding record before read",
        statx_fd(
            &file,
            StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID,
        ),
    )?;
    let identity = proc_record_identity(&before, expected_proc_mount_id).map_err(|source| {
        hard_error(
            "verify fixed private IPv4-forwarding record before read",
            source,
        )
    })?;
    let bytes = read_bounded(&mut file, MAX_IPV4_FORWARDING_RECORD_BYTES)
        .map_err(|source| hard_error("read fixed private IPv4-forwarding record", source))?;
    let after = hard_rustix(
        "measure fixed private IPv4-forwarding record after read",
        statx_fd(
            &file,
            StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID,
        ),
    )?;
    let identity_after =
        proc_record_identity(&after, expected_proc_mount_id).map_err(|source| {
            hard_error(
                "verify fixed private IPv4-forwarding record after read",
                source,
            )
        })?;
    if identity_after != identity {
        return Err(hard_error(
            "verify fixed private IPv4-forwarding record stability",
            invalid_data("fixed private IPv4-forwarding record identity changed during read"),
        ));
    }
    Ok(Ipv4ForwardingRecordSnapshot { bytes, identity })
}

fn set_ipv4_forwarding_at(
    proc: &OwnedFd,
    expected_proc_mount_id: u64,
    expected_before: &Ipv4ForwardingRecordSnapshot,
    target: Ipv4ForwardingState,
) -> Result<Ipv4ForwardingMutation, Ipv4ForwardingMutationFailure> {
    set_ipv4_forwarding_at_with(
        proc,
        expected_proc_mount_id,
        expected_before,
        target,
        io::Write::write,
    )
}

fn set_ipv4_forwarding_at_with<WriteOnce>(
    proc: &OwnedFd,
    expected_proc_mount_id: u64,
    expected_before: &Ipv4ForwardingRecordSnapshot,
    target: Ipv4ForwardingState,
    write_once: WriteOnce,
) -> Result<Ipv4ForwardingMutation, Ipv4ForwardingMutationFailure>
where
    WriteOnce: FnOnce(&mut File, &[u8]) -> io::Result<usize>,
{
    let before = read_ipv4_forwarding_record_at(proc, expected_proc_mount_id)
        .map_err(Ipv4ForwardingMutationFailure::before_request)?;
    let previous = before.canonical_state().ok_or_else(|| {
        Ipv4ForwardingMutationFailure::before_request(hard_error(
            "classify fixed private IPv4-forwarding record before mutation",
            invalid_data("fixed private IPv4-forwarding record is not canonical"),
        ))
    })?;
    if &before != expected_before {
        return Err(Ipv4ForwardingMutationFailure::before_request(hard_error(
            "match fixed private IPv4-forwarding mutation baseline",
            invalid_data("fixed private IPv4-forwarding baseline changed before mutation"),
        )));
    }

    if previous == target {
        let after = read_ipv4_forwarding_record_at(proc, expected_proc_mount_id)
            .map_err(Ipv4ForwardingMutationFailure::before_request)?;
        if after != before {
            return Err(Ipv4ForwardingMutationFailure::before_request(hard_error(
                "verify no-op fixed private IPv4-forwarding transition",
                invalid_data("fixed private IPv4-forwarding record changed without a request"),
            )));
        }
        return Ok(Ipv4ForwardingMutation {
            before,
            after,
            previous,
            target,
            write_was_requested: false,
        });
    }

    write_ipv4_forwarding_change(
        proc,
        expected_proc_mount_id,
        before,
        previous,
        target,
        write_once,
    )
}

fn write_ipv4_forwarding_change<WriteOnce>(
    proc: &OwnedFd,
    expected_proc_mount_id: u64,
    before: Ipv4ForwardingRecordSnapshot,
    previous: Ipv4ForwardingState,
    target: Ipv4ForwardingState,
    write_once: WriteOnce,
) -> Result<Ipv4ForwardingMutation, Ipv4ForwardingMutationFailure>
where
    WriteOnce: FnOnce(&mut File, &[u8]) -> io::Result<usize>,
{
    let descriptor = hard_rustix(
        "open fixed private IPv4-forwarding record for mutation",
        open_ipv4_forwarding_record_for_mutation(proc),
    )
    .map_err(Ipv4ForwardingMutationFailure::before_request)?;
    let mut file = File::from(descriptor);
    let identity_before_request = hard_rustix(
        "re-measure fixed private IPv4-forwarding record before mutation",
        statx_fd(
            &file,
            StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID,
        ),
    )
    .and_then(|observed| {
        proc_record_identity(&observed, expected_proc_mount_id).map_err(|source| {
            hard_error(
                "verify fixed private IPv4-forwarding identity before mutation",
                source,
            )
        })
    })
    .map_err(Ipv4ForwardingMutationFailure::before_request)?;
    if identity_before_request != before.identity {
        return Err(Ipv4ForwardingMutationFailure::before_request(hard_error(
            "match fixed private IPv4-forwarding identity before mutation",
            invalid_data("fixed private IPv4-forwarding identity changed before mutation"),
        )));
    }

    let bytes = target.bytes();
    let written = match write_once(&mut file, bytes) {
        Ok(written) => written,
        Err(source) => {
            return Err(Ipv4ForwardingMutationFailure::possibly_written(
                hard_error("write fixed private IPv4-forwarding record", source),
                before,
                previous,
                target,
            ));
        }
    };
    if written != bytes.len() {
        return Err(Ipv4ForwardingMutationFailure::possibly_written(
            hard_error(
                "write fixed private IPv4-forwarding record",
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "fixed private IPv4-forwarding write was partial",
                ),
            ),
            before,
            previous,
            target,
        ));
    }
    drop(file);

    let after = match read_ipv4_forwarding_record_at(proc, expected_proc_mount_id) {
        Ok(after) => after,
        Err(source) => {
            return Err(Ipv4ForwardingMutationFailure::possibly_written(
                source, before, previous, target,
            ));
        }
    };
    if after.identity != before.identity || after.canonical_state() != Some(target) {
        return Err(Ipv4ForwardingMutationFailure::possibly_written(
            hard_error(
                "verify fixed private IPv4-forwarding record after mutation",
                invalid_data("fixed private IPv4-forwarding post-state or identity was not exact"),
            ),
            before,
            previous,
            target,
        ));
    }
    Ok(Ipv4ForwardingMutation {
        before,
        after,
        previous,
        target,
        write_was_requested: true,
    })
}

fn read_bounded(file: &mut File, maximum: usize) -> io::Result<Vec<u8>> {
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| invalid_data("proof record read bound overflowed"))?;
    let mut bytes = Vec::with_capacity(limit);
    io::Read::by_ref(file)
        .take(
            u64::try_from(limit)
                .map_err(|_| invalid_data("proof record read bound does not fit u64"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid_data("proof record exceeded its fixed byte bound"));
    }
    Ok(bytes)
}

/// Verify one bounded mountinfo snapshot against the visible private mount IDs.
///
/// Covered inherited `/run` and `/proc` records are permitted. The caller must
/// obtain `visible_run_mount_id` and `visible_proc_mount_id` from descriptor-
/// anchored `statx(STATX_MNT_ID)` observations of the currently visible paths.
pub(crate) fn verify_private_mountinfo(
    bytes: &[u8],
    visible_run_mount_id: u64,
    visible_proc_mount_id: u64,
) -> io::Result<PrivateMountIds> {
    if bytes.is_empty()
        || bytes.len() > MAX_PRIVATE_MOUNTINFO_BYTES
        || !bytes.ends_with(b"\n")
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
        || visible_run_mount_id == 0
        || visible_proc_mount_id == 0
        || visible_run_mount_id == visible_proc_mount_id
    {
        return Err(invalid_data(
            "private mountinfo framing or visible IDs are invalid",
        ));
    }

    let mut mount_ids = HashSet::new();
    let mut run_verified = false;
    let mut proc_verified = false;
    let mut record_count = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        record_count = record_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("private mountinfo record count overflowed"))?;
        if line.is_empty() || record_count > MAX_PRIVATE_MOUNTINFO_RECORDS {
            return Err(invalid_data("private mountinfo record count is invalid"));
        }
        let record = MountInfoRecord::parse(line)?;
        if !mount_ids.insert(record.mount_id) {
            return Err(invalid_data(
                "private mountinfo contains a duplicate mount ID",
            ));
        }
        if record.has_optional_field() {
            return Err(invalid_data("mount propagation is not recursively private"));
        }
        if record.mount_id == visible_run_mount_id {
            verify_run_record(&record)?;
            run_verified = true;
        }
        if record.mount_id == visible_proc_mount_id {
            verify_proc_record(&record)?;
            proc_verified = true;
        }
    }
    if !run_verified || !proc_verified {
        return Err(invalid_data(
            "visible private /run or /proc mount record is missing",
        ));
    }
    Ok(PrivateMountIds {
        run_mount_id: visible_run_mount_id,
        proc_mount_id: visible_proc_mount_id,
    })
}

fn verify_unchanged_mountinfo(baseline: &[u8], observed: &[u8]) -> io::Result<()> {
    let baseline_records = mountinfo_record_map(baseline)?;
    let observed_records = mountinfo_record_map(observed)?;
    if baseline_records.len() != observed_records.len()
        || baseline_records
            .iter()
            .any(|(mount_id, record)| observed_records.get(mount_id) != Some(record))
    {
        return Err(invalid_data(
            "private mount-table baseline changed unexpectedly",
        ));
    }
    Ok(())
}

fn verify_authorized_namespace_mountinfo(
    baseline: &[u8],
    observed: &[u8],
    private_ids: PrivateMountIds,
    namespace_mount_ids: [u64; 2],
    namespace_mount_points: [&[u8]; 2],
) -> io::Result<()> {
    verify_private_mountinfo(
        baseline,
        private_ids.run_mount_id,
        private_ids.proc_mount_id,
    )?;
    verify_private_mountinfo(
        observed,
        private_ids.run_mount_id,
        private_ids.proc_mount_id,
    )?;
    validate_namespace_mount_expectations(namespace_mount_ids, namespace_mount_points)?;

    let baseline_records = mountinfo_record_map(baseline)?;
    let observed_records = mountinfo_record_map(observed)?;
    let expected_record_count = baseline_records
        .len()
        .checked_add(2)
        .ok_or_else(|| invalid_data("authorized mount-table record count overflowed"))?;
    if observed_records.len() != expected_record_count {
        return Err(invalid_data(
            "authorized mount table does not contain exactly two additions",
        ));
    }
    for (mount_id, baseline_record) in &baseline_records {
        if observed_records.get(mount_id) != Some(baseline_record) {
            return Err(invalid_data(
                "authorized mount table changed a baseline mount record",
            ));
        }
    }
    for (mount_id, mount_point) in namespace_mount_ids.into_iter().zip(namespace_mount_points) {
        if baseline_records.contains_key(&mount_id)
            || mountinfo_contains_mount_point(&baseline_records, mount_point)?
        {
            return Err(invalid_data(
                "authorized namespace mount collides with the baseline",
            ));
        }
        let record_bytes = observed_records
            .get(&mount_id)
            .ok_or_else(|| invalid_data("authorized nsfs mount ID is missing"))?;
        let record = MountInfoRecord::parse(record_bytes)?;
        if record.parent_id != private_ids.run_mount_id
            || record.mount_point != mount_point
            || record.file_system_type != b"nsfs"
            || record.has_optional_field()
        {
            return Err(invalid_data("authorized nsfs mount record is not exact"));
        }
    }
    Ok(())
}

fn verify_namespace_mountinfo_rollback(
    baseline: &[u8],
    observed: &[u8],
    private_ids: PrivateMountIds,
    retired_mount_ids: [u64; 2],
    retired_mount_points: [&[u8]; 2],
) -> io::Result<()> {
    verify_private_mountinfo(
        observed,
        private_ids.run_mount_id,
        private_ids.proc_mount_id,
    )?;
    verify_unchanged_mountinfo(baseline, observed)?;
    let observed_records = mountinfo_record_map(observed)?;
    for (mount_id, mount_point) in retired_mount_ids.into_iter().zip(retired_mount_points) {
        if observed_records.contains_key(&mount_id)
            || mountinfo_contains_mount_point(&observed_records, mount_point)?
        {
            return Err(invalid_data(
                "retired nsfs mount ID or path remains in the mount table",
            ));
        }
    }
    Ok(())
}

fn validate_namespace_mount_expectations(
    mount_ids: [u64; 2],
    mount_points: [&[u8]; 2],
) -> io::Result<()> {
    if mount_ids[0] == 0
        || mount_ids[1] == 0
        || mount_ids[0] == mount_ids[1]
        || mount_points[0] == mount_points[1]
        || mount_points.iter().any(|mount_point| {
            let leaf = &mount_point[b"/run/netns/".len().min(mount_point.len())..];
            !mount_point.starts_with(b"/run/netns/")
                || leaf.is_empty()
                || leaf.contains(&b'/')
                || leaf.iter().any(|byte| {
                    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-'
                })
        })
    {
        return Err(invalid_data(
            "authorized namespace mount expectations are invalid",
        ));
    }
    Ok(())
}

fn mountinfo_record_map(bytes: &[u8]) -> io::Result<HashMap<u64, &[u8]>> {
    if bytes.is_empty()
        || bytes.len() > MAX_PRIVATE_MOUNTINFO_BYTES
        || !bytes.ends_with(b"\n")
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
    {
        return Err(invalid_data("private mountinfo framing is invalid"));
    }
    let mut records = HashMap::new();
    for (index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() || index >= MAX_PRIVATE_MOUNTINFO_RECORDS {
            return Err(invalid_data("private mountinfo record count is invalid"));
        }
        let record = MountInfoRecord::parse(line)?;
        if records.insert(record.mount_id, line).is_some() {
            return Err(invalid_data(
                "private mountinfo contains a duplicate mount ID",
            ));
        }
    }
    Ok(records)
}

fn mountinfo_contains_mount_point(
    records: &HashMap<u64, &[u8]>,
    mount_point: &[u8],
) -> io::Result<bool> {
    for record in records.values() {
        if MountInfoRecord::parse(record)?.mount_point == mount_point {
            return Ok(true);
        }
    }
    Ok(false)
}

struct MountInfoRecord<'a> {
    mount_id: u64,
    parent_id: u64,
    root: &'a [u8],
    mount_point: &'a [u8],
    mount_options: &'a [u8],
    has_optional_field: bool,
    file_system_type: &'a [u8],
    super_options: &'a [u8],
}

impl<'a> MountInfoRecord<'a> {
    fn parse(line: &'a [u8]) -> io::Result<Self> {
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.len() < 10 || fields.iter().any(|field| field.is_empty()) {
            return Err(invalid_data("private mountinfo record shape is invalid"));
        }
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| invalid_data("private mountinfo separator is missing"))?;
        if separator < 6 || separator.checked_add(4) != Some(fields.len()) {
            return Err(invalid_data(
                "private mountinfo separator position is invalid",
            ));
        }
        let mount_id = parse_canonical_decimal(fields[0])?;
        let parent_id = parse_canonical_decimal(fields[1])?;
        if mount_id == 0 || parent_id == 0 || !is_major_minor(fields[2]) {
            return Err(invalid_data(
                "private mountinfo identity fields are invalid",
            ));
        }
        Ok(Self {
            mount_id,
            parent_id,
            root: fields[3],
            mount_point: fields[4],
            mount_options: fields[5],
            has_optional_field: separator != 6,
            file_system_type: fields[separator + 1],
            super_options: fields[separator + 3],
        })
    }

    fn has_optional_field(&self) -> bool {
        self.has_optional_field
    }
}

fn verify_run_record(record: &MountInfoRecord<'_>) -> io::Result<()> {
    if record.root != b"/"
        || record.mount_point != RUN_MOUNT_POINT
        || record.file_system_type != b"tmpfs"
    {
        return Err(invalid_data(
            "visible private /run mount record is not exact",
        ));
    }
    verify_hardened_mount_options(record.mount_options)?;
    require_flag(record.super_options, b"rw")?;
    let size = parse_quantity(require_value(record.super_options, b"size")?)?;
    let inodes = parse_quantity(require_value(record.super_options, b"nr_inodes")?)?;
    let mode = require_value(record.super_options, b"mode")?;
    if size != PRIVATE_RUN_SIZE_BYTES || inodes != PRIVATE_RUN_INODES || mode != b"700" {
        return Err(invalid_data(
            "private /run tmpfs bounds or mode are not exact",
        ));
    }
    Ok(())
}

fn verify_proc_record(record: &MountInfoRecord<'_>) -> io::Result<()> {
    if record.root != b"/"
        || record.mount_point != PROC_MOUNT_POINT
        || record.file_system_type != b"proc"
    {
        return Err(invalid_data(
            "visible private /proc mount record is not exact",
        ));
    }
    verify_hardened_mount_options(record.mount_options)?;
    require_flag(record.super_options, b"rw")
}

fn verify_hardened_mount_options(options: &[u8]) -> io::Result<()> {
    for required in [b"rw".as_slice(), b"nosuid", b"nodev", b"noexec"] {
        require_flag(options, required)?;
    }
    for forbidden in [b"ro".as_slice(), b"suid", b"dev", b"exec"] {
        if option_count(options, forbidden, false)? != 0 {
            return Err(invalid_data("private mount has a conflicting mount option"));
        }
    }
    Ok(())
}

fn require_flag(options: &[u8], name: &[u8]) -> io::Result<()> {
    if option_count(options, name, false)? == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "required private mount flag {} is missing or duplicated",
                String::from_utf8_lossy(name)
            ),
        ))
    }
}

fn require_value<'a>(options: &'a [u8], name: &[u8]) -> io::Result<&'a [u8]> {
    let mut found = None;
    for option in options.split(|byte| *byte == b',') {
        if option.is_empty() {
            return Err(invalid_data(
                "private mount option list contains an empty field",
            ));
        }
        let Some((key, value)) = split_byte_once(option, b'=') else {
            continue;
        };
        if key != name {
            continue;
        }
        if value.is_empty() || found.replace(value).is_some() {
            return Err(invalid_data(
                "private mount option value is missing or duplicated",
            ));
        }
    }
    found.ok_or_else(|| invalid_data("required private mount option value is missing"))
}

fn option_count(options: &[u8], name: &[u8], accept_value: bool) -> io::Result<usize> {
    let mut count = 0_usize;
    for option in options.split(|byte| *byte == b',') {
        if option.is_empty() {
            return Err(invalid_data(
                "private mount option list contains an empty field",
            ));
        }
        let (key, has_value) =
            split_byte_once(option, b'=').map_or((option, false), |(key, _)| (key, true));
        if key == name && (accept_value || !has_value) {
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("private mount option count overflowed"))?;
        }
    }
    Ok(count)
}

fn parse_quantity(value: &[u8]) -> io::Result<u64> {
    let (digits, multiplier) = match value.last().copied() {
        Some(b'k') => (&value[..value.len() - 1], 1024_u64),
        Some(b'm') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some(b'g') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        _ => (value, 1_u64),
    };
    parse_canonical_decimal(digits)?
        .checked_mul(multiplier)
        .ok_or_else(|| invalid_data("private mount quantity overflowed"))
}

fn parse_canonical_decimal(value: &[u8]) -> io::Result<u64> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value.starts_with(b"0"))
    {
        return Err(invalid_data("private mount decimal is not canonical"));
    }
    let mut parsed = 0_u64;
    for digit in value {
        parsed = parsed
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid_data("private mount decimal overflowed"))?;
    }
    Ok(parsed)
}

fn is_major_minor(value: &[u8]) -> bool {
    let Some((major, minor)) = split_byte_once(value, b':') else {
        return false;
    };
    parse_canonical_decimal(major).is_ok() && parse_canonical_decimal(minor).is_ok()
}

fn split_byte_once(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().position(|byte| *byte == delimiter)?;
    Some((&value[..index], &value[index + 1..]))
}

fn mount_uapi<T>(
    operation: &'static str,
    result: rustix::io::Result<T>,
) -> Result<T, PrivateMountSetupError> {
    result.map_err(|error| classify_mount_error(operation, error))
}

fn hard_rustix<T>(
    operation: &'static str,
    result: rustix::io::Result<T>,
) -> Result<T, PrivateMountSetupError> {
    result.map_err(|error| {
        hard_error(
            operation,
            io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })
}

fn hard_io<T>(operation: &'static str, result: io::Result<T>) -> Result<T, PrivateMountSetupError> {
    result.map_err(|source| hard_error(operation, source))
}

fn classify_mount_error(operation: &'static str, error: Errno) -> PrivateMountSetupError {
    let source = io::Error::from_raw_os_error(error.raw_os_error());
    if matches!(error, Errno::PERM | Errno::ACCESS) {
        PrivateMountSetupError::PolicyDenied { operation, source }
    } else {
        PrivateMountSetupError::HardFailure { operation, source }
    }
}

fn hard_error(operation: &'static str, source: io::Error) -> PrivateMountSetupError {
    PrivateMountSetupError::HardFailure { operation, source }
}

fn private_run_error(
    operation: &'static str,
    source: AuthorizedPrivateRunError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn namespace_pin_error(
    operation: &'static str,
    source: NamespacePinError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn veth_pair_error(operation: &'static str, source: VethPairError) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn ipv4_address_set_error(
    operation: &'static str,
    source: FixedIpv4AddressSetError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn fixed_link_error(
    operation: &'static str,
    source: FixedLinkActivationError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn fixed_route_error(
    operation: &'static str,
    source: FixedEndpointRouteSetError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn endpoint_index(endpoint: NamespaceEndpoint) -> usize {
    match endpoint {
        NamespaceEndpoint::A => 0,
        NamespaceEndpoint::B => 1,
    }
}

fn require_complete_endpoint_visit(
    visited: [bool; 2],
) -> Result<(), NamespacePinsNetworkProofError> {
    if visited == [true, true] {
        Ok(())
    } else {
        Err(NamespacePinsNetworkProofError::Network(
            crate::network::NetworkError::Inconsistent,
        ))
    }
}

fn exact_ipv4_address_expectations(
    addresses: &AuthorizedIpv4Addresses,
) -> Result<ExactIpv4AddressExpectations, crate::network::NetworkError> {
    exact_ipv4_address_expectations_from(addresses.veth_pairs().fixed_pairs(), addresses.owners())
}

fn exact_ipv4_address_expectations_from(
    fixed_pairs: [&crate::topology::veth::FixedVethPair; 2],
    owners: [&crate::topology::ipv4::FixedIpv4AddressOwner; 4],
) -> Result<ExactIpv4AddressExpectations, crate::network::NetworkError> {
    let pair_expectations = [
        crate::network::ExpectedVethPair::new(
            fixed_pairs[0].parent_name(),
            fixed_pairs[0].parent_ifindex(),
            fixed_pairs[0].peer_ifindex(),
            fixed_pairs[0].target_namespace_identity(),
        )?,
        crate::network::ExpectedVethPair::new(
            fixed_pairs[1].parent_name(),
            fixed_pairs[1].parent_ifindex(),
            fixed_pairs[1].peer_ifindex(),
            fixed_pairs[1].target_namespace_identity(),
        )?,
    ];
    if owners
        .iter()
        .any(|owner| owner.address().prefix_length() != 30)
    {
        return Err(crate::network::NetworkError::Inconsistent);
    }
    let parent_alpha_namespace = owners[0].namespace_identity();
    let endpoint_alpha_namespace = owners[1].namespace_identity();
    let parent_omega_namespace = owners[2].namespace_identity();
    let endpoint_omega_namespace = owners[3].namespace_identity();
    let alpha_target = fixed_pairs[0].target_namespace_identity();
    let omega_target = fixed_pairs[1].target_namespace_identity();
    if parent_alpha_namespace != parent_omega_namespace
        || (
            endpoint_alpha_namespace.device(),
            endpoint_alpha_namespace.inode(),
        ) != (alpha_target.device(), alpha_target.inode())
        || (
            endpoint_omega_namespace.device(),
            endpoint_omega_namespace.inode(),
        ) != (omega_target.device(), omega_target.inode())
        || parent_alpha_namespace == endpoint_alpha_namespace
        || parent_alpha_namespace == endpoint_omega_namespace
        || endpoint_alpha_namespace == endpoint_omega_namespace
    {
        return Err(crate::network::NetworkError::Inconsistent);
    }
    let address_expectations = [
        crate::network::ExpectedIpv4Address::new(
            owners[0].interface_name(),
            owners[0].ifindex(),
            owners[0].address().octets(),
        )?,
        crate::network::ExpectedIpv4Address::new(
            owners[1].interface_name(),
            owners[1].ifindex(),
            owners[1].address().octets(),
        )?,
        crate::network::ExpectedIpv4Address::new(
            owners[2].interface_name(),
            owners[2].ifindex(),
            owners[2].address().octets(),
        )?,
        crate::network::ExpectedIpv4Address::new(
            owners[3].interface_name(),
            owners[3].ifindex(),
            owners[3].address().octets(),
        )?,
    ];
    Ok(ExactIpv4AddressExpectations {
        pairs: pair_expectations,
        addresses: address_expectations,
    })
}

fn map_veth_visit_error(
    operation: &'static str,
    error: NamespaceVisitError<crate::network::NetworkError>,
) -> NamespacePinsNetworkProofError {
    match error {
        NamespaceVisitError::Namespace(source) => {
            NamespacePinsNetworkProofError::Mount(namespace_pin_error(operation, source))
        }
        NamespaceVisitError::Visitor(source) => NamespacePinsNetworkProofError::Network(source),
    }
}

fn map_topology_visit_error(
    operation: &'static str,
    error: FixedTopologyVisitError<crate::network::NetworkError>,
) -> NamespacePinsNetworkProofError {
    match error {
        FixedTopologyVisitError::Topology(source) => {
            NamespacePinsNetworkProofError::Mount(fixed_link_error(operation, source))
        }
        FixedTopologyVisitError::Namespace(source) => {
            NamespacePinsNetworkProofError::Mount(namespace_pin_error(operation, source))
        }
        FixedTopologyVisitError::Visitor(source) => NamespacePinsNetworkProofError::Network(source),
    }
}

fn map_endpoint_route_visit_error(
    operation: &'static str,
    error: FixedEndpointRouteVisitError<crate::network::NetworkError>,
) -> NamespacePinsNetworkProofError {
    match error {
        FixedEndpointRouteVisitError::Topology(source) => {
            NamespacePinsNetworkProofError::Mount(fixed_route_error(operation, source))
        }
        FixedEndpointRouteVisitError::Namespace(source) => {
            NamespacePinsNetworkProofError::Mount(namespace_pin_error(operation, source))
        }
        FixedEndpointRouteVisitError::Visitor(source) => {
            NamespacePinsNetworkProofError::Network(source)
        }
    }
}

fn map_infallible_topology_visit_error(
    operation: &'static str,
    error: FixedTopologyVisitError<Infallible>,
) -> PrivateMountSetupError {
    match error {
        FixedTopologyVisitError::Topology(source) => fixed_link_error(operation, source),
        FixedTopologyVisitError::Namespace(source) => namespace_pin_error(operation, source),
        FixedTopologyVisitError::Visitor(never) => match never {},
    }
}

fn topology_network_visit_error(
    operation: &'static str,
    error: FixedTopologyVisitError<crate::network::NetworkError>,
) -> PrivateMountSetupError {
    match error {
        FixedTopologyVisitError::Topology(source) => fixed_link_error(operation, source),
        FixedTopologyVisitError::Namespace(source) => namespace_pin_error(operation, source),
        FixedTopologyVisitError::Visitor(source) => network_proof_setup_error(operation, source),
    }
}

fn network_proof_setup_error(
    operation: &'static str,
    source: crate::network::NetworkError,
) -> PrivateMountSetupError {
    hard_error(operation, io::Error::other(source))
}

fn verify_deleted_pair_identities(
    identities: &[crate::topology::namespaces::DeletedVethPairIdentity; 2],
) -> Result<(), PrivateMountSetupError> {
    let target_alpha = (
        identities[0].target_namespace_device(),
        identities[0].target_namespace_inode(),
    );
    let target_omega = (
        identities[1].target_namespace_device(),
        identities[1].target_namespace_inode(),
    );
    let exact = identities[0].endpoint() == NamespaceEndpoint::A
        && identities[1].endpoint() == NamespaceEndpoint::B
        && !identities[0].parent_name().is_empty()
        && !identities[1].parent_name().is_empty()
        && identities[0].parent_name() != identities[1].parent_name()
        && identities[0].parent_ifindex() != 0
        && identities[1].parent_ifindex() != 0
        && identities[0].parent_ifindex() != identities[1].parent_ifindex()
        && identities[0].peer_ifindex() != 0
        && identities[1].peer_ifindex() != 0
        && target_alpha.1 != 0
        && target_omega.1 != 0
        && target_alpha != target_omega;
    if exact {
        Ok(())
    } else {
        Err(hard_error(
            "verify deleted topology retained pair identities",
            invalid_data("deleted topology retained pair identities are not exact"),
        ))
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn errno_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        path::{Path, PathBuf},
        process::Command,
    };

    use rustix::fs::mkfifoat;

    use super::*;

    const VALID_MOUNTINFO: &[u8] = b"10 10 8:1 / / rw,relatime - ext4 /dev/root rw\n\
20 10 0:20 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k,mode=755,inode64\n\
21 20 0:21 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k,nr_inodes=4096,mode=700,inode64\n\
30 10 0:30 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
31 30 0:31 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
    const LIVE_IPV4_FORWARDING_CHILD_ENV: &str =
        "VOLPAROSSA_TEST_LIVE_IPV4_FORWARDING_WRITER_CHILD";
    const LIVE_IPV4_FORWARDING_PARENT_NETNS_ENV: &str =
        "VOLPAROSSA_TEST_LIVE_IPV4_FORWARDING_PARENT_NETNS";

    fn open_test_directory(path: &Path) -> OwnedFd {
        File::open(path).expect("open test directory").into()
    }

    fn fixed_record_path(root: &Path) -> PathBuf {
        root.join(IPV4_FORWARDING_RECORD_PATH)
    }

    fn create_fixed_record_parents(root: &Path) {
        fs::create_dir_all(
            fixed_record_path(root)
                .parent()
                .expect("fixed record parent"),
        )
        .expect("create fixed record parents");
    }

    fn hard_failure_source(error: PrivateMountSetupError) -> io::Error {
        match error {
            PrivateMountSetupError::HardFailure { source, .. } => source,
            PrivateMountSetupError::PolicyDenied { .. } => {
                panic!("fixed read errors may never be mount-policy denials")
            }
        }
    }

    fn forwarding_snapshot(root: &OwnedFd) -> Ipv4ForwardingRecordSnapshot {
        let mount_id = mount_id_for_fd(root).expect("fixture mount ID");
        read_ipv4_forwarding_record_at(root, mount_id).expect("fixed forwarding snapshot")
    }

    fn current_network_namespace_identity() -> (u64, u64) {
        let metadata = fs::metadata("/proc/self/ns/net").expect("network namespace metadata");
        (metadata.dev(), metadata.ino())
    }

    fn parse_network_namespace_identity(value: &str) -> Option<(u64, u64)> {
        let (device, inode) = value.split_once(':')?;
        Some((device.parse().ok()?, inode.parse().ok()?))
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

    #[test]
    fn fixed_ipv4_forwarding_reader_pins_real_proc_record_identity() {
        let root = open_test_directory(Path::new("/"));
        let run_pin = open_test_directory(Path::new("/run"));
        let proc_pin = open_test_directory(Path::new("/proc"));
        let root_mount_id = mount_id_for_fd(&root).expect("root mount ID");
        let run_mount_id = mount_id_for_fd(&run_pin).expect("run mount ID");
        let proc_mount_id = mount_id_for_fd(&proc_pin).expect("proc mount ID");
        let mounts = PrivateMounts {
            root,
            run_pin,
            proc_pin,
            root_mount_id,
            ids: PrivateMountIds {
                run_mount_id,
                proc_mount_id,
            },
            baseline_mountinfo: Vec::new(),
            run_state: PristineRun,
        };

        let first = mounts
            .read_ipv4_forwarding_record()
            .expect("first fixed forwarding read");
        let second = mounts
            .read_ipv4_forwarding_record()
            .expect("second fixed forwarding read");
        assert!(matches!(first.bytes(), b"0\n" | b"1\n"));
        assert_eq!(first, second, "value and proc-record identity stay exact");
    }

    #[test]
    fn fixed_ipv4_forwarding_reader_rejects_wrong_mount_identity() {
        let proc = open_test_directory(Path::new("/proc"));
        let mount_id = mount_id_for_fd(&proc).expect("proc mount ID");
        let wrong_mount_id = mount_id.checked_add(1).expect("mount ID increment");
        let source = hard_failure_source(
            read_ipv4_forwarding_record_at(&proc, wrong_mount_id)
                .expect_err("wrong mount ID must fail"),
        );
        assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn fixed_ipv4_forwarding_reader_is_nonblocking_and_rejects_non_regular_leaf() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let root = open_test_directory(directory.path());
        mkfifoat(
            &root,
            IPV4_FORWARDING_RECORD_PATH,
            Mode::from_raw_mode(0o600),
        )
        .expect("FIFO fixture");
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let source = hard_failure_source(
            read_ipv4_forwarding_record_at(&root, mount_id)
                .expect_err("FIFO leaf must fail without blocking"),
        );
        assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn fixed_ipv4_forwarding_reader_rejects_symlink_and_mount_crossing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let leaf = fixed_record_path(directory.path());
        fs::write(leaf.with_file_name("target"), b"0\n").expect("symlink target");
        symlink("target", &leaf).expect("symlink fixture");
        let fixture = open_test_directory(directory.path());
        let fixture_mount_id = mount_id_for_fd(&fixture).expect("fixture mount ID");
        let symlink_source = hard_failure_source(
            read_ipv4_forwarding_record_at(&fixture, fixture_mount_id)
                .expect_err("symlink leaf must fail"),
        );
        assert_eq!(
            symlink_source.raw_os_error(),
            Some(Errno::LOOP.raw_os_error())
        );

        let root = open_test_directory(Path::new("/"));
        let sys = open_test_directory(Path::new("/sys"));
        let root_mount_id = mount_id_for_fd(&root).expect("root mount ID");
        assert_ne!(
            root_mount_id,
            mount_id_for_fd(&sys).expect("sysfs mount ID"),
            "test requires /sys to be a distinct mount"
        );
        let crossing_source = hard_failure_source(
            read_ipv4_forwarding_record_at(&root, root_mount_id)
                .expect_err("cross-mount lookup must fail"),
        );
        assert_eq!(
            crossing_source.raw_os_error(),
            Some(Errno::XDEV.raw_os_error())
        );
    }

    #[test]
    fn fixed_ipv4_forwarding_reader_rejects_oversized_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        fs::write(fixed_record_path(directory.path()), b"000").expect("oversized fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let source = hard_failure_source(
            read_ipv4_forwarding_record_at(&root, mount_id)
                .expect_err("oversized record must fail"),
        );
        assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_roundtrips_with_exact_snapshots() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        fs::write(fixed_record_path(directory.path()), b"0\n").expect("initial fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let initial = forwarding_snapshot(&root);

        let enabled =
            set_ipv4_forwarding_at(&root, mount_id, &initial, Ipv4ForwardingState::Enabled)
                .expect("enable fixed forwarding record");
        assert_eq!(enabled.before(), &initial);
        assert_eq!(enabled.previous(), Ipv4ForwardingState::Disabled);
        assert_eq!(enabled.target(), Ipv4ForwardingState::Enabled);
        assert!(enabled.write_was_requested());
        assert_eq!(enabled.after().bytes(), b"1\n");
        assert_eq!(
            fs::read(fixed_record_path(directory.path())).expect("enabled fixture"),
            b"1\n"
        );

        let restored = set_ipv4_forwarding_at(&root, mount_id, enabled.after(), enabled.previous())
            .expect("restore fixed forwarding record");
        assert!(restored.write_was_requested());
        assert_eq!(restored.after(), &initial);
        assert_eq!(
            fs::read(fixed_record_path(directory.path())).expect("restored fixture"),
            b"0\n"
        );
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_avoids_write_when_target_already_holds() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        fs::write(fixed_record_path(directory.path()), b"1\n").expect("initial fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let initial = forwarding_snapshot(&root);
        let mut writer_called = false;

        let unchanged = set_ipv4_forwarding_at_with(
            &root,
            mount_id,
            &initial,
            Ipv4ForwardingState::Enabled,
            |_, _| {
                writer_called = true;
                panic!("no-op transition must not call its writer")
            },
        )
        .expect("no-op fixed forwarding transition");
        assert!(!writer_called);
        assert!(!unchanged.write_was_requested());
        assert_eq!(unchanged.before(), &initial);
        assert_eq!(unchanged.after(), &initial);
    }

    #[test]
    fn fixed_ipv4_forwarding_no_op_needs_only_read_capability() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let path = fixed_record_path(directory.path());
        fs::write(&path, b"0\n").expect("initial fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .expect("read-only forwarding fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let initial = forwarding_snapshot(&root);

        let unchanged =
            set_ipv4_forwarding_at(&root, mount_id, &initial, Ipv4ForwardingState::Disabled)
                .expect("no-op forwarding transition with read-only capability");
        assert!(!unchanged.write_was_requested());
        assert_eq!(unchanged.after(), &initial);
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_rejects_changed_expected_snapshot_without_writing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let path = fixed_record_path(directory.path());
        fs::write(&path, b"0\n").expect("initial fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let expected = forwarding_snapshot(&root);
        fs::write(&path, b"1\n").expect("change fixture before request");
        let mut writer_called = false;

        let failure = set_ipv4_forwarding_at_with(
            &root,
            mount_id,
            &expected,
            Ipv4ForwardingState::Disabled,
            |_, _| {
                writer_called = true;
                panic!("mismatched baseline must not call its writer")
            },
        )
        .expect_err("changed expected snapshot must fail before request");
        assert!(!writer_called);
        let (source, state) = failure.into_parts();
        assert!(matches!(
            state,
            Ipv4ForwardingMutationFailureState::BeforeRequest
        ));
        assert_eq!(
            hard_failure_source(source).kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(path).expect("unchanged current fixture"), b"1\n");
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_rejects_substituted_expected_inode_without_writing() {
        let expected_directory = tempfile::tempdir().expect("expected temporary directory");
        let target_directory = tempfile::tempdir().expect("target temporary directory");
        for directory in [&expected_directory, &target_directory] {
            create_fixed_record_parents(directory.path());
            fs::write(fixed_record_path(directory.path()), b"0\n").expect("initial fixture");
        }
        let expected_root = open_test_directory(expected_directory.path());
        let target_root = open_test_directory(target_directory.path());
        let target_mount_id = mount_id_for_fd(&target_root).expect("target fixture mount ID");
        let substituted = forwarding_snapshot(&expected_root);
        let mut writer_called = false;

        let failure = set_ipv4_forwarding_at_with(
            &target_root,
            target_mount_id,
            &substituted,
            Ipv4ForwardingState::Enabled,
            |_, _| {
                writer_called = true;
                panic!("substituted inode must not call its writer")
            },
        )
        .expect_err("substituted expected inode must fail before request");
        assert!(!writer_called);
        let (_, state) = failure.into_parts();
        assert!(matches!(
            state,
            Ipv4ForwardingMutationFailureState::BeforeRequest
        ));
        assert_eq!(
            fs::read(fixed_record_path(target_directory.path())).expect("unchanged target fixture"),
            b"0\n"
        );
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_rejects_noncanonical_baseline_without_writing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let path = fixed_record_path(directory.path());
        fs::write(&path, b"2\n").expect("noncanonical fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let expected = forwarding_snapshot(&root);

        let failure = set_ipv4_forwarding_at_with(
            &root,
            mount_id,
            &expected,
            Ipv4ForwardingState::Enabled,
            |_, _| panic!("noncanonical baseline must not call its writer"),
        )
        .expect_err("noncanonical baseline must fail before request");
        let (_, state) = failure.into_parts();
        assert!(matches!(
            state,
            Ipv4ForwardingMutationFailureState::BeforeRequest
        ));
        assert_eq!(fs::read(path).expect("noncanonical fixture"), b"2\n");
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_returns_context_after_partial_request() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let path = fixed_record_path(directory.path());
        fs::write(&path, b"0\n").expect("initial fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let expected = forwarding_snapshot(&root);

        let failure = set_ipv4_forwarding_at_with(
            &root,
            mount_id,
            &expected,
            Ipv4ForwardingState::Enabled,
            |file, bytes| io::Write::write(file, &bytes[..1]),
        )
        .expect_err("partial request must be indeterminate");
        let (source, state) = failure.into_parts();
        assert_eq!(hard_failure_source(source).kind(), io::ErrorKind::WriteZero);
        match state {
            Ipv4ForwardingMutationFailureState::PossiblyWritten {
                before,
                previous,
                target,
            } => {
                assert_eq!(before, expected);
                assert_eq!(previous, Ipv4ForwardingState::Disabled);
                assert_eq!(target, Ipv4ForwardingState::Enabled);
            }
            Ipv4ForwardingMutationFailureState::BeforeRequest => {
                panic!("partial request crossed the write boundary")
            }
        }
        assert_eq!(fs::read(path).expect("partially changed fixture"), b"1\n");
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_treats_failed_post_read_as_possibly_written() {
        let directory = tempfile::tempdir().expect("temporary directory");
        create_fixed_record_parents(directory.path());
        let path = fixed_record_path(directory.path());
        fs::write(&path, b"0\n").expect("initial fixture");
        let root = open_test_directory(directory.path());
        let mount_id = mount_id_for_fd(&root).expect("fixture mount ID");
        let expected = forwarding_snapshot(&root);

        let failure = set_ipv4_forwarding_at_with(
            &root,
            mount_id,
            &expected,
            Ipv4ForwardingState::Enabled,
            |file, bytes| {
                let written = io::Write::write(file, bytes)?;
                file.set_len(3)?;
                Ok(written)
            },
        )
        .expect_err("invalid post-read must be indeterminate");
        let (_, state) = failure.into_parts();
        assert!(matches!(
            state,
            Ipv4ForwardingMutationFailureState::PossiblyWritten {
                previous: Ipv4ForwardingState::Disabled,
                target: Ipv4ForwardingState::Enabled,
                ..
            }
        ));
        assert_eq!(fs::read(path).expect("oversized post-state").len(), 3);
    }

    #[test]
    fn fixed_ipv4_forwarding_writer_live_roundtrip_is_network_namespace_isolated() {
        if env::var_os(LIVE_IPV4_FORWARDING_CHILD_ENV).is_some() {
            let parent_identity = env::var(LIVE_IPV4_FORWARDING_PARENT_NETNS_ENV)
                .ok()
                .and_then(|value| parse_network_namespace_identity(&value))
                .expect("outer test must supply its network namespace identity");
            assert_ne!(
                current_network_namespace_identity(),
                parent_identity,
                "live forwarding writes require a distinct disposable network namespace"
            );
            let proc = open_test_directory(Path::new("/proc"));
            let proc_mount_id = mount_id_for_fd(&proc).expect("proc mount ID");
            let initial = read_ipv4_forwarding_record_at(&proc, proc_mount_id)
                .expect("initial isolated forwarding record");
            let previous = initial
                .canonical_state()
                .expect("canonical isolated forwarding state");
            let disabled = set_ipv4_forwarding_at(
                &proc,
                proc_mount_id,
                &initial,
                Ipv4ForwardingState::Disabled,
            )
            .expect("establish disabled isolated forwarding baseline");
            let enabled = set_ipv4_forwarding_at(
                &proc,
                proc_mount_id,
                disabled.after(),
                Ipv4ForwardingState::Enabled,
            )
            .expect("enable isolated forwarding record");
            assert!(enabled.write_was_requested(), "0 -> 1 must write");
            let disabled_again = set_ipv4_forwarding_at(
                &proc,
                proc_mount_id,
                enabled.after(),
                Ipv4ForwardingState::Disabled,
            )
            .expect("disable isolated forwarding record");
            assert!(disabled_again.write_was_requested(), "1 -> 0 must write");
            let restored =
                set_ipv4_forwarding_at(&proc, proc_mount_id, disabled_again.after(), previous)
                    .expect("restore original isolated forwarding record");
            assert_eq!(restored.after(), &initial);
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let (parent_device, parent_inode) = current_network_namespace_identity();
        let output = match Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg(
                "mounts::tests::fixed_ipv4_forwarding_writer_live_roundtrip_is_network_namespace_isolated",
            )
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_IPV4_FORWARDING_CHILD_ENV, "1")
            .env(
                LIVE_IPV4_FORWARDING_PARENT_NETNS_ENV,
                format!("{parent_device}:{parent_inode}"),
            )
            .env("LC_ALL", "C")
            .output()
        {
            Ok(output) => output,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipped live forwarding roundtrip: unshare is unavailable");
                return;
            }
            Err(source) => panic!("spawn isolated forwarding roundtrip: {source}"),
        };
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live forwarding roundtrip: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated forwarding roundtrip failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn visible_private_mounts_accept_covered_inherited_records() {
        let ids = verify_private_mountinfo(VALID_MOUNTINFO, 21, 31).expect("private mounts");
        assert_eq!(ids.run_mount_id, 21);
        assert_eq!(ids.proc_mount_id, 31);
    }

    #[test]
    fn active_namespace_mountinfo_adds_exactly_two_nsfs_records() {
        const A: &[u8] = b"/run/netns/vpl-0123456789abcdef0123456789abcdef-a";
        const B: &[u8] = b"/run/netns/vpl-0123456789abcdef0123456789abcdef-b";
        let mut active = VALID_MOUNTINFO.to_vec();
        active.extend_from_slice(
            b"40 21 0:4 net:[4026533001] /run/netns/vpl-0123456789abcdef0123456789abcdef-a rw,nosuid,nodev,noexec,relatime - nsfs nsfs rw\n\
41 21 0:4 net:[4026533002] /run/netns/vpl-0123456789abcdef0123456789abcdef-b rw,nosuid,nodev,noexec,relatime - nsfs nsfs rw\n",
        );
        verify_authorized_namespace_mountinfo(
            VALID_MOUNTINFO,
            &active,
            PrivateMountIds {
                run_mount_id: 21,
                proc_mount_id: 31,
            },
            [40, 41],
            [A, B],
        )
        .expect("exact active namespace mount table");

        let changed_baseline = String::from_utf8(active.clone())
            .expect("fixture")
            .replace("10 10 8:1 / / rw,relatime", "10 10 8:1 / / rw");
        assert!(
            verify_authorized_namespace_mountinfo(
                VALID_MOUNTINFO,
                changed_baseline.as_bytes(),
                PrivateMountIds {
                    run_mount_id: 21,
                    proc_mount_id: 31,
                },
                [40, 41],
                [A, B],
            )
            .is_err()
        );
        for changed in [
            String::from_utf8(active.clone())
                .expect("fixture")
                .replace("- nsfs nsfs", "- tmpfs tmpfs"),
            String::from_utf8(active.clone()).expect("fixture").replace(
                "rw,nosuid,nodev,noexec,relatime - nsfs",
                "rw shared:7 - nsfs",
            ),
            String::from_utf8(active.clone())
                .expect("fixture")
                .replace("40 21 0:4", "40 10 0:4"),
            String::from_utf8(active)
                .expect("fixture")
                .replace("abcdef-a", "abcdef-c"),
        ] {
            assert!(
                verify_authorized_namespace_mountinfo(
                    VALID_MOUNTINFO,
                    changed.as_bytes(),
                    PrivateMountIds {
                        run_mount_id: 21,
                        proc_mount_id: 31,
                    },
                    [40, 41],
                    [A, B],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn namespace_mountinfo_rollback_requires_exact_baseline_and_absence() {
        const A: &[u8] = b"/run/netns/vpl-0123456789abcdef0123456789abcdef-a";
        const B: &[u8] = b"/run/netns/vpl-0123456789abcdef0123456789abcdef-b";
        let ids = PrivateMountIds {
            run_mount_id: 21,
            proc_mount_id: 31,
        };
        verify_namespace_mountinfo_rollback(
            VALID_MOUNTINFO,
            VALID_MOUNTINFO,
            ids,
            [40, 41],
            [A, B],
        )
        .expect("exact mount-table rollback");

        let mut leaked = VALID_MOUNTINFO.to_vec();
        leaked.extend_from_slice(
            b"40 21 0:4 net:[4026533001] /run/netns/vpl-0123456789abcdef0123456789abcdef-a rw,nosuid,nodev,noexec,relatime - nsfs nsfs rw\n",
        );
        assert!(
            verify_namespace_mountinfo_rollback(VALID_MOUNTINFO, &leaked, ids, [40, 41], [A, B],)
                .is_err()
        );
    }

    #[test]
    fn every_propagation_relationship_is_rejected() {
        for field in [
            "shared:7",
            "master:7",
            "propagate_from:7",
            "unbindable",
            "future_kernel_field:7",
        ] {
            let changed = String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replacen(
                    "rw,relatime - ext4",
                    &format!("rw,relatime {field} - ext4"),
                    1,
                );
            assert!(verify_private_mountinfo(changed.as_bytes(), 21, 31).is_err());
        }
    }

    #[test]
    fn visible_ids_select_exact_top_records() {
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 20, 31).is_err());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 30).is_ok());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 999).is_err());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 21).is_err());
    }

    #[test]
    fn duplicate_mount_ids_and_malformed_records_are_rejected() {
        let duplicate = String::from_utf8(VALID_MOUNTINFO.to_vec())
            .expect("fixture")
            .replace("31 30 0:31", "21 30 0:31");
        assert!(verify_private_mountinfo(duplicate.as_bytes(), 21, 31).is_err());
        for malformed in [
            b"".as_slice(),
            b"1 1 0:1 / / rw - proc proc rw",
            b"1 1 bad / / rw - proc proc rw\n",
            b"1 1 0:1 / / rw shared:1 proc proc rw\n",
            b"1 1 0:1 / / rw - proc proc rw\n\n",
        ] {
            assert!(verify_private_mountinfo(malformed, 21, 31).is_err());
        }
    }

    #[test]
    fn mount_types_hardening_and_tmpfs_bounds_are_exact() {
        for changed in [
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("- tmpfs tmpfs", "- ramfs ramfs"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("- proc proc", "- sysfs sysfs"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace(
                    "rw,nosuid,nodev,noexec,relatime",
                    "rw,nosuid,nodev,relatime",
                ),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("size=16384k", "size=32768k"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("nr_inodes=4096", "nr_inodes=8192"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("mode=700", "mode=755"),
        ] {
            assert!(verify_private_mountinfo(changed.as_bytes(), 21, 31).is_err());
        }
    }

    #[test]
    fn mountinfo_is_strictly_bounded() {
        let mut oversized = vec![b'x'; MAX_PRIVATE_MOUNTINFO_BYTES];
        oversized.push(b'\n');
        assert!(verify_private_mountinfo(&oversized, 21, 31).is_err());
    }

    #[test]
    fn local_run_guard_rejects_every_non_dot_entry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let empty = File::open(directory.path()).expect("open empty directory");
        verify_empty_directory(&empty).expect("empty directory");
        fs::write(directory.path().join("owned-object"), b"x").expect("write entry");
        assert!(verify_empty_directory(&empty).is_err());
    }

    #[test]
    fn quantities_are_canonical_bounded_and_binary_scaled() {
        assert_eq!(
            parse_quantity(b"16384k").expect("kilobytes"),
            16 * 1024 * 1024
        );
        assert_eq!(parse_quantity(b"16m").expect("megabytes"), 16 * 1024 * 1024);
        assert!(parse_quantity(b"016m").is_err());
        assert!(parse_quantity(b"1t").is_err());
        assert!(parse_quantity(b"18446744073709551615g").is_err());
    }

    #[allow(dead_code)]
    fn routed_mount_typestate_can_only_finish_through_policy_bound_deleted_proof(
        active: PolicyBoundPrivateMounts<AuthorizedActivatedTopology, PolicyEnabledNetworkProof>,
        active_proof: ExactActivatedIpv4NetworkProof,
        endpoint_baselines: [crate::network::PristineNetworkNamespaceObservation; 2],
    ) {
        let (routed, routed_proof) = active
            .install_endpoint_routes(active_proof)
            .unwrap_or_else(|_| std::process::abort());
        let deleted = routed
            .begin_retirement(routed_proof)
            .unwrap_or_else(|_| std::process::abort());
        let _ = deleted
            .finish_forward_policy_teardown(endpoint_baselines)
            .unwrap_or_else(|_| std::process::abort());
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelRouteMountFailure {
        ActiveObservation,
        PlanA,
        BeforeMutationA,
        DeletionBoundA,
        PlanB,
        BeforeMutationB,
        DeletionBoundB,
        RoutedObservation,
    }

    #[test]
    fn every_post_activation_mount_failure_retains_exact_deleted_route_authority() {
        for (failure, expected_routes) in [
            (ModelRouteMountFailure::ActiveObservation, [false, false]),
            (ModelRouteMountFailure::PlanA, [false, false]),
            (ModelRouteMountFailure::BeforeMutationA, [false, false]),
            (ModelRouteMountFailure::DeletionBoundA, [true, false]),
            (ModelRouteMountFailure::PlanB, [true, false]),
            (ModelRouteMountFailure::BeforeMutationB, [true, false]),
            (ModelRouteMountFailure::DeletionBoundB, [true, true]),
            (ModelRouteMountFailure::RoutedObservation, [true, true]),
        ] {
            let state = match failure {
                ModelRouteMountFailure::ActiveObservation
                | ModelRouteMountFailure::PlanA
                | ModelRouteMountFailure::BeforeMutationA => ("deleted", [false, false]),
                ModelRouteMountFailure::DeletionBoundA
                | ModelRouteMountFailure::PlanB
                | ModelRouteMountFailure::BeforeMutationB => ("deleted", [true, false]),
                ModelRouteMountFailure::DeletionBoundB
                | ModelRouteMountFailure::RoutedObservation => ("deleted", [true, true]),
            };
            assert_eq!(state, ("deleted", expected_routes));
            assert_ne!(state.0, "pristine");
        }
    }

    #[test]
    fn route_mount_error_preserves_before_rejected_and_deletion_bound_sources() {
        let before = PrivateMountLinkActivationError::Route(
            FixedEndpointRouteSetError::InstallBeforeMutation(
                crate::topology::route::FixedRouteOperationError::Unsafe("before marker"),
            ),
        );
        let rejected = PrivateMountLinkActivationError::Route(
            FixedEndpointRouteSetError::InstallRejected(nix::libc::EEXIST),
        );
        let deletion_bound = PrivateMountLinkActivationError::Route(
            FixedEndpointRouteSetError::InstallDeletionBound(
                crate::topology::route::FixedRouteOperationError::Unsafe("bound marker"),
            ),
        );

        assert!(before.to_string().contains("before marker"));
        assert!(
            rejected
                .to_string()
                .contains(&nix::libc::EEXIST.to_string())
        );
        assert!(deletion_bound.to_string().contains("bound marker"));
    }

    #[test]
    fn only_mount_uapi_permission_errors_are_policy_denials() {
        for error in [Errno::PERM, Errno::ACCESS] {
            assert!(classify_mount_error("test", error).is_policy_denial());
        }
        for error in [
            Errno::NOENT,
            Errno::INVAL,
            Errno::NOSYS,
            Errno::NODEV,
            Errno::NOMEM,
            Errno::NOSPC,
            Errno::BUSY,
        ] {
            assert!(!classify_mount_error("test", error).is_policy_denial());
        }
    }
}
