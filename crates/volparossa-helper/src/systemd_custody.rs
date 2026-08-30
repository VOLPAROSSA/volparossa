//! Fail-closed systemd descriptor-store startup boundary.
//!
//! Debian 13 systemd may return descriptor-store entries to the service on restart. The current
//! production recovery executor cannot consume stored custody yet, so the executable bootstrap
//! transfers one affine snapshot of the exact inherited descriptor range before any thread or
//! worker can be created. This module consumes that snapshot, canonicalises each pair into typed
//! pidfd/network-namespace ownership, validates identity separation and the exact bounded naming
//! shape, and classifies it against one lock-held durable-journal projection plus a barrier-ordered
//! stable manager inventory. A non-empty set may continue only when every target was already
//! durably `CleanupConfirmed`, both inherited and manager custody are empty, and a fresh barrier
//! plus two stable exact-empty manager snapshots mint one-shot target evidence for the actor's
//! existing manager-absence transition. Every other classification refuses socket publication.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt,
    future::Future,
    io,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::ffi::OsStrExt,
};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use rustix::fs::{
    FileType, Mode, OFlags, ResolveFlags, StatVfsMountFlags, fstat, fstatfs, fstatvfs, open,
    openat2,
};
use tokio::runtime::Runtime;
use volparossa_linux_uapi::{cgroup_v2_id, namespace_type};

use crate::{
    deadline::{HardDeadline, wait_for_process_pidfd_exit},
    ownership_journal::{
        DurableCustodyDescriptorBinding, ProductionOwnershipRuntime, ProductionOwnershipStartup,
        StartupCustodyPhase, StartupCustodyTarget,
    },
    systemd_fdstore::{
        BorrowedCustodyPair, CustodyDescriptorBinding, CustodyFdName, FdStoreError,
        StableServiceCgroupIsolation, StableStartupInventory,
        observe_current_process_startup_inventory,
    },
    worker_v3::acquire_worker_spawn_admission_until,
};

const DESCRIPTORS_PER_CUSTODY_BUNDLE: usize = 2;
const MAX_WORKER_CUSTODY_BUNDLES: usize = 64;
const MAX_INHERITED_CUSTODY_DESCRIPTORS: usize =
    DESCRIPTORS_PER_CUSTODY_BUNDLE * MAX_WORKER_CUSTODY_BUNDLES;
type InheritedBindingMaps = (
    BTreeMap<CustodyFdName, CustodyDescriptorBinding>,
    BTreeMap<CustodyFdName, DurableCustodyDescriptorBinding>,
);
const PID_FS_MAGIC: libc::c_long = 0x5049_4446;
pub(super) const CUSTODY_FD_NAME_PREFIX: &str = "volparossa-custody-v1-";
const CUSTODY_FD_NAME_DIGEST_BYTES: usize = 32;
pub(super) const CUSTODY_FD_NAME_BYTES: usize =
    CUSTODY_FD_NAME_PREFIX.len() + CUSTODY_FD_NAME_DIGEST_BYTES * 2;

#[must_use = "dropping inherited custody releases its exact typed descriptor owners"]
struct InheritedCustodyBundle {
    pidfd: OwnedFd,
    network_namespace: OwnedFd,
    binding: CustodyDescriptorBinding,
}

impl fmt::Debug for InheritedCustodyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritedCustodyBundle(<redacted>)")
    }
}

#[must_use = "dropping inherited custody releases every captured descriptor owner"]
pub(crate) struct InheritedCustody {
    bundles: BTreeMap<CustodyFdName, InheritedCustodyBundle>,
}

impl InheritedCustody {
    fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    fn verify_retained_bindings(&self) -> Result<InheritedBindingMaps, io::Error> {
        let mut manager_bindings = BTreeMap::new();
        let mut durable_bindings = BTreeMap::new();
        for (name, bundle) in &self.bundles {
            bundle.verify_retained_binding()?;
            let custody =
                BorrowedCustodyPair::new(bundle.pidfd.as_fd(), bundle.network_namespace.as_fd())
                    .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
            let manager_binding = CustodyDescriptorBinding::from_custody(custody)
                .map_err(|_| invalid_data("inherited custody descriptor identity is invalid"))?;
            let durable_binding = custody
                .durable_binding()
                .map_err(|_| invalid_data("inherited durable custody binding is invalid"))?;
            if manager_bindings.insert(*name, manager_binding).is_some()
                || durable_bindings.insert(*name, durable_binding).is_some()
            {
                return Err(invalid_data("inherited custody name is duplicated"));
            }
        }
        Ok((manager_bindings, durable_bindings))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupCustodyDisposition {
    ExactPresent,
    ExactNoStoredCustody,
    CleanupConfirmedNoStoredCustody,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ClassifiedStartupCustodyTarget {
    target: StartupCustodyTarget,
    disposition: StartupCustodyDisposition,
}

impl fmt::Debug for ClassifiedStartupCustodyTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClassifiedStartupCustodyTarget(<redacted>)")
    }
}

/// Read-only exact classification which retains every affine inherited descriptor owner.
///
/// This classification is observation-only: it neither authorizes cleanup or adoption nor
/// performs a journal transition. Any durable cleanup authority remains owned by the journal.
#[must_use = "startup custody classification retains affine descriptor owners and is not cleanup authority"]
pub(crate) struct StartupCustodyClassification {
    custody: InheritedCustody,
    manager_inventory: StableStartupInventory,
    classified: Vec<ClassifiedStartupCustodyTarget>,
}

impl StartupCustodyClassification {
    pub(crate) fn is_empty(&self) -> bool {
        self.custody.is_empty() && self.classified.is_empty()
    }

    /// Whether this complete classification is the one narrow restart state which can already be
    /// settled without worker, kernel or descriptor-store mutation.
    pub(crate) fn is_cleanup_confirmed_no_stored_custody_only(&self) -> bool {
        self.custody.is_empty()
            && !self.classified.is_empty()
            && self.classified.iter().all(|entry| {
                entry.target.phase() == StartupCustodyPhase::CleanupConfirmed
                    && entry.disposition
                        == StartupCustodyDisposition::CleanupConfirmedNoStoredCustody
            })
    }
}

/// One-shot exact-set manager-absence evidence for already durable `CleanupConfirmed` records.
///
/// Construction remains private to the fresh manager observation below. The ownership actor can
/// compare and consume only opaque startup targets; this value exposes neither manager inventory,
/// journal coordinates, descriptor identity nor cleanup authority. In particular it cannot prove
/// worker or kernel cleanup for a `MayOwn` record.
#[must_use = "restart manager-absence evidence must be consumed by the retained startup actor"]
pub(crate) struct CleanupConfirmedManagerAbsenceEvidence {
    remaining: Vec<StartupCustodyTarget>,
}

impl CleanupConfirmedManagerAbsenceEvidence {
    pub(crate) fn matches_exact_targets(&self, targets: &[StartupCustodyTarget]) -> bool {
        self.remaining == targets
            && !targets.is_empty()
            && targets
                .iter()
                .all(|target| target.phase() == StartupCustodyPhase::CleanupConfirmed)
    }

    pub(crate) fn consume_exact_target(&mut self, target: &StartupCustodyTarget) -> bool {
        let Some(index) = self
            .remaining
            .iter()
            .position(|candidate| candidate == target)
        else {
            return false;
        };
        self.remaining.remove(index);
        true
    }

    pub(crate) fn is_consumed(&self) -> bool {
        self.remaining.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_targets_for_test(targets: Vec<StartupCustodyTarget>) -> Self {
        Self { remaining: targets }
    }
}

impl fmt::Debug for CleanupConfirmedManagerAbsenceEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanupConfirmedManagerAbsenceEvidence")
            .field("remaining_target_count", &self.remaining.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StartupCustodyClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_present = self
            .classified
            .iter()
            .filter(|entry| entry.disposition == StartupCustodyDisposition::ExactPresent)
            .count();
        let may_own_prepare = self
            .classified
            .iter()
            .filter(|entry| entry.target.phase() == StartupCustodyPhase::MayOwnPrepare)
            .count();
        let cleanup_confirmed = self
            .classified
            .iter()
            .filter(|entry| entry.target.phase() == StartupCustodyPhase::CleanupConfirmed)
            .count();
        let cleanup_confirmed_no_store = self
            .classified
            .iter()
            .filter(|entry| {
                entry.disposition == StartupCustodyDisposition::CleanupConfirmedNoStoredCustody
            })
            .count();
        formatter
            .debug_struct("StartupCustodyClassification")
            .field("target_count", &self.classified.len())
            .field("exact_present_count", &exact_present)
            .field("may_own_prepare_count", &may_own_prepare)
            .field("cleanup_confirmed_count", &cleanup_confirmed)
            .field(
                "cleanup_confirmed_no_store_count",
                &cleanup_confirmed_no_store,
            )
            .field("descriptor_bundle_count", &self.custody.bundles.len())
            .finish_non_exhaustive()
    }
}

/// Fixed failure classes for the exact process-pidfd exit observer used by restart refusal.
///
/// Every failure returns the original affine startup classification. No variant means that the
/// worker, its descendants, namespace resources, journal state, or manager custody are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum InheritedWorkerExitObservationError {
    #[error("startup custody contains no pending worker exit target")]
    NotApplicable,
    #[error("a pending worker has no exact inherited process pidfd")]
    MissingExactCustody,
    #[error("the exact inherited custody binding changed")]
    BindingChanged,
    #[error("the inherited process-pidfd exit deadline elapsed")]
    DeadlineElapsed,
    #[error("the inherited process pidfd returned invalid readiness")]
    InvalidReadiness,
}

/// Affine observation that every exact-present pending target's original process pidfd reached
/// Linux `POLLIN` under one deadline.
///
/// This value deliberately retains the complete classification, manager snapshot, pidfd and
/// network-namespace owners while exposing none of them. It is not worker-descendant, namespace,
/// kernel-cleanup, manager-removal, journal-transition, adoption, or server-start authority.
/// It owns no journal startup guard and performs no fresh journal revalidation; a future settlement
/// must rejoin this evidence to the exact retained guard or to fresh journal and manager evidence.
#[must_use = "an exact inherited worker-exit observation is correlation evidence, not cleanup authority"]
struct ObservedExactInheritedWorkerExitSet {
    classification: StartupCustodyClassification,
    observed_target_count: NonZeroUsize,
}

impl fmt::Debug for ObservedExactInheritedWorkerExitSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedExactInheritedWorkerExitSet")
            .field("observed_target_count", &self.observed_target_count)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

enum InheritedWorkerExitObservationState {
    Observed(ObservedExactInheritedWorkerExitSet),
    Retained {
        error: InheritedWorkerExitObservationError,
        classification: StartupCustodyClassification,
    },
}

/// Opaque all-or-nothing affine result of one observation-only inherited process-pidfd wait.
///
/// The state and every retained owner remain private to this module. No sibling module can unpack
/// success or failure into cleanup, journal, manager, server or raw-descriptor authority.
#[must_use = "every worker-exit observation outcome retains the affine startup classification"]
pub(crate) struct InheritedWorkerExitObservationOutcome {
    state: InheritedWorkerExitObservationState,
}

impl fmt::Debug for InheritedWorkerExitObservationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            InheritedWorkerExitObservationState::Observed(observed) => {
                formatter.debug_tuple("Observed").field(observed).finish()
            }
            InheritedWorkerExitObservationState::Retained {
                error,
                classification,
            } => formatter
                .debug_struct("Retained")
                .field("error", error)
                .field("classification", classification)
                .finish_non_exhaustive(),
        }
    }
}

trait ProcessPidfdExitObserver {
    fn wait_for_exit(
        &mut self,
        pidfd: BorrowedFd<'_>,
        deadline: HardDeadline,
    ) -> Result<(), io::Error>;
}

struct LinuxProcessPidfdExitObserver;

impl ProcessPidfdExitObserver for LinuxProcessPidfdExitObserver {
    fn wait_for_exit(
        &mut self,
        pidfd: BorrowedFd<'_>,
        deadline: HardDeadline,
    ) -> Result<(), io::Error> {
        // The custody source creates this process pidfd with `PidfdFlags::empty()`. On the Debian
        // 13 kernel, `POLLIN` means the last thread in that exact thread group exited; a reaped
        // task additionally reports `POLLHUP`. The shared helper requires `POLLIN`, permits HUP
        // only alongside it, rejects ERR/NVAL/bare HUP, retries EINTR, and rechecks this deadline.
        // This interpretation depends on that private causal source: pidfs typing alone cannot
        // recover whether `PIDFD_THREAD` was requested after a restart.
        wait_for_process_pidfd_exit(&pidfd, deadline)
    }
}

/// Test-facing observation-only seam for exact inherited process-pidfd exit.
///
/// The complete classification is consumed and returned in every outcome. Cleanup-confirmed
/// targets are deliberately skipped: their earlier cleanup transition must not be replaced or
/// repeated by this weaker observation. Every pending `MayOwn` target must have one exact-present
/// inherited bundle before any wait starts, and all such targets must reach `POLLIN` before the
/// same absolute deadline. All pending bindings are then remeasured as one complete pending set.
/// Process-wide semantics rely on the private custody source having used `PidfdFlags::empty()`;
/// pidfs object typing alone cannot prove that flag history. Production calls the same private
/// observer core from its outer refusal composition while retaining the journal and admission
/// guards; it does not call this standalone owner-returning wrapper.
#[allow(dead_code)]
pub(crate) fn observe_exact_inherited_worker_exits(
    classification: StartupCustodyClassification,
    deadline: HardDeadline,
) -> InheritedWorkerExitObservationOutcome {
    let mut observer = LinuxProcessPidfdExitObserver;
    observe_exact_inherited_worker_exits_outcome_with(classification, deadline, &mut observer)
}

fn observe_exact_inherited_worker_exits_outcome_with<Observer: ProcessPidfdExitObserver>(
    classification: StartupCustodyClassification,
    deadline: HardDeadline,
    observer: &mut Observer,
) -> InheritedWorkerExitObservationOutcome {
    let state = match observe_exact_inherited_worker_exits_with(&classification, deadline, observer)
    {
        Ok(observed_target_count) => {
            InheritedWorkerExitObservationState::Observed(ObservedExactInheritedWorkerExitSet {
                classification,
                observed_target_count,
            })
        }
        Err(error) => InheritedWorkerExitObservationState::Retained {
            error,
            classification,
        },
    };
    InheritedWorkerExitObservationOutcome { state }
}

fn observe_exact_inherited_worker_exits_with<Observer: ProcessPidfdExitObserver>(
    classification: &StartupCustodyClassification,
    deadline: HardDeadline,
    observer: &mut Observer,
) -> Result<NonZeroUsize, InheritedWorkerExitObservationError> {
    ensure_exit_observation_deadline(deadline)?;

    // Complete this validation before the first potentially blocking poll. A mixed set can never
    // partially observe present targets and then discover an absent MayOwn target.
    let mut pending = Vec::<(CustodyFdName, StartupCustodyTarget)>::with_capacity(
        classification.classified.len(),
    );
    for entry in &classification.classified {
        if entry.target.phase() == StartupCustodyPhase::CleanupConfirmed {
            continue;
        }
        if entry.disposition != StartupCustodyDisposition::ExactPresent {
            return Err(InheritedWorkerExitObservationError::MissingExactCustody);
        }
        let name = CustodyFdName::from_durable_digest(entry.target.custody_name_digest());
        let bundle = classification
            .custody
            .bundles
            .get(&name)
            .ok_or(InheritedWorkerExitObservationError::MissingExactCustody)?;
        bundle
            .verify_exact_target(&entry.target)
            .map_err(|_| InheritedWorkerExitObservationError::BindingChanged)?;
        pending.push((name, entry.target));
    }
    let observed_target_count = NonZeroUsize::new(pending.len())
        .ok_or(InheritedWorkerExitObservationError::NotApplicable)?;
    ensure_exit_observation_deadline(deadline)?;

    for (name, target) in &pending {
        let bundle = classification
            .custody
            .bundles
            .get(name)
            .ok_or(InheritedWorkerExitObservationError::MissingExactCustody)?;
        bundle
            .verify_exact_target(target)
            .map_err(|_| InheritedWorkerExitObservationError::BindingChanged)?;
        observer
            .wait_for_exit(bundle.pidfd.as_fd(), deadline)
            .map_err(|error| classify_pidfd_wait_error(&error))?;
        bundle
            .verify_exact_target(target)
            .map_err(|_| InheritedWorkerExitObservationError::BindingChanged)?;
    }
    // A later wait can race shared-open-description drift in a bundle already observed above.
    // Revalidate the complete pending set together immediately before minting set evidence.
    for (name, target) in &pending {
        classification
            .custody
            .bundles
            .get(name)
            .ok_or(InheritedWorkerExitObservationError::MissingExactCustody)?
            .verify_exact_target(target)
            .map_err(|_| InheritedWorkerExitObservationError::BindingChanged)?;
    }
    ensure_exit_observation_deadline(deadline)?;
    Ok(observed_target_count)
}

fn ensure_exit_observation_deadline(
    deadline: HardDeadline,
) -> Result<(), InheritedWorkerExitObservationError> {
    deadline
        .ensure_remaining()
        .map_err(|_| InheritedWorkerExitObservationError::DeadlineElapsed)
}

fn classify_pidfd_wait_error(error: &io::Error) -> InheritedWorkerExitObservationError {
    if error.kind() == io::ErrorKind::TimedOut {
        InheritedWorkerExitObservationError::DeadlineElapsed
    } else {
        InheritedWorkerExitObservationError::InvalidReadiness
    }
}

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const PROC_SUPER_MAGIC: i64 = 0x0000_9fa0;
const MAX_PROC_CGROUP_BYTES: usize = 4 * 1_024;
const MAX_CGROUP_COMPONENTS: usize = 256;
const MAX_CGROUP_COMPONENT_BYTES: usize = 255;
const MAX_CGROUP_TYPE_BYTES: usize = 32;
const MAX_CGROUP_STAT_BYTES: usize = 32 * 1_024;
const MAX_CGROUP_PROCS_BYTES: usize = 16 * 1_024;
const MAX_CGROUP_STAT_FIELDS: usize = 256;
const MAX_CGROUP_STAT_KEY_BYTES: usize = 64;
const MAX_CGROUP_PROCS_LINES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PinnedFileIdentity {
    device: u64,
    inode: u64,
}

#[must_use = "a pinned service-cgroup observation owner must remain joined to exit evidence"]
struct PinnedSharedServiceCgroup {
    root: OwnedFd,
    root_identity: PinnedFileIdentity,
    service: OwnedFd,
    service_identity: PinnedFileIdentity,
    kernel_cgroup_id: NonZeroU64,
    pid_namespace: OwnedFd,
    pid_namespace_identity: PinnedFileIdentity,
    cgroup_namespace: OwnedFd,
    cgroup_namespace_identity: PinnedFileIdentity,
    path: Box<[u8]>,
}

impl fmt::Debug for PinnedSharedServiceCgroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedSharedServiceCgroup(<redacted>)")
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SharedServiceCgroupSnapshot {
    control_file_identities: [PinnedFileIdentity; 3],
    stat_fields: BTreeMap<Box<[u8]>, u64>,
    canonical_members: BTreeSet<NonZeroU32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum SharedServiceCgroupObservationError {
    #[error("the shared-service-cgroup observation deadline elapsed")]
    DeadlineElapsed,
    #[error("the exact retained systemd service scope could not be reobserved")]
    ManagerObservation,
    #[error("the retained systemd service scope or current MainPID changed")]
    ManagerScopeChanged,
    #[error("the exact retained descriptor-store inventory changed")]
    ManagerInventoryChanged,
    #[error("the retained service-cgroup isolation contract changed")]
    ManagerIsolationChanged,
    #[error("the current process identity is invalid")]
    InvalidCurrentProcess,
    #[error("the current unified service cgroup could not be pinned exactly")]
    CgroupCapture,
    #[error("a retained worker anchor does not name the pinned shared service cgroup")]
    AnchorMismatch,
    #[error("a retained worker custody binding changed")]
    BindingChanged,
    #[error("the pinned service-cgroup identity changed")]
    CgroupIdentityChanged,
    #[error("the pinned service cgroup is not an exact domain cgroup")]
    InvalidCgroupType,
    #[error("the pinned service cgroup has a live or dying descendant cgroup")]
    DescendantCgroupPresent,
    #[error("the pinned service cgroup contains a process other than the current MainPID")]
    UnexpectedCgroupMember,
    #[error("the pinned service-cgroup observation changed across snapshots")]
    UnstableObservation,
}

struct SharedServiceCgroupSamplingState {
    manager_before: Option<StableStartupInventory>,
    isolation_before: Option<StableServiceCgroupIsolation>,
    cgroup: Option<PinnedSharedServiceCgroup>,
    manager_after: Option<StableStartupInventory>,
    isolation_after: Option<StableServiceCgroupIsolation>,
}

impl fmt::Debug for SharedServiceCgroupSamplingState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedServiceCgroupSamplingState")
            .field("has_manager_before", &self.manager_before.is_some())
            .field("has_isolation_before", &self.isolation_before.is_some())
            .field("has_pinned_cgroup", &self.cgroup.is_some())
            .field("has_manager_after", &self.manager_after.is_some())
            .field("has_isolation_after", &self.isolation_after.is_some())
            .finish_non_exhaustive()
    }
}

enum SharedServiceCgroupSamplingResult {
    Sampled(SharedServiceCgroupSnapshot),
    Failed(SharedServiceCgroupObservationError),
}

#[derive(Eq, PartialEq)]
struct SharedServiceCgroupSamplingBinding {
    observed_target_count: NonZeroUsize,
    manager_bindings: BTreeMap<CustodyFdName, CustodyDescriptorBinding>,
    durable_bindings: BTreeMap<CustodyFdName, DurableCustodyDescriptorBinding>,
    classified: Vec<ClassifiedStartupCustodyTarget>,
}

impl fmt::Debug for SharedServiceCgroupSamplingBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedServiceCgroupSamplingBinding(<redacted>)")
    }
}

/// Returned evidence from the cancellable, borrowing async sampling layer.
///
/// This value never owns the PR68 exit capability. Cancelling the future can discard partial
/// manager/cgroup samples, but cannot drop the caller-owned exit/custody owners. Only the separate
/// synchronous join below may consume those owners.
#[must_use = "a returned cgroup sampling attempt must be joined synchronously or discarded"]
struct SharedServiceCgroupSamplingAttempt {
    deadline: HardDeadline,
    binding: Option<SharedServiceCgroupSamplingBinding>,
    state: SharedServiceCgroupSamplingState,
    result: SharedServiceCgroupSamplingResult,
}

impl fmt::Debug for SharedServiceCgroupSamplingAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self.result {
            SharedServiceCgroupSamplingResult::Sampled(_) => "Sampled",
            SharedServiceCgroupSamplingResult::Failed(_) => "Failed",
        };
        formatter
            .debug_struct("SharedServiceCgroupSamplingAttempt")
            .field("deadline", &self.deadline)
            .field("has_binding", &self.binding.is_some())
            .field("state", &self.state)
            .field("result", &result)
            .finish_non_exhaustive()
    }
}

struct SharedServiceCgroupObservationState {
    exits: ObservedExactInheritedWorkerExitSet,
    sampling: SharedServiceCgroupSamplingAttempt,
}

impl fmt::Debug for SharedServiceCgroupObservationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedServiceCgroupObservationState")
            .field("exits", &self.exits)
            .field("sampling", &self.sampling)
            .finish_non_exhaustive()
    }
}

#[must_use = "shared-cgroup quiescence samples are not cleanup or journal authority"]
struct ObservedSharedServiceCgroupQuiescenceSamples {
    state: SharedServiceCgroupObservationState,
    _joined_snapshot: SharedServiceCgroupSnapshot,
}

impl fmt::Debug for ObservedSharedServiceCgroupQuiescenceSamples {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedSharedServiceCgroupQuiescenceSamples")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

enum SharedServiceCgroupObservationOutcomeState {
    Observed(ObservedSharedServiceCgroupQuiescenceSamples),
    Retained {
        error: SharedServiceCgroupObservationError,
        state: SharedServiceCgroupObservationState,
    },
}

/// Opaque all-or-nothing result of the production restart-refusal cgroup sample join.
///
/// Success retains bounded exact samples, not continuous absence or absence at return. It exposes
/// no PID, path, descriptor, signal, mutation, cleanup, journal, manager-removal, server, or
/// adoption authority. Every returned outcome retains the exact PR68 exit evidence and every
/// complete later observation owner returned by the async layer.
#[must_use = "every shared-cgroup observation outcome retains its affine exit evidence"]
struct SharedServiceCgroupObservationOutcome {
    state: SharedServiceCgroupObservationOutcomeState,
}

impl fmt::Debug for SharedServiceCgroupObservationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            SharedServiceCgroupObservationOutcomeState::Observed(observed) => {
                formatter.debug_tuple("Observed").field(observed).finish()
            }
            SharedServiceCgroupObservationOutcomeState::Retained { error, state } => formatter
                .debug_struct("Retained")
                .field("error", error)
                .field("state", state)
                .finish_non_exhaustive(),
        }
    }
}

trait SharedServiceCgroupSource {
    fn capture(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<PinnedSharedServiceCgroup, SharedServiceCgroupObservationError>;

    fn observe(
        &mut self,
        pinned: &PinnedSharedServiceCgroup,
        current_main_pid: NonZeroU32,
        deadline: HardDeadline,
    ) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError>;

    fn revalidate(
        &mut self,
        pinned: &PinnedSharedServiceCgroup,
        deadline: HardDeadline,
    ) -> Result<(), SharedServiceCgroupObservationError>;
}

trait SharedServiceManagerSource {
    fn reobserve<'a>(
        &'a mut self,
        baseline: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a;

    fn observe_isolation<'a>(
        &'a mut self,
        inventory: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableServiceCgroupIsolation, FdStoreError>> + 'a;
}

struct LinuxSharedServiceManagerSource;

impl SharedServiceManagerSource for LinuxSharedServiceManagerSource {
    fn reobserve<'a>(
        &'a mut self,
        baseline: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a {
        baseline.observe_same_service_scope(deadline)
    }

    fn observe_isolation<'a>(
        &'a mut self,
        inventory: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableServiceCgroupIsolation, FdStoreError>> + 'a {
        inventory.observe_same_service_cgroup_isolation(deadline)
    }
}

struct LinuxSharedServiceCgroupSource;

impl SharedServiceCgroupSource for LinuxSharedServiceCgroupSource {
    fn capture(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<PinnedSharedServiceCgroup, SharedServiceCgroupObservationError> {
        capture_current_shared_service_cgroup(deadline)
    }

    fn observe(
        &mut self,
        pinned: &PinnedSharedServiceCgroup,
        current_main_pid: NonZeroU32,
        deadline: HardDeadline,
    ) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
        observe_pinned_shared_service_cgroup(pinned, current_main_pid, deadline)
    }

    fn revalidate(
        &mut self,
        pinned: &PinnedSharedServiceCgroup,
        deadline: HardDeadline,
    ) -> Result<(), SharedServiceCgroupObservationError> {
        revalidate_pinned_shared_service_cgroup(pinned, deadline)
    }
}

/// Read-only shared-service-cgroup quiescence sampler for production restart refusal.
///
/// The private PR68 success capability is borrowed across every await, so cancellation cannot drop
/// its affine exit/custody owners. The retained unit object path and current `MainPID` are reobserved
/// on both sides without a second `GetUnitByPID` lookup. Two pre-manager and one post-manager
/// cgroup samples must match under one absolute deadline. The production refusal caller runs this
/// synchronously while retaining both the journal owner and worker-spawn admission.
async fn sample_shared_service_cgroup_quiescence(
    exits: &ObservedExactInheritedWorkerExitSet,
    deadline: HardDeadline,
) -> SharedServiceCgroupSamplingAttempt {
    let mut manager = LinuxSharedServiceManagerSource;
    let mut cgroup = LinuxSharedServiceCgroupSource;
    sample_shared_service_cgroup_quiescence_with(exits, deadline, &mut manager, &mut cgroup).await
}

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed sampler retains each partial manager, isolation, and cgroup owner explicitly"
)]
async fn sample_shared_service_cgroup_quiescence_with<
    Manager: SharedServiceManagerSource,
    Source: SharedServiceCgroupSource,
>(
    exits: &ObservedExactInheritedWorkerExitSet,
    deadline: HardDeadline,
    manager: &mut Manager,
    source: &mut Source,
) -> SharedServiceCgroupSamplingAttempt {
    let mut state = SharedServiceCgroupSamplingState {
        manager_before: None,
        isolation_before: None,
        cgroup: None,
        manager_after: None,
        isolation_after: None,
    };
    if ensure_shared_cgroup_deadline(deadline).is_err() {
        return failed_shared_cgroup_sampling(
            SharedServiceCgroupObservationError::DeadlineElapsed,
            deadline,
            None,
            state,
        );
    }
    let binding = match capture_shared_cgroup_sampling_binding(exits) {
        Ok(binding) => binding,
        Err(error) => return failed_shared_cgroup_sampling(error, deadline, None, state),
    };

    let baseline = &exits.classification.manager_inventory;
    let manager_before = manager.reobserve(baseline, deadline).await;
    let Ok(manager_before) = manager_before else {
        let error = classify_manager_observation_error(
            &manager_before.expect_err("manager reobservation failed"),
        );
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    };
    state.manager_before = Some(manager_before);
    let manager_before = state
        .manager_before
        .as_ref()
        .expect("manager-before sample was installed");
    if let Err(error) = verify_exact_manager_scope(exits, baseline, manager_before, deadline) {
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    }
    let isolation_before = manager.observe_isolation(manager_before, deadline).await;
    let Ok(isolation_before) = isolation_before else {
        let error = classify_manager_observation_error(
            &isolation_before.expect_err("isolation reobservation failed"),
        );
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    };
    state.isolation_before = Some(isolation_before);

    let current_main_pid = match current_main_process_id() {
        Ok(pid) => pid,
        Err(error) => {
            return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
        }
    };
    let cgroup = source.capture(deadline);
    let Ok(cgroup) = cgroup else {
        let error = cgroup.expect_err("cgroup capture failed");
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    };
    state.cgroup = Some(cgroup);
    let pinned = state.cgroup.as_ref().expect("cgroup sample was installed");
    if let Err(error) = verify_service_cgroup_isolation(
        state
            .isolation_before
            .as_ref()
            .expect("isolation-before sample was installed"),
        manager_before,
        pinned,
        current_main_pid,
        deadline,
    ) {
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    }
    let stable_snapshot = match observe_initial_shared_service_cgroup_samples(
        exits,
        pinned,
        current_main_pid,
        deadline,
        source,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
        }
    };

    let before = state
        .manager_before
        .as_ref()
        .expect("manager-before sample was installed");
    let manager_after = manager.reobserve(before, deadline).await;
    let Ok(manager_after) = manager_after else {
        let error = classify_manager_observation_error(
            &manager_after.expect_err("manager reobservation failed"),
        );
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    };
    state.manager_after = Some(manager_after);
    let manager_after = state
        .manager_after
        .as_ref()
        .expect("manager-after sample was installed");
    if let Err(error) = verify_exact_manager_scope(exits, before, manager_after, deadline) {
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    }
    let isolation_after = manager.observe_isolation(manager_after, deadline).await;
    let Ok(isolation_after) = isolation_after else {
        let error = classify_manager_observation_error(
            &isolation_after.expect_err("isolation reobservation failed"),
        );
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    };
    state.isolation_after = Some(isolation_after);

    let pinned = state.cgroup.as_ref().expect("cgroup sample was installed");
    if let Err(error) = verify_joined_isolation_samples(
        &state,
        manager_before,
        manager_after,
        pinned,
        current_main_pid,
        deadline,
    ) {
        return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
    }
    let final_snapshot = match observe_final_shared_service_cgroup_sample(
        exits,
        pinned,
        current_main_pid,
        &stable_snapshot,
        deadline,
        source,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return failed_shared_cgroup_sampling(error, deadline, Some(binding), state);
        }
    };
    SharedServiceCgroupSamplingAttempt {
        deadline,
        binding: Some(binding),
        state,
        result: SharedServiceCgroupSamplingResult::Sampled(final_snapshot),
    }
}

fn classify_manager_observation_error(error: &FdStoreError) -> SharedServiceCgroupObservationError {
    if matches!(error, FdStoreError::Deadline)
        || matches!(error, FdStoreError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
    {
        SharedServiceCgroupObservationError::DeadlineElapsed
    } else {
        SharedServiceCgroupObservationError::ManagerObservation
    }
}

fn verify_service_cgroup_isolation(
    isolation: &StableServiceCgroupIsolation,
    inventory: &StableStartupInventory,
    pinned: &PinnedSharedServiceCgroup,
    current_main_pid: NonZeroU32,
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    isolation
        .verify_exact_scope_and_kernel_id(inventory, current_main_pid, pinned.kernel_cgroup_id)
        .map_err(|_| SharedServiceCgroupObservationError::ManagerIsolationChanged)?;
    ensure_shared_cgroup_deadline(deadline)
}

fn verify_joined_isolation_samples(
    state: &SharedServiceCgroupSamplingState,
    manager_before: &StableStartupInventory,
    manager_after: &StableStartupInventory,
    pinned: &PinnedSharedServiceCgroup,
    current_main_pid: NonZeroU32,
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    let isolation_before = state
        .isolation_before
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerIsolationChanged)?;
    let isolation_after = state
        .isolation_after
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerIsolationChanged)?;
    if !isolation_before.matches_exact(isolation_after) {
        return Err(SharedServiceCgroupObservationError::ManagerIsolationChanged);
    }
    verify_service_cgroup_isolation(
        isolation_before,
        manager_before,
        pinned,
        current_main_pid,
        deadline,
    )?;
    verify_service_cgroup_isolation(
        isolation_after,
        manager_after,
        pinned,
        current_main_pid,
        deadline,
    )
}

fn current_main_process_id() -> Result<NonZeroU32, SharedServiceCgroupObservationError> {
    NonZeroU32::new(std::process::id())
        .ok_or(SharedServiceCgroupObservationError::InvalidCurrentProcess)
}

fn verify_exact_manager_scope(
    exits: &ObservedExactInheritedWorkerExitSet,
    baseline: &StableStartupInventory,
    candidate: &StableStartupInventory,
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    if !baseline.matches_current_service_scope(candidate) {
        return Err(SharedServiceCgroupObservationError::ManagerScopeChanged);
    }
    verify_manager_inventory_against_retained_custody(exits, candidate)?;
    ensure_shared_cgroup_deadline(deadline)
}

fn failed_shared_cgroup_sampling(
    error: SharedServiceCgroupObservationError,
    deadline: HardDeadline,
    binding: Option<SharedServiceCgroupSamplingBinding>,
    state: SharedServiceCgroupSamplingState,
) -> SharedServiceCgroupSamplingAttempt {
    SharedServiceCgroupSamplingAttempt {
        deadline,
        binding,
        state,
        result: SharedServiceCgroupSamplingResult::Failed(error),
    }
}

fn capture_shared_cgroup_sampling_binding(
    exits: &ObservedExactInheritedWorkerExitSet,
) -> Result<SharedServiceCgroupSamplingBinding, SharedServiceCgroupObservationError> {
    let (manager_bindings, durable_bindings) = exits
        .classification
        .custody
        .verify_retained_bindings()
        .map_err(|_| SharedServiceCgroupObservationError::BindingChanged)?;
    Ok(SharedServiceCgroupSamplingBinding {
        observed_target_count: exits.observed_target_count,
        manager_bindings,
        durable_bindings,
        classified: exits.classification.classified.clone(),
    })
}

fn observe_initial_shared_service_cgroup_samples<Source: SharedServiceCgroupSource>(
    exits: &ObservedExactInheritedWorkerExitSet,
    pinned: &PinnedSharedServiceCgroup,
    current_main_pid: NonZeroU32,
    deadline: HardDeadline,
    source: &mut Source,
) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
    verify_exit_set_against_shared_cgroup(exits, pinned)?;
    source.revalidate(pinned, deadline)?;
    let first = source.observe(pinned, current_main_pid, deadline)?;

    verify_exit_set_against_shared_cgroup(exits, pinned)?;
    source.revalidate(pinned, deadline)?;
    let second = source.observe(pinned, current_main_pid, deadline)?;
    if first != second {
        return Err(SharedServiceCgroupObservationError::UnstableObservation);
    }

    ensure_shared_cgroup_deadline(deadline)?;
    Ok(second)
}

fn observe_final_shared_service_cgroup_sample<Source: SharedServiceCgroupSource>(
    exits: &ObservedExactInheritedWorkerExitSet,
    pinned: &PinnedSharedServiceCgroup,
    current_main_pid: NonZeroU32,
    baseline: &SharedServiceCgroupSnapshot,
    deadline: HardDeadline,
    source: &mut Source,
) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
    verify_exit_set_against_shared_cgroup(exits, pinned)?;
    source.revalidate(pinned, deadline)?;
    let final_snapshot = source.observe(pinned, current_main_pid, deadline)?;
    if baseline != &final_snapshot {
        return Err(SharedServiceCgroupObservationError::UnstableObservation);
    }
    ensure_shared_cgroup_deadline(deadline)?;
    Ok(final_snapshot)
}

/// Consume the PR68 capability only after the borrowing async sampler returned.
///
/// This join performs no await. It synchronously revalidates the supplied capability and retained
/// manager samples, then takes one last bounded cgroup projection. The production refusal caller
/// runs sampling non-cancellably and keeps process-local worker-spawn admission closed across this
/// join; this seam confers no cleanup or migration authority.
fn join_shared_service_cgroup_quiescence(
    exits: ObservedExactInheritedWorkerExitSet,
    sampling: SharedServiceCgroupSamplingAttempt,
) -> SharedServiceCgroupObservationOutcome {
    let mut source = LinuxSharedServiceCgroupSource;
    join_shared_service_cgroup_quiescence_with(exits, sampling, &mut source)
}

/// Run the complete bounded restart observation while retaining every refusal owner.
///
/// The journal startup guard and process-wide worker-spawn admission remain live from before the
/// first pidfd wait through the final synchronous cgroup join and journal revalidation. The
/// function performs no cleanup, descriptor-store mutation, journal transition, or readiness
/// publication. Even success remains refusal-only evidence.
pub(crate) fn observe_nonempty_restart_custody_for_refusal(
    runtime: &Runtime,
    mut ownership_startup: ProductionOwnershipStartup,
    classification: StartupCustodyClassification,
    deadline: HardDeadline,
) -> Result<(), io::Error> {
    if classification.is_empty() {
        return Err(restart_refusal_incomplete());
    }
    verify_classification_against_locked_journal(&mut ownership_startup, &classification)?;
    let _spawn_admission =
        acquire_worker_spawn_admission_until(deadline).map_err(|_| restart_refusal_incomplete())?;
    verify_classification_against_locked_journal(&mut ownership_startup, &classification)?;

    let mut pidfd_source = LinuxProcessPidfdExitObserver;
    let observed_target_count =
        observe_exact_inherited_worker_exits_with(&classification, deadline, &mut pidfd_source)
            .map_err(|_| restart_refusal_incomplete())?;
    let exits = ObservedExactInheritedWorkerExitSet {
        classification,
        observed_target_count,
    };
    let sampling = runtime.block_on(sample_shared_service_cgroup_quiescence(&exits, deadline));
    let outcome = join_shared_service_cgroup_quiescence(exits, sampling);
    let cgroup_evidence = match &outcome.state {
        SharedServiceCgroupObservationOutcomeState::Observed(evidence) => evidence,
        SharedServiceCgroupObservationOutcomeState::Retained { .. } => {
            return Err(restart_refusal_incomplete());
        }
    };
    verify_classification_against_locked_journal(
        &mut ownership_startup,
        &cgroup_evidence.state.exits.classification,
    )?;
    deadline
        .ensure_remaining()
        .map_err(|_| restart_refusal_incomplete())?;
    Ok(())
}

fn verify_classification_against_locked_journal(
    ownership_startup: &mut ProductionOwnershipStartup,
    classification: &StartupCustodyClassification,
) -> Result<(), io::Error> {
    let targets = ownership_startup
        .revalidate_targets()
        .map_err(|_| restart_refusal_incomplete())?;
    if targets.len() != classification.classified.len()
        || targets
            .iter()
            .zip(&classification.classified)
            .any(|(target, classified)| target != &classified.target)
    {
        return Err(restart_refusal_incomplete());
    }
    Ok(())
}

fn restart_refusal_incomplete() -> io::Error {
    invalid_data("restart custody observation remained incomplete")
}

fn join_shared_service_cgroup_quiescence_with<Source: SharedServiceCgroupSource>(
    exits: ObservedExactInheritedWorkerExitSet,
    sampling: SharedServiceCgroupSamplingAttempt,
    source: &mut Source,
) -> SharedServiceCgroupObservationOutcome {
    let joined = validate_shared_service_cgroup_join(&exits, &sampling, source);
    let state = SharedServiceCgroupObservationState { exits, sampling };
    match joined {
        Ok(joined_snapshot) => SharedServiceCgroupObservationOutcome {
            state: SharedServiceCgroupObservationOutcomeState::Observed(
                ObservedSharedServiceCgroupQuiescenceSamples {
                    state,
                    _joined_snapshot: joined_snapshot,
                },
            ),
        },
        Err(error) => SharedServiceCgroupObservationOutcome {
            state: SharedServiceCgroupObservationOutcomeState::Retained { error, state },
        },
    }
}

fn validate_shared_service_cgroup_join<Source: SharedServiceCgroupSource>(
    exits: &ObservedExactInheritedWorkerExitSet,
    sampling: &SharedServiceCgroupSamplingAttempt,
    source: &mut Source,
) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
    let sampled_snapshot = match &sampling.result {
        SharedServiceCgroupSamplingResult::Sampled(snapshot) => snapshot,
        SharedServiceCgroupSamplingResult::Failed(error) => return Err(*error),
    };
    ensure_shared_cgroup_deadline(sampling.deadline)?;
    verify_shared_cgroup_sampling_binding(exits, sampling)?;
    verify_joined_manager_samples(exits, sampling, sampling.deadline)?;
    let pinned = sampling
        .state
        .cgroup
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    verify_exit_set_against_shared_cgroup(exits, pinned)?;
    source.revalidate(pinned, sampling.deadline)?;
    let current_main_pid = current_main_process_id()?;
    let manager_before = sampling
        .state
        .manager_before
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerObservation)?;
    let manager_after = sampling
        .state
        .manager_after
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerObservation)?;
    verify_joined_isolation_samples(
        &sampling.state,
        manager_before,
        manager_after,
        pinned,
        current_main_pid,
        sampling.deadline,
    )?;
    let joined_snapshot = source.observe(pinned, current_main_pid, sampling.deadline)?;
    if sampled_snapshot != &joined_snapshot {
        return Err(SharedServiceCgroupObservationError::UnstableObservation);
    }
    source.revalidate(pinned, sampling.deadline)?;
    verify_shared_cgroup_sampling_binding(exits, sampling)?;
    verify_joined_manager_samples(exits, sampling, sampling.deadline)?;
    verify_joined_isolation_samples(
        &sampling.state,
        manager_before,
        manager_after,
        pinned,
        current_main_pid,
        sampling.deadline,
    )?;
    verify_exit_set_against_shared_cgroup(exits, pinned)?;
    ensure_shared_cgroup_deadline(sampling.deadline)?;
    Ok(joined_snapshot)
}

fn verify_shared_cgroup_sampling_binding(
    exits: &ObservedExactInheritedWorkerExitSet,
    sampling: &SharedServiceCgroupSamplingAttempt,
) -> Result<(), SharedServiceCgroupObservationError> {
    let binding = sampling
        .binding
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::BindingChanged)?;
    let (manager_bindings, durable_bindings) = exits
        .classification
        .custody
        .verify_retained_bindings()
        .map_err(|_| SharedServiceCgroupObservationError::BindingChanged)?;
    if binding.observed_target_count != exits.observed_target_count
        || binding.manager_bindings != manager_bindings
        || binding.durable_bindings != durable_bindings
        || binding.classified != exits.classification.classified
    {
        return Err(SharedServiceCgroupObservationError::BindingChanged);
    }
    Ok(())
}

fn verify_joined_manager_samples(
    exits: &ObservedExactInheritedWorkerExitSet,
    sampling: &SharedServiceCgroupSamplingAttempt,
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    let before = sampling
        .state
        .manager_before
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerObservation)?;
    let after = sampling
        .state
        .manager_after
        .as_ref()
        .ok_or(SharedServiceCgroupObservationError::ManagerObservation)?;
    verify_exact_manager_scope(
        exits,
        &exits.classification.manager_inventory,
        before,
        deadline,
    )?;
    verify_exact_manager_scope(exits, before, after, deadline)
}

fn verify_exit_set_against_shared_cgroup(
    exits: &ObservedExactInheritedWorkerExitSet,
    pinned: &PinnedSharedServiceCgroup,
) -> Result<(), SharedServiceCgroupObservationError> {
    let service_inode = NonZeroU64::new(pinned.service_identity.inode)
        .ok_or(SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    let mut pending_target_count = 0_usize;
    for entry in &exits.classification.classified {
        if !entry.target.has_valid_recovery_binding() {
            return Err(SharedServiceCgroupObservationError::AnchorMismatch);
        }
        if entry.target.phase() != StartupCustodyPhase::CleanupConfirmed {
            if !entry.target.has_service_cgroup_inode(service_inode) {
                return Err(SharedServiceCgroupObservationError::AnchorMismatch);
            }
            if entry.disposition != StartupCustodyDisposition::ExactPresent {
                return Err(SharedServiceCgroupObservationError::BindingChanged);
            }
            pending_target_count = pending_target_count
                .checked_add(1)
                .ok_or(SharedServiceCgroupObservationError::BindingChanged)?;
        }
        if entry.disposition == StartupCustodyDisposition::ExactPresent {
            let name = CustodyFdName::from_durable_digest(entry.target.custody_name_digest());
            exits
                .classification
                .custody
                .bundles
                .get(&name)
                .ok_or(SharedServiceCgroupObservationError::BindingChanged)?
                .verify_exact_target(&entry.target)
                .map_err(|_| SharedServiceCgroupObservationError::BindingChanged)?;
        }
    }
    if NonZeroUsize::new(pending_target_count) != Some(exits.observed_target_count) {
        return Err(SharedServiceCgroupObservationError::BindingChanged);
    }
    Ok(())
}

fn verify_manager_inventory_against_retained_custody(
    exits: &ObservedExactInheritedWorkerExitSet,
    inventory: &StableStartupInventory,
) -> Result<(), SharedServiceCgroupObservationError> {
    let (manager_bindings, _) = exits
        .classification
        .custody
        .verify_retained_bindings()
        .map_err(|_| SharedServiceCgroupObservationError::BindingChanged)?;
    inventory
        .verify_complete_exact_set(&manager_bindings)
        .map_err(|_| SharedServiceCgroupObservationError::ManagerInventoryChanged)
}

fn capture_current_shared_service_cgroup(
    deadline: HardDeadline,
) -> Result<PinnedSharedServiceCgroup, SharedServiceCgroupObservationError> {
    ensure_shared_cgroup_deadline(deadline)?;
    let path = read_current_unified_cgroup_path(deadline)?;
    if path.as_ref() != b"/" {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let root = open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)?;
    ensure_filesystem_magic(&root, CGROUP2_SUPER_MAGIC)?;
    ensure_read_only_mount(&root)?;
    let root_identity = pinned_file_identity(&root, FileType::Directory)?;
    let service = resolve_pinned_service_cgroup(&root, &path)?;
    ensure_filesystem_magic(&service, CGROUP2_SUPER_MAGIC)?;
    ensure_read_only_mount(&service)?;
    let service_identity = pinned_file_identity(&service, FileType::Directory)?;
    let kernel_cgroup_id =
        cgroup_v2_id(&service).map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)?;
    if service_identity.device != root_identity.device {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let pid_namespace = open(
        "/proc/self/ns/pid",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)?;
    if namespace_type(&pid_namespace).ok() != Some(libc::CLONE_NEWPID) {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let pid_namespace_identity = pinned_namespace_identity(&pid_namespace)?;
    let cgroup_namespace = open(
        "/proc/self/ns/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)?;
    if namespace_type(&cgroup_namespace).ok() != Some(libc::CLONE_NEWCGROUP) {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let cgroup_namespace_identity = pinned_namespace_identity(&cgroup_namespace)?;
    let pinned = PinnedSharedServiceCgroup {
        root,
        root_identity,
        service,
        service_identity,
        kernel_cgroup_id,
        pid_namespace,
        pid_namespace_identity,
        cgroup_namespace,
        cgroup_namespace_identity,
        path,
    };
    revalidate_pinned_shared_service_cgroup(&pinned, deadline)?;
    Ok(pinned)
}

fn revalidate_pinned_shared_service_cgroup(
    pinned: &PinnedSharedServiceCgroup,
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    ensure_shared_cgroup_deadline(deadline)?;
    ensure_filesystem_magic(&pinned.root, CGROUP2_SUPER_MAGIC)?;
    ensure_filesystem_magic(&pinned.service, CGROUP2_SUPER_MAGIC)?;
    ensure_read_only_mount(&pinned.root)?;
    ensure_read_only_mount(&pinned.service)?;
    if pinned_file_identity(&pinned.root, FileType::Directory)? != pinned.root_identity
        || pinned_file_identity(&pinned.service, FileType::Directory)? != pinned.service_identity
        || cgroup_v2_id(&pinned.service).ok() != Some(pinned.kernel_cgroup_id)
        || namespace_type(&pinned.pid_namespace).ok() != Some(libc::CLONE_NEWPID)
        || pinned_namespace_identity(&pinned.pid_namespace)? != pinned.pid_namespace_identity
        || namespace_type(&pinned.cgroup_namespace).ok() != Some(libc::CLONE_NEWCGROUP)
        || pinned_namespace_identity(&pinned.cgroup_namespace)? != pinned.cgroup_namespace_identity
    {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    let current_pid_namespace = open(
        "/proc/self/ns/pid",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if namespace_type(&current_pid_namespace).ok() != Some(libc::CLONE_NEWPID)
        || pinned_namespace_identity(&current_pid_namespace)? != pinned.pid_namespace_identity
    {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    let current_cgroup_namespace = open(
        "/proc/self/ns/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if namespace_type(&current_cgroup_namespace).ok() != Some(libc::CLONE_NEWCGROUP)
        || pinned_namespace_identity(&current_cgroup_namespace)? != pinned.cgroup_namespace_identity
    {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    let current_path = read_current_unified_cgroup_path(deadline)?;
    if current_path != pinned.path {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    let current_service = resolve_pinned_service_cgroup(&pinned.root, &current_path)?;
    if pinned_file_identity(&current_service, FileType::Directory)? != pinned.service_identity {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    ensure_shared_cgroup_deadline(deadline)
}

fn observe_pinned_shared_service_cgroup(
    pinned: &PinnedSharedServiceCgroup,
    current_main_pid: NonZeroU32,
    deadline: HardDeadline,
) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
    revalidate_pinned_shared_service_cgroup(pinned, deadline)?;
    let (type_identity, cgroup_type) = read_pinned_cgroup_file(
        &pinned.service,
        "cgroup.type",
        MAX_CGROUP_TYPE_BYTES,
        deadline,
    )?;
    if cgroup_type.as_slice() != b"domain\n" {
        return Err(SharedServiceCgroupObservationError::InvalidCgroupType);
    }
    let (stat_identity, stat) = read_pinned_cgroup_file(
        &pinned.service,
        "cgroup.stat",
        MAX_CGROUP_STAT_BYTES,
        deadline,
    )?;
    let stat_fields = parse_cgroup_stat(&stat)?;
    let (procs_identity, procs) = read_pinned_cgroup_file(
        &pinned.service,
        "cgroup.procs",
        MAX_CGROUP_PROCS_BYTES,
        deadline,
    )?;
    let canonical_members = parse_cgroup_procs(&procs, current_main_pid)?;
    revalidate_pinned_shared_service_cgroup(pinned, deadline)?;
    Ok(SharedServiceCgroupSnapshot {
        control_file_identities: [type_identity, stat_identity, procs_identity],
        stat_fields,
        canonical_members,
    })
}

fn read_current_unified_cgroup_path(
    deadline: HardDeadline,
) -> Result<Box<[u8]>, SharedServiceCgroupObservationError> {
    let record = open(
        "/proc/self/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)?;
    ensure_filesystem_magic(&record, PROC_SUPER_MAGIC)?;
    let _ = pinned_file_identity(&record, FileType::RegularFile)?;
    parse_unified_cgroup_path(&read_bounded_descriptor(
        &record,
        MAX_PROC_CGROUP_BYTES,
        deadline,
    )?)
}

fn parse_unified_cgroup_path(
    bytes: &[u8],
) -> Result<Box<[u8]>, SharedServiceCgroupObservationError> {
    if bytes.len() < 5
        || !bytes.starts_with(b"0::/")
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let path = &bytes[3..bytes.len() - 1];
    if path == b"/" {
        return Ok(path.into());
    }
    if path.last() == Some(&b'/') {
        return Err(SharedServiceCgroupObservationError::CgroupCapture);
    }
    let mut components = 0_usize;
    for component in path[1..].split(|byte| *byte == b'/') {
        components = components
            .checked_add(1)
            .ok_or(SharedServiceCgroupObservationError::CgroupCapture)?;
        if components > MAX_CGROUP_COMPONENTS
            || component.is_empty()
            || component.len() > MAX_CGROUP_COMPONENT_BYTES
            || matches!(component, b"." | b"..")
            || component.ends_with(b" (deleted)")
            || component
                .iter()
                .any(|byte| *byte == 0 || *byte < b' ' || *byte == 0x7f)
        {
            return Err(SharedServiceCgroupObservationError::CgroupCapture);
        }
    }
    Ok(path.into())
}

fn resolve_pinned_service_cgroup<Fd: AsFd>(
    root: &Fd,
    absolute_path: &[u8],
) -> Result<OwnedFd, SharedServiceCgroupObservationError> {
    let relative = if absolute_path == b"/" {
        &b"."[..]
    } else {
        absolute_path
            .strip_prefix(b"/")
            .ok_or(SharedServiceCgroupObservationError::CgroupCapture)?
    };
    openat2(
        root,
        OsStr::from_bytes(relative),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupCapture)
}

fn read_pinned_cgroup_file<Fd: AsFd>(
    service: &Fd,
    name: &str,
    maximum: usize,
    deadline: HardDeadline,
) -> Result<(PinnedFileIdentity, Vec<u8>), SharedServiceCgroupObservationError> {
    ensure_shared_cgroup_deadline(deadline)?;
    let descriptor = openat2(
        service,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    ensure_filesystem_magic(&descriptor, CGROUP2_SUPER_MAGIC)?;
    let before = pinned_file_identity(&descriptor, FileType::RegularFile)?;
    let bytes = read_bounded_descriptor(&descriptor, maximum, deadline)?;
    if pinned_file_identity(&descriptor, FileType::RegularFile)? != before {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    ensure_shared_cgroup_deadline(deadline)?;
    Ok((before, bytes))
}

fn read_bounded_descriptor<Fd: AsFd>(
    descriptor: &Fd,
    maximum: usize,
    deadline: HardDeadline,
) -> Result<Vec<u8>, SharedServiceCgroupObservationError> {
    const READ_CHUNK_BYTES: usize = 1_024;
    let limit = maximum
        .checked_add(1)
        .ok_or(SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    let mut bytes = Vec::with_capacity(limit);
    while bytes.len() < limit {
        ensure_shared_cgroup_deadline(deadline)?;
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        let remaining = limit - bytes.len();
        let length = rustix::io::pread(
            descriptor,
            &mut chunk[..remaining.min(READ_CHUNK_BYTES)],
            u64::try_from(bytes.len())
                .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?,
        )
        .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
        if length == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    ensure_shared_cgroup_deadline(deadline)?;
    Ok(bytes)
}

fn parse_cgroup_stat(
    bytes: &[u8],
) -> Result<BTreeMap<Box<[u8]>, u64>, SharedServiceCgroupObservationError> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(SharedServiceCgroupObservationError::DescendantCgroupPresent);
    }
    let mut fields = BTreeMap::<Box<[u8]>, u64>::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let separator = line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(SharedServiceCgroupObservationError::DescendantCgroupPresent)?;
        let (key, value_with_separator) = line.split_at(separator);
        let value = value_with_separator
            .strip_prefix(b" ")
            .ok_or(SharedServiceCgroupObservationError::DescendantCgroupPresent)?;
        if key.is_empty()
            || key.len() > MAX_CGROUP_STAT_KEY_BYTES
            || !key
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(SharedServiceCgroupObservationError::DescendantCgroupPresent);
        }
        let value = parse_canonical_decimal_u64(value)
            .ok_or(SharedServiceCgroupObservationError::DescendantCgroupPresent)?;
        if fields.insert(key.into(), value).is_some() || fields.len() > MAX_CGROUP_STAT_FIELDS {
            return Err(SharedServiceCgroupObservationError::DescendantCgroupPresent);
        }
    }
    if fields.get(b"nr_descendants".as_slice()) != Some(&0)
        || fields.get(b"nr_dying_descendants".as_slice()) != Some(&0)
    {
        return Err(SharedServiceCgroupObservationError::DescendantCgroupPresent);
    }
    Ok(fields)
}

fn parse_cgroup_procs(
    bytes: &[u8],
    current_main_pid: NonZeroU32,
) -> Result<BTreeSet<NonZeroU32>, SharedServiceCgroupObservationError> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(SharedServiceCgroupObservationError::UnexpectedCgroupMember);
    }
    let mut members = BTreeSet::new();
    let mut line_count = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        line_count = line_count
            .checked_add(1)
            .ok_or(SharedServiceCgroupObservationError::UnexpectedCgroupMember)?;
        if line_count > MAX_CGROUP_PROCS_LINES {
            return Err(SharedServiceCgroupObservationError::UnexpectedCgroupMember);
        }
        let value = parse_canonical_decimal_u64(line)
            .and_then(|value| u32::try_from(value).ok())
            .and_then(NonZeroU32::new)
            .ok_or(SharedServiceCgroupObservationError::UnexpectedCgroupMember)?;
        if value != current_main_pid {
            return Err(SharedServiceCgroupObservationError::UnexpectedCgroupMember);
        }
        // Linux documents that cgroup.procs can repeat a PID while membership or PID identity
        // changes during iteration. Canonicalising identical current-MainPID lines avoids treating
        // that documented repetition as an extra process; any different value already failed.
        members.insert(value);
    }
    if members.len() != 1 || !members.contains(&current_main_pid) {
        return Err(SharedServiceCgroupObservationError::UnexpectedCgroupMember);
    }
    Ok(members)
}

fn parse_canonical_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
    {
        return None;
    }
    let mut value = 0_u64;
    for byte in bytes {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(*byte - b'0'))?;
    }
    Some(value)
}

fn ensure_filesystem_magic<Fd: AsFd>(
    descriptor: &Fd,
    expected: i64,
) -> Result<(), SharedServiceCgroupObservationError> {
    let filesystem = fstatfs(descriptor)
        .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if i128::from(filesystem.f_type) != i128::from(expected) {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    Ok(())
}

fn ensure_read_only_mount<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<(), SharedServiceCgroupObservationError> {
    let filesystem = fstatvfs(descriptor)
        .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if !filesystem.f_flag.contains(StatVfsMountFlags::RDONLY) {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    Ok(())
}

fn pinned_file_identity<Fd: AsFd>(
    descriptor: &Fd,
    expected_type: FileType,
) -> Result<PinnedFileIdentity, SharedServiceCgroupObservationError> {
    let metadata = fstat(descriptor)
        .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if FileType::from_raw_mode(metadata.st_mode) != expected_type
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    Ok(PinnedFileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn pinned_namespace_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<PinnedFileIdentity, SharedServiceCgroupObservationError> {
    let metadata = fstat(descriptor)
        .map_err(|_| SharedServiceCgroupObservationError::CgroupIdentityChanged)?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(SharedServiceCgroupObservationError::CgroupIdentityChanged);
    }
    Ok(PinnedFileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn ensure_shared_cgroup_deadline(
    deadline: HardDeadline,
) -> Result<(), SharedServiceCgroupObservationError> {
    deadline
        .ensure_remaining()
        .map_err(|_| SharedServiceCgroupObservationError::DeadlineElapsed)
}

/// Consume the complete affine systemd startup snapshot into typed custody bundles.
///
/// The audited Linux-UAPI boundary has already taken exact ownership of systemd's raw descriptor
/// range. This crate keeps `unsafe_code = "forbid"`; it only consumes the resulting affine
/// `OwnedFd` set and never reopens or duplicates a descriptor by number.
pub(crate) fn capture_inherited_custody(
    inherited: volparossa_linux_uapi::SystemdListenFdSet,
) -> Result<InheritedCustody, io::Error> {
    let expected_count = inherited.len();
    let (fd_names, received) = inherited.into_parts();
    if received.len() != expected_count {
        return Err(invalid_data("inherited descriptor count changed"));
    }
    if expected_count == 0 {
        if fd_names.is_some() {
            return Err(invalid_data("absent descriptor names are inconsistent"));
        }
        return Ok(InheritedCustody {
            bundles: BTreeMap::new(),
        });
    }

    let fd_names = fd_names
        .as_deref()
        .ok_or_else(|| invalid_data("inherited descriptor names are absent"))?;
    let names = advertised_descriptor_names_from(fd_names, expected_count)?;
    let entries = names
        .into_iter()
        .zip(received)
        .map(|(name, descriptor)| (Some(name), descriptor))
        .collect::<Vec<_>>();
    validate_inherited_custody(entries.len(), entries)
}

/// Stable manager evidence bound to the locally remeasured affine inherited owners.
///
/// The journal must be independently revalidated after this async observation and before the
/// value may be consumed by [`classify_startup_custody`].
#[must_use = "manager and inherited evidence must be joined to the revalidated journal snapshot"]
pub(crate) struct VerifiedStartupCustodyInventory {
    manager_inventory: StableStartupInventory,
    manager_bindings: BTreeMap<CustodyFdName, CustodyDescriptorBinding>,
    durable_bindings: BTreeMap<CustodyFdName, DurableCustodyDescriptorBinding>,
}

impl fmt::Debug for VerifiedStartupCustodyInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedStartupCustodyInventory(<redacted>)")
    }
}

/// Observe the exact inherited and manager sets while the caller retains the journal startup lock.
///
/// The local bindings are measured immediately before the manager barrier and again after both
/// complete manager snapshots. Every present manager entry must be exactly one inherited owner.
pub(crate) async fn observe_startup_custody_inventory(
    custody: &InheritedCustody,
    deadline: HardDeadline,
) -> Result<VerifiedStartupCustodyInventory, io::Error> {
    let (manager_before, durable_before) = custody.verify_retained_bindings()?;
    let manager_inventory = observe_current_process_startup_inventory(deadline)
        .await
        .map_err(|_| invalid_data("systemd startup inventory could not be observed exactly"))?;
    let (manager_after, durable_after) = custody.verify_retained_bindings()?;
    if manager_before != manager_after || durable_before != durable_after {
        return Err(invalid_data(
            "inherited custody descriptor identity changed during observation",
        ));
    }
    manager_inventory
        .verify_complete_exact_set(&manager_after)
        .map_err(|_| invalid_data("systemd startup inventory does not match inherited custody"))?;
    Ok(VerifiedStartupCustodyInventory {
        manager_inventory,
        manager_bindings: manager_after,
        durable_bindings: durable_after,
    })
}

/// Join stable manager/inherited evidence to one revalidated lock-held journal projection.
///
/// A final local remeasurement closes the short interval used to revalidate the journal. The
/// result remains observation-only and retains the affine owners plus the stable manager evidence.
pub(crate) fn classify_startup_custody(
    custody: InheritedCustody,
    targets: &[StartupCustodyTarget],
    verified: VerifiedStartupCustodyInventory,
    deadline: HardDeadline,
) -> Result<StartupCustodyClassification, io::Error> {
    deadline
        .ensure_remaining()
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "startup custody deadline elapsed"))?;
    let (manager_final, durable_final) = custody.verify_retained_bindings()?;
    if manager_final != verified.manager_bindings || durable_final != verified.durable_bindings {
        return Err(invalid_data(
            "inherited custody descriptor identity changed after journal revalidation",
        ));
    }
    let classified = classify_journal_targets(targets, &durable_final)?;
    deadline
        .ensure_remaining()
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "startup custody deadline elapsed"))?;
    Ok(StartupCustodyClassification {
        custody,
        manager_inventory: verified.manager_inventory,
        classified,
    })
}

trait CleanupConfirmedManagerSource {
    fn reobserve<'a>(
        &'a mut self,
        baseline: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a;
}

struct LinuxCleanupConfirmedManagerSource;

impl CleanupConfirmedManagerSource for LinuxCleanupConfirmedManagerSource {
    fn reobserve<'a>(
        &'a mut self,
        baseline: &'a StableStartupInventory,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a {
        baseline.observe_same_service_scope(deadline)
    }
}

/// Settle only a complete non-empty set of durable `CleanupConfirmed` records whose inherited and
/// manager custody were already empty and remain exactly empty after a fresh manager barrier plus
/// two uncached stable snapshots.
///
/// The lock-held journal is revalidated before and after the asynchronous observation. Process-wide
/// worker-spawn admission remains closed through actor continuation. The evidence authorizes only
/// the existing `CleanupConfirmed -> Absent` manager-absence transition; the installed cleanup
/// executor continues to refuse every `MayOwnCustody` and `MayOwnPrepare` recovery request.
pub(crate) fn settle_cleanup_confirmed_restart_absence(
    runtime: &Runtime,
    mut ownership_startup: ProductionOwnershipStartup,
    classification: StartupCustodyClassification,
    deadline: HardDeadline,
) -> Result<ProductionOwnershipRuntime, io::Error> {
    if !classification.is_cleanup_confirmed_no_stored_custody_only() {
        return Err(restart_settlement_incomplete());
    }
    verify_classification_against_locked_journal(&mut ownership_startup, &classification)?;
    let _spawn_admission = acquire_worker_spawn_admission_until(deadline)
        .map_err(|_| restart_settlement_incomplete())?;
    verify_classification_against_locked_journal(&mut ownership_startup, &classification)?;

    let mut manager = LinuxCleanupConfirmedManagerSource;
    let evidence = runtime
        .block_on(observe_cleanup_confirmed_manager_absence_with(
            &classification,
            deadline,
            &mut manager,
        ))
        .map_err(|_| restart_settlement_incomplete())?;
    verify_classification_against_locked_journal(&mut ownership_startup, &classification)?;
    deadline
        .ensure_remaining()
        .map_err(|_| restart_settlement_incomplete())?;
    drop(classification);

    ownership_startup
        .continue_cleanup_confirmed_absent(evidence)
        .map_err(|_| restart_settlement_incomplete())
}

async fn observe_cleanup_confirmed_manager_absence_with<Manager: CleanupConfirmedManagerSource>(
    classification: &StartupCustodyClassification,
    deadline: HardDeadline,
    manager: &mut Manager,
) -> Result<CleanupConfirmedManagerAbsenceEvidence, io::Error> {
    deadline
        .ensure_remaining()
        .map_err(|_| restart_settlement_incomplete())?;
    if !classification.is_cleanup_confirmed_no_stored_custody_only() {
        return Err(restart_settlement_incomplete());
    }
    let (manager_bindings, durable_bindings) = classification
        .custody
        .verify_retained_bindings()
        .map_err(|_| restart_settlement_incomplete())?;
    if !manager_bindings.is_empty() || !durable_bindings.is_empty() {
        return Err(restart_settlement_incomplete());
    }
    classification
        .manager_inventory
        .verify_complete_exact_set(&manager_bindings)
        .map_err(|_| restart_settlement_incomplete())?;

    // This adapter sends a new manager barrier and takes two new uncached snapshots of the exact
    // retained service object. Equality includes manager incarnation, object path, MainPID,
    // service policy, complete empty inventory and the retained notify endpoint.
    let fresh = manager
        .reobserve(&classification.manager_inventory, deadline)
        .await
        .map_err(|_| restart_settlement_incomplete())?;
    if fresh != classification.manager_inventory
        || !classification
            .manager_inventory
            .matches_current_service_scope(&fresh)
    {
        return Err(restart_settlement_incomplete());
    }
    fresh
        .verify_complete_exact_set(&manager_bindings)
        .map_err(|_| restart_settlement_incomplete())?;
    let (manager_after, durable_after) = classification
        .custody
        .verify_retained_bindings()
        .map_err(|_| restart_settlement_incomplete())?;
    if manager_after != manager_bindings || durable_after != durable_bindings {
        return Err(restart_settlement_incomplete());
    }
    deadline
        .ensure_remaining()
        .map_err(|_| restart_settlement_incomplete())?;

    Ok(CleanupConfirmedManagerAbsenceEvidence {
        remaining: classification
            .classified
            .iter()
            .map(|entry| entry.target)
            .collect(),
    })
}

fn restart_settlement_incomplete() -> io::Error {
    invalid_data("cleanup-confirmed restart settlement remained incomplete")
}

fn classify_journal_targets(
    targets: &[StartupCustodyTarget],
    inherited: &BTreeMap<CustodyFdName, DurableCustodyDescriptorBinding>,
) -> Result<Vec<ClassifiedStartupCustodyTarget>, io::Error> {
    if targets.len() > MAX_WORKER_CUSTODY_BUNDLES {
        return Err(invalid_data("startup custody target set is oversized"));
    }
    let mut named_targets = BTreeMap::<CustodyFdName, &StartupCustodyTarget>::new();
    let mut prior_targets = Vec::<&StartupCustodyTarget>::with_capacity(targets.len());
    for target in targets {
        if !target.has_valid_recovery_binding() {
            return Err(invalid_data(
                "startup journal custody target has an invalid recovery-anchor binding",
            ));
        }
        if prior_targets
            .iter()
            .any(|prior| prior.overlaps_binding(&target.durable_binding()))
        {
            return Err(invalid_data("startup journal custody identity is reused"));
        }
        let name = CustodyFdName::from_durable_digest(target.custody_name_digest());
        if named_targets.insert(name, target).is_some() {
            return Err(invalid_data("startup journal custody name is duplicated"));
        }
        prior_targets.push(target);
    }
    if inherited
        .keys()
        .any(|name| !named_targets.contains_key(name))
    {
        return Err(invalid_data(
            "inherited custody has no exact durable journal target",
        ));
    }

    let mut classified = Vec::with_capacity(targets.len());
    for target in targets {
        let name = CustodyFdName::from_durable_digest(target.custody_name_digest());
        let disposition = match inherited.get(&name) {
            Some(binding) if target.matches_binding(binding) => {
                StartupCustodyDisposition::ExactPresent
            }
            Some(_) => {
                return Err(invalid_data(
                    "inherited custody does not match its durable journal binding",
                ));
            }
            None if inherited
                .values()
                .any(|binding| target.overlaps_binding(binding)) =>
            {
                return Err(invalid_data(
                    "durable journal custody exists under another inherited name",
                ));
            }
            None => match target.phase() {
                StartupCustodyPhase::MayOwnCustody => {
                    StartupCustodyDisposition::ExactNoStoredCustody
                }
                StartupCustodyPhase::CleanupConfirmed => {
                    StartupCustodyDisposition::CleanupConfirmedNoStoredCustody
                }
                StartupCustodyPhase::MayOwnPrepare => {
                    return Err(invalid_data(
                        "MayOwnPrepare custody is absent from the inherited and manager sets",
                    ));
                }
            },
        };
        classified.push(ClassifiedStartupCustodyTarget {
            target: *target,
            disposition,
        });
    }
    Ok(classified)
}

#[cfg(test)]
fn refuse_unrecoverable_custody(custody: &InheritedCustody) -> Result<(), io::Error> {
    if custody.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restart custody exists but no production recovery executor is installed",
        ))
    }
}

fn advertised_descriptor_names_from(
    fd_names: &OsStr,
    count: usize,
) -> Result<Vec<CustodyFdName>, io::Error> {
    if count == 0
        || count > MAX_INHERITED_CUSTODY_DESCRIPTORS
        || count % DESCRIPTORS_PER_CUSTODY_BUNDLE != 0
    {
        return Err(invalid_data("systemd descriptor count is invalid"));
    }
    let names = fd_names
        .to_str()
        .ok_or_else(|| invalid_data("systemd descriptor names are not UTF-8"))?;
    let expected_name_bytes = count
        .checked_mul(CUSTODY_FD_NAME_BYTES)
        .and_then(|bytes| bytes.checked_add(count - 1))
        .ok_or_else(|| invalid_data("systemd descriptor names are invalid"))?;
    if names.len() != expected_name_bytes {
        return Err(invalid_data("systemd descriptor names are invalid"));
    }
    let mut parsed = Vec::with_capacity(count);
    for name in names.split(':') {
        if parsed.len() == count {
            return Err(invalid_data("systemd descriptor names are invalid"));
        }
        parsed.push(
            CustodyFdName::parse(name)
                .map_err(|_| invalid_data("systemd descriptor names are invalid"))?,
        );
    }
    if parsed.len() != count {
        return Err(invalid_data("systemd descriptor names are invalid"));
    }
    Ok(parsed)
}

fn validate_inherited_custody(
    expected_count: usize,
    entries: Vec<(Option<CustodyFdName>, OwnedFd)>,
) -> Result<InheritedCustody, io::Error> {
    if expected_count == 0
        || expected_count > MAX_INHERITED_CUSTODY_DESCRIPTORS
        || entries.len() != expected_count
    {
        return Err(invalid_data("inherited descriptor count changed"));
    }
    let mut grouped = BTreeMap::<CustodyFdName, Vec<OwnedFd>>::new();
    for (name, descriptor) in entries {
        fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| invalid_data("inherited descriptor flags could not be sealed"))?;
        let name = name.ok_or_else(|| invalid_data("inherited descriptor name is invalid"))?;
        grouped.entry(name).or_default().push(descriptor);
    }
    let mut bundles = BTreeMap::new();
    let mut observed_bindings = Vec::<CustodyDescriptorBinding>::new();
    for (name, descriptors) in grouped {
        let descriptors: [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE] = descriptors
            .try_into()
            .map_err(|_| invalid_data("inherited custody bundle is incomplete"))?;
        let bundle = InheritedCustodyBundle::from_unordered(descriptors)?;
        bundle.verify_retained_binding()?;
        if observed_bindings
            .iter()
            .any(|binding| binding.overlaps(&bundle.binding))
        {
            return Err(invalid_data(
                "inherited custody descriptor identity is reused",
            ));
        }
        observed_bindings.push(bundle.binding.clone());
        bundles.insert(name, bundle);
    }
    if bundles.len() > MAX_WORKER_CUSTODY_BUNDLES
        || bundles.len() * DESCRIPTORS_PER_CUSTODY_BUNDLE != expected_count
    {
        return Err(invalid_data("inherited custody bundle count is invalid"));
    }
    Ok(InheritedCustody { bundles })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InheritedDescriptorRole {
    Pidfd,
    NetworkNamespace,
}

impl InheritedCustodyBundle {
    fn from_unordered(
        descriptors: [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE],
    ) -> Result<Self, io::Error> {
        let [first, second] = descriptors;
        let first_role = inherited_descriptor_role(first.as_fd())?;
        let second_role = inherited_descriptor_role(second.as_fd())?;
        let (pidfd, network_namespace) = match (first_role, second_role) {
            (InheritedDescriptorRole::Pidfd, InheritedDescriptorRole::NetworkNamespace) => {
                (first, second)
            }
            (InheritedDescriptorRole::NetworkNamespace, InheritedDescriptorRole::Pidfd) => {
                (second, first)
            }
            _ => {
                return Err(invalid_data(
                    "inherited custody roles are incomplete or ambiguous",
                ));
            }
        };
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
        let binding = CustodyDescriptorBinding::from_custody(custody)
            .map_err(|_| invalid_data("inherited custody descriptor identity is invalid"))?;
        Ok(Self {
            pidfd,
            network_namespace,
            binding,
        })
    }

    fn verify_retained_binding(&self) -> Result<(), io::Error> {
        let custody = BorrowedCustodyPair::new(self.pidfd.as_fd(), self.network_namespace.as_fd())
            .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
        let observed = CustodyDescriptorBinding::from_custody(custody)
            .map_err(|_| invalid_data("inherited custody descriptor identity is invalid"))?;
        if observed == self.binding {
            Ok(())
        } else {
            Err(invalid_data(
                "inherited custody descriptor identity changed",
            ))
        }
    }

    /// Re-read the exact role-ordered pair and join it to one complete durable startup target.
    fn verify_exact_target(&self, target: &StartupCustodyTarget) -> Result<(), io::Error> {
        if !target.has_valid_recovery_binding() {
            return Err(invalid_data(
                "inherited custody target has an invalid recovery-anchor binding",
            ));
        }
        self.verify_retained_binding()?;
        let custody = BorrowedCustodyPair::new(self.pidfd.as_fd(), self.network_namespace.as_fd())
            .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
        let durable = custody
            .durable_binding()
            .map_err(|_| invalid_data("inherited durable custody binding is invalid"))?;
        if !target.matches_binding(&durable) {
            return Err(invalid_data(
                "inherited custody no longer matches its complete durable target",
            ));
        }
        Ok(())
    }
}

fn inherited_descriptor_role(
    descriptor: BorrowedFd<'_>,
) -> Result<InheritedDescriptorRole, io::Error> {
    let pidfd = fstatfs(descriptor).map_err(rustix_io)?.f_type == PID_FS_MAGIC;
    if pidfd {
        return Ok(InheritedDescriptorRole::Pidfd);
    }
    match namespace_type(&descriptor) {
        Ok(namespace_type) if namespace_type == libc::CLONE_NEWNET => {
            Ok(InheritedDescriptorRole::NetworkNamespace)
        }
        Ok(_) | Err(_) => Err(invalid_data(
            "inherited descriptor has no unique custody role",
        )),
    }
}

pub(super) fn custody_fd_name_is_valid(value: &str) -> bool {
    value.len() == CUSTODY_FD_NAME_BYTES
        && value
            .strip_prefix(CUSTODY_FD_NAME_PREFIX)
            .is_some_and(|digest| {
                digest
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        ffi::OsString,
        fs::File,
        num::{NonZeroU32, NonZeroU64},
        os::fd::{AsRawFd, OwnedFd},
        os::unix::ffi::OsStringExt,
        process::Command,
        rc::Rc,
        thread,
        time::Duration,
    };

    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use rustix::process::{PidfdFlags, getpid, pidfd_open};
    use tempfile::tempfile;

    use super::*;
    use crate::ownership_journal::{
        DurableCustodyDescriptorIdentity, DurableCustodyDescriptorIdentityParts,
        DurableCustodyNameDigest, DurablePrepareAnchor, DurablePrepareAnchorParts,
        durable_prepare_anchor_from_parts,
    };
    use crate::systemd_fdstore::{
        stable_service_cgroup_isolation_for_test, stable_startup_inventory_for_test,
    };
    use volparossa_linux_uapi::duplicate_descriptor_cloexec;

    const TEST_WAIT: Duration = Duration::from_secs(2);

    #[derive(Default)]
    struct FakeProcessPidfdExitObserver {
        calls: usize,
        deadlines: Vec<HardDeadline>,
        results: VecDeque<Result<(), io::ErrorKind>>,
        delay: Duration,
        mutate_status_flags_on_call: Option<(usize, OwnedFd)>,
    }

    impl ProcessPidfdExitObserver for FakeProcessPidfdExitObserver {
        fn wait_for_exit(
            &mut self,
            pidfd: BorrowedFd<'_>,
            deadline: HardDeadline,
        ) -> Result<(), io::Error> {
            assert_eq!(
                inherited_descriptor_role(pidfd).expect("fake receives a kernel-typed pidfd"),
                InheritedDescriptorRole::Pidfd
            );
            self.calls += 1;
            self.deadlines.push(deadline);
            if self
                .mutate_status_flags_on_call
                .as_ref()
                .is_some_and(|(call, _)| *call == self.calls)
            {
                let (_, alias) = self
                    .mutate_status_flags_on_call
                    .take()
                    .expect("matching scripted mutation");
                let flags = OFlag::from_bits_truncate(
                    fcntl(&alias, FcntlArg::F_GETFL).expect("read retained alias flags"),
                );
                fcntl(&alias, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
                    .expect("mutate retained descriptor identity");
            }
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            match self.results.pop_front().unwrap_or(Ok(())) {
                Ok(()) => Ok(()),
                Err(kind) => Err(io::Error::new(kind, "scripted pidfd observation failure")),
            }
        }
    }

    fn descriptor() -> OwnedFd {
        tempfile().expect("create descriptor fixture").into()
    }

    fn pidfd() -> OwnedFd {
        pidfd_open(getpid(), PidfdFlags::empty()).expect("open current-process pidfd")
    }

    fn network_namespace() -> OwnedFd {
        File::open("/proc/self/ns/net")
            .expect("open current network namespace")
            .into()
    }

    fn custody_name(seed: u8) -> String {
        format!(
            "{CUSTODY_FD_NAME_PREFIX}{}",
            format!("{seed:02x}").repeat(CUSTODY_FD_NAME_DIGEST_BYTES)
        )
    }

    fn typed_custody_name(seed: u8) -> CustodyFdName {
        CustodyFdName::parse(&custody_name(seed)).expect("valid typed custody name")
    }

    fn synthetic_durable_binding(seed: u32) -> DurableCustodyDescriptorBinding {
        let identity = |offset: u32| {
            DurableCustodyDescriptorIdentity::try_from_parts(
                DurableCustodyDescriptorIdentityParts {
                    mode: NonZeroU32::new(0o100_600).expect("nonzero mode"),
                    device_major: seed,
                    device_minor: offset,
                    inode: NonZeroU64::new(u64::from(seed) * 100 + u64::from(offset))
                        .expect("nonzero inode"),
                    special_device_major: seed + 1,
                    special_device_minor: offset,
                    status_flags: 0,
                },
            )
            .expect("synthetic durable descriptor identity")
        };
        DurableCustodyDescriptorBinding::try_from_role_ordered(identity(1), identity(2))
            .expect("distinct synthetic durable binding")
    }

    fn startup_target(
        seed: u8,
        phase: StartupCustodyPhase,
        binding: DurableCustodyDescriptorBinding,
    ) -> StartupCustodyTarget {
        let namespace = network_namespace();
        let status = fstat(&namespace).expect("stat current network namespace");
        startup_target_with_anchor(
            seed,
            phase,
            durable_anchor(seed, status.st_dev, status.st_ino),
            binding,
        )
    }

    fn startup_target_with_anchor(
        seed: u8,
        phase: StartupCustodyPhase,
        recovery_anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
    ) -> StartupCustodyTarget {
        StartupCustodyTarget::for_test(
            phase,
            DurableCustodyNameDigest::for_test([seed; CUSTODY_FD_NAME_DIGEST_BYTES]),
            recovery_anchor,
            binding,
        )
    }

    fn durable_anchor(seed: u8, network_device: u64, network_inode: u64) -> DurablePrepareAnchor {
        durable_prepare_anchor_from_parts(DurablePrepareAnchorParts {
            boot_id: [seed; 16],
            pid: NonZeroU32::new(u32::from(seed)).expect("nonzero test pid"),
            process_start_ticks: NonZeroU64::new(u64::from(seed) + 10)
                .expect("nonzero start ticks"),
            network_namespace_device: NonZeroU64::new(network_device)
                .expect("nonzero namespace device"),
            network_namespace_inode: NonZeroU64::new(network_inode)
                .expect("nonzero namespace inode"),
            executable_device: NonZeroU64::new(u64::from(seed) + 20)
                .expect("nonzero executable device"),
            executable_inode: NonZeroU64::new(u64::from(seed) + 30)
                .expect("nonzero executable inode"),
            service_cgroup_inode: NonZeroU64::new(u64::from(seed) + 40)
                .expect("nonzero cgroup inode"),
        })
        .expect("valid durable anchor")
    }

    fn synthetic_startup_target(
        name_seed: u8,
        phase: StartupCustodyPhase,
        binding_seed: u32,
    ) -> StartupCustodyTarget {
        let binding = synthetic_durable_binding(binding_seed);
        let network_device = rustix::fs::makedev(binding_seed, 2);
        let network_inode = u64::from(binding_seed) * 100 + 2;
        startup_target_with_anchor(
            name_seed,
            phase,
            durable_anchor(name_seed, network_device, network_inode),
            binding,
        )
    }

    fn captured_custody(seed: u8) -> InheritedCustody {
        validate_inherited_custody(
            2,
            vec![
                (Some(typed_custody_name(seed)), pidfd()),
                (Some(typed_custody_name(seed)), network_namespace()),
            ],
        )
        .expect("capture exact custody fixture")
    }

    fn captured_child_custody(seed: u8, child: &std::process::Child) -> InheritedCustody {
        let pidfd = pidfd_open(rustix::process::Pid::from_child(child), PidfdFlags::empty())
            .expect("pin exact child process");
        validate_inherited_custody(
            2,
            vec![
                (Some(typed_custody_name(seed)), pidfd),
                (Some(typed_custody_name(seed)), network_namespace()),
            ],
        )
        .expect("capture exact child custody fixture")
    }

    fn startup_classification(
        custody: InheritedCustody,
        targets: &[StartupCustodyTarget],
    ) -> StartupCustodyClassification {
        let (manager_bindings, durable_bindings) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture bindings");
        let manager_inventory = stable_startup_inventory_for_test(&manager_bindings);
        manager_inventory
            .verify_complete_exact_set(&manager_bindings)
            .expect("exact fixture manager inventory");
        let classified = classify_journal_targets(targets, &durable_bindings)
            .expect("exact fixture target classification");
        StartupCustodyClassification {
            custody,
            manager_inventory,
            classified,
        }
    }

    struct FakeCleanupConfirmedManagerSource {
        result: Option<Result<StableStartupInventory, FdStoreError>>,
        deadlines: Vec<HardDeadline>,
    }

    impl CleanupConfirmedManagerSource for FakeCleanupConfirmedManagerSource {
        fn reobserve<'a>(
            &'a mut self,
            _baseline: &'a StableStartupInventory,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a {
            self.deadlines.push(deadline);
            std::future::ready(
                self.result
                    .take()
                    .unwrap_or(Err(FdStoreError::InvalidInventory(
                        "scripted cleanup-confirmed sample is absent",
                    ))),
            )
        }
    }

    fn exact_target_for_custody(
        seed: u8,
        phase: StartupCustodyPhase,
        custody: &InheritedCustody,
    ) -> StartupCustodyTarget {
        let (_, durable) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture");
        let binding = *durable
            .get(&typed_custody_name(seed))
            .expect("exact durable fixture binding");
        startup_target(seed, phase, binding)
    }

    fn retained_observation(
        outcome: InheritedWorkerExitObservationOutcome,
        expected: InheritedWorkerExitObservationError,
    ) -> StartupCustodyClassification {
        match outcome.state {
            InheritedWorkerExitObservationState::Retained {
                error,
                classification,
            } => {
                assert_eq!(error, expected);
                classification
            }
            InheritedWorkerExitObservationState::Observed(_) => {
                panic!("observation unexpectedly succeeded")
            }
        }
    }

    fn observed_observation(
        outcome: InheritedWorkerExitObservationOutcome,
        expected_count: usize,
    ) -> ObservedExactInheritedWorkerExitSet {
        match outcome.state {
            InheritedWorkerExitObservationState::Observed(observed) => {
                assert_eq!(observed.observed_target_count.get(), expected_count);
                observed
            }
            InheritedWorkerExitObservationState::Retained { error, .. } => {
                panic!("observation unexpectedly retained custody: {error:?}")
            }
        }
    }

    /// Build a test-only multi-target set which bypasses the earlier cross-bundle namespace
    /// separation check. Unprivileged tests cannot create distinct network namespaces; this
    /// fixture exists only to exercise the observer's all-or-nothing sequencing under one exact
    /// deadline. Every individual process-pidfd/netns pair and durable target remains exact.
    fn unchecked_multi_observation_classification(
        children: &[(u8, &std::process::Child)],
    ) -> StartupCustodyClassification {
        let mut bundles = BTreeMap::new();
        let mut classified = Vec::with_capacity(children.len());
        for (seed, child) in children {
            let bundle = InheritedCustodyBundle::from_unordered([
                pidfd_open(rustix::process::Pid::from_child(child), PidfdFlags::empty())
                    .expect("pin exact child for multi-target fixture"),
                network_namespace(),
            ])
            .expect("exact child custody pair");
            let custody =
                BorrowedCustodyPair::new(bundle.pidfd.as_fd(), bundle.network_namespace.as_fd())
                    .expect("role-ordered child custody");
            let target = startup_target(
                *seed,
                StartupCustodyPhase::MayOwnCustody,
                custody
                    .durable_binding()
                    .expect("durable child custody binding"),
            );
            let name = typed_custody_name(*seed);
            assert!(bundles.insert(name, bundle).is_none());
            classified.push(ClassifiedStartupCustodyTarget {
                target,
                disposition: StartupCustodyDisposition::ExactPresent,
            });
        }
        StartupCustodyClassification {
            custody: InheritedCustody { bundles },
            manager_inventory: stable_startup_inventory_for_test(&BTreeMap::new()),
            classified,
        }
    }

    #[test]
    fn descriptor_names_require_an_even_bounded_exact_shape() {
        for (names, count) in [
            (OsString::new(), 0),
            (custody_name(1).into(), 1),
            (custody_name(1).into(), 2),
            (
                format!(
                    "{}:{}:{}",
                    custody_name(1),
                    custody_name(1),
                    custody_name(1)
                )
                .into(),
                2,
            ),
            ("x".repeat(16 * 1_024).into(), 2),
            (
                std::iter::repeat_n(custody_name(2), 129)
                    .collect::<Vec<_>>()
                    .join(":")
                    .into(),
                129,
            ),
        ] {
            assert!(advertised_descriptor_names_from(&names, count).is_err());
        }
        let non_utf8 = OsString::from_vec(vec![0xff; CUSTODY_FD_NAME_BYTES * 2 + 1]);
        assert!(advertised_descriptor_names_from(&non_utf8, 2).is_err());
    }

    #[test]
    fn custody_names_are_fixed_lowercase_opaque_digests() {
        assert!(custody_fd_name_is_valid(&custody_name(1)));
        assert!(!custody_fd_name_is_valid("volparossa-custody-v1-secret"));
        assert!(!custody_fd_name_is_valid(&format!(
            "{CUSTODY_FD_NAME_PREFIX}{}",
            "A".repeat(64)
        )));
        assert!(!custody_fd_name_is_valid(&format!(
            "{CUSTODY_FD_NAME_PREFIX}{}",
            "0".repeat(63)
        )));
        let names = format!("{}:{}", custody_name(1), custody_name(1));
        let parsed = advertised_descriptor_names_from(OsStr::new(&names), 2)
            .expect("parse exact fixed names");
        assert_eq!(parsed, vec![typed_custody_name(1); 2]);
        assert_eq!(format!("{:?}", parsed[0]), "CustodyFdName(<redacted>)");
    }

    #[test]
    fn descriptor_advertisement_bounds_are_exact() {
        let one_name = custody_name(1);
        assert!(advertised_descriptor_names_from(OsStr::new(&one_name), 1).is_err());

        let maximum_names = std::iter::repeat_n(custody_name(2), 128)
            .collect::<Vec<_>>()
            .join(":");
        let parsed = advertised_descriptor_names_from(OsStr::new(&maximum_names), 128)
            .expect("parse maximum descriptor count");
        assert_eq!(parsed.len(), 128);

        let excessive_names = std::iter::repeat_n(custody_name(3), 129)
            .collect::<Vec<_>>()
            .join(":");
        assert!(advertised_descriptor_names_from(OsStr::new(&excessive_names), 129).is_err());
    }

    #[test]
    fn exact_pidfd_and_network_namespace_are_canonicalised_and_sealed() {
        let network_namespace = network_namespace();
        let pidfd = pidfd();
        fcntl(&network_namespace, FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("clear namespace CLOEXEC");
        fcntl(&pidfd, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear pidfd CLOEXEC");
        let custody = validate_inherited_custody(
            2,
            vec![
                (Some(typed_custody_name(1)), network_namespace),
                (Some(typed_custody_name(1)), pidfd),
            ],
        )
        .expect("adopt exact custody bundle");
        assert_eq!(custody.bundles.len(), 1);
        let bundle = custody.bundles.values().next().expect("custody pair");
        assert_eq!(
            inherited_descriptor_role(bundle.pidfd.as_fd()).expect("pidfd role"),
            InheritedDescriptorRole::Pidfd
        );
        assert_eq!(
            inherited_descriptor_role(bundle.network_namespace.as_fd()).expect("namespace role"),
            InheritedDescriptorRole::NetworkNamespace
        );
        assert_eq!(format!("{bundle:?}"), "InheritedCustodyBundle(<redacted>)");
        assert_eq!(
            format!("{:?}", &bundle.binding),
            "CustodyDescriptorBinding(<redacted>)"
        );
        let reread = CustodyDescriptorBinding::from_custody(
            BorrowedCustodyPair::new(bundle.pidfd.as_fd(), bundle.network_namespace.as_fd())
                .expect("role-ordered custody"),
        )
        .expect("re-read retained descriptor identities");
        assert_eq!(bundle.binding, reread);
        for descriptor in [&bundle.pidfd, &bundle.network_namespace] {
            let flags = FdFlag::from_bits_truncate(
                fcntl(descriptor.as_fd(), FcntlArg::F_GETFD).expect("read descriptor flags"),
            );
            assert_eq!(flags, FdFlag::FD_CLOEXEC);
        }
    }

    #[test]
    fn bundle_retains_exact_owner_numbers_in_both_orders() {
        for reversed in [false, true] {
            let pidfd = pidfd();
            let network_namespace = network_namespace();
            let source_numbers = [pidfd.as_raw_fd(), network_namespace.as_raw_fd()];
            let entries = if reversed {
                vec![network_namespace, pidfd]
            } else {
                vec![pidfd, network_namespace]
            };
            let custody = validate_inherited_custody(
                2,
                entries
                    .into_iter()
                    .map(|descriptor| (Some(typed_custody_name(7)), descriptor))
                    .collect(),
            )
            .expect("adopt exact source owners");
            let bundle = custody.bundles.values().next().expect("captured pair");
            let mut retained_numbers = [
                bundle.pidfd.as_raw_fd(),
                bundle.network_namespace.as_raw_fd(),
            ];
            let mut expected_numbers = source_numbers;
            retained_numbers.sort_unstable();
            expected_numbers.sort_unstable();
            assert_eq!(retained_numbers, expected_numbers);
            bundle
                .verify_retained_binding()
                .expect("captured role binding remains exact");

            let error = refuse_unrecoverable_custody(&custody)
                .expect_err("non-empty inherited custody must block startup");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn descriptor_roles_are_kernel_typed_and_ambiguous_pairs_fail_closed() {
        assert_eq!(
            inherited_descriptor_role(pidfd().as_fd()).expect("pidfd type"),
            InheritedDescriptorRole::Pidfd
        );
        assert_eq!(
            inherited_descriptor_role(network_namespace().as_fd()).expect("netns type"),
            InheritedDescriptorRole::NetworkNamespace
        );
        assert!(inherited_descriptor_role(descriptor().as_fd()).is_err());
        assert!(
            inherited_descriptor_role(
                File::open("/proc/self/ns/user")
                    .expect("open wrong namespace type")
                    .as_fd()
            )
            .is_err()
        );

        for entries in [
            vec![pidfd(), pidfd()],
            vec![network_namespace(), network_namespace()],
            vec![pidfd(), descriptor()],
            vec![descriptor(), network_namespace()],
        ] {
            assert!(
                validate_inherited_custody(
                    2,
                    entries
                        .into_iter()
                        .map(|descriptor| (Some(typed_custody_name(1)), descriptor))
                        .collect(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn exited_process_descriptor_remains_typed_as_pidfd() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn short-lived child");
        let pidfd = pidfd_open(
            rustix::process::Pid::from_child(&child),
            PidfdFlags::empty(),
        )
        .expect("pin short-lived child");
        assert!(child.wait().expect("reap child").success());
        assert_eq!(
            inherited_descriptor_role(pidfd.as_fd()).expect("exited pidfd type"),
            InheritedDescriptorRole::Pidfd
        );
    }

    #[test]
    fn descriptor_identity_cannot_be_reused_across_custody_names() {
        let first_pidfd = pidfd();
        let first_namespace = network_namespace();
        let second_pidfd = pidfd();
        let second_namespace = network_namespace();
        for alias in [&second_pidfd, &second_namespace] {
            let flags = OFlag::from_bits_truncate(
                fcntl(alias, FcntlArg::F_GETFL).expect("read alias status flags"),
            );
            fcntl(alias, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
                .expect("set different alias status flags");
        }
        let result = validate_inherited_custody(
            4,
            vec![
                (Some(typed_custody_name(1)), first_pidfd),
                (Some(typed_custody_name(1)), first_namespace),
                (Some(typed_custody_name(2)), second_pidfd),
                (Some(typed_custody_name(2)), second_namespace),
            ],
        );
        let Err(error) = result else {
            panic!("cross-name descriptor identity reuse was accepted");
        };
        assert_eq!(
            error.to_string(),
            "inherited custody descriptor identity is reused"
        );
    }

    #[test]
    fn partial_duplicate_and_unnamed_bundles_fail_closed() {
        assert!(
            validate_inherited_custody(1, vec![(Some(typed_custody_name(1)), descriptor())])
                .is_err()
        );
        assert!(
            validate_inherited_custody(
                4,
                vec![
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(2)), descriptor()),
                ],
            )
            .is_err()
        );
        assert!(
            validate_inherited_custody(2, vec![(None, descriptor()), (None, descriptor())],)
                .is_err()
        );
    }

    #[test]
    fn startup_classification_accepts_exact_present_and_retains_owners() {
        for phase in [
            StartupCustodyPhase::MayOwnCustody,
            StartupCustodyPhase::MayOwnPrepare,
            StartupCustodyPhase::CleanupConfirmed,
        ] {
            let custody = captured_custody(21);
            let (_, durable) = custody
                .verify_retained_bindings()
                .expect("stable inherited fixture");
            let binding = *durable
                .get(&typed_custody_name(21))
                .expect("durable inherited binding");
            let target = startup_target(21, phase, binding);

            let classified = classify_journal_targets(&[target], &durable)
                .expect("exact present classification");

            assert_eq!(custody.bundles.len(), 1);
            assert_eq!(classified.len(), 1);
            assert_eq!(
                classified[0].disposition,
                StartupCustodyDisposition::ExactPresent
            );
        }
    }

    #[test]
    fn absent_may_own_custody_is_only_a_non_authoritative_classification() {
        let custody = InheritedCustody {
            bundles: BTreeMap::new(),
        };
        let target = synthetic_startup_target(22, StartupCustodyPhase::MayOwnCustody, 22);

        let classified = classify_journal_targets(&[target], &BTreeMap::new())
            .expect("exact no-stored-custody classification");

        assert!(custody.is_empty());
        assert_eq!(classified.len(), 1);
        assert_eq!(
            classified[0].disposition,
            StartupCustodyDisposition::ExactNoStoredCustody
        );
    }

    #[test]
    fn absent_may_own_prepare_never_classifies_as_absent() {
        let custody = InheritedCustody {
            bundles: BTreeMap::new(),
        };
        let target = synthetic_startup_target(23, StartupCustodyPhase::MayOwnPrepare, 23);

        let error = classify_journal_targets(&[target], &BTreeMap::new())
            .expect_err("MayOwnPrepare requires exact present custody");
        assert!(custody.is_empty());
        assert_eq!(
            error.to_string(),
            "MayOwnPrepare custody is absent from the inherited and manager sets"
        );
    }

    #[test]
    fn absent_cleanup_confirmed_has_a_distinct_non_final_classification() {
        let custody = InheritedCustody {
            bundles: BTreeMap::new(),
        };
        let target = synthetic_startup_target(31, StartupCustodyPhase::CleanupConfirmed, 31);

        let classified = classify_journal_targets(&[target], &BTreeMap::new())
            .expect("cleanup-confirmed no-stored-custody classification");

        assert!(custody.is_empty());
        assert_eq!(classified.len(), 1);
        assert_eq!(
            classified[0].disposition,
            StartupCustodyDisposition::CleanupConfirmedNoStoredCustody
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_exact_empty_manager_observation_mints_only_cleanup_confirmed_evidence() {
        let targets = [
            synthetic_startup_target(61, StartupCustodyPhase::CleanupConfirmed, 61),
            synthetic_startup_target(62, StartupCustodyPhase::CleanupConfirmed, 62),
        ];
        let classification = startup_classification(
            InheritedCustody {
                bundles: BTreeMap::new(),
            },
            &targets,
        );
        assert!(classification.is_cleanup_confirmed_no_stored_custody_only());
        let deadline = HardDeadline::after(TEST_WAIT).expect("fresh manager deadline");
        let mut manager = FakeCleanupConfirmedManagerSource {
            result: Some(Ok(classification.manager_inventory.clone())),
            deadlines: Vec::new(),
        };

        let mut evidence =
            observe_cleanup_confirmed_manager_absence_with(&classification, deadline, &mut manager)
                .await
                .expect("fresh exact-empty manager evidence");

        assert_eq!(manager.deadlines, vec![deadline]);
        assert!(evidence.matches_exact_targets(&targets));
        assert!(evidence.consume_exact_target(&targets[1]));
        assert!(!evidence.consume_exact_target(&targets[1]));
        assert!(evidence.consume_exact_target(&targets[0]));
        assert!(evidence.is_consumed());
        assert_eq!(
            format!("{evidence:?}"),
            "CleanupConfirmedManagerAbsenceEvidence { remaining_target_count: 0, .. }"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mixed_present_may_own_drift_and_deadline_never_mint_restart_absence() {
        let cleanup = synthetic_startup_target(63, StartupCustodyPhase::CleanupConfirmed, 63);
        let may_own = synthetic_startup_target(64, StartupCustodyPhase::MayOwnCustody, 64);
        let mixed = startup_classification(
            InheritedCustody {
                bundles: BTreeMap::new(),
            },
            &[cleanup, may_own],
        );
        let mut manager = FakeCleanupConfirmedManagerSource {
            result: Some(Ok(mixed.manager_inventory.clone())),
            deadlines: Vec::new(),
        };
        assert!(
            observe_cleanup_confirmed_manager_absence_with(
                &mixed,
                HardDeadline::after(TEST_WAIT).expect("mixed deadline"),
                &mut manager,
            )
            .await
            .is_err()
        );
        assert!(manager.deadlines.is_empty());

        let present_custody = captured_custody(65);
        let present_target =
            exact_target_for_custody(65, StartupCustodyPhase::CleanupConfirmed, &present_custody);
        let present = startup_classification(present_custody, &[present_target]);
        let mut manager = FakeCleanupConfirmedManagerSource {
            result: Some(Ok(present.manager_inventory.clone())),
            deadlines: Vec::new(),
        };
        assert!(
            observe_cleanup_confirmed_manager_absence_with(
                &present,
                HardDeadline::after(TEST_WAIT).expect("present deadline"),
                &mut manager,
            )
            .await
            .is_err()
        );
        assert!(manager.deadlines.is_empty());

        let cleanup_only = startup_classification(
            InheritedCustody {
                bundles: BTreeMap::new(),
            },
            &[cleanup],
        );
        let foreign_name = typed_custody_name(66);
        let foreign_binding = CustodyDescriptorBinding::from_custody(
            BorrowedCustodyPair::new(pidfd().as_fd(), network_namespace().as_fd())
                .expect("foreign manager binding"),
        )
        .expect("foreign manager identity");
        let mut manager = FakeCleanupConfirmedManagerSource {
            result: Some(Ok(stable_startup_inventory_for_test(&BTreeMap::from([(
                foreign_name,
                foreign_binding,
            )])))),
            deadlines: Vec::new(),
        };
        assert!(
            observe_cleanup_confirmed_manager_absence_with(
                &cleanup_only,
                HardDeadline::after(TEST_WAIT).expect("drift deadline"),
                &mut manager,
            )
            .await
            .is_err()
        );
        assert_eq!(manager.deadlines.len(), 1);

        let expired = HardDeadline::after(Duration::from_millis(1)).expect("short deadline");
        while expired.ensure_remaining().is_ok() {
            thread::yield_now();
        }
        let mut manager = FakeCleanupConfirmedManagerSource {
            result: Some(Ok(cleanup_only.manager_inventory.clone())),
            deadlines: Vec::new(),
        };
        assert!(
            observe_cleanup_confirmed_manager_absence_with(&cleanup_only, expired, &mut manager,)
                .await
                .is_err()
        );
        assert!(manager.deadlines.is_empty());
    }

    #[test]
    fn mixed_present_and_no_stored_custody_targets_are_complete() {
        let custody = captured_custody(24);
        let (_, durable) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture");
        let present_binding = *durable
            .get(&typed_custody_name(24))
            .expect("present durable binding");
        let targets = [
            startup_target(24, StartupCustodyPhase::MayOwnPrepare, present_binding),
            synthetic_startup_target(25, StartupCustodyPhase::MayOwnCustody, 25),
        ];

        let classified =
            classify_journal_targets(&targets, &durable).expect("mixed complete classification");
        assert_eq!(custody.bundles.len(), 1);
        assert_eq!(classified.len(), 2);
        assert_eq!(
            classified[0].disposition,
            StartupCustodyDisposition::ExactPresent
        );
        assert_eq!(
            classified[1].disposition,
            StartupCustodyDisposition::ExactNoStoredCustody
        );
    }

    #[test]
    fn startup_classification_rejects_extras_wrong_binding_and_aliases() {
        let custody = captured_custody(26);
        let (_, durable) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture");
        assert!(classify_journal_targets(&[], &durable).is_err());
        assert_eq!(custody.bundles.len(), 1);

        let custody = captured_custody(27);
        let (_, durable) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture");
        let wrong = synthetic_startup_target(27, StartupCustodyPhase::MayOwnCustody, 27);
        assert!(classify_journal_targets(&[wrong], &durable).is_err());
        assert_eq!(custody.bundles.len(), 1);

        let targets = [
            synthetic_startup_target(28, StartupCustodyPhase::MayOwnCustody, 28),
            synthetic_startup_target(29, StartupCustodyPhase::MayOwnCustody, 28),
        ];
        let custody = InheritedCustody {
            bundles: BTreeMap::new(),
        };
        assert!(classify_journal_targets(&targets, &BTreeMap::new()).is_err());
        assert!(custody.is_empty());
    }

    #[test]
    fn empty_startup_triple_is_the_only_empty_classification() {
        let classified =
            classify_journal_targets(&[], &BTreeMap::new()).expect("empty exact classification");
        assert!(classified.is_empty());
    }

    #[test]
    fn exit_observation_is_not_applicable_to_empty_or_cleanup_confirmed_sets() {
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut observer = FakeProcessPidfdExitObserver::default();
        let empty = startup_classification(
            InheritedCustody {
                bundles: BTreeMap::new(),
            },
            &[],
        );
        let empty = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(empty, deadline, &mut observer),
            InheritedWorkerExitObservationError::NotApplicable,
        );
        assert!(empty.is_empty());
        assert_eq!(observer.calls, 0);

        let cleanup_target =
            synthetic_startup_target(32, StartupCustodyPhase::CleanupConfirmed, 32);
        let cleanup = startup_classification(
            InheritedCustody {
                bundles: BTreeMap::new(),
            },
            &[cleanup_target],
        );
        let cleanup = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(cleanup, deadline, &mut observer),
            InheritedWorkerExitObservationError::NotApplicable,
        );
        assert_eq!(cleanup.classified.len(), 1);
        assert_eq!(observer.calls, 0);
    }

    #[test]
    fn absent_may_own_target_blocks_every_wait_before_partial_observation() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let custody = captured_child_custody(33, &child);
        let present = exact_target_for_custody(33, StartupCustodyPhase::MayOwnCustody, &custody);
        let absent = synthetic_startup_target(34, StartupCustodyPhase::MayOwnCustody, 34);
        let classification = startup_classification(custody, &[present, absent]);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut observer = FakeProcessPidfdExitObserver::default();

        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                deadline,
                &mut observer,
            ),
            InheritedWorkerExitObservationError::MissingExactCustody,
        );
        assert_eq!(retained.classified.len(), 2);
        assert_eq!(retained.custody.bundles.len(), 1);
        assert_eq!(observer.calls, 0);
        child.kill().expect("terminate child");
        child.wait().expect("reap child");
    }

    #[test]
    fn cleanup_confirmed_is_skipped_alongside_one_pending_target() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let custody = captured_child_custody(35, &child);
        let pending = exact_target_for_custody(35, StartupCustodyPhase::MayOwnPrepare, &custody);
        let cleanup = synthetic_startup_target(36, StartupCustodyPhase::CleanupConfirmed, 36);
        let classification = startup_classification(custody, &[pending, cleanup]);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut observer = FakeProcessPidfdExitObserver::default();

        let exit_set = observed_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                deadline,
                &mut observer,
            ),
            1,
        );
        assert_eq!(exit_set.classification.classified.len(), 2);
        assert_eq!(observer.calls, 1);
        child.kill().expect("terminate child");
        child.wait().expect("reap child");
    }

    #[test]
    fn all_pending_targets_share_one_deadline_and_succeed_as_one_affine_set() {
        let mut first = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn first child");
        let mut second = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn second child");
        let classification =
            unchecked_multi_observation_classification(&[(37, &first), (38, &second)]);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut observer = FakeProcessPidfdExitObserver::default();

        let exit_set = observed_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                deadline,
                &mut observer,
            ),
            2,
        );
        assert_eq!(exit_set.classification.custody.bundles.len(), 2);
        assert_eq!(observer.calls, 2);
        assert!(
            observer
                .deadlines
                .iter()
                .all(|observed_deadline| *observed_deadline == deadline)
        );
        first.kill().expect("terminate first child");
        first.wait().expect("reap first child");
        second.kill().expect("terminate second child");
        second.wait().expect("reap second child");
    }

    #[test]
    fn nth_wait_failure_returns_the_complete_classification_without_success() {
        let mut first = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn first child");
        let mut second = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn second child");
        let classification =
            unchecked_multi_observation_classification(&[(39, &first), (40, &second)]);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut observer = FakeProcessPidfdExitObserver {
            results: VecDeque::from([Ok(()), Err(io::ErrorKind::InvalidData)]),
            ..FakeProcessPidfdExitObserver::default()
        };

        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                deadline,
                &mut observer,
            ),
            InheritedWorkerExitObservationError::InvalidReadiness,
        );
        assert_eq!(retained.custody.bundles.len(), 2);
        assert_eq!(retained.classified.len(), 2);
        assert_eq!(observer.calls, 2);
        assert!(
            observer
                .deadlines
                .iter()
                .all(|observed_deadline| *observed_deadline == deadline)
        );
        first.kill().expect("terminate first child");
        first.wait().expect("reap first child");
        second.kill().expect("terminate second child");
        second.wait().expect("reap second child");
    }

    #[test]
    fn final_set_remeasurement_detects_earlier_bundle_drift_during_a_later_wait() {
        let mut first = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn first child");
        let mut second = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn second child");
        let classification =
            unchecked_multi_observation_classification(&[(41, &first), (42, &second)]);
        let first_alias = duplicate_descriptor_cloexec(
            &classification
                .custody
                .bundles
                .get(&typed_custody_name(41))
                .expect("first exact bundle")
                .network_namespace,
        )
        .expect("duplicate first namespace owner");
        let mut observer = FakeProcessPidfdExitObserver {
            mutate_status_flags_on_call: Some((2, first_alias)),
            ..FakeProcessPidfdExitObserver::default()
        };

        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live deadline"),
                &mut observer,
            ),
            InheritedWorkerExitObservationError::BindingChanged,
        );
        assert_eq!(retained.custody.bundles.len(), 2);
        assert_eq!(observer.calls, 2);
        first.kill().expect("terminate first child");
        first.wait().expect("reap first child");
        second.kill().expect("terminate second child");
        second.wait().expect("reap second child");
    }

    #[test]
    fn deadlines_fail_before_wait_and_after_a_late_observer_without_minting_evidence() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let custody = captured_child_custody(43, &child);
        let target = exact_target_for_custody(43, StartupCustodyPhase::MayOwnCustody, &custody);
        let classification = startup_classification(custody, &[target]);
        let expired = HardDeadline::after(Duration::from_millis(1)).expect("brief deadline");
        thread::sleep(Duration::from_millis(5));
        let mut observer = FakeProcessPidfdExitObserver::default();
        let classification = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                expired,
                &mut observer,
            ),
            InheritedWorkerExitObservationError::DeadlineElapsed,
        );
        assert_eq!(observer.calls, 0);

        let deadline = HardDeadline::after(Duration::from_millis(25)).expect("live deadline");
        observer.delay = Duration::from_millis(50);
        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                deadline,
                &mut observer,
            ),
            InheritedWorkerExitObservationError::DeadlineElapsed,
        );
        assert_eq!(retained.custody.bundles.len(), 1);
        assert_eq!(observer.calls, 1);
        child.kill().expect("terminate child");
        child.wait().expect("reap child");
    }

    #[test]
    fn exact_binding_is_remeasured_before_and_after_each_wait() {
        let mut before_child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn pre-wait child");
        let custody = captured_child_custody(44, &before_child);
        let target = exact_target_for_custody(44, StartupCustodyPhase::MayOwnCustody, &custody);
        let alias = duplicate_descriptor_cloexec(
            &custody
                .bundles
                .get(&typed_custody_name(44))
                .expect("pre-wait bundle")
                .network_namespace,
        )
        .expect("duplicate namespace owner");
        let classification = startup_classification(custody, &[target]);
        let flags = OFlag::from_bits_truncate(
            fcntl(&alias, FcntlArg::F_GETFL).expect("read pre-wait flags"),
        );
        fcntl(&alias, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).expect("mutate before wait");
        let mut observer = FakeProcessPidfdExitObserver::default();
        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live deadline"),
                &mut observer,
            ),
            InheritedWorkerExitObservationError::BindingChanged,
        );
        assert_eq!(retained.custody.bundles.len(), 1);
        assert_eq!(observer.calls, 0);
        before_child.kill().expect("terminate pre-wait child");
        before_child.wait().expect("reap pre-wait child");

        let mut after_child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn post-wait child");
        let custody = captured_child_custody(45, &after_child);
        let target = exact_target_for_custody(45, StartupCustodyPhase::MayOwnPrepare, &custody);
        let alias = duplicate_descriptor_cloexec(
            &custody
                .bundles
                .get(&typed_custody_name(45))
                .expect("post-wait bundle")
                .network_namespace,
        )
        .expect("duplicate namespace owner");
        let classification = startup_classification(custody, &[target]);
        let mut observer = FakeProcessPidfdExitObserver {
            mutate_status_flags_on_call: Some((1, alias)),
            ..FakeProcessPidfdExitObserver::default()
        };
        let retained = retained_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live deadline"),
                &mut observer,
            ),
            InheritedWorkerExitObservationError::BindingChanged,
        );
        assert_eq!(retained.custody.bundles.len(), 1);
        assert_eq!(observer.calls, 1);
        after_child.kill().expect("terminate post-wait child");
        after_child.wait().expect("reap post-wait child");
    }

    #[test]
    fn invalid_anchor_namespace_binding_is_rejected_before_observation() {
        let custody = captured_custody(46);
        let (_, durable) = custody
            .verify_retained_bindings()
            .expect("stable inherited fixture");
        let binding = *durable
            .get(&typed_custody_name(46))
            .expect("durable inherited binding");
        let namespace = network_namespace();
        let status = fstat(&namespace).expect("stat network namespace");
        let correct_anchor = durable_anchor(46, status.st_dev, status.st_ino);
        let wrong_anchor = durable_anchor(47, status.st_dev, status.st_ino);
        let correct = startup_target_with_anchor(
            46,
            StartupCustodyPhase::MayOwnCustody,
            correct_anchor,
            binding,
        );
        assert!(correct.matches_recovery_anchor(&correct_anchor));
        assert!(!correct.matches_recovery_anchor(&wrong_anchor));

        let invalid = startup_target_with_anchor(
            46,
            StartupCustodyPhase::MayOwnCustody,
            durable_anchor(46, status.st_dev, status.st_ino + 1),
            binding,
        );
        let error = classify_journal_targets(&[invalid], &durable)
            .expect_err("mismatched anchor/netns binding must fail closed");
        assert_eq!(
            error.to_string(),
            "startup journal custody target has an invalid recovery-anchor binding"
        );
    }

    #[test]
    fn real_exact_process_pidfd_times_out_live_then_observes_after_reap() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let custody = captured_child_custody(48, &child);
        let target = exact_target_for_custody(48, StartupCustodyPhase::MayOwnCustody, &custody);
        let classification = startup_classification(custody, &[target]);
        let retained = retained_observation(
            observe_exact_inherited_worker_exits(
                classification,
                HardDeadline::after(Duration::from_millis(20)).expect("brief deadline"),
            ),
            InheritedWorkerExitObservationError::DeadlineElapsed,
        );
        child.kill().expect("terminate child");
        child.wait().expect("reap child");

        let exit_set = observed_observation(
            observe_exact_inherited_worker_exits(
                retained,
                HardDeadline::after(Duration::from_secs(1)).expect("live deadline"),
            ),
            1,
        );
        assert_eq!(exit_set.classification.custody.bundles.len(), 1);
    }

    #[test]
    fn real_exact_process_pidfd_observes_a_zombie_before_parent_reaps_it() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let custody = captured_child_custody(49, &child);
        let target = exact_target_for_custody(49, StartupCustodyPhase::MayOwnPrepare, &custody);
        let classification = startup_classification(custody, &[target]);
        child.kill().expect("terminate child without reaping");

        let exit_set = observed_observation(
            observe_exact_inherited_worker_exits(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live deadline"),
            ),
            1,
        );
        assert_eq!(exit_set.classification.custody.bundles.len(), 1);
        child.wait().expect("reap observed zombie");
    }

    struct FakeSharedServiceCgroupSource {
        captured: Option<PinnedSharedServiceCgroup>,
        observations:
            VecDeque<Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError>>,
        revalidations: VecDeque<Result<(), SharedServiceCgroupObservationError>>,
        observe_deadlines: Vec<HardDeadline>,
        revalidate_deadlines: Vec<HardDeadline>,
        capture_deadlines: Vec<HardDeadline>,
        events: Option<Rc<RefCell<Vec<&'static str>>>>,
    }

    impl SharedServiceCgroupSource for FakeSharedServiceCgroupSource {
        fn capture(
            &mut self,
            deadline: HardDeadline,
        ) -> Result<PinnedSharedServiceCgroup, SharedServiceCgroupObservationError> {
            if let Some(events) = &self.events {
                events.borrow_mut().push("capture");
            }
            self.capture_deadlines.push(deadline);
            self.captured
                .take()
                .ok_or(SharedServiceCgroupObservationError::CgroupCapture)
        }

        fn observe(
            &mut self,
            _pinned: &PinnedSharedServiceCgroup,
            current_main_pid: NonZeroU32,
            deadline: HardDeadline,
        ) -> Result<SharedServiceCgroupSnapshot, SharedServiceCgroupObservationError> {
            assert_eq!(current_main_pid.get(), std::process::id());
            if let Some(events) = &self.events {
                let event = match self.observe_deadlines.len() {
                    0 => "sample-1",
                    1 => "sample-2",
                    2 => "sample-3",
                    _ => "sample-join",
                };
                events.borrow_mut().push(event);
            }
            self.observe_deadlines.push(deadline);
            self.observations
                .pop_front()
                .unwrap_or(Err(SharedServiceCgroupObservationError::CgroupCapture))
        }

        fn revalidate(
            &mut self,
            _pinned: &PinnedSharedServiceCgroup,
            deadline: HardDeadline,
        ) -> Result<(), SharedServiceCgroupObservationError> {
            self.revalidate_deadlines.push(deadline);
            self.revalidations.pop_front().unwrap_or(Ok(()))
        }
    }

    struct FakeSharedServiceManagerSource {
        observations: VecDeque<Result<StableStartupInventory, FdStoreError>>,
        deadlines: Vec<HardDeadline>,
        isolation_ids: VecDeque<Result<NonZeroU64, FdStoreError>>,
        isolation_deadlines: Vec<HardDeadline>,
        events: Option<Rc<RefCell<Vec<&'static str>>>>,
    }

    impl SharedServiceManagerSource for FakeSharedServiceManagerSource {
        fn reobserve<'a>(
            &'a mut self,
            _baseline: &'a StableStartupInventory,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<StableStartupInventory, FdStoreError>> + 'a {
            if let Some(events) = &self.events {
                let event = if self.deadlines.is_empty() {
                    "manager-before"
                } else {
                    "manager-after"
                };
                events.borrow_mut().push(event);
            }
            self.deadlines.push(deadline);
            std::future::ready(self.observations.pop_front().unwrap_or(Err(
                FdStoreError::InvalidInventory("scripted manager sample is absent"),
            )))
        }

        fn observe_isolation<'a>(
            &'a mut self,
            inventory: &'a StableStartupInventory,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<StableServiceCgroupIsolation, FdStoreError>> + 'a {
            if let Some(events) = &self.events {
                let event = if self.isolation_deadlines.is_empty() {
                    "isolation-before"
                } else {
                    "isolation-after"
                };
                events.borrow_mut().push(event);
            }
            self.isolation_deadlines.push(deadline);
            let id = self
                .isolation_ids
                .pop_front()
                .unwrap_or(Err(FdStoreError::InvalidInventory(
                    "scripted isolation sample is absent",
                )));
            std::future::ready(id.map(|id| stable_service_cgroup_isolation_for_test(inventory, id)))
        }
    }

    fn fake_pinned_shared_service_cgroup(inode: u64) -> PinnedSharedServiceCgroup {
        PinnedSharedServiceCgroup {
            root: descriptor(),
            root_identity: PinnedFileIdentity {
                device: 7,
                inode: 8,
            },
            service: descriptor(),
            service_identity: PinnedFileIdentity { device: 7, inode },
            kernel_cgroup_id: NonZeroU64::new(inode).expect("nonzero fake cgroup ID"),
            pid_namespace: descriptor(),
            pid_namespace_identity: PinnedFileIdentity {
                device: 9,
                inode: 10,
            },
            cgroup_namespace: descriptor(),
            cgroup_namespace_identity: PinnedFileIdentity {
                device: 9,
                inode: 11,
            },
            path: b"/volparossa-test.service".as_slice().into(),
        }
    }

    fn shared_cgroup_snapshot(
        current_main_pid: NonZeroU32,
        extra_stat_value: u64,
    ) -> SharedServiceCgroupSnapshot {
        SharedServiceCgroupSnapshot {
            control_file_identities: [
                PinnedFileIdentity {
                    device: 7,
                    inode: 11,
                },
                PinnedFileIdentity {
                    device: 7,
                    inode: 12,
                },
                PinnedFileIdentity {
                    device: 7,
                    inode: 13,
                },
            ],
            stat_fields: BTreeMap::from([
                (Box::<[u8]>::from(&b"nr_descendants"[..]), 0),
                (Box::<[u8]>::from(&b"nr_dying_descendants"[..]), 0),
                (
                    Box::<[u8]>::from(&b"nr_subsys_memory"[..]),
                    extra_stat_value,
                ),
            ]),
            canonical_members: BTreeSet::from([current_main_pid]),
        }
    }

    fn observed_exit_fixture(seed: u8) -> ObservedExactInheritedWorkerExitSet {
        let custody = captured_custody(seed);
        let target = exact_target_for_custody(seed, StartupCustodyPhase::MayOwnPrepare, &custody);
        let classification = startup_classification(custody, &[target]);
        let mut observer = FakeProcessPidfdExitObserver::default();
        observed_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live exit deadline"),
                &mut observer,
            ),
            1,
        )
    }

    fn observed_exit_with_cleanup_fixture(
        pending_seed: u8,
        cleanup_seed: u8,
    ) -> ObservedExactInheritedWorkerExitSet {
        let custody = captured_custody(pending_seed);
        let pending =
            exact_target_for_custody(pending_seed, StartupCustodyPhase::MayOwnPrepare, &custody);
        let cleanup = synthetic_startup_target(
            cleanup_seed,
            StartupCustodyPhase::CleanupConfirmed,
            u32::from(cleanup_seed),
        );
        let classification = startup_classification(custody, &[pending, cleanup]);
        let mut observer = FakeProcessPidfdExitObserver::default();
        observed_observation(
            observe_exact_inherited_worker_exits_outcome_with(
                classification,
                HardDeadline::after(Duration::from_secs(1)).expect("live exit deadline"),
                &mut observer,
            ),
            1,
        )
    }

    fn manager_sample_for_exits(
        exits: &ObservedExactInheritedWorkerExitSet,
    ) -> StableStartupInventory {
        let (bindings, _) = exits
            .classification
            .custody
            .verify_retained_bindings()
            .expect("stable exit fixture bindings");
        stable_startup_inventory_for_test(&bindings)
    }

    async fn successful_sampling_attempt(
        exits: &ObservedExactInheritedWorkerExitSet,
        seed: u8,
        deadline: HardDeadline,
    ) -> (
        SharedServiceCgroupSamplingAttempt,
        FakeSharedServiceCgroupSource,
    ) {
        let pid = NonZeroU32::new(std::process::id()).expect("nonzero current PID");
        let mut manager = FakeSharedServiceManagerSource {
            observations: VecDeque::from([
                Ok(manager_sample_for_exits(exits)),
                Ok(manager_sample_for_exits(exits)),
            ]),
            deadlines: Vec::new(),
            isolation_ids: VecDeque::from([
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
            ]),
            isolation_deadlines: Vec::new(),
            events: None,
        };
        let mut source = FakeSharedServiceCgroupSource {
            captured: Some(fake_pinned_shared_service_cgroup(u64::from(seed) + 40)),
            observations: VecDeque::from([
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
            ]),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        let sampling = sample_shared_service_cgroup_quiescence_with(
            exits,
            deadline,
            &mut manager,
            &mut source,
        )
        .await;
        assert!(matches!(
            sampling.result,
            SharedServiceCgroupSamplingResult::Sampled(_)
        ));
        (sampling, source)
    }

    #[test]
    fn cgroup_parsers_are_bounded_canonical_and_accept_only_current_main_pid() {
        assert_eq!(
            parse_unified_cgroup_path(b"0::/system.slice/volparossa-helper.service\n")
                .expect("canonical unified path")
                .as_ref(),
            b"/system.slice/volparossa-helper.service"
        );
        for invalid in [
            &b"1:name=/x\n"[..],
            &b"0::/x/../y\n"[..],
            &b"0::/x/\n"[..],
            &b"0::/x\n0::/y\n"[..],
            &b"0::/x (deleted)\n"[..],
        ] {
            assert!(parse_unified_cgroup_path(invalid).is_err());
        }

        let stat = b"nr_descendants 0\nnr_subsys_memory 1\nnr_dying_descendants 0\n";
        let parsed = parse_cgroup_stat(stat).expect("exact zero descendants");
        assert_eq!(parsed.get(b"nr_subsys_memory".as_slice()), Some(&1));
        for invalid in [
            &b"nr_descendants 1\nnr_dying_descendants 0\n"[..],
            &b"nr_descendants 0\nnr_dying_descendants 1\n"[..],
            &b"nr_descendants 0\n"[..],
            &b"nr_descendants 00\nnr_dying_descendants 0\n"[..],
            &b"nr_descendants 0\nnr_descendants 0\nnr_dying_descendants 0\n"[..],
            &b"nr_descendants 0 extra\nnr_dying_descendants 0\n"[..],
        ] {
            assert!(parse_cgroup_stat(invalid).is_err());
        }

        let pid = NonZeroU32::new(42).expect("nonzero PID");
        assert_eq!(
            parse_cgroup_procs(b"42\n42\n", pid).expect("documented duplicate PID"),
            BTreeSet::from([pid])
        );
        for invalid in [
            &b""[..],
            &b"42"[..],
            &b"0\n"[..],
            &b"042\n"[..],
            &b"42\n43\n"[..],
            &b"+42\n"[..],
        ] {
            assert!(parse_cgroup_procs(invalid, pid).is_err());
        }

        let mut maximum_component = b"0::/".to_vec();
        maximum_component.extend(std::iter::repeat_n(b'a', MAX_CGROUP_COMPONENT_BYTES));
        maximum_component.push(b'\n');
        assert!(parse_unified_cgroup_path(&maximum_component).is_ok());
        maximum_component.insert(maximum_component.len() - 1, b'a');
        assert!(parse_unified_cgroup_path(&maximum_component).is_err());

        let maximum_pid_lines = b"42\n".repeat(MAX_CGROUP_PROCS_LINES);
        assert!(parse_cgroup_procs(&maximum_pid_lines, pid).is_ok());
        let oversized_pid_lines = b"42\n".repeat(MAX_CGROUP_PROCS_LINES + 1);
        assert!(parse_cgroup_procs(&oversized_pid_lines, pid).is_err());
        assert!(parse_cgroup_procs(b"4294967296\n", pid).is_err());

        let mut maximum_stat_fields = b"nr_descendants 0\nnr_dying_descendants 0\n".to_vec();
        for index in 0..MAX_CGROUP_STAT_FIELDS - 2 {
            maximum_stat_fields.extend_from_slice(format!("field{index} 0\n").as_bytes());
        }
        assert!(parse_cgroup_stat(&maximum_stat_fields).is_ok());
        maximum_stat_fields.extend_from_slice(b"one_field_too_many 0\n");
        assert!(parse_cgroup_stat(&maximum_stat_fields).is_err());
        assert!(
            parse_cgroup_stat(
                b"nr_descendants 0\nnr_dying_descendants 0\noverflow 18446744073709551616\n"
            )
            .is_err()
        );
    }

    #[test]
    fn async_sampling_future_borrows_and_cancellation_keeps_the_exit_owner() {
        let exits = observed_exit_fixture(52);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut manager = FakeSharedServiceManagerSource {
            observations: VecDeque::new(),
            deadlines: Vec::new(),
            isolation_ids: VecDeque::new(),
            isolation_deadlines: Vec::new(),
            events: None,
        };
        let mut source = FakeSharedServiceCgroupSource {
            captured: None,
            observations: VecDeque::new(),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        let sampling = sample_shared_service_cgroup_quiescence_with(
            &exits,
            deadline,
            &mut manager,
            &mut source,
        );
        drop(sampling);

        assert_eq!(exits.observed_target_count.get(), 1);
        assert_eq!(exits.classification.custody.bundles.len(), 1);
        assert!(manager.deadlines.is_empty());
        assert!(source.capture_deadlines.is_empty());
    }

    #[tokio::test]
    async fn injected_sources_prove_manager_and_post_manager_sample_order_and_sync_join() {
        let seed = 53_u8;
        let exits = observed_exit_fixture(seed);
        let pid = NonZeroU32::new(std::process::id()).expect("nonzero current PID");
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut manager = FakeSharedServiceManagerSource {
            observations: VecDeque::from([
                Ok(manager_sample_for_exits(&exits)),
                Ok(manager_sample_for_exits(&exits)),
            ]),
            deadlines: Vec::new(),
            isolation_ids: VecDeque::from([
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
            ]),
            isolation_deadlines: Vec::new(),
            events: Some(Rc::clone(&events)),
        };
        let mut source = FakeSharedServiceCgroupSource {
            captured: Some(fake_pinned_shared_service_cgroup(u64::from(seed) + 40)),
            observations: VecDeque::from([
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
            ]),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: Some(Rc::clone(&events)),
        };

        let sampling = sample_shared_service_cgroup_quiescence_with(
            &exits,
            deadline,
            &mut manager,
            &mut source,
        )
        .await;
        assert!(matches!(
            sampling.result,
            SharedServiceCgroupSamplingResult::Sampled(_)
        ));
        assert_eq!(
            events.borrow().as_slice(),
            [
                "manager-before",
                "isolation-before",
                "capture",
                "sample-1",
                "sample-2",
                "manager-after",
                "isolation-after",
                "sample-3"
            ]
        );
        assert_eq!(manager.deadlines, vec![deadline; 2]);
        assert_eq!(manager.isolation_deadlines, vec![deadline; 2]);

        let outcome = join_shared_service_cgroup_quiescence_with(exits, sampling, &mut source);
        let SharedServiceCgroupObservationOutcomeState::Observed(observed) = outcome.state else {
            panic!("exact sampling and synchronous join did not succeed")
        };
        assert_eq!(observed.state.exits.observed_target_count.get(), 1);
        assert_eq!(events.borrow().last().copied(), Some("sample-join"));
        assert_eq!(source.observe_deadlines, vec![deadline; 4]);
        assert!(
            source
                .observe_deadlines
                .iter()
                .all(|observed| *observed == deadline)
        );
    }

    #[tokio::test]
    async fn manager_deadline_remains_deadline_and_returned_attempt_leaves_exits_owned() {
        let exits = observed_exit_fixture(54);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut manager = FakeSharedServiceManagerSource {
            observations: VecDeque::from([Err(FdStoreError::Deadline)]),
            deadlines: Vec::new(),
            isolation_ids: VecDeque::new(),
            isolation_deadlines: Vec::new(),
            events: None,
        };
        let mut source = FakeSharedServiceCgroupSource {
            captured: None,
            observations: VecDeque::new(),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        let sampling = sample_shared_service_cgroup_quiescence_with(
            &exits,
            deadline,
            &mut manager,
            &mut source,
        )
        .await;
        assert!(matches!(
            sampling.result,
            SharedServiceCgroupSamplingResult::Failed(
                SharedServiceCgroupObservationError::DeadlineElapsed
            )
        ));
        assert_eq!(exits.observed_target_count.get(), 1);
        assert!(source.capture_deadlines.is_empty());
    }

    #[test]
    fn cleanup_confirmed_target_does_not_claim_current_pending_cgroup_membership() {
        let pending_seed = 55_u8;
        let exits = observed_exit_with_cleanup_fixture(pending_seed, 56);
        let pinned = fake_pinned_shared_service_cgroup(u64::from(pending_seed) + 40);
        verify_exit_set_against_shared_cgroup(&exits, &pinned)
            .expect("only pending target requires current shared-cgroup anchor");
        assert_eq!(exits.classification.classified.len(), 2);
        assert_eq!(exits.observed_target_count.get(), 1);
    }

    #[tokio::test]
    async fn sampling_attempt_cannot_be_cross_joined_to_another_exit_set() {
        let exits_a = observed_exit_fixture(57);
        let exits_b = observed_exit_fixture(58);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let (sampling, mut source) = successful_sampling_attempt(&exits_a, 57, deadline).await;
        let sampled_calls = source.observe_deadlines.len();

        let outcome = join_shared_service_cgroup_quiescence_with(exits_b, sampling, &mut source);
        let SharedServiceCgroupObservationOutcomeState::Retained { error, state } = outcome.state
        else {
            panic!("cross-joined sampling unexpectedly minted evidence")
        };
        assert_eq!(error, SharedServiceCgroupObservationError::BindingChanged);
        assert_eq!(state.exits.classification.custody.bundles.len(), 1);
        assert_eq!(source.observe_deadlines.len(), sampled_calls);
        assert_eq!(exits_a.classification.custody.bundles.len(), 1);
    }

    #[tokio::test]
    async fn joined_isolation_must_retain_the_exact_kernel_cgroup_id() {
        let seed = 61_u8;
        let exits = observed_exit_fixture(seed);
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let (mut sampling, mut source) = successful_sampling_attempt(&exits, seed, deadline).await;
        let wrong = stable_service_cgroup_isolation_for_test(
            sampling
                .state
                .manager_after
                .as_ref()
                .expect("manager-after sample"),
            NonZeroU64::new(u64::from(seed) + 41).expect("wrong nonzero cgroup ID"),
        );
        sampling.state.isolation_after = Some(wrong);
        let sampled_calls = source.observe_deadlines.len();

        let outcome = join_shared_service_cgroup_quiescence_with(exits, sampling, &mut source);
        assert!(matches!(
            outcome.state,
            SharedServiceCgroupObservationOutcomeState::Retained {
                error: SharedServiceCgroupObservationError::ManagerIsolationChanged,
                ..
            }
        ));
        assert_eq!(source.observe_deadlines.len(), sampled_calls);
    }

    #[tokio::test]
    async fn expired_sampling_attempt_is_retained_before_join_io() {
        let exits = observed_exit_fixture(59);
        let deadline = HardDeadline::after(Duration::from_millis(40)).expect("brief deadline");
        let (sampling, mut source) = successful_sampling_attempt(&exits, 59, deadline).await;
        let sampled_calls = source.observe_deadlines.len();
        while deadline.ensure_remaining().is_ok() {
            thread::sleep(Duration::from_millis(1));
        }

        let outcome = join_shared_service_cgroup_quiescence_with(exits, sampling, &mut source);
        let SharedServiceCgroupObservationOutcomeState::Retained { error, state } = outcome.state
        else {
            panic!("expired sampling unexpectedly minted evidence")
        };
        assert_eq!(error, SharedServiceCgroupObservationError::DeadlineElapsed);
        assert_eq!(state.exits.observed_target_count.get(), 1);
        assert_eq!(source.observe_deadlines.len(), sampled_calls);
    }

    #[tokio::test]
    async fn post_manager_and_join_projection_drift_never_mints_samples() {
        let seed = 60_u8;
        let exits = observed_exit_fixture(seed);
        let pid = NonZeroU32::new(std::process::id()).expect("nonzero current PID");
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut manager = FakeSharedServiceManagerSource {
            observations: VecDeque::from([
                Ok(manager_sample_for_exits(&exits)),
                Ok(manager_sample_for_exits(&exits)),
            ]),
            deadlines: Vec::new(),
            isolation_ids: VecDeque::from([
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
                Ok(NonZeroU64::new(u64::from(seed) + 40).expect("fake cgroup ID")),
            ]),
            isolation_deadlines: Vec::new(),
            events: None,
        };
        let mut source = FakeSharedServiceCgroupSource {
            captured: Some(fake_pinned_shared_service_cgroup(u64::from(seed) + 40)),
            observations: VecDeque::from([
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 2)),
            ]),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        let post_manager_drift = sample_shared_service_cgroup_quiescence_with(
            &exits,
            deadline,
            &mut manager,
            &mut source,
        )
        .await;
        assert!(matches!(
            post_manager_drift.result,
            SharedServiceCgroupSamplingResult::Failed(
                SharedServiceCgroupObservationError::UnstableObservation
            )
        ));

        let (sampling, mut source) = successful_sampling_attempt(&exits, seed, deadline).await;
        source.observations = VecDeque::from([Ok(shared_cgroup_snapshot(pid, 2))]);
        let join_drift = join_shared_service_cgroup_quiescence_with(exits, sampling, &mut source);
        assert!(matches!(
            join_drift.state,
            SharedServiceCgroupObservationOutcomeState::Retained {
                error: SharedServiceCgroupObservationError::UnstableObservation,
                ..
            }
        ));
    }

    #[test]
    fn shared_cgroup_sampling_uses_two_initial_and_one_final_snapshot_under_one_deadline() {
        let seed = 50_u8;
        let exits = observed_exit_fixture(seed);
        let pinned = fake_pinned_shared_service_cgroup(u64::from(seed) + 40);
        let pid = NonZeroU32::new(std::process::id()).expect("nonzero current PID");
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut source = FakeSharedServiceCgroupSource {
            captured: None,
            observations: VecDeque::from([
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
                Ok(shared_cgroup_snapshot(pid, 1)),
            ]),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        let initial = observe_initial_shared_service_cgroup_samples(
            &exits,
            &pinned,
            pid,
            deadline,
            &mut source,
        )
        .expect("two matching initial samples");
        let final_snapshot = observe_final_shared_service_cgroup_sample(
            &exits,
            &pinned,
            pid,
            &initial,
            deadline,
            &mut source,
        )
        .expect("matching final sample");
        assert_eq!(final_snapshot, shared_cgroup_snapshot(pid, 1));
        assert_eq!(source.observe_deadlines, vec![deadline; 3]);
        assert_eq!(source.revalidate_deadlines, vec![deadline; 3]);
    }

    #[test]
    fn cgroup_anchor_mismatch_and_snapshot_drift_fail_before_evidence() {
        let seed = 51_u8;
        let mut exits = observed_exit_fixture(seed);
        let exact = fake_pinned_shared_service_cgroup(u64::from(seed) + 40);
        let wrong = fake_pinned_shared_service_cgroup(u64::from(seed) + 41);
        let pid = NonZeroU32::new(std::process::id()).expect("nonzero current PID");
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        let mut source = FakeSharedServiceCgroupSource {
            captured: None,
            observations: VecDeque::new(),
            revalidations: VecDeque::new(),
            observe_deadlines: Vec::new(),
            revalidate_deadlines: Vec::new(),
            capture_deadlines: Vec::new(),
            events: None,
        };
        exits.observed_target_count = NonZeroUsize::new(2).expect("nonzero wrong count");
        assert_eq!(
            observe_initial_shared_service_cgroup_samples(
                &exits,
                &exact,
                pid,
                deadline,
                &mut source,
            )
            .expect_err("observed pending count cannot drift"),
            SharedServiceCgroupObservationError::BindingChanged
        );
        assert!(source.observe_deadlines.is_empty());
        exits.observed_target_count = NonZeroUsize::new(1).expect("original exact count");
        assert_eq!(
            observe_initial_shared_service_cgroup_samples(
                &exits,
                &wrong,
                pid,
                deadline,
                &mut source,
            )
            .expect_err("wrong anchor inode"),
            SharedServiceCgroupObservationError::AnchorMismatch
        );
        assert!(source.observe_deadlines.is_empty());

        let pinned = fake_pinned_shared_service_cgroup(u64::from(seed) + 40);
        source.observations = VecDeque::from([
            Ok(shared_cgroup_snapshot(pid, 1)),
            Ok(shared_cgroup_snapshot(pid, 2)),
        ]);
        assert_eq!(
            observe_initial_shared_service_cgroup_samples(
                &exits,
                &pinned,
                pid,
                deadline,
                &mut source,
            )
            .expect_err("unstable stat projection"),
            SharedServiceCgroupObservationError::UnstableObservation
        );
        assert_eq!(source.observe_deadlines, vec![deadline; 2]);
    }

    #[test]
    fn shared_cgroup_surface_exposes_no_pid_fd_path_mutation_or_settlement_authority() {
        let source = include_str!("systemd_custody.rs");
        let start = source
            .find("struct PinnedSharedServiceCgroup")
            .expect("cgroup observer source start");
        let end = source[start..]
            .find("/// Consume the complete affine systemd startup snapshot")
            .map(|offset| start + offset)
            .expect("cgroup observer source end");
        let observer = &source[start..end];
        for forbidden in [
            "pub fn pid",
            "pub fn path",
            "pub fn descriptor",
            "as_raw_fd",
            "RawFd",
            "from_raw_fd",
            "pidfd_send_signal",
            "kill(",
            "cgroup.kill",
            "cgroup.procs\", OFlags::WR",
            "OFlags::WRONLY",
            "OFlags::RDWR",
            "rustix::io::write",
            "std::fs::write",
            "confirm_cleanup",
            "confirm_manager_absent",
            "run_production_server",
            "continue_empty",
        ] {
            assert!(
                !observer.contains(forbidden),
                "cgroup observer unexpectedly contains {forbidden} authority"
            );
        }
        assert!(!include_str!("server.rs").contains("sample_shared_service_cgroup_quiescence"));
        assert!(!include_str!("server.rs").contains("join_shared_service_cgroup_quiescence"));
        assert!(observer.contains("observe_same_service_scope"));
        assert!(observer.contains("observe_same_service_cgroup_isolation"));
        assert!(observer.contains("cgroup_v2_id"));
        assert!(observer.contains("StatVfsMountFlags::RDONLY"));
        assert!(observer.contains("exits: &ObservedExactInheritedWorkerExitSet"));
        assert!(observer.contains("ResolveFlags::BENEATH"));
        assert!(observer.contains("ResolveFlags::NO_XDEV"));
        assert!(observer.contains("OFlags::RDONLY"));
    }

    #[test]
    fn cleanup_confirmed_restart_composition_is_exact_read_only_and_precedes_continuation() {
        let source = include_str!("systemd_custody.rs");
        let start = source
            .find("pub(crate) fn settle_cleanup_confirmed_restart_absence")
            .expect("cleanup-confirmed restart composition");
        let end = source[start..]
            .find("fn classify_journal_targets")
            .map(|offset| start + offset)
            .expect("cleanup-confirmed restart composition end");
        let composition = &source[start..end];
        let classification = composition
            .find("is_cleanup_confirmed_no_stored_custody_only")
            .expect("complete classification gate");
        let initial_journal = composition
            .find("verify_classification_against_locked_journal")
            .expect("initial exact journal revalidation");
        let admission = composition
            .find("acquire_worker_spawn_admission_until")
            .expect("closed worker-spawn admission");
        let observe = composition
            .find("block_on(observe_cleanup_confirmed_manager_absence_with")
            .expect("non-cancellable fresh manager observation");
        let final_journal = composition
            .rfind("verify_classification_against_locked_journal")
            .expect("final exact journal revalidation");
        let continue_actor = composition
            .find("continue_cleanup_confirmed_absent(evidence)")
            .expect("one-shot actor continuation");
        assert!(classification < initial_journal);
        assert!(initial_journal < admission);
        assert!(admission < observe);
        assert!(observe < final_journal);
        assert!(final_journal < continue_actor);
        assert!(source.contains("baseline.observe_same_service_scope(deadline)"));
        assert!(composition.contains("fresh != classification.manager_inventory"));
        assert!(composition.contains("verify_complete_exact_set(&manager_bindings)"));
        for forbidden in [
            "confirm_cleanup(",
            "FDSTOREREMOVE",
            "READY=1",
            "bind_production_socket",
            "OFlags::WRONLY",
            "OFlags::RDWR",
            "worker_v3::",
        ] {
            assert!(
                !composition.contains(forbidden),
                "cleanup-confirmed restart composition unexpectedly contains {forbidden}"
            );
        }
        let server = include_str!("server.rs");
        let settlement = server
            .find("settle_cleanup_confirmed_restart_absence(")
            .expect("server settlement branch");
        let socket = server
            .find("bind_production_socket(prepared_runtime, ownership_runtime)")
            .expect("server socket publication");
        assert!(settlement < socket);
    }

    #[test]
    fn production_restart_refusal_retains_admission_and_journal_across_the_sync_join() {
        let source = include_str!("systemd_custody.rs");
        let start = source
            .find("pub(crate) fn observe_nonempty_restart_custody_for_refusal")
            .expect("production restart-refusal composition");
        let end = source[start..]
            .find("fn join_shared_service_cgroup_quiescence_with")
            .map(|offset| start + offset)
            .expect("restart-refusal composition end");
        let composition = &source[start..end];
        let initial_journal = composition
            .find("verify_classification_against_locked_journal")
            .expect("initial retained journal validation");
        let admission = composition
            .find("acquire_worker_spawn_admission_until")
            .expect("shared spawn admission");
        let pidfd = composition
            .find("observe_exact_inherited_worker_exits_with")
            .expect("exact process-pidfd observation");
        let sampling = composition
            .find("runtime.block_on(sample_shared_service_cgroup_quiescence")
            .expect("non-cancellable outer sampling drive");
        let join = composition
            .find("join_shared_service_cgroup_quiescence(exits, sampling)")
            .expect("synchronous cgroup join");
        let final_journal = composition
            .rfind("verify_classification_against_locked_journal")
            .expect("final retained journal validation");
        assert!(initial_journal < admission);
        assert!(admission < pidfd);
        assert!(pidfd < sampling);
        assert!(sampling < join);
        assert!(join < final_journal);
        for forbidden in [
            "continue_empty",
            "confirm_cleanup",
            "confirm_manager_absent",
            "FDSTOREREMOVE",
            "READY=1",
            "bind_production_socket",
            "OFlags::WRONLY",
            "OFlags::RDWR",
        ] {
            assert!(
                !composition.contains(forbidden),
                "restart refusal unexpectedly contains {forbidden} authority"
            );
        }
        assert!(
            include_str!("server.rs").contains("observe_nonempty_restart_custody_for_refusal(")
        );
    }

    #[test]
    fn observer_surface_has_no_reopen_signal_cleanup_journal_or_server_authority() {
        let source = include_str!("systemd_custody.rs");
        let start = source
            .find("trait ProcessPidfdExitObserver")
            .expect("observer source start");
        let end = source[start..]
            .find("/// Consume the complete affine systemd startup snapshot")
            .map(|offset| start + offset)
            .expect("observer source end");
        let observer = &source[start..end];
        for forbidden in [
            "pidfd_open(",
            "waitid",
            "pidfd_send_signal",
            "kill(",
            "as_raw_fd",
            "RawFd",
            "from_raw_fd",
            "FDSTOREREMOVE",
            "confirm_cleanup",
            "confirm_manager_absent",
            "journal.transition",
            "run_production_server",
            "continue_empty",
        ] {
            assert!(
                !observer.contains(forbidden),
                "observer unexpectedly contains {forbidden} authority"
            );
        }
        assert!(!include_str!("server.rs").contains("observe_exact_inherited_worker_exits"));
        assert!(
            include_str!("worker_sandbox.rs")
                .contains("let pidfd = pidfd_open(pid, PidfdFlags::empty())")
        );
        assert!(observer.contains("wait_for_process_pidfd_exit"));
        assert!(observer.contains("verify_exact_target"));
    }
}
