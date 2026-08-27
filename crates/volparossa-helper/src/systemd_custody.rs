//! Fail-closed systemd descriptor-store startup boundary.
//!
//! Debian 13 systemd may return descriptor-store entries to the service on restart. The current
//! production recovery executor cannot consume those entries yet, so the executable bootstrap
//! transfers one affine snapshot of the exact inherited descriptor range before any thread or
//! worker can be created. This module consumes that snapshot, canonicalises each pair into typed
//! pidfd/network-namespace ownership, validates identity separation and the exact bounded naming
//! shape, and classifies it against one lock-held durable-journal projection plus a barrier-ordered
//! stable manager inventory. Every non-empty classification still refuses to publish the helper
//! socket. This prevents inherited recovery capability from being silently ignored or leaked into
//! a child without prematurely treating observation as adoption or cleanup authority.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt, io,
    num::NonZeroUsize,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

use crate::{
    deadline::{HardDeadline, wait_for_process_pidfd_exit},
    ownership_journal::{
        DurableCustodyDescriptorBinding, StartupCustodyPhase, StartupCustodyTarget,
    },
    systemd_fdstore::{
        BorrowedCustodyPair, CustodyDescriptorBinding, CustodyFdName, StableStartupInventory,
        observe_current_process_startup_inventory,
    },
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
    _manager_inventory: StableStartupInventory,
    classified: Vec<ClassifiedStartupCustodyTarget>,
}

impl StartupCustodyClassification {
    pub(crate) fn is_empty(&self) -> bool {
        self.custody.is_empty() && self.classified.is_empty()
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

/// Fixed failure classes for the dormant exact process-pidfd exit observer.
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

/// Dormant observation-only seam for exact inherited process-pidfd exit.
///
/// The complete classification is consumed and returned in every outcome. Cleanup-confirmed
/// targets are deliberately skipped: their earlier cleanup transition must not be replaced or
/// repeated by this weaker observation. Every pending `MayOwn` target must have one exact-present
/// inherited bundle before any wait starts, and all such targets must reach `POLLIN` before the
/// same absolute deadline. All pending bindings are then remeasured as one complete pending set.
/// Process-wide semantics rely on the private custody source having used `PidfdFlags::empty()`;
/// pidfs object typing alone cannot prove that flag history. Production does not call this function
/// yet.
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
        _manager_inventory: verified.manager_inventory,
        classified,
    })
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
    let pidfd = rustix::fs::fstatfs(descriptor).map_err(rustix_io)?.f_type == PID_FS_MAGIC;
    if pidfd {
        return Ok(InheritedDescriptorRole::Pidfd);
    }
    match volparossa_linux_uapi::namespace_type(&descriptor) {
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
        collections::VecDeque,
        ffi::OsString,
        fs::File,
        num::{NonZeroU32, NonZeroU64},
        os::fd::{AsRawFd, OwnedFd},
        os::unix::ffi::OsStringExt,
        process::Command,
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
    use crate::systemd_fdstore::stable_startup_inventory_for_test;
    use volparossa_linux_uapi::duplicate_descriptor_cloexec;

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
        let status = rustix::fs::fstat(&namespace).expect("stat current network namespace");
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
            _manager_inventory: manager_inventory,
            classified,
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
            _manager_inventory: stable_startup_inventory_for_test(&BTreeMap::new()),
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
        let status = rustix::fs::fstat(&namespace).expect("stat network namespace");
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
