//! Single-writer actor for durable helper ownership.
//!
//! Production owns this actor for startup, live Prepare admission, same-runtime clean settlement
//! and shutdown. It owns the journal and trusted recovery executor on one named OS thread, exposes
//! no revision/CAS surface, and never reopens a store in the same process after its store-identity
//! latch has been acquired. The installed restart executor remains a separate fail-closed refusal;
//! only opaque functional-backend evidence joined to the affine live-Prepare settlement may
//! request the private same-runtime proof echo. Startup additionally accepts one opaque exact-set
//! manager-absence owner only for records which were already durably `CleanupConfirmed`; it never
//! supplies the installed executor with worker/kernel cleanup authority.
//!
//! A recovery executor cannot be forcefully cancelled safely. If it exceeds the bounded reply
//! wait, admission becomes permanently ambiguous and the worker handle is detached instead of
//! joined. The process-lifetime latch remains set, the journal lock remains held while the worker
//! is stuck, and at most that already-accepted recovery may finish late; no later command runs.
//! The same absolute deadline reaches the trusted executor and is checked again before a recovery
//! proof may mutate the journal, so a late executor return cannot publish `Absent`. Deadlines are
//! also rechecked before startup touches the store and after every dequeue. An expired,
//! not-yet-started command is mutation-free; non-recovery journal I/O which already started always
//! settles before its late result fences admission.

use std::{
    fmt, fs,
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(not(test))]
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::{collections::BTreeSet, sync::OnceLock};

use volparossa_routing::PrepareIntent;

use crate::{
    deadline::HardDeadline,
    internal_protocol::PrepareLeases,
    systemd_custody::{CleanupConfirmedManagerAbsenceEvidence, RestartMayOwnCleanupEvidence},
    worker_v3::{
        ExactNeverDispatchedPrepareProof, ExactSameRuntimeCleanupProof,
        ExactSameRuntimeManagerAbsenceProof, ExactUndispatchedDurableAuthority,
        ExactUndispatchedPrepareCleanupProof,
    },
};

use super::{
    CleanupExecutor, ClosedPlan, ConfirmedManagerAbsentProof, DurableCustodyDescriptorBinding,
    DurableWireguardResource, Id16, JournalConfig, JournalEpochId, JournalError, JournalSnapshot,
    ManagerAbsenceExecutor, ManagerAbsenceTarget, NewOwnershipIntent, OwnershipId,
    OwnershipJournal, OwnershipPhase, PrepareRecoveryAnchorV1, PrepareRecoveryEvidenceV1,
    RuntimeId, SameRuntimeCleanSettlement, SettlementAttemptError, open_verified_parent,
    random_ownership_id,
};
#[cfg(test)]
use super::{DurableCustodyDescriptorIdentity, DurableCustodyDescriptorIdentityParts};

const MAX_ACCEPTED_OPERATIONS: usize = 4;
const COMMAND_CHANNEL_CAPACITY: usize = MAX_ACCEPTED_OPERATIONS + 1;
const MAX_STARTUP_CUSTODY_TARGETS: usize = 64;
const ACTOR_THREAD_NAME: &str = "volparossa-ownership-journal";
const DURABLE_CUSTODY_NAME_DOMAIN: &str = "VOLPAROSSA helper durable systemd custody name v1";
const DURABLE_CUSTODY_NAME_DIGEST_BYTES: usize = 32;
const DURABLE_CUSTODY_NAME_HEX_BYTES: usize = DURABLE_CUSTODY_NAME_DIGEST_BYTES * 2;
const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
#[cfg(not(test))]
const REPLY_WAIT_LIMIT: Duration = Duration::from_secs(31);
#[cfg(test)]
const REPLY_WAIT_LIMIT: Duration = Duration::from_millis(250);
#[cfg(not(test))]
const THREAD_COMPLETION_WAIT_LIMIT: Duration = Duration::from_secs(1);
#[cfg(test)]
const THREAD_COMPLETION_WAIT_LIMIT: Duration = Duration::from_millis(250);

#[cfg(not(test))]
static STORE_STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static STARTED_STORES: OnceLock<Mutex<StartedStores>> = OnceLock::new();

#[derive(Clone, Eq, PartialEq)]
struct StoreIdentity {
    canonical_parent: PathBuf,
    parent_device: u64,
    parent_inode: u64,
}

#[cfg(test)]
#[derive(Default)]
struct StartedStores {
    canonical_parents: BTreeSet<PathBuf>,
    parent_objects: BTreeSet<(u64, u64)>,
    retained_parents: Vec<fs::File>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DurableOwnershipError {
    #[error("durable ownership admission is full")]
    Capacity,
    #[error("durable ownership request was rejected")]
    Rejected,
    #[error("durable ownership recovery did not confirm absence")]
    RecoveryNotConfirmed,
    #[error("durable ownership actor is unavailable")]
    Unavailable,
    #[error("durable ownership state is ambiguous")]
    Ambiguous,
    #[error("this durable ownership store already started in this process")]
    AlreadyStarted,
    #[error("durable ownership deadline elapsed before durable work began")]
    DeadlineElapsed,
}

fn default_actor_deadline() -> Result<HardDeadline, DurableOwnershipError> {
    let complete_wait = REPLY_WAIT_LIMIT
        .checked_add(THREAD_COMPLETION_WAIT_LIMIT)
        .ok_or(DurableOwnershipError::Unavailable)?;
    HardDeadline::after(complete_wait).map_err(|_| DurableOwnershipError::Unavailable)
}

fn ensure_deadline_before_acceptance(deadline: HardDeadline) -> Result<(), DurableOwnershipError> {
    deadline
        .ensure_remaining()
        .map_err(|_| DurableOwnershipError::DeadlineElapsed)
}

#[derive(Clone)]
struct DurablePrepareIntent(NewOwnershipIntent);

impl DurablePrepareIntent {
    fn try_from_wire(
        origin_runtime_id: [u8; 32],
        value: &PrepareIntent,
    ) -> Result<Self, DurableOwnershipError> {
        let origin_runtime_id =
            RuntimeId::new(origin_runtime_id).map_err(|_| DurableOwnershipError::Rejected)?;
        let context_id = Id16::new(
            value
                .route_context_id
                .as_slice()
                .try_into()
                .map_err(|_| DurableOwnershipError::Rejected)?,
        )
        .map_err(|_| DurableOwnershipError::Rejected)?;
        let prepare_request_id = Id16::new(
            value
                .prepare_request_id
                .as_slice()
                .try_into()
                .map_err(|_| DurableOwnershipError::Rejected)?,
        )
        .map_err(|_| DurableOwnershipError::Rejected)?;
        let prepare_operation_digest = value
            .prepare_operation_digest
            .as_slice()
            .try_into()
            .map_err(|_| DurableOwnershipError::Rejected)?;
        let setup_expires_at_unix =
            NonZeroU64::new(value.setup_expires_at_unix).ok_or(DurableOwnershipError::Rejected)?;
        let hard_expires_at_unix = NonZeroU64::new(value.hard_expires_at_unix)
            .filter(|hard| *hard >= setup_expires_at_unix)
            .ok_or(DurableOwnershipError::Rejected)?;
        let plan = ClosedPlan::try_from_wire(
            value
                .closed_plan
                .as_ref()
                .ok_or(DurableOwnershipError::Rejected)?,
        )
        .map_err(|_| DurableOwnershipError::Rejected)?;
        let ownership_id = random_ownership_id().map_err(|_| DurableOwnershipError::Unavailable)?;
        Ok(Self(NewOwnershipIntent {
            origin_runtime_id,
            ownership_id,
            context_id,
            prepare_request_id,
            prepare_operation_digest,
            setup_expires_at_unix,
            hard_expires_at_unix,
            plan,
        }))
    }
}

impl fmt::Debug for DurablePrepareIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePrepareIntent(<redacted>)")
    }
}

/// Unique, retryable owner of one validated wire Prepare intent.
///
/// This value is deliberately non-`Clone`: safe code can submit only the same retained owner
/// after a definite or ambiguous error and cannot independently mint multiple durable keys for
/// one wire message. The actor receives an internal payload copy while this owner stays with the
/// synchronous caller until registration is known to have succeeded.
#[must_use = "a durable intent registration must be registered or explicitly retained"]
pub(crate) struct DurableIntentRegistration(DurablePrepareIntent);

impl DurableIntentRegistration {
    pub(crate) fn try_from_wire(
        origin_runtime_id: [u8; 32],
        value: &PrepareIntent,
    ) -> Result<Self, DurableOwnershipError> {
        DurablePrepareIntent::try_from_wire(origin_runtime_id, value).map(Self)
    }

    pub(crate) const fn context_id(&self) -> [u8; 16] {
        self.0.0.context_id.0
    }

    fn actor_payload(&self) -> DurablePrepareIntent {
        self.0.clone()
    }
}

impl fmt::Debug for DurableIntentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableIntentRegistration(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurablePrepareAnchorParts {
    pub(crate) boot_id: [u8; 16],
    pub(crate) pid: NonZeroU32,
    pub(crate) process_start_ticks: NonZeroU64,
    pub(crate) network_namespace_device: NonZeroU64,
    pub(crate) network_namespace_inode: NonZeroU64,
    pub(crate) executable_device: NonZeroU64,
    pub(crate) executable_inode: NonZeroU64,
    pub(crate) service_cgroup_inode: NonZeroU64,
    pub(crate) service_cgroup_id: NonZeroU64,
}

/// Durable, two-coordinate identity of the service cgroup which originally contained a worker.
///
/// The inode and kernel cgroup ID must move together. This prevents an inode-only comparison from
/// treating PID-1 replacement or identifier reuse as continuity across a service restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableServiceCgroupIdentity {
    pub(crate) inode: NonZeroU64,
    pub(crate) kernel_id: NonZeroU64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurablePrepareAnchor(PrepareRecoveryAnchorV1);

impl DurablePrepareAnchor {
    pub(super) fn try_from_parts(
        parts: DurablePrepareAnchorParts,
    ) -> Result<Self, DurableOwnershipError> {
        Ok(Self(PrepareRecoveryAnchorV1 {
            boot_id: Id16::new(parts.boot_id).map_err(|_| DurableOwnershipError::Rejected)?,
            pid: parts.pid,
            process_start_ticks: parts.process_start_ticks,
            network_namespace_device: parts.network_namespace_device,
            network_namespace_inode: parts.network_namespace_inode,
            executable_device: parts.executable_device,
            executable_inode: parts.executable_inode,
            service_cgroup_inode: parts.service_cgroup_inode,
            service_cgroup_id: parts.service_cgroup_id,
        }))
    }
}

impl fmt::Debug for DurablePrepareAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePrepareAnchor(<redacted>)")
    }
}

#[cfg(test)]
fn custody_binding_for_test(
    anchor: DurablePrepareAnchor,
) -> Result<DurableCustodyDescriptorBinding, DurableOwnershipError> {
    let namespace_minor = u32::try_from(anchor.0.network_namespace_device.get())
        .map_err(|_| DurableOwnershipError::Rejected)?;
    let pidfd =
        DurableCustodyDescriptorIdentity::try_from_parts(DurableCustodyDescriptorIdentityParts {
            mode: NonZeroU32::new(0o100_600).expect("non-zero fixture mode"),
            device_major: 8,
            device_minor: anchor.0.pid.get(),
            inode: anchor.0.process_start_ticks,
            special_device_major: 0,
            special_device_minor: 0,
            status_flags: 0,
        })
        .ok_or(DurableOwnershipError::Rejected)?;
    let network_namespace =
        DurableCustodyDescriptorIdentity::try_from_parts(DurableCustodyDescriptorIdentityParts {
            mode: NonZeroU32::new(0o100_444).expect("non-zero fixture mode"),
            device_major: 0,
            device_minor: namespace_minor,
            inode: anchor.0.network_namespace_inode,
            special_device_major: 0,
            special_device_minor: 0,
            status_flags: 0,
        })
        .ok_or(DurableOwnershipError::Rejected)?;
    DurableCustodyDescriptorBinding::try_from_role_ordered(pidfd, network_namespace)
        .ok_or(DurableOwnershipError::Rejected)
}

#[derive(Eq, PartialEq)]
#[must_use = "a durable ownership key must be armed or explicitly retired"]
pub(crate) struct DurableOwnershipKey {
    coordinates: OwnershipCoordinates,
}

/// Copyable correlation identity for selecting one retained terminal without carrying mutation
/// authority. Only affine keys and proofs can expose this opaque value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurableOwnershipSelector(OwnershipCoordinates);

impl DurableOwnershipSelector {
    pub(crate) const fn from_key(key: &DurableOwnershipKey) -> Self {
        Self(key.coordinates)
    }

    pub(crate) const fn context_id(self) -> [u8; 16] {
        self.0.context_id.0
    }
}

impl fmt::Debug for DurableOwnershipSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableOwnershipSelector(<redacted>)")
    }
}

/// Stable, secret-free descriptor-store identity derived from one exact durable key.
///
/// This value is not ownership authority and is therefore copyable. Its raw digest remains
/// private; the only exposed representation is a fixed-size lowercase hexadecimal buffer for the
/// systemd descriptor-store naming boundary.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DurableCustodyNameDigest([u8; DURABLE_CUSTODY_NAME_DIGEST_BYTES]);

impl DurableCustodyNameDigest {
    pub(crate) fn encode_lower_hex(self) -> [u8; DURABLE_CUSTODY_NAME_HEX_BYTES] {
        let mut encoded = [0_u8; DURABLE_CUSTODY_NAME_HEX_BYTES];
        for (byte, pair) in self.0.iter().zip(encoded.chunks_exact_mut(2)) {
            pair[0] = LOWER_HEX_DIGITS[usize::from(*byte >> 4)];
            pair[1] = LOWER_HEX_DIGITS[usize::from(*byte & 0x0f)];
        }
        encoded
    }

    #[cfg(test)]
    pub(crate) const fn for_test(bytes: [u8; DURABLE_CUSTODY_NAME_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DurableCustodyNameDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableCustodyNameDigest(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OwnershipCoordinates {
    journal_epoch_id: JournalEpochId,
    context_id: Id16,
    ownership_id: OwnershipId,
    generation: NonZeroU64,
}

fn custody_name_digest_for_coordinates(
    coordinates: OwnershipCoordinates,
) -> DurableCustodyNameDigest {
    let mut digest = blake3::Hasher::new_derive_key(DURABLE_CUSTODY_NAME_DOMAIN);
    digest.update(&coordinates.journal_epoch_id.0);
    digest.update(&coordinates.context_id.0);
    digest.update(&coordinates.ownership_id.0);
    digest.update(&coordinates.generation.get().to_be_bytes());
    DurableCustodyNameDigest(*digest.finalize().as_bytes())
}

pub(super) fn custody_name_digest_for_record(
    record: &super::OwnershipRecord,
) -> DurableCustodyNameDigest {
    custody_name_digest_for_coordinates(OwnershipCoordinates {
        journal_epoch_id: record.journal_epoch_id,
        context_id: record.context_id,
        ownership_id: record.ownership_id,
        generation: record.generation,
    })
}

/// Durable phase of one exact startup custody target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupCustodyPhase {
    MayOwnCustody,
    MayOwnPrepare,
    CleanupConfirmed,
}

/// Opaque, copyable correlation evidence from one exact locked journal snapshot.
///
/// This is neither ownership nor cleanup authority. The name digest, phase, complete opaque
/// recovery anchor and descriptor binding are sufficient only for exact-set restart correlation
/// while the startup guard remains live.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StartupCustodyTarget {
    phase: StartupCustodyPhase,
    custody_name_digest: DurableCustodyNameDigest,
    recovery_anchor: DurablePrepareAnchor,
    durable_binding: DurableCustodyDescriptorBinding,
    restart_plan: Option<StartupRestartPlan>,
}

/// Secret-free, journal-derived identity of the worker bootstrap which preceded custody.
///
/// This is observation input only. It carries no journal key, kernel mutation authority or raw
/// descriptor. A zero `path_id` means that the durable plan contains more than one path and is
/// deliberately outside the first restart-reaper slice.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StartupRestartPlan {
    network: RestartNetworkPlan,
    boot_id: [u8; 16],
    network_namespace_device: NonZeroU64,
    network_namespace_inode: NonZeroU64,
    executable_device: NonZeroU64,
    executable_inode: NonZeroU64,
}

/// Fixed operational subset transferred to the authenticated reaper child.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RestartNetworkPlan {
    context_id: [u8; 16],
    context_role: volparossa_routing::ContextRole,
    path_id: u8,
}

impl RestartNetworkPlan {
    pub(crate) fn from_authenticated_reaper(
        context_id: [u8; 16],
        context_role: volparossa_routing::ContextRole,
        path_id: u8,
    ) -> Option<Self> {
        (!context_id.iter().all(|byte| *byte == 0)
            && context_role != volparossa_routing::ContextRole::Unspecified
            && (1..=8).contains(&path_id))
        .then_some(Self {
            context_id,
            context_role,
            path_id,
        })
    }

    pub(crate) const fn context_id(self) -> [u8; 16] {
        self.context_id
    }

    pub(crate) const fn context_role(self) -> volparossa_routing::ContextRole {
        self.context_role
    }

    pub(crate) const fn path_id(self) -> u8 {
        self.path_id
    }
}

impl StartupRestartPlan {
    pub(crate) const fn context_id(self) -> [u8; 16] {
        self.network.context_id()
    }

    pub(crate) const fn context_role(self) -> volparossa_routing::ContextRole {
        self.network.context_role()
    }

    pub(crate) const fn path_id(self) -> u8 {
        self.network.path_id()
    }

    pub(crate) const fn network_plan(self) -> RestartNetworkPlan {
        self.network
    }

    pub(crate) const fn boot_id(self) -> [u8; 16] {
        self.boot_id
    }

    pub(crate) const fn network_namespace_identity(self) -> (NonZeroU64, NonZeroU64) {
        (self.network_namespace_device, self.network_namespace_inode)
    }

    pub(crate) const fn executable_identity(self) -> (NonZeroU64, NonZeroU64) {
        (self.executable_device, self.executable_inode)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        context_id: [u8; 16],
        context_role: volparossa_routing::ContextRole,
        path_id: u8,
        boot_id: [u8; 16],
        network_namespace_identity: (NonZeroU64, NonZeroU64),
        executable_identity: (NonZeroU64, NonZeroU64),
    ) -> Self {
        Self {
            network: RestartNetworkPlan {
                context_id,
                context_role,
                path_id,
            },
            boot_id,
            network_namespace_device: network_namespace_identity.0,
            network_namespace_inode: network_namespace_identity.1,
            executable_device: executable_identity.0,
            executable_inode: executable_identity.1,
        }
    }
}

impl fmt::Debug for StartupRestartPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartupRestartPlan(<redacted>)")
    }
}

impl StartupCustodyTarget {
    pub(crate) const fn phase(&self) -> StartupCustodyPhase {
        self.phase
    }

    pub(crate) const fn custody_name_digest(&self) -> DurableCustodyNameDigest {
        self.custody_name_digest
    }

    pub(crate) const fn durable_binding(&self) -> DurableCustodyDescriptorBinding {
        self.durable_binding
    }

    pub(crate) const fn restart_plan(&self) -> Option<StartupRestartPlan> {
        self.restart_plan
    }

    pub(crate) fn same_identity_except_phase(&self, other: &Self) -> bool {
        self.custody_name_digest == other.custody_name_digest
            && self.recovery_anchor == other.recovery_anchor
            && self.durable_binding == other.durable_binding
            && self.restart_plan == other.restart_plan
    }

    /// Compare one opaque complete worker anchor without exposing any of its numeric coordinates.
    #[cfg(test)]
    pub(crate) fn matches_recovery_anchor(&self, candidate: &DurablePrepareAnchor) -> bool {
        self.recovery_anchor == *candidate
    }

    /// Revalidate the portion of the complete anchor which the inherited custody pair can
    /// independently attest after process exit.
    ///
    /// The other anchor fields remain bound by this target's private construction from one exact
    /// validated, lock-held journal record; Linux exposes no safe way to reconstruct them from an
    /// already-terminal pidfd.
    pub(crate) fn has_valid_recovery_binding(&self) -> bool {
        self.durable_binding
            .0
            .validate_against_anchor(self.recovery_anchor.0)
            .is_ok()
    }

    /// Compare the opaque recovery anchor's service-cgroup inode without exposing it.
    ///
    /// This is correlation evidence only. A match neither authorizes cgroup mutation nor proves
    /// that the cgroup is empty, undelegated, or immutable.
    pub(crate) fn service_cgroup_identity(&self) -> DurableServiceCgroupIdentity {
        DurableServiceCgroupIdentity {
            inode: self.recovery_anchor.0.service_cgroup_inode,
            kernel_id: self.recovery_anchor.0.service_cgroup_id,
        }
    }

    pub(crate) fn matches_binding(&self, candidate: &DurableCustodyDescriptorBinding) -> bool {
        self.durable_binding.matches_role_ordered(candidate)
    }

    pub(crate) fn overlaps_binding(&self, candidate: &DurableCustodyDescriptorBinding) -> bool {
        self.durable_binding.overlaps(candidate)
    }

    #[cfg(test)]
    pub(crate) const fn for_test(
        phase: StartupCustodyPhase,
        custody_name_digest: DurableCustodyNameDigest,
        recovery_anchor: DurablePrepareAnchor,
        durable_binding: DurableCustodyDescriptorBinding,
    ) -> Self {
        Self {
            phase,
            custody_name_digest,
            recovery_anchor,
            durable_binding,
            restart_plan: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_restart_plan_for_test(mut self, plan: StartupRestartPlan) -> Self {
        self.restart_plan = Some(plan);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_phase_for_test(mut self, phase: StartupCustodyPhase) -> Self {
        self.phase = phase;
        self
    }
}

impl fmt::Debug for StartupCustodyTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartupCustodyTarget(<redacted>)")
    }
}

impl fmt::Debug for DurableOwnershipKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableOwnershipKey(<redacted>)")
    }
}

#[must_use = "MayOwnCustody authority must be armed or explicitly retained"]
pub(crate) struct DurableMayOwnCustody {
    key: DurableOwnershipKey,
}

impl DurableMayOwnCustody {
    pub(crate) const fn context_id(&self) -> [u8; 16] {
        self.key.coordinates.context_id.0
    }

    pub(crate) const fn selector(&self) -> DurableOwnershipSelector {
        DurableOwnershipSelector(self.key.coordinates)
    }

    /// Derive stable descriptor-store name material only after phase 4 is known durable.
    pub(crate) fn custody_name_digest(&self) -> DurableCustodyNameDigest {
        custody_name_digest_for_coordinates(self.key.coordinates)
    }
}

impl fmt::Debug for DurableMayOwnCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableMayOwnCustody(<redacted>)")
    }
}

/// Durable evidence that Prepare may own the exact ordered resource projection.
///
/// The key remains owned inside this token so safe code cannot arm the same authority twice. The
/// only exposed data is the typed context identity and borrowed, owner-bound resource metadata.
#[must_use = "MayOwnPrepare authority must remain owned until settled"]
pub(crate) struct DurableMayOwnPrepare {
    key: DurableOwnershipKey,
    resources: Vec<DurableWireguardResource>,
}

impl DurableMayOwnPrepare {
    pub(crate) const fn context_id(&self) -> [u8; 16] {
        self.key.coordinates.context_id.0
    }

    pub(crate) const fn selector(&self) -> DurableOwnershipSelector {
        DurableOwnershipSelector(self.key.coordinates)
    }

    pub(crate) fn resources(&self) -> &[DurableWireguardResource] {
        &self.resources
    }

    /// Canonically project the complete ordered durable plan for the private worker-v3 channel.
    ///
    /// No path, role, address, expiry or marker is supplied by an agent or call site. Production
    /// dispatch can consume this projection only with the same affine `MayOwnPrepare` owner.
    pub(crate) fn prepare_leases_v3(&self) -> Result<PrepareLeases, DurableOwnershipError> {
        let leases = self
            .resources
            .iter()
            .map(DurableWireguardResource::internal_lease_plan_v3)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DurableOwnershipError::Rejected)?;
        Ok(PrepareLeases {
            route_context_id: self.context_id().to_vec(),
            leases,
        })
    }

    /// Split the armed authority into the exact durable resources which may be dispatched and
    /// the affine journal settlement owner which must survive until cleanup is proven.
    ///
    /// The resources cannot be copied or reconstructed by a production caller. Consuming this
    /// value is therefore the only path from durable `MayOwnPrepare` evidence to live kernel
    /// owners, while the returned settlement token prevents that dispatch authority from being
    /// mistaken for a completed lifecycle.
    pub(crate) fn into_dispatch_parts(
        self,
    ) -> (DurablePrepareSettlement, Vec<DurableWireguardResource>) {
        let Self { key, resources } = self;
        (DurablePrepareSettlement { key }, resources)
    }
}

impl fmt::Debug for DurableMayOwnPrepare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableMayOwnPrepare(<redacted>)")
    }
}

/// Affine journal authority retained after the exact durable resources leave the actor token.
#[must_use = "dispatched durable Prepare ownership must be cleanup-confirmed or retained"]
pub(crate) struct DurablePrepareSettlement {
    key: DurableOwnershipKey,
}

impl DurablePrepareSettlement {
    pub(crate) const fn context_id(&self) -> [u8; 16] {
        self.key.coordinates.context_id.0
    }
}

impl fmt::Debug for DurablePrepareSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePrepareSettlement(<redacted>)")
    }
}

/// Affine proof that kernel/worker cleanup was durably confirmed but manager custody is not yet
/// proven absent.
#[must_use = "CleanupConfirmed ownership must be manager-absent-confirmed or retained"]
pub(crate) struct DurableCleanupConfirmed {
    key: DurableOwnershipKey,
}

impl DurableCleanupConfirmed {
    pub(crate) const fn context_id(&self) -> [u8; 16] {
        self.key.coordinates.context_id.0
    }
}

impl fmt::Debug for DurableCleanupConfirmed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableCleanupConfirmed(<redacted>)")
    }
}

#[must_use = "cleanup confirmation retains the opaque cleanup proof on every error"]
pub(crate) enum DurableCleanupOutcome {
    Confirmed(DurableCleanupConfirmed),
    Retained {
        error: DurableOwnershipError,
        proof: ExactSameRuntimeCleanupProof,
    },
}

#[must_use = "undispatched cleanup confirmation retains its opaque proof on every error"]
pub(crate) enum DurableUndispatchedCleanupOutcome {
    Confirmed(DurableCleanupConfirmed),
    Retained {
        error: DurableOwnershipError,
        proof: ExactUndispatchedPrepareCleanupProof,
    },
}

#[must_use = "manager-absence confirmation retains the opaque removal proof on every error"]
pub(crate) enum DurableManagerAbsentOutcome {
    Absent,
    Retained {
        error: DurableOwnershipError,
        proof: ExactSameRuntimeManagerAbsenceProof,
    },
}

#[must_use = "never-dispatched retirement retains the opaque absence proof on every error"]
pub(crate) enum DurableNeverDispatchedOutcome {
    Absent,
    Retained {
        error: DurableOwnershipError,
        proof: ExactNeverDispatchedPrepareProof,
    },
}

#[must_use = "registration outcomes retain the unique owner on every error"]
pub(crate) enum DurableRegistrationOutcome {
    Registered(DurableOwnershipKey),
    Retained {
        error: DurableOwnershipError,
        registration: DurableIntentRegistration,
    },
}

impl fmt::Debug for DurableRegistrationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registered(_) => formatter.write_str("Registered(<redacted>)"),
            Self::Retained { error, .. } => formatter
                .debug_struct("Retained")
                .field("error", error)
                .field("registration", &"<redacted>")
                .finish(),
        }
    }
}

#[must_use = "arm outcomes retain ownership on every error"]
pub(crate) enum DurableArmOutcome {
    Armed(DurableMayOwnPrepare),
    Retained {
        error: DurableOwnershipError,
        custody: DurableMayOwnCustody,
    },
}

impl fmt::Debug for DurableArmOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Armed(_) => formatter.write_str("Armed(<redacted>)"),
            Self::Retained { error, .. } => formatter
                .debug_struct("Retained")
                .field("error", error)
                .field("custody", &"<redacted>")
                .finish(),
        }
    }
}

#[must_use = "custody outcomes retain ownership on every error"]
pub(crate) enum DurableCustodyOutcome {
    Marked(DurableMayOwnCustody),
    Retained {
        error: DurableOwnershipError,
        key: DurableOwnershipKey,
    },
}

impl fmt::Debug for DurableCustodyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Marked(_) => formatter.write_str("Marked(<redacted>)"),
            Self::Retained { error, .. } => formatter
                .debug_struct("Retained")
                .field("error", error)
                .field("key", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Lifecycle {
    Starting = 1,
    Running = 2,
    Closing = 3,
    Stopped = 4,
    Unavailable = 5,
    Ambiguous = 6,
}

struct LifecycleState(AtomicU8);

impl LifecycleState {
    fn new() -> Self {
        Self(AtomicU8::new(Lifecycle::Starting as u8))
    }

    fn load(&self) -> Lifecycle {
        match self.0.load(Ordering::Acquire) {
            1 => Lifecycle::Starting,
            2 => Lifecycle::Running,
            3 => Lifecycle::Closing,
            4 => Lifecycle::Stopped,
            5 => Lifecycle::Unavailable,
            _ => Lifecycle::Ambiguous,
        }
    }

    fn transition(&self, next: Lifecycle) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let current = match current {
                    1 => Lifecycle::Starting,
                    2 => Lifecycle::Running,
                    3 => Lifecycle::Closing,
                    4 => Lifecycle::Stopped,
                    5 => Lifecycle::Unavailable,
                    _ => Lifecycle::Ambiguous,
                };
                let allowed = matches!(
                    (current, next),
                    (
                        Lifecycle::Starting,
                        Lifecycle::Running | Lifecycle::Unavailable | Lifecycle::Ambiguous
                    ) | (
                        Lifecycle::Running,
                        Lifecycle::Closing | Lifecycle::Unavailable | Lifecycle::Ambiguous
                    ) | (
                        Lifecycle::Closing,
                        Lifecycle::Stopped | Lifecycle::Unavailable | Lifecycle::Ambiguous
                    )
                );
                allowed.then_some(next as u8)
            });
    }

    fn mark_ambiguous(&self) {
        // Ambiguity is the strongest terminal state: a timeout or lost completion can reveal
        // uncertainty even after an earlier path tentatively classified the actor as stopped or
        // unavailable.
        self.0.store(Lifecycle::Ambiguous as u8, Ordering::Release);
    }

    fn admission_error(&self) -> DurableOwnershipError {
        match self.load() {
            Lifecycle::Ambiguous => DurableOwnershipError::Ambiguous,
            _ => DurableOwnershipError::Unavailable,
        }
    }

    fn disconnected_error(&self) -> DurableOwnershipError {
        match self.load() {
            Lifecycle::Ambiguous => DurableOwnershipError::Ambiguous,
            Lifecycle::Unavailable | Lifecycle::Stopped => DurableOwnershipError::Unavailable,
            Lifecycle::Starting | Lifecycle::Running | Lifecycle::Closing => {
                self.mark_ambiguous();
                DurableOwnershipError::Ambiguous
            }
        }
    }
}

struct ReplySender<T> {
    sender: SyncSender<Result<T, DurableOwnershipError>>,
    lifecycle: Arc<LifecycleState>,
    admission: Arc<Admission>,
    deadline: HardDeadline,
    armed: bool,
}

impl<T> ReplySender<T> {
    fn arm(&mut self) {
        self.armed = true;
    }

    fn complete(mut self, value: Result<T, DurableOwnershipError>) {
        self.armed = false;
        let value = if self.deadline.ensure_remaining().is_err() {
            self.admission
                .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
            Err(DurableOwnershipError::Ambiguous)
        } else {
            value
        };
        self.send_result(value);
    }

    fn complete_unstarted_deadline(mut self) {
        self.armed = false;
        self.send_result(Err(DurableOwnershipError::DeadlineElapsed));
    }

    fn send_result(&self, value: Result<T, DurableOwnershipError>) {
        match self.sender.try_send(value) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => self
                .admission
                .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous),
        }
    }
}

impl<T> Drop for ReplySender<T> {
    fn drop(&mut self) {
        if self.armed {
            self.admission
                .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
        }
    }
}

struct PendingReply<T> {
    receiver: Receiver<Result<T, DurableOwnershipError>>,
    lifecycle: Arc<LifecycleState>,
    admission: Arc<Admission>,
    deadline: HardDeadline,
}

struct ThreadCompletionGuard(Option<SyncSender<()>>);

impl Drop for ThreadCompletionGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}

impl<T> PendingReply<T> {
    fn wait(self) -> Result<T, DurableOwnershipError> {
        let Ok(remaining) = self.deadline.remaining() else {
            return self.resolve_after_deadline();
        };
        match self.receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                self.admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                Err(DurableOwnershipError::Ambiguous)
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                Err(self.lifecycle.disconnected_error())
            }
        }
    }

    fn resolve_after_deadline(&self) -> Result<T, DurableOwnershipError> {
        match self.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => {
                self.admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                Err(DurableOwnershipError::Ambiguous)
            }
            Err(TryRecvError::Disconnected) => {
                self.admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                Err(self.lifecycle.disconnected_error())
            }
        }
    }
}

fn reply_pair<T>(
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
    deadline: HardDeadline,
) -> (ReplySender<T>, PendingReply<T>) {
    let (sender, receiver) = sync_channel(1);
    (
        ReplySender {
            sender,
            lifecycle: Arc::clone(lifecycle),
            admission: Arc::clone(admission),
            deadline,
            armed: false,
        },
        PendingReply {
            receiver,
            lifecycle: Arc::clone(lifecycle),
            admission: Arc::clone(admission),
            deadline,
        },
    )
}

struct Admission {
    accepting: Mutex<bool>,
    accepted: AtomicUsize,
}

impl Admission {
    fn new() -> Self {
        Self {
            accepting: Mutex::new(true),
            accepted: AtomicUsize::new(0),
        }
    }

    fn fence_terminal(&self, lifecycle: &LifecycleState, terminal: Lifecycle) {
        match self.accepting.lock() {
            Ok(mut accepting) => {
                *accepting = false;
                if terminal == Lifecycle::Ambiguous {
                    lifecycle.mark_ambiguous();
                } else {
                    lifecycle.transition(terminal);
                }
            }
            Err(_) => lifecycle.mark_ambiguous(),
        }
    }
}

struct AdmissionPermit(Arc<Admission>);

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let previous = self.0.accepted.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "accepted operation accounting underflow");
    }
}

enum Operation {
    Register {
        deadline: HardDeadline,
        intent: DurablePrepareIntent,
        reply: ReplySender<DurableOwnershipKey>,
    },
    MarkCustody {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        reply: ReplySender<()>,
    },
    ArmCustody {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<Vec<DurableWireguardResource>>,
    },
    RetireNeverDispatched {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<()>,
    },
    ConfirmCleanup {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<()>,
    },
    ConfirmManagerAbsent {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<()>,
    },
    SameRuntimeCleanup {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<()>,
    },
    SameRuntimeManagerAbsent {
        deadline: HardDeadline,
        key: OwnershipCoordinates,
        reply: ReplySender<()>,
    },
    #[cfg(test)]
    PanicAfterRegister {
        deadline: HardDeadline,
        intent: DurablePrepareIntent,
        reply: ReplySender<DurableOwnershipKey>,
    },
    #[cfg(test)]
    TestBarrier {
        deadline: HardDeadline,
        hook: Box<dyn FnOnce() + Send>,
        reply: ReplySender<()>,
    },
}

enum Command {
    Operation {
        deadline: HardDeadline,
        operation: Operation,
        _permit: AdmissionPermit,
    },
    Shutdown {
        deadline: HardDeadline,
        reply: ReplySender<()>,
    },
}

enum StartupControl {
    Revalidate {
        reply: ReplySender<()>,
    },
    ConfirmRestartCleanup {
        evidence: Box<RestartMayOwnCleanupEvidence>,
        reply: ReplySender<Box<[StartupCustodyTarget]>>,
    },
    Continue {
        manager_absence: Option<CleanupConfirmedManagerAbsenceEvidence>,
    },
}

impl Operation {
    fn deadline(&self) -> HardDeadline {
        match self {
            Self::Register { deadline, .. }
            | Self::MarkCustody { deadline, .. }
            | Self::ArmCustody { deadline, .. }
            | Self::RetireNeverDispatched { deadline, .. }
            | Self::ConfirmCleanup { deadline, .. }
            | Self::ConfirmManagerAbsent { deadline, .. }
            | Self::SameRuntimeCleanup { deadline, .. }
            | Self::SameRuntimeManagerAbsent { deadline, .. } => *deadline,
            #[cfg(test)]
            Self::PanicAfterRegister { deadline, .. } | Self::TestBarrier { deadline, .. } => {
                *deadline
            }
        }
    }

    fn complete_unstarted_deadline(self) {
        match self {
            Self::Register { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
            #[cfg(test)]
            Self::PanicAfterRegister { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
            Self::MarkCustody { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
            Self::ArmCustody { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
            Self::RetireNeverDispatched { reply, .. }
            | Self::ConfirmCleanup { reply, .. }
            | Self::ConfirmManagerAbsent { reply, .. }
            | Self::SameRuntimeCleanup { reply, .. }
            | Self::SameRuntimeManagerAbsent { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
            #[cfg(test)]
            Self::TestBarrier { reply, .. } => {
                reply.complete_unstarted_deadline();
            }
        }
    }
}

#[derive(Clone)]
struct ActorClient {
    sender: SyncSender<Command>,
    admission: Arc<Admission>,
    lifecycle: Arc<LifecycleState>,
}

impl ActorClient {
    fn submit<T>(
        &self,
        deadline: HardDeadline,
        build: impl FnOnce(ReplySender<T>) -> Operation,
    ) -> Result<PendingReply<T>, DurableOwnershipError> {
        ensure_deadline_before_acceptance(deadline)?;
        let accepting = self.admission.accepting.lock().map_err(|_| {
            self.lifecycle.mark_ambiguous();
            DurableOwnershipError::Ambiguous
        })?;
        if !*accepting {
            return Err(self.lifecycle.admission_error());
        }
        if self.lifecycle.load() != Lifecycle::Running {
            return Err(self.lifecycle.admission_error());
        }
        // This is the admission linearization point. After this check succeeds and capacity is
        // reserved, the operation is allowed to run even if its caller drops the reply receiver.
        ensure_deadline_before_acceptance(deadline)?;
        self.admission
            .accepted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |accepted| {
                (accepted < MAX_ACCEPTED_OPERATIONS).then_some(accepted + 1)
            })
            .map_err(|_| DurableOwnershipError::Capacity)?;
        let permit = AdmissionPermit(Arc::clone(&self.admission));
        let (reply, pending) = reply_pair(&self.lifecycle, &self.admission, deadline);
        let command = Command::Operation {
            deadline,
            operation: build(reply),
            _permit: permit,
        };
        let result = match self.sender.try_send(command) {
            Ok(()) => Ok(pending),
            Err(TrySendError::Full(command)) => {
                drop(command);
                Err(DurableOwnershipError::Capacity)
            }
            Err(TrySendError::Disconnected(command)) => {
                drop(command);
                Err(self.lifecycle.disconnected_error())
            }
        };
        drop(accepting);
        result
    }

    #[cfg(test)]
    fn register_pending(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<PendingReply<DurableOwnershipKey>, DurableOwnershipError> {
        self.register_pending_until(intent, default_actor_deadline()?)
    }

    fn register_pending_until(
        &self,
        intent: DurablePrepareIntent,
        deadline: HardDeadline,
    ) -> Result<PendingReply<DurableOwnershipKey>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::Register {
            deadline,
            intent,
            reply,
        })
    }

    #[cfg(test)]
    fn mark_custody_pending(
        &self,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.mark_custody_pending_until(key, anchor, binding, default_actor_deadline()?)
    }

    fn mark_custody_pending_until(
        &self,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::MarkCustody {
            deadline,
            key,
            anchor,
            binding,
            reply,
        })
    }

    #[cfg(test)]
    fn arm_custody_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<Vec<DurableWireguardResource>>, DurableOwnershipError> {
        self.arm_custody_pending_until(key, default_actor_deadline()?)
    }

    fn arm_custody_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<Vec<DurableWireguardResource>>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::ArmCustody {
            deadline,
            key,
            reply,
        })
    }

    #[cfg(test)]
    fn retire_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.retire_pending_until(key, default_actor_deadline()?)
    }

    fn retire_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::RetireNeverDispatched {
            deadline,
            key,
            reply,
        })
    }

    #[cfg(test)]
    fn confirm_cleanup_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.confirm_cleanup_pending_until(key, default_actor_deadline()?)
    }

    fn confirm_cleanup_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::ConfirmCleanup {
            deadline,
            key,
            reply,
        })
    }

    #[cfg(test)]
    fn confirm_manager_absent_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.confirm_manager_absent_pending_until(key, default_actor_deadline()?)
    }

    fn confirm_manager_absent_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::ConfirmManagerAbsent {
            deadline,
            key,
            reply,
        })
    }

    fn same_runtime_cleanup_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::SameRuntimeCleanup {
            deadline,
            key,
            reply,
        })
    }

    fn same_runtime_manager_absent_pending_until(
        &self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::SameRuntimeManagerAbsent {
            deadline,
            key,
            reply,
        })
    }

    #[cfg(test)]
    fn panic_after_register_pending(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<PendingReply<DurableOwnershipKey>, DurableOwnershipError> {
        let deadline = default_actor_deadline()?;
        self.submit(deadline, |reply| Operation::PanicAfterRegister {
            deadline,
            intent,
            reply,
        })
    }

    #[cfg(test)]
    fn test_barrier_pending_until(
        &self,
        deadline: HardDeadline,
        hook: impl FnOnce() + Send + 'static,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(deadline, |reply| Operation::TestBarrier {
            deadline,
            hook: Box::new(hook),
            reply,
        })
    }

    #[cfg(test)]
    fn fence_and_shutdown(&self) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.fence_and_shutdown_until(default_actor_deadline()?)
    }

    fn fence_and_shutdown_until(
        &self,
        deadline: HardDeadline,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        ensure_deadline_before_acceptance(deadline)?;
        let mut accepting = self.admission.accepting.lock().map_err(|_| {
            self.lifecycle.mark_ambiguous();
            DurableOwnershipError::Ambiguous
        })?;
        if !*accepting {
            return Err(self.lifecycle.admission_error());
        }
        if self.lifecycle.load() != Lifecycle::Running {
            *accepting = false;
            return Err(self.lifecycle.admission_error());
        }
        ensure_deadline_before_acceptance(deadline)?;
        *accepting = false;
        self.lifecycle.transition(Lifecycle::Closing);
        let (reply, pending) = reply_pair(&self.lifecycle, &self.admission, deadline);
        match self.sender.try_send(Command::Shutdown { deadline, reply }) {
            Ok(()) => Ok(pending),
            Err(TrySendError::Full(command) | TrySendError::Disconnected(command)) => {
                drop(command);
                self.lifecycle.mark_ambiguous();
                Err(DurableOwnershipError::Ambiguous)
            }
        }
    }
}

/// Cloneable, arm-only admission authority for a durable custody token.
///
/// This handle deliberately owns no actor thread, join handle, recovery executor or lifecycle
/// transition API. Clones may only submit the exact `MayOwnCustody -> MayOwnPrepare` transition;
/// [`DurableOwnershipActor`] remains the sole owner of shutdown and thread settlement.
#[derive(Clone)]
#[must_use = "a custody arm handle is the bounded authority to arm durable custody"]
pub(crate) struct DurableCustodyArmHandle {
    client: ActorClient,
}

impl DurableCustodyArmHandle {
    pub(crate) fn arm_custody_until(
        &self,
        custody: DurableMayOwnCustody,
        deadline: HardDeadline,
    ) -> DurableArmOutcome {
        arm_custody_with_client(&self.client, custody, deadline)
    }
}

/// Cloneable, typed production admission and settlement authority.
///
/// This handle cannot start, stop or recover the journal actor. It accepts only immutable wire
/// intent registration, the exact worker-derived custody binding, arming of that same custody,
/// and the two ordered clean-settlement transitions. Clean settlement additionally requires
/// non-forgeable functional-backend evidence; every affine input is returned on failure.
#[derive(Clone)]
#[must_use = "durable Prepare admission remains bound to the owning journal runtime"]
pub(crate) struct DurableOwnershipPrepareHandle {
    client: ActorClient,
}

impl DurableOwnershipPrepareHandle {
    pub(crate) fn register_until(
        &self,
        registration: DurableIntentRegistration,
        deadline: HardDeadline,
    ) -> DurableRegistrationOutcome {
        let payload = registration.actor_payload();
        let result = self
            .client
            .register_pending_until(payload, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(key) => DurableRegistrationOutcome::Registered(key),
            Err(error) => DurableRegistrationOutcome::Retained {
                error,
                registration,
            },
        }
    }

    /// Inject a reply-path panic after a different Intent has durably registered.
    ///
    /// This cross-module test seam makes the actor deterministically ambiguous without exposing
    /// its client, journal coordinates or any production mutation authority.
    #[cfg(test)]
    pub(crate) fn panic_after_registration_for_test(
        &self,
        registration: DurableIntentRegistration,
    ) -> DurableRegistrationOutcome {
        let payload = registration.actor_payload();
        let result = self
            .client
            .panic_after_register_pending(payload)
            .and_then(PendingReply::wait);
        match result {
            Ok(key) => DurableRegistrationOutcome::Registered(key),
            Err(error) => DurableRegistrationOutcome::Retained {
                error,
                registration,
            },
        }
    }

    pub(crate) fn mark_custody_until(
        &self,
        key: DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> DurableCustodyOutcome {
        let result = self
            .client
            .mark_custody_pending_until(key.coordinates, anchor, binding, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => DurableCustodyOutcome::Marked(DurableMayOwnCustody { key }),
            Err(error) => DurableCustodyOutcome::Retained { error, key },
        }
    }

    pub(crate) fn custody_arm_handle(&self) -> DurableCustodyArmHandle {
        DurableCustodyArmHandle {
            client: self.client.clone(),
        }
    }

    pub(crate) fn retire_never_dispatched_until(
        &self,
        proof: ExactNeverDispatchedPrepareProof,
        deadline: HardDeadline,
    ) -> DurableNeverDispatchedOutcome {
        let result = self
            .client
            .retire_pending_until(proof.key().coordinates, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => DurableNeverDispatchedOutcome::Absent,
            Err(error) => DurableNeverDispatchedOutcome::Retained { error, proof },
        }
    }

    pub(crate) fn confirm_cleanup_until(
        &self,
        proof: ExactSameRuntimeCleanupProof,
        deadline: HardDeadline,
    ) -> DurableCleanupOutcome {
        let result = self
            .client
            .same_runtime_cleanup_pending_until(proof.settlement().key.coordinates, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => {
                let settlement = proof.into_settlement();
                DurableCleanupOutcome::Confirmed(DurableCleanupConfirmed {
                    key: settlement.key,
                })
            }
            Err(error) => DurableCleanupOutcome::Retained { error, proof },
        }
    }

    pub(crate) fn confirm_undispatched_cleanup_until(
        &self,
        proof: ExactUndispatchedPrepareCleanupProof,
        deadline: HardDeadline,
    ) -> DurableUndispatchedCleanupOutcome {
        let result = self
            .client
            .same_runtime_cleanup_pending_until(proof.selector().0, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => {
                let key = match proof.into_authority() {
                    ExactUndispatchedDurableAuthority::Custody(authority) => authority.key,
                    ExactUndispatchedDurableAuthority::Prepare(authority) => authority.key,
                };
                DurableUndispatchedCleanupOutcome::Confirmed(DurableCleanupConfirmed { key })
            }
            Err(error) => DurableUndispatchedCleanupOutcome::Retained { error, proof },
        }
    }

    pub(crate) fn confirm_manager_absent_until(
        &self,
        proof: ExactSameRuntimeManagerAbsenceProof,
        deadline: HardDeadline,
    ) -> DurableManagerAbsentOutcome {
        let result = self
            .client
            .same_runtime_manager_absent_pending_until(proof.cleanup().key.coordinates, deadline)
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => DurableManagerAbsentOutcome::Absent,
            Err(error) => DurableManagerAbsentOutcome::Retained { error, proof },
        }
    }
}

/// Affine owner of one exact lock-held startup snapshot awaiting external classification.
pub(super) struct DurableOwnershipStartup {
    targets: Box<[StartupCustodyTarget]>,
    control: Option<SyncSender<StartupControl>>,
    final_pending: Option<PendingReply<()>>,
    client: Option<ActorClient>,
    join: Option<JoinHandle<()>>,
    completion: Option<Receiver<()>>,
    lifecycle: Arc<LifecycleState>,
    deadline: HardDeadline,
}

impl DurableOwnershipStartup {
    pub(super) fn targets(&self) -> &[StartupCustodyTarget] {
        &self.targets
    }

    pub(super) fn revalidate_targets(
        &mut self,
    ) -> Result<&[StartupCustodyTarget], DurableOwnershipError> {
        ensure_deadline_before_acceptance(self.deadline)?;
        if self.lifecycle.load() != Lifecycle::Starting {
            return Err(self.lifecycle.admission_error());
        }
        let client = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?;
        let (reply, pending) = reply_pair(&self.lifecycle, &client.admission, self.deadline);
        let control = StartupControl::Revalidate { reply };
        match self
            .control
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .try_send(control)
        {
            Ok(()) => pending.wait()?,
            Err(TrySendError::Full(control)) => {
                drop(control);
                client
                    .admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                return Err(DurableOwnershipError::Ambiguous);
            }
            Err(TrySendError::Disconnected(control)) => {
                drop(control);
                return Err(self.lifecycle.disconnected_error());
            }
        }
        Ok(&self.targets)
    }

    /// Consume one exact restart-reaper proof and durably cross only
    /// `MayOwnCustody -> CleanupConfirmed` while the actor remains startup-locked.
    pub(super) fn confirm_single_restart_cleanup(
        &mut self,
        evidence: RestartMayOwnCleanupEvidence,
    ) -> Result<&[StartupCustodyTarget], DurableOwnershipError> {
        if !evidence.matches_exact_target_set(&self.targets) {
            return Err(DurableOwnershipError::RecoveryNotConfirmed);
        }
        self.revalidate_targets()?;
        let client = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?;
        let (reply, pending) = reply_pair(&self.lifecycle, &client.admission, self.deadline);
        match self
            .control
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .try_send(StartupControl::ConfirmRestartCleanup {
                evidence: Box::new(evidence),
                reply,
            }) {
            Ok(()) => {}
            Err(TrySendError::Full(control)) => {
                drop(control);
                client
                    .admission
                    .fence_terminal(&self.lifecycle, Lifecycle::Ambiguous);
                return Err(DurableOwnershipError::Ambiguous);
            }
            Err(TrySendError::Disconnected(control)) => {
                drop(control);
                return Err(self.lifecycle.disconnected_error());
            }
        }
        self.targets = pending.wait()?;
        if self.targets.len() != 1
            || self.targets[0].phase() != StartupCustodyPhase::CleanupConfirmed
        {
            self.lifecycle.mark_ambiguous();
            return Err(DurableOwnershipError::Ambiguous);
        }
        Ok(&self.targets)
    }

    pub(super) fn continue_empty(mut self) -> Result<DurableOwnershipActor, DurableOwnershipError> {
        if !self.targets.is_empty() {
            return Err(self.abort_with(DurableOwnershipError::RecoveryNotConfirmed, self.deadline));
        }
        self.continue_existing(None)
    }

    pub(super) fn continue_cleanup_confirmed_absent(
        mut self,
        evidence: CleanupConfirmedManagerAbsenceEvidence,
    ) -> Result<DurableOwnershipActor, DurableOwnershipError> {
        if !evidence.matches_exact_targets(&self.targets) {
            return Err(self.abort_with(DurableOwnershipError::RecoveryNotConfirmed, self.deadline));
        }
        self.continue_existing(Some(evidence))
    }

    fn continue_existing(
        mut self,
        manager_absence: Option<CleanupConfirmedManagerAbsenceEvidence>,
    ) -> Result<DurableOwnershipActor, DurableOwnershipError> {
        self.revalidate_targets()?;
        let control = self
            .control
            .take()
            .ok_or(DurableOwnershipError::Unavailable)?;
        match control.try_send(StartupControl::Continue { manager_absence }) {
            Ok(()) => {}
            Err(TrySendError::Full(control)) => {
                drop(control);
                self.lifecycle.mark_ambiguous();
                return Err(self.abort_with(DurableOwnershipError::Ambiguous, self.deadline));
            }
            Err(TrySendError::Disconnected(control)) => {
                drop(control);
                let error = self.lifecycle.disconnected_error();
                return Err(self.abort_with(error, self.deadline));
            }
        }
        drop(control);

        let result = self
            .final_pending
            .take()
            .ok_or(DurableOwnershipError::Unavailable)?
            .wait();
        match result {
            Ok(()) => Ok(DurableOwnershipActor {
                client: self.client.take(),
                join: self.join.take(),
                completion: self.completion.take(),
                lifecycle: Arc::clone(&self.lifecycle),
            }),
            Err(error) => Err(self.abort_with(error, self.deadline)),
        }
    }

    fn abort_with(
        &mut self,
        error: DurableOwnershipError,
        deadline: HardDeadline,
    ) -> DurableOwnershipError {
        self.control.take();
        self.final_pending.take();
        self.client.take();
        match (self.join.take(), self.completion.take()) {
            (Some(join), Some(completion)) => {
                if settle_thread_until(join, &completion, &self.lifecycle, deadline).is_err() {
                    DurableOwnershipError::Ambiguous
                } else {
                    error
                }
            }
            (None, None) => error,
            _ => {
                self.lifecycle.mark_ambiguous();
                DurableOwnershipError::Ambiguous
            }
        }
    }
}

impl Drop for DurableOwnershipStartup {
    fn drop(&mut self) {
        let Ok(deadline) = default_actor_deadline() else {
            self.lifecycle.mark_ambiguous();
            self.control.take();
            self.final_pending.take();
            self.client.take();
            self.join.take();
            self.completion.take();
            return;
        };
        let _ = self.abort_with(DurableOwnershipError::Unavailable, deadline);
    }
}

pub(crate) struct DurableOwnershipActor {
    client: Option<ActorClient>,
    join: Option<JoinHandle<()>>,
    completion: Option<Receiver<()>>,
    lifecycle: Arc<LifecycleState>,
}

impl DurableOwnershipActor {
    #[cfg(test)]
    pub(super) fn spawn_with_executor_factory<ExecutorFactory, Executor>(
        config: JournalConfig,
        executor_factory: ExecutorFactory,
    ) -> Result<Self, DurableOwnershipError>
    where
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::spawn_with_executor_factory_until(config, executor_factory, default_actor_deadline()?)
    }

    pub(super) fn spawn_with_executor_factory_until<ExecutorFactory, Executor>(
        config: JournalConfig,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<Self, DurableOwnershipError>
    where
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::spawn_inner(config, || {}, || {}, executor_factory, deadline)
    }

    pub(super) fn begin_with_executor_factory_until<ExecutorFactory, Executor>(
        config: JournalConfig,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<DurableOwnershipStartup, DurableOwnershipError>
    where
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::begin_inner(config, || {}, || {}, executor_factory, deadline)
    }

    #[cfg(test)]
    fn spawn_with_startup_hook<StartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        startup_hook: StartupHook,
        executor_factory: ExecutorFactory,
    ) -> Result<Self, DurableOwnershipError>
    where
        StartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::spawn_with_startup_hook_until(
            config,
            startup_hook,
            executor_factory,
            default_actor_deadline()?,
        )
    }

    #[cfg(test)]
    fn spawn_with_startup_hook_until<StartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        startup_hook: StartupHook,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<Self, DurableOwnershipError>
    where
        StartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::spawn_inner(config, || {}, startup_hook, executor_factory, deadline)
    }

    #[cfg(test)]
    fn spawn_with_pre_startup_hook_until<PreStartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        pre_startup_hook: PreStartupHook,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<Self, DurableOwnershipError>
    where
        PreStartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::spawn_inner(config, pre_startup_hook, || {}, executor_factory, deadline)
    }

    fn spawn_inner<PreStartupHook, StartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        pre_startup_hook: PreStartupHook,
        startup_hook: StartupHook,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<Self, DurableOwnershipError>
    where
        PreStartupHook: FnOnce() + Send + 'static,
        StartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        Self::begin_inner(
            config,
            pre_startup_hook,
            startup_hook,
            executor_factory,
            deadline,
        )?
        .continue_existing(None)
    }

    fn begin_inner<PreStartupHook, StartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        pre_startup_hook: PreStartupHook,
        startup_hook: StartupHook,
        executor_factory: ExecutorFactory,
        deadline: HardDeadline,
    ) -> Result<DurableOwnershipStartup, DurableOwnershipError>
    where
        PreStartupHook: FnOnce() + Send + 'static,
        StartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: CleanupExecutor + ManagerAbsenceExecutor + Send + 'static,
    {
        ensure_deadline_before_acceptance(deadline)?;
        let lifecycle = Arc::new(LifecycleState::new());
        let admission = Arc::new(Admission::new());
        let (sender, receiver) = sync_channel(COMMAND_CHANNEL_CAPACITY);
        let client = ActorClient {
            sender,
            admission,
            lifecycle: Arc::clone(&lifecycle),
        };
        let (preflight_reply, preflight_pending) =
            reply_pair(&lifecycle, &client.admission, deadline);
        let (final_reply, final_pending) = reply_pair(&lifecycle, &client.admission, deadline);
        let (control_sender, control_receiver) = sync_channel(1);
        let (completion_sender, completion_receiver) = sync_channel(1);
        let thread_lifecycle = Arc::clone(&lifecycle);
        let thread_admission = Arc::clone(&client.admission);
        // Thread creation is the startup admission point. Once this final deadline check passes,
        // startup is allowed to finish even if the caller stops waiting.
        ensure_deadline_before_acceptance(deadline)?;
        let join = thread::Builder::new()
            .name(ACTOR_THREAD_NAME.to_owned())
            .spawn(move || {
                let _completion = ThreadCompletionGuard(Some(completion_sender));
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    actor_thread(
                        config,
                        pre_startup_hook,
                        startup_hook,
                        executor_factory,
                        ActorThreadContext {
                            receiver: &receiver,
                            control_receiver: &control_receiver,
                            preflight_reply,
                            final_reply,
                            lifecycle: &thread_lifecycle,
                            admission: &thread_admission,
                            deadline,
                        },
                    );
                }));
                if outcome.is_err() {
                    thread_admission.fence_terminal(&thread_lifecycle, Lifecycle::Ambiguous);
                }
            })
            .map_err(|_| DurableOwnershipError::Unavailable)?;
        match preflight_pending.wait() {
            Ok(targets) => Ok(DurableOwnershipStartup {
                targets,
                control: Some(control_sender),
                final_pending: Some(final_pending),
                client: Some(client),
                join: Some(join),
                completion: Some(completion_receiver),
                lifecycle,
                deadline,
            }),
            Err(error) => {
                drop(control_sender);
                drop(final_pending);
                drop(client);
                if settle_thread_until(join, &completion_receiver, &lifecycle, deadline).is_err() {
                    Err(DurableOwnershipError::Ambiguous)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub(crate) fn register_until(
        &self,
        registration: DurableIntentRegistration,
        deadline: HardDeadline,
    ) -> DurableRegistrationOutcome {
        let payload = registration.actor_payload();
        let result = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)
            .and_then(|client| client.register_pending_until(payload, deadline))
            .and_then(PendingReply::wait);
        match result {
            Ok(key) => DurableRegistrationOutcome::Registered(key),
            Err(error) => DurableRegistrationOutcome::Retained {
                error,
                registration,
            },
        }
    }

    pub(crate) fn mark_custody_until(
        &self,
        key: DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> DurableCustodyOutcome {
        let result = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)
            .and_then(|client| {
                client.mark_custody_pending_until(key.coordinates, anchor, binding, deadline)
            })
            .and_then(PendingReply::wait);
        match result {
            Ok(()) => DurableCustodyOutcome::Marked(DurableMayOwnCustody { key }),
            Err(error) => DurableCustodyOutcome::Retained { error, key },
        }
    }

    pub(crate) fn arm_custody_until(
        &self,
        custody: DurableMayOwnCustody,
        deadline: HardDeadline,
    ) -> DurableArmOutcome {
        match self.client.as_ref() {
            Some(client) => arm_custody_with_client(client, custody, deadline),
            None => DurableArmOutcome::Retained {
                error: DurableOwnershipError::Unavailable,
                custody,
            },
        }
    }

    pub(crate) fn custody_arm_handle(
        &self,
    ) -> Result<DurableCustodyArmHandle, DurableOwnershipError> {
        self.client
            .clone()
            .map(|client| DurableCustodyArmHandle { client })
            .ok_or(DurableOwnershipError::Unavailable)
    }

    pub(crate) fn prepare_handle(
        &self,
    ) -> Result<DurableOwnershipPrepareHandle, DurableOwnershipError> {
        self.client
            .clone()
            .map(|client| DurableOwnershipPrepareHandle { client })
            .ok_or(DurableOwnershipError::Unavailable)
    }

    #[cfg(test)]
    fn register_intent(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<DurableOwnershipKey, DurableOwnershipError> {
        self.register_intent_until(intent, default_actor_deadline()?)
    }

    #[cfg(test)]
    fn register_intent_until(
        &self,
        intent: DurablePrepareIntent,
        deadline: HardDeadline,
    ) -> Result<DurableOwnershipKey, DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .register_pending_until(intent, deadline)?
            .wait()
    }

    #[cfg(test)]
    fn mark_custody_prepare(
        &self,
        key: &DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
    ) -> Result<(), DurableOwnershipError> {
        self.mark_custody_prepare_until(key, anchor, binding, default_actor_deadline()?)
    }

    #[cfg(test)]
    fn mark_custody_prepare_until(
        &self,
        key: &DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .mark_custody_pending_until(key.coordinates, anchor, binding, deadline)?
            .wait()
    }

    #[cfg(test)]
    fn arm_prepare(
        &self,
        key: &DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
    ) -> Result<(), DurableOwnershipError> {
        self.arm_prepare_until(key, anchor, default_actor_deadline()?)
    }

    #[cfg(test)]
    fn arm_prepare_until(
        &self,
        key: &DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.mark_custody_prepare_until(key, anchor, custody_binding_for_test(anchor)?, deadline)?;
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .arm_custody_pending_until(key.coordinates, deadline)?
            .wait()
            .map(drop)
    }

    #[cfg(test)]
    fn arm_custody_prepare(
        &self,
        custody: &DurableMayOwnCustody,
    ) -> Result<(), DurableOwnershipError> {
        self.arm_custody_prepare_until(custody, default_actor_deadline()?)
    }

    #[cfg(test)]
    fn arm_custody_prepare_until(
        &self,
        custody: &DurableMayOwnCustody,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .arm_custody_pending_until(custody.key.coordinates, deadline)?
            .wait()
            .map(drop)
    }

    #[cfg(test)]
    pub(super) fn retire_never_dispatched(
        &self,
        key: &DurableOwnershipKey,
    ) -> Result<(), DurableOwnershipError> {
        self.retire_never_dispatched_until(key, default_actor_deadline()?)
    }

    pub(super) fn retire_never_dispatched_until(
        &self,
        key: &DurableOwnershipKey,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .retire_pending_until(key.coordinates, deadline)?
            .wait()
    }

    #[cfg(test)]
    pub(super) fn confirm_cleanup(
        &self,
        key: &DurableOwnershipKey,
    ) -> Result<(), DurableOwnershipError> {
        self.confirm_cleanup_until(key, default_actor_deadline()?)
    }

    pub(super) fn confirm_cleanup_until(
        &self,
        key: &DurableOwnershipKey,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .confirm_cleanup_pending_until(key.coordinates, deadline)?
            .wait()
    }

    #[cfg(test)]
    pub(super) fn confirm_manager_absent(
        &self,
        key: &DurableOwnershipKey,
    ) -> Result<(), DurableOwnershipError> {
        self.confirm_manager_absent_until(key, default_actor_deadline()?)
    }

    pub(super) fn confirm_manager_absent_until(
        &self,
        key: &DurableOwnershipKey,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .confirm_manager_absent_pending_until(key.coordinates, deadline)?
            .wait()
    }

    #[cfg(test)]
    pub(super) fn shutdown(mut self) -> Result<(), DurableOwnershipError> {
        self.shutdown_until(default_actor_deadline()?)
    }

    /// Deterministically fence the actor for cross-module retained-owner tests.
    #[cfg(test)]
    pub(crate) fn shutdown_for_test(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.shutdown_until(deadline)
    }

    pub(super) fn shutdown_until(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        let pending = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .fence_and_shutdown_until(deadline)?;
        let reply = pending.wait();
        self.client.take();
        let settled = self.settle_thread_until(deadline);
        combine_shutdown_results(reply, settled)
    }

    fn settle_thread_until(&mut self, deadline: HardDeadline) -> Result<(), DurableOwnershipError> {
        let join = self.join.take().ok_or(DurableOwnershipError::Unavailable)?;
        let completion = self
            .completion
            .take()
            .ok_or(DurableOwnershipError::Unavailable)?;
        settle_thread_until(join, &completion, &self.lifecycle, deadline)
    }
}

fn arm_custody_with_client(
    client: &ActorClient,
    custody: DurableMayOwnCustody,
    deadline: HardDeadline,
) -> DurableArmOutcome {
    let result = client
        .arm_custody_pending_until(custody.key.coordinates, deadline)
        .and_then(PendingReply::wait);
    match result {
        Ok(resources) => DurableArmOutcome::Armed(DurableMayOwnPrepare {
            key: custody.key,
            resources,
        }),
        Err(error) => DurableArmOutcome::Retained { error, custody },
    }
}

fn combine_shutdown_results(
    reply: Result<(), DurableOwnershipError>,
    settled: Result<(), DurableOwnershipError>,
) -> Result<(), DurableOwnershipError> {
    if matches!(reply, Err(DurableOwnershipError::Ambiguous))
        || matches!(settled, Err(DurableOwnershipError::Ambiguous))
    {
        Err(DurableOwnershipError::Ambiguous)
    } else {
        reply.and(settled)
    }
}

impl Drop for DurableOwnershipActor {
    fn drop(&mut self) {
        let Ok(deadline) = default_actor_deadline() else {
            self.lifecycle.mark_ambiguous();
            self.client.take();
            self.join.take();
            self.completion.take();
            return;
        };
        let reply = self.client.as_ref().map_or(Ok(None), |client| {
            client.fence_and_shutdown_until(deadline).map(Some)
        });
        if let Ok(Some(pending)) = reply {
            let _ = pending.wait();
        }
        self.client.take();
        if let (Some(join), Some(completion)) = (self.join.take(), self.completion.take()) {
            let _ = settle_thread_until(join, &completion, &self.lifecycle, deadline);
        }
    }
}

fn settle_thread_until(
    join: JoinHandle<()>,
    completion: &Receiver<()>,
    lifecycle: &LifecycleState,
    deadline: HardDeadline,
) -> Result<(), DurableOwnershipError> {
    let Ok(remaining) = deadline.remaining() else {
        lifecycle.mark_ambiguous();
        drop(join);
        return Err(DurableOwnershipError::Ambiguous);
    };
    if completion.recv_timeout(remaining).is_err() {
        lifecycle.mark_ambiguous();
        drop(join);
        return Err(DurableOwnershipError::Ambiguous);
    }
    while !join.is_finished() && deadline.ensure_remaining().is_ok() {
        thread::yield_now();
    }
    if !join.is_finished() {
        lifecycle.mark_ambiguous();
        drop(join);
        return Err(DurableOwnershipError::Ambiguous);
    }
    join.join().map_err(|_| {
        lifecycle.mark_ambiguous();
        DurableOwnershipError::Ambiguous
    })
}

#[derive(Clone, Copy)]
enum FailureDisposition {
    Continue(DurableOwnershipError),
    Stop(DurableOwnershipError, Lifecycle),
}

enum OperationOutcome<T> {
    Complete(Result<T, DurableOwnershipError>),
    Stop(DurableOwnershipError, Lifecycle),
}

impl<T> OperationOutcome<T> {
    fn failure(disposition: FailureDisposition) -> Self {
        match disposition {
            FailureDisposition::Continue(error) => Self::Complete(Err(error)),
            FailureDisposition::Stop(error, lifecycle) => Self::Stop(error, lifecycle),
        }
    }
}

fn project_startup_custody_targets(
    snapshot: &JournalSnapshot,
) -> Result<Box<[StartupCustodyTarget]>, DurableOwnershipError> {
    let mut targets = Vec::with_capacity(snapshot.records.len().min(MAX_STARTUP_CUSTODY_TARGETS));
    for record in snapshot.records.values() {
        let Some(target) = project_startup_custody_target(record)? else {
            continue;
        };
        if targets.len() == MAX_STARTUP_CUSTODY_TARGETS {
            return Err(DurableOwnershipError::RecoveryNotConfirmed);
        }
        if targets.iter().any(|existing: &StartupCustodyTarget| {
            existing.custody_name_digest == target.custody_name_digest
                || existing.durable_binding.overlaps(&target.durable_binding)
        }) {
            return Err(DurableOwnershipError::RecoveryNotConfirmed);
        }
        targets.push(target);
    }
    targets.sort_unstable_by_key(|target| target.custody_name_digest);
    Ok(targets.into_boxed_slice())
}

fn project_startup_custody_target(
    record: &super::OwnershipRecord,
) -> Result<Option<StartupCustodyTarget>, DurableOwnershipError> {
    let phase = match record.phase {
        OwnershipPhase::MayOwnCustody => StartupCustodyPhase::MayOwnCustody,
        OwnershipPhase::MayOwnPrepare => StartupCustodyPhase::MayOwnPrepare,
        OwnershipPhase::CleanupConfirmed => StartupCustodyPhase::CleanupConfirmed,
        OwnershipPhase::Intent | OwnershipPhase::Absent => return Ok(None),
    };
    let Some(PrepareRecoveryEvidenceV1::CustodyBound { anchor, binding }) =
        record.recovery_evidence
    else {
        // Legacy MayOwnPrepare is not correlated to descriptor-store custody and must never be
        // interpreted as an absent or adoptable startup target.
        return Err(DurableOwnershipError::RecoveryNotConfirmed);
    };
    let first_path_id = record
        .plan
        .paths
        .first()
        .map(|path| path.path_id)
        .ok_or(DurableOwnershipError::RecoveryNotConfirmed)?;
    let path_id = if record
        .plan
        .paths
        .iter()
        .all(|path| path.path_id == first_path_id)
    {
        first_path_id
    } else {
        0
    };
    let context_role = super::routing_context_role(record.plan.context_role);
    Ok(Some(StartupCustodyTarget {
        phase,
        custody_name_digest: custody_name_digest_for_coordinates(OwnershipCoordinates {
            journal_epoch_id: record.journal_epoch_id,
            context_id: record.context_id,
            ownership_id: record.ownership_id,
            generation: record.generation,
        }),
        recovery_anchor: DurablePrepareAnchor(anchor),
        durable_binding: DurableCustodyDescriptorBinding(binding),
        restart_plan: Some(StartupRestartPlan {
            network: RestartNetworkPlan {
                context_id: record.context_id.0,
                context_role,
                path_id,
            },
            boot_id: anchor.boot_id.0,
            network_namespace_device: anchor.network_namespace_device,
            network_namespace_inode: anchor.network_namespace_inode,
            executable_device: anchor.executable_device,
            executable_inode: anchor.executable_inode,
        }),
    }))
}

struct ActorCore<Executor> {
    journal: OwnershipJournal,
    executor: Executor,
    startup_manager_absence: Option<CleanupConfirmedManagerAbsenceEvidence>,
    revision: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct CleanupConfirmedManagerAbsenceMismatch;

struct CleanupConfirmedManagerAbsenceExecutor<'a> {
    evidence: &'a mut CleanupConfirmedManagerAbsenceEvidence,
}

#[derive(Debug, Eq, PartialEq)]
struct RestartMayOwnCleanupMismatch;

struct RestartMayOwnCleanupExecutor<'a> {
    evidence: &'a mut RestartMayOwnCleanupEvidence,
}

impl CleanupExecutor for RestartMayOwnCleanupExecutor<'_> {
    type Error = RestartMayOwnCleanupMismatch;

    fn confirm_cleanup(
        &mut self,
        target: &super::CleanupTarget,
        _deadline: HardDeadline,
    ) -> Result<super::ConfirmedCleanupProof, Self::Error> {
        let candidate = project_startup_custody_target(&target.exact_record)
            .ok()
            .flatten()
            .filter(|candidate| candidate.phase() == StartupCustodyPhase::MayOwnCustody)
            .ok_or(RestartMayOwnCleanupMismatch)?;
        if !self.evidence.consume_exact_target(&candidate) {
            return Err(RestartMayOwnCleanupMismatch);
        }
        Ok(target.confirmed_cleanup())
    }
}

impl ManagerAbsenceExecutor for CleanupConfirmedManagerAbsenceExecutor<'_> {
    type Error = CleanupConfirmedManagerAbsenceMismatch;

    fn confirm_manager_absent(
        &mut self,
        target: &ManagerAbsenceTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
        let candidate = project_startup_custody_target(&target.exact_record)
            .ok()
            .flatten()
            .filter(|candidate| candidate.phase() == StartupCustodyPhase::CleanupConfirmed)
            .ok_or(CleanupConfirmedManagerAbsenceMismatch)?;
        if !self.evidence.consume_exact_target(&candidate) {
            return Err(CleanupConfirmedManagerAbsenceMismatch);
        }
        Ok(target.confirmed_manager_absent())
    }
}

impl<Executor: CleanupExecutor + ManagerAbsenceExecutor> ActorCore<Executor> {
    fn new(journal: OwnershipJournal, executor: Executor) -> Result<Self, FailureDisposition> {
        let revision = journal
            .snapshot()
            .map_err(|error| classify_without_healthcheck(&error))?
            .revision;
        Ok(Self {
            journal,
            executor,
            startup_manager_absence: None,
            revision,
        })
    }

    fn startup_sweep(&mut self, deadline: HardDeadline) -> Result<(), FailureDisposition> {
        let snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        self.validate_startup_manager_absence(snapshot)?;
        // Settle custody-bearing records before retiring any Intent. Production enters this sweep
        // with non-empty custody only for a prevalidated all-CleanupConfirmed set and one-shot
        // exact manager-absence evidence. The generic actor path preserves the distinct cleanup
        // and manager proofs used by tests and same-runtime composition.
        let custody_pending = snapshot
            .records
            .values()
            .filter_map(|record| {
                matches!(
                    record.phase,
                    OwnershipPhase::MayOwnCustody
                        | OwnershipPhase::MayOwnPrepare
                        | OwnershipPhase::CleanupConfirmed
                )
                .then_some((record.ownership_id, record.generation, record.phase))
            })
            .collect::<Vec<_>>();
        let intents = snapshot
            .records
            .values()
            .filter(|record| record.phase == OwnershipPhase::Intent)
            .map(|record| (record.ownership_id, record.generation))
            .collect::<Vec<_>>();
        for (ownership_id, generation, phase) in custody_pending {
            if deadline.ensure_remaining().is_err() {
                return Err(FailureDisposition::Continue(
                    DurableOwnershipError::DeadlineElapsed,
                ));
            }
            if phase != OwnershipPhase::CleanupConfirmed {
                self.revision = match self.journal.confirm_cleanup(
                    self.revision,
                    ownership_id,
                    generation,
                    &mut self.executor,
                    deadline,
                ) {
                    Ok(revision) => revision,
                    Err(error) => return Err(self.classify_settlement_error(error)),
                };
            }
            self.revision =
                self.settle_startup_manager_absent(ownership_id, generation, deadline)?;
        }
        if self
            .startup_manager_absence
            .as_ref()
            .is_some_and(|evidence| !evidence.is_consumed())
        {
            return Err(FailureDisposition::Stop(
                DurableOwnershipError::Ambiguous,
                Lifecycle::Ambiguous,
            ));
        }
        for (ownership_id, generation) in intents {
            if deadline.ensure_remaining().is_err() {
                return Err(FailureDisposition::Continue(
                    DurableOwnershipError::DeadlineElapsed,
                ));
            }
            self.revision = self
                .journal
                .mark_intent_absent(self.revision, ownership_id, generation)
                .map_err(|error| self.classify_journal_error(error))?;
        }
        let snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        if snapshot
            .records
            .values()
            .any(|record| record.phase != OwnershipPhase::Absent)
        {
            return Err(FailureDisposition::Stop(
                DurableOwnershipError::Ambiguous,
                Lifecycle::Ambiguous,
            ));
        }
        Ok(())
    }

    fn confirm_single_restart_cleanup(
        &mut self,
        mut evidence: RestartMayOwnCleanupEvidence,
        deadline: HardDeadline,
    ) -> Result<Box<[StartupCustodyTarget]>, FailureDisposition> {
        let snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        let targets =
            project_startup_custody_targets(snapshot).map_err(FailureDisposition::Continue)?;
        if !evidence.matches_exact_target_set(&targets) {
            return Err(FailureDisposition::Continue(
                DurableOwnershipError::RecoveryNotConfirmed,
            ));
        }
        let record_snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        let record = record_snapshot
            .records
            .values()
            .find(|record| record.phase == OwnershipPhase::MayOwnCustody)
            .cloned()
            .ok_or(FailureDisposition::Continue(
                DurableOwnershipError::RecoveryNotConfirmed,
            ))?;
        let mut executor = RestartMayOwnCleanupExecutor {
            evidence: &mut evidence,
        };
        self.revision = self
            .journal
            .confirm_cleanup(
                self.revision,
                record.ownership_id,
                record.generation,
                &mut executor,
                deadline,
            )
            .map_err(|error| self.classify_settlement_error(error))?;
        if !evidence.is_consumed() {
            return Err(FailureDisposition::Stop(
                DurableOwnershipError::Ambiguous,
                Lifecycle::Ambiguous,
            ));
        }
        self.confirm_complete_boundary().map_err(|_| {
            FailureDisposition::Stop(DurableOwnershipError::Ambiguous, Lifecycle::Ambiguous)
        })?;
        let snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        let targets =
            project_startup_custody_targets(snapshot).map_err(FailureDisposition::Continue)?;
        if targets.len() != 1 || targets[0].phase() != StartupCustodyPhase::CleanupConfirmed {
            return Err(FailureDisposition::Stop(
                DurableOwnershipError::Ambiguous,
                Lifecycle::Ambiguous,
            ));
        }
        Ok(targets)
    }

    fn validate_startup_manager_absence(
        &self,
        snapshot: &JournalSnapshot,
    ) -> Result<(), FailureDisposition> {
        let Some(evidence) = &self.startup_manager_absence else {
            return Ok(());
        };
        let targets =
            project_startup_custody_targets(snapshot).map_err(FailureDisposition::Continue)?;
        // Validate the complete canonical set before the first per-record CAS. This prevents
        // mixed, missing, duplicate or foreign evidence from partially settling the journal.
        if evidence.matches_exact_targets(&targets) {
            Ok(())
        } else {
            Err(FailureDisposition::Continue(
                DurableOwnershipError::RecoveryNotConfirmed,
            ))
        }
    }

    fn settle_startup_manager_absent(
        &mut self,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        deadline: HardDeadline,
    ) -> Result<u64, FailureDisposition> {
        if let Some(evidence) = &mut self.startup_manager_absence {
            let mut executor = CleanupConfirmedManagerAbsenceExecutor { evidence };
            return self
                .journal
                .confirm_manager_absent(
                    self.revision,
                    ownership_id,
                    generation,
                    &mut executor,
                    deadline,
                )
                .map_err(|error| self.classify_settlement_error(error));
        }
        self.journal
            .confirm_manager_absent(
                self.revision,
                ownership_id,
                generation,
                &mut self.executor,
                deadline,
            )
            .map_err(|error| self.classify_settlement_error(error))
    }

    fn register(&mut self, intent: DurablePrepareIntent) -> OperationOutcome<DurableOwnershipKey> {
        let context_id = intent.0.context_id;
        let journal_epoch_id = match self.journal.snapshot() {
            Ok(snapshot) => snapshot.journal_epoch_id,
            Err(error) => {
                return OperationOutcome::failure(self.classify_journal_error(error));
            }
        };
        match self.journal.insert_intent(self.revision, intent.0) {
            Ok(inserted) => {
                self.revision = inserted.revision;
                OperationOutcome::Complete(Ok(DurableOwnershipKey {
                    coordinates: OwnershipCoordinates {
                        journal_epoch_id,
                        context_id,
                        ownership_id: inserted.ownership_id,
                        generation: inserted.generation,
                    },
                }))
            }
            Err(error) => OperationOutcome::failure(self.classify_journal_error(error)),
        }
    }

    fn mark_custody(
        &mut self,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
        binding: DurableCustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.mark_may_own_custody(
            self.revision,
            key.ownership_id,
            key.generation,
            anchor.0,
            binding.0,
            deadline,
        ) {
            Ok(marked) => {
                self.revision = marked.revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(error) => OperationOutcome::failure(self.classify_journal_error(error)),
        }
    }

    fn arm_custody(
        &mut self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> OperationOutcome<Vec<DurableWireguardResource>> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.mark_may_own_prepare_from_custody(
            self.revision,
            key.ownership_id,
            key.generation,
            deadline,
        ) {
            Ok(marked) => {
                self.revision = marked.revision;
                OperationOutcome::Complete(Ok(marked.resources))
            }
            Err(error) => OperationOutcome::failure(self.classify_journal_error(error)),
        }
    }

    fn retire(&mut self, key: OwnershipCoordinates) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self
            .journal
            .mark_intent_absent(self.revision, key.ownership_id, key.generation)
        {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(error) => OperationOutcome::failure(self.classify_journal_error(error)),
        }
    }

    fn confirm_cleanup(
        &mut self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.confirm_cleanup(
            self.revision,
            key.ownership_id,
            key.generation,
            &mut self.executor,
            deadline,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(SettlementAttemptError::Executor(_)) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::RecoveryNotConfirmed))
            }
            Err(SettlementAttemptError::Deadline) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::DeadlineElapsed))
            }
            Err(SettlementAttemptError::Journal(error)) => {
                OperationOutcome::failure(self.classify_journal_error(error))
            }
        }
    }

    fn confirm_manager_absent(
        &mut self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.confirm_manager_absent(
            self.revision,
            key.ownership_id,
            key.generation,
            &mut self.executor,
            deadline,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(SettlementAttemptError::Executor(_)) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::RecoveryNotConfirmed))
            }
            Err(SettlementAttemptError::Deadline) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::DeadlineElapsed))
            }
            Err(SettlementAttemptError::Journal(error)) => {
                OperationOutcome::failure(self.classify_journal_error(error))
            }
        }
    }

    fn confirm_same_runtime_cleanup(
        &mut self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        let mut executor = SameRuntimeCleanSettlement;
        match self.journal.confirm_cleanup(
            self.revision,
            key.ownership_id,
            key.generation,
            &mut executor,
            deadline,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(SettlementAttemptError::Executor(error)) => match error {},
            Err(SettlementAttemptError::Deadline) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::DeadlineElapsed))
            }
            Err(SettlementAttemptError::Journal(error)) => {
                OperationOutcome::failure(self.classify_journal_error(error))
            }
        }
    }

    fn confirm_same_runtime_manager_absent(
        &mut self,
        key: OwnershipCoordinates,
        deadline: HardDeadline,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        let mut executor = SameRuntimeCleanSettlement;
        match self.journal.confirm_manager_absent(
            self.revision,
            key.ownership_id,
            key.generation,
            &mut executor,
            deadline,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(SettlementAttemptError::Executor(error)) => match error {},
            Err(SettlementAttemptError::Deadline) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::DeadlineElapsed))
            }
            Err(SettlementAttemptError::Journal(error)) => {
                OperationOutcome::failure(self.classify_journal_error(error))
            }
        }
    }

    fn classify_settlement_error<ExecutorError>(
        &mut self,
        error: SettlementAttemptError<ExecutorError>,
    ) -> FailureDisposition {
        match error {
            SettlementAttemptError::Executor(_) => {
                FailureDisposition::Continue(DurableOwnershipError::RecoveryNotConfirmed)
            }
            SettlementAttemptError::Deadline => {
                FailureDisposition::Continue(DurableOwnershipError::DeadlineElapsed)
            }
            SettlementAttemptError::Journal(error) => self.classify_journal_error(error),
        }
    }

    fn confirm_complete_boundary(&mut self) -> Result<(), DurableOwnershipError> {
        self.journal
            .confirm_retry_safe_after_definite_failure()
            .map_err(|_| DurableOwnershipError::Ambiguous)
    }

    fn confirm_quiescent_boundary(&mut self) -> Result<(), DurableOwnershipError> {
        self.confirm_complete_boundary()?;
        let snapshot = self
            .journal
            .snapshot()
            .map_err(|_| DurableOwnershipError::Ambiguous)?;
        if snapshot
            .records
            .values()
            .any(|record| record.phase != OwnershipPhase::Absent)
        {
            return Err(DurableOwnershipError::RecoveryNotConfirmed);
        }
        Ok(())
    }

    fn validate_key(&mut self, key: OwnershipCoordinates) -> Result<(), FailureDisposition> {
        match self.journal.snapshot() {
            Ok(snapshot)
                if snapshot.journal_epoch_id == key.journal_epoch_id
                    && snapshot
                        .records
                        .get(&key.ownership_id)
                        .is_some_and(|record| {
                            record.context_id == key.context_id
                                && record.generation == key.generation
                        }) =>
            {
                Ok(())
            }
            Ok(_) => Err(FailureDisposition::Continue(
                DurableOwnershipError::Rejected,
            )),
            Err(error) => Err(self.classify_journal_error(error)),
        }
    }

    fn classify_journal_error(&mut self, error: JournalError) -> FailureDisposition {
        match error {
            JournalError::Io(_) => match self.journal.confirm_retry_safe_after_definite_failure() {
                Ok(()) => FailureDisposition::Continue(DurableOwnershipError::Unavailable),
                Err(_) => {
                    FailureDisposition::Stop(DurableOwnershipError::Ambiguous, Lifecycle::Ambiguous)
                }
            },
            error => classify_without_healthcheck(&error),
        }
    }
}

fn classify_without_healthcheck(error: &JournalError) -> FailureDisposition {
    match error {
        JournalError::InvalidRecord | JournalError::InvalidTransition => {
            FailureDisposition::Continue(DurableOwnershipError::Rejected)
        }
        JournalError::Capacity => FailureDisposition::Continue(DurableOwnershipError::Capacity),
        JournalError::PersistUncertain
        | JournalError::Poisoned
        | JournalError::RevisionConflict
        | JournalError::ProofMismatch
        | JournalError::Corrupt
        | JournalError::LockHeld
        | JournalError::UnsafeMetadata
        | JournalError::Io(_) => {
            FailureDisposition::Stop(DurableOwnershipError::Ambiguous, Lifecycle::Ambiguous)
        }
        JournalError::Random => {
            FailureDisposition::Stop(DurableOwnershipError::Unavailable, Lifecycle::Unavailable)
        }
    }
}

fn classify_startup_error(error: &JournalError) -> FailureDisposition {
    match error {
        JournalError::LockHeld | JournalError::Random => {
            FailureDisposition::Stop(DurableOwnershipError::Unavailable, Lifecycle::Unavailable)
        }
        error => classify_without_healthcheck(error),
    }
}

fn derive_store_identity(
    config: &JournalConfig,
    parent_directory: &fs::File,
) -> Result<StoreIdentity, DurableOwnershipError> {
    let metadata = parent_directory
        .metadata()
        .map_err(|_| DurableOwnershipError::Unavailable)?;
    let canonical_parent =
        fs::canonicalize(&config.parent_path).map_err(|_| DurableOwnershipError::Unavailable)?;
    let canonical_metadata =
        fs::metadata(&canonical_parent).map_err(|_| DurableOwnershipError::Unavailable)?;
    if canonical_metadata.dev() != metadata.dev() || canonical_metadata.ino() != metadata.ino() {
        return Err(DurableOwnershipError::Unavailable);
    }
    Ok(StoreIdentity {
        canonical_parent,
        parent_device: metadata.dev(),
        parent_inode: metadata.ino(),
    })
}

#[cfg(not(test))]
fn acquire_start_latch(
    store: &StoreIdentity,
    parent_directory: &fs::File,
) -> Result<(), DurableOwnershipError> {
    let _ = store;
    let _ = parent_directory;
    if STORE_STARTED.swap(true, Ordering::AcqRel) {
        Err(DurableOwnershipError::AlreadyStarted)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn acquire_start_latch(
    store: &StoreIdentity,
    parent_directory: &fs::File,
) -> Result<(), DurableOwnershipError> {
    let started = STARTED_STORES.get_or_init(|| Mutex::new(StartedStores::default()));
    let mut started = started
        .lock()
        .map_err(|_| DurableOwnershipError::Ambiguous)?;
    let object = (store.parent_device, store.parent_inode);
    if started.canonical_parents.contains(&store.canonical_parent)
        || started.parent_objects.contains(&object)
    {
        return Err(DurableOwnershipError::AlreadyStarted);
    }
    let retained_parent = parent_directory
        .try_clone()
        .map_err(|_| DurableOwnershipError::Ambiguous)?;
    started
        .canonical_parents
        .insert(store.canonical_parent.clone());
    started.parent_objects.insert(object);
    started.retained_parents.push(retained_parent);
    Ok(())
}

struct ActorThreadContext<'a> {
    receiver: &'a Receiver<Command>,
    control_receiver: &'a Receiver<StartupControl>,
    preflight_reply: ReplySender<Box<[StartupCustodyTarget]>>,
    final_reply: ReplySender<()>,
    lifecycle: &'a Arc<LifecycleState>,
    admission: &'a Arc<Admission>,
    deadline: HardDeadline,
}

#[allow(clippy::too_many_lines)] // Keep the affine lock, preflight and ready transition linear.
fn actor_thread<PreStartupHook, StartupHook, ExecutorFactory, Executor>(
    config: JournalConfig,
    pre_startup_hook: PreStartupHook,
    startup_hook: StartupHook,
    executor_factory: ExecutorFactory,
    context: ActorThreadContext<'_>,
) where
    PreStartupHook: FnOnce(),
    StartupHook: FnOnce(),
    ExecutorFactory: FnOnce() -> Executor,
    Executor: CleanupExecutor + ManagerAbsenceExecutor,
{
    let ActorThreadContext {
        receiver,
        control_receiver,
        mut preflight_reply,
        mut final_reply,
        lifecycle,
        admission,
        deadline,
    } = context;
    preflight_reply.arm();
    pre_startup_hook();
    if deadline.ensure_remaining().is_err() {
        lifecycle.transition(Lifecycle::Unavailable);
        preflight_reply.complete_unstarted_deadline();
        return;
    }
    let parent_directory = match open_verified_parent(&config) {
        Ok(parent_directory) => parent_directory,
        Err(error) => {
            let failure = classify_startup_error(&error);
            let (error, terminal) = terminal_start_failure(failure);
            complete_startup_failure(preflight_reply, error, terminal, lifecycle);
            return;
        }
    };
    let store = match derive_store_identity(&config, &parent_directory) {
        Ok(store) => store,
        Err(error) => {
            complete_startup_failure(preflight_reply, error, Lifecycle::Unavailable, lifecycle);
            return;
        }
    };
    if let Err(error) = acquire_start_latch(&store, &parent_directory) {
        let terminal = if error == DurableOwnershipError::Ambiguous {
            Lifecycle::Ambiguous
        } else {
            Lifecycle::Unavailable
        };
        complete_startup_failure(preflight_reply, error, terminal, lifecycle);
        return;
    }
    startup_hook();
    let journal = match OwnershipJournal::open_with_verified_parent(config, parent_directory) {
        Ok(journal) => journal,
        Err(error) => {
            let failure = classify_startup_error(&error);
            let (error, terminal) = terminal_start_failure(failure);
            complete_startup_failure(preflight_reply, error, terminal, lifecycle);
            return;
        }
    };
    let executor = executor_factory();
    let mut core = match ActorCore::new(journal, executor) {
        Ok(core) => core,
        Err(failure) => {
            let (error, terminal) = terminal_start_failure(failure);
            complete_startup_failure(preflight_reply, error, terminal, lifecycle);
            return;
        }
    };
    if core.confirm_complete_boundary().is_err() {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        preflight_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    let snapshot = match core.journal.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let (error, terminal) = terminal_start_failure(core.classify_journal_error(error));
            complete_startup_failure(preflight_reply, error, terminal, lifecycle);
            return;
        }
    };
    let targets = match project_startup_custody_targets(snapshot) {
        Ok(targets) => targets,
        Err(error) => {
            complete_startup_failure(preflight_reply, error, Lifecycle::Unavailable, lifecycle);
            return;
        }
    };
    preflight_reply.complete(Ok(targets));
    if lifecycle.load() != Lifecycle::Starting {
        return;
    }

    loop {
        match control_receiver.recv() {
            Ok(StartupControl::Revalidate { mut reply }) => {
                reply.arm();
                if deadline.ensure_remaining().is_err() {
                    reply.complete_unstarted_deadline();
                    continue;
                }
                if core.confirm_complete_boundary().is_err() {
                    admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
                    reply.complete(Err(DurableOwnershipError::Ambiguous));
                    retain_startup_lock_until_owner_drop(control_receiver);
                    return;
                }
                reply.complete(Ok(()));
                if lifecycle.load() != Lifecycle::Starting {
                    retain_startup_lock_until_owner_drop(control_receiver);
                    return;
                }
            }
            Ok(StartupControl::ConfirmRestartCleanup {
                evidence,
                mut reply,
            }) => {
                reply.arm();
                if deadline.ensure_remaining().is_err() {
                    reply.complete_unstarted_deadline();
                    continue;
                }
                match core.confirm_single_restart_cleanup(*evidence, deadline) {
                    Ok(targets) => reply.complete(Ok(targets)),
                    Err(failure) => {
                        let (error, terminal) = terminal_start_failure(failure);
                        admission.fence_terminal(lifecycle, terminal);
                        reply.complete(Err(error));
                        retain_startup_lock_until_owner_drop(control_receiver);
                        return;
                    }
                }
                if lifecycle.load() != Lifecycle::Starting {
                    retain_startup_lock_until_owner_drop(control_receiver);
                    return;
                }
            }
            Ok(StartupControl::Continue { manager_absence }) => {
                core.startup_manager_absence = manager_absence;
                break;
            }
            Err(_) => {
                admission.fence_terminal(lifecycle, Lifecycle::Unavailable);
                return;
            }
        }
    }

    final_reply.arm();
    if deadline.ensure_remaining().is_err() {
        lifecycle.transition(Lifecycle::Unavailable);
        final_reply.complete_unstarted_deadline();
        return;
    }
    if core.confirm_complete_boundary().is_err() {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        final_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    if let Err(failure) = core.startup_sweep(deadline) {
        let (error, terminal) = terminal_start_failure(failure);
        complete_startup_failure(final_reply, error, terminal, lifecycle);
        return;
    }
    if core.confirm_complete_boundary().is_err() {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        final_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    if lifecycle.load() != Lifecycle::Starting {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        final_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    lifecycle.transition(Lifecycle::Running);
    final_reply.complete(Ok(()));

    run_actor_commands(&mut core, receiver, lifecycle, admission);
}

fn retain_startup_lock_until_owner_drop(control_receiver: &Receiver<StartupControl>) {
    // Once post-observation revalidation fails, the affine startup owner still denotes this exact
    // open journal and lock. Keep both alive until that owner is consumed or dropped. Leaking the
    // owner intentionally keeps the store fenced rather than creating a lock gap after ambiguity.
    while control_receiver.recv().is_ok() {}
}

fn run_actor_commands<Executor: CleanupExecutor + ManagerAbsenceExecutor>(
    core: &mut ActorCore<Executor>,
    receiver: &Receiver<Command>,
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) {
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Operation {
                deadline,
                operation,
                _permit,
            } => {
                debug_assert_eq!(deadline, operation.deadline());
                if deadline.ensure_remaining().is_err() {
                    operation.complete_unstarted_deadline();
                    if lifecycle.load() != Lifecycle::Running {
                        return;
                    }
                    continue;
                }
                if process_operation(core, operation, lifecycle, admission) {
                    return;
                }
            }
            Command::Shutdown {
                deadline,
                mut reply,
            } => {
                reply.arm();
                if deadline.ensure_remaining().is_err() {
                    lifecycle.transition(Lifecycle::Stopped);
                    reply.complete_unstarted_deadline();
                    return;
                }
                match core.confirm_quiescent_boundary() {
                    Ok(()) => {
                        lifecycle.transition(Lifecycle::Stopped);
                        reply.complete(Ok(()));
                    }
                    Err(DurableOwnershipError::RecoveryNotConfirmed) => {
                        lifecycle.transition(Lifecycle::Stopped);
                        reply.complete(Err(DurableOwnershipError::RecoveryNotConfirmed));
                    }
                    Err(error) => {
                        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
                        reply.complete(Err(error));
                    }
                }
                return;
            }
        }
    }
    admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
}

fn complete_startup_failure<T>(
    reply: ReplySender<T>,
    error: DurableOwnershipError,
    terminal: Lifecycle,
    lifecycle: &LifecycleState,
) {
    lifecycle.transition(terminal);
    reply.complete(Err(error));
}

fn terminal_start_failure(failure: FailureDisposition) -> (DurableOwnershipError, Lifecycle) {
    match failure {
        FailureDisposition::Continue(error) => (error, Lifecycle::Unavailable),
        FailureDisposition::Stop(error, lifecycle) => (error, lifecycle),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "all affine actor operations remain one exhaustive owner-preserving dispatch"
)]
fn process_operation<Executor: CleanupExecutor + ManagerAbsenceExecutor>(
    core: &mut ActorCore<Executor>,
    operation: Operation,
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) -> bool {
    match operation {
        Operation::Register {
            deadline: _,
            intent,
            mut reply,
        } => {
            reply.arm();
            finish_operation(reply, core.register(intent), lifecycle, admission)
        }
        Operation::MarkCustody {
            deadline,
            key,
            anchor,
            binding,
            mut reply,
        } => {
            reply.arm();
            finish_operation(
                reply,
                core.mark_custody(key, anchor, binding, deadline),
                lifecycle,
                admission,
            )
        }
        Operation::ArmCustody {
            deadline,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(reply, core.arm_custody(key, deadline), lifecycle, admission)
        }
        Operation::RetireNeverDispatched {
            deadline: _,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(reply, core.retire(key), lifecycle, admission)
        }
        Operation::ConfirmCleanup {
            deadline,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(
                reply,
                core.confirm_cleanup(key, deadline),
                lifecycle,
                admission,
            )
        }
        Operation::ConfirmManagerAbsent {
            deadline,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(
                reply,
                core.confirm_manager_absent(key, deadline),
                lifecycle,
                admission,
            )
        }
        Operation::SameRuntimeCleanup {
            deadline,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(
                reply,
                core.confirm_same_runtime_cleanup(key, deadline),
                lifecycle,
                admission,
            )
        }
        Operation::SameRuntimeManagerAbsent {
            deadline,
            key,
            mut reply,
        } => {
            reply.arm();
            finish_operation(
                reply,
                core.confirm_same_runtime_manager_absent(key, deadline),
                lifecycle,
                admission,
            )
        }
        #[cfg(test)]
        Operation::PanicAfterRegister {
            deadline: _,
            intent,
            mut reply,
        } => {
            reply.arm();
            match core.register(intent) {
                OperationOutcome::Complete(Ok(_)) => {
                    panic!("injected panic after durable ownership registration")
                }
                outcome => finish_operation(reply, outcome, lifecycle, admission),
            }
        }
        #[cfg(test)]
        Operation::TestBarrier {
            deadline: _,
            hook,
            mut reply,
        } => {
            reply.arm();
            hook();
            finish_operation(
                reply,
                OperationOutcome::Complete(Ok(())),
                lifecycle,
                admission,
            )
        }
    }
}

fn finish_operation<T>(
    reply: ReplySender<T>,
    outcome: OperationOutcome<T>,
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) -> bool {
    match outcome {
        OperationOutcome::Complete(result) => {
            reply.complete(result);
            matches!(
                lifecycle.load(),
                Lifecycle::Ambiguous | Lifecycle::Unavailable | Lifecycle::Stopped
            )
        }
        OperationOutcome::Stop(error, terminal) => {
            admission.fence_terminal(lifecycle, terminal);
            reply.complete(Err(error));
            true
        }
    }
}

#[cfg(test)]
mod durable_custody_name_tests {
    use super::*;
    use crate::systemd_fdstore::CustodyFdName;

    fn key(
        journal_epoch_id: [u8; 32],
        context_id: [u8; 16],
        ownership_id: [u8; 32],
        generation: u64,
    ) -> DurableOwnershipKey {
        DurableOwnershipKey {
            coordinates: OwnershipCoordinates {
                journal_epoch_id: JournalEpochId::new(journal_epoch_id).expect("journal epoch"),
                context_id: Id16::new(context_id).expect("context identity"),
                ownership_id: OwnershipId::new(ownership_id).expect("ownership identity"),
                generation: NonZeroU64::new(generation).expect("non-zero generation"),
            },
        }
    }

    fn vector_a_key() -> DurableOwnershipKey {
        key(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ],
            [
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f,
            ],
            0x0102_0304_0506_0708,
        )
    }

    fn custody(key: DurableOwnershipKey) -> DurableMayOwnCustody {
        DurableMayOwnCustody { key }
    }

    #[test]
    fn durable_custody_digest_and_name_vectors_are_frozen() {
        let first = custody(vector_a_key()).custody_name_digest();
        assert_eq!(
            first.0,
            [
                0xfb, 0x92, 0xf5, 0x4d, 0xbd, 0x88, 0x48, 0xdc, 0xc4, 0x8f, 0x85, 0x85, 0x3b, 0x38,
                0x6f, 0xf7, 0x54, 0xb9, 0xdb, 0x23, 0xfc, 0xd1, 0x17, 0x8a, 0xb7, 0xa2, 0x60, 0x9a,
                0xf9, 0x38, 0x63, 0x24,
            ]
        );
        assert_eq!(
            first.encode_lower_hex(),
            *b"fb92f54dbd8848dcc48f85853b386ff754b9db23fcd1178ab7a2609af9386324"
        );
        let first_name = CustodyFdName::from_durable_digest(first);
        assert_eq!(
            first_name,
            CustodyFdName::parse(
                "volparossa-custody-v1-fb92f54dbd8848dcc48f85853b386ff754b9db23fcd1178ab7a2609af9386324"
            )
            .expect("first frozen custody name")
        );

        let second =
            custody(key([0xff; 32], [0xaa; 16], [0x55; 32], u64::MAX)).custody_name_digest();
        assert_eq!(
            second.0,
            [
                0x54, 0x53, 0x8c, 0xe4, 0x20, 0x79, 0x5a, 0x9d, 0xc7, 0x2b, 0xb2, 0xc9, 0x82, 0x29,
                0x91, 0xb3, 0x17, 0xf4, 0x48, 0x42, 0xd0, 0xc6, 0x35, 0x96, 0xac, 0x7e, 0x83, 0x5a,
                0xaf, 0x79, 0xbe, 0x4c,
            ]
        );
        assert_eq!(
            CustodyFdName::from_durable_digest(second),
            CustodyFdName::parse(
                "volparossa-custody-v1-54538ce420795a9dc72bb2c9822991b317f44842d0c63596ac7e835aaf79be4c"
            )
            .expect("second frozen custody name")
        );
        assert_eq!(format!("{first:?}"), "DurableCustodyNameDigest(<redacted>)");
        assert!(!format!("{first:?}").contains("fb92f54d"));
    }

    #[test]
    fn every_durable_coordinate_changes_the_custody_digest() {
        let base = vector_a_key();
        let coordinates = base.coordinates;
        let expected = custody(base).custody_name_digest();
        for changed in [
            OwnershipCoordinates {
                journal_epoch_id: JournalEpochId::new([0x11; 32]).expect("different epoch"),
                ..coordinates
            },
            OwnershipCoordinates {
                context_id: Id16::new([0x22; 16]).expect("different context"),
                ..coordinates
            },
            OwnershipCoordinates {
                ownership_id: OwnershipId::new([0x33; 32]).expect("different ownership"),
                ..coordinates
            },
            OwnershipCoordinates {
                generation: NonZeroU64::new(coordinates.generation.get() + 1)
                    .expect("different generation"),
                ..coordinates
            },
        ] {
            assert_ne!(
                custody(DurableOwnershipKey {
                    coordinates: changed,
                })
                .custody_name_digest(),
                expected
            );
        }
    }
}

#[cfg(test)]
mod tests;
