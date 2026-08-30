//! Fail-closed migration interlock and durable helper-v3 ownership journal.
//!
//! Helper v3 never parses or executes cleanup from the former v1 journal. If that journal exists,
//! production startup stops and an operator must inspect the host explicitly. Production now opens
//! the v3 store through one canonical locked actor before publishing its cleanup token or socket.
//! Startup projects custody-bound `MayOwnCustody`, `MayOwnPrepare` and `CleanupConfirmed` records
//! without mutation. The installed general restart cleanup executor deliberately refuses every
//! worker-plus-kernel cleanup proof. One startup-only affine control can confirm only the exact
//! singleton reaper target. A complete set consisting only of already durable
//! `CleanupConfirmed` records may receive one-shot exact-target manager-absence evidence from the
//! external startup join; every broader `MayOwn` set still refuses. A separate affine production handle
//! admits live Prepare and can settle only its same-runtime owner after both exact proofs.

#![allow(dead_code)] // The production actor is live; restart-recovery APIs remain private.

mod actor;

// This affine surface and its opaque, non-authoritative custody digest remain crate-private.
#[allow(unused_imports)]
pub(crate) use actor::{
    DurableArmOutcome, DurableCleanupConfirmed, DurableCleanupOutcome, DurableCustodyArmHandle,
    DurableCustodyNameDigest, DurableCustodyOutcome, DurableIntentRegistration,
    DurableManagerAbsentOutcome, DurableMayOwnCustody, DurableMayOwnPrepare,
    DurableNeverDispatchedOutcome, DurableOwnershipActor, DurableOwnershipError,
    DurableOwnershipKey, DurableOwnershipPrepareHandle, DurableOwnershipSelector,
    DurablePrepareAnchor, DurablePrepareAnchorParts, DurablePrepareSettlement,
    DurableRegistrationOutcome, DurableUndispatchedCleanupOutcome, RestartNetworkPlan,
    StartupCustodyPhase, StartupCustodyTarget, StartupRestartPlan,
};

use crate::{
    deadline::HardDeadline,
    internal_protocol::{InternalEndpointRole, InternalIpPrefix, LeasePlan as InternalLeasePlan},
    lease_spec::{DURABLE_WIREGUARD_ALIAS_PREFIX, WireguardLeaseSpec},
    systemd_custody::{CleanupConfirmedManagerAbsenceEvidence, RestartMayOwnCleanupEvidence},
};

/// Constructs one journal anchor without exposing actor-internal failure types outside this module.
pub(crate) fn durable_prepare_anchor_from_parts(
    parts: DurablePrepareAnchorParts,
) -> Option<DurablePrepareAnchor> {
    DurablePrepareAnchor::try_from_parts(parts).ok()
}

use rand_core::{OsRng, RngCore};
use rustix::{
    fs::{
        AtFlags, FlockOperation, Gid, Mode, OFlags, Uid, fchmod, fchown, flock, openat, renameat,
        statat, unlinkat,
    },
    io::Errno,
    process::getegid,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

/// Starts the actor against a caller-owned temporary directory for cross-module tests.
///
/// The fixture never opens production paths and deliberately accepts one absolute outer deadline.
/// Its recovery executor is a typed exact echo suitable only for deterministic unit tests.
#[cfg(test)]
pub(crate) fn spawn_test_durable_ownership_actor_until(
    parent: &Path,
    deadline: HardDeadline,
) -> Result<DurableOwnershipActor, DurableOwnershipError> {
    let metadata = fs::metadata(parent).map_err(|_| DurableOwnershipError::Unavailable)?;
    let config = JournalConfig::for_test(
        parent,
        metadata.mode() & 0o7777,
        metadata.uid(),
        metadata.gid(),
    );
    DurableOwnershipActor::spawn_with_executor_factory_until(
        config,
        || ExactTestRecoveryExecutor,
        deadline,
    )
}

#[cfg(test)]
pub(crate) fn journal_bytes_have_exact_custody_phase_for_test(
    bytes: &[u8],
    context_id: [u8; 16],
) -> bool {
    let Ok(context_id) = Id16::new(context_id) else {
        return false;
    };
    JournalSnapshot::decode(bytes).is_ok_and(|snapshot| {
        snapshot.records.values().any(|record| {
            record.context_id == context_id
                && record.phase == OwnershipPhase::MayOwnCustody
                && matches!(
                    record.recovery_evidence,
                    Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
                )
        })
    })
}

/// Read-only KVM evidence seam for the three fixed functional production cycles.
///
/// This decodes only the fixed production journal, requires a stable canonical snapshot with one
/// settled Client, Relay and Exit tombstone, and grants no cleanup or restart authority.
pub(crate) fn production_functional_journal_is_exactly_settled() -> bool {
    production_journal_matches_stably(functional_snapshot_is_exactly_settled)
}

/// Read-only KVM evidence seam for the forced-crash boundary immediately after the fourth
/// functional Client record became durably `CleanupConfirmed`.
///
/// The three earlier functional records must remain their exact settled tombstones. This grants
/// no journal mutation, cleanup, descriptor-store removal or restart authority.
pub(crate) fn production_functional_journal_is_exactly_restart_cleanup_confirmed() -> bool {
    production_journal_matches_stably(functional_snapshot_is_exactly_restart_cleanup_confirmed)
}

/// Read-only KVM evidence seam for the forced-crash successor after exact-present recovery.
///
/// The snapshot must contain the original three tombstones plus exactly one second Client
/// tombstone. This grants no journal mutation or restart authority.
pub(crate) fn production_functional_journal_is_exactly_restart_settled() -> bool {
    production_journal_matches_stably(functional_snapshot_is_exactly_restart_settled)
}

fn production_journal_matches_stably(predicate: fn(&JournalSnapshot) -> bool) -> bool {
    let config = JournalConfig::production();
    let Ok(parent_directory) = open_verified_parent(&config) else {
        return false;
    };
    if config.validate().is_err() || verify_next_absent(&config, &parent_directory).is_err() {
        return false;
    }
    let Ok(Some(first)) = load_snapshot(&config, &parent_directory) else {
        return false;
    };
    if !predicate(&first) {
        return false;
    }
    let Ok(first_bytes) = first.encode() else {
        return false;
    };
    if verify_next_absent(&config, &parent_directory).is_err() {
        return false;
    }
    let Ok(Some(second)) = load_snapshot(&config, &parent_directory) else {
        return false;
    };
    predicate(&second)
        && second.encode().is_ok_and(|bytes| bytes == first_bytes)
        && verify_next_absent(&config, &parent_directory).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionalJournalRecordKind {
    Client,
    Relay,
    Exit,
}

fn functional_journal_record_kind(record: &OwnershipRecord) -> Option<FunctionalJournalRecordKind> {
    match (record.plan.context_role, record.plan.paths.as_slice()) {
        (
            ContextRole::Client,
            [
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::Client,
                },
            ],
        ) => Some(FunctionalJournalRecordKind::Client),
        (
            ContextRole::Relay,
            [
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit,
                },
            ],
        ) => Some(FunctionalJournalRecordKind::Relay),
        (
            ContextRole::Exit,
            [
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::Exit,
                },
            ],
        ) => Some(FunctionalJournalRecordKind::Exit),
        _ => None,
    }
}

fn is_exact_recovered_tombstone(record: &OwnershipRecord) -> bool {
    record.phase == OwnershipPhase::Absent
        && record.absent_origin == Some(AbsentOrigin::RecoveredMayOwn)
        && record.recovery_evidence.is_none()
        && record.reconcile.is_none()
}

fn functional_snapshot_is_exactly_settled(snapshot: &JournalSnapshot) -> bool {
    if snapshot.records.len() != 3 {
        return false;
    }
    let mut client = 0_u8;
    let mut relay = 0_u8;
    let mut exit = 0_u8;
    for record in snapshot.records.values() {
        if !is_exact_recovered_tombstone(record) {
            return false;
        }
        match functional_journal_record_kind(record) {
            Some(FunctionalJournalRecordKind::Client) => client = client.saturating_add(1),
            Some(FunctionalJournalRecordKind::Relay) => relay = relay.saturating_add(1),
            Some(FunctionalJournalRecordKind::Exit) => exit = exit.saturating_add(1),
            None => return false,
        }
    }
    (client, relay, exit) == (1, 1, 1)
}

fn functional_snapshot_is_exactly_restart_cleanup_confirmed(snapshot: &JournalSnapshot) -> bool {
    if snapshot.records.len() != 4 {
        return false;
    }
    let mut settled_client = 0_u8;
    let mut settled_relay = 0_u8;
    let mut settled_exit = 0_u8;
    let mut cleanup_client = 0_u8;
    for record in snapshot.records.values() {
        match (record.phase, functional_journal_record_kind(record)) {
            (OwnershipPhase::Absent, Some(kind)) if is_exact_recovered_tombstone(record) => {
                match kind {
                    FunctionalJournalRecordKind::Client => {
                        settled_client = settled_client.saturating_add(1);
                    }
                    FunctionalJournalRecordKind::Relay => {
                        settled_relay = settled_relay.saturating_add(1);
                    }
                    FunctionalJournalRecordKind::Exit => {
                        settled_exit = settled_exit.saturating_add(1);
                    }
                }
            }
            (OwnershipPhase::CleanupConfirmed, Some(FunctionalJournalRecordKind::Client))
                if record.absent_origin.is_none()
                    && matches!(
                        record.recovery_evidence,
                        Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
                    )
                    && record.reconcile.is_none() =>
            {
                cleanup_client = cleanup_client.saturating_add(1);
            }
            _ => return false,
        }
    }
    (settled_client, settled_relay, settled_exit, cleanup_client) == (1, 1, 1, 1)
}

fn functional_snapshot_is_exactly_restart_settled(snapshot: &JournalSnapshot) -> bool {
    if snapshot.records.len() != 4 {
        return false;
    }
    let mut client = 0_u8;
    let mut relay = 0_u8;
    let mut exit = 0_u8;
    for record in snapshot.records.values() {
        if !is_exact_recovered_tombstone(record) {
            return false;
        }
        match functional_journal_record_kind(record) {
            Some(FunctionalJournalRecordKind::Client) => client = client.saturating_add(1),
            Some(FunctionalJournalRecordKind::Relay) => relay = relay.saturating_add(1),
            Some(FunctionalJournalRecordKind::Exit) => exit = exit.saturating_add(1),
            None => return false,
        }
    }
    (client, relay, exit) == (2, 1, 1)
}

#[cfg(test)]
struct ExactTestRecoveryExecutor;

#[cfg(test)]
impl CleanupExecutor for ExactTestRecoveryExecutor {
    type Error = std::convert::Infallible;

    fn confirm_cleanup(
        &mut self,
        target: &CleanupTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedCleanupProof, Self::Error> {
        Ok(target.confirmed_cleanup())
    }
}

#[cfg(test)]
impl ManagerAbsenceExecutor for ExactTestRecoveryExecutor {
    type Error = std::convert::Infallible;

    fn confirm_manager_absent(
        &mut self,
        target: &ManagerAbsenceTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
        Ok(target.confirmed_manager_absent())
    }
}

/// Production ownership lifecycle with a separately cloneable typed Prepare authority.
///
/// The wrapper remains the sole owner of actor startup, shutdown, recovery and thread settlement.
/// Its handle can admit and cleanly settle only affine same-runtime Prepare ownership.
pub(crate) struct ProductionOwnershipRuntime {
    actor: DurableOwnershipActor,
}

/// Lock-holding, mutation-free production startup preflight.
///
/// The underlying actor thread retains the exact verified parent, runtime lock and decoded
/// snapshot from which `targets` was projected. Dropping this guard aborts startup without running
/// the Intent sweep. Production may continue only after the external descriptor-store observer has
/// classified this exact bounded target set and the guard has revalidated the retained snapshot.
#[must_use = "production ownership startup must be revalidated and continued or explicitly dropped"]
pub(crate) struct ProductionOwnershipStartup {
    startup: actor::DurableOwnershipStartup,
}

impl ProductionOwnershipStartup {
    /// Canonical, digest-ordered custody targets from the exact locked startup snapshot.
    pub(crate) fn targets(&self) -> &[StartupCustodyTarget] {
        self.startup.targets()
    }

    /// Revalidate the retained parent, lock, `.next` absence and exact durable snapshot.
    ///
    /// This performs no repair or journal mutation. Success returns the same canonical slice so a
    /// caller cannot accidentally classify targets from a different preflight.
    pub(crate) fn revalidate_targets(
        &mut self,
    ) -> Result<&[StartupCustodyTarget], DurableOwnershipError> {
        self.startup.revalidate_targets()
    }

    /// Continue only a startup whose durable snapshot projected no custody target.
    pub(crate) fn continue_empty(
        self,
    ) -> Result<ProductionOwnershipRuntime, DurableOwnershipError> {
        self.startup
            .continue_empty()
            .map(|actor| ProductionOwnershipRuntime { actor })
    }

    /// Consume one affine exact-reaper proof while retaining the startup actor and journal lock.
    ///
    /// This crosses only the actor's single-target `MayOwnCustody -> CleanupConfirmed` CAS. It
    /// neither removes systemd custody nor continues startup.
    pub(crate) fn confirm_single_restart_cleanup(
        &mut self,
        evidence: RestartMayOwnCleanupEvidence,
    ) -> Result<&[StartupCustodyTarget], DurableOwnershipError> {
        self.startup.confirm_single_restart_cleanup(evidence)
    }

    /// Continue the retained startup only with fresh exact manager-absence evidence for its full
    /// canonical non-empty `CleanupConfirmed` target set.
    pub(crate) fn continue_cleanup_confirmed_absent(
        self,
        evidence: CleanupConfirmedManagerAbsenceEvidence,
    ) -> Result<ProductionOwnershipRuntime, DurableOwnershipError> {
        self.startup
            .continue_cleanup_confirmed_absent(evidence)
            .map(|actor| ProductionOwnershipRuntime { actor })
    }
}

impl ProductionOwnershipRuntime {
    /// Open, lock, validate and sweep the fixed journal before socket publication may proceed.
    pub(crate) fn start_until(deadline: HardDeadline) -> Result<Self, DurableOwnershipError> {
        Self::begin_until(deadline)?.continue_empty()
    }

    /// Open, lock and project custody-bound startup state without mutating any Intent.
    pub(crate) fn begin_until(
        deadline: HardDeadline,
    ) -> Result<ProductionOwnershipStartup, DurableOwnershipError> {
        Self::begin_with_config_until(JournalConfig::production(), deadline)
    }

    fn start_with_config_until(
        config: JournalConfig,
        deadline: HardDeadline,
    ) -> Result<Self, DurableOwnershipError> {
        Self::begin_with_config_until(config, deadline)?.continue_empty()
    }

    fn begin_with_config_until(
        config: JournalConfig,
        deadline: HardDeadline,
    ) -> Result<ProductionOwnershipStartup, DurableOwnershipError> {
        let startup = DurableOwnershipActor::begin_with_executor_factory_until(
            config,
            || RefuseMayOwnRecovery,
            deadline,
        )?;
        Ok(ProductionOwnershipStartup { startup })
    }

    /// Issue only the cloneable authority needed to arm an already durable custody token.
    pub(crate) fn custody_arm_handle(
        &self,
    ) -> Result<DurableCustodyArmHandle, DurableOwnershipError> {
        self.actor.custody_arm_handle()
    }

    /// Issue the typed production admission/settlement authority while retaining sole actor
    /// startup, recovery and shutdown ownership in this runtime.
    pub(crate) fn prepare_handle(
        &self,
    ) -> Result<DurableOwnershipPrepareHandle, DurableOwnershipError> {
        self.actor.prepare_handle()
    }

    /// Fence admission, prove that every record is Absent and join the actor thread.
    pub(crate) fn shutdown_until(
        mut self,
        deadline: HardDeadline,
    ) -> Result<(), DurableOwnershipError> {
        self.actor.shutdown_until(deadline)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RefuseMayOwnRecovery;

#[derive(Debug, Eq, PartialEq)]
struct MayOwnRecoveryUnavailable;

/// Typed echo used only after the live production backend has independently completed the exact
/// same-runtime worker/kernel or manager-custody operation. This is deliberately distinct from
/// the installed restart executor, which continues to refuse every recovery proof.
struct SameRuntimeCleanSettlement;

impl CleanupExecutor for SameRuntimeCleanSettlement {
    type Error = std::convert::Infallible;

    fn confirm_cleanup(
        &mut self,
        target: &CleanupTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedCleanupProof, Self::Error> {
        Ok(target.confirmed_cleanup())
    }
}

impl ManagerAbsenceExecutor for SameRuntimeCleanSettlement {
    type Error = std::convert::Infallible;

    fn confirm_manager_absent(
        &mut self,
        target: &ManagerAbsenceTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
        Ok(target.confirmed_manager_absent())
    }
}

impl CleanupExecutor for RefuseMayOwnRecovery {
    type Error = MayOwnRecoveryUnavailable;

    fn confirm_cleanup(
        &mut self,
        _target: &CleanupTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedCleanupProof, Self::Error> {
        Err(MayOwnRecoveryUnavailable)
    }
}

impl ManagerAbsenceExecutor for RefuseMayOwnRecovery {
    type Error = MayOwnRecoveryUnavailable;

    fn confirm_manager_absent(
        &mut self,
        _target: &ManagerAbsenceTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
        Err(MayOwnRecoveryUnavailable)
    }
}

const LEGACY_JOURNAL_PATH: &str = "/run/volparossa/helper.ownership-v1";
const OWNERSHIP_JOURNAL_PATH: &str = "/run/volparossa/helper.ownership-v3";
const OWNERSHIP_LOCK_PATH: &str = "/run/volparossa/helper.ownership-v3.lock";
const OWNERSHIP_NEXT_PATH: &str = "/run/volparossa/helper.ownership-v3.next";
const PRODUCTION_PARENT_MODE: u32 = 0o750;
const JOURNAL_FILE_MODE: u32 = 0o600;
const MAX_RECORDS: usize = 1_024;
const MAX_JOURNAL_BYTES: usize = 256 * 1_024;
const MAX_PATHS: usize = 8;
const MAX_PATH_ID: u8 = 8;
const MAX_LEASE_IDENTITIES: usize = 16;
const JOURNAL_MAGIC: [u8; 8] = *b"VOLJRN3\0";
const JOURNAL_VERSION: u16 = 3;
const DIGEST_BYTES: usize = 32;
const DURABLE_WIREGUARD_MARKER_DOMAIN: &str =
    "VOLPAROSSA helper durable WireGuard resource marker v1";
const DERIVED_WIREGUARD_INTERFACE_BYTES: usize = 12;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Id16([u8; 16]);

impl Id16 {
    fn new(value: [u8; 16]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Id16(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RuntimeId([u8; 32]);

impl RuntimeId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct JournalEpochId([u8; 32]);

impl JournalEpochId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for JournalEpochId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalEpochId(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct OwnershipId([u8; 32]);

impl OwnershipId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for OwnershipId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnershipId(<redacted>)")
    }
}

impl fmt::Debug for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeId(<redacted>)")
    }
}

/// Secret-free kernel metadata derived from one exact durable ownership record.
///
/// The alias is public evidence used to reject stale same-name links. It is neither proof of the
/// journal's current phase nor authority to create, adopt, mutate or delete a kernel resource.
/// Construction accepts either one exact journal record or the fixed authenticated worker
/// binding; neither path accepts raw ownership coordinates or a free-form alias. The value is
/// deliberately non-`Clone` and its debug form reveals no marker.
#[derive(Eq, PartialEq)]
pub(crate) struct DurableWireguardResource {
    specification: WireguardLeaseSpec,
    ownership_alias: String,
    setup_expires_at_unix: NonZeroU64,
    hard_expires_at_unix: NonZeroU64,
}

impl DurableWireguardResource {
    /// Reconstruct public resource evidence received over the authenticated parent-to-worker
    /// channel.
    ///
    /// This constructor grants no durable ownership or cleanup authority. It accepts only the
    /// topology-derived interface/address and the fixed ownership-marker grammar; the privileged
    /// parent must retain the corresponding affine journal owner outside the worker.
    pub(crate) fn from_authenticated_worker_binding(
        route_context_id: [u8; 16],
        context_role: volparossa_routing::ContextRole,
        path_id: u32,
        role: i32,
        ownership_alias: String,
        setup_expires_at_unix: u64,
        hard_expires_at_unix: u64,
    ) -> Option<Self> {
        let setup_expires_at_unix = NonZeroU64::new(setup_expires_at_unix)?;
        let hard_expires_at_unix =
            NonZeroU64::new(hard_expires_at_unix).filter(|hard| *hard >= setup_expires_at_unix)?;
        let specification =
            WireguardLeaseSpec::derive(route_context_id, context_role, path_id, role).ok()?;
        specification
            .matches_ownership_alias(&ownership_alias)
            .then_some(Self {
                specification,
                ownership_alias,
                setup_expires_at_unix,
                hard_expires_at_unix,
            })
    }

    /// Context-local path and endpoint role committed by the durable record.
    pub(crate) const fn key(&self) -> (u8, i32) {
        self.specification.key()
    }

    /// Exact topology-derived kernel interface name committed by the marker.
    pub(crate) fn interface(&self) -> &str {
        self.specification.interface()
    }

    /// Public fixed-format ownership marker; this is evidence, not authority.
    pub(crate) fn ownership_alias(&self) -> &str {
        &self.ownership_alias
    }

    /// Exact topology-derived local overlay address committed by the marker.
    pub(crate) const fn local_address(&self) -> std::net::Ipv6Addr {
        self.specification.local_address()
    }

    /// Exact peer overlay address derived from the topology committed by the durable record.
    pub(crate) const fn peer_address(&self) -> std::net::Ipv6Addr {
        self.specification.peer_address()
    }

    /// Absolute hard expiry retained from the authenticated durable Prepare record.
    pub(crate) const fn hard_expires_at_unix(&self) -> u64 {
        self.hard_expires_at_unix.get()
    }

    /// Project the exact durable resource into the private worker-v3 lease descriptor.
    ///
    /// This is deliberately private to the ownership module: production callers receive a
    /// complete descriptor only through the affine `DurableMayOwnPrepare` owner and cannot
    /// substitute a path, role, address, expiry or public ownership marker.
    fn internal_lease_plan_v3(&self) -> Result<InternalLeasePlan, JournalError> {
        let (path_id, role) = self.key();
        let role = match volparossa_routing::WireguardRole::try_from(role)
            .map_err(|_| JournalError::InvalidRecord)?
        {
            volparossa_routing::WireguardRole::Client => InternalEndpointRole::Client,
            volparossa_routing::WireguardRole::RelayClient => InternalEndpointRole::RelayClient,
            volparossa_routing::WireguardRole::RelayExit => InternalEndpointRole::RelayExit,
            volparossa_routing::WireguardRole::Exit => InternalEndpointRole::Exit,
            volparossa_routing::WireguardRole::Unspecified => {
                return Err(JournalError::InvalidRecord);
            }
        };
        Ok(InternalLeasePlan {
            path_id: u32::from(path_id),
            role: role as i32,
            local_overlay_address: Some(InternalIpPrefix {
                address: self.local_address().octets().to_vec(),
                prefix_length: 128,
            }),
            setup_expires_at_unix: self.setup_expires_at_unix.get(),
            hard_expires_at_unix: self.hard_expires_at_unix.get(),
            ownership_alias: self.ownership_alias().to_owned(),
        })
    }
}

impl fmt::Debug for DurableWireguardResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableWireguardResource(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ContextRole {
    Client = 1,
    Relay = 2,
    Exit = 3,
}

impl TryFrom<u8> for ContextRole {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Relay),
            3 => Ok(Self::Exit),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
enum WireguardRole {
    Client = 1,
    RelayClient = 2,
    RelayExit = 3,
    Exit = 4,
}

impl WireguardRole {
    fn belongs_to(self, context: ContextRole) -> bool {
        matches!(
            (context, self),
            (ContextRole::Client, Self::Client)
                | (ContextRole::Relay, Self::RelayClient | Self::RelayExit)
                | (ContextRole::Exit, Self::Exit)
        )
    }
}

impl TryFrom<u8> for WireguardRole {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::RelayClient),
            3 => Ok(Self::RelayExit),
            4 => Ok(Self::Exit),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PathPlan {
    path_id: u8,
    role: WireguardRole,
}

#[derive(Clone, Eq, PartialEq)]
struct ClosedPlan {
    context_role: ContextRole,
    paths: Vec<PathPlan>,
}

impl ClosedPlan {
    fn new(context_role: ContextRole, paths: Vec<PathPlan>) -> Result<Self, JournalError> {
        if paths.is_empty() || paths.len() > MAX_LEASE_IDENTITIES {
            return Err(JournalError::InvalidRecord);
        }
        let mut seen = BTreeSet::new();
        let mut roles_by_path = BTreeMap::<u8, BTreeSet<WireguardRole>>::new();
        for path in &paths {
            if !(1..=MAX_PATH_ID).contains(&path.path_id)
                || !path.role.belongs_to(context_role)
                || !seen.insert(*path)
            {
                return Err(JournalError::InvalidRecord);
            }
            roles_by_path
                .entry(path.path_id)
                .or_default()
                .insert(path.role);
        }
        if roles_by_path.len() > MAX_PATHS
            || roles_by_path.values().any(|roles| {
                let expected = match context_role {
                    ContextRole::Client => BTreeSet::from([WireguardRole::Client]),
                    ContextRole::Relay => {
                        BTreeSet::from([WireguardRole::RelayClient, WireguardRole::RelayExit])
                    }
                    ContextRole::Exit => BTreeSet::from([WireguardRole::Exit]),
                };
                *roles != expected
            })
        {
            return Err(JournalError::InvalidRecord);
        }
        let mut paths = paths;
        paths.sort_unstable();
        Ok(Self {
            context_role,
            paths,
        })
    }

    /// Convert the externally validated recovery plan without silently canonicalising it.
    ///
    /// The durable intent must commit the same canonical identity order that appeared on tag 35.
    /// Accepting a permutation here and sorting it would give the journal a different semantic
    /// boundary from the helper protocol.
    fn try_from_wire(value: &volparossa_routing::ClosedPreparePlan) -> Result<Self, JournalError> {
        if !(1..=MAX_LEASE_IDENTITIES).contains(&value.leases.len()) {
            return Err(JournalError::InvalidRecord);
        }
        let context_role = match volparossa_routing::ContextRole::try_from(value.context_role)
            .map_err(|_| JournalError::InvalidRecord)?
        {
            volparossa_routing::ContextRole::Client => ContextRole::Client,
            volparossa_routing::ContextRole::Relay => ContextRole::Relay,
            volparossa_routing::ContextRole::Exit => ContextRole::Exit,
            volparossa_routing::ContextRole::Unspecified => {
                return Err(JournalError::InvalidRecord);
            }
        };
        let mut paths = Vec::with_capacity(value.leases.len());
        for lease in &value.leases {
            let path_id = u8::try_from(lease.path_id).map_err(|_| JournalError::InvalidRecord)?;
            let role = match volparossa_routing::WireguardRole::try_from(lease.role)
                .map_err(|_| JournalError::InvalidRecord)?
            {
                volparossa_routing::WireguardRole::Client => WireguardRole::Client,
                volparossa_routing::WireguardRole::RelayClient => WireguardRole::RelayClient,
                volparossa_routing::WireguardRole::RelayExit => WireguardRole::RelayExit,
                volparossa_routing::WireguardRole::Exit => WireguardRole::Exit,
                volparossa_routing::WireguardRole::Unspecified => {
                    return Err(JournalError::InvalidRecord);
                }
            };
            paths.push(PathPlan { path_id, role });
        }
        if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(JournalError::InvalidRecord);
        }
        Self::new(context_role, paths)
    }
}

impl fmt::Debug for ClosedPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedPlan")
            .field("context_role", &self.context_role)
            .field("path_count", &self.paths.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OwnershipPhase {
    Intent = 1,
    MayOwnPrepare = 2,
    Absent = 3,
    MayOwnCustody = 4,
    CleanupConfirmed = 5,
}

impl TryFrom<u8> for OwnershipPhase {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Intent),
            2 => Ok(Self::MayOwnPrepare),
            3 => Ok(Self::Absent),
            4 => Ok(Self::MayOwnCustody),
            5 => Ok(Self::CleanupConfirmed),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AbsentOrigin {
    NeverDispatched = 1,
    RecoveredMayOwn = 2,
}

impl TryFrom<u8> for AbsentOrigin {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NeverDispatched),
            2 => Ok(Self::RecoveredMayOwn),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReconcileBinding {
    request_id: Id16,
    operation_digest: [u8; DIGEST_BYTES],
}

impl fmt::Debug for ReconcileBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReconcileBinding(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PrepareRecoveryAnchorV1 {
    boot_id: Id16,
    pid: NonZeroU32,
    process_start_ticks: NonZeroU64,
    network_namespace_device: NonZeroU64,
    network_namespace_inode: NonZeroU64,
    executable_device: NonZeroU64,
    executable_inode: NonZeroU64,
    service_cgroup_inode: NonZeroU64,
}

impl fmt::Debug for PrepareRecoveryAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrepareRecoveryAnchorV1(<redacted>)")
    }
}

const CUSTODY_DESCRIPTOR_IDENTITY_BYTES: usize = 32;
const CUSTODY_DESCRIPTOR_BINDING_BYTES: usize = CUSTODY_DESCRIPTOR_IDENTITY_BYTES * 2;

/// One fixed descriptor identity persisted only as restart correlation evidence.
///
/// Kernel role classification remains the responsibility of the descriptor-custody boundary. The
/// journal stores the already classified role-ordered identities and never treats these fields as
/// descriptor or cleanup authority.
#[derive(Clone, Copy, Eq, PartialEq)]
struct CustodyDescriptorIdentityV1 {
    mode: NonZeroU32,
    device_major: u32,
    device_minor: u32,
    inode: NonZeroU64,
    special_device_major: u32,
    special_device_minor: u32,
    status_flags: u32,
}

impl CustodyDescriptorIdentityV1 {
    fn new(
        mode: NonZeroU32,
        device_major: u32,
        device_minor: u32,
        inode: NonZeroU64,
        special_device_major: u32,
        special_device_minor: u32,
        status_flags: u32,
    ) -> Result<Self, JournalError> {
        if status_flags & OFlags::LARGEFILE.bits() != 0 {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self {
            mode,
            device_major,
            device_minor,
            inode,
            special_device_major,
            special_device_minor,
            status_flags,
        })
    }

    fn is_same_kernel_object(self, other: Self) -> bool {
        self.mode == other.mode
            && self.device_major == other.device_major
            && self.device_minor == other.device_minor
            && self.inode == other.inode
            && self.special_device_major == other.special_device_major
            && self.special_device_minor == other.special_device_minor
    }
}

impl fmt::Debug for CustodyDescriptorIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustodyDescriptorIdentityV1(<redacted>)")
    }
}

/// Exact pidfd-then-network-namespace descriptor identity binding.
#[derive(Clone, Copy, Eq, PartialEq)]
struct CustodyDescriptorBindingV1 {
    pidfd: CustodyDescriptorIdentityV1,
    network_namespace: CustodyDescriptorIdentityV1,
}

impl CustodyDescriptorBindingV1 {
    fn new(
        pidfd: CustodyDescriptorIdentityV1,
        network_namespace: CustodyDescriptorIdentityV1,
    ) -> Result<Self, JournalError> {
        if pidfd.is_same_kernel_object(network_namespace) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self {
            pidfd,
            network_namespace,
        })
    }

    fn validate_against_anchor(self, anchor: PrepareRecoveryAnchorV1) -> Result<(), JournalError> {
        let network_namespace_device = rustix::fs::makedev(
            self.network_namespace.device_major,
            self.network_namespace.device_minor,
        );
        if network_namespace_device != anchor.network_namespace_device.get()
            || self.network_namespace.inode != anchor.network_namespace_inode
        {
            return Err(JournalError::InvalidRecord);
        }
        Ok(())
    }
}

impl fmt::Debug for CustodyDescriptorBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustodyDescriptorBindingV1(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PrepareRecoveryEvidenceV1 {
    LegacyAnchor(PrepareRecoveryAnchorV1),
    CustodyBound {
        anchor: PrepareRecoveryAnchorV1,
        binding: CustodyDescriptorBindingV1,
    },
}

impl PrepareRecoveryEvidenceV1 {
    fn custody_bound(
        anchor: PrepareRecoveryAnchorV1,
        binding: CustodyDescriptorBindingV1,
    ) -> Result<Self, JournalError> {
        binding.validate_against_anchor(anchor)?;
        Ok(Self::CustodyBound { anchor, binding })
    }

    fn is_custody_bound(self) -> bool {
        matches!(self, Self::CustodyBound { .. })
    }

    fn validate(self) -> Result<(), JournalError> {
        match self {
            Self::LegacyAnchor(_) => Ok(()),
            Self::CustodyBound { anchor, binding } => binding.validate_against_anchor(anchor),
        }
    }
}

impl fmt::Debug for PrepareRecoveryEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrepareRecoveryEvidenceV1(<redacted>)")
    }
}

/// Fixed-width descriptor-stat input for one already kernel-classified custody role.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurableCustodyDescriptorIdentityParts {
    pub(crate) mode: NonZeroU32,
    pub(crate) device_major: u32,
    pub(crate) device_minor: u32,
    pub(crate) inode: NonZeroU64,
    pub(crate) special_device_major: u32,
    pub(crate) special_device_minor: u32,
    pub(crate) status_flags: u32,
}

impl fmt::Debug for DurableCustodyDescriptorIdentityParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableCustodyDescriptorIdentityParts(<redacted>)")
    }
}

/// Opaque durable form of one descriptor identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurableCustodyDescriptorIdentity(CustodyDescriptorIdentityV1);

impl DurableCustodyDescriptorIdentity {
    pub(crate) fn try_from_parts(parts: DurableCustodyDescriptorIdentityParts) -> Option<Self> {
        CustodyDescriptorIdentityV1::new(
            parts.mode,
            parts.device_major,
            parts.device_minor,
            parts.inode,
            parts.special_device_major,
            parts.special_device_minor,
            parts.status_flags,
        )
        .ok()
        .map(Self)
    }
}

impl fmt::Debug for DurableCustodyDescriptorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableCustodyDescriptorIdentity(<redacted>)")
    }
}

/// Opaque role-ordered pidfd-then-network-namespace journal correlation binding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DurableCustodyDescriptorBinding(CustodyDescriptorBindingV1);

impl DurableCustodyDescriptorBinding {
    pub(crate) fn try_from_role_ordered(
        pidfd: DurableCustodyDescriptorIdentity,
        network_namespace: DurableCustodyDescriptorIdentity,
    ) -> Option<Self> {
        CustodyDescriptorBindingV1::new(pidfd.0, network_namespace.0)
            .ok()
            .map(Self)
    }

    /// Compare the exact role-ordered durable identities, including normalized status flags.
    pub(crate) fn matches_role_ordered(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Report reuse of either underlying kernel object, independent of role or status flags.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        [self.0.pidfd, self.0.network_namespace]
            .iter()
            .any(|identity| {
                [other.0.pidfd, other.0.network_namespace]
                    .iter()
                    .any(|candidate| identity.is_same_kernel_object(*candidate))
            })
    }
}

impl fmt::Debug for DurableCustodyDescriptorBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableCustodyDescriptorBinding(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct OwnershipRecord {
    journal_epoch_id: JournalEpochId,
    origin_runtime_id: RuntimeId,
    ownership_id: OwnershipId,
    context_id: Id16,
    prepare_request_id: Id16,
    prepare_operation_digest: [u8; DIGEST_BYTES],
    generation: NonZeroU64,
    setup_expires_at_unix: NonZeroU64,
    hard_expires_at_unix: NonZeroU64,
    plan: ClosedPlan,
    phase: OwnershipPhase,
    absent_origin: Option<AbsentOrigin>,
    reconcile: Option<ReconcileBinding>,
    recovery_evidence: Option<PrepareRecoveryEvidenceV1>,
}

impl OwnershipRecord {
    fn validate(&self) -> Result<(), JournalError> {
        let phase_evidence_is_valid = matches!(
            (self.phase, self.absent_origin, self.recovery_evidence),
            (OwnershipPhase::Intent, None, None)
                | (
                    OwnershipPhase::MayOwnCustody | OwnershipPhase::CleanupConfirmed,
                    None,
                    Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
                )
                | (OwnershipPhase::MayOwnPrepare, None, Some(_))
                | (
                    OwnershipPhase::Absent,
                    Some(AbsentOrigin::NeverDispatched | AbsentOrigin::RecoveredMayOwn),
                    None
                )
        );
        if self.hard_expires_at_unix < self.setup_expires_at_unix || !phase_evidence_is_valid {
            return Err(JournalError::InvalidRecord);
        }
        if let Some(evidence) = self.recovery_evidence {
            evidence.validate()?;
        }
        let canonical = ClosedPlan::new(self.plan.context_role, self.plan.paths.clone())?;
        if canonical != self.plan {
            return Err(JournalError::InvalidRecord);
        }
        Ok(())
    }

    /// Project the immutable durable identity into exact per-link public kernel markers.
    ///
    /// Validation precedes every construction. Mutable lifecycle and reconciliation evidence is
    /// intentionally excluded so the marker remains stable until exact cleanup is proved.
    fn durable_wireguard_resources(&self) -> Result<Vec<DurableWireguardResource>, JournalError> {
        self.validate()?;
        let path_count =
            u8::try_from(self.plan.paths.len()).map_err(|_| JournalError::InvalidRecord)?;
        let mut resources = Vec::with_capacity(self.plan.paths.len());
        for resource_path in &self.plan.paths {
            let specification = WireguardLeaseSpec::derive(
                self.context_id.0,
                routing_context_role(self.plan.context_role),
                u32::from(resource_path.path_id),
                routing_wireguard_role(resource_path.role) as i32,
            )
            .map_err(|_| JournalError::InvalidRecord)?;
            if specification.interface().len() != DERIVED_WIREGUARD_INTERFACE_BYTES
                || specification.key()
                    != (
                        resource_path.path_id,
                        routing_wireguard_role(resource_path.role) as i32,
                    )
            {
                return Err(JournalError::InvalidRecord);
            }

            let mut marker = blake3::Hasher::new_derive_key(DURABLE_WIREGUARD_MARKER_DOMAIN);
            marker.update(&self.journal_epoch_id.0);
            marker.update(&self.origin_runtime_id.0);
            marker.update(&self.ownership_id.0);
            marker.update(&self.context_id.0);
            marker.update(&self.prepare_request_id.0);
            marker.update(&self.prepare_operation_digest);
            marker.update(&self.generation.get().to_be_bytes());
            marker.update(&self.setup_expires_at_unix.get().to_be_bytes());
            marker.update(&self.hard_expires_at_unix.get().to_be_bytes());
            marker.update(&[self.plan.context_role as u8, path_count]);
            for path in &self.plan.paths {
                marker.update(&[path.path_id, path.role as u8]);
            }
            marker.update(&[resource_path.path_id, resource_path.role as u8]);
            marker.update(specification.interface().as_bytes());
            marker.update(&specification.local_address().octets());
            let digest = marker.finalize();
            let ownership_alias = format!(
                "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
                specification.interface(),
                digest.to_hex()
            );
            resources.push(DurableWireguardResource {
                specification,
                ownership_alias,
                setup_expires_at_unix: self.setup_expires_at_unix,
                hard_expires_at_unix: self.hard_expires_at_unix,
            });
        }
        Ok(resources)
    }

    fn advance(
        &mut self,
        next: OwnershipPhase,
        recovery_evidence: Option<PrepareRecoveryEvidenceV1>,
        absent_origin: Option<AbsentOrigin>,
    ) -> Result<(), JournalError> {
        let transition_is_valid = matches!(
            (self.phase, next, absent_origin, recovery_evidence),
            (
                OwnershipPhase::Intent,
                OwnershipPhase::MayOwnCustody,
                None,
                Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
            ) | (
                OwnershipPhase::MayOwnCustody,
                OwnershipPhase::MayOwnPrepare,
                None,
                Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
            ) | (
                OwnershipPhase::Intent,
                OwnershipPhase::Absent,
                Some(AbsentOrigin::NeverDispatched),
                None
            ) | (
                OwnershipPhase::MayOwnCustody | OwnershipPhase::MayOwnPrepare,
                OwnershipPhase::CleanupConfirmed,
                None,
                Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
            ) | (
                OwnershipPhase::CleanupConfirmed,
                OwnershipPhase::Absent,
                Some(AbsentOrigin::RecoveredMayOwn),
                None
            )
        );
        let custody_evidence_is_preserved = !matches!(
            (self.phase, next),
            (
                OwnershipPhase::MayOwnCustody,
                OwnershipPhase::MayOwnPrepare | OwnershipPhase::CleanupConfirmed
            ) | (
                OwnershipPhase::MayOwnPrepare,
                OwnershipPhase::CleanupConfirmed
            )
        ) || self.recovery_evidence == recovery_evidence;
        if !transition_is_valid || !custody_evidence_is_preserved {
            return Err(JournalError::InvalidTransition);
        }
        let mut candidate = self.clone();
        candidate.phase = next;
        candidate.absent_origin = absent_origin;
        candidate.recovery_evidence = recovery_evidence;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

const fn routing_context_role(role: ContextRole) -> volparossa_routing::ContextRole {
    match role {
        ContextRole::Client => volparossa_routing::ContextRole::Client,
        ContextRole::Relay => volparossa_routing::ContextRole::Relay,
        ContextRole::Exit => volparossa_routing::ContextRole::Exit,
    }
}

const fn routing_wireguard_role(role: WireguardRole) -> volparossa_routing::WireguardRole {
    match role {
        WireguardRole::Client => volparossa_routing::WireguardRole::Client,
        WireguardRole::RelayClient => volparossa_routing::WireguardRole::RelayClient,
        WireguardRole::RelayExit => volparossa_routing::WireguardRole::RelayExit,
        WireguardRole::Exit => volparossa_routing::WireguardRole::Exit,
    }
}

/// Build one deterministic marker fixture without adding a production raw-marker constructor.
#[cfg(test)]
pub(crate) fn durable_wireguard_resource_for_test(
    route_context_id: [u8; 16],
    context_role: volparossa_routing::ContextRole,
    path_id: u8,
    role: volparossa_routing::WireguardRole,
    ownership_seed: u8,
) -> Option<DurableWireguardResource> {
    if route_context_id.iter().all(|byte| *byte == 0)
        || !(1..=MAX_PATH_ID).contains(&path_id)
        || !(1..=240).contains(&ownership_seed)
    {
        return None;
    }
    let context_role = match context_role {
        volparossa_routing::ContextRole::Client => ContextRole::Client,
        volparossa_routing::ContextRole::Relay => ContextRole::Relay,
        volparossa_routing::ContextRole::Exit => ContextRole::Exit,
        volparossa_routing::ContextRole::Unspecified => return None,
    };
    let requested_role = match role {
        volparossa_routing::WireguardRole::Client => WireguardRole::Client,
        volparossa_routing::WireguardRole::RelayClient => WireguardRole::RelayClient,
        volparossa_routing::WireguardRole::RelayExit => WireguardRole::RelayExit,
        volparossa_routing::WireguardRole::Exit => WireguardRole::Exit,
        volparossa_routing::WireguardRole::Unspecified => return None,
    };
    if !requested_role.belongs_to(context_role) {
        return None;
    }
    let paths = match context_role {
        ContextRole::Client => vec![PathPlan {
            path_id,
            role: WireguardRole::Client,
        }],
        ContextRole::Relay => vec![
            PathPlan {
                path_id,
                role: WireguardRole::RelayClient,
            },
            PathPlan {
                path_id,
                role: WireguardRole::RelayExit,
            },
        ],
        ContextRole::Exit => vec![PathPlan {
            path_id,
            role: WireguardRole::Exit,
        }],
    };
    let origin_seed = ownership_seed.checked_add(1)?;
    let owner_seed = ownership_seed.checked_add(2)?;
    let request_seed = ownership_seed.checked_add(3)?;
    let digest_seed = ownership_seed.checked_add(4)?;
    let generation = NonZeroU64::new(u64::from(ownership_seed))?;
    let record = OwnershipRecord {
        journal_epoch_id: JournalEpochId::new([ownership_seed; 32]).ok()?,
        origin_runtime_id: RuntimeId::new([origin_seed; 32]).ok()?,
        ownership_id: OwnershipId::new([owner_seed; 32]).ok()?,
        context_id: Id16::new(route_context_id).ok()?,
        prepare_request_id: Id16::new([request_seed; 16]).ok()?,
        prepare_operation_digest: [digest_seed; DIGEST_BYTES],
        generation,
        setup_expires_at_unix: NonZeroU64::new(1_000 + u64::from(ownership_seed))?,
        hard_expires_at_unix: NonZeroU64::new(2_000 + u64::from(ownership_seed))?,
        plan: ClosedPlan::new(context_role, paths).ok()?,
        phase: OwnershipPhase::Intent,
        absent_origin: None,
        reconcile: None,
        recovery_evidence: None,
    };
    record
        .durable_wireguard_resources()
        .ok()?
        .into_iter()
        .find(|resource| resource.key() == (path_id, role as i32))
}

impl fmt::Debug for OwnershipRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnershipRecord")
            .field("journal_epoch_id", &"<redacted>")
            .field("origin_runtime_id", &"<redacted>")
            .field("ownership_id", &"<redacted>")
            .field("context_id", &"<redacted>")
            .field("prepare_request_id", &"<redacted>")
            .field("prepare_operation_digest", &"<redacted>")
            .field("generation", &"<redacted>")
            .field("setup_expires_at_unix", &"<redacted>")
            .field("hard_expires_at_unix", &"<redacted>")
            .field("plan", &self.plan)
            .field("phase", &self.phase)
            .field("absent_origin", &self.absent_origin)
            .field("reconcile", &self.reconcile)
            .field("recovery_evidence", &self.recovery_evidence)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
enum JournalError {
    #[error("journal I/O failed")]
    Io(#[from] io::Error),
    #[error("journal record is invalid")]
    InvalidRecord,
    #[error("journal transition is invalid")]
    InvalidTransition,
    #[error("journal encoding is corrupt")]
    Corrupt,
    #[error("journal capacity is exhausted")]
    Capacity,
    #[error("journal revision conflict")]
    RevisionConflict,
    #[error("journal persistence is uncertain")]
    PersistUncertain,
    #[error("journal store is poisoned")]
    Poisoned,
    #[error("journal runtime lock is already held")]
    LockHeld,
    #[error("journal filesystem metadata is unsafe")]
    UnsafeMetadata,
    #[error("secure random generation failed")]
    Random,
    #[error("recovery proof does not match the exact ownership record")]
    ProofMismatch,
}

#[derive(Clone, Eq, PartialEq)]
struct JournalSnapshot {
    journal_epoch_id: JournalEpochId,
    revision: u64,
    next_generation: u64,
    records: BTreeMap<OwnershipId, OwnershipRecord>,
}

impl JournalSnapshot {
    fn empty(journal_epoch_id: JournalEpochId) -> Self {
        Self {
            journal_epoch_id,
            revision: 0,
            next_generation: 1,
            records: BTreeMap::new(),
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.records.len() > MAX_RECORDS || self.next_generation == 0 {
            return Err(JournalError::Capacity);
        }
        let mut generations = BTreeSet::new();
        let mut context_ids = BTreeSet::new();
        let mut prepare_request_ids = BTreeSet::new();
        let mut reconcile_request_ids = BTreeSet::new();
        for (key, record) in &self.records {
            if *key != record.ownership_id
                || record.journal_epoch_id != self.journal_epoch_id
                || record.generation.get() >= self.next_generation
                || !generations.insert(record.generation)
                || !context_ids.insert(record.context_id)
                || !prepare_request_ids.insert(record.prepare_request_id)
                || record.reconcile.is_some_and(|binding| {
                    !reconcile_request_ids.insert(binding.request_id)
                        || prepare_request_ids.contains(&binding.request_id)
                })
            {
                return Err(JournalError::InvalidRecord);
            }
            record.validate()?;
        }
        if prepare_request_ids
            .iter()
            .any(|request_id| reconcile_request_ids.contains(request_id))
        {
            return Err(JournalError::InvalidRecord);
        }
        Ok(())
    }

    fn mint_generation(&mut self) -> Result<NonZeroU64, JournalError> {
        let generation = NonZeroU64::new(self.next_generation).ok_or(JournalError::Capacity)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        Ok(generation)
    }

    fn encode(&self) -> Result<Vec<u8>, JournalError> {
        self.validate()?;
        let mut encoded = Vec::with_capacity(128 + self.records.len() * 192);
        encoded.extend_from_slice(&JOURNAL_MAGIC);
        put_u16(&mut encoded, JOURNAL_VERSION);
        encoded.extend_from_slice(&self.journal_epoch_id.0);
        put_u64(&mut encoded, self.revision);
        put_u64(&mut encoded, self.next_generation);
        put_u32(
            &mut encoded,
            u32::try_from(self.records.len()).map_err(|_| JournalError::Capacity)?,
        );
        for record in self.records.values() {
            encode_record(&mut encoded, record);
            if encoded.len() + DIGEST_BYTES > MAX_JOURNAL_BYTES {
                return Err(JournalError::Capacity);
            }
        }
        let checksum = blake3::hash(&encoded);
        encoded.extend_from_slice(checksum.as_bytes());
        if encoded.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Capacity);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, JournalError> {
        const PREFIX_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        if encoded.len() < PREFIX_BYTES + DIGEST_BYTES || encoded.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Corrupt);
        }
        let payload_len = encoded.len() - DIGEST_BYTES;
        let (payload, checksum) = encoded.split_at(payload_len);
        let expected = blake3::hash(payload);
        if expected.as_bytes().ct_eq(checksum).unwrap_u8() != 1 {
            return Err(JournalError::Corrupt);
        }

        let mut decoder = Decoder::new(payload);
        if decoder.take::<8>()? != JOURNAL_MAGIC || decoder.u16()? != JOURNAL_VERSION {
            return Err(JournalError::Corrupt);
        }
        let journal_epoch_id =
            JournalEpochId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
        let revision = decoder.u64()?;
        let next_generation = decoder.u64()?;
        let record_count = usize::try_from(decoder.u32()?).map_err(|_| JournalError::Corrupt)?;
        if record_count > MAX_RECORDS {
            return Err(JournalError::Corrupt);
        }
        let mut records = BTreeMap::new();
        let mut previous = None;
        for _ in 0..record_count {
            let record = decode_record(&mut decoder)?;
            if previous.is_some_and(|value| value >= record.ownership_id) {
                return Err(JournalError::Corrupt);
            }
            previous = Some(record.ownership_id);
            records.insert(record.ownership_id, record);
        }
        if !decoder.is_empty() {
            return Err(JournalError::Corrupt);
        }
        let snapshot = Self {
            journal_epoch_id,
            revision,
            next_generation,
            records,
        };
        snapshot.validate().map_err(|_| JournalError::Corrupt)?;
        Ok(snapshot)
    }
}

impl fmt::Debug for JournalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalSnapshot")
            .field("journal_epoch_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("next_generation", &self.next_generation)
            .field("record_count", &self.records.len())
            .finish()
    }
}

fn encode_record(encoded: &mut Vec<u8>, record: &OwnershipRecord) {
    encoded.extend_from_slice(&record.journal_epoch_id.0);
    encoded.extend_from_slice(&record.origin_runtime_id.0);
    encoded.extend_from_slice(&record.ownership_id.0);
    encoded.extend_from_slice(&record.context_id.0);
    encoded.extend_from_slice(&record.prepare_request_id.0);
    encoded.extend_from_slice(&record.prepare_operation_digest);
    put_u64(encoded, record.generation.get());
    put_u64(encoded, record.setup_expires_at_unix.get());
    put_u64(encoded, record.hard_expires_at_unix.get());
    encoded.push(record.plan.context_role as u8);
    encoded.push(u8::try_from(record.plan.paths.len()).expect("closed plan length"));
    for path in &record.plan.paths {
        encoded.push(path.path_id);
        encoded.push(path.role as u8);
    }
    encoded.push(record.phase as u8);
    match record.absent_origin {
        None => encoded.push(0),
        Some(origin) => {
            encoded.push(1);
            encoded.push(origin as u8);
        }
    }
    match record.reconcile {
        None => encoded.push(0),
        Some(binding) => {
            encoded.push(1);
            encoded.extend_from_slice(&binding.request_id.0);
            encoded.extend_from_slice(&binding.operation_digest);
        }
    }
    match record.recovery_evidence {
        None => encoded.push(0),
        Some(PrepareRecoveryEvidenceV1::LegacyAnchor(anchor)) => {
            encoded.push(1);
            encode_recovery_anchor(encoded, anchor);
        }
        Some(PrepareRecoveryEvidenceV1::CustodyBound { anchor, binding }) => {
            encoded.push(2);
            encode_recovery_anchor(encoded, anchor);
            let binding_start = encoded.len();
            encode_custody_descriptor_identity(encoded, binding.pidfd);
            encode_custody_descriptor_identity(encoded, binding.network_namespace);
            debug_assert_eq!(
                encoded.len() - binding_start,
                CUSTODY_DESCRIPTOR_BINDING_BYTES
            );
        }
    }
}

fn encode_recovery_anchor(encoded: &mut Vec<u8>, anchor: PrepareRecoveryAnchorV1) {
    encoded.extend_from_slice(&anchor.boot_id.0);
    put_u32(encoded, anchor.pid.get());
    put_u64(encoded, anchor.process_start_ticks.get());
    put_u64(encoded, anchor.network_namespace_device.get());
    put_u64(encoded, anchor.network_namespace_inode.get());
    put_u64(encoded, anchor.executable_device.get());
    put_u64(encoded, anchor.executable_inode.get());
    put_u64(encoded, anchor.service_cgroup_inode.get());
}

fn encode_custody_descriptor_identity(
    encoded: &mut Vec<u8>,
    identity: CustodyDescriptorIdentityV1,
) {
    let start = encoded.len();
    put_u32(encoded, identity.mode.get());
    put_u32(encoded, identity.device_major);
    put_u32(encoded, identity.device_minor);
    put_u64(encoded, identity.inode.get());
    put_u32(encoded, identity.special_device_major);
    put_u32(encoded, identity.special_device_minor);
    put_u32(encoded, identity.status_flags);
    debug_assert_eq!(encoded.len() - start, CUSTODY_DESCRIPTOR_IDENTITY_BYTES);
}

fn decode_record(decoder: &mut Decoder<'_>) -> Result<OwnershipRecord, JournalError> {
    let journal_epoch_id =
        JournalEpochId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let origin_runtime_id =
        RuntimeId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let ownership_id =
        OwnershipId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let context_id = Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?;
    let prepare_request_id = Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?;
    let prepare_operation_digest = decoder.take::<DIGEST_BYTES>()?;
    let generation = nonzero(decoder.u64()?)?;
    let setup_expires_at_unix = nonzero(decoder.u64()?)?;
    let hard_expires_at_unix = nonzero(decoder.u64()?)?;
    let context_role = ContextRole::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?;
    let path_count = usize::from(decoder.u8()?);
    if !(1..=MAX_LEASE_IDENTITIES).contains(&path_count) {
        return Err(JournalError::Corrupt);
    }
    let mut paths = Vec::with_capacity(path_count);
    for _ in 0..path_count {
        paths.push(PathPlan {
            path_id: decoder.u8()?,
            role: WireguardRole::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?,
        });
    }
    if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(JournalError::Corrupt);
    }
    let plan = ClosedPlan::new(context_role, paths).map_err(|_| JournalError::Corrupt)?;
    let phase = OwnershipPhase::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?;
    let absent_origin = match decoder.u8()? {
        0 => None,
        1 => Some(AbsentOrigin::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?),
        _ => return Err(JournalError::Corrupt),
    };
    let reconcile = match decoder.u8()? {
        0 => None,
        1 => Some(ReconcileBinding {
            request_id: Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?,
            operation_digest: decoder.take::<DIGEST_BYTES>()?,
        }),
        _ => return Err(JournalError::Corrupt),
    };
    let recovery_evidence = match decoder.u8()? {
        0 => None,
        1 => Some(PrepareRecoveryEvidenceV1::LegacyAnchor(
            decode_recovery_anchor(decoder)?,
        )),
        2 => {
            let anchor = decode_recovery_anchor(decoder)?;
            let pidfd = decode_custody_descriptor_identity(decoder)?;
            let network_namespace = decode_custody_descriptor_identity(decoder)?;
            let binding = CustodyDescriptorBindingV1::new(pidfd, network_namespace)
                .map_err(|_| JournalError::Corrupt)?;
            Some(
                PrepareRecoveryEvidenceV1::custody_bound(anchor, binding)
                    .map_err(|_| JournalError::Corrupt)?,
            )
        }
        _ => return Err(JournalError::Corrupt),
    };
    let record = OwnershipRecord {
        journal_epoch_id,
        origin_runtime_id,
        ownership_id,
        context_id,
        prepare_request_id,
        prepare_operation_digest,
        generation,
        setup_expires_at_unix,
        hard_expires_at_unix,
        plan,
        phase,
        absent_origin,
        reconcile,
        recovery_evidence,
    };
    record.validate().map_err(|_| JournalError::Corrupt)?;
    Ok(record)
}

fn decode_recovery_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<PrepareRecoveryAnchorV1, JournalError> {
    Ok(PrepareRecoveryAnchorV1 {
        boot_id: Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?,
        pid: nonzero_u32(decoder.u32()?)?,
        process_start_ticks: nonzero(decoder.u64()?)?,
        network_namespace_device: nonzero(decoder.u64()?)?,
        network_namespace_inode: nonzero(decoder.u64()?)?,
        executable_device: nonzero(decoder.u64()?)?,
        executable_inode: nonzero(decoder.u64()?)?,
        service_cgroup_inode: nonzero(decoder.u64()?)?,
    })
}

fn decode_custody_descriptor_identity(
    decoder: &mut Decoder<'_>,
) -> Result<CustodyDescriptorIdentityV1, JournalError> {
    CustodyDescriptorIdentityV1::new(
        nonzero_u32(decoder.u32()?)?,
        decoder.u32()?,
        decoder.u32()?,
        nonzero(decoder.u64()?)?,
        decoder.u32()?,
        decoder.u32()?,
        decoder.u32()?,
    )
    .map_err(|_| JournalError::Corrupt)
}

fn nonzero(value: u64) -> Result<NonZeroU64, JournalError> {
    NonZeroU64::new(value).ok_or(JournalError::Corrupt)
}

fn nonzero_u32(value: u32) -> Result<NonZeroU32, JournalError> {
    NonZeroU32::new(value).ok_or(JournalError::Corrupt)
}

fn put_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

struct Decoder<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        let end = self.position.checked_add(N).ok_or(JournalError::Corrupt)?;
        let bytes = self
            .encoded
            .get(self.position..end)
            .ok_or(JournalError::Corrupt)?;
        self.position = end;
        bytes.try_into().map_err(|_| JournalError::Corrupt)
    }

    fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, JournalError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, JournalError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn is_empty(&self) -> bool {
        self.position == self.encoded.len()
    }
}

#[derive(Clone)]
struct JournalConfig {
    parent_path: PathBuf,
    journal_path: PathBuf,
    lock_path: PathBuf,
    next_path: PathBuf,
    expected_parent_mode: u32,
    expected_owner_uid: u32,
    expected_owner_gid: u32,
}

impl JournalConfig {
    fn production() -> Self {
        Self {
            parent_path: PathBuf::from("/run/volparossa"),
            journal_path: PathBuf::from(OWNERSHIP_JOURNAL_PATH),
            lock_path: PathBuf::from(OWNERSHIP_LOCK_PATH),
            next_path: PathBuf::from(OWNERSHIP_NEXT_PATH),
            expected_parent_mode: PRODUCTION_PARENT_MODE,
            expected_owner_uid: 0,
            expected_owner_gid: getegid().as_raw(),
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.journal_path.parent() != Some(self.parent_path.as_path())
            || self.lock_path.parent() != Some(self.parent_path.as_path())
            || self.next_path.parent() != Some(self.parent_path.as_path())
            || self.journal_path == self.lock_path
            || self.journal_path == self.next_path
            || self.lock_path == self.next_path
            || self.journal_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3"))
            || self.lock_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3.lock"))
            || self.next_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3.next"))
            || self.expected_parent_mode & !0o7777 != 0
        {
            return Err(JournalError::UnsafeMetadata);
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::similar_names)]
    fn for_test(
        parent_path: &Path,
        expected_parent_mode: u32,
        expected_owner_uid: u32,
        expected_owner_gid: u32,
    ) -> Self {
        Self {
            parent_path: parent_path.to_path_buf(),
            journal_path: parent_path.join("helper.ownership-v3"),
            lock_path: parent_path.join("helper.ownership-v3.lock"),
            next_path: parent_path.join("helper.ownership-v3.next"),
            expected_parent_mode,
            expected_owner_uid,
            expected_owner_gid,
        }
    }
}

impl fmt::Debug for JournalConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalConfig")
            .field("paths", &"<fixed-or-test-scoped>")
            .field("expected_parent_mode", &self.expected_parent_mode)
            .field("expected_owner_uid", &self.expected_owner_uid)
            .field("expected_owner_gid", &self.expected_owner_gid)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct NewOwnershipIntent {
    origin_runtime_id: RuntimeId,
    ownership_id: OwnershipId,
    context_id: Id16,
    prepare_request_id: Id16,
    prepare_operation_digest: [u8; DIGEST_BYTES],
    setup_expires_at_unix: NonZeroU64,
    hard_expires_at_unix: NonZeroU64,
    plan: ClosedPlan,
}

impl fmt::Debug for NewOwnershipIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewOwnershipIntent")
            .field("identities", &"<redacted>")
            .field("deadlines", &"<redacted>")
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}

fn record_matches_intent(record: &OwnershipRecord, intent: &NewOwnershipIntent) -> bool {
    record.origin_runtime_id == intent.origin_runtime_id
        && record.ownership_id == intent.ownership_id
        && record.context_id == intent.context_id
        && record.prepare_request_id == intent.prepare_request_id
        && record.prepare_operation_digest == intent.prepare_operation_digest
        && record.setup_expires_at_unix == intent.setup_expires_at_unix
        && record.hard_expires_at_unix == intent.hard_expires_at_unix
        && record.plan == intent.plan
}

fn record_is_exact_post_insert(record: &OwnershipRecord, intent: &NewOwnershipIntent) -> bool {
    record_matches_intent(record, intent)
        && record.phase == OwnershipPhase::Intent
        && record.absent_origin.is_none()
        && record.reconcile.is_none()
        && record.recovery_evidence.is_none()
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InsertedOwnership {
    ownership_id: OwnershipId,
    generation: NonZeroU64,
    revision: u64,
}

impl fmt::Debug for InsertedOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InsertedOwnership(<redacted>)")
    }
}

/// Result of durably fencing the first possible descriptor-store publication attempt.
struct MarkedMayOwnCustody {
    revision: u64,
}

impl fmt::Debug for MarkedMayOwnCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MarkedMayOwnCustody(<redacted>)")
    }
}

/// Result of durably crossing the point after which Prepare may have created resources.
///
/// The descriptors are projected from the exact validated ownership record before persistence,
/// but this value is constructed only after the transition is known durable. That ordering keeps
/// callers from observing cleanup authority for a merely in-memory candidate.
struct MarkedMayOwnPrepare {
    revision: u64,
    resources: Vec<DurableWireguardResource>,
}

impl fmt::Debug for MarkedMayOwnPrepare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MarkedMayOwnPrepare(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct CleanupTarget {
    exact_record: OwnershipRecord,
}

impl CleanupTarget {
    /// Re-derive the exact public kernel markers committed by this validated durable record.
    ///
    /// These descriptors let a future trusted recovery backend inventory exact resources. They do
    /// not themselves prove absence or grant cleanup authority.
    fn durable_wireguard_resources(&self) -> Result<Vec<DurableWireguardResource>, JournalError> {
        self.exact_record.durable_wireguard_resources()
    }

    /// Constructs only a typed echo, not cryptographic or kernel evidence. A trusted executor may
    /// call this only after both trusted-worker teardown and exact kernel cleanup have completed.
    /// Restart recovery deliberately provides no accepting production executor; same-runtime clean
    /// settlement reaches this echo only through its separate affine actor operation.
    fn confirmed_cleanup(&self) -> ConfirmedCleanupProof {
        ConfirmedCleanupProof {
            exact_record: self.exact_record.clone(),
        }
    }
}

impl fmt::Debug for CleanupTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanupTarget(<redacted>)")
    }
}

/// Exact-record-bound affine proof that worker and kernel cleanup completed.
struct ConfirmedCleanupProof {
    exact_record: OwnershipRecord,
}

impl fmt::Debug for ConfirmedCleanupProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedCleanupProof(<redacted>)")
    }
}

/// Trusted cleanup boundary; implementations must prove worker and kernel cleanup before echoing.
trait CleanupExecutor {
    type Error;

    fn confirm_cleanup(
        &mut self,
        target: &CleanupTarget,
        deadline: HardDeadline,
    ) -> Result<ConfirmedCleanupProof, Self::Error>;
}

#[derive(Clone, Eq, PartialEq)]
struct ManagerAbsenceTarget {
    exact_record: OwnershipRecord,
}

impl ManagerAbsenceTarget {
    /// Construct the distinct affine proof only after an exact stable manager inventory excludes
    /// this custody name. `ExactNoStoredCustody` alone is not manager-absence evidence.
    fn confirmed_manager_absent(&self) -> ConfirmedManagerAbsentProof {
        ConfirmedManagerAbsentProof {
            exact_record: self.exact_record.clone(),
        }
    }
}

impl fmt::Debug for ManagerAbsenceTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagerAbsenceTarget(<redacted>)")
    }
}

/// Exact-record-bound affine proof from a distinct stable manager-absence observation.
struct ConfirmedManagerAbsentProof {
    exact_record: OwnershipRecord,
}

impl fmt::Debug for ConfirmedManagerAbsentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedManagerAbsentProof(<redacted>)")
    }
}

/// Trusted manager boundary; implementations must prove exact stable absence before echoing.
trait ManagerAbsenceExecutor {
    type Error;

    fn confirm_manager_absent(
        &mut self,
        target: &ManagerAbsenceTarget,
        deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error>;
}

#[derive(Debug)]
enum SettlementAttemptError<ExecutorError> {
    Journal(JournalError),
    Executor(ExecutorError),
    Deadline,
}

struct OwnershipJournal {
    config: JournalConfig,
    parent_directory: File,
    runtime_lock: File,
    snapshot: JournalSnapshot,
    poisoned: bool,
}

impl OwnershipJournal {
    fn open(config: JournalConfig) -> Result<Self, JournalError> {
        config.validate()?;
        let parent_directory = open_verified_parent(&config)?;
        Self::open_with_verified_parent(config, parent_directory)
    }

    /// Completes journal startup through one already verified directory object. Callers that need
    /// to latch that object before any lock creation or stale-next cleanup must never reopen the
    /// parent path between verification and this constructor.
    fn open_with_verified_parent(
        config: JournalConfig,
        parent_directory: File,
    ) -> Result<Self, JournalError> {
        config.validate()?;
        verify_parent_descriptor(&config, &parent_directory)?;
        let runtime_lock = open_runtime_lock(&config, &parent_directory)?;
        cleanup_stale_next(&config, &parent_directory)?;
        let snapshot = match load_snapshot(&config, &parent_directory)? {
            Some(snapshot) => snapshot,
            None => JournalSnapshot::empty(random_journal_epoch_id()?),
        };
        Ok(Self {
            config,
            parent_directory,
            runtime_lock,
            snapshot,
            poisoned: false,
        })
    }

    fn snapshot(&self) -> Result<&JournalSnapshot, JournalError> {
        self.ensure_usable()?;
        Ok(&self.snapshot)
    }

    fn ensure_usable(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_expected_revision(&self, expected_revision: u64) -> Result<(), JournalError> {
        self.ensure_usable()?;
        if self.snapshot.revision != expected_revision {
            return Err(JournalError::RevisionConflict);
        }
        Ok(())
    }

    fn ensure_durable_matches(&self) -> Result<(), JournalError> {
        self.ensure_usable()?;
        let durable = load_snapshot(&self.config, &self.parent_directory)?;
        let exact = if self.snapshot.revision == 0 {
            durable.is_none()
        } else {
            durable.as_ref() == Some(&self.snapshot)
        };
        if !exact {
            return Err(JournalError::RevisionConflict);
        }
        Ok(())
    }

    /// Re-establishes that a persistence failure classified as pre-rename left this runtime's
    /// complete authority boundary unchanged before another mutation may be attempted.
    ///
    /// This is deliberately stricter than `ensure_durable_matches`: the retained parent and lock
    /// descriptors must still name the exact secure directory entries, this runtime must still
    /// own the exclusive lock, no temporary journal entry may exist, and the durable main entry
    /// must decode to the exact in-memory snapshot. The check never repairs or removes anything.
    /// Any inability to prove the complete state poisons this journal permanently.
    fn confirm_retry_safe_after_definite_failure(&mut self) -> Result<(), JournalError> {
        self.ensure_usable()?;
        let verified = (|| {
            verify_parent_descriptor(&self.config, &self.parent_directory)?;
            verify_runtime_lock_held(&self.config, &self.parent_directory, &self.runtime_lock)?;
            verify_next_absent(&self.config, &self.parent_directory)?;
            self.ensure_durable_matches()?;

            // Bracket the durable read so a replaced parent or lock entry is not accepted merely
            // because the retained directory descriptor still points at the former directory.
            verify_parent_descriptor(&self.config, &self.parent_directory)?;
            verify_runtime_lock_entry(&self.config, &self.parent_directory, &self.runtime_lock)?;
            verify_next_absent(&self.config, &self.parent_directory)
        })();
        if verified.is_err() {
            self.poisoned = true;
            return Err(JournalError::Poisoned);
        }
        Ok(())
    }

    fn insert_intent(
        &mut self,
        expected_revision: u64,
        intent: NewOwnershipIntent,
    ) -> Result<InsertedOwnership, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        // A durable insert may have completed after its reply was lost. Only the complete immutable
        // intent is an idempotency key; every partial match remains a conflicting new insert.
        if let Some(record) = self.snapshot.records.get(&intent.ownership_id) {
            if !record_matches_intent(record, &intent) {
                return Err(JournalError::InvalidRecord);
            }
            if !record_is_exact_post_insert(record, &intent) {
                return Err(JournalError::InvalidTransition);
            }
            let inserted = InsertedOwnership {
                ownership_id: record.ownership_id,
                generation: record.generation,
                revision: self.snapshot.revision,
            };
            self.ensure_durable_matches()?;
            return Ok(inserted);
        }
        if self.snapshot.records.len() >= MAX_RECORDS
            || self
                .snapshot
                .records
                .values()
                .any(|record| record.context_id == intent.context_id)
            || request_id_in_use(&self.snapshot, intent.prepare_request_id)
            || intent.hard_expires_at_unix < intent.setup_expires_at_unix
        {
            return Err(JournalError::InvalidRecord);
        }
        let ownership_id = intent.ownership_id;
        let mut next = self.snapshot.clone();
        let generation = next.mint_generation()?;
        let record = OwnershipRecord {
            journal_epoch_id: next.journal_epoch_id,
            origin_runtime_id: intent.origin_runtime_id,
            ownership_id,
            context_id: intent.context_id,
            prepare_request_id: intent.prepare_request_id,
            prepare_operation_digest: intent.prepare_operation_digest,
            generation,
            setup_expires_at_unix: intent.setup_expires_at_unix,
            hard_expires_at_unix: intent.hard_expires_at_unix,
            plan: intent.plan,
            phase: OwnershipPhase::Intent,
            absent_origin: None,
            reconcile: None,
            recovery_evidence: None,
        };
        record.validate()?;
        next.records.insert(ownership_id, record);
        let revision = self.compare_and_swap(expected_revision, next)?;
        Ok(InsertedOwnership {
            ownership_id,
            generation,
            revision,
        })
    }

    fn bind_reconcile(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        binding: ReconcileBinding,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if let Some(existing) = record.reconcile {
            if existing != binding {
                return Err(JournalError::InvalidTransition);
            }
            self.ensure_durable_matches()?;
            return Ok(expected_revision);
        }
        if request_id_in_use(&self.snapshot, binding.request_id) {
            return Err(JournalError::InvalidRecord);
        }
        let mut next = self.snapshot.clone();
        next.records
            .get_mut(&ownership_id)
            .expect("checked ownership")
            .reconcile = Some(binding);
        self.compare_and_swap(expected_revision, next)
    }

    fn mark_may_own_custody(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        anchor: PrepareRecoveryAnchorV1,
        binding: CustodyDescriptorBindingV1,
        deadline: HardDeadline,
    ) -> Result<MarkedMayOwnCustody, JournalError> {
        let evidence = PrepareRecoveryEvidenceV1::custody_bound(anchor, binding)?;
        self.mark_may_own_custody_observed(
            expected_revision,
            ownership_id,
            generation,
            evidence,
            deadline,
            &mut NoFailPersistObserver,
        )
    }

    fn mark_may_own_custody_observed(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        evidence: PrepareRecoveryEvidenceV1,
        deadline: HardDeadline,
        observer: &mut impl PersistObserver,
    ) -> Result<MarkedMayOwnCustody, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase == OwnershipPhase::MayOwnCustody {
            // At the exact current revision, acknowledge only the durable transition already made.
            if record.recovery_evidence != Some(evidence)
                || record.absent_origin.is_some()
                || record.reconcile.is_some()
            {
                return Err(JournalError::InvalidTransition);
            }
            self.ensure_durable_matches()?;
            return Ok(MarkedMayOwnCustody {
                revision: self.snapshot.revision,
            });
        }
        let mut next = self.snapshot.clone();
        let record = next
            .records
            .get_mut(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase != OwnershipPhase::Intent || record.reconcile.is_some() {
            return Err(JournalError::InvalidTransition);
        }
        record.advance(OwnershipPhase::MayOwnCustody, Some(evidence), None)?;
        deadline
            .ensure_remaining()
            .map_err(|_| JournalError::Io(io::ErrorKind::TimedOut.into()))?;
        let revision = self.compare_and_swap_observed_with_deadline(
            expected_revision,
            next,
            observer,
            Some(deadline),
        )?;
        Ok(MarkedMayOwnCustody { revision })
    }

    fn mark_may_own_prepare_from_custody(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        deadline: HardDeadline,
    ) -> Result<MarkedMayOwnPrepare, JournalError> {
        self.mark_may_own_prepare_from_custody_observed(
            expected_revision,
            ownership_id,
            generation,
            deadline,
            &mut NoFailPersistObserver,
        )
    }

    fn mark_may_own_prepare_from_custody_observed(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        deadline: HardDeadline,
        observer: &mut impl PersistObserver,
    ) -> Result<MarkedMayOwnPrepare, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase == OwnershipPhase::MayOwnPrepare {
            if !record
                .recovery_evidence
                .is_some_and(PrepareRecoveryEvidenceV1::is_custody_bound)
                || record.absent_origin.is_some()
                || record.reconcile.is_some()
            {
                return Err(JournalError::InvalidTransition);
            }
            let resources = record.durable_wireguard_resources()?;
            self.ensure_durable_matches()?;
            return Ok(MarkedMayOwnPrepare {
                revision: self.snapshot.revision,
                resources,
            });
        }
        let mut next = self.snapshot.clone();
        let record = next
            .records
            .get_mut(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation
            || record.phase != OwnershipPhase::MayOwnCustody
            || record.reconcile.is_some()
        {
            return Err(JournalError::InvalidTransition);
        }
        let evidence = record
            .recovery_evidence
            .filter(|evidence| evidence.is_custody_bound())
            .ok_or(JournalError::InvalidTransition)?;
        record.advance(OwnershipPhase::MayOwnPrepare, Some(evidence), None)?;
        let resources = record.durable_wireguard_resources()?;
        deadline
            .ensure_remaining()
            .map_err(|_| JournalError::Io(io::ErrorKind::TimedOut.into()))?;
        let revision = self.compare_and_swap_observed_with_deadline(
            expected_revision,
            next,
            observer,
            Some(deadline),
        )?;
        Ok(MarkedMayOwnPrepare {
            revision,
            resources,
        })
    }

    fn mark_intent_absent(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase == OwnershipPhase::Absent {
            // Only the exact never-dispatched transition may be acknowledged without another write.
            if record.absent_origin != Some(AbsentOrigin::NeverDispatched) {
                return Err(JournalError::InvalidTransition);
            }
            self.ensure_durable_matches()?;
            return Ok(self.snapshot.revision);
        }
        let mut next = self.snapshot.clone();
        let record = next
            .records
            .get_mut(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.phase != OwnershipPhase::Intent || record.recovery_evidence.is_some() {
            return Err(JournalError::InvalidTransition);
        }
        record.advance(
            OwnershipPhase::Absent,
            None,
            Some(AbsentOrigin::NeverDispatched),
        )?;
        self.compare_and_swap(expected_revision, next)
    }

    fn confirm_cleanup<Executor: CleanupExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        self.confirm_cleanup_observed(
            expected_revision,
            ownership_id,
            generation,
            executor,
            deadline,
            &mut NoFailPersistObserver,
        )
    }

    fn confirm_cleanup_observed<Executor: CleanupExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
        observer: &mut impl PersistObserver,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        self.ensure_expected_revision(expected_revision)
            .map_err(SettlementAttemptError::Journal)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .filter(|record| record.generation == generation)
            .cloned()
            .ok_or(SettlementAttemptError::Journal(JournalError::InvalidRecord))?;
        if record.phase == OwnershipPhase::CleanupConfirmed {
            // A lost reply may retry only the exact already-durable cleanup transition. The
            // distinct manager-absence transition cannot run without receiving this result.
            self.ensure_durable_matches()
                .map_err(SettlementAttemptError::Journal)?;
            return Ok(self.snapshot.revision);
        }
        if !matches!(
            (record.phase, record.recovery_evidence),
            (
                OwnershipPhase::MayOwnCustody | OwnershipPhase::MayOwnPrepare,
                Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
            )
        ) {
            return Err(SettlementAttemptError::Journal(
                JournalError::InvalidTransition,
            ));
        }
        self.ensure_durable_matches()
            .map_err(SettlementAttemptError::Journal)?;
        let target = CleanupTarget {
            exact_record: record,
        };
        deadline
            .ensure_remaining()
            .map_err(|_| SettlementAttemptError::Deadline)?;
        let proof = executor
            .confirm_cleanup(&target, deadline)
            .map_err(SettlementAttemptError::Executor)?;
        if proof.exact_record != target.exact_record {
            return Err(SettlementAttemptError::Journal(JournalError::ProofMismatch));
        }
        let mut next = self.snapshot.clone();
        let next_record = next
            .records
            .get_mut(&ownership_id)
            .expect("checked ownership");
        let recovery_evidence = next_record.recovery_evidence;
        next_record
            .advance(OwnershipPhase::CleanupConfirmed, recovery_evidence, None)
            .map_err(SettlementAttemptError::Journal)?;
        deadline
            .ensure_remaining()
            .map_err(|_| SettlementAttemptError::Deadline)?;
        match self.compare_and_swap_observed_with_deadline(
            expected_revision,
            next,
            observer,
            Some(deadline),
        ) {
            Ok(revision) => Ok(revision),
            Err(JournalError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
                    && deadline.ensure_remaining().is_err() =>
            {
                Err(SettlementAttemptError::Deadline)
            }
            Err(error) => Err(SettlementAttemptError::Journal(error)),
        }
    }

    fn confirm_manager_absent<Executor: ManagerAbsenceExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        self.confirm_manager_absent_observed(
            expected_revision,
            ownership_id,
            generation,
            executor,
            deadline,
            &mut NoFailPersistObserver,
        )
    }

    fn confirm_manager_absent_observed<Executor: ManagerAbsenceExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
        observer: &mut impl PersistObserver,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        self.ensure_expected_revision(expected_revision)
            .map_err(SettlementAttemptError::Journal)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .filter(|record| record.generation == generation)
            .cloned()
            .ok_or(SettlementAttemptError::Journal(JournalError::InvalidRecord))?;
        if record.phase == OwnershipPhase::Absent {
            // Only the exact second transition's tombstone may suppress manager observation on a
            // lost-reply retry; NeverDispatched cannot stand in for manager absence.
            if record.absent_origin != Some(AbsentOrigin::RecoveredMayOwn) {
                return Err(SettlementAttemptError::Journal(
                    JournalError::InvalidTransition,
                ));
            }
            self.ensure_durable_matches()
                .map_err(SettlementAttemptError::Journal)?;
            return Ok(self.snapshot.revision);
        }
        if !matches!(
            (record.phase, record.recovery_evidence),
            (
                OwnershipPhase::CleanupConfirmed,
                Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
            )
        ) {
            return Err(SettlementAttemptError::Journal(
                JournalError::InvalidTransition,
            ));
        }
        self.ensure_durable_matches()
            .map_err(SettlementAttemptError::Journal)?;
        let target = ManagerAbsenceTarget {
            exact_record: record,
        };
        deadline
            .ensure_remaining()
            .map_err(|_| SettlementAttemptError::Deadline)?;
        let proof = executor
            .confirm_manager_absent(&target, deadline)
            .map_err(SettlementAttemptError::Executor)?;
        if proof.exact_record != target.exact_record {
            return Err(SettlementAttemptError::Journal(JournalError::ProofMismatch));
        }
        let mut next = self.snapshot.clone();
        next.records
            .get_mut(&ownership_id)
            .expect("checked ownership")
            .advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::RecoveredMayOwn),
            )
            .map_err(SettlementAttemptError::Journal)?;
        deadline
            .ensure_remaining()
            .map_err(|_| SettlementAttemptError::Deadline)?;
        match self.compare_and_swap_observed_with_deadline(
            expected_revision,
            next,
            observer,
            Some(deadline),
        ) {
            Ok(revision) => Ok(revision),
            Err(JournalError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
                    && deadline.ensure_remaining().is_err() =>
            {
                Err(SettlementAttemptError::Deadline)
            }
            Err(error) => Err(SettlementAttemptError::Journal(error)),
        }
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        next: JournalSnapshot,
    ) -> Result<u64, JournalError> {
        self.compare_and_swap_observed(expected_revision, next, &mut NoFailPersistObserver)
    }

    fn compare_and_swap_observed(
        &mut self,
        expected_revision: u64,
        next: JournalSnapshot,
        observer: &mut impl PersistObserver,
    ) -> Result<u64, JournalError> {
        self.compare_and_swap_observed_with_deadline(expected_revision, next, observer, None)
    }

    fn compare_and_swap_observed_with_deadline(
        &mut self,
        expected_revision: u64,
        mut next: JournalSnapshot,
        observer: &mut impl PersistObserver,
        mutation_deadline: Option<HardDeadline>,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        if next.revision != expected_revision
            || next.journal_epoch_id != self.snapshot.journal_epoch_id
            || next.next_generation < self.snapshot.next_generation
        {
            return Err(JournalError::RevisionConflict);
        }
        self.ensure_durable_matches()?;
        next.revision = expected_revision
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        next.validate()?;
        let encoded = next.encode()?;
        match persist_atomic(
            &self.config,
            &self.parent_directory,
            &self.snapshot,
            &encoded,
            observer,
            mutation_deadline,
        ) {
            Ok(()) => {
                self.snapshot = next;
                Ok(self.snapshot.revision)
            }
            Err(failure) if failure.uncertain => {
                self.poisoned = true;
                Err(JournalError::PersistUncertain)
            }
            Err(failure) if is_revision_conflict_io(&failure.error) => {
                Err(JournalError::RevisionConflict)
            }
            Err(failure) => Err(JournalError::Io(failure.error)),
        }
    }
}

fn open_verified_parent(config: &JournalConfig) -> Result<File, JournalError> {
    let path_metadata = fs::symlink_metadata(&config.parent_path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.uid() != config.expected_owner_uid
        || path_metadata.gid() != config.expected_owner_gid
        || path_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&config.parent_path)
        .map_err(JournalError::Io)?;
    let descriptor_metadata = directory.metadata()?;
    if !descriptor_metadata.is_dir()
        || descriptor_metadata.dev() != path_metadata.dev()
        || descriptor_metadata.ino() != path_metadata.ino()
        || descriptor_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(directory)
}

fn open_runtime_lock(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<File, JournalError> {
    let lock_name = child_name(&config.lock_path)?;
    let lock = open_or_create_secure_file(config, parent_directory, lock_name)?;
    match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => return Err(JournalError::LockHeld),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    }
    Ok(lock)
}

fn verify_runtime_lock_entry(
    config: &JournalConfig,
    parent_directory: &File,
    runtime_lock: &File,
) -> Result<(), JournalError> {
    let lock_name = child_name(&config.lock_path)?;
    verify_open_regular_file(runtime_lock, config)?;
    verify_child_entry(parent_directory, lock_name, runtime_lock)
}

fn verify_runtime_lock_held(
    config: &JournalConfig,
    parent_directory: &File,
    runtime_lock: &File,
) -> Result<(), JournalError> {
    verify_runtime_lock_entry(config, parent_directory, runtime_lock)?;
    let lock_name = child_name(&config.lock_path)?;
    let contender_descriptor = match openat(
        parent_directory,
        lock_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let contender = File::from(contender_descriptor);
    verify_open_regular_file(&contender, config)?;
    verify_child_entry(parent_directory, lock_name, &contender)?;

    match flock(&contender, FlockOperation::NonBlockingLockShared) {
        Err(Errno::WOULDBLOCK) => {}
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
        Ok(()) => {
            // A shared contender can succeed only if the retained descriptor lost or downgraded
            // its exclusive lock. Release the diagnostic lock immediately; the caller poisons the
            // journal and must never try to repair or continue this runtime.
            flock(&contender, FlockOperation::Unlock)
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            return Err(JournalError::LockHeld);
        }
    }

    // Distinguish our retained exclusive lock from a conflicting lock acquired through a
    // different open-file description. Reasserting the same exclusive lock is idempotent.
    flock(runtime_lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| JournalError::Io(rustix_io(error)))
}

fn verify_next_absent(config: &JournalConfig, parent_directory: &File) -> Result<(), JournalError> {
    let next_name = child_name(&config.next_path)?;
    match statat(parent_directory, next_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
        Ok(_) => Err(JournalError::RevisionConflict),
    }
}

fn load_snapshot(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<Option<JournalSnapshot>, JournalError> {
    let journal_name = child_name(&config.journal_path)?;
    let descriptor = match openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let mut journal = File::from(descriptor);
    let metadata = verify_open_regular_file(&journal, config)?;
    verify_child_entry(parent_directory, journal_name, &journal)?;
    if metadata.len() > MAX_JOURNAL_BYTES as u64 {
        return Err(JournalError::Corrupt);
    }
    let mut encoded =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| JournalError::Corrupt)?);
    Read::by_ref(&mut journal)
        .take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Corrupt);
    }
    let snapshot = JournalSnapshot::decode(&encoded)?;
    if snapshot.revision == 0 {
        return Err(JournalError::Corrupt);
    }
    Ok(Some(snapshot))
}

fn cleanup_stale_next(config: &JournalConfig, parent_directory: &File) -> Result<(), JournalError> {
    let next_name = child_name(&config.next_path)?;
    let descriptor = match openat(
        parent_directory,
        next_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(()),
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let stale = File::from(descriptor);
    verify_open_regular_file(&stale, config)?;
    verify_child_entry(parent_directory, next_name, &stale)?;
    unlinkat(parent_directory, next_name, AtFlags::empty())
        .map_err(|error| JournalError::Io(rustix_io(error)))?;
    parent_directory.sync_all()?;
    Ok(())
}

fn verify_open_regular_file(
    file: &File,
    config: &JournalConfig,
) -> Result<fs::Metadata, JournalError> {
    let descriptor_metadata = file.metadata()?;
    if !descriptor_metadata.is_file()
        || descriptor_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.mode() & 0o7777 != JOURNAL_FILE_MODE
        || descriptor_metadata.nlink() != 1
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(descriptor_metadata)
}

fn open_or_create_secure_file(
    config: &JournalConfig,
    parent_directory: &File,
    name: &std::ffi::OsStr,
) -> Result<File, JournalError> {
    let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    match openat(parent_directory, name, flags, Mode::empty()) {
        Ok(descriptor) => {
            let file = File::from(descriptor);
            verify_open_regular_file(&file, config)?;
            verify_child_entry(parent_directory, name, &file)?;
            Ok(file)
        }
        Err(Errno::NOENT) => {
            let descriptor = openat(
                parent_directory,
                name,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(JOURNAL_FILE_MODE),
            )
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
            let file = File::from(descriptor);
            fchmod(&file, Mode::from_raw_mode(JOURNAL_FILE_MODE))
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            let metadata = file.metadata()?;
            if metadata.uid() != config.expected_owner_uid
                || metadata.gid() != config.expected_owner_gid
            {
                fchown(
                    &file,
                    Some(Uid::from_raw(config.expected_owner_uid)),
                    Some(Gid::from_raw(config.expected_owner_gid)),
                )
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            }
            verify_open_regular_file(&file, config)?;
            verify_child_entry(parent_directory, name, &file)?;
            Ok(file)
        }
        Err(Errno::LOOP) => Err(JournalError::UnsafeMetadata),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
    }
}

fn child_name(path: &Path) -> Result<&std::ffi::OsStr, JournalError> {
    path.file_name().ok_or(JournalError::UnsafeMetadata)
}

fn verify_child_entry(
    parent_directory: &File,
    name: &std::ffi::OsStr,
    file: &File,
) -> Result<(), JournalError> {
    let entry = statat(parent_directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| JournalError::Io(rustix_io(error)))?;
    let descriptor = file.metadata()?;
    if entry.st_dev != descriptor.dev()
        || entry.st_ino != descriptor.ino()
        || entry.st_uid != descriptor.uid()
        || entry.st_gid != descriptor.gid()
        || entry.st_nlink != descriptor.nlink()
        || entry.st_mode != descriptor.mode()
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(())
}

fn random_journal_epoch_id() -> Result<JournalEpochId, JournalError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| JournalError::Random)?;
        if let Ok(epoch) = JournalEpochId::new(bytes) {
            return Ok(epoch);
        }
    }
    Err(JournalError::Random)
}

fn random_ownership_id() -> Result<OwnershipId, JournalError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| JournalError::Random)?;
        if let Ok(ownership_id) = OwnershipId::new(bytes) {
            return Ok(ownership_id);
        }
    }
    Err(JournalError::Random)
}

fn request_id_in_use(snapshot: &JournalSnapshot, request_id: Id16) -> bool {
    snapshot.records.values().any(|record| {
        record.prepare_request_id == request_id
            || record
                .reconcile
                .is_some_and(|binding| binding.request_id == request_id)
    })
}

fn rustix_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistStep {
    BeforeCreate,
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    BeforeRename,
    BeforeCleanupUnlink,
    BeforeCleanupDirectorySync,
    AfterRename,
    AfterDirectorySync,
}

trait PersistObserver {
    fn observe(&mut self, step: PersistStep) -> io::Result<()>;
}

struct NoFailPersistObserver;

impl PersistObserver for NoFailPersistObserver {
    fn observe(&mut self, _step: PersistStep) -> io::Result<()> {
        Ok(())
    }
}

struct PersistFailure {
    error: io::Error,
    uncertain: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "atomic ordering, failpoints, identity checks and uncertainty form one audit unit"
)]
fn persist_atomic(
    config: &JournalConfig,
    parent_directory: &File,
    expected_snapshot: &JournalSnapshot,
    encoded: &[u8],
    observer: &mut impl PersistObserver,
    mutation_deadline: Option<HardDeadline>,
) -> Result<(), PersistFailure> {
    observer
        .observe(PersistStep::BeforeCreate)
        .map_err(|error| PersistFailure {
            error,
            uncertain: false,
        })?;
    verify_parent_descriptor(config, parent_directory).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    let next_name = child_name(&config.next_path).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    if let Some(deadline) = mutation_deadline {
        deadline
            .ensure_remaining()
            .map_err(|error| PersistFailure {
                error,
                uncertain: false,
            })?;
    }
    let mut temporary = match create_next_file(config, parent_directory) {
        Ok(file) => file,
        Err(error) => {
            let uncertain = statat(parent_directory, next_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_or_else(|status| status != Errno::NOENT, |_| true);
            return Err(PersistFailure { error, uncertain });
        }
    };

    let before_rename = (|| -> io::Result<()> {
        observer.observe(PersistStep::AfterCreate)?;
        temporary.write_all(encoded)?;
        observer.observe(PersistStep::AfterWrite)?;
        temporary.sync_all()?;
        observer.observe(PersistStep::AfterFileSync)?;
        verify_open_regular_file(&temporary, config).map_err(journal_error_as_io)?;
        verify_parent_descriptor(config, parent_directory).map_err(journal_error_as_io)?;
        verify_destination_if_present(config, parent_directory).map_err(journal_error_as_io)?;
        Ok(())
    })();
    if let Err(error) = before_rename {
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }

    let durable = load_snapshot(config, parent_directory);
    let exact = durable.as_ref().is_ok_and(|durable| {
        if expected_snapshot.revision == 0 {
            durable.is_none()
        } else {
            durable.as_ref() == Some(expected_snapshot)
        }
    });
    if !exact {
        let durable_error = durable
            .err()
            .map_or_else(revision_conflict_io, journal_error_as_io);
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error: durable_error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }

    let journal_name = child_name(&config.journal_path).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    if let Err(error) = observer.observe(PersistStep::BeforeRename) {
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }
    if let Err(error) = renameat(parent_directory, next_name, parent_directory, journal_name) {
        let cleanup = cleanup_failed_next(parent_directory, next_name, observer);
        return Err(PersistFailure {
            error: cleanup.err().unwrap_or_else(|| rustix_io(error)),
            uncertain: true,
        });
    }
    observer
        .observe(PersistStep::AfterRename)
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    let destination = openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| PersistFailure {
        error: rustix_io(error),
        uncertain: true,
    })?;
    verify_open_regular_file(&destination, config).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: true,
    })?;
    verify_child_entry(parent_directory, journal_name, &destination).map_err(|error| {
        PersistFailure {
            error: journal_error_as_io(error),
            uncertain: true,
        }
    })?;
    let temporary_metadata = temporary.metadata().map_err(|error| PersistFailure {
        error,
        uncertain: true,
    })?;
    let destination_metadata = destination.metadata().map_err(|error| PersistFailure {
        error,
        uncertain: true,
    })?;
    if temporary_metadata.dev() != destination_metadata.dev()
        || temporary_metadata.ino() != destination_metadata.ino()
    {
        return Err(PersistFailure {
            error: io::Error::other("journal destination identity changed after rename"),
            uncertain: true,
        });
    }
    parent_directory
        .sync_all()
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    observer
        .observe(PersistStep::AfterDirectorySync)
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    Ok(())
}

fn cleanup_failed_next(
    parent_directory: &File,
    next_name: &std::ffi::OsStr,
    observer: &mut impl PersistObserver,
) -> io::Result<()> {
    observer.observe(PersistStep::BeforeCleanupUnlink)?;
    unlinkat(parent_directory, next_name, AtFlags::empty()).map_err(rustix_io)?;
    observer.observe(PersistStep::BeforeCleanupDirectorySync)?;
    parent_directory.sync_all()
}

fn create_next_file(config: &JournalConfig, parent_directory: &File) -> io::Result<File> {
    let next_name = child_name(&config.next_path).map_err(journal_error_as_io)?;
    let descriptor = openat(
        parent_directory,
        next_name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(JOURNAL_FILE_MODE),
    )
    .map_err(rustix_io)?;
    let file = File::from(descriptor);
    let setup = (|| -> Result<(), JournalError> {
        fchmod(&file, Mode::from_raw_mode(JOURNAL_FILE_MODE))
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
        let metadata = file.metadata()?;
        if metadata.uid() != config.expected_owner_uid
            || metadata.gid() != config.expected_owner_gid
        {
            fchown(
                &file,
                Some(Uid::from_raw(config.expected_owner_uid)),
                Some(Gid::from_raw(config.expected_owner_gid)),
            )
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
        }
        verify_open_regular_file(&file, config)?;
        verify_child_entry(parent_directory, next_name, &file)
    })();
    if let Err(error) = setup {
        let cleanup = unlinkat(parent_directory, next_name, AtFlags::empty())
            .map_err(rustix_io)
            .and_then(|()| parent_directory.sync_all());
        return Err(cleanup.err().unwrap_or_else(|| journal_error_as_io(error)));
    }
    Ok(file)
}

fn verify_destination_if_present(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<(), JournalError> {
    let journal_name = child_name(&config.journal_path)?;
    match openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let destination = File::from(descriptor);
            verify_open_regular_file(&destination, config)?;
            verify_child_entry(parent_directory, journal_name, &destination)
        }
        Err(Errno::NOENT) => Ok(()),
        Err(Errno::LOOP) => Err(JournalError::UnsafeMetadata),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
    }
}

fn verify_parent_descriptor(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<(), JournalError> {
    let path_metadata = fs::symlink_metadata(&config.parent_path)?;
    let descriptor_metadata = parent_directory.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || !descriptor_metadata.is_dir()
        || path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || path_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.uid() != config.expected_owner_uid
        || path_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || path_metadata.mode() & 0o7777 != config.expected_parent_mode
        || descriptor_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(())
}

fn journal_error_as_io(error: JournalError) -> io::Error {
    match error {
        JournalError::Io(error) => error,
        other => io::Error::other(other.to_string()),
    }
}

#[derive(Debug)]
struct RevisionConflictMarker;

impl fmt::Display for RevisionConflictMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("journal revision conflict")
    }
}

impl std::error::Error for RevisionConflictMarker {}

fn revision_conflict_io() -> io::Error {
    io::Error::other(RevisionConflictMarker)
}

fn is_revision_conflict_io(error: &io::Error) -> bool {
    matches!(
        error.get_ref(),
        Some(source) if source.is::<RevisionConflictMarker>()
    )
}

/// Reject startup whenever any filesystem object occupies the retired journal path.
pub(crate) fn ensure_legacy_journal_absent() -> io::Result<()> {
    ensure_absent(Path::new(LEGACY_JOURNAL_PATH))
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "retired helper ownership journal requires manual inspection",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        num::{NonZeroU32, NonZeroU64},
        os::unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
        path::Path,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use tempfile::tempdir;

    use super::*;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("non-zero fixture")
    }

    fn id16(byte: u8) -> Id16 {
        Id16::new([byte; 16]).expect("non-zero ID fixture")
    }

    fn runtime(byte: u8) -> RuntimeId {
        RuntimeId::new([byte; 32]).expect("non-zero runtime fixture")
    }

    fn epoch(byte: u8) -> JournalEpochId {
        JournalEpochId::new([byte; 32]).expect("non-zero epoch fixture")
    }

    fn ownership(byte: u8) -> OwnershipId {
        OwnershipId::new([byte; 32]).expect("non-zero ownership fixture")
    }

    fn recovery_deadline() -> HardDeadline {
        HardDeadline::after(Duration::from_secs(1)).expect("live recovery deadline")
    }

    fn confirm_cleanup_fixture<Executor: CleanupExecutor>(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
        executor: &mut Executor,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        journal.confirm_cleanup(
            expected_revision,
            inserted.ownership_id,
            inserted.generation,
            executor,
            recovery_deadline(),
        )
    }

    fn confirm_manager_absent_fixture<Executor: ManagerAbsenceExecutor>(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
        executor: &mut Executor,
    ) -> Result<u64, SettlementAttemptError<Executor::Error>> {
        journal.confirm_manager_absent(
            expected_revision,
            inserted.ownership_id,
            inserted.generation,
            executor,
            recovery_deadline(),
        )
    }

    fn mark_custody_fixture(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
        exact_anchor: PrepareRecoveryAnchorV1,
    ) -> MarkedMayOwnCustody {
        journal
            .mark_may_own_custody(
                expected_revision,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                custody_binding(exact_anchor, 7),
                recovery_deadline(),
            )
            .expect("durable MayOwnCustody fixture")
    }

    fn arm_custody_fixture(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
    ) -> MarkedMayOwnPrepare {
        journal
            .mark_may_own_prepare_from_custody(
                expected_revision,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
            )
            .expect("durable custody-bound MayOwnPrepare fixture")
    }

    fn mark_and_arm_custody_fixture(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
        exact_anchor: PrepareRecoveryAnchorV1,
    ) -> MarkedMayOwnPrepare {
        let marked = mark_custody_fixture(journal, expected_revision, inserted, exact_anchor);
        arm_custody_fixture(journal, marked.revision, inserted)
    }

    fn client_plan(path_ids: &[u8]) -> ClosedPlan {
        ClosedPlan::new(
            ContextRole::Client,
            path_ids
                .iter()
                .map(|path_id| PathPlan {
                    path_id: *path_id,
                    role: WireguardRole::Client,
                })
                .collect(),
        )
        .expect("client plan fixture")
    }

    fn anchor(seed: u64) -> PrepareRecoveryAnchorV1 {
        PrepareRecoveryAnchorV1 {
            boot_id: id16(u8::try_from(seed).expect("small fixture seed")),
            pid: NonZeroU32::new(u32::try_from(seed).expect("small fixture seed"))
                .expect("non-zero pid"),
            process_start_ticks: nz(seed + 10),
            network_namespace_device: nz(seed + 20),
            network_namespace_inode: nz(seed + 30),
            executable_device: nz(seed + 40),
            executable_inode: nz(seed + 50),
            service_cgroup_inode: nz(seed + 60),
        }
    }

    fn descriptor_identity(
        mode: u32,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        special_device_major: u32,
        special_device_minor: u32,
        status_flags: u32,
    ) -> CustodyDescriptorIdentityV1 {
        CustodyDescriptorIdentityV1::new(
            NonZeroU32::new(mode).expect("non-zero descriptor mode"),
            device_major,
            device_minor,
            nz(inode),
            special_device_major,
            special_device_minor,
            status_flags,
        )
        .expect("valid descriptor identity fixture")
    }

    fn custody_binding(
        exact_anchor: PrepareRecoveryAnchorV1,
        seed: u32,
    ) -> CustodyDescriptorBindingV1 {
        let network_namespace_minor = u32::try_from(exact_anchor.network_namespace_device.get())
            .expect("small fixture namespace device");
        CustodyDescriptorBindingV1::new(
            descriptor_identity(0o100_600, 8, seed, u64::from(seed) + 100, 0, 0, 0),
            descriptor_identity(
                0o100_444,
                0,
                network_namespace_minor,
                exact_anchor.network_namespace_inode.get(),
                0,
                0,
                0,
            ),
        )
        .expect("distinct role-ordered descriptor binding")
    }

    fn record(
        journal_epoch_id: JournalEpochId,
        ownership_seed: u8,
        context_seed: u8,
        prepare_seed: u8,
        generation: u64,
        phase: OwnershipPhase,
    ) -> OwnershipRecord {
        OwnershipRecord {
            journal_epoch_id,
            origin_runtime_id: runtime(9),
            ownership_id: ownership(ownership_seed),
            context_id: id16(context_seed),
            prepare_request_id: id16(prepare_seed),
            prepare_operation_digest: [0; DIGEST_BYTES],
            generation: nz(generation),
            setup_expires_at_unix: nz(100),
            hard_expires_at_unix: nz(200),
            plan: client_plan(&[1, 2]),
            phase,
            absent_origin: (phase == OwnershipPhase::Absent)
                .then_some(AbsentOrigin::NeverDispatched),
            reconcile: None,
            recovery_evidence: match phase {
                OwnershipPhase::MayOwnCustody | OwnershipPhase::CleanupConfirmed => {
                    let exact_anchor = anchor(7);
                    Some(
                        PrepareRecoveryEvidenceV1::custody_bound(
                            exact_anchor,
                            custody_binding(exact_anchor, 7),
                        )
                        .expect("custody evidence fixture"),
                    )
                }
                OwnershipPhase::MayOwnPrepare => {
                    Some(PrepareRecoveryEvidenceV1::LegacyAnchor(anchor(7)))
                }
                OwnershipPhase::Intent | OwnershipPhase::Absent => None,
            },
        }
    }

    fn snapshot_with(records: Vec<OwnershipRecord>) -> JournalSnapshot {
        let journal_epoch_id = records
            .first()
            .map_or_else(|| epoch(1), |record| record.journal_epoch_id);
        let next_generation = records
            .iter()
            .map(|record| record.generation.get())
            .max()
            .unwrap_or(0)
            + 1;
        JournalSnapshot {
            journal_epoch_id,
            revision: 1,
            next_generation,
            records: records
                .into_iter()
                .map(|record| (record.ownership_id, record))
                .collect(),
        }
    }

    fn test_config(parent: &Path) -> JournalConfig {
        let metadata = fs::metadata(parent).expect("temporary parent metadata");
        JournalConfig::for_test(
            parent,
            metadata.mode() & 0o7777,
            metadata.uid(),
            metadata.gid(),
        )
    }

    fn open_fifo_with_deadline(
        config: JournalConfig,
        fifo_path: PathBuf,
    ) -> Result<OwnershipJournal, JournalError> {
        let (sender, receiver) = mpsc::channel();
        let opener = thread::spawn(move || {
            let _ = sender.send(OwnershipJournal::open(config));
        });
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => {
                opener.join().expect("FIFO opener thread");
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let writer = OpenOptions::new()
                    .write(true)
                    .open(fifo_path)
                    .expect("unblock regressed FIFO reader");
                drop(writer);
                let _ = receiver.recv_timeout(Duration::from_secs(1));
                opener.join().expect("unblocked FIFO opener thread");
                panic!("journal FIFO open exceeded its bounded deadline");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                opener.join().expect("FIFO opener thread");
                panic!("journal FIFO opener disconnected")
            }
        }
    }

    fn intent(context_seed: u8, request_seed: u8) -> NewOwnershipIntent {
        NewOwnershipIntent {
            origin_runtime_id: runtime(8),
            ownership_id: ownership(context_seed.wrapping_add(32)),
            context_id: id16(context_seed),
            prepare_request_id: id16(request_seed),
            prepare_operation_digest: [0; DIGEST_BYTES],
            setup_expires_at_unix: nz(100),
            hard_expires_at_unix: nz(200),
            plan: client_plan(&[1, 2]),
        }
    }

    fn binding(seed: u8) -> ReconcileBinding {
        ReconcileBinding {
            request_id: id16(seed),
            operation_digest: [seed; DIGEST_BYTES],
        }
    }

    fn marker_aliases(record: &OwnershipRecord) -> Vec<String> {
        record
            .durable_wireguard_resources()
            .expect("valid durable resource projection")
            .into_iter()
            .map(|resource| resource.ownership_alias().to_owned())
            .collect()
    }

    fn marker_digest(alias: &str) -> &str {
        alias
            .rsplit_once(':')
            .map(|(_, digest)| digest)
            .expect("fixed marker separator")
    }

    #[test]
    fn durable_resource_exposes_exact_peer_for_every_endpoint_role() {
        let cases = [
            (
                volparossa_routing::ContextRole::Client,
                volparossa_routing::WireguardRole::Client,
                [0, 1],
                [0, 4],
            ),
            (
                volparossa_routing::ContextRole::Relay,
                volparossa_routing::WireguardRole::RelayClient,
                [0, 2],
                [0, 1],
            ),
            (
                volparossa_routing::ContextRole::Relay,
                volparossa_routing::WireguardRole::RelayExit,
                [0, 3],
                [0, 4],
            ),
            (
                volparossa_routing::ContextRole::Exit,
                volparossa_routing::WireguardRole::Exit,
                [0, 4],
                [0, 1],
            ),
        ];

        for (context_role, role, local_host, peer_host) in cases {
            let resource = durable_wireguard_resource_for_test([7; 16], context_role, 1, role, 11)
                .expect("durable endpoint resource");
            assert_eq!(resource.local_address().octets()[14..], local_host);
            assert_eq!(resource.peer_address().octets()[14..], peer_host);
        }
    }

    #[test]
    fn durable_wireguard_marker_has_fixed_golden_grammar_and_redacts_coordinates() {
        let exact = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let resources = exact
            .durable_wireguard_resources()
            .expect("valid resource projection");
        assert_eq!(resources.len(), 2);
        let first = &resources[0];
        assert_eq!(first.key(), (1, WireguardRole::Client as i32));
        assert_eq!(first.interface().len(), DERIVED_WIREGUARD_INTERFACE_BYTES);
        assert_eq!(first.local_address().octets()[14..], [0, 1]);
        assert_eq!(first.peer_address().octets()[14..], [0, 4]);
        assert_eq!(
            first.ownership_alias(),
            "volparossa:wireguard:ownership-v1:vpc123799507:\
             badfee16fe6577b6ea576dca60b0db2ed40adce2bf94d4571ae6fe95265f502b"
        );
        let expected_prefix = format!("{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:", first.interface());
        assert!(first.ownership_alias().starts_with(&expected_prefix));
        assert_eq!(
            first.ownership_alias().len(),
            DURABLE_WIREGUARD_ALIAS_PREFIX.len()
                + DERIVED_WIREGUARD_INTERFACE_BYTES
                + 1
                + DIGEST_BYTES * 2
        );
        let digest = marker_digest(first.ownership_alias());
        assert_eq!(digest.len(), DIGEST_BYTES * 2);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert!(!first.ownership_alias().contains(&"01".repeat(32)));
        assert!(!first.ownership_alias().contains(&"02".repeat(32)));
        assert_eq!(format!("{first:?}"), "DurableWireguardResource(<redacted>)");

        let target = CleanupTarget {
            exact_record: exact.clone(),
        };
        assert_eq!(
            target
                .durable_wireguard_resources()
                .expect("recovery resource projection")[0]
                .ownership_alias(),
            first.ownership_alias()
        );
        let snapshot = snapshot_with(vec![exact]);
        let decoded = JournalSnapshot::decode(&snapshot.encode().expect("encoded marker record"))
            .expect("decoded marker record");
        assert_eq!(
            marker_aliases(decoded.records.values().next().expect("decoded record")),
            resources
                .iter()
                .map(|resource| resource.ownership_alias().to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn durable_wireguard_marker_commits_every_immutable_record_class_and_exact_resource() {
        let base = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let base_digest = marker_digest(&marker_aliases(&base)[0]).to_owned();
        let assert_changes = |candidate: OwnershipRecord, field: &str| {
            candidate.validate().expect("valid immutable mutation");
            assert_ne!(
                marker_digest(&marker_aliases(&candidate)[0]),
                base_digest,
                "immutable field did not change marker: {field}"
            );
        };

        let mut candidate = base.clone();
        candidate.journal_epoch_id = epoch(5);
        assert_changes(candidate, "journal epoch");
        let mut candidate = base.clone();
        candidate.origin_runtime_id = runtime(5);
        assert_changes(candidate, "origin runtime");
        let mut candidate = base.clone();
        candidate.ownership_id = ownership(5);
        assert_changes(candidate, "ownership ID");
        let mut candidate = base.clone();
        candidate.context_id = id16(5);
        assert_changes(candidate, "context ID");
        let mut candidate = base.clone();
        candidate.prepare_request_id = id16(5);
        assert_changes(candidate, "prepare request ID");
        let mut candidate = base.clone();
        candidate.prepare_operation_digest = [5; DIGEST_BYTES];
        assert_changes(candidate, "prepare operation digest");
        let mut candidate = base.clone();
        candidate.generation = nz(5);
        assert_changes(candidate, "generation");
        let mut candidate = base.clone();
        candidate.setup_expires_at_unix = nz(101);
        assert_changes(candidate, "setup expiry");
        let mut candidate = base.clone();
        candidate.hard_expires_at_unix = nz(201);
        assert_changes(candidate, "hard expiry");
        let mut candidate = base.clone();
        candidate.plan = client_plan(&[1]);
        assert_changes(candidate, "canonical path list");
        let mut candidate = base.clone();
        candidate.plan = ClosedPlan::new(
            ContextRole::Exit,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::Exit,
                },
                PathPlan {
                    path_id: 2,
                    role: WireguardRole::Exit,
                },
            ],
        )
        .expect("exit plan");
        assert_changes(candidate, "canonical context role");

        let client_resources = base
            .durable_wireguard_resources()
            .expect("client resources");
        assert_ne!(
            marker_digest(client_resources[0].ownership_alias()),
            marker_digest(client_resources[1].ownership_alias()),
            "different path/name/address must have a distinct marker"
        );
        let mut relay = base;
        relay.plan = ClosedPlan::new(
            ContextRole::Relay,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit,
                },
            ],
        )
        .expect("relay plan");
        let relay_resources = relay
            .durable_wireguard_resources()
            .expect("relay resources");
        assert_ne!(
            relay_resources[0].interface(),
            relay_resources[1].interface()
        );
        assert_ne!(
            relay_resources[0].local_address(),
            relay_resources[1].local_address()
        );
        assert_ne!(
            marker_digest(relay_resources[0].ownership_alias()),
            marker_digest(relay_resources[1].ownership_alias()),
            "different role/name/address must have a distinct marker"
        );
    }

    #[test]
    fn durable_wireguard_marker_excludes_every_mutable_record_field() {
        let intent = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let expected = marker_aliases(&intent);

        let mut reconciled = intent.clone();
        reconciled.reconcile = Some(binding(8));
        assert_eq!(marker_aliases(&reconciled), expected);

        let may_own = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnPrepare);
        assert_eq!(marker_aliases(&may_own), expected);
        let mut different_anchor = may_own;
        different_anchor.recovery_evidence =
            Some(PrepareRecoveryEvidenceV1::LegacyAnchor(anchor(8)));
        assert_eq!(marker_aliases(&different_anchor), expected);

        let absent = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Absent);
        assert_eq!(marker_aliases(&absent), expected);
        let mut different_absent_origin = absent;
        different_absent_origin.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        assert_eq!(marker_aliases(&different_absent_origin), expected);
    }

    #[test]
    fn canonical_codec_round_trips_byte_exact_and_detects_every_truncation_and_corruption() {
        let mut first = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnPrepare);
        first.reconcile = Some(binding(5));
        let snapshot = snapshot_with(vec![first]);
        let encoded = snapshot.encode().expect("canonical encoding");
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "e01cbfd204aa20db6ce7e223b5e49eb2c9e73edb392d48025014b829df9bf69e"
        );
        let legacy_matrix = snapshot_with(vec![
            record(epoch(1), 5, 6, 7, 2, OwnershipPhase::Intent),
            record(epoch(1), 8, 9, 10, 3, OwnershipPhase::MayOwnPrepare),
            record(epoch(1), 11, 12, 13, 4, OwnershipPhase::Absent),
        ]);
        assert_eq!(
            blake3::hash(&legacy_matrix.encode().expect("legacy matrix encoding"))
                .to_hex()
                .as_str(),
            "ddb36231c7c1c6db9a108b08dac8d7f31f46f3a0b602f134e3c1e5fe764374cd"
        );
        assert!(encoded.len() <= MAX_JOURNAL_BYTES);
        let decoded = JournalSnapshot::decode(&encoded).expect("canonical decoding");
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.encode().expect("canonical re-encoding"), encoded);

        for length in 0..encoded.len() {
            assert!(JournalSnapshot::decode(&encoded[..length]).is_err());
        }
        let mut flipped = encoded.clone();
        let flipped_index = flipped.len() / 2;
        flipped[flipped_index] ^= 0x80;
        assert!(matches!(
            JournalSnapshot::decode(&flipped),
            Err(JournalError::Corrupt)
        ));

        let mut trailing_payload = encoded[..encoded.len() - DIGEST_BYTES].to_vec();
        trailing_payload.push(0);
        let checksum = blake3::hash(&trailing_payload);
        trailing_payload.extend_from_slice(checksum.as_bytes());
        assert!(matches!(
            JournalSnapshot::decode(&trailing_payload),
            Err(JournalError::Corrupt)
        ));
        assert!(!format!("{snapshot:?}").contains("03030303"));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One exhaustive phase/evidence codec matrix.
    fn custody_evidence_tag_two_is_exact_bounded_and_phase_matrix_fail_closed() {
        const RECOVERY_ANCHOR_BYTES: usize = 16 + 4 + (6 * 8);
        const CUSTODY_EVIDENCE_BYTES: usize =
            1 + RECOVERY_ANCHOR_BYTES + CUSTODY_DESCRIPTOR_BINDING_BYTES;

        fn replace_checksum(encoded: &mut [u8]) {
            let payload_len = encoded
                .len()
                .checked_sub(DIGEST_BYTES)
                .expect("encoded journal checksum");
            let checksum = *blake3::hash(&encoded[..payload_len]).as_bytes();
            encoded[payload_len..].copy_from_slice(&checksum);
        }

        let custody_record = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnCustody);
        let snapshot = snapshot_with(vec![custody_record.clone()]);
        let encoded = snapshot.encode().expect("canonical custody encoding");
        let evidence_tag = encoded.len()
            - DIGEST_BYTES
            - RECOVERY_ANCHOR_BYTES
            - CUSTODY_DESCRIPTOR_BINDING_BYTES
            - 1;
        assert_eq!(encoded[evidence_tag], 2, "custody evidence tag is frozen");
        assert_eq!(
            JournalSnapshot::decode(&encoded).expect("custody decode"),
            snapshot
        );
        assert_eq!(
            JournalSnapshot::decode(&encoded)
                .expect("custody decode")
                .encode()
                .expect("custody re-encode"),
            encoded
        );
        let exact_evidence = custody_record
            .recovery_evidence
            .expect("phase-4 custody evidence");
        let different_anchor = anchor(8);
        let different_evidence = PrepareRecoveryEvidenceV1::custody_bound(
            different_anchor,
            custody_binding(different_anchor, 8),
        )
        .expect("different valid custody evidence");
        let mut rejected_substitution = custody_record.clone();
        assert!(matches!(
            rejected_substitution.advance(
                OwnershipPhase::MayOwnPrepare,
                Some(different_evidence),
                None,
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(rejected_substitution, custody_record);

        let mut armed_record = custody_record.clone();
        armed_record
            .advance(OwnershipPhase::MayOwnPrepare, Some(exact_evidence), None)
            .expect("exact custody evidence survives arming");
        let armed_encoded = snapshot_with(vec![armed_record.clone()])
            .encode()
            .expect("custody-bound phase-2 encoding");
        let custody_evidence_start = encoded.len() - DIGEST_BYTES - CUSTODY_EVIDENCE_BYTES;
        let armed_evidence_start = armed_encoded.len() - DIGEST_BYTES - CUSTODY_EVIDENCE_BYTES;
        assert_eq!(
            &encoded[custody_evidence_start..encoded.len() - DIGEST_BYTES],
            &armed_encoded[armed_evidence_start..armed_encoded.len() - DIGEST_BYTES]
        );
        let mut cleanup_confirmed = armed_record;
        cleanup_confirmed
            .advance(OwnershipPhase::CleanupConfirmed, Some(exact_evidence), None)
            .expect("exact custody evidence survives cleanup confirmation");
        let cleanup_snapshot = snapshot_with(vec![cleanup_confirmed.clone()]);
        let cleanup_encoded = cleanup_snapshot
            .encode()
            .expect("canonical phase-5 encoding");
        let cleanup_evidence_start = cleanup_encoded.len() - DIGEST_BYTES - CUSTODY_EVIDENCE_BYTES;
        let cleanup_evidence_tag = cleanup_evidence_start;
        let cleanup_phase_offset = cleanup_evidence_tag - 3;
        assert_eq!(
            cleanup_encoded[cleanup_phase_offset], 5,
            "CleanupConfirmed phase tag is frozen at five"
        );
        assert_eq!(cleanup_encoded[cleanup_phase_offset + 1], 0);
        assert_eq!(cleanup_encoded[cleanup_evidence_tag], 2);
        assert_eq!(
            &encoded[custody_evidence_start..encoded.len() - DIGEST_BYTES],
            &cleanup_encoded[cleanup_evidence_start..cleanup_encoded.len() - DIGEST_BYTES]
        );
        assert_eq!(
            JournalSnapshot::decode(&cleanup_encoded).expect("phase-5 decode"),
            cleanup_snapshot
        );
        for length in 0..encoded.len() {
            assert!(
                JournalSnapshot::decode(&encoded[..length]).is_err(),
                "custody truncation unexpectedly decoded at {length}"
            );
        }

        let mut unknown_tag = encoded.clone();
        unknown_tag[evidence_tag] = 99;
        replace_checksum(&mut unknown_tag);
        assert!(matches!(
            JournalSnapshot::decode(&unknown_tag),
            Err(JournalError::Corrupt)
        ));

        let mut mismatched_anchor = encoded.clone();
        let namespace_device_offset = evidence_tag + 1 + 16 + 4 + 8;
        mismatched_anchor[namespace_device_offset + 7] ^= 1;
        replace_checksum(&mut mismatched_anchor);
        assert!(matches!(
            JournalSnapshot::decode(&mismatched_anchor),
            Err(JournalError::Corrupt)
        ));

        let mut bad_checksum = encoded;
        let checksum_index = bad_checksum.len() - 1;
        bad_checksum[checksum_index] ^= 0x80;
        assert!(matches!(
            JournalSnapshot::decode(&bad_checksum),
            Err(JournalError::Corrupt)
        ));

        let custody_evidence = custody_record
            .recovery_evidence
            .expect("custody evidence fixture");
        let mut invalid_intent = custody_record.clone();
        invalid_intent.phase = OwnershipPhase::Intent;
        assert!(matches!(
            invalid_intent.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut invalid_absent = custody_record.clone();
        invalid_absent.phase = OwnershipPhase::Absent;
        invalid_absent.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        assert!(matches!(
            invalid_absent.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut valid_prepare = custody_record;
        valid_prepare.phase = OwnershipPhase::MayOwnPrepare;
        valid_prepare.validate().expect("custody-bound phase 2");
        let mut invalid_legacy_custody = valid_prepare;
        invalid_legacy_custody.phase = OwnershipPhase::MayOwnCustody;
        invalid_legacy_custody.recovery_evidence =
            Some(PrepareRecoveryEvidenceV1::LegacyAnchor(anchor(7)));
        assert!(matches!(
            invalid_legacy_custody.validate(),
            Err(JournalError::InvalidRecord)
        ));
        assert!(custody_evidence.is_custody_bound());
    }

    #[test]
    fn custody_namespace_binding_reconstructs_major_minor_and_rejects_each_anchor_mismatch() {
        let mut exact_anchor = anchor(7);
        let exact_device = rustix::fs::makedev(12, 34);
        assert_ne!(exact_device, 0);
        exact_anchor.network_namespace_device =
            NonZeroU64::new(exact_device).expect("non-zero reconstructed namespace device");
        exact_anchor.network_namespace_inode = nz(987);
        let pidfd = descriptor_identity(0o100_600, 8, 7, 107, 0, 0, 0);
        let exact_namespace = descriptor_identity(0o100_444, 12, 34, 987, 0, 0, 0);
        let exact_binding =
            CustodyDescriptorBindingV1::new(pidfd, exact_namespace).expect("exact binding");
        exact_binding
            .validate_against_anchor(exact_anchor)
            .expect("major/minor reconstruction matches the anchor");

        let wrong_device = CustodyDescriptorBindingV1::new(
            pidfd,
            descriptor_identity(0o100_444, 12, 35, 987, 0, 0, 0),
        )
        .expect("different-device binding shape");
        assert!(matches!(
            wrong_device.validate_against_anchor(exact_anchor),
            Err(JournalError::InvalidRecord)
        ));
        let wrong_inode = CustodyDescriptorBindingV1::new(
            pidfd,
            descriptor_identity(0o100_444, 12, 34, 988, 0, 0, 0),
        )
        .expect("different-inode binding shape");
        assert!(matches!(
            wrong_inode.validate_against_anchor(exact_anchor),
            Err(JournalError::InvalidRecord)
        ));
    }

    #[test]
    fn absent_origin_is_persisted_and_phase_exact() {
        let journal_epoch = epoch(1);
        let never_dispatched = record(journal_epoch, 2, 3, 4, 1, OwnershipPhase::Absent);
        let mut recovered = record(journal_epoch, 5, 6, 7, 2, OwnershipPhase::Absent);
        recovered.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        let snapshot = snapshot_with(vec![never_dispatched.clone(), recovered.clone()]);
        let decoded =
            JournalSnapshot::decode(&snapshot.encode().expect("encoded typed tombstones"))
                .expect("decoded typed tombstones");
        assert_eq!(decoded, snapshot);
        assert_eq!(
            decoded
                .records
                .get(&never_dispatched.ownership_id)
                .expect("never-dispatched tombstone")
                .absent_origin,
            Some(AbsentOrigin::NeverDispatched)
        );
        assert_eq!(
            decoded
                .records
                .get(&recovered.ownership_id)
                .expect("recovered tombstone")
                .absent_origin,
            Some(AbsentOrigin::RecoveredMayOwn)
        );

        let mut intent_with_origin = record(journal_epoch, 8, 9, 10, 3, OwnershipPhase::Intent);
        intent_with_origin.absent_origin = Some(AbsentOrigin::NeverDispatched);
        assert!(matches!(
            intent_with_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut may_own_with_origin =
            record(journal_epoch, 11, 12, 13, 4, OwnershipPhase::MayOwnPrepare);
        may_own_with_origin.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        assert!(matches!(
            may_own_with_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut absent_without_origin = never_dispatched;
        absent_without_origin.absent_origin = None;
        assert!(matches!(
            absent_without_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));

        let mut never_dispatched_with_recovery_origin =
            record(journal_epoch, 14, 15, 16, 5, OwnershipPhase::Intent);
        assert!(matches!(
            never_dispatched_with_recovery_origin.advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::RecoveredMayOwn),
            ),
            Err(JournalError::InvalidTransition)
        ));
        let mut recovered_with_never_dispatched_origin =
            record(journal_epoch, 17, 18, 19, 6, OwnershipPhase::MayOwnPrepare);
        assert!(matches!(
            recovered_with_never_dispatched_origin.advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::NeverDispatched),
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert!(matches!(
            recovered_with_never_dispatched_origin.advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::RecoveredMayOwn),
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert!(matches!(
            recovered_with_never_dispatched_origin.advance(
                OwnershipPhase::CleanupConfirmed,
                recovered_with_never_dispatched_origin.recovery_evidence,
                None,
            ),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    fn codec_rejects_raw_absent_origin_ambiguity_with_a_valid_checksum() {
        const HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        const RECORD_PREFIX_TO_PATHS: usize = 32 + 32 + 32 + 16 + 16 + 32 + 8 + 8 + 8 + 1 + 1;
        const CLIENT_PATH_BYTES: usize = 4;
        const PHASE_OFFSET: usize = HEADER_BYTES + RECORD_PREFIX_TO_PATHS + CLIENT_PATH_BYTES;
        const ABSENT_ORIGIN_PRESENCE_OFFSET: usize = PHASE_OFFSET + 1;
        const ABSENT_ORIGIN_VALUE_OFFSET: usize = ABSENT_ORIGIN_PRESENCE_OFFSET + 1;

        fn replace_checksum(encoded: &mut [u8]) {
            let payload_len = encoded
                .len()
                .checked_sub(DIGEST_BYTES)
                .expect("encoded journal checksum");
            let checksum = *blake3::hash(&encoded[..payload_len]).as_bytes();
            encoded[payload_len..].copy_from_slice(&checksum);
        }

        let intent_snapshot =
            snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent)]);
        let mut invalid_presence = intent_snapshot.encode().expect("encoded Intent record");
        assert_eq!(invalid_presence[PHASE_OFFSET], OwnershipPhase::Intent as u8);
        assert_eq!(invalid_presence[ABSENT_ORIGIN_PRESENCE_OFFSET], 0);
        invalid_presence[ABSENT_ORIGIN_PRESENCE_OFFSET] = 2;
        replace_checksum(&mut invalid_presence);
        assert!(matches!(
            JournalSnapshot::decode(&invalid_presence),
            Err(JournalError::Corrupt)
        ));

        let absent_snapshot =
            snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Absent)]);
        let valid_absent = absent_snapshot.encode().expect("encoded Absent record");
        assert_eq!(valid_absent[PHASE_OFFSET], OwnershipPhase::Absent as u8);
        assert_eq!(valid_absent[ABSENT_ORIGIN_PRESENCE_OFFSET], 1);
        assert_eq!(
            valid_absent[ABSENT_ORIGIN_VALUE_OFFSET],
            AbsentOrigin::NeverDispatched as u8
        );

        let mut invalid_value = valid_absent.clone();
        invalid_value[ABSENT_ORIGIN_VALUE_OFFSET] = 99;
        replace_checksum(&mut invalid_value);
        assert!(matches!(
            JournalSnapshot::decode(&invalid_value),
            Err(JournalError::Corrupt)
        ));

        let mut mismatched_phase = valid_absent;
        mismatched_phase[PHASE_OFFSET] = OwnershipPhase::Intent as u8;
        replace_checksum(&mut mismatched_phase);
        assert!(matches!(
            JournalSnapshot::decode(&mismatched_phase),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn codec_rejects_noncanonical_path_order_even_with_a_recomputed_checksum() {
        const HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        const RECORD_PREFIX_TO_PATHS: usize = 32 + 32 + 32 + 16 + 16 + 32 + 8 + 8 + 8 + 1 + 1;
        let snapshot = snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent)]);
        let encoded = snapshot.encode().expect("canonical encoding");
        let mut payload = encoded[..encoded.len() - DIGEST_BYTES].to_vec();
        let paths = HEADER_BYTES + RECORD_PREFIX_TO_PATHS;
        assert_eq!(&payload[paths..paths + 4], &[1, 1, 2, 1]);
        payload.swap(paths, paths + 2);
        payload.swap(paths + 1, paths + 3);
        assert_eq!(&payload[paths..paths + 4], &[2, 1, 1, 1]);
        let checksum = blake3::hash(&payload);
        payload.extend_from_slice(checksum.as_bytes());
        assert!(matches!(
            JournalSnapshot::decode(&payload),
            Err(JournalError::Corrupt)
        ));

        let mut noncanonical = snapshot;
        noncanonical
            .records
            .values_mut()
            .next()
            .expect("record fixture")
            .plan
            .paths
            .swap(0, 1);
        assert!(matches!(
            noncanonical.validate(),
            Err(JournalError::InvalidRecord)
        ));
        assert!(matches!(
            noncanonical.encode(),
            Err(JournalError::InvalidRecord)
        ));
    }

    #[test]
    fn closed_plan_enforces_exact_wire_roles_and_full_per_path_cardinality() {
        let relay = ClosedPlan::new(
            ContextRole::Relay,
            (1..=8)
                .flat_map(|path_id| {
                    [WireguardRole::RelayClient, WireguardRole::RelayExit]
                        .into_iter()
                        .map(move |role| PathPlan { path_id, role })
                })
                .collect(),
        )
        .expect("eight complete relay paths");
        assert_eq!(relay.paths.len(), MAX_LEASE_IDENTITIES);

        assert!(
            ClosedPlan::new(
                ContextRole::Relay,
                vec![PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                }],
            )
            .is_err()
        );
        assert!(
            ClosedPlan::new(
                ContextRole::Client,
                vec![PathPlan {
                    path_id: 1,
                    role: WireguardRole::Exit,
                }],
            )
            .is_err()
        );
        assert!(
            ClosedPlan::new(
                ContextRole::Client,
                (1..=9)
                    .map(|path_id| PathPlan {
                        path_id,
                        role: WireguardRole::Client,
                    })
                    .collect(),
            )
            .is_err()
        );
    }

    #[test]
    fn wire_closed_plan_converts_exactly_without_normalising_a_permutation() {
        let wire = volparossa_routing::ClosedPreparePlan {
            context_role: volparossa_routing::ContextRole::Relay as i32,
            leases: vec![
                volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::RelayClient as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::RelayExit as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 2,
                    role: volparossa_routing::WireguardRole::RelayClient as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 2,
                    role: volparossa_routing::WireguardRole::RelayExit as i32,
                },
            ],
        };
        let converted = ClosedPlan::try_from_wire(&wire).expect("canonical wire plan");
        assert_eq!(converted.context_role, ContextRole::Relay);
        assert_eq!(converted.paths.len(), wire.leases.len());
        for (path, lease) in converted.paths.iter().zip(&wire.leases) {
            assert_eq!(u32::from(path.path_id), lease.path_id);
            assert_eq!(i32::from(path.role as u8), lease.role);
        }

        let mut permuted = wire;
        permuted.leases.swap(0, 1);
        assert!(matches!(
            ClosedPlan::try_from_wire(&permuted),
            Err(JournalError::InvalidRecord)
        ));

        let invalid_cases = [
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: Vec::new(),
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: (1..=17)
                    .map(|path_id| volparossa_routing::LeasePlan {
                        path_id,
                        role: volparossa_routing::WireguardRole::Client as i32,
                    })
                    .collect(),
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 256,
                    role: volparossa_routing::WireguardRole::Client as i32,
                }],
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: 99,
                }],
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::Exit as i32,
                }],
            },
        ];
        for invalid in invalid_cases {
            assert!(matches!(
                ClosedPlan::try_from_wire(&invalid),
                Err(JournalError::InvalidRecord)
            ));
        }
    }

    #[test]
    fn snapshot_rejects_cross_lineage_context_generation_and_request_id_collisions() {
        let journal_epoch = epoch(1);
        let first = record(journal_epoch, 2, 3, 4, 1, OwnershipPhase::Intent);
        let mut second = record(journal_epoch, 5, 6, 7, 2, OwnershipPhase::Intent);

        second.context_id = first.context_id;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.context_id = id16(6);
        second.generation = first.generation;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.generation = nz(2);
        second.prepare_request_id = first.prepare_request_id;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.prepare_request_id = id16(7);
        second.reconcile = Some(ReconcileBinding {
            request_id: first.prepare_request_id,
            operation_digest: [0; DIGEST_BYTES],
        });
        assert!(snapshot_with(vec![first, second]).validate().is_err());
    }

    #[test]
    fn generation_mint_is_checked_and_does_not_wrap_or_mutate_on_failure() {
        let mut snapshot = JournalSnapshot {
            journal_epoch_id: epoch(1),
            revision: 1,
            next_generation: u64::MAX,
            records: BTreeMap::new(),
        };
        let before = snapshot.clone();
        assert!(matches!(
            snapshot.mint_generation(),
            Err(JournalError::Capacity)
        ));
        assert_eq!(snapshot, before);
    }

    struct FakeRecoveryExecutor {
        exact: bool,
        calls: usize,
    }

    impl CleanupExecutor for FakeRecoveryExecutor {
        type Error = ();

        fn confirm_cleanup(
            &mut self,
            target: &CleanupTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedCleanupProof, Self::Error> {
            self.calls += 1;
            let mut proof = target.confirmed_cleanup();
            if !self.exact {
                proof.exact_record.context_id = id16(99);
            }
            Ok(proof)
        }
    }

    impl ManagerAbsenceExecutor for FakeRecoveryExecutor {
        type Error = ();

        fn confirm_manager_absent(
            &mut self,
            target: &ManagerAbsenceTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
            self.calls += 1;
            let mut proof = target.confirmed_manager_absent();
            if !self.exact {
                proof.exact_record.context_id = id16(99);
            }
            Ok(proof)
        }
    }

    struct ErrorRecoveryExecutor;

    impl CleanupExecutor for ErrorRecoveryExecutor {
        type Error = &'static str;

        fn confirm_cleanup(
            &mut self,
            _target: &CleanupTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedCleanupProof, Self::Error> {
            Err("injected recovery failure")
        }
    }

    impl ManagerAbsenceExecutor for ErrorRecoveryExecutor {
        type Error = &'static str;

        fn confirm_manager_absent(
            &mut self,
            _target: &ManagerAbsenceTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
            Err("injected recovery failure")
        }
    }

    struct ExpiringRecoveryExecutor {
        calls: usize,
        observed_deadline: Option<HardDeadline>,
    }

    impl CleanupExecutor for ExpiringRecoveryExecutor {
        type Error = ();

        fn confirm_cleanup(
            &mut self,
            target: &CleanupTarget,
            deadline: HardDeadline,
        ) -> Result<ConfirmedCleanupProof, Self::Error> {
            self.calls += 1;
            self.observed_deadline = Some(deadline);
            while let Ok(remaining) = deadline.remaining() {
                thread::sleep(remaining.min(Duration::from_millis(2)));
            }
            Ok(target.confirmed_cleanup())
        }
    }

    impl ManagerAbsenceExecutor for ExpiringRecoveryExecutor {
        type Error = ();

        fn confirm_manager_absent(
            &mut self,
            target: &ManagerAbsenceTarget,
            deadline: HardDeadline,
        ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
            self.calls += 1;
            self.observed_deadline = Some(deadline);
            while let Ok(remaining) = deadline.remaining() {
                thread::sleep(remaining.min(Duration::from_millis(2)));
            }
            Ok(target.confirmed_manager_absent())
        }
    }

    struct FailingObserver {
        steps: Vec<PersistStep>,
    }

    impl PersistObserver for FailingObserver {
        fn observe(&mut self, step: PersistStep) -> io::Result<()> {
            if self.steps.contains(&step) {
                Err(io::Error::other("injected persistence failure"))
            } else {
                Ok(())
            }
        }
    }

    struct ExpireBeforeCreateObserver {
        deadline: HardDeadline,
        steps: Vec<PersistStep>,
    }

    impl PersistObserver for ExpireBeforeCreateObserver {
        fn observe(&mut self, step: PersistStep) -> io::Result<()> {
            self.steps.push(step);
            if step == PersistStep::BeforeCreate {
                while let Ok(remaining) = self.deadline.remaining() {
                    thread::sleep(remaining.min(Duration::from_millis(2)));
                }
            }
            Ok(())
        }
    }

    fn next_with_binding(
        journal: &OwnershipJournal,
        inserted: InsertedOwnership,
        reconcile: ReconcileBinding,
    ) -> JournalSnapshot {
        let mut next = journal.snapshot().expect("usable journal").clone();
        next.records
            .get_mut(&inserted.ownership_id)
            .expect("inserted record")
            .reconcile = Some(reconcile);
        next
    }

    fn assert_retry_healthcheck_poisoned(journal: &mut OwnershipJournal) {
        assert!(matches!(
            journal.confirm_retry_safe_after_definite_failure(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        assert!(matches!(
            journal.confirm_retry_safe_after_definite_failure(),
            Err(JournalError::Poisoned)
        ));
    }

    #[test]
    fn secure_metadata_runtime_lock_and_stale_next_are_enforced() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        fs::write(&config.next_path, b"stale next").expect("stale next fixture");
        fs::set_permissions(
            &config.next_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("secure stale next mode");

        let mut first = OwnershipJournal::open(config.clone()).expect("first runtime lock");
        first
            .insert_intent(0, intent(2, 3))
            .expect("journal metadata fixture");
        assert!(!config.next_path.exists());
        let lock_metadata = fs::metadata(&config.lock_path).expect("lock metadata");
        assert_eq!(lock_metadata.mode() & 0o7777, JOURNAL_FILE_MODE);
        assert_eq!(lock_metadata.nlink(), 1);
        let journal_metadata = fs::metadata(&config.journal_path).expect("journal metadata");
        assert_eq!(journal_metadata.mode() & 0o7777, JOURNAL_FILE_MODE);
        assert_eq!(journal_metadata.uid(), config.expected_owner_uid);
        assert_eq!(journal_metadata.gid(), config.expected_owner_gid);
        assert_eq!(journal_metadata.nlink(), 1);
        assert!(matches!(
            OwnershipJournal::open(config.clone()),
            Err(JournalError::LockHeld)
        ));
        drop(first);
        drop(OwnershipJournal::open(config).expect("lock released with descriptor drop"));

        let unsafe_directory = tempdir().expect("unsafe fixture directory");
        let unsafe_config = test_config(unsafe_directory.path());
        symlink("missing", &unsafe_config.next_path).expect("next symlink fixture");
        assert!(matches!(
            OwnershipJournal::open(unsafe_config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(&unsafe_config.next_path)
                .expect("unsafe next remains")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn insecure_or_hardlinked_lock_is_rejected_without_repair() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        fs::write(&config.lock_path, b"lock").expect("lock fixture");
        fs::set_permissions(&config.lock_path, fs::Permissions::from_mode(0o640))
            .expect("insecure mode fixture");
        assert!(matches!(
            OwnershipJournal::open(config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert_eq!(
            fs::metadata(&config.lock_path)
                .expect("lock remains")
                .mode()
                & 0o7777,
            0o640
        );

        fs::set_permissions(
            &config.lock_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("secure mode for hardlink fixture");
        fs::hard_link(&config.lock_path, directory.path().join("alias")).expect("hardlink fixture");
        assert!(matches!(
            OwnershipJournal::open(config),
            Err(JournalError::UnsafeMetadata)
        ));
    }

    #[test]
    fn intent_restart_absence_and_late_exact_reconcile_binding_are_durable() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        assert_eq!(inserted.revision, 1);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let absent_revision = journal
            .mark_intent_absent(1, inserted.ownership_id, inserted.generation)
            .expect("never-dispatched intent is absent");
        assert_eq!(absent_revision, 2);
        let exact = binding(4);
        let bound_revision = journal
            .bind_reconcile(2, inserted.ownership_id, inserted.generation, exact)
            .expect("late exact binding on tombstone");
        assert_eq!(bound_revision, 3);
        assert_eq!(
            journal
                .bind_reconcile(3, inserted.ownership_id, inserted.generation, exact)
                .expect("idempotent exact binding"),
            3
        );
        let before = fs::read(&config.journal_path).expect("durable bytes before conflict");
        assert!(matches!(
            journal.bind_reconcile(3, inserted.ownership_id, inserted.generation, binding(5)),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("durable bytes after conflict"),
            before
        );
    }

    #[test]
    fn lost_insert_reply_restarts_to_the_same_exact_ownership_identity() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_intent = intent(2, 3);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, exact_intent.clone())
            .expect("durable insert whose reply is discarded");
        let marker_before_restart = marker_aliases(
            journal
                .snapshot()
                .expect("inserted snapshot")
                .records
                .values()
                .next()
                .expect("inserted record"),
        );
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let existing = journal
            .snapshot()
            .expect("usable restarted snapshot")
            .records
            .values()
            .next()
            .expect("durable ownership")
            .clone();
        assert_eq!(marker_aliases(&existing), marker_before_restart);
        let before = fs::read(&config.journal_path).expect("durable insert bytes");
        for wrong_revision in [0, 2] {
            assert!(matches!(
                journal.insert_intent(wrong_revision, exact_intent.clone()),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale insert retry"),
            before
        );
        let retried = journal
            .insert_intent(1, exact_intent.clone())
            .expect("exact retry at the current revision");
        assert_eq!(retried.ownership_id, existing.ownership_id);
        assert_eq!(retried.generation, existing.generation);
        assert_eq!(retried.revision, 1);
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact retry"),
            before
        );

        let mut conflicts = Vec::new();
        let mut changed = exact_intent.clone();
        changed.ownership_id = ownership(99);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.origin_runtime_id = runtime(9);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.context_id = id16(4);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.prepare_request_id = id16(5);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.prepare_operation_digest = [1; DIGEST_BYTES];
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.setup_expires_at_unix = nz(101);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.hard_expires_at_unix = nz(201);
        conflicts.push(changed);
        let mut changed = exact_intent;
        changed.plan = client_plan(&[1]);
        conflicts.push(changed);

        for conflict in conflicts {
            assert!(matches!(
                journal.insert_intent(1, conflict),
                Err(JournalError::InvalidRecord)
            ));
            assert_eq!(
                fs::read(&config.journal_path).expect("bytes after conflicting retry"),
                before
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Both lost custody replies and exact restart retries form one proof.
    fn lost_custody_and_arm_replies_restart_to_exact_idempotent_success() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_anchor = anchor(7);
        let exact_binding = custody_binding(exact_anchor, 7);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let first_custody = journal
            .mark_may_own_custody(
                1,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                exact_binding,
                recovery_deadline(),
            )
            .expect("durable custody mark whose reply is discarded");
        assert_eq!(first_custody.revision, 2);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart after custody");
        let custody_bytes = fs::read(&config.journal_path).expect("durable custody bytes");
        let retried_custody = journal
            .mark_may_own_custody(
                2,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                exact_binding,
                recovery_deadline(),
            )
            .expect("exact custody retry at current revision");
        assert_eq!(retried_custody.revision, 2);
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact custody retry"),
            custody_bytes
        );
        assert!(matches!(
            journal.mark_intent_absent(2, inserted.ownership_id, inserted.generation),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("phase 4 cannot be retired"),
            custody_bytes
        );
        assert!(matches!(
            journal.mark_may_own_custody(
                2,
                inserted.ownership_id,
                inserted.generation,
                anchor(8),
                custody_binding(anchor(8), 8),
                recovery_deadline(),
            ),
            Err(JournalError::InvalidTransition)
        ));
        let first_projection = journal
            .mark_may_own_prepare_from_custody(
                2,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
            )
            .expect("durable arm whose reply is discarded");
        let first_aliases = first_projection
            .resources
            .iter()
            .map(|resource| resource.ownership_alias().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(first_projection.revision, 3);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before = fs::read(&config.journal_path).expect("durable arm bytes");
        for wrong_revision in [2, 4] {
            assert!(matches!(
                journal.mark_may_own_prepare_from_custody(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                    recovery_deadline(),
                ),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale arm retry"),
            before
        );
        let retried = journal
            .mark_may_own_prepare_from_custody(
                3,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
            )
            .expect("exact arm retry at the current revision");
        assert_eq!(retried.revision, 3);
        assert_eq!(
            retried
                .resources
                .iter()
                .map(|resource| resource.ownership_alias().to_owned())
                .collect::<Vec<_>>(),
            first_aliases,
            "an exact durable retry must return the identical ordered resource projection"
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact arm retry"),
            before
        );
        assert!(matches!(
            journal.mark_may_own_custody(
                3,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                exact_binding,
                recovery_deadline(),
            ),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    fn custody_transition_deadlines_expire_before_next_file_creation() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let exact_anchor = anchor(7);
        let exact_binding = custody_binding(exact_anchor, 7);
        let intent_snapshot = journal.snapshot().expect("intent snapshot").clone();
        let intent_bytes = fs::read(&config.journal_path).expect("intent bytes");
        let mark_deadline = HardDeadline::after(Duration::from_millis(30)).expect("mark deadline");
        let mut mark_observer = ExpireBeforeCreateObserver {
            deadline: mark_deadline,
            steps: Vec::new(),
        };
        assert!(matches!(
            journal.mark_may_own_custody_observed(
                1,
                inserted.ownership_id,
                inserted.generation,
                PrepareRecoveryEvidenceV1::custody_bound(exact_anchor, exact_binding)
                    .expect("deadline custody evidence"),
                mark_deadline,
                &mut mark_observer,
            ),
            Err(JournalError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(mark_observer.steps, vec![PersistStep::BeforeCreate]);
        assert_eq!(
            journal.snapshot().expect("intent remains"),
            &intent_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("intent bytes remain"),
            intent_bytes
        );
        assert!(!config.next_path.exists());
        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("mark timeout is retry-safe");

        let custody_revision = journal
            .mark_may_own_custody(
                1,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                exact_binding,
                recovery_deadline(),
            )
            .expect("durable custody retry")
            .revision;
        let custody_snapshot = journal.snapshot().expect("custody snapshot").clone();
        let custody_bytes = fs::read(&config.journal_path).expect("custody bytes");
        let arm_deadline = HardDeadline::after(Duration::from_millis(30)).expect("arm deadline");
        let mut arm_observer = ExpireBeforeCreateObserver {
            deadline: arm_deadline,
            steps: Vec::new(),
        };
        assert!(matches!(
            journal.mark_may_own_prepare_from_custody_observed(
                custody_revision,
                inserted.ownership_id,
                inserted.generation,
                arm_deadline,
                &mut arm_observer,
            ),
            Err(JournalError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(arm_observer.steps, vec![PersistStep::BeforeCreate]);
        assert_eq!(
            journal.snapshot().expect("custody remains"),
            &custody_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("custody bytes remain"),
            custody_bytes
        );
        assert!(!config.next_path.exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Cover both chained durable transitions at both rename boundaries.
    fn custody_transition_failpoints_preserve_or_poison_exactly() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let exact_anchor = anchor(7);
        let exact_binding = custody_binding(exact_anchor, 7);
        let exact_evidence = PrepareRecoveryEvidenceV1::custody_bound(exact_anchor, exact_binding)
            .expect("exact custody evidence");
        let before = journal.snapshot().expect("intent snapshot").clone();
        let bytes = fs::read(&config.journal_path).expect("intent bytes");
        let mut pre_rename = FailingObserver {
            steps: vec![PersistStep::BeforeRename],
        };
        assert!(matches!(
            journal.mark_may_own_custody_observed(
                1,
                inserted.ownership_id,
                inserted.generation,
                exact_evidence,
                recovery_deadline(),
                &mut pre_rename,
            ),
            Err(JournalError::Io(_))
        ));
        assert_eq!(journal.snapshot().expect("retryable Intent"), &before);
        assert_eq!(fs::read(&config.journal_path).expect("intent bytes"), bytes);
        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("clean failpoint is retry-safe");

        let mut post_rename = FailingObserver {
            steps: vec![PersistStep::AfterRename],
        };
        assert!(matches!(
            journal.mark_may_own_custody_observed(
                1,
                inserted.ownership_id,
                inserted.generation,
                exact_evidence,
                recovery_deadline(),
                &mut post_rename,
            ),
            Err(JournalError::PersistUncertain)
        ));
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        drop(journal);
        let mut journal = OwnershipJournal::open(config.clone())
            .expect("restart after ambiguous custody-mark reply");
        assert_eq!(
            journal
                .snapshot()
                .expect("durable custody snapshot")
                .records
                .get(&inserted.ownership_id)
                .expect("custody record")
                .phase,
            OwnershipPhase::MayOwnCustody
        );

        let before_arm = journal
            .snapshot()
            .expect("custody snapshot before arm")
            .clone();
        let custody_bytes = fs::read(&config.journal_path).expect("custody bytes before arm");
        let mut arm_pre_rename = FailingObserver {
            steps: vec![PersistStep::BeforeRename],
        };
        assert!(matches!(
            journal.mark_may_own_prepare_from_custody_observed(
                before_arm.revision,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
                &mut arm_pre_rename,
            ),
            Err(JournalError::Io(_))
        ));
        assert_eq!(
            journal.snapshot().expect("retryable custody snapshot"),
            &before_arm
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("retryable custody bytes"),
            custody_bytes
        );
        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("clean arm failpoint is retry-safe");

        let mut arm_post_rename = FailingObserver {
            steps: vec![PersistStep::AfterRename],
        };
        assert!(matches!(
            journal.mark_may_own_prepare_from_custody_observed(
                before_arm.revision,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
                &mut arm_post_rename,
            ),
            Err(JournalError::PersistUncertain)
        ));
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        drop(journal);
        assert_eq!(
            OwnershipJournal::open(config)
                .expect("restart after ambiguous custody-arm reply")
                .snapshot()
                .expect("durable MayOwnPrepare snapshot")
                .records
                .get(&inserted.ownership_id)
                .expect("MayOwnPrepare record")
                .phase,
            OwnershipPhase::MayOwnPrepare
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Audit both proof boundaries at both rename crash windows.
    fn settlement_transition_failpoints_preserve_or_poison_each_phase_exactly() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        mark_and_arm_custody_fixture(&mut journal, 1, inserted, anchor(7));

        let may_own_snapshot = journal.snapshot().expect("MayOwn snapshot").clone();
        let may_own_bytes = fs::read(&config.journal_path).expect("MayOwn bytes");
        let mut cleanup_pre_rename = FailingObserver {
            steps: vec![PersistStep::BeforeRename],
        };
        let mut cleanup_executor = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert!(matches!(
            journal.confirm_cleanup_observed(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut cleanup_executor,
                recovery_deadline(),
                &mut cleanup_pre_rename,
            ),
            Err(SettlementAttemptError::Journal(JournalError::Io(_)))
        ));
        assert_eq!(cleanup_executor.calls, 1);
        assert_eq!(
            journal.snapshot().expect("retryable MayOwn snapshot"),
            &may_own_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("retryable MayOwn bytes"),
            may_own_bytes
        );
        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("pre-rename cleanup failure is retry-safe");

        let mut cleanup_post_rename = FailingObserver {
            steps: vec![PersistStep::AfterRename],
        };
        assert!(matches!(
            journal.confirm_cleanup_observed(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut cleanup_executor,
                recovery_deadline(),
                &mut cleanup_post_rename,
            ),
            Err(SettlementAttemptError::Journal(
                JournalError::PersistUncertain
            ))
        ));
        assert_eq!(cleanup_executor.calls, 2);
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone())
            .expect("restart after ambiguous cleanup confirmation");
        let cleanup_snapshot = journal
            .snapshot()
            .expect("durable CleanupConfirmed snapshot")
            .clone();
        let cleanup_record = cleanup_snapshot
            .records
            .get(&inserted.ownership_id)
            .expect("CleanupConfirmed record");
        assert_eq!(cleanup_snapshot.revision, 4);
        assert_eq!(cleanup_record.phase, OwnershipPhase::CleanupConfirmed);
        assert_eq!(cleanup_record.absent_origin, None);
        assert!(matches!(
            cleanup_record.recovery_evidence,
            Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
        ));
        let cleanup_bytes = fs::read(&config.journal_path).expect("CleanupConfirmed bytes");

        let mut manager_pre_rename = FailingObserver {
            steps: vec![PersistStep::BeforeRename],
        };
        let mut manager_executor = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert!(matches!(
            journal.confirm_manager_absent_observed(
                4,
                inserted.ownership_id,
                inserted.generation,
                &mut manager_executor,
                recovery_deadline(),
                &mut manager_pre_rename,
            ),
            Err(SettlementAttemptError::Journal(JournalError::Io(_)))
        ));
        assert_eq!(manager_executor.calls, 1);
        assert_eq!(
            journal
                .snapshot()
                .expect("retryable CleanupConfirmed snapshot"),
            &cleanup_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("retryable CleanupConfirmed bytes"),
            cleanup_bytes
        );
        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("pre-rename manager failure is retry-safe");

        let mut manager_post_rename = FailingObserver {
            steps: vec![PersistStep::AfterRename],
        };
        assert!(matches!(
            journal.confirm_manager_absent_observed(
                4,
                inserted.ownership_id,
                inserted.generation,
                &mut manager_executor,
                recovery_deadline(),
                &mut manager_post_rename,
            ),
            Err(SettlementAttemptError::Journal(
                JournalError::PersistUncertain
            ))
        ));
        assert_eq!(manager_executor.calls, 2);
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        drop(journal);

        let journal = OwnershipJournal::open(config)
            .expect("restart after ambiguous manager-absence confirmation");
        let absent = journal
            .snapshot()
            .expect("durable Absent snapshot")
            .records
            .get(&inserted.ownership_id)
            .expect("RecoveredMayOwn tombstone");
        assert_eq!(absent.phase, OwnershipPhase::Absent);
        assert_eq!(absent.absent_origin, Some(AbsentOrigin::RecoveredMayOwn));
        assert!(absent.recovery_evidence.is_none());
    }

    #[test]
    fn interposed_transitions_are_never_misreported_as_insert_or_arm_retries() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_intent = intent(2, 3);
        let exact_anchor = anchor(7);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, exact_intent.clone())
            .expect("durable intent");
        mark_and_arm_custody_fixture(&mut journal, 1, inserted, exact_anchor);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart after arm");
        let before_insert_retry =
            fs::read(&config.journal_path).expect("durable armed journal bytes");
        let revision_before_insert_retry =
            journal.snapshot().expect("usable armed snapshot").revision;
        assert_eq!(revision_before_insert_retry, 3);
        assert!(matches!(
            journal.insert_intent(3, exact_intent),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("insert retry leaves snapshot usable")
                .revision,
            revision_before_insert_retry
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after interposed insert retry"),
            before_insert_retry
        );

        journal
            .bind_reconcile(3, inserted.ownership_id, inserted.generation, binding(4))
            .expect("interposed reconcile binding");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart after binding");
        let before_arm_retry = fs::read(&config.journal_path).expect("durable bound journal bytes");
        let revision_before_arm_retry = journal.snapshot().expect("usable bound snapshot").revision;
        assert_eq!(revision_before_arm_retry, 4);
        assert!(matches!(
            journal.mark_may_own_prepare_from_custody(
                4,
                inserted.ownership_id,
                inserted.generation,
                recovery_deadline(),
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("arm retry leaves snapshot usable")
                .revision,
            revision_before_arm_retry
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after interposed arm retry"),
            before_arm_retry
        );

        let bound_intent_directory = tempdir().expect("bound Intent temporary directory");
        let bound_intent_config = test_config(bound_intent_directory.path());
        let bound_intent = intent(5, 6);
        let mut journal =
            OwnershipJournal::open(bound_intent_config.clone()).expect("new bound-Intent journal");
        let inserted = journal
            .insert_intent(0, bound_intent.clone())
            .expect("durable bound-Intent fixture");
        journal
            .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(7))
            .expect("interposed Intent reconcile binding");
        drop(journal);

        let mut journal = OwnershipJournal::open(bound_intent_config.clone())
            .expect("restart after Intent binding");
        let before_bound_insert_retry =
            fs::read(&bound_intent_config.journal_path).expect("durable bound-Intent bytes");
        assert_eq!(
            journal
                .snapshot()
                .expect("usable bound-Intent snapshot")
                .revision,
            2
        );
        assert!(matches!(
            journal.insert_intent(2, bound_intent),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("bound insert retry leaves snapshot usable")
                .revision,
            2
        );
        assert_eq!(
            fs::read(&bound_intent_config.journal_path).expect("bytes after bound insert retry"),
            before_bound_insert_retry
        );
    }

    #[test]
    fn lost_never_dispatched_reply_restarts_to_exact_absent_success() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .mark_intent_absent(1, inserted.ownership_id, inserted.generation)
            .expect("durable retirement whose reply is discarded");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before = fs::read(&config.journal_path).expect("durable absent bytes");
        for wrong_revision in [1, 3] {
            assert!(matches!(
                journal.mark_intent_absent(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                ),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale absent retry"),
            before
        );
        assert_eq!(
            journal
                .mark_intent_absent(2, inserted.ownership_id, inserted.generation)
                .expect("exact absent retry at the current revision"),
            2
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact absent retry"),
            before
        );
        assert!(matches!(
            journal.confirm_cleanup(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut PanicIfRecoveryRuns,
                recovery_deadline(),
            ),
            Err(SettlementAttemptError::Journal(
                JournalError::InvalidTransition
            ))
        ));
    }

    struct PanicIfRecoveryRuns;

    impl CleanupExecutor for PanicIfRecoveryRuns {
        type Error = ();

        fn confirm_cleanup(
            &mut self,
            _target: &CleanupTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedCleanupProof, Self::Error> {
            panic!("an already-CleanupConfirmed retry must not run cleanup again")
        }
    }

    impl ManagerAbsenceExecutor for PanicIfRecoveryRuns {
        type Error = ();

        fn confirm_manager_absent(
            &mut self,
            _target: &ManagerAbsenceTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
            panic!("an already-Absent retry must not observe manager absence again")
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exercise both lost-reply retries and stale revisions inline.
    fn lost_replies_retry_both_settlement_phases_without_rerunning_executors() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        mark_and_arm_custody_fixture(&mut journal, 1, inserted, anchor(7));
        journal
            .confirm_cleanup(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut FakeRecoveryExecutor {
                    exact: true,
                    calls: 0,
                },
                recovery_deadline(),
            )
            .expect("durable cleanup confirmation whose reply is discarded");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before_cleanup_retry =
            fs::read(&config.journal_path).expect("durable CleanupConfirmed bytes");
        for wrong_revision in [3, 5] {
            assert!(matches!(
                journal.confirm_cleanup(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                ),
                Err(SettlementAttemptError::Journal(
                    JournalError::RevisionConflict
                ))
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale cleanup retry"),
            before_cleanup_retry
        );
        assert_eq!(
            journal
                .confirm_cleanup(
                    4,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                )
                .expect("exact cleanup retry at current revision skips executor"),
            4
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact cleanup retry"),
            before_cleanup_retry
        );
        journal
            .confirm_manager_absent(
                4,
                inserted.ownership_id,
                inserted.generation,
                &mut FakeRecoveryExecutor {
                    exact: true,
                    calls: 0,
                },
                recovery_deadline(),
            )
            .expect("durable manager-absence confirmation whose reply is discarded");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("second restart journal");
        let before_absent_retry = fs::read(&config.journal_path).expect("durable Absent bytes");
        for wrong_revision in [4, 6] {
            assert!(matches!(
                journal.confirm_manager_absent(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                ),
                Err(SettlementAttemptError::Journal(
                    JournalError::RevisionConflict
                ))
            ));
        }
        assert_eq!(
            journal
                .confirm_manager_absent(
                    5,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                )
                .expect("exact Absent retry skips manager observer"),
            5
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact Absent retry"),
            before_absent_retry
        );
        assert!(matches!(
            journal.mark_intent_absent(5, inserted.ownership_id, inserted.generation),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep both exact proof/mismatch boundaries in one audit.
    fn both_settlement_phases_require_distinct_exact_proofs_and_cannot_be_bypassed() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let may_own_revision =
            mark_and_arm_custody_fixture(&mut journal, 1, inserted, anchor(7)).revision;
        assert_eq!(may_own_revision, 3);
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");

        let mut stale = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert!(matches!(
            confirm_cleanup_fixture(&mut journal, 1, inserted, &mut stale),
            Err(SettlementAttemptError::Journal(
                JournalError::RevisionConflict
            ))
        ));
        assert_eq!(stale.calls, 0);
        assert_eq!(
            journal.snapshot().expect("stale recovery is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("stale recovery leaves bytes unchanged"),
            before_bytes
        );

        assert!(matches!(
            journal.mark_intent_absent(3, inserted.ownership_id, inserted.generation),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(journal.snapshot().expect("still usable"), &before_snapshot);
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before_bytes
        );

        let mut wrong = FakeRecoveryExecutor {
            exact: false,
            calls: 0,
        };
        assert!(matches!(
            confirm_cleanup_fixture(&mut journal, 3, inserted, &mut wrong),
            Err(SettlementAttemptError::Journal(JournalError::ProofMismatch))
        ));
        assert_eq!(wrong.calls, 1);
        assert_eq!(journal.snapshot().expect("still usable"), &before_snapshot);
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before_bytes
        );

        assert!(matches!(
            confirm_cleanup_fixture(&mut journal, 3, inserted, &mut ErrorRecoveryExecutor),
            Err(SettlementAttemptError::Executor(
                "injected recovery failure"
            ))
        ));
        assert_eq!(
            journal.snapshot().expect("executor error is retryable"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("executor error leaves bytes unchanged"),
            before_bytes
        );

        let mut exact = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert_eq!(
            confirm_cleanup_fixture(&mut journal, 3, inserted, &mut exact)
                .expect("exact cleanup proof"),
            4
        );
        let cleanup_confirmed = journal
            .snapshot()
            .expect("usable cleanup-confirmed journal")
            .records
            .get(&inserted.ownership_id)
            .expect("cleanup-confirmed record");
        assert_eq!(cleanup_confirmed.phase, OwnershipPhase::CleanupConfirmed);
        assert_eq!(cleanup_confirmed.absent_origin, None);
        assert!(matches!(
            cleanup_confirmed.recovery_evidence,
            Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
        ));

        let cleanup_snapshot = journal.snapshot().expect("cleanup snapshot").clone();
        let cleanup_bytes = fs::read(&config.journal_path).expect("cleanup bytes");
        let mut wrong_manager = FakeRecoveryExecutor {
            exact: false,
            calls: 0,
        };
        assert!(matches!(
            confirm_manager_absent_fixture(&mut journal, 4, inserted, &mut wrong_manager),
            Err(SettlementAttemptError::Journal(JournalError::ProofMismatch))
        ));
        assert_eq!(wrong_manager.calls, 1);
        assert_eq!(
            journal.snapshot().expect("manager mismatch inert"),
            &cleanup_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("manager mismatch bytes"),
            cleanup_bytes
        );
        assert!(matches!(
            confirm_manager_absent_fixture(&mut journal, 4, inserted, &mut ErrorRecoveryExecutor,),
            Err(SettlementAttemptError::Executor(
                "injected recovery failure"
            ))
        ));
        assert_eq!(
            journal.snapshot().expect("manager error inert"),
            &cleanup_snapshot
        );

        let mut exact_manager = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert_eq!(
            confirm_manager_absent_fixture(&mut journal, 4, inserted, &mut exact_manager)
                .expect("exact distinct manager-absence proof"),
            5
        );
        let recovered = journal
            .snapshot()
            .expect("usable recovered journal")
            .records
            .get(&inserted.ownership_id)
            .expect("recovered tombstone");
        assert_eq!(recovered.phase, OwnershipPhase::Absent);
        assert_eq!(recovered.absent_origin, Some(AbsentOrigin::RecoveredMayOwn));
        assert!(recovered.recovery_evidence.is_none());
    }

    #[test]
    fn expired_cleanup_and_late_exact_proof_leave_snapshot_and_bytes_unchanged() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        mark_and_arm_custody_fixture(&mut journal, 1, inserted, anchor(7));
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");

        let mut never_started = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        let expired_before_executor =
            HardDeadline::after(Duration::from_millis(1)).expect("short deadline");
        while expired_before_executor.ensure_remaining().is_ok() {
            thread::yield_now();
        }
        assert!(matches!(
            journal.confirm_cleanup(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut never_started,
                expired_before_executor,
            ),
            Err(SettlementAttemptError::Deadline)
        ));
        assert_eq!(never_started.calls, 0);
        assert_eq!(
            journal.snapshot().expect("expired recovery is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after pre-executor expiry"),
            before_bytes
        );

        let deadline =
            HardDeadline::after(Duration::from_millis(100)).expect("blocking executor deadline");
        let mut blocked = ExpiringRecoveryExecutor {
            calls: 0,
            observed_deadline: None,
        };
        assert!(matches!(
            journal.confirm_cleanup(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut blocked,
                deadline,
            ),
            Err(SettlementAttemptError::Deadline)
        ));
        assert_eq!(blocked.calls, 1);
        assert_eq!(blocked.observed_deadline, Some(deadline));
        assert_eq!(
            journal.snapshot().expect("late proof is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after late exact proof"),
            before_bytes
        );
    }

    #[test]
    fn cleanup_expiry_after_encoding_stops_before_creating_the_next_file() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        mark_and_arm_custody_fixture(&mut journal, 1, inserted, anchor(7));
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");
        let deadline =
            HardDeadline::after(Duration::from_millis(30)).expect("persist boundary deadline");
        let mut observer = ExpireBeforeCreateObserver {
            deadline,
            steps: Vec::new(),
        };
        let mut exact = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };

        assert!(matches!(
            journal.confirm_cleanup_observed(
                3,
                inserted.ownership_id,
                inserted.generation,
                &mut exact,
                deadline,
                &mut observer,
            ),
            Err(SettlementAttemptError::Deadline)
        ));
        assert_eq!(exact.calls, 1);
        assert_eq!(observer.steps, vec![PersistStep::BeforeCreate]);
        assert_eq!(
            journal.snapshot().expect("persist expiry is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after persist-boundary expiry"),
            before_bytes
        );
        assert!(!config.next_path.exists());
    }

    #[test]
    fn reconcile_bound_intent_can_retire_but_can_never_be_dispatched_later() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(4))
            .expect("durable reconcile lineage");
        let before = journal.snapshot().expect("usable snapshot").clone();
        let exact_anchor = anchor(7);
        assert!(matches!(
            journal.mark_may_own_custody(
                2,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
                custody_binding(exact_anchor, 7),
                recovery_deadline(),
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(journal.snapshot().expect("unchanged snapshot"), &before);
        assert_eq!(
            journal
                .mark_intent_absent(2, inserted.ownership_id, inserted.generation)
                .expect("retirement-only transition"),
            3
        );
    }

    #[test]
    fn pre_rename_failpoints_preserve_authoritative_state_and_durable_bytes() {
        for step in [
            PersistStep::BeforeCreate,
            PersistStep::AfterCreate,
            PersistStep::AfterWrite,
            PersistStep::AfterFileSync,
            PersistStep::BeforeRename,
        ] {
            let directory = tempdir().expect("temporary directory");
            let config = test_config(directory.path());
            let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
            let inserted = journal
                .insert_intent(0, intent(2, 3))
                .expect("durable intent");
            let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
            let before_bytes = fs::read(&config.journal_path).expect("durable bytes");
            let next = next_with_binding(&journal, inserted, binding(4));
            let mut observer = FailingObserver { steps: vec![step] };
            assert!(matches!(
                journal.compare_and_swap_observed(1, next, &mut observer),
                Err(JournalError::Io(_))
            ));
            assert_eq!(
                journal.snapshot().expect("retryable journal"),
                &before_snapshot
            );
            assert_eq!(
                fs::read(&config.journal_path).expect("unchanged journal bytes"),
                before_bytes
            );
            assert!(!config.next_path.exists());
        }
    }

    #[test]
    fn clean_pre_rename_failure_is_confirmed_retry_safe_and_retry_writes_once() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let before = fs::read(&config.journal_path).expect("durable bytes before failure");
        let next = next_with_binding(&journal, inserted, binding(4));
        let mut observer = FailingObserver {
            steps: vec![PersistStep::AfterWrite],
        };
        assert!(matches!(
            journal.compare_and_swap_observed(1, next, &mut observer),
            Err(JournalError::Io(_))
        ));

        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("complete authority boundary remains retry-safe");
        assert_eq!(
            journal
                .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(4))
                .expect("single retry commits"),
            2
        );
        let committed = fs::read(&config.journal_path).expect("committed retry bytes");
        assert_ne!(committed, before);
        assert_eq!(
            journal
                .bind_reconcile(2, inserted.ownership_id, inserted.generation, binding(4))
                .expect("exact retry is read-only"),
            2
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact retry"),
            committed
        );
        assert!(!config.next_path.exists());
    }

    #[test]
    fn retry_healthcheck_rejects_next_entry_without_removing_it_and_poison_is_sticky() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        fs::write(&config.next_path, b"foreign next entry").expect("next fixture");
        fs::set_permissions(
            &config.next_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("next fixture mode");

        assert_retry_healthcheck_poisoned(&mut journal);
        assert_eq!(
            fs::read(&config.next_path).expect("healthcheck leaves next untouched"),
            b"foreign next entry"
        );
    }

    #[test]
    fn retry_healthcheck_rejects_parent_substitution_without_creating_entries() {
        let directory = tempdir().expect("temporary directory");
        let parent = directory.path().join("runtime");
        let moved_parent = directory.path().join("retained-runtime");
        fs::create_dir(&parent).expect("runtime parent");
        let config = test_config(&parent);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        fs::rename(&parent, &moved_parent).expect("move retained parent");
        fs::create_dir(&parent).expect("substituted parent");
        fs::set_permissions(
            &parent,
            fs::Permissions::from_mode(config.expected_parent_mode),
        )
        .expect("substituted parent mode");

        assert_retry_healthcheck_poisoned(&mut journal);
        assert_eq!(
            fs::read_dir(&parent)
                .expect("substituted parent remains readable")
                .count(),
            0
        );
        assert!(moved_parent.join("helper.ownership-v3").exists());
        assert!(moved_parent.join("helper.ownership-v3.lock").exists());
    }

    #[test]
    fn retry_healthcheck_rejects_lock_substitution_or_lost_exclusive_lock() {
        let substituted_directory = tempdir().expect("substitution directory");
        let substituted_config = test_config(substituted_directory.path());
        let mut substituted =
            OwnershipJournal::open(substituted_config.clone()).expect("new journal");
        let retained_lock = substituted_directory.path().join("retained-lock");
        fs::rename(&substituted_config.lock_path, &retained_lock)
            .expect("move retained lock entry");
        fs::write(&substituted_config.lock_path, b"").expect("replacement lock entry");
        fs::set_permissions(
            &substituted_config.lock_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("replacement lock mode");

        assert_retry_healthcheck_poisoned(&mut substituted);
        assert!(retained_lock.exists());
        assert!(substituted_config.lock_path.exists());

        let unlocked_directory = tempdir().expect("unlocked directory");
        let unlocked_config = test_config(unlocked_directory.path());
        let mut unlocked = OwnershipJournal::open(unlocked_config).expect("new journal");
        flock(&unlocked.runtime_lock, FlockOperation::Unlock).expect("release fixture lock");
        assert_retry_healthcheck_poisoned(&mut unlocked);
    }

    #[test]
    fn retry_healthcheck_rejects_main_substitution_or_readability_loss_without_repair() {
        let substituted_directory = tempdir().expect("substitution directory");
        let substituted_config = test_config(substituted_directory.path());
        let mut substituted =
            OwnershipJournal::open(substituted_config.clone()).expect("new journal");
        substituted
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let mut replacement = substituted.snapshot().expect("snapshot").clone();
        replacement.revision = 2;
        let replacement_path = substituted_directory.path().join("replacement-main");
        let replacement_bytes = replacement.encode().expect("replacement encoding");
        fs::write(&replacement_path, &replacement_bytes).expect("replacement main");
        fs::set_permissions(
            &replacement_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("replacement main mode");
        fs::rename(&replacement_path, &substituted_config.journal_path)
            .expect("substitute main entry");

        assert_retry_healthcheck_poisoned(&mut substituted);
        assert_eq!(
            fs::read(&substituted_config.journal_path)
                .expect("healthcheck leaves substituted main untouched"),
            replacement_bytes
        );

        let unreadable_directory = tempdir().expect("unreadable directory");
        let unreadable_config = test_config(unreadable_directory.path());
        let mut unreadable =
            OwnershipJournal::open(unreadable_config.clone()).expect("new journal");
        unreadable
            .insert_intent(0, intent(5, 6))
            .expect("durable intent");
        fs::set_permissions(
            &unreadable_config.journal_path,
            fs::Permissions::from_mode(0o000),
        )
        .expect("remove main readability");

        assert_retry_healthcheck_poisoned(&mut unreadable);
        assert_eq!(
            fs::metadata(&unreadable_config.journal_path)
                .expect("unreadable main remains")
                .mode()
                & 0o7777,
            0
        );
    }

    #[test]
    fn post_rename_and_cleanup_uncertainty_poison_all_authoritative_access() {
        for steps in [
            vec![PersistStep::AfterRename],
            vec![PersistStep::AfterDirectorySync],
            vec![PersistStep::AfterWrite, PersistStep::BeforeCleanupUnlink],
            vec![
                PersistStep::AfterWrite,
                PersistStep::BeforeCleanupDirectorySync,
            ],
        ] {
            let directory = tempdir().expect("temporary directory");
            let config = test_config(directory.path());
            let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
            let inserted = journal
                .insert_intent(0, intent(2, 3))
                .expect("durable intent");
            let next = next_with_binding(&journal, inserted, binding(4));
            let expected_after_restart = if steps.contains(&PersistStep::AfterRename)
                || steps.contains(&PersistStep::AfterDirectorySync)
            {
                let mut committed = next.clone();
                committed.revision = 2;
                committed
            } else {
                journal.snapshot().expect("old complete snapshot").clone()
            };
            let mut observer = FailingObserver { steps };
            assert!(matches!(
                journal.compare_and_swap_observed(1, next, &mut observer),
                Err(JournalError::PersistUncertain)
            ));
            assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
            assert!(matches!(
                journal.mark_intent_absent(1, inserted.ownership_id, inserted.generation),
                Err(JournalError::Poisoned)
            ));
            drop(journal);
            let reopened = OwnershipJournal::open(config.clone()).expect("restart after ambiguity");
            assert_eq!(
                reopened.snapshot().expect("complete restarted snapshot"),
                &expected_after_restart
            );
            assert!(!config.next_path.exists());
        }
    }

    #[test]
    fn stale_cas_and_revision_overflow_leave_bytes_and_memory_unchanged() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let before = fs::read(&config.journal_path).expect("durable bytes");
        assert!(matches!(
            journal.bind_reconcile(0, inserted.ownership_id, inserted.generation, binding(4)),
            Err(JournalError::RevisionConflict)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before
        );

        drop(journal);
        let overflow_snapshot = JournalSnapshot {
            journal_epoch_id: epoch(1),
            revision: u64::MAX,
            next_generation: 1,
            records: BTreeMap::new(),
        };
        fs::write(
            &config.journal_path,
            overflow_snapshot
                .encode()
                .expect("overflow fixture encoding"),
        )
        .expect("overflow journal fixture");
        fs::set_permissions(
            &config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("overflow fixture mode");
        let mut journal = OwnershipJournal::open(config.clone()).expect("overflow journal");
        let before = fs::read(&config.journal_path).expect("overflow bytes");
        assert!(matches!(
            journal.insert_intent(u64::MAX, intent(5, 6)),
            Err(JournalError::Capacity)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged overflow bytes"),
            before
        );
        assert_eq!(
            journal.snapshot().expect("usable snapshot"),
            &overflow_snapshot
        );
    }

    #[test]
    fn fifo_entries_fail_closed_with_a_bounded_open_and_no_mutation() {
        let fifo_directory = tempdir().expect("FIFO fixture directory");
        let fifo_config = test_config(fifo_directory.path());
        let fifo_parent = File::open(fifo_directory.path()).expect("FIFO parent descriptor");
        rustix::fs::mkfifoat(
            &fifo_parent,
            "helper.ownership-v3",
            Mode::from_raw_mode(JOURNAL_FILE_MODE),
        )
        .expect("FIFO fixture");
        assert!(matches!(
            open_fifo_with_deadline(fifo_config.clone(), fifo_config.journal_path.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(fifo_directory.path().join("helper.ownership-v3"))
                .expect("FIFO remains")
                .file_type()
                .is_fifo()
        );

        let next_fifo_directory = tempdir().expect("next FIFO fixture directory");
        let next_fifo_config = test_config(next_fifo_directory.path());
        let next_fifo_parent =
            File::open(next_fifo_directory.path()).expect("next FIFO parent descriptor");
        rustix::fs::mkfifoat(
            &next_fifo_parent,
            "helper.ownership-v3.next",
            Mode::from_raw_mode(JOURNAL_FILE_MODE),
        )
        .expect("next FIFO fixture");
        assert!(matches!(
            open_fifo_with_deadline(next_fifo_config.clone(), next_fifo_config.next_path.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(&next_fifo_config.next_path)
                .expect("unsafe next FIFO remains")
                .file_type()
                .is_fifo()
        );
    }

    #[test]
    fn socket_directory_symlink_and_hardlink_journals_fail_closed_without_mutation() {
        let socket_directory = tempdir().expect("socket fixture parent");
        let socket_config = test_config(socket_directory.path());
        let _socket = UnixListener::bind(&socket_config.journal_path).expect("socket fixture");
        assert!(OwnershipJournal::open(socket_config.clone()).is_err());
        assert!(
            fs::symlink_metadata(&socket_config.journal_path)
                .expect("socket remains")
                .file_type()
                .is_socket()
        );

        let directory_fixture = tempdir().expect("directory fixture parent");
        let directory_config = test_config(directory_fixture.path());
        fs::create_dir(&directory_config.journal_path).expect("directory journal fixture");
        assert!(matches!(
            OwnershipJournal::open(directory_config),
            Err(JournalError::UnsafeMetadata)
        ));

        let symlink_directory = tempdir().expect("symlink fixture parent");
        let symlink_config = test_config(symlink_directory.path());
        symlink("missing", &symlink_config.journal_path).expect("journal symlink fixture");
        assert!(matches!(
            OwnershipJournal::open(symlink_config),
            Err(JournalError::UnsafeMetadata)
        ));

        let hardlink_directory = tempdir().expect("hardlink fixture parent");
        let hardlink_config = test_config(hardlink_directory.path());
        fs::write(&hardlink_config.journal_path, b"journal").expect("hardlink journal fixture");
        fs::set_permissions(
            &hardlink_config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("hardlink fixture mode");
        fs::hard_link(
            &hardlink_config.journal_path,
            hardlink_directory.path().join("journal-alias"),
        )
        .expect("journal hardlink fixture");
        assert!(matches!(
            OwnershipJournal::open(hardlink_config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert_eq!(
            fs::metadata(&hardlink_config.journal_path)
                .expect("hardlinked journal remains")
                .nlink(),
            2
        );
    }

    #[test]
    fn oversized_journal_input_is_rejected_before_unbounded_read_or_decode() {
        let oversized_directory = tempdir().expect("oversized fixture parent");
        let oversized_config = test_config(oversized_directory.path());
        fs::write(
            &oversized_config.journal_path,
            vec![0; MAX_JOURNAL_BYTES + 1],
        )
        .expect("oversized journal fixture");
        fs::set_permissions(
            &oversized_config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("oversized fixture mode");
        assert!(matches!(
            OwnershipJournal::open(oversized_config),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn record_count_capacity_is_enforced_before_encoding_allocation_growth() {
        let journal_epoch = epoch(1);
        let template = record(journal_epoch, 1, 2, 3, 1, OwnershipPhase::Intent);
        let mut records = BTreeMap::new();
        for index in 1..=MAX_RECORDS + 1 {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("bounded record index")
                    .to_be_bytes(),
            );
            let ownership_id = OwnershipId::new(bytes).expect("unique ownership fixture");
            let mut entry = template.clone();
            entry.ownership_id = ownership_id;
            records.insert(ownership_id, entry);
        }
        let oversized = JournalSnapshot {
            journal_epoch_id: journal_epoch,
            revision: 1,
            next_generation: 2,
            records,
        };
        assert!(matches!(oversized.validate(), Err(JournalError::Capacity)));
        assert!(matches!(oversized.encode(), Err(JournalError::Capacity)));
    }

    #[test]
    fn production_config_is_consumed_only_by_the_lifecycle_wrapper() {
        let source = include_str!("ownership_journal.rs");
        let production_config = ["JournalConfig", "::production()"].concat();
        assert_eq!(source.matches(&production_config).count(), 2);
        let observer = source
            .find("pub(crate) fn production_functional_journal_is_exactly_settled")
            .expect("read-only production observer");
        let observer_call = source[observer..]
            .find(&production_config)
            .map(|offset| observer + offset)
            .expect("observer production config call");
        let wrapper = source
            .find("impl ProductionOwnershipRuntime")
            .expect("production wrapper");
        let wrapper_call = source[wrapper..]
            .find(&production_config)
            .map(|offset| wrapper + offset)
            .expect("lifecycle production config call");
        let executor = source
            .find("struct RefuseMayOwnRecovery")
            .expect("production executor");
        assert!(observer < observer_call && observer_call < wrapper);
        assert!(wrapper < wrapper_call && wrapper_call < executor);
    }

    #[test]
    fn functional_journal_evidence_requires_three_exact_fixed_recovered_tombstones() {
        let journal_epoch = epoch(1);
        let mut client = record(journal_epoch, 1, 2, 3, 1, OwnershipPhase::Absent);
        client.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        client.plan = ClosedPlan::new(
            ContextRole::Client,
            vec![PathPlan {
                path_id: 1,
                role: WireguardRole::Client,
            }],
        )
        .expect("client plan");
        let mut relay = record(journal_epoch, 4, 5, 6, 2, OwnershipPhase::Absent);
        relay.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        relay.plan = ClosedPlan::new(
            ContextRole::Relay,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit,
                },
            ],
        )
        .expect("relay plan");
        let mut exit = record(journal_epoch, 7, 8, 9, 3, OwnershipPhase::Absent);
        exit.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        exit.plan = ClosedPlan::new(
            ContextRole::Exit,
            vec![PathPlan {
                path_id: 1,
                role: WireguardRole::Exit,
            }],
        )
        .expect("exit plan");
        let settled = snapshot_with(vec![client.clone(), relay.clone(), exit.clone()]);
        assert!(functional_snapshot_is_exactly_settled(&settled));

        let mut never_dispatched = client.clone();
        never_dispatched.absent_origin = Some(AbsentOrigin::NeverDispatched);
        assert!(!functional_snapshot_is_exactly_settled(&snapshot_with(
            vec![never_dispatched, relay.clone(), exit.clone(),]
        )));
        let mut duplicate_role = relay;
        duplicate_role.plan = exit.plan.clone();
        assert!(!functional_snapshot_is_exactly_settled(&snapshot_with(
            vec![client, duplicate_role, exit,]
        )));

        let mut wrong_fixed_path = settled
            .records
            .values()
            .find(|record| record.plan.context_role == ContextRole::Relay)
            .expect("Relay tombstone")
            .clone();
        wrong_fixed_path.plan = ClosedPlan::new(
            ContextRole::Relay,
            vec![
                PathPlan {
                    path_id: 2,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 2,
                    role: WireguardRole::RelayExit,
                },
            ],
        )
        .expect("valid but non-fixture Relay plan");
        let other_records = settled
            .records
            .values()
            .filter(|record| record.plan.context_role != ContextRole::Relay)
            .cloned()
            .chain(std::iter::once(wrong_fixed_path))
            .collect();
        assert!(!functional_snapshot_is_exactly_settled(&snapshot_with(
            other_records
        )));
    }

    #[test]
    fn restart_evidence_accepts_only_one_cleanup_confirmed_client_then_four_tombstones() {
        let journal_epoch = epoch(1);
        let mut client = record(journal_epoch, 1, 2, 3, 1, OwnershipPhase::Absent);
        client.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        client.plan = ClosedPlan::new(
            ContextRole::Client,
            vec![PathPlan {
                path_id: 1,
                role: WireguardRole::Client,
            }],
        )
        .expect("client plan");
        let mut relay = record(journal_epoch, 4, 5, 6, 2, OwnershipPhase::Absent);
        relay.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        relay.plan = ClosedPlan::new(
            ContextRole::Relay,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit,
                },
            ],
        )
        .expect("relay plan");
        let mut exit = record(journal_epoch, 7, 8, 9, 3, OwnershipPhase::Absent);
        exit.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        exit.plan = ClosedPlan::new(
            ContextRole::Exit,
            vec![PathPlan {
                path_id: 1,
                role: WireguardRole::Exit,
            }],
        )
        .expect("exit plan");
        let mut restart_client = record(
            journal_epoch,
            10,
            11,
            12,
            4,
            OwnershipPhase::CleanupConfirmed,
        );
        restart_client.plan = client.plan.clone();

        let precrash = snapshot_with(vec![
            client.clone(),
            relay.clone(),
            exit.clone(),
            restart_client.clone(),
        ]);
        assert!(functional_snapshot_is_exactly_restart_cleanup_confirmed(
            &precrash
        ));
        let mut wrong_role = restart_client.clone();
        wrong_role.plan = exit.plan.clone();
        assert!(!functional_snapshot_is_exactly_restart_cleanup_confirmed(
            &snapshot_with(vec![
                client.clone(),
                relay.clone(),
                exit.clone(),
                wrong_role
            ])
        ));
        let mut lost_custody = restart_client.clone();
        lost_custody.recovery_evidence = None;
        assert!(!functional_snapshot_is_exactly_restart_cleanup_confirmed(
            &snapshot_with(vec![
                client.clone(),
                relay.clone(),
                exit.clone(),
                lost_custody,
            ])
        ));

        restart_client.phase = OwnershipPhase::Absent;
        restart_client.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        restart_client.recovery_evidence = None;
        let settled = snapshot_with(vec![client, relay, exit, restart_client.clone()]);
        assert!(functional_snapshot_is_exactly_restart_settled(&settled));
        restart_client.absent_origin = Some(AbsentOrigin::NeverDispatched);
        assert!(!functional_snapshot_is_exactly_restart_settled(
            &snapshot_with(vec![restart_client])
        ));
    }

    #[test]
    fn production_settlement_boundary_refuses_both_distinct_proofs() {
        let cleanup_target = CleanupTarget {
            exact_record: record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnCustody),
        };
        let manager_absence_target = ManagerAbsenceTarget {
            exact_record: record(epoch(1), 5, 6, 7, 2, OwnershipPhase::CleanupConfirmed),
        };
        let mut executor = RefuseMayOwnRecovery;
        assert!(matches!(
            executor.confirm_cleanup(&cleanup_target, recovery_deadline()),
            Err(MayOwnRecoveryUnavailable)
        ));
        assert!(matches!(
            executor.confirm_manager_absent(&manager_absence_target, recovery_deadline()),
            Err(MayOwnRecoveryUnavailable)
        ));
    }

    #[test]
    fn production_wrapper_exposes_only_lifecycle_and_arm_handle_with_refusing_recovery() {
        let source = include_str!("ownership_journal.rs");
        let start = source
            .find("impl ProductionOwnershipRuntime")
            .expect("production wrapper");
        let end = source[start..]
            .find("struct RefuseMayOwnRecovery")
            .map(|offset| start + offset)
            .expect("recovery executor boundary");
        let wrapper = &source[start..end];
        let production_config = ["JournalConfig", "::production()"].concat();
        assert!(wrapper.contains(&production_config));
        assert!(wrapper.contains("|| RefuseMayOwnRecovery"));
        assert!(wrapper.contains("start_until"));
        assert!(wrapper.contains("custody_arm_handle"));
        assert!(wrapper.contains("shutdown_until"));
        assert!(!wrapper.contains("register_until"));
        assert!(!wrapper.contains("mark_custody_until"));
        assert!(!wrapper.contains("arm_custody_until"));
        assert!(!wrapper.contains("retire_never_dispatched"));
        assert!(!wrapper.contains("confirm_cleanup_until"));
        assert!(!wrapper.contains("confirm_manager_absent_until"));
    }

    #[test]
    fn production_wrapper_sweeps_intent_and_preserves_may_own_bytes() {
        let intent_directory = tempdir().expect("intent directory");
        let intent_config = test_config(intent_directory.path());
        let mut intent_journal =
            OwnershipJournal::open(intent_config.clone()).expect("intent journal");
        let intent_inserted = intent_journal
            .insert_intent(0, intent(20, 21))
            .expect("durable intent");
        drop(intent_journal);

        ProductionOwnershipRuntime::start_with_config_until(
            intent_config.clone(),
            recovery_deadline(),
        )
        .expect("intent startup")
        .shutdown_until(recovery_deadline())
        .expect("intent shutdown");
        let intent_reopened =
            OwnershipJournal::open(intent_config).expect("reopen swept intent journal");
        assert_eq!(
            intent_reopened
                .snapshot()
                .expect("intent snapshot")
                .records
                .get(&intent_inserted.ownership_id)
                .expect("intent record")
                .phase,
            OwnershipPhase::Absent
        );

        let may_own_directory = tempdir().expect("MayOwn directory");
        let may_own_config = test_config(may_own_directory.path());
        let mut may_own_journal =
            OwnershipJournal::open(may_own_config.clone()).expect("MayOwn journal");
        let may_own_inserted = may_own_journal
            .insert_intent(0, intent(22, 23))
            .expect("MayOwn intent");
        mark_custody_fixture(
            &mut may_own_journal,
            may_own_inserted.revision,
            may_own_inserted,
            anchor(24),
        );
        drop(may_own_journal);
        let before = fs::read(&may_own_config.journal_path).expect("MayOwn bytes before startup");
        assert!(matches!(
            ProductionOwnershipRuntime::start_with_config_until(
                may_own_config.clone(),
                recovery_deadline(),
            ),
            Err(DurableOwnershipError::RecoveryNotConfirmed)
        ));
        assert_eq!(
            fs::read(&may_own_config.journal_path).expect("MayOwn bytes after refused startup"),
            before
        );

        let mixed_directory = tempdir().expect("mixed directory");
        let mixed_config = test_config(mixed_directory.path());
        let mut mixed_journal =
            OwnershipJournal::open(mixed_config.clone()).expect("mixed journal");
        let custody = mixed_journal
            .insert_intent(0, intent(30, 31))
            .expect("mixed custody intent");
        let custody_revision =
            mark_custody_fixture(&mut mixed_journal, custody.revision, custody, anchor(32))
                .revision;
        let pending_intent = mixed_journal
            .insert_intent(custody_revision, intent(33, 34))
            .expect("mixed pending Intent");
        drop(mixed_journal);
        let mixed_before =
            fs::read(&mixed_config.journal_path).expect("mixed bytes before startup");
        assert!(matches!(
            ProductionOwnershipRuntime::start_with_config_until(
                mixed_config.clone(),
                recovery_deadline(),
            ),
            Err(DurableOwnershipError::RecoveryNotConfirmed)
        ));
        assert_eq!(
            fs::read(&mixed_config.journal_path).expect("mixed bytes after refused startup"),
            mixed_before,
            "phase 4 preflight must run before retiring any Intent"
        );
        let mixed_reopened = OwnershipJournal::open(mixed_config).expect("reopen mixed journal");
        assert_eq!(
            mixed_reopened
                .snapshot()
                .expect("mixed snapshot")
                .records
                .get(&pending_intent.ownership_id)
                .expect("pending mixed Intent")
                .phase,
            OwnershipPhase::Intent
        );
    }

    #[test]
    fn production_wrapper_consumes_only_exact_cleanup_confirmed_restart_absence() {
        let directory = tempdir().expect("CleanupConfirmed directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("CleanupConfirmed journal");
        let inserted = journal
            .insert_intent(0, intent(35, 36))
            .expect("CleanupConfirmed intent");
        let armed =
            mark_and_arm_custody_fixture(&mut journal, inserted.revision, inserted, anchor(37));
        let revision = confirm_cleanup_fixture(
            &mut journal,
            armed.revision,
            inserted,
            &mut SameRuntimeCleanSettlement,
        )
        .expect("durable CleanupConfirmed fixture");
        drop(journal);

        let startup = ProductionOwnershipRuntime::begin_with_config_until(
            config.clone(),
            recovery_deadline(),
        )
        .expect("production CleanupConfirmed preflight");
        assert_eq!(startup.targets().len(), 1);
        assert_eq!(
            startup.targets()[0].phase(),
            StartupCustodyPhase::CleanupConfirmed
        );
        let evidence = CleanupConfirmedManagerAbsenceEvidence::from_targets_for_test(
            startup.targets().to_vec(),
        );
        startup
            .continue_cleanup_confirmed_absent(evidence)
            .expect("consume exact production restart absence")
            .shutdown_until(recovery_deadline())
            .expect("production restart shutdown");

        let reopened = OwnershipJournal::open(config).expect("reopen settled restart journal");
        let snapshot = reopened.snapshot().expect("settled restart snapshot");
        assert_eq!(snapshot.revision, revision + 1);
        let record = snapshot
            .records
            .get(&inserted.ownership_id)
            .expect("restart tombstone");
        assert_eq!(record.phase, OwnershipPhase::Absent);
        assert_eq!(record.absent_origin, Some(AbsentOrigin::RecoveredMayOwn));
    }

    #[test]
    fn absent_is_accepted_but_every_existing_object_fails_closed_without_mutation() {
        let directory = tempdir().expect("temporary directory");
        let candidate = directory.path().join("journal");
        ensure_absent(&candidate).expect("absent journal");

        fs::write(&candidate, b"legacy").expect("legacy fixture");
        assert_eq!(
            ensure_absent(&candidate)
                .expect_err("file must block")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&candidate).expect("fixture remains"), b"legacy");

        fs::remove_file(&candidate).expect("remove fixture");
        symlink("missing-target", &candidate).expect("symlink fixture");
        assert_eq!(
            ensure_absent(&candidate)
                .expect_err("symlink must block")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(fs::symlink_metadata(&candidate).is_ok());
    }

    #[test]
    fn production_server_classifies_lock_held_snapshot_before_ready_and_socket_mutation() {
        let source = include_str!("server.rs");
        let start = source
            .find("pub fn run_production_server")
            .expect("production entrypoint");
        let end = source[start..]
            .find("#[cfg(test)]")
            .map(|offset| start + offset)
            .expect("end of production entrypoint");
        let production = &source[start..end];
        let inherited = production
            .find("capture_inherited_custody(inherited)")
            .expect("affine inherited custody capture");
        let legacy = production
            .find("ensure_legacy_journal_absent()?")
            .expect("legacy interlock");
        let identity = production
            .find("prepare_production_runtime_identity()?")
            .expect("runtime identity preparation");
        let ownership = production
            .find("ProductionOwnershipRuntime::begin_until")
            .expect("lock-held durable ownership preflight");
        let runtime = production
            .find("Builder::new_multi_thread()")
            .expect("Tokio runtime construction");
        let observe = production
            .find("observe_startup_custody_inventory")
            .expect("stable manager inventory observation");
        let revalidate = production
            .find("revalidate_targets()")
            .expect("post-observation journal revalidation");
        let classify = production
            .find("classify_startup_custody")
            .expect("exact-set custody classification");
        let continue_empty = production
            .find("continue_empty()")
            .expect("empty projection continuation");
        let cleanup_confirmed_restart = production
            .find("settle_cleanup_confirmed_restart_absence(")
            .expect("cleanup-confirmed restart settlement");
        let cleanup_confirmed_present = production
            .find("settle_cleanup_confirmed_restart_present(")
            .expect("cleanup-confirmed exact-present removal");
        let bind_call = production
            .find("bind_production_socket(prepared_runtime, ownership_runtime)")
            .expect("production socket bind call");

        assert!(inherited < legacy);
        assert!(legacy < identity);
        assert!(identity < ownership);
        assert!(ownership < runtime);
        assert!(runtime < observe);
        assert!(observe < revalidate);
        assert!(revalidate < classify);
        assert!(classify < continue_empty);
        assert!(classify < cleanup_confirmed_restart);
        assert!(cleanup_confirmed_restart < cleanup_confirmed_present);
        assert!(continue_empty < bind_call);
        assert!(cleanup_confirmed_restart < bind_call);
        assert!(cleanup_confirmed_present < bind_call);

        let bind_start = source
            .find("fn bind_production_socket")
            .expect("production bind function");
        let bind_end = source[bind_start..]
            .find("async fn run_server")
            .map(|offset| bind_start + offset)
            .expect("end of production bind function");
        let bind = &source[bind_start..bind_end];
        let token = bind
            .find("publish_cleanup_token()")
            .expect("cleanup-token publication");
        let stale_socket = bind
            .find("remove_stale_socket")
            .expect("stale-socket removal");
        let guarded_listener = bind
            .find("bind_guarded_nonblocking_socket")
            .expect("guarded non-blocking listener bind");
        let secure = bind.find("secure_socket").expect("socket security");

        assert!(token < stale_socket);
        assert!(stale_socket < guarded_listener);
        assert!(guarded_listener < secure);
        assert!(!bind.contains("UnixListener::from_std"));
    }

    #[test]
    fn production_shutdown_cleans_engine_then_joins_actor_before_socket_release() {
        let source = include_str!("server.rs");
        let start = source
            .find("async fn run_server")
            .expect("production server loop");
        let end = source[start..]
            .find("\nasync fn process_connection")
            .map(|offset| start + offset)
            .expect("server-loop end");
        let shutdown = &source[start..end];
        let adoption = shutdown
            .find("UnixListener::from_std")
            .expect("asynchronous listener adoption");
        let service = shutdown
            .find("serve_connections")
            .expect("fallible service loop");
        let listener = shutdown.find("drop(listener)").expect("listener close");
        let tasks = shutdown.find("tasks.abort_all()").expect("task abort");
        let engine = shutdown
            .find("engine.shutdown_cleanup().await")
            .expect("engine cleanup");
        let ownership = shutdown
            .find("shutdown_production_ownership(ownership_runtime)")
            .expect("ownership shutdown and join");
        let socket = shutdown.find("drop(socket_guard)").expect("socket release");
        assert!(adoption < service);
        assert!(service < listener);
        assert!(listener < tasks);
        assert!(tasks < engine);
        assert!(engine < ownership);
        assert!(ownership < socket);
    }
}
