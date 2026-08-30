use std::{
    collections::BTreeMap,
    fs, io,
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::sync_channel,
    },
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

use tempfile::tempdir;
use volparossa_routing::{
    ClosedPreparePlan, ContextRole as WireContextRole, LeasePlan, PrepareIntent,
    WireguardRole as WireRole,
};

use crate::worker_v3::{
    exact_same_runtime_cleanup_proof_for_test, exact_same_runtime_manager_absence_proof_for_test,
};

use super::super::{
    AbsentOrigin, CleanupTarget, ConfirmedCleanupProof, ConfirmedManagerAbsentProof,
    JournalSnapshot, ManagerAbsenceTarget, PrepareRecoveryEvidenceV1, RefuseMayOwnRecovery,
};
use super::*;

const TEST_WAIT: Duration = Duration::from_secs(2);
// Fsync-heavy fixtures and executor-start tests must outlive the coordination wait even when
// parallel journal persistence delays the actor thread. Production and the default timeout tests
// retain their separately reviewed bounds.
const TEST_DURABLE_IO_WAIT: Duration = Duration::from_millis(2_500);

fn io_deadline() -> HardDeadline {
    HardDeadline::after(TEST_DURABLE_IO_WAIT).expect("durable test deadline")
}

#[derive(Clone, Copy)]
enum ExecutorMode {
    Exact,
    Error,
    MismatchedProof,
}

#[derive(Default)]
struct ExecutorObservations {
    calls: usize,
    cleanup_calls: usize,
    manager_absence_calls: usize,
    threads: Vec<ThreadId>,
    thread_names: Vec<Option<String>>,
    deadlines: Vec<HardDeadline>,
}

#[derive(Default)]
struct ExecutorGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    entered: bool,
    released: bool,
    returned: bool,
}

impl ExecutorGate {
    fn block(&self) {
        let mut state = self.state.lock().expect("executor gate");
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).expect("executor gate wait");
        }
        state.returned = true;
        self.changed.notify_all();
    }

    fn wait_entered(&self) {
        self.wait_for(|state| state.entered, "executor did not start");
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("executor gate");
        state.released = true;
        self.changed.notify_all();
    }

    fn wait_returned(&self) {
        self.wait_for(|state| state.returned, "executor did not return");
    }

    fn returned(&self) -> bool {
        self.state.lock().expect("executor gate").returned
    }

    fn wait_for(&self, predicate: impl Fn(&GateState) -> bool, message: &str) {
        let deadline = Instant::now() + TEST_WAIT;
        let mut state = self.state.lock().expect("executor gate");
        while !predicate(&state) {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            assert!(!remaining.is_zero(), "{message}");
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("executor gate wait");
            state = next;
            assert!(!timeout.timed_out() || predicate(&state), "{message}");
        }
    }
}

struct RecordingExecutor {
    mode: ExecutorMode,
    observations: Arc<Mutex<ExecutorObservations>>,
    gate: Option<Arc<ExecutorGate>>,
}

impl RecordingExecutor {
    fn observe(&self, deadline: HardDeadline, cleanup: bool) {
        let mut observations = self.observations.lock().expect("executor observations");
        observations.calls += 1;
        if cleanup {
            observations.cleanup_calls += 1;
        } else {
            observations.manager_absence_calls += 1;
        }
        observations.threads.push(thread::current().id());
        observations
            .thread_names
            .push(thread::current().name().map(str::to_owned));
        observations.deadlines.push(deadline);
    }

    fn block_if_requested(&self) {
        if let Some(gate) = &self.gate {
            gate.block();
        }
    }
}

impl CleanupExecutor for RecordingExecutor {
    type Error = &'static str;

    fn confirm_cleanup(
        &mut self,
        target: &CleanupTarget,
        deadline: HardDeadline,
    ) -> Result<ConfirmedCleanupProof, Self::Error> {
        self.observe(deadline, true);
        self.block_if_requested();
        match self.mode {
            ExecutorMode::Exact => Ok(target.confirmed_cleanup()),
            ExecutorMode::Error => Err("definite executor failure"),
            ExecutorMode::MismatchedProof => {
                let mut proof = target.confirmed_cleanup();
                proof.exact_record.prepare_operation_digest[0] ^= 0x80;
                Ok(proof)
            }
        }
    }
}

impl ManagerAbsenceExecutor for RecordingExecutor {
    type Error = &'static str;

    fn confirm_manager_absent(
        &mut self,
        target: &ManagerAbsenceTarget,
        deadline: HardDeadline,
    ) -> Result<ConfirmedManagerAbsentProof, Self::Error> {
        self.observe(deadline, false);
        self.block_if_requested();
        match self.mode {
            ExecutorMode::Exact => Ok(target.confirmed_manager_absent()),
            ExecutorMode::Error => Err("definite executor failure"),
            ExecutorMode::MismatchedProof => {
                let mut proof = target.confirmed_manager_absent();
                proof.exact_record.prepare_operation_digest[0] ^= 0x80;
                Ok(proof)
            }
        }
    }
}

fn test_config(directory: &Path) -> JournalConfig {
    let metadata = fs::metadata(directory).expect("temporary parent metadata");
    JournalConfig::for_test(
        directory,
        metadata.mode() & 0o7777,
        metadata.uid(),
        metadata.gid(),
    )
}

fn wire_intent(seed: u8) -> PrepareIntent {
    PrepareIntent {
        route_context_id: vec![seed; 16],
        prepare_request_id: vec![seed.wrapping_add(32); 16],
        prepare_operation_digest: vec![seed.wrapping_add(64); 32],
        setup_expires_at_unix: 100,
        hard_expires_at_unix: 200,
        closed_plan: Some(ClosedPreparePlan {
            context_role: WireContextRole::Client as i32,
            leases: vec![LeasePlan {
                path_id: 1,
                role: WireRole::Client as i32,
            }],
        }),
    }
}

fn durable_intent(seed: u8) -> DurablePrepareIntent {
    DurablePrepareIntent::try_from_wire([seed.wrapping_add(96); 32], &wire_intent(seed))
        .expect("valid durable intent")
}

fn durable_registration(seed: u8) -> DurableIntentRegistration {
    DurableIntentRegistration::try_from_wire([seed.wrapping_add(96); 32], &wire_intent(seed))
        .expect("valid durable registration")
}

fn durable_anchor(seed: u8) -> DurablePrepareAnchor {
    let seed_u64 = u64::from(seed);
    DurablePrepareAnchor::try_from_parts(DurablePrepareAnchorParts {
        boot_id: [seed; 16],
        pid: NonZeroU32::new(u32::from(seed)).expect("non-zero pid"),
        process_start_ticks: NonZeroU64::new(seed_u64 + 10).expect("non-zero ticks"),
        network_namespace_device: NonZeroU64::new(seed_u64 + 20).expect("non-zero device"),
        network_namespace_inode: NonZeroU64::new(seed_u64 + 30).expect("non-zero inode"),
        executable_device: NonZeroU64::new(seed_u64 + 40).expect("non-zero device"),
        executable_inode: NonZeroU64::new(seed_u64 + 50).expect("non-zero inode"),
        service_cgroup_inode: NonZeroU64::new(seed_u64 + 60).expect("non-zero inode"),
    })
    .expect("valid durable anchor")
}

fn executor(
    mode: ExecutorMode,
    observations: &Arc<Mutex<ExecutorObservations>>,
    gate: Option<Arc<ExecutorGate>>,
) -> RecordingExecutor {
    RecordingExecutor {
        mode,
        observations: Arc::clone(observations),
        gate,
    }
}

fn spawn_actor(
    config: JournalConfig,
    mode: ExecutorMode,
    observations: &Arc<Mutex<ExecutorObservations>>,
    gate: Option<Arc<ExecutorGate>>,
) -> Result<DurableOwnershipActor, DurableOwnershipError> {
    let observations = Arc::clone(observations);
    DurableOwnershipActor::spawn_with_executor_factory(config, move || {
        executor(mode, &observations, gate)
    })
}

fn prepopulate(
    config: &JournalConfig,
    entries: &[(DurablePrepareIntent, Option<DurablePrepareAnchor>)],
) -> Vec<OwnershipCoordinates> {
    let mut journal = OwnershipJournal::open(config.clone()).expect("open setup journal");
    let mut revision = journal.snapshot().expect("setup snapshot").revision;
    let epoch = journal.snapshot().expect("setup snapshot").journal_epoch_id;
    let mut coordinates = Vec::with_capacity(entries.len());
    for (intent, anchor) in entries {
        let inserted = journal
            .insert_intent(revision, intent.0.clone())
            .expect("persist setup intent");
        revision = inserted.revision;
        if let Some(anchor) = anchor {
            revision = journal
                .mark_may_own_custody(
                    revision,
                    inserted.ownership_id,
                    inserted.generation,
                    anchor.0,
                    custody_binding_for_test(*anchor)
                        .expect("custody binding fixture")
                        .0,
                    HardDeadline::after(TEST_WAIT).expect("custody fixture deadline"),
                )
                .expect("mark custody setup intent")
                .revision;
            revision = journal
                .mark_may_own_prepare_from_custody(
                    revision,
                    inserted.ownership_id,
                    inserted.generation,
                    HardDeadline::after(TEST_WAIT).expect("arm fixture deadline"),
                )
                .expect("arm custody setup intent")
                .revision;
        }
        coordinates.push(OwnershipCoordinates {
            journal_epoch_id: epoch,
            context_id: intent.0.context_id,
            ownership_id: inserted.ownership_id,
            generation: inserted.generation,
        });
    }
    coordinates
}

fn prepopulate_custody_target(
    journal: &mut OwnershipJournal,
    revision: u64,
    seed: u8,
    phase: StartupCustodyPhase,
) -> (u64, OwnershipCoordinates, DurableCustodyDescriptorBinding) {
    let intent = durable_intent(seed);
    let inserted = journal
        .insert_intent(revision, intent.0.clone())
        .expect("persist startup target Intent");
    let anchor = durable_anchor(seed);
    let binding = custody_binding_for_test(anchor).expect("startup custody binding");
    let marked = journal
        .mark_may_own_custody(
            inserted.revision,
            inserted.ownership_id,
            inserted.generation,
            anchor.0,
            binding.0,
            HardDeadline::after(TEST_WAIT).expect("startup target deadline"),
        )
        .expect("persist startup MayOwnCustody");
    let revision = match phase {
        StartupCustodyPhase::MayOwnCustody => marked.revision,
        StartupCustodyPhase::MayOwnPrepare | StartupCustodyPhase::CleanupConfirmed => {
            let armed = journal
                .mark_may_own_prepare_from_custody(
                    marked.revision,
                    inserted.ownership_id,
                    inserted.generation,
                    HardDeadline::after(TEST_WAIT).expect("startup arm deadline"),
                )
                .expect("persist startup MayOwnPrepare");
            if phase == StartupCustodyPhase::MayOwnPrepare {
                armed.revision
            } else {
                journal
                    .confirm_cleanup(
                        armed.revision,
                        inserted.ownership_id,
                        inserted.generation,
                        &mut RecordingExecutor {
                            mode: ExecutorMode::Exact,
                            observations: Arc::new(Mutex::new(ExecutorObservations::default())),
                            gate: None,
                        },
                        HardDeadline::after(TEST_WAIT).expect("cleanup fixture deadline"),
                    )
                    .expect("persist startup CleanupConfirmed")
            }
        }
    };
    (
        revision,
        OwnershipCoordinates {
            journal_epoch_id: journal
                .snapshot()
                .expect("startup target snapshot")
                .journal_epoch_id,
            context_id: intent.0.context_id,
            ownership_id: inserted.ownership_id,
            generation: inserted.generation,
        },
        binding,
    )
}

type ExpectedStartupTarget = (
    StartupCustodyPhase,
    DurablePrepareAnchor,
    DurableCustodyDescriptorBinding,
);

fn expected_startup_targets(
    entries: &[(
        OwnershipCoordinates,
        StartupCustodyPhase,
        DurablePrepareAnchor,
        DurableCustodyDescriptorBinding,
    ); 3],
) -> BTreeMap<DurableCustodyNameDigest, ExpectedStartupTarget> {
    entries
        .iter()
        .copied()
        .map(|(coordinates, phase, anchor, binding)| {
            (
                custody_name_digest_for_coordinates(coordinates),
                (phase, anchor, binding),
            )
        })
        .collect()
}

fn assert_startup_targets(
    actual: &[StartupCustodyTarget],
    expected: &BTreeMap<DurableCustodyNameDigest, ExpectedStartupTarget>,
) {
    assert_eq!(actual.len(), expected.len());
    assert!(
        actual
            .windows(2)
            .all(|pair| pair[0].custody_name_digest() < pair[1].custody_name_digest()),
        "startup targets must be in strict canonical digest order"
    );
    for target in actual {
        let (phase, anchor, binding) = expected
            .get(&target.custody_name_digest())
            .expect("exact projected target");
        assert_eq!(target.phase(), *phase);
        assert!(target.matches_recovery_anchor(anchor));
        assert!(target.matches_binding(binding));
        assert_eq!(target.durable_binding(), *binding);
        assert_eq!(format!("{target:?}"), "StartupCustodyTarget(<redacted>)");
    }
}

fn prepopulate_legacy_may_own_prepare(config: &JournalConfig, seed: u8) {
    let mut journal = OwnershipJournal::open(config.clone()).expect("open legacy setup journal");
    let inserted = journal
        .insert_intent(0, durable_intent(seed).0)
        .expect("persist legacy setup Intent");
    let mut next = journal.snapshot().expect("legacy setup snapshot").clone();
    let record = next
        .records
        .get_mut(&inserted.ownership_id)
        .expect("legacy setup record");
    record.phase = OwnershipPhase::MayOwnPrepare;
    record.recovery_evidence = Some(PrepareRecoveryEvidenceV1::LegacyAnchor(
        durable_anchor(seed).0,
    ));
    journal
        .compare_and_swap(inserted.revision, next)
        .expect("persist legacy MayOwnPrepare");
}

fn reopened_snapshot(config: &JournalConfig) -> JournalSnapshot {
    let journal = OwnershipJournal::open(config.clone()).expect("reopen journal");
    journal.snapshot().expect("reopened snapshot").clone()
}

fn wait_until_fenced(client: &ActorClient) {
    let deadline = Instant::now() + TEST_WAIT;
    loop {
        if !*client.admission.accepting.lock().expect("admission gate") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "shutdown did not fence admission"
        );
        thread::yield_now();
    }
}

fn expect_error<T>(result: &Result<T, DurableOwnershipError>) -> DurableOwnershipError {
    match result {
        Ok(_) => panic!("expected durable ownership error"),
        Err(error) => *error,
    }
}

fn expired_deadline() -> HardDeadline {
    let deadline = HardDeadline::after(Duration::from_millis(1)).expect("short deadline");
    while deadline.ensure_remaining().is_ok() {
        thread::yield_now();
    }
    deadline
}

type ResourceProjection = ((u8, i32), String, String, std::net::Ipv6Addr);

fn project_resources(resources: &[DurableWireguardResource]) -> Vec<ResourceProjection> {
    resources
        .iter()
        .map(|resource| {
            (
                resource.key(),
                resource.interface().to_owned(),
                resource.ownership_alias().to_owned(),
                resource.local_address(),
            )
        })
        .collect()
}

#[test]
fn typed_inputs_validate_complete_wire_values_and_redact_debug_output() {
    let valid = wire_intent(1);
    let typed = DurablePrepareIntent::try_from_wire([2; 32], &valid).expect("valid intent");
    assert_eq!(format!("{typed:?}"), "DurablePrepareIntent(<redacted>)");
    let registration =
        DurableIntentRegistration::try_from_wire([2; 32], &valid).expect("valid registration");
    assert_eq!(registration.context_id(), [1; 16]);
    assert_eq!(
        format!("{registration:?}"),
        "DurableIntentRegistration(<redacted>)"
    );

    assert_eq!(
        DurablePrepareIntent::try_from_wire([0; 32], &valid).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    let mut invalid = valid.clone();
    invalid.route_context_id.pop();
    assert_eq!(
        DurablePrepareIntent::try_from_wire([2; 32], &invalid).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    let mut invalid = valid.clone();
    invalid.prepare_operation_digest.pop();
    assert_eq!(
        DurablePrepareIntent::try_from_wire([2; 32], &invalid).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    let mut invalid = valid.clone();
    invalid.hard_expires_at_unix = invalid.setup_expires_at_unix - 1;
    assert_eq!(
        DurablePrepareIntent::try_from_wire([2; 32], &invalid).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    let mut invalid = valid;
    invalid.closed_plan = None;
    assert_eq!(
        DurablePrepareIntent::try_from_wire([2; 32], &invalid).unwrap_err(),
        DurableOwnershipError::Rejected
    );

    let invalid_anchor = DurablePrepareAnchor::try_from_parts(DurablePrepareAnchorParts {
        boot_id: [0; 16],
        pid: NonZeroU32::new(1).expect("non-zero"),
        process_start_ticks: NonZeroU64::new(1).expect("non-zero"),
        network_namespace_device: NonZeroU64::new(1).expect("non-zero"),
        network_namespace_inode: NonZeroU64::new(1).expect("non-zero"),
        executable_device: NonZeroU64::new(1).expect("non-zero"),
        executable_inode: NonZeroU64::new(1).expect("non-zero"),
        service_cgroup_inode: NonZeroU64::new(1).expect("non-zero"),
    });
    assert_eq!(invalid_anchor.unwrap_err(), DurableOwnershipError::Rejected);
    assert_eq!(
        format!("{:?}", durable_anchor(3)),
        "DurablePrepareAnchor(<redacted>)"
    );
}

#[test]
fn affine_registration_retains_the_only_owner_and_rejects_an_independent_reparse() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");

    let wire = wire_intent(31);
    let first = DurableIntentRegistration::try_from_wire([127; 32], &wire)
        .expect("first registration owner");
    let second = DurableIntentRegistration::try_from_wire([127; 32], &wire)
        .expect("independent registration owner");
    assert_ne!(
        first.0.0.ownership_id, second.0.0.ownership_id,
        "independent parsing must mint a distinct durable issuance identity"
    );

    let first = match actor.register_until(first, expired_deadline()) {
        DurableRegistrationOutcome::Retained {
            error: DurableOwnershipError::DeadlineElapsed,
            registration,
        } => registration,
        outcome => panic!("expired registration did not retain its owner: {outcome:?}"),
    };
    assert!(!config.journal_path.exists());

    let key = match actor.register_until(
        first,
        HardDeadline::after(TEST_WAIT).expect("registration deadline"),
    ) {
        DurableRegistrationOutcome::Registered(key) => key,
        outcome @ DurableRegistrationOutcome::Retained { .. } => {
            panic!("retained registration retry did not succeed: {outcome:?}")
        }
    };
    assert_eq!(key.coordinates.context_id.0, [31; 16]);
    let before = fs::read(&config.journal_path).expect("durable registration bytes");
    let revision = JournalSnapshot::decode(&before)
        .expect("decode durable registration")
        .revision;

    let rejected = match actor.register_until(
        second,
        HardDeadline::after(TEST_WAIT).expect("duplicate deadline"),
    ) {
        DurableRegistrationOutcome::Retained {
            error: DurableOwnershipError::Rejected,
            registration,
        } => registration,
        outcome => panic!("independent duplicate was not retained and rejected: {outcome:?}"),
    };
    assert_eq!(rejected.context_id(), [31; 16]);
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after rejected duplicate"),
        before
    );
    assert_eq!(
        JournalSnapshot::decode(
            &fs::read(&config.journal_path).expect("bytes after rejected duplicate")
        )
        .expect("decode bytes after rejected duplicate")
        .revision,
        revision
    );

    actor
        .retire_never_dispatched(&key)
        .expect("retire registered fixture");
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
#[allow(clippy::too_many_lines)] // One affine key-to-custody-to-MayOwn durability proof.
fn affine_arm_emits_no_token_before_durability_and_exact_retry_projects_identically() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let key = match actor.register_until(
        durable_registration(28),
        HardDeadline::after(TEST_WAIT).expect("registration deadline"),
    ) {
        DurableRegistrationOutcome::Registered(key) => key,
        outcome @ DurableRegistrationOutcome::Retained { .. } => {
            panic!("registration failed: {outcome:?}")
        }
    };
    let original = key.coordinates;

    let counterfeit = DurableOwnershipKey {
        coordinates: OwnershipCoordinates {
            context_id: Id16::new([99; 16]).expect("different context"),
            ..original
        },
    };
    let counterfeit_anchor = durable_anchor(28);
    let retained_counterfeit = match actor.mark_custody_until(
        counterfeit,
        counterfeit_anchor,
        custody_binding_for_test(counterfeit_anchor).expect("counterfeit binding"),
        HardDeadline::after(TEST_WAIT).expect("counterfeit deadline"),
    ) {
        DurableCustodyOutcome::Retained {
            error: DurableOwnershipError::Rejected,
            key,
        } => key,
        outcome => panic!("context substitution was not retained and rejected: {outcome:?}"),
    };
    assert_eq!(retained_counterfeit.coordinates.context_id.0, [99; 16]);

    let before = fs::read(&config.journal_path).expect("durable Intent bytes");
    let exact_anchor = durable_anchor(28);
    let key = match actor.mark_custody_until(
        key,
        exact_anchor,
        custody_binding_for_test(exact_anchor).expect("exact binding"),
        expired_deadline(),
    ) {
        DurableCustodyOutcome::Retained {
            error: DurableOwnershipError::DeadlineElapsed,
            key,
        } => key,
        outcome => panic!("pre-acceptance arm did not retain the key: {outcome:?}"),
    };
    assert!(key.coordinates == original);
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after expired arm"),
        before
    );
    assert_eq!(
        JournalSnapshot::decode(
            &fs::read(&config.journal_path).expect("bytes after retained expired arm")
        )
        .expect("decode retained expired arm")
        .records
        .get(&original.ownership_id)
        .expect("registered record")
        .phase,
        OwnershipPhase::Intent,
        "no MayOwn token may exist before a durable phase transition"
    );

    let custody = match actor.mark_custody_until(
        key,
        exact_anchor,
        custody_binding_for_test(exact_anchor).expect("exact binding"),
        HardDeadline::after(TEST_WAIT).expect("custody deadline"),
    ) {
        DurableCustodyOutcome::Marked(custody) => custody,
        outcome @ DurableCustodyOutcome::Retained { .. } => {
            panic!("durable custody mark failed: {outcome:?}")
        }
    };
    assert_eq!(custody.context_id(), [28; 16]);
    assert_eq!(format!("{custody:?}"), "DurableMayOwnCustody(<redacted>)");
    let may_own = match actor.arm_custody_until(
        custody,
        HardDeadline::after(TEST_WAIT).expect("arm deadline"),
    ) {
        DurableArmOutcome::Armed(may_own) => may_own,
        outcome @ DurableArmOutcome::Retained { .. } => {
            panic!("durable arm failed: {outcome:?}")
        }
    };
    assert_eq!(may_own.context_id(), [28; 16]);
    assert_eq!(format!("{may_own:?}"), "DurableMayOwnPrepare(<redacted>)");
    assert_eq!(may_own.resources().len(), 1);
    assert_eq!(may_own.resources()[0].key(), (1, WireRole::Client as i32));
    let worker_plan = may_own
        .prepare_leases_v3()
        .expect("canonical private worker-v3 plan");
    assert_eq!(worker_plan.route_context_id, vec![28; 16]);
    assert_eq!(worker_plan.leases.len(), 1);
    let worker_lease = &worker_plan.leases[0];
    assert_eq!(worker_lease.path_id, 1);
    assert_eq!(
        worker_lease.role,
        crate::internal_protocol::InternalEndpointRole::Client as i32
    );
    assert_eq!(
        worker_lease
            .local_overlay_address
            .as_ref()
            .expect("canonical local overlay")
            .address,
        may_own.resources()[0].local_address().octets()
    );
    assert_eq!(
        worker_lease
            .local_overlay_address
            .as_ref()
            .expect("canonical local overlay")
            .prefix_length,
        128
    );
    assert_eq!(worker_lease.setup_expires_at_unix, 100);
    assert_eq!(worker_lease.hard_expires_at_unix, 200);
    assert_eq!(
        worker_lease.ownership_alias,
        may_own.resources()[0].ownership_alias()
    );
    let first_projection = project_resources(may_own.resources());
    let armed_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");

    let retried = actor
        .client
        .as_ref()
        .expect("actor client")
        .arm_custody_pending(may_own.key.coordinates)
        .expect("admit exact raw test retry")
        .wait()
        .expect("exact durable retry");
    assert_eq!(project_resources(&retried), first_projection);
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after exact arm retry"),
        armed_bytes
    );

    actor
        .confirm_cleanup(&may_own.key)
        .expect("confirm cleanup for armed fixture");
    actor
        .confirm_manager_absent(&may_own.key)
        .expect("confirm manager absence for armed fixture");
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
fn cloned_custody_arm_handle_retains_affinity_and_never_owns_actor_shutdown() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor = spawn_actor(config, ExecutorMode::Exact, &observations, None).expect("start actor");
    let key = match actor.register_until(
        durable_registration(29),
        HardDeadline::after(TEST_WAIT).expect("registration deadline"),
    ) {
        DurableRegistrationOutcome::Registered(key) => key,
        outcome @ DurableRegistrationOutcome::Retained { .. } => {
            panic!("registration failed: {outcome:?}")
        }
    };
    let anchor = durable_anchor(29);
    let custody = match actor.mark_custody_until(
        key,
        anchor,
        custody_binding_for_test(anchor).expect("custody binding"),
        HardDeadline::after(TEST_WAIT).expect("custody deadline"),
    ) {
        DurableCustodyOutcome::Marked(custody) => custody,
        outcome @ DurableCustodyOutcome::Retained { .. } => {
            panic!("custody mark failed: {outcome:?}")
        }
    };

    let handle = actor.custody_arm_handle().expect("arm handle");
    let cloned_handle = handle.clone();
    let custody = match cloned_handle.arm_custody_until(custody, expired_deadline()) {
        DurableArmOutcome::Retained {
            error: DurableOwnershipError::DeadlineElapsed,
            custody,
        } => custody,
        outcome => panic!("expired handle arm did not retain custody: {outcome:?}"),
    };
    assert_eq!(custody.context_id(), [29; 16]);

    let may_own = match handle.arm_custody_until(
        custody,
        HardDeadline::after(TEST_WAIT).expect("arm retry deadline"),
    ) {
        DurableArmOutcome::Armed(may_own) => may_own,
        outcome @ DurableArmOutcome::Retained { .. } => {
            panic!("cloned-handle arm retry failed: {outcome:?}")
        }
    };
    actor
        .confirm_cleanup(&may_own.key)
        .expect("confirm cleanup for armed fixture");
    actor
        .confirm_manager_absent(&may_own.key)
        .expect("confirm manager absence for armed fixture");

    let lifecycle = Arc::clone(&handle.client.lifecycle);
    actor
        .shutdown()
        .expect("actor owner shuts down while arm handles remain alive");
    assert_eq!(lifecycle.load(), Lifecycle::Stopped);
    drop((handle, cloned_handle));
}

#[test]
fn deadline_expiry_before_startup_acceptance_is_mutation_free_and_does_not_latch_store() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls_capture = Arc::clone(&factory_calls);

    let expired = DurableOwnershipActor::spawn_with_executor_factory_until(
        config.clone(),
        move || {
            factory_calls_capture.fetch_add(1, Ordering::AcqRel);
            executor(ExecutorMode::Exact, &observations_capture, None)
        },
        expired_deadline(),
    );
    assert_eq!(
        expect_error(&expired),
        DurableOwnershipError::DeadlineElapsed
    );
    assert_eq!(factory_calls.load(Ordering::Acquire), 0);
    assert!(!config.journal_path.exists());
    assert!(!config.next_path.exists());
    assert!(!config.lock_path.exists());

    spawn_actor(config, ExecutorMode::Exact, &observations, None)
        .expect("expired startup did not acquire the process latch")
        .shutdown()
        .expect("clean actor shutdown");
}

#[test]
fn deadline_expiry_on_delayed_actor_start_is_mutation_free_and_does_not_latch_store() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls_capture = Arc::clone(&factory_calls);
    let gate = Arc::new(ExecutorGate::default());
    let hook_gate = Arc::clone(&gate);
    let release_gate = Arc::clone(&gate);
    let deadline = HardDeadline::after(Duration::from_millis(20)).expect("short startup deadline");
    let releaser = thread::spawn(move || {
        release_gate.wait_entered();
        while deadline.ensure_remaining().is_ok() {
            thread::yield_now();
        }
        release_gate.release();
    });

    let delayed = DurableOwnershipActor::spawn_with_pre_startup_hook_until(
        config.clone(),
        move || hook_gate.block(),
        move || {
            factory_calls_capture.fetch_add(1, Ordering::AcqRel);
            executor(ExecutorMode::Exact, &observations_capture, None)
        },
        deadline,
    );
    assert_eq!(expect_error(&delayed), DurableOwnershipError::Ambiguous);
    releaser.join().expect("startup deadline releaser");
    gate.wait_returned();
    assert_eq!(factory_calls.load(Ordering::Acquire), 0);
    assert!(!config.journal_path.exists());
    assert!(!config.next_path.exists());
    assert!(!config.lock_path.exists());

    spawn_actor(config, ExecutorMode::Exact, &observations, None)
        .expect("delayed expired startup did not acquire the process latch")
        .shutdown()
        .expect("clean actor shutdown");
}

#[test]
fn queued_expiry_is_observed_before_core_mutation_and_keeps_exact_journal_bytes() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let client = actor.client.as_ref().expect("actor client");
    let gate = Arc::new(ExecutorGate::default());
    let barrier_gate = Arc::clone(&gate);
    let barrier = client
        .test_barrier_pending_until(
            HardDeadline::after(TEST_WAIT).expect("barrier deadline"),
            move || barrier_gate.block(),
        )
        .expect("admit blocking barrier");
    gate.wait_entered();
    assert!(!config.journal_path.exists());
    assert!(!config.next_path.exists());

    let expired_at_dequeue =
        HardDeadline::after(Duration::from_millis(20)).expect("queued deadline");
    let expired = client
        .register_pending_until(durable_intent(27), expired_at_dequeue)
        .expect("admit queued registration");
    let trailing = client
        .test_barrier_pending_until(
            HardDeadline::after(TEST_WAIT).expect("trailing barrier deadline"),
            || {},
        )
        .expect("admit trailing barrier");
    while expired_at_dequeue.ensure_remaining().is_ok() {
        thread::yield_now();
    }
    gate.release();
    assert_eq!(barrier.wait(), Ok(()));
    assert_eq!(trailing.wait(), Ok(()));
    assert_eq!(expired.wait(), Err(DurableOwnershipError::DeadlineElapsed));
    assert!(!config.journal_path.exists());
    assert!(!config.next_path.exists());

    let key = actor
        .register_intent(durable_intent(27))
        .expect("expired queued command did not fence admission");
    actor
        .retire_never_dispatched(&key)
        .expect("retire post-expiry fixture");
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
fn ambiguous_shutdown_settlement_dominates_queued_deadline_reply() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let mut actor = spawn_actor(config, ExecutorMode::Exact, &observations, None)
        .expect("start shutdown-boundary actor");
    let client = actor.client.as_ref().expect("actor client").clone();
    let gate = Arc::new(ExecutorGate::default());
    let barrier_gate = Arc::clone(&gate);
    let barrier = client
        .test_barrier_pending_until(
            HardDeadline::after(TEST_WAIT).expect("barrier deadline"),
            move || barrier_gate.block(),
        )
        .expect("admit blocking barrier");
    gate.wait_entered();

    let shutdown_deadline =
        HardDeadline::after(Duration::from_millis(20)).expect("queued shutdown deadline");
    let shutdown_reply = client
        .fence_and_shutdown_until(shutdown_deadline)
        .expect("queue shutdown behind barrier");
    while shutdown_deadline.ensure_remaining().is_ok() {
        thread::yield_now();
    }
    gate.release();

    let finish_deadline = Instant::now() + TEST_WAIT;
    while !actor
        .join
        .as_ref()
        .expect("actor join handle")
        .is_finished()
    {
        assert!(
            Instant::now() < finish_deadline,
            "expired queued shutdown did not finish"
        );
        thread::yield_now();
    }
    assert_eq!(barrier.wait(), Ok(()));
    let reply = shutdown_reply.wait();
    assert_eq!(reply, Err(DurableOwnershipError::DeadlineElapsed));

    actor.client.take();
    let settled = actor.settle_thread_until(shutdown_deadline);
    assert_eq!(settled, Err(DurableOwnershipError::Ambiguous));
    assert_eq!(
        combine_shutdown_results(reply, settled),
        Err(DurableOwnershipError::Ambiguous),
        "join ambiguity must dominate the weaker no-mutation deadline reply"
    );
    assert_eq!(actor.lifecycle.load(), Lifecycle::Ambiguous);
}

#[test]
fn deadline_expiry_before_operation_acceptance_is_truthful_and_mutation_free() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let mut actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let expired = expired_deadline();

    assert!(!config.journal_path.exists());
    assert_eq!(
        actor
            .register_intent_until(durable_intent(22), expired)
            .unwrap_err(),
        DurableOwnershipError::DeadlineElapsed
    );
    assert!(!config.journal_path.exists());

    let recovered = actor
        .register_intent(durable_intent(22))
        .expect("register recovery fixture");
    let before = fs::read(&config.journal_path).expect("registered journal bytes");
    assert_eq!(
        actor
            .arm_prepare_until(&recovered, durable_anchor(22), expired)
            .unwrap_err(),
        DurableOwnershipError::DeadlineElapsed
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes"),
        before
    );
    actor
        .arm_prepare(&recovered, durable_anchor(22))
        .expect("arm recovery fixture");

    let before = fs::read(&config.journal_path).expect("armed journal bytes");
    assert_eq!(
        actor
            .confirm_cleanup_until(&recovered, expired)
            .unwrap_err(),
        DurableOwnershipError::DeadlineElapsed
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes"),
        before
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
    actor
        .confirm_cleanup(&recovered)
        .expect("confirm cleanup for armed fixture");
    actor
        .confirm_manager_absent(&recovered)
        .expect("confirm manager absence for armed fixture");

    let retired = actor
        .register_intent(durable_intent(23))
        .expect("register retire fixture");
    let before = fs::read(&config.journal_path).expect("retire journal bytes");
    assert_eq!(
        actor
            .retire_never_dispatched_until(&retired, expired)
            .unwrap_err(),
        DurableOwnershipError::DeadlineElapsed
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes"),
        before
    );
    actor
        .retire_never_dispatched(&retired)
        .expect("retire fixture after expired attempt");

    let before = fs::read(&config.journal_path).expect("pre-shutdown journal bytes");
    assert_eq!(
        actor.shutdown_until(expired).unwrap_err(),
        DurableOwnershipError::DeadlineElapsed
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes"),
        before
    );
    let still_running = actor
        .register_intent(durable_intent(24))
        .expect("expired shutdown leaves actor running");
    actor
        .retire_never_dispatched(&still_running)
        .expect("retire post-expiry fixture");
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
fn startup_sweeps_every_intent_before_ready_on_the_named_actor_thread() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let intent_only = durable_intent(1);
    let may_own = durable_intent(2);
    let anchor = durable_anchor(2);
    let coordinates = prepopulate(&config, &[(intent_only, None), (may_own, Some(anchor))]);
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let factory_thread = Arc::new(Mutex::new(None));
    let factory_thread_capture = Arc::clone(&factory_thread);
    let observations_capture = Arc::clone(&observations);
    let caller_thread = thread::current().id();
    let actor = DurableOwnershipActor::spawn_with_executor_factory(config.clone(), move || {
        *factory_thread_capture.lock().expect("factory thread") = Some(thread::current().id());
        executor(ExecutorMode::Exact, &observations_capture, None)
    })
    .expect("start actor after complete sweep");

    assert_ne!(
        factory_thread.lock().expect("factory thread").as_ref(),
        Some(&caller_thread)
    );
    let observed = observations.lock().expect("executor observations");
    assert_eq!(observed.calls, 2);
    assert_eq!(observed.cleanup_calls, 1);
    assert_eq!(observed.manager_absence_calls, 1);
    let actor_thread = factory_thread.lock().expect("factory thread").unwrap();
    assert_eq!(observed.threads, vec![actor_thread, actor_thread]);
    assert_eq!(
        observed.thread_names,
        vec![
            Some(ACTOR_THREAD_NAME.to_owned()),
            Some(ACTOR_THREAD_NAME.to_owned()),
        ]
    );
    drop(observed);
    actor.shutdown().expect("clean actor shutdown");

    let snapshot = reopened_snapshot(&config);
    let first = snapshot
        .records
        .get(&coordinates[0].ownership_id)
        .expect("first record");
    assert_eq!(first.phase, OwnershipPhase::Absent);
    assert_eq!(first.absent_origin, Some(AbsentOrigin::NeverDispatched));
    let second = snapshot
        .records
        .get(&coordinates[1].ownership_id)
        .expect("second record");
    assert_eq!(second.phase, OwnershipPhase::Absent);
    assert_eq!(second.absent_origin, Some(AbsentOrigin::RecoveredMayOwn));
}

#[test]
fn lock_held_preflight_projects_canonical_targets_before_any_intent_mutation() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let mut journal = OwnershipJournal::open(config.clone()).expect("open target setup journal");
    let (revision, custody_coordinates, custody_binding) =
        prepopulate_custody_target(&mut journal, 0, 40, StartupCustodyPhase::MayOwnCustody);
    let (revision, prepare_coordinates, prepare_binding) = prepopulate_custody_target(
        &mut journal,
        revision,
        41,
        StartupCustodyPhase::MayOwnPrepare,
    );
    let (revision, cleanup_coordinates, cleanup_binding) = prepopulate_custody_target(
        &mut journal,
        revision,
        42,
        StartupCustodyPhase::CleanupConfirmed,
    );
    let pending_intent = journal
        .insert_intent(revision, durable_intent(43).0)
        .expect("persist mixed pending Intent");
    drop(journal);

    let before = fs::read(&config.journal_path).expect("preflight journal bytes");
    let before_snapshot = JournalSnapshot::decode(&before).expect("preflight journal snapshot");
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let mut startup = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("preflight deadline"),
    )
    .expect("lock-held startup preflight");

    let expected = expected_startup_targets(&[
        (
            custody_coordinates,
            StartupCustodyPhase::MayOwnCustody,
            durable_anchor(40),
            custody_binding,
        ),
        (
            prepare_coordinates,
            StartupCustodyPhase::MayOwnPrepare,
            durable_anchor(41),
            prepare_binding,
        ),
        (
            cleanup_coordinates,
            StartupCustodyPhase::CleanupConfirmed,
            durable_anchor(42),
            cleanup_binding,
        ),
    ]);
    assert_startup_targets(startup.targets(), &expected);
    assert!(matches!(
        OwnershipJournal::open(config.clone()),
        Err(JournalError::LockHeld)
    ));
    let projected = startup.targets().to_vec();
    assert_eq!(
        startup
            .revalidate_targets()
            .expect("unchanged lock-held targets"),
        projected
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes during preflight"),
        before
    );

    assert_eq!(
        expect_error(&startup.continue_empty()),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    let after = fs::read(&config.journal_path).expect("bytes after refused continuation");
    assert_eq!(after, before);
    let after_snapshot = JournalSnapshot::decode(&after).expect("snapshot after refusal");
    assert_eq!(after_snapshot.revision, before_snapshot.revision);
    assert_eq!(
        after_snapshot
            .records
            .get(&pending_intent.ownership_id)
            .expect("pending Intent retained")
            .phase,
        OwnershipPhase::Intent
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn dropping_startup_guard_releases_lock_without_sweeping_pending_intent() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let mut journal = OwnershipJournal::open(config.clone()).expect("open drop setup journal");
    let (revision, custody_coordinates, _) =
        prepopulate_custody_target(&mut journal, 0, 46, StartupCustodyPhase::MayOwnCustody);
    let pending_intent = journal
        .insert_intent(revision, durable_intent(47).0)
        .expect("persist drop pending Intent");
    drop(journal);
    let before = fs::read(&config.journal_path).expect("journal bytes before guard drop");
    let before_revision = JournalSnapshot::decode(&before)
        .expect("snapshot before guard drop")
        .revision;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let startup = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("guard drop deadline"),
    )
    .expect("lock-held guard drop preflight");
    assert_eq!(startup.targets().len(), 1);
    assert_eq!(
        startup.targets()[0].custody_name_digest(),
        custody_name_digest_for_coordinates(custody_coordinates)
    );
    assert!(matches!(
        OwnershipJournal::open(config.clone()),
        Err(JournalError::LockHeld)
    ));

    let drop_started = Instant::now();
    drop(startup);
    assert!(
        drop_started.elapsed() < TEST_WAIT,
        "startup guard Drop did not settle its actor thread boundedly"
    );
    let after = fs::read(&config.journal_path).expect("journal bytes after guard drop");
    assert_eq!(after, before);
    assert_eq!(
        JournalSnapshot::decode(&after)
            .expect("snapshot after guard drop")
            .revision,
        before_revision
    );
    let reopened = OwnershipJournal::open(config.clone()).expect("lock released after guard drop");
    let snapshot = reopened.snapshot().expect("reopened snapshot");
    assert_eq!(
        snapshot
            .records
            .get(&pending_intent.ownership_id)
            .expect("pending Intent retained after guard drop")
            .phase,
        OwnershipPhase::Intent
    );
    assert_eq!(
        snapshot
            .records
            .get(&custody_coordinates.ownership_id)
            .expect("MayOwnCustody retained after guard drop")
            .phase,
        OwnershipPhase::MayOwnCustody
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn post_observation_revalidation_rejects_interposed_store_state_without_repair() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let mut journal = OwnershipJournal::open(config.clone()).expect("open revalidation journal");
    journal
        .insert_intent(0, durable_intent(45).0)
        .expect("persist revalidation Intent");
    drop(journal);
    let before = fs::read(&config.journal_path).expect("journal bytes before revalidation");
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let mut startup = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("revalidation deadline"),
    )
    .expect("lock-held revalidation preflight");
    assert!(startup.targets().is_empty());

    fs::write(&config.next_path, b"interposed next entry").expect("interpose next entry");
    assert_eq!(
        startup.revalidate_targets().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert!(matches!(
        OwnershipJournal::open(config.clone()),
        Err(JournalError::LockHeld)
    ));
    drop(startup);
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes after failed revalidation"),
        before
    );
    assert_eq!(
        fs::read(&config.next_path).expect("interposed next entry remains"),
        b"interposed next entry"
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn legacy_may_own_prepare_is_rejected_without_mutating_bytes_or_revision() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    prepopulate_legacy_may_own_prepare(&config, 43);
    let before = fs::read(&config.journal_path).expect("legacy journal bytes");
    let revision = JournalSnapshot::decode(&before)
        .expect("legacy journal snapshot")
        .revision;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);

    let result = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("legacy preflight deadline"),
    );
    assert_eq!(
        expect_error(&result),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    let after = fs::read(&config.journal_path).expect("legacy bytes after refusal");
    assert_eq!(after, before);
    assert_eq!(
        JournalSnapshot::decode(&after)
            .expect("legacy snapshot after refusal")
            .revision,
        revision
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn more_than_sixty_four_startup_targets_are_rejected_without_mutation() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let mut journal = OwnershipJournal::open(config.clone()).expect("open capacity setup journal");
    let mut revision = 0;
    for seed in 1_u8..=65 {
        (revision, _, _) = prepopulate_custody_target(
            &mut journal,
            revision,
            seed,
            StartupCustodyPhase::MayOwnCustody,
        );
    }
    drop(journal);
    let before = fs::read(&config.journal_path).expect("capacity journal bytes");
    let before_revision = JournalSnapshot::decode(&before)
        .expect("capacity journal snapshot")
        .revision;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);

    let result = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("capacity preflight deadline"),
    );
    assert_eq!(
        expect_error(&result),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    let after = fs::read(&config.journal_path).expect("capacity bytes after refusal");
    assert_eq!(after, before);
    assert_eq!(
        JournalSnapshot::decode(&after)
            .expect("capacity snapshot after refusal")
            .revision,
        before_revision
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn empty_target_preflight_preserves_existing_intent_settlement() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let mut journal = OwnershipJournal::open(config.clone()).expect("open Intent setup journal");
    let inserted = journal
        .insert_intent(0, durable_intent(44).0)
        .expect("persist pending Intent");
    drop(journal);
    let before = fs::read(&config.journal_path).expect("Intent bytes before preflight");
    let before_revision = JournalSnapshot::decode(&before)
        .expect("Intent snapshot before preflight")
        .revision;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let mut startup = DurableOwnershipActor::begin_with_executor_factory_until(
        config.clone(),
        move || executor(ExecutorMode::Exact, &observations_capture, None),
        HardDeadline::after(TEST_WAIT).expect("empty preflight deadline"),
    )
    .expect("empty target preflight");

    assert!(startup.targets().is_empty());
    assert!(
        startup
            .revalidate_targets()
            .expect("revalidate empty target set")
            .is_empty()
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("Intent bytes during preflight"),
        before
    );
    let actor = startup
        .continue_empty()
        .expect("continue empty startup and settle Intent");
    actor.shutdown().expect("clean actor shutdown");

    let after = fs::read(&config.journal_path).expect("Intent bytes after continuation");
    let snapshot = JournalSnapshot::decode(&after).expect("settled Intent snapshot");
    assert_eq!(snapshot.revision, before_revision + 1);
    let record = snapshot
        .records
        .get(&inserted.ownership_id)
        .expect("settled Intent record");
    assert_eq!(record.phase, OwnershipPhase::Absent);
    assert_eq!(record.absent_origin, Some(AbsentOrigin::NeverDispatched));
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn startup_and_command_recovery_receive_the_exact_outer_deadline() {
    let startup_directory = tempdir().expect("startup temporary directory");
    let startup_config = test_config(startup_directory.path());
    prepopulate(
        &startup_config,
        &[(durable_intent(28), Some(durable_anchor(28)))],
    );
    let startup_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let startup_capture = Arc::clone(&startup_observations);
    let startup_deadline = HardDeadline::after(TEST_WAIT).expect("startup deadline");
    DurableOwnershipActor::spawn_with_executor_factory_until(
        startup_config,
        move || executor(ExecutorMode::Exact, &startup_capture, None),
        startup_deadline,
    )
    .expect("start actor after deadline-bound recovery")
    .shutdown()
    .expect("clean startup actor shutdown");
    assert_eq!(
        startup_observations
            .lock()
            .expect("startup observations")
            .deadlines,
        vec![startup_deadline, startup_deadline]
    );

    let command_directory = tempdir().expect("command temporary directory");
    let command_config = test_config(command_directory.path());
    let command_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor = spawn_actor(
        command_config,
        ExecutorMode::Exact,
        &command_observations,
        None,
    )
    .expect("start command actor");
    let key = actor
        .register_intent(durable_intent(29))
        .expect("register command fixture");
    actor
        .arm_prepare(&key, durable_anchor(29))
        .expect("arm command fixture");
    let command_deadline = HardDeadline::after(TEST_WAIT).expect("command deadline");
    actor
        .confirm_cleanup_until(&key, command_deadline)
        .expect("deadline-bound cleanup confirmation");
    actor
        .confirm_manager_absent_until(&key, command_deadline)
        .expect("deadline-bound manager-absence confirmation");
    actor.shutdown().expect("clean command actor shutdown");
    assert_eq!(
        command_observations
            .lock()
            .expect("command observations")
            .deadlines,
        vec![command_deadline, command_deadline]
    );
}

#[test]
fn dropped_replies_do_not_cancel_durable_transitions_and_exact_retries_recover() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let client = actor.client.as_ref().expect("actor client");

    let first_intent = durable_intent(3);
    drop(
        client
            .register_pending_until(first_intent.clone(), io_deadline())
            .expect("admit lost register reply"),
    );
    let first_key = actor
        .register_intent_until(first_intent, io_deadline())
        .expect("exact register retry returns key");
    assert_eq!(format!("{first_key:?}"), "DurableOwnershipKey(<redacted>)");
    let anchor = durable_anchor(3);
    drop(
        client
            .mark_custody_pending_until(
                first_key.coordinates,
                anchor,
                custody_binding_for_test(anchor).expect("custody binding"),
                io_deadline(),
            )
            .expect("admit lost custody reply"),
    );
    actor
        .arm_prepare_until(&first_key, anchor, io_deadline())
        .expect("exact arm retry succeeds");
    drop(
        client
            .confirm_cleanup_pending_until(first_key.coordinates, io_deadline())
            .expect("admit lost cleanup reply"),
    );
    actor
        .confirm_cleanup_until(&first_key, io_deadline())
        .expect("exact cleanup retry succeeds");
    drop(
        client
            .confirm_manager_absent_pending_until(first_key.coordinates, io_deadline())
            .expect("admit lost manager-absence reply"),
    );
    actor
        .confirm_manager_absent_until(&first_key, io_deadline())
        .expect("exact manager-absence retry succeeds");

    let second_intent = durable_intent(4);
    let second_key = actor
        .register_intent_until(second_intent, io_deadline())
        .expect("register second intent");
    drop(
        client
            .retire_pending_until(second_key.coordinates, io_deadline())
            .expect("admit lost retire reply"),
    );
    actor
        .retire_never_dispatched_until(&second_key, io_deadline())
        .expect("exact retire retry succeeds");
    let observations = observations.lock().expect("executor observations");
    assert_eq!(observations.calls, 2);
    assert_eq!(observations.cleanup_calls, 1);
    assert_eq!(observations.manager_absence_calls, 1);
    drop(observations);
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
fn actor_exposes_only_ordered_distinct_cleanup_and_manager_absence_transitions() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let key = actor
        .register_intent(durable_intent(44))
        .expect("register settlement fixture");
    actor
        .arm_prepare(&key, durable_anchor(44))
        .expect("arm settlement fixture");
    let may_own_bytes = fs::read(&config.journal_path).expect("MayOwn bytes");

    assert_eq!(
        actor.confirm_manager_absent(&key).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        observations.lock().expect("executor observations").calls,
        0,
        "out-of-order manager settlement must not invoke an executor"
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after rejected manager transition"),
        may_own_bytes
    );

    actor.confirm_cleanup(&key).expect("confirm exact cleanup");
    let cleanup_bytes = fs::read(&config.journal_path).expect("CleanupConfirmed bytes");
    let cleanup_snapshot =
        JournalSnapshot::decode(&cleanup_bytes).expect("CleanupConfirmed decode");
    let cleanup_record = cleanup_snapshot
        .records
        .get(&key.coordinates.ownership_id)
        .expect("CleanupConfirmed record");
    assert_eq!(cleanup_record.phase, OwnershipPhase::CleanupConfirmed);
    assert_eq!(cleanup_record.absent_origin, None);
    assert!(matches!(
        cleanup_record.recovery_evidence,
        Some(PrepareRecoveryEvidenceV1::CustodyBound { .. })
    ));
    actor
        .confirm_cleanup(&key)
        .expect("exact cleanup retry is read-only");
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after cleanup retry"),
        cleanup_bytes
    );

    actor
        .confirm_manager_absent(&key)
        .expect("confirm distinct manager absence");
    let absent_bytes = fs::read(&config.journal_path).expect("Absent bytes");
    let absent_snapshot = JournalSnapshot::decode(&absent_bytes).expect("Absent decode");
    let absent_record = absent_snapshot
        .records
        .get(&key.coordinates.ownership_id)
        .expect("RecoveredMayOwn tombstone");
    assert_eq!(absent_record.phase, OwnershipPhase::Absent);
    assert_eq!(
        absent_record.absent_origin,
        Some(AbsentOrigin::RecoveredMayOwn)
    );
    assert!(absent_record.recovery_evidence.is_none());
    actor
        .confirm_manager_absent(&key)
        .expect("exact manager-absence retry is read-only");
    assert_eq!(
        fs::read(&config.journal_path).expect("bytes after manager retry"),
        absent_bytes
    );

    let observations = observations.lock().expect("executor observations");
    assert_eq!(observations.calls, 2);
    assert_eq!(observations.cleanup_calls, 1);
    assert_eq!(observations.manager_absence_calls, 1);
    drop(observations);
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "both opaque settlement phases and retained-error retries form one actor transaction"
)]
fn production_prepare_handle_preserves_affinity_through_both_clean_settlement_phases() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let actor =
        DurableOwnershipActor::spawn_with_executor_factory(config.clone(), || RefuseMayOwnRecovery)
            .expect("start production-executor actor");
    let handle = actor.prepare_handle().expect("production prepare handle");
    let registration = DurableIntentRegistration::try_from_wire([0x71; 32], &wire_intent(17))
        .expect("validated wire registration");
    let key = match handle.register_until(registration, io_deadline()) {
        DurableRegistrationOutcome::Registered(key) => key,
        DurableRegistrationOutcome::Retained { error, .. } => {
            panic!("registration retained unexpectedly: {error}")
        }
    };
    let coordinates = key.coordinates;
    let anchor = durable_anchor(17);
    let custody = match handle.mark_custody_until(
        key,
        anchor,
        custody_binding_for_test(anchor).expect("exact custody binding"),
        io_deadline(),
    ) {
        DurableCustodyOutcome::Marked(custody) => custody,
        DurableCustodyOutcome::Retained { error, .. } => {
            panic!("custody mark retained unexpectedly: {error}")
        }
    };
    let may_own = match handle
        .custody_arm_handle()
        .arm_custody_until(custody, io_deadline())
    {
        DurableArmOutcome::Armed(may_own) => may_own,
        DurableArmOutcome::Retained { error, .. } => {
            panic!("custody arm retained unexpectedly: {error}")
        }
    };
    assert_eq!(
        actor
            .client
            .as_ref()
            .expect("actor client")
            .confirm_cleanup_pending_until(coordinates, io_deadline())
            .expect("ordinary recovery admission")
            .wait(),
        Err(DurableOwnershipError::RecoveryNotConfirmed),
        "the installed restart executor must remain fail-closed"
    );
    let expected_plan = may_own
        .prepare_leases_v3()
        .expect("durable worker projection");
    let (settlement, resources) = may_own.into_dispatch_parts();
    assert_eq!(
        settlement.context_id().as_slice(),
        expected_plan.route_context_id.as_slice()
    );
    assert_eq!(resources.len(), expected_plan.leases.len());
    drop(resources);
    let proof = exact_same_runtime_cleanup_proof_for_test(settlement);
    assert_eq!(
        format!("{proof:?}"),
        "ExactSameRuntimeCleanupProof(<redacted>)"
    );
    let proof = match handle.confirm_cleanup_until(proof, expired_deadline()) {
        DurableCleanupOutcome::Retained { error, proof } => {
            assert_eq!(error, DurableOwnershipError::DeadlineElapsed);
            proof
        }
        DurableCleanupOutcome::Confirmed(_) => {
            panic!("expired cleanup proof unexpectedly settled")
        }
    };
    assert_eq!(
        JournalSnapshot::decode(&fs::read(&config.journal_path).expect("retained cleanup bytes"))
            .expect("retained cleanup snapshot")
            .records
            .values()
            .next()
            .expect("retained cleanup record")
            .phase,
        OwnershipPhase::MayOwnPrepare
    );
    let cleanup = match handle.confirm_cleanup_until(proof, io_deadline()) {
        DurableCleanupOutcome::Confirmed(cleanup) => cleanup,
        DurableCleanupOutcome::Retained { error, .. } => {
            panic!("cleanup confirmation retained unexpectedly: {error}")
        }
    };
    assert_eq!(
        cleanup.context_id().as_slice(),
        expected_plan.route_context_id.as_slice()
    );
    assert_eq!(
        JournalSnapshot::decode(&fs::read(&config.journal_path).expect("cleanup bytes"))
            .expect("cleanup snapshot")
            .records
            .values()
            .next()
            .expect("cleanup record")
            .phase,
        OwnershipPhase::CleanupConfirmed
    );
    let proof = exact_same_runtime_manager_absence_proof_for_test(cleanup);
    assert_eq!(
        format!("{proof:?}"),
        "ExactSameRuntimeManagerAbsenceProof(<redacted>)"
    );
    let proof = match handle.confirm_manager_absent_until(proof, expired_deadline()) {
        DurableManagerAbsentOutcome::Retained { error, proof } => {
            assert_eq!(error, DurableOwnershipError::DeadlineElapsed);
            proof
        }
        DurableManagerAbsentOutcome::Absent => {
            panic!("expired manager-absence proof unexpectedly settled")
        }
    };
    assert_eq!(
        JournalSnapshot::decode(&fs::read(&config.journal_path).expect("retained manager bytes"))
            .expect("retained manager snapshot")
            .records
            .values()
            .next()
            .expect("retained manager record")
            .phase,
        OwnershipPhase::CleanupConfirmed
    );
    assert!(matches!(
        handle.confirm_manager_absent_until(proof, io_deadline()),
        DurableManagerAbsentOutcome::Absent
    ));
    actor.shutdown().expect("clean actor shutdown");
}

#[test]
fn late_recovery_after_caller_drop_fences_admission_without_publishing_absent() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let gate = Arc::new(ExecutorGate::default());
    let actor = spawn_actor(
        config.clone(),
        ExecutorMode::Exact,
        &observations,
        Some(Arc::clone(&gate)),
    )
    .expect("start actor");
    let key = actor
        .register_intent(durable_intent(25))
        .expect("register late fixture");
    actor
        .arm_prepare(&key, durable_anchor(25))
        .expect("arm late fixture");
    let client = actor.client.as_ref().expect("actor client");
    // The actor must enter the executor before this intentional late-completion boundary. Real
    // journal fsyncs from parallel tests can delay scheduling on CI, so the admission window must
    // exceed the bounded gate wait rather than relying on a 20 ms scheduling race.
    let deadline = io_deadline();
    let pending = client
        .confirm_cleanup_pending_until(key.coordinates, deadline)
        .expect("accept cleanup before deadline");
    gate.wait_entered();
    drop(pending);
    while deadline.ensure_remaining().is_ok() {
        thread::yield_now();
    }
    gate.release();
    gate.wait_returned();
    wait_until_fenced(client);

    assert_eq!(
        expect_error(&client.register_pending(durable_intent(26))),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 1);
    let snapshot = JournalSnapshot::decode(
        &fs::read(&config.journal_path).expect("late-completion journal bytes"),
    )
    .expect("decode late-completion snapshot");
    assert_eq!(
        snapshot
            .records
            .get(&key.coordinates.ownership_id)
            .expect("late recovery record")
            .phase,
        OwnershipPhase::MayOwnPrepare,
        "an executor return after the hard deadline must not publish absence"
    );
    drop(actor);
}

#[test]
fn interposed_transitions_and_wrong_keys_reject_without_changing_durable_bytes() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");

    let retired_intent = durable_intent(5);
    let retired_key = actor
        .register_intent(retired_intent.clone())
        .expect("register retire fixture");
    actor
        .retire_never_dispatched(&retired_key)
        .expect("retire fixture");
    let before = fs::read(&config.journal_path).expect("journal bytes before register retry");
    assert_eq!(
        actor.register_intent(retired_intent).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes after register retry"),
        before
    );

    let armed_key = actor
        .register_intent(durable_intent(6))
        .expect("register arm fixture");
    let anchor = durable_anchor(6);
    let armed = actor.arm_prepare_until(&armed_key, anchor, io_deadline());
    armed.expect("arm fixture");
    actor
        .confirm_cleanup(&armed_key)
        .expect("confirm fixture cleanup");
    actor
        .confirm_manager_absent(&armed_key)
        .expect("confirm fixture manager absence");
    let before = fs::read(&config.journal_path).expect("journal bytes before arm retry");
    assert_eq!(
        actor.arm_prepare(&armed_key, anchor).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes after arm retry"),
        before
    );

    let live_key = actor
        .register_intent(durable_intent(7))
        .expect("register wrong-key fixture");
    let original = live_key.coordinates;
    let wrong_keys = [
        DurableOwnershipKey {
            coordinates: OwnershipCoordinates {
                journal_epoch_id: JournalEpochId::new([99; 32]).expect("different epoch"),
                ..original
            },
        },
        DurableOwnershipKey {
            coordinates: OwnershipCoordinates {
                context_id: Id16::new([97; 16]).expect("different context"),
                ..original
            },
        },
        DurableOwnershipKey {
            coordinates: OwnershipCoordinates {
                ownership_id: OwnershipId::new([98; 32]).expect("different ownership"),
                ..original
            },
        },
        DurableOwnershipKey {
            coordinates: OwnershipCoordinates {
                generation: NonZeroU64::new(original.generation.get() + 1)
                    .expect("different generation"),
                ..original
            },
        },
    ];
    let before = fs::read(&config.journal_path).expect("journal bytes before wrong keys");
    assert_eq!(
        actor
            .arm_prepare(&wrong_keys[0], durable_anchor(7))
            .unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        actor.retire_never_dispatched(&wrong_keys[1]).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        actor.confirm_cleanup(&wrong_keys[2]).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        actor.confirm_manager_absent(&wrong_keys[3]).unwrap_err(),
        DurableOwnershipError::Rejected
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes after wrong keys"),
        before
    );
    assert_eq!(
        actor.shutdown().unwrap_err(),
        DurableOwnershipError::RecoveryNotConfirmed
    );
}

#[test]
fn executor_failure_is_definite_and_preserves_may_own_for_later_recovery() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Error, &observations, None).expect("start actor");
    let key = actor
        .register_intent(durable_intent(8))
        .expect("register intent");
    actor
        .arm_prepare(&key, durable_anchor(8))
        .expect("arm intent");
    assert_eq!(
        actor.confirm_cleanup(&key).unwrap_err(),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    assert_eq!(
        actor.confirm_cleanup(&key).unwrap_err(),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 2);
    let ownership_id = key.coordinates.ownership_id;
    assert_eq!(
        actor.shutdown().unwrap_err(),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    assert_eq!(
        reopened_snapshot(&config)
            .records
            .get(&ownership_id)
            .expect("retained record")
            .phase,
        OwnershipPhase::MayOwnPrepare
    );
}

#[test]
fn shutdown_refuses_a_durable_intent_and_preserves_exact_bytes() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let actor =
        spawn_actor(config.clone(), ExecutorMode::Exact, &observations, None).expect("start actor");
    let key = actor
        .register_intent(durable_intent(30))
        .expect("register live intent");
    let before = fs::read(&config.journal_path).expect("durable intent bytes");

    assert_eq!(
        actor.shutdown().unwrap_err(),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("journal bytes after refused shutdown"),
        before
    );
    assert_eq!(
        reopened_snapshot(&config)
            .records
            .get(&key.coordinates.ownership_id)
            .expect("retained intent")
            .phase,
        OwnershipPhase::Intent
    );
    assert_eq!(observations.lock().expect("executor observations").calls, 0);
}

#[test]
fn startup_failure_retains_may_own_and_the_inode_latch_survives_aliases_and_shutdown() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let coordinates = prepopulate(&config, &[(durable_intent(9), Some(durable_anchor(9)))]);
    let before = fs::read(&config.journal_path).expect("MayOwn bytes before startup");
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    assert_eq!(
        expect_error(&spawn_actor(
            config.clone(),
            ExecutorMode::Error,
            &observations,
            None,
        )),
        DurableOwnershipError::RecoveryNotConfirmed
    );
    assert_eq!(
        reopened_snapshot(&config)
            .records
            .get(&coordinates[0].ownership_id)
            .expect("retained startup record")
            .phase,
        OwnershipPhase::MayOwnPrepare
    );
    assert_eq!(
        fs::read(&config.journal_path).expect("MayOwn bytes after refused startup"),
        before
    );
    let calls = observations.lock().expect("executor observations").calls;
    assert_eq!(calls, 1);
    let alias_config = test_config(&directory.path().join("."));
    assert_eq!(
        expect_error(&spawn_actor(
            alias_config,
            ExecutorMode::Exact,
            &observations,
            None,
        )),
        DurableOwnershipError::AlreadyStarted
    );
    assert_eq!(
        observations.lock().expect("executor observations").calls,
        calls
    );

    let second_directory = tempdir().expect("second temporary directory");
    let second_config = test_config(second_directory.path());
    let second_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    spawn_actor(
        second_config.clone(),
        ExecutorMode::Exact,
        &second_observations,
        None,
    )
    .expect("start clean actor")
    .shutdown()
    .expect("clean shutdown");
    assert_eq!(
        expect_error(&spawn_actor(
            test_config(&second_directory.path().join(".")),
            ExecutorMode::Exact,
            &second_observations,
            None,
        )),
        DurableOwnershipError::AlreadyStarted
    );
}

#[test]
fn retained_parent_fd_prevents_path_swap_mutation_and_logical_store_reopen() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let original_parent = config.parent_path.clone();
    let moved_parent = original_parent.with_extension("retained-parent");
    let replacement_next = original_parent.join("helper.ownership-v3.next");
    let moved_parent_for_factory = moved_parent.clone();
    let original_parent_for_factory = original_parent.clone();
    let replacement_next_for_factory = replacement_next.clone();
    let expected_parent_mode = config.expected_parent_mode;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_for_factory = Arc::clone(&observations);
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls_capture = Arc::clone(&factory_calls);

    let started = DurableOwnershipActor::spawn_with_startup_hook(
        config.clone(),
        move || {
            fs::rename(&original_parent_for_factory, &moved_parent_for_factory)
                .expect("detach verified parent");
            fs::create_dir(&original_parent_for_factory).expect("create replacement parent");
            fs::set_permissions(
                &original_parent_for_factory,
                fs::Permissions::from_mode(expected_parent_mode),
            )
            .expect("replacement parent mode");
            fs::write(&replacement_next_for_factory, b"replacement sentinel")
                .expect("replacement sentinel");
            fs::set_permissions(
                &replacement_next_for_factory,
                fs::Permissions::from_mode(0o600),
            )
            .expect("replacement sentinel mode");
        },
        move || {
            factory_calls_capture.fetch_add(1, Ordering::AcqRel);
            executor(ExecutorMode::Exact, &observations_for_factory, None)
        },
    );
    assert_eq!(expect_error(&started), DurableOwnershipError::Ambiguous);
    assert_eq!(factory_calls.load(Ordering::Acquire), 0);
    assert_eq!(
        fs::read(&replacement_next).expect("replacement sentinel remains"),
        b"replacement sentinel"
    );
    assert!(
        !config.lock_path.exists(),
        "replacement lock was not created"
    );
    assert!(
        !moved_parent.join("helper.ownership-v3.lock").exists(),
        "retained parent was not mutated after its path identity changed"
    );

    assert_eq!(
        expect_error(&spawn_actor(
            test_config(&original_parent),
            ExecutorMode::Exact,
            &observations,
            None,
        )),
        DurableOwnershipError::AlreadyStarted
    );
    fs::remove_file(&replacement_next).expect("remove replacement sentinel");
    fs::remove_dir(&original_parent).expect("remove replacement parent");
    fs::rename(&moved_parent, &original_parent).expect("restore temporary parent");
}

#[test]
fn executor_factory_runs_only_after_lock_and_snapshot_open_succeed() {
    let locked_directory = tempdir().expect("locked temporary directory");
    let locked_config = test_config(locked_directory.path());
    let held_journal = OwnershipJournal::open(locked_config.clone()).expect("hold runtime lock");
    let locked_factory_calls = Arc::new(AtomicUsize::new(0));
    let locked_factory_capture = Arc::clone(&locked_factory_calls);
    let locked_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let locked_observations_capture = Arc::clone(&locked_observations);
    let locked = DurableOwnershipActor::spawn_with_executor_factory(locked_config, move || {
        locked_factory_capture.fetch_add(1, Ordering::AcqRel);
        executor(ExecutorMode::Exact, &locked_observations_capture, None)
    });
    assert_eq!(expect_error(&locked), DurableOwnershipError::Unavailable);
    assert_eq!(locked_factory_calls.load(Ordering::Acquire), 0);
    drop(held_journal);

    let corrupt_directory = tempdir().expect("corrupt temporary directory");
    let corrupt_config = test_config(corrupt_directory.path());
    fs::write(&corrupt_config.journal_path, b"not a journal").expect("corrupt journal fixture");
    fs::set_permissions(
        &corrupt_config.journal_path,
        fs::Permissions::from_mode(0o600),
    )
    .expect("corrupt journal mode");
    let corrupt_factory_calls = Arc::new(AtomicUsize::new(0));
    let corrupt_factory_capture = Arc::clone(&corrupt_factory_calls);
    let corrupt_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let corrupt_observations_capture = Arc::clone(&corrupt_observations);
    let corrupt = DurableOwnershipActor::spawn_with_executor_factory(corrupt_config, move || {
        corrupt_factory_capture.fetch_add(1, Ordering::AcqRel);
        executor(ExecutorMode::Exact, &corrupt_observations_capture, None)
    });
    assert_eq!(expect_error(&corrupt), DurableOwnershipError::Ambiguous);
    assert_eq!(corrupt_factory_calls.load(Ordering::Acquire), 0);
}

#[test]
fn final_startup_healthcheck_rejects_a_path_swap_before_ready() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let original_parent = config.parent_path.clone();
    let moved_parent = original_parent.with_extension("post-open-parent");
    let replacement_sentinel = original_parent.join("replacement-sentinel");
    let original_parent_capture = original_parent.clone();
    let moved_parent_capture = moved_parent.clone();
    let replacement_sentinel_capture = replacement_sentinel.clone();
    let expected_parent_mode = config.expected_parent_mode;
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let observations_capture = Arc::clone(&observations);
    let started = DurableOwnershipActor::spawn_with_executor_factory(config.clone(), move || {
        fs::rename(&original_parent_capture, &moved_parent_capture).expect("detach opened parent");
        fs::create_dir(&original_parent_capture).expect("create post-open replacement");
        fs::set_permissions(
            &original_parent_capture,
            fs::Permissions::from_mode(expected_parent_mode),
        )
        .expect("replacement parent mode");
        fs::write(
            &replacement_sentinel_capture,
            b"replacement remains untouched",
        )
        .expect("replacement sentinel");
        executor(ExecutorMode::Exact, &observations_capture, None)
    });
    assert_eq!(expect_error(&started), DurableOwnershipError::Ambiguous);
    assert_eq!(
        fs::read(&replacement_sentinel).expect("replacement sentinel remains"),
        b"replacement remains untouched"
    );
    assert!(!config.lock_path.exists(), "replacement has no actor lock");
    assert!(
        moved_parent.join("helper.ownership-v3.lock").exists(),
        "only the retained directory received the pre-swap lock"
    );
    assert_eq!(
        expect_error(&spawn_actor(
            test_config(&original_parent),
            ExecutorMode::Exact,
            &observations,
            None,
        )),
        DurableOwnershipError::AlreadyStarted
    );
    fs::remove_file(&replacement_sentinel).expect("remove replacement sentinel");
    fs::remove_dir(&original_parent).expect("remove replacement parent");
    fs::rename(&moved_parent, &original_parent).expect("restore temporary parent");
}

#[test]
fn runtime_corruption_is_terminal_and_mutation_free() {
    let corrupt_directory = tempdir().expect("corrupt temporary directory");
    let corrupt_config = test_config(corrupt_directory.path());
    let corrupt_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let corrupt_actor = spawn_actor(
        corrupt_config.clone(),
        ExecutorMode::Exact,
        &corrupt_observations,
        None,
    )
    .expect("start corrupt actor");
    let corrupt_key = corrupt_actor
        .register_intent(durable_intent(17))
        .expect("register corrupt fixture");
    let mut corrupt_bytes = fs::read(&corrupt_config.journal_path).expect("journal bytes");
    let final_byte = corrupt_bytes.last_mut().expect("non-empty journal");
    *final_byte ^= 0x80;
    fs::write(&corrupt_config.journal_path, &corrupt_bytes).expect("inject corruption");
    assert_eq!(
        corrupt_actor
            .retire_never_dispatched(&corrupt_key)
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        fs::read(&corrupt_config.journal_path).expect("corrupt bytes remain"),
        corrupt_bytes
    );
    assert_eq!(
        corrupt_actor
            .register_intent(durable_intent(18))
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        corrupt_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
}

#[test]
fn runtime_unsafe_metadata_is_terminal_and_mutation_free() {
    let unsafe_directory = tempdir().expect("unsafe temporary directory");
    let unsafe_config = test_config(unsafe_directory.path());
    let unsafe_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let unsafe_actor = spawn_actor(
        unsafe_config.clone(),
        ExecutorMode::Exact,
        &unsafe_observations,
        None,
    )
    .expect("start unsafe actor");
    let unsafe_key = unsafe_actor
        .register_intent(durable_intent(19))
        .expect("register unsafe fixture");
    let before = fs::read(&unsafe_config.journal_path).expect("safe bytes");
    fs::set_permissions(
        &unsafe_config.journal_path,
        fs::Permissions::from_mode(0o644),
    )
    .expect("inject unsafe mode");
    assert_eq!(
        unsafe_actor
            .retire_never_dispatched(&unsafe_key)
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        fs::read(&unsafe_config.journal_path).expect("unsafe bytes remain"),
        before
    );
    assert_eq!(
        unsafe_actor
            .register_intent(durable_intent(20))
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        unsafe_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
}

#[test]
fn queue_capacity_reserves_shutdown_and_the_fence_linearizes_admission() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let gate = Arc::new(ExecutorGate::default());
    let actor = spawn_actor(
        config,
        ExecutorMode::Exact,
        &observations,
        Some(Arc::clone(&gate)),
    )
    .expect("start actor");
    let key = actor
        .register_intent(durable_intent(10))
        .expect("register intent");
    actor
        .arm_prepare(&key, durable_anchor(10))
        .expect("arm intent");
    let client = actor.client.as_ref().expect("actor client").clone();
    let active = client
        .confirm_cleanup_pending(key.coordinates)
        .expect("admit active recovery");
    gate.wait_entered();
    let wrong = OwnershipCoordinates {
        generation: NonZeroU64::new(key.coordinates.generation.get() + 1)
            .expect("wrong generation"),
        ..key.coordinates
    };
    let manager_absence = client
        .confirm_manager_absent_pending(key.coordinates)
        .expect("queue distinct manager-absence transition");
    let queued = (0..2)
        .map(|_| client.retire_pending(wrong).expect("fill accepted queue"))
        .collect::<Vec<_>>();
    assert_eq!(
        expect_error(&client.retire_pending(wrong)),
        DurableOwnershipError::Capacity
    );

    let shutdown_client = client.clone();
    let (shutdown_sender, shutdown_receiver) = sync_channel(1);
    let shutdown = thread::spawn(move || {
        let result = actor.shutdown();
        let _ = shutdown_sender.try_send(result);
    });
    wait_until_fenced(&shutdown_client);
    assert_eq!(
        expect_error(&shutdown_client.retire_pending(wrong)),
        DurableOwnershipError::Unavailable
    );
    gate.release();
    assert_eq!(active.wait(), Ok(()));
    assert_eq!(manager_absence.wait(), Ok(()));
    for reply in queued {
        assert_eq!(reply.wait(), Err(DurableOwnershipError::Rejected));
    }
    assert_eq!(
        shutdown_receiver
            .recv_timeout(TEST_WAIT)
            .expect("bounded shutdown reply"),
        Ok(())
    );
    shutdown.join().expect("shutdown thread");
}

#[test]
fn timed_out_operation_fences_queue_and_drop_never_waits_forever_for_executor() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let gate = Arc::new(ExecutorGate::default());
    let actor = spawn_actor(
        config,
        ExecutorMode::Exact,
        &observations,
        Some(Arc::clone(&gate)),
    )
    .expect("start actor");
    let first = actor
        .register_intent(durable_intent(11))
        .expect("register first intent");
    actor
        .arm_prepare(&first, durable_anchor(11))
        .expect("arm first intent");
    let second = actor
        .register_intent(durable_intent(12))
        .expect("register second intent");
    actor
        .arm_prepare(&second, durable_anchor(12))
        .expect("arm second intent");
    let client = actor.client.as_ref().expect("actor client");
    let first_deadline = io_deadline();
    let first_reply = client
        .confirm_cleanup_pending_until(first.coordinates, first_deadline)
        .expect("admit blocked recovery");
    gate.wait_entered();
    let second_reply = client
        .confirm_cleanup_pending(second.coordinates)
        .expect("queue second recovery");
    assert_eq!(first_reply.wait(), Err(DurableOwnershipError::Ambiguous));
    assert_eq!(
        expect_error(&client.confirm_cleanup_pending(second.coordinates)),
        DurableOwnershipError::Ambiguous
    );
    gate.release();
    assert_eq!(second_reply.wait(), Err(DurableOwnershipError::Ambiguous));
    gate.wait_returned();
    assert_eq!(
        observations.lock().expect("executor observations").calls,
        1,
        "queued recovery must not execute after the first operation times out"
    );
    drop(actor);

    let second_directory = tempdir().expect("second temporary directory");
    let second_config = test_config(second_directory.path());
    let second_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let second_gate = Arc::new(ExecutorGate::default());
    let second_actor = spawn_actor(
        second_config,
        ExecutorMode::Exact,
        &second_observations,
        Some(Arc::clone(&second_gate)),
    )
    .expect("start second actor");
    let key = second_actor
        .register_intent(durable_intent(13))
        .expect("register drop fixture");
    second_actor
        .arm_prepare(&key, durable_anchor(13))
        .expect("arm drop fixture");
    drop(
        second_actor
            .client
            .as_ref()
            .expect("actor client")
            .confirm_cleanup_pending(key.coordinates)
            .expect("admit drop fixture"),
    );
    second_gate.wait_entered();
    let (dropped_sender, dropped_receiver) = sync_channel(1);
    thread::spawn(move || {
        drop(second_actor);
        let _ = dropped_sender.try_send(());
    });
    dropped_receiver
        .recv_timeout(TEST_WAIT)
        .expect("actor Drop must remain bounded");
    assert!(
        !second_gate.returned(),
        "Drop must not await a hung executor"
    );
    second_gate.release();
    second_gate.wait_returned();
}

#[test]
fn proof_mismatch_is_terminal_and_fences_admission() {
    let mismatch_directory = tempdir().expect("mismatch temporary directory");
    let mismatch_config = test_config(mismatch_directory.path());
    let mismatch_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let mismatch_actor = spawn_actor(
        mismatch_config.clone(),
        ExecutorMode::MismatchedProof,
        &mismatch_observations,
        None,
    )
    .expect("start mismatch actor");
    let mismatch_key = mismatch_actor
        .register_intent(durable_intent(14))
        .expect("register mismatch intent");
    mismatch_actor
        .arm_prepare(&mismatch_key, durable_anchor(14))
        .expect("arm mismatch intent");
    assert_eq!(
        mismatch_actor.confirm_cleanup(&mismatch_key).unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        mismatch_actor
            .register_intent(durable_intent(15))
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        mismatch_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
}

#[test]
fn actor_panic_is_terminal_and_the_store_cannot_restart() {
    let panic_directory = tempdir().expect("panic temporary directory");
    let panic_config = test_config(panic_directory.path());
    let panic_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let panic_actor = spawn_actor(
        panic_config.clone(),
        ExecutorMode::Exact,
        &panic_observations,
        None,
    )
    .expect("start panic actor");
    let panic_intent = durable_intent(21);
    assert_eq!(
        panic_actor
            .client
            .as_ref()
            .expect("actor client")
            .panic_after_register_pending(panic_intent)
            .expect("admit panic")
            .wait(),
        Err(DurableOwnershipError::Ambiguous)
    );
    assert_eq!(
        panic_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    let snapshot = reopened_snapshot(&panic_config);
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(
        snapshot
            .records
            .values()
            .next()
            .expect("durable record")
            .phase,
        OwnershipPhase::Intent,
        "the CAS completed before the injected reply-path panic"
    );
    assert_eq!(
        expect_error(&spawn_actor(
            panic_config,
            ExecutorMode::Exact,
            &panic_observations,
            None,
        )),
        DurableOwnershipError::AlreadyStarted
    );
}

#[test]
fn durable_revision_conflict_is_terminal() {
    let conflict_directory = tempdir().expect("conflict temporary directory");
    let conflict_config = test_config(conflict_directory.path());
    let conflict_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let conflict_actor = spawn_actor(
        conflict_config.clone(),
        ExecutorMode::Exact,
        &conflict_observations,
        None,
    )
    .expect("start conflict actor");
    let conflict_key = conflict_actor
        .register_intent(durable_intent(16))
        .expect("register conflict intent");
    let bytes = fs::read(&conflict_config.journal_path).expect("read conflict journal");
    let mut durable = JournalSnapshot::decode(&bytes).expect("decode conflict journal");
    durable.revision += 1;
    fs::write(
        &conflict_config.journal_path,
        durable.encode().expect("encode conflicting revision"),
    )
    .expect("write conflicting revision");
    assert_eq!(
        conflict_actor
            .retire_never_dispatched(&conflict_key)
            .unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
    assert_eq!(
        conflict_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
}

#[test]
fn shutdown_ack_requires_a_complete_durable_boundary_check() {
    let shutdown_directory = tempdir().expect("shutdown temporary directory");
    let shutdown_config = test_config(shutdown_directory.path());
    let shutdown_observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let shutdown_actor = spawn_actor(
        shutdown_config.clone(),
        ExecutorMode::Exact,
        &shutdown_observations,
        None,
    )
    .expect("start shutdown actor");
    fs::write(&shutdown_config.next_path, b"unexpected next entry")
        .expect("inject shutdown-boundary mismatch");
    assert_eq!(
        shutdown_actor.shutdown().unwrap_err(),
        DurableOwnershipError::Ambiguous
    );
}

#[test]
fn definite_io_requires_health_confirmation_and_lifecycle_terminals_are_absorbing() {
    let directory = tempdir().expect("temporary directory");
    let config = test_config(directory.path());
    let journal = OwnershipJournal::open(config.clone()).expect("open direct actor core journal");
    let observations = Arc::new(Mutex::new(ExecutorObservations::default()));
    let mut core = ActorCore::new(journal, executor(ExecutorMode::Exact, &observations, None))
        .unwrap_or_else(|_| panic!("construct actor core"));
    assert!(matches!(
        core.classify_journal_error(JournalError::Io(io::Error::other("definite"))),
        FailureDisposition::Continue(DurableOwnershipError::Unavailable)
    ));
    fs::write(&config.next_path, b"unexpected next entry").expect("inject unsafe next entry");
    assert!(matches!(
        core.classify_journal_error(JournalError::Io(io::Error::other("unconfirmed"))),
        FailureDisposition::Stop(DurableOwnershipError::Ambiguous, Lifecycle::Ambiguous)
    ));
    assert!(matches!(
        classify_startup_error(&JournalError::LockHeld),
        FailureDisposition::Stop(DurableOwnershipError::Unavailable, Lifecycle::Unavailable)
    ));
    for runtime_error in [
        JournalError::LockHeld,
        JournalError::Corrupt,
        JournalError::UnsafeMetadata,
    ] {
        assert!(matches!(
            classify_without_healthcheck(&runtime_error),
            FailureDisposition::Stop(DurableOwnershipError::Ambiguous, Lifecycle::Ambiguous)
        ));
    }

    let lifecycle = LifecycleState::new();
    lifecycle.transition(Lifecycle::Running);
    lifecycle.transition(Lifecycle::Ambiguous);
    lifecycle.transition(Lifecycle::Closing);
    lifecycle.transition(Lifecycle::Stopped);
    assert_eq!(lifecycle.load(), Lifecycle::Ambiguous);
    let lifecycle = LifecycleState::new();
    lifecycle.transition(Lifecycle::Unavailable);
    lifecycle.transition(Lifecycle::Running);
    lifecycle.transition(Lifecycle::Stopped);
    assert_eq!(lifecycle.load(), Lifecycle::Unavailable);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete private actor API surface audit together.
fn affine_actor_api_is_bounded_redacted_and_only_wrapped_for_production() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_clone<T: Clone>() {}
    assert_send::<DurableOwnershipActor>();
    assert_send::<DurableIntentRegistration>();
    assert_send_sync::<DurableCustodyNameDigest>();
    assert_send_sync::<DurableOwnershipKey>();
    assert_send_sync::<DurableMayOwnCustody>();
    assert_send_sync::<DurableMayOwnPrepare>();
    assert_send_sync::<DurableCustodyArmHandle>();
    assert_clone::<DurableCustodyArmHandle>();
    let _: fn(&DurableMayOwnCustody) -> DurableCustodyNameDigest =
        DurableMayOwnCustody::custody_name_digest;
    let _: fn(
        &DurableOwnershipActor,
        &DurableOwnershipKey,
        DurablePrepareAnchor,
    ) -> Result<(), DurableOwnershipError> = DurableOwnershipActor::arm_prepare;
    let _: fn(&DurableOwnershipActor, &DurableOwnershipKey) -> Result<(), DurableOwnershipError> =
        DurableOwnershipActor::retire_never_dispatched;
    let _: fn(
        &DurableOwnershipActor,
        DurableIntentRegistration,
        HardDeadline,
    ) -> DurableRegistrationOutcome = DurableOwnershipActor::register_until;
    let _: fn(
        &DurableOwnershipActor,
        DurableOwnershipKey,
        DurablePrepareAnchor,
        DurableCustodyDescriptorBinding,
        HardDeadline,
    ) -> DurableCustodyOutcome = DurableOwnershipActor::mark_custody_until;
    let _: fn(&DurableOwnershipActor, DurableMayOwnCustody, HardDeadline) -> DurableArmOutcome =
        DurableOwnershipActor::arm_custody_until;
    let _: fn(&DurableOwnershipActor) -> Result<DurableCustodyArmHandle, DurableOwnershipError> =
        DurableOwnershipActor::custody_arm_handle;
    let _: fn(&DurableCustodyArmHandle, DurableMayOwnCustody, HardDeadline) -> DurableArmOutcome =
        DurableCustodyArmHandle::arm_custody_until;
    let _: fn(
        &DurableOwnershipActor,
        &DurableOwnershipKey,
        HardDeadline,
    ) -> Result<(), DurableOwnershipError> = DurableOwnershipActor::retire_never_dispatched_until;
    let _: fn(
        &DurableOwnershipActor,
        &DurableOwnershipKey,
        HardDeadline,
    ) -> Result<(), DurableOwnershipError> = DurableOwnershipActor::confirm_cleanup_until;
    let _: fn(
        &DurableOwnershipActor,
        &DurableOwnershipKey,
        HardDeadline,
    ) -> Result<(), DurableOwnershipError> = DurableOwnershipActor::confirm_manager_absent_until;
    let _: fn(&mut DurableOwnershipActor, HardDeadline) -> Result<(), DurableOwnershipError> =
        DurableOwnershipActor::shutdown_until;

    let actor_source = include_str!("../actor.rs");
    let library_source = include_str!("../../lib.rs");
    let main_source = include_str!("../../../../volparossa-helper-entry/src/main.rs");
    let engine_source = include_str!("../../engine_v3.rs");
    let server_source = include_str!("../../server.rs");
    assert!(actor_source.contains("sync_channel(COMMAND_CHANNEL_CAPACITY)"));
    assert!(actor_source.contains("recv_timeout(remaining)"));
    assert!(actor_source.contains("HardDeadline"));
    assert!(actor_source.contains("spawn_with_executor_factory_until"));
    for test_only_wrapper in [
        "#[cfg(test)]\n    pub(super) fn spawn_with_executor_factory",
        "#[cfg(test)]\n    fn register_intent(",
        "#[cfg(test)]\n    fn register_intent_until(",
        "#[cfg(test)]\n    fn arm_prepare(",
        "#[cfg(test)]\n    fn arm_prepare_until(",
        "#[cfg(test)]\n    pub(super) fn retire_never_dispatched(",
        "#[cfg(test)]\n    pub(super) fn confirm_cleanup(",
        "#[cfg(test)]\n    pub(super) fn confirm_manager_absent(",
        "#[cfg(test)]\n    pub(super) fn shutdown(",
    ] {
        assert!(
            actor_source.contains(test_only_wrapper),
            "deadline-resetting wrapper must stay test-only: {test_only_wrapper}"
        );
    }
    assert!(actor_source.contains("confirm_retry_safe_after_definite_failure"));
    assert!(!actor_source.contains("tokio::"));
    assert!(!actor_source.contains("async fn"));
    assert!(!actor_source.contains("pub struct "));
    assert!(!actor_source.contains("pub enum "));
    assert!(!actor_source.contains("expected_revision"));
    assert!(!actor_source.contains("pub(crate) fn register("));
    assert!(!actor_source.contains("pub(crate) fn arm("));
    assert!(actor_source.contains("pub(crate) fn register_until("));
    assert!(actor_source.contains("pub(crate) fn mark_custody_until("));
    assert!(actor_source.contains("pub(crate) fn arm_custody_until("));
    assert!(actor_source.contains("pub(crate) fn custody_arm_handle("));
    assert!(actor_source.contains("fn register_pending_until("));
    assert!(actor_source.contains("fn mark_custody_pending_until("));
    assert!(actor_source.contains("fn arm_custody_pending_until("));
    assert!(!actor_source.contains("pub(crate) fn arm_until("));

    for (name, source) in [
        ("lib", library_source),
        ("main", main_source),
        ("engine", engine_source),
        ("server", server_source),
    ] {
        for affine_api in [
            "DurableIntentRegistration",
            "DurableOwnershipActor",
            "DurableMayOwnCustody",
            "DurableMayOwnPrepare",
            "DurableRegistrationOutcome",
            "DurableCustodyOutcome",
            "DurableArmOutcome",
            "DurableCustodyNameDigest",
            "DurableCustodyArmHandle",
        ] {
            assert!(
                !source.contains(affine_api),
                "raw affine API escaped the production lifecycle wrapper in {name}: {affine_api}"
            );
        }
    }
}

#[test]
fn custody_arm_handle_surface_cannot_register_retire_recover_or_own_lifecycle() {
    let actor_source = include_str!("../actor.rs");
    let declaration = actor_source
        .split("pub(crate) struct DurableCustodyArmHandle {")
        .nth(1)
        .expect("custody arm handle declaration")
        .split("impl DurableCustodyArmHandle")
        .next()
        .expect("bounded custody arm handle declaration");
    assert!(declaration.contains("client: ActorClient"));
    for forbidden in ["join", "completion", "executor", "thread"] {
        assert!(
            !declaration.contains(forbidden),
            "arm handle owns forbidden lifecycle state: {forbidden}"
        );
    }

    let surface = actor_source
        .split("impl DurableCustodyArmHandle {")
        .nth(1)
        .expect("custody arm handle implementation")
        .split("/// Cloneable, typed production admission and settlement authority.")
        .next()
        .expect("bounded custody arm handle implementation");
    assert_eq!(surface.matches("pub(crate) fn").count(), 1);
    assert!(surface.contains("arm_custody_until"));
    assert!(surface.contains("HardDeadline"));
    for forbidden in [
        "register",
        "mark_custody",
        "retire",
        "recover",
        "confirm",
        "shutdown",
        "settle",
        "join",
    ] {
        assert!(
            !surface.contains(forbidden),
            "arm handle exposes forbidden authority: {forbidden}"
        );
    }
}

#[test]
fn affine_authority_types_are_non_clone_must_use_and_minimally_exposed() {
    let actor_source = include_str!("../actor.rs");
    for declaration in [
        "pub(crate) struct DurableIntentRegistration",
        "pub(crate) struct DurableOwnershipKey",
        "pub(crate) struct DurableMayOwnCustody",
        "pub(crate) struct DurableMayOwnPrepare",
    ] {
        let attributes = actor_source
            .split(declaration)
            .next()
            .expect("declaration prefix")
            .rsplit("\n\n")
            .next()
            .expect("direct declaration attributes");
        assert!(
            attributes.contains("#[must_use"),
            "missing must_use: {declaration}"
        );
        let derives = attributes
            .lines()
            .filter(|line| line.trim_start().starts_with("#[derive("))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!derives.contains("Clone"), "Clone authority: {declaration}");
        assert!(!derives.contains("Copy"), "Copy authority: {declaration}");
    }

    let may_own_surface = actor_source
        .split("impl DurableMayOwnPrepare {")
        .nth(1)
        .expect("MayOwn implementation")
        .split("impl fmt::Debug for DurableMayOwnPrepare")
        .next()
        .expect("bounded MayOwn implementation");
    assert_eq!(may_own_surface.matches("pub(crate)").count(), 4);
    assert!(may_own_surface.contains("context_id(&self)"));
    assert!(may_own_surface.contains("resources(&self) -> &[DurableWireguardResource]"));
    assert!(may_own_surface.contains("prepare_leases_v3(&self)"));
    assert!(may_own_surface.contains("into_dispatch_parts("));

    assert!(!actor_source.contains("impl DurableOwnershipKey {"));
    let custody_surface = actor_source
        .split("impl DurableMayOwnCustody {")
        .nth(1)
        .expect("durable custody implementation")
        .split("impl fmt::Debug for DurableMayOwnCustody")
        .next()
        .expect("bounded durable custody implementation");
    assert_eq!(custody_surface.matches("pub(crate)").count(), 2);
    assert!(custody_surface.contains("context_id(&self)"));
    assert!(custody_surface.contains("custody_name_digest(&self) -> DurableCustodyNameDigest"));

    let digest_surface = actor_source
        .split("impl DurableCustodyNameDigest {")
        .nth(1)
        .expect("custody digest implementation")
        .split("impl fmt::Debug for DurableCustodyNameDigest")
        .next()
        .expect("bounded custody digest implementation");
    assert_eq!(digest_surface.matches("pub(crate) fn").count(), 1);
    assert!(digest_surface.contains("encode_lower_hex(self) -> [u8;"));
    for forbidden in ["as_bytes", "as_ref", "to_vec", "to_string", "Display"] {
        assert!(
            !digest_surface.contains(forbidden),
            "custody digest exposed raw or variable-size material: {forbidden}"
        );
    }
    assert_eq!(
        actor_source
            .matches("VOLPAROSSA helper durable systemd custody name v1")
            .count(),
        1
    );
}
