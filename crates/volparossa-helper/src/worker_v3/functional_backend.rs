//! Process-owned functional-alpha lease backend.
//!
//! This adapter proves one live helper-runtime Client/Exit singleton or one atomic
//! RelayClient+RelayExit pair. It uses the real authenticated worker, a real anonymous network
//! namespace and kernel `WireGuard` UAPI. Activate verifies the signed role-specific local and peer
//! authority, then installs and reads back the complete exact peer set plus its main-table IPv6
//! `/128` link routes. A Relay worker starts behind a policy-drop baseline, enables forwarding only
//! inside its exact private namespace, and atomically admits the two context-bound directions with
//! authenticated rate and hard-expiry bounds. Probe-Commit requires a recent handshake plus strict
//! `WireGuard` and forwarding-counter growth on both legs. This seam proves only helper-internal
//! Relay forwarding; it does not yet claim a complete client-to-destination datapath or
//! crash/restart recovery. Production Prepare now completes the durable journal plus systemd
//! descriptor-store handoff before child/kernel mutation, and same-runtime clean teardown settles
//! that exact custody. Inherited-custody recovery after a helper restart remains fail-closed.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd as _,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustix::time::{ClockId, clock_gettime};
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, ProtocolError, RelayAuthorization, RelayReservation,
    RelayReservationRequest, ReplayCache, TimePolicy, VerifiedControlMessage, WireguardEndpoint,
    relay_reservation_request_sha256, verify_control_message, verify_relay_reservation,
};
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, ClosedPreparePlan, ContextRole,
    HELPER_HANDLE_BYTES, LeasePlan as RoutingLeasePlan, PrepareIntent, PrepareLeaseBatch,
    PublicUdpEndpoint, UnderlayEvidence as RoutingUnderlayEvidence, WireguardRole,
};

use crate::{
    deadline::HardDeadline,
    engine::{
        AsyncLeaseBackend, BackendAction, BackendBinding, BackendCompletion, BackendDestroy,
        BackendError, BackendFuture, BackendLineage, BackendPhase, BackendProbe, BackendRequest,
        BackendRuntimeCompletion, BackendRuntimeRequest, ConfirmedAbsent, ContextPhase,
        KernelCounters, OperationKind, PreparedKernelLease,
    },
    internal_protocol::{
        ActivateLeases, DestroyContext, INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION,
        InitialiseContext, InternalContextRole, InternalEndpointRole, InternalIpPrefix,
        InternalUdpEndpoint, InternalWorkerRequest, InternalWorkerResult,
        LeaseActivation as InternalLeaseActivation, LeasePlan as InternalLeasePlan, LeaseProbe,
        PrepareLeases, ProbeCommitLeases, internal_worker_request, internal_worker_response,
    },
    kernel::{BirthLinkError, BirthNamespaceKernel, LiveWireguardLeaseOwner},
    lease_spec::{DURABLE_WIREGUARD_ALIAS_PREFIX, WireguardLeaseSpec},
    ownership_journal::{
        DurableCleanupConfirmed, DurableCleanupOutcome, DurableIntentRegistration,
        DurableManagerAbsentOutcome, DurableOwnershipPrepareHandle, DurablePrepareSettlement,
        DurableWireguardResource,
    },
    underlay::{UnderlayCandidate, collect_consistent_direct_underlay},
};

use super::{
    ConfirmedWorkerGenerationAbsent, DEFAULT_MAX_CACHE_ENTRIES, DEFAULT_MAX_TTL,
    DurableFunctionalPrepareFailure, DurableFunctionalWorkerOwnership,
    DurableHandoffPrepareFailure, DurableHandoffTerminalSelector, DurableHandoffTerminalSettlement,
    ShutdownStatus, WorkerCoordinator, WorkerGenerationOwnership, WorkerGenerationReap,
    WorkerLifecycleAdmission, WorkerRecoveryIdentitySource, WorkerRegistry, WorkerV3Error,
};

const MAX_FUNCTIONAL_ALPHA_CONTEXTS: usize = 1;
const MARKER_DOMAIN: &[u8] = b"VOLPAROSSA functional alpha WireGuard owner v1";
const REQUEST_ID_DOMAIN: &[u8] = b"VOLPAROSSA functional alpha worker request v1";
const STAGE_INITIALISE: u8 = 1;
const STAGE_PREPARE: u8 = 2;
const STAGE_ACTIVATE: u8 = 3;
const STAGE_DESTROY: u8 = 4;
const STAGE_PROBE_COMMIT: u8 = 5;
const FUNCTIONAL_ALPHA_KEEPALIVE_SECONDS: u32 = 25;
/// Outer call budget reserved for exact process reap and immediate namespace-pin release.
const WORKER_FAIL_CLOSED_RETIREMENT_TAIL: Duration = Duration::from_millis(500);

/// Install the deliberately narrow process-owned backend used only by the production server.
pub(crate) fn functional_alpha_lease_backend(
    durable_ownership: DurableOwnershipPrepareHandle,
) -> Arc<dyn AsyncLeaseBackend> {
    Arc::new(FunctionalAlphaLeaseBackend {
        coordinator: WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        )),
        relay_replay: Mutex::new(functional_alpha_replay_cache()),
        state: Mutex::new(None),
        durable_ownership: Some(durable_ownership),
    })
}

fn functional_alpha_replay_cache() -> ReplayCache {
    match ReplayCache::new(DEFAULT_MAX_CACHE_ENTRIES) {
        Ok(cache) => cache,
        Err(_) => std::process::abort(),
    }
}

struct FunctionalAlphaLeaseBackend {
    coordinator: WorkerCoordinator,
    relay_replay: Mutex<ReplayCache>,
    state: Mutex<Option<OpenLeaseEntry>>,
    /// Always present in production. `None` exists only for narrow unit fixtures which never
    /// execute Prepare.
    durable_ownership: Option<DurableOwnershipPrepareHandle>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct OpenLineageKey {
    helper_runtime_id: [u8; 32],
    context_id: [u8; 16],
    backend_generation: u64,
    prepare_request_id: [u8; 16],
    prepare_operation_digest: [u8; 32],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
    setup_expires_at_boottime_ns: u64,
    hard_expires_at_boottime_ns: u64,
}

impl From<BackendLineage> for OpenLineageKey {
    fn from(value: BackendLineage) -> Self {
        Self {
            helper_runtime_id: value.helper_runtime_id,
            context_id: value.context_id,
            backend_generation: value.backend_generation,
            prepare_request_id: value.prepare_request_id,
            prepare_operation_digest: value.prepare_operation_digest,
            setup_expires_at_unix: value.setup_expires_at_unix,
            hard_expires_at_unix: value.hard_expires_at_unix,
            setup_expires_at_boottime_ns: value.setup_expires_at_boottime_ns,
            hard_expires_at_boottime_ns: value.hard_expires_at_boottime_ns,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenLeasePhase {
    Reserved,
    DurableHandoffPending,
    Registered,
    Initialised,
    BirthMayExist,
    Prepared,
    Activated,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedWorkerLease {
    path_id: u32,
    role: i32,
    public_key: [u8; 32],
    listen_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActivatedWorkerLease {
    prepared: PreparedWorkerLease,
    peer_public_key: [u8; 32],
    baseline: KernelCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedWireguardEndpoint {
    public_key: [u8; 32],
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FunctionalLeaseRole {
    context: ContextRole,
    wireguard: WireguardRole,
    internal_context: InternalContextRole,
    internal_endpoint: InternalEndpointRole,
}

struct OpenLeaseEntry {
    key: OpenLineageKey,
    context_role: ContextRole,
    worker: Option<WorkerGenerationOwnership>,
    recovery: Option<WorkerRecoveryIdentitySource>,
    durable: Option<DurableLeaseCustody>,
    durable_handoff_terminal: Option<DurableHandoffTerminalSelector>,
    wireguard: Vec<LiveWireguardLeaseOwner>,
    prepare: PrepareLeases,
    underlay: UnderlayCandidate,
    prepared: Vec<PreparedWorkerLease>,
    activated: Vec<ActivatedWorkerLease>,
    phase: OpenLeasePhase,
    birth_may_exist: Vec<bool>,
    /// Safe phase/birth-classified exact child `Destroyed` response observed before worker reap.
    /// Durable settlement must never infer worker-namespace cleanup from process death while
    /// systemd still pins that namespace.
    child_cleanup: Option<ExactChildCleanupConfirmed>,
    /// Affine exact-generation reap and complete registry-purge authority. A missing worker owner
    /// is not by itself absence evidence.
    worker_cleanup: Option<ConfirmedWorkerGenerationAbsent>,
}

enum DurableJournalSettlement {
    MayOwn(DurablePrepareSettlement),
    CleanupProven(ExactSameRuntimeCleanupProof),
    CleanupConfirmed(DurableCleanupConfirmed),
    RemovalAmbiguous {
        cleanup: DurableCleanupConfirmed,
        attempt_id: crate::systemd_fdstore::RemovalAttemptId,
    },
    RemovalRetryAuthorized {
        cleanup: DurableCleanupConfirmed,
        evidence: Box<crate::systemd_fdstore::ExactStillPresentRemovalEvidence>,
    },
    ManagerRemovalProven(ExactSameRuntimeManagerAbsenceProof),
}

struct DurableLeaseCustody {
    settlement: DurableJournalSettlement,
    custody_name: crate::systemd_fdstore::CustodyFdName,
    attestation: crate::systemd_fdstore::InventoryAttestation,
}

struct ExactChildCleanupConfirmed {
    key: OpenLineageKey,
}

struct ExactParentKernelAbsent {
    key: OpenLineageKey,
}

impl ExactParentKernelAbsent {
    fn after_exact_parent_kernel_absence(key: OpenLineageKey) -> Self {
        Self { key }
    }
}

enum ExactSameRuntimeCleanupEvidence {
    Production(Box<ExactProductionCleanupEvidence>),
    #[cfg(test)]
    Fixture,
}

struct ExactProductionCleanupEvidence {
    _child: ExactChildCleanupConfirmed,
    _worker: ConfirmedWorkerGenerationAbsent,
    _parent: ExactParentKernelAbsent,
}

/// Opaque authority that the functional backend may mint only after an exact child `Destroyed`
/// response, exact worker-generation reap and complete parent/kernel absence.
///
/// Its field and constructor remain private to this module. Other crate modules can only retain or
/// consume a proof which this backend already produced.
#[must_use = "exact same-runtime cleanup evidence must be consumed or retained"]
pub(crate) struct ExactSameRuntimeCleanupProof {
    settlement: DurablePrepareSettlement,
    _evidence: ExactSameRuntimeCleanupEvidence,
}

impl ExactSameRuntimeCleanupProof {
    fn after_exact_worker_kernel_cleanup(
        settlement: DurablePrepareSettlement,
        child: ExactChildCleanupConfirmed,
        worker: ConfirmedWorkerGenerationAbsent,
        parent: ExactParentKernelAbsent,
    ) -> Self {
        if child.key != parent.key
            || worker.coordinates.context_id != child.key.context_id
            || settlement.context_id() != child.key.context_id
        {
            std::process::abort();
        }
        Self {
            settlement,
            _evidence: ExactSameRuntimeCleanupEvidence::Production(Box::new(
                ExactProductionCleanupEvidence {
                    _child: child,
                    _worker: worker,
                    _parent: parent,
                },
            )),
        }
    }

    pub(crate) const fn settlement(&self) -> &DurablePrepareSettlement {
        &self.settlement
    }

    pub(crate) fn into_settlement(self) -> DurablePrepareSettlement {
        self.settlement
    }
}

impl std::fmt::Debug for ExactSameRuntimeCleanupProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExactSameRuntimeCleanupProof(<redacted>)")
    }
}

enum ExactManagerRemovalEvidence {
    Production(Box<crate::systemd_fdstore::ExactRemovalProof>),
    #[cfg(test)]
    Fixture,
}

/// Opaque authority that the functional backend may mint only from exact named-removal evidence.
///
/// The exact systemd proof stays owned inside this value until the journal reaches `Absent` or the
/// complete affine proof is returned for retry.
#[must_use = "exact manager-absence evidence must be consumed or retained"]
pub(crate) struct ExactSameRuntimeManagerAbsenceProof {
    cleanup: DurableCleanupConfirmed,
    _removal: ExactManagerRemovalEvidence,
}

impl ExactSameRuntimeManagerAbsenceProof {
    fn after_exact_named_removal(
        cleanup: DurableCleanupConfirmed,
        removal: crate::systemd_fdstore::ExactRemovalProof,
    ) -> Self {
        Self {
            cleanup,
            _removal: ExactManagerRemovalEvidence::Production(Box::new(removal)),
        }
    }

    pub(crate) const fn cleanup(&self) -> &DurableCleanupConfirmed {
        &self.cleanup
    }
}

impl std::fmt::Debug for ExactSameRuntimeManagerAbsenceProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExactSameRuntimeManagerAbsenceProof(<redacted>)")
    }
}

#[cfg(test)]
pub(crate) fn exact_same_runtime_cleanup_proof_for_test(
    settlement: DurablePrepareSettlement,
) -> ExactSameRuntimeCleanupProof {
    ExactSameRuntimeCleanupProof {
        settlement,
        _evidence: ExactSameRuntimeCleanupEvidence::Fixture,
    }
}

#[cfg(test)]
pub(crate) fn exact_same_runtime_manager_absence_proof_for_test(
    cleanup: DurableCleanupConfirmed,
) -> ExactSameRuntimeManagerAbsenceProof {
    ExactSameRuntimeManagerAbsenceProof {
        cleanup,
        _removal: ExactManagerRemovalEvidence::Fixture,
    }
}

impl FunctionalAlphaLeaseBackend {
    #[allow(
        clippy::too_many_lines,
        reason = "durable handoff and the first child mutation remain one auditable transaction"
    )]
    async fn prepare_one(
        &self,
        binding: BackendBinding,
        value: PrepareLeaseBatch,
    ) -> Result<Vec<PreparedKernelLease>, BackendError> {
        let (key, context_role, leases, context_ttl) =
            validate_prepare_batch_binding(binding, &value)?;
        let path_id = leases
            .first()
            .and_then(|lease| u8::try_from(lease.path_id).ok())
            .ok_or(BackendError::Invalid)?;
        let deadline = prepare_deadline(binding)?;
        let operation_deadline = worker_operation_deadline(deadline)?;
        let durable_handle = self
            .durable_ownership
            .as_ref()
            .ok_or(BackendError::Unavailable)?;
        let intent = reconstruct_durable_prepare_intent(binding.lineage, &value)?;
        let registration =
            DurableIntentRegistration::try_from_wire(binding.lineage.helper_runtime_id, &intent)
                .map_err(|_| BackendError::Invalid)?;
        let underlay = collect_consistent_direct_underlay(operation_deadline)
            .map_err(|_| BackendError::Unavailable)?;
        self.reserve_entry(key, context_role, underlay)?;
        {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key)?.phase = OpenLeasePhase::DurableHandoffPending;
        }
        let durable = match self
            .coordinator
            .durable_functional_prepare_until(
                durable_handle,
                registration,
                context_role,
                path_id,
                context_ttl,
                operation_deadline,
            )
            .await
        {
            Ok(durable) => durable,
            Err(DurableFunctionalPrepareFailure::Handoff(DurableHandoffPrepareFailure {
                error: _,
                selector,
            })) => {
                if selector.context_id() != key.context_id {
                    std::process::abort();
                }
                let mut state = lock_state(&self.state);
                let entry = exact_entry_mut(&mut state, key)?;
                if entry.durable_handoff_terminal.replace(selector).is_some() {
                    std::process::abort();
                }
                return Err(BackendError::CleanupIncomplete);
            }
            Err(DurableFunctionalPrepareFailure::Later(_error)) => {
                return Err(BackendError::CleanupIncomplete);
            }
        };
        let DurableFunctionalWorkerOwnership {
            settlement,
            resources,
            prepare,
            worker,
            source,
            custody_name,
            attestation,
        } = durable;
        let wireguard = resources
            .into_iter()
            .map(LiveWireguardLeaseOwner::claim)
            .collect::<Vec<_>>();
        if settlement.context_id() != key.context_id
            || prepare.route_context_id.as_slice() != key.context_id.as_slice()
            || wireguard.len() != leases.len()
            || wireguard.iter().zip(&leases).any(|(owner, lease)| {
                owner.resource().key() != (u8::try_from(lease.path_id).unwrap_or(0), lease.role)
            })
            || wireguard.iter().enumerate().any(|(index, owner)| {
                wireguard[index + 1..].iter().any(|other| {
                    owner.resource().key() == other.resource().key()
                        || owner.resource().interface() == other.resource().interface()
                        || owner.resource().ownership_alias() == other.resource().ownership_alias()
                })
            })
        {
            // Dispatch is already durably open; retain every owner in the process and fail closed.
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            entry.worker = Some(worker);
            entry.recovery = Some(source);
            entry.wireguard = wireguard;
            entry.prepare = prepare;
            entry.durable = Some(DurableLeaseCustody {
                settlement: DurableJournalSettlement::MayOwn(settlement),
                custody_name,
                attestation,
            });
            return Err(BackendError::CleanupIncomplete);
        }
        {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            entry.worker = Some(worker);
            entry.recovery = Some(source);
            entry.wireguard = wireguard;
            entry.prepare = prepare;
            entry.durable = Some(DurableLeaseCustody {
                settlement: DurableJournalSettlement::MayOwn(settlement),
                custody_name,
                attestation,
            });
            entry.birth_may_exist = vec![false; entry.wireguard.len()];
            entry.phase = OpenLeasePhase::Registered;
        }
        if let Err(error) = self.initialise_child(key, &value, operation_deadline).await {
            return Err(self.cleanup_after_failure(key, deadline, error).await);
        }
        if let Err(error) = self.create_birth_links(key, operation_deadline) {
            return Err(self.cleanup_after_failure(key, deadline, error).await);
        }
        let prepared = match self.prepare_child(key, &leases, operation_deadline).await {
            Ok(prepared) => prepared,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };

        let (underlay, prepared) = {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            entry.prepared = prepared;
            entry.phase = OpenLeasePhase::Prepared;
            (entry.underlay, entry.prepared.clone())
        };
        deadline
            .complete(())
            .map_err(|_| BackendError::CleanupIncomplete)?;
        Ok(prepared
            .into_iter()
            .map(|lease| PreparedKernelLease {
                path_id: lease.path_id,
                role: lease.role,
                public_key: lease.public_key,
                public_endpoint: PublicUdpEndpoint {
                    address: ip_bytes(underlay.address),
                    port: u32::from(lease.listen_port),
                },
                evidence: RoutingUnderlayEvidence::DirectAssigned,
            })
            .collect())
    }

    fn reserve_entry(
        &self,
        key: OpenLineageKey,
        context_role: ContextRole,
        underlay: UnderlayCandidate,
    ) -> Result<(), BackendError> {
        let mut state = lock_state(&self.state);
        if state.is_some() {
            return Err(BackendError::Capacity);
        }
        *state = Some(OpenLeaseEntry {
            key,
            context_role,
            worker: None,
            recovery: None,
            durable: None,
            durable_handoff_terminal: None,
            wireguard: Vec::new(),
            prepare: PrepareLeases {
                route_context_id: key.context_id.to_vec(),
                leases: Vec::new(),
            },
            underlay,
            prepared: Vec::new(),
            activated: Vec::new(),
            phase: OpenLeasePhase::Reserved,
            birth_may_exist: Vec::new(),
            child_cleanup: None,
            worker_cleanup: None,
        });
        Ok(())
    }

    async fn admit_worker(
        &self,
        key: OpenLineageKey,
        context_role: ContextRole,
        path_id: u8,
        context_ttl: Duration,
        operation_deadline: HardDeadline,
        cleanup_deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let admission = self.coordinator.reserve_spawn_register_for_context_until(
            key.context_id,
            context_role,
            path_id,
            context_ttl,
            operation_deadline,
        );
        match admission {
            WorkerLifecycleAdmission::Registered(worker) => {
                let mut state = lock_state(&self.state);
                let entry = exact_entry_mut(&mut state, key)?;
                entry.worker = Some(worker);
                entry.phase = OpenLeasePhase::Registered;
                Ok(())
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                remove_exact_entry(&self.state, key);
                Err(definite_worker_error(&error))
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                {
                    let mut state = lock_state(&self.state);
                    exact_entry_mut(&mut state, key)?.worker = Some(ownership);
                }
                Err(if self.cleanup_exact(key, cleanup_deadline, false).await {
                    definite_worker_error(&error)
                } else {
                    BackendError::CleanupIncomplete
                })
            }
        }
    }

    fn retain_recovery_source(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let recovery = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            let worker = entry
                .worker
                .as_ref()
                .ok_or(BackendError::CleanupIncomplete)?;
            self.coordinator
                .recovery_identity_source_until(worker, deadline)
                .map_err(|_| BackendError::Unavailable)?
        };
        let mut state = lock_state(&self.state);
        exact_entry_mut(&mut state, key)?.recovery = Some(recovery);
        Ok(())
    }

    async fn initialise_child(
        &self,
        key: OpenLineageKey,
        value: &PrepareLeaseBatch,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let (generation, context_role, prepare) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            let generation = entry
                .worker
                .as_ref()
                .ok_or(BackendError::CleanupIncomplete)?
                .coordinates
                .worker_generation
                .get();
            (generation, entry.context_role, entry.prepare.clone())
        };
        let internal_context = internal_context_role(context_role).ok_or(BackendError::Invalid)?;
        let request = worker_request(
            worker_request_id(key, STAGE_INITIALISE),
            internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id: key.context_id.to_vec(),
                role: internal_context as i32,
                mptcp_accepted_addrs: value.mptcp_accepted_addrs,
                mptcp_subflows: value.mptcp_subflows,
                prepare: Some(prepare),
            }),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, deadline)
            .await;
        if !matches_initialised(execution.as_ref().ok(), key.context_id) {
            return Err(response_error(execution));
        }
        let mut state = lock_state(&self.state);
        exact_entry_mut(&mut state, key)?.phase = OpenLeasePhase::Initialised;
        Ok(())
    }

    fn create_birth_links(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let mut kernel =
            BirthNamespaceKernel::connect(deadline).map_err(|_| BackendError::Kernel)?;
        let resource_count = {
            let state = lock_state(&self.state);
            exact_entry(state.as_ref(), key)?.wireguard.len()
        };
        if !(1..=2).contains(&resource_count) {
            return Err(BackendError::Invalid);
        }
        for index in 0..resource_count {
            let birth = {
                let mut state = lock_state(&self.state);
                let entry = exact_entry_mut(&mut state, key)?;
                let recovery = entry
                    .recovery
                    .as_ref()
                    .ok_or(BackendError::CleanupIncomplete)?;
                let target_namespace = recovery
                    .restart_custody
                    .borrowed_network_namespace()
                    .as_raw_fd();
                if entry.birth_may_exist.len() != entry.wireguard.len()
                    || index >= entry.birth_may_exist.len()
                {
                    return Err(BackendError::CleanupIncomplete);
                }
                entry.birth_may_exist[index] = true;
                entry.phase = OpenLeasePhase::BirthMayExist;
                kernel.create_and_move_wireguard(
                    entry
                        .wireguard
                        .get_mut(index)
                        .ok_or(BackendError::CleanupIncomplete)?,
                    target_namespace,
                    deadline,
                )
            };
            if matches!(
                birth,
                Err(BirthLinkError::Conflict | BirthLinkError::Kernel(_))
            ) {
                let mut state = lock_state(&self.state);
                let entry = exact_entry_mut(&mut state, key)?;
                *entry
                    .birth_may_exist
                    .get_mut(index)
                    .ok_or(BackendError::CleanupIncomplete)? = false;
            }
            match birth {
                Ok(()) => {}
                Err(BirthLinkError::Conflict) => return Err(BackendError::Invalid),
                Err(BirthLinkError::Kernel(_) | BirthLinkError::CleanupIncomplete) => {
                    return Err(BackendError::Kernel);
                }
            }
        }
        Ok(())
    }

    async fn prepare_child(
        &self,
        key: OpenLineageKey,
        leases: &[RoutingLeasePlan],
        deadline: HardDeadline,
    ) -> Result<Vec<PreparedWorkerLease>, BackendError> {
        let (generation, prepare) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            let generation = entry
                .worker
                .as_ref()
                .ok_or(BackendError::CleanupIncomplete)?
                .coordinates
                .worker_generation
                .get();
            (generation, entry.prepare.clone())
        };
        let request = worker_request(
            worker_request_id(key, STAGE_PREPARE),
            internal_worker_request::Operation::PrepareLeases(prepare),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, deadline)
            .await;
        matches_prepared_batch(execution.as_ref().ok(), leases)
            .ok_or_else(|| response_error(execution))
    }

    async fn activate_one(
        &self,
        binding: BackendBinding,
        value: ActivateLeaseBatch,
    ) -> Result<Vec<KernelCounters>, BackendError> {
        let (key, activations) = validate_activate_batch_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let operation_deadline = match worker_operation_deadline(deadline) {
            Ok(deadline) => deadline,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };
        let now_ms = unix_milliseconds()?;
        let (prepared, plan) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            if entry.phase != OpenLeasePhase::Prepared {
                return Err(BackendError::Invalid);
            }
            let prepared = entry.prepared.clone();
            if prepared.len() != activations.len()
                || prepared
                    .iter()
                    .zip(&activations)
                    .any(|(prepared, activation)| {
                        (prepared.path_id, prepared.role) != (activation.path_id, activation.role)
                    })
            {
                return Err(BackendError::Invalid);
            }
            (
                prepared.clone(),
                verified_internal_activate_batch_plan(
                    &self.relay_replay,
                    &entry.wireguard,
                    key,
                    &prepared,
                    entry.underlay,
                    &activations,
                    now_ms,
                )?,
            )
        };
        let counters = match self
            .activate_child(key, &prepared, plan, operation_deadline)
            .await
        {
            Ok(counters) => counters,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };
        if counters.len() != activations.len() {
            return Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await);
        }

        let activated = prepared
            .iter()
            .copied()
            .zip(&activations)
            .zip(&counters)
            .map(|((prepared, activation), baseline)| {
                let peer_public_key: [u8; 32] = activation
                    .peer_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| BackendError::Invalid)?;
                Ok(ActivatedWorkerLease {
                    prepared,
                    peer_public_key,
                    baseline: *baseline,
                })
            })
            .collect::<Result<Vec<_>, BackendError>>()?;
        let phase_committed = {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key).is_ok_and(|entry| {
                if entry.phase == OpenLeasePhase::Prepared && entry.prepared == prepared {
                    entry.activated = activated;
                    entry.phase = OpenLeasePhase::Activated;
                    true
                } else {
                    false
                }
            })
        };
        if !phase_committed {
            return Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await);
        }
        match deadline.complete(counters) {
            Ok(counters) => Ok(counters),
            Err(_) => Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await),
        }
    }

    async fn activate_child(
        &self,
        key: OpenLineageKey,
        prepared: &[PreparedWorkerLease],
        activate: ActivateLeases,
        deadline: HardDeadline,
    ) -> Result<Vec<KernelCounters>, BackendError> {
        let generation = entry_generation(&self.state, key)?;
        let request = worker_request(
            worker_request_id(key, STAGE_ACTIVATE),
            internal_worker_request::Operation::ActivateLeases(activate),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, deadline)
            .await;
        matches_activated_batch(execution.as_ref().ok(), prepared)
            .ok_or_else(|| response_error(execution))
    }

    async fn probe_one(
        &self,
        binding: BackendBinding,
        value: BackendProbe,
    ) -> Result<Vec<KernelCounters>, BackendError> {
        let (key, commits, activated_at_unix) = validate_probe_batch_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let operation_deadline = match worker_operation_deadline(deadline) {
            Ok(deadline) => deadline,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };
        let activated = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            if entry.phase != OpenLeasePhase::Activated {
                return Err(BackendError::Invalid);
            }
            let activated = entry.activated.clone();
            if activated.len() != commits.len()
                || activated.iter().zip(&commits).any(|(activated, commit)| {
                    (activated.prepared.path_id, activated.prepared.role)
                        != (commit.path_id, commit.role)
                })
            {
                return Err(BackendError::Invalid);
            }
            activated
        };
        let generation = entry_generation(&self.state, key)?;
        let request = worker_request(
            worker_attempt_request_id(key, STAGE_PROBE_COMMIT, binding),
            internal_worker_request::Operation::ProbeCommitLeases(ProbeCommitLeases {
                route_context_id: key.context_id.to_vec(),
                leases: commits
                    .iter()
                    .zip(&activated)
                    .map(|(commit, activated)| LeaseProbe {
                        path_id: commit.path_id,
                        role: functional_lease_role_for_wireguard(commit.role)
                            .expect("validated functional commit role")
                            .internal_endpoint as i32,
                        expected_peer_public_key: activated.peer_public_key.to_vec(),
                        not_before_unix: activated_at_unix,
                    })
                    .collect(),
            }),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, operation_deadline)
            .await;
        let proof = match execution {
            Ok(execution) => {
                match matches_probed_batch(Some(&execution), &activated, activated_at_unix) {
                    Some(proof) => proof,
                    None if InternalWorkerResult::try_from(execution.response.result)
                        == Ok(InternalWorkerResult::Kernel) =>
                    {
                        return Err(BackendError::Kernel);
                    }
                    None => {
                        return Err(self
                            .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                            .await);
                    }
                }
            }
            Err(_) => {
                return Err(self
                    .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                    .await);
            }
        };

        let phase_committed = {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key).is_ok_and(|entry| {
                if entry.phase == OpenLeasePhase::Activated && entry.activated == activated {
                    entry.phase = OpenLeasePhase::Committed;
                    true
                } else {
                    false
                }
            })
        };
        if !phase_committed {
            return Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await);
        }
        match deadline.complete(proof) {
            Ok(proofs) => Ok(proofs),
            Err(_) => Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await),
        }
    }

    async fn cleanup_after_failure(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
        desired: BackendError,
    ) -> BackendError {
        if self.cleanup_exact(key, deadline, true).await {
            desired
        } else {
            BackendError::CleanupIncomplete
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "worker, kernel and durable cleanup ordering remains one auditable transaction"
    )]
    async fn cleanup_exact(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
        request_child_destroy: bool,
    ) -> bool {
        let handoff_terminal = {
            let mut state = lock_state(&self.state);
            state.as_mut().and_then(|entry| {
                if entry.key == key
                    && entry.phase == OpenLeasePhase::DurableHandoffPending
                    && entry.worker.is_none()
                {
                    entry.durable_handoff_terminal.take()
                } else {
                    None
                }
            })
        };
        if let Some(selector) = handoff_terminal {
            let Some(handle) = self.durable_ownership.as_ref() else {
                self.restore_durable_handoff_terminal(key, selector);
                return false;
            };
            match self.coordinator.settle_durable_handoff_terminal_until(
                handle,
                selector,
                key.context_id,
                deadline,
            ) {
                DurableHandoffTerminalSettlement::Absent => {
                    return remove_exact_entry(&self.state, key);
                }
                DurableHandoffTerminalSettlement::Retained { error: _, selector } => {
                    self.restore_durable_handoff_terminal(key, selector);
                    return false;
                }
            }
        }
        if lock_state(&self.state).as_ref().is_some_and(|entry| {
            entry.key == key
                && entry.phase == OpenLeasePhase::DurableHandoffPending
                && entry.worker.is_none()
        }) {
            // The coordinator retains the exact failed handoff terminal. No local cleanup path may
            // erase the corresponding durable record or make shutdown appear complete.
            return false;
        }
        let generation = entry_generation(&self.state, key).ok();
        let should_destroy = request_child_destroy
            && lock_state(&self.state).as_ref().is_some_and(|entry| {
                entry.key == key
                    && entry.child_cleanup.is_none()
                    && matches!(
                        entry.phase,
                        OpenLeasePhase::Initialised
                            | OpenLeasePhase::BirthMayExist
                            | OpenLeasePhase::Prepared
                            | OpenLeasePhase::Activated
                            | OpenLeasePhase::Committed
                    )
            });
        if let (true, Some(generation)) = (should_destroy, generation) {
            let destroy = worker_request(
                worker_request_id(key, STAGE_DESTROY),
                internal_worker_request::Operation::DestroyContext(DestroyContext {
                    route_context_id: key.context_id.to_vec(),
                }),
            );
            if let Ok(destroy_deadline) = worker_operation_deadline(deadline) {
                let execution = self
                    .coordinator
                    .execute_until(key.context_id, generation, destroy, destroy_deadline)
                    .await;
                let mut state = lock_state(&self.state);
                let Ok(entry) = exact_entry_mut(&mut state, key) else {
                    return false;
                };
                entry.child_cleanup =
                    classify_exact_child_cleanup(entry, key, execution.as_ref().ok());
            }
        }

        if lock_state(&self.state).as_ref().is_some_and(|entry| {
            entry.key == key
                && entry.durable.as_ref().is_some_and(|custody| {
                    matches!(custody.settlement, DurableJournalSettlement::MayOwn(_))
                })
                && entry.child_cleanup.is_none()
        }) {
            // Exact child cleanup did not complete. Keep the worker and all recovery authority
            // available for a later same-runtime Destroy retry; process death is not namespace
            // cleanup evidence while PID 1 still owns the published namespace descriptor.
            return false;
        }

        let worker = {
            let mut state = lock_state(&self.state);
            let Ok(entry) = exact_entry_mut(&mut state, key) else {
                return false;
            };
            entry.worker.take()
        };
        if let Some(worker) = worker {
            match self
                .coordinator
                .settle_and_terminate_lifecycle_until(worker, deadline)
            {
                WorkerGenerationReap::Confirmed(proof) => {
                    // Process death alone does not destroy an anonymous network namespace while
                    // duplicated recovery descriptors still pin it. Consume those descriptors
                    // immediately after exact reap confirmation, before any fallible parent-link
                    // cleanup or later deadline check can retain the entry for retry.
                    let recovery = {
                        let mut state = lock_state(&self.state);
                        let Ok(entry) = exact_entry_mut(&mut state, key) else {
                            return false;
                        };
                        if entry.durable.is_none() {
                            drop(proof);
                            entry.recovery.take()
                        } else {
                            if entry.worker_cleanup.replace(proof).is_some() {
                                std::process::abort();
                            }
                            None
                        }
                    };
                    drop(recovery);
                }
                WorkerGenerationReap::Retained { ownership, .. } => {
                    let mut state = lock_state(&self.state);
                    if let Ok(entry) = exact_entry_mut(&mut state, key) {
                        entry.worker = Some(*ownership);
                    }
                    return false;
                }
            }
        }

        let parent_absent = {
            let mut state = lock_state(&self.state);
            let Ok(entry) = exact_entry_mut(&mut state, key) else {
                return false;
            };
            if entry.birth_may_exist.len() != entry.wireguard.len() {
                return false;
            }
            if entry.birth_may_exist.iter().all(|may_exist| !*may_exist) {
                true
            } else {
                let Ok(mut kernel) = BirthNamespaceKernel::connect(deadline) else {
                    return false;
                };
                let mut absent = true;
                for index in (0..entry.wireguard.len()).rev() {
                    if !entry.birth_may_exist[index] {
                        continue;
                    }
                    if kernel
                        .delete_owned_wireguard(&mut entry.wireguard[index], deadline)
                        .is_ok()
                    {
                        entry.birth_may_exist[index] = false;
                    } else {
                        absent = false;
                    }
                }
                absent && entry.birth_may_exist.iter().all(|may_exist| !*may_exist)
            }
        };
        if !parent_absent || deadline.ensure_remaining().is_err() {
            return false;
        }
        let durable_cleanup_ready = lock_state(&self.state)
            .as_ref()
            .filter(|entry| entry.key == key)
            .and_then(|entry| {
                entry.durable.as_ref().map(|custody| {
                    !matches!(custody.settlement, DurableJournalSettlement::MayOwn(_))
                        || (entry.child_cleanup.is_some() && entry.worker_cleanup.is_some())
                })
            });
        if let Some(cleanup_ready) = durable_cleanup_ready {
            if !cleanup_ready {
                return false;
            }
            let parent = ExactParentKernelAbsent::after_exact_parent_kernel_absence(key);
            if !self.settle_durable_cleanup(key, parent, deadline).await {
                return false;
            }
        }
        remove_exact_entry(&self.state, key)
    }

    fn restore_durable_handoff_terminal(
        &self,
        key: OpenLineageKey,
        selector: DurableHandoffTerminalSelector,
    ) {
        let mut state = lock_state(&self.state);
        let Ok(entry) = exact_entry_mut(&mut state, key) else {
            std::process::abort();
        };
        if entry.phase != OpenLeasePhase::DurableHandoffPending
            || entry.worker.is_some()
            || entry.durable_handoff_terminal.replace(selector).is_some()
        {
            std::process::abort();
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "both journal phases and exact manager removal remain one affine transaction"
    )]
    async fn settle_durable_cleanup(
        &self,
        key: OpenLineageKey,
        parent: ExactParentKernelAbsent,
        deadline: HardDeadline,
    ) -> bool {
        let Some(handle) = self.durable_ownership.as_ref() else {
            return false;
        };
        let (mut custody, recovery, child, worker) = {
            let mut state = lock_state(&self.state);
            let Ok(entry) = exact_entry_mut(&mut state, key) else {
                return false;
            };
            if entry.durable.is_none() || entry.recovery.is_none() {
                return false;
            }
            if entry
                .durable
                .as_ref()
                .is_none_or(|custody| custody_context_id(custody) != key.context_id)
            {
                return false;
            }
            let requires_cleanup_evidence = entry.durable.as_ref().is_some_and(|custody| {
                matches!(custody.settlement, DurableJournalSettlement::MayOwn(_))
            });
            if requires_cleanup_evidence
                && (entry.child_cleanup.is_none() || entry.worker_cleanup.is_none())
            {
                return false;
            }
            let Some(custody) = entry.durable.take() else {
                std::process::abort();
            };
            let Some(recovery) = entry.recovery.take() else {
                std::process::abort();
            };
            (
                custody,
                recovery,
                entry.child_cleanup.take(),
                entry.worker_cleanup.take(),
            )
        };
        if custody_context_id(&custody) != key.context_id {
            std::process::abort();
        }

        custody.settlement = match custody.settlement {
            DurableJournalSettlement::MayOwn(settlement) => {
                let (Some(child), Some(worker)) = (child, worker) else {
                    std::process::abort();
                };
                DurableJournalSettlement::CleanupProven(
                    ExactSameRuntimeCleanupProof::after_exact_worker_kernel_cleanup(
                        settlement, child, worker, parent,
                    ),
                )
            }
            settlement => settlement,
        };

        custody.settlement = match custody.settlement {
            DurableJournalSettlement::CleanupProven(proof) => {
                match handle.confirm_cleanup_until(proof, deadline) {
                    DurableCleanupOutcome::Confirmed(cleanup) => {
                        DurableJournalSettlement::CleanupConfirmed(cleanup)
                    }
                    DurableCleanupOutcome::Retained { proof, .. } => {
                        custody.settlement = DurableJournalSettlement::CleanupProven(proof);
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                }
            }
            settlement => settlement,
        };

        let Ok(pair) = crate::systemd_fdstore::BorrowedCustodyPair::new(
            recovery.restart_custody.borrowed_pidfd(),
            recovery.restart_custody.borrowed_network_namespace(),
        ) else {
            self.restore_durable_cleanup(key, custody, recovery);
            return false;
        };
        let Ok(binding) = pair.descriptor_binding() else {
            self.restore_durable_cleanup(key, custody, recovery);
            return false;
        };

        custody.settlement = match custody.settlement {
            DurableJournalSettlement::CleanupConfirmed(cleanup) => {
                let Some(baseline) = custody.attestation.removal_baseline() else {
                    custody.settlement = DurableJournalSettlement::CleanupConfirmed(cleanup);
                    self.restore_durable_cleanup(key, custody, recovery);
                    return false;
                };
                match crate::systemd_fdstore::remove_current_process_custody(
                    baseline,
                    custody.custody_name,
                    binding.clone(),
                    pair,
                    deadline,
                )
                .await
                {
                    Ok(proof) => {
                        if proof
                            .verify_exact_target(custody.custody_name, &binding)
                            .is_err()
                        {
                            custody.settlement =
                                DurableJournalSettlement::CleanupConfirmed(cleanup);
                            self.restore_durable_cleanup(key, custody, recovery);
                            return false;
                        }
                        DurableJournalSettlement::ManagerRemovalProven(
                            ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(
                                cleanup, proof,
                            ),
                        )
                    }
                    Err(crate::systemd_fdstore::RemovalFailure::BeforeSend { .. }) => {
                        custody.settlement = DurableJournalSettlement::CleanupConfirmed(cleanup);
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                    Err(crate::systemd_fdstore::RemovalFailure::ManagerMayHaveRemoved {
                        attempt_id,
                        ..
                    }) => {
                        custody.settlement = DurableJournalSettlement::RemovalAmbiguous {
                            cleanup,
                            attempt_id,
                        };
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                }
            }
            DurableJournalSettlement::RemovalAmbiguous {
                cleanup,
                attempt_id,
            } => match crate::systemd_fdstore::reconcile_current_process_removal(
                attempt_id,
                custody.custody_name,
                binding.clone(),
                pair,
                deadline,
            )
            .await
            {
                crate::systemd_fdstore::RemovalInventoryReconciliation::ExactRemoved(proof) => {
                    if proof
                        .verify_exact_target(custody.custody_name, &binding)
                        .is_err()
                    {
                        custody.settlement = DurableJournalSettlement::RemovalAmbiguous {
                            cleanup,
                            attempt_id,
                        };
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                    DurableJournalSettlement::ManagerRemovalProven(
                        ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(
                            cleanup, proof,
                        ),
                    )
                }
                crate::systemd_fdstore::RemovalInventoryReconciliation::ExactStillPresent(
                    evidence,
                ) => {
                    custody.settlement = DurableJournalSettlement::RemovalRetryAuthorized {
                        cleanup,
                        evidence: Box::new(evidence),
                    };
                    self.restore_durable_cleanup(key, custody, recovery);
                    return false;
                }
                crate::systemd_fdstore::RemovalInventoryReconciliation::Unresolved { .. } => {
                    custody.settlement = DurableJournalSettlement::RemovalAmbiguous {
                        cleanup,
                        attempt_id,
                    };
                    self.restore_durable_cleanup(key, custody, recovery);
                    return false;
                }
            },
            DurableJournalSettlement::RemovalRetryAuthorized { cleanup, evidence } => {
                match crate::systemd_fdstore::retry_current_process_removal(
                    &evidence,
                    custody.custody_name,
                    binding.clone(),
                    pair,
                    deadline,
                )
                .await
                {
                    Ok(proof) => {
                        if proof
                            .verify_exact_target(custody.custody_name, &binding)
                            .is_err()
                        {
                            custody.settlement = DurableJournalSettlement::RemovalRetryAuthorized {
                                cleanup,
                                evidence,
                            };
                            self.restore_durable_cleanup(key, custody, recovery);
                            return false;
                        }
                        DurableJournalSettlement::ManagerRemovalProven(
                            ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(
                                cleanup, proof,
                            ),
                        )
                    }
                    Err(crate::systemd_fdstore::RemovalFailure::BeforeSend { .. }) => {
                        custody.settlement =
                            DurableJournalSettlement::RemovalRetryAuthorized { cleanup, evidence };
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                    Err(crate::systemd_fdstore::RemovalFailure::ManagerMayHaveRemoved {
                        attempt_id,
                        ..
                    }) => {
                        custody.settlement = DurableJournalSettlement::RemovalAmbiguous {
                            cleanup,
                            attempt_id,
                        };
                        self.restore_durable_cleanup(key, custody, recovery);
                        return false;
                    }
                }
            }
            settlement @ DurableJournalSettlement::ManagerRemovalProven(_) => settlement,
            DurableJournalSettlement::MayOwn(_) | DurableJournalSettlement::CleanupProven(_) => {
                std::process::abort()
            }
        };

        let DurableJournalSettlement::ManagerRemovalProven(proof) = custody.settlement else {
            std::process::abort();
        };
        match handle.confirm_manager_absent_until(proof, deadline) {
            DurableManagerAbsentOutcome::Absent => {
                drop(recovery);
                true
            }
            DurableManagerAbsentOutcome::Retained { proof, .. } => {
                custody.settlement = DurableJournalSettlement::ManagerRemovalProven(proof);
                self.restore_durable_cleanup(key, custody, recovery);
                false
            }
        }
    }

    fn restore_durable_cleanup(
        &self,
        key: OpenLineageKey,
        custody: DurableLeaseCustody,
        recovery: WorkerRecoveryIdentitySource,
    ) {
        let mut state = lock_state(&self.state);
        let Ok(entry) = exact_entry_mut(&mut state, key) else {
            std::process::abort();
        };
        if entry.durable.is_some() || entry.recovery.is_some() {
            std::process::abort();
        }
        entry.durable = Some(custody);
        entry.recovery = Some(recovery);
    }

    async fn destroy_one(
        &self,
        binding: BackendBinding,
        value: BackendDestroy,
    ) -> Result<ConfirmedAbsent, BackendError> {
        let key = validate_destroy_binding(binding, value)?;
        let target_is_open = {
            let state = lock_state(&self.state);
            match state.as_ref() {
                Some(entry) if entry.key == key => true,
                None | Some(_) => false,
            }
        };
        let deadline = HardDeadline::at(binding.call_deadline.into_std())
            .map_err(|_| BackendError::CleanupIncomplete)?;
        if !target_is_open {
            return deadline
                .complete(ConfirmedAbsent)
                .map_err(|_| BackendError::CleanupIncomplete);
        }
        if self.cleanup_exact(key, deadline, true).await {
            deadline
                .complete(ConfirmedAbsent)
                .map_err(|_| BackendError::CleanupIncomplete)
        } else {
            Err(BackendError::CleanupIncomplete)
        }
    }
}

impl AsyncLeaseBackend for FunctionalAlphaLeaseBackend {
    fn prepare(
        self: Arc<Self>,
        request: BackendRequest<PrepareLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<PreparedKernelLease>>> {
        let (completion, value) = request.into_parts();
        let binding = completion.binding();
        Box::pin(async move { completion.complete(self.prepare_one(binding, value).await) })
    }

    fn activate(
        self: Arc<Self>,
        request: BackendRequest<ActivateLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>> {
        let (completion, value) = request.into_parts();
        let binding = completion.binding();
        Box::pin(async move { completion.complete(self.activate_one(binding, value).await) })
    }

    fn probe(
        self: Arc<Self>,
        request: BackendRequest<BackendProbe>,
    ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>> {
        let (completion, value) = request.into_parts();
        let binding = completion.binding();
        Box::pin(async move { completion.complete(self.probe_one(binding, value).await) })
    }

    fn destroy(
        self: Arc<Self>,
        request: BackendRequest<BackendDestroy>,
    ) -> BackendFuture<BackendCompletion<ConfirmedAbsent>> {
        let (completion, value) = request.into_parts();
        let binding = completion.binding();
        Box::pin(async move { completion.complete(self.destroy_one(binding, value).await) })
    }

    fn acquire_transport_socket(
        self: Arc<Self>,
        request: BackendRequest<AcquireTransportSocket>,
    ) -> BackendFuture<BackendCompletion<std::os::fd::OwnedFd>> {
        let (completion, _) = request.into_parts();
        Box::pin(async move { completion.complete(Err(BackendError::Unavailable)) })
    }

    fn transport_socket_supported(
        self: Arc<Self>,
        request: BackendRuntimeRequest,
    ) -> BackendFuture<BackendRuntimeCompletion<bool>> {
        Box::pin(async move { request.complete(Ok(false)) })
    }

    fn shutdown(
        self: Arc<Self>,
        request: BackendRuntimeRequest,
    ) -> BackendFuture<BackendRuntimeCompletion<()>> {
        Box::pin(async move {
            let deadline = HardDeadline::at(request.binding().call_deadline.into_std())
                .map_err(|_| BackendError::CleanupIncomplete);
            let result = match deadline {
                Err(error) => Err(error),
                Ok(deadline) => {
                    let key = lock_state(&self.state).as_ref().map(|entry| entry.key);
                    if let Some(key) = key {
                        if !self.cleanup_exact(key, deadline, true).await {
                            return request.complete(Err(BackendError::CleanupIncomplete));
                        }
                    }
                    if self.coordinator.shutdown_until(deadline).await == ShutdownStatus::Confirmed
                        && lock_state(&self.state).is_none()
                    {
                        Ok(())
                    } else {
                        Err(BackendError::CleanupIncomplete)
                    }
                }
            };
            request.complete(result)
        })
    }
}

fn current_boottime_nanos() -> Result<u64, BackendError> {
    const NANOS_PER_SECOND: u64 = 1_000_000_000;
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| BackendError::Unavailable)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| BackendError::Unavailable)?;
    if nanoseconds >= NANOS_PER_SECOND {
        return Err(BackendError::Unavailable);
    }
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(BackendError::Unavailable)
}

const fn boottime_lineage_is_well_formed(lineage: BackendLineage) -> bool {
    lineage.setup_expires_at_boottime_ns != 0
        && lineage.hard_expires_at_boottime_ns >= lineage.setup_expires_at_boottime_ns
}

const fn boottime_setup_and_hard_are_live(lineage: BackendLineage, now_ns: u64) -> bool {
    now_ns < lineage.setup_expires_at_boottime_ns && now_ns < lineage.hard_expires_at_boottime_ns
}

fn ensure_setup_and_hard_are_live(lineage: BackendLineage) -> Result<(), BackendError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    let now_boottime_ns = current_boottime_nanos()?;
    if now_unix >= lineage.setup_expires_at_unix
        || now_unix >= lineage.hard_expires_at_unix
        || !boottime_setup_and_hard_are_live(lineage, now_boottime_ns)
    {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn validate_prepare_batch_binding(
    binding: BackendBinding,
    value: &PrepareLeaseBatch,
) -> Result<(OpenLineageKey, ContextRole, Vec<RoutingLeasePlan>, Duration), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let context_role = ContextRole::try_from(value.role).map_err(|_| BackendError::Invalid)?;
    validate_functional_lease_batch_shape(context_role, &value.leases)?;
    if binding.action != BackendAction::Prepare
        || binding.phase != BackendPhase::PreparePending
        || binding.operation_kind != OperationKind::Prepare
        || binding.prior_phase.is_some()
        || binding.operation_sequence == 0
        || binding.operation_generation != lineage.backend_generation
        || binding.request_id != lineage.prepare_request_id
        || binding.request_digest != lineage.prepare_operation_digest
        || context_id != lineage.context_id
        || context_id.iter().all(|byte| *byte == 0)
        || lineage.helper_runtime_id.iter().all(|byte| *byte == 0)
        || lineage.backend_generation == 0
        || value.setup_expires_at_unix != lineage.setup_expires_at_unix
        || value.hard_expires_at_unix != lineage.hard_expires_at_unix
        || value.hard_expires_at_unix < value.setup_expires_at_unix
        || !boottime_lineage_is_well_formed(lineage)
    {
        return Err(BackendError::Invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    let boottime_now_ns = current_boottime_nanos()?;
    let ttl_ns = lineage
        .hard_expires_at_boottime_ns
        .checked_sub(boottime_now_ns)
        .filter(|ttl| *ttl != 0)
        .ok_or(BackendError::Invalid)?;
    let context_ttl = Duration::from_nanos(ttl_ns);
    if value.setup_expires_at_unix <= now
        || lineage.setup_expires_at_boottime_ns <= boottime_now_ns
        || context_ttl > DEFAULT_MAX_TTL
    {
        return Err(BackendError::Invalid);
    }
    Ok((
        OpenLineageKey::from(lineage),
        context_role,
        value.leases.clone(),
        context_ttl,
    ))
}

/// Reconstruct the exact wire intent accepted by Bind from the immutable engine lineage and the
/// subsequently correlated canonical Prepare batch.
fn reconstruct_durable_prepare_intent(
    lineage: BackendLineage,
    value: &PrepareLeaseBatch,
) -> Result<PrepareIntent, BackendError> {
    if value.route_context_id.as_slice() != lineage.context_id.as_slice()
        || value.setup_expires_at_unix != lineage.setup_expires_at_unix
        || value.hard_expires_at_unix != lineage.hard_expires_at_unix
        || lineage.helper_runtime_id.iter().all(|byte| *byte == 0)
        || lineage.prepare_request_id.iter().all(|byte| *byte == 0)
        || lineage
            .prepare_operation_digest
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(BackendError::Invalid);
    }
    Ok(PrepareIntent {
        route_context_id: value.route_context_id.clone(),
        prepare_request_id: lineage.prepare_request_id.to_vec(),
        prepare_operation_digest: lineage.prepare_operation_digest.to_vec(),
        setup_expires_at_unix: value.setup_expires_at_unix,
        hard_expires_at_unix: value.hard_expires_at_unix,
        closed_plan: Some(ClosedPreparePlan {
            context_role: value.role,
            leases: value.leases.clone(),
        }),
    })
}

fn validate_activate_batch_binding(
    binding: BackendBinding,
    value: &ActivateLeaseBatch,
) -> Result<(OpenLineageKey, Vec<volparossa_routing::LeaseActivation>), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let context = value
        .leases
        .first()
        .and_then(|lease| functional_lease_role_for_wireguard(lease.role))
        .map(|role| role.context)
        .ok_or(BackendError::Invalid)?;
    let plans = value
        .leases
        .iter()
        .map(|lease| RoutingLeasePlan {
            path_id: lease.path_id,
            role: lease.role,
        })
        .collect::<Vec<_>>();
    validate_functional_lease_batch_shape(context, &plans)?;
    if binding.action != BackendAction::Activate
        || binding.phase != BackendPhase::Prepared
        || binding.operation_kind != OperationKind::Activate
        || binding.prior_phase != Some(ContextPhase::Prepared)
        || binding.operation_sequence == 0
        || binding.operation_generation != lineage.backend_generation
        || binding.request_id.iter().all(|byte| *byte == 0)
        || binding.request_digest.iter().all(|byte| *byte == 0)
        || lineage.helper_runtime_id.iter().all(|byte| *byte == 0)
        || lineage.context_id.iter().all(|byte| *byte == 0)
        || lineage.backend_generation == 0
        || lineage.prepare_request_id.iter().all(|byte| *byte == 0)
        || lineage
            .prepare_operation_digest
            .iter()
            .all(|byte| *byte == 0)
        || lineage.setup_expires_at_unix == 0
        || lineage.hard_expires_at_unix < lineage.setup_expires_at_unix
        || !boottime_lineage_is_well_formed(lineage)
        || context_id != lineage.context_id
        || value.context_handle.len() != HELPER_HANDLE_BYTES
        || value.context_handle.iter().all(|byte| *byte == 0)
        || value.leases.iter().any(|activation| {
            activation.lease_handle.len() != HELPER_HANDLE_BYTES
                || activation.lease_handle.iter().all(|byte| *byte == 0)
                || !(1..=8).contains(&activation.path_id)
                || activation.peer_public_key.len() != 32
                || activation.peer_public_key.iter().all(|byte| *byte == 0)
                || activation.signed_relay_reservation.is_empty()
                || parse_public_udp_endpoint(activation.peer_endpoint.as_ref()).is_none()
        })
        || value.leases.iter().enumerate().any(|(index, activation)| {
            value.leases[index + 1..]
                .iter()
                .any(|other| other.lease_handle == activation.lease_handle)
        })
    {
        return Err(BackendError::Invalid);
    }
    match context {
        ContextRole::Client | ContextRole::Exit => {
            let [activation] = value.leases.as_slice() else {
                return Err(BackendError::Invalid);
            };
            if activation.maximum_up_mbps != 0
                || activation.maximum_down_mbps != 0
                || !activation.signed_client_relay_request.is_empty()
            {
                return Err(BackendError::Invalid);
            }
        }
        ContextRole::Relay => {
            let [client, exit] = value.leases.as_slice() else {
                return Err(BackendError::Invalid);
            };
            if client.maximum_up_mbps == 0
                || client.maximum_down_mbps == 0
                || exit.maximum_up_mbps != client.maximum_up_mbps
                || exit.maximum_down_mbps != client.maximum_down_mbps
                || client.signed_client_relay_request.is_empty()
                || !exit.signed_client_relay_request.is_empty()
                || client.signed_relay_reservation != exit.signed_relay_reservation
            {
                return Err(BackendError::Invalid);
            }
        }
        ContextRole::Unspecified => return Err(BackendError::Invalid),
    }
    ensure_setup_and_hard_are_live(lineage)?;
    Ok((OpenLineageKey::from(lineage), value.leases.clone()))
}

fn validate_probe_batch_binding(
    binding: BackendBinding,
    value: &BackendProbe,
) -> Result<(OpenLineageKey, Vec<volparossa_routing::LeaseCommit>, u64), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .commit
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let context = value
        .commit
        .leases
        .first()
        .and_then(|lease| functional_lease_role_for_wireguard(lease.role))
        .map(|role| role.context)
        .ok_or(BackendError::Invalid)?;
    let plans = value
        .commit
        .leases
        .iter()
        .map(|lease| RoutingLeasePlan {
            path_id: lease.path_id,
            role: lease.role,
        })
        .collect::<Vec<_>>();
    validate_functional_lease_batch_shape(context, &plans)?;
    if binding.action != BackendAction::Probe
        || binding.phase != BackendPhase::Activated
        || binding.operation_kind != OperationKind::Probe
        || binding.prior_phase != Some(ContextPhase::Activated)
        || binding.operation_sequence == 0
        || binding.operation_generation == 0
        || binding.request_id.iter().all(|byte| *byte == 0)
        || binding.request_digest.iter().all(|byte| *byte == 0)
        || lineage.helper_runtime_id.iter().all(|byte| *byte == 0)
        || lineage.context_id.iter().all(|byte| *byte == 0)
        || lineage.backend_generation == 0
        || lineage.prepare_request_id.iter().all(|byte| *byte == 0)
        || lineage
            .prepare_operation_digest
            .iter()
            .all(|byte| *byte == 0)
        || lineage.setup_expires_at_unix == 0
        || lineage.hard_expires_at_unix < lineage.setup_expires_at_unix
        || !boottime_lineage_is_well_formed(lineage)
        || context_id != lineage.context_id
        || value.commit.context_handle.len() != HELPER_HANDLE_BYTES
        || value.commit.context_handle.iter().all(|byte| *byte == 0)
        || value.commit.leases.iter().any(|commit| {
            commit.lease_handle.len() != HELPER_HANDLE_BYTES
                || commit.lease_handle.iter().all(|byte| *byte == 0)
                || !(1..=8).contains(&commit.path_id)
        })
        || value
            .commit
            .leases
            .iter()
            .enumerate()
            .any(|(index, commit)| {
                value.commit.leases[index + 1..]
                    .iter()
                    .any(|other| other.lease_handle == commit.lease_handle)
            })
        || value.activated_at_unix == 0
        || value.activated_at_unix >= lineage.setup_expires_at_unix
    {
        return Err(BackendError::Invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    if value.activated_at_unix > now
        || now >= lineage.hard_expires_at_unix
        || current_boottime_nanos()? >= lineage.hard_expires_at_boottime_ns
    {
        return Err(BackendError::Invalid);
    }
    Ok((
        OpenLineageKey::from(lineage),
        value.commit.leases.clone(),
        value.activated_at_unix,
    ))
}

#[cfg(test)]
fn validate_prepare_binding(
    binding: BackendBinding,
    value: &PrepareLeaseBatch,
) -> Result<
    (
        OpenLineageKey,
        FunctionalLeaseRole,
        RoutingLeasePlan,
        Duration,
    ),
    BackendError,
> {
    let (key, context, leases, ttl) = validate_prepare_batch_binding(binding, value)?;
    let [lease] = leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    let role = functional_lease_role(context as i32, lease.role).ok_or(BackendError::Invalid)?;
    Ok((key, role, lease.clone(), ttl))
}

#[cfg(test)]
fn validate_activate_binding(
    binding: BackendBinding,
    value: &ActivateLeaseBatch,
) -> Result<(OpenLineageKey, volparossa_routing::LeaseActivation), BackendError> {
    let (key, leases) = validate_activate_batch_binding(binding, value)?;
    let [lease] = leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    Ok((key, lease.clone()))
}

#[cfg(test)]
fn validate_probe_binding(
    binding: BackendBinding,
    value: &BackendProbe,
) -> Result<(OpenLineageKey, volparossa_routing::LeaseCommit, u64), BackendError> {
    let (key, leases, activated_at_unix) = validate_probe_batch_binding(binding, value)?;
    let [lease] = leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    Ok((key, lease.clone(), activated_at_unix))
}

fn validate_destroy_binding(
    binding: BackendBinding,
    value: BackendDestroy,
) -> Result<OpenLineageKey, BackendError> {
    let lineage = binding.lineage;
    let request_correlation_is_valid = if binding.operation_kind == OperationKind::Shutdown {
        binding.request_id == [0; 16] && binding.request_digest == [0; 32]
    } else {
        binding.request_id.iter().any(|byte| *byte != 0)
            && binding.request_digest.iter().any(|byte| *byte != 0)
    };
    if binding.action != BackendAction::Destroy
        || binding.phase != BackendPhase::Quarantined
        || binding.operation_sequence == 0
        || binding.operation_generation == 0
        || !destroy_operation_shape_is_valid(binding)
        || !request_correlation_is_valid
        || lineage.helper_runtime_id.iter().all(|byte| *byte == 0)
        || lineage.context_id.iter().all(|byte| *byte == 0)
        || lineage.backend_generation == 0
        || lineage.prepare_request_id.iter().all(|byte| *byte == 0)
        || lineage
            .prepare_operation_digest
            .iter()
            .all(|byte| *byte == 0)
        || lineage.setup_expires_at_unix == 0
        || lineage.hard_expires_at_unix < lineage.setup_expires_at_unix
        || !boottime_lineage_is_well_formed(lineage)
        || value.context_id != lineage.context_id
        || value.backend_generation != lineage.backend_generation
    {
        return Err(BackendError::Invalid);
    }
    Ok(OpenLineageKey::from(lineage))
}

const fn destroy_operation_shape_is_valid(binding: BackendBinding) -> bool {
    matches!(
        (binding.operation_kind, binding.prior_phase),
        (OperationKind::Prepare, None)
            | (OperationKind::Activate, Some(ContextPhase::Prepared))
            | (OperationKind::Probe, Some(ContextPhase::Activated))
            | (OperationKind::Acquire, Some(ContextPhase::Committed))
            | (OperationKind::Destroy, Some(_))
            | (
                OperationKind::Reconcile,
                None | Some(ContextPhase::Prepared | ContextPhase::Quarantined),
            )
            | (
                OperationKind::Reap,
                None | Some(
                    ContextPhase::Prepared
                        | ContextPhase::Activated
                        | ContextPhase::Committed
                        | ContextPhase::Quarantined
                ),
            )
            | (OperationKind::Cleanup | OperationKind::Shutdown, _)
    )
}

fn functional_lease_role(context: i32, wireguard: i32) -> Option<FunctionalLeaseRole> {
    let context = ContextRole::try_from(context).ok()?;
    let wireguard = WireguardRole::try_from(wireguard).ok()?;
    let role = functional_lease_role_for_wireguard(wireguard as i32)?;
    (role.context == context).then_some(role)
}

const fn internal_context_role(context: ContextRole) -> Option<InternalContextRole> {
    match context {
        ContextRole::Client => Some(InternalContextRole::Client),
        ContextRole::Relay => Some(InternalContextRole::Relay),
        ContextRole::Exit => Some(InternalContextRole::Exit),
        ContextRole::Unspecified => None,
    }
}

fn functional_lease_role_for_wireguard(wireguard: i32) -> Option<FunctionalLeaseRole> {
    match WireguardRole::try_from(wireguard) {
        Ok(WireguardRole::Client) => Some(FunctionalLeaseRole {
            context: ContextRole::Client,
            wireguard: WireguardRole::Client,
            internal_context: InternalContextRole::Client,
            internal_endpoint: InternalEndpointRole::Client,
        }),
        Ok(WireguardRole::RelayClient) => Some(FunctionalLeaseRole {
            context: ContextRole::Relay,
            wireguard: WireguardRole::RelayClient,
            internal_context: InternalContextRole::Relay,
            internal_endpoint: InternalEndpointRole::RelayClient,
        }),
        Ok(WireguardRole::RelayExit) => Some(FunctionalLeaseRole {
            context: ContextRole::Relay,
            wireguard: WireguardRole::RelayExit,
            internal_context: InternalContextRole::Relay,
            internal_endpoint: InternalEndpointRole::RelayExit,
        }),
        Ok(WireguardRole::Exit) => Some(FunctionalLeaseRole {
            context: ContextRole::Exit,
            wireguard: WireguardRole::Exit,
            internal_context: InternalContextRole::Exit,
            internal_endpoint: InternalEndpointRole::Exit,
        }),
        Ok(WireguardRole::Unspecified) | Err(_) => None,
    }
}

fn validate_functional_lease_batch_shape(
    context: ContextRole,
    leases: &[RoutingLeasePlan],
) -> Result<(), BackendError> {
    match context {
        ContextRole::Client | ContextRole::Exit => {
            if leases.is_empty()
                || leases.iter().any(|lease| {
                    functional_lease_role(context as i32, lease.role).is_none()
                        || !(1..=8).contains(&lease.path_id)
                })
            {
                return Err(BackendError::Invalid);
            }
            if leases.len() == 1 {
                Ok(())
            } else {
                Err(BackendError::Unavailable)
            }
        }
        ContextRole::Relay => {
            let [client, exit] = leases else {
                return Err(BackendError::Invalid);
            };
            if client.path_id == exit.path_id
                && (1..=8).contains(&client.path_id)
                && client.role == WireguardRole::RelayClient as i32
                && exit.role == WireguardRole::RelayExit as i32
            {
                Ok(())
            } else {
                Err(BackendError::Invalid)
            }
        }
        ContextRole::Unspecified => Err(BackendError::Invalid),
    }
}

fn process_owned_resource(
    key: OpenLineageKey,
    lease: &RoutingLeasePlan,
) -> Result<LiveWireguardLeaseOwner, BackendError> {
    let role = functional_lease_role_for_wireguard(lease.role).ok_or(BackendError::Invalid)?;
    let specification =
        WireguardLeaseSpec::derive(key.context_id, role.context, lease.path_id, lease.role)
            .map_err(|_| BackendError::Invalid)?;
    let marker = ownership_marker(key, lease);
    let alias = format!(
        "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{marker}",
        specification.interface()
    );
    let resource = DurableWireguardResource::from_authenticated_worker_binding(
        key.context_id,
        role.context,
        lease.path_id,
        lease.role,
        alias,
        key.setup_expires_at_unix,
        key.hard_expires_at_unix,
    )
    .ok_or(BackendError::Invalid)?;
    Ok(LiveWireguardLeaseOwner::claim(resource))
}

fn ownership_marker(key: OpenLineageKey, lease: &RoutingLeasePlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MARKER_DOMAIN);
    bind_lineage(&mut hasher, key);
    hasher.update(&lease.path_id.to_be_bytes());
    hasher.update(&lease.role.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

fn worker_request_id(key: OpenLineageKey, stage: u8) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update(&[stage]);
    bind_lineage(&mut hasher, key);
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    if request_id.iter().all(|byte| *byte == 0) {
        request_id[15] = stage.max(1);
    }
    request_id
}

fn worker_attempt_request_id(key: OpenLineageKey, stage: u8, binding: BackendBinding) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update(&[stage]);
    bind_lineage(&mut hasher, key);
    hasher.update(&binding.operation_sequence.to_be_bytes());
    hasher.update(&binding.operation_generation.to_be_bytes());
    hasher.update(&binding.request_id);
    hasher.update(&binding.request_digest);
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    if request_id.iter().all(|byte| *byte == 0) {
        request_id[15] = stage.max(1);
    }
    request_id
}

fn bind_lineage(hasher: &mut blake3::Hasher, key: OpenLineageKey) {
    hasher.update(&key.helper_runtime_id);
    hasher.update(&key.context_id);
    hasher.update(&key.backend_generation.to_be_bytes());
    hasher.update(&key.prepare_request_id);
    hasher.update(&key.prepare_operation_digest);
    hasher.update(&key.setup_expires_at_unix.to_be_bytes());
    hasher.update(&key.hard_expires_at_unix.to_be_bytes());
    hasher.update(&key.setup_expires_at_boottime_ns.to_be_bytes());
    hasher.update(&key.hard_expires_at_boottime_ns.to_be_bytes());
}

fn internal_prepare_batch_plan(
    resources: &[LiveWireguardLeaseOwner],
    key: OpenLineageKey,
    leases: &[RoutingLeasePlan],
) -> Result<PrepareLeases, BackendError> {
    if resources.len() != leases.len() || !(1..=2).contains(&leases.len()) {
        return Err(BackendError::Invalid);
    }
    let leases = resources
        .iter()
        .zip(leases)
        .map(|(owner, lease)| {
            let resource = owner.resource();
            let role =
                functional_lease_role_for_wireguard(lease.role).ok_or(BackendError::Invalid)?;
            if resource.key()
                != (
                    u8::try_from(lease.path_id).map_err(|_| BackendError::Invalid)?,
                    lease.role,
                )
            {
                return Err(BackendError::Invalid);
            }
            Ok(InternalLeasePlan {
                path_id: lease.path_id,
                role: role.internal_endpoint as i32,
                local_overlay_address: Some(InternalIpPrefix {
                    address: resource.local_address().octets().to_vec(),
                    prefix_length: 128,
                }),
                setup_expires_at_unix: key.setup_expires_at_unix,
                hard_expires_at_unix: key.hard_expires_at_unix,
                ownership_alias: resource.ownership_alias().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, BackendError>>()?;
    Ok(PrepareLeases {
        route_context_id: key.context_id.to_vec(),
        leases,
    })
}

#[cfg(test)]
fn internal_prepare_plan(
    resource: &DurableWireguardResource,
    key: OpenLineageKey,
    lease: &RoutingLeasePlan,
) -> PrepareLeases {
    let role = functional_lease_role_for_wireguard(lease.role)
        .expect("test resource has one validated functional role");
    PrepareLeases {
        route_context_id: key.context_id.to_vec(),
        leases: vec![InternalLeasePlan {
            path_id: lease.path_id,
            role: role.internal_endpoint as i32,
            local_overlay_address: Some(InternalIpPrefix {
                address: resource.local_address().octets().to_vec(),
                prefix_length: 128,
            }),
            setup_expires_at_unix: key.setup_expires_at_unix,
            hard_expires_at_unix: key.hard_expires_at_unix,
            ownership_alias: resource.ownership_alias().to_owned(),
        }],
    }
}

fn verified_internal_activate_batch_plan(
    replay_cache: &Mutex<ReplayCache>,
    resources: &[LiveWireguardLeaseOwner],
    key: OpenLineageKey,
    prepared: &[PreparedWorkerLease],
    underlay: UnderlayCandidate,
    activations: &[volparossa_routing::LeaseActivation],
    now_ms: u64,
) -> Result<ActivateLeases, BackendError> {
    if resources.len() != prepared.len()
        || prepared.len() != activations.len()
        || !(1..=2).contains(&prepared.len())
    {
        return Err(BackendError::Invalid);
    }
    let context = functional_lease_role_for_wireguard(prepared[0].role)
        .map(|role| role.context)
        .ok_or(BackendError::Invalid)?;
    let plans = prepared
        .iter()
        .map(|lease| RoutingLeasePlan {
            path_id: lease.path_id,
            role: lease.role,
        })
        .collect::<Vec<_>>();
    if validate_functional_lease_batch_shape(context, &plans).is_err()
        || prepared
            .iter()
            .zip(activations)
            .any(|(prepared, activation)| {
                (prepared.path_id, prepared.role) != (activation.path_id, activation.role)
            })
    {
        return Err(BackendError::Invalid);
    }

    let mut replay_guard = lock_replay_cache(replay_cache);
    let mut replay_keys = Vec::with_capacity(5);
    let result = (|| {
        let authority = verify_activation_authority(
            context,
            key,
            prepared,
            activations,
            now_ms,
            &mut replay_guard,
            &mut replay_keys,
        )?;
        let endpoints = verified_activation_endpoints(&authority, prepared, underlay, activations)?;
        project_internal_activation_batch(
            resources,
            key,
            prepared,
            underlay,
            activations,
            &endpoints,
        )
    })();

    if result.is_err() {
        rollback_replay_entries(&mut replay_guard, &replay_keys);
    }
    result
}

struct VerifiedActivationAuthority {
    context: ContextRole,
    request: Option<VerifiedControlMessage<RelayReservationRequest>>,
    relay: VerifiedControlMessage<RelayReservation>,
    exit: VerifiedControlMessage<RelayAuthorization>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the verifier binds the complete immutable route authority and replay transaction"
)]
fn verify_activation_authority(
    context: ContextRole,
    key: OpenLineageKey,
    prepared: &[PreparedWorkerLease],
    activations: &[volparossa_routing::LeaseActivation],
    now_ms: u64,
    replay_cache: &mut ReplayCache,
    replay_keys: &mut Vec<([u8; 32], [u8; 32])>,
) -> Result<VerifiedActivationAuthority, BackendError> {
    let (request, capability, exit_reservation) = if context == ContextRole::Relay {
        let [client, exit] = activations else {
            return Err(BackendError::Invalid);
        };
        if client.signed_client_relay_request.is_empty()
            || !exit.signed_client_relay_request.is_empty()
        {
            return Err(BackendError::Invalid);
        }
        let verified = verify_control_message::<RelayReservationRequest>(
            &client.signed_client_relay_request,
            now_ms,
            TimePolicy::default(),
            replay_cache,
        )
        .map_err(|error| protocol_backend_error(&error))?;
        replay_keys.push((*verified.sender_id(), *verified.nonce()));
        let verified_capability = verify_control_message::<ClientSessionCapability>(
            &verified.message().client_session_capability,
            now_ms,
            TimePolicy::default(),
            replay_cache,
        )
        .map_err(|error| protocol_backend_error(&error))?;
        replay_keys.push((
            *verified_capability.sender_id(),
            *verified_capability.nonce(),
        ));
        let verified_exit_reservation = verify_control_message::<ExitReservation>(
            &verified.message().exit_reservation,
            now_ms,
            TimePolicy::default(),
            replay_cache,
        )
        .map_err(|error| protocol_backend_error(&error))?;
        replay_keys.push((
            *verified_exit_reservation.sender_id(),
            *verified_exit_reservation.nonce(),
        ));
        (
            Some(verified),
            Some(verified_capability),
            Some(verified_exit_reservation),
        )
    } else {
        (None, None, None)
    };
    let (relay, exit) = verify_relay_reservation(
        &activations[0].signed_relay_reservation,
        now_ms,
        TimePolicy::default(),
        replay_cache,
    )
    .map_err(|error| {
        rollback_replay_entries(replay_cache, replay_keys);
        protocol_backend_error(&error)
    })?;
    replay_keys.push((*relay.sender_id(), *relay.nonce()));
    replay_keys.push((*exit.sender_id(), *exit.nonce()));

    let relay_message = relay.message();
    let hard_expires_at_ms = unix_seconds_to_milliseconds(key.hard_expires_at_unix)?;
    if activations.iter().skip(1).any(|activation| {
        activation.signed_relay_reservation != activations[0].signed_relay_reservation
    }) || relay_message.route_context_id.as_slice() != key.context_id
        || relay_message.path_id != prepared[0].path_id
        || prepared
            .iter()
            .any(|lease| lease.path_id != relay_message.path_id)
        || relay.expires_at_ms() < hard_expires_at_ms
        || exit.expires_at_ms() < hard_expires_at_ms
        || !signer_matches_peer_id(relay.sender_public_key(), &relay_message.relay_peer_id)
        || !signer_matches_peer_id(exit.sender_public_key(), &exit.message().exit_peer_id)
        || relay.sender_public_key() == exit.sender_public_key()
    {
        return Err(BackendError::Invalid);
    }
    if context == ContextRole::Relay
        && !verified_relay_request_scope(
            request.as_ref().ok_or(BackendError::Invalid)?,
            capability.as_ref().ok_or(BackendError::Invalid)?,
            exit_reservation.as_ref().ok_or(BackendError::Invalid)?,
            &relay,
            &exit,
        )
    {
        return Err(BackendError::Invalid);
    }
    Ok(VerifiedActivationAuthority {
        context,
        request,
        relay,
        exit,
    })
}

fn verified_relay_request_scope(
    request: &VerifiedControlMessage<RelayReservationRequest>,
    capability: &VerifiedControlMessage<ClientSessionCapability>,
    exit_reservation: &VerifiedControlMessage<ExitReservation>,
    relay: &VerifiedControlMessage<RelayReservation>,
    authorization: &VerifiedControlMessage<RelayAuthorization>,
) -> bool {
    let request_message = request.message();
    let capability_message = capability.message();
    let exit_message = exit_reservation.message();
    let authorization_message = authorization.message();
    request.sender_public_key().as_slice() == capability_message.client_session_public_key
        && capability.sender_public_key() == exit_reservation.sender_public_key()
        && exit_reservation.sender_public_key() == authorization.sender_public_key()
        && signer_matches_peer_id(
            exit_reservation.sender_public_key(),
            &exit_message.exit_peer_id,
        )
        && request_message.client_session_id == capability_message.client_session_id
        && request_message.exit_authorization == relay.message().exit_authorization
        && request_message.created_at_ms >= capability_message.created_at_ms
        && request_message.expires_at_ms <= capability_message.expires_at_ms
        && request_message.created_at_ms >= authorization_message.created_at_ms
        && request_message.expires_at_ms <= authorization_message.expires_at_ms
        && same_capability_exit_scope(capability_message, exit_message)
        && same_authorization_exit_scope(authorization_message, exit_message, capability_message)
}

fn same_capability_exit_scope(
    capability: &ClientSessionCapability,
    exit: &ExitReservation,
) -> bool {
    capability.reservation_id == exit.reservation_id
        && capability.route_context_id == exit.route_context_id
        && capability.client_session_id == exit.client_session_id
        && capability.client_session_public_key == exit.client_session_public_key
        && capability.exit_node_id == exit.exit_node_id
        && capability.exit_peer_id == exit.exit_peer_id
        && capability.exit_boot_id == exit.exit_boot_id
        && capability.control_relay_node_id == exit.control_relay_node_id
        && capability.control_relay_peer_id == exit.control_relay_peer_id
        && capability.policy_hash == exit.policy_hash
        && capability.allowed_transports == exit.allowed_transports
        && capability.reserved_up_mbps == exit.reserved_up_mbps
        && capability.reserved_down_mbps == exit.reserved_down_mbps
        && capability.maximum_paths >= exit.maximum_paths
        && capability.created_at_ms == exit.created_at_ms
        && capability.expires_at_ms == exit.expires_at_ms
        && capability.capability_id == exit.capability_id
}

fn same_authorization_exit_scope(
    authorization: &RelayAuthorization,
    exit: &ExitReservation,
    capability: &ClientSessionCapability,
) -> bool {
    authorization.reservation_id == exit.reservation_id
        && authorization.route_context_id == exit.route_context_id
        && authorization.path_id <= capability.probe_permit_limit
        && authorization.exit_node_id == exit.exit_node_id
        && authorization.exit_peer_id == exit.exit_peer_id
        && authorization.client_session_id == exit.client_session_id
        && authorization.client_session_public_key == exit.client_session_public_key
        && authorization.allowed_transports == exit.allowed_transports
        && authorization.maximum_up_mbps == exit.reserved_up_mbps
        && authorization.maximum_down_mbps == exit.reserved_down_mbps
        && authorization.policy_hash == exit.policy_hash
        && authorization.created_at_ms == exit.created_at_ms
        && authorization.expires_at_ms == exit.expires_at_ms
        && authorization.capability_id == exit.capability_id
        && authorization.exit_boot_id == exit.exit_boot_id
        && authorization.hold_id == exit.hold_id
        && authorization.finalize_id == exit.finalize_id
        && authorization.control_relay_node_id == exit.control_relay_node_id
        && authorization.control_relay_peer_id == exit.control_relay_peer_id
}

fn verified_activation_endpoints(
    authority: &VerifiedActivationAuthority,
    prepared: &[PreparedWorkerLease],
    underlay: UnderlayCandidate,
    activations: &[volparossa_routing::LeaseActivation],
) -> Result<Vec<VerifiedWireguardEndpoint>, BackendError> {
    match authority.context {
        ContextRole::Client => {
            let [prepared] = prepared else {
                return Err(BackendError::Invalid);
            };
            if authority
                .relay
                .message()
                .client_wireguard_public_key
                .as_slice()
                != prepared.public_key
            {
                return Err(BackendError::Invalid);
            }
            authority
                .relay
                .message()
                .relay_client_wireguard_endpoint
                .as_ref()
                .and_then(verified_wireguard_endpoint)
                .map(|endpoint| vec![endpoint])
                .ok_or(BackendError::Invalid)
        }
        ContextRole::Exit => {
            let [prepared] = prepared else {
                return Err(BackendError::Invalid);
            };
            let signed_local = authority
                .exit
                .message()
                .exit_wireguard_endpoint
                .as_ref()
                .and_then(verified_wireguard_endpoint)
                .ok_or(BackendError::Invalid)?;
            if (
                signed_local.public_key,
                signed_local.address,
                signed_local.port,
            ) != (prepared.public_key, underlay.address, prepared.listen_port)
            {
                return Err(BackendError::Invalid);
            }
            authority
                .relay
                .message()
                .relay_exit_wireguard_endpoint
                .as_ref()
                .and_then(verified_wireguard_endpoint)
                .map(|endpoint| vec![endpoint])
                .ok_or(BackendError::Invalid)
        }
        ContextRole::Relay => {
            verified_relay_activation_endpoints(authority, prepared, underlay, activations)
        }
        ContextRole::Unspecified => Err(BackendError::Invalid),
    }
}

fn verified_relay_activation_endpoints(
    authority: &VerifiedActivationAuthority,
    prepared: &[PreparedWorkerLease],
    underlay: UnderlayCandidate,
    activations: &[volparossa_routing::LeaseActivation],
) -> Result<Vec<VerifiedWireguardEndpoint>, BackendError> {
    let [relay_client, relay_exit] = prepared else {
        return Err(BackendError::Invalid);
    };
    let [client_activation, exit_activation] = activations else {
        return Err(BackendError::Invalid);
    };
    let verified_request = authority.request.as_ref().ok_or(BackendError::Invalid)?;
    let request = verified_request.message();
    let relay = authority.relay.message();
    let request_hash =
        relay_reservation_request_sha256(&client_activation.signed_client_relay_request)
            .map_err(|_| BackendError::Invalid)?;
    let signed_hash: [u8; 32] = relay
        .signed_client_relay_request_sha256
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    if request_hash != signed_hash
        || verified_request.sender_public_key().as_slice() != relay.client_session_public_key
        || verified_request.sender_public_key() == authority.relay.sender_public_key()
        || verified_request.sender_public_key() == authority.exit.sender_public_key()
        || client_activation.maximum_up_mbps
            != u32::try_from(relay.maximum_up_mbps).map_err(|_| BackendError::Invalid)?
        || client_activation.maximum_down_mbps
            != u32::try_from(relay.maximum_down_mbps).map_err(|_| BackendError::Invalid)?
        || exit_activation.maximum_up_mbps != client_activation.maximum_up_mbps
        || exit_activation.maximum_down_mbps != client_activation.maximum_down_mbps
    {
        return Err(BackendError::Invalid);
    }
    let signed_client_local = relay
        .relay_client_wireguard_endpoint
        .as_ref()
        .and_then(verified_wireguard_endpoint)
        .ok_or(BackendError::Invalid)?;
    let signed_exit_local = relay
        .relay_exit_wireguard_endpoint
        .as_ref()
        .and_then(verified_wireguard_endpoint)
        .ok_or(BackendError::Invalid)?;
    if (
        signed_client_local.public_key,
        signed_client_local.address,
        signed_client_local.port,
    ) != (
        relay_client.public_key,
        underlay.address,
        relay_client.listen_port,
    ) || (
        signed_exit_local.public_key,
        signed_exit_local.address,
        signed_exit_local.port,
    ) != (
        relay_exit.public_key,
        underlay.address,
        relay_exit.listen_port,
    ) {
        return Err(BackendError::Invalid);
    }
    let client_peer = request
        .client_wireguard_endpoint
        .as_ref()
        .and_then(verified_wireguard_endpoint)
        .ok_or(BackendError::Invalid)?;
    let exit_peer = authority
        .exit
        .message()
        .exit_wireguard_endpoint
        .as_ref()
        .and_then(verified_wireguard_endpoint)
        .ok_or(BackendError::Invalid)?;
    if client_peer.public_key.as_slice() != relay.client_wireguard_public_key {
        return Err(BackendError::Invalid);
    }
    Ok(vec![client_peer, exit_peer])
}

fn project_internal_activation_batch(
    resources: &[LiveWireguardLeaseOwner],
    key: OpenLineageKey,
    prepared: &[PreparedWorkerLease],
    underlay: UnderlayCandidate,
    activations: &[volparossa_routing::LeaseActivation],
    endpoints: &[VerifiedWireguardEndpoint],
) -> Result<ActivateLeases, BackendError> {
    let mut public_keys = Vec::with_capacity(prepared.len() * 2);
    let mut socket_tuples = Vec::with_capacity(prepared.len() * 2);
    let mut leases = Vec::with_capacity(prepared.len());
    for (((owner, prepared), activation), endpoint) in resources
        .iter()
        .zip(prepared)
        .zip(activations)
        .zip(endpoints)
    {
        let supplied_public_key: [u8; 32] = activation
            .peer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| BackendError::Invalid)?;
        let supplied_endpoint = parse_public_udp_endpoint(activation.peer_endpoint.as_ref())
            .ok_or(BackendError::Invalid)?;
        if supplied_public_key != endpoint.public_key
            || supplied_endpoint != (endpoint.address, endpoint.port)
            || endpoint.public_key == prepared.public_key
            || (endpoint.address, endpoint.port) == (underlay.address, prepared.listen_port)
            || public_keys.contains(&prepared.public_key)
            || public_keys.contains(&endpoint.public_key)
            || socket_tuples.contains(&(underlay.address, prepared.listen_port))
            || socket_tuples.contains(&(endpoint.address, endpoint.port))
        {
            return Err(BackendError::Invalid);
        }
        public_keys.extend([prepared.public_key, endpoint.public_key]);
        socket_tuples.extend([
            (underlay.address, prepared.listen_port),
            (endpoint.address, endpoint.port),
        ]);
        leases.push(internal_lease_activation(
            owner.resource(),
            activation.path_id,
            prepared.role,
            *endpoint,
            activation.maximum_up_mbps,
            activation.maximum_down_mbps,
        )?);
    }
    Ok(ActivateLeases {
        route_context_id: key.context_id.to_vec(),
        hard_expires_at_boottime_ns: key.hard_expires_at_boottime_ns,
        leases,
    })
}

#[cfg(test)]
fn verified_internal_activate_plan(
    replay_cache: &Mutex<ReplayCache>,
    resource: &DurableWireguardResource,
    key: OpenLineageKey,
    prepared: PreparedWorkerLease,
    underlay: UnderlayCandidate,
    activation: &volparossa_routing::LeaseActivation,
    now_ms: u64,
) -> Result<ActivateLeases, BackendError> {
    if !activation.signed_client_relay_request.is_empty() {
        return Err(BackendError::Invalid);
    }
    let mut replay_guard = lock_replay_cache(replay_cache);
    let (relay_grant, exit_grant) = verify_relay_reservation(
        &activation.signed_relay_reservation,
        now_ms,
        TimePolicy::default(),
        &mut replay_guard,
    )
    .map_err(|error| protocol_backend_error(&error))?;
    let replay_keys = [
        (*relay_grant.sender_id(), *relay_grant.nonce()),
        (*exit_grant.sender_id(), *exit_grant.nonce()),
    ];
    let result = (|| {
        let relay_message = relay_grant.message();
        let exit_message = exit_grant.message();
        let hard_expires_at_ms = unix_seconds_to_milliseconds(key.hard_expires_at_unix)?;
        if relay_message.route_context_id.as_slice() != key.context_id
            || relay_message.path_id != activation.path_id
            || relay_message.path_id != prepared.path_id
            || activation.role != prepared.role
            || relay_grant.expires_at_ms() < hard_expires_at_ms
            || exit_grant.expires_at_ms() < hard_expires_at_ms
            || !signer_matches_peer_id(
                relay_grant.sender_public_key(),
                &relay_message.relay_peer_id,
            )
            || !signer_matches_peer_id(exit_grant.sender_public_key(), &exit_message.exit_peer_id)
            || relay_grant.sender_public_key() == exit_grant.sender_public_key()
        {
            return Err(BackendError::Invalid);
        }
        let endpoint =
            match WireguardRole::try_from(prepared.role).map_err(|_| BackendError::Invalid)? {
                WireguardRole::Client => {
                    if relay_message.client_wireguard_public_key.as_slice() != prepared.public_key {
                        return Err(BackendError::Invalid);
                    }
                    relay_message
                        .relay_client_wireguard_endpoint
                        .as_ref()
                        .and_then(verified_wireguard_endpoint)
                        .ok_or(BackendError::Invalid)?
                }
                WireguardRole::Exit => {
                    let signed_local = exit_message
                        .exit_wireguard_endpoint
                        .as_ref()
                        .and_then(verified_wireguard_endpoint)
                        .ok_or(BackendError::Invalid)?;
                    if signed_local.public_key != prepared.public_key
                        || (signed_local.address, signed_local.port)
                            != (underlay.address, prepared.listen_port)
                    {
                        return Err(BackendError::Invalid);
                    }
                    relay_message
                        .relay_exit_wireguard_endpoint
                        .as_ref()
                        .and_then(verified_wireguard_endpoint)
                        .ok_or(BackendError::Invalid)?
                }
                WireguardRole::RelayClient
                | WireguardRole::RelayExit
                | WireguardRole::Unspecified => return Err(BackendError::Invalid),
            };
        let supplied_public_key: [u8; 32] = activation
            .peer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| BackendError::Invalid)?;
        let supplied_endpoint = parse_public_udp_endpoint(activation.peer_endpoint.as_ref())
            .ok_or(BackendError::Invalid)?;
        if supplied_public_key != endpoint.public_key
            || supplied_endpoint != (endpoint.address, endpoint.port)
            || endpoint.public_key == prepared.public_key
            || (endpoint.address, endpoint.port) == (underlay.address, prepared.listen_port)
        {
            return Err(BackendError::Invalid);
        }
        Ok(ActivateLeases {
            route_context_id: key.context_id.to_vec(),
            hard_expires_at_boottime_ns: key.hard_expires_at_boottime_ns,
            leases: vec![internal_lease_activation(
                resource,
                activation.path_id,
                prepared.role,
                endpoint,
                activation.maximum_up_mbps,
                activation.maximum_down_mbps,
            )?],
        })
    })();
    if result.is_err() {
        rollback_replay_entries(&mut replay_guard, &replay_keys);
    }
    result
}

fn internal_lease_activation(
    resource: &DurableWireguardResource,
    path_id: u32,
    wireguard_role: i32,
    endpoint: VerifiedWireguardEndpoint,
    maximum_up_mbps: u32,
    maximum_down_mbps: u32,
) -> Result<InternalLeaseActivation, BackendError> {
    let role = functional_lease_role_for_wireguard(wireguard_role).ok_or(BackendError::Invalid)?;
    if resource.key()
        != (
            u8::try_from(path_id).map_err(|_| BackendError::Invalid)?,
            wireguard_role,
        )
    {
        return Err(BackendError::Invalid);
    }
    Ok(InternalLeaseActivation {
        path_id,
        role: role.internal_endpoint as i32,
        peer_public_key: endpoint.public_key.to_vec(),
        peer_endpoint: Some(InternalUdpEndpoint {
            address: ip_bytes(endpoint.address),
            port: u32::from(endpoint.port),
        }),
        allowed_prefixes: vec![InternalIpPrefix {
            address: resource.peer_address().octets().to_vec(),
            prefix_length: 128,
        }],
        persistent_keepalive_seconds: FUNCTIONAL_ALPHA_KEEPALIVE_SECONDS,
        maximum_up_mbps,
        maximum_down_mbps,
        hard_expires_at_unix: resource.hard_expires_at_unix(),
    })
}

fn rollback_replay_entries(cache: &mut ReplayCache, entries: &[([u8; 32], [u8; 32])]) {
    for (sender, nonce) in entries.iter().rev() {
        let _ = cache.rollback(sender, nonce);
    }
}

fn verified_wireguard_endpoint(value: &WireguardEndpoint) -> Option<VerifiedWireguardEndpoint> {
    let public_key: [u8; 32] = value.public_key.as_slice().try_into().ok()?;
    let port = u16::try_from(value.listen_port)
        .ok()
        .filter(|port| *port != 0)?;
    let address = match value.underlay_ip.as_slice() {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    (!address.is_unspecified() && !address.is_multicast()).then_some(VerifiedWireguardEndpoint {
        public_key,
        address,
        port,
    })
}

fn signer_matches_peer_id(public_key: &[u8; 32], expected_peer_id: &[u8]) -> bool {
    libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map(libp2p_identity::PublicKey::from)
        .is_ok_and(|key| key.to_peer_id().to_bytes() == expected_peer_id)
}

fn protocol_backend_error(error: &ProtocolError) -> BackendError {
    if matches!(error, ProtocolError::ReplayCapacity) {
        BackendError::Capacity
    } else {
        BackendError::Invalid
    }
}

fn unix_milliseconds() -> Result<u64, BackendError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BackendError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| BackendError::Unavailable)
}

fn unix_seconds_to_milliseconds(seconds: u64) -> Result<u64, BackendError> {
    seconds.checked_mul(1_000).ok_or(BackendError::Invalid)
}

fn worker_request(
    request_id: [u8; 16],
    operation: internal_worker_request::Operation,
) -> InternalWorkerRequest {
    InternalWorkerRequest {
        protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
        magic: INTERNAL_WORKER_MAGIC.to_vec(),
        request_id: request_id.to_vec(),
        operation: Some(operation),
    }
}

fn matches_initialised(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    context_id: [u8; 16],
) -> bool {
    execution.is_some_and(|execution| {
        execution.descriptor.is_none()
            && execution.response.result == InternalWorkerResult::Ok as i32
            && matches!(
                execution.response.outcome.as_ref(),
                Some(internal_worker_response::Outcome::Initialised(value))
                    if value.route_context_id.as_slice() == context_id
            )
    })
}

fn exact_child_cleanup_is_confirmed(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    phase: OpenLeasePhase,
    birth_may_exist: &[bool],
    resource_count: usize,
) -> bool {
    if resource_count == 0 || birth_may_exist.len() != resource_count {
        return false;
    }
    let Some(execution) = execution.filter(|execution| execution.descriptor.is_none()) else {
        return false;
    };
    match (
        InternalWorkerResult::try_from(execution.response.result).ok(),
        execution.response.outcome.as_ref(),
    ) {
        (Some(InternalWorkerResult::Ok), Some(internal_worker_response::Outcome::Destroyed(_))) => {
            matches!(
                phase,
                OpenLeasePhase::Initialised
                    | OpenLeasePhase::BirthMayExist
                    | OpenLeasePhase::Prepared
                    | OpenLeasePhase::Activated
                    | OpenLeasePhase::Committed
            )
        }
        (Some(InternalWorkerResult::NotFound), None) => {
            matches!(
                phase,
                OpenLeasePhase::Initialised | OpenLeasePhase::BirthMayExist
            ) && birth_may_exist.iter().all(|may_exist| !*may_exist)
        }
        _ => false,
    }
}

fn classify_exact_child_cleanup(
    entry: &OpenLeaseEntry,
    key: OpenLineageKey,
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
) -> Option<ExactChildCleanupConfirmed> {
    if entry.key != key {
        return None;
    }
    exact_child_cleanup_is_confirmed(
        execution,
        entry.phase,
        &entry.birth_may_exist,
        entry.wireguard.len(),
    )
    .then_some(ExactChildCleanupConfirmed { key })
}

fn matches_prepared_batch(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    leases: &[RoutingLeasePlan],
) -> Option<Vec<PreparedWorkerLease>> {
    let execution = execution?;
    if execution.descriptor.is_some()
        || execution.response.result != InternalWorkerResult::Ok as i32
    {
        return None;
    }
    let Some(internal_worker_response::Outcome::Prepared(prepared)) =
        execution.response.outcome.as_ref()
    else {
        return None;
    };
    if prepared.leases.len() != leases.len() || !(1..=2).contains(&leases.len()) {
        return None;
    }
    let mut output = Vec::with_capacity(leases.len());
    for (actual, planned) in prepared.leases.iter().zip(leases) {
        let role = functional_lease_role_for_wireguard(planned.role)?;
        let public_key: [u8; 32] = actual.public_key.as_slice().try_into().ok()?;
        let listen_port = u16::try_from(actual.listen_port)
            .ok()
            .filter(|port| *port != 0)?;
        if actual.path_id != planned.path_id
            || actual.role != role.internal_endpoint as i32
            || public_key.iter().all(|byte| *byte == 0)
            || output.iter().any(|existing: &PreparedWorkerLease| {
                existing.public_key == public_key || existing.listen_port == listen_port
            })
        {
            return None;
        }
        output.push(PreparedWorkerLease {
            path_id: planned.path_id,
            role: planned.role,
            public_key,
            listen_port,
        });
    }
    Some(output)
}

fn matches_activated_batch(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    prepared: &[PreparedWorkerLease],
) -> Option<Vec<KernelCounters>> {
    let execution = execution?;
    if execution.descriptor.is_some()
        || execution.response.result != InternalWorkerResult::Ok as i32
    {
        return None;
    }
    let Some(internal_worker_response::Outcome::Activated(activated)) =
        execution.response.outcome.as_ref()
    else {
        return None;
    };
    if activated.leases.len() != prepared.len() || !(1..=2).contains(&prepared.len()) {
        return None;
    }
    activated
        .leases
        .iter()
        .zip(prepared)
        .map(|(lease, expected)| {
            let role = functional_lease_role_for_wireguard(expected.role)?;
            let public_key: [u8; 32] = lease.public_key.as_slice().try_into().ok()?;
            let listen_port = u16::try_from(lease.listen_port)
                .ok()
                .filter(|port| *port != 0)?;
            if (lease.path_id, lease.role, public_key, listen_port)
                != (
                    expected.path_id,
                    role.internal_endpoint as i32,
                    expected.public_key,
                    expected.listen_port,
                )
                || lease.latest_handshake_nanoseconds >= 1_000_000_000
                || (lease.latest_handshake_unix == 0 && lease.latest_handshake_nanoseconds != 0)
            {
                return None;
            }
            Some(KernelCounters {
                path_id: expected.path_id,
                role: expected.role,
                latest_handshake_unix: lease.latest_handshake_unix,
                received_bytes: lease.received_bytes,
                transmitted_bytes: lease.transmitted_bytes,
            })
        })
        .collect()
}

fn matches_probed_batch(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    activated: &[ActivatedWorkerLease],
    not_before_unix: u64,
) -> Option<Vec<KernelCounters>> {
    let execution = execution?;
    if execution.descriptor.is_some()
        || execution.response.result != InternalWorkerResult::Ok as i32
    {
        return None;
    }
    let Some(internal_worker_response::Outcome::ProbedCommitted(probed)) =
        execution.response.outcome.as_ref()
    else {
        return None;
    };
    if probed.leases.len() != activated.len() || !(1..=2).contains(&activated.len()) {
        return None;
    }
    probed
        .leases
        .iter()
        .zip(activated)
        .map(|(lease, expected)| {
            let role = functional_lease_role_for_wireguard(expected.prepared.role)?;
            if (lease.path_id, lease.role)
                != (expected.prepared.path_id, role.internal_endpoint as i32)
                || lease.latest_handshake_unix < not_before_unix
                || lease.latest_handshake_unix < expected.baseline.latest_handshake_unix
                || lease.received_bytes <= expected.baseline.received_bytes
                || lease.transmitted_bytes <= expected.baseline.transmitted_bytes
            {
                return None;
            }
            Some(KernelCounters {
                path_id: expected.prepared.path_id,
                role: expected.prepared.role,
                latest_handshake_unix: lease.latest_handshake_unix,
                received_bytes: lease.received_bytes,
                transmitted_bytes: lease.transmitted_bytes,
            })
        })
        .collect()
}

#[cfg(test)]
fn matches_activated(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    prepared: PreparedWorkerLease,
) -> Option<KernelCounters> {
    let mut proofs = matches_activated_batch(execution, std::slice::from_ref(&prepared))?;
    (proofs.len() == 1).then(|| proofs.remove(0))
}

#[cfg(test)]
fn matches_probed(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    activated: ActivatedWorkerLease,
    not_before_unix: u64,
) -> Option<KernelCounters> {
    let mut proofs =
        matches_probed_batch(execution, std::slice::from_ref(&activated), not_before_unix)?;
    (proofs.len() == 1).then(|| proofs.remove(0))
}

fn response_error(
    result: Result<crate::worker_transport::CredentialedWorkerExecution, WorkerV3Error>,
) -> BackendError {
    match result {
        Ok(execution) => match InternalWorkerResult::try_from(execution.response.result).ok() {
            Some(InternalWorkerResult::Invalid | InternalWorkerResult::Conflict) => {
                BackendError::Invalid
            }
            Some(InternalWorkerResult::Kernel) => BackendError::Kernel,
            Some(InternalWorkerResult::CleanupIncomplete) => BackendError::CleanupIncomplete,
            _ => BackendError::Unavailable,
        },
        Err(_) => BackendError::Unavailable,
    }
}

fn prepare_deadline(binding: BackendBinding) -> Result<HardDeadline, BackendError> {
    HardDeadline::at(binding.call_deadline.into_std()).map_err(|_| BackendError::Unavailable)
}

fn worker_operation_deadline(deadline: HardDeadline) -> Result<HardDeadline, BackendError> {
    deadline
        .before_tail(WORKER_FAIL_CLOSED_RETIREMENT_TAIL)
        .map_err(|_| BackendError::CleanupIncomplete)
}

fn definite_worker_error(error: &WorkerV3Error) -> BackendError {
    match error {
        WorkerV3Error::Capacity => BackendError::Capacity,
        WorkerV3Error::Invalid | WorkerV3Error::Conflict | WorkerV3Error::Stale => {
            BackendError::Invalid
        }
        _ => BackendError::Unavailable,
    }
}

fn entry_generation(
    state: &Mutex<Option<OpenLeaseEntry>>,
    key: OpenLineageKey,
) -> Result<u64, BackendError> {
    let state = lock_state(state);
    let worker = exact_entry(state.as_ref(), key)?
        .worker
        .as_ref()
        .ok_or(BackendError::CleanupIncomplete)?;
    Ok(worker.coordinates.worker_generation.get())
}

fn exact_entry(
    state: Option<&OpenLeaseEntry>,
    key: OpenLineageKey,
) -> Result<&OpenLeaseEntry, BackendError> {
    state
        .filter(|entry| entry.key == key)
        .ok_or(BackendError::CleanupIncomplete)
}

fn exact_entry_mut(
    state: &mut Option<OpenLeaseEntry>,
    key: OpenLineageKey,
) -> Result<&mut OpenLeaseEntry, BackendError> {
    state
        .as_mut()
        .filter(|entry| entry.key == key)
        .ok_or(BackendError::CleanupIncomplete)
}

fn remove_exact_entry(state: &Mutex<Option<OpenLeaseEntry>>, key: OpenLineageKey) -> bool {
    let mut state = lock_state(state);
    if state.as_ref().is_some_and(|entry| entry.key == key) {
        *state = None;
        true
    } else {
        false
    }
}

fn custody_context_id(custody: &DurableLeaseCustody) -> [u8; 16] {
    match &custody.settlement {
        DurableJournalSettlement::MayOwn(settlement) => settlement.context_id(),
        DurableJournalSettlement::CleanupProven(proof) => proof.settlement().context_id(),
        DurableJournalSettlement::CleanupConfirmed(cleanup)
        | DurableJournalSettlement::RemovalAmbiguous { cleanup, .. }
        | DurableJournalSettlement::RemovalRetryAuthorized { cleanup, .. } => cleanup.context_id(),
        DurableJournalSettlement::ManagerRemovalProven(proof) => proof.cleanup().context_id(),
    }
}

fn lock_state(
    state: &Mutex<Option<OpenLeaseEntry>>,
) -> std::sync::MutexGuard<'_, Option<OpenLeaseEntry>> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_replay_cache(replay: &Mutex<ReplayCache>) -> std::sync::MutexGuard<'_, ReplayCache> {
    replay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn parse_public_udp_endpoint(value: Option<&PublicUdpEndpoint>) -> Option<(IpAddr, u16)> {
    let value = value?;
    let port = u16::try_from(value.port).ok().filter(|port| *port != 0)?;
    let address = match value.address.as_slice() {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    (!address.is_unspecified() && !address.is_multicast()).then_some((address, port))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use ed25519_dalek::SigningKey;
    use nix::unistd::{getegid, geteuid};
    use tempfile::tempdir;
    use volparossa_protocol::{
        MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, RelayAuthorization, RelayReservation,
        SignedEnvelope, Transport, decode_canonical, generate_nonce, node_id_from_public_key,
        sign_control_message,
    };
    use volparossa_test_support::SignedRouteFixture;

    use super::*;
    use crate::{
        internal_protocol::ContextDestroyed,
        worker_transport::{
            ExpectedUnixCredentials, private_credential_worker_channel,
            receive_credential_worker_request, send_credential_worker_response,
        },
        worker_v3::{
            BootstrapChallenge, DurableWorkerPrepareOutcome, DurableWorkerPrepareTerminal,
            SpawnedWorker, StablePhase, WorkerProcess, correlated_response,
        },
    };

    fn backend_with_state(state: Option<OpenLeaseEntry>) -> FunctionalAlphaLeaseBackend {
        FunctionalAlphaLeaseBackend {
            coordinator: WorkerCoordinator::new(WorkerRegistry::new(
                MAX_FUNCTIONAL_ALPHA_CONTEXTS,
                DEFAULT_MAX_CACHE_ENTRIES,
                DEFAULT_MAX_TTL,
            )),
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(state),
            durable_ownership: None,
        }
    }

    fn key() -> OpenLineageKey {
        OpenLineageKey {
            helper_runtime_id: [1; 32],
            context_id: [2; 16],
            backend_generation: 3,
            prepare_request_id: [4; 16],
            prepare_operation_digest: [5; 32],
            setup_expires_at_unix: 6,
            hard_expires_at_unix: 7,
            setup_expires_at_boottime_ns: 6,
            hard_expires_at_boottime_ns: 7,
        }
    }

    fn lineage(key: OpenLineageKey) -> BackendLineage {
        BackendLineage {
            helper_runtime_id: key.helper_runtime_id,
            context_id: key.context_id,
            backend_generation: key.backend_generation,
            prepare_request_id: key.prepare_request_id,
            prepare_operation_digest: key.prepare_operation_digest,
            setup_expires_at_unix: key.setup_expires_at_unix,
            hard_expires_at_unix: key.hard_expires_at_unix,
            setup_expires_at_boottime_ns: key.setup_expires_at_boottime_ns,
            hard_expires_at_boottime_ns: key.hard_expires_at_boottime_ns,
        }
    }

    fn live_key(context_id: [u8; 16], now_unix: u64) -> OpenLineageKey {
        const NANOS_PER_SECOND: u64 = 1_000_000_000;
        let now_boottime = current_boottime_nanos().expect("fixture boottime");
        OpenLineageKey {
            context_id,
            setup_expires_at_unix: now_unix + 20,
            hard_expires_at_unix: now_unix + 120,
            setup_expires_at_boottime_ns: now_boottime + 20 * NANOS_PER_SECOND,
            hard_expires_at_boottime_ns: now_boottime + 120 * NANOS_PER_SECOND,
            ..key()
        }
    }

    fn binding(
        key: OpenLineageKey,
        operation_kind: OperationKind,
        phase: BackendPhase,
        action: BackendAction,
        call_deadline: tokio::time::Instant,
    ) -> BackendBinding {
        let shutdown = operation_kind == OperationKind::Shutdown;
        BackendBinding {
            lineage: lineage(key),
            operation_sequence: 1,
            request_id: if shutdown { [0; 16] } else { [8; 16] },
            request_digest: if shutdown { [0; 32] } else { [9; 32] },
            operation_generation: key.backend_generation,
            prior_phase: None,
            operation_kind,
            phase,
            action,
            call_deadline,
        }
    }

    fn destroy_binding(key: OpenLineageKey, deadline: tokio::time::Instant) -> BackendBinding {
        let mut binding = binding(
            key,
            OperationKind::Destroy,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            deadline,
        );
        binding.prior_phase = Some(ContextPhase::Prepared);
        binding
    }

    fn destroy_value(key: OpenLineageKey) -> BackendDestroy {
        BackendDestroy {
            context_id: key.context_id,
            backend_generation: key.backend_generation,
        }
    }

    fn open_entry(key: OpenLineageKey) -> OpenLeaseEntry {
        open_entry_for_role(key, WireguardRole::Client)
    }

    fn open_entry_for_role(key: OpenLineageKey, wireguard_role: WireguardRole) -> OpenLeaseEntry {
        let role = functional_lease_role_for_wireguard(wireguard_role as i32)
            .expect("functional fixture role");
        let lease = RoutingLeasePlan {
            path_id: 1,
            role: wireguard_role as i32,
        };
        let wireguard = process_owned_resource(key, &lease).expect("live owner");
        let prepare = internal_prepare_plan(wireguard.resource(), key, &lease);
        OpenLeaseEntry {
            key,
            context_role: role.context,
            worker: None,
            recovery: None,
            durable: None,
            durable_handoff_terminal: None,
            wireguard: vec![wireguard],
            prepare,
            underlay: UnderlayCandidate {
                ifindex: 2,
                address: "198.51.100.7".parse().expect("fixture address"),
                evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
            },
            prepared: Vec::new(),
            activated: Vec::new(),
            phase: OpenLeasePhase::Reserved,
            birth_may_exist: vec![false],
            child_cleanup: None,
            worker_cleanup: None,
        }
    }

    fn open_relay_entry(key: OpenLineageKey) -> OpenLeaseEntry {
        let leases = [
            RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::RelayClient as i32,
            },
            RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::RelayExit as i32,
            },
        ];
        let wireguard = leases
            .iter()
            .map(|lease| process_owned_resource(key, lease))
            .collect::<Result<Vec<_>, _>>()
            .expect("relay resources");
        let prepare = internal_prepare_batch_plan(&wireguard, key, &leases)
            .expect("relay prepare projection");
        OpenLeaseEntry {
            key,
            context_role: ContextRole::Relay,
            worker: None,
            recovery: None,
            durable: None,
            durable_handoff_terminal: None,
            birth_may_exist: vec![false; wireguard.len()],
            wireguard,
            prepare,
            underlay: fixture_underlay(),
            prepared: Vec::new(),
            activated: Vec::new(),
            phase: OpenLeasePhase::Reserved,
            child_cleanup: None,
            worker_cleanup: None,
        }
    }

    fn live_prepare_fixture() -> (BackendBinding, PrepareLeaseBatch) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture time")
            .as_secs();
        let key = live_key(key().context_id, now);
        let mut binding = binding(
            key,
            OperationKind::Prepare,
            BackendPhase::PreparePending,
            BackendAction::Prepare,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.request_id = key.prepare_request_id;
        binding.request_digest = key.prepare_operation_digest;
        let value = PrepareLeaseBatch {
            route_context_id: key.context_id.to_vec(),
            role: ContextRole::Client as i32,
            mptcp_accepted_addrs: 2,
            mptcp_subflows: 2,
            leases: vec![RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            }],
            setup_expires_at_unix: key.setup_expires_at_unix,
            hard_expires_at_unix: key.hard_expires_at_unix,
        };
        (binding, value)
    }

    fn live_exit_prepare_fixture() -> (BackendBinding, PrepareLeaseBatch) {
        let (binding, mut value) = live_prepare_fixture();
        value.role = ContextRole::Exit as i32;
        value.leases[0].role = WireguardRole::Exit as i32;
        (binding, value)
    }

    fn live_relay_prepare_fixture() -> (BackendBinding, PrepareLeaseBatch) {
        let (binding, mut value) = live_prepare_fixture();
        value.role = ContextRole::Relay as i32;
        value.leases = vec![
            RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::RelayClient as i32,
            },
            RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::RelayExit as i32,
            },
        ];
        (binding, value)
    }

    #[test]
    fn durable_prepare_reconstruction_is_byte_exact_for_every_functional_context_shape() {
        for (binding, value) in [
            live_prepare_fixture(),
            live_relay_prepare_fixture(),
            live_exit_prepare_fixture(),
        ] {
            let expected = PrepareIntent {
                route_context_id: value.route_context_id.clone(),
                prepare_request_id: binding.lineage.prepare_request_id.to_vec(),
                prepare_operation_digest: binding.lineage.prepare_operation_digest.to_vec(),
                setup_expires_at_unix: value.setup_expires_at_unix,
                hard_expires_at_unix: value.hard_expires_at_unix,
                closed_plan: Some(ClosedPreparePlan {
                    context_role: value.role,
                    leases: value.leases.clone(),
                }),
            };
            let reconstructed =
                reconstruct_durable_prepare_intent(binding.lineage, &value).expect("exact intent");
            assert_eq!(
                prost::Message::encode_to_vec(&reconstructed),
                prost::Message::encode_to_vec(&expected)
            );

            let mut wrong_context = value.clone();
            wrong_context.route_context_id[0] ^= 1;
            assert_eq!(
                reconstruct_durable_prepare_intent(binding.lineage, &wrong_context),
                Err(BackendError::Invalid)
            );
            let mut wrong_setup = value.clone();
            wrong_setup.setup_expires_at_unix = wrong_setup.setup_expires_at_unix.saturating_add(1);
            assert_eq!(
                reconstruct_durable_prepare_intent(binding.lineage, &wrong_setup),
                Err(BackendError::Invalid)
            );
            let mut wrong_hard = value.clone();
            wrong_hard.hard_expires_at_unix = wrong_hard.hard_expires_at_unix.saturating_add(1);
            assert_eq!(
                reconstruct_durable_prepare_intent(binding.lineage, &wrong_hard),
                Err(BackendError::Invalid)
            );
        }
    }

    #[test]
    fn exact_child_destroy_classifier_is_phase_and_birth_fail_closed() {
        let open_key = key();
        let mut entry = open_entry(open_key);
        let destroyed = cleanup_execution(
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {},
            )),
        );
        let not_found = cleanup_execution(InternalWorkerResult::NotFound, None);

        entry.phase = OpenLeasePhase::Registered;
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&destroyed)).is_none());

        entry.phase = OpenLeasePhase::Initialised;
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&destroyed)).is_some());

        entry.phase = OpenLeasePhase::BirthMayExist;
        entry.birth_may_exist[0] = true;
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&destroyed)).is_some());
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&not_found)).is_none());
        entry.birth_may_exist[0] = false;
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&not_found)).is_some());

        entry.phase = OpenLeasePhase::Prepared;
        entry.birth_may_exist[0] = true;
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&destroyed)).is_some());

        entry.birth_may_exist.clear();
        assert!(classify_exact_child_cleanup(&entry, open_key, Some(&destroyed)).is_none());
        entry.birth_may_exist.push(true);
        let mut wrong_key = open_key;
        wrong_key.context_id[0] ^= 1;
        assert!(classify_exact_child_cleanup(&entry, wrong_key, Some(&destroyed)).is_none());
    }

    #[test]
    fn production_prepare_order_is_fail_closed() {
        let source = include_str!("functional_backend.rs");
        let prepare_start = source
            .find("    async fn prepare_one(")
            .expect("Prepare start");
        let prepare_end = source[prepare_start..]
            .find("\n    fn reserve_entry(")
            .map(|offset| prepare_start + offset)
            .expect("Prepare end");
        let prepare = &source[prepare_start..prepare_end];
        let intent = prepare
            .find("reconstruct_durable_prepare_intent(binding.lineage, &value)")
            .expect("wire intent reconstruction");
        let handoff = prepare
            .find(".durable_functional_prepare_until(")
            .expect("durable handoff");
        let initialise = prepare
            .find("self.initialise_child(")
            .expect("first child request");
        let kernel = prepare
            .find("self.create_birth_links(")
            .expect("first kernel mutation");
        assert!(intent < handoff && handoff < initialise && handoff < kernel);
        let initialise_start = source
            .find("    async fn initialise_child(")
            .expect("Initialise child start");
        let initialise_end = source[initialise_start..]
            .find("\n    fn create_birth_links(")
            .map(|offset| initialise_start + offset)
            .expect("Initialise child end");
        let initialise_body = &source[initialise_start..initialise_end];
        let staged_plan = initialise_body
            .find("entry.prepare.clone()")
            .expect("canonical staged Prepare plan");
        let encoded_plan = initialise_body
            .find("prepare: Some(prepare)")
            .expect("typed Initialise cleanup target");
        let dispatch = initialise_body
            .find(".execute_until(")
            .expect("Initialise dispatch");
        assert!(staged_plan < encoded_plan && encoded_plan < dispatch);
    }

    #[test]
    fn production_clean_settlement_order_is_fail_closed() {
        let source = include_str!("functional_backend.rs");
        let cleanup_start = source
            .find("    async fn settle_durable_cleanup(")
            .expect("durable cleanup start");
        let cleanup_end = source[cleanup_start..]
            .find("\n    fn restore_durable_cleanup(")
            .map(|offset| cleanup_start + offset)
            .expect("durable cleanup end");
        let cleanup = &source[cleanup_start..cleanup_end];
        let child_cleanup_classified = source[..cleanup_start]
            .rfind("classify_exact_child_cleanup(entry, key, execution.as_ref().ok())")
            .expect("phase/birth-classified child cleanup authority");
        let retain_without_child_cleanup = source[..cleanup_start]
            .rfind("// Exact child cleanup did not complete.")
            .expect("unproven child cleanup retention");
        let exact_worker_reap = source[..cleanup_start]
            .rfind("WorkerGenerationReap::Confirmed(proof) =>")
            .expect("exact worker-generation reap");
        let worker_reap_recorded = source[..cleanup_start]
            .rfind("entry.worker_cleanup.replace(proof)")
            .expect("affine worker reap evidence retention");
        let kernel_absent = source[..cleanup_start]
            .rfind("if !parent_absent")
            .expect("kernel absence gate");
        let all_cleanup_evidence = source[..cleanup_start]
            .rfind("entry.child_cleanup.is_some() && entry.worker_cleanup.is_some()")
            .expect("joined exact cleanup evidence gate");
        let parent_absence = source[..cleanup_start]
            .rfind("ExactParentKernelAbsent::after_exact_parent_kernel_absence(key)")
            .expect("opaque parent/kernel absence marker");
        let durable_call = source[..cleanup_start]
            .rfind("self.settle_durable_cleanup(key, parent, deadline).await")
            .expect("durable cleanup call");
        assert!(
            child_cleanup_classified < retain_without_child_cleanup
                && retain_without_child_cleanup < exact_worker_reap
                && exact_worker_reap < worker_reap_recorded
                && worker_reap_recorded < kernel_absent
                && kernel_absent < all_cleanup_evidence
                && all_cleanup_evidence < parent_absence
                && parent_absence < durable_call
                && durable_call < cleanup_start
        );
        let cleanup_proof = cleanup
            .find("ExactSameRuntimeCleanupProof::after_exact_worker_kernel_cleanup(")
            .expect("opaque exact cleanup proof mint");
        let cleanup_confirmed = cleanup
            .find("handle.confirm_cleanup_until(proof, deadline)")
            .expect("CleanupConfirmed transition");
        let fdstore_remove = cleanup
            .find("remove_current_process_custody(")
            .expect("exact FD-store removal");
        let direct_removal_validation = cleanup
            .find(".verify_exact_target(custody.custody_name, &binding)")
            .expect("direct exact named-removal validation");
        let direct_manager_proof = cleanup
            .find("ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(")
            .expect("direct opaque manager-absence proof mint");
        let removal_reconcile = cleanup
            .find("reconcile_current_process_removal(")
            .expect("ambiguous removal reconciliation");
        let retry_authority = cleanup
            .find("DurableJournalSettlement::RemovalRetryAuthorized {")
            .expect("exact-still-present retry authority");
        let fdstore_retry = cleanup
            .find("retry_current_process_removal(")
            .expect("exact correlated FD-store retry");
        let retry_removal_validation = cleanup
            .rfind(".verify_exact_target(custody.custody_name, &binding)")
            .expect("retry exact named-removal validation");
        let retry_manager_proof = cleanup
            .rfind("ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(")
            .expect("retry opaque manager-absence proof mint");
        let manager_absent = cleanup
            .find("handle.confirm_manager_absent_until(proof, deadline)")
            .expect("Absent transition");
        assert!(
            cleanup_proof < cleanup_confirmed
                && cleanup_confirmed < fdstore_remove
                && fdstore_remove < direct_removal_validation
                && direct_removal_validation < direct_manager_proof
                && direct_manager_proof < removal_reconcile
                && removal_reconcile < retry_authority
                && retry_authority < fdstore_retry
                && fdstore_retry < retry_removal_validation
                && retry_removal_validation < retry_manager_proof
                && retry_manager_proof < manager_absent
        );
    }

    #[test]
    fn opaque_same_runtime_settlement_has_one_private_production_path() {
        let source = include_str!("functional_backend.rs");
        let production_end = source
            .find("#[cfg(test)]\nmod tests {")
            .expect("production source boundary");
        let production = &source[..production_end];
        let actor_source = include_str!("../ownership_journal/actor.rs");
        let journal_source = include_str!("../ownership_journal.rs");
        let classifier_start = production
            .find("fn classify_exact_child_cleanup(")
            .expect("private child-cleanup classifier");
        let classifier_end = production[classifier_start..]
            .find("\nfn matches_prepared_batch(")
            .map(|offset| classifier_start + offset)
            .expect("bounded child-cleanup classifier");
        assert!(
            production[classifier_start..classifier_end]
                .contains("exact_child_cleanup_is_confirmed(")
        );

        assert_eq!(
            production.matches("handle.confirm_cleanup_until(").count(),
            1,
            "only the functional production cleanup transaction may invoke same-runtime cleanup"
        );
        assert_eq!(
            production
                .matches("handle.confirm_manager_absent_until(")
                .count(),
            1,
            "only the functional production cleanup transaction may invoke manager absence"
        );
        assert_eq!(
            production
                .matches("ExactSameRuntimeCleanupProof::after_exact_worker_kernel_cleanup(")
                .count(),
            1,
            "exact cleanup authority has one production mint site"
        );
        assert_eq!(
            production
                .matches("ExactParentKernelAbsent::after_exact_parent_kernel_absence(key)")
                .count(),
            1,
            "parent/kernel absence has one production marker site"
        );
        assert_eq!(
            production
                .matches("classify_exact_child_cleanup(entry, key, execution.as_ref().ok())")
                .count(),
            1,
            "child cleanup authority has one production classifier site"
        );
        assert_eq!(
            production
                .matches("ExactSameRuntimeManagerAbsenceProof::after_exact_named_removal(")
                .count(),
            3,
            "direct, reconciled and correlated-retry removals each have one proof mint"
        );

        let cleanup_api = actor_source
            .find("    pub(crate) fn confirm_cleanup_until(\n        &self,\n        proof: ExactSameRuntimeCleanupProof,")
            .expect("cleanup handle requires opaque backend proof");
        let manager_api = actor_source
            .find("    pub(crate) fn confirm_manager_absent_until(\n        &self,\n        proof: ExactSameRuntimeManagerAbsenceProof,")
            .expect("manager handle requires opaque backend proof");
        assert!(cleanup_api < manager_api);
        assert!(!actor_source.contains(
            "pub(crate) fn confirm_cleanup_until(\n        &self,\n        settlement: DurablePrepareSettlement,"
        ));
        assert!(!actor_source.contains(
            "pub(crate) fn confirm_manager_absent_until(\n        &self,\n        cleanup: DurableCleanupConfirmed,"
        ));
        assert!(production.contains("fn after_exact_worker_kernel_cleanup("));
        assert!(!production.contains("pub(crate) fn after_exact_worker_kernel_cleanup"));
        assert!(production.contains("_worker: ConfirmedWorkerGenerationAbsent"));
        assert!(production.contains("_parent: ExactParentKernelAbsent"));
        assert!(production.contains("_child: ExactChildCleanupConfirmed"));
        assert!(production.contains("fn after_exact_parent_kernel_absence("));
        assert!(!production.contains("pub(crate) fn after_exact_parent_kernel_absence("));
        assert!(production.contains("fn after_exact_named_removal("));
        assert!(!production.contains("pub(crate) fn after_exact_named_removal("));
        assert!(journal_source.contains("struct SameRuntimeCleanSettlement;"));
        assert!(!journal_source.contains("pub(crate) struct SameRuntimeCleanSettlement;"));
        assert!(!journal_source.contains("pub(super) struct SameRuntimeCleanSettlement;"));
    }

    fn cleanup_execution(
        result: InternalWorkerResult,
        outcome: Option<internal_worker_response::Outcome>,
    ) -> crate::worker_transport::CredentialedWorkerExecution {
        crate::worker_transport::CredentialedWorkerExecution {
            response: crate::internal_protocol::InternalWorkerResponse {
                protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                magic: INTERNAL_WORKER_MAGIC.to_vec(),
                request_id: vec![0xd1; 16],
                result: result as i32,
                request_digest: vec![0xd2; 32],
                outcome,
            },
            descriptor: None,
        }
    }

    #[test]
    fn exact_child_cleanup_evidence_is_phase_and_birth_sensitive() {
        let destroyed = cleanup_execution(
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {},
            )),
        );
        for phase in [
            OpenLeasePhase::Initialised,
            OpenLeasePhase::BirthMayExist,
            OpenLeasePhase::Prepared,
            OpenLeasePhase::Activated,
            OpenLeasePhase::Committed,
        ] {
            assert!(exact_child_cleanup_is_confirmed(
                Some(&destroyed),
                phase,
                &[true, false],
                2,
            ));
        }
        for phase in [
            OpenLeasePhase::Reserved,
            OpenLeasePhase::DurableHandoffPending,
            OpenLeasePhase::Registered,
        ] {
            assert!(!exact_child_cleanup_is_confirmed(
                Some(&destroyed),
                phase,
                &[false],
                1,
            ));
        }

        let not_found = cleanup_execution(InternalWorkerResult::NotFound, None);
        for phase in [OpenLeasePhase::Initialised, OpenLeasePhase::BirthMayExist] {
            assert!(exact_child_cleanup_is_confirmed(
                Some(&not_found),
                phase,
                &[false, false],
                2,
            ));
            assert!(!exact_child_cleanup_is_confirmed(
                Some(&not_found),
                phase,
                &[true, false],
                2,
            ));
        }
        assert!(!exact_child_cleanup_is_confirmed(
            Some(&not_found),
            OpenLeasePhase::Prepared,
            &[false],
            1,
        ));
        assert!(!exact_child_cleanup_is_confirmed(
            Some(&not_found),
            OpenLeasePhase::BirthMayExist,
            &[],
            1,
        ));
        assert!(!exact_child_cleanup_is_confirmed(
            Some(&not_found),
            OpenLeasePhase::BirthMayExist,
            &[false],
            0,
        ));
    }

    #[test]
    fn cleanup_evidence_rejects_wrong_result_outcome_and_descriptor() {
        let wrong_result = cleanup_execution(
            InternalWorkerResult::CleanupIncomplete,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {},
            )),
        );
        let wrong_outcome = cleanup_execution(
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Initialised(
                crate::internal_protocol::ContextInitialised {
                    route_context_id: key().context_id.to_vec(),
                },
            )),
        );
        for execution in [&wrong_result, &wrong_outcome] {
            assert!(!exact_child_cleanup_is_confirmed(
                Some(execution),
                OpenLeasePhase::BirthMayExist,
                &[false],
                1,
            ));
        }

        let mut with_descriptor = cleanup_execution(
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {},
            )),
        );
        with_descriptor.descriptor = Some(
            std::fs::File::open("/dev/null")
                .expect("test descriptor")
                .into(),
        );
        assert!(!exact_child_cleanup_is_confirmed(
            Some(&with_descriptor),
            OpenLeasePhase::Committed,
            &[false],
            1,
        ));
        assert!(!exact_child_cleanup_is_confirmed(
            None,
            OpenLeasePhase::Committed,
            &[false],
            1,
        ));
    }

    #[test]
    fn opaque_never_dispatched_settlement_has_one_bounded_production_path() {
        let functional_source = include_str!("functional_backend.rs");
        let functional_end = functional_source
            .find("#[cfg(test)]\nmod tests {")
            .expect("functional production boundary");
        let functional = &functional_source[..functional_end];
        let worker_source = include_str!("../worker_v3.rs");
        let worker_end = worker_source
            .find("#[cfg(test)]\nmod tests {")
            .expect("worker production boundary");
        let worker = &worker_source[..worker_end];
        let actor = include_str!("../ownership_journal/actor.rs");
        let journal = include_str!("../ownership_journal.rs");

        assert_eq!(
            worker
                .matches(
                    "ExactNeverDispatchedPrepareProof::after_definite_worker_admission_rejection("
                )
                .count(),
            1,
            "definite no-worker admission has one proof mint"
        );
        assert_eq!(
            worker
                .matches("ExactNeverDispatchedPrepareProof::after_exact_worker_absence(")
                .count(),
            1,
            "exact worker reap has one proof mint"
        );
        assert_eq!(
            worker
                .matches("handle.retire_never_dispatched_until(proof, deadline)")
                .count(),
            1,
            "the coordinator has one proof-consuming actor call"
        );
        assert_eq!(
            functional
                .matches(".settle_durable_handoff_terminal_until(")
                .count(),
            1,
            "only exact later functional cleanup retries a handoff terminal"
        );
        assert!(actor.contains(
            "pub(crate) fn retire_never_dispatched_until(\n        &self,\n        proof: ExactNeverDispatchedPrepareProof,"
        ));
        assert!(!actor.contains(
            "pub(crate) fn retire_never_dispatched_until(\n        &self,\n        key: DurableOwnershipKey,"
        ));

        let settlement_start = worker
            .find("    fn settle_durable_handoff_terminal_until(")
            .expect("bounded handoff settlement");
        let settlement_end = worker[settlement_start..]
            .find("\n    /// Complete the cancellation-safe durable Prepare handoff")
            .map(|offset| settlement_start + offset)
            .expect("bounded handoff settlement end");
        let settlement = &worker[settlement_start..settlement_end];
        assert!(!settlement.contains("async fn"));
        assert!(!settlement.contains(".await"));
        assert!(settlement.contains("take_exact_durable_handoff_terminal(&selector)"));
        assert!(settlement.contains("restore_exact_durable_handoff_terminal(&selector, outcome)"));
        assert!(!settlement.contains("PublicationStart"));
        assert!(!settlement.contains("DispatchOpen"));
        assert!(!settlement.contains("remove_current_process_custody"));
        assert!(!settlement.contains("reconcile_current_process_removal"));

        let cleanup_start = functional
            .find("    async fn cleanup_exact(")
            .expect("functional cleanup");
        let cleanup_end = functional[cleanup_start..]
            .find("\n    fn restore_durable_handoff_terminal(")
            .map(|offset| cleanup_start + offset)
            .expect("handoff cleanup end");
        let cleanup = &functional[cleanup_start..cleanup_end];
        let retry = cleanup
            .find(".settle_durable_handoff_terminal_until(")
            .expect("exact handoff retry");
        let absent = cleanup
            .find("DurableHandoffTerminalSettlement::Absent")
            .expect("durable Absent result");
        let remove = cleanup
            .find("remove_exact_entry(&self.state, key)")
            .expect("entry removal");
        assert!(retry < absent && absent < remove);

        // Any registration reply lost after a possible mutation is promoted to Ambiguous. A
        // non-Ambiguous persistence error is returned only after the complete journal boundary is
        // confirmed unchanged, so the registration can be dropped without orphaning its Intent.
        assert!(actor.contains("operation.complete_unstarted_deadline();"));
        assert!(actor.contains("fence_terminal(&self.lifecycle, Lifecycle::Ambiguous)"));
        assert!(actor.contains("self.journal.confirm_retry_safe_after_definite_failure()"));
        assert!(journal.contains("fn confirm_retry_safe_after_definite_failure(&mut self)"));
        assert!(journal.contains("Err(failure) if failure.uncertain =>"));
        assert!(journal.contains("self.poisoned = true;"));
    }

    fn live_activate_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        ActivateLeaseBatch,
        PreparedWorkerLease,
        SignedRouteFixture,
    ) {
        let now_ms = unix_milliseconds().expect("fixture time");
        let now = now_ms / 1_000;
        let route = SignedRouteFixture::new(1, &[Transport::TcpMptcp], now_ms)
            .expect("signed route fixture");
        let relay = decode_relay_reservation(
            route
                .relay_reservations()
                .first()
                .expect("one relay reservation"),
        );
        let relay_client = relay
            .relay_client_wireguard_endpoint
            .as_ref()
            .expect("relay-client endpoint");
        let key = live_key(*route.route_context_id(), now);
        let mut binding = binding(
            key,
            OperationKind::Activate,
            BackendPhase::Prepared,
            BackendAction::Activate,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Prepared);
        let value = ActivateLeaseBatch {
            route_context_id: key.context_id.to_vec(),
            context_handle: vec![0x31; HELPER_HANDLE_BYTES],
            leases: vec![volparossa_routing::LeaseActivation {
                lease_handle: vec![0x32; HELPER_HANDLE_BYTES],
                path_id: 1,
                role: WireguardRole::Client as i32,
                peer_public_key: relay_client.public_key.clone(),
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: relay_client.underlay_ip.clone(),
                    port: relay_client.listen_port,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation: route.relay_reservations()[0].clone(),
                signed_client_relay_request: Vec::new(),
            }],
        };
        let prepared = PreparedWorkerLease {
            path_id: 1,
            role: WireguardRole::Client as i32,
            public_key: relay
                .client_wireguard_public_key
                .as_slice()
                .try_into()
                .expect("client key"),
            listen_port: 51_820,
        };
        (key, binding, value, prepared, route)
    }

    fn live_probe_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        BackendProbe,
        ActivatedWorkerLease,
    ) {
        let (key, _, activation, prepared, _) = live_activate_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture time")
            .as_secs();
        let mut binding = binding(
            key,
            OperationKind::Probe,
            BackendPhase::Activated,
            BackendAction::Probe,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Activated);
        binding.operation_generation = key.backend_generation + 1;
        let value = BackendProbe {
            commit: volparossa_routing::CommitLeaseBatch {
                route_context_id: key.context_id.to_vec(),
                context_handle: activation.context_handle,
                leases: vec![volparossa_routing::LeaseCommit {
                    lease_handle: activation.leases[0].lease_handle.clone(),
                    path_id: prepared.path_id,
                    role: prepared.role,
                }],
            },
            activated_at_unix: now,
        };
        let activated = ActivatedWorkerLease {
            prepared,
            peer_public_key: activation.leases[0]
                .peer_public_key
                .as_slice()
                .try_into()
                .expect("relay peer key"),
            baseline: KernelCounters {
                path_id: prepared.path_id,
                role: prepared.role,
                latest_handshake_unix: 0,
                received_bytes: 10,
                transmitted_bytes: 20,
            },
        };
        (key, binding, value, activated)
    }

    fn live_exit_activate_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        ActivateLeaseBatch,
        PreparedWorkerLease,
        UnderlayCandidate,
        SignedRouteFixture,
    ) {
        let now_ms = unix_milliseconds().expect("fixture time");
        let now = now_ms / 1_000;
        let route = SignedRouteFixture::new(1, &[Transport::TcpMptcp], now_ms)
            .expect("signed route fixture");
        let relay = decode_relay_reservation(
            route
                .relay_reservations()
                .first()
                .expect("one relay reservation"),
        );
        let relay_exit = relay
            .relay_exit_wireguard_endpoint
            .as_ref()
            .expect("relay-exit endpoint");
        let exit = relay
            .exit_wireguard_endpoint
            .as_ref()
            .expect("exit endpoint");
        let verified_exit = verified_wireguard_endpoint(exit).expect("verified exit endpoint");
        let key = live_key(*route.route_context_id(), now);
        let mut binding = binding(
            key,
            OperationKind::Activate,
            BackendPhase::Prepared,
            BackendAction::Activate,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Prepared);
        let value = ActivateLeaseBatch {
            route_context_id: key.context_id.to_vec(),
            context_handle: vec![0x41; HELPER_HANDLE_BYTES],
            leases: vec![volparossa_routing::LeaseActivation {
                lease_handle: vec![0x42; HELPER_HANDLE_BYTES],
                path_id: 1,
                role: WireguardRole::Exit as i32,
                peer_public_key: relay_exit.public_key.clone(),
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: relay_exit.underlay_ip.clone(),
                    port: relay_exit.listen_port,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation: route.relay_reservations()[0].clone(),
                signed_client_relay_request: Vec::new(),
            }],
        };
        let prepared = PreparedWorkerLease {
            path_id: 1,
            role: WireguardRole::Exit as i32,
            public_key: verified_exit.public_key,
            listen_port: verified_exit.port,
        };
        let underlay = UnderlayCandidate {
            ifindex: 3,
            address: verified_exit.address,
            evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
        };
        (key, binding, value, prepared, underlay, route)
    }

    fn live_exit_probe_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        BackendProbe,
        ActivatedWorkerLease,
    ) {
        let (key, _, activation, prepared, _, _) = live_exit_activate_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture time")
            .as_secs();
        let mut binding = binding(
            key,
            OperationKind::Probe,
            BackendPhase::Activated,
            BackendAction::Probe,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Activated);
        binding.operation_generation = key.backend_generation + 1;
        let value = BackendProbe {
            commit: volparossa_routing::CommitLeaseBatch {
                route_context_id: key.context_id.to_vec(),
                context_handle: activation.context_handle,
                leases: vec![volparossa_routing::LeaseCommit {
                    lease_handle: activation.leases[0].lease_handle.clone(),
                    path_id: prepared.path_id,
                    role: prepared.role,
                }],
            },
            activated_at_unix: now,
        };
        let activated = ActivatedWorkerLease {
            prepared,
            peer_public_key: activation.leases[0]
                .peer_public_key
                .as_slice()
                .try_into()
                .expect("relay-exit peer key"),
            baseline: KernelCounters {
                path_id: prepared.path_id,
                role: prepared.role,
                latest_handshake_unix: 0,
                received_bytes: 50,
                transmitted_bytes: 60,
            },
        };
        (key, binding, value, activated)
    }

    fn live_relay_activate_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        ActivateLeaseBatch,
        [PreparedWorkerLease; 2],
        UnderlayCandidate,
        SignedRouteFixture,
    ) {
        let now_ms = unix_milliseconds().expect("fixture time");
        let now = now_ms / 1_000;
        let route = SignedRouteFixture::new(1, &[Transport::TcpMptcp], now_ms)
            .expect("signed route fixture");
        let relay = decode_relay_reservation(&route.relay_reservations()[0]);
        let request = decode_relay_request(route.relay_request(0).expect("client relay request"));
        let relay_client = relay
            .relay_client_wireguard_endpoint
            .as_ref()
            .and_then(verified_wireguard_endpoint)
            .expect("relay-client local endpoint");
        let relay_exit = relay
            .relay_exit_wireguard_endpoint
            .as_ref()
            .and_then(verified_wireguard_endpoint)
            .expect("relay-exit local endpoint");
        let client = request
            .client_wireguard_endpoint
            .as_ref()
            .and_then(verified_wireguard_endpoint)
            .expect("client peer endpoint");
        let exit = decode_relay_authorization(&relay.exit_authorization)
            .exit_wireguard_endpoint
            .as_ref()
            .and_then(verified_wireguard_endpoint)
            .expect("exit peer endpoint");
        assert_eq!(relay_client.address, relay_exit.address);
        let key = live_key(*route.route_context_id(), now);
        let mut binding = binding(
            key,
            OperationKind::Activate,
            BackendPhase::Prepared,
            BackendAction::Activate,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Prepared);
        let rate_up = u32::try_from(relay.maximum_up_mbps).expect("fixture up rate");
        let rate_down = u32::try_from(relay.maximum_down_mbps).expect("fixture down rate");
        let value = ActivateLeaseBatch {
            route_context_id: key.context_id.to_vec(),
            context_handle: vec![0x51; HELPER_HANDLE_BYTES],
            leases: vec![
                volparossa_routing::LeaseActivation {
                    lease_handle: vec![0x52; HELPER_HANDLE_BYTES],
                    path_id: 1,
                    role: WireguardRole::RelayClient as i32,
                    peer_public_key: client.public_key.to_vec(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: ip_bytes(client.address),
                        port: u32::from(client.port),
                    }),
                    maximum_up_mbps: rate_up,
                    maximum_down_mbps: rate_down,
                    signed_relay_reservation: route.relay_reservations()[0].clone(),
                    signed_client_relay_request: route
                        .relay_request(0)
                        .expect("client relay request")
                        .to_vec(),
                },
                volparossa_routing::LeaseActivation {
                    lease_handle: vec![0x53; HELPER_HANDLE_BYTES],
                    path_id: 1,
                    role: WireguardRole::RelayExit as i32,
                    peer_public_key: exit.public_key.to_vec(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: ip_bytes(exit.address),
                        port: u32::from(exit.port),
                    }),
                    maximum_up_mbps: rate_up,
                    maximum_down_mbps: rate_down,
                    signed_relay_reservation: route.relay_reservations()[0].clone(),
                    signed_client_relay_request: Vec::new(),
                },
            ],
        };
        let prepared = [
            PreparedWorkerLease {
                path_id: 1,
                role: WireguardRole::RelayClient as i32,
                public_key: relay_client.public_key,
                listen_port: relay_client.port,
            },
            PreparedWorkerLease {
                path_id: 1,
                role: WireguardRole::RelayExit as i32,
                public_key: relay_exit.public_key,
                listen_port: relay_exit.port,
            },
        ];
        let underlay = UnderlayCandidate {
            ifindex: 4,
            address: relay_client.address,
            evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
        };
        (key, binding, value, prepared, underlay, route)
    }

    fn live_relay_probe_fixture() -> (
        OpenLineageKey,
        BackendBinding,
        BackendProbe,
        [ActivatedWorkerLease; 2],
    ) {
        let (key, _, activation, prepared, _, _) = live_relay_activate_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture time")
            .as_secs();
        let mut binding = binding(
            key,
            OperationKind::Probe,
            BackendPhase::Activated,
            BackendAction::Probe,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        binding.prior_phase = Some(ContextPhase::Activated);
        binding.operation_generation = key.backend_generation + 1;
        let value = BackendProbe {
            commit: volparossa_routing::CommitLeaseBatch {
                route_context_id: key.context_id.to_vec(),
                context_handle: activation.context_handle,
                leases: activation
                    .leases
                    .iter()
                    .map(|lease| volparossa_routing::LeaseCommit {
                        lease_handle: lease.lease_handle.clone(),
                        path_id: lease.path_id,
                        role: lease.role,
                    })
                    .collect(),
            },
            activated_at_unix: now,
        };
        let activated = std::array::from_fn(|index| ActivatedWorkerLease {
            prepared: prepared[index],
            peer_public_key: activation.leases[index]
                .peer_public_key
                .as_slice()
                .try_into()
                .expect("peer key"),
            baseline: KernelCounters {
                path_id: prepared[index].path_id,
                role: prepared[index].role,
                latest_handshake_unix: 0,
                received_bytes: 100 + u64::try_from(index).expect("index"),
                transmitted_bytes: 200 + u64::try_from(index).expect("index"),
            },
        });
        (key, binding, value, activated)
    }

    fn decode_relay_reservation(encoded: &[u8]) -> RelayReservation {
        let envelope: SignedEnvelope =
            decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE).expect("relay envelope");
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("relay payload")
    }

    fn decode_relay_request(encoded: &[u8]) -> RelayReservationRequest {
        let envelope: SignedEnvelope =
            decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE).expect("request envelope");
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("request payload")
    }

    fn fixture_underlay() -> UnderlayCandidate {
        UnderlayCandidate {
            ifindex: 2,
            address: "198.51.100.7".parse().expect("fixture address"),
            evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
        }
    }

    fn decode_relay_authorization(encoded: &[u8]) -> RelayAuthorization {
        let envelope: SignedEnvelope =
            decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE).expect("authorization envelope");
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
            .expect("authorization payload")
    }

    fn resign_consistent_grant(
        route: &SignedRouteFixture,
        mutate: impl FnOnce(&mut RelayReservation, &mut RelayAuthorization),
    ) -> Vec<u8> {
        let mut relay = decode_relay_reservation(&route.relay_reservations()[0]);
        let mut exit = decode_relay_authorization(&relay.exit_authorization);
        mutate(&mut relay, &mut exit);
        let exit_nonce: [u8; 32] = exit.nonce.as_slice().try_into().expect("exit nonce");
        relay.exit_authorization = sign_control_message(
            &exit,
            route.exit_key(),
            exit.created_at_ms,
            exit.expires_at_ms,
            exit_nonce,
            TimePolicy::default(),
        )
        .expect("re-signed exit authorization");
        let relay_nonce: [u8; 32] = relay.nonce.as_slice().try_into().expect("relay nonce");
        sign_control_message(
            &relay,
            route.relay_key(0).expect("relay key"),
            relay.created_at_ms,
            relay.expires_at_ms,
            relay_nonce,
            TimePolicy::default(),
        )
        .expect("re-signed relay reservation")
    }

    fn resign_client_relay_request(
        route: &SignedRouteFixture,
        mutate: impl FnOnce(&mut RelayReservationRequest),
    ) -> Vec<u8> {
        resign_client_relay_request_with_key(route, route.client_key(), mutate)
    }

    fn resign_client_relay_request_with_key(
        route: &SignedRouteFixture,
        signing_key: &SigningKey,
        mutate: impl FnOnce(&mut RelayReservationRequest),
    ) -> Vec<u8> {
        let mut request = decode_relay_request(route.relay_request(0).expect("relay request"));
        mutate(&mut request);
        let nonce: [u8; 32] = request.nonce.as_slice().try_into().expect("request nonce");
        sign_control_message(
            &request,
            signing_key,
            request.created_at_ms,
            request.expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .expect("re-signed client relay request")
    }

    fn bind_grant_to_request(route: &SignedRouteFixture, request: &[u8]) -> Vec<u8> {
        let request_hash = relay_reservation_request_sha256(request).expect("request hash");
        resign_consistent_grant(route, |relay, _| {
            relay.signed_client_relay_request_sha256 = request_hash.to_vec();
        })
    }

    fn resign_with_corrupt_nested_signature(route: &SignedRouteFixture) -> Vec<u8> {
        let mut relay = decode_relay_reservation(&route.relay_reservations()[0]);
        let last = relay
            .exit_authorization
            .last_mut()
            .expect("nested signature byte");
        *last ^= 1;
        let relay_nonce: [u8; 32] = relay.nonce.as_slice().try_into().expect("relay nonce");
        sign_control_message(
            &relay,
            route.relay_key(0).expect("relay key"),
            relay.created_at_ms,
            relay.expires_at_ms,
            relay_nonce,
            TimePolicy::default(),
        )
        .expect("relay reservation with corrupt nested signature")
    }

    fn endpoint_copy(endpoint: &WireguardEndpoint) -> (Vec<u8>, PublicUdpEndpoint) {
        (
            endpoint.public_key.clone(),
            PublicUdpEndpoint {
                address: endpoint.underlay_ip.clone(),
                port: endpoint.listen_port,
            },
        )
    }

    fn verify_fixture_plan(
        replay: &Mutex<ReplayCache>,
        key: OpenLineageKey,
        prepared: PreparedWorkerLease,
        value: &ActivateLeaseBatch,
        now_ms: u64,
    ) -> Result<ActivateLeases, BackendError> {
        let resource = process_owned_resource(
            key,
            &RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            },
        )
        .expect("resource");
        verified_internal_activate_plan(
            replay,
            resource.resource(),
            key,
            prepared,
            fixture_underlay(),
            &value.leases[0],
            now_ms,
        )
    }

    fn verify_exit_fixture_plan(
        replay: &Mutex<ReplayCache>,
        key: OpenLineageKey,
        prepared: PreparedWorkerLease,
        underlay: UnderlayCandidate,
        value: &ActivateLeaseBatch,
        now_ms: u64,
    ) -> Result<ActivateLeases, BackendError> {
        let resource = process_owned_resource(
            key,
            &RoutingLeasePlan {
                path_id: prepared.path_id,
                role: WireguardRole::Exit as i32,
            },
        )
        .expect("exit resource");
        verified_internal_activate_plan(
            replay,
            resource.resource(),
            key,
            prepared,
            underlay,
            &value.leases[0],
            now_ms,
        )
    }

    fn verify_relay_fixture_plan(
        replay: &Mutex<ReplayCache>,
        key: OpenLineageKey,
        prepared: &[PreparedWorkerLease; 2],
        underlay: UnderlayCandidate,
        value: &ActivateLeaseBatch,
        now_ms: u64,
    ) -> Result<ActivateLeases, BackendError> {
        let plans = [
            RoutingLeasePlan {
                path_id: prepared[0].path_id,
                role: prepared[0].role,
            },
            RoutingLeasePlan {
                path_id: prepared[1].path_id,
                role: prepared[1].role,
            },
        ];
        let resources = plans
            .iter()
            .map(|lease| process_owned_resource(key, lease))
            .collect::<Result<Vec<_>, _>>()
            .expect("relay resources");
        verified_internal_activate_batch_plan(
            replay,
            &resources,
            key,
            prepared,
            underlay,
            &value.leases,
            now_ms,
        )
    }

    #[test]
    fn markers_and_stage_request_ids_bind_complete_lineage() {
        let lease = RoutingLeasePlan {
            path_id: 1,
            role: WireguardRole::Client as i32,
        };
        let marker = ownership_marker(key(), &lease);
        assert_eq!(marker.len(), 64);
        assert!(
            marker
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_ne!(
            worker_request_id(key(), STAGE_INITIALISE),
            worker_request_id(key(), STAGE_PREPARE)
        );
        assert_ne!(
            worker_request_id(key(), STAGE_PREPARE),
            worker_request_id(key(), STAGE_ACTIVATE)
        );
        assert_ne!(
            worker_request_id(key(), STAGE_ACTIVATE),
            worker_request_id(key(), STAGE_DESTROY)
        );
        let (_, binding, _, _) = live_probe_fixture();
        let probe_id = worker_attempt_request_id(key(), STAGE_PROBE_COMMIT, binding);
        assert_ne!(probe_id, worker_request_id(key(), STAGE_DESTROY));
        assert_eq!(
            probe_id,
            worker_attempt_request_id(key(), STAGE_PROBE_COMMIT, binding)
        );
        for changed in [
            BackendBinding {
                operation_sequence: binding.operation_sequence + 1,
                ..binding
            },
            BackendBinding {
                operation_generation: binding.operation_generation + 1,
                ..binding
            },
            BackendBinding {
                request_id: [0xa1; 16],
                ..binding
            },
            BackendBinding {
                request_digest: [0xa2; 32],
                ..binding
            },
        ] {
            assert_ne!(
                probe_id,
                worker_attempt_request_id(key(), STAGE_PROBE_COMMIT, changed)
            );
        }
        let mut changed = key();
        changed.backend_generation += 1;
        assert_ne!(marker, ownership_marker(changed, &lease));
    }

    #[test]
    fn internal_plan_is_canonical_and_worker_rederivable() {
        let lease = RoutingLeasePlan {
            path_id: 1,
            role: WireguardRole::Client as i32,
        };
        let resource = process_owned_resource(key(), &lease).expect("resource");
        let plan = internal_prepare_plan(resource.resource(), key(), &lease);
        assert_eq!(plan.route_context_id, key().context_id);
        let [projected] = plan.leases.as_slice() else {
            panic!("one lease")
        };
        assert_eq!(projected.path_id, 1);
        assert_eq!(projected.role, InternalEndpointRole::Client as i32);
        assert_eq!(projected.setup_expires_at_unix, 6);
        assert_eq!(projected.hard_expires_at_unix, 7);
        assert_eq!(
            projected
                .local_overlay_address
                .as_ref()
                .expect("overlay")
                .prefix_length,
            128
        );
        assert_eq!(
            projected.ownership_alias,
            resource.resource().ownership_alias()
        );
    }

    #[test]
    fn functional_role_matrix_accepts_only_exact_client_and_exit_singletons() {
        for (binding, value, context, wireguard, internal_context, internal_endpoint) in [
            {
                let (binding, value) = live_prepare_fixture();
                (
                    binding,
                    value,
                    ContextRole::Client,
                    WireguardRole::Client,
                    InternalContextRole::Client,
                    InternalEndpointRole::Client,
                )
            },
            {
                let (binding, value) = live_exit_prepare_fixture();
                (
                    binding,
                    value,
                    ContextRole::Exit,
                    WireguardRole::Exit,
                    InternalContextRole::Exit,
                    InternalEndpointRole::Exit,
                )
            },
        ] {
            let (_, role, lease, _) =
                validate_prepare_binding(binding, &value).expect("functional role pair");
            assert_eq!(role.context, context);
            assert_eq!(role.wireguard, wireguard);
            assert_eq!(role.internal_context, internal_context);
            assert_eq!(role.internal_endpoint, internal_endpoint);
            let resource = process_owned_resource(OpenLineageKey::from(binding.lineage), &lease)
                .expect("role-bound resource");
            let plan = internal_prepare_plan(
                resource.resource(),
                OpenLineageKey::from(binding.lineage),
                &lease,
            );
            assert_eq!(plan.leases[0].role, internal_endpoint as i32);
        }

        let (binding, client) = live_prepare_fixture();
        let (_, exit) = live_exit_prepare_fixture();
        let mut invalid = Vec::new();
        let mut cross = client.clone();
        cross.leases[0].role = WireguardRole::Exit as i32;
        invalid.push(cross);
        let mut cross = exit;
        cross.leases[0].role = WireguardRole::Client as i32;
        invalid.push(cross);
        for role in [WireguardRole::RelayClient, WireguardRole::RelayExit] {
            let mut relay = client.clone();
            relay.role = ContextRole::Relay as i32;
            relay.leases[0].role = role as i32;
            invalid.push(relay);
        }
        let mut unspecified_context = client.clone();
        unspecified_context.role = ContextRole::Unspecified as i32;
        invalid.push(unspecified_context);
        let mut unspecified_endpoint = client;
        unspecified_endpoint.leases[0].role = WireguardRole::Unspecified as i32;
        invalid.push(unspecified_endpoint);

        for value in invalid {
            assert_eq!(
                validate_prepare_binding(binding, &value),
                Err(BackendError::Invalid)
            );
        }

        let (exit_binding, mut multipath_exit) = live_exit_prepare_fixture();
        multipath_exit.leases.push(multipath_exit.leases[0].clone());
        multipath_exit.leases[1].path_id = 2;
        assert_eq!(
            validate_prepare_binding(exit_binding, &multipath_exit),
            Err(BackendError::Unavailable),
            "the functional Exit seam remains an exact singleton"
        );
    }

    #[test]
    fn relay_prepare_accepts_only_one_canonical_atomic_endpoint_pair() {
        let (binding, value) = live_relay_prepare_fixture();
        let (key, context, leases, _) =
            validate_prepare_batch_binding(binding, &value).expect("relay pair binding");
        assert_eq!(context, ContextRole::Relay);
        assert_eq!(leases, value.leases);
        let resources = leases
            .iter()
            .map(|lease| process_owned_resource(key, lease))
            .collect::<Result<Vec<_>, _>>()
            .expect("relay resources");
        let plan = internal_prepare_batch_plan(&resources, key, &leases).expect("relay plan");
        assert_eq!(plan.leases.len(), 2);
        assert_eq!(
            plan.leases[0].role,
            InternalEndpointRole::RelayClient as i32
        );
        assert_eq!(plan.leases[1].role, InternalEndpointRole::RelayExit as i32);
        assert_ne!(
            plan.leases[0].ownership_alias,
            plan.leases[1].ownership_alias
        );
        assert_ne!(
            plan.leases[0].local_overlay_address,
            plan.leases[1].local_overlay_address
        );

        let mut malformed = Vec::new();
        let mut missing = value.clone();
        missing.leases.pop();
        malformed.push(missing);
        let mut reordered = value.clone();
        reordered.leases.swap(0, 1);
        malformed.push(reordered);
        let mut cross_path = value.clone();
        cross_path.leases[1].path_id = 2;
        malformed.push(cross_path);
        let mut duplicate_role = value.clone();
        duplicate_role.leases[1].role = WireguardRole::RelayClient as i32;
        malformed.push(duplicate_role);
        let mut client_context = value;
        client_context.role = ContextRole::Client as i32;
        malformed.push(client_context);
        for value in malformed {
            assert_eq!(
                validate_prepare_batch_binding(binding, &value),
                Err(BackendError::Invalid)
            );
        }
    }

    #[test]
    fn relay_activate_projects_the_exact_client_and_exit_authority_in_order() {
        let (key, binding, value, prepared, underlay, _) = live_relay_activate_fixture();
        let (validated_key, activations) =
            validate_activate_batch_binding(binding, &value).expect("relay activation binding");
        assert_eq!(validated_key, key);
        assert_eq!(activations, value.leases);
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let plan = verify_relay_fixture_plan(
            &replay,
            key,
            &prepared,
            underlay,
            &value,
            unix_milliseconds().expect("fixture time"),
        )
        .expect("verified relay pair");
        assert_eq!(lock_replay_cache(&replay).len(), 5);
        let [client, exit] = plan.leases.as_slice() else {
            panic!("two relay endpoint activations")
        };
        assert_eq!(client.role, InternalEndpointRole::RelayClient as i32);
        assert_eq!(exit.role, InternalEndpointRole::RelayExit as i32);
        assert_eq!(client.peer_public_key, value.leases[0].peer_public_key);
        assert_eq!(exit.peer_public_key, value.leases[1].peer_public_key);
        assert_ne!(client.peer_public_key, exit.peer_public_key);
        assert_ne!(client.peer_endpoint, exit.peer_endpoint);
        assert_ne!(client.allowed_prefixes, exit.allowed_prefixes);

        let (_, probe_binding, probe, _) = live_relay_probe_fixture();
        let (_, commits, _) =
            validate_probe_batch_binding(probe_binding, &probe).expect("relay probe binding");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].role, WireguardRole::RelayClient as i32);
        assert_eq!(commits[1].role, WireguardRole::RelayExit as i32);
    }

    #[test]
    fn relay_activate_shape_rejects_partial_reordered_or_ambiguous_pairs_before_authority() {
        let (_, binding, value, _, _, _) = live_relay_activate_fixture();
        let mut malformed = Vec::new();
        let mut missing = value.clone();
        missing.leases.pop();
        malformed.push(missing);
        let mut reordered = value.clone();
        reordered.leases.swap(0, 1);
        malformed.push(reordered);
        let mut cross_path = value.clone();
        cross_path.leases[1].path_id = 2;
        malformed.push(cross_path);
        let mut unequal_rate = value.clone();
        unequal_rate.leases[1].maximum_down_mbps += 1;
        malformed.push(unequal_rate);
        let mut unequal_grant = value.clone();
        *unequal_grant.leases[1]
            .signed_relay_reservation
            .last_mut()
            .expect("grant byte") ^= 1;
        malformed.push(unequal_grant);
        let mut request_on_both = value.clone();
        request_on_both.leases[1].signed_client_relay_request = request_on_both.leases[0]
            .signed_client_relay_request
            .clone();
        malformed.push(request_on_both);
        let mut duplicate_handle = value;
        duplicate_handle.leases[1].lease_handle = duplicate_handle.leases[0].lease_handle.clone();
        malformed.push(duplicate_handle);
        for value in malformed {
            assert_eq!(
                validate_activate_batch_binding(binding, &value),
                Err(BackendError::Invalid)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mutation matrix proves all five authority records roll back together"
    )]
    fn relay_authority_endpoint_and_request_substitutions_roll_back_all_replay_records() {
        let (key, _, value, prepared, underlay, route) = live_relay_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");
        let mut substitutions = Vec::new();

        let mut wrong_hash = value.clone();
        let grant = resign_consistent_grant(&route, |relay, _| {
            relay.signed_client_relay_request_sha256[0] ^= 1;
        });
        for lease in &mut wrong_hash.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(wrong_hash);

        for select_endpoint in [
            |relay: &mut RelayReservation| {
                relay
                    .relay_client_wireguard_endpoint
                    .as_mut()
                    .expect("relay-client local")
                    .listen_port += 10;
            },
            |relay: &mut RelayReservation| {
                relay
                    .relay_exit_wireguard_endpoint
                    .as_mut()
                    .expect("relay-exit local")
                    .public_key[0] ^= 1;
            },
        ] {
            let mut substituted = value.clone();
            let grant = resign_consistent_grant(&route, |relay, _| select_endpoint(relay));
            for lease in &mut substituted.leases {
                lease.signed_relay_reservation.clone_from(&grant);
            }
            substitutions.push(substituted);
        }

        let mut wrong_client_peer = value.clone();
        wrong_client_peer.leases[0].peer_public_key[0] ^= 1;
        substitutions.push(wrong_client_peer);
        let mut wrong_exit_peer = value.clone();
        wrong_exit_peer.leases[1]
            .peer_endpoint
            .as_mut()
            .expect("exit peer")
            .port += 1;
        substitutions.push(wrong_exit_peer);

        let request = resign_client_relay_request(&route, |request| {
            request
                .client_wireguard_endpoint
                .as_mut()
                .expect("client endpoint")
                .listen_port += 1;
        });
        let mut wrong_request_peer = value.clone();
        wrong_request_peer.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut wrong_request_peer.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(wrong_request_peer);

        let substitute_key = SigningKey::from_bytes(&[0x91; 32]);
        let substitute_session_id =
            node_id_from_public_key(&substitute_key.verifying_key().to_bytes());
        let request = resign_client_relay_request_with_key(&route, &substitute_key, |request| {
            request.client_session_id = substitute_session_id.to_vec();
        });
        let mut wrong_session = value.clone();
        wrong_session.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut wrong_session.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(wrong_session);

        let request = resign_client_relay_request(&route, |request| {
            *request.exit_authorization.last_mut().expect("nested byte") ^= 1;
        });
        let mut wrong_nested = value.clone();
        wrong_nested.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut wrong_nested.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(wrong_nested);

        let request = resign_client_relay_request(&route, |request| {
            *request
                .client_session_capability
                .last_mut()
                .expect("capability signature") ^= 1;
        });
        let mut corrupt_capability = value.clone();
        corrupt_capability.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut corrupt_capability.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(corrupt_capability);

        let request = resign_client_relay_request(&route, |request| {
            *request
                .exit_reservation
                .last_mut()
                .expect("exit reservation signature") ^= 1;
        });
        let mut corrupt_exit_reservation = value.clone();
        corrupt_exit_reservation.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut corrupt_exit_reservation.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(corrupt_exit_reservation);

        let other_route = SignedRouteFixture::new(1, &[Transport::TcpMptcp], now_ms)
            .expect("independent signed route");
        let request = resign_client_relay_request(&route, |request| {
            request.client_session_capability = other_route.client_session_capability().to_vec();
        });
        let mut substituted_capability = value.clone();
        substituted_capability.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut substituted_capability.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(substituted_capability);

        let request = resign_client_relay_request(&route, |request| {
            request.exit_reservation = other_route.exit_reservation().to_vec();
        });
        let mut substituted_exit_reservation = value.clone();
        substituted_exit_reservation.leases[0].signed_client_relay_request = request.clone();
        let grant = bind_grant_to_request(&route, &request);
        for lease in &mut substituted_exit_reservation.leases {
            lease.signed_relay_reservation.clone_from(&grant);
        }
        substitutions.push(substituted_exit_reservation);

        for substituted in substitutions {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            assert_eq!(
                verify_relay_fixture_plan(&replay, key, &prepared, underlay, &substituted, now_ms,),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            assert!(
                verify_relay_fixture_plan(&replay, key, &prepared, underlay, &value, now_ms)
                    .is_ok()
            );
        }
    }

    #[test]
    fn exit_activation_projects_only_exact_signed_relay_exit_peer() {
        let (key, binding, value, prepared, underlay, _) = live_exit_activate_fixture();
        let (validated_key, activation) =
            validate_activate_binding(binding, &value).expect("valid Exit Activate binding");
        assert_eq!(validated_key, key);
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let plan = verify_exit_fixture_plan(
            &replay,
            key,
            prepared,
            underlay,
            &value,
            unix_milliseconds().expect("fixture time"),
        )
        .expect("verified Exit activation plan");
        assert_eq!(lock_replay_cache(&replay).len(), 2);
        let [lease] = plan.leases.as_slice() else {
            panic!("one Exit activation")
        };
        assert_eq!(lease.role, InternalEndpointRole::Exit as i32);
        assert_eq!(lease.peer_public_key, activation.peer_public_key);
        assert_eq!(
            lease.peer_endpoint,
            Some(InternalUdpEndpoint {
                address: activation
                    .peer_endpoint
                    .as_ref()
                    .expect("relay-exit endpoint")
                    .address
                    .clone(),
                port: activation
                    .peer_endpoint
                    .as_ref()
                    .expect("relay-exit endpoint")
                    .port,
            })
        );
        let resource = process_owned_resource(
            key,
            &RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::Exit as i32,
            },
        )
        .expect("Exit resource");
        assert_eq!(
            lease.allowed_prefixes[0].address,
            resource.resource().peer_address().octets()
        );
        assert_eq!(lease.allowed_prefixes[0].prefix_length, 128);

        let mut nonzero_rate = value;
        nonzero_rate.leases[0].maximum_down_mbps = 1;
        assert_eq!(
            validate_activate_binding(binding, &nonzero_rate),
            Err(BackendError::Invalid)
        );
    }

    #[test]
    fn exit_activation_rejects_every_peer_endpoint_substitution_and_rolls_back_replay() {
        let (key, _, value, prepared, underlay, _) = live_exit_activate_fixture();
        let grant = decode_relay_reservation(&value.leases[0].signed_relay_reservation);
        let exit_endpoint = grant
            .exit_wireguard_endpoint
            .as_ref()
            .expect("signed exit endpoint")
            .clone();
        let client_endpoint = WireguardEndpoint {
            public_key: grant.client_wireguard_public_key.clone(),
            underlay_ip: exit_endpoint.underlay_ip.clone(),
            listen_port: 30_000,
        };
        for forbidden in [
            grant
                .relay_client_wireguard_endpoint
                .as_ref()
                .expect("relay-client endpoint")
                .clone(),
            exit_endpoint,
            client_endpoint,
        ] {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            let mut substituted = value.clone();
            let (public_key, endpoint) = endpoint_copy(&forbidden);
            substituted.leases[0].peer_public_key = public_key;
            substituted.leases[0].peer_endpoint = Some(endpoint);
            assert_eq!(
                verify_exit_fixture_plan(
                    &replay,
                    key,
                    prepared,
                    underlay,
                    &substituted,
                    unix_milliseconds().expect("fixture time"),
                ),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            assert!(
                verify_exit_fixture_plan(
                    &replay,
                    key,
                    prepared,
                    underlay,
                    &value,
                    unix_milliseconds().expect("fixture time"),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn exit_activation_binds_each_signed_local_endpoint_field_and_rolls_back_replay() {
        let (key, _, value, prepared, underlay, route) = live_exit_activate_fixture();
        let mutations: [fn(&mut WireguardEndpoint); 3] = [
            |endpoint| endpoint.public_key[0] ^= 1,
            |endpoint| endpoint.underlay_ip = vec![8, 8, 8, 8],
            |endpoint| endpoint.listen_port += 1,
        ];
        for mutate_endpoint in mutations {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            let mut substituted = value.clone();
            substituted.leases[0].signed_relay_reservation =
                resign_consistent_grant(&route, |relay, exit| {
                    mutate_endpoint(
                        relay
                            .exit_wireguard_endpoint
                            .as_mut()
                            .expect("relay copy of exit endpoint"),
                    );
                    mutate_endpoint(
                        exit.exit_wireguard_endpoint
                            .as_mut()
                            .expect("exit-signed endpoint"),
                    );
                });
            assert_eq!(
                verify_exit_fixture_plan(
                    &replay,
                    key,
                    prepared,
                    underlay,
                    &substituted,
                    unix_milliseconds().expect("fixture time"),
                ),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            assert!(
                verify_exit_fixture_plan(
                    &replay,
                    key,
                    prepared,
                    underlay,
                    &value,
                    unix_milliseconds().expect("fixture time"),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn prepare_validation_binds_the_complete_initial_operation() {
        let (binding, value) = live_prepare_fixture();
        assert!(validate_prepare_binding(binding, &value).is_ok());

        let mut expired = binding;
        expired.lineage.setup_expires_at_boottime_ns = 1;
        expired.lineage.hard_expires_at_boottime_ns = 1;
        assert_eq!(
            validate_prepare_binding(expired, &value).unwrap_err(),
            BackendError::Invalid
        );

        let mut wrong = binding;
        wrong.phase = BackendPhase::Prepared;
        assert_eq!(
            validate_prepare_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = binding;
        wrong.operation_kind = OperationKind::Activate;
        assert_eq!(
            validate_prepare_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = binding;
        wrong.prior_phase = Some(ContextPhase::Prepared);
        assert_eq!(
            validate_prepare_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = binding;
        wrong.operation_generation += 1;
        assert_eq!(
            validate_prepare_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.leases[0].role = WireguardRole::RelayClient as i32;
        assert_eq!(
            validate_prepare_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value;
        wrong.setup_expires_at_unix = 1;
        assert_eq!(
            validate_prepare_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test covers the complete external Activate shape plus verified worker projection"
    )]
    fn activate_validation_and_internal_plan_bind_the_exact_client_peer() {
        let (key, binding, value, prepared, _) = live_activate_fixture();
        let (validated_key, activation) =
            validate_activate_binding(binding, &value).expect("valid Activate binding");
        assert_eq!(validated_key, key);
        let resource = process_owned_resource(
            key,
            &RoutingLeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            },
        )
        .expect("resource");
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let plan = verified_internal_activate_plan(
            &replay,
            resource.resource(),
            key,
            prepared,
            fixture_underlay(),
            &activation,
            unix_milliseconds().expect("fixture time"),
        )
        .expect("verified internal activation plan");
        assert_eq!(lock_replay_cache(&replay).len(), 2);
        assert_eq!(plan.route_context_id, key.context_id);
        assert_eq!(
            plan.hard_expires_at_boottime_ns,
            key.hard_expires_at_boottime_ns
        );
        let [lease] = plan.leases.as_slice() else {
            panic!("one internal activation")
        };
        assert_eq!(lease.path_id, 1);
        assert_eq!(lease.role, InternalEndpointRole::Client as i32);
        assert_eq!(lease.peer_public_key, activation.peer_public_key);
        assert_eq!(
            lease.peer_endpoint,
            Some(InternalUdpEndpoint {
                address: activation
                    .peer_endpoint
                    .as_ref()
                    .expect("peer endpoint")
                    .address
                    .clone(),
                port: activation
                    .peer_endpoint
                    .as_ref()
                    .expect("peer endpoint")
                    .port,
            })
        );
        assert_eq!(lease.allowed_prefixes.len(), 1);
        assert_eq!(
            lease.allowed_prefixes[0].address,
            resource.resource().peer_address().octets()
        );
        assert_eq!(lease.allowed_prefixes[0].prefix_length, 128);
        assert_eq!(
            lease.persistent_keepalive_seconds,
            FUNCTIONAL_ALPHA_KEEPALIVE_SECONDS
        );

        let mut wrong = binding;
        wrong.prior_phase = None;
        assert_eq!(
            validate_activate_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut expired = binding;
        expired.lineage.setup_expires_at_boottime_ns = 1;
        expired.lineage.hard_expires_at_boottime_ns = 1;
        assert_eq!(
            validate_activate_binding(expired, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = binding;
        wrong.operation_generation += 1;
        assert_eq!(
            validate_activate_binding(wrong, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.leases[0].maximum_up_mbps = 1;
        assert_eq!(
            validate_activate_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.leases[0].role = WireguardRole::RelayExit as i32;
        assert_eq!(
            validate_activate_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut cross_role = value.clone();
        cross_role.leases[0].role = WireguardRole::Exit as i32;
        let (_, cross_role) =
            validate_activate_binding(binding, &cross_role).expect("supported Exit shape");
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert_eq!(
            verified_internal_activate_plan(
                &replay,
                resource.resource(),
                key,
                prepared,
                fixture_underlay(),
                &cross_role,
                unix_milliseconds().expect("fixture time"),
            ),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());
        let mut wrong = value.clone();
        wrong.leases[0].signed_relay_reservation.clear();
        assert_eq!(
            validate_activate_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut ambiguous = value.clone();
        ambiguous.leases.push(ambiguous.leases[0].clone());
        assert_eq!(
            validate_activate_binding(binding, &ambiguous).unwrap_err(),
            BackendError::Unavailable
        );
        let mut wrong = value;
        wrong.leases[0]
            .peer_endpoint
            .as_mut()
            .expect("peer endpoint")
            .address = vec![0; 4];
        assert_eq!(
            validate_activate_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
    }

    #[test]
    fn probe_validation_binds_engine_activation_threshold_and_exact_client_lease() {
        let (_, binding, value, _) = live_probe_fixture();
        assert!(validate_probe_binding(binding, &value).is_ok());

        let mut expired = binding;
        expired.lineage.setup_expires_at_boottime_ns = 1;
        expired.lineage.hard_expires_at_boottime_ns = 1;
        assert_eq!(
            validate_probe_binding(expired, &value).unwrap_err(),
            BackendError::Invalid
        );

        let mut wrong_binding = binding;
        wrong_binding.operation_generation = 0;
        assert_eq!(
            validate_probe_binding(wrong_binding, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong_binding = binding;
        wrong_binding.prior_phase = Some(ContextPhase::Prepared);
        assert_eq!(
            validate_probe_binding(wrong_binding, &value).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.activated_at_unix = 0;
        assert_eq!(
            validate_probe_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.activated_at_unix = binding.lineage.setup_expires_at_unix;
        assert_eq!(
            validate_probe_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value.clone();
        wrong.commit.leases[0].path_id = 0;
        assert_eq!(
            validate_probe_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
        let mut wrong = value;
        wrong.commit.leases[0].role = WireguardRole::RelayClient as i32;
        assert_eq!(
            validate_probe_binding(binding, &wrong).unwrap_err(),
            BackendError::Invalid
        );
    }

    #[tokio::test]
    async fn exit_probe_binds_activation_threshold_role_and_strict_counter_growth() {
        let (key, binding, value, activated) = live_exit_probe_fixture();
        let (_, commit, threshold) =
            validate_probe_binding(binding, &value).expect("valid Exit Probe binding");
        assert_eq!(commit.role, WireguardRole::Exit as i32);
        assert_eq!(threshold, value.activated_at_unix);

        let execution = |handshake, received, transmitted| {
            crate::worker_transport::CredentialedWorkerExecution {
                response: crate::internal_protocol::InternalWorkerResponse {
                    protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                    magic: INTERNAL_WORKER_MAGIC.to_vec(),
                    request_id: vec![0x91; 16],
                    result: InternalWorkerResult::Ok as i32,
                    request_digest: vec![0x92; 32],
                    outcome: Some(internal_worker_response::Outcome::ProbedCommitted(
                        crate::internal_protocol::ProbedLeases {
                            leases: vec![crate::internal_protocol::ProbedLease {
                                path_id: activated.prepared.path_id,
                                role: activated.prepared.role,
                                latest_handshake_unix: handshake,
                                received_bytes: received,
                                transmitted_bytes: transmitted,
                            }],
                        },
                    )),
                },
                descriptor: None,
            }
        };
        assert_eq!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 51, 61)),
                activated,
                value.activated_at_unix,
            ),
            Some(KernelCounters {
                path_id: 1,
                role: WireguardRole::Exit as i32,
                latest_handshake_unix: value.activated_at_unix,
                received_bytes: 51,
                transmitted_bytes: 61,
            })
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix - 1, 51, 61)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 50, 61)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 51, 60)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );

        let mut substituted = value;
        substituted.commit.leases[0].role = WireguardRole::Client as i32;
        let mut entry = open_entry_for_role(key, WireguardRole::Exit);
        entry.prepared = vec![activated.prepared];
        entry.activated = vec![activated];
        entry.phase = OpenLeasePhase::Activated;
        let backend = backend_with_state(Some(entry));
        assert_eq!(
            backend.probe_one(binding, substituted).await,
            Err(BackendError::Invalid)
        );
        assert_eq!(
            lock_state(&backend.state).as_ref().map(|entry| entry.phase),
            Some(OpenLeasePhase::Activated)
        );
    }

    #[test]
    fn exit_signed_scope_ttl_signers_and_replay_fail_closed() {
        let (key, _, value, prepared, underlay, route) = live_exit_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut wrong_context = key;
        wrong_context.context_id[0] ^= 1;
        assert_eq!(
            verify_exit_fixture_plan(&replay, wrong_context, prepared, underlay, &value, now_ms,),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut wrong_path = prepared;
        wrong_path.path_id = 2;
        assert_eq!(
            verify_exit_fixture_plan(&replay, key, wrong_path, underlay, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut outlives_grant = key;
        outlives_grant.hard_expires_at_unix = route.expires_at_ms() / 1_000 + 1;
        assert_eq!(
            verify_exit_fixture_plan(&replay, outlives_grant, prepared, underlay, &value, now_ms,),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        for signed in [
            resign_consistent_grant(&route, |relay, exit| {
                relay.relay_peer_id = vec![0xa1];
                exit.relay_peer_id = vec![0xa1];
            }),
            resign_consistent_grant(&route, |relay, exit| {
                relay.exit_peer_id = vec![0xa2];
                exit.exit_peer_id = vec![0xa2];
            }),
        ] {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            let mut substituted = value.clone();
            substituted.leases[0].signed_relay_reservation = signed;
            assert_eq!(
                verify_exit_fixture_plan(&replay, key, prepared, underlay, &substituted, now_ms,),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            assert!(
                verify_exit_fixture_plan(&replay, key, prepared, underlay, &value, now_ms,).is_ok()
            );
        }

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert!(verify_exit_fixture_plan(&replay, key, prepared, underlay, &value, now_ms).is_ok());
        assert_eq!(lock_replay_cache(&replay).len(), 2);
        assert_eq!(
            verify_exit_fixture_plan(&replay, key, prepared, underlay, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&replay).len(), 2);
    }

    #[tokio::test]
    async fn exit_post_verification_worker_lookup_failure_retains_both_replay_records() {
        let (key, binding, value, prepared, underlay, _) = live_exit_activate_fixture();
        let mut entry = open_entry_for_role(key, WireguardRole::Exit);
        entry.underlay = underlay;
        entry.prepared = vec![prepared];
        entry.phase = OpenLeasePhase::Prepared;
        let backend = backend_with_state(Some(entry));

        assert_eq!(
            backend.activate_one(binding, value.clone()).await,
            Err(BackendError::CleanupIncomplete)
        );
        assert!(lock_state(&backend.state).is_none());
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 2);

        let mut retry = open_entry_for_role(key, WireguardRole::Exit);
        retry.underlay = underlay;
        retry.prepared = vec![prepared];
        retry.phase = OpenLeasePhase::Prepared;
        *lock_state(&backend.state) = Some(retry);
        let mut retry_binding = binding;
        retry_binding.operation_sequence += 1;
        retry_binding.request_id = [0xb3; 16];
        retry_binding.request_digest = [0xb4; 32];
        retry_binding.call_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            backend.activate_one(retry_binding, value).await,
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 2);
        drop(lock_state(&backend.state).take());
    }

    #[tokio::test]
    async fn relay_post_verification_worker_lookup_failure_retains_all_five_replay_records() {
        let (key, binding, value, prepared, underlay, _) = live_relay_activate_fixture();
        let mut entry = open_relay_entry(key);
        entry.underlay = underlay;
        entry.prepared = prepared.to_vec();
        entry.phase = OpenLeasePhase::Prepared;
        let backend = backend_with_state(Some(entry));

        assert_eq!(
            backend.activate_one(binding, value.clone()).await,
            Err(BackendError::CleanupIncomplete)
        );
        assert!(lock_state(&backend.state).is_none());
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 5);

        let mut retry = open_relay_entry(key);
        retry.underlay = underlay;
        retry.prepared = prepared.to_vec();
        retry.phase = OpenLeasePhase::Prepared;
        *lock_state(&backend.state) = Some(retry);
        let mut retry_binding = binding;
        retry_binding.operation_sequence += 1;
        retry_binding.request_id = [0xd3; 16];
        retry_binding.request_digest = [0xd4; 32];
        retry_binding.call_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            backend.activate_one(retry_binding, value).await,
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 5);
        drop(lock_state(&backend.state).take());
    }

    #[test]
    fn relay_grant_signatures_expiry_replay_and_capacity_fail_closed() {
        let (key, _, value, prepared, route) = live_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");

        let mut corrupt_outer = value.clone();
        *corrupt_outer.leases[0]
            .signed_relay_reservation
            .last_mut()
            .expect("outer signature byte") ^= 1;
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &corrupt_outer, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let mut noncanonical = value.clone();
        noncanonical.leases[0]
            .signed_relay_reservation
            .extend_from_slice(&[0x98, 0x06, 0x01]);
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &noncanonical, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let mut corrupt_nested = value.clone();
        corrupt_nested.leases[0].signed_relay_reservation =
            resign_with_corrupt_nested_signature(&route);
        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &corrupt_nested, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &value, route.expires_at_ms()),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        assert!(verify_fixture_plan(&replay, key, prepared, &value, now_ms).is_ok());
        assert_eq!(lock_replay_cache(&replay).len(), 2);
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&replay).len(), 2);

        let replay = Mutex::new(ReplayCache::new(1).expect("bounded replay cache"));
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &value, now_ms),
            Err(BackendError::Capacity)
        );
        assert!(lock_replay_cache(&replay).is_empty());
    }

    #[test]
    fn signed_scope_and_helper_owned_prepare_binding_roll_back_before_mutation() {
        let (key, _, value, prepared, route) = live_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut wrong_context = key;
        wrong_context.context_id[0] ^= 1;
        assert_eq!(
            verify_fixture_plan(&replay, wrong_context, prepared, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());
        assert!(verify_fixture_plan(&replay, key, prepared, &value, now_ms).is_ok());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut wrong_path = prepared;
        wrong_path.path_id = 2;
        assert_eq!(
            verify_fixture_plan(&replay, key, wrong_path, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut signed_wrong_path = value.clone();
        signed_wrong_path.leases[0].signed_relay_reservation =
            resign_consistent_grant(&route, |relay, exit| {
                relay.path_id = 2;
                exit.path_id = 2;
            });
        assert_eq!(
            verify_fixture_plan(&replay, key, prepared, &signed_wrong_path, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut wrong_key = prepared;
        wrong_key.public_key[0] ^= 1;
        assert_eq!(
            verify_fixture_plan(&replay, key, wrong_key, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());

        let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
        let mut outlives_grant = key;
        outlives_grant.hard_expires_at_unix = route.expires_at_ms() / 1_000 + 1;
        assert_eq!(
            verify_fixture_plan(&replay, outlives_grant, prepared, &value, now_ms),
            Err(BackendError::Invalid)
        );
        assert!(lock_replay_cache(&replay).is_empty());
    }

    #[test]
    fn only_exact_signed_relay_client_endpoint_can_reach_worker_plan() {
        let (key, _, value, prepared, _) = live_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");
        let signed_grant = decode_relay_reservation(&value.leases[0].signed_relay_reservation);

        for forbidden in [
            signed_grant
                .relay_exit_wireguard_endpoint
                .as_ref()
                .expect("relay-exit endpoint"),
            signed_grant
                .exit_wireguard_endpoint
                .as_ref()
                .expect("exit endpoint"),
        ] {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            let mut substituted = value.clone();
            let (key_copy, endpoint_copy) = endpoint_copy(forbidden);
            substituted.leases[0].peer_public_key = key_copy;
            substituted.leases[0].peer_endpoint = Some(endpoint_copy);
            assert_eq!(
                verify_fixture_plan(&replay, key, prepared, &substituted, now_ms),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            let plan = verify_fixture_plan(&replay, key, prepared, &value, now_ms)
                .expect("same grant remains usable after local mismatch rollback");
            let [lease] = plan.leases.as_slice() else {
                panic!("one activation")
            };
            assert_eq!(lease.peer_public_key, value.leases[0].peer_public_key);
            assert_eq!(
                lease.peer_endpoint.as_ref().expect("peer endpoint").address,
                value.leases[0]
                    .peer_endpoint
                    .as_ref()
                    .expect("copied endpoint")
                    .address
            );
        }
    }

    #[test]
    fn relay_and_exit_peer_ids_must_derive_from_their_ed25519_signers() {
        let (key, _, value, prepared, route) = live_activate_fixture();
        let now_ms = unix_milliseconds().expect("fixture time");

        for signed in [
            resign_consistent_grant(&route, |relay, exit| {
                relay.relay_peer_id = vec![0x91];
                exit.relay_peer_id = vec![0x91];
            }),
            resign_consistent_grant(&route, |relay, exit| {
                relay.exit_peer_id = vec![0x92];
                exit.exit_peer_id = vec![0x92];
            }),
        ] {
            let replay = Mutex::new(ReplayCache::new(8).expect("replay cache"));
            let mut substituted = value.clone();
            substituted.leases[0].signed_relay_reservation = signed;
            assert_eq!(
                verify_fixture_plan(&replay, key, prepared, &substituted, now_ms),
                Err(BackendError::Invalid)
            );
            assert!(lock_replay_cache(&replay).is_empty());
            assert!(verify_fixture_plan(&replay, key, prepared, &value, now_ms).is_ok());
        }
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test keeps post-verification dispatch, cleanup and both replay identities in one auditable transaction"
    )]
    async fn post_verification_worker_failure_retains_both_replay_records() {
        let (key, mut binding, value, prepared, route) = live_activate_fixture();
        binding.call_deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        let (parent, peer) =
            private_credential_worker_channel().expect("credentialed fake worker channel");
        let alive = Arc::new(AtomicBool::new(true));
        let mut process = WorkerProcess::fake(parent, std::process::id(), Arc::clone(&alive));
        let coordinator = WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        ));
        let ownership = match coordinator.reserve_spawn_register_with_until(
            key.context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa5; 32]),
                })
            },
        ) {
            WorkerLifecycleAdmission::Registered(ownership) => ownership,
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("fake worker registration rejected: {error}")
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("fake worker registration unresolved: {error}")
            }
        };
        {
            let mut registry = coordinator
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = registry
                .records
                .get_mut(&key.context_id)
                .expect("registered fake worker");
            assert_eq!(
                record.generation,
                ownership.coordinates.worker_generation.get()
            );
            record.stable_phase = StablePhase::Prepared;
        }

        let mut entry = open_entry(key);
        entry.worker = Some(ownership);
        entry.prepared = vec![prepared];
        entry.phase = OpenLeasePhase::Prepared;
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
            durable_ownership: None,
        };

        let expected_worker = ExpectedUnixCredentials::new(
            std::process::id(),
            geteuid().as_raw(),
            getegid().as_raw(),
        )
        .expect("current worker credentials");
        let worker = std::thread::spawn(move || {
            let activate = receive_credential_worker_request(&peer, expected_worker)
                .expect("dispatched Activate request");
            assert!(matches!(
                activate.request.operation,
                Some(internal_worker_request::Operation::ActivateLeases(_))
            ));
            let failed = correlated_response(&activate.request, InternalWorkerResult::Kernel, None)
                .expect("correlated Activate failure");
            send_credential_worker_response(&peer, &activate.request, &failed, None)
                .expect("send Activate failure");

            let destroy = receive_credential_worker_request(&peer, expected_worker)
                .expect("cleanup Destroy request");
            assert!(matches!(
                destroy.request.operation,
                Some(internal_worker_request::Operation::DestroyContext(_))
            ));
            let destroyed = correlated_response(
                &destroy.request,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::Destroyed(
                    ContextDestroyed {},
                )),
            )
            .expect("correlated Destroy success");
            send_credential_worker_response(&peer, &destroy.request, &destroyed, None)
                .expect("send Destroy success");
        });

        assert_eq!(
            backend.activate_one(binding, value.clone()).await,
            Err(BackendError::Kernel)
        );
        worker.join().expect("fake worker thread");
        assert!(!alive.load(Ordering::SeqCst));
        assert!(lock_state(&backend.state).is_none());
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 2);

        let mut retry_entry = open_entry(key);
        retry_entry.prepared = vec![prepared];
        retry_entry.phase = OpenLeasePhase::Prepared;
        *lock_state(&backend.state) = Some(retry_entry);

        let mut exact_retry = binding;
        exact_retry.operation_sequence += 1;
        exact_retry.request_id = [0xb1; 16];
        exact_retry.request_digest = [0xb2; 32];
        exact_retry.call_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            backend.activate_one(exact_retry, value.clone()).await,
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 2);

        // A fresh outer relay nonce gets as far as the unchanged nested exit envelope. Its replay
        // rejection, plus the exact-grant rejection above, proves both original records survived
        // the post-verification worker failure. The newly admitted outer nonce is rolled back.
        let mut fresh_outer = decode_relay_reservation(&value.leases[0].signed_relay_reservation);
        let retained_exit_envelope = fresh_outer.exit_authorization.clone();
        let fresh_relay_nonce = loop {
            let candidate = generate_nonce();
            if fresh_outer.nonce.as_slice() != candidate {
                break candidate;
            }
        };
        fresh_outer.nonce = fresh_relay_nonce.to_vec();
        let mut nested_retry = value;
        nested_retry.leases[0].signed_relay_reservation = sign_control_message(
            &fresh_outer,
            route.relay_key(0).expect("relay signing key"),
            fresh_outer.created_at_ms,
            fresh_outer.expires_at_ms,
            fresh_relay_nonce,
            TimePolicy::default(),
        )
        .expect("fresh outer envelope around retained exit envelope");
        assert_eq!(
            decode_relay_reservation(&nested_retry.leases[0].signed_relay_reservation)
                .exit_authorization,
            retained_exit_envelope
        );
        let mut nested_replay_request = exact_retry;
        nested_replay_request.operation_sequence += 1;
        nested_replay_request.request_id = [0xc1; 16];
        nested_replay_request.request_digest = [0xc2; 32];
        nested_replay_request.call_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            backend
                .activate_one(nested_replay_request, nested_retry)
                .await,
            Err(BackendError::Invalid)
        );
        assert_eq!(lock_replay_cache(&backend.relay_replay).len(), 2);
        drop(lock_state(&backend.state).take());
    }

    #[test]
    fn activated_response_preserves_zero_or_nonzero_kernel_baselines_exactly() {
        let (_, _, _, prepared, _) = live_activate_fixture();
        let execution = |handshake, nanoseconds, received, transmitted| {
            crate::worker_transport::CredentialedWorkerExecution {
                response: crate::internal_protocol::InternalWorkerResponse {
                    protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                    magic: INTERNAL_WORKER_MAGIC.to_vec(),
                    request_id: vec![7; 16],
                    result: InternalWorkerResult::Ok as i32,
                    request_digest: vec![8; 32],
                    outcome: Some(internal_worker_response::Outcome::Activated(
                        crate::internal_protocol::ActivatedLeases {
                            leases: vec![crate::internal_protocol::ActivatedLease {
                                path_id: prepared.path_id,
                                role: prepared.role,
                                public_key: prepared.public_key.to_vec(),
                                listen_port: u32::from(prepared.listen_port),
                                latest_handshake_unix: handshake,
                                latest_handshake_nanoseconds: nanoseconds,
                                received_bytes: received,
                                transmitted_bytes: transmitted,
                            }],
                        },
                    )),
                },
                descriptor: None,
            }
        };

        assert_eq!(
            matches_activated(Some(&execution(0, 0, 0, 0)), prepared),
            Some(KernelCounters {
                path_id: 1,
                role: WireguardRole::Client as i32,
                latest_handshake_unix: 0,
                received_bytes: 0,
                transmitted_bytes: 0,
            })
        );
        assert_eq!(
            matches_activated(Some(&execution(123, 456, 11, 12)), prepared),
            Some(KernelCounters {
                path_id: 1,
                role: WireguardRole::Client as i32,
                latest_handshake_unix: 123,
                received_bytes: 11,
                transmitted_bytes: 12,
            })
        );
        assert!(matches_activated(Some(&execution(0, 1, 0, 0)), prepared).is_none());
        assert!(matches_activated(Some(&execution(0, 1_000_000_000, 0, 0)), prepared).is_none());
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test keeps the divergent Probe response and exact cleanup in one audit unit"
    )]
    async fn semantically_invalid_successful_probe_is_destroyed_and_removed() {
        let (key, mut binding, value, activated) = live_probe_fixture();
        binding.call_deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        let (parent, peer) =
            private_credential_worker_channel().expect("credentialed fake worker channel");
        let alive = Arc::new(AtomicBool::new(true));
        let mut process = WorkerProcess::fake(parent, std::process::id(), Arc::clone(&alive));
        let coordinator = WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        ));
        let ownership = match coordinator.reserve_spawn_register_with_until(
            key.context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa5; 32]),
                })
            },
        ) {
            WorkerLifecycleAdmission::Registered(ownership) => ownership,
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("fake worker registration rejected: {error}")
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("fake worker registration unresolved: {error}")
            }
        };
        {
            let mut registry = coordinator
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = registry
                .records
                .get_mut(&key.context_id)
                .expect("registered fake worker");
            assert_eq!(
                record.generation,
                ownership.coordinates.worker_generation.get()
            );
            record.stable_phase = StablePhase::Activated;
        }

        let mut entry = open_entry(key);
        entry.worker = Some(ownership);
        entry.prepared = vec![activated.prepared];
        entry.activated = vec![activated];
        entry.phase = OpenLeasePhase::Activated;
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
            durable_ownership: None,
        };

        let expected_worker = ExpectedUnixCredentials::new(
            std::process::id(),
            geteuid().as_raw(),
            getegid().as_raw(),
        )
        .expect("current worker credentials");
        let worker = std::thread::spawn(move || {
            let probe = receive_credential_worker_request(&peer, expected_worker)
                .expect("dispatched Probe request");
            assert!(matches!(
                probe.request.operation,
                Some(internal_worker_request::Operation::ProbeCommitLeases(_))
            ));
            let malformed = correlated_response(
                &probe.request,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::ProbedCommitted(
                    crate::internal_protocol::ProbedLeases {
                        leases: vec![crate::internal_protocol::ProbedLease {
                            path_id: activated.prepared.path_id,
                            role: activated.prepared.role,
                            latest_handshake_unix: value.activated_at_unix,
                            received_bytes: activated.baseline.received_bytes,
                            transmitted_bytes: activated.baseline.transmitted_bytes + 1,
                        }],
                    },
                )),
            )
            .expect("correlated malformed Probe success");
            send_credential_worker_response(&peer, &probe.request, &malformed, None)
                .expect("send malformed Probe success");

            let destroy = receive_credential_worker_request(&peer, expected_worker)
                .expect("cleanup Destroy request");
            assert!(matches!(
                destroy.request.operation,
                Some(internal_worker_request::Operation::DestroyContext(_))
            ));
            let destroyed = correlated_response(
                &destroy.request,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::Destroyed(
                    ContextDestroyed {},
                )),
            )
            .expect("correlated Destroy success");
            send_credential_worker_response(&peer, &destroy.request, &destroyed, None)
                .expect("send Destroy success");
        });

        assert_eq!(
            backend.probe_one(binding, value).await,
            Err(BackendError::CleanupIncomplete)
        );
        worker.join().expect("fake worker thread");
        assert!(!alive.load(Ordering::SeqCst));
        assert!(lock_state(&backend.state).is_none());
    }

    #[test]
    fn probed_response_requires_threshold_and_strict_bidirectional_growth() {
        let (_, _, value, activated) = live_probe_fixture();
        let execution = |handshake, received, transmitted| {
            crate::worker_transport::CredentialedWorkerExecution {
                response: crate::internal_protocol::InternalWorkerResponse {
                    protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                    magic: INTERNAL_WORKER_MAGIC.to_vec(),
                    request_id: vec![7; 16],
                    result: InternalWorkerResult::Ok as i32,
                    request_digest: vec![8; 32],
                    outcome: Some(internal_worker_response::Outcome::ProbedCommitted(
                        crate::internal_protocol::ProbedLeases {
                            leases: vec![crate::internal_protocol::ProbedLease {
                                path_id: activated.prepared.path_id,
                                role: activated.prepared.role,
                                latest_handshake_unix: handshake,
                                received_bytes: received,
                                transmitted_bytes: transmitted,
                            }],
                        },
                    )),
                },
                descriptor: None,
            }
        };

        assert_eq!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 11, 21)),
                activated,
                value.activated_at_unix,
            ),
            Some(KernelCounters {
                path_id: 1,
                role: WireguardRole::Client as i32,
                latest_handshake_unix: value.activated_at_unix,
                received_bytes: 11,
                transmitted_bytes: 21,
            })
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix - 1, 11, 21)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 10, 21)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );
        assert!(
            matches_probed(
                Some(&execution(value.activated_at_unix, 11, 20)),
                activated,
                value.activated_at_unix,
            )
            .is_none()
        );
    }

    #[test]
    fn relay_probe_requires_complete_ordered_proof_and_growth_on_both_legs() {
        let (_, _, value, activated) = live_relay_probe_fixture();
        let execution = |second_leg_grows: bool| {
            let leases = activated
                .iter()
                .enumerate()
                .map(|(index, lease)| crate::internal_protocol::ProbedLease {
                    path_id: lease.prepared.path_id,
                    role: functional_lease_role_for_wireguard(lease.prepared.role)
                        .expect("relay role")
                        .internal_endpoint as i32,
                    latest_handshake_unix: value.activated_at_unix,
                    received_bytes: lease.baseline.received_bytes
                        + u64::from(index == 0 || second_leg_grows),
                    transmitted_bytes: lease.baseline.transmitted_bytes + 1,
                })
                .collect();
            crate::worker_transport::CredentialedWorkerExecution {
                response: crate::internal_protocol::InternalWorkerResponse {
                    protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                    magic: INTERNAL_WORKER_MAGIC.to_vec(),
                    request_id: vec![7; 16],
                    result: InternalWorkerResult::Ok as i32,
                    request_digest: vec![8; 32],
                    outcome: Some(internal_worker_response::Outcome::ProbedCommitted(
                        crate::internal_protocol::ProbedLeases { leases },
                    )),
                },
                descriptor: None,
            }
        };

        let complete = execution(true);
        let proof = matches_probed_batch(Some(&complete), &activated, value.activated_at_unix)
            .expect("both relay legs prove ready");
        assert_eq!(proof.len(), 2);
        assert!(
            matches_probed_batch(Some(&execution(false)), &activated, value.activated_at_unix,)
                .is_none()
        );
        let mut partial = execution(true);
        let Some(internal_worker_response::Outcome::ProbedCommitted(probed)) =
            partial.response.outcome.as_mut()
        else {
            panic!("probe response")
        };
        probed.leases.pop();
        assert!(
            matches_probed_batch(Some(&partial), &activated, value.activated_at_unix).is_none()
        );
        let mut reordered = execution(true);
        let Some(internal_worker_response::Outcome::ProbedCommitted(probed)) =
            reordered.response.outcome.as_mut()
        else {
            panic!("probe response")
        };
        probed.leases.swap(0, 1);
        assert!(
            matches_probed_batch(Some(&reordered), &activated, value.activated_at_unix,).is_none()
        );
    }

    #[tokio::test]
    async fn foreign_lineage_destroy_confirms_absent_without_disturbing_open_entry() {
        let open_key = key();
        let backend = backend_with_state(Some(open_entry(open_key)));
        let mut foreign_key = open_key;
        foreign_key.context_id = [7; 16];
        foreign_key.backend_generation += 1;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            backend
                .destroy_one(
                    destroy_binding(foreign_key, deadline),
                    destroy_value(foreign_key),
                )
                .await,
            Ok(ConfirmedAbsent)
        );
        assert_eq!(
            lock_state(&backend.state).as_ref().map(|entry| entry.key),
            Some(open_key)
        );
    }

    #[tokio::test]
    async fn confirmed_reap_releases_recovery_pins_before_retryable_parent_cleanup() {
        let open_key = key();
        let (parent, _peer) =
            private_credential_worker_channel().expect("credentialed fake worker channel");
        let alive = Arc::new(AtomicBool::new(true));
        let mut process = WorkerProcess::fake(parent, std::process::id(), Arc::clone(&alive));
        let coordinator = WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        ));
        let ownership = match coordinator.reserve_spawn_register_with_until(
            open_key.context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xd5; 32]),
                })
            },
        ) {
            WorkerLifecycleAdmission::Registered(ownership) => ownership,
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("fake worker registration rejected: {error}")
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("fake worker registration unresolved: {error}")
            }
        };
        let recovery = coordinator
            .recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("recovery deadline"),
            )
            .expect("authenticated duplicate recovery pins");

        let mut entry = open_relay_entry(open_key);
        entry.worker = Some(ownership);
        entry.recovery = Some(recovery);
        entry.phase = OpenLeasePhase::Registered;
        // A corrupt cardinality is a deterministic, retryable parent-cleanup failure after reap.
        // The remaining WireGuard owners must survive, but the dead worker's namespace pins must
        // not survive with them.
        entry.birth_may_exist.clear();
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
            durable_ownership: None,
        };

        let cleanup_deadline =
            HardDeadline::after(Duration::from_millis(650)).expect("cleanup deadline");
        let operation_deadline =
            worker_operation_deadline(cleanup_deadline).expect("reserved retirement tail");
        tokio::time::sleep(
            operation_deadline
                .remaining()
                .expect("live operation deadline")
                + Duration::from_millis(10),
        )
        .await;
        assert!(operation_deadline.ensure_remaining().is_err());
        assert!(
            !backend
                .cleanup_exact(open_key, cleanup_deadline, false)
                .await
        );
        assert!(!alive.load(Ordering::SeqCst));
        let state = lock_state(&backend.state);
        let retained = state.as_ref().expect("retryable parent ownership");
        assert!(retained.worker.is_none());
        assert!(retained.recovery.is_none());
        assert_eq!(retained.wireguard.len(), 2);
        assert!(retained.birth_may_exist.is_empty());
    }

    #[tokio::test]
    async fn expired_destroy_retains_open_owner_for_exact_retry() {
        let open_key = key();
        let backend = backend_with_state(Some(open_entry(open_key)));
        let deadline = tokio::time::Instant::now() - Duration::from_millis(1);
        assert_eq!(
            backend
                .destroy_one(destroy_binding(open_key, deadline), destroy_value(open_key),)
                .await,
            Err(BackendError::CleanupIncomplete)
        );
        assert_eq!(
            lock_state(&backend.state).as_ref().map(|entry| entry.key),
            Some(open_key)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn later_destroy_retries_exact_handoff_terminal_and_removes_only_after_durable_absent() {
        let open_key = key();
        let directory = tempdir().expect("durable handoff directory");
        let mut actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(2)).expect("actor startup deadline"),
        )
        .expect("durable ownership actor");
        let handle = actor.prepare_handle().expect("durable Prepare handle");
        let registration = DurableIntentRegistration::try_from_wire(
            open_key.helper_runtime_id,
            &PrepareIntent {
                route_context_id: open_key.context_id.to_vec(),
                prepare_request_id: open_key.prepare_request_id.to_vec(),
                prepare_operation_digest: open_key.prepare_operation_digest.to_vec(),
                setup_expires_at_unix: 100,
                hard_expires_at_unix: 200,
                closed_plan: Some(ClosedPreparePlan {
                    context_role: ContextRole::Client as i32,
                    leases: vec![RoutingLeasePlan {
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                    }],
                }),
            },
        )
        .expect("durable registration");
        let durable_key = match handle.register_until(
            registration,
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
        ) {
            crate::ownership_journal::DurableRegistrationOutcome::Registered(key) => key,
            crate::ownership_journal::DurableRegistrationOutcome::Retained {
                error,
                registration,
            } => {
                drop(registration);
                panic!("durable registration remained retained: {error}")
            }
        };
        let coordinator = WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        ));
        let selector = coordinator
            .settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .store_durable_prepare_terminal(DurableWorkerPrepareTerminal::Handoff(Box::new(
                DurableWorkerPrepareOutcome::KeyRetained {
                    error: WorkerV3Error::Invalid,
                    key: durable_key,
                },
            )))
            .expect("ordinary handoff selector");
        let mut entry = open_entry(open_key);
        entry.phase = OpenLeasePhase::DurableHandoffPending;
        entry.durable_handoff_terminal = Some(selector);
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
            durable_ownership: Some(handle),
        };

        assert_eq!(
            backend
                .destroy_one(
                    destroy_binding(
                        open_key,
                        tokio::time::Instant::now() - Duration::from_millis(1),
                    ),
                    destroy_value(open_key),
                )
                .await,
            Err(BackendError::CleanupIncomplete)
        );
        assert!(
            lock_state(&backend.state)
                .as_ref()
                .is_some_and(|entry| entry.durable_handoff_terminal.is_some())
        );
        assert_eq!(
            backend
                .destroy_one(
                    destroy_binding(
                        open_key,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    ),
                    destroy_value(open_key),
                )
                .await,
            Ok(ConfirmedAbsent)
        );
        assert!(lock_state(&backend.state).is_none());
        assert!(backend.coordinator.shutdown().await);
        drop(backend);
        assert_eq!(
            actor.shutdown_for_test(
                HardDeadline::after(Duration::from_secs(1)).expect("actor shutdown deadline")
            ),
            Ok(())
        );
    }

    #[tokio::test]
    async fn exact_destroy_is_idempotent_and_releases_capacity() {
        let open_key = key();
        let backend = backend_with_state(Some(open_entry(open_key)));
        for _ in 0..2 {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            assert_eq!(
                backend
                    .destroy_one(destroy_binding(open_key, deadline), destroy_value(open_key),)
                    .await,
                Ok(ConfirmedAbsent)
            );
        }
        assert!(lock_state(&backend.state).is_none());
    }

    #[test]
    fn shutdown_destroy_uses_zero_request_correlation_only_for_shutdown() {
        let key = key();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let shutdown = binding(
            key,
            OperationKind::Shutdown,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            deadline,
        );
        assert_eq!(
            validate_destroy_binding(shutdown, destroy_value(key)),
            Ok(key)
        );
        let mut ordinary = destroy_binding(key, deadline);
        ordinary.request_id = [0; 16];
        ordinary.request_digest = [0; 32];
        assert_eq!(
            validate_destroy_binding(ordinary, destroy_value(key)),
            Err(BackendError::Invalid)
        );

        let mut reaping = binding(
            key,
            OperationKind::Reap,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            deadline,
        );
        reaping.prior_phase = Some(ContextPhase::Quarantined);
        assert_eq!(
            validate_destroy_binding(reaping, destroy_value(key)),
            Ok(key)
        );
        reaping.operation_generation += 1;
        assert_eq!(
            validate_destroy_binding(reaping, destroy_value(key)),
            Ok(key),
            "engine operation generations rotate independently of stable backend lineage"
        );

        let mut malformed_prepare_rollback = binding(
            key,
            OperationKind::Prepare,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            deadline,
        );
        malformed_prepare_rollback.prior_phase = Some(ContextPhase::Prepared);
        assert_eq!(
            validate_destroy_binding(malformed_prepare_rollback, destroy_value(key)),
            Err(BackendError::Invalid)
        );
    }
}
