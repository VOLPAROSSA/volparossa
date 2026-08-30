//! Process-owned functional-alpha lease backend.
//!
//! This adapter deliberately proves only one live helper-runtime Client or Exit lease. It uses the
//! real authenticated worker, a real anonymous network namespace and kernel `WireGuard` UAPI.
//! Activate verifies the signed role-specific local and peer authority, then installs and reads
//! back one exact public peer plus its main-table IPv6 `/128` link route. Probe-Commit requires a
//! recent handshake and strict bidirectional counter growth from the activation baseline. It does
//! not claim a usable datapath or crash/restart recovery. Durable journal and systemd
//! descriptor-store composition stay closed until their affine recovery path is complete.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd as _,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use volparossa_protocol::{
    ProtocolError, ReplayCache, TimePolicy, WireguardEndpoint, verify_relay_reservation,
};
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, ContextRole, HELPER_HANDLE_BYTES,
    LeasePlan as RoutingLeasePlan, PrepareLeaseBatch, PublicUdpEndpoint,
    UnderlayEvidence as RoutingUnderlayEvidence, WireguardRole,
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
    ownership_journal::DurableWireguardResource,
    underlay::{UnderlayCandidate, collect_consistent_direct_underlay},
};

use super::{
    DEFAULT_MAX_CACHE_ENTRIES, DEFAULT_MAX_TTL, ShutdownStatus, WorkerCoordinator,
    WorkerGenerationOwnership, WorkerGenerationReap, WorkerLifecycleAdmission,
    WorkerRecoveryIdentitySource, WorkerRegistry, WorkerV3Error,
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

/// Install the deliberately narrow process-owned backend used only by the production server.
pub(crate) fn functional_alpha_lease_backend() -> Arc<dyn AsyncLeaseBackend> {
    Arc::new(FunctionalAlphaLeaseBackend {
        coordinator: WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        )),
        relay_replay: Mutex::new(functional_alpha_replay_cache()),
        state: Mutex::new(None),
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
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenLeasePhase {
    Reserved,
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
    wireguard: LiveWireguardLeaseOwner,
    prepare: PrepareLeases,
    underlay: UnderlayCandidate,
    prepared: Option<PreparedWorkerLease>,
    activated: Option<ActivatedWorkerLease>,
    phase: OpenLeasePhase,
    birth_may_exist: bool,
}

impl FunctionalAlphaLeaseBackend {
    async fn prepare_one(
        &self,
        binding: BackendBinding,
        value: PrepareLeaseBatch,
    ) -> Result<Vec<PreparedKernelLease>, BackendError> {
        let (key, role, lease, context_ttl) = validate_prepare_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let underlay =
            collect_consistent_direct_underlay(deadline).map_err(|_| BackendError::Unavailable)?;
        let wireguard = process_owned_resource(key, &lease)?;
        let prepare = internal_prepare_plan(wireguard.resource(), key, &lease);

        self.reserve_entry(key, role.context, wireguard, prepare, underlay)?;
        self.admit_worker(key, context_ttl, deadline).await?;
        if let Err(error) = self.retain_recovery_source(key, deadline) {
            return Err(self.cleanup_after_failure(key, deadline, error).await);
        }
        if let Err(error) = self.initialise_child(key, &value, deadline).await {
            return Err(self.cleanup_after_failure(key, deadline, error).await);
        }
        if let Err(error) = self.create_birth_link(key, deadline) {
            return Err(self.cleanup_after_failure(key, deadline, error).await);
        }
        let (public_key, listen_port) = match self.prepare_child(key, &lease, deadline).await {
            Ok(prepared) => prepared,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };

        let underlay = {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            entry.prepared = Some(PreparedWorkerLease {
                path_id: lease.path_id,
                role: lease.role,
                public_key,
                listen_port,
            });
            entry.phase = OpenLeasePhase::Prepared;
            entry.underlay
        };
        deadline
            .complete(())
            .map_err(|_| BackendError::CleanupIncomplete)?;
        Ok(vec![PreparedKernelLease {
            path_id: lease.path_id,
            role: lease.role,
            public_key,
            public_endpoint: PublicUdpEndpoint {
                address: ip_bytes(underlay.address),
                port: u32::from(listen_port),
            },
            evidence: RoutingUnderlayEvidence::DirectAssigned,
        }])
    }

    fn reserve_entry(
        &self,
        key: OpenLineageKey,
        context_role: ContextRole,
        wireguard: LiveWireguardLeaseOwner,
        prepare: PrepareLeases,
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
            wireguard,
            prepare,
            underlay,
            prepared: None,
            activated: None,
            phase: OpenLeasePhase::Reserved,
            birth_may_exist: false,
        });
        Ok(())
    }

    async fn admit_worker(
        &self,
        key: OpenLineageKey,
        context_ttl: Duration,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let admission =
            self.coordinator
                .reserve_spawn_register_until(key.context_id, context_ttl, deadline);
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
                Err(if self.cleanup_exact(key, deadline, false).await {
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
        let (generation, context_role) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            let generation = entry
                .worker
                .as_ref()
                .ok_or(BackendError::CleanupIncomplete)?
                .coordinates
                .worker_generation
                .get();
            (generation, entry.context_role)
        };
        let role = functional_lease_role_for_context(context_role).ok_or(BackendError::Invalid)?;
        let request = worker_request(
            worker_request_id(key, STAGE_INITIALISE),
            internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id: key.context_id.to_vec(),
                role: role.internal_context as i32,
                mptcp_accepted_addrs: value.mptcp_accepted_addrs,
                mptcp_subflows: value.mptcp_subflows,
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

    fn create_birth_link(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let mut kernel =
            BirthNamespaceKernel::connect(deadline).map_err(|_| BackendError::Kernel)?;
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
            entry.birth_may_exist = true;
            entry.phase = OpenLeasePhase::BirthMayExist;
            kernel.create_and_move_wireguard(&mut entry.wireguard, target_namespace, deadline)
        };
        if matches!(
            birth,
            Err(BirthLinkError::Conflict | BirthLinkError::Kernel(_))
        ) {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key)?.birth_may_exist = false;
        }
        match birth {
            Ok(()) => Ok(()),
            Err(BirthLinkError::Conflict) => Err(BackendError::Invalid),
            Err(BirthLinkError::Kernel(_) | BirthLinkError::CleanupIncomplete) => {
                Err(BackendError::Kernel)
            }
        }
    }

    async fn prepare_child(
        &self,
        key: OpenLineageKey,
        lease: &RoutingLeasePlan,
        deadline: HardDeadline,
    ) -> Result<([u8; 32], u16), BackendError> {
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
        matches_prepared(
            execution.as_ref().ok(),
            lease.path_id,
            functional_lease_role_for_wireguard(lease.role)
                .ok_or(BackendError::Invalid)?
                .internal_endpoint as i32,
        )
        .ok_or_else(|| response_error(execution))
    }

    async fn activate_one(
        &self,
        binding: BackendBinding,
        value: ActivateLeaseBatch,
    ) -> Result<Vec<KernelCounters>, BackendError> {
        let (key, activation) = validate_activate_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let now_ms = unix_milliseconds()?;
        let (prepared, plan) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            if entry.phase != OpenLeasePhase::Prepared {
                return Err(BackendError::Invalid);
            }
            let prepared = entry.prepared.ok_or(BackendError::CleanupIncomplete)?;
            if (prepared.path_id, prepared.role) != (activation.path_id, activation.role) {
                return Err(BackendError::Invalid);
            }
            (
                prepared,
                verified_internal_activate_plan(
                    &self.relay_replay,
                    entry.wireguard.resource(),
                    key,
                    prepared,
                    entry.underlay,
                    &activation,
                    now_ms,
                )?,
            )
        };
        let counters = match self.activate_child(key, prepared, plan, deadline).await {
            Ok(counters) => counters,
            Err(error) => return Err(self.cleanup_after_failure(key, deadline, error).await),
        };
        let [baseline] = counters.as_slice() else {
            return Err(self
                .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                .await);
        };

        let peer_public_key: [u8; 32] = activation
            .peer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| BackendError::Invalid)?;
        let phase_committed = {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key).is_ok_and(|entry| {
                if entry.phase == OpenLeasePhase::Prepared && entry.prepared == Some(prepared) {
                    entry.activated = Some(ActivatedWorkerLease {
                        prepared,
                        peer_public_key,
                        baseline: *baseline,
                    });
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
        prepared: PreparedWorkerLease,
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
        matches_activated(execution.as_ref().ok(), prepared)
            .map(|baseline| vec![baseline])
            .ok_or_else(|| response_error(execution))
    }

    async fn probe_one(
        &self,
        binding: BackendBinding,
        value: BackendProbe,
    ) -> Result<Vec<KernelCounters>, BackendError> {
        let (key, commit, activated_at_unix) = validate_probe_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let activated = {
            let state = lock_state(&self.state);
            let entry = exact_entry(state.as_ref(), key)?;
            if entry.phase != OpenLeasePhase::Activated {
                return Err(BackendError::Invalid);
            }
            let activated = entry.activated.ok_or(BackendError::CleanupIncomplete)?;
            if (activated.prepared.path_id, activated.prepared.role)
                != (commit.path_id, commit.role)
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
                leases: vec![LeaseProbe {
                    path_id: commit.path_id,
                    role: commit.role,
                    expected_peer_public_key: activated.peer_public_key.to_vec(),
                    not_before_unix: activated_at_unix,
                }],
            }),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, deadline)
            .await;
        let proof = match execution {
            Ok(execution) => match matches_probed(Some(&execution), activated, activated_at_unix) {
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
            },
            Err(_) => {
                return Err(self
                    .cleanup_after_failure(key, deadline, BackendError::CleanupIncomplete)
                    .await);
            }
        };

        let phase_committed = {
            let mut state = lock_state(&self.state);
            exact_entry_mut(&mut state, key).is_ok_and(|entry| {
                if entry.phase == OpenLeasePhase::Activated && entry.activated == Some(activated) {
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
        match deadline.complete(vec![proof]) {
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

    async fn cleanup_exact(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
        request_child_destroy: bool,
    ) -> bool {
        let generation = entry_generation(&self.state, key).ok();
        let should_destroy = request_child_destroy
            && lock_state(&self.state).as_ref().is_some_and(|entry| {
                entry.key == key
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
            let _ = self
                .coordinator
                .execute_until(key.context_id, generation, destroy, deadline)
                .await;
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
                WorkerGenerationReap::Confirmed(_) => {}
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
            if entry.birth_may_exist {
                BirthNamespaceKernel::connect(deadline)
                    .and_then(|mut kernel| {
                        kernel.delete_owned_wireguard(&mut entry.wireguard, deadline)
                    })
                    .is_ok()
            } else {
                true
            }
        };
        if !parent_absent || deadline.ensure_remaining().is_err() {
            return false;
        }
        remove_exact_entry(&self.state, key)
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
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let [lease] = value.leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    let role = functional_lease_role(value.role, lease.role).ok_or(BackendError::Invalid)?;
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
        || !(1..=8).contains(&lease.path_id)
        || value.setup_expires_at_unix != lineage.setup_expires_at_unix
        || value.hard_expires_at_unix != lineage.hard_expires_at_unix
        || value.hard_expires_at_unix < value.setup_expires_at_unix
    {
        return Err(BackendError::Invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    let ttl_seconds = value
        .hard_expires_at_unix
        .checked_sub(now)
        .filter(|ttl| *ttl != 0 && *ttl <= DEFAULT_MAX_TTL.as_secs())
        .ok_or(BackendError::Invalid)?;
    if value.setup_expires_at_unix <= now {
        return Err(BackendError::Invalid);
    }
    Ok((
        OpenLineageKey::from(lineage),
        role,
        lease.clone(),
        Duration::from_secs(ttl_seconds),
    ))
}

fn validate_activate_binding(
    binding: BackendBinding,
    value: &ActivateLeaseBatch,
) -> Result<(OpenLineageKey, volparossa_routing::LeaseActivation), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let [activation] = value.leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    if functional_lease_role_for_wireguard(activation.role).is_none() {
        return Err(BackendError::Invalid);
    }
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
        || context_id != lineage.context_id
        || value.context_handle.len() != HELPER_HANDLE_BYTES
        || value.context_handle.iter().all(|byte| *byte == 0)
        || activation.lease_handle.len() != HELPER_HANDLE_BYTES
        || activation.lease_handle.iter().all(|byte| *byte == 0)
        || !(1..=8).contains(&activation.path_id)
        || activation.peer_public_key.len() != 32
        || activation.peer_public_key.iter().all(|byte| *byte == 0)
        || activation.signed_relay_reservation.is_empty()
        || activation.maximum_up_mbps != 0
        || activation.maximum_down_mbps != 0
        || parse_public_udp_endpoint(activation.peer_endpoint.as_ref()).is_none()
    {
        return Err(BackendError::Invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    if now >= lineage.setup_expires_at_unix || now >= lineage.hard_expires_at_unix {
        return Err(BackendError::Invalid);
    }
    Ok((OpenLineageKey::from(lineage), activation.clone()))
}

fn validate_probe_binding(
    binding: BackendBinding,
    value: &BackendProbe,
) -> Result<(OpenLineageKey, volparossa_routing::LeaseCommit, u64), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .commit
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let [commit] = value.commit.leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
    if functional_lease_role_for_wireguard(commit.role).is_none() {
        return Err(BackendError::Invalid);
    }
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
        || context_id != lineage.context_id
        || value.commit.context_handle.len() != HELPER_HANDLE_BYTES
        || value.commit.context_handle.iter().all(|byte| *byte == 0)
        || commit.lease_handle.len() != HELPER_HANDLE_BYTES
        || commit.lease_handle.iter().all(|byte| *byte == 0)
        || !(1..=8).contains(&commit.path_id)
        || value.activated_at_unix == 0
        || value.activated_at_unix >= lineage.setup_expires_at_unix
    {
        return Err(BackendError::Invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::Unavailable)?
        .as_secs();
    if value.activated_at_unix > now || now >= lineage.hard_expires_at_unix {
        return Err(BackendError::Invalid);
    }
    Ok((
        OpenLineageKey::from(lineage),
        commit.clone(),
        value.activated_at_unix,
    ))
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
    let role = functional_lease_role_for_context(context)?;
    (role.wireguard as i32 == wireguard).then_some(role)
}

const fn functional_lease_role_for_context(context: ContextRole) -> Option<FunctionalLeaseRole> {
    match context {
        ContextRole::Client => Some(FunctionalLeaseRole {
            context,
            wireguard: WireguardRole::Client,
            internal_context: InternalContextRole::Client,
            internal_endpoint: InternalEndpointRole::Client,
        }),
        ContextRole::Exit => Some(FunctionalLeaseRole {
            context,
            wireguard: WireguardRole::Exit,
            internal_context: InternalContextRole::Exit,
            internal_endpoint: InternalEndpointRole::Exit,
        }),
        ContextRole::Relay | ContextRole::Unspecified => None,
    }
}

fn functional_lease_role_for_wireguard(wireguard: i32) -> Option<FunctionalLeaseRole> {
    match WireguardRole::try_from(wireguard).ok()? {
        WireguardRole::Client => functional_lease_role_for_context(ContextRole::Client),
        WireguardRole::Exit => functional_lease_role_for_context(ContextRole::Exit),
        WireguardRole::RelayClient | WireguardRole::RelayExit | WireguardRole::Unspecified => None,
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
}

fn internal_prepare_plan(
    resource: &DurableWireguardResource,
    key: OpenLineageKey,
    lease: &RoutingLeasePlan,
) -> PrepareLeases {
    let role = functional_lease_role_for_wireguard(lease.role)
        .expect("process-owned resource already validated the functional lease role");
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

fn verified_internal_activate_plan(
    replay_cache: &Mutex<ReplayCache>,
    resource: &DurableWireguardResource,
    key: OpenLineageKey,
    prepared: PreparedWorkerLease,
    underlay: UnderlayCandidate,
    activation: &volparossa_routing::LeaseActivation,
    now_ms: u64,
) -> Result<ActivateLeases, BackendError> {
    let mut replay_guard = lock_replay_cache(replay_cache);
    let (relay_grant, exit_grant) = verify_relay_reservation(
        &activation.signed_relay_reservation,
        now_ms,
        TimePolicy::default(),
        &mut replay_guard,
    )
    .map_err(|error| protocol_backend_error(&error))?;
    let relay_replay_key = (*relay_grant.sender_id(), *relay_grant.nonce());
    let exit_replay_key = (*exit_grant.sender_id(), *exit_grant.nonce());

    let result = (|| {
        let relay_message = relay_grant.message();
        let exit_message = exit_grant.message();
        let hard_expires_at_ms = key
            .hard_expires_at_unix
            .checked_mul(1_000)
            .ok_or(BackendError::Invalid)?;
        if relay_message.route_context_id.as_slice() != key.context_id
            || relay_message.path_id != activation.path_id
            || relay_message.path_id != prepared.path_id
            || activation.role != prepared.role
            || relay_grant.expires_at_ms() < hard_expires_at_ms
            || !signer_matches_peer_id(
                relay_grant.sender_public_key(),
                &relay_message.relay_peer_id,
            )
            || !signer_matches_peer_id(exit_grant.sender_public_key(), &exit_message.exit_peer_id)
        {
            return Err(BackendError::Invalid);
        }

        let supplied_public_key: [u8; 32] = activation
            .peer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| BackendError::Invalid)?;
        let supplied_endpoint = parse_public_udp_endpoint(activation.peer_endpoint.as_ref())
            .ok_or(BackendError::Invalid)?;
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
        if supplied_public_key != endpoint.public_key
            || supplied_endpoint != (endpoint.address, endpoint.port)
            || endpoint.public_key == prepared.public_key
            || (endpoint.address, endpoint.port) == (underlay.address, prepared.listen_port)
        {
            return Err(BackendError::Invalid);
        }

        internal_activate_plan(resource, key, activation.path_id, prepared.role, endpoint)
    })();

    if result.is_err() {
        let _ = replay_guard.rollback(&relay_replay_key.0, &relay_replay_key.1);
        let _ = replay_guard.rollback(&exit_replay_key.0, &exit_replay_key.1);
    }
    result
}

fn internal_activate_plan(
    resource: &DurableWireguardResource,
    key: OpenLineageKey,
    path_id: u32,
    wireguard_role: i32,
    endpoint: VerifiedWireguardEndpoint,
) -> Result<ActivateLeases, BackendError> {
    let role = functional_lease_role_for_wireguard(wireguard_role).ok_or(BackendError::Invalid)?;
    if resource.key()
        != (
            u8::try_from(path_id).map_err(|_| BackendError::Invalid)?,
            wireguard_role,
        )
    {
        return Err(BackendError::Invalid);
    }
    Ok(ActivateLeases {
        route_context_id: key.context_id.to_vec(),
        leases: vec![InternalLeaseActivation {
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
        }],
    })
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

fn matches_prepared(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    path_id: u32,
    role: i32,
) -> Option<([u8; 32], u16)> {
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
    let [lease] = prepared.leases.as_slice() else {
        return None;
    };
    let public_key: [u8; 32] = lease.public_key.as_slice().try_into().ok()?;
    let listen_port = u16::try_from(lease.listen_port)
        .ok()
        .filter(|port| *port != 0)?;
    (lease.path_id == path_id && lease.role == role && public_key.iter().any(|byte| *byte != 0))
        .then_some((public_key, listen_port))
}

fn matches_activated(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    prepared: PreparedWorkerLease,
) -> Option<KernelCounters> {
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
    let [lease] = activated.leases.as_slice() else {
        return None;
    };
    let public_key: [u8; 32] = lease.public_key.as_slice().try_into().ok()?;
    let listen_port = u16::try_from(lease.listen_port)
        .ok()
        .filter(|port| *port != 0)?;
    if (lease.path_id, lease.role, public_key, listen_port)
        != (
            prepared.path_id,
            prepared.role,
            prepared.public_key,
            prepared.listen_port,
        )
        || lease.latest_handshake_nanoseconds >= 1_000_000_000
        || (lease.latest_handshake_unix == 0 && lease.latest_handshake_nanoseconds != 0)
    {
        return None;
    }
    Some(KernelCounters {
        path_id: lease.path_id,
        role: lease.role,
        latest_handshake_unix: lease.latest_handshake_unix,
        received_bytes: lease.received_bytes,
        transmitted_bytes: lease.transmitted_bytes,
    })
}

fn matches_probed(
    execution: Option<&crate::worker_transport::CredentialedWorkerExecution>,
    activated: ActivatedWorkerLease,
    not_before_unix: u64,
) -> Option<KernelCounters> {
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
    let [lease] = probed.leases.as_slice() else {
        return None;
    };
    if (lease.path_id, lease.role) != (activated.prepared.path_id, activated.prepared.role)
        || lease.latest_handshake_unix < not_before_unix
        || lease.latest_handshake_unix < activated.baseline.latest_handshake_unix
        || lease.received_bytes <= activated.baseline.received_bytes
        || lease.transmitted_bytes <= activated.baseline.transmitted_bytes
    {
        return None;
    }
    Some(KernelCounters {
        path_id: lease.path_id,
        role: lease.role,
        latest_handshake_unix: lease.latest_handshake_unix,
        received_bytes: lease.received_bytes,
        transmitted_bytes: lease.transmitted_bytes,
    })
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

    use nix::unistd::{getegid, geteuid};
    use volparossa_protocol::{
        MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, RelayAuthorization, RelayReservation,
        SignedEnvelope, Transport, decode_canonical, generate_nonce, sign_control_message,
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
            BootstrapChallenge, SpawnedWorker, StablePhase, WorkerProcess, correlated_response,
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
            wireguard,
            prepare,
            underlay: UnderlayCandidate {
                ifindex: 2,
                address: "198.51.100.7".parse().expect("fixture address"),
                evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
            },
            prepared: None,
            activated: None,
            phase: OpenLeasePhase::Reserved,
            birth_may_exist: false,
        }
    }

    fn live_prepare_fixture() -> (BackendBinding, PrepareLeaseBatch) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture time")
            .as_secs();
        let key = OpenLineageKey {
            setup_expires_at_unix: now + 20,
            hard_expires_at_unix: now + 120,
            ..key()
        };
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
        let key = OpenLineageKey {
            context_id: *route.route_context_id(),
            setup_expires_at_unix: now + 20,
            hard_expires_at_unix: now + 120,
            ..key()
        };
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
        let key = OpenLineageKey {
            context_id: *route.route_context_id(),
            setup_expires_at_unix: now + 20,
            hard_expires_at_unix: now + 120,
            ..key()
        };
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

    fn decode_relay_reservation(encoded: &[u8]) -> RelayReservation {
        let envelope: SignedEnvelope =
            decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE).expect("relay envelope");
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("relay payload")
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
        entry.prepared = Some(activated.prepared);
        entry.activated = Some(activated);
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
        entry.prepared = Some(prepared);
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
        retry.prepared = Some(prepared);
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
        entry.prepared = Some(prepared);
        entry.phase = OpenLeasePhase::Prepared;
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
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
        retry_entry.prepared = Some(prepared);
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
        entry.prepared = Some(activated.prepared);
        entry.activated = Some(activated);
        entry.phase = OpenLeasePhase::Activated;
        let backend = FunctionalAlphaLeaseBackend {
            coordinator,
            relay_replay: Mutex::new(functional_alpha_replay_cache()),
            state: Mutex::new(Some(entry)),
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
