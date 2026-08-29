//! Process-owned functional-alpha lease backend.
//!
//! This adapter deliberately proves only one live helper-runtime Client lease. It uses the real
//! authenticated worker, a real anonymous network namespace and kernel `WireGuard` UAPI, but it does
//! not claim crash/restart recovery. Durable journal and systemd descriptor-store composition stay
//! closed until their affine recovery path is complete.

use std::{
    net::IpAddr,
    os::fd::AsRawFd as _,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, ContextRole, LeasePlan as RoutingLeasePlan,
    PrepareLeaseBatch, PublicUdpEndpoint, UnderlayEvidence as RoutingUnderlayEvidence,
    WireguardRole,
};

use crate::{
    deadline::HardDeadline,
    engine::{
        AsyncLeaseBackend, BackendAction, BackendBinding, BackendCompletion, BackendDestroy,
        BackendError, BackendFuture, BackendLineage, BackendPhase, BackendRequest,
        BackendRuntimeCompletion, BackendRuntimeRequest, ConfirmedAbsent, ContextPhase,
        KernelCounters, OperationKind, PreparedKernelLease,
    },
    internal_protocol::{
        DestroyContext, INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION, InitialiseContext,
        InternalContextRole, InternalEndpointRole, InternalIpPrefix, InternalWorkerRequest,
        InternalWorkerResult, LeasePlan as InternalLeasePlan, PrepareLeases,
        internal_worker_request, internal_worker_response,
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
const STAGE_DESTROY: u8 = 3;

/// Install the deliberately narrow process-owned backend used only by the production server.
pub(crate) fn functional_alpha_lease_backend() -> Arc<dyn AsyncLeaseBackend> {
    Arc::new(FunctionalAlphaLeaseBackend {
        coordinator: WorkerCoordinator::new(WorkerRegistry::new(
            MAX_FUNCTIONAL_ALPHA_CONTEXTS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        )),
        state: Mutex::new(None),
    })
}

struct FunctionalAlphaLeaseBackend {
    coordinator: WorkerCoordinator,
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
}

struct OpenLeaseEntry {
    key: OpenLineageKey,
    worker: Option<WorkerGenerationOwnership>,
    recovery: Option<WorkerRecoveryIdentitySource>,
    wireguard: LiveWireguardLeaseOwner,
    prepare: PrepareLeases,
    underlay: UnderlayCandidate,
    phase: OpenLeasePhase,
    birth_may_exist: bool,
}

impl FunctionalAlphaLeaseBackend {
    async fn prepare_one(
        &self,
        binding: BackendBinding,
        value: PrepareLeaseBatch,
    ) -> Result<Vec<PreparedKernelLease>, BackendError> {
        let (key, lease, context_ttl) = validate_prepare_binding(binding, &value)?;
        let deadline = prepare_deadline(binding)?;
        let underlay =
            collect_consistent_direct_underlay(deadline).map_err(|_| BackendError::Unavailable)?;
        let wireguard = process_owned_resource(key, &lease)?;
        let prepare = internal_prepare_plan(wireguard.resource(), key, &lease);

        self.reserve_entry(key, wireguard, prepare, underlay)?;
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
            worker: None,
            recovery: None,
            wireguard,
            prepare,
            underlay,
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
        let generation = entry_generation(&self.state, key)?;
        let request = worker_request(
            worker_request_id(key, STAGE_INITIALISE),
            internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id: key.context_id.to_vec(),
                role: InternalContextRole::Client as i32,
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
            kernel.create_and_move_wireguard(&entry.wireguard, target_namespace, deadline)
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
            InternalEndpointRole::Client as i32,
        )
        .ok_or_else(|| response_error(execution))
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
                        kernel.delete_owned_wireguard(&entry.wireguard, deadline)
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
        let (completion, _) = request.into_parts();
        Box::pin(async move { completion.complete(Err(BackendError::Unavailable)) })
    }

    fn probe(
        self: Arc<Self>,
        request: BackendRequest<volparossa_routing::CommitLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>> {
        let (completion, _) = request.into_parts();
        Box::pin(async move { completion.complete(Err(BackendError::Unavailable)) })
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
) -> Result<(OpenLineageKey, RoutingLeasePlan, Duration), BackendError> {
    let lineage = binding.lineage;
    let context_id: [u8; 16] = value
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::Invalid)?;
    let [lease] = value.leases.as_slice() else {
        return Err(BackendError::Unavailable);
    };
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
        || value.role != ContextRole::Client as i32
        || lease.role != WireguardRole::Client as i32
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
        lease.clone(),
        Duration::from_secs(ttl_seconds),
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

fn process_owned_resource(
    key: OpenLineageKey,
    lease: &RoutingLeasePlan,
) -> Result<LiveWireguardLeaseOwner, BackendError> {
    let specification = WireguardLeaseSpec::derive(
        key.context_id,
        ContextRole::Client,
        lease.path_id,
        lease.role,
    )
    .map_err(|_| BackendError::Invalid)?;
    let marker = ownership_marker(key, lease);
    let alias = format!(
        "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{marker}",
        specification.interface()
    );
    let resource = DurableWireguardResource::from_authenticated_worker_binding(
        key.context_id,
        ContextRole::Client,
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
    PrepareLeases {
        route_context_id: key.context_id.to_vec(),
        leases: vec![InternalLeasePlan {
            path_id: lease.path_id,
            role: InternalEndpointRole::Client as i32,
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

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_with_state(state: Option<OpenLeaseEntry>) -> FunctionalAlphaLeaseBackend {
        FunctionalAlphaLeaseBackend {
            coordinator: WorkerCoordinator::new(WorkerRegistry::new(
                MAX_FUNCTIONAL_ALPHA_CONTEXTS,
                DEFAULT_MAX_CACHE_ENTRIES,
                DEFAULT_MAX_TTL,
            )),
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
        let lease = RoutingLeasePlan {
            path_id: 1,
            role: WireguardRole::Client as i32,
        };
        let wireguard = process_owned_resource(key, &lease).expect("live owner");
        let prepare = internal_prepare_plan(wireguard.resource(), key, &lease);
        OpenLeaseEntry {
            key,
            worker: None,
            recovery: None,
            wireguard,
            prepare,
            underlay: UnderlayCandidate {
                ifindex: 2,
                address: "198.51.100.7".parse().expect("fixture address"),
                evidence: crate::underlay::UnderlayEvidence::DirectAssigned,
            },
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
