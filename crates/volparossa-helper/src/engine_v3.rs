//! Fail-closed helper-v3 lease state machine.
//!
//! The production server can prepare and destroy one process-owned functional-alpha Client lease
//! through the authenticated namespace worker. No response can claim a committed tunnel or usable
//! datapath until activation, probing and transport acquisition are connected to kernel evidence.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    future::Future,
    os::fd::OwnedFd,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio::time::Instant;
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, BindHelperRuntime, ClosedPreparePlan,
    CommittedLease, CommittedLeaseBatch, ContextRole, DestroyedContext, Empty, HELPER_HANDLE_BYTES,
    HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, HelperResult, HelperRuntime,
    LeaseActivation, LeasePlan, PrepareLeaseBatch, PreparedLease, PreparedLeaseBatch,
    PublicUdpEndpoint, ReconcileExpiredPrepare, ReconciledExpiredPrepare, TransportSocketReady,
    UnderlayEvidence, WireguardRole, helper_request, helper_response, operation_digest,
};
use zeroize::Zeroizing;

const MAX_CONTEXTS: usize = 64;
const MAX_CACHED_REQUESTS: usize = 1_024;
const MAX_PREPARE_RECONCILIATIONS: usize = 1_024;
const MAX_RECONCILIATION_REQUEST_IDS: usize = 1_024;
const MAX_CLOSED_PREPARE_IDENTITIES: usize = 16;
const SETUP_TTL_SECONDS: u64 = 30;
const HARD_TTL_SECONDS: u64 = 15 * 60;
const RESPONSE_CACHE_SECONDS: u64 = 30;
const BACKEND_CALL_TIMEOUT: Duration = Duration::from_secs(5);
const MAINTENANCE_REAP_DOMAIN: &[u8] = b"VOLPAROSSA helper-v3 maintenance reap v1";

/// Stateful authenticated helper-v3 dispatcher.
#[derive(Clone)]
pub struct HelperEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    cleanup_token: Zeroizing<[u8; 32]>,
    runtime_id: [u8; 32],
    trusted_agent_uid: u32,
    backend: Arc<dyn AsyncLeaseBackend>,
    handles: Arc<dyn HandleSource>,
    clock: Arc<dyn Clock>,
    state: Mutex<EngineState>,
    operation_gate: Mutex<()>,
    backend_timeout: Duration,
}

#[derive(Default)]
struct EngineState {
    contexts: HashMap<[u8; 16], ContextRecord>,
    cache: HashMap<[u8; 16], CachedResponse>,
    cache_order: VecDeque<[u8; 16]>,
    next_generation: u64,
    next_operation: u64,
    in_flight: Option<OperationToken>,
    cleanup_pending: BTreeSet<([u8; 16], u64)>,
    prepare_reconciliations: HashMap<[u8; 16], PrepareReconciliationRecord>,
    reconciliation_request_ids: HashMap<[u8; 16], ReconciliationRequestRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareReconciliationPhase {
    Intent,
    Pending,
    Owned,
    Absent,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PrepareReconciliationRecord {
    helper_runtime_id: [u8; 32],
    prepare_request_id: [u8; 16],
    prepare_operation_digest: [u8; 32],
    backend_generation: u64,
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
    closed_plan: ClosedPreparePlanBinding,
    phase: PrepareReconciliationPhase,
    reconciliation_request_id: Option<[u8; 16]>,
}

/// Fixed-size, non-secret copy of the canonical recovery topology bound by tag 35.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosedPreparePlanBinding {
    context_role: u8,
    lease_count: u8,
    identities: [(u8, u8); MAX_CLOSED_PREPARE_IDENTITIES],
}

impl ClosedPreparePlanBinding {
    fn from_closed_plan(value: &ClosedPreparePlan) -> Option<Self> {
        Self::from_parts(value.context_role, &value.leases)
    }

    fn from_prepare(value: &PrepareLeaseBatch) -> Option<Self> {
        Self::from_parts(value.role, &value.leases)
    }

    fn from_parts(context_role: i32, leases: &[LeasePlan]) -> Option<Self> {
        let context = ContextRole::try_from(context_role).ok()?;
        if context == ContextRole::Unspecified
            || leases.is_empty()
            || leases.len() > MAX_CLOSED_PREPARE_IDENTITIES
        {
            return None;
        }
        let mut identities = [(0, 0); MAX_CLOSED_PREPARE_IDENTITIES];
        let mut roles_by_path = [0_u8; 9];
        let mut previous = None;
        for (position, lease) in leases.iter().enumerate() {
            let path_id = u8::try_from(lease.path_id).ok()?;
            if !(1..=8).contains(&path_id)
                || previous.is_some_and(|prior| prior >= (lease.path_id, lease.role))
            {
                return None;
            }
            let role = WireguardRole::try_from(lease.role).ok()?;
            let role_bit = match (context, role) {
                (ContextRole::Client, WireguardRole::Client) => 1,
                (ContextRole::Relay, WireguardRole::RelayClient) => 2,
                (ContextRole::Relay, WireguardRole::RelayExit) => 4,
                (ContextRole::Exit, WireguardRole::Exit) => 8,
                _ => return None,
            };
            roles_by_path[usize::from(path_id)] |= role_bit;
            identities[position] = (path_id, u8::try_from(lease.role).ok()?);
            previous = Some((lease.path_id, lease.role));
        }
        let expected_roles = match context {
            ContextRole::Client => 1,
            ContextRole::Relay => 2 | 4,
            ContextRole::Exit => 8,
            ContextRole::Unspecified => return None,
        };
        if roles_by_path
            .iter()
            .skip(1)
            .any(|roles| *roles != 0 && *roles != expected_roles)
        {
            return None;
        }
        Some(Self {
            context_role: u8::try_from(context_role).ok()?,
            lease_count: u8::try_from(leases.len()).ok()?,
            identities,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReconciliationRequestRecord {
    digest: [u8; 32],
    context_id: [u8; 16],
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationRequestAdmissionError {
    Conflict,
    Capacity,
    EvidenceUnavailable,
}

struct CachedResponse {
    digest: [u8; 32],
    expires_at_unix: u64,
    response: HelperResponse,
    descriptor: Option<Arc<OwnedFd>>,
    context_id: Option<[u8; 16]>,
}

pub(crate) struct HelperExecution {
    pub(crate) response: HelperResponse,
    pub(crate) descriptor: Option<Arc<OwnedFd>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContextPhase {
    Prepared,
    Activated,
    Committed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationKind {
    Prepare,
    Activate,
    Probe,
    Destroy,
    Acquire,
    Cleanup,
    Reap,
    Reconcile,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationToken {
    sequence: u64,
    request_id: [u8; 16],
    digest: [u8; 32],
    context_id: [u8; 16],
    generation: u64,
    prior_phase: Option<ContextPhase>,
    kind: OperationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendLineage {
    pub(crate) helper_runtime_id: [u8; 32],
    pub(crate) context_id: [u8; 16],
    pub(crate) backend_generation: u64,
    pub(crate) prepare_request_id: [u8; 16],
    pub(crate) prepare_operation_digest: [u8; 32],
    pub(crate) setup_expires_at_unix: u64,
    pub(crate) hard_expires_at_unix: u64,
}

/// Affine engine-side authority for settling one exact planned operation.
///
/// The copyable token stored in `EngineState` and sent to the backend is only a binding. This
/// owner deliberately stays in the supervisor task, so a backend task panic or join failure can
/// never consume the engine's only rollback authority.
#[must_use = "a planned operation owner must be committed or rolled back"]
struct OperationOwner {
    token: OperationToken,
    lineage: BackendLineage,
    call_deadline: Instant,
    armed: bool,
}

impl OperationOwner {
    const fn token(&self) -> OperationToken {
        self.token
    }

    const fn lineage(&self) -> BackendLineage {
        self.lineage
    }

    const fn call_deadline(&self) -> Instant {
        self.call_deadline
    }

    fn settle(mut self) -> OperationToken {
        self.armed = false;
        self.token
    }
}

impl Drop for OperationOwner {
    fn drop(&mut self) {
        if self.armed {
            // PLAN without explicit COMMIT/rollback settlement is an ownership invariant breach.
            // In particular, unwinding an engine panic must not leave live privileged state behind
            // in an ownerless generation.
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendPhase {
    PreparePending,
    Prepared,
    Activated,
    Committed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendAction {
    Prepare,
    Activate,
    Probe,
    Destroy,
    AcquireTransportSocket,
}

/// Non-authoritative copyable identity used only to correlate a backend completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendBinding {
    pub(crate) lineage: BackendLineage,
    pub(crate) operation_sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: [u8; 32],
    pub(crate) operation_generation: u64,
    pub(crate) prior_phase: Option<ContextPhase>,
    pub(crate) operation_kind: OperationKind,
    pub(crate) phase: BackendPhase,
    pub(crate) action: BackendAction,
    pub(crate) call_deadline: Instant,
}

impl BackendBinding {
    fn for_owner(
        owner: &OperationOwner,
        phase: BackendPhase,
        action: BackendAction,
        call_deadline: Instant,
    ) -> Self {
        let token = owner.token();
        Self {
            lineage: owner.lineage(),
            operation_sequence: token.sequence,
            request_id: token.request_id,
            request_digest: token.digest,
            operation_generation: token.generation,
            prior_phase: token.prior_phase,
            operation_kind: token.kind,
            phase,
            action,
            call_deadline,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendDestroy {
    pub(crate) context_id: [u8; 16],
    pub(crate) backend_generation: u64,
}

/// One non-cloneable backend input. Engine rollback authority remains in `OperationOwner`.
#[must_use = "an affine backend call must produce one correlated completion"]
pub(crate) struct BackendRequest<T> {
    binding: BackendBinding,
    value: T,
}

#[must_use = "the backend completion owner must return one correlated completion"]
pub(crate) struct BackendCompletionOwner {
    binding: BackendBinding,
}

impl BackendCompletionOwner {
    #[allow(dead_code, reason = "used by the sibling production adapter seam")]
    pub(crate) const fn binding(&self) -> BackendBinding {
        self.binding
    }

    pub(crate) fn complete<T>(self, result: Result<T, BackendError>) -> BackendCompletion<T> {
        BackendCompletion {
            binding: self.binding,
            result,
        }
    }
}

impl<T> BackendRequest<T> {
    pub(crate) const fn new(binding: BackendBinding, value: T) -> Self {
        Self { binding, value }
    }

    pub(crate) fn into_parts(self) -> (BackendCompletionOwner, T) {
        (
            BackendCompletionOwner {
                binding: self.binding,
            },
            self.value,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConfirmedAbsent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendRuntimeAction {
    QueryTransportSocket,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendRuntimeBinding {
    pub(crate) helper_runtime_id: [u8; 32],
    pub(crate) action: BackendRuntimeAction,
    pub(crate) call_deadline: Instant,
}

#[must_use = "a runtime backend call must produce one correlated completion"]
pub(crate) struct BackendRuntimeRequest {
    binding: BackendRuntimeBinding,
}

impl BackendRuntimeRequest {
    pub(crate) const fn new(binding: BackendRuntimeBinding) -> Self {
        Self { binding }
    }

    #[allow(dead_code, reason = "used by the sibling production adapter seam")]
    pub(crate) const fn binding(&self) -> BackendRuntimeBinding {
        self.binding
    }

    pub(crate) fn complete<T>(
        self,
        result: Result<T, BackendError>,
    ) -> BackendRuntimeCompletion<T> {
        BackendRuntimeCompletion {
            binding: self.binding,
            result,
        }
    }
}

pub(crate) struct BackendRuntimeCompletion<T> {
    pub(crate) binding: BackendRuntimeBinding,
    pub(crate) result: Result<T, BackendError>,
}

pub(crate) struct BackendCompletion<T> {
    pub(crate) binding: BackendBinding,
    pub(crate) result: Result<T, BackendError>,
}

pub(crate) type BackendFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

struct ContextRecord {
    generation: u64,
    backend_generation: u64,
    handle: [u8; HELPER_HANDLE_BYTES],
    helper_runtime_id: [u8; 32],
    prepare_request_id: [u8; 16],
    prepare_operation_digest: [u8; 32],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
    phase: ContextPhase,
    activated_at_unix: Option<u64>,
    leases: BTreeMap<(u32, i32), LeaseRecord>,
}

struct LeaseRecord {
    handle: [u8; HELPER_HANDLE_BYTES],
    public_key: [u8; 32],
    public_endpoint: PublicUdpEndpoint,
    baseline: Option<KernelCounters>,
}

#[derive(Clone)]
pub(crate) struct PreparedKernelLease {
    pub(crate) path_id: u32,
    pub(crate) role: i32,
    pub(crate) public_key: [u8; 32],
    pub(crate) public_endpoint: PublicUdpEndpoint,
    pub(crate) evidence: UnderlayEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelCounters {
    pub(crate) path_id: u32,
    pub(crate) role: i32,
    pub(crate) latest_handshake_unix: u64,
    pub(crate) received_bytes: u64,
    pub(crate) transmitted_bytes: u64,
}

#[allow(dead_code)] // Future real backends map these closed error classes without free-form text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendError {
    Unavailable,
    Capacity,
    Invalid,
    Kernel,
    CleanupIncomplete,
}

/// Cancellation-safe affine boundary for privileged worker adapters.
///
/// Every returned future must enforce `binding.call_deadline` as its own absolute hard deadline.
/// It may return `Ok` only after the exact operation is quiescent and any live resources remain
/// under exact backend authority. Prepare success may retain process-owned resources for the same
/// helper runtime; that is not crash durability. Definitive `Err` variants guarantee no mutation,
/// detached work, or owned descriptor survives.
/// `CleanupIncomplete` instead means exact-lineage resources may remain only under backend-owned
/// quarantine/reaper authority, so the engine must issue exact rollback/destroy. Every Acquire
/// error closes every descriptor it created, and no error may leave *unowned* detached work.
/// Destroy success is stronger: `ConfirmedAbsent` proves that the exact stable lineage's worker is
/// reaped and every resource, pin, authority and descriptor acquired by that backend is absent for
/// the live runtime. A complete production backend must additionally settle durable journal and
/// systemd custody so that this proof survives restart; the functional-alpha backend acquires no
/// such custody and makes no restart-recovery claim. Dropping any future must be safe. The engine's
/// timeout remains a soft ambiguity boundary and continues awaiting task settlement.
///
/// The production server installs a deliberately narrow functional-alpha adapter for one Client
/// lease's Prepare and Destroy only. Activate, Probe, descriptor acquisition and datapath work stay
/// unavailable, and the public [`HelperEngine::new`] constructor deliberately retains the fully
/// unavailable backend. A complete production adapter still requires integration tests for all of
/// these properties.
pub(crate) trait AsyncLeaseBackend: Send + Sync {
    fn prepare(
        self: Arc<Self>,
        request: BackendRequest<PrepareLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<PreparedKernelLease>>>;

    fn activate(
        self: Arc<Self>,
        request: BackendRequest<ActivateLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>>;

    fn probe(
        self: Arc<Self>,
        request: BackendRequest<volparossa_routing::CommitLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>>;

    fn destroy(
        self: Arc<Self>,
        request: BackendRequest<BackendDestroy>,
    ) -> BackendFuture<BackendCompletion<ConfirmedAbsent>>;

    fn acquire_transport_socket(
        self: Arc<Self>,
        request: BackendRequest<AcquireTransportSocket>,
    ) -> BackendFuture<BackendCompletion<OwnedFd>>;

    fn transport_socket_supported(
        self: Arc<Self>,
        request: BackendRuntimeRequest,
    ) -> BackendFuture<BackendRuntimeCompletion<bool>>;

    fn shutdown(
        self: Arc<Self>,
        request: BackendRuntimeRequest,
    ) -> BackendFuture<BackendRuntimeCompletion<()>>;
}

struct UnavailableLeaseBackend;

impl AsyncLeaseBackend for UnavailableLeaseBackend {
    fn prepare(
        self: Arc<Self>,
        request: BackendRequest<PrepareLeaseBatch>,
    ) -> BackendFuture<BackendCompletion<Vec<PreparedKernelLease>>> {
        let (completion, _) = request.into_parts();
        Box::pin(async move { completion.complete(Err(BackendError::Unavailable)) })
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
        let (completion, _) = request.into_parts();
        Box::pin(async move { completion.complete(Ok(ConfirmedAbsent)) })
    }

    fn acquire_transport_socket(
        self: Arc<Self>,
        request: BackendRequest<AcquireTransportSocket>,
    ) -> BackendFuture<BackendCompletion<OwnedFd>> {
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
        Box::pin(async move { request.complete(Ok(())) })
    }
}

trait HandleSource: Send + Sync {
    fn fill(&self, output: &mut [u8]);
}

struct OsHandleSource;

impl HandleSource for OsHandleSource {
    fn fill(&self, output: &mut [u8]) {
        OsRng.fill_bytes(output);
    }
}

trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

enum BackendCall<T> {
    Complete(T),
    TimedOut(tokio::task::JoinHandle<T>),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CleanupOutcome {
    confirmed: bool,
    response_sent: bool,
}

enum ResolvedCall<T> {
    Definite {
        owner: Box<OperationOwner>,
        result: Result<T, BackendError>,
    },
    Ambiguous,
}

enum ReapOutcome {
    Complete,
    Failure(Box<HelperExecution>),
    ResponseSent,
}

#[derive(Clone, Copy)]
struct ReapTarget {
    context_id: [u8; 16],
    generation: u64,
    prior_phase: Option<ContextPhase>,
    lineage: BackendLineage,
}

impl HelperEngine {
    /// Create a standalone fail-closed engine.
    ///
    /// Every lease-backend operation deliberately returns `Unavailable`. The production server is
    /// the only crate-internal caller that selects the narrow functional-alpha backend.
    ///
    /// The engine immediately moves the argument into zeroizing storage. Because fixed arrays are
    /// `Copy`, a caller that retains another source copy remains responsible for wiping that copy.
    #[must_use]
    pub fn new(cleanup_token: [u8; 32], trusted_agent_uid: u32) -> Self {
        Self::new_with_protected_cleanup_token(Zeroizing::new(cleanup_token), trusted_agent_uid)
    }

    pub(crate) fn new_with_protected_cleanup_token(
        cleanup_token: Zeroizing<[u8; 32]>,
        trusted_agent_uid: u32,
    ) -> Self {
        Self::new_with_backend(
            cleanup_token,
            trusted_agent_uid,
            Arc::new(UnavailableLeaseBackend),
        )
    }

    /// Install one crate-internal asynchronous backend without exposing test clocks or handles.
    /// The public standalone constructor continues to select the unavailable backend.
    pub(crate) fn new_with_backend(
        cleanup_token: Zeroizing<[u8; 32]>,
        trusted_agent_uid: u32,
        backend: Arc<dyn AsyncLeaseBackend>,
    ) -> Self {
        Self::with_protected_components_and_timeout(
            cleanup_token,
            random_runtime_id(),
            trusted_agent_uid,
            backend,
            Arc::new(OsHandleSource),
            Arc::new(SystemClock),
            BACKEND_CALL_TIMEOUT,
        )
    }

    #[cfg(test)]
    fn with_components(
        cleanup_token: [u8; 32],
        trusted_agent_uid: u32,
        backend: Arc<dyn AsyncLeaseBackend>,
        handles: Arc<dyn HandleSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_components_and_timeout(
            cleanup_token,
            trusted_agent_uid,
            backend,
            handles,
            clock,
            BACKEND_CALL_TIMEOUT,
        )
    }

    #[cfg(test)]
    fn with_components_and_timeout(
        cleanup_token: [u8; 32],
        trusted_agent_uid: u32,
        backend: Arc<dyn AsyncLeaseBackend>,
        handles: Arc<dyn HandleSource>,
        clock: Arc<dyn Clock>,
        backend_timeout: Duration,
    ) -> Self {
        Self::with_protected_components_and_timeout(
            Zeroizing::new(cleanup_token),
            [0xa5; 32],
            trusted_agent_uid,
            backend,
            handles,
            clock,
            backend_timeout,
        )
    }

    fn with_protected_components_and_timeout(
        cleanup_token: Zeroizing<[u8; 32]>,
        runtime_id: [u8; 32],
        trusted_agent_uid: u32,
        backend: Arc<dyn AsyncLeaseBackend>,
        handles: Arc<dyn HandleSource>,
        clock: Arc<dyn Clock>,
        backend_timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(EngineInner {
                cleanup_token,
                runtime_id,
                trusted_agent_uid,
                backend,
                handles,
                clock,
                state: Mutex::new(EngineState::default()),
                operation_gate: Mutex::new(()),
                backend_timeout,
            }),
        }
    }

    /// Execute one fully decoded request.
    pub async fn execute(&self, request: HelperRequest) -> HelperResponse {
        self.execute_with_descriptor(request).await.response
    }

    /// Execute through an owned supervisor.
    ///
    /// Once PLAN reserves state, dropping the caller cannot abort CALL or skip COMMIT/rollback.
    /// The operation gate is intentionally held until the owned asynchronous backend task has
    /// actually returned. A timeout publishes ambiguity but does not cancel or detach that task;
    /// the supervisor retains the affine operation owner and performs exact rollback settlement.
    pub(crate) async fn execute_with_descriptor(&self, request: HelperRequest) -> HelperExecution {
        if operation_digest(&request).is_err() {
            return execution(invalid_response(&request), None);
        }
        if fixed::<16>(&request.request_id).is_none() {
            return execution(invalid_response(&request), None);
        }
        if matches!(
            request.operation.as_ref(),
            Some(
                helper_request::Operation::PrepareClientIngress(_)
                    | helper_request::Operation::AcquireIngressSocket(_)
                    | helper_request::Operation::ActivateClientIngress(_)
                    | helper_request::Operation::DestroyClientIngress(_)
            )
        ) {
            return execution(
                response(
                    &request,
                    HelperResult::Unavailable,
                    "CLIENT_INGRESS_UNAVAILABLE",
                    None,
                ),
                None,
            );
        }

        let fallback = execution(
            response(
                &request,
                HelperResult::CleanupIncomplete,
                "SUPERVISOR_RESULT_AMBIGUOUS",
                None,
            ),
            None,
        );
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let engine = self.clone();
        tokio::spawn(async move {
            engine.supervise(request, sender).await;
        });
        receiver.await.unwrap_or(fallback)
    }

    async fn supervise(
        &self,
        request: HelperRequest,
        sender: tokio::sync::oneshot::Sender<HelperExecution>,
    ) {
        let _operation_guard = self.inner.operation_gate.lock().await;
        if sender.is_closed() {
            return;
        }
        let mut sender = Some(sender);
        let result = self.execute_serial(&request, &mut sender).await;
        if let (Some(sender), Some(result)) = (sender.take(), result) {
            let _ = sender.send(result);
        }
    }

    #[allow(clippy::too_many_lines)] // Keep the complete typed dispatch and cache boundary together.
    async fn execute_serial(
        &self,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let digest = operation_digest(request).unwrap_or([0; 32]);
        let request_id = fixed::<16>(&request.request_id)?;
        let is_reconciliation = matches!(
            request.operation.as_ref(),
            Some(helper_request::Operation::ReconcileExpiredPrepare(_))
        );

        // Tag 28 deliberately re-evaluates exact retries instead of caching a response, but its
        // outer request ID remains globally bound to one canonical request digest. Check the
        // dedicated runtime-lifetime
        // tombstone before any Bind, global reap, target transition or backend call. A new tag-28
        // ID is reserved later, only after its exact live lineage has been validated.
        {
            let state = self.inner.state.lock().await;
            let request_id_conflict = if is_reconciliation {
                state
                    .cache
                    .get(&request_id)
                    .is_some_and(|cached| cached.digest.ct_eq(&digest).unwrap_u8() != 1)
                    || state
                        .reconciliation_request_ids
                        .get(&request_id)
                        .is_some_and(|record| record.digest.ct_eq(&digest).unwrap_u8() != 1)
            } else {
                state.reconciliation_request_ids.contains_key(&request_id)
            };
            if request_id_conflict {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "REQUEST_ID_CONFLICT",
                        None,
                    ),
                    None,
                ));
            }
        }

        if let Some(helper_request::Operation::BindHelperRuntime(value)) =
            request.operation.as_ref()
        {
            if value.prepare_intent.is_none() {
                let state = self.inner.state.lock().await;
                if state
                    .cache
                    .get(&request_id)
                    .is_some_and(|cached| cached.digest.ct_eq(&digest).unwrap_u8() != 1)
                {
                    return Some(execution(
                        response(
                            request,
                            HelperResult::InvalidRequest,
                            "REQUEST_ID_CONFLICT",
                            None,
                        ),
                        None,
                    ));
                }
                drop(state);
                return Some(helper_runtime_execution(request, self.inner.runtime_id));
            }
            {
                let now = self.inner.clock.now_unix();
                let mut state = self.inner.state.lock().await;
                prune_cache(&mut state, now);
                prune_prepare_reconciliations(&mut state, now);
                if let Some(cached) = state.cache.get(&request_id) {
                    let same_digest = cached.digest.ct_eq(&digest).unwrap_u8() == 1;
                    let cached_failure = cached.response.result != HelperResult::Ok as i32;
                    let exact_live_lineage = value.prepare_intent.as_ref().is_some_and(|intent| {
                        let Some(closed_plan) = intent
                            .closed_plan
                            .as_ref()
                            .and_then(ClosedPreparePlanBinding::from_closed_plan)
                        else {
                            return false;
                        };
                        let identity = (
                            fixed::<16>(&intent.route_context_id),
                            fixed::<16>(&intent.prepare_request_id),
                            fixed::<32>(&intent.prepare_operation_digest),
                        );
                        let (Some(context_id), Some(prepare_request_id), Some(prepare_digest)) =
                            identity
                        else {
                            return false;
                        };
                        state
                            .prepare_reconciliations
                            .get(&context_id)
                            .is_some_and(|record| {
                                reconciliation_record_matches(
                                    record,
                                    self.inner.runtime_id,
                                    prepare_request_id,
                                    prepare_digest,
                                    intent.setup_expires_at_unix,
                                    intent.hard_expires_at_unix,
                                ) && record.closed_plan == closed_plan
                                    && record.phase == PrepareReconciliationPhase::Intent
                            })
                    });
                    return Some(if same_digest && (cached_failure || exact_live_lineage) {
                        HelperExecution {
                            response: cached.response.clone(),
                            descriptor: cached.descriptor.clone(),
                        }
                    } else if same_digest {
                        execution(
                            response(
                                request,
                                HelperResult::Unavailable,
                                "BIND_LINEAGE_UNAVAILABLE",
                                None,
                            ),
                            None,
                        )
                    } else {
                        execution(
                            response(
                                request,
                                HelperResult::InvalidRequest,
                                "REQUEST_ID_CONFLICT",
                                None,
                            ),
                            None,
                        )
                    });
                }
            }
            let result = self.bind_helper_runtime(request, value).await;
            self.cache_execution(request, &result, true).await;
            return Some(result);
        }

        if let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
            request.operation.as_ref()
        {
            return self
                .reconcile_expired_prepare(request, request_id, digest, value, sender)
                .await;
        }

        match self.reap_expired(request, request_id, digest, sender).await {
            ReapOutcome::Complete => {}
            ReapOutcome::Failure(result) => {
                let result = *result;
                self.cache_execution(request, &result, false).await;
                return Some(result);
            }
            ReapOutcome::ResponseSent => return None,
        }

        {
            let now = self.inner.clock.now_unix();
            let mut state = self.inner.state.lock().await;
            prune_cache(&mut state, now);
            prune_prepare_reconciliations(&mut state, now);
            if let Some(cached) = state.cache.get(&request_id) {
                return Some(if cached.digest.ct_eq(&digest).unwrap_u8() == 1 {
                    HelperExecution {
                        response: cached.response.clone(),
                        descriptor: cached.descriptor.clone(),
                    }
                } else {
                    execution(
                        response(
                            request,
                            HelperResult::InvalidRequest,
                            "REQUEST_ID_CONFLICT",
                            None,
                        ),
                        None,
                    )
                });
            }
        }

        let result = match request.operation.as_ref() {
            Some(helper_request::Operation::PrepareLeaseBatch(value)) => {
                self.prepare_async(request, request_id, digest, value, sender)
                    .await
            }
            Some(helper_request::Operation::ActivateLeaseBatch(value)) => {
                self.activate_async(request, request_id, digest, value, sender)
                    .await
            }
            Some(helper_request::Operation::CommitLeaseBatch(value)) => {
                self.commit_async(request, request_id, digest, value, sender)
                    .await
            }
            Some(helper_request::Operation::DestroyContext(value)) => {
                self.destroy_async(request, request_id, digest, value, sender)
                    .await
            }
            Some(helper_request::Operation::AcquireTransportSocket(value)) => {
                self.acquire_async(request, request_id, digest, value, sender)
                    .await
            }
            Some(helper_request::Operation::CleanupOwned(value)) => {
                if value.cleanup_token.len() != self.inner.cleanup_token.len()
                    || value
                        .cleanup_token
                        .ct_eq(self.inner.cleanup_token.as_slice())
                        .unwrap_u8()
                        != 1
                {
                    Some(execution(
                        response(
                            request,
                            HelperResult::UnauthorisedPeer,
                            "CLEANUP_UNAUTHORISED",
                            None,
                        ),
                        None,
                    ))
                } else {
                    self.cleanup_async(request, request_id, digest, sender)
                        .await
                }
            }
            Some(
                helper_request::Operation::AddMptcpEndpoint(_)
                | helper_request::Operation::RemoveMptcpEndpoint(_),
            ) => Some(execution(
                response(
                    request,
                    HelperResult::Unavailable,
                    "TRANSPORT_HANDOFF_UNAVAILABLE",
                    None,
                ),
                None,
            )),
            Some(
                helper_request::Operation::PrepareClientIngress(_)
                | helper_request::Operation::AcquireIngressSocket(_)
                | helper_request::Operation::ActivateClientIngress(_)
                | helper_request::Operation::DestroyClientIngress(_),
            ) => Some(execution(
                response(
                    request,
                    HelperResult::Unavailable,
                    "CLIENT_INGRESS_UNAVAILABLE",
                    None,
                ),
                None,
            )),
            Some(
                helper_request::Operation::ReconcileExpiredPrepare(_)
                | helper_request::Operation::BindHelperRuntime(_),
            ) => unreachable!("early helper-runtime dispatch"),
            None => Some(execution(invalid_response(request), None)),
        };

        if let Some(result) = result.as_ref() {
            self.cache_execution(request, result, true).await;
        }
        result
    }

    async fn cache_execution(
        &self,
        request: &HelperRequest,
        result: &HelperExecution,
        bind_context: bool,
    ) {
        let Some(request_id) = fixed::<16>(&request.request_id) else {
            return;
        };
        let now = self.inner.clock.now_unix();
        let expires_at_unix = match request.operation.as_ref() {
            Some(helper_request::Operation::PrepareLeaseBatch(value)) => {
                value.setup_expires_at_unix
            }
            Some(helper_request::Operation::BindHelperRuntime(value)) => {
                value.prepare_intent.as_ref().map_or_else(
                    || now.saturating_add(RESPONSE_CACHE_SECONDS),
                    |intent| intent.setup_expires_at_unix,
                )
            }
            _ => now.saturating_add(RESPONSE_CACHE_SECONDS),
        };
        let mut state = self.inner.state.lock().await;
        insert_cache(
            &mut state,
            request_id,
            CachedResponse {
                digest: operation_digest(request).unwrap_or([0; 32]),
                expires_at_unix,
                response: result.response.clone(),
                descriptor: result.descriptor.clone(),
                context_id: if bind_context {
                    request_context_id(request)
                } else {
                    None
                },
            },
        );
    }

    async fn send_ambiguous(
        &self,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) {
        let result = execution(
            response(
                request,
                HelperResult::CleanupIncomplete,
                "BACKEND_RESULT_AMBIGUOUS",
                None,
            ),
            None,
        );
        self.cache_execution(request, &result, false).await;
        if let Some(sender) = sender.take() {
            let _ = sender.send(result);
        }
    }

    async fn call_backend<T, F>(&self, deadline: Instant, call: F) -> BackendCall<T>
    where
        T: Send + 'static,
        F: FnOnce() -> BackendFuture<T> + Send + 'static,
    {
        // The trait method itself is invoked inside the owned task. A backend panic either while
        // constructing its future or polling it is therefore one JoinError; the engine-side owner
        // remains available for exact stable-lineage rollback.
        let mut task = tokio::spawn(async move { call().await });
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(result)) => BackendCall::Complete(result),
            Ok(Err(_)) => BackendCall::Ambiguous,
            Err(_) => BackendCall::TimedOut(task),
        }
    }

    async fn resolve_mutating_call<T>(
        &self,
        call: BackendCall<BackendCompletion<T>>,
        owner: OperationOwner,
        expected_binding: BackendBinding,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<ResolvedCall<T>>
    where
        T: Send + 'static,
    {
        match call {
            BackendCall::Complete(completion) if completion.binding == expected_binding => {
                Some(ResolvedCall::Definite {
                    owner: Box::new(owner),
                    result: completion.result,
                })
            }
            BackendCall::Complete(completion) => {
                // A rejected Acquire completion can own an FD. Close it before privileged cleanup
                // starts so no stale descriptor survives across the rollback boundary.
                drop(completion);
                let cleanup = self.rollback_context(owner, request, sender).await;
                if cleanup.response_sent {
                    None
                } else {
                    Some(ResolvedCall::Ambiguous)
                }
            }
            BackendCall::Ambiguous => {
                let cleanup = self.rollback_context(owner, request, sender).await;
                if cleanup.response_sent {
                    None
                } else {
                    Some(ResolvedCall::Ambiguous)
                }
            }
            BackendCall::TimedOut(task) => {
                let _ = self.mark_cleanup(&owner).await;
                self.send_ambiguous(request, sender).await;
                if let Ok(completion) = task.await {
                    drop(completion);
                }
                let _ = self.rollback_context(owner, request, sender).await;
                None
            }
        }
    }

    async fn rollback_context(
        &self,
        owner: OperationOwner,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> CleanupOutcome {
        if !self.mark_cleanup(&owner).await {
            self.finish_cleanup(owner, false).await;
            return CleanupOutcome {
                confirmed: false,
                response_sent: false,
            };
        }
        let token = owner.token();
        let backend = Arc::clone(&self.inner.backend);
        let context_id = token.context_id;
        let call_deadline = Instant::now() + self.inner.backend_timeout;
        let binding = BackendBinding::for_owner(
            &owner,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            call_deadline,
        );
        let call = BackendRequest::new(
            binding,
            BackendDestroy {
                context_id,
                backend_generation: owner.lineage().backend_generation,
            },
        );
        match self
            .call_backend(call_deadline, move || backend.destroy(call))
            .await
        {
            BackendCall::Complete(completion) => {
                let confirmed = completion.binding == binding && completion.result.is_ok();
                self.finish_cleanup(owner, confirmed).await;
                CleanupOutcome {
                    confirmed,
                    response_sent: false,
                }
            }
            BackendCall::Ambiguous => {
                self.finish_cleanup(owner, false).await;
                CleanupOutcome {
                    confirmed: false,
                    response_sent: false,
                }
            }
            BackendCall::TimedOut(task) => {
                self.send_ambiguous(request, sender).await;
                let confirmed = matches!(
                    task.await,
                    Ok(BackendCompletion {
                        binding: completed_binding,
                        result: Ok(ConfirmedAbsent),
                    }) if completed_binding == binding
                );
                self.finish_cleanup(owner, confirmed).await;
                CleanupOutcome {
                    confirmed,
                    response_sent: true,
                }
            }
        }
    }

    async fn mark_cleanup(&self, owner: &OperationOwner) -> bool {
        let token = owner.token();
        let lineage = owner.lineage();
        let mut state = self.inner.state.lock().await;
        if state.in_flight.is_some_and(|current| current != token)
            || !state
                .cleanup_pending
                .contains(&(token.context_id, token.generation))
        {
            return false;
        }
        let exact = match state.contexts.get_mut(&token.context_id) {
            Some(context)
                if context.generation == token.generation
                    && context_backend_lineage(token.context_id, context) == lineage =>
            {
                context.phase = ContextPhase::Quarantined;
                true
            }
            Some(_) => false,
            None => {
                let exact_pending = state
                    .prepare_reconciliations
                    .get(&token.context_id)
                    .is_some_and(|record| {
                        record.backend_generation == token.generation
                            && reconciliation_backend_lineage(token.context_id, record) == lineage
                    });
                if !exact_pending {
                    return false;
                }
                true
            }
        };
        if exact {
            // `OperationOwner` is the authority. Recover a missing copyable state binding only
            // after exact lineage, generation, and cleanup-pending validation; never replace a
            // different live operation.
            state.in_flight = Some(token);
        }
        exact
    }

    async fn finish_cleanup(&self, owner: OperationOwner, confirmed: bool) {
        let lineage = owner.lineage();
        let token = owner.token();
        let mut state = self.inner.state.lock().await;
        let exact_operation = state.in_flight == Some(token)
            && state
                .cleanup_pending
                .contains(&(token.context_id, token.generation));
        let exact_generation = state.contexts.get(&token.context_id).map_or_else(
            || {
                state
                    .prepare_reconciliations
                    .get(&token.context_id)
                    .is_some_and(|record| {
                        record.backend_generation == token.generation
                            && reconciliation_backend_lineage(token.context_id, record) == lineage
                    })
            },
            |context| {
                context.generation == token.generation
                    && context_backend_lineage(token.context_id, context) == lineage
            },
        );
        if confirmed {
            if exact_operation && exact_generation {
                state.contexts.remove(&token.context_id);
                state
                    .cleanup_pending
                    .remove(&(token.context_id, token.generation));
                if let Some(record) = state.prepare_reconciliations.get_mut(&token.context_id) {
                    if record.backend_generation == token.generation {
                        record.phase = PrepareReconciliationPhase::Absent;
                    }
                }
            }
        } else if exact_operation && exact_generation {
            if let Some(context) = state.contexts.get_mut(&token.context_id) {
                if context.generation == token.generation {
                    context.phase = ContextPhase::Quarantined;
                }
            }
        }
        if exact_operation {
            state.in_flight = None;
        }
        if exact_operation && exact_generation {
            purge_context_cache(&mut state, token.context_id);
        }
        drop(state);
        let _ = owner.settle();
    }

    #[allow(clippy::too_many_lines)] // Admission, lineage reservation, and cache commit are one audit unit.
    async fn bind_helper_runtime(
        &self,
        request: &HelperRequest,
        value: &BindHelperRuntime,
    ) -> HelperExecution {
        let Some(intent) = value.prepare_intent.as_ref() else {
            return helper_runtime_execution(request, self.inner.runtime_id);
        };
        let now = self.inner.clock.now_unix();
        if intent.setup_expires_at_unix <= now
            || intent.setup_expires_at_unix > now.saturating_add(SETUP_TTL_SECONDS)
            || intent.hard_expires_at_unix < intent.setup_expires_at_unix
            || intent.hard_expires_at_unix > now.saturating_add(HARD_TTL_SECONDS)
        {
            return execution(
                response(request, HelperResult::Expired, "INTENT_TTL_INVALID", None),
                None,
            );
        }
        let (Some(context_id), Some(prepare_request_id), Some(prepare_digest)) = (
            fixed::<16>(&intent.route_context_id),
            fixed::<16>(&intent.prepare_request_id),
            fixed::<32>(&intent.prepare_operation_digest),
        ) else {
            return execution(invalid_response(request), None);
        };
        let Some(closed_plan) = intent
            .closed_plan
            .as_ref()
            .and_then(ClosedPreparePlanBinding::from_closed_plan)
        else {
            return execution(invalid_response(request), None);
        };

        let mut state = self.inner.state.lock().await;
        if state.contexts.contains_key(&context_id) {
            return execution(
                response(
                    request,
                    HelperResult::AlreadyExists,
                    "CONTEXT_CONFLICT",
                    None,
                ),
                None,
            );
        }
        if state
            .cleanup_pending
            .iter()
            .any(|(pending_id, _)| *pending_id == context_id)
        {
            return execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "CONTEXT_CLEANUP_PENDING",
                    None,
                ),
                None,
            );
        }
        if let Some(record) = state.prepare_reconciliations.get(&context_id) {
            let exact = record.helper_runtime_id == self.inner.runtime_id
                && record.prepare_request_id == prepare_request_id
                && record.prepare_operation_digest == prepare_digest
                && record.setup_expires_at_unix == intent.setup_expires_at_unix
                && record.hard_expires_at_unix == intent.hard_expires_at_unix
                && record.closed_plan == closed_plan
                && record.phase == PrepareReconciliationPhase::Intent;
            return if exact {
                helper_runtime_execution(request, self.inner.runtime_id)
            } else {
                execution(
                    response(
                        request,
                        HelperResult::AlreadyExists,
                        "CONTEXT_RECONCILIATION_RETAINED",
                        None,
                    ),
                    None,
                )
            };
        }
        if state.prepare_reconciliations.len() >= MAX_PREPARE_RECONCILIATIONS {
            return execution(
                response(
                    request,
                    HelperResult::Capacity,
                    "RECONCILIATION_CAPACITY",
                    None,
                ),
                None,
            );
        }
        let Some(generation) = reserve_generation(&mut state) else {
            return execution(
                response(request, HelperResult::Capacity, "GENERATION_CAPACITY", None),
                None,
            );
        };
        state.prepare_reconciliations.insert(
            context_id,
            PrepareReconciliationRecord {
                helper_runtime_id: self.inner.runtime_id,
                prepare_request_id,
                prepare_operation_digest: prepare_digest,
                backend_generation: generation,
                setup_expires_at_unix: intent.setup_expires_at_unix,
                hard_expires_at_unix: intent.hard_expires_at_unix,
                closed_plan,
                phase: PrepareReconciliationPhase::Intent,
                reconciliation_request_id: None,
            },
        );
        drop(state);
        helper_runtime_execution(request, self.inner.runtime_id)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keep target-specific lineage validation, cleanup and absence commit in one audit boundary"
    )]
    async fn reconcile_expired_prepare(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &ReconcileExpiredPrepare,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let now = self.inner.clock.now_unix();
        if now < value.setup_expires_at_unix {
            return Some(execution(
                response(
                    request,
                    HelperResult::Expired,
                    "RECONCILE_BEFORE_EXPIRY",
                    None,
                ),
                None,
            ));
        }
        let (Some(runtime_id), Some(context_id), Some(prepare_request_id), Some(prepare_digest)) = (
            fixed::<32>(&value.helper_runtime_id),
            fixed::<16>(&value.route_context_id),
            fixed::<16>(&value.prepare_request_id),
            fixed::<32>(&value.prepare_operation_digest),
        ) else {
            return Some(execution(invalid_response(request), None));
        };
        if runtime_id.ct_eq(&self.inner.runtime_id).unwrap_u8() != 1 {
            return Some(execution(
                response(
                    request,
                    HelperResult::Unavailable,
                    "HELPER_RUNTIME_CHANGED",
                    None,
                ),
                None,
            ));
        }

        let token = {
            let mut state = self.inner.state.lock().await;
            let Some(record) = state.prepare_reconciliations.get(&context_id).copied() else {
                return Some(execution(
                    response(
                        request,
                        HelperResult::Unavailable,
                        "RECONCILIATION_EVIDENCE_UNAVAILABLE",
                        None,
                    ),
                    None,
                ));
            };
            if !reconciliation_record_matches(
                &record,
                runtime_id,
                prepare_request_id,
                prepare_digest,
                value.setup_expires_at_unix,
                value.hard_expires_at_unix,
            ) {
                return Some(execution(
                    response(
                        request,
                        HelperResult::Unavailable,
                        "RECONCILIATION_EVIDENCE_UNAVAILABLE",
                        None,
                    ),
                    None,
                ));
            }
            if state.in_flight.is_some() {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "RECONCILIATION_OPERATION_IN_FLIGHT",
                        None,
                    ),
                    None,
                ));
            }
            let target_pending = state
                .cleanup_pending
                .iter()
                .any(|(pending_id, _)| *pending_id == context_id);
            match record.phase {
                PrepareReconciliationPhase::Intent => {
                    if state.contexts.contains_key(&context_id) || target_pending {
                        return Some(execution(
                            response(
                                request,
                                HelperResult::CleanupIncomplete,
                                "RECONCILIATION_NOT_QUIESCENT",
                                None,
                            ),
                            None,
                        ));
                    }
                    if let Err(error) = bind_reconciliation_request(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                    ) {
                        return Some(reconciliation_request_admission_error(request, error));
                    }
                    state
                        .prepare_reconciliations
                        .get_mut(&context_id)
                        .expect("exact Prepare intent")
                        .phase = PrepareReconciliationPhase::Absent;
                    purge_context_cache(&mut state, context_id);
                    None
                }
                PrepareReconciliationPhase::Absent => {
                    if state.contexts.contains_key(&context_id) || target_pending {
                        return Some(execution(
                            response(
                                request,
                                HelperResult::CleanupIncomplete,
                                "RECONCILIATION_NOT_QUIESCENT",
                                None,
                            ),
                            None,
                        ));
                    }
                    if let Err(error) = bind_reconciliation_request(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                    ) {
                        return Some(reconciliation_request_admission_error(request, error));
                    }
                    None
                }
                PrepareReconciliationPhase::Pending => {
                    if state.contexts.contains_key(&context_id) {
                        return Some(execution(
                            response(
                                request,
                                HelperResult::CleanupIncomplete,
                                "RECONCILIATION_STATE_CONFLICT",
                                None,
                            ),
                            None,
                        ));
                    }
                    if let Err(error) = bind_reconciliation_request(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                    ) {
                        return Some(reconciliation_request_admission_error(request, error));
                    }
                    let Some(token) = begin_operation(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                        None,
                        OperationKind::Reconcile,
                        reconciliation_backend_lineage(context_id, &record),
                        Instant::now() + self.inner.backend_timeout,
                    ) else {
                        return Some(execution(
                            response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                            None,
                        ));
                    };
                    state
                        .cleanup_pending
                        .insert((context_id, record.backend_generation));
                    Some(token)
                }
                PrepareReconciliationPhase::Owned => {
                    let Some(context) = state.contexts.get(&context_id) else {
                        return Some(execution(
                            response(
                                request,
                                HelperResult::CleanupIncomplete,
                                "RECONCILIATION_STATE_CONFLICT",
                                None,
                            ),
                            None,
                        ));
                    };
                    let prior_phase = context.phase;
                    let exact_context = context.generation == record.backend_generation
                        && context.backend_generation == record.backend_generation
                        && context.helper_runtime_id == runtime_id
                        && context.prepare_request_id == prepare_request_id
                        && context.prepare_operation_digest == prepare_digest
                        && context.setup_expires_at_unix == value.setup_expires_at_unix
                        && context.hard_expires_at_unix == value.hard_expires_at_unix;
                    if !exact_context
                        || !matches!(
                            context.phase,
                            ContextPhase::Prepared | ContextPhase::Quarantined
                        )
                    {
                        return Some(execution(
                            response(
                                request,
                                HelperResult::CleanupIncomplete,
                                "RECONCILIATION_STATE_CONFLICT",
                                None,
                            ),
                            None,
                        ));
                    }
                    if let Err(error) = bind_reconciliation_request(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                    ) {
                        return Some(reconciliation_request_admission_error(request, error));
                    }
                    let Some(token) = begin_operation(
                        &mut state,
                        request_id,
                        digest,
                        context_id,
                        record.backend_generation,
                        Some(prior_phase),
                        OperationKind::Reconcile,
                        reconciliation_backend_lineage(context_id, &record),
                        Instant::now() + self.inner.backend_timeout,
                    ) else {
                        return Some(execution(
                            response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                            None,
                        ));
                    };
                    state
                        .contexts
                        .get_mut(&context_id)
                        .expect("exact Prepared generation")
                        .phase = ContextPhase::Quarantined;
                    state
                        .cleanup_pending
                        .insert((context_id, record.backend_generation));
                    Some(token)
                }
            }
        };

        if let Some(token) = token {
            let cleanup = self.destroy_generation(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            if !cleanup.confirmed {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "RECONCILIATION_CLEANUP_INCOMPLETE",
                        None,
                    ),
                    None,
                ));
            }
        }

        let state = self.inner.state.lock().await;
        let confirmed_absent =
            state
                .prepare_reconciliations
                .get(&context_id)
                .is_some_and(|record| {
                    reconciliation_record_matches(
                        record,
                        runtime_id,
                        prepare_request_id,
                        prepare_digest,
                        value.setup_expires_at_unix,
                        value.hard_expires_at_unix,
                    ) && record.phase == PrepareReconciliationPhase::Absent
                })
                && !state.contexts.contains_key(&context_id)
                && !state
                    .cleanup_pending
                    .iter()
                    .any(|(pending_id, _)| *pending_id == context_id)
                && state
                    .in_flight
                    .is_none_or(|operation| operation.context_id != context_id);
        drop(state);
        if !confirmed_absent {
            return Some(execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "RECONCILIATION_NOT_QUIESCENT",
                    None,
                ),
                None,
            ));
        }
        Some(reconciled_prepare_execution(request, value))
    }

    #[allow(clippy::too_many_lines)] // PLAN, proof validation, rollback, and COMMIT form one audit unit.
    async fn prepare_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &PrepareLeaseBatch,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let now = self.inner.clock.now_unix();
        if value.setup_expires_at_unix <= now
            || value.setup_expires_at_unix > now.saturating_add(SETUP_TTL_SECONDS)
            || value.hard_expires_at_unix < value.setup_expires_at_unix
            || value.hard_expires_at_unix > now.saturating_add(HARD_TTL_SECONDS)
        {
            return Some(execution(
                response(request, HelperResult::Expired, "LEASE_TTL_INVALID", None),
                None,
            ));
        }
        let Some(context_id) = fixed::<16>(&value.route_context_id) else {
            return Some(execution(invalid_response(request), None));
        };
        let Some(closed_plan) = ClosedPreparePlanBinding::from_prepare(value) else {
            return Some(execution(invalid_response(request), None));
        };

        let (token, context_handle, lease_handles) = {
            let mut state = self.inner.state.lock().await;
            if state.contexts.contains_key(&context_id) {
                return Some(execution(
                    response(
                        request,
                        HelperResult::AlreadyExists,
                        "CONTEXT_CONFLICT",
                        None,
                    ),
                    None,
                ));
            }
            if state
                .cleanup_pending
                .iter()
                .any(|(pending_id, _)| *pending_id == context_id)
            {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "CONTEXT_CLEANUP_PENDING",
                        None,
                    ),
                    None,
                ));
            }
            let Some(intent) = state.prepare_reconciliations.get(&context_id).copied() else {
                return Some(execution(
                    response(
                        request,
                        HelperResult::Unavailable,
                        "PREPARE_INTENT_REQUIRED",
                        None,
                    ),
                    None,
                ));
            };
            if !reconciliation_record_matches(
                &intent,
                self.inner.runtime_id,
                request_id,
                digest,
                value.setup_expires_at_unix,
                value.hard_expires_at_unix,
            ) || intent.closed_plan != closed_plan
                || intent.phase != PrepareReconciliationPhase::Intent
            {
                return Some(execution(
                    response(
                        request,
                        HelperResult::AlreadyExists,
                        "PREPARE_INTENT_CONFLICT",
                        None,
                    ),
                    None,
                ));
            }
            if state.contexts.len() >= MAX_CONTEXTS {
                return Some(execution(
                    response(request, HelperResult::Capacity, "CONTEXT_CAPACITY", None),
                    None,
                ));
            }
            if state.in_flight.is_some() {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "OPERATION_IN_FLIGHT",
                        None,
                    ),
                    None,
                ));
            }
            let mut reserved = BTreeSet::new();
            let Some(context_handle) = self.unique_handle(&state, &reserved) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "HANDLE_CAPACITY", None),
                    None,
                ));
            };
            reserved.insert(context_handle);
            let mut lease_handles = Vec::with_capacity(value.leases.len());
            for _ in &value.leases {
                let Some(handle) = self.unique_handle(&state, &reserved) else {
                    return Some(execution(
                        response(request, HelperResult::Capacity, "HANDLE_CAPACITY", None),
                        None,
                    ));
                };
                reserved.insert(handle);
                lease_handles.push(handle);
            }
            let generation = intent.backend_generation;
            let Some(token) = begin_operation(
                &mut state,
                request_id,
                digest,
                context_id,
                generation,
                None,
                OperationKind::Prepare,
                reconciliation_backend_lineage(context_id, &intent),
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            state
                .prepare_reconciliations
                .get_mut(&context_id)
                .expect("validated Prepare intent")
                .phase = PrepareReconciliationPhase::Pending;
            state.cleanup_pending.insert((context_id, generation));
            (token, context_handle, lease_handles)
        };

        let backend = Arc::clone(&self.inner.backend);
        let binding = BackendBinding::for_owner(
            &token,
            BackendPhase::PreparePending,
            BackendAction::Prepare,
            token.call_deadline(),
        );
        let backend_value = BackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.prepare(backend_value)
            })
            .await;
        let resolved = self
            .resolve_mutating_call(call, token, binding, request, sender)
            .await?;
        let (token, prepared) = match resolved {
            ResolvedCall::Definite {
                owner,
                result: Ok(prepared),
            } => (*owner, prepared),
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                let cleanup = self.rollback_context(*owner, request, sender).await;
                if cleanup.response_sent {
                    return None;
                }
                return Some(execution(
                    if cleanup.confirmed {
                        backend_response(request, error, "PREPARE_FAILED")
                    } else {
                        response(
                            request,
                            HelperResult::CleanupIncomplete,
                            "CLEANUP_INCOMPLETE",
                            None,
                        )
                    },
                    None,
                ));
            }
            ResolvedCall::Ambiguous => {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "BACKEND_RESULT_AMBIGUOUS",
                        None,
                    ),
                    None,
                ));
            }
        };
        let operation = token.token();

        let proof_valid = prepared_matches(value, &prepared);
        let commit_now = self.inner.clock.now_unix();
        let exact = {
            let state = self.inner.state.lock().await;
            state.in_flight == Some(operation)
                && !state.contexts.contains_key(&context_id)
                && state
                    .cleanup_pending
                    .contains(&(context_id, operation.generation))
                && state
                    .prepare_reconciliations
                    .get(&context_id)
                    .is_some_and(|record| {
                        record.backend_generation == operation.generation
                            && record.phase == PrepareReconciliationPhase::Pending
                    })
                && commit_now < value.setup_expires_at_unix
                && commit_now < value.hard_expires_at_unix
        };
        if !proof_valid || !exact {
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            let result = if !cleanup.confirmed {
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "CLEANUP_INCOMPLETE",
                    None,
                )
            } else if !proof_valid {
                response(request, HelperResult::Kernel, "PREPARE_PROOF_INVALID", None)
            } else {
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "STALE_BACKEND_RESULT",
                    None,
                )
            };
            return Some(execution(result, None));
        }

        let mut records = BTreeMap::new();
        let mut output = Vec::with_capacity(prepared.len());
        for (lease, lease_handle) in prepared.into_iter().zip(lease_handles) {
            output.push(PreparedLease {
                lease_handle: lease_handle.to_vec(),
                path_id: lease.path_id,
                role: lease.role,
                public_key: lease.public_key.to_vec(),
                public_endpoint: Some(lease.public_endpoint.clone()),
                underlay_evidence: lease.evidence as i32,
            });
            records.insert(
                (lease.path_id, lease.role),
                LeaseRecord {
                    handle: lease_handle,
                    public_key: lease.public_key,
                    public_endpoint: lease.public_endpoint,
                    baseline: None,
                },
            );
        }

        let mut state = self.inner.state.lock().await;
        let final_commit_now = self.inner.clock.now_unix();
        let still_exact = state.in_flight == Some(operation)
            && !state.contexts.contains_key(&context_id)
            && state
                .cleanup_pending
                .contains(&(context_id, operation.generation))
            && state
                .prepare_reconciliations
                .get(&context_id)
                .is_some_and(|record| {
                    record.backend_generation == operation.generation
                        && record.phase == PrepareReconciliationPhase::Pending
                })
            && final_commit_now < value.setup_expires_at_unix
            && final_commit_now < value.hard_expires_at_unix;
        if !still_exact {
            drop(state);
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "STALE_BACKEND_RESULT",
                    None,
                ),
                None,
            ));
        }
        state.contexts.insert(
            context_id,
            ContextRecord {
                generation: operation.generation,
                backend_generation: token.lineage().backend_generation,
                handle: context_handle,
                helper_runtime_id: self.inner.runtime_id,
                prepare_request_id: request_id,
                prepare_operation_digest: digest,
                setup_expires_at_unix: value.setup_expires_at_unix,
                hard_expires_at_unix: value.hard_expires_at_unix,
                phase: ContextPhase::Prepared,
                activated_at_unix: None,
                leases: records,
            },
        );
        state
            .prepare_reconciliations
            .get_mut(&context_id)
            .expect("reserved Prepare reconciliation")
            .phase = PrepareReconciliationPhase::Owned;
        state
            .cleanup_pending
            .remove(&(context_id, operation.generation));
        state.in_flight = None;
        drop(state);
        let _ = token.settle();

        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "LEASES_PREPARED",
                Some(helper_response::Outcome::PreparedLeaseBatch(
                    PreparedLeaseBatch {
                        context_handle: context_handle.to_vec(),
                        leases: output,
                    },
                )),
            ),
            None,
        ))
    }

    #[allow(clippy::too_many_lines)] // PLAN, proof validation, rollback, and COMMIT form one audit unit.
    async fn activate_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &ActivateLeaseBatch,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(context_id) = fixed::<16>(&value.route_context_id) else {
            return Some(execution(invalid_response(request), None));
        };
        let (token, next_generation) = {
            let mut state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(request, HelperResult::NotFound, "CONTEXT_ABSENT", None),
                    None,
                ));
            };
            if !matches_handle(&context.handle, &value.context_handle) {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "CONTEXT_HANDLE_INVALID",
                        None,
                    ),
                    None,
                ));
            }
            if context.phase != ContextPhase::Prepared {
                return Some(execution(
                    response(request, phase_result(context.phase), "INVALID_STATE", None),
                    None,
                ));
            }
            let now = self.inner.clock.now_unix();
            if now >= context.setup_expires_at_unix || now >= context.hard_expires_at_unix {
                return Some(execution(
                    response(request, HelperResult::Expired, "CONTEXT_EXPIRED", None),
                    None,
                ));
            }
            if !activation_matches(context, &value.leases) {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "ACTIVATION_MISMATCH",
                        None,
                    ),
                    None,
                ));
            }
            let generation = context.generation;
            let lineage = context_backend_lineage(context_id, context);
            let Some(next_generation) = state.next_generation.checked_add(1) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "GENERATION_CAPACITY", None),
                    None,
                ));
            };
            let Some(token) = begin_operation(
                &mut state,
                request_id,
                digest,
                context_id,
                generation,
                Some(ContextPhase::Prepared),
                OperationKind::Activate,
                lineage,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            state.next_generation = next_generation;
            state.cleanup_pending.insert((context_id, generation));
            (token, next_generation)
        };

        let backend = Arc::clone(&self.inner.backend);
        let binding = BackendBinding::for_owner(
            &token,
            BackendPhase::Prepared,
            BackendAction::Activate,
            token.call_deadline(),
        );
        let backend_value = BackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.activate(backend_value)
            })
            .await;
        let resolved = self
            .resolve_mutating_call(call, token, binding, request, sender)
            .await?;
        let (token, baselines) = match resolved {
            ResolvedCall::Definite {
                owner,
                result: Ok(baselines),
            } => (*owner, baselines),
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                let cleanup = self.rollback_context(*owner, request, sender).await;
                if cleanup.response_sent {
                    return None;
                }
                return Some(execution(
                    if cleanup.confirmed {
                        backend_response(request, error, "ACTIVATION_FAILED")
                    } else {
                        response(
                            request,
                            HelperResult::CleanupIncomplete,
                            "CLEANUP_INCOMPLETE",
                            None,
                        )
                    },
                    None,
                ));
            }
            ResolvedCall::Ambiguous => {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "BACKEND_RESULT_AMBIGUOUS",
                        None,
                    ),
                    None,
                ));
            }
        };
        let operation = token.token();

        let mut state = self.inner.state.lock().await;
        let exact = state.in_flight == Some(operation)
            && state.contexts.get(&context_id).is_some_and(|context| {
                context.generation == operation.generation
                    && context_backend_lineage(context_id, context) == token.lineage()
                    && context.phase == ContextPhase::Prepared
                    && activation_matches(context, &value.leases)
                    && counters_match(context, &baselines)
            });
        let now = self.inner.clock.now_unix();
        let unexpired = state.contexts.get(&context_id).is_some_and(|context| {
            now < context.setup_expires_at_unix && now < context.hard_expires_at_unix
        });
        if !exact || !unexpired {
            drop(state);
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "STALE_BACKEND_RESULT",
                    None,
                ),
                None,
            ));
        }
        let context = state
            .contexts
            .get_mut(&context_id)
            .expect("validated context");
        for baseline in baselines {
            if let Some(lease) = context.leases.get_mut(&(baseline.path_id, baseline.role)) {
                lease.baseline = Some(baseline);
            }
        }
        context.generation = next_generation;
        context.phase = ContextPhase::Activated;
        context.activated_at_unix = Some(now);
        let context_handle = context.handle;
        let lease_handles = context
            .leases
            .values()
            .map(|lease| lease.handle.to_vec())
            .collect();
        state.prepare_reconciliations.remove(&context_id);
        state
            .cleanup_pending
            .remove(&(context_id, operation.generation));
        state.in_flight = None;
        drop(state);
        let _ = token.settle();

        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "LEASES_ACTIVATED",
                Some(helper_response::Outcome::ActivatedLeaseBatch(
                    volparossa_routing::ActivatedLeaseBatch {
                        context_handle: context_handle.to_vec(),
                        lease_handles,
                    },
                )),
            ),
            None,
        ))
    }

    #[allow(clippy::too_many_lines)] // PLAN, proof validation, rollback, and COMMIT form one audit unit.
    async fn commit_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &volparossa_routing::CommitLeaseBatch,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(context_id) = fixed::<16>(&value.route_context_id) else {
            return Some(execution(invalid_response(request), None));
        };
        let (token, next_generation) = {
            let mut state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(request, HelperResult::NotFound, "CONTEXT_ABSENT", None),
                    None,
                ));
            };
            if !matches_handle(&context.handle, &value.context_handle)
                || !commit_matches(context, &value.leases)
            {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "COMMIT_MISMATCH",
                        None,
                    ),
                    None,
                ));
            }
            if context.phase != ContextPhase::Activated {
                return Some(execution(
                    response(request, phase_result(context.phase), "INVALID_STATE", None),
                    None,
                ));
            }
            if self.inner.clock.now_unix() >= context.hard_expires_at_unix {
                return Some(execution(
                    response(request, HelperResult::Expired, "CONTEXT_EXPIRED", None),
                    None,
                ));
            }
            let generation = context.generation;
            let lineage = context_backend_lineage(context_id, context);
            let Some(next_generation) = state.next_generation.checked_add(1) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "GENERATION_CAPACITY", None),
                    None,
                ));
            };
            let Some(token) = begin_operation(
                &mut state,
                request_id,
                digest,
                context_id,
                generation,
                Some(ContextPhase::Activated),
                OperationKind::Probe,
                lineage,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            state.next_generation = next_generation;
            state.cleanup_pending.insert((context_id, generation));
            (token, next_generation)
        };

        let backend = Arc::clone(&self.inner.backend);
        let binding = BackendBinding::for_owner(
            &token,
            BackendPhase::Activated,
            BackendAction::Probe,
            token.call_deadline(),
        );
        let backend_value = BackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || backend.probe(backend_value))
            .await;
        let resolved = self
            .resolve_mutating_call(call, token, binding, request, sender)
            .await?;
        let (token, proofs) = match resolved {
            ResolvedCall::Definite {
                owner,
                result: Ok(proofs),
            } => (*owner, proofs),
            ResolvedCall::Definite {
                owner,
                result: Err(BackendError::CleanupIncomplete),
            } => {
                let cleanup = self.rollback_context(*owner, request, sender).await;
                if cleanup.response_sent {
                    return None;
                }
                return Some(execution(
                    if cleanup.confirmed {
                        backend_response(
                            request,
                            BackendError::CleanupIncomplete,
                            "COMMIT_PROBE_FAILED",
                        )
                    } else {
                        response(
                            request,
                            HelperResult::CleanupIncomplete,
                            "CLEANUP_INCOMPLETE",
                            None,
                        )
                    },
                    None,
                ));
            }
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                self.clear_operation(*owner).await;
                return Some(execution(
                    backend_response(request, error, "COMMIT_PROBE_FAILED"),
                    None,
                ));
            }
            ResolvedCall::Ambiguous => {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "BACKEND_RESULT_AMBIGUOUS",
                        None,
                    ),
                    None,
                ));
            }
        };
        let operation = token.token();

        let mut state = self.inner.state.lock().await;
        let exact = state.in_flight == Some(operation)
            && state.contexts.get(&context_id).is_some_and(|context| {
                context.generation == operation.generation
                    && context_backend_lineage(context_id, context) == token.lineage()
                    && context.phase == ContextPhase::Activated
                    && commit_matches(context, &value.leases)
            });
        if !exact {
            drop(state);
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "STALE_BACKEND_RESULT",
                    None,
                ),
                None,
            ));
        }
        let now = self.inner.clock.now_unix();
        let context = state.contexts.get(&context_id).expect("validated context");
        if now >= context.hard_expires_at_unix {
            drop(state);
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                response(request, HelperResult::Expired, "CONTEXT_EXPIRED", None),
                None,
            ));
        }
        let activated_at = context.activated_at_unix.unwrap_or(u64::MAX);
        if !proofs_commit(context, &proofs, activated_at) {
            drop(state);
            self.clear_operation(token).await;
            return Some(execution(
                response(
                    request,
                    HelperResult::Kernel,
                    "HANDSHAKE_PROOF_INCOMPLETE",
                    None,
                ),
                None,
            ));
        }

        let context = state
            .contexts
            .get_mut(&context_id)
            .expect("validated context");
        context.generation = next_generation;
        context.phase = ContextPhase::Committed;
        let leases = proofs
            .into_iter()
            .map(|proof| CommittedLease {
                lease_handle: context
                    .leases
                    .get(&(proof.path_id, proof.role))
                    .map_or_else(Vec::new, |lease| lease.handle.to_vec()),
                latest_handshake_unix: proof.latest_handshake_unix,
                received_bytes: proof.received_bytes,
                transmitted_bytes: proof.transmitted_bytes,
            })
            .collect();
        let context_handle = context.handle;
        state
            .cleanup_pending
            .remove(&(context_id, operation.generation));
        state.in_flight = None;
        drop(state);
        let _ = token.settle();

        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "LEASES_COMMITTED",
                Some(helper_response::Outcome::CommittedLeaseBatch(
                    CommittedLeaseBatch {
                        context_handle: context_handle.to_vec(),
                        leases,
                    },
                )),
            ),
            None,
        ))
    }

    #[allow(clippy::too_many_lines)] // PLAN, descriptor ownership, rollback, and COMMIT form one audit unit.
    async fn acquire_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &AcquireTransportSocket,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let backend = Arc::clone(&self.inner.backend);
        let query_binding = BackendRuntimeBinding {
            helper_runtime_id: self.inner.runtime_id,
            action: BackendRuntimeAction::QueryTransportSocket,
            call_deadline: Instant::now() + self.inner.backend_timeout,
        };
        let query = BackendRuntimeRequest::new(query_binding);
        let supported = match self
            .call_backend(query_binding.call_deadline, move || {
                backend.transport_socket_supported(query)
            })
            .await
        {
            BackendCall::Complete(BackendRuntimeCompletion {
                binding,
                result: Ok(supported),
            }) if binding == query_binding => supported,
            BackendCall::Complete(BackendRuntimeCompletion {
                binding,
                result: Err(error),
            }) if binding == query_binding => {
                return Some(execution(
                    backend_response(request, error, "TRANSPORT_SOCKET_UNAVAILABLE"),
                    None,
                ));
            }
            BackendCall::Complete(_) | BackendCall::Ambiguous => {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "BACKEND_RESULT_AMBIGUOUS",
                        None,
                    ),
                    None,
                ));
            }
            BackendCall::TimedOut(task) => {
                self.send_ambiguous(request, sender).await;
                let _ = task.await;
                return None;
            }
        };
        if !supported {
            return Some(execution(
                backend_response(
                    request,
                    BackendError::Unavailable,
                    "TRANSPORT_SOCKET_UNAVAILABLE",
                ),
                None,
            ));
        }

        let Some(context_id) = fixed::<16>(&value.route_context_id) else {
            return Some(execution(invalid_response(request), None));
        };
        let token = {
            let mut state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(request, HelperResult::NotFound, "CONTEXT_ABSENT", None),
                    None,
                ));
            };
            if !matches_handle(&context.handle, &value.context_handle)
                || !context.leases.contains_key(&(value.path_id, value.role))
            {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "TRANSPORT_CONTEXT_MISMATCH",
                        None,
                    ),
                    None,
                ));
            }
            if context.phase != ContextPhase::Committed {
                return Some(execution(
                    response(request, phase_result(context.phase), "INVALID_STATE", None),
                    None,
                ));
            }
            if self.inner.clock.now_unix() >= context.hard_expires_at_unix {
                return Some(execution(
                    response(request, HelperResult::Expired, "CONTEXT_EXPIRED", None),
                    None,
                ));
            }
            let generation = context.generation;
            let lineage = context_backend_lineage(context_id, context);
            let Some(token) = begin_operation(
                &mut state,
                request_id,
                digest,
                context_id,
                generation,
                Some(ContextPhase::Committed),
                OperationKind::Acquire,
                lineage,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            state.cleanup_pending.insert((context_id, generation));
            token
        };

        let backend = Arc::clone(&self.inner.backend);
        let binding = BackendBinding::for_owner(
            &token,
            BackendPhase::Committed,
            BackendAction::AcquireTransportSocket,
            token.call_deadline(),
        );
        let backend_value = BackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.acquire_transport_socket(backend_value)
            })
            .await;
        let resolved = self
            .resolve_mutating_call(call, token, binding, request, sender)
            .await?;
        let (token, descriptor) = match resolved {
            ResolvedCall::Definite {
                owner,
                result: Ok(descriptor),
            } => (*owner, descriptor),
            ResolvedCall::Definite {
                owner,
                result: Err(BackendError::CleanupIncomplete),
            } => {
                let cleanup = self.rollback_context(*owner, request, sender).await;
                if cleanup.response_sent {
                    return None;
                }
                return Some(execution(
                    if cleanup.confirmed {
                        backend_response(
                            request,
                            BackendError::CleanupIncomplete,
                            "TRANSPORT_SOCKET_UNAVAILABLE",
                        )
                    } else {
                        response(
                            request,
                            HelperResult::CleanupIncomplete,
                            "CLEANUP_INCOMPLETE",
                            None,
                        )
                    },
                    None,
                ));
            }
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                self.clear_operation(*owner).await;
                return Some(execution(
                    backend_response(request, error, "TRANSPORT_SOCKET_UNAVAILABLE"),
                    None,
                ));
            }
            ResolvedCall::Ambiguous => {
                return Some(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "BACKEND_RESULT_AMBIGUOUS",
                        None,
                    ),
                    None,
                ));
            }
        };
        let operation = token.token();

        let mut state = self.inner.state.lock().await;
        let exact = state.in_flight == Some(operation)
            && state.contexts.get(&context_id).is_some_and(|context| {
                context.generation == operation.generation
                    && context_backend_lineage(context_id, context) == token.lineage()
                    && context.phase == ContextPhase::Committed
                    && matches_handle(&context.handle, &value.context_handle)
                    && context.leases.contains_key(&(value.path_id, value.role))
                    && self.inner.clock.now_unix() < context.hard_expires_at_unix
            });
        if !exact {
            drop(state);
            drop(descriptor);
            let cleanup = self.rollback_context(token, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "STALE_BACKEND_RESULT",
                    None,
                ),
                None,
            ));
        }
        state
            .cleanup_pending
            .remove(&(context_id, operation.generation));
        state.in_flight = None;
        drop(state);
        let _ = token.settle();

        let ready = TransportSocketReady {
            path_id: value.path_id,
            role: value.role,
            descriptor_kind: value.descriptor_kind,
            local: value.expected_local.clone(),
            remote: value.expected_remote.clone(),
        };
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "TRANSPORT_SOCKET_READY",
                Some(helper_response::Outcome::TransportSocketReady(ready)),
            ),
            Some(Arc::new(descriptor)),
        ))
    }

    async fn destroy_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &volparossa_routing::DestroyContext,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(context_id) = fixed::<16>(&value.route_context_id) else {
            return Some(execution(invalid_response(request), None));
        };
        let token = {
            let mut state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(
                        request,
                        HelperResult::Ok,
                        "CONTEXT_ABSENT",
                        Some(helper_response::Outcome::DestroyedContext(
                            DestroyedContext { existed: false },
                        )),
                    ),
                    None,
                ));
            };
            if !matches_handle(&context.handle, &value.context_handle) {
                return Some(execution(
                    response(
                        request,
                        HelperResult::InvalidRequest,
                        "CONTEXT_HANDLE_INVALID",
                        None,
                    ),
                    None,
                ));
            }
            let generation = context.generation;
            let prior_phase = context.phase;
            let lineage = context_backend_lineage(context_id, context);
            let Some(token) = begin_operation(
                &mut state,
                request_id,
                digest,
                context_id,
                generation,
                Some(prior_phase),
                OperationKind::Destroy,
                lineage,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            let context = state
                .contexts
                .get_mut(&context_id)
                .expect("validated context");
            context.phase = ContextPhase::Quarantined;
            state.cleanup_pending.insert((context_id, generation));
            token
        };
        let cleanup = self.destroy_generation(token, request, sender).await;
        if cleanup.response_sent {
            return None;
        }
        Some(execution(
            if cleanup.confirmed {
                response(
                    request,
                    HelperResult::Ok,
                    "CONTEXT_DESTROYED",
                    Some(helper_response::Outcome::DestroyedContext(
                        DestroyedContext { existed: true },
                    )),
                )
            } else {
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "CLEANUP_INCOMPLETE",
                    None,
                )
            },
            None,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keep context and handleless Pending cleanup settlement in one ownership boundary"
    )]
    async fn cleanup_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let identities = {
            let state = self.inner.state.lock().await;
            state
                .contexts
                .iter()
                .map(|(context_id, context)| (*context_id, context.generation))
                .collect::<Vec<_>>()
        };
        let mut complete = true;
        let mut response_sent = false;
        for (context_id, generation) in identities {
            let token = {
                let mut state = self.inner.state.lock().await;
                let Some(context) = state.contexts.get(&context_id) else {
                    continue;
                };
                if context.generation != generation {
                    complete = false;
                    continue;
                }
                let prior_phase = context.phase;
                let lineage = context_backend_lineage(context_id, context);
                let Some(token) = begin_operation(
                    &mut state,
                    request_id,
                    digest,
                    context_id,
                    generation,
                    Some(prior_phase),
                    OperationKind::Cleanup,
                    lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    return Some(execution(
                        response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                        None,
                    ));
                };
                state
                    .contexts
                    .get_mut(&context_id)
                    .expect("validated context")
                    .phase = ContextPhase::Quarantined;
                state.cleanup_pending.insert((context_id, generation));
                token
            };
            let outcome = self.destroy_generation(token, request, sender).await;
            complete &= outcome.confirmed;
            response_sent |= outcome.response_sent;
        }
        let orphan_pending = {
            let state = self.inner.state.lock().await;
            orphan_pending_identities(&state)
        };
        for (context_id, generation) in orphan_pending {
            let token = {
                let mut state = self.inner.state.lock().await;
                let exact = state
                    .prepare_reconciliations
                    .get(&context_id)
                    .is_some_and(|record| {
                        record.backend_generation == generation
                            && record.phase == PrepareReconciliationPhase::Pending
                    })
                    && !state.contexts.contains_key(&context_id)
                    && state.in_flight.is_none();
                if !exact {
                    complete = false;
                    continue;
                }
                let lineage = state
                    .prepare_reconciliations
                    .get(&context_id)
                    .map(|record| reconciliation_backend_lineage(context_id, record))
                    .expect("validated Pending reconciliation");
                let Some(token) = begin_operation(
                    &mut state,
                    request_id,
                    digest,
                    context_id,
                    generation,
                    None,
                    OperationKind::Cleanup,
                    lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    return Some(execution(
                        response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                        None,
                    ));
                };
                state.cleanup_pending.insert((context_id, generation));
                token
            };
            let outcome = self.destroy_generation(token, request, sender).await;
            complete &= outcome.confirmed;
            response_sent |= outcome.response_sent;
        }
        if response_sent {
            return None;
        }
        let empty = {
            let state = self.inner.state.lock().await;
            cleanup_state_complete(&state)
        };
        Some(execution(
            if complete && empty {
                response(
                    request,
                    HelperResult::Ok,
                    "CLEANUP_COMPLETE",
                    Some(helper_response::Outcome::Empty(Empty {})),
                )
            } else {
                response(
                    request,
                    HelperResult::CleanupIncomplete,
                    "CLEANUP_INCOMPLETE",
                    None,
                )
            },
            None,
        ))
    }

    async fn reap_expired(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> ReapOutcome {
        loop {
            let token = {
                let now = self.inner.clock.now_unix();
                let mut state = self.inner.state.lock().await;
                let Some(target) = expired_reap_target(&state, now, false) else {
                    return ReapOutcome::Complete;
                };
                let Some(token) = begin_operation(
                    &mut state,
                    request_id,
                    digest,
                    target.context_id,
                    target.generation,
                    target.prior_phase,
                    OperationKind::Reap,
                    target.lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    return ReapOutcome::Failure(Box::new(execution(
                        response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                        None,
                    )));
                };
                if let Some(context) = state.contexts.get_mut(&target.context_id) {
                    context.phase = ContextPhase::Quarantined;
                }
                state
                    .cleanup_pending
                    .insert((target.context_id, target.generation));
                token
            };
            let cleanup = self.destroy_generation(token, request, sender).await;
            if cleanup.response_sent {
                return ReapOutcome::ResponseSent;
            }
            if !cleanup.confirmed {
                return ReapOutcome::Failure(Box::new(execution(
                    response(
                        request,
                        HelperResult::CleanupIncomplete,
                        "EXPIRED_CLEANUP_INCOMPLETE",
                        None,
                    ),
                    None,
                )));
            }
        }
    }

    async fn destroy_generation(
        &self,
        token: OperationOwner,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> CleanupOutcome {
        self.destroy_generation_inner(token, Some((request, sender)))
            .await
    }

    async fn destroy_generation_quiet(&self, token: OperationOwner) -> bool {
        self.destroy_generation_inner(token, None).await.confirmed
    }

    async fn destroy_generation_inner(
        &self,
        token: OperationOwner,
        ambiguity: Option<(
            &HelperRequest,
            &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
        )>,
    ) -> CleanupOutcome {
        let operation = token.token();
        let safe = {
            let state = self.inner.state.lock().await;
            state.in_flight == Some(operation)
                && state
                    .cleanup_pending
                    .contains(&(operation.context_id, operation.generation))
                && state.contexts.get(&operation.context_id).map_or_else(
                    || {
                        state
                            .prepare_reconciliations
                            .get(&operation.context_id)
                            .is_some_and(|record| {
                                record.backend_generation == operation.generation
                                    && reconciliation_backend_lineage(operation.context_id, record)
                                        == token.lineage()
                            })
                    },
                    |context| {
                        context.generation == operation.generation
                            && context.phase == ContextPhase::Quarantined
                            && context_backend_lineage(operation.context_id, context)
                                == token.lineage()
                    },
                )
        };
        if !safe {
            self.finish_cleanup(token, false).await;
            return CleanupOutcome {
                confirmed: false,
                response_sent: false,
            };
        }
        let backend = Arc::clone(&self.inner.backend);
        let context_id = operation.context_id;
        let binding = BackendBinding::for_owner(
            &token,
            BackendPhase::Quarantined,
            BackendAction::Destroy,
            token.call_deadline(),
        );
        let backend_value = BackendRequest::new(
            binding,
            BackendDestroy {
                context_id,
                backend_generation: token.lineage().backend_generation,
            },
        );
        match self
            .call_backend(binding.call_deadline, move || {
                backend.destroy(backend_value)
            })
            .await
        {
            BackendCall::Complete(completion) => {
                let confirmed = completion.binding == binding && completion.result.is_ok();
                self.finish_cleanup(token, confirmed).await;
                CleanupOutcome {
                    confirmed,
                    response_sent: false,
                }
            }
            BackendCall::Ambiguous => {
                self.finish_cleanup(token, false).await;
                CleanupOutcome {
                    confirmed: false,
                    response_sent: false,
                }
            }
            BackendCall::TimedOut(task) => {
                let response_sent = if let Some((request, sender)) = ambiguity {
                    self.send_ambiguous(request, sender).await;
                    true
                } else {
                    false
                };
                let confirmed = matches!(
                    task.await,
                    Ok(BackendCompletion {
                        binding: completed_binding,
                        result: Ok(ConfirmedAbsent),
                    }) if completed_binding == binding
                );
                self.finish_cleanup(token, confirmed).await;
                CleanupOutcome {
                    confirmed,
                    response_sent,
                }
            }
        }
    }

    async fn clear_operation(&self, owner: OperationOwner) {
        let token = owner.token();
        let mut state = self.inner.state.lock().await;
        let exact_lineage = state.contexts.get(&token.context_id).map_or_else(
            || {
                state
                    .prepare_reconciliations
                    .get(&token.context_id)
                    .is_some_and(|record| {
                        reconciliation_backend_lineage(token.context_id, record) == owner.lineage()
                    })
            },
            |context| context_backend_lineage(token.context_id, context) == owner.lineage(),
        );
        if exact_lineage && state.in_flight == Some(token) {
            state.in_flight = None;
            state
                .cleanup_pending
                .remove(&(token.context_id, token.generation));
        }
        drop(state);
        let _ = owner.settle();
    }

    /// Stop and clean every context during authenticated process shutdown.
    ///
    /// The owned task preserves cleanup if its caller is cancelled. Backend destroy itself must
    /// enforce the installed binding's absolute hard deadline; the functional-alpha backend does.
    pub async fn shutdown_cleanup(&self) -> bool {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let engine = self.clone();
        tokio::spawn(async move {
            let complete = engine.shutdown_serial().await;
            let _ = sender.send(complete);
        });
        receiver.await.unwrap_or(false)
    }

    /// Reap every expired or already quarantined generation without relying on another agent
    /// request.
    ///
    /// The cleanup task owns the operation after this future is cancelled. A failed proof leaves
    /// the exact lineage quarantined for the next periodic retry or shutdown cleanup.
    pub(crate) async fn reap_expired_cleanup(&self) -> bool {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let engine = self.clone();
        tokio::spawn(async move {
            let complete = engine.reap_expired_serial().await;
            let _ = sender.send(complete);
        });
        receiver.await.unwrap_or(false)
    }

    async fn reap_expired_serial(&self) -> bool {
        let _operation_guard = self.inner.operation_gate.lock().await;
        loop {
            let token = {
                let now = self.inner.clock.now_unix();
                let mut state = self.inner.state.lock().await;
                let Some(target) = expired_reap_target(&state, now, true) else {
                    return true;
                };
                let (request_id, digest) = maintenance_reap_correlation(target.lineage);
                let Some(token) = begin_operation(
                    &mut state,
                    request_id,
                    digest,
                    target.context_id,
                    target.generation,
                    target.prior_phase,
                    OperationKind::Reap,
                    target.lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    return false;
                };
                if let Some(context) = state.contexts.get_mut(&target.context_id) {
                    context.phase = ContextPhase::Quarantined;
                }
                state
                    .cleanup_pending
                    .insert((target.context_id, target.generation));
                token
            };
            if !self.destroy_generation_quiet(token).await {
                return false;
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Both exact cleanup waves must settle before one runtime shutdown.
    async fn shutdown_serial(&self) -> bool {
        let _operation_guard = self.inner.operation_gate.lock().await;
        let identities = {
            let state = self.inner.state.lock().await;
            state
                .contexts
                .iter()
                .map(|(context_id, context)| (*context_id, context.generation, context.phase))
                .collect::<Vec<_>>()
        };
        let mut complete = true;
        for (context_id, generation, prior_phase) in identities {
            let token = {
                let mut state = self.inner.state.lock().await;
                let exact = state
                    .contexts
                    .get(&context_id)
                    .is_some_and(|context| context.generation == generation);
                if !exact {
                    complete = false;
                    continue;
                }
                let lineage = state
                    .contexts
                    .get(&context_id)
                    .map(|context| context_backend_lineage(context_id, context))
                    .expect("validated shutdown context");
                let Some(token) = begin_operation(
                    &mut state,
                    [0; 16],
                    [0; 32],
                    context_id,
                    generation,
                    Some(prior_phase),
                    OperationKind::Shutdown,
                    lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    complete = false;
                    continue;
                };
                state
                    .contexts
                    .get_mut(&context_id)
                    .expect("validated context")
                    .phase = ContextPhase::Quarantined;
                state.cleanup_pending.insert((context_id, generation));
                token
            };
            let backend = Arc::clone(&self.inner.backend);
            let binding = BackendBinding::for_owner(
                &token,
                BackendPhase::Quarantined,
                BackendAction::Destroy,
                token.call_deadline(),
            );
            let backend_value = BackendRequest::new(
                binding,
                BackendDestroy {
                    context_id,
                    backend_generation: token.lineage().backend_generation,
                },
            );
            let call = self
                .call_backend(binding.call_deadline, move || {
                    backend.destroy(backend_value)
                })
                .await;
            let confirmed = match call {
                BackendCall::Complete(completion) => {
                    completion.binding == binding && completion.result.is_ok()
                }
                BackendCall::Ambiguous => false,
                BackendCall::TimedOut(task) => matches!(
                    task.await,
                    Ok(BackendCompletion {
                        binding: completed_binding,
                        result: Ok(ConfirmedAbsent),
                    }) if completed_binding == binding
                ),
            };
            self.finish_cleanup(token, confirmed).await;
            complete &= confirmed;
        }
        let orphan_pending = {
            let state = self.inner.state.lock().await;
            orphan_pending_identities(&state)
        };
        for (context_id, generation) in orphan_pending {
            let token = {
                let mut state = self.inner.state.lock().await;
                let exact = state
                    .prepare_reconciliations
                    .get(&context_id)
                    .is_some_and(|record| {
                        record.backend_generation == generation
                            && record.phase == PrepareReconciliationPhase::Pending
                    })
                    && !state.contexts.contains_key(&context_id)
                    && state.in_flight.is_none();
                if !exact {
                    complete = false;
                    continue;
                }
                let lineage = state
                    .prepare_reconciliations
                    .get(&context_id)
                    .map(|record| reconciliation_backend_lineage(context_id, record))
                    .expect("validated shutdown Pending reconciliation");
                let Some(token) = begin_operation(
                    &mut state,
                    [0; 16],
                    [0; 32],
                    context_id,
                    generation,
                    None,
                    OperationKind::Shutdown,
                    lineage,
                    Instant::now() + self.inner.backend_timeout,
                ) else {
                    complete = false;
                    continue;
                };
                state.cleanup_pending.insert((context_id, generation));
                token
            };
            let backend = Arc::clone(&self.inner.backend);
            let binding = BackendBinding::for_owner(
                &token,
                BackendPhase::Quarantined,
                BackendAction::Destroy,
                token.call_deadline(),
            );
            let backend_value = BackendRequest::new(
                binding,
                BackendDestroy {
                    context_id,
                    backend_generation: token.lineage().backend_generation,
                },
            );
            let call = self
                .call_backend(binding.call_deadline, move || {
                    backend.destroy(backend_value)
                })
                .await;
            let confirmed = match call {
                BackendCall::Complete(completion) => {
                    completion.binding == binding && completion.result.is_ok()
                }
                BackendCall::Ambiguous => false,
                BackendCall::TimedOut(task) => matches!(
                    task.await,
                    Ok(BackendCompletion {
                        binding: completed_binding,
                        result: Ok(ConfirmedAbsent),
                    }) if completed_binding == binding
                ),
            };
            self.finish_cleanup(token, confirmed).await;
            complete &= confirmed;
        }
        let engine_cleanup_complete = {
            let state = self.inner.state.lock().await;
            cleanup_state_complete(&state)
        };
        if !complete || !engine_cleanup_complete {
            return false;
        }
        let backend = Arc::clone(&self.inner.backend);
        let shutdown_binding = BackendRuntimeBinding {
            helper_runtime_id: self.inner.runtime_id,
            action: BackendRuntimeAction::Shutdown,
            call_deadline: Instant::now() + self.inner.backend_timeout,
        };
        let shutdown_request = BackendRuntimeRequest::new(shutdown_binding);
        let shutdown = self
            .call_backend(shutdown_binding.call_deadline, move || {
                backend.shutdown(shutdown_request)
            })
            .await;
        let backend_stopped = match shutdown {
            BackendCall::Complete(completion) => {
                completion.binding == shutdown_binding && completion.result.is_ok()
            }
            BackendCall::Ambiguous => false,
            BackendCall::TimedOut(task) => matches!(
                task.await,
                Ok(BackendRuntimeCompletion {
                    binding,
                    result: Ok(()),
                }) if binding == shutdown_binding
            ),
        };
        let state = self.inner.state.lock().await;
        backend_stopped && cleanup_state_complete(&state)
    }

    fn unique_handle(
        &self,
        state: &EngineState,
        reserved: &BTreeSet<[u8; HELPER_HANDLE_BYTES]>,
    ) -> Option<[u8; HELPER_HANDLE_BYTES]> {
        for _ in 0..16 {
            let mut handle = [0_u8; HELPER_HANDLE_BYTES];
            self.inner.handles.fill(&mut handle);
            let unused = handle.iter().any(|byte| *byte != 0)
                && !reserved.contains(&handle)
                && state.contexts.values().all(|context| {
                    context.handle != handle
                        && context.leases.values().all(|lease| lease.handle != handle)
                });
            if unused {
                return Some(handle);
            }
        }
        None
    }

    /// UID reserved for worker-side transport policy.
    #[must_use]
    pub fn trusted_agent_uid(&self) -> u32 {
        self.inner.trusted_agent_uid
    }
}

fn expired_reap_target(
    state: &EngineState,
    now: u64,
    retry_quarantined: bool,
) -> Option<ReapTarget> {
    let context_target = |context_id: &[u8; 16], context: &ContextRecord| ReapTarget {
        context_id: *context_id,
        generation: context.generation,
        prior_phase: Some(context.phase),
        lineage: context_backend_lineage(*context_id, context),
    };
    retry_quarantined
        .then(|| {
            state.contexts.iter().find_map(|(context_id, context)| {
                (context.phase == ContextPhase::Quarantined
                    && state
                        .cleanup_pending
                        .contains(&(*context_id, context.generation)))
                .then_some(context_target(context_id, context))
            })
        })
        .flatten()
        .or_else(|| {
            state.contexts.iter().find_map(|(context_id, context)| {
                let setup_expired =
                    context.phase == ContextPhase::Prepared && now >= context.setup_expires_at_unix;
                (context.phase != ContextPhase::Quarantined
                    && (setup_expired || now >= context.hard_expires_at_unix))
                    .then_some(context_target(context_id, context))
            })
        })
        .or_else(|| {
            state
                .prepare_reconciliations
                .iter()
                .find_map(|(context_id, record)| {
                    (record.phase == PrepareReconciliationPhase::Pending
                        && !state.contexts.contains_key(context_id)
                        && (now >= record.setup_expires_at_unix
                            || (retry_quarantined
                                && state
                                    .cleanup_pending
                                    .contains(&(*context_id, record.backend_generation)))))
                    .then_some(ReapTarget {
                        context_id: *context_id,
                        generation: record.backend_generation,
                        prior_phase: None,
                        lineage: reconciliation_backend_lineage(*context_id, record),
                    })
                })
        })
}

fn maintenance_reap_correlation(lineage: BackendLineage) -> ([u8; 16], [u8; 32]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MAINTENANCE_REAP_DOMAIN);
    hasher.update(&lineage.helper_runtime_id);
    hasher.update(&lineage.context_id);
    hasher.update(&lineage.backend_generation.to_be_bytes());
    hasher.update(&lineage.prepare_request_id);
    hasher.update(&lineage.prepare_operation_digest);
    hasher.update(&lineage.setup_expires_at_unix.to_be_bytes());
    hasher.update(&lineage.hard_expires_at_unix.to_be_bytes());
    let mut digest = *hasher.finalize().as_bytes();
    if digest.iter().all(|byte| *byte == 0) {
        digest[31] = 1;
    }
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id.iter().all(|byte| *byte == 0) {
        request_id[15] = 1;
    }
    (request_id, digest)
}

fn random_runtime_id() -> [u8; 32] {
    loop {
        let mut runtime_id = [0_u8; 32];
        OsRng.fill_bytes(&mut runtime_id);
        if runtime_id.iter().any(|byte| *byte != 0) {
            return runtime_id;
        }
    }
}

fn reserve_generation(state: &mut EngineState) -> Option<u64> {
    let next = state.next_generation.checked_add(1)?;
    state.next_generation = next;
    Some(next)
}

const fn context_backend_lineage(context_id: [u8; 16], context: &ContextRecord) -> BackendLineage {
    BackendLineage {
        helper_runtime_id: context.helper_runtime_id,
        context_id,
        backend_generation: context.backend_generation,
        prepare_request_id: context.prepare_request_id,
        prepare_operation_digest: context.prepare_operation_digest,
        setup_expires_at_unix: context.setup_expires_at_unix,
        hard_expires_at_unix: context.hard_expires_at_unix,
    }
}

const fn reconciliation_backend_lineage(
    context_id: [u8; 16],
    record: &PrepareReconciliationRecord,
) -> BackendLineage {
    BackendLineage {
        helper_runtime_id: record.helper_runtime_id,
        context_id,
        backend_generation: record.backend_generation,
        prepare_request_id: record.prepare_request_id,
        prepare_operation_digest: record.prepare_operation_digest,
        setup_expires_at_unix: record.setup_expires_at_unix,
        hard_expires_at_unix: record.hard_expires_at_unix,
    }
}

#[allow(clippy::too_many_arguments)] // Constructs one fully bound affine owner at the PLAN boundary.
fn begin_operation(
    state: &mut EngineState,
    request_id: [u8; 16],
    digest: [u8; 32],
    context_id: [u8; 16],
    generation: u64,
    prior_phase: Option<ContextPhase>,
    kind: OperationKind,
    lineage: BackendLineage,
    call_deadline: Instant,
) -> Option<OperationOwner> {
    if state.in_flight.is_some() {
        return None;
    }
    let next_operation = state.next_operation.checked_add(1)?;
    state.next_operation = next_operation;
    let token = OperationToken {
        sequence: next_operation,
        request_id,
        digest,
        context_id,
        generation,
        prior_phase,
        kind,
    };
    state.in_flight = Some(token);
    Some(OperationOwner {
        token,
        lineage,
        call_deadline,
        armed: true,
    })
}

fn prepared_matches(request: &PrepareLeaseBatch, prepared: &[PreparedKernelLease]) -> bool {
    if request.leases.len() != prepared.len() {
        return false;
    }
    let mut public_keys = BTreeSet::new();
    let mut public_endpoints = BTreeSet::new();
    for (requested, lease) in request.leases.iter().zip(prepared) {
        if lease.public_key.iter().all(|byte| *byte == 0)
            || lease.evidence != UnderlayEvidence::DirectAssigned
            || (requested.path_id, requested.role) != (lease.path_id, lease.role)
            || !public_keys.insert(lease.public_key)
            || !public_endpoints.insert((
                lease.public_endpoint.address.clone(),
                lease.public_endpoint.port,
            ))
        {
            return false;
        }
    }
    true
}

fn activation_matches(context: &ContextRecord, leases: &[LeaseActivation]) -> bool {
    if context.leases.len() != leases.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for activation in leases {
        let key = (activation.path_id, activation.role);
        let Some(prepared) = context.leases.get(&key) else {
            return false;
        };
        if !matches_handle(&prepared.handle, &activation.lease_handle)
            || activation.peer_public_key.as_slice() == prepared.public_key
            || activation
                .peer_endpoint
                .as_ref()
                .is_some_and(|endpoint| *endpoint == prepared.public_endpoint)
            || !seen.insert(key)
        {
            return false;
        }
    }
    seen.len() == context.leases.len()
}

fn commit_matches(context: &ContextRecord, leases: &[volparossa_routing::LeaseCommit]) -> bool {
    if context.leases.len() != leases.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for commit in leases {
        let key = (commit.path_id, commit.role);
        let Some(prepared) = context.leases.get(&key) else {
            return false;
        };
        if !matches_handle(&prepared.handle, &commit.lease_handle) || !seen.insert(key) {
            return false;
        }
    }
    seen.len() == context.leases.len()
}

fn counters_match(context: &ContextRecord, counters: &[KernelCounters]) -> bool {
    if context.leases.len() != counters.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    counters.iter().all(|counter| {
        context
            .leases
            .contains_key(&(counter.path_id, counter.role))
            && seen.insert((counter.path_id, counter.role))
    })
}

fn proofs_commit(context: &ContextRecord, proofs: &[KernelCounters], activated_at: u64) -> bool {
    counters_match(context, proofs)
        && proofs.iter().all(|proof| {
            let Some(baseline) = context
                .leases
                .get(&(proof.path_id, proof.role))
                .and_then(|lease| lease.baseline)
            else {
                return false;
            };
            proof.latest_handshake_unix >= activated_at
                && proof.latest_handshake_unix >= baseline.latest_handshake_unix
                && proof.received_bytes > baseline.received_bytes
                && proof.transmitted_bytes > baseline.transmitted_bytes
        })
}

fn matches_handle(expected: &[u8; HELPER_HANDLE_BYTES], actual: &[u8]) -> bool {
    actual.len() == HELPER_HANDLE_BYTES && expected.ct_eq(actual).unwrap_u8() == 1
}

fn fixed<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    value.try_into().ok()
}

fn reconciliation_record_matches(
    record: &PrepareReconciliationRecord,
    helper_runtime_id: [u8; 32],
    prepare_request_id: [u8; 16],
    prepare_operation_digest: [u8; 32],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
) -> bool {
    record
        .helper_runtime_id
        .ct_eq(&helper_runtime_id)
        .unwrap_u8()
        == 1
        && record
            .prepare_request_id
            .ct_eq(&prepare_request_id)
            .unwrap_u8()
            == 1
        && record
            .prepare_operation_digest
            .ct_eq(&prepare_operation_digest)
            .unwrap_u8()
            == 1
        && record.setup_expires_at_unix == setup_expires_at_unix
        && record.hard_expires_at_unix == hard_expires_at_unix
}

fn bind_reconciliation_request(
    state: &mut EngineState,
    request_id: [u8; 16],
    digest: [u8; 32],
    context_id: [u8; 16],
    generation: u64,
) -> Result<(), ReconciliationRequestAdmissionError> {
    let bound_request_id = state
        .prepare_reconciliations
        .get(&context_id)
        .filter(|record| record.backend_generation == generation)
        .ok_or(ReconciliationRequestAdmissionError::EvidenceUnavailable)?
        .reconciliation_request_id;

    if let Some(bound_request_id) = bound_request_id {
        if bound_request_id.ct_eq(&request_id).unwrap_u8() != 1 {
            return Err(ReconciliationRequestAdmissionError::Conflict);
        }
        let binding = state
            .reconciliation_request_ids
            .get(&request_id)
            .ok_or(ReconciliationRequestAdmissionError::EvidenceUnavailable)?;
        if binding.digest.ct_eq(&digest).unwrap_u8() != 1
            || binding.context_id.ct_eq(&context_id).unwrap_u8() != 1
            || binding.generation != generation
        {
            return Err(ReconciliationRequestAdmissionError::Conflict);
        }
        return Ok(());
    }

    if state.reconciliation_request_ids.contains_key(&request_id) {
        return Err(ReconciliationRequestAdmissionError::Conflict);
    }
    if state.reconciliation_request_ids.len() >= MAX_RECONCILIATION_REQUEST_IDS {
        return Err(ReconciliationRequestAdmissionError::Capacity);
    }
    state.reconciliation_request_ids.insert(
        request_id,
        ReconciliationRequestRecord {
            digest,
            context_id,
            generation,
        },
    );
    state
        .prepare_reconciliations
        .get_mut(&context_id)
        .expect("validated reconciliation lineage")
        .reconciliation_request_id = Some(request_id);
    Ok(())
}

fn reconciliation_request_admission_error(
    request: &HelperRequest,
    error: ReconciliationRequestAdmissionError,
) -> HelperExecution {
    let (result, diagnostic) = match error {
        ReconciliationRequestAdmissionError::Conflict => {
            (HelperResult::InvalidRequest, "REQUEST_ID_CONFLICT")
        }
        ReconciliationRequestAdmissionError::Capacity => {
            (HelperResult::Capacity, "RECONCILIATION_REQUEST_CAPACITY")
        }
        ReconciliationRequestAdmissionError::EvidenceUnavailable => (
            HelperResult::Unavailable,
            "RECONCILIATION_EVIDENCE_UNAVAILABLE",
        ),
    };
    execution(response(request, result, diagnostic, None), None)
}

fn execution(response: HelperResponse, descriptor: Option<Arc<OwnedFd>>) -> HelperExecution {
    HelperExecution {
        response,
        descriptor,
    }
}

fn prune_cache(state: &mut EngineState, now: u64) {
    state
        .cache
        .retain(|_, cached| cached.expires_at_unix >= now);
    state
        .cache_order
        .retain(|request_id| state.cache.contains_key(request_id));
}

fn prune_prepare_reconciliations(state: &mut EngineState, now: u64) {
    let expired_intents = state
        .prepare_reconciliations
        .iter()
        .filter_map(|(context_id, record)| {
            (record.phase == PrepareReconciliationPhase::Intent
                && now >= record.setup_expires_at_unix
                && !state.contexts.contains_key(context_id)
                && !state
                    .cleanup_pending
                    .iter()
                    .any(|(pending_id, _)| pending_id == context_id))
            .then_some(*context_id)
        })
        .collect::<Vec<_>>();
    for context_id in expired_intents {
        state
            .prepare_reconciliations
            .get_mut(&context_id)
            .expect("selected Prepare intent")
            .phase = PrepareReconciliationPhase::Absent;
        purge_context_cache(state, context_id);
    }

    // `Absent` is proof that a particular Prepare identity has no surviving backend context.
    // Keep that proof for this helper runtime: without an authenticated receipt ACK, pruning it
    // could turn a lost reconciliation response into permanent uncertainty. The fixed ledger cap
    // makes retention bounded and new intent admission fails closed when it is exhausted.
}

fn orphan_pending_identities(state: &EngineState) -> Vec<([u8; 16], u64)> {
    state
        .prepare_reconciliations
        .iter()
        .filter_map(|(context_id, record)| {
            (record.phase == PrepareReconciliationPhase::Pending
                && !state.contexts.contains_key(context_id))
            .then_some((*context_id, record.backend_generation))
        })
        .collect()
}

fn cleanup_state_complete(state: &EngineState) -> bool {
    state.contexts.is_empty()
        && state.cleanup_pending.is_empty()
        && state.in_flight.is_none()
        && state.prepare_reconciliations.values().all(|record| {
            matches!(
                record.phase,
                PrepareReconciliationPhase::Intent | PrepareReconciliationPhase::Absent
            )
        })
}

fn purge_context_cache(state: &mut EngineState, context_id: [u8; 16]) {
    state
        .cache
        .retain(|_, cached| cached.context_id != Some(context_id));
    state
        .cache_order
        .retain(|request_id| state.cache.contains_key(request_id));
}

fn insert_cache(state: &mut EngineState, request_id: [u8; 16], value: CachedResponse) {
    if !state.cache.contains_key(&request_id) {
        while state.cache.len() >= MAX_CACHED_REQUESTS {
            let Some(oldest) = state.cache_order.pop_front() else {
                break;
            };
            state.cache.remove(&oldest);
        }
        state.cache_order.push_back(request_id);
    }
    state.cache.insert(request_id, value);
}

fn request_context_id(request: &HelperRequest) -> Option<[u8; 16]> {
    let value = match request.operation.as_ref()? {
        helper_request::Operation::PrepareLeaseBatch(value) => &value.route_context_id,
        helper_request::Operation::ActivateLeaseBatch(value) => &value.route_context_id,
        helper_request::Operation::CommitLeaseBatch(value) => &value.route_context_id,
        helper_request::Operation::DestroyContext(value) => &value.route_context_id,
        helper_request::Operation::AddMptcpEndpoint(value) => &value.route_context_id,
        helper_request::Operation::RemoveMptcpEndpoint(value) => &value.route_context_id,
        helper_request::Operation::AcquireTransportSocket(value) => &value.route_context_id,
        helper_request::Operation::ReconcileExpiredPrepare(value) => &value.route_context_id,
        helper_request::Operation::BindHelperRuntime(value) => {
            &value.prepare_intent.as_ref()?.route_context_id
        }
        helper_request::Operation::PrepareClientIngress(_)
        | helper_request::Operation::AcquireIngressSocket(_)
        | helper_request::Operation::ActivateClientIngress(_)
        | helper_request::Operation::DestroyClientIngress(_)
        | helper_request::Operation::CleanupOwned(_) => return None,
    };
    fixed(value)
}

fn helper_runtime_execution(request: &HelperRequest, runtime_id: [u8; 32]) -> HelperExecution {
    execution(
        response(
            request,
            HelperResult::Ok,
            "HELPER_RUNTIME",
            Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: runtime_id.to_vec(),
            })),
        ),
        None,
    )
}

fn reconciled_prepare_execution(
    request: &HelperRequest,
    value: &ReconcileExpiredPrepare,
) -> HelperExecution {
    execution(
        response(
            request,
            HelperResult::Ok,
            "EXPIRED_PREPARE_ABSENT",
            Some(helper_response::Outcome::ReconciledExpiredPrepare(
                ReconciledExpiredPrepare {
                    helper_runtime_id: value.helper_runtime_id.clone(),
                    route_context_id: value.route_context_id.clone(),
                    prepare_request_id: value.prepare_request_id.clone(),
                    prepare_operation_digest: value.prepare_operation_digest.clone(),
                    setup_expires_at_unix: value.setup_expires_at_unix,
                    hard_expires_at_unix: value.hard_expires_at_unix,
                },
            )),
        ),
        None,
    )
}

const fn phase_result(phase: ContextPhase) -> HelperResult {
    if matches!(phase, ContextPhase::Quarantined) {
        HelperResult::CleanupIncomplete
    } else {
        HelperResult::AlreadyExists
    }
}

fn backend_response(
    request: &HelperRequest,
    error: BackendError,
    diagnostic: &'static str,
) -> HelperResponse {
    let result = match error {
        BackendError::Unavailable => HelperResult::Unavailable,
        BackendError::Capacity => HelperResult::Capacity,
        BackendError::Invalid => HelperResult::InvalidRequest,
        BackendError::Kernel => HelperResult::Kernel,
        BackendError::CleanupIncomplete => HelperResult::CleanupIncomplete,
    };
    response(request, result, diagnostic, None)
}

fn invalid_response(request: &HelperRequest) -> HelperResponse {
    response(
        request,
        HelperResult::InvalidRequest,
        "INVALID_REQUEST",
        None,
    )
}

fn response(
    request: &HelperRequest,
    result: HelperResult,
    diagnostic_code: &'static str,
    outcome: Option<helper_response::Outcome>,
) -> HelperResponse {
    HelperResponse {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: fixed::<16>(&request.request_id).map_or_else(|| vec![1; 16], |id| id.to_vec()),
        result: result as i32,
        diagnostic_code: diagnostic_code.to_owned(),
        operation_digest: operation_digest(request).unwrap_or([0; 32]).to_vec(),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::{
        io::Read,
        os::unix::{net::UnixStream as StdUnixStream, process::ExitStatusExt},
        process::Command,
        time::Duration,
    };

    use volparossa_routing::{
        CommitLeaseBatch, ContextRole, LeaseCommit, LeasePlan, PrepareIntent, PreparedLeaseBatch,
        WireguardRole,
    };

    use super::*;

    struct FixedClock(AtomicU64);

    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    struct PanicClock;

    impl Clock for PanicClock {
        fn now_unix(&self) -> u64 {
            panic!("test clock panic");
        }
    }

    struct FixedHandles(AtomicU64);

    impl HandleSource for FixedHandles {
        fn fill(&self, output: &mut [u8]) {
            let value = self.0.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            output.fill(0);
            output[..8].copy_from_slice(&value.to_be_bytes());
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        proof_increment: AtomicU64,
        destroyed: StdMutex<Vec<[u8; 16]>>,
        transport_calls: AtomicU64,
        transport_peers: StdMutex<Vec<StdUnixStream>>,
        block_prepare: AtomicBool,
        prepare_entered: AtomicBool,
        prepare_released: AtomicBool,
        prepare_release: tokio::sync::Notify,
        block_destroy: AtomicBool,
        destroy_entered: AtomicBool,
        destroy_released: AtomicBool,
        destroy_release: tokio::sync::Notify,
        block_acquire: AtomicBool,
        acquire_entered: AtomicBool,
        acquire_released: AtomicBool,
        acquire_release: tokio::sync::Notify,
        invalid_prepare: AtomicBool,
        fail_destroy: AtomicBool,
        fail_prepare_capacity: AtomicBool,
        fail_probe_cleanup: AtomicBool,
        fail_acquire_cleanup: AtomicBool,
        panic_prepare_factory: AtomicBool,
        panic_prepare_poll: AtomicBool,
        substitute_prepare_generation: AtomicBool,
        substitute_prepare_deadline: AtomicBool,
        substitute_acquire_generation: AtomicBool,
        prepare_bindings: StdMutex<Vec<BackendBinding>>,
        destroy_calls: StdMutex<Vec<(BackendBinding, BackendDestroy)>>,
        runtime_bindings: StdMutex<Vec<BackendRuntimeBinding>>,
    }

    impl FakeBackend {
        fn release_prepare(&self) {
            self.prepare_released.store(true, Ordering::Release);
            self.prepare_release.notify_one();
        }

        fn release_destroy(&self) {
            self.destroy_released.store(true, Ordering::Release);
            self.destroy_release.notify_one();
        }

        fn release_acquire(&self) {
            self.acquire_released.store(true, Ordering::Release);
            self.acquire_release.notify_one();
        }
    }

    impl AsyncLeaseBackend for FakeBackend {
        fn prepare(
            self: Arc<Self>,
            request: BackendRequest<PrepareLeaseBatch>,
        ) -> BackendFuture<BackendCompletion<Vec<PreparedKernelLease>>> {
            assert!(
                !self.panic_prepare_factory.load(Ordering::Acquire),
                "injected backend future factory panic"
            );
            let (completion, request) = request.into_parts();
            self.prepare_bindings
                .lock()
                .expect("prepare bindings")
                .push(completion.binding());
            Box::pin(async move {
                self.prepare_entered.store(true, Ordering::Release);
                assert!(
                    !self.panic_prepare_poll.load(Ordering::Acquire),
                    "injected backend poll panic"
                );
                loop {
                    let notified = self.prepare_release.notified();
                    if !self.block_prepare.load(Ordering::Acquire)
                        || self.prepare_released.load(Ordering::Acquire)
                    {
                        break;
                    }
                    notified.await;
                }
                let invalid = self.invalid_prepare.load(Ordering::Acquire);
                let result = request
                    .leases
                    .iter()
                    .map(|lease| PreparedKernelLease {
                        path_id: lease.path_id,
                        role: lease.role,
                        public_key: if invalid {
                            [0; 32]
                        } else {
                            [u8::try_from(lease.path_id).unwrap_or(1); 32]
                        },
                        public_endpoint: PublicUdpEndpoint {
                            address: vec![8, 8, 8, 8],
                            port: 50_000 + lease.path_id,
                        },
                        evidence: UnderlayEvidence::DirectAssigned,
                    })
                    .collect();
                let outcome = if self.fail_prepare_capacity.load(Ordering::Acquire) {
                    Err(BackendError::Capacity)
                } else {
                    Ok(result)
                };
                let mut completion = completion.complete(outcome);
                if self.substitute_prepare_generation.load(Ordering::Acquire) {
                    completion.binding.operation_generation =
                        completion.binding.operation_generation.saturating_add(1);
                }
                if self.substitute_prepare_deadline.load(Ordering::Acquire) {
                    completion.binding.call_deadline += Duration::from_nanos(1);
                }
                completion
            })
        }

        fn activate(
            self: Arc<Self>,
            request: BackendRequest<ActivateLeaseBatch>,
        ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>> {
            let (completion, request) = request.into_parts();
            Box::pin(async move {
                let result = request
                    .leases
                    .iter()
                    .map(|lease| KernelCounters {
                        path_id: lease.path_id,
                        role: lease.role,
                        latest_handshake_unix: 0,
                        received_bytes: 10,
                        transmitted_bytes: 20,
                    })
                    .collect();
                completion.complete(Ok(result))
            })
        }

        fn probe(
            self: Arc<Self>,
            request: BackendRequest<CommitLeaseBatch>,
        ) -> BackendFuture<BackendCompletion<Vec<KernelCounters>>> {
            let (completion, request) = request.into_parts();
            Box::pin(async move {
                if self.fail_probe_cleanup.load(Ordering::Acquire) {
                    return completion.complete(Err(BackendError::CleanupIncomplete));
                }
                let increment = self.proof_increment.load(Ordering::Relaxed);
                let result = request
                    .leases
                    .iter()
                    .map(|lease| KernelCounters {
                        path_id: lease.path_id,
                        role: lease.role,
                        latest_handshake_unix: 101,
                        received_bytes: 10 + increment,
                        transmitted_bytes: 20 + increment,
                    })
                    .collect();
                completion.complete(Ok(result))
            })
        }

        fn destroy(
            self: Arc<Self>,
            request: BackendRequest<BackendDestroy>,
        ) -> BackendFuture<BackendCompletion<ConfirmedAbsent>> {
            let (completion, request) = request.into_parts();
            self.destroy_calls
                .lock()
                .expect("destroy calls")
                .push((completion.binding(), request));
            Box::pin(async move {
                self.destroyed
                    .lock()
                    .expect("destroy lock")
                    .push(request.context_id);
                self.destroy_entered.store(true, Ordering::Release);
                loop {
                    let notified = self.destroy_release.notified();
                    if !self.block_destroy.load(Ordering::Acquire)
                        || self.destroy_released.load(Ordering::Acquire)
                    {
                        break;
                    }
                    notified.await;
                }
                let result = if self.fail_destroy.load(Ordering::Acquire) {
                    Err(BackendError::CleanupIncomplete)
                } else {
                    Ok(ConfirmedAbsent)
                };
                completion.complete(result)
            })
        }

        fn acquire_transport_socket(
            self: Arc<Self>,
            request: BackendRequest<AcquireTransportSocket>,
        ) -> BackendFuture<BackendCompletion<OwnedFd>> {
            let (completion, _request) = request.into_parts();
            Box::pin(async move {
                let result = if self.fail_acquire_cleanup.load(Ordering::Acquire) {
                    Err(BackendError::CleanupIncomplete)
                } else {
                    StdUnixStream::pair()
                        .map_err(|_| BackendError::Kernel)
                        .and_then(|(worker, peer)| {
                            self.transport_calls.fetch_add(1, Ordering::Relaxed);
                            self.transport_peers
                                .lock()
                                .map_err(|_| BackendError::Kernel)?
                                .push(peer);
                            Ok(worker.into())
                        })
                };
                self.acquire_entered.store(true, Ordering::Release);
                loop {
                    let notified = self.acquire_release.notified();
                    if !self.block_acquire.load(Ordering::Acquire)
                        || self.acquire_released.load(Ordering::Acquire)
                    {
                        break;
                    }
                    notified.await;
                }
                let mut completion = completion.complete(result);
                if self.substitute_acquire_generation.load(Ordering::Acquire) {
                    completion.binding.operation_generation =
                        completion.binding.operation_generation.saturating_add(1);
                }
                completion
            })
        }

        fn transport_socket_supported(
            self: Arc<Self>,
            request: BackendRuntimeRequest,
        ) -> BackendFuture<BackendRuntimeCompletion<bool>> {
            self.runtime_bindings
                .lock()
                .expect("runtime bindings")
                .push(request.binding());
            Box::pin(async move { request.complete(Ok(true)) })
        }

        fn shutdown(
            self: Arc<Self>,
            request: BackendRuntimeRequest,
        ) -> BackendFuture<BackendRuntimeCompletion<()>> {
            self.runtime_bindings
                .lock()
                .expect("runtime bindings")
                .push(request.binding());
            Box::pin(async move { request.complete(Ok(())) })
        }
    }

    fn request(id: u8, operation: helper_request::Operation) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![id; 16],
            operation: Some(operation),
        }
    }

    fn prepare_request(id: u8) -> HelperRequest {
        request(
            id,
            helper_request::Operation::PrepareLeaseBatch(PrepareLeaseBatch {
                route_context_id: vec![7; 16],
                role: ContextRole::Client as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
                leases: vec![LeasePlan {
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                }],
                setup_expires_at_unix: 120,
                hard_expires_at_unix: 900,
            }),
        )
    }

    fn bind_request_for(prepare: &HelperRequest, id: u8) -> HelperRequest {
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) = prepare.operation.as_ref()
        else {
            panic!("Prepare request");
        };
        request(
            id,
            helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
                prepare_intent: Some(PrepareIntent {
                    route_context_id: value.route_context_id.clone(),
                    prepare_request_id: prepare.request_id.clone(),
                    prepare_operation_digest: operation_digest(prepare)
                        .expect("Prepare digest")
                        .to_vec(),
                    setup_expires_at_unix: value.setup_expires_at_unix,
                    hard_expires_at_unix: value.hard_expires_at_unix,
                    closed_plan: Some(ClosedPreparePlan {
                        context_role: value.role,
                        leases: value.leases.clone(),
                    }),
                }),
            }),
        )
    }

    fn reconcile_request_for(
        prepare: &HelperRequest,
        id: u8,
        runtime_id: [u8; 32],
    ) -> HelperRequest {
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) = prepare.operation.as_ref()
        else {
            panic!("Prepare request");
        };
        request(
            id,
            helper_request::Operation::ReconcileExpiredPrepare(ReconcileExpiredPrepare {
                helper_runtime_id: runtime_id.to_vec(),
                route_context_id: value.route_context_id.clone(),
                prepare_request_id: prepare.request_id.clone(),
                prepare_operation_digest: operation_digest(prepare)
                    .expect("Prepare digest")
                    .to_vec(),
                setup_expires_at_unix: value.setup_expires_at_unix,
                hard_expires_at_unix: value.hard_expires_at_unix,
            }),
        )
    }

    async fn execute_prepare(engine: &HelperEngine, prepare: HelperRequest) -> HelperResponse {
        let prepare_request_id: [u8; 16] = prepare
            .request_id
            .as_slice()
            .try_into()
            .expect("request ID");
        let mut bind_byte = prepare_request_id[0] ^ 0x80;
        if bind_byte == 0 || bind_byte == prepare_request_id[0] {
            bind_byte = 0xfe;
        }
        let bind = bind_request_for(&prepare, bind_byte);
        assert_eq!(
            engine.execute(bind).await.result,
            HelperResult::Ok as i32,
            "Prepare intent"
        );
        engine.execute(prepare).await
    }

    fn fake_engine(backend: Arc<FakeBackend>, clock: Arc<FixedClock>) -> HelperEngine {
        HelperEngine::with_components(
            [9; 32],
            1_000,
            backend,
            Arc::new(FixedHandles(AtomicU64::new(0))),
            clock,
        )
    }

    fn fake_engine_with_timeout(
        backend: Arc<FakeBackend>,
        clock: Arc<FixedClock>,
        timeout: Duration,
    ) -> HelperEngine {
        HelperEngine::with_components_and_timeout(
            [9; 32],
            1_000,
            backend,
            Arc::new(FixedHandles(AtomicU64::new(0))),
            clock,
            timeout,
        )
    }

    fn prepared(response: &HelperResponse) -> PreparedLeaseBatch {
        let Some(helper_response::Outcome::PreparedLeaseBatch(value)) = response.outcome.clone()
        else {
            panic!("prepared outcome");
        };
        value
    }

    async fn activate_client_context(engine: &HelperEngine) -> PreparedLeaseBatch {
        let prepared = prepared(&execute_prepare(engine, prepare_request(1)).await);
        let lease = &prepared.leases[0];
        let activated = engine
            .execute(request(
                2,
                helper_request::Operation::ActivateLeaseBatch(ActivateLeaseBatch {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle.clone(),
                    leases: vec![LeaseActivation {
                        lease_handle: lease.lease_handle.clone(),
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                        peer_public_key: vec![8; 32],
                        peer_endpoint: Some(PublicUdpEndpoint {
                            address: vec![1, 1, 1, 1],
                            port: 51_820,
                        }),
                        maximum_up_mbps: 0,
                        maximum_down_mbps: 0,
                    }],
                }),
            ))
            .await;
        assert_eq!(activated.result, HelperResult::Ok as i32);
        prepared
    }

    async fn commit_client_context(
        engine: &HelperEngine,
        backend: &FakeBackend,
    ) -> PreparedLeaseBatch {
        let prepared = activate_client_context(engine).await;
        let lease = &prepared.leases[0];
        backend.proof_increment.store(1, Ordering::Relaxed);
        let committed = engine
            .execute(request(
                3,
                helper_request::Operation::CommitLeaseBatch(CommitLeaseBatch {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle.clone(),
                    leases: vec![LeaseCommit {
                        lease_handle: lease.lease_handle.clone(),
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                    }],
                }),
            ))
            .await;
        assert_eq!(committed.result, HelperResult::Ok as i32);
        prepared
    }

    fn transport_address(
        address: [u8; 4],
        port: u32,
    ) -> volparossa_routing::TransportSocketAddress {
        volparossa_routing::TransportSocketAddress {
            address: address.to_vec(),
            port,
        }
    }

    fn client_ingress_receipts() -> Vec<volparossa_routing::IngressSocketReceipt> {
        [
            volparossa_routing::IngressSocketKind::TransparentTcpListener,
            volparossa_routing::IngressSocketKind::TransparentUdp,
            volparossa_routing::IngressSocketKind::DnsTcpListener,
            volparossa_routing::IngressSocketKind::DnsUdp,
        ]
        .into_iter()
        .flat_map(|kind| {
            [
                volparossa_routing::IngressAddressFamily::Ipv4,
                volparossa_routing::IngressAddressFamily::Ipv6,
            ]
            .into_iter()
            .map(move |family| (kind, family))
        })
        .enumerate()
        .map(
            |(index, (kind, family))| volparossa_routing::IngressSocketReceipt {
                socket_handle: vec![u8::try_from(index + 11).expect("bounded index"); 32],
                receipt_handle: vec![u8::try_from(index + 21).expect("bounded index"); 32],
                descriptor_kind: kind as i32,
                address_family: family as i32,
            },
        )
        .collect()
    }

    #[tokio::test]
    async fn client_ingress_lifecycle_is_unavailable_before_backend_state_or_network() {
        let engine = HelperEngine::new([9; 32], 1_000);
        let operations = [
            helper_request::Operation::PrepareClientIngress(
                volparossa_routing::PrepareClientIngress {
                    client_runtime_id: vec![7; 16],
                    setup_expires_at_unix: 120,
                    hard_expires_at_unix: 900,
                },
            ),
            helper_request::Operation::AcquireIngressSocket(
                volparossa_routing::AcquireIngressSocket {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    socket_handle: vec![9; 32],
                    descriptor_kind: volparossa_routing::IngressSocketKind::TransparentUdp as i32,
                    address_family: volparossa_routing::IngressAddressFamily::Ipv4 as i32,
                },
            ),
            helper_request::Operation::ActivateClientIngress(
                volparossa_routing::ActivateClientIngress {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    receipts: client_ingress_receipts(),
                },
            ),
            helper_request::Operation::DestroyClientIngress(
                volparossa_routing::DestroyClientIngress {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                },
            ),
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            let execution = engine
                .execute_with_descriptor(request(
                    u8::try_from(index + 40).expect("bounded request ID"),
                    operation,
                ))
                .await;
            assert_eq!(execution.response.result, HelperResult::Unavailable as i32);
            assert_eq!(
                execution.response.diagnostic_code,
                "CLIENT_INGRESS_UNAVAILABLE"
            );
            assert!(execution.response.outcome.is_none());
            assert!(execution.descriptor.is_none());
        }
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cache.is_empty());
    }

    #[tokio::test]
    async fn unavailable_backend_prepare_is_explicit_and_creates_nothing() {
        let engine = HelperEngine::with_components(
            [9; 32],
            1_000,
            Arc::new(UnavailableLeaseBackend),
            Arc::new(FixedHandles(AtomicU64::new(0))),
            Arc::new(FixedClock(AtomicU64::new(100))),
        );
        let value = prepare_request(1);
        let first = execute_prepare(&engine, value.clone()).await;
        let second = engine.execute(value).await;
        assert_eq!(first, second);
        assert_eq!(first.result, HelperResult::Unavailable as i32);
        assert!(first.outcome.is_none());
        assert!(engine.inner.state.lock().await.contexts.is_empty());
    }

    #[test]
    fn closed_plan_and_prepare_bindings_match_for_every_context_shape() {
        let maximal_relay = (1..=8)
            .flat_map(|path_id| {
                [WireguardRole::RelayClient, WireguardRole::RelayExit]
                    .into_iter()
                    .map(move |role| LeasePlan {
                        path_id,
                        role: role as i32,
                    })
            })
            .collect::<Vec<_>>();
        let cases = [
            (
                "client",
                ContextRole::Client,
                vec![LeasePlan {
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                }],
            ),
            (
                "relay",
                ContextRole::Relay,
                vec![
                    LeasePlan {
                        path_id: 1,
                        role: WireguardRole::RelayClient as i32,
                    },
                    LeasePlan {
                        path_id: 1,
                        role: WireguardRole::RelayExit as i32,
                    },
                ],
            ),
            (
                "exit",
                ContextRole::Exit,
                vec![LeasePlan {
                    path_id: 1,
                    role: WireguardRole::Exit as i32,
                }],
            ),
            ("maximal relay", ContextRole::Relay, maximal_relay),
        ];

        for (label, context_role, leases) in cases {
            let prepare = PrepareLeaseBatch {
                route_context_id: vec![7; 16],
                role: context_role as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
                leases: leases.clone(),
                setup_expires_at_unix: 120,
                hard_expires_at_unix: 900,
            };
            let closed_plan = ClosedPreparePlan {
                context_role: context_role as i32,
                leases,
            };
            let from_prepare = ClosedPreparePlanBinding::from_prepare(&prepare)
                .unwrap_or_else(|| panic!("valid {label} Prepare binding"));
            let from_closed_plan = ClosedPreparePlanBinding::from_closed_plan(&closed_plan)
                .unwrap_or_else(|| panic!("valid {label} closed-plan binding"));

            assert_eq!(from_closed_plan, from_prepare, "{label}");
            assert_eq!(
                usize::from(from_closed_plan.lease_count),
                closed_plan.leases.len(),
                "{label} identity count"
            );
        }
    }

    async fn assert_equal_cardinality_plan_substitution_rejected(
        prepare_b: HelperRequest,
        plan_a: ClosedPreparePlan,
        bind_request_id: u8,
    ) {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let context_id: [u8; 16] = prepare_b
            .operation
            .as_ref()
            .and_then(|operation| match operation {
                helper_request::Operation::PrepareLeaseBatch(value) => {
                    value.route_context_id.as_slice().try_into().ok()
                }
                _ => None,
            })
            .expect("Prepare B context ID");
        let mut bind_a_digest_b = bind_request_for(&prepare_b, bind_request_id);
        let Some(helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
            prepare_intent: Some(intent),
        })) = bind_a_digest_b.operation.as_mut()
        else {
            panic!("Bind A/digest B");
        };
        let plan_b = intent.closed_plan.replace(plan_a).expect("closed plan B");
        assert_eq!(
            intent
                .closed_plan
                .as_ref()
                .expect("closed plan A")
                .leases
                .len(),
            plan_b.leases.len(),
            "the adversarial plans must have equal cardinality"
        );
        assert_ne!(intent.closed_plan.as_ref(), Some(&plan_b));
        assert!(operation_digest(&bind_a_digest_b).is_ok());
        assert_eq!(
            engine.execute(bind_a_digest_b).await.result,
            HelperResult::Ok as i32
        );

        let (record_before, next_generation_before, next_operation_before) = {
            let state = engine.inner.state.lock().await;
            (
                *state
                    .prepare_reconciliations
                    .get(&context_id)
                    .expect("retained plan A"),
                state.next_generation,
                state.next_operation,
            )
        };
        let rejected = engine.execute(prepare_b).await;
        assert_eq!(rejected.result, HelperResult::AlreadyExists as i32);
        assert_eq!(rejected.diagnostic_code, "PREPARE_INTENT_CONFLICT");
        assert!(
            backend
                .prepare_bindings
                .lock()
                .expect("prepare bindings")
                .is_empty()
        );
        assert!(!backend.prepare_entered.load(Ordering::Acquire));
        assert!(
            backend
                .destroy_calls
                .lock()
                .expect("destroy calls")
                .is_empty()
        );
        assert!(
            backend
                .runtime_bindings
                .lock()
                .expect("runtime bindings")
                .is_empty()
        );
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.in_flight.is_none());
        assert!(state.cleanup_pending.is_empty());
        assert_eq!(state.next_generation, next_generation_before);
        assert_eq!(state.next_operation, next_operation_before);
        assert!(
            state.prepare_reconciliations.get(&context_id).copied() == Some(record_before),
            "the rejected Prepare must not change its retained target authority"
        );
    }

    #[tokio::test]
    async fn equal_cardinality_path_plan_a_cannot_authorize_prepare_and_digest_b() {
        let mut prepare_b = prepare_request(81);
        let Some(helper_request::Operation::PrepareLeaseBatch(value_b)) =
            prepare_b.operation.as_mut()
        else {
            panic!("Prepare B");
        };
        value_b.leases[0].path_id = 2;
        let plan_a = ClosedPreparePlan {
            context_role: ContextRole::Client as i32,
            leases: vec![LeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            }],
        };

        assert_equal_cardinality_plan_substitution_rejected(prepare_b, plan_a, 82).await;
    }

    #[tokio::test]
    async fn equal_cardinality_context_role_plan_a_cannot_authorize_prepare_and_digest_b() {
        let mut prepare_b = prepare_request(83);
        let Some(helper_request::Operation::PrepareLeaseBatch(value_b)) =
            prepare_b.operation.as_mut()
        else {
            panic!("Prepare B");
        };
        value_b.role = ContextRole::Exit as i32;
        value_b.leases[0].role = WireguardRole::Exit as i32;
        let plan_a = ClosedPreparePlan {
            context_role: ContextRole::Client as i32,
            leases: vec![LeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            }],
        };

        assert_equal_cardinality_plan_substitution_rejected(prepare_b, plan_a, 84).await;
    }

    #[tokio::test]
    async fn retained_prepare_identity_rejects_a_new_bind_with_substituted_plan() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let mut prepare_b = prepare_request(83);
        let Some(helper_request::Operation::PrepareLeaseBatch(value_b)) =
            prepare_b.operation.as_mut()
        else {
            panic!("Prepare B");
        };
        value_b.leases[0].path_id = 2;
        assert_eq!(
            engine
                .execute(bind_request_for(&prepare_b, 84))
                .await
                .result,
            HelperResult::Ok as i32
        );

        let mut substituted = bind_request_for(&prepare_b, 85);
        let Some(helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
            prepare_intent: Some(intent),
        })) = substituted.operation.as_mut()
        else {
            panic!("substituted Bind");
        };
        let closed_plan = intent.closed_plan.as_mut().expect("closed plan");
        closed_plan.leases[0].path_id = 1;
        assert!(operation_digest(&substituted).is_ok());
        let rejected = engine.execute(substituted).await;
        assert_eq!(rejected.result, HelperResult::AlreadyExists as i32);
        assert_eq!(rejected.diagnostic_code, "CONTEXT_RECONCILIATION_RETAINED");
        assert!(
            backend
                .prepare_bindings
                .lock()
                .expect("prepare bindings")
                .is_empty()
        );
        assert!(!backend.prepare_entered.load(Ordering::Acquire));
        assert!(
            backend
                .destroy_calls
                .lock()
                .expect("destroy calls")
                .is_empty()
        );
        let state = engine.inner.state.lock().await;
        let retained = state
            .prepare_reconciliations
            .get(&[7; 16])
            .expect("retained plan B");
        assert_eq!(retained.phase, PrepareReconciliationPhase::Intent);
        assert_eq!(retained.closed_plan.lease_count, 1);
        assert_eq!(retained.closed_plan.identities[0], (2, 1));
    }

    #[tokio::test]
    async fn exact_activation_and_counter_growth_are_required_before_commit() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = execute_prepare(&engine, prepare_request(1)).await;
        let prepared = prepared(&prepare);
        let lease = &prepared.leases[0];

        let activation = ActivateLeaseBatch {
            route_context_id: vec![7; 16],
            context_handle: prepared.context_handle.clone(),
            leases: vec![LeaseActivation {
                lease_handle: lease.lease_handle.clone(),
                path_id: 1,
                role: WireguardRole::Client as i32,
                peer_public_key: vec![8; 32],
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: vec![1, 1, 1, 1],
                    port: 51_820,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
            }],
        };
        let mut wrong = activation.clone();
        wrong.leases[0].lease_handle[0] ^= 1;
        let rejected = engine
            .execute(request(
                2,
                helper_request::Operation::ActivateLeaseBatch(wrong),
            ))
            .await;
        assert_eq!(rejected.result, HelperResult::InvalidRequest as i32);

        let activated = engine
            .execute(request(
                3,
                helper_request::Operation::ActivateLeaseBatch(activation),
            ))
            .await;
        assert_eq!(activated.result, HelperResult::Ok as i32);

        let commit = CommitLeaseBatch {
            route_context_id: vec![7; 16],
            context_handle: prepared.context_handle,
            leases: vec![LeaseCommit {
                lease_handle: lease.lease_handle.clone(),
                path_id: 1,
                role: WireguardRole::Client as i32,
            }],
        };
        let incomplete = engine
            .execute(request(
                4,
                helper_request::Operation::CommitLeaseBatch(commit.clone()),
            ))
            .await;
        assert_eq!(incomplete.result, HelperResult::Kernel as i32);
        backend.proof_increment.store(1, Ordering::Relaxed);
        let committed = engine
            .execute(request(
                5,
                helper_request::Operation::CommitLeaseBatch(commit),
            ))
            .await;
        assert_eq!(committed.result, HelperResult::Ok as i32);
    }

    #[tokio::test]
    async fn committed_transport_handoffs_are_typed_cached_and_closed_on_destroy() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepared = commit_client_context(&engine, &backend).await;

        for (request_id, kind) in [
            (10, volparossa_routing::TransportSocketKind::MptcpConnected),
            (11, volparossa_routing::TransportSocketKind::MptcpListener),
            (
                12,
                volparossa_routing::TransportSocketKind::QuicUdpUnconnected,
            ),
        ] {
            let remote = (kind == volparossa_routing::TransportSocketKind::MptcpConnected)
                .then(|| transport_address([10, 77, 0, 3], 443));
            let acquire = request(
                request_id,
                helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle.clone(),
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: kind as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: remote.clone(),
                }),
            );
            let first = engine.execute_with_descriptor(acquire.clone()).await;
            assert_eq!(first.response.result, HelperResult::Ok as i32);
            let Some(helper_response::Outcome::TransportSocketReady(ready)) =
                first.response.outcome.as_ref()
            else {
                panic!("transport ready");
            };
            assert_eq!(ready.descriptor_kind, kind as i32);
            assert_eq!(ready.remote, remote);
            let second = engine.execute_with_descriptor(acquire).await;
            assert_eq!(first.response, second.response);
            let first_descriptor = first.descriptor.as_ref().expect("first descriptor");
            let second_descriptor = second.descriptor.as_ref().expect("cached descriptor");
            assert!(Arc::ptr_eq(first_descriptor, second_descriptor));
            drop(first);
            drop(second);
        }
        assert_eq!(backend.transport_calls.load(Ordering::Relaxed), 3);

        let mut wrong_handle = AcquireTransportSocket {
            route_context_id: vec![7; 16],
            context_handle: prepared.context_handle.clone(),
            path_id: 1,
            role: WireguardRole::Client as i32,
            descriptor_kind: volparossa_routing::TransportSocketKind::MptcpListener as i32,
            expected_local: Some(transport_address([10, 77, 0, 2], 42_001)),
            expected_remote: None,
        };
        wrong_handle.context_handle[0] ^= 1;
        let rejected = engine
            .execute_with_descriptor(request(
                20,
                helper_request::Operation::AcquireTransportSocket(wrong_handle),
            ))
            .await;
        assert_eq!(
            rejected.response.result,
            HelperResult::InvalidRequest as i32
        );
        assert!(rejected.descriptor.is_none());

        let destroyed = engine
            .execute(request(
                21,
                helper_request::Operation::DestroyContext(volparossa_routing::DestroyContext {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle,
                }),
            ))
            .await;
        assert_eq!(destroyed.result, HelperResult::Ok as i32);
        let peers =
            std::mem::take(&mut *backend.transport_peers.lock().expect("transport peer lock"));
        for mut peer in peers {
            peer.set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            let mut byte = [0_u8; 1];
            assert_eq!(peer.read(&mut byte).expect("closed cached descriptor"), 0);
        }
    }

    #[test]
    fn engine_cleanup_token_uses_a_zeroizing_owner() {
        fn requires_zeroizing_array(_: &Zeroizing<[u8; 32]>) {}

        let engine = HelperEngine::new([9; 32], 1_000);
        requires_zeroizing_array(&engine.inner.cleanup_token);
    }

    #[tokio::test]
    async fn cleanup_supervisor_panic_keeps_exact_sanitized_fallback() {
        let engine = HelperEngine::with_components(
            [9; 32],
            1_000,
            Arc::new(FakeBackend::default()),
            Arc::new(FixedHandles(AtomicU64::new(0))),
            Arc::new(PanicClock),
        );
        let cleanup = request(
            41,
            helper_request::Operation::CleanupOwned(volparossa_routing::CleanupOwned {
                cleanup_token: vec![9; 32],
            }),
        );
        let expected_digest = operation_digest(&cleanup).expect("digest").to_vec();

        let response = engine.execute(cleanup).await;

        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "SUPERVISOR_RESULT_AMBIGUOUS");
        assert_eq!(response.request_id, vec![41; 16]);
        assert_eq!(response.operation_digest, expected_digest);
        assert!(response.outcome.is_none());
    }

    #[tokio::test]
    async fn standalone_acquire_fails_unavailable_before_context_or_network_work() {
        let engine = HelperEngine::new([9; 32], 1_000);
        let execution = engine
            .execute_with_descriptor(request(
                31,
                helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: vec![8; 32],
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: volparossa_routing::TransportSocketKind::QuicUdpUnconnected
                        as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: None,
                }),
            ))
            .await;
        assert_eq!(execution.response.result, HelperResult::Unavailable as i32);
        assert_eq!(
            execution.response.diagnostic_code,
            "TRANSPORT_SOCKET_UNAVAILABLE"
        );
        assert!(execution.response.outcome.is_none());
        assert!(execution.descriptor.is_none());
        assert!(engine.inner.state.lock().await.contexts.is_empty());
    }

    #[tokio::test]
    async fn expiry_reaps_and_request_id_collision_fails_closed() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        assert_eq!(
            execute_prepare(&engine, prepare_request(1)).await.result,
            HelperResult::Ok as i32
        );

        let mut collision = prepare_request(1);
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) =
            collision.operation.as_mut()
        else {
            panic!("prepare");
        };
        value.route_context_id = vec![8; 16];
        assert_eq!(
            engine.execute(collision).await.result,
            HelperResult::InvalidRequest as i32
        );

        clock.0.store(121, Ordering::Relaxed);
        let cleanup = request(
            7,
            helper_request::Operation::CleanupOwned(volparossa_routing::CleanupOwned {
                cleanup_token: vec![9; 32],
            }),
        );
        assert_eq!(
            engine.execute(cleanup).await.result,
            HelperResult::Ok as i32
        );
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
    }

    #[tokio::test]
    async fn maintenance_reaper_removes_expired_prepare_without_an_agent_request() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        assert_eq!(
            execute_prepare(&engine, prepare_request(81)).await.result,
            HelperResult::Ok as i32
        );

        assert!(engine.reap_expired_cleanup().await);
        assert!(
            backend
                .destroy_calls
                .lock()
                .expect("destroy calls")
                .is_empty()
        );

        clock.0.store(120, Ordering::Release);
        assert!(engine.reap_expired_cleanup().await);
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        let calls = backend.destroy_calls.lock().expect("destroy calls");
        let (binding, value) = calls.last().expect("maintenance Destroy");
        assert_eq!(binding.operation_kind, OperationKind::Reap);
        assert_eq!(binding.prior_phase, Some(ContextPhase::Prepared));
        assert!(binding.request_id.iter().any(|byte| *byte != 0));
        assert!(binding.request_digest.iter().any(|byte| *byte != 0));
        assert_eq!(value.context_id, [7; 16]);
    }

    #[tokio::test]
    async fn maintenance_reaper_retries_exact_quarantined_lineage() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        assert_eq!(
            execute_prepare(&engine, prepare_request(82)).await.result,
            HelperResult::Ok as i32
        );

        clock.0.store(120, Ordering::Release);
        assert!(!engine.reap_expired_cleanup().await);
        {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("quarantined context");
            assert_eq!(context.phase, ContextPhase::Quarantined);
            assert!(
                state
                    .cleanup_pending
                    .contains(&([7; 16], context.generation))
            );
        }

        backend.fail_destroy.store(false, Ordering::Release);
        assert!(engine.reap_expired_cleanup().await);
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        let calls = backend.destroy_calls.lock().expect("destroy calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0.lineage, calls[1].0.lineage);
        assert_eq!(calls[0].0.request_id, calls[1].0.request_id);
        assert_eq!(calls[0].0.request_digest, calls[1].0.request_digest);
        assert_eq!(calls[0].0.prior_phase, Some(ContextPhase::Prepared));
        assert_eq!(calls[1].0.prior_phase, Some(ContextPhase::Quarantined));
    }

    #[tokio::test]
    async fn maintenance_reaper_retries_owned_orphan_before_setup_expiry() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_prepare_capacity.store(true, Ordering::Release);
        backend.fail_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let response = execute_prepare(&engine, prepare_request(84)).await;
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        {
            let state = engine.inner.state.lock().await;
            assert!(state.contexts.is_empty());
            let record = state
                .prepare_reconciliations
                .get(&[7; 16])
                .expect("owned orphan");
            assert_eq!(record.phase, PrepareReconciliationPhase::Pending);
            assert!(
                state
                    .cleanup_pending
                    .contains(&([7; 16], record.backend_generation))
            );
        }

        backend.fail_destroy.store(false, Ordering::Release);
        assert!(engine.reap_expired_cleanup().await);
        let state = engine.inner.state.lock().await;
        assert!(cleanup_state_complete(&state));
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn cancelled_maintenance_waiter_cannot_cancel_owned_destroy() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        assert_eq!(
            execute_prepare(&engine, prepare_request(83)).await.result,
            HelperResult::Ok as i32
        );
        clock.0.store(120, Ordering::Release);

        let reaping_engine = engine.clone();
        let waiter = tokio::spawn(async move { reaping_engine.reap_expired_cleanup().await });
        wait_for_destroy_entry(&backend).await;
        waiter.abort();
        assert!(waiter.await.expect_err("cancelled waiter").is_cancelled());

        backend.release_destroy();
        wait_for_supervisor_settlement(&engine).await;
        assert!(engine.inner.state.lock().await.contexts.is_empty());
    }

    async fn wait_for_prepare_entry(backend: &FakeBackend) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !backend.prepare_entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("prepare entered");
    }

    async fn wait_for_destroy_entry(backend: &FakeBackend) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !backend.destroy_entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("destroy entered");
    }

    async fn wait_for_acquire_entry(backend: &FakeBackend) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !backend.acquire_entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Acquire entered");
    }

    async fn wait_for_supervisor_settlement(engine: &HelperEngine) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let settled = {
                    let state = engine.inner.state.lock().await;
                    state.in_flight.is_none() && state.cleanup_pending.is_empty()
                };
                if settled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor settled");
    }

    #[tokio::test]
    async fn engine_state_lock_is_available_while_prepare_backend_is_blocked() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_prepare.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let executing_engine = engine.clone();
        let execution =
            tokio::spawn(
                async move { execute_prepare(&executing_engine, prepare_request(40)).await },
            );

        wait_for_prepare_entry(&backend).await;
        let state = tokio::time::timeout(Duration::from_millis(100), engine.inner.state.lock())
            .await
            .expect("EngineState lock must not be held by backend I/O");
        assert!(state.in_flight.is_some());
        drop(state);

        backend.release_prepare();
        let response = execution.await.expect("execute task");
        assert_eq!(response.result, HelperResult::Ok as i32);
    }

    #[tokio::test]
    async fn stale_prepare_completion_is_rejected_and_rolled_back() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_prepare.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let executing_engine = engine.clone();
        let execution =
            tokio::spawn(
                async move { execute_prepare(&executing_engine, prepare_request(41)).await },
            );

        wait_for_prepare_entry(&backend).await;
        engine.inner.state.lock().await.in_flight = None;
        backend.release_prepare();

        let response = execution.await.expect("execute task");
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "STALE_BACKEND_RESULT");
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        drop(state);
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
    }

    #[tokio::test]
    async fn caller_abort_after_plan_does_not_cancel_supervisor_commit() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_prepare.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let executing_engine = engine.clone();
        let execution =
            tokio::spawn(
                async move { execute_prepare(&executing_engine, prepare_request(42)).await },
            );

        wait_for_prepare_entry(&backend).await;
        execution.abort();
        assert!(
            execution
                .await
                .expect_err("caller task cancelled")
                .is_cancelled()
        );
        backend.release_prepare();
        wait_for_supervisor_settlement(&engine).await;

        let state = engine.inner.state.lock().await;
        assert!(state.contexts.contains_key(&[7; 16]));
        assert!(state.in_flight.is_none());
        assert!(state.cleanup_pending.is_empty());
    }

    #[tokio::test]
    async fn invalid_prepare_proof_has_confirmed_rollback_authority() {
        let backend = Arc::new(FakeBackend::default());
        backend.invalid_prepare.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);

        let response = execute_prepare(&engine, prepare_request(43)).await;
        assert_eq!(response.result, HelperResult::Kernel as i32);
        assert_eq!(response.diagnostic_code, "PREPARE_PROOF_INVALID");
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
        drop(state);
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
    }

    #[test]
    fn prepare_proof_order_keys_and_public_endpoints_are_affinely_unique() {
        let prepare = prepare_request(43);
        let Some(helper_request::Operation::PrepareLeaseBatch(mut request)) = prepare.operation
        else {
            panic!("Prepare request")
        };
        let mut second = request.leases[0].clone();
        second.path_id = 2;
        request.leases.push(second);
        let lease = |path_id, key, port| PreparedKernelLease {
            path_id,
            role: WireguardRole::Client as i32,
            public_key: [key; 32],
            public_endpoint: PublicUdpEndpoint {
                address: vec![8, 8, 8, 8],
                port,
            },
            evidence: UnderlayEvidence::DirectAssigned,
        };
        let valid = [lease(1, 1, 51_821), lease(2, 2, 51_822)];
        assert!(prepared_matches(&request, &valid));

        let reordered = [valid[1].clone(), valid[0].clone()];
        assert!(!prepared_matches(&request, &reordered));
        let duplicate_key = [lease(1, 1, 51_821), lease(2, 1, 51_822)];
        assert!(!prepared_matches(&request, &duplicate_key));
        let duplicate_endpoint = [lease(1, 1, 51_821), lease(2, 2, 51_821)];
        assert!(!prepared_matches(&request, &duplicate_endpoint));
    }

    #[tokio::test]
    async fn timeout_is_immediately_ambiguous_then_late_result_is_rolled_back() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_prepare.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let started = Instant::now();
        let engine =
            fake_engine_with_timeout(Arc::clone(&backend), clock, Duration::from_millis(20));
        let executing_engine = engine.clone();
        let execution =
            tokio::spawn(
                async move { execute_prepare(&executing_engine, prepare_request(44)).await },
            );

        wait_for_prepare_entry(&backend).await;
        let call_deadline = backend
            .prepare_bindings
            .lock()
            .expect("prepare bindings")
            .first()
            .expect("Prepare binding")
            .call_deadline;
        assert!(call_deadline >= started + Duration::from_millis(20));
        let response = tokio::time::timeout(Duration::from_millis(250), execution)
            .await
            .expect("orchestration timeout response")
            .expect("execute task");
        backend.release_prepare();

        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
        wait_for_supervisor_settlement(&engine).await;
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
    }

    async fn assert_prepare_panic_rolls_back(backend: Arc<FakeBackend>) {
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let response = execute_prepare(&engine, prepare_request(45)).await;

        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
        drop(state);
        let destroy = backend.destroy_calls.lock().expect("destroy calls");
        assert_eq!(destroy.len(), 1);
        assert_eq!(destroy[0].0.lineage.helper_runtime_id, [0xa5; 32]);
        assert_eq!(destroy[0].0.lineage.context_id, [7; 16]);
        assert_eq!(destroy[0].0.lineage.prepare_request_id, [45; 16]);
        assert_eq!(destroy[0].0.request_id, [45; 16]);
        assert_eq!(destroy[0].0.operation_generation, 1);
        assert_eq!(destroy[0].0.phase, BackendPhase::Quarantined);
        assert_eq!(
            destroy[0].1.backend_generation,
            destroy[0].0.lineage.backend_generation
        );
    }

    #[tokio::test]
    async fn backend_factory_panic_keeps_engine_owner_for_exact_rollback() {
        let backend = Arc::new(FakeBackend::default());
        backend.panic_prepare_factory.store(true, Ordering::Release);
        assert_prepare_panic_rolls_back(backend).await;
    }

    #[tokio::test]
    async fn backend_poll_panic_keeps_engine_owner_for_exact_rollback() {
        let backend = Arc::new(FakeBackend::default());
        backend.panic_prepare_poll.store(true, Ordering::Release);
        assert_prepare_panic_rolls_back(backend).await;
    }

    #[tokio::test]
    async fn substituted_generation_or_deadline_completion_is_never_committed() {
        for substitute_deadline in [false, true] {
            let backend = Arc::new(FakeBackend::default());
            backend
                .substitute_prepare_generation
                .store(!substitute_deadline, Ordering::Release);
            backend
                .substitute_prepare_deadline
                .store(substitute_deadline, Ordering::Release);
            let clock = Arc::new(FixedClock(AtomicU64::new(100)));
            let engine = fake_engine(Arc::clone(&backend), clock);

            let response = execute_prepare(&engine, prepare_request(46)).await;
            assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
            assert_eq!(response.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
            let state = engine.inner.state.lock().await;
            assert!(state.contexts.is_empty());
            assert!(state.cleanup_pending.is_empty());
            assert!(state.in_flight.is_none());
            drop(state);
            assert_eq!(
                backend.destroy_calls.lock().expect("destroy calls").len(),
                1
            );
        }
    }

    #[tokio::test]
    async fn stable_backend_lineage_survives_engine_generation_rotation() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepared = commit_client_context(&engine, &backend).await;
        let (operation_generation, backend_generation) = {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Committed context");
            (context.generation, context.backend_generation)
        };
        assert_ne!(operation_generation, backend_generation);
        let initial_lineage = backend.prepare_bindings.lock().expect("prepare bindings")[0].lineage;

        let destroyed = engine
            .execute(request(
                47,
                helper_request::Operation::DestroyContext(volparossa_routing::DestroyContext {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle,
                }),
            ))
            .await;
        assert_eq!(destroyed.result, HelperResult::Ok as i32);
        let calls = backend.destroy_calls.lock().expect("destroy calls");
        let (binding, payload) = calls.last().expect("Destroy binding");
        assert_eq!(binding.lineage, initial_lineage);
        assert_eq!(binding.operation_generation, operation_generation);
        assert_eq!(binding.phase, BackendPhase::Quarantined);
        assert_eq!(binding.operation_kind, OperationKind::Destroy);
        assert_eq!(payload.context_id, [7; 16]);
        assert_eq!(payload.backend_generation, backend_generation);
    }

    #[tokio::test]
    async fn backend_capacity_is_mapped_and_confirmedly_rolled_back() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_prepare_capacity.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);

        let response = execute_prepare(&engine, prepare_request(48)).await;
        assert_eq!(response.result, HelperResult::Capacity as i32);
        assert_eq!(response.diagnostic_code, "PREPARE_FAILED");
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        assert_eq!(
            backend.destroy_calls.lock().expect("destroy calls").len(),
            1
        );
    }

    #[tokio::test]
    async fn runtime_query_and_shutdown_are_runtime_and_deadline_correlated() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let before_query = Instant::now();
        let response = engine
            .execute(request(
                49,
                helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: vec![8; HELPER_HANDLE_BYTES],
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: volparossa_routing::TransportSocketKind::MptcpListener as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: None,
                }),
            ))
            .await;
        assert_eq!(response.result, HelperResult::NotFound as i32);
        assert!(engine.shutdown_cleanup().await);

        let bindings = backend.runtime_bindings.lock().expect("runtime bindings");
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].helper_runtime_id, [0xa5; 32]);
        assert_eq!(
            bindings[0].action,
            BackendRuntimeAction::QueryTransportSocket
        );
        assert!(bindings[0].call_deadline > before_query);
        assert_eq!(bindings[1].helper_runtime_id, [0xa5; 32]);
        assert_eq!(bindings[1].action, BackendRuntimeAction::Shutdown);
        assert!(bindings[1].call_deadline >= bindings[0].call_deadline);
    }

    #[test]
    fn armed_operation_owner_drop_fixture() {
        if std::env::var_os("VOLPAROSSA_TEST_ARMED_OWNER_ABORT").is_none() {
            return;
        }
        let owner = OperationOwner {
            token: OperationToken {
                sequence: 1,
                request_id: [1; 16],
                digest: [2; 32],
                context_id: [3; 16],
                generation: 4,
                prior_phase: Some(ContextPhase::Prepared),
                kind: OperationKind::Prepare,
            },
            lineage: BackendLineage {
                helper_runtime_id: [5; 32],
                context_id: [3; 16],
                backend_generation: 4,
                prepare_request_id: [1; 16],
                prepare_operation_digest: [2; 32],
                setup_expires_at_unix: 10,
                hard_expires_at_unix: 20,
            },
            call_deadline: Instant::now() + Duration::from_secs(1),
            armed: true,
        };
        drop(owner);
    }

    #[test]
    fn armed_operation_owner_drop_is_process_fatal() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("armed_operation_owner_drop_fixture")
            .arg("--nocapture")
            .env("VOLPAROSSA_TEST_ARMED_OWNER_ABORT", "1")
            .status()
            .expect("armed-owner fixture");
        assert_eq!(status.signal(), Some(libc::SIGABRT));
    }

    #[tokio::test]
    async fn generation_and_operation_counter_overflow_are_fail_atomic_capacity() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        engine.inner.state.lock().await.next_generation = u64::MAX;
        let prepare = prepare_request(83);
        let generation_capacity = engine.execute(bind_request_for(&prepare, 84)).await;
        assert_eq!(generation_capacity.result, HelperResult::Capacity as i32);
        assert_eq!(generation_capacity.diagnostic_code, "GENERATION_CAPACITY");
        {
            let state = engine.inner.state.lock().await;
            assert_eq!(state.next_generation, u64::MAX);
            assert!(state.prepare_reconciliations.is_empty());
            assert!(state.in_flight.is_none());
        }

        let second_backend = Arc::new(FakeBackend::default());
        let second_clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let second = fake_engine(Arc::clone(&second_backend), second_clock);
        let second_prepare = prepare_request(85);
        assert_eq!(
            second
                .execute(bind_request_for(&second_prepare, 86))
                .await
                .result,
            HelperResult::Ok as i32
        );
        second.inner.state.lock().await.next_operation = u64::MAX;
        let operation_capacity = second.execute(second_prepare).await;
        assert_eq!(operation_capacity.result, HelperResult::Capacity as i32);
        assert_eq!(operation_capacity.diagnostic_code, "OPERATION_CAPACITY");
        let state = second.inner.state.lock().await;
        assert_eq!(state.next_operation, u64::MAX);
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Intent)
        );
        assert!(
            second_backend
                .prepare_bindings
                .lock()
                .expect("bindings")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn stale_same_lineage_owner_cannot_destroy_or_disturb_current_operation() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        assert_eq!(
            execute_prepare(&engine, prepare_request(87)).await.result,
            HelperResult::Ok as i32
        );
        let current_owner = {
            let mut state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Prepared context");
            let generation = context.generation;
            let lineage = context_backend_lineage([7; 16], context);
            let owner = begin_operation(
                &mut state,
                [88; 16],
                [89; 32],
                [7; 16],
                generation,
                Some(ContextPhase::Prepared),
                OperationKind::Cleanup,
                lineage,
                Instant::now() + Duration::from_secs(1),
            )
            .expect("current operation");
            state.cleanup_pending.insert(([7; 16], generation));
            owner
        };
        let operation = current_owner.token();
        let forged_owner = OperationOwner {
            token: OperationToken {
                sequence: operation.sequence.saturating_add(1),
                request_id: [90; 16],
                digest: [91; 32],
                context_id: operation.context_id,
                generation: operation.generation,
                prior_phase: operation.prior_phase,
                kind: OperationKind::Destroy,
            },
            lineage: current_owner.lineage(),
            call_deadline: Instant::now() + Duration::from_secs(1),
            armed: true,
        };
        let before = {
            let state = engine.inner.state.lock().await;
            (
                state.contexts.get(&[7; 16]).expect("context").phase,
                state.cache.keys().copied().collect::<BTreeSet<_>>(),
                state.cleanup_pending.clone(),
                state.in_flight,
            )
        };
        let mut no_sender = None;
        let outcome = engine
            .destroy_generation(forged_owner, &prepare_request(92), &mut no_sender)
            .await;
        assert!(!outcome.confirmed);
        let state = engine.inner.state.lock().await;
        assert_eq!(
            state.contexts.get(&[7; 16]).expect("context").phase,
            before.0
        );
        assert_eq!(
            state.cache.keys().copied().collect::<BTreeSet<_>>(),
            before.1
        );
        assert_eq!(state.cleanup_pending, before.2);
        assert_eq!(state.in_flight, before.3);
        drop(state);
        assert!(
            backend
                .destroy_calls
                .lock()
                .expect("destroy calls")
                .is_empty()
        );
        engine.clear_operation(current_owner).await;
    }

    #[tokio::test]
    async fn wrong_binding_acquire_closes_descriptor_before_destroy_call() {
        let backend = Arc::new(FakeBackend::default());
        backend
            .substitute_acquire_generation
            .store(true, Ordering::Release);
        backend.block_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepared = commit_client_context(&engine, &backend).await;
        let (expected_lineage, expected_generation) = {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Committed context");
            (
                context_backend_lineage([7; 16], context),
                context.generation,
            )
        };
        let executing = engine.clone();
        let acquire = tokio::spawn(async move {
            executing
                .execute(request(
                    93,
                    helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                        route_context_id: vec![7; 16],
                        context_handle: prepared.context_handle,
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                        descriptor_kind: volparossa_routing::TransportSocketKind::MptcpListener
                            as i32,
                        expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                        expected_remote: None,
                    }),
                ))
                .await
        });
        wait_for_destroy_entry(&backend).await;
        let mut peer = backend
            .transport_peers
            .lock()
            .expect("transport peers")
            .pop()
            .expect("Acquire peer");
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("descriptor closed"), 0);
        backend.release_destroy();
        let response = acquire.await.expect("Acquire task");
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
        {
            let calls = backend.destroy_calls.lock().expect("destroy calls");
            assert_eq!(calls.len(), 1);
            let (binding, payload) = calls[0];
            assert_eq!(binding.lineage, expected_lineage);
            assert_eq!(binding.operation_generation, expected_generation);
            assert_eq!(binding.request_id, [93; 16]);
            assert_eq!(binding.prior_phase, Some(ContextPhase::Committed));
            assert_eq!(binding.operation_kind, OperationKind::Acquire);
            assert_eq!(binding.phase, BackendPhase::Quarantined);
            assert_eq!(binding.action, BackendAction::Destroy);
            assert_eq!(payload.context_id, [7; 16]);
            assert_eq!(
                payload.backend_generation,
                expected_lineage.backend_generation
            );
        }
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
        assert!(
            state
                .cache
                .get(&[93; 16])
                .is_some_and(|cached| cached.descriptor.is_none())
        );
    }

    #[tokio::test]
    async fn timed_out_acquire_closes_late_descriptor_before_destroy_call() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine =
            fake_engine_with_timeout(Arc::clone(&backend), clock, Duration::from_millis(20));
        let prepared = commit_client_context(&engine, &backend).await;
        let (expected_lineage, expected_generation) = {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Committed context");
            (
                context_backend_lineage([7; 16], context),
                context.generation,
            )
        };
        backend.block_acquire.store(true, Ordering::Release);
        backend.block_destroy.store(true, Ordering::Release);

        let executing = engine.clone();
        let acquire = tokio::spawn(async move {
            executing
                .execute(request(
                    94,
                    helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                        route_context_id: vec![7; 16],
                        context_handle: prepared.context_handle,
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                        descriptor_kind: volparossa_routing::TransportSocketKind::MptcpListener
                            as i32,
                        expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                        expected_remote: None,
                    }),
                ))
                .await
        });
        wait_for_acquire_entry(&backend).await;
        let response = tokio::time::timeout(Duration::from_millis(250), acquire)
            .await
            .expect("immediate ambiguous Acquire response")
            .expect("Acquire task");
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
        {
            let state = engine.inner.state.lock().await;
            assert!(
                state
                    .cache
                    .get(&[94; 16])
                    .is_some_and(|cached| cached.descriptor.is_none())
            );
            assert_eq!(
                state.contexts.get(&[7; 16]).map(|context| context.phase),
                Some(ContextPhase::Quarantined)
            );
        }

        let mut peer = backend
            .transport_peers
            .lock()
            .expect("transport peers")
            .pop()
            .expect("late Acquire peer");
        backend.release_acquire();
        wait_for_destroy_entry(&backend).await;
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("late descriptor closed"), 0);
        {
            let calls = backend.destroy_calls.lock().expect("destroy calls");
            assert_eq!(calls.len(), 1);
            let (binding, payload) = calls[0];
            assert_eq!(binding.lineage, expected_lineage);
            assert_eq!(binding.operation_generation, expected_generation);
            assert_eq!(binding.request_id, [94; 16]);
            assert_eq!(binding.operation_kind, OperationKind::Acquire);
            assert_eq!(binding.phase, BackendPhase::Quarantined);
            assert_eq!(binding.action, BackendAction::Destroy);
            assert_eq!(payload.context_id, [7; 16]);
            assert_eq!(
                payload.backend_generation,
                expected_lineage.backend_generation
            );
        }

        backend.release_destroy();
        wait_for_supervisor_settlement(&engine).await;
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
        assert!(
            state
                .cache
                .get(&[94; 16])
                .is_some_and(|cached| cached.descriptor.is_none())
        );
    }

    #[tokio::test]
    async fn uncertain_probe_error_quarantines_exact_lineage_until_destroy_is_confirmed() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepared = activate_client_context(&engine).await;
        let (expected_lineage, expected_generation) = {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Activated context");
            (
                context_backend_lineage([7; 16], context),
                context.generation,
            )
        };
        backend.fail_probe_cleanup.store(true, Ordering::Release);
        backend.fail_destroy.store(true, Ordering::Release);
        let lease = &prepared.leases[0];
        let response = engine
            .execute(request(
                95,
                helper_request::Operation::CommitLeaseBatch(CommitLeaseBatch {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle,
                    leases: vec![LeaseCommit {
                        lease_handle: lease.lease_handle.clone(),
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                    }],
                }),
            ))
            .await;
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "CLEANUP_INCOMPLETE");
        {
            let calls = backend.destroy_calls.lock().expect("destroy calls");
            assert_eq!(calls.len(), 1);
            let (binding, payload) = calls[0];
            assert_eq!(binding.lineage, expected_lineage);
            assert_eq!(binding.operation_generation, expected_generation);
            assert_eq!(binding.request_id, [95; 16]);
            assert_eq!(binding.operation_kind, OperationKind::Probe);
            assert_eq!(binding.phase, BackendPhase::Quarantined);
            assert_eq!(binding.action, BackendAction::Destroy);
            assert_eq!(
                payload.backend_generation,
                expected_lineage.backend_generation
            );
        }
        let state = engine.inner.state.lock().await;
        assert_eq!(
            state.contexts.get(&[7; 16]).map(|context| context.phase),
            Some(ContextPhase::Quarantined)
        );
        assert!(
            state
                .cleanup_pending
                .contains(&([7; 16], expected_generation))
        );
        assert!(state.in_flight.is_none());
    }

    #[tokio::test]
    async fn uncertain_acquire_error_quarantines_exact_lineage_and_returns_no_descriptor() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepared = commit_client_context(&engine, &backend).await;
        let (expected_lineage, expected_generation) = {
            let state = engine.inner.state.lock().await;
            let context = state.contexts.get(&[7; 16]).expect("Committed context");
            (
                context_backend_lineage([7; 16], context),
                context.generation,
            )
        };
        backend.fail_acquire_cleanup.store(true, Ordering::Release);
        backend.fail_destroy.store(true, Ordering::Release);
        let response = engine
            .execute(request(
                96,
                helper_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: prepared.context_handle,
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: volparossa_routing::TransportSocketKind::MptcpListener as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: None,
                }),
            ))
            .await;
        assert_eq!(response.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(response.diagnostic_code, "CLEANUP_INCOMPLETE");
        assert!(backend.transport_peers.lock().expect("peers").is_empty());
        {
            let calls = backend.destroy_calls.lock().expect("destroy calls");
            assert_eq!(calls.len(), 1);
            let (binding, payload) = calls[0];
            assert_eq!(binding.lineage, expected_lineage);
            assert_eq!(binding.operation_generation, expected_generation);
            assert_eq!(binding.request_id, [96; 16]);
            assert_eq!(binding.operation_kind, OperationKind::Acquire);
            assert_eq!(binding.phase, BackendPhase::Quarantined);
            assert_eq!(binding.action, BackendAction::Destroy);
            assert_eq!(
                payload.backend_generation,
                expected_lineage.backend_generation
            );
        }
        let state = engine.inner.state.lock().await;
        assert_eq!(
            state.contexts.get(&[7; 16]).map(|context| context.phase),
            Some(ContextPhase::Quarantined)
        );
        assert!(
            state
                .cleanup_pending
                .contains(&([7; 16], expected_generation))
        );
        assert!(state.in_flight.is_none());
        assert!(
            state
                .cache
                .get(&[96; 16])
                .is_some_and(|cached| cached.descriptor.is_none())
        );
    }

    #[tokio::test]
    async fn runtime_query_is_state_and_clock_mutation_free() {
        let engine = HelperEngine::with_components(
            [9; 32],
            1_000,
            Arc::new(FakeBackend::default()),
            Arc::new(FixedHandles(AtomicU64::new(0))),
            Arc::new(PanicClock),
        );
        let query = request(
            50,
            helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
                prepare_intent: None,
            }),
        );
        let response = engine.execute(query).await;
        assert_eq!(response.result, HelperResult::Ok as i32);
        assert_eq!(
            response.outcome,
            Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: vec![0xa5; 32],
            }))
        );
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.cache.is_empty());
        assert!(state.prepare_reconciliations.is_empty());
        assert!(state.reconciliation_request_ids.is_empty());
        assert!(state.cleanup_pending.is_empty());
        assert!(state.in_flight.is_none());
    }

    #[tokio::test]
    async fn missing_runtime_and_scope_substitution_never_prove_absence() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = prepare_request(51);

        clock.0.store(120, Ordering::Relaxed);
        let missing = engine
            .execute(reconcile_request_for(&prepare, 52, [0xa5; 32]))
            .await;
        assert_eq!(missing.result, HelperResult::Unavailable as i32);
        assert!(backend.destroyed.lock().expect("destroyed").is_empty());

        clock.0.store(100, Ordering::Relaxed);
        assert_eq!(
            engine.execute(bind_request_for(&prepare, 53)).await.result,
            HelperResult::Ok as i32
        );
        clock.0.store(120, Ordering::Relaxed);
        let wrong_runtime = engine
            .execute(reconcile_request_for(&prepare, 54, [0xb6; 32]))
            .await;
        assert_eq!(wrong_runtime.result, HelperResult::Unavailable as i32);

        let mut substituted = reconcile_request_for(&prepare, 55, [0xa5; 32]);
        let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
            substituted.operation.as_mut()
        else {
            panic!("Reconcile");
        };
        value.prepare_operation_digest[0] ^= 1;
        assert_eq!(
            engine.execute(substituted).await.result,
            HelperResult::Unavailable as i32
        );
        assert!(
            engine
                .inner
                .state
                .lock()
                .await
                .reconciliation_request_ids
                .is_empty(),
            "missing, wrong-runtime and wrong-scope requests must not consume lifetime IDs"
        );

        let exact = engine
            .execute(reconcile_request_for(&prepare, 56, [0xa5; 32]))
            .await;
        assert_eq!(exact.result, HelperResult::Ok as i32);
        assert!(backend.destroyed.lock().expect("destroyed").is_empty());
        assert_eq!(
            engine
                .inner
                .state
                .lock()
                .await
                .reconciliation_request_ids
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn equality_reconciliation_reaps_exact_owned_generation_and_is_idempotent() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = prepare_request(57);
        assert_eq!(
            execute_prepare(&engine, prepare.clone()).await.result,
            HelperResult::Ok as i32
        );

        clock.0.store(120, Ordering::Relaxed);
        let reconcile = reconcile_request_for(&prepare, 58, [0xa5; 32]);
        let first = engine.execute(reconcile.clone()).await;
        assert_eq!(first.result, HelperResult::Ok as i32);
        let Some(helper_response::Outcome::ReconciledExpiredPrepare(echo)) = first.outcome else {
            panic!("typed reconciliation");
        };
        let Some(helper_request::Operation::ReconcileExpiredPrepare(expected)) =
            reconcile.operation.as_ref()
        else {
            panic!("Reconcile");
        };
        assert_eq!(echo.helper_runtime_id, expected.helper_runtime_id);
        assert_eq!(echo.route_context_id, expected.route_context_id);
        assert_eq!(echo.prepare_request_id, expected.prepare_request_id);
        assert_eq!(
            echo.prepare_operation_digest,
            expected.prepare_operation_digest
        );
        assert_eq!(echo.setup_expires_at_unix, expected.setup_expires_at_unix);
        assert_eq!(echo.hard_expires_at_unix, expected.hard_expires_at_unix);
        assert_eq!(
            engine.execute(reconcile).await.result,
            HelperResult::Ok as i32
        );
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn reconciliation_is_target_specific_for_unrelated_expired_intent_and_cache() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(backend, Arc::clone(&clock));
        let first = prepare_request(59);
        let mut second = prepare_request(60);
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) = second.operation.as_mut()
        else {
            panic!("Prepare");
        };
        value.route_context_id = vec![8; 16];
        assert_eq!(
            engine.execute(bind_request_for(&first, 61)).await.result,
            HelperResult::Ok as i32
        );
        assert_eq!(
            engine.execute(bind_request_for(&second, 62)).await.result,
            HelperResult::Ok as i32
        );
        let before_cache = engine.inner.state.lock().await.cache.len();
        clock.0.store(120, Ordering::Relaxed);
        assert_eq!(
            engine
                .execute(reconcile_request_for(&first, 63, [0xa5; 32]))
                .await
                .result,
            HelperResult::Ok as i32
        );
        let state = engine.inner.state.lock().await;
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[8; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Intent)
        );
        assert_eq!(state.cache.len(), before_cache - 1);
        assert!(
            state
                .cache
                .values()
                .any(|cached| cached.context_id == Some([8; 16]))
        );
    }

    #[tokio::test]
    async fn successful_tag28_tombstone_rejects_same_outer_id_with_different_digest() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = prepare_request(79);
        assert_eq!(
            execute_prepare(&engine, prepare.clone()).await.result,
            HelperResult::Ok as i32
        );
        clock.0.store(120, Ordering::Relaxed);
        let reconcile = reconcile_request_for(&prepare, 80, [0xa5; 32]);
        assert_eq!(
            engine.execute(reconcile.clone()).await.result,
            HelperResult::Ok as i32
        );
        let mut substituted = reconcile;
        let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
            substituted.operation.as_mut()
        else {
            panic!("Reconcile");
        };
        value.hard_expires_at_unix += 1;
        let conflict = engine.execute(substituted).await;
        assert_eq!(conflict.result, HelperResult::InvalidRequest as i32);
        assert_eq!(conflict.diagnostic_code, "REQUEST_ID_CONFLICT");

        // A different operation cannot reuse a tag-28-reserved outer ID either.
        let cross_operation = engine
            .execute(request(
                80,
                helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
                    prepare_intent: None,
                }),
            ))
            .await;
        assert_eq!(cross_operation.result, HelperResult::InvalidRequest as i32);
        assert_eq!(cross_operation.diagnostic_code, "REQUEST_ID_CONFLICT");
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
        let state = engine.inner.state.lock().await;
        assert!(state.contexts.is_empty());
        assert_eq!(state.reconciliation_request_ids.len(), 1);
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn orphan_pending_cleanup_and_shutdown_retry_until_confirmed_absent() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), clock);
        let prepare = prepare_request(64);
        assert_eq!(
            engine.execute(bind_request_for(&prepare, 65)).await.result,
            HelperResult::Ok as i32
        );
        {
            let mut state = engine.inner.state.lock().await;
            let record = state
                .prepare_reconciliations
                .get_mut(&[7; 16])
                .expect("Prepare intent");
            record.phase = PrepareReconciliationPhase::Pending;
            let generation = record.backend_generation;
            state.cleanup_pending.insert(([7; 16], generation));
        }
        let cleanup = request(
            66,
            helper_request::Operation::CleanupOwned(volparossa_routing::CleanupOwned {
                cleanup_token: vec![9; 32],
            }),
        );
        assert_eq!(
            engine.execute(cleanup).await.result,
            HelperResult::CleanupIncomplete as i32
        );
        assert!(!engine.shutdown_cleanup().await);
        assert!(
            backend
                .runtime_bindings
                .lock()
                .expect("runtime bindings")
                .is_empty(),
            "an unconfirmed context destroy must not irreversibly fence the backend"
        );
        backend.fail_destroy.store(false, Ordering::Release);
        assert!(engine.shutdown_cleanup().await);
        assert_eq!(
            backend
                .runtime_bindings
                .lock()
                .expect("runtime bindings")
                .as_slice()
                .last()
                .map(|binding| binding.action),
            Some(BackendRuntimeAction::Shutdown)
        );
        let state = engine.inner.state.lock().await;
        assert!(cleanup_state_complete(&state));
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn cached_bind_ack_requires_the_exact_lineage_to_remain_intent() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(backend, clock);
        let prepare = prepare_request(67);
        let bind = bind_request_for(&prepare, 68);
        assert_eq!(
            engine.execute(bind.clone()).await.result,
            HelperResult::Ok as i32
        );
        assert_eq!(
            engine.execute(bind.clone()).await.result,
            HelperResult::Ok as i32
        );

        for phase in [
            PrepareReconciliationPhase::Pending,
            PrepareReconciliationPhase::Owned,
            PrepareReconciliationPhase::Absent,
        ] {
            engine
                .inner
                .state
                .lock()
                .await
                .prepare_reconciliations
                .get_mut(&[7; 16])
                .expect("Prepare lineage")
                .phase = phase;
            let response = engine.execute(bind.clone()).await;
            assert_eq!(response.result, HelperResult::Unavailable as i32);
            assert_eq!(response.diagnostic_code, "BIND_LINEAGE_UNAVAILABLE");
        }

        engine
            .inner
            .state
            .lock()
            .await
            .prepare_reconciliations
            .remove(&[7; 16]);
        assert_eq!(
            engine.execute(bind).await.result,
            HelperResult::Unavailable as i32
        );
    }

    #[tokio::test]
    async fn absent_proof_survives_old_prune_window_and_lost_response_retry() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = prepare_request(69);
        assert_eq!(
            execute_prepare(&engine, prepare.clone()).await.result,
            HelperResult::Ok as i32
        );
        clock.0.store(120, Ordering::Relaxed);
        let reconcile = reconcile_request_for(&prepare, 70, [0xa5; 32]);
        assert_eq!(
            engine.execute(reconcile.clone()).await.result,
            HelperResult::Ok as i32
        );

        // Drive an unrelated mutating prune path well beyond the former hard-expiry+30 window.
        clock.0.store(1_000, Ordering::Relaxed);
        let mut unrelated = prepare_request(71);
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) =
            unrelated.operation.as_mut()
        else {
            panic!("Prepare");
        };
        value.route_context_id = vec![8; 16];
        value.setup_expires_at_unix = 1_020;
        value.hard_expires_at_unix = 1_800;
        assert_eq!(
            engine
                .execute(bind_request_for(&unrelated, 72))
                .await
                .result,
            HelperResult::Ok as i32
        );

        // Model a lost first tag-28 response with the exact stable outer request ID and bytes.
        assert_eq!(
            engine.execute(reconcile).await.result,
            HelperResult::Ok as i32
        );
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]]
        );
        assert_eq!(
            engine
                .inner
                .state
                .lock()
                .await
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn tag28_retries_an_orphan_pending_generation_until_destroy_is_confirmed() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(Arc::clone(&backend), Arc::clone(&clock));
        let prepare = prepare_request(74);
        assert_eq!(
            engine.execute(bind_request_for(&prepare, 75)).await.result,
            HelperResult::Ok as i32
        );
        {
            let mut state = engine.inner.state.lock().await;
            let generation = {
                let record = state
                    .prepare_reconciliations
                    .get_mut(&[7; 16])
                    .expect("Prepare intent");
                record.phase = PrepareReconciliationPhase::Pending;
                record.backend_generation
            };
            state.cleanup_pending.insert(([7; 16], generation));
        }
        clock.0.store(120, Ordering::Relaxed);
        let reconcile = reconcile_request_for(&prepare, 76, [0xa5; 32]);
        assert_eq!(
            engine.execute(reconcile.clone()).await.result,
            HelperResult::CleanupIncomplete as i32
        );
        assert_eq!(
            engine
                .inner
                .state
                .lock()
                .await
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Pending)
        );
        backend.fail_destroy.store(false, Ordering::Release);
        assert_eq!(
            engine.execute(reconcile).await.result,
            HelperResult::Ok as i32
        );
        let state = engine.inner.state.lock().await;
        assert!(state.cleanup_pending.is_empty());
        assert_eq!(state.reconciliation_request_ids.len(), 1);
        assert_eq!(
            state
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Absent)
        );
    }

    #[tokio::test]
    async fn exact_tag28_retry_recomputes_after_cached_destroy_timeout_settles() {
        let backend = Arc::new(FakeBackend::default());
        backend.block_destroy.store(true, Ordering::Release);
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine_with_timeout(
            Arc::clone(&backend),
            Arc::clone(&clock),
            Duration::from_millis(20),
        );
        let prepare = prepare_request(81);
        assert_eq!(
            execute_prepare(&engine, prepare.clone()).await.result,
            HelperResult::Ok as i32
        );
        clock.0.store(120, Ordering::Relaxed);
        let reconcile = reconcile_request_for(&prepare, 82, [0xa5; 32]);

        let executing_engine = engine.clone();
        let first_request = reconcile.clone();
        let first = tokio::spawn(async move { executing_engine.execute(first_request).await });
        wait_for_destroy_entry(&backend).await;
        let ambiguous = tokio::time::timeout(Duration::from_millis(250), first)
            .await
            .expect("tag-28 ambiguity response")
            .expect("tag-28 task");
        assert_eq!(ambiguous.result, HelperResult::CleanupIncomplete as i32);
        assert_eq!(ambiguous.diagnostic_code, "BACKEND_RESULT_AMBIGUOUS");
        assert!(
            engine
                .inner
                .state
                .lock()
                .await
                .cache
                .contains_key(&[82; 16]),
            "timeout response must exercise the generic ambiguity cache"
        );

        backend.release_destroy();
        wait_for_supervisor_settlement(&engine).await;
        let retry = engine.execute(reconcile).await;
        assert_eq!(retry.result, HelperResult::Ok as i32);
        assert_eq!(
            backend.destroyed.lock().expect("destroyed").as_slice(),
            &[[7; 16]],
            "exact retry must prove the settled tombstone without a second destroy"
        );
    }

    #[tokio::test]
    async fn stale_cleanup_generation_leaves_newer_context_cache_and_pending_unchanged() {
        let backend = Arc::new(FakeBackend::default());
        let clock = Arc::new(FixedClock(AtomicU64::new(100)));
        let engine = fake_engine(backend, clock);
        let prepare = prepare_request(78);
        assert_eq!(
            execute_prepare(&engine, prepare).await.result,
            HelperResult::Ok as i32
        );
        let (generation, phase, handle, lineage, cache_ids, cleanup_pending) = {
            let mut state = engine.inner.state.lock().await;
            state.cleanup_pending.insert(([8; 16], 99));
            let context = state.contexts.get(&[7; 16]).expect("newer context");
            (
                context.generation,
                context.phase,
                context.handle,
                context_backend_lineage([7; 16], context),
                state.cache.keys().copied().collect::<BTreeSet<_>>(),
                state.cleanup_pending.clone(),
            )
        };
        let stale = OperationOwner {
            token: OperationToken {
                sequence: 999,
                request_id: [0xee; 16],
                digest: [0xdd; 32],
                context_id: [7; 16],
                generation: generation.saturating_sub(1),
                prior_phase: Some(ContextPhase::Prepared),
                kind: OperationKind::Cleanup,
            },
            lineage,
            call_deadline: Instant::now() + Duration::from_secs(1),
            armed: true,
        };
        assert!(!engine.mark_cleanup(&stale).await);
        engine.finish_cleanup(stale, true).await;

        let current = engine.inner.state.lock().await;
        let context = current
            .contexts
            .get(&[7; 16])
            .expect("newer context retained");
        assert_eq!(context.generation, generation);
        assert_eq!(context.phase, phase);
        assert_eq!(context.handle, handle);
        assert_eq!(
            current.cache.keys().copied().collect::<BTreeSet<_>>(),
            cache_ids
        );
        assert_eq!(current.cleanup_pending, cleanup_pending);
        assert_eq!(
            current
                .prepare_reconciliations
                .get(&[7; 16])
                .map(|record| record.phase),
            Some(PrepareReconciliationPhase::Owned)
        );
    }

    #[test]
    fn private_key_material_is_unrepresentable_in_engine_inputs() {
        let debug = format!("{:?}", prepare_request(1));
        assert!(!debug.contains("private_key"));
        assert!(!debug.contains("allowed_prefix"));
        assert!(!debug.contains("listen_port"));
    }

    #[test]
    fn backend_errors_are_distinct() {
        assert_ne!(BackendError::Invalid, BackendError::Kernel);
        assert_ne!(BackendError::Kernel, BackendError::CleanupIncomplete);
    }
}
