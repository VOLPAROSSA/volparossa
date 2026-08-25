//! Dormant single-writer actor for durable helper ownership.
//!
//! The actor is intentionally disconnected from production. It owns the journal and trusted
//! recovery executor on one named OS thread, exposes no revision/CAS surface, and never reopens a
//! store in the same process after its store-identity latch has been acquired.
//!
//! A recovery executor cannot be forcefully cancelled safely. If it exceeds the bounded reply
//! wait, admission becomes permanently ambiguous and the worker handle is detached instead of
//! joined. The process-lifetime latch remains set, the journal lock remains held while the worker
//! is stuck, and at most that already-accepted recovery may finish late; no later command runs.

use std::{
    fmt, fs,
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(not(test))]
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::{collections::BTreeSet, sync::OnceLock};

use volparossa_routing::PrepareIntent;

use super::{
    ClosedPlan, Id16, JournalConfig, JournalEpochId, JournalError, NewOwnershipIntent, OwnershipId,
    OwnershipJournal, OwnershipPhase, PrepareRecoveryAnchorV1, RecoveryAttemptError,
    RecoveryExecutor, RuntimeId, open_verified_parent,
};

const MAX_ACCEPTED_OPERATIONS: usize = 4;
const COMMAND_CHANNEL_CAPACITY: usize = MAX_ACCEPTED_OPERATIONS + 1;
const ACTOR_THREAD_NAME: &str = "volparossa-ownership-journal";
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
pub(super) enum DurableOwnershipError {
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
}

#[derive(Clone)]
pub(super) struct DurablePrepareIntent(NewOwnershipIntent);

impl DurablePrepareIntent {
    pub(super) fn try_from_wire(
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
        Ok(Self(NewOwnershipIntent {
            origin_runtime_id,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct DurablePrepareAnchorParts {
    pub(super) boot_id: [u8; 16],
    pub(super) pid: NonZeroU32,
    pub(super) process_start_ticks: NonZeroU64,
    pub(super) network_namespace_device: NonZeroU64,
    pub(super) network_namespace_inode: NonZeroU64,
    pub(super) executable_device: NonZeroU64,
    pub(super) executable_inode: NonZeroU64,
    pub(super) service_cgroup_inode: NonZeroU64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct DurablePrepareAnchor(PrepareRecoveryAnchorV1);

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
        }))
    }
}

impl fmt::Debug for DurablePrepareAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePrepareAnchor(<redacted>)")
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct DurableOwnershipKey {
    coordinates: OwnershipCoordinates,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OwnershipCoordinates {
    journal_epoch_id: JournalEpochId,
    ownership_id: OwnershipId,
    generation: NonZeroU64,
}

impl fmt::Debug for DurableOwnershipKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableOwnershipKey(<redacted>)")
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
        self.transition(Lifecycle::Ambiguous);
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
    sender: SyncSender<T>,
    lifecycle: Arc<LifecycleState>,
    armed: bool,
}

impl<T> ReplySender<T> {
    fn arm(&mut self) {
        self.armed = true;
    }

    fn complete(mut self, value: T) {
        self.armed = false;
        match self.sender.try_send(value) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => self.lifecycle.mark_ambiguous(),
        }
    }
}

impl<T> Drop for ReplySender<T> {
    fn drop(&mut self) {
        if self.armed {
            self.lifecycle.mark_ambiguous();
        }
    }
}

struct PendingReply<T> {
    receiver: Receiver<Result<T, DurableOwnershipError>>,
    lifecycle: Arc<LifecycleState>,
    admission: Arc<Admission>,
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
        match self.receiver.recv_timeout(REPLY_WAIT_LIMIT) {
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
}

fn reply_pair<T>(
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) -> (
    ReplySender<Result<T, DurableOwnershipError>>,
    PendingReply<T>,
) {
    let (sender, receiver) = sync_channel(1);
    (
        ReplySender {
            sender,
            lifecycle: Arc::clone(lifecycle),
            armed: false,
        },
        PendingReply {
            receiver,
            lifecycle: Arc::clone(lifecycle),
            admission: Arc::clone(admission),
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
                lifecycle.transition(terminal);
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
        intent: DurablePrepareIntent,
        reply: ReplySender<Result<DurableOwnershipKey, DurableOwnershipError>>,
    },
    Arm {
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
        reply: ReplySender<Result<(), DurableOwnershipError>>,
    },
    RetireNeverDispatched {
        key: OwnershipCoordinates,
        reply: ReplySender<Result<(), DurableOwnershipError>>,
    },
    ConfirmRecoveredAbsent {
        key: OwnershipCoordinates,
        reply: ReplySender<Result<(), DurableOwnershipError>>,
    },
    #[cfg(test)]
    PanicAfterRegister {
        intent: DurablePrepareIntent,
        reply: ReplySender<Result<DurableOwnershipKey, DurableOwnershipError>>,
    },
}

enum Command {
    Operation {
        operation: Operation,
        _permit: AdmissionPermit,
    },
    Shutdown {
        reply: ReplySender<Result<(), DurableOwnershipError>>,
    },
}

#[cfg_attr(test, derive(Clone))]
struct ActorClient {
    sender: SyncSender<Command>,
    admission: Arc<Admission>,
    lifecycle: Arc<LifecycleState>,
}

impl ActorClient {
    fn submit<T>(
        &self,
        build: impl FnOnce(ReplySender<Result<T, DurableOwnershipError>>) -> Operation,
    ) -> Result<PendingReply<T>, DurableOwnershipError> {
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
        self.admission
            .accepted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |accepted| {
                (accepted < MAX_ACCEPTED_OPERATIONS).then_some(accepted + 1)
            })
            .map_err(|_| DurableOwnershipError::Capacity)?;
        let permit = AdmissionPermit(Arc::clone(&self.admission));
        let (reply, pending) = reply_pair(&self.lifecycle, &self.admission);
        let command = Command::Operation {
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

    fn register_pending(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<PendingReply<DurableOwnershipKey>, DurableOwnershipError> {
        self.submit(|reply| Operation::Register { intent, reply })
    }

    fn arm_pending(
        &self,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(|reply| Operation::Arm { key, anchor, reply })
    }

    fn retire_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(|reply| Operation::RetireNeverDispatched { key, reply })
    }

    fn confirm_pending(
        &self,
        key: OwnershipCoordinates,
    ) -> Result<PendingReply<()>, DurableOwnershipError> {
        self.submit(|reply| Operation::ConfirmRecoveredAbsent { key, reply })
    }

    #[cfg(test)]
    fn panic_after_register_pending(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<PendingReply<DurableOwnershipKey>, DurableOwnershipError> {
        self.submit(|reply| Operation::PanicAfterRegister { intent, reply })
    }

    fn fence_and_shutdown(&self) -> Result<PendingReply<()>, DurableOwnershipError> {
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
        *accepting = false;
        self.lifecycle.transition(Lifecycle::Closing);
        let (reply, pending) = reply_pair(&self.lifecycle, &self.admission);
        match self.sender.try_send(Command::Shutdown { reply }) {
            Ok(()) => Ok(pending),
            Err(TrySendError::Full(command) | TrySendError::Disconnected(command)) => {
                drop(command);
                self.lifecycle.mark_ambiguous();
                Err(DurableOwnershipError::Ambiguous)
            }
        }
    }
}

pub(super) struct DurableOwnershipActor {
    client: Option<ActorClient>,
    join: Option<JoinHandle<()>>,
    completion: Option<Receiver<()>>,
    lifecycle: Arc<LifecycleState>,
}

impl DurableOwnershipActor {
    pub(super) fn spawn_with_executor_factory<ExecutorFactory, Executor>(
        config: JournalConfig,
        executor_factory: ExecutorFactory,
    ) -> Result<Self, DurableOwnershipError>
    where
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: RecoveryExecutor + Send + 'static,
    {
        Self::spawn_inner(config, || {}, executor_factory)
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
        Executor: RecoveryExecutor + Send + 'static,
    {
        Self::spawn_inner(config, startup_hook, executor_factory)
    }

    fn spawn_inner<StartupHook, ExecutorFactory, Executor>(
        config: JournalConfig,
        startup_hook: StartupHook,
        executor_factory: ExecutorFactory,
    ) -> Result<Self, DurableOwnershipError>
    where
        StartupHook: FnOnce() + Send + 'static,
        ExecutorFactory: FnOnce() -> Executor + Send + 'static,
        Executor: RecoveryExecutor + Send + 'static,
    {
        let lifecycle = Arc::new(LifecycleState::new());
        let admission = Arc::new(Admission::new());
        let (sender, receiver) = sync_channel(COMMAND_CHANNEL_CAPACITY);
        let client = ActorClient {
            sender,
            admission,
            lifecycle: Arc::clone(&lifecycle),
        };
        let (startup_reply, startup_pending) = reply_pair(&lifecycle, &client.admission);
        let (completion_sender, completion_receiver) = sync_channel(1);
        let thread_lifecycle = Arc::clone(&lifecycle);
        let thread_admission = Arc::clone(&client.admission);
        let join = thread::Builder::new()
            .name(ACTOR_THREAD_NAME.to_owned())
            .spawn(move || {
                let _completion = ThreadCompletionGuard(Some(completion_sender));
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    actor_thread(
                        config,
                        startup_hook,
                        executor_factory,
                        &receiver,
                        startup_reply,
                        &thread_lifecycle,
                        &thread_admission,
                    );
                }));
                if outcome.is_err() {
                    thread_admission.fence_terminal(&thread_lifecycle, Lifecycle::Ambiguous);
                }
            })
            .map_err(|_| DurableOwnershipError::Unavailable)?;
        match startup_pending.wait() {
            Ok(()) => Ok(Self {
                client: Some(client),
                join: Some(join),
                completion: Some(completion_receiver),
                lifecycle,
            }),
            Err(error) => {
                drop(client);
                if settle_thread(join, &completion_receiver, &lifecycle).is_err() {
                    Err(DurableOwnershipError::Ambiguous)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub(super) fn register_intent(
        &self,
        intent: DurablePrepareIntent,
    ) -> Result<DurableOwnershipKey, DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .register_pending(intent)?
            .wait()
    }

    pub(super) fn arm_prepare(
        &self,
        key: &DurableOwnershipKey,
        anchor: DurablePrepareAnchor,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .arm_pending(key.coordinates, anchor)?
            .wait()
    }

    pub(super) fn retire_never_dispatched(
        &self,
        key: &DurableOwnershipKey,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .retire_pending(key.coordinates)?
            .wait()
    }

    pub(super) fn confirm_recovered_absent(
        &self,
        key: &DurableOwnershipKey,
    ) -> Result<(), DurableOwnershipError> {
        self.client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .confirm_pending(key.coordinates)?
            .wait()
    }

    pub(super) fn shutdown(mut self) -> Result<(), DurableOwnershipError> {
        let pending = self
            .client
            .as_ref()
            .ok_or(DurableOwnershipError::Unavailable)?
            .fence_and_shutdown();
        let reply = pending.and_then(PendingReply::wait);
        self.client.take();
        let settled = self.settle_thread();
        reply.and(settled)
    }

    fn settle_thread(&mut self) -> Result<(), DurableOwnershipError> {
        let join = self.join.take().ok_or(DurableOwnershipError::Unavailable)?;
        let completion = self
            .completion
            .take()
            .ok_or(DurableOwnershipError::Unavailable)?;
        settle_thread(join, &completion, &self.lifecycle)
    }
}

impl Drop for DurableOwnershipActor {
    fn drop(&mut self) {
        let reply = self
            .client
            .as_ref()
            .map_or(Ok(None), |client| client.fence_and_shutdown().map(Some));
        if let Ok(Some(pending)) = reply {
            let _ = pending.wait();
        }
        self.client.take();
        if let (Some(join), Some(completion)) = (self.join.take(), self.completion.take()) {
            let _ = settle_thread(join, &completion, &self.lifecycle);
        }
    }
}

fn settle_thread(
    join: JoinHandle<()>,
    completion: &Receiver<()>,
    lifecycle: &LifecycleState,
) -> Result<(), DurableOwnershipError> {
    if completion
        .recv_timeout(THREAD_COMPLETION_WAIT_LIMIT)
        .is_err()
    {
        lifecycle.mark_ambiguous();
        drop(join);
        return Err(DurableOwnershipError::Ambiguous);
    }
    let deadline = Instant::now() + THREAD_COMPLETION_WAIT_LIMIT;
    while !join.is_finished() && Instant::now() < deadline {
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

struct ActorCore<Executor> {
    journal: OwnershipJournal,
    executor: Executor,
    revision: u64,
}

impl<Executor: RecoveryExecutor> ActorCore<Executor> {
    fn new(journal: OwnershipJournal, executor: Executor) -> Result<Self, FailureDisposition> {
        let revision = journal
            .snapshot()
            .map_err(|error| classify_without_healthcheck(&error))?
            .revision;
        Ok(Self {
            journal,
            executor,
            revision,
        })
    }

    fn startup_sweep(&mut self) -> Result<(), FailureDisposition> {
        let snapshot = match self.journal.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.classify_journal_error(error)),
        };
        let pending = snapshot
            .records
            .values()
            .filter_map(|record| {
                matches!(
                    record.phase,
                    OwnershipPhase::Intent | OwnershipPhase::MayOwnPrepare
                )
                .then_some((record.ownership_id, record.generation, record.phase))
            })
            .collect::<Vec<_>>();
        for (ownership_id, generation, phase) in pending {
            match phase {
                OwnershipPhase::Intent => {
                    self.revision = self
                        .journal
                        .mark_intent_absent(self.revision, ownership_id, generation)
                        .map_err(|error| self.classify_journal_error(error))?;
                }
                OwnershipPhase::MayOwnPrepare => {
                    self.revision = match self.journal.recover_may_own_prepare(
                        self.revision,
                        ownership_id,
                        generation,
                        &mut self.executor,
                    ) {
                        Ok(revision) => revision,
                        Err(RecoveryAttemptError::Executor(_)) => {
                            return Err(FailureDisposition::Continue(
                                DurableOwnershipError::RecoveryNotConfirmed,
                            ));
                        }
                        Err(RecoveryAttemptError::Journal(error)) => {
                            return Err(self.classify_journal_error(error));
                        }
                    };
                }
                OwnershipPhase::Absent => {}
            }
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

    fn register(&mut self, intent: DurablePrepareIntent) -> OperationOutcome<DurableOwnershipKey> {
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
                        ownership_id: inserted.ownership_id,
                        generation: inserted.generation,
                    },
                }))
            }
            Err(error) => OperationOutcome::failure(self.classify_journal_error(error)),
        }
    }

    fn arm(
        &mut self,
        key: OwnershipCoordinates,
        anchor: DurablePrepareAnchor,
    ) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.mark_may_own_prepare(
            self.revision,
            key.ownership_id,
            key.generation,
            anchor.0,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
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

    fn confirm(&mut self, key: OwnershipCoordinates) -> OperationOutcome<()> {
        if let Err(error) = self.validate_key(key) {
            return OperationOutcome::failure(error);
        }
        match self.journal.recover_may_own_prepare(
            self.revision,
            key.ownership_id,
            key.generation,
            &mut self.executor,
        ) {
            Ok(revision) => {
                self.revision = revision;
                OperationOutcome::Complete(Ok(()))
            }
            Err(RecoveryAttemptError::Executor(_)) => {
                OperationOutcome::Complete(Err(DurableOwnershipError::RecoveryNotConfirmed))
            }
            Err(RecoveryAttemptError::Journal(error)) => {
                OperationOutcome::failure(self.classify_journal_error(error))
            }
        }
    }

    fn confirm_complete_boundary(&mut self) -> Result<(), DurableOwnershipError> {
        self.journal
            .confirm_retry_safe_after_definite_failure()
            .map_err(|_| DurableOwnershipError::Ambiguous)
    }

    fn validate_key(&mut self, key: OwnershipCoordinates) -> Result<(), FailureDisposition> {
        match self.journal.snapshot() {
            Ok(snapshot) if snapshot.journal_epoch_id == key.journal_epoch_id => Ok(()),
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

fn actor_thread<StartupHook, ExecutorFactory, Executor>(
    config: JournalConfig,
    startup_hook: StartupHook,
    executor_factory: ExecutorFactory,
    receiver: &Receiver<Command>,
    mut startup_reply: ReplySender<Result<(), DurableOwnershipError>>,
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) where
    StartupHook: FnOnce(),
    ExecutorFactory: FnOnce() -> Executor,
    Executor: RecoveryExecutor,
{
    startup_reply.arm();
    let parent_directory = match open_verified_parent(&config) {
        Ok(parent_directory) => parent_directory,
        Err(error) => {
            let failure = classify_startup_error(&error);
            let (error, terminal) = terminal_start_failure(failure);
            lifecycle.transition(terminal);
            startup_reply.complete(Err(error));
            return;
        }
    };
    let store = match derive_store_identity(&config, &parent_directory) {
        Ok(store) => store,
        Err(error) => {
            lifecycle.transition(Lifecycle::Unavailable);
            startup_reply.complete(Err(error));
            return;
        }
    };
    if let Err(error) = acquire_start_latch(&store, &parent_directory) {
        lifecycle.transition(if error == DurableOwnershipError::Ambiguous {
            Lifecycle::Ambiguous
        } else {
            Lifecycle::Unavailable
        });
        startup_reply.complete(Err(error));
        return;
    }
    startup_hook();
    let journal = match OwnershipJournal::open_with_verified_parent(config, parent_directory) {
        Ok(journal) => journal,
        Err(error) => {
            let failure = classify_startup_error(&error);
            let (error, terminal) = terminal_start_failure(failure);
            lifecycle.transition(terminal);
            startup_reply.complete(Err(error));
            return;
        }
    };
    let executor = executor_factory();
    let mut core = match ActorCore::new(journal, executor) {
        Ok(core) => core,
        Err(failure) => {
            let (error, terminal) = terminal_start_failure(failure);
            lifecycle.transition(terminal);
            startup_reply.complete(Err(error));
            return;
        }
    };
    if let Err(failure) = core.startup_sweep() {
        let (error, terminal) = terminal_start_failure(failure);
        lifecycle.transition(terminal);
        startup_reply.complete(Err(error));
        return;
    }
    if core.confirm_complete_boundary().is_err() {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        startup_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    if lifecycle.load() != Lifecycle::Starting {
        admission.fence_terminal(lifecycle, Lifecycle::Ambiguous);
        startup_reply.complete(Err(DurableOwnershipError::Ambiguous));
        return;
    }
    lifecycle.transition(Lifecycle::Running);
    startup_reply.complete(Ok(()));

    while let Ok(command) = receiver.recv() {
        match command {
            Command::Operation { operation, _permit } => {
                if process_operation(&mut core, operation, lifecycle, admission) {
                    return;
                }
            }
            Command::Shutdown { mut reply } => {
                reply.arm();
                match core.confirm_complete_boundary() {
                    Ok(()) => {
                        lifecycle.transition(Lifecycle::Stopped);
                        reply.complete(Ok(()));
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

fn terminal_start_failure(failure: FailureDisposition) -> (DurableOwnershipError, Lifecycle) {
    match failure {
        FailureDisposition::Continue(error) => (error, Lifecycle::Unavailable),
        FailureDisposition::Stop(error, lifecycle) => (error, lifecycle),
    }
}

fn process_operation<Executor: RecoveryExecutor>(
    core: &mut ActorCore<Executor>,
    operation: Operation,
    lifecycle: &Arc<LifecycleState>,
    admission: &Arc<Admission>,
) -> bool {
    match operation {
        Operation::Register { intent, mut reply } => {
            reply.arm();
            finish_operation(reply, core.register(intent), lifecycle, admission)
        }
        Operation::Arm {
            key,
            anchor,
            mut reply,
        } => {
            reply.arm();
            finish_operation(reply, core.arm(key, anchor), lifecycle, admission)
        }
        Operation::RetireNeverDispatched { key, mut reply } => {
            reply.arm();
            finish_operation(reply, core.retire(key), lifecycle, admission)
        }
        Operation::ConfirmRecoveredAbsent { key, mut reply } => {
            reply.arm();
            finish_operation(reply, core.confirm(key), lifecycle, admission)
        }
        #[cfg(test)]
        Operation::PanicAfterRegister { intent, mut reply } => {
            reply.arm();
            match core.register(intent) {
                OperationOutcome::Complete(Ok(_)) => {
                    panic!("injected panic after durable ownership registration")
                }
                outcome => finish_operation(reply, outcome, lifecycle, admission),
            }
        }
    }
}

fn finish_operation<T>(
    reply: ReplySender<Result<T, DurableOwnershipError>>,
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
mod tests;
