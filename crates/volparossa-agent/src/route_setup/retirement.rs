//! Bounded, non-blocking publication of helper context retirement ownership.

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    endpoint_leases::LocalEndpointLeaseBatch,
    helper::{PrepareReconciliationAuthority, RuntimeBoundPreparedLeaseBatch},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval, timeout},
};

use super::{ClientReservationProtocol, LocalRouteBackend};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetirementOutcome {
    Destroyed { released_local_leases: usize },
    Quarantined,
}

#[derive(Debug)]
pub(super) struct RetirementState {
    outstanding: AtomicUsize,
    quarantined: AtomicUsize,
    ambiguous: AtomicUsize,
    worker_alive: AtomicBool,
    fail_stopped: AtomicBool,
    #[cfg(test)]
    armed_job_drop_fail_stopped: AtomicBool,
}

impl RetirementState {
    fn new() -> Self {
        Self {
            outstanding: AtomicUsize::new(0),
            quarantined: AtomicUsize::new(0),
            ambiguous: AtomicUsize::new(0),
            worker_alive: AtomicBool::new(true),
            fail_stopped: AtomicBool::new(false),
            #[cfg(test)]
            armed_job_drop_fail_stopped: AtomicBool::new(false),
        }
    }

    pub(super) fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    pub(super) fn quarantined(&self) -> usize {
        self.quarantined.load(Ordering::Acquire)
    }

    pub(super) fn ambiguous(&self) -> usize {
        self.ambiguous.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn worker_alive(&self) -> bool {
        self.worker_alive.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn fail_stopped(&self) -> bool {
        self.fail_stopped.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn armed_job_drop_fail_stopped(&self) -> bool {
        self.armed_job_drop_fail_stopped.load(Ordering::Acquire)
    }
}

struct RetirementSlot {
    _permit: OwnedSemaphorePermit,
    state: Arc<RetirementState>,
}

impl Drop for RetirementSlot {
    fn drop(&mut self) {
        let previous = self.state.outstanding.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

enum CleanupTarget {
    Exact(Arc<Mutex<RuntimeBoundPreparedLeaseBatch>>),
    AmbiguousPrepare {
        authority: PrepareReconciliationAuthority,
        not_before: Instant,
    },
}

struct RetirementJob<P> {
    target: CleanupTarget,
    endpoints: Option<LocalEndpointLeaseBatch>,
    protocol: P,
    reservation_id: [u8; 16],
    slot: RetirementSlot,
    reply: Option<oneshot::Sender<RetirementOutcome>>,
    quarantined: bool,
    ambiguous_prepare: bool,
    armed: bool,
}

impl<P> RetirementJob<P> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<P> Drop for RetirementJob<P> {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(test)]
            self.slot
                .state
                .armed_job_drop_fail_stopped
                .store(true, Ordering::Release);
            publication_fail_stop(&self.slot.state);
        }
    }
}

pub(super) struct RetirementSink<P> {
    sender: mpsc::UnboundedSender<RetirementJob<P>>,
    slots: Arc<Semaphore>,
    state: Arc<RetirementState>,
    shutdown: watch::Receiver<bool>,
}

impl<P> Clone for RetirementSink<P> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            slots: Arc::clone(&self.slots),
            state: Arc::clone(&self.state),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<P> RetirementSink<P> {
    pub(super) async fn reserve(&self) -> Result<RetirementReservation<P>, ()> {
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return Err(());
        }
        let permit = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                return Err(());
            }
            permit = Arc::clone(&self.slots).acquire_owned() => permit.map_err(|_| ())?,
        };
        self.state.outstanding.fetch_add(1, Ordering::AcqRel);
        let slot = RetirementSlot {
            _permit: permit,
            state: Arc::clone(&self.state),
        };
        if *shutdown.borrow() {
            drop(slot);
            return Err(());
        }
        Ok(RetirementReservation {
            sink: self.clone(),
            slot: Some(slot),
        })
    }

    fn publish(&self, job: RetirementJob<P>) {
        if let Err(error) = self.sender.send(job) {
            let failed_job = error.0;
            publication_fail_stop(&self.state);
            drop(failed_job);
        }
    }

    pub(super) fn state(&self) -> &Arc<RetirementState> {
        &self.state
    }

    pub(super) fn fail_stop(&self) {
        publication_fail_stop(&self.state);
    }
}

pub(super) struct RetirementReservation<P> {
    sink: RetirementSink<P>,
    slot: Option<RetirementSlot>,
}

impl<P> RetirementReservation<P> {
    pub(super) fn bind(
        mut self,
        prepared: RuntimeBoundPreparedLeaseBatch,
        protocol: P,
        reservation_id: [u8; 16],
    ) -> PreparedContextOwner<P> {
        PreparedContextOwner {
            sink: self.sink.clone(),
            job: Some(RetirementJob {
                target: CleanupTarget::Exact(Arc::new(Mutex::new(prepared))),
                endpoints: None,
                protocol,
                reservation_id,
                slot: self.slot.take().expect("retirement slot is single-use"),
                reply: None,
                quarantined: false,
                ambiguous_prepare: false,
                armed: true,
            }),
        }
    }

    pub(super) fn bind_ambiguous_prepare(
        mut self,
        authority: PrepareReconciliationAuthority,
        protocol: P,
        reservation_id: [u8; 16],
        not_before: Instant,
    ) -> PreparedContextOwner<P> {
        self.sink.state.ambiguous.fetch_add(1, Ordering::AcqRel);
        PreparedContextOwner {
            sink: self.sink.clone(),
            job: Some(RetirementJob {
                target: CleanupTarget::AmbiguousPrepare {
                    authority,
                    not_before,
                },
                endpoints: None,
                protocol,
                reservation_id,
                slot: self.slot.take().expect("retirement slot is single-use"),
                reply: None,
                quarantined: false,
                ambiguous_prepare: true,
                armed: true,
            }),
        }
    }
}

pub(super) struct PreparedContextOwner<P> {
    sink: RetirementSink<P>,
    job: Option<RetirementJob<P>>,
}

impl<P> PreparedContextOwner<P> {
    pub(super) fn runtime_owner(&self) -> Option<Arc<Mutex<RuntimeBoundPreparedLeaseBatch>>> {
        let job = self.job.as_ref()?;
        match &job.target {
            CleanupTarget::Exact(owner) => Some(Arc::clone(owner)),
            CleanupTarget::AmbiguousPrepare { .. } => None,
        }
    }

    pub(super) fn attach_endpoints(
        &mut self,
        endpoints: LocalEndpointLeaseBatch,
    ) -> Result<(), ()> {
        let job = self.job.as_mut().ok_or(())?;
        if job.endpoints.is_some() {
            return Err(());
        }
        job.endpoints = Some(endpoints);
        Ok(())
    }

    pub(super) fn endpoints(&self) -> Option<&LocalEndpointLeaseBatch> {
        self.job.as_ref().and_then(|job| job.endpoints.as_ref())
    }

    pub(super) fn protocol(&self) -> Option<&P> {
        self.job.as_ref().map(|job| &job.protocol)
    }

    pub(super) fn protocol_mut(&mut self) -> Option<&mut P> {
        self.job.as_mut().map(|job| &mut job.protocol)
    }

    pub(super) fn protocol_and_endpoints_mut(
        &mut self,
    ) -> Option<(&mut P, &LocalEndpointLeaseBatch)> {
        let job = self.job.as_mut()?;
        Some((&mut job.protocol, job.endpoints.as_ref()?))
    }

    pub(super) async fn retire(mut self) -> RetirementOutcome {
        let (reply, response) = oneshot::channel();
        let mut job = self.job.take().expect("prepared owner is single-use");
        job.reply = Some(reply);
        self.sink.publish(job);
        response.await.unwrap_or_else(|_| {
            publication_fail_stop(self.sink.state());
            RetirementOutcome::Quarantined
        })
    }
}

impl<P> Drop for PreparedContextOwner<P> {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            self.sink.publish(job);
        }
    }
}

pub(super) struct RetirementSupervisor<P> {
    sink: RetirementSink<P>,
    shutdown: watch::Sender<bool>,
    worker: JoinHandle<()>,
}

impl<P> RetirementSupervisor<P>
where
    P: ClientReservationProtocol,
{
    pub(super) fn start<L>(
        backend: L,
        capacity: usize,
        destroy_timeout: Duration,
    ) -> Result<Self, ()>
    where
        L: LocalRouteBackend,
    {
        if capacity == 0 || destroy_timeout.is_zero() {
            return Err(());
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let state = Arc::new(RetirementState::new());
        let sink = RetirementSink {
            sender,
            slots: Arc::new(Semaphore::new(capacity)),
            state: Arc::clone(&state),
            shutdown: shutdown_receiver.clone(),
        };
        let guard = WorkerGuard::new(Arc::clone(&state));
        let worker = tokio::spawn(run_worker::<P, L>(
            receiver,
            shutdown_receiver,
            backend,
            destroy_timeout,
            Arc::clone(&state),
            guard,
        ));
        Ok(Self {
            sink,
            shutdown,
            worker,
        })
    }

    pub(super) fn sink(&self) -> RetirementSink<P> {
        self.sink.clone()
    }

    pub(super) async fn shutdown(self) -> Result<(), ()> {
        let Self {
            sink,
            shutdown,
            worker,
        } = self;
        let state = Arc::clone(sink.state());
        let _ = shutdown.send(true);
        drop(shutdown);
        drop(sink);
        worker.await.map_err(|_| ())?;
        if state.fail_stopped.load(Ordering::Acquire) {
            return Err(());
        }
        Ok(())
    }

    pub(super) fn state(&self) -> &Arc<RetirementState> {
        self.sink.state()
    }

    #[cfg(test)]
    pub(super) fn terminate_worker_for_test(&self) {
        self.worker.abort();
    }
}

struct WorkerGuard {
    state: Arc<RetirementState>,
    armed: bool,
}

impl WorkerGuard {
    fn new(state: Arc<RetirementState>) -> Self {
        Self { state, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.state.worker_alive.store(false, Ordering::Release);
        if self.armed {
            publication_fail_stop(&self.state);
        }
    }
}

async fn run_worker<P, L>(
    mut receiver: mpsc::UnboundedReceiver<RetirementJob<P>>,
    mut shutdown: watch::Receiver<bool>,
    mut backend: L,
    destroy_timeout: Duration,
    state: Arc<RetirementState>,
    mut guard: WorkerGuard,
) where
    P: ClientReservationProtocol,
    L: LocalRouteBackend,
{
    let mut retry = interval(RETRY_INTERVAL);
    retry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut quarantine = VecDeque::new();
    let mut receiver_closed = false;
    let mut shutdown_requested = *shutdown.borrow();

    loop {
        if (receiver_closed || shutdown_requested)
            && quarantine.is_empty()
            && state.outstanding() == 0
        {
            receiver.close();
            guard.disarm();
            break;
        }
        tokio::select! {
            maybe = receiver.recv(), if !receiver_closed => {
                match maybe {
                    Some(job) => process_job(
                        job,
                        &mut backend,
                        destroy_timeout,
                        &state,
                        &mut quarantine,
                    ).await,
                    None => receiver_closed = true,
                }
            }
            changed = shutdown.changed(), if !shutdown_requested => {
                shutdown_requested = changed.is_err() || *shutdown.borrow();
            }
            _ = retry.tick(), if shutdown_requested || receiver_closed || !quarantine.is_empty() => {
                if let Some(job) = quarantine.pop_front() {
                    process_job(
                        job,
                        &mut backend,
                        destroy_timeout,
                        &state,
                        &mut quarantine,
                    ).await;
                }
            }
        }
    }
}

async fn process_job<P, L>(
    mut job: RetirementJob<P>,
    backend: &mut L,
    destroy_timeout: Duration,
    state: &Arc<RetirementState>,
    quarantine: &mut VecDeque<RetirementJob<P>>,
) where
    P: ClientReservationProtocol,
    L: LocalRouteBackend,
{
    if matches!(
        &job.target,
        CleanupTarget::AmbiguousPrepare { not_before, .. } if Instant::now() < *not_before
    ) {
        quarantine.push_back(job);
        return;
    }
    let confirmed = match &job.target {
        CleanupTarget::Exact(owner) => {
            let owner = owner.lock().await;
            matches!(
                timeout(destroy_timeout, backend.destroy(&owner)).await,
                Ok(Ok(_))
            )
        }
        CleanupTarget::AmbiguousPrepare { authority, .. } => {
            let reconciled = timeout(
                destroy_timeout,
                backend.reconcile_expired_prepare(authority),
            )
            .await;
            matches!(
                reconciled,
                Ok(Ok(ref receipt)) if authority.matches_reconciled(receipt)
            )
        }
    };
    if confirmed {
        if job.quarantined {
            state.quarantined.fetch_sub(1, Ordering::AcqRel);
        }
        if job.ambiguous_prepare {
            state.ambiguous.fetch_sub(1, Ordering::AcqRel);
        }
        let released = job.protocol.release(job.reservation_id);
        let _ = job.endpoints.take();
        if let Some(reply) = job.reply.take() {
            let _ = reply.send(RetirementOutcome::Destroyed {
                released_local_leases: released,
            });
        }
        job.disarm();
    } else {
        if !job.quarantined {
            job.quarantined = true;
            state.quarantined.fetch_add(1, Ordering::AcqRel);
            if let Some(reply) = job.reply.take() {
                let _ = reply.send(RetirementOutcome::Quarantined);
            }
        }
        quarantine.push_back(job);
    }
}

fn publication_fail_stop(state: &RetirementState) {
    state.fail_stopped.store(true, Ordering::Release);
    #[cfg(not(test))]
    std::process::abort();
}
