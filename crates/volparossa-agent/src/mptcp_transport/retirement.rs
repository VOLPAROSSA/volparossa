//! Route-owned, bounded retirement of issued flow capabilities. No detached cleanup task.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::Shutdown,
    os::fd::OwnedFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use rand_core::{OsRng, RngCore};
use socket2::SockRef;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use volparossa_routing::{HelperResult, RetireMptcpFlow};

use super::MptcpTransportError;
use crate::helper::{HelperClient, HelperClientError};

const MAX_FLOWS: usize = 64;

#[derive(Clone)]
pub(super) struct Retirements(Arc<State>);

struct State {
    pending: Mutex<VecDeque<Pending>>,
    flushing: AsyncMutex<()>,
    slots: Arc<Semaphore>,
    acquire_unconfirmed: AtomicBool,
}

struct Pending {
    request: RetireMptcpFlow,
    request_id: [u8; 16],
    descriptor: OwnedFd,
    _slot: OwnedSemaphorePermit,
}

pub(super) struct Reservation {
    owner: Retirements,
    slot: Option<OwnedSemaphorePermit>,
    acquire_started: bool,
}

pub(crate) struct Guard {
    owner: Retirements,
    pending: Option<Pending>,
}

impl Retirements {
    pub(super) fn new() -> Self {
        Self(Arc::new(State {
            pending: Mutex::new(VecDeque::new()),
            flushing: AsyncMutex::new(()),
            slots: Arc::new(Semaphore::new(MAX_FLOWS)),
            acquire_unconfirmed: AtomicBool::new(false),
        }))
    }

    pub(super) fn reserve(&self) -> io::Result<Reservation> {
        if self.0.acquire_unconfirmed.load(Ordering::Acquire) {
            return Err(io::Error::other("MPTCP acquire requires route retirement"));
        }
        let slot = self
            .0
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::other("MPTCP flow retirement capacity pending"))?;
        Ok(Reservation {
            owner: self.clone(),
            slot: Some(slot),
            acquire_started: false,
        })
    }

    pub(super) async fn drain(&self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
        self.drain_with(|request, id, descriptor| helper.retire_mptcp_flow(request, id, descriptor))
            .await
    }

    async fn drain_with<F, Fut>(&self, mut retire: F) -> Result<(), MptcpTransportError>
    where
        F: FnMut(RetireMptcpFlow, [u8; 16], OwnedFd) -> Fut,
        Fut: Future<Output = Result<(), HelperClientError>>,
    {
        let _serial = self.0.flushing.lock().await;
        if self.0.acquire_unconfirmed.load(Ordering::Acquire) {
            return Err(MptcpTransportError::AcquireUnconfirmed);
        }
        loop {
            // The original remains queued until the correlated ACK. Cancellation cannot
            // lose ownership; retries use the SAME request ID and descriptor identity.
            let next = {
                let pending = self
                    .0
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending
                    .front()
                    .map(|entry| {
                        Ok::<_, io::Error>((
                            entry.request.clone(),
                            entry.request_id,
                            entry.descriptor.try_clone()?,
                        ))
                    })
                    .transpose()?
            };
            let Some((request, id, descriptor)) = next else {
                return Ok(());
            };
            match retire(request, id, descriptor).await {
                Ok(()) | Err(HelperClientError::Rejected(HelperResult::NotFound)) => {
                    // NotFound also proves the old capability cannot authorize mutations;
                    // it may follow full context destruction. It is not a payload receipt.
                    let mut pending = self
                        .0
                        .pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let done = pending
                        .pop_front()
                        .expect("serialized retirement still queued");
                    debug_assert_eq!(done.request_id, id);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Reservation {
    pub(super) fn begin_acquire(&mut self) {
        self.acquire_started = true;
    }

    pub(super) fn bind(mut self, request: RetireMptcpFlow, descriptor: OwnedFd) -> Guard {
        let mut request_id = [0; 16];
        OsRng.fill_bytes(&mut request_id);
        self.acquire_started = false;
        Guard {
            owner: self.owner.clone(),
            pending: Some(Pending {
                request,
                request_id,
                descriptor,
                _slot: self.slot.take().expect("reserved flow slot"),
            }),
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.acquire_started {
            // The helper may have issued a capability before its FD response was lost.
            // Do not retry on this route or pretend an unknown flow was retired. The route
            // owner must destroy the exact context, immediately on error or next use after
            // caller cancellation; its existing hard expiry still owns abandoned contexts.
            self.owner
                .0
                .acquire_unconfirmed
                .store(true, Ordering::Release);
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            // The duplicate cannot keep application traffic alive while awaiting the next
            // route-owned flush. The helper independently verifies identity and shuts down
            // the presented socket before acknowledging retirement.
            let _ = SockRef::from(&pending.descriptor).shutdown(Shutdown::Both);
            let mut queue = self
                .owner
                .0
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(queue.len() < MAX_FLOWS);
            queue.push_back(pending);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read as _, os::unix::net::UnixStream, time::Duration};

    fn pair(owner: &Retirements) -> (Guard, UnixStream) {
        let (socket, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let guard = owner.reserve().unwrap().bind(
            RetireMptcpFlow {
                route_context_id: vec![1; 16],
                context_handle: vec![2; 32],
                mptcp_flow_handle: vec![3; 32],
            },
            socket.into(),
        );
        (guard, peer)
    }

    #[tokio::test]
    async fn cancelled_acquire_requires_context_retirement_before_reuse() {
        let owner = Retirements::new();
        let mut slot = owner.reserve().unwrap();
        slot.begin_acquire();
        drop(slot);
        assert!(owner.reserve().is_err());
        assert!(matches!(
            owner
                .drain_with(|_, _, _| async { panic!("no fabricated retirement") })
                .await,
            Err(MptcpTransportError::AcquireUnconfirmed)
        ));
    }

    #[tokio::test]
    async fn completed_flows_reuse_bounded_slots_but_live_flows_do_not() {
        let owner = Retirements::new();
        for _ in 0..130 {
            let (guard, mut peer) = pair(&owner);
            drop(guard);
            // Real local descriptor EOF, not a simulated socket or an MPTCP claim.
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            owner.drain_with(|_, _, _| async { Ok(()) }).await.unwrap();
            assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
        }
        let held = (0..MAX_FLOWS).map(|_| pair(&owner)).collect::<Vec<_>>();
        assert!(owner.reserve().is_err());
        drop(held);
        assert!(
            owner.reserve().is_err(),
            "queued work still reserves its slot"
        );
        owner.drain_with(|_, _, _| async { Ok(()) }).await.unwrap();
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
    }

    #[tokio::test]
    async fn cancelled_drain_retains_original_identity_and_exact_request_id() {
        let owner = Retirements::new();
        let (guard, _peer) = pair(&owner);
        drop(guard);
        let original = owner.0.pending.lock().unwrap().front().unwrap().request_id;
        let result = tokio::time::timeout(
            Duration::from_millis(10),
            owner.drain_with(|_, id, _| {
                assert_eq!(id, original);
                std::future::pending::<Result<(), HelperClientError>>()
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(owner.0.pending.lock().unwrap().len(), 1);
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS - 1);
        owner
            .drain_with(|request, id, _| {
                assert_eq!(id, original);
                assert_eq!(request.route_context_id, vec![1; 16]);
                async { Ok(()) }
            })
            .await
            .unwrap();
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
    }

    #[tokio::test]
    async fn unconfirmed_retirement_never_frees_capacity() {
        let owner = Retirements::new();
        let (guard, _peer) = pair(&owner);
        drop(guard);
        assert!(
            owner
                .drain_with(|_, _, _| async { Err(HelperClientError::Timeout) })
                .await
                .is_err()
        );
        assert_eq!(owner.0.pending.lock().unwrap().len(), 1);
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS - 1);
        owner
            .drain_with(|_, _, _| async {
                Err(HelperClientError::Rejected(HelperResult::NotFound))
            })
            .await
            .unwrap();
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
    }
}
