//! Ephemeral core resource turns. Owner signing and archive state stay outside this service.

use super::{
    ContentError, ContentRuntime, background_custody, cancellation::until_requester_closed, now,
    worker_budget::WorkerLease,
};
use crate::control::ControlContext;
use rand_core::{OsRng, RngCore};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use subtle::ConstantTimeEq as _;
use tokio::{
    io::AsyncReadExt as _,
    net::UnixStream,
    sync::watch,
    time::{Duration, Instant},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, PrivateStorageMaintenanceReady,
    PrivateStorageMaintenanceRequest, control_response::Payload, write_response,
};

pub(super) struct Coordinator {
    pulse: watch::Sender<u64>,
    active: Mutex<Option<Arc<Turn>>>,
}

impl Default for Coordinator {
    fn default() -> Self {
        Self {
            pulse: watch::channel(0).0,
            active: Mutex::new(None),
        }
    }
}

pub(super) struct Turn {
    token: [u8; 32],
    uid: u32,
    owner: [u8; 32],
    deadline: Instant,
    remaining: AtomicU64,
    stopped: watch::Sender<bool>,
    _worker: WorkerLease,
    lane: background_custody::OwnedLease,
    operation: tokio::sync::Mutex<()>,
}

struct TurnGuard {
    coordinator: Arc<Coordinator>,
    turn: Arc<Turn>,
}

impl Drop for TurnGuard {
    fn drop(&mut self) {
        self.turn.stopped.send_replace(true);
        if let Ok(mut active) = self.coordinator.active.lock() {
            if active
                .as_ref()
                .is_some_and(|turn| Arc::ptr_eq(turn, &self.turn))
            {
                active.take();
            }
        }
    }
}

impl Turn {
    async fn wait_for_end(&self, foreground: &mut watch::Receiver<u64>, local: &mut UnixStream) {
        let mut terminal = [0];
        tokio::select! {
            biased;
            _ = foreground.changed() => {},
            () = self.cancelled() => {},
            _ = local.read(&mut terminal) => {},
        }
    }
    pub(super) fn operation(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, ContentError> {
        self.operation.try_lock().map_err(|_| ContentError::Busy)
    }
    pub(super) async fn cancelled(&self) {
        let mut changed = self.stopped.subscribe();
        if *changed.borrow() {
            return;
        }
        tokio::select! {
            _ = changed.changed() => {},
            () = tokio::time::sleep_until(self.deadline) => {},
        }
    }

    pub(super) async fn admit(&self, bytes: u64) -> bool {
        if self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(bytes)
            })
            .is_err()
        {
            self.stopped.send_replace(true);
            return false;
        }
        tokio::select! {
            biased;
            () = self.cancelled() => false,
            () = self.lane.admit(bytes) => true,
        }
    }
}

impl ContentRuntime {
    fn try_maintenance_turn(
        &self,
        request: &PrivateStorageMaintenanceRequest,
        uid: u32,
        config: &volparossa_config::Config,
    ) -> Result<(TurnGuard, watch::Receiver<u64>), ContentError> {
        let owner = request
            .owner_key
            .as_slice()
            .try_into()
            .map_err(|_| ContentError::Invalid)?;
        let foreground = background_custody::owner_idle(&self.foreground)?;
        let mut active = self
            .storage_maintenance
            .active
            .lock()
            .map_err(|_| ContentError::Unavailable)?;
        if active.is_some() {
            return Err(ContentError::Busy);
        }
        let lane = self.background_custody.acquire_owned(config)?;
        let worker = self.worker_budget.try_acquire().ok_or(ContentError::Busy)?;
        let mut token = [0; 32];
        OsRng.fill_bytes(&mut token);
        let turn = Arc::new(Turn {
            token,
            uid,
            owner,
            deadline: Instant::now() + Duration::from_secs(3600),
            remaining: AtomicU64::new(request.maximum_bytes),
            stopped: watch::channel(false).0,
            _worker: worker,
            lane,
            operation: tokio::sync::Mutex::new(()),
        });
        *active = Some(Arc::clone(&turn));
        Ok((
            TurnGuard {
                coordinator: Arc::clone(&self.storage_maintenance),
                turn,
            },
            foreground,
        ))
    }

    pub(crate) fn storage_maintenance_tick(&self) {
        self.storage_maintenance
            .pulse
            .send_modify(|tick| *tick = tick.wrapping_add(1));
    }

    pub(super) fn maintenance_turn(
        &self,
        token: &[u8],
        uid: u32,
        owner: &[u8],
    ) -> Result<Arc<Turn>, ContentError> {
        let active = self
            .storage_maintenance
            .active
            .lock()
            .map_err(|_| ContentError::Unavailable)?;
        let turn = active.as_ref().ok_or(ContentError::Unavailable)?;
        if token.len() != 32
            || turn.token.ct_eq(token).unwrap_u8() != 1
            || turn.uid != uid
            || turn.owner != owner
            || *turn.stopped.borrow()
            || Instant::now() >= turn.deadline
        {
            return Err(ContentError::Invalid);
        }
        Ok(Arc::clone(turn))
    }

    pub(crate) async fn private_storage_maintenance(
        &self,
        request: &PrivateStorageMaintenanceRequest,
        context: &ControlContext,
        local: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let uid = local.peer_cred().map_err(|_| ContentError::Invalid)?.uid();
        let mut pulse = self.storage_maintenance.pulse.subscribe();
        // No independent worker timer: admission requires a subsequent existing daemon tick.
        let (guard, mut foreground) = until_requester_closed(local, async {
            loop {
                pulse
                    .changed()
                    .await
                    .map_err(|_| ContentError::Unavailable)?;
                super::custody::checked_policy(context, None).await?;
                match self.try_maintenance_turn(request, uid, &context.config) {
                    Err(ContentError::Busy) => continue,
                    result => return result,
                }
            }
        })
        .await?;
        let turn = &guard.turn;
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            result: 0,
            diagnostic_code: "PRIVATE_STORAGE_MAINTENANCE_READY".into(),
            payload: Some(Payload::PrivateStorageMaintenanceReady(
                PrivateStorageMaintenanceReady {
                    turn: turn.token.to_vec(),
                    expires: now() + 3600,
                    maximum_bytes: request.maximum_bytes,
                },
            )),
        };
        write_response(local, &response)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        *ready_sent = true;
        turn.wait_for_end(&mut foreground, local).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use volparossa_config::Config;
    use volparossa_identity::Identity;

    fn configured() -> Config {
        let mut config = Config::default();
        config.sharing.enabled = true;
        config.sharing.interface = "lo".into();
        config.sharing.total_upload_mbps = 100;
        config.download_sharing.enabled = true;
        config.download_sharing.interface = "lo".into();
        config.download_sharing.total_download_mbps = 100;
        config
    }
    fn runtime() -> ContentRuntime {
        let mut runtime = ContentRuntime::new(&Identity::generate()).unwrap();
        runtime.worker_budget =
            super::super::worker_budget::WorkerBudget::for_test(1024 * 1024 * 1024, 128, false);
        runtime
    }
    fn request(bytes: u64) -> PrivateStorageMaintenanceRequest {
        PrivateStorageMaintenanceRequest {
            owner_key: SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            enrollment_id: vec![9; 32],
            maximum_bytes: bytes,
        }
    }

    #[tokio::test]
    async fn core_maintenance_turn_is_owner_uid_bound_and_shares_existing_resources() {
        let runtime = runtime();
        let request = request(8192);
        let mut pulse = runtime.storage_maintenance.pulse.subscribe();
        assert!(!pulse.has_changed().unwrap());
        runtime.storage_maintenance_tick();
        pulse.changed().await.unwrap();
        assert!(
            runtime
                .try_maintenance_turn(&request, 1, &Config::default())
                .is_err()
        );
        let foreground = runtime.foreground.enter();
        assert!(
            runtime
                .try_maintenance_turn(&request, 1, &configured())
                .is_err()
        );
        drop(foreground);
        let (guard, _) = runtime
            .try_maintenance_turn(&request, 1, &configured())
            .unwrap();
        let turn = Arc::clone(&guard.turn);
        assert!(
            runtime
                .try_maintenance_turn(&request, 1, &configured())
                .is_err()
        );
        assert!(runtime.background_custody.acquire(&configured()).is_err());
        assert!(
            runtime
                .maintenance_turn(&turn.token, 1, &request.owner_key)
                .is_ok()
        );
        assert!(
            runtime
                .maintenance_turn(&turn.token, 2, &request.owner_key)
                .is_err()
        );
        assert!(
            runtime
                .maintenance_turn(&[3; 32], 1, &request.owner_key)
                .is_err()
        );
        assert!(runtime.maintenance_turn(&turn.token, 1, &[5; 32]).is_err());
        let operation = turn.operation().unwrap();
        assert!(turn.operation().is_err());
        drop(operation);
        // Loopback is deliberately not an eligible independent link. Waiting for quiet
        // must not grant credit or refund an already bounded attempt; no host link is changed.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), turn.admit(8192))
                .await
                .is_err()
        );
        assert!(!turn.admit(1).await);
        assert_eq!(turn.remaining.load(Ordering::Acquire), 0);
        assert!(
            runtime
                .maintenance_turn(&turn.token, 1, &request.owner_key)
                .is_err()
        );
        drop(guard);
        assert!(runtime.storage_maintenance.active.lock().unwrap().is_none());
        assert!(
            runtime.background_custody.acquire(&configured()).is_err(),
            "active flow keeps resource reservation after revocation"
        );
        drop(turn);
        assert!(runtime.background_custody.acquire(&configured()).is_ok());
    }

    #[tokio::test]
    async fn foreground_or_owner_disconnect_revokes_live_core_turn() {
        for owner_disconnect in [false, true] {
            let runtime = runtime();
            let (guard, mut changed) = runtime
                .try_maintenance_turn(&request(65536), 1, &configured())
                .unwrap();
            let turn = Arc::clone(&guard.turn);
            let (client, mut server) = UnixStream::pair().unwrap();
            let job = tokio::spawn(async move {
                guard.turn.wait_for_end(&mut changed, &mut server).await;
                drop(guard);
            });
            if owner_disconnect {
                drop(client);
            } else {
                let active = runtime.foreground.enter();
                drop(active);
            }
            tokio::time::timeout(Duration::from_secs(1), job)
                .await
                .unwrap()
                .unwrap();
            assert!(!turn.admit(1).await);
            assert!(runtime.storage_maintenance.active.lock().unwrap().is_none());
        }
    }
}
