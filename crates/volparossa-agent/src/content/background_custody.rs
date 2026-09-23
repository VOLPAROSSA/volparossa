//! One owner-first custody lane, with configured quiet admission and shared byte cooldown.

use tokio::{
    sync::{Mutex, MutexGuard, watch},
    time::{Instant, sleep_until},
};
use volparossa_config::Config;

use super::{
    ContentError,
    replication_budget::{Foreground, IdleBudget},
};

pub(super) fn owner_idle(foreground: &Foreground) -> Result<watch::Receiver<u64>, ContentError> {
    let changed = foreground.subscribe();
    if foreground.active() {
        return Err(ContentError::Busy);
    }
    Ok(changed)
}

pub(super) struct BackgroundCustody {
    serial: Mutex<()>,
    next: Mutex<Instant>,
}

impl Default for BackgroundCustody {
    fn default() -> Self {
        Self {
            serial: Mutex::new(()),
            next: Mutex::new(Instant::now()),
        }
    }
}

pub(super) struct Lease<'a> {
    _serial: MutexGuard<'a, ()>,
    next: &'a Mutex<Instant>,
    budget: IdleBudget,
}

impl BackgroundCustody {
    pub(super) fn acquire<'a>(&'a self, config: &Config) -> Result<Lease<'a>, ContentError> {
        let budget = IdleBudget::new(config).ok_or(ContentError::Busy)?;
        let serial = self.serial.try_lock().map_err(|_| ContentError::Busy)?;
        Ok(Lease {
            _serial: serial,
            next: &self.next,
            budget,
        })
    }
}

impl Lease<'_> {
    /// Caller retains its original operation deadline and foreground/EOF cancellation.
    /// Reserve each actual requested chunk before forwarding it, even if later cancelled.
    pub(super) async fn admit(&self, bytes: u64) -> bool {
        sleep_until(*self.next.lock().await).await;
        self.budget.wait_until_quiet().await;
        *self.next.lock().await = Instant::now() + self.budget.cooldown(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::cancellation::until_requester_closed;
    use super::*;
    use std::{future::pending, sync::Arc, time::Duration};
    use tokio::{net::UnixStream, sync::oneshot, time::timeout};

    fn configured() -> Config {
        let mut config = Config::default();
        config.sharing.enabled = true;
        config.sharing.total_upload_mbps = 100;
        config.download_sharing.enabled = true;
        config.download_sharing.total_download_mbps = 100;
        config
    }

    #[tokio::test]
    async fn foreground_generation_cancels_background_even_after_owner_finishes() {
        let foreground = Arc::new(Foreground::default());
        let active = foreground.enter();
        assert!(matches!(owner_idle(&foreground), Err(ContentError::Busy)));
        drop(active);
        let mut watch = owner_idle(&foreground).unwrap();
        let brief = foreground.enter();
        drop(brief);
        timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn requester_eof_releases_background_lane_without_erasing_reserved_cooldown() {
        let lane = Arc::new(BackgroundCustody::default());
        assert!(matches!(
            lane.acquire(&Config::default()),
            Err(ContentError::Busy)
        ));
        let next = Instant::now() + Duration::from_secs(30);
        *lane.next.lock().await = next;
        let (client, mut server) = UnixStream::pair().unwrap();
        let (started, ready) = oneshot::channel();
        let owner = Arc::clone(&lane);
        let job = tokio::spawn(async move {
            let _lease = owner.acquire(&configured()).unwrap();
            started.send(()).unwrap();
            until_requester_closed(&mut server, pending::<Result<(), ContentError>>()).await
        });
        ready.await.unwrap();
        assert!(matches!(
            lane.acquire(&configured()),
            Err(ContentError::Busy)
        ));
        drop(client);
        assert!(matches!(
            timeout(Duration::from_secs(1), job).await.unwrap().unwrap(),
            Err(ContentError::Unavailable)
        ));
        let _lease = lane.acquire(&configured()).unwrap();
        assert_eq!(*lane.next.lock().await, next);
    }
}
