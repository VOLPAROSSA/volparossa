//! Caller-owned futures: no worker task survives cancellation or an origin fallback.

use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};

use tokio::time::{Instant, timeout_at};
use volparossa_content::transfer::parallel::ChunkWorker;

use super::ContentError;

#[derive(Default)]
pub(super) struct Measurement {
    pub(super) attempted: bool,
    pub(super) elapsed: Option<Duration>,
}

struct ActiveLease<'a, L> {
    _lease: L,
    active: &'a AtomicUsize,
}

impl<L> Drop for ActiveLease<'_, L> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A dormant candidate owns neither a network flow nor a resource lease. Last-moment
/// contention drops the assignment back to the writer without making a peer-failure claim.
pub(super) async fn assigned<L, F: Future<Output = Result<bool, ContentError>>>(
    mut worker: ChunkWorker,
    deadline: Instant,
    active: &AtomicUsize,
    acquire: impl FnOnce() -> Option<L>,
    open: impl FnOnce(ChunkWorker) -> F,
) -> Result<Measurement, ContentError> {
    let mut measurement = Measurement::default();
    let work = async {
        if !worker
            .wait_for_assignment()
            .await
            .map_err(|_| ContentError::Unavailable)?
        {
            return Ok(());
        }
        let Some(lease) = acquire() else {
            return Ok(());
        };
        active.fetch_add(1, Ordering::AcqRel);
        let _guard = ActiveLease {
            _lease: lease,
            active,
        };
        measurement.attempted = true;
        let started = Instant::now();
        match open(worker).await {
            Ok(true) => measurement.elapsed = Some(started.elapsed()),
            Ok(false) | Err(ContentError::Unavailable) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    };
    match timeout_at(deadline, work).await {
        Ok(Ok(()) | Err(ContentError::Unavailable)) | Err(_) => Ok(measurement),
        Ok(Err(error)) => Err(error),
    }
}

/// Poll the bounded provider input batch without spawning tasks or changing provider order.
/// A completed failure does not cancel useful siblings; dropping this future drops them all.
pub(super) async fn collect<F: Future>(workers: Vec<F>) -> Vec<F::Output> {
    let mut pending = workers
        .into_iter()
        .map(|worker| Some(Box::pin(worker)))
        .collect::<Vec<_>>();
    let mut outcomes = (0..pending.len()).map(|_| None).collect::<Vec<_>>();
    let mut remaining = pending.len();
    std::future::poll_fn(|context| {
        for (worker, result) in pending.iter_mut().zip(&mut outcomes) {
            let Some(current) = worker else {
                continue;
            };
            if let Poll::Ready(outcome) = current.as_mut().poll(context) {
                *result = Some(outcome);
                *worker = None;
                remaining -= 1;
            }
        }
        if remaining == 0 {
            Poll::Ready(outcomes.iter_mut().filter_map(Option::take).collect())
        } else {
            Poll::Pending
        }
    })
    .await
}
