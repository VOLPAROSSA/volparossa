//! Bounded, cancellable admission probes. No task bytes or job IDs are submitted here.

use std::{future::Future, path::Path, time::Duration};

use anyhow::{Result, bail};
use ed25519_dalek::VerifyingKey;
use tokio::{sync::watch, time::timeout};
use volparossa_local_control::compute::Capabilities;

pub(super) async fn capabilities(
    socket: &Path,
    provider: &VerifyingKey,
    activity: watch::Receiver<bool>,
) -> Result<Capabilities> {
    // Newly reachable peers can still be absent from an exact DHT lookup. Retry
    // only this read-only phase; never replay Submit or replace an uncertain job.
    probe(
        activity,
        4,
        Duration::from_secs(45),
        Duration::from_secs(2),
        || async {
            let caps = super::capabilities(socket, provider).await?;
            Ok(caps.accepting_work.then_some(caps))
        },
    )
    .await
}

async fn probe<T, F, Fut>(
    mut activity: watch::Receiver<bool>,
    attempts: usize,
    deadline: Duration,
    delay: Duration,
    mut fetch: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let work = async {
        for index in 0..attempts {
            if index != 0 {
                tokio::time::sleep(delay).await;
            }
            if let Ok(Some(value)) = fetch().await {
                return Ok(value);
            }
        }
        // Do not copy provider-supplied error text into durable task results.
        bail!("compute_distribute_capability_probe_unavailable")
    };
    tokio::select! {
        biased;
        () = async {
            while !*activity.borrow() {
                if activity.changed().await.is_err() {
                    break; // A lost owner is not permission to keep probing.
                }
            }
        } => bail!("compute_distribute_cancelled_before_submit"),
        result = timeout(deadline, work) => {
            result.map_err(|_| anyhow::anyhow!("compute_distribute_capability_probe_timeout"))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn retries_only_readiness_until_one_available_result() {
        let (_owner, activity) = watch::channel(false);
        let calls = AtomicUsize::new(0);
        let result = probe(activity, 4, Duration::from_secs(1), Duration::ZERO, || {
            let index = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                match index {
                    0 => bail!("transient lookup failure"),
                    1 => Ok(None), // Real peer exists but is busy.
                    _ => Ok(Some(17)),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 17);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn unavailable_probe_stops_at_its_attempt_bound() {
        let (_owner, activity) = watch::channel(false);
        let calls = AtomicUsize::new(0);
        let error = probe::<(), _, _>(activity, 4, Duration::from_secs(1), Duration::ZERO, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { bail!("untrusted upstream exception") }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            error.to_string(),
            "compute_distribute_capability_probe_unavailable"
        );
    }

    #[tokio::test]
    async fn owner_cancellation_never_waits_for_a_stuck_probe() {
        let (owner, activity) = watch::channel(false);
        let calls = AtomicUsize::new(0);
        let error = probe::<(), _, _>(activity, 4, Duration::from_secs(1), Duration::ZERO, || {
            calls.fetch_add(1, Ordering::SeqCst);
            owner.send(true).unwrap();
            std::future::pending()
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            error.to_string(),
            "compute_distribute_cancelled_before_submit"
        );
        let error = probe::<(), _, _>(
            owner.subscribe(),
            4,
            Duration::from_secs(1),
            Duration::ZERO,
            || async { panic!("already cancelled must never probe") },
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "compute_distribute_cancelled_before_submit"
        );
    }

    #[tokio::test]
    async fn whole_probe_has_a_deadline_even_if_one_rpc_never_returns() {
        let (_owner, activity) = watch::channel(false);
        let error = probe::<(), _, _>(
            activity,
            4,
            Duration::from_millis(5),
            Duration::ZERO,
            std::future::pending,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "compute_distribute_capability_probe_timeout"
        );
    }
}
