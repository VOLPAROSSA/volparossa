//! Owner-enabled continuation of existing bounded rounds, never a replacement lease policy.

use std::{future::Future, time::Duration};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use tokio::{sync::watch, time::Instant};

#[derive(Clone, Debug, Args)]
#[group(id = "PeerFollowOptions")]
pub(super) struct Options {
    /// Continue bounded rounds until complete, cancelled, source expiry or retained-storage limit.
    #[arg(long)]
    pub(super) follow: bool,
    /// Delay between continuation windows; does not renew any existing executor lease.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=60))]
    pub(super) follow_poll_seconds: u16,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            follow: false,
            follow_poll_seconds: 5,
        }
    }
}

/// Only locally generated, pre-submission availability failures are retryable here.
/// Malformed source, incompatible models, file errors and failed verification propagate.
pub(super) fn transient_preflight(error: &anyhow::Error) -> bool {
    matches!(
        error.to_string().as_str(),
        "compute_distribute_capability_probe_unavailable"
            | "compute_distribute_capability_probe_timeout"
            | "compute_distribute_peer_busy"
    )
}

fn continue_after(report: &Value) -> Result<bool> {
    ensure!(
        report["complete"].is_boolean() && report["execute"].is_boolean(),
        "compute_follow_report_shape"
    );
    if report["complete"] == true || report["execute"] == false {
        return Ok(false);
    }
    match report["stopped"].as_str() {
        Some(
            "interrupted_handles_retained"
            | "source_expired_new_signed_package_required"
            | "attempt_storage_bound"
            | "answer_incomplete_no_new_work",
        ) => Ok(false),
        Some(
            "invocation_budget"
            | "initial_admission_failed_no_work_submitted"
            | "pending_handles_retained_no_busy_retry_loop",
        ) => Ok(true),
        _ => anyhow::bail!("compute_follow_unrecognized_stop"),
    }
}

pub(super) async fn run<F, Fut>(
    options: &Options,
    cancelled: &watch::Receiver<bool>,
    next: F,
) -> Result<Value>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    run_with_wait(options, cancelled, next, |duration| {
        wait(duration, cancelled.clone())
    })
    .await
}

async fn run_with_wait<F, Fut, W, Wait>(
    options: &Options,
    cancelled: &watch::Receiver<bool>,
    mut next: F,
    mut wait: W,
) -> Result<Value>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Value>>,
    W: FnMut(Duration) -> Wait,
    Wait: Future<Output = (bool, Duration)>,
{
    ensure!(
        (1..=60).contains(&options.follow_poll_seconds),
        "compute_follow_poll_bound"
    );
    let mut windows = 0_u64;
    let mut rounds = 0_u64;
    let mut waits = 0_u64;
    let mut waited_ms = 0_u64;
    loop {
        // Do not select/drop this future: existing batch/resume code owns the actual jobs,
        // retained handles, cancellation RPCs and joined worker futures until it returns.
        let mut report = next().await?;
        if !options.follow {
            return Ok(report);
        }
        windows = windows.checked_add(1).context("compute_follow_counter")?;
        rounds = rounds
            .checked_add(
                report["rounds_this_invocation"]
                    .as_u64()
                    .context("compute_follow_rounds")?,
            )
            .context("compute_follow_counter")?;
        if report["execute"] == true && report["complete"] != true && *cancelled.borrow() {
            report["stopped"] = json!("interrupted_handles_retained");
            report["pending_failure"] = json!(true);
        }
        let continuing = continue_after(&report)?;
        report["follow"] = json!(true);
        report["follow_windows"] = json!(windows);
        report["follow_waits"] = json!(waits);
        report["follow_wait_milliseconds"] = json!(waited_ms);
        report["rounds_this_invocation"] = json!(rounds);
        if !continuing {
            return Ok(report);
        }
        let expires = report["source_admission_expires_unix_seconds"]
            .as_u64()
            .context("compute_follow_source_expiry")?;
        let remaining = expires.saturating_sub(super::now()?);
        if remaining == 0 {
            report["stopped"] = json!("source_expired_new_signed_package_required");
            report["pending_failure"] = json!(true);
            return Ok(report);
        }
        waits = waits.checked_add(1).context("compute_follow_counter")?;
        println!(
            "{}",
            json!({"operation":"compute_workflow_progress","event":"COMPUTE_WORKFLOW_FOLLOW_WAIT",
                "follow_windows":windows,"rounds_this_invocation":rounds,
                "follow_waits":waits,"follow_wait_milliseconds":waited_ms})
        );
        let delay = Duration::from_secs(u64::from(options.follow_poll_seconds).min(remaining));
        let (still_owned, elapsed) = wait(delay).await;
        waited_ms = waited_ms
            .checked_add(u64::try_from(elapsed.as_millis())?)
            .context("compute_follow_counter")?;
        if !still_owned {
            report["follow_waits"] = json!(waits);
            report["follow_wait_milliseconds"] = json!(waited_ms);
            report["stopped"] = json!("interrupted_handles_retained");
            report["pending_failure"] = json!(true);
            return Ok(report);
        }
    }
}

async fn wait(duration: Duration, mut cancelled: watch::Receiver<bool>) -> (bool, Duration) {
    let started = Instant::now();
    let owned = tokio::select! {
        biased;
        () = async {
            while !*cancelled.borrow() {
                if cancelled.changed().await.is_err() { break; }
            }
        } => false,
        () = tokio::time::sleep(duration) => true,
    };
    (owned, started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn window(stopped: &str, rounds: u64) -> Value {
        json!({"execute":true,"complete":stopped=="complete","stopped":stopped,
            "rounds_this_invocation":rounds,"source_admission_expires_unix_seconds":super::super::now().unwrap()+600})
    }

    #[tokio::test]
    async fn multiple_windows_keep_totals_and_default_does_not_repeat() {
        // Pure orchestration responses, not manufactured worker/model receipts.
        let (_owner, activity) = watch::channel(false);
        let calls = AtomicUsize::new(0);
        let report = run_with_wait(
            &Options {
                follow: true,
                ..Options::default()
            },
            &activity,
            || async {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                Ok(window(
                    if index < 2 {
                        "invocation_budget"
                    } else {
                        "complete"
                    },
                    1,
                ))
            },
            |_| async { (true, Duration::from_millis(7)) },
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(report["rounds_this_invocation"], 3);
        assert_eq!(report["follow_windows"], 3);
        assert_eq!(report["follow_waits"], 2);
        assert_eq!(report["follow_wait_milliseconds"], 14);
        let original = window("invocation_budget", 1);
        let report = run_with_wait(
            &Options::default(),
            &activity,
            || async { Ok(original.clone()) },
            |_| async { panic!("default must never follow") },
        )
        .await
        .unwrap();
        assert_eq!(report, original);
    }

    #[tokio::test]
    async fn cancellation_stops_wait_and_permanent_boundaries_never_repeat() {
        let (owner, activity) = watch::channel(false);
        owner.send(true).unwrap();
        assert!(!wait(Duration::from_secs(60), activity).await.0);
        let (_owner, activity) = watch::channel(false);
        for stopped in [
            "complete",
            "source_expired_new_signed_package_required",
            "attempt_storage_bound",
            "answer_incomplete_no_new_work",
        ] {
            let report = run_with_wait(
                &Options {
                    follow: true,
                    ..Options::default()
                },
                &activity,
                || async { Ok(window(stopped, 0)) },
                |_| async { panic!("terminal boundary must never wait") },
            )
            .await
            .unwrap();
            assert_eq!(report["follow_windows"], 1);
            assert_eq!(report["follow_waits"], 0);
            assert_eq!(report["complete"], stopped == "complete");
        }
        for message in [
            "invalid signed source",
            "compute_workflow_attempt_storage_bound",
            "permission denied",
        ] {
            assert!(!transient_preflight(&anyhow::anyhow!(message)));
        }
        assert!(transient_preflight(&anyhow::anyhow!(
            "compute_distribute_peer_busy"
        )));
        assert!(continue_after(&window("unknown_permanent_failure", 0)).is_err());
    }

    #[tokio::test]
    async fn owner_cancel_before_or_during_wait_is_not_a_successful_incomplete_workflow() {
        let (owner, activity) = watch::channel(false);
        for already_cancelled in [false, true] {
            owner.send(already_cancelled).unwrap();
            let report = run_with_wait(
                &Options {
                    follow: true,
                    ..Options::default()
                },
                &activity,
                || async {
                    let mut report = window("invocation_budget", 1);
                    report["pending_failure"] = json!(false);
                    Ok(report)
                },
                |_| async { (false, Duration::ZERO) },
            )
            .await
            .unwrap();
            assert_eq!(report["complete"], false);
            assert_eq!(report["pending_failure"], true);
            assert_eq!(report["stopped"], "interrupted_handles_retained");
            assert_eq!(report["follow_windows"], 1);
        }
    }
}
