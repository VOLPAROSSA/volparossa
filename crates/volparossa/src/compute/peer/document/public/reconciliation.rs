//! Observe/cancel only retained public jobs; no submission, replacement or lease renewal.

use std::{fs, os::unix::fs::DirBuilderExt as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, ensure};
use serde::Serialize;
use tokio::time::{Instant, sleep_until, timeout_at};

use super::{ReceiptObservation, diagnostic, scan_receipts, task};
use crate::compute::peer::{self, JobHandle, RpcDiagnostic, RpcPhase, rpc};

const CLEANUP_BUDGET: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default, Serialize)]
pub(super) struct Observation {
    attempted: usize,
    terminal_persisted: usize,
    deadline_reached: bool,
    error: diagnostic::ErrorClass,
    rpc: Option<serde_json::Value>,
}

impl Observation {
    fn failed(&mut self, error: &anyhow::Error) {
        // Keep the first failure, never upstream error text or retained identities.
        if self.error == diagnostic::ErrorClass::None {
            self.error = diagnostic::classify(error);
            self.rpc = peer::rpc_diagnostic(error).map(|value| serde_json::json!(value));
        }
    }
}

pub(super) async fn run(root: &Path, socket: &Path) -> Observation {
    run_until(root, socket, Instant::now() + CLEANUP_BUDGET).await
}

async fn run_until(root: &Path, socket: &Path, deadline: Instant) -> Observation {
    let mut observed = Observation::default();
    let (handles, terminal) = match scan_receipts(root, &mut ReceiptObservation::default()) {
        Ok(value) => value,
        Err(error) => {
            observed.failed(&error);
            return observed;
        }
    };
    for (id, handle) in handles {
        if terminal.contains(&id) {
            continue;
        }
        if Instant::now() >= deadline {
            observed.deadline_reached = true;
            break;
        }
        observed.attempted += 1;
        let result = async {
            let status = settle(socket, &handle, deadline).await?;
            // New observations are separate from every original attempt/result. Missing,
            // Running, expired authority and transport failure never manufacture a receipt.
            let directory = root.join("cleanup-observations");
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            super::private_directory(&directory)?;
            task::write_bytes(
                &directory.join(format!("receipt-{id}.json")),
                serde_json::to_vec(
                    &serde_json::json!({"version":1,"handle":handle,"status":status,
                    "verified_at_unix_seconds":peer::now()?}),
                )?
                .as_slice(),
                false,
            )
        }
        .await;
        match result {
            Ok(()) => observed.terminal_persisted += 1,
            Err(error) => observed.failed(&error),
        }
        if Instant::now() >= deadline {
            observed.deadline_reached = true;
        }
    }
    observed
}

async fn exchange_status(
    socket: &Path,
    handle: &JobHandle,
    operation: rpc::Operation,
    deadline: Instant,
) -> Result<rpc::JobStatus> {
    let provider = peer::parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
    ensure!(handle.version == 1, "compute_public_cleanup_handle_version");
    let phase = RpcPhase::of(&operation);
    // Only the bounded RPC is dropped on timeout; the immutable remote authority remains
    // retained and admission stays quarantined. There is no new worker-owning future.
    let outcome = timeout_at(deadline, peer::exchange(socket, &provider, operation))
        .await
        .context("compute_public_cleanup_deadline")
        .map_err(|error| {
            peer::rpc_failure(error, RpcDiagnostic::ExchangeUnconfirmed { phase })
        })??;
    peer::job_in_phase(outcome, handle, phase)
}

async fn settle(socket: &Path, handle: &JobHandle, deadline: Instant) -> Result<rpc::JobStatus> {
    let mut status = exchange_status(
        socket,
        handle,
        rpc::Operation::Poll(handle.binding.clone()),
        deadline,
    )
    .await?;
    if status.state == rpc::JobState::Running {
        status = exchange_status(
            socket,
            handle,
            rpc::Operation::Cancel(handle.binding.clone()),
            deadline,
        )
        .await?;
    }
    while status.state == rpc::JobState::Running {
        // A Cancel acknowledgement may still describe a live worker. Wait for the broker's
        // existing joined terminal state, not merely cancellation_requested or lease expiry.
        sleep_until((Instant::now() + POLL_INTERVAL).min(deadline)).await;
        status = exchange_status(
            socket,
            handle,
            rpc::Operation::Poll(handle.binding.clone()),
            deadline,
        )
        .await?;
    }
    Ok(status)
}

#[cfg(test)]
mod tests;
