//! Sharing approved combinations through the owner's existing public channel.
//! Publication failures never turn a locally approved adapter into a rejected model.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::watch, time::Instant};

use super::{Options, Path, Registry, State, Store, checkpoint, now, root, snapshot};
use crate::compute::train_loop::{active, aggregate_publication};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Pending,
    Complete,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    phase: Phase,
    next_attempt: u64,
    manifest: Option<Value>,
}

impl Record {
    pub(super) fn pending() -> Self {
        Self {
            phase: Phase::Pending,
            next_attempt: 0,
            manifest: None,
        }
    }

    pub(super) fn settled(&self) -> bool {
        self.phase != Phase::Pending
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.phase != Phase::Complete || self.manifest.is_some(),
            "aggregate_publication_missing_manifest"
        );
        if let Some(manifest) = &self.manifest {
            ensure!(
                manifest["created"]
                    .as_u64()
                    .zip(manifest["expires"].as_u64())
                    .is_some_and(|(from, until)| from < until)
                    && manifest["manifest_id"]
                        .as_str()
                        .is_some_and(|id| crate::compute::is_hex(id, 64)),
                "aggregate_publication_manifest_record"
            );
        }
        Ok(())
    }
}

pub(in crate::compute::train_loop) fn pending_sequences(registry: &Registry) -> Vec<u64> {
    registry
        .rounds
        .iter()
        .filter(|round| {
            round.retirement.is_none()
                && round
                    .publication
                    .as_ref()
                    .is_some_and(|record| !record.settled())
        })
        .map(|round| round.sequence)
        .collect()
}

pub(in crate::compute::train_loop) fn has_retired(registry: &Registry) -> bool {
    registry
        .rounds
        .iter()
        .any(|round| round.retirement.is_some())
}

pub(in crate::compute::train_loop) fn has_expired(registry: &Registry) -> bool {
    registry.rounds.iter().any(|round| {
        round
            .publication
            .as_ref()
            .is_some_and(|record| record.phase == Phase::Expired)
    })
}

/// Returns whether this revision is terminal, so the next channel revision may proceed.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "One ordered approval/sign/checkpoint/handoff transaction with the owning loop's lifetime"
)]
pub(in crate::compute::train_loop) async fn publish(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    sequence: u64,
    revision: u64,
    activity: &watch::Receiver<bool>,
    deadline: Option<Instant>,
) -> Result<bool> {
    let mut registry = state
        .aggregate_updates
        .clone()
        .context("aggregate_publication_registry")?;
    let index = registry
        .rounds
        .iter()
        .position(|round| round.sequence == sequence)
        .context("aggregate_publication_round")?;
    let round = &registry.rounds[index];
    if round.retirement.is_some() {
        // Preserve any original manifest and allocated revision, but never retry
        // or re-sign a model after its selected local extraction was retired.
        return Ok(true);
    }
    let record = round
        .publication
        .as_ref()
        .context("aggregate_publication_not_enrolled")?;
    if record.settled() {
        return Ok(true);
    }
    let time = now()?;
    let expires = record
        .manifest
        .as_ref()
        .and_then(|value| value["expires"].as_u64())
        .map_or(round.expires, |expires| expires.min(round.expires));
    if !active(activity)
        || deadline.is_some_and(|until| Instant::now() >= until)
        || (record.next_attempt > time && expires > time)
    {
        return Ok(false);
    }
    let directory = root(args, sequence)?;
    ensure!(
        round.phase == super::Phase::Approved
            && round.snapshot.as_ref() == Some(&snapshot(&directory)?),
        "aggregate_publication_original_approval_bytes"
    );
    // A durable original receipt can settle a crash even after expiry. No receipt means
    // expired authority must terminate, never lead to a fresh signature or a new lease.
    if expires <= time
        && !directory
            .join("publication/contribution.json")
            .try_exists()?
    {
        registry.rounds[index].publication.as_mut().unwrap().phase = Phase::Expired;
        checkpoint(&registry, store, state)?;
        return Ok(true);
    }
    let Ok(prepared) =
        aggregate_publication::prepare_loop(args, &directory, revision, socket, activity).await
    else {
        defer(&mut registry, index, expires, args.poll_seconds)?;
        checkpoint(&registry, store, state)?;
        eprintln!("compute loop_event=aggregate_publication_preparation_deferred");
        return Ok(registry.rounds[index]
            .publication
            .as_ref()
            .unwrap()
            .settled());
    };
    ensure!(
        round.approval.as_ref() == Some(prepared.approved_identity()),
        "aggregate_publication_original_approval_changed"
    );
    if let Some(original) = &record.manifest {
        ensure!(
            original == prepared.record(),
            "aggregate_publication_original_manifest_changed"
        );
    }
    let pending = registry.rounds[index].publication.as_mut().unwrap();
    pending.manifest = Some(prepared.record().clone());
    if prepared.original_receipt().is_some() {
        pending.phase = Phase::Complete;
        checkpoint(&registry, store, state)?;
        return Ok(true);
    }
    // The assigned revision and exact signed identity are durable before network delivery.
    checkpoint(&registry, store, state)?;
    let expires = prepared.expires();
    let until = Instant::now() + Duration::from_secs(expires.saturating_sub(now()?).min(60));
    let until = deadline.map_or(until, |deadline| until.min(deadline));
    if aggregate_publication::handoff_loop(prepared, socket, activity, until)
        .await
        .is_ok()
    {
        registry.rounds[index].publication.as_mut().unwrap().phase = Phase::Complete;
        println!(
            "{}",
            json!({"operation":"compute_train_loop_aggregate_publication",
                "sequence":sequence,"revision":revision,"network_publication":true,
                "publication":registry.rounds[index].publication.as_ref().unwrap().manifest,
                "optimizer_steps":0,"general_quality_proven":false})
        );
    } else {
        defer(&mut registry, index, expires, args.poll_seconds)?;
        eprintln!("compute loop_event=aggregate_publication_handoff_deferred");
    }
    checkpoint(&registry, store, state)?;
    Ok(registry.rounds[index]
        .publication
        .as_ref()
        .unwrap()
        .settled())
}

fn defer(registry: &mut Registry, index: usize, expires: u64, poll: u16) -> Result<()> {
    let time = now()?;
    let record = registry.rounds[index]
        .publication
        .as_mut()
        .context("aggregate_publication_record")?;
    record.next_attempt = time.saturating_add(u64::from(poll));
    if time >= expires {
        record.phase = Phase::Expired;
    }
    Ok(())
}
