//! Retire only a proven damaged local extraction, preserving original approval evidence.
//! No worker, source refresh, publisher verdict, file repair or base-model fallback.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    Cycle, Options, Phase, Snapshot, State, Store, aggregate_updates, evaluation, now,
    peer_evaluation, peer_updates, serving,
};

const SCOPE: &str = "local-successor-extraction-integrity-not-model-or-publisher-verdict";
const FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    scope: String,
    sequence: u64,
    observed_at: u64,
    original_snapshot_sha256: String,
    observed_adapter_files: Snapshot,
    restored_origin: Value,
    restored_expires: u64,
}

#[derive(Debug)]
struct RecoveryBlocked;

impl std::fmt::Display for RecoveryBlocked {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("local_successor_integrity_no_verified_predecessor")
    }
}
impl std::error::Error for RecoveryBlocked {}

#[cfg(test)]
fn recovery_blocked(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RecoveryBlocked>().is_some()
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

/// Missing/linked/unreadable/foreign files and changes to any original receipt
/// are not attributable extraction damage and must remain ordinary errors.
fn changed_extraction(expected: &Snapshot, actual: &Snapshot) -> Result<Option<Snapshot>> {
    ensure!(
        expected.keys().eq(actual.keys()),
        "local_retirement_fileset_changed"
    );
    let mut observed = Snapshot::new();
    let mut changed = false;
    for (path, old) in expected {
        let current = &actual[path];
        if let Some((name, maximum)) = FILES
            .iter()
            .find(|(name, _)| path == &format!("training/adapter/{name}"))
        {
            ensure!(
                current.bytes > 0 && current.bytes <= *maximum,
                "local_retirement_adapter_bound"
            );
            changed |= old != current;
            observed.insert((*name).into(), current.clone());
        } else {
            ensure!(current == old, "local_retirement_original_evidence_changed");
        }
    }
    ensure!(
        observed.len() == FILES.len(),
        "local_retirement_adapter_missing"
    );
    Ok(changed.then_some(observed))
}

fn original(store: &Store, cycle: &Cycle) -> Result<evaluation::Record> {
    ensure!(
        matches!(
            cycle.phase,
            Phase::Trained | Phase::PublishPending | Phase::Complete | Phase::PublicationExpired
        ),
        "local_retirement_unapproved_phase"
    );
    let snapshot = cycle
        .snapshot
        .as_ref()
        .context("local_retirement_snapshot")?;
    let record = evaluation::verify_original(store, cycle.sequence, snapshot)?;
    ensure!(
        record.approved && record.sequence == cycle.sequence,
        "local_retirement_original_approval"
    );
    Ok(record)
}

fn origin(record: &evaluation::Record) -> Result<Value> {
    let value = serde_json::to_value(record)?;
    if let Some(aggregate) = value.get("aggregate_predecessor") {
        ensure!(
            aggregate["kind"] == "aggregate_update"
                && aggregate["local_predecessor"] == serde_json::to_value(record.predecessor)?,
            "local_retirement_aggregate_lineage"
        );
        return Ok(aggregate.clone());
    }
    ensure!(
        value.get("peer_predecessor").is_none(),
        "local_retirement_peer_predecessor_unsupported"
    );
    let previous = record
        .predecessor
        .context("local_retirement_no_approved_predecessor")?;
    ensure!(
        previous > 0 && previous < record.sequence,
        "local_retirement_predecessor_order"
    );
    Ok(json!({"kind":"local_cycle","sequence":previous}))
}

/// Recheck a retired cycle against the same immutable receipts and bundle. Its
/// selected predecessor may now be expired; historical proof never grants execution.
pub(super) fn verify(store: &Store, cycle: &Cycle) -> Result<evaluation::Record> {
    let retired = cycle
        .retirement
        .as_ref()
        .context("local_retirement_missing_record")?;
    let snapshot = cycle
        .snapshot
        .as_ref()
        .context("local_retirement_snapshot")?;
    let observed = changed_extraction(snapshot, &store.snapshot_cycle(cycle.sequence)?)?
        .context("local_retirement_original_difference_missing")?;
    let approved = original(store, cycle)?;
    let source = store.read_cycle_json(cycle.sequence, "source-provenance.json")?;
    ensure!(
        retired.version == 1
            && retired.scope == SCOPE
            && retired.sequence == cycle.sequence
            && retired.original_snapshot_sha256 == digest(snapshot)?
            && retired.observed_adapter_files == observed
            && source["verified_at_unix_seconds"]
                .as_u64()
                .is_some_and(|at| at <= retired.observed_at)
            && retired.observed_at <= now()?
            && retired.restored_expires > retired.observed_at
            && retired.restored_origin == origin(&approved)?,
        "local_retirement_record_binding"
    );
    Ok(approved)
}

struct Restoration {
    local: Option<u64>,
    aggregate: Option<u64>,
    origin: Value,
    expires: u64,
}

fn predecessor(
    args: &Options,
    store: &Store,
    state: &State,
    approved: &evaluation::Record,
    at: u64,
) -> Result<Restoration> {
    let original = serde_json::to_value(approved)?;
    let origin = origin(approved)?;
    let (local, aggregate, path, expires) = if origin["kind"] == "aggregate_update" {
        let sequence = origin["aggregate_sequence"]
            .as_u64()
            .context("local_retirement_aggregate_sequence")?;
        let registry = state
            .aggregate_updates
            .as_ref()
            .context("local_retirement_aggregate_registry")?;
        let selected = aggregate_updates::selected_for_sequence(
            args,
            registry,
            sequence,
            approved.predecessor,
        )?;
        ensure!(
            selected.origin == origin,
            "local_retirement_aggregate_origin_changed"
        );
        (
            approved.predecessor,
            Some(sequence),
            selected
                .adapter_root
                .context("local_retirement_aggregate_adapter")?,
            selected
                .authority_expires
                .context("local_retirement_aggregate_expiry")?,
        )
    } else {
        let sequence = approved
            .predecessor
            .context("local_retirement_local_predecessor")?;
        let previous = state
            .cycles
            .iter()
            .find(|cycle| cycle.sequence == sequence)
            .context("local_retirement_predecessor_missing")?;
        ensure!(
            previous.retirement.is_none(),
            "local_retirement_predecessor_retired"
        );
        // Reuse the complete existing snapshot, approval and lease computation;
        // this temporary selection does not mutate the live coordinator.
        let mut selected: State = serde_json::from_value(serde_json::to_value(state)?)?;
        selected.latest = Some(sequence);
        let (path, expires, _) = serving::local_candidate(store, &selected)?
            .context("local_retirement_predecessor_unavailable")?;
        let prior = serde_json::to_value(evaluation::verify(store, sequence)?)?;
        ensure!(
            original["input_adapter"]["applied_parameters"] == prior["candidate_parameters"],
            "local_retirement_predecessor_parameters"
        );
        (Some(sequence), None, path, expires)
    };
    let selected = store.read_cycle_json(approved.sequence, "selection.json")?;
    ensure!(
        selected["adapter_root"] == serde_json::to_value(&path)?
            && original["input_adapter"]["files"]
                == serde_json::to_value(peer_evaluation::adapter_files(&path)?)?
            && expires > at,
        "local_retirement_predecessor_binding_or_expiry"
    );
    Ok(Restoration {
        local,
        aggregate,
        origin,
        expires,
    })
}

fn pending_local(store: &Store, state: &State, sequence: u64) -> Result<Option<usize>> {
    let expected: PathBuf = store.cycle_path(sequence)?.join("training/adapter");
    let mut pending = None;
    for (index, cycle) in state.cycles.iter().enumerate() {
        if cycle.phase != Phase::Evaluating {
            continue;
        }
        ensure!(
            pending.is_none(),
            "local_retirement_multiple_pending_cycles"
        );
        store.validate_training(
            cycle.sequence,
            cycle
                .training
                .as_ref()
                .context("local_retirement_pending_training")?,
        )?;
        let selection = store.read_cycle_json(cycle.sequence, "selection.json")?;
        if selection["adapter_root"] == serde_json::to_value(&expected)? {
            ensure!(cycle.sequence > sequence, "local_retirement_pending_order");
            pending = Some(index);
        }
    }
    Ok(pending)
}

/// Invoked between reaped attempts, before selection/serving de-duplication.
pub(super) fn recover_active(
    args: &Options,
    store: &Store,
    state: &mut State,
    serving: &mut Option<serving::Serving>,
) -> Result<bool> {
    // A remote/aggregate selection supersedes the local pointer. Never retire its
    // historical local baseline as if that baseline were the current model.
    if state
        .aggregate_updates
        .as_ref()
        .and_then(aggregate_updates::active_sequence)
        .is_some()
        || state
            .peer_updates
            .as_ref()
            .and_then(peer_updates::active_sequence)
            .is_some()
    {
        return Ok(false);
    }
    let Some(sequence) = state.latest else {
        return Ok(false);
    };
    ensure!(
        sequence > 0
            && sequence < state.next_sequence
            && state.promoted > 0
            && state.promoted.checked_add(state.rejected) == Some(state.completed)
            && state
                .cycles
                .iter()
                .filter(|cycle| cycle.sequence == sequence)
                .count()
                == 1,
        "local_retirement_selected_history"
    );
    let index = state
        .cycles
        .iter()
        .position(|cycle| cycle.sequence == sequence)
        .context("local_retirement_latest_missing")?;
    let cycle = &state.cycles[index];
    ensure!(
        cycle.retirement.is_none(),
        "local_retirement_active_retired"
    );
    let snapshot = cycle
        .snapshot
        .as_ref()
        .context("local_retirement_snapshot")?;
    let actual = store.snapshot_cycle(sequence)?;
    if &actual == snapshot {
        return Ok(false);
    }
    let observed =
        changed_extraction(snapshot, &actual)?.context("local_retirement_not_extraction")?;
    let approved = original(store, cycle)?;
    // Proven local corruption must revoke the exported snapshot even when its
    // exact predecessor cannot be recovered or the following checkpoint fails.
    if let Some(serving) = serving.as_mut() {
        serving.withdraw()?;
    }
    let at = now()?;
    let restored = predecessor(args, store, state, &approved, at)
        .map_err(|_| anyhow::Error::new(RecoveryBlocked))?;
    let pending = pending_local(store, state, sequence)?;
    let record = Record {
        version: 1,
        scope: SCOPE.into(),
        sequence,
        observed_at: at,
        original_snapshot_sha256: digest(snapshot)?,
        observed_adapter_files: observed,
        restored_origin: restored.origin,
        restored_expires: restored.expires,
    };
    if let Some(aggregate) = restored.aggregate {
        aggregate_updates::select_for_recovery(
            state
                .aggregate_updates
                .as_mut()
                .context("local_retirement_aggregate_registry")?,
            aggregate,
        )?;
    }
    if let Some(registry) = state.aggregate_updates.as_mut() {
        aggregate_updates::invalidate_local_baseline(args, registry, sequence)?;
    }
    state.cycles[index].retirement = Some(record);
    state.latest = restored.local;
    if let Some(pending) = pending {
        state.cycles[pending].phase = Phase::Failed;
    }
    store.save_state(&serde_json::to_value(&*state)?)?;
    eprintln!("compute loop_event=local_successor_retired_exact_predecessor_restored");
    Ok(true)
}

pub(super) fn allows_empty_latest(store: &Store, state: &State) -> Result<bool> {
    if state.latest.is_some() || state.promoted == 0 {
        return Ok(false);
    }
    // The last retained promoted local cycle must itself have been retired to
    // an aggregate with no local predecessor. Later aggregate A→B adoption is
    // legitimate; this historical exception must not depend on A still active.
    let Some(cycle) = state
        .cycles
        .iter()
        .filter(|cycle| cycle.snapshot.is_some() && cycle.phase != Phase::Rejected)
        .max_by_key(|cycle| cycle.sequence)
    else {
        return Ok(false);
    };
    let Some(retired) = &cycle.retirement else {
        return Ok(false);
    };
    if state.aggregate_updates.is_none()
        || retired.restored_origin["kind"] != "aggregate_update"
        || !retired.restored_origin["local_predecessor"].is_null()
    {
        return Ok(false);
    }
    let _ = verify(store, cycle)?;
    Ok(true)
}

/// Keep the exact direct local predecessor available, not an arbitrary older model.
pub(super) fn protected_sequences(store: &Store, state: &State) -> Result<BTreeSet<u64>> {
    let mut protected = BTreeSet::new();
    if let Some(sequence) = state.latest {
        let cycle = state
            .cycles
            .iter()
            .find(|cycle| cycle.sequence == sequence)
            .context("local_retirement_latest_missing")?;
        ensure!(
            cycle.retirement.is_none(),
            "local_retirement_active_retired"
        );
        let record = evaluation::verify(store, sequence)?;
        if let Some(previous) = record.predecessor {
            protected.insert(previous);
        }
    } else if allows_empty_latest(store, state)? {
        if let Some(cycle) = state
            .cycles
            .iter()
            .filter(|cycle| cycle.retirement.is_some())
            .max_by_key(|cycle| cycle.sequence)
        {
            protected.insert(cycle.sequence);
        }
    }
    Ok(protected)
}

#[cfg(test)]
mod tests;
