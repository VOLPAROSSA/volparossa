//! Local aggregate extraction retirement, never publisher blame or a new approval.

use super::*;

const SCOPE: &str = "local-extracted-aggregate-integrity-not-publisher-or-network-ban";
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
    observed_at: u64,
    original_snapshot_sha256: String,
    observed_adapter_files: Snapshot,
    restored_origin: Value,
    restored_expires: u64,
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

/// Unreadable/missing/linked/foreign-owned files and changed evidence are ordinary
/// errors. Only bounded byte differences in the same three extracted files qualify.
fn changed_extraction(expected: &Snapshot, actual: &Snapshot) -> Result<Option<Snapshot>> {
    ensure!(
        expected.keys().eq(actual.keys()),
        "aggregate_retirement_fileset_changed"
    );
    let mut observed = Snapshot::new();
    let mut changed = false;
    for (path, original) in expected {
        let current = &actual[path];
        if let Some((name, maximum)) = FILES
            .iter()
            .find(|(name, _)| path == &format!("candidate/import/adapter/{name}"))
        {
            ensure!(
                current.bytes <= *maximum,
                "aggregate_retirement_extraction_bound"
            );
            changed |= current != original;
            observed.insert((*name).to_owned(), current.clone());
        } else {
            ensure!(
                original == current,
                "aggregate_retirement_original_evidence_changed"
            );
        }
    }
    ensure!(
        observed.len() == FILES.len(),
        "aggregate_retirement_extraction_missing"
    );
    Ok(changed.then_some(observed))
}

fn approved_original(args: &Options, registry: &Registry, round: &Round) -> Result<Value> {
    ensure!(
        round.phase == Phase::Approved,
        "aggregate_retirement_unapproved"
    );
    let directory = root(args, round.sequence)?;
    let approved = aggregate::reopen_retired_original(&directory, &args.limits, round.observed_at)?;
    let selection: Value =
        serde_json::from_slice(&read_file(&directory.join("selection.json"), 64 * 1024)?)?;
    let proof: Value =
        serde_json::from_slice(&read_file(&directory.join("cohort.json"), 512 * 1024)?)?;
    ensure!(
        round.approval.as_ref() == Some(&approved.identity)
            && round.expires == approved.expires
            && selection["plan"] == registry.selection["plan"]
            && selection["validation_source"] == registry.selection["validation_source"]
            && selection
                .get("baseline_expires_unix_seconds")
                .and_then(Value::as_u64)
                == round.baseline_expires
            && proof["baseline"]["adapter_files"] == serde_json::to_value(&round.baseline_files)?,
        "aggregate_retirement_original_approval"
    );
    for (index, id) in round.cohort.manifest_ids.iter().enumerate() {
        let signed = read_file(
            &directory.join(format!("peers/{index}/import/adapter.manifest")),
            64 * 1024,
        )?;
        ensure!(
            &hex::encode(Sha256::digest(signed)) == id,
            "aggregate_retirement_original_cohort"
        );
    }
    let files: Snapshot = serde_json::from_value(approved.identity["adapter_files"].clone())?;
    let snapshot = round
        .snapshot
        .as_ref()
        .context("aggregate_retirement_snapshot")?;
    ensure!(
        files.len() == FILES.len()
            && files.iter().all(|(name, identity)| snapshot
                .get(&format!("candidate/import/adapter/{name}"))
                == Some(identity)),
        "aggregate_retirement_original_extraction"
    );
    Ok(
        json!({"kind":"aggregate_update","aggregate_sequence":round.sequence,
        "local_predecessor":round.local_predecessor,"manifest_ids":round.cohort.manifest_ids,
        "dataset_manifest_id":approved.identity["dataset_manifest_id"],
        "cohort_sha256":approved.identity["cohort_sha256"],
        "comparison_sha256":approved.identity["comparison_sha256"],
        "result_sha256":approved.identity["result_sha256"],
        "adapter_files":approved.identity["adapter_files"],"expires_unix_seconds":round.expires}),
    )
}

fn predecessor(
    args: &Options,
    store: &Store,
    state: &State,
    registry: &Registry,
    round: &Round,
) -> Result<(Option<u64>, u64)> {
    ensure!(
        round.local_predecessor == state.latest,
        "aggregate_retirement_local_history"
    );
    let (sequence, current) = match round.baseline_origin["kind"].as_str() {
        Some("aggregate_update") => {
            let sequence = round.baseline_origin["aggregate_sequence"]
                .as_u64()
                .filter(|sequence| *sequence > 0 && *sequence < round.sequence)
                .context("aggregate_retirement_predecessor_order")?;
            (
                Some(sequence),
                selected_for_sequence(args, registry, sequence, state.latest)?,
            )
        }
        Some("local_cycle") => {
            let sequence = round.baseline_origin["sequence"]
                .as_u64()
                .context("aggregate_retirement_local_sequence")?;
            ensure!(
                state.latest == Some(sequence),
                "aggregate_retirement_local_predecessor"
            );
            let (path, expires, _) = super::super::serving::local_candidate(store, state)?
                .context("aggregate_retirement_local_missing")?;
            (
                None,
                CurrentAdapter {
                    adapter_root: Some(path),
                    origin: json!({"kind":"local_cycle","sequence":sequence}),
                    authority_expires: Some(expires),
                },
            )
        }
        _ => anyhow::bail!("aggregate_retirement_no_approved_predecessor"),
    };
    let expires = current
        .authority_expires
        .context("aggregate_retirement_predecessor_expiry")?;
    let path = current
        .adapter_root
        .context("aggregate_retirement_predecessor_adapter")?;
    ensure!(
        current.origin == round.baseline_origin
            && Some(expires) == round.baseline_expires
            && now()? < expires
            && Some(serde_json::to_value(
                super::super::peer_evaluation::adapter_files(&path)?
            )?) == round.baseline_files,
        "aggregate_retirement_predecessor_binding_or_expiry"
    );
    let selected: Value = serde_json::from_slice(&read_file(
        &root(args, round.sequence)?.join("selection.json"),
        64 * 1024,
    )?)?;
    ensure!(
        selected["baseline_adapter"] == serde_json::to_value(path)?,
        "aggregate_retirement_predecessor_path"
    );
    Ok((sequence, expires))
}

pub(super) fn verify(args: &Options, registry: &Registry, round: &Round) -> Result<()> {
    let record = round
        .retirement
        .as_ref()
        .context("aggregate_retirement_missing_record")?;
    let original = round
        .snapshot
        .as_ref()
        .context("aggregate_retirement_snapshot")?;
    let observed = changed_extraction(original, &snapshot(&root(args, round.sequence)?)?)?
        .context("aggregate_retirement_missing_difference")?;
    approved_original(args, registry, round)?;
    ensure!(
        record.version == 1
            && record.scope == SCOPE
            && record.original_snapshot_sha256 == digest(original)?
            && record.observed_adapter_files == observed
            && record.observed_at >= round.observed_at
            && record.observed_at <= now()?
            && record.restored_expires > record.observed_at
            && Some(record.restored_expires) == round.baseline_expires
            && record.restored_origin == round.baseline_origin
            && matches!(
                record.restored_origin["kind"].as_str(),
                Some("aggregate_update" | "local_cycle")
            )
            && registry.active != Some(round.sequence),
        "aggregate_retirement_record_binding"
    );
    Ok(())
}

pub(super) fn invalidate_pending(
    args: &Options,
    registry: &mut Registry,
    origin: &Value,
) -> Result<()> {
    for pending in &mut registry.rounds {
        if pending.phase == Phase::Running && &pending.baseline_origin == origin {
            pending.snapshot = Some(snapshot(&root(args, pending.sequence)?)?);
            pending.phase = Phase::Failed;
        }
    }
    Ok(())
}

/// Called under the coordinator lock, only between reaped attempts. Withdrawal
/// precedes changing the selected pointer; a failed predecessor check stays closed.
pub(in crate::compute::train_loop) fn recover_active(
    args: &Options,
    store: &Store,
    state: &mut State,
    serving: &mut Option<super::super::serving::Serving>,
) -> Result<bool> {
    let Some(mut registry) = state.aggregate_updates.clone() else {
        return Ok(false);
    };
    let Some(sequence) = registry.active else {
        return Ok(false);
    };
    let round = registry
        .rounds
        .iter()
        .find(|round| round.sequence == sequence)
        .context("aggregate_retirement_active_missing")?
        .clone();
    ensure!(
        round.retirement.is_none(),
        "aggregate_retirement_active_retired"
    );
    let original = round
        .snapshot
        .as_ref()
        .context("aggregate_retirement_snapshot")?;
    let actual = snapshot(&root(args, sequence)?)?;
    if &actual == original {
        return Ok(false);
    }
    let observed =
        changed_extraction(original, &actual)?.context("aggregate_retirement_not_extraction")?;
    let origin = approved_original(args, &registry, &round)?;
    if let Some(serving) = serving {
        serving.withdraw()?;
    }
    let (selected, expires) = predecessor(args, store, state, &registry, &round)
        .map_err(|_| anyhow::anyhow!("aggregate_retirement_no_verified_predecessor"))?;
    // An interrupted comparison cannot reuse its old receipts against a new baseline.
    for cycle in &mut state.cycles {
        if cycle.phase == super::super::Phase::Evaluating {
            let selection = store.read_cycle_json(cycle.sequence, "selection.json")?;
            if selection["aggregate_predecessor"] == origin {
                store.validate_training(
                    cycle.sequence,
                    cycle
                        .training
                        .as_ref()
                        .context("aggregate_retirement_pending_training")?,
                )?;
                ensure!(
                    selection["adapter_root"]
                        == serde_json::to_value(
                            root(args, sequence)?.join("candidate/import/adapter")
                        )?,
                    "aggregate_retirement_pending_adapter"
                );
                cycle.phase = super::super::Phase::Failed;
            }
        }
    }
    invalidate_pending(args, &mut registry, &origin)?;
    let observed_at = now()?;
    ensure!(
        observed_at < expires,
        "aggregate_retirement_predecessor_expired_before_checkpoint"
    );
    registry
        .rounds
        .iter_mut()
        .find(|entry| entry.sequence == sequence)
        .context("aggregate_retirement_active_missing")?
        .retirement = Some(Record {
        version: 1,
        scope: SCOPE.into(),
        observed_at,
        original_snapshot_sha256: digest(original)?,
        observed_adapter_files: observed,
        restored_origin: round.baseline_origin,
        restored_expires: expires,
    });
    registry.active = selected;
    checkpoint(&registry, store, state)?;
    eprintln!("compute loop_event=active_aggregate_retired_predecessor_restored");
    Ok(true)
}

/// Pin only the selected aggregate and its direct predecessor, or the exact
/// aggregate baseline of the selected local cycle. No arbitrary old round wins.
pub(super) fn pinned_sequences(
    registry: &Registry,
    store: &Store,
    latest: Option<u64>,
) -> Result<BTreeSet<u64>> {
    let mut pinned = BTreeSet::new();
    let approved = |previous: &u64| {
        registry.rounds.iter().any(|round| {
            round.sequence == *previous
                && round.phase == Phase::Approved
                && round.retirement.is_none()
        })
    };
    if let Some(sequence) = registry.active {
        let round = registry
            .rounds
            .iter()
            .find(|round| round.sequence == sequence)
            .context("aggregate_retirement_pin_missing")?;
        ensure!(
            round.retirement.is_none(),
            "aggregate_retirement_pin_retired"
        );
        pinned.insert(sequence);
        if round.baseline_origin["kind"] == "aggregate_update" {
            pinned.extend(
                round.baseline_origin["aggregate_sequence"]
                    .as_u64()
                    .filter(approved),
            );
        }
    }
    if let Some(sequence) = latest {
        let selection = store.read_cycle_json(sequence, "selection.json")?;
        pinned.extend(
            selection["aggregate_predecessor"]["aggregate_sequence"]
                .as_u64()
                .filter(approved),
        );
    }
    Ok(pinned)
}

#[cfg(test)]
mod tests;
