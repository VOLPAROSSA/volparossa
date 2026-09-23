//! Retirement of a damaged *local extraction*, not a verdict against its publisher.
//! Original signed bytes and completed comparison evidence must remain intact. No
//! network, worker-error string, missing file or ordinary quality difference enters here.

use super::*;
use volparossa_content::{
    SignedManifest, agent_artifact::AdapterBundle, provider::compute::dataset,
};

const SCOPE: &str = "local-extracted-adapter-integrity-not-publisher-or-network-ban";
const ADAPTER_FILES: [(&str, u64); 3] = [
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
    manifest_id: String,
    original_snapshot_sha256: String,
    observed_adapter_files: Snapshot,
    restored_origin: Value,
    restored_expires: u64,
}

#[derive(Debug)]
struct ActiveRecoveryBlocked;

impl std::fmt::Display for ActiveRecoveryBlocked {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("peer_updates_active_integrity_no_verified_predecessor")
    }
}

impl std::error::Error for ActiveRecoveryBlocked {}

/// Only a proven corrupt active extraction can create this classification. The
/// predecessor's failure is not evidence of wrongdoing by that predecessor.
pub(in crate::compute::train_loop) fn recovery_blocked(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ActiveRecoveryBlocked>().is_some()
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn identity(bytes: &[u8]) -> super::super::storage::FileSnapshot {
    super::super::storage::FileSnapshot {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

pub(super) fn predecessor_sequence(registry: &Registry) -> Option<u64> {
    let active = registry
        .completed
        .iter()
        .find(|round| Some(round.sequence) == registry.active)?;
    let baseline = active.baseline.as_ref()?;
    (baseline.origin["kind"] == "peer_update")
        .then(|| baseline.origin["import_sequence"].as_u64())
        .flatten()
        .filter(|id| *id < active.sequence)
}

/// A strict, same-fileset content difference is attributable. An unreadable,
/// missing, linked, foreign-owned or unexpected file remains an ordinary error.
fn changed_extraction(expected: &Snapshot, actual: &Snapshot) -> Result<Option<Snapshot>> {
    ensure!(
        expected.keys().eq(actual.keys()),
        "peer_retirement_fileset_changed"
    );
    let mut observed = Snapshot::new();
    let mut changed = false;
    for (path, original) in expected {
        let current = &actual[path];
        if let Some((name, maximum)) = ADAPTER_FILES
            .iter()
            .find(|(name, _)| path == &format!("import/adapter/{name}"))
        {
            ensure!(
                current.bytes <= *maximum,
                "peer_retirement_extraction_bound"
            );
            changed |= current != original;
            observed.insert((*name).to_owned(), current.clone());
        } else {
            ensure!(
                original == current,
                "peer_retirement_original_evidence_changed"
            );
        }
    }
    ensure!(
        observed.len() == ADAPTER_FILES.len(),
        "peer_retirement_extraction_missing"
    );
    Ok(changed.then_some(observed))
}

/// Revalidate the original signed publication and the original successful
/// comparison independently of the now-damaged extracted copy. No new import or
/// training authority is produced by this historical check.
fn approved_original(args: &Options, registry: &Registry, round: &Round) -> Result<Value> {
    ensure!(round.phase == Phase::Approved, "peer_retirement_unapproved");
    let root = round_root(args, round.sequence)?;
    let at = round.imported_at.context("peer_retirement_import_time")?;
    let query = request(args, &registry.feeds[round.channel], Some(round.revision))?;
    let update = peer_update::open_pending(&root.join("pending"), &query, at)?;
    bind_update(&update, round)?;
    ensure!(
        read_file(&root.join("import/adapter.bundle"), 4 * 1024 * 1024)? == update.bundle()
            && read_file(&root.join("import/adapter.manifest"), 64 * 1024)?
                == update.signed_manifest(),
        "peer_retirement_import_original"
    );
    let comparison = super::super::peer_evaluation::verify(&root)?;
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_retirement_baseline")?;
    let imported: Value = serde_json::from_slice(&read_file(
        &root.join("import/provenance.json"),
        128 * 1024,
    )?)?;
    ensure!(
        comparison.approved
            && comparison.baseline_origin == baseline.origin
            && comparison.import_proof == imported,
        "peer_retirement_original_approval"
    );
    let bundle = AdapterBundle::decode(update.bundle().to_vec())?;
    let original_files: Snapshot = [
        ("README.md", bundle.readme()),
        ("adapter_config.json", bundle.config()),
        ("adapter_model.safetensors", bundle.weights()),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.into(), identity(bytes)))
    .collect();
    let original = round
        .snapshot
        .as_ref()
        .context("peer_retirement_snapshot")?;
    ensure!(
        comparison.candidate_files == original_files
            && original_files
                .iter()
                .all(|(name, file)| original.get(&format!("import/adapter/{name}")) == Some(file)),
        "peer_retirement_original_adapter_binding"
    );
    let source = dataset_source(round.source.as_ref().context("peer_retirement_source")?)?;
    let signed = read_file(&root.join("import/dataset.manifest"), 64 * 1024)?;
    let bytes = read_file(&root.join("import/dataset.json"), 1024 * 1024)?;
    let manifest = SignedManifest::decode(&signed)?.verify(&source.publisher_key, at)?;
    let dataset = dataset::verify_source(
        &signed,
        &source.publisher_key,
        std::str::from_utf8(&bytes)?,
        at,
    )?;
    ensure!(
        !dataset.is_document()
            && manifest.metadata().content_type == dataset::CONTENT_TYPE
            && manifest.metadata().name == source.name
            && manifest.metadata().revision == source.revision
            && manifest.manifest_id() == &source.manifest_id
            && update.dataset_manifest_id() == &source.manifest_id
            && imported["expires_unix_seconds"] == update.expires().min(dataset.expires()),
        "peer_retirement_original_source"
    );
    let selection: Value = serde_json::from_slice(&read_file(
        &root.join("comparison/selection.json"),
        512 * 1024,
    )?)?;
    ensure!(
        selection["candidate_adapter"] == serde_json::to_value(root.join("import/adapter"))?
            && selection["import_proof"] == imported,
        "peer_retirement_original_selection"
    );
    Ok(selection)
}

fn predecessor(
    args: &Options,
    store: &Store,
    state: &State,
    registry: &Registry,
    round: &Round,
    selection: &Value,
    at: u64,
) -> Result<(Option<u64>, u64)> {
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_retirement_baseline")?;
    ensure!(
        baseline.local_predecessor == state.latest,
        "peer_retirement_local_history"
    );
    let (next, path, origin, expires) = match baseline.origin["kind"].as_str() {
        Some("peer_update") => {
            let id = baseline.origin["import_sequence"]
                .as_u64()
                .context("peer_retirement_predecessor")?;
            ensure!(id < round.sequence, "peer_retirement_predecessor_order");
            let mut selected = registry.clone();
            selected.active = Some(id);
            let accepted = active(args, &selected, state.latest)?
                .context("peer_retirement_predecessor_missing")?;
            let raw = read_file(
                &round_root(args, id)?.join("comparison/selection.json"),
                512 * 1024,
            )?;
            let evidence: Value = serde_json::from_slice(&raw)?;
            (
                Some(id),
                accepted.adapter_root,
                accepted.origin,
                evidence["expires"]
                    .as_u64()
                    .context("peer_retirement_predecessor_expiry")?,
            )
        }
        Some("local_cycle") => {
            let id = baseline.origin["sequence"]
                .as_u64()
                .context("peer_retirement_local_sequence")?;
            ensure!(
                state.latest == Some(id),
                "peer_retirement_local_predecessor"
            );
            let (path, expires, _) = super::super::serving::local_candidate(store, state)?
                .context("peer_retirement_local_missing")?;
            (
                None,
                path,
                json!({"kind":"local_cycle","sequence":id}),
                expires,
            )
        }
        _ => anyhow::bail!("peer_retirement_no_approved_predecessor"),
    };
    ensure!(
        origin == baseline.origin
            && baseline.adapter_root.as_ref() == Some(&path)
            && serde_json::to_value(super::super::peer_evaluation::adapter_files(&path)?)?
                == selection["baseline_files"]
            && expires > at,
        "peer_retirement_predecessor_binding_or_expiry"
    );
    Ok((next, expires))
}

/// An interrupted local validation may still name the retired extraction as its
/// baseline. Do not execute it again or reinterpret its receipts against the
/// restored predecessor; preserve its original evidence as a failed attempt.
fn pending_local_cycle(
    args: &Options,
    store: &Store,
    state: &State,
    registry: &Registry,
    round: &Round,
    selection: &Value,
) -> Result<Option<usize>> {
    let root = round_root(args, round.sequence)?;
    let decision = read_file(&root.join("comparison/decision.json"), 512 * 1024)?;
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_retirement_baseline")?;
    let origin = json!({
        "kind":"peer_update", "import_sequence":round.sequence,
        "adapter_manifest_id":round.manifest_id,"dataset_manifest_id":round.dataset_manifest_id,
        "publisher_key":registry.feeds[round.channel].channel.publisher_key,
        "revision":round.revision,"local_predecessor":baseline.local_predecessor,
        "comparison_sha256":hex::encode(Sha256::digest(decision)),
        "adapter_files":selection["candidate_files"]
    });
    for (index, cycle) in state.cycles.iter().enumerate() {
        if cycle.phase != super::super::Phase::Evaluating {
            continue;
        }
        store.validate_training(
            cycle.sequence,
            cycle
                .training
                .as_ref()
                .context("train_loop_training_checkpoint_missing")?,
        )?;
        let selected = store.read_cycle_json(cycle.sequence, "selection.json")?;
        if selected["peer_predecessor"] == origin
            && selected["adapter_root"] == serde_json::to_value(root.join("import/adapter"))?
        {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

pub(super) fn verify(args: &Options, registry: &Registry, round: &Round) -> Result<()> {
    let record = round
        .retirement
        .as_ref()
        .context("peer_retirement_missing_record")?;
    let original = round
        .snapshot
        .as_ref()
        .context("peer_retirement_snapshot")?;
    let observed = changed_extraction(original, &snapshot(&round_root(args, round.sequence)?)?)?
        .context("peer_retirement_missing_original_difference")?;
    let selection = approved_original(args, registry, round)?;
    ensure!(
        record.version == 1
            && record.scope == SCOPE
            && record.manifest_id == round.manifest_id
            && record.original_snapshot_sha256 == digest(original)?
            && record.observed_adapter_files == observed
            && record.observed_at >= round.imported_at.context("peer_retirement_import_time")?
            && record.observed_at <= now()?
            && record.restored_expires > record.observed_at
            && record.restored_origin == selection["baseline_origin"]
            && matches!(
                record.restored_origin["kind"].as_str(),
                Some("peer_update" | "local_cycle")
            )
            && registry.active != Some(round.sequence),
        "peer_retirement_record_binding"
    );
    Ok(())
}

/// No worker is started and no source expiry/budget is renewed. The caller owns
/// the loop lock and invokes this only between fully reaped execution attempts.
pub(in crate::compute::train_loop) fn recover_active(
    args: &Options,
    store: &Store,
    state: &mut State,
) -> Result<bool> {
    let Some(mut registry) = state.peer_updates.clone() else {
        return Ok(false);
    };
    let Some(id) = registry.active else {
        return Ok(false);
    };
    let round = registry
        .completed
        .iter()
        .find(|round| round.sequence == id)
        .context("peer_retirement_active_missing")?
        .clone();
    ensure!(round.retirement.is_none(), "peer_retirement_active_retired");
    let original = round
        .snapshot
        .as_ref()
        .context("peer_retirement_snapshot")?;
    let actual = snapshot(&round_root(args, id)?)?;
    if &actual == original {
        return Ok(false);
    }
    let observed =
        changed_extraction(original, &actual)?.context("peer_retirement_not_extraction")?;
    let selection = approved_original(args, &registry, &round)?;
    let at = now()?;
    // From this point the active local copy is demonstrably damaged. Failure to
    // prove its explicit predecessor is a typed fail-closed outcome, never base fallback.
    let (next, expires) = predecessor(args, store, state, &registry, &round, &selection, at)
        .map_err(|_| anyhow::Error::new(ActiveRecoveryBlocked))?;
    let local_cycle = pending_local_cycle(args, store, state, &registry, &round, &selection)?;
    if registry
        .pending
        .as_ref()
        .is_some_and(|pending| pending.phase == Phase::Evaluating)
    {
        // Its baseline was captured before the rollback. Preserve the failed
        // attempt rather than reusing reports under a different baseline.
        finish(args, &mut registry, Phase::Failed)?;
    }
    registry
        .completed
        .iter_mut()
        .find(|entry| entry.sequence == id)
        .context("peer_retirement_active_missing")?
        .retirement = Some(Record {
        version: 1,
        scope: SCOPE.into(),
        observed_at: at,
        manifest_id: round.manifest_id,
        original_snapshot_sha256: digest(original)?,
        observed_adapter_files: observed,
        restored_origin: round.baseline.context("peer_retirement_baseline")?.origin,
        restored_expires: expires,
    });
    registry.active = next;
    if let Some(index) = local_cycle {
        state.cycles[index].phase = super::super::Phase::Failed;
    }
    checkpoint(&registry, store, state)?;
    eprintln!("compute loop_event=active_local_adapter_retired_predecessor_restored");
    Ok(true)
}

#[cfg(test)]
mod tests;
