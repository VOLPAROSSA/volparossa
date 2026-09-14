//! Explicit second-source selection-set validation using two real inference jobs.
//! Repeated selection on this set is not an independent benchmark, nor proof
//! that a pretrained/imported model never encountered the public source before.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    SignedManifest,
    agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION},
    provider::compute::dataset::verify_source,
};

use super::{
    Options, Source, State, Store, active, now, private_directory, read_file, storage::FileSnapshot,
};
use crate::content::agent_artifact::{self, TrainingSource};

const POLICY: &str = "second-source-heldout-loss-v1";
const SCOPE: &str = "explicit-second-source-selection-set-not-independent-benchmark-or-historical-contamination-proof";
const EPSILON: f64 = 1e-6;
const SOURCE_FILES: [(&str, u64); 3] = [
    ("dataset.json", 1024 * 1024),
    ("dataset.manifest", 64 * 1024),
    ("provenance.json", 64 * 1024),
];
const ADAPTER_FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];
type Files = BTreeMap<String, FileSnapshot>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    policy: String,
    scope: String,
    epsilon: f64,
    pub(super) sequence: u64,
    pub(super) approved: bool,
    source_manifest_id: String,
    publisher_key: String,
    source_revision: String,
    source_expires_unix_seconds: u64,
    files: Files,
    model_id: String,
    model_revision: String,
    baseline_input_adapter: Option<Value>,
    candidate_input_adapter: Value,
    baseline: Metric,
    candidate: Metric,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Metric {
    loss: f64,
    target_tokens: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    version: u32,
    selection: Source,
    manifest_id: String,
    verified_at_unix_seconds: u64,
    expires_unix_seconds: u64,
    dataset: FileSnapshot,
    manifest: FileSnapshot,
    source_receipt: Value,
}

struct PublicInput {
    bytes: Vec<u8>,
    manifest: Vec<u8>,
    provenance: Provenance,
    raw_provenance: Vec<u8>,
    source_revision: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    version: u32,
    started_at_unix_seconds: u64,
    verified_at_unix_seconds: u64,
    deadline_unix_seconds: u64,
    report: Value,
}

pub(super) fn selection(args: &Options) -> Result<Option<Source>> {
    args.validation_source
        .as_ref()
        .map(|path| {
            let selected: Source = serde_json::from_slice(&read_file(path, 64 * 1024)?)?;
            validate_selection(&selected)?;
            Ok(selected)
        })
        .transpose()
}

fn validate_selection(source: &Source) -> Result<()> {
    source.key()?;
    crate::content::parse_content_name(&source.name).map_err(anyhow::Error::msg)?;
    ensure!(
        source.manifest()?.is_some() && source.min_revision != Some(0),
        "train_validation_exact_source_required"
    );
    Ok(())
}

pub(super) async fn prepare(
    args: &Options,
    socket: &Path,
    enrollment: &Value,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let Some(selected) = enrollment.get("validation_source").filter(|v| !v.is_null()) else {
        ensure!(
            state.validation.is_none() && args.validation_source.is_none(),
            "train_validation_unrequested_source"
        );
        return Ok(());
    };
    let selected: Source = serde_json::from_value(selected.clone())?;
    validate_selection(&selected)?;
    let root = args.directory.join("validation-input");
    if let Some(expected) = &state.validation {
        ensure!(
            &snapshot(&root)? == expected,
            "train_validation_source_snapshot_changed"
        );
        let input = load_input(&root)?;
        ensure!(
            serde_json::to_value(&input.provenance.selection)? == serde_json::to_value(&selected)?,
            "train_validation_enrollment_changed"
        );
        return Ok(());
    }
    ensure!(active(activity), "train_validation_cancelled");
    ensure!(
        !present(&root)?,
        "train_validation_unconfirmed_source_retained"
    );
    make_directory(&root)?;
    let request = TrainingSource {
        publisher_key: selected.key()?,
        name: selected.name.clone(),
        manifest_id: selected.manifest()?,
        min_revision: selected.min_revision,
        cache: args.cache.clone(),
        reuse_cache: true,
        limits: args.limits.clone(),
    };
    let mut changed = activity.clone();
    let downloaded = tokio::select! { biased;
        _=changed.changed()=>bail!("train_validation_cancelled"),
        result=agent_artifact::fetch_training_source(&request,socket,&root)=>result?,
    };
    let at = now()?;
    let provenance = Provenance {
        version: 1,
        selection: selected,
        manifest_id: hex::encode(request.manifest_id.context("train_validation_manifest")?),
        verified_at_unix_seconds: at,
        expires_unix_seconds: downloaded.expires,
        dataset: identity(&downloaded.dataset),
        manifest: identity(&downloaded.signed_manifest),
        source_receipt: downloaded.receipt,
    };
    validate_source(
        &downloaded.dataset,
        &downloaded.signed_manifest,
        &provenance,
    )?;
    write_new(&root.join("dataset.json"), &downloaded.dataset)?;
    write_new(&root.join("dataset.manifest"), &downloaded.signed_manifest)?;
    write_json(&root.join("provenance.json"), &provenance)?;
    state.validation = Some(snapshot(&root)?);
    store.save_state(&serde_json::to_value(state)?)
}

/// This source must be pinned before training. The caller compares its held-out
/// rows against each actual training input; cache presence does not select it.
pub(super) fn data(args: &Options, state: &State) -> Result<Option<Vec<u8>>> {
    let Some(selected) = selection(args)? else {
        ensure!(
            state.validation.is_none(),
            "train_validation_unrequested_source"
        );
        return Ok(None);
    };
    let root = args.directory.join("validation-input");
    ensure!(
        state.validation.as_ref() == Some(&snapshot(&root)?),
        "train_validation_source_snapshot_changed"
    );
    let input = load_input(&root)?;
    ensure!(
        serde_json::to_value(&selected)? == serde_json::to_value(&input.provenance.selection)?
            && input.provenance.expires_unix_seconds > now()?,
        "train_validation_source_expired_or_changed"
    );
    Ok(Some(input.bytes))
}

pub(super) async fn assess(
    args: &Options,
    store: &Store,
    state: &State,
    sequence: u64,
    activity: &watch::Receiver<bool>,
) -> Result<Record> {
    let cycle = store.cycle_path(sequence)?;
    let prepared = args.directory.join("validation-input");
    ensure!(
        state.validation.as_ref() == Some(&snapshot(&prepared)?),
        "train_validation_source_snapshot_changed"
    );
    let root = cycle.join("validation");
    if present(&cycle.join("validation.json"))? {
        ensure!(
            snapshot(&root)? == snapshot(&prepared)?,
            "train_validation_cycle_source_changed"
        );
        return verify(store, sequence);
    }
    let source = load_input(&prepared)?;
    if !present(&root)? {
        ensure!(active(activity), "train_validation_cancelled");
        make_directory(&root)?;
        write_new(&root.join("dataset.json"), &source.bytes)?;
        write_new(&root.join("dataset.manifest"), &source.manifest)?;
        write_new(&root.join("provenance.json"), &source.raw_provenance)?;
    }
    ensure!(
        snapshot(&root)? == snapshot(&prepared)?,
        "train_validation_cycle_source_changed"
    );
    let result = store.read_cycle_json(sequence, "result.json")?;
    let selected = store.read_cycle_json(sequence, "selection.json")?;
    let baseline_root: Option<PathBuf> = serde_json::from_value(selected["adapter_root"].clone())?;
    let training_expires = result["source_expires_unix_seconds"]
        .as_u64()
        .context("train_validation_training_expiry")?;
    run_stage(
        args,
        &cycle,
        &source,
        training_expires,
        "baseline",
        baseline_root.as_deref(),
        activity,
    )
    .await?;
    run_stage(
        args,
        &cycle,
        &source,
        training_expires,
        "candidate",
        Some(&cycle.join("training/adapter")),
        activity,
    )
    .await?;
    let record = recompute(store, sequence)?;
    store.write_cycle_json(sequence, "validation.json", &serde_json::to_value(&record)?)?;
    Ok(record)
}

// Two deliberately sequential jobs share the normal runtime lock and owner
// pressure controls. They do not get a combined or silently renewed lease.
#[allow(clippy::too_many_arguments)]
async fn run_stage(
    args: &Options,
    cycle: &Path,
    source: &PublicInput,
    training_expires: u64,
    stage: &str,
    adapter: Option<&Path>,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let envelope = cycle.join(format!("{stage}-report.json"));
    if present(&envelope)? {
        check_stage(cycle, source, training_expires, stage)?;
        return Ok(());
    }
    let output = cycle.join("validation").join(stage);
    // Existing raw output without the supervisor's durable envelope is retained
    // as an explicit interrupted-stage failure, never adopted or erased silently.
    ensure!(
        !present(&output)?,
        "train_validation_interrupted_stage_retained"
    );
    ensure!(active(activity), "train_validation_cancelled");
    let started = now()?;
    let expires = source.provenance.expires_unix_seconds.min(training_expires);
    let seconds = expires
        .checked_sub(started)
        .filter(|n| *n > 0)
        .context("train_validation_source_expired")?
        .min(u64::from(args.max_seconds));
    let options = super::super::Options {
        mode: super::super::Mode::Infer,
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        dataset: cycle.join("validation/dataset.json"),
        output,
        adapter_root: adapter.map(Path::to_path_buf),
        steps: 1,
        threads: args.threads,
        max_seconds: u16::try_from(seconds)?,
        spare_capacity: true,
        execute: true,
    };
    options.validate()?;
    let report = super::super::execute(&options, activity.clone()).await?;
    ensure!(
        active(activity),
        "train_validation_cancelled_completed_output_retained"
    );
    let completed = Stage {
        version: 1,
        started_at_unix_seconds: started,
        verified_at_unix_seconds: now()?,
        deadline_unix_seconds: started + seconds,
        report,
    };
    // Check every completed field before persisting a resumable full report.
    validate_stage(&completed, cycle, source, training_expires, stage)?;
    write_json(&envelope, &completed)?;
    Ok(())
}

pub(super) fn verify(store: &Store, sequence: u64) -> Result<Record> {
    let saved: Record =
        serde_json::from_value(store.read_cycle_json(sequence, "validation.json")?)?;
    let actual = recompute(store, sequence)?;
    ensure!(saved == actual, "train_validation_record_changed");
    Ok(actual)
}

fn recompute(store: &Store, sequence: u64) -> Result<Record> {
    ensure!(sequence > 0, "train_validation_sequence");
    let cycle = store.cycle_path(sequence)?;
    let input = load_input(&cycle.join("validation"))?;
    let result = store.read_cycle_json(sequence, "result.json")?;
    let training_expires = result["source_expires_unix_seconds"]
        .as_u64()
        .context("train_validation_training_expiry")?;
    ensure!(
        result["dataset_manifest_id"] != input.provenance.manifest_id
            && result["dataset_sha256"] != input.provenance.dataset.sha256,
        "train_validation_training_source_reused"
    );
    let baseline = check_stage(&cycle, &input, training_expires, "baseline")?;
    let candidate = check_stage(&cycle, &input, training_expires, "candidate")?;
    let old = metric(&baseline.report["baseline_evaluation"])?;
    let new = metric(&candidate.report["baseline_evaluation"])?;
    ensure!(
        old.target_tokens == new.target_tokens,
        "train_validation_tokens_changed"
    );
    let mut files = Files::new();
    for (name, limit) in SOURCE_FILES {
        let path = format!("validation/{name}");
        files.insert(
            path.clone(),
            identity(&read_owned(&cycle.join(path), limit)?),
        );
    }
    for (name, limit) in [
        ("baseline-report.json", 64 * 1024),
        ("candidate-report.json", 64 * 1024),
        ("validation/baseline/report.json", 16 * 1024),
        ("validation/candidate/report.json", 16 * 1024),
        ("training-report.json", 32 * 1024),
        ("result.json", 64 * 1024),
        ("selection.json", 64 * 1024),
    ] {
        files.insert(
            name.into(),
            identity(&read_owned(&cycle.join(name), limit)?),
        );
    }
    for (name, limit) in ADAPTER_FILES {
        let path = format!("training/adapter/{name}");
        files.insert(
            path.clone(),
            identity(&read_owned(&cycle.join(path), limit)?),
        );
    }
    Ok(Record {
        version: 1,
        policy: POLICY.into(),
        scope: SCOPE.into(),
        epsilon: EPSILON,
        sequence,
        approved: new.loss < old.loss - EPSILON,
        source_manifest_id: input.provenance.manifest_id,
        publisher_key: input.provenance.selection.publisher_key,
        source_revision: input.source_revision,
        source_expires_unix_seconds: input.provenance.expires_unix_seconds,
        files,
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        baseline_input_adapter: baseline.report.get("input_adapter").cloned(),
        candidate_input_adapter: candidate.report["input_adapter"].clone(),
        baseline: old,
        candidate: new,
    })
}

fn check_stage(
    cycle: &Path,
    input: &PublicInput,
    training_expires: u64,
    name: &str,
) -> Result<Stage> {
    let stage: Stage = serde_json::from_slice(&read_owned(
        &cycle.join(format!("{name}-report.json")),
        64 * 1024,
    )?)?;
    validate_stage(&stage, cycle, input, training_expires, name)?;
    Ok(stage)
}

fn validate_stage(
    stage: &Stage,
    cycle: &Path,
    input: &PublicInput,
    training_expires: u64,
    name: &str,
) -> Result<()> {
    ensure!(
        matches!(name, "baseline" | "candidate"),
        "train_validation_stage"
    );
    let report = &stage.report;
    let seconds = report["supervisor"]["deadline_seconds"]
        .as_u64()
        .filter(|n| (1..=600).contains(n))
        .context("train_validation_deadline")?;
    ensure!(
        stage.version == 1
            && stage.started_at_unix_seconds > 0
            && stage.started_at_unix_seconds >= input.provenance.verified_at_unix_seconds
            && stage.started_at_unix_seconds.checked_add(seconds)
                == Some(stage.deadline_unix_seconds)
            && stage.started_at_unix_seconds <= stage.verified_at_unix_seconds
            && stage.verified_at_unix_seconds <= stage.deadline_unix_seconds
            && stage.verified_at_unix_seconds <= now()?
            && stage.verified_at_unix_seconds
                < input.provenance.expires_unix_seconds.min(training_expires)
            && stage.deadline_unix_seconds
                <= input.provenance.expires_unix_seconds.min(training_expires),
        "train_validation_stage_expiry"
    );
    let mut raw_report = report.clone();
    raw_report
        .as_object_mut()
        .context("train_validation_report")?
        .remove("supervisor");
    let stored: Value = serde_json::from_slice(&read_owned(
        &cycle.join(format!("validation/{name}/report.json")),
        16 * 1024,
    )?)?;
    ensure!(
        raw_report == stored
            && report["version"] == 1
            && report["kind"] == "result"
            && report["status"] == "ok"
            && report["mode"] == "infer"
            && report["device"] == "cpu"
            && report["id"]
                .as_str()
                .is_some_and(|id| super::super::is_hex(id, 32))
            && report["updates_completed"] == 0
            && report["artifacts"].as_array().is_some_and(Vec::is_empty)
            && report["model"]["id"] == MODEL_ID
            && report["model"]["revision"] == MODEL_REVISION
            && report["model"]["files"]["model.safetensors"]["sha256"]
                == hex::encode(BASE_MODEL_SHA256)
            && report["model"]["files"]["model.safetensors"]["bytes"] == 269_060_552_u64
            && report["dataset"]["sha256"] == input.provenance.dataset.sha256
            && report["dataset"]["bytes"] == input.provenance.dataset.bytes
            && report["dataset"]["source_revision"] == input.source_revision
            && report["dataset"]["visibility"] == "public"
            && report["dataset"]["license"] == "GPL-3.0-only"
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["supervisor"]["spare_capacity"] == true
            && report["elapsed_ms"]
                .as_u64()
                .is_some_and(|n| n <= seconds * 1000),
        "train_validation_report_binding"
    );
    metric(&report["baseline_evaluation"])?;
    validate_adapter(cycle, report, name)
}

fn validate_adapter(cycle: &Path, report: &Value, name: &str) -> Result<()> {
    let training: Value =
        serde_json::from_slice(&read_owned(&cycle.join("training-report.json"), 32 * 1024)?)?;
    let selected: Value =
        serde_json::from_slice(&read_owned(&cycle.join("selection.json"), 64 * 1024)?)?;
    if name == "baseline" {
        if let Some(original) = training.get("input_adapter") {
            ensure!(
                report.get("input_adapter") == Some(original)
                    && selected["adapter_root"]
                        .as_str()
                        .is_some_and(|p| Path::new(p).is_absolute()),
                "train_validation_baseline_adapter"
            );
        } else {
            ensure!(
                report.get("input_adapter").is_none() && selected["adapter_root"].is_null(),
                "train_validation_unexpected_baseline_adapter"
            );
            return Ok(());
        }
    }
    let adapter = &report["input_adapter"];
    ensure!(
        adapter["applied"] == true
            && adapter["model_id"] == MODEL_ID
            && adapter["model_revision"] == MODEL_REVISION
            && adapter["applied_parameters"]["parameters"] == 230_400_u64
            && adapter["base_parameters_before_apply"] == training["base_before"]
            && adapter["base_parameters_after_apply"] == training["base_before"],
        "train_validation_adapter_binding"
    );
    if name == "candidate" {
        ensure!(
            adapter["applied_parameters"] == training["adapter_after"],
            "train_validation_candidate_parameters"
        );
        let expected: Files = ADAPTER_FILES
            .into_iter()
            .map(|(file, limit)| {
                Ok((
                    file.into(),
                    identity(&read_owned(
                        &cycle.join("training/adapter").join(file),
                        limit,
                    )?),
                ))
            })
            .collect::<Result<_>>()?;
        ensure!(
            serde_json::from_value::<Files>(adapter["files"].clone())? == expected,
            "train_validation_candidate_files"
        );
    }
    Ok(())
}

fn load_input(root: &Path) -> Result<PublicInput> {
    let bytes = read_owned(&root.join("dataset.json"), 1024 * 1024)?;
    let manifest = read_owned(&root.join("dataset.manifest"), 64 * 1024)?;
    let raw_provenance = read_owned(&root.join("provenance.json"), 64 * 1024)?;
    let provenance: Provenance = serde_json::from_slice(&raw_provenance)?;
    let source_revision = validate_source(&bytes, &manifest, &provenance)?;
    Ok(PublicInput {
        bytes,
        manifest,
        provenance,
        raw_provenance,
        source_revision,
    })
}

fn validate_source(bytes: &[u8], manifest: &[u8], source: &Provenance) -> Result<String> {
    validate_selection(&source.selection)?;
    ensure!(
        source.version == 1
            && source.verified_at_unix_seconds > 0
            && source.verified_at_unix_seconds <= now()?
            && source.dataset == identity(bytes)
            && source.manifest == identity(manifest),
        "train_validation_source_identity"
    );
    let key = source.selection.key()?;
    let verified = verify_source(
        manifest,
        &key,
        std::str::from_utf8(bytes)?,
        source.verified_at_unix_seconds,
    )?;
    let signed = SignedManifest::decode(manifest)?.verify(&key, source.verified_at_unix_seconds)?;
    let dataset: Value = serde_json::from_slice(bytes)?;
    ensure!(
        !verified.is_document()
            && dataset["train"].as_array().is_some_and(Vec::is_empty)
            && *verified.manifest_id()
                == source
                    .selection
                    .manifest()?
                    .context("train_validation_manifest")?
            && source.manifest_id == hex::encode(verified.manifest_id())
            && source.expires_unix_seconds == verified.expires()
            && source.selection.name == signed.metadata().name
            && source
                .selection
                .min_revision
                .is_none_or(|n| signed.metadata().revision >= n),
        "train_validation_signed_source"
    );
    Ok(dataset["source_revision"]
        .as_str()
        .context("train_validation_source_revision")?
        .into())
}

fn metric(value: &Value) -> Result<Metric> {
    let metric: Metric = serde_json::from_value(value.clone())?;
    ensure!(
        metric.loss.is_finite() && metric.loss >= 0.0 && metric.target_tokens > 0,
        "train_validation_invalid_metric"
    );
    Ok(metric)
}

fn snapshot(root: &Path) -> Result<Value> {
    private_directory(root)?;
    let values: Files = SOURCE_FILES
        .into_iter()
        .map(|(name, limit)| Ok((name.into(), identity(&read_owned(&root.join(name), limit)?))))
        .collect::<Result<_>>()?;
    Ok(serde_json::to_value(values)?)
}

fn identity(bytes: &[u8]) -> FileSnapshot {
    FileSnapshot {
        sha256: hex::encode(Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn read_owned(path: &Path, limit: u64) -> Result<Vec<u8>> {
    private_directory(path.parent().context("train_validation_parent")?)?;
    read_file(path, limit)
}
fn make_directory(path: &Path) -> Result<()> {
    private_directory(path.parent().context("train_validation_parent")?)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    File::open(path.parent().context("train_validation_parent")?)?.sync_all()?;
    Ok(())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_new(path, &serde_json::to_vec(value)?)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("train_validation_parent")?;
    private_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
