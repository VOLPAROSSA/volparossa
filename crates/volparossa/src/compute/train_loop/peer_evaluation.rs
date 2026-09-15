//! Local comparison of a peer update against the actual current adapter.
//! Two real inference jobs use one explicitly pinned public validation set.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    SignedManifest,
    agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION},
};

use super::{Options, Source, active, now, private_directory, read_file, storage::FileSnapshot};

const POLICY: &str = "local-peer-update-validation-loss-v1";
const SCOPE: &str = "owner-selected-public-validation-not-independent-benchmark-or-poisoning-proof";
const EPSILON: f64 = 1e-6;
const ADAPTER_FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];
type Files = BTreeMap<String, FileSnapshot>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Comparison {
    version: u32,
    policy: String,
    scope: String,
    pub(super) approved: bool,
    pub(super) baseline_origin: Value,
    pub(super) import_proof: Value,
    pub(super) candidate_files: Files,
    baseline: Metric,
    candidate: Metric,
    validation_manifest_id: String,
    files: Files,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Metric {
    loss: f64,
    target_tokens: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    version: u32,
    started_at: u64,
    completed_at: u64,
    deadline: u64,
    report: Value,
}

fn identity(bytes: &[u8]) -> FileSnapshot {
    FileSnapshot {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

pub(super) fn adapter_files(root: &Path) -> Result<Files> {
    private_directory(root)?;
    ADAPTER_FILES
        .into_iter()
        .map(|(name, maximum)| {
            Ok((
                name.to_owned(),
                identity(&read_file(&root.join(name), maximum)?),
            ))
        })
        .collect()
}

fn json_file(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read_file(path, 512 * 1024)?)?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("peer_comparison_parent")?)?.sync_all()?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 512 * 1024, "peer_comparison_json_bound");
    write_new(path, &bytes)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn assess(
    args: &Options,
    candidate_root: &Path,
    validation_input_root: &Path,
    baseline_adapter: Option<&Path>,
    baseline_origin: &Value,
    import_proof: &Value,
    activity: &watch::Receiver<bool>,
) -> Result<Comparison> {
    ensure!(active(activity), "peer_comparison_cancelled");
    private_directory(candidate_root)?;
    private_directory(validation_input_root)?;
    let selected =
        super::validation::selection(args)?.context("peer_comparison_validation_required")?;
    let dataset = read_file(&validation_input_root.join("dataset.json"), 1024 * 1024)?;
    let signed = read_file(&validation_input_root.join("dataset.manifest"), 64 * 1024)?;
    let provenance = read_file(&validation_input_root.join("provenance.json"), 64 * 1024)?;
    let verified_at = now()?;
    let validation_expires = validate_source(&selected, &signed, &dataset, verified_at)?;
    let expires = validation_expires.min(
        import_proof["expires_unix_seconds"]
            .as_u64()
            .context("peer_comparison_import_expiry")?,
    );
    ensure!(expires > verified_at, "peer_comparison_source_expired");
    let imported = candidate_root.join("import");
    // A known declared training/validation collision is not excused by importing weights.
    super::super::train_cycle::guard_overlap(
        &read_file(&imported.join("dataset.json"), 1024 * 1024)?,
        &dataset,
    )?;
    let candidate_adapter = imported.join("adapter");
    let expected = json!({"version":1,"validation_source":selected,
        "validation_sha256":identity(&dataset),"validation_manifest":identity(&signed),
        "baseline_origin":baseline_origin,"baseline_adapter":baseline_adapter,
        "baseline_files":baseline_adapter.map(adapter_files).transpose()?,
        "candidate_adapter":candidate_adapter,"candidate_files":adapter_files(&candidate_adapter)?,
        "import_proof":import_proof,"expires":expires,"max_seconds":args.max_seconds,
        "threads":args.threads,"policy":POLICY,"scope":SCOPE});
    let root = candidate_root.join("comparison");
    if root.try_exists()? {
        private_directory(&root)?;
        let saved = json_file(&root.join("selection.json"))?;
        ensure!(saved == expected, "peer_comparison_selected_inputs_changed");
        ensure!(
            read_file(&root.join("dataset.json"), 1024 * 1024)? == dataset
                && read_file(&root.join("dataset.manifest"), 64 * 1024)? == signed
                && read_file(&root.join("provenance.json"), 64 * 1024)? == provenance,
            "peer_comparison_validation_changed"
        );
    } else {
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        write_json(&root.join("selection.json"), &expected)?;
        write_new(&root.join("dataset.json"), &dataset)?;
        write_new(&root.join("dataset.manifest"), &signed)?;
        write_new(&root.join("provenance.json"), &provenance)?;
    }
    if root.join("decision.json").try_exists()? {
        return verify(candidate_root);
    }
    for (stage, adapter) in [
        ("baseline", baseline_adapter),
        ("candidate", Some(candidate_adapter.as_path())),
    ] {
        execute_stage(args, &root, &expected, stage, adapter, activity).await?;
    }
    let comparison = recompute(&root)?;
    write_json(&root.join("decision.json"), &comparison)?;
    Ok(comparison)
}

fn validate_source(source: &Source, signed: &[u8], dataset: &[u8], time: u64) -> Result<u64> {
    let manifest = SignedManifest::decode(signed)?.verify(&source.key()?, time)?;
    ensure!(
        source.manifest()? == Some(*manifest.manifest_id())
            && manifest.metadata().name == source.name
            && source
                .min_revision
                .is_none_or(|floor| manifest.metadata().revision >= floor)
            && manifest.metadata().content_type
                == volparossa_content::provider::compute::dataset::CONTENT_TYPE
            && manifest.length() == dataset.len() as u64
            && manifest.object_sha256() == &<[u8; 32]>::from(Sha256::digest(dataset)),
        "peer_comparison_exact_validation_source"
    );
    let value: Value = serde_json::from_slice(dataset)?;
    ensure!(
        value["version"] == 1
            && value["visibility"] == "public"
            && value["license"] == "GPL-3.0-only"
            && value["train"].as_array().is_some_and(Vec::is_empty),
        "peer_comparison_public_validation_profile"
    );
    Ok(manifest.validity().expires)
}

async fn execute_stage(
    args: &Options,
    root: &Path,
    selection: &Value,
    name: &str,
    adapter: Option<&Path>,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let envelope = root.join(format!("{name}-report.json"));
    if envelope.try_exists()? {
        checked_stage(root, selection, name)?;
        return Ok(());
    }
    let output = root.join(name);
    ensure!(
        !output.try_exists()?,
        "peer_comparison_interrupted_stage_retained"
    );
    ensure!(active(activity), "peer_comparison_cancelled");
    let started = now()?;
    let expires = selection["expires"]
        .as_u64()
        .context("peer_comparison_expiry")?;
    let seconds = expires
        .checked_sub(started)
        .filter(|n| *n > 0)
        .context("peer_comparison_source_expired")?
        .min(u64::from(args.max_seconds));
    let options = super::super::Options {
        mode: super::super::Mode::Infer,
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        dataset: root.join("dataset.json"),
        output,
        adapter_root: adapter.map(Path::to_path_buf),
        steps: 1,
        threads: args.threads,
        max_seconds: u16::try_from(seconds)?,
        spare_capacity: true,
        execute: true,
    };
    options.validate()?;
    // Await cancellation cleanup; never drop an active model supervisor's future.
    let report = super::super::execute(&options, activity.clone()).await?;
    let stage = Stage {
        version: 1,
        started_at: started,
        completed_at: now()?,
        deadline: started + seconds,
        report,
    };
    validate_stage(&stage, root, selection, name)?;
    write_json(&envelope, &stage)
}

fn metric(value: &Value) -> Result<Metric> {
    let loss = value["loss"]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .context("peer_comparison_finite_loss")?;
    let target_tokens = value["target_tokens"]
        .as_u64()
        .filter(|n| (1..=2048).contains(n))
        .context("peer_comparison_target_tokens")?;
    Ok(Metric {
        loss,
        target_tokens,
    })
}

fn checked_stage(root: &Path, selection: &Value, name: &str) -> Result<Stage> {
    let stage: Stage = serde_json::from_slice(&read_file(
        &root.join(format!("{name}-report.json")),
        64 * 1024,
    )?)?;
    validate_stage(&stage, root, selection, name)?;
    Ok(stage)
}

#[allow(clippy::too_many_lines)]
fn validate_stage(stage: &Stage, root: &Path, selection: &Value, name: &str) -> Result<()> {
    ensure!(
        matches!(name, "baseline" | "candidate"),
        "peer_comparison_stage"
    );
    let report = &stage.report;
    let seconds = report["supervisor"]["deadline_seconds"]
        .as_u64()
        .filter(|n| (1..=600).contains(n))
        .context("peer_comparison_deadline")?;
    let expires = selection["expires"]
        .as_u64()
        .context("peer_comparison_expiry")?;
    ensure!(
        stage.version == 1
            && stage.started_at > 0
            && stage.started_at.checked_add(seconds) == Some(stage.deadline)
            && stage.started_at <= stage.completed_at
            && stage.completed_at <= stage.deadline
            && stage.completed_at <= now()?
            && stage.completed_at < expires
            && stage.deadline <= expires,
        "peer_comparison_original_deadline"
    );
    let source: Source = serde_json::from_value(selection["validation_source"].clone())?;
    let signed = read_file(&root.join("dataset.manifest"), 64 * 1024)?;
    let bytes = read_file(&root.join("dataset.json"), 1024 * 1024)?;
    ensure!(
        validate_source(&source, &signed, &bytes, stage.started_at)? >= expires
            && serde_json::to_value(identity(&signed))? == selection["validation_manifest"]
            && serde_json::to_value(identity(&bytes))? == selection["validation_sha256"],
        "peer_comparison_source_substitution"
    );
    let mut worker = report.clone();
    worker
        .as_object_mut()
        .context("peer_comparison_report")?
        .remove("supervisor");
    let actual: Value =
        serde_json::from_slice(&read_file(&root.join(name).join("report.json"), 16 * 1024)?)?;
    ensure!(
        actual == worker
            && report["version"] == 1
            && report["kind"] == "result"
            && report["status"] == "ok"
            && report["mode"] == "infer"
            && report["device"] == "cpu"
            && report["threads"] == selection["threads"]
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
            && report["dataset"]["sha256"] == identity(&bytes).sha256
            && report["dataset"]["bytes"] == bytes.len() as u64
            && report["dataset"]["training_examples"] == 0
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["supervisor"]["spare_capacity"] == true
            && report["elapsed_ms"]
                .as_u64()
                .is_some_and(|n| n <= seconds * 1000),
        "peer_comparison_actual_inference_binding"
    );
    let expected = &selection[if name == "baseline" {
        "baseline_files"
    } else {
        "candidate_files"
    }];
    if expected.is_null() {
        ensure!(
            name == "baseline" && report.get("input_adapter").is_none(),
            "peer_comparison_unexpected_adapter"
        );
    } else {
        let adapter = &report["input_adapter"];
        ensure!(
            adapter["applied"] == true
                && adapter["model_id"] == MODEL_ID
                && adapter["model_revision"] == MODEL_REVISION
                && &adapter["files"] == expected
                && adapter["applied_parameters"]["parameters"] == 230_400_u64
                && adapter["applied_parameters"]["sha256"]
                    .as_str()
                    .is_some_and(|id| super::super::is_hex(id, 64))
                && adapter["base_parameters_before_apply"]
                    == adapter["base_parameters_after_apply"],
            "peer_comparison_actual_adapter_binding"
        );
    }
    metric(&report["baseline_evaluation"])?;
    Ok(())
}

fn recompute(root: &Path) -> Result<Comparison> {
    private_directory(root)?;
    let selection = json_file(&root.join("selection.json"))?;
    ensure!(
        selection["version"] == 1 && selection["policy"] == POLICY && selection["scope"] == SCOPE,
        "peer_comparison_selection_profile"
    );
    let old = checked_stage(root, &selection, "baseline")?;
    let new = checked_stage(root, &selection, "candidate")?;
    ensure!(
        old.completed_at <= new.started_at && old.report["id"] != new.report["id"],
        "peer_comparison_distinct_sequential_jobs"
    );
    let baseline = metric(&old.report["baseline_evaluation"])?;
    let candidate = metric(&new.report["baseline_evaluation"])?;
    ensure!(
        baseline.target_tokens == candidate.target_tokens,
        "peer_comparison_same_targets"
    );
    let files = [
        ("selection.json", 512 * 1024),
        ("dataset.json", 1024 * 1024),
        ("dataset.manifest", 64 * 1024),
        ("provenance.json", 64 * 1024),
        ("baseline-report.json", 64 * 1024),
        ("candidate-report.json", 64 * 1024),
        ("baseline/report.json", 16 * 1024),
        ("candidate/report.json", 16 * 1024),
    ]
    .into_iter()
    .map(|(name, maximum)| {
        Ok((
            name.to_owned(),
            identity(&read_file(&root.join(name), maximum)?),
        ))
    })
    .collect::<Result<Files>>()?;
    Ok(Comparison {
        version: 1,
        policy: POLICY.into(),
        scope: SCOPE.into(),
        approved: candidate.loss < baseline.loss - EPSILON,
        baseline_origin: selection["baseline_origin"].clone(),
        import_proof: selection["import_proof"].clone(),
        candidate_files: serde_json::from_value(selection["candidate_files"].clone())?,
        baseline,
        candidate,
        validation_manifest_id: selection["validation_source"]["manifest_id"]
            .as_str()
            .context("peer_comparison_manifest_id")?
            .into(),
        files,
    })
}

pub(super) fn verify(candidate_root: &Path) -> Result<Comparison> {
    let root = candidate_root.join("comparison");
    let saved: Comparison = serde_json::from_value(json_file(&root.join("decision.json"))?)?;
    let actual = recompute(&root)?;
    ensure!(saved == actual, "peer_comparison_decision_changed");
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_finite_equal_target_metrics_can_support_a_real_comparison() {
        assert_eq!(
            metric(&json!({"loss":0.4,"target_tokens":12}))
                .unwrap()
                .target_tokens,
            12
        );
        for bad in [
            json!({"loss":-1,"target_tokens":12}),
            json!({"loss":null,"target_tokens":12}),
            json!({"loss":0.4,"target_tokens":0}),
            json!({"loss":0.4,"target_tokens":true}),
        ] {
            assert!(metric(&bad).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        assert!(verify(root.path()).is_err()); // No synthetic successful worker receipts.
    }
}
