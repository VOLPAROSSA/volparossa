//! Local successor selection on the current source's own held-out rows only.
//! These owner-local receipts do not establish independent benchmark quality or
//! portable peer attestation. Technical checkpoint completion remains separate.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use volparossa_content::{
    SignedManifest,
    agent_artifact::{AdapterBundle, BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION},
    provider::compute::dataset::verify_source,
};

use super::{Store, content, now, private_directory, read_file, storage::FileSnapshot};

const POLICY: &str = "source-heldout-loss-v1";
const SCOPE: &str =
    "current-source-heldout-only-not-independent-benchmark-or-general-answer-quality";
const EPSILON: f64 = 1e-6;
const FILES: [(&str, u64); 11] = [
    ("selection.json", 64 * 1024),
    ("dataset.json", 1024 * 1024),
    ("dataset.manifest", 64 * 1024),
    ("source-provenance.json", 64 * 1024),
    ("training-report.json", 32 * 1024),
    ("result.json", 64 * 1024),
    ("adapter.bundle", 4 * 1024 * 1024),
    ("training/report.json", 16 * 1024),
    ("training/adapter/README.md", 16 * 1024),
    ("training/adapter/adapter_config.json", 16 * 1024),
    (
        "training/adapter/adapter_model.safetensors",
        2 * 1024 * 1024,
    ),
];
const ADAPTER_FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];
type Identities = BTreeMap<String, FileSnapshot>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    policy: String,
    scope: String,
    epsilon: f64,
    pub(super) sequence: u64,
    pub(super) predecessor: Option<u64>,
    baseline_kind: BaselineKind,
    pub(super) approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validation: Option<super::validation::Record>,
    source_manifest_id: String,
    source_publisher_key: String,
    source_revision: String,
    files: Identities,
    model_id: String,
    model_revision: String,
    base_model: FileSnapshot,
    base_parameters: Parameters,
    input_adapter: Option<InputAdapter>,
    candidate_adapter: Identities,
    candidate_parameters: Parameters,
    baseline: Metric,
    adapted: Metric,
    reloaded: Metric,
}

impl Record {
    pub(super) fn has_validation(&self) -> bool {
        self.validation.is_some()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BaselineKind {
    PinnedBase,
    ConfiguredAdapter,
    ApprovedPredecessor,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    sha256: String,
    parameters: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InputAdapter {
    files: Identities,
    applied_parameters: Parameters,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Metric {
    loss: f64,
    target_tokens: u64,
}

/// Assess a completed cycle before writing its immutable evaluation checkpoint.
/// The caller must persist the result before promoting or sharing the candidate.
pub(super) fn assess(
    store: &Store,
    sequence: u64,
    predecessor: Option<u64>,
    expected_adapter: Option<&Path>,
) -> Result<Record> {
    let record = recompute(store, sequence, predecessor)?;
    let selection = store.read_cycle_json(sequence, "selection.json")?;
    ensure!(
        selection.get("adapter_root") == Some(&serde_json::to_value(expected_adapter)?),
        "train_evaluation_selected_adapter"
    );
    match (expected_adapter, &record.input_adapter) {
        (Some(path), Some(input)) => {
            private_directory(path)?;
            let mut actual = Identities::new();
            for (name, limit) in ADAPTER_FILES {
                actual.insert(name.into(), identity(&read_file(&path.join(name), limit)?));
            }
            ensure!(
                actual == input.files,
                "train_evaluation_input_files_changed"
            );
        }
        (None, None) => {}
        _ => anyhow::bail!("train_evaluation_input_adapter_missing"),
    }
    Ok(record)
}

/// Recheck historical evidence without needing a retained predecessor directory.
/// New execution/source admission still uses the caller's current wall clock.
pub(super) fn verify(store: &Store, sequence: u64) -> Result<Record> {
    let saved: Record =
        serde_json::from_value(store.read_cycle_json(sequence, "evaluation.json")?)?;
    let actual = recompute(store, sequence, saved.predecessor)?;
    ensure!(saved == actual, "train_evaluation_checkpoint_changed");
    Ok(actual)
}

struct Evidence {
    bytes: BTreeMap<String, Vec<u8>>,
    files: Identities,
}

impl Evidence {
    fn load(store: &Store, sequence: u64) -> Result<Self> {
        let root = store.cycle_path(sequence)?;
        let mut bytes = BTreeMap::new();
        let mut files = Identities::new();
        for (name, limit) in FILES {
            let path = root.join(name);
            private_directory(path.parent().context("train_evaluation_parent")?)?;
            let raw = read_file(&path, limit)?;
            ensure!(!raw.is_empty(), "train_evaluation_empty_file");
            files.insert(name.into(), identity(&raw));
            bytes.insert(name.into(), raw);
        }
        Ok(Self { bytes, files })
    }
    fn json(&self, name: &str) -> Result<Value> {
        Ok(serde_json::from_slice(&self.bytes[name])?)
    }
}

fn recompute(store: &Store, sequence: u64, predecessor: Option<u64>) -> Result<Record> {
    ensure!(
        sequence > 0 && predecessor.is_none_or(|p| p > 0 && p < sequence),
        "train_evaluation_lineage"
    );
    let evidence = Evidence::load(store, sequence)?;
    let report = evidence.json("training-report.json")?;
    let result = evidence.json("result.json")?;
    let selection = evidence.json("selection.json")?;
    let (source_manifest_id, source_publisher_key, source_revision) =
        source_binding(&evidence, &report, &result, &selection)?;
    let (base_parameters, candidate_parameters) = technical_binding(&evidence, &report, &result)?;
    let input_adapter = input_binding(&report, &result, &selection)?;
    if let Some(previous) = predecessor {
        ensure!(
            input_adapter.is_some()
                && selection["adapter_root"]
                    == serde_json::to_value(store.cycle_path(previous)?.join("training/adapter"))?,
            "train_evaluation_predecessor_path"
        );
    }
    let baseline = metric(&report["baseline_evaluation"])?;
    let adapted = metric(&report["adapted_evaluation"])?;
    let reloaded = metric(&report["reloaded_evaluation"])?;
    let local_improvement = improvement(baseline, adapted, reloaded)?;
    let validation = if store
        .cycle_path(sequence)?
        .join("validation.json")
        .try_exists()?
    {
        Some(super::validation::verify(store, sequence)?)
    } else {
        None
    };
    let approved = local_improvement && validation.as_ref().is_none_or(|record| record.approved);
    let candidate_adapter = ADAPTER_FILES
        .into_iter()
        .map(|(name, _)| {
            (
                name.to_owned(),
                evidence.files[&format!("training/adapter/{name}")].clone(),
            )
        })
        .collect();
    Ok(Record {
        version: 1,
        policy: if validation.is_some() {
            "source-and-second-source-loss-v1"
        } else {
            POLICY
        }
        .into(),
        scope: if validation.is_some() {
            "source-and-pinned-second-source-selection-only-not-independent-test-benchmark"
        } else {
            SCOPE
        }
        .into(),
        epsilon: EPSILON,
        sequence,
        predecessor,
        baseline_kind: if predecessor.is_some() {
            BaselineKind::ApprovedPredecessor
        } else if input_adapter.is_some() {
            BaselineKind::ConfiguredAdapter
        } else {
            BaselineKind::PinnedBase
        },
        approved,
        validation,
        source_manifest_id,
        source_publisher_key,
        source_revision,
        files: evidence.files,
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_model: serde_json::from_value(report["model"]["files"]["model.safetensors"].clone())?,
        base_parameters,
        input_adapter,
        candidate_adapter,
        candidate_parameters,
        baseline,
        adapted,
        reloaded,
    })
}

fn source_binding(
    e: &Evidence,
    report: &Value,
    result: &Value,
    selection: &Value,
) -> Result<(String, String, String)> {
    let source = e.json("source-provenance.json")?;
    let publisher = source["publisher_key"]
        .as_str()
        .context("train_evaluation_publisher")?;
    let key = content::parse_publisher_key(publisher).map_err(anyhow::Error::msg)?;
    let at = source["verified_at_unix_seconds"]
        .as_u64()
        .filter(|at| *at > 0)
        .context("train_evaluation_source_time")?;
    ensure!(at <= now()?, "train_evaluation_future_source_time");
    let verified = verify_source(
        &e.bytes["dataset.manifest"],
        &key,
        std::str::from_utf8(&e.bytes["dataset.json"])?,
        at,
    )?;
    let manifest = SignedManifest::decode(&e.bytes["dataset.manifest"])?.verify(&key, at)?;
    let id = hex::encode(verified.manifest_id());
    let dataset = e.json("dataset.json")?;
    ensure!(
        !verified.is_document()
            && dataset["train"].as_array().is_some_and(|v| !v.is_empty())
            && dataset["heldout"].as_array().is_some_and(|v| !v.is_empty())
            && selection["publisher_key"] == publisher
            && selection["dataset_name"] == manifest.metadata().name
            && source["dataset_name"] == manifest.metadata().name
            && source["dataset_manifest_id"] == id
            && result["dataset_manifest_id"] == id
            && source["dataset_sha256"] == e.files["dataset.json"].sha256
            && source["signed_manifest_sha256"] == e.files["dataset.manifest"].sha256
            && source["dataset_bytes"] == e.files["dataset.json"].bytes
            && result["dataset_sha256"] == e.files["dataset.json"].sha256
            && report["dataset"]["sha256"] == e.files["dataset.json"].sha256
            && report["dataset"]["bytes"] == e.files["dataset.json"].bytes
            && report["dataset"]["source_revision"] == dataset["source_revision"]
            && source["expires_unix_seconds"] == verified.expires()
            && result["source_expires_unix_seconds"] == verified.expires(),
        "train_evaluation_source_binding"
    );
    Ok((
        id,
        publisher.to_owned(),
        dataset["source_revision"]
            .as_str()
            .context("train_evaluation_source_revision")?
            .into(),
    ))
}

fn technical_binding(
    e: &Evidence,
    report: &Value,
    result: &Value,
) -> Result<(Parameters, Parameters)> {
    let mut original = report.clone();
    original
        .as_object_mut()
        .context("train_evaluation_report")?
        .remove("supervisor");
    ensure!(
        original == e.json("training/report.json")?
            && report["version"] == 1
            && report["status"] == "ok"
            && report["mode"] == "train"
            && report["model"]["id"] == MODEL_ID
            && report["model"]["revision"] == MODEL_REVISION
            && report["model"]["files"]["model.safetensors"]["sha256"]
                == hex::encode(BASE_MODEL_SHA256)
            && report["model"]["files"]["model.safetensors"]["bytes"] == 269_060_552_u64
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["base_weights_unchanged"] == true
            && report["adapter_weights_changed"] == true
            && report["checkpoint_reloaded"] == true
            && result["version"] == 1
            && result["operation"] == "compute_train_cycle"
            && result["complete"] == true
            && result["training_report_sha256"] == e.files["training-report.json"].sha256
            && result["updates_completed"] == report["updates_completed"]
            && report["updates_completed"]
                .as_u64()
                .is_some_and(|n| (1..=64).contains(&n))
            && result["bundle"]["sha256"] == e.files["adapter.bundle"].sha256
            && result["bundle"]["bytes"] == e.files["adapter.bundle"].bytes
            && result["bundle"]["dataset_manifest_id"] == result["dataset_manifest_id"],
        "train_evaluation_technical_binding"
    );
    let base = parameters(&report["base_before"], false)?;
    let before = parameters(&report["adapter_before"], true)?;
    let after = parameters(&report["adapter_after"], true)?;
    ensure!(
        base == parameters(&report["base_after"], false)?
            && base == parameters(&report["reloaded_base"], false)?
            && after == parameters(&report["reloaded_adapter"], true)?
            && before.sha256 != after.sha256,
        "train_evaluation_parameter_binding"
    );
    let bundle = AdapterBundle::decode(e.bytes["adapter.bundle"].clone())?;
    ensure!(
        hex::encode(bundle.dataset_manifest_id()) == result["dataset_manifest_id"]
            && bundle.config() == e.bytes["training/adapter/adapter_config.json"]
            && bundle.weights() == e.bytes["training/adapter/adapter_model.safetensors"]
            && bundle.readme() == e.bytes["training/adapter/README.md"],
        "train_evaluation_bundle_binding"
    );
    let artifacts = report["artifacts"]
        .as_array()
        .filter(|a| a.len() == 3)
        .context("train_evaluation_artifacts")?;
    let mut observed = Identities::new();
    for artifact in artifacts {
        let path = artifact["relative_path"]
            .as_str()
            .context("train_evaluation_artifact_name")?;
        ensure!(
            ADAPTER_FILES
                .iter()
                .any(|(name, _)| path == format!("adapter/{name}")),
            "train_evaluation_artifact_name"
        );
        let actual = &e.files[&format!("training/{path}")];
        ensure!(
            artifact["sha256"] == actual.sha256
                && artifact["bytes"] == actual.bytes
                && observed.insert(path.into(), actual.clone()).is_none(),
            "train_evaluation_artifact_hash"
        );
    }
    Ok((base, after))
}

fn input_binding(
    report: &Value,
    result: &Value,
    selection: &Value,
) -> Result<Option<InputAdapter>> {
    let Some(input) = report.get("input_adapter") else {
        ensure!(
            selection.get("adapter_root").is_some_and(Value::is_null)
                && result["input_adapter_applied"] == false
                && result["input_adapter"].is_null(),
            "train_evaluation_unapplied_adapter"
        );
        return Ok(None);
    };
    ensure!(
        input["applied"] == true
            && input["model_id"] == MODEL_ID
            && input["model_revision"] == MODEL_REVISION
            && result["input_adapter_applied"] == true
            && result["input_adapter"] == *input
            && selection["adapter_root"]
                .as_str()
                .is_some_and(|p| Path::new(p).is_absolute())
            && input["base_parameters_before_apply"] == report["base_before"]
            && input["base_parameters_after_apply"] == report["base_before"],
        "train_evaluation_input_binding"
    );
    let files: Identities = serde_json::from_value(input["files"].clone())?;
    ensure!(
        files.len() == 3
            && ADAPTER_FILES.iter().all(|(name, limit)| files
                .get(*name)
                .is_some_and(|f| f.bytes > 0
                    && f.bytes <= *limit
                    && super::super::is_hex(&f.sha256, 64))),
        "train_evaluation_input_file_identity"
    );
    let applied = parameters(&input["applied_parameters"], true)?;
    ensure!(
        applied == parameters(&report["adapter_before"], true)?,
        "train_evaluation_warmstart_parameters"
    );
    Ok(Some(InputAdapter {
        files,
        applied_parameters: applied,
    }))
}

fn parameters(value: &Value, adapter: bool) -> Result<Parameters> {
    let p: Parameters = serde_json::from_value(value.clone())?;
    ensure!(
        super::super::is_hex(&p.sha256, 64)
            && p.parameters > 0
            && (!adapter || p.parameters == 230_400),
        "train_evaluation_parameter_identity"
    );
    Ok(p)
}

fn metric(value: &Value) -> Result<Metric> {
    let result: Metric = serde_json::from_value(value.clone())?;
    ensure!(
        result.loss.is_finite() && result.loss >= 0.0 && result.target_tokens > 0,
        "train_evaluation_invalid_metric"
    );
    Ok(result)
}

fn improvement(baseline: Metric, adapted: Metric, reloaded: Metric) -> Result<bool> {
    for value in [baseline, adapted, reloaded] {
        ensure!(
            value.loss.is_finite() && value.loss >= 0.0 && value.target_tokens > 0,
            "train_evaluation_invalid_metric"
        );
    }
    ensure!(
        baseline.target_tokens == adapted.target_tokens
            && adapted.target_tokens == reloaded.target_tokens,
        "train_evaluation_heldout_tokens_changed"
    );
    ensure!(
        (adapted.loss - reloaded.loss).abs()
            <= EPSILON.max(1e-5 * adapted.loss.abs().max(reloaded.loss.abs())),
        "train_evaluation_reload_loss_changed"
    );
    Ok(reloaded.loss < baseline.loss - EPSILON)
}

fn identity(bytes: &[u8]) -> FileSnapshot {
    FileSnapshot {
        sha256: hex::encode(Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(super) use tests::{fixture, fixture_input};
