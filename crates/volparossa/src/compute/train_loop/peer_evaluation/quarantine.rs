//! Local, exact-artifact runtime-contract evidence. Never a publisher or network ban.

use super::*;
use crate::compute::supervise::{WorkerFailure, adapter_violation};

const POLICY: &str = "local-peer-update-runtime-contract-v1";
const SCOPE: &str = "local-artifact-only-not-publisher-or-network-ban";
const FILE: &str = "quarantine.json";
const EVIDENCE_FILES: [(&str, u64); 11] = [
    ("comparison/selection.json", 512 * 1024),
    ("comparison/dataset.json", 1024 * 1024),
    ("comparison/dataset.manifest", 64 * 1024),
    ("comparison/provenance.json", 64 * 1024),
    ("comparison/baseline-report.json", 64 * 1024),
    ("comparison/baseline/report.json", 16 * 1024),
    ("import/adapter.bundle", 4 * 1024 * 1024),
    ("import/adapter.manifest", 64 * 1024),
    ("import/dataset.json", 1024 * 1024),
    ("import/dataset.manifest", 64 * 1024),
    ("import/provenance.json", 128 * 1024),
];

/// Closed on-disk vocabulary matching deterministic fixed-backend adapter checks.
/// Operational failures, finite quality regressions and unknown text cannot deserialize here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Code {
    InvalidAdapterWeights,
    InvalidAdapterHeader,
    InvalidAdapterMetadata,
    UnsupportedAdapterTensorKeys,
    UnsupportedAdapterTensorFormat,
    InvalidAdapterTensorOffsets,
    InvalidAdapterTensorLayout,
    NonfiniteAdapterWeights,
    UnsupportedAdapterConfig,
    InvalidAdapterReadme,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    policy: String,
    scope: String,
    stage: String,
    request_id: String,
    code: Code,
    started_at: u64,
    completed_at: u64,
    deadline: u64,
    source_expires: u64,
    pub(super) baseline_origin: Value,
    pub(super) import_proof: Value,
    candidate_files: Files,
    validation_manifest_id: String,
    files: Files,
}

fn fault(stage: &str, error: &anyhow::Error) -> Option<(String, Code)> {
    if stage != "candidate" {
        return None;
    }
    let code = adapter_violation(error)?;
    let failure = error.downcast_ref::<WorkerFailure>()?;
    let code: Code = serde_json::from_value(Value::String(code.to_owned())).ok()?;
    Some((failure.request_id().to_owned(), code))
}

fn files(root: &Path) -> Result<Files> {
    let candidate = root.parent().context("peer_quarantine_parent")?;
    EVIDENCE_FILES
        .into_iter()
        .map(|(name, maximum)| {
            Ok((
                name.to_owned(),
                identity(&read_file(&candidate.join(name), maximum)?),
            ))
        })
        .collect()
}

/// The caller has already awaited the unchanged supervisor cleanup path.
pub(super) fn record_failure(
    root: &Path,
    selection: &Value,
    stage: &str,
    started_at: u64,
    deadline: u64,
    error: &anyhow::Error,
) -> Result<bool> {
    let Some((request_id, code)) = fault(stage, error) else {
        return Ok(false);
    };
    let record = Record {
        version: 1,
        policy: POLICY.into(),
        scope: SCOPE.into(),
        stage: "candidate".into(),
        request_id,
        code,
        started_at,
        completed_at: now()?,
        deadline,
        source_expires: selection["expires"]
            .as_u64()
            .context("peer_quarantine_expiry")?,
        baseline_origin: selection["baseline_origin"].clone(),
        import_proof: selection["import_proof"].clone(),
        candidate_files: serde_json::from_value(selection["candidate_files"].clone())?,
        validation_manifest_id: selection["validation_source"]["manifest_id"]
            .as_str()
            .context("peer_quarantine_validation_identity")?
            .into(),
        files: files(root)?,
    };
    validate(root, selection, &record)?;
    write_json(&root.join(FILE), &record)?;
    Ok(true)
}

/// Rechecks retained local evidence without renewing any execution/source authority.
pub(super) fn verify(root: &Path) -> Result<Record> {
    private_directory(root)?;
    let record: Record = serde_json::from_slice(&read_file(&root.join(FILE), 256 * 1024)?)?;
    let selection = json_file(&root.join("selection.json"))?;
    validate(root, &selection, &record)?;
    Ok(record)
}

fn validate(root: &Path, selection: &Value, record: &Record) -> Result<()> {
    private_directory(root)?;
    let candidate = root
        .parent()
        .context("peer_quarantine_parent")?
        .join("import/adapter");
    ensure!(
        record.version == 1
            && record.policy == POLICY
            && record.scope == SCOPE
            && record.stage == "candidate"
            && super::super::super::is_hex(&record.request_id, 32)
            && selection["version"] == 1
            && selection["policy"] == super::POLICY
            && selection["scope"] == super::SCOPE
            && selection["candidate_adapter"] == serde_json::to_value(&candidate)?
            && !root.join("decision.json").try_exists()?
            && !root.join("candidate-report.json").try_exists()?
            && !root.join("candidate/report.json").try_exists()?,
        "peer_quarantine_local_candidate_only"
    );
    let baseline = checked_stage(root, selection, "baseline")?;
    let maximum = selection["max_seconds"]
        .as_u64()
        .filter(|n| (1..=600).contains(n))
        .context("peer_quarantine_worker_bound")?;
    let expires = selection["expires"]
        .as_u64()
        .context("peer_quarantine_expiry")?;
    ensure!(
        baseline.completed_at <= record.started_at
            && baseline.report["id"] != record.request_id
            && record.started_at > 0
            && record.started_at <= record.completed_at
            && record.completed_at <= record.deadline
            && record.completed_at <= now()?
            && record.completed_at < expires
            && record.source_expires == expires
            && record.deadline
                == record.started_at.saturating_add(
                    expires
                        .checked_sub(record.started_at)
                        .context("peer_quarantine_expired")?
                        .min(maximum)
                )
            && record.deadline <= expires
            && record.baseline_origin == selection["baseline_origin"]
            && record.import_proof == selection["import_proof"]
            && record.validation_manifest_id == selection["validation_source"]["manifest_id"]
            && serde_json::to_value(&record.candidate_files)? == selection["candidate_files"]
            && record.candidate_files == adapter_files(&candidate)?
            && record.files == files(root)?,
        "peer_quarantine_original_evidence_changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
