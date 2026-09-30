//! Fixed operator configuration for the real public-document browser backend.

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tokio::sync::watch;

use super::{Options, parse_key, private_directory, rpc, task};
use crate::compute::ModelProfile;

#[derive(Clone, Debug, Args)]
pub(in crate::compute) struct Config {
    #[arg(long)]
    pub runtime_root: PathBuf,
    #[arg(long)]
    pub model_root: PathBuf,
    #[arg(long, default_value_t = ModelProfile::default())]
    pub model_profile: ModelProfile,
    /// Existing encrypted publisher identity, never supplied by an IPC request.
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(long)]
    pub passphrase_file: PathBuf,
    #[arg(long, value_parser = parse_key)]
    pub publisher_key: VerifyingKey,
    /// Two to four independently selected compatible workers trusting this publisher.
    #[arg(long, required = true, value_parser = parse_key)]
    pub provider_key: Vec<VerifyingKey>,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    pub max_seconds: u16,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    pub threads: u16,
    #[command(flatten)]
    source_limits: crate::content::Limits,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (2..=4).contains(&self.provider_key.len())
                && self
                    .provider_key
                    .iter()
                    .map(VerifyingKey::to_bytes)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.provider_key.len()
                && (1..=600).contains(&self.max_seconds)
                && (1..=2).contains(&self.threads),
            "compute_public_fixed_configuration"
        );
        private_directory(&self.runtime_root)?;
        private_directory(&self.model_root)?;
        ensure!(
            self.runtime_root.join("bin/python3").is_file()
                && self.model_root.join("model.safetensors").is_file(),
            "compute_public_runtime_missing"
        );
        for path in [&self.identity, &self.passphrase_file] {
            ensure!(
                path.is_absolute() && fs::canonicalize(path)? == *path,
                "compute_public_signer_path"
            );
        }
        let signer =
            crate::content::unlock_signer(Some(&self.identity), Some(&self.passphrase_file))?;
        ensure!(
            signer.verifying_key() == self.publisher_key,
            "compute_document_publisher_identity"
        );
        Ok(())
    }

    fn options(&self, root: &Path, question: String, license: String) -> Options {
        Options {
            directory: root.join("document"),
            resume: false,
            batch_barrier: false,
            synthesize: true,
            task_plan: None,
            plan_tasks: false,
            plan_task_graph: false,
            grounded_synthesis: false,
            plan_structure: None,
            input: Some(root.join("input.txt")),
            source_plan: None,
            source_cache: None,
            reuse_source_cache: false,
            source_limits: self.source_limits.clone(),
            public_content: true,
            public_question: Some(question),
            license: Some(license),
            runtime_root: Some(self.runtime_root.clone()),
            model_root: Some(self.model_root.clone()),
            model_profile: self.model_profile,
            identity: Some(self.identity.clone()),
            passphrase_file: Some(self.passphrase_file.clone()),
            publisher_key: Some(self.publisher_key),
            provider_key: self.provider_key.clone(),
            discovery: super::discovery::Options::default(),
            lifetime_seconds: 86_400,
            max_batches: 32,
            follow: super::super::follow::Options::default(),
            max_seconds: self.max_seconds,
            threads: self.threads,
            execute: true,
            enroll_only: false,
        }
    }
}

pub(in crate::compute) struct Execution {
    pub result: Result<Value>,
    pub cleanup_confirmed: bool,
}

pub(in crate::compute) async fn execute(
    config: &Config,
    root: &Path,
    socket: &Path,
    question: String,
    context: String,
    license: String,
    cancelled: &watch::Receiver<bool>,
) -> Execution {
    let options = config.options(root, question, license);
    let result = async {
        private_directory(root)?;
        ensure!(
            !*cancelled.borrow(),
            "compute_document_cancelled_before_planning"
        );
        task::write_bytes(&root.join("input.txt"), context.as_bytes(), false)?;
        super::report_with_activity(&options, socket, cancelled).await
    }
    .await;
    // Failed/ambiguous execution must never free the admission slot just because the
    // coordinator future returned. Recheck every original handle, not only latest rows.
    let remote_cleanup = terminal_receipts(root).unwrap_or(false);
    let local_cleanup = result.is_ok()
        || result.as_ref().is_err_and(|error| {
            matches!(
                error.to_string().as_str(),
                "compute_document_cancelled_before_planning"
                    | "compute_document_cancelled_before_publication"
                    | "compute_document_cancelled"
                    | "compute_owner_busy"
            ) || error
                .downcast_ref::<crate::compute::supervise::WorkerFailure>()
                .is_some()
        });
    let cleanup_confirmed = local_cleanup && remote_cleanup;
    let result = result.and_then(|report| compact(&report, config, cleanup_confirmed));
    Execution {
        result,
        cleanup_confirmed,
    }
}

fn compact(report: &Value, config: &Config, cleanup: bool) -> Result<Value> {
    ensure!(
        report["operation"] == "compute_public_document"
            && report["complete"].is_boolean()
            && report["execution_complete"].is_boolean(),
        "compute_public_report_shape"
    );
    let mut providers = BTreeSet::new();
    let mut collect = |answers: &Value| -> Result<()> {
        if let Some(answers) = answers.as_array() {
            for answer in answers {
                let key = answer["provider_key"]
                    .as_str()
                    .context("compute_public_answer_provider")?;
                parse_key(key).map_err(anyhow::Error::msg)?;
                providers.insert(key.to_owned());
            }
        }
        Ok(())
    };
    collect(&report["answers"])?;
    if let Some(levels) = report["synthesis"]["levels"].as_array() {
        for level in levels {
            collect(&level["answers"])?;
        }
    }
    let text = report["synthesized_answer"]["text"].as_str().unwrap_or("");
    ensure!(
        text.len() <= config.model_profile.spec().max_output_bytes,
        "compute_public_answer_bound"
    );
    let complete = report["complete"] == true;
    ensure!(
        !complete || (!text.trim().is_empty() && report["answer_complete"] == true),
        "compute_public_complete_answer"
    );
    Ok(
        json!({"answer_complete":complete,"answer_status":if complete {"complete"} else {"incomplete"},
        "output":{"text":text},"provider_keys":providers,
        "selected_provider_keys":config.provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "joining":report["joining"],"execution_complete":report["execution_complete"],
        "package_count":report["packages"].as_array().context("compute_public_packages")?.len(),
        "total_parts":report["total_parts"],
        "synthesis_levels":report["synthesis"]["levels"].as_array().map_or(0, Vec::len),
        "source_manifest_id":report["source_manifest_id"],
        "remote_cleanup_confirmed":cleanup,"cleanup":{"complete":cleanup},
        "retained_public_receipts":true,"model_answer_correctness_proven":false,
        "semantic_completeness_proven":false}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    handle: super::super::JobHandle,
    status: rpc::JobStatus,
    verified_at_unix_seconds: u64,
}

/// Recheck coordinator-retained, exact authenticated RPC observations. This does not
/// upgrade them into independently portable execution attestations or remote erasure.
fn terminal_receipts(root: &Path) -> Result<bool> {
    let mut directories = vec![(root.to_path_buf(), 0)];
    let mut paths = Vec::new();
    let mut entries = 0;
    while let Some((directory, depth)) = directories.pop() {
        private_directory(&directory)?;
        ensure!(depth <= 20, "compute_public_retained_depth");
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries += 1;
            ensure!(entries <= 16_384, "compute_public_retained_entries");
            let kind = entry.file_type()?;
            ensure!(
                kind.is_dir() || kind.is_file(),
                "compute_public_retained_type"
            );
            if kind.is_dir() {
                directories.push((entry.path(), depth + 1));
            } else {
                paths.push(entry.path());
            }
        }
    }
    let mut handles = BTreeMap::new();
    for path in &paths {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("job-0.json" | "job-1.json" | "job-2.json" | "job-3.json")
        ) {
            let handle: super::super::JobHandle =
                serde_json::from_slice(&super::read_file(path, 65_536)?)?;
            ensure!(
                handles
                    .insert(handle.binding.job_id.clone(), handle)
                    .is_none(),
                "compute_public_duplicate_handle"
            );
        }
    }
    let mut terminal = BTreeSet::new();
    for path in &paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("receipt-") || !name.ends_with(".json") {
            continue;
        }
        let receipt: Receipt =
            serde_json::from_slice(&super::read_file(path, rpc::MAX_RESPONSE_BYTES + 32768)?)?;
        let id = &receipt.handle.binding.job_id;
        let handle = handles
            .get(id)
            .context("compute_public_receipt_without_handle")?;
        ensure!(
            receipt.version == 1
                && name == format!("receipt-{id}.json")
                && receipt.verified_at_unix_seconds <= super::now()?
                && serde_json::to_vec(handle)? == serde_json::to_vec(&receipt.handle)?,
            "compute_public_retained_receipt_binding"
        );
        let status = super::super::job(rpc::Outcome::Job(receipt.status), handle)?;
        if matches!(
            status.state,
            rpc::JobState::Complete | rpc::JobState::Failed | rpc::JobState::Cancelled
        ) {
            terminal.insert(id.clone());
        }
    }
    Ok(handles.keys().all(|id| terminal.contains(id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn absent_jobs_are_quiescent_but_unknown_retained_objects_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(terminal_receipts(root.path()).unwrap());
        std::os::unix::fs::symlink("/unused", root.path().join("untrusted")).unwrap();
        assert!(terminal_receipts(root.path()).is_err());
    }
}
