//! Explicit local-only private Q/A. This module has no peer or publication client.

use std::{
    fmt, fs,
    io::{Read, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use super::{Mode, ModelProfile, inference_output::Generation};

const MAX_INPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Owned regular mode-0600 JSON containing only version, visibility, question and context.
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    runtime_root: PathBuf,
    #[arg(long)]
    model_root: PathBuf,
    /// Existing owned mode-0700 parent for an ephemeral private execution directory.
    #[arg(long)]
    work_parent: PathBuf,
    #[arg(long, default_value_t = ModelProfile::Smol360)]
    model_profile: ModelProfile,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Execute locally; otherwise print only a fixed, input-free scope preview.
    #[arg(long)]
    execute: bool,
}

/// Owner-selected execution configuration. Incoming requests cannot select paths,
/// executables, model assets or resource limits.
#[derive(Clone, Debug)]
pub(super) struct ExecutionConfig {
    pub runtime_root: PathBuf,
    pub model_root: PathBuf,
    pub work_parent: PathBuf,
    pub model_profile: ModelProfile,
    pub native_backend: super::native_cpu::Options,
    pub threads: u16,
    pub max_seconds: u16,
}

impl From<&Options> for ExecutionConfig {
    fn from(args: &Options) -> Self {
        Self {
            runtime_root: args.runtime_root.clone(),
            model_root: args.model_root.clone(),
            work_parent: args.work_parent.clone(),
            model_profile: args.model_profile,
            native_backend: super::native_cpu::Options::default(),
            threads: args.threads,
            max_seconds: args.max_seconds,
        }
    }
}

impl ExecutionConfig {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=2).contains(&self.threads) && (1..=600).contains(&self.max_seconds),
            "compute_private_budget"
        );
        super::private_directory(&self.runtime_root)?;
        super::private_directory(&self.model_root)?;
        super::private_directory(&self.work_parent)?;
        self.native_backend.validate(self.model_profile)?;
        if let Some(root) = &self.native_backend.native_backend_root {
            ensure!(
                !self.work_parent.starts_with(root) && !root.starts_with(&self.work_parent),
                "compute_native_backend_work_overlap"
            );
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    visibility: String,
    question: String,
    context: String,
}

pub(super) fn validate_input(raw: &[u8]) -> Result<()> {
    ensure!(
        !raw.is_empty() && raw.len() as u64 <= MAX_INPUT_BYTES,
        "compute_private_input_bound"
    );
    // Discard parser diagnostics: an unknown JSON field could contain private text.
    let input: Input =
        serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("compute_private_input_schema"))?;
    ensure!(
        input.version == 1 && input.visibility == "private_local",
        "compute_private_input_scope"
    );
    for (text, maximum) in [(&input.question, 512), (&input.context, 4096)] {
        ensure!(
            !text.trim().is_empty() && text.len() <= maximum && !text.contains('\0'),
            "compute_private_input_text"
        );
    }
    Ok(())
}

pub(super) fn validate_mode_input(mode: Mode, raw: &[u8]) -> Result<()> {
    validate_profile_input(mode, raw, ModelProfile::Smol360)
}

pub(super) fn validate_profile_input(mode: Mode, raw: &[u8], profile: ModelProfile) -> Result<()> {
    ensure!(
        !profile.is_native_conversation() || mode == Mode::PrivateConversation,
        "compute_profile_conversation_only"
    );
    match mode {
        Mode::PrivateInfer => validate_input(raw),
        Mode::PrivateConversation => {
            super::private_conversation::Input::decode_profile(raw, profile).map(|_| ())
        }
        _ => anyhow::bail!("compute_private_mode"),
    }
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "compute_private_input_path"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.mode() & 0o777 == 0o600
            && info.len() <= MAX_INPUT_BYTES,
        "compute_private_input_file"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut raw)?;
    validate_input(&raw)?;
    Ok(raw)
}

/// No process-cleanup claim can be made if the exact sandbox child cannot be reaped.
#[derive(Debug)]
pub(super) struct CleanupUnconfirmed;

impl fmt::Display for CleanupUnconfirmed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("compute_private_cleanup_unconfirmed")
    }
}
impl std::error::Error for CleanupUnconfirmed {}

struct Staged {
    directory: tempfile::TempDir,
    options: super::Options,
}

impl Staged {
    #[cfg(test)]
    fn new(args: &Options, input: &[u8]) -> Result<Self> {
        Self::from_config(&ExecutionConfig::from(args), input)
    }

    #[cfg(test)]
    fn from_config(args: &ExecutionConfig, input: &[u8]) -> Result<Self> {
        Self::from_mode(args, input, Mode::PrivateInfer)
    }

    fn from_mode(args: &ExecutionConfig, input: &[u8], mode: Mode) -> Result<Self> {
        args.native_backend
            .validate_input(mode, input, args.model_profile)?;
        super::private_directory(&args.work_parent)?;
        let directory = tempfile::Builder::new()
            .prefix("private-task-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&args.work_parent)?;
        let dataset = directory.path().join("input.json");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&dataset)?;
        file.write_all(input)?;
        file.sync_all()?;
        let options = super::Options {
            mode,
            runtime_root: args.runtime_root.clone(),
            model_root: args.model_root.clone(),
            model_profile: args.model_profile,
            native_backend: args.native_backend.clone(),
            adapter_root: None,
            dataset,
            output: directory.path().join("output"),
            steps: 1,
            threads: args.threads,
            max_seconds: args.max_seconds,
            spare_capacity: true,
            execute: true,
        };
        Ok(Self { directory, options })
    }

    fn finish(self, result: Result<Value>) -> Result<Value> {
        if result
            .as_ref()
            .is_err_and(|error| error.downcast_ref::<CleanupUnconfirmed>().is_some())
        {
            // Keep only this exact owned tree. Never remove inputs still possibly
            // mounted by a live worker and never emit an answer or a false cleanup flag.
            let _ = self.directory.keep();
            return Err(CleanupUnconfirmed.into());
        }
        self.directory
            .close()
            .map_err(|_| anyhow::anyhow!("compute_private_storage_cleanup_failed"))?;
        result
    }
}

fn preview(args: &Options) -> Value {
    json!({"version":1,"operation":"compute_private_task_plan","execute":false,
        "model_profile":args.model_profile,"threads":args.threads,"max_seconds":args.max_seconds,
        "input_contents_disclosed":false,"private_data_supported":true,"local_only":true,
        "distributed_execution_claimed":false,"private_training_claimed":false,
        "publication":false,"cache":false,"network":"isolated-loopback-only",
        "temporary_input_and_report_removed_after_reaping":true})
}

/// Exact local input/model binding after ordinary sandbox cleanup, never a public receipt.
#[cfg(test)]
pub(super) fn validate_report(report: &Value, raw: &[u8], profile: ModelProfile) -> Result<()> {
    validate_mode_report(report, raw, profile, Mode::PrivateInfer)
}

pub(super) fn validate_mode_report(
    report: &Value,
    raw: &[u8],
    profile: ModelProfile,
    mode: Mode,
) -> Result<()> {
    validate_profile_input(mode, raw, profile)?;
    let spec = profile.spec();
    ensure!(
        report["mode"] == serde_json::to_value(mode)?
            && report["status"] == "ok"
            && report["updates_completed"] == 0
            && report["private_data_supported"] == true
            && report["distributed_execution_claimed"] == false
            && report["private_training_claimed"] == false
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["model_weights_loaded"] == true
            && report.get("baseline_evaluation").is_none()
            && report.get("input_adapter").is_none()
            && report["artifacts"] == json!([]),
        "compute_private_result_scope"
    );
    ensure!(
        report["dataset"]
            == json!({"sha256":hex::encode(Sha256::digest(raw)),"bytes":raw.len(),
        "visibility":"private_local"}),
        "compute_private_result_input"
    );
    ensure!(
        report["model"]["id"] == spec.model_id && report["model"]["revision"] == spec.revision,
        "compute_private_result_model"
    );
    validate_model_weights(&report["model"], profile)?;
    let outputs = report["outputs"]
        .as_array()
        .context("compute_private_result_outputs")?;
    ensure!(
        outputs.len() == 1
            && outputs[0]["sample_index"] == 0
            && outputs[0]["text"]
                .as_str()
                .is_some_and(|text| text.len() <= spec.max_output_bytes)
            && outputs[0]["text_truncated"].is_boolean()
            && Generation::from_output(&outputs[0], true)?
                .is_some_and(|generation| generation.model_profile == profile),
        "compute_private_result_output"
    );
    if mode == Mode::PrivateConversation {
        super::private_conversation::validate_report(report, raw, profile)?;
    }
    Ok(())
}

pub(super) fn validate_model_weights(model: &Value, profile: ModelProfile) -> Result<()> {
    let spec = profile.spec();
    if let Some(files) = profile.sharded_weight_files() {
        ensure!(
            model["files"].get("model.safetensors").is_none()
                && files.iter().all(|file| model["files"][file.name]
                    == json!({"bytes":file.bytes,"sha256":file.sha256}))
                && model["weights"]
                    == json!({
                        "layout":"safetensors_shards_concat_v1",
                        "bytes":spec.weights_bytes,"sha256":spec.weights_sha256,
                        "files":files[1..].iter().map(|file| file.name).collect::<Vec<_>>()
                    }),
            "compute_private_result_model_weights"
        );
    } else {
        ensure!(
            model["files"]["model.safetensors"]
                == json!({"bytes":spec.weights_bytes,"sha256":spec.weights_sha256}),
            "compute_private_result_model"
        );
    }
    Ok(())
}

fn summary(report: &Value, profile: ModelProfile) -> Result<Value> {
    let output = &report["outputs"][0];
    let generation =
        Generation::from_output(output, true)?.context("compute_private_generation")?;
    let status = if output["text_truncated"] == true {
        "wire_truncated"
    } else if !generation.is_eos() {
        "token_limit"
    } else if output["text"]
        .as_str()
        .is_none_or(|text| text.trim().is_empty())
    {
        "empty"
    } else {
        "eos"
    };
    Ok(
        json!({"version":1,"operation":"compute_private_task","model_profile":profile,
        "execution_complete":true,"answer_complete":status=="eos","complete":status=="eos",
        "answer_status":status,"output":output,"local_only":true,"private_data_supported":true,
        "distributed_execution_claimed":false,"private_training_claimed":false,"semantic_completeness_proven":false,
        "model_answer_correctness_proven":false,"cleanup":{"complete":true,"retained_input":false,"retained_report":false}}),
    )
}

pub(super) async fn run(args: &Options) -> Result<()> {
    let result = run_inner(args).await;
    // The CLI never renders a path-bearing I/O error, JSON fragment or unrecognized
    // backend message that could expose private input in its diagnostic stream.
    result.map_err(|error| {
        if error.downcast_ref::<CleanupUnconfirmed>().is_some() {
            anyhow::anyhow!("compute_private_cleanup_unconfirmed")
        } else if error.to_string() == "compute_private_answer_incomplete" {
            anyhow::anyhow!("compute_private_answer_incomplete")
        } else {
            anyhow::anyhow!("compute_private_task_failed")
        }
    })
}

async fn run_inner(args: &Options) -> Result<()> {
    let config = ExecutionConfig::from(args);
    config.validate()?;
    let input = read_input(&args.input)?;
    if !args.execute {
        println!("{}", preview(args));
        return Ok(());
    }
    let (owner, activity) = watch::channel(true);
    let interrupt = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = owner.send(false);
    });
    let result = execute_bytes(&config, input, activity).await;
    interrupt.abort();
    let result = result?;
    // Only the owner-requested answer is printed, after confirmed process and file cleanup.
    println!("{result}");
    ensure!(
        result["answer_complete"] == true,
        "compute_private_answer_incomplete"
    );
    Ok(())
}

/// The private service and the file-oriented CLI share the exact staging, sandbox,
/// report binding and cleanup path. No public broker or retained result is involved.
pub(super) async fn execute_bytes(
    config: &ExecutionConfig,
    input: Vec<u8>,
    activity: watch::Receiver<bool>,
) -> Result<Value> {
    execute_mode(config, input, activity, Mode::PrivateInfer).await
}

pub(super) async fn execute_mode(
    config: &ExecutionConfig,
    input: Vec<u8>,
    activity: watch::Receiver<bool>,
    mode: Mode,
) -> Result<Value> {
    validate_profile_input(mode, &input, config.model_profile)?;
    config.validate()?;
    ensure!(*activity.borrow(), "compute_owner_busy");
    let staged = Staged::from_mode(config, &input, mode)?;
    let result = async {
        staged.options.validate()?;
        let report = super::execute(&staged.options, activity).await?;
        validate_mode_report(&report, &input, config.model_profile, mode)?;
        if mode == Mode::PrivateConversation {
            Ok(super::private_conversation::summary(
                &report,
                config.model_profile,
            ))
        } else {
            summary(&report, config.model_profile)
        }
    }
    .await;
    staged.finish(result)
}

#[cfg(test)]
mod tests;
