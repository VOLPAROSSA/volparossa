//! Explicit public-data model jobs, isolated from the network agent and its identity.

mod broker;
mod device_capacity;
mod document_plan;
mod inference_output;
mod owner_control;
mod peer;
mod policy_assessment;
mod private_task;
mod resources;
mod sandbox;
mod serving_snapshot;
mod spare_capacity;
mod supervise;
mod task_plan;
mod train_cycle;
mod train_loop;

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use volparossa_content::model_profile::ModelProfile;

const MAX_DATASET_BYTES: u64 = 1024 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_STREAM_BYTES: usize = 256 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Read current owner-capacity signals without loading a model or changing device settings.
    Capacity,
    /// Preview or explicitly run an isolated job on an already provisioned open model.
    Run(Box<Options>),
    /// Answer one private local question without publishing inputs or using peer executors.
    PrivateTask(Box<private_task::Options>),
    /// Fetch one explicitly selected signed public training source, train, and pack an adapter.
    TrainCycle(Box<train_cycle::Options>),
    /// Autonomously cycle through explicitly selected public sources using spare capacity.
    TrainLoop(Box<train_loop::Options>),
    /// Combine three explicitly trusted public adapters, then compare on pinned heldout data.
    AggregateAdapters(Box<train_loop::aggregate::Options>),
    /// Sign and share one approved aggregate without retraining or extending its source validity.
    PublishAggregate(Box<train_loop::aggregate_publication::Options>),
    /// Explicit same-UID public-inference service using the fixed isolated worker.
    Serve(Box<broker::Serve>),
    /// Attach a local broker or perform a bounded protected peer job exchange.
    Peer {
        #[command(subcommand)]
        command: Box<peer::Command>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    Infer,
    Train,
    #[serde(rename = "plan_document")]
    PlanDocument,
    #[serde(rename = "plan_tasks")]
    PlanTasks,
    #[value(skip)]
    #[serde(rename = "private_infer")]
    PrivateInfer,
    #[value(skip)]
    #[serde(rename = "aggregate_adapter")]
    AggregateAdapter,
}

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Only explicitly public project-data jobs are currently supported.
    #[arg(long, value_enum)]
    mode: Mode,
    /// Private venv created by the pinned, explicit guest provisioner.
    #[arg(long)]
    runtime_root: PathBuf,
    /// Private directory containing verified model assets, not executable remote code.
    #[arg(long)]
    model_root: PathBuf,
    /// Explicit pinned inference/planning profile; the default also supports training/adapters.
    #[arg(long, default_value_t = ModelProfile::default())]
    model_profile: ModelProfile,
    /// Explicit verified adapter directory; cache storage alone never activates an adapter.
    #[arg(long)]
    adapter_root: Option<PathBuf>,
    /// Explicit public Q/A dataset. This is never inferred from browsing or private files.
    #[arg(long)]
    dataset: PathBuf,
    /// New job directory under an existing private parent. Existing data is not overwritten.
    #[arg(long)]
    output: PathBuf,
    /// Genuine optimizer updates, not synthetic iterations.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=64))]
    steps: u16,
    /// CPU worker threads; no GPU is exposed to this initial backend.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    /// Total wall-clock deadline, including loading and cancellation cleanup.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Yield to observed CPU/IO, battery and thermal constraints; critical reserves cancel.
    #[arg(long)]
    spare_capacity: bool,
    /// Without this flag only the exact bounded job plan is printed.
    #[arg(long)]
    execute: bool,
}

#[derive(Serialize)]
struct WorkerRequest {
    version: u8,
    id: String,
    mode: Mode,
    #[serde(skip_serializing_if = "ModelProfile::is_default")]
    model_profile: ModelProfile,
    model_root: &'static str,
    dataset_path: &'static str,
    output_root: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter_root: Option<&'static str>,
    steps: u16,
    threads: u16,
    max_seconds: u16,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    owner_control: bool,
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    let options = match command {
        Command::Capacity => return spare_capacity::diagnostic(),
        Command::Run(options) => options,
        Command::PrivateTask(options) => return private_task::run(&options).await,
        Command::TrainCycle(options) => return train_cycle::run(&options, socket).await,
        Command::TrainLoop(options) => return train_loop::run(&options, socket).await,
        Command::AggregateAdapters(options) => {
            return train_loop::aggregate::run(&options, socket).await;
        }
        Command::PublishAggregate(options) => {
            return train_loop::aggregate_publication::run(&options, socket).await;
        }
        Command::Serve(options) => return broker::run(*options).await,
        Command::Peer { command } => return peer::run(*command, socket).await,
    };
    options.validate()?;
    if !options.execute {
        println!(
            "{}",
            serde_json::json!({
                "version": 1, "kind": "volparossa-compute-plan", "execute": false,
                "mode": options.mode, "runtime_root": options.runtime_root,
                "model_root": options.model_root, "model_profile": options.model_profile, "dataset": options.dataset,
                "adapter_root": options.adapter_root,
                "new_output": options.output, "steps": options.steps,
                "threads": options.threads, "max_seconds": options.max_seconds,
                "spare_capacity": options.spare_capacity,
                "network": "isolated-loopback-only", "device": "cpu",
                "private_data_supported": false, "distributed_execution": false,
                "limits": {
                    "address_space_bytes": resources::limits(options.model_profile).address_space,
                    "observed_rss_cancel_bytes": resources::limits(options.model_profile).observed_rss,
                    "output_cancel_bytes": supervise::MAX_OUTPUT_BYTES,
                    "file_size_bytes": sandbox::MAX_FILE_BYTES,
                    "tmpfs_bytes": sandbox::TMPFS_BYTES,
                    "cpu_priority": "idle", "io_priority": "idle"
                }
            })
        );
        return Ok(());
    }
    // A visible foreground command is owner authorization for this one bounded job.
    // The watch input is also used by the future background scheduler: owner activity
    // cancels, rather than pretending nice(19) guarantees no user-visible impact.
    let (owner_idle, activity) = watch::channel(true);
    let interrupt = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = owner_idle.send(false);
    });
    let result = execute(&options, activity).await;
    interrupt.abort();
    match result {
        Ok(report) => {
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn execute(options: &Options, activity: watch::Receiver<bool>) -> Result<Value> {
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let _lease = runtime_lease(&options.runtime_root)?;
    resources::admission(options.model_profile)?;
    if options.spare_capacity {
        let mut capacity = spare_capacity::Budget::new();
        ensure!(
            capacity.sample() != spare_capacity::Decision::Cancel,
            "{}",
            capacity.cancellation_code()
        );
    } else {
        supervise::headroom()?;
    }
    ensure!(*activity.borrow(), "compute_owner_busy");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&options.output)
        .context("compute_output_create")?;
    let mut nonce = [0_u8; 16];
    // This job ID only correlates the local isolated process; it is not a network identity.
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("compute_randomness"))?;
    let request = WorkerRequest {
        version: 1,
        id: hex::encode(nonce),
        mode: options.mode,
        model_profile: options.model_profile,
        model_root: "/model",
        dataset_path: "/dataset.json",
        output_root: "/output",
        adapter_root: options.adapter_root.as_ref().map(|_| "/adapter"),
        steps: options.steps,
        threads: options.threads,
        max_seconds: options.max_seconds,
        owner_control: options.spare_capacity,
    };
    let child = sandbox::command(options)
        .spawn()
        .context("compute_sandbox_spawn")?;
    // Failure does not publish partial adapters or delete diagnostic job artifacts.
    // A later job must use a new output directory, never silently overwrite them.
    supervise::run(child, &request, options, activity).await
}

impl Options {
    fn validate(&self) -> Result<()> {
        if self.mode == Mode::AggregateAdapter {
            ensure!(
                self.adapter_root.is_some() && self.steps == 1 && self.spare_capacity,
                "compute_aggregation_execution_scope"
            );
        }
        if self.mode == Mode::PrivateInfer {
            ensure!(
                self.adapter_root.is_none() && self.steps == 1 && self.spare_capacity,
                "compute_private_execution_scope"
            );
        }
        ensure!((1..=64).contains(&self.steps), "compute_steps");
        ensure!((1..=2).contains(&self.threads), "compute_threads");
        ensure!((1..=600).contains(&self.max_seconds), "compute_deadline");
        private_directory(&self.runtime_root)?;
        private_directory(&self.model_root)?;
        if let Some(adapter) = &self.adapter_root {
            private_directory(adapter)?;
        }
        ensure!(self.output.is_absolute(), "compute_output_absolute");
        private_directory(self.output.parent().context("compute_output_parent")?)?;
        ensure!(
            fs::symlink_metadata(&self.output)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "compute_output_exists"
        );
        ensure!(self.output.file_name().is_some(), "compute_output_name");
        let dataset = read_file(
            &self.dataset,
            if self.mode == Mode::PlanDocument {
                8 * MAX_DATASET_BYTES
            } else {
                MAX_DATASET_BYTES
            },
        )?;
        validate_profile_dataset(
            self.mode,
            self.adapter_root.is_some(),
            &dataset,
            self.model_profile,
        )?;
        for file in [
            "/usr/bin/bwrap",
            "/usr/bin/prlimit",
            "/usr/bin/nice",
            "/usr/bin/ionice",
        ] {
            ensure!(Path::new(file).is_file(), "compute_sandbox_prerequisite");
        }
        ensure!(
            self.runtime_root.join("bin/python3").is_file(),
            "compute_runtime_missing"
        );
        Ok(())
    }
}

// Shared by direct execution and Broker::start before a worker is created. Inference-only
// profiles must pass their strict validator here as well as at the signed RPC boundary.
fn validate_dataset(mode: Mode, has_adapter: bool, dataset: &[u8]) -> Result<()> {
    if mode == Mode::AggregateAdapter {
        ensure!(has_adapter, "compute_aggregation_cohort_required");
    }
    if mode == Mode::PrivateInfer {
        ensure!(!has_adapter, "compute_private_adapter_forbidden");
        return private_task::validate_input(dataset);
    }
    if mode == Mode::PlanTasks {
        ensure!(!has_adapter, "compute_task_plan_adapter");
        return task_plan::Input::decode(dataset)?.validate_execution();
    }
    let public: Value = serde_json::from_slice(dataset).context("compute_dataset_json")?;
    if mode == Mode::PlanDocument {
        ensure!(!has_adapter, "compute_document_plan_adapter");
        document_plan::validate_input(&public)?;
    } else if matches!(public["version"].as_u64(), Some(2..=5)) {
        ensure!(
            mode == Mode::Infer,
            "compute_document_training_not_supported"
        );
        let rows = public["inference"]
            .as_array()
            .context("compute_document_rows")?
            .len();
        let text = std::str::from_utf8(dataset)?;
        if public["version"] == 4 {
            volparossa_content::provider::compute::dataset::validate_principle_json(text, rows)?;
        } else if matches!(public["version"].as_u64(), Some(3 | 5)) {
            volparossa_content::provider::compute::dataset::validate_derived_json(text, rows)?;
        } else {
            volparossa_content::provider::compute::dataset::validate_document_json(text, rows)?;
        }
    } else {
        ensure!(
            public.get("version") == Some(&Value::from(1)),
            "compute_dataset_version"
        );
        ensure!(
            public.get("visibility").and_then(Value::as_str) == Some("public"),
            "compute_public_data_required"
        );
        ensure!(
            public.get("license").and_then(Value::as_str) == Some("GPL-3.0-only"),
            "compute_dataset_license"
        );
        ensure!(
            public
                .get("source_revision")
                .and_then(Value::as_str)
                .is_some_and(|s| is_hex(s, 40)),
            "compute_dataset_revision"
        );
    }
    Ok(())
}

fn validate_profile_dataset(
    mode: Mode,
    has_adapter: bool,
    dataset: &[u8],
    profile: ModelProfile,
) -> Result<()> {
    ensure!(
        profile.is_default() || (mode != Mode::Train && !has_adapter),
        "compute_profile_inference_only"
    );
    validate_dataset(mode, has_adapter, dataset)?;
    if mode == Mode::PlanTasks {
        ensure!(
            task_plan::Input::decode(dataset)?.model_profile == profile,
            "compute_planning_model_profile"
        );
    } else if mode == Mode::PlanDocument {
        let input: document_plan::Input = serde_json::from_slice(dataset)?;
        ensure!(
            input.model_profile == profile,
            "compute_planning_model_profile"
        );
    }
    if mode == Mode::Infer {
        let public: Value = serde_json::from_slice(dataset)?;
        let rows = public["inference"]
            .as_array()
            .context("compute_profile_inference_rows")?;
        ensure!(
            (1..=usize::from(profile.spec().max_rows)).contains(&rows.len()),
            "compute_profile_row_limit"
        );
        if matches!(public["version"].as_u64(), Some(3 | 5)) {
            let selected: ModelProfile = public
                .get("model_profile")
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()?
                .unwrap_or_default();
            ensure!(selected == profile, "compute_derived_model_profile");
        }
        if public["version"] == 4 {
            ensure!(
                profile.supports_rich_inference() && !has_adapter,
                "compute_principle_model_profile"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests;

fn private_directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "compute_path_absolute");
    let info = fs::symlink_metadata(path).context("compute_directory_missing")?;
    ensure!(
        info.is_dir()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o700,
        "compute_directory_not_private"
    );
    ensure!(fs::canonicalize(path)? == path, "compute_directory_symlink");
    Ok(())
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "compute_file_absolute");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.len() <= limit,
        "compute_file_invalid"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "compute_file_size");
    Ok(bytes)
}

fn runtime_lease(runtime: &Path) -> Result<nix::fcntl::Flock<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(runtime.join(".volparossa-compute.lock"))?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.mode() & 0o777 == 0o600,
        "compute_lock_invalid"
    );
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| anyhow::anyhow!("compute_runtime_busy"))
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_message(bytes: &[u8], id: &str) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_LINE_BYTES,
        "compute_worker_line_size"
    );
    let value: Value = serde_json::from_slice(bytes).context("compute_worker_json")?;
    ensure!(
        value.get("version") == Some(&Value::from(1))
            && value.get("id").and_then(Value::as_str) == Some(id),
        "compute_worker_correlation"
    );
    match value.get("kind").and_then(Value::as_str) {
        Some("progress") => ensure!(
            matches!(
                value.get("phase").and_then(Value::as_str),
                Some(
                    "preparing"
                        | "baseline"
                        | "training"
                        | "checkpoint"
                        | "reload"
                        | "complete"
                        | "paused"
                        | "resumed"
                )
            ),
            "compute_worker_phase"
        ),
        Some("result") => ensure!(
            matches!(
                value.get("status").and_then(Value::as_str),
                Some("ok" | "error")
            ),
            "compute_worker_status"
        ),
        _ => bail!("compute_worker_kind"),
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_requires_cohort_and_default_public_profile() {
        let dataset = br#"{"version":1,"visibility":"public","license":"GPL-3.0-only","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        validate_profile_dataset(
            Mode::AggregateAdapter,
            true,
            dataset,
            ModelProfile::default(),
        )
        .unwrap();
        assert!(
            validate_profile_dataset(
                Mode::AggregateAdapter,
                false,
                dataset,
                ModelProfile::default()
            )
            .is_err()
        );
        let private = br#"{"version":1,"visibility":"private_local","license":"GPL-3.0-only","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(
            validate_profile_dataset(
                Mode::AggregateAdapter,
                true,
                private,
                ModelProfile::default()
            )
            .is_err()
        );
        let inference = br#"{"version":2}"#;
        assert!(
            validate_profile_dataset(
                Mode::AggregateAdapter,
                true,
                inference,
                ModelProfile::default()
            )
            .is_err()
        );
    }

    #[test]
    fn response_is_bounded_and_bound_to_exact_job() {
        let id = "abc";
        assert!(
            check_message(
                br#"{"version":1,"id":"abc","kind":"result","status":"ok"}"#,
                id
            )
            .is_ok()
        );
        assert!(
            check_message(
                br#"{"version":1,"id":"def","kind":"result","status":"ok"}"#,
                id
            )
            .is_err()
        );
        assert!(
            check_message(
                br#"{"version":1,"id":"abc","kind":"result","status":"pending"}"#,
                id
            )
            .is_err()
        );
        assert!(check_message(&vec![b' '; MAX_LINE_BYTES + 1], id).is_err());
        assert!(
            check_message(
                br#"{"version":1,"id":"abc","kind":"progress","phase":"raw prompt!"}"#,
                id
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_jobs_are_serialized_without_changing_user_files() {
        let root = tempfile::tempdir().expect("root");
        let first = runtime_lease(root.path()).expect("lease");
        assert!(runtime_lease(root.path()).is_err());
        drop(first);
        assert!(runtime_lease(root.path()).is_ok());
    }
}
