//! Explicit owner-side inference executor, never an arbitrary remote command broker.

mod dataset;
#[cfg(test)]
mod tests;

use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
use volparossa_local_control::compute::{
    self, Capabilities, ErrorCode, FileIdentity, JobBinding, JobState, JobStatus, ModelIdentity,
    Operation, Outcome, Request, Response, Submit,
};

use super::spare_capacity::{Budget, Decision};
use super::{Mode, Options, execute, private_directory};

const RETAINED_JOBS: usize = 8;
const TERMINAL_GRACE_SECONDS: u64 = 60;
const EXCHANGE_SECONDS: u64 = 3;

#[derive(Debug, Args)]
pub(crate) struct Serve {
    /// Existing private pinned Python runtime, configured by this node's owner.
    #[arg(long)]
    runtime_root: PathBuf,
    /// Existing private fixed `SmolLM2` model directory; never downloaded by serving.
    #[arg(long)]
    model_root: PathBuf,
    /// Optional existing compatible fixed adapter, never selected by an incoming path.
    #[arg(long)]
    adapter_root: Option<PathBuf>,
    /// Existing private directory for bounded temporary job inputs and outputs.
    #[arg(long)]
    work_root: PathBuf,
    /// New same-UID Unix socket below an existing private directory.
    #[arg(long)]
    socket: PathBuf,
    /// Without this flag only the exact owner-side service plan is printed.
    #[arg(long)]
    execute: bool,
}

struct Job {
    requester: String,
    status: JobStatus,
    activity: watch::Sender<bool>,
    execution: Option<JoinHandle<Result<Value>>>,
    // Receipt retention only: the original execution authorization is never extended.
    terminal_retain_until: Option<u64>,
    // This exact newly created directory is retained until the worker has returned.
    // Its RAII cleanup never traverses an operator-supplied or pre-existing job directory.
    directory: Option<TempDir>,
}

struct Broker {
    options: Serve,
    capabilities: Capabilities,
    jobs: VecDeque<Job>,
    budget: Budget,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|info| {
            info.file_type().is_socket()
                && info.dev() == self.device
                && info.ino() == self.inode
                && info.uid() == nix::unistd::geteuid().as_raw()
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) async fn run(options: Serve) -> Result<()> {
    validate_roots(&options)?;
    if !options.execute {
        println!(
            "{}",
            serde_json::json!({
                "version": 1, "kind": "volparossa-compute-broker-plan", "execute": false,
                "socket": options.socket, "runtime_root": options.runtime_root,
                "model_root": options.model_root, "adapter_root": options.adapter_root,
                "work_root": options.work_root, "mode": "public_inference_only",
                "runtime_slots": 1, "pending_queue": 0, "retained_jobs": RETAINED_JOBS,
                "terminal_receipt_grace_seconds": TERMINAL_GRACE_SECONDS,
                "spare_capacity": true, "pressure_action": "cooperative-pause-resume-memory-cancel",
                "pause_extends_deadline": false,
                "max_job_seconds": compute::MAX_JOB_SECONDS, "same_uid_only": true,
                "remote_network_authentication": "required-agent-boundary",
                "network_access": false, "remote_execution_proved": false,
                "task_derivation_v1": true,
                "document_inference_v2": true,
                "derived_inference_v3": true
            })
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let capabilities = capabilities(&options)?;
    let listener = UnixListener::bind(&options.socket).context("compute_broker_socket_bind")?;
    fs::set_permissions(&options.socket, fs::Permissions::from_mode(0o600))?;
    let info = fs::symlink_metadata(&options.socket)?;
    let _socket = SocketGuard {
        path: options.socket.clone(),
        device: info.dev(),
        inode: info.ino(),
    };
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut broker = Broker {
        options,
        capabilities,
        jobs: VecDeque::new(),
        budget: Budget::new(),
    };
    let mut ticks = tokio::time::interval(Duration::from_millis(100));
    let serving = async {
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = ticks.tick() => broker.refresh(now()?).await,
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.context("compute_broker_accept")?;
                    if stream.peer_cred()?.uid() != nix::unistd::geteuid().as_raw() { continue; }
                    let Ok(Ok(request)) = timeout(Duration::from_secs(EXCHANGE_SECONDS), compute::read_request(&mut stream)).await else { continue; };
                    let response = broker.handle(request, now()?).await;
                    let _ = timeout(Duration::from_secs(EXCHANGE_SECONDS), compute::write_response(&mut stream, &response)).await;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    drop(listener);
    broker.shutdown().await?;
    serving
}

fn validate_roots(options: &Serve) -> Result<()> {
    for root in [
        &options.runtime_root,
        &options.model_root,
        &options.work_root,
    ] {
        private_directory(root)?;
    }
    if let Some(adapter) = &options.adapter_root {
        private_directory(adapter)?;
    }
    ensure!(
        options.socket.is_absolute(),
        "compute_broker_socket_absolute"
    );
    private_directory(
        options
            .socket
            .parent()
            .context("compute_broker_socket_parent")?,
    )?;
    ensure!(
        fs::symlink_metadata(&options.socket)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "compute_broker_socket_exists"
    );
    ensure!(
        !options.work_root.starts_with(&options.model_root)
            && !options.model_root.starts_with(&options.work_root)
            && !options.work_root.starts_with(&options.runtime_root)
            && !options.runtime_root.starts_with(&options.work_root),
        "compute_broker_roots_overlap"
    );
    if let Some(adapter) = &options.adapter_root {
        ensure!(
            !options.work_root.starts_with(adapter) && !adapter.starts_with(&options.work_root),
            "compute_broker_adapter_overlap"
        );
    }
    ensure!(
        options.runtime_root.join("bin/python3").is_file(),
        "compute_runtime_missing"
    );
    Ok(())
}

fn capabilities(options: &Serve) -> Result<Capabilities> {
    let base_weights = identity(&options.model_root.join("model.safetensors"), 269_060_552)?;
    ensure!(
        base_weights.bytes == 269_060_552 && base_weights.sha256 == hex::encode(BASE_MODEL_SHA256),
        "compute_broker_model_mismatch"
    );
    let adapter_files = options
        .adapter_root
        .as_ref()
        .map(|root| {
            let names = [
                "README.md",
                "adapter_config.json",
                "adapter_model.safetensors",
            ];
            ensure!(
                fs::read_dir(root)?.count() == names.len(),
                "compute_broker_adapter_files"
            );
            names
                .into_iter()
                .map(|name| {
                    let maximum = if name == "adapter_model.safetensors" {
                        2 * 1024 * 1024
                    } else {
                        16 * 1024
                    };
                    Ok((name.to_owned(), identity(&root.join(name), maximum)?))
                })
                .collect::<Result<_>>()
        })
        .transpose()?;
    let model = ModelIdentity {
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_weights,
        adapter_files,
    };
    let fingerprint = sha(&serde_json::to_vec(&model)?);
    Ok(Capabilities {
        model,
        model_fingerprint: fingerprint,
        accepting_work: true,
        public_inference_only: true,
        runtime_slots: 1,
        max_threads: 2,
        max_job_seconds: compute::MAX_JOB_SECONDS,
        max_dataset_bytes: compute::MAX_DATASET_BYTES as u64,
        max_rows: 4,
        task_derivation_v1: true,
        document_inference_v2: true,
        derived_inference_v3: true,
    })
}

fn identity(path: &Path, maximum: u64) -> Result<FileIdentity> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.mode() & 0o022 == 0
            && (1..=maximum).contains(&info.len()),
        "compute_broker_model_file"
    );
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= maximum, "compute_broker_model_file_size");
        hasher.update(&buffer[..count]);
    }
    ensure!(bytes == info.len(), "compute_broker_model_file_changed");
    Ok(FileIdentity {
        bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

impl Broker {
    async fn handle(&mut self, request: Request, time: u64) -> Response {
        self.refresh(time).await;
        let outcome = if request.validate(time).is_err() {
            Outcome::Error(ErrorCode::Invalid)
        } else {
            match &request.operation {
                Operation::Capabilities => {
                    let mut caps = self.capabilities.clone();
                    caps.accepting_work = self.available();
                    Outcome::Capabilities(caps)
                }
                Operation::Submit(submit) => self.submit(&request.requester_key, submit, time),
                Operation::Poll(binding) => self.observe(&request.requester_key, binding, false),
                Operation::Cancel(binding) => self.observe(&request.requester_key, binding, true),
            }
        };
        Response {
            version: compute::VERSION,
            request_id: request.request_id,
            outcome,
        }
    }

    fn available(&self) -> bool {
        self.budget.current() == Decision::Run
            && self.jobs.len() < RETAINED_JOBS
            && self.jobs.iter().all(|job| job.execution.is_none())
    }

    fn submit(&mut self, requester: &str, submit: &Submit, time: u64) -> Outcome {
        if submit.binding.expires_unix_seconds <= time {
            return Outcome::Error(ErrorCode::Expired);
        }
        if submit.binding.model_fingerprint != self.capabilities.model_fingerprint {
            return Outcome::Error(ErrorCode::ModelMismatch);
        }
        if sha(submit.dataset_json.as_bytes()) != submit.binding.dataset_sha256
            || dataset::validate(&submit.dataset_json, submit.binding.row_indices.len()).is_err()
            || !self.accepts_task(submit)
        {
            return Outcome::Error(ErrorCode::Invalid);
        }
        if let Some(job) = self
            .jobs
            .iter()
            .find(|job| job.status.binding.job_id == submit.binding.job_id)
        {
            return if job.requester == requester && job.status.binding == submit.binding {
                Outcome::Job(job.status.clone())
            } else {
                Outcome::Error(ErrorCode::Missing)
            };
        }
        if !self.available() {
            return Outcome::Error(ErrorCode::Busy);
        }
        match self.start(requester, submit, time) {
            Ok(job) => {
                let status = job.status.clone();
                self.jobs.push_back(job);
                Outcome::Job(status)
            }
            Err(_) => Outcome::Error(ErrorCode::Unavailable),
        }
    }

    fn accepts_task(&self, submit: &Submit) -> bool {
        if !self.capabilities.document_inference_v2
            && serde_json::from_str::<Value>(&submit.dataset_json)
                .is_ok_and(|value| value["version"] == 2)
        {
            return false;
        }
        if !self.capabilities.derived_inference_v3
            && serde_json::from_str::<Value>(&submit.dataset_json)
                .is_ok_and(|value| value["version"] == 3)
        {
            return false;
        }
        let Some(task) = &submit.binding.task else {
            return true;
        };
        if !self.capabilities.task_derivation_v1 {
            return false;
        }
        let Ok(question) = task.question() else {
            return false;
        };
        // The same-UID agent verifies signed-source/context derivation before forwarding.
        // Independently ensure this fixed worker receives the exact bound requester instruction.
        serde_json::from_str::<Value>(&submit.dataset_json).is_ok_and(|value| {
            value
                .get("inference")
                .and_then(Value::as_array)
                .is_some_and(|rows| {
                    rows.iter()
                        .all(|row| row["question"].as_str() == Some(question))
                })
        })
    }

    fn start(&self, requester: &str, submit: &Submit, time: u64) -> Result<Job> {
        let directory = tempfile::Builder::new()
            .prefix("compute-job-")
            .tempdir_in(&self.options.work_root)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let dataset_path = directory.path().join("dataset.json");
        let mut dataset = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dataset_path)?;
        dataset.write_all(submit.dataset_json.as_bytes())?;
        dataset.sync_all()?;
        drop(dataset);
        let options = Options {
            mode: Mode::Infer,
            runtime_root: self.options.runtime_root.clone(),
            model_root: self.options.model_root.clone(),
            adapter_root: self.options.adapter_root.clone(),
            dataset: dataset_path,
            output: directory.path().join("output"),
            steps: 1,
            threads: 2,
            max_seconds: u16::try_from(submit.binding.expires_unix_seconds - time)?,
            execute: true,
            spare_capacity: true,
        };
        options.validate()?;
        let (activity, receiver) = watch::channel(true);
        let execution = tokio::spawn(async move { execute(&options, receiver).await });
        Ok(Job {
            requester: requester.into(),
            status: JobStatus {
                binding: submit.binding.clone(),
                state: JobState::Running,
                cancellation_requested: false,
                report_json: None,
                report_sha256: None,
                error: None,
            },
            activity,
            execution: Some(execution),
            terminal_retain_until: None,
            directory: Some(directory),
        })
    }

    fn observe(&mut self, requester: &str, binding: &JobBinding, cancel: bool) -> Outcome {
        let Some(job) = self
            .jobs
            .iter_mut()
            .find(|job| job.requester == requester && job.status.binding == *binding)
        else {
            return Outcome::Error(ErrorCode::Missing);
        };
        if cancel && job.execution.is_some() {
            job.status.cancellation_requested = true;
            let _ = job.activity.send(false);
        }
        Outcome::Job(job.status.clone())
    }

    async fn refresh(&mut self, time: u64) {
        self.budget.sample();
        for job in &mut self.jobs {
            if job.status.binding.expires_unix_seconds <= time && job.execution.is_some() {
                job.status.cancellation_requested = true;
                let _ = job.activity.send(false);
            }
            if !job.execution.as_ref().is_some_and(JoinHandle::is_finished) {
                continue;
            }
            let Some(execution) = job.execution.take() else {
                continue;
            };
            let result = execution.await;
            finish_job(job, result, &self.capabilities);
            job.terminal_retain_until = Some(
                job.status
                    .binding
                    .expires_unix_seconds
                    .max(time.saturating_add(TERMINAL_GRACE_SECONDS)),
            );
        }
        self.jobs.retain(|job| {
            job.execution.is_some() || job.terminal_retain_until.is_some_and(|until| until > time)
        });
    }

    async fn shutdown(&mut self) -> Result<()> {
        for job in &self.jobs {
            let _ = job.activity.send(false);
        }
        for job in &mut self.jobs {
            if let Some(mut execution) = job.execution.take() {
                // The existing supervisor cancels and reaps its real bwrap child. Do not
                // delete the active job directory or release its slot before it returns.
                if timeout(Duration::from_secs(10), &mut execution)
                    .await
                    .is_err()
                {
                    // Preserve inputs/output if the supervisor cannot confirm termination.
                    // Aborting drops its kill-on-drop child; report failure, never clean exit.
                    execution.abort();
                    let _ = execution.await;
                    if let Some(directory) = job.directory.take() {
                        let _ = directory.keep();
                    }
                    anyhow::bail!("compute_broker_shutdown_unconfirmed");
                }
            }
        }
        self.jobs.clear();
        Ok(())
    }
}

fn finish_job(
    job: &mut Job,
    result: Result<Result<Value>, tokio::task::JoinError>,
    caps: &Capabilities,
) {
    if job.status.cancellation_requested
        && match &result {
            Ok(Ok(_)) => true,
            Ok(Err(error)) => {
                error.to_string() == "compute_owner_busy" || error.to_string() == "compute_deadline"
            }
            Err(_) => false,
        }
    {
        job.status.state = JobState::Cancelled;
        return;
    }
    let Ok(Ok(report)) = result else {
        job.status.state = JobState::Failed;
        job.status.error = Some(ErrorCode::WorkerFailed);
        return;
    };
    let checked = checked_report(&report, &job.status.binding, caps);
    if let Ok(report_json) = checked {
        job.status.report_sha256 = Some(sha(report_json.as_bytes()));
        job.status.report_json = Some(report_json);
        job.status.state = JobState::Complete;
    } else {
        job.status.state = JobState::Failed;
        job.status.error = Some(ErrorCode::ResultMismatch);
    }
}

pub(super) fn checked_report(
    report: &Value,
    binding: &JobBinding,
    caps: &Capabilities,
) -> Result<String> {
    ensure!(
        report["mode"] == "infer"
            && report["status"] == "ok"
            && report["updates_completed"] == 0
            && report["dataset"]["sha256"] == binding.dataset_sha256
            && report["dataset"]["visibility"] == "public"
            && report["dataset"]["inference_examples"] == binding.row_indices.len()
            && report["model"]["id"] == caps.model.model_id
            && report["model"]["revision"] == caps.model.model_revision
            && report["model"]["files"]["model.safetensors"]
                == serde_json::to_value(&caps.model.base_weights)?
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false,
        "compute_broker_result_binding"
    );
    match &caps.model.adapter_files {
        Some(files) => ensure!(
            report["input_adapter"]["applied"] == true
                && report["input_adapter"]["files"] == serde_json::to_value(files)?,
            "compute_broker_result_adapter"
        ),
        None => ensure!(
            report.get("input_adapter").is_none(),
            "compute_broker_unexpected_adapter"
        ),
    }
    let outputs = report["outputs"]
        .as_array()
        .context("compute_broker_result_outputs")?;
    ensure!(
        outputs.len() == binding.row_indices.len(),
        "compute_broker_result_rows"
    );
    for (index, output) in outputs.iter().enumerate() {
        ensure!(
            output["sample_index"] == index
                && output["text"]
                    .as_str()
                    .is_some_and(|text| text.len() <= 1024),
            "compute_broker_result_row"
        );
    }
    let json = serde_json::to_string(report)?;
    ensure!(
        json.len() <= compute::MAX_REPORT_BYTES,
        "compute_broker_result_size"
    );
    Ok(json)
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
