//! Owner-controlled lifecycle and bounded observations, outside the model worker.

use std::{
    collections::BTreeSet, fmt, fs::File, io::Read, os::unix::process::ExitStatusExt, path::Path,
    process::ExitStatus, time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Child,
    sync::watch,
};

use super::{MAX_LINE_BYTES, MAX_STREAM_BYTES, Mode, Options, WorkerRequest, check_message};
use super::{
    owner_control::{Action, Controls},
    spare_capacity::{Budget, Decision},
};

pub(super) const MAX_RSS_BYTES: u64 = 3 * 1024 * 1024 * 1024;
pub(super) const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MIN_FREE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBSERVED_PROCESSES: usize = 64;
const MAX_OBSERVED_THREADS: usize = 128;

/// A fixed error reply from the exact local worker, exposed only after its cleanup succeeds.
/// This is local execution evidence, not an independently portable or network-wide verdict.
#[derive(Debug)]
pub(super) struct WorkerFailure {
    request_id: String,
    code: String,
    planner_diagnostic: Option<super::task_plan::PlanningDiagnostic>,
}

impl WorkerFailure {
    pub(super) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(super) fn code(&self) -> &str {
        &self.code
    }

    pub(super) fn planner_diagnostic(&self) -> Option<&super::task_plan::PlanningDiagnostic> {
        self.planner_diagnostic.as_ref()
    }
}

impl fmt::Display for WorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compute_backend_failed: {}", self.code)
    }
}

impl std::error::Error for WorkerFailure {}

// This private type is deliberately not WorkerFailure and does not expose one as its source.
// An error in the supervisor's cleanup must supersede the pending worker observation.
#[derive(Debug)]
struct PendingWorkerFailure {
    request_id: String,
    code: String,
    planner_diagnostic: Option<super::task_plan::PlanningDiagnostic>,
}

impl fmt::Display for PendingWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compute_backend_failed: {}", self.code)
    }
}

impl std::error::Error for PendingWorkerFailure {}

/// Only deterministic adapter format/value failures authorize local artifact quarantine.
pub(super) fn adapter_violation(error: &anyhow::Error) -> Option<&'static str> {
    let failure = error.downcast_ref::<WorkerFailure>()?;
    [
        "INVALID_ADAPTER_WEIGHTS",
        "INVALID_ADAPTER_HEADER",
        "INVALID_ADAPTER_METADATA",
        "UNSUPPORTED_ADAPTER_TENSOR_KEYS",
        "UNSUPPORTED_ADAPTER_TENSOR_FORMAT",
        "INVALID_ADAPTER_TENSOR_OFFSETS",
        "INVALID_ADAPTER_TENSOR_LAYOUT",
        "NONFINITE_ADAPTER_WEIGHTS",
        "UNSUPPORTED_ADAPTER_CONFIG",
        "INVALID_ADAPTER_README",
    ]
    .into_iter()
    .find(|code| *code == failure.code())
}

fn reaped_failure(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<PendingWorkerFailure>() {
        Ok(failure) => WorkerFailure {
            request_id: failure.request_id,
            code: failure.code,
            planner_diagnostic: failure.planner_diagnostic,
        }
        .into(),
        Err(error) => error,
    }
}

/// Synthetic protocol input for pure caller tests; not evidence of a real worker or cleanup.
#[cfg(test)]
pub(super) fn test_worker_failure(code: &str) -> anyhow::Error {
    test_worker_failure_with_diagnostic(code, None)
}

#[cfg(test)]
pub(super) fn test_worker_failure_with_diagnostic(
    code: &str,
    diagnostic: Option<Value>,
) -> anyhow::Error {
    let id = "ab".repeat(16);
    let mut reply =
        serde_json::json!({"version":1,"id":id,"kind":"result", "status":"error","code":code});
    if let Some(diagnostic) = diagnostic {
        reply["planner_diagnostic"] = diagnostic;
    }
    reaped_failure(worker_failure(&reply, &id, ExitStatus::from_raw(1 << 8)))
}

pub(super) async fn run(
    mut child: Child,
    request: &WorkerRequest,
    options: &Options,
    mut owner_idle: watch::Receiver<bool>,
) -> Result<Value> {
    let pid = child.id().context("compute_child_id")?;
    let mut stdin = child.stdin.take().context("compute_child_stdin")?;
    let stdout = child.stdout.take().context("compute_child_stdout")?;
    let stderr = child.stderr.take().context("compute_child_stderr")?;
    let mut input = serde_json::to_vec(request)?;
    ensure!(input.len() < 65536, "compute_request_limit");
    input.push(b'\n');
    let deadline = tokio::time::sleep(Duration::from_secs(u64::from(options.max_seconds)));
    tokio::pin!(deadline);
    let mut peak_rss = 0;
    let mut ticks = tokio::time::interval(Duration::from_millis(250));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut budget = Budget::new();
    let controls = options.spare_capacity.then(Controls::default);
    let result = async {
        if let Some(controls) = &controls {
            let action = pressure_action(&mut budget)?;
            input.extend(controls.issue(action, &request.id)?.context("compute_initial_control")?);
        }
        tokio::time::timeout(Duration::from_secs(1), stdin.write_all(&input))
            .await.context("compute_request_write_deadline")?
            .context("compute_request_write")?;
        // Legacy workers receive EOF after the request. Controlled workers retain
        // exactly this private pipe; neither peers nor model output can issue commands.
        let mut control_stdin = if controls.is_some() { Some(stdin) } else { drop(stdin); None };
        let io = async {
            let (result, status) = collect_completion(
                &mut child, stdout, stderr, &request.id, controls.as_ref()
            ).await?;
            check_result(&result, request, status)?;
            if let Some(controls) = &controls {
                controls.check_report(&result)?;
            } else {
                ensure!(result.get("owner_control").is_none(), "compute_unrequested_owner_control");
            }
            ensure!(status.success(), "compute_worker_exit");
            check_artifacts(&result, request.mode, &options.output)?;
            check_input_adapter(&result, options)?;
            Ok(result)
        };
        tokio::pin!(io);
        loop {
            tokio::select! {
                biased;
                () = &mut deadline => break Err(anyhow::anyhow!("compute_deadline")),
                changed = owner_idle.changed() => {
                    if changed.is_err() || !*owner_idle.borrow() {
                        break Err(anyhow::anyhow!("compute_owner_busy"));
                    }
                },
                result = &mut io => break result,
                _ = ticks.tick() => {
                    let observation = observe(pid, &options.output, !options.spare_capacity);
                    match observation {
                        Ok(rss) => peak_rss = peak_rss.max(rss),
                        Err(error) => break Err(error),
                    }
                    if let Some(controls) = &controls {
                        let action = pressure_action(&mut budget)?;
                        if let Some(record) = controls.issue(action, &request.id)? {
                            tokio::time::timeout(Duration::from_secs(1),
                                control_stdin.as_mut().context("compute_control_stdin")?.write_all(&record))
                                .await.context("compute_control_write_deadline")?
                                .context("compute_control_write")?;
                        }
                    }
                }
            }
        }
    }.await;
    if result.is_err() {
        reap_failed_child(&mut child, options.mode).await?;
    }
    // Only this post-cleanup boundary can expose typed worker failure evidence to callers.
    let mut result = result.map_err(reaped_failure)?;
    result["supervisor"] = serde_json::json!({
        "version": 1, "sandbox": "bubblewrap-private-user-net-pid-ipc-mount",
        "network_access": false, "gpu_access": false,
        "max_observed_rss_bytes": peak_rss,
        "rss_limit_bytes": MAX_RSS_BYTES,
        "rss_enforcement": "250ms-observed-cancel-not-cgroup-hard-limit",
        "owner_activity_action": "cancel",
        "spare_capacity": options.spare_capacity,
        "pressure_action": if options.spare_capacity { "cooperative-pause-resume-memory-cancel" } else { "cancel" },
        "last_capacity_observation": controls.as_ref().map(|_| budget.observation()),
        "last_capacity_constraint": controls.as_ref().map(|_| budget.constraint()),
        "device_capacity_policy": options.spare_capacity.then_some("battery-20-pause-5-cancel-thermal-trips-v1"),
        "pause_extends_deadline": false,
        "deadline_seconds": options.max_seconds,
        "child_reaped": true,
        "distributed_execution_claimed": false,
        "private_training_claimed": false
    });
    if options.mode == Mode::PlanTasks {
        check_task_plan_result(&result, options)?;
    } else if options.mode == Mode::PrivateInfer {
        let input = super::read_file(&options.dataset, super::MAX_DATASET_BYTES)?;
        super::private_task::validate_report(&result, &input, options.model_profile)?;
    }
    Ok(result)
}

async fn reap_failed_child(child: &mut Child, mode: Mode) -> Result<()> {
    // Killing the exact live bwrap parent kills its sandbox child (die-with-parent).
    // PID namespace teardown kills/reaps descendants; no host process-group scan.
    let _ = child.start_kill();
    let reaped = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .context("compute_reap_deadline")
        .and_then(|result| result.context("compute_reap"));
    if mode == Mode::PrivateInfer && reaped.is_err() {
        return Err(super::private_task::CleanupUnconfirmed.into());
    }
    reaped?;
    Ok(())
}

fn check_task_plan_result(result: &Value, options: &Options) -> Result<()> {
    let bytes = super::read_file(&options.dataset, super::MAX_DATASET_BYTES)?;
    let input = super::task_plan::Input::decode(&bytes)?;
    input.validate_execution()?;
    let (strategy, name) = if input.version == 3 {
        (
            super::task_plan::GRAPH_STRATEGY,
            super::task_plan::GRAPH_ARTIFACT_NAME,
        )
    } else {
        (super::task_plan::CURRENT_STRATEGY, "task-questions.json")
    };
    ensure!(
        result["planner_strategy"] == strategy,
        "compute_task_plan_execution_strategy"
    );
    let artifact = super::read_file(
        &options.output.join(name),
        super::task_plan::MAX_ARTIFACT_BYTES,
    )?;
    if input.version == 3 {
        super::task_plan::validate_graph_report(result, &input, &bytes, &artifact).map(|_| ())
    } else {
        super::task_plan::validate_report(result, &input, &bytes, &artifact).map(|_| ())
    }
}

fn pressure_action(budget: &mut Budget) -> Result<Action> {
    match budget.sample() {
        Decision::Run => Ok(Action::Resume),
        Decision::Pause => Ok(Action::Pause),
        Decision::Cancel => bail!("{}", budget.cancellation_code()),
    }
}

fn check_result(value: &Value, request: &WorkerRequest, status: ExitStatus) -> Result<()> {
    if value.get("status").and_then(Value::as_str) == Some("error") {
        return Err(worker_failure(value, &request.id, status));
    }
    ensure!(
        value.get("status").and_then(Value::as_str) == Some("ok"),
        "compute_backend_failed"
    );
    ensure!(
        value.get("mode") == Some(&serde_json::to_value(request.mode)?),
        "compute_result_mode"
    );
    ensure!(
        value.get("device").and_then(Value::as_str) == Some("cpu"),
        "compute_result_device"
    );
    let updates = value.get("updates_completed").and_then(Value::as_u64);
    match request.mode {
        Mode::Infer | Mode::PrivateInfer | Mode::PlanDocument | Mode::PlanTasks => {
            ensure!(updates == Some(0), "compute_unrequested_training");
        }
        Mode::Train => {
            ensure!(
                updates == Some(u64::from(request.steps)),
                "compute_training_incomplete"
            );
            for field in [
                "base_weights_unchanged",
                "adapter_weights_changed",
                "checkpoint_reloaded",
            ] {
                ensure!(
                    value.get(field) == Some(&Value::Bool(true)),
                    "compute_training_proof_missing"
                );
            }
        }
    }
    if request.mode == Mode::PrivateInfer {
        ensure!(
            value["private_data_supported"] == true
                && value["distributed_execution_claimed"] == false
                && value["private_training_claimed"] == false
                && value["dataset"]["visibility"] == "private_local"
                && value["outputs"]
                    .as_array()
                    .is_some_and(|outputs| outputs.len() == 1),
            "compute_private_result_scope"
        );
    }
    if matches!(request.mode, Mode::Infer | Mode::PrivateInfer | Mode::Train) {
        let outputs = value["outputs"]
            .as_array()
            .context("compute_result_outputs")?;
        ensure!(
            (1..=usize::from(request.model_profile.spec().max_rows)).contains(&outputs.len()),
            "compute_result_output_count"
        );
        for (index, output) in outputs.iter().enumerate() {
            ensure!(
                output["sample_index"] == index
                    && output["text"].as_str().is_some_and(
                        |text| text.len() <= request.model_profile.spec().max_output_bytes
                    )
                    && output["text_truncated"].is_boolean(),
                "compute_result_output_shape"
            );
            ensure!(
                super::inference_output::Generation::from_output(output, true)?
                    .is_some_and(|generation| generation.model_profile == request.model_profile),
                "compute_result_generation_profile"
            );
        }
    }
    Ok(())
}

fn worker_failure(value: &Value, id: &str, status: ExitStatus) -> anyhow::Error {
    let fixed_code = value.get("code").and_then(Value::as_str).filter(|s| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    });
    let code = fixed_code.unwrap_or("UNKNOWN_FIXED_FAILURE");
    if fixed_code.is_some()
        && value.get("version") == Some(&Value::from(1))
        && value.get("id").and_then(Value::as_str) == Some(id)
        && value.get("kind").and_then(Value::as_str) == Some("result")
        && value.get("status").and_then(Value::as_str) == Some("error")
        // The fixed Python protocol returns 1 after emitting its error reply. A later
        // signal/OOM/crash is not deterministic evidence against the adapter bytes.
        && status.code() == Some(1)
    {
        PendingWorkerFailure {
            request_id: id.to_owned(),
            code: code.to_owned(),
            // Optional diagnostic data cannot change the fixed failure or authorize a plan.
            // Invalid traces are discarded, never normalized into plausible observations.
            planner_diagnostic: value
                .get("planner_diagnostic")
                .and_then(|value| super::task_plan::PlanningDiagnostic::from_value(value).ok()),
        }
        .into()
    } else {
        anyhow::anyhow!("compute_backend_failed: {code}")
    }
}

fn check_artifacts(value: &Value, mode: Mode, output: &Path) -> Result<()> {
    let artifacts = value
        .get("artifacts")
        .and_then(Value::as_array)
        .context("compute_artifacts")?;
    if matches!(mode, Mode::Infer | Mode::PrivateInfer) {
        ensure!(artifacts.is_empty(), "compute_inference_artifacts");
        return Ok(());
    }
    if mode == Mode::PlanTasks {
        ensure!(
            value["model_weights_loaded"] == true
                && artifacts.len() == 1
                && matches!(
                    artifacts[0]["relative_path"].as_str(),
                    Some("task-questions.json" | super::task_plan::GRAPH_ARTIFACT_NAME)
                ),
            "compute_task_plan_artifact"
        );
        let name = artifacts[0]["relative_path"]
            .as_str()
            .context("compute_task_plan_artifact")?;
        let bytes = super::read_file(&output.join(name), super::task_plan::MAX_ARTIFACT_BYTES)?;
        ensure!(
            artifacts[0]["bytes"] == bytes.len() as u64
                && artifacts[0]["sha256"] == hex::encode(Sha256::digest(&bytes)),
            "compute_task_plan_artifact_hash"
        );
        // Exact graph/goal corroboration follows the decoded original input after
        // cleanup. At this boundary only either fixed filename and its bytes pass.
        if name == "task-questions.json" {
            super::task_plan::Questions::decode(&bytes)?;
        }
        return Ok(());
    }
    if mode == Mode::PlanDocument {
        ensure!(
            value["model_weights_loaded"] == false,
            "compute_document_plan_loaded_weights"
        );
        ensure!(
            artifacts.len() == 1 && artifacts[0]["relative_path"] == "document-plan.json",
            "compute_document_plan_artifact"
        );
        let bytes = super::read_file(&output.join("document-plan.json"), MAX_OUTPUT_BYTES)?;
        ensure!(
            artifacts[0]["bytes"] == bytes.len() as u64
                && artifacts[0]["sha256"] == hex::encode(Sha256::digest(&bytes)),
            "compute_document_plan_hash"
        );
        return Ok(());
    }
    let expected = [
        "adapter/README.md",
        "adapter/adapter_config.json",
        "adapter/adapter_model.safetensors",
    ];
    ensure!(artifacts.len() == expected.len(), "compute_artifact_count");
    for (artifact, path) in artifacts.iter().zip(expected) {
        ensure!(
            artifact.get("relative_path").and_then(Value::as_str) == Some(path),
            "compute_artifact_path"
        );
        let bytes = super::read_file(&output.join(path), super::sandbox::MAX_FILE_BYTES)?;
        ensure!(
            artifact.get("bytes").and_then(Value::as_u64) == Some(bytes.len() as u64),
            "compute_artifact_size"
        );
        let hash = hex::encode(Sha256::digest(&bytes));
        ensure!(
            artifact.get("sha256").and_then(Value::as_str) == Some(hash.as_str()),
            "compute_artifact_hash"
        );
    }
    Ok(())
}

fn check_input_adapter(value: &Value, options: &Options) -> Result<()> {
    let Some(root) = &options.adapter_root else {
        ensure!(
            value.get("input_adapter").is_none(),
            "compute_unrequested_adapter"
        );
        return Ok(());
    };
    let input = &value["input_adapter"];
    ensure!(
        input["applied"] == true
            && input["applied_parameters"]["parameters"].as_u64() == Some(230_400),
        "compute_adapter_not_applied"
    );
    ensure!(
        input["base_parameters_before_apply"].is_object()
            && input["base_parameters_before_apply"] == input["base_parameters_after_apply"],
        "compute_adapter_changed_base"
    );
    for name in [
        "README.md",
        "adapter_config.json",
        "adapter_model.safetensors",
    ] {
        let bytes = super::read_file(&root.join(name), 2 * 1024 * 1024)?;
        ensure!(
            input["files"][name]["bytes"].as_u64() == Some(bytes.len() as u64)
                && input["files"][name]["sha256"].as_str()
                    == Some(hex::encode(Sha256::digest(&bytes)).as_str()),
            "compute_input_adapter_hash"
        );
    }
    Ok(())
}

async fn collect_completion(
    child: &mut Child,
    stdout: impl AsyncRead + Unpin,
    stderr: impl AsyncRead + Unpin,
    id: &str,
    controls: Option<&Controls>,
) -> Result<(Value, ExitStatus)> {
    let missing = tokio::sync::Notify::new();
    let finish = async {
        tokio::try_join!(
            async {
                let result = collect_stdout(stdout, id, controls).await?;
                if result.is_none() {
                    missing.notify_one();
                }
                Ok(result)
            },
            drain_stderr(stderr),
            async { child.wait().await.context("compute_wait") }
        )
    };
    tokio::pin!(finish);
    // Only clean EOF without a result waits for startup diagnostics. Invalid or
    // oversized stdout still fails immediately. Retained stderr gets at most
    // one second, within the supervisor's original cancellation/deadline scope.
    let (result, diagnostics, status) = tokio::select! {
        result = &mut finish => result?,
        () = missing.notified() => tokio::time::timeout(Duration::from_secs(1), &mut finish)
            .await.context("compute_missing_result_exit_deadline")??,
    };
    Ok((required_result(result, status, diagnostics)?, status))
}

async fn collect_stdout(
    stream: impl AsyncRead + Unpin,
    id: &str,
    controls: Option<&Controls>,
) -> Result<Option<Value>> {
    let mut reader = BufReader::new(stream);
    let mut result = None;
    let mut bytes = 0_usize;
    while let Some(line) = bounded_line(&mut reader).await? {
        bytes = bytes
            .checked_add(line.len() + 1)
            .context("compute_stdout_size")?;
        ensure!(bytes <= MAX_STREAM_BYTES, "compute_stdout_size");
        ensure!(result.is_none(), "compute_output_after_result");
        let value = check_message(&line, id)?;
        if value.get("kind").and_then(Value::as_str) == Some("result") {
            if let Some(controls) = controls {
                controls.terminal()?;
            }
            result = Some(value);
        } else {
            if matches!(value["phase"].as_str(), Some("paused" | "resumed")) {
                controls
                    .context("compute_unrequested_control_ack")?
                    .acknowledge(&value)?;
                let sequence = value["control_sequence"]
                    .as_u64()
                    .context("compute_control_sequence")?;
                let step = value["step"]
                    .as_u64()
                    .filter(|step| *step <= 64)
                    .context("compute_control_step")?;
                let elapsed = value["elapsed_ms"]
                    .as_u64()
                    .filter(|elapsed| *elapsed < 600_000)
                    .context("compute_control_elapsed")?;
                eprintln!(
                    "compute owner_ack phase={} sequence={sequence} step={step} elapsed_ms={elapsed}",
                    value["phase"].as_str().context("compute_control_phase")?
                );
            } else {
                ensure!(
                    value.get("control_sequence").is_none(),
                    "compute_unexpected_control_sequence"
                );
            }
            // Only the validated phase label is logged, never raw backend text or data.
            eprintln!(
                "compute phase={}",
                value["phase"].as_str().context("compute_phase")?
            );
        }
    }
    Ok(result)
}

async fn bounded_line(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await.context("compute_stdout_read")?;
        if available.is_empty() {
            ensure!(line.is_empty(), "compute_worker_unterminated_line");
            return Ok(None);
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.unwrap_or(available.len());
        ensure!(
            line.len() + count <= MAX_LINE_BYTES,
            "compute_worker_line_size"
        );
        line.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupClass {
    None,
    Bubblewrap,
    UserNamespace,
    ProcMount,
    ExecDenied,
    PythonStartup,
    Other,
}

impl StartupClass {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bubblewrap => "bubblewrap",
            Self::UserNamespace => "user_namespace",
            Self::ProcMount => "proc_mount",
            Self::ExecDenied => "exec_denied",
            Self::PythonStartup => "python_startup",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct StartupDiagnostics {
    class: StartupClass,
    bytes: usize,
}

fn startup_class(prefix: &[u8]) -> StartupClass {
    if prefix.is_empty() {
        StartupClass::None
    } else if prefix.starts_with(b"bwrap: Creating new namespace failed")
        || prefix.starts_with(b"bwrap: setting up uid map")
        || prefix.starts_with(b"bwrap: unshare user ns")
    {
        StartupClass::UserNamespace
    } else if prefix.starts_with(b"bwrap: Can't mount proc on ")
        || prefix.starts_with(b"bwrap: Creating proc failed")
    {
        StartupClass::ProcMount
    } else if prefix.starts_with(b"bwrap: execvp ")
        || prefix.starts_with(b"bwrap: execv ")
        || prefix.starts_with(b"prlimit:")
        || prefix.starts_with(b"nice:")
        || prefix.starts_with(b"ionice:")
    {
        // A fixed launcher/exec failure category, not proof of a particular errno.
        StartupClass::ExecDenied
    } else if prefix.starts_with(b"bwrap:") {
        StartupClass::Bubblewrap
    } else if prefix.starts_with(b"Fatal Python error:")
        || prefix.starts_with(b"Python path configuration:")
        || prefix.starts_with(b"Traceback (most recent call last):")
    {
        StartupClass::PythonStartup
    } else {
        StartupClass::Other
    }
}

fn required_result(
    result: Option<Value>,
    status: ExitStatus,
    diagnostics: StartupDiagnostics,
) -> Result<Value> {
    result.with_context(|| {
        format!(
            "compute_result_missing exit_code={} signal={} stderr_class={} stderr_bytes={}",
            status.code().unwrap_or(-1),
            status.signal().unwrap_or(0),
            diagnostics.class.label(),
            diagnostics.bytes,
        )
    })
}

async fn drain_stderr(mut stream: impl AsyncRead + Unpin) -> Result<StartupDiagnostics> {
    let mut buffer = [0_u8; 4096];
    let mut total = 0;
    // Transient bounded matching only: never persist/echo raw exception text,
    // paths, Python source lines, payloads or a hash identifying those inputs.
    let mut prefix = Vec::with_capacity(1024);
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .context("compute_stderr_read")?;
        if length == 0 {
            return Ok(StartupDiagnostics {
                class: startup_class(&prefix),
                bytes: total,
            });
        }
        total += length;
        ensure!(total <= MAX_STREAM_BYTES, "compute_stderr_size");
        let available = (1024 - prefix.len()).min(length);
        prefix.extend_from_slice(&buffer[..available]);
    }
}

pub(super) fn headroom() -> Result<()> {
    let memory = system_text(Path::new("/proc/meminfo"))?;
    let available = status_kib(&memory, "MemAvailable:").context("compute_memory_observation")?;
    ensure!(
        available >= MIN_FREE_MEMORY_BYTES,
        "compute_memory_pressure"
    );
    for (kind, maximum) in [("memory", 2.0), ("io", 20.0)] {
        let pressure = system_text(&Path::new("/proc/pressure").join(kind))?;
        let value = pressure
            .lines()
            .find(|s| s.starts_with("some "))
            .and_then(|s| s.split_whitespace().find_map(|p| p.strip_prefix("avg10=")))
            .and_then(|s| s.parse::<f64>().ok())
            .context("compute_pressure_observation")?;
        ensure!(
            value.is_finite() && value >= 0.0 && value < maximum,
            "compute_owner_pressure"
        );
    }
    Ok(())
}

fn observe(pid: u32, output: &Path, legacy_headroom: bool) -> Result<u64> {
    if legacy_headroom {
        headroom()?;
    }
    let mut pending = vec![pid];
    let mut visited = BTreeSet::new();
    let mut total = 0_u64;
    while let Some(current) = pending.pop() {
        if visited.contains(&current) {
            continue;
        }
        ensure!(
            visited.len() < MAX_OBSERVED_PROCESSES && visited.insert(current),
            "compute_process_bound"
        );
        let root = Path::new("/proc").join(current.to_string());
        let status = match system_text(&root.join("status")) {
            Ok(value) => value,
            Err(_) if !root.exists() => continue, // An already exited exact child.
            Err(error) => return Err(error),
        };
        total += status_kib(&status, "VmRSS:").unwrap_or(0);
        ensure!(total <= MAX_RSS_BYTES, "compute_memory_budget");
        let descendants = match process_children(&root) {
            Ok(value) => value,
            Err(_) if !root.exists() => continue,
            Err(error) => return Err(error),
        };
        for child in descendants {
            if !visited.contains(&child) && !pending.contains(&child) {
                ensure!(
                    pending.len() < MAX_OBSERVED_PROCESSES,
                    "compute_process_bound"
                );
                pending.push(child);
            }
        }
    }
    ensure!(
        output_bytes(output)? <= MAX_OUTPUT_BYTES,
        "compute_storage_budget"
    );
    Ok(total)
}

fn process_children(root: &Path) -> Result<BTreeSet<u32>> {
    // Linux records children on the *spawning thread*. Reading only task/PID
    // would omit children created by a worker thread and undercount their RSS.
    // Sum process RSS once; threads themselves share that address space.
    let mut children = BTreeSet::new();
    for (index, thread) in std::fs::read_dir(root.join("task"))?.enumerate() {
        ensure!(index < MAX_OBSERVED_THREADS, "compute_thread_bound");
        let thread = thread?.path();
        let text = match system_text(&thread.join("children")) {
            Ok(value) => value,
            Err(_) if !thread.exists() => continue, // Thread exited during this sample.
            Err(error) => return Err(error),
        };
        for child in text.split_whitespace() {
            let child = child
                .parse::<u32>()
                .context("compute_process_observation")?;
            ensure!(child > 0, "compute_process_observation");
            children.insert(child);
            ensure!(
                children.len() <= MAX_OBSERVED_PROCESSES,
                "compute_process_bound"
            );
        }
    }
    Ok(children)
}

fn output_bytes(path: &Path) -> Result<u64> {
    let mut pending = vec![path.to_path_buf()];
    let mut entries = 0;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            entries += 1;
            ensure!(entries <= 64, "compute_output_entries");
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes
                    .checked_add(metadata.len())
                    .context("compute_storage_budget")?;
            } else {
                bail!("compute_output_type");
            }
        }
    }
    Ok(bytes)
}

fn system_text(path: &Path) -> Result<String> {
    let mut output = String::new();
    File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_string(&mut output)?;
    ensure!(output.len() <= 16 * 1024, "compute_observation_size");
    Ok(output)
}

fn status_kib(text: &str, key: &str) -> Option<u64> {
    let mut fields = text
        .lines()
        .find(|line| line.starts_with(key))?
        .split_whitespace();
    (fields.next()? == key).then_some(())?;
    let value = fields.next()?.parse::<u64>().ok()?;
    (fields.next()? == "kB" && fields.next().is_none()).then_some(())?;
    value.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure_reply(code: &str) -> Value {
        serde_json::json!({"version":1,"id":"abc","kind":"result","status":"error","code":code})
    }

    #[test]
    fn new_planner_execution_does_not_accept_historical_strategy() {
        let directory = tempfile::tempdir().unwrap();
        let options = Options {
            mode: Mode::PlanTasks,
            model_profile: crate::compute::ModelProfile::default(),
            runtime_root: directory.path().join("unused-runtime"),
            model_root: directory.path().join("unused-model"),
            adapter_root: None,
            dataset: directory.path().join("input.json"),
            output: directory.path().join("absent-output"),
            steps: 1,
            threads: 2,
            max_seconds: 600,
            spare_capacity: true,
            execute: true,
        };
        for version in [2, 3] {
            let hash = hex::encode(Sha256::digest(b"public"));
            let input = serde_json::json!({"version":version,"visibility":"public","license":"CC0-1.0",
                "question":"What is described?","source_bytes":6,"source_sha256":hash,
                "source_excerpt":{"start":0,"end":6,"text":"public","sha256":hash}});
            std::fs::write(&options.dataset, serde_json::to_vec(&input).unwrap()).unwrap();
            for strategy in [
                "model_questions_scaffold_v1",
                "model_questions_scaffold_recovery_v2",
                "model_questions_source_recovery_v3",
                if version == 3 {
                    crate::compute::task_plan::CURRENT_STRATEGY
                } else {
                    crate::compute::task_plan::GRAPH_STRATEGY
                },
            ] {
                let report = serde_json::json!({"planner_strategy":strategy});
                assert_eq!(
                    check_task_plan_result(&report, &options)
                        .unwrap_err()
                        .to_string(),
                    "compute_task_plan_execution_strategy"
                );
            }
        }
    }

    #[test]
    fn fresh_inference_and_training_require_generation_metadata_but_keep_limited_jobs_terminal() {
        // Inert result-contract inputs, not model execution or answer-quality evidence.
        for mode in [Mode::Infer, Mode::Train] {
            let request = WorkerRequest {
                version: 1,
                id: "abc".into(),
                mode,
                model_profile: super::super::ModelProfile::default(),
                model_root: "/model",
                dataset_path: "/dataset.json",
                output_root: "/output",
                adapter_root: None,
                steps: 1,
                threads: 1,
                max_seconds: 60,
                owner_control: false,
            };
            let mut reply = serde_json::json!({"status":"ok","mode":mode,"device":"cpu",
                "updates_completed":u8::from(mode==Mode::Train),"base_weights_unchanged":true,
                "adapter_weights_changed":true,"checkpoint_reloaded":true,
                "outputs":[{"sample_index":0,"text":"Inert partial response",
                    "generated_tokens":64,"text_truncated":false,
                    "generation":{"version":1,"stop_reason":"token_limit","max_new_tokens":64}}]});
            assert!(check_result(&reply, &request, ExitStatus::from_raw(0)).is_ok());
            reply["outputs"][0]["generation"]["stop_reason"] = "eos".into();
            assert!(check_result(&reply, &request, ExitStatus::from_raw(0)).is_ok());
            reply["outputs"][0]["text_truncated"] = true.into();
            assert!(check_result(&reply, &request, ExitStatus::from_raw(0)).is_ok());
            reply["outputs"][0]
                .as_object_mut()
                .unwrap()
                .remove("generation");
            assert!(check_result(&reply, &request, ExitStatus::from_raw(0)).is_err());
        }
    }

    #[test]
    fn planning_diagnostics_are_typed_only_after_reaping_and_never_quarantine() {
        let trace = serde_json::json!({"strategy":"model_questions_scaffold_recovery_v2",
            "attempts":[],"incomplete_attempt":true});
        let mut reply = failure_reply("BACKEND_EXECUTION_FAILED");
        reply["planner_diagnostic"] = trace.clone();
        let pending = worker_failure(&reply, "abc", ExitStatus::from_raw(256));
        assert!(pending.downcast_ref::<WorkerFailure>().is_none());
        let error = reaped_failure(pending);
        let failure = error.downcast_ref::<WorkerFailure>().unwrap();
        assert_eq!(
            serde_json::to_value(failure.planner_diagnostic().unwrap()).unwrap(),
            trace
        );
        assert_eq!(adapter_violation(&error), None);
        reply["planner_diagnostic"]["incomplete_attempt"] = "invented".into();
        let error = reaped_failure(worker_failure(&reply, "abc", ExitStatus::from_raw(256)));
        let failure = error.downcast_ref::<WorkerFailure>().unwrap();
        assert_eq!(failure.code(), "BACKEND_EXECUTION_FAILED");
        assert!(failure.planner_diagnostic().is_none());
        let error = reaped_failure(worker_failure(&reply, "abc", ExitStatus::from_raw(9)));
        assert!(error.downcast_ref::<WorkerFailure>().is_none());
    }

    #[test]
    fn planner_stage_failures_preserve_fixed_codes_without_adapter_authority() {
        for stage in ["ONE", "TWO"] {
            for cause in [
                "PROMPT_TOKEN_LIMIT_EXCEEDED",
                "INVALID_GENERATION_SHAPE",
                "PROMPT_CHANGED",
                "GENERATION_LIMIT_REACHED",
                "COMPLETION_TOKENS_CHANGED",
                "INCOMPLETE_GENERATION",
                "INVALID_TEXT",
                "EMPTY_TEXT",
                "GOAL_COPY",
            ] {
                let code = format!("TASK_PLAN_QUESTION_{stage}_{cause}");
                let error = reaped_failure(worker_failure(
                    &failure_reply(&code),
                    "abc",
                    ExitStatus::from_raw(256),
                ));
                assert_eq!(error.to_string(), format!("compute_backend_failed: {code}"));
                assert_eq!(error.downcast_ref::<WorkerFailure>().unwrap().code(), code);
                assert_eq!(adapter_violation(&error), None);
            }
        }
    }

    #[tokio::test]
    async fn exact_adapter_failures_become_typed_only_at_the_reaped_boundary() {
        for code in [
            "INVALID_ADAPTER_WEIGHTS",
            "INVALID_ADAPTER_HEADER",
            "INVALID_ADAPTER_METADATA",
            "UNSUPPORTED_ADAPTER_TENSOR_KEYS",
            "UNSUPPORTED_ADAPTER_TENSOR_FORMAT",
            "INVALID_ADAPTER_TENSOR_OFFSETS",
            "INVALID_ADAPTER_TENSOR_LAYOUT",
            "NONFINITE_ADAPTER_WEIGHTS",
            "UNSUPPORTED_ADAPTER_CONFIG",
            "INVALID_ADAPTER_README",
        ] {
            let line = format!("{}\n", failure_reply(code));
            let reply = collect_stdout(line.as_bytes(), "abc", None)
                .await
                .unwrap()
                .unwrap();
            let pending = worker_failure(&reply, "abc", ExitStatus::from_raw(256));
            assert!(pending.downcast_ref::<WorkerFailure>().is_none());
            assert_eq!(adapter_violation(&pending), None);
            let error = reaped_failure(pending);
            assert_eq!(error.to_string(), format!("compute_backend_failed: {code}"));
            let failure = error.downcast_ref::<WorkerFailure>().unwrap();
            assert_eq!(failure.request_id(), "abc");
            assert_eq!(failure.code(), code);
            assert_eq!(adapter_violation(&error), Some(code));
            assert_eq!(
                adapter_violation(&error.context("local evaluation failed")),
                Some(code)
            );
        }
    }

    #[test]
    fn resource_io_cancel_and_text_errors_never_authorize_adapter_quarantine() {
        for code in [
            "JOB_INPUT_NOT_FOUND",
            "JOB_PATH_PERMISSION_DENIED",
            "JOB_MEMORY_EXHAUSTED",
            "JOB_DEADLINE_EXCEEDED",
            "BACKEND_IMPORT_FAILED",
            "BACKEND_EXECUTION_FAILED",
            "JOB_CANCELLED",
            "ADAPTER_INPUT_CHANGED",
            "INVALID_ADAPTER_CONFIG",
        ] {
            let error = reaped_failure(worker_failure(
                &failure_reply(code),
                "abc",
                ExitStatus::from_raw(256),
            ));
            assert_eq!(adapter_violation(&error), None);
        }
        for message in [
            "compute_backend_failed: INVALID_ADAPTER_WEIGHTS",
            "compute_owner_busy",
            "compute_deadline",
            "compute_reap_deadline",
            "compute_reap",
            "compute_input_adapter_hash",
        ] {
            let error = reaped_failure(anyhow::anyhow!("{message}"));
            assert!(error.downcast_ref::<WorkerFailure>().is_none());
            assert_eq!(adapter_violation(&error), None);
        }
        let error = anyhow::Error::new(std::io::Error::other(
            "compute_backend_failed: INVALID_ADAPTER_WEIGHTS",
        ));
        assert_eq!(adapter_violation(&error), None);
    }

    #[tokio::test]
    async fn malformed_or_uncorrelated_worker_output_cannot_mint_failure_evidence() {
        let valid = failure_reply("INVALID_ADAPTER_WEIGHTS");
        for field in ["version", "id", "kind", "status"] {
            let mut changed = valid.clone();
            changed[field] = Value::Null;
            let line = format!("{changed}\n");
            let error = collect_stdout(line.as_bytes(), "abc", None)
                .await
                .unwrap_err();
            assert_eq!(adapter_violation(&error), None);
            assert!(
                reaped_failure(worker_failure(&changed, "abc", ExitStatus::from_raw(256)))
                    .downcast_ref::<WorkerFailure>()
                    .is_none()
            );
        }
        for suffix in ["{}\n".to_owned(), format!("{valid}\n")] {
            let line = format!("{valid}\n{suffix}");
            let error = collect_stdout(line.as_bytes(), "abc", None)
                .await
                .unwrap_err();
            assert_eq!(adapter_violation(&error), None);
        }
        for status in [0, 9, 15, 512] {
            let error = reaped_failure(worker_failure(&valid, "abc", ExitStatus::from_raw(status)));
            assert!(error.downcast_ref::<WorkerFailure>().is_none());
            assert_eq!(
                error.to_string(),
                "compute_backend_failed: INVALID_ADAPTER_WEIGHTS"
            );
        }
        for code in [
            "",
            "invalid_adapter_weights",
            "/private/input",
            "A".repeat(65).as_str(),
        ] {
            let error = reaped_failure(worker_failure(
                &failure_reply(code),
                "abc",
                ExitStatus::from_raw(256),
            ));
            assert!(error.downcast_ref::<WorkerFailure>().is_none());
            assert_eq!(
                error.to_string(),
                "compute_backend_failed: UNKNOWN_FIXED_FAILURE"
            );
        }
    }

    #[tokio::test]
    async fn startup_diagnostics_classify_only_fixed_prefixes_without_echoing_private_text() {
        for (prefix, expected) in [
            ("", StartupClass::None),
            (
                "bwrap: Creating new namespace failed: ",
                StartupClass::UserNamespace,
            ),
            ("bwrap: Can't mount proc on ", StartupClass::ProcMount),
            ("bwrap: Can't bind mount ", StartupClass::Bubblewrap),
            ("bwrap: execvp ", StartupClass::ExecDenied),
            ("prlimit: ", StartupClass::ExecDenied),
            ("Fatal Python error: ", StartupClass::PythonStartup),
            ("unexpected private diagnostic: ", StartupClass::Other),
        ] {
            let raw = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/private/owner-secret-name payload-sensitive-sentinel\n")
            };
            let diagnostics = drain_stderr(raw.as_bytes()).await.unwrap();
            assert_eq!(diagnostics.class, expected);
            assert_eq!(diagnostics.bytes, raw.len());
            let error = required_result(None, ExitStatus::from_raw(256), diagnostics)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with("compute_result_missing exit_code=1 signal=0 stderr_class="));
            assert!(
                !error.contains("owner-secret-name")
                    && !error.contains("payload-sensitive-sentinel")
            );
            assert!(!format!("{diagnostics:?}").contains("private"));
        }
        let too_large = vec![b'x'; MAX_STREAM_BYTES + 1];
        assert!(drain_stderr(too_large.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn clean_missing_result_retains_exit_diagnostics_but_malformed_output_still_fails_fast() {
        assert!(
            collect_stdout(&b""[..], "abc", None)
                .await
                .unwrap()
                .is_none()
        );
        let error = required_result(
            None,
            ExitStatus::from_raw(9),
            StartupDiagnostics {
                class: StartupClass::None,
                bytes: 0,
            },
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "compute_result_missing exit_code=-1 signal=9 stderr_class=none stderr_bytes=0"
        );
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"not-json\n").await.unwrap();
        // The writer deliberately remains open: malformed input must not wait for
        // EOF, a final child status, or the one-second startup collection window.
        let rejected = tokio::time::timeout(
            Duration::from_millis(50),
            collect_stdout(reader, "abc", None),
        )
        .await;
        assert!(rejected.unwrap().is_err());
        drop(writer);
    }

    #[test]
    fn document_plan_requires_actual_artifact_hash_without_weight_execution() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"{\"parser_fixture_not_tokenizer_proof\":true}";
        let mut file = tempfile::NamedTempFile::new_in(root.path()).unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        file.persist(root.path().join("document-plan.json"))
            .unwrap();
        let mut report = serde_json::json!({"model_weights_loaded":false,"artifacts":[{
            "relative_path":"document-plan.json", "bytes":bytes.len(),
            "sha256":hex::encode(Sha256::digest(bytes))}]});
        check_artifacts(&report, Mode::PlanDocument, root.path()).unwrap();
        report["model_weights_loaded"] = true.into();
        assert!(check_artifacts(&report, Mode::PlanDocument, root.path()).is_err());
        report["model_weights_loaded"] = false.into();
        report["artifacts"][0]["sha256"] = "a".repeat(64).into();
        assert!(check_artifacts(&report, Mode::PlanDocument, root.path()).is_err());
    }

    #[tokio::test]
    async fn bounded_framing_rejects_missing_newlines_and_oversized_records() {
        assert!(
            bounded_line(&mut BufReader::new(&b"partial"[..]))
                .await
                .is_err()
        );
        let excessive = vec![b'a'; MAX_LINE_BYTES + 1];
        assert!(
            bounded_line(&mut BufReader::new(excessive.as_slice()))
                .await
                .is_err()
        );
        assert_eq!(
            bounded_line(&mut BufReader::new(&b"{}\n"[..]))
                .await
                .expect("line"),
            Some(b"{}".to_vec())
        );
    }

    #[tokio::test]
    async fn control_acks_require_owner_issuance_and_cannot_appear_on_legacy_stdout() {
        let controls = Controls::default();
        let ack = b"{\"version\":1,\"id\":\"abc\",\"kind\":\"progress\",\"phase\":\"paused\",\"control_sequence\":1,\"step\":0,\"elapsed_ms\":10}\n";
        assert!(collect_stdout(&ack[..], "abc", None).await.is_err());
        assert!(
            collect_stdout(&ack[..], "abc", Some(&controls))
                .await
                .is_err()
        );
        controls.issue(Action::Pause, "abc").unwrap();
        let mut stream = ack.to_vec();
        stream.extend(b"{\"version\":1,\"id\":\"abc\",\"kind\":\"result\",\"status\":\"error\"}\n");
        assert!(
            collect_stdout(stream.as_slice(), "abc", Some(&controls))
                .await
                .is_ok()
        );
        assert!(controls.issue(Action::Resume, "abc").unwrap().is_none());
        assert!(
            collect_stdout(stream.as_slice(), "abc", Some(&controls))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_second_result_cannot_override_the_first() {
        let line = "{\"version\":1,\"id\":\"abc\",\"kind\":\"result\",\"status\":\"ok\"}\n";
        let doubled = line.repeat(2);
        assert!(
            collect_stdout(doubled.as_bytes(), "abc", None)
                .await
                .is_err()
        );
        assert!(collect_stdout(line.as_bytes(), "abc", None).await.is_ok());
    }

    #[test]
    fn memory_units_and_output_symlinks_are_not_accepted_blindly() {
        assert_eq!(status_kib("VmRSS: 512 kB\n", "VmRSS:"), Some(524_288));
        assert_eq!(status_kib("VmRSS: 512 MB\n", "VmRSS:"), None);
        let root = tempfile::tempdir().expect("root");
        std::os::unix::fs::symlink("/etc", root.path().join("escape")).expect("symlink");
        assert!(output_bytes(root.path()).is_err());
    }

    #[test]
    fn child_observation_includes_children_spawned_by_other_threads() {
        // No model/network is used. Keep the spawning thread alive while inspecting
        // its real Linux children, then kill/reap the exact probe before assertions.
        let (started, pid) = std::sync::mpsc::channel();
        let (done, finish) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut child = std::process::Command::new("/usr/bin/sleep")
                .arg("10")
                .spawn()
                .expect("probe child");
            started.send(child.id()).expect("probe pid");
            let _ = finish.recv_timeout(Duration::from_secs(5));
            let _ = child.kill();
            child.wait().expect("probe reap");
        });
        let child = pid
            .recv_timeout(Duration::from_secs(5))
            .expect("probe ready");
        let observed = process_children(&Path::new("/proc").join(std::process::id().to_string()));
        let _ = done.send(());
        worker.join().expect("probe thread");
        assert!(observed.expect("all thread children").contains(&child));
    }
}
