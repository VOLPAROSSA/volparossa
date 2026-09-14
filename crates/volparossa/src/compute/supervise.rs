//! Owner-controlled lifecycle and bounded observations, outside the model worker.

use std::{
    collections::BTreeSet, fs::File, io::Read, os::unix::process::ExitStatusExt, path::Path,
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
            let action = pressure_action(budget.sample())?;
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
            check_result(&result, request)?;
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
                        let action = pressure_action(budget.sample())?;
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
        // Killing the exact live bwrap parent kills its sandbox child (die-with-parent).
        // PID namespace teardown kills/reaps descendants; no host process-group scan.
        let _ = child.start_kill();
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .context("compute_reap_deadline")?
            .context("compute_reap")?;
    }
    let mut result = result?;
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
        "pause_extends_deadline": false,
        "deadline_seconds": options.max_seconds,
        "child_reaped": true,
        "distributed_execution_claimed": false,
        "private_training_claimed": false
    });
    Ok(result)
}

fn pressure_action(decision: Decision) -> Result<Action> {
    match decision {
        Decision::Run => Ok(Action::Resume),
        Decision::Pause => Ok(Action::Pause),
        Decision::Cancel => bail!("compute_memory_pressure"),
    }
}

fn check_result(value: &Value, request: &WorkerRequest) -> Result<()> {
    if value.get("status").and_then(Value::as_str) == Some("error") {
        let code = value
            .get("code")
            .and_then(Value::as_str)
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            })
            .unwrap_or("UNKNOWN_FIXED_FAILURE");
        bail!("compute_backend_failed: {code}");
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
        Mode::Infer | Mode::PlanDocument => {
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
    Ok(())
}

fn check_artifacts(value: &Value, mode: Mode, output: &Path) -> Result<()> {
    let artifacts = value
        .get("artifacts")
        .and_then(Value::as_array)
        .context("compute_artifacts")?;
    if mode == Mode::Infer {
        ensure!(artifacts.is_empty(), "compute_inference_artifacts");
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
