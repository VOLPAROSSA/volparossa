//! Owner-controlled lifecycle and bounded observations, outside the model worker.

use std::{collections::BTreeSet, fs::File, io::Read, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Child,
    sync::watch,
};

use super::{MAX_LINE_BYTES, MAX_STREAM_BYTES, Mode, Options, WorkerRequest, check_message};

pub(super) const MAX_RSS_BYTES: u64 = 3 * 1024 * 1024 * 1024;
pub(super) const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MIN_FREE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

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
    let result = {
        let io = async {
            stdin
                .write_all(&input)
                .await
                .context("compute_request_write")?;
            drop(stdin);
            let (result, (), status) = tokio::try_join!(
                collect_stdout(stdout, &request.id),
                drain_stderr(stderr),
                async { child.wait().await.context("compute_wait") }
            )?;
            check_result(&result, request)?;
            ensure!(status.success(), "compute_worker_exit");
            check_artifacts(&result, request.mode, &options.output)?;
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
                    let observation = observe(pid, &options.output);
                    match observation {
                        Ok(rss) => peak_rss = peak_rss.max(rss),
                        Err(error) => break Err(error),
                    }
                }
            }
        }
    };
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
        "deadline_seconds": options.max_seconds,
        "child_reaped": true,
        "distributed_execution_claimed": false,
        "private_training_claimed": false
    });
    Ok(result)
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
        Mode::Infer => ensure!(updates == Some(0), "compute_unrequested_training"),
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

async fn collect_stdout(stream: impl AsyncRead + Unpin, id: &str) -> Result<Value> {
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
            result = Some(value);
        } else {
            // Only the validated phase label is logged, never raw backend text or data.
            eprintln!(
                "compute phase={}",
                value["phase"].as_str().context("compute_phase")?
            );
        }
    }
    result.context("compute_result_missing")
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

async fn drain_stderr(mut stream: impl AsyncRead + Unpin) -> Result<()> {
    let mut buffer = [0_u8; 4096];
    let mut total = 0;
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .context("compute_stderr_read")?;
        if length == 0 {
            return Ok(());
        }
        total += length;
        // Exceptions may contain input text or filesystem names. Do not retain/echo them.
        ensure!(total <= MAX_STREAM_BYTES, "compute_stderr_size");
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

fn observe(pid: u32, output: &Path) -> Result<u64> {
    headroom()?;
    let mut pending = vec![pid];
    let mut visited = BTreeSet::new();
    let mut total = 0_u64;
    while let Some(current) = pending.pop() {
        ensure!(
            visited.len() < 64 && visited.insert(current),
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
        let descendants = match system_text(&root.join(format!("task/{current}/children"))) {
            Ok(value) => value,
            Err(_) if !root.exists() => continue,
            Err(error) => return Err(error),
        };
        for child in descendants.split_whitespace() {
            ensure!(pending.len() < 64, "compute_process_bound");
            pending.push(
                child
                    .parse::<u32>()
                    .context("compute_process_observation")?,
            );
        }
    }
    ensure!(
        output_bytes(output)? <= MAX_OUTPUT_BYTES,
        "compute_storage_budget"
    );
    Ok(total)
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
    async fn a_second_result_cannot_override_the_first() {
        let line = "{\"version\":1,\"id\":\"abc\",\"kind\":\"result\",\"status\":\"ok\"}\n";
        let doubled = line.repeat(2);
        assert!(collect_stdout(doubled.as_bytes(), "abc").await.is_err());
        assert!(collect_stdout(line.as_bytes(), "abc").await.is_ok());
    }

    #[test]
    fn memory_units_and_output_symlinks_are_not_accepted_blindly() {
        assert_eq!(status_kib("VmRSS: 512 kB\n", "VmRSS:"), Some(524_288));
        assert_eq!(status_kib("VmRSS: 512 MB\n", "VmRSS:"), None);
        let root = tempfile::tempdir().expect("root");
        std::os::unix::fs::symlink("/etc", root.path().join("escape")).expect("symlink");
        assert!(output_bytes(root.path()).is_err());
    }
}
