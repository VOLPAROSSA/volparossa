//! Persistent pipe supervision. A turn result is not a process-exit receipt.

use std::{io::Read as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{Child, ChildStdin, ChildStdout},
    sync::watch,
    task::JoinHandle,
    time::Instant,
};

use crate::compute::{
    MAX_LINE_BYTES, MAX_STREAM_BYTES, ModelProfile, Options, WorkerRequest, check_message,
    owner_control::{Action, Controls},
    private_conversation::decode_worker_message,
    resources, sandbox,
    spare_capacity::{Budget, Decision},
    supervise::{self as supervisor, lifetime::OwnedLifetimes},
};

struct Frames {
    stream: BufReader<ChildStdout>,
    pending: Vec<u8>,
    bytes: usize,
}

impl Frames {
    async fn next(&mut self) -> Result<Value> {
        // Partial bytes belong to this reader, so select cancellation cannot
        // silently lose a prefix or splice two differently correlated records.
        loop {
            let available = self.stream.fill_buf().await?;
            ensure!(
                !available.is_empty(),
                "compute_native_session_stdout_closed"
            );
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.unwrap_or(available.len());
            ensure!(
                self.pending.len() + count <= MAX_LINE_BYTES,
                "compute_worker_line_size"
            );
            self.pending.extend_from_slice(&available[..count]);
            self.stream.consume(count + usize::from(newline.is_some()));
            if newline.is_some() {
                self.bytes = self
                    .bytes
                    .checked_add(self.pending.len() + 1)
                    .context("compute_stdout_size")?;
                ensure!(self.bytes <= MAX_STREAM_BYTES, "compute_stdout_size");
                let raw = std::mem::take(&mut self.pending);
                return decode_worker_message(&raw)
                    .map_err(|_| anyhow::anyhow!("compute_worker_invalid_json"));
            }
        }
    }
}

pub(super) struct Live {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Frames,
    stderr: Option<JoinHandle<Result<supervisor::StartupDiagnostics>>>,
    lifetimes: Option<Result<OwnedLifetimes>>,
    pid: u32,
    budget: Budget,
    peak_rss: u64,
    clock_ticks: u64,
}

fn clock_ticks() -> Result<u64> {
    // Linux's own bounded auxiliary vector, not a subprocess or guessed USER_HZ.
    ensure!(size_of::<usize>() == 8, "compute_native_session_cpu_clock");
    let mut bytes = Vec::new();
    std::fs::File::open("/proc/self/auxv")?
        .take(8193)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8192 && bytes.len() % 16 == 0,
        "compute_native_session_cpu_clock"
    );
    let mut found = None;
    for pair in bytes.chunks_exact(16) {
        let key = u64::from_ne_bytes(pair[..8].try_into()?);
        let value = u64::from_ne_bytes(pair[8..].try_into()?);
        if key == libc::AT_CLKTCK {
            ensure!(
                found.is_none() && (1..=1_000_000).contains(&value),
                "compute_native_session_cpu_clock"
            );
            found = Some(value);
        }
    }
    found.context("compute_native_session_cpu_clock")
}

impl Live {
    pub(super) fn spawn(options: &Options, root: &Path, deadline: Instant) -> Result<Self> {
        super::budget::check_deadline(deadline)?;
        let ticks = clock_ticks()?;
        let mut command = sandbox::native_session_command(options, root);
        super::budget::check_deadline(deadline)?;
        let child = command.spawn().context("compute_sandbox_spawn")?;
        Ok(Self::own(child, ticks))
    }

    fn own(mut child: Child, ticks: u64) -> Self {
        // The fixed builder configures all three pipes. A panic still keeps the
        // session tree and quarantines its slot; it cannot fabricate cleanup.
        let pid = child.id().expect("newly spawned owned worker has an id");
        let stdin = child.stdin.take().expect("fixed piped stdin");
        let stdout = child.stdout.take().expect("fixed piped stdout");
        let stderr = child.stderr.take().expect("fixed piped stderr");
        Self {
            child,
            stdin: Some(stdin),
            stdout: Frames {
                stream: BufReader::new(stdout),
                pending: Vec::new(),
                bytes: 0,
            },
            stderr: Some(tokio::spawn(supervisor::drain_stderr(stderr))),
            lifetimes: Some(OwnedLifetimes::capture(pid)),
            pid,
            budget: Budget::new(),
            peak_rss: 0,
            clock_ticks: ticks,
        }
    }

    fn tracker(&mut self) -> Result<&mut OwnedLifetimes> {
        self.lifetimes
            .as_mut()
            .context("compute_private_process_observation")?
            .as_mut()
            .map_err(|_| anyhow::anyhow!("compute_private_process_observation"))
    }

    pub(super) fn idle(&mut self, root: &Path, profile: ModelProfile) -> Result<()> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "compute_native_session_child_exited"
        );
        self.tracker()?.refresh()?;
        self.peak_rss = self.peak_rss.max(supervisor::observe(
            self.pid,
            root,
            false,
            resources::limits(profile).observed_rss,
        )?);
        ensure!(
            self.budget.sample() != Decision::Cancel,
            "{}",
            self.budget.cancellation_code()
        );
        ensure!(
            !self.stderr.as_ref().is_some_and(JoinHandle::is_finished),
            "compute_native_session_stderr_closed"
        );
        Ok(())
    }

    pub(super) async fn turn(
        &mut self,
        request: &WorkerRequest,
        options: &Options,
        turn: u16,
        deadline: Instant,
        activity: &mut watch::Receiver<bool>,
    ) -> Result<Value> {
        ensure!(
            *activity.borrow() && Instant::now() < deadline,
            "compute_owner_busy"
        );
        self.tracker()?.refresh()?;
        let before = self.tracker()?.cpu_ticks()?;
        let controls = Controls::default();
        let progress = supervisor::diagnostic::Progress::with_generation(
            request.private_generation_diagnostics,
        );
        let mut value = serde_json::to_value(request)?;
        value["dataset_path"] = json!(format!("/session/turn-{turn}/input.json"));
        value["output_root"] = json!(format!("/session/turn-{turn}/output"));
        value["native_session"] = json!({"version":1,"turn":turn});
        let mut bytes = serde_json::to_vec(&value)?;
        ensure!(bytes.len() < 65536, "compute_request_limit");
        bytes.push(b'\n');
        bytes.extend(
            controls
                .issue(supervisor::pressure_action(&mut self.budget)?, &request.id)?
                .context("compute_initial_control")?,
        );
        self.stdout.bytes = 0;
        let result = self
            .turn_inner(
                request, options, deadline, activity, before, &controls, &progress, &bytes,
            )
            .await;
        if result.is_err() {
            supervisor::diagnostic::terminal_state(
                &progress,
                &self.budget,
                Some(&controls),
                self.peak_rss,
            );
        }
        result
    }

    async fn write(&mut self, bytes: &[u8], deadline: Instant) -> Result<()> {
        tokio::time::timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(1)),
            self.stdin
                .as_mut()
                .context("compute_control_stdin")?
                .write_all(bytes),
        )
        .await
        .context("compute_control_write_deadline")??;
        Ok(())
    }

    fn tick(&mut self, options: &Options, before: u64) -> Result<()> {
        let root = options
            .dataset
            .parent()
            .and_then(Path::parent)
            .context("compute_native_session_root")?;
        self.idle(root, options.model_profile)?;
        let consumed = self
            .tracker()?
            .cpu_ticks()?
            .checked_sub(before)
            .context("compute_native_session_cpu_backwards")?;
        let bound = u64::from(options.max_seconds) * u64::from(options.threads) * self.clock_ticks;
        ensure!(consumed < bound, "compute_native_session_cpu_budget");
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "One original turn deadline surrounds controls, result and quiescence before file removal"
    )]
    async fn turn_inner(
        &mut self,
        request: &WorkerRequest,
        options: &Options,
        deadline: Instant,
        activity: &mut watch::Receiver<bool>,
        before: u64,
        controls: &Controls,
        progress: &supervisor::diagnostic::Progress,
        input: &[u8],
    ) -> Result<Value> {
        self.write(input, deadline).await?;
        let mut ticks = tokio::time::interval(Duration::from_millis(250));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut result = None;
        loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => return Err(supervisor::ExecutionDeadline.into()),
                changed = activity.changed() => {
                    ensure!(changed.is_ok() && *activity.borrow(), "compute_owner_busy");
                },
                record = self.stdout.next() => {
                    let record = record?;
                    if record == json!({"version":1,"id":request.id,"kind":"native_turn_idle"}) {
                        ensure!(result.is_some(), "compute_native_session_unrequested_idle");
                        break;
                    }
                    let bytes = serde_json::to_vec(&record)?;
                    let value = check_message(&bytes, &request.id)?;
                    if value["kind"] == "result" {
                        ensure!(result.is_none(), "compute_output_after_result");
                        controls.terminal()?;
                        if let Some(error) = supervisor::diagnostic::native_worker_failure(&value, &request.id) {
                            // A correlated worker error is not proof of its exit,
                            // cleanup, adapter invalidity or a retry entitlement.
                            return Err(error);
                        }
                        // There is no invented successful exit status here.
                        supervisor::check_successful_result(&value, request)?;
                        controls.check_report(&value)?;
                        supervisor::check_artifacts(&value, options.mode, &options.output)?;
                        let disk = crate::compute::read_file(&options.output.join("report.json"), MAX_LINE_BYTES as u64)?;
                        let persisted = decode_worker_message(&disk).map_err(|_| anyhow::anyhow!("compute_native_session_report"))?;
                        ensure!(persisted == value, "compute_native_session_report");
                        result = Some(value);
                        let mut finish = serde_json::to_vec(&json!({"version":1,"id":request.id,"kind":"native_turn_finish"}))?;
                        finish.push(b'\n');
                        self.write(&finish, deadline).await?;
                    } else if matches!(value["phase"].as_str(), Some("paused" | "resumed")) {
                        controls.acknowledge(&value)?;
                    } else {
                        ensure!(result.is_none() && value.get("control_sequence").is_none(), "compute_output_after_result");
                        progress.observe(&value)?;
                    }
                },
                _ = ticks.tick() => {
                    self.tick(options, before)?;
                    if result.is_none() {
                        // tick() already sampled the unchanged capacity guard.
                        let action = match self.budget.current() {
                            Decision::Run => Action::Resume,
                            Decision::Pause => Action::Pause,
                            Decision::Cancel => anyhow::bail!("{}", self.budget.cancellation_code()),
                        };
                        if let Some(record) = controls.issue(action, &request.id)? {
                            self.write(&record, deadline).await?;
                        }
                    }
                },
            }
        }
        self.tick(options, before)?;
        let mut report = result.context("compute_result_missing")?;
        let mut observed =
            supervisor::supervisor_report(options, self.peak_rss, Some(controls), &self.budget);
        observed["child_reaped"] = json!(false);
        observed["native_session_version"] = json!(1);
        report["supervisor"] = observed;
        Ok(report)
    }

    pub(super) async fn close(mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        if let Some(Ok(tracker)) = self.lifetimes.as_mut() {
            let _ = tracker.refresh();
        }
        drop(self.stdin.take());
        // The normal EOF path lets native destructors run; cancellation still
        // has the exact original three-second cleanup ceiling and owned child.
        if tokio::time::timeout(Duration::from_millis(250), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.start_kill();
        }
        let joined = tokio::time::timeout_at(deadline, self.child.wait()).await;
        if !matches!(joined, Ok(Ok(_))) {
            return Err(crate::compute::private_task::CleanupUnconfirmed.into());
        }
        let lifetime = self
            .lifetimes
            .take()
            .context("compute_private_process_observation")?;
        let closed = match lifetime {
            Ok(tracker) => tracker.wait_closed(deadline).await.is_ok(),
            Err(_) => false,
        };
        let mut stderr = self
            .stderr
            .take()
            .context("compute_native_session_stderr")?;
        let drained = if let Ok(Ok(Ok(_))) = tokio::time::timeout_at(deadline, &mut stderr).await {
            true
        } else {
            stderr.abort();
            let _ = stderr.await;
            false
        };
        ensure!(
            closed && drained,
            crate::compute::private_task::CleanupUnconfirmed
        );
        Ok(())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(stderr) = self.stderr.take() {
            stderr.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;

    fn child(script: &str) -> Child {
        tokio::process::Command::new("/usr/bin/python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[tokio::test]
    async fn partial_frame_survives_select_cancellation_without_splicing() {
        let mut process = child(
            "import sys,time;sys.stdout.write('{\"value\":');sys.stdout.flush();time.sleep(.1);print('1}')",
        );
        let mut frames = Frames {
            stream: BufReader::new(process.stdout.take().unwrap()),
            pending: Vec::new(),
            bytes: 0,
        };
        let first = tokio::time::timeout(Duration::from_millis(40), frames.next()).await;
        assert!(first.is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), frames.next())
                .await
                .unwrap()
                .unwrap(),
            json!({"value":1})
        );
        assert!(process.wait().await.unwrap().success());
    }

    #[tokio::test]
    async fn exact_owned_inert_child_is_joined_before_cleanup_returns() {
        let process = child("import sys;sys.stdin.buffer.read()");
        let pid = process.id().unwrap();
        let live = Live::own(process, clock_ticks().unwrap());
        let original = live
            .lifetimes
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .cpu_ticks()
            .unwrap();
        assert!(original < 1_000_000);
        live.close().await.unwrap();
        assert!(!Path::new("/proc").join(pid.to_string()).exists());
    }

    #[tokio::test]
    async fn oversized_or_uncorrelated_data_never_becomes_a_turn_boundary() {
        let mut process = child("print('x'*17000)");
        let mut frames = Frames {
            stream: BufReader::new(process.stdout.take().unwrap()),
            pending: Vec::new(),
            bytes: 0,
        };
        assert!(frames.next().await.is_err());
        let _ = process.kill().await;
        let _ = process.wait().await;
    }

    #[tokio::test]
    async fn duplicate_keys_are_rejected_before_any_value_round_trip() {
        let mut process = child("print('{\"version\":0,\"version\":1}')");
        let mut frames = Frames {
            stream: BufReader::new(process.stdout.take().unwrap()),
            pending: Vec::new(),
            bytes: 0,
        };
        assert!(frames.next().await.is_err());
        assert!(process.wait().await.unwrap().success());
    }
}
