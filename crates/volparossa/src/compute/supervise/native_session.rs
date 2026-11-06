//! A single same-owner IPC connection owns one resident native worker.
//! Per-turn files and whole-process cleanup have deliberately different receipts.

mod budget;
#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod tests;
mod worker;

pub(in crate::compute) use budget::SessionBudget;

use std::{
    fmt, fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

use crate::compute::{
    Mode, Options, WorkerRequest, native_cpu, private_conversation, private_task, resources,
    runtime_lease,
};

pub(in crate::compute) const MAX_TASK_SECONDS: u64 = 2400;
pub(in crate::compute) const MAX_IDLE_SECONDS: u64 = 300;
pub(in crate::compute) const MAX_REQUESTS: u16 = 128;

pub(in crate::compute) enum Command {
    Submit { id: String, input: Vec<u8> },
    Close,
}

pub(in crate::compute) enum Event {
    Opened,
    Result { id: String, value: Value },
}

#[derive(Debug)]
struct Failure {
    cause: anyhow::Error,
    diagnostic: super::diagnostic::Detail,
    public_bubblewrap_stage: Option<super::BubblewrapStage>,
}

impl Failure {
    // Called only after the original process join and private-root removal.
    // Keep the cause private for the existing deadline predicate; its chain is
    // deliberately not exposed through Error::source or public wire messages.
    fn after_cleanup(cause: anyhow::Error) -> Self {
        let diagnostic = super::diagnostic::native_session_detail(&cause);
        Self {
            cause,
            diagnostic,
            public_bubblewrap_stage: None,
        }
    }

    fn with_close_observation(mut self, observation: Option<worker::CloseObservation>) -> Self {
        if let Some(observation) = observation {
            self.public_bubblewrap_stage = observation.public_bubblewrap_stage;
            self.diagnostic = self.diagnostic.with_native_stdout_close(
                observation.status_before_cleanup,
                observation.stderr_class,
            );
        }
        self
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("compute_native_session_execution_failed")
    }
}

impl std::error::Error for Failure {}

pub(super) fn diagnostic(error: &anyhow::Error) -> Option<super::diagnostic::Detail> {
    error
        .downcast_ref::<Failure>()
        .map(|failure| failure.diagnostic)
}

/// Public-fixture projection only. Ordinary errors cannot assert completed cleanup.
pub(in crate::compute) fn public_fixture_failure(error: &anyhow::Error) -> Option<Value> {
    error.downcast_ref::<Failure>().and_then(|failure| {
        let detail = failure
            .diagnostic
            .with_public_bubblewrap_stage(failure.public_bubblewrap_stage);
        serde_json::to_value(detail).ok()
    })
}

// Fabricated owner result for injected-worker protocol tests only. This helper
// performs no worker execution and must never be used as runtime evidence.
#[cfg(test)]
pub(in crate::compute) fn public_fixture_test_failure(cause: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Failure::after_cleanup(cause))
}

fn cleanup_record() -> Value {
    json!({"version":1,"child_reaped":true,"private_state_removed":true})
}

/// Only this private type is constructed after both independent cleanup steps.
pub(in crate::compute) fn cleanup(error: &anyhow::Error) -> Option<Value> {
    error.downcast_ref::<Failure>().map(|_| cleanup_record())
}

pub(in crate::compute) fn execution_deadline(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Failure>().is_some_and(|failure| {
        failure
            .cause
            .downcast_ref::<super::ExecutionDeadline>()
            .is_some()
    })
}

struct PrivateRoot(Option<tempfile::TempDir>);

impl PrivateRoot {
    fn new(parent: &Path) -> Result<Self> {
        crate::compute::private_directory(parent)?;
        Ok(Self(Some(
            tempfile::Builder::new()
                .prefix("private-native-session-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?,
        )))
    }

    fn path(&self) -> &Path {
        self.0
            .as_ref()
            .expect("owned session root exists until explicit cleanup")
            .path()
    }

    fn close(mut self) -> Result<()> {
        self.0
            .take()
            .context("compute_native_session_root")?
            .close()
            .map_err(|_| anyhow::anyhow!("compute_private_storage_cleanup_failed"))
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        // Panic/cancellation cannot unlink files still mounted by an unjoined child.
        if let Some(root) = self.0.take() {
            let _ = root.keep();
        }
    }
}

fn stage(
    config: &private_task::ExecutionConfig,
    root: &Path,
    turn: u16,
    input: &[u8],
) -> Result<Options> {
    config
        .native_backend
        .validate_input(Mode::PrivateConversation, input, config.model_profile)?;
    let directory = root.join(format!("turn-{turn}"));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let dataset = directory.join("input.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&dataset)?;
    file.write_all(input)?;
    file.sync_all()?;
    let output = directory.join("output");
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    Ok(Options {
        mode: Mode::PrivateConversation,
        runtime_root: config.runtime_root.clone(),
        model_root: config.model_root.clone(),
        model_profile: config.model_profile,
        native_backend: config.native_backend.clone(),
        adapter_root: None,
        dataset,
        output,
        steps: 1,
        threads: config.threads,
        max_seconds: config.max_seconds,
        spare_capacity: true,
        execute: true,
    })
}

fn request(options: &Options, id: String) -> Result<WorkerRequest> {
    Ok(WorkerRequest {
        native_backend: options.native_backend.request_for_dataset(
            options.model_profile,
            Mode::PrivateConversation,
            &options.dataset,
        )?,
        version: 1,
        id,
        mode: Mode::PrivateConversation,
        model_profile: options.model_profile,
        model_root: "/model",
        dataset_path: "/dataset.json",
        output_root: "/output",
        adapter_root: None,
        steps: 1,
        threads: options.threads,
        max_seconds: options.max_seconds,
        owner_control: true,
        private_generation_diagnostics: tracing::enabled!(target: "volparossa::compute::private_diagnostic", tracing::Level::DEBUG),
    })
}

struct Resident {
    worker: Option<worker::Live>,
    hints: Option<native_cpu::SessionHints>,
    turn: u16,
}

impl Resident {
    #[allow(
        clippy::too_many_arguments,
        reason = "Task and per-turn identities remain explicit"
    )]
    async fn submit(
        &mut self,
        config: &private_task::ExecutionConfig,
        root: &Path,
        id: String,
        input: &[u8],
        budget: &SessionBudget,
        activity: &mut watch::Receiver<bool>,
    ) -> Result<Value> {
        budget.check()?;
        ensure!(
            self.turn < budget.maximum_requests(),
            "compute_native_session_request_bound"
        );
        let deadline = budget.turn_deadline(config.max_seconds)?;
        budget::check_execution(deadline, activity)?;
        self.turn += 1;
        let options = stage(config, root, self.turn, input)?;
        let request = request(&options, id)?;
        budget::check_execution(deadline, activity)?;
        if self.worker.is_none() {
            resources::admission(config.model_profile, true)?;
            budget::check_execution(deadline, activity)?;
            self.hints = Some(native_cpu::SessionHints::bind(
                &request.native_backend,
                &options,
            ));
            budget::check_execution(deadline, activity)?;
            self.worker = Some(worker::Live::spawn(&options, root, deadline)?);
        }
        let report = self
            .worker
            .as_mut()
            .context("compute_native_session_worker")?
            .turn(&request, &options, self.turn, deadline, activity)
            .await?;
        private_task::validate_native_session_report(&report, input, config.model_profile)?;
        // The worker has acknowledged its no-more-IO turn boundary, not exited.
        let turn_root = options
            .dataset
            .parent()
            .context("compute_native_session_turn_root")?;
        fs::remove_dir_all(turn_root)
            .map_err(|_| anyhow::anyhow!("compute_private_storage_cleanup_failed"))?;
        let mut value = private_conversation::summary(&report, config.model_profile);
        value["version"] = json!(2);
        value["cleanup"] = json!({"version":2,"request_files_removed":true,
            "session_closed":false,"session_private_state_retained":true});
        Ok(value)
    }
}

async fn serve(
    config: &private_task::ExecutionConfig,
    root: &Path,
    resident: &mut Resident,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<Event>,
    activity: &mut watch::Receiver<bool>,
    budget: &SessionBudget,
) -> Result<()> {
    budget.check()?;
    let task_deadline = budget.deadline();
    let mut idle_deadline = Instant::now() + Duration::from_secs(MAX_IDLE_SECONDS);
    let mut ticks = tokio::time::interval(Duration::from_millis(250));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    budget::send_event(events, Event::Opened, task_deadline, activity).await?;
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(task_deadline.min(idle_deadline)) => return Ok(()),
            changed = activity.changed() => {
                ensure!(changed.is_ok() && *activity.borrow(), "compute_owner_busy");
            },
            command = commands.recv() => match command {
                Some(Command::Submit { id, input }) => {
                    let value = resident.submit(config, root, id.clone(), &input, budget, activity).await?;
                    budget::send_event(events, Event::Result { id, value }, task_deadline, activity).await?;
                    idle_deadline = Instant::now() + Duration::from_secs(MAX_IDLE_SECONDS);
                },
                Some(Command::Close) | None => return Ok(()),
            },
            _ = ticks.tick() => if let Some(worker) = resident.worker.as_mut() {
                worker.idle(root, config.model_profile)?;
            },
        }
    }
}

pub(in crate::compute) async fn run(
    config: Arc<private_task::ExecutionConfig>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    activity: watch::Receiver<bool>,
) -> Result<Value> {
    let budget = SessionBudget::new(
        Instant::now() + Duration::from_secs(MAX_TASK_SECONDS),
        MAX_REQUESTS,
    )?;
    run_bounded(config, commands, events, activity, budget).await
}

/// Execute under an already anchored budget, not an admission or attestation permit.
/// Configuration, preparation and all turns consume the same original deadline.
/// Cleanup retains its separate existing ceiling and must finish before its receipt.
pub(in crate::compute) async fn run_bounded(
    config: Arc<private_task::ExecutionConfig>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    activity: watch::Receiver<bool>,
    budget: SessionBudget,
) -> Result<Value> {
    budget.check()?;
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    config.validate()?;
    budget.check()?;
    ensure!(
        config
            .native_backend
            .supports_native_session(config.model_profile),
        "compute_native_session_unsupported"
    );
    budget.check()?;
    let _lease = runtime_lease(&config.runtime_root)?;
    budget.check()?;
    let root = PrivateRoot::new(&config.work_parent)?;
    run_owned(&config, root, commands, events, activity, &budget).await
}

async fn run_owned(
    config: &private_task::ExecutionConfig,
    root: PrivateRoot,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    mut activity: watch::Receiver<bool>,
    budget: &SessionBudget,
) -> Result<Value> {
    let mut resident = Resident {
        worker: None,
        hints: None,
        turn: 0,
    };
    let result = serve(
        config,
        root.path(),
        &mut resident,
        &mut commands,
        &events,
        &mut activity,
        budget,
    )
    .await;
    let observation = if let Some(worker) = resident.worker.take() {
        // This join is mandatory even when the client disconnects or a validator fails.
        Some(worker.close().await?)
    } else {
        None
    };
    root.close()?;
    let result = result.map(|()| cleanup_record()).map_err(|cause| {
        anyhow::Error::new(Failure::after_cleanup(cause).with_close_observation(observation))
    });
    if let Some(hints) = resident.hints.take() {
        hints.finish(&result);
    }
    result
}
