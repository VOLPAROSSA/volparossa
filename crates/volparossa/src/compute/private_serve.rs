//! Owner-authorized private local inference, separate from public/peer compute.
//! See `private_serve/WIRE.md` for the versioned local-only JSON exception.

#[cfg(test)]
mod tests;
mod wire;

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

use super::{ModelProfile, private_directory, private_task};

const MAX_CONNECTIONS: usize = 8;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Existing owner-provisioned pinned Python runtime; never downloaded by serving.
    #[arg(long)]
    runtime_root: PathBuf,
    /// Existing fixed model assets. Incoming requests cannot change the model.
    #[arg(long)]
    model_root: PathBuf,
    /// Existing owned mode-0700 parent for disposable private task files.
    #[arg(long)]
    work_parent: PathBuf,
    #[arg(long, default_value_t = ModelProfile::Smol360)]
    model_profile: ModelProfile,
    #[command(flatten)]
    native_backend: super::native_cpu::Options,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// New mode-0600 socket below an existing same-owner mode-0700 directory.
    #[arg(long)]
    socket: PathBuf,
    /// Start the foreground service; without this flag print only a scope preview.
    #[arg(long)]
    execute: bool,
}

impl Options {
    fn config(&self) -> private_task::ExecutionConfig {
        private_task::ExecutionConfig {
            runtime_root: self.runtime_root.clone(),
            model_root: self.model_root.clone(),
            work_parent: self.work_parent.clone(),
            model_profile: self.model_profile,
            native_backend: self.native_backend.clone(),
            threads: self.threads,
            max_seconds: self.max_seconds,
        }
    }

    fn validate(&self) -> Result<()> {
        self.config().validate()?;
        ensure!(self.socket.is_absolute(), "private_ipc_socket_absolute");
        private_directory(self.socket.parent().context("private_ipc_socket_parent")?)?;
        ensure!(
            fs::symlink_metadata(&self.socket)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "private_ipc_socket_exists"
        );
        for root in [&self.runtime_root, &self.model_root] {
            ensure!(
                !self.work_parent.starts_with(root) && !root.starts_with(&self.work_parent),
                "private_ipc_roots_overlap"
            );
        }
        ensure!(
            self.runtime_root.join("bin/python3").is_file(),
            "compute_runtime_missing"
        );
        let model_present = self.model_profile.sharded_weight_files().map_or_else(
            || self.model_root.join("model.safetensors").is_file(),
            |files| {
                files
                    .iter()
                    .all(|file| self.model_root.join(file.name).is_file())
            },
        );
        ensure!(model_present, "compute_model_missing");
        Ok(())
    }
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

/// The job owns the permit until the shared backend has returned and removed its
/// private staging files. Panic/abort/unconfirmed cleanup quarantines admission.
struct ExecutionSlot {
    _permit: OwnedSemaphorePermit,
    gate: Arc<Semaphore>,
    cleanup_confirmed: bool,
}

impl ExecutionSlot {
    fn admit(gate: &Arc<Semaphore>) -> Option<Self> {
        Some(Self {
            _permit: gate.clone().try_acquire_owned().ok()?,
            gate: gate.clone(),
            cleanup_confirmed: false,
        })
    }

    fn finish(&mut self, result: &Result<Value>) {
        if result
            .as_ref()
            .is_err_and(|error| error.to_string() == "compute_private_storage_cleanup_failed")
        {
            super::supervise::diagnostic::event(
                "storage",
                "compute_private_storage_cleanup_failed",
            );
        }
        self.cleanup_confirmed = !result.as_ref().is_err_and(|error| {
            error
                .downcast_ref::<private_task::CleanupUnconfirmed>()
                .is_some()
                || error.to_string() == "compute_private_storage_cleanup_failed"
        });
    }
}

impl Drop for ExecutionSlot {
    fn drop(&mut self) {
        if !self.cleanup_confirmed {
            self.gate.close();
        }
    }
}

struct Active {
    id: String,
    activity: watch::Sender<bool>,
    execution: Option<JoinHandle<Result<Value>>>,
    cancelled: bool,
    budget_error: bool,
}

impl Active {
    fn start(
        id: String,
        config: Arc<private_task::ExecutionConfig>,
        input: Vec<u8>,
        slot: ExecutionSlot,
    ) -> Self {
        Self::start_mode(id, config, input, slot, super::Mode::PrivateInfer)
    }

    fn start_mode(
        id: String,
        config: Arc<private_task::ExecutionConfig>,
        input: Vec<u8>,
        mut slot: ExecutionSlot,
        mode: super::Mode,
    ) -> Self {
        let (activity, signal) = watch::channel(true);
        let execution = tokio::spawn(async move {
            let result = private_task::execute_mode(&config, input, signal, mode).await;
            finish_execution(&mut slot, result)
        });
        Self {
            id,
            activity,
            execution: Some(execution),
            cancelled: false,
            budget_error: false,
        }
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        let _ = self.activity.send(false);
    }

    async fn reap(&mut self) -> Result<Value> {
        match self
            .execution
            .take()
            .expect("active task owns an execution")
            .await
        {
            Ok(result) => result,
            Err(_) => Err(private_task::CleanupUnconfirmed.into()),
        }
    }
}

fn finish_execution(slot: &mut ExecutionSlot, result: Result<Value>) -> Result<Value> {
    slot.finish(&result);
    if let Err(error) = &result {
        // Cover failures before worker supervision and after report validation.
        // The existing opt-in target emits only closed facts, never error text.
        // This observation grants neither cleanup nor a different wire response.
        super::supervise::diagnostic::failure("task", error);
    }
    result
}

impl Drop for Active {
    fn drop(&mut self) {
        // Dropping a connection never aborts/detaches ownership of the worker slot:
        // the executing future owns it and cooperatively reaps before releasing it.
        let _ = self.activity.send(false);
    }
}

fn capabilities(config: &private_task::ExecutionConfig, gate: &Semaphore) -> Value {
    json!({
        "visibility":"private_local", "local_only":true,
        "model_profile":config.model_profile, "max_question_bytes":512, "max_context_bytes":4096,
        "max_request_bytes":wire::MAX_REQUEST_BYTES, "max_response_bytes":wire::MAX_RESPONSE_BYTES,
        "execution_slots":1, "max_connections":MAX_CONNECTIONS, "max_seconds":config.max_seconds,
        "network_access":false, "public_cache":false, "training":false, "cloud_fallback":false,
        "model_execution_proven":false, "quarantined":gate.is_closed(),
    })
}

fn capabilities_response(
    id: &str,
    config: &private_task::ExecutionConfig,
    gate: &Semaphore,
) -> Value {
    let mut response = wire::response(id, "capabilities");
    response["capabilities"] = capabilities(config, gate);
    if config.native_backend.enabled() {
        response["capabilities"]["qa_supported"] = false.into();
        response["capabilities"]["inference_backend"] = super::native_cpu::KIND.into();
    }
    response
}

enum Incoming {
    Request(wire::Request),
    Invalid,
}

#[derive(Clone, Default)]
struct Handshakes {
    qa: bool,
    conversation: bool,
    generation_policy: Option<u8>,
    execution_error: Option<u8>,
    output_constraint: Option<u8>,
    native_session: Option<u8>,
}

fn conversation_capabilities(
    config: &private_task::ExecutionConfig,
    gate: &Semaphore,
    handshakes: &Handshakes,
) -> Value {
    let mut caps = super::private_conversation::capabilities(config.model_profile);
    caps["execution_slots"] = 1.into();
    caps["max_seconds"] = config.max_seconds.into();
    caps["max_request_bytes"] =
        super::private_conversation::request_frame(config.model_profile).into();
    caps["max_response_bytes"] = wire::MAX_RESPONSE_BYTES.into();
    caps["quarantined"] = gate.is_closed().into();
    if handshakes.execution_error == Some(1) {
        caps["execution_error_version"] = 1.into();
    }
    if handshakes.generation_policy == Some(1) {
        caps["generation_policy_version"] = 1.into();
        caps["generation_policies"] = if config.model_profile.is_native_conversation() {
            json!(["greedy_v1"])
        } else {
            json!([])
        };
    }
    if config.native_backend.enabled() {
        caps["inference_backend"] = super::native_cpu::KIND.into();
        caps["required_generation_policy"] = "greedy_v1".into();
    }
    if handshakes.output_constraint == Some(1) {
        caps["output_constraint_version"] = 1.into();
        caps["output_constraints"] = if config
            .native_backend
            .supports_output_constraint(config.model_profile)
        {
            json!([super::native_cpu::OutputConstraint::QwenTaggedToolJsonV1])
        } else {
            json!([])
        };
    }
    if handshakes.native_session == Some(1) {
        caps["native_session_version"] = 1.into();
        caps["native_session"] = if config
            .native_backend
            .supports_native_session(config.model_profile)
        {
            json!({"version":1,"max_task_seconds":2400,"max_idle_seconds":300,
                "max_requests":128})
        } else {
            Value::Null
        };
    }
    caps
}

fn respond(
    request: wire::Request,
    config: &Arc<private_task::ExecutionConfig>,
    gate: &Arc<Semaphore>,
    active: &mut Option<Active>,
    handshakes: &mut Handshakes,
) -> Value {
    match request.operation {
        wire::Operation::Capabilities {} => {
            handshakes.qa = true;
            capabilities_response(&request.id, config, gate)
        }
        wire::Operation::ConversationCapabilities {
            generation_policy_version,
            execution_error_version,
            output_constraint_version,
            native_session_version,
        } => {
            handshakes.conversation = true;
            handshakes.generation_policy = generation_policy_version;
            handshakes.execution_error = execution_error_version;
            handshakes.output_constraint = output_constraint_version;
            handshakes.native_session = native_session_version;
            let mut response = wire::response(&request.id, "conversation_capabilities");
            response["capabilities"] = conversation_capabilities(config, gate, handshakes);
            response
        }
        wire::Operation::SubmitConversation { conversation } => {
            if !handshakes.conversation
                || (conversation.requires_generation_policy_handshake()
                    && handshakes.generation_policy != Some(1))
                || (conversation.output_constraint().is_some()
                    && handshakes.output_constraint != Some(1))
            {
                wire::error(Some(&request.id), "handshake_required")
            } else if gate.is_closed() {
                wire::error(Some(&request.id), "cleanup_unconfirmed")
            } else if active.is_some() {
                wire::error(Some(&request.id), "busy")
            } else if (conversation.output_constraint().is_some()
                && !config
                    .native_backend
                    .supports_output_constraint(config.model_profile))
                || (config.native_backend.enabled()
                    && !conversation.requires_generation_policy_handshake())
            {
                wire::error(Some(&request.id), "invalid_request")
            } else if let Some(slot) = ExecutionSlot::admit(gate) {
                let input = conversation
                    .bytes_profile(config.model_profile)
                    .expect("validated conversation serializes");
                let mut task = Active::start_mode(
                    request.id.clone(),
                    config.clone(),
                    input,
                    slot,
                    super::Mode::PrivateConversation,
                );
                // Snapshot at admission: later capability requests cannot change
                // the error vocabulary of work already entrusted to the service.
                task.budget_error = handshakes.execution_error == Some(1);
                *active = Some(task);
                wire::response(&request.id, "admitted")
            } else {
                wire::error(Some(&request.id), "busy")
            }
        }
        wire::Operation::Submit { question, context } => {
            if !handshakes.qa {
                wire::error(Some(&request.id), "handshake_required")
            } else if config.native_backend.enabled() {
                wire::error(Some(&request.id), "invalid_request")
            } else if gate.is_closed() {
                wire::error(Some(&request.id), "cleanup_unconfirmed")
            } else if active.is_some() {
                wire::error(Some(&request.id), "busy")
            } else if let Some(slot) = ExecutionSlot::admit(gate) {
                let input =
                    wire::input_bytes(&question, &context).expect("bounded strings serialize");
                *active = Some(Active::start(
                    request.id.clone(),
                    config.clone(),
                    input,
                    slot,
                ));
                wire::response(&request.id, "admitted")
            } else {
                wire::error(Some(&request.id), "busy")
            }
        }
        wire::Operation::Cancel { task_id } => {
            if let Some(task) = active.as_mut().filter(|task| task.id == task_id) {
                task.cancel();
                let mut response = wire::response(&request.id, "cancel_requested");
                response["task_id"] = task_id.into();
                response
            } else {
                wire::error(Some(&request.id), "no_such_task")
            }
        }
        wire::Operation::OpenNativeSession {} | wire::Operation::CloseNativeSession {} => {
            wire::error(Some(&request.id), "invalid_request")
        }
    }
}

fn terminal_response(
    task: &Active,
    result: std::result::Result<Result<Value>, tokio::task::JoinError>,
    gate: &Semaphore,
) -> Value {
    if gate.is_closed() {
        return wire::error(Some(&task.id), "cleanup_unconfirmed");
    }
    if task.cancelled {
        return wire::error(Some(&task.id), "cancelled");
    }
    match result {
        Ok(Ok(answer)) => {
            let mut response = wire::response(&task.id, "result");
            response["result"] = answer;
            response
        }
        Ok(Err(error)) if task.budget_error && execution_budget_exceeded(&error) => {
            wire::error(Some(&task.id), "execution_budget_exceeded")
        }
        _ => wire::error(Some(&task.id), "execution_failed"),
    }
}

fn execution_budget_exceeded(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<super::supervise::ExecutionDeadline>()
        .is_some()
        || error
            .downcast_ref::<super::supervise::WorkerFailure>()
            .is_some_and(|failure| failure.code() == "JOB_DEADLINE_EXCEEDED")
}

/// This lane is owned by one authenticated Unix connection, never by a UID or
/// a prompt-cache key. Its slot is released only after the entire session joins.
struct NativeSession {
    open_id: String,
    handshakes: Handshakes,
    commands: mpsc::Sender<super::supervise::native_session::Command>,
    events: mpsc::Receiver<super::supervise::native_session::Event>,
    activity: watch::Sender<bool>,
    execution: Option<JoinHandle<Result<Value>>>,
    opened: bool,
    pending: Option<String>,
    close_id: Option<String>,
    requests: usize,
    cancelled: bool,
    invalid_event: bool,
}

impl NativeSession {
    fn start(
        open_id: String,
        config: Arc<private_task::ExecutionConfig>,
        slot: ExecutionSlot,
        handshakes: Handshakes,
    ) -> Self {
        Self::spawn(
            open_id,
            slot,
            handshakes,
            move |commands, events, activity| {
                super::supervise::native_session::run(config, commands, events, activity)
            },
        )
    }

    fn spawn<F, Fut>(
        open_id: String,
        mut slot: ExecutionSlot,
        handshakes: Handshakes,
        run: F,
    ) -> Self
    where
        F: FnOnce(
            mpsc::Receiver<super::supervise::native_session::Command>,
            mpsc::Sender<super::supervise::native_session::Event>,
            watch::Receiver<bool>,
        ) -> Fut,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let (commands, receive) = mpsc::channel(1);
        let (send, events) = mpsc::channel(1);
        let (activity, signal) = watch::channel(true);
        let execution = run(receive, send, signal);
        let execution = tokio::spawn(async move {
            let result = execution.await;
            if native_cleanup(&result).is_none() {
                // Quarantine before dropping the permit, not after scheduling the
                // connection's terminal response: another connection may be ready.
                slot.gate.close();
            }
            finish_execution(&mut slot, result)
        });
        Self {
            open_id,
            handshakes,
            commands,
            events,
            activity,
            execution: Some(execution),
            opened: false,
            pending: None,
            close_id: None,
            requests: 0,
            cancelled: false,
            invalid_event: false,
        }
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        let _ = self.activity.send(false);
    }

    fn request(&mut self, request: wire::Request) -> Option<Value> {
        use super::supervise::native_session::Command;
        match request.operation {
            wire::Operation::SubmitConversation { conversation } => {
                if !self.opened
                    || self.pending.is_some()
                    || self.close_id.is_some()
                    || self.cancelled
                {
                    return Some(wire::error(Some(&request.id), "busy"));
                }
                if self.requests >= 128
                    || !conversation.requires_generation_policy_handshake()
                    || (conversation.output_constraint().is_some()
                        && self.handshakes.output_constraint != Some(1))
                {
                    return Some(wire::error(Some(&request.id), "invalid_request"));
                }
                let input = conversation
                    .bytes_profile(ModelProfile::Qwen4bInstruct2507)
                    .expect("validated native conversation serializes");
                self.pending = Some(request.id.clone());
                if self
                    .commands
                    .try_send(Command::Submit {
                        id: request.id.clone(),
                        input,
                    })
                    .is_err()
                {
                    self.invalid_event = true;
                    self.cancel();
                    return None;
                }
                self.requests += 1;
                Some(wire::response(&request.id, "admitted"))
            }
            wire::Operation::CloseNativeSession {} => {
                if self.close_id.is_some() {
                    return Some(wire::error(Some(&request.id), "busy"));
                }
                self.close_id = Some(request.id);
                if self.pending.is_some() {
                    self.cancel();
                } else if self.commands.try_send(Command::Close).is_err() {
                    self.invalid_event = true;
                    self.cancel();
                }
                None // A close receipt is emitted only after the session joins.
            }
            wire::Operation::Cancel { task_id } => {
                if self.pending.as_deref() != Some(task_id.as_str()) {
                    return Some(wire::error(Some(&request.id), "no_such_task"));
                }
                self.cancel();
                let mut reply = wire::response(&request.id, "cancel_requested");
                reply["task_id"] = task_id.into();
                Some(reply)
            }
            _ => Some(wire::error(Some(&request.id), "busy")),
        }
    }

    fn event(&mut self, event: super::supervise::native_session::Event) -> Option<Value> {
        use super::supervise::native_session::Event;
        match event {
            Event::Opened if !self.opened && !self.cancelled && self.close_id.is_none() => {
                self.opened = true;
                Some(wire::response(&self.open_id, "native_session_opened"))
            }
            Event::Result { id, value } if self.opened && self.pending.as_ref() == Some(&id) => {
                if self.cancelled || self.close_id.is_some() {
                    return None;
                }
                // The runtime validates model output. This separate check prevents
                // a per-turn result from masquerading as a child-reaped terminal.
                if value["version"] != 2
                    || value["cleanup"]
                        != json!({"version":2,"request_files_removed":true,
                            "session_closed":false,"session_private_state_retained":true})
                {
                    self.invalid_event = true;
                    self.cancel();
                    return None;
                }
                self.pending = None;
                let mut reply = wire::response(&id, "result");
                reply["result"] = value;
                Some(reply)
            }
            _ => {
                self.invalid_event = true;
                self.cancel();
                None
            }
        }
    }

    fn terminal(
        &self,
        result: std::result::Result<Result<Value>, tokio::task::JoinError>,
        gate: &Semaphore,
    ) -> Vec<Value> {
        let (cleanup, failed, deadline) = match result {
            Ok(Ok(value)) => (Some(value), false, false),
            Ok(Err(error)) => (
                super::supervise::native_session::cleanup(&error),
                true,
                super::supervise::native_session::execution_deadline(&error),
            ),
            Err(_) => (None, true, false),
        };
        let cleanup = cleanup.filter(|value| {
            *value == json!({"version":1,"child_reaped":true,"private_state_removed":true})
        });
        if cleanup.is_none() {
            gate.close();
        }
        let id = self
            .pending
            .as_ref()
            .or(self.close_id.as_ref())
            .unwrap_or(&self.open_id);
        if gate.is_closed()
            || failed
            || self.cancelled
            || self.invalid_event
            || self.pending.is_some()
        {
            let code = if gate.is_closed() {
                "cleanup_unconfirmed"
            } else if self.cancelled && !self.invalid_event {
                "cancelled"
            } else if deadline && self.handshakes.execution_error == Some(1) {
                "execution_budget_exceeded"
            } else {
                "execution_failed"
            };
            let mut reply = wire::error(Some(id), code);
            reply["session_cleanup"] = cleanup.clone().unwrap_or(Value::Null);
            let mut replies = vec![reply];
            if let Some(cleanup) = cleanup
                .filter(|_| self.pending.is_some() && self.close_id.is_some() && !gate.is_closed())
            {
                replies.push(self.closed(cleanup));
            }
            return replies;
        }
        vec![self.closed(cleanup.expect("confirmed cleanup"))]
    }

    fn closed(&self, cleanup: Value) -> Value {
        let mut reply = wire::response(
            self.close_id.as_ref().unwrap_or(&self.open_id),
            "native_session_closed",
        );
        reply["cleanup"] = cleanup;
        reply
    }
}

fn native_cleanup(result: &Result<Value>) -> Option<Value> {
    let value = match result {
        Ok(value) => Some(value.clone()),
        Err(error) => super::supervise::native_session::cleanup(error),
    };
    value.filter(|value| {
        *value == json!({"version":1,"child_reaped":true,"private_state_removed":true})
    })
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        let _ = self.activity.send(false);
    }
}

type NativeSessionStart =
    fn(String, Arc<private_task::ExecutionConfig>, ExecutionSlot, Handshakes) -> NativeSession;

fn connection_request(
    request: wire::Request,
    config: &Arc<private_task::ExecutionConfig>,
    gate: &Arc<Semaphore>,
    active: &mut Option<Active>,
    handshakes: &mut Handshakes,
    native: &mut Option<NativeSession>,
    start_native: NativeSessionStart,
) -> Option<Value> {
    if let Some(session) = native {
        return session.request(request);
    }
    if !matches!(request.operation, wire::Operation::OpenNativeSession {}) {
        return Some(respond(request, config, gate, active, handshakes));
    }
    if !handshakes.conversation
        || handshakes.native_session != Some(1)
        || handshakes.generation_policy != Some(1)
    {
        Some(wire::error(Some(&request.id), "handshake_required"))
    } else if !config
        .native_backend
        .supports_native_session(config.model_profile)
    {
        Some(wire::error(Some(&request.id), "invalid_request"))
    } else if gate.is_closed() {
        Some(wire::error(Some(&request.id), "cleanup_unconfirmed"))
    } else if active.is_some() {
        Some(wire::error(Some(&request.id), "busy"))
    } else if let Some(slot) = ExecutionSlot::admit(gate) {
        *native = Some(start_native(
            request.id,
            config.clone(),
            slot,
            handshakes.clone(),
        ));
        None
    } else {
        Some(wire::error(Some(&request.id), "busy"))
    }
}

async fn connection(
    stream: UnixStream,
    config: Arc<private_task::ExecutionConfig>,
    gate: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
) {
    connection_with_native(stream, config, gate, shutdown, NativeSession::start).await;
}

async fn connection_with_native(
    stream: UnixStream,
    config: Arc<private_task::ExecutionConfig>,
    gate: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    start_native: NativeSessionStart,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (send, mut receive) = mpsc::channel(1);
    let profile = config.model_profile;
    // A dedicated reader keeps partial frames intact while execution finishes or
    // cancellation/status responses are written; select! never discards half a frame.
    let reader_task = tokio::spawn(async move {
        loop {
            let message = match wire::read_request(&mut reader, profile).await {
                Ok(Some(request)) => Incoming::Request(request),
                Ok(None) => break,
                _ => {
                    let _ = send.send(Incoming::Invalid).await;
                    break;
                }
            };
            if send.send(message).await.is_err() {
                break;
            }
        }
    });
    let mut handshakes = Handshakes::default();
    let mut seen = BTreeSet::new();
    let mut active: Option<Active> = None;
    let mut native: Option<NativeSession> = None;
    let mut native_events_open = true;
    loop {
        // Borrow the disjoint channel/handle fields separately while select!
        // polls them; no two futures may borrow the whole session mutably.
        let (events, execution) = if let Some(session) = native.as_mut() {
            (Some(&mut session.events), session.execution.as_mut())
        } else {
            (None, None)
        };
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            incoming = receive.recv() => {
                let Some(Incoming::Request(request)) = incoming else {
                    if matches!(incoming, Some(Incoming::Invalid)) {
                        let _ = wire::write(&mut writer, &wire::error(None, "invalid_request")).await;
                    }
                    break;
                };
                if seen.len() >= wire::MAX_REQUESTS || !seen.insert(request.id.clone()) {
                    let _ = wire::write(&mut writer, &wire::error(Some(&request.id), "invalid_request")).await;
                    break;
                }
                let response = connection_request(request, &config, &gate, &mut active,
                    &mut handshakes, &mut native, start_native);
                if let Some(response) = response {
                    if wire::write(&mut writer, &response).await.is_err() { break; }
                }
            }
            event = async {
                events.expect("guarded native events").recv().await
            }, if events.is_some() && native_events_open => {
                if let Some(event) = event {
                    if let Some(response) = native.as_mut().expect("native session").event(event) {
                        if wire::write(&mut writer, &response).await.is_err() { break; }
                    }
                } else {
                    native_events_open = false;
                }
            }
            result = async {
                execution.expect("guarded native execution").await
            }, if execution.is_some() => {
                let mut session = native.take().expect("completed native session");
                session.execution.take();
                for response in session.terminal(result, &gate) {
                    if wire::write(&mut writer, &response).await.is_err() { break; }
                }
                break; // A closed/failed owner session cannot be reused or reopened.
            }
            result = async {
                active.as_mut().expect("guarded active task").execution.as_mut().expect("active handle").await
            }, if active.is_some() => {
                let mut task = active.take().expect("completed active task");
                // The handle was already awaited by select!; do not poll it again.
                task.execution.take();
                if let Err(error) = &result {
                    super::supervise::diagnostic::event("task",
                        if error.is_panic() { "panic" } else { "join_cancelled" });
                }
                let response = terminal_response(&task, result, &gate);
                if wire::write(&mut writer, &response).await.is_err() { break; }
            }
        }
    }
    reader_task.abort();
    let _ = reader_task.await;
    if let Some(mut task) = active {
        task.cancel();
        let _ = task.reap().await;
    }
    if let Some(mut session) = native {
        session.cancel();
        if let Some(execution) = session.execution.take() {
            // No detached worker after EOF, shutdown, invalid frame or write failure.
            let _ = execution.await;
        }
    }
}

pub(super) async fn run(options: Options) -> Result<()> {
    // Keep launch diagnostics static too: never turn an incoming request into a log.
    run_inner(options)
        .await
        .map_err(|_| anyhow::anyhow!("compute_private_service_failed"))
}

async fn run_inner(options: Options) -> Result<()> {
    options.validate()?;
    let config = Arc::new(options.config());
    let gate = Arc::new(Semaphore::new(1));
    if !options.execute {
        println!(
            "{}",
            json!({"version":1,"operation":"compute_private_service_plan","execute":false,
            "same_uid_only":true,"retained_results":false,"capabilities":capabilities(&config,&gate)})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let listener = UnixListener::bind(&options.socket)?;
    let info = fs::symlink_metadata(&options.socket)?;
    let socket_guard = SocketGuard {
        path: options.socket,
        device: info.dev(),
        inode: info.ino(),
    };
    fs::set_permissions(&socket_guard.path, fs::Permissions::from_mode(0o600))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let (shutdown, signal) = watch::channel(false);
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = match accepted { Ok(stream) => stream, Err(error) => break Err(error.into()) };
                if connections.len() >= MAX_CONNECTIONS
                    || stream.peer_cred().map(|peer| peer.uid()).ok() != Some(nix::unistd::geteuid().as_raw()) {
                    continue;
                }
                connections.spawn(connection(stream, config.clone(), gate.clone(), signal.clone()));
            }
        }
    };
    drop(listener);
    let _ = shutdown.send(true);
    while connections.join_next().await.is_some() {}
    result
}
