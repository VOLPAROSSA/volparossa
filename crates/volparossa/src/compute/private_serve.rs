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
        ensure!(
            self.model_root.join("model.safetensors").is_file(),
            "compute_model_missing"
        );
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
            slot.finish(&result);
            result
        });
        Self {
            id,
            activity,
            execution: Some(execution),
            cancelled: false,
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

enum Incoming {
    Request(wire::Request),
    Invalid,
}

async fn connection(
    stream: UnixStream,
    config: Arc<private_task::ExecutionConfig>,
    gate: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (send, mut receive) = mpsc::channel(1);
    // A dedicated reader keeps partial frames intact while execution finishes or
    // cancellation/status responses are written; select! never discards half a frame.
    let reader_task = tokio::spawn(async move {
        loop {
            let message =
                match wire::read::<wire::Request>(&mut reader, wire::MAX_REQUEST_BYTES).await {
                    Ok(Some(request)) if request.validate().is_ok() => Incoming::Request(request),
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
    let mut handshake = false;
    let mut conversation_handshake = false;
    let mut seen = BTreeSet::new();
    let mut active: Option<Active> = None;
    loop {
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
                let response = match request.operation {
                    wire::Operation::Capabilities {} => {
                        handshake = true;
                        let mut response = wire::response(&request.id, "capabilities");
                        response["capabilities"] = capabilities(&config, &gate);
                        response
                    }
                    wire::Operation::ConversationCapabilities {} => {
                        conversation_handshake = true;
                        let mut response = wire::response(&request.id, "conversation_capabilities");
                        response["capabilities"] = super::private_conversation::capabilities(config.model_profile);
                        response["capabilities"]["execution_slots"] = 1.into();
                        response["capabilities"]["max_seconds"] = config.max_seconds.into();
                        response["capabilities"]["max_request_bytes"] = wire::MAX_REQUEST_BYTES.into();
                        response["capabilities"]["max_response_bytes"] = wire::MAX_RESPONSE_BYTES.into();
                        response["capabilities"]["quarantined"] = gate.is_closed().into();
                        response
                    }
                    wire::Operation::SubmitConversation { conversation } => {
                        if !conversation_handshake {
                            wire::error(Some(&request.id), "handshake_required")
                        } else if gate.is_closed() {
                            wire::error(Some(&request.id), "cleanup_unconfirmed")
                        } else if active.is_some() {
                            wire::error(Some(&request.id), "busy")
                        } else if let Some(slot) = ExecutionSlot::admit(&gate) {
                            let input = conversation.bytes().expect("validated conversation serializes");
                            active = Some(Active::start_mode(request.id.clone(), config.clone(), input, slot,
                                super::Mode::PrivateConversation));
                            wire::response(&request.id, "admitted")
                        } else {
                            wire::error(Some(&request.id), "busy")
                        }
                    }
                    wire::Operation::Submit { question, context } => {
                        if !handshake {
                            wire::error(Some(&request.id), "handshake_required")
                        } else if gate.is_closed() {
                            wire::error(Some(&request.id), "cleanup_unconfirmed")
                        } else if active.is_some() {
                            wire::error(Some(&request.id), "busy")
                        } else if let Some(slot) = ExecutionSlot::admit(&gate) {
                            let input = wire::input_bytes(&question, &context).expect("bounded strings serialize");
                            active = Some(Active::start(request.id.clone(), config.clone(), input, slot));
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
                };
                if wire::write(&mut writer, &response).await.is_err() { break; }
            }
            result = async {
                active.as_mut().expect("guarded active task").execution.as_mut().expect("active handle").await
            }, if active.is_some() => {
                let mut task = active.take().expect("completed active task");
                // The handle was already awaited by select!; do not poll it again.
                task.execution.take();
                let response = match result {
                    Ok(Ok(answer)) if !task.cancelled => {
                        let mut response = wire::response(&task.id, "result");
                        response["result"] = answer;
                        response
                    }
                    _ if gate.is_closed() => wire::error(Some(&task.id), "cleanup_unconfirmed"),
                    _ if task.cancelled => wire::error(Some(&task.id), "cancelled"),
                    _ => wire::error(Some(&task.id), "execution_failed"),
                };
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
