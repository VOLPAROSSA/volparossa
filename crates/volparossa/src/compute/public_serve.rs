//! Same-owner public cooperation through the real document/synthesis coordinator.
//! Unlike `private_serve`, explicitly authorized inputs are published to selected peers.

#[cfg(test)]
mod tests;
mod wire;

use super::{peer::document::public as backend, private_directory};
use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    os::unix::fs::{
        DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
        PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_CONNECTIONS: usize = 8;
const MAX_RETAINED_TASKS: usize = 32;
const MAX_RETAINED_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[command(flatten)]
    backend: backend::Config,
    /// Existing dedicated same-owner mode-0700 directory. Public journals remain for reconciliation.
    #[arg(long)]
    state_parent: PathBuf,
    /// New same-owner mode-0600 socket, separate from private-local compute.
    #[arg(long)]
    socket: PathBuf,
    /// Starts cooperative cancellation; existing exact-handle cleanup is still awaited.
    #[arg(long, default_value_t = 7200, value_parser = clap::value_parser!(u16).range(1..=7200))]
    max_task_seconds: u16,
    #[arg(long)]
    execute: bool,
}

struct Config {
    backend: backend::Config,
    state_parent: PathBuf,
    agent_socket: PathBuf,
    max_task_seconds: u16,
}

impl Options {
    fn validate(&self, agent_socket: &Path) -> Result<()> {
        self.backend.validate()?;
        private_directory(&self.state_parent)?;
        ensure!(
            self.socket.is_absolute() && agent_socket.is_absolute() && self.socket != agent_socket,
            "public_ipc_socket_scope"
        );
        private_directory(self.socket.parent().context("public_ipc_socket_parent")?)?;
        ensure!(
            fs::symlink_metadata(&self.socket)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "public_ipc_socket_exists"
        );
        for root in [&self.backend.runtime_root, &self.backend.model_root] {
            ensure!(
                !self.state_parent.starts_with(root) && !root.starts_with(&self.state_parent),
                "public_ipc_roots_overlap"
            );
        }
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

fn state_lock(parent: &Path) -> Result<nix::fcntl::Flock<fs::File>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent.join(".service.lock"))?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.mode() & 0o777 == 0o600,
        "public_ipc_state_lock"
    );
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| anyhow::anyhow!("public_ipc_state_busy"))
}

fn new_task(parent: &Path) -> Result<PathBuf> {
    let mut directories = vec![parent.to_owned()];
    let mut tasks = 0;
    let mut entries = 0;
    let mut bytes = 0_u64;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries += 1;
            ensure!(entries <= 32_768, "public_ipc_storage_bound");
            let info = entry.metadata()?;
            ensure!(!entry.file_type()?.is_symlink(), "public_ipc_storage_type");
            if info.is_dir() {
                if directory == parent {
                    tasks += 1;
                }
                directories.push(entry.path());
            } else if info.is_file() {
                bytes = bytes
                    .checked_add(info.len())
                    .context("public_ipc_storage_bound")?;
            } else {
                // The service socket may itself be inside its private state parent.
                ensure!(
                    directory == parent && info.file_type().is_socket(),
                    "public_ipc_storage_type"
                );
            }
            ensure!(bytes <= MAX_RETAINED_BYTES, "public_ipc_storage_bound");
        }
    }
    ensure!(tasks < MAX_RETAINED_TASKS, "public_ipc_storage_bound");
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("public_ipc_randomness"))?;
    let root = parent.join(format!("task-{}", hex::encode(nonce)));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    Ok(root)
}

struct ExecutionSlot {
    _permit: OwnedSemaphorePermit,
    gate: Arc<Semaphore>,
    parent: PathBuf,
    confirmed: bool,
}
impl Drop for ExecutionSlot {
    fn drop(&mut self) {
        if !self.confirmed {
            self.gate.close();
            if let Ok(mut file) = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.parent.join(".cleanup-unconfirmed"))
            {
                let _ =
                    file.write_all(b"public execution cleanup requires explicit reconciliation\n");
                let _ = file.sync_all();
            }
        }
    }
}

struct Active {
    id: String,
    cancellation: watch::Sender<bool>,
    execution: Option<JoinHandle<backend::Execution>>,
    cancelled: bool,
    deadline: tokio::time::Instant,
    deadline_reached: bool,
}

impl Active {
    fn start(
        id: String,
        config: Arc<Config>,
        root: PathBuf,
        question: String,
        context: String,
        license: String,
        mut slot: ExecutionSlot,
    ) -> Self {
        let (cancellation, cancelled) = watch::channel(false);
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(config.max_task_seconds));
        let execution = tokio::spawn(async move {
            let result = backend::execute(
                &config.backend,
                &root,
                &config.agent_socket,
                question,
                context,
                license,
                &cancelled,
            )
            .await;
            slot.confirmed = result.cleanup_confirmed;
            result
        });
        Self {
            id,
            cancellation,
            execution: Some(execution),
            cancelled: false,
            deadline,
            deadline_reached: false,
        }
    }
    fn cancel(&mut self) {
        self.cancelled = true;
        let _ = self.cancellation.send(true);
    }
    async fn reap(&mut self) {
        if let Some(execution) = self.execution.take() {
            let _ = execution.await;
        }
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        let _ = self.cancellation.send(true);
    }
}

fn capabilities(config: &Config, gate: &Semaphore) -> Value {
    json!({"visibility":"public_cooperative","network_access":true,"private_data_supported":false,
        "public_cache":true,"training":false,"cloud_fallback":false,"retained_public_receipts":true,
        "remote_erasure_guaranteed":false,"model_execution_proven":false,"model_profile":config.backend.model_profile,
        "max_question_bytes":512,"max_context_bytes":4096,"max_request_bytes":wire::MAX_REQUEST_BYTES,
        "max_response_bytes":wire::MAX_RESPONSE_BYTES,"execution_slots":1,"max_connections":MAX_CONNECTIONS,
        "max_seconds":config.backend.max_seconds,"max_task_seconds":config.max_task_seconds,
        "max_retained_tasks":MAX_RETAINED_TASKS,"retained_bytes_admission_limit":MAX_RETAINED_BYTES,
        "quarantined":gate.is_closed()})
}

enum Incoming {
    Request(wire::Request),
    Invalid,
}

async fn connection(
    stream: UnixStream,
    config: Arc<Config>,
    gate: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (send, mut receive) = mpsc::channel(1);
    let reader_task = tokio::spawn(async move {
        loop {
            let message = match wire::read::<wire::Request>(&mut reader).await {
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
    let mut seen = BTreeSet::new();
    let mut active: Option<Active> = None;
    loop {
        let deadline = active
            .as_ref()
            .filter(|task| !task.deadline_reached)
            .map(|task| task.deadline);
        tokio::select! {
            biased;
            _=shutdown.changed()=>break,
            ()=async { tokio::time::sleep_until(deadline.expect("guarded deadline")).await },
                if deadline.is_some()=>{
                    let task=active.as_mut().expect("guarded task");
                    task.deadline_reached=true;
                    task.cancel();
                },
            incoming=receive.recv()=>{
                let Some(Incoming::Request(request))=incoming else {
                    if matches!(incoming,Some(Incoming::Invalid)) {
                        let _=wire::write(&mut writer,&wire::error(None,"invalid_request")).await;
                    }
                    break;
                };
                if seen.len()>=wire::MAX_REQUESTS || !seen.insert(request.id.clone()) {
                    let _=wire::write(&mut writer,&wire::error(Some(&request.id),"invalid_request")).await;
                    break;
                }
                let response=match request.operation {
                    wire::Operation::Capabilities{}=>{
                        handshake=true;
                        let mut response=wire::response(&request.id,"capabilities");
                        response["capabilities"]=capabilities(&config,&gate); response
                    },
                    wire::Operation::Submit{question,context,license,..}=>{
                        if !handshake { wire::error(Some(&request.id),"handshake_required") }
                        else if gate.is_closed() { wire::error(Some(&request.id),"cleanup_unconfirmed") }
                        else if active.is_some() { wire::error(Some(&request.id),"busy") }
                        else if let Ok(permit)=gate.clone().try_acquire_owned() {
                            match new_task(&config.state_parent) {
                                Ok(root)=>{
                                    let slot=ExecutionSlot{_permit:permit,gate:gate.clone(),parent:config.state_parent.clone(),confirmed:false};
                                    active=Some(Active::start(request.id.clone(),config.clone(),root,question,context,license,slot));
                                    wire::response(&request.id,"admitted")
                                },
                                Err(_)=>wire::error(Some(&request.id),"storage_bound"),
                            }
                        } else { wire::error(Some(&request.id),"busy") }
                    },
                    wire::Operation::Cancel{task_id}=>{
                        if let Some(task)=active.as_mut().filter(|task|task.id==task_id) {
                            task.cancel();
                            let mut response=wire::response(&request.id,"cancel_requested");
                            response["task_id"]=task_id.into(); response
                        } else { wire::error(Some(&request.id),"no_such_task") }
                    },
                };
                if wire::write(&mut writer,&response).await.is_err() { break; }
            },
            result=async{active.as_mut().expect("guarded task").execution.as_mut().expect("owned execution").await}, if active.is_some()=>{
                let mut task=active.take().expect("completed task");
                task.execution.take();
                let response=match result {
                    _ if gate.is_closed()=>wire::error(Some(&task.id),"cleanup_unconfirmed"),
                    _ if task.deadline_reached=>wire::error(Some(&task.id),"deadline_exceeded"),
                    _ if task.cancelled=>wire::error(Some(&task.id),"cancelled"),
                    Ok(backend::Execution{result:Ok(answer),cleanup_confirmed:true})=>{
                        let mut response=wire::response(&task.id,"result"); response["result"]=answer; response
                    },
                    _=>wire::error(Some(&task.id),"execution_failed"),
                };
                if wire::write(&mut writer,&response).await.is_err() { break; }
            },
        }
    }
    reader_task.abort();
    let _ = reader_task.await;
    if let Some(mut task) = active {
        task.cancel();
        task.reap().await;
    }
}

pub(super) async fn run(options: Options, agent_socket: &Path) -> Result<()> {
    run_inner(options, agent_socket)
        .await
        .map_err(|_| anyhow::anyhow!("compute_public_service_failed"))
}

async fn run_inner(options: Options, agent_socket: &Path) -> Result<()> {
    options.validate(agent_socket)?;
    let gate = Arc::new(Semaphore::new(1));
    let config = Arc::new(Config {
        backend: options.backend,
        state_parent: options.state_parent,
        agent_socket: agent_socket.to_owned(),
        max_task_seconds: options.max_task_seconds,
    });
    if fs::symlink_metadata(config.state_parent.join(".cleanup-unconfirmed")).is_ok() {
        gate.close();
    }
    if !options.execute {
        println!(
            "{}",
            json!({"version":1,"operation":"compute_public_service_plan","execute":false,
            "same_uid_only":true,"capabilities":capabilities(&config,&gate)})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let _lock = state_lock(&config.state_parent)?;
    let listener = UnixListener::bind(&options.socket)?;
    let info = fs::symlink_metadata(&options.socket)?;
    let guard = SocketGuard {
        path: options.socket,
        device: info.dev(),
        inode: info.ino(),
    };
    fs::set_permissions(&guard.path, fs::Permissions::from_mode(0o600))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let (shutdown, activity) = watch::channel(false);
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _=terminate.recv()=>break Ok(()),
            _=interrupt.recv()=>break Ok(()),
            _=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{
                let(stream,_)=match accepted {Ok(stream)=>stream,Err(error)=>break Err(error.into())};
                if connections.len()>=MAX_CONNECTIONS
                    || stream.peer_cred().map(|peer|peer.uid()).ok()!=Some(nix::unistd::geteuid().as_raw()) {continue;}
                connections.spawn(connection(stream,config.clone(),gate.clone(),activity.clone()));
            },
        }
    };
    drop(listener);
    let _ = shutdown.send(true);
    while connections.join_next().await.is_some() {}
    result
}
