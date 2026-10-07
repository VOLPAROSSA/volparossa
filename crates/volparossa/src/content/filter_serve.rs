//! Explicit public filter data service, not browser activation or publisher governance.
//! Fixed owner authority, original signed content and same-UID local IPC only.

#[cfg(test)]
mod tests;
mod wire;

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read as _,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use rustix::time::{ClockId, clock_gettime};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};

use super::{Limits, filter_snapshot, public_text};

const MAX_CONNECTIONS: usize = 4;
const AUTHORITY_BYTES: usize = 4096;
const NS: u64 = 1_000_000_000;
const MAX_WIRE_INTEGER: u64 = 9_007_199_254_740_991;
const FETCH_TIMEOUT: Duration = Duration::from_secs(55);

#[derive(Debug, Args)]
#[group(id = "ContentFilterServeOptions")]
pub(crate) struct Options {
    /// Existing private operator grant; never created or amended by this command.
    #[arg(long)]
    authority: PathBuf,
    /// Fixed absolute agent-owned cache; the agent validates/reopens it without resetting floors.
    #[arg(long)]
    cache: PathBuf,
    /// Existing private directory for transient verified downloads.
    #[arg(long)]
    work_parent: PathBuf,
    /// New same-owner mode-0600 Unix socket below an existing private directory.
    #[arg(long)]
    socket: PathBuf,
    /// Explicitly start the foreground broker. Otherwise only print a scope preview.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityFile {
    version: u8,
    enabled: bool,
    public_content: bool,
    authorize_filter_publisher: bool,
    publisher_key: String,
    name: String,
    manifest_id: String,
    not_after_unix_seconds: u64,
}

struct Authority {
    path: PathBuf,
    original: Vec<u8>,
    publisher: VerifyingKey,
    name: String,
    manifest_id: [u8; 32],
    expires: u64,
}

fn absolute(path: &Path) -> Result<()> {
    let text = path.to_str().context("private_path")?;
    ensure!(
        text.starts_with('/')
            && text.len() <= 4096
            && !text.contains('\0')
            && text[1..]
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "private_path"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    absolute(path)?;
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o700
            && path.canonicalize()? == path,
        "private_directory"
    );
    Ok(())
}

fn authority_bytes(path: &Path) -> Result<Vec<u8>> {
    absolute(path)?;
    private_directory(path.parent().context("authority_parent")?)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o600
            && info.nlink() == 1
            && info.len() > 0
            && info.len() <= AUTHORITY_BYTES as u64,
        "private_authority_file"
    );
    let mut bytes = Vec::new();
    file.take((AUTHORITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= AUTHORITY_BYTES, "authority_bound");
    Ok(bytes)
}

impl Authority {
    fn load(path: &Path) -> Result<Self> {
        let original = authority_bytes(path)?;
        let value: AuthorityFile =
            serde_json::from_slice(&original).map_err(|_| anyhow::anyhow!("invalid_authority"))?;
        ensure!(
            value.version == 1
                && value.enabled
                && value.public_content
                && value.authorize_filter_publisher,
            "explicit_public_authority_required"
        );
        let publisher = super::parse_publisher_key(&value.publisher_key)
            .map_err(|_| anyhow::anyhow!("invalid_authority"))?;
        let name = super::parse_content_name(&value.name)
            .map_err(|_| anyhow::anyhow!("invalid_authority"))?;
        ensure!(
            name.is_ascii() && value.not_after_unix_seconds <= MAX_WIRE_INTEGER,
            "invalid_authority"
        );
        let mut manifest_id = [0; 32];
        ensure!(
            value.manifest_id.len() == 64
                && hex::decode_to_slice(value.manifest_id, &mut manifest_id).is_ok()
                && manifest_id != [0; 32],
            "invalid_authority"
        );
        Ok(Self {
            path: path.to_owned(),
            original,
            publisher,
            name,
            manifest_id,
            expires: value.not_after_unix_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    wall_ns: u64,
    boot_ns: u64,
}

fn nanos(clock: ClockId) -> Result<u64> {
    let value = clock_gettime(clock);
    let seconds = u64::try_from(value.tv_sec)?;
    let fraction = u64::try_from(value.tv_nsec)?;
    ensure!(fraction < NS, "clock_error");
    seconds
        .checked_mul(NS)
        .and_then(|v| v.checked_add(fraction))
        .context("clock_error")
}

impl Sample {
    fn now() -> Result<Self> {
        // BOOTTIME includes suspend; sampling before realtime cannot extend validity.
        let boot_ns = nanos(ClockId::Boottime)?;
        Ok(Self {
            boot_ns,
            wall_ns: nanos(ClockId::Realtime)?,
        })
    }

    fn deadline(self, expires: u64) -> Result<u64> {
        expires
            .checked_mul(NS)
            .and_then(|v| v.checked_sub(self.wall_ns))
            .filter(|v| *v > 0)
            .and_then(|v| self.boot_ns.checked_add(v))
            .context("expired")
    }
}

struct Cached {
    download: public_text::TextDownload,
    boot_deadline: u64,
}

struct Broker {
    authority: Authority,
    origin: Sample,
    previous: Sample,
    boot_deadline: u64,
    terminal: Option<&'static str>,
    cached: Option<Cached>,
}

impl Broker {
    fn new(authority: Authority, now: Sample) -> Result<Self> {
        let boot_deadline = now.deadline(authority.expires)?;
        Ok(Self {
            authority,
            origin: now,
            previous: now,
            boot_deadline,
            terminal: None,
            cached: None,
        })
    }

    fn check_at(&mut self, now: Sample) -> Result<Sample, &'static str> {
        if let Some(code) = self.terminal {
            return Err(code);
        }
        let error = if !authority_bytes(&self.authority.path)
            .is_ok_and(|bytes| bytes == self.authority.original)
        {
            Some("revoked")
        } else if now.wall_ns < self.previous.wall_ns || now.boot_ns < self.previous.boot_ns {
            Some("clock_error")
        } else if now.wall_ns / NS >= self.authority.expires
            || now.boot_ns >= self.boot_deadline
            || self.cached.as_ref().is_some_and(|cached| {
                now.wall_ns / NS >= cached.download.expires || now.boot_ns >= cached.boot_deadline
            })
        {
            Some("expired")
        } else {
            None
        };
        self.previous = now;
        if let Some(code) = error {
            self.terminal = Some(code);
            return Err(code);
        }
        Ok(now)
    }

    fn check(&mut self) -> Result<Sample, &'static str> {
        if let Ok(now) = Sample::now() {
            self.check_at(now)
        } else {
            self.terminal = Some("clock_error");
            Err("clock_error")
        }
    }

    fn validate_cached(&self, now: Sample) -> Result<Option<Value>, &'static str> {
        let Some(cached) = &self.cached else {
            return Ok(None);
        };
        let (manifest, rules) = filter_snapshot::validate_download(
            &self.authority.publisher,
            &self.authority.name,
            &self.authority.manifest_id,
            &cached.download,
            now.wall_ns / NS,
        )
        .map_err(|_| "invalid_snapshot")?;
        if [
            manifest.metadata().revision,
            cached.download.expires,
            cached.download.verified_at,
            self.authority.expires,
        ]
        .iter()
        .any(|value| *value > MAX_WIRE_INTEGER)
        {
            return Err("invalid_snapshot");
        }
        Ok(Some(
            json!({"generation":hex::encode(manifest.manifest_id()),
            "publisher_key":hex::encode(manifest.publisher()),"name":manifest.metadata().name,
            "revision":manifest.metadata().revision,"sha256":hex::encode(manifest.object_sha256()),
            "bytes":manifest.length(),"rules":rules,"grammar":"ubo-domain-block-v1",
            "verified_at_unix_seconds":cached.download.verified_at,
            "expires_unix_seconds":cached.download.expires,
            "authorization_expires_unix_seconds":cached.download.expires.min(self.authority.expires)}),
        ))
    }

    fn install(
        &mut self,
        download: public_text::TextDownload,
        now: Sample,
    ) -> Result<(), &'static str> {
        self.check_at(now)?;
        filter_snapshot::validate_download(
            &self.authority.publisher,
            &self.authority.name,
            &self.authority.manifest_id,
            &download,
            now.wall_ns / NS,
        )
        .map_err(|_| "invalid_snapshot")?;
        // A suspended transfer or a slowed wall clock must not grant a fresh
        // lifetime when the signed expiry is finally learned. Keep the earlier
        // projection from process start as well as the current wall-time bound.
        let boot_deadline = now.deadline(download.expires).map_err(|_| "expired")?.min(
            self.origin
                .deadline(download.expires)
                .map_err(|_| "expired")?,
        );
        if now.boot_ns >= boot_deadline {
            self.terminal = Some("expired");
            return Err("expired");
        }
        self.cached = Some(Cached {
            download,
            boot_deadline,
        });
        Ok(())
    }
}

struct Service {
    broker: Mutex<Broker>,
    fetch_slot: tokio::sync::Mutex<()>,
    source: public_text::TextSource,
    control: PathBuf,
    work_parent: PathBuf,
}

impl Service {
    fn access<T>(
        &self,
        action: impl FnOnce(&mut Broker) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let mut broker = self.broker.lock().map_err(|_| "unavailable")?;
        action(&mut broker)
    }

    async fn fetch(&self) -> Result<(), &'static str> {
        let _slot = self.fetch_slot.try_lock().map_err(|_| "busy")?;
        if self.access(|broker| {
            let now = broker.check()?;
            Ok(broker.validate_cached(now)?.is_some())
        })? {
            return Ok(());
        }
        private_directory(&self.work_parent).map_err(|_| "unavailable")?;
        let pending = tempfile::Builder::new()
            .prefix(".filter-broker-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&self.work_parent)
            .map_err(|_| "unavailable")?;
        let result = tokio::time::timeout(
            FETCH_TIMEOUT,
            public_text::fetch_text_source(&self.source, &self.control, pending.path()),
        )
        .await;
        // Even an unsuccessful transfer must observe a mid-fetch local revocation.
        self.access(|broker| {
            let now = broker.check()?;
            broker.install(
                result
                    .map_err(|_| "unavailable")?
                    .map_err(|_| "unavailable")?,
                now,
            )
        })
    }

    async fn response(&self, request: &wire::Request) -> Value {
        if matches!(request.operation, wire::Operation::Fetch {}) {
            if let Err(code) = self.fetch().await {
                return wire::error(Some(&request.id), code);
            }
        }
        self.access(|broker| {
            let now = broker.check()?;
            let metadata = broker.validate_cached(now)?;
            Ok(match request.operation {
                wire::Operation::Capabilities {} => json!({"version":wire::VERSION,"id":request.id,
                    "event":"capabilities","protocol":"volparossa-filter","same_uid_only":true,
                    "public_content_only":true,"fixed_publication":true,"browser_activation":false,
                    "max_request_bytes":wire::MAX_REQUEST,"max_response_bytes":wire::MAX_RESPONSE,
                    "max_requests":wire::MAX_REQUESTS,"max_connections":MAX_CONNECTIONS,
                    "publisher_key":hex::encode(broker.authority.publisher.as_bytes()),
                    "name":broker.authority.name,"manifest_id":hex::encode(broker.authority.manifest_id),
                    "authority_expires_unix_seconds":broker.authority.expires}),
                wire::Operation::Status {} => json!({"version":wire::VERSION,"id":request.id,
                    "event":"status","state":if metadata.is_some() { "ready" } else { "unavailable" },
                    "snapshot":metadata}),
                wire::Operation::Fetch {} => {
                    let cached = broker.cached.as_ref().ok_or("unavailable")?;
                    json!({"version":wire::VERSION,"id":request.id,"event":"snapshot",
                        "snapshot":metadata.ok_or("unavailable")?,"filters":cached.download.text,
                        "manifest_hex":hex::encode(&cached.download.signed_manifest)})
                }
            })
        }).unwrap_or_else(|code| wire::error(Some(&request.id), code))
    }

    fn live_response(&self) -> Result<()> {
        self.access(|broker| {
            let now = broker.check()?;
            broker.validate_cached(now).map(|_| ())
        })
        .map_err(anyhow::Error::msg)
    }
}

async fn connection(mut stream: UnixStream, service: Arc<Service>) -> Result<()> {
    ensure!(
        stream.peer_cred()?.uid() == nix::unistd::geteuid().as_raw(),
        "wrong_peer"
    );
    let mut ids = BTreeSet::new();
    let mut handshaken = false;
    for _ in 0..wire::MAX_REQUESTS {
        let request = match wire::read(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(_) => {
                wire::write(
                    &mut stream,
                    &wire::encode(&wire::error(None, "invalid_request"))?,
                    || Ok(()),
                )
                .await?;
                return Ok(());
            }
        };
        let value = if !ids.insert(request.id.clone()) {
            wire::error(Some(&request.id), "duplicate_request")
        } else if !handshaken && !matches!(request.operation, wire::Operation::Capabilities {}) {
            wire::error(Some(&request.id), "handshake_required")
        } else {
            let value = service.response(&request).await;
            if value["event"] == "capabilities" {
                handshaken = true;
            }
            value
        };
        let authorized = value["event"] != "error";
        if authorized {
            service.live_response()?;
        }
        let bytes = wire::encode(&value)?;
        // Recheck original authority, signature, bytes and expiry after serialization.
        if authorized {
            service.live_response()?;
        }
        wire::write(&mut stream, &bytes, || {
            if authorized {
                service.live_response()
            } else {
                Ok(())
            }
        })
        .await?;
    }
    Ok(())
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

fn bind(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    absolute(path)?;
    private_directory(path.parent().context("socket_parent")?)?;
    ensure!(
        path.as_os_str().len() <= 100
            && fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "socket_exists_or_invalid"
    );
    let listener = UnixListener::bind(path)?;
    let info = fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        device: info.dev(),
        inode: info.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok((listener, guard))
}

pub(crate) async fn run(options: &Options, control: &Path) -> Result<()> {
    private_directory(&options.work_parent)?;
    // The system agent and desktop broker may have different UIDs. Do not open,
    // chmod or adopt the agent's cache; its existing reuse-only handler enforces
    // ownership, index integrity and durable revision floors.
    absolute(&options.cache)?;
    let authority = Authority::load(&options.authority)?;
    let source = public_text::TextSource {
        publisher_key: authority.publisher,
        name: authority.name.clone(),
        manifest_id: authority.manifest_id,
        cache: options.cache.clone(),
        reuse_cache: true,
        limits: options.limits.clone(),
    };
    let broker = Broker::new(authority, Sample::now()?)?;
    if !options.execute {
        println!(
            "{}",
            json!({"version":1,"operation":"content_filter_service_plan","execute":false,
            "same_uid_only":true,"public_content_only":true,"fixed_publication":true,
            "browser_activation":false,"protected_fetch_on_request_only":true})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "unprivileged_user_required"
    );
    let service = Arc::new(Service {
        broker: Mutex::new(broker),
        fetch_slot: tokio::sync::Mutex::new(()),
        source,
        control: control.to_owned(),
        work_parent: options.work_parent.clone(),
    });
    let (listener, _guard) = bind(&options.socket)?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = match accepted { Ok(value) => value, Err(error) => break Err(error.into()) };
                if connections.len() >= MAX_CONNECTIONS
                    || stream.peer_cred().map(|peer| peer.uid()).ok() != Some(nix::unistd::geteuid().as_raw()) {
                    continue;
                }
                connections.spawn(connection(stream, service.clone()));
            }
        }
    };
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    drop(listener);
    result
}
