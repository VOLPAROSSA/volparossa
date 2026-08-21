//! Unprivileged VOLPAROSSA service orchestration.
//!
//! This crate owns identity loading, decentralised discovery, privacy-safe
//! peer persistence, threshold policy verification, local control, bounded
//! selection/reservation state, and the typed helper boundary. It performs no
//! direct route, firewall, DNS, namespace, `WireGuard`, or sysctl operations.

#![forbid(unsafe_code)]

mod advertisement;
mod control;
mod discovery;
mod endpoint_leases;
#[path = "helper_v3.rs"]
pub mod helper;
mod paths;
mod policy;
mod roles;
mod route_setup;
mod secret;
mod state;

use std::{
    fs::{self, OpenOptions},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio::{
    sync::{RwLock, watch},
    task::JoinHandle,
};
use volparossa_config::Config;
use volparossa_identity::IdentityStore;
use volparossa_local_control::LogLevel;
use volparossa_metrics::{LocalMetricsEndpoint, MetricsRegistry};
use volparossa_peerstore::PeerStore;

use control::{ControlContext, bind_control_socket, serve_control};
use discovery::{DiscoveryControlHandle, DiscoveryRuntime, DiscoveryRuntimeResources};
use helper::HelperClient;
use policy::load_active_policy;
use roles::{RoleStore, ensure_private_state_directory};
use secret::read_identity_credential;
use state::AgentState;

pub use paths::{
    AgentPaths, DEFAULT_CONFIG, DEFAULT_CONTROL_SOCKET, DEFAULT_HELPER_SOCKET,
    DEFAULT_MPQUIC_SOCKET, DEFAULT_STATE_DIRECTORY, IDENTITY_CREDENTIAL_NAME, PathError,
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

/// Fully loaded unprivileged service.
pub struct Agent {
    paths: AgentPaths,
    config: Arc<Config>,
    state: Arc<RwLock<AgentState>>,
    helper: HelperClient,
    discovery: DiscoveryRuntime,
    discovery_control: DiscoveryControlHandle,
    metrics: MetricsRegistry,
}

impl Agent {
    /// Validates local files, decrypts the identity from a protected systemd
    /// credential, opens the peerstore, and constructs the real discovery swarm.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe local state, invalid configuration or identity, an unavailable
    /// peerstore, or discovery construction failure.
    pub fn load(paths: AgentPaths) -> Result<Self, AgentError> {
        paths.validate()?;
        ensure_private_state_directory(&paths.state_directory)?;
        validate_integrity_file(&paths.config, MAX_CONFIG_BYTES)?;
        let config = Config::from_path(&paths.config)?;
        let passphrase = read_identity_credential(&paths.identity_credential)?;
        let identity = IdentityStore::new(&paths.identity).load(&passphrase)?;
        let role_store = RoleStore::new(paths.roles.clone());
        let roles = role_store.load_or_initialize(config.roles)?;
        let mut effective = config.clone();
        effective.roles = roles;
        effective.validate()?;
        let (active_policy, policy_failed) =
            match load_active_policy(&config, &paths.policy_trust, unix_millis()) {
                Ok(policy) => (policy, false),
                Err(_) => (None, true),
            };
        prepare_peerstore(&paths.peerstore)?;
        let peerstore = PeerStore::open(&paths.peerstore)?;
        fs::set_permissions(&paths.peerstore, fs::Permissions::from_mode(0o600))?;
        let metrics = MetricsRegistry::new();
        let mut state = AgentState::new(&config, roles, active_policy.clone(), metrics.clone())?;
        let (discovery, discovery_control) = DiscoveryRuntime::new(
            identity,
            &config,
            peerstore,
            paths.state_directory.join("advertisement.sequence"),
            DiscoveryRuntimeResources {
                roles,
                policy: active_policy,
                role_store,
                metrics: metrics.clone(),
            },
        )?;
        state.log(LogLevel::Info, "AGENT_INITIALIZED", unix_millis());
        if policy_failed {
            state.log(LogLevel::Warn, "POLICY_LOAD_FAILED", unix_millis());
        } else if state.policy_active(unix_millis()) {
            state.log(LogLevel::Info, "POLICY_ACTIVE", unix_millis());
        } else {
            state.log(LogLevel::Warn, "POLICY_UNAVAILABLE", unix_millis());
        }
        match socket_path_present(&paths.mpquic_socket) {
            Ok(true) => state.log(LogLevel::Info, "MPQUIC_SOCKET_PRESENT", unix_millis()),
            Ok(false) => state.log(LogLevel::Warn, "MPQUIC_SOCKET_ABSENT", unix_millis()),
            Err(()) => state.log(LogLevel::Warn, "MPQUIC_SOCKET_UNSAFE", unix_millis()),
        }
        let helper = HelperClient::new(paths.helper_socket.clone(), paths.helper_token.clone());
        Ok(Self {
            paths,
            config: Arc::new(config),
            state: Arc::new(RwLock::new(state)),
            helper,
            discovery,
            discovery_control,
            metrics,
        })
    }

    /// Runs until the supplied shutdown future resolves. Tests can inject an
    /// isolated shutdown signal without touching host networking.
    ///
    /// # Errors
    ///
    /// Returns an error when a service actor, local endpoint, or required helper cleanup fails.
    pub async fn run_with_shutdown<F>(self, shutdown: F) -> Result<(), AgentError>
    where
        F: Future<Output = ()> + Send,
    {
        let endpoint = bind_control_socket(&self.paths.control_socket)?;
        let (listener, socket_guard) = endpoint.into_parts();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let control_context = ControlContext {
            state: Arc::clone(&self.state),
            config: Arc::clone(&self.config),
            discovery: self.discovery_control.clone(),
            helper: self.helper.clone(),
        };
        let mut control_task = tokio::spawn(serve_control(
            listener,
            control_context,
            shutdown_rx.clone(),
        ));
        let discovery_state = Arc::clone(&self.state);
        let mut discovery_task =
            tokio::spawn(self.discovery.run(discovery_state, shutdown_rx.clone()));
        let maintenance_state = Arc::clone(&self.state);
        let maintenance_config = Arc::clone(&self.config);
        let maintenance_trust = self.paths.policy_trust.clone();
        let maintenance_discovery = self.discovery_control.clone();
        let mut maintenance_task = tokio::spawn(run_maintenance(
            maintenance_state,
            maintenance_config,
            maintenance_trust,
            maintenance_discovery,
            shutdown_rx,
        ));
        let mut metrics_task = tokio::spawn(run_metrics_endpoint(
            self.config.privacy.metrics_enabled,
            self.config.privacy.metrics_port,
            self.metrics.clone(),
            shutdown_tx.subscribe(),
        ));

        tokio::pin!(shutdown);
        let run_result = tokio::select! {
            () = &mut shutdown => Ok(()),
            result = &mut control_task => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(AgentError::Control(error)),
                Err(_) => Err(AgentError::Task),
            },
            _ = &mut discovery_task => Err(AgentError::Task),
            _ = &mut maintenance_task => Err(AgentError::Task),
            result = &mut metrics_task => match result {
                Ok(Err(error)) => Err(AgentError::Metrics(error)),
                Ok(Ok(())) | Err(_) => Err(AgentError::Task),
            },
        };
        let _ = shutdown_tx.send(true);
        stop_task(&mut control_task).await;
        stop_task(&mut discovery_task).await;
        stop_task(&mut maintenance_task).await;
        stop_task(&mut metrics_task).await;
        drop(socket_guard);

        if self.state.read().await.has_network_state() {
            self.helper
                .cleanup_owned()
                .await
                .map_err(|_| AgentError::ShutdownCleanup)?;
        }
        run_result
    }
}

async fn stop_task<T>(task: &mut JoinHandle<T>) {
    if tokio::time::timeout(Duration::from_secs(5), &mut *task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn run_metrics_endpoint(
    enabled: bool,
    port: u16,
    registry: MetricsRegistry,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), volparossa_metrics::MetricsError> {
    if !enabled {
        wait_for_shutdown(&mut shutdown).await;
        return Ok(());
    }
    let endpoint =
        LocalMetricsEndpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), registry).await?;
    endpoint
        .serve(async move {
            wait_for_shutdown(&mut shutdown).await;
        })
        .await
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

async fn run_maintenance(
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    trust_path: std::path::PathBuf,
    discovery: DiscoveryControlHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(MAINTENANCE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                let now_ms = unix_millis();
                let was_active = state.read().await.policy_active(now_ms);
                let (policy, policy_load_failed) = match load_active_policy(
                    &config,
                    &trust_path,
                    now_ms,
                ) {
                    Ok(policy) => (policy, false),
                    Err(_) => (None, true),
                };
                let is_active = policy
                        .as_ref()
                        .is_some_and(|manifest| manifest.ensure_active_at(now_ms).is_ok());
                if discovery.apply_policy(policy).await.is_err() {
                    state.write().await.log(
                        LogLevel::Error,
                        "POLICY_ACTOR_REFRESH_FAILED",
                        now_ms,
                    );
                    break;
                }
                let mut state = state.write().await;
                if policy_load_failed {
                    if was_active {
                        state.log(LogLevel::Error, "POLICY_LOAD_FAILED", now_ms);
                    }
                } else if is_active != was_active {
                    state.log(
                        if is_active { LogLevel::Info } else { LogLevel::Warn },
                        if is_active { "POLICY_ACTIVE" } else { "POLICY_UNAVAILABLE" },
                        now_ms,
                    );
                }
            }
        }
    }
}

fn validate_integrity_file(path: &Path, maximum: u64) -> Result<(), AgentError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AgentError::UnsafeConfig);
    }
    Ok(())
}

fn prepare_peerstore(path: &Path) -> Result<(), AgentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if peerstore_metadata_is_safe(&metadata) => Ok(()),
        Ok(_) => Err(AgentError::UnsafePeerstore),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;
            let metadata = file.metadata()?;
            if !peerstore_metadata_is_safe(&metadata) {
                return Err(AgentError::UnsafePeerstore);
            }
            file.sync_all()?;
            Ok(())
        }
        Err(error) => Err(AgentError::Io(error)),
    }
}

fn peerstore_metadata_is_safe(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.nlink() == 1
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o777 == 0o600
}

fn socket_path_present(path: &Path) -> Result<bool, ()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(_) | Err(_) => Err(()),
    }
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

pub(crate) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Agent startup, runtime, or cleanup failure.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Packaged paths were unsafe.
    #[error("agent path configuration is invalid")]
    Path(#[from] PathError),
    /// Local filesystem I/O failed.
    #[error("agent local filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// YAML configuration was malformed or unsafe.
    #[error("agent configuration is invalid")]
    Config(#[from] volparossa_config::ConfigError),
    /// Configuration file type, mode, or size was unsafe.
    #[error("agent configuration file is unsafe")]
    UnsafeConfig,
    /// State directory or role file was unsafe.
    #[error("agent role state is invalid")]
    Roles(#[from] roles::RoleStoreError),
    /// Protected passphrase credential was unavailable or unsafe.
    #[error("agent identity credential is unavailable")]
    Credential(#[from] secret::CredentialError),
    /// Encrypted identity could not be authenticated.
    #[error("agent identity could not be loaded")]
    Identity(#[from] volparossa_identity::IdentityError),
    /// Existing peerstore was unsafe.
    #[error("agent peerstore file is unsafe")]
    UnsafePeerstore,
    /// `SQLite` peerstore failed.
    #[error("agent peerstore is unavailable")]
    Peerstore(#[from] volparossa_peerstore::PeerStoreError),
    /// Discovery could not be safely constructed.
    #[error("agent discovery is unavailable")]
    Discovery(#[from] discovery::DiscoveryRuntimeError),
    /// Bounded selection/reservation state could not be built.
    #[error("agent runtime state is invalid")]
    State(#[from] state::StateError),
    /// Local control endpoint failed.
    #[error("agent control endpoint failed")]
    Control(#[from] control::ControlServerError),
    /// Loopback-only aggregate metrics endpoint failed.
    #[error("agent metrics endpoint failed")]
    Metrics(#[source] volparossa_metrics::MetricsError),
    /// A required actor ended unexpectedly.
    #[error("agent runtime task ended unexpectedly")]
    Task,
    /// Known helper-owned network state could not be cleaned up.
    #[error("agent shutdown cleanup could not be confirmed")]
    ShutdownCleanup,
}

impl AgentError {
    /// Stable code suitable for logs without leaking input or secret data.
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Path(_) => "PATH_INVALID",
            Self::Io(_) => "LOCAL_IO_FAILED",
            Self::Config(_) | Self::UnsafeConfig => "CONFIG_INVALID",
            Self::Roles(_) => "ROLE_STATE_INVALID",
            Self::Credential(_) => "IDENTITY_CREDENTIAL_FAILED",
            Self::Identity(_) => "IDENTITY_LOAD_FAILED",
            Self::UnsafePeerstore | Self::Peerstore(_) => "PEERSTORE_FAILED",
            Self::Discovery(_) => "DISCOVERY_FAILED",
            Self::State(_) => "STATE_INVALID",
            Self::Control(_) => "CONTROL_FAILED",
            Self::Metrics(_) => "METRICS_FAILED",
            Self::Task => "RUNTIME_TASK_FAILED",
            Self::ShutdownCleanup => "SHUTDOWN_CLEANUP_FAILED",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn peerstore_is_created_owner_only_and_rejects_unsafe_existing_files() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("peers.sqlite3");

        prepare_peerstore(&path).expect("secure creation");
        let metadata = fs::symlink_metadata(&path).expect("peerstore metadata");
        assert!(peerstore_metadata_is_safe(&metadata));
        assert_eq!(metadata.mode() & 0o777, 0o600);
        prepare_peerstore(&path).expect("safe existing peerstore");
        let peerstore = PeerStore::open(&path).expect("SQLite opens pre-created file");
        drop(peerstore);
        assert!(peerstore_metadata_is_safe(
            &fs::symlink_metadata(&path).expect("metadata")
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weaken permissions");
        assert!(matches!(
            prepare_peerstore(&path),
            Err(AgentError::UnsafePeerstore)
        ));
    }

    #[test]
    fn peerstore_rejects_symlinks_and_hardlinks() {
        let directory = tempdir().expect("temporary directory");
        let target = directory.path().join("target.sqlite3");
        prepare_peerstore(&target).expect("secure target");
        let link = directory.path().join("link.sqlite3");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            prepare_peerstore(&link),
            Err(AgentError::UnsafePeerstore)
        ));

        let hardlink = directory.path().join("hardlink.sqlite3");
        fs::hard_link(&target, &hardlink).expect("hard link");
        assert!(matches!(
            prepare_peerstore(&target),
            Err(AgentError::UnsafePeerstore)
        ));
    }
}
