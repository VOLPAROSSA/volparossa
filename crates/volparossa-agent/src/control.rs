//! Protected local CLI socket and typed operation dispatch.

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use nix::unistd::{Gid, chown, geteuid};
use thiserror::Error;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use volparossa_config::{Config, RolesConfig};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ConnectRequest, ControlRequest, ControlResponse, ControlResult,
    Empty, LogLevel, NodeRole, SessionTransport, control_request, control_response, read_request,
    write_response,
};

use crate::{
    discovery::{DiscoveryControlError, DiscoveryControlHandle, RoleApplyError},
    helper::HelperClient,
    route_setup::{ClientRouteConnectError, ClientRouteControl, ClientRouteProgress},
    state::AgentState,
    unix_millis,
};

const MAX_CONTROL_CONNECTIONS: usize = 32;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared operation dependencies. No privileged network primitive is exposed.
#[derive(Clone)]
pub struct ControlContext {
    /// Mutable privacy-safe state.
    pub state: Arc<RwLock<AgentState>>,
    /// Immutable validated product configuration.
    pub config: Arc<Config>,
    /// Bounded typed access to the role-owning discovery actor.
    pub discovery: DiscoveryControlHandle,
    /// Narrow helper client.
    pub helper: HelperClient,
    /// Affine owner of the current client route bootstrap, if any.
    pub routes: ClientRouteControl,
}

/// Listener plus an inode-bound cleanup guard.
pub struct BoundControlSocket {
    listener: UnixListener,
    guard: SocketGuard,
}

impl BoundControlSocket {
    /// Splits the endpoint while keeping the guard alive in the caller.
    pub fn into_parts(self) -> (UnixListener, SocketGuard) {
        (self.listener, self.guard)
    }
}

/// Binds a `0660` socket and adopts the trusted parent directory's group.
pub fn bind_control_socket(path: &Path) -> Result<BoundControlSocket, ControlServerError> {
    let parent = path.parent().ok_or(ControlServerError::UnsafeParent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != geteuid().as_raw()
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(ControlServerError::UnsafeParent);
    }
    remove_stale_socket(path, parent_metadata.gid())?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    chown(path, None, Some(Gid::from_raw(parent_metadata.gid())))
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.gid() != parent_metadata.gid()
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(ControlServerError::UnsafeSocket);
    }
    Ok(BoundControlSocket {
        listener,
        guard: SocketGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    })
}

fn remove_stale_socket(path: &Path, expected_gid: u32) -> Result<(), ControlServerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ControlServerError::Io(error)),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(ControlServerError::UnsafeSocket);
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Serves one bounded request per connection until shutdown.
pub async fn serve_control(
    listener: UnixListener,
    context: ControlContext,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ControlServerError> {
    let permits = Arc::new(Semaphore::new(MAX_CONTROL_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    continue;
                };
                let request_context = context.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    Box::pin(process_connection(stream, request_context)).await
                });
            }
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if joined.is_err() {
                    tracing::warn!(diagnostic_code = "CONTROL_TASK_FAILED", "control task failed");
                }
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn process_connection(
    mut stream: UnixStream,
    context: ControlContext,
) -> Result<(), ControlServerError> {
    let request = timeout(CONTROL_TIMEOUT, read_request(&mut stream))
        .await
        .map_err(|_| ControlServerError::Timeout)?
        .map_err(|_| ControlServerError::InvalidFrame)?;
    let response = Box::pin(handle_request(request, &context)).await;
    timeout(CONTROL_TIMEOUT, write_response(&mut stream, &response))
        .await
        .map_err(|_| ControlServerError::Timeout)?
        .map_err(|_| ControlServerError::InvalidFrame)
}

async fn handle_request(request: ControlRequest, context: &ControlContext) -> ControlResponse {
    let request_id = request.request_id;
    let Some(operation) = request.operation else {
        return response(
            request_id,
            ControlResult::InvalidRequest,
            "INVALID_REQUEST",
            control_response::Payload::Ack(Empty {}),
        );
    };
    match operation {
        control_request::Operation::Status(_) => {
            let status = context.state.read().await.status();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Status(status),
            )
        }
        control_request::Operation::Connect(connect) => {
            Box::pin(connect_response(request_id, connect, context)).await
        }
        control_request::Operation::Disconnect(_) => {
            Box::pin(disconnect_response(request_id, context)).await
        }
        control_request::Operation::Peers(_) => {
            let peers = context.state.read().await.peer_list();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Peers(peers),
            )
        }
        control_request::Operation::Paths(_) => {
            let paths = context.state.read().await.path_list();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Paths(paths),
            )
        }
        control_request::Operation::Sessions(_) => {
            let sessions = context.state.read().await.session_list();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Sessions(sessions),
            )
        }
        control_request::Operation::PolicyStatus(_) => {
            let policy = context.state.read().await.policy_snapshot(unix_millis());
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Policy(policy),
            )
        }
        control_request::Operation::SetRole(change) => {
            set_role_response(request_id, change.role, change.enabled, context).await
        }
        control_request::Operation::Roles(_) => {
            let roles = context.state.read().await.role_snapshot();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Roles(roles),
            )
        }
        control_request::Operation::Logs(query) => {
            let logs = context
                .state
                .read()
                .await
                .logs(usize::try_from(query.maximum_records).unwrap_or(1_000));
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Logs(logs),
            )
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the control boundary maps every fail-closed route phase to one stable diagnostic"
)]
async fn connect_response(
    request_id: Vec<u8>,
    request: ConnectRequest,
    context: &ControlContext,
) -> ControlResponse {
    {
        let mut state = context.state.write().await;
        if !state.roles().client {
            return response(
                request_id,
                ControlResult::InvalidState,
                "CLIENT_ROLE_DISABLED",
                control_response::Payload::Ack(Empty {}),
            );
        }
        if !state.policy_active(unix_millis()) {
            state.record_policy_rejection();
            state.log(LogLevel::Warn, "CONNECT_POLICY_UNAVAILABLE", unix_millis());
            return response(
                request_id,
                ControlResult::Policy,
                "POLICY_UNAVAILABLE",
                control_response::Payload::Ack(Empty {}),
            );
        }
    }
    let Some(profile) = requested_connect_profile(&context.config, request.transport) else {
        context
            .state
            .write()
            .await
            .log(LogLevel::Warn, "CONNECT_PROFILE_INVALID", unix_millis());
        return response(
            request_id,
            ControlResult::InvalidRequest,
            "CLIENT_ROUTE_PROFILE_INVALID",
            control_response::Payload::Ack(Empty {}),
        );
    };
    let (result, diagnostic, log_code, log_level) = match Box::pin(context.routes.connect(
        &profile,
        &context.discovery,
        &context.helper,
    ))
    .await
    {
        Ok(ClientRouteProgress::TransportActive) => (
            ControlResult::Ok,
            "OK",
            "CONNECT_ROUTE_ESTABLISHED",
            LogLevel::Info,
        ),
        Ok(ClientRouteProgress::UdpRouteReady) => (
            ControlResult::Ok,
            "UDP_ROUTE_READY",
            "CONNECT_UDP_ROUTE_READY",
            LogLevel::Info,
        ),
        Err(ClientRouteConnectError::Busy) => (
            ControlResult::InvalidState,
            "CONNECT_ALREADY_IN_PROGRESS",
            "CONNECT_ALREADY_IN_PROGRESS",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::InvalidProfile) => (
            ControlResult::InvalidRequest,
            "CLIENT_ROUTE_PROFILE_INVALID",
            "CONNECT_PROFILE_INVALID",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::PreselectionUnavailable) => (
            ControlResult::Unavailable,
            "PRESELECTION_UNAVAILABLE",
            "CONNECT_PRESELECTION_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativePermitUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_PERMIT_UNAVAILABLE",
            "CONNECT_NATIVE_PERMIT_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeRelayUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_RELAY_READY_UNAVAILABLE",
            "CONNECT_NATIVE_RELAY_READY_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeHelperPrepareUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_HELPER_PREPARE_UNAVAILABLE",
            "CONNECT_NATIVE_HELPER_PREPARE_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeAuthorizationUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_PROBE_AUTHORIZE_UNAVAILABLE",
            "CONNECT_NATIVE_PROBE_AUTHORIZE_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeHelperActivateUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_HELPER_ACTIVATE_UNAVAILABLE",
            "CONNECT_NATIVE_HELPER_ACTIVATE_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeStartUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_PROBE_START_UNAVAILABLE",
            "CONNECT_NATIVE_PROBE_START_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeHelperCommitUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_HELPER_COMMIT_UNAVAILABLE",
            "CONNECT_NATIVE_HELPER_COMMIT_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeProofUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_PROBE_PROOF_UNAVAILABLE",
            "CONNECT_NATIVE_PROBE_PROOF_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeSamplerRetirementUnavailable) => (
            ControlResult::Helper,
            "NATIVE_SAMPLER_RETIREMENT_UNAVAILABLE",
            "CONNECT_NATIVE_SAMPLER_RETIREMENT_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeRemoteRetirementUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_REMOTE_RETIREMENT_UNAVAILABLE",
            "CONNECT_NATIVE_REMOTE_RETIREMENT_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::NativeTransportIdentityUnavailable) => (
            ControlResult::Unavailable,
            "NATIVE_TRANSPORT_IDENTITY_UNAVAILABLE",
            "CONNECT_NATIVE_TRANSPORT_IDENTITY_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::RouteAdmissionUnavailable) => (
            ControlResult::Unavailable,
            "ROUTE_ADMISSION_UNAVAILABLE",
            "CONNECT_ROUTE_ADMISSION_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable) => (
            ControlResult::Unavailable,
            "MPTCP_EXIT_LISTENER_SIGNAL_UNAVAILABLE",
            "CONNECT_MPTCP_EXIT_LISTENER_SIGNAL_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::TransportRuntimeUnavailable) => (
            ControlResult::Unavailable,
            "TRANSPORT_RUNTIME_UNAVAILABLE",
            "CONNECT_TRANSPORT_RUNTIME_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::UdpExitSessionSignalUnavailable) => (
            ControlResult::Unavailable,
            "UDP_EXIT_SESSION_SIGNAL_UNAVAILABLE",
            "CONNECT_UDP_EXIT_SESSION_SIGNAL_UNAVAILABLE",
            LogLevel::Warn,
        ),
        Err(ClientRouteConnectError::UdpIngressUnavailable) => (
            ControlResult::Unavailable,
            "UDP_INGRESS_UNAVAILABLE",
            "CONNECT_UDP_INGRESS_UNAVAILABLE",
            LogLevel::Warn,
        ),
    };
    context
        .state
        .write()
        .await
        .log(log_level, log_code, unix_millis());
    response(
        request_id,
        result,
        diagnostic,
        control_response::Payload::Ack(Empty {}),
    )
}

fn requested_connect_profile(config: &Config, transport: Option<i32>) -> Option<Config> {
    if !config.roles.client || config.validate().is_err() {
        return None;
    }
    let Some(transport) = transport else {
        return Some(config.clone());
    };
    let transport = SessionTransport::try_from(transport).ok()?;
    let enabled = match transport {
        SessionTransport::Mptcp => config.tcp.enabled,
        SessionTransport::SinglePathUdp => config.udp.enabled,
        SessionTransport::MultipathQuic => config.quic.enabled,
    };
    if !enabled {
        return None;
    }
    let mut profile = config.clone();
    profile.tcp.enabled = transport == SessionTransport::Mptcp;
    profile.udp.enabled = transport == SessionTransport::SinglePathUdp;
    profile.quic.enabled = transport == SessionTransport::MultipathQuic;
    Some(profile)
}

async fn disconnect_response(request_id: Vec<u8>, context: &ControlContext) -> ControlResponse {
    Box::pin(context.routes.disconnect()).await;
    if context.helper.cleanup_route_contexts().await.is_ok() {
        let mut state = context.state.write().await;
        if state.clear_after_helper_cleanup(&context.config).is_err() {
            state.log(LogLevel::Error, "STATE_RESET_FAILED", unix_millis());
            return response(
                request_id,
                ControlResult::Unavailable,
                "STATE_RESET_FAILED",
                control_response::Payload::Ack(Empty {}),
            );
        }
        state.log(LogLevel::Info, "HELPER_CLEANUP_COMPLETE", unix_millis());
        response(
            request_id,
            ControlResult::Ok,
            "OK",
            control_response::Payload::Ack(Empty {}),
        )
    } else {
        context
            .state
            .write()
            .await
            .log(LogLevel::Error, "HELPER_CLEANUP_FAILED", unix_millis());
        response(
            request_id,
            ControlResult::Helper,
            "HELPER_UNAVAILABLE",
            control_response::Payload::Ack(Empty {}),
        )
    }
}

async fn set_role_response(
    request_id: Vec<u8>,
    raw_role: i32,
    enabled: bool,
    context: &ControlContext,
) -> ControlResponse {
    let Ok(role) = NodeRole::try_from(raw_role) else {
        return response(
            request_id,
            ControlResult::InvalidRequest,
            "INVALID_ROLE",
            control_response::Payload::Ack(Empty {}),
        );
    };
    let current = context.state.read().await.roles();
    let candidate = changed_roles(current, role, enabled);
    let mut validated = (*context.config).clone();
    validated.roles = candidate;
    if validated.validate().is_err() {
        return response(
            request_id,
            ControlResult::InvalidState,
            "ROLE_PREREQUISITES",
            control_response::Payload::Ack(Empty {}),
        );
    }
    if role == NodeRole::Exit && enabled && !context.state.read().await.policy_active(unix_millis())
    {
        context.state.write().await.record_policy_rejection();
        return response(
            request_id,
            ControlResult::Policy,
            "POLICY_UNAVAILABLE",
            control_response::Payload::Ack(Empty {}),
        );
    }
    match context.discovery.set_roles(current, candidate).await {
        Ok(_) => {
            let roles = context.state.read().await.role_snapshot();
            response(
                request_id,
                ControlResult::Ok,
                "OK",
                control_response::Payload::Roles(roles),
            )
        }
        Err(DiscoveryControlError::Actor(RoleApplyError::Prerequisites)) => response(
            request_id,
            ControlResult::InvalidState,
            "ROLE_PREREQUISITES",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Actor(RoleApplyError::PolicyUnavailable)) => {
            context.state.write().await.record_policy_rejection();
            response(
                request_id,
                ControlResult::Policy,
                "POLICY_UNAVAILABLE",
                control_response::Payload::Ack(Empty {}),
            )
        }
        Err(DiscoveryControlError::Actor(RoleApplyError::Persistence)) => response(
            request_id,
            ControlResult::Unavailable,
            "ROLE_PERSIST_FAILED",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Actor(RoleApplyError::ServiceUnavailable)) => response(
            request_id,
            ControlResult::Unavailable,
            "ROLE_SERVICE_INIT_FAILED",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Actor(RoleApplyError::RestartRequired)) => response(
            request_id,
            ControlResult::InvalidState,
            "ROLE_RESTART_REQUIRED",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Actor(RoleApplyError::StateDiverged)) => response(
            request_id,
            ControlResult::InvalidState,
            "ROLE_TRANSACTION_CONFLICT",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Busy) => response(
            request_id,
            ControlResult::Unavailable,
            "ROLE_ACTOR_BUSY",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Closed) => response(
            request_id,
            ControlResult::Unavailable,
            "ROLE_ACTOR_UNAVAILABLE",
            control_response::Payload::Ack(Empty {}),
        ),
        Err(DiscoveryControlError::Timeout) => response(
            request_id,
            ControlResult::Unavailable,
            "ROLE_TRANSACTION_UNKNOWN",
            control_response::Payload::Ack(Empty {}),
        ),
    }
}

const fn changed_roles(current: RolesConfig, role: NodeRole, enabled: bool) -> RolesConfig {
    match role {
        NodeRole::Client => RolesConfig {
            client: enabled,
            ..current
        },
        NodeRole::Relay => RolesConfig {
            relay: enabled,
            ..current
        },
        NodeRole::Exit => RolesConfig {
            exit: enabled,
            ..current
        },
    }
}

fn response(
    request_id: Vec<u8>,
    result: ControlResult,
    diagnostic_code: &'static str,
    payload: control_response::Payload,
) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id,
        result: result as i32,
        diagnostic_code: diagnostic_code.to_owned(),
        payload: Some(payload),
    }
}

/// Inode-bound socket unlink guard.
pub struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Control endpoint failure.
#[derive(Debug, Error)]
pub enum ControlServerError {
    /// Socket filesystem I/O failed.
    #[error("local control socket I/O failed")]
    Io(#[from] std::io::Error),
    /// Parent directory can be replaced or modified by control clients.
    #[error("local control socket parent is unsafe")]
    UnsafeParent,
    /// Existing or newly created endpoint has unsafe type/ownership/mode.
    #[error("local control socket metadata is unsafe")]
    UnsafeSocket,
    /// A client exceeded the request deadline.
    #[error("local control request timed out")]
    Timeout,
    /// A client sent or triggered an invalid bounded frame.
    #[error("local control frame is invalid")]
    InvalidFrame,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn bound_socket_is_exactly_0660_and_guard_removes_only_its_inode() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let socket = directory.path().join("agent.sock");
        let endpoint = bind_control_socket(&socket).expect("bind");
        assert_eq!(
            fs::symlink_metadata(&socket).expect("metadata").mode() & 0o777,
            0o660
        );
        drop(endpoint);
        assert!(!socket.exists());
    }

    #[test]
    fn client_role_change_preserves_service_consent_and_honors_disable() {
        let roles = RolesConfig {
            client: true,
            relay: true,
            exit: true,
        };
        assert_eq!(
            changed_roles(roles, NodeRole::Client, false),
            RolesConfig {
                client: false,
                relay: true,
                exit: true,
            }
        );

        let dormant = RolesConfig::default();
        assert_eq!(changed_roles(dormant, NodeRole::Client, false), dormant);
        assert_eq!(
            changed_roles(dormant, NodeRole::Client, true),
            RolesConfig {
                client: true,
                relay: false,
                exit: false,
            }
        );
        let candidate = Config {
            roles: changed_roles(dormant, NodeRole::Client, true),
            ..Config::default()
        };
        assert!(candidate.validate().is_err());
        assert!(requested_connect_profile(&candidate, None).is_none());
    }

    #[test]
    fn dormant_node_cannot_request_a_client_transport_profile() {
        let config = Config::default();
        for transport in [
            None,
            Some(SessionTransport::Mptcp as i32),
            Some(SessionTransport::SinglePathUdp as i32),
            Some(SessionTransport::MultipathQuic as i32),
        ] {
            assert!(requested_connect_profile(&config, transport).is_none());
        }
    }

    #[test]
    fn explicit_connect_transport_selects_only_that_enabled_product_path() {
        let config = Config {
            runtime_mode: volparossa_config::RuntimeMode::Development,
            roles: RolesConfig {
                client: true,
                relay: false,
                exit: false,
            },
            ..Config::default()
        };
        for (transport, expected) in [
            (SessionTransport::Mptcp, (true, false, false)),
            (SessionTransport::SinglePathUdp, (false, true, false)),
            (SessionTransport::MultipathQuic, (false, false, true)),
        ] {
            let profile = requested_connect_profile(&config, Some(transport as i32))
                .expect("enabled transport profile");
            assert_eq!(
                (
                    profile.tcp.enabled,
                    profile.udp.enabled,
                    profile.quic.enabled
                ),
                expected
            );
        }

        let mut disabled = config;
        disabled.quic.enabled = false;
        assert!(
            requested_connect_profile(&disabled, Some(SessionTransport::MultipathQuic as i32))
                .is_none()
        );
    }
}
