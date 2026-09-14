//! Protected local CLI socket and typed operation dispatch.

mod content_transfer;

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
    route_setup::{
        ClientRouteConnectError, ClientRouteControl, ClientRouteDisconnectError,
        ClientRouteProgress,
    },
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
    /// Separate affine owner shared by protected UDP and TCP DNS ingress.
    pub dns_routes: ClientRouteControl,
    /// Explicit unprivileged content publication/retrieval lifecycle.
    pub(crate) content: crate::content::ContentRuntime,
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
    if matches!(
        request.operation.as_ref(),
        Some(
            control_request::Operation::ContentDownloadHttps(_)
                | control_request::Operation::ContentFetchName(_)
                | control_request::Operation::MailboxRemote(_)
        )
    ) {
        let mut ready_sent = false;
        let result = match request.operation.as_ref() {
            Some(control_request::Operation::ContentDownloadHttps(download)) => {
                Box::pin(context.content.download_https(
                    download.clone(),
                    &context,
                    &mut stream,
                    &request.request_id,
                    &mut ready_sent,
                ))
                .await
            }
            Some(control_request::Operation::ContentFetchName(download)) => {
                Box::pin(context.content.fetch_name(
                    download.clone(),
                    &context,
                    &mut stream,
                    &request.request_id,
                    &mut ready_sent,
                ))
                .await
            }
            Some(control_request::Operation::MailboxRemote(remote)) => {
                Box::pin(context.content.mailbox_remote(
                    remote.clone(),
                    &context,
                    &mut stream,
                    &request.request_id,
                    &mut ready_sent,
                ))
                .await
            }
            _ => return Err(ControlServerError::InvalidFrame),
        };
        return match result {
            Ok(()) => Ok(()),
            Err(_) if ready_sent => Err(ControlServerError::InvalidFrame),
            Err(error) => timeout(
                CONTROL_TIMEOUT,
                write_response(
                    &mut stream,
                    &content_response(request.request_id, Err(error)),
                ),
            )
            .await
            .map_err(|_| ControlServerError::Timeout)?
            .map_err(|_| ControlServerError::InvalidFrame),
        };
    }
    if matches!(
        request.operation.as_ref(),
        Some(
            control_request::Operation::ContentImport(_)
                | control_request::Operation::ContentExport(_)
        )
    ) {
        return Box::pin(content_transfer::process(stream, request, Some(&context))).await;
    }
    let response = Box::pin(handle_request(request, &context)).await;
    timeout(CONTROL_TIMEOUT, write_response(&mut stream, &response))
        .await
        .map_err(|_| ControlServerError::Timeout)?
        .map_err(|_| ControlServerError::InvalidFrame)
}

#[allow(
    clippy::too_many_lines,
    reason = "One exhaustive typed local-operation dispatch"
)]
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
        control_request::Operation::ContentImport(_)
        | control_request::Operation::ContentExport(_)
        | control_request::Operation::ContentFetchName(_)
        | control_request::Operation::MailboxRemote(_)
        | control_request::Operation::ContentDownloadHttps(_) => {
            // These require the same authorized stream, never a second socket or generic dispatch.
            response(
                request_id,
                ControlResult::InvalidRequest,
                "CONTENT_STREAM_REQUIRED",
                control_response::Payload::Ack(Empty {}),
            )
        }
        control_request::Operation::ContentServe(request) => {
            content_response(request_id, context.content.serve(request, context).await)
        }
        control_request::Operation::MailboxServe(request) => content_response(
            request_id,
            context.content.mailbox_serve(request, context).await,
        ),
        control_request::Operation::ContentFetch(request) => content_response(
            request_id,
            Box::pin(context.content.fetch(request, context)).await,
        ),
        control_request::Operation::ContentFetchHttps(request) => content_response(
            request_id,
            Box::pin(context.content.fetch_https(request, context)).await,
        ),
        control_request::Operation::ContentStop(_) => {
            content_response(request_id, context.content.stop(&context.discovery).await)
        }
        control_request::Operation::ContentStatus(_) => {
            content_response(request_id, context.content.status(context).await)
        }
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
            Box::pin(disconnect_response(
                request_id,
                &context.routes,
                &context.dns_routes,
                &context.state,
            ))
            .await
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
            paths_response(request_id, &context.routes, &context.state).await
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

fn content_response(
    request_id: Vec<u8>,
    result: Result<volparossa_local_control::ContentReceipt, crate::content::ContentError>,
) -> ControlResponse {
    use crate::content::ContentError;
    match result {
        Ok(receipt) => response(
            request_id,
            ControlResult::Ok,
            "CONTENT_OK",
            control_response::Payload::Content(receipt),
        ),
        Err(error) => {
            let (result, code) = match error {
                ContentError::Invalid => (ControlResult::InvalidRequest, "CONTENT_INVALID"),
                ContentError::Unavailable => (ControlResult::Unavailable, "CONTENT_UNAVAILABLE"),
                ContentError::Busy => (ControlResult::InvalidState, "CONTENT_BUSY"),
                ContentError::Policy => (ControlResult::Policy, "CONTENT_POLICY"),
                ContentError::NameConflict => {
                    (ControlResult::InvalidState, "CONTENT_NAME_CONFLICT")
                }
                ContentError::NameRollback => {
                    (ControlResult::InvalidState, "CONTENT_NAME_ROLLBACK")
                }
            };
            response(
                request_id,
                result,
                code,
                control_response::Payload::Ack(Empty {}),
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
    let protected_dns = request.transport == Some(SessionTransport::ProtectedDns as i32);
    let progress = if protected_dns {
        match timeout(CONTROL_TIMEOUT, context.dns_routes.lock_dns_transaction()).await {
            Ok(_transaction) => {
                Box::pin(context.dns_routes.ensure_single_udp(
                    &profile,
                    &context.discovery,
                    &context.helper,
                ))
                .await
            }
            Err(_) => Err(ClientRouteConnectError::Busy),
        }
    } else {
        Box::pin(
            context
                .routes
                .connect(&profile, &context.discovery, &context.helper),
        )
        .await
    };
    let (result, diagnostic, log_code, log_level) = match progress {
        Ok(ClientRouteProgress::TransportActive) => (
            ControlResult::Ok,
            "OK",
            "CONNECT_ROUTE_ESTABLISHED",
            LogLevel::Info,
        ),
        Ok(ClientRouteProgress::UdpRouteReady) if protected_dns => (
            ControlResult::Ok,
            "DNS_ROUTE_READY",
            "CONNECT_DNS_ROUTE_READY",
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
        SessionTransport::SinglePathUdp | SessionTransport::ProtectedDns => config.udp.enabled,
        SessionTransport::MultipathQuic => config.quic.enabled,
    };
    if !enabled {
        return None;
    }
    let mut profile = config.clone();
    profile.tcp.enabled = transport == SessionTransport::Mptcp;
    profile.udp.enabled = matches!(
        transport,
        SessionTransport::SinglePathUdp | SessionTransport::ProtectedDns
    );
    profile.quic.enabled = transport == SessionTransport::MultipathQuic;
    Some(profile)
}

async fn paths_response(
    request_id: Vec<u8>,
    routes: &ClientRouteControl,
    state: &Arc<RwLock<AgentState>>,
) -> ControlResponse {
    if routes.refresh_mpquic_path_summaries().await.is_err() {
        return response(
            request_id,
            ControlResult::Unavailable,
            "MPQUIC_PATH_STATUS_UNAVAILABLE",
            control_response::Payload::Ack(Empty {}),
        );
    }
    let paths = state.read().await.path_list();
    response(
        request_id,
        ControlResult::Ok,
        "OK",
        control_response::Payload::Paths(paths),
    )
}

// Client Disconnect deliberately has no whole-helper authority: the same daemon may be
// forwarding unrelated Relay/Exit sessions and owning mesh/sharing resources at this moment.
async fn disconnect_response(
    request_id: Vec<u8>,
    routes: &ClientRouteControl,
    dns_routes: &ClientRouteControl,
    state: &Arc<RwLock<AgentState>>,
) -> ControlResponse {
    if let Err(error) = disconnect_client_routes(routes, dns_routes).await {
        let (result, diagnostic) = match error {
            ClientRouteDisconnectError::Busy => (ControlResult::Unavailable, "CLIENT_ROUTE_BUSY"),
            ClientRouteDisconnectError::CleanupPending => {
                (ControlResult::Helper, "CLIENT_CLEANUP_PENDING")
            }
        };
        state
            .write()
            .await
            .log(LogLevel::Warn, diagnostic, unix_millis());
        return response(
            request_id,
            result,
            diagnostic,
            control_response::Payload::Ack(Empty {}),
        );
    }
    // The controller clears the exact retired context before releasing its gate. A global
    // projection reset here could instead erase a newer concurrently established Client route.
    state
        .write()
        .await
        .log(LogLevel::Info, "CLIENT_CLEANUP_COMPLETE", unix_millis());
    response(
        request_id,
        ControlResult::Ok,
        "OK",
        control_response::Payload::Ack(Empty {}),
    )
}

/// Attempt both exact client owners concurrently; one failure must not leave the other untouched.
pub(crate) async fn disconnect_client_routes(
    routes: &ClientRouteControl,
    dns_routes: &ClientRouteControl,
) -> Result<(), ClientRouteDisconnectError> {
    let (main, dns) = tokio::join!(
        routes.disconnect_confirmed(),
        dns_routes.disconnect_confirmed()
    );
    match (main, dns) {
        (Err(ClientRouteDisconnectError::CleanupPending), _)
        | (_, Err(ClientRouteDisconnectError::CleanupPending)) => {
            Err(ClientRouteDisconnectError::CleanupPending)
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
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
        Ok(_) => role_snapshot_after_cleanup(request_id, candidate.client, context).await,
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

async fn role_snapshot_after_cleanup(
    request_id: Vec<u8>,
    client_enabled: bool,
    context: &ControlContext,
) -> ControlResponse {
    if !client_enabled {
        let cleanup = disconnect_response(
            request_id.clone(),
            &context.routes,
            &context.dns_routes,
            &context.state,
        )
        .await;
        if cleanup.result != ControlResult::Ok as i32 {
            return cleanup;
        }
    }
    let roles = context.state.read().await.role_snapshot();
    response(
        request_id,
        ControlResult::Ok,
        "OK",
        control_response::Payload::Roles(roles),
    )
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
    async fn paths_query_without_native_owner_preserves_non_mpquic_display() {
        let config = Config::default();
        let state = Arc::new(RwLock::new(
            AgentState::new(
                &config,
                config.roles,
                None,
                volparossa_metrics::MetricsRegistry::new(),
            )
            .unwrap(),
        ));
        let path = volparossa_local_control::PathSummary {
            route_context_id: vec![2; 16],
            path_id: 1,
            relay_peer_id: "relay".to_owned(),
            exit_peer_id: "exit".to_owned(),
            state: volparossa_local_control::PathState::Active as i32,
            ..Default::default()
        };
        state
            .write()
            .await
            .replace_single_udp_path(path.clone())
            .unwrap();
        let routes = ClientRouteControl::default();
        let result = paths_response(vec![1; 16], &routes, &state).await;
        assert_eq!(result.result, ControlResult::Ok as i32);
        let Some(control_response::Payload::Paths(paths)) = result.payload else {
            panic!("explicit paths response");
        };
        assert_eq!(paths.paths, vec![path]);
    }

    #[tokio::test]
    async fn idle_client_disconnect_needs_no_helper_and_preserves_contribution_roles() {
        let config = Config {
            roles: RolesConfig {
                client: true,
                relay: true,
                exit: true,
            },
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(
            AgentState::new(
                &config,
                config.roles,
                None,
                volparossa_metrics::MetricsRegistry::new(),
            )
            .expect("bounded state"),
        ));
        let routes = ClientRouteControl::default();
        let dns_routes = ClientRouteControl::default();
        // No helper, discovery actor or native runtime is started or supplied to this operation.
        // Repeated idle Disconnect must not issue an all-role Cleanup on somebody else's behalf.
        for _ in 0..2 {
            let result = disconnect_response(vec![1; 16], &routes, &dns_routes, &state).await;
            assert_eq!(result.result, ControlResult::Ok as i32);
            let state = state.read().await;
            assert_eq!(state.roles(), config.roles);
            assert!(!state.status().connected);
        }
        let newer_path = volparossa_local_control::PathSummary {
            route_context_id: vec![2; 16],
            path_id: 1,
            relay_peer_id: "new-relay".to_owned(),
            exit_peer_id: "new-exit".to_owned(),
            state: volparossa_local_control::PathState::Active as i32,
            ..Default::default()
        };
        state
            .write()
            .await
            .replace_single_udp_path(newer_path.clone())
            .expect("newer context projection");
        let result = disconnect_response(vec![3; 16], &routes, &dns_routes, &state).await;
        assert_eq!(result.result, ControlResult::Ok as i32);
        assert_eq!(state.read().await.path_list().paths, vec![newer_path]);
    }

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
            Some(SessionTransport::ProtectedDns as i32),
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
            (SessionTransport::ProtectedDns, (false, true, false)),
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
        disabled.udp.enabled = false;
        assert!(
            requested_connect_profile(&disabled, Some(SessionTransport::ProtectedDns as i32))
                .is_none()
        );
    }
}
