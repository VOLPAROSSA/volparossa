//! Authenticated root-owned Unix socket server.

use std::{
    io, os::unix::net::UnixListener as StdUnixListener, path::Path, sync::Arc, time::Duration,
};

use nix::unistd::Gid;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{UnixListener, UnixStream},
    runtime::{Builder, Handle},
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};
use volparossa_linux_uapi::{SystemdListenFdSet, send_fd_with_binding};
use volparossa_routing::{
    HelperRequest, MAX_HELPER_FRAME, decode_request, descriptor_fd_binding, encode_response,
    helper_response, safe_preview,
};
use zeroize::Zeroizing;

use crate::{
    HelperEngine,
    deadline::HardDeadline,
    engine::HelperExecution,
    ownership_journal::{ProductionOwnershipRuntime, ensure_legacy_journal_absent},
    runtime::{
        PreparedProductionRuntime, SOCKET_PATH, SocketPathGuard, bind_guarded_nonblocking_socket,
        prepare_production_runtime_identity, remove_stale_socket, secure_socket,
    },
    systemd_custody::{
        capture_inherited_custody, classify_startup_custody,
        observe_nonempty_restart_custody_for_refusal, observe_startup_custody_inventory,
        settle_cleanup_confirmed_restart_absence,
    },
};

const MAX_CONNECTIONS: usize = 32;
const MAX_REQUESTS_PER_CONNECTION: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const EXPIRY_REAP_INTERVAL: Duration = Duration::from_secs(1);
const OWNERSHIP_STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const OWNERSHIP_SHUTDOWN_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Exact Linux effective UID/GID accepted through `SO_PEERCRED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedPeer {
    /// Dedicated agent effective UID.
    pub uid: u32,
    /// Dedicated agent effective GID.
    pub gid: u32,
}

impl AllowedPeer {
    fn authorises(self, credential: &tokio::net::unix::UCred) -> bool {
        credential.uid() == self.uid && credential.gid() == self.gid
    }
}

/// Bound production server. Construction validates root ownership and exact modes.
struct ProductionServer {
    listener: StdUnixListener,
    engine: HelperEngine,
    allowed_peer: AllowedPeer,
    ownership_runtime: ProductionOwnershipRuntime,
    _socket_guard: SocketPathGuard,
}

// Field order is intentional: unwind or an unhandled startup error shuts down and joins durable
// ownership before it may unlink the exact captured socket inode.
struct ProductionServerStartup {
    ownership_runtime: ProductionOwnershipRuntime,
    socket_guard: SocketPathGuard,
}

enum ExpiryDriverState {
    NotStarted,
    Running {
        stop: tokio::sync::oneshot::Sender<()>,
        task: tokio::task::JoinHandle<()>,
    },
    Failed,
}

/// Helper server failures which reveal no kernel/user-controlled diagnostic strings.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Fixed runtime or socket operation failed.
    #[error("helper runtime socket operation failed")]
    Io(#[from] io::Error),
    /// Shutdown could not confirm all worker cleanup.
    #[error("helper namespace cleanup was incomplete")]
    CleanupIncomplete,
    /// Durable ownership startup or shutdown did not reach a proven boundary.
    #[error("helper durable ownership lifecycle was incomplete")]
    OwnershipIncomplete,
    /// Restart custody or its durable journal state could not be settled exactly.
    #[error("helper inherited restart custody is not recoverable")]
    InheritedCustody,
    /// The synchronous production owner cannot be nested in another Tokio runtime.
    #[error("helper production runtime context is already active")]
    RuntimeContextConflict,
}

/// Own the production Tokio I/O runtime, durable startup boundary, service loop and shutdown.
///
/// Keeping the fallible async listener adoption behind this synchronous entry point makes a
/// runtime without an I/O driver and external cancellation of the production future
/// unrepresentable to library callers.
///
/// # Errors
///
/// Returns an error when inherited custody cannot be recovered, runtime construction, protected
/// helper startup, service I/O, in-memory cleanup, or durable ownership shutdown cannot be
/// completed.
pub fn run_production_server(inherited: SystemdListenFdSet) -> Result<(), ServerError> {
    if Handle::try_current().is_ok() {
        return Err(ServerError::RuntimeContextConflict);
    }
    let inherited =
        capture_inherited_custody(inherited).map_err(|_| ServerError::InheritedCustody)?;
    ensure_legacy_journal_absent()?;
    let prepared_runtime = prepare_production_runtime_identity()?;
    let ownership_deadline = HardDeadline::after(OWNERSHIP_STARTUP_TIMEOUT)?;
    let mut ownership_startup = ProductionOwnershipRuntime::begin_until(ownership_deadline)
        .map_err(|_| ServerError::OwnershipIncomplete)?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let observed_inventory = runtime
        .block_on(observe_startup_custody_inventory(
            &inherited,
            ownership_deadline,
        ))
        .map_err(|_| ServerError::InheritedCustody)?;
    let targets = ownership_startup
        .revalidate_targets()
        .map_err(|_| ServerError::OwnershipIncomplete)?;
    let classification =
        classify_startup_custody(inherited, targets, observed_inventory, ownership_deadline)
            .map_err(|_| ServerError::InheritedCustody)?;
    let ownership_runtime = if classification.is_empty() {
        drop(classification);
        ownership_startup
            .continue_empty()
            .map_err(|_| ServerError::OwnershipIncomplete)?
    } else if classification.is_cleanup_confirmed_no_stored_custody_only() {
        settle_cleanup_confirmed_restart_absence(
            &runtime,
            ownership_startup,
            classification,
            ownership_deadline,
        )
        .map_err(|_| ServerError::InheritedCustody)?
    } else {
        let _ = observe_nonempty_restart_custody_for_refusal(
            &runtime,
            ownership_startup,
            classification,
            ownership_deadline,
        );
        return Err(ServerError::InheritedCustody);
    };
    let server = bind_production_socket(prepared_runtime, ownership_runtime)?;
    runtime.block_on(run_server(server))
}

#[cfg(test)]
fn run_production_server_with_empty_custody_for_test() -> Result<(), ServerError> {
    if Handle::try_current().is_ok() {
        return Err(ServerError::RuntimeContextConflict);
    }
    Err(ServerError::InheritedCustody)
}

/// Creates the fixed `/run/volparossa/helper.sock` production endpoint.
///
/// The socket is exactly `root:volparossa 0660`; the parent directory must be exactly `0750`.
///
/// # Errors
///
/// Returns an error when the fixed runtime directory, durable ownership actor, or protected Unix
/// socket cannot be prepared. A `MayOwnPrepare` record remains unreaped and blocks startup.
fn bind_production_socket(
    prepared_runtime: PreparedProductionRuntime,
    ownership_runtime: ProductionOwnershipRuntime,
) -> Result<ProductionServer, ServerError> {
    let Ok(durable_ownership) = ownership_runtime.prepare_handle() else {
        let _ = shutdown_production_ownership(ownership_runtime);
        return Err(ServerError::OwnershipIncomplete);
    };
    let runtime = match prepared_runtime.publish_cleanup_token() {
        Ok(runtime) => runtime,
        Err(error) => {
            return Err(startup_io_failure(ownership_runtime, error));
        }
    };
    let trusted_uid = runtime.agent_uid;
    let socket_group = runtime.agent_gid;
    let path = Path::new(SOCKET_PATH);
    if let Err(error) = remove_stale_socket(path, socket_group) {
        return Err(startup_io_failure(ownership_runtime, error));
    }
    let (listener, guard) = match bind_guarded_nonblocking_socket(path, 0, socket_group) {
        Ok(bound) => bound,
        Err(error) => {
            return Err(startup_io_failure(ownership_runtime, error));
        }
    };
    let startup = ProductionServerStartup {
        ownership_runtime,
        socket_guard: guard,
    };
    if let Err(error) = secure_socket(path, Gid::from_raw(socket_group)) {
        let ProductionServerStartup {
            ownership_runtime,
            socket_guard,
        } = startup;
        let ownership_complete = shutdown_production_ownership(ownership_runtime);
        drop(socket_guard);
        return match ownership_complete {
            Ok(()) => Err(ServerError::Io(error)),
            Err(ownership_error) => Err(ownership_error),
        };
    }
    let ProductionServerStartup {
        ownership_runtime,
        socket_guard: guard,
    } = startup;
    Ok(ProductionServer {
        listener,
        engine: HelperEngine::new_with_backend(
            runtime.cleanup_token,
            trusted_uid,
            crate::worker_v3::functional_alpha_lease_backend(durable_ownership),
        ),
        allowed_peer: AllowedPeer {
            uid: trusted_uid,
            gid: socket_group,
        },
        ownership_runtime,
        _socket_guard: guard,
    })
}

/// Serves until SIGINT/SIGTERM while an owned expiry driver retires stale in-memory contexts, then
/// closes the durable actor.
///
/// The crate-internal production engine can prepare, activate, probe-commit and destroy one
/// process-owned functional-alpha Client or Exit singleton lease. A committed response proves only
/// the exact `WireGuard` identity, signed peer, `/128` route, recent handshake and strict
/// bidirectional counter growth; transport descriptor acquisition and every usable datapath remain
/// unavailable. A successful return proves the engine was cleaned before the durable journal actor
/// became quiescent. Startup still refuses `MayOwnPrepare` because no production restart reaper can
/// yet prove absence of stale kernel state. Unexpected expiry-driver exit stops serving and fails
/// the runtime closed.
///
/// # Errors
///
/// Returns an error for listener or signal I/O failures, when owned in-memory context cleanup
/// cannot be confirmed, or when durable actor quiescence and thread settlement cannot be proven.
async fn run_server(server: ProductionServer) -> Result<(), ServerError> {
    let ProductionServer {
        listener,
        engine,
        allowed_peer,
        ownership_runtime,
        _socket_guard: socket_guard,
    } = server;
    let mut tasks = JoinSet::new();
    let (service_result, expiry_driver) = match UnixListener::from_std(listener) {
        Ok(listener) => {
            let (expiry_stop, expiry_stopped) = tokio::sync::oneshot::channel();
            let expiry_engine = engine.clone();
            let mut expiry_task = tokio::spawn(async move {
                run_expiry_reaper(expiry_engine, expiry_stopped).await;
            });
            let (result, expiry_driver_failed) = tokio::select! {
                result = serve_connections(&listener, &engine, allowed_peer, &mut tasks) => {
                    (result.map_err(ServerError::Io), false)
                }
                _ = &mut expiry_task => {
                    (Err(ServerError::CleanupIncomplete), true)
                }
            };
            drop(listener);
            let expiry_driver = if expiry_driver_failed {
                ExpiryDriverState::Failed
            } else {
                ExpiryDriverState::Running {
                    stop: expiry_stop,
                    task: expiry_task,
                }
            };
            (result, expiry_driver)
        }
        Err(error) => (Err(ServerError::Io(error)), ExpiryDriverState::NotStarted),
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let expiry_complete = match expiry_driver {
        ExpiryDriverState::NotStarted => true,
        ExpiryDriverState::Running { stop, task } => {
            let _ = stop.send(());
            task.await.is_ok()
        }
        ExpiryDriverState::Failed => false,
    };
    let engine_complete = engine.shutdown_cleanup().await;
    let complete = expiry_complete && engine_complete;
    let ownership_complete = shutdown_production_ownership(ownership_runtime);
    drop(socket_guard);
    combine_server_completion(service_result, complete, ownership_complete)
}

async fn run_expiry_reaper(engine: HelperEngine, mut stopped: tokio::sync::oneshot::Receiver<()>) {
    let mut ticks = interval(EXPIRY_REAP_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticks.tick().await;
    loop {
        tokio::select! {
            _ = &mut stopped => return,
            _ = ticks.tick() => {
                if !engine.reap_expired_cleanup().await {
                    tracing::warn!(
                        diagnostic_code = "EXPIRY_REAP_INCOMPLETE",
                        "helper expiry cleanup remains quarantined"
                    );
                }
            }
        }
    }
}

fn startup_io_failure(
    ownership_runtime: ProductionOwnershipRuntime,
    error: io::Error,
) -> ServerError {
    let ownership_complete = shutdown_production_ownership(ownership_runtime);
    combine_startup_failure(error, ownership_complete)
}

fn combine_startup_failure(
    error: io::Error,
    ownership_complete: Result<(), ServerError>,
) -> ServerError {
    ownership_complete.err().unwrap_or(ServerError::Io(error))
}

fn shutdown_production_ownership(
    ownership_runtime: ProductionOwnershipRuntime,
) -> Result<(), ServerError> {
    let deadline = HardDeadline::after(OWNERSHIP_SHUTDOWN_ATTEMPT_TIMEOUT)
        .map_err(|_| ServerError::OwnershipIncomplete)?;
    ownership_runtime
        .shutdown_until(deadline)
        .map_err(|_| ServerError::OwnershipIncomplete)
}

fn combine_server_completion(
    service_result: Result<(), ServerError>,
    engine_complete: bool,
    ownership_complete: Result<(), ServerError>,
) -> Result<(), ServerError> {
    match (ownership_complete, engine_complete) {
        (Err(error), _) => Err(error),
        (Ok(()), false) => Err(ServerError::CleanupIncomplete),
        (Ok(()), true) => service_result,
    }
}

async fn serve_connections(
    listener: &UnixListener,
    engine: &HelperEngine,
    allowed_peer: AllowedPeer,
    tasks: &mut JoinSet<()>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    tracing::warn!(diagnostic_code = "CONNECTION_LIMIT", "helper connection rejected");
                    continue;
                };
                let request_engine = engine.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = process_connection(stream, allowed_peer, request_engine).await {
                        tracing::warn!(diagnostic_code = error.diagnostic(), "helper connection closed");
                    }
                });
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if joined.is_err() {
                    tracing::warn!(diagnostic_code = "CONNECTION_TASK_FAILED", "helper task failed");
                }
            }
        }
    }
    Ok(())
}

async fn process_connection(
    mut stream: UnixStream,
    allowed_peer: AllowedPeer,
    engine: HelperEngine,
) -> Result<(), ConnectionError> {
    let credential = stream
        .peer_cred()
        .map_err(|_| ConnectionError::Credentials)?;
    if !allowed_peer.authorises(&credential) {
        tracing::warn!(
            peer_uid = credential.uid(),
            peer_gid = credential.gid(),
            diagnostic_code = "UNAUTHORISED_PEER",
            "helper peer rejected"
        );
        return Err(ConnectionError::Unauthorised);
    }

    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let request = match timeout(REQUEST_TIMEOUT, read_secure_request(&mut stream)).await {
            Ok(Ok(request)) => request,
            Ok(Err(_)) => return Err(ConnectionError::InvalidFrame),
            Err(_) => return Err(ConnectionError::Timeout),
        };
        let preview = safe_preview(&request).unwrap_or_else(|_| "invalid typed request".to_owned());
        tracing::info!(operation = %preview, "helper request accepted");
        let execution = engine.execute_with_descriptor(request).await;
        tracing::info!(
            result = execution.response.result,
            diagnostic_code = execution.response.diagnostic_code,
            "helper request completed"
        );
        write_execution(&mut stream, execution).await?;
    }
    Ok(())
}

async fn write_execution(
    stream: &mut UnixStream,
    execution: HelperExecution,
) -> Result<(), ConnectionError> {
    let expects_descriptor = matches!(
        execution.response.outcome,
        Some(
            helper_response::Outcome::TransportSocketReady(_)
                | helper_response::Outcome::IngressSocketReady(_)
        )
    );
    let binding = match (expects_descriptor, execution.descriptor.as_ref()) {
        (true, Some(_)) => Some(
            descriptor_fd_binding(&execution.response)
                .map_err(|_| ConnectionError::InvalidResponse)?,
        ),
        (false, None) => None,
        (true, None) | (false, Some(_)) => return Err(ConnectionError::InvalidResponse),
    };
    let bytes =
        encode_response(&execution.response).map_err(|_| ConnectionError::InvalidResponse)?;
    timeout(REQUEST_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| ConnectionError::Timeout)?
        .map_err(|_| ConnectionError::Io)?;
    timeout(REQUEST_TIMEOUT, stream.flush())
        .await
        .map_err(|_| ConnectionError::Timeout)?
        .map_err(|_| ConnectionError::Io)?;
    if let (Some(binding), Some(descriptor)) = (binding, execution.descriptor.as_ref()) {
        timeout(
            REQUEST_TIMEOUT,
            send_bound_descriptor(stream, descriptor, &binding),
        )
        .await
        .map_err(|_| ConnectionError::Timeout)?
        .map_err(|_| ConnectionError::Io)?;
    }
    Ok(())
}

async fn send_bound_descriptor(
    stream: &UnixStream,
    descriptor: &Arc<std::os::fd::OwnedFd>,
    binding: &[u8],
) -> io::Result<()> {
    loop {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            send_fd_with_binding(stream, descriptor.as_ref(), binding)
        }) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
    }
}

async fn read_secure_request(stream: &mut UnixStream) -> Result<HelperRequest, ConnectionError> {
    let length = usize::try_from(stream.read_u32().await.map_err(|_| ConnectionError::Io)?)
        .map_err(|_| ConnectionError::InvalidFrame)?;
    if length == 0 || length > MAX_HELPER_FRAME {
        return Err(ConnectionError::InvalidFrame);
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    if stream.read_exact(payload.as_mut_slice()).await.is_err() {
        return Err(ConnectionError::Io);
    }
    decode_request(payload.as_slice()).map_err(|_| ConnectionError::InvalidFrame)
}

#[derive(Clone, Copy, Debug)]
enum ConnectionError {
    Credentials,
    Unauthorised,
    InvalidFrame,
    InvalidResponse,
    Timeout,
    Io,
}

impl ConnectionError {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Credentials => "PEERCRED_FAILED",
            Self::Unauthorised => "UNAUTHORISED_PEER",
            Self::InvalidFrame => "INVALID_FRAME",
            Self::InvalidResponse => "INVALID_RESPONSE",
            Self::Timeout => "REQUEST_TIMEOUT",
            Self::Io => "SOCKET_IO_FAILED",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::fd::OwnedFd,
        os::unix::net::UnixStream as StdUnixStream,
        sync::Arc,
    };

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::{getegid, geteuid};
    use volparossa_linux_uapi::receive_fd_with_binding;
    use volparossa_routing::{
        AcquireIngressSocket, AcquireTransportSocket, BindHelperRuntime, CleanupOwned,
        HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, HelperResult, IngressAddressFamily,
        IngressSocketAddress, IngressSocketKind, IngressSocketReady, TransportSocketAddress,
        TransportSocketKind, TransportSocketReady, WireguardRole, encode_request, helper_request,
        helper_response, ingress_fd_binding, operation_digest, read_response, transport_fd_binding,
    };

    use super::*;

    #[tokio::test]
    async fn peer_credentials_and_bounded_frame_work_without_network_changes() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let engine = HelperEngine::new([4; 32], 1_000);
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            operation: Some(helper_request::Operation::CleanupOwned(CleanupOwned {
                cleanup_token: vec![4; 32],
            })),
        };
        let task = tokio::spawn(process_connection(
            server,
            AllowedPeer {
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
            },
            engine,
        ));
        let frame = Zeroizing::new(encode_request(&request).expect("request"));
        client.write_all(frame.as_slice()).await.expect("write");
        let response = read_response(&mut client).await.expect("response");
        assert_eq!(response.result, HelperResult::Ok as i32);
        assert_eq!(response.diagnostic_code, "CLEANUP_COMPLETE");
        drop(client);
        assert!(task.await.expect("task").is_err());
    }

    #[tokio::test]
    async fn authenticated_connection_processes_two_correlated_runtime_queries() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let task = tokio::spawn(process_connection(
            server,
            AllowedPeer {
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
            },
            HelperEngine::new([4; 32], 1_000),
        ));
        let requests = [[0x31; 16], [0x32; 16]].map(|request_id| HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: None,
                },
            )),
        });
        let mut digests = Vec::with_capacity(requests.len());
        let mut runtime_id = None;

        for request in &requests {
            let digest = operation_digest(request).expect("runtime query digest");
            let frame = Zeroizing::new(encode_request(request).expect("runtime query"));
            client.write_all(frame.as_slice()).await.expect("write");
            let response = read_response(&mut client).await.expect("response");

            assert_eq!(response.protocol_version, HELPER_PROTOCOL_VERSION);
            assert_eq!(response.request_id, request.request_id);
            assert_eq!(response.operation_digest.as_slice(), digest);
            assert_eq!(response.result, HelperResult::Ok as i32);
            assert_eq!(response.diagnostic_code, "HELPER_RUNTIME");
            let Some(helper_response::Outcome::HelperRuntime(runtime)) = response.outcome else {
                panic!("helper runtime outcome");
            };
            if let Some(expected) = runtime_id.as_ref() {
                assert_eq!(&runtime.helper_runtime_id, expected);
            } else {
                runtime_id = Some(runtime.helper_runtime_id);
            }
            digests.push(digest);
        }

        assert_ne!(requests[0].request_id, requests[1].request_id);
        assert_ne!(digests[0], digests[1]);
        drop(client);
        let result = timeout(Duration::from_secs(1), task)
            .await
            .expect("connection task closes after client drop")
            .expect("connection task");
        assert!(result.is_err());
    }

    fn transport_address(address: [u8; 4], port: u32) -> TransportSocketAddress {
        TransportSocketAddress {
            address: address.to_vec(),
            port,
        }
    }

    fn transport_exchange(id: u8, kind: TransportSocketKind) -> (HelperRequest, HelperResponse) {
        let remote = (kind == TransportSocketKind::MptcpConnected)
            .then(|| transport_address([10, 77, 0, 3], 443));
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![id; 16],
            operation: Some(helper_request::Operation::AcquireTransportSocket(
                AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: vec![8; 32],
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: kind as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: remote.clone(),
                },
            )),
        };
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TRANSPORT_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: kind as i32,
                    local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    remote,
                },
            )),
        };
        (request, response)
    }

    fn ingress_exchange(
        id: u8,
        kind: IngressSocketKind,
        family: IngressAddressFamily,
        port: u32,
    ) -> (HelperRequest, HelperResponse) {
        let local = IngressSocketAddress {
            address: match family {
                IngressAddressFamily::Ipv4 => vec![0; 4],
                IngressAddressFamily::Ipv6 => vec![0; 16],
                IngressAddressFamily::Unspecified => panic!("closed test family"),
            },
            port,
        };
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![id; 16],
            operation: Some(helper_request::Operation::AcquireIngressSocket(
                AcquireIngressSocket {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    socket_handle: vec![9; 32],
                    descriptor_kind: kind as i32,
                    address_family: family as i32,
                },
            )),
        };
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::IngressSocketReady(
                IngressSocketReady {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    socket_handle: vec![9; 32],
                    receipt_handle: vec![10; 32],
                    descriptor_kind: kind as i32,
                    address_family: family as i32,
                    local: Some(local),
                },
            )),
        };
        (request, response)
    }

    async fn receive_test_descriptor(stream: &UnixStream, binding: &[u8]) -> io::Result<OwnedFd> {
        loop {
            stream.readable().await?;
            match stream.try_io(Interest::READABLE, || {
                receive_fd_with_binding(stream, binding)
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }

    #[tokio::test]
    async fn response_transport_hands_off_one_bound_cloexec_descriptor_for_every_kind() {
        for (id, kind) in [
            (10, TransportSocketKind::MptcpConnected),
            (11, TransportSocketKind::MptcpListener),
            (12, TransportSocketKind::QuicUdpUnconnected),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("control socket pair");
            let (sent, mut peer) = StdUnixStream::pair().expect("descriptor socket pair");
            let (_, response) = transport_exchange(id, kind);
            let execution = HelperExecution {
                response: response.clone(),
                descriptor: Some(Arc::new(OwnedFd::from(sent))),
            };
            let task = tokio::spawn(async move { write_execution(&mut server, execution).await });
            let received_response = read_response(&mut client).await.expect("response");
            assert_eq!(received_response, response);
            let binding = transport_fd_binding(&received_response).expect("binding");
            let descriptor = receive_test_descriptor(&client, &binding)
                .await
                .expect("bound descriptor");
            let flags =
                FdFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFD).expect("flags"));
            assert!(flags.contains(FdFlag::FD_CLOEXEC));

            let mut received = StdUnixStream::from(descriptor);
            peer.write_all(b"x").expect("write peer");
            let mut byte = [0_u8; 1];
            received.read_exact(&mut byte).expect("read descriptor");
            assert_eq!(byte, *b"x");
            task.await.expect("send task").expect("send descriptor");
        }
    }

    #[tokio::test]
    async fn response_ingress_hands_off_one_bound_cloexec_descriptor_for_every_identity() {
        let identities = [
            IngressSocketKind::TransparentTcpListener,
            IngressSocketKind::TransparentUdp,
            IngressSocketKind::DnsTcpListener,
            IngressSocketKind::DnsUdp,
        ]
        .into_iter()
        .flat_map(|kind| {
            [IngressAddressFamily::Ipv4, IngressAddressFamily::Ipv6]
                .into_iter()
                .map(move |family| (kind, family))
        });
        for (index, (kind, family)) in identities.enumerate() {
            let (mut client, mut server) = UnixStream::pair().expect("control socket pair");
            let (sent, mut peer) = StdUnixStream::pair().expect("descriptor socket pair");
            let (_, response) = ingress_exchange(
                u8::try_from(index + 30).expect("bounded request ID"),
                kind,
                family,
                42_000 + u32::try_from(index).expect("bounded port"),
            );
            let execution = HelperExecution {
                response: response.clone(),
                descriptor: Some(Arc::new(OwnedFd::from(sent))),
            };
            let task = tokio::spawn(async move { write_execution(&mut server, execution).await });
            let received_response = read_response(&mut client).await.expect("response");
            assert_eq!(received_response, response);
            let binding = ingress_fd_binding(&received_response).expect("binding");
            let descriptor = receive_test_descriptor(&client, &binding)
                .await
                .expect("bound descriptor");
            let flags =
                FdFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFD).expect("flags"));
            assert!(flags.contains(FdFlag::FD_CLOEXEC));
            let mut received = StdUnixStream::from(descriptor);
            peer.write_all(b"x").expect("write peer");
            let mut byte = [0_u8; 1];
            received.read_exact(&mut byte).expect("read descriptor");
            assert_eq!(byte, *b"x");
            task.await.expect("send task").expect("send descriptor");
        }
    }

    #[tokio::test]
    async fn transport_success_without_descriptor_is_rejected_before_frame_write() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let (_, response) = transport_exchange(20, TransportSocketKind::MptcpListener);
        let error = write_execution(
            &mut server,
            HelperExecution {
                response,
                descriptor: None,
            },
        )
        .await
        .expect_err("missing descriptor");
        assert!(matches!(error, ConnectionError::InvalidResponse));
        drop(server);
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("frame EOF"), 0);
    }

    #[tokio::test]
    async fn mismatched_peer_is_rejected_before_request_read() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        let result = process_connection(
            server,
            AllowedPeer {
                uid: geteuid().as_raw().wrapping_add(1),
                gid: getegid().as_raw(),
            },
            HelperEngine::new([0; 32], 1_000),
        )
        .await;
        assert!(matches!(result, Err(ConnectionError::Unauthorised)));
        drop(client);
    }

    #[test]
    fn durable_ownership_failure_dominates_every_weaker_server_result() {
        let service_error = Err(ServerError::Io(io::Error::other("fixture")));
        assert!(matches!(
            combine_server_completion(service_error, false, Err(ServerError::OwnershipIncomplete),),
            Err(ServerError::OwnershipIncomplete)
        ));
        assert!(matches!(
            combine_server_completion(Ok(()), false, Ok(())),
            Err(ServerError::CleanupIncomplete)
        ));
        assert!(combine_server_completion(Ok(()), true, Ok(())).is_ok());

        assert!(matches!(
            combine_startup_failure(
                io::Error::other("startup fixture"),
                Err(ServerError::OwnershipIncomplete),
            ),
            ServerError::OwnershipIncomplete
        ));
        assert!(matches!(
            combine_startup_failure(io::Error::other("startup fixture"), Ok(())),
            ServerError::Io(_)
        ));
    }

    #[test]
    fn production_entry_constructively_owns_io_runtime_and_private_future() {
        let source = include_str!("server.rs");
        let start = source
            .find("pub fn run_production_server")
            .expect("synchronous production entry");
        let end = source[start..]
            .find("fn bind_production_socket")
            .map(|offset| start + offset)
            .expect("private production bind");
        let entry = &source[start..end];
        let preflight = entry
            .find("Handle::try_current().is_ok()")
            .expect("nested-runtime preflight");
        let custody = entry
            .find("capture_inherited_custody(inherited)")
            .expect("affine inherited custody capture");
        let prepare = entry
            .find("prepare_production_runtime_identity()?")
            .expect("runtime identity before journal open");
        let ownership = entry
            .find("ProductionOwnershipRuntime::begin_until(ownership_deadline)")
            .expect("lock-holding ownership preflight");
        let runtime = entry
            .find("Builder::new_multi_thread().enable_all().build()?")
            .expect("owned I/O-enabled Tokio runtime");
        let inventory = entry
            .find("observe_startup_custody_inventory(")
            .expect("barriered manager inventory observation");
        let revalidate = entry
            .find("revalidate_targets()")
            .expect("post-observation locked journal revalidation");
        let classify = entry
            .find("classify_startup_custody(inherited, targets, observed_inventory, ownership_deadline)")
            .expect("three-way startup custody classification");
        let restart_refusal = entry
            .find("observe_nonempty_restart_custody_for_refusal(")
            .expect("nonempty restart observation before refusal");
        let cleanup_confirmed_restart = entry
            .find("settle_cleanup_confirmed_restart_absence(")
            .expect("cleanup-confirmed restart settlement");
        let continue_empty = entry
            .find("continue_empty()")
            .expect("empty-only ownership startup continuation");
        let bind = entry
            .find("bind_production_socket(prepared_runtime, ownership_runtime)?")
            .expect("private bind call");
        let drive = entry
            .find("runtime.block_on(run_server(server))")
            .expect("private future driven to completion");
        assert!(preflight < custody);
        assert!(custody < prepare);
        assert!(prepare < ownership);
        assert!(ownership < runtime);
        assert!(runtime < inventory);
        assert!(inventory < revalidate);
        assert!(revalidate < classify);
        assert!(classify < continue_empty);
        assert!(classify < cleanup_confirmed_restart);
        assert!(classify < restart_refusal);
        assert!(continue_empty < bind);
        assert!(cleanup_confirmed_restart < bind);
        assert!(restart_refusal < bind);
        assert!(bind < drive);
        assert!(source.contains("async fn run_server"));
        let public_future = ["pub async fn", " run_server"].concat();
        let unwind_catch = ["catch_", "unwind"].concat();
        assert!(!source.contains(&public_future));
        assert!(!source.contains(&unwind_catch));

        let library = include_str!("lib.rs");
        assert!(library.contains("run_production_server"));
        assert!(!library.contains("bind_production_socket"));
        assert!(!library.contains("run_server"));
    }

    #[test]
    fn production_composition_is_narrow_and_shutdown_is_ordered() {
        let source = include_str!("server.rs");
        let bind_start = source
            .find("fn bind_production_socket")
            .expect("private production bind");
        let bind_end = source[bind_start..]
            .find("async fn run_server")
            .map(|offset| bind_start + offset)
            .expect("private server loop");
        let bind = &source[bind_start..bind_end];
        assert!(bind.contains("HelperEngine::new_with_backend("));
        assert!(
            bind.contains("crate::worker_v3::functional_alpha_lease_backend(durable_ownership)")
        );
        assert!(bind.contains("ownership_runtime.prepare_handle()"));
        assert!(!bind.contains("HelperEngine::new_with_protected_cleanup_token("));

        let run_end = source[bind_end..]
            .find("fn startup_io_failure")
            .map(|offset| bind_end + offset)
            .expect("startup failure helper");
        let run = &source[bind_end..run_end];
        let abort_connections = run.find("tasks.abort_all()").expect("connection stop");
        let expiry_join = run
            .find("let expiry_complete = match expiry_driver")
            .expect("expiry driver join");
        let engine_shutdown = run
            .find("engine.shutdown_cleanup().await")
            .expect("engine cleanup");
        let ownership_shutdown = run
            .find("shutdown_production_ownership(ownership_runtime)")
            .expect("ownership shutdown");
        assert!(run.contains("tokio::select!"));
        assert!(run.contains("ExpiryDriverState::Failed"));
        assert!(run.contains("MissedTickBehavior::Skip"));
        assert!(abort_connections < expiry_join);
        assert!(expiry_join < engine_shutdown);
        assert!(engine_shutdown < ownership_shutdown);

        let engine = include_str!("engine_v3.rs");
        let public_start = engine
            .find("pub fn new(cleanup_token")
            .expect("public standalone constructor");
        let public_end = engine[public_start..]
            .find("pub(crate) fn new_with_backend")
            .map(|offset| public_start + offset)
            .expect("crate-internal backend constructor");
        assert!(engine[public_start..public_end].contains("Arc::new(UnavailableLeaseBackend)"));
    }

    #[tokio::test]
    async fn empty_expiry_driver_stops_and_joins_on_signal() {
        let engine = HelperEngine::new([9; 32], 1_000);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(run_expiry_reaper(engine, stopped));
        tokio::task::yield_now().await;
        stop.send(()).expect("expiry stop receiver");
        timeout(Duration::from_secs(1), driver)
            .await
            .expect("expiry driver stop deadline")
            .expect("expiry driver join");
    }

    #[test]
    fn nested_runtime_is_rejected_before_any_production_startup() {
        let runtime = Builder::new_current_thread().build().expect("test runtime");
        let result =
            runtime.block_on(async { run_production_server_with_empty_custody_for_test() });
        assert!(matches!(result, Err(ServerError::RuntimeContextConflict)));
    }
}
