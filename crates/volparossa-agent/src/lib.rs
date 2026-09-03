//! Unprivileged VOLPAROSSA service orchestration.
//!
//! This crate owns identity loading, decentralised discovery, privacy-safe
//! peer persistence, threshold policy verification, local control, bounded
//! selection/reservation state, and the typed helper boundary. It performs no
//! direct route, firewall, DNS, namespace, `WireGuard`, or sysctl operations.

#![forbid(unsafe_code)]

mod advertisement;
mod client_ingress;
mod control;
mod discovery;
mod endpoint_leases;
#[path = "helper_v3.rs"]
pub mod helper;
pub mod mpquic_runtime;
mod mptcp_flow_runtime;
pub mod mptcp_transport;
mod paths;
mod policy;
mod roles;
mod route_setup;
mod secret;
mod state;
mod udp_exit_provider;

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
    io::{AsyncReadExt, AsyncWriteExt, unix::AsyncFd},
    sync::{RwLock, Semaphore, watch},
    task::{JoinHandle, JoinSet},
};
use volparossa_config::Config;
use volparossa_identity::IdentityStore;
use volparossa_inspection::InspectionError;
use volparossa_local_control::LogLevel;
use volparossa_metrics::{LocalMetricsEndpoint, MetricsRegistry};
use volparossa_peerstore::PeerStore;
use volparossa_udp::MAX_DNS_MESSAGE_BYTES;

use client_ingress::{
    BrowserQuicIngressDecision, BrowserQuicIngressGate, ClientIngressRuntime,
    ClientIngressTcpError, ClientIngressUdpError, PolicyAuthorizedDnsIngress,
};
use control::{ControlContext, bind_control_socket, serve_control};
use discovery::{DiscoveryControlHandle, DiscoveryRuntime, DiscoveryRuntimeResources};
use helper::{ClientIngressSocketFamily, HelperClient};
use policy::load_active_policy;
use roles::{RoleStore, ensure_private_state_directory};
use route_setup::{ClientPathMaintenance, ClientRouteConnectError, ClientRouteControl};
use secret::read_identity_credential;
use state::AgentState;

pub use paths::{
    AgentPaths, DEFAULT_CONFIG, DEFAULT_CONTROL_SOCKET, DEFAULT_HELPER_SOCKET,
    DEFAULT_MPQUIC_SOCKET, DEFAULT_STATE_DIRECTORY, IDENTITY_CREDENTIAL_NAME, PathError,
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const INGRESS_POLICY_BACKOFF: Duration = Duration::from_millis(50);
const BROWSER_QUIC_REVERSE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK: usize = 64;
const DNS_TCP_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
        let helper = HelperClient::new(paths.helper_socket.clone(), paths.helper_token.clone());
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
                helper: helper.clone(),
                mpquic_socket: paths.mpquic_socket.clone(),
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
    #[allow(
        clippy::too_many_lines,
        reason = "one owner starts and shuts down the complete bounded service actor set"
    )]
    pub async fn run_with_shutdown<F>(self, shutdown: F) -> Result<(), AgentError>
    where
        F: Future<Output = ()> + Send,
    {
        let (listener, socket_guard) =
            bind_control_socket(&self.paths.control_socket)?.into_parts();
        let client_ingress = if self.config.roles.client {
            Some(
                ClientIngressRuntime::start(self.helper.clone())
                    .await
                    .map(Arc::new)
                    .map_err(|_| AgentError::ClientIngress)?,
            )
        } else {
            None
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let routes = production_client_routes(&self.paths, &self.state);
        let control_context = ControlContext {
            state: Arc::clone(&self.state),
            config: Arc::clone(&self.config),
            discovery: self.discovery_control.clone(),
            helper: self.helper.clone(),
            routes: routes.clone(),
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
        let maintenance_routes = routes.clone();
        let mut maintenance_task = tokio::spawn(run_maintenance(
            maintenance_state,
            maintenance_config,
            maintenance_trust,
            maintenance_discovery,
            maintenance_routes,
            shutdown_rx,
        ));
        let mut metrics_task = tokio::spawn(run_metrics_endpoint(
            self.config.privacy.metrics_enabled,
            self.config.privacy.metrics_port,
            self.metrics.clone(),
            shutdown_tx.subscribe(),
        ));
        let (
            mut tcp_ingress_task,
            mut ingress_task,
            mut dns_ingress_task,
            mut dns_tcp_ingress_task,
        ) = spawn_client_ingress_tasks(
            client_ingress.as_ref().map(Arc::clone),
            Arc::clone(&self.state),
            Arc::clone(&self.config),
            self.discovery_control.clone(),
            self.helper.clone(),
            routes.clone(),
            routes.clone(),
            routes.clone(),
            &shutdown_tx,
        );
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
            _ = &mut ingress_task => Err(AgentError::Task),
            _ = &mut tcp_ingress_task => Err(AgentError::Task),
            _ = &mut dns_ingress_task => Err(AgentError::Task),
            _ = &mut dns_tcp_ingress_task => Err(AgentError::Task),
        };
        let _ = shutdown_tx.send(true);
        stop_task(&mut control_task).await;
        stop_task(&mut discovery_task).await;
        stop_task(&mut maintenance_task).await;
        stop_task(&mut metrics_task).await;
        stop_task(&mut ingress_task).await;
        stop_task(&mut tcp_ingress_task).await;
        stop_task(&mut dns_ingress_task).await;
        stop_task(&mut dns_tcp_ingress_task).await;
        routes.disconnect().await;
        drop(socket_guard);
        if let Some(client_ingress) = client_ingress {
            let Ok(client_ingress) = Arc::try_unwrap(client_ingress) else {
                let _ = self.helper.cleanup_owned().await;
                return Err(AgentError::ShutdownCleanup);
            };
            if client_ingress.shutdown().await.is_err() {
                let _ = self.helper.cleanup_owned().await;
                return Err(AgentError::ShutdownCleanup);
            }
        }

        if self.state.read().await.has_network_state() {
            self.helper
                .cleanup_owned()
                .await
                .map_err(|_| AgentError::ShutdownCleanup)?;
        }
        run_result
    }
}

fn production_client_routes(
    paths: &AgentPaths,
    state: &Arc<RwLock<AgentState>>,
) -> ClientRouteControl {
    ClientRouteControl::new_with_agent_state(paths.mpquic_socket.clone(), Arc::clone(state))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the ingress actors share one exact production dependency set"
)]
fn spawn_client_ingress_tasks(
    runtime: Option<Arc<ClientIngressRuntime>>,
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    discovery: DiscoveryControlHandle,
    helper: HelperClient,
    tcp_routes: ClientRouteControl,
    udp_routes: ClientRouteControl,
    dns_routes: ClientRouteControl,
    shutdown: &watch::Sender<bool>,
) -> (
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
) {
    let udp_config = Arc::clone(&config);
    let udp_discovery = discovery.clone();
    let udp_helper = helper.clone();
    let dns_runtime = runtime.clone();
    let dns_state = Arc::clone(&state);
    let dns_config = Arc::clone(&udp_config);
    let dns_discovery = udp_discovery.clone();
    let dns_helper = udp_helper.clone();
    let dns_tcp_runtime = runtime.clone();
    let dns_tcp_state = Arc::clone(&state);
    let dns_tcp_config = Arc::clone(&udp_config);
    let dns_tcp_discovery = udp_discovery.clone();
    let dns_tcp_helper = udp_helper.clone();
    let dns_tcp_routes = dns_routes.clone();
    let tcp = tokio::spawn(run_client_tcp_ingress(
        runtime.clone(),
        Arc::clone(&state),
        config,
        discovery,
        helper,
        tcp_routes,
        shutdown.subscribe(),
    ));
    let udp = tokio::spawn(run_client_udp_ingress(
        runtime,
        state,
        udp_config,
        udp_discovery,
        udp_helper,
        udp_routes,
        shutdown.subscribe(),
    ));
    let dns = tokio::spawn(run_client_dns_ingress(
        dns_runtime,
        dns_state,
        dns_config,
        dns_discovery,
        dns_helper,
        dns_routes,
        shutdown.subscribe(),
    ));
    let dns_tcp = tokio::spawn(run_client_dns_tcp_ingress(
        dns_tcp_runtime,
        dns_tcp_state,
        dns_tcp_config,
        dns_tcp_discovery,
        dns_tcp_helper,
        dns_tcp_routes,
        shutdown.subscribe(),
    ));
    (tcp, udp, dns, dns_tcp)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one production ingress actor keeps accept, policy, route, and outcome ownership linear"
)]
async fn run_client_tcp_ingress(
    runtime: Option<Arc<ClientIngressRuntime>>,
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    discovery: DiscoveryControlHandle,
    helper: HelperClient,
    routes: ClientRouteControl,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(runtime) = runtime else {
        wait_for_shutdown(&mut shutdown).await;
        return;
    };
    let Ok([ipv4, ipv6]) = runtime.transparent_tcp_listeners() else {
        state.write().await.log(
            LogLevel::Error,
            "INGRESS_TCP_LISTENER_FAILED",
            unix_millis(),
        );
        return;
    };
    let flow_limit = Arc::new(Semaphore::new(config.routing.maximum_active_contexts));
    let mut flows = JoinSet::new();

    loop {
        let observed = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            completed = flows.join_next(), if !flows.is_empty() => {
                if !matches!(completed, Some(Ok(()))) {
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_TCP_FLOW_TASK_FAILED",
                        unix_millis(),
                    );
                }
                continue;
            }
            result = ipv4.accept() => result,
            result = ipv6.accept() => result,
        };
        let observed = match observed {
            Ok(observed) => observed,
            Err(ClientIngressTcpError::OriginalDestination(_)) => {
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_TCP_DESTINATION_REJECTED",
                    unix_millis(),
                );
                continue;
            }
            Err(_) => {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "INGRESS_TCP_ACCEPT_FAILED", unix_millis());
                tokio::time::sleep(INGRESS_POLICY_BACKOFF).await;
                continue;
            }
        };
        let now_ms = unix_millis();
        let Some(policy) = state.read().await.active_policy(now_ms) else {
            let mut state = state.write().await;
            state.record_policy_rejection();
            state.log(LogLevel::Warn, "INGRESS_TCP_POLICY_DENIED", now_ms);
            continue;
        };
        let ingress = match observed.authorize(&policy, now_ms).await {
            Ok(ingress) => ingress,
            Err(ClientIngressTcpError::Policy(_)) => {
                let mut state = state.write().await;
                state.record_policy_rejection();
                state.log(LogLevel::Warn, "INGRESS_TCP_POLICY_DENIED", unix_millis());
                continue;
            }
            Err(ClientIngressTcpError::ClientHello(InspectionError::EncryptedClientHello(_))) => {
                let mut state = state.write().await;
                state.record_policy_rejection();
                state.log(LogLevel::Warn, "INGRESS_TCP_ECH_DENIED", unix_millis());
                continue;
            }
            Err(
                ClientIngressTcpError::ClientHello(_)
                | ClientIngressTcpError::ClientHelloUnavailable,
            ) => {
                let mut state = state.write().await;
                state.record_policy_rejection();
                state.log(
                    LogLevel::Warn,
                    "INGRESS_TCP_CLIENT_HELLO_DENIED",
                    unix_millis(),
                );
                continue;
            }
            Err(_) => {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "INGRESS_TCP_FLOW_REJECTED", unix_millis());
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&flow_limit).acquire_owned().await else {
            return;
        };
        let state = Arc::clone(&state);
        let config = Arc::clone(&config);
        let discovery = discovery.clone();
        let helper = helper.clone();
        let routes = routes.clone();
        flows.spawn(async move {
            let _permit = permit;
            if Box::pin(routes.connect_tcp(&config, &discovery, &helper))
                .await
                .is_err()
            {
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_TCP_ROUTE_UNAVAILABLE",
                    unix_millis(),
                );
                return;
            }
            let activation_ms = unix_millis();
            let Some(active_policy) = state.read().await.active_policy(activation_ms) else {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "INGRESS_TCP_STREAM_FAILED", activation_ms);
                return;
            };
            let (level, message) = if routes
                .run_tcp_ingress(ingress, &active_policy, activation_ms)
                .await
                .is_ok()
            {
                (LogLevel::Info, "INGRESS_TCP_STREAM_COMPLETED")
            } else {
                (LogLevel::Warn, "INGRESS_TCP_STREAM_FAILED")
            };
            state.write().await.log(level, message, unix_millis());
        });
    }
}

#[allow(clippy::single_match_else, clippy::too_many_lines)] // Keep readiness and route ownership in one actor.
async fn run_client_udp_ingress(
    runtime: Option<Arc<ClientIngressRuntime>>,
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    discovery: DiscoveryControlHandle,
    helper: HelperClient,
    routes: ClientRouteControl,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(runtime) = runtime else {
        wait_for_shutdown(&mut shutdown).await;
        return;
    };
    let Ok([ipv4_descriptor, ipv6_descriptor]) = runtime.duplicate_udp_poll_descriptors() else {
        state
            .write()
            .await
            .log(LogLevel::Error, "INGRESS_UDP_POLL_FAILED", unix_millis());
        return;
    };
    let (Ok(ipv4_poll), Ok(ipv6_poll)) =
        (AsyncFd::new(ipv4_descriptor), AsyncFd::new(ipv6_descriptor))
    else {
        state
            .write()
            .await
            .log(LogLevel::Error, "INGRESS_UDP_POLL_FAILED", unix_millis());
        return;
    };
    let mut browser_gate = BrowserQuicIngressGate::new();
    let mut browser_reverse_poll = tokio::time::interval(BROWSER_QUIC_REVERSE_POLL_INTERVAL);
    browser_reverse_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let browser_flow_active = routes.browser_quic_flow_active().await;
        if !browser_flow_active {
            browser_gate.reset_authorized_if_route_inactive();
        }
        let ready = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            _ = browser_reverse_poll.tick(), if browser_flow_active => {
                let now_ms = unix_millis();
                let Some(policy) = state.read().await.active_policy(now_ms) else {
                    routes.disconnect().await;
                    continue;
                };
                for _ in 0..MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK {
                    match routes.receive_browser_quic_response(&policy, now_ms).await {
                        Ok(Some(response)) => {
                            if runtime
                                .send_udp_response(
                                    response.application(),
                                    response.remote(),
                                    response.payload(),
                                )
                                .await
                                .is_err()
                            {
                                state.write().await.log(
                                    LogLevel::Warn,
                                    "INGRESS_MPQUIC_REPLY_FAILED",
                                    unix_millis(),
                                );
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            routes.disconnect().await;
                            state.write().await.log(
                                LogLevel::Warn,
                                "INGRESS_MPQUIC_RESPONSE_UNAVAILABLE",
                                unix_millis(),
                            );
                            break;
                        }
                    }
                }
                continue;
            }
            result = ipv4_poll.readable() => match result {
                Ok(ready) => (ClientIngressSocketFamily::Ipv4, ready),
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Error,
                        "INGRESS_UDP_POLL_FAILED",
                        unix_millis(),
                    );
                    return;
                }
            },
            result = ipv6_poll.readable() => match result {
                Ok(ready) => (ClientIngressSocketFamily::Ipv6, ready),
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Error,
                        "INGRESS_UDP_POLL_FAILED",
                        unix_millis(),
                    );
                    return;
                }
            },
        };
        let (family, mut ready) = ready;
        let now_ms = unix_millis();
        let policy = state.read().await.active_policy(now_ms);
        let Some(policy) = policy else {
            ready.clear_ready();
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(INGRESS_POLICY_BACKOFF) => {}
            }
            continue;
        };
        let observed = match runtime.try_receive_udp(family) {
            Ok(ingress) => ingress,
            Err(ClientIngressUdpError::Receive(error))
                if error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                ready.clear_ready();
                continue;
            }
            Err(
                ClientIngressUdpError::Policy(_)
                | ClientIngressUdpError::PolicyBinding
                | ClientIngressUdpError::DestinationBinding,
            ) => {
                ready.clear_ready();
                state.write().await.record_policy_rejection();
                continue;
            }
            Err(_) => {
                ready.clear_ready();
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_UDP_DATAGRAM_REJECTED",
                    unix_millis(),
                );
                continue;
            }
        };
        ready.clear_ready();
        if observed.is_browser_quic() {
            let ingresses = match browser_gate.inspect(observed, &policy, now_ms) {
                Ok(BrowserQuicIngressDecision::NeedMore) => continue,
                Ok(BrowserQuicIngressDecision::Authorized(ingresses)) => ingresses,
                Err(ClientIngressUdpError::Policy(_)) => {
                    browser_gate = BrowserQuicIngressGate::new();
                    state.write().await.record_policy_rejection();
                    continue;
                }
                Err(_) => {
                    browser_gate = BrowserQuicIngressGate::new();
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_MPQUIC_CLIENT_HELLO_DENIED",
                        unix_millis(),
                    );
                    continue;
                }
            };
            if Box::pin(routes.ensure_browser_quic(&config, &discovery, &helper))
                .await
                .is_err()
            {
                browser_gate = BrowserQuicIngressGate::new();
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_MPQUIC_ROUTE_UNAVAILABLE",
                    unix_millis(),
                );
                continue;
            }
            let activation_ms = unix_millis();
            let Some(active_policy) = state.read().await.active_policy(activation_ms) else {
                browser_gate = BrowserQuicIngressGate::new();
                routes.disconnect().await;
                state.write().await.record_policy_rejection();
                continue;
            };
            let ingresses = match browser_gate.reauthorize_after_route_ready(
                ingresses,
                &active_policy,
                activation_ms,
            ) {
                Ok(ingresses) => ingresses,
                Err(ClientIngressUdpError::Policy(_)) => {
                    browser_gate = BrowserQuicIngressGate::new();
                    routes.disconnect().await;
                    state.write().await.record_policy_rejection();
                    continue;
                }
                Err(_) => {
                    browser_gate = BrowserQuicIngressGate::new();
                    routes.disconnect().await;
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_MPQUIC_DATAGRAM_REJECTED",
                        unix_millis(),
                    );
                    continue;
                }
            };
            for ingress in ingresses {
                match routes
                    .send_browser_quic_ingress(ingress, &active_policy, activation_ms)
                    .await
                {
                    Ok(_) => {}
                    Err(ClientRouteConnectError::UdpIngressUnavailable) => {
                        state.write().await.log(
                            LogLevel::Warn,
                            "INGRESS_MPQUIC_DATAGRAM_DROPPED",
                            unix_millis(),
                        );
                    }
                    Err(_) => {
                        browser_gate = BrowserQuicIngressGate::new();
                        routes.disconnect().await;
                        state.write().await.log(
                            LogLevel::Warn,
                            "INGRESS_MPQUIC_DATAGRAM_REJECTED",
                            unix_millis(),
                        );
                        break;
                    }
                }
            }
            continue;
        }
        let ingress = match observed.authorize_ip(&policy, now_ms) {
            Ok(ingress) => ingress,
            Err(ClientIngressUdpError::Policy(_)) => {
                state.write().await.record_policy_rejection();
                continue;
            }
            Err(_) => {
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_UDP_DATAGRAM_REJECTED",
                    unix_millis(),
                );
                continue;
            }
        };
        if Box::pin(routes.ensure_general_udp(&config, &discovery, &helper))
            .await
            .is_err()
        {
            state.write().await.log(
                LogLevel::Warn,
                "INGRESS_UDP_ROUTE_UNAVAILABLE",
                unix_millis(),
            );
            continue;
        }
        let activation_ms = unix_millis();
        let Some(active_policy) = state.read().await.active_policy(activation_ms) else {
            routes.disconnect().await;
            state.write().await.record_policy_rejection();
            continue;
        };
        let ingress = match ingress.reauthorize_ip_after_route_ready(&active_policy, activation_ms)
        {
            Ok(ingress) => ingress,
            Err(ClientIngressUdpError::Policy(_)) => {
                routes.disconnect().await;
                state.write().await.record_policy_rejection();
                continue;
            }
            Err(_) => {
                routes.disconnect().await;
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_UDP_DATAGRAM_REJECTED",
                    unix_millis(),
                );
                continue;
            }
        };
        if Box::pin(routes.activate_udp_ingress(ingress, &active_policy, activation_ms))
            .await
            .is_err()
        {
            state.write().await.log(
                LogLevel::Warn,
                "INGRESS_UDP_ROUTE_UNAVAILABLE",
                unix_millis(),
            );
            continue;
        }
        let response = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            result = routes.receive_udp_response() => match result {
                Ok(response) => response,
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_UDP_RESPONSE_UNAVAILABLE",
                        unix_millis(),
                    );
                    continue;
                }
            },
        };
        if runtime
            .send_udp_response(
                response.application(),
                response.remote(),
                response.payload(),
            )
            .await
            .is_err()
        {
            state
                .write()
                .await
                .log(LogLevel::Warn, "INGRESS_UDP_REPLY_FAILED", unix_millis());
        }
        routes.disconnect().await;
    }
}

/// Owns the helper-acquired DNS socket. Every accepted query is policy-bound to its QNAME and
/// crosses the existing single-relay protected QUIC route; this actor never opens a resolver
/// socket on the Client.
#[allow(clippy::single_match_else, clippy::too_many_lines)]
async fn run_client_dns_ingress(
    runtime: Option<Arc<ClientIngressRuntime>>,
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    discovery: DiscoveryControlHandle,
    helper: HelperClient,
    routes: ClientRouteControl,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(runtime) = runtime else {
        wait_for_shutdown(&mut shutdown).await;
        return;
    };
    let Ok([ipv4_descriptor, ipv6_descriptor]) = runtime.duplicate_dns_udp_poll_descriptors()
    else {
        state
            .write()
            .await
            .log(LogLevel::Error, "INGRESS_DNS_POLL_FAILED", unix_millis());
        return;
    };
    let (Ok(ipv4_poll), Ok(ipv6_poll)) =
        (AsyncFd::new(ipv4_descriptor), AsyncFd::new(ipv6_descriptor))
    else {
        state
            .write()
            .await
            .log(LogLevel::Error, "INGRESS_DNS_POLL_FAILED", unix_millis());
        return;
    };
    loop {
        let ready = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    routes.disconnect().await;
                    return;
                }
                continue;
            }
            result = ipv4_poll.readable() => match result {
                Ok(ready) => (ClientIngressSocketFamily::Ipv4, ready),
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Error,
                        "INGRESS_DNS_POLL_FAILED",
                        unix_millis(),
                    );
                    return;
                }
            },
            result = ipv6_poll.readable() => match result {
                Ok(ready) => (ClientIngressSocketFamily::Ipv6, ready),
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Error,
                        "INGRESS_DNS_POLL_FAILED",
                        unix_millis(),
                    );
                    return;
                }
            },
        };
        let (family, mut ready) = ready;
        let now_ms = unix_millis();
        let Some(policy) = state.read().await.active_policy(now_ms) else {
            ready.clear_ready();
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        routes.disconnect().await;
                        return;
                    }
                }
                () = tokio::time::sleep(INGRESS_POLICY_BACKOFF) => {}
            }
            continue;
        };
        let ingress = match runtime.try_receive_dns_udp(family, &policy, now_ms) {
            Ok(ingress) => ingress,
            Err(ClientIngressUdpError::Receive(error))
                if error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                ready.clear_ready();
                continue;
            }
            Err(ClientIngressUdpError::Policy(_)) => {
                ready.clear_ready();
                state.write().await.record_policy_rejection();
                continue;
            }
            Err(_) => {
                ready.clear_ready();
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_DNS_QUERY_REJECTED",
                    unix_millis(),
                );
                continue;
            }
        };
        ready.clear_ready();
        if Box::pin(routes.ensure_single_udp(&config, &discovery, &helper))
            .await
            .is_err()
        {
            state.write().await.log(
                LogLevel::Warn,
                "INGRESS_DNS_ROUTE_UNAVAILABLE",
                unix_millis(),
            );
            continue;
        }
        if Box::pin(routes.activate_dns_ingress(ingress, &policy, now_ms))
            .await
            .is_err()
        {
            routes.disconnect().await;
            state
                .write()
                .await
                .log(LogLevel::Warn, "INGRESS_DNS_QUERY_REJECTED", unix_millis());
            continue;
        }
        let response = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    routes.disconnect().await;
                    return;
                }
                routes.disconnect().await;
                continue;
            }
            result = routes.receive_udp_response() => match result {
                Ok(response) => response,
                Err(_) => {
                    routes.disconnect().await;
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_DNS_RESPONSE_UNAVAILABLE",
                        unix_millis(),
                    );
                    continue;
                }
            },
        };
        let sent = runtime
            .send_udp_response(
                response.application(),
                response.remote(),
                response.payload(),
            )
            .await
            .is_ok();
        routes.disconnect().await;
        state.write().await.log(
            if sent { LogLevel::Info } else { LogLevel::Warn },
            if sent {
                "INGRESS_DNS_QUERY_COMPLETED"
            } else {
                "INGRESS_DNS_REPLY_FAILED"
            },
            unix_millis(),
        );
    }
}

/// Own both dedicated DNS-over-TCP listeners. Each accepted stream is bound to its kernel
/// original resolver tuple; every framed query still crosses the same protected one-relay DNS
/// association used by UDP, and the Client never opens a resolver socket directly.
#[allow(clippy::single_match_else, clippy::too_many_lines)]
async fn run_client_dns_tcp_ingress(
    runtime: Option<Arc<ClientIngressRuntime>>,
    state: Arc<RwLock<AgentState>>,
    config: Arc<Config>,
    discovery: DiscoveryControlHandle,
    helper: HelperClient,
    routes: ClientRouteControl,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(runtime) = runtime else {
        wait_for_shutdown(&mut shutdown).await;
        return;
    };
    let Ok([ipv4, ipv6]) = runtime.dns_tcp_listeners() else {
        state.write().await.log(
            LogLevel::Error,
            "INGRESS_DNS_TCP_LISTENER_FAILED",
            unix_millis(),
        );
        return;
    };
    loop {
        let observed = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    routes.disconnect().await;
                    return;
                }
                continue;
            }
            result = ipv4.accept() => result,
            result = ipv6.accept() => result,
        };
        let (mut application, source, resolver) =
            match observed.and_then(client_ingress::ObservedTcpIngress::into_dns_parts) {
                Ok(parts) => parts,
                Err(ClientIngressTcpError::OriginalDestination(_)) => {
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_DNS_TCP_DESTINATION_REJECTED",
                        unix_millis(),
                    );
                    continue;
                }
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_DNS_TCP_ACCEPT_FAILED",
                        unix_millis(),
                    );
                    tokio::time::sleep(INGRESS_POLICY_BACKOFF).await;
                    continue;
                }
            };

        loop {
            let mut length = [0_u8; 2];
            let read_length = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        routes.disconnect().await;
                        return;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    DNS_TCP_IO_TIMEOUT,
                    application.read_exact(&mut length),
                ) => result,
            };
            if read_length.is_err() || read_length.is_ok_and(|result| result.is_err()) {
                break;
            }
            let query_length = usize::from(u16::from_be_bytes(length));
            if query_length == 0 || query_length > MAX_DNS_MESSAGE_BYTES {
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_DNS_TCP_QUERY_REJECTED",
                    unix_millis(),
                );
                break;
            }
            let mut query = vec![0_u8; query_length];
            let read_query = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        routes.disconnect().await;
                        return;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    DNS_TCP_IO_TIMEOUT,
                    application.read_exact(&mut query),
                ) => result,
            };
            if read_query.is_err() || read_query.is_ok_and(|result| result.is_err()) {
                break;
            }
            let now_ms = unix_millis();
            let Some(policy) = state.read().await.active_policy(now_ms) else {
                state.write().await.record_policy_rejection();
                break;
            };
            let ingress = match PolicyAuthorizedDnsIngress::authorize(
                source, resolver, query, &policy, now_ms,
            ) {
                Ok(ingress) => ingress,
                Err(ClientIngressUdpError::Policy(_)) => {
                    state.write().await.record_policy_rejection();
                    break;
                }
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Warn,
                        "INGRESS_DNS_TCP_QUERY_REJECTED",
                        unix_millis(),
                    );
                    break;
                }
            };
            if Box::pin(routes.ensure_single_udp(&config, &discovery, &helper))
                .await
                .is_err()
                || Box::pin(routes.activate_dns_ingress(ingress, &policy, now_ms))
                    .await
                    .is_err()
            {
                routes.disconnect().await;
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_DNS_TCP_ROUTE_UNAVAILABLE",
                    unix_millis(),
                );
                break;
            }
            let response = tokio::select! {
                changed = shutdown.changed() => {
                    routes.disconnect().await;
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                result = routes.receive_udp_response() => result,
            };
            let Ok(response) = response else {
                routes.disconnect().await;
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_DNS_TCP_RESPONSE_UNAVAILABLE",
                    unix_millis(),
                );
                break;
            };
            if response.application() != source || response.remote() != resolver {
                routes.disconnect().await;
                state.write().await.log(
                    LogLevel::Warn,
                    "INGRESS_DNS_TCP_RESPONSE_REJECTED",
                    unix_millis(),
                );
                break;
            }
            let Ok(response_length) = u16::try_from(response.payload().len()) else {
                routes.disconnect().await;
                break;
            };
            let mut framed = Vec::with_capacity(2 + response.payload().len());
            framed.extend_from_slice(&response_length.to_be_bytes());
            framed.extend_from_slice(response.payload());
            let sent = tokio::select! {
                changed = shutdown.changed() => {
                    routes.disconnect().await;
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                result = tokio::time::timeout(DNS_TCP_IO_TIMEOUT, async {
                    application.write_all(&framed).await?;
                    application.flush().await
                }) => matches!(result, Ok(Ok(()))),
            };
            routes.disconnect().await;
            state.write().await.log(
                if sent { LogLevel::Info } else { LogLevel::Warn },
                if sent {
                    "INGRESS_DNS_TCP_QUERY_COMPLETED"
                } else {
                    "INGRESS_DNS_TCP_REPLY_FAILED"
                },
                unix_millis(),
            );
            if !sent {
                break;
            }
        }
    }
}

async fn stop_task<T>(task: &mut JoinHandle<T>) {
    // One actor handle may already have been polled to completion by the runtime select above.
    // Tokio JoinHandles are not fused and panic when polled again after yielding their result.
    if task.is_finished() {
        return;
    }
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
    routes: ClientRouteControl,
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
                    // Native route setup can keep the single discovery owner busy beyond this
                    // maintenance call's bounded timeout. The command remains safely queued; a
                    // transient timeout must not terminate the whole agent process.
                    continue;
                }
                let mut locked = state.write().await;
                if policy_load_failed {
                    if was_active {
                        locked.log(LogLevel::Error, "POLICY_LOAD_FAILED", now_ms);
                    }
                } else if is_active != was_active {
                    locked.log(
                        if is_active { LogLevel::Info } else { LogLevel::Warn },
                        if is_active { "POLICY_ACTIVE" } else { "POLICY_UNAVAILABLE" },
                        now_ms,
                    );
                }
                drop(locked);
                match routes.maintain_path_health(now_ms).await {
                    Ok(ClientPathMaintenance::Unchanged) => {}
                    Ok(ClientPathMaintenance::Reconfigured) => {
                        state.write().await.log(
                            LogLevel::Warn,
                            "MPQUIC_PATH_RECONFIGURED",
                            now_ms,
                        );
                    }
                    Err(_) => {
                        routes.disconnect().await;
                        state.write().await.log(
                            LogLevel::Error,
                            "MPQUIC_PATH_FAIL_CLOSED",
                            now_ms,
                        );
                    }
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
    /// The process-owned client ingress could not be prepared or activated.
    #[error("client ingress runtime is unavailable")]
    ClientIngress,
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
            Self::ClientIngress => "CLIENT_INGRESS_FAILED",
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

    #[tokio::test]
    async fn shutdown_does_not_repoll_a_consumed_actor_handle() {
        let mut task = tokio::spawn(async { 7_u8 });
        assert_eq!((&mut task).await.expect("actor task"), 7);

        stop_task(&mut task).await;
    }

    #[test]
    fn maintenance_policy_timeout_keeps_the_actor_alive() {
        let source = include_str!("lib.rs");
        let refresh_failure = source
            .split_once("if discovery.apply_policy(policy).await.is_err() {")
            .expect("maintenance policy refresh branch")
            .1
            .split_once("let mut locked = state.write().await;")
            .expect("maintenance continues with policy state")
            .0;

        assert!(refresh_failure.contains("continue;"));
        assert!(!refresh_failure.contains("break;"));
    }

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
