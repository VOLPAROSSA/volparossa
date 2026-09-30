//! Finite operator-delegated application TCP tunnels over genuine overlay MPTCP.
//!
//! The separate app socket never dispatches administrative requests. A kernel UID plus an
//! opaque capability delegates authority; neither proves a specific browser executable.
//! Each attachment owns its own route controller, never the shared main/DNS controller.

mod connect;
mod wire;

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{
    net::{TcpListener, UnixListener, UnixStream},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use volparossa_local_control::{BrowserGatewayGrantRequest, BrowserGatewayGranted};
use volparossa_policy::{TransportProtocol, VerifiedManifest, normalize_domain};

use crate::{
    control::ControlContext,
    route_setup::{ClientRouteControl, ClientRouteDisconnectError},
    unix_millis,
};

const MAX_ATTACHMENTS: usize = 8;
const MAX_STREAMS: usize = 8;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);

/// In-memory, bounded delegation owner. No authority, hostname or partition is persisted.
#[derive(Clone)]
pub(crate) struct BrowserGateway {
    app_socket: Arc<PathBuf>,
    mpquic_socket: Arc<PathBuf>,
    grants: Arc<Mutex<BTreeMap<[u8; 32], IssuedGrant>>>,
}

struct IssuedGrant {
    scope: Arc<Scope>,
    routes: ClientRouteControl,
    claimed: bool,
}

struct Scope {
    uid: u32,
    hostname: String,
    port: u16,
    partition: [u8; 32],
    policy_hash: [u8; 32],
    expires_at_ms: u64,
    deadline: Instant,
}

struct Attachment {
    key: [u8; 32],
    scope: Arc<Scope>,
    routes: ClientRouteControl,
    proxy_secret: [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) enum GatewayError {
    Invalid,
    Policy,
    Busy,
    Unavailable,
    /// Not interchangeable with generic errors. Still requires confirmed retirement,
    /// live grant/policy and no published Ready before a browser may fall back.
    NoEligiblePaths,
}

impl GatewayError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "BROWSER_GATEWAY_INVALID",
            Self::Policy => "BROWSER_GATEWAY_POLICY",
            Self::Busy => "BROWSER_GATEWAY_BUSY",
            Self::Unavailable => "BROWSER_GATEWAY_UNAVAILABLE",
            Self::NoEligiblePaths => "BROWSER_GATEWAY_NO_ELIGIBLE_PATHS",
        }
    }
}

impl BrowserGateway {
    pub(crate) fn new(app_socket: PathBuf, mpquic_socket: PathBuf) -> Self {
        Self {
            app_socket: Arc::new(app_socket),
            mpquic_socket: Arc::new(mpquic_socket),
            grants: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) async fn grant(
        &self,
        request: BrowserGatewayGrantRequest,
        context: &ControlContext,
    ) -> Result<BrowserGatewayGranted, GatewayError> {
        request.validate().map_err(|_| GatewayError::Invalid)?;
        if normalize_domain(&request.hostname).map_err(|_| GatewayError::Invalid)?
            != request.hostname
        {
            return Err(GatewayError::Invalid);
        }
        let now = unix_millis();
        let state = context.state.read().await;
        let policy = state.active_policy(now).ok_or(GatewayError::Policy)?;
        if !state.roles().client {
            return Err(GatewayError::Policy);
        }
        let port = u16::try_from(request.port).map_err(|_| GatewayError::Invalid)?;
        policy
            .authorize_domain(now, &request.hostname, TransportProtocol::Tcp, port)
            .map_err(|_| GatewayError::Policy)?;
        let scope = Arc::new(Scope {
            uid: request.app_uid,
            hostname: request.hostname,
            port,
            partition: request
                .partition
                .try_into()
                .map_err(|_| GatewayError::Invalid)?,
            policy_hash: *policy.policy_hash(),
            expires_at_ms: now + u64::from(request.lifetime_seconds) * 1000,
            deadline: Instant::now() + Duration::from_secs(u64::from(request.lifetime_seconds)),
        });
        drop(state);
        let key = self.issue(Arc::clone(&scope)).await?;
        Ok(BrowserGatewayGranted {
            app_socket: self.app_socket.to_string_lossy().into_owned(),
            capability: key.to_vec(),
            expires_at_ms: scope.expires_at_ms,
            hostname: scope.hostname.clone(),
            port: u32::from(scope.port),
            partition: scope.partition.to_vec(),
        })
    }

    async fn issue(&self, scope: Arc<Scope>) -> Result<[u8; 32], GatewayError> {
        let mut grants = self.grants.lock().await;
        grants.retain(|_, grant| grant.claimed || grant.scope.live());
        if grants.len() >= MAX_ATTACHMENTS {
            return Err(GatewayError::Busy);
        }
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        let id = grant_id(&key);
        if grants.contains_key(&id) {
            return Err(GatewayError::Unavailable);
        }
        grants.insert(
            id,
            IssuedGrant {
                scope,
                // No shared AgentState projection: an app cannot erase another route's paths.
                routes: ClientRouteControl::new((*self.mpquic_socket).clone()),
                claimed: false,
            },
        );
        Ok(key)
    }

    async fn claim(
        &self,
        key: [u8; 32],
        partition: &[u8; 32],
        uid: u32,
    ) -> Result<Attachment, GatewayError> {
        let mut grants = self.grants.lock().await;
        let id = grant_id(&key);
        let grant = grants.get_mut(&id).ok_or(GatewayError::Invalid)?;
        if grant.claimed
            || !grant.scope.live()
            || grant.scope.uid != uid
            || grant.scope.partition != *partition
        {
            return Err(GatewayError::Invalid);
        }
        grant.claimed = true;
        let mut proxy_secret = [0; 32];
        OsRng.fill_bytes(&mut proxy_secret);
        Ok(Attachment {
            key: id,
            scope: Arc::clone(&grant.scope),
            routes: grant.routes.clone(),
            proxy_secret,
        })
    }

    async fn retire(&self, attachment: &Attachment) -> Result<(), ClientRouteDisconnectError> {
        attachment.routes.shutdown_confirmed().await?;
        self.grants.lock().await.remove(&attachment.key);
        Ok(())
    }

    /// Retained controllers survive cancelled app tasks until exact route cleanup is confirmed.
    pub(crate) async fn shutdown_confirmed(&self) -> Result<(), ClientRouteDisconnectError> {
        let owners: Vec<_> = self
            .grants
            .lock()
            .await
            .iter()
            .map(|(key, grant)| (*key, grant.routes.clone()))
            .collect();
        let mut retirements = JoinSet::new();
        for (key, routes) in owners {
            retirements.spawn(async move { (key, routes.shutdown_confirmed().await) });
        }
        let mut clean = true;
        while let Some(result) = retirements.join_next().await {
            if let Ok((key, Ok(()))) = result {
                self.grants.lock().await.remove(&key);
            } else {
                clean = false;
            }
        }
        if clean {
            Ok(())
        } else {
            Err(ClientRouteDisconnectError::CleanupPending)
        }
    }

    pub(crate) async fn serve(
        &self,
        listener: UnixListener,
        context: ControlContext,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), std::io::Error> {
        let permits = Arc::new(Semaphore::new(MAX_ATTACHMENTS));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                () = crate::wait_for_shutdown(&mut shutdown) => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                    let gateway = self.clone();
                    let context = context.clone();
                    let shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        gateway.bootstrap(stream, context, shutdown).await;
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        // The shared shutdown first lets each attachment abort and join its own stream tasks
        // before retiring that route. Unauthenticated bootstrap waits are bounded to five seconds.
        // Agent cancellation still retains every controller for cleanup before discovery stops.
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn bootstrap(
        &self,
        mut stream: UnixStream,
        context: ControlContext,
        shutdown: watch::Receiver<bool>,
    ) {
        let Ok(credentials) = stream.peer_cred() else {
            return;
        };
        let Ok(Ok(request)) = timeout(BOOTSTRAP_TIMEOUT, wire::read_bootstrap(&mut stream)).await
        else {
            return;
        };
        let Ok(attachment) = self.claim(request.0, &request.1, credentials.uid()).await else {
            return;
        };
        let result = attachment
            .serve(&mut stream, &context, shutdown.clone())
            .await;
        // Failure remains retained/quota-charged for daemon cleanup, never global Disconnect.
        let retired = self.retire(&attachment).await.is_ok();
        if let Err(error) = result {
            // Only pre-Ready admission failures arrive here. After Ready, loss/expiry
            // closes the attachment and must never authorize a transparent direct retry.
            let policy_expiry = attachment
                .scope
                .policy(&context)
                .await
                .ok()
                .map(|policy| policy.expires_at_ms());
            let direct_until_ms = wire::direct_deadline(
                error,
                retired,
                !*shutdown.borrow() && shutdown.has_changed().is_ok(),
                &attachment.scope,
                policy_expiry,
            );
            let _ = timeout(
                BOOTSTRAP_TIMEOUT,
                wire::write_failure(&mut stream, &attachment, direct_until_ms),
            )
            .await;
        }
    }
}

// Index by a fixed-length SHA-256 capability digest, never ordered raw secret bytes. An
// attacker cannot choose a comparison prefix without finding a corresponding preimage.
fn grant_id(capability: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(capability).into()
}

impl Scope {
    fn live(&self) -> bool {
        unix_millis() < self.expires_at_ms && Instant::now() < self.deadline
    }

    async fn policy(&self, context: &ControlContext) -> Result<VerifiedManifest, GatewayError> {
        let state = context.state.read().await;
        let now = unix_millis();
        let policy = state.active_policy(now).ok_or(GatewayError::Policy)?;
        if !self.live() || !state.roles().client || *policy.policy_hash() != self.policy_hash {
            return Err(GatewayError::Policy);
        }
        policy
            .authorize_domain(now, &self.hostname, TransportProtocol::Tcp, self.port)
            .map_err(|_| GatewayError::Policy)?;
        Ok(policy)
    }
}

impl Attachment {
    async fn serve(
        &self,
        bootstrap: &mut UnixStream,
        context: &ControlContext,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), GatewayError> {
        self.scope.policy(context).await?;
        // Cold signed discovery/native probing may outlast a browser's CONNECT/TLS timer.
        // Do not publish Ready (or a proxy listener) until this independently owned route
        // is prepared. No origin TLS/payload is sent or certified by this control handshake.
        connect::prepare(
            bootstrap,
            &mut shutdown,
            self.scope
                .deadline
                .min(Instant::now() + connect::PREPARE_TIMEOUT),
            Box::pin(
                self.routes
                    .connect_tcp(&context.config, &context.discovery, &context.helper),
            ),
        )
        .await?;
        self.scope.policy(context).await?;
        // Only a loopback listener is created. There is no destination TcpStream::connect here.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        let port = listener
            .local_addr()
            .map_err(|_| GatewayError::Unavailable)?
            .port();
        timeout(BOOTSTRAP_TIMEOUT, wire::write_ready(bootstrap, self, port))
            .await
            .map_err(|_| GatewayError::Unavailable)??;
        let mut streams = JoinSet::new();
        let mut policy_tick = tokio::time::interval(Duration::from_secs(1));
        let mut unexpected = [0; 1];
        loop {
            use tokio::io::AsyncReadExt;
            tokio::select! {
                () = crate::wait_for_shutdown(&mut shutdown) => break,
                () = tokio::time::sleep_until(self.scope.deadline) => break,
                _ = bootstrap.read(&mut unexpected) => break,
                _ = policy_tick.tick() => {
                    if self.scope.policy(context).await.is_err() { break; }
                }
                accepted = listener.accept() => {
                    let Ok((application, peer)) = accepted else { break; };
                    if !peer.ip().is_loopback() || streams.len() >= MAX_STREAMS { continue; }
                    let scope = Arc::clone(&self.scope);
                    let routes = self.routes.clone();
                    let context = context.clone();
                    let secret = self.proxy_secret;
                    streams.spawn(async move {
                        Box::pin(connect::proxy(application, &scope, &routes, &context, &secret)).await;
                    });
                }
                Some(_) = streams.join_next(), if !streams.is_empty() => {}
            }
        }
        streams.abort_all();
        while streams.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests;
