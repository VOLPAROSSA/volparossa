//! Bounded, actor-authorized, hard-incompatible privacy-v4 client route setup.
//!
//! Stored advertisements may nominate identities for selection, but they never authorize an RPC.
//! Every control relay, forwarded exit, and prospective datapath relay is resolved again through
//! the discovery actor immediately before setup. The local Connect boundary now owns one affine
//! A1/native-preselection attempt through a helper-backed native path proof. The resulting affine
//! proof owner remains local until the later full-route admission stage consumes it.

#![allow(
    dead_code,
    reason = "a future transparent ingress coordinator consumes this boundary"
)]

mod retirement;
mod selection_bridge;

pub(crate) use selection_bridge::{
    PreProbeContinuation, PreparedPreselectionEvidence, prepare_preselection_evidence,
};

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId as Libp2pPeerId;
use rand_core::{OsRng, RngCore};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, oneshot, watch},
    time::{Instant, timeout},
};
use volparossa_config::{ClientAddressFamily, Config, TcpTransport};
use volparossa_core::{
    Bandwidth, IpFamily, NodeId, ObservedNetworkPrefix, OperatorId, PathId, ServiceRole,
    Transport as SelectionTransport, UnixTime,
};
use volparossa_discovery::{
    DATAPATH_RELAY_REQUEST_TIMEOUT, DatapathRelayOperation, DatapathRelayRequest,
    DatapathRelayResponse, ExitForwardOperation, ExitForwardRequest, ExitForwardResponse,
    ExitMpquicSessionSignal, ExitMptcpSessionSignal as DiscoveryExitMptcpSessionSignal,
    ForwardStatus, MpquicSessionPathProof, MpquicSessionStartRequest, MptcpSessionPathProof,
    MptcpSessionStartRequest, UdpExitSessionSignal as DiscoveryUdpExitSessionSignal,
    UdpSessionStartRequest,
};
use volparossa_local_control::{PathState, PathSummary};
use volparossa_policy::{TransportProtocol, VerifiedManifest};
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, ProbeAddressFamily, ProbeLegEvidence, ReplayCache, SignedEnvelope,
    TimePolicy, Transport, decode_canonical, encode_canonical,
};
use volparossa_quic::{NativeClient, NativePathStatus};
use volparossa_reservation::{
    ClientNativeRouteAuthorization, ExitReservationIntent, RelayPathIntent, ReservationCoordinator,
    SignedExitFinalizeRequest, SignedProbePermitRequest, VerifiedExitCapacityHold,
    VerifiedFinalizedExitBundle, VerifiedProbePermit, VerifiedRelayGrant, VerifiedRelayProbe,
};
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, ActivatedLeaseBatch, CommitLeaseBatch,
    CommittedLeaseBatch, ContextRole, DestroyedContext, HelperResult, LeaseActivation, LeaseCommit,
    LeasePlan, MAX_HELPER_PATHS, MAX_HELPER_RATE_MBPS, PrepareLeaseBatch, PublicUdpEndpoint,
    ReconciledExpiredPrepare, WireguardRole,
};
#[cfg(test)]
use volparossa_routing::{PreparedLeaseBatch, TransportSocketAddress, TransportSocketKind};
#[cfg(test)]
use volparossa_selection::Candidate;
use volparossa_selection::{
    FilterRequirements, HysteresisPolicy, PathMetrics, PathState as SelectionPathState, PathStatus,
    ProjectedRelayPath, RelaySelectionPolicy, ReplacementDecision, ReplacementHysteresis,
    SelectionMix, select_projected_relay_paths,
};
use volparossa_tcp_proxy::VerifiedMptcpRoute;
use volparossa_udp::{
    AuthorizedUdpFlow, CommittedQuicUdpTransport, CommittedUdpRole, ProtectedExitUdpTarget,
    SINGLE_RELAY_UDP_EXIT_PORT, SingleRelayUdpClient, VerifiedSingleRelayPath,
    committed_quic_udp_socket_request,
};
#[cfg(test)]
use volparossa_wireguard::overlay_addresses;
use volparossa_wireguard::{HELPER_HANDLE_BYTES, HelperContextHandle, PublicWireGuardEndpoint};

use crate::{
    client_ingress::{
        BrowserQuicFlowBinding, PolicyAuthorizedDnsIngress, PolicyAuthorizedTcpIngress,
        PolicyAuthorizedUdpIngress, RouteAuthorizedUdpIngress,
    },
    discovery::{
        AdvertisementPayloadHash, ClientPreselectionError, ClientPreselectionParameters,
        DirectRelayCapability, DiscoveryControlHandle, EndpointTraversalBinding,
        ForwardedExitCapability, OutboundReservationError,
    },
    endpoint_leases::{LocalEndpointLeaseBatch, bind_prepared_endpoint_leases},
    helper::{
        HelperClient, HelperClientError, PrepareLeaseBatchFailure, PrepareReconciliationAuthority,
        RuntimeBoundPreparedLeaseBatch,
    },
    mpquic_runtime::{
        MINIMUM_MPQUIC_TUNNEL_MTU, ProductionMpquicPreflight, ProductionMpquicSession,
    },
    mptcp_flow_runtime::{ActiveProductionMptcpClientFlow, activate_production_mptcp_client_flow},
    mptcp_transport::{
        ClientMptcpTransport, ExitMptcpListenerSignal, MptcpTransportError,
        PRODUCTION_MPTCP_EXIT_PORT,
    },
    paths::DEFAULT_MPQUIC_SOCKET,
    state::AgentState,
};
use retirement::{PreparedContextOwner, RetirementOutcome, RetirementSink, RetirementSupervisor};

const MAXIMUM_SETUP_DURATION: Duration = Duration::from_secs(30);
const MAXIMUM_CALL_DURATION: Duration = Duration::from_secs(12);
const MAXIMUM_OUTBOUND_ATTEMPTS: u8 = 3;
const MAXIMUM_RESERVATION_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const MAXIMUM_PHASE_LIFETIME_MS: u64 = 30 * 1_000;
const MAXIMUM_REPLAY_CAPACITY: usize = 65_536;
const MAXIMUM_RETIREMENT_OWNERS: usize = 64;
const MAXIMUM_CLIENT_BROWSER_QUIC_FLOWS: usize = 256;
const ID_BYTES: usize = 16;
const CLIENT_SINGLE_RELAY_UDP_PORT: u16 = 40_001;
const MAXIMUM_TCP_STREAM_CHUNK_BYTES: usize = 64 * 1_024;
const OPEN_TCP_LIFETIME_MS: u64 = 60_000;
const MPQUIC_READY_WAIT: Duration = Duration::from_secs(10);
const TCP_CONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(1);
// The discovery attempt owner cools for 30 seconds after a successful route bootstrap. Keep a
// small bounded recovery window beyond it without extending any individual setup deadline.
const TCP_CONNECT_RECOVERY_HORIZON: Duration = Duration::from_secs(35);

/// Cloneable single-owner gate for the local Connect route bootstrap.
#[derive(Clone)]
pub(crate) struct ClientRouteControl {
    state: Arc<Mutex<ClientRouteControlState>>,
    tcp_connect: Arc<Mutex<()>>,
    mpquic_socket: Arc<PathBuf>,
    agent_state: Option<Arc<tokio::sync::RwLock<AgentState>>>,
}

impl Default for ClientRouteControl {
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_MPQUIC_SOCKET))
    }
}

#[derive(Default)]
enum ClientRouteControlState {
    #[default]
    Idle,
    Connecting,
    Established(Box<EstablishedClientRoute>),
}

struct EstablishedClientRoute {
    expiry: ClientRouteExpiry,
    transport: ClientTransportState,
    tcp_flow: Option<ActiveProductionMptcpClientFlow>,
    route: Option<ProductionRoute>,
    orchestrator: ProductionRouteOrchestrator,
    helper: HelperClient,
}

/// Immutable hard lifetime retained independently of transport-specific route ownership.
///
/// The wall deadline preserves the signed/helper authority boundary. Its monotonic projection
/// additionally prevents a backward wall-clock adjustment from resurrecting an established route.
#[derive(Clone, Copy, Debug)]
struct ClientRouteExpiry {
    hard_expires_at_ms: u64,
    monotonic_deadline: Instant,
}

enum ClientTransportState {
    TcpMptcp(ClientMptcpTransport),
    UdpReady(CertificateBoundProductionUdpRoute),
    UdpActive(ActiveProductionUdpRoute),
    NativeUdp(Box<ActiveProductionNativeUdpRoute>),
    Mpquic(Box<ActiveProductionMpquicRoute>),
}

struct ActiveProductionNativeUdpRoute {
    session: ProductionMpquicSession,
    path: VerifiedSingleRelayPath,
    binding: Option<RouteAuthorizedUdpIngress>,
}

struct ActiveProductionMpquicRoute {
    session: ProductionMpquicSession,
    identity: CommittedMpquicRouteIdentity,
    health: ProductionMpquicPathHealth,
    browser_flows: Vec<BrowserQuicFlowBinding>,
}

#[derive(Clone, Copy)]
struct NativePathCounters {
    delivered_bytes: u64,
    packets_lost: u64,
    last_progress_at: UnixTime,
}

struct ProductionMpquicPathHealth {
    statuses: BTreeMap<u32, PathStatus>,
    counters: BTreeMap<u32, NativePathCounters>,
    hysteresis: ReplacementHysteresis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientPathMaintenance {
    Unchanged,
    Reconfigured,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommittedMpquicPathIdentity {
    path_id: u32,
    relay_peer_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommittedMpquicRouteIdentity {
    route_context_id: [u8; ID_BYTES],
    exit_peer_id: String,
    paths: Vec<CommittedMpquicPathIdentity>,
}

impl EstablishedClientRoute {
    fn is_expired(&self, wall_now_ms: u64, monotonic_now: Instant) -> bool {
        self.expiry.is_expired(wall_now_ms, monotonic_now)
    }

    const fn progress(&self) -> ClientRouteProgress {
        match &self.transport {
            ClientTransportState::UdpReady(_) => ClientRouteProgress::UdpRouteReady,
            ClientTransportState::TcpMptcp(_)
            | ClientTransportState::UdpActive(_)
            | ClientTransportState::NativeUdp(_)
            | ClientTransportState::Mpquic(_) => ClientRouteProgress::TransportActive,
        }
    }

    const fn matches_transport(&self, transport: Transport, native_single_udp: bool) -> bool {
        matches!(
            (&self.transport, transport, native_single_udp),
            (ClientTransportState::TcpMptcp(_), Transport::TcpMptcp, _)
                | (
                    ClientTransportState::UdpReady(_) | ClientTransportState::UdpActive(_),
                    Transport::UdpSinglePath,
                    false
                )
                | (
                    ClientTransportState::NativeUdp(_),
                    Transport::UdpSinglePath,
                    true
                )
                | (ClientTransportState::Mpquic(_), Transport::MultipathQuic, _)
        )
    }

    async fn shutdown(self) {
        if let Some(flow) = self.tcp_flow {
            flow.shutdown();
        }
        match self.transport {
            ClientTransportState::TcpMptcp(transport) => {
                let _ = transport.shutdown(&self.helper).await;
            }
            ClientTransportState::UdpReady(route) => {
                let _ = Box::pin(route.disconnect()).await;
            }
            ClientTransportState::UdpActive(route) => {
                let _ = route.shutdown().await;
            }
            ClientTransportState::NativeUdp(active) => {
                let _ = active.session.shutdown().await;
            }
            ClientTransportState::Mpquic(active) => {
                let _ = active.session.shutdown().await;
            }
        }
        if let Some(route) = self.route {
            let _ = Box::pin(route.disconnect()).await;
        }
        let _ = self.orchestrator.shutdown().await;
    }
}

impl ClientRouteExpiry {
    fn from_hard_expiry(
        hard_expires_at_unix: u64,
        wall_now_ms: u64,
        monotonic_now: Instant,
    ) -> Self {
        let hard_expires_at_ms = hard_expires_at_unix.saturating_mul(1_000);
        let remaining = hard_expires_at_ms.saturating_sub(wall_now_ms);
        let monotonic_deadline = monotonic_now
            .checked_add(Duration::from_millis(remaining))
            .unwrap_or(monotonic_now);
        Self {
            hard_expires_at_ms,
            monotonic_deadline,
        }
    }

    fn is_expired(self, wall_now_ms: u64, monotonic_now: Instant) -> bool {
        wall_now_ms >= self.hard_expires_at_ms || monotonic_now >= self.monotonic_deadline
    }
}

impl ActiveProductionMpquicRoute {
    async fn path_summaries(&self) -> Result<Vec<PathSummary>, ClientRouteConnectError> {
        let statuses = self
            .session
            .path_statuses()
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        self.identity
            .project(&statuses, self.session.warm_path_ids())
    }

    async fn maintain(
        &mut self,
        now_ms: u64,
    ) -> Result<ClientPathMaintenance, ClientRouteConnectError> {
        let now = UnixTime::from_secs(now_ms / 1_000);
        let statuses = self
            .session
            .path_statuses()
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let unhealthy = self
            .health
            .observe(&statuses, now)
            .map_err(|()| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let Some(unhealthy_path_id) = unhealthy.first().copied() else {
            return Ok(ClientPathMaintenance::Unchanged);
        };

        let warm_path_id = self.session.warm_path_ids().next();
        if let Some(warm_path_id) = warm_path_id {
            if !self
                .health
                .authorizes_replacement(unhealthy_path_id, warm_path_id, now)
            {
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            }
            self.session
                .replace_active_path(unhealthy_path_id, warm_path_id, now_ms, MPQUIC_READY_WAIT)
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
            self.health
                .record_replacement(unhealthy_path_id, warm_path_id, now)
                .map_err(|()| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        } else {
            // A live browser flow may finish over the surviving native path during its bounded
            // failover grace. Do not turn physical degradation into an explicit RemovePath while
            // that would cross the route's immutable minimum: native and signed flow expiry still
            // close the degraded association, and no new route can start below its full minimum.
            if retain_degraded_path_for_active_browser_flow(
                self.session.active_path_ids().len(),
                self.session.minimum_paths(),
                self.browser_flows.len(),
            ) {
                return Ok(ClientPathMaintenance::Unchanged);
            }
            self.session
                .remove_active_path(unhealthy_path_id, now_ms, MPQUIC_READY_WAIT)
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
            self.health.retire(unhealthy_path_id);
        }

        let statuses = self
            .session
            .path_statuses()
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        self.health
            .observe(&statuses, now)
            .map_err(|()| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        if self.session.active_path_ids().len() < self.session.minimum_paths() {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        Ok(ClientPathMaintenance::Reconfigured)
    }
}

const fn retain_degraded_path_for_active_browser_flow(
    active_paths: usize,
    minimum_paths: usize,
    browser_flows: usize,
) -> bool {
    browser_flows != 0 && active_paths.saturating_sub(1) < minimum_paths
}

impl CommittedMpquicRouteIdentity {
    fn project<I>(
        &self,
        statuses: &[NativePathStatus],
        warm_path_ids: I,
    ) -> Result<Vec<PathSummary>, ClientRouteConnectError>
    where
        I: IntoIterator<Item = u32>,
    {
        if !(2..=8).contains(&statuses.len()) || statuses.len() > self.paths.len() {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let status_count = statuses.len();
        let statuses = statuses
            .iter()
            .map(|status| (status.path_id, status))
            .collect::<BTreeMap<_, _>>();
        let identities = self
            .paths
            .iter()
            .map(|identity| (identity.path_id, identity))
            .collect::<BTreeMap<_, _>>();
        if identities.len() != self.paths.len()
            || statuses.len() != status_count
            || statuses
                .keys()
                .any(|path_id| !identities.contains_key(path_id))
        {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let warm_path_ids = warm_path_ids.into_iter().collect::<Vec<_>>();
        let warm_path_count = warm_path_ids.len();
        let warm_path_ids = warm_path_ids.into_iter().collect::<BTreeSet<_>>();
        if warm_path_ids.len() != warm_path_count
            || warm_path_ids
                .iter()
                .any(|path_id| statuses.contains_key(path_id) || !identities.contains_key(path_id))
            || statuses.len().saturating_add(warm_path_ids.len()) > self.paths.len()
        {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let mut summaries = Vec::with_capacity(statuses.len() + warm_path_ids.len());
        for (path_id, status) in statuses {
            let identity = identities
                .get(&path_id)
                .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
            summaries.push(PathSummary {
                route_context_id: self.route_context_id.to_vec(),
                path_id: status.path_id,
                relay_peer_id: identity.relay_peer_id.clone(),
                exit_peer_id: self.exit_peer_id.clone(),
                state: if status.data_carrying {
                    PathState::Active as i32
                } else {
                    PathState::Reachable as i32
                },
                smoothed_rtt_micros: status.smoothed_rtt_us,
                user_bytes: status.delivered_bytes,
            });
        }
        for path_id in warm_path_ids {
            let identity = identities
                .get(&path_id)
                .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
            summaries.push(PathSummary {
                route_context_id: self.route_context_id.to_vec(),
                path_id,
                relay_peer_id: identity.relay_peer_id.clone(),
                exit_peer_id: self.exit_peer_id.clone(),
                state: PathState::Backup as i32,
                smoothed_rtt_micros: 0,
                user_bytes: 0,
            });
        }
        summaries.sort_unstable_by_key(|path| path.path_id);
        Ok(summaries)
    }
}

impl ProductionMpquicPathHealth {
    fn new(
        active_path_ids: &[u32],
        warm_path_ids: impl IntoIterator<Item = u32>,
        now: UnixTime,
    ) -> Result<Self, ClientRouteConnectError> {
        let mut statuses = BTreeMap::new();
        for path_id in active_path_ids {
            insert_health_status(&mut statuses, *path_id, SelectionPathState::Active, now)?;
        }
        for path_id in warm_path_ids {
            insert_health_status(&mut statuses, path_id, SelectionPathState::Backup, now)?;
        }
        if active_path_ids.len() < 2 || statuses.len() > 8 {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let hysteresis = ReplacementHysteresis::new(HysteresisPolicy::default())
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        Ok(Self {
            statuses,
            counters: BTreeMap::new(),
            hysteresis,
        })
    }

    fn observe(&mut self, native: &[NativePathStatus], now: UnixTime) -> Result<Vec<u32>, ()> {
        let native_ids = native
            .iter()
            .map(|status| status.path_id)
            .collect::<BTreeSet<_>>();
        let expected_ids = self
            .statuses
            .iter()
            .filter_map(|(path_id, status)| {
                matches!(
                    status.state,
                    SelectionPathState::Active
                        | SelectionPathState::Degraded
                        | SelectionPathState::Dead
                )
                .then_some(*path_id)
            })
            .collect::<BTreeSet<_>>();
        if native_ids.len() != native.len() || native_ids != expected_ids {
            return Err(());
        }
        for status in native {
            if let Some(previous) = self.counters.get(&status.path_id) {
                if status.delivered_bytes < previous.delivered_bytes
                    || status.packets_lost < previous.packets_lost
                {
                    return Err(());
                }
            }
        }
        let route_progressed = native.iter().any(|status| {
            self.counters
                .get(&status.path_id)
                .is_some_and(|previous| status.delivered_bytes > previous.delivered_bytes)
        });
        for status in native {
            let previous = self.counters.get(&status.path_id).copied();
            let delivered_delta =
                previous.map_or(0, |value| status.delivered_bytes - value.delivered_bytes);
            let lost_delta = previous.map_or(0, |value| status.packets_lost - value.packets_lost);
            let last_progress_at = previous.map_or(now, |value| {
                if delivered_delta != 0 || !route_progressed {
                    now
                } else {
                    value.last_progress_at
                }
            });
            let delivered_packets = delivered_delta.saturating_add(1_199) / 1_200;
            let observed_packets = delivered_packets.saturating_add(lost_delta);
            #[allow(clippy::cast_precision_loss)]
            let packet_loss_ratio = if observed_packets == 0 {
                0.0
            } else {
                lost_delta as f64 / observed_packets as f64
            };
            #[allow(clippy::cast_precision_loss)]
            let metrics = PathMetrics {
                smoothed_rtt_ms: status.smoothed_rtt_us as f64 / 1_000.0,
                rtt_variance_ms: 0.0,
                packet_loss_ratio,
                delivery_rate_mbps: status.delivery_rate_bps as f64 / 1_000_000.0,
                loaded_rtt_ms: status.smoothed_rtt_us as f64 / 1_000.0,
                bytes_in_flight: status.bytes_in_flight,
                last_progress_at,
                relay_reported_free: Bandwidth::default(),
                locally_estimated_free: Bandwidth::default(),
            };
            self.statuses
                .get_mut(&status.path_id)
                .ok_or(())?
                .observe(metrics, now, HysteresisPolicy::default())
                .map_err(|_| ())?;
            self.counters.insert(
                status.path_id,
                NativePathCounters {
                    delivered_bytes: status.delivered_bytes,
                    packets_lost: status.packets_lost,
                    last_progress_at,
                },
            );
        }
        let mut unhealthy = self
            .statuses
            .iter()
            .filter_map(|(path_id, status)| {
                matches!(
                    status.state,
                    SelectionPathState::Degraded | SelectionPathState::Dead
                )
                .then_some((*path_id, status.state))
            })
            .collect::<Vec<_>>();
        unhealthy.sort_unstable_by_key(|(path_id, state)| {
            (u8::from(*state != SelectionPathState::Dead), *path_id)
        });
        Ok(unhealthy.into_iter().map(|(path_id, _)| path_id).collect())
    }

    fn authorizes_replacement(
        &mut self,
        unhealthy_path_id: u32,
        warm_path_id: u32,
        now: UnixTime,
    ) -> bool {
        let Some(unhealthy) = self.statuses.get(&unhealthy_path_id).cloned() else {
            return false;
        };
        let Some(warm) = self.statuses.get(&warm_path_id).cloned() else {
            return false;
        };
        matches!(
            self.hysteresis.consider(&unhealthy, &warm, now),
            Ok(ReplacementDecision::Replace { .. })
        )
    }

    fn record_replacement(
        &mut self,
        unhealthy_path_id: u32,
        warm_path_id: u32,
        now: UnixTime,
    ) -> Result<(), ()> {
        self.retire(unhealthy_path_id);
        let warm = self.statuses.get_mut(&warm_path_id).ok_or(())?;
        warm.transition(SelectionPathState::Active, now)
            .map_err(|_| ())?;
        self.counters.remove(&warm_path_id);
        Ok(())
    }

    fn retire(&mut self, path_id: u32) {
        self.statuses.remove(&path_id);
        self.counters.remove(&path_id);
    }
}

fn insert_health_status(
    statuses: &mut BTreeMap<u32, PathStatus>,
    path_id: u32,
    state: SelectionPathState,
    now: UnixTime,
) -> Result<(), ClientRouteConnectError> {
    let path_id_value = u16::try_from(path_id)
        .ok()
        .and_then(|path_id| PathId::new(path_id).ok())
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let status = PathStatus::new(
        path_id_value,
        state,
        PathMetrics {
            smoothed_rtt_ms: 0.0,
            rtt_variance_ms: 0.0,
            packet_loss_ratio: 0.0,
            delivery_rate_mbps: 0.0,
            loaded_rtt_ms: 0.0,
            bytes_in_flight: 0,
            last_progress_at: now,
            relay_reported_free: Bandwidth::default(),
            locally_estimated_free: Bandwidth::default(),
        },
        now,
    )
    .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    if statuses.insert(path_id, status).is_some() {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    Ok(())
}

/// Detail-free current production boundary reached by a successful native-path bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientRouteProgress {
    TransportActive,
    UdpRouteReady,
}

/// One response datagram plus the exact transparent local return tuple.
pub(crate) struct ClientUdpResponse {
    application: SocketAddr,
    remote: SocketAddr,
    payload: Vec<u8>,
}

impl ClientUdpResponse {
    pub(crate) const fn application(&self) -> SocketAddr {
        self.application
    }

    pub(crate) const fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Stable local classification for a failed client-route bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientRouteConnectError {
    Busy,
    InvalidProfile,
    PreselectionUnavailable,
    NativePermitUnavailable,
    NativeRelayUnavailable,
    NativeHelperPrepareUnavailable,
    NativeAuthorizationUnavailable,
    NativeHelperActivateUnavailable,
    NativeStartUnavailable,
    NativeHelperCommitUnavailable,
    NativeProofUnavailable,
    NativeSamplerRetirementUnavailable,
    NativeRemoteRetirementUnavailable,
    NativeTransportIdentityUnavailable,
    RouteAdmissionUnavailable,
    MptcpExitListenerSignalUnavailable,
    TransportRuntimeUnavailable,
    UdpExitSessionSignalUnavailable,
    UdpIngressUnavailable,
}

impl ClientRouteControl {
    pub(crate) fn new(mpquic_socket: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClientRouteControlState::Idle)),
            tcp_connect: Arc::new(Mutex::new(())),
            mpquic_socket: Arc::new(mpquic_socket),
            agent_state: None,
        }
    }

    pub(crate) fn new_with_agent_state(
        mpquic_socket: PathBuf,
        agent_state: Arc<tokio::sync::RwLock<AgentState>>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClientRouteControlState::Idle)),
            tcp_connect: Arc::new(Mutex::new(())),
            mpquic_socket: Arc::new(mpquic_socket),
            agent_state: Some(agent_state),
        }
    }

    /// Retire an established route as soon as either projection of its signed hard deadline has
    /// elapsed. Cleanup runs outside the state lock behind `Connecting`; callers therefore never
    /// observe either an expired reusable owner or Idle until its shutdown has completed.
    async fn retire_expired_route(&self, wall_now_ms: u64, monotonic_now: Instant) {
        let expired = {
            let mut state = self.state.lock().await;
            let should_retire = matches!(
                &*state,
                ClientRouteControlState::Established(established)
                    if established.is_expired(wall_now_ms, monotonic_now)
            );
            should_retire
                .then(|| std::mem::replace(&mut *state, ClientRouteControlState::Connecting))
        };
        if let Some(ClientRouteControlState::Established(established)) = expired {
            Box::pin(established.shutdown()).await;
            self.clear_agent_mpquic_paths().await;
            let mut state = self.state.lock().await;
            if matches!(*state, ClientRouteControlState::Connecting) {
                *state = ClientRouteControlState::Idle;
            }
        }
    }

    /// Select and establish one normal relay-only MPTCP route for transparent TCP ingress.
    ///
    /// The transport-specific view prevents an enabled UDP profile from changing this TCP flow
    /// into a different route type. It does not enable any direct-Exit or ordinary-TCP path.
    pub(crate) async fn connect_tcp(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if !config.tcp.enabled
            || config.tcp.transport != TcpTransport::Mptcp
            || config.tcp.allow_plain_tcp_fallback
        {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        let _connect = self.tcp_connect.lock().await;
        let retry_deadline = Instant::now() + TCP_CONNECT_RECOVERY_HORIZON;
        loop {
            self.retire_expired_route(crate::unix_millis(), Instant::now())
                .await;
            let route_available = {
                let state = self.state.lock().await;
                match &*state {
                    ClientRouteControlState::Established(established)
                        if matches!(established.transport, ClientTransportState::TcpMptcp(_))
                            && !established.is_expired(crate::unix_millis(), Instant::now()) =>
                    {
                        return Ok(ClientRouteProgress::TransportActive);
                    }
                    ClientRouteControlState::Idle => true,
                    ClientRouteControlState::Connecting
                    | ClientRouteControlState::Established(_) => false,
                }
            };
            let result = if route_available {
                let mut tcp_profile = config.clone();
                tcp_profile.udp.enabled = false;
                tcp_profile.quic.enabled = false;
                Box::pin(self.connect_with_udp_mode(&tcp_profile, discovery, helper, false)).await
            } else {
                Err(ClientRouteConnectError::Busy)
            };
            match result {
                Ok(progress) => return Ok(progress),
                Err(error) => {
                    let Some(delay) =
                        tcp_connect_retry_delay(error, Instant::now(), retry_deadline)
                    else {
                        return Err(error);
                    };
                    tokio::time::sleep(delay).await;
                    if Instant::now() >= retry_deadline {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Ensure UDP/443 uses one genuine multipath-only route, never general UDP fallback.
    pub(crate) async fn ensure_browser_quic(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if !config.quic.enabled
            || !config.quic.require_multipath
            || config.quic.allow_degraded_single_path
            || config.quic.minimum_paths < 2
        {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        {
            self.retire_expired_route(crate::unix_millis(), Instant::now())
                .await;
            let state = self.state.lock().await;
            match &*state {
                ClientRouteControlState::Established(established)
                    if matches!(established.transport, ClientTransportState::Mpquic(_))
                        && !established.is_expired(crate::unix_millis(), Instant::now()) =>
                {
                    return Ok(ClientRouteProgress::TransportActive);
                }
                ClientRouteControlState::Idle => {}
                ClientRouteControlState::Connecting | ClientRouteControlState::Established(_) => {
                    return Err(ClientRouteConnectError::Busy);
                }
            }
        }
        let mut profile = config.clone();
        profile.tcp.enabled = false;
        profile.udp.enabled = false;
        Box::pin(self.connect_with_udp_mode(&profile, discovery, helper, false)).await
    }

    /// Ensure one relay-only single-path QUIC route is ready for UDP or protected DNS.
    pub(crate) async fn ensure_single_udp(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if !config.udp.enabled {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        {
            self.retire_expired_route(crate::unix_millis(), Instant::now())
                .await;
            let state = self.state.lock().await;
            match &*state {
                ClientRouteControlState::Established(established)
                    if matches!(established.transport, ClientTransportState::UdpReady(_))
                        && !established.is_expired(crate::unix_millis(), Instant::now()) =>
                {
                    return Ok(ClientRouteProgress::UdpRouteReady);
                }
                ClientRouteControlState::Idle => {}
                ClientRouteControlState::Connecting | ClientRouteControlState::Established(_) => {
                    return Err(ClientRouteConnectError::Busy);
                }
            }
        }
        let mut profile = config.clone();
        profile.tcp.enabled = false;
        profile.quic.enabled = false;
        Box::pin(self.connect_with_udp_mode(&profile, discovery, helper, false)).await
    }

    /// Ensure general UDP uses native single-path MASQUE CONNECT-IP through one Relay.
    pub(crate) async fn ensure_general_udp(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if !config.udp.enabled {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        let mut profile = config.clone();
        profile.tcp.enabled = false;
        profile.quic.enabled = false;
        Box::pin(self.connect_with_udp_mode(&profile, discovery, helper, true)).await
    }

    /// Starts exactly one config-bound preselection and retains its affine continuation.
    pub(crate) async fn connect(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        Box::pin(self.connect_with_udp_mode(config, discovery, helper, config.udp.enabled)).await
    }

    async fn connect_with_udp_mode(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
        native_single_udp: bool,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        let (requested_transport, _) = client_native_path_requirement(config)?;
        let previous = {
            let mut state = self.state.lock().await;
            match std::mem::replace(&mut *state, ClientRouteControlState::Connecting) {
                ClientRouteControlState::Idle => None,
                ClientRouteControlState::Established(established)
                    if established.matches_transport(requested_transport, native_single_udp)
                        && !established.is_expired(crate::unix_millis(), Instant::now()) =>
                {
                    let progress = established.progress();
                    *state = ClientRouteControlState::Established(established);
                    return Ok(progress);
                }
                ClientRouteControlState::Established(previous) => Some(previous),
                ClientRouteControlState::Connecting => {
                    return Err(ClientRouteConnectError::Busy);
                }
            }
        };
        if let Some(previous) = previous {
            Box::pin(previous.shutdown()).await;
            self.clear_agent_mpquic_paths().await;
        }

        let result = Box::pin(begin_client_route(config, discovery)).await;
        let result = match result {
            Ok((ready, required_native_paths)) => {
                match Box::pin(complete_required_client_native_paths(
                    ready,
                    required_native_paths,
                    discovery,
                    helper,
                ))
                .await
                {
                    Ok(completed) => {
                        Box::pin(admit_completed_native_route(
                            completed,
                            config,
                            discovery,
                            helper,
                            self.mpquic_socket.as_ref().clone(),
                            native_single_udp,
                        ))
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(established) => {
                if established.is_expired(crate::unix_millis(), Instant::now()) {
                    Box::pin(established.shutdown()).await;
                    self.clear_agent_mpquic_paths().await;
                    let mut state = self.state.lock().await;
                    *state = ClientRouteControlState::Idle;
                    return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
                }
                let progress = established.progress();
                let mpquic_paths = match &established.transport {
                    ClientTransportState::Mpquic(active) => match active.path_summaries().await {
                        Ok(paths) => Some(paths),
                        Err(error) => {
                            Box::pin(established.shutdown()).await;
                            let mut state = self.state.lock().await;
                            *state = ClientRouteControlState::Idle;
                            return Err(error);
                        }
                    },
                    _ => None,
                };
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Established(Box::new(established));
                if let Some(paths) = mpquic_paths {
                    if self.replace_agent_mpquic_paths(paths).await.is_err() {
                        let previous =
                            std::mem::replace(&mut *state, ClientRouteControlState::Idle);
                        drop(state);
                        if let ClientRouteControlState::Established(established) = previous {
                            Box::pin(established.shutdown()).await;
                        }
                        self.clear_agent_mpquic_paths().await;
                        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
                    }
                }
                Ok(progress)
            }
            Err(error) => {
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Idle;
                Err(error)
            }
        }
    }

    async fn replace_agent_mpquic_paths(
        &self,
        paths: Vec<PathSummary>,
    ) -> Result<(), ClientRouteConnectError> {
        let Some(agent_state) = self.agent_state.as_ref() else {
            return Ok(());
        };
        agent_state
            .write()
            .await
            .replace_mpquic_paths(paths)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)
    }

    async fn clear_agent_mpquic_paths(&self) {
        if let Some(agent_state) = self.agent_state.as_ref() {
            agent_state.write().await.clear_mpquic_paths();
        }
    }

    /// Consume the connected genuine-MPTCP capability into one pinned TLS 1.3 TCP flow.
    ///
    /// This is the functional stream seam used until transparent TCP ingress is connected. The
    /// caller supplies a hostname/port that must already be allowed by the active signed policy;
    /// the retained route coordinator signs that exact tuple and the frame is written before this
    /// method reports success.
    pub(crate) async fn activate_tcp_flow(
        &self,
        policy: &VerifiedManifest,
        hostname: &str,
        port: u16,
        now_ms: u64,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if policy
            .authorize_domain(now_ms, hostname, TransportProtocol::Tcp, port)
            .is_err()
        {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        self.activate_tcp_destination(
            policy,
            ClientTcpDestination::Hostname(hostname.to_owned()),
            port,
            now_ms,
        )
        .await
    }

    async fn activate_tcp_destination(
        &self,
        policy: &VerifiedManifest,
        destination: ClientTcpDestination,
        port: u16,
        now_ms: u64,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        let (transport, material) = self
            .acquire_tcp_flow_transport(policy, &destination, port, now_ms)
            .await?;
        let flow = activate_production_mptcp_client_flow(
            transport,
            &material.route,
            &material.certificate_sha256,
            &material.tls_server_name,
            &material.signed_open_tcp,
            now_ms,
        )
        .await
        .map_err(|failure| {
            let _ = failure.cause();
            ClientRouteConnectError::TransportRuntimeUnavailable
        })?;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            flow.shutdown();
            return Err(ClientRouteConnectError::Busy);
        };
        if established.tcp_flow.is_some() {
            flow.shutdown();
            return Err(ClientRouteConnectError::Busy);
        }
        established.tcp_flow = Some(flow);
        Ok(ClientRouteProgress::TransportActive)
    }

    async fn acquire_tcp_flow_transport(
        &self,
        policy: &VerifiedManifest,
        destination: &ClientTcpDestination,
        port: u16,
        now_ms: u64,
    ) -> Result<
        (
            crate::mptcp_transport::ClientMptcpFlowTransport,
            ClientOpenTcpMaterial,
        ),
        ClientRouteConnectError,
    > {
        self.retire_expired_route(now_ms, Instant::now()).await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Err(ClientRouteConnectError::Busy);
        };
        let route = established
            .route
            .as_ref()
            .ok_or(ClientRouteConnectError::Busy)?;
        let material = client_open_tcp_material(route, policy, destination, port, now_ms)?;
        let ClientTransportState::TcpMptcp(transport) = &mut established.transport else {
            return Err(ClientRouteConnectError::Busy);
        };
        let mut helper_route_was_lost = false;
        for _ in 0..8 {
            let local_port = random_mptcp_source_port(PRODUCTION_MPTCP_EXIT_PORT)?;
            match transport
                .acquire_flow(&established.helper, local_port)
                .await
            {
                Ok(flow) => return Ok((flow, material)),
                Err(error) if mptcp_acquire_failure_lost_helper_route(&error) => {
                    helper_route_was_lost = true;
                    break;
                }
                Err(_) => {}
            }
        }
        if helper_route_was_lost {
            let prior_route = std::mem::replace(&mut *state, ClientRouteControlState::Idle);
            drop(state);
            if let ClientRouteControlState::Established(established) = prior_route {
                Box::pin(established.shutdown()).await;
            }
            self.clear_agent_mpquic_paths().await;
        }
        Err(ClientRouteConnectError::TransportRuntimeUnavailable)
    }

    /// Bind one accepted kernel-observed TCP stream and proxy it over the selected genuine
    /// MPTCP/TLS route. TLS/443 signs both visible SNI and the exact kernel destination address;
    /// non-TLS ingress remains an explicitly authorized raw-IP tuple.
    pub(crate) async fn run_tcp_ingress(
        &self,
        ingress: PolicyAuthorizedTcpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<(), ClientRouteConnectError> {
        let (application, destination, hostname) = ingress
            .reauthorize_after_route_ready(policy, now_ms)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .into_route_parts(policy, now_ms)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let destination_scope =
            hostname.map_or(ClientTcpDestination::Ip(destination.ip()), |hostname| {
                ClientTcpDestination::PinnedHostname {
                    hostname,
                    address: destination.ip(),
                }
            });
        let (transport, material) = self
            .acquire_tcp_flow_transport(policy, &destination_scope, destination.port(), now_ms)
            .await?;
        let flow = activate_production_mptcp_client_flow(
            transport,
            &material.route,
            &material.certificate_sha256,
            &material.tls_server_name,
            &material.signed_open_tcp,
            now_ms,
        )
        .await
        .map_err(|failure| {
            let _ = failure.cause();
            ClientRouteConnectError::TransportRuntimeUnavailable
        })?;
        flow.proxy_application(application)
            .await
            .map(|_| ())
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)
    }

    /// Write one bounded payload chunk to the active protected TCP stream.
    pub(crate) async fn write_tcp_payload(
        &self,
        payload: &[u8],
    ) -> Result<(), ClientRouteConnectError> {
        if payload.is_empty() || payload.len() > MAXIMUM_TCP_STREAM_CHUNK_BYTES {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Err(ClientRouteConnectError::Busy);
        };
        let Some(flow) = &mut established.tcp_flow else {
            return Err(ClientRouteConnectError::Busy);
        };
        timeout(MAXIMUM_CALL_DURATION, flow.stream_mut().write_all(payload))
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        timeout(MAXIMUM_CALL_DURATION, flow.stream_mut().flush())
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)
    }

    /// Read at most one fixed-size payload chunk from the active protected TCP stream.
    pub(crate) async fn read_tcp_payload(&self) -> Result<Vec<u8>, ClientRouteConnectError> {
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Err(ClientRouteConnectError::Busy);
        };
        let Some(flow) = &mut established.tcp_flow else {
            return Err(ClientRouteConnectError::Busy);
        };
        let mut payload = vec![0_u8; MAXIMUM_TCP_STREAM_CHUNK_BYTES];
        let count = timeout(MAXIMUM_CALL_DURATION, flow.stream_mut().read(&mut payload))
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        payload.truncate(count);
        Ok(payload)
    }

    /// Bind one kernel-observed datagram to this route, activate Quinn, and queue its payload.
    #[allow(
        clippy::too_many_lines,
        reason = "native and DNS-only UDP owners require distinct affine activation paths"
    )]
    pub(crate) async fn activate_udp_ingress(
        &self,
        ingress: PolicyAuthorizedUdpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        self.retire_expired_route(now_ms, Instant::now()).await;
        {
            let mut state = self.state.lock().await;
            if let ClientRouteControlState::Established(established) = &mut *state {
                if let ClientTransportState::NativeUdp(active) = &mut established.transport {
                    if let Some(binding) = active.binding.as_ref() {
                        let payload = binding
                            .bind_next_native_datagram(ingress, policy, now_ms)
                            .map_err(|_| ClientRouteConnectError::UdpIngressUnavailable)?;
                        let (flow, _) = binding.activation();
                        let SocketAddr::V4(destination) = binding.destination() else {
                            return Err(ClientRouteConnectError::UdpIngressUnavailable);
                        };
                        active
                            .session
                            .send_general_udp(
                                flow,
                                None,
                                binding.source().port(),
                                destination,
                                &payload,
                                now_ms,
                            )
                            .await
                            .map_err(|error| {
                                // This error contains only bounded local/native categories; it
                                // never contains the datagram, tuple, route ID, or credentials.
                                eprintln!("native general UDP activation failed: {error}");
                                ClientRouteConnectError::TransportRuntimeUnavailable
                            })?;
                        return Ok(ClientRouteProgress::TransportActive);
                    }
                    let route = established
                        .route
                        .as_ref()
                        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
                    let protocol = route
                        .established
                        .owner
                        .as_ref()
                        .and_then(PreparedContextOwner::protocol)
                        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
                    let authorized = ingress
                        .bind_to_route(&active.path, &protocol.coordinator, policy, now_ms)
                        .map_err(|_| ClientRouteConnectError::UdpIngressUnavailable)?;
                    let (flow, signed_authorization) = authorized.activation();
                    let SocketAddr::V4(destination) = authorized.destination() else {
                        return Err(ClientRouteConnectError::UdpIngressUnavailable);
                    };
                    active
                        .session
                        .send_general_udp(
                            flow,
                            Some(signed_authorization),
                            authorized.source().port(),
                            destination,
                            authorized.payload(),
                            now_ms,
                        )
                        .await
                        .map_err(|error| {
                            // See the repeated-flow branch above: retain a privacy-safe reason
                            // so acceptance failures do not require speculative datapath changes.
                            eprintln!("native general UDP activation failed: {error}");
                            ClientRouteConnectError::TransportRuntimeUnavailable
                        })?;
                    active.binding = Some(authorized);
                    return Ok(ClientRouteProgress::TransportActive);
                }
            }
        }
        let previous = {
            let mut state = self.state.lock().await;
            std::mem::replace(&mut *state, ClientRouteControlState::Connecting)
        };
        let established = match previous {
            ClientRouteControlState::Established(established) => established,
            other => {
                let mut state = self.state.lock().await;
                *state = other;
                return Err(ClientRouteConnectError::Busy);
            }
        };
        let EstablishedClientRoute {
            expiry,
            transport,
            tcp_flow,
            route,
            orchestrator,
            helper,
        } = *established;
        let ClientTransportState::UdpReady(ready) = transport else {
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                expiry,
                transport,
                tcp_flow,
                route,
                orchestrator,
                helper,
            }));
            return Err(ClientRouteConnectError::Busy);
        };
        if route.is_some() {
            let _ = Box::pin(ready.disconnect()).await;
            if let Some(route) = route {
                let _ = route.disconnect().await;
            }
            orchestrator.shutdown_detached();
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Idle;
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let Ok(authorized) = ready.bind_ingress(ingress, policy, now_ms) else {
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                expiry,
                transport: ClientTransportState::UdpReady(ready),
                tcp_flow: None,
                route: None,
                orchestrator,
                helper,
            }));
            return Err(ClientRouteConnectError::UdpIngressUnavailable);
        };
        let (flow, signed_authorization) = authorized.activation();
        match ready
            .activate(flow, signed_authorization, MAXIMUM_CALL_DURATION, now_ms)
            .await
        {
            Ok(mut active) => {
                active.return_path = Some(ClientUdpReturnPath {
                    application: authorized.source(),
                    remote: authorized.destination(),
                });
                if active.client.send_payload(authorized.payload()).is_err() {
                    let _ = active.shutdown().await;
                    orchestrator.shutdown_detached();
                    let mut state = self.state.lock().await;
                    *state = ClientRouteControlState::Idle;
                    return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
                }
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                    expiry,
                    transport: ClientTransportState::UdpActive(active),
                    tcp_flow: None,
                    route: None,
                    orchestrator,
                    helper,
                }));
                Ok(ClientRouteProgress::TransportActive)
            }
            Err(failure) => {
                let _ = failure.route.disconnect().await;
                orchestrator.shutdown_detached();
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Idle;
                Err(ClientRouteConnectError::TransportRuntimeUnavailable)
            }
        }
    }

    /// Bind one helper-intercepted DNS request to this single-relay route and queue it to the Exit.
    pub(crate) async fn activate_dns_ingress(
        &self,
        ingress: PolicyAuthorizedDnsIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        self.retire_expired_route(now_ms, Instant::now()).await;
        let previous = {
            let mut state = self.state.lock().await;
            std::mem::replace(&mut *state, ClientRouteControlState::Connecting)
        };
        let established = match previous {
            ClientRouteControlState::Established(established) => established,
            other => {
                let mut state = self.state.lock().await;
                *state = other;
                return Err(ClientRouteConnectError::Busy);
            }
        };
        let EstablishedClientRoute {
            expiry,
            transport,
            tcp_flow,
            route,
            orchestrator,
            helper,
        } = *established;
        let ClientTransportState::UdpReady(ready) = transport else {
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                expiry,
                transport,
                tcp_flow,
                route,
                orchestrator,
                helper,
            }));
            return Err(ClientRouteConnectError::Busy);
        };
        if route.is_some() {
            let _ = Box::pin(ready.disconnect()).await;
            if let Some(route) = route {
                let _ = route.disconnect().await;
            }
            orchestrator.shutdown_detached();
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Idle;
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let Ok(authorized) = ready.bind_dns_ingress(ingress, policy, now_ms) else {
            let mut state = self.state.lock().await;
            *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                expiry,
                transport: ClientTransportState::UdpReady(ready),
                tcp_flow,
                route: None,
                orchestrator,
                helper,
            }));
            return Err(ClientRouteConnectError::UdpIngressUnavailable);
        };
        let (flow, signed_authorization) = authorized.activation();
        match ready
            .activate(flow, signed_authorization, MAXIMUM_CALL_DURATION, now_ms)
            .await
        {
            Ok(mut active) => {
                active.return_path = Some(ClientUdpReturnPath {
                    application: authorized.source(),
                    remote: authorized.destination(),
                });
                if active.client.send_payload(authorized.payload()).is_err() {
                    let _ = active.shutdown().await;
                    orchestrator.shutdown_detached();
                    let mut state = self.state.lock().await;
                    *state = ClientRouteControlState::Idle;
                    return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
                }
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Established(Box::new(EstablishedClientRoute {
                    expiry,
                    transport: ClientTransportState::UdpActive(active),
                    tcp_flow,
                    route: None,
                    orchestrator,
                    helper,
                }));
                Ok(ClientRouteProgress::TransportActive)
            }
            Err(failure) => {
                let _ = failure.route.disconnect().await;
                orchestrator.shutdown_detached();
                let mut state = self.state.lock().await;
                *state = ClientRouteControlState::Idle;
                Err(ClientRouteConnectError::TransportRuntimeUnavailable)
            }
        }
    }

    /// Receive one bounded Exit response with the exact local transparent-return binding.
    pub(crate) async fn receive_udp_response(
        &self,
    ) -> Result<ClientUdpResponse, ClientRouteConnectError> {
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Err(ClientRouteConnectError::Busy);
        };
        if let ClientTransportState::NativeUdp(active) = &mut established.transport {
            let binding = active
                .binding
                .as_ref()
                .ok_or(ClientRouteConnectError::Busy)?;
            let SocketAddr::V4(destination) = binding.destination() else {
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let packet = timeout(MAXIMUM_CALL_DURATION, async {
                loop {
                    if let Some(packet) = active
                        .session
                        .receive_general_udp(
                            binding.activation().0,
                            binding.source().port(),
                            destination,
                            crate::unix_millis(),
                        )
                        .await?
                    {
                        return Ok::<_, crate::mpquic_runtime::ProductionMpquicError>(packet);
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
            let payload = binding
                .accept_native_response(&packet)
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
                .to_vec();
            return Ok(ClientUdpResponse {
                application: binding.source(),
                remote: binding.destination(),
                payload,
            });
        }
        let ClientTransportState::UdpActive(active) = &established.transport else {
            return Err(ClientRouteConnectError::Busy);
        };
        let binding = active
            .return_path
            .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let payload = timeout(MAXIMUM_CALL_DURATION, active.client.receive_payload())
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        Ok(ClientUdpResponse {
            application: binding.application,
            remote: binding.remote,
            payload: payload.to_vec(),
        })
    }

    /// Hand one policy-approved UDP/443 datagram to the retained native MPQUIC session.
    pub(crate) async fn send_browser_quic_ingress(
        &self,
        ingress: PolicyAuthorizedUdpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<ClientRouteProgress, ClientRouteConnectError> {
        if !ingress.is_browser_quic() {
            return Err(ClientRouteConnectError::UdpIngressUnavailable);
        }
        self.retire_expired_route(now_ms, Instant::now()).await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Err(ClientRouteConnectError::Busy);
        };
        let ClientTransportState::Mpquic(active) = &mut established.transport else {
            return Err(ClientRouteConnectError::Busy);
        };
        let route = established
            .route
            .as_ref()
            .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let (tunnel_source, maximum_packet_bytes) = mpquic_tunnel_packet_scope(&active.session)?;

        active
            .browser_flows
            .retain(|binding| binding.is_live(policy, now_ms));
        let existing = active
            .browser_flows
            .iter()
            .position(|binding| binding.matches_ingress_tuple(&ingress));
        let (packet, pending_binding) = if let Some(index) = existing {
            (
                active.browser_flows[index]
                    .bind_next(&ingress, policy, maximum_packet_bytes, now_ms)
                    .map_err(|_| ClientRouteConnectError::UdpIngressUnavailable)?,
                None,
            )
        } else {
            if active.browser_flows.len() >= MAXIMUM_CLIENT_BROWSER_QUIC_FLOWS {
                return Err(ClientRouteConnectError::UdpIngressUnavailable);
            }
            let protocol = route
                .established
                .owner
                .as_ref()
                .and_then(PreparedContextOwner::protocol)
                .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
            let route_expires_at_ms = route
                .established
                .relay_grants
                .iter()
                .map(VerifiedRelayGrant::expires_at_ms)
                .min()
                .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
            let (binding, packet) = ingress
                .bind_to_multipath_route(
                    route.established.request.parameters.route_context_id,
                    *protocol.coordinator.client_session_id(),
                    route_expires_at_ms,
                    &protocol.coordinator,
                    policy,
                    tunnel_source,
                    maximum_packet_bytes,
                    now_ms,
                )
                .map_err(|_| ClientRouteConnectError::UdpIngressUnavailable)?;
            (packet, Some(binding))
        };

        if let Some(pending) = pending_binding.as_ref() {
            active
                .session
                .authorize_browser_quic(
                    pending.flow(),
                    pending.application().port(),
                    pending.signed_authorization(),
                    now_ms,
                )
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
            active
                .session
                .send_browser_quic(pending.flow(), packet, now_ms)
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        } else {
            let index = existing.ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
            active
                .session
                .send_browser_quic(active.browser_flows[index].flow(), packet, now_ms)
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        }
        let index = if let Some(binding) = pending_binding {
            active.browser_flows.push(binding);
            active.browser_flows.len() - 1
        } else {
            existing.ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?
        };
        active.browser_flows[index]
            .record_sent(now_ms)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let paths = active.path_summaries().await?;
        drop(state);
        self.replace_agent_mpquic_paths(paths).await?;
        Ok(ClientRouteProgress::TransportActive)
    }

    /// Poll one native reverse inner-IP packet and recover its transparent application reply.
    pub(crate) async fn receive_browser_quic_response(
        &self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Option<ClientUdpResponse>, ClientRouteConnectError> {
        self.retire_expired_route(now_ms, Instant::now()).await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Ok(None);
        };
        let ClientTransportState::Mpquic(active) = &mut established.transport else {
            return Ok(None);
        };
        active
            .browser_flows
            .retain(|binding| binding.is_live(policy, now_ms));
        if active.browser_flows.is_empty() {
            return Ok(None);
        }
        let received = active
            .session
            .receive_browser_quic(
                active
                    .browser_flows
                    .iter()
                    .map(BrowserQuicFlowBinding::receive_scope),
                now_ms,
            )
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let Some((index, packet)) = received else {
            return Ok(None);
        };
        let flow = active
            .browser_flows
            .get_mut(index)
            .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let application = flow.application();
        let remote = flow.remote();
        let payload = flow
            .accept_response(&packet, policy, now_ms)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?
            .to_vec();
        let response = ClientUdpResponse {
            application: SocketAddr::V4(application),
            remote: SocketAddr::V4(remote),
            payload,
        };
        let paths = active.path_summaries().await?;
        drop(state);
        self.replace_agent_mpquic_paths(paths).await?;
        Ok(Some(response))
    }

    /// Whether periodic reverse polling is meaningful for the current route owner.
    pub(crate) async fn browser_quic_flow_active(&self) -> bool {
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let state = self.state.lock().await;
        matches!(
            &*state,
            ClientRouteControlState::Established(established)
                if matches!(
                    &established.transport,
                    ClientTransportState::Mpquic(active) if !active.browser_flows.is_empty()
                )
        )
    }

    /// Assess and, when necessary, reconfigure the live native multipath route.
    ///
    /// Single-relay UDP is deliberately excluded: it owns one immutable Relay association and a
    /// failed association must be torn down before ingress can create a new one. MPTCP continues
    /// to rely on the kernel path manager until per-subflow telemetry crosses the helper boundary.
    pub(crate) async fn maintain_path_health(
        &self,
        now_ms: u64,
    ) -> Result<ClientPathMaintenance, ClientRouteConnectError> {
        self.retire_expired_route(now_ms, Instant::now()).await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let ClientTransportState::Mpquic(active) = &mut established.transport else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let outcome = active.maintain(now_ms).await?;
        let paths = active.path_summaries().await?;
        drop(state);
        self.replace_agent_mpquic_paths(paths).await?;
        Ok(outcome)
    }

    /// Cancels any pre-route affine ownership; helper cleanup remains a separate fail-closed step.
    pub(crate) async fn disconnect(&self) {
        let previous = {
            let mut state = self.state.lock().await;
            std::mem::replace(&mut *state, ClientRouteControlState::Idle)
        };
        if let ClientRouteControlState::Established(established) = previous {
            Box::pin(established.shutdown()).await;
        }
        self.clear_agent_mpquic_paths().await;
    }
}

fn tcp_connect_retry_delay(
    error: ClientRouteConnectError,
    now: Instant,
    deadline: Instant,
) -> Option<Duration> {
    if !matches!(
        error,
        ClientRouteConnectError::Busy | ClientRouteConnectError::PreselectionUnavailable
    ) || now >= deadline
    {
        return None;
    }
    Some(TCP_CONNECT_RETRY_INTERVAL.min(deadline.saturating_duration_since(now)))
}

struct ClientOpenTcpMaterial {
    route: VerifiedMptcpRoute,
    certificate_sha256: [u8; 32],
    tls_server_name: String,
    signed_open_tcp: Vec<u8>,
}

enum ClientTcpDestination {
    Hostname(String),
    PinnedHostname { hostname: String, address: IpAddr },
    Ip(IpAddr),
}

fn mpquic_tunnel_packet_scope(
    session: &ProductionMpquicSession,
) -> Result<(Ipv4Addr, usize), ClientRouteConnectError> {
    let assigned_ipv4: [u8; 4] = session
        .assignment()
        .assigned_ipv4
        .as_slice()
        .try_into()
        .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let assigned_ipv4 = Ipv4Addr::from(assigned_ipv4);
    let maximum_packet_bytes = maximum_mpquic_tunnel_packet_bytes(session.assignment().mtu)?;
    if assigned_ipv4.is_unspecified() || assigned_ipv4.is_multicast() {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    Ok((assigned_ipv4, maximum_packet_bytes))
}

fn maximum_mpquic_tunnel_packet_bytes(
    assignment_mtu: u32,
) -> Result<usize, ClientRouteConnectError> {
    usize::try_from(assignment_mtu)
        .ok()
        .filter(|mtu| *mtu >= 28 && u16::try_from(*mtu).is_ok())
        .map(|mtu| mtu.min(MINIMUM_MPQUIC_TUNNEL_MTU))
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)
}

fn client_open_tcp_material(
    route: &ProductionRoute,
    policy: &VerifiedManifest,
    destination: &ClientTcpDestination,
    port: u16,
    now_ms: u64,
) -> Result<ClientOpenTcpMaterial, ClientRouteConnectError> {
    let established = &route.established;
    if established.request.parameters.allowed_transports != [Transport::TcpMptcp]
        || established.request.parameters.policy_hash != *policy.policy_hash()
    {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    let relay_reservations = established
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::signed_relay_reservation)
        .collect::<Vec<_>>();
    let mut replay = ReplayCache::new(MAXIMUM_REPLAY_CAPACITY)
        .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let verified_route = VerifiedMptcpRoute::verify(
        &established.signed_exit_reservation,
        &relay_reservations,
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let identity = established
        .native_authorization
        .as_ref()
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?
        .native_route_identity();
    let certificate_sha256: [u8; 32] = identity
        .certificate_sha256
        .as_slice()
        .try_into()
        .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let expires_at_ms = now_ms
        .checked_add(OPEN_TCP_LIFETIME_MS)
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?
        .min(verified_route.expires_at_ms())
        .min(policy.expires_at_ms());
    if expires_at_ms <= now_ms {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    let coordinator = established
        .owner
        .as_ref()
        .and_then(PreparedContextOwner::protocol)
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let signed_open_tcp = match destination {
        ClientTcpDestination::Hostname(hostname) => coordinator.coordinator.sign_open_tcp(
            *verified_route.route_context_id(),
            *policy.policy_hash(),
            hostname,
            port,
            now_ms,
            expires_at_ms,
        ),
        ClientTcpDestination::PinnedHostname { hostname, address } => {
            coordinator.coordinator.sign_open_tcp_pinned(
                *verified_route.route_context_id(),
                *policy.policy_hash(),
                hostname,
                *address,
                port,
                now_ms,
                expires_at_ms,
            )
        }
        ClientTcpDestination::Ip(address) => coordinator.coordinator.sign_open_tcp_ip(
            *verified_route.route_context_id(),
            *policy.policy_hash(),
            *address,
            port,
            now_ms,
            expires_at_ms,
        ),
    }
    .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    Ok(ClientOpenTcpMaterial {
        route: verified_route,
        certificate_sha256,
        tls_server_name: identity.tls_server_name.clone(),
        signed_open_tcp,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed transport-specific route admission transaction"
)]
async fn admit_completed_native_route(
    completed: selection_bridge::CompletedClientNativeProbe,
    config: &Config,
    discovery: &DiscoveryControlHandle,
    helper: &HelperClient,
    mpquic_socket: PathBuf,
    native_single_udp: bool,
) -> Result<EstablishedClientRoute, ClientRouteConnectError> {
    let (transport, _) = client_native_path_requirement(config)?;
    let mpquic_preflight = if transport == Transport::MultipathQuic
        || (transport == Transport::UdpSinglePath && native_single_udp)
    {
        let native = NativeClient::new(mpquic_socket)
            .map_err(|_| ClientRouteConnectError::NativeTransportIdentityUnavailable)?;
        Some(
            ProductionMpquicPreflight::new(native)
                .await
                .map_err(|_| ClientRouteConnectError::NativeTransportIdentityUnavailable)?,
        )
    } else {
        None
    };
    let client_native_instance_id = mpquic_preflight
        .as_ref()
        .map_or_else(random_runtime_instance_id, |preflight| {
            Ok(*preflight.native_instance_id())
        })?;
    let Ok(admission) = completed.into_route_admission(client_native_instance_id) else {
        let _ = helper.cleanup_owned().await;
        return Err(ClientRouteConnectError::RouteAdmissionUnavailable);
    };
    let (continuation, remote_retirement_confirmed, _exit_helper_runtime_id) =
        admission.into_parts();
    if !remote_retirement_confirmed {
        return Err(ClientRouteConnectError::NativeRemoteRetirementUnavailable);
    }
    let orchestrator = ProductionRouteOrchestrator::start(helper.clone())
        .map_err(|_| ClientRouteConnectError::RouteAdmissionUnavailable)?;
    let attempt = orchestrator.connect(continuation, discovery.clone());
    match attempt.wait().await {
        Ok(mut route)
            if route.selected_transport() == Some(Transport::UdpSinglePath)
                && native_single_udp =>
        {
            let Some(preflight) = mpquic_preflight else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::NativeTransportIdentityUnavailable);
            };
            let now_ms = crate::unix_millis();
            let Ok(path) = verified_single_relay_udp_path(&route.established, now_ms) else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let signal = start_native_udp_exit_session(&route, &path, discovery, now_ms).await;
            let Ok(signal) = signal else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::UdpExitSessionSignalUnavailable);
            };
            let Ok(context_handle): Result<[u8; HELPER_HANDLE_BYTES], _> =
                route.context_handle().try_into()
            else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let Some(authorization) = route.established.native_authorization.take() else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let [grant] = route.established.relay_grants.as_slice() else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let session = preflight
                .establish_single_path_udp(
                    helper,
                    context_handle,
                    authorization,
                    grant,
                    &signal,
                    crate::unix_millis(),
                    MPQUIC_READY_WAIT,
                )
                .await;
            let Ok(session) = session else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            Ok(EstablishedClientRoute {
                expiry: route.expiry,
                transport: ClientTransportState::NativeUdp(Box::new(
                    ActiveProductionNativeUdpRoute {
                        session,
                        path,
                        binding: None,
                    },
                )),
                tcp_flow: None,
                route: Some(route),
                orchestrator,
                helper: helper.clone(),
            })
        }
        Ok(route) if route.selected_transport() == Some(Transport::UdpSinglePath) => {
            let expiry = route.expiry;
            let prepared = route
                .prepare_single_relay_udp(helper, crate::unix_millis())
                .await;
            match prepared {
                Ok(prepared) => match prepared
                    .start_exit_session(discovery, crate::unix_millis())
                    .await
                {
                    Ok(ready) => Ok(EstablishedClientRoute {
                        expiry,
                        transport: ClientTransportState::UdpReady(ready),
                        tcp_flow: None,
                        route: None,
                        orchestrator,
                        helper: helper.clone(),
                    }),
                    Err(failure) => {
                        let cleanup = failure.prepared.disconnect().await;
                        orchestrator.shutdown_detached();
                        if cleanup.is_err() {
                            Err(ClientRouteConnectError::TransportRuntimeUnavailable)
                        } else {
                            Err(ClientRouteConnectError::UdpExitSessionSignalUnavailable)
                        }
                    }
                },
                Err(failure) => {
                    let ProductionUdpPreparationFailure { route, .. } = failure;
                    let _ = route
                        .disconnect()
                        .await
                        .map_err(|_| ProductionUdpRouteError::CleanupPending);
                    orchestrator.shutdown_detached();
                    Err(ClientRouteConnectError::TransportRuntimeUnavailable)
                }
            }
        }
        Ok(route) if route.selected_transport() == Some(Transport::TcpMptcp) => {
            let signal = start_mptcp_exit_session(&route, discovery, crate::unix_millis()).await;
            let Ok(signal) = signal else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable);
            };
            match activate_committed_transport(&route, helper, Some(signal)).await {
                Ok(transport) => Ok(EstablishedClientRoute {
                    expiry: route.expiry,
                    transport,
                    tcp_flow: None,
                    route: Some(route),
                    orchestrator,
                    helper: helper.clone(),
                }),
                Err(error) => {
                    let _ = route.disconnect().await;
                    orchestrator.shutdown_detached();
                    Err(error)
                }
            }
        }
        Ok(mut route) if route.selected_transport() == Some(Transport::MultipathQuic) => {
            let Some(preflight) = mpquic_preflight else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::NativeTransportIdentityUnavailable);
            };
            let identity = match route.committed_mpquic_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = route.disconnect().await;
                    orchestrator.shutdown_detached();
                    return Err(error);
                }
            };
            let signal = start_mpquic_exit_session(&route, discovery, crate::unix_millis()).await;
            let Ok(signal) = signal else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let Ok(context_handle): Result<[u8; HELPER_HANDLE_BYTES], _> =
                route.context_handle().try_into()
            else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let active_path_ids = route.established.active_path_ids.clone();
            let minimum_paths = route
                .established
                .request
                .parameters
                .post_probe_policy
                .relay_policy
                .minimum_paths;
            let Some(authorization) = route.established.native_authorization.take() else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            };
            let mut grants = route.established.relay_grants.clone();
            grants.sort_unstable_by_key(VerifiedRelayGrant::path_id);
            let session = preflight
                .establish_committed(
                    helper,
                    context_handle,
                    authorization,
                    &grants,
                    &active_path_ids,
                    minimum_paths,
                    &signal,
                    crate::unix_millis(),
                    MPQUIC_READY_WAIT,
                )
                .await;
            if let Err(error) = &session {
                // Production MPQUIC errors expose only bounded local/native protocol diagnostics;
                // they never contain route credentials or traffic.
                eprintln!("production MPQUIC Client startup failed: {error}");
            }
            if let Ok(session) = session {
                let health = ProductionMpquicPathHealth::new(
                    session.active_path_ids(),
                    session.warm_path_ids(),
                    UnixTime::from_secs(crate::unix_seconds()),
                );
                let Ok(health) = health else {
                    let _ = session.shutdown().await;
                    let _ = route.disconnect().await;
                    orchestrator.shutdown_detached();
                    return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
                };
                Ok(EstablishedClientRoute {
                    expiry: route.expiry,
                    transport: ClientTransportState::Mpquic(Box::new(
                        ActiveProductionMpquicRoute {
                            session,
                            identity,
                            health,
                            browser_flows: Vec::new(),
                        },
                    )),
                    tcp_flow: None,
                    route: Some(route),
                    orchestrator,
                    helper: helper.clone(),
                })
            } else {
                let _ = route.disconnect().await;
                orchestrator.shutdown_detached();
                Err(ClientRouteConnectError::TransportRuntimeUnavailable)
            }
        }
        Ok(route) => {
            let _ = route.disconnect().await;
            orchestrator.shutdown_detached();
            Err(ClientRouteConnectError::NativeTransportIdentityUnavailable)
        }
        Err(ProductionRouteError::NativeTransportIdentityUnavailable) => {
            orchestrator.shutdown_detached();
            Err(ClientRouteConnectError::NativeTransportIdentityUnavailable)
        }
        Err(_) => {
            orchestrator.shutdown_detached();
            Err(ClientRouteConnectError::RouteAdmissionUnavailable)
        }
    }
}

async fn activate_committed_transport(
    route: &ProductionRoute,
    helper: &HelperClient,
    mptcp_listener: Option<ExitMptcpListenerSignal>,
) -> Result<ClientTransportState, ClientRouteConnectError> {
    match route.selected_transport() {
        Some(Transport::TcpMptcp) => {
            let signal = mptcp_listener
                .ok_or(ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
            if !route.accepts_mptcp_listener(&signal) {
                return Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable);
            }
            let local_port = random_mptcp_source_port(signal.port())?;
            ClientMptcpTransport::acquire_and_activate(
                helper,
                signal,
                route.context_handle().to_vec(),
                local_port,
            )
            .await
            .map(ClientTransportState::TcpMptcp)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)
        }
        Some(Transport::UdpSinglePath | Transport::MultipathQuic | Transport::Unspecified)
        | None => Err(ClientRouteConnectError::TransportRuntimeUnavailable),
    }
}

fn random_mptcp_source_port(exit_listener_port: u16) -> Result<u16, ClientRouteConnectError> {
    const FIRST_DYNAMIC_PORT: u16 = 49_152;
    const DYNAMIC_PORT_COUNT: u16 = u16::MAX - FIRST_DYNAMIC_PORT + 1;
    for _ in 0..8 {
        let mut bytes = [0_u8; 2];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let port = FIRST_DYNAMIC_PORT + (u16::from_le_bytes(bytes) % DYNAMIC_PORT_COUNT);
        if port != exit_listener_port {
            return Ok(port);
        }
    }
    Err(ClientRouteConnectError::TransportRuntimeUnavailable)
}

fn mptcp_acquire_failure_lost_helper_route(error: &MptcpTransportError) -> bool {
    matches!(
        error,
        MptcpTransportError::Helper(HelperClientError::Rejected(
            HelperResult::CleanupIncomplete | HelperResult::NotFound
        ))
    )
}

fn random_runtime_instance_id() -> Result<[u8; 32], ClientRouteConnectError> {
    for _ in 0..8 {
        let mut instance_id = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut instance_id)
            .map_err(|_| ClientRouteConnectError::NativeTransportIdentityUnavailable)?;
        if instance_id != [0; 32] {
            return Ok(instance_id);
        }
    }
    Err(ClientRouteConnectError::NativeTransportIdentityUnavailable)
}

/// Repeat an affine Ready-to-proof lifecycle until the selected transport's hard minimum is met.
async fn drive_required_native_paths<
    Ready,
    Completed,
    Error,
    Complete,
    CompleteFuture,
    Continue,
    ContinueFuture,
    Count,
>(
    mut ready: Ready,
    required_paths: usize,
    mut complete: Complete,
    mut continue_with: Continue,
    completed_path_count: Count,
) -> Result<Completed, Error>
where
    Complete: FnMut(Ready) -> CompleteFuture,
    CompleteFuture: Future<Output = Result<Completed, Error>>,
    Continue: FnMut(Completed) -> ContinueFuture,
    ContinueFuture: Future<Output = Result<Ready, Error>>,
    Count: Fn(&Completed) -> usize,
{
    debug_assert!(required_paths != 0);
    loop {
        let completed = complete(ready).await?;
        if completed_path_count(&completed) >= required_paths {
            return Ok(completed);
        }
        ready = continue_with(completed).await?;
    }
}

/// Collect every required Ready authority, then establish all paths in one helper context.
async fn complete_required_client_native_paths(
    mut ready: selection_bridge::ClientNativeRelayReady,
    required_paths: usize,
    discovery: &DiscoveryControlHandle,
    helper: &HelperClient,
) -> Result<selection_bridge::CompletedClientNativeProbe, ClientRouteConnectError> {
    while ready.ready_path_count() < required_paths {
        let preselection = Box::pin(ready.retain_and_dispatch_next_permit(discovery))
            .await
            .map_err(|_| ClientRouteConnectError::NativePermitUnavailable)?;
        ready = Box::pin(preselection.dispatch_relay_ready(discovery))
            .await
            .map_err(|_| ClientRouteConnectError::NativeRelayUnavailable)?;
    }
    let result = Box::pin(complete_client_native_probe(ready, discovery, helper)).await;
    if result.is_err() {
        // A later affine protocol join may have consumed its exact current helper owner. The
        // existing agent-scoped token is the only authority that can close the shared context.
        let _ = helper.cleanup_owned().await;
    }
    result
}

/// Drive the collected path set through one exact helper runtime and every signed native RPC.
///
/// A helper-side context is destroyed immediately when the affine runtime owner is still
/// available. Failures at consuming protocol joins fall back to the existing agent-scoped cleanup
/// token because those joins intentionally reveal no reusable helper capability on failure.
async fn complete_client_native_probe(
    ready: selection_bridge::ClientNativeRelayReady,
    discovery: &DiscoveryControlHandle,
    helper: &HelperClient,
) -> Result<selection_bridge::CompletedClientNativeProbe, ClientRouteConnectError> {
    let prepare = ready
        .prepare_request()
        .map_err(|_| ClientRouteConnectError::NativeHelperPrepareUnavailable)?;
    let Ok(prepared) = helper.prepare_lease_batch(prepare.clone()).await else {
        let _ = helper.cleanup_owned().await;
        return Err(ClientRouteConnectError::NativeHelperPrepareUnavailable);
    };
    let Ok(prepared) = ready.bind_prepared_endpoint(&prepare, prepared) else {
        let _ = helper.cleanup_owned().await;
        return Err(ClientRouteConnectError::NativeHelperPrepareUnavailable);
    };
    let Ok(mut authorized) = prepared.request_activation_authority(discovery).await else {
        let _ = helper.cleanup_owned().await;
        return Err(ClientRouteConnectError::NativeAuthorizationUnavailable);
    };
    let activation = authorized.activation_request().clone();
    let Ok(activated) = helper
        .activate_lease_batch(authorized.runtime_owner_mut(), activation)
        .await
    else {
        let _ = helper
            .destroy_context(&*authorized.runtime_owner_mut())
            .await;
        return Err(ClientRouteConnectError::NativeHelperActivateUnavailable);
    };
    if authorized.exchange_challenges(helper).await.is_err() {
        let _ = helper
            .destroy_context(&*authorized.runtime_owner_mut())
            .await;
        return Err(ClientRouteConnectError::NativeStartUnavailable);
    }
    let Ok(mut awaiting) = authorized.accept_activation(&activated) else {
        let _ = helper.cleanup_owned().await;
        return Err(ClientRouteConnectError::NativeStartUnavailable);
    };
    let commit = awaiting.commit_request();
    let Ok(committed) = helper
        .commit_lease_batch(awaiting.runtime_owner_mut(), commit)
        .await
    else {
        let _ = helper.destroy_context(&*awaiting.runtime_owner_mut()).await;
        return Err(ClientRouteConnectError::NativeHelperCommitUnavailable);
    };
    let completed =
        match Box::pin(awaiting.accept_committed_and_dispatch(committed, discovery)).await {
            Ok(completed) => completed,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "native terminal Start/result exact-set failed"
                );
                let _ = helper.cleanup_owned().await;
                return Err(ClientRouteConnectError::NativeProofUnavailable);
            }
        };
    let owner = completed
        .runtime_owner()
        .map_err(|_| ClientRouteConnectError::NativeProofUnavailable)?;
    let Ok(destroyed) = helper.destroy_context(owner).await else {
        return Err(ClientRouteConnectError::NativeHelperCommitUnavailable);
    };
    completed
        .accept_destroyed(destroyed)
        .map_err(|_| ClientRouteConnectError::NativeProofUnavailable)
}

async fn begin_client_route(
    config: &Config,
    discovery: &DiscoveryControlHandle,
) -> Result<(selection_bridge::ClientNativeRelayReady, usize), ClientRouteConnectError> {
    let (parameters, minimum_native_paths) = client_preselection_plan(config)?;
    let admission = client_route_admission_profile(config)?;
    let prepared = discovery
        .prepare_client_preselection(parameters)
        .await
        .map_err(map_preselection_error)?;
    let preselection =
        selection_bridge::begin_client_native_preselection(prepared, admission, discovery)
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    "native preselection failed before the first data-Relay dispatch"
                );
                ClientRouteConnectError::NativePermitUnavailable
            })?;
    let ready = Box::pin(preselection.dispatch_relay_ready(discovery))
        .await
        .map_err(|_| ClientRouteConnectError::NativeRelayUnavailable)?;
    let required_native_paths = ready.candidate_path_count();
    if required_native_paths < minimum_native_paths {
        return Err(ClientRouteConnectError::NativeRelayUnavailable);
    }
    Ok((ready, required_native_paths))
}

fn client_route_admission_profile(
    config: &Config,
) -> Result<selection_bridge::ClientRouteAdmissionProfile, ClientRouteConnectError> {
    let (transport, required_paths) = client_native_path_requirement(config)?;
    let transport = match transport {
        Transport::TcpMptcp => SelectionTransport::TcpMptcp,
        Transport::UdpSinglePath => SelectionTransport::UdpSinglePath,
        Transport::MultipathQuic => SelectionTransport::MultipathQuic,
        Transport::Unspecified => return Err(ClientRouteConnectError::InvalidProfile),
    };
    let address_family = match config.routing.client_address_family {
        ClientAddressFamily::Ipv4 => IpFamily::Ipv4,
        ClientAddressFamily::Ipv6 => IpFamily::Ipv6,
    };
    let minimum_capacity = Bandwidth::new(
        config.routing.client_minimum_upload_mbps,
        config.routing.client_minimum_download_mbps,
    )
    .map_err(|_| ClientRouteConnectError::InvalidProfile)?;
    let exploration = config.selection.exploration_ratio;
    if !exploration.is_finite() || !(0.0..=0.5).contains(&exploration) {
        return Err(ClientRouteConnectError::InvalidProfile);
    }
    let mix = SelectionMix {
        high: 0.8 - exploration,
        diverse_middle: 0.2,
        exploration,
    };
    let relay_policy = if transport == SelectionTransport::UdpSinglePath {
        RelaySelectionPolicy {
            active_paths: 1,
            minimum_paths: 1,
            maximum_paths: 1,
            warm_backup_paths: 0,
            maximum_rtt_spread_ms: f64::from(config.selection.maximum_rtt_spread_ms),
            minimum_unique_throughput_gain_ratio: 0.10,
            mix,
        }
    } else {
        let maximum_paths = usize::from(config.selection.maximum_multipath_paths);
        let active_paths = usize::from(config.selection.active_multipath_paths).max(required_paths);
        if active_paths > maximum_paths {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        RelaySelectionPolicy {
            active_paths,
            minimum_paths: required_paths,
            maximum_paths,
            warm_backup_paths: usize::from(config.selection.warm_backup_paths)
                .min(maximum_paths.saturating_sub(active_paths)),
            maximum_rtt_spread_ms: f64::from(config.selection.maximum_rtt_spread_ms),
            minimum_unique_throughput_gain_ratio: 0.10,
            mix,
        }
    };
    let hard_lifetime = Duration::from_secs(
        config
            .routing
            .context_ttl_seconds
            .min(MAXIMUM_RESERVATION_LIFETIME_MS / 1_000),
    );
    if hard_lifetime.is_zero() {
        return Err(ClientRouteConnectError::InvalidProfile);
    }
    Ok(selection_bridge::ClientRouteAdmissionProfile::new(
        transport,
        minimum_capacity,
        address_family,
        mix,
        relay_policy,
        hard_lifetime,
    ))
}

fn client_preselection_parameters(
    config: &Config,
) -> Result<ClientPreselectionParameters, ClientRouteConnectError> {
    client_preselection_plan(config).map(|(parameters, _required_native_paths)| parameters)
}

fn client_preselection_plan(
    config: &Config,
) -> Result<(ClientPreselectionParameters, usize), ClientRouteConnectError> {
    let (transport, required_native_paths) = client_native_path_requirement(config)?;
    let address_family = match config.routing.client_address_family {
        ClientAddressFamily::Ipv4 => volparossa_protocol::ObservationAddressFamily::Ipv4,
        ClientAddressFamily::Ipv6 => volparossa_protocol::ObservationAddressFamily::Ipv6,
    };
    let minimum_capacity = Bandwidth::new(
        config.routing.client_minimum_upload_mbps,
        config.routing.client_minimum_download_mbps,
    )
    .map_err(|_| ClientRouteConnectError::InvalidProfile)?;
    let local_profile_capacity = Bandwidth::new(
        config.routing.client_local_upload_mbps,
        config.routing.client_local_download_mbps,
    )
    .map_err(|_| ClientRouteConnectError::InvalidProfile)?;
    let conservative_capacity_ceiling = Bandwidth::new(
        config.routing.client_capacity_ceiling_upload_mbps,
        config.routing.client_capacity_ceiling_download_mbps,
    )
    .map_err(|_| ClientRouteConnectError::InvalidProfile)?;
    if !conservative_capacity_ceiling.satisfies(minimum_capacity)
        || !local_profile_capacity.satisfies(conservative_capacity_ceiling)
    {
        return Err(ClientRouteConnectError::InvalidProfile);
    }
    let multipath = transport != Transport::UdpSinglePath;
    let minimum_other_relays = if multipath { required_native_paths } else { 1 };
    let maximum_other_relays = if multipath {
        usize::from(config.selection.maximum_multipath_paths.max(1))
    } else {
        1
    };
    Ok((
        ClientPreselectionParameters::new(
            transport,
            address_family,
            minimum_capacity,
            local_profile_capacity,
            conservative_capacity_ceiling,
            minimum_other_relays,
            maximum_other_relays,
            config
                .network
                .candidate_pool_size
                .min(volparossa_selection::MAXIMUM_SELECTION_CANDIDATES),
        ),
        required_native_paths,
    ))
}

fn client_native_path_requirement(
    config: &Config,
) -> Result<(Transport, usize), ClientRouteConnectError> {
    if config.udp.enabled {
        return Ok((Transport::UdpSinglePath, 1));
    }
    let (transport, required_paths) = if config.tcp.enabled {
        if config.tcp.allow_plain_tcp_fallback {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        (
            Transport::TcpMptcp,
            usize::from(config.selection.minimum_multipath_paths),
        )
    } else if config.quic.enabled {
        if !config.quic.require_multipath || config.quic.allow_degraded_single_path {
            return Err(ClientRouteConnectError::InvalidProfile);
        }
        (
            Transport::MultipathQuic,
            usize::from(
                config
                    .selection
                    .minimum_multipath_paths
                    .max(config.quic.minimum_paths),
            ),
        )
    } else {
        return Err(ClientRouteConnectError::InvalidProfile);
    };
    let maximum_paths = usize::from(config.selection.maximum_multipath_paths);
    if required_paths < 2
        || required_paths > maximum_paths
        || required_paths > usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)
    {
        return Err(ClientRouteConnectError::InvalidProfile);
    }
    Ok((transport, required_paths))
}

fn map_preselection_error(_: ClientPreselectionError) -> ClientRouteConnectError {
    ClientRouteConnectError::PreselectionUnavailable
}

/// A complete actor snapshot projected into a selection-only identity.
///
/// This value is deliberately not accepted by any discovery RPC. Route execution must re-resolve
/// an actor-minted capability and compare every field before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProspectivePeerIdentity {
    wire_node_id: [u8; 32],
    peer_id: Libp2pPeerId,
    public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    policy_version: u64,
    policy_hash: [u8; 32],
    policy_expires_at_ms: u64,
    expires_at_ms: u64,
}

impl ProspectivePeerIdentity {
    fn selection_node_id(&self) -> Result<NodeId, RouteSetupError> {
        NodeId::new(hex::encode(self.wire_node_id))
            .map_err(|_| RouteSetupError::Invalid("selection node id"))
    }

    fn from_direct(capability: &DirectRelayCapability) -> Self {
        Self {
            wire_node_id: capability.node_id,
            peer_id: capability.peer_id,
            public_key: capability.public_key,
            advertisement_sequence: capability.advertisement_sequence,
            advertisement_expires_at_ms: capability.advertisement_expires_at_ms,
            advertisement_payload_hash: capability.advertisement_payload_hash,
            policy_version: capability.policy_version,
            policy_hash: capability.policy_hash,
            policy_expires_at_ms: capability.policy_expires_at_ms,
            expires_at_ms: capability.expires_at_ms,
        }
    }

    fn from_forwarded(capability: &ForwardedExitCapability, expires_at_ms: u64) -> Self {
        Self {
            wire_node_id: capability.exit_node_id,
            peer_id: capability.exit_peer_id,
            public_key: capability.exit_public_key,
            advertisement_sequence: capability.exit_advertisement_sequence,
            advertisement_expires_at_ms: capability.exit_advertisement_expires_at_ms,
            advertisement_payload_hash: capability.exit_advertisement_payload_hash,
            policy_version: capability.policy_version,
            policy_hash: capability.policy_hash,
            policy_expires_at_ms: capability.policy_expires_at_ms,
            expires_at_ms,
        }
    }

    fn direct_matches(&self, capability: &DirectRelayCapability) -> bool {
        self == &Self::from_direct(capability)
    }

    /// Accept the exact selected advertisement or a strictly newer advertisement from the same
    /// actor and policy. This keeps an already-live route attempt usable across ordinary service
    /// re-publication without allowing rollback or equal-sequence drift.
    fn direct_lineage_matches(
        &self,
        current: &DirectRelayCapability,
        required_expiry_ms: u64,
    ) -> bool {
        if self.wire_node_id != current.node_id
            || self.peer_id != current.peer_id
            || self.public_key != current.public_key
            || self.policy_version != current.policy_version
            || self.policy_hash != current.policy_hash
            || self.policy_expires_at_ms != current.policy_expires_at_ms
            || self.advertisement_expires_at_ms < required_expiry_ms
            || self.policy_expires_at_ms < required_expiry_ms
            || self.expires_at_ms < required_expiry_ms
            || self.expires_at_ms
                > self
                    .advertisement_expires_at_ms
                    .min(self.policy_expires_at_ms)
            || current.advertisement_expires_at_ms < required_expiry_ms
            || current.policy_expires_at_ms < required_expiry_ms
            || current.expires_at_ms < required_expiry_ms
            || current.expires_at_ms
                > current
                    .advertisement_expires_at_ms
                    .min(current.policy_expires_at_ms)
        {
            return false;
        }
        if self.advertisement_sequence == current.advertisement_sequence {
            return self.direct_matches(current);
        }
        self.advertisement_sequence != 0
            && self.advertisement_sequence < current.advertisement_sequence
    }
}

fn forwarded_control_lineage_matches_current(
    current: &DirectRelayCapability,
    forwarded: &ForwardedExitCapability,
    required_expiry_ms: u64,
) -> bool {
    if forwarded.control_relay_node_id != current.node_id
        || forwarded.control_relay_peer_id != current.peer_id
        || forwarded.control_relay_public_key != current.public_key
        || forwarded.policy_version != current.policy_version
        || forwarded.policy_hash != current.policy_hash
        || forwarded.policy_expires_at_ms != current.policy_expires_at_ms
        || forwarded.control_relay_advertisement_sequence == 0
        || forwarded.control_relay_advertisement_expires_at_ms < required_expiry_ms
        || forwarded.expires_at_ms < required_expiry_ms
        || current.advertisement_expires_at_ms < required_expiry_ms
        || current.policy_expires_at_ms < required_expiry_ms
        || current.expires_at_ms < required_expiry_ms
    {
        return false;
    }
    if forwarded.control_relay_advertisement_sequence == current.advertisement_sequence {
        return forwarded.control_relay_advertisement_expires_at_ms
            == current.advertisement_expires_at_ms
            && forwarded.control_relay_advertisement_payload_hash
                == current.advertisement_payload_hash;
    }
    forwarded.control_relay_advertisement_sequence < current.advertisement_sequence
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProspectiveDirectRelay {
    identity: ProspectivePeerIdentity,
}

impl ProspectiveDirectRelay {
    fn from_capability(capability: &DirectRelayCapability) -> Self {
        Self {
            identity: ProspectivePeerIdentity::from_direct(capability),
        }
    }

    fn selection_node_id(&self) -> Result<NodeId, RouteSetupError> {
        self.identity.selection_node_id()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProspectiveForwardedExit {
    control: ProspectiveDirectRelay,
    exit: ProspectivePeerIdentity,
}

impl ProspectiveForwardedExit {
    fn from_capabilities(
        control: &DirectRelayCapability,
        exit: &ForwardedExitCapability,
    ) -> Result<Self, RouteSetupError> {
        let canonical_exit_expiry_ms = exit
            .exit_advertisement_expires_at_ms
            .min(exit.policy_expires_at_ms)
            .min(control.expires_at_ms);
        if exit.expires_at_ms == 0
            || exit.expires_at_ms > canonical_exit_expiry_ms
            || !forwarded_control_lineage_matches_current(control, exit, exit.expires_at_ms)
            || control.node_id == exit.exit_node_id
            || control.peer_id == exit.exit_peer_id
        {
            return Err(RouteSetupError::Capability);
        }
        Ok(Self {
            control: ProspectiveDirectRelay::from_capability(control),
            exit: ProspectivePeerIdentity::from_forwarded(exit, canonical_exit_expiry_ms),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct DiversitySnapshot {
    operator_id: OperatorId,
    asn: u32,
    observed_network_prefix: ObservedNetworkPrefix,
}

impl fmt::Debug for DiversitySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiversitySnapshot([REDACTED])")
    }
}

impl DiversitySnapshot {
    fn conflicts_with(&self, other: &Self) -> bool {
        self.operator_id == other.operator_id
            || self.asn == other.asn
            || self.observed_network_prefix == other.observed_network_prefix
    }
}

struct ProspectiveRouteRelay {
    path_id: u32,
    proof: selection_bridge::ActorBoundRelayProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedForwardedExit {
    authority: ProspectiveForwardedExit,
    control_diversity: DiversitySnapshot,
    exit_diversity: DiversitySnapshot,
    evidence_batch_id: [u8; ID_BYTES],
}

#[derive(Clone, Debug)]
struct PostProbeSelectionPolicy {
    requirements: FilterRequirements,
    relay_policy: RelaySelectionPolicy,
}

/// Locally proven dataplane-runtime scope required before Exit finalization may be dispatched.
///
/// Kernel-backed UDP/TCP routes bind a fresh in-process route-runtime incarnation after the helper
/// endpoints prove live. A userspace MPQUIC route must instead bind its role-specific preflight
/// incarnation before it can establish a native session. Neither identifier is binary attestation.
#[derive(Clone, Debug)]
struct ClientNativeRouteScope {
    masque_context_id: u64,
    client_native_instance_id: [u8; 32],
}

#[derive(Clone, Debug)]
struct RouteSetupParameters {
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    allowed_transports: Vec<Transport>,
    reserved_up_mbps: u64,
    reserved_down_mbps: u64,
    policy_hash: [u8; 32],
    probe_address_family: ProbeAddressFamily,
    post_probe_policy: PostProbeSelectionPolicy,
    created_at_ms: u64,
    expires_at_ms: u64,
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
    client_native_route_scope: Option<ClientNativeRouteScope>,
}

struct RouteSetupPath {
    path_id: u32,
    proof: selection_bridge::ActorBoundRelayProof,
}

struct SelectedRouteSetupPath {
    path_id: u32,
    relay: ProspectiveDirectRelay,
}

struct RouteSetupRequest {
    control: ProspectiveDirectRelay,
    exit: ProspectivePeerIdentity,
    evidence_batch_id: [u8; ID_BYTES],
    paths: Vec<RouteSetupPath>,
    parameters: RouteSetupParameters,
}

impl RouteSetupRequest {
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed constructor cross-binds every selected actor and evidence field"
    )]
    fn new(
        forwarded_exit: SelectedForwardedExit,
        prospective_relays: Vec<ProspectiveRouteRelay>,
        mut parameters: RouteSetupParameters,
    ) -> Result<Self, RouteSetupError> {
        if prospective_relays.is_empty()
            || prospective_relays.len() > usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)
            || prospective_relays.len() < parameters.post_probe_policy.relay_policy.minimum_paths
        {
            return Err(RouteSetupError::Invalid("prospective path count"));
        }
        validate_parameters(&parameters)?;

        let SelectedForwardedExit {
            authority: ProspectiveForwardedExit { control, exit },
            control_diversity,
            exit_diversity,
            evidence_batch_id,
        } = forwarded_exit;
        let setup_expires_at_ms = parameters
            .setup_expires_at_unix
            .checked_mul(1_000)
            .ok_or(RouteSetupError::Invalid("setup expiry"))?;
        if control_diversity.conflicts_with(&exit_diversity) {
            return Err(RouteSetupError::Invalid("control exit diversity"));
        }
        let exit_selection_node_id = exit.selection_node_id()?;
        if control.identity.selection_node_id()? == exit_selection_node_id
            || control.identity.wire_node_id == exit.wire_node_id
            || control.identity.peer_id == exit.peer_id
            || control.identity.public_key == exit.public_key
            || control.identity.policy_version != exit.policy_version
            || control.identity.policy_hash != parameters.policy_hash
            || exit.policy_hash != parameters.policy_hash
            || control.identity.policy_expires_at_ms != exit.policy_expires_at_ms
            || control.identity.advertisement_expires_at_ms < setup_expires_at_ms
            || exit.advertisement_expires_at_ms < setup_expires_at_ms
            || control.identity.policy_expires_at_ms < parameters.expires_at_ms
            || exit.policy_expires_at_ms < parameters.expires_at_ms
            || control.identity.expires_at_ms < setup_expires_at_ms
            || exit.expires_at_ms < setup_expires_at_ms
        {
            return Err(RouteSetupError::Invalid("selected forwarded exit evidence"));
        }

        let mut paths = Vec::with_capacity(prospective_relays.len());
        for (index, binding) in prospective_relays.into_iter().enumerate() {
            let ProspectiveRouteRelay { path_id, proof } = binding;
            proof.validate_request_binding(
                parameters.created_at_ms,
                setup_expires_at_ms,
                parameters.expires_at_ms,
                &parameters.post_probe_policy.requirements,
                evidence_batch_id,
                &control.identity,
                &exit,
                &control_diversity,
                &exit_diversity,
                &paths,
            )?;
            let expected_path_id =
                u32::try_from(index + 1).map_err(|_| RouteSetupError::Invalid("path id"))?;
            if path_id != expected_path_id {
                return Err(RouteSetupError::Invalid("selected relay evidence"));
            }
            paths.push(RouteSetupPath { path_id, proof });
        }

        parameters
            .allowed_transports
            .sort_by_key(|transport| *transport as i32);
        Ok(Self {
            control,
            exit,
            evidence_batch_id,
            paths,
            parameters,
        })
    }

    fn final_path_upper(&self) -> Result<u32, RouteSetupError> {
        let maximum = self
            .paths
            .len()
            .min(self.parameters.post_probe_policy.relay_policy.maximum_paths);
        u32::try_from(maximum).map_err(|_| RouteSetupError::Invalid("final path upper"))
    }

    fn probe_permit_limit(&self) -> Result<u32, RouteSetupError> {
        u32::try_from(self.paths.len()).map_err(|_| RouteSetupError::Invalid("probe permit limit"))
    }

    fn exit_intent(
        &self,
        authorities: &RouteSetupAuthorities,
    ) -> Result<ExitReservationIntent, RouteSetupError> {
        let setup_deadline_ms = self
            .parameters
            .setup_expires_at_unix
            .checked_mul(1_000)
            .ok_or(RouteSetupError::Invalid("setup expiry"))?;
        let hold_expires_at_ms = self
            .parameters
            .created_at_ms
            .checked_add(MAXIMUM_PHASE_LIFETIME_MS)
            .ok_or(RouteSetupError::Invalid("hold expiry"))?
            .min(setup_deadline_ms)
            .min(self.parameters.expires_at_ms);
        if hold_expires_at_ms <= self.parameters.created_at_ms {
            return Err(RouteSetupError::Invalid("hold expiry"));
        }
        let native_scope = self
            .parameters
            .client_native_route_scope
            .as_ref()
            .ok_or(RouteSetupError::NativeRouteScopeUnavailable)?;
        Ok(ExitReservationIntent {
            reservation_id: self.parameters.reservation_id,
            route_context_id: self.parameters.route_context_id,
            exit_node_id: authorities.exit.exit_node_id,
            exit_peer_id: authorities.exit.exit_peer_id.to_bytes(),
            control_relay_node_id: authorities.control.node_id,
            control_relay_peer_id: authorities.control.peer_id.to_bytes(),
            allowed_transports: self.parameters.allowed_transports.clone(),
            reserved_up_mbps: self.parameters.reserved_up_mbps,
            reserved_down_mbps: self.parameters.reserved_down_mbps,
            maximum_paths: self.final_path_upper()?,
            probe_permit_limit: self.probe_permit_limit()?,
            policy_hash: self.parameters.policy_hash,
            created_at_ms: self.parameters.created_at_ms,
            hold_expires_at_ms,
            reservation_expires_at_ms: self.parameters.expires_at_ms,
            masque_context_id: native_scope.masque_context_id,
            client_native_instance_id: native_scope.client_native_instance_id,
        })
    }

    fn prepare_request(
        &self,
        selected: &[SelectedRouteSetupPath],
        active_path_count: usize,
        traversal_hints: Vec<volparossa_routing::TraversalEndpointHint>,
    ) -> PrepareLeaseBatch {
        let path_count = u32::try_from(active_path_count).unwrap_or(MAX_HELPER_PATHS);
        PrepareLeaseBatch {
            route_context_id: self.parameters.route_context_id.to_vec(),
            role: ContextRole::Client as i32,
            mptcp_accepted_addrs: path_count,
            mptcp_subflows: path_count,
            leases: selected
                .iter()
                .map(|path| LeasePlan {
                    path_id: path.path_id,
                    role: WireguardRole::Client as i32,
                })
                .collect(),
            setup_expires_at_unix: self.parameters.setup_expires_at_unix,
            hard_expires_at_unix: self.parameters.hard_expires_at_unix,
            traversal_hints,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the incompatible v4 route policy is validated as one atomic cross-field contract"
)]
fn validate_parameters(parameters: &RouteSetupParameters) -> Result<(), RouteSetupError> {
    if parameters.reservation_id.iter().all(|byte| *byte == 0)
        || parameters.route_context_id.iter().all(|byte| *byte == 0)
        || parameters.reservation_id == parameters.route_context_id
        || parameters.policy_hash.iter().all(|byte| *byte == 0)
    {
        return Err(RouteSetupError::Invalid("route identifiers"));
    }
    if parameters.allowed_transports.len() != 1
        || parameters.allowed_transports[0] == Transport::Unspecified
    {
        return Err(RouteSetupError::Invalid("transport scope"));
    }
    let transport = parameters.allowed_transports[0];
    let policy = parameters.post_probe_policy.relay_policy;
    let requirements = &parameters.post_probe_policy.requirements;
    let expected_selection_transport = match transport {
        Transport::TcpMptcp => SelectionTransport::TcpMptcp,
        Transport::UdpSinglePath => SelectionTransport::UdpSinglePath,
        Transport::MultipathQuic => SelectionTransport::MultipathQuic,
        Transport::Unspecified => return Err(RouteSetupError::Invalid("transport scope")),
    };
    let expected_family = match parameters.probe_address_family {
        ProbeAddressFamily::Ipv4 => IpFamily::Ipv4,
        ProbeAddressFamily::Ipv6 => IpFamily::Ipv6,
        ProbeAddressFamily::Unspecified => {
            return Err(RouteSetupError::Invalid("probe address family"));
        }
    };
    let required_up = u32::try_from(parameters.reserved_up_mbps)
        .map_err(|_| RouteSetupError::Invalid("reservation capacity"))?;
    let required_down = u32::try_from(parameters.reserved_down_mbps)
        .map_err(|_| RouteSetupError::Invalid("reservation capacity"))?;
    let mix = policy.mix;
    let mix_values = [mix.high, mix.diverse_middle, mix.exploration];
    if mix_values
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
        || (mix_values.iter().sum::<f64>() - 1.0).abs() > 1e-9
    {
        return Err(RouteSetupError::Invalid("post-probe selection mix"));
    }
    if requirements.role != ServiceRole::Relay
        || requirements.transport != expected_selection_transport
        || requirements.policy_hash.as_bytes() != &parameters.policy_hash
        || requirements.minimum_capacity
            != Bandwidth::new(required_up, required_down)
                .map_err(|_| RouteSetupError::Invalid("reservation capacity"))?
        || requirements.address_family != Some(expected_family)
        || !requirements.require_reachable
        || policy.minimum_paths == 0
        || policy.minimum_paths > policy.active_paths
        || policy.active_paths > policy.maximum_paths
        || policy.maximum_paths > usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)
        || policy.active_paths.saturating_add(policy.warm_backup_paths) > policy.maximum_paths
        || policy.maximum_rtt_spread_ms <= 0.0
        || policy.maximum_rtt_spread_ms > 1_000.0
        || !policy.maximum_rtt_spread_ms.is_finite()
        || !(0.0..=1.0).contains(&policy.minimum_unique_throughput_gain_ratio)
        || !policy.minimum_unique_throughput_gain_ratio.is_finite()
    {
        return Err(RouteSetupError::Invalid("post-probe policy"));
    }
    match transport {
        Transport::UdpSinglePath
            if policy.active_paths != 1
                || policy.minimum_paths != 1
                || policy.maximum_paths != 1
                || policy.warm_backup_paths != 0 =>
        {
            return Err(RouteSetupError::Invalid("single-path UDP path count"));
        }
        Transport::TcpMptcp | Transport::MultipathQuic
            if policy.active_paths < 2 || policy.minimum_paths < 2 =>
        {
            return Err(RouteSetupError::Invalid("multipath path count"));
        }
        Transport::Unspecified => return Err(RouteSetupError::Invalid("transport scope")),
        Transport::UdpSinglePath | Transport::TcpMptcp | Transport::MultipathQuic => {}
    }
    if parameters.reserved_up_mbps == 0
        || parameters.reserved_down_mbps == 0
        || parameters.reserved_up_mbps > u64::from(MAX_HELPER_RATE_MBPS)
        || parameters.reserved_down_mbps > u64::from(MAX_HELPER_RATE_MBPS)
    {
        return Err(RouteSetupError::Invalid("reservation capacity"));
    }
    let lifetime = parameters
        .expires_at_ms
        .checked_sub(parameters.created_at_ms)
        .ok_or(RouteSetupError::Invalid("reservation lifetime"))?;
    let hard_expiry_ms = parameters
        .hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(RouteSetupError::Invalid("helper expiry"))?;
    if lifetime == 0
        || lifetime > MAXIMUM_RESERVATION_LIFETIME_MS
        || parameters.setup_expires_at_unix == 0
        || parameters.setup_expires_at_unix > parameters.hard_expires_at_unix
        || hard_expiry_ms > parameters.expires_at_ms
    {
        return Err(RouteSetupError::Invalid("route deadlines"));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RouteSetupAuthorities {
    control: DirectRelayCapability,
    exit: ForwardedExitCapability,
    datapath_relays: Vec<DirectRelayCapability>,
}

impl RouteSetupAuthorities {
    async fn resolve<R: RouteCapabilityResolver>(
        resolver: &R,
        request: &RouteSetupRequest,
    ) -> Result<Self, RouteSetupError> {
        let control = &request.control.identity;
        let control_capability = resolver
            .resolve_direct_relay(control.wire_node_id, control.peer_id)
            .await?;
        let exit = resolver
            .resolve_forwarded_exit(
                control.wire_node_id,
                control.peer_id,
                request.exit.wire_node_id,
                request.exit.peer_id,
            )
            .await?;
        let mut datapath_relays = Vec::with_capacity(request.paths.len());
        for path in &request.paths {
            datapath_relays.push(path.proof.resolve(resolver).await?);
        }
        let authorities = Self {
            control: control_capability,
            exit,
            datapath_relays,
        };
        authorities.validate(request)?;
        Ok(authorities)
    }

    fn validate(&self, request: &RouteSetupRequest) -> Result<(), RouteSetupError> {
        let forwarded = ProspectiveForwardedExit::from_capabilities(&self.control, &self.exit)
            .map_err(|_| RouteSetupError::Capability)?;
        let route_required_expiry = request.parameters.expires_at_ms;
        let setup_required_expiry = request
            .parameters
            .setup_expires_at_unix
            .checked_mul(1_000)
            .ok_or(RouteSetupError::Capability)?;
        let selected_exit_expiry = self
            .exit
            .exit_advertisement_expires_at_ms
            .min(self.exit.policy_expires_at_ms)
            .min(request.control.identity.expires_at_ms);
        let selected_exit =
            ProspectivePeerIdentity::from_forwarded(&self.exit, selected_exit_expiry);
        if self.datapath_relays.len() != request.paths.len()
            || !request
                .control
                .identity
                .direct_lineage_matches(&self.control, setup_required_expiry)
            || selected_exit != request.exit
            || forwarded.exit.expires_at_ms < request.exit.expires_at_ms
            || self.control.policy_hash != request.parameters.policy_hash
            || self.exit.policy_hash != request.parameters.policy_hash
        {
            return Err(RouteSetupError::Capability);
        }
        if self.control.expires_at_ms < setup_required_expiry
            || self.exit.expires_at_ms < setup_required_expiry
            || self.control.advertisement_expires_at_ms < setup_required_expiry
            || self.exit.exit_advertisement_expires_at_ms < setup_required_expiry
            || self.control.policy_expires_at_ms < route_required_expiry
            || self.exit.policy_expires_at_ms < route_required_expiry
        {
            return Err(RouteSetupError::Capability);
        }

        let mut nodes = BTreeSet::from([self.control.node_id, self.exit.exit_node_id]);
        let mut peers = BTreeSet::from([
            self.control.peer_id.to_bytes(),
            self.exit.exit_peer_id.to_bytes(),
        ]);
        let mut public_keys = BTreeSet::from([self.control.public_key, self.exit.exit_public_key]);
        for (path, capability) in request.paths.iter().zip(&self.datapath_relays) {
            if !path.proof.capability_matches(
                capability,
                request.parameters.policy_hash,
                setup_required_expiry,
                route_required_expiry,
            ) || !nodes.insert(capability.node_id)
                || !peers.insert(capability.peer_id.to_bytes())
                || !public_keys.insert(capability.public_key)
            {
                return Err(RouteSetupError::Capability);
            }
        }
        Ok(())
    }

    fn relay_for_path(&self, path_id: u32) -> Option<&DirectRelayCapability> {
        let index = usize::try_from(path_id.checked_sub(1)?).ok()?;
        self.datapath_relays.get(index)
    }
}

#[derive(Clone, Copy, Debug)]
struct RouteSetupLimits {
    setup_timeout: Duration,
    call_timeout: Duration,
    maximum_outbound_attempts: u8,
}

impl RouteSetupLimits {
    fn new(
        setup_timeout: Duration,
        call_timeout: Duration,
        maximum_outbound_attempts: u8,
    ) -> Result<Self, RouteSetupError> {
        if setup_timeout.is_zero()
            || setup_timeout > MAXIMUM_SETUP_DURATION
            || call_timeout.is_zero()
            || call_timeout > MAXIMUM_CALL_DURATION
            || call_timeout > setup_timeout
            || !(1..=MAXIMUM_OUTBOUND_ATTEMPTS).contains(&maximum_outbound_attempts)
        {
            return Err(RouteSetupError::Invalid("setup limits"));
        }
        Ok(Self {
            setup_timeout,
            call_timeout,
            maximum_outbound_attempts,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteSetupPhase {
    Validated,
    CapacityHold,
    ProbePermits,
    ExecuteProbes,
    RetirementSlot,
    Preparing,
    Finalizing,
    RelayReservations,
    ExitConfirmations,
    Activating,
    Committing,
    Retiring,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
enum RouteSetupError {
    #[error("invalid route setup input: {0}")]
    Invalid(&'static str),
    #[error("current actor-minted route authority is unavailable or mismatched")]
    Capability,
    #[error("native process route scope is unavailable before reservation dispatch")]
    NativeRouteScopeUnavailable,
    #[error("route setup reservation expired")]
    Expired,
    #[error("route setup was cancelled")]
    Cancelled,
    #[error("route setup absolute deadline elapsed during {0:?}")]
    Deadline(RouteSetupPhase),
    #[error("route setup call timed out during {0:?}")]
    CallTimeout(RouteSetupPhase),
    #[error("local setup backend failed during {0:?}")]
    LocalBackend(RouteSetupPhase),
    #[error("reservation transport failed during {0:?}")]
    Outbound(RouteSetupPhase),
    #[error("remote reservation was definitively rejected during {0:?}")]
    RemoteRejected(RouteSetupPhase),
    #[error("remote reservation was definitively unavailable during {0:?}")]
    RemoteUnavailable(RouteSetupPhase),
    #[error("reservation protocol rejected data during {0:?}")]
    ReservationProtocol(RouteSetupPhase),
    #[error("helper response did not match the local transaction")]
    HelperCorrelation,
    #[error("bounded retirement ownership is unavailable")]
    RetirementUnavailable,
    #[error("owned setup supervisor stopped unexpectedly")]
    SupervisorStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStatus {
    NotRequired,
    Destroyed,
    Quarantined,
}

#[derive(Debug, Error)]
#[error("route setup failed: {cause}")]
struct RouteSetupFailure {
    cause: RouteSetupError,
    cleanup: CleanupStatus,
    released_local_leases: usize,
    remote_grants_expire_only: bool,
}

impl RouteSetupFailure {
    fn before_dispatch(cause: RouteSetupError) -> Self {
        Self {
            cause,
            cleanup: CleanupStatus::NotRequired,
            released_local_leases: 0,
            remote_grants_expire_only: false,
        }
    }
}

enum LocalPrepareFailure<E> {
    Definitive(E),
    Ambiguous {
        source: E,
        authority: PrepareReconciliationAuthority,
    },
}

trait LocalRouteBackend: Clone + Send + Sync + 'static {
    type Error: Send + 'static;

    fn prepare<'a>(
        &'a mut self,
        request: &'a PrepareLeaseBatch,
    ) -> impl Future<
        Output = Result<RuntimeBoundPreparedLeaseBatch, LocalPrepareFailure<Self::Error>>,
    > + Send
    + 'a;

    fn activate<'a>(
        &'a mut self,
        owner: &'a mut RuntimeBoundPreparedLeaseBatch,
        request: &'a ActivateLeaseBatch,
    ) -> impl Future<Output = Result<ActivatedLeaseBatch, Self::Error>> + Send + 'a;

    fn commit<'a>(
        &'a mut self,
        owner: &'a mut RuntimeBoundPreparedLeaseBatch,
        request: &'a CommitLeaseBatch,
    ) -> impl Future<Output = Result<CommittedLeaseBatch, Self::Error>> + Send + 'a;

    fn destroy<'a>(
        &'a mut self,
        owner: &'a RuntimeBoundPreparedLeaseBatch,
    ) -> impl Future<Output = Result<DestroyedContext, Self::Error>> + Send + 'a;

    fn reconcile_expired_prepare(
        &mut self,
        authority: &PrepareReconciliationAuthority,
    ) -> impl Future<Output = Result<ReconciledExpiredPrepare, Self::Error>> + Send;
}

impl LocalRouteBackend for HelperClient {
    type Error = HelperClientError;

    async fn prepare(
        &mut self,
        request: &PrepareLeaseBatch,
    ) -> Result<RuntimeBoundPreparedLeaseBatch, LocalPrepareFailure<Self::Error>> {
        self.prepare_lease_batch(request.clone())
            .await
            .map_err(|failure| match failure {
                PrepareLeaseBatchFailure::Definitive(source) => {
                    LocalPrepareFailure::Definitive(source)
                }
                PrepareLeaseBatchFailure::Ambiguous { source, authority } => {
                    LocalPrepareFailure::Ambiguous { source, authority }
                }
            })
    }

    async fn activate(
        &mut self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        request: &ActivateLeaseBatch,
    ) -> Result<ActivatedLeaseBatch, Self::Error> {
        self.activate_lease_batch(owner, request.clone()).await
    }

    async fn commit(
        &mut self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        request: &CommitLeaseBatch,
    ) -> Result<CommittedLeaseBatch, Self::Error> {
        self.commit_lease_batch(owner, request.clone()).await
    }

    async fn destroy(
        &mut self,
        owner: &RuntimeBoundPreparedLeaseBatch,
    ) -> Result<DestroyedContext, Self::Error> {
        self.destroy_context(owner).await
    }

    async fn reconcile_expired_prepare(
        &mut self,
        authority: &PrepareReconciliationAuthority,
    ) -> Result<ReconciledExpiredPrepare, Self::Error> {
        HelperClient::reconcile_expired_prepare(self, authority).await
    }
}

trait ReservationTransport: Send + 'static {
    type Error: Send + 'static;

    fn ambiguous_after_dispatch(error: &Self::Error) -> bool;

    fn endpoint_traversal_hints(
        &mut self,
        bindings: Vec<EndpointTraversalBinding>,
    ) -> impl Future<Output = Result<Vec<volparossa_routing::TraversalEndpointHint>, Self::Error>> + Send;

    fn exit_forward<'a>(
        &'a mut self,
        control: &'a DirectRelayCapability,
        request: &'a ExitForwardRequest,
    ) -> impl Future<Output = Result<ExitForwardResponse, Self::Error>> + Send + 'a;

    fn datapath_relay<'a>(
        &'a mut self,
        relay: &'a DirectRelayCapability,
        request: &'a DatapathRelayRequest,
    ) -> impl Future<Output = Result<DatapathRelayResponse, Self::Error>> + Send + 'a;
}

trait RouteCapabilityResolver: Send + 'static {
    fn resolve_direct_relay(
        &self,
        expected_node_id: [u8; 32],
        expected_peer_id: Libp2pPeerId,
    ) -> impl Future<Output = Result<DirectRelayCapability, RouteSetupError>> + Send + '_;

    fn resolve_forwarded_exit(
        &self,
        control_relay_node_id: [u8; 32],
        control_relay_peer_id: Libp2pPeerId,
        exit_node_id: [u8; 32],
        exit_peer_id: Libp2pPeerId,
    ) -> impl Future<Output = Result<ForwardedExitCapability, RouteSetupError>> + Send + '_;
}

impl RouteCapabilityResolver for DiscoveryControlHandle {
    async fn resolve_direct_relay(
        &self,
        expected_node_id: [u8; 32],
        expected_peer_id: Libp2pPeerId,
    ) -> Result<DirectRelayCapability, RouteSetupError> {
        DiscoveryControlHandle::resolve_direct_relay(self, expected_node_id, expected_peer_id)
            .await
            .map_err(|_| RouteSetupError::Capability)
    }

    async fn resolve_forwarded_exit(
        &self,
        control_relay_node_id: [u8; 32],
        control_relay_peer_id: Libp2pPeerId,
        exit_node_id: [u8; 32],
        exit_peer_id: Libp2pPeerId,
    ) -> Result<ForwardedExitCapability, RouteSetupError> {
        DiscoveryControlHandle::resolve_forwarded_exit(
            self,
            control_relay_node_id,
            control_relay_peer_id,
            exit_node_id,
            exit_peer_id,
        )
        .await
        .map_err(|_| RouteSetupError::Capability)
    }
}

impl ReservationTransport for DiscoveryControlHandle {
    type Error = OutboundReservationError;

    fn ambiguous_after_dispatch(error: &Self::Error) -> bool {
        *error == OutboundReservationError::AmbiguousAfterDispatch
    }

    async fn endpoint_traversal_hints(
        &mut self,
        bindings: Vec<EndpointTraversalBinding>,
    ) -> Result<Vec<volparossa_routing::TraversalEndpointHint>, Self::Error> {
        DiscoveryControlHandle::endpoint_traversal_hints(self, bindings).await
    }

    async fn exit_forward<'a>(
        &'a mut self,
        control: &'a DirectRelayCapability,
        request: &'a ExitForwardRequest,
    ) -> Result<ExitForwardResponse, Self::Error> {
        self.request_exit_forward(control.peer_id, request.clone())
            .await
    }

    async fn datapath_relay<'a>(
        &'a mut self,
        relay: &'a DirectRelayCapability,
        request: &'a DatapathRelayRequest,
    ) -> Result<DatapathRelayResponse, Self::Error> {
        self.request_datapath_relay(relay.peer_id, request.clone())
            .await
    }
}

trait RouteSetupClock: Send + Sync + 'static {
    fn unix_millis(&self) -> u64;
}

struct SystemRouteSetupClock;

impl RouteSetupClock for SystemRouteSetupClock {
    fn unix_millis(&self) -> u64 {
        crate::unix_millis()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ProbeProjection {
    path_id: u32,
    transport: Transport,
    address_family: ProbeAddressFamily,
    minimum_directional_capacity_mbps: u64,
    evidence_bytes: u64,
    client_to_relay_rtt_micros: u64,
    relay_to_exit_rtt_micros: u64,
    total_rtt_micros: u64,
    unique_throughput_gain_ratio: f64,
    meaningful_failover: bool,
}

trait ClientReservationProtocol: Send + 'static {
    type Hold: Send + 'static;
    type ProbeRequest: Send + 'static;
    type ProbePermit: Send + 'static;
    type Probe: Send + 'static;
    type FinalizeRequest: Send + 'static;
    type ExitBundle: Send + 'static;
    type RelayGrant: Send + Sync + 'static;
    type NativeAuthorization: Send + 'static;

    fn sign_hold(&mut self, intent: &ExitReservationIntent) -> Result<Vec<u8>, RouteSetupError>;

    fn verify_hold(
        &mut self,
        intent: &ExitReservationIntent,
        signed_responses: Vec<Vec<u8>>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<Self::Hold, RouteSetupError>;

    fn sign_probe_request(
        &mut self,
        hold: &Self::Hold,
        path: &RelayPathIntent,
        transport: Transport,
        address_family: ProbeAddressFamily,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self::ProbeRequest, RouteSetupError>;

    fn probe_request_bytes(request: &Self::ProbeRequest) -> &[u8];

    fn verify_probe_permit(
        &mut self,
        request: &Self::ProbeRequest,
        signed_permit: Vec<u8>,
        now_ms: u64,
    ) -> Result<Self::ProbePermit, RouteSetupError>;

    fn probe_permit_bytes(permit: &Self::ProbePermit) -> &[u8];

    fn verify_probe_result(
        &mut self,
        permit: Self::ProbePermit,
        signed_result: Vec<u8>,
        now_ms: u64,
    ) -> Result<Self::Probe, RouteSetupError>;

    fn probe_projection(probe: &Self::Probe) -> Result<ProbeProjection, RouteSetupError>;

    fn sign_finalize(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &Self::Hold,
        probes: &[Self::Probe],
        created_at_ms: u64,
        expires_at_ms: u64,
        endpoints: &LocalEndpointLeaseBatch,
    ) -> Result<Self::FinalizeRequest, RouteSetupError>;

    fn finalize_request_bytes(request: &Self::FinalizeRequest) -> &[u8];

    fn verify_finalize(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &Self::Hold,
        request: &Self::FinalizeRequest,
        signed_responses: Vec<Vec<u8>>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<Self::ExitBundle, RouteSetupError>;

    fn exit_bundle_path_count(bundle: &Self::ExitBundle) -> usize;

    fn signed_exit_reservation(bundle: &Self::ExitBundle) -> &[u8];

    fn sign_relay_request(
        &mut self,
        bundle: &Self::ExitBundle,
        path_index: usize,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, RouteSetupError>;

    fn verify_relay_response(
        &mut self,
        bundle: &Self::ExitBundle,
        signed_relay: Vec<u8>,
        path_index: usize,
        path: &SelectedRouteSetupPath,
        now_ms: u64,
    ) -> Result<Self::RelayGrant, RouteSetupError>;

    fn sign_confirmation(
        &mut self,
        grant: &Self::RelayGrant,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, RouteSetupError>;

    fn verify_confirmation_receipt(
        &mut self,
        grant: &Self::RelayGrant,
        signed_confirmation: &[u8],
        signed_receipt: &[u8],
        now_ms: u64,
    ) -> Result<(), RouteSetupError>;

    fn take_native_route_authorization(
        &mut self,
        request: &Self::FinalizeRequest,
        now_ms: u64,
    ) -> Result<Self::NativeAuthorization, RouteSetupError>;

    fn grant_path_id(grant: &Self::RelayGrant) -> u32;

    fn signed_relay_reservation(grant: &Self::RelayGrant) -> &[u8];

    fn relay_client_endpoint(
        grant: &Self::RelayGrant,
    ) -> Result<PublicWireGuardEndpoint, RouteSetupError>;

    fn release(&mut self, reservation_id: [u8; ID_BYTES]) -> usize;
}

struct ReservationSession {
    coordinator: ReservationCoordinator,
}

impl ReservationSession {
    fn generate(replay_capacity: usize) -> Result<Self, RouteSetupError> {
        if replay_capacity == 0 || replay_capacity > MAXIMUM_REPLAY_CAPACITY {
            return Err(RouteSetupError::Invalid("reservation replay capacity"));
        }
        Ok(Self {
            coordinator: ReservationCoordinator::new(replay_capacity)
                .map_err(|_| RouteSetupError::Invalid("client reservation identity"))?,
        })
    }
}

impl fmt::Debug for ReservationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservationSession")
            .field("coordinator", &self.coordinator)
            .finish()
    }
}

impl ClientReservationProtocol for ReservationSession {
    type Hold = VerifiedExitCapacityHold;
    type ProbeRequest = SignedProbePermitRequest;
    type ProbePermit = VerifiedProbePermit;
    type Probe = VerifiedRelayProbe;
    type FinalizeRequest = SignedExitFinalizeRequest;
    type ExitBundle = VerifiedFinalizedExitBundle;
    type RelayGrant = VerifiedRelayGrant;
    type NativeAuthorization = ClientNativeRouteAuthorization;

    fn sign_hold(&mut self, intent: &ExitReservationIntent) -> Result<Vec<u8>, RouteSetupError> {
        self.coordinator
            .sign_hold_request(intent)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::CapacityHold))
    }

    fn verify_hold(
        &mut self,
        intent: &ExitReservationIntent,
        signed_responses: Vec<Vec<u8>>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<Self::Hold, RouteSetupError> {
        let [signed_capability, signed_hold]: [Vec<u8>; 2] = signed_responses
            .try_into()
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::CapacityHold))?;
        self.coordinator
            .verify_hold_response(
                intent,
                signed_capability,
                signed_hold,
                authenticated_exit_peer_id,
                now_ms,
            )
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::CapacityHold))
    }

    fn sign_probe_request(
        &mut self,
        hold: &Self::Hold,
        path: &RelayPathIntent,
        transport: Transport,
        address_family: ProbeAddressFamily,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self::ProbeRequest, RouteSetupError> {
        self.coordinator
            .sign_probe_permit_request(
                hold,
                path,
                transport,
                address_family,
                created_at_ms,
                expires_at_ms,
            )
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ProbePermits))
    }

    fn probe_request_bytes(request: &Self::ProbeRequest) -> &[u8] {
        request.encoded()
    }

    fn verify_probe_permit(
        &mut self,
        request: &Self::ProbeRequest,
        signed_permit: Vec<u8>,
        now_ms: u64,
    ) -> Result<Self::ProbePermit, RouteSetupError> {
        self.coordinator
            .verify_probe_permit(request, signed_permit, now_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ProbePermits))
    }

    fn probe_permit_bytes(permit: &Self::ProbePermit) -> &[u8] {
        permit.encoded()
    }

    fn verify_probe_result(
        &mut self,
        permit: Self::ProbePermit,
        signed_result: Vec<u8>,
        now_ms: u64,
    ) -> Result<Self::Probe, RouteSetupError> {
        self.coordinator
            .verify_probe_result(permit, signed_result, now_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes))
    }

    fn probe_projection(probe: &Self::Probe) -> Result<ProbeProjection, RouteSetupError> {
        fn minimum_capacity(first: &ProbeLegEvidence, second: &ProbeLegEvidence) -> u64 {
            first
                .up_capacity_mbps
                .min(first.down_capacity_mbps)
                .min(second.up_capacity_mbps)
                .min(second.down_capacity_mbps)
        }
        fn minimum_bytes(first: &ProbeLegEvidence, second: &ProbeLegEvidence) -> u64 {
            first
                .transmitted_bytes
                .min(first.received_bytes)
                .min(second.transmitted_bytes)
                .min(second.received_bytes)
        }
        let client = probe.client_relay();
        let exit = probe.relay_exit();
        let total_rtt_micros = client.rtt_micros.checked_add(exit.rtt_micros).ok_or(
            RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes),
        )?;
        let projection = ProbeProjection {
            path_id: probe.path_id(),
            transport: probe.transport(),
            address_family: probe.address_family(),
            minimum_directional_capacity_mbps: minimum_capacity(client, exit),
            evidence_bytes: minimum_bytes(client, exit),
            client_to_relay_rtt_micros: client.rtt_micros,
            relay_to_exit_rtt_micros: exit.rtt_micros,
            total_rtt_micros,
            unique_throughput_gain_ratio: 0.0,
            meaningful_failover: false,
        };
        if projection.minimum_directional_capacity_mbps == 0
            || projection.evidence_bytes == 0
            || projection.total_rtt_micros == 0
        {
            return Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::ExecuteProbes,
            ));
        }
        Ok(projection)
    }

    fn sign_finalize(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &Self::Hold,
        probes: &[Self::Probe],
        created_at_ms: u64,
        expires_at_ms: u64,
        endpoints: &LocalEndpointLeaseBatch,
    ) -> Result<Self::FinalizeRequest, RouteSetupError> {
        let by_path = endpoints
            .client_leases()
            .iter()
            .map(|lease| (lease.path_id(), *lease))
            .collect::<BTreeMap<_, _>>();
        self.coordinator
            .sign_finalize_request(
                intent,
                hold,
                probes,
                created_at_ms,
                expires_at_ms,
                |path_id| by_path.get(&path_id).copied(),
            )
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::Finalizing))
    }

    fn finalize_request_bytes(request: &Self::FinalizeRequest) -> &[u8] {
        request.encoded()
    }

    fn verify_finalize(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &Self::Hold,
        request: &Self::FinalizeRequest,
        signed_responses: Vec<Vec<u8>>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<Self::ExitBundle, RouteSetupError> {
        let mut responses = signed_responses.into_iter();
        let signed_exit = responses
            .next()
            .ok_or(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::Finalizing,
            ))?;
        let authorizations = responses.collect::<Vec<_>>();
        self.coordinator
            .verify_finalize_response(
                intent,
                hold,
                request,
                signed_exit,
                authorizations,
                authenticated_exit_peer_id,
                now_ms,
            )
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::Finalizing))
    }

    fn exit_bundle_path_count(bundle: &Self::ExitBundle) -> usize {
        bundle.path_count()
    }

    fn signed_exit_reservation(bundle: &Self::ExitBundle) -> &[u8] {
        bundle.signed_exit_reservation()
    }

    fn sign_relay_request(
        &mut self,
        bundle: &Self::ExitBundle,
        path_index: usize,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, RouteSetupError> {
        self.coordinator
            .sign_relay_request(bundle, path_index, created_at_ms, expires_at_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::RelayReservations))
    }

    fn verify_relay_response(
        &mut self,
        bundle: &Self::ExitBundle,
        signed_relay: Vec<u8>,
        path_index: usize,
        path: &SelectedRouteSetupPath,
        now_ms: u64,
    ) -> Result<Self::RelayGrant, RouteSetupError> {
        self.coordinator
            .verify_relay_response(
                bundle,
                &signed_relay,
                path_index,
                path.relay.identity.wire_node_id,
                &path.relay.identity.peer_id.to_bytes(),
                now_ms,
            )
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::RelayReservations))
    }

    fn sign_confirmation(
        &mut self,
        grant: &Self::RelayGrant,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, RouteSetupError> {
        self.coordinator
            .sign_exit_confirmation(grant, created_at_ms, expires_at_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExitConfirmations))
    }

    fn verify_confirmation_receipt(
        &mut self,
        grant: &Self::RelayGrant,
        signed_confirmation: &[u8],
        signed_receipt: &[u8],
        now_ms: u64,
    ) -> Result<(), RouteSetupError> {
        self.coordinator
            .verify_confirmation_receipt(grant, signed_confirmation, signed_receipt, now_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExitConfirmations))
    }

    fn take_native_route_authorization(
        &mut self,
        request: &Self::FinalizeRequest,
        now_ms: u64,
    ) -> Result<Self::NativeAuthorization, RouteSetupError> {
        self.coordinator
            .take_native_route_authorization(*request.finalize_id(), now_ms)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExitConfirmations))
    }

    fn grant_path_id(grant: &Self::RelayGrant) -> u32 {
        grant.path_id()
    }

    fn signed_relay_reservation(grant: &Self::RelayGrant) -> &[u8] {
        grant.signed_relay_reservation()
    }

    fn relay_client_endpoint(
        grant: &Self::RelayGrant,
    ) -> Result<PublicWireGuardEndpoint, RouteSetupError> {
        Ok(grant.relay_client_endpoint())
    }

    fn release(&mut self, reservation_id: [u8; ID_BYTES]) -> usize {
        self.coordinator.release(reservation_id)
    }
}

struct IssuedProbe<Q, P> {
    path_id: u32,
    request: Q,
    permit: P,
    expires_at_ms: u64,
}

struct SelectedProbe<P> {
    path_id: u32,
    probe: P,
    projection: ProbeProjection,
}

struct SelectedProbeSet<P> {
    active: Vec<SelectedProbe<P>>,
    warm: Vec<SelectedProbe<P>>,
}

impl<P> SelectedProbeSet<P> {
    fn active_path_ids(&self) -> Vec<u32> {
        self.active
            .iter()
            .map(|selected| selected.path_id)
            .collect()
    }

    fn warm_path_ids(&self) -> Vec<u32> {
        self.warm.iter().map(|selected| selected.path_id).collect()
    }

    fn into_sorted(self) -> Vec<SelectedProbe<P>> {
        let mut selected = self.active;
        selected.extend(self.warm);
        selected.sort_by_key(|candidate| candidate.path_id);
        selected
    }
}

fn probe_rtt_millis(rtt_micros: u64) -> Result<f64, RouteSetupError> {
    let bounded = u32::try_from(rtt_micros)
        .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes))?;
    Ok(f64::from(bounded) / 1_000.0)
}

fn projected_candidate_from_probe<'a, P>(
    request: &'a RouteSetupRequest,
    selected: &SelectedProbe<P>,
) -> Result<ProjectedRelayPath<'a>, RouteSetupError> {
    let path = request
        .paths
        .iter()
        .find(|path| path.path_id == selected.path_id)
        .ok_or(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::ExecuteProbes,
        ))?;
    let required_up = u32::try_from(request.parameters.reserved_up_mbps)
        .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes))?;
    let required_down = u32::try_from(request.parameters.reserved_down_mbps)
        .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes))?;
    path.proof
        .projected_path(&selected.projection, required_up, required_down)
}

fn exact_probe_index<P>(
    selected: &volparossa_selection::SelectedPath,
    request: &RouteSetupRequest,
    verified: &[SelectedProbe<P>],
) -> Result<usize, RouteSetupError> {
    let mut matching = verified.iter().enumerate().filter(|(_, record)| {
        request.paths.iter().any(|path| {
            path.path_id == record.path_id && path.proof.matches_selected_path(selected)
        })
    });
    let (index, _) = matching.next().ok_or(RouteSetupError::ReservationProtocol(
        RouteSetupPhase::ExecuteProbes,
    ))?;
    if matching.next().is_some() {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::ExecuteProbes,
        ));
    }
    Ok(index)
}

fn select_verified_probe_subset<P: ClientReservationProtocol>(
    request: &RouteSetupRequest,
    probes: Vec<(u32, P::Probe)>,
    trusted_now_ms: u64,
) -> Result<SelectedProbeSet<P::Probe>, RouteSetupError> {
    select_verified_probe_subset_with_rng::<P, _>(request, probes, trusted_now_ms, &mut OsRng)
}

#[allow(
    clippy::too_many_lines,
    reason = "post-probe active and warm selection is one fail-closed evidence transaction"
)]
fn select_verified_probe_subset_with_rng<P, R>(
    request: &RouteSetupRequest,
    probes: Vec<(u32, P::Probe)>,
    trusted_now_ms: u64,
    rng: &mut R,
) -> Result<SelectedProbeSet<P::Probe>, RouteSetupError>
where
    P: ClientReservationProtocol,
    R: RngCore + ?Sized,
{
    let maximum = usize::try_from(request.final_path_upper()?)
        .map_err(|_| RouteSetupError::Invalid("final path upper"))?;
    let required_capacity_mbps = request
        .parameters
        .reserved_up_mbps
        .max(request.parameters.reserved_down_mbps);
    let policy = request.parameters.post_probe_policy.relay_policy;
    let mut eligible = Vec::with_capacity(probes.len());
    let mut seen = BTreeSet::new();
    let expected = request
        .paths
        .iter()
        .map(|path| path.path_id)
        .collect::<BTreeSet<_>>();
    for (path_id, probe) in probes {
        let projection = P::probe_projection(&probe)?;
        if projection.path_id != path_id
            || !expected.contains(&projection.path_id)
            || projection.transport != request.parameters.allowed_transports[0]
            || projection.address_family != request.parameters.probe_address_family
            || !seen.insert(projection.path_id)
            || projection.client_to_relay_rtt_micros == 0
            || projection.relay_to_exit_rtt_micros == 0
            || !projection.unique_throughput_gain_ratio.is_finite()
            || !(0.0..=1.0).contains(&projection.unique_throughput_gain_ratio)
        {
            return Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::ExecuteProbes,
            ));
        }
        if projection.minimum_directional_capacity_mbps < required_capacity_mbps {
            continue;
        }
        eligible.push(SelectedProbe {
            path_id,
            probe,
            projection,
        });
    }
    if seen != expected {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::ExecuteProbes,
        ));
    }

    let mut requirements = request.parameters.post_probe_policy.requirements.clone();
    requirements.now = UnixTime::from_secs(trusted_now_ms / 1_000);
    for path in &request.paths {
        path.proof.revalidate_for_scoring(
            trusted_now_ms,
            &requirements,
            request.evidence_batch_id,
        )?;
    }
    let active_candidates = eligible
        .iter()
        .map(|candidate| projected_candidate_from_probe(request, candidate))
        .collect::<Result<Vec<_>, _>>()?;
    let mut active_policy = policy;
    active_policy.warm_backup_paths = 0;
    let selected =
        select_projected_relay_paths(&active_candidates, &requirements, active_policy, rng)
            .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes))?;
    if selected.active.len() < policy.minimum_paths
        || selected.active.len() > policy.active_paths
        || !selected.warm_backups.is_empty()
    {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::ExecuteProbes,
        ));
    }
    let active_indices = selected
        .active
        .iter()
        .map(|selected| exact_probe_index(selected, request, &eligible))
        .collect::<Result<Vec<_>, _>>()?;
    let active_ids = active_indices
        .iter()
        .map(|index| eligible[*index].path_id)
        .collect::<BTreeSet<_>>();

    let remaining = maximum.saturating_sub(active_indices.len());
    let warm_limit = policy.warm_backup_paths.min(remaining);
    let mut warm_indices = eligible
        .iter()
        .enumerate()
        .filter(|(_, candidate)| !active_ids.contains(&candidate.path_id))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    warm_indices.sort_by_key(|index| {
        let candidate = &eligible[*index];
        (
            Reverse(candidate.projection.minimum_directional_capacity_mbps),
            Reverse(candidate.projection.evidence_bytes),
            candidate.projection.total_rtt_micros,
            candidate.projection.path_id,
        )
    });
    warm_indices.truncate(warm_limit);
    if active_indices.is_empty()
        || active_indices.len().saturating_add(warm_indices.len()) > maximum
    {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::ExecuteProbes,
        ));
    }
    let mut owned = eligible.into_iter().map(Some).collect::<Vec<_>>();
    let active = active_indices
        .into_iter()
        .map(|index| {
            owned[index]
                .take()
                .ok_or(RouteSetupError::ReservationProtocol(
                    RouteSetupPhase::ExecuteProbes,
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let warm = warm_indices
        .into_iter()
        .map(|index| {
            owned[index]
                .take()
                .ok_or(RouteSetupError::ReservationProtocol(
                    RouteSetupPhase::ExecuteProbes,
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SelectedProbeSet { active, warm })
}

enum PrepareTicketSettlement<P> {
    Prepared(PreparedContextOwner<P>),
    Failed(RouteSetupError),
    OwnedFailure(PreparedContextOwner<P>, RouteSetupError),
}

struct HelperTicketGuard<P> {
    retirement: RetirementSink<P>,
    armed: bool,
}

impl<P> HelperTicketGuard<P> {
    fn new(retirement: RetirementSink<P>) -> Self {
        Self {
            retirement,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<P> Drop for HelperTicketGuard<P> {
    fn drop(&mut self) {
        if self.armed {
            self.retirement.fail_stop();
        }
    }
}

struct RouteSetupExecutionContext<P, L> {
    local: L,
    retirement: RetirementSink<P>,
    helper_call_timeout: Duration,
}

impl<P, L: Clone> Clone for RouteSetupExecutionContext<P, L> {
    fn clone(&self) -> Self {
        Self {
            local: self.local.clone(),
            retirement: self.retirement.clone(),
            helper_call_timeout: self.helper_call_timeout,
        }
    }
}

impl<P, L> RouteSetupExecutionContext<P, L>
where
    P: ClientReservationProtocol,
    L: LocalRouteBackend,
{
    fn helper_deadline(&self, setup_deadline: Instant) -> Instant {
        setup_deadline.min(Instant::now() + self.helper_call_timeout)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the owned settlement ticket receives every exact cleanup authority explicitly"
    )]
    fn prepare_ticket(
        &self,
        request: PrepareLeaseBatch,
        reservation: retirement::RetirementReservation<P>,
        protocol: P,
        reservation_id: [u8; ID_BYTES],
        route_context_id: [u8; ID_BYTES],
        setup_deadline: Instant,
        reconciliation_not_before: Instant,
    ) -> oneshot::Receiver<PrepareTicketSettlement<P>> {
        let (sender, receiver) = oneshot::channel();
        let mut local = self.local.clone();
        let retirement = self.retirement.clone();
        let helper_deadline = self.helper_deadline(setup_deadline);
        tokio::spawn(async move {
            let mut guard = HelperTicketGuard::new(retirement.clone());
            let mut call = Box::pin(local.prepare(&request));
            let (prepared, mut deadline_violated) = tokio::select! {
                biased;
                () = tokio::time::sleep_until(helper_deadline) => {
                    retirement.fail_stop();
                    (call.await, true)
                }
                result = &mut call => (result, false),
            };
            if !deadline_violated && Instant::now() >= helper_deadline {
                retirement.fail_stop();
                deadline_violated = true;
            }
            let settlement = match prepared {
                Err(LocalPrepareFailure::Definitive(_error)) => PrepareTicketSettlement::Failed(
                    RouteSetupError::LocalBackend(RouteSetupPhase::Preparing),
                ),
                Err(LocalPrepareFailure::Ambiguous {
                    source: _error,
                    authority,
                }) => {
                    let owner = reservation.bind_ambiguous_prepare(
                        authority,
                        protocol,
                        reservation_id,
                        reconciliation_not_before,
                    );
                    PrepareTicketSettlement::OwnedFailure(
                        owner,
                        RouteSetupError::LocalBackend(RouteSetupPhase::Preparing),
                    )
                }
                Ok(prepared) => {
                    if prepared.prepare().route_context_id.as_slice() != route_context_id
                        || HelperContextHandle::try_from(
                            prepared.prepared().context_handle.as_slice(),
                        )
                        .is_err()
                    {
                        retirement.fail_stop();
                        std::mem::forget((reservation, protocol));
                        let _ = sender.send(PrepareTicketSettlement::Failed(
                            RouteSetupError::HelperCorrelation,
                        ));
                        guard.disarm();
                        return;
                    }
                    let endpoints =
                        bind_prepared_endpoint_leases(&request, prepared.prepared().clone())
                            .map_err(|_| RouteSetupError::HelperCorrelation);
                    let mut owner = reservation.bind(prepared, protocol, reservation_id);
                    match endpoints {
                        Ok(endpoints) => {
                            if endpoints.client_leases().len() != request.leases.len()
                                || owner.attach_endpoints(endpoints).is_err()
                            {
                                PrepareTicketSettlement::OwnedFailure(
                                    owner,
                                    RouteSetupError::HelperCorrelation,
                                )
                            } else if deadline_violated {
                                PrepareTicketSettlement::OwnedFailure(
                                    owner,
                                    RouteSetupError::CallTimeout(RouteSetupPhase::Preparing),
                                )
                            } else {
                                PrepareTicketSettlement::Prepared(owner)
                            }
                        }
                        Err(_) => PrepareTicketSettlement::OwnedFailure(
                            owner,
                            RouteSetupError::HelperCorrelation,
                        ),
                    }
                }
            };
            let _ = sender.send(settlement);
            guard.disarm();
        });
        receiver
    }

    fn activate_ticket(
        &self,
        runtime_owner: Arc<Mutex<RuntimeBoundPreparedLeaseBatch>>,
        request: ActivateLeaseBatch,
        setup_deadline: Instant,
    ) -> oneshot::Receiver<Result<ActivatedLeaseBatch, RouteSetupError>> {
        let (sender, receiver) = oneshot::channel();
        let mut local = self.local.clone();
        let retirement = self.retirement.clone();
        let helper_deadline = self.helper_deadline(setup_deadline);
        tokio::spawn(async move {
            let mut guard = HelperTicketGuard::new(retirement.clone());
            let mut runtime_owner = runtime_owner.lock().await;
            let mut call = Box::pin(local.activate(&mut runtime_owner, &request));
            let (result, mut deadline_violated) = tokio::select! {
                biased;
                () = tokio::time::sleep_until(helper_deadline) => {
                    retirement.fail_stop();
                    (call.await, true)
                }
                result = &mut call => (result, false),
            };
            if !deadline_violated && Instant::now() >= helper_deadline {
                retirement.fail_stop();
                deadline_violated = true;
            }
            let settled = if deadline_violated {
                Err(RouteSetupError::CallTimeout(RouteSetupPhase::Activating))
            } else {
                result.map_err(|_| RouteSetupError::LocalBackend(RouteSetupPhase::Activating))
            };
            let _ = sender.send(settled);
            guard.disarm();
        });
        receiver
    }

    fn commit_ticket(
        &self,
        runtime_owner: Arc<Mutex<RuntimeBoundPreparedLeaseBatch>>,
        request: CommitLeaseBatch,
        setup_deadline: Instant,
    ) -> oneshot::Receiver<Result<CommittedLeaseBatch, RouteSetupError>> {
        let (sender, receiver) = oneshot::channel();
        let mut local = self.local.clone();
        let retirement = self.retirement.clone();
        let helper_deadline = self.helper_deadline(setup_deadline);
        tokio::spawn(async move {
            let mut guard = HelperTicketGuard::new(retirement.clone());
            let mut runtime_owner = runtime_owner.lock().await;
            let mut call = Box::pin(local.commit(&mut runtime_owner, &request));
            let (result, mut deadline_violated) = tokio::select! {
                biased;
                () = tokio::time::sleep_until(helper_deadline) => {
                    retirement.fail_stop();
                    (call.await, true)
                }
                result = &mut call => (result, false),
            };
            if !deadline_violated && Instant::now() >= helper_deadline {
                retirement.fail_stop();
                deadline_violated = true;
            }
            let settled = if deadline_violated {
                Err(RouteSetupError::CallTimeout(RouteSetupPhase::Committing))
            } else {
                result.map_err(|_| RouteSetupError::LocalBackend(RouteSetupPhase::Committing))
            };
            let _ = sender.send(settled);
            guard.disarm();
        });
        receiver
    }
}

struct RouteSetupManager<P, L> {
    context: RouteSetupExecutionContext<P, L>,
    retirement: RetirementSupervisor<P>,
}

/// Callable production owner for route setup and bounded helper-context retirement.
///
/// Connect supplies one already validated affine `PreProbeContinuation`; this orchestrator owns
/// the real discovery/reservation/helper lifecycle without interpreting command input.
pub(crate) struct ProductionRouteOrchestrator {
    manager: RouteSetupManager<ReservationSession, HelperClient>,
}

/// One cancellable production route attempt.
#[must_use = "a production route attempt must be awaited or cancelled"]
pub(crate) struct ProductionRouteAttempt {
    handle: RouteSetupHandle<ReservationSession>,
}

/// Affine owner of one established production route.
///
/// Dropping this value delegates Destroy-first retirement to the existing owner RAII. Prefer
/// `disconnect` to wait for the exact cleanup result.
#[must_use = "an established route must remain owned until disconnect"]
pub(crate) struct ProductionRoute {
    established: EstablishedRoute<ReservationSession>,
    expiry: ClientRouteExpiry,
}

/// A committed one-relay UDP route with its helper-owned Client socket adopted but not yet
/// connected. The only missing input is the public Exit certificate whose signed digest is
/// already retained in `native_authorization`.
#[must_use = "a prepared UDP route must be activated or disconnected"]
pub(crate) struct PreparedProductionUdpRoute {
    // Field order is intentional: an ordinary Drop closes the socket before the route owner can
    // schedule helper Destroy for the namespace.
    transport: CommittedQuicUdpTransport,
    path: VerifiedSingleRelayPath,
    route: ProductionRoute,
}

/// A prepared route whose exact Exit certificate has been matched to the signed reservation.
#[must_use = "a certificate-bound UDP route must be activated or disconnected"]
pub(crate) struct CertificateBoundProductionUdpRoute {
    prepared: PreparedProductionUdpRoute,
    client_config: quinn::ClientConfig,
    target: ProtectedExitUdpTarget,
    server_name: String,
}

/// Active QUIC-DATAGRAM Client association and its still-owned helper route.
#[must_use = "an active UDP route must remain owned until shutdown"]
pub(crate) struct ActiveProductionUdpRoute {
    // Field order is intentional for the same socket-before-namespace Drop barrier.
    client: SingleRelayUdpClient,
    route: ProductionRoute,
    return_path: Option<ClientUdpReturnPath>,
}

#[derive(Clone, Copy)]
struct ClientUdpReturnPath {
    application: SocketAddr,
    remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionUdpRouteError {
    #[error("committed route is not one exact single-relay UDP route")]
    InvalidRoute,
    #[error("committed Client UDP socket handoff failed")]
    HelperSocket,
    #[error("Exit certificate does not match the signed native route identity")]
    ExitCertificate,
    #[error("exact committed Exit UDP session start failed")]
    SessionStart,
    #[error("single-relay UDP association activation failed")]
    Association,
    #[error("single-relay UDP route cleanup remains pending")]
    CleanupPending,
}

struct ProductionUdpPreparationFailure {
    route: ProductionRoute,
    cause: ProductionUdpRouteError,
}

struct ProductionUdpCertificateFailure {
    prepared: PreparedProductionUdpRoute,
    cause: ProductionUdpRouteError,
}

struct ProductionUdpSessionFailure {
    prepared: PreparedProductionUdpRoute,
    cause: ProductionUdpRouteError,
}

struct ProductionUdpActivationFailure {
    route: ProductionRoute,
    cause: ProductionUdpRouteError,
}

/// Compact failure returned to the Connect/runtime seam.
#[derive(Debug, Error)]
pub(crate) enum ProductionRouteError {
    /// A real native-process preflight identity has not yet crossed the production boundary.
    #[error("production native transport identity is unavailable")]
    NativeTransportIdentityUnavailable,
    /// Setup failed; `cleanup_pending` means retirement remains quarantined and owned.
    #[error("production route setup failed")]
    Setup {
        /// Whether exact helper cleanup remains pending in the retirement worker.
        cleanup_pending: bool,
    },
    /// Exact Destroy is still quarantined and owned for retry.
    #[error("production route cleanup remains pending")]
    CleanupPending,
    /// The route orchestrator or its retirement worker was unavailable.
    #[error("production route orchestrator is unavailable")]
    Unavailable,
}

impl ProductionRouteError {
    /// Whether helper-side state remains owned for retry.
    #[must_use]
    pub(crate) const fn cleanup_pending(&self) -> bool {
        matches!(
            self,
            Self::Setup {
                cleanup_pending: true
            } | Self::CleanupPending
        )
    }
}

impl ProductionRouteOrchestrator {
    /// Start the long-lived production route and retirement owner.
    pub(crate) fn start(helper: HelperClient) -> Result<Self, ProductionRouteError> {
        RouteSetupManager::start(
            helper,
            MAXIMUM_RETIREMENT_OWNERS,
            MAXIMUM_CALL_DURATION,
            MAXIMUM_CALL_DURATION,
        )
        .map(|manager| Self { manager })
        .map_err(|_| ProductionRouteError::Unavailable)
    }

    /// Start one real selected route attempt over the existing discovery actor.
    pub(crate) fn connect(
        &self,
        selected: PreProbeContinuation,
        discovery: DiscoveryControlHandle,
    ) -> ProductionRouteAttempt {
        ProductionRouteAttempt {
            handle: self
                .manager
                .spawn_preprobe(selected, discovery, SystemRouteSetupClock),
        }
    }

    /// Report whether this orchestrator still owns helper-side network state.
    #[must_use]
    pub(crate) fn has_network_state(&self) -> bool {
        self.manager.has_network_state()
    }

    /// Stop only after all established or quarantined route owners settle.
    pub(crate) async fn shutdown(self) -> Result<(), ProductionRouteError> {
        self.manager
            .shutdown()
            .await
            .map_err(|_| ProductionRouteError::Unavailable)
    }

    /// Let the retirement supervisor finish quarantined cleanup without delaying a failed Connect
    /// response. The spawned owner keeps retrying exact Destroy until the helper confirms it.
    fn shutdown_detached(self) {
        self.manager.shutdown_detached();
    }
}

impl ProductionRouteAttempt {
    /// Request cancellation; the owned task still waits for any dispatched helper phase to settle.
    pub(crate) fn cancel(&self) {
        self.handle.cancel();
    }

    /// Wait for an established affine route owner or fully classified cleanup failure.
    pub(crate) async fn wait(self) -> Result<ProductionRoute, ProductionRouteError> {
        self.handle
            .wait()
            .await
            .map(|established| {
                let expiry = ClientRouteExpiry::from_hard_expiry(
                    established.request.parameters.hard_expires_at_unix,
                    crate::unix_millis(),
                    Instant::now(),
                );
                ProductionRoute {
                    established,
                    expiry,
                }
            })
            .map_err(|failure| {
                tracing::warn!(
                    error = %failure.cause,
                    cleanup_pending = failure.cleanup == CleanupStatus::Quarantined,
                    "production route setup failed before transport activation"
                );
                if failure.cause == RouteSetupError::NativeRouteScopeUnavailable {
                    ProductionRouteError::NativeTransportIdentityUnavailable
                } else {
                    ProductionRouteError::Setup {
                        cleanup_pending: failure.cleanup == CleanupStatus::Quarantined,
                    }
                }
            })
    }
}

impl ProductionRoute {
    /// Borrow the selected active path IDs without exposing helper handles.
    #[must_use]
    pub(crate) fn active_path_ids(&self) -> &[u32] {
        &self.established.active_path_ids
    }

    /// Borrow the selected warm path IDs without exposing helper handles.
    #[must_use]
    pub(crate) fn warm_path_ids(&self) -> &[u32] {
        &self.established.warm_path_ids
    }

    /// Exact single transport admitted by the signed reservation.
    #[must_use]
    pub(crate) fn selected_transport(&self) -> Option<Transport> {
        let [transport] = self
            .established
            .request
            .parameters
            .allowed_transports
            .as_slice()
        else {
            return None;
        };
        Some(*transport)
    }

    /// Opaque helper context handle for transport descriptor acquisition.
    #[must_use]
    pub(crate) fn context_handle(&self) -> &[u8] {
        &self.established.commit_proof.context_handle
    }

    fn committed_mpquic_identity(
        &self,
    ) -> Result<CommittedMpquicRouteIdentity, ClientRouteConnectError> {
        let path_count = self.established.relay_grants.len();
        if self.selected_transport() != Some(Transport::MultipathQuic)
            || !(2..=usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)).contains(&path_count)
            || self.established.relay_authorities.len() != path_count
        {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let route_context_id = self.established.request.parameters.route_context_id;
        let mut paths = Vec::with_capacity(path_count);
        let mut path_ids = BTreeSet::new();
        let mut relay_peers = BTreeSet::new();
        for (grant, authority) in self
            .established
            .relay_grants
            .iter()
            .zip(&self.established.relay_authorities)
        {
            let path_id = grant.path_id();
            let relay_peer_id = authority.peer_id.to_string();
            if grant.route_context_id() != &route_context_id
                || grant.relay_node_id() != &authority.node_id
                || !path_ids.insert(path_id)
                || !relay_peers.insert(relay_peer_id.clone())
            {
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            }
            paths.push(CommittedMpquicPathIdentity {
                path_id,
                relay_peer_id,
            });
        }
        paths.sort_unstable_by_key(|path| path.path_id);
        Ok(CommittedMpquicRouteIdentity {
            route_context_id,
            exit_peer_id: self.established.request.exit.peer_id.to_string(),
            paths,
        })
    }

    /// Whether an authenticated Exit listener signal belongs to this committed path set.
    #[must_use]
    pub(crate) fn accepts_mptcp_listener(&self, signal: &ExitMptcpListenerSignal) -> bool {
        let expected_paths = self
            .established
            .relay_grants
            .iter()
            .map(ReservationSession::grant_path_id)
            .collect::<BTreeSet<_>>();
        signal.route_context_id() == self.established.request.parameters.route_context_id
            && expected_paths.len() == self.established.relay_grants.len()
            && expected_paths
                .iter()
                .copied()
                .eq(signal.selected_path_ids().iter().copied())
    }

    /// Consume an exact committed UDP route and acquire its Client QUIC descriptor from helper.
    ///
    /// The descriptor is bound only to the canonical Client overlay address of the sole selected
    /// Relay path. It remains explicitly unconnected, so this step cannot create a direct
    /// Client-to-Exit underlay path.
    async fn prepare_single_relay_udp(
        self,
        helper: &HelperClient,
        now_ms: u64,
    ) -> Result<PreparedProductionUdpRoute, ProductionUdpPreparationFailure> {
        let path = match verified_single_relay_udp_path(&self.established, now_ms) {
            Ok(path) => path,
            Err(cause) => return Err(ProductionUdpPreparationFailure { route: self, cause }),
        };
        let request = match client_udp_socket_request(&self.established, &path) {
            Ok(request) => request,
            Err(cause) => return Err(ProductionUdpPreparationFailure { route: self, cause }),
        };
        let Ok(acquired) = helper.acquire_transport_socket(request).await else {
            return Err(ProductionUdpPreparationFailure {
                route: self,
                cause: ProductionUdpRouteError::HelperSocket,
            });
        };
        let (descriptor, metadata) = acquired.into_parts();
        let Ok(transport) = CommittedQuicUdpTransport::from_helper_handoff(
            descriptor,
            &metadata,
            &path,
            CommittedUdpRole::Client,
        ) else {
            return Err(ProductionUdpPreparationFailure {
                route: self,
                cause: ProductionUdpRouteError::HelperSocket,
            });
        };
        Ok(PreparedProductionUdpRoute {
            transport,
            path,
            route: self,
        })
    }

    /// Run exact Destroy-first teardown and wait for its retirement result.
    pub(crate) async fn disconnect(self) -> Result<(), ProductionRouteError> {
        match self.established.teardown().await {
            RetirementOutcome::Destroyed { .. } => Ok(()),
            RetirementOutcome::Quarantined => Err(ProductionRouteError::CleanupPending),
        }
    }
}

impl PreparedProductionUdpRoute {
    /// Commit the exact selected data Relay and bind the Exit's authenticated readiness signal.
    async fn start_exit_session(
        self,
        discovery: &DiscoveryControlHandle,
        now_ms: u64,
    ) -> Result<CertificateBoundProductionUdpRoute, ProductionUdpSessionFailure> {
        let dispatch =
            match udp_session_start_dispatch(&self.route.established, &self.path, false, now_ms) {
                Ok(dispatch) => dispatch,
                Err(cause) => {
                    return Err(ProductionUdpSessionFailure {
                        prepared: self,
                        cause,
                    });
                }
            };
        let Ok(response) = discovery
            .request_datapath_relay(dispatch.relay.peer_id, dispatch.request.clone())
            .await
        else {
            return Err(ProductionUdpSessionFailure {
                prepared: self,
                cause: ProductionUdpRouteError::SessionStart,
            });
        };
        let Ok(encoded_signal) = accepted_datapath_response(
            &dispatch.request,
            &response,
            &dispatch.relay,
            RouteSetupPhase::Committing,
        ) else {
            return Err(ProductionUdpSessionFailure {
                prepared: self,
                cause: ProductionUdpRouteError::SessionStart,
            });
        };
        let local_signal = match verified_udp_exit_session_signal(&encoded_signal, &self.path) {
            Ok(signal) => signal,
            Err(cause) => {
                return Err(ProductionUdpSessionFailure {
                    prepared: self,
                    cause,
                });
            }
        };
        self.bind_exit_session_signal(&local_signal)
            .map_err(|failure| ProductionUdpSessionFailure {
                prepared: failure.prepared,
                cause: failure.cause,
            })
    }

    /// Bind the public Exit certificate to the exact digest and TLS name signed into this route.
    ///
    /// The Exit port is fixed inside the protected overlay namespace. A successful QUIC handshake
    /// is therefore the readiness signal; an unready or substituted Exit cannot yield an active
    /// owner.
    fn bind_exit_session_signal(
        self,
        signal: &DiscoveryUdpExitSessionSignal,
    ) -> Result<CertificateBoundProductionUdpRoute, ProductionUdpCertificateFailure> {
        let certificate_der = signal.certificate_der().to_vec();
        let Some(authorization) = self.route.established.native_authorization.as_ref() else {
            return Err(ProductionUdpCertificateFailure {
                prepared: self,
                cause: ProductionUdpRouteError::ExitCertificate,
            });
        };
        let identity = authorization.native_route_identity();
        let expected_certificate_sha256 = identity.certificate_sha256.clone();
        let server_name = identity.tls_server_name.clone();
        let digest = Sha256::digest(&certificate_der);
        if expected_certificate_sha256.len() != digest.len()
            || digest
                .as_slice()
                .ct_eq(expected_certificate_sha256.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(ProductionUdpCertificateFailure {
                prepared: self,
                cause: ProductionUdpRouteError::ExitCertificate,
            });
        }
        let certificate = CertificateDer::from(certificate_der);
        let mut roots = RootCertStore::empty();
        if roots.add(certificate).is_err() {
            return Err(ProductionUdpCertificateFailure {
                prepared: self,
                cause: ProductionUdpRouteError::ExitCertificate,
            });
        }
        let Ok(client_config) = quinn::ClientConfig::with_root_certificates(Arc::new(roots)) else {
            return Err(ProductionUdpCertificateFailure {
                prepared: self,
                cause: ProductionUdpRouteError::ExitCertificate,
            });
        };
        let Ok(target) = ProtectedExitUdpTarget::new(&self.path, SINGLE_RELAY_UDP_EXIT_PORT) else {
            return Err(ProductionUdpCertificateFailure {
                prepared: self,
                cause: ProductionUdpRouteError::ExitCertificate,
            });
        };
        Ok(CertificateBoundProductionUdpRoute {
            prepared: self,
            client_config,
            target,
            server_name,
        })
    }

    async fn disconnect(self) -> Result<(), ProductionUdpRouteError> {
        let Self {
            route, transport, ..
        } = self;
        drop(transport);
        route
            .disconnect()
            .await
            .map_err(|_| ProductionUdpRouteError::CleanupPending)
    }
}

impl CertificateBoundProductionUdpRoute {
    fn bind_ingress(
        &self,
        ingress: PolicyAuthorizedUdpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ()> {
        let protocol = self
            .prepared
            .route
            .established
            .owner
            .as_ref()
            .and_then(PreparedContextOwner::protocol)
            .ok_or(())?;
        ingress
            .bind_to_route(&self.prepared.path, &protocol.coordinator, policy, now_ms)
            .map_err(|_| ())
    }

    fn bind_dns_ingress(
        &self,
        ingress: PolicyAuthorizedDnsIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ()> {
        let protocol = self
            .prepared
            .route
            .established
            .owner
            .as_ref()
            .and_then(PreparedContextOwner::protocol)
            .ok_or(())?;
        ingress
            .bind_to_route(&self.prepared.path, &protocol.coordinator, policy, now_ms)
            .map_err(|_| ())
    }

    /// Establish the existing single-relay QUIC-DATAGRAM Client over the protected Exit target.
    async fn activate(
        self,
        flow: &AuthorizedUdpFlow,
        signed_authorization: &[u8],
        authorization_timeout: Duration,
        now_ms: u64,
    ) -> Result<ActiveProductionUdpRoute, ProductionUdpActivationFailure> {
        let Self {
            prepared,
            client_config,
            target,
            server_name,
        } = self;
        let PreparedProductionUdpRoute {
            route,
            path,
            transport,
        } = prepared;
        match SingleRelayUdpClient::connect(
            transport,
            target,
            client_config,
            &server_name,
            path,
            flow,
            signed_authorization,
            authorization_timeout,
            now_ms,
        )
        .await
        {
            Ok(client) => Ok(ActiveProductionUdpRoute {
                client,
                route,
                return_path: None,
            }),
            Err(_error) => Err(ProductionUdpActivationFailure {
                route,
                cause: ProductionUdpRouteError::Association,
            }),
        }
    }

    async fn disconnect(self) -> Result<(), ProductionUdpRouteError> {
        self.prepared.disconnect().await
    }
}

impl ActiveProductionUdpRoute {
    async fn shutdown(self) -> Result<(), ProductionUdpRouteError> {
        let Self {
            route,
            client,
            return_path: _,
        } = self;
        client.shutdown().await;
        route
            .disconnect()
            .await
            .map_err(|_| ProductionUdpRouteError::CleanupPending)
    }
}

fn verified_single_relay_udp_path(
    route: &EstablishedRoute<ReservationSession>,
    now_ms: u64,
) -> Result<VerifiedSingleRelayPath, ProductionUdpRouteError> {
    let [path_id] = route.active_path_ids.as_slice() else {
        return Err(ProductionUdpRouteError::InvalidRoute);
    };
    let [grant] = route.relay_grants.as_slice() else {
        return Err(ProductionUdpRouteError::InvalidRoute);
    };
    if route.request.parameters.allowed_transports != [Transport::UdpSinglePath]
        || !route.warm_path_ids.is_empty()
        || route.commit_proof.leases.len() != 1
        || grant.path_id() != *path_id
        || route.signed_exit_reservation.is_empty()
    {
        return Err(ProductionUdpRouteError::InvalidRoute);
    }
    let mut replay = ReplayCache::new(4).map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let path = VerifiedSingleRelayPath::verify(
        &route.signed_exit_reservation,
        grant.signed_relay_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    if path.reservation_id() != &route.request.parameters.reservation_id
        || path.route_context_id() != &route.request.parameters.route_context_id
        || path.path_id() != *path_id
        || route
            .native_authorization
            .as_ref()
            .is_none_or(|authorization| {
                authorization.reservation_id() != path.reservation_id()
                    || authorization.route_context_id() != path.route_context_id()
            })
    {
        return Err(ProductionUdpRouteError::InvalidRoute);
    }
    Ok(path)
}

fn client_udp_socket_request(
    route: &EstablishedRoute<ReservationSession>,
    path: &VerifiedSingleRelayPath,
) -> Result<AcquireTransportSocket, ProductionUdpRouteError> {
    committed_quic_udp_socket_request(
        &route.commit_proof.context_handle,
        path,
        CommittedUdpRole::Client,
        CLIENT_SINGLE_RELAY_UDP_PORT,
    )
    .map_err(|_| ProductionUdpRouteError::InvalidRoute)
}

struct UdpSessionStartDispatch {
    relay: DirectRelayCapability,
    request: DatapathRelayRequest,
}

fn udp_session_start_dispatch(
    route: &EstablishedRoute<ReservationSession>,
    path: &VerifiedSingleRelayPath,
    native_connect_ip: bool,
    now_ms: u64,
) -> Result<UdpSessionStartDispatch, ProductionUdpRouteError> {
    let [grant] = route.relay_grants.as_slice() else {
        return Err(ProductionUdpRouteError::InvalidRoute);
    };
    let [relay] = route.relay_authorities.as_slice() else {
        return Err(ProductionUdpRouteError::InvalidRoute);
    };
    let [confirmation] = route.confirmations.as_slice() else {
        return Err(ProductionUdpRouteError::InvalidRoute);
    };
    if ReservationSession::grant_path_id(grant) != path.path_id()
        || relay.node_id != *path.relay_node_id()
    {
        return Err(ProductionUdpRouteError::InvalidRoute);
    }
    let signed_credential_delivery = if native_connect_ip {
        let authorization = route
            .native_authorization
            .as_ref()
            .ok_or(ProductionUdpRouteError::InvalidRoute)?;
        let protocol = route
            .owner
            .as_ref()
            .and_then(PreparedContextOwner::protocol)
            .ok_or(ProductionUdpRouteError::InvalidRoute)?;
        protocol
            .coordinator
            .sign_native_route_credential_delivery(authorization, now_ms)
            .map_err(|_| ProductionUdpRouteError::InvalidRoute)?
    } else {
        Vec::new()
    };
    let start = UdpSessionStartRequest::new(
        route.signed_exit_reservation.clone(),
        ReservationSession::signed_relay_reservation(grant).to_vec(),
        confirmation.signed_confirmation.clone(),
        confirmation.signed_receipt.clone(),
        signed_credential_delivery,
    )
    .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let confirmation_envelope = decode_canonical::<SignedEnvelope>(
        &confirmation.signed_confirmation,
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let receipt_envelope =
        decode_canonical::<SignedEnvelope>(&confirmation.signed_receipt, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let request_id: [u8; ID_BYTES] = confirmation_envelope
        .nonce
        .get(..ID_BYTES)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; ID_BYTES]| value.iter().any(|byte| *byte != 0))
        .ok_or(ProductionUdpRouteError::InvalidRoute)?;
    let call_ms = u64::try_from(DATAPATH_RELAY_REQUEST_TIMEOUT.as_millis())
        .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let deadline_unix_ms = now_ms
        .checked_add(call_ms)
        .ok_or(ProductionUdpRouteError::InvalidRoute)?
        .min(path.expires_at_ms())
        .min(confirmation_envelope.expires_at_ms)
        .min(receipt_envelope.expires_at_ms);
    if deadline_unix_ms <= now_ms {
        return Err(ProductionUdpRouteError::InvalidRoute);
    }
    let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    let request = DatapathRelayRequest::new(
        request_id.to_vec(),
        relay.node_id.to_vec(),
        relay.peer_id.to_bytes(),
        deadline_unix_ms,
        DatapathRelayOperation::UdpSessionStart,
        encoded,
        Vec::new(),
    )
    .map_err(|_| ProductionUdpRouteError::InvalidRoute)?;
    Ok(UdpSessionStartDispatch {
        relay: relay.clone(),
        request,
    })
}

fn verified_udp_exit_session_signal(
    encoded: &[u8],
    path: &VerifiedSingleRelayPath,
) -> Result<DiscoveryUdpExitSessionSignal, ProductionUdpRouteError> {
    let signal =
        decode_canonical::<DiscoveryUdpExitSessionSignal>(encoded, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| ProductionUdpRouteError::SessionStart)?;
    if signal.validate().is_err()
        || signal.reservation_id() != path.reservation_id()
        || signal.route_context_id() != path.route_context_id()
        || signal.path_id() != path.path_id()
        || signal.exit_native_instance_id().len() != 32
        || signal
            .exit_native_instance_id()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(ProductionUdpRouteError::SessionStart);
    }
    Ok(signal)
}

/// Commit the sole data Relay and obtain the native Exit readiness bound to that exact path.
async fn start_native_udp_exit_session(
    route: &ProductionRoute,
    path: &VerifiedSingleRelayPath,
    discovery: &DiscoveryControlHandle,
    now_ms: u64,
) -> Result<DiscoveryUdpExitSessionSignal, ProductionUdpRouteError> {
    let dispatch = udp_session_start_dispatch(&route.established, path, true, now_ms)?;
    let response = discovery
        .request_datapath_relay(dispatch.relay.peer_id, dispatch.request.clone())
        .await
        .map_err(|_| ProductionUdpRouteError::SessionStart)?;
    let encoded_signal = accepted_datapath_response(
        &dispatch.request,
        &response,
        &dispatch.relay,
        RouteSetupPhase::Committing,
    )
    .map_err(|_| ProductionUdpRouteError::SessionStart)?;
    verified_udp_exit_session_signal(&encoded_signal, path)
}

struct MptcpSessionStartDispatch {
    relay: DirectRelayCapability,
    request: DatapathRelayRequest,
}

/// Commit every finalized data Relay concurrently, then require one byte-identical Exit signal.
///
/// Dispatch must be concurrent: the Exit deliberately withholds readiness until every Relay in
/// the canonical proof set has committed and arrived. No request targets the Exit directly.
async fn start_mptcp_exit_session(
    route: &ProductionRoute,
    discovery: &DiscoveryControlHandle,
    now_ms: u64,
) -> Result<ExitMptcpListenerSignal, ClientRouteConnectError> {
    let dispatches = mptcp_session_start_dispatches(&route.established, now_ms)
        .map_err(|()| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
    let expected_responses = dispatches.len();
    let mut tasks = tokio::task::JoinSet::new();
    for dispatch in dispatches {
        let discovery = discovery.clone();
        tasks.spawn(async move {
            let response = discovery
                .request_datapath_relay(dispatch.relay.peer_id, dispatch.request.clone())
                .await;
            (dispatch, response)
        });
    }

    let mut canonical_signal = None;
    let mut received = 0_usize;
    while let Some(joined) = tasks.join_next().await {
        let (dispatch, response) =
            joined.map_err(|_| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
        let response =
            response.map_err(|_| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
        let encoded = accepted_datapath_response(
            &dispatch.request,
            &response,
            &dispatch.relay,
            RouteSetupPhase::Committing,
        )
        .map_err(|_| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
        if canonical_signal
            .as_ref()
            .is_some_and(|first: &Vec<u8>| first != &encoded)
        {
            return Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable);
        }
        canonical_signal.get_or_insert(encoded);
        received = received.saturating_add(1);
    }
    if received != expected_responses {
        return Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable);
    }
    verified_mptcp_exit_session_signal(
        canonical_signal
            .as_deref()
            .ok_or(ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?,
        &route.established,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one fail-atomic exact-set validation and byte-identical dispatch construction"
)]
fn mptcp_session_start_dispatches(
    route: &EstablishedRoute<ReservationSession>,
    now_ms: u64,
) -> Result<Vec<MptcpSessionStartDispatch>, ()> {
    let path_count = route.relay_grants.len();
    if route.request.parameters.allowed_transports != [Transport::TcpMptcp]
        || !(2..=usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)).contains(&path_count)
        || route.relay_authorities.len() != path_count
        || route.confirmations.len() != path_count
        || route.commit_proof.leases.len() != path_count
        || route.signed_exit_reservation.is_empty()
        || route.active_path_ids.len() < 2
    {
        return Err(());
    }

    let mut selected_path_ids = route
        .active_path_ids
        .iter()
        .chain(&route.warm_path_ids)
        .copied()
        .collect::<Vec<_>>();
    selected_path_ids.sort_unstable();
    if selected_path_ids.len() != path_count
        || selected_path_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(());
    }

    let mut indexes = (0..path_count).collect::<Vec<_>>();
    indexes.sort_unstable_by_key(|index| route.relay_grants[*index].path_id());
    let grant_path_ids = indexes
        .iter()
        .map(|index| route.relay_grants[*index].path_id())
        .collect::<Vec<_>>();
    if grant_path_ids != selected_path_ids {
        return Err(());
    }

    let exit_envelope = decode_canonical::<SignedEnvelope>(
        &route.signed_exit_reservation,
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .map_err(|_| ())?;
    let mut proofs = Vec::with_capacity(path_count);
    let mut wrappers = Vec::with_capacity(path_count);
    let mut request_ids = BTreeSet::new();
    for index in indexes {
        let grant = &route.relay_grants[index];
        let relay = &route.relay_authorities[index];
        let confirmation = &route.confirmations[index];
        if grant.relay_node_id() != &relay.node_id {
            return Err(());
        }
        let confirmation_envelope = decode_canonical::<SignedEnvelope>(
            &confirmation.signed_confirmation,
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .map_err(|_| ())?;
        let receipt_envelope = decode_canonical::<SignedEnvelope>(
            &confirmation.signed_receipt,
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .map_err(|_| ())?;
        let request_id: [u8; ID_BYTES] = confirmation_envelope
            .nonce
            .get(..ID_BYTES)
            .and_then(|value| value.try_into().ok())
            .filter(|value: &[u8; ID_BYTES]| value.iter().any(|byte| *byte != 0))
            .ok_or(())?;
        if !request_ids.insert(request_id) {
            return Err(());
        }
        let call_ms = u64::try_from(DATAPATH_RELAY_REQUEST_TIMEOUT.as_millis()).map_err(|_| ())?;
        let deadline_unix_ms = now_ms
            .checked_add(call_ms)
            .ok_or(())?
            .min(route.request.parameters.expires_at_ms)
            .min(grant.expires_at_ms())
            .min(exit_envelope.expires_at_ms)
            .min(confirmation_envelope.expires_at_ms)
            .min(receipt_envelope.expires_at_ms);
        if deadline_unix_ms <= now_ms {
            return Err(());
        }
        proofs.push(MptcpSessionPathProof::new(
            grant.signed_relay_reservation().to_vec(),
            confirmation.signed_confirmation.clone(),
            confirmation.signed_receipt.clone(),
        ));
        wrappers.push((relay.clone(), request_id, deadline_unix_ms));
    }

    let start = MptcpSessionStartRequest::new(route.signed_exit_reservation.clone(), proofs)
        .map_err(|_| ())?;
    let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE).map_err(|_| ())?;
    wrappers
        .into_iter()
        .map(|(relay, request_id, deadline_unix_ms)| {
            let request = DatapathRelayRequest::new(
                request_id.to_vec(),
                relay.node_id.to_vec(),
                relay.peer_id.to_bytes(),
                deadline_unix_ms,
                DatapathRelayOperation::MptcpSessionStart,
                encoded.clone(),
                Vec::new(),
            )
            .map_err(|_| ())?;
            Ok(MptcpSessionStartDispatch { relay, request })
        })
        .collect()
}

fn verified_mptcp_exit_session_signal(
    encoded: &[u8],
    route: &EstablishedRoute<ReservationSession>,
) -> Result<ExitMptcpListenerSignal, ClientRouteConnectError> {
    let signal =
        decode_canonical::<DiscoveryExitMptcpSessionSignal>(encoded, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?;
    let mut selected_path_ids = route
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::path_id)
        .collect::<Vec<_>>();
    selected_path_ids.sort_unstable();
    if signal.validate().is_err()
        || signal.reservation_id() != route.request.parameters.reservation_id
        || signal.route_context_id() != route.request.parameters.route_context_id
        || signal.selected_path_ids() != selected_path_ids
    {
        return Err(ClientRouteConnectError::MptcpExitListenerSignalUnavailable);
    }
    ExitMptcpListenerSignal::try_from_discovery(
        &signal,
        &route
            .native_authorization
            .as_ref()
            .ok_or(ClientRouteConnectError::MptcpExitListenerSignalUnavailable)?
            .native_route_identity()
            .certificate_sha256,
    )
    .map_err(|_| ClientRouteConnectError::MptcpExitListenerSignalUnavailable)
}

struct MpquicSessionStartDispatch {
    relay: DirectRelayCapability,
    request: DatapathRelayRequest,
}

/// Commit the complete selected Relay set concurrently and accept only one byte-identical native
/// Exit readiness signal. Every copy carries the same Client-signed HPKE credential delivery; no
/// request or native socket ever targets an Exit underlay address directly.
async fn start_mpquic_exit_session(
    route: &ProductionRoute,
    discovery: &DiscoveryControlHandle,
    now_ms: u64,
) -> Result<ExitMpquicSessionSignal, ClientRouteConnectError> {
    let dispatches = mpquic_session_start_dispatches(&route.established, now_ms)
        .map_err(|()| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let expected_responses = dispatches.len();
    let mut tasks = tokio::task::JoinSet::new();
    for dispatch in dispatches {
        let discovery = discovery.clone();
        tasks.spawn(async move {
            let response = discovery
                .request_datapath_relay(dispatch.relay.peer_id, dispatch.request.clone())
                .await;
            (dispatch, response)
        });
    }

    let mut canonical_signal = None;
    let mut received = 0_usize;
    while let Some(joined) = tasks.join_next().await {
        let (dispatch, response) =
            joined.map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let response =
            response.map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        let encoded = accepted_datapath_response(
            &dispatch.request,
            &response,
            &dispatch.relay,
            RouteSetupPhase::Committing,
        )
        .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        if canonical_signal
            .as_ref()
            .is_some_and(|first: &Vec<u8>| first != &encoded)
        {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        canonical_signal.get_or_insert(encoded);
        received = received.saturating_add(1);
    }
    if received != expected_responses {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    verified_mpquic_exit_session_signal(
        canonical_signal
            .as_deref()
            .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?,
        &route.established,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one fail-atomic exact-set proof and opaque-credential dispatch construction"
)]
fn mpquic_session_start_dispatches(
    route: &EstablishedRoute<ReservationSession>,
    now_ms: u64,
) -> Result<Vec<MpquicSessionStartDispatch>, ()> {
    let path_count = route.relay_grants.len();
    if route.request.parameters.allowed_transports != [Transport::MultipathQuic]
        || !(2..=usize::try_from(MAX_HELPER_PATHS).unwrap_or(8)).contains(&path_count)
        || route.relay_authorities.len() != path_count
        || route.confirmations.len() != path_count
        || route.commit_proof.leases.len() != path_count
        || route.signed_exit_reservation.is_empty()
        || route.active_path_ids.len() < 2
    {
        return Err(());
    }

    let authorization = route.native_authorization.as_ref().ok_or(())?;
    if authorization.reservation_id() != &route.request.parameters.reservation_id
        || authorization.route_context_id() != &route.request.parameters.route_context_id
        || authorization.expires_at_ms() <= now_ms
    {
        return Err(());
    }
    let protocol = route
        .owner
        .as_ref()
        .and_then(PreparedContextOwner::protocol)
        .ok_or(())?;
    let signed_credential_delivery = protocol
        .coordinator
        .sign_native_route_credential_delivery(authorization, now_ms)
        .map_err(|_| ())?;

    let mut selected_path_ids = route
        .active_path_ids
        .iter()
        .chain(&route.warm_path_ids)
        .copied()
        .collect::<Vec<_>>();
    selected_path_ids.sort_unstable();
    if selected_path_ids.len() != path_count
        || selected_path_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(());
    }

    let mut indexes = (0..path_count).collect::<Vec<_>>();
    indexes.sort_unstable_by_key(|index| route.relay_grants[*index].path_id());
    let grant_path_ids = indexes
        .iter()
        .map(|index| route.relay_grants[*index].path_id())
        .collect::<Vec<_>>();
    if grant_path_ids != selected_path_ids {
        return Err(());
    }

    let exit_envelope = decode_canonical::<SignedEnvelope>(
        &route.signed_exit_reservation,
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .map_err(|_| ())?;
    let mut proofs = Vec::with_capacity(path_count);
    let mut wrappers = Vec::with_capacity(path_count);
    let mut request_ids = BTreeSet::new();
    for index in indexes {
        let grant = &route.relay_grants[index];
        let relay = &route.relay_authorities[index];
        let confirmation = &route.confirmations[index];
        if grant.relay_node_id() != &relay.node_id {
            return Err(());
        }
        let confirmation_envelope = decode_canonical::<SignedEnvelope>(
            &confirmation.signed_confirmation,
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .map_err(|_| ())?;
        let receipt_envelope = decode_canonical::<SignedEnvelope>(
            &confirmation.signed_receipt,
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .map_err(|_| ())?;
        let request_id: [u8; ID_BYTES] = confirmation_envelope
            .nonce
            .get(..ID_BYTES)
            .and_then(|value| value.try_into().ok())
            .filter(|value: &[u8; ID_BYTES]| value.iter().any(|byte| *byte != 0))
            .ok_or(())?;
        if !request_ids.insert(request_id) {
            return Err(());
        }
        let call_ms = u64::try_from(DATAPATH_RELAY_REQUEST_TIMEOUT.as_millis()).map_err(|_| ())?;
        let deadline_unix_ms = now_ms
            .checked_add(call_ms)
            .ok_or(())?
            .min(route.request.parameters.expires_at_ms)
            .min(grant.expires_at_ms())
            .min(exit_envelope.expires_at_ms)
            .min(confirmation_envelope.expires_at_ms)
            .min(receipt_envelope.expires_at_ms);
        if deadline_unix_ms <= now_ms {
            return Err(());
        }
        proofs.push(MpquicSessionPathProof::new(
            grant.signed_relay_reservation().to_vec(),
            confirmation.signed_confirmation.clone(),
            confirmation.signed_receipt.clone(),
        ));
        wrappers.push((relay.clone(), request_id, deadline_unix_ms));
    }

    let start = MpquicSessionStartRequest::new(
        route.signed_exit_reservation.clone(),
        proofs,
        signed_credential_delivery,
    )
    .map_err(|_| ())?;
    let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE).map_err(|_| ())?;
    wrappers
        .into_iter()
        .map(|(relay, request_id, deadline_unix_ms)| {
            let request = DatapathRelayRequest::new(
                request_id.to_vec(),
                relay.node_id.to_vec(),
                relay.peer_id.to_bytes(),
                deadline_unix_ms,
                DatapathRelayOperation::MpquicSessionStart,
                encoded.clone(),
                Vec::new(),
            )
            .map_err(|_| ())?;
            Ok(MpquicSessionStartDispatch { relay, request })
        })
        .collect()
}

fn verified_mpquic_exit_session_signal(
    encoded: &[u8],
    route: &EstablishedRoute<ReservationSession>,
) -> Result<ExitMpquicSessionSignal, ClientRouteConnectError> {
    let signal = decode_canonical::<ExitMpquicSessionSignal>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
    let mut selected_path_ids = route
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::path_id)
        .collect::<Vec<_>>();
    selected_path_ids.sort_unstable();
    let authorization = route
        .native_authorization
        .as_ref()
        .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
    if signal.validate().is_err()
        || signal.reservation_id() != route.request.parameters.reservation_id
        || signal.route_context_id() != route.request.parameters.route_context_id
        || signal.exit_native_instance_id()
            != authorization
                .native_route_identity()
                .exit_native_instance_id
        || signal.selected_path_ids() != selected_path_ids
    {
        return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
    }
    Ok(signal)
}

impl<P, L> RouteSetupManager<P, L>
where
    P: ClientReservationProtocol,
    L: LocalRouteBackend,
{
    fn start(
        local: L,
        retirement_capacity: usize,
        destroy_timeout: Duration,
        helper_call_timeout: Duration,
    ) -> Result<Self, RouteSetupError> {
        if helper_call_timeout.is_zero() || helper_call_timeout > MAXIMUM_CALL_DURATION {
            return Err(RouteSetupError::Invalid("helper call timeout"));
        }
        let retirement =
            RetirementSupervisor::start(local.clone(), retirement_capacity, destroy_timeout)
                .map_err(|()| RouteSetupError::RetirementUnavailable)?;
        let context = RouteSetupExecutionContext {
            local,
            retirement: retirement.sink(),
            helper_call_timeout,
        };
        Ok(Self {
            context,
            retirement,
        })
    }

    fn has_network_state(&self) -> bool {
        self.retirement.state().outstanding() != 0
    }

    async fn shutdown(self) -> Result<(), RouteSetupError> {
        let Self {
            context,
            retirement,
        } = self;
        drop(context);
        retirement
            .shutdown()
            .await
            .map_err(|()| RouteSetupError::SupervisorStopped)
    }

    /// Begin shutdown while retaining every retirement owner in a detached task.
    fn shutdown_detached(self) {
        drop(tokio::spawn(async move {
            if self.shutdown().await.is_err() {
                tracing::warn!("detached route retirement supervisor stopped unexpectedly");
            }
        }));
    }

    fn spawn_owned<F, Fut>(&self, operation: F) -> RouteSetupHandle<P>
    where
        F: FnOnce(RouteSetupExecutionContext<P, L>, watch::Receiver<bool>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<EstablishedRoute<P>, RouteSetupFailure>> + Send + 'static,
    {
        let context = self.context.clone();
        let (cancel, cancellation) = watch::channel(false);
        let (result_sender, result) = oneshot::channel();
        tokio::spawn(async move {
            let outcome = operation(context, cancellation).await;
            let _ = result_sender.send(outcome);
        });
        RouteSetupHandle {
            cancel,
            result: Some(result),
        }
    }

    fn spawn<R, C>(
        &self,
        unmeasured: UnmeasuredRouteSetup<P>,
        transport: R,
        clock: C,
    ) -> RouteSetupHandle<P>
    where
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        self.spawn_owned(move |context, cancellation| {
            unmeasured.execute_owned(context, transport, clock, cancellation)
        })
    }

    #[cfg(test)]
    fn retirement_state(&self) -> &Arc<retirement::RetirementState> {
        self.retirement.state()
    }

    #[cfg(test)]
    fn retirement_sink(&self) -> RetirementSink<P> {
        self.retirement.sink()
    }

    #[cfg(test)]
    fn terminate_retirement_worker_for_test(&self) {
        self.retirement.terminate_worker_for_test();
    }
}

async fn await_prepare_ticket<P>(
    mut receiver: oneshot::Receiver<PrepareTicketSettlement<P>>,
    deadline: Instant,
    cancellation: &mut watch::Receiver<bool>,
) -> Result<(PrepareTicketSettlement<P>, Option<RouteSetupError>), RouteSetupError> {
    let deferred_error = tokio::select! {
        biased;
        () = tokio::time::sleep_until(deadline) => {
            RouteSetupError::Deadline(RouteSetupPhase::Preparing)
        }
        () = wait_for_cancellation(cancellation) => RouteSetupError::Cancelled,
        result = &mut receiver => {
            let settlement = result.map_err(|_| RouteSetupError::SupervisorStopped)?;
            if Instant::now() >= deadline {
                return Ok((
                    settlement,
                    Some(RouteSetupError::Deadline(RouteSetupPhase::Preparing)),
                ));
            }
            return Ok((settlement, None));
        }
    };
    let settlement = receiver
        .await
        .map_err(|_| RouteSetupError::SupervisorStopped)?;
    Ok((settlement, Some(deferred_error)))
}

async fn await_helper_ticket<T>(
    mut receiver: oneshot::Receiver<Result<T, RouteSetupError>>,
    deadline: Instant,
    cancellation: &mut watch::Receiver<bool>,
    phase: RouteSetupPhase,
) -> Result<T, RouteSetupError> {
    let deferred_error = tokio::select! {
        biased;
        () = tokio::time::sleep_until(deadline) => RouteSetupError::Deadline(phase),
        () = wait_for_cancellation(cancellation) => RouteSetupError::Cancelled,
        result = &mut receiver => {
            let settled = result.map_err(|_| RouteSetupError::SupervisorStopped)?;
            if Instant::now() >= deadline {
                drop(settled);
                return Err(RouteSetupError::Deadline(phase));
            }
            return settled;
        }
    };
    let settled = receiver
        .await
        .map_err(|_| RouteSetupError::SupervisorStopped)?;
    drop(settled);
    Err(deferred_error)
}

struct VerifiedRouteMeasurement<P: ClientReservationProtocol> {
    intent: ExitReservationIntent,
    hold: P::Hold,
    selected_paths: Vec<SelectedRouteSetupPath>,
    selected_probes: Vec<P::Probe>,
    active_path_ids: Vec<u32>,
    warm_path_ids: Vec<u32>,
    active_path_count: usize,
}

struct UnmeasuredRouteSetup<P: ClientReservationProtocol> {
    transaction: RouteSetupTransaction<P>,
    deadline: Instant,
}

struct MeasuredRouteSetup<P: ClientReservationProtocol> {
    transaction: RouteSetupTransaction<P>,
    measurement: VerifiedRouteMeasurement<P>,
    deadline: Instant,
}

struct InterruptedRouteSetup<P: ClientReservationProtocol> {
    transaction: RouteSetupTransaction<P>,
    cause: RouteSetupError,
}

struct RouteSetupTransaction<P> {
    request: RouteSetupRequest,
    authorities: RouteSetupAuthorities,
    limits: RouteSetupLimits,
    protocol: Option<P>,
    phase: RouteSetupPhase,
    prepared: Option<PreparedContextOwner<P>>,
    remote_grants_possible: bool,
}

impl<P: ClientReservationProtocol> RouteSetupTransaction<P> {
    fn with_protocol_and_deadline(
        request: RouteSetupRequest,
        authorities: RouteSetupAuthorities,
        limits: RouteSetupLimits,
        protocol: P,
        deadline: Instant,
    ) -> Result<UnmeasuredRouteSetup<P>, RouteSetupError> {
        let maximum_deadline = Instant::now()
            .checked_add(limits.setup_timeout)
            .ok_or(RouteSetupError::Invalid("setup deadline"))?;
        if deadline > maximum_deadline {
            return Err(RouteSetupError::Invalid("setup deadline"));
        }
        authorities.validate(&request)?;
        Ok(UnmeasuredRouteSetup {
            transaction: Self {
                request,
                authorities,
                limits,
                protocol: Some(protocol),
                phase: RouteSetupPhase::Validated,
                prepared: None,
                remote_grants_possible: false,
            },
            deadline,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "measurement keeps the hold, permits, probes and canonical selection in one order"
    )]
    async fn measure_inner<R, C>(
        &mut self,
        transport: &mut R,
        clock: &C,
        cancellation: &mut watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<VerifiedRouteMeasurement<P>, RouteSetupError>
    where
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        self.ensure_live(clock, cancellation, deadline)?;
        let intent = self.request.exit_intent(&self.authorities)?;
        let transport_kind = *self
            .request
            .parameters
            .allowed_transports
            .first()
            .ok_or(RouteSetupError::Invalid("transport"))?;
        let probe_address_family = self.request.parameters.probe_address_family;

        self.phase = RouteSetupPhase::CapacityHold;
        let signed_hold = self.protocol_mut()?.sign_hold(&intent)?;
        let hold_rpc = exit_forward_request(
            &self.authorities,
            ExitForwardOperation::CapacityHold,
            signed_hold,
            intent.hold_expires_at_ms,
        )?;
        self.remote_grants_possible = true;
        let hold_response = retry_exit_forward(
            transport,
            &self.authorities.control,
            &hold_rpc,
            self.limits,
            deadline,
            cancellation,
            self.phase,
        )
        .await?;
        let signed_hold_response = accepted_exit_response(
            &hold_rpc,
            &hold_response,
            &self.authorities.exit,
            self.phase,
        )?;
        self.ensure_live(clock, cancellation, deadline)?;
        let authenticated_exit = self.authorities.exit.exit_peer_id.to_bytes();
        let hold = self.protocol_mut()?.verify_hold(
            &intent,
            signed_hold_response,
            &authenticated_exit,
            clock.unix_millis(),
        )?;

        self.phase = RouteSetupPhase::ProbePermits;
        let mut issued = Vec::with_capacity(self.request.paths.len());
        for index in 0..self.request.paths.len() {
            self.ensure_live(clock, cancellation, deadline)?;
            let relay_intent = {
                let path = &self.request.paths[index];
                path.proof.relay_intent(path.path_id)
            };
            let now_ms = clock.unix_millis();
            let expires_at_ms = bounded_phase_expiry(now_ms, intent.hold_expires_at_ms)?;
            let probe_request = self.protocol_mut()?.sign_probe_request(
                &hold,
                &relay_intent,
                transport_kind,
                probe_address_family,
                now_ms,
                expires_at_ms,
            )?;
            let rpc = exit_forward_request(
                &self.authorities,
                ExitForwardOperation::ProbePermit,
                P::probe_request_bytes(&probe_request).to_vec(),
                expires_at_ms,
            )?;
            let response = retry_exit_forward(
                transport,
                &self.authorities.control,
                &rpc,
                self.limits,
                deadline,
                cancellation,
                self.phase,
            )
            .await?;
            let mut signed =
                accepted_exit_response(&rpc, &response, &self.authorities.exit, self.phase)?;
            let signed_permit = signed
                .pop()
                .ok_or(RouteSetupError::ReservationProtocol(self.phase))?;
            if !signed.is_empty() {
                return Err(RouteSetupError::ReservationProtocol(self.phase));
            }
            let permit = self.protocol_mut()?.verify_probe_permit(
                &probe_request,
                signed_permit,
                clock.unix_millis(),
            )?;
            issued.push(IssuedProbe {
                path_id: relay_intent.path_id,
                request: probe_request,
                permit,
                expires_at_ms,
            });
        }

        self.phase = RouteSetupPhase::ExecuteProbes;
        let mut verified_probes = Vec::with_capacity(issued.len());
        for issued_probe in issued {
            self.ensure_live(clock, cancellation, deadline)?;
            let relay = self
                .authorities
                .relay_for_path(issued_probe.path_id)
                .ok_or(RouteSetupError::Capability)?;
            // The outer datapath wrapper is part of the exact signed-request scope. Reuse the
            // expiry signed into this probe request instead of deriving a later value.
            let expires_at_ms = issued_probe.expires_at_ms;
            let rpc = datapath_request(
                relay,
                DatapathRelayOperation::ExecuteProbe,
                P::probe_request_bytes(&issued_probe.request).to_vec(),
                P::probe_permit_bytes(&issued_probe.permit).to_vec(),
                expires_at_ms,
            )?;
            let response = retry_datapath(
                transport,
                relay,
                &rpc,
                self.limits,
                deadline,
                cancellation,
                self.phase,
            )
            .await?;
            let signed_result = accepted_datapath_response(&rpc, &response, relay, self.phase)?;
            let probe = self.protocol_mut()?.verify_probe_result(
                issued_probe.permit,
                signed_result,
                clock.unix_millis(),
            )?;
            verified_probes.push((issued_probe.path_id, probe));
        }
        let selected =
            select_verified_probe_subset::<P>(&self.request, verified_probes, clock.unix_millis())?;
        let active_path_ids = selected.active_path_ids();
        let warm_path_ids = selected.warm_path_ids();
        let active_path_count = selected.active.len();
        let selected = selected.into_sorted();
        let selected_path_ids = selected
            .iter()
            .map(|candidate| candidate.path_id)
            .collect::<BTreeSet<_>>();
        if selected_path_ids.len() != selected.len()
            || selected_path_ids.iter().any(|path_id| {
                !self
                    .request
                    .paths
                    .iter()
                    .any(|path| path.path_id == *path_id)
            })
        {
            return Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::ExecuteProbes,
            ));
        }
        let selected_probes = selected
            .into_iter()
            .map(|candidate| candidate.probe)
            .collect::<Vec<_>>();
        let selected_paths = std::mem::take(&mut self.request.paths)
            .into_iter()
            .filter(|path| selected_path_ids.contains(&path.path_id))
            .map(|path| path.proof.into_selected(path.path_id))
            .collect::<Vec<_>>();

        Ok(VerifiedRouteMeasurement {
            intent,
            hold,
            selected_paths,
            selected_probes,
            active_path_ids,
            warm_path_ids,
            active_path_count,
        })
    }
}

impl<P: ClientReservationProtocol> UnmeasuredRouteSetup<P> {
    async fn execute_owned<L, R, C>(
        self,
        context: RouteSetupExecutionContext<P, L>,
        mut transport: R,
        clock: C,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<EstablishedRoute<P>, RouteSetupFailure>
    where
        L: LocalRouteBackend,
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        let measured = match self
            .measure_owned(&mut transport, &clock, &mut cancellation)
            .await
        {
            Ok(measured) => measured,
            Err(InterruptedRouteSetup { transaction, cause }) => {
                return Err(transaction.rollback(cause).await);
            }
        };
        measured
            .finish_owned(context, &mut transport, &clock, &mut cancellation)
            .await
    }

    async fn measure_owned<R, C>(
        self,
        transport: &mut R,
        clock: &C,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<MeasuredRouteSetup<P>, InterruptedRouteSetup<P>>
    where
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        let Self {
            mut transaction,
            deadline,
        } = self;
        match transaction
            .measure_inner(transport, clock, cancellation, deadline)
            .await
        {
            Ok(measurement) => Ok(MeasuredRouteSetup {
                transaction,
                measurement,
                deadline,
            }),
            Err(cause) => Err(InterruptedRouteSetup { transaction, cause }),
        }
    }
}

impl<P: ClientReservationProtocol> RouteSetupTransaction<P> {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the measured continuation retains the explicit fail-closed finish phase order"
    )]
    async fn finish_inner<L, R, C>(
        &mut self,
        context: &RouteSetupExecutionContext<P, L>,
        transport: &mut R,
        clock: &C,
        cancellation: &mut watch::Receiver<bool>,
        deadline: Instant,
        measurement: VerifiedRouteMeasurement<P>,
    ) -> Result<ExecutionProof<P::RelayGrant, P::NativeAuthorization>, RouteSetupError>
    where
        L: LocalRouteBackend,
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        let VerifiedRouteMeasurement {
            intent,
            hold,
            selected_paths,
            selected_probes,
            active_path_ids,
            warm_path_ids,
            active_path_count,
        } = measurement;
        self.ensure_live(clock, cancellation, deadline)?;
        let authenticated_exit = self.authorities.exit.exit_peer_id.to_bytes();

        self.phase = RouteSetupPhase::RetirementSlot;
        let retirement_reservation = bounded_call(
            deadline,
            self.limits.call_timeout,
            cancellation,
            self.phase,
            context.retirement.reserve(),
        )
        .await?
        .map_err(|()| RouteSetupError::RetirementUnavailable)?;
        self.ensure_live(clock, cancellation, deadline)?;

        self.phase = RouteSetupPhase::Preparing;
        let traversal_bindings = selected_paths
            .iter()
            .map(|path| EndpointTraversalBinding {
                path_id: path.path_id,
                role: WireguardRole::Client,
                observer_id: path.relay.identity.wire_node_id,
                observer_peer_id: path.relay.identity.peer_id,
            })
            .collect();
        let traversal_hints = match bounded_call(
            deadline,
            self.limits.call_timeout,
            cancellation,
            self.phase,
            transport.endpoint_traversal_hints(traversal_bindings),
        )
        .await
        {
            Ok(Ok(hints)) => hints,
            // A direct public underlay remains independently usable; the helper decides whether
            // absent observations are fatal only after checking IPv6 and public IPv4 first.
            Ok(Err(_)) | Err(_) => Vec::new(),
        };
        let prepare_request =
            self.request
                .prepare_request(&selected_paths, active_path_count, traversal_hints);
        let protocol = self
            .protocol
            .take()
            .ok_or(RouteSetupError::ReservationProtocol(self.phase))?;
        let setup_expiry_ms = self
            .request
            .parameters
            .setup_expires_at_unix
            .checked_mul(1_000)
            .ok_or(RouteSetupError::Invalid("setup expiry"))?;
        let reconciliation_delay_ms = setup_expiry_ms
            .checked_sub(clock.unix_millis())
            .ok_or(RouteSetupError::Expired)?;
        let reconciliation_not_before =
            Instant::now() + Duration::from_millis(reconciliation_delay_ms);
        let ticket = context.prepare_ticket(
            prepare_request,
            retirement_reservation,
            protocol,
            self.request.parameters.reservation_id,
            self.request.parameters.route_context_id,
            deadline,
            reconciliation_not_before,
        );
        let (settlement, deferred_error) =
            await_prepare_ticket(ticket, deadline, cancellation).await?;
        match settlement {
            PrepareTicketSettlement::Prepared(owner) => {
                self.prepared = Some(owner);
                if let Some(error) = deferred_error {
                    return Err(error);
                }
            }
            PrepareTicketSettlement::OwnedFailure(owner, error) => {
                self.prepared = Some(owner);
                return Err(deferred_error.unwrap_or(error));
            }
            PrepareTicketSettlement::Failed(error) => {
                return Err(deferred_error.unwrap_or(error));
            }
        }
        self.ensure_live(clock, cancellation, deadline)?;

        self.phase = RouteSetupPhase::Finalizing;
        let now_ms = clock.unix_millis();
        let expires_at_ms = bounded_phase_expiry(now_ms, intent.hold_expires_at_ms)?;
        let finalize = {
            let (protocol, endpoints) = self
                .prepared
                .as_mut()
                .and_then(PreparedContextOwner::protocol_and_endpoints_mut)
                .ok_or(RouteSetupError::HelperCorrelation)?;
            protocol.sign_finalize(
                &intent,
                &hold,
                &selected_probes,
                now_ms,
                expires_at_ms,
                endpoints,
            )?
        };
        let finalize_rpc = exit_forward_request(
            &self.authorities,
            ExitForwardOperation::FinalizeReservation,
            P::finalize_request_bytes(&finalize).to_vec(),
            expires_at_ms,
        )?;
        let finalize_response = retry_exit_forward(
            transport,
            &self.authorities.control,
            &finalize_rpc,
            self.limits,
            deadline,
            cancellation,
            self.phase,
        )
        .await?;
        let signed_finalize = accepted_exit_response(
            &finalize_rpc,
            &finalize_response,
            &self.authorities.exit,
            self.phase,
        )?;
        let finalized = self
            .prepared
            .as_mut()
            .and_then(PreparedContextOwner::protocol_mut)
            .ok_or(RouteSetupError::HelperCorrelation)?
            .verify_finalize(
                &intent,
                &hold,
                &finalize,
                signed_finalize,
                &authenticated_exit,
                clock.unix_millis(),
            )?;
        if P::exit_bundle_path_count(&finalized) != selected_paths.len() {
            return Err(RouteSetupError::ReservationProtocol(self.phase));
        }

        self.phase = RouteSetupPhase::RelayReservations;
        let mut grants = Vec::with_capacity(selected_paths.len());
        let mut relay_authorities = Vec::with_capacity(selected_paths.len());
        for (path_index, path) in selected_paths.iter().enumerate() {
            self.ensure_live(clock, cancellation, deadline)?;
            let relay = self
                .authorities
                .relay_for_path(path.path_id)
                .ok_or(RouteSetupError::Capability)?;
            let now_ms = clock.unix_millis();
            let expires_at_ms =
                bounded_phase_expiry(now_ms, self.request.parameters.expires_at_ms)?;
            let signed = self
                .prepared
                .as_mut()
                .and_then(PreparedContextOwner::protocol_mut)
                .ok_or(RouteSetupError::HelperCorrelation)?
                .sign_relay_request(&finalized, path_index, now_ms, expires_at_ms)?;
            let rpc = datapath_request(
                relay,
                DatapathRelayOperation::ReservePath,
                signed,
                Vec::new(),
                expires_at_ms,
            )?;
            let response = retry_datapath(
                transport,
                relay,
                &rpc,
                self.limits,
                deadline,
                cancellation,
                self.phase,
            )
            .await?;
            let signed_relay = accepted_datapath_response(&rpc, &response, relay, self.phase)?;
            let grant = self
                .prepared
                .as_mut()
                .and_then(PreparedContextOwner::protocol_mut)
                .ok_or(RouteSetupError::HelperCorrelation)?
                .verify_relay_response(
                    &finalized,
                    signed_relay,
                    path_index,
                    path,
                    clock.unix_millis(),
                )?;
            if P::grant_path_id(&grant) != path.path_id {
                return Err(RouteSetupError::ReservationProtocol(self.phase));
            }
            grants.push(grant);
            relay_authorities.push(relay.clone());
        }

        self.phase = RouteSetupPhase::ExitConfirmations;
        let mut confirmations = Vec::with_capacity(grants.len());
        for grant in &grants {
            self.ensure_live(clock, cancellation, deadline)?;
            let now_ms = clock.unix_millis();
            // ConfirmRelay still crosses the request-bounded control-to-Exit forwarding
            // capability. Its wrapper may authorize the long reservation, but must itself remain
            // inside the short setup/hold authority just like every earlier Exit setup phase.
            let expires_at_ms = bounded_phase_expiry(now_ms, intent.hold_expires_at_ms)?;
            let signed_confirmation = self
                .prepared
                .as_mut()
                .and_then(PreparedContextOwner::protocol_mut)
                .ok_or(RouteSetupError::HelperCorrelation)?
                .sign_confirmation(grant, now_ms, expires_at_ms)?;
            let rpc = exit_forward_request(
                &self.authorities,
                ExitForwardOperation::ConfirmRelay,
                signed_confirmation.clone(),
                expires_at_ms,
            )?;
            let response = retry_exit_forward(
                transport,
                &self.authorities.control,
                &rpc,
                self.limits,
                deadline,
                cancellation,
                self.phase,
            )
            .await?;
            let mut signed_receipts =
                accepted_exit_response(&rpc, &response, &self.authorities.exit, self.phase)?;
            let signed_receipt = signed_receipts
                .pop()
                .ok_or(RouteSetupError::ReservationProtocol(self.phase))?;
            if !signed_receipts.is_empty() {
                return Err(RouteSetupError::ReservationProtocol(self.phase));
            }
            self.prepared
                .as_mut()
                .and_then(PreparedContextOwner::protocol_mut)
                .ok_or(RouteSetupError::HelperCorrelation)?
                .verify_confirmation_receipt(
                    grant,
                    &signed_confirmation,
                    &signed_receipt,
                    clock.unix_millis(),
                )?;
            confirmations.push(RelayConfirmationProof {
                signed_confirmation,
                signed_receipt,
            });
        }

        let signed_exit_reservation = P::signed_exit_reservation(&finalized).to_vec();
        if signed_exit_reservation.is_empty() {
            return Err(RouteSetupError::ReservationProtocol(self.phase));
        }
        let native_authorization = self
            .prepared
            .as_mut()
            .and_then(PreparedContextOwner::protocol_mut)
            .ok_or(RouteSetupError::HelperCorrelation)?
            .take_native_route_authorization(&finalize, clock.unix_millis())?;

        self.ensure_live(clock, cancellation, deadline)?;
        self.phase = RouteSetupPhase::Activating;
        let runtime_owner = self
            .prepared
            .as_ref()
            .and_then(PreparedContextOwner::runtime_owner)
            .ok_or(RouteSetupError::HelperCorrelation)?;
        let activation = activation_request::<P>(
            self.request.parameters.route_context_id,
            self.prepared
                .as_ref()
                .and_then(PreparedContextOwner::endpoints)
                .ok_or(RouteSetupError::HelperCorrelation)?,
            &grants,
        )?;
        let activated = await_helper_ticket(
            context.activate_ticket(runtime_owner, activation.clone(), deadline),
            deadline,
            cancellation,
            self.phase,
        )
        .await?;
        validate_activated(&activation, &activated)?;
        self.ensure_live(clock, cancellation, deadline)?;

        self.phase = RouteSetupPhase::Committing;
        let commit_request = commit_request(&activation);
        let runtime_owner = self
            .prepared
            .as_ref()
            .and_then(PreparedContextOwner::runtime_owner)
            .ok_or(RouteSetupError::HelperCorrelation)?;
        let committed = await_helper_ticket(
            context.commit_ticket(runtime_owner, commit_request.clone(), deadline),
            deadline,
            cancellation,
            self.phase,
        )
        .await?;
        validate_committed(&commit_request, &committed)?;
        self.ensure_live(clock, cancellation, deadline)?;
        Ok(ExecutionProof {
            grants,
            relay_authorities,
            confirmations,
            active_path_ids,
            warm_path_ids,
            commit: committed,
            signed_exit_reservation,
            native_authorization,
        })
    }

    fn protocol_mut(&mut self) -> Result<&mut P, RouteSetupError> {
        self.protocol
            .as_mut()
            .ok_or(RouteSetupError::ReservationProtocol(self.phase))
    }

    fn ensure_live<C: RouteSetupClock>(
        &self,
        clock: &C,
        cancellation: &watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<(), RouteSetupError> {
        if *cancellation.borrow() {
            return Err(RouteSetupError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(RouteSetupError::Deadline(self.phase));
        }
        let now_ms = clock.unix_millis();
        if now_ms < self.request.parameters.created_at_ms {
            return Err(RouteSetupError::Invalid("clock before request"));
        }
        if now_ms >= self.request.parameters.expires_at_ms
            || now_ms / 1_000 >= self.request.parameters.setup_expires_at_unix
        {
            return Err(RouteSetupError::Expired);
        }
        Ok(())
    }

    async fn rollback(mut self, cause: RouteSetupError) -> RouteSetupFailure {
        self.phase = RouteSetupPhase::Retiring;
        let outcome = match self.prepared.take() {
            Some(owner) => Some(owner.retire().await),
            None => None,
        };
        let (cleanup, released_local_leases) = match outcome {
            None => (CleanupStatus::NotRequired, 0),
            Some(RetirementOutcome::Destroyed {
                released_local_leases,
            }) => (CleanupStatus::Destroyed, released_local_leases),
            Some(RetirementOutcome::Quarantined) => (CleanupStatus::Quarantined, 0),
        };
        RouteSetupFailure {
            cause,
            cleanup,
            released_local_leases,
            remote_grants_expire_only: self.remote_grants_possible,
        }
    }
}

impl<P: ClientReservationProtocol> MeasuredRouteSetup<P> {
    async fn finish_owned<L, R, C>(
        self,
        context: RouteSetupExecutionContext<P, L>,
        transport: &mut R,
        clock: &C,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<EstablishedRoute<P>, RouteSetupFailure>
    where
        L: LocalRouteBackend,
        R: ReservationTransport,
        C: RouteSetupClock,
    {
        let Self {
            mut transaction,
            measurement,
            deadline,
        } = self;
        match transaction
            .finish_inner(
                &context,
                transport,
                clock,
                cancellation,
                deadline,
                measurement,
            )
            .await
        {
            Ok(proof) => Ok(EstablishedRoute {
                owner: transaction.prepared.take(),
                request: transaction.request,
                relay_grants: proof.grants,
                relay_authorities: proof.relay_authorities,
                confirmations: proof.confirmations,
                active_path_ids: proof.active_path_ids,
                warm_path_ids: proof.warm_path_ids,
                commit_proof: proof.commit,
                signed_exit_reservation: proof.signed_exit_reservation,
                native_authorization: Some(proof.native_authorization),
            }),
            Err(cause) => Err(transaction.rollback(cause).await),
        }
    }
}

struct ExecutionProof<G, A> {
    grants: Vec<G>,
    relay_authorities: Vec<DirectRelayCapability>,
    confirmations: Vec<RelayConfirmationProof>,
    active_path_ids: Vec<u32>,
    warm_path_ids: Vec<u32>,
    commit: CommittedLeaseBatch,
    signed_exit_reservation: Vec<u8>,
    native_authorization: A,
}

struct RelayConfirmationProof {
    signed_confirmation: Vec<u8>,
    signed_receipt: Vec<u8>,
}

struct EstablishedRoute<P: ClientReservationProtocol> {
    owner: Option<PreparedContextOwner<P>>,
    request: RouteSetupRequest,
    relay_grants: Vec<P::RelayGrant>,
    relay_authorities: Vec<DirectRelayCapability>,
    confirmations: Vec<RelayConfirmationProof>,
    active_path_ids: Vec<u32>,
    warm_path_ids: Vec<u32>,
    commit_proof: CommittedLeaseBatch,
    signed_exit_reservation: Vec<u8>,
    native_authorization: Option<P::NativeAuthorization>,
}

impl<P: ClientReservationProtocol> EstablishedRoute<P> {
    async fn teardown(mut self) -> RetirementOutcome {
        self.owner
            .take()
            .expect("established route owns prepared context")
            .retire()
            .await
    }
}

impl<P: ClientReservationProtocol> fmt::Debug for EstablishedRoute<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EstablishedRoute")
            .field("prospective_paths", &self.request.paths.len())
            .field("relay_grants", &self.relay_grants.len())
            .field("active_paths", &self.active_path_ids.len())
            .field("warm_paths", &self.warm_path_ids.len())
            .field("commit_proofs", &self.commit_proof.leases.len())
            .finish_non_exhaustive()
    }
}

struct RouteSetupHandle<P: ClientReservationProtocol> {
    cancel: watch::Sender<bool>,
    result: Option<oneshot::Receiver<Result<EstablishedRoute<P>, RouteSetupFailure>>>,
}

impl<P: ClientReservationProtocol> RouteSetupHandle<P> {
    fn cancel(&self) {
        let _ = self.cancel.send(true);
    }

    async fn wait(mut self) -> Result<EstablishedRoute<P>, RouteSetupFailure> {
        let response = self
            .result
            .take()
            .expect("route setup handle is single-use")
            .await;
        match response {
            Ok(result) => result,
            Err(_) => Err(RouteSetupFailure {
                cause: RouteSetupError::SupervisorStopped,
                cleanup: CleanupStatus::Quarantined,
                released_local_leases: 0,
                remote_grants_expire_only: true,
            }),
        }
    }
}

impl<P: ClientReservationProtocol> Drop for RouteSetupHandle<P> {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
    }
}

enum RouteAttemptState<P: ClientReservationProtocol> {
    Vacant,
    Pending(RouteSetupHandle<P>),
    Established(EstablishedRoute<P>),
    Settling,
    Quarantined,
}

struct RouteAttemptOwner<P: ClientReservationProtocol> {
    state: RouteAttemptState<P>,
}

struct FailedRouteAttempt<P: ClientReservationProtocol> {
    owner: RouteAttemptOwner<P>,
    failure: RouteSetupFailure,
}

enum RouteAttemptSettlement<P: ClientReservationProtocol> {
    Established(RouteAttemptOwner<P>),
    Failed(FailedRouteAttempt<P>),
    NotPending(RouteAttemptOwner<P>),
}

enum RouteAttemptDrain {
    Vacant,
    Failed(RouteSetupFailure),
    Retired(RetirementOutcome),
    Quarantined,
}

impl<P: ClientReservationProtocol> RouteAttemptOwner<P> {
    fn vacant() -> Self {
        Self {
            state: RouteAttemptState::Vacant,
        }
    }

    fn adopt(&mut self, handle: RouteSetupHandle<P>) -> Result<(), RouteSetupHandle<P>> {
        if !matches!(self.state, RouteAttemptState::Vacant) {
            return Err(handle);
        }
        self.state = RouteAttemptState::Pending(handle);
        Ok(())
    }

    fn adopt_established(&mut self, route: EstablishedRoute<P>) -> Result<(), EstablishedRoute<P>> {
        if !matches!(self.state, RouteAttemptState::Vacant) {
            return Err(route);
        }
        self.state = RouteAttemptState::Established(route);
        Ok(())
    }

    async fn settle(mut self) -> RouteAttemptSettlement<P> {
        let state = std::mem::replace(&mut self.state, RouteAttemptState::Settling);
        let RouteAttemptState::Pending(handle) = state else {
            self.state = state;
            return RouteAttemptSettlement::NotPending(self);
        };
        match handle.wait().await {
            Ok(route) => {
                self.state = RouteAttemptState::Established(route);
                RouteAttemptSettlement::Established(self)
            }
            Err(failure) => {
                self.state = if failure.cleanup == CleanupStatus::Quarantined {
                    RouteAttemptState::Quarantined
                } else {
                    RouteAttemptState::Vacant
                };
                RouteAttemptSettlement::Failed(FailedRouteAttempt {
                    owner: self,
                    failure,
                })
            }
        }
    }

    async fn drain(mut self) -> RouteAttemptDrain {
        let state = std::mem::replace(&mut self.state, RouteAttemptState::Settling);
        match state {
            RouteAttemptState::Vacant => RouteAttemptDrain::Vacant,
            RouteAttemptState::Pending(handle) => {
                handle.cancel();
                match handle.wait().await {
                    Ok(route) => RouteAttemptDrain::Retired(route.teardown().await),
                    Err(failure) => RouteAttemptDrain::Failed(failure),
                }
            }
            RouteAttemptState::Established(route) => {
                RouteAttemptDrain::Retired(route.teardown().await)
            }
            RouteAttemptState::Settling | RouteAttemptState::Quarantined => {
                RouteAttemptDrain::Quarantined
            }
        }
    }
}

fn bounded_phase_expiry(now_ms: u64, hard_limit_ms: u64) -> Result<u64, RouteSetupError> {
    let expiry = now_ms
        .checked_add(MAXIMUM_PHASE_LIFETIME_MS)
        .ok_or(RouteSetupError::Invalid("phase expiry"))?
        .min(hard_limit_ms);
    if expiry <= now_ms {
        return Err(RouteSetupError::Expired);
    }
    Ok(expiry)
}

fn signed_outer_scope(
    canonical_request: &[u8],
    expected_expiry_ms: u64,
) -> Result<([u8; ID_BYTES], u64), RouteSetupError> {
    let envelope = decode_canonical::<SignedEnvelope>(canonical_request, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::Validated))?;
    if envelope.nonce.len() != 32
        || envelope.expires_at_ms != expected_expiry_ms
        || envelope.expires_at_ms == 0
    {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::Validated,
        ));
    }
    let mut request_id = [0_u8; ID_BYTES];
    request_id.copy_from_slice(&envelope.nonce[..ID_BYTES]);
    if request_id.iter().all(|byte| *byte == 0) {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::Validated,
        ));
    }
    Ok((request_id, envelope.expires_at_ms))
}

fn exit_forward_request(
    authorities: &RouteSetupAuthorities,
    operation: ExitForwardOperation,
    signed_request: Vec<u8>,
    deadline_ms: u64,
) -> Result<ExitForwardRequest, RouteSetupError> {
    let (forward_id, signed_expiry_ms) = signed_outer_scope(&signed_request, deadline_ms)?;
    ExitForwardRequest::new(
        forward_id.to_vec(),
        authorities.control.node_id.to_vec(),
        authorities.control.peer_id.to_bytes(),
        authorities.control.public_key.to_vec(),
        authorities.exit.exit_peer_id.to_bytes(),
        authorities.exit.exit_node_id.to_vec(),
        signed_expiry_ms,
        operation,
        signed_request,
    )
    .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::Validated))
}

fn datapath_request(
    relay: &DirectRelayCapability,
    operation: DatapathRelayOperation,
    client_request: Vec<u8>,
    exit_authorization: Vec<u8>,
    deadline_ms: u64,
) -> Result<DatapathRelayRequest, RouteSetupError> {
    let (request_id, signed_expiry_ms) = signed_outer_scope(&client_request, deadline_ms)?;
    DatapathRelayRequest::new(
        request_id.to_vec(),
        relay.node_id.to_vec(),
        relay.peer_id.to_bytes(),
        signed_expiry_ms,
        operation,
        client_request,
        exit_authorization,
    )
    .map_err(|_| RouteSetupError::ReservationProtocol(RouteSetupPhase::Validated))
}

fn accepted_exit_response(
    request: &ExitForwardRequest,
    response: &ExitForwardResponse,
    exit: &ForwardedExitCapability,
    phase: RouteSetupPhase,
) -> Result<Vec<Vec<u8>>, RouteSetupError> {
    if response.validate().is_err()
        || response.forward_id() != request.forward_id()
        || response.validated_operation() != request.validated_operation()
        || response.exit_node_id() != exit.exit_node_id
        || response.exit_peer_id() != exit.exit_peer_id.to_bytes()
    {
        return Err(RouteSetupError::ReservationProtocol(phase));
    }
    match response
        .validated_status()
        .map_err(|_| RouteSetupError::ReservationProtocol(phase))?
    {
        ForwardStatus::Granted => Ok(response.signed_responses().to_vec()),
        ForwardStatus::Rejected => Err(RouteSetupError::RemoteRejected(phase)),
        ForwardStatus::Unavailable => Err(RouteSetupError::RemoteUnavailable(phase)),
        ForwardStatus::Unspecified => Err(RouteSetupError::ReservationProtocol(phase)),
    }
}

fn accepted_datapath_response(
    request: &DatapathRelayRequest,
    response: &DatapathRelayResponse,
    relay: &DirectRelayCapability,
    phase: RouteSetupPhase,
) -> Result<Vec<u8>, RouteSetupError> {
    if response.validate().is_err()
        || response.request_id() != request.request_id()
        || response.validated_operation() != request.validated_operation()
        || response.relay_node_id() != relay.node_id
        || response.relay_peer_id() != relay.peer_id.to_bytes()
    {
        return Err(RouteSetupError::ReservationProtocol(phase));
    }
    match response
        .validated_status()
        .map_err(|_| RouteSetupError::ReservationProtocol(phase))?
    {
        ForwardStatus::Granted => Ok(response.signed_response().to_vec()),
        ForwardStatus::Rejected => Err(RouteSetupError::RemoteRejected(phase)),
        ForwardStatus::Unavailable => Err(RouteSetupError::RemoteUnavailable(phase)),
        ForwardStatus::Unspecified => Err(RouteSetupError::ReservationProtocol(phase)),
    }
}

async fn retry_exit_forward<R: ReservationTransport>(
    transport: &mut R,
    control: &DirectRelayCapability,
    request: &ExitForwardRequest,
    limits: RouteSetupLimits,
    deadline: Instant,
    cancellation: &mut watch::Receiver<bool>,
    phase: RouteSetupPhase,
) -> Result<ExitForwardResponse, RouteSetupError> {
    for attempt in 1..=limits.maximum_outbound_attempts {
        match bounded_call(
            deadline,
            limits.call_timeout,
            cancellation,
            phase,
            transport.exit_forward(control, request),
        )
        .await
        {
            Ok(response) => match response {
                Ok(value) => return Ok(value),
                Err(error)
                    if R::ambiguous_after_dispatch(&error)
                        && attempt < limits.maximum_outbound_attempts => {}
                Err(_) => return Err(RouteSetupError::Outbound(phase)),
            },
            Err(error) => return Err(error),
        }
    }
    Err(RouteSetupError::Outbound(phase))
}

async fn retry_datapath<R: ReservationTransport>(
    transport: &mut R,
    relay: &DirectRelayCapability,
    request: &DatapathRelayRequest,
    limits: RouteSetupLimits,
    deadline: Instant,
    cancellation: &mut watch::Receiver<bool>,
    phase: RouteSetupPhase,
) -> Result<DatapathRelayResponse, RouteSetupError> {
    for attempt in 1..=limits.maximum_outbound_attempts {
        match bounded_call(
            deadline,
            limits.call_timeout,
            cancellation,
            phase,
            transport.datapath_relay(relay, request),
        )
        .await
        {
            Ok(response) => match response {
                Ok(value) => return Ok(value),
                Err(error)
                    if R::ambiguous_after_dispatch(&error)
                        && attempt < limits.maximum_outbound_attempts => {}
                Err(_) => return Err(RouteSetupError::Outbound(phase)),
            },
            Err(error) => return Err(error),
        }
    }
    Err(RouteSetupError::Outbound(phase))
}

async fn bounded_call<F, T>(
    deadline: Instant,
    call_timeout: Duration,
    cancellation: &mut watch::Receiver<bool>,
    phase: RouteSetupPhase,
    future: F,
) -> Result<T, RouteSetupError>
where
    F: Future<Output = T>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(RouteSetupError::Deadline(phase));
    }
    let budget = remaining.min(call_timeout);
    tokio::select! {
        () = wait_for_cancellation(cancellation) => Err(RouteSetupError::Cancelled),
        result = timeout(budget, future) => match result {
            Ok(value) => Ok(value),
            Err(_) if Instant::now() >= deadline => Err(RouteSetupError::Deadline(phase)),
            Err(_) => Err(RouteSetupError::CallTimeout(phase)),
        }
    }
}

async fn wait_for_cancellation(cancellation: &mut watch::Receiver<bool>) {
    loop {
        if *cancellation.borrow() {
            return;
        }
        if cancellation.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn activation_request<P: ClientReservationProtocol>(
    route_context_id: [u8; ID_BYTES],
    batch: &LocalEndpointLeaseBatch,
    grants: &[P::RelayGrant],
) -> Result<ActivateLeaseBatch, RouteSetupError> {
    if grants.len() != batch.client_leases().len() {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::Activating,
        ));
    }
    let by_path = grants
        .iter()
        .map(|grant| (P::grant_path_id(grant), grant))
        .collect::<BTreeMap<_, _>>();
    if by_path.len() != grants.len() {
        return Err(RouteSetupError::ReservationProtocol(
            RouteSetupPhase::Activating,
        ));
    }
    let mut activations = Vec::with_capacity(batch.client_leases().len());
    for lease in batch.client_leases() {
        if lease.route_context_id() != &route_context_id {
            return Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::Activating,
            ));
        }
        let grant = by_path
            .get(&lease.path_id())
            .ok_or(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::Activating,
            ))?;
        let signed_relay_reservation = P::signed_relay_reservation(grant);
        if signed_relay_reservation.is_empty() {
            return Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::Activating,
            ));
        }
        let endpoint = P::relay_client_endpoint(grant)?;
        activations.push(LeaseActivation {
            lease_handle: lease.lease_handle().as_bytes().to_vec(),
            path_id: lease.path_id(),
            role: WireguardRole::Client as i32,
            peer_public_key: endpoint.public_key().as_bytes().to_vec(),
            peer_endpoint: Some(PublicUdpEndpoint {
                address: ip_bytes(endpoint.underlay_ip()),
                port: u32::from(endpoint.listen_port()),
            }),
            // Reservation rates constrain selection and signed capacity, but
            // helper-v3 rate fields configure relay forwarding only. A Client
            // lease must therefore carry the protocol-canonical zero values.
            maximum_up_mbps: 0,
            maximum_down_mbps: 0,
            // Preserve byte identity: the production helper verifies this exact canonical signed
            // envelope and binds it to the prepared lease before mutation. Never decode,
            // reconstruct, or substitute another path's grant here.
            signed_relay_reservation: signed_relay_reservation.to_vec(),
            // Client-role activations never carry the Relay-only client-to-relay request proof.
            signed_client_relay_request: Vec::new(),
        });
    }
    Ok(ActivateLeaseBatch {
        route_context_id: route_context_id.to_vec(),
        context_handle: batch.context_handle().as_bytes().to_vec(),
        leases: activations,
    })
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    }
}

fn validate_activated(
    request: &ActivateLeaseBatch,
    response: &ActivatedLeaseBatch,
) -> Result<(), RouteSetupError> {
    let expected = request
        .leases
        .iter()
        .map(|lease| lease.lease_handle.as_slice())
        .collect::<BTreeSet<_>>();
    let actual = response
        .lease_handles
        .iter()
        .map(Vec::as_slice)
        .collect::<BTreeSet<_>>();
    if response.context_handle != request.context_handle
        || expected.len() != request.leases.len()
        || actual.len() != response.lease_handles.len()
        || actual != expected
    {
        return Err(RouteSetupError::HelperCorrelation);
    }
    Ok(())
}

fn commit_request(activation: &ActivateLeaseBatch) -> CommitLeaseBatch {
    CommitLeaseBatch {
        route_context_id: activation.route_context_id.clone(),
        context_handle: activation.context_handle.clone(),
        leases: activation
            .leases
            .iter()
            .map(|lease| LeaseCommit {
                lease_handle: lease.lease_handle.clone(),
                path_id: lease.path_id,
                role: lease.role,
            })
            .collect(),
    }
}

fn validate_committed(
    request: &CommitLeaseBatch,
    response: &CommittedLeaseBatch,
) -> Result<(), RouteSetupError> {
    let expected = request
        .leases
        .iter()
        .map(|lease| lease.lease_handle.as_slice())
        .collect::<BTreeSet<_>>();
    let actual = response
        .leases
        .iter()
        .map(|lease| lease.lease_handle.as_slice())
        .collect::<BTreeSet<_>>();
    if response.context_handle != request.context_handle
        || expected.len() != request.leases.len()
        || actual.len() != response.leases.len()
        || actual != expected
        || response.leases.iter().any(|proof| {
            proof.latest_handshake_unix == 0
                || proof.received_bytes == 0
                || proof.transmitted_bytes == 0
        })
    {
        return Err(RouteSetupError::HelperCorrelation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use ed25519_dalek::{Signer as _, SigningKey};
    use libp2p::identity;
    use tokio::{
        sync::Notify,
        time::{sleep, timeout},
    };
    use volparossa_core::{
        CapacitySnapshot, NetworkMetadata, NodeAdvertisement, NodeCapabilities, NodeQuality,
        NodeRoles, PeerId as CorePeerId, PolicyHash, UnixTime,
    };
    use volparossa_exit::{
        ExitNativeRouteIdentityError, ExitNativeRouteIdentityOwner,
        ExitNativeRouteIdentityProvider, ExitNativeRouteIdentityRequest, ExitService,
        ExitServiceConfig, ProbeEvidence, ProbeEvidenceError, ProbeEvidenceVerifier,
    };
    use volparossa_protocol::{
        ControlMessageType, ExitReservation, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE,
        NativeRouteIdentity, PROTOCOL_VERSION, RelayAuthorization, RelayProbePermit,
        RelayProbeResult, ReplayCache, SignedEnvelope, TimePolicy, decode_canonical,
        encode_canonical, generate_nonce, node_id_from_public_key, sign_control_message,
        verify_control_message,
    };
    use volparossa_relay::{RelayService, RelayServiceConfig};
    use volparossa_routing::{
        CommittedLease, HELPER_HANDLE_BYTES, HELPER_PROTOCOL_VERSION, HelperRequest, PreparedLease,
        UnderlayEvidence, encode_request, helper_request, operation_digest,
    };
    use volparossa_selection::{CandidateEvidence, SelectionMix};
    use volparossa_test_support::{ephemeral_signing_key, verified_development_manifest};
    use volparossa_wireguard::{
        EndpointRole, ExitEndpointLease, HelperContextHandle, HelperLeaseHandle,
        RelayEndpointLease, WireGuardPublicKey,
    };

    use super::*;

    const NOW_MS: u64 = 1_700_000_000_000;
    const TEST_TIMEOUT: Duration = Duration::from_secs(3);
    const TEST_EXIT_NATIVE_INSTANCE_ID: [u8; 32] = [43; 32];

    #[test]
    fn client_route_expiry_fails_closed_at_the_signed_wall_deadline() {
        let monotonic_now = Instant::now();
        let expiry =
            ClientRouteExpiry::from_hard_expiry((NOW_MS + 2_000) / 1_000, NOW_MS, monotonic_now);

        assert!(!expiry.is_expired(NOW_MS + 1_999, monotonic_now));
        assert!(expiry.is_expired(NOW_MS + 2_000, monotonic_now));
    }

    #[test]
    fn client_route_expiry_monotonic_projection_survives_wall_clock_rollback() {
        let monotonic_now = Instant::now();
        let expiry =
            ClientRouteExpiry::from_hard_expiry((NOW_MS + 2_000) / 1_000, NOW_MS, monotonic_now);

        assert!(!expiry.is_expired(
            NOW_MS.saturating_sub(60_000),
            monotonic_now + Duration::from_millis(1_999),
        ));
        assert!(expiry.is_expired(
            NOW_MS.saturating_sub(60_000),
            monotonic_now + Duration::from_millis(2_000),
        ));
    }

    #[test]
    fn already_expired_route_projection_is_never_reusable() {
        let monotonic_now = Instant::now();
        let expiry =
            ClientRouteExpiry::from_hard_expiry((NOW_MS - 1_000) / 1_000, NOW_MS, monotonic_now);

        assert!(expiry.is_expired(NOW_MS, monotonic_now));
    }

    #[test]
    fn mptcp_acquire_retires_only_a_helper_route_that_is_no_longer_owned() {
        for result in [HelperResult::CleanupIncomplete, HelperResult::NotFound] {
            assert!(mptcp_acquire_failure_lost_helper_route(
                &MptcpTransportError::Helper(HelperClientError::Rejected(result))
            ));
        }
        for result in [
            HelperResult::Kernel,
            HelperResult::Unavailable,
            HelperResult::Capacity,
        ] {
            assert!(!mptcp_acquire_failure_lost_helper_route(
                &MptcpTransportError::Helper(HelperClientError::Rejected(result))
            ));
        }
    }

    #[test]
    fn active_browser_flow_defers_only_minimum_crossing_path_removal() {
        assert!(retain_degraded_path_for_active_browser_flow(2, 2, 1));
        assert!(!retain_degraded_path_for_active_browser_flow(2, 2, 0));
        assert!(!retain_degraded_path_for_active_browser_flow(3, 2, 1));
    }

    fn native_path_status(path_id: u32, data_carrying: bool) -> NativePathStatus {
        NativePathStatus {
            path_id,
            smoothed_rtt_us: 1_000_u64.saturating_mul(u64::from(path_id)),
            packets_lost: 0,
            delivered_bytes: 0,
            congestion_window_bytes: 64 * 1_024,
            bytes_in_flight: 512,
            delivery_rate_bps: 8_000_000,
            data_carrying,
        }
    }

    #[test]
    fn browser_mpquic_packet_scope_never_exceeds_exit_parser_limit() {
        assert_eq!(
            maximum_mpquic_tunnel_packet_bytes(1_420),
            Ok(MINIMUM_MPQUIC_TUNNEL_MTU)
        );
        assert_eq!(maximum_mpquic_tunnel_packet_bytes(1_200), Ok(1_200));
        assert_eq!(
            maximum_mpquic_tunnel_packet_bytes(27),
            Err(ClientRouteConnectError::TransportRuntimeUnavailable)
        );
    }

    #[test]
    fn tcp_route_retry_is_bounded_to_transient_bootstrap_failures() {
        let now = Instant::now();
        assert_eq!(
            tcp_connect_retry_delay(
                ClientRouteConnectError::Busy,
                now,
                now + TCP_CONNECT_RECOVERY_HORIZON
            ),
            Some(TCP_CONNECT_RETRY_INTERVAL)
        );
        assert_eq!(
            tcp_connect_retry_delay(
                ClientRouteConnectError::PreselectionUnavailable,
                now,
                now + Duration::from_millis(250)
            ),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            tcp_connect_retry_delay(
                ClientRouteConnectError::TransportRuntimeUnavailable,
                now,
                now + TCP_CONNECT_RECOVERY_HORIZON
            ),
            None
        );
        assert_eq!(
            tcp_connect_retry_delay(ClientRouteConnectError::Busy, now, now),
            None
        );
    }

    #[test]
    fn committed_mpquic_identity_projects_native_status_by_exact_path_id() {
        let identity = CommittedMpquicRouteIdentity {
            route_context_id: [7; ID_BYTES],
            exit_peer_id: "exit-peer".to_owned(),
            paths: vec![
                CommittedMpquicPathIdentity {
                    path_id: 1,
                    relay_peer_id: "relay-one".to_owned(),
                },
                CommittedMpquicPathIdentity {
                    path_id: 2,
                    relay_peer_id: "relay-two".to_owned(),
                },
            ],
        };

        let summaries = identity
            .project(
                &[native_path_status(2, true), native_path_status(1, false)],
                std::iter::empty(),
            )
            .expect("exact status projection");

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].path_id, 1);
        assert_eq!(summaries[0].relay_peer_id, "relay-one");
        assert_eq!(summaries[0].state, PathState::Reachable as i32);
        assert_eq!(summaries[1].path_id, 2);
        assert_eq!(summaries[1].relay_peer_id, "relay-two");
        assert_eq!(summaries[1].state, PathState::Active as i32);
        assert_eq!(summaries[1].smoothed_rtt_micros, 2_000);
        assert!(summaries.iter().all(|summary| summary.user_bytes == 0));
    }

    #[test]
    fn committed_mpquic_identity_rejects_duplicate_native_path_status() {
        let identity = CommittedMpquicRouteIdentity {
            route_context_id: [7; ID_BYTES],
            exit_peer_id: "exit-peer".to_owned(),
            paths: vec![
                CommittedMpquicPathIdentity {
                    path_id: 1,
                    relay_peer_id: "relay-one".to_owned(),
                },
                CommittedMpquicPathIdentity {
                    path_id: 2,
                    relay_peer_id: "relay-two".to_owned(),
                },
            ],
        };

        assert!(matches!(
            identity.project(
                &[native_path_status(1, true), native_path_status(1, true),],
                std::iter::empty(),
            ),
            Err(ClientRouteConnectError::TransportRuntimeUnavailable)
        ));
    }

    #[test]
    fn committed_mpquic_identity_keeps_warm_path_out_of_active_projection() {
        let identity = CommittedMpquicRouteIdentity {
            route_context_id: [7; ID_BYTES],
            exit_peer_id: "exit-peer".to_owned(),
            paths: (1..=3)
                .map(|path_id| CommittedMpquicPathIdentity {
                    path_id,
                    relay_peer_id: format!("relay-{path_id}"),
                })
                .collect(),
        };

        let summaries = identity
            .project(
                &[native_path_status(1, true), native_path_status(2, true)],
                [3],
            )
            .expect("active plus warm projection");

        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[2].path_id, 3);
        assert_eq!(summaries[2].state, PathState::Backup as i32);
        assert_eq!(summaries[2].user_bytes, 0);
    }

    #[test]
    fn production_health_promotes_warm_path_after_live_peer_progress_stalls() {
        let start = UnixTime::from_secs(1_000);
        let mut health =
            ProductionMpquicPathHealth::new(&[1, 2], [3], start).expect("health state");
        let initial = [native_path_status(1, true), native_path_status(2, true)];
        assert!(health.observe(&initial, start).expect("initial").is_empty());

        let mut progressed = initial;
        progressed[0].delivered_bytes = 2_400;
        let degraded_at = UnixTime::from_secs(1_011);
        assert_eq!(
            health.observe(&progressed, degraded_at).expect("metrics"),
            [2]
        );
        assert!(health.authorizes_replacement(2, 3, degraded_at));
        health
            .record_replacement(2, 3, degraded_at)
            .expect("promote warm path");

        let promoted = [progressed[0].clone(), native_path_status(3, false)];
        assert!(
            health
                .observe(&promoted, degraded_at)
                .expect("post replacement")
                .is_empty()
        );
    }

    #[test]
    fn default_connect_profile_selects_configured_udp_ipv4_capacity_exactly() {
        let config = Config::default();
        let parameters = client_preselection_parameters(&config).expect("default route profile");
        let (transport, family, minimum, local, ceiling, minimum_other, maximum_other, bound) =
            parameters.fields_for_test();
        assert_eq!(transport, Transport::UdpSinglePath);
        assert_eq!(family, volparossa_protocol::ObservationAddressFamily::Ipv4);
        assert_eq!(minimum, Bandwidth::new(10, 10).expect("minimum"));
        assert_eq!(local, Bandwidth::new(100, 100).expect("local"));
        assert_eq!(ceiling, Bandwidth::new(80, 80).expect("ceiling"));
        assert_eq!((minimum_other, maximum_other), (1, 1));
        assert_eq!(
            bound,
            config
                .network
                .candidate_pool_size
                .min(volparossa_selection::MAXIMUM_SELECTION_CANDIDATES)
        );
    }

    #[test]
    fn connect_profile_uses_ipv6_and_multipath_bounds_without_hidden_fallback() {
        let mut config = Config::default();
        config.udp.enabled = false;
        config.routing.client_address_family = ClientAddressFamily::Ipv6;
        let expected_minimum = usize::from(config.selection.minimum_multipath_paths);
        let expected_maximum = usize::from(config.selection.maximum_multipath_paths);
        let parameters = client_preselection_parameters(&config).expect("MPTCP route profile");
        let (transport, family, _, _, _, minimum_other, maximum_other, _) =
            parameters.fields_for_test();
        assert_eq!(transport, Transport::TcpMptcp);
        assert_eq!(family, volparossa_protocol::ObservationAddressFamily::Ipv6);
        assert_eq!(minimum_other, expected_minimum);
        assert_eq!(maximum_other, expected_maximum);

        config.tcp.enabled = false;
        config.quic.enabled = false;
        assert_eq!(
            client_preselection_parameters(&config).err(),
            Some(ClientRouteConnectError::InvalidProfile)
        );
    }

    #[test]
    fn connect_path_requirement_is_exact_and_never_degrades_multipath() {
        let mut config = Config::default();
        assert_eq!(
            client_native_path_requirement(&config),
            Ok((Transport::UdpSinglePath, 1))
        );

        config.udp.enabled = false;
        config.selection.minimum_multipath_paths = 4;
        assert_eq!(
            client_native_path_requirement(&config),
            Ok((Transport::TcpMptcp, 4))
        );
        let parameters = client_preselection_parameters(&config).expect("MPTCP parameters");
        let (_, _, _, _, _, minimum_other, _, _) = parameters.fields_for_test();
        assert_eq!(minimum_other, 4);

        config.tcp.enabled = false;
        config.selection.minimum_multipath_paths = 2;
        config.quic.minimum_paths = 3;
        assert_eq!(
            client_native_path_requirement(&config),
            Ok((Transport::MultipathQuic, 3))
        );
        let parameters = client_preselection_parameters(&config).expect("MPQUIC parameters");
        let (_, _, _, _, _, minimum_other, _, _) = parameters.fields_for_test();
        assert_eq!(minimum_other, 3);

        config.quic.allow_degraded_single_path = true;
        assert_eq!(
            client_native_path_requirement(&config),
            Err(ClientRouteConnectError::InvalidProfile)
        );
        config.quic.allow_degraded_single_path = false;
        config.quic.minimum_paths = 1;
        config.selection.minimum_multipath_paths = 1;
        assert_eq!(
            client_native_path_requirement(&config),
            Err(ClientRouteConnectError::InvalidProfile)
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct FakeNativeReady {
        completed_paths: Vec<u32>,
        next_path: u32,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct FakeNativeCompleted {
        paths: Vec<u32>,
    }

    #[tokio::test]
    async fn required_path_driver_stops_after_one_udp_or_the_exact_multipath_minimum() {
        for required_paths in [1_usize, 2, 4] {
            let completed = drive_required_native_paths(
                FakeNativeReady {
                    completed_paths: Vec::new(),
                    next_path: 1,
                },
                required_paths,
                |mut ready| async move {
                    ready.completed_paths.push(ready.next_path);
                    Ok::<_, ClientRouteConnectError>(FakeNativeCompleted {
                        paths: ready.completed_paths,
                    })
                },
                |completed| async move {
                    let next_path = u32::try_from(completed.paths.len() + 1)
                        .expect("bounded native path count");
                    Ok(FakeNativeReady {
                        completed_paths: completed.paths,
                        next_path,
                    })
                },
                |completed| completed.paths.len(),
            )
            .await
            .expect("required paths complete");
            assert_eq!(
                completed.paths,
                (1..=u32::try_from(required_paths).expect("bounded requirement"))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn required_path_driver_fails_closed_without_single_path_fallback() {
        let result = drive_required_native_paths(
            FakeNativeReady {
                completed_paths: Vec::new(),
                next_path: 1,
            },
            2,
            |mut ready| async move {
                ready.completed_paths.push(ready.next_path);
                Ok::<_, ClientRouteConnectError>(FakeNativeCompleted {
                    paths: ready.completed_paths,
                })
            },
            |_completed| async {
                Err::<FakeNativeReady, _>(ClientRouteConnectError::NativePermitUnavailable)
            },
            |completed| completed.paths.len(),
        )
        .await;
        assert_eq!(
            result,
            Err(ClientRouteConnectError::NativePermitUnavailable)
        );
    }

    #[derive(Default)]
    #[allow(
        clippy::struct_excessive_bools,
        reason = "independent fault injection switches keep each rollback regression explicit"
    )]
    struct FakeState {
        events: Vec<String>,
        selected_paths: Vec<u32>,
        finalized_probe_tokens: Vec<(u64, u32)>,
        session_tokens: Vec<u64>,
        relay_paths: BTreeMap<Vec<u8>, u32>,
        exit_attempts: BTreeMap<i32, usize>,
        exit_frames: BTreeMap<i32, Vec<ExitForwardRequest>>,
        datapath_attempts: BTreeMap<(i32, u32), usize>,
        ambiguous_exit: Option<(i32, usize)>,
        unavailable_probe: Option<u32>,
        blocked_probe: Option<u32>,
        block_prepare: bool,
        block_activate: bool,
        block_commit: bool,
        prepare_delay_ms: Option<u64>,
        ambiguous_prepare: bool,
        block_destroy: bool,
        fail_destroy: bool,
        panic_destroy: bool,
        fail_reconcile: bool,
        substitute_reconcile_receipt: bool,
        probe_family_substitution: Option<ProbeAddressFamily>,
        all_probe_capacity: Option<u64>,
        disable_probe_gain: bool,
        force_probe_gain: bool,
        prepared_mptcp_accepted_addrs: Option<u32>,
        prepared_mptcp_subflows: Option<u32>,
        prepared_lease_count: Option<usize>,
        prepared_lease_identities: Option<Vec<(u32, i32)>>,
        activation_batches: Vec<ActivateLeaseBatch>,
    }

    #[derive(Default)]
    struct FakeShared {
        state: Mutex<FakeState>,
        prepare_started: Notify,
        prepare_release: Notify,
        activate_started: Notify,
        activate_release: Notify,
        commit_started: Notify,
        commit_release: Notify,
        probe_started: Notify,
        late_probe_release: Notify,
        destroy_started: Notify,
        destroy_release: Notify,
    }

    impl FakeShared {
        fn record(&self, event: impl Into<String>) {
            self.state
                .lock()
                .expect("fake state")
                .events
                .push(event.into());
        }

        fn events(&self) -> Vec<String> {
            self.state.lock().expect("fake state").events.clone()
        }

        fn selected_paths(&self) -> Vec<u32> {
            self.state
                .lock()
                .expect("fake state")
                .selected_paths
                .clone()
        }

        fn prepared_lease_identities(&self) -> Option<Vec<(u32, i32)>> {
            self.state
                .lock()
                .expect("fake state")
                .prepared_lease_identities
                .clone()
        }
    }

    #[derive(Clone)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn new() -> Self {
            Self(Arc::new(AtomicU64::new(NOW_MS)))
        }
    }

    impl RouteSetupClock for FakeClock {
        fn unix_millis(&self) -> u64 {
            self.0.load(Ordering::Acquire)
        }
    }

    #[derive(Default)]
    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FakeLocalError {
        Definitive,
        Ambiguous,
    }

    #[derive(Clone)]
    struct FakeLocal {
        shared: Arc<FakeShared>,
    }

    impl LocalRouteBackend for FakeLocal {
        type Error = FakeLocalError;

        async fn prepare(
            &mut self,
            request: &PrepareLeaseBatch,
        ) -> Result<RuntimeBoundPreparedLeaseBatch, LocalPrepareFailure<Self::Error>> {
            self.shared.record("local.prepare");
            let (block, delay_ms, ambiguous) = {
                let mut state = self.shared.state.lock().expect("fake state");
                state.prepared_mptcp_accepted_addrs = Some(request.mptcp_accepted_addrs);
                state.prepared_mptcp_subflows = Some(request.mptcp_subflows);
                state.prepared_lease_count = Some(request.leases.len());
                state.prepared_lease_identities = Some(
                    request
                        .leases
                        .iter()
                        .map(|lease| (lease.path_id, lease.role))
                        .collect(),
                );
                (
                    state.block_prepare,
                    state.prepare_delay_ms,
                    state.ambiguous_prepare,
                )
            };
            self.shared.prepare_started.notify_one();
            if let Some(delay_ms) = delay_ms {
                sleep(Duration::from_millis(delay_ms)).await;
            }
            if block {
                self.shared.prepare_release.notified().await;
            }
            if ambiguous {
                return Err(LocalPrepareFailure::Ambiguous {
                    source: FakeLocalError::Ambiguous,
                    authority: PrepareReconciliationAuthority::for_test(request),
                });
            }
            let leases = request
                .leases
                .iter()
                .map(|lease| {
                    let path = u8::try_from(lease.path_id).expect("bounded path id");
                    PreparedLease {
                        lease_handle: vec![path; HELPER_HANDLE_BYTES],
                        path_id: lease.path_id,
                        role: lease.role,
                        public_key: vec![path.saturating_add(32); 32],
                        public_endpoint: Some(PublicUdpEndpoint {
                            address: vec![8, 8, 4, path.saturating_add(10)],
                            port: 40_000 + lease.path_id,
                        }),
                        underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
                    }
                })
                .collect();
            Ok(RuntimeBoundPreparedLeaseBatch::for_test(
                request.clone(),
                PreparedLeaseBatch {
                    context_handle: vec![99; HELPER_HANDLE_BYTES],
                    leases,
                },
            ))
        }

        async fn activate(
            &mut self,
            owner: &mut RuntimeBoundPreparedLeaseBatch,
            request: &ActivateLeaseBatch,
        ) -> Result<ActivatedLeaseBatch, Self::Error> {
            encode_request(&HelperRequest {
                protocol_version: HELPER_PROTOCOL_VERSION,
                request_id: vec![0xa7; ID_BYTES],
                operation: Some(helper_request::Operation::ActivateLeaseBatch(
                    request.clone(),
                )),
            })
            .map_err(|_| FakeLocalError::Definitive)?;
            self.shared.record("local.activate");
            let block = {
                let mut state = self.shared.state.lock().expect("fake state");
                state.activation_batches.push(request.clone());
                state.block_activate
            };
            self.shared.activate_started.notify_one();
            if block {
                self.shared.activate_release.notified().await;
            }
            owner
                .begin_activation(request)
                .map_err(|_| FakeLocalError::Definitive)?;
            let response = ActivatedLeaseBatch {
                context_handle: request.context_handle.clone(),
                lease_handles: request
                    .leases
                    .iter()
                    .map(|lease| lease.lease_handle.clone())
                    .collect(),
            };
            owner
                .finish_activation(&response)
                .map_err(|_| FakeLocalError::Definitive)?;
            Ok(response)
        }

        async fn commit(
            &mut self,
            owner: &mut RuntimeBoundPreparedLeaseBatch,
            request: &CommitLeaseBatch,
        ) -> Result<CommittedLeaseBatch, Self::Error> {
            self.shared.record("local.commit");
            let block = self.shared.state.lock().expect("fake state").block_commit;
            self.shared.commit_started.notify_one();
            if block {
                self.shared.commit_release.notified().await;
            }
            owner
                .begin_commit(request)
                .map_err(|_| FakeLocalError::Definitive)?;
            let response = CommittedLeaseBatch {
                context_handle: request.context_handle.clone(),
                leases: request
                    .leases
                    .iter()
                    .map(|lease| CommittedLease {
                        lease_handle: lease.lease_handle.clone(),
                        latest_handshake_unix: NOW_MS / 1_000,
                        received_bytes: 10,
                        transmitted_bytes: 10,
                    })
                    .collect(),
            };
            owner
                .finish_commit(&response)
                .map_err(|_| FakeLocalError::Definitive)?;
            Ok(response)
        }

        async fn destroy(
            &mut self,
            _owner: &RuntimeBoundPreparedLeaseBatch,
        ) -> Result<DestroyedContext, Self::Error> {
            self.shared.record("local.destroy");
            let block = self.shared.state.lock().expect("fake state").block_destroy;
            self.shared.destroy_started.notify_one();
            if block {
                self.shared.destroy_release.notified().await;
            }
            let (fail, panic_destroy) = {
                let state = self.shared.state.lock().expect("fake state");
                (state.fail_destroy, state.panic_destroy)
            };
            assert!(!panic_destroy, "injected retirement worker panic");
            if fail {
                Err(FakeLocalError::Definitive)
            } else {
                Ok(DestroyedContext { existed: true })
            }
        }

        async fn reconcile_expired_prepare(
            &mut self,
            authority: &PrepareReconciliationAuthority,
        ) -> Result<ReconciledExpiredPrepare, Self::Error> {
            self.shared.record("local.reconcile_expired_prepare");
            let (fail, substitute) = {
                let state = self.shared.state.lock().expect("fake state");
                (state.fail_reconcile, state.substitute_reconcile_receipt)
            };
            if fail {
                Err(FakeLocalError::Definitive)
            } else {
                let mut receipt = authority.reconciled_for_test();
                if substitute {
                    receipt.route_context_id[0] ^= 1;
                }
                Ok(receipt)
            }
        }
    }

    #[derive(Clone)]
    struct FakeProbeRequest {
        path_id: u32,
        transport: Transport,
        address_family: ProbeAddressFamily,
        encoded: Vec<u8>,
    }

    struct FakeProbePermit {
        path_id: u32,
        transport: Transport,
        address_family: ProbeAddressFamily,
        encoded: Vec<u8>,
    }

    struct UniqueProbeToken {
        session: u64,
        path_id: u32,
    }

    struct FakeProbe {
        projection: ProbeProjection,
        token: UniqueProbeToken,
    }

    fn measured_fake_probe(path_id: u32, capacity_mbps: u64) -> (u32, FakeProbe) {
        (
            path_id,
            FakeProbe {
                projection: ProbeProjection {
                    path_id,
                    transport: Transport::TcpMptcp,
                    address_family: ProbeAddressFamily::Ipv4,
                    minimum_directional_capacity_mbps: capacity_mbps,
                    evidence_bytes: capacity_mbps.saturating_mul(1_000),
                    client_to_relay_rtt_micros: u64::from(path_id).saturating_mul(40),
                    relay_to_exit_rtt_micros: u64::from(path_id).saturating_mul(60),
                    total_rtt_micros: u64::from(path_id).saturating_mul(100),
                    unique_throughput_gain_ratio: 0.20,
                    meaningful_failover: true,
                },
                token: UniqueProbeToken {
                    session: 0,
                    path_id,
                },
            },
        )
    }

    fn bound_activation_batch(
        route_context_id: [u8; ID_BYTES],
        requested_path_ids: &[u32],
        response_path_ids: &[u32],
    ) -> LocalEndpointLeaseBatch {
        let request = PrepareLeaseBatch {
            route_context_id: route_context_id.to_vec(),
            role: ContextRole::Client as i32,
            mptcp_accepted_addrs: MAX_HELPER_PATHS,
            mptcp_subflows: MAX_HELPER_PATHS,
            leases: requested_path_ids
                .iter()
                .map(|path_id| LeasePlan {
                    path_id: *path_id,
                    role: WireguardRole::Client as i32,
                })
                .collect(),
            setup_expires_at_unix: NOW_MS / 1_000 + 20,
            hard_expires_at_unix: NOW_MS / 1_000 + 60,
            traversal_hints: Vec::new(),
        };
        let response = PreparedLeaseBatch {
            context_handle: vec![99; HELPER_HANDLE_BYTES],
            leases: response_path_ids
                .iter()
                .map(|path_id| {
                    let path = u8::try_from(*path_id).expect("bounded path id");
                    PreparedLease {
                        lease_handle: vec![path; HELPER_HANDLE_BYTES],
                        path_id: *path_id,
                        role: WireguardRole::Client as i32,
                        public_key: vec![path.saturating_add(32); 32],
                        public_endpoint: Some(PublicUdpEndpoint {
                            address: vec![8, 8, 4, path.saturating_add(10)],
                            port: 40_000 + *path_id,
                        }),
                        underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
                    }
                })
                .collect(),
        };
        bind_prepared_endpoint_leases(&request, response).expect("bound activation batch")
    }

    fn fake_relay_grant(path_id: u32, signed_relay_reservation: &[u8]) -> FakeRelayGrant {
        FakeRelayGrant {
            path_id,
            signed_relay_reservation: signed_relay_reservation.to_vec(),
        }
    }

    struct FakeFinalizeRequest {
        path_ids: Vec<u32>,
        encoded: Vec<u8>,
    }

    struct FakeExitBundle {
        path_ids: Vec<u32>,
        signed_exit_reservation: Vec<u8>,
    }

    #[derive(Debug)]
    struct FakeRelayGrant {
        path_id: u32,
        signed_relay_reservation: Vec<u8>,
    }

    struct UniqueSessionToken(u64);

    static NEXT_FAKE_SESSION_TOKEN: AtomicU64 = AtomicU64::new(1);

    struct FakeProtocol {
        shared: Arc<FakeShared>,
        session_token: UniqueSessionToken,
    }

    impl FakeProtocol {
        fn new(shared: Arc<FakeShared>) -> Self {
            let token = NEXT_FAKE_SESSION_TOKEN.fetch_add(1, Ordering::Relaxed);
            shared
                .state
                .lock()
                .expect("fake state")
                .session_tokens
                .push(token);
            Self {
                shared,
                session_token: UniqueSessionToken(token),
            }
        }

        fn phase_error(phase: RouteSetupPhase) -> RouteSetupError {
            RouteSetupError::ReservationProtocol(phase)
        }
    }

    impl ClientReservationProtocol for FakeProtocol {
        type Hold = ();
        type ProbeRequest = FakeProbeRequest;
        type ProbePermit = FakeProbePermit;
        type Probe = FakeProbe;
        type FinalizeRequest = FakeFinalizeRequest;
        type ExitBundle = FakeExitBundle;
        type RelayGrant = FakeRelayGrant;
        type NativeAuthorization = ();

        fn sign_hold(
            &mut self,
            intent: &ExitReservationIntent,
        ) -> Result<Vec<u8>, RouteSetupError> {
            self.shared.record("protocol.sign.hold");
            Ok(signed_envelope_at(
                ControlMessageType::ExitCapacityHoldRequest,
                Vec::new(),
                intent.hold_expires_at_ms,
            ))
        }

        fn verify_hold(
            &mut self,
            _intent: &ExitReservationIntent,
            signed_responses: Vec<Vec<u8>>,
            authenticated_exit_peer_id: &[u8],
            _now_ms: u64,
        ) -> Result<Self::Hold, RouteSetupError> {
            if signed_responses.len() != 2 || authenticated_exit_peer_id.is_empty() {
                return Err(Self::phase_error(RouteSetupPhase::CapacityHold));
            }
            envelope_payload(
                &signed_responses[0],
                ControlMessageType::ClientSessionCapability,
                RouteSetupPhase::CapacityHold,
            )?;
            envelope_payload(
                &signed_responses[1],
                ControlMessageType::ExitCapacityHold,
                RouteSetupPhase::CapacityHold,
            )?;
            self.shared.record("protocol.verify.hold");
            Ok(())
        }

        fn sign_probe_request(
            &mut self,
            _hold: &Self::Hold,
            path: &RelayPathIntent,
            transport: Transport,
            address_family: ProbeAddressFamily,
            _created_at_ms: u64,
            expires_at_ms: u64,
        ) -> Result<Self::ProbeRequest, RouteSetupError> {
            self.shared
                .record(format!("protocol.sign.permit.{}", path.path_id));
            if transport == Transport::Unspecified
                || address_family == ProbeAddressFamily::Unspecified
            {
                return Err(Self::phase_error(RouteSetupPhase::ProbePermits));
            }
            Ok(FakeProbeRequest {
                path_id: path.path_id,
                transport,
                address_family,
                encoded: signed_envelope_at(
                    ControlMessageType::RelayProbePermitRequest,
                    vec![
                        u8::try_from(path.path_id)
                            .map_err(|_| Self::phase_error(RouteSetupPhase::ProbePermits))?,
                    ],
                    expires_at_ms,
                ),
            })
        }

        fn probe_request_bytes(request: &Self::ProbeRequest) -> &[u8] {
            &request.encoded
        }

        fn verify_probe_permit(
            &mut self,
            request: &Self::ProbeRequest,
            signed_permit: Vec<u8>,
            _now_ms: u64,
        ) -> Result<Self::ProbePermit, RouteSetupError> {
            require_path_payload(
                &signed_permit,
                ControlMessageType::RelayProbePermit,
                request.path_id,
                RouteSetupPhase::ProbePermits,
            )?;
            self.shared
                .record(format!("protocol.verify.permit.{}", request.path_id));
            Ok(FakeProbePermit {
                path_id: request.path_id,
                transport: request.transport,
                address_family: request.address_family,
                encoded: signed_permit,
            })
        }

        fn probe_permit_bytes(permit: &Self::ProbePermit) -> &[u8] {
            &permit.encoded
        }

        fn verify_probe_result(
            &mut self,
            permit: Self::ProbePermit,
            signed_result: Vec<u8>,
            _now_ms: u64,
        ) -> Result<Self::Probe, RouteSetupError> {
            require_path_payload(
                &signed_result,
                ControlMessageType::RelayProbeResult,
                permit.path_id,
                RouteSetupPhase::ExecuteProbes,
            )?;
            self.shared
                .record(format!("protocol.verify.probe.{}", permit.path_id));
            let (capacity_override, family_substitution, disable_gain, force_gain) = {
                let state = self.shared.state.lock().expect("fake state");
                (
                    state.all_probe_capacity,
                    state.probe_family_substitution,
                    state.disable_probe_gain,
                    state.force_probe_gain,
                )
            };
            let capacity = capacity_override.unwrap_or(match permit.path_id {
                2 => 300,
                5 => 200,
                8 => 100,
                _ => 10,
            });
            Ok(FakeProbe {
                projection: ProbeProjection {
                    path_id: permit.path_id,
                    transport: permit.transport,
                    address_family: family_substitution.unwrap_or(permit.address_family),
                    minimum_directional_capacity_mbps: capacity,
                    evidence_bytes: capacity * 1_000,
                    client_to_relay_rtt_micros: u64::from(permit.path_id) * 40,
                    relay_to_exit_rtt_micros: u64::from(permit.path_id) * 60,
                    total_rtt_micros: u64::from(permit.path_id) * 100,
                    unique_throughput_gain_ratio: if !disable_gain
                        && (force_gain || matches!(permit.path_id, 5 | 8))
                    {
                        0.20
                    } else {
                        0.0
                    },
                    meaningful_failover: !disable_gain
                        && (force_gain || matches!(permit.path_id, 5 | 8)),
                },
                token: UniqueProbeToken {
                    session: self.session_token.0,
                    path_id: permit.path_id,
                },
            })
        }

        fn probe_projection(probe: &Self::Probe) -> Result<ProbeProjection, RouteSetupError> {
            if probe.projection.minimum_directional_capacity_mbps == 0
                || probe.projection.evidence_bytes == 0
                || probe.projection.total_rtt_micros == 0
            {
                return Err(Self::phase_error(RouteSetupPhase::ExecuteProbes));
            }
            Ok(probe.projection)
        }

        fn sign_finalize(
            &mut self,
            _intent: &ExitReservationIntent,
            _hold: &Self::Hold,
            probes: &[Self::Probe],
            _created_at_ms: u64,
            expires_at_ms: u64,
            endpoints: &LocalEndpointLeaseBatch,
        ) -> Result<Self::FinalizeRequest, RouteSetupError> {
            let path_ids = probes
                .iter()
                .map(|probe| probe.projection.path_id)
                .collect::<Vec<_>>();
            let probe_tokens = probes
                .iter()
                .map(|probe| (probe.token.session, probe.token.path_id))
                .collect::<Vec<_>>();
            let endpoint_ids = endpoints
                .client_leases()
                .iter()
                .map(volparossa_wireguard::ClientEndpointLease::path_id)
                .collect::<Vec<_>>();
            if path_ids != endpoint_ids
                || probe_tokens
                    .iter()
                    .any(|(session, _)| *session != self.session_token.0)
                || probe_tokens
                    .iter()
                    .map(|(_, path_id)| *path_id)
                    .ne(path_ids.iter().copied())
            {
                return Err(Self::phase_error(RouteSetupPhase::Finalizing));
            }
            self.shared
                .record(format!("protocol.sign.finalize.{path_ids:?}"));
            {
                let mut state = self.shared.state.lock().expect("fake state");
                if probe_tokens
                    .iter()
                    .any(|token| state.finalized_probe_tokens.contains(token))
                {
                    return Err(Self::phase_error(RouteSetupPhase::Finalizing));
                }
                state.finalized_probe_tokens.extend(probe_tokens);
                state.selected_paths = path_ids.clone();
            }
            Ok(FakeFinalizeRequest {
                encoded: signed_envelope_at(
                    ControlMessageType::ExitReservationFinalizeRequest,
                    path_ids
                        .iter()
                        .map(|path_id| u8::try_from(*path_id).expect("bounded path id"))
                        .collect(),
                    expires_at_ms,
                ),
                path_ids,
            })
        }

        fn finalize_request_bytes(request: &Self::FinalizeRequest) -> &[u8] {
            &request.encoded
        }

        fn verify_finalize(
            &mut self,
            _intent: &ExitReservationIntent,
            _hold: &Self::Hold,
            request: &Self::FinalizeRequest,
            signed_responses: Vec<Vec<u8>>,
            authenticated_exit_peer_id: &[u8],
            _now_ms: u64,
        ) -> Result<Self::ExitBundle, RouteSetupError> {
            if authenticated_exit_peer_id.is_empty()
                || signed_responses.len() != request.path_ids.len() + 1
            {
                return Err(Self::phase_error(RouteSetupPhase::Finalizing));
            }
            let exit_payload = envelope_payload(
                &signed_responses[0],
                ControlMessageType::ExitReservation,
                RouteSetupPhase::Finalizing,
            )?;
            let exit = decode_canonical::<ExitReservation>(&exit_payload, MAX_CONTROL_PAYLOAD_SIZE)
                .map_err(|_| Self::phase_error(RouteSetupPhase::Finalizing))?;
            if usize::try_from(exit.maximum_paths).ok() != Some(request.path_ids.len()) {
                return Err(Self::phase_error(RouteSetupPhase::Finalizing));
            }
            for (signed, expected) in signed_responses[1..].iter().zip(&request.path_ids) {
                let payload = envelope_payload(
                    signed,
                    ControlMessageType::RelayAuthorization,
                    RouteSetupPhase::Finalizing,
                )?;
                let authorization =
                    decode_canonical::<RelayAuthorization>(&payload, MAX_CONTROL_PAYLOAD_SIZE)
                        .map_err(|_| Self::phase_error(RouteSetupPhase::Finalizing))?;
                if authorization.path_id != *expected {
                    return Err(Self::phase_error(RouteSetupPhase::Finalizing));
                }
            }
            self.shared.record("protocol.verify.finalize");
            Ok(FakeExitBundle {
                path_ids: request.path_ids.clone(),
                signed_exit_reservation: signed_responses[0].clone(),
            })
        }

        fn exit_bundle_path_count(bundle: &Self::ExitBundle) -> usize {
            bundle.path_ids.len()
        }

        fn signed_exit_reservation(bundle: &Self::ExitBundle) -> &[u8] {
            &bundle.signed_exit_reservation
        }

        fn sign_relay_request(
            &mut self,
            bundle: &Self::ExitBundle,
            path_index: usize,
            _created_at_ms: u64,
            expires_at_ms: u64,
        ) -> Result<Vec<u8>, RouteSetupError> {
            let path_id = *bundle
                .path_ids
                .get(path_index)
                .ok_or_else(|| Self::phase_error(RouteSetupPhase::RelayReservations))?;
            self.shared.record(format!("protocol.sign.relay.{path_id}"));
            Ok(signed_envelope_at(
                ControlMessageType::RelayReservationRequest,
                vec![
                    u8::try_from(path_id)
                        .map_err(|_| Self::phase_error(RouteSetupPhase::RelayReservations))?,
                ],
                expires_at_ms,
            ))
        }

        fn verify_relay_response(
            &mut self,
            bundle: &Self::ExitBundle,
            signed_relay: Vec<u8>,
            path_index: usize,
            path: &SelectedRouteSetupPath,
            _now_ms: u64,
        ) -> Result<Self::RelayGrant, RouteSetupError> {
            let expected = *bundle
                .path_ids
                .get(path_index)
                .ok_or_else(|| Self::phase_error(RouteSetupPhase::RelayReservations))?;
            if expected != path.path_id {
                return Err(Self::phase_error(RouteSetupPhase::RelayReservations));
            }
            require_path_payload(
                &signed_relay,
                ControlMessageType::RelayReservation,
                expected,
                RouteSetupPhase::RelayReservations,
            )?;
            self.shared
                .record(format!("protocol.verify.relay.{expected}"));
            Ok(FakeRelayGrant {
                path_id: expected,
                signed_relay_reservation: signed_relay,
            })
        }

        fn sign_confirmation(
            &mut self,
            grant: &Self::RelayGrant,
            _created_at_ms: u64,
            expires_at_ms: u64,
        ) -> Result<Vec<u8>, RouteSetupError> {
            self.shared
                .record(format!("protocol.sign.confirm.{}", grant.path_id));
            Ok(signed_envelope_at(
                ControlMessageType::ExitReservationConfirmation,
                vec![
                    u8::try_from(grant.path_id)
                        .map_err(|_| Self::phase_error(RouteSetupPhase::ExitConfirmations))?,
                ],
                expires_at_ms,
            ))
        }

        fn verify_confirmation_receipt(
            &mut self,
            grant: &Self::RelayGrant,
            signed_confirmation: &[u8],
            signed_receipt: &[u8],
            _now_ms: u64,
        ) -> Result<(), RouteSetupError> {
            require_path_payload(
                signed_confirmation,
                ControlMessageType::ExitReservationConfirmation,
                grant.path_id,
                RouteSetupPhase::ExitConfirmations,
            )?;
            require_path_payload(
                signed_receipt,
                ControlMessageType::ExitConfirmationReceipt,
                grant.path_id,
                RouteSetupPhase::ExitConfirmations,
            )?;
            self.shared
                .record(format!("protocol.verify.receipt.{}", grant.path_id));
            Ok(())
        }

        fn take_native_route_authorization(
            &mut self,
            _request: &Self::FinalizeRequest,
            _now_ms: u64,
        ) -> Result<Self::NativeAuthorization, RouteSetupError> {
            Ok(())
        }

        fn grant_path_id(grant: &Self::RelayGrant) -> u32 {
            grant.path_id
        }

        fn signed_relay_reservation(grant: &Self::RelayGrant) -> &[u8] {
            &grant.signed_relay_reservation
        }

        fn relay_client_endpoint(
            grant: &Self::RelayGrant,
        ) -> Result<PublicWireGuardEndpoint, RouteSetupError> {
            let suffix = u8::try_from(grant.path_id)
                .map_err(|_| Self::phase_error(RouteSetupPhase::Activating))?;
            PublicWireGuardEndpoint::new(
                WireGuardPublicKey::from_bytes([suffix.saturating_add(64); 32]),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, suffix.saturating_add(10))),
                u16::try_from(50_000 + grant.path_id)
                    .map_err(|_| Self::phase_error(RouteSetupPhase::Activating))?,
            )
            .map_err(|_| Self::phase_error(RouteSetupPhase::Activating))
        }

        fn release(&mut self, _reservation_id: [u8; ID_BYTES]) -> usize {
            self.shared.record("protocol.release");
            self.shared.selected_paths().len()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeTransportError {
        Ambiguous,
        Definitive,
    }

    struct FakeTransport {
        shared: Arc<FakeShared>,
    }

    impl ReservationTransport for FakeTransport {
        type Error = FakeTransportError;

        fn ambiguous_after_dispatch(error: &Self::Error) -> bool {
            *error == FakeTransportError::Ambiguous
        }

        async fn endpoint_traversal_hints(
            &mut self,
            _bindings: Vec<EndpointTraversalBinding>,
        ) -> Result<Vec<volparossa_routing::TraversalEndpointHint>, Self::Error> {
            Ok(Vec::new())
        }

        async fn exit_forward(
            &mut self,
            control: &DirectRelayCapability,
            request: &ExitForwardRequest,
        ) -> Result<ExitForwardResponse, Self::Error> {
            validate_fake_outer_scope(
                request.forward_id(),
                request.deadline_unix_ms(),
                request.canonical_request(),
            )?;
            if request.control_relay_node_id() != control.node_id
                || request.control_relay_peer_id() != control.peer_id.to_bytes()
            {
                return Err(FakeTransportError::Definitive);
            }
            let operation = request
                .validated_operation()
                .map_err(|_| FakeTransportError::Definitive)?;
            let frame = request.clone();
            let attempt;
            let ambiguous;
            {
                let mut state = self.shared.state.lock().expect("fake state");
                attempt = {
                    let value = state.exit_attempts.entry(operation as i32).or_insert(0);
                    *value += 1;
                    *value
                };
                state
                    .exit_frames
                    .entry(operation as i32)
                    .or_default()
                    .push(frame);
                ambiguous = match state.ambiguous_exit.as_mut() {
                    Some((target, remaining)) if *target == operation as i32 && *remaining != 0 => {
                        *remaining -= 1;
                        true
                    }
                    _ => false,
                };
                state
                    .events
                    .push(format!("transport.exit.{operation:?}.{attempt}"));
            }
            if ambiguous {
                return Err(FakeTransportError::Ambiguous);
            }

            let responses = match operation {
                ExitForwardOperation::CapacityHold => vec![
                    signed_envelope(ControlMessageType::ClientSessionCapability, Vec::new()),
                    signed_envelope(ControlMessageType::ExitCapacityHold, Vec::new()),
                ],
                ExitForwardOperation::ProbePermit => {
                    let path_id = payload_path(
                        request.canonical_request(),
                        ControlMessageType::RelayProbePermitRequest,
                        RouteSetupPhase::ProbePermits,
                    )
                    .map_err(|_| FakeTransportError::Definitive)?;
                    vec![signed_envelope(
                        ControlMessageType::RelayProbePermit,
                        vec![u8::try_from(path_id).map_err(|_| FakeTransportError::Definitive)?],
                    )]
                }
                ExitForwardOperation::FinalizeReservation => {
                    finalized_response(self.shared.selected_paths())?
                }
                ExitForwardOperation::ConfirmRelay => {
                    let path_id = payload_path(
                        request.canonical_request(),
                        ControlMessageType::ExitReservationConfirmation,
                        RouteSetupPhase::ExitConfirmations,
                    )
                    .map_err(|_| FakeTransportError::Definitive)?;
                    vec![signed_envelope(
                        ControlMessageType::ExitConfirmationReceipt,
                        vec![u8::try_from(path_id).map_err(|_| FakeTransportError::Definitive)?],
                    )]
                }
                ExitForwardOperation::FetchExitAdvertisement
                | ExitForwardOperation::NativeProbePermit
                | ExitForwardOperation::NativeProbeAuthorize
                | ExitForwardOperation::NativeProbeReady
                | ExitForwardOperation::NativeProbeResult
                | ExitForwardOperation::UdpSessionStart
                | ExitForwardOperation::MptcpSessionStart
                | ExitForwardOperation::MpquicSessionStart
                | ExitForwardOperation::Unspecified => {
                    return Err(FakeTransportError::Definitive);
                }
            };
            ExitForwardResponse::granted(
                request.forward_id().to_vec(),
                operation,
                request.exit_node_id().to_vec(),
                request.exit_peer_id().to_vec(),
                responses,
            )
            .map_err(|_| FakeTransportError::Definitive)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the fake asserts the complete typed datapath phase matrix"
        )]
        async fn datapath_relay(
            &mut self,
            relay: &DirectRelayCapability,
            request: &DatapathRelayRequest,
        ) -> Result<DatapathRelayResponse, Self::Error> {
            validate_fake_outer_scope(
                request.request_id(),
                request.deadline_unix_ms(),
                request.client_signed_request(),
            )?;
            if request.relay_node_id() != relay.node_id
                || request.relay_peer_id() != relay.peer_id.to_bytes()
            {
                return Err(FakeTransportError::Definitive);
            }
            let operation = request
                .validated_operation()
                .map_err(|_| FakeTransportError::Definitive)?;
            let (path_id, attempt, unavailable, blocked) = {
                let mut state = self.shared.state.lock().expect("fake state");
                let path_id = *state
                    .relay_paths
                    .get(request.relay_peer_id())
                    .ok_or(FakeTransportError::Definitive)?;
                let attempt = {
                    let value = state
                        .datapath_attempts
                        .entry((operation as i32, path_id))
                        .or_insert(0);
                    *value += 1;
                    *value
                };
                let unavailable = operation == DatapathRelayOperation::ExecuteProbe
                    && state.unavailable_probe == Some(path_id);
                let blocked = operation == DatapathRelayOperation::ExecuteProbe
                    && state.blocked_probe == Some(path_id);
                state.events.push(format!(
                    "transport.datapath.{operation:?}.{path_id}.{attempt}"
                ));
                (path_id, attempt, unavailable, blocked)
            };
            let _ = attempt;

            if blocked {
                self.shared.probe_started.notify_one();
                let shared = Arc::clone(&self.shared);
                tokio::spawn(async move {
                    shared.late_probe_release.notified().await;
                    shared.record(format!("transport.late.probe.{path_id}"));
                });
                std::future::pending::<()>().await;
                unreachable!("blocked fake probe is cancelled by the setup supervisor");
            }

            if unavailable {
                return DatapathRelayResponse::unavailable(
                    request.request_id().to_vec(),
                    operation,
                    request.relay_node_id().to_vec(),
                    request.relay_peer_id().to_vec(),
                )
                .map_err(|_| FakeTransportError::Definitive);
            }

            let response_type = match operation {
                DatapathRelayOperation::ExecuteProbe => {
                    require_path_payload(
                        request.client_signed_request(),
                        ControlMessageType::RelayProbePermitRequest,
                        path_id,
                        RouteSetupPhase::ExecuteProbes,
                    )
                    .map_err(|_| FakeTransportError::Definitive)?;
                    require_path_payload(
                        request.exit_signed_authorization(),
                        ControlMessageType::RelayProbePermit,
                        path_id,
                        RouteSetupPhase::ExecuteProbes,
                    )
                    .map_err(|_| FakeTransportError::Definitive)?;
                    ControlMessageType::RelayProbeResult
                }
                DatapathRelayOperation::ReservePath => {
                    require_path_payload(
                        request.client_signed_request(),
                        ControlMessageType::RelayReservationRequest,
                        path_id,
                        RouteSetupPhase::RelayReservations,
                    )
                    .map_err(|_| FakeTransportError::Definitive)?;
                    ControlMessageType::RelayReservation
                }
                DatapathRelayOperation::NativeProbeReady
                | DatapathRelayOperation::NativeProbeStart
                | DatapathRelayOperation::NativeProbeAuthorize
                | DatapathRelayOperation::UdpSessionStart
                | DatapathRelayOperation::MptcpSessionStart
                | DatapathRelayOperation::MpquicSessionStart
                | DatapathRelayOperation::Unspecified => {
                    return Err(FakeTransportError::Definitive);
                }
            };
            DatapathRelayResponse::granted(
                request.request_id().to_vec(),
                operation,
                request.relay_node_id().to_vec(),
                request.relay_peer_id().to_vec(),
                signed_envelope(
                    response_type,
                    vec![u8::try_from(path_id).map_err(|_| FakeTransportError::Definitive)?],
                ),
            )
            .map_err(|_| FakeTransportError::Definitive)
        }
    }

    fn validate_fake_outer_scope(
        request_id: &[u8],
        deadline_unix_ms: u64,
        canonical_request: &[u8],
    ) -> Result<(), FakeTransportError> {
        let envelope =
            decode_canonical::<SignedEnvelope>(canonical_request, MAX_CONTROL_MESSAGE_SIZE)
                .map_err(|_| FakeTransportError::Definitive)?;
        if envelope.nonce.len() != 32
            || request_id != &envelope.nonce[..ID_BYTES]
            || deadline_unix_ms != envelope.expires_at_ms
        {
            return Err(FakeTransportError::Definitive);
        }
        Ok(())
    }

    struct ExactProbeVerifier {
        expected: Vec<(Vec<u8>, Vec<u8>)>,
    }

    struct ExactTestNativeIdentityProvider;

    impl ExitNativeRouteIdentityProvider for ExactTestNativeIdentityProvider {
        fn provide(
            &mut self,
            request: &ExitNativeRouteIdentityRequest,
        ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
            ExitNativeRouteIdentityOwner::new(
                *request,
                NativeRouteIdentity {
                    auth_commitment: request.auth_commitment().to_vec(),
                    certificate_sha256: vec![41; 32],
                    spki_sha256: vec![42; 32],
                    tls_server_name: "route.exit.example".to_owned(),
                    masque_context_id: request.masque_context_id(),
                    client_native_instance_id: request.client_native_instance_id().to_vec(),
                    exit_native_instance_id: TEST_EXIT_NATIVE_INSTANCE_ID.to_vec(),
                    credential_hpke_public_key: Vec::new(),
                },
                b"-----BEGIN CERTIFICATE-----\ntest-certificate\n-----END CERTIFICATE-----\n"
                    .to_vec(),
                b"-----BEGIN PRIVATE KEY-----\ntest-private-key\n-----END PRIVATE KEY-----\n"
                    .to_vec(),
            )
        }
    }

    impl ProbeEvidenceVerifier for ExactProbeVerifier {
        fn verify(&self, evidence: &ProbeEvidence<'_>) -> Result<(), ProbeEvidenceError> {
            let exact = self.expected.iter().any(|(permit, result)| {
                permit.as_slice() == evidence.signed_permit()
                    && result.as_slice() == evidence.signed_result()
            });
            let client_relay = evidence.client_relay();
            let relay_exit = evidence.relay_exit();
            if !exact
                || evidence.path_id() != 1
                || evidence.transport() != Transport::UdpSinglePath
                || evidence.address_family() != ProbeAddressFamily::Ipv4
                || client_relay.up_capacity_mbps != 100
                || client_relay.down_capacity_mbps != 100
                || relay_exit.up_capacity_mbps != 100
                || relay_exit.down_capacity_mbps != 100
                || client_relay.transmitted_bytes != 8_192
                || client_relay.received_bytes != 8_192
                || relay_exit.transmitted_bytes != 8_192
                || relay_exit.received_bytes != 8_192
                || client_relay.window_started_at_ms != NOW_MS - 50
                || client_relay.window_ended_at_ms != NOW_MS
                || relay_exit.window_started_at_ms != NOW_MS - 50
                || relay_exit.window_ended_at_ms != NOW_MS
            {
                return Err(ProbeEvidenceError::Rejected(
                    "test verifier requires the exact signed probe artifact",
                ));
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct RealTransportError;

    struct RealServiceTransport {
        exit: ExitService,
        exit_key: SigningKey,
        relay: RelayService,
        relay_key: SigningKey,
        control_node_id: [u8; 32],
        control_peer_id: Vec<u8>,
        route_context_id: [u8; ID_BYTES],
        exact_probe_evidence: Vec<(Vec<u8>, Vec<u8>)>,
        scope_events: Arc<Mutex<Vec<String>>>,
    }

    impl ReservationTransport for RealServiceTransport {
        type Error = RealTransportError;

        fn ambiguous_after_dispatch(_error: &Self::Error) -> bool {
            false
        }

        async fn endpoint_traversal_hints(
            &mut self,
            _bindings: Vec<EndpointTraversalBinding>,
        ) -> Result<Vec<volparossa_routing::TraversalEndpointHint>, Self::Error> {
            Ok(Vec::new())
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the integration test double dispatches every typed exit operation"
        )]
        async fn exit_forward(
            &mut self,
            _control: &DirectRelayCapability,
            request: &ExitForwardRequest,
        ) -> Result<ExitForwardResponse, Self::Error> {
            let operation = request
                .validated_operation()
                .map_err(|_| RealTransportError)?;
            if !crate::discovery::forward_request_scope_matches_for_test(request, operation, NOW_MS)
            {
                return Err(RealTransportError);
            }
            self.scope_events
                .lock()
                .expect("scope events")
                .push(format!("forward.{operation:?}"));
            let exit_public_key = self.exit_key.verifying_key().to_bytes();
            let responses = match operation {
                ExitForwardOperation::CapacityHold => {
                    let exit_key = &self.exit_key;
                    let accepted = self
                        .exit
                        .hold_capacity_with(
                            request.canonical_request(),
                            &self.control_node_id,
                            &self.control_peer_id,
                            NOW_MS,
                            exit_public_key,
                            |message| Some(exit_key.sign(message).to_bytes()),
                        )
                        .map_err(|_| RealTransportError)?;
                    vec![
                        accepted.signed_capability().to_vec(),
                        accepted.signed_hold().to_vec(),
                    ]
                }
                ExitForwardOperation::ProbePermit => {
                    let exit_key = &self.exit_key;
                    let accepted = self
                        .exit
                        .issue_probe_permit_with(
                            request.canonical_request(),
                            &self.control_node_id,
                            &self.control_peer_id,
                            NOW_MS,
                            exit_public_key,
                            |message| Some(exit_key.sign(message).to_bytes()),
                        )
                        .map_err(|_| RealTransportError)?;
                    vec![accepted.encoded().to_vec()]
                }
                ExitForwardOperation::FinalizeReservation => {
                    let verifier = ExactProbeVerifier {
                        expected: self.exact_probe_evidence.clone(),
                    };
                    let mut identity_provider = ExactTestNativeIdentityProvider;
                    let exit_key = &self.exit_key;
                    let route_context_id = self.route_context_id;
                    let accepted = self
                        .exit
                        .finalize_reservation_with_providers(
                            request.canonical_request(),
                            &self.control_node_id,
                            &self.control_peer_id,
                            NOW_MS,
                            exit_public_key,
                            &verifier,
                            &mut identity_provider,
                            TEST_EXIT_NATIVE_INSTANCE_ID,
                            move |path_id| real_exit_endpoint(route_context_id, path_id),
                            |message| Some(exit_key.sign(message).to_bytes()),
                        )
                        .map_err(|_| RealTransportError)?;
                    let (signed_exit, relay_authorizations) = accepted.into_signed_parts();
                    std::iter::once(signed_exit)
                        .chain(relay_authorizations)
                        .collect()
                }
                ExitForwardOperation::ConfirmRelay => {
                    let exit_key = &self.exit_key;
                    let accepted = self
                        .exit
                        .confirm_relay_with(
                            request.canonical_request(),
                            &self.control_node_id,
                            &self.control_peer_id,
                            NOW_MS,
                            exit_public_key,
                            |message| Some(exit_key.sign(message).to_bytes()),
                        )
                        .map_err(|_| RealTransportError)?;
                    vec![accepted.signed_receipt().to_vec()]
                }
                ExitForwardOperation::FetchExitAdvertisement
                | ExitForwardOperation::NativeProbePermit
                | ExitForwardOperation::NativeProbeAuthorize
                | ExitForwardOperation::NativeProbeReady
                | ExitForwardOperation::NativeProbeResult
                | ExitForwardOperation::UdpSessionStart
                | ExitForwardOperation::MptcpSessionStart
                | ExitForwardOperation::MpquicSessionStart
                | ExitForwardOperation::Unspecified => return Err(RealTransportError),
            };
            ExitForwardResponse::granted(
                request.forward_id().to_vec(),
                operation,
                request.exit_node_id().to_vec(),
                request.exit_peer_id().to_vec(),
                responses,
            )
            .map_err(|_| RealTransportError)
        }

        async fn datapath_relay(
            &mut self,
            _relay: &DirectRelayCapability,
            request: &DatapathRelayRequest,
        ) -> Result<DatapathRelayResponse, Self::Error> {
            let operation = request
                .validated_operation()
                .map_err(|_| RealTransportError)?;
            if !crate::discovery::datapath_request_scope_matches_for_test(
                request, operation, NOW_MS,
            ) {
                return Err(RealTransportError);
            }
            self.scope_events
                .lock()
                .expect("scope events")
                .push(format!("datapath.{operation:?}"));
            let signed_response = match operation {
                DatapathRelayOperation::ExecuteProbe => {
                    let mut replay = ReplayCache::new(2).map_err(|_| RealTransportError)?;
                    let permit = verify_control_message::<RelayProbePermit>(
                        request.exit_signed_authorization(),
                        NOW_MS,
                        TimePolicy::default(),
                        &mut replay,
                    )
                    .map_err(|_| RealTransportError)?
                    .into_message();
                    let nonce = generate_nonce();
                    let result = RelayProbeResult {
                        probe_id: permit.probe_id.clone(),
                        relay_probe_permit: request.exit_signed_authorization().to_vec(),
                        relay_node_id: permit.relay_node_id.clone(),
                        relay_peer_id: permit.relay_peer_id.clone(),
                        exit_node_id: permit.exit_node_id.clone(),
                        exit_peer_id: permit.exit_peer_id.clone(),
                        exit_boot_id: permit.exit_boot_id.clone(),
                        hold_id: permit.hold_id.clone(),
                        capability_id: permit.capability_id.clone(),
                        reservation_id: permit.reservation_id.clone(),
                        route_context_id: permit.route_context_id.clone(),
                        client_session_id: permit.client_session_id.clone(),
                        policy_hash: permit.policy_hash.clone(),
                        transport: permit.transport,
                        address_family: permit.address_family,
                        client_relay: Some(real_probe_leg(2_000)),
                        relay_exit: Some(real_probe_leg(3_000)),
                        measured_at_ms: NOW_MS,
                        expires_at_ms: permit.expires_at_ms,
                        nonce: nonce.to_vec(),
                    };
                    let signed_result = sign_control_message(
                        &result,
                        &self.relay_key,
                        NOW_MS,
                        result.expires_at_ms,
                        nonce,
                        TimePolicy::default(),
                    )
                    .map_err(|_| RealTransportError)?;
                    self.exact_probe_evidence.push((
                        request.exit_signed_authorization().to_vec(),
                        signed_result.clone(),
                    ));
                    signed_result
                }
                DatapathRelayOperation::ReservePath => {
                    let relay_key = &self.relay_key;
                    let route_context_id = self.route_context_id;
                    self.relay
                        .accept_request_with(
                            request.client_signed_request(),
                            NOW_MS,
                            relay_key.verifying_key().to_bytes(),
                            move |path_id| real_relay_endpoint(route_context_id, path_id),
                            |message| Some(relay_key.sign(message).to_bytes()),
                        )
                        .map_err(|_| RealTransportError)?
                        .encoded()
                        .to_vec()
                }
                DatapathRelayOperation::NativeProbeReady
                | DatapathRelayOperation::NativeProbeStart
                | DatapathRelayOperation::NativeProbeAuthorize
                | DatapathRelayOperation::UdpSessionStart
                | DatapathRelayOperation::MptcpSessionStart
                | DatapathRelayOperation::MpquicSessionStart
                | DatapathRelayOperation::Unspecified => return Err(RealTransportError),
            };
            DatapathRelayResponse::granted(
                request.request_id().to_vec(),
                operation,
                request.relay_node_id().to_vec(),
                request.relay_peer_id().to_vec(),
                signed_response,
            )
            .map_err(|_| RealTransportError)
        }
    }

    fn real_probe_leg(rtt_micros: u64) -> ProbeLegEvidence {
        ProbeLegEvidence {
            up_capacity_mbps: 100,
            down_capacity_mbps: 100,
            rtt_micros,
            transmitted_bytes: 8_192,
            received_bytes: 8_192,
            window_started_at_ms: NOW_MS - 50,
            window_ended_at_ms: NOW_MS,
            measured_at_ms: NOW_MS,
        }
    }

    fn real_public_endpoint(
        key_seed: u8,
        address: Ipv4Addr,
        port: u16,
    ) -> Option<PublicWireGuardEndpoint> {
        PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([key_seed; 32]),
            IpAddr::V4(address),
            port,
        )
        .ok()
    }

    fn real_exit_endpoint(
        route_context_id: [u8; ID_BYTES],
        path_id: u32,
    ) -> Option<ExitEndpointLease> {
        let path = u8::try_from(path_id).ok()?;
        ExitEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([201; 32]).ok()?,
            HelperLeaseHandle::from_bytes([220_u8.checked_add(path)?; 32]).ok()?,
            path_id,
            EndpointRole::Exit,
            real_public_endpoint(
                30_u8.checked_add(path)?,
                Ipv4Addr::new(8, 8, 4, 11),
                31_000_u16.checked_add(u16::from(path))?,
            )?,
        )
        .ok()
    }

    fn real_relay_endpoint(
        route_context_id: [u8; ID_BYTES],
        path_id: u32,
    ) -> Option<RelayEndpointLease> {
        let path = u8::try_from(path_id).ok()?;
        let offset = path.checked_mul(2)?;
        RelayEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([202; 32]).ok()?,
            HelperLeaseHandle::from_bytes([230_u8.checked_add(offset)?; 32]).ok()?,
            HelperLeaseHandle::from_bytes([231_u8.checked_add(offset)?; 32]).ok()?,
            path_id,
            EndpointRole::RelayClient,
            EndpointRole::RelayExit,
            real_public_endpoint(
                50_u8.checked_add(offset)?,
                Ipv4Addr::new(8, 8, 4, 12),
                32_000_u16.checked_add(u16::from(offset))?,
            )?,
            real_public_endpoint(
                51_u8.checked_add(offset)?,
                Ipv4Addr::new(8, 8, 4, 13),
                32_001_u16.checked_add(u16::from(offset))?,
            )?,
        )
        .ok()
    }

    struct FixtureIdentity {
        node_id: [u8; 32],
        peer_id: Libp2pPeerId,
        public_key: [u8; 32],
    }

    struct Fixture {
        transaction: UnmeasuredRouteSetup<FakeProtocol>,
        manager: RouteSetupManager<FakeProtocol, FakeLocal>,
        transport: FakeTransport,
        clock: FakeClock,
        shared: Arc<FakeShared>,
    }

    struct RealServiceFixture {
        transaction: UnmeasuredRouteSetup<ReservationSession>,
        manager: RouteSetupManager<ReservationSession, FakeLocal>,
        transport: RealServiceTransport,
        clock: FakeClock,
        shared: Arc<FakeShared>,
        scope_events: Arc<Mutex<Vec<String>>>,
    }

    struct ControlledRouteHandle {
        handle: RouteSetupHandle<FakeProtocol>,
        cancellation: watch::Receiver<bool>,
        result: oneshot::Sender<Result<EstablishedRoute<FakeProtocol>, RouteSetupFailure>>,
    }

    fn controlled_route_handle() -> ControlledRouteHandle {
        let (cancel, cancellation) = watch::channel(false);
        let (result, response) = oneshot::channel();
        ControlledRouteHandle {
            handle: RouteSetupHandle {
                cancel,
                result: Some(response),
            },
            cancellation,
            result,
        }
    }

    fn controlled_route_failure(cleanup: CleanupStatus) -> RouteSetupFailure {
        RouteSetupFailure {
            cause: RouteSetupError::Cancelled,
            cleanup,
            released_local_leases: 0,
            remote_grants_expire_only: false,
        }
    }

    async fn established_fake_route() -> (
        EstablishedRoute<FakeProtocol>,
        RouteSetupManager<FakeProtocol, FakeLocal>,
        Arc<FakeShared>,
    ) {
        let Fixture {
            transaction,
            manager,
            transport,
            clock,
            shared,
        } = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let established = manager
            .spawn(transaction, transport, clock)
            .wait()
            .await
            .expect("established fake route");
        (established, manager, shared)
    }

    #[tokio::test]
    async fn route_attempt_owner_busy_returns_second_handle_intact() {
        let first = controlled_route_handle();
        let second = controlled_route_handle();
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(first.handle).is_ok(), "first ownership slot");

        let returned = owner
            .adopt(second.handle)
            .expect_err("occupied ownership slot must return the supplied handle");
        let expected = controlled_route_failure(CleanupStatus::NotRequired);
        second
            .result
            .send(Err(expected))
            .expect("returned handle retains its result receiver");
        let failure = returned.wait().await.expect_err("controlled failure");
        assert_eq!(failure.cause, RouteSetupError::Cancelled);
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(
            !*first.cancellation.borrow(),
            "Busy must leave the retained first handle untouched"
        );

        drop(owner);
        let mut first_cancellation = first.cancellation;
        timeout(TEST_TIMEOUT, first_cancellation.changed())
            .await
            .expect("owner drop cancels retained first handle")
            .expect("first cancellation sender remains live until owner drop");
        assert!(*first_cancellation.borrow());
    }

    #[tokio::test]
    async fn route_attempt_owner_normal_failure_vacates_and_readopts() {
        for cleanup in [CleanupStatus::NotRequired, CleanupStatus::Destroyed] {
            let first = controlled_route_handle();
            let mut owner = RouteAttemptOwner::vacant();
            assert!(owner.adopt(first.handle).is_ok(), "pending route ownership");
            first
                .result
                .send(Err(controlled_route_failure(cleanup)))
                .expect("settlement receiver");

            let RouteAttemptSettlement::Failed(FailedRouteAttempt { mut owner, failure }) =
                owner.settle().await
            else {
                panic!("controlled route failure must return its owner");
            };
            assert_eq!(failure.cleanup, cleanup);
            assert!(matches!(owner.state, RouteAttemptState::Vacant));

            let replacement = controlled_route_handle();
            assert!(
                owner.adopt(replacement.handle).is_ok(),
                "definitively cleaned failure reopens the ownership slot"
            );
            drop(owner);
            let mut replacement_cancellation = replacement.cancellation;
            timeout(TEST_TIMEOUT, replacement_cancellation.changed())
                .await
                .expect("replacement cancellation")
                .expect("replacement cancellation sender");
            assert!(*replacement_cancellation.borrow());
        }
    }

    #[tokio::test]
    async fn route_attempt_owner_quarantined_failure_is_terminal_and_busy() {
        let first = controlled_route_handle();
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(first.handle).is_ok(), "pending route ownership");
        first
            .result
            .send(Err(controlled_route_failure(CleanupStatus::Quarantined)))
            .expect("settlement receiver");

        let RouteAttemptSettlement::Failed(FailedRouteAttempt { mut owner, failure }) =
            owner.settle().await
        else {
            panic!("quarantined failure must remain explicitly owned");
        };
        assert_eq!(failure.cleanup, CleanupStatus::Quarantined);
        assert!(matches!(owner.state, RouteAttemptState::Quarantined));

        let second = controlled_route_handle();
        let returned = owner
            .adopt(second.handle)
            .expect_err("quarantined ownership slot must stay occupied");
        second
            .result
            .send(Err(controlled_route_failure(CleanupStatus::NotRequired)))
            .expect("returned handle retains its result receiver");
        assert_eq!(
            returned
                .wait()
                .await
                .expect_err("controlled failure")
                .cleanup,
            CleanupStatus::NotRequired
        );
        let RouteAttemptSettlement::NotPending(owner) = owner.settle().await else {
            panic!("terminal quarantine is not a successful settlement");
        };
        assert!(matches!(owner.state, RouteAttemptState::Quarantined));
        assert!(matches!(
            owner.drain().await,
            RouteAttemptDrain::Quarantined
        ));
    }

    #[tokio::test]
    async fn route_attempt_owner_not_pending_is_typed_for_vacant_and_established() {
        let RouteAttemptSettlement::NotPending(vacant) =
            RouteAttemptOwner::<FakeProtocol>::vacant().settle().await
        else {
            panic!("vacant owner is not a successful route");
        };
        assert!(matches!(vacant.state, RouteAttemptState::Vacant));
        assert!(matches!(vacant.drain().await, RouteAttemptDrain::Vacant));

        let (route, manager, shared) = established_fake_route().await;
        let mut owner = RouteAttemptOwner::vacant();
        assert!(
            owner.adopt_established(route).is_ok(),
            "established ownership slot"
        );
        let RouteAttemptSettlement::NotPending(owner) = owner.settle().await else {
            panic!("already established owner is not a fresh settlement");
        };
        assert!(matches!(owner.state, RouteAttemptState::Established(_)));
        assert!(matches!(
            owner.drain().await,
            RouteAttemptDrain::Retired(RetirementOutcome::Destroyed { .. })
        ));
        assert_before(&shared.events(), "local.destroy", "protocol.release");
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn route_attempt_owner_success_remains_established_until_explicit_drain() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let controlled = controlled_route_handle();
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(controlled.handle).is_ok());
        controlled
            .result
            .send(Ok(route))
            .expect("pending owner retains the result receiver");

        let RouteAttemptSettlement::Established(owner) = owner.settle().await else {
            panic!("successful pending route must become established");
        };
        assert!(matches!(owner.state, RouteAttemptState::Established(_)));
        assert_eq!(retirement.outstanding(), 1);
        assert!(!shared.events().iter().any(|event| event == "local.destroy"));

        assert!(matches!(
            owner.drain().await,
            RouteAttemptDrain::Retired(RetirementOutcome::Destroyed { .. })
        ));
        assert_eq!(retirement.outstanding(), 0);
        let events = shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn route_attempt_owner_pending_drain_cancels_first_and_last_probe_gate() {
        for blocked_path in [1, 8] {
            let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
            fixture
                .shared
                .state
                .lock()
                .expect("fake state")
                .blocked_probe = Some(blocked_path);
            let probe_started = fixture.shared.probe_started.notified();
            let handle =
                fixture
                    .manager
                    .spawn(fixture.transaction, fixture.transport, fixture.clock);
            let mut owner = RouteAttemptOwner::vacant();
            assert!(owner.adopt(handle).is_ok());
            timeout(TEST_TIMEOUT, probe_started)
                .await
                .expect("selected probe gate reached");

            let RouteAttemptDrain::Failed(failure) = owner.drain().await else {
                panic!("draining a pending probe must return its cancellation failure");
            };
            assert_eq!(failure.cause, RouteSetupError::Cancelled);
            assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
            assert!(
                !fixture
                    .shared
                    .events()
                    .iter()
                    .any(|event| event == "local.prepare")
            );

            fixture.shared.late_probe_release.notify_one();
            wait_for_event(
                &fixture.shared,
                &format!("transport.late.probe.{blocked_path}"),
            )
            .await;
            fixture
                .manager
                .shutdown()
                .await
                .expect("clean manager shutdown");
        }
    }

    #[tokio::test]
    async fn route_attempt_owner_pending_late_success_is_immediately_retired() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let controlled = controlled_route_handle();
        let mut cancellation = controlled.cancellation;
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(controlled.handle).is_ok());
        let mut drain = Box::pin(owner.drain());

        tokio::select! {
            biased;
            _ = &mut drain => panic!("drain completed before the pending result arrived"),
            changed = cancellation.changed() => {
                changed.expect("drain keeps the cancellation sender alive");
            }
        }
        assert!(*cancellation.borrow());
        controlled
            .result
            .send(Ok(route))
            .expect("pending drain still owns the result receiver");
        assert!(matches!(
            timeout(TEST_TIMEOUT, &mut drain)
                .await
                .expect("late success teardown"),
            RouteAttemptDrain::Retired(RetirementOutcome::Destroyed { .. })
        ));
        assert_eq!(retirement.outstanding(), 0);
        let events = shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn route_attempt_owner_literal_drop_cancels_or_retires_exactly_once() {
        let controlled = controlled_route_handle();
        let mut cancellation = controlled.cancellation;
        let mut pending = RouteAttemptOwner::vacant();
        assert!(pending.adopt(controlled.handle).is_ok());
        drop(pending);
        timeout(TEST_TIMEOUT, cancellation.changed())
            .await
            .expect("pending owner cancellation")
            .expect("pending handle cancellation sender");
        assert!(*cancellation.borrow());
        assert!(cancellation.changed().await.is_err());

        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let mut established = RouteAttemptOwner::vacant();
        assert!(established.adopt_established(route).is_ok());
        drop(established);
        wait_for_event(&shared, "protocol.release").await;
        timeout(TEST_TIMEOUT, async {
            while retirement.outstanding() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("passive owner drop retirement");
        manager.shutdown().await.expect("clean manager shutdown");
        let events = shared.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_polled_route_attempt_settle_future_retires_late_success() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let controlled = controlled_route_handle();
        let mut cancellation = controlled.cancellation;
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(controlled.handle).is_ok());
        let mut settling = Box::pin(owner.settle());

        tokio::select! {
            biased;
            _ = &mut settling => panic!("settlement completed without a result"),
            () = tokio::task::yield_now() => {}
        }
        drop(settling);
        timeout(TEST_TIMEOUT, cancellation.changed())
            .await
            .expect("dropping the polled settlement cancels its handle")
            .expect("settlement cancellation sender");
        let late = controlled
            .result
            .send(Ok(route))
            .expect_err("dropped settlement must reject a late route result");
        drop(late);

        wait_for_event(&shared, "protocol.release").await;
        manager.shutdown().await.expect("clean manager shutdown");
        assert_eq!(retirement.outstanding(), 0);
        let events = shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_polled_route_attempt_drain_future_keeps_retirement_owned() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        shared.state.lock().expect("fake state").block_destroy = true;
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt_established(route).is_ok());
        let destroy_started = shared.destroy_started.notified();
        let mut drain = Box::pin(owner.drain());

        tokio::select! {
            biased;
            _ = &mut drain => panic!("blocked destroy unexpectedly completed"),
            () = destroy_started => {}
        }
        drop(drain);
        assert_eq!(retirement.outstanding(), 1);
        shared.destroy_release.notify_one();
        wait_for_event(&shared, "protocol.release").await;
        manager.shutdown().await.expect("clean manager shutdown");
        assert_eq!(retirement.outstanding(), 0);
        let events = shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_polled_pending_route_attempt_drain_retires_late_success() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let controlled = controlled_route_handle();
        let mut cancellation = controlled.cancellation;
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt(controlled.handle).is_ok());
        let mut drain = Box::pin(owner.drain());

        tokio::select! {
            biased;
            _ = &mut drain => panic!("pending drain completed without a result"),
            changed = cancellation.changed() => {
                changed.expect("pending drain cancellation sender");
            }
        }
        drop(drain);
        let late = controlled
            .result
            .send(Ok(route))
            .expect_err("dropped pending drain rejects its late route result");
        drop(late);

        wait_for_event(&shared, "protocol.release").await;
        manager.shutdown().await.expect("clean manager shutdown");
        assert_eq!(retirement.outstanding(), 0);
        let events = shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "protocol.release")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn route_attempt_owner_retired_quarantine_remains_owned_until_retry() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        {
            let mut state = shared.state.lock().expect("fake state");
            state.block_destroy = true;
            state.fail_destroy = true;
        }
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt_established(route).is_ok());
        let destroy_started = shared.destroy_started.notified();
        let mut drain = Box::pin(owner.drain());
        tokio::select! {
            biased;
            _ = &mut drain => panic!("blocked destroy unexpectedly completed"),
            () = destroy_started => {}
        }
        shared.destroy_release.notify_one();
        assert!(matches!(
            drain.await,
            RouteAttemptDrain::Retired(RetirementOutcome::Quarantined)
        ));
        assert_eq!(retirement.outstanding(), 1);
        assert_eq!(retirement.quarantined(), 1);
        assert!(
            !shared
                .events()
                .iter()
                .any(|event| event == "protocol.release")
        );

        shared.state.lock().expect("fake state").fail_destroy = false;
        let retry_started = shared.destroy_started.notified();
        timeout(TEST_TIMEOUT, retry_started)
            .await
            .expect("quarantined destroy retry");
        shared.destroy_release.notify_one();
        wait_for_event(&shared, "protocol.release").await;
        manager.shutdown().await.expect("clean manager shutdown");
        assert_eq!(retirement.outstanding(), 0);
        assert_eq!(retirement.quarantined(), 0);
    }

    #[tokio::test]
    async fn detached_shutdown_returns_while_quarantined_owner_keeps_retrying() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        shared.state.lock().expect("fake state").fail_destroy = true;

        assert_eq!(route.teardown().await, RetirementOutcome::Quarantined);
        assert_eq!(retirement.outstanding(), 1);
        assert_eq!(retirement.quarantined(), 1);

        manager.shutdown_detached();
        assert!(retirement.worker_alive());
        assert_eq!(retirement.outstanding(), 1);
        assert_eq!(retirement.quarantined(), 1);

        timeout(TEST_TIMEOUT, async {
            while shared
                .events()
                .iter()
                .filter(|event| event.as_str() == "local.destroy")
                .count()
                < 2
            {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("detached supervisor keeps retrying permanent quarantine");
        assert!(retirement.worker_alive());
        assert_eq!(retirement.outstanding(), 1);
        assert_eq!(retirement.quarantined(), 1);
        assert!(
            !shared
                .events()
                .iter()
                .any(|event| event == "protocol.release")
        );

        shared.state.lock().expect("fake state").fail_destroy = false;
        wait_for_event(&shared, "protocol.release").await;
        timeout(TEST_TIMEOUT, async {
            while retirement.worker_alive() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("detached supervisor exits after exact Destroy succeeds");
        assert_eq!(retirement.outstanding(), 0);
        assert_eq!(retirement.quarantined(), 0);
        assert!(!retirement.fail_stopped());
    }

    #[tokio::test]
    async fn route_attempt_owner_must_drain_before_manager_shutdown_completes() {
        let (route, manager, shared) = established_fake_route().await;
        let retirement = Arc::clone(manager.retirement_state());
        let mut owner = RouteAttemptOwner::vacant();
        assert!(owner.adopt_established(route).is_ok());
        let mut shutdown = tokio::spawn(manager.shutdown());
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                panic!("manager shutdown completed before owner drain")
            }
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(retirement.outstanding(), 1);

        assert!(matches!(
            owner.drain().await,
            RouteAttemptDrain::Retired(RetirementOutcome::Destroyed { .. })
        ));
        timeout(TEST_TIMEOUT, shutdown)
            .await
            .expect("shutdown after owner drain")
            .expect("shutdown task")
            .expect("clean manager shutdown");
        assert_eq!(retirement.outstanding(), 0);
        assert_before(&shared.events(), "local.destroy", "protocol.release");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one complete actor-bound real v4 service topology"
    )]
    fn real_service_fixture() -> RealServiceFixture {
        let shared = Arc::new(FakeShared::default());
        let scope_events = Arc::new(Mutex::new(Vec::new()));
        let policy =
            verified_development_manifest(NOW_MS, Vec::new()).expect("verified development policy");
        let policy_hash = *policy.policy_hash();
        let policy_version = policy.manifest_version();
        let policy_expires_at_ms = policy.expires_at_ms();
        assert!(policy_expires_at_ms >= NOW_MS + 60_000);

        let control_key = ephemeral_signing_key();
        let exit_key = ephemeral_signing_key();
        let relay_key = ephemeral_signing_key();
        let control = fixture_identity_from_signing_key(&control_key);
        let exit = fixture_identity_from_signing_key(&exit_key);
        let relay = fixture_identity_from_signing_key(&relay_key);
        let advertisement_expires_at_ms = (NOW_MS + 120_000).min(policy_expires_at_ms);
        let capability_expiry = advertisement_expires_at_ms.min(policy_expires_at_ms);
        let scoped_capability = |identity: &FixtureIdentity| DirectRelayCapability {
            node_id: identity.node_id,
            peer_id: identity.peer_id,
            public_key: identity.public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms,
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(identity.node_id),
            policy_version,
            policy_hash,
            policy_expires_at_ms,
            expires_at_ms: capability_expiry,
        };
        let control_capability = scoped_capability(&control);
        let relay_capability = scoped_capability(&relay);
        let exit_capability = ForwardedExitCapability {
            control_relay_node_id: control.node_id,
            control_relay_peer_id: control.peer_id,
            control_relay_public_key: control.public_key,
            control_relay_advertisement_sequence: 1,
            control_relay_advertisement_expires_at_ms: advertisement_expires_at_ms,
            control_relay_advertisement_payload_hash: control_capability.advertisement_payload_hash,
            exit_node_id: exit.node_id,
            exit_peer_id: exit.peer_id,
            exit_public_key: exit.public_key,
            exit_advertisement_sequence: 1,
            exit_advertisement_expires_at_ms: advertisement_expires_at_ms,
            exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(exit.node_id),
            policy_version,
            policy_hash,
            policy_expires_at_ms,
            expires_at_ms: capability_expiry,
        };
        let forwarded_exit = SelectedForwardedExit {
            authority: ProspectiveForwardedExit::from_capabilities(
                &control_capability,
                &exit_capability,
            )
            .expect("forwarded exit capability"),
            control_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-control-real").expect("operator"),
                asn: 64_410,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([44, 10, 1]),
            },
            exit_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-exit-real").expect("operator"),
                asn: 64_420,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([45, 10, 1]),
            },
            evidence_batch_id: [55; ID_BYTES],
        };
        let reservation_id = [71; ID_BYTES];
        let route_context_id = [72; ID_BYTES];
        let parameters = RouteSetupParameters {
            reservation_id,
            route_context_id,
            allowed_transports: vec![Transport::UdpSinglePath],
            reserved_up_mbps: 10,
            reserved_down_mbps: 20,
            policy_hash,
            probe_address_family: ProbeAddressFamily::Ipv4,
            post_probe_policy: PostProbeSelectionPolicy {
                requirements: FilterRequirements {
                    now: UnixTime::from_secs(NOW_MS / 1_000),
                    role: ServiceRole::Relay,
                    transport: SelectionTransport::UdpSinglePath,
                    policy_hash: PolicyHash::from_bytes(policy_hash),
                    minimum_capacity: Bandwidth::new(10, 20).expect("minimum capacity"),
                    address_family: Some(IpFamily::Ipv4),
                    region: Some("eu-west".to_owned()),
                    require_reachable: true,
                },
                relay_policy: RelaySelectionPolicy {
                    active_paths: 1,
                    minimum_paths: 1,
                    maximum_paths: 1,
                    warm_backup_paths: 0,
                    maximum_rtt_spread_ms: 20.0,
                    minimum_unique_throughput_gain_ratio: 0.10,
                    mix: SelectionMix {
                        high: 1.0,
                        diverse_middle: 0.0,
                        exploration: 0.0,
                    },
                },
            },
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            setup_expires_at_unix: NOW_MS / 1_000 + 20,
            hard_expires_at_unix: NOW_MS / 1_000 + 60,
            client_native_route_scope: Some(ClientNativeRouteScope {
                masque_context_id: 71,
                client_native_instance_id: [73; 32],
            }),
        };
        let relay_binding = relay_binding(
            &relay_capability,
            0,
            &forwarded_exit,
            &parameters.post_probe_policy.requirements,
        );
        let request = RouteSetupRequest::new(forwarded_exit, vec![relay_binding], parameters)
            .expect("real route request");
        let authorities = RouteSetupAuthorities {
            control: control_capability,
            exit: exit_capability,
            datapath_relays: vec![relay_capability],
        };
        let limits = RouteSetupLimits::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
            MAXIMUM_OUTBOUND_ATTEMPTS,
        )
        .expect("route limits");
        let transaction = RouteSetupTransaction::with_protocol_and_deadline(
            request,
            authorities,
            limits,
            ReservationSession::generate(128).expect("reservation session"),
            Instant::now() + limits.setup_timeout,
        )
        .expect("real reservation transaction");
        let local = FakeLocal {
            shared: Arc::clone(&shared),
        };
        let manager =
            RouteSetupManager::start(local, 1, Duration::from_secs(1), Duration::from_secs(1))
                .expect("route manager");
        let exit_service = ExitService::new_with_boot_id(
            ExitServiceConfig::enabled(
                exit.node_id,
                Bandwidth::new(500, 500).expect("exit bandwidth"),
                4,
                900,
                10,
                256,
            ),
            policy,
            None,
            [77; ID_BYTES],
        )
        .expect("exit service");
        let relay_service = RelayService::new(
            RelayServiceConfig::enabled(
                relay.node_id,
                Bandwidth::new(500, 500).expect("relay bandwidth"),
                4,
                900,
                30,
                128,
            ),
            None,
        )
        .expect("relay service");
        RealServiceFixture {
            transaction,
            manager,
            transport: RealServiceTransport {
                exit: exit_service,
                exit_key,
                relay: relay_service,
                relay_key,
                control_node_id: control.node_id,
                control_peer_id: control.peer_id.to_bytes(),
                route_context_id,
                exact_probe_evidence: Vec::new(),
                scope_events: Arc::clone(&scope_events),
            },
            clock: FakeClock::new(),
            shared,
            scope_events,
        }
    }

    #[allow(clippy::too_many_lines, reason = "complete bounded v4 test topology")]
    fn fixture(retirement_capacity: usize) -> Fixture {
        fixture_with_helper_timeout(retirement_capacity, Duration::from_secs(1))
    }

    #[allow(clippy::too_many_lines, reason = "complete bounded v4 test topology")]
    fn fixture_with_helper_timeout(
        retirement_capacity: usize,
        helper_call_timeout: Duration,
    ) -> Fixture {
        let shared = Arc::new(FakeShared::default());
        let control = fixture_identity();
        let exit = fixture_identity();
        let relay_identities = (0..8).map(|_| fixture_identity()).collect::<Vec<_>>();

        let control_capability = direct_capability(&control);
        let exit_capability = ForwardedExitCapability {
            control_relay_node_id: control.node_id,
            control_relay_peer_id: control.peer_id,
            control_relay_public_key: control.public_key,
            control_relay_advertisement_sequence: 1,
            control_relay_advertisement_expires_at_ms: NOW_MS + 60_000,
            control_relay_advertisement_payload_hash: control_capability.advertisement_payload_hash,
            exit_node_id: exit.node_id,
            exit_peer_id: exit.peer_id,
            exit_public_key: exit.public_key,
            exit_advertisement_sequence: 1,
            exit_advertisement_expires_at_ms: NOW_MS + 60_000,
            exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(exit.node_id),
            policy_version: 1,
            policy_hash: [33; 32],
            policy_expires_at_ms: NOW_MS + 60_000,
            expires_at_ms: NOW_MS + 60_000,
        };
        let datapath_relays = relay_identities
            .iter()
            .map(direct_capability)
            .collect::<Vec<_>>();
        let forwarded_exit = SelectedForwardedExit {
            authority: ProspectiveForwardedExit::from_capabilities(
                &control_capability,
                &exit_capability,
            )
            .expect("valid forwarded exit snapshot"),
            control_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-control").expect("operator"),
                asn: 64_499,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([44, 1, 1]),
            },
            exit_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-exit").expect("operator"),
                asn: 64_500,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([45, 1, 1]),
            },
            evidence_batch_id: [55; ID_BYTES],
        };
        let parameters = RouteSetupParameters {
            reservation_id: [11; ID_BYTES],
            route_context_id: [22; ID_BYTES],
            allowed_transports: vec![Transport::TcpMptcp],
            reserved_up_mbps: 10,
            reserved_down_mbps: 20,
            policy_hash: [33; 32],
            probe_address_family: ProbeAddressFamily::Ipv4,
            post_probe_policy: PostProbeSelectionPolicy {
                requirements: FilterRequirements {
                    now: UnixTime::from_secs(NOW_MS / 1_000),
                    role: ServiceRole::Relay,
                    transport: SelectionTransport::TcpMptcp,
                    policy_hash: PolicyHash::from_bytes([33; 32]),
                    minimum_capacity: Bandwidth::new(10, 20).expect("minimum capacity"),
                    address_family: Some(IpFamily::Ipv4),
                    region: Some("eu-west".to_owned()),
                    require_reachable: true,
                },
                relay_policy: RelaySelectionPolicy {
                    active_paths: 3,
                    minimum_paths: 2,
                    maximum_paths: 3,
                    warm_backup_paths: 0,
                    maximum_rtt_spread_ms: 20.0,
                    minimum_unique_throughput_gain_ratio: 0.10,
                    mix: SelectionMix {
                        high: 1.0,
                        diverse_middle: 0.0,
                        exploration: 0.0,
                    },
                },
            },
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            setup_expires_at_unix: NOW_MS / 1_000 + 20,
            hard_expires_at_unix: NOW_MS / 1_000 + 60,
            client_native_route_scope: Some(ClientNativeRouteScope {
                masque_context_id: 72,
                client_native_instance_id: [74; 32],
            }),
        };
        let relay_bindings = datapath_relays
            .iter()
            .enumerate()
            .map(|(index, capability)| {
                relay_binding(
                    capability,
                    index,
                    &forwarded_exit,
                    &parameters.post_probe_policy.requirements,
                )
            })
            .collect::<Vec<_>>();
        let request = RouteSetupRequest::new(forwarded_exit, relay_bindings, parameters)
            .expect("valid route request");

        {
            let mut state = shared.state.lock().expect("fake state");
            state.relay_paths = datapath_relays
                .iter()
                .enumerate()
                .map(|(index, capability)| {
                    (
                        capability.peer_id.to_bytes(),
                        u32::try_from(index + 1).expect("bounded path"),
                    )
                })
                .collect();
        }
        let authorities = RouteSetupAuthorities {
            control: control_capability,
            exit: exit_capability,
            datapath_relays,
        };
        let limits = RouteSetupLimits::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
            MAXIMUM_OUTBOUND_ATTEMPTS,
        )
        .expect("valid test limits");
        let transaction = RouteSetupTransaction::with_protocol_and_deadline(
            request,
            authorities,
            limits,
            FakeProtocol::new(Arc::clone(&shared)),
            Instant::now() + limits.setup_timeout,
        )
        .expect("valid transaction");
        let local = FakeLocal {
            shared: Arc::clone(&shared),
        };
        let manager = RouteSetupManager::start(
            local,
            retirement_capacity,
            Duration::from_secs(1),
            helper_call_timeout,
        )
        .expect("valid route manager");
        Fixture {
            transaction,
            manager,
            transport: FakeTransport {
                shared: Arc::clone(&shared),
            },
            clock: FakeClock::new(),
            shared,
        }
    }

    fn prospective_relay_bindings(
        authorities: &RouteSetupAuthorities,
        forwarded_exit: &SelectedForwardedExit,
        requirements: &FilterRequirements,
        prospective_indices: &[usize],
    ) -> Vec<ProspectiveRouteRelay> {
        prospective_indices
            .iter()
            .enumerate()
            .map(|(path_index, index)| {
                let capability = authorities
                    .datapath_relays
                    .get(*index)
                    .expect("fixture path index");
                relay_binding_with_path_id(
                    capability,
                    *index,
                    u32::try_from(path_index + 1).expect("bounded path id"),
                    forwarded_exit,
                    requirements,
                )
            })
            .collect()
    }

    fn forwarded_exit_from_authorities(
        authorities: &RouteSetupAuthorities,
    ) -> SelectedForwardedExit {
        SelectedForwardedExit {
            authority: ProspectiveForwardedExit::from_capabilities(
                &authorities.control,
                &authorities.exit,
            )
            .expect("fixture forwarded exit"),
            control_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-control").expect("operator"),
                asn: 64_499,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([44, 1, 1]),
            },
            exit_diversity: DiversitySnapshot {
                operator_id: OperatorId::new("operator-exit").expect("operator"),
                asn: 64_500,
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([45, 1, 1]),
            },
            evidence_batch_id: [55; ID_BYTES],
        }
    }

    fn rebuild_prospective_request(
        authorities: &RouteSetupAuthorities,
        prospective_indices: &[usize],
        parameters: RouteSetupParameters,
    ) -> RouteSetupRequest {
        let forwarded_exit = forwarded_exit_from_authorities(authorities);
        let prospective = prospective_relay_bindings(
            authorities,
            &forwarded_exit,
            &parameters.post_probe_policy.requirements,
            prospective_indices,
        );
        RouteSetupRequest::new(forwarded_exit, prospective, parameters)
            .expect("rebuilt route request")
    }

    fn fake_transaction(
        request: RouteSetupRequest,
        authorities: RouteSetupAuthorities,
        limits: RouteSetupLimits,
        shared: &Arc<FakeShared>,
    ) -> UnmeasuredRouteSetup<FakeProtocol> {
        RouteSetupTransaction::with_protocol_and_deadline(
            request,
            authorities,
            limits,
            FakeProtocol::new(Arc::clone(shared)),
            Instant::now() + limits.setup_timeout,
        )
        .expect("valid rebuilt transaction")
    }

    fn fixture_identity_from_signing_key(key: &SigningKey) -> FixtureIdentity {
        let public_key = key.verifying_key().to_bytes();
        let libp2p_public =
            identity::ed25519::PublicKey::try_from_bytes(&public_key).expect("Ed25519 public key");
        let peer_id = identity::PublicKey::from(libp2p_public).to_peer_id();
        FixtureIdentity {
            node_id: node_id_from_public_key(&public_key),
            peer_id,
            public_key,
        }
    }

    fn fixture_identity() -> FixtureIdentity {
        let key = identity::Keypair::generate_ed25519();
        let public_key = key
            .clone()
            .try_into_ed25519()
            .expect("Ed25519 identity")
            .public()
            .to_bytes();
        FixtureIdentity {
            node_id: node_id_from_public_key(&public_key),
            peer_id: key.public().to_peer_id(),
            public_key,
        }
    }

    fn direct_capability(identity: &FixtureIdentity) -> DirectRelayCapability {
        DirectRelayCapability {
            node_id: identity.node_id,
            peer_id: identity.peer_id,
            public_key: identity.public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms: NOW_MS + 60_000,
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(identity.node_id),
            policy_version: 1,
            policy_hash: [33; 32],
            policy_expires_at_ms: NOW_MS + 60_000,
            expires_at_ms: NOW_MS + 60_000,
        }
    }

    fn relay_binding(
        capability: &DirectRelayCapability,
        index: usize,
        forwarded_exit: &SelectedForwardedExit,
        requirements: &FilterRequirements,
    ) -> ProspectiveRouteRelay {
        relay_binding_with_path_id(
            capability,
            index,
            u32::try_from(index + 1).expect("bounded path id"),
            forwarded_exit,
            requirements,
        )
    }

    fn relay_binding_with_path_id(
        capability: &DirectRelayCapability,
        index: usize,
        path_id: u32,
        forwarded_exit: &SelectedForwardedExit,
        requirements: &FilterRequirements,
    ) -> ProspectiveRouteRelay {
        let octet = u8::try_from(index)
            .expect("bounded relay index")
            .saturating_add(46);
        let bandwidth = Bandwidth::new(500, 500).expect("test bandwidth");
        let reserved = Bandwidth::new(100, 100).expect("reserved bandwidth");
        let observed_network_prefix = ObservedNetworkPrefix::ipv4_24([octet, 1, 1]);
        let diversity = DiversitySnapshot {
            operator_id: OperatorId::new(format!("operator-relay-{index}")).expect("operator"),
            asn: 64_501 + u32::try_from(index).expect("bounded relay index"),
            observed_network_prefix,
        };
        let candidate = Candidate {
            advertisement: NodeAdvertisement {
                protocol_version: volparossa_core::PROTOCOL_VERSION,
                node_id: NodeId::new(hex::encode(capability.node_id)).expect("node id"),
                peer_id: CorePeerId::new(capability.peer_id.to_string()).expect("peer id"),
                sequence_number: capability.advertisement_sequence,
                roles: NodeRoles {
                    client: false,
                    relay: true,
                    exit: false,
                },
                capabilities: NodeCapabilities {
                    tcp_mptcp: true,
                    udp_single_path: true,
                    multipath_quic: true,
                    ipv4: true,
                    ipv6: false,
                    udp_hole_punching: false,
                },
                capacity: CapacitySnapshot {
                    relay_limit: bandwidth,
                    exit_limit: Bandwidth::new(0, 0).expect("zero bandwidth"),
                    currently_reserved: Bandwidth::new(0, 0).expect("zero bandwidth"),
                    estimated_free: bandwidth,
                    active_relay_sessions: 0,
                    active_exit_sessions: 0,
                    free_relay_slots: 8,
                    free_exit_slots: 0,
                    sample_window_seconds: 30,
                },
                network: NetworkMetadata {
                    operator_id: diversity.operator_id.clone(),
                    region: "eu-west".to_owned(),
                    country_code: "NL".to_owned(),
                    asn: Some(diversity.asn),
                    ipv4_prefix_hint: None,
                    ipv6_prefix_hint: None,
                },
                quality: NodeQuality {
                    local_uptime_seconds: 600,
                    historical_uptime_score: 0.9,
                    historical_delivery_ratio_p25: 0.8,
                },
                policy_hash: PolicyHash::from_bytes(capability.policy_hash),
                control_endpoints: vec![format!("/ip4/{octet}.1.1.1/udp/4001/quic-v1")],
                measured_at: UnixTime::from_secs(NOW_MS / 1_000 - 1),
                expires_at: UnixTime::from_secs(capability.advertisement_expires_at_ms / 1_000),
            },
            signature_verified: true,
            evidence: CandidateEvidence {
                locally_measured_p25: Some(bandwidth),
                reserved_path_limit: reserved,
                uptime_score: 0.9,
                reputation_score: 0.8,
                proximity_score: 0.8,
                recent_egress_quality: 0.8,
                rtt_ms: Some(10.0 + f64::from(u32::try_from(index).expect("bounded relay index"))),
                measurement_count: 4,
                reachable: true,
                network_address_usable: true,
                observed_network_origin: None,
                locally_blocked: false,
                serious_protocol_fault_until: None,
            },
        };
        let proof = selection_bridge::actor_bound_relay_proof_for_test(
            capability,
            candidate,
            diversity,
            forwarded_exit,
            forwarded_exit.evidence_batch_id,
            NOW_MS,
            requirements.clone(),
        );
        ProspectiveRouteRelay { path_id, proof }
    }

    fn signed_envelope(message_type: ControlMessageType, payload: Vec<u8>) -> Vec<u8> {
        signed_envelope_at(message_type, payload, NOW_MS + 30_000)
    }

    fn signed_envelope_at(
        message_type: ControlMessageType,
        payload: Vec<u8>,
        expires_at_ms: u64,
    ) -> Vec<u8> {
        let mut nonce = vec![43; 32];
        nonce[0] = u8::try_from(message_type as i32).unwrap_or(43);
        if let Some(path_id) = payload.first() {
            nonce[1] = *path_id;
        }
        encode_canonical(
            &SignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                sender_id: vec![41; 32],
                sender_public_key: vec![42; 32],
                timestamp_ms: NOW_MS,
                expires_at_ms,
                nonce,
                message_type: message_type as i32,
                payload,
                payload_hash: vec![44; 32],
                signature: vec![45; 64],
            },
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("canonical fake envelope")
    }

    fn envelope_payload(
        encoded: &[u8],
        expected: ControlMessageType,
        phase: RouteSetupPhase,
    ) -> Result<Vec<u8>, RouteSetupError> {
        let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| RouteSetupError::ReservationProtocol(phase))?;
        if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32
        {
            return Err(RouteSetupError::ReservationProtocol(phase));
        }
        Ok(envelope.payload)
    }

    fn payload_path(
        encoded: &[u8],
        expected: ControlMessageType,
        phase: RouteSetupPhase,
    ) -> Result<u32, RouteSetupError> {
        let payload = envelope_payload(encoded, expected, phase)?;
        match payload.as_slice() {
            [path] if *path != 0 => Ok(u32::from(*path)),
            _ => Err(RouteSetupError::ReservationProtocol(phase)),
        }
    }

    fn require_path_payload(
        encoded: &[u8],
        expected: ControlMessageType,
        path_id: u32,
        phase: RouteSetupPhase,
    ) -> Result<(), RouteSetupError> {
        if payload_path(encoded, expected, phase)? != path_id {
            return Err(RouteSetupError::ReservationProtocol(phase));
        }
        Ok(())
    }

    fn finalized_response(path_ids: Vec<u32>) -> Result<Vec<Vec<u8>>, FakeTransportError> {
        if path_ids.is_empty() {
            return Err(FakeTransportError::Definitive);
        }
        let maximum_paths =
            u32::try_from(path_ids.len()).map_err(|_| FakeTransportError::Definitive)?;
        let exit_payload = encode_canonical(
            &ExitReservation {
                maximum_paths,
                ..ExitReservation::default()
            },
            MAX_CONTROL_PAYLOAD_SIZE,
        )
        .map_err(|_| FakeTransportError::Definitive)?;
        let mut responses = vec![signed_envelope(
            ControlMessageType::ExitReservation,
            exit_payload,
        )];
        for path_id in path_ids {
            let payload = encode_canonical(
                &RelayAuthorization {
                    path_id,
                    ..RelayAuthorization::default()
                },
                MAX_CONTROL_PAYLOAD_SIZE,
            )
            .map_err(|_| FakeTransportError::Definitive)?;
            responses.push(signed_envelope(
                ControlMessageType::RelayAuthorization,
                payload,
            ));
        }
        Ok(responses)
    }

    fn assert_before(events: &[String], first: &str, second: &str) {
        let first_index = events
            .iter()
            .position(|event| event == first)
            .unwrap_or_else(|| panic!("missing event {first}: {events:?}"));
        let second_index = events
            .iter()
            .position(|event| event == second)
            .unwrap_or_else(|| panic!("missing event {second}: {events:?}"));
        assert!(
            first_index < second_index,
            "{first} must precede {second}: {events:?}"
        );
    }

    async fn wait_for_event(shared: &FakeShared, expected: &str) {
        timeout(TEST_TIMEOUT, async {
            loop {
                if shared
                    .state
                    .lock()
                    .expect("fake state")
                    .events
                    .iter()
                    .any(|event| event == expected)
                {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected}"));
    }

    async fn wait_for_fail_stop(state: &retirement::RetirementState) {
        timeout(TEST_TIMEOUT, async {
            while !state.fail_stopped() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("retirement fail-stop");
    }

    #[test]
    fn activation_copies_exact_grant_wires_by_path_in_canonical_order_and_digest() {
        let route_context_id = [22; ID_BYTES];
        let batch = bound_activation_batch(route_context_id, &[2, 5, 8], &[8, 2, 5]);
        let wires = BTreeMap::from([
            (2, vec![0x00, 0x82, 0xff, 0x02]),
            (5, vec![0x05, 0x00, 0xa5, 0x5a, 0x05]),
            (8, vec![0x88, 0x08, 0x00, 0xfe]),
        ]);
        let grants = [
            fake_relay_grant(5, wires.get(&5).expect("path 5 wire")),
            fake_relay_grant(8, wires.get(&8).expect("path 8 wire")),
            fake_relay_grant(2, wires.get(&2).expect("path 2 wire")),
        ];

        let activation = activation_request::<FakeProtocol>(route_context_id, &batch, &grants)
            .expect("exact provenance-bound activation");
        assert_eq!(
            activation
                .leases
                .iter()
                .map(|lease| lease.path_id)
                .collect::<Vec<_>>(),
            [2, 5, 8]
        );
        for lease in &activation.leases {
            assert_eq!(
                &lease.signed_relay_reservation,
                wires.get(&lease.path_id).expect("wire for activation path"),
                "one path must receive only its own retained envelope"
            );
        }

        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![0xa7; ID_BYTES],
            operation: Some(helper_request::Operation::ActivateLeaseBatch(
                activation.clone(),
            )),
        };
        let digest = operation_digest(&request).expect("provenance-bound digest");

        let mut without_provenance = request.clone();
        let Some(helper_request::Operation::ActivateLeaseBatch(batch)) =
            without_provenance.operation.as_mut()
        else {
            panic!("Activate operation");
        };
        for lease in &mut batch.leases {
            lease.signed_relay_reservation.clear();
        }
        assert_ne!(
            digest,
            operation_digest(&without_provenance).expect("legacy digest"),
            "the exact retained envelopes must affect the helper operation digest"
        );

        let mut substituted = request;
        let Some(helper_request::Operation::ActivateLeaseBatch(batch)) =
            substituted.operation.as_mut()
        else {
            panic!("Activate operation");
        };
        let first_wire = batch.leases[0].signed_relay_reservation.clone();
        batch.leases[0].signed_relay_reservation = batch.leases[2].signed_relay_reservation.clone();
        batch.leases[2].signed_relay_reservation = first_wire;
        assert_ne!(
            digest,
            operation_digest(&substituted).expect("path-substituted digest"),
            "moving exact grant bytes to another path must change the digest"
        );
    }

    #[test]
    fn activation_fails_closed_on_missing_empty_ambiguous_or_foreign_provenance() {
        let route_context_id = [22; ID_BYTES];
        let batch = bound_activation_batch(route_context_id, &[2, 5], &[5, 2]);
        let phase_error = |result: Result<ActivateLeaseBatch, RouteSetupError>| {
            assert_eq!(
                result.expect_err("invalid provenance must fail closed"),
                RouteSetupError::ReservationProtocol(RouteSetupPhase::Activating)
            );
        };

        phase_error(activation_request::<FakeProtocol>(
            route_context_id,
            &batch,
            &[fake_relay_grant(2, &[0x22])],
        ));
        phase_error(activation_request::<FakeProtocol>(
            route_context_id,
            &batch,
            &[fake_relay_grant(2, &[]), fake_relay_grant(5, &[0x55])],
        ));
        phase_error(activation_request::<FakeProtocol>(
            route_context_id,
            &batch,
            &[fake_relay_grant(2, &[0x21]), fake_relay_grant(2, &[0x22])],
        ));
        phase_error(activation_request::<FakeProtocol>(
            route_context_id,
            &batch,
            &[fake_relay_grant(2, &[0x22]), fake_relay_grant(8, &[0x88])],
        ));
        phase_error(activation_request::<FakeProtocol>(
            route_context_id,
            &batch,
            &[
                fake_relay_grant(2, &[0x22]),
                fake_relay_grant(5, &[0x55]),
                fake_relay_grant(8, &[0x88]),
            ],
        ));
        phase_error(activation_request::<FakeProtocol>(
            [23; ID_BYTES],
            &batch,
            &[fake_relay_grant(2, &[0x22]), fake_relay_grant(5, &[0x55])],
        ));
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the full phase-order test also proves one signed frame across exact retries"
    )]
    async fn v4_phase_order_uses_real_probes_noncontiguous_subset_and_exact_retry_bytes() {
        let mut fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let forwarding_expiry_ms = NOW_MS + 20_000;
        fixture
            .transaction
            .transaction
            .authorities
            .exit
            .expires_at_ms = forwarding_expiry_ms;
        {
            fixture
                .shared
                .state
                .lock()
                .expect("fake state")
                .ambiguous_exit = Some((ExitForwardOperation::FinalizeReservation as i32, 2));
        }
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");

        let grant_paths = established
            .relay_grants
            .iter()
            .map(|grant| grant.path_id)
            .collect::<Vec<_>>();
        assert_eq!(grant_paths, [2, 5, 8]);
        assert_eq!(fixture.shared.selected_paths(), [2, 5, 8]);

        let events = fixture.shared.events();
        assert_before(
            &events,
            "transport.exit.CapacityHold.1",
            "protocol.verify.hold",
        );
        assert_before(&events, "protocol.verify.hold", "protocol.sign.permit.1");
        assert_before(
            &events,
            "protocol.verify.permit.8",
            "transport.datapath.ExecuteProbe.1.1",
        );
        assert_before(&events, "protocol.verify.probe.8", "local.prepare");
        assert_before(&events, "local.prepare", "protocol.sign.finalize.[2, 5, 8]");
        assert_before(&events, "protocol.verify.finalize", "protocol.sign.relay.2");
        assert_before(
            &events,
            "protocol.verify.relay.8",
            "protocol.sign.confirm.2",
        );
        assert_before(&events, "protocol.verify.receipt.8", "local.activate");
        assert_before(&events, "local.activate", "local.commit");
        for path_id in [2, 5, 8] {
            assert!(events.contains(&format!("protocol.verify.receipt.{path_id}")));
            assert!(events.iter().any(|event| {
                event.starts_with(&format!("transport.datapath.ReservePath.{path_id}."))
            }));
        }
        assert!(!events.iter().any(|event| {
            event.starts_with("transport.datapath.ReservePath.")
                && ![".2.", ".5.", ".8."]
                    .iter()
                    .any(|needle| event.contains(needle))
        }));

        {
            let state = fixture.shared.state.lock().expect("fake state");
            let session_token = state.session_tokens[0];
            assert_eq!(
                state.finalized_probe_tokens,
                [(session_token, 2), (session_token, 5), (session_token, 8)]
            );
            let finalize_attempts = state
                .exit_attempts
                .get(&(ExitForwardOperation::FinalizeReservation as i32));
            assert_eq!(finalize_attempts, Some(&3));
            let frames = state
                .exit_frames
                .get(&(ExitForwardOperation::FinalizeReservation as i32))
                .expect("finalize frames");
            assert_eq!(frames.len(), 3);
            assert!(frames.windows(2).all(|pair| pair[0] == pair[1]));
            let confirmations = state
                .exit_frames
                .get(&(ExitForwardOperation::ConfirmRelay as i32))
                .expect("confirmation frames");
            assert_eq!(confirmations.len(), 3);
            assert!(
                confirmations
                    .iter()
                    .all(|frame| frame.deadline_unix_ms() == forwarding_expiry_ms),
                "Exit confirmations must not outlive short forwarding authority"
            );
            let [activation] = state.activation_batches.as_slice() else {
                panic!("one exact activation batch");
            };
            assert_eq!(
                activation
                    .leases
                    .iter()
                    .map(|lease| lease.path_id)
                    .collect::<Vec<_>>(),
                [2, 5, 8]
            );
            for (lease, grant) in activation.leases.iter().zip(&established.relay_grants) {
                assert_eq!(lease.path_id, grant.path_id);
                assert_eq!(
                    lease.signed_relay_reservation, grant.signed_relay_reservation,
                    "verified response bytes must reach the same-path activation unchanged"
                );
            }
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("protocol.sign.finalize"))
                .count(),
            1,
            "one finalize frame is signed before retrying its exact bytes"
        );

        let retirement_state = Arc::clone(fixture.manager.retirement_state());
        assert_eq!(retirement_state.outstanding(), 1);
        assert_eq!(
            established.teardown().await,
            RetirementOutcome::Destroyed {
                released_local_leases: 3,
            }
        );
        assert_eq!(retirement_state.outstanding(), 0);
        assert_eq!(retirement_state.quarantined(), 0);
        let events = fixture.shared.events();
        let destroy = events
            .iter()
            .rposition(|event| event == "local.destroy")
            .expect("destroy event");
        let release = events
            .iter()
            .rposition(|event| event == "protocol.release")
            .expect("release event");
        assert!(
            destroy < release,
            "Destroy must precede coordinator release"
        );
    }

    #[tokio::test]
    async fn non_clone_probe_tokens_reach_finalize_exactly_once_for_selected_2_5_8() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");

        {
            let state = fixture.shared.state.lock().expect("fake state");
            let session_token = state.session_tokens[0];
            assert_eq!(
                state.finalized_probe_tokens,
                [(session_token, 2), (session_token, 5), (session_token, 8)]
            );
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| event.starts_with("protocol.sign.finalize"))
                    .count(),
                1
            );
        }
        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn noncontiguous_selection_reaches_prepare_in_canonical_identity_order() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");

        assert_eq!(fixture.shared.selected_paths(), [2, 5, 8]);
        assert_eq!(
            fixture.shared.prepared_lease_identities(),
            Some(vec![
                (2, WireguardRole::Client as i32),
                (5, WireguardRole::Client as i32),
                (8, WireguardRole::Client as i32),
            ]),
            "the actual LocalRouteBackend Prepare call must preserve canonical identity order"
        );

        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn carried_deadline_factory_accepts_expired_and_boundary_but_rejects_overlong() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let authorities = fixture.transaction.transaction.authorities.clone();
        let parameters = fixture.transaction.transaction.request.parameters.clone();
        let limits = fixture.transaction.transaction.limits;
        let make_request = || {
            rebuild_prospective_request(&authorities, &[0, 1, 2, 3, 4, 5, 6, 7], parameters.clone())
        };

        let boundary = Instant::now() + limits.setup_timeout;
        let boundary_setup = RouteSetupTransaction::with_protocol_and_deadline(
            make_request(),
            authorities.clone(),
            limits,
            FakeProtocol::new(Arc::clone(&fixture.shared)),
            boundary,
        )
        .expect("exact setup-timeout boundary is accepted");
        assert_eq!(boundary_setup.deadline, boundary);

        let expired = Instant::now() - Duration::from_millis(1);
        let expired_setup = RouteSetupTransaction::with_protocol_and_deadline(
            make_request(),
            authorities.clone(),
            limits,
            FakeProtocol::new(Arc::clone(&fixture.shared)),
            expired,
        )
        .expect("an already-expired deadline remains assembled for the pre-RPC live check");
        assert_eq!(expired_setup.deadline, expired);

        let overlong = Instant::now() + limits.setup_timeout + Duration::from_secs(1);
        assert!(matches!(
            RouteSetupTransaction::with_protocol_and_deadline(
                make_request(),
                authorities,
                limits,
                FakeProtocol::new(Arc::clone(&fixture.shared)),
                overlong,
            ),
            Err(RouteSetupError::Invalid("setup deadline"))
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn expired_unmeasured_before_spawn_emits_zero_protocol_or_transport_events() {
        let mut fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        fixture.transaction.deadline = Instant::now();
        let retirement = Arc::clone(fixture.manager.retirement_state());
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let failure = handle
            .wait()
            .await
            .expect_err("expired unmeasured setup fails before its first RPC");

        assert_eq!(
            failure.cause,
            RouteSetupError::Deadline(RouteSetupPhase::Validated)
        );
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(!failure.remote_grants_expire_only);
        assert_eq!(retirement.outstanding(), 0);
        {
            let state = fixture.shared.state.lock().expect("fake state");
            assert!(state.events.is_empty());
            assert!(state.exit_attempts.is_empty());
            assert!(state.datapath_attempts.is_empty());
            assert!(state.selected_paths.is_empty());
        }
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn measured_continuation_preserves_single_session_attempt_ids_and_deadline() {
        let Fixture {
            transaction,
            manager,
            mut transport,
            clock,
            shared,
        } = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let context = manager.context.clone();
        let session_token = transaction
            .transaction
            .protocol
            .as_ref()
            .expect("unmeasured protocol")
            .session_token
            .0;
        let reservation_id = transaction.transaction.request.parameters.reservation_id;
        let route_context_id = transaction.transaction.request.parameters.route_context_id;
        let deadline = transaction.deadline;
        let (_cancel_sender, mut cancellation) = watch::channel(false);

        let Ok(measured) = transaction
            .measure_owned(&mut transport, &clock, &mut cancellation)
            .await
        else {
            panic!("measurement must preserve the owned transaction");
        };
        assert_eq!(measured.deadline, deadline);
        assert_eq!(
            measured
                .transaction
                .protocol
                .as_ref()
                .expect("measured protocol")
                .session_token
                .0,
            session_token
        );
        assert_eq!(
            measured.transaction.request.parameters.reservation_id,
            reservation_id
        );
        assert_eq!(
            measured.transaction.request.parameters.route_context_id,
            route_context_id
        );

        let established = measured
            .finish_owned(context, &mut transport, &clock, &mut cancellation)
            .await
            .expect("same measured continuation finishes");
        let continued_protocol = established
            .owner
            .as_ref()
            .and_then(PreparedContextOwner::protocol)
            .expect("established owner retains protocol");
        assert_eq!(continued_protocol.session_token.0, session_token);
        assert_eq!(
            established.request.parameters.reservation_id,
            reservation_id
        );
        assert_eq!(
            established.request.parameters.route_context_id,
            route_context_id
        );
        assert_eq!(
            shared.state.lock().expect("fake state").session_tokens,
            [session_token]
        );
        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn cancellation_between_measurement_and_finish_never_prepares_or_remints() {
        let Fixture {
            transaction,
            manager,
            mut transport,
            clock,
            shared,
        } = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let context = manager.context.clone();
        let session_token = transaction
            .transaction
            .protocol
            .as_ref()
            .expect("unmeasured protocol")
            .session_token
            .0;
        let (cancel_sender, mut cancellation) = watch::channel(false);
        let Ok(measured) = transaction
            .measure_owned(&mut transport, &clock, &mut cancellation)
            .await
        else {
            panic!("measurement must complete before cancellation");
        };
        assert_eq!(
            measured
                .transaction
                .protocol
                .as_ref()
                .expect("measured protocol")
                .session_token
                .0,
            session_token
        );
        cancel_sender.send(true).expect("cancel continuation");

        let failure = measured
            .finish_owned(context, &mut transport, &clock, &mut cancellation)
            .await
            .expect_err("cancelled continuation cannot finish");
        assert_eq!(failure.cause, RouteSetupError::Cancelled);
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(failure.remote_grants_expire_only);
        {
            let state = shared.state.lock().expect("fake state");
            assert_eq!(state.session_tokens, [session_token]);
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| event.as_str() == "protocol.sign.hold")
                    .count(),
                1
            );
            assert!(!state.events.iter().any(|event| event == "local.prepare"));
        }
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn expired_carried_deadline_at_measurement_finish_seam_never_prepares_or_remints() {
        let Fixture {
            transaction,
            manager,
            mut transport,
            clock,
            shared,
        } = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let context = manager.context.clone();
        let session_token = transaction
            .transaction
            .protocol
            .as_ref()
            .expect("unmeasured protocol")
            .session_token
            .0;
        let deadline = transaction.deadline;
        let (_cancel_sender, mut cancellation) = watch::channel(false);
        let Ok(mut measured) = transaction
            .measure_owned(&mut transport, &clock, &mut cancellation)
            .await
        else {
            panic!("measurement must complete before the carried deadline");
        };
        assert_eq!(measured.deadline, deadline);
        assert!(measured.transaction.request.paths.is_empty());
        let selected_path_ids = measured
            .measurement
            .selected_paths
            .iter()
            .map(|path| path.path_id)
            .collect::<BTreeSet<_>>();
        let selected_probe_ids = measured
            .measurement
            .selected_probes
            .iter()
            .map(|probe| probe.projection.path_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(selected_path_ids, selected_probe_ids);
        assert_eq!(
            selected_path_ids,
            measured
                .measurement
                .active_path_ids
                .iter()
                .chain(&measured.measurement.warm_path_ids)
                .copied()
                .collect()
        );
        measured.deadline = Instant::now();

        let failure = measured
            .finish_owned(context, &mut transport, &clock, &mut cancellation)
            .await
            .expect_err("expired measured continuation cannot reset its deadline");
        assert_eq!(
            failure.cause,
            RouteSetupError::Deadline(RouteSetupPhase::ExecuteProbes)
        );
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(failure.remote_grants_expire_only);
        assert_eq!(manager.retirement_state().outstanding(), 0);
        {
            let state = shared.state.lock().expect("fake state");
            assert_eq!(state.session_tokens, [session_token]);
            assert!(!state.events.iter().any(|event| {
                event == "local.prepare" || event.starts_with("protocol.sign.finalize")
            }));
        }
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn measurement_error_returns_original_transaction_for_single_rollback() {
        let Fixture {
            transaction,
            manager,
            mut transport,
            clock,
            shared,
        } = fixture(MAXIMUM_RETIREMENT_OWNERS);
        shared.state.lock().expect("fake state").unavailable_probe = Some(1);
        let session_token = transaction
            .transaction
            .protocol
            .as_ref()
            .expect("unmeasured protocol")
            .session_token
            .0;
        let reservation_id = transaction.transaction.request.parameters.reservation_id;
        let route_context_id = transaction.transaction.request.parameters.route_context_id;
        let original_path_ids = transaction
            .transaction
            .request
            .paths
            .iter()
            .map(|path| path.path_id)
            .collect::<Vec<_>>();
        let (_cancel_sender, mut cancellation) = watch::channel(false);

        let Err(InterruptedRouteSetup { transaction, cause }) = transaction
            .measure_owned(&mut transport, &clock, &mut cancellation)
            .await
        else {
            panic!("unavailable probe must interrupt measurement");
        };
        assert_eq!(
            cause,
            RouteSetupError::RemoteUnavailable(RouteSetupPhase::ExecuteProbes)
        );
        assert_eq!(
            transaction
                .protocol
                .as_ref()
                .expect("interrupted protocol")
                .session_token
                .0,
            session_token
        );
        assert_eq!(
            transaction.request.parameters.reservation_id,
            reservation_id
        );
        assert_eq!(
            transaction.request.parameters.route_context_id,
            route_context_id
        );
        assert_eq!(
            transaction
                .request
                .paths
                .iter()
                .map(|path| path.path_id)
                .collect::<Vec<_>>(),
            original_path_ids
        );
        let failure = transaction.rollback(cause).await;
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(failure.remote_grants_expire_only);
        {
            let state = shared.state.lock().expect("fake state");
            assert_eq!(state.session_tokens, [session_token]);
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| event.as_str() == "protocol.sign.hold")
                    .count(),
                1
            );
            assert!(!state.events.iter().any(|event| {
                matches!(
                    event.as_str(),
                    "local.prepare" | "local.destroy" | "protocol.release"
                )
            }));
        }
        manager.shutdown().await.expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn received_probe_unavailable_is_definitive_and_never_prepares_helper() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .unavailable_probe = Some(1);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let failure = handle.wait().await.expect_err("probe unavailable");
        assert_eq!(
            failure.cause,
            RouteSetupError::RemoteUnavailable(RouteSetupPhase::ExecuteProbes)
        );
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        let state = fixture.shared.state.lock().expect("fake state");
        assert_eq!(
            state
                .datapath_attempts
                .get(&(DatapathRelayOperation::ExecuteProbe as i32, 1)),
            Some(&1)
        );
        assert!(!state.events.iter().any(|event| event == "local.prepare"));
    }

    #[tokio::test]
    async fn cancellation_ignores_late_probe_result_and_stays_before_prepare() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .blocked_probe = Some(1);
        let probe_started = fixture.shared.probe_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, probe_started)
            .await
            .expect("probe started");
        handle.cancel();
        let failure = handle.wait().await.expect_err("cancelled probe");
        assert_eq!(failure.cause, RouteSetupError::Cancelled);
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        fixture.shared.late_probe_release.notify_one();
        wait_for_event(&fixture.shared, "transport.late.probe.1").await;
        assert!(
            !fixture
                .shared
                .events()
                .iter()
                .any(|event| event == "local.prepare")
        );
    }

    #[tokio::test]
    async fn cancellation_after_prepare_is_destroy_first_and_fail_atomic() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .block_prepare = true;
        let prepare_started = fixture.shared.prepare_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, prepare_started)
            .await
            .expect("prepare started");
        handle.cancel();
        fixture.shared.prepare_release.notify_one();
        let failure = handle.wait().await.expect_err("cancel after prepare");
        assert_eq!(failure.cause, RouteSetupError::Cancelled);
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        let events = fixture.shared.events();
        assert!(
            !events
                .iter()
                .any(|event| event.starts_with("protocol.sign.finalize"))
        );
        assert_before(&events, "local.destroy", "protocol.release");
    }

    #[tokio::test]
    async fn late_prepare_is_fail_stopped_and_destroyed_before_release() {
        let fixture =
            fixture_with_helper_timeout(MAXIMUM_RETIREMENT_OWNERS, Duration::from_millis(20));
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .block_prepare = true;
        let prepare_started = fixture.shared.prepare_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, prepare_started)
            .await
            .expect("prepare started");
        wait_for_fail_stop(fixture.manager.retirement_state()).await;
        fixture.shared.prepare_release.notify_one();

        let failure = handle.wait().await.expect_err("late prepare rejected");
        assert_eq!(
            failure.cause,
            RouteSetupError::CallTimeout(RouteSetupPhase::Preparing)
        );
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        assert_before(
            &fixture.shared.events(),
            "local.destroy",
            "protocol.release",
        );
    }

    #[tokio::test]
    async fn late_activate_is_fail_stopped_and_destroyed_before_release() {
        let fixture =
            fixture_with_helper_timeout(MAXIMUM_RETIREMENT_OWNERS, Duration::from_millis(20));
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .block_activate = true;
        let activate_started = fixture.shared.activate_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, activate_started)
            .await
            .expect("activate started");
        wait_for_fail_stop(fixture.manager.retirement_state()).await;
        fixture.shared.activate_release.notify_one();

        let failure = handle.wait().await.expect_err("late activation rejected");
        assert_eq!(
            failure.cause,
            RouteSetupError::CallTimeout(RouteSetupPhase::Activating)
        );
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        let events = fixture.shared.events();
        assert!(!events.iter().any(|event| event == "local.commit"));
        assert_before(&events, "local.destroy", "protocol.release");
    }

    #[tokio::test]
    async fn late_commit_is_fail_stopped_and_destroyed_before_release() {
        let fixture =
            fixture_with_helper_timeout(MAXIMUM_RETIREMENT_OWNERS, Duration::from_millis(20));
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .block_commit = true;
        let commit_started = fixture.shared.commit_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, commit_started)
            .await
            .expect("commit started");
        wait_for_fail_stop(fixture.manager.retirement_state()).await;
        fixture.shared.commit_release.notify_one();

        let failure = handle.wait().await.expect_err("late commit rejected");
        assert_eq!(
            failure.cause,
            RouteSetupError::CallTimeout(RouteSetupPhase::Committing)
        );
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        assert_before(
            &fixture.shared.events(),
            "local.destroy",
            "protocol.release",
        );
    }

    #[tokio::test]
    async fn dropping_caller_does_not_abort_owned_destroy_first_supervisor() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .prepare_delay_ms = Some(50);
        let prepare_started = fixture.shared.prepare_started.notified();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        timeout(TEST_TIMEOUT, prepare_started)
            .await
            .expect("prepare started");
        drop(handle);
        wait_for_event(&fixture.shared, "protocol.release").await;
        let events = fixture.shared.events();
        assert_before(&events, "local.destroy", "protocol.release");
        assert!(!events.iter().any(|event| event == "local.activate"));
    }

    #[tokio::test]
    async fn one_permit_bounds_owner_processing_and_quarantine_until_confirmed_destroy() {
        let fixture = fixture(1);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");
        let sink = fixture.manager.retirement_sink();
        let state = Arc::clone(fixture.manager.retirement_state());
        assert_eq!(state.outstanding(), 1);
        assert!(
            timeout(Duration::from_millis(20), sink.reserve())
                .await
                .is_err(),
            "prepared owner must retain the sole slot"
        );

        {
            let mut fake = fixture.shared.state.lock().expect("fake state");
            fake.block_destroy = true;
            fake.fail_destroy = true;
        }
        let destroy_started = fixture.shared.destroy_started.notified();
        let teardown = tokio::spawn(established.teardown());
        timeout(TEST_TIMEOUT, destroy_started)
            .await
            .expect("first destroy started");
        assert!(
            timeout(Duration::from_millis(20), sink.reserve())
                .await
                .is_err(),
            "in-flight destroy must retain the sole slot"
        );
        fixture.shared.destroy_release.notify_one();
        assert_eq!(
            teardown.await.expect("teardown task"),
            RetirementOutcome::Quarantined
        );
        assert_eq!(state.outstanding(), 1);
        assert_eq!(state.quarantined(), 1);
        assert!(
            !fixture
                .shared
                .events()
                .iter()
                .any(|event| event == "protocol.release")
        );
        assert!(
            timeout(Duration::from_millis(20), sink.reserve())
                .await
                .is_err(),
            "quarantine must retain the sole slot"
        );

        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .fail_destroy = false;
        let retry_started = fixture.shared.destroy_started.notified();
        timeout(TEST_TIMEOUT, retry_started)
            .await
            .expect("quarantined destroy retried");
        fixture.shared.destroy_release.notify_one();
        wait_for_event(&fixture.shared, "protocol.release").await;
        timeout(TEST_TIMEOUT, async {
            while state.outstanding() != 0 || state.quarantined() != 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("confirmed destroy releases slot");

        let reservation = timeout(Duration::from_millis(100), sink.reserve())
            .await
            .expect("slot became available")
            .expect("worker remains available");
        assert_eq!(state.outstanding(), 1);
        drop(reservation);
        assert_eq!(state.outstanding(), 0);
        let events = fixture.shared.events();
        let destroy = events
            .iter()
            .rposition(|event| event == "local.destroy")
            .expect("successful destroy");
        let release = events
            .iter()
            .rposition(|event| event == "protocol.release")
            .expect("release after destroy");
        assert!(destroy < release);
        assert!(!state.fail_stopped());
    }

    #[tokio::test]
    async fn missing_native_process_scope_fails_before_any_route_dispatch() {
        let mut fixture = real_service_fixture();
        fixture
            .transaction
            .transaction
            .request
            .parameters
            .client_native_route_scope = None;
        let failure = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock)
            .wait()
            .await
            .expect_err("missing native process identity must fail closed");

        assert_eq!(failure.cause, RouteSetupError::NativeRouteScopeUnavailable);
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(fixture.shared.events().is_empty());
        assert!(
            fixture
                .scope_events
                .lock()
                .expect("scope events")
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real signed lifecycle also proves the exact post-commit UDP activation frame"
    )]
    async fn production_route_owner_completes_and_disconnects_one_real_v4_lifecycle() {
        // The exact-match verifier below is test-only. Production intentionally remains
        // ProbeEvidenceUnavailable until helper-proven, exit-participating probes are wired.
        let fixture = real_service_fixture();
        let retirement_state = Arc::clone(fixture.manager.retirement_state());
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle
            .wait()
            .await
            .expect("real signed v4 UDP orchestration");

        assert_eq!(established.active_path_ids, [1]);
        assert!(established.warm_path_ids.is_empty());
        assert_eq!(established.relay_grants.len(), 1);
        assert_eq!(established.relay_authorities.len(), 1);
        assert_eq!(established.confirmations.len(), 1);
        assert_eq!(established.commit_proof.leases.len(), 1);
        assert_eq!(
            *fixture.scope_events.lock().expect("scope events"),
            [
                "forward.CapacityHold",
                "forward.ProbePermit",
                "datapath.ExecuteProbe",
                "forward.FinalizeReservation",
                "datapath.ReservePath",
                "forward.ConfirmRelay",
            ]
        );
        let local_events = fixture.shared.events();
        assert_before(&local_events, "local.prepare", "local.activate");
        assert_before(&local_events, "local.activate", "local.commit");
        {
            let state = fixture.shared.state.lock().expect("fake state");
            let [activation] = state.activation_batches.as_slice() else {
                panic!("one real-service activation batch");
            };
            let [lease] = activation.leases.as_slice() else {
                panic!("one real-service activation lease");
            };
            let [grant] = established.relay_grants.as_slice() else {
                panic!("one real-service relay grant");
            };
            assert!(!grant.signed_relay_reservation().is_empty());
            assert_eq!(
                lease.signed_relay_reservation,
                grant.signed_relay_reservation(),
                "the real verified relay envelope must reach helper activation byte-for-byte"
            );
        }
        let verified_path = verified_single_relay_udp_path(&established, NOW_MS)
            .expect("real route yields one verified UDP path");
        let acquire = client_udp_socket_request(&established, &verified_path)
            .expect("real route yields one exact helper socket request");
        let start = udp_session_start_dispatch(&established, &verified_path, true, NOW_MS)
            .expect("real route yields one exact UDP session start");
        assert_eq!(start.relay.node_id, *verified_path.relay_node_id());
        assert_eq!(
            start.request.validated_operation(),
            Ok(DatapathRelayOperation::UdpSessionStart)
        );
        assert_eq!(start.request.relay_node_id(), start.relay.node_id);
        assert_eq!(
            start.request.relay_peer_id(),
            start.relay.peer_id.to_bytes()
        );
        let start_frame = decode_canonical::<UdpSessionStartRequest>(
            start.request.client_signed_request(),
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("canonical UDP start frame");
        start_frame.validate().expect("correlated UDP proof set");
        assert_eq!(
            start_frame.signed_exit_reservation(),
            established.signed_exit_reservation
        );
        assert_eq!(
            start_frame.signed_relay_reservation(),
            established.relay_grants[0].signed_relay_reservation()
        );
        assert_eq!(
            start_frame.signed_confirmation(),
            established.confirmations[0].signed_confirmation
        );
        assert_eq!(
            start_frame.signed_confirmation_receipt(),
            established.confirmations[0].signed_receipt
        );
        let exit_signal = DiscoveryUdpExitSessionSignal::new(
            *verified_path.reservation_id(),
            *verified_path.route_context_id(),
            verified_path.path_id(),
            vec![0x30, 1, 2],
            [9; 32],
        )
        .expect("bounded Exit signal");
        let exit_signal = encode_canonical(&exit_signal, MAX_CONTROL_MESSAGE_SIZE)
            .expect("canonical Exit signal");
        assert_eq!(
            verified_udp_exit_session_signal(&exit_signal, &verified_path)
                .expect("exact Exit signal")
                .certificate_der(),
            [0x30, 1, 2]
        );
        let wrong_path_signal = DiscoveryUdpExitSessionSignal::new(
            *verified_path.reservation_id(),
            *verified_path.route_context_id(),
            verified_path.path_id() + 1,
            vec![0x30, 1, 2],
            [9; 32],
        )
        .expect("bounded wrong-path Exit signal");
        let wrong_path_signal = encode_canonical(&wrong_path_signal, MAX_CONTROL_MESSAGE_SIZE)
            .expect("canonical wrong-path Exit signal");
        assert!(matches!(
            verified_udp_exit_session_signal(&wrong_path_signal, &verified_path),
            Err(ProductionUdpRouteError::SessionStart)
        ));
        let expected_client = overlay_addresses(
            *verified_path.route_context_id(),
            u8::try_from(verified_path.path_id()).expect("bounded path"),
        )
        .expect("canonical overlay")
        .client;
        assert_eq!(acquire.route_context_id, verified_path.route_context_id());
        assert_eq!(
            acquire.context_handle,
            established.commit_proof.context_handle
        );
        assert_eq!(acquire.path_id, verified_path.path_id());
        assert_eq!(acquire.role, WireguardRole::Client as i32);
        assert_eq!(
            acquire.descriptor_kind,
            TransportSocketKind::QuicUdpUnconnected as i32
        );
        assert_eq!(
            acquire.expected_local,
            Some(TransportSocketAddress {
                address: expected_client.octets().to_vec(),
                port: u32::from(CLIENT_SINGLE_RELAY_UDP_PORT),
            })
        );
        assert!(acquire.expected_remote.is_none());
        assert_eq!(
            established
                .native_authorization
                .as_ref()
                .expect("retained native authorization")
                .native_route_identity()
                .tls_server_name,
            "route.exit.example"
        );
        let expiry = ClientRouteExpiry::from_hard_expiry(
            established.request.parameters.hard_expires_at_unix,
            NOW_MS,
            Instant::now(),
        );
        let route = ProductionRoute {
            established,
            expiry,
        };
        assert_eq!(route.active_path_ids(), [1]);
        assert!(route.warm_path_ids().is_empty());
        assert_eq!(retirement_state.outstanding(), 1);
        route.disconnect().await.expect("production disconnect");
        assert_eq!(retirement_state.outstanding(), 0);
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean real-service manager shutdown");
        assert!(!retirement_state.fail_stopped());
    }

    #[test]
    fn outer_scope_is_exact_signed_nonce_prefix_and_expiry() {
        let expiry = NOW_MS + 17_000;
        let encoded =
            signed_envelope_at(ControlMessageType::RelayReservationRequest, vec![7], expiry);
        let envelope = decode_canonical::<SignedEnvelope>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
            .expect("signed envelope");
        let (request_id, signed_expiry) =
            signed_outer_scope(&encoded, expiry).expect("exact signed outer scope");
        assert_eq!(request_id.as_slice(), &envelope.nonce[..ID_BYTES]);
        assert_eq!(signed_expiry, expiry);
        assert!(signed_outer_scope(&encoded, expiry - 1).is_err());
        assert!(signed_outer_scope(&encoded, expiry + 1).is_err());

        let mut zero_nonce = envelope;
        zero_nonce.nonce[..ID_BYTES].fill(0);
        let zero_nonce = encode_canonical(&zero_nonce, MAX_CONTROL_MESSAGE_SIZE)
            .expect("canonical zero-prefix envelope");
        assert!(signed_outer_scope(&zero_nonce, expiry).is_err());
    }

    #[tokio::test]
    async fn handleless_prepare_ambiguity_retains_global_owner_until_expiry_reconciliation() {
        let mut fixture = fixture(1);
        fixture
            .transaction
            .transaction
            .request
            .parameters
            .setup_expires_at_unix = NOW_MS / 1_000 + 1;
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .ambiguous_prepare = true;
        let state = Arc::clone(fixture.manager.retirement_state());
        let sink = fixture.manager.retirement_sink();
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        wait_for_event(&fixture.shared, "local.prepare").await;
        timeout(TEST_TIMEOUT, async {
            while state.ambiguous() != 1 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("ambiguous owner published");
        assert!(fixture.manager.has_network_state());
        assert_eq!(state.outstanding(), 1);
        assert!(
            timeout(Duration::from_millis(20), sink.reserve())
                .await
                .is_err(),
            "handleless tombstone must retain the global slot"
        );

        let failure = timeout(TEST_TIMEOUT, handle.wait())
            .await
            .expect("expiry reconciliation completed")
            .expect_err("ambiguous Prepare fails setup");
        assert_eq!(
            failure.cause,
            RouteSetupError::LocalBackend(RouteSetupPhase::Preparing)
        );
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        assert_eq!(state.outstanding(), 0);
        assert_eq!(state.ambiguous(), 0);
        assert_eq!(state.quarantined(), 0);
        let events = fixture.shared.events();
        assert!(!events.iter().any(|event| event == "local.destroy"));
        assert_before(
            &events,
            "local.reconcile_expired_prepare",
            "protocol.release",
        );
        drop(sink);

        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
        assert!(!state.worker_alive());
        assert!(!state.fail_stopped());
    }

    #[tokio::test]
    async fn manager_shutdown_waits_for_ambiguous_prepare_owner_and_quarantine_retry() {
        let mut fixture = fixture(1);
        fixture
            .transaction
            .transaction
            .request
            .parameters
            .setup_expires_at_unix = NOW_MS / 1_000 + 1;
        {
            let mut state = fixture.shared.state.lock().expect("fake state");
            state.ambiguous_prepare = true;
            state.fail_reconcile = true;
        }
        let state = Arc::clone(fixture.manager.retirement_state());
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let failure = timeout(TEST_TIMEOUT, handle.wait())
            .await
            .expect("first reconciliation attempt")
            .expect_err("ambiguous setup remains failed");
        assert_eq!(failure.cleanup, CleanupStatus::Quarantined);
        assert_eq!(state.outstanding(), 1);
        assert_eq!(state.ambiguous(), 1);
        assert_eq!(state.quarantined(), 1);
        assert!(fixture.manager.has_network_state());

        let mut shutdown = tokio::spawn(fixture.manager.shutdown());
        assert!(
            timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "shutdown must wait while the tombstone is quarantined"
        );
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .fail_reconcile = false;
        timeout(TEST_TIMEOUT, shutdown)
            .await
            .expect("shutdown settles after retry")
            .expect("shutdown task")
            .expect("clean shutdown after definitive absence");
        assert_eq!(state.outstanding(), 0);
        assert_eq!(state.ambiguous(), 0);
        assert_eq!(state.quarantined(), 0);
        assert!(!state.worker_alive());
        assert!(!state.fail_stopped());
    }

    #[tokio::test]
    async fn substituted_reconciliation_receipt_never_releases_before_exact_retry() {
        let mut fixture = fixture(1);
        fixture
            .transaction
            .transaction
            .request
            .parameters
            .setup_expires_at_unix = NOW_MS / 1_000 + 1;
        {
            let mut state = fixture.shared.state.lock().expect("fake state");
            state.ambiguous_prepare = true;
            state.substitute_reconcile_receipt = true;
        }
        let retirement = Arc::clone(fixture.manager.retirement_state());
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let failure = timeout(TEST_TIMEOUT, handle.wait())
            .await
            .expect("substituted receipt attempt")
            .expect_err("substituted receipt must not settle ownership");
        assert_eq!(failure.cleanup, CleanupStatus::Quarantined);
        assert_eq!(retirement.outstanding(), 1);
        assert_eq!(retirement.ambiguous(), 1);
        assert_eq!(retirement.quarantined(), 1);
        assert!(
            !fixture
                .shared
                .events()
                .iter()
                .any(|event| event == "protocol.release"),
            "wrong-field receipt must never release the reservation"
        );

        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .substitute_reconcile_receipt = false;
        timeout(TEST_TIMEOUT, fixture.manager.shutdown())
            .await
            .expect("exact retry settles")
            .expect("clean shutdown after exact receipt");
        let events = fixture.shared.events();
        assert!(
            events
                .iter()
                .filter(|event| event.as_str() == "local.reconcile_expired_prepare")
                .count()
                >= 2
        );
        assert_before(
            &events,
            "local.reconcile_expired_prepare",
            "protocol.release",
        );
        assert_eq!(retirement.outstanding(), 0);
        assert_eq!(retirement.ambiguous(), 0);
        assert_eq!(retirement.quarantined(), 0);
        assert!(!retirement.fail_stopped());
    }

    #[tokio::test]
    async fn manager_shutdown_fences_new_reservations_despite_idle_sink_clone() {
        let fixture = fixture(1);
        let sink = fixture.manager.retirement_sink();
        let state = Arc::clone(fixture.manager.retirement_state());

        timeout(TEST_TIMEOUT, fixture.manager.shutdown())
            .await
            .expect("idle sink clone cannot block shutdown")
            .expect("clean manager shutdown");

        assert!(!state.worker_alive());
        assert!(!state.fail_stopped());
        assert!(sink.reserve().await.is_err());
        assert_eq!(state.outstanding(), 0);
    }

    #[tokio::test]
    async fn one_process_manager_bounds_multiple_transactions_with_one_global_slot() {
        let fixture = fixture(1);
        let second_authorities = fixture.transaction.transaction.authorities.clone();
        let second_request = rebuild_prospective_request(
            &second_authorities,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            fixture.transaction.transaction.request.parameters.clone(),
        );
        let second = fake_transaction(
            second_request,
            second_authorities,
            fixture.transaction.transaction.limits,
            &fixture.shared,
        );
        let state = Arc::clone(fixture.manager.retirement_state());
        let first_handle = fixture.manager.spawn(
            fixture.transaction,
            fixture.transport,
            fixture.clock.clone(),
        );
        let first = first_handle.wait().await.expect("first established route");
        assert_eq!(state.outstanding(), 1);

        let second_handle = fixture.manager.spawn(
            second,
            FakeTransport {
                shared: Arc::clone(&fixture.shared),
            },
            fixture.clock,
        );
        timeout(TEST_TIMEOUT, async {
            loop {
                let probe_eights = fixture
                    .shared
                    .events()
                    .iter()
                    .filter(|event| event.as_str() == "protocol.verify.probe.8")
                    .count();
                if probe_eights >= 2 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("second transaction reached retirement slot");
        sleep(Duration::from_millis(20)).await;
        assert_eq!(state.outstanding(), 1);
        assert_eq!(
            fixture
                .shared
                .events()
                .iter()
                .filter(|event| event.as_str() == "local.prepare")
                .count(),
            1,
            "second transaction cannot prepare before a global slot exists"
        );

        assert!(matches!(
            first.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        let second = second_handle
            .wait()
            .await
            .expect("second established route");
        assert_eq!(state.outstanding(), 1);
        assert!(matches!(
            second.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        assert_eq!(state.outstanding(), 0);
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
        assert!(!state.fail_stopped());
    }

    #[tokio::test]
    async fn retirement_worker_abort_is_unconditionally_fail_stopped() {
        let fixture = fixture(1);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");
        let state = Arc::clone(fixture.manager.retirement_state());
        assert_eq!(state.outstanding(), 1);
        assert!(state.worker_alive());
        fixture.manager.terminate_retirement_worker_for_test();
        timeout(TEST_TIMEOUT, async {
            while state.worker_alive() || !state.fail_stopped() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("aborted worker guard fired");
        assert_eq!(established.teardown().await, RetirementOutcome::Quarantined);
        assert!(state.armed_job_drop_fail_stopped());
        assert_eq!(
            fixture.manager.shutdown().await,
            Err(RouteSetupError::SupervisorStopped)
        );
    }

    #[tokio::test]
    async fn retirement_worker_panic_is_unconditionally_fail_stopped() {
        let fixture = fixture(1);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("established route");
        let state = Arc::clone(fixture.manager.retirement_state());
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .panic_destroy = true;
        assert_eq!(established.teardown().await, RetirementOutcome::Quarantined);
        timeout(TEST_TIMEOUT, async {
            while state.worker_alive() || !state.fail_stopped() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("panicked worker guard fired");
        assert!(state.armed_job_drop_fail_stopped());
        assert_eq!(
            fixture.manager.shutdown().await,
            Err(RouteSetupError::SupervisorStopped)
        );
    }

    #[tokio::test]
    async fn exact_transport_cardinality_rejects_udp_multipath_and_single_multipath() {
        let fixture = fixture(1);
        let base = fixture.transaction.transaction.request.parameters.clone();

        let mut udp_one = base.clone();
        udp_one.allowed_transports = vec![Transport::UdpSinglePath];
        udp_one.post_probe_policy.requirements.transport = SelectionTransport::UdpSinglePath;
        udp_one.post_probe_policy.relay_policy.active_paths = 1;
        udp_one.post_probe_policy.relay_policy.minimum_paths = 1;
        udp_one.post_probe_policy.relay_policy.maximum_paths = 1;
        udp_one.post_probe_policy.relay_policy.warm_backup_paths = 0;
        assert_eq!(validate_parameters(&udp_one), Ok(()));

        let mut udp_two = udp_one.clone();
        udp_two.post_probe_policy.relay_policy.active_paths = 2;
        udp_two.post_probe_policy.relay_policy.maximum_paths = 2;
        assert_eq!(
            validate_parameters(&udp_two),
            Err(RouteSetupError::Invalid("single-path UDP path count"))
        );

        for (transport, selection_transport) in [
            (Transport::TcpMptcp, SelectionTransport::TcpMptcp),
            (Transport::MultipathQuic, SelectionTransport::MultipathQuic),
        ] {
            let mut one = base.clone();
            one.allowed_transports = vec![transport];
            one.post_probe_policy.requirements.transport = selection_transport;
            one.post_probe_policy.relay_policy.active_paths = 1;
            one.post_probe_policy.relay_policy.minimum_paths = 1;
            one.post_probe_policy.relay_policy.maximum_paths = 1;
            one.post_probe_policy.relay_policy.warm_backup_paths = 0;
            assert_eq!(
                validate_parameters(&one),
                Err(RouteSetupError::Invalid("multipath path count"))
            );
        }
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn prospective_request_rejects_zero_duplicate_gapped_reordered_and_nine_path_ids() {
        let fixture = fixture(1);
        let authorities = &fixture.transaction.transaction.authorities;
        let parameters = fixture.transaction.transaction.request.parameters.clone();
        let bindings = |indices: &[usize]| {
            let forwarded = forwarded_exit_from_authorities(authorities);
            let relays = prospective_relay_bindings(
                authorities,
                &forwarded,
                &parameters.post_probe_policy.requirements,
                indices,
            );
            (forwarded, relays)
        };

        let (forwarded, mut zero) = bindings(&[0, 1]);
        zero[0].path_id = 0;
        assert!(matches!(
            RouteSetupRequest::new(forwarded, zero, parameters.clone()),
            Err(RouteSetupError::Invalid("selected relay evidence"))
        ));
        let (forwarded, mut duplicate) = bindings(&[0, 1]);
        duplicate[1].path_id = 1;
        assert!(matches!(
            RouteSetupRequest::new(forwarded, duplicate, parameters.clone()),
            Err(RouteSetupError::Invalid("selected relay evidence"))
        ));
        let (forwarded, mut gapped) = bindings(&[0, 1]);
        gapped[1].path_id = 3;
        assert!(matches!(
            RouteSetupRequest::new(forwarded, gapped, parameters.clone()),
            Err(RouteSetupError::Invalid("selected relay evidence"))
        ));
        let (forwarded, mut reordered) = bindings(&[0, 1]);
        reordered.swap(0, 1);
        assert!(matches!(
            RouteSetupRequest::new(forwarded, reordered, parameters.clone()),
            Err(RouteSetupError::Invalid("selected relay evidence"))
        ));

        let (forwarded, mut nine) = bindings(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let ninth = relay_binding_with_path_id(
            &authorities.datapath_relays[0],
            0,
            9,
            &forwarded,
            &parameters.post_probe_policy.requirements,
        );
        nine.push(ninth);
        assert!(matches!(
            RouteSetupRequest::new(forwarded, nine, parameters.clone()),
            Err(RouteSetupError::Invalid("prospective path count"))
        ));
        for indices in [&[][..], &[0][..]] {
            let (forwarded, below_minimum) = bindings(indices);
            assert!(matches!(
                RouteSetupRequest::new(forwarded, below_minimum, parameters.clone()),
                Err(RouteSetupError::Invalid("prospective path count"))
            ));
        }
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn actor_bound_relay_proof_rejects_forwarded_exit_identity_splicing() {
        let fixture = fixture(1);
        let authorities = &fixture.transaction.transaction.authorities;
        let parameters = fixture.transaction.transaction.request.parameters.clone();
        let mutations: [fn(&mut SelectedForwardedExit); 6] = [
            |forwarded| forwarded.authority.control.identity.wire_node_id = [201; 32],
            |forwarded| forwarded.authority.control.identity.peer_id = fixture_identity().peer_id,
            |forwarded| forwarded.authority.control.identity.advertisement_sequence += 1,
            |forwarded| forwarded.authority.exit.wire_node_id = [202; 32],
            |forwarded| forwarded.authority.exit.peer_id = fixture_identity().peer_id,
            |forwarded| forwarded.authority.exit.advertisement_sequence += 1,
        ];
        for mutate in mutations {
            let proof_exit = forwarded_exit_from_authorities(authorities);
            let relays = prospective_relay_bindings(
                authorities,
                &proof_exit,
                &parameters.post_probe_policy.requirements,
                &[0, 1],
            );
            let mut request_exit = proof_exit.clone();
            mutate(&mut request_exit);
            assert!(matches!(
                RouteSetupRequest::new(request_exit, relays, parameters.clone()),
                Err(RouteSetupError::Invalid("selected relay evidence"))
            ));
        }
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn unknown_low_capacity_probe_cannot_mask_a_missing_requested_path() {
        let fixture = fixture(1);
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            fixture.transaction.transaction.request.parameters.clone(),
        );
        let mut probes = (1..=7)
            .map(|path_id| measured_fake_probe(path_id, 100))
            .collect::<Vec<_>>();
        probes.push(measured_fake_probe(99, 1));
        assert!(matches!(
            select_verified_probe_subset_with_rng::<FakeProtocol, _>(
                &request,
                probes,
                NOW_MS,
                &mut ZeroRng,
            ),
            Err(RouteSetupError::ReservationProtocol(
                RouteSetupPhase::ExecuteProbes
            ))
        ));
        assert!(fixture.shared.events().is_empty());
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn actor_proof_expiry_at_current_time_rejects_postprobe_selection() {
        let fixture = fixture(1);
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            fixture.transaction.transaction.request.parameters.clone(),
        );
        let probes = (1..=8)
            .map(|path_id| measured_fake_probe(path_id, 100))
            .collect::<Vec<_>>();
        assert_eq!(
            select_verified_probe_subset_with_rng::<FakeProtocol, _>(
                &request,
                probes,
                NOW_MS + 60_000,
                &mut ZeroRng,
            )
            .map(|_| ()),
            Err(RouteSetupError::Invalid("stale actor-bound relay proof"))
        );
        assert!(fixture.shared.events().is_empty());
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn udp_policy_one_one_one_accepts_four_prospectives_and_finalizes_exactly_one() {
        let mut fixture = fixture(1);
        let mut parameters = fixture.transaction.transaction.request.parameters.clone();
        parameters.allowed_transports = vec![Transport::UdpSinglePath];
        parameters.post_probe_policy.requirements.transport = SelectionTransport::UdpSinglePath;
        parameters.post_probe_policy.relay_policy.active_paths = 1;
        parameters.post_probe_policy.relay_policy.minimum_paths = 1;
        parameters.post_probe_policy.relay_policy.maximum_paths = 1;
        parameters.post_probe_policy.relay_policy.warm_backup_paths = 0;
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3],
            parameters,
        );
        assert_eq!(request.probe_permit_limit(), Ok(4));
        assert_eq!(request.final_path_upper(), Ok(1));
        assert_eq!(
            request
                .paths
                .iter()
                .map(|path| path.path_id)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        let mut authorities = fixture.transaction.transaction.authorities.clone();
        authorities.datapath_relays.truncate(4);
        fixture.transaction = fake_transaction(
            request,
            authorities,
            fixture.transaction.transaction.limits,
            &fixture.shared,
        );
        {
            let mut state = fixture.shared.state.lock().expect("fake state");
            state.all_probe_capacity = Some(100);
        }
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("single-path UDP route");
        assert_eq!(established.active_path_ids.len(), 1);
        assert!((1..=4).contains(&established.active_path_ids[0]));
        assert!(established.warm_path_ids.is_empty());
        assert_eq!(established.relay_grants.len(), 1);
        assert_eq!(fixture.shared.selected_paths().len(), 1);
        let events = fixture.shared.events();
        for path_id in 1..=4 {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| {
                        event.as_str() == format!("protocol.verify.permit.{path_id}")
                    })
                    .count(),
                1
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| {
                        event.as_str() == format!("protocol.verify.probe.{path_id}")
                    })
                    .count(),
                1
            );
        }
        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn probe_address_family_substitution_fails_before_prepare() {
        let fixture = fixture(1);
        fixture
            .shared
            .state
            .lock()
            .expect("fake state")
            .probe_family_substitution = Some(ProbeAddressFamily::Ipv6);
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let failure = handle
            .wait()
            .await
            .expect_err("family substitution rejected");
        assert_eq!(
            failure.cause,
            RouteSetupError::ReservationProtocol(RouteSetupPhase::ExecuteProbes)
        );
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert!(
            !fixture
                .shared
                .events()
                .iter()
                .any(|event| event == "local.prepare")
        );
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn later_prospective_candidates_can_fill_the_measured_minimum() {
        let fixture = fixture(1);
        let mut parameters = fixture.transaction.transaction.request.parameters.clone();
        parameters.post_probe_policy.relay_policy.active_paths = 4;
        parameters.post_probe_policy.relay_policy.minimum_paths = 2;
        parameters.post_probe_policy.relay_policy.maximum_paths = 4;
        parameters.post_probe_policy.relay_policy.warm_backup_paths = 0;
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            parameters,
        );
        let probes = request
            .paths
            .iter()
            .map(|path| {
                let path_id = path.path_id;
                let capacity = if path_id <= 4 { 10 } else { 100 };
                (
                    path_id,
                    FakeProbe {
                        projection: ProbeProjection {
                            path_id,
                            transport: Transport::TcpMptcp,
                            address_family: ProbeAddressFamily::Ipv4,
                            minimum_directional_capacity_mbps: capacity,
                            evidence_bytes: capacity * 1_000,
                            client_to_relay_rtt_micros: u64::from(path_id) * 40,
                            relay_to_exit_rtt_micros: u64::from(path_id) * 60,
                            total_rtt_micros: u64::from(path_id) * 100,
                            unique_throughput_gain_ratio: 0.0,
                            meaningful_failover: false,
                        },
                        token: UniqueProbeToken {
                            session: 0,
                            path_id,
                        },
                    },
                )
            })
            .collect();

        let selected = select_verified_probe_subset_with_rng::<FakeProtocol, _>(
            &request,
            probes,
            NOW_MS,
            &mut ZeroRng,
        )
        .expect("later prospective candidates may fill the measured minimum");
        assert_eq!(selected.active.len(), 2);
        assert!(selected.warm.is_empty());
        assert!(selected.active.iter().all(|selected| selected.path_id > 4));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn no_gain_proof_selects_only_minimum_active_and_keeps_warm_separate() {
        let mut fixture = fixture(1);
        let mut parameters = fixture.transaction.transaction.request.parameters.clone();
        parameters.post_probe_policy.relay_policy.maximum_paths = 4;
        parameters.post_probe_policy.relay_policy.warm_backup_paths = 1;
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            parameters,
        );
        fixture.transaction = fake_transaction(
            request,
            fixture.transaction.transaction.authorities.clone(),
            fixture.transaction.transaction.limits,
            &fixture.shared,
        );
        {
            let mut state = fixture.shared.state.lock().expect("fake state");
            state.all_probe_capacity = Some(100);
            state.disable_probe_gain = true;
        }
        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle.wait().await.expect("minimum plus warm route");
        assert_eq!(established.active_path_ids.len(), 2);
        assert_eq!(established.warm_path_ids.len(), 1);
        assert_eq!(established.relay_grants.len(), 3);
        assert_eq!(fixture.shared.selected_paths().len(), 3);
        let (accepted_addrs, subflows, lease_count) = {
            let fake = fixture.shared.state.lock().expect("fake state");
            (
                fake.prepared_mptcp_accepted_addrs,
                fake.prepared_mptcp_subflows,
                fake.prepared_lease_count,
            )
        };
        assert_eq!(accepted_addrs, Some(2));
        assert_eq!(subflows, Some(2));
        assert_eq!(lease_count, Some(3));
        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn complete_active_set_keeps_requested_warm_backups_within_total_maximum() {
        let mut fixture = fixture(1);
        let mut parameters = fixture.transaction.transaction.request.parameters.clone();
        parameters.post_probe_policy.relay_policy.active_paths = 4;
        parameters.post_probe_policy.relay_policy.minimum_paths = 2;
        parameters.post_probe_policy.relay_policy.maximum_paths = 8;
        parameters.post_probe_policy.relay_policy.warm_backup_paths = 2;
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5],
            parameters,
        );
        let mut authorities = fixture.transaction.transaction.authorities.clone();
        authorities.datapath_relays.truncate(6);
        fixture.transaction = fake_transaction(
            request,
            authorities,
            fixture.transaction.transaction.limits,
            &fixture.shared,
        );
        {
            let mut state = fixture.shared.state.lock().expect("fake state");
            state.all_probe_capacity = Some(100);
            state.force_probe_gain = true;
        }

        let handle = fixture
            .manager
            .spawn(fixture.transaction, fixture.transport, fixture.clock);
        let established = handle
            .wait()
            .await
            .expect("four active paths plus two warm backups");

        assert_eq!(established.active_path_ids.len(), 4);
        assert_eq!(established.warm_path_ids.len(), 2);
        assert_eq!(established.relay_grants.len(), 6);
        assert_eq!(fixture.shared.selected_paths().len(), 6);
        {
            let fake = fixture.shared.state.lock().expect("fake state");
            assert_eq!(fake.prepared_mptcp_accepted_addrs, Some(4));
            assert_eq!(fake.prepared_mptcp_subflows, Some(4));
            assert_eq!(fake.prepared_lease_count, Some(6));
        }
        assert!(matches!(
            established.teardown().await,
            RetirementOutcome::Destroyed { .. }
        ));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn promoted_warm_paths_are_backfilled_from_unselected_active_prospects() {
        let fixture = fixture(1);
        let mut parameters = fixture.transaction.transaction.request.parameters.clone();
        parameters.post_probe_policy.relay_policy.active_paths = 4;
        parameters.post_probe_policy.relay_policy.minimum_paths = 2;
        parameters.post_probe_policy.relay_policy.maximum_paths = 8;
        parameters.post_probe_policy.relay_policy.warm_backup_paths = 2;
        let request = rebuild_prospective_request(
            &fixture.transaction.transaction.authorities,
            &[0, 1, 2, 3, 4, 5],
            parameters,
        );
        let probes = request
            .paths
            .iter()
            .map(|path| {
                let capacity = match path.path_id {
                    5 => 10_000,
                    6 => 9_000,
                    _ => 100,
                };
                let path_id = path.path_id;
                let (client_rtt, exit_rtt) = if path_id >= 5 {
                    (1, 1)
                } else {
                    (10_000, 10_000)
                };
                (
                    path_id,
                    FakeProbe {
                        projection: ProbeProjection {
                            path_id,
                            transport: Transport::TcpMptcp,
                            address_family: ProbeAddressFamily::Ipv4,
                            minimum_directional_capacity_mbps: capacity,
                            evidence_bytes: capacity * 1_000,
                            client_to_relay_rtt_micros: client_rtt,
                            relay_to_exit_rtt_micros: exit_rtt,
                            total_rtt_micros: client_rtt + exit_rtt,
                            unique_throughput_gain_ratio: 0.20,
                            meaningful_failover: true,
                        },
                        token: UniqueProbeToken {
                            session: 0,
                            path_id,
                        },
                    },
                )
            })
            .collect();
        let selected = select_verified_probe_subset_with_rng::<FakeProtocol, _>(
            &request,
            probes,
            NOW_MS,
            &mut ZeroRng,
        )
        .expect("deterministic active and warm subset");
        let active_ids = selected
            .active
            .iter()
            .map(|probe| probe.path_id)
            .collect::<BTreeSet<_>>();
        let warm_ids = selected
            .warm
            .iter()
            .map(|probe| probe.path_id)
            .collect::<BTreeSet<_>>();

        assert!(active_ids.contains(&5));
        assert!(active_ids.contains(&6));
        assert_eq!(active_ids.len(), 4);
        assert_eq!(warm_ids.len(), 2);
        assert!(warm_ids.iter().all(|path_id| *path_id <= 4));
        fixture
            .manager
            .shutdown()
            .await
            .expect("clean manager shutdown");
    }

    #[tokio::test]
    async fn actor_authorities_reject_control_datapath_identity_overlap() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let mut authorities = fixture.transaction.transaction.authorities.clone();
        authorities.datapath_relays[0] = authorities.control.clone();
        assert_eq!(
            authorities.validate(&fixture.transaction.transaction.request),
            Err(RouteSetupError::Capability)
        );
    }

    #[tokio::test]
    async fn request_bounded_forwarded_authority_only_needs_to_cover_route_setup() {
        let fixture = fixture(MAXIMUM_RETIREMENT_OWNERS);
        let request = &fixture.transaction.transaction.request;
        let mut authorities = fixture.transaction.transaction.authorities.clone();
        let setup_expiry_ms = request
            .parameters
            .setup_expires_at_unix
            .checked_mul(1_000)
            .expect("bounded setup expiry");
        assert!(request.parameters.expires_at_ms > setup_expiry_ms);

        authorities.exit.expires_at_ms = setup_expiry_ms;
        assert_eq!(authorities.validate(request), Ok(()));
        assert!(request.exit.expires_at_ms > authorities.exit.expires_at_ms);

        authorities.exit.expires_at_ms = setup_expiry_ms.saturating_sub(1);
        assert_eq!(
            authorities.validate(request),
            Err(RouteSetupError::Capability)
        );
    }

    fn assert_unmeasured_setup_surface(product: &str) {
        assert!(!product.contains("std::ops::Deref"));
        assert!(!product.contains("std::ops::DerefMut"));
        assert!(!product.contains("Clone for UnmeasuredRouteSetup"));
        assert!(!product.contains("Copy for UnmeasuredRouteSetup"));
        assert!(!product.contains("Debug for UnmeasuredRouteSetup"));
        assert!(!product.contains("Serialize for UnmeasuredRouteSetup"));
        assert!(!product.contains("Deserialize for UnmeasuredRouteSetup"));
        let declaration_offset = product
            .find("struct UnmeasuredRouteSetup")
            .expect("private unmeasured setup exists");
        assert_eq!(
            product[..declaration_offset]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::trim),
            Some("}")
        );
        assert!(!product.contains("fn into_parts("));
        assert!(!product.contains("fn decompose("));
        assert!(!product.contains("fn transaction("));
        assert!(!product.contains("fn deadline("));
        assert!(!product.contains("RouteSetupTransaction::execute_owned"));
        assert!(!product.contains("fn with_protocol("));
        assert!(!product.contains("resolve_and_generate"));
        assert!(!product.contains("ReservationSession::generate"));
        assert_eq!(product.matches(".measure_inner(").count(), 1);
        assert_eq!(product.matches("fn measure_inner<").count(), 1);
        assert_eq!(product.matches("fn execute_owned<").count(), 1);
        assert!(product.contains("unmeasured: UnmeasuredRouteSetup<P>"));
    }

    fn assert_route_attempt_owner_surface(product: &str) {
        let declaration_offset = product
            .find("enum RouteAttemptState")
            .expect("private route-attempt state exists");
        assert_eq!(
            product[..declaration_offset]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::trim),
            Some("}"),
            "route-attempt state must not gain derives or attributes"
        );
        let end = product[declaration_offset..]
            .find("\nfn bounded_phase_expiry")
            .expect("route-attempt owner surface end")
            + declaration_offset;
        let owner = &product[declaration_offset..end];
        assert_eq!(product.matches("enum RouteAttemptState").count(), 1);
        assert_eq!(product.matches("struct RouteAttemptOwner").count(), 1);
        for outside in [&product[..declaration_offset], &product[end..]] {
            for type_name in [
                "RouteAttemptState",
                "RouteAttemptOwner",
                "FailedRouteAttempt",
                "RouteAttemptSettlement",
                "RouteAttemptDrain",
            ] {
                assert!(
                    !outside.contains(type_name),
                    "dormant owner must have no product caller: {type_name}"
                );
            }
        }
        assert!(!owner.contains("#[derive"));
        assert!(
            !owner
                .lines()
                .any(|line| line.trim_start().starts_with("pub"))
        );
        for type_name in [
            "RouteAttemptState",
            "RouteAttemptOwner",
            "FailedRouteAttempt",
            "RouteAttemptSettlement",
            "RouteAttemptDrain",
        ] {
            for trait_name in [
                "Clone",
                "Copy",
                "Debug",
                "Serialize",
                "Default",
                "Drop",
                "Deref",
                "DerefMut",
            ] {
                assert!(
                    !product.contains(&format!("{trait_name} for {type_name}")),
                    "{type_name} must not implement {trait_name}"
                );
            }
            assert!(!product.contains(&format!("Deserialize<'de> for {type_name}")));
            assert!(!product.contains(&format!("DeserializeOwned for {type_name}")));
        }
        for forbidden in [
            "fn into_parts(",
            "fn decompose(",
            "fn state(",
            "fn handle(",
            "fn route(",
            "fn owner(",
            "RouteSetupManager",
            "tokio::spawn",
            "spawn(",
            "watch::",
            "oneshot::",
            "RouteSessionAuthority",
            "ReservationSession",
            "generate(",
            "Instant",
            "deadline",
            "reservation_id",
            "route_context_id",
            "FreshEvidence",
            "snapshot",
            "resolve",
            "transport",
            "helper",
        ] {
            assert!(!owner.contains(forbidden), "owner surface: {forbidden}");
        }
        assert_eq!(owner.matches("async fn ").count(), 2);
        assert_eq!(owner.matches("async fn settle(mut self)").count(), 1);
        assert_eq!(owner.matches("async fn drain(mut self)").count(), 1);
        assert_eq!(owner.matches("\n    fn ").count(), 3);
        assert_eq!(owner.matches("fn vacant()").count(), 1);
        assert_eq!(owner.matches("fn adopt(").count(), 1);
        assert_eq!(owner.matches("fn adopt_established(").count(), 1);
    }

    fn assert_affine_route_setup_surface(product: &str) {
        for type_name in [
            "ProspectiveRouteRelay",
            "RouteSetupPath",
            "SelectedRouteSetupPath",
            "RouteSetupRequest",
        ] {
            let declaration_offset = product
                .find(&format!("struct {type_name}"))
                .expect("private affine declaration");
            assert_eq!(
                product[..declaration_offset]
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .map(str::trim),
                Some("}"),
                "{type_name} must not gain derives or attributes"
            );
            for trait_name in ["Clone", "Copy", "Debug", "Serialize"] {
                assert!(
                    !product.contains(&format!("{trait_name} for {type_name}")),
                    "{type_name} must not implement {trait_name}"
                );
            }
            assert!(!product.contains(&format!("Deserialize<'de> for {type_name}")));
            assert!(!product.contains(&format!("DeserializeOwned for {type_name}")));
        }
        assert!(!product.contains("request.paths.clone()"));
        assert!(!product.contains("request.paths.iter().cloned()"));
        assert!(!product.contains("fn into_parts("));
        assert!(!product.contains("fn decompose("));
        let request_body = product
            .split("struct RouteSetupRequest {")
            .nth(1)
            .expect("private request")
            .split("}\n\nimpl RouteSetupRequest")
            .next()
            .expect("request body");
        for forbidden in [
            "Candidate",
            "NodeAdvertisement",
            "control_endpoints",
            "ObservedNetworkOrigin",
            "IpAddr",
            "DiversitySnapshot",
        ] {
            assert!(
                !request_body.contains(forbidden),
                "request leak: {forbidden}"
            );
        }
        for type_name in [
            "ProspectivePeerIdentity",
            "ProspectiveDirectRelay",
            "ProspectiveForwardedExit",
            "ProspectiveRouteRelay",
            "RouteSetupPath",
            "SelectedRouteSetupPath",
        ] {
            let body = product
                .split(&format!("struct {type_name} {{"))
                .nth(1)
                .expect("private path binding")
                .split('}')
                .next()
                .expect("path binding body");
            for forbidden in [
                "Candidate",
                "NodeAdvertisement",
                "ObservedNetworkOrigin",
                "IpAddr",
                "control_endpoints",
                "DiversitySnapshot",
            ] {
                assert!(!body.contains(forbidden), "{type_name} leak: {forbidden}");
            }
        }

        for type_name in ["PostProbeSelectionPolicy", "RouteSetupParameters"] {
            let body = product
                .split(&format!("struct {type_name} {{"))
                .nth(1)
                .expect("private setup parameter binding")
                .split('}')
                .next()
                .expect("setup parameter body");
            for forbidden in [
                "Candidate",
                "NodeAdvertisement",
                "ObservedNetworkOrigin",
                "IpAddr",
                "control_endpoints",
                "DiversitySnapshot",
            ] {
                assert!(!body.contains(forbidden), "{type_name} leak: {forbidden}");
            }
        }
    }

    fn assert_actor_bound_proof_surface(bridge: &str) {
        let bridge_product = bridge
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("bridge product source");
        assert_eq!(
            bridge_product
                .matches("NodeId, ObservedNetworkPrefix, OperatorId")
                .count(),
            1
        );
        for forbidden in [
            "enum ObservedNetworkPrefix",
            "struct ObservedNetworkPrefix",
            "ObservedNetworkOrigin",
            "std::net::IpAddr",
            ".ipv4_24()",
            ".ipv6_48()",
        ] {
            assert!(
                !bridge_product.contains(forbidden),
                "prefix path: {forbidden}"
            );
        }
        let diversity_body = bridge_product
            .split("struct ActorRelayDiversity {")
            .nth(1)
            .expect("private diversity binding")
            .split('}')
            .next()
            .expect("diversity binding body");
        assert_eq!(
            diversity_body
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>(),
            [
                "operator_id: OperatorId,",
                "asn: u32,",
                "prefix: ObservedNetworkPrefix,",
            ]
        );
        for forbidden in [
            "Candidate",
            "NodeAdvertisement",
            "ObservedNetworkOrigin",
            "IpAddr",
            "control_endpoints",
            "DiversitySnapshot",
        ] {
            assert!(
                !diversity_body.contains(forbidden),
                "diversity leak: {forbidden}"
            );
        }
        let proof_api = bridge
            .split("/// Affine authenticated actor and sanitized selection binding.")
            .nth(1)
            .expect("actor-bound proof documentation")
            .split("#[derive(Clone, Copy, Debug)]\nstruct ActivePolicySnapshot")
            .next()
            .expect("actor-bound proof API end");
        assert!(!proof_api.contains("#[derive"));
        assert_eq!(bridge.matches("Ok(ActorBoundRelayProof {").count(), 1);
        let proof_body = bridge
            .split("pub(super) struct ActorBoundRelayProof {")
            .nth(1)
            .expect("private actor proof")
            .split('}')
            .next()
            .expect("actor proof body");
        for forbidden in [
            "Candidate",
            "NodeAdvertisement",
            "ObservedNetworkOrigin",
            "IpAddr",
            "control_endpoints",
            "DiversitySnapshot",
        ] {
            assert!(!proof_body.contains(forbidden), "proof leak: {forbidden}");
        }
        for forbidden in [
            "Clone for ActorBoundRelayProof",
            "Copy for ActorBoundRelayProof",
            "Debug for ActorBoundRelayProof",
            "Serialize for ActorBoundRelayProof",
            "Deserialize<'de> for ActorBoundRelayProof",
            "DeserializeOwned for ActorBoundRelayProof",
            "pub(super) fn into_parts(",
            "pub(super) fn decompose(",
            "pub(super) fn relay(",
            "pub(super) fn selection(",
        ] {
            assert!(!bridge.contains(forbidden), "proof surface: {forbidden}");
        }
    }

    #[test]
    fn unmeasured_setup_source_has_one_deadline_owned_measurement_surface() {
        let source = include_str!("route_setup.rs");
        let product = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("product source before test module");
        assert_unmeasured_setup_surface(product);
        assert_affine_route_setup_surface(product);
        assert_actor_bound_proof_surface(include_str!("route_setup/selection_bridge.rs"));
    }

    #[test]
    fn route_attempt_owner_surface_is_private_affine_and_task_free() {
        let source = include_str!("route_setup.rs");
        let product = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("product source before test module");
        assert_route_attempt_owner_surface(product);
    }
}
