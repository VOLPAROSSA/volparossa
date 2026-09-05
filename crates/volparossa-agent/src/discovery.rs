//! Real libp2p privacy-v4 discovery, forwarding, and verified peerstore ingestion.

mod native_ready;
mod preselection_observation;
mod preselection_sampler;

pub(crate) use preselection_observation::{
    BoundPreselectionFreshnessProofBatch, CompletedPreselectionFreshnessAttempt,
    CoolingPreselectionAttemptGate, PreselectionTranscriptFreshnessFacts,
    PreselectionTransportFreshnessFacts,
};
use preselection_observation::{
    DispatchedPreselectionAttempt, PreselectionAttemptGate, PreselectionGateRecovery,
    PreselectionLocalRecovery, PreselectionOwnerTransitionFailure, PreselectionResponseOutcome,
    consume_local_preselection_attempt_failure, consume_preselection_begin_failure,
};
#[cfg(test)]
use preselection_sampler::MAXIMUM_OTHER_RELAYS;
use preselection_sampler::{
    PreselectionSamplingError, PreselectionSamplingScope, narrow_route_candidate_snapshot,
};

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    net::{IpAddr, UdpSocket as StdUdpSocket},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use libp2p::{
    Multiaddr, PeerId as Libp2pPeerId, kad,
    multiaddr::Protocol,
    request_response,
    swarm::{ConnectionId, SwarmEvent},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::{
    net::UdpSocket,
    sync::{RwLock, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, timeout},
};

use volparossa_config::{Config, RolesConfig};
use volparossa_core::{
    Bandwidth, CapacitySnapshot, NetworkMetadata, NodeAdvertisement as CoreAdvertisement,
    NodeCapabilities, NodeId, NodeQuality, NodeRoles, OperatorId, PeerId as CorePeerId, PolicyHash,
    UnixTime, is_local_lan_ip, is_public_routable_ip,
};
use volparossa_discovery::{
    AdvertisementResponse, BehaviourEvent, BoundClientPreselectionTransport,
    BoundNativeProbeControlConnection, BoundNativeProbeDataRelayConnection,
    ClientPreselectionResponseArrival, DATAPATH_RELAY_REQUEST_TIMEOUT, DatapathRelayOperation,
    DatapathRelayRequest, DatapathRelayResponse, DiscoveryEvent, DiscoveryProtocolRoles,
    DiscoveryService, EXIT_FORWARD_REQUEST_TIMEOUT, EXIT_FORWARD_UPSTREAM_TIMEOUT,
    ExitForwardOperation, ExitForwardRequest, ExitForwardResponse, ExitMpquicSessionSignal,
    ExitMptcpSessionSignal, ForwardStatus, LocalPreselectionPolicy,
    MAX_CONCURRENT_DATAPATH_RELAY_STREAMS, MAX_CONCURRENT_FORWARDING_STREAMS,
    MAX_FORWARDING_FRAME_BYTES, MpquicSessionStartRequest, MptcpSessionStartRequest,
    NativeProbeReadyForwardRequest, PRESELECTION_OBSERVATION_REQUEST_TIMEOUT, PeerLink,
    UdpExitSessionSignal, UdpSessionStartRequest, UpstreamExitForwardRequest,
    UpstreamExitForwardResponse, advertisement_envelope_matches_peer, capability,
    signed_envelope_matches_peer,
};
use volparossa_exit::{
    AcceptedExitConfirmation, AcceptedExitReservationBundle, ExitService, ExitServiceConfig,
    ProbeEvidence, ProbeEvidenceError, ProbeEvidenceVerifier,
};
use volparossa_identity::Identity;
use volparossa_local_control::{
    LogLevel, PeerSummary, PolicySnapshot as AgentPolicySnapshot, Reachability,
};
use volparossa_metrics::MetricsRegistry;
use volparossa_peerstore::PeerStore;
use volparossa_policy::VerifiedManifest;
use volparossa_protocol::{
    AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork,
    ClientSessionCapability, ControlPayload, ExitCapacityHold, ExitCapacityHoldRequest,
    ExitConfirmationReceipt, ExitReservation, ExitReservationConfirmation,
    ExitReservationFinalizeRequest, IssuedNativeProbeRelayReady, MAX_CONTROL_PAYLOAD_SIZE,
    MAX_NATIVE_PROBE_CONTROL_ADDRESS_BYTES, MAX_NATIVE_PROBE_LIFETIME_MS,
    NativeProbeEndpointBinding, NativeProbeForwardingProof, NativeProbeLeaseProof,
    NativeProbePathScope, NativeProbePermitRequest, NativeProbeRelayLocalProofs, NativeProbeStart,
    NativeRouteCredentialDelivery, NodeAdvertisement as WireAdvertisement,
    ObservationAddressFamily, ObservationNetworkPrefix, PreselectionActorBinding, ProbeLegEvidence,
    RelayAuthorization, RelayProbePermit, RelayProbePermitRequest, RelayProbeResult,
    RelayReservation, RelayReservationRequest, ReplayCache, SignedEnvelope, TimePolicy, Transport,
    VerifiedNativeProbePermit, VerifiedNativeProbeStartForRelay, decode_canonical,
    encode_canonical, exit_confirmation_envelope_hash, generate_nonce,
    native_probe_prepared_lease_commitment, node_id_from_public_key, sign_control_message_with,
    sign_native_probe_relay_ready_with, sign_native_probe_relay_result_with,
    verify_control_message, verify_native_probe_authorization_chain,
    verify_native_probe_exit_ready, verify_native_probe_exit_result_for_relay,
    verify_native_probe_permit, verify_native_probe_start_for_relay, verify_relay_reservation,
};
use volparossa_quic::NativeClient;
use volparossa_relay::{AcceptedRelayReservation, RelayService, RelayServiceConfig};
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, CommitLeaseBatch, CommittedLeaseBatch, ContextRole,
    LeaseActivation, LeaseCommit, LeasePlan, MAX_HELPER_PATHS, NATIVE_PROBE_CLIENT_PORT,
    NATIVE_PROBE_DATAGRAM_BYTES, NATIVE_PROBE_EXIT_PORT, PrepareLeaseBatch, PublicUdpEndpoint,
    TransportSocketAddress, TransportSocketKind, TraversalEndpointHint, WireguardRole,
};
use volparossa_selection::MAXIMUM_SELECTION_CANDIDATES;
use volparossa_udp::{DatagramLimits, VerifiedSingleRelayPath};
use volparossa_wireguard::{ExitEndpointLease, RelayEndpointLease, overlay_addresses};

use crate::{
    advertisement::{AdvertisementPublisher, LocalAdvertisementInput},
    endpoint_leases::{
        bind_prepared_exit_endpoint_leases, bind_prepared_relay_endpoint_lease,
        protocol_endpoint_for_native,
    },
    helper::{HelperClient, RuntimeBoundPreparedLeaseBatch},
    mpquic_runtime::{
        ExitMpquicPathAuthorization, ProductionMpquicExitPreflight, start_production_mpquic_exit,
        start_production_single_path_udp_exit,
    },
    mptcp_flow_runtime::{
        ProductionMptcpExitCleanup, ProductionMptcpExitCompletion, ProductionMptcpExitRuntime,
    },
    mptcp_transport::{ExitMptcpListenerSignal, ExitMptcpTransport, PRODUCTION_MPTCP_EXIT_PORT},
    roles::RoleStore,
    route_setup::{PreparedPreselectionEvidence, prepare_preselection_evidence},
    state::AgentState,
    udp_exit_provider::{
        ProductionExitNativeRouteIdentityProvider, route_certificate_der, start_production_udp_exit,
    },
    unix_millis, unix_seconds,
};

const PEERSTORE_LOAD_BOUND: usize = 1_000;
const PEER_RETENTION_SECONDS: u64 = 3_600;
const ROLE_COMMAND_CAPACITY: usize = 8;
const MPTCP_EXIT_RUNTIME_EVENT_CAPACITY: usize = 64;
const ROLE_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const RESERVATION_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
const CAPABILITY_QUERY_INTERVAL: Duration = Duration::from_secs(5);
const MAXIMUM_RESERVATION_TTL_SECONDS: u64 = 15 * 60;
const TUNNEL_SETUP_TIMEOUT_SECONDS: u64 = 30;
const SERVICE_REPLAY_CAPACITY: usize = 65_536;
const FORWARD_ID_BYTES: usize = 16;
const MAX_PENDING_PER_PEER: usize = 16;
const MAX_COALESCED_WAITERS: usize = 3;
const MAX_DISPATCH_ATTEMPTS: usize = 3;
const MAX_LEDGER_ENTRIES: usize = 256;
// One complete two-path route keeps several idempotent 512-KiB response reservations alive at
// once (advertisement, native phases, production probes and transport activation). Keep that
// protocol transaction bounded without rejecting its later phases merely because the control
// Relay is also one of the selected data Relays.
const MAX_LEDGER_BYTES: usize = 128 * 1024 * 1024;
const MAX_LEDGER_BYTES_PER_PEER: usize = 16 * 1024 * 1024;
const MAX_EXIT_PROVIDER_PEERS: usize = 1_024;
const MAX_RECENT_NATIVE_EVIDENCE: usize = 64;
pub(crate) const MAX_FORWARD_OPERATION_LIFETIME_MS: u64 = 30_000;
const AUTOMATIC_EXIT_FETCH_RETRY_BACKOFF_MS: u64 = 1_000;
// A provider observation is client-local: a selected control Relay may not have converged on the
// same DHT record yet. Retire that exact Relay/Exit lineage long enough to rotate through the
// bounded control set, but retry it well inside the provider observation and A01 liveness windows.
const AUTOMATIC_EXIT_FETCH_EXHAUSTED_COOLDOWN_MS: u64 = 10_000;
// Helper Destroy can legitimately remain ambiguous for its full five-second RPC bound. Retrying
// that synchronous call on every one-second actor tick starves discovery traffic, so quarantine
// the affine owner and retry slowly while the helper's durable reaper also converges cleanup.
const HELPER_CLEANUP_RETRY_BACKOFF_MS: u64 = 60_000;
const PROVIDER_OBSERVATION_TTL_MS: u64 = 120_000;
const CLIENT_PRESELECTION_TIMEOUT: Duration = Duration::from_secs(TUNNEL_SETUP_TIMEOUT_SECONDS);

/// Single-owner resources installed into the discovery actor at startup.
pub(crate) struct DiscoveryRuntimeResources {
    pub(crate) roles: RolesConfig,
    pub(crate) policy: Option<VerifiedManifest>,
    pub(crate) role_store: RoleStore,
    pub(crate) metrics: MetricsRegistry,
    pub(crate) helper: HelperClient,
    pub(crate) mpquic_socket: PathBuf,
}

/// Route-policy-only input for one actor-owned client preselection attempt.
///
/// No peer, target, endpoint, Exit, request, or dispatch identity can cross this boundary. The
/// discovery actor derives every network target from its own freshly revalidated snapshot.
pub(crate) struct ClientPreselectionParameters {
    transport: Transport,
    address_family: ObservationAddressFamily,
    minimum_capacity: Bandwidth,
    local_profile_capacity: Bandwidth,
    conservative_capacity_ceiling: Bandwidth,
    minimum_other_relays: usize,
    maximum_other_relays: usize,
    requested_candidate_bound: usize,
}

#[allow(
    dead_code,
    reason = "the typed route-orchestrator boundary is intentionally crate-private"
)]
impl ClientPreselectionParameters {
    #[allow(
        clippy::too_many_arguments,
        reason = "the typed boundary keeps every bounded route-policy input explicit"
    )]
    pub(crate) const fn new(
        transport: Transport,
        address_family: ObservationAddressFamily,
        minimum_capacity: Bandwidth,
        local_profile_capacity: Bandwidth,
        conservative_capacity_ceiling: Bandwidth,
        minimum_other_relays: usize,
        maximum_other_relays: usize,
        requested_candidate_bound: usize,
    ) -> Self {
        Self {
            transport,
            address_family,
            minimum_capacity,
            local_profile_capacity,
            conservative_capacity_ceiling,
            minimum_other_relays,
            maximum_other_relays,
            requested_candidate_bound,
        }
    }

    #[cfg(test)]
    pub(crate) const fn fields_for_test(
        &self,
    ) -> (
        Transport,
        ObservationAddressFamily,
        Bandwidth,
        Bandwidth,
        Bandwidth,
        usize,
        usize,
        usize,
    ) {
        (
            self.transport,
            self.address_family,
            self.minimum_capacity,
            self.local_profile_capacity,
            self.conservative_capacity_ceiling,
            self.minimum_other_relays,
            self.maximum_other_relays,
            self.requested_candidate_bound,
        )
    }
}

/// Detail-free terminal result at the production client-preselection handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientPreselectionError {
    Busy,
    Closed,
    Timeout,
    InvalidParameters,
    Unavailable,
    Invalidated,
    Transport,
}

/// Bounded typed control path into the single-owner discovery actor.
#[derive(Clone)]
pub(crate) struct DiscoveryControlHandle {
    sender: mpsc::Sender<DiscoveryCommand>,
}

#[allow(
    dead_code,
    reason = "the typed v4 route boundary is consumed by the route-orchestrator slice"
)]
impl DiscoveryControlHandle {
    fn from_sender(sender: mpsc::Sender<DiscoveryCommand>) -> Self {
        Self { sender }
    }

    /// Test transport replies only after every Ready request crosses the actor queue.
    #[cfg(test)]
    pub(crate) fn native_ready_barrier_for_test(count: usize) -> (Self, JoinHandle<usize>) {
        let (sender, mut receiver) = mpsc::channel(count);
        let task = tokio::spawn(async move {
            let mut replies = Vec::new();
            while replies.len() < count {
                let Some(DiscoveryCommand::RequestDatapathRelay { request, reply, .. }) =
                    receiver.recv().await
                else {
                    panic!("expected one native Ready request per candidate");
                };
                assert_eq!(
                    request.validated_operation(),
                    Ok(DatapathRelayOperation::NativeProbeReady)
                );
                replies.push(reply);
            }
            for reply in replies {
                let _ = reply.send(Err(OutboundReservationError::SendFailed));
            }
            count
        });
        (Self { sender }, task)
    }

    pub async fn set_roles(
        &self,
        expected: RolesConfig,
        candidate: RolesConfig,
    ) -> Result<RolesConfig, DiscoveryControlError> {
        let (reply, response) = oneshot::channel();
        self.send(DiscoveryCommand::SetRoles {
            expected,
            candidate,
            reply,
        })
        .await?;
        timeout(ROLE_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| DiscoveryControlError::Timeout)?
            .map_err(|_| DiscoveryControlError::Closed)?
            .map_err(DiscoveryControlError::Actor)
    }

    pub async fn apply_policy(
        &self,
        policy: Option<VerifiedManifest>,
    ) -> Result<(), DiscoveryControlError> {
        let (reply, response) = oneshot::channel();
        self.send(DiscoveryCommand::ApplyPolicy { policy, reply })
            .await?;
        timeout(ROLE_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| DiscoveryControlError::Timeout)?
            .map_err(|_| DiscoveryControlError::Closed)?;
        Ok(())
    }

    pub(crate) async fn route_candidate_snapshot(
        &self,
        requested_candidates: usize,
    ) -> Result<RouteCandidateSnapshot, RouteCandidateSnapshotError> {
        let (reply, response) = oneshot::channel();
        timeout(
            ROLE_COMMAND_TIMEOUT,
            self.sender.send(DiscoveryCommand::RouteCandidateSnapshot {
                requested_candidates,
                reply,
            }),
        )
        .await
        .map_err(|_| RouteCandidateSnapshotError::Busy)?
        .map_err(|_| RouteCandidateSnapshotError::Closed)?;
        timeout(ROLE_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| RouteCandidateSnapshotError::Timeout)?
            .map_err(|_| RouteCandidateSnapshotError::Closed)?
    }

    pub(crate) async fn prepare_client_preselection(
        &self,
        parameters: ClientPreselectionParameters,
    ) -> Result<PreparedPreselectionEvidence, ClientPreselectionError> {
        let (reply, response) = oneshot::channel();
        timeout(
            CLIENT_PRESELECTION_TIMEOUT,
            self.sender
                .send(DiscoveryCommand::BeginClientPreselection { parameters, reply }),
        )
        .await
        .map_err(|_| ClientPreselectionError::Busy)?
        .map_err(|_| ClientPreselectionError::Closed)?;
        timeout(CLIENT_PRESELECTION_TIMEOUT, response)
            .await
            .map_err(|_| ClientPreselectionError::Timeout)?
            .map_err(|_| ClientPreselectionError::Closed)?
    }

    pub(crate) async fn resolve_direct_relay(
        &self,
        expected_node_id: [u8; 32],
        expected_peer_id: Libp2pPeerId,
    ) -> Result<DirectRelayCapability, CapabilityLookupError> {
        let (reply, response) = oneshot::channel();
        self.send_capability(DiscoveryCommand::ResolveDirectRelay {
            expected_node_id,
            expected_peer_id,
            reply,
        })
        .await?;
        Self::await_capability(response).await
    }

    pub(crate) async fn resolve_forwarded_exit(
        &self,
        control_relay_node_id: [u8; 32],
        control_relay_peer_id: Libp2pPeerId,
        exit_node_id: [u8; 32],
        exit_peer_id: Libp2pPeerId,
    ) -> Result<ForwardedExitCapability, CapabilityLookupError> {
        let (reply, response) = oneshot::channel();
        self.send_capability(DiscoveryCommand::ResolveForwardedExit {
            control_relay_node_id,
            control_relay_peer_id,
            exit_node_id,
            exit_peer_id,
            reply,
        })
        .await?;
        Self::await_capability(response).await
    }

    async fn send_capability(
        &self,
        command: DiscoveryCommand,
    ) -> Result<(), CapabilityLookupError> {
        timeout(ROLE_COMMAND_TIMEOUT, self.sender.send(command))
            .await
            .map_err(|_| CapabilityLookupError::Busy)?
            .map_err(|_| CapabilityLookupError::Closed)
    }

    async fn await_capability<T>(
        response: oneshot::Receiver<Option<T>>,
    ) -> Result<T, CapabilityLookupError> {
        timeout(ROLE_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| CapabilityLookupError::Timeout)?
            .map_err(|_| CapabilityLookupError::Closed)?
            .ok_or(CapabilityLookupError::Unavailable)
    }

    pub(crate) async fn request_exit_forward(
        &self,
        control_relay_peer: Libp2pPeerId,
        request: ExitForwardRequest,
    ) -> Result<ExitForwardResponse, OutboundReservationError> {
        request
            .validate()
            .map_err(|_| OutboundReservationError::InvalidRequest)?;
        let (reply, response) = oneshot::channel();
        self.send_rpc(DiscoveryCommand::RequestExitForward {
            control_relay_peer,
            request,
            reply,
        })
        .await?;
        Self::await_rpc(response, EXIT_FORWARD_REQUEST_TIMEOUT).await
    }

    pub(crate) async fn request_datapath_relay(
        &self,
        relay_peer: Libp2pPeerId,
        request: DatapathRelayRequest,
    ) -> Result<DatapathRelayResponse, OutboundReservationError> {
        request
            .validate()
            .map_err(|_| OutboundReservationError::InvalidRequest)?;
        let (reply, response) = oneshot::channel();
        self.send_rpc(DiscoveryCommand::RequestDatapathRelay {
            relay_peer,
            request,
            reply,
        })
        .await?;
        Self::await_rpc(response, DATAPATH_RELAY_REQUEST_TIMEOUT).await
    }

    pub(crate) async fn endpoint_traversal_hints(
        &self,
        bindings: Vec<EndpointTraversalBinding>,
    ) -> Result<Vec<TraversalEndpointHint>, OutboundReservationError> {
        let (reply, response) = oneshot::channel();
        self.send_rpc(DiscoveryCommand::ResolveEndpointTraversalHints { bindings, reply })
            .await?;
        Self::await_rpc(response, ROLE_COMMAND_TIMEOUT).await
    }

    async fn send_rpc(&self, command: DiscoveryCommand) -> Result<(), OutboundReservationError> {
        timeout(ROLE_COMMAND_TIMEOUT, self.sender.send(command))
            .await
            .map_err(|_| OutboundReservationError::Busy)?
            .map_err(|_| OutboundReservationError::Closed)
    }

    async fn await_rpc<T>(
        response: oneshot::Receiver<Result<T, OutboundReservationError>>,
        maximum_wait: Duration,
    ) -> Result<T, OutboundReservationError> {
        timeout(maximum_wait, response)
            .await
            .map_err(|_| OutboundReservationError::AmbiguousAfterDispatch)?
            .map_err(|_| OutboundReservationError::AmbiguousAfterDispatch)?
    }

    async fn send(&self, command: DiscoveryCommand) -> Result<(), DiscoveryControlError> {
        timeout(ROLE_COMMAND_TIMEOUT, self.sender.send(command))
            .await
            .map_err(|_| DiscoveryControlError::Busy)?
            .map_err(|_| DiscoveryControlError::Closed)
    }
}

#[allow(dead_code, reason = "typed route boundary")]
enum DiscoveryCommand {
    SetRoles {
        expected: RolesConfig,
        candidate: RolesConfig,
        reply: oneshot::Sender<Result<RolesConfig, RoleApplyError>>,
    },
    ApplyPolicy {
        policy: Option<VerifiedManifest>,
        reply: oneshot::Sender<()>,
    },
    RouteCandidateSnapshot {
        requested_candidates: usize,
        reply: oneshot::Sender<Result<RouteCandidateSnapshot, RouteCandidateSnapshotError>>,
    },
    BeginClientPreselection {
        parameters: ClientPreselectionParameters,
        reply: oneshot::Sender<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
    },
    ResolveDirectRelay {
        expected_node_id: [u8; 32],
        expected_peer_id: Libp2pPeerId,
        reply: oneshot::Sender<Option<DirectRelayCapability>>,
    },
    ResolveForwardedExit {
        control_relay_node_id: [u8; 32],
        control_relay_peer_id: Libp2pPeerId,
        exit_node_id: [u8; 32],
        exit_peer_id: Libp2pPeerId,
        reply: oneshot::Sender<Option<ForwardedExitCapability>>,
    },
    ResolveEndpointTraversalHints {
        bindings: Vec<EndpointTraversalBinding>,
        reply: oneshot::Sender<Result<Vec<TraversalEndpointHint>, OutboundReservationError>>,
    },
    RequestExitForward {
        control_relay_peer: Libp2pPeerId,
        request: ExitForwardRequest,
        reply: oneshot::Sender<Result<ExitForwardResponse, OutboundReservationError>>,
    },
    RequestDatapathRelay {
        relay_peer: Libp2pPeerId,
        request: DatapathRelayRequest,
        reply: oneshot::Sender<Result<DatapathRelayResponse, OutboundReservationError>>,
    },
}

/// Exact authenticated control peer allowed to contribute one local endpoint observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndpointTraversalBinding {
    pub(crate) path_id: u32,
    pub(crate) role: WireguardRole,
    pub(crate) observer_id: [u8; 32],
    pub(crate) observer_peer_id: Libp2pPeerId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiscoveryControlError {
    Busy,
    Closed,
    Timeout,
    Actor(RoleApplyError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityLookupError {
    Busy,
    Closed,
    Timeout,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteCandidateSnapshotError {
    Busy,
    Closed,
    Timeout,
    InvalidLimit,
    PolicyUnavailable,
    StoreUnavailable,
}

#[allow(dead_code, reason = "typed route boundary")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundReservationError {
    Busy,
    Closed,
    InvalidRequest,
    Capacity,
    SendFailed,
    AmbiguousAfterDispatch,
    RetryExhausted,
    InvalidResponse,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProviderQueryKind {
    Relay,
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClientForwardKey {
    control_relay_peer: Libp2pPeerId,
    forward_id: [u8; FORWARD_ID_BYTES],
}

struct PendingClientForward {
    key: ClientForwardKey,
    expected_exit_peer: Libp2pPeerId,
    operation: ExitForwardOperation,
    expected_exit_node_id: Option<[u8; 32]>,
    authorized_control: DirectRelayCapability,
    authorized_exit: Option<ForwardedExitCapability>,
    canonical_request: Vec<u8>,
    operation_expires_at_ms: u64,
    attempt_deadline: Instant,
    dispatch_attempts: usize,
    reserved_bytes: usize,
    waiters: Vec<oneshot::Sender<Result<ExitForwardResponse, OutboundReservationError>>>,
}

#[derive(Clone)]
struct CompletedClientForward {
    canonical_request: Vec<u8>,
    target_peer: Libp2pPeerId,
    operation: ExitForwardOperation,
    outcome: Result<ExitForwardResponse, OutboundReservationError>,
    expires_at_ms: u64,
    reserved_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RelayForwardKey {
    authenticated_client_peer: Libp2pPeerId,
    forward_id: [u8; FORWARD_ID_BYTES],
}

struct PendingRelayForward {
    key: RelayForwardKey,
    expected_exit_peer: Libp2pPeerId,
    operation: ExitForwardOperation,
    expected_exit_node_id: Option<[u8; 32]>,
    authorized_control: DirectRelayCapability,
    authorized_exit: Option<ForwardedExitCapability>,
    canonical_request: Vec<u8>,
    operation_expires_at_ms: u64,
    attempt_deadline: Instant,
    dispatch_attempts: usize,
    reserved_bytes: usize,
    client_channels: Vec<request_response::ResponseChannel<ExitForwardResponse>>,
    native_ready: Option<PendingNativeProbeReady>,
    native_authorization: Option<PendingNativeProbeAuthorization>,
    native_result: Option<PendingNativeProbeResult>,
    udp_session: Option<PendingUdpSessionStart>,
    mptcp_session: Option<PendingMptcpSessionStart>,
    mpquic_session: Option<PendingMpquicSessionStart>,
}

struct PendingNativeProbeReady {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    channel: request_response::ResponseChannel<DatapathRelayResponse>,
    authenticated_client_peer: Libp2pPeerId,
    permit: VerifiedNativeProbePermit,
    endpoint: RelayEndpointLease,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
}

struct PreparedNativeProbeReady {
    authenticated_client_peer: Libp2pPeerId,
    authorized_relay: DirectRelayCapability,
    ready: IssuedNativeProbeRelayReady,
    endpoint: RelayEndpointLease,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
}

/// One shared Exit helper Prepare for every exact path signed into a native attempt.
struct ExitNativeReadyAttempt {
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    exit_leases: Vec<ExitEndpointLease>,
    authorized_data_relays: HashMap<u32, DirectRelayCapability>,
    ready_paths: HashSet<u32>,
    pending_activations: HashMap<u32, LeaseActivation>,
    activated: bool,
    probe_tasks: HashMap<u32, JoinHandle<Result<[u8; NATIVE_PROBE_DATAGRAM_BYTES], ()>>>,
    pending_results: HashMap<u32, PendingExitNativeProbeResult>,
    candidate_set_hash: [u8; 32],
    expires_at_ms: u64,
    cleanup_not_before_ms: u64,
}

struct PendingExitNativeProbeResult {
    connection: BoundNativeProbeDataRelayConnection,
    authenticated_data_relay: Libp2pPeerId,
    authenticated_data_relay_node_id: [u8; 32],
    probe_id: [u8; FORWARD_ID_BYTES],
    forward_id: [u8; FORWARD_ID_BYTES],
    path_id: u32,
    observed_network_prefix: ObservationNetworkPrefix,
    scope: NativeProbePathScope,
    channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
}

/// Relay-owned affine Start plus the exact already-prepared helper endpoint pair.
///
/// A preceding Ready/Start handler installs this value under the authenticated client and derived
/// authorization request ID. `NativeProbeAuthorize` consumes it exactly once before any upstream
/// Exit dispatch.
struct PreparedNativeProbeAuthorization {
    authenticated_client_peer: Libp2pPeerId,
    authorized_relay: DirectRelayCapability,
    start: VerifiedNativeProbeStartForRelay,
    endpoint: RelayEndpointLease,
}

struct PendingNativeProbeAuthorization {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    channel: request_response::ResponseChannel<DatapathRelayResponse>,
    start: VerifiedNativeProbeStartForRelay,
    endpoint: RelayEndpointLease,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
}

struct ActiveNativeRelayProbe {
    authenticated_client_peer: Libp2pPeerId,
    authorized_relay: DirectRelayCapability,
    endpoint: RelayEndpointLease,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
}

/// One fresh, helper-observed native probe that may authorize exactly one standard probe result.
///
/// The standard reservation protocol deliberately carries no native endpoints. Retaining this
/// affine ticket lets its `ExecuteProbe` phase reuse the immediately preceding real
/// Client-to-Relay-to-Exit observation instead of fabricating a second probe or accepting an
/// unsigned metric. The ticket is consumed when the Relay signs that result.
struct RecentNativeRelayEvidence {
    authenticated_client_peer: Libp2pPeerId,
    scope: NativeProbePathScope,
    client_relay: ProbeLegEvidence,
    relay_exit: ProbeLegEvidence,
    expires_at_ms: u64,
}

/// One Exit-observed native proof that may authorize exactly one structurally verified standard
/// result from the same actors, policy and transport.
///
/// Native preselection and the later reservation intentionally use different ephemeral client
/// sessions. The one-shot ticket plus exact authenticated actor lineage bridges those phases;
/// their unrelated session identifiers must never be compared.
#[derive(Clone)]
struct RecentNativeExitEvidence {
    evidence_id: [u8; 32],
    scope: NativeProbePathScope,
    authenticated_data_relay_node_id: [u8; 32],
    authenticated_data_relay_peer_id: Vec<u8>,
    measured_at_ms: u64,
    expires_at_ms: u64,
}

struct ExactNativeExitEvidenceVerifier {
    tickets: Vec<RecentNativeExitEvidence>,
    consumed: Mutex<HashSet<[u8; 32]>>,
    now_ms: u64,
}

impl ExactNativeExitEvidenceVerifier {
    fn new(tickets: &[RecentNativeExitEvidence], now_ms: u64) -> Self {
        Self {
            tickets: tickets.to_vec(),
            consumed: Mutex::new(HashSet::new()),
            now_ms,
        }
    }

    fn consumed(&self) -> HashSet<[u8; 32]> {
        self.consumed
            .lock()
            .map_or_else(|_| HashSet::new(), |consumed| consumed.clone())
    }
}

impl ProbeEvidenceVerifier for ExactNativeExitEvidenceVerifier {
    fn verify(&self, evidence: &ProbeEvidence<'_>) -> Result<(), ProbeEvidenceError> {
        let result = decoded_signed_payload::<RelayProbeResult>(evidence.signed_result()).ok_or(
            ProbeEvidenceError::Rejected("standard probe result framing"),
        )?;
        let consumed = self
            .consumed
            .lock()
            .map_err(|_| ProbeEvidenceError::Unavailable)?;
        let ticket = self.tickets.iter().find(|ticket| {
            !consumed.contains(&ticket.evidence_id)
                && native_exit_ticket_matches_standard_result(
                    ticket,
                    &result,
                    evidence,
                    self.now_ms,
                )
        });
        let evidence_id =
            ticket
                .map(|ticket| ticket.evidence_id)
                .ok_or(ProbeEvidenceError::Rejected(
                    "matching native Exit evidence unavailable",
                ))?;
        drop(consumed);
        self.consumed
            .lock()
            .map_err(|_| ProbeEvidenceError::Unavailable)?
            .insert(evidence_id);
        Ok(())
    }
}

struct PendingNativeProbeResult {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    channel: request_response::ResponseChannel<DatapathRelayResponse>,
    start: VerifiedNativeProbeStartForRelay,
    endpoint: RelayEndpointLease,
    committed: CommittedLeaseBatch,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
}

struct PreparedProductionRelayRoute {
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    accepted: AcceptedRelayReservation,
    authenticated_client_peer: Libp2pPeerId,
    commit: Option<CommitLeaseBatch>,
    committed_start: Option<Vec<u8>>,
    committed_signal: Option<Vec<u8>>,
    usable: bool,
    expires_at_ms: u64,
    cleanup_not_before_ms: u64,
}

fn helper_cleanup_due(expires_at_ms: u64, cleanup_not_before_ms: u64, now_ms: u64) -> bool {
    now_ms == u64::MAX || (expires_at_ms <= now_ms && cleanup_not_before_ms <= now_ms)
}

struct PendingUdpSessionStart {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    route_context_id: [u8; FORWARD_ID_BYTES],
    channels: Vec<request_response::ResponseChannel<DatapathRelayResponse>>,
    canonical_start: Vec<u8>,
    route: PreparedProductionRelayRoute,
}

struct PendingMptcpSessionStart {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    route_context_id: [u8; FORWARD_ID_BYTES],
    channels: Vec<request_response::ResponseChannel<DatapathRelayResponse>>,
    canonical_start: Vec<u8>,
    selected_path_ids: Vec<u32>,
    route: PreparedProductionRelayRoute,
}

struct PendingMpquicSessionStart {
    datapath_request_id: [u8; FORWARD_ID_BYTES],
    route_context_id: [u8; FORWARD_ID_BYTES],
    channels: Vec<request_response::ResponseChannel<DatapathRelayResponse>>,
    canonical_start: Vec<u8>,
    route: PreparedProductionRelayRoute,
}

struct VerifiedMpquicRelayDispatch {
    exit: ExitReservation,
    relay: RelayReservation,
    signed_relay_reservation: Vec<u8>,
}

struct PendingMptcpExitRelay {
    forward_id: [u8; FORWARD_ID_BYTES],
    channels: Vec<request_response::ResponseChannel<UpstreamExitForwardResponse>>,
}

struct PendingMptcpExitSession {
    canonical_start: Vec<u8>,
    selected_path_ids: Vec<u32>,
    relays: HashMap<u32, PendingMptcpExitRelay>,
    expires_at_ms: u64,
}

struct PendingMpquicExitRelay {
    forward_id: [u8; FORWARD_ID_BYTES],
    channels: Vec<request_response::ResponseChannel<UpstreamExitForwardResponse>>,
}

struct PendingMpquicExitSession {
    canonical_start: Vec<u8>,
    selected_path_ids: Vec<u32>,
    relays: HashMap<u32, PendingMpquicExitRelay>,
    expires_at_ms: u64,
}

/// Exit-owned helper context and finalized grant awaiting exact Relay confirmations.
///
/// The helper leases are prepared before their public endpoints are signed. Activation happens
/// only after `ExitService` has authenticated each Relay reservation and exposed its exact public
/// relay-to-Exit endpoint. Commit and transport-socket adoption remain deferred to the exact
/// transport-specific session Start.
struct PreparedProductionExitRoute {
    canonical_finalize_request: Vec<u8>,
    bundle: AcceptedExitReservationBundle,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    exit_leases: Vec<ExitEndpointLease>,
    pending_activations: HashMap<u32, LeaseActivation>,
    commit: Option<CommitLeaseBatch>,
    mpquic_preflight: Option<ProductionMpquicExitPreflight>,
    expires_at_ms: u64,
    cleanup_not_before_ms: u64,
}

/// A genuine helper-owned Exit MPTCP listener retained with its reservation and TLS identity.
///
/// The stream/TLS proxy consumes these owners in the next vertical slice. Until then the actor
/// keeps them affine, answers only exact idempotent Start retries, and destroys the helper context
/// at signed expiry.
pub(crate) struct ActiveProductionMptcpExitRoute {
    canonical_start: Vec<u8>,
    encoded_signal: Vec<u8>,
    runtime: Option<ProductionMptcpExitRuntime>,
    cleanup: Option<ProductionMptcpExitCleanup>,
    runtime_started: bool,
    reservation_id: [u8; FORWARD_ID_BYTES],
    expires_at_ms: u64,
    cleanup_not_before_ms: u64,
}

struct MptcpExitRuntimeCompletionEvent {
    route_context_id: [u8; FORWARD_ID_BYTES],
    completion: ProductionMptcpExitCompletion,
}

enum MptcpExitRuntimeEvent {
    FlowCompleted {
        route_context_id: [u8; FORWARD_ID_BYTES],
        reservation_id: [u8; FORWARD_ID_BYTES],
        succeeded: bool,
    },
    RuntimeCompleted(MptcpExitRuntimeCompletionEvent),
}

#[derive(Clone)]
struct CompletedRelayForward {
    canonical_request: Vec<u8>,
    target_peer: Libp2pPeerId,
    operation: ExitForwardOperation,
    response: Option<ExitForwardResponse>,
    expires_at_ms: u64,
    reserved_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DatapathKey {
    relay_peer: Libp2pPeerId,
    request_id: [u8; FORWARD_ID_BYTES],
}

struct PendingDatapath {
    key: DatapathKey,
    operation: DatapathRelayOperation,
    relay_node_id: [u8; 32],
    authorized_relay: DirectRelayCapability,
    canonical_request: Vec<u8>,
    operation_expires_at_ms: u64,
    attempt_deadline: Instant,
    dispatch_attempts: usize,
    reserved_bytes: usize,
    waiters: Vec<oneshot::Sender<Result<DatapathRelayResponse, OutboundReservationError>>>,
}

#[derive(Clone)]
struct CompletedDatapath {
    canonical_request: Vec<u8>,
    outcome: Result<DatapathRelayResponse, OutboundReservationError>,
    expires_at_ms: u64,
    reserved_bytes: usize,
}

#[derive(Clone)]
struct RetryLedgerEntry {
    canonical_request: Vec<u8>,
    operation: Option<ExitForwardOperation>,
    dispatch_attempts: usize,
    expires_at_ms: u64,
    reserved_bytes: usize,
    target_peer: Libp2pPeerId,
}

/// Exact service-local handoff for one authenticated native-Permit response.
///
/// The opaque connection proof and behaviour-local response channel stay together until the
/// immediate synchronous send boundary. Signed Permit bytes are only a response projection; the
/// affine phase owner remains inside `ExitService` across a closed or ambiguous channel.
#[must_use = "a prepared native-Permit response must be sent or dropped as one owner"]
struct PreparedNativeProbePermitResponse {
    connection: BoundNativeProbeControlConnection,
    authenticated_control_relay: Libp2pPeerId,
    channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    response: UpstreamExitForwardResponse,
}

/// Exact service-local handoff for one authenticated native authorization response.
///
/// The selected data-Relay connection proof remains affine through the immediate synchronous
/// response send. The Exit service has already independently verified all five signed phases and
/// retained its standard reservation before this value can exist.
#[must_use = "a prepared native authorization response must be sent or dropped as one owner"]
struct PreparedNativeProbeAuthorizationResponse {
    connection: BoundNativeProbeDataRelayConnection,
    authenticated_data_relay: Libp2pPeerId,
    channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    response: UpstreamExitForwardResponse,
}

/// Opaque identity of one freshly verified canonical advertisement payload.
///
/// The bytes never cross the agent's public API. Equality is carried through discovery,
/// selection and route setup so a same-actor advertisement replacement cannot inherit a stale
/// observation or selection binding. The digest grants no reservation, dispatch or session
/// authority.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct AdvertisementPayloadHash([u8; 32]);

impl AdvertisementPayloadHash {
    fn from_fresh_fingerprint(value: [u8; 32]) -> Option<Self> {
        value.iter().any(|byte| *byte != 0).then_some(Self(value))
    }

    /// Append this exact authenticated digest to an endpoint-free native-probe commitment.
    ///
    /// This purpose-limited writer avoids introducing a general byte accessor for the opaque
    /// equality token. The digest remains non-authoritative and never reveals an endpoint.
    pub(crate) fn append_native_probe_commitment(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    /// Compare one untrusted wire digest to this exact authenticated native-probe commitment.
    ///
    /// This purpose-limited equality check avoids exposing the opaque digest bytes to the caller.
    fn matches_native_probe_commitment(&self, wire_digest: &[u8]) -> bool {
        self.0.as_slice() == wire_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: [u8; 32]) -> Self {
        Self::from_fresh_fingerprint(value).expect("non-zero advertisement payload hash")
    }

    #[cfg(test)]
    pub(crate) fn xor_for_test(mut self) -> Self {
        self.0[0] ^= 1;
        assert!(self.0.iter().any(|byte| *byte != 0));
        self
    }
}

impl fmt::Debug for AdvertisementPayloadHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvertisementPayloadHash([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectRelayCapability {
    pub(crate) node_id: [u8; 32],
    pub(crate) peer_id: Libp2pPeerId,
    pub(crate) public_key: [u8; 32],
    pub(crate) advertisement_sequence: u64,
    pub(crate) advertisement_expires_at_ms: u64,
    pub(crate) advertisement_payload_hash: AdvertisementPayloadHash,
    pub(crate) policy_version: u64,
    pub(crate) policy_hash: [u8; 32],
    pub(crate) policy_expires_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ForwardedExitCapability {
    pub(crate) control_relay_node_id: [u8; 32],
    pub(crate) control_relay_peer_id: Libp2pPeerId,
    pub(crate) control_relay_public_key: [u8; 32],
    pub(crate) control_relay_advertisement_sequence: u64,
    pub(crate) control_relay_advertisement_expires_at_ms: u64,
    pub(crate) control_relay_advertisement_payload_hash: AdvertisementPayloadHash,
    pub(crate) exit_node_id: [u8; 32],
    pub(crate) exit_peer_id: Libp2pPeerId,
    pub(crate) exit_public_key: [u8; 32],
    pub(crate) exit_advertisement_sequence: u64,
    pub(crate) exit_advertisement_expires_at_ms: u64,
    pub(crate) exit_advertisement_payload_hash: AdvertisementPayloadHash,
    pub(crate) policy_version: u64,
    pub(crate) policy_hash: [u8; 32],
    pub(crate) policy_expires_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}

/// Exact active-policy metadata captured once by the discovery actor.
///
/// Fields stay private so sibling modules can consume, but cannot forge, a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteCandidatePolicySnapshot {
    version: u64,
    hash: [u8; 32],
    expires_at_ms: u64,
}

impl RouteCandidatePolicySnapshot {
    pub(crate) const fn version(&self) -> u64 {
        self.version
    }

    pub(crate) const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub(crate) const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Revalidated advertisement projection safe to hand to in-process selection.
///
/// The signed envelope, fingerprint signature and encoded length, persisted endpoint, and stored
/// RTT/capacity values stay inside discovery. Only the opaque, redacted payload-hash equality
/// binding leaves discovery; it grants no authority. A bounded local measurement count,
/// historical reputation and a serious-fault cooldown are the only peerstore evidence projected;
/// none is fresh route reachability or capacity evidence.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RouteCandidateAdvertisement {
    advertisement: CoreAdvertisement,
    signed_measured_at_ms: u64,
    signed_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    local_measurement_count: usize,
    historical_reputation_score: f64,
    serious_protocol_fault_until: Option<UnixTime>,
}

impl RouteCandidateAdvertisement {
    pub(crate) const fn advertisement(&self) -> &CoreAdvertisement {
        &self.advertisement
    }

    pub(crate) const fn signed_measured_at_ms(&self) -> u64 {
        self.signed_measured_at_ms
    }

    pub(crate) const fn signed_expires_at_ms(&self) -> u64 {
        self.signed_expires_at_ms
    }

    pub(crate) const fn advertisement_payload_hash(&self) -> AdvertisementPayloadHash {
        self.advertisement_payload_hash
    }

    pub(crate) const fn local_measurement_count(&self) -> usize {
        self.local_measurement_count
    }

    pub(crate) const fn historical_reputation_score(&self) -> f64 {
        self.historical_reputation_score
    }

    pub(crate) const fn serious_protocol_fault_until(&self) -> Option<UnixTime> {
        self.serious_protocol_fault_until
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        stored: &volparossa_peerstore::StoredPeer,
        now_ms: u64,
    ) -> Result<Self, StoredAdvertisementError> {
        let exact = revalidate_stored_advertisement(stored, now_ms)?;
        Ok(Self {
            advertisement: stored.advertisement.clone(),
            signed_measured_at_ms: exact.signed_measured_at_ms,
            signed_expires_at_ms: exact.signed_expires_at_ms,
            advertisement_payload_hash: exact.fingerprint.payload_hash,
            local_measurement_count: stored.evidence.measurement_count,
            historical_reputation_score: stored.evidence.reputation_score(),
            serious_protocol_fault_until: stored.evidence.serious_protocol_fault_until,
        })
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct DirectRelayCandidateSnapshot {
    advertisement: RouteCandidateAdvertisement,
    capability: DirectRelayCapability,
    authenticated_local_prefix: Option<volparossa_core::ObservedNetworkPrefix>,
}

impl fmt::Debug for DirectRelayCandidateSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectRelayCandidateSnapshot")
            .field("advertisement", &self.advertisement)
            .field("capability", &self.capability)
            .field(
                "has_authenticated_local_prefix",
                &self.authenticated_local_prefix.is_some(),
            )
            .finish()
    }
}

impl DirectRelayCandidateSnapshot {
    pub(crate) const fn advertisement(&self) -> &RouteCandidateAdvertisement {
        &self.advertisement
    }

    pub(crate) const fn capability(&self) -> &DirectRelayCapability {
        &self.capability
    }

    /// Current authenticated LAN metadata for sampling, never a `FreshEvidence` capability.
    pub(crate) const fn authenticated_local_prefix(
        &self,
    ) -> Option<volparossa_core::ObservedNetworkPrefix> {
        self.authenticated_local_prefix
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        advertisement: RouteCandidateAdvertisement,
        capability: DirectRelayCapability,
    ) -> Self {
        Self {
            advertisement,
            capability,
            authenticated_local_prefix: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_local_prefix(
        advertisement: RouteCandidateAdvertisement,
        capability: DirectRelayCapability,
        prefix: volparossa_core::ObservedNetworkPrefix,
    ) -> Self {
        Self {
            advertisement,
            capability,
            authenticated_local_prefix: Some(prefix),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ForwardedExitCandidateSnapshot {
    advertisement: RouteCandidateAdvertisement,
    control: DirectRelayCandidateSnapshot,
    capability: ForwardedExitCapability,
}

impl ForwardedExitCandidateSnapshot {
    pub(crate) const fn advertisement(&self) -> &RouteCandidateAdvertisement {
        &self.advertisement
    }

    pub(crate) const fn control(&self) -> &DirectRelayCandidateSnapshot {
        &self.control
    }

    pub(crate) const fn capability(&self) -> &ForwardedExitCapability {
        &self.capability
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        advertisement: RouteCandidateAdvertisement,
        control: DirectRelayCandidateSnapshot,
        capability: ForwardedExitCapability,
    ) -> Self {
        Self {
            advertisement,
            control,
            capability,
        }
    }
}

/// Bounded, actor-linearized input to route-selection preflight.
///
/// This process-local type is intentionally not serializable and carries no dispatch authority.
pub(crate) struct RouteCandidateSnapshot {
    captured_at_ms: u64,
    policy: RouteCandidatePolicySnapshot,
    direct_relays: Vec<DirectRelayCandidateSnapshot>,
    forwarded_exits: Vec<ForwardedExitCandidateSnapshot>,
    preselection_subjects: preselection_observation::PreselectionSubjectSet,
}

impl RouteCandidateSnapshot {
    pub(crate) const fn captured_at_ms(&self) -> u64 {
        self.captured_at_ms
    }

    pub(crate) const fn policy(&self) -> RouteCandidatePolicySnapshot {
        self.policy
    }

    pub(crate) fn direct_relays(&self) -> &[DirectRelayCandidateSnapshot] {
        &self.direct_relays
    }

    pub(crate) fn forwarded_exits(&self) -> &[ForwardedExitCandidateSnapshot] {
        &self.forwarded_exits
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        captured_at_ms: u64,
        policy: RouteCandidatePolicySnapshot,
        direct_relays: Vec<DirectRelayCandidateSnapshot>,
        forwarded_exits: Vec<ForwardedExitCandidateSnapshot>,
    ) -> Self {
        Self {
            captured_at_ms,
            policy,
            direct_relays,
            forwarded_exits,
            preselection_subjects:
                preselection_observation::PreselectionSubjectSet::unavailable_for_test(),
        }
    }
}

#[cfg(test)]
impl RouteCandidatePolicySnapshot {
    pub(crate) const fn for_test(version: u64, hash: [u8; 32], expires_at_ms: u64) -> Self {
        Self {
            version,
            hash,
            expires_at_ms,
        }
    }
}

#[derive(Clone)]
struct RevalidatedStoredCandidate {
    advertisement: RouteCandidateAdvertisement,
    revalidated: RevalidatedAdvertisement,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ForwardedExitKey {
    control_relay_peer: Libp2pPeerId,
    exit_peer: Libp2pPeerId,
}

enum AutomaticExitFetchAttemptState {
    InFlight(oneshot::Receiver<Result<ExitForwardResponse, OutboundReservationError>>),
    RetryNotBefore(u64),
}

struct AutomaticExitFetchAttempt {
    key: ForwardedExitKey,
    authorized_control: DirectRelayCapability,
    request: ExitForwardRequest,
    dispatch_attempts: usize,
    state: AutomaticExitFetchAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ForwardedIngestAuthority {
    authorized_control: DirectRelayCapability,
    attempt_deadline: Instant,
    operation_expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdvertisementProvenance {
    DirectRelay {
        authenticated_peer: Libp2pPeerId,
    },
    ForwardedExit {
        control_relay_node_id: [u8; 32],
        control_relay_peer: Libp2pPeerId,
        exit_node_id: [u8; 32],
        exit_peer: Libp2pPeerId,
        request_deadline_ms: u64,
        authority: Box<ForwardedIngestAuthority>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedAdvertisement {
    node_id: [u8; 32],
    peer_id: Libp2pPeerId,
    public_key: [u8; 32],
    sequence_number: u64,
    advertisement_expires_at_ms: u64,
    policy_version: u64,
    policy_hash: [u8; 32],
    policy_expires_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct AdvertisementCommitClock {
    unix_ms: u64,
    monotonic: Instant,
}

impl AdvertisementCommitClock {
    fn now() -> Self {
        Self {
            unix_ms: unix_millis(),
            monotonic: Instant::now(),
        }
    }
}

struct PreparedAdvertisementCommit {
    peer: Libp2pPeerId,
    provenance: AdvertisementProvenance,
    envelope: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdvertisementCommitStatus {
    Rejected,
    CommittedWithoutCapability,
    Committed,
}

struct AdvertisementCommitOutcome {
    status: AdvertisementCommitStatus,
    accepted: Option<AcceptedAdvertisement>,
    refresh_candidates: bool,
    diagnostic: Option<(LogLevel, &'static str, u64)>,
}

impl AdvertisementCommitOutcome {
    const fn rejected(diagnostic: Option<(LogLevel, &'static str, u64)>) -> Self {
        Self {
            status: AdvertisementCommitStatus::Rejected,
            accepted: None,
            refresh_candidates: false,
            diagnostic,
        }
    }

    const fn accepted(
        accepted: AcceptedAdvertisement,
        diagnostic: Option<(LogLevel, &'static str, u64)>,
    ) -> Self {
        Self {
            status: AdvertisementCommitStatus::Committed,
            accepted: Some(accepted),
            refresh_candidates: true,
            diagnostic,
        }
    }

    const fn committed_without_capability(
        diagnostic: Option<(LogLevel, &'static str, u64)>,
    ) -> Self {
        Self {
            status: AdvertisementCommitStatus::CommittedWithoutCapability,
            accepted: None,
            refresh_candidates: true,
            diagnostic,
        }
    }

    const fn accepted_advertisement(&self) -> Option<AcceptedAdvertisement> {
        self.accepted
    }
}

struct ForwardedAdvertisementIngest {
    valid: bool,
    commit: Option<AdvertisementCommitOutcome>,
}

impl ForwardedAdvertisementIngest {
    const fn valid_without_advertisement() -> Self {
        Self {
            valid: true,
            commit: None,
        }
    }

    const fn invalid() -> Self {
        Self {
            valid: false,
            commit: None,
        }
    }

    fn from_commit(commit: AdvertisementCommitOutcome) -> Self {
        Self {
            valid: commit.status == AdvertisementCommitStatus::Committed,
            commit: Some(commit),
        }
    }
}
#[cfg(test)]
#[derive(Clone)]
struct AdvertisementCommitTestGate {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

#[cfg(test)]
impl AdvertisementCommitTestGate {
    fn new() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn pause(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("test gate remains open")
            .forget();
    }

    async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("test gate remains open")
            .forget();
    }

    fn release(&self) {
        self.release.add_permits(1);
    }
}

#[cfg(test)]
#[derive(Default)]
struct AdvertisementCommitTestBarriers {
    before_commit: Option<AdvertisementCommitTestGate>,
    after_commit: Option<AdvertisementCommitTestGate>,
    before_finish: Option<AdvertisementCommitTestGate>,
    policy_apply_pre_reply: Option<PolicyApplyPreReplyBarrier>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PrivacyConflictKey {
    peer_id: Libp2pPeerId,
    advertisement_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ForwardedAdvertisementReplayKey {
    control_relay_peer: Libp2pPeerId,
    exit_sender_id: [u8; 32],
    nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdvertisementFingerprint {
    encoded_len: usize,
    payload_hash: AdvertisementPayloadHash,
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedAdvertisementRecord {
    sequence_number: u64,
    expires_at_ms: u64,
    fingerprint: AdvertisementFingerprint,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OutboundReapCounts {
    ambiguous: usize,
    canceled: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundEventOutcome {
    Completed,
    Failed,
    InvalidResponse,
    PeerMismatch,
    Unexpected,
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct PolicyApplyPreReplySnapshot {
    active_policy_version: u64,
    direct_relays: usize,
    local_relay_snapshots: usize,
    forwarded_exits: usize,
    pending_client_forwards: usize,
    client_forward_index: usize,
    retry_client_forwards: usize,
    completed_client_forwards: usize,
    invalid_client_tombstones: usize,
    pending_relay_forwards: usize,
    relay_forward_index: usize,
    retry_relay_forwards: usize,
    completed_relay_forwards: usize,
    withdrawn_relay_tombstones: usize,
    exit_services: usize,
    served_local_advertisements: usize,
    service_local_advertisements: usize,
    active_provider_keys: usize,
}

#[cfg(test)]
struct PolicyApplyPreReplyBarrier {
    reached: oneshot::Sender<PolicyApplyPreReplySnapshot>,
    release: oneshot::Receiver<()>,
}

/// Actor-side role transaction outcome.
#[allow(dead_code, reason = "stable fail-closed control error surface")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoleApplyError {
    StateDiverged,
    Prerequisites,
    PolicyUnavailable,
    ServiceUnavailable,
    Persistence,
    RestartRequired,
}

struct ActiveClientPreselection {
    dispatch: DispatchedPreselectionAttempt,
    transports: Vec<BoundClientPreselectionTransport>,
    reply: oneshot::Sender<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
    request_deadline: Instant,
    attempt_deadline: Instant,
    terminal_error: Option<ClientPreselectionError>,
}

/// Single affine owner for the complete client preselection lifecycle.
///
/// `Lost` is a private move sentinel only. Every transition replaces it synchronously with exact
/// retained authority, cooling authority, or permanent closure before returning to the actor loop.
enum ClientPreselectionOwner {
    Available(PreselectionAttemptGate),
    Active(ActiveClientPreselection),
    Cooling(CoolingPreselectionAttemptGate),
    Closed,
    Lost,
}

/// Owns non-`Sync` discovery and `SQLite` values inside one async actor.
pub struct DiscoveryRuntime {
    service: DiscoveryService,
    store: PeerStore,
    replay: ReplayCache,
    forwarded_ad_replays: HashMap<ForwardedAdvertisementReplayKey, u64>,
    forwarded_replay_capacity: usize,
    identity: Identity,
    local_public_key: [u8; 32],
    local_node_id: [u8; 32],
    config: Config,
    roles: RolesConfig,
    helper: HelperClient,
    mpquic_socket: PathBuf,
    relay_service: Option<RelayService>,
    exit_service: Option<ExitService>,
    metrics: MetricsRegistry,
    role_commands: mpsc::Receiver<DiscoveryCommand>,
    client_preselection: ClientPreselectionOwner,
    provider_queries: HashMap<kad::QueryId, ProviderQueryKind>,
    relay_provider_peers: HashMap<Libp2pPeerId, u64>,
    // Scheduling-only partition: these untrusted provider IDs are never dialed for Client relay
    // advertisements. Signed forwarded provenance is still required to become an Exit candidate.
    reserved_provider_exit_peers: HashMap<Libp2pPeerId, u64>,
    relay_advertisement_requests: HashMap<request_response::OutboundRequestId, Libp2pPeerId>,
    exit_provider_peers: HashMap<Libp2pPeerId, u64>,
    automatic_exit_fetches: HashMap<ForwardedExitKey, u64>,
    automatic_exit_fetch_attempts: Vec<AutomaticExitFetchAttempt>,
    // Bounded, non-authoritative control scheduling hint. Every fetch still revalidates the current
    // direct Relay capability, provider observation, signed Exit advertisement and policy.
    preferred_exit_controls: HashMap<Libp2pPeerId, Libp2pPeerId>,
    direct_relays: HashMap<Libp2pPeerId, DirectRelayCapability>,
    // Incoming data-relay authority for this node's Exit service is not local Client selection.
    exit_data_relays: HashMap<Libp2pPeerId, DirectRelayCapability>,
    /// Signed control authorities for this Exit service, independent from its Client selection.
    exit_control_relays: HashMap<Libp2pPeerId, DirectRelayCapability>,
    local_relay_snapshot: Option<DirectRelayCapability>,
    forwarded_exits: HashMap<ForwardedExitKey, ForwardedExitCapability>,
    forwarded_exit_targets: HashMap<Libp2pPeerId, u64>,
    privacy_conflicts: HashMap<PrivacyConflictKey, u64>,
    forwarded_exit_fail_closed_until_ms: u64,
    accepted_advertisements: HashMap<[u8; 32], AcceptedAdvertisementRecord>,
    pending_client_forwards: HashMap<request_response::OutboundRequestId, PendingClientForward>,
    client_forward_index: HashMap<ClientForwardKey, request_response::OutboundRequestId>,
    completed_client_forwards: HashMap<ClientForwardKey, CompletedClientForward>,
    retry_client_forwards: HashMap<ClientForwardKey, RetryLedgerEntry>,
    pending_relay_forwards: HashMap<request_response::OutboundRequestId, PendingRelayForward>,
    relay_forward_index: HashMap<RelayForwardKey, request_response::OutboundRequestId>,
    completed_relay_forwards: HashMap<RelayForwardKey, CompletedRelayForward>,
    retry_relay_forwards: HashMap<RelayForwardKey, RetryLedgerEntry>,
    prepared_native_ready: HashMap<[u8; FORWARD_ID_BYTES], PreparedNativeProbeReady>,
    prepared_native_authorizations:
        HashMap<[u8; FORWARD_ID_BYTES], PreparedNativeProbeAuthorization>,
    prepared_native_authorization_helpers:
        HashMap<[u8; FORWARD_ID_BYTES], RuntimeBoundPreparedLeaseBatch>,
    active_native_relay_helpers: HashMap<[u8; FORWARD_ID_BYTES], ActiveNativeRelayProbe>,
    recent_native_relay_evidence: Vec<RecentNativeRelayEvidence>,
    recent_native_exit_evidence: Vec<RecentNativeExitEvidence>,
    prepared_production_relay_routes: HashMap<[u8; FORWARD_ID_BYTES], PreparedProductionRelayRoute>,
    prepared_production_exit_routes: HashMap<[u8; FORWARD_ID_BYTES], PreparedProductionExitRoute>,
    pending_mptcp_exit_sessions: HashMap<[u8; FORWARD_ID_BYTES], PendingMptcpExitSession>,
    pending_mpquic_exit_sessions: HashMap<[u8; FORWARD_ID_BYTES], PendingMpquicExitSession>,
    active_production_mptcp_exit_routes:
        HashMap<[u8; FORWARD_ID_BYTES], ActiveProductionMptcpExitRoute>,
    mptcp_exit_runtime_events: mpsc::Sender<MptcpExitRuntimeEvent>,
    mptcp_exit_runtime_completions: mpsc::Receiver<MptcpExitRuntimeEvent>,
    exit_native_ready_attempts: HashMap<[u8; FORWARD_ID_BYTES], ExitNativeReadyAttempt>,
    pending_exit_native_ready: HashMap<[u8; FORWARD_ID_BYTES], native_ready::ExitNativeReadySet>,
    pending_datapath: HashMap<request_response::OutboundRequestId, PendingDatapath>,
    datapath_index: HashMap<DatapathKey, request_response::OutboundRequestId>,
    completed_datapath: HashMap<DatapathKey, CompletedDatapath>,
    retry_datapath: HashMap<DatapathKey, RetryLedgerEntry>,
    candidate_limit: usize,
    observed_endpoints: HashMap<Libp2pPeerId, (String, Option<IpAddr>)>,
    local_endpoint_observations: HashMap<Libp2pPeerId, BTreeSet<IpAddr>>,
    publisher: AdvertisementPublisher,
    served_local_advertisement: Option<Vec<u8>>,
    control_addresses: BTreeSet<String>,
    active_provider_keys: BTreeSet<String>,
    #[cfg(test)]
    advertisement_commit_test_barriers: AdvertisementCommitTestBarriers,
    #[cfg(test)]
    route_snapshot_store_failure: bool,
    #[cfg(test)]
    route_snapshot_build_attempts: Cell<usize>,
}

impl DiscoveryRuntime {
    /// Install listeners and initial peer dials only after the owned mesh address exists.
    /// No radio operation is performed by this unprivileged actor.
    pub(crate) fn configure_mesh_network(
        &mut self,
        mesh_installed: bool,
    ) -> Result<(), DiscoveryRuntimeError> {
        configure_network(&mut self.service, &self.config)?;
        if mesh_installed {
            if let Some(address) = mesh_listener_address(&self.config)? {
                self.service
                    .listen_on(address)
                    .map_err(|_| DiscoveryRuntimeError::Build)?;
            }
        }
        Ok(())
    }

    /// Builds and configures the real libp2p swarm without altering host routes,
    /// firewall, DNS, or interfaces.
    #[allow(
        clippy::too_many_lines,
        reason = "construction installs all actor-owned services and affine preselection state"
    )]
    pub fn new(
        identity: Identity,
        config: &Config,
        store: PeerStore,
        sequence_path: PathBuf,
        resources: DiscoveryRuntimeResources,
    ) -> Result<(Self, DiscoveryControlHandle), DiscoveryRuntimeError> {
        let DiscoveryRuntimeResources {
            roles,
            policy,
            role_store: _role_store,
            metrics,
            helper,
            mpquic_socket,
        } = resources;
        let protocol_roles = DiscoveryProtocolRoles::new(roles.client, roles.relay, roles.exit);
        let mut service =
            DiscoveryService::new_with_protocol_roles(identity.keypair().clone(), protocol_roles)
                .map_err(|_| DiscoveryRuntimeError::Build)?;
        let local_public_key = identity
            .ed25519_public_key_bytes()
            .map_err(|_| DiscoveryRuntimeError::Build)?;
        let local_node_id = node_id_from_public_key(&local_public_key);
        // An explicitly configured mesh and its on-link bootstrap addresses do not exist yet.
        // Startup creates the helper-owned interface before listening/dialing on that underlay.
        if !config.wifi_mesh.enabled {
            configure_network(&mut service, config)?;
        }
        let replay_capacity = config
            .network
            .candidate_pool_size
            .saturating_mul(4)
            .clamp(256, 40_000);
        let replay = ReplayCache::new(replay_capacity).map_err(|_| DiscoveryRuntimeError::Build)?;
        let mut effective = config.clone();
        effective.roles = roles;
        effective
            .validate()
            .map_err(|_| DiscoveryRuntimeError::RolePrerequisites)?;
        let relay_service = if roles.relay {
            Some(
                build_relay_service(local_node_id, config, &metrics)
                    .map_err(|()| DiscoveryRuntimeError::ReservationService)?,
            )
        } else {
            None
        };
        let exit_service = if roles.exit {
            let policy = policy.ok_or(DiscoveryRuntimeError::PolicyUnavailable)?;
            Some(
                build_exit_service(local_node_id, config, policy, &metrics)
                    .map_err(|()| DiscoveryRuntimeError::ReservationService)?,
            )
        } else {
            None
        };
        let (role_sender, role_commands) = mpsc::channel(ROLE_COMMAND_CAPACITY);
        let (mptcp_exit_runtime_events, mptcp_exit_runtime_completions) =
            mpsc::channel(MPTCP_EXIT_RUNTIME_EVENT_CAPACITY);
        let client_preselection = if roles.client {
            PreselectionAttemptGate::new().map_or(
                ClientPreselectionOwner::Closed,
                ClientPreselectionOwner::Available,
            )
        } else {
            ClientPreselectionOwner::Closed
        };
        let runtime = Self {
            service,
            store,
            replay,
            forwarded_ad_replays: HashMap::new(),
            forwarded_replay_capacity: replay_capacity,
            identity,
            local_public_key,
            local_node_id,
            config: config.clone(),
            roles,
            helper,
            mpquic_socket,
            relay_service,
            exit_service,
            metrics,
            role_commands,
            client_preselection,
            provider_queries: HashMap::new(),
            relay_provider_peers: HashMap::new(),
            reserved_provider_exit_peers: HashMap::new(),
            relay_advertisement_requests: HashMap::new(),
            exit_provider_peers: HashMap::new(),
            automatic_exit_fetches: HashMap::new(),
            automatic_exit_fetch_attempts: Vec::new(),
            preferred_exit_controls: HashMap::new(),
            direct_relays: HashMap::new(),
            exit_data_relays: HashMap::new(),
            exit_control_relays: HashMap::new(),
            local_relay_snapshot: None,
            forwarded_exits: HashMap::new(),
            forwarded_exit_targets: HashMap::new(),
            privacy_conflicts: HashMap::new(),
            forwarded_exit_fail_closed_until_ms: 0,
            accepted_advertisements: HashMap::new(),
            pending_client_forwards: HashMap::new(),
            client_forward_index: HashMap::new(),
            completed_client_forwards: HashMap::new(),
            retry_client_forwards: HashMap::new(),
            pending_relay_forwards: HashMap::new(),
            relay_forward_index: HashMap::new(),
            completed_relay_forwards: HashMap::new(),
            retry_relay_forwards: HashMap::new(),
            prepared_native_ready: HashMap::new(),
            prepared_native_authorizations: HashMap::new(),
            prepared_native_authorization_helpers: HashMap::new(),
            active_native_relay_helpers: HashMap::new(),
            recent_native_relay_evidence: Vec::new(),
            recent_native_exit_evidence: Vec::new(),
            prepared_production_relay_routes: HashMap::new(),
            prepared_production_exit_routes: HashMap::new(),
            pending_mptcp_exit_sessions: HashMap::new(),
            pending_mpquic_exit_sessions: HashMap::new(),
            active_production_mptcp_exit_routes: HashMap::new(),
            mptcp_exit_runtime_events,
            mptcp_exit_runtime_completions,
            exit_native_ready_attempts: HashMap::new(),
            pending_exit_native_ready: HashMap::new(),
            pending_datapath: HashMap::new(),
            datapath_index: HashMap::new(),
            completed_datapath: HashMap::new(),
            retry_datapath: HashMap::new(),
            candidate_limit: config.network.candidate_pool_size.min(PEERSTORE_LOAD_BOUND),
            observed_endpoints: HashMap::new(),
            local_endpoint_observations: HashMap::new(),
            publisher: AdvertisementPublisher::new(
                sequence_path,
                config.network.advertisement_ttl_seconds,
            ),
            served_local_advertisement: None,
            control_addresses: BTreeSet::new(),
            active_provider_keys: BTreeSet::new(),
            #[cfg(test)]
            advertisement_commit_test_barriers: AdvertisementCommitTestBarriers::default(),
            #[cfg(test)]
            route_snapshot_store_failure: false,
            #[cfg(test)]
            route_snapshot_build_attempts: Cell::new(0),
        };
        let control = DiscoveryControlHandle::from_sender(role_sender);
        Ok((runtime, control))
    }

    /// Runs provider queries, advertisement verification, and bounded
    /// peerstore maintenance until shutdown.
    #[allow(
        clippy::too_many_lines,
        reason = "one actor loop owns publication, capability convergence, reservations and commands"
    )]
    pub async fn run(
        mut self,
        state: Arc<RwLock<AgentState>>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        self.synchronize_exit_policy(&state).await;
        self.publish_local(&state).await;
        self.query_capabilities(&state).await;
        self.refresh_candidates(&state).await;
        let mut maintenance = tokio::time::interval(self.publisher.refresh_interval());
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut capability_maintenance = tokio::time::interval(CAPABILITY_QUERY_INTERVAL);
        capability_maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut reservation_maintenance = tokio::time::interval(RESERVATION_MAINTENANCE_INTERVAL);
        reservation_maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            self.maintain_client_preselection();
            let responder_policy = {
                let now_ms = unix_millis();
                let policy = state.read().await.policy_snapshot(now_ms);
                preselection_responder_policy(self.roles, &policy, now_ms)
            };
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = maintenance.tick() => {
                    self.synchronize_exit_policy(&state).await;
                    let now_ms = unix_millis();
                    self.destroy_expired_exit_native_attempts(now_ms).await;
                    self.destroy_expired_production_relay_routes(now_ms).await;
                    self.expire_pending_mptcp_exit_sessions(now_ms).await;
                    self.expire_pending_mpquic_exit_sessions(now_ms).await;
                    self.destroy_expired_production_exit_routes(now_ms).await;
                    self.destroy_expired_active_mptcp_exit_routes(now_ms).await;
                    let relay_purged = self
                        .relay_service
                        .as_mut()
                        .map_or(0, |service| service.purge_expired(now_ms));
                    let exit_purged = self
                        .exit_service
                        .as_mut()
                        .map_or(0, |service| service.purge_expired(now_ms));
                    self.publish_local(&state).await;
                    Self::log_expiry_reclaim(&state, relay_purged, exit_purged).await;
                    self.query_capabilities(&state).await;
                    self.schedule_exit_advertisement_fetches();
                    let now = UnixTime::from_secs(unix_seconds());
                    if self.store.prune_expired(now, PEER_RETENTION_SECONDS).is_err() {
                        state.write().await.log(LogLevel::Warn, "PEERSTORE_PRUNE_FAILED", unix_millis());
                    }
                    self.refresh_candidates(&state).await;
                }
                _ = reservation_maintenance.tick() => {
                    self.synchronize_exit_policy(&state).await;
                    let now_ms = unix_millis();
                    self.destroy_expired_exit_native_attempts(now_ms).await;
                    self.destroy_expired_production_relay_routes(now_ms).await;
                    self.expire_pending_mptcp_exit_sessions(now_ms).await;
                    self.expire_pending_mpquic_exit_sessions(now_ms).await;
                    self.destroy_expired_production_exit_routes(now_ms).await;
                    self.destroy_expired_active_mptcp_exit_routes(now_ms).await;
                    let relay_purged = self
                        .relay_service
                        .as_mut()
                        .map_or(0, |service| service.purge_expired(now_ms));
                    let exit_purged = self
                        .exit_service
                        .as_mut()
                        .map_or(0, |service| service.purge_expired(now_ms));
                    if relay_purged > 0 || exit_purged > 0 {
                        self.publish_local(&state).await;
                        Self::log_expiry_reclaim(
                            &state,
                            relay_purged,
                            exit_purged,
                        ).await;
                    }
                    let reaped = Box::pin(self.reap_outbound_reservations(Instant::now())).await;
                    if reaped.ambiguous > 0 {
                        log_reservation_event(&state, "RESERVATION_RPC_TIMEOUT").await;
                    }
                    if reaped.canceled > 0 {
                        log_reservation_event(
                            &state,
                            "RESERVATION_RPC_CALLER_CLOSED",
                        ).await;
                    }
                    // The automatic fetch owner uses a one-second retry backoff. Drive it on the
                    // matching bounded maintenance clock instead of stretching every retry to the
                    // five-second provider-query cadence.
                    self.schedule_exit_advertisement_fetches();
                }
                _ = capability_maintenance.tick() => {
                    self.query_capabilities(&state).await;
                    self.schedule_exit_advertisement_fetches();
                }
                event = next_actor_discovery_event(
                    &mut self.service,
                    &self.identity,
                    self.local_public_key,
                    responder_policy,
                ) => {
                    Box::pin(self.handle_sanitized_event(event, &state)).await;
                }
                command = self.role_commands.recv() => {
                    let Some(command) = command else {
                        state.write().await.log(LogLevel::Error, "ROLE_ACTOR_CHANNEL_CLOSED", unix_millis());
                        break;
                    };
                    self.handle_command(command, &state).await;
                }
                completion = self.mptcp_exit_runtime_completions.recv() => {
                    if let Some(completion) = completion {
                        match completion {
                            MptcpExitRuntimeEvent::FlowCompleted {
                                route_context_id,
                                reservation_id,
                                succeeded,
                            } => self.finish_mptcp_exit_flow(
                                route_context_id,
                                reservation_id,
                                succeeded,
                                &state,
                            ).await,
                            MptcpExitRuntimeEvent::RuntimeCompleted(completion) => {
                                self.finish_mptcp_exit_runtime(completion, &state).await;
                            }
                        }
                    }
                }
            }
        }
        self.destroy_expired_exit_native_attempts(u64::MAX).await;
        Box::pin(self.fail_all_pending_route_sessions()).await;
        self.destroy_expired_production_relay_routes(u64::MAX).await;
        self.expire_pending_mptcp_exit_sessions(u64::MAX).await;
        self.expire_pending_mpquic_exit_sessions(u64::MAX).await;
        self.destroy_expired_production_exit_routes(u64::MAX).await;
        self.destroy_expired_active_mptcp_exit_routes(u64::MAX)
            .await;
        self.cancel_client_preselection(ClientPreselectionError::Closed);
        self.fail_all_outbound_reservations(OutboundReservationError::Shutdown);
        self.reject_queued_outbound_commands();
        self.withdraw_local();
        clear_relay_metric(&self.metrics);
        clear_exit_metric(&self.metrics);
    }

    async fn handle_sanitized_event(
        &mut self,
        event: DiscoveryEvent,
        state: &Arc<RwLock<AgentState>>,
    ) {
        match event {
            DiscoveryEvent::Other(event) => Box::pin(self.handle_event(event, state)).await,
            DiscoveryEvent::ClientPreselectionResponse(arrival) => {
                if let Some(code) = self.handle_client_preselection_response(arrival) {
                    state.write().await.log(LogLevel::Warn, code, unix_millis());
                }
            }
            DiscoveryEvent::UpstreamPreselectionResponse(_) => {
                state.write().await.log(
                    LogLevel::Error,
                    "PRESELECTION_RESPONSE_WITHOUT_OWNER",
                    unix_millis(),
                );
            }
            DiscoveryEvent::PreselectionResponderRejected(reject) => {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, reject.event_code(), unix_millis());
            }
            _ => {
                state.write().await.log(
                    LogLevel::Error,
                    "UNSUPPORTED_SANITIZED_DISCOVERY_EVENT",
                    unix_millis(),
                );
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed actor command set stays in one exhaustive dispatcher"
    )]
    async fn handle_command(&mut self, command: DiscoveryCommand, state: &Arc<RwLock<AgentState>>) {
        self.maintain_client_preselection();
        match command {
            DiscoveryCommand::SetRoles {
                expected,
                candidate,
                reply,
            } => {
                let result = self.apply_roles(expected, candidate, state).await;
                let _ = reply.send(result);
            }
            DiscoveryCommand::ApplyPolicy { policy, reply } => {
                // Policy replacement/revocation invalidates every retained Relay authority input.
                // Cancel both affine owners before publishing the new actor state.
                self.cancel_client_preselection(ClientPreselectionError::Invalidated);
                self.service.cancel_preselection_forwarding();
                state.write().await.set_policy(policy);
                self.synchronize_exit_policy(state).await;
                self.publish_local(state).await;
                #[cfg(test)]
                self.wait_at_policy_apply_pre_reply_barrier(state).await;
                let _ = reply.send(());
            }
            DiscoveryCommand::RouteCandidateSnapshot {
                requested_candidates,
                reply,
            } => {
                self.reply_route_candidate_snapshot(requested_candidates, reply, state)
                    .await;
            }
            DiscoveryCommand::BeginClientPreselection { parameters, reply } => {
                self.begin_client_preselection(parameters, reply, state)
                    .await;
            }
            DiscoveryCommand::ResolveEndpointTraversalHints { bindings, reply } => {
                let _ = reply.send(self.exact_endpoint_traversal_hints(bindings));
            }
            DiscoveryCommand::ResolveDirectRelay {
                expected_node_id,
                expected_peer_id,
                reply,
            } => {
                self.purge_completed(Instant::now());
                let now_ms = unix_millis();
                let capability = self
                    .direct_relays
                    .get(&expected_peer_id)
                    .filter(|capability| {
                        capability.node_id == expected_node_id
                            && capability.peer_id == expected_peer_id
                            && capability.expires_at_ms > now_ms
                    })
                    .cloned();
                let _ = reply.send(capability);
            }
            DiscoveryCommand::ResolveForwardedExit {
                control_relay_node_id,
                control_relay_peer_id,
                exit_node_id,
                exit_peer_id,
                reply,
            } => {
                self.purge_completed(Instant::now());
                let now_ms = unix_millis();
                let control = if control_relay_peer_id == *self.service.local_peer_id() {
                    self.local_relay_snapshot.as_ref()
                } else {
                    self.direct_relays.get(&control_relay_peer_id)
                };
                let capability = self
                    .forwarded_exits
                    .get(&ForwardedExitKey {
                        control_relay_peer: control_relay_peer_id,
                        exit_peer: exit_peer_id,
                    })
                    .filter(|capability| {
                        control.is_some_and(|control| {
                            forwarded_exit_capability_matches(
                                capability,
                                control,
                                control_relay_node_id,
                                control_relay_peer_id,
                                capability.control_relay_public_key,
                                exit_node_id,
                                exit_peer_id,
                                now_ms.saturating_add(1),
                            )
                        })
                    })
                    .cloned();
                let _ = reply.send(capability);
            }
            DiscoveryCommand::RequestExitForward {
                control_relay_peer,
                request,
                reply,
            } => self.begin_client_forward(control_relay_peer, request, reply),
            DiscoveryCommand::RequestDatapathRelay {
                relay_peer,
                request,
                reply,
            } => self.begin_datapath(relay_peer, request, reply),
        }
    }

    async fn reply_route_candidate_snapshot(
        &mut self,
        requested_candidates: usize,
        reply: oneshot::Sender<Result<RouteCandidateSnapshot, RouteCandidateSnapshotError>>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        if reply.is_closed() {
            return;
        }
        let captured_at_ms = unix_millis();
        self.purge_completed_at(captured_at_ms);
        let policy = state.read().await.policy_snapshot(captured_at_ms);
        let snapshot =
            self.build_route_candidate_snapshot(requested_candidates, captured_at_ms, &policy);
        let _ = reply.send(snapshot);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one auditable affine admission path retains every failure authority"
    )]
    async fn begin_client_preselection(
        &mut self,
        parameters: ClientPreselectionParameters,
        reply: oneshot::Sender<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        if reply.is_closed() {
            return;
        }
        match &self.client_preselection {
            ClientPreselectionOwner::Available(_) => {}
            ClientPreselectionOwner::Active(_) | ClientPreselectionOwner::Cooling(_) => {
                state
                    .write()
                    .await
                    .log(LogLevel::Debug, "PRESELECTION_OWNER_BUSY", unix_millis());
                let _ = reply.send(Err(ClientPreselectionError::Busy));
                return;
            }
            ClientPreselectionOwner::Closed | ClientPreselectionOwner::Lost => {
                let _ = reply.send(Err(ClientPreselectionError::Closed));
                return;
            }
        }

        if !client_preselection_parameters_are_valid(&parameters) {
            let _ = reply.send(Err(ClientPreselectionError::InvalidParameters));
            return;
        }

        let ClientPreselectionParameters {
            transport,
            address_family,
            minimum_capacity,
            local_profile_capacity,
            conservative_capacity_ceiling,
            minimum_other_relays,
            maximum_other_relays,
            requested_candidate_bound,
        } = parameters;

        let captured_at_ms = unix_millis();
        self.purge_completed_at(captured_at_ms);
        let policy = state.read().await.policy_snapshot(captured_at_ms);
        if reply.is_closed() {
            return;
        }
        let snapshot = match self.build_route_candidate_snapshot(
            requested_candidate_bound,
            captured_at_ms,
            &policy,
        ) {
            Ok(snapshot) => snapshot,
            Err(RouteCandidateSnapshotError::InvalidLimit) => {
                state.write().await.log(
                    LogLevel::Debug,
                    "PRESELECTION_SNAPSHOT_INVALID_LIMIT",
                    captured_at_ms,
                );
                let _ = reply.send(Err(ClientPreselectionError::InvalidParameters));
                return;
            }
            Err(
                RouteCandidateSnapshotError::Busy
                | RouteCandidateSnapshotError::Closed
                | RouteCandidateSnapshotError::Timeout
                | RouteCandidateSnapshotError::PolicyUnavailable
                | RouteCandidateSnapshotError::StoreUnavailable,
            ) => {
                state.write().await.log(
                    LogLevel::Debug,
                    "PRESELECTION_SNAPSHOT_UNAVAILABLE",
                    captured_at_ms,
                );
                let _ = reply.send(Err(ClientPreselectionError::Unavailable));
                return;
            }
        };
        let scope = PreselectionSamplingScope::new(
            transport,
            address_family,
            minimum_capacity,
            minimum_other_relays,
            maximum_other_relays,
        );
        let snapshot = match narrow_route_candidate_snapshot(snapshot, scope) {
            Ok(snapshot) => snapshot,
            Err(failure) => {
                let diagnostic = match failure.error {
                    PreselectionSamplingError::InvalidPolicy => {
                        "PRESELECTION_SAMPLE_INVALID_POLICY"
                    }
                    PreselectionSamplingError::InvalidSnapshot => {
                        "PRESELECTION_SAMPLE_INVALID_SNAPSHOT"
                    }
                    PreselectionSamplingError::NoEligibleForwardedExit => {
                        "PRESELECTION_SAMPLE_NO_EXIT"
                    }
                    PreselectionSamplingError::InsufficientDiverseRelays => {
                        "PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS"
                    }
                    PreselectionSamplingError::Entropy => "PRESELECTION_SAMPLE_ENTROPY",
                };
                state
                    .write()
                    .await
                    .log(LogLevel::Debug, diagnostic, captured_at_ms);
                let error = if failure.error == PreselectionSamplingError::InvalidPolicy {
                    ClientPreselectionError::InvalidParameters
                } else {
                    ClientPreselectionError::Unavailable
                };
                let _ = reply.send(Err(error));
                return;
            }
        };
        if reply.is_closed() {
            return;
        }
        let Some(attempt_deadline) = Instant::now().checked_add(CLIENT_PRESELECTION_TIMEOUT) else {
            let _ = reply.send(Err(ClientPreselectionError::Closed));
            return;
        };
        let Some(request_deadline) = Instant::now()
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .map(|deadline| deadline.min(attempt_deadline))
        else {
            let _ = reply.send(Err(ClientPreselectionError::Closed));
            return;
        };

        let owner = std::mem::replace(&mut self.client_preselection, ClientPreselectionOwner::Lost);
        let ClientPreselectionOwner::Available(gate) = owner else {
            self.client_preselection = owner;
            let _ = reply.send(Err(ClientPreselectionError::Busy));
            return;
        };
        let pending = match gate.begin(
            snapshot,
            transport,
            address_family,
            minimum_capacity,
            local_profile_capacity,
            conservative_capacity_ceiling,
        ) {
            Ok(pending) => pending,
            Err(failure) => {
                self.install_client_preselection_gate_recovery(consume_preselection_begin_failure(
                    failure,
                ));
                state.write().await.log(
                    LogLevel::Debug,
                    "PRESELECTION_GATE_BEGIN_FAILED",
                    unix_millis(),
                );
                let _ = reply.send(Err(ClientPreselectionError::Unavailable));
                return;
            }
        };
        if reply.is_closed() {
            match pending.cancel() {
                Ok(gate) => self.client_preselection = ClientPreselectionOwner::Cooling(gate),
                Err(failure) => self.install_local_client_preselection_failure(
                    consume_local_preselection_attempt_failure(failure),
                    reply,
                    ClientPreselectionError::Closed,
                ),
            }
            return;
        }
        match pending.dispatch(&mut self.service) {
            Ok(dispatch) => {
                let active = ActiveClientPreselection {
                    dispatch,
                    transports: Vec::with_capacity(maximum_other_relays.saturating_add(1)),
                    reply,
                    request_deadline,
                    attempt_deadline,
                    terminal_error: None,
                };
                if active.reply.is_closed()
                    || Instant::now() >= active.request_deadline
                    || Instant::now() >= active.attempt_deadline
                {
                    let error = if active.reply.is_closed() {
                        ClientPreselectionError::Closed
                    } else {
                        ClientPreselectionError::Timeout
                    };
                    self.cancel_active_client_preselection(active, error);
                } else {
                    self.client_preselection = ClientPreselectionOwner::Active(active);
                }
            }
            Err(failure) => {
                state.write().await.log(
                    LogLevel::Debug,
                    "PRESELECTION_INITIAL_DISPATCH_FAILED",
                    unix_millis(),
                );
                self.install_client_preselection_transition_failure(
                    failure,
                    Vec::new(),
                    reply,
                    request_deadline,
                    attempt_deadline,
                    ClientPreselectionError::Transport,
                    Some(ClientPreselectionError::Transport),
                );
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one auditable affine response path binds, joins and cools exact ownership"
    )]
    fn handle_client_preselection_response(
        &mut self,
        arrival: ClientPreselectionResponseArrival,
    ) -> Option<&'static str> {
        let owner = std::mem::replace(&mut self.client_preselection, ClientPreselectionOwner::Lost);
        let ClientPreselectionOwner::Active(active) = owner else {
            self.client_preselection = owner;
            return Some("PRESELECTION_RESPONSE_WITHOUT_OWNER");
        };
        if let Some(error) = active.terminal_error {
            self.cancel_active_client_preselection(active, error);
            return Some("PRESELECTION_RESPONSE_AFTER_TERMINAL");
        }
        if active.reply.is_closed()
            || Instant::now() >= active.request_deadline
            || Instant::now() >= active.attempt_deadline
        {
            let error = if active.reply.is_closed() {
                ClientPreselectionError::Closed
            } else {
                ClientPreselectionError::Timeout
            };
            self.cancel_active_client_preselection(active, error);
            return Some("PRESELECTION_RESPONSE_AFTER_TERMINAL");
        }

        let ActiveClientPreselection {
            dispatch,
            mut transports,
            reply,
            request_deadline,
            attempt_deadline,
            terminal_error: _,
        } = active;
        let transition_started_at = Instant::now();
        let (outcome, transport) = match dispatch.bind_response(&mut self.service, arrival) {
            Ok(bound) => bound,
            Err(failure) => {
                self.install_client_preselection_transition_failure(
                    failure,
                    transports,
                    reply,
                    request_deadline,
                    attempt_deadline,
                    ClientPreselectionError::Transport,
                    None,
                );
                return Some("PRESELECTION_RESPONSE_REJECTED");
            }
        };
        transports.push(transport);
        match outcome {
            PreselectionResponseOutcome::Pending(pending) => {
                if reply.is_closed() || Instant::now() >= attempt_deadline {
                    let error = if reply.is_closed() {
                        ClientPreselectionError::Closed
                    } else {
                        ClientPreselectionError::Timeout
                    };
                    match pending.cancel() {
                        Ok(gate) => {
                            self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                            let _ = reply.send(Err(error));
                        }
                        Err(failure) => self.install_local_client_preselection_failure(
                            consume_local_preselection_attempt_failure(failure),
                            reply,
                            error,
                        ),
                    }
                    return Some("PRESELECTION_ATTEMPT_TERMINATED");
                }
                let Some(request_deadline) = transition_started_at
                    .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
                    .map(|deadline| deadline.min(attempt_deadline))
                else {
                    match pending.cancel() {
                        Ok(gate) => {
                            self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                            let _ = reply.send(Err(ClientPreselectionError::Closed));
                        }
                        Err(failure) => self.install_local_client_preselection_failure(
                            consume_local_preselection_attempt_failure(failure),
                            reply,
                            ClientPreselectionError::Closed,
                        ),
                    }
                    return Some("PRESELECTION_CLOCK_UNAVAILABLE");
                };
                match pending.dispatch(&mut self.service) {
                    Ok(dispatch) => {
                        let active = ActiveClientPreselection {
                            dispatch,
                            transports,
                            reply,
                            request_deadline,
                            attempt_deadline,
                            terminal_error: None,
                        };
                        if active.reply.is_closed()
                            || Instant::now() >= active.request_deadline
                            || Instant::now() >= active.attempt_deadline
                        {
                            let error = if active.reply.is_closed() {
                                ClientPreselectionError::Closed
                            } else {
                                ClientPreselectionError::Timeout
                            };
                            self.cancel_active_client_preselection(active, error);
                        } else {
                            self.client_preselection = ClientPreselectionOwner::Active(active);
                        }
                        None
                    }
                    Err(failure) => {
                        self.install_client_preselection_transition_failure(
                            failure,
                            transports,
                            reply,
                            request_deadline,
                            attempt_deadline,
                            ClientPreselectionError::Transport,
                            Some(ClientPreselectionError::Transport),
                        );
                        Some("PRESELECTION_REDISPATCH_FAILED")
                    }
                }
            }
            PreselectionResponseOutcome::Ready(ready) => {
                if reply.is_closed() || Instant::now() >= attempt_deadline {
                    let error = if reply.is_closed() {
                        ClientPreselectionError::Closed
                    } else {
                        ClientPreselectionError::Timeout
                    };
                    match ready.cancel() {
                        Ok(gate) => {
                            self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                            let _ = reply.send(Err(error));
                        }
                        Err(failure) => self.install_local_client_preselection_failure(
                            consume_local_preselection_attempt_failure(failure),
                            reply,
                            error,
                        ),
                    }
                    return Some("PRESELECTION_ATTEMPT_TERMINATED");
                }
                let completed = match ready.finish() {
                    Ok(completed) => completed,
                    Err(failure) => {
                        self.install_local_client_preselection_failure(
                            consume_local_preselection_attempt_failure(failure),
                            reply,
                            ClientPreselectionError::Transport,
                        );
                        return Some("PRESELECTION_FINISH_FAILED");
                    }
                };
                let fresh = match completed.join_transport_proofs(transports) {
                    Ok(fresh) => fresh,
                    Err(failure) => {
                        let _ = failure.error();
                        self.client_preselection =
                            ClientPreselectionOwner::Cooling(failure.into_gate());
                        let _ = reply.send(Err(ClientPreselectionError::Transport));
                        return Some("PRESELECTION_EXACT_SET_JOIN_FAILED");
                    }
                };
                match prepare_preselection_evidence(fresh) {
                    Ok((prepared, gate)) => {
                        self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                        let _ = reply.send(Ok(prepared));
                        None
                    }
                    Err(gate) => {
                        self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                        let _ = reply.send(Err(ClientPreselectionError::Unavailable));
                        Some("PRESELECTION_FRESH_EVIDENCE_REJECTED")
                    }
                }
            }
        }
    }

    fn handle_client_preselection_outbound_failure(
        &mut self,
        peer: Libp2pPeerId,
        request_id: request_response::OutboundRequestId,
    ) -> bool {
        let owner = std::mem::replace(&mut self.client_preselection, ClientPreselectionOwner::Lost);
        let ClientPreselectionOwner::Active(active) = owner else {
            self.client_preselection = owner;
            return false;
        };
        let ActiveClientPreselection {
            dispatch,
            transports,
            reply,
            request_deadline,
            attempt_deadline,
            terminal_error,
        } = active;
        match dispatch.consume_outbound_failure(&mut self.service, peer, request_id) {
            Ok(gate) | Err(PreselectionOwnerTransitionFailure::Cooling(gate)) => {
                self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                let _ = reply.send(Err(ClientPreselectionError::Transport));
                true
            }
            Err(PreselectionOwnerTransitionFailure::Retained(dispatch)) => {
                self.client_preselection =
                    ClientPreselectionOwner::Active(ActiveClientPreselection {
                        dispatch: *dispatch,
                        transports,
                        reply,
                        request_deadline,
                        attempt_deadline,
                        terminal_error,
                    });
                false
            }
            Err(PreselectionOwnerTransitionFailure::Closed) => {
                self.client_preselection = ClientPreselectionOwner::Closed;
                let _ = reply.send(Err(ClientPreselectionError::Transport));
                true
            }
        }
    }

    fn maintain_client_preselection(&mut self) {
        let owner = std::mem::replace(&mut self.client_preselection, ClientPreselectionOwner::Lost);
        match owner {
            ClientPreselectionOwner::Cooling(gate) => match gate.resume() {
                Ok(gate) => self.client_preselection = ClientPreselectionOwner::Available(gate),
                Err(gate) => self.client_preselection = ClientPreselectionOwner::Cooling(gate),
            },
            ClientPreselectionOwner::Active(active) if active.terminal_error.is_some() => {
                let error = active
                    .terminal_error
                    .unwrap_or(ClientPreselectionError::Closed);
                self.cancel_active_client_preselection(active, error);
            }
            ClientPreselectionOwner::Active(active) if active.reply.is_closed() => {
                self.cancel_active_client_preselection(active, ClientPreselectionError::Closed);
            }
            ClientPreselectionOwner::Active(active)
                if Instant::now() >= active.request_deadline
                    || Instant::now() >= active.attempt_deadline =>
            {
                self.cancel_active_client_preselection(active, ClientPreselectionError::Timeout);
            }
            ClientPreselectionOwner::Lost => {
                self.client_preselection = ClientPreselectionOwner::Closed;
            }
            owner => self.client_preselection = owner,
        }
    }

    fn cancel_client_preselection(&mut self, error: ClientPreselectionError) {
        let owner = std::mem::replace(&mut self.client_preselection, ClientPreselectionOwner::Lost);
        match owner {
            ClientPreselectionOwner::Active(active) => {
                self.cancel_active_client_preselection(active, error);
            }
            ClientPreselectionOwner::Lost => {
                self.client_preselection = ClientPreselectionOwner::Closed;
            }
            owner => self.client_preselection = owner,
        }
    }

    fn cancel_active_client_preselection(
        &mut self,
        active: ActiveClientPreselection,
        error: ClientPreselectionError,
    ) {
        let ActiveClientPreselection {
            dispatch,
            transports,
            reply,
            request_deadline,
            attempt_deadline,
            terminal_error: _,
        } = active;
        match dispatch.cancel(&mut self.service) {
            Ok(gate) => {
                self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                let _ = reply.send(Err(error));
            }
            Err(failure) => self.install_client_preselection_transition_failure(
                failure,
                transports,
                reply,
                request_deadline,
                attempt_deadline,
                error,
                Some(error),
            ),
        }
    }

    fn install_client_preselection_gate_recovery(&mut self, recovery: PreselectionGateRecovery) {
        self.client_preselection = match recovery {
            PreselectionGateRecovery::Available(gate) => ClientPreselectionOwner::Available(*gate),
            PreselectionGateRecovery::Cooling(gate) => ClientPreselectionOwner::Cooling(*gate),
            PreselectionGateRecovery::Closed => ClientPreselectionOwner::Closed,
        };
    }

    fn install_local_client_preselection_failure(
        &mut self,
        failure: PreselectionLocalRecovery,
        reply: oneshot::Sender<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
        error: ClientPreselectionError,
    ) {
        self.client_preselection = match failure {
            PreselectionLocalRecovery::Cooling(gate) => ClientPreselectionOwner::Cooling(gate),
            PreselectionLocalRecovery::Closed => ClientPreselectionOwner::Closed,
        };
        let _ = reply.send(Err(error));
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the exact retained dispatch state is restored without a getter or clone"
    )]
    fn install_client_preselection_transition_failure(
        &mut self,
        failure: PreselectionOwnerTransitionFailure,
        transports: Vec<BoundClientPreselectionTransport>,
        reply: oneshot::Sender<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
        request_deadline: Instant,
        attempt_deadline: Instant,
        error: ClientPreselectionError,
        retained_terminal_error: Option<ClientPreselectionError>,
    ) {
        match failure {
            PreselectionOwnerTransitionFailure::Retained(dispatch) => {
                self.client_preselection =
                    ClientPreselectionOwner::Active(ActiveClientPreselection {
                        dispatch: *dispatch,
                        transports,
                        reply,
                        request_deadline,
                        attempt_deadline,
                        terminal_error: retained_terminal_error,
                    });
            }
            PreselectionOwnerTransitionFailure::Cooling(gate) => {
                self.client_preselection = ClientPreselectionOwner::Cooling(gate);
                let _ = reply.send(Err(error));
            }
            PreselectionOwnerTransitionFailure::Closed => {
                self.client_preselection = ClientPreselectionOwner::Closed;
                let _ = reply.send(Err(error));
            }
        }
    }

    #[allow(clippy::too_many_lines, reason = "single-owner admission transaction")]
    fn begin_client_forward(
        &mut self,
        control_relay_peer: Libp2pPeerId,
        request: ExitForwardRequest,
        reply: oneshot::Sender<Result<ExitForwardResponse, OutboundReservationError>>,
    ) {
        if reply.is_closed() {
            return;
        }
        self.purge_completed(Instant::now());
        let Some(forward_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.forward_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Ok(wrapper_relay) = Libp2pPeerId::from_bytes(request.control_relay_peer_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Some(control_relay_node_id) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Some(control_relay_public_key) = fixed_bytes::<32>(request.control_relay_public_key())
        else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(request.exit_peer_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Ok(operation) = request.validated_operation() else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let expected_exit_node_id = optional_fixed_bytes::<32>(request.exit_node_id());
        let operation_expires_at_ms = request.deadline_unix_ms();
        let now_ms = unix_millis();
        let direct_control = self.direct_relays.get(&control_relay_peer).cloned();
        let direct_control_is_fresh = direct_control.as_ref().is_some_and(|capability| {
            direct_relay_capability_matches(
                capability,
                control_relay_node_id,
                control_relay_peer,
                control_relay_public_key,
                operation_expires_at_ms,
            )
        });
        let authorized_exit = expected_exit_node_id.and_then(|exit_node_id| {
            self.forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer,
                    exit_peer,
                })
                .filter(|capability| {
                    direct_control.as_ref().is_some_and(|control| {
                        forwarded_exit_capability_matches(
                            capability,
                            control,
                            control_relay_node_id,
                            control_relay_peer,
                            control_relay_public_key,
                            exit_node_id,
                            exit_peer,
                            operation_expires_at_ms,
                        )
                    })
                })
                .cloned()
        });
        if request.validate().is_err()
            || !forward_request_scope_matches(&request, operation, now_ms)
            || wrapper_relay != control_relay_peer
            || control_relay_peer == exit_peer
            || !direct_control_is_fresh
            || !self.exit_provider_peers.contains_key(&exit_peer)
            || !self.forwarded_exit_peer_is_eligible(exit_peer, now_ms)
            || (operation != ExitForwardOperation::FetchExitAdvertisement
                && authorized_exit.is_none())
        {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        }
        let Ok(canonical_request) = encode_canonical(
            &request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let key = ClientForwardKey {
            control_relay_peer,
            forward_id,
        };
        if let Some(completed) = self.completed_client_forwards.get(&key) {
            let outcome = if completed.canonical_request == canonical_request
                && completed.operation == operation
            {
                completed.outcome.clone()
            } else {
                Err(OutboundReservationError::InvalidRequest)
            };
            let _ = reply.send(outcome);
            return;
        }
        if let Some(request_id) = self.client_forward_index.get(&key).copied() {
            let Some(pending) = self.pending_client_forwards.get_mut(&request_id) else {
                self.client_forward_index.remove(&key);
                let _ = reply.send(Err(OutboundReservationError::SendFailed));
                return;
            };
            if pending.canonical_request != canonical_request {
                let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            } else if pending.waiters.len() >= MAX_COALESCED_WAITERS {
                let _ = reply.send(Err(OutboundReservationError::Capacity));
            } else {
                pending.waiters.push(reply);
            }
            return;
        }
        let retry = self.retry_client_forwards.get(&key);
        if retry.is_some_and(|entry| {
            entry.canonical_request != canonical_request || entry.target_peer != exit_peer
        }) {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        }
        let dispatch_attempts = retry.map_or(1, |entry| entry.dispatch_attempts.saturating_add(1));
        if dispatch_attempts > MAX_DISPATCH_ATTEMPTS {
            let _ = reply.send(Err(OutboundReservationError::RetryExhausted));
            return;
        }
        let Some(reserved_bytes) = retry
            .map(|entry| entry.reserved_bytes)
            .or_else(|| ledger_reservation_bytes(canonical_request.len()))
        else {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        };
        if retry.is_none() && !self.ledger_can_reserve(control_relay_peer, reserved_bytes) {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        }
        if self.pending_client_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self
                .pending_client_forwards
                .values()
                .filter(|pending| pending.key.control_relay_peer == control_relay_peer)
                .count()
                >= MAX_PENDING_PER_PEER
            || !self.mark_forwarded_exit_target(exit_peer, operation_expires_at_ms)
        {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        }
        let attempt_deadline = rpc_deadline(operation_expires_at_ms, EXIT_FORWARD_REQUEST_TIMEOUT);
        let Ok(request_id) = self
            .service
            .request_exit_forward(&control_relay_peer, request)
        else {
            let _ = reply.send(Err(OutboundReservationError::SendFailed));
            return;
        };
        self.retry_client_forwards.remove(&key);
        self.client_forward_index.insert(key, request_id);
        self.pending_client_forwards.insert(
            request_id,
            PendingClientForward {
                key,
                expected_exit_peer: exit_peer,
                operation,
                expected_exit_node_id,
                authorized_control: direct_control.expect("validated control capability"),
                authorized_exit,
                canonical_request,
                operation_expires_at_ms,
                attempt_deadline,
                dispatch_attempts,
                reserved_bytes,
                waiters: vec![reply],
            },
        );
    }

    #[allow(clippy::too_many_lines, reason = "single-owner admission transaction")]
    fn begin_datapath(
        &mut self,
        relay_peer: Libp2pPeerId,
        request: DatapathRelayRequest,
        reply: oneshot::Sender<Result<DatapathRelayResponse, OutboundReservationError>>,
    ) {
        if reply.is_closed() {
            return;
        }
        self.purge_completed(Instant::now());
        let Some(request_id_bytes) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Some(relay_node_id) = fixed_bytes::<32>(request.relay_node_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Ok(wrapper_peer) = Libp2pPeerId::from_bytes(request.relay_peer_id()) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let Ok(operation) = request.validated_operation() else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let operation_expires_at_ms = request.deadline_unix_ms();
        let now_ms = unix_millis();
        let authorized_relay = self.direct_relays.get(&relay_peer).cloned();
        if request.validate().is_err()
            || !datapath_request_scope_matches(&request, operation, now_ms)
            || wrapper_peer != relay_peer
            || !authorized_relay.as_ref().is_some_and(|capability| {
                direct_relay_target_matches(
                    capability,
                    relay_node_id,
                    relay_peer,
                    operation_expires_at_ms,
                )
            })
        {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        }
        let Ok(canonical_request) = encode_canonical(
            &request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let key = DatapathKey {
            relay_peer,
            request_id: request_id_bytes,
        };
        if let Some(completed) = self.completed_datapath.get(&key) {
            let outcome = if completed.canonical_request == canonical_request {
                completed.outcome.clone()
            } else {
                Err(OutboundReservationError::InvalidRequest)
            };
            let _ = reply.send(outcome);
            return;
        }
        if let Some(outbound_id) = self.datapath_index.get(&key).copied() {
            let Some(pending) = self.pending_datapath.get_mut(&outbound_id) else {
                self.datapath_index.remove(&key);
                let _ = reply.send(Err(OutboundReservationError::SendFailed));
                return;
            };
            if pending.canonical_request != canonical_request {
                let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            } else if pending.waiters.len() >= MAX_COALESCED_WAITERS {
                let _ = reply.send(Err(OutboundReservationError::Capacity));
            } else {
                pending.waiters.push(reply);
            }
            return;
        }
        let retry = self.retry_datapath.get(&key);
        if retry.is_some_and(|entry| {
            entry.canonical_request != canonical_request || entry.target_peer != relay_peer
        }) {
            let _ = reply.send(Err(OutboundReservationError::InvalidRequest));
            return;
        }
        let dispatch_attempts = retry.map_or(1, |entry| entry.dispatch_attempts.saturating_add(1));
        if dispatch_attempts > MAX_DISPATCH_ATTEMPTS {
            let _ = reply.send(Err(OutboundReservationError::RetryExhausted));
            return;
        }
        let Some(reserved_bytes) = retry
            .map(|entry| entry.reserved_bytes)
            .or_else(|| ledger_reservation_bytes(canonical_request.len()))
        else {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        };
        if retry.is_none() && !self.ledger_can_reserve(relay_peer, reserved_bytes) {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        }
        if self.pending_datapath.len() >= MAX_CONCURRENT_DATAPATH_RELAY_STREAMS
            || self
                .pending_datapath
                .values()
                .filter(|pending| pending.key.relay_peer == relay_peer)
                .count()
                >= MAX_PENDING_PER_PEER
        {
            let _ = reply.send(Err(OutboundReservationError::Capacity));
            return;
        }
        let attempt_deadline =
            rpc_deadline(operation_expires_at_ms, DATAPATH_RELAY_REQUEST_TIMEOUT);
        let Ok(outbound_id) = self.service.request_datapath_relay(&relay_peer, request) else {
            let _ = reply.send(Err(OutboundReservationError::SendFailed));
            return;
        };
        self.retry_datapath.remove(&key);
        self.datapath_index.insert(key, outbound_id);
        self.pending_datapath.insert(
            outbound_id,
            PendingDatapath {
                key,
                operation,
                relay_node_id,
                authorized_relay: authorized_relay.expect("validated relay capability"),
                canonical_request,
                operation_expires_at_ms,
                attempt_deadline,
                dispatch_attempts,
                reserved_bytes,
                waiters: vec![reply],
            },
        );
    }

    async fn complete_client_forward(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
        response: &ExitForwardResponse,
        state: &Arc<RwLock<AgentState>>,
    ) -> OutboundEventOutcome {
        let Some(pending) = self.pending_client_forwards.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if pending.key.control_relay_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let Some(pending) = self.pending_client_forwards.remove(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        self.client_forward_index.remove(&pending.key);
        let now_ms = unix_millis();
        let valid_before_ingest = pending.attempt_deadline > Instant::now()
            && pending.operation_expires_at_ms > now_ms
            && self.client_authority_is_current(&pending, now_ms)
            && exit_response_matches(
                response,
                pending.key.forward_id,
                pending.operation,
                pending.expected_exit_peer,
                pending.expected_exit_node_id,
            );
        if !valid_before_ingest {
            self.finish_client_definitive_error(pending, OutboundReservationError::InvalidResponse);
            log_reservation_event(state, "EXIT_FORWARD_CLIENT_RESPONSE_INVALID").await;
            return OutboundEventOutcome::InvalidResponse;
        }
        let ingest = self
            .ingest_client_forwarded_advertisement(&pending, response, state)
            .await;
        if !ingest.valid {
            self.finish_client_definitive_error(pending, OutboundReservationError::InvalidResponse);
            if let Some(commit) = ingest.commit.as_ref() {
                self.finish_advertisement_commit(commit, state).await;
            }
            log_reservation_event(state, "EXIT_FORWARD_CLIENT_INGEST_REJECTED").await;
            return OutboundEventOutcome::InvalidResponse;
        }
        self.cache_client_result(&pending, Ok(response.clone()));
        for waiter in pending.waiters {
            let _ = waiter.send(Ok(response.clone()));
        }
        if let Some(commit) = ingest.commit.as_ref() {
            self.finish_advertisement_commit(commit, state).await;
        }
        log_reservation_event(state, "EXIT_FORWARD_CLIENT_COMPLETED").await;
        OutboundEventOutcome::Completed
    }

    fn complete_datapath(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
        response: &DatapathRelayResponse,
    ) -> OutboundEventOutcome {
        let Some(pending) = self.pending_datapath.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if pending.key.relay_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let now_ms = unix_millis();
        let authority_current = pending.attempt_deadline > Instant::now()
            && pending.operation_expires_at_ms > now_ms
            && self.direct_relays.get(&peer).is_some_and(|current| {
                direct_relay_authority_lineage_matches(
                    current,
                    &pending.authorized_relay,
                    pending.operation_expires_at_ms,
                ) && direct_relay_target_matches(
                    current,
                    pending.relay_node_id,
                    peer,
                    pending.operation_expires_at_ms,
                )
            });
        let valid = authority_current
            && response.validate().is_ok()
            && response.request_id() == pending.key.request_id
            && response.validated_operation() == Ok(pending.operation)
            && response.relay_node_id() == pending.relay_node_id
            && response.relay_peer_id() == peer.to_bytes()
            && (response.validated_status() != Ok(ForwardStatus::Granted)
                || matches!(
                    pending.operation,
                    DatapathRelayOperation::UdpSessionStart
                        | DatapathRelayOperation::MptcpSessionStart
                        | DatapathRelayOperation::MpquicSessionStart
                )
                || signed_envelope_matches_peer(response.signed_response(), &peer));
        let pending = self.pending_datapath.remove(&request_id).expect("present");
        self.datapath_index.remove(&pending.key);
        if !valid {
            self.finish_datapath_definitive_error(
                pending,
                OutboundReservationError::InvalidResponse,
            );
            return OutboundEventOutcome::InvalidResponse;
        }
        self.cache_datapath_result(&pending, Ok(response.clone()));
        for waiter in pending.waiters {
            let _ = waiter.send(Ok(response.clone()));
        }
        OutboundEventOutcome::Completed
    }

    fn client_authority_is_current(&self, pending: &PendingClientForward, now_ms: u64) -> bool {
        let control_current = self
            .direct_relays
            .get(&pending.key.control_relay_peer)
            .is_some_and(|current| {
                direct_relay_authority_lineage_matches(
                    current,
                    &pending.authorized_control,
                    pending.operation_expires_at_ms,
                )
            });
        if !control_current
            || !self.forwarded_exit_peer_is_eligible(pending.expected_exit_peer, now_ms)
        {
            return false;
        }
        match &pending.authorized_exit {
            Some(expected) => self
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: pending.key.control_relay_peer,
                    exit_peer: pending.expected_exit_peer,
                })
                .is_some_and(|current| {
                    current == expected && current.expires_at_ms >= pending.operation_expires_at_ms
                }),
            None => pending.operation == ExitForwardOperation::FetchExitAdvertisement,
        }
    }

    fn finish_client_definitive_error(
        &mut self,
        pending: PendingClientForward,
        error: OutboundReservationError,
    ) {
        self.cache_client_result(&pending, Err(error));
        for waiter in pending.waiters {
            let _ = waiter.send(Err(error));
        }
    }

    fn finish_datapath_definitive_error(
        &mut self,
        pending: PendingDatapath,
        error: OutboundReservationError,
    ) {
        self.cache_datapath_result(&pending, Err(error));
        for waiter in pending.waiters {
            let _ = waiter.send(Err(error));
        }
    }

    fn finish_client_ambiguity(&mut self, pending: PendingClientForward) {
        let retryable = pending.dispatch_attempts < MAX_DISPATCH_ATTEMPTS
            && pending.operation_expires_at_ms > unix_millis();
        let error = if retryable {
            self.retry_client_forwards.insert(
                pending.key,
                RetryLedgerEntry {
                    canonical_request: pending.canonical_request.clone(),
                    operation: Some(pending.operation),
                    dispatch_attempts: pending.dispatch_attempts,
                    expires_at_ms: pending.operation_expires_at_ms,
                    reserved_bytes: pending.reserved_bytes,
                    target_peer: pending.expected_exit_peer,
                },
            );
            OutboundReservationError::AmbiguousAfterDispatch
        } else {
            self.cache_client_result(&pending, Err(OutboundReservationError::RetryExhausted));
            OutboundReservationError::RetryExhausted
        };
        for waiter in pending.waiters {
            let _ = waiter.send(Err(error));
        }
    }

    fn finish_datapath_ambiguity(&mut self, pending: PendingDatapath) {
        let retryable = pending.dispatch_attempts < MAX_DISPATCH_ATTEMPTS
            && pending.operation_expires_at_ms > unix_millis();
        let error = if retryable {
            self.retry_datapath.insert(
                pending.key,
                RetryLedgerEntry {
                    canonical_request: pending.canonical_request.clone(),
                    operation: None,
                    dispatch_attempts: pending.dispatch_attempts,
                    expires_at_ms: pending.operation_expires_at_ms,
                    reserved_bytes: pending.reserved_bytes,
                    target_peer: pending.key.relay_peer,
                },
            );
            OutboundReservationError::AmbiguousAfterDispatch
        } else {
            self.cache_datapath_result(&pending, Err(OutboundReservationError::RetryExhausted));
            OutboundReservationError::RetryExhausted
        };
        for waiter in pending.waiters {
            let _ = waiter.send(Err(error));
        }
    }

    fn fail_client_forward(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
    ) -> OutboundEventOutcome {
        let Some(pending) = self.pending_client_forwards.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if pending.key.control_relay_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let pending = self
            .pending_client_forwards
            .remove(&request_id)
            .expect("present");
        self.client_forward_index.remove(&pending.key);
        self.finish_client_ambiguity(pending);
        OutboundEventOutcome::Failed
    }

    fn fail_datapath(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
    ) -> OutboundEventOutcome {
        let Some(pending) = self.pending_datapath.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if pending.key.relay_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let pending = self.pending_datapath.remove(&request_id).expect("present");
        self.datapath_index.remove(&pending.key);
        self.finish_datapath_ambiguity(pending);
        OutboundEventOutcome::Failed
    }

    async fn reap_outbound_reservations(&mut self, now: Instant) -> OutboundReapCounts {
        self.purge_completed(now);
        let client_ids = self
            .pending_client_forwards
            .iter()
            .filter_map(|(id, pending)| (pending.attempt_deadline <= now).then_some(*id))
            .collect::<Vec<_>>();
        let datapath_ids = self
            .pending_datapath
            .iter()
            .filter_map(|(id, pending)| (pending.attempt_deadline <= now).then_some(*id))
            .collect::<Vec<_>>();
        let relay_ids = self
            .pending_relay_forwards
            .iter()
            .filter_map(|(id, pending)| (pending.attempt_deadline <= now).then_some(*id))
            .collect::<Vec<_>>();
        let mut counts = OutboundReapCounts::default();
        for id in client_ids {
            if let Some(pending) = self.pending_client_forwards.remove(&id) {
                self.client_forward_index.remove(&pending.key);
                counts.ambiguous = counts.ambiguous.saturating_add(1);
                self.finish_client_ambiguity(pending);
            }
        }
        for id in datapath_ids {
            if let Some(pending) = self.pending_datapath.remove(&id) {
                self.datapath_index.remove(&pending.key);
                counts.ambiguous = counts.ambiguous.saturating_add(1);
                self.finish_datapath_ambiguity(pending);
            }
        }
        for id in relay_ids {
            if let Some(pending) = self.pending_relay_forwards.remove(&id) {
                self.relay_forward_index.remove(&pending.key);
                counts.ambiguous = counts.ambiguous.saturating_add(1);
                Box::pin(self.finish_relay_ambiguity_awaited(pending)).await;
            }
        }
        counts
    }

    fn fail_all_outbound_reservations(&mut self, error: OutboundReservationError) {
        for (_, pending) in self.pending_client_forwards.drain() {
            for waiter in pending.waiters {
                let _ = waiter.send(Err(error));
            }
        }
        self.client_forward_index.clear();
        for (_, pending) in self.pending_datapath.drain() {
            for waiter in pending.waiters {
                let _ = waiter.send(Err(error));
            }
        }
        self.datapath_index.clear();
        self.pending_relay_forwards.clear();
        self.relay_forward_index.clear();
        self.retry_client_forwards.clear();
        self.retry_datapath.clear();
        self.retry_relay_forwards.clear();
    }

    async fn fail_all_pending_route_sessions(&mut self) {
        let pending_ids = self
            .pending_relay_forwards
            .iter()
            .filter_map(|(id, pending)| {
                (pending.udp_session.is_some()
                    || pending.mptcp_session.is_some()
                    || pending.mpquic_session.is_some())
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in pending_ids {
            let Some(mut pending) = self.pending_relay_forwards.remove(&id) else {
                continue;
            };
            self.relay_forward_index.remove(&pending.key);
            if let Some(udp) = pending.udp_session.take() {
                self.finish_udp_session_unavailable(udp).await;
            } else if let Some(mptcp) = pending.mptcp_session.take() {
                self.finish_mptcp_session_unavailable(mptcp).await;
            } else if let Some(mpquic) = pending.mpquic_session.take() {
                self.finish_mpquic_session_unavailable(mpquic).await;
            }
        }
    }

    fn reject_queued_outbound_commands(&mut self) {
        while let Ok(command) = self.role_commands.try_recv() {
            match command {
                DiscoveryCommand::RequestExitForward { reply, .. } => {
                    let _ = reply.send(Err(OutboundReservationError::Shutdown));
                }
                DiscoveryCommand::RequestDatapathRelay { reply, .. } => {
                    let _ = reply.send(Err(OutboundReservationError::Shutdown));
                }
                DiscoveryCommand::ResolveDirectRelay { reply, .. } => {
                    let _ = reply.send(None);
                }
                DiscoveryCommand::ResolveForwardedExit { reply, .. } => {
                    let _ = reply.send(None);
                }
                DiscoveryCommand::ResolveEndpointTraversalHints { reply, .. } => {
                    let _ = reply.send(Err(OutboundReservationError::Shutdown));
                }
                DiscoveryCommand::RouteCandidateSnapshot { reply, .. } => {
                    let _ = reply.send(Err(RouteCandidateSnapshotError::Closed));
                }
                DiscoveryCommand::BeginClientPreselection { reply, .. } => {
                    let _ = reply.send(Err(ClientPreselectionError::Closed));
                }
                DiscoveryCommand::SetRoles { .. } | DiscoveryCommand::ApplyPolicy { .. } => {}
            }
        }
    }

    fn purge_completed(&mut self, _now: Instant) {
        self.purge_completed_at(unix_millis());
    }

    fn purge_completed_at(&mut self, now_ms: u64) {
        self.completed_client_forwards
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.completed_relay_forwards
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.completed_datapath
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.retry_client_forwards
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.retry_relay_forwards
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.retry_datapath
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.recent_native_relay_evidence
            .retain(|evidence| evidence.expires_at_ms > now_ms);
        self.recent_native_exit_evidence
            .retain(|evidence| evidence.expires_at_ms > now_ms);
        let expired_direct_relays = self
            .direct_relays
            .iter()
            .filter_map(|(peer, capability)| {
                (capability.expires_at_ms <= now_ms).then_some((*peer, capability.clone()))
            })
            .collect::<Vec<_>>();
        for (peer, capability) in expired_direct_relays {
            let accepted = accepted_from_direct_capability(&capability);
            self.revoke_for_direct_advertisement(peer, &accepted, false, true);
        }
        if let Some(capability) = self
            .local_relay_snapshot
            .take_if(|capability| capability.expires_at_ms <= now_ms)
        {
            let accepted = accepted_from_direct_capability(&capability);
            self.revoke_for_direct_advertisement(capability.peer_id, &accepted, false, true);
        }
        let local_peer = *self.service.local_peer_id();
        let stale_forwarded_keys = self
            .forwarded_exits
            .iter()
            .filter_map(|(key, capability)| {
                let control = if key.control_relay_peer == local_peer {
                    self.local_relay_snapshot.as_ref()
                } else {
                    self.direct_relays.get(&key.control_relay_peer)
                };
                let current = control.is_some_and(|control| {
                    forwarded_exit_capability_matches(
                        capability,
                        control,
                        capability.control_relay_node_id,
                        capability.control_relay_peer_id,
                        capability.control_relay_public_key,
                        capability.exit_node_id,
                        capability.exit_peer_id,
                        now_ms.saturating_add(1),
                    )
                });
                (!current).then_some(*key)
            })
            .collect::<Vec<_>>();
        self.revoke_forwarded_keys(&stale_forwarded_keys, false);
        self.forwarded_exit_targets
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.privacy_conflicts
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.forwarded_ad_replays
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.accepted_advertisements
            .retain(|_, record| record.expires_at_ms > now_ms);
        self.exit_provider_peers
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.relay_provider_peers
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.reserved_provider_exit_peers
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.exit_data_relays.retain(|_, capability| {
            capability.expires_at_ms > now_ms
                && capability.advertisement_expires_at_ms > now_ms
                && capability.policy_expires_at_ms > now_ms
        });
        self.exit_control_relays.retain(|_, capability| {
            capability.expires_at_ms > now_ms
                && capability.advertisement_expires_at_ms > now_ms
                && capability.policy_expires_at_ms > now_ms
        });
        self.preferred_exit_controls
            .retain(|exit_peer, control_peer| {
                exit_peer != control_peer
                    && self.exit_provider_peers.contains_key(exit_peer)
                    && self.direct_relays.contains_key(control_peer)
            });
        self.retain_live_automatic_exit_fetch_history();
        if self.forwarded_exit_fail_closed_until_ms <= now_ms {
            self.forwarded_exit_fail_closed_until_ms = 0;
        }
    }

    fn cache_client_result(
        &mut self,
        pending: &PendingClientForward,
        outcome: Result<ExitForwardResponse, OutboundReservationError>,
    ) {
        let response_bytes = outcome.as_ref().ok().map_or(0, |response| {
            encode_canonical(
                response,
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
            )
            .map_or(
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
                |encoded| encoded.len(),
            )
        });
        let reserved_bytes = completed_ledger_reservation_bytes(
            pending.canonical_request.len(),
            response_bytes,
            pending.reserved_bytes,
        );
        let previous = self.completed_client_forwards.insert(
            pending.key,
            CompletedClientForward {
                canonical_request: pending.canonical_request.clone(),
                target_peer: pending.expected_exit_peer,
                operation: pending.operation,
                outcome,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes,
            },
        );
        debug_assert!(previous.is_none(), "logical client result already cached");
    }

    fn cache_datapath_result(
        &mut self,
        pending: &PendingDatapath,
        outcome: Result<DatapathRelayResponse, OutboundReservationError>,
    ) {
        let response_bytes = outcome.as_ref().ok().map_or(0, |response| {
            encode_canonical(
                response,
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
            )
            .map_or(
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
                |encoded| encoded.len(),
            )
        });
        let reserved_bytes = completed_ledger_reservation_bytes(
            pending.canonical_request.len(),
            response_bytes,
            pending.reserved_bytes,
        );
        let previous = self.completed_datapath.insert(
            pending.key,
            CompletedDatapath {
                canonical_request: pending.canonical_request.clone(),
                outcome,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes,
            },
        );
        debug_assert!(previous.is_none(), "logical datapath result already cached");
    }

    fn ledger_can_reserve(&self, peer: Libp2pPeerId, reserved_bytes: usize) -> bool {
        self.ledger_entry_count() < MAX_LEDGER_ENTRIES
            && self
                .ledger_reserved_bytes()
                .checked_add(reserved_bytes)
                .is_some_and(|bytes| bytes <= MAX_LEDGER_BYTES)
            && self
                .ledger_reserved_bytes_for_peer(peer)
                .checked_add(reserved_bytes)
                .is_some_and(|bytes| bytes <= MAX_LEDGER_BYTES_PER_PEER)
    }

    fn ledger_entry_count(&self) -> usize {
        self.pending_client_forwards.len()
            + self.completed_client_forwards.len()
            + self.retry_client_forwards.len()
            + self.pending_relay_forwards.len()
            + self.completed_relay_forwards.len()
            + self.retry_relay_forwards.len()
            + self.pending_datapath.len()
            + self.completed_datapath.len()
            + self.retry_datapath.len()
            + self
                .pending_exit_native_ready
                .values()
                .map(native_ready::ExitNativeReadySet::entry_count)
                .sum::<usize>()
    }

    fn ledger_reserved_bytes(&self) -> usize {
        let groups = [
            self.pending_exit_native_ready
                .values()
                .map(native_ready::ExitNativeReadySet::retained_bytes)
                .fold(0, usize::saturating_add),
            self.pending_client_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_client_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_client_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.pending_relay_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_relay_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_relay_forwards
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.pending_datapath
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_datapath
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_datapath
                .values()
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
        ];
        groups.into_iter().fold(0, usize::saturating_add)
    }

    fn ledger_reserved_bytes_for_peer(&self, peer: Libp2pPeerId) -> usize {
        let groups = [
            self.pending_exit_native_ready
                .values()
                .map(|set| set.retained_bytes_for_peer(peer))
                .fold(0, usize::saturating_add),
            self.pending_client_forwards
                .values()
                .filter(|entry| entry.key.control_relay_peer == peer)
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_client_forwards
                .iter()
                .filter(|(key, _)| key.control_relay_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_client_forwards
                .iter()
                .filter(|(key, _)| key.control_relay_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.pending_relay_forwards
                .values()
                .filter(|entry| entry.key.authenticated_client_peer == peer)
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_relay_forwards
                .iter()
                .filter(|(key, _)| key.authenticated_client_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_relay_forwards
                .iter()
                .filter(|(key, _)| key.authenticated_client_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.pending_datapath
                .values()
                .filter(|entry| entry.key.relay_peer == peer)
                .map(|entry| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.completed_datapath
                .iter()
                .filter(|(key, _)| key.relay_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
            self.retry_datapath
                .iter()
                .filter(|(key, _)| key.relay_peer == peer)
                .map(|(_, entry)| entry.reserved_bytes)
                .fold(0, usize::saturating_add),
        ];
        groups.into_iter().fold(0, usize::saturating_add)
    }

    fn peer_is_forwarded_exit_target(&self, peer: Libp2pPeerId, now_ms: u64) -> bool {
        let local_peer = *self.service.local_peer_id();
        self.forwarded_exit_targets
            .get(&peer)
            .is_some_and(|expires_at_ms| *expires_at_ms > now_ms)
            || self.forwarded_exits.values().any(|capability| {
                capability.control_relay_peer_id != local_peer
                    && capability.exit_peer_id == peer
                    && capability.expires_at_ms > now_ms
            })
            || self
                .pending_client_forwards
                .values()
                .any(|pending| pending.expected_exit_peer == peer)
            || self
                .retry_client_forwards
                .values()
                .any(|entry| entry.target_peer == peer && entry.expires_at_ms > now_ms)
    }

    fn forwarded_exit_peer_is_eligible(&self, peer: Libp2pPeerId, now_ms: u64) -> bool {
        let direct_association = self
            .direct_relays
            .get(&peer)
            .is_some_and(|capability| capability.expires_at_ms > now_ms);
        let privacy_conflict = has_active_privacy_conflict(
            &self.privacy_conflicts,
            self.forwarded_exit_fail_closed_until_ms,
            peer,
            now_ms,
        );
        let pending_direct_association = self
            .relay_advertisement_requests
            .values()
            .any(|pending_peer| *pending_peer == peer);
        !(direct_association || privacy_conflict || pending_direct_association)
    }

    /// Server-side forwarding belongs to the authenticated remote client, not this node's own
    /// Client selection. Its exact signed Relay/Exit authority is checked by each caller.
    fn relay_forward_exit_peer_is_eligible(
        &self,
        authenticated_client_peer: Libp2pPeerId,
        exit_peer: Libp2pPeerId,
    ) -> bool {
        let local_peer = *self.service.local_peer_id();
        self.roles.relay
            && authenticated_client_peer != local_peer
            && exit_peer != local_peer
            && exit_peer != authenticated_client_peer
    }

    /// A local Relay-owned capability must not inherit unrelated local Client provenance guards.
    /// Remote-control capabilities remain subject to the original Client fail-closed checks.
    fn forwarded_exit_authority_is_eligible(
        &self,
        control_relay_peer: Libp2pPeerId,
        exit_peer: Libp2pPeerId,
        now_ms: u64,
    ) -> bool {
        let local_peer = *self.service.local_peer_id();
        if control_relay_peer == local_peer {
            self.roles.relay && exit_peer != local_peer
        } else {
            self.forwarded_exit_peer_is_eligible(exit_peer, now_ms)
        }
    }

    /// Native Ready and Authorization derive their target from an exact, verified Permit chain.
    /// A simultaneous local Client role cannot invalidate forwarding for a different client.
    fn permit_bound_exit_peer_is_eligible(
        &self,
        authenticated_client_peer: Libp2pPeerId,
        exit_peer: Libp2pPeerId,
    ) -> bool {
        self.relay_forward_exit_peer_is_eligible(authenticated_client_peer, exit_peer)
    }

    fn mark_forwarded_exit_target(&mut self, peer: Libp2pPeerId, expires_at_ms: u64) -> bool {
        if let Some(existing) = self.forwarded_exit_targets.get_mut(&peer) {
            *existing = (*existing).max(expires_at_ms);
        } else if self.forwarded_exit_targets.len() >= MAX_EXIT_PROVIDER_PEERS {
            return false;
        } else {
            self.forwarded_exit_targets.insert(peer, expires_at_ms);
        }
        self.relay_advertisement_requests
            .retain(|_, pending_peer| *pending_peer != peer);
        true
    }

    async fn apply_roles(
        &mut self,
        expected: RolesConfig,
        candidate: RolesConfig,
        state: &Arc<RwLock<AgentState>>,
    ) -> Result<RolesConfig, RoleApplyError> {
        if self.roles != expected || state.read().await.roles() != expected {
            return Err(RoleApplyError::StateDiverged);
        }
        if candidate == expected {
            return Ok(candidate);
        }
        let mut effective = self.config.clone();
        effective.roles = candidate;
        effective
            .validate()
            .map_err(|_| RoleApplyError::Prerequisites)?;
        if candidate.exit && !expected.exit && !state.read().await.policy_active(unix_millis()) {
            return Err(RoleApplyError::PolicyUnavailable);
        }
        // libp2p ProtocolSupport is fixed when the swarm is built. Mutating service roles in a
        // running swarm could leave forbidden protocol directions registered, so role changes are
        // rejected without persistence or in-memory mutation and require a controlled restart.
        Err(RoleApplyError::RestartRequired)
    }

    #[cfg(test)]
    async fn wait_at_policy_apply_pre_reply_barrier(&mut self, state: &Arc<RwLock<AgentState>>) {
        let Some(barrier) = self
            .advertisement_commit_test_barriers
            .policy_apply_pre_reply
            .take()
        else {
            return;
        };
        let state = state.read().await;
        let snapshot = PolicyApplyPreReplySnapshot {
            active_policy_version: state.policy_snapshot(unix_millis()).manifest_version,
            direct_relays: self.direct_relays.len(),
            local_relay_snapshots: usize::from(self.local_relay_snapshot.is_some()),
            forwarded_exits: self.forwarded_exits.len(),
            pending_client_forwards: self.pending_client_forwards.len(),
            client_forward_index: self.client_forward_index.len(),
            retry_client_forwards: self.retry_client_forwards.len(),
            completed_client_forwards: self.completed_client_forwards.len(),
            invalid_client_tombstones: self
                .completed_client_forwards
                .values()
                .filter(|entry| entry.outcome == Err(OutboundReservationError::InvalidResponse))
                .count(),
            pending_relay_forwards: self.pending_relay_forwards.len(),
            relay_forward_index: self.relay_forward_index.len(),
            retry_relay_forwards: self.retry_relay_forwards.len(),
            completed_relay_forwards: self.completed_relay_forwards.len(),
            withdrawn_relay_tombstones: self
                .completed_relay_forwards
                .values()
                .filter(|entry| entry.response.is_none())
                .count(),
            exit_services: usize::from(self.exit_service.is_some()),
            served_local_advertisements: usize::from(self.served_local_advertisement.is_some()),
            service_local_advertisements: usize::from(
                self.service.is_serving_local_advertisement(),
            ),
            active_provider_keys: self.active_provider_keys.len(),
        };
        drop(state);
        let _ = barrier.reached.send(snapshot);
        let _ = barrier.release.await;
    }

    async fn revoke_capabilities_outside_active_policy(&mut self, state: &Arc<RwLock<AgentState>>) {
        let now_ms = unix_millis();
        let policy = state.read().await.policy_snapshot(now_ms);
        let active_hash = fixed_bytes::<32>(&policy.policy_hash);
        let policy_matches = |version: u64, hash: [u8; 32], expires_at_ms: u64| {
            policy.active
                && policy.manifest_version == version
                && active_hash == Some(hash)
                && policy.expires_at_ms == expires_at_ms
                && expires_at_ms > now_ms
        };

        self.exit_data_relays.retain(|_, capability| {
            policy_matches(
                capability.policy_version,
                capability.policy_hash,
                capability.policy_expires_at_ms,
            )
        });
        self.exit_control_relays.retain(|_, capability| {
            policy_matches(
                capability.policy_version,
                capability.policy_hash,
                capability.policy_expires_at_ms,
            )
        });

        let stale_direct = self
            .direct_relays
            .iter()
            .filter_map(|(peer, capability)| {
                (!policy_matches(
                    capability.policy_version,
                    capability.policy_hash,
                    capability.policy_expires_at_ms,
                ))
                .then_some((*peer, capability.clone()))
            })
            .collect::<Vec<_>>();
        for (peer, capability) in stale_direct {
            let accepted = accepted_from_direct_capability(&capability);
            let removed_expiry = self.revoke_for_direct_advertisement(peer, &accepted, false, true);
            self.record_privacy_conflict(
                peer,
                capability.advertisement_sequence,
                capability
                    .advertisement_expires_at_ms
                    .max(removed_expiry.unwrap_or_default()),
            );
        }

        let local_stale = self
            .local_relay_snapshot
            .as_ref()
            .is_some_and(|capability| {
                !policy_matches(
                    capability.policy_version,
                    capability.policy_hash,
                    capability.policy_expires_at_ms,
                )
            });
        if local_stale {
            if let Some(capability) = self.local_relay_snapshot.take() {
                let accepted = accepted_from_direct_capability(&capability);
                self.revoke_for_direct_advertisement(capability.peer_id, &accepted, false, true);
            }
        }

        let stale_forwarded = self
            .forwarded_exits
            .iter()
            .filter_map(|(key, capability)| {
                (!policy_matches(
                    capability.policy_version,
                    capability.policy_hash,
                    capability.policy_expires_at_ms,
                ))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        self.revoke_forwarded_keys(&stale_forwarded, false);
    }

    async fn synchronize_exit_policy(&mut self, state: &Arc<RwLock<AgentState>>) {
        self.revoke_capabilities_outside_active_policy(state).await;
        if !self.roles.exit {
            self.destroy_expired_production_exit_routes(u64::MAX).await;
            if self.exit_service.take().is_some() {
                clear_exit_metric(&self.metrics);
            }
            return;
        }
        let now_ms = unix_millis();
        let active_policy = state.read().await.active_policy(now_ms);
        let unchanged = active_policy.as_ref().is_some_and(|policy| {
            self.exit_service
                .as_ref()
                .is_some_and(|service| service.policy_hash() == policy.policy_hash())
        });
        if unchanged {
            return;
        }

        // Finalized helper routes are inseparable from the policy-bound ExitService that admitted
        // them. Destroy their affine helper owners before replacing that service.
        self.destroy_expired_production_exit_routes(u64::MAX).await;

        let had_service = self.exit_service.take().is_some();
        clear_exit_metric(&self.metrics);
        match active_policy {
            Some(policy) => {
                if let Ok(service) =
                    build_exit_service(self.local_node_id, &self.config, policy, &self.metrics)
                {
                    self.exit_service = Some(service);
                    state.write().await.log(
                        LogLevel::Info,
                        "EXIT_POLICY_SERVICE_REFRESHED",
                        now_ms,
                    );
                } else {
                    state
                        .write()
                        .await
                        .log(LogLevel::Error, "EXIT_POLICY_SERVICE_FAILED", now_ms);
                }
            }
            None if had_service => {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "EXIT_POLICY_SERVICE_WITHDRAWN", now_ms);
            }
            None => {}
        }
    }

    async fn log_expiry_reclaim(
        state: &Arc<RwLock<AgentState>>,
        relay_count: usize,
        exit_count: usize,
    ) {
        if relay_count > 0 {
            state
                .write()
                .await
                .log(LogLevel::Debug, "RELAY_RESERVATION_EXPIRED", unix_millis());
        }
        if exit_count > 0 {
            state
                .write()
                .await
                .log(LogLevel::Debug, "EXIT_RESERVATION_EXPIRED", unix_millis());
        }
    }

    async fn query_capabilities(&mut self, state: &Arc<RwLock<AgentState>>) {
        for (key, kind) in [
            (capability::RELAY, ProviderQueryKind::Relay),
            (capability::EXIT, ProviderQueryKind::Exit),
        ] {
            match self.service.find_providers(key) {
                Ok(query_id) => match self.provider_queries.get(&query_id) {
                    Some(existing) if *existing != kind => {
                        state.write().await.log(
                            LogLevel::Warn,
                            "DISCOVERY_QUERY_PROVENANCE_CONFLICT",
                            unix_millis(),
                        );
                    }
                    Some(_) => {}
                    None => {
                        self.provider_queries.insert(query_id, kind);
                    }
                },
                Err(_) => {
                    state.write().await.log(
                        LogLevel::Warn,
                        "DISCOVERY_QUERY_FAILED",
                        unix_millis(),
                    );
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one local publication transaction installs its served and affine authority state"
    )]
    async fn publish_local(&mut self, state: &Arc<RwLock<AgentState>>) {
        let now_ms = unix_millis();
        if !(self.roles.relay || self.roles.exit) {
            self.withdraw_local();
            return;
        }
        let Some(operator_id) = self.config.network.operator_id.clone() else {
            self.withdraw_local();
            return;
        };
        let (roles, policy) = {
            let state = state.read().await;
            (state.roles(), state.policy_snapshot(now_ms))
        };
        let Ok(policy_hash) = <[u8; 32]>::try_from(policy.policy_hash.as_slice()) else {
            self.withdraw_local();
            return;
        };
        if !policy.active || self.control_addresses.is_empty() {
            self.withdraw_local();
            return;
        }
        let Some(capacity) = self.local_advertisement_capacity(roles, now_ms) else {
            self.withdraw_local();
            return;
        };
        let input = LocalAdvertisementInput {
            roles,
            operator_id,
            capabilities: self.local_advertisement_capabilities(),
            capacity,
            origin: self.local_advertisement_origin(),
            policy_version: policy.manifest_version,
            policy_hash,
            policy_expires_at_ms: policy.expires_at_ms,
            control_addresses: self.control_addresses.clone(),
        };
        let Ok(signed) = self.publisher.sign(&self.identity, &input, now_ms) else {
            self.withdraw_local();
            state
                .write()
                .await
                .log(LogLevel::Warn, "ADVERTISEMENT_PUBLISH_FAILED", now_ms);
            return;
        };
        if self
            .service
            .set_local_advertisement(signed.envelope.clone())
            .is_err()
        {
            self.withdraw_local();
            state
                .write()
                .await
                .log(LogLevel::Warn, "ADVERTISEMENT_PUBLISH_FAILED", now_ms);
            return;
        }
        self.served_local_advertisement = Some(signed.envelope.clone());

        if roles.relay {
            let Some(fingerprint) = advertisement_fingerprint(&signed.envelope) else {
                self.withdraw_local();
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "ADVERTISEMENT_PUBLISH_FAILED", now_ms);
                return;
            };
            self.local_relay_snapshot = Some(DirectRelayCapability {
                node_id: self.local_node_id,
                peer_id: *self.service.local_peer_id(),
                public_key: self.local_public_key,
                advertisement_sequence: signed.sequence_number,
                advertisement_expires_at_ms: signed.expires_at_ms,
                advertisement_payload_hash: fingerprint.payload_hash,
                policy_version: policy.manifest_version,
                policy_hash,
                policy_expires_at_ms: policy.expires_at_ms,
                expires_at_ms: signed.expires_at_ms.min(policy.expires_at_ms),
            });
        } else {
            self.local_relay_snapshot = None;
        }

        let removed: Vec<String> = self
            .active_provider_keys
            .difference(&signed.provider_keys)
            .cloned()
            .collect();
        for key in removed {
            let _ = self.service.stop_providing(&key);
            self.active_provider_keys.remove(&key);
        }
        let added: Vec<String> = signed
            .provider_keys
            .difference(&self.active_provider_keys)
            .cloned()
            .collect();
        for key in added {
            if self.service.provide(&key).is_err() {
                self.withdraw_local();
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "ADVERTISEMENT_PROVIDER_FAILED", now_ms);
                return;
            }
            self.active_provider_keys.insert(key);
        }
    }

    fn local_advertisement_capabilities(&self) -> AdvertisementCapabilities {
        AdvertisementCapabilities {
            tcp_mptcp: self.config.tcp.enabled,
            udp_single_path: self.config.udp.enabled,
            multipath_quic: self.config.quic.enabled,
            ipv4: false,
            ipv6: false,
            udp_hole_punching: false,
        }
    }

    fn local_advertisement_origin(&self) -> AdvertisementNetwork {
        AdvertisementNetwork {
            uplink: match self.config.network.uplink {
                volparossa_config::NetworkUplink::IndependentInternet => {
                    volparossa_protocol::AdvertisementUplink::IndependentInternet
                }
                volparossa_config::NetworkUplink::LocalOnly => {
                    volparossa_protocol::AdvertisementUplink::LocalOnly
                }
            } as i32,
            region: self.config.network.advertised_region.clone(),
            country_code: self.config.network.advertised_country_code.clone(),
            asn: self.config.network.advertised_asn,
            ipv4_prefix_hint: self
                .config
                .network
                .advertised_ipv4_prefix
                .clone()
                .unwrap_or_default(),
            ipv6_prefix_hint: self
                .config
                .network
                .advertised_ipv6_prefix
                .clone()
                .unwrap_or_default(),
            operator_id: String::new(),
        }
    }

    fn local_advertisement_capacity(
        &mut self,
        roles: RolesConfig,
        now_ms: u64,
    ) -> Option<AdvertisementCapacity> {
        let relay_available = if roles.relay {
            Some(self.relay_service.as_mut()?.available(now_ms)?)
        } else {
            None
        };
        let exit_available = if roles.exit {
            Some(self.exit_service.as_mut()?.available(now_ms)?)
        } else {
            None
        };
        let estimated_free = match (relay_available, exit_available) {
            (Some(relay), Some(exit)) => Bandwidth {
                up_mbps: relay.bandwidth.up_mbps.min(exit.bandwidth.up_mbps),
                down_mbps: relay.bandwidth.down_mbps.min(exit.bandwidth.down_mbps),
            },
            (Some(relay), None) => relay.bandwidth,
            (None, Some(exit)) => exit.bandwidth,
            (None, None) => return None,
        };
        let relay_reserved = relay_available.map_or(Bandwidth::default(), |available| Bandwidth {
            up_mbps: self
                .config
                .capacity
                .relay_upload_limit_mbps
                .saturating_sub(available.bandwidth.up_mbps),
            down_mbps: self
                .config
                .capacity
                .relay_download_limit_mbps
                .saturating_sub(available.bandwidth.down_mbps),
        });
        let exit_reserved = exit_available.map_or(Bandwidth::default(), |available| Bandwidth {
            up_mbps: self
                .config
                .capacity
                .exit_upload_limit_mbps
                .saturating_sub(available.bandwidth.up_mbps),
            down_mbps: self
                .config
                .capacity
                .exit_download_limit_mbps
                .saturating_sub(available.bandwidth.down_mbps),
        });
        Some(AdvertisementCapacity {
            operator_relay_limit_up_mbps: u64::from(
                self.config.capacity.relay_upload_limit_mbps * u32::from(roles.relay),
            ),
            operator_relay_limit_down_mbps: u64::from(
                self.config.capacity.relay_download_limit_mbps * u32::from(roles.relay),
            ),
            operator_exit_limit_up_mbps: u64::from(
                self.config.capacity.exit_upload_limit_mbps * u32::from(roles.exit),
            ),
            operator_exit_limit_down_mbps: u64::from(
                self.config.capacity.exit_download_limit_mbps * u32::from(roles.exit),
            ),
            currently_reserved_up_mbps: u64::from(
                relay_reserved.up_mbps.saturating_add(exit_reserved.up_mbps),
            ),
            currently_reserved_down_mbps: u64::from(
                relay_reserved
                    .down_mbps
                    .saturating_add(exit_reserved.down_mbps),
            ),
            estimated_free_up_mbps: u64::from(estimated_free.up_mbps),
            estimated_free_down_mbps: u64::from(estimated_free.down_mbps),
            active_relay_sessions: relay_available.map_or(0, |available| {
                self.config
                    .capacity
                    .maximum_relay_sessions
                    .saturating_sub(available.free_slots)
            }),
            active_exit_sessions: exit_available.map_or(0, |available| {
                self.config
                    .capacity
                    .maximum_exit_sessions
                    .saturating_sub(available.free_slots)
            }),
            free_relay_slots: relay_available.map_or(0, |available| available.free_slots),
            free_exit_slots: exit_available.map_or(0, |available| available.free_slots),
            sample_window_seconds: 0,
        })
    }

    fn withdraw_local(&mut self) {
        self.served_local_advertisement = None;
        self.local_relay_snapshot = None;
        self.service.clear_local_advertisement();
        for key in std::mem::take(&mut self.active_provider_keys) {
            let _ = self.service.stop_providing(&key);
        }
    }

    /// Re-announces the small desired provider-key set after the DHT gains usable connectivity.
    ///
    /// `start_providing` can begin while a freshly started service has only configured routing
    /// addresses and no established QUIC connection. Keeping the signed advertisement served and
    /// retrying its one or two capability indexes is both bounded and authority-free; withdrawing
    /// the advertisement on that transient query timeout makes startup order observable forever.
    async fn reannounce_local_providers(&mut self, state: &Arc<RwLock<AgentState>>) {
        let keys = self
            .active_provider_keys
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if self.service.provide(&key).is_err() {
                state.write().await.log(
                    LogLevel::Warn,
                    "ADVERTISEMENT_PROVIDER_FAILED",
                    unix_millis(),
                );
            }
        }
    }

    fn record_local_endpoint_observation(
        &mut self,
        observer_peer: Libp2pPeerId,
        observed_address: &Multiaddr,
    ) {
        let Some(address) = multiaddr_ip(observed_address)
            .filter(|address| is_public_routable_ip(*address) || is_local_lan_ip(*address))
        else {
            return;
        };
        let observations = self
            .local_endpoint_observations
            .entry(observer_peer)
            .or_default();
        // At most two distinct observations per family are useful: one is usable and two make
        // that family ambiguous. Retaining more would only consume actor memory.
        let same_family = observations
            .iter()
            .filter(|candidate| candidate.is_ipv4() == address.is_ipv4())
            .count();
        if same_family < 2 {
            observations.insert(address);
        }
    }

    fn exact_endpoint_traversal_hints(
        &self,
        mut bindings: Vec<EndpointTraversalBinding>,
    ) -> Result<Vec<TraversalEndpointHint>, OutboundReservationError> {
        if bindings.is_empty()
            || bindings.len() > usize::try_from(MAX_HELPER_PATHS).unwrap_or(8) * 2
        {
            return Err(OutboundReservationError::InvalidRequest);
        }
        bindings.sort_by_key(|binding| (binding.path_id, binding.role as i32));
        if bindings
            .windows(2)
            .any(|pair| (pair[0].path_id, pair[0].role) == (pair[1].path_id, pair[1].role))
        {
            return Err(OutboundReservationError::InvalidRequest);
        }

        let local_peer = *self.service.local_peer_id();
        let mut hints = Vec::new();
        for binding in bindings {
            if !(1..=MAX_HELPER_PATHS).contains(&binding.path_id)
                || binding.role == WireguardRole::Unspecified
                || binding.observer_id == [0; 32]
                || binding.observer_peer_id == local_peer
                || !self
                    .observed_endpoints
                    .contains_key(&binding.observer_peer_id)
            {
                return Err(OutboundReservationError::InvalidRequest);
            }
            let Some(observations) = self
                .local_endpoint_observations
                .get(&binding.observer_peer_id)
            else {
                continue;
            };
            for ipv4 in [false, true] {
                let candidates = observations
                    .iter()
                    .filter(|address| address.is_ipv4() == ipv4)
                    .copied()
                    .collect::<Vec<_>>();
                let [address] = candidates.as_slice() else {
                    continue;
                };
                if let Some(hint) = endpoint_hint_from_observation(
                    &binding,
                    *address,
                    &self.observed_endpoints[&binding.observer_peer_id],
                ) {
                    hints.push(hint);
                }
            }
        }
        Ok(hints)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive v4 swarm dispatcher keeps every protocol direction fail closed"
    )]
    async fn handle_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if self.control_addresses.insert(address.to_string()) {
                    self.publish_local(state).await;
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                if self.control_addresses.remove(&address.to_string()) {
                    self.publish_local(state).await;
                }
            }
            SwarmEvent::ListenerClosed { addresses, .. } => {
                let mut changed = false;
                for address in addresses {
                    changed |= self.control_addresses.remove(&address.to_string());
                }
                if changed {
                    self.publish_local(state).await;
                }
            }
            SwarmEvent::ListenerError { .. } => {
                state
                    .write()
                    .await
                    .log(LogLevel::Warn, "DISCOVERY_LISTENER_FAILED", unix_millis());
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let remote = endpoint.get_remote_address().clone();
                self.observed_endpoints
                    .insert(peer_id, (remote.to_string(), multiaddr_ip(&remote)));
                state.write().await.peer_connected(peer_id.to_string());
                self.reannounce_local_providers(state).await;
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.observed_endpoints.remove(&peer_id);
                self.local_endpoint_observations.remove(&peer_id);
                state.write().await.peer_disconnected(&peer_id.to_string());
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) => {
                self.record_local_endpoint_observation(peer_id, &info.observed_addr);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result:
                        kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                            key,
                            providers,
                        })),
                    step,
                    ..
                },
            )) => {
                let kind = self.provider_queries.get(&id).copied();
                if kind.is_some_and(|kind| provider_key_matches(&key, kind)) {
                    self.handle_provider_peers(kind.expect("checked"), providers);
                } else {
                    state.write().await.log(
                        LogLevel::Warn,
                        "DISCOVERY_QUERY_PROVENANCE_CONFLICT",
                        unix_millis(),
                    );
                }
                if step.last {
                    self.finish_provider_query(id);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result:
                        kad::QueryResult::StartProviding(Err(_))
                        | kad::QueryResult::RepublishProvider(Err(_)),
                    ..
                },
            )) => {
                state.write().await.log(
                    LogLevel::Warn,
                    "ADVERTISEMENT_PROVIDER_FAILED",
                    unix_millis(),
                );
                self.provider_queries.remove(&id);
                self.reannounce_local_providers(state).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { id, step, .. },
            )) => {
                if step.last {
                    self.finish_provider_query(id);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Advertisements(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let expected = self.relay_advertisement_requests.remove(&request_id);
                if expected == Some(peer) {
                    let _ = self
                        .ingest_advertisement(
                            peer,
                            response,
                            AdvertisementProvenance::DirectRelay {
                                authenticated_peer: peer,
                            },
                            state,
                        )
                        .await;
                } else {
                    state.write().await.log(
                        LogLevel::Warn,
                        "ADVERTISEMENT_PROVENANCE_MISMATCH",
                        unix_millis(),
                    );
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Advertisements(
                request_response::Event::OutboundFailure { request_id, .. },
            )) => {
                self.relay_advertisement_requests.remove(&request_id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                request_response::Event::OutboundFailure {
                    peer,
                    request_id,
                    error,
                    ..
                },
            )) => {
                let failure_code = match error {
                    request_response::OutboundFailure::DialFailure => {
                        "PRESELECTION_OUTBOUND_DIAL_FAILED"
                    }
                    request_response::OutboundFailure::Timeout => "PRESELECTION_OUTBOUND_TIMED_OUT",
                    request_response::OutboundFailure::ConnectionClosed => {
                        "PRESELECTION_OUTBOUND_CONNECTION_CLOSED"
                    }
                    request_response::OutboundFailure::UnsupportedProtocols => {
                        "PRESELECTION_OUTBOUND_PROTOCOL_UNSUPPORTED"
                    }
                    request_response::OutboundFailure::Io(error) => match error.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            "PRESELECTION_OUTBOUND_IO_UNEXPECTED_EOF"
                        }
                        std::io::ErrorKind::InvalidData => "PRESELECTION_OUTBOUND_IO_INVALID_DATA",
                        std::io::ErrorKind::ConnectionReset => {
                            "PRESELECTION_OUTBOUND_IO_CONNECTION_RESET"
                        }
                        std::io::ErrorKind::BrokenPipe => "PRESELECTION_OUTBOUND_IO_BROKEN_PIPE",
                        std::io::ErrorKind::TimedOut => "PRESELECTION_OUTBOUND_IO_TIMED_OUT",
                        _ => "PRESELECTION_OUTBOUND_IO_OTHER",
                    },
                };
                let owned = self.handle_client_preselection_outbound_failure(peer, request_id);
                state.write().await.log(
                    LogLevel::Warn,
                    if owned {
                        failure_code
                    } else {
                        "PRESELECTION_OUTBOUND_FAILURE_UNOWNED"
                    },
                    unix_millis(),
                );
            }
            SwarmEvent::Behaviour(BehaviourEvent::ExitForward(event)) => {
                self.handle_exit_forward_event(event, state).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(event)) => {
                Box::pin(self.handle_exit_forward_upstream_event(event, state)).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(event)) => {
                Box::pin(self.handle_datapath_event(event, state)).await;
            }
            SwarmEvent::OutgoingConnectionError { .. }
            | SwarmEvent::IncomingConnectionError { .. } => {
                state.write().await.log(
                    LogLevel::Debug,
                    "DISCOVERY_CONNECTION_FAILED",
                    unix_millis(),
                );
            }
            _ => {}
        }
    }

    fn handle_provider_peers(&mut self, kind: ProviderQueryKind, providers: HashSet<Libp2pPeerId>) {
        self.purge_completed(Instant::now());
        let now_ms = unix_millis();
        let provider_expires_at_ms = now_ms.saturating_add(PROVIDER_OBSERVATION_TTL_MS);
        for peer in providers.into_iter().take(self.candidate_limit) {
            if peer == *self.service.local_peer_id() {
                continue;
            }
            match kind {
                ProviderQueryKind::Relay => {
                    if self.relay_provider_peers.contains_key(&peer)
                        || self.relay_provider_peers.len() < self.candidate_limit.max(1)
                    {
                        self.relay_provider_peers
                            .insert(peer, provider_expires_at_ms);
                    }
                }
                ProviderQueryKind::Exit => {
                    if self.exit_provider_peers.contains_key(&peer)
                        || self.exit_provider_peers.len() < MAX_EXIT_PROVIDER_PEERS
                    {
                        self.exit_provider_peers
                            .insert(peer, provider_expires_at_ms);
                    }
                }
            }
        }
        self.schedule_relay_advertisement_fetches(now_ms);
        self.schedule_exit_advertisement_fetches();
    }

    fn finish_provider_query(&mut self, id: kad::QueryId) {
        if self.provider_queries.remove(&id) == Some(ProviderQueryKind::Exit) {
            // The service coalesces same-capability queries. Partition only after its complete
            // result stream, including terminal events with no additional provider records.
            self.schedule_relay_advertisement_fetches(unix_millis());
            self.schedule_exit_advertisement_fetches();
        }
    }

    fn schedule_relay_advertisement_fetches(&mut self, now_ms: u64) {
        if self.roles.client && self.roles.relay {
            // On a homogeneous network the Relay and Exit provider indexes contain the same
            // peers. Fetching every Relay advertisement first would irreversibly associate every
            // possible Exit directly with this Client. Reserve a sticky, bounded portion before
            // making those requests. Provider-result order does not decide the privacy boundary.
            // This also applies to local-only consumers: not offering Exit service themselves
            // must not make them directly contact every available remote Exit as a Relay.
            if self.reserved_provider_exit_peers.is_empty()
                && self
                    .provider_queries
                    .values()
                    .any(|kind| *kind == ProviderQueryKind::Exit)
            {
                // A streamed result may contain only adjacent peers before the opposite peer
                // arrives. Do not turn that partial observation into a sticky privacy boundary.
                return;
            }
            self.reserve_provider_exit_candidates(now_ms);
            if self.reserved_provider_exit_peers.is_empty() {
                return;
            }
        }
        let mut peers = self
            .relay_provider_peers
            .keys()
            .copied()
            .collect::<Vec<_>>();
        peers.sort_by_key(|peer| peer.to_bytes());
        for peer in peers {
            if self.relay_advertisement_requests.len() >= self.candidate_limit.max(1)
                || self.reserved_provider_exit_peers.contains_key(&peer)
                || self.peer_is_forwarded_exit_target(peer, now_ms)
                || self
                    .relay_advertisement_requests
                    .values()
                    .any(|pending| *pending == peer)
            {
                continue;
            }
            // A fresh provider observation may refer to a restarted or changed Relay while the
            // previous advertisement is still unexpired. Refresh within the existing request
            // bounds; expiry is an authority ceiling, not a reason to suppress updates.
            if let Ok(request_id) = self.service.request_relay_advertisement(&peer) {
                self.relay_advertisement_requests.insert(request_id, peer);
            }
        }
    }

    fn reserve_provider_exit_candidates(&mut self, now_ms: u64) {
        // An Exit query finishing says nothing about peers which have not announced yet.
        // This route architecture needs a separate Exit, control Relay and data Relay. Do not
        // permanently sacrifice one of the first two neighbors before that pool can exist.
        if self.reserved_provider_exit_peers.is_empty()
            && self
                .relay_provider_peers
                .keys()
                .chain(self.exit_provider_peers.keys())
                .copied()
                .collect::<HashSet<_>>()
                .len()
                < 3
        {
            return;
        }
        for (peer, expires_at_ms) in &mut self.reserved_provider_exit_peers {
            if let Some(observed_expiry) = self.exit_provider_peers.get(peer) {
                *expires_at_ms = (*expires_at_ms).max(*observed_expiry);
            }
        }
        let target_count = (self.exit_provider_peers.len() / 3)
            .max(1)
            .min(self.candidate_limit.max(1));
        // Prefer authenticated neighbors and explicit bootstrap contacts as Relay contacts.
        // Bootstrap configuration is only a scheduling preference, not signed service authority;
        // including it prevents connection-start order from reserving a known adjacent contact.
        let mut directly_connected = self
            .observed_endpoints
            .iter()
            .filter_map(|(peer, (endpoint, _))| {
                (!endpoint.contains("/p2p-circuit")).then_some(*peer)
            })
            .collect::<HashSet<_>>();
        directly_connected.extend(
            self.config
                .network
                .bootstrap_peers
                .iter()
                .filter_map(|address| parse_bootstrap(address).ok())
                .map(|link| *link.peer_id()),
        );
        let mut peers = self.exit_provider_peers.keys().copied().collect::<Vec<_>>();
        let has_provider_only_exit = peers.iter().any(|peer| {
            !directly_connected.contains(peer)
                && self.forwarded_exit_peer_is_eligible(*peer, now_ms)
        });
        // Relay results can arrive ahead of Exit results. Even a three-peer union must not
        // turn a first Exit result containing only one or two known neighbors into a sticky
        // fallback. A non-neighbor Exit is usable immediately; dense fallback needs its full
        // minimum three-role provider pool in this index as well.
        if !has_provider_only_exit && self.exit_provider_peers.len() < 3 {
            return;
        }
        // Keep existing reservations private even if the topology changed. A newly discovered
        // provider-only Exit can still be reserved when an earlier fallback reserved a neighbor.
        let mut preferred_count = self
            .reserved_provider_exit_peers
            .keys()
            .filter(|peer| !has_provider_only_exit || !directly_connected.contains(peer))
            .count();
        // Selection is local to each Client, not a network-wide permanent Relay/Exit class.
        peers.sort_by_cached_key(|peer| {
            let mut hash = Sha256::new();
            hash.update(b"VOLPAROSSA-provider-partition-v1");
            hash.update(self.local_node_id);
            hash.update(peer.to_bytes());
            <[u8; 32]>::from(hash.finalize())
        });
        for peer in peers {
            if preferred_count >= target_count
                || self.reserved_provider_exit_peers.len() >= self.candidate_limit.max(1)
            {
                break;
            }
            if (!has_provider_only_exit || !directly_connected.contains(&peer))
                && !self.reserved_provider_exit_peers.contains_key(&peer)
                && self.forwarded_exit_peer_is_eligible(peer, now_ms)
            {
                self.reserved_provider_exit_peers
                    .insert(peer, self.exit_provider_peers[&peer]);
                preferred_count += 1;
            }
        }
    }

    /// Fetch provider-only Exit advertisements through one authenticated control Relay.
    ///
    /// A client never dials the Exit here. The actor sends the existing bounded fetch RPC to one
    /// current direct Relay, and only the normal forwarded-provenance commit can make the response
    /// selectable.
    fn schedule_exit_advertisement_fetches(&mut self) {
        if !self.roles.client {
            return;
        }
        let now_ms = unix_millis();
        self.drive_automatic_exit_fetch_attempts(now_ms);
        self.retain_live_automatic_exit_fetch_history();
        if self.automatic_exit_fetch_attempts.len() >= self.candidate_limit.max(1) {
            return;
        }

        let mut controls = self
            .direct_relays
            .values()
            .filter(|control| control.expires_at_ms > now_ms.saturating_add(1_000))
            .cloned()
            .collect::<Vec<_>>();
        controls.sort_by(|left, right| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()));
        let mut exits = self
            .exit_provider_peers
            .iter()
            .filter_map(|(peer, expiry)| {
                (*expiry > now_ms.saturating_add(1_000)).then_some((*peer, *expiry))
            })
            .collect::<Vec<_>>();
        exits.sort_by(|(left, _), (right, _)| left.to_bytes().cmp(&right.to_bytes()));

        for (exit_peer, provider_expiry_ms) in exits {
            if self.automatic_exit_fetch_attempts.len() >= self.candidate_limit.max(1)
                || !self.forwarded_exit_peer_is_eligible(exit_peer, now_ms)
                || self.has_current_forwarded_exit(exit_peer, now_ms.saturating_add(1_000))
                || self
                    .automatic_exit_fetch_attempts
                    .iter()
                    .any(|attempt| attempt.key.exit_peer == exit_peer)
            {
                continue;
            }
            let Some(control) = self.next_untried_exit_control(&controls, exit_peer, now_ms) else {
                continue;
            };
            let key = ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            };
            let deadline_unix_ms = now_ms
                .saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
                .min(provider_expiry_ms)
                .min(control.expires_at_ms.saturating_sub(1));
            if deadline_unix_ms <= now_ms.saturating_add(1_000) {
                continue;
            }
            let mut forward_id = [0_u8; FORWARD_ID_BYTES];
            OsRng.fill_bytes(&mut forward_id);
            forward_id[0] |= 1;
            let Ok(request) = ExitForwardRequest::new(
                forward_id.to_vec(),
                control.node_id.to_vec(),
                control.peer_id.to_bytes(),
                control.public_key.to_vec(),
                exit_peer.to_bytes(),
                Vec::new(),
                deadline_unix_ms,
                ExitForwardOperation::FetchExitAdvertisement,
                Vec::new(),
            ) else {
                continue;
            };
            let (reply, receiver) = oneshot::channel();
            self.automatic_exit_fetches.insert(key, deadline_unix_ms);
            self.begin_client_forward(control.peer_id, request.clone(), reply);
            self.automatic_exit_fetch_attempts
                .push(AutomaticExitFetchAttempt {
                    key,
                    authorized_control: control,
                    request,
                    dispatch_attempts: 1,
                    state: AutomaticExitFetchAttemptState::InFlight(receiver),
                });
        }
    }

    /// A retained affine forwarding capability may outlive the exact advertisement snapshot that
    /// created it. It remains valid for already-authorized operations, but it must not suppress a
    /// refresh needed by a new preselection snapshot.
    fn has_current_forwarded_exit(&self, exit_peer: Libp2pPeerId, required_until_ms: u64) -> bool {
        self.forwarded_exits.iter().any(|(key, capability)| {
            key.exit_peer == exit_peer
                && self
                    .direct_relays
                    .get(&key.control_relay_peer)
                    .is_some_and(|control| {
                        forwarded_exit_capability_matches(
                            capability,
                            control,
                            control.node_id,
                            control.peer_id,
                            control.public_key,
                            capability.exit_node_id,
                            exit_peer,
                            required_until_ms,
                        ) && forwarded_control_projection_lineage_matches(
                            capability,
                            control,
                            required_until_ms,
                        )
                    })
        })
    }

    fn next_untried_exit_control(
        &self,
        controls: &[DirectRelayCapability],
        exit_peer: Libp2pPeerId,
        now_ms: u64,
    ) -> Option<DirectRelayCapability> {
        if let Some(preferred_peer) = self.preferred_exit_controls.get(&exit_peer) {
            let preferred_key = ForwardedExitKey {
                control_relay_peer: *preferred_peer,
                exit_peer,
            };
            if let Some(control) = controls
                .iter()
                .find(|control| control.peer_id == *preferred_peer && control.peer_id != exit_peer)
            {
                let available = self
                    .automatic_exit_fetches
                    .get(&preferred_key)
                    .is_none_or(|expiry| *expiry <= now_ms)
                    && !self
                        .automatic_exit_fetch_attempts
                        .iter()
                        .any(|pending| pending.key == preferred_key);
                return available.then(|| control.clone());
            }
        }

        if let Some(control) = controls
            .iter()
            .find(|control| {
                let key = ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                };
                control.peer_id != exit_peer
                    && !self.automatic_exit_fetches.contains_key(&key)
                    && !self
                        .automatic_exit_fetch_attempts
                        .iter()
                        .any(|pending| pending.key == key)
            })
            .cloned()
        {
            return Some(control);
        }

        // Every never-tried live control wins over an expired suppression. Once the bounded set
        // has completed a round, choose the least-recently suppressed eligible lineage. Retaining
        // expired entries while both peers remain live makes this a fair rotation instead of
        // repeatedly selecting the lexicographically first Relay.
        controls
            .iter()
            .filter_map(|control| {
                let key = ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                };
                let retry_at_ms = self.automatic_exit_fetches.get(&key).copied()?;
                (control.peer_id != exit_peer
                    && retry_at_ms <= now_ms
                    && !self
                        .automatic_exit_fetch_attempts
                        .iter()
                        .any(|pending| pending.key == key))
                .then_some((retry_at_ms, control))
            })
            .min_by(|(left_time, left), (right_time, right)| {
                left_time
                    .cmp(right_time)
                    .then_with(|| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()))
            })
            .map(|(_, control)| control.clone())
    }

    /// Keep only bounded scheduling history for currently live provider/control pairs.
    fn retain_live_automatic_exit_fetch_history(&mut self) {
        let providers = &self.exit_provider_peers;
        let controls = &self.direct_relays;
        self.automatic_exit_fetches.retain(|key, _| {
            providers.contains_key(&key.exit_peer) && controls.contains_key(&key.control_relay_peer)
        });
    }

    fn drive_automatic_exit_fetch_attempts(&mut self, now_ms: u64) {
        let attempts = std::mem::take(&mut self.automatic_exit_fetch_attempts);
        let mut retained = Vec::with_capacity(attempts.len());
        for mut attempt in attempts {
            match &mut attempt.state {
                AutomaticExitFetchAttemptState::InFlight(receiver) => match receiver.try_recv() {
                    Err(oneshot::error::TryRecvError::Empty) => {
                        retained.push(attempt);
                        continue;
                    }
                    Ok(Err(
                        OutboundReservationError::Busy
                        | OutboundReservationError::Capacity
                        | OutboundReservationError::SendFailed
                        | OutboundReservationError::AmbiguousAfterDispatch,
                    )) if attempt.dispatch_attempts < MAX_DISPATCH_ATTEMPTS => {
                        let retry_at_ms =
                            now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_RETRY_BACKOFF_MS);
                        self.automatic_exit_fetches.insert(attempt.key, retry_at_ms);
                        attempt.state = AutomaticExitFetchAttemptState::RetryNotBefore(retry_at_ms);
                        retained.push(attempt);
                        continue;
                    }
                    Ok(Ok(response)) => {
                        if response.validated_status() != Ok(ForwardStatus::Granted) {
                            self.retain_exhausted_exit_fetch_control(attempt.key, now_ms);
                        }
                        continue;
                    }
                    Ok(Err(_)) | Err(oneshot::error::TryRecvError::Closed) => {
                        self.retain_exhausted_exit_fetch_control(attempt.key, now_ms);
                        continue;
                    }
                },
                AutomaticExitFetchAttemptState::RetryNotBefore(retry_at_ms)
                    if *retry_at_ms > now_ms =>
                {
                    retained.push(attempt);
                    continue;
                }
                AutomaticExitFetchAttemptState::RetryNotBefore(_) => {}
            }

            if attempt.dispatch_attempts >= MAX_DISPATCH_ATTEMPTS
                || !self.automatic_exit_fetch_retry_is_current(&attempt, now_ms)
            {
                continue;
            }
            let (reply, receiver) = oneshot::channel();
            self.begin_client_forward(
                attempt.key.control_relay_peer,
                attempt.request.clone(),
                reply,
            );
            attempt.dispatch_attempts = attempt.dispatch_attempts.saturating_add(1);
            attempt.state = AutomaticExitFetchAttemptState::InFlight(receiver);
            self.automatic_exit_fetches
                .insert(attempt.key, attempt.request.deadline_unix_ms());
            retained.push(attempt);
        }
        self.automatic_exit_fetch_attempts = retained;
    }

    /// Prevent a failed control Relay from starving later candidates while still recovering when
    /// that Relay's local DHT view converges after the client observed the Exit provider.
    fn retain_exhausted_exit_fetch_control(&mut self, key: ForwardedExitKey, now_ms: u64) {
        let exhausted_until_ms = self
            .exit_provider_peers
            .get(&key.exit_peer)
            .copied()
            .unwrap_or_else(|| now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_RETRY_BACKOFF_MS))
            .min(now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_EXHAUSTED_COOLDOWN_MS));
        self.automatic_exit_fetches.insert(key, exhausted_until_ms);
    }

    fn automatic_exit_fetch_retry_is_current(
        &self,
        attempt: &AutomaticExitFetchAttempt,
        now_ms: u64,
    ) -> bool {
        let request = &attempt.request;
        request.validate().is_ok()
            && forward_request_scope_matches(
                request,
                ExitForwardOperation::FetchExitAdvertisement,
                now_ms,
            )
            && request.control_relay_peer_id() == attempt.key.control_relay_peer.to_bytes()
            && request.exit_peer_id() == attempt.key.exit_peer.to_bytes()
            && self
                .exit_provider_peers
                .get(&attempt.key.exit_peer)
                .is_some_and(|expires_at_ms| *expires_at_ms > now_ms.saturating_add(1_000))
            && self.forwarded_exit_peer_is_eligible(attempt.key.exit_peer, now_ms)
            && !self.forwarded_exits.contains_key(&attempt.key)
            && self
                .direct_relays
                .get(&attempt.key.control_relay_peer)
                .is_some_and(|current| {
                    direct_relay_authority_lineage_matches(
                        current,
                        &attempt.authorized_control,
                        request.deadline_unix_ms(),
                    )
                })
    }

    async fn handle_exit_forward_event(
        &mut self,
        event: request_response::Event<ExitForwardRequest, ExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => self.begin_relay_forward_observed(peer, &request, channel, state),
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let outcome = self
                    .complete_client_forward(request_id, peer, &response, state)
                    .await;
                log_outbound_event(state, outcome).await;
                self.schedule_exit_advertisement_fetches();
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let outcome = self.fail_client_forward(request_id, peer);
                log_outbound_event(state, outcome).await;
                self.schedule_exit_advertisement_fetches();
            }
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_exit_forward_upstream_event(
        &mut self,
        event: request_response::Event<UpstreamExitForwardRequest, UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                self.answer_exit_forward_upstream(peer, connection_id, request, channel, state)
                    .await;
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let outcome =
                    Box::pin(self.complete_relay_forward(request_id, peer, response, state)).await;
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let outcome = Box::pin(self.fail_relay_forward(request_id, peer)).await;
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => {}
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the typed inbound operation dispatch keeps every affine continuation explicit"
    )]
    async fn handle_datapath_event(
        &mut self,
        event: request_response::Event<DatapathRelayRequest, DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        match event {
            request_response::Event::Message {
                peer: authenticated_client_peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                match request.validated_operation() {
                    Ok(DatapathRelayOperation::ExecuteProbe) => {
                        self.answer_production_execute_probe(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::ReservePath) => {
                        self.begin_production_relay_reservation(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::NativeProbeReady) => {
                        self.begin_native_probe_ready(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::NativeProbeAuthorize) => {
                        Box::pin(self.begin_native_probe_start_authorization(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        ))
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::NativeProbeStart) => {
                        self.begin_native_probe_result(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::UdpSessionStart) => {
                        self.begin_udp_session_start(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::MptcpSessionStart) => {
                        self.begin_mptcp_session_start(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    Ok(DatapathRelayOperation::MpquicSessionStart) => {
                        self.begin_mpquic_session_start(
                            authenticated_client_peer,
                            &request,
                            channel,
                            state,
                        )
                        .await;
                        return;
                    }
                    _ => {}
                }
                let local_peer = *self.service.local_peer_id();
                if let Some(response) = inbound_datapath_unavailable_response(
                    &request,
                    authenticated_client_peer,
                    self.local_node_id,
                    local_peer,
                    self.roles.relay && self.relay_service.is_some(),
                    unix_millis(),
                ) {
                    let _ = self.service.send_datapath_relay_response(channel, response);
                }
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let outcome = self.complete_datapath(request_id, peer, &response);
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let outcome = self.fail_datapath(request_id, peer);
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Translate one immediately preceding helper-proven native path observation into the
    /// standard reservation protocol's Relay-signed probe result.
    ///
    /// This does not trust metrics supplied by the client and does not claim a second network
    /// measurement. The affine ticket was created only after the native Relay helper committed,
    /// the Exit returned its signed observation, and the Relay proved bidirectional forwarding.
    #[allow(
        clippy::too_many_lines,
        reason = "one exact native-evidence consumption and signed response are fail-atomic"
    )]
    async fn answer_production_execute_probe(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                tracing::warn!(rejection = $code, "production Relay ExecuteProbe rejected");
                log_relay_forward_admission(Some(state), $code);
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::ExecuteProbe,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let request_valid = request.validate().is_ok();
        let scope_matches =
            datapath_request_scope_matches(request, DatapathRelayOperation::ExecuteProbe, now_ms);
        let remote_client = authenticated_client_peer != local_peer;
        let relay_role = self.roles.relay;
        let relay_service = self.relay_service.is_some();
        let relay_node_matches = request.relay_node_id() == self.local_node_id;
        let relay_peer_matches = request.relay_peer_id() == local_peer.to_bytes();
        if !request_valid
            || !scope_matches
            || !remote_client
            || !relay_role
            || !relay_service
            || !relay_node_matches
            || !relay_peer_matches
        {
            tracing::warn!(
                request_valid,
                scope_matches,
                remote_client,
                relay_role,
                relay_service,
                relay_node_matches,
                relay_peer_matches,
                "production Relay ExecuteProbe scope diagnostics"
            );
            reject!("PRODUCTION_RELAY_PROBE_SCOPE_REJECTED");
        }
        let Ok(mut replay) = ReplayCache::new(1) else {
            reject!("PRODUCTION_RELAY_PROBE_FRAME_REJECTED");
        };
        let Ok(verified_permit) = verify_control_message::<RelayProbePermit>(
            request.exit_signed_authorization(),
            now_ms,
            TimePolicy::default(),
            &mut replay,
        ) else {
            reject!("PRODUCTION_RELAY_PROBE_FRAME_REJECTED");
        };
        let permit = verified_permit.into_message();
        self.recent_native_relay_evidence
            .retain(|evidence| evidence.expires_at_ms > now_ms);
        let matching_client = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| evidence.authenticated_client_peer == authenticated_client_peer)
            .count();
        let matching_data_relay = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| {
                evidence
                    .scope
                    .data_relay
                    .as_ref()
                    .is_some_and(|data_relay| {
                        data_relay.node_id == permit.relay_node_id
                            && data_relay.peer_id == permit.relay_peer_id
                    })
            })
            .count();
        let matching_control = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| {
                evidence.scope.control.as_ref().is_some_and(|control| {
                    control.node_id == permit.control_relay_node_id
                        && control.peer_id == permit.control_relay_peer_id
                })
            })
            .count();
        let matching_exit = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| {
                evidence.scope.exit.as_ref().is_some_and(|exit| {
                    exit.node_id == permit.exit_node_id && exit.peer_id == permit.exit_peer_id
                })
            })
            .count();
        let matching_policy = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| evidence.scope.policy_hash == permit.policy_hash)
            .count();
        let matching_transport = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| evidence.scope.transport == permit.transport)
            .count();
        let matching_family = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| evidence.scope.address_family == permit.address_family)
            .count();
        let matching_expiry = self
            .recent_native_relay_evidence
            .iter()
            .filter(|evidence| evidence.expires_at_ms <= evidence.scope.attempt_expires_at_ms)
            .count();
        let Some(index) = self
            .recent_native_relay_evidence
            .iter()
            .rposition(|evidence| {
                let Some(data_relay) = evidence.scope.data_relay.as_ref() else {
                    return false;
                };
                let Some(control) = evidence.scope.control.as_ref() else {
                    return false;
                };
                let Some(exit) = evidence.scope.exit.as_ref() else {
                    return false;
                };
                evidence.authenticated_client_peer == authenticated_client_peer
                    && data_relay.node_id == permit.relay_node_id
                    && data_relay.peer_id == permit.relay_peer_id
                    && control.node_id == permit.control_relay_node_id
                    && control.peer_id == permit.control_relay_peer_id
                    && exit.node_id == permit.exit_node_id
                    && exit.peer_id == permit.exit_peer_id
                    && evidence.scope.policy_hash == permit.policy_hash
                    && evidence.scope.transport == permit.transport
                    && evidence.scope.address_family == permit.address_family
                    && evidence.expires_at_ms <= evidence.scope.attempt_expires_at_ms
            })
        else {
            tracing::warn!(
                retained = self.recent_native_relay_evidence.len(),
                matching_client,
                matching_data_relay,
                matching_control,
                matching_exit,
                matching_policy,
                matching_transport,
                matching_family,
                matching_expiry,
                "production Relay ExecuteProbe native evidence diagnostics"
            );
            reject!("PRODUCTION_RELAY_PROBE_NATIVE_EVIDENCE_UNAVAILABLE");
        };
        let evidence = self.recent_native_relay_evidence.remove(index);
        let measured_at_ms = evidence.client_relay.measured_at_ms;
        let expires_at_ms = permit
            .expires_at_ms
            .min(evidence.expires_at_ms)
            .min(measured_at_ms.saturating_add(30_000));
        if expires_at_ms <= now_ms {
            reject!("PRODUCTION_RELAY_PROBE_NATIVE_EVIDENCE_EXPIRED");
        }
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
            client_relay: Some(evidence.client_relay),
            relay_exit: Some(evidence.relay_exit),
            measured_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        let identity = &self.identity;
        let Ok(signed_result) = sign_control_message_with(
            &result,
            self.local_public_key,
            result.measured_at_ms,
            result.expires_at_ms,
            nonce,
            TimePolicy::default(),
            |message| identity.sign(message).ok(),
        ) else {
            reject!("PRODUCTION_RELAY_PROBE_SIGNING_FAILED");
        };
        let Ok(response) = DatapathRelayResponse::granted(
            request.request_id().to_vec(),
            DatapathRelayOperation::ExecuteProbe,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            signed_result,
        ) else {
            reject!("PRODUCTION_RELAY_PROBE_RESPONSE_FAILED");
        };
        if self
            .service
            .send_datapath_relay_response(channel, response)
            .is_err()
        {
            log_relay_forward_admission(Some(state), "PRODUCTION_RELAY_PROBE_DELIVERY_FAILED");
            return;
        }
        log_reservation_event(state, "PRODUCTION_RELAY_PROBE_COMPLETED").await;
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the signed standard grant and exact Relay helper owner are one transaction"
    )]
    async fn begin_production_relay_reservation(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::ReservePath,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        if request.validate().is_err()
            || !datapath_request_scope_matches(request, DatapathRelayOperation::ReservePath, now_ms)
            || authenticated_client_peer == local_peer
            || !self.roles.relay
            || self.relay_service.is_none()
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != local_peer.to_bytes()
        {
            reject!("PRODUCTION_RELAY_RESERVATION_SCOPE_REJECTED");
        }
        let Some((relay_request, authorization)) =
            decoded_relay_reservation_request(request.client_signed_request())
        else {
            reject!("PRODUCTION_RELAY_RESERVATION_FRAME_REJECTED");
        };
        let Some(route_context_id) =
            fixed_bytes::<FORWARD_ID_BYTES>(&authorization.route_context_id)
        else {
            reject!("PRODUCTION_RELAY_RESERVATION_FRAME_REJECTED");
        };
        if let Some(existing) = self.prepared_production_relay_routes.get(&route_context_id) {
            if existing.usable
                && existing.authenticated_client_peer == authenticated_client_peer
                && existing.accepted.signed_client_relay_request()
                    == request.client_signed_request()
                && existing.accepted.expires_at_ms() > now_ms
            {
                if let Ok(response) = DatapathRelayResponse::granted(
                    request.request_id().to_vec(),
                    DatapathRelayOperation::ReservePath,
                    self.local_node_id.to_vec(),
                    local_peer.to_bytes(),
                    existing.accepted.encoded().to_vec(),
                ) {
                    let _ = self.service.send_datapath_relay_response(channel, response);
                }
                return;
            }
            reject!("PRODUCTION_RELAY_RESERVATION_OWNER_CONFLICT");
        }
        let Some(mut prepare) = production_service_prepare_request(
            route_context_id,
            ContextRole::Relay,
            authorization.path_id,
            request.deadline_unix_ms(),
            authorization.expires_at_ms,
        ) else {
            reject!("PRODUCTION_RELAY_RESERVATION_HELPER_SCOPE_REJECTED");
        };
        let Some(client_session_id) = fixed_bytes::<32>(&authorization.client_session_id) else {
            reject!("PRODUCTION_RELAY_RESERVATION_TRAVERSAL_SCOPE_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&authorization.exit_node_id) else {
            reject!("PRODUCTION_RELAY_RESERVATION_TRAVERSAL_SCOPE_REJECTED");
        };
        let Ok(exit_peer_id) = Libp2pPeerId::from_bytes(&authorization.exit_peer_id) else {
            reject!("PRODUCTION_RELAY_RESERVATION_TRAVERSAL_SCOPE_REJECTED");
        };
        prepare.traversal_hints = self
            .exact_endpoint_traversal_hints(vec![
                EndpointTraversalBinding {
                    path_id: authorization.path_id,
                    role: WireguardRole::RelayClient,
                    observer_id: client_session_id,
                    observer_peer_id: authenticated_client_peer,
                },
                EndpointTraversalBinding {
                    path_id: authorization.path_id,
                    role: WireguardRole::RelayExit,
                    observer_id: exit_node_id,
                    observer_peer_id: exit_peer_id,
                },
            ])
            .unwrap_or_default();
        let Ok(mut helper_owner) = self.helper.prepare_lease_batch(prepare.clone()).await else {
            reject!("PRODUCTION_RELAY_RESERVATION_HELPER_PREPARE_UNAVAILABLE");
        };
        let Ok(endpoint) =
            bind_prepared_relay_endpoint_lease(&prepare, helper_owner.prepared().clone())
        else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("PRODUCTION_RELAY_RESERVATION_HELPER_BIND_REJECTED");
        };
        let identity = &self.identity;
        let accepted = self.relay_service.as_mut().and_then(|service| {
            service
                .accept_request_with(
                    request.client_signed_request(),
                    now_ms,
                    self.local_public_key,
                    move |path_id| (path_id == endpoint.path_id()).then_some(endpoint),
                    |message| identity.sign(message).ok(),
                )
                .ok()
        });
        let Some(accepted) = accepted else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("PRODUCTION_RELAY_RESERVATION_SERVICE_REJECTED");
        };
        let Some(relay) = decoded_signed_payload::<RelayReservation>(accepted.encoded()) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_RESPONSE_REJECTED");
        };
        let Some(client_endpoint) = relay_request.client_wireguard_endpoint else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_CLIENT_ENDPOINT_REJECTED");
        };
        let Some(exit_endpoint) = relay.exit_wireguard_endpoint.clone() else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_EXIT_ENDPOINT_REJECTED");
        };
        let (Ok(maximum_up_mbps), Ok(maximum_down_mbps)) = (
            u32::try_from(relay.maximum_up_mbps),
            u32::try_from(relay.maximum_down_mbps),
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_RATE_REJECTED");
        };
        let activation = ActivateLeaseBatch {
            route_context_id: route_context_id.to_vec(),
            context_handle: endpoint.context_handle().as_bytes().to_vec(),
            leases: vec![
                LeaseActivation {
                    lease_handle: endpoint.client_facing_handle().as_bytes().to_vec(),
                    path_id: accepted.path_id(),
                    role: WireguardRole::RelayClient as i32,
                    peer_public_key: client_endpoint.public_key.clone(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: client_endpoint.underlay_ip.clone(),
                        port: client_endpoint.listen_port,
                    }),
                    maximum_up_mbps,
                    maximum_down_mbps,
                    signed_relay_reservation: accepted.encoded().to_vec(),
                    signed_client_relay_request: accepted.signed_client_relay_request().to_vec(),
                },
                LeaseActivation {
                    lease_handle: endpoint.exit_facing_handle().as_bytes().to_vec(),
                    path_id: accepted.path_id(),
                    role: WireguardRole::RelayExit as i32,
                    peer_public_key: exit_endpoint.public_key.clone(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: exit_endpoint.underlay_ip,
                        port: exit_endpoint.listen_port,
                    }),
                    maximum_up_mbps,
                    maximum_down_mbps,
                    signed_relay_reservation: accepted.encoded().to_vec(),
                    signed_client_relay_request: Vec::new(),
                },
            ],
        };
        debug_assert!(
            !activation.leases[0].signed_client_relay_request.is_empty()
                && activation.leases[1].signed_client_relay_request.is_empty(),
            "only the RelayClient activation carries client-session authority"
        );
        if let Err(error) = self
            .helper
            .activate_lease_batch(&mut helper_owner, activation.clone())
            .await
        {
            tracing::warn!(
                error = %error,
                "production Relay helper activation rejected"
            );
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_HELPER_ACTIVATE_REJECTED");
        }
        let commit = commit_lease_batch(&activation);
        let response = DatapathRelayResponse::granted(
            request.request_id().to_vec(),
            DatapathRelayOperation::ReservePath,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            accepted.encoded().to_vec(),
        );
        let Ok(response) = response else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(accepted.reservation_id()).ok());
            reject!("PRODUCTION_RELAY_RESERVATION_FRAME_REJECTED");
        };
        self.prepared_production_relay_routes.insert(
            route_context_id,
            PreparedProductionRelayRoute {
                helper_owner,
                authenticated_client_peer,
                expires_at_ms: accepted.expires_at_ms(),
                accepted,
                commit: Some(commit),
                committed_start: None,
                committed_signal: None,
                usable: true,
                cleanup_not_before_ms: 0,
            },
        );
        let _ = self.service.send_datapath_relay_response(channel, response);
        log_relay_forward_admission(Some(state), "PRODUCTION_RELAY_RESERVATION_ACTIVATED");
    }

    /// Consume the exact prepared Relay route once, commit it, and forward the unchanged signed
    /// session proof to the selected Exit. No listener readiness is returned before both helper
    /// Commit and the authenticated Exit response have completed.
    #[allow(
        clippy::too_many_lines,
        reason = "one affine Relay Commit and Exit dispatch transaction"
    )]
    async fn begin_udp_session_start(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let mut cleanup: Option<([u8; FORWARD_ID_BYTES], PreparedProductionRelayRoute)> = None;
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Some((route_context_id, route)) = cleanup.take() {
                    self.retire_production_relay_route(route_context_id, route)
                        .await;
                }
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::UdpSessionStart,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let Some(datapath_request_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id())
        else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::UdpSessionStart,
                now_ms,
            )
            || authenticated_client_peer == local_peer
            || !self.roles.relay
            || self.relay_service.is_none()
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != local_peer.to_bytes()
        {
            reject!("UDP_SESSION_RELAY_SCOPE_REJECTED");
        }
        let Some(scope) = verified_udp_session_start_scope(request.client_signed_request(), now_ms)
        else {
            reject!("UDP_SESSION_RELAY_SCOPE_REJECTED");
        };
        let Ok(start) = decode_canonical::<UdpSessionStartRequest>(
            request.client_signed_request(),
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(route_context_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)
        else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&scope.exit.exit_peer_id) else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&scope.exit.exit_node_id) else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: datapath_request_id,
        };
        if let Some(outbound_id) = self.relay_forward_index.get(&key).copied() {
            if let Some(pending) = self.pending_relay_forwards.get_mut(&outbound_id) {
                if let Some(udp) = pending.udp_session.as_mut() {
                    if pending.operation == ExitForwardOperation::UdpSessionStart
                        && udp.canonical_start == request.client_signed_request()
                        && udp.channels.len() < MAX_COALESCED_WAITERS
                    {
                        udp.channels.push(channel);
                        return;
                    }
                }
            }
            reject!("UDP_SESSION_RELAY_RETRY_CONFLICT");
        }
        if let Some(existing) = self.prepared_production_relay_routes.get(&route_context_id) {
            if existing.usable
                && existing.authenticated_client_peer == authenticated_client_peer
                && existing.accepted.encoded() == start.signed_relay_reservation()
                && existing.accepted.path_id() == scope.relay.path_id
                && existing.expires_at_ms > now_ms
                && existing.committed_start.as_deref() == Some(request.client_signed_request())
            {
                if let Some(signal) = existing.committed_signal.clone() {
                    if let Ok(response) = DatapathRelayResponse::granted(
                        datapath_request_id.to_vec(),
                        DatapathRelayOperation::UdpSessionStart,
                        self.local_node_id.to_vec(),
                        local_peer.to_bytes(),
                        signal,
                    ) {
                        let _ = self.service.send_datapath_relay_response(channel, response);
                    }
                    return;
                }
            }
        }
        let Some(route) = self
            .prepared_production_relay_routes
            .remove(&route_context_id)
        else {
            reject!("UDP_SESSION_RELAY_OWNER_UNAVAILABLE");
        };
        cleanup = Some((route_context_id, route));
        let route = cleanup
            .as_ref()
            .map(|(_, route)| route)
            .expect("installed UDP Relay cleanup owner");
        if !route.usable
            || route.authenticated_client_peer != authenticated_client_peer
            || route.accepted.encoded() != start.signed_relay_reservation()
            || route.accepted.route_context_id() != &route_context_id
            || route.accepted.path_id() != scope.relay.path_id
            || route.accepted.reservation_id().as_slice() != scope.exit.reservation_id
            || route.accepted.exit_node_id().as_slice() != scope.exit.exit_node_id
            || route.expires_at_ms <= now_ms
            || route.commit.is_none()
            || route.committed_signal.is_some()
            || exit_peer == local_peer
        {
            reject!("UDP_SESSION_RELAY_OWNER_MISMATCH");
        }
        let Some(authorized_control) = self.local_relay_snapshot.clone() else {
            reject!("UDP_SESSION_RELAY_AUTHORITY_UNAVAILABLE");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            datapath_request_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::UdpSessionStart,
            request.client_signed_request().to_vec(),
        ) else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("UDP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            reject!("UDP_SESSION_RELAY_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            reject!("UDP_SESSION_RELAY_CAPACITY");
        }
        let route = cleanup
            .as_mut()
            .map(|(_, route)| route)
            .expect("installed UDP Relay cleanup owner");
        let commit = route
            .commit
            .take()
            .expect("validated prepared UDP Relay commit");
        if self
            .helper
            .commit_lease_batch(&mut route.helper_owner, commit)
            .await
            .is_err()
        {
            reject!("UDP_SESSION_RELAY_HELPER_COMMIT_REJECTED");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            reject!("UDP_SESSION_RELAY_TRANSPORT_UNAVAILABLE");
        };
        let (_, route) = cleanup.take().expect("committed UDP Relay owner");
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::UdpSessionStart,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control,
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: Some(PendingUdpSessionStart {
                    datapath_request_id,
                    route_context_id,
                    channels: vec![channel],
                    canonical_start: request.client_signed_request().to_vec(),
                    route,
                }),
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(Some(state), "UDP_SESSION_RELAY_DISPATCHED");
    }

    /// Commit this Relay's one exact helper route and forward the byte-identical complete MPTCP
    /// proof set to the signed Exit. Other selected Relay routes remain owned by their own actors.
    #[allow(
        clippy::too_many_lines,
        reason = "one affine per-Relay Commit and exact-set Exit dispatch transaction"
    )]
    async fn begin_mptcp_session_start(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let mut cleanup: Option<([u8; FORWARD_ID_BYTES], PreparedProductionRelayRoute)> = None;
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Some((route_context_id, route)) = cleanup.take() {
                    self.retire_production_relay_route(route_context_id, route)
                        .await;
                }
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::MptcpSessionStart,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let Some(datapath_request_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id())
        else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::MptcpSessionStart,
                now_ms,
            )
            || authenticated_client_peer == local_peer
            || !self.roles.relay
            || self.relay_service.is_none()
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != local_peer.to_bytes()
        {
            reject!("MPTCP_SESSION_RELAY_SCOPE_REJECTED");
        }
        let Some(scope) =
            verified_mptcp_session_start_scope(request.client_signed_request(), now_ms)
        else {
            reject!("MPTCP_SESSION_RELAY_SCOPE_REJECTED");
        };
        let Ok(start) = decode_canonical::<MptcpSessionStartRequest>(
            request.client_signed_request(),
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(route_context_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)
        else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&scope.exit.exit_peer_id) else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&scope.exit.exit_node_id) else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let local_matches = scope
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| {
                path.relay.relay_node_id == self.local_node_id
                    && path.relay.relay_peer_id == local_peer.to_bytes()
                    && datapath_request_id == path.confirmation_nonce[..FORWARD_ID_BYTES]
            })
            .collect::<Vec<_>>();
        let [(local_index, local_path)] = local_matches.as_slice() else {
            reject!("MPTCP_SESSION_RELAY_PATH_SET_REJECTED");
        };
        let Some(local_proof) = start.paths().get(*local_index) else {
            reject!("MPTCP_SESSION_RELAY_PATH_SET_REJECTED");
        };
        let selected_path_ids = scope
            .paths
            .iter()
            .map(|path| path.relay.path_id)
            .collect::<Vec<_>>();
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: datapath_request_id,
        };
        if let Some(outbound_id) = self.relay_forward_index.get(&key).copied() {
            if let Some(pending) = self.pending_relay_forwards.get_mut(&outbound_id) {
                if let Some(mptcp) = pending.mptcp_session.as_mut() {
                    if pending.operation == ExitForwardOperation::MptcpSessionStart
                        && mptcp.canonical_start == request.client_signed_request()
                        && mptcp.channels.len() < MAX_COALESCED_WAITERS
                    {
                        mptcp.channels.push(channel);
                        return;
                    }
                }
            }
            reject!("MPTCP_SESSION_RELAY_RETRY_CONFLICT");
        }
        if let Some(existing) = self.prepared_production_relay_routes.get(&route_context_id) {
            if existing.usable
                && existing.authenticated_client_peer == authenticated_client_peer
                && existing.accepted.encoded() == local_proof.signed_relay_reservation()
                && existing.accepted.path_id() == local_path.relay.path_id
                && existing.expires_at_ms > now_ms
                && existing.committed_start.as_deref() == Some(request.client_signed_request())
            {
                if let Some(signal) = existing.committed_signal.clone() {
                    if let Ok(response) = DatapathRelayResponse::granted(
                        datapath_request_id.to_vec(),
                        DatapathRelayOperation::MptcpSessionStart,
                        self.local_node_id.to_vec(),
                        local_peer.to_bytes(),
                        signal,
                    ) {
                        let _ = self.service.send_datapath_relay_response(channel, response);
                    }
                    return;
                }
            }
        }
        let Some(route) = self
            .prepared_production_relay_routes
            .remove(&route_context_id)
        else {
            reject!("MPTCP_SESSION_RELAY_OWNER_UNAVAILABLE");
        };
        cleanup = Some((route_context_id, route));
        let route = cleanup
            .as_ref()
            .map(|(_, route)| route)
            .expect("installed MPTCP Relay cleanup owner");
        if !route.usable
            || route.authenticated_client_peer != authenticated_client_peer
            || route.accepted.encoded() != local_proof.signed_relay_reservation()
            || route.accepted.route_context_id() != &route_context_id
            || route.accepted.path_id() != local_path.relay.path_id
            || route.accepted.reservation_id().as_slice() != scope.exit.reservation_id
            || route.accepted.exit_node_id().as_slice() != scope.exit.exit_node_id
            || route.expires_at_ms <= now_ms
            || route.commit.is_none()
            || route.committed_signal.is_some()
            || exit_peer == local_peer
        {
            reject!("MPTCP_SESSION_RELAY_OWNER_MISMATCH");
        }
        let Some(authorized_control) = self.local_relay_snapshot.clone() else {
            reject!("MPTCP_SESSION_RELAY_AUTHORITY_UNAVAILABLE");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            datapath_request_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::MptcpSessionStart,
            request.client_signed_request().to_vec(),
        ) else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("MPTCP_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            reject!("MPTCP_SESSION_RELAY_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            reject!("MPTCP_SESSION_RELAY_CAPACITY");
        }
        let route = cleanup
            .as_mut()
            .map(|(_, route)| route)
            .expect("installed MPTCP Relay cleanup owner");
        let commit = route
            .commit
            .take()
            .expect("validated prepared MPTCP Relay commit");
        if self
            .helper
            .commit_lease_batch(&mut route.helper_owner, commit)
            .await
            .is_err()
        {
            reject!("MPTCP_SESSION_RELAY_HELPER_COMMIT_REJECTED");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            reject!("MPTCP_SESSION_RELAY_TRANSPORT_UNAVAILABLE");
        };
        let (_, route) = cleanup.take().expect("committed MPTCP Relay owner");
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::MptcpSessionStart,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control,
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: Some(PendingMptcpSessionStart {
                    datapath_request_id,
                    route_context_id,
                    channels: vec![channel],
                    canonical_start: request.client_signed_request().to_vec(),
                    selected_path_ids,
                    route,
                }),
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(Some(state), "MPTCP_SESSION_RELAY_DISPATCHED");
    }

    /// Commit the carrying Relay route and forward the complete, byte-identical MPQUIC proof set
    /// to the signed Exit. The Relay never opens or learns the opaque native bearer.
    #[allow(
        clippy::too_many_lines,
        reason = "one affine Relay Commit and exact MPQUIC Exit dispatch transaction"
    )]
    async fn begin_mpquic_session_start(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let mut cleanup: Option<([u8; FORWARD_ID_BYTES], PreparedProductionRelayRoute)> = None;
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Some((route_context_id, route)) = cleanup.take() {
                    self.retire_production_relay_route(route_context_id, route)
                        .await;
                }
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::MpquicSessionStart,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let Some(datapath_request_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id())
        else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::MpquicSessionStart,
                now_ms,
            )
            || authenticated_client_peer == local_peer
            || !self.roles.relay
            || self.relay_service.is_none()
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != local_peer.to_bytes()
        {
            reject!("MPQUIC_SESSION_RELAY_SCOPE_REJECTED");
        }
        let Some(scope) =
            verified_mpquic_session_start_scope(request.client_signed_request(), now_ms)
        else {
            reject!("MPQUIC_SESSION_RELAY_SCOPE_REJECTED");
        };
        let Some(path) = scope.paths.into_iter().find(|path| {
            path.relay.relay_node_id == request.relay_node_id()
                && path.relay.relay_peer_id == request.relay_peer_id()
                && request.request_id() == &path.confirmation_nonce[..FORWARD_ID_BYTES]
        }) else {
            reject!("MPQUIC_SESSION_RELAY_PATH_SET_REJECTED");
        };
        let dispatch = VerifiedMpquicRelayDispatch {
            exit: scope.exit,
            relay: path.relay,
            signed_relay_reservation: path.signed_relay_reservation,
        };
        let Some(route_context_id) =
            fixed_bytes::<FORWARD_ID_BYTES>(&dispatch.exit.route_context_id)
        else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&dispatch.exit.exit_peer_id) else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&dispatch.exit.exit_node_id) else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: datapath_request_id,
        };
        if let Some(outbound_id) = self.relay_forward_index.get(&key).copied() {
            if let Some(pending) = self.pending_relay_forwards.get_mut(&outbound_id) {
                if let Some(mpquic) = pending.mpquic_session.as_mut() {
                    if pending.operation == ExitForwardOperation::MpquicSessionStart
                        && mpquic.canonical_start == request.client_signed_request()
                        && mpquic.channels.len() < MAX_COALESCED_WAITERS
                    {
                        mpquic.channels.push(channel);
                        return;
                    }
                }
            }
            reject!("MPQUIC_SESSION_RELAY_RETRY_CONFLICT");
        }
        if let Some(existing) = self.prepared_production_relay_routes.get(&route_context_id) {
            if existing.usable
                && existing.authenticated_client_peer == authenticated_client_peer
                && existing.accepted.encoded() == dispatch.signed_relay_reservation
                && existing.accepted.path_id() == dispatch.relay.path_id
                && existing.expires_at_ms > now_ms
                && existing.committed_start.as_deref() == Some(request.client_signed_request())
            {
                if let Some(signal) = existing.committed_signal.clone() {
                    if let Ok(response) = DatapathRelayResponse::granted(
                        datapath_request_id.to_vec(),
                        DatapathRelayOperation::MpquicSessionStart,
                        self.local_node_id.to_vec(),
                        local_peer.to_bytes(),
                        signal,
                    ) {
                        let _ = self.service.send_datapath_relay_response(channel, response);
                    }
                    return;
                }
            }
        }
        let Some(route) = self
            .prepared_production_relay_routes
            .remove(&route_context_id)
        else {
            reject!("MPQUIC_SESSION_RELAY_OWNER_UNAVAILABLE");
        };
        cleanup = Some((route_context_id, route));
        let route = cleanup
            .as_ref()
            .map(|(_, route)| route)
            .expect("installed MPQUIC Relay cleanup owner");
        if !route.usable
            || route.authenticated_client_peer != authenticated_client_peer
            || route.accepted.encoded() != dispatch.signed_relay_reservation
            || route.accepted.route_context_id() != &route_context_id
            || route.accepted.path_id() != dispatch.relay.path_id
            || route.accepted.reservation_id().as_slice() != dispatch.exit.reservation_id
            || route.accepted.exit_node_id().as_slice() != dispatch.exit.exit_node_id
            || route.expires_at_ms <= now_ms
            || route.commit.is_none()
            || route.committed_signal.is_some()
            || exit_peer == local_peer
        {
            reject!("MPQUIC_SESSION_RELAY_OWNER_MISMATCH");
        }
        let Some(authorized_control) = self.local_relay_snapshot.clone() else {
            reject!("MPQUIC_SESSION_RELAY_AUTHORITY_UNAVAILABLE");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            datapath_request_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::MpquicSessionStart,
            request.client_signed_request().to_vec(),
        ) else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("MPQUIC_SESSION_RELAY_FRAME_REJECTED");
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            reject!("MPQUIC_SESSION_RELAY_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            reject!("MPQUIC_SESSION_RELAY_CAPACITY");
        }
        let route = cleanup
            .as_mut()
            .map(|(_, route)| route)
            .expect("installed MPQUIC Relay cleanup owner");
        let commit = route
            .commit
            .take()
            .expect("validated prepared MPQUIC Relay commit");
        if self
            .helper
            .commit_lease_batch(&mut route.helper_owner, commit)
            .await
            .is_err()
        {
            reject!("MPQUIC_SESSION_RELAY_HELPER_COMMIT_REJECTED");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            reject!("MPQUIC_SESSION_RELAY_TRANSPORT_UNAVAILABLE");
        };
        let (_, route) = cleanup.take().expect("committed MPQUIC Relay owner");
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::MpquicSessionStart,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control,
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: Some(PendingMpquicSessionStart {
                    datapath_request_id,
                    route_context_id,
                    channels: vec![channel],
                    canonical_start: request.client_signed_request().to_vec(),
                    route,
                }),
            },
        );
        log_relay_forward_admission(Some(state), "MPQUIC_SESSION_RELAY_DISPATCHED");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one Relay helper Prepare and Exit-ready dispatch stay in one affine transaction"
    )]
    async fn begin_native_probe_ready(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::NativeProbeReady,
                    channel,
                );
                return;
            }};
        }
        let Some(probe_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id()) else {
            reject!("NATIVE_PROBE_READY_FRAME_REJECTED");
        };
        let local_peer = *self.service.local_peer_id();
        let now_ms = unix_millis();
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::NativeProbeReady,
                now_ms,
            )
            || !self.roles.relay
            || self.relay_service.is_none()
            || fixed_bytes::<32>(request.relay_node_id()) != Some(self.local_node_id)
            || Libp2pPeerId::from_bytes(request.relay_peer_id()).ok() != Some(local_peer)
            || authenticated_client_peer == local_peer
            || self.prepared_native_ready.contains_key(&probe_id)
        {
            reject!("NATIVE_PROBE_READY_SCOPE_REJECTED");
        }
        let Ok(permit) = verify_native_probe_permit(
            request.client_signed_request().to_vec(),
            request.exit_signed_authorization().to_vec(),
            now_ms,
            &mut self.replay,
        ) else {
            reject!("NATIVE_PROBE_READY_PERMIT_REJECTED");
        };
        let scope = permit.scope().clone();
        let Some(data_relay) = scope.data_relay.as_ref() else {
            reject!("NATIVE_PROBE_READY_SCOPE_REJECTED");
        };
        let Some(exit) = scope.exit.as_ref() else {
            reject!("NATIVE_PROBE_READY_SCOPE_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&exit.peer_id) else {
            reject!("NATIVE_PROBE_READY_SCOPE_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&exit.node_id) else {
            reject!("NATIVE_PROBE_READY_SCOPE_REJECTED");
        };
        if !self.local_relay_snapshot.as_ref().is_some_and(|current| {
            local_relay_policy_is_current(
                current,
                &scope,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                now_ms,
            )
        }) {
            reject!("NATIVE_PROBE_READY_RELAY_AUTHORITY_UNAVAILABLE");
        }
        let Some((authorized_control, signed_relay_advertisement)) =
            local_native_probe_data_relay_authority(
                &self.service,
                data_relay,
                &scope,
                local_peer,
                now_ms,
                scope.attempt_expires_at_ms,
            )
        else {
            reject!("NATIVE_PROBE_READY_RELAY_AUTHORITY_UNAVAILABLE");
        };
        if !self.permit_bound_exit_peer_is_eligible(authenticated_client_peer, exit_peer) {
            reject!("NATIVE_PROBE_READY_EXIT_UNAVAILABLE");
        }
        let Ok(exit_control_address) = Multiaddr::from_str(permit.exit_control_address()) else {
            reject!("NATIVE_PROBE_READY_EXIT_ADDRESS_REJECTED");
        };
        let Ok(exit_peerlink) = PeerLink::new(exit_peer, exit_control_address.clone()) else {
            reject!("NATIVE_PROBE_READY_EXIT_ADDRESS_REJECTED");
        };
        if exit_peerlink.dial_address() != exit_control_address
            || self
                .service
                .add_known_peer(exit_peer, &exit_control_address)
                .is_err()
            || self.service.dial_peerlink(&exit_peerlink).is_err()
        {
            reject!("NATIVE_PROBE_READY_EXIT_ADDRESS_REJECTED");
        }
        let Some(mut prepare) = native_service_prepare_request(
            &scope,
            ContextRole::Relay,
            &[WireguardRole::RelayClient, WireguardRole::RelayExit],
            now_ms,
        ) else {
            reject!("NATIVE_PROBE_READY_HELPER_SCOPE_REJECTED");
        };
        let Some(client_session_id) = fixed_bytes::<32>(&scope.client_session_id) else {
            reject!("NATIVE_PROBE_READY_TRAVERSAL_SCOPE_REJECTED");
        };
        prepare.traversal_hints = self
            .exact_endpoint_traversal_hints(vec![
                EndpointTraversalBinding {
                    path_id: scope.candidate_ordinal,
                    role: WireguardRole::RelayClient,
                    observer_id: client_session_id,
                    observer_peer_id: authenticated_client_peer,
                },
                EndpointTraversalBinding {
                    path_id: scope.candidate_ordinal,
                    role: WireguardRole::RelayExit,
                    observer_id: exit_node_id,
                    observer_peer_id: exit_peer,
                },
            ])
            .unwrap_or_default();
        let Ok(helper_owner) = self.helper.prepare_lease_batch(prepare.clone()).await else {
            reject!("NATIVE_PROBE_READY_HELPER_PREPARE_UNAVAILABLE");
        };
        let Ok(endpoint) =
            bind_prepared_relay_endpoint_lease(&prepare, helper_owner.prepared().clone())
        else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_HELPER_BIND_REJECTED");
        };
        let Some(relay_exit_endpoint) = native_endpoint_binding(
            helper_owner.helper_runtime_id(),
            endpoint.route_context_id(),
            endpoint.exit_facing_handle().as_bytes(),
            endpoint.path_id(),
            endpoint.exit_facing_endpoint(),
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_HELPER_BIND_REJECTED");
        };
        let Ok(forward) = NativeProbeReadyForwardRequest::new(
            request.client_signed_request().to_vec(),
            request.exit_signed_authorization().to_vec(),
            relay_exit_endpoint,
            signed_relay_advertisement,
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_FRAME_REJECTED");
        };
        let Ok(canonical_ready) = encode_canonical(
            &forward,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_FRAME_REJECTED");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            probe_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::NativeProbeReady,
            canonical_ready,
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: probe_id,
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_CAPACITY");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            reject!("NATIVE_PROBE_READY_TRANSPORT_UNAVAILABLE");
        };
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::NativeProbeReady,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control,
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: Some(PendingNativeProbeReady {
                    datapath_request_id: probe_id,
                    channel,
                    authenticated_client_peer,
                    permit,
                    endpoint,
                    helper_owner,
                }),
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(Some(state), "NATIVE_PROBE_READY_DISPATCHED");
    }

    async fn begin_native_probe_start_authorization(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let now_ms = unix_millis();
        let Some(probe_id) = native_start_probe_id(request.client_signed_request()) else {
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        };
        let Some(prepared) = self.prepared_native_ready.remove(&probe_id) else {
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        };
        if prepared.authenticated_client_peer != authenticated_client_peer {
            let _ = self.helper.destroy_context(&prepared.helper_owner).await;
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        }
        let Ok(start) = verify_native_probe_start_for_relay(
            prepared.ready,
            request.client_signed_request().to_vec(),
            now_ms,
            &mut self.replay,
        ) else {
            let _ = self.helper.destroy_context(&prepared.helper_owner).await;
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        };
        let Some(authorization_id) = native_start_authorization_id(start.encoded_start()) else {
            let _ = self.helper.destroy_context(&prepared.helper_owner).await;
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        };
        if request.request_id() != authorization_id
            || !self.retain_prepared_native_probe_authorization(
                authenticated_client_peer,
                prepared.authorized_relay,
                start,
                prepared.endpoint,
            )
        {
            let _ = self.helper.destroy_context(&prepared.helper_owner).await;
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                channel,
            );
            return;
        }
        self.prepared_native_authorization_helpers
            .insert(authorization_id, prepared.helper_owner);
        self.begin_native_probe_authorization(authenticated_client_peer, request, channel, state)
            .await;
    }

    fn send_native_datapath_unavailable(
        &mut self,
        request: &DatapathRelayRequest,
        operation: DatapathRelayOperation,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
    ) {
        if let Ok(response) = DatapathRelayResponse::unavailable(
            request.request_id().to_vec(),
            operation,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            let _ = self.service.send_datapath_relay_response(channel, response);
        }
    }

    /// Install the exact Ready-owned Start and Relay helper endpoint for one subsequent request.
    ///
    /// The preceding native Ready/Start phase calls this without serializing either affine owner.
    /// The authenticated client is retained so another connection cannot spend the preparation.
    fn retain_prepared_native_probe_authorization(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        authorized_relay: DirectRelayCapability,
        start: VerifiedNativeProbeStartForRelay,
        endpoint: RelayEndpointLease,
    ) -> bool {
        let Ok(envelope) = decode_canonical::<SignedEnvelope>(
            start.encoded_start(),
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        ) else {
            return false;
        };
        let Some(nonce) = fixed_bytes::<32>(&envelope.nonce) else {
            return false;
        };
        let request_id = native_probe_authorization_request_id(nonce);
        let scope = start.scope();
        let Some(data_relay) = scope.data_relay.as_ref() else {
            return false;
        };
        let local_peer = *self.service.local_peer_id();
        if authenticated_client_peer == local_peer
            || data_relay.node_id.as_slice() != self.local_node_id
            || data_relay.peer_id != local_peer.to_bytes()
            || data_relay.public_key.as_slice() != self.local_public_key
            || !native_probe_data_relay_capability_matches(
                &authorized_relay,
                data_relay,
                scope,
                local_peer,
                scope.attempt_expires_at_ms,
            )
            || endpoint.route_context_id().as_slice() != scope.attempt_id
            || endpoint.path_id() != scope.candidate_ordinal
            || self.prepared_native_authorizations.len() >= MAX_CONCURRENT_DATAPATH_RELAY_STREAMS
            || self
                .prepared_native_authorizations
                .contains_key(&request_id)
            || self
                .prepared_native_authorization_helpers
                .contains_key(&request_id)
        {
            return false;
        }
        self.prepared_native_authorizations.insert(
            request_id,
            PreparedNativeProbeAuthorization {
                authenticated_client_peer,
                authorized_relay,
                start,
                endpoint,
            },
        );
        true
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one affine Relay-to-Exit native authorization dispatch transaction"
    )]
    async fn begin_native_probe_authorization(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let mut cleanup_owner: Option<RuntimeBoundPreparedLeaseBatch> = None;
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Some(owner) = cleanup_owner.take() {
                    let _ = self.helper.destroy_context(&owner).await;
                }
                let request_id = request.request_id().to_vec();
                if let Ok(response) = DatapathRelayResponse::unavailable(
                    request_id,
                    DatapathRelayOperation::NativeProbeAuthorize,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    let _ = self.service.send_datapath_relay_response(channel, response);
                }
                return;
            }};
        }
        let Some(request_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id()) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_FRAME_REJECTED");
        };
        let local_peer = *self.service.local_peer_id();
        let now_ms = unix_millis();
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::NativeProbeAuthorize,
                now_ms,
            )
            || !self.roles.relay
            || self.relay_service.is_none()
            || fixed_bytes::<32>(request.relay_node_id()) != Some(self.local_node_id)
            || Libp2pPeerId::from_bytes(request.relay_peer_id()).ok() != Some(local_peer)
            || authenticated_client_peer == local_peer
        {
            reject!("NATIVE_PROBE_AUTHORIZATION_SCOPE_REJECTED");
        }
        let Some(prepared) = self.prepared_native_authorizations.remove(&request_id) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_OWNER_UNAVAILABLE");
        };
        let Some(helper_owner) = self
            .prepared_native_authorization_helpers
            .remove(&request_id)
        else {
            reject!("NATIVE_PROBE_AUTHORIZATION_OWNER_UNAVAILABLE");
        };
        cleanup_owner = Some(helper_owner);
        if prepared.authenticated_client_peer != authenticated_client_peer
            || prepared.start.encoded_start() != request.client_signed_request()
            || !native_rpc_deadline_is_within_authority(
                request.deadline_unix_ms(),
                prepared.start.scope().attempt_expires_at_ms,
            )
        {
            reject!("NATIVE_PROBE_AUTHORIZATION_OWNER_MISMATCH");
        }
        let scope = prepared.start.scope();
        let Some(data_relay) = scope.data_relay.as_ref() else {
            reject!("NATIVE_PROBE_AUTHORIZATION_SCOPE_REJECTED");
        };
        let Some(exit) = scope.exit.as_ref() else {
            reject!("NATIVE_PROBE_AUTHORIZATION_SCOPE_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&exit.peer_id) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_SCOPE_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&exit.node_id) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_SCOPE_REJECTED");
        };
        if !self.local_relay_snapshot.as_ref().is_some_and(|current| {
            local_relay_policy_is_current(
                current,
                scope,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                now_ms,
            )
        }) {
            reject!("NATIVE_PROBE_AUTHORIZATION_RELAY_AUTHORITY_UNAVAILABLE");
        }
        let authorized_control = prepared.authorized_relay.clone();
        if !self.permit_bound_exit_peer_is_eligible(authenticated_client_peer, exit_peer)
            || !native_probe_data_relay_capability_matches(
                &authorized_control,
                data_relay,
                scope,
                local_peer,
                scope.attempt_expires_at_ms,
            )
        {
            reject!("NATIVE_PROBE_AUTHORIZATION_EXIT_UNAVAILABLE");
        }
        let Ok(authorization_chain) = prepared.start.authorization_chain() else {
            reject!("NATIVE_PROBE_AUTHORIZATION_FRAME_REJECTED");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            request_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::NativeProbeAuthorize,
            authorization_chain,
        ) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: request_id,
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            reject!("NATIVE_PROBE_AUTHORIZATION_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            reject!("NATIVE_PROBE_AUTHORIZATION_CAPACITY");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            reject!("NATIVE_PROBE_AUTHORIZATION_TRANSPORT_UNAVAILABLE");
        };
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::NativeProbeAuthorize,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control,
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: Some(PendingNativeProbeAuthorization {
                    datapath_request_id: request_id,
                    channel,
                    start: prepared.start,
                    endpoint: prepared.endpoint,
                    helper_owner: cleanup_owner.take().expect("validated native helper owner"),
                }),
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(Some(state), "NATIVE_PROBE_AUTHORIZATION_DISPATCHED");
    }

    /// Commit the activated Relay pair and forward its exact Start chain for an Exit result.
    #[allow(
        clippy::too_many_lines,
        reason = "Relay Start verification, commit, forward and owner transfer are one transaction"
    )]
    async fn begin_native_probe_result(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_reservation_event(state, $code).await;
                self.send_native_datapath_unavailable(
                    request,
                    DatapathRelayOperation::NativeProbeStart,
                    channel,
                );
                return;
            }};
        }
        let now_ms = unix_millis();
        let Some(datapath_request_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.request_id())
        else {
            reject!("NATIVE_PROBE_RESULT_FRAME_REJECTED");
        };
        let Some(probe_id) = native_start_probe_id(request.client_signed_request()) else {
            reject!("NATIVE_PROBE_RESULT_FRAME_REJECTED");
        };
        let local_peer = *self.service.local_peer_id();
        if request.validate().is_err()
            || !datapath_request_scope_matches(
                request,
                DatapathRelayOperation::NativeProbeStart,
                now_ms,
            )
            || !self.roles.relay
            || fixed_bytes::<32>(request.relay_node_id()) != Some(self.local_node_id)
            || Libp2pPeerId::from_bytes(request.relay_peer_id()).ok() != Some(local_peer)
            || authenticated_client_peer == local_peer
        {
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        }
        let Some(start) = self
            .relay_service
            .as_mut()
            .and_then(|service| service.take_native_probe_start(&probe_id))
        else {
            reject!("NATIVE_PROBE_RESULT_OWNER_UNAVAILABLE");
        };
        let Some(attempt_id) = fixed_bytes::<FORWARD_ID_BYTES>(&start.scope().attempt_id) else {
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        };
        let Some(mut active) = self.active_native_relay_helpers.remove(&attempt_id) else {
            reject!("NATIVE_PROBE_RESULT_OWNER_UNAVAILABLE");
        };
        if active.authenticated_client_peer != authenticated_client_peer
            || start.encoded_start() != request.client_signed_request()
            || !native_rpc_deadline_is_within_authority(
                request.deadline_unix_ms(),
                start.scope().attempt_expires_at_ms,
            )
            || active.endpoint.route_context_id() != &attempt_id
            || active.endpoint.path_id() != start.scope().candidate_ordinal
        {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_OWNER_MISMATCH");
        }
        let commit = CommitLeaseBatch {
            route_context_id: attempt_id.to_vec(),
            context_handle: active.endpoint.context_handle().as_bytes().to_vec(),
            leases: vec![
                LeaseCommit {
                    lease_handle: active.endpoint.client_facing_handle().as_bytes().to_vec(),
                    path_id: active.endpoint.path_id(),
                    role: WireguardRole::RelayClient as i32,
                },
                LeaseCommit {
                    lease_handle: active.endpoint.exit_facing_handle().as_bytes().to_vec(),
                    path_id: active.endpoint.path_id(),
                    role: WireguardRole::RelayExit as i32,
                },
            ],
        };
        let Ok(committed) = self
            .helper
            .commit_lease_batch(&mut active.helper_owner, commit)
            .await
        else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_HELPER_COMMIT_REJECTED");
        };
        let scope = start.scope();
        let Some(data_relay) = scope.data_relay.as_ref() else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        };
        let Some(exit) = scope.exit.as_ref() else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&exit.peer_id) else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        };
        let Some(exit_node_id) = fixed_bytes::<32>(&exit.node_id) else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_SCOPE_REJECTED");
        };
        if !native_probe_data_relay_capability_matches(
            &active.authorized_relay,
            data_relay,
            scope,
            local_peer,
            scope.attempt_expires_at_ms,
        ) {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_RELAY_AUTHORITY_UNAVAILABLE");
        }
        let Ok(chain) = start.authorization_chain() else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_FRAME_REJECTED");
        };
        let Ok(upstream) = ExitForwardRequest::new(
            datapath_request_id.to_vec(),
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            self.local_public_key.to_vec(),
            exit_peer.to_bytes(),
            exit_node_id.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::NativeProbeResult,
            chain,
        ) else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_FRAME_REJECTED");
        };
        let Ok(canonical_request) = encode_canonical(
            &upstream,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id: datapath_request_id,
        };
        let Some(reserved_bytes) = ledger_reservation_bytes(canonical_request.len()) else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_CAPACITY");
        };
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self.relay_forward_index.contains_key(&key)
            || !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes)
        {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_CAPACITY");
        }
        let attempt_deadline =
            rpc_deadline(request.deadline_unix_ms(), EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream.into())
        else {
            let _ = self.helper.destroy_context(&active.helper_owner).await;
            reject!("NATIVE_PROBE_RESULT_TRANSPORT_UNAVAILABLE");
        };
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::NativeProbeResult,
                expected_exit_node_id: Some(exit_node_id),
                authorized_control: active.authorized_relay.clone(),
                authorized_exit: None,
                canonical_request,
                operation_expires_at_ms: request.deadline_unix_ms(),
                attempt_deadline,
                dispatch_attempts: 1,
                reserved_bytes,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: Some(PendingNativeProbeResult {
                    datapath_request_id,
                    channel,
                    start,
                    endpoint: active.endpoint,
                    committed,
                    helper_owner: active.helper_owner,
                }),
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(Some(state), "NATIVE_PROBE_RESULT_DISPATCHED");
    }

    fn begin_relay_forward_observed(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<ExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        self.begin_relay_forward_inner(authenticated_client_peer, request, channel, Some(state));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "single-owner relay admission transaction"
    )]
    fn begin_relay_forward_inner(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<ExitForwardResponse>,
        state: Option<&Arc<RwLock<AgentState>>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(state, $code);
                return;
            }};
        }
        self.purge_completed(Instant::now());
        let Some(forward_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.forward_id()) else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let Some(control_node) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let Ok(control_peer) = Libp2pPeerId::from_bytes(request.control_relay_peer_id()) else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(request.exit_peer_id()) else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let Ok(operation) = request.validated_operation() else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let expected_exit_node_id = optional_fixed_bytes::<32>(request.exit_node_id());
        let operation_expires_at_ms = request.deadline_unix_ms();
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let Some(authorized_control) = self.local_relay_snapshot.clone() else {
            reject!("EXIT_FORWARD_RELAY_LOCAL_ADVERTISEMENT_UNAVAILABLE");
        };
        let authorized_exit = expected_exit_node_id.and_then(|exit_node_id| {
            self.forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: local_peer,
                    exit_peer,
                })
                .filter(|capability| {
                    forwarded_exit_capability_matches(
                        capability,
                        &authorized_control,
                        self.local_node_id,
                        local_peer,
                        self.local_public_key,
                        exit_node_id,
                        exit_peer,
                        operation_expires_at_ms,
                    )
                })
                .cloned()
        });
        if request.validate().is_err()
            || !forward_request_scope_matches(request, operation, now_ms)
            || !self.roles.relay
            || self.relay_service.is_none()
            || control_node != self.local_node_id
            || control_peer != local_peer
            || request.control_relay_public_key() != self.local_public_key
            || !direct_relay_capability_matches(
                &authorized_control,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                operation_expires_at_ms,
            )
            || authenticated_client_peer == local_peer
            || exit_peer == local_peer
        {
            reject!("EXIT_FORWARD_RELAY_SCOPE_REJECTED");
        }
        if !self.exit_provider_peers.contains_key(&exit_peer)
            || !self.relay_forward_exit_peer_is_eligible(authenticated_client_peer, exit_peer)
        {
            reject!("EXIT_FORWARD_RELAY_PROVIDER_UNAVAILABLE");
        }
        if operation != ExitForwardOperation::FetchExitAdvertisement && authorized_exit.is_none() {
            reject!("EXIT_FORWARD_RELAY_EXIT_AUTHORITY_UNAVAILABLE");
        }
        let Ok(canonical_request) = encode_canonical(
            request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("EXIT_FORWARD_RELAY_FRAME_REJECTED");
        };
        let key = RelayForwardKey {
            authenticated_client_peer,
            forward_id,
        };
        if let Some(completed) = self.completed_relay_forwards.get(&key) {
            if completed.canonical_request == canonical_request && completed.operation == operation
            {
                if let Some(response) = completed.response.clone() {
                    let _ = self.service.send_exit_forward_response(channel, response);
                }
            }
            return;
        }
        if let Some(outbound_id) = self.relay_forward_index.get(&key).copied() {
            if let Some(pending) = self.pending_relay_forwards.get_mut(&outbound_id) {
                if pending.canonical_request == canonical_request
                    && pending.client_channels.len() < MAX_COALESCED_WAITERS
                {
                    pending.client_channels.push(channel);
                }
            }
            return;
        }
        let retry = self.retry_relay_forwards.get(&key);
        if retry.is_some_and(|entry| {
            entry.canonical_request != canonical_request || entry.target_peer != exit_peer
        }) {
            reject!("EXIT_FORWARD_RELAY_RETRY_CONFLICT");
        }
        let dispatch_attempts = retry.map_or(1, |entry| entry.dispatch_attempts.saturating_add(1));
        if dispatch_attempts > MAX_DISPATCH_ATTEMPTS {
            reject!("EXIT_FORWARD_RELAY_RETRY_EXHAUSTED");
        }
        let Some(upstream) =
            local_exit_forward_upstream_request(&self.service, request, local_peer, now_ms)
        else {
            reject!("EXIT_FORWARD_RELAY_CONTROL_AUTHORITY_UNAVAILABLE");
        };
        let upstream_size = canonical_request
            .len()
            .saturating_add(upstream.as_forward_request().control_advertisement().len());
        let Some(reserved_bytes) = retry
            .map(|entry| entry.reserved_bytes)
            .or_else(|| ledger_reservation_bytes(upstream_size))
        else {
            reject!("EXIT_FORWARD_RELAY_CAPACITY");
        };
        if retry.is_none() && !self.ledger_can_reserve(authenticated_client_peer, reserved_bytes) {
            reject!("EXIT_FORWARD_RELAY_CAPACITY");
        }
        if self.pending_relay_forwards.len() >= MAX_CONCURRENT_FORWARDING_STREAMS
            || self
                .pending_relay_forwards
                .values()
                .filter(|pending| {
                    pending.key.authenticated_client_peer == authenticated_client_peer
                        || pending.expected_exit_peer == exit_peer
                })
                .count()
                >= MAX_PENDING_PER_PEER
        {
            reject!("EXIT_FORWARD_RELAY_CAPACITY");
        }
        let attempt_deadline = rpc_deadline(operation_expires_at_ms, EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, upstream)
        else {
            reject!("EXIT_FORWARD_RELAY_TRANSPORT_UNAVAILABLE");
        };
        self.retry_relay_forwards.remove(&key);
        self.relay_forward_index.insert(key, outbound_id);
        self.pending_relay_forwards.insert(
            outbound_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation,
                expected_exit_node_id,
                authorized_control,
                authorized_exit,
                canonical_request,
                operation_expires_at_ms,
                attempt_deadline,
                dispatch_attempts,
                reserved_bytes,
                client_channels: vec![channel],
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        log_relay_forward_admission(state, "EXIT_FORWARD_RELAY_DISPATCHED");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one upstream response consumes forwarding and optional native authorization owners"
    )]
    async fn complete_relay_forward(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
        response: UpstreamExitForwardResponse,
        state: &Arc<RwLock<AgentState>>,
    ) -> OutboundEventOutcome {
        let response = response.into_forward_response();
        let Some(observed) = self.pending_relay_forwards.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if observed.expected_exit_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let Some(mut pending) = self.pending_relay_forwards.remove(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        self.relay_forward_index.remove(&pending.key);
        let now_ms = unix_millis();
        let valid_before_ingest = pending.attempt_deadline > Instant::now()
            && pending.operation_expires_at_ms > now_ms
            && self.relay_authority_is_current(&pending, now_ms)
            && exit_response_matches(
                &response,
                pending.key.forward_id,
                pending.operation,
                pending.expected_exit_peer,
                pending.expected_exit_node_id,
            );
        if !valid_before_ingest {
            if let Some(udp) = pending.udp_session.take() {
                self.finish_udp_session_unavailable(udp).await;
            } else if let Some(mptcp) = pending.mptcp_session.take() {
                self.finish_mptcp_session_unavailable(mptcp).await;
            } else if let Some(mpquic) = pending.mpquic_session.take() {
                self.finish_mpquic_session_unavailable(mpquic).await;
            } else {
                self.finish_relay_definitive(pending);
            }
            log_reservation_event(state, "EXIT_FORWARD_RELAY_RESPONSE_INVALID").await;
            return OutboundEventOutcome::InvalidResponse;
        }
        if let Some(mut udp) = pending.udp_session.take() {
            let signal = response
                .signed_responses()
                .first()
                .filter(|_| response.validated_status() == Ok(ForwardStatus::Granted))
                .and_then(|encoded| {
                    decode_canonical::<UdpExitSessionSignal>(
                        encoded,
                        usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
                    )
                    .ok()
                    .map(|signal| (encoded.clone(), signal))
                });
            let Some((encoded_signal, signal)) = signal else {
                self.finish_udp_session_unavailable(udp).await;
                return OutboundEventOutcome::InvalidResponse;
            };
            if signal.validate().is_err()
                || signal.reservation_id() != udp.route.accepted.reservation_id()
                || signal.route_context_id() != udp.route.accepted.route_context_id()
                || signal.path_id() != udp.route.accepted.path_id()
            {
                self.finish_udp_session_unavailable(udp).await;
                return OutboundEventOutcome::InvalidResponse;
            }
            let Ok(datapath_response) = DatapathRelayResponse::granted(
                udp.datapath_request_id.to_vec(),
                DatapathRelayOperation::UdpSessionStart,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                encoded_signal.clone(),
            ) else {
                self.finish_udp_session_unavailable(udp).await;
                return OutboundEventOutcome::Failed;
            };
            udp.route.committed_start = Some(udp.canonical_start.clone());
            udp.route.committed_signal = Some(encoded_signal);
            let route_context_id = udp.route_context_id;
            if self
                .prepared_production_relay_routes
                .contains_key(&route_context_id)
            {
                self.finish_udp_session_unavailable(udp).await;
                return OutboundEventOutcome::Failed;
            }
            self.prepared_production_relay_routes
                .insert(route_context_id, udp.route);
            for channel in udp.channels {
                if self
                    .service
                    .send_datapath_relay_response(channel, datapath_response.clone())
                    .is_err()
                {
                    if let Some(route) = self
                        .prepared_production_relay_routes
                        .remove(&route_context_id)
                    {
                        self.retire_production_relay_route(route_context_id, route)
                            .await;
                    }
                    return OutboundEventOutcome::Failed;
                }
            }
            log_reservation_event(state, "UDP_SESSION_RELAY_COMPLETED").await;
            return OutboundEventOutcome::Completed;
        }
        if let Some(mut mptcp) = pending.mptcp_session.take() {
            let signal = response
                .signed_responses()
                .first()
                .filter(|_| response.validated_status() == Ok(ForwardStatus::Granted))
                .and_then(|encoded| {
                    decode_canonical::<ExitMptcpSessionSignal>(
                        encoded,
                        usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
                    )
                    .ok()
                    .map(|signal| (encoded.clone(), signal))
                });
            let Some((encoded_signal, signal)) = signal else {
                self.finish_mptcp_session_unavailable(mptcp).await;
                return OutboundEventOutcome::InvalidResponse;
            };
            if signal.validate().is_err()
                || signal.reservation_id() != mptcp.route.accepted.reservation_id()
                || signal.route_context_id() != mptcp.route.accepted.route_context_id()
                || signal.selected_path_ids() != mptcp.selected_path_ids
                || !signal
                    .selected_path_ids()
                    .contains(&mptcp.route.accepted.path_id())
            {
                self.finish_mptcp_session_unavailable(mptcp).await;
                return OutboundEventOutcome::InvalidResponse;
            }
            let Ok(datapath_response) = DatapathRelayResponse::granted(
                mptcp.datapath_request_id.to_vec(),
                DatapathRelayOperation::MptcpSessionStart,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                encoded_signal.clone(),
            ) else {
                self.finish_mptcp_session_unavailable(mptcp).await;
                return OutboundEventOutcome::Failed;
            };
            mptcp.route.committed_start = Some(mptcp.canonical_start.clone());
            mptcp.route.committed_signal = Some(encoded_signal);
            let route_context_id = mptcp.route_context_id;
            if self
                .prepared_production_relay_routes
                .contains_key(&route_context_id)
            {
                self.finish_mptcp_session_unavailable(mptcp).await;
                return OutboundEventOutcome::Failed;
            }
            self.prepared_production_relay_routes
                .insert(route_context_id, mptcp.route);
            for channel in mptcp.channels {
                if self
                    .service
                    .send_datapath_relay_response(channel, datapath_response.clone())
                    .is_err()
                {
                    if let Some(route) = self
                        .prepared_production_relay_routes
                        .remove(&route_context_id)
                    {
                        self.retire_production_relay_route(route_context_id, route)
                            .await;
                    }
                    return OutboundEventOutcome::Failed;
                }
            }
            log_reservation_event(state, "MPTCP_SESSION_RELAY_COMPLETED").await;
            return OutboundEventOutcome::Completed;
        }
        if let Some(mut mpquic) = pending.mpquic_session.take() {
            let encoded_signal = response
                .signed_responses()
                .first()
                .filter(|_| response.validated_status() == Ok(ForwardStatus::Granted))
                .cloned();
            let Some(encoded_signal) = encoded_signal else {
                self.finish_mpquic_session_unavailable(mpquic).await;
                return OutboundEventOutcome::InvalidResponse;
            };
            if !mpquic_session_signal_matches(&mpquic, &encoded_signal, now_ms) {
                self.finish_mpquic_session_unavailable(mpquic).await;
                return OutboundEventOutcome::InvalidResponse;
            }
            let Ok(datapath_response) = DatapathRelayResponse::granted(
                mpquic.datapath_request_id.to_vec(),
                DatapathRelayOperation::MpquicSessionStart,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                encoded_signal.clone(),
            ) else {
                self.finish_mpquic_session_unavailable(mpquic).await;
                return OutboundEventOutcome::Failed;
            };
            mpquic.route.committed_start = Some(mpquic.canonical_start.clone());
            mpquic.route.committed_signal = Some(encoded_signal);
            let route_context_id = mpquic.route_context_id;
            if self
                .prepared_production_relay_routes
                .contains_key(&route_context_id)
            {
                self.finish_mpquic_session_unavailable(mpquic).await;
                return OutboundEventOutcome::Failed;
            }
            self.prepared_production_relay_routes
                .insert(route_context_id, mpquic.route);
            for channel in mpquic.channels {
                if self
                    .service
                    .send_datapath_relay_response(channel, datapath_response.clone())
                    .is_err()
                {
                    if let Some(route) = self
                        .prepared_production_relay_routes
                        .remove(&route_context_id)
                    {
                        self.retire_production_relay_route(route_context_id, route)
                            .await;
                    }
                    return OutboundEventOutcome::Failed;
                }
            }
            log_reservation_event(state, "MPQUIC_SESSION_RELAY_COMPLETED").await;
            return OutboundEventOutcome::Completed;
        }
        if let Some(native) = pending.native_ready.take() {
            if response.validated_status() != Ok(ForwardStatus::Granted) {
                pending.native_ready = Some(native);
                self.finish_relay_definitive(pending);
                return OutboundEventOutcome::Failed;
            }
            let Some(signed_exit_ready) = response.signed_responses().first() else {
                pending.native_ready = Some(native);
                self.finish_relay_definitive(pending);
                return OutboundEventOutcome::InvalidResponse;
            };
            let Ok(exit_ready) = verify_native_probe_exit_ready(
                native.permit,
                signed_exit_ready.clone(),
                now_ms,
                &mut self.replay,
            ) else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::InvalidResponse;
            };
            let relay_client_endpoint = native_endpoint_binding(
                native.helper_owner.helper_runtime_id(),
                native.endpoint.route_context_id(),
                native.endpoint.client_facing_handle().as_bytes(),
                native.endpoint.path_id(),
                native.endpoint.client_facing_endpoint(),
            );
            let relay_exit_endpoint = native_endpoint_binding(
                native.helper_owner.helper_runtime_id(),
                native.endpoint.route_context_id(),
                native.endpoint.exit_facing_handle().as_bytes(),
                native.endpoint.path_id(),
                native.endpoint.exit_facing_endpoint(),
            );
            let ready = match (relay_client_endpoint, relay_exit_endpoint) {
                (Some(relay_client), Some(relay_exit)) => {
                    let identity = &self.identity;
                    sign_native_probe_relay_ready_with(
                        exit_ready,
                        relay_client,
                        relay_exit,
                        self.local_public_key,
                        now_ms,
                        generate_nonce(),
                        |message| identity.sign(message).ok(),
                    )
                    .ok()
                }
                _ => None,
            };
            let Some(ready) = ready else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::Failed;
            };
            let response = DatapathRelayResponse::granted(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeReady,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                ready.encoded_relay_ready().to_vec(),
            );
            let Ok(response) = response else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::Failed;
            };
            let previous = self.prepared_native_ready.insert(
                native.datapath_request_id,
                PreparedNativeProbeReady {
                    authenticated_client_peer: native.authenticated_client_peer,
                    authorized_relay: pending.authorized_control.clone(),
                    ready,
                    endpoint: native.endpoint,
                    helper_owner: native.helper_owner,
                },
            );
            if let Some(previous) = previous {
                let inserted = self
                    .prepared_native_ready
                    .remove(&native.datapath_request_id)
                    .expect("inserted native Ready owner");
                self.destroy_helper_owner(inserted.helper_owner);
                self.destroy_helper_owner(previous.helper_owner);
                return OutboundEventOutcome::Failed;
            }
            if self
                .service
                .send_datapath_relay_response(native.channel, response)
                .is_err()
            {
                if let Some(prepared) = self
                    .prepared_native_ready
                    .remove(&native.datapath_request_id)
                {
                    self.destroy_helper_owner(prepared.helper_owner);
                }
                return OutboundEventOutcome::Failed;
            }
            log_reservation_event(state, "NATIVE_PROBE_READY_COMPLETED").await;
            return OutboundEventOutcome::Completed;
        }
        if let Some(mut native) = pending.native_authorization.take() {
            if response.validated_status() != Ok(ForwardStatus::Granted) {
                pending.native_authorization = Some(native);
                self.finish_relay_definitive(pending);
                return OutboundEventOutcome::Failed;
            }
            let Some(signed_exit_authorization) = response.signed_responses().first() else {
                pending.native_authorization = Some(native);
                self.finish_relay_definitive(pending);
                return OutboundEventOutcome::InvalidResponse;
            };
            let client_endpoint = native.start.client_endpoint().endpoint.clone();
            let exit_endpoint = native.start.exit_endpoint().endpoint.clone();
            let signed_start = native.start.encoded_start().to_vec();
            let identity = &self.identity;
            let endpoint = native.endpoint;
            let accepted = self.relay_service.as_mut().and_then(|service| {
                service
                    .accept_native_probe_start_with(
                        native.start,
                        signed_exit_authorization,
                        now_ms,
                        self.local_public_key,
                        move |path_id| (path_id == endpoint.path_id()).then_some(endpoint),
                        |message| identity.sign(message).ok(),
                    )
                    .ok()
            });
            let signed_relay_reservation = accepted.map(|accepted| accepted.encoded().to_vec());
            let relay_rates = signed_relay_reservation
                .as_deref()
                .and_then(decoded_signed_payload::<RelayReservation>)
                .and_then(|reservation| {
                    Some((
                        u32::try_from(reservation.maximum_up_mbps).ok()?,
                        u32::try_from(reservation.maximum_down_mbps).ok()?,
                    ))
                });
            let activation = match (
                signed_relay_reservation.as_ref(),
                client_endpoint,
                exit_endpoint,
                relay_rates,
            ) {
                (
                    Some(signed),
                    Some(client),
                    Some(exit),
                    Some((maximum_up_mbps, maximum_down_mbps)),
                ) => Some(ActivateLeaseBatch {
                    route_context_id: endpoint.route_context_id().to_vec(),
                    context_handle: endpoint.context_handle().as_bytes().to_vec(),
                    leases: vec![
                        LeaseActivation {
                            lease_handle: endpoint.client_facing_handle().as_bytes().to_vec(),
                            path_id: endpoint.path_id(),
                            role: WireguardRole::RelayClient as i32,
                            peer_public_key: client.public_key.clone(),
                            peer_endpoint: Some(PublicUdpEndpoint {
                                address: client.underlay_ip.clone(),
                                port: client.listen_port,
                            }),
                            maximum_up_mbps,
                            maximum_down_mbps,
                            signed_relay_reservation: signed.clone(),
                            signed_client_relay_request: signed_start.clone(),
                        },
                        LeaseActivation {
                            lease_handle: endpoint.exit_facing_handle().as_bytes().to_vec(),
                            path_id: endpoint.path_id(),
                            role: WireguardRole::RelayExit as i32,
                            peer_public_key: exit.public_key.clone(),
                            peer_endpoint: Some(PublicUdpEndpoint {
                                address: exit.underlay_ip,
                                port: exit.listen_port,
                            }),
                            maximum_up_mbps,
                            maximum_down_mbps,
                            signed_relay_reservation: signed.clone(),
                            signed_client_relay_request: Vec::new(),
                        },
                    ],
                }),
                _ => None,
            };
            let route_id = *endpoint.route_context_id();
            if let (Some(signed), Some(activation)) = (signed_relay_reservation, activation) {
                if self
                    .helper
                    .activate_lease_batch(&mut native.helper_owner, activation)
                    .await
                    .is_ok()
                {
                    let response = DatapathRelayResponse::granted(
                        native.datapath_request_id.to_vec(),
                        DatapathRelayOperation::NativeProbeAuthorize,
                        self.local_node_id.to_vec(),
                        self.service.local_peer_id().to_bytes(),
                        signed,
                    );
                    if let Ok(response) = response {
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            self.active_native_relay_helpers.entry(route_id)
                        {
                            entry.insert(ActiveNativeRelayProbe {
                                authenticated_client_peer: pending.key.authenticated_client_peer,
                                authorized_relay: pending.authorized_control.clone(),
                                endpoint,
                                helper_owner: native.helper_owner,
                            });
                            if self
                                .service
                                .send_datapath_relay_response(native.channel, response)
                                .is_err()
                            {
                                if let Some(owner) =
                                    self.active_native_relay_helpers.remove(&route_id)
                                {
                                    self.destroy_helper_owner(owner.helper_owner);
                                }
                                return OutboundEventOutcome::Failed;
                            }
                            log_reservation_event(state, "NATIVE_PROBE_AUTHORIZATION_COMPLETED")
                                .await;
                            return OutboundEventOutcome::Completed;
                        }
                    }
                }
            }
            self.destroy_helper_owner(native.helper_owner);
            if let Ok(response) = DatapathRelayResponse::unavailable(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeAuthorize,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ) {
                let _ = self
                    .service
                    .send_datapath_relay_response(native.channel, response);
            }
            return OutboundEventOutcome::Failed;
        }
        if let Some(native) = pending.native_result.take() {
            if response.validated_status() != Ok(ForwardStatus::Granted) {
                let _ = self.helper.destroy_context(&native.helper_owner).await;
                if let Ok(unavailable) = DatapathRelayResponse::unavailable(
                    native.datapath_request_id.to_vec(),
                    DatapathRelayOperation::NativeProbeStart,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    let _ = self
                        .service
                        .send_datapath_relay_response(native.channel, unavailable);
                }
                return OutboundEventOutcome::Failed;
            }
            let Some(signed_exit_result) = response.signed_responses().first().cloned() else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::InvalidResponse;
            };
            let native_scope = native.start.scope().clone();
            let native_reservation_id = fixed_bytes::<FORWARD_ID_BYTES>(&native_scope.probe_id);
            let native_started_at_ms = native.start.started_at_ms();
            let Ok(exit_result) = verify_native_probe_exit_result_for_relay(
                native.start,
                signed_exit_result,
                now_ms,
                &mut self.replay,
            ) else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::InvalidResponse;
            };
            let runtime_id = native.helper_owner.helper_runtime_id();
            let route_context_id = *native.endpoint.route_context_id();
            let relay_client_binding = native_endpoint_binding(
                runtime_id,
                &route_context_id,
                native.endpoint.client_facing_handle().as_bytes(),
                native.endpoint.path_id(),
                native.endpoint.client_facing_endpoint(),
            );
            let relay_exit_binding = native_endpoint_binding(
                runtime_id,
                &route_context_id,
                native.endpoint.exit_facing_handle().as_bytes(),
                native.endpoint.path_id(),
                native.endpoint.exit_facing_endpoint(),
            );
            let relay_client_committed = native.committed.leases.iter().find(|lease| {
                lease.lease_handle == native.endpoint.client_facing_handle().as_bytes()
            });
            let relay_exit_committed = native.committed.leases.iter().find(|lease| {
                lease.lease_handle == native.endpoint.exit_facing_handle().as_bytes()
            });
            let (
                Some(relay_client_binding),
                Some(relay_exit_binding),
                Some(relay_client),
                Some(relay_exit),
            ) = (
                relay_client_binding,
                relay_exit_binding,
                relay_client_committed,
                relay_exit_committed,
            )
            else {
                self.destroy_helper_owner(native.helper_owner);
                return OutboundEventOutcome::Failed;
            };
            let local_proofs = NativeProbeRelayLocalProofs {
                relay_client_lease: NativeProbeLeaseProof {
                    helper_runtime_id: runtime_id.to_vec(),
                    route_context_id: route_context_id.to_vec(),
                    prepared_lease_commitment: relay_client_binding
                        .prepared_lease_commitment
                        .clone(),
                    latest_handshake_unix: relay_client.latest_handshake_unix,
                    received_bytes_after_baseline: relay_client.received_bytes,
                    transmitted_bytes_after_baseline: relay_client.transmitted_bytes,
                },
                relay_exit_lease: NativeProbeLeaseProof {
                    helper_runtime_id: runtime_id.to_vec(),
                    route_context_id: route_context_id.to_vec(),
                    prepared_lease_commitment: relay_exit_binding.prepared_lease_commitment.clone(),
                    latest_handshake_unix: relay_exit.latest_handshake_unix,
                    received_bytes_after_baseline: relay_exit.received_bytes,
                    transmitted_bytes_after_baseline: relay_exit.transmitted_bytes,
                },
                forwarding: NativeProbeForwardingProof {
                    client_to_exit_packets_after_baseline: 1,
                    client_to_exit_bytes_after_baseline: NATIVE_PROBE_DATAGRAM_BYTES as u64,
                    exit_to_client_packets_after_baseline: 1,
                    exit_to_client_bytes_after_baseline: NATIVE_PROBE_DATAGRAM_BYTES as u64,
                    terminal_drop_packets_after_baseline: 0,
                    terminal_drop_bytes_after_baseline: 0,
                },
            };
            let evidence_measured_at_ms = unix_millis();
            let evidence_window_started_at_ms = native_started_at_ms
                .min(evidence_measured_at_ms.saturating_sub(1))
                .max(evidence_measured_at_ms.saturating_sub(10_000));
            let recent_evidence = native_probe_leg_evidence(
                relay_client.transmitted_bytes,
                relay_client.received_bytes,
                native_scope.reserved_up_mbps,
                native_scope.reserved_down_mbps,
                evidence_window_started_at_ms,
                evidence_measured_at_ms,
            )
            .zip(native_probe_leg_evidence(
                relay_exit.transmitted_bytes,
                relay_exit.received_bytes,
                native_scope.reserved_up_mbps,
                native_scope.reserved_down_mbps,
                evidence_window_started_at_ms,
                evidence_measured_at_ms,
            ))
            .and_then(|(client_relay, relay_exit)| {
                (native_scope.attempt_expires_at_ms > evidence_measured_at_ms).then_some(
                    RecentNativeRelayEvidence {
                        authenticated_client_peer: pending.key.authenticated_client_peer,
                        expires_at_ms: native_scope.attempt_expires_at_ms,
                        scope: native_scope,
                        client_relay,
                        relay_exit,
                    },
                )
            });
            let Ok(_destroyed) = self.helper.destroy_context(&native.helper_owner).await else {
                return OutboundEventOutcome::Failed;
            };
            // Capacity remains reserved until the exact probe helper owner is confirmed gone.
            // Release also removes cached acceptance while retaining authorization replay state.
            if native_reservation_id
                .and_then(|reservation_id| {
                    self.relay_service.as_mut()?.release(&reservation_id).ok()
                })
                .is_none()
            {
                return OutboundEventOutcome::Failed;
            }
            let identity = &self.identity;
            let Ok(result) = sign_native_probe_relay_result_with(
                exit_result,
                local_proofs,
                self.local_public_key,
                unix_millis(),
                generate_nonce(),
                |message| identity.sign(message).ok(),
            ) else {
                return OutboundEventOutcome::Failed;
            };
            let Ok(result_response) = DatapathRelayResponse::granted(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeStart,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                result.encoded_relay_result().to_vec(),
            ) else {
                return OutboundEventOutcome::Failed;
            };
            if self
                .service
                .send_datapath_relay_response(native.channel, result_response)
                .is_err()
            {
                return OutboundEventOutcome::Failed;
            }
            if let Some(evidence) = recent_evidence {
                self.recent_native_relay_evidence
                    .retain(|entry| entry.expires_at_ms > evidence_measured_at_ms);
                if self.recent_native_relay_evidence.len() >= MAX_RECENT_NATIVE_EVIDENCE {
                    self.recent_native_relay_evidence.remove(0);
                }
                self.recent_native_relay_evidence.push(evidence);
            }
            log_reservation_event(state, "NATIVE_PROBE_RESULT_COMPLETED").await;
            return OutboundEventOutcome::Completed;
        }
        let mut commit = None;
        if pending.operation == ExitForwardOperation::FetchExitAdvertisement
            && response.validated_status() == Ok(ForwardStatus::Granted)
        {
            let advertisement = response
                .signed_responses()
                .first()
                .cloned()
                .and_then(|encoded| AdvertisementResponse::new(encoded).ok());
            let exit_node_id = fixed_bytes::<32>(response.exit_node_id());
            let forwarded = match (advertisement, exit_node_id) {
                (Some(advertisement), Some(exit_node_id)) => {
                    let provenance = AdvertisementProvenance::ForwardedExit {
                        control_relay_node_id: self.local_node_id,
                        control_relay_peer: *self.service.local_peer_id(),
                        exit_node_id,
                        exit_peer: peer,
                        request_deadline_ms: pending.operation_expires_at_ms,
                        authority: Box::new(ForwardedIngestAuthority {
                            authorized_control: pending.authorized_control.clone(),
                            attempt_deadline: pending.attempt_deadline,
                            operation_expires_at_ms: pending.operation_expires_at_ms,
                        }),
                    };
                    let outcome = self
                        .stage_advertisement_commit(
                            PreparedAdvertisementCommit {
                                peer,
                                provenance,
                                envelope: advertisement.signed_envelope().to_vec(),
                            },
                            state,
                        )
                        .await;
                    let forwarded = outcome.status == AdvertisementCommitStatus::Committed;
                    commit = Some(outcome);
                    forwarded
                }
                _ => false,
            };
            if !forwarded {
                self.finish_relay_definitive(pending);
                if let Some(outcome) = commit.as_ref() {
                    self.finish_advertisement_commit(outcome, state).await;
                }
                return OutboundEventOutcome::InvalidResponse;
            }
        }
        self.cache_relay_result(&pending, Some(response.clone()));
        for channel in pending.client_channels {
            let _ = self
                .service
                .send_exit_forward_response(channel, response.clone());
        }
        if let Some(outcome) = commit.as_ref() {
            self.finish_advertisement_commit(outcome, state).await;
        }
        log_reservation_event(state, "EXIT_FORWARD_RELAY_COMPLETED").await;
        OutboundEventOutcome::Completed
    }

    fn relay_authority_is_current(&self, pending: &PendingRelayForward, now_ms: u64) -> bool {
        let control_current = self.local_relay_snapshot.as_ref().is_some_and(|current| {
            direct_relay_authority_lineage_matches(
                current,
                &pending.authorized_control,
                pending.operation_expires_at_ms,
            )
        });
        if !control_current
            || pending.operation_expires_at_ms <= now_ms
            || !self.relay_forward_exit_peer_is_eligible(
                pending.key.authenticated_client_peer,
                pending.expected_exit_peer,
            )
        {
            return false;
        }
        match &pending.authorized_exit {
            Some(expected) => self
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: pending.authorized_control.peer_id,
                    exit_peer: pending.expected_exit_peer,
                })
                .is_some_and(|current| {
                    current == expected && current.expires_at_ms >= pending.operation_expires_at_ms
                }),
            None => matches!(
                pending.operation,
                ExitForwardOperation::FetchExitAdvertisement
                    | ExitForwardOperation::NativeProbeReady
                    | ExitForwardOperation::NativeProbeAuthorize
                    | ExitForwardOperation::NativeProbeResult
                    | ExitForwardOperation::UdpSessionStart
                    | ExitForwardOperation::MptcpSessionStart
                    | ExitForwardOperation::MpquicSessionStart
            ),
        }
    }

    fn cache_relay_result(
        &mut self,
        pending: &PendingRelayForward,
        response: Option<ExitForwardResponse>,
    ) {
        let response_bytes = response.as_ref().map_or(0, |response| {
            encode_canonical(
                response,
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
            )
            .map_or(
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
                |encoded| encoded.len(),
            )
        });
        let reserved_bytes = completed_ledger_reservation_bytes(
            pending.canonical_request.len(),
            response_bytes,
            pending.reserved_bytes,
        );
        let previous = self.completed_relay_forwards.insert(
            pending.key,
            CompletedRelayForward {
                canonical_request: pending.canonical_request.clone(),
                target_peer: pending.expected_exit_peer,
                operation: pending.operation,
                response,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes,
            },
        );
        debug_assert!(previous.is_none(), "logical relay result already cached");
    }

    fn unavailable_for_pending_relay(pending: &PendingRelayForward) -> Option<ExitForwardResponse> {
        let exit_node_id = pending.expected_exit_node_id?;
        ExitForwardResponse::unavailable(
            pending.key.forward_id.to_vec(),
            pending.operation,
            exit_node_id.to_vec(),
            pending.expected_exit_peer.to_bytes(),
        )
        .ok()
    }

    async fn finish_udp_session_unavailable(&mut self, udp: PendingUdpSessionStart) {
        let PendingUdpSessionStart {
            datapath_request_id,
            route_context_id,
            channels,
            canonical_start: _,
            route,
        } = udp;
        self.retire_production_relay_route(route_context_id, route)
            .await;
        if let Ok(response) = DatapathRelayResponse::unavailable(
            datapath_request_id.to_vec(),
            DatapathRelayOperation::UdpSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            for channel in channels {
                let _ = self
                    .service
                    .send_datapath_relay_response(channel, response.clone());
            }
        }
    }

    async fn finish_mptcp_session_unavailable(&mut self, mptcp: PendingMptcpSessionStart) {
        let PendingMptcpSessionStart {
            datapath_request_id,
            route_context_id,
            channels,
            canonical_start: _,
            selected_path_ids: _,
            route,
        } = mptcp;
        self.retire_production_relay_route(route_context_id, route)
            .await;
        if let Ok(response) = DatapathRelayResponse::unavailable(
            datapath_request_id.to_vec(),
            DatapathRelayOperation::MptcpSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            for channel in channels {
                let _ = self
                    .service
                    .send_datapath_relay_response(channel, response.clone());
            }
        }
    }

    async fn finish_mpquic_session_unavailable(&mut self, mpquic: PendingMpquicSessionStart) {
        let PendingMpquicSessionStart {
            datapath_request_id,
            route_context_id,
            channels,
            canonical_start: _,
            route,
        } = mpquic;
        self.retire_production_relay_route(route_context_id, route)
            .await;
        if let Ok(response) = DatapathRelayResponse::unavailable(
            datapath_request_id.to_vec(),
            DatapathRelayOperation::MpquicSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            for channel in channels {
                let _ = self
                    .service
                    .send_datapath_relay_response(channel, response.clone());
            }
        }
    }

    /// Destroy before releasing the Relay reservation. A failed Destroy keeps the exact affine
    /// owner quarantined for the actor's bounded maintenance retry and never makes it reusable.
    async fn retire_production_relay_route(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        mut route: PreparedProductionRelayRoute,
    ) -> bool {
        route.usable = false;
        route.expires_at_ms = 0;
        if self
            .helper
            .destroy_context(&route.helper_owner)
            .await
            .is_ok()
        {
            let _ = self
                .relay_service
                .as_mut()
                .and_then(|service| service.release(route.accepted.reservation_id()).ok());
            true
        } else {
            route.cleanup_not_before_ms =
                unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
            let previous = self
                .prepared_production_relay_routes
                .insert(route_context_id, route);
            debug_assert!(previous.is_none(), "UDP Relay cleanup owner collision");
            false
        }
    }

    fn finish_relay_definitive(&mut self, mut pending: PendingRelayForward) {
        debug_assert!(
            pending.udp_session.is_none()
                && pending.mptcp_session.is_none()
                && pending.mpquic_session.is_none(),
            "session cleanup must use the awaited affine path"
        );
        if let Some(native) = pending.native_ready.take() {
            if let Ok(response) = DatapathRelayResponse::unavailable(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeReady,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ) {
                let _ = self
                    .service
                    .send_datapath_relay_response(native.channel, response);
            }
            self.destroy_helper_owner(native.helper_owner);
            return;
        }
        if let Some(native) = pending.native_authorization.take() {
            if let Ok(response) = DatapathRelayResponse::unavailable(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeAuthorize,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ) {
                let _ = self
                    .service
                    .send_datapath_relay_response(native.channel, response);
            }
            self.destroy_helper_owner(native.helper_owner);
            return;
        }
        if let Some(native) = pending.native_result.take() {
            if let Ok(response) = DatapathRelayResponse::unavailable(
                native.datapath_request_id.to_vec(),
                DatapathRelayOperation::NativeProbeStart,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ) {
                let _ = self
                    .service
                    .send_datapath_relay_response(native.channel, response);
            }
            self.destroy_helper_owner(native.helper_owner);
            return;
        }
        let response = Self::unavailable_for_pending_relay(&pending);
        self.cache_relay_result(&pending, response.clone());
        if let Some(response) = response {
            for channel in pending.client_channels {
                let _ = self
                    .service
                    .send_exit_forward_response(channel, response.clone());
            }
        }
    }

    fn finish_relay_ambiguity(&mut self, pending: PendingRelayForward) {
        if pending.native_ready.is_none()
            && pending.native_authorization.is_none()
            && pending.native_result.is_none()
            && pending.dispatch_attempts < MAX_DISPATCH_ATTEMPTS
            && pending.operation_expires_at_ms > unix_millis()
        {
            self.retry_relay_forwards.insert(
                pending.key,
                RetryLedgerEntry {
                    canonical_request: pending.canonical_request,
                    operation: Some(pending.operation),
                    dispatch_attempts: pending.dispatch_attempts,
                    expires_at_ms: pending.operation_expires_at_ms,
                    reserved_bytes: pending.reserved_bytes,
                    target_peer: pending.expected_exit_peer,
                },
            );
        } else {
            self.finish_relay_definitive(pending);
        }
    }

    async fn finish_relay_ambiguity_awaited(&mut self, mut pending: PendingRelayForward) {
        if let Some(udp) = pending.udp_session.take() {
            self.finish_udp_session_unavailable(udp).await;
        } else if let Some(mptcp) = pending.mptcp_session.take() {
            self.finish_mptcp_session_unavailable(mptcp).await;
        } else if let Some(mpquic) = pending.mpquic_session.take() {
            self.finish_mpquic_session_unavailable(mpquic).await;
        } else {
            self.finish_relay_ambiguity(pending);
        }
    }

    fn destroy_helper_owner(&self, owner: RuntimeBoundPreparedLeaseBatch) {
        let helper = self.helper.clone();
        tokio::spawn(async move {
            let _ = helper.destroy_context(&owner).await;
        });
    }

    async fn destroy_expired_exit_native_attempts(&mut self, now_ms: u64) -> usize {
        self.expire_pending_exit_native_ready(now_ms);
        let expired = self
            .exit_native_ready_attempts
            .iter()
            .filter_map(|(attempt_id, attempt)| {
                helper_cleanup_due(attempt.expires_at_ms, attempt.cleanup_not_before_ms, now_ms)
                    .then_some(*attempt_id)
            })
            .collect::<Vec<_>>();
        let mut destroyed = 0;
        for attempt_id in expired {
            let Some(mut attempt) = self.exit_native_ready_attempts.remove(&attempt_id) else {
                continue;
            };
            if self
                .helper
                .destroy_context(&attempt.helper_owner)
                .await
                .is_ok()
            {
                destroyed += 1;
            } else {
                attempt.cleanup_not_before_ms =
                    unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
                let previous = self.exit_native_ready_attempts.insert(attempt_id, attempt);
                debug_assert!(previous.is_none(), "expired Exit attempt was removed above");
            }
        }
        destroyed
    }

    async fn destroy_expired_production_relay_routes(&mut self, now_ms: u64) -> usize {
        let expired = self
            .prepared_production_relay_routes
            .iter()
            .filter_map(|(route_context_id, route)| {
                helper_cleanup_due(route.expires_at_ms, route.cleanup_not_before_ms, now_ms)
                    .then_some(*route_context_id)
            })
            .collect::<Vec<_>>();
        let mut destroyed = 0;
        for route_context_id in expired {
            let Some(mut route) = self
                .prepared_production_relay_routes
                .remove(&route_context_id)
            else {
                continue;
            };
            route.usable = false;
            if self
                .helper
                .destroy_context(&route.helper_owner)
                .await
                .is_ok()
            {
                let _ = self
                    .relay_service
                    .as_mut()
                    .and_then(|service| service.release(route.accepted.reservation_id()).ok());
                destroyed += 1;
            } else {
                route.cleanup_not_before_ms =
                    unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
                let previous = self
                    .prepared_production_relay_routes
                    .insert(route_context_id, route);
                debug_assert!(previous.is_none(), "expired Relay route was removed above");
            }
        }
        destroyed
    }

    async fn destroy_expired_production_exit_routes(&mut self, now_ms: u64) -> usize {
        let expired = self
            .prepared_production_exit_routes
            .iter()
            .filter_map(|(route_context_id, route)| {
                helper_cleanup_due(route.expires_at_ms, route.cleanup_not_before_ms, now_ms)
                    .then_some(*route_context_id)
            })
            .collect::<Vec<_>>();
        let mut destroyed = 0;
        for route_context_id in expired {
            let Some(mut route) = self
                .prepared_production_exit_routes
                .remove(&route_context_id)
            else {
                continue;
            };
            if self
                .helper
                .destroy_context(&route.helper_owner)
                .await
                .is_ok()
            {
                let _ = self
                    .exit_service
                    .as_mut()
                    .and_then(|service| service.release(route.bundle.reservation_id()).ok());
                destroyed += 1;
            } else {
                route.cleanup_not_before_ms =
                    unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
                let previous = self
                    .prepared_production_exit_routes
                    .insert(route_context_id, route);
                debug_assert!(previous.is_none(), "expired Exit route was removed above");
            }
        }
        destroyed
    }

    async fn expire_pending_mptcp_exit_sessions(&mut self, now_ms: u64) -> usize {
        let expired = self
            .pending_mptcp_exit_sessions
            .iter()
            .filter_map(|(route_context_id, pending)| {
                (pending.expires_at_ms <= now_ms).then_some(*route_context_id)
            })
            .collect::<Vec<_>>();
        let count = expired.len();
        for route_context_id in expired {
            let Some(pending) = self.pending_mptcp_exit_sessions.remove(&route_context_id) else {
                continue;
            };
            self.finish_mptcp_exit_session_unavailable(route_context_id, pending)
                .await;
        }
        count
    }

    async fn expire_pending_mpquic_exit_sessions(&mut self, now_ms: u64) -> usize {
        let expired = self
            .pending_mpquic_exit_sessions
            .iter()
            .filter_map(|(route_context_id, pending)| {
                (pending.expires_at_ms <= now_ms).then_some(*route_context_id)
            })
            .collect::<Vec<_>>();
        let count = expired.len();
        for route_context_id in expired {
            let Some(pending) = self.pending_mpquic_exit_sessions.remove(&route_context_id) else {
                continue;
            };
            self.finish_mpquic_exit_session_unavailable(route_context_id, pending)
                .await;
        }
        count
    }

    async fn destroy_expired_active_mptcp_exit_routes(&mut self, now_ms: u64) -> usize {
        let expired = self
            .active_production_mptcp_exit_routes
            .iter()
            .filter_map(|(route_context_id, route)| {
                (helper_cleanup_due(route.expires_at_ms, route.cleanup_not_before_ms, now_ms)
                    && !route.runtime_started)
                    .then_some(*route_context_id)
            })
            .collect::<Vec<_>>();
        let mut destroyed = 0;
        for route_context_id in expired {
            let Some(route) = self
                .active_production_mptcp_exit_routes
                .remove(&route_context_id)
            else {
                continue;
            };
            if self
                .retire_active_mptcp_exit_route(route_context_id, route)
                .await
            {
                destroyed += 1;
            }
        }
        destroyed
    }

    async fn fail_relay_forward(
        &mut self,
        request_id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
    ) -> OutboundEventOutcome {
        let Some(pending) = self.pending_relay_forwards.get(&request_id) else {
            return OutboundEventOutcome::Unexpected;
        };
        if pending.expected_exit_peer != peer {
            return OutboundEventOutcome::PeerMismatch;
        }
        let pending = self
            .pending_relay_forwards
            .remove(&request_id)
            .expect("present");
        self.relay_forward_index.remove(&pending.key);
        Box::pin(self.finish_relay_ambiguity_awaited(pending)).await;
        OutboundEventOutcome::Failed
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one Exit admission path validates every forwarded operation and response"
    )]
    async fn answer_exit_forward_upstream(
        &mut self,
        authenticated_control_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: UpstreamExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                return;
            }};
        }
        let request = request.into_forward_request();
        let Ok(operation) = request.validated_operation() else {
            reject!("EXIT_FORWARD_EXIT_FRAME_REJECTED");
        };
        if operation == ExitForwardOperation::NativeProbeReady {
            self.answer_native_probe_ready_upstream(
                authenticated_control_relay,
                connection_id,
                &request,
                channel,
                state,
            )
            .await;
            return;
        }
        if operation == ExitForwardOperation::NativeProbeAuthorize {
            if let Some((connection, authenticated_data_relay, response)) = self
                .prepare_native_probe_authorization_response(
                    authenticated_control_relay,
                    connection_id,
                    &request,
                )
                .await
            {
                self.send_prepared_native_probe_authorization_response(
                    PreparedNativeProbeAuthorizationResponse {
                        connection,
                        authenticated_data_relay,
                        channel,
                        response,
                    },
                );
                log_relay_forward_admission(
                    Some(state),
                    "NATIVE_PROBE_AUTHORIZATION_EXIT_RESPONDED",
                );
            } else {
                let response = ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::NativeProbeAuthorize,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                );
                if let Ok(response) = response {
                    let _ = self
                        .service
                        .send_exit_forward_upstream_response(channel, response.into());
                }
                log_relay_forward_admission(
                    Some(state),
                    "NATIVE_PROBE_AUTHORIZATION_EXIT_REJECTED",
                );
            }
            return;
        }
        if operation == ExitForwardOperation::NativeProbeResult {
            self.answer_native_probe_result_upstream(
                authenticated_control_relay,
                connection_id,
                &request,
                channel,
                state,
            )
            .await;
            return;
        }
        if operation == ExitForwardOperation::NativeProbePermit {
            if let Some((connection, authenticated_control_relay, response)) = self
                .prepare_native_probe_permit_response(
                    authenticated_control_relay,
                    connection_id,
                    &request,
                )
            {
                self.send_prepared_native_probe_permit_response(
                    PreparedNativeProbePermitResponse {
                        connection,
                        authenticated_control_relay,
                        channel,
                        response,
                    },
                );
                log_relay_forward_admission(Some(state), "NATIVE_PROBE_PERMIT_EXIT_RESPONDED");
            } else {
                let response = ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::NativeProbePermit,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                );
                if let Ok(response) = response {
                    let _ = self
                        .service
                        .send_exit_forward_upstream_response(channel, response.into());
                }
                log_relay_forward_admission(Some(state), "NATIVE_PROBE_PERMIT_EXIT_REJECTED");
            }
            return;
        }
        let Some(control_relay_node_id) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            reject!("EXIT_FORWARD_EXIT_FRAME_REJECTED");
        };
        let Some(control_relay_public_key) = fixed_bytes::<32>(request.control_relay_public_key())
        else {
            reject!("EXIT_FORWARD_EXIT_FRAME_REJECTED");
        };
        let Ok(control_relay_peer) = Libp2pPeerId::from_bytes(request.control_relay_peer_id())
        else {
            reject!("EXIT_FORWARD_EXIT_FRAME_REJECTED");
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(request.exit_peer_id()) else {
            reject!("EXIT_FORWARD_EXIT_FRAME_REJECTED");
        };
        let local_peer = *self.service.local_peer_id();
        let now_ms = unix_millis();
        let valid_exit_target = operation == ExitForwardOperation::FetchExitAdvertisement
            || fixed_bytes::<32>(request.exit_node_id()) == Some(self.local_node_id);
        let valid_control_relay = matches!(
            operation,
            ExitForwardOperation::FetchExitAdvertisement
                | ExitForwardOperation::UdpSessionStart
                | ExitForwardOperation::MptcpSessionStart
                | ExitForwardOperation::MpquicSessionStart
        ) || self
            .exit_control_relays
            .get(&authenticated_control_relay)
            .or_else(|| self.direct_relays.get(&authenticated_control_relay))
            .is_some_and(|capability| {
                direct_relay_capability_matches(
                    capability,
                    control_relay_node_id,
                    authenticated_control_relay,
                    control_relay_public_key,
                    request.deadline_unix_ms(),
                )
            });
        if request.validate().is_err()
            || !forward_request_scope_matches(&request, operation, now_ms)
            || !self.roles.exit
            || self.exit_service.is_none()
            || control_relay_peer != authenticated_control_relay
            || !valid_control_relay
            || exit_peer != local_peer
            || exit_peer == authenticated_control_relay
            || !valid_exit_target
        {
            reject!("EXIT_FORWARD_EXIT_SCOPE_REJECTED");
        }
        if operation == ExitForwardOperation::MptcpSessionStart {
            self.begin_production_mptcp_exit_session(
                authenticated_control_relay,
                &request,
                channel,
                state,
            )
            .await;
            return;
        }
        if operation == ExitForwardOperation::MpquicSessionStart {
            self.begin_production_mpquic_exit_session(
                authenticated_control_relay,
                &request,
                channel,
                state,
            )
            .await;
            return;
        }
        let local_peer_bytes = local_peer.to_bytes();
        let responses = match operation {
            ExitForwardOperation::FetchExitAdvertisement => self
                .served_local_advertisement
                .as_ref()
                .filter(|advertisement| {
                    decode_canonical::<SignedEnvelope>(
                        advertisement,
                        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
                    )
                    .is_ok_and(|envelope| envelope.expires_at_ms > now_ms)
                })
                .cloned()
                .map(|advertisement| vec![advertisement]),
            ExitForwardOperation::CapacityHold => {
                let identity = &self.identity;
                self.exit_service
                    .as_mut()
                    .and_then(|service| {
                        service
                            .hold_capacity_with(
                                request.canonical_request(),
                                &control_relay_node_id,
                                &authenticated_control_relay.to_bytes(),
                                now_ms,
                                self.local_public_key,
                                |message| identity.sign(message).ok(),
                            )
                            .ok()
                    })
                    .map(|accepted| {
                        vec![
                            accepted.signed_capability().to_vec(),
                            accepted.signed_hold().to_vec(),
                        ]
                    })
            }
            ExitForwardOperation::ProbePermit => {
                let identity = &self.identity;
                self.exit_service
                    .as_mut()
                    .and_then(|service| {
                        service
                            .issue_probe_permit_with(
                                request.canonical_request(),
                                &control_relay_node_id,
                                &authenticated_control_relay.to_bytes(),
                                now_ms,
                                self.local_public_key,
                                |message| identity.sign(message).ok(),
                            )
                            .ok()
                    })
                    .map(|accepted| vec![accepted.encoded().to_vec()])
            }
            ExitForwardOperation::ConfirmRelay => {
                let identity = &self.identity;
                let accepted = self.exit_service.as_mut().and_then(|service| {
                    service
                        .confirm_relay_with(
                            request.canonical_request(),
                            &control_relay_node_id,
                            &authenticated_control_relay.to_bytes(),
                            now_ms,
                            self.local_public_key,
                            |message| identity.sign(message).ok(),
                        )
                        .ok()
                });
                if let Some(accepted) = accepted.as_ref() {
                    self.activate_confirmed_production_exit_path(
                        request.canonical_request(),
                        accepted,
                    )
                    .await;
                }
                accepted.map(|accepted| vec![accepted.signed_receipt().to_vec()])
            }
            ExitForwardOperation::FinalizeReservation => {
                self.recent_native_exit_evidence
                    .retain(|evidence| evidence.expires_at_ms > now_ms);
                let verifier =
                    ExactNativeExitEvidenceVerifier::new(&self.recent_native_exit_evidence, now_ms);
                let response = self
                    .finalize_production_exit_route(
                        &request,
                        control_relay_node_id,
                        authenticated_control_relay,
                        now_ms,
                        &verifier,
                    )
                    .await;
                if response.is_some() {
                    let consumed = verifier.consumed();
                    self.recent_native_exit_evidence
                        .retain(|evidence| !consumed.contains(&evidence.evidence_id));
                }
                response
            }
            ExitForwardOperation::UdpSessionStart => self
                .start_production_udp_exit_session(request.canonical_request(), now_ms, state)
                .await
                .map(|signal| vec![signal]),
            ExitForwardOperation::NativeProbePermit
            | ExitForwardOperation::NativeProbeAuthorize
            | ExitForwardOperation::NativeProbeReady
            | ExitForwardOperation::NativeProbeResult
            | ExitForwardOperation::MptcpSessionStart
            | ExitForwardOperation::MpquicSessionStart
            | ExitForwardOperation::Unspecified => None,
        };
        let response = responses
            .and_then(|responses| {
                ExitForwardResponse::granted(
                    request.forward_id().to_vec(),
                    operation,
                    self.local_node_id.to_vec(),
                    local_peer_bytes.clone(),
                    responses,
                )
                .ok()
            })
            .or_else(|| {
                ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    operation,
                    self.local_node_id.to_vec(),
                    local_peer_bytes,
                )
                .ok()
            });
        if let Some(response) = response {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
            log_relay_forward_admission(Some(state), "EXIT_FORWARD_EXIT_RESPONDED");
        } else {
            log_relay_forward_admission(Some(state), "EXIT_FORWARD_EXIT_RESPONSE_UNAVAILABLE");
        }
    }

    /// Prepare truthful Exit helper endpoints, finalize through one exact evidence verifier and
    /// retain every affine owner needed by confirmation and a transport-specific session Start.
    ///
    /// The current caller supplies a fail-closed verifier. The native-evidence bridge replaces
    /// only that argument with its short-lived exact ticket; this transaction never accepts
    /// structural probe fields on their own.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one fail-atomic Exit helper Prepare and signed finalization transaction"
    )]
    async fn finalize_production_exit_route<V>(
        &mut self,
        request: &ExitForwardRequest,
        authenticated_control_relay_node_id: [u8; 32],
        authenticated_control_relay: Libp2pPeerId,
        now_ms: u64,
        evidence_verifier: &V,
    ) -> Option<Vec<Vec<u8>>>
    where
        V: ProbeEvidenceVerifier + ?Sized,
    {
        let finalize =
            decoded_signed_payload::<ExitReservationFinalizeRequest>(request.canonical_request())?;
        let route_context_id = fixed_bytes::<FORWARD_ID_BYTES>(&finalize.route_context_id)?;
        let capability =
            decoded_signed_payload::<ClientSessionCapability>(&finalize.client_session_capability)?;

        // Kernel MPTCP owns a fresh per-route incarnation. Both userspace native QUIC modes must
        // instead sign the real process instance observed during preflight.
        let native_mpquic = match capability.allowed_transports.as_slice() {
            [transport] if *transport == Transport::TcpMptcp as i32 => false,
            [transport]
                if *transport == Transport::UdpSinglePath as i32
                    || *transport == Transport::MultipathQuic as i32 =>
            {
                true
            }
            _ => return None,
        };
        if let Some(existing) = self.prepared_production_exit_routes.get(&route_context_id) {
            return (existing.canonical_finalize_request == request.canonical_request()
                && existing.expires_at_ms > now_ms)
                .then(|| exit_finalize_response(&existing.bundle));
        }
        if self.prepared_production_exit_routes.len() >= MAX_CONCURRENT_FORWARDING_STREAMS {
            return None;
        }
        let mpquic_preflight = if native_mpquic {
            Some(
                ProductionMpquicExitPreflight::new(
                    NativeClient::new(self.mpquic_socket.clone()).ok()?,
                )
                .await
                .ok()?,
            )
        } else {
            None
        };
        let mut prepare = production_exit_prepare_request(
            &finalize,
            request.deadline_unix_ms(),
            capability.expires_at_ms,
        )?;
        let traversal_bindings = finalize
            .relay_paths
            .iter()
            .map(|path| {
                Some(EndpointTraversalBinding {
                    path_id: path.path_id,
                    role: WireguardRole::Exit,
                    observer_id: fixed_bytes::<32>(&path.relay_node_id)?,
                    observer_peer_id: Libp2pPeerId::from_bytes(&path.relay_peer_id).ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        prepare.traversal_hints = self
            .exact_endpoint_traversal_hints(traversal_bindings)
            .unwrap_or_default();
        let helper_owner = self
            .helper
            .prepare_lease_batch(prepare.clone())
            .await
            .ok()?;
        let Ok(exit_batch) =
            bind_prepared_exit_endpoint_leases(&prepare, helper_owner.prepared().clone())
        else {
            let _ = self.helper.destroy_context(&helper_owner).await;
            return None;
        };
        let exit_leases = exit_batch.exit_leases().to_vec();
        let exit_native_instance_id = mpquic_preflight
            .as_ref()
            .map_or_else(fresh_exit_route_runtime_instance_id, |preflight| {
                Some(*preflight.native_instance_id())
            })?;
        let mut identity_provider = ProductionExitNativeRouteIdentityProvider;
        let identity = &self.identity;
        let finalized = self
            .exit_service
            .as_mut()?
            .finalize_reservation_with_providers(
                request.canonical_request(),
                &authenticated_control_relay_node_id,
                &authenticated_control_relay.to_bytes(),
                now_ms,
                self.local_public_key,
                evidence_verifier,
                &mut identity_provider,
                exit_native_instance_id,
                |path_id| {
                    exit_leases
                        .iter()
                        .find(|lease| lease.path_id() == path_id)
                        .copied()
                },
                |message| identity.sign(message).ok(),
            );
        let bundle = match finalized {
            Ok(bundle) => bundle,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    retained_native_evidence = self.recent_native_exit_evidence.len(),
                    finalized_paths = finalize.relay_paths.len(),
                    "production Exit finalization rejected"
                );
                let _ = self.helper.destroy_context(&helper_owner).await;
                return None;
            }
        };
        if bundle.accepted().route_context_id() != &route_context_id
            || bundle.accepted().expires_at_ms() <= now_ms
            || bundle.accepted().maximum_paths()
                != u32::try_from(exit_leases.len()).unwrap_or(u32::MAX)
        {
            let _ = self.helper.destroy_context(&helper_owner).await;
            let _ = self
                .exit_service
                .as_mut()
                .and_then(|service| service.release(bundle.reservation_id()).ok());
            return None;
        }
        let response = exit_finalize_response(&bundle);
        let previous = self.prepared_production_exit_routes.insert(
            route_context_id,
            PreparedProductionExitRoute {
                canonical_finalize_request: request.canonical_request().to_vec(),
                expires_at_ms: bundle.accepted().expires_at_ms(),
                bundle,
                helper_owner,
                exit_leases,
                pending_activations: HashMap::new(),
                commit: None,
                mpquic_preflight,
                cleanup_not_before_ms: 0,
            },
        );
        debug_assert!(previous.is_none(), "production Exit route checked vacant");
        Some(response)
    }

    /// Add one service-authenticated Relay endpoint to the prepared Exit helper route. The exact
    /// set activates atomically once every finalized path has confirmed. Activation failures keep
    /// the affine owner and deterministic request so an idempotent confirmation retry can resume.
    async fn activate_confirmed_production_exit_path(
        &mut self,
        encoded_confirmation: &[u8],
        confirmation: &AcceptedExitConfirmation,
    ) {
        let Some(message) =
            decoded_signed_payload::<ExitReservationConfirmation>(encoded_confirmation)
        else {
            return;
        };
        let Some(route_context_id) = fixed_bytes::<FORWARD_ID_BYTES>(&message.route_context_id)
        else {
            return;
        };
        let Some(route) = self
            .prepared_production_exit_routes
            .get_mut(&route_context_id)
        else {
            return;
        };
        if confirmation.confirmed_path().reservation_id() != route.bundle.reservation_id()
            || confirmation.expires_at_ms() <= unix_millis()
            || route.commit.is_some()
        {
            return;
        }
        let path_id = confirmation.confirmed_path().path_id();
        let Some(exit_lease) = route
            .exit_leases
            .iter()
            .find(|lease| lease.path_id() == path_id)
        else {
            return;
        };
        if exit_lease.public_endpoint().public_key()
            != confirmation.confirmed_path().exit_public_key()
        {
            return;
        }
        let relay_endpoint = confirmation.confirmed_path().relay_exit_endpoint();
        let activation = LeaseActivation {
            lease_handle: exit_lease.lease_handle().as_bytes().to_vec(),
            path_id,
            role: WireguardRole::Exit as i32,
            peer_public_key: relay_endpoint.public_key().as_bytes().to_vec(),
            peer_endpoint: Some(public_udp_endpoint(relay_endpoint)),
            maximum_up_mbps: 0,
            maximum_down_mbps: 0,
            signed_relay_reservation: confirmation.signed_relay_reservation().to_vec(),
            signed_client_relay_request: Vec::new(),
        };
        match route.pending_activations.entry(path_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(activation);
            }
            std::collections::hash_map::Entry::Occupied(entry) if entry.get() == &activation => {}
            std::collections::hash_map::Entry::Occupied(_) => return,
        }
        if route.pending_activations.len() != route.exit_leases.len() {
            return;
        }
        let mut leases = route
            .pending_activations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        leases.sort_unstable_by_key(|lease| lease.path_id);
        let activation = ActivateLeaseBatch {
            route_context_id: route_context_id.to_vec(),
            context_handle: route.helper_owner.prepared().context_handle.clone(),
            leases,
        };
        if self
            .helper
            .activate_lease_batch(&mut route.helper_owner, activation.clone())
            .await
            .is_ok()
        {
            route.commit = Some(commit_lease_batch(&activation));
        }
    }

    /// Commit the exact confirmed Exit helper route, adopt its socket and return readiness only
    /// after a real Quinn listener owns it.
    #[allow(
        clippy::too_many_lines,
        reason = "native and DNS-only UDP activation retain affine cleanup in one transaction"
    )]
    async fn start_production_udp_exit_session(
        &mut self,
        encoded_start: &[u8],
        now_ms: u64,
        state: &Arc<RwLock<AgentState>>,
    ) -> Option<Vec<u8>> {
        let scope = verified_udp_session_start_scope(encoded_start, now_ms)?;
        let start = decode_canonical::<UdpSessionStartRequest>(
            encoded_start,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
        )
        .ok()?;
        let route_context_id = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)?;
        let signed_policy_hash = fixed_bytes::<32>(&scope.exit.policy_hash)?;
        let policy = state.read().await.active_policy(now_ms)?;
        if policy.policy_hash() != &signed_policy_hash {
            return None;
        }
        let route = self
            .prepared_production_exit_routes
            .get(&route_context_id)?;
        let exact_activation = route.exit_leases.len() == 1
            && route.pending_activations.len() == 1
            && route
                .pending_activations
                .get(&scope.relay.path_id)
                .is_some_and(|activation| {
                    activation.signed_relay_reservation == start.signed_relay_reservation()
                });
        if route.bundle.signed_exit_reservation() != start.signed_exit_reservation()
            || route.bundle.accepted().reservation_id().as_slice() != scope.exit.reservation_id
            || route.bundle.accepted().route_context_id() != &route_context_id
            || route.bundle.accepted().maximum_paths() != 1
            || route.expires_at_ms <= now_ms
            || route.commit.is_none()
            || route.mpquic_preflight.is_none()
            || !exact_activation
        {
            return None;
        }
        let mut route = self
            .prepared_production_exit_routes
            .remove(&route_context_id)?;
        let native_scope = route.bundle.accepted().native_route_authorization_scope();
        let activated = self
            .exit_service
            .as_mut()?
            .bind_udp_path(
                route.bundle.accepted(),
                start.signed_relay_reservation(),
                now_ms,
            )
            .ok()?;
        let commit = route.commit.take()?;
        let path = activated.into_verified_path();
        if start.uses_native_connect_ip() {
            let credential = self
                .exit_service
                .as_mut()?
                .take_native_route_authorization_with_credential(
                    &native_scope,
                    start.signed_credential_delivery(),
                    now_ms,
                )
                .ok()?;
            let certificate_der = route_certificate_der(credential.authorization()).ok()?;
            let native_path = ExitMpquicPathAuthorization::new(
                path.path_id(),
                start.signed_relay_reservation().to_vec(),
            )?;
            let result = start_production_single_path_udp_exit(
                route.mpquic_preflight.take()?,
                self.helper.clone(),
                route.helper_owner,
                commit,
                credential,
                native_path,
                path,
                policy,
                signed_policy_hash,
                Duration::from_secs(self.config.udp.idle_timeout_seconds),
                certificate_der,
                now_ms,
            )
            .await;
            let Ok((active, signal)) = result else {
                let _ = self
                    .exit_service
                    .as_mut()
                    .and_then(|service| service.release(route.bundle.reservation_id()).ok());
                return None;
            };
            let encoded = encode_canonical(
                &signal,
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
            )
            .ok()?;
            tokio::spawn(async move {
                let _ = active.run(now_ms).await;
            });
            Some(encoded)
        } else {
            let authorization = self
                .exit_service
                .as_mut()?
                .take_native_route_authorization(&native_scope, now_ms)
                .ok()?;
            let limits =
                DatagramLimits::new(volparossa_udp::MAX_UDP_PAYLOAD_BYTES, 1_000_000, 1_000_000)
                    .ok()?;
            let authorization_timeout = Duration::from_secs(
                self.config
                    .udp
                    .idle_timeout_seconds
                    .clamp(1, TUNNEL_SETUP_TIMEOUT_SECONDS),
            );
            let result = start_production_udp_exit(
                self.helper.clone(),
                route.helper_owner,
                commit,
                path,
                authorization,
                policy,
                authorization_timeout,
                limits,
                now_ms,
            )
            .await;
            let (active, signal) = match result {
                Ok(active) => active,
                Err(failure) => {
                    if let Some(cleanup) = failure.into_cleanup() {
                        tokio::spawn(async move {
                            let _ = cleanup.destroy().await;
                        });
                    }
                    let _ = self
                        .exit_service
                        .as_mut()
                        .and_then(|service| service.release(route.bundle.reservation_id()).ok());
                    return None;
                }
            };
            let encoded = encode_canonical(
                &signal,
                usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
            )
            .ok()?;
            tokio::spawn(async move {
                let _ = active.run(now_ms).await;
            });
            Some(encoded)
        }
    }

    /// Coalesce the same Client-signed MPQUIC proof set from every selected carrying Relay.
    /// Native Exit startup and every response remain withheld until each Relay has committed and
    /// arrived under its own confirmation nonce.
    #[allow(
        clippy::too_many_lines,
        reason = "exact-set MPQUIC coalescing and native startup are one fail-atomic transaction"
    )]
    async fn begin_production_mpquic_exit_session(
        &mut self,
        authenticated_control_relay: Libp2pPeerId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal, $channel:expr) => {{
                log_relay_forward_admission(Some(state), $code);
                self.send_mpquic_exit_unavailable(request.forward_id(), $channel);
                return;
            }};
        }
        let now_ms = unix_millis();
        let Some(scope) = verified_mpquic_session_start_scope(request.canonical_request(), now_ms)
        else {
            reject!("MPQUIC_SESSION_EXIT_SCOPE_REJECTED", channel);
        };
        let Ok(start) = decode_canonical::<MpquicSessionStartRequest>(
            request.canonical_request(),
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("MPQUIC_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let Some(route_context_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)
        else {
            reject!("MPQUIC_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let Some(forward_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.forward_id()) else {
            reject!("MPQUIC_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let relay_matches = scope
            .paths
            .iter()
            .filter(|path| {
                path.relay.relay_node_id == request.control_relay_node_id()
                    && path.relay.relay_peer_id == authenticated_control_relay.to_bytes()
                    && forward_id == path.confirmation_nonce[..FORWARD_ID_BYTES]
            })
            .collect::<Vec<_>>();
        let [relay_path] = relay_matches.as_slice() else {
            reject!("MPQUIC_SESSION_EXIT_RELAY_SET_REJECTED", channel);
        };
        let selected_path_ids = scope
            .paths
            .iter()
            .map(|path| path.relay.path_id)
            .collect::<Vec<_>>();
        let pending_expiry = scope
            .expires_at_ms
            .min(relay_path.expires_at_ms)
            .min(request.deadline_unix_ms());

        let prepared_matches = self
            .prepared_production_exit_routes
            .get(&route_context_id)
            .is_some_and(|route| {
                route.bundle.signed_exit_reservation() == start.signed_exit_reservation()
                    && route.bundle.accepted().reservation_id().as_slice()
                        == scope.exit.reservation_id
                    && route.bundle.accepted().route_context_id() == &route_context_id
                    && usize::try_from(route.bundle.accepted().maximum_paths()).ok()
                        == Some(selected_path_ids.len())
                    && route.expires_at_ms > now_ms
                    && route.commit.is_some()
                    && route.mpquic_preflight.is_some()
                    && route.exit_leases.len() == selected_path_ids.len()
                    && route.pending_activations.len() == selected_path_ids.len()
                    && scope.paths.iter().zip(start.paths()).all(|(path, proof)| {
                        route
                            .pending_activations
                            .get(&path.relay.path_id)
                            .is_some_and(|activation| {
                                activation.signed_relay_reservation
                                    == proof.signed_relay_reservation()
                            })
                    })
            });
        if !prepared_matches || pending_expiry <= now_ms {
            reject!("MPQUIC_SESSION_EXIT_OWNER_MISMATCH", channel);
        }

        if let Some(existing) = self.pending_mpquic_exit_sessions.get(&route_context_id) {
            if existing.canonical_start != request.canonical_request()
                || existing.selected_path_ids != selected_path_ids
            {
                let pending = self
                    .pending_mpquic_exit_sessions
                    .remove(&route_context_id)
                    .expect("observed MPQUIC Exit session");
                self.finish_mpquic_exit_session_unavailable(route_context_id, pending)
                    .await;
                reject!("MPQUIC_SESSION_EXIT_SET_CONFLICT", channel);
            }
        }

        if let Some(pending) = self.pending_mpquic_exit_sessions.get_mut(&route_context_id) {
            pending.expires_at_ms = pending.expires_at_ms.min(pending_expiry);
            match pending.relays.entry(relay_path.relay.path_id) {
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if entry.get().forward_id == forward_id
                        && entry.get().channels.len() < MAX_COALESCED_WAITERS =>
                {
                    entry.get_mut().channels.push(channel);
                    return;
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    reject!("MPQUIC_SESSION_EXIT_RELAY_RETRY_CONFLICT", channel);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(PendingMpquicExitRelay {
                        forward_id,
                        channels: vec![channel],
                    });
                }
            }
        } else {
            self.pending_mpquic_exit_sessions.insert(
                route_context_id,
                PendingMpquicExitSession {
                    canonical_start: request.canonical_request().to_vec(),
                    selected_path_ids: selected_path_ids.clone(),
                    relays: HashMap::from([(
                        relay_path.relay.path_id,
                        PendingMpquicExitRelay {
                            forward_id,
                            channels: vec![channel],
                        },
                    )]),
                    expires_at_ms: pending_expiry,
                },
            );
        }
        let complete = self
            .pending_mpquic_exit_sessions
            .get(&route_context_id)
            .is_some_and(|pending| {
                pending.relays.len() == pending.selected_path_ids.len()
                    && pending
                        .selected_path_ids
                        .iter()
                        .all(|path_id| pending.relays.contains_key(path_id))
            });
        if !complete {
            log_relay_forward_admission(Some(state), "MPQUIC_SESSION_EXIT_WAITING_EXACT_SET");
            return;
        }
        let pending = self
            .pending_mpquic_exit_sessions
            .remove(&route_context_id)
            .expect("complete MPQUIC Exit session");
        let signal = self
            .start_production_mpquic_exit_session(&pending.canonical_start, now_ms, state)
            .await;
        if let Some(encoded_signal) = signal {
            self.send_pending_mpquic_exit_granted(pending, &encoded_signal);
            log_relay_forward_admission(Some(state), "MPQUIC_SESSION_EXIT_NATIVE_READY");
        } else {
            if let Some(route) = self
                .prepared_production_exit_routes
                .remove(&route_context_id)
            {
                self.retire_production_exit_route(route_context_id, route)
                    .await;
            }
            self.send_pending_mpquic_exit_unavailable(pending);
            log_relay_forward_admission(Some(state), "MPQUIC_SESSION_EXIT_RUNTIME_REJECTED");
        }
    }

    /// Consume one exact Client-session-signed opaque bearer at the Exit, commit every confirmed
    /// helper path and return readiness only after the preflighted native Exit owns all listeners.
    async fn start_production_mpquic_exit_session(
        &mut self,
        encoded_start: &[u8],
        now_ms: u64,
        state: &Arc<RwLock<AgentState>>,
    ) -> Option<Vec<u8>> {
        let scope = verified_mpquic_session_start_scope(encoded_start, now_ms)?;
        let start = decode_canonical::<MpquicSessionStartRequest>(
            encoded_start,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
        )
        .ok()?;
        let route_context_id = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)?;
        let signed_policy_hash = fixed_bytes::<32>(&scope.exit.policy_hash)?;
        let policy = state.read().await.active_policy(now_ms)?;
        if policy.policy_hash() != &signed_policy_hash {
            return None;
        }
        let route = self
            .prepared_production_exit_routes
            .get(&route_context_id)?;
        let exact_activations = route.exit_leases.len() == start.paths().len()
            && route.pending_activations.len() == start.paths().len()
            && scope
                .paths
                .iter()
                .zip(start.paths())
                .all(|(verified, proof)| {
                    route
                        .pending_activations
                        .get(&verified.path_id)
                        .is_some_and(|activation| {
                            activation.signed_relay_reservation == proof.signed_relay_reservation()
                        })
                });
        if route.bundle.signed_exit_reservation() != start.signed_exit_reservation()
            || route.bundle.accepted().reservation_id().as_slice() != scope.exit.reservation_id
            || route.bundle.accepted().route_context_id() != &route_context_id
            || usize::try_from(route.bundle.accepted().maximum_paths()).ok()? != scope.paths.len()
            || route.expires_at_ms <= now_ms
            || route.commit.is_none()
            || route.mpquic_preflight.is_none()
            || !exact_activations
        {
            return None;
        }
        let native_scope = route.bundle.accepted().native_route_authorization_scope();
        let credential = self
            .exit_service
            .as_mut()?
            .take_native_route_authorization_with_credential(
                &native_scope,
                start.signed_credential_delivery(),
                now_ms,
            )
            .ok()?;
        let mut route = self
            .prepared_production_exit_routes
            .remove(&route_context_id)?;
        let paths = scope
            .paths
            .into_iter()
            .map(|path| {
                ExitMpquicPathAuthorization::new(path.path_id, path.signed_relay_reservation)
            })
            .collect::<Option<Vec<_>>>()?;
        let result = start_production_mpquic_exit(
            route.mpquic_preflight.take()?,
            self.helper.clone(),
            route.helper_owner,
            route.commit.take()?,
            credential,
            paths,
            policy,
            signed_policy_hash,
            Duration::from_secs(self.config.udp.idle_timeout_seconds),
            now_ms,
        )
        .await;
        let (active, signal) = match result {
            Ok(started) => started,
            Err(error) => {
                // The error contains only fixed local validation text or the native process's
                // bounded protocol diagnostic code; it never contains route secrets or traffic.
                eprintln!("production MPQUIC Exit startup failed: {error}");
                let _ = self
                    .exit_service
                    .as_mut()
                    .and_then(|service| service.release(route.bundle.reservation_id()).ok());
                return None;
            }
        };
        let encoded = encode_canonical(
            &signal,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        )
        .ok()?;
        tokio::spawn(async move {
            let _ = active.run(now_ms).await;
        });
        Some(encoded)
    }

    /// Coalesce one byte-identical complete MPTCP Start from every authenticated selected Relay.
    ///
    /// The first Relay cannot force an early listener. Only after the exact 2..=8 path set has
    /// arrived do we consume the finalized Exit owner, commit all leases, adopt a real
    /// `IPPROTO_MPTCP` listener, and register every selected Exit path.
    #[allow(
        clippy::too_many_lines,
        reason = "exact-set coalescing and affine Exit activation are one fail-atomic transaction"
    )]
    async fn begin_production_mptcp_exit_session(
        &mut self,
        authenticated_control_relay: Libp2pPeerId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal, $channel:expr) => {{
                log_relay_forward_admission(Some(state), $code);
                self.send_mptcp_exit_unavailable(request.forward_id(), $channel);
                return;
            }};
        }
        let now_ms = unix_millis();
        let Some(scope) = verified_mptcp_session_start_scope(request.canonical_request(), now_ms)
        else {
            reject!("MPTCP_SESSION_EXIT_SCOPE_REJECTED", channel);
        };
        let Ok(start) = decode_canonical::<MptcpSessionStartRequest>(
            request.canonical_request(),
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("MPTCP_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let Some(route_context_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.route_context_id)
        else {
            reject!("MPTCP_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let Some(forward_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.forward_id()) else {
            reject!("MPTCP_SESSION_EXIT_FRAME_REJECTED", channel);
        };
        let relay_matches = scope
            .paths
            .iter()
            .filter(|path| {
                path.relay.relay_node_id == request.control_relay_node_id()
                    && path.relay.relay_peer_id == authenticated_control_relay.to_bytes()
                    && forward_id == path.confirmation_nonce[..FORWARD_ID_BYTES]
            })
            .collect::<Vec<_>>();
        let [relay_path] = relay_matches.as_slice() else {
            reject!("MPTCP_SESSION_EXIT_RELAY_SET_REJECTED", channel);
        };
        let selected_path_ids = scope
            .paths
            .iter()
            .map(|path| path.relay.path_id)
            .collect::<Vec<_>>();
        let pending_expiry = scope
            .paths
            .iter()
            .map(|path| path.expires_at_ms)
            .min()
            .unwrap_or(0)
            .min(request.deadline_unix_ms());

        if let Some(active) = self
            .active_production_mptcp_exit_routes
            .get(&route_context_id)
        {
            if active.expires_at_ms > now_ms
                && active.canonical_start == request.canonical_request()
            {
                self.send_mptcp_exit_granted(
                    request.forward_id(),
                    active.encoded_signal.clone(),
                    channel,
                );
                return;
            }
            reject!("MPTCP_SESSION_EXIT_ACTIVE_CONFLICT", channel);
        }

        let prepared_matches = self
            .prepared_production_exit_routes
            .get(&route_context_id)
            .is_some_and(|route| {
                route.bundle.signed_exit_reservation() == start.signed_exit_reservation()
                    && route.bundle.accepted().reservation_id().as_slice()
                        == scope.exit.reservation_id
                    && route.bundle.accepted().route_context_id() == &route_context_id
                    && usize::try_from(route.bundle.accepted().maximum_paths()).ok()
                        == Some(selected_path_ids.len())
                    && route.expires_at_ms > now_ms
                    && route.commit.is_some()
                    && route.exit_leases.len() == selected_path_ids.len()
                    && route.pending_activations.len() == selected_path_ids.len()
                    && scope.paths.iter().zip(start.paths()).all(|(path, proof)| {
                        route
                            .pending_activations
                            .get(&path.relay.path_id)
                            .is_some_and(|activation| {
                                activation.signed_relay_reservation
                                    == proof.signed_relay_reservation()
                            })
                    })
            });
        if !prepared_matches {
            reject!("MPTCP_SESSION_EXIT_OWNER_MISMATCH", channel);
        }

        if let Some(existing) = self.pending_mptcp_exit_sessions.get(&route_context_id) {
            if existing.canonical_start != request.canonical_request()
                || existing.selected_path_ids != selected_path_ids
            {
                let pending = self
                    .pending_mptcp_exit_sessions
                    .remove(&route_context_id)
                    .expect("observed MPTCP Exit session");
                self.finish_mptcp_exit_session_unavailable(route_context_id, pending)
                    .await;
                reject!("MPTCP_SESSION_EXIT_SET_CONFLICT", channel);
            }
        }

        if let Some(pending) = self.pending_mptcp_exit_sessions.get_mut(&route_context_id) {
            pending.expires_at_ms = pending.expires_at_ms.min(pending_expiry);
            match pending.relays.entry(relay_path.relay.path_id) {
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if entry.get().forward_id == forward_id
                        && entry.get().channels.len() < MAX_COALESCED_WAITERS =>
                {
                    entry.get_mut().channels.push(channel);
                    return;
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    reject!("MPTCP_SESSION_EXIT_RELAY_RETRY_CONFLICT", channel);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(PendingMptcpExitRelay {
                        forward_id,
                        channels: vec![channel],
                    });
                }
            }
        } else {
            self.pending_mptcp_exit_sessions.insert(
                route_context_id,
                PendingMptcpExitSession {
                    canonical_start: request.canonical_request().to_vec(),
                    selected_path_ids: selected_path_ids.clone(),
                    relays: HashMap::from([(
                        relay_path.relay.path_id,
                        PendingMptcpExitRelay {
                            forward_id,
                            channels: vec![channel],
                        },
                    )]),
                    expires_at_ms: pending_expiry,
                },
            );
        }
        let complete = self
            .pending_mptcp_exit_sessions
            .get(&route_context_id)
            .is_some_and(|pending| {
                pending.relays.len() == pending.selected_path_ids.len()
                    && pending
                        .selected_path_ids
                        .iter()
                        .all(|path_id| pending.relays.contains_key(path_id))
            });
        if !complete {
            log_relay_forward_admission(Some(state), "MPTCP_SESSION_EXIT_WAITING_EXACT_SET");
            return;
        }
        let pending = self
            .pending_mptcp_exit_sessions
            .remove(&route_context_id)
            .expect("complete MPTCP Exit session");
        let Some(mut route) = self
            .prepared_production_exit_routes
            .remove(&route_context_id)
        else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_OWNER_LOST").await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };

        let relay_reservations = start
            .paths()
            .iter()
            .map(volparossa_discovery::MptcpSessionPathProof::signed_relay_reservation)
            .collect::<Vec<_>>();
        let native_scope = route.bundle.accepted().native_route_authorization_scope();
        let active_route = match self.exit_service.as_mut().map(|service| {
            service.bind_tcp_route(route.bundle.accepted(), &relay_reservations, now_ms)
        }) {
            Some(Ok(active)) => active,
            Some(Err(error)) => {
                tracing::warn!(%error, "MPTCP Exit route binding rejected");
                log_reservation_event(state, "MPTCP_SESSION_EXIT_ROUTE_BINDING_REJECTED").await;
                self.retire_production_exit_route(route_context_id, route)
                    .await;
                self.send_pending_mptcp_exit_unavailable(pending);
                return;
            }
            None => {
                log_reservation_event(state, "MPTCP_SESSION_EXIT_SERVICE_LOST").await;
                self.retire_production_exit_route(route_context_id, route)
                    .await;
                self.send_pending_mptcp_exit_unavailable(pending);
                return;
            }
        };
        let native_authorization = match self
            .exit_service
            .as_mut()
            .map(|service| service.take_native_route_authorization(&native_scope, now_ms))
        {
            Some(Ok(authorization)) => authorization,
            Some(Err(error)) => {
                tracing::warn!(%error, "MPTCP Exit native authorization rejected");
                log_reservation_event(state, "MPTCP_SESSION_EXIT_NATIVE_AUTHORIZATION_REJECTED")
                    .await;
                self.retire_production_exit_route(route_context_id, route)
                    .await;
                self.send_pending_mptcp_exit_unavailable(pending);
                return;
            }
            None => {
                log_reservation_event(state, "MPTCP_SESSION_EXIT_SERVICE_LOST").await;
                self.retire_production_exit_route(route_context_id, route)
                    .await;
                self.send_pending_mptcp_exit_unavailable(pending);
                return;
            }
        };
        let Some(commit) = route.commit.take() else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_COMMIT_OWNER_LOST").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        if !exact_mptcp_exit_commit(&route, &commit, &selected_path_ids) {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_COMMIT_SCOPE_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        }
        let Some(reservation_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.exit.reservation_id)
        else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_RESERVATION_ID_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let Ok(certificate_der) = route_certificate_der(&native_authorization) else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_CERTIFICATE_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let Ok(wire_signal) = ExitMptcpSessionSignal::new(
            reservation_id,
            route_context_id,
            PRODUCTION_MPTCP_EXIT_PORT,
            selected_path_ids,
            certificate_der,
        ) else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_SIGNAL_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let Ok(listener_signal) = ExitMptcpListenerSignal::try_from_discovery(
            &wire_signal,
            &native_authorization.public_identity().certificate_sha256,
        ) else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_LISTENER_SIGNAL_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let Some(encoded_signal) = encode_canonical(
            &wire_signal,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        )
        .ok() else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_SIGNAL_ENCODING_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let context_handle = route.helper_owner.prepared().context_handle.clone();
        if self
            .helper
            .commit_lease_batch(&mut route.helper_owner, commit)
            .await
            .is_err()
        {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_HELPER_COMMIT_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        }
        let Ok(transport) =
            ExitMptcpTransport::acquire_and_activate(&self.helper, listener_signal, context_handle)
                .await
        else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_TRANSPORT_REJECTED").await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        if !transport
            .listener()
            .local_addr()
            .is_ok_and(|address| address.port() == PRODUCTION_MPTCP_EXIT_PORT)
        {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_LISTENER_ADDRESS_REJECTED").await;
            let _ = transport.shutdown(&self.helper).await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        }
        let expires_at_ms = route.expires_at_ms;
        let Some(exit_service) = self.exit_service.as_ref() else {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_SERVICE_LOST").await;
            let _ = transport.shutdown(&self.helper).await;
            self.retire_production_exit_route(route_context_id, route)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        };
        let runtime = ProductionMptcpExitRuntime::new(
            self.helper.clone(),
            route.helper_owner,
            transport,
            active_route,
            native_authorization,
            exit_service,
            now_ms,
        );
        let runtime = match runtime {
            Ok(runtime) => runtime,
            Err(failure) => {
                let _cause = failure.cause();
                let active = ActiveProductionMptcpExitRoute {
                    canonical_start: pending.canonical_start.clone(),
                    encoded_signal: encoded_signal.clone(),
                    runtime: None,
                    cleanup: Some(failure.into_cleanup()),
                    runtime_started: false,
                    reservation_id,
                    expires_at_ms: 0,
                    cleanup_not_before_ms: 0,
                };
                self.active_production_mptcp_exit_routes
                    .insert(route_context_id, active);
                self.send_pending_mptcp_exit_unavailable(pending);
                log_relay_forward_admission(Some(state), "MPTCP_SESSION_EXIT_RUNTIME_REJECTED");
                return;
            }
        };
        let active = ActiveProductionMptcpExitRoute {
            canonical_start: pending.canonical_start.clone(),
            encoded_signal: encoded_signal.clone(),
            runtime: Some(runtime),
            cleanup: None,
            runtime_started: false,
            reservation_id,
            expires_at_ms,
            cleanup_not_before_ms: 0,
        };
        if self
            .active_production_mptcp_exit_routes
            .contains_key(&route_context_id)
        {
            log_reservation_event(state, "MPTCP_SESSION_EXIT_ACTIVE_OWNER_CONFLICT").await;
            self.retire_active_mptcp_exit_route(route_context_id, active)
                .await;
            self.send_pending_mptcp_exit_unavailable(pending);
            return;
        }
        self.active_production_mptcp_exit_routes
            .insert(route_context_id, active);
        self.send_pending_mptcp_exit_granted(pending, &encoded_signal);
        self.start_mptcp_exit_runtime(route_context_id);
        log_relay_forward_admission(Some(state), "MPTCP_SESSION_EXIT_LISTENER_READY");
    }

    fn send_mptcp_exit_unavailable(
        &mut self,
        forward_id: &[u8],
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        if let Ok(response) = ExitForwardResponse::unavailable(
            forward_id.to_vec(),
            ExitForwardOperation::MptcpSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    fn send_mptcp_exit_granted(
        &mut self,
        forward_id: &[u8],
        encoded_signal: Vec<u8>,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        if let Ok(response) = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::MptcpSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
            vec![encoded_signal],
        ) {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    fn send_pending_mptcp_exit_unavailable(&mut self, pending: PendingMptcpExitSession) {
        for relay in pending.relays.into_values() {
            for channel in relay.channels {
                self.send_mptcp_exit_unavailable(&relay.forward_id, channel);
            }
        }
    }

    fn send_pending_mptcp_exit_granted(
        &mut self,
        pending: PendingMptcpExitSession,
        encoded_signal: &[u8],
    ) {
        for relay in pending.relays.into_values() {
            for channel in relay.channels {
                self.send_mptcp_exit_granted(&relay.forward_id, encoded_signal.to_vec(), channel);
            }
        }
    }

    fn send_mpquic_exit_unavailable(
        &mut self,
        forward_id: &[u8],
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        if let Ok(response) = ExitForwardResponse::unavailable(
            forward_id.to_vec(),
            ExitForwardOperation::MpquicSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    fn send_mpquic_exit_granted(
        &mut self,
        forward_id: &[u8],
        encoded_signal: Vec<u8>,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        if let Ok(response) = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::MpquicSessionStart,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
            vec![encoded_signal],
        ) {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    fn send_pending_mpquic_exit_unavailable(&mut self, pending: PendingMpquicExitSession) {
        for relay in pending.relays.into_values() {
            for channel in relay.channels {
                self.send_mpquic_exit_unavailable(&relay.forward_id, channel);
            }
        }
    }

    fn send_pending_mpquic_exit_granted(
        &mut self,
        pending: PendingMpquicExitSession,
        encoded_signal: &[u8],
    ) {
        for relay in pending.relays.into_values() {
            for channel in relay.channels {
                self.send_mpquic_exit_granted(&relay.forward_id, encoded_signal.to_vec(), channel);
            }
        }
    }

    fn start_mptcp_exit_runtime(&mut self, route_context_id: [u8; FORWARD_ID_BYTES]) {
        let Some(active) = self
            .active_production_mptcp_exit_routes
            .get_mut(&route_context_id)
        else {
            return;
        };
        let Some(runtime) = active.runtime.take() else {
            return;
        };
        active.runtime_started = true;
        let events = self.mptcp_exit_runtime_events.clone();
        let reservation_id = active.reservation_id;
        tokio::spawn(async move {
            let completion = runtime
                .run(|succeeded| {
                    let events = events.clone();
                    async move {
                        let _ = events
                            .send(MptcpExitRuntimeEvent::FlowCompleted {
                                route_context_id,
                                reservation_id,
                                succeeded,
                            })
                            .await;
                    }
                })
                .await;
            let event = MptcpExitRuntimeEvent::RuntimeCompleted(MptcpExitRuntimeCompletionEvent {
                route_context_id,
                completion,
            });
            if let Err(error) = events.send(event).await {
                let MptcpExitRuntimeEvent::RuntimeCompleted(completion) = error.0 else {
                    return;
                };
                if let Some(cleanup) = completion.completion.into_cleanup() {
                    let _ = cleanup.destroy().await;
                }
            }
        });
    }

    async fn finish_mptcp_exit_flow(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        reservation_id: [u8; FORWARD_ID_BYTES],
        succeeded: bool,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let Some(active) = self
            .active_production_mptcp_exit_routes
            .get(&route_context_id)
        else {
            state.write().await.log(
                LogLevel::Error,
                "MPTCP_EXIT_FLOW_OWNER_MISSING",
                unix_millis(),
            );
            return;
        };
        if !active.runtime_started || active.reservation_id != reservation_id {
            state.write().await.log(
                LogLevel::Error,
                "MPTCP_EXIT_FLOW_SCOPE_MISMATCH",
                unix_millis(),
            );
            return;
        }
        state.write().await.log(
            if succeeded {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            if succeeded {
                "MPTCP_EXIT_FLOW_COMPLETED"
            } else {
                "MPTCP_EXIT_FLOW_FAILED"
            },
            unix_millis(),
        );
    }

    async fn finish_mptcp_exit_runtime(
        &mut self,
        event: MptcpExitRuntimeCompletionEvent,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let Some(mut active) = self
            .active_production_mptcp_exit_routes
            .remove(&event.route_context_id)
        else {
            if let Some(cleanup) = event.completion.into_cleanup() {
                let _ = cleanup.destroy().await;
            }
            state.write().await.log(
                LogLevel::Error,
                "MPTCP_EXIT_RUNTIME_OWNER_MISSING",
                unix_millis(),
            );
            return;
        };
        if event.completion.reservation_id() != &active.reservation_id {
            if let Some(cleanup) = event.completion.into_cleanup() {
                let _ = cleanup.destroy().await;
            }
            active.expires_at_ms = 0;
            self.active_production_mptcp_exit_routes
                .insert(event.route_context_id, active);
            state.write().await.log(
                LogLevel::Error,
                "MPTCP_EXIT_RUNTIME_SCOPE_MISMATCH",
                unix_millis(),
            );
            return;
        }
        let succeeded = event.completion.succeeded();
        if let Some(cleanup) = event.completion.into_cleanup() {
            match cleanup.destroy().await {
                Ok(()) => {}
                Err(cleanup) => {
                    active.cleanup = Some(cleanup);
                    active.runtime_started = false;
                    active.expires_at_ms = 0;
                    active.cleanup_not_before_ms =
                        unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
                    self.active_production_mptcp_exit_routes
                        .insert(event.route_context_id, active);
                    state.write().await.log(
                        LogLevel::Error,
                        "MPTCP_EXIT_RUNTIME_CLEANUP_PENDING",
                        unix_millis(),
                    );
                    return;
                }
            }
        }
        let _ = self
            .exit_service
            .as_mut()
            .and_then(|service| service.release(&active.reservation_id).ok());
        state.write().await.log(
            if succeeded {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            if succeeded {
                "MPTCP_EXIT_RUNTIME_COMPLETED"
            } else {
                "MPTCP_EXIT_RUNTIME_FAILED"
            },
            unix_millis(),
        );
    }

    async fn finish_mptcp_exit_session_unavailable(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        pending: PendingMptcpExitSession,
    ) {
        if let Some(route) = self
            .prepared_production_exit_routes
            .remove(&route_context_id)
        {
            self.retire_production_exit_route(route_context_id, route)
                .await;
        }
        self.send_pending_mptcp_exit_unavailable(pending);
    }

    async fn finish_mpquic_exit_session_unavailable(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        pending: PendingMpquicExitSession,
    ) {
        if let Some(route) = self
            .prepared_production_exit_routes
            .remove(&route_context_id)
        {
            self.retire_production_exit_route(route_context_id, route)
                .await;
        }
        self.send_pending_mpquic_exit_unavailable(pending);
    }

    /// Destroy helper state before releasing the signed Exit allocation. A failed Destroy keeps
    /// the owner quarantined for the actor's next bounded maintenance pass.
    async fn retire_production_exit_route(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        mut route: PreparedProductionExitRoute,
    ) -> bool {
        route.expires_at_ms = 0;
        if self
            .helper
            .destroy_context(&route.helper_owner)
            .await
            .is_ok()
        {
            let _ = self
                .exit_service
                .as_mut()
                .and_then(|service| service.release(route.bundle.reservation_id()).ok());
            true
        } else {
            route.cleanup_not_before_ms =
                unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
            let previous = self
                .prepared_production_exit_routes
                .insert(route_context_id, route);
            debug_assert!(previous.is_none(), "MPTCP Exit cleanup owner collision");
            false
        }
    }

    async fn retire_active_mptcp_exit_route(
        &mut self,
        route_context_id: [u8; FORWARD_ID_BYTES],
        mut route: ActiveProductionMptcpExitRoute,
    ) -> bool {
        route.expires_at_ms = 0;
        if let Some(runtime) = route.runtime.take() {
            if let Err(cleanup) = runtime.shutdown().await {
                route.cleanup = Some(cleanup);
            }
        }
        let cleanup_complete = match route.cleanup.take() {
            Some(cleanup) => match cleanup.destroy().await {
                Ok(()) => true,
                Err(cleanup) => {
                    route.cleanup = Some(cleanup);
                    false
                }
            },
            None => true,
        };
        if cleanup_complete {
            let _ = self
                .exit_service
                .as_mut()
                .and_then(|service| service.release(&route.reservation_id).ok());
            true
        } else {
            route.cleanup_not_before_ms =
                unix_millis().saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);
            let previous = self
                .active_production_mptcp_exit_routes
                .insert(route_context_id, route);
            debug_assert!(
                previous.is_none(),
                "active MPTCP Exit cleanup owner collision"
            );
            false
        }
    }

    /// Validate one native-Permit request and prepare its exact connection-owned response.
    ///
    /// Every state-free wrapper, signature, current-capability and local-advertisement check runs
    /// before connection provenance is bound. The bind itself precedes the only Exit replay/sign
    /// call. There is no suspension point from that bind through the returned response owner. The
    /// handler only proceeds while a truthful, unexpired local Exit capability is being served.
    fn prepare_native_probe_permit_response(
        &mut self,
        authenticated_control_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: &ExitForwardRequest,
    ) -> Option<(
        BoundNativeProbeControlConnection,
        Libp2pPeerId,
        UpstreamExitForwardResponse,
    )> {
        let now_ms = unix_millis();
        if request.validate().is_err() || !self.roles.exit {
            return None;
        }
        let scope = verified_native_probe_forward_scope(request, now_ms)?;
        let control = scope.control.as_ref()?;
        let exit = scope.exit.as_ref()?;
        let control_relay_node_id = fixed_bytes::<32>(request.control_relay_node_id())?;
        let control_relay_public_key = fixed_bytes::<32>(request.control_relay_public_key())?;
        let control_relay_peer = Libp2pPeerId::from_bytes(request.control_relay_peer_id()).ok()?;
        let exit_node_id = fixed_bytes::<32>(request.exit_node_id())?;
        let exit_peer = Libp2pPeerId::from_bytes(request.exit_peer_id()).ok()?;
        let local_peer = *self.service.local_peer_id();
        let exit_control_address = self.native_permit_exit_control_address(&scope)?;
        let current_control = native_probe_relay_capability_from_advertisement(
            request.control_advertisement(),
            control,
            &scope,
            authenticated_control_relay,
            now_ms,
        )?;
        if control_relay_peer != authenticated_control_relay
            || control_relay_public_key != current_control.public_key
            || exit_node_id != self.local_node_id
            || exit_peer != local_peer
            || exit_peer == authenticated_control_relay
            || !native_probe_control_capability_lineage_matches(
                &current_control,
                control,
                &scope,
                authenticated_control_relay,
                request.deadline_unix_ms(),
                now_ms,
            )
            || !local_native_probe_exit_actor_is_served(
                &self.service,
                exit,
                &scope,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                now_ms,
            )
        {
            return None;
        }

        // This purpose token comes from the exact inbound event's authenticated PeerId and
        // behaviour-local ConnectionId. Bind before the Exit can consume replay or invoke its
        // signer; a closed, stale, foreign-service or substituted lineage therefore fails first.
        let connection = self
            .service
            .bind_native_probe_control_connection(authenticated_control_relay, connection_id)
            .ok()?;
        // The verified self-advertisement also authorizes subsequent reservation requests to
        // this Exit. It never becomes a candidate for this node's unrelated Client role.
        retain_exit_relay_capability(
            &mut self.exit_control_relays,
            self.candidate_limit,
            current_control,
        )?;
        let authenticated_control_peer = authenticated_control_relay.to_bytes();
        let identity = &self.identity;
        let accepted = self
            .exit_service
            .as_mut()?
            .issue_native_probe_permit_with(
                request.canonical_request(),
                &control_relay_node_id,
                &authenticated_control_peer,
                &exit_control_address,
                now_ms,
                self.local_public_key,
                |message| identity.sign(message).ok(),
            )
            .ok()?;
        let response = ExitForwardResponse::granted(
            request.forward_id().to_vec(),
            ExitForwardOperation::NativeProbePermit,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            vec![accepted.encoded().to_vec()],
        )
        .ok()?;
        Some((connection, authenticated_control_relay, response.into()))
    }

    /// Select this Exit's listener for the signed data Relay, not the forwarding control Relay.
    /// A private listener requires that exact peer's current authenticated direct-LAN lineage
    /// and unambiguous observation of our own address. This is only control dial eligibility;
    /// it creates no native endpoint/lease authority and does not replace helper route proof.
    fn native_permit_exit_control_address(&self, scope: &NativeProbePathScope) -> Option<String> {
        let relay = scope.data_relay.as_ref()?;
        let peer = Libp2pPeerId::from_bytes(&relay.peer_id).ok()?;
        let family = ObservationAddressFamily::try_from(scope.address_family).ok()?;
        let local_family = self
            .service
            .authenticated_local_peer_prefix(peer)
            .is_some_and(|prefix| {
                matches!(
                    (family, prefix.family()),
                    (
                        ObservationAddressFamily::Ipv4,
                        volparossa_core::IpFamily::Ipv4
                    ) | (
                        ObservationAddressFamily::Ipv6,
                        volparossa_core::IpFamily::Ipv6
                    )
                )
            });
        let local_hint = if local_family {
            let hints = self
                .exact_endpoint_traversal_hints(vec![EndpointTraversalBinding {
                    path_id: scope.candidate_ordinal,
                    role: WireguardRole::Exit,
                    observer_id: fixed_bytes::<32>(&relay.node_id)?,
                    observer_peer_id: peer,
                }])
                .ok()?;
            Some(hints.into_iter().find_map(|hint| {
                hint.on_link.filter(|link| {
                    matches!(
                        (family, link.local_address.len()),
                        (ObservationAddressFamily::Ipv4, 4) | (ObservationAddressFamily::Ipv6, 16)
                    )
                })
            })?)
        } else {
            None
        };
        identity_bound_exit_control_address(
            &self.control_addresses,
            scope,
            *self.service.local_peer_id(),
            local_hint
                .as_ref()
                .map(|hint| hint.local_address.as_slice()),
        )
    }

    fn send_prepared_native_probe_permit_response(
        &mut self,
        prepared: PreparedNativeProbePermitResponse,
    ) {
        let PreparedNativeProbePermitResponse {
            connection,
            authenticated_control_relay,
            channel,
            response,
        } = prepared;
        let _ = self.service.send_native_probe_permit_response(
            connection,
            authenticated_control_relay,
            channel,
            response,
        );
    }

    /// Verify one Relay-forwarded native Start chain and prepare the standard Exit authority.
    ///
    /// The data Relay comes from the exact signed scope and must equal both the authenticated
    /// upstream peer and its current direct advertisement capability. The selected Exit must be
    /// this process and its current local advertisement. Connection lineage is bound before the
    /// Exit service can retain capacity or sign.
    #[allow(
        clippy::too_many_lines,
        reason = "Exit authorization also activates every exact sampler path and socket"
    )]
    async fn prepare_native_probe_authorization_response(
        &mut self,
        authenticated_data_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: &ExitForwardRequest,
    ) -> Option<(
        BoundNativeProbeDataRelayConnection,
        Libp2pPeerId,
        UpstreamExitForwardResponse,
    )> {
        let now_ms = unix_millis();
        if request.validate().is_err() || !self.roles.exit {
            return None;
        }
        let scope = verified_native_probe_authorization_forward_scope(request, now_ms)?;
        let verified_chain =
            verify_native_probe_authorization_chain(request.canonical_request(), now_ms).ok()?;
        if verified_chain.scope() != &scope {
            return None;
        }
        let data_relay = scope.data_relay.as_ref()?;
        let exit = scope.exit.as_ref()?;
        let data_relay_node_id = fixed_bytes::<32>(request.control_relay_node_id())?;
        let data_relay_public_key = fixed_bytes::<32>(request.control_relay_public_key())?;
        let data_relay_peer = Libp2pPeerId::from_bytes(request.control_relay_peer_id()).ok()?;
        let exit_node_id = fixed_bytes::<32>(request.exit_node_id())?;
        let exit_peer = Libp2pPeerId::from_bytes(request.exit_peer_id()).ok()?;
        let attempt_id = fixed_bytes::<FORWARD_ID_BYTES>(&scope.attempt_id)?;
        let path_id = scope.candidate_ordinal;
        let local_peer = *self.service.local_peer_id();
        let authorized_data_relay = self
            .exit_native_ready_attempts
            .get(&attempt_id)?
            .authorized_data_relays
            .get(&path_id)?;
        if data_relay_peer != authenticated_data_relay
            || data_relay_public_key != authorized_data_relay.public_key
            || exit_node_id != self.local_node_id
            || exit_peer != local_peer
            || exit_peer == authenticated_data_relay
            || !native_probe_data_relay_capability_matches(
                authorized_data_relay,
                data_relay,
                &scope,
                authenticated_data_relay,
                scope.attempt_expires_at_ms,
            )
            || !local_native_probe_exit_actor_is_served(
                &self.service,
                exit,
                &scope,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                now_ms,
            )
        {
            return None;
        }

        let connection = self
            .service
            .bind_native_probe_data_relay_connection(authenticated_data_relay, connection_id)
            .ok()?;
        let authenticated_data_relay_peer = authenticated_data_relay.to_bytes();
        let identity = &self.identity;
        let accepted = self
            .exit_service
            .as_mut()?
            .issue_native_probe_relay_authorization_with(
                request.canonical_request(),
                &data_relay_node_id,
                &authenticated_data_relay_peer,
                now_ms,
                self.local_public_key,
                |message| identity.sign(message).ok(),
            )
            .ok()?;
        let relay_endpoint = verified_chain.relay_exit_endpoint().endpoint.as_ref()?;
        let accepted_encoded = accepted.encoded().to_vec();
        let accepted_chain = accepted.authorization_chain().to_vec();
        let activation = {
            let attempt = self.exit_native_ready_attempts.get(&attempt_id)?;
            if !attempt.ready_paths.contains(&path_id) {
                return None;
            }
            let exit_lease = attempt
                .exit_leases
                .iter()
                .find(|lease| lease.path_id() == path_id)?;
            LeaseActivation {
                lease_handle: exit_lease.lease_handle().as_bytes().to_vec(),
                path_id,
                role: WireguardRole::Exit as i32,
                peer_public_key: relay_endpoint.public_key.clone(),
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: relay_endpoint.underlay_ip.clone(),
                    port: relay_endpoint.listen_port,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation: accepted_encoded.clone(),
                signed_client_relay_request: accepted_chain,
            }
        };
        let activate_now = {
            let attempt = self.exit_native_ready_attempts.get_mut(&attempt_id)?;
            match attempt.pending_activations.entry(path_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(activation);
                }
                std::collections::hash_map::Entry::Occupied(entry)
                    if entry.get() == &activation => {}
                std::collections::hash_map::Entry::Occupied(_) => return None,
            }
            !attempt.activated && attempt.pending_activations.len() == attempt.exit_leases.len()
        };
        if activate_now {
            let helper = self.helper.clone();
            let activation_result = {
                let attempt = self.exit_native_ready_attempts.get_mut(&attempt_id)?;
                let mut leases = attempt
                    .pending_activations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                leases.sort_unstable_by_key(|lease| lease.path_id);
                let activation = ActivateLeaseBatch {
                    route_context_id: scope.attempt_id.clone(),
                    context_handle: attempt.helper_owner.prepared().context_handle.clone(),
                    leases,
                };
                helper
                    .activate_lease_batch(&mut attempt.helper_owner, activation)
                    .await
            };
            if activation_result.is_err() {
                if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                    let _ = self.helper.destroy_context(&attempt.helper_owner).await;
                }
                return None;
            }
            let socket_requests = {
                let attempt = self.exit_native_ready_attempts.get(&attempt_id)?;
                attempt
                    .exit_leases
                    .iter()
                    .map(|lease| {
                        native_probe_exit_socket_request(
                            attempt_id,
                            &attempt.helper_owner.prepared().context_handle,
                            lease.path_id(),
                        )
                        .map(|request| (lease.path_id(), request))
                    })
                    .collect::<Option<Vec<_>>>()?
            };
            let mut probe_tasks: HashMap<
                u32,
                JoinHandle<Result<[u8; NATIVE_PROBE_DATAGRAM_BYTES], ()>>,
            > = HashMap::with_capacity(socket_requests.len());
            for (path_id, socket_request) in socket_requests {
                let Ok(acquired) = self.helper.acquire_transport_socket(socket_request).await
                else {
                    for task in probe_tasks.into_values() {
                        task.abort();
                    }
                    if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                        let _ = self.helper.destroy_context(&attempt.helper_owner).await;
                    }
                    return None;
                };
                let (descriptor, _) = acquired.into_parts();
                let socket = StdUdpSocket::from(descriptor);
                if socket.set_nonblocking(true).is_err() {
                    if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                        let _ = self.helper.destroy_context(&attempt.helper_owner).await;
                    }
                    return None;
                }
                let Ok(socket) = UdpSocket::from_std(socket) else {
                    if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                        let _ = self.helper.destroy_context(&attempt.helper_owner).await;
                    }
                    return None;
                };
                probe_tasks.insert(
                    path_id,
                    tokio::spawn(async move {
                        let mut challenge = [0_u8; NATIVE_PROBE_DATAGRAM_BYTES];
                        let received =
                            timeout(EXIT_FORWARD_UPSTREAM_TIMEOUT, socket.recv(&mut challenge))
                                .await
                                .map_err(|_| ())?
                                .map_err(|_| ())?;
                        if received != NATIVE_PROBE_DATAGRAM_BYTES {
                            return Err(());
                        }
                        let sent = socket.send(&challenge).await.map_err(|_| ())?;
                        (sent == NATIVE_PROBE_DATAGRAM_BYTES)
                            .then_some(challenge)
                            .ok_or(())
                    }),
                );
            }
            let attempt = self.exit_native_ready_attempts.get_mut(&attempt_id)?;
            attempt.probe_tasks = probe_tasks;
            attempt.activated = true;
        }
        let response = ExitForwardResponse::granted(
            request.forward_id().to_vec(),
            ExitForwardOperation::NativeProbeAuthorize,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            vec![accepted_encoded],
        )
        .ok()?;
        Some((connection, authenticated_data_relay, response.into()))
    }

    /// Join every exact path result, commit and destroy the shared Exit sampler, then respond.
    #[allow(
        clippy::too_many_lines,
        reason = "exact-set Exit observation, commit, cleanup and signed responses are one transaction"
    )]
    async fn answer_native_probe_result_upstream(
        &mut self,
        authenticated_data_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Ok(response) = ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::NativeProbeResult,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    let _ = self
                        .service
                        .send_exit_forward_upstream_response(channel, response.into());
                }
                return;
            }};
        }
        let now_ms = unix_millis();
        if request.validate().is_err() || !self.roles.exit {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        }
        let Some(scope) = verified_native_probe_result_forward_scope(request, now_ms) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Ok(chain) =
            verify_native_probe_authorization_chain(request.canonical_request(), now_ms)
        else {
            reject!("NATIVE_PROBE_RESULT_EXIT_CHAIN_REJECTED");
        };
        if chain.scope() != &scope {
            reject!("NATIVE_PROBE_RESULT_EXIT_CHAIN_REJECTED");
        }
        let Some(data_relay) = scope.data_relay.as_ref() else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(exit) = scope.exit.as_ref() else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(data_relay_node_id) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(attempt_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.attempt_id) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(probe_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.probe_id) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(forward_id) = fixed_bytes::<FORWARD_ID_BYTES>(request.forward_id()) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(relay_wire_endpoint) = chain.relay_exit_endpoint().endpoint.as_ref() else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let Some(observed_network_prefix) = native_probe_observed_relay_prefix(relay_wire_endpoint)
        else {
            reject!("NATIVE_PROBE_RESULT_EXIT_SCOPE_REJECTED");
        };
        let path_id = scope.candidate_ordinal;
        let local_peer = *self.service.local_peer_id();
        let Some(authorized_data_relay) = self
            .exit_native_ready_attempts
            .get(&attempt_id)
            .and_then(|attempt| attempt.authorized_data_relays.get(&path_id))
        else {
            reject!("NATIVE_PROBE_RESULT_EXIT_RELAY_REJECTED");
        };
        if request.control_relay_peer_id() != authenticated_data_relay.to_bytes()
            || request.control_relay_public_key() != authorized_data_relay.public_key
            || request.exit_node_id() != self.local_node_id
            || request.exit_peer_id() != local_peer.to_bytes()
            || exit.node_id != self.local_node_id
            || exit.peer_id != local_peer.to_bytes()
            || !native_probe_data_relay_capability_matches(
                authorized_data_relay,
                data_relay,
                &scope,
                authenticated_data_relay,
                scope.attempt_expires_at_ms,
            )
        {
            reject!("NATIVE_PROBE_RESULT_EXIT_RELAY_REJECTED");
        }
        let Some(connection) = self
            .service
            .bind_native_probe_data_relay_connection(authenticated_data_relay, connection_id)
            .ok()
        else {
            reject!("NATIVE_PROBE_RESULT_EXIT_CONNECTION_REJECTED");
        };
        let Some(attempt) = self.exit_native_ready_attempts.get_mut(&attempt_id) else {
            reject!("NATIVE_PROBE_RESULT_EXIT_OWNER_UNAVAILABLE");
        };
        if !attempt.activated
            || !attempt.ready_paths.contains(&path_id)
            || !attempt.probe_tasks.contains_key(&path_id)
            || attempt.pending_results.contains_key(&path_id)
            || attempt
                .exit_leases
                .iter()
                .all(|lease| lease.path_id() != path_id)
        {
            reject!("NATIVE_PROBE_RESULT_EXIT_OWNER_MISMATCH");
        }
        attempt.pending_results.insert(
            path_id,
            PendingExitNativeProbeResult {
                connection,
                authenticated_data_relay,
                authenticated_data_relay_node_id: data_relay_node_id,
                probe_id,
                forward_id,
                path_id,
                observed_network_prefix,
                scope: scope.clone(),
                channel,
            },
        );
        if attempt.pending_results.len() != attempt.exit_leases.len() {
            log_relay_forward_admission(Some(state), "NATIVE_PROBE_RESULT_EXIT_RETAINED");
            return;
        }
        let Some(mut attempt) = self.exit_native_ready_attempts.remove(&attempt_id) else {
            return;
        };
        if attempt.probe_tasks.len() != attempt.exit_leases.len()
            || attempt.pending_results.len() != attempt.exit_leases.len()
        {
            self.fail_exit_native_result_attempt(attempt).await;
            return;
        }
        let tasks = attempt.probe_tasks.drain().collect::<Vec<_>>();
        let mut challenges = HashMap::with_capacity(tasks.len());
        for (path_id, task) in tasks {
            let Ok(Ok(challenge)) = task.await else {
                self.fail_exit_native_result_attempt(attempt).await;
                return;
            };
            challenges.insert(path_id, challenge);
        }
        let mut lease_commits = attempt
            .exit_leases
            .iter()
            .map(|lease| LeaseCommit {
                lease_handle: lease.lease_handle().as_bytes().to_vec(),
                path_id: lease.path_id(),
                role: WireguardRole::Exit as i32,
            })
            .collect::<Vec<_>>();
        lease_commits.sort_unstable_by_key(|lease| lease.path_id);
        let commit_request = CommitLeaseBatch {
            route_context_id: attempt_id.to_vec(),
            context_handle: attempt.helper_owner.prepared().context_handle.clone(),
            leases: lease_commits,
        };
        let Ok(committed) = self
            .helper
            .commit_lease_batch(&mut attempt.helper_owner, commit_request)
            .await
        else {
            self.fail_exit_native_result_attempt(attempt).await;
            return;
        };
        if committed.leases.len() != attempt.exit_leases.len() {
            self.fail_exit_native_result_attempt(attempt).await;
            return;
        }
        let helper_runtime_id = attempt.helper_owner.helper_runtime_id();
        let Ok(_destroyed) = self.helper.destroy_context(&attempt.helper_owner).await else {
            self.fail_exit_native_result_attempt(attempt).await;
            return;
        };
        let mut responses = Vec::with_capacity(attempt.pending_results.len());
        let mut pending_results = attempt.pending_results.into_values().collect::<Vec<_>>();
        pending_results.sort_unstable_by_key(|pending| pending.path_id);
        for pending in pending_results {
            let Some(exit_lease) = attempt
                .exit_leases
                .iter()
                .find(|lease| lease.path_id() == pending.path_id)
            else {
                return;
            };
            let Some(lease) = committed
                .leases
                .iter()
                .find(|lease| lease.lease_handle == exit_lease.lease_handle().as_bytes())
            else {
                return;
            };
            let Some(challenge) = challenges.remove(&pending.path_id) else {
                return;
            };
            let measured_at_ms = unix_millis();
            let identity = &self.identity;
            let accepted = self.exit_service.as_mut().and_then(|service| {
                service
                    .issue_native_probe_result_from_observation_with(
                        pending.probe_id,
                        &pending.authenticated_data_relay_node_id,
                        &pending.authenticated_data_relay.to_bytes(),
                        helper_runtime_id,
                        attempt_id,
                        challenge,
                        pending.observed_network_prefix.clone(),
                        lease.latest_handshake_unix,
                        lease.received_bytes,
                        lease.transmitted_bytes,
                        measured_at_ms,
                        self.local_public_key,
                        |message| identity.sign(message).ok(),
                    )
                    .ok()
            });
            let Some(accepted) = accepted else {
                return;
            };
            let evidence_id: [u8; 32] = Sha256::digest(accepted.encoded()).into();
            let evidence = RecentNativeExitEvidence {
                evidence_id,
                scope: pending.scope.clone(),
                authenticated_data_relay_node_id: pending.authenticated_data_relay_node_id,
                authenticated_data_relay_peer_id: pending.authenticated_data_relay.to_bytes(),
                measured_at_ms,
                expires_at_ms: pending.scope.attempt_expires_at_ms,
            };
            let Ok(response) = ExitForwardResponse::granted(
                pending.forward_id.to_vec(),
                ExitForwardOperation::NativeProbeResult,
                self.local_node_id.to_vec(),
                local_peer.to_bytes(),
                vec![accepted.encoded().to_vec()],
            ) else {
                return;
            };
            responses.push((pending, response.into(), evidence));
        }
        for (pending, response, evidence) in responses {
            if self
                .service
                .send_native_probe_result_response(
                    pending.connection,
                    pending.authenticated_data_relay,
                    pending.channel,
                    response,
                )
                .is_ok()
            {
                self.recent_native_exit_evidence
                    .retain(|entry| entry.expires_at_ms > evidence.measured_at_ms);
                if self.recent_native_exit_evidence.len() >= MAX_RECENT_NATIVE_EVIDENCE {
                    self.recent_native_exit_evidence.remove(0);
                }
                self.recent_native_exit_evidence.push(evidence);
            }
        }
        log_relay_forward_admission(Some(state), "NATIVE_PROBE_RESULT_EXIT_RESPONDED");
    }

    async fn fail_exit_native_result_attempt(&mut self, mut attempt: ExitNativeReadyAttempt) {
        for task in attempt.probe_tasks.drain().map(|(_, task)| task) {
            task.abort();
        }
        let _ = self.helper.destroy_context(&attempt.helper_owner).await;
        for pending in attempt.pending_results.into_values() {
            if let Ok(response) = ExitForwardResponse::unavailable(
                pending.forward_id.to_vec(),
                ExitForwardOperation::NativeProbeResult,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ) {
                let _ = self.service.send_native_probe_result_response(
                    pending.connection,
                    pending.authenticated_data_relay,
                    pending.channel,
                    response.into(),
                );
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one Exit helper Prepare and affine readiness response remain a single transaction"
    )]
    async fn answer_native_probe_ready_upstream(
        &mut self,
        authenticated_data_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Ok(response) = ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::NativeProbeReady,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    let _ = self
                        .service
                        .send_exit_forward_upstream_response(channel, response.into());
                }
                return;
            }};
        }
        let now_ms = unix_millis();
        if request.validate().is_err()
            || !deadline_is_bounded(request.deadline_unix_ms(), now_ms)
            || !self.roles.exit
        {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        }
        let Ok(forward) = decode_canonical::<NativeProbeReadyForwardRequest>(
            request.canonical_request(),
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            reject!("NATIVE_PROBE_READY_EXIT_FRAME_REJECTED");
        };
        let Some(relay_exit_endpoint) = forward.relay_exit_endpoint().cloned() else {
            reject!("NATIVE_PROBE_READY_EXIT_FRAME_REJECTED");
        };
        let Ok(permit) = verify_native_probe_permit(
            forward.signed_permit_request().to_vec(),
            forward.signed_permit().to_vec(),
            now_ms,
            &mut self.replay,
        ) else {
            reject!("NATIVE_PROBE_READY_EXIT_PERMIT_REJECTED");
        };
        let scope = permit.scope().clone();
        if forward.validate().is_err()
            || relay_exit_endpoint.path_id != scope.candidate_ordinal
            || relay_exit_endpoint.route_context_id != scope.attempt_id
            || relay_exit_endpoint
                .endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.validate("native Exit traversal endpoint").is_err())
        {
            reject!("NATIVE_PROBE_READY_EXIT_FRAME_REJECTED");
        }
        let Some(data_relay) = scope.data_relay.as_ref() else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        let Some(exit) = scope.exit.as_ref() else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        let Some(data_relay_node_id) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        let Some(data_relay_public_key) = fixed_bytes::<32>(request.control_relay_public_key())
        else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        let local_peer = *self.service.local_peer_id();
        if request.validated_operation() != Ok(ExitForwardOperation::NativeProbeReady)
            || request.forward_id() != scope.probe_id
            || !native_rpc_deadline_is_within_authority(
                request.deadline_unix_ms(),
                scope.attempt_expires_at_ms,
            )
            || request.control_relay_peer_id() != authenticated_data_relay.to_bytes()
            || request.exit_node_id() != self.local_node_id
            || request.exit_peer_id() != local_peer.to_bytes()
            || data_relay.node_id.as_slice() != data_relay_node_id
            || data_relay.public_key.as_slice() != data_relay_public_key
            || !local_native_probe_exit_actor_is_served(
                &self.service,
                exit,
                &scope,
                self.local_node_id,
                local_peer,
                self.local_public_key,
                now_ms,
            )
        {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        }
        // This capability serves another Client's signed route at our Exit. It must not enter
        // this node's own Client candidate/provenance cache or inherit that Client's conflicts.
        let Some(authorized_data_relay) = cache_exit_data_relay_capability(
            &mut self.exit_data_relays,
            self.candidate_limit,
            forward.signed_relay_advertisement(),
            data_relay,
            &scope,
            authenticated_data_relay,
            now_ms,
        ) else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        if self
            .service
            .bind_native_probe_data_relay_connection(authenticated_data_relay, connection_id)
            .is_err()
        {
            reject!("NATIVE_PROBE_READY_EXIT_CONNECTION_REJECTED");
        }
        self.collect_exit_native_ready(
            native_ready::PendingExitNativeReady {
                authenticated_data_relay,
                connection_id,
                request: request.clone(),
                forward,
                scope,
                authorized_data_relay,
                data_relay_node_id,
                channel,
            },
            state,
        )
        .await;
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one shared Exit helper Prepare and affine per-path response transaction"
    )]
    async fn finish_exit_native_ready(
        &mut self,
        pending: native_ready::PendingExitNativeReady,
        prepare: PrepareLeaseBatch,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let native_ready::PendingExitNativeReady {
            authenticated_data_relay,
            connection_id,
            request,
            forward,
            scope,
            authorized_data_relay,
            data_relay_node_id,
            channel,
        } = pending;
        macro_rules! reject {
            ($code:literal) => {{
                log_relay_forward_admission(Some(state), $code);
                if let Ok(response) = ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::NativeProbeReady,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    let _ = self
                        .service
                        .send_exit_forward_upstream_response(channel, response.into());
                }
                return;
            }};
        }
        let now_ms = unix_millis();
        let local_peer = *self.service.local_peer_id();
        let Some(relay_exit_endpoint) = forward.relay_exit_endpoint().cloned() else {
            reject!("NATIVE_PROBE_READY_EXIT_FRAME_REJECTED");
        };
        let Some(attempt_id) = fixed_bytes::<FORWARD_ID_BYTES>(&scope.attempt_id) else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        let Some(candidate_set_hash) = fixed_bytes::<32>(&scope.candidate_set_hash) else {
            reject!("NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED");
        };
        if self
            .exit_native_ready_attempts
            .get(&attempt_id)
            .is_some_and(|attempt| {
                !native_exit_ready_prepare_matches(attempt.helper_owner.prepare(), &prepare, now_ms)
                    || attempt.candidate_set_hash != candidate_set_hash
                    || attempt.expires_at_ms != scope.attempt_expires_at_ms
                    || attempt.ready_paths.contains(&scope.candidate_ordinal)
            })
        {
            reject!("NATIVE_PROBE_READY_EXIT_OWNER_CONFLICT");
        }
        if !self.exit_native_ready_attempts.contains_key(&attempt_id) {
            if self.exit_native_ready_attempts.len() >= MAX_CONCURRENT_FORWARDING_STREAMS {
                reject!("NATIVE_PROBE_READY_EXIT_CAPACITY");
            }
            let Ok(helper_owner) = self.helper.prepare_lease_batch(prepare.clone()).await else {
                reject!("NATIVE_PROBE_READY_EXIT_HELPER_PREPARE_UNAVAILABLE");
            };
            let Ok(exit_batch) =
                bind_prepared_exit_endpoint_leases(&prepare, helper_owner.prepared().clone())
            else {
                let _ = self.helper.destroy_context(&helper_owner).await;
                reject!("NATIVE_PROBE_READY_EXIT_HELPER_BIND_REJECTED");
            };
            let previous = self.exit_native_ready_attempts.insert(
                attempt_id,
                ExitNativeReadyAttempt {
                    helper_owner,
                    exit_leases: exit_batch.exit_leases().to_vec(),
                    authorized_data_relays: HashMap::with_capacity(
                        usize::try_from(scope.required_path_count).unwrap_or(0),
                    ),
                    ready_paths: HashSet::with_capacity(
                        usize::try_from(scope.required_path_count).unwrap_or(0),
                    ),
                    pending_activations: HashMap::with_capacity(
                        usize::try_from(scope.required_path_count).unwrap_or(0),
                    ),
                    activated: false,
                    probe_tasks: HashMap::with_capacity(
                        usize::try_from(scope.required_path_count).unwrap_or(0),
                    ),
                    pending_results: HashMap::with_capacity(
                        usize::try_from(scope.required_path_count).unwrap_or(0),
                    ),
                    candidate_set_hash,
                    expires_at_ms: scope.attempt_expires_at_ms,
                    cleanup_not_before_ms: 0,
                },
            );
            debug_assert!(
                previous.is_none(),
                "native Exit attempt already checked vacant"
            );
        }
        let Some((helper_runtime_id, exit_lease)) = self
            .exit_native_ready_attempts
            .get(&attempt_id)
            .and_then(|attempt| {
                attempt
                    .exit_leases
                    .iter()
                    .find(|lease| lease.path_id() == scope.candidate_ordinal)
                    .copied()
                    .map(|lease| (attempt.helper_owner.helper_runtime_id(), lease))
            })
        else {
            if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                self.destroy_helper_owner(attempt.helper_owner);
            }
            reject!("NATIVE_PROBE_READY_EXIT_HELPER_BIND_REJECTED");
        };
        let Some(connection) = self
            .service
            .bind_native_probe_data_relay_connection(authenticated_data_relay, connection_id)
            .ok()
        else {
            if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                self.destroy_helper_owner(attempt.helper_owner);
            }
            reject!("NATIVE_PROBE_READY_EXIT_CONNECTION_REJECTED");
        };
        let identity = &self.identity;
        let accepted = self.exit_service.as_mut().and_then(|service| {
            service
                .issue_native_probe_ready_from_permit_with(
                    forward.signed_permit_request(),
                    forward.signed_permit(),
                    &data_relay_node_id,
                    &authenticated_data_relay.to_bytes(),
                    relay_exit_endpoint,
                    helper_runtime_id,
                    exit_lease,
                    now_ms,
                    self.local_public_key,
                    |message| identity.sign(message).ok(),
                )
                .ok()
        });
        let Some(accepted) = accepted else {
            reject!("NATIVE_PROBE_READY_EXIT_SERVICE_REJECTED");
        };
        let Some(attempt) = self.exit_native_ready_attempts.get_mut(&attempt_id) else {
            reject!("NATIVE_PROBE_READY_EXIT_OWNER_CONFLICT");
        };
        if attempt
            .authorized_data_relays
            .insert(scope.candidate_ordinal, authorized_data_relay)
            .is_some()
            || !attempt.ready_paths.insert(scope.candidate_ordinal)
        {
            reject!("NATIVE_PROBE_READY_EXIT_OWNER_CONFLICT");
        }
        let response = ExitForwardResponse::granted(
            request.forward_id().to_vec(),
            ExitForwardOperation::NativeProbeReady,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            vec![accepted.encoded().to_vec()],
        );
        let Ok(response) = response else {
            if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                self.destroy_helper_owner(attempt.helper_owner);
            }
            reject!("NATIVE_PROBE_READY_EXIT_FRAME_REJECTED");
        };
        if self
            .service
            .send_native_probe_ready_response(
                connection,
                authenticated_data_relay,
                channel,
                response.into(),
            )
            .is_err()
        {
            if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                self.destroy_helper_owner(attempt.helper_owner);
            }
            log_relay_forward_admission(
                Some(state),
                "NATIVE_PROBE_READY_EXIT_RESPONSE_UNAVAILABLE",
            );
            return;
        }
        log_relay_forward_admission(Some(state), "NATIVE_PROBE_READY_EXIT_RESPONDED");
    }

    fn send_prepared_native_probe_authorization_response(
        &mut self,
        prepared: PreparedNativeProbeAuthorizationResponse,
    ) {
        let PreparedNativeProbeAuthorizationResponse {
            connection,
            authenticated_data_relay,
            channel,
            response,
        } = prepared;
        let _ = self.service.send_native_probe_authorization_response(
            connection,
            authenticated_data_relay,
            channel,
            response,
        );
    }

    async fn ingest_client_forwarded_advertisement(
        &mut self,
        pending: &PendingClientForward,
        response: &ExitForwardResponse,
        state: &Arc<RwLock<AgentState>>,
    ) -> ForwardedAdvertisementIngest {
        if !exit_response_matches(
            response,
            pending.key.forward_id,
            pending.operation,
            pending.expected_exit_peer,
            pending.expected_exit_node_id,
        ) {
            return ForwardedAdvertisementIngest::invalid();
        }
        if pending.operation != ExitForwardOperation::FetchExitAdvertisement
            || response.validated_status() != Ok(ForwardStatus::Granted)
        {
            return ForwardedAdvertisementIngest::valid_without_advertisement();
        }
        let Ok(request) = decode_canonical::<ExitForwardRequest>(
            &pending.canonical_request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        ) else {
            return ForwardedAdvertisementIngest::invalid();
        };
        let Some(control_relay_node_id) = fixed_bytes::<32>(request.control_relay_node_id()) else {
            return ForwardedAdvertisementIngest::invalid();
        };
        let Some(exit_node_id) = fixed_bytes::<32>(response.exit_node_id()) else {
            return ForwardedAdvertisementIngest::invalid();
        };
        let Ok(advertisement) = AdvertisementResponse::new(response.signed_responses()[0].clone())
        else {
            return ForwardedAdvertisementIngest::invalid();
        };
        let exit_peer = pending.expected_exit_peer;
        let provenance = AdvertisementProvenance::ForwardedExit {
            control_relay_node_id,
            control_relay_peer: pending.key.control_relay_peer,
            exit_node_id,
            exit_peer,
            request_deadline_ms: pending.operation_expires_at_ms,
            authority: Box::new(ForwardedIngestAuthority {
                authorized_control: pending.authorized_control.clone(),
                attempt_deadline: pending.attempt_deadline,
                operation_expires_at_ms: pending.operation_expires_at_ms,
            }),
        };
        let commit = self
            .stage_advertisement_commit(
                PreparedAdvertisementCommit {
                    peer: exit_peer,
                    provenance,
                    envelope: advertisement.signed_envelope().to_vec(),
                },
                state,
            )
            .await;
        ForwardedAdvertisementIngest::from_commit(commit)
    }

    fn forwarded_ingest_authority_is_current(
        &self,
        provenance: &AdvertisementProvenance,
        clock: AdvertisementCommitClock,
    ) -> bool {
        let AdvertisementProvenance::ForwardedExit {
            control_relay_node_id,
            control_relay_peer,
            exit_peer,
            request_deadline_ms,
            authority,
            ..
        } = provenance
        else {
            return true;
        };
        if authority.attempt_deadline <= clock.monotonic
            || authority.operation_expires_at_ms <= clock.unix_ms
            || authority.operation_expires_at_ms != *request_deadline_ms
            || authority.authorized_control.node_id != *control_relay_node_id
            || authority.authorized_control.peer_id != *control_relay_peer
        {
            return false;
        }
        let current = if *control_relay_peer == *self.service.local_peer_id() {
            self.local_relay_snapshot.as_ref()
        } else {
            self.direct_relays.get(control_relay_peer)
        };
        current.is_some_and(|current| {
            direct_relay_authority_lineage_matches(
                current,
                &authority.authorized_control,
                *request_deadline_ms,
            ) && direct_relay_target_matches(
                current,
                *control_relay_node_id,
                *control_relay_peer,
                *request_deadline_ms,
            )
        }) && self.forwarded_exit_authority_is_eligible(
            *control_relay_peer,
            *exit_peer,
            clock.unix_ms,
        ) && (*control_relay_peer == *self.service.local_peer_id()
            || self.peer_is_forwarded_exit_target(*exit_peer, clock.unix_ms))
    }

    async fn ingest_advertisement(
        &mut self,
        peer: Libp2pPeerId,
        response: AdvertisementResponse,
        provenance: AdvertisementProvenance,
        state: &Arc<RwLock<AgentState>>,
    ) -> Option<AcceptedAdvertisement> {
        let outcome = self
            .stage_advertisement_commit(
                PreparedAdvertisementCommit {
                    peer,
                    provenance,
                    envelope: response.signed_envelope().to_vec(),
                },
                state,
            )
            .await;
        let accepted = outcome.accepted_advertisement();
        self.finish_advertisement_commit(&outcome, state).await;
        accepted
    }

    async fn finish_advertisement_commit(
        &mut self,
        outcome: &AdvertisementCommitOutcome,
        state: &Arc<RwLock<AgentState>>,
    ) {
        #[cfg(test)]
        if let Some(gate) = self
            .advertisement_commit_test_barriers
            .before_finish
            .clone()
        {
            gate.pause().await;
        }

        if let Some((level, code, timestamp_ms)) = outcome.diagnostic {
            state.write().await.log(level, code, timestamp_ms);
        }
        if outcome.refresh_candidates {
            self.refresh_candidates(state).await;
            self.schedule_exit_advertisement_fetches();
        }
    }

    async fn stage_advertisement_commit(
        &mut self,
        prepared: PreparedAdvertisementCommit,
        state: &Arc<RwLock<AgentState>>,
    ) -> AdvertisementCommitOutcome {
        #[cfg(test)]
        if let Some(gate) = self
            .advertisement_commit_test_barriers
            .before_commit
            .clone()
        {
            gate.pause().await;
        }

        let state_guard = state.read().await;
        let outcome = self.commit_advertisement(prepared, &state_guard);
        drop(state_guard);
        #[cfg(test)]
        if let Some(gate) = self.advertisement_commit_test_barriers.after_commit.clone() {
            gate.pause().await;
        }

        outcome
    }

    #[allow(
        clippy::too_many_lines,
        reason = "single synchronous advertisement commit transaction"
    )]
    fn commit_advertisement(
        &mut self,
        prepared: PreparedAdvertisementCommit,
        state: &AgentState,
    ) -> AdvertisementCommitOutcome {
        let PreparedAdvertisementCommit {
            peer,
            provenance,
            envelope,
        } = prepared;
        let now_ms = unix_millis();
        if !advertisement_envelope_matches_peer(&envelope, &peer) {
            return AdvertisementCommitOutcome::rejected(Some((
                LogLevel::Warn,
                "ADVERTISEMENT_PEER_MISMATCH",
                now_ms,
            )));
        }
        let forwarded_control = match &provenance {
            AdvertisementProvenance::DirectRelay { .. } => None,
            AdvertisementProvenance::ForwardedExit {
                control_relay_peer, ..
            } => Some(*control_relay_peer),
        };
        let Ok(mut scratch_replay) = ReplayCache::new(1) else {
            return AdvertisementCommitOutcome::rejected(None);
        };
        let verified = verify_control_message::<WireAdvertisement>(
            &envelope,
            now_ms,
            TimePolicy::default(),
            &mut scratch_replay,
        );
        let Ok(verified) = verified else {
            return AdvertisementCommitOutcome::rejected(Some((
                LogLevel::Warn,
                "ADVERTISEMENT_SIGNATURE_VERIFY_FAILED",
                now_ms,
            )));
        };
        let Some(roles) = verified.message().roles.as_ref() else {
            return AdvertisementCommitOutcome::rejected(None);
        };
        let Some(advertised_policy) = verified.message().policy.as_ref() else {
            return AdvertisementCommitOutcome::rejected(None);
        };
        let Some(policy_hash) = fixed_bytes::<32>(&advertised_policy.whitelist_hash) else {
            return AdvertisementCommitOutcome::rejected(None);
        };
        if verified.message().peer_id != peer.to_bytes() {
            return AdvertisementCommitOutcome::rejected(None);
        }
        let Some(fingerprint) = advertisement_fingerprint(&envelope) else {
            return AdvertisementCommitOutcome::rejected(None);
        };
        let Ok(advertisement) =
            convert_advertisement(verified.message(), UnixTime::from_secs(now_ms / 1_000))
        else {
            return AdvertisementCommitOutcome::rejected(Some((
                LogLevel::Warn,
                "ADVERTISEMENT_CORE_REJECTED",
                now_ms,
            )));
        };

        let clock = AdvertisementCommitClock::now();
        let policy = state.policy_snapshot(clock.unix_ms);
        let active_policy_hash = fixed_bytes::<32>(&policy.policy_hash);
        let policy_matches = policy.active
            && advertised_policy.whitelist_version == policy.manifest_version
            && active_policy_hash == Some(policy_hash)
            && policy.expires_at_ms > clock.unix_ms
            && verified.expires_at_ms() > clock.unix_ms;
        if !policy_matches {
            return AdvertisementCommitOutcome::rejected(None);
        }
        let accepted = AcceptedAdvertisement {
            node_id: *verified.sender_id(),
            peer_id: peer,
            public_key: *verified.sender_public_key(),
            sequence_number: verified.message().sequence_number,
            advertisement_expires_at_ms: verified.expires_at_ms(),
            policy_version: advertised_policy.whitelist_version,
            policy_hash,
            policy_expires_at_ms: policy.expires_at_ms,
            expires_at_ms: verified.expires_at_ms().min(policy.expires_at_ms),
        };
        if let Some(record) = self.accepted_advertisements.get(&accepted.node_id) {
            if record.expires_at_ms > clock.unix_ms
                && (accepted.sequence_number < record.sequence_number
                    || (accepted.sequence_number == record.sequence_number
                        && fingerprint != record.fingerprint))
            {
                return AdvertisementCommitOutcome::rejected(Some((
                    LogLevel::Debug,
                    "ADVERTISEMENT_STORE_REJECTED",
                    clock.unix_ms,
                )));
            }
        }

        if !self.forwarded_ingest_authority_is_current(&provenance, clock) {
            return AdvertisementCommitOutcome::rejected(None);
        }
        match &provenance {
            AdvertisementProvenance::DirectRelay { authenticated_peer } => {
                if *authenticated_peer != peer {
                    return AdvertisementCommitOutcome::rejected(None);
                }
            }
            AdvertisementProvenance::ForwardedExit {
                control_relay_node_id,
                control_relay_peer,
                exit_node_id,
                exit_peer,
                request_deadline_ms,
                authority,
            } => {
                let control = &authority.authorized_control;
                let control_policy_matches = control.policy_version == accepted.policy_version
                    && control.policy_hash == accepted.policy_hash
                    && control.policy_expires_at_ms == accepted.policy_expires_at_ms;
                if *exit_peer != peer
                    || *exit_node_id != accepted.node_id
                    || *control_relay_peer == peer
                    || *control_relay_node_id == accepted.node_id
                    || !deadline_is_bounded(*request_deadline_ms, clock.unix_ms)
                    || !control_policy_matches
                {
                    return AdvertisementCommitOutcome::rejected(None);
                }
            }
        }

        self.purge_completed_at(clock.unix_ms);
        if let Some(control_relay_peer) = forwarded_control {
            let replay_key = ForwardedAdvertisementReplayKey {
                control_relay_peer,
                exit_sender_id: *verified.sender_id(),
                nonce: *verified.nonce(),
            };
            let replayed = self
                .forwarded_ad_replays
                .get(&replay_key)
                .is_some_and(|expires_at_ms| *expires_at_ms > clock.unix_ms);
            let active_replays = self
                .forwarded_ad_replays
                .values()
                .filter(|expires_at_ms| **expires_at_ms > clock.unix_ms)
                .count();
            if replayed || active_replays >= self.forwarded_replay_capacity {
                return AdvertisementCommitOutcome::rejected(Some((
                    LogLevel::Warn,
                    "ADVERTISEMENT_FORWARDED_REPLAY_REJECTED",
                    clock.unix_ms,
                )));
            }
            self.forwarded_ad_replays
                .retain(|_, expires_at_ms| *expires_at_ms > clock.unix_ms);
            self.forwarded_ad_replays
                .insert(replay_key, verified.expires_at_ms());
        } else if verify_control_message::<WireAdvertisement>(
            &envelope,
            clock.unix_ms,
            TimePolicy::default(),
            &mut self.replay,
        )
        .is_err()
        {
            return AdvertisementCommitOutcome::rejected(Some((
                LogLevel::Warn,
                "ADVERTISEMENT_DIRECT_REPLAY_REJECTED",
                clock.unix_ms,
            )));
        }

        let now_ms = clock.unix_ms;

        let mut removed_expiry = None;
        let capability_expiry_ms = match &provenance {
            AdvertisementProvenance::DirectRelay { authenticated_peer } => {
                if *authenticated_peer == peer {
                    removed_expiry = self.revoke_for_direct_advertisement(
                        peer,
                        &accepted,
                        roles.relay && policy_matches,
                        false,
                    );
                    if roles.relay && policy_matches {
                        accepted.expires_at_ms
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            AdvertisementProvenance::ForwardedExit {
                control_relay_node_id,
                control_relay_peer,
                exit_node_id,
                exit_peer,
                request_deadline_ms,
                ..
            } => {
                let control = if *control_relay_peer == *self.service.local_peer_id() {
                    self.local_relay_snapshot.clone()
                } else {
                    self.direct_relays.get(control_relay_peer).cloned()
                };
                let stale_keys = self
                    .forwarded_exits
                    .iter()
                    .filter_map(|(candidate, capability)| {
                        (candidate.exit_peer == peer
                            && capability.exit_advertisement_sequence < accepted.sequence_number)
                            .then_some(*candidate)
                    })
                    .collect::<Vec<_>>();
                removed_expiry = self.revoke_forwarded_keys(&stale_keys, true);
                let control_valid = control.as_ref().is_some_and(|control| {
                    direct_relay_target_matches(
                        control,
                        *control_relay_node_id,
                        *control_relay_peer,
                        *request_deadline_ms,
                    ) && control.policy_version == accepted.policy_version
                        && control.policy_hash == accepted.policy_hash
                        && control.policy_expires_at_ms == accepted.policy_expires_at_ms
                });
                if *exit_peer != peer
                    || *exit_node_id != accepted.node_id
                    || !roles.exit
                    || !policy_matches
                    || *control_relay_peer == peer
                    || *control_relay_node_id == accepted.node_id
                    || !deadline_is_bounded(*request_deadline_ms, now_ms)
                    || !control_valid
                    || !self.forwarded_exit_authority_is_eligible(*control_relay_peer, peer, now_ms)
                    || (*control_relay_peer != *self.service.local_peer_id()
                        && !self.peer_is_forwarded_exit_target(peer, now_ms))
                {
                    0
                } else {
                    accepted.expires_at_ms.min(
                        control
                            .as_ref()
                            .map_or(0, |capability| capability.expires_at_ms),
                    )
                }
            }
        };

        let actor_record_exact = self
            .accepted_advertisements
            .get(&accepted.node_id)
            .is_some_and(|record| {
                record.sequence_number == accepted.sequence_number
                    && record.fingerprint == fingerprint
            });
        let new_record = !self.accepted_advertisements.contains_key(&accepted.node_id);
        let new_capability = match &provenance {
            AdvertisementProvenance::DirectRelay { .. } => !self.direct_relays.contains_key(&peer),
            AdvertisementProvenance::ForwardedExit {
                control_relay_peer,
                exit_peer,
                ..
            } => !self.forwarded_exits.contains_key(&ForwardedExitKey {
                control_relay_peer: *control_relay_peer,
                exit_peer: *exit_peer,
            }),
        };
        let capability_count = self
            .direct_relays
            .len()
            .saturating_add(self.forwarded_exits.len())
            .saturating_add(self.privacy_conflicts.len());
        if (new_record && self.accepted_advertisements.len() >= self.candidate_limit)
            || (capability_expiry_ms > now_ms
                && new_capability
                && capability_count >= self.candidate_limit)
        {
            if matches!(&provenance, AdvertisementProvenance::DirectRelay { .. }) {
                self.record_privacy_conflict(
                    peer,
                    accepted.sequence_number,
                    accepted
                        .advertisement_expires_at_ms
                        .max(removed_expiry.unwrap_or_default()),
                );
            }
            self.rollback_advertisement_replay(&provenance, verified.sender_id(), verified.nonce());
            return AdvertisementCommitOutcome::committed_without_capability(Some((
                LogLevel::Warn,
                "ADVERTISEMENT_PROVENANCE_CAPACITY",
                now_ms,
            )));
        }

        let now = UnixTime::from_secs(now_ms / 1_000);
        if !actor_record_exact
            && self
                .store
                .upsert_advertisement(&advertisement, &envelope, now)
                .is_err()
        {
            if matches!(&provenance, AdvertisementProvenance::DirectRelay { .. }) {
                self.record_privacy_conflict(
                    peer,
                    accepted.sequence_number,
                    accepted
                        .advertisement_expires_at_ms
                        .max(removed_expiry.unwrap_or_default()),
                );
            }
            self.rollback_advertisement_replay(&provenance, verified.sender_id(), verified.nonce());
            return AdvertisementCommitOutcome::committed_without_capability(Some((
                LogLevel::Debug,
                "ADVERTISEMENT_STORE_REJECTED",
                now_ms,
            )));
        }
        self.accepted_advertisements.insert(
            accepted.node_id,
            AcceptedAdvertisementRecord {
                sequence_number: accepted.sequence_number,
                expires_at_ms: accepted.advertisement_expires_at_ms,
                fingerprint,
            },
        );

        if capability_expiry_ms <= now_ms {
            if matches!(&provenance, AdvertisementProvenance::DirectRelay { .. }) {
                self.record_privacy_conflict(
                    peer,
                    accepted.sequence_number,
                    accepted
                        .advertisement_expires_at_ms
                        .max(removed_expiry.unwrap_or_default()),
                );
            }
            return AdvertisementCommitOutcome::committed_without_capability(None);
        }

        let mut diagnostic = None;
        match provenance {
            AdvertisementProvenance::DirectRelay { .. } => {
                self.direct_relays.insert(
                    peer,
                    DirectRelayCapability {
                        node_id: accepted.node_id,
                        peer_id: peer,
                        public_key: accepted.public_key,
                        advertisement_sequence: accepted.sequence_number,
                        advertisement_expires_at_ms: accepted.advertisement_expires_at_ms,
                        advertisement_payload_hash: fingerprint.payload_hash,
                        policy_version: accepted.policy_version,
                        policy_hash: accepted.policy_hash,
                        policy_expires_at_ms: accepted.policy_expires_at_ms,
                        expires_at_ms: capability_expiry_ms,
                    },
                );
                // Identify observations can be transient link addresses. Retain the
                // authenticated relay's own signed listeners as stable dial candidates so a
                // later link flap cannot strand preselection on an obsolete observation.
                // Forwarded Exit advertisements deliberately never reach this branch.
                for endpoint in &advertisement.control_endpoints {
                    if let Ok(address) = Multiaddr::from_str(endpoint) {
                        let _ = self.service.add_known_peer(peer, &address);
                    }
                }
                if removed_expiry.is_some_and(|expiry| expiry > capability_expiry_ms) {
                    self.record_privacy_conflict(
                        peer,
                        accepted.sequence_number,
                        removed_expiry.expect("checked"),
                    );
                }
                if let Some((endpoint, observed_ip)) = self.observed_endpoints.get(&peer) {
                    if self
                        .store
                        .record_endpoint(&advertisement.node_id, endpoint, *observed_ip, true, now)
                        .is_err()
                    {
                        diagnostic = Some((LogLevel::Warn, "PEER_ENDPOINT_STORE_FAILED", now_ms));
                    }
                }
            }
            AdvertisementProvenance::ForwardedExit {
                control_relay_node_id,
                control_relay_peer,
                exit_peer,
                ..
            } => {
                let control = if control_relay_peer == *self.service.local_peer_id() {
                    self.local_relay_snapshot
                        .as_ref()
                        .expect("validated local control snapshot")
                } else {
                    self.direct_relays
                        .get(&control_relay_peer)
                        .expect("validated direct control snapshot")
                };
                self.forwarded_exits.insert(
                    ForwardedExitKey {
                        control_relay_peer,
                        exit_peer,
                    },
                    ForwardedExitCapability {
                        control_relay_node_id,
                        control_relay_peer_id: control_relay_peer,
                        control_relay_public_key: control.public_key,
                        control_relay_advertisement_sequence: control.advertisement_sequence,
                        control_relay_advertisement_expires_at_ms: control
                            .advertisement_expires_at_ms,
                        control_relay_advertisement_payload_hash: control
                            .advertisement_payload_hash,
                        exit_node_id: accepted.node_id,
                        exit_peer_id: exit_peer,
                        exit_public_key: accepted.public_key,
                        exit_advertisement_sequence: accepted.sequence_number,
                        exit_advertisement_expires_at_ms: accepted.advertisement_expires_at_ms,
                        exit_advertisement_payload_hash: fingerprint.payload_hash,
                        policy_version: accepted.policy_version,
                        policy_hash: accepted.policy_hash,
                        policy_expires_at_ms: accepted.policy_expires_at_ms,
                        expires_at_ms: capability_expiry_ms,
                    },
                );
                if !self.preferred_exit_controls.contains_key(&exit_peer)
                    && self.preferred_exit_controls.len() < MAX_EXIT_PROVIDER_PEERS
                {
                    self.preferred_exit_controls
                        .insert(exit_peer, control_relay_peer);
                }
                if control_relay_peer != *self.service.local_peer_id() {
                    let _ = self.mark_forwarded_exit_target(
                        exit_peer,
                        accepted.advertisement_expires_at_ms,
                    );
                }
            }
        }
        AdvertisementCommitOutcome::accepted(accepted, diagnostic)
    }

    fn rollback_advertisement_replay(
        &mut self,
        provenance: &AdvertisementProvenance,
        sender_id: &[u8; 32],
        nonce: &[u8; 32],
    ) {
        match provenance {
            AdvertisementProvenance::DirectRelay { .. } => {
                let _ = self.replay.rollback(sender_id, nonce);
            }
            AdvertisementProvenance::ForwardedExit {
                control_relay_peer, ..
            } => {
                self.forwarded_ad_replays
                    .remove(&ForwardedAdvertisementReplayKey {
                        control_relay_peer: *control_relay_peer,
                        exit_sender_id: *sender_id,
                        nonce: *nonce,
                    });
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "atomic cross-ledger privacy revocation"
    )]
    fn revoke_for_direct_advertisement(
        &mut self,
        peer: Libp2pPeerId,
        accepted: &AcceptedAdvertisement,
        relay_authorized: bool,
        force_control_revoke: bool,
    ) -> Option<u64> {
        let local_control_peer = *self.service.local_peer_id();
        let exit_authority_changed = force_control_revoke
            || self.forwarded_exits.iter().any(|(key, capability)| {
                key.control_relay_peer == local_control_peer
                    && key.exit_peer == peer
                    && (capability.exit_node_id != accepted.node_id
                        || capability.exit_peer_id != accepted.peer_id
                        || capability.exit_public_key != accepted.public_key
                        || capability.policy_version != accepted.policy_version
                        || capability.policy_hash != accepted.policy_hash
                        || capability.policy_expires_at_ms != accepted.policy_expires_at_ms)
            });
        let control_authority_changed = force_control_revoke
            || !relay_authorized
            || self.direct_relays.get(&peer).is_some_and(|current| {
                current.node_id != accepted.node_id
                    || current.peer_id != accepted.peer_id
                    || current.public_key != accepted.public_key
                    || current.policy_version != accepted.policy_version
                    || current.policy_hash != accepted.policy_hash
                    || current.policy_expires_at_ms != accepted.policy_expires_at_ms
            });
        self.preferred_exit_controls.remove(&peer);
        if control_authority_changed {
            self.preferred_exit_controls
                .retain(|_, control_peer| *control_peer != peer);
        }
        let mut keys = self
            .forwarded_exits
            .iter()
            .filter_map(|(key, capability)| {
                let target_conflict = key.exit_peer == peer
                    && (key.control_relay_peer != local_control_peer || exit_authority_changed);
                let control_changed = key.control_relay_peer == peer
                    && control_authority_changed
                    && (!relay_authorized
                        || capability.control_relay_node_id != accepted.node_id
                        || capability.control_relay_public_key != accepted.public_key
                        || capability.control_relay_advertisement_sequence
                            != accepted.sequence_number
                        || capability.policy_version != accepted.policy_version
                        || capability.policy_hash != accepted.policy_hash
                        || capability.policy_expires_at_ms != accepted.policy_expires_at_ms);
                (target_conflict || control_changed).then_some(*key)
            })
            .collect::<Vec<_>>();
        for pending in self.pending_client_forwards.values() {
            if pending.expected_exit_peer == peer
                || (control_authority_changed && pending.key.control_relay_peer == peer)
            {
                let key = ForwardedExitKey {
                    control_relay_peer: pending.key.control_relay_peer,
                    exit_peer: pending.expected_exit_peer,
                };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        for pending in self.pending_relay_forwards.values() {
            if (pending.expected_exit_peer == peer && exit_authority_changed)
                || (control_authority_changed && pending.authorized_control.peer_id == peer)
            {
                let key = ForwardedExitKey {
                    control_relay_peer: pending.authorized_control.peer_id,
                    exit_peer: pending.expected_exit_peer,
                };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        for (key, entry) in &self.retry_client_forwards {
            if entry.target_peer == peer
                || (control_authority_changed && key.control_relay_peer == peer)
            {
                let capability_key = ForwardedExitKey {
                    control_relay_peer: key.control_relay_peer,
                    exit_peer: entry.target_peer,
                };
                if !keys.contains(&capability_key) {
                    keys.push(capability_key);
                }
            }
        }
        for entry in self.retry_relay_forwards.values() {
            if (entry.target_peer == peer && exit_authority_changed)
                || (control_authority_changed && local_control_peer == peer)
            {
                let key = ForwardedExitKey {
                    control_relay_peer: local_control_peer,
                    exit_peer: entry.target_peer,
                };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        for (key, entry) in &self.completed_client_forwards {
            if entry.target_peer == peer
                || (control_authority_changed && key.control_relay_peer == peer)
            {
                let capability_key = ForwardedExitKey {
                    control_relay_peer: key.control_relay_peer,
                    exit_peer: entry.target_peer,
                };
                if !keys.contains(&capability_key) {
                    keys.push(capability_key);
                }
            }
        }
        for entry in self.completed_relay_forwards.values() {
            if (entry.target_peer == peer && exit_authority_changed)
                || (control_authority_changed && local_control_peer == peer)
            {
                let key = ForwardedExitKey {
                    control_relay_peer: local_control_peer,
                    exit_peer: entry.target_peer,
                };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        let removed_expiry = self.revoke_forwarded_keys(&keys, false);
        if control_authority_changed {
            self.direct_relays.remove(&peer);
            self.revoke_datapath_authority(peer);
        }
        removed_expiry
    }

    fn revoke_datapath_authority(&mut self, peer: Libp2pPeerId) {
        let pending_ids = self
            .pending_datapath
            .iter()
            .filter_map(|(id, pending)| (pending.key.relay_peer == peer).then_some(*id))
            .collect::<Vec<_>>();
        for id in pending_ids {
            if let Some(pending) = self.pending_datapath.remove(&id) {
                self.datapath_index.remove(&pending.key);
                self.finish_datapath_definitive_error(
                    pending,
                    OutboundReservationError::InvalidResponse,
                );
            }
        }
        let retry_keys = self
            .retry_datapath
            .keys()
            .filter(|key| key.relay_peer == peer)
            .copied()
            .collect::<Vec<_>>();
        for key in retry_keys {
            if let Some(entry) = self.retry_datapath.remove(&key) {
                let reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
                self.completed_datapath.insert(
                    key,
                    CompletedDatapath {
                        canonical_request: entry.canonical_request,
                        outcome: Err(OutboundReservationError::InvalidResponse),
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes,
                    },
                );
            }
        }
        for (key, entry) in &mut self.completed_datapath {
            if key.relay_peer == peer {
                entry.outcome = Err(OutboundReservationError::InvalidResponse);
                entry.reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "atomic cross-ledger authority revocation"
    )]
    fn revoke_forwarded_keys(
        &mut self,
        keys: &[ForwardedExitKey],
        preserve_fetch_attempts: bool,
    ) -> Option<u64> {
        if keys.is_empty() {
            return None;
        }
        let local_control_peer = *self.service.local_peer_id();
        let removed_expiry = self
            .forwarded_exits
            .iter()
            .filter_map(|(key, capability)| {
                keys.contains(key).then_some(
                    capability
                        .control_relay_advertisement_expires_at_ms
                        .max(capability.exit_advertisement_expires_at_ms),
                )
            })
            .max();
        self.forwarded_exits.retain(|key, _| !keys.contains(key));

        let client_ids = self
            .pending_client_forwards
            .iter()
            .filter_map(|(id, pending)| {
                ((!preserve_fetch_attempts
                    || pending.operation != ExitForwardOperation::FetchExitAdvertisement)
                    && keys.contains(&ForwardedExitKey {
                        control_relay_peer: pending.key.control_relay_peer,
                        exit_peer: pending.expected_exit_peer,
                    }))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in client_ids {
            if let Some(pending) = self.pending_client_forwards.remove(&id) {
                self.client_forward_index.remove(&pending.key);
                self.finish_client_definitive_error(
                    pending,
                    OutboundReservationError::InvalidResponse,
                );
            }
        }
        let relay_ids = self
            .pending_relay_forwards
            .iter()
            .filter_map(|(id, pending)| {
                (pending.udp_session.is_none()
                    && pending.mptcp_session.is_none()
                    && pending.mpquic_session.is_none()
                    && (!preserve_fetch_attempts
                        || pending.operation != ExitForwardOperation::FetchExitAdvertisement)
                    && keys.contains(&ForwardedExitKey {
                        control_relay_peer: pending.authorized_control.peer_id,
                        exit_peer: pending.expected_exit_peer,
                    }))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in relay_ids {
            if let Some(pending) = self.pending_relay_forwards.remove(&id) {
                self.relay_forward_index.remove(&pending.key);
                self.finish_relay_definitive(pending);
            }
        }

        let retry_client_keys = self
            .retry_client_forwards
            .iter()
            .filter_map(|(key, entry)| {
                ((!preserve_fetch_attempts
                    || entry.operation != Some(ExitForwardOperation::FetchExitAdvertisement))
                    && keys.contains(&ForwardedExitKey {
                        control_relay_peer: key.control_relay_peer,
                        exit_peer: entry.target_peer,
                    }))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in retry_client_keys {
            if let Some(entry) = self.retry_client_forwards.remove(&key) {
                let reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
                self.completed_client_forwards.insert(
                    key,
                    CompletedClientForward {
                        canonical_request: entry.canonical_request,
                        target_peer: entry.target_peer,
                        operation: entry.operation.expect("client retry operation"),
                        outcome: Err(OutboundReservationError::InvalidResponse),
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes,
                    },
                );
            }
        }
        let retry_relay_keys = self
            .retry_relay_forwards
            .iter()
            .filter_map(|(key, entry)| {
                ((!preserve_fetch_attempts
                    || entry.operation != Some(ExitForwardOperation::FetchExitAdvertisement))
                    && keys.contains(&ForwardedExitKey {
                        control_relay_peer: local_control_peer,
                        exit_peer: entry.target_peer,
                    }))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in retry_relay_keys {
            if let Some(entry) = self.retry_relay_forwards.remove(&key) {
                let reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
                self.completed_relay_forwards.insert(
                    key,
                    CompletedRelayForward {
                        canonical_request: entry.canonical_request,
                        target_peer: entry.target_peer,
                        operation: entry.operation.expect("relay retry operation"),
                        response: None,
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes,
                    },
                );
            }
        }
        for (key, entry) in &mut self.completed_client_forwards {
            if keys.contains(&ForwardedExitKey {
                control_relay_peer: key.control_relay_peer,
                exit_peer: entry.target_peer,
            }) {
                entry.outcome = Err(OutboundReservationError::InvalidResponse);
                entry.reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
            }
        }
        for entry in self.completed_relay_forwards.values_mut() {
            if keys.contains(&ForwardedExitKey {
                control_relay_peer: local_control_peer,
                exit_peer: entry.target_peer,
            }) {
                entry.response = None;
                entry.reserved_bytes = completed_ledger_reservation_bytes(
                    entry.canonical_request.len(),
                    0,
                    entry.reserved_bytes,
                );
            }
        }
        removed_expiry
    }

    fn record_privacy_conflict(
        &mut self,
        peer: Libp2pPeerId,
        advertisement_sequence: u64,
        expires_at_ms: u64,
    ) {
        let existing_expiry = self
            .privacy_conflicts
            .iter()
            .filter_map(|(key, expiry)| (key.peer_id == peer).then_some(*expiry))
            .max()
            .unwrap_or_default();
        self.privacy_conflicts.retain(|key, _| key.peer_id != peer);
        let expiry = expires_at_ms.max(existing_expiry);
        if self.privacy_conflicts.len() < self.candidate_limit.max(1) {
            self.privacy_conflicts.insert(
                PrivacyConflictKey {
                    peer_id: peer,
                    advertisement_sequence,
                },
                expiry,
            );
        } else {
            self.forwarded_exit_fail_closed_until_ms =
                self.forwarded_exit_fail_closed_until_ms.max(expiry);
        }
    }

    /// Builds one read-only selection snapshot from state already serialized by the actor.
    ///
    /// The command handler captures time once and purges actor expiry before entering this method.
    /// Persisted records are never projected without fresh signature verification and an exact
    /// fingerprint join to the actor's accepted record and capability.
    fn build_route_candidate_snapshot(
        &self,
        requested_candidates: usize,
        captured_at_ms: u64,
        active: &AgentPolicySnapshot,
    ) -> Result<RouteCandidateSnapshot, RouteCandidateSnapshotError> {
        #[cfg(test)]
        self.route_snapshot_build_attempts
            .set(self.route_snapshot_build_attempts.get().saturating_add(1));
        if requested_candidates == 0
            || requested_candidates > MAXIMUM_SELECTION_CANDIDATES
            || captured_at_ms == 0
        {
            return Err(RouteCandidateSnapshotError::InvalidLimit);
        }
        let maximum_candidates = requested_candidates.min(self.candidate_limit.max(1));
        let policy = Self::validated_route_candidate_policy(active, captured_at_ms)?;
        #[cfg(test)]
        if self.route_snapshot_store_failure {
            return Err(RouteCandidateSnapshotError::StoreUnavailable);
        }
        let revalidated =
            self.load_revalidated_route_candidates(maximum_candidates, captured_at_ms, policy)?;
        let mut direct_relays =
            self.project_direct_route_candidates(&revalidated, captured_at_ms, policy);
        let mut forwarded_exits = self.project_forwarded_route_candidates(
            &revalidated,
            &direct_relays,
            captured_at_ms,
            policy,
        );
        Self::finalize_route_candidate_projection(
            &mut direct_relays,
            &mut forwarded_exits,
            maximum_candidates,
        );
        let preselection_subjects = preselection_observation::PreselectionSubjectSet::from_snapshot(
            &revalidated,
            &direct_relays,
            &forwarded_exits,
        );
        Ok(RouteCandidateSnapshot {
            captured_at_ms,
            policy,
            direct_relays,
            forwarded_exits,
            preselection_subjects,
        })
    }

    fn validated_route_candidate_policy(
        active: &AgentPolicySnapshot,
        captured_at_ms: u64,
    ) -> Result<RouteCandidatePolicySnapshot, RouteCandidateSnapshotError> {
        let Some(policy_hash) = fixed_bytes::<32>(&active.policy_hash) else {
            return Err(RouteCandidateSnapshotError::PolicyUnavailable);
        };
        if !active.active
            || active.manifest_version == 0
            || active.expires_at_ms <= captured_at_ms
            || policy_hash.iter().all(|byte| *byte == 0)
        {
            return Err(RouteCandidateSnapshotError::PolicyUnavailable);
        }
        Ok(RouteCandidatePolicySnapshot {
            version: active.manifest_version,
            hash: policy_hash,
            expires_at_ms: active.expires_at_ms,
        })
    }

    fn load_revalidated_route_candidates(
        &self,
        maximum_candidates: usize,
        captured_at_ms: u64,
        policy: RouteCandidatePolicySnapshot,
    ) -> Result<Vec<RevalidatedStoredCandidate>, RouteCandidateSnapshotError> {
        let stored = self
            .store
            .load_candidates(
                UnixTime::from_secs(captured_at_ms / 1_000),
                maximum_candidates,
            )
            .map_err(|_| RouteCandidateSnapshotError::StoreUnavailable)?;
        let local_peer = *self.service.local_peer_id();
        let mut revalidated = Vec::with_capacity(stored.len());
        for stored in stored {
            let Ok(exact) = revalidate_stored_advertisement(&stored, captured_at_ms) else {
                continue;
            };
            let accepted_matches = self
                .accepted_advertisements
                .get(&exact.wire_node_id)
                .is_some_and(|record| {
                    record.sequence_number == exact.sequence_number
                        && record.expires_at_ms == exact.signed_expires_at_ms
                        && record.fingerprint == exact.fingerprint
                });
            if !accepted_matches
                || exact.peer_id == local_peer
                || exact.wire_node_id == self.local_node_id
                || exact.sequence_number != stored.advertisement.sequence_number
                || exact.signed_expires_at_ms <= captured_at_ms
                || exact.policy_version != policy.version
                || exact.policy_hash != policy.hash
                || has_active_privacy_conflict(
                    &self.privacy_conflicts,
                    self.forwarded_exit_fail_closed_until_ms,
                    exact.peer_id,
                    captured_at_ms,
                )
            {
                continue;
            }
            revalidated.push(RevalidatedStoredCandidate {
                advertisement: RouteCandidateAdvertisement {
                    advertisement: stored.advertisement,
                    signed_measured_at_ms: exact.signed_measured_at_ms,
                    signed_expires_at_ms: exact.signed_expires_at_ms,
                    advertisement_payload_hash: exact.fingerprint.payload_hash,
                    local_measurement_count: stored.evidence.measurement_count,
                    historical_reputation_score: stored.evidence.reputation_score(),
                    serious_protocol_fault_until: stored.evidence.serious_protocol_fault_until,
                },
                revalidated: exact,
            });
        }
        Self::retain_unique_revalidated_candidates(&mut revalidated);
        Ok(revalidated)
    }

    fn retain_unique_revalidated_candidates(candidates: &mut Vec<RevalidatedStoredCandidate>) {
        // A duplicated node or Peer ID is ambiguity, not an invitation to pick whichever SQLite
        // row happened to be returned first.
        let mut node_counts = HashMap::<[u8; 32], usize>::new();
        let mut peer_counts = HashMap::<Libp2pPeerId, usize>::new();
        for candidate in candidates.iter() {
            *node_counts
                .entry(candidate.revalidated.wire_node_id)
                .or_default() += 1;
            *peer_counts
                .entry(candidate.revalidated.peer_id)
                .or_default() += 1;
        }
        candidates.retain(|candidate| {
            node_counts.get(&candidate.revalidated.wire_node_id) == Some(&1)
                && peer_counts.get(&candidate.revalidated.peer_id) == Some(&1)
        });
        candidates.sort_by(|left, right| {
            (
                left.revalidated.wire_node_id,
                left.revalidated.peer_id.to_bytes(),
            )
                .cmp(&(
                    right.revalidated.wire_node_id,
                    right.revalidated.peer_id.to_bytes(),
                ))
        });
    }

    fn project_direct_route_candidates(
        &self,
        revalidated: &[RevalidatedStoredCandidate],
        captured_at_ms: u64,
        policy: RouteCandidatePolicySnapshot,
    ) -> Vec<DirectRelayCandidateSnapshot> {
        let mut direct_relays = Vec::new();
        for candidate in revalidated {
            let exact = &candidate.revalidated;
            let Some(capability) = self.direct_relays.get(&exact.peer_id) else {
                continue;
            };
            if !exact.relay
                || capability.node_id != exact.wire_node_id
                || capability.peer_id != exact.peer_id
                || capability.public_key != exact.public_key
                || capability.advertisement_sequence != exact.sequence_number
                || capability.advertisement_expires_at_ms != exact.signed_expires_at_ms
                || capability.advertisement_payload_hash != exact.fingerprint.payload_hash
                || candidate.advertisement.advertisement_payload_hash
                    != exact.fingerprint.payload_hash
                || capability.policy_version != policy.version
                || capability.policy_hash != policy.hash
                || capability.policy_expires_at_ms != policy.expires_at_ms
                || capability.expires_at_ms != exact.signed_expires_at_ms.min(policy.expires_at_ms)
                || capability.expires_at_ms <= captured_at_ms
            {
                continue;
            }
            direct_relays.push(DirectRelayCandidateSnapshot {
                advertisement: candidate.advertisement.clone(),
                capability: capability.clone(),
                authenticated_local_prefix: self
                    .service
                    .authenticated_local_peer_prefix(exact.peer_id),
            });
        }
        direct_relays
    }

    fn project_forwarded_route_candidates(
        &self,
        revalidated: &[RevalidatedStoredCandidate],
        direct_relays: &[DirectRelayCandidateSnapshot],
        captured_at_ms: u64,
        policy: RouteCandidatePolicySnapshot,
    ) -> Vec<ForwardedExitCandidateSnapshot> {
        let direct_by_peer = direct_relays
            .iter()
            .cloned()
            .map(|candidate| (candidate.capability.peer_id, candidate))
            .collect::<HashMap<_, _>>();
        let stored_by_peer = revalidated
            .iter()
            .map(|candidate| (candidate.revalidated.peer_id, candidate))
            .collect::<HashMap<_, _>>();

        let mut forwarded_exits = Vec::new();
        for (key, capability) in &self.forwarded_exits {
            let Some(control) = direct_by_peer.get(&key.control_relay_peer) else {
                continue;
            };
            let Some(exit) = stored_by_peer.get(&key.exit_peer) else {
                continue;
            };
            let exact = &exit.revalidated;
            let control_capability = &control.capability;
            if !self.forwarded_route_capability_matches(
                capability,
                exact,
                exit.advertisement.advertisement_payload_hash,
                control_capability,
                captured_at_ms,
                policy,
            ) {
                continue;
            }
            forwarded_exits.push(ForwardedExitCandidateSnapshot {
                advertisement: exit.advertisement.clone(),
                control: control.clone(),
                capability: capability.clone(),
            });
        }
        forwarded_exits
    }

    fn forwarded_route_capability_matches(
        &self,
        capability: &ForwardedExitCapability,
        exact: &RevalidatedAdvertisement,
        projected_advertisement_payload_hash: AdvertisementPayloadHash,
        control: &DirectRelayCapability,
        captured_at_ms: u64,
        policy: RouteCandidatePolicySnapshot,
    ) -> bool {
        let upper_expiry = exact
            .signed_expires_at_ms
            .min(policy.expires_at_ms)
            .min(control.expires_at_ms)
            .min(capability.control_relay_advertisement_expires_at_ms);
        exact.exit
            && !self.direct_relays.contains_key(&exact.peer_id)
            && self.forwarded_exit_peer_is_eligible(exact.peer_id, captured_at_ms)
            && forwarded_control_projection_lineage_matches(
                capability,
                control,
                captured_at_ms.saturating_add(1),
            )
            && capability.exit_node_id == exact.wire_node_id
            && capability.exit_peer_id == exact.peer_id
            && capability.exit_public_key == exact.public_key
            && capability.exit_advertisement_sequence == exact.sequence_number
            && capability.exit_advertisement_expires_at_ms == exact.signed_expires_at_ms
            && capability.exit_advertisement_payload_hash == exact.fingerprint.payload_hash
            && projected_advertisement_payload_hash == exact.fingerprint.payload_hash
            && capability.policy_version == policy.version
            && capability.policy_hash == policy.hash
            && capability.policy_expires_at_ms == policy.expires_at_ms
            && capability.expires_at_ms > captured_at_ms
            && capability.expires_at_ms <= upper_expiry
            && capability.control_relay_node_id != capability.exit_node_id
            && capability.control_relay_peer_id != capability.exit_peer_id
            && capability.control_relay_public_key != capability.exit_public_key
    }

    fn finalize_route_candidate_projection(
        direct_relays: &mut [DirectRelayCandidateSnapshot],
        forwarded_exits: &mut Vec<ForwardedExitCandidateSnapshot>,
        maximum_candidates: usize,
    ) {
        direct_relays.sort_by(|left, right| {
            (left.capability.node_id, left.capability.peer_id.to_bytes()).cmp(&(
                right.capability.node_id,
                right.capability.peer_id.to_bytes(),
            ))
        });
        forwarded_exits.sort_by(|left, right| {
            (
                left.capability.exit_node_id,
                left.capability.exit_peer_id.to_bytes(),
                left.capability.control_relay_node_id,
                left.capability.control_relay_peer_id.to_bytes(),
            )
                .cmp(&(
                    right.capability.exit_node_id,
                    right.capability.exit_peer_id.to_bytes(),
                    right.capability.control_relay_node_id,
                    right.capability.control_relay_peer_id.to_bytes(),
                ))
        });
        let mut forwarded_node_counts = HashMap::<[u8; 32], usize>::new();
        let mut forwarded_peer_counts = HashMap::<Libp2pPeerId, usize>::new();
        for candidate in forwarded_exits.iter() {
            *forwarded_node_counts
                .entry(candidate.capability.exit_node_id)
                .or_default() += 1;
            *forwarded_peer_counts
                .entry(candidate.capability.exit_peer_id)
                .or_default() += 1;
        }
        forwarded_exits.retain(|candidate| {
            forwarded_node_counts.get(&candidate.capability.exit_node_id) == Some(&1)
                && forwarded_peer_counts.get(&candidate.capability.exit_peer_id) == Some(&1)
        });

        debug_assert!(
            direct_relays.len().saturating_add(forwarded_exits.len()) <= maximum_candidates
        );
    }

    async fn refresh_candidates(&mut self, state: &Arc<RwLock<AgentState>>) {
        let now = UnixTime::from_secs(unix_seconds());
        let Ok(candidates) = self.store.load_candidates(now, self.candidate_limit) else {
            state
                .write()
                .await
                .log(LogLevel::Warn, "PEERSTORE_LOAD_FAILED", unix_millis());
            return;
        };
        // Signed advertisements and observed control-plane endpoints are not dataplane evidence.
        // Until a producer supplies fresh, transport-, advertisement-, policy-, and selected-exit-
        // bound reachability/capacity/path measurements, no stored peer is a usable route candidate.
        let usable_candidates = 0;
        let summaries = candidates
            .into_iter()
            .map(|stored| {
                let roles = stored.advertisement.roles;
                let role_bits = u32::from(roles.client)
                    | (u32::from(roles.relay) << 1)
                    | (u32::from(roles.exit) << 2);
                let reachability = match stored.latest_endpoint {
                    Some(endpoint) if endpoint.reachable => Reachability::Direct,
                    Some(_) => Reachability::Unreachable,
                    None => Reachability::Unknown,
                };
                PeerSummary {
                    peer_id: stored.advertisement.peer_id.to_string(),
                    role_bits,
                    reachability: reachability as i32,
                    advertisement_sequence: stored.advertisement.sequence_number,
                }
            })
            .collect();
        state
            .write()
            .await
            .replace_candidates(summaries, usable_candidates);
    }
}

fn preselection_responder_policy(
    roles: RolesConfig,
    policy: &AgentPolicySnapshot,
    now_ms: u64,
) -> Option<LocalPreselectionPolicy> {
    if !(roles.relay || roles.exit) || !policy.active || policy.expires_at_ms <= now_ms {
        return None;
    }
    let hash = fixed_bytes::<32>(&policy.policy_hash)?;
    LocalPreselectionPolicy::new(policy.manifest_version, hash, policy.expires_at_ms).ok()
}

async fn next_actor_discovery_event(
    service: &mut DiscoveryService,
    identity: &Identity,
    public_key: [u8; 32],
    responder_policy: Option<LocalPreselectionPolicy>,
) -> DiscoveryEvent {
    let Some(policy) = responder_policy else {
        service.cancel_preselection_forwarding();
        return service.next_event().await;
    };
    let mut signer = |message: &[u8]| identity.sign(message).ok();
    service
        .next_event_with_preselection_responders(policy, public_key, &mut signer)
        .await
}

async fn log_reservation_event(state: &Arc<RwLock<AgentState>>, event_code: &'static str) {
    state
        .write()
        .await
        .log(LogLevel::Debug, event_code, unix_millis());
}

fn log_relay_forward_admission(state: Option<&Arc<RwLock<AgentState>>>, event_code: &'static str) {
    if let Some(state) = state {
        if let Ok(mut guard) = state.try_write() {
            guard.log(LogLevel::Debug, event_code, unix_millis());
        }
    }
}

async fn log_outbound_event(state: &Arc<RwLock<AgentState>>, outcome: OutboundEventOutcome) {
    let (level, code) = match outcome {
        OutboundEventOutcome::Completed => return,
        OutboundEventOutcome::Failed => (LogLevel::Debug, "RESERVATION_RPC_FAILED"),
        OutboundEventOutcome::InvalidResponse => {
            (LogLevel::Warn, "RESERVATION_RESPONSE_VERIFY_FAILED")
        }
        OutboundEventOutcome::PeerMismatch => {
            (LogLevel::Warn, "RESERVATION_RESPONSE_PEER_MISMATCH")
        }
        OutboundEventOutcome::Unexpected => (LogLevel::Debug, "RESERVATION_RESPONSE_UNEXPECTED"),
    };
    state.write().await.log(level, code, unix_millis());
}

fn direct_relay_target_matches(
    capability: &DirectRelayCapability,
    expected_node_id: [u8; 32],
    expected_peer_id: Libp2pPeerId,
    required_until_ms: u64,
) -> bool {
    capability.node_id == expected_node_id
        && capability.peer_id == expected_peer_id
        && capability.expires_at_ms >= required_until_ms
}

fn accepted_from_direct_capability(capability: &DirectRelayCapability) -> AcceptedAdvertisement {
    AcceptedAdvertisement {
        node_id: capability.node_id,
        peer_id: capability.peer_id,
        public_key: capability.public_key,
        sequence_number: capability.advertisement_sequence,
        advertisement_expires_at_ms: capability.advertisement_expires_at_ms,
        policy_version: capability.policy_version,
        policy_hash: capability.policy_hash,
        policy_expires_at_ms: capability.policy_expires_at_ms,
        expires_at_ms: capability.expires_at_ms,
    }
}

fn direct_relay_capability_matches(
    capability: &DirectRelayCapability,
    expected_node_id: [u8; 32],
    expected_peer_id: Libp2pPeerId,
    expected_public_key: [u8; 32],
    required_until_ms: u64,
) -> bool {
    direct_relay_target_matches(
        capability,
        expected_node_id,
        expected_peer_id,
        required_until_ms,
    ) && capability.public_key == expected_public_key
}

fn direct_relay_authority_lineage_matches(
    current: &DirectRelayCapability,
    authorized: &DirectRelayCapability,
    required_until_ms: u64,
) -> bool {
    current.node_id == authorized.node_id
        && current.peer_id == authorized.peer_id
        && current.public_key == authorized.public_key
        && current.policy_version == authorized.policy_version
        && current.policy_hash == authorized.policy_hash
        && current.policy_expires_at_ms == authorized.policy_expires_at_ms
        && current.expires_at_ms >= required_until_ms
        && authorized.expires_at_ms >= required_until_ms
}

/// Keeps a still-live forwarded Exit usable across an ordinary advertisement refresh by the same
/// authenticated control Relay. Equal sequences remain fingerprint-exact; only a strictly newer
/// current sequence may carry forward the older, still-live provenance.
fn forwarded_control_projection_lineage_matches(
    capability: &ForwardedExitCapability,
    current: &DirectRelayCapability,
    required_until_ms: u64,
) -> bool {
    let sequence_matches = if capability.control_relay_advertisement_sequence
        == current.advertisement_sequence
    {
        capability.control_relay_advertisement_expires_at_ms == current.advertisement_expires_at_ms
            && capability.control_relay_advertisement_payload_hash
                == current.advertisement_payload_hash
    } else {
        capability.control_relay_advertisement_sequence < current.advertisement_sequence
    };

    capability.control_relay_node_id == current.node_id
        && capability.control_relay_peer_id == current.peer_id
        && capability.control_relay_public_key == current.public_key
        && capability.control_relay_advertisement_sequence != 0
        && capability.control_relay_advertisement_expires_at_ms >= required_until_ms
        && capability.policy_version == current.policy_version
        && capability.policy_hash == current.policy_hash
        && capability.policy_expires_at_ms == current.policy_expires_at_ms
        && capability.expires_at_ms >= required_until_ms
        && current.expires_at_ms >= required_until_ms
        && sequence_matches
}

#[allow(
    clippy::too_many_arguments,
    reason = "two immutable identity snapshots"
)]
fn forwarded_exit_capability_matches(
    capability: &ForwardedExitCapability,
    control: &DirectRelayCapability,
    expected_control_node_id: [u8; 32],
    expected_control_peer_id: Libp2pPeerId,
    expected_control_public_key: [u8; 32],
    expected_exit_node_id: [u8; 32],
    expected_exit_peer_id: Libp2pPeerId,
    required_until_ms: u64,
) -> bool {
    capability.control_relay_node_id == expected_control_node_id
        && capability.control_relay_peer_id == expected_control_peer_id
        && capability.control_relay_public_key == expected_control_public_key
        && capability.control_relay_node_id == control.node_id
        && capability.control_relay_peer_id == control.peer_id
        && capability.control_relay_public_key == control.public_key
        && capability.control_relay_advertisement_sequence != 0
        && capability.control_relay_advertisement_expires_at_ms >= required_until_ms
        && capability.exit_node_id == expected_exit_node_id
        && capability.exit_peer_id == expected_exit_peer_id
        && capability.policy_version == control.policy_version
        && capability.policy_hash == control.policy_hash
        && capability.policy_expires_at_ms == control.policy_expires_at_ms
        && control.expires_at_ms >= required_until_ms
        && capability.expires_at_ms >= required_until_ms
}

fn client_preselection_capacities_are_valid(
    minimum: Bandwidth,
    local_profile: Bandwidth,
    conservative_ceiling: Bandwidth,
) -> bool {
    minimum.validate().is_ok()
        && minimum.up_mbps > 0
        && minimum.down_mbps > 0
        && local_profile.validate().is_ok()
        && conservative_ceiling.validate().is_ok()
        && conservative_ceiling.up_mbps > 0
        && conservative_ceiling.down_mbps > 0
        && conservative_ceiling.satisfies(minimum)
        && local_profile.satisfies(conservative_ceiling)
}

fn client_preselection_parameters_are_valid(parameters: &ClientPreselectionParameters) -> bool {
    client_preselection_capacities_are_valid(
        parameters.minimum_capacity,
        parameters.local_profile_capacity,
        parameters.conservative_capacity_ceiling,
    ) && PreselectionSamplingScope::new(
        parameters.transport,
        parameters.address_family,
        parameters.minimum_capacity,
        parameters.minimum_other_relays,
        parameters.maximum_other_relays,
    )
    .is_valid()
        && (1..=MAXIMUM_SELECTION_CANDIDATES).contains(&parameters.requested_candidate_bound)
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn native_probe_exit_socket_request(
    route_context_id: [u8; FORWARD_ID_BYTES],
    context_handle: &[u8],
    path_id: u32,
) -> Option<AcquireTransportSocket> {
    let path_number = u8::try_from(path_id).ok()?;
    let addresses = overlay_addresses(route_context_id, path_number).ok()?;
    Some(AcquireTransportSocket {
        route_context_id: route_context_id.to_vec(),
        context_handle: context_handle.to_vec(),
        path_id,
        role: WireguardRole::Exit as i32,
        descriptor_kind: TransportSocketKind::NativeProbeUdpConnected as i32,
        expected_local: Some(TransportSocketAddress {
            address: addresses.exit.octets().to_vec(),
            port: u32::from(NATIVE_PROBE_EXIT_PORT),
        }),
        expected_remote: Some(TransportSocketAddress {
            address: addresses.client.octets().to_vec(),
            port: u32::from(NATIVE_PROBE_CLIENT_PORT),
        }),
    })
}

fn native_probe_observed_relay_prefix(
    endpoint: &volparossa_protocol::WireguardEndpoint,
) -> Option<ObservationNetworkPrefix> {
    let underlay_ip = endpoint.underlay_ip.as_slice();
    let address = match underlay_ip.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(underlay_ip).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(underlay_ip).ok()?),
        _ => return None,
    };
    // This is Exit-side Relay-to-Exit evidence, never the Client's local LAN origin.
    let scope = volparossa_protocol::UnderlayScope::try_from(endpoint.underlay_scope).ok()?;
    if !match scope {
        volparossa_protocol::UnderlayScope::PublicInternet => is_public_routable_ip(address),
        volparossa_protocol::UnderlayScope::DirectLocalLan => is_local_lan_ip(address),
    } {
        return None;
    }
    match underlay_ip.len() {
        4 => Some(ObservationNetworkPrefix {
            scope: scope as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            network_prefix: underlay_ip[..3].to_vec(),
        }),
        16 => Some(ObservationNetworkPrefix {
            scope: scope as i32,
            address_family: ObservationAddressFamily::Ipv6 as i32,
            network_prefix: underlay_ip[..6].to_vec(),
        }),
        _ => None,
    }
}

fn optional_fixed_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    (!bytes.is_empty()).then(|| fixed_bytes(bytes)).flatten()
}

fn ledger_reservation_bytes(canonical_request_bytes: usize) -> Option<usize> {
    canonical_request_bytes
        .checked_add(usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?)
        .filter(|reserved| *reserved <= MAX_LEDGER_BYTES_PER_PEER)
}

/// Replace a pending worst-case response reservation with the bytes actually retained.
///
/// A completed ledger entry stores its canonical request and, at most, one canonical response.
/// Keep the original reservation if an impossible overflow or oversized encoded response is
/// observed so accounting always remains conservative.
fn completed_ledger_reservation_bytes(
    canonical_request_bytes: usize,
    canonical_response_bytes: usize,
    pending_reserved_bytes: usize,
) -> usize {
    canonical_request_bytes
        .checked_add(canonical_response_bytes)
        .filter(|completed| *completed <= pending_reserved_bytes)
        .unwrap_or(pending_reserved_bytes)
}

fn native_exit_ticket_matches_standard_result(
    ticket: &RecentNativeExitEvidence,
    result: &RelayProbeResult,
    evidence: &ProbeEvidence<'_>,
    now_ms: u64,
) -> bool {
    let Some(data_relay) = ticket.scope.data_relay.as_ref() else {
        return false;
    };
    let Some(control) = ticket.scope.control.as_ref() else {
        return false;
    };
    let Some(exit) = ticket.scope.exit.as_ref() else {
        return false;
    };
    let Some(permit) = decoded_signed_payload::<RelayProbePermit>(&result.relay_probe_permit)
    else {
        return false;
    };
    let valid_leg = |leg: &ProbeLegEvidence| {
        leg.up_capacity_mbps > 0
            && leg.down_capacity_mbps > 0
            && leg.rtt_micros > 0
            && leg.transmitted_bytes >= NATIVE_PROBE_DATAGRAM_BYTES as u64
            && leg.received_bytes >= NATIVE_PROBE_DATAGRAM_BYTES as u64
            && leg.window_started_at_ms < leg.window_ended_at_ms
            && leg.window_ended_at_ms == leg.measured_at_ms
            && leg.measured_at_ms == result.measured_at_ms
    };
    ticket.expires_at_ms > now_ms
        && result.expires_at_ms > now_ms
        && result.expires_at_ms <= ticket.expires_at_ms
        && result.measured_at_ms <= now_ms
        && result
            .measured_at_ms
            .saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
            >= ticket.measured_at_ms
        && ticket
            .measured_at_ms
            .saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
            >= result.measured_at_ms
        && ticket.authenticated_data_relay_node_id.as_slice() == data_relay.node_id
        && ticket.authenticated_data_relay_peer_id == data_relay.peer_id
        && result.relay_node_id == data_relay.node_id
        && result.relay_peer_id == data_relay.peer_id
        && permit.control_relay_node_id == control.node_id
        && permit.control_relay_peer_id == control.peer_id
        && result.exit_node_id == exit.node_id
        && result.exit_peer_id == exit.peer_id
        && result.policy_hash == ticket.scope.policy_hash
        && result.transport == ticket.scope.transport
        && result.address_family == ticket.scope.address_family
        && evidence.path_id() == ticket.scope.candidate_ordinal
        && evidence.transport() as i32 == ticket.scope.transport
        && evidence.address_family() as i32 == ticket.scope.address_family
        && valid_leg(evidence.client_relay())
        && valid_leg(evidence.relay_exit())
}

fn native_probe_leg_evidence(
    transmitted_bytes: u64,
    received_bytes: u64,
    reserved_up_mbps: u64,
    reserved_down_mbps: u64,
    window_started_at_ms: u64,
    window_ended_at_ms: u64,
) -> Option<ProbeLegEvidence> {
    let duration_ms = window_ended_at_ms.checked_sub(window_started_at_ms)?;
    if duration_ms == 0
        || transmitted_bytes == 0
        || received_bytes == 0
        || reserved_up_mbps == 0
        || reserved_down_mbps == 0
    {
        return None;
    }
    Some(ProbeLegEvidence {
        // The native exchange is a liveness/RTT probe, not a throughput benchmark. Capacity was
        // already signed, reserved, and enforced for this exact scope before the probe ran.
        up_capacity_mbps: reserved_up_mbps,
        down_capacity_mbps: reserved_down_mbps,
        rtt_micros: duration_ms.saturating_mul(1_000).clamp(1, 60_000_000),
        transmitted_bytes,
        received_bytes,
        window_started_at_ms,
        window_ended_at_ms,
        measured_at_ms: window_ended_at_ms,
    })
}

fn deadline_is_bounded(deadline_unix_ms: u64, now_ms: u64) -> bool {
    deadline_unix_ms > now_ms
        && deadline_unix_ms <= now_ms.saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
}

fn native_rpc_deadline_is_within_authority(
    deadline_unix_ms: u64,
    authority_expires_at_ms: u64,
) -> bool {
    deadline_unix_ms <= authority_expires_at_ms
}

fn inbound_datapath_unavailable_response(
    request: &DatapathRelayRequest,
    authenticated_client_peer: Libp2pPeerId,
    local_node_id: [u8; 32],
    local_peer: Libp2pPeerId,
    relay_ready: bool,
    now_ms: u64,
) -> Option<DatapathRelayResponse> {
    let operation = request.validated_operation().ok()?;
    let local_target = fixed_bytes::<32>(request.relay_node_id()) == Some(local_node_id)
        && Libp2pPeerId::from_bytes(request.relay_peer_id()).is_ok_and(|peer| peer == local_peer);
    if request.validate().is_err()
        || !datapath_request_scope_matches(request, operation, now_ms)
        || !relay_ready
        || authenticated_client_peer == local_peer
        || !local_target
    {
        return None;
    }
    DatapathRelayResponse::unavailable(
        request.request_id().to_vec(),
        operation,
        local_node_id.to_vec(),
        local_peer.to_bytes(),
    )
    .ok()
}

fn datapath_request_scope_matches(
    request: &DatapathRelayRequest,
    operation: DatapathRelayOperation,
    now_ms: u64,
) -> bool {
    if !deadline_is_bounded(request.deadline_unix_ms(), now_ms) {
        return false;
    }
    let Ok(mut replay) = ReplayCache::new(8) else {
        return false;
    };
    match operation {
        DatapathRelayOperation::ExecuteProbe => {
            execute_probe_scope_matches(request, now_ms, &mut replay)
        }
        DatapathRelayOperation::ReservePath => {
            reserve_path_scope_matches(request, now_ms, &mut replay)
        }
        DatapathRelayOperation::NativeProbeReady => {
            native_probe_ready_scope_matches(request, now_ms, &mut replay)
        }
        DatapathRelayOperation::NativeProbeStart | DatapathRelayOperation::NativeProbeAuthorize => {
            native_probe_start_scope_matches(request, operation, now_ms, &mut replay)
        }
        DatapathRelayOperation::UdpSessionStart => {
            verified_udp_session_start_scope(request.client_signed_request(), now_ms).is_some_and(
                |scope| {
                    request.exit_signed_authorization().is_empty()
                        && request.request_id() == &scope.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= scope.expires_at_ms
                        && request.relay_node_id() == scope.relay.relay_node_id
                        && request.relay_peer_id() == scope.relay.relay_peer_id
                },
            )
        }
        DatapathRelayOperation::MptcpSessionStart => {
            verified_mptcp_session_start_scope(request.client_signed_request(), now_ms)
                .and_then(|scope| {
                    scope.paths.into_iter().find(|path| {
                        request.relay_node_id() == path.relay.relay_node_id
                            && request.relay_peer_id() == path.relay.relay_peer_id
                    })
                })
                .is_some_and(|path| {
                    request.exit_signed_authorization().is_empty()
                        && request.request_id() == &path.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= path.expires_at_ms
                })
        }
        DatapathRelayOperation::MpquicSessionStart => {
            verified_mpquic_session_start_scope(request.client_signed_request(), now_ms)
                .and_then(|scope| {
                    scope.paths.into_iter().find(|path| {
                        request.relay_node_id() == path.relay.relay_node_id
                            && request.relay_peer_id() == path.relay.relay_peer_id
                    })
                })
                .is_some_and(|path| {
                    request.exit_signed_authorization().is_empty()
                        && request.request_id() == &path.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= path.expires_at_ms
                })
        }
        DatapathRelayOperation::Unspecified => false,
    }
}

fn native_probe_ready_scope_matches(
    wrapper: &DatapathRelayRequest,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> bool {
    let Ok(permit) = verify_native_probe_permit(
        wrapper.client_signed_request().to_vec(),
        wrapper.exit_signed_authorization().to_vec(),
        now_ms,
        replay,
    ) else {
        return false;
    };
    let scope = permit.scope();
    let Some(data_relay) = scope.data_relay.as_ref() else {
        return false;
    };
    wrapper.request_id() == scope.probe_id
        && native_rpc_deadline_is_within_authority(
            wrapper.deadline_unix_ms(),
            scope.attempt_expires_at_ms,
        )
        && wrapper.relay_node_id() == data_relay.node_id
        && wrapper.relay_peer_id() == data_relay.peer_id
}

fn native_probe_start_scope_matches(
    wrapper: &DatapathRelayRequest,
    operation: DatapathRelayOperation,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> bool {
    let Ok(start) = verify_control_message::<NativeProbeStart>(
        wrapper.client_signed_request(),
        now_ms,
        TimePolicy {
            maximum_lifetime_ms: MAX_NATIVE_PROBE_LIFETIME_MS,
            maximum_clock_skew_ms: TimePolicy::default().maximum_clock_skew_ms,
        },
        replay,
    ) else {
        return false;
    };
    let nonce = *start.nonce();
    let expires_at_ms = start.expires_at_ms();
    let start = start.into_message();
    let Some(scope) = start.scope.as_ref() else {
        return false;
    };
    let Some(data_relay) = scope.data_relay.as_ref() else {
        return false;
    };
    let expected_request_id = if operation == DatapathRelayOperation::NativeProbeAuthorize {
        native_probe_authorization_request_id(nonce)
    } else {
        nonce[..FORWARD_ID_BYTES]
            .try_into()
            .expect("fixed nonce prefix")
    };
    wrapper.request_id() == expected_request_id
        && native_rpc_deadline_is_within_authority(wrapper.deadline_unix_ms(), expires_at_ms)
        && wrapper.relay_node_id() == data_relay.node_id
        && wrapper.relay_peer_id() == data_relay.peer_id
}

#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed cross-envelope probe authorization check"
)]
fn execute_probe_scope_matches(
    wrapper: &DatapathRelayRequest,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> bool {
    let Ok(verified_request) = verify_control_message::<RelayProbePermitRequest>(
        wrapper.client_signed_request(),
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let request_public_key = *verified_request.sender_public_key();
    let request_nonce = *verified_request.nonce();
    let request_expires_at_ms = verified_request.expires_at_ms();
    let request = verified_request.into_message();
    if !inner_datapath_scope_matches(
        wrapper,
        &request_nonce,
        request_expires_at_ms,
        &request.relay_node_id,
        &request.relay_peer_id,
    ) {
        return false;
    }

    let Ok(verified_capability) = verify_control_message::<ClientSessionCapability>(
        &request.client_session_capability,
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let capability_public_key = *verified_capability.sender_public_key();
    let capability = verified_capability.into_message();
    let Ok(verified_hold) = verify_control_message::<ExitCapacityHold>(
        &request.exit_capacity_hold,
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let hold_public_key = *verified_hold.sender_public_key();
    let hold = verified_hold.into_message();
    let Ok(verified_permit) = verify_control_message::<RelayProbePermit>(
        wrapper.exit_signed_authorization(),
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let permit_public_key = *verified_permit.sender_public_key();
    let permit = verified_permit.into_message();

    request_public_key.as_slice() == capability.client_session_public_key
        && capability_public_key == hold_public_key
        && capability_public_key == permit_public_key
        && exit_signed_authority_matches(
            capability_public_key,
            &capability.exit_node_id,
            &capability.exit_peer_id,
            &[
                request.client_session_capability.as_slice(),
                request.exit_capacity_hold.as_slice(),
                wrapper.exit_signed_authorization(),
            ],
        )
        && probe_hold_scope_matches(&hold, &capability, &request.client_session_capability)
        && probe_request_scope_matches(
            &request,
            &hold,
            &capability,
            &request.exit_capacity_hold,
            &request.client_session_capability,
        )
        && probe_permit_scope_matches(&permit, &request, &hold, &capability)
}

#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed cross-envelope relay reservation authorization check"
)]
fn reserve_path_scope_matches(
    wrapper: &DatapathRelayRequest,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> bool {
    let Ok(verified_request) = verify_control_message::<RelayReservationRequest>(
        wrapper.client_signed_request(),
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let request_public_key = *verified_request.sender_public_key();
    let request_nonce = *verified_request.nonce();
    let request_expires_at_ms = verified_request.expires_at_ms();
    let request = verified_request.into_message();

    let Ok(verified_capability) = verify_control_message::<ClientSessionCapability>(
        &request.client_session_capability,
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let capability_public_key = *verified_capability.sender_public_key();
    let capability = verified_capability.into_message();
    let Ok(verified_exit) = verify_control_message::<ExitReservation>(
        &request.exit_reservation,
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let exit_public_key = *verified_exit.sender_public_key();
    let exit = verified_exit.into_message();
    let Ok(verified_authorization) = verify_control_message::<RelayAuthorization>(
        &request.exit_authorization,
        now_ms,
        TimePolicy::default(),
        replay,
    ) else {
        return false;
    };
    let authorization_public_key = *verified_authorization.sender_public_key();
    let authorization = verified_authorization.into_message();

    inner_datapath_scope_matches(
        wrapper,
        &request_nonce,
        request_expires_at_ms,
        &authorization.relay_node_id,
        &authorization.relay_peer_id,
    ) && request_public_key.as_slice() == capability.client_session_public_key
        && capability_public_key == exit_public_key
        && capability_public_key == authorization_public_key
        && exit_signed_authority_matches(
            capability_public_key,
            &capability.exit_node_id,
            &capability.exit_peer_id,
            &[
                request.client_session_capability.as_slice(),
                request.exit_reservation.as_slice(),
                request.exit_authorization.as_slice(),
            ],
        )
        && request.client_session_id == capability.client_session_id
        && request.created_at_ms >= capability.created_at_ms
        && request.expires_at_ms <= capability.expires_at_ms
        && request.created_at_ms >= authorization.created_at_ms
        && request.expires_at_ms <= authorization.expires_at_ms
        && request
            .client_wireguard_endpoint
            .as_ref()
            .is_some_and(|endpoint| {
                endpoint.public_key == authorization.client_wireguard_public_key
            })
        && reservation_capability_scope_matches(&capability, &exit)
        && reservation_authorization_scope_matches(&authorization, &exit, &capability)
}

fn inner_datapath_scope_matches(
    request: &DatapathRelayRequest,
    signed_nonce: &[u8; 32],
    signed_expires_at_ms: u64,
    relay_node_id: &[u8],
    relay_peer_id: &[u8],
) -> bool {
    request.request_id() == &signed_nonce[..FORWARD_ID_BYTES]
        && request.deadline_unix_ms() == signed_expires_at_ms
        && request.relay_node_id() == relay_node_id
        && request.relay_peer_id() == relay_peer_id
}

fn exit_signed_authority_matches(
    public_key: [u8; 32],
    exit_node_id: &[u8],
    exit_peer_id: &[u8],
    signed_envelopes: &[&[u8]],
) -> bool {
    let Ok(exit_peer) = Libp2pPeerId::from_bytes(exit_peer_id) else {
        return false;
    };
    node_id_from_public_key(&public_key).as_slice() == exit_node_id
        && signed_envelopes
            .iter()
            .all(|encoded| signed_envelope_matches_peer(encoded, &exit_peer))
}

fn probe_hold_scope_matches(
    hold: &ExitCapacityHold,
    capability: &ClientSessionCapability,
    signed_capability: &[u8],
) -> bool {
    hold.client_session_capability == signed_capability
        && hold.reservation_id == capability.reservation_id
        && hold.route_context_id == capability.route_context_id
        && hold.exit_node_id == capability.exit_node_id
        && hold.exit_peer_id == capability.exit_peer_id
        && hold.exit_boot_id == capability.exit_boot_id
        && hold.client_session_id == capability.client_session_id
        && hold.policy_hash == capability.policy_hash
        && hold.allowed_transports == capability.allowed_transports
        && hold.reserved_up_mbps == capability.reserved_up_mbps
        && hold.reserved_down_mbps == capability.reserved_down_mbps
        && hold.maximum_paths == capability.maximum_paths
        && hold.probe_permit_limit == capability.probe_permit_limit
        && hold.created_at_ms == capability.created_at_ms
        && hold.expires_at_ms <= capability.expires_at_ms
        && hold.reservation_expires_at_ms == capability.expires_at_ms
        && hold.control_relay_node_id == capability.control_relay_node_id
        && hold.control_relay_peer_id == capability.control_relay_peer_id
}

fn probe_request_scope_matches(
    request: &RelayProbePermitRequest,
    hold: &ExitCapacityHold,
    capability: &ClientSessionCapability,
    signed_hold: &[u8],
    signed_capability: &[u8],
) -> bool {
    request.exit_capacity_hold == signed_hold
        && request.client_session_capability == signed_capability
        && request.client_session_id == capability.client_session_id
        && request.exit_node_id == capability.exit_node_id
        && request.exit_peer_id == capability.exit_peer_id
        && request.control_relay_node_id == capability.control_relay_node_id
        && request.control_relay_peer_id == capability.control_relay_peer_id
        && request.path_id <= capability.probe_permit_limit
        && capability.allowed_transports.contains(&request.transport)
        && request.created_at_ms >= hold.created_at_ms
        && request.expires_at_ms <= hold.expires_at_ms
}

fn probe_permit_scope_matches(
    permit: &RelayProbePermit,
    request: &RelayProbePermitRequest,
    hold: &ExitCapacityHold,
    capability: &ClientSessionCapability,
) -> bool {
    permit.probe_id == request.probe_id
        && permit.hold_id == hold.hold_id
        && permit.capability_id == capability.capability_id
        && permit.reservation_id == capability.reservation_id
        && permit.route_context_id == capability.route_context_id
        && permit.client_session_id == request.client_session_id
        && permit.client_session_id == capability.client_session_id
        && permit.exit_node_id == request.exit_node_id
        && permit.exit_node_id == capability.exit_node_id
        && permit.exit_boot_id == capability.exit_boot_id
        && permit.exit_peer_id == request.exit_peer_id
        && permit.exit_peer_id == capability.exit_peer_id
        && permit.control_relay_node_id == request.control_relay_node_id
        && permit.control_relay_node_id == capability.control_relay_node_id
        && permit.control_relay_peer_id == request.control_relay_peer_id
        && permit.control_relay_peer_id == capability.control_relay_peer_id
        && permit.policy_hash == capability.policy_hash
        && permit.relay_node_id == request.relay_node_id
        && permit.relay_peer_id == request.relay_peer_id
        && permit.path_id == request.path_id
        && permit.created_at_ms == request.created_at_ms
        && permit.expires_at_ms == request.expires_at_ms
        && permit.transport == request.transport
        && permit.address_family == request.address_family
}

fn reservation_capability_scope_matches(
    capability: &ClientSessionCapability,
    exit: &ExitReservation,
) -> bool {
    capability.reservation_id == exit.reservation_id
        && capability.route_context_id == exit.route_context_id
        && capability.client_session_id == exit.client_session_id
        && capability.client_session_public_key == exit.client_session_public_key
        && capability.exit_node_id == exit.exit_node_id
        && capability.exit_peer_id == exit.exit_peer_id
        && capability.exit_boot_id == exit.exit_boot_id
        && capability.control_relay_node_id == exit.control_relay_node_id
        && capability.control_relay_peer_id == exit.control_relay_peer_id
        && capability.policy_hash == exit.policy_hash
        && capability.allowed_transports == exit.allowed_transports
        && capability.reserved_up_mbps == exit.reserved_up_mbps
        && capability.reserved_down_mbps == exit.reserved_down_mbps
        && capability.maximum_paths >= exit.maximum_paths
        && capability.created_at_ms == exit.created_at_ms
        && capability.expires_at_ms == exit.expires_at_ms
        && capability.capability_id == exit.capability_id
}

fn reservation_authorization_scope_matches(
    authorization: &RelayAuthorization,
    exit: &ExitReservation,
    capability: &ClientSessionCapability,
) -> bool {
    authorization.reservation_id == exit.reservation_id
        && authorization.route_context_id == exit.route_context_id
        && authorization.path_id <= capability.probe_permit_limit
        && authorization.exit_node_id == exit.exit_node_id
        && authorization.exit_peer_id == exit.exit_peer_id
        && authorization.client_session_id == exit.client_session_id
        && authorization.client_session_public_key == exit.client_session_public_key
        && authorization.allowed_transports == exit.allowed_transports
        && authorization.maximum_up_mbps == exit.reserved_up_mbps
        && authorization.maximum_down_mbps == exit.reserved_down_mbps
        && authorization.policy_hash == exit.policy_hash
        && authorization.created_at_ms == exit.created_at_ms
        && authorization.expires_at_ms == exit.expires_at_ms
        && authorization.capability_id == exit.capability_id
        && authorization.exit_boot_id == exit.exit_boot_id
        && authorization.hold_id == exit.hold_id
        && authorization.finalize_id == exit.finalize_id
        && authorization.control_relay_node_id == exit.control_relay_node_id
        && authorization.control_relay_peer_id == exit.control_relay_peer_id
}

fn verified_native_probe_forward_scope(
    request: &ExitForwardRequest,
    now_ms: u64,
) -> Option<NativeProbePathScope> {
    if request.validated_operation().ok()? != ExitForwardOperation::NativeProbePermit
        || !deadline_is_bounded(request.deadline_unix_ms(), now_ms)
    {
        return None;
    }
    let mut replay = ReplayCache::new(1).ok()?;
    let verified = verify_control_message::<NativeProbePermitRequest>(
        request.canonical_request(),
        now_ms,
        native_probe_time_policy(),
        &mut replay,
    )
    .ok()?;
    let scope = verified.message().scope.as_ref()?;
    let control = scope.control.as_ref()?;
    let exit = scope.exit.as_ref()?;
    (request.forward_id() == &verified.nonce()[..FORWARD_ID_BYTES]
        && native_rpc_deadline_is_within_authority(
            request.deadline_unix_ms(),
            verified.expires_at_ms(),
        )
        && request.control_relay_node_id() == control.node_id
        && request.control_relay_peer_id() == control.peer_id
        && request.exit_node_id() == exit.node_id
        && request.exit_peer_id() == exit.peer_id)
        .then(|| scope.clone())
}

fn verified_native_probe_authorization_forward_scope(
    request: &ExitForwardRequest,
    now_ms: u64,
) -> Option<NativeProbePathScope> {
    if request.validated_operation().ok()? != ExitForwardOperation::NativeProbeAuthorize
        || !deadline_is_bounded(request.deadline_unix_ms(), now_ms)
    {
        return None;
    }
    let verified =
        verify_native_probe_authorization_chain(request.canonical_request(), now_ms).ok()?;
    let scope = verified.scope();
    let data_relay = scope.data_relay.as_ref()?;
    let exit = scope.exit.as_ref()?;
    let start_envelope = decode_canonical::<SignedEnvelope>(
        verified.encoded_start(),
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .ok()?;
    let start_nonce = fixed_bytes::<32>(&start_envelope.nonce)?;
    let authorization_id = native_probe_authorization_request_id(start_nonce);
    (request.forward_id() == authorization_id
        && native_rpc_deadline_is_within_authority(
            request.deadline_unix_ms(),
            verified.expires_at_ms(),
        )
        && request.control_relay_node_id() == data_relay.node_id
        && request.control_relay_peer_id() == data_relay.peer_id
        && request.control_relay_public_key() == data_relay.public_key
        && request.exit_node_id() == exit.node_id
        && request.exit_peer_id() == exit.peer_id)
        .then(|| scope.clone())
}

fn verified_native_probe_result_forward_scope(
    request: &ExitForwardRequest,
    now_ms: u64,
) -> Option<NativeProbePathScope> {
    if request.validated_operation().ok()? != ExitForwardOperation::NativeProbeResult
        || !deadline_is_bounded(request.deadline_unix_ms(), now_ms)
    {
        return None;
    }
    let verified =
        verify_native_probe_authorization_chain(request.canonical_request(), now_ms).ok()?;
    let scope = verified.scope();
    let data_relay = scope.data_relay.as_ref()?;
    let exit = scope.exit.as_ref()?;
    let start_envelope = decode_canonical::<SignedEnvelope>(
        verified.encoded_start(),
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .ok()?;
    let request_id = start_envelope.nonce.get(..FORWARD_ID_BYTES)?;
    (request.forward_id() == request_id
        && native_rpc_deadline_is_within_authority(
            request.deadline_unix_ms(),
            verified.expires_at_ms(),
        )
        && request.control_relay_node_id() == data_relay.node_id
        && request.control_relay_peer_id() == data_relay.peer_id
        && request.control_relay_public_key() == data_relay.public_key
        && request.exit_node_id() == exit.node_id
        && request.exit_peer_id() == exit.peer_id)
        .then(|| scope.clone())
}

fn verified_native_probe_ready_forward_scope(
    request: &ExitForwardRequest,
    now_ms: u64,
) -> Option<NativeProbePathScope> {
    if request.validated_operation().ok()? != ExitForwardOperation::NativeProbeReady
        || !deadline_is_bounded(request.deadline_unix_ms(), now_ms)
    {
        return None;
    }
    let ready = decode_canonical::<NativeProbeReadyForwardRequest>(
        request.canonical_request(),
        usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
    )
    .ok()?;
    let mut replay = ReplayCache::new(2).ok()?;
    let permit = verify_native_probe_permit(
        ready.signed_permit_request().to_vec(),
        ready.signed_permit().to_vec(),
        now_ms,
        &mut replay,
    )
    .ok()?;
    let scope = permit.scope();
    let data_relay = scope.data_relay.as_ref()?;
    let exit = scope.exit.as_ref()?;
    (request.forward_id() == scope.probe_id
        && native_rpc_deadline_is_within_authority(
            request.deadline_unix_ms(),
            scope.attempt_expires_at_ms,
        )
        && request.control_relay_node_id() == data_relay.node_id
        && request.control_relay_peer_id() == data_relay.peer_id
        && request.control_relay_public_key() == data_relay.public_key
        && request.exit_node_id() == exit.node_id
        && request.exit_peer_id() == exit.peer_id
        && ready
            .relay_exit_endpoint()
            .is_some_and(|binding| binding.route_context_id == scope.attempt_id))
    .then(|| scope.clone())
}

fn native_probe_authorization_request_id(mut start_nonce: [u8; 32]) -> [u8; FORWARD_ID_BYTES] {
    start_nonce[0] ^= 0x80;
    let mut request_id: [u8; FORWARD_ID_BYTES] = start_nonce[..FORWARD_ID_BYTES]
        .try_into()
        .expect("fixed nonce prefix");
    if request_id.iter().all(|byte| *byte == 0) {
        request_id[FORWARD_ID_BYTES - 1] = 1;
    }
    request_id
}

fn native_start_probe_id(encoded_start: &[u8]) -> Option<[u8; FORWARD_ID_BYTES]> {
    let envelope = decode_canonical::<SignedEnvelope>(
        encoded_start,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .ok()?;
    let start =
        decode_canonical::<NativeProbeStart>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).ok()?;
    fixed_bytes::<FORWARD_ID_BYTES>(&start.scope?.probe_id)
}

fn native_start_authorization_id(encoded_start: &[u8]) -> Option<[u8; FORWARD_ID_BYTES]> {
    let envelope = decode_canonical::<SignedEnvelope>(
        encoded_start,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .ok()?;
    Some(native_probe_authorization_request_id(fixed_bytes::<32>(
        &envelope.nonce,
    )?))
}

fn decoded_signed_payload<M: ControlPayload>(encoded: &[u8]) -> Option<M> {
    let envelope =
        decode_canonical::<SignedEnvelope>(encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
            .ok()?;
    let payload = decode_canonical::<M>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).ok()?;
    payload.validate().ok()?;
    Some(payload)
}

fn decoded_relay_reservation_request(
    encoded: &[u8],
) -> Option<(RelayReservationRequest, RelayAuthorization)> {
    let request = decoded_signed_payload::<RelayReservationRequest>(encoded)?;
    let authorization = decoded_signed_payload::<RelayAuthorization>(&request.exit_authorization)?;
    Some((request, authorization))
}

fn exit_finalize_response(bundle: &AcceptedExitReservationBundle) -> Vec<Vec<u8>> {
    std::iter::once(bundle.signed_exit_reservation().to_vec())
        .chain(bundle.relay_authorizations().iter().cloned())
        .collect()
}

fn fresh_exit_route_runtime_instance_id() -> Option<[u8; 32]> {
    loop {
        let mut instance_id = [0_u8; 32];
        OsRng.try_fill_bytes(&mut instance_id).ok()?;
        if instance_id != [0; 32] {
            return Some(instance_id);
        }
    }
}

fn endpoint_hint_from_observation(
    binding: &EndpointTraversalBinding,
    observed: IpAddr,
    remote: &(String, Option<IpAddr>),
) -> Option<TraversalEndpointHint> {
    let bytes = |address: IpAddr| match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let (observed_address, on_link) = if is_public_routable_ip(observed) {
        (bytes(observed), None)
    } else {
        let peer = remote.1?;
        if remote.0.contains("/p2p-circuit")
            || !is_local_lan_ip(observed)
            || !is_local_lan_ip(peer)
            || observed.is_ipv4() != peer.is_ipv4()
            || observed == peer
        {
            return None;
        }
        (
            Vec::new(),
            Some(volparossa_routing::OnLinkUnderlayHint {
                local_address: bytes(observed),
                peer_address: bytes(peer),
            }),
        )
    };
    // The permanent transport PeerId stays helper-local. RelayClient's observer_id is the
    // signed ephemeral session actor; neither this hint nor its interface proof goes to Exit.
    Some(TraversalEndpointHint {
        path_id: binding.path_id,
        role: binding.role as i32,
        observer_id: binding.observer_id.to_vec(),
        observer_peer_id: binding.observer_peer_id.to_bytes(),
        observed_address,
        on_link,
    })
}

fn public_udp_endpoint(
    endpoint: volparossa_wireguard::PublicWireGuardEndpoint,
) -> PublicUdpEndpoint {
    let address = match endpoint.underlay_ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    PublicUdpEndpoint {
        address,
        port: u32::from(endpoint.listen_port()),
    }
}

fn production_exit_prepare_request(
    finalize: &ExitReservationFinalizeRequest,
    setup_expires_at_ms: u64,
    hard_expires_at_ms: u64,
) -> Option<PrepareLeaseBatch> {
    let route_context_id = fixed_bytes::<FORWARD_ID_BYTES>(&finalize.route_context_id)?;
    if route_context_id == [0; FORWARD_ID_BYTES]
        || finalize.relay_paths.is_empty()
        || finalize.relay_paths.len() > usize::from(volparossa_wireguard::MAX_PATHS)
        || setup_expires_at_ms > hard_expires_at_ms
    {
        return None;
    }
    // Helper ownership may never extend past the millisecond authority that created it. Rounding
    // up would make almost every non-second-aligned signed grant fail Activate's expiry binding.
    let setup_expires_at_unix = setup_expires_at_ms / 1_000;
    let hard_expires_at_unix = hard_expires_at_ms / 1_000;
    if setup_expires_at_unix <= unix_seconds() || hard_expires_at_unix < setup_expires_at_unix {
        return None;
    }
    let mut path_ids = finalize
        .relay_paths
        .iter()
        .map(|path| path.path_id)
        .collect::<Vec<_>>();
    path_ids.sort_unstable();
    if path_ids.iter().enumerate().any(|(index, path_id)| {
        *path_id == 0
            || *path_id > u32::from(volparossa_wireguard::MAX_PATHS)
            || path_ids.get(index.saturating_sub(1)) == Some(path_id) && index != 0
    }) {
        return None;
    }
    let path_count = u32::try_from(path_ids.len()).ok()?;
    Some(PrepareLeaseBatch {
        route_context_id: route_context_id.to_vec(),
        role: ContextRole::Exit as i32,
        mptcp_accepted_addrs: path_count,
        mptcp_subflows: path_count,
        leases: path_ids
            .into_iter()
            .map(|path_id| LeasePlan {
                path_id,
                role: WireguardRole::Exit as i32,
            })
            .collect(),
        setup_expires_at_unix,
        hard_expires_at_unix,
        traversal_hints: Vec::new(),
    })
}

fn production_service_prepare_request(
    route_context_id: [u8; FORWARD_ID_BYTES],
    role: ContextRole,
    path_id: u32,
    setup_expires_at_ms: u64,
    hard_expires_at_ms: u64,
) -> Option<PrepareLeaseBatch> {
    if route_context_id.iter().all(|byte| *byte == 0)
        || !(1..=8).contains(&path_id)
        || setup_expires_at_ms > hard_expires_at_ms
        || !matches!(role, ContextRole::Relay | ContextRole::Exit)
    {
        return None;
    }
    // Keep privileged lifetime within the exact signed millisecond authority (see the Exit path
    // above); truncation is deliberately fail-closed by at most 999 ms.
    let setup_expires_at_unix = setup_expires_at_ms / 1_000;
    let hard_expires_at_unix = hard_expires_at_ms / 1_000;
    if setup_expires_at_unix <= unix_seconds() || hard_expires_at_unix < setup_expires_at_unix {
        return None;
    }
    let lease_roles: &[WireguardRole] = match role {
        ContextRole::Relay => &[WireguardRole::RelayClient, WireguardRole::RelayExit],
        ContextRole::Exit => &[WireguardRole::Exit],
        ContextRole::Unspecified | ContextRole::Client => return None,
    };
    Some(PrepareLeaseBatch {
        route_context_id: route_context_id.to_vec(),
        role: role as i32,
        mptcp_accepted_addrs: 1,
        mptcp_subflows: 1,
        leases: lease_roles
            .iter()
            .map(|lease_role| LeasePlan {
                path_id,
                role: *lease_role as i32,
            })
            .collect(),
        setup_expires_at_unix,
        hard_expires_at_unix,
        traversal_hints: Vec::new(),
    })
}

fn commit_lease_batch(activation: &ActivateLeaseBatch) -> CommitLeaseBatch {
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

fn exact_mptcp_exit_commit(
    route: &PreparedProductionExitRoute,
    commit: &CommitLeaseBatch,
    selected_path_ids: &[u32],
) -> bool {
    let prepare = route.helper_owner.prepare();
    if ContextRole::try_from(prepare.role).ok() != Some(ContextRole::Exit)
        || prepare.route_context_id != route.bundle.accepted().route_context_id()
        || commit.route_context_id != prepare.route_context_id
        || commit.context_handle != route.helper_owner.prepared().context_handle
        || selected_path_ids.len() < 2
        || selected_path_ids.len() > usize::from(volparossa_wireguard::MAX_PATHS)
        || prepare.leases.len() != selected_path_ids.len()
        || commit.leases.len() != selected_path_ids.len()
    {
        return false;
    }
    let prepared = prepare
        .leases
        .iter()
        .map(|lease| (lease.path_id, lease.role))
        .collect::<BTreeSet<_>>();
    let committed = commit
        .leases
        .iter()
        .map(|lease| (lease.path_id, lease.role))
        .collect::<BTreeSet<_>>();
    let expected = selected_path_ids
        .iter()
        .copied()
        .map(|path_id| (path_id, WireguardRole::Exit as i32))
        .collect::<BTreeSet<_>>();
    prepared.len() == selected_path_ids.len()
        && committed.len() == selected_path_ids.len()
        && prepared == expected
        && committed == expected
}

fn native_service_prepare_request(
    scope: &NativeProbePathScope,
    role: ContextRole,
    lease_roles: &[WireguardRole],
    now_ms: u64,
) -> Option<PrepareLeaseBatch> {
    if scope.attempt_id.len() != FORWARD_ID_BYTES
        || scope.attempt_id.iter().all(|byte| *byte == 0)
        || !(1..=u32::try_from(volparossa_protocol::MAX_NATIVE_PROBE_PATHS).ok()?)
            .contains(&scope.required_path_count)
        || !(1..=scope.required_path_count).contains(&scope.candidate_ordinal)
        || scope.attempt_expires_at_ms <= now_ms.saturating_add(1_000)
        || !matches!(
            (role, lease_roles),
            (
                ContextRole::Relay,
                [WireguardRole::RelayClient, WireguardRole::RelayExit]
            ) | (ContextRole::Exit, [WireguardRole::Exit])
        )
    {
        return None;
    }
    let now_unix = now_ms / 1_000;
    let hard_expires_at_unix = scope.attempt_expires_at_ms / 1_000;
    let setup_expires_at_unix =
        hard_expires_at_unix.min(now_unix.checked_add(TUNNEL_SETUP_TIMEOUT_SECONDS)?);
    let leases = match role {
        ContextRole::Relay => lease_roles
            .iter()
            .map(|lease_role| LeasePlan {
                path_id: scope.candidate_ordinal,
                role: *lease_role as i32,
            })
            .collect(),
        ContextRole::Exit => (1..=scope.required_path_count)
            .map(|path_id| LeasePlan {
                path_id,
                role: WireguardRole::Exit as i32,
            })
            .collect(),
        ContextRole::Unspecified | ContextRole::Client => return None,
    };
    let local_path_count = match role {
        ContextRole::Exit => scope.required_path_count,
        ContextRole::Relay => 1,
        ContextRole::Unspecified | ContextRole::Client => return None,
    };
    (setup_expires_at_unix > now_unix).then(|| PrepareLeaseBatch {
        route_context_id: scope.attempt_id.clone(),
        role: role as i32,
        mptcp_accepted_addrs: local_path_count,
        mptcp_subflows: local_path_count,
        leases,
        setup_expires_at_unix,
        hard_expires_at_unix,
        traversal_hints: Vec::new(),
    })
}

fn native_exit_ready_prepare_matches(
    owner_prepare: &PrepareLeaseBatch,
    requested_prepare: &PrepareLeaseBatch,
    now_ms: u64,
) -> bool {
    if owner_prepare.setup_expires_at_unix <= now_ms / 1_000 {
        return false;
    }
    let mut requested_prepare = requested_prepare.clone();
    requested_prepare.setup_expires_at_unix = owner_prepare.setup_expires_at_unix;
    owner_prepare == &requested_prepare
}

fn native_endpoint_binding(
    helper_runtime_id: [u8; 32],
    route_context_id: &[u8; FORWARD_ID_BYTES],
    lease_handle: &[u8; 32],
    path_id: u32,
    endpoint: volparossa_wireguard::PublicWireGuardEndpoint,
) -> Option<NativeProbeEndpointBinding> {
    let wire = protocol_endpoint_for_native(endpoint);
    let commitment = native_probe_prepared_lease_commitment(
        &helper_runtime_id,
        route_context_id,
        lease_handle,
        &wire,
    )
    .ok()?;
    Some(NativeProbeEndpointBinding {
        helper_runtime_id: helper_runtime_id.to_vec(),
        route_context_id: route_context_id.to_vec(),
        endpoint: Some(wire),
        prepared_lease_commitment: commitment.to_vec(),
        path_id,
    })
}

fn native_probe_control_capability_matches(
    capability: &DirectRelayCapability,
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    required_until_ms: u64,
) -> bool {
    scope.control.as_ref() == Some(actor)
        && actor.node_id.as_slice() == capability.node_id
        && actor.peer_id == capability.peer_id.to_bytes()
        && actor.public_key.as_slice() == capability.public_key
        && actor.advertisement_sequence == capability.advertisement_sequence
        && actor.advertisement_expires_at_ms == capability.advertisement_expires_at_ms
        && capability
            .advertisement_payload_hash
            .matches_native_probe_commitment(&actor.advertisement_payload_hash)
        && actor.capability_expires_at_ms == capability.expires_at_ms
        && capability.peer_id == authenticated_peer
        && capability.policy_version == scope.policy_version
        && capability.policy_hash.as_slice() == scope.policy_hash
        && capability.policy_expires_at_ms == scope.policy_expires_at_ms
        && capability.expires_at_ms >= required_until_ms
}

/// Accept an exact control-Relay capability or an asynchronously observed same-identity version.
///
/// The Client and Exit can receive consecutive signed Relay advertisements in either order. The
/// actor committed by the verified Permit scope must cover the complete attempt. The Exit's own
/// view is used only to prove that the authenticated forwarding peer still serves the same policy
/// through this bounded RPC. An equal sequence still requires exact payload and expiry equality, so
/// a contradictory same-version advertisement cannot be substituted.
fn native_probe_control_capability_lineage_matches(
    current: &DirectRelayCapability,
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    operation_deadline_ms: u64,
    now_ms: u64,
) -> bool {
    if native_probe_control_capability_matches(
        current,
        actor,
        scope,
        authenticated_peer,
        operation_deadline_ms,
    ) {
        return true;
    }

    scope.control.as_ref() == Some(actor)
        && actor.node_id.as_slice() == current.node_id
        && actor.peer_id == current.peer_id.to_bytes()
        && actor.public_key.as_slice() == current.public_key
        && actor.advertisement_sequence > 0
        && actor.advertisement_sequence != current.advertisement_sequence
        && fixed_bytes::<32>(&actor.advertisement_payload_hash).is_some_and(|hash| hash != [0; 32])
        && actor.advertisement_expires_at_ms >= scope.attempt_expires_at_ms
        && actor.capability_expires_at_ms >= scope.attempt_expires_at_ms
        && actor.capability_expires_at_ms <= actor.advertisement_expires_at_ms
        && actor.capability_expires_at_ms <= scope.policy_expires_at_ms
        && current.peer_id == authenticated_peer
        && current.policy_version == scope.policy_version
        && current.policy_hash.as_slice() == scope.policy_hash
        && current.policy_expires_at_ms == scope.policy_expires_at_ms
        && current.advertisement_expires_at_ms > now_ms
        && current.advertisement_expires_at_ms >= operation_deadline_ms
        && current.expires_at_ms >= operation_deadline_ms
}

fn cache_exit_data_relay_capability(
    cache: &mut HashMap<Libp2pPeerId, DirectRelayCapability>,
    candidate_limit: usize,
    encoded_advertisement: &[u8],
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    now_ms: u64,
) -> Option<DirectRelayCapability> {
    if scope.attempt_expires_at_ms <= now_ms {
        return None;
    }
    if let Some(current) = cache.get(&authenticated_peer).filter(|current| {
        native_probe_data_relay_capability_matches(
            current,
            actor,
            scope,
            authenticated_peer,
            scope.attempt_expires_at_ms,
        )
    }) {
        return Some(current.clone());
    }
    let capability = native_probe_data_relay_capability_from_advertisement(
        encoded_advertisement,
        actor,
        scope,
        authenticated_peer,
        now_ms,
    )?;
    if !native_probe_data_relay_capability_matches(
        &capability,
        actor,
        scope,
        authenticated_peer,
        scope.attempt_expires_at_ms,
    ) {
        return None;
    }
    retain_exit_relay_capability(cache, candidate_limit, capability)
}

/// Keep bounded Exit-service authority without changing the independent Client candidate set.
fn retain_exit_relay_capability(
    cache: &mut HashMap<Libp2pPeerId, DirectRelayCapability>,
    candidate_limit: usize,
    capability: DirectRelayCapability,
) -> Option<DirectRelayCapability> {
    let authenticated_peer = capability.peer_id;
    if cache.get(&authenticated_peer) == Some(&capability) {
        return Some(capability);
    }
    let replace_cached = match cache.get(&authenticated_peer) {
        Some(current)
            if current.node_id != capability.node_id
                || current.public_key != capability.public_key
                || current.peer_id != capability.peer_id
                || current.policy_version != capability.policy_version
                || current.policy_hash != capability.policy_hash
                || current.policy_expires_at_ms != capability.policy_expires_at_ms
                || current.advertisement_sequence == capability.advertisement_sequence =>
        {
            return None;
        }
        Some(current) => current.advertisement_sequence < capability.advertisement_sequence,
        None if cache.len() >= candidate_limit.max(1) => return None,
        None => true,
    };
    if replace_cached {
        cache.insert(authenticated_peer, capability.clone());
    }
    Some(capability)
}

fn native_probe_data_relay_capability_matches(
    capability: &DirectRelayCapability,
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    required_until_ms: u64,
) -> bool {
    scope.data_relay.as_ref() == Some(actor)
        && actor.node_id.as_slice() == capability.node_id
        && actor.peer_id == capability.peer_id.to_bytes()
        && actor.public_key.as_slice() == capability.public_key
        && actor.advertisement_sequence == capability.advertisement_sequence
        && actor.advertisement_expires_at_ms == capability.advertisement_expires_at_ms
        && capability
            .advertisement_payload_hash
            .matches_native_probe_commitment(&actor.advertisement_payload_hash)
        && actor.capability_expires_at_ms == capability.expires_at_ms
        && capability.peer_id == authenticated_peer
        && capability.policy_version == scope.policy_version
        && capability.policy_hash.as_slice() == scope.policy_hash
        && capability.policy_expires_at_ms == scope.policy_expires_at_ms
        && capability.expires_at_ms >= required_until_ms
}

fn local_relay_policy_is_current(
    capability: &DirectRelayCapability,
    scope: &NativeProbePathScope,
    local_node_id: [u8; 32],
    local_peer_id: Libp2pPeerId,
    local_public_key: [u8; 32],
    now_ms: u64,
) -> bool {
    capability.node_id == local_node_id
        && capability.peer_id == local_peer_id
        && capability.public_key == local_public_key
        && capability.policy_version == scope.policy_version
        && capability.policy_hash.as_slice() == scope.policy_hash
        && capability.policy_expires_at_ms == scope.policy_expires_at_ms
        && capability.expires_at_ms > now_ms
}

/// Reconstruct the exact data-Relay capability carried by a native Ready request.
///
/// The request's authenticated libp2p connection remains the authority for peer identity. The
/// carried advertisement is accepted only as a self-contained cryptographic proof of the exact
/// actor already committed by the signed native scope; it deliberately does not enter the normal
/// advertisement replay, persistence, candidate, or provider-record paths.
fn native_probe_data_relay_capability_from_advertisement(
    encoded_advertisement: &[u8],
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    now_ms: u64,
) -> Option<DirectRelayCapability> {
    if scope.data_relay.as_ref() != Some(actor) {
        return None;
    }
    native_probe_relay_capability_from_advertisement(
        encoded_advertisement,
        actor,
        scope,
        authenticated_peer,
        now_ms,
    )
}

/// Verify a self-contained signed Relay capability for the exact control or data actor.
/// This never consults or populates this node's independent Client candidate cache.
fn native_probe_relay_capability_from_advertisement(
    encoded_advertisement: &[u8],
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    authenticated_peer: Libp2pPeerId,
    now_ms: u64,
) -> Option<DirectRelayCapability> {
    if !advertisement_envelope_matches_peer(encoded_advertisement, &authenticated_peer) {
        return None;
    }
    let envelope = decode_canonical::<SignedEnvelope>(
        encoded_advertisement,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .ok()?;
    let payload_hash = fixed_bytes::<32>(&envelope.payload_hash)?;
    let fingerprint = advertisement_fingerprint(encoded_advertisement)?;
    let mut replay = ReplayCache::new(1).ok()?;
    let verified = verify_control_message::<WireAdvertisement>(
        encoded_advertisement,
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .ok()?;
    let advertisement = verified.message();
    let roles = advertisement.roles.as_ref()?;
    let capabilities = advertisement.capabilities.as_ref()?;
    let policy = advertisement.policy.as_ref()?;
    let network = advertisement.network.as_ref()?;
    let policy_hash = fixed_bytes::<32>(&policy.whitelist_hash)?;
    let node_id = *verified.sender_id();
    let public_key = *verified.sender_public_key();
    let advertisement_expires_at_ms = verified.expires_at_ms();
    let maximum_capability_expiry = advertisement_expires_at_ms.min(scope.policy_expires_at_ms);

    if (scope.data_relay.as_ref() != Some(actor) && scope.control.as_ref() != Some(actor))
        || !roles.relay
        || (network.asn == 0
            && network.uplink != volparossa_protocol::AdvertisementUplink::LocalOnly as i32)
        || !native_probe_capabilities_support_scope(capabilities, scope)
        || node_id_from_public_key(&public_key) != node_id
        || advertisement.node_id.as_slice() != node_id
        || advertisement.peer_id != authenticated_peer.to_bytes()
        || advertisement.sequence_number == 0
        || advertisement.sequence_number != actor.advertisement_sequence
        || advertisement.expires_at_ms != advertisement_expires_at_ms
        || advertisement_expires_at_ms != actor.advertisement_expires_at_ms
        || advertisement_expires_at_ms <= now_ms
        || policy.whitelist_version != scope.policy_version
        || policy_hash.as_slice() != scope.policy_hash
        || scope.policy_expires_at_ms <= now_ms
        || actor.node_id.as_slice() != node_id
        || actor.peer_id != authenticated_peer.to_bytes()
        || actor.public_key.as_slice() != public_key
        || actor.advertisement_payload_hash.as_slice() != payload_hash
        || actor.capability_expires_at_ms > maximum_capability_expiry
        || actor.capability_expires_at_ms <= now_ms
    {
        return None;
    }

    Some(DirectRelayCapability {
        node_id,
        peer_id: authenticated_peer,
        public_key,
        advertisement_sequence: advertisement.sequence_number,
        advertisement_expires_at_ms,
        advertisement_payload_hash: fingerprint.payload_hash,
        policy_version: scope.policy_version,
        policy_hash,
        policy_expires_at_ms: scope.policy_expires_at_ms,
        expires_at_ms: actor.capability_expires_at_ms,
    })
}

/// Recover the exact still-valid local Relay authority committed by a native scope.
///
/// Publication refresh is intentionally independent from an already signed attempt. Search the
/// bounded served lineage and reverify every candidate instead of substituting the current local
/// advertisement for the actor that the Permit actually names.
fn local_native_probe_data_relay_authority(
    service: &DiscoveryService,
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    local_peer: Libp2pPeerId,
    now_ms: u64,
    required_until_ms: u64,
) -> Option<(DirectRelayCapability, Vec<u8>)> {
    service.bounded_local_advertisements().find_map(|encoded| {
        let capability = native_probe_data_relay_capability_from_advertisement(
            encoded, actor, scope, local_peer, now_ms,
        )?;
        native_probe_data_relay_capability_matches(
            &capability,
            actor,
            scope,
            local_peer,
            required_until_ms,
        )
        .then(|| (capability, encoded.to_vec()))
    })
}

/// The control Relay adds only its own exact signed authority on the upstream hop. The
/// client-session-signed request stays byte-identical, and no Client endpoint accompanies it.
fn local_exit_forward_upstream_request(
    service: &DiscoveryService,
    request: &ExitForwardRequest,
    local_peer: Libp2pPeerId,
    now_ms: u64,
) -> Option<UpstreamExitForwardRequest> {
    request.validate().ok()?;
    if !request.control_advertisement().is_empty() {
        return None;
    }
    let upstream = UpstreamExitForwardRequest::from(request.clone());
    if request.validated_operation().ok()? != ExitForwardOperation::NativeProbePermit {
        return Some(upstream);
    }
    let scope = verified_native_probe_forward_scope(request, now_ms)?;
    let actor = scope.control.as_ref()?;
    let advertisement = service.bounded_local_advertisements().find_map(|encoded| {
        let capability = native_probe_relay_capability_from_advertisement(
            encoded, actor, &scope, local_peer, now_ms,
        )?;
        native_probe_control_capability_matches(
            &capability,
            actor,
            &scope,
            local_peer,
            scope.attempt_expires_at_ms,
        )
        .then(|| encoded.to_vec())
    })?;
    upstream.with_control_advertisement(advertisement).ok()
}

fn local_native_probe_exit_actor_is_served(
    service: &DiscoveryService,
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    local_node_id: [u8; 32],
    local_peer_id: Libp2pPeerId,
    local_public_key: [u8; 32],
    now_ms: u64,
) -> bool {
    service.bounded_local_advertisements().any(|encoded| {
        local_native_probe_exit_actor_matches(
            encoded,
            actor,
            scope,
            local_node_id,
            local_peer_id,
            local_public_key,
            now_ms,
        )
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the local signed advertisement and exact native scope stay explicit"
)]
fn local_native_probe_exit_actor_matches(
    encoded_advertisement: &[u8],
    actor: &PreselectionActorBinding,
    scope: &NativeProbePathScope,
    local_node_id: [u8; 32],
    local_peer_id: Libp2pPeerId,
    local_public_key: [u8; 32],
    now_ms: u64,
) -> bool {
    let Ok(envelope) = decode_canonical::<SignedEnvelope>(
        encoded_advertisement,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    ) else {
        return false;
    };
    let Some(payload_hash) = fixed_bytes::<32>(&envelope.payload_hash) else {
        return false;
    };
    let Ok(mut replay) = ReplayCache::new(1) else {
        return false;
    };
    let Ok(verified) = verify_control_message::<WireAdvertisement>(
        encoded_advertisement,
        now_ms,
        TimePolicy::default(),
        &mut replay,
    ) else {
        return false;
    };
    let advertisement = verified.message();
    let Some(roles) = advertisement.roles.as_ref() else {
        return false;
    };
    let Some(capabilities) = advertisement.capabilities.as_ref() else {
        return false;
    };
    let Some(policy) = advertisement.policy.as_ref() else {
        return false;
    };
    let Some(network) = advertisement.network.as_ref() else {
        return false;
    };
    let Some(control) = scope.control.as_ref() else {
        return false;
    };
    let expected_capability_expiry = verified
        .expires_at_ms()
        .min(scope.policy_expires_at_ms)
        .min(control.capability_expires_at_ms);
    scope.exit.as_ref() == Some(actor)
        && roles.exit
        && network.asn != 0
        && native_probe_capabilities_support_scope(capabilities, scope)
        && verified.sender_id() == &local_node_id
        && verified.sender_public_key() == &local_public_key
        && advertisement.node_id.as_slice() == local_node_id
        && advertisement.peer_id == local_peer_id.to_bytes()
        && advertisement.sequence_number != 0
        && advertisement.expires_at_ms == verified.expires_at_ms()
        && policy.whitelist_version == scope.policy_version
        && policy.whitelist_hash == scope.policy_hash
        && verified.expires_at_ms() <= scope.policy_expires_at_ms
        && actor.node_id.as_slice() == local_node_id
        && actor.peer_id == local_peer_id.to_bytes()
        && actor.public_key.as_slice() == local_public_key
        && actor.advertisement_sequence == advertisement.sequence_number
        && actor.advertisement_expires_at_ms == verified.expires_at_ms()
        && actor.advertisement_payload_hash.as_slice() == payload_hash
        && actor.capability_expires_at_ms <= expected_capability_expiry
        && actor.capability_expires_at_ms > now_ms
}

fn native_probe_capabilities_support_scope(
    capabilities: &AdvertisementCapabilities,
    scope: &NativeProbePathScope,
) -> bool {
    let family_supported = match ObservationAddressFamily::try_from(scope.address_family) {
        Ok(ObservationAddressFamily::Ipv4) => capabilities.ipv4,
        Ok(ObservationAddressFamily::Ipv6) => capabilities.ipv6,
        Ok(ObservationAddressFamily::Unspecified) | Err(_) => false,
    };
    let transport_supported = match Transport::try_from(scope.transport) {
        Ok(Transport::TcpMptcp) => capabilities.tcp_mptcp,
        Ok(Transport::UdpSinglePath) => capabilities.udp_single_path,
        Ok(Transport::MultipathQuic) => capabilities.multipath_quic,
        Ok(Transport::Unspecified) | Err(_) => false,
    };
    family_supported && transport_supported
}

fn native_probe_time_policy() -> TimePolicy {
    TimePolicy {
        maximum_lifetime_ms: MAX_NATIVE_PROBE_LIFETIME_MS,
        maximum_clock_skew_ms: TimePolicy::default().maximum_clock_skew_ms,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive operation matrix keeps every signed forward scope explicit"
)]
fn forward_request_scope_matches(
    request: &ExitForwardRequest,
    operation: ExitForwardOperation,
    now_ms: u64,
) -> bool {
    if !deadline_is_bounded(request.deadline_unix_ms(), now_ms) {
        return false;
    }
    if operation == ExitForwardOperation::FetchExitAdvertisement {
        return request.canonical_request().is_empty();
    }
    let Ok(mut replay) = ReplayCache::new(1) else {
        return false;
    };
    match operation {
        ExitForwardOperation::CapacityHold => {
            let Ok(verified) = verify_control_message::<ExitCapacityHoldRequest>(
                request.canonical_request(),
                now_ms,
                TimePolicy::default(),
                &mut replay,
            ) else {
                return false;
            };
            inner_forward_scope_matches(
                request,
                verified.nonce(),
                verified.expires_at_ms(),
                &verified.message().control_relay_node_id,
                &verified.message().control_relay_peer_id,
                &verified.message().exit_node_id,
                &verified.message().exit_peer_id,
            )
        }
        ExitForwardOperation::ProbePermit => {
            let Ok(verified) = verify_control_message::<RelayProbePermitRequest>(
                request.canonical_request(),
                now_ms,
                TimePolicy::default(),
                &mut replay,
            ) else {
                return false;
            };
            inner_forward_scope_matches(
                request,
                verified.nonce(),
                verified.expires_at_ms(),
                &verified.message().control_relay_node_id,
                &verified.message().control_relay_peer_id,
                &verified.message().exit_node_id,
                &verified.message().exit_peer_id,
            )
        }
        ExitForwardOperation::FinalizeReservation => {
            let Ok(verified) = verify_control_message::<ExitReservationFinalizeRequest>(
                request.canonical_request(),
                now_ms,
                TimePolicy::default(),
                &mut replay,
            ) else {
                return false;
            };
            inner_forward_scope_matches(
                request,
                verified.nonce(),
                verified.expires_at_ms(),
                &verified.message().control_relay_node_id,
                &verified.message().control_relay_peer_id,
                &verified.message().exit_node_id,
                &verified.message().exit_peer_id,
            )
        }
        ExitForwardOperation::ConfirmRelay => {
            let Ok(verified) = verify_control_message::<ExitReservationConfirmation>(
                request.canonical_request(),
                now_ms,
                TimePolicy::default(),
                &mut replay,
            ) else {
                return false;
            };
            inner_forward_scope_matches(
                request,
                verified.nonce(),
                verified.expires_at_ms(),
                &verified.message().control_relay_node_id,
                &verified.message().control_relay_peer_id,
                &verified.message().exit_node_id,
                &verified.message().exit_peer_id,
            )
        }
        ExitForwardOperation::NativeProbePermit => {
            verified_native_probe_forward_scope(request, now_ms).is_some()
        }
        ExitForwardOperation::NativeProbeAuthorize => {
            verified_native_probe_authorization_forward_scope(request, now_ms).is_some()
        }
        ExitForwardOperation::NativeProbeReady => {
            verified_native_probe_ready_forward_scope(request, now_ms).is_some()
        }
        ExitForwardOperation::NativeProbeResult => {
            verified_native_probe_result_forward_scope(request, now_ms).is_some()
        }
        ExitForwardOperation::UdpSessionStart => {
            verified_udp_session_start_scope(request.canonical_request(), now_ms).is_some_and(
                |scope| {
                    request.forward_id() == &scope.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= scope.expires_at_ms
                        && request.control_relay_node_id() == scope.relay.relay_node_id
                        && request.control_relay_peer_id() == scope.relay.relay_peer_id
                        && request.exit_node_id() == scope.exit.exit_node_id
                        && request.exit_peer_id() == scope.exit.exit_peer_id
                },
            )
        }
        ExitForwardOperation::MptcpSessionStart => {
            verified_mptcp_session_start_scope(request.canonical_request(), now_ms)
                .and_then(|scope| {
                    (request.exit_node_id() == scope.exit.exit_node_id
                        && request.exit_peer_id() == scope.exit.exit_peer_id)
                        .then(|| {
                            scope.paths.into_iter().find(|path| {
                                request.control_relay_node_id() == path.relay.relay_node_id
                                    && request.control_relay_peer_id() == path.relay.relay_peer_id
                            })
                        })
                        .flatten()
                })
                .is_some_and(|path| {
                    request.forward_id() == &path.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= path.expires_at_ms
                })
        }
        ExitForwardOperation::MpquicSessionStart => {
            verified_mpquic_session_start_scope(request.canonical_request(), now_ms)
                .and_then(|scope| {
                    (request.exit_node_id() == scope.exit.exit_node_id
                        && request.exit_peer_id() == scope.exit.exit_peer_id)
                        .then(|| {
                            scope.paths.into_iter().find(|path| {
                                request.control_relay_node_id() == path.relay.relay_node_id
                                    && request.control_relay_peer_id() == path.relay.relay_peer_id
                            })
                        })
                        .flatten()
                })
                .is_some_and(|path| {
                    request.forward_id() == &path.confirmation_nonce[..FORWARD_ID_BYTES]
                        && request.deadline_unix_ms() <= path.expires_at_ms
                })
        }
        ExitForwardOperation::FetchExitAdvertisement | ExitForwardOperation::Unspecified => false,
    }
}

struct VerifiedMpquicPathScope {
    relay: RelayReservation,
    path_id: u32,
    signed_relay_reservation: Vec<u8>,
    confirmation_nonce: [u8; 32],
    expires_at_ms: u64,
}

struct VerifiedMpquicSessionStartScope {
    exit: ExitReservation,
    paths: Vec<VerifiedMpquicPathScope>,
    expires_at_ms: u64,
}

fn mpquic_session_signal_matches(
    pending: &PendingMpquicSessionStart,
    encoded_signal: &[u8],
    now_ms: u64,
) -> bool {
    let Some(scope) = verified_mpquic_session_start_scope(&pending.canonical_start, now_ms) else {
        return false;
    };
    let Some(native_identity) = scope.exit.native_route_identity.as_ref() else {
        return false;
    };
    let expected_path_ids = scope
        .paths
        .iter()
        .map(|path| path.path_id)
        .collect::<Vec<_>>();
    decode_canonical::<ExitMpquicSessionSignal>(
        encoded_signal,
        usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
    )
    .ok()
    .is_some_and(|signal| {
        signal.validate().is_ok()
            && signal.reservation_id() == pending.route.accepted.reservation_id()
            && signal.route_context_id() == pending.route.accepted.route_context_id()
            && signal.exit_native_instance_id() == native_identity.exit_native_instance_id
            && signal.selected_path_ids() == expected_path_ids
            && signal
                .selected_path_ids()
                .contains(&pending.route.accepted.path_id())
    })
}

/// Verify every signature in one complete MPQUIC activation frame without consuming the
/// actor-owned replay state. The Exit service consumes the credential delivery in its persistent
/// replay cache immediately before native handoff.
#[allow(
    clippy::too_many_lines,
    reason = "one exact signed MPQUIC proof-set verification transaction"
)]
fn verified_mpquic_session_start_scope(
    encoded: &[u8],
    now_ms: u64,
) -> Option<VerifiedMpquicSessionStartScope> {
    let request = decode_canonical::<MpquicSessionStartRequest>(
        encoded,
        usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
    )
    .ok()?;
    request.validate().ok()?;
    let replay_capacity = request.paths().len().checked_mul(4)?.checked_add(2)?;
    let mut replay = ReplayCache::new(replay_capacity).ok()?;
    let exit_verified = verify_control_message::<ExitReservation>(
        request.signed_exit_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .ok()?;
    let exit_sender = *exit_verified.sender_id();
    let mut expires_at_ms = exit_verified.expires_at_ms();
    let exit = exit_verified.into_message();
    if exit_sender.as_slice() != exit.exit_node_id {
        return None;
    }
    let credential_verified = verify_control_message::<NativeRouteCredentialDelivery>(
        request.signed_credential_delivery(),
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .ok()?;
    expires_at_ms = expires_at_ms.min(credential_verified.expires_at_ms());
    if credential_verified.sender_id().as_slice() != exit.client_session_id
        || credential_verified.sender_public_key().as_slice() != exit.client_session_public_key
    {
        return None;
    }

    let mut paths = Vec::with_capacity(request.paths().len());
    for proof in request.paths() {
        let (relay_verified, authorization_verified) = verify_relay_reservation(
            proof.signed_relay_reservation(),
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .ok()?;
        let relay_sender = *relay_verified.sender_id();
        let relay_expiry = relay_verified.expires_at_ms();
        let authorization_sender = *authorization_verified.sender_id();
        let authorization_expiry = authorization_verified.expires_at_ms();
        let relay_grant = relay_verified.into_message();
        let confirmation_verified = verify_control_message::<ExitReservationConfirmation>(
            proof.signed_confirmation(),
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .ok()?;
        let confirmation_sender = *confirmation_verified.sender_id();
        let confirmation_public_key = *confirmation_verified.sender_public_key();
        let confirmation_nonce = *confirmation_verified.nonce();
        let confirmation_expiry = confirmation_verified.expires_at_ms();
        let confirmation = confirmation_verified.into_message();
        let receipt_verified = verify_control_message::<ExitConfirmationReceipt>(
            proof.signed_confirmation_receipt(),
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .ok()?;
        let receipt_sender = *receipt_verified.sender_id();
        let receipt_expiry = receipt_verified.expires_at_ms();
        let receipt = receipt_verified.into_message();
        let confirmation_hash =
            exit_confirmation_envelope_hash(proof.signed_confirmation()).ok()?;
        if relay_sender.as_slice() != relay_grant.relay_node_id
            || authorization_sender != exit_sender
            || confirmation_sender.as_slice() != exit.client_session_id
            || confirmation_public_key.as_slice() != exit.client_session_public_key
            || receipt_sender != exit_sender
            || receipt.confirmation_envelope_hash.as_slice() != confirmation_hash
            || confirmation.relay_reservation != proof.signed_relay_reservation()
        {
            return None;
        }
        expires_at_ms = expires_at_ms
            .min(relay_expiry)
            .min(authorization_expiry)
            .min(confirmation_expiry)
            .min(receipt_expiry);
        paths.push(VerifiedMpquicPathScope {
            path_id: relay_grant.path_id,
            relay: relay_grant,
            signed_relay_reservation: proof.signed_relay_reservation().to_vec(),
            confirmation_nonce,
            expires_at_ms: relay_expiry
                .min(authorization_expiry)
                .min(confirmation_expiry)
                .min(receipt_expiry),
        });
    }
    for path in &mut paths {
        path.expires_at_ms = path.expires_at_ms.min(expires_at_ms);
    }
    Some(VerifiedMpquicSessionStartScope {
        exit,
        paths,
        expires_at_ms,
    })
}

struct VerifiedUdpSessionStartScope {
    exit: ExitReservation,
    relay: RelayReservation,
    confirmation_nonce: [u8; 32],
    expires_at_ms: u64,
}

fn verified_udp_session_start_scope(
    encoded: &[u8],
    now_ms: u64,
) -> Option<VerifiedUdpSessionStartScope> {
    let request = decode_canonical::<UdpSessionStartRequest>(
        encoded,
        usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
    )
    .ok()?;
    request.validate().ok()?;
    let mut path_replay = ReplayCache::new(4).ok()?;
    let path = VerifiedSingleRelayPath::verify(
        request.signed_exit_reservation(),
        request.signed_relay_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut path_replay,
    )
    .ok()?;
    let mut verification_replay = ReplayCache::new(4).ok()?;
    let exit_verified = verify_control_message::<ExitReservation>(
        request.signed_exit_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut verification_replay,
    )
    .ok()?;
    let exit_sender = *exit_verified.sender_id();
    let exit = exit_verified.into_message();
    let relay_verified = verify_control_message::<RelayReservation>(
        request.signed_relay_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut verification_replay,
    )
    .ok()?;
    let relay_sender = *relay_verified.sender_id();
    let relay = relay_verified.into_message();
    let confirmation_verified = verify_control_message::<ExitReservationConfirmation>(
        request.signed_confirmation(),
        now_ms,
        TimePolicy::default(),
        &mut verification_replay,
    )
    .ok()?;
    let confirmation_sender = *confirmation_verified.sender_id();
    let confirmation_public_key = *confirmation_verified.sender_public_key();
    let confirmation_nonce = *confirmation_verified.nonce();
    let confirmation = confirmation_verified.into_message();
    let receipt_verified = verify_control_message::<ExitConfirmationReceipt>(
        request.signed_confirmation_receipt(),
        now_ms,
        TimePolicy::default(),
        &mut verification_replay,
    )
    .ok()?;
    let receipt_sender = *receipt_verified.sender_id();
    let receipt_expiry = receipt_verified.expires_at_ms();
    let receipt = receipt_verified.into_message();
    let confirmation_hash = exit_confirmation_envelope_hash(request.signed_confirmation()).ok()?;
    if exit_sender != *path.exit_node_id()
        || relay_sender != *path.relay_node_id()
        || confirmation_sender != *path.client_ephemeral_id()
        || confirmation_public_key.as_slice() != relay.client_session_public_key
        || receipt_sender != *path.exit_node_id()
        || receipt.confirmation_envelope_hash.as_slice() != confirmation_hash
        || receipt.client_session_id != confirmation.client_session_id
        || receipt.capability_id != confirmation.capability_id
        || receipt.hold_id != confirmation.hold_id
        || receipt.finalize_id != confirmation.finalize_id
        || receipt.control_relay_node_id != confirmation.control_relay_node_id
        || receipt.control_relay_peer_id != confirmation.control_relay_peer_id
        || receipt.exit_node_id != confirmation.exit_node_id
        || receipt.exit_peer_id != confirmation.exit_peer_id
        || receipt.exit_boot_id != confirmation.exit_boot_id
    {
        return None;
    }
    let expires_at_ms = receipt_expiry.min(path.expires_at_ms());
    Some(VerifiedUdpSessionStartScope {
        exit,
        relay,
        confirmation_nonce,
        expires_at_ms,
    })
}

struct VerifiedMptcpSessionPathScope {
    relay: RelayReservation,
    confirmation_nonce: [u8; 32],
    expires_at_ms: u64,
}

struct VerifiedMptcpSessionStartScope {
    exit: ExitReservation,
    paths: Vec<VerifiedMptcpSessionPathScope>,
}

/// Verify every signature in one complete MPTCP activation set before actor lineage is matched.
fn verified_mptcp_session_start_scope(
    encoded: &[u8],
    now_ms: u64,
) -> Option<VerifiedMptcpSessionStartScope> {
    let request = decode_canonical::<MptcpSessionStartRequest>(
        encoded,
        usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
    )
    .ok()?;
    request.validate().ok()?;
    let replay_capacity = request.paths().len().checked_mul(3)?.checked_add(1)?;
    let mut verification_cache = ReplayCache::new(replay_capacity).ok()?;
    let exit_verified = verify_control_message::<ExitReservation>(
        request.signed_exit_reservation(),
        now_ms,
        TimePolicy::default(),
        &mut verification_cache,
    )
    .ok()?;
    let exit_sender = *exit_verified.sender_id();
    let exit_expiry = exit_verified.expires_at_ms();
    let exit = exit_verified.into_message();
    if exit_sender.as_slice() != exit.exit_node_id {
        return None;
    }
    let mut paths = Vec::with_capacity(request.paths().len());
    for proof in request.paths() {
        let relay_verified = verify_control_message::<RelayReservation>(
            proof.signed_relay_reservation(),
            now_ms,
            TimePolicy::default(),
            &mut verification_cache,
        )
        .ok()?;
        let relay_sender = *relay_verified.sender_id();
        let relay_expiry = relay_verified.expires_at_ms();
        let relay = relay_verified.into_message();
        let confirmation_verified = verify_control_message::<ExitReservationConfirmation>(
            proof.signed_confirmation(),
            now_ms,
            TimePolicy::default(),
            &mut verification_cache,
        )
        .ok()?;
        let confirmation_sender = *confirmation_verified.sender_id();
        let confirmation_public_key = *confirmation_verified.sender_public_key();
        let confirmation_nonce = *confirmation_verified.nonce();
        let confirmation_expiry = confirmation_verified.expires_at_ms();
        let confirmation = confirmation_verified.into_message();
        let receipt_verified = verify_control_message::<ExitConfirmationReceipt>(
            proof.signed_confirmation_receipt(),
            now_ms,
            TimePolicy::default(),
            &mut verification_cache,
        )
        .ok()?;
        let receipt_sender = *receipt_verified.sender_id();
        let receipt_expiry = receipt_verified.expires_at_ms();
        let receipt = receipt_verified.into_message();
        let confirmation_hash =
            exit_confirmation_envelope_hash(proof.signed_confirmation()).ok()?;
        if relay_sender.as_slice() != relay.relay_node_id
            || confirmation_sender.as_slice() != exit.client_session_id
            || confirmation_public_key.as_slice() != relay.client_session_public_key
            || receipt_sender != exit_sender
            || receipt.confirmation_envelope_hash.as_slice() != confirmation_hash
            || receipt.client_session_id != confirmation.client_session_id
            || receipt.capability_id != confirmation.capability_id
            || receipt.hold_id != confirmation.hold_id
            || receipt.finalize_id != confirmation.finalize_id
            || receipt.control_relay_node_id != confirmation.control_relay_node_id
            || receipt.control_relay_peer_id != confirmation.control_relay_peer_id
            || receipt.exit_node_id != confirmation.exit_node_id
            || receipt.exit_peer_id != confirmation.exit_peer_id
            || receipt.exit_boot_id != confirmation.exit_boot_id
        {
            return None;
        }
        paths.push(VerifiedMptcpSessionPathScope {
            relay,
            confirmation_nonce,
            expires_at_ms: exit_expiry
                .min(relay_expiry)
                .min(confirmation_expiry)
                .min(receipt_expiry),
        });
    }
    Some(VerifiedMptcpSessionStartScope { exit, paths })
}

/// Test-only access to the production exit-forward scope validator.
#[cfg(test)]
pub(crate) fn forward_request_scope_matches_for_test(
    request: &ExitForwardRequest,
    operation: ExitForwardOperation,
    now_ms: u64,
) -> bool {
    forward_request_scope_matches(request, operation, now_ms)
}

/// Test-only access to the production datapath scope validator.
#[cfg(test)]
pub(crate) fn datapath_request_scope_matches_for_test(
    request: &DatapathRelayRequest,
    operation: DatapathRelayOperation,
    now_ms: u64,
) -> bool {
    datapath_request_scope_matches(request, operation, now_ms)
}

fn inner_forward_scope_matches(
    request: &ExitForwardRequest,
    signed_nonce: &[u8; 32],
    signed_expires_at_ms: u64,
    control_relay_node_id: &[u8],
    control_relay_peer_id: &[u8],
    exit_node_id: &[u8],
    exit_peer_id: &[u8],
) -> bool {
    request.forward_id() == &signed_nonce[..FORWARD_ID_BYTES]
        && request.deadline_unix_ms() == signed_expires_at_ms
        && request.control_relay_node_id() == control_relay_node_id
        && request.control_relay_peer_id() == control_relay_peer_id
        && request.exit_node_id() == exit_node_id
        && request.exit_peer_id() == exit_peer_id
}

fn advertisement_fingerprint(encoded: &[u8]) -> Option<AdvertisementFingerprint> {
    let envelope =
        decode_canonical::<SignedEnvelope>(encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
            .ok()?;
    Some(AdvertisementFingerprint {
        encoded_len: encoded.len(),
        payload_hash: AdvertisementPayloadHash::from_fresh_fingerprint(fixed_bytes::<32>(
            &envelope.payload_hash,
        )?)?,
        signature: fixed_bytes::<64>(&envelope.signature)?,
    })
}

fn has_active_privacy_conflict(
    conflicts: &HashMap<PrivacyConflictKey, u64>,
    fail_closed_until_ms: u64,
    peer: Libp2pPeerId,
    now_ms: u64,
) -> bool {
    fail_closed_until_ms > now_ms
        || conflicts
            .iter()
            .any(|(key, expiry)| key.peer_id == peer && *expiry > now_ms)
}

fn rpc_deadline(deadline_unix_ms: u64, maximum: Duration) -> Instant {
    let remaining = Duration::from_millis(deadline_unix_ms.saturating_sub(unix_millis()));
    Instant::now() + remaining.min(maximum)
}

fn provider_key_matches(key: &kad::RecordKey, kind: ProviderQueryKind) -> bool {
    let expected = match kind {
        ProviderQueryKind::Relay => capability::RELAY,
        ProviderQueryKind::Exit => capability::EXIT,
    };
    key.as_ref() == expected.as_bytes()
}

fn exit_response_matches(
    response: &ExitForwardResponse,
    forward_id: [u8; FORWARD_ID_BYTES],
    operation: ExitForwardOperation,
    expected_exit_peer: Libp2pPeerId,
    expected_exit_node_id: Option<[u8; 32]>,
) -> bool {
    response.validate().is_ok()
        && response.forward_id() == forward_id
        && response.validated_operation() == Ok(operation)
        && response.exit_peer_id() == expected_exit_peer.to_bytes()
        && expected_exit_node_id.is_none_or(|node_id| response.exit_node_id() == node_id)
        && (response.validated_status() != Ok(ForwardStatus::Granted)
            || matches!(
                operation,
                ExitForwardOperation::UdpSessionStart
                    | ExitForwardOperation::MptcpSessionStart
                    | ExitForwardOperation::MpquicSessionStart
            )
            || response
                .signed_responses()
                .iter()
                .all(|envelope| signed_envelope_matches_peer(envelope, &expected_exit_peer)))
}

fn mesh_listener_address(config: &Config) -> Result<Option<Multiaddr>, DiscoveryRuntimeError> {
    use libp2p::multiaddr::Protocol;
    let ip: IpAddr = config
        .wifi_mesh
        .local_address
        .parse()
        .map_err(|_| DiscoveryRuntimeError::ListenAddress)?;
    if config.network.listen_addresses.is_empty() && ip.is_ipv4() {
        return Ok(None); // The normal IPv4 wildcard QUIC listener covers this new interface.
    }
    for text in &config.network.listen_addresses {
        let address =
            Multiaddr::from_str(text).map_err(|_| DiscoveryRuntimeError::ListenAddress)?;
        let same_address = address.iter().any(|protocol| match protocol {
            Protocol::Ip4(value) => {
                ip.is_ipv4() && (value.is_unspecified() || IpAddr::V4(value) == ip)
            }
            Protocol::Ip6(value) => {
                ip.is_ipv6() && (value.is_unspecified() || IpAddr::V6(value) == ip)
            }
            _ => false,
        });
        if same_address
            && address
                .iter()
                .any(|protocol| matches!(protocol, Protocol::QuicV1))
        {
            return Ok(None);
        }
    }
    let family = if ip.is_ipv4() { "ip4" } else { "ip6" };
    Multiaddr::from_str(&format!("/{family}/{ip}/udp/0/quic-v1"))
        .map(Some)
        .map_err(|_| DiscoveryRuntimeError::ListenAddress)
}

fn configure_network(
    service: &mut DiscoveryService,
    config: &Config,
) -> Result<(), DiscoveryRuntimeError> {
    let listen_addresses: Vec<String> = if config.network.listen_addresses.is_empty() {
        vec![
            "/ip4/0.0.0.0/tcp/0".to_owned(),
            "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
        ]
    } else {
        config.network.listen_addresses.clone()
    };
    for text in listen_addresses {
        let address =
            Multiaddr::from_str(&text).map_err(|_| DiscoveryRuntimeError::ListenAddress)?;
        service
            .listen_on(address)
            .map_err(|_| DiscoveryRuntimeError::Build)?;
    }
    let mut known = 0_usize;
    for text in &config.network.bootstrap_peers {
        let link = parse_bootstrap(text)?;
        service
            .add_known_peer(*link.peer_id(), link.address())
            .map_err(|_| DiscoveryRuntimeError::Bootstrap)?;
        service
            .dial_peerlink(&link)
            .map_err(|_| DiscoveryRuntimeError::Bootstrap)?;
        known = known.saturating_add(1);
    }
    if known > 0 {
        service
            .bootstrap()
            .map_err(|_| DiscoveryRuntimeError::Bootstrap)?;
    }
    Ok(())
}

fn build_relay_service(
    node_id: [u8; 32],
    config: &Config,
    metrics: &MetricsRegistry,
) -> Result<RelayService, ()> {
    let bandwidth = Bandwidth::new(
        config.capacity.relay_upload_limit_mbps,
        config.capacity.relay_download_limit_mbps,
    )
    .map_err(|_| ())?;
    RelayService::new(
        RelayServiceConfig::enabled(
            node_id,
            bandwidth,
            config.capacity.maximum_relay_sessions,
            MAXIMUM_RESERVATION_TTL_SECONDS,
            TUNNEL_SETUP_TIMEOUT_SECONDS,
            SERVICE_REPLAY_CAPACITY,
        ),
        Some(metrics.clone()),
    )
    .map_err(|_| ())
}

fn build_exit_service(
    node_id: [u8; 32],
    config: &Config,
    policy: VerifiedManifest,
    metrics: &MetricsRegistry,
) -> Result<ExitService, ()> {
    let bandwidth = Bandwidth::new(
        config.capacity.exit_upload_limit_mbps,
        config.capacity.exit_download_limit_mbps,
    )
    .map_err(|_| ())?;
    ExitService::new(
        ExitServiceConfig::enabled(
            node_id,
            bandwidth,
            config.capacity.maximum_exit_sessions,
            MAXIMUM_RESERVATION_TTL_SECONDS,
            TUNNEL_SETUP_TIMEOUT_SECONDS,
            SERVICE_REPLAY_CAPACITY,
        ),
        policy,
        Some(metrics.clone()),
    )
    .map_err(|_| ())
}

fn clear_relay_metric(metrics: &MetricsRegistry) {
    if metrics.set_relay_reservations(0).is_err() {
        tracing::warn!(
            diagnostic_code = "METRIC_BOUND_REJECTED",
            "relay reservation metric reset failed"
        );
    }
}

fn clear_exit_metric(metrics: &MetricsRegistry) {
    if metrics.set_exit_reservations(0).is_err() {
        tracing::warn!(
            diagnostic_code = "METRIC_BOUND_REJECTED",
            "exit reservation metric reset failed"
        );
    }
}

fn parse_bootstrap(value: &str) -> Result<PeerLink, DiscoveryRuntimeError> {
    if value.starts_with("volparossa://") {
        return value
            .parse()
            .map_err(|_| DiscoveryRuntimeError::BootstrapAddress);
    }
    let address: Multiaddr = value
        .parse()
        .map_err(|_| DiscoveryRuntimeError::BootstrapAddress)?;
    let mut embedded = address.iter().filter_map(|protocol| match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    });
    let peer = embedded
        .next()
        .ok_or(DiscoveryRuntimeError::BootstrapAddress)?;
    if embedded.next().is_some() {
        return Err(DiscoveryRuntimeError::BootstrapAddress);
    }
    PeerLink::new(peer, address).map_err(|_| DiscoveryRuntimeError::BootstrapAddress)
}

fn multiaddr_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(address) => Some(IpAddr::V4(address)),
        Protocol::Ip6(address) => Some(IpAddr::V6(address)),
        _ => None,
    })
}

fn identity_bound_exit_control_address(
    control_addresses: &BTreeSet<String>,
    scope: &NativeProbePathScope,
    exit_peer: Libp2pPeerId,
    adjacent_local_address: Option<&[u8]>,
) -> Option<String> {
    let family = ObservationAddressFamily::try_from(scope.address_family).ok()?;
    control_addresses.iter().find_map(|text| {
        let address = Multiaddr::from_str(text).ok()?;
        let ip = multiaddr_ip(&address)?;
        let address_matches_family = matches!(
            (family, ip),
            (ObservationAddressFamily::Ipv4, IpAddr::V4(_))
                | (ObservationAddressFamily::Ipv6, IpAddr::V6(_))
        );
        if !address_matches_family {
            return None;
        }
        let eligible = adjacent_local_address.map_or_else(
            || is_public_routable_ip(ip),
            |local| {
                is_local_lan_ip(ip)
                    && match ip {
                        IpAddr::V4(ip) => local == ip.octets(),
                        IpAddr::V6(ip) => local == ip.octets(),
                    }
            },
        );
        if !eligible {
            return None;
        }
        let peerlink = PeerLink::new(exit_peer, address).ok()?;
        let identity_bound = peerlink.dial_address().to_string();
        (identity_bound.len() <= MAX_NATIVE_PROBE_CONTROL_ADDRESS_BYTES).then_some(identity_bound)
    })
}

/// Stable reason why persisted advertisement evidence cannot mint a peer capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoredAdvertisementError {
    InvalidPeerId,
    PeerBinding,
    Signature,
    BodyMismatch,
}

/// Minimal capability fields reconstructed from fresh cryptographic verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevalidatedAdvertisement {
    pub(crate) wire_node_id: [u8; 32],
    pub(crate) peer_id: Libp2pPeerId,
    public_key: [u8; 32],
    sequence_number: u64,
    signed_measured_at_ms: u64,
    signed_expires_at_ms: u64,
    policy_version: u64,
    policy_hash: [u8; 32],
    fingerprint: AdvertisementFingerprint,
    pub(crate) relay: bool,
    pub(crate) exit: bool,
}

/// Revalidates persisted provenance without mutating the network-ingest replay cache.
///
/// A fresh one-entry cache deliberately performs all signature, canonical, time and nonce
/// validation on every local use while allowing the same accepted advertisement to establish
/// more than one route during its lifetime. Network ingest keeps using the actor-owned cache.
pub(crate) fn revalidate_stored_advertisement(
    stored: &volparossa_peerstore::StoredPeer,
    now_ms: u64,
) -> Result<RevalidatedAdvertisement, StoredAdvertisementError> {
    let peer_id = Libp2pPeerId::from_str(stored.advertisement.peer_id.as_str())
        .map_err(|_| StoredAdvertisementError::InvalidPeerId)?;
    let envelope = stored.signed_advertisement_envelope();
    if !advertisement_envelope_matches_peer(envelope, &peer_id) {
        return Err(StoredAdvertisementError::PeerBinding);
    }
    let mut replay = ReplayCache::new(1).map_err(|_| StoredAdvertisementError::Signature)?;
    let verified = verify_control_message::<WireAdvertisement>(
        envelope,
        now_ms,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| StoredAdvertisementError::Signature)?;
    let reconstructed =
        convert_advertisement(verified.message(), UnixTime::from_secs(now_ms / 1_000))
            .map_err(|()| StoredAdvertisementError::BodyMismatch)?;
    if reconstructed != stored.advertisement {
        return Err(StoredAdvertisementError::BodyMismatch);
    }
    let roles = verified
        .message()
        .roles
        .as_ref()
        .ok_or(StoredAdvertisementError::BodyMismatch)?;
    let policy = verified
        .message()
        .policy
        .as_ref()
        .ok_or(StoredAdvertisementError::BodyMismatch)?;
    let wire_node_id = verified
        .message()
        .node_id
        .as_slice()
        .try_into()
        .map_err(|_| StoredAdvertisementError::BodyMismatch)?;
    let public_key = *verified.sender_public_key();
    let policy_hash =
        fixed_bytes::<32>(&policy.whitelist_hash).ok_or(StoredAdvertisementError::BodyMismatch)?;
    let fingerprint =
        advertisement_fingerprint(envelope).ok_or(StoredAdvertisementError::BodyMismatch)?;
    if wire_node_id != *verified.sender_id()
        || wire_node_id != node_id_from_public_key(&public_key)
        || verified.message().peer_id != peer_id.to_bytes()
        || verified.message().measured_at_ms != verified.timestamp_ms()
        || verified.message().expires_at_ms != verified.expires_at_ms()
        || reconstructed.measured_at.as_secs() != verified.message().measured_at_ms / 1_000
        || reconstructed.expires_at.as_secs() != verified.message().expires_at_ms / 1_000
    {
        return Err(StoredAdvertisementError::BodyMismatch);
    }
    Ok(RevalidatedAdvertisement {
        wire_node_id,
        peer_id,
        public_key,
        sequence_number: verified.message().sequence_number,
        signed_measured_at_ms: verified.message().measured_at_ms,
        signed_expires_at_ms: verified.message().expires_at_ms,
        policy_version: policy.whitelist_version,
        policy_hash,
        fingerprint,
        relay: roles.relay,
        exit: roles.exit,
    })
}

fn convert_advertisement(wire: &WireAdvertisement, now: UnixTime) -> Result<CoreAdvertisement, ()> {
    let roles = wire.roles.as_ref().ok_or(())?;
    let capabilities = wire.capabilities.as_ref().ok_or(())?;
    let capacity = wire.capacity.as_ref().ok_or(())?;
    let network = wire.network.as_ref().ok_or(())?;
    let quality = wire.quality.as_ref().ok_or(())?;
    let policy = wire.policy.as_ref().ok_or(())?;
    let node_id = NodeId::new(hex::encode(&wire.node_id)).map_err(|_| ())?;
    let peer = Libp2pPeerId::from_bytes(&wire.peer_id).map_err(|_| ())?;
    let advertisement = CoreAdvertisement {
        protocol_version: volparossa_core::PROTOCOL_VERSION,
        node_id,
        peer_id: CorePeerId::new(peer.to_string()).map_err(|_| ())?,
        sequence_number: wire.sequence_number,
        roles: NodeRoles {
            client: roles.client,
            relay: roles.relay,
            exit: roles.exit,
        },
        capabilities: NodeCapabilities {
            tcp_mptcp: capabilities.tcp_mptcp,
            udp_single_path: capabilities.udp_single_path,
            multipath_quic: capabilities.multipath_quic,
            ipv4: capabilities.ipv4,
            ipv6: capabilities.ipv6,
            udp_hole_punching: capabilities.udp_hole_punching,
        },
        capacity: CapacitySnapshot {
            relay_limit: Bandwidth::new(
                u32::try_from(capacity.operator_relay_limit_up_mbps).map_err(|_| ())?,
                u32::try_from(capacity.operator_relay_limit_down_mbps).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
            exit_limit: Bandwidth::new(
                u32::try_from(capacity.operator_exit_limit_up_mbps).map_err(|_| ())?,
                u32::try_from(capacity.operator_exit_limit_down_mbps).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
            currently_reserved: Bandwidth::new(
                u32::try_from(capacity.currently_reserved_up_mbps).map_err(|_| ())?,
                u32::try_from(capacity.currently_reserved_down_mbps).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
            estimated_free: Bandwidth::new(
                u32::try_from(capacity.estimated_free_up_mbps).map_err(|_| ())?,
                u32::try_from(capacity.estimated_free_down_mbps).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
            active_relay_sessions: capacity.active_relay_sessions,
            active_exit_sessions: capacity.active_exit_sessions,
            free_relay_slots: capacity.free_relay_slots,
            free_exit_slots: capacity.free_exit_slots,
            sample_window_seconds: u16::try_from(capacity.sample_window_seconds).map_err(|_| ())?,
        },
        network: NetworkMetadata {
            uplink: match volparossa_protocol::AdvertisementUplink::try_from(network.uplink)
                .map_err(|_| ())?
            {
                volparossa_protocol::AdvertisementUplink::IndependentInternet => {
                    volparossa_core::NetworkUplink::IndependentInternet
                }
                volparossa_protocol::AdvertisementUplink::LocalOnly => {
                    volparossa_core::NetworkUplink::LocalOnly
                }
            },
            operator_id: OperatorId::new(network.operator_id.clone()).map_err(|_| ())?,
            region: network.region.clone(),
            country_code: network.country_code.clone(),
            asn: (network.asn != 0).then_some(network.asn),
            ipv4_prefix_hint: (!network.ipv4_prefix_hint.is_empty())
                .then(|| network.ipv4_prefix_hint.clone()),
            ipv6_prefix_hint: (!network.ipv6_prefix_hint.is_empty())
                .then(|| network.ipv6_prefix_hint.clone()),
        },
        quality: NodeQuality {
            local_uptime_seconds: quality.local_uptime_seconds,
            historical_uptime_score: f64::from(quality.historical_uptime_ppm) / 1_000_000.0,
            historical_delivery_ratio_p25: f64::from(quality.historical_delivery_ratio_p25_ppm)
                / 1_000_000.0,
        },
        policy_hash: PolicyHash::from_bytes(
            policy
                .whitelist_hash
                .as_slice()
                .try_into()
                .map_err(|_| ())?,
        ),
        control_endpoints: wire.control_addresses.clone(),
        measured_at: UnixTime::from_secs(wire.measured_at_ms / 1_000),
        expires_at: UnixTime::from_secs(wire.expires_at_ms / 1_000),
    };
    advertisement.validate_at(now).map_err(|_| ())?;
    Ok(advertisement)
}

/// Discovery setup failure with no untrusted address echoed in its display.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryRuntimeError {
    /// Swarm or behaviour construction failed.
    #[error("discovery service construction failed")]
    Build,
    /// Configured listen multiaddress was invalid.
    #[error("configured discovery listen address is invalid")]
    ListenAddress,
    /// Bootstrap peerlink or multiaddress was malformed.
    #[error("configured bootstrap address is invalid")]
    BootstrapAddress,
    /// Bootstrap dial/routing setup failed.
    #[error("discovery bootstrap setup failed")]
    Bootstrap,
    /// Persisted roles do not meet their configured non-zero capacity prerequisites.
    #[error("configured service role prerequisites are invalid")]
    RolePrerequisites,
    /// Exit startup was requested without a currently active threshold policy.
    #[error("configured exit role has no active policy")]
    PolicyUnavailable,
    /// A capacity-bounded relay or exit admission service could not be built.
    #[error("configured reservation service is invalid")]
    ReservationService,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use libp2p::{
        Multiaddr,
        core::{ConnectedPoint, Endpoint, transport::PortUse},
        swarm::SwarmEvent,
    };
    use tempfile::TempDir;
    use tokio::sync::{RwLock, oneshot};
    use volparossa_protocol::{
        AdvertisementNetwork, ControlPayload, ProbeAddressFamily, Transport, generate_nonce,
        sign_control_message, sign_control_message_with,
    };
    use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};

    use super::*;

    static NEXT_MEMORY_ADDRESS: AtomicU64 = AtomicU64::new(90_000);

    const fn test_client_roles() -> RolesConfig {
        RolesConfig {
            client: true,
            relay: false,
            exit: false,
        }
    }

    struct RuntimeFixture {
        runtime: DiscoveryRuntime,
        control: DiscoveryControlHandle,
        state: Arc<RwLock<AgentState>>,
        policy: VerifiedManifest,
        role_store: RoleStore,
        directory: TempDir,
    }

    fn fixture(roles: RolesConfig) -> RuntimeFixture {
        let now_ms = unix_millis();
        let policy = verified_development_manifest(now_ms, Vec::new()).expect("test policy");
        let directory = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private test state");
        let memory_id = NEXT_MEMORY_ADDRESS.fetch_add(1, Ordering::Relaxed);
        let address: Multiaddr = format!("/memory/{memory_id}")
            .parse()
            .expect("memory address");
        let mut config = Config {
            roles,
            runtime_mode: volparossa_config::RuntimeMode::Development,
            ..Config::default()
        };
        config.network.operator_id = Some("operator-test".to_owned());
        config.network.advertised_region = "test".to_owned();
        config.network.advertised_country_code = "NL".to_owned();
        config.network.advertised_asn = 64_512;
        config.network.advertised_ipv4_prefix = Some("44.160.1.0/24".to_owned());
        config.network.listen_addresses = vec![address.to_string()];
        config.network.advertisement_ttl_seconds = 30;
        config.capacity.relay_upload_limit_mbps = 100;
        config.capacity.relay_download_limit_mbps = 100;
        config.capacity.maximum_relay_sessions = 4;
        config.capacity.exit_upload_limit_mbps = 100;
        config.capacity.exit_download_limit_mbps = 100;
        config.capacity.maximum_exit_sessions = 4;
        config.policy.manifest_path = "/etc/volparossa/policy.cbor".to_owned();
        config.validate().expect("test config");

        let role_store = RoleStore::new(directory.path().join("roles.json"));
        role_store.load_or_initialize(roles).expect("initial roles");
        let peerstore =
            PeerStore::open(directory.path().join("peers.sqlite")).expect("test peerstore");
        let metrics = MetricsRegistry::new();
        let state = Arc::new(RwLock::new(
            AgentState::new(&config, roles, Some(policy.clone()), metrics.clone())
                .expect("agent state"),
        ));
        let identity = Identity::generate();
        let (runtime, control) = DiscoveryRuntime::new(
            identity,
            &config,
            peerstore,
            directory.path().join("advertisement.sequence"),
            DiscoveryRuntimeResources {
                roles,
                policy: Some(policy.clone()),
                role_store: role_store.clone(),
                metrics,
                helper: HelperClient::new(
                    directory.path().join("helper.sock"),
                    directory.path().join("helper.token"),
                ),
                mpquic_socket: directory.path().join("mpquic.sock"),
            },
        )
        .expect("discovery runtime");
        RuntimeFixture {
            runtime,
            control,
            state,
            policy,
            role_store,
            directory,
        }
    }

    #[tokio::test]
    async fn direct_local_endpoint_observations_keep_transport_and_actor_bindings() {
        let mut fixture = fixture(test_client_roles());
        let observer = *Identity::generate().peer_id();
        fixture.runtime.observed_endpoints.insert(
            observer,
            (
                "/ip4/192.168.8.2/udp/443/quic-v1".to_owned(),
                Some("192.168.8.2".parse().unwrap()),
            ),
        );
        fixture.runtime.record_local_endpoint_observation(
            observer,
            &"/ip4/192.168.8.1/udp/443/quic-v1".parse().unwrap(),
        );
        let binding = EndpointTraversalBinding {
            path_id: 1,
            role: WireguardRole::RelayClient,
            observer_id: [7; 32],
            observer_peer_id: observer,
        };
        let hints = fixture
            .runtime
            .exact_endpoint_traversal_hints(vec![binding.clone()])
            .expect("direct local authenticated observer");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].observer_id, vec![7; 32]);
        assert_eq!(hints[0].observer_peer_id, observer.to_bytes());
        assert!(hints[0].observed_address.is_empty());
        let local = hints[0].on_link.as_ref().unwrap();
        assert_eq!(local.local_address, vec![192, 168, 8, 1]);
        assert_eq!(local.peer_address, vec![192, 168, 8, 2]);
        fixture
            .runtime
            .observed_endpoints
            .get_mut(&observer)
            .unwrap()
            .0
            .push_str("/p2p-circuit");
        assert!(
            fixture
                .runtime
                .exact_endpoint_traversal_hints(vec![binding])
                .unwrap()
                .is_empty()
        );
        let mut wire_endpoint = volparossa_protocol::WireguardEndpoint {
            public_key: vec![8; 32],
            underlay_ip: vec![192, 168, 8, 2],
            listen_port: 41_000,
            underlay_scope: volparossa_protocol::UnderlayScope::PublicInternet as i32,
        };
        assert!(native_probe_observed_relay_prefix(&wire_endpoint).is_none());
        wire_endpoint.underlay_scope = volparossa_protocol::UnderlayScope::DirectLocalLan as i32;
        let local = native_probe_observed_relay_prefix(&wire_endpoint).unwrap();
        assert_eq!(local.network_prefix, vec![192, 168, 8]);
        assert_eq!(
            local.scope,
            volparossa_protocol::UnderlayScope::DirectLocalLan as i32
        );
        wire_endpoint.underlay_ip = vec![8, 8, 8, 8];
        assert!(native_probe_observed_relay_prefix(&wire_endpoint).is_none());
        wire_endpoint.underlay_scope = volparossa_protocol::UnderlayScope::PublicInternet as i32;
        assert!(native_probe_observed_relay_prefix(&wire_endpoint).is_some());
    }

    #[tokio::test]
    async fn traversal_observations_bind_only_the_exact_active_peer_and_path() {
        let mut fixture = fixture(test_client_roles());
        let observer = Identity::generate().peer_id().to_owned();
        fixture
            .runtime
            .observed_endpoints
            .insert(observer, ("/ip4/1.1.1.1/udp/443/quic-v1".to_owned(), None));
        fixture.runtime.record_local_endpoint_observation(
            observer,
            &"/ip6/2606:4700:4700::1111/udp/443/quic-v1"
                .parse()
                .expect("IPv6 observation"),
        );
        fixture.runtime.record_local_endpoint_observation(
            observer,
            &"/ip4/8.8.8.8/udp/443/quic-v1"
                .parse()
                .expect("IPv4 observation"),
        );
        let hints = fixture
            .runtime
            .exact_endpoint_traversal_hints(vec![EndpointTraversalBinding {
                path_id: 2,
                role: WireguardRole::Client,
                observer_id: [7; 32],
                observer_peer_id: observer,
            }])
            .expect("exact active peer");
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].path_id, 2);
        assert_eq!(hints[0].observer_peer_id, observer.to_bytes());
        assert_eq!(hints[0].observed_address.len(), 16);
        assert_eq!(hints[1].observed_address, vec![8, 8, 8, 8]);

        let foreign = Identity::generate().peer_id().to_owned();
        assert_eq!(
            fixture
                .runtime
                .exact_endpoint_traversal_hints(vec![EndpointTraversalBinding {
                    path_id: 2,
                    role: WireguardRole::Client,
                    observer_id: [7; 32],
                    observer_peer_id: foreign,
                }]),
            Err(OutboundReservationError::InvalidRequest)
        );
    }

    fn local_advertisement_input(
        roles: RolesConfig,
        operator_id: &str,
        policy: &VerifiedManifest,
        control_addresses: BTreeSet<String>,
    ) -> LocalAdvertisementInput {
        LocalAdvertisementInput {
            roles,
            operator_id: operator_id.to_owned(),
            capabilities: AdvertisementCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: false,
                ipv6: false,
                udp_hole_punching: false,
            },
            capacity: AdvertisementCapacity {
                operator_relay_limit_up_mbps: u64::from(roles.relay) * 100,
                operator_relay_limit_down_mbps: u64::from(roles.relay) * 100,
                operator_exit_limit_up_mbps: u64::from(roles.exit) * 100,
                operator_exit_limit_down_mbps: u64::from(roles.exit) * 100,
                currently_reserved_up_mbps: 0,
                currently_reserved_down_mbps: 0,
                estimated_free_up_mbps: 100,
                estimated_free_down_mbps: 100,
                active_relay_sessions: 0,
                active_exit_sessions: 0,
                free_relay_slots: u32::from(roles.relay) * 4,
                free_exit_slots: u32::from(roles.exit) * 4,
                sample_window_seconds: 0,
            },
            origin: AdvertisementNetwork {
                uplink: volparossa_protocol::AdvertisementUplink::IndependentInternet as i32,
                region: "test".to_owned(),
                country_code: "NL".to_owned(),
                asn: 64_512,
                ipv4_prefix_hint: "44.160.1.0/24".to_owned(),
                ipv6_prefix_hint: "2606:4700:100::/48".to_owned(),
                operator_id: String::new(),
            },
            policy_version: policy.manifest_version(),
            policy_hash: *policy.policy_hash(),
            policy_expires_at_ms: policy.expires_at_ms(),
            control_addresses,
        }
    }

    fn valid_client_preselection_parameters() -> ClientPreselectionParameters {
        ClientPreselectionParameters::new(
            Transport::UdpSinglePath,
            ObservationAddressFamily::Ipv4,
            Bandwidth::new(10, 10).expect("minimum capacity"),
            Bandwidth::new(100, 100).expect("local capacity"),
            Bandwidth::new(80, 80).expect("conservative ceiling"),
            1,
            1,
            10,
        )
    }

    async fn next_service_other(service: &mut DiscoveryService) -> SwarmEvent<BehaviourEvent> {
        loop {
            if let DiscoveryEvent::Other(event) = service.next_event().await {
                return event;
            }
        }
    }

    async fn connect_runtime_client_to_control(
        runtime: &mut DiscoveryRuntime,
        control: &mut DiscoveryService,
    ) {
        let memory_id = NEXT_MEMORY_ADDRESS.fetch_add(1, Ordering::Relaxed);
        let address = format!("/memory/{memory_id}")
            .parse::<Multiaddr>()
            .expect("control memory address");
        control.listen_on(address).expect("control memory listener");
        let address = timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_service_other(control).await
                {
                    break address;
                }
            }
        })
        .await
        .expect("control listener timeout");

        let control_peer = *control.local_peer_id();
        let client_peer = *runtime.service.local_peer_id();
        runtime
            .service
            .dial_peerlink(&PeerLink::new(control_peer, address).expect("control memory peerlink"))
            .expect("client-control memory dial");
        let (connection_id, old_endpoint) = timeout(Duration::from_secs(10), async {
            let mut client_lineage = None;
            let mut control_connected = false;
            while client_lineage.is_none() || !control_connected {
                tokio::select! {
                    event = next_service_other(&mut runtime.service) => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } = event
                        {
                            if peer_id == control_peer {
                                client_lineage = Some((connection_id, endpoint));
                            }
                        }
                    }
                    event = next_service_other(control) => {
                        control_connected |= matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == client_peer
                        );
                    }
                }
            }
            client_lineage.expect("client connection lineage")
        })
        .await
        .expect("client-control connection timeout");
        let public_endpoint = ConnectedPoint::Dialer {
            address: "/ip4/44.160.1.8/tcp/443"
                .parse()
                .expect("public test endpoint"),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        runtime.service.install_test_connection_address_change(
            control_peer,
            connection_id,
            &old_endpoint,
            &public_endpoint,
        );
    }

    fn direct_capability(
        identity: &Identity,
        policy: &VerifiedManifest,
        advertisement_sequence: u64,
        advertisement_expires_at_ms: u64,
    ) -> DirectRelayCapability {
        let public_key = identity
            .ed25519_public_key_bytes()
            .expect("Ed25519 public key");
        DirectRelayCapability {
            node_id: node_id_from_public_key(&public_key),
            peer_id: identity.peer_id().to_owned(),
            public_key,
            advertisement_sequence,
            advertisement_expires_at_ms,
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(
                node_id_from_public_key(&public_key),
            ),
            policy_version: policy.manifest_version(),
            policy_hash: *policy.policy_hash(),
            policy_expires_at_ms: policy.expires_at_ms(),
            expires_at_ms: advertisement_expires_at_ms.min(policy.expires_at_ms()),
        }
    }

    fn braced_item<'a>(source: &'a str, marker: &str) -> &'a str {
        let start = source.find(marker).expect("source marker");
        let opening = start + source[start..].find('{').expect("opening brace");
        let mut depth = 0_usize;
        for (offset, character) in source[opening..].char_indices() {
            match character {
                '{' => depth = depth.checked_add(1).expect("brace depth"),
                '}' => {
                    depth = depth.checked_sub(1).expect("balanced braces");
                    if depth == 0 {
                        return &source[start..opening + offset + character.len_utf8()];
                    }
                }
                _ => {}
            }
        }
        panic!("closing brace");
    }

    #[test]
    fn ambiguous_helper_cleanup_is_quarantined_between_bounded_retries() {
        let expired_at_ms = 1_000_u64;
        let failed_at_ms = 2_000_u64;
        let retry_at_ms = failed_at_ms.saturating_add(HELPER_CLEANUP_RETRY_BACKOFF_MS);

        assert!(helper_cleanup_due(expired_at_ms, 0, failed_at_ms));
        assert!(!helper_cleanup_due(
            expired_at_ms,
            retry_at_ms,
            failed_at_ms.saturating_add(1),
        ));
        assert!(!helper_cleanup_due(
            expired_at_ms,
            retry_at_ms,
            retry_at_ms.saturating_sub(1),
        ));
        assert!(helper_cleanup_due(expired_at_ms, retry_at_ms, retry_at_ms,));
        assert!(helper_cleanup_due(expired_at_ms, u64::MAX, u64::MAX,));

        let source = include_str!("discovery.rs");
        let runtime_impl = braced_item(source, "impl DiscoveryRuntime {");
        let relay_cleanup = braced_item(
            runtime_impl,
            "async fn destroy_expired_production_relay_routes(",
        );
        let quarantine = relay_cleanup
            .find("route.usable = false;")
            .expect("expired Relay is quarantined");
        let destroy = relay_cleanup
            .find(".destroy_context(&route.helper_owner)")
            .expect("helper Destroy attempt");
        let retry = relay_cleanup
            .find("HELPER_CLEANUP_RETRY_BACKOFF_MS")
            .expect("bounded retry deadline");
        let reinsert = relay_cleanup
            .find(".insert(route_context_id, route)")
            .expect("affine owner retained");
        assert!(quarantine < destroy);
        assert!(destroy < retry);
        assert!(retry < reinsert);

        for cleanup in [
            "async fn destroy_expired_exit_native_attempts(",
            "async fn destroy_expired_production_relay_routes(",
            "async fn destroy_expired_production_exit_routes(",
            "async fn destroy_expired_active_mptcp_exit_routes(",
        ] {
            assert!(braced_item(runtime_impl, cleanup).contains("helper_cleanup_due("));
        }
    }

    #[test]
    fn signer_ownership_surface_stays_actor_bound() {
        let advertisement_source = include_str!("advertisement.rs");
        let publisher_marker = "pub(crate) struct AdvertisementPublisher {";
        let publisher_offset = advertisement_source
            .find(publisher_marker)
            .expect("publisher declaration");
        let declaration_prefix = advertisement_source[..publisher_offset]
            .rsplit_once("\n\n")
            .map_or(&advertisement_source[..publisher_offset], |(_, suffix)| {
                suffix
            });
        assert!(declaration_prefix.trim().is_empty());

        let publisher = braced_item(advertisement_source, publisher_marker);
        assert!(!publisher.contains("Identity"));
        assert!(!publisher.contains("Arc"));
        assert!(!publisher.contains("Box"));
        assert!(!publisher.contains("Fn"));
        assert!(!publisher.contains("fn("));

        let publisher_impl = braced_item(advertisement_source, "impl AdvertisementPublisher {");
        assert_eq!(publisher_impl.matches("pub(crate) fn sign(").count(), 1);
        let sign = braced_item(publisher_impl, "pub(crate) fn sign(");
        let signature = &sign[..sign.find('{').expect("sign body")];
        assert_eq!(signature.matches("signer: &Identity").count(), 1);
        assert!(!signature.contains("Arc"));
        assert!(!signature.contains("Box"));
        assert!(!signature.contains("Fn"));
        assert!(!publisher_impl.contains("pub fn sign("));
        assert!(!publisher_impl.contains("fn identity("));
        assert!(!publisher_impl.contains("fn signer("));
        assert!(!publisher_impl.contains("-> &Identity"));
        assert!(!publisher_impl.contains("-> Identity"));

        let role_validation = sign
            .find("if !(input.roles.relay || input.roles.exit)")
            .expect("role validation");
        let input_validation = sign
            .find("if input.control_addresses.is_empty()")
            .expect("input validation");
        let sequence = sign
            .find("self.sequence_store.next()")
            .expect("sequence mutation");
        assert!(role_validation < input_validation);
        assert!(input_validation < sequence);

        let discovery_source = include_str!("discovery.rs");
        let runtime = braced_item(discovery_source, "pub struct DiscoveryRuntime {");
        assert_eq!(runtime.matches("Identity").count(), 1);
        assert_eq!(runtime.matches("identity: Identity,").count(), 1);
        assert!(!runtime.contains("pub identity: Identity"));
        assert!(!runtime.contains("pub(crate) identity: Identity"));
        assert!(!runtime.contains("Arc<Identity"));

        let runtime_impl = braced_item(discovery_source, "impl DiscoveryRuntime {");
        let constructor = braced_item(runtime_impl, "pub fn new(");
        assert_eq!(constructor.matches("identity.keypair().clone()").count(), 1);
        assert_eq!(constructor.matches("\n            identity,\n").count(), 1);
        assert!(!runtime_impl.contains("fn identity("));
        assert!(!runtime_impl.contains("fn signer("));
        assert_eq!(runtime_impl.matches(".publisher.sign(").count(), 1);

        let publish = braced_item(
            runtime_impl,
            "async fn publish_local(&mut self, state: &Arc<RwLock<AgentState>>) {",
        );
        let service_role_guard = publish
            .find("if !(self.roles.relay || self.roles.exit)")
            .expect("service-role guard");
        let operator_read = publish
            .find("let Some(operator_id)")
            .expect("operator read");
        let state_read = publish.find("let (roles, policy)").expect("state read");
        let signer_borrow = publish
            .find("self.publisher.sign(&self.identity, &input, now_ms)")
            .expect("actor-owned signer borrow");
        assert!(service_role_guard < operator_read);
        assert!(operator_read < state_read);
        assert!(state_read < signer_borrow);
    }

    #[tokio::test]
    async fn actor_identity_cryptographically_matches_swarm_and_local_advertisement() {
        let fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let public_key = fixture
            .runtime
            .identity
            .ed25519_public_key_bytes()
            .expect("Ed25519 public key");
        let node_id = node_id_from_public_key(&public_key);
        let peer_id = fixture.runtime.identity.peer_id().to_owned();
        assert_eq!(&peer_id, fixture.runtime.service.local_peer_id());
        assert_eq!(fixture.runtime.local_public_key, public_key);
        assert_eq!(fixture.runtime.local_node_id, node_id);

        let signed = fixture
            .runtime
            .publisher
            .sign(
                &fixture.runtime.identity,
                &local_advertisement_input(
                    RolesConfig {
                        client: true,
                        relay: true,
                        exit: false,
                    },
                    "operator-identity-coherence",
                    &fixture.policy,
                    BTreeSet::from(["/ip4/127.0.0.1/tcp/42100".to_owned()]),
                ),
                now_ms,
            )
            .expect("actor-signed advertisement");
        let mut replay = ReplayCache::new(1).expect("replay cache");
        let verified = verify_control_message::<WireAdvertisement>(
            &signed.envelope,
            now_ms.saturating_add(1),
            TimePolicy::default(),
            &mut replay,
        )
        .expect("cryptographically verified advertisement");
        assert_eq!(verified.sender_public_key(), &public_key);
        assert_eq!(verified.sender_id(), &node_id);
        assert_eq!(verified.message().node_id, node_id.to_vec());
        assert_eq!(verified.message().peer_id, peer_id.to_bytes());
    }

    #[test]
    fn preselection_responder_authority_is_role_gated_and_active_policy_scoped() {
        let now_ms = unix_millis();
        let active = AgentPolicySnapshot {
            manifest_version: 7,
            policy_hash: vec![0x5a; 32],
            expires_at_ms: now_ms.saturating_add(60_000),
            verified_signatures: 2,
            active: true,
        };
        let relay_roles = RolesConfig {
            client: false,
            relay: true,
            exit: false,
        };
        assert_eq!(
            preselection_responder_policy(relay_roles, &active, now_ms),
            LocalPreselectionPolicy::new(
                active.manifest_version,
                [0x5a; 32],
                active.expires_at_ms,
            )
            .ok(),
        );
        let exit_roles = RolesConfig {
            client: false,
            relay: false,
            exit: true,
        };
        assert_eq!(
            preselection_responder_policy(exit_roles, &active, now_ms),
            LocalPreselectionPolicy::new(
                active.manifest_version,
                [0x5a; 32],
                active.expires_at_ms,
            )
            .ok(),
        );

        let mut inactive = active.clone();
        inactive.active = false;
        let mut malformed = active.clone();
        malformed.policy_hash.pop();
        let mut zero_version = active.clone();
        zero_version.manifest_version = 0;
        let mut expired = active.clone();
        expired.expires_at_ms = now_ms;
        for (roles, policy) in [
            (test_client_roles(), active),
            (relay_roles, inactive),
            (relay_roles, malformed),
            (relay_roles, zero_version),
            (relay_roles, expired),
        ] {
            assert_eq!(preselection_responder_policy(roles, &policy, now_ms), None,);
        }
    }

    #[test]
    fn discovery_actor_polls_only_the_private_role_gated_preselection_responder_seam() {
        let source = include_str!("discovery.rs");
        let run = braced_item(source, "pub async fn run(");
        assert_eq!(
            run.matches("preselection_responder_policy(self.roles, &policy, now_ms)")
                .count(),
            1,
        );
        assert_eq!(run.matches("next_actor_discovery_event(").count(), 1);
        assert!(!run.contains("dispatch_preselection_observation("));
        assert!(!run.contains("dispatch_preselection_observation_upstream("));

        let actor_pump = braced_item(source, "async fn next_actor_discovery_event(");
        assert_eq!(
            actor_pump
                .matches("next_event_with_preselection_responders")
                .count(),
            1,
        );
        assert_eq!(actor_pump.matches("identity.sign(message).ok()").count(), 1);
        assert_eq!(
            actor_pump
                .matches("cancel_preselection_forwarding()")
                .count(),
            1
        );
        assert!(
            actor_pump
                .find("cancel_preselection_forwarding()")
                .expect("policy-off cancellation")
                < actor_pump
                    .find("service.next_event()")
                    .expect("generic pump")
        );
        assert!(!actor_pump.contains("request_exit_forward"));
        assert!(!actor_pump.contains("dispatch_preselection_observation"));
        assert!(!actor_pump.contains("Fresh"));

        let handle_command = braced_item(source, "async fn handle_command(");
        assert_eq!(
            handle_command
                .matches("self.service.cancel_preselection_forwarding()")
                .count(),
            1,
        );
        assert!(
            handle_command
                .find("self.service.cancel_preselection_forwarding()")
                .expect("pre-policy cancellation")
                < handle_command
                    .find("state.write().await.set_policy(policy)")
                    .expect("policy publication")
        );
    }

    #[test]
    fn advertisement_payload_hash_is_nonzero_and_redacted() {
        assert!(AdvertisementPayloadHash::from_fresh_fingerprint([0; 32]).is_none());
        let token = AdvertisementPayloadHash::from_fresh_fingerprint([0x5a; 32])
            .expect("non-zero payload hash");
        let debug = format!("{token:?}");
        assert_eq!(debug, "AdvertisementPayloadHash([REDACTED])");
        assert!(!debug.contains("5a"));
    }

    fn install_control(
        fixture: &mut RuntimeFixture,
        identity: &Identity,
        now_ms: u64,
    ) -> DirectRelayCapability {
        let capability =
            direct_capability(identity, &fixture.policy, 1, now_ms.saturating_add(60_000));
        fixture
            .runtime
            .direct_relays
            .insert(capability.peer_id, capability.clone());
        capability
    }

    fn fetch_request(
        control: &DirectRelayCapability,
        exit_peer: Libp2pPeerId,
        forward_id: [u8; FORWARD_ID_BYTES],
        deadline_unix_ms: u64,
    ) -> ExitForwardRequest {
        ExitForwardRequest::new(
            forward_id.to_vec(),
            control.node_id.to_vec(),
            control.peer_id.to_bytes(),
            control.public_key.to_vec(),
            exit_peer.to_bytes(),
            Vec::new(),
            deadline_unix_ms,
            ExitForwardOperation::FetchExitAdvertisement,
            Vec::new(),
        )
        .expect("valid FetchExitAdvertisement")
    }

    fn authorize_fetch(
        fixture: &mut RuntimeFixture,
        control_identity: &Identity,
        exit_peer: Libp2pPeerId,
        forward_id: [u8; FORWARD_ID_BYTES],
        deadline_unix_ms: u64,
    ) -> (DirectRelayCapability, ExitForwardRequest) {
        let control = install_control(fixture, control_identity, unix_millis());
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, deadline_unix_ms);
        let request = fetch_request(&control, exit_peer, forward_id, deadline_unix_ms);
        (control, request)
    }

    #[derive(Clone, Copy)]
    struct PreselectionTestTransports {
        pub(super) tcp_mptcp: bool,
        pub(super) udp_single_path: bool,
        pub(super) multipath_quic: bool,
    }

    #[derive(Clone, Copy)]
    struct PreselectionTestFamilies {
        pub(super) ipv4: bool,
        pub(super) ipv6: bool,
    }

    #[derive(Clone, Copy)]
    pub(super) struct PreselectionTestCapabilities {
        transports: PreselectionTestTransports,
        families: PreselectionTestFamilies,
    }

    impl PreselectionTestCapabilities {
        pub(super) const fn all() -> Self {
            Self {
                transports: PreselectionTestTransports {
                    tcp_mptcp: true,
                    udp_single_path: true,
                    multipath_quic: true,
                },
                families: PreselectionTestFamilies {
                    ipv4: true,
                    ipv6: true,
                },
            }
        }
    }

    impl Default for PreselectionTestCapabilities {
        fn default() -> Self {
            Self {
                transports: PreselectionTestTransports {
                    tcp_mptcp: false,
                    udp_single_path: true,
                    multipath_quic: false,
                },
                families: PreselectionTestFamilies {
                    ipv4: true,
                    ipv6: false,
                },
            }
        }
    }

    fn service_advertisement(
        identity: &Identity,
        roles: RolesConfig,
        policy: &VerifiedManifest,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
        directory: &TempDir,
    ) -> AdvertisementResponse {
        service_advertisement_with_capabilities(
            identity,
            roles,
            policy,
            sequence_number,
            nonce,
            now_ms,
            directory,
            PreselectionTestCapabilities::default(),
        )
    }

    fn populate_test_network(
        network: &mut AdvertisementNetwork,
        advertised: PreselectionTestCapabilities,
        nonce: [u8; 32],
        sequence_number: u64,
    ) {
        network.country_code = "NL".to_owned();
        network.operator_id = format!("operator-{}-{sequence_number}", nonce[0]);
        network.asn = 64_512_u32
            .saturating_add(u32::from(nonce[0]).saturating_mul(16))
            .saturating_add(u32::try_from(sequence_number % 16).expect("bounded sequence suffix"));
        network.ipv4_prefix_hint = advertised
            .families
            .ipv4
            .then(|| format!("44.{}.{}.0/24", nonce[0], sequence_number % 255))
            .unwrap_or_default();
        network.ipv6_prefix_hint = advertised
            .families
            .ipv6
            .then(|| {
                let prefix_segment = (u16::from(nonce[0]) << 8)
                    | u16::try_from(sequence_number % 255).expect("bounded sequence suffix");
                format!("2606:4700:{prefix_segment:x}::/48")
            })
            .unwrap_or_default();
    }

    fn generated_nonce_with_unique_network_discriminator() -> [u8; 32] {
        static USED_DISCRIMINATORS: OnceLock<Mutex<BTreeSet<u8>>> = OnceLock::new();
        let used = USED_DISCRIMINATORS.get_or_init(|| Mutex::new(BTreeSet::new()));
        loop {
            let nonce = generate_nonce();
            if used
                .lock()
                .expect("network discriminator set")
                .insert(nonce[0])
            {
                return nonce;
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test fixture preserves the signed advertisement inputs explicitly"
    )]
    fn service_advertisement_with_capabilities(
        identity: &Identity,
        roles: RolesConfig,
        policy: &VerifiedManifest,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
        directory: &TempDir,
        advertised: PreselectionTestCapabilities,
    ) -> AdvertisementResponse {
        let mut control_addresses = BTreeSet::new();
        if advertised.families.ipv4 {
            control_addresses.insert("/ip4/127.0.0.1/tcp/42100".to_owned());
        }
        if advertised.families.ipv6 {
            control_addresses.insert("/ip6/2606:4700:4700::1111/tcp/42100".to_owned());
        }
        assert!(!control_addresses.is_empty());
        let publisher = AdvertisementPublisher::new(
            directory.path().join(format!(
                "advertisement-{sequence_number}-{}.sequence",
                nonce[0]
            )),
            30,
        );
        let seed_roles = if roles.relay || roles.exit {
            roles
        } else {
            RolesConfig {
                client: true,
                relay: true,
                exit: false,
            }
        };
        let seed = publisher
            .sign(
                identity,
                &local_advertisement_input(seed_roles, "operator-proof", policy, control_addresses),
                now_ms,
            )
            .expect("seed advertisement");
        let mut scratch_replay = ReplayCache::new(1).expect("scratch replay");
        let mut wire = verify_control_message::<WireAdvertisement>(
            &seed.envelope,
            now_ms,
            TimePolicy::default(),
            &mut scratch_replay,
        )
        .expect("verify seed")
        .into_message();
        wire.sequence_number = sequence_number;
        let wire_roles = wire.roles.as_mut().expect("roles");
        wire_roles.client = roles.client;
        wire_roles.relay = roles.relay;
        wire_roles.exit = roles.exit;
        let capabilities = wire.capabilities.as_mut().expect("capabilities");
        capabilities.tcp_mptcp = advertised.transports.tcp_mptcp && (roles.relay || roles.exit);
        capabilities.udp_single_path =
            advertised.transports.udp_single_path && (roles.relay || roles.exit);
        capabilities.multipath_quic =
            advertised.transports.multipath_quic && (roles.relay || roles.exit);
        capabilities.ipv4 = advertised.families.ipv4;
        capabilities.ipv6 = advertised.families.ipv6;
        let capacity = wire.capacity.as_mut().expect("capacity");
        let sample_window_seconds = capacity.sample_window_seconds;
        *capacity = AdvertisementCapacity {
            operator_relay_limit_up_mbps: 0,
            operator_relay_limit_down_mbps: 0,
            operator_exit_limit_up_mbps: 0,
            operator_exit_limit_down_mbps: 0,
            currently_reserved_up_mbps: 0,
            currently_reserved_down_mbps: 0,
            estimated_free_up_mbps: 0,
            estimated_free_down_mbps: 0,
            active_relay_sessions: 0,
            active_exit_sessions: 0,
            free_relay_slots: 0,
            free_exit_slots: 0,
            sample_window_seconds,
        };
        if roles.relay {
            capacity.operator_relay_limit_up_mbps = 100;
            capacity.operator_relay_limit_down_mbps = 100;
            capacity.free_relay_slots = 4;
        }
        if roles.exit {
            capacity.operator_exit_limit_up_mbps = 100;
            capacity.operator_exit_limit_down_mbps = 100;
            capacity.free_exit_slots = 4;
        }
        if roles.relay || roles.exit {
            capacity.estimated_free_up_mbps = 100;
            capacity.estimated_free_down_mbps = 100;
        }
        let network = wire.network.as_mut().expect("network");
        populate_test_network(network, advertised, nonce, sequence_number);
        let public_key = identity
            .ed25519_public_key_bytes()
            .expect("Ed25519 public key");
        let envelope = sign_control_message_with(
            &wire,
            public_key,
            wire.measured_at_ms,
            wire.expires_at_ms,
            nonce,
            TimePolicy::default(),
            |bytes| identity.sign(bytes).ok(),
        )
        .expect("signed service advertisement");
        AdvertisementResponse::new(envelope).expect("bounded advertisement")
    }

    struct NativePermitForwardFixture {
        fixture: RuntimeFixture,
        now_ms: u64,
        control: DirectRelayCapability,
        control_identity: Identity,
        control_advertisement: Vec<u8>,
        scope: NativeProbePathScope,
        request: ExitForwardRequest,
        local_advertisement: Vec<u8>,
    }

    fn actor_from_direct_capability(
        capability: &DirectRelayCapability,
    ) -> PreselectionActorBinding {
        PreselectionActorBinding {
            node_id: capability.node_id.to_vec(),
            peer_id: capability.peer_id.to_bytes(),
            public_key: capability.public_key.to_vec(),
            advertisement_sequence: capability.advertisement_sequence,
            advertisement_expires_at_ms: capability.advertisement_expires_at_ms,
            advertisement_payload_hash: capability.advertisement_payload_hash.0.to_vec(),
            capability_expires_at_ms: capability.expires_at_ms,
        }
    }

    fn actor_from_signed_advertisement(
        encoded: &[u8],
        identity: &Identity,
        capability_expires_at_ms: u64,
        now_ms: u64,
    ) -> PreselectionActorBinding {
        let envelope: SignedEnvelope =
            decode_canonical(encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
                .expect("signed advertisement envelope");
        let payload_hash = fixed_bytes::<32>(&envelope.payload_hash).expect("payload hash");
        let mut replay = ReplayCache::new(1).expect("advertisement replay");
        let verified = verify_control_message::<WireAdvertisement>(
            encoded,
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified signed advertisement");
        let public_key = identity
            .ed25519_public_key_bytes()
            .expect("Ed25519 public key");
        PreselectionActorBinding {
            node_id: verified.sender_id().to_vec(),
            peer_id: identity.peer_id().to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: verified.message().sequence_number,
            advertisement_expires_at_ms: verified.expires_at_ms(),
            advertisement_payload_hash: payload_hash.to_vec(),
            capability_expires_at_ms,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one fixture preserves every signed native-Permit provenance field explicitly"
    )]
    fn native_permit_forward_fixture() -> NativePermitForwardFixture {
        let roles = RolesConfig {
            client: true,
            relay: false,
            exit: true,
        };
        let mut fixture = fixture(roles);
        let now_ms = unix_millis();
        let request_expires_at_ms = now_ms.saturating_add(5_000);
        let actor_expires_at_ms = now_ms.saturating_add(20_000);

        let control_identity = Identity::generate();
        let mut control =
            direct_capability(&control_identity, &fixture.policy, 17, actor_expires_at_ms);
        let control_advertisement = service_advertisement(
            &control_identity,
            RolesConfig {
                client: false,
                relay: true,
                exit: false,
            },
            &fixture.policy,
            17,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        let control_envelope: SignedEnvelope = decode_canonical(
            &control_advertisement,
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("signed control advertisement");
        control.advertisement_expires_at_ms = control_envelope.expires_at_ms;
        control.advertisement_payload_hash = advertisement_fingerprint(&control_advertisement)
            .expect("control fingerprint")
            .payload_hash;
        fixture
            .runtime
            .direct_relays
            .insert(control.peer_id, control.clone());
        let control_actor = actor_from_direct_capability(&control);

        let data_relay_identity = Identity::generate();
        let data_relay = direct_capability(
            &data_relay_identity,
            &fixture.policy,
            19,
            actor_expires_at_ms,
        );
        let data_relay_actor = actor_from_direct_capability(&data_relay);

        let local_advertisement = service_advertisement(
            &fixture.runtime.identity,
            roles,
            &fixture.policy,
            23,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        let envelope: SignedEnvelope = decode_canonical(
            &local_advertisement,
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("local Exit advertisement envelope");
        let exit_capability_expiry = envelope
            .expires_at_ms
            .min(fixture.policy.expires_at_ms())
            .min(control.expires_at_ms);
        let exit_actor = actor_from_signed_advertisement(
            &local_advertisement,
            &fixture.runtime.identity,
            exit_capability_expiry,
            now_ms,
        );

        let session_identity = Identity::generate();
        let session_public_key = session_identity
            .ed25519_public_key_bytes()
            .expect("session Ed25519 public key");
        let scope = NativeProbePathScope {
            attempt_id: vec![0x31; 16],
            probe_id: vec![0x32; 16],
            candidate_set_hash: vec![0x33; 32],
            candidate_ordinal: 1,
            data_relay: Some(data_relay_actor),
            control: Some(control_actor),
            exit: Some(exit_actor),
            client_session_id: node_id_from_public_key(&session_public_key).to_vec(),
            client_session_public_key: session_public_key.to_vec(),
            transport: Transport::UdpSinglePath as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version: fixture.policy.manifest_version(),
            policy_hash: fixture.policy.policy_hash().to_vec(),
            policy_expires_at_ms: fixture.policy.expires_at_ms(),
            challenge_hash: vec![0x34; 32],
            attempt_expires_at_ms: request_expires_at_ms,
            required_path_count: 1,
            reserved_up_mbps: 8,
            reserved_down_mbps: 12,
        };
        let nonce = generate_nonce();
        let permit_request = NativeProbePermitRequest {
            scope: Some(scope.clone()),
            created_at_ms: now_ms,
            expires_at_ms: request_expires_at_ms,
            nonce: nonce.to_vec(),
        };
        let signed_request = sign_control_message_with(
            &permit_request,
            session_public_key,
            now_ms,
            request_expires_at_ms,
            nonce,
            native_probe_time_policy(),
            |message| session_identity.sign(message).ok(),
        )
        .expect("session-signed native Permit request");
        let request = ExitForwardRequest::new(
            nonce[..FORWARD_ID_BYTES].to_vec(),
            control.node_id.to_vec(),
            control.peer_id.to_bytes(),
            control.public_key.to_vec(),
            fixture.runtime.service.local_peer_id().to_bytes(),
            fixture.runtime.local_node_id.to_vec(),
            request_expires_at_ms,
            ExitForwardOperation::NativeProbePermit,
            signed_request,
        )
        .expect("native Permit forward wrapper");
        fixture.runtime.served_local_advertisement = Some(local_advertisement.clone());
        NativePermitForwardFixture {
            fixture,
            now_ms,
            control,
            control_identity,
            control_advertisement,
            scope,
            request,
            local_advertisement,
        }
    }

    #[tokio::test]
    async fn native_permit_forward_scope_accepts_bounded_transaction_deadline() {
        let fixture = native_permit_forward_fixture();
        let verified = verified_native_probe_forward_scope(&fixture.request, fixture.now_ms)
            .expect("exact native Permit scope");
        assert!(verified == fixture.scope);
        assert!(forward_request_scope_matches(
            &fixture.request,
            ExitForwardOperation::NativeProbePermit,
            fixture.now_ms,
        ));

        let rebuild = |forward_id: Vec<u8>, deadline_unix_ms: u64, canonical_request: Vec<u8>| {
            ExitForwardRequest::new(
                forward_id,
                fixture.control.node_id.to_vec(),
                fixture.control.peer_id.to_bytes(),
                fixture.control.public_key.to_vec(),
                fixture.fixture.runtime.service.local_peer_id().to_bytes(),
                fixture.fixture.runtime.local_node_id.to_vec(),
                deadline_unix_ms,
                ExitForwardOperation::NativeProbePermit,
                canonical_request,
            )
            .expect("structurally valid native Permit wrapper")
        };
        let wrong_forward = rebuild(
            vec![0x91; FORWARD_ID_BYTES],
            fixture.request.deadline_unix_ms(),
            fixture.request.canonical_request().to_vec(),
        );
        assert!(verified_native_probe_forward_scope(&wrong_forward, fixture.now_ms).is_none());
        let transactional_deadline = rebuild(
            fixture.request.forward_id().to_vec(),
            fixture.request.deadline_unix_ms().saturating_sub(1),
            fixture.request.canonical_request().to_vec(),
        );
        assert!(
            verified_native_probe_forward_scope(&transactional_deadline, fixture.now_ms)
                == Some(fixture.scope.clone())
        );
        assert!(forward_request_scope_matches(
            &transactional_deadline,
            ExitForwardOperation::NativeProbePermit,
            fixture.now_ms,
        ));
        let authority_overrun = rebuild(
            fixture.request.forward_id().to_vec(),
            fixture.request.deadline_unix_ms().saturating_add(1),
            fixture.request.canonical_request().to_vec(),
        );
        assert!(verified_native_probe_forward_scope(&authority_overrun, fixture.now_ms).is_none());

        let mut envelope: SignedEnvelope = decode_canonical(
            fixture.request.canonical_request(),
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("native Permit envelope");
        envelope.signature[0] ^= 1;
        let tampered = encode_canonical(&envelope, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
            .expect("canonical tampered envelope");
        let wrong_signature = rebuild(
            fixture.request.forward_id().to_vec(),
            fixture.request.deadline_unix_ms(),
            tampered,
        );
        assert!(verified_native_probe_forward_scope(&wrong_signature, fixture.now_ms).is_none());
    }

    #[tokio::test]
    async fn native_permit_control_address_selects_lan_and_public_relay_listeners_separately() {
        let fixture = native_permit_forward_fixture();
        let scope = &fixture.scope;
        let exit_peer = *fixture.fixture.runtime.service.local_peer_id();
        // The unrelated private address sorts first, exactly as the mixed-link regression.
        let listeners = [
            "/ip4/10.241.20.2/udp/41000/quic-v1",
            "/ip4/10.241.21.2/udp/41000/quic-v1",
            "/ip4/46.162.3.1/udp/41000/quic-v1",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect::<BTreeSet<_>>();
        let lan = identity_bound_exit_control_address(
            &listeners,
            scope,
            exit_peer,
            Some(&[10, 241, 21, 2]),
        )
        .expect("the LAN Relay receives its exact observed active Exit listener");
        let public = identity_bound_exit_control_address(&listeners, scope, exit_peer, None)
            .expect("the public Relay does not inherit another peer's private listener");
        assert_eq!(
            lan,
            format!("/ip4/10.241.21.2/udp/41000/quic-v1/p2p/{exit_peer}")
        );
        assert_eq!(
            public,
            format!("/ip4/46.162.3.1/udp/41000/quic-v1/p2p/{exit_peer}")
        );
        assert!(
            identity_bound_exit_control_address(
                &listeners,
                scope,
                exit_peer,
                Some(&[10, 241, 22, 2]),
            )
            .is_none(),
            "an unserved observed address never falls back to a different LAN"
        );
        let private_only = listeners
            .into_iter()
            .filter(|address| address.contains("/10."))
            .collect();
        assert!(
            identity_bound_exit_control_address(&private_only, scope, exit_peer, None).is_none()
        );
    }

    #[tokio::test]
    async fn native_permit_private_listener_needs_current_authenticated_data_relay_lineage() {
        let mut fixture = native_permit_forward_fixture();
        let relay = fixture.scope.data_relay.as_ref().unwrap();
        let relay_peer = Libp2pPeerId::from_bytes(&relay.peer_id).unwrap();
        let runtime = &mut fixture.fixture.runtime;
        runtime.control_addresses = [
            "/ip4/10.241.21.2/udp/41000/quic-v1",
            "/ip4/46.162.3.1/udp/41000/quic-v1",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect();
        // A remembered/private peer claim alone cannot select a private listener. The live,
        // bounded connection registry must still agree that this exact data peer is direct LAN.
        runtime.observed_endpoints.insert(
            relay_peer,
            (
                "/ip4/10.241.21.1/udp/41000/quic-v1".to_owned(),
                Some("10.241.21.1".parse().unwrap()),
            ),
        );
        runtime.record_local_endpoint_observation(
            relay_peer,
            &"/ip4/10.241.21.2/udp/41000/quic-v1".parse().unwrap(),
        );
        assert!(
            runtime
                .service
                .authenticated_local_peer_prefix(relay_peer)
                .is_none()
        );
        let selected = runtime
            .native_permit_exit_control_address(&fixture.scope)
            .unwrap();
        assert!(selected.starts_with("/ip4/46.162.3.1/"));
        runtime
            .control_addresses
            .retain(|address| address.contains("/10."));
        assert!(
            runtime
                .native_permit_exit_control_address(&fixture.scope)
                .is_none()
        );
    }

    #[test]
    fn native_rpc_deadline_is_capped_by_signed_authority() {
        let authority_expires_at_ms = 300_000;
        assert!(native_rpc_deadline_is_within_authority(
            30_000,
            authority_expires_at_ms
        ));
        assert!(native_rpc_deadline_is_within_authority(
            authority_expires_at_ms,
            authority_expires_at_ms
        ));
        assert!(!native_rpc_deadline_is_within_authority(
            authority_expires_at_ms.saturating_add(1),
            authority_expires_at_ms
        ));
    }

    #[tokio::test]
    async fn native_permit_control_actor_matches_every_current_capability_field() {
        let fixture = native_permit_forward_fixture();
        let actor = fixture.scope.control.as_ref().expect("control actor");
        let peer = fixture.control.peer_id;
        let deadline = fixture.request.deadline_unix_ms();
        assert!(native_probe_control_capability_matches(
            &fixture.control,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));

        let mut changed = fixture.control.clone();
        changed.advertisement_sequence = changed.advertisement_sequence.saturating_add(1);
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.advertisement_expires_at_ms = changed.advertisement_expires_at_ms.saturating_add(1);
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.advertisement_payload_hash = changed.advertisement_payload_hash.xor_for_test();
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.policy_version = changed.policy_version.saturating_add(1);
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.policy_hash[0] ^= 1;
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.policy_expires_at_ms = changed.policy_expires_at_ms.saturating_sub(1);
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        let mut changed = fixture.control.clone();
        changed.expires_at_ms = changed.expires_at_ms.saturating_sub(1);
        assert!(!native_probe_control_capability_matches(
            &changed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        assert!(!native_probe_control_capability_matches(
            &fixture.control,
            actor,
            &fixture.scope,
            Identity::generate().peer_id().to_owned(),
            deadline,
        ));

        let mut substituted_actor = actor.clone();
        substituted_actor.advertisement_payload_hash[0] ^= 1;
        let mut substituted_scope = fixture.scope.clone();
        substituted_scope.control = Some(substituted_actor.clone());
        assert!(!native_probe_control_capability_matches(
            &fixture.control,
            &substituted_actor,
            &substituted_scope,
            peer,
            deadline,
        ));
    }

    #[tokio::test]
    async fn native_permit_accepts_async_same_identity_control_views() {
        let fixture = native_permit_forward_fixture();
        let actor = fixture.scope.control.as_ref().expect("control actor");
        let peer = fixture.control.peer_id;
        let deadline = fixture.request.deadline_unix_ms();
        let mut refreshed = fixture.control.clone();
        refreshed.advertisement_sequence = refreshed.advertisement_sequence.saturating_add(1);
        refreshed.advertisement_payload_hash = refreshed.advertisement_payload_hash.xor_for_test();

        assert!(!native_probe_control_capability_matches(
            &refreshed,
            actor,
            &fixture.scope,
            peer,
            deadline,
        ));
        assert!(native_probe_control_capability_lineage_matches(
            &refreshed,
            actor,
            &fixture.scope,
            peer,
            deadline,
            fixture.now_ms,
        ));

        let mut substituted_identity = refreshed.clone();
        substituted_identity.public_key[0] ^= 1;
        assert!(!native_probe_control_capability_lineage_matches(
            &substituted_identity,
            actor,
            &fixture.scope,
            peer,
            deadline,
            fixture.now_ms,
        ));

        let mut lagging = fixture.control.clone();
        lagging.advertisement_sequence = actor.advertisement_sequence.saturating_sub(1);
        lagging.advertisement_payload_hash = lagging.advertisement_payload_hash.xor_for_test();
        lagging.advertisement_expires_at_ms = deadline.saturating_add(1_000);
        lagging.expires_at_ms = deadline.saturating_add(1_000);
        let mut long_attempt = fixture.scope.clone();
        long_attempt.attempt_expires_at_ms = actor.capability_expires_at_ms;
        assert!(native_probe_control_capability_lineage_matches(
            &lagging,
            actor,
            &long_attempt,
            peer,
            deadline,
            fixture.now_ms,
        ));

        let mut actor_lifetime_overrun = long_attempt.clone();
        actor_lifetime_overrun.attempt_expires_at_ms =
            actor.capability_expires_at_ms.saturating_add(1);
        assert!(!native_probe_control_capability_lineage_matches(
            &lagging,
            actor,
            &actor_lifetime_overrun,
            peer,
            deadline,
            fixture.now_ms,
        ));

        let mut stale_for_operation = lagging.clone();
        stale_for_operation.expires_at_ms = deadline.saturating_sub(1);
        assert!(!native_probe_control_capability_lineage_matches(
            &stale_for_operation,
            actor,
            &long_attempt,
            peer,
            deadline,
            fixture.now_ms,
        ));

        let mut contradictory_same_sequence = lagging;
        contradictory_same_sequence.advertisement_sequence = actor.advertisement_sequence;
        assert!(!native_probe_control_capability_lineage_matches(
            &contradictory_same_sequence,
            actor,
            &long_attempt,
            peer,
            deadline,
            fixture.now_ms,
        ));
    }

    fn exit_data_relay_cache_input(
        fixture: &NativePermitForwardFixture,
        relay: &Identity,
        sequence: u64,
    ) -> (Vec<u8>, NativeProbePathScope) {
        let encoded = service_advertisement(
            relay,
            RolesConfig {
                client: true,
                relay: true,
                exit: true,
            },
            &fixture.fixture.policy,
            sequence,
            generate_nonce(),
            fixture.now_ms,
            &fixture.fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        let mut scope = fixture.scope.clone();
        scope.data_relay = Some(actor_from_signed_advertisement(
            &encoded,
            relay,
            scope.attempt_expires_at_ms,
            fixture.now_ms,
        ));
        (encoded, scope)
    }

    #[tokio::test]
    async fn native_permit_control_authority_is_carried_without_exit_client_candidates() {
        let mut fixture = native_permit_forward_fixture();
        fixture.fixture.runtime.direct_relays.clear();
        let mut control_service = DiscoveryService::new_with_protocol_roles(
            fixture.control_identity.keypair().clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("control service");
        control_service
            .set_local_advertisement(fixture.control_advertisement.clone())
            .expect("serve exact signed control advertisement");
        let upstream = local_exit_forward_upstream_request(
            &control_service,
            &fixture.request,
            fixture.control.peer_id,
            fixture.now_ms,
        )
        .expect("control adds its own authority without rewriting the signed Client request");
        let forwarded = upstream.as_forward_request();
        assert_eq!(
            forwarded.canonical_request(),
            fixture.request.canonical_request()
        );
        assert_eq!(
            forwarded.control_advertisement(),
            fixture.control_advertisement
        );
        let actor = fixture.scope.control.as_ref().unwrap();
        let accepted = native_probe_relay_capability_from_advertisement(
            forwarded.control_advertisement(),
            actor,
            &fixture.scope,
            fixture.control.peer_id,
            fixture.now_ms,
        )
        .expect("Exit verifies exact signed authority without its own Client candidates");
        assert_eq!(accepted, fixture.control);
        assert!(fixture.fixture.runtime.direct_relays.is_empty());
        assert!(
            retain_exit_relay_capability(
                &mut fixture.fixture.runtime.exit_control_relays,
                1,
                accepted.clone(),
            )
            .is_some()
        );
        assert_eq!(
            fixture
                .fixture
                .runtime
                .exit_control_relays
                .get(&accepted.peer_id),
            Some(&accepted)
        );
        assert!(fixture.fixture.runtime.direct_relays.is_empty());
        assert!(
            native_probe_relay_capability_from_advertisement(
                &[],
                actor,
                &fixture.scope,
                fixture.control.peer_id,
                fixture.now_ms,
            )
            .is_none()
        );
        assert!(
            native_probe_relay_capability_from_advertisement(
                forwarded.control_advertisement(),
                actor,
                &fixture.scope,
                *Identity::generate().peer_id(),
                fixture.now_ms,
            )
            .is_none()
        );
        let mut wrong_actor = actor.clone();
        wrong_actor.advertisement_payload_hash[0] ^= 1;
        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.control = Some(wrong_actor.clone());
        assert!(
            native_probe_relay_capability_from_advertisement(
                forwarded.control_advertisement(),
                &wrong_actor,
                &wrong_scope,
                fixture.control.peer_id,
                fixture.now_ms,
            )
            .is_none()
        );
        let production = include_str!("discovery.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .unwrap()
            .0;
        let handler = braced_item(production, "fn prepare_native_probe_permit_response(");
        assert!(!handler.contains(".direct_relays"));
        assert!(handler.contains("request.control_advertisement()"));
    }

    #[tokio::test]
    async fn native_ready_exit_service_cache_is_separate_from_local_client_provenance() {
        let mut fixture = native_permit_forward_fixture();
        fixture.fixture.runtime.roles = RolesConfig {
            client: true,
            relay: true,
            exit: true,
        };
        let relay = Identity::generate();
        let peer = *relay.peer_id();
        let (encoded, scope) = exit_data_relay_cache_input(&fixture, &relay, 31);
        fixture
            .fixture
            .runtime
            .record_privacy_conflict(peer, 31, scope.attempt_expires_at_ms);
        let client_candidates = fixture.fixture.runtime.direct_relays.clone();
        let client_conflicts = fixture.fixture.runtime.privacy_conflicts.clone();
        let runtime = &mut fixture.fixture.runtime;
        let accepted = cache_exit_data_relay_capability(
            &mut runtime.exit_data_relays,
            runtime.candidate_limit,
            &encoded,
            scope.data_relay.as_ref().unwrap(),
            &scope,
            peer,
            fixture.now_ms,
        )
        .expect("another Client's signed data-Relay authority is Exit-service scoped");
        assert_eq!(runtime.exit_data_relays.get(&peer), Some(&accepted));
        assert_eq!(runtime.direct_relays, client_candidates);
        assert_eq!(runtime.privacy_conflicts, client_conflicts);
        let production = include_str!("discovery.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .unwrap()
            .0;
        let ready = braced_item(production, "async fn answer_native_probe_ready_upstream(");
        assert!(ready.contains("&mut self.exit_data_relays"));
        assert!(!ready.contains(".direct_relays"));
        assert!(!ready.contains("self.privacy_conflicts"));
        assert!(ready.contains("verify_native_probe_permit("));
        assert!(ready.contains(".bind_native_probe_data_relay_connection("));
    }

    #[tokio::test]
    async fn native_ready_exit_service_cache_bounds_peers_and_preserves_signed_lineage() {
        let fixture = native_permit_forward_fixture();
        let relay = Identity::generate();
        let peer = *relay.peer_id();
        let mut cache = HashMap::new();
        let (encoded, scope) = exit_data_relay_cache_input(&fixture, &relay, 31);
        let admit =
            |cache: &mut HashMap<_, _>, encoded: &[u8], scope: &NativeProbePathScope, peer| {
                cache_exit_data_relay_capability(
                    cache,
                    1,
                    encoded,
                    scope.data_relay.as_ref().unwrap(),
                    scope,
                    peer,
                    fixture.now_ms,
                )
            };
        let first = admit(&mut cache, &encoded, &scope, peer).expect("first peer");
        let other = Identity::generate();
        let (other_encoded, other_scope) = exit_data_relay_cache_input(&fixture, &other, 31);
        assert!(admit(&mut cache, &other_encoded, &other_scope, *other.peer_id()).is_none());
        assert_eq!(cache.len(), 1);
        assert!(admit(&mut cache, &encoded, &scope, *other.peer_id()).is_none());
        let (conflict_encoded, conflict_scope) = exit_data_relay_cache_input(&fixture, &relay, 31);
        assert!(admit(&mut cache, &conflict_encoded, &conflict_scope, peer).is_none());
        assert_eq!(cache.get(&peer), Some(&first));

        let (new_encoded, new_scope) = exit_data_relay_cache_input(&fixture, &relay, 32);
        let latest = admit(&mut cache, &new_encoded, &new_scope, peer).expect("same-peer refresh");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&peer), Some(&latest));
        assert_eq!(admit(&mut cache, &encoded, &scope, peer), Some(first));
        assert_eq!(
            cache.get(&peer),
            Some(&latest),
            "old signed scope cannot roll cache back"
        );
        let mut wrong_policy = scope.clone();
        wrong_policy.policy_hash[0] ^= 1;
        assert!(admit(&mut cache, &encoded, &wrong_policy, peer).is_none());
        assert!(
            cache_exit_data_relay_capability(
                &mut cache,
                1,
                &new_encoded,
                new_scope.data_relay.as_ref().unwrap(),
                &new_scope,
                peer,
                new_scope.attempt_expires_at_ms,
            )
            .is_none()
        );
        assert_eq!(cache.get(&peer), Some(&latest));
    }

    #[tokio::test]
    async fn native_ready_recovers_exact_previous_local_relay_advertisement_after_refresh() {
        let roles = RolesConfig {
            client: false,
            relay: true,
            exit: false,
        };
        let mut fixture = fixture(roles);
        let now_ms = unix_millis();
        let required_until_ms = now_ms.saturating_add(5_000);
        let original = service_advertisement(
            &fixture.runtime.identity,
            roles,
            &fixture.policy,
            41,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        let original_envelope: SignedEnvelope =
            decode_canonical(&original, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
                .expect("original local Relay envelope");
        let actor = actor_from_signed_advertisement(
            &original,
            &fixture.runtime.identity,
            original_envelope
                .expires_at_ms
                .min(fixture.policy.expires_at_ms()),
            now_ms,
        );
        let scope = NativeProbePathScope {
            attempt_id: vec![0xb1; FORWARD_ID_BYTES],
            probe_id: vec![0xb2; FORWARD_ID_BYTES],
            candidate_set_hash: vec![0xb3; 32],
            candidate_ordinal: 1,
            data_relay: Some(actor.clone()),
            control: None,
            exit: None,
            client_session_id: vec![0xb4; 32],
            client_session_public_key: vec![0xb5; 32],
            transport: Transport::UdpSinglePath as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version: fixture.policy.manifest_version(),
            policy_hash: fixture.policy.policy_hash().to_vec(),
            policy_expires_at_ms: fixture.policy.expires_at_ms(),
            challenge_hash: vec![0xb6; 32],
            attempt_expires_at_ms: required_until_ms,
            required_path_count: 1,
            reserved_up_mbps: 8,
            reserved_down_mbps: 12,
        };
        fixture
            .runtime
            .service
            .set_local_advertisement(original.clone())
            .expect("install original local Relay advertisement");

        let replacement = service_advertisement(
            &fixture.runtime.identity,
            roles,
            &fixture.policy,
            42,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        fixture
            .runtime
            .service
            .set_local_advertisement(replacement.clone())
            .expect("refresh local Relay advertisement");

        assert!(
            native_probe_data_relay_capability_from_advertisement(
                &replacement,
                &actor,
                &scope,
                *fixture.runtime.service.local_peer_id(),
                now_ms,
            )
            .is_none(),
            "the current advertisement must not be substituted for the signed actor"
        );
        let (capability, encoded) = local_native_probe_data_relay_authority(
            &fixture.runtime.service,
            &actor,
            &scope,
            *fixture.runtime.service.local_peer_id(),
            now_ms,
            required_until_ms,
        )
        .expect("exact still-valid previous Relay authority");
        assert_eq!(encoded, original);
        assert!(native_probe_data_relay_capability_matches(
            &capability,
            &actor,
            &scope,
            *fixture.runtime.service.local_peer_id(),
            required_until_ms,
        ));
    }

    #[tokio::test]
    async fn native_permit_local_exit_actor_requires_current_signed_role_and_policy() {
        let fixture = native_permit_forward_fixture();
        let runtime = &fixture.fixture.runtime;
        let actor = fixture.scope.exit.as_ref().expect("Exit actor");
        let matches = |advertisement: &[u8], actor: &PreselectionActorBinding, scope| {
            local_native_probe_exit_actor_matches(
                advertisement,
                actor,
                scope,
                runtime.local_node_id,
                *runtime.service.local_peer_id(),
                runtime.local_public_key,
                fixture.now_ms,
            )
        };
        assert!(matches(&fixture.local_advertisement, actor, &fixture.scope,));

        let mut conservative_actor = actor.clone();
        conservative_actor.capability_expires_at_ms = conservative_actor
            .capability_expires_at_ms
            .saturating_sub(1);
        let mut conservative_scope = fixture.scope.clone();
        conservative_scope.exit = Some(conservative_actor.clone());
        assert!(matches(
            &fixture.local_advertisement,
            &conservative_actor,
            &conservative_scope,
        ));

        let mut overlong_actor = actor.clone();
        overlong_actor.capability_expires_at_ms =
            overlong_actor.capability_expires_at_ms.saturating_add(1);
        let mut overlong_scope = fixture.scope.clone();
        overlong_scope.exit = Some(overlong_actor.clone());
        assert!(!matches(
            &fixture.local_advertisement,
            &overlong_actor,
            &overlong_scope,
        ));

        let mut expired_actor = actor.clone();
        expired_actor.capability_expires_at_ms = fixture.now_ms;
        let mut expired_scope = fixture.scope.clone();
        expired_scope.exit = Some(expired_actor.clone());
        assert!(!matches(
            &fixture.local_advertisement,
            &expired_actor,
            &expired_scope,
        ));

        let mut wrong_actor = actor.clone();
        wrong_actor.advertisement_sequence = wrong_actor.advertisement_sequence.saturating_add(1);
        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.exit = Some(wrong_actor.clone());
        assert!(!matches(
            &fixture.local_advertisement,
            &wrong_actor,
            &wrong_scope,
        ));
        let mut wrong_actor = actor.clone();
        wrong_actor.advertisement_payload_hash[0] ^= 1;
        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.exit = Some(wrong_actor.clone());
        assert!(!matches(
            &fixture.local_advertisement,
            &wrong_actor,
            &wrong_scope,
        ));
        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.policy_hash[0] ^= 1;
        assert!(!matches(&fixture.local_advertisement, actor, &wrong_scope,));
        let mut unsupported = fixture.scope.clone();
        unsupported.transport = Transport::MultipathQuic as i32;
        assert!(!matches(&fixture.local_advertisement, actor, &unsupported,));

        let relay_only = service_advertisement(
            &runtime.identity,
            RolesConfig {
                client: false,
                relay: true,
                exit: false,
            },
            &fixture.fixture.policy,
            actor.advertisement_sequence,
            generate_nonce(),
            fixture.now_ms,
            &fixture.fixture.directory,
        );
        assert!(!matches(
            relay_only.signed_envelope(),
            actor,
            &fixture.scope,
        ));
    }

    #[tokio::test]
    async fn native_exit_accepts_exact_previous_local_advertisement_after_refresh() {
        let mut fixture = native_permit_forward_fixture();
        let actor = fixture.scope.exit.as_ref().expect("Exit actor").clone();
        fixture
            .fixture
            .runtime
            .service
            .set_local_advertisement(fixture.local_advertisement.clone())
            .expect("install original local Exit advertisement");
        let replacement = service_advertisement(
            &fixture.fixture.runtime.identity,
            RolesConfig {
                client: true,
                relay: false,
                exit: true,
            },
            &fixture.fixture.policy,
            actor.advertisement_sequence.saturating_add(1),
            generate_nonce(),
            fixture.now_ms,
            &fixture.fixture.directory,
        )
        .signed_envelope()
        .to_vec();
        fixture
            .fixture
            .runtime
            .service
            .set_local_advertisement(replacement.clone())
            .expect("refresh local Exit advertisement");
        let runtime = &fixture.fixture.runtime;
        assert!(!local_native_probe_exit_actor_matches(
            &replacement,
            &actor,
            &fixture.scope,
            runtime.local_node_id,
            *runtime.service.local_peer_id(),
            runtime.local_public_key,
            fixture.now_ms,
        ));
        assert!(local_native_probe_exit_actor_is_served(
            &runtime.service,
            &actor,
            &fixture.scope,
            runtime.local_node_id,
            *runtime.service.local_peer_id(),
            runtime.local_public_key,
            fixture.now_ms,
        ));
    }

    #[test]
    fn production_session_starts_use_prepared_route_proofs_without_advertisement_cache() {
        let source = include_str!("discovery.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("production/test boundary")
            .0;

        for handler in [
            "async fn begin_udp_session_start(",
            "async fn begin_mptcp_session_start(",
            "async fn begin_mpquic_session_start(",
        ] {
            let relay_start = braced_item(production, handler);
            for proof in [
                "prepared_production_relay_routes",
                "route.accepted.reservation_id()",
                "route.accepted.exit_node_id()",
                "authorized_exit: None",
            ] {
                assert!(
                    relay_start.contains(proof),
                    "missing Relay proof {proof} in {handler}"
                );
            }
            assert!(!relay_start.contains("self.forwarded_exits"));
        }

        let relay_authority = braced_item(production, "fn relay_authority_is_current(");
        let cache_independent = relay_authority
            .find("None => matches!(")
            .expect("cache-independent operations");
        for operation in [
            "ExitForwardOperation::UdpSessionStart",
            "ExitForwardOperation::MptcpSessionStart",
            "ExitForwardOperation::MpquicSessionStart",
        ] {
            assert!(relay_authority[cache_independent..].contains(operation));
        }

        let exit_forward = braced_item(production, "async fn answer_exit_forward_upstream(");
        let advertisement_cache = exit_forward
            .find(".direct_relays")
            .expect("ordinary forwarded operation advertisement cache");
        for operation in [
            "| ExitForwardOperation::UdpSessionStart",
            "| ExitForwardOperation::MptcpSessionStart",
            "| ExitForwardOperation::MpquicSessionStart",
        ] {
            assert!(
                exit_forward
                    .find(operation)
                    .is_some_and(|bypass| bypass < advertisement_cache),
                "missing prepared-session cache bypass {operation}"
            );
        }

        let exit_start = braced_item(production, "async fn begin_production_mpquic_exit_session(");
        for proof in [
            "path.relay.relay_peer_id == authenticated_control_relay.to_bytes()",
            "forward_id == path.confirmation_nonce[..FORWARD_ID_BYTES]",
            "prepared_production_exit_routes",
            "route.bundle.signed_exit_reservation() == start.signed_exit_reservation()",
            "route.pending_activations.len() == selected_path_ids.len()",
        ] {
            assert!(exit_start.contains(proof), "missing Exit proof {proof}");
        }
    }

    #[test]
    fn native_permit_chain_targets_exact_exit_without_provider_catalog() {
        let source = include_str!("discovery.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("production/test boundary")
            .0;

        let ready = braced_item(production, "async fn begin_native_probe_ready(");
        let permit = ready
            .find("verify_native_probe_permit(")
            .expect("verified short-lived Exit Permit");
        let eligibility = ready
            .find("permit_bound_exit_peer_is_eligible(")
            .expect("privacy-safe permit target gate");
        let dispatch = ready
            .find(".request_exit_forward_upstream(&exit_peer")
            .expect("exact Permit Exit dispatch");
        assert!(permit < eligibility && eligibility < dispatch);
        assert!(ready.contains("local_native_probe_data_relay_authority("));
        assert!(!ready.contains("exit_provider_peers"));

        let authorization = braced_item(production, "async fn begin_native_probe_authorization(");
        for retained in [
            "prepared.start.encoded_start() != request.client_signed_request()",
            "prepared.start.authorization_chain()",
            "permit_bound_exit_peer_is_eligible(",
            "native_probe_data_relay_capability_matches(",
            ".request_exit_forward_upstream(&exit_peer",
        ] {
            assert!(
                authorization.contains(retained),
                "missing Permit-descended authorization binding {retained}"
            );
        }
        assert!(!authorization.contains("exit_provider_peers"));

        let generic = braced_item(production, "fn begin_relay_forward_inner(");
        assert!(generic.contains("self.exit_provider_peers.contains_key(&exit_peer)"));
        assert!(generic.contains(
            "self.relay_forward_exit_peer_is_eligible(authenticated_client_peer, exit_peer)"
        ));
    }

    #[tokio::test]
    async fn permit_bound_exit_target_scopes_client_conflicts_to_the_client_role() {
        let now_ms = unix_millis();
        let mut fixture = fixture(RolesConfig {
            client: false,
            relay: true,
            exit: false,
        });
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let client_peer = Identity::generate().peer_id().to_owned();
        let local_peer = *fixture.runtime.service.local_peer_id();

        assert!(!fixture.runtime.exit_provider_peers.contains_key(&exit_peer));
        assert!(
            fixture
                .runtime
                .permit_bound_exit_peer_is_eligible(client_peer, exit_peer)
        );
        for (client, exit) in [
            (client_peer, local_peer),
            (local_peer, exit_peer),
            (exit_peer, exit_peer),
        ] {
            assert!(
                !fixture
                    .runtime
                    .permit_bound_exit_peer_is_eligible(client, exit)
            );
        }

        let direct = direct_capability(
            &exit_identity,
            &fixture.policy,
            1,
            now_ms.saturating_add(20_000),
        );
        fixture.runtime.direct_relays.insert(exit_peer, direct);
        assert!(
            fixture
                .runtime
                .permit_bound_exit_peer_is_eligible(client_peer, exit_peer)
        );
        assert!(
            !fixture
                .runtime
                .forwarded_exit_peer_is_eligible(exit_peer, now_ms)
        );

        fixture.runtime.direct_relays.remove(&exit_peer);
        fixture
            .runtime
            .record_privacy_conflict(exit_peer, 2, now_ms.saturating_add(20_000));
        assert!(
            fixture
                .runtime
                .permit_bound_exit_peer_is_eligible(client_peer, exit_peer)
        );
        assert!(
            !fixture
                .runtime
                .forwarded_exit_peer_is_eligible(exit_peer, now_ms)
        );
    }

    #[test]
    fn native_permit_production_caller_keeps_connection_owner_until_immediate_send() {
        let source = include_str!("discovery.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("production/test boundary")
            .0;
        let handler = braced_item(production, "async fn handle_exit_forward_upstream_event(");
        assert!(handler.contains("connection_id,"));
        assert!(handler.contains(
            "self.answer_exit_forward_upstream(peer, connection_id, request, channel, state)"
        ));

        let caller = braced_item(production, "fn prepare_native_probe_permit_response(");
        assert_eq!(
            production
                .matches(".issue_native_probe_permit_with(")
                .count(),
            1,
        );
        let capability_check = caller
            .find("native_probe_control_capability_lineage_matches(")
            .expect("current control capability lineage check");
        let local_advertisement_check = caller
            .find("local_native_probe_exit_actor_is_served(")
            .expect("bounded local Exit advertisement check");
        let connection_bind = caller
            .find(".bind_native_probe_control_connection(")
            .expect("event connection bind");
        let exit_call = caller
            .find(".issue_native_probe_permit_with(")
            .expect("Exit Permit call");
        assert!(capability_check < connection_bind);
        assert!(local_advertisement_check < connection_bind);
        assert!(connection_bind < exit_call);
        assert!(!caller.contains(".await"));
        assert!(!caller.contains("issue_native_probe_ready"));
        assert!(!caller.contains("issue_native_probe_result"));
        assert!(!caller.contains("HelperClient"));
        assert!(!caller.contains("network_address_usable"));

        let prepared = braced_item(production, "struct PreparedNativeProbePermitResponse {");
        for retained in [
            "connection: BoundNativeProbeControlConnection",
            "channel: request_response::ResponseChannel<UpstreamExitForwardResponse>",
            "response: UpstreamExitForwardResponse",
        ] {
            assert!(prepared.contains(retained));
        }
        assert!(!prepared.contains("derive("));

        let sender = braced_item(production, "fn send_prepared_native_probe_permit_response(");
        assert!(sender.contains("send_native_probe_permit_response("));
        assert!(!sender.contains(".await"));

        let publisher = braced_item(production, "async fn publish_local(");
        let service_role_guard = publisher
            .find("if !(self.roles.relay || self.roles.exit)")
            .expect("service advertisement role gate");
        let capacity_snapshot = publisher
            .find("self.local_advertisement_capacity(roles, now_ms)")
            .expect("current local capacity snapshot");
        let served_assignment = publisher
            .find("self.served_local_advertisement = Some(")
            .expect("service advertisement assignment");
        assert!(service_role_guard < capacity_snapshot);
        assert!(capacity_snapshot < served_assignment);
    }

    #[test]
    fn native_authorization_request_id_is_distinct_nonzero_and_deterministic() {
        let start = [0x35; 32];
        let authorization = native_probe_authorization_request_id(start);
        assert_ne!(authorization, start[..FORWARD_ID_BYTES]);
        assert_eq!(authorization[0], start[0] ^ 0x80);
        assert!(authorization.iter().any(|byte| *byte != 0));
        assert_eq!(authorization, native_probe_authorization_request_id(start));

        let mut zero_after_toggle = [0_u8; 32];
        zero_after_toggle[0] = 0x80;
        assert_eq!(native_probe_authorization_request_id(zero_after_toggle), {
            let mut expected = [0_u8; FORWARD_ID_BYTES];
            expected[FORWARD_ID_BYTES - 1] = 1;
            expected
        });
    }

    #[test]
    fn native_probe_liveness_evidence_preserves_reserved_capacity() {
        let evidence = native_probe_leg_evidence(
            NATIVE_PROBE_DATAGRAM_BYTES as u64,
            NATIVE_PROBE_DATAGRAM_BYTES as u64,
            8,
            12,
            1_000,
            11_000,
        )
        .expect("native liveness evidence");

        assert_eq!(evidence.up_capacity_mbps, 8);
        assert_eq!(evidence.down_capacity_mbps, 12);
        assert_eq!(
            evidence.transmitted_bytes,
            NATIVE_PROBE_DATAGRAM_BYTES as u64
        );
        assert_eq!(evidence.received_bytes, NATIVE_PROBE_DATAGRAM_BYTES as u64);
        assert_eq!(evidence.rtt_micros, 10_000_000);
        assert_eq!(evidence.measured_at_ms, 11_000);
    }

    #[test]
    fn native_service_prepare_plan_is_role_exact_and_deadline_bound() {
        let now_ms = unix_millis();
        let scope = NativeProbePathScope {
            attempt_id: vec![0x36; FORWARD_ID_BYTES],
            probe_id: vec![0x37; FORWARD_ID_BYTES],
            candidate_ordinal: 2,
            attempt_expires_at_ms: now_ms.saturating_add(300_000),
            required_path_count: 3,
            reserved_up_mbps: 8,
            reserved_down_mbps: 12,
            ..NativeProbePathScope::default()
        };
        let relay = native_service_prepare_request(
            &scope,
            ContextRole::Relay,
            &[WireguardRole::RelayClient, WireguardRole::RelayExit],
            now_ms,
        )
        .expect("relay prepare plan");
        assert_eq!(relay.route_context_id, scope.attempt_id);
        assert_eq!(relay.role, ContextRole::Relay as i32);
        assert_eq!(relay.leases.len(), 2);
        assert!(relay.leases.iter().all(|lease| lease.path_id == 2));
        assert_eq!(relay.setup_expires_at_unix, now_ms / 1_000 + 30);
        assert_eq!(
            relay.hard_expires_at_unix,
            scope.attempt_expires_at_ms / 1_000
        );
        assert!(relay.setup_expires_at_unix < relay.hard_expires_at_unix);

        let exit = native_service_prepare_request(
            &scope,
            ContextRole::Exit,
            &[WireguardRole::Exit],
            now_ms,
        )
        .expect("exit prepare plan");
        assert_eq!(exit.leases.len(), 3);
        assert_eq!(exit.setup_expires_at_unix, relay.setup_expires_at_unix);
        assert_eq!(exit.hard_expires_at_unix, relay.hard_expires_at_unix);
        assert_eq!(
            exit.leases
                .iter()
                .map(|lease| (lease.path_id, lease.role))
                .collect::<Vec<_>>(),
            vec![
                (1, WireguardRole::Exit as i32),
                (2, WireguardRole::Exit as i32),
                (3, WireguardRole::Exit as i32),
            ]
        );

        assert!(
            native_service_prepare_request(
                &scope,
                ContextRole::Relay,
                &[WireguardRole::RelayExit, WireguardRole::RelayClient],
                now_ms,
            )
            .is_none()
        );
        assert!(
            native_service_prepare_request(
                &scope,
                ContextRole::Client,
                &[WireguardRole::Client],
                now_ms,
            )
            .is_none()
        );
        let mut expiring = scope;
        expiring.attempt_expires_at_ms = now_ms.saturating_add(1_000);
        assert!(
            native_service_prepare_request(
                &expiring,
                ContextRole::Exit,
                &[WireguardRole::Exit],
                now_ms,
            )
            .is_none()
        );
    }

    #[test]
    fn native_exit_ready_reuses_live_owner_across_setup_deadline_ticks() {
        let now_ms = 1_000_000;
        let scope = NativeProbePathScope {
            attempt_id: vec![0x38; FORWARD_ID_BYTES],
            probe_id: vec![0x39; FORWARD_ID_BYTES],
            candidate_ordinal: 1,
            attempt_expires_at_ms: now_ms + 300_000,
            required_path_count: 2,
            reserved_up_mbps: 8,
            reserved_down_mbps: 8,
            ..NativeProbePathScope::default()
        };
        let owner = native_service_prepare_request(
            &scope,
            ContextRole::Exit,
            &[WireguardRole::Exit],
            now_ms,
        )
        .expect("first Exit prepare");
        let requested = native_service_prepare_request(
            &scope,
            ContextRole::Exit,
            &[WireguardRole::Exit],
            now_ms + 1_000,
        )
        .expect("next-path Exit prepare");
        assert_ne!(owner.setup_expires_at_unix, requested.setup_expires_at_unix);
        assert!(native_exit_ready_prepare_matches(
            &owner,
            &requested,
            now_ms + 1_000
        ));

        let mut conflicting = requested.clone();
        conflicting.mptcp_subflows += 1;
        assert!(!native_exit_ready_prepare_matches(
            &owner,
            &conflicting,
            now_ms + 1_000
        ));
        assert!(!native_exit_ready_prepare_matches(
            &owner,
            &requested,
            owner.setup_expires_at_unix * 1_000
        ));
    }

    #[test]
    fn native_ready_production_chain_prepares_signs_and_retains_before_authorize() {
        let source = include_str!("discovery.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("production/test boundary")
            .0;

        let relay_ready = braced_item(production, "async fn begin_native_probe_ready(");
        let relay_prepare = relay_ready
            .find(".prepare_lease_batch(")
            .expect("Relay helper Prepare");
        let ready_dispatch = relay_ready
            .find(".request_exit_forward_upstream(")
            .expect("Ready upstream dispatch");
        assert!(relay_prepare < ready_dispatch);
        assert!(relay_ready.contains("native_ready: Some(PendingNativeProbeReady"));

        let exit_ready = braced_item(production, "async fn answer_native_probe_ready_upstream(");
        assert!(exit_ready.contains("self.collect_exit_native_ready("));
        assert!(!exit_ready.contains(".prepare_lease_batch("));
        let collector_source = include_str!("discovery/native_ready.rs");
        let collector = braced_item(collector_source, "async fn collect_exit_native_ready(");
        assert!(
            collector.find("if !complete {").unwrap()
                < collector
                    .find("self.prepare_complete_exit_native_ready(")
                    .unwrap()
        );
        assert!(!collector.contains(".prepare_lease_batch("));
        let exit_ready = braced_item(production, "async fn finish_exit_native_ready(");
        let exit_prepare = exit_ready
            .find(".prepare_lease_batch(")
            .expect("Exit helper Prepare");
        let connection_bind = exit_ready
            .find(".bind_native_probe_data_relay_connection(")
            .expect("affine data-Relay connection");
        let issue_ready = exit_ready
            .find(".issue_native_probe_ready_from_permit_with(")
            .expect("Exit Ready issue");
        let send_ready = exit_ready
            .find(".send_native_probe_ready_response(")
            .expect("affine Ready response");
        assert!(exit_prepare < connection_bind);
        assert!(connection_bind < issue_ready);
        assert!(issue_ready < send_ready);

        let client_start = braced_item(
            production,
            "async fn begin_native_probe_start_authorization(",
        );
        let verify_start = client_start
            .find("verify_native_probe_start_for_relay(")
            .expect("full Start verification");
        let retain = client_start
            .find(".retain_prepared_native_probe_authorization(")
            .expect("affine prepared authorization retention");
        let authorize = client_start
            .find(".begin_native_probe_authorization(")
            .expect("Authorize dispatch");
        assert!(verify_start < retain);
        assert!(retain < authorize);
    }

    #[test]
    fn native_authorization_runtime_preserves_relay_exit_relay_ownership() {
        let source = include_str!("discovery.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("production/test boundary")
            .0;
        let datapath_handler = braced_item(production, "async fn handle_datapath_event(");
        assert!(datapath_handler.contains("DatapathRelayOperation::NativeProbeAuthorize"));
        assert!(datapath_handler.contains("self.begin_native_probe_start_authorization("));

        let relay_dispatch = braced_item(production, "fn begin_native_probe_authorization(");
        for required in [
            "prepared_native_authorizations.remove(&request_id)",
            "prepared.authenticated_client_peer != authenticated_client_peer",
            "prepared.start.encoded_start() != request.client_signed_request()",
            "ExitForwardOperation::NativeProbeAuthorize",
            ".request_exit_forward_upstream(&exit_peer, upstream.into())",
            "native_authorization: Some(PendingNativeProbeAuthorization",
        ] {
            assert!(relay_dispatch.contains(required), "missing {required}");
        }
        assert!(!relay_dispatch.contains("request_datapath_relay(&exit_peer"));

        let exit_prepare = braced_item(
            production,
            "async fn prepare_native_probe_authorization_response(",
        );
        let connection_bind = exit_prepare
            .find(".bind_native_probe_data_relay_connection(")
            .expect("exact inbound data Relay connection bind");
        let exit_issue = exit_prepare
            .find(".issue_native_probe_relay_authorization_with(")
            .expect("standard Exit authorization issue");
        assert!(connection_bind < exit_issue);
        assert!(exit_prepare.contains("native_probe_data_relay_capability_matches("));
        assert!(exit_prepare.contains(".activate_lease_batch("));
        assert!(exit_prepare.contains(".await"));

        let relay_complete = braced_item(production, "async fn complete_relay_forward(");
        let relay_accept = relay_complete
            .find(".accept_native_probe_start_with(")
            .expect("standard nested Relay reservation");
        let client_reply = relay_complete[relay_accept..]
            .find(".send_datapath_relay_response(native.channel, response)")
            .map(|offset| relay_accept + offset)
            .expect("direct response to authenticated Client hop after Relay acceptance");
        assert!(relay_accept < client_reply);
    }

    async fn ingest_direct_snapshot_advertisement(
        fixture: &mut RuntimeFixture,
        identity: &Identity,
        roles: RolesConfig,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
    ) -> Option<AcceptedAdvertisement> {
        ingest_direct_snapshot_advertisement_with_capabilities(
            fixture,
            identity,
            roles,
            sequence_number,
            nonce,
            now_ms,
            PreselectionTestCapabilities::default(),
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test fixture preserves the signed advertisement inputs explicitly"
    )]
    async fn ingest_direct_snapshot_advertisement_with_capabilities(
        fixture: &mut RuntimeFixture,
        identity: &Identity,
        roles: RolesConfig,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
        advertised: PreselectionTestCapabilities,
    ) -> Option<AcceptedAdvertisement> {
        let peer = identity.peer_id().to_owned();
        let advertisement = service_advertisement_with_capabilities(
            identity,
            roles,
            &fixture.policy,
            sequence_number,
            nonce,
            now_ms,
            &fixture.directory,
            advertised,
        );
        fixture
            .runtime
            .ingest_advertisement(
                peer,
                advertisement,
                AdvertisementProvenance::DirectRelay {
                    authenticated_peer: peer,
                },
                &fixture.state,
            )
            .await
    }

    async fn ingest_forwarded_snapshot_exit(
        fixture: &mut RuntimeFixture,
        control: &DirectRelayCapability,
        exit: &Identity,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
    ) -> Option<AcceptedAdvertisement> {
        ingest_forwarded_snapshot_exit_with_capabilities(
            fixture,
            control,
            exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            sequence_number,
            nonce,
            now_ms,
            PreselectionTestCapabilities::default(),
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test fixture preserves the signed advertisement inputs explicitly"
    )]
    async fn ingest_forwarded_snapshot_exit_with_capabilities(
        fixture: &mut RuntimeFixture,
        control: &DirectRelayCapability,
        exit: &Identity,
        roles: RolesConfig,
        sequence_number: u64,
        nonce: [u8; 32],
        now_ms: u64,
        advertised: PreselectionTestCapabilities,
    ) -> Option<AcceptedAdvertisement> {
        let deadline = now_ms.saturating_add(20_000);
        let exit_peer = exit.peer_id().to_owned();
        fixture
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let advertisement = service_advertisement_with_capabilities(
            exit,
            roles,
            &fixture.policy,
            sequence_number,
            nonce,
            now_ms,
            &fixture.directory,
            advertised,
        );
        fixture
            .runtime
            .ingest_advertisement(
                exit_peer,
                advertisement,
                forwarded_provenance(control, exit, deadline),
                &fixture.state,
            )
            .await
    }

    async fn route_snapshot_at(
        fixture: &mut RuntimeFixture,
        requested_candidates: usize,
        now_ms: u64,
    ) -> Result<RouteCandidateSnapshot, RouteCandidateSnapshotError> {
        fixture.runtime.purge_completed_at(now_ms);
        let policy = fixture.state.read().await.policy_snapshot(now_ms);
        fixture
            .runtime
            .build_route_candidate_snapshot(requested_candidates, now_ms, &policy)
    }

    pub(super) struct PreselectionSnapshotFixture {
        pub(super) snapshot: RouteCandidateSnapshot,
        pub(super) signers: Vec<Identity>,
        pub(super) advertisement_payload_hashes: BTreeMap<[u8; 32], [u8; 32]>,
        pub(super) now_ms: u64,
    }

    pub(super) async fn preselection_snapshot_fixture(
        other_relays: usize,
        dual_role_subjects: bool,
    ) -> PreselectionSnapshotFixture {
        preselection_snapshot_fixture_with_capabilities(
            other_relays,
            dual_role_subjects,
            PreselectionTestCapabilities::default(),
        )
        .await
    }

    pub(super) async fn preselection_snapshot_fixture_with_capabilities(
        other_relays: usize,
        dual_role_subjects: bool,
        advertised: PreselectionTestCapabilities,
    ) -> PreselectionSnapshotFixture {
        assert!((1..=8).contains(&other_relays));
        let mut fixture = Box::new(fixture(test_client_roles()));
        let now_ms = unix_millis();
        let relay_roles = RolesConfig {
            client: false,
            relay: true,
            exit: dual_role_subjects,
        };
        let control = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement_with_capabilities(
                &mut fixture,
                &control,
                relay_roles,
                1,
                generate_nonce(),
                now_ms,
                advertised,
            )
            .await
            .is_some()
        );
        let control_capability = fixture
            .runtime
            .direct_relays
            .get(control.peer_id())
            .expect("preselection control capability")
            .clone();
        let exit = Identity::generate();
        assert!(
            ingest_forwarded_snapshot_exit_with_capabilities(
                &mut fixture,
                &control_capability,
                &exit,
                RolesConfig {
                    client: false,
                    relay: dual_role_subjects,
                    exit: true,
                },
                1,
                generate_nonce(),
                now_ms,
                advertised,
            )
            .await
            .is_some()
        );
        let mut signers = vec![control, exit];
        for offset in 0..other_relays {
            let relay = Identity::generate();
            assert!(
                ingest_direct_snapshot_advertisement_with_capabilities(
                    &mut fixture,
                    &relay,
                    relay_roles,
                    1,
                    [193_u8.wrapping_add(u8::try_from(offset).expect("bounded relay count")); 32],
                    now_ms,
                    advertised,
                )
                .await
                .is_some()
            );
            signers.push(relay);
        }
        let snapshot = route_snapshot_at(&mut fixture, other_relays + 2, now_ms)
            .await
            .expect("fresh preselection snapshot");
        assert_eq!(snapshot.direct_relays().len(), other_relays + 1);
        assert_eq!(snapshot.forwarded_exits().len(), 1);
        let advertisement_payload_hashes = fixture
            .runtime
            .store
            .load_candidates(UnixTime::from_secs(now_ms / 1_000), 10)
            .expect("persisted preselection advertisements")
            .into_iter()
            .map(|stored| {
                let envelope = decode_canonical::<SignedEnvelope>(
                    stored.signed_advertisement_envelope(),
                    volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
                )
                .expect("canonical persisted preselection envelope");
                (
                    fixed_bytes::<32>(&envelope.sender_public_key)
                        .expect("persisted sender public key"),
                    fixed_bytes::<32>(&envelope.payload_hash)
                        .expect("persisted advertisement payload hash"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(advertisement_payload_hashes.len(), other_relays + 2);
        PreselectionSnapshotFixture {
            snapshot,
            signers,
            advertisement_payload_hashes,
            now_ms,
        }
    }

    pub(super) async fn preselection_multi_exit_snapshot_fixture(
        exits: usize,
        other_relays: usize,
        duplicate_relay_hint_clusters: Option<usize>,
        advertised: PreselectionTestCapabilities,
    ) -> RouteCandidateSnapshot {
        assert!((2..=8).contains(&exits));
        assert!((1..=32).contains(&other_relays));
        assert!(
            duplicate_relay_hint_clusters.is_none_or(|clusters| {
                (1..=other_relays).contains(&clusters) && clusters <= 32
            })
        );
        let mut fixture = Box::new(fixture(test_client_roles()));
        let now_ms = unix_millis();
        let relay_roles = RolesConfig {
            client: false,
            relay: true,
            exit: false,
        };
        for offset in 0..exits {
            let control = Identity::generate();
            let control_nonce = 32_u8
                .checked_add(u8::try_from(offset.saturating_mul(2)).expect("bounded exit offset"))
                .expect("bounded control nonce");
            assert!(
                ingest_direct_snapshot_advertisement_with_capabilities(
                    &mut fixture,
                    &control,
                    relay_roles,
                    1,
                    [control_nonce; 32],
                    now_ms,
                    advertised,
                )
                .await
                .is_some()
            );
            let control_capability = fixture
                .runtime
                .direct_relays
                .get(control.peer_id())
                .expect("multi-exit control capability")
                .clone();
            let exit = Identity::generate();
            assert!(
                ingest_forwarded_snapshot_exit_with_capabilities(
                    &mut fixture,
                    &control_capability,
                    &exit,
                    RolesConfig {
                        client: false,
                        relay: false,
                        exit: true,
                    },
                    1,
                    [control_nonce + 1; 32],
                    now_ms,
                    advertised,
                )
                .await
                .is_some()
            );
        }
        for offset in 0..other_relays {
            let relay = Identity::generate();
            let cluster =
                duplicate_relay_hint_clusters.map_or(offset, |clusters| offset % clusters);
            let nonce = 96_u8
                .checked_add(u8::try_from(cluster).expect("bounded relay cluster"))
                .expect("bounded relay nonce");
            assert!(
                ingest_direct_snapshot_advertisement_with_capabilities(
                    &mut fixture,
                    &relay,
                    relay_roles,
                    1,
                    [nonce; 32],
                    now_ms,
                    advertised,
                )
                .await
                .is_some()
            );
        }
        let snapshot = route_snapshot_at(
            &mut fixture,
            exits.saturating_mul(2).saturating_add(other_relays),
            now_ms,
        )
        .await
        .expect("multi-exit preselection snapshot");
        assert_eq!(snapshot.forwarded_exits().len(), exits);
        assert_eq!(snapshot.direct_relays().len(), exits + other_relays);
        snapshot
    }

    fn assert_exact_persisted_snapshot_time(
        fixture: &RuntimeFixture,
        exact: &DirectRelayCandidateSnapshot,
        peer: &Libp2pPeerId,
    ) {
        let peer_text = peer.to_string();
        let stored = fixture
            .runtime
            .store
            .load_candidates(UnixTime::from_secs(unix_seconds()), 10)
            .expect("stored committed advertisement")
            .into_iter()
            .find(|candidate| candidate.advertisement.peer_id.as_str() == peer_text)
            .expect("exact stored peer");
        let envelope = decode_canonical::<SignedEnvelope>(
            stored.signed_advertisement_envelope(),
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("canonical stored envelope");
        assert_eq!(
            exact.advertisement().signed_measured_at_ms(),
            envelope.timestamp_ms
        );
    }

    fn forwarded_provenance(
        control: &DirectRelayCapability,
        exit_identity: &Identity,
        request_deadline_ms: u64,
    ) -> AdvertisementProvenance {
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        AdvertisementProvenance::ForwardedExit {
            control_relay_node_id: control.node_id,
            control_relay_peer: control.peer_id,
            exit_node_id: node_id_from_public_key(&exit_public_key),
            exit_peer: exit_identity.peer_id().to_owned(),
            request_deadline_ms,
            authority: Box::new(ForwardedIngestAuthority {
                authorized_control: control.clone(),
                attempt_deadline: rpc_deadline(request_deadline_ms, EXIT_FORWARD_REQUEST_TIMEOUT),
                operation_expires_at_ms: request_deadline_ms,
            }),
        }
    }

    fn accepted_for_identity(
        identity: &Identity,
        policy: &VerifiedManifest,
        sequence_number: u64,
        advertisement_expires_at_ms: u64,
    ) -> AcceptedAdvertisement {
        let public_key = identity.ed25519_public_key_bytes().expect("public key");
        AcceptedAdvertisement {
            node_id: node_id_from_public_key(&public_key),
            peer_id: identity.peer_id().to_owned(),
            public_key,
            sequence_number,
            advertisement_expires_at_ms,
            policy_version: policy.manifest_version(),
            policy_hash: *policy.policy_hash(),
            policy_expires_at_ms: policy.expires_at_ms(),
            expires_at_ms: advertisement_expires_at_ms.min(policy.expires_at_ms()),
        }
    }

    fn forwarded_capability_for_identity(
        control: &DirectRelayCapability,
        exit: &Identity,
        advertisement_sequence: u64,
        advertisement_expires_at_ms: u64,
    ) -> ForwardedExitCapability {
        let exit_public_key = exit.ed25519_public_key_bytes().expect("exit public key");
        ForwardedExitCapability {
            control_relay_node_id: control.node_id,
            control_relay_peer_id: control.peer_id,
            control_relay_public_key: control.public_key,
            control_relay_advertisement_sequence: control.advertisement_sequence,
            control_relay_advertisement_expires_at_ms: control.advertisement_expires_at_ms,
            control_relay_advertisement_payload_hash: control.advertisement_payload_hash,
            exit_node_id: node_id_from_public_key(&exit_public_key),
            exit_peer_id: exit.peer_id().to_owned(),
            exit_public_key,
            exit_advertisement_sequence: advertisement_sequence,
            exit_advertisement_expires_at_ms: advertisement_expires_at_ms,
            exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(
                node_id_from_public_key(&exit_public_key),
            ),
            policy_version: control.policy_version,
            policy_hash: control.policy_hash,
            policy_expires_at_ms: control.policy_expires_at_ms,
            expires_at_ms: advertisement_expires_at_ms.min(control.expires_at_ms),
        }
    }

    struct SignedProbeDatapathFixture {
        wrapper: DatapathRelayRequest,
        request: RelayProbePermitRequest,
        signed_request: Vec<u8>,
        signed_permit: Vec<u8>,
        control_public_key: [u8; 32],
    }

    fn sign_with_identity<T: ControlPayload>(
        message: &T,
        identity: &Identity,
        created_at_ms: u64,
        expires_at_ms: u64,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let public_key = identity
            .ed25519_public_key_bytes()
            .expect("Ed25519 public key");
        sign_control_message_with(
            message,
            public_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
            |bytes| identity.sign(bytes).ok(),
        )
        .expect("signed control message")
    }

    fn signed_probe_datapath_fixture(now_ms: u64) -> SignedProbeDatapathFixture {
        let relay = Identity::generate();
        let relay_public_key = relay.ed25519_public_key_bytes().expect("relay public key");
        signed_probe_datapath_fixture_for_relay(
            now_ms,
            node_id_from_public_key(&relay_public_key),
            relay.peer_id().to_bytes(),
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one cryptographically consistent probe authorization graph"
    )]
    fn signed_probe_datapath_fixture_for_relay(
        now_ms: u64,
        relay_node_id: [u8; 32],
        relay_peer_id: Vec<u8>,
    ) -> SignedProbeDatapathFixture {
        let exit = Identity::generate();
        let client = Identity::generate();
        let control = Identity::generate();
        let exit_public_key = exit.ed25519_public_key_bytes().expect("exit public key");
        let client_public_key = client
            .ed25519_public_key_bytes()
            .expect("client public key");
        let control_public_key = control
            .ed25519_public_key_bytes()
            .expect("control public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let client_session_id = node_id_from_public_key(&client_public_key);
        let control_node_id = node_id_from_public_key(&control_public_key);
        let exit_peer_id = exit.peer_id().to_bytes();
        let control_peer_id = control.peer_id().to_bytes();
        let capability_created_at_ms = now_ms.saturating_sub(100);
        let capability_expires_at_ms = now_ms.saturating_add(60_000);
        let hold_expires_at_ms = now_ms.saturating_add(25_000);
        let request_expires_at_ms = now_ms.saturating_add(20_000);
        let capability_nonce = generate_nonce();
        let capability = ClientSessionCapability {
            capability_id: vec![1; 16],
            reservation_id: vec![2; 16],
            route_context_id: vec![3; 16],
            client_session_id: client_session_id.to_vec(),
            client_session_public_key: client_public_key.to_vec(),
            exit_node_id: exit_node_id.to_vec(),
            exit_boot_id: vec![4; 16],
            control_relay_node_id: control_node_id.to_vec(),
            control_relay_peer_id: control_peer_id.clone(),
            policy_hash: vec![5; 32],
            allowed_transports: vec![Transport::UdpSinglePath as i32],
            reserved_up_mbps: 10,
            reserved_down_mbps: 10,
            maximum_paths: 1,
            probe_permit_limit: 1,
            created_at_ms: capability_created_at_ms,
            expires_at_ms: capability_expires_at_ms,
            nonce: capability_nonce.to_vec(),
            exit_peer_id: exit_peer_id.clone(),
        };
        let signed_capability = sign_with_identity(
            &capability,
            &exit,
            capability.created_at_ms,
            capability.expires_at_ms,
            capability_nonce,
        );
        let hold_nonce = generate_nonce();
        let hold = ExitCapacityHold {
            hold_id: vec![6; 16],
            client_session_capability: signed_capability.clone(),
            reservation_id: capability.reservation_id.clone(),
            route_context_id: capability.route_context_id.clone(),
            exit_node_id: capability.exit_node_id.clone(),
            exit_boot_id: capability.exit_boot_id.clone(),
            client_session_id: capability.client_session_id.clone(),
            policy_hash: capability.policy_hash.clone(),
            allowed_transports: capability.allowed_transports.clone(),
            reserved_up_mbps: capability.reserved_up_mbps,
            reserved_down_mbps: capability.reserved_down_mbps,
            maximum_paths: capability.maximum_paths,
            probe_permit_limit: capability.probe_permit_limit,
            created_at_ms: capability.created_at_ms,
            expires_at_ms: hold_expires_at_ms,
            nonce: hold_nonce.to_vec(),
            exit_peer_id: capability.exit_peer_id.clone(),
            control_relay_node_id: capability.control_relay_node_id.clone(),
            control_relay_peer_id: capability.control_relay_peer_id.clone(),
            reservation_expires_at_ms: capability.expires_at_ms,
        };
        let signed_hold = sign_with_identity(
            &hold,
            &exit,
            hold.created_at_ms,
            hold.expires_at_ms,
            hold_nonce,
        );
        let request_nonce = generate_nonce();
        let request = RelayProbePermitRequest {
            probe_id: vec![7; 16],
            exit_capacity_hold: signed_hold,
            client_session_capability: signed_capability,
            path_id: 1,
            relay_node_id: relay_node_id.to_vec(),
            relay_peer_id: relay_peer_id.clone(),
            client_session_id: capability.client_session_id.clone(),
            control_relay_node_id: capability.control_relay_node_id.clone(),
            control_relay_peer_id: capability.control_relay_peer_id.clone(),
            created_at_ms: now_ms,
            expires_at_ms: request_expires_at_ms,
            nonce: request_nonce.to_vec(),
            exit_node_id: capability.exit_node_id.clone(),
            exit_peer_id: capability.exit_peer_id.clone(),
            transport: Transport::UdpSinglePath as i32,
            address_family: ProbeAddressFamily::Ipv4 as i32,
        };
        let signed_request = sign_with_identity(
            &request,
            &client,
            request.created_at_ms,
            request.expires_at_ms,
            request_nonce,
        );
        let permit_nonce = generate_nonce();
        let permit = RelayProbePermit {
            probe_id: request.probe_id.clone(),
            hold_id: hold.hold_id,
            capability_id: capability.capability_id,
            reservation_id: capability.reservation_id,
            route_context_id: capability.route_context_id,
            client_session_id: capability.client_session_id,
            exit_node_id: capability.exit_node_id,
            exit_boot_id: capability.exit_boot_id,
            control_relay_node_id: capability.control_relay_node_id,
            control_relay_peer_id: capability.control_relay_peer_id,
            relay_node_id: request.relay_node_id.clone(),
            relay_peer_id: request.relay_peer_id.clone(),
            path_id: request.path_id,
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
            nonce: permit_nonce.to_vec(),
            exit_peer_id: capability.exit_peer_id,
            policy_hash: capability.policy_hash,
            transport: request.transport,
            address_family: request.address_family,
        };
        let signed_permit = sign_with_identity(
            &permit,
            &exit,
            permit.created_at_ms,
            permit.expires_at_ms,
            permit_nonce,
        );
        let wrapper = DatapathRelayRequest::new(
            request_nonce[..FORWARD_ID_BYTES].to_vec(),
            relay_node_id.to_vec(),
            relay_peer_id,
            request_expires_at_ms,
            DatapathRelayOperation::ExecuteProbe,
            signed_request.clone(),
            signed_permit.clone(),
        )
        .expect("valid ExecuteProbe wrapper");
        SignedProbeDatapathFixture {
            wrapper,
            request,
            signed_request,
            signed_permit,
            control_public_key,
        }
    }

    #[tokio::test]
    async fn service_roles_publish_current_signed_advertisement_and_provider() {
        let roles = RolesConfig {
            client: true,
            relay: true,
            exit: false,
        };
        let mut fixture = fixture(roles);
        let now_ms = unix_millis();
        fixture.runtime.control_addresses =
            BTreeSet::from(["/ip4/44.160.1.8/tcp/42100".to_owned()]);
        fixture.runtime.publish_local(&fixture.state).await;

        let encoded = fixture
            .runtime
            .served_local_advertisement
            .as_ref()
            .expect("served service advertisement");
        let mut replay = ReplayCache::new(1).expect("replay cache");
        let verified = verify_control_message::<WireAdvertisement>(
            encoded,
            now_ms.saturating_add(1),
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified service advertisement");
        let message = verified.message();
        assert!(
            message
                .roles
                .as_ref()
                .is_some_and(|advertised| advertised.relay)
        );
        assert!(message.capabilities.as_ref().is_some_and(|capabilities| {
            capabilities.ipv4
                && capabilities.tcp_mptcp
                && capabilities.udp_single_path
                && capabilities.multipath_quic
        }));
        assert_eq!(
            message
                .capacity
                .as_ref()
                .map(|capacity| capacity.free_relay_slots),
            Some(4)
        );
        assert!(fixture.runtime.service.is_serving_local_advertisement());
        assert!(
            fixture
                .runtime
                .active_provider_keys
                .contains(capability::RELAY)
        );
    }

    #[tokio::test]
    async fn role_changes_require_restart_without_mutation_or_persistence() {
        let expected = test_client_roles();
        let mut fixture = fixture(expected);
        let persisted_before =
            fs::read(fixture.directory.path().join("roles.json")).expect("initial persisted roles");
        assert_eq!(
            fixture
                .runtime
                .apply_roles(expected, expected, &fixture.state)
                .await,
            Ok(expected)
        );
        let candidate = RolesConfig {
            client: true,
            relay: true,
            exit: false,
        };
        assert_eq!(
            fixture
                .runtime
                .apply_roles(expected, candidate, &fixture.state)
                .await,
            Err(RoleApplyError::RestartRequired)
        );
        assert_eq!(fixture.runtime.roles, expected);
        assert_eq!(fixture.state.read().await.roles(), expected);
        assert_eq!(
            fs::read(fixture.directory.path().join("roles.json"))
                .expect("unchanged persisted roles"),
            persisted_before
        );
    }

    #[tokio::test]
    async fn fetch_wrapper_deadline_is_bounded_to_thirty_seconds() {
        let fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let now_ms = unix_millis();
        let control = direct_capability(
            &control_identity,
            &fixture.policy,
            1,
            now_ms.saturating_add(60_000),
        );
        let valid = fetch_request(
            &control,
            exit_identity.peer_id().to_owned(),
            [1; FORWARD_ID_BYTES],
            now_ms.saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS),
        );
        let too_long = fetch_request(
            &control,
            exit_identity.peer_id().to_owned(),
            [2; FORWARD_ID_BYTES],
            now_ms
                .saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
                .saturating_add(1),
        );
        assert!(forward_request_scope_matches(
            &valid,
            ExitForwardOperation::FetchExitAdvertisement,
            now_ms
        ));
        assert!(!forward_request_scope_matches(
            &too_long,
            ExitForwardOperation::FetchExitAdvertisement,
            now_ms
        ));
    }

    #[tokio::test]
    async fn ambiguous_automatic_exit_fetch_retries_exact_lineage_after_short_backoff() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_peer = Identity::generate().peer_id().to_owned();
        let now_ms = unix_millis();
        let deadline_unix_ms = now_ms.saturating_add(25_000);
        let forward_id = [73; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline_unix_ms,
        );
        let alternate_control = install_control(&mut fixture, &Identity::generate(), now_ms);
        let key = ForwardedExitKey {
            control_relay_peer: control.peer_id,
            exit_peer,
        };
        let (reply, receiver) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request.clone(), reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("initial automatic dispatch");
        fixture
            .runtime
            .automatic_exit_fetches
            .insert(key, deadline_unix_ms);
        fixture
            .runtime
            .automatic_exit_fetch_attempts
            .push(AutomaticExitFetchAttempt {
                key,
                authorized_control: control.clone(),
                request: request.clone(),
                dispatch_attempts: 1,
                state: AutomaticExitFetchAttemptState::InFlight(receiver),
            });
        assert_eq!(
            fixture
                .runtime
                .fail_client_forward(request_id, control.peer_id),
            OutboundEventOutcome::Failed
        );

        fixture.runtime.drive_automatic_exit_fetch_attempts(now_ms);

        let retry_at_ms = now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_RETRY_BACKOFF_MS);
        assert_eq!(
            fixture.runtime.automatic_exit_fetches.get(&key).copied(),
            Some(retry_at_ms)
        );
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert_eq!(fixture.runtime.automatic_exit_fetch_attempts.len(), 1);
        assert!(matches!(
            fixture.runtime.automatic_exit_fetch_attempts[0].state,
            AutomaticExitFetchAttemptState::RetryNotBefore(value) if value == retry_at_ms
        ));
        fixture.runtime.schedule_exit_advertisement_fetches();
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert!(
            fixture
                .runtime
                .automatic_exit_fetch_attempts
                .iter()
                .all(|attempt| attempt.key.control_relay_peer != alternate_control.peer_id)
        );

        fixture
            .runtime
            .drive_automatic_exit_fetch_attempts(retry_at_ms);

        let logical_key = ClientForwardKey {
            control_relay_peer: control.peer_id,
            forward_id,
        };
        assert!(
            fixture
                .runtime
                .client_forward_index
                .contains_key(&logical_key)
        );
        assert!(
            !fixture
                .runtime
                .retry_client_forwards
                .contains_key(&logical_key)
        );
        assert_eq!(fixture.runtime.pending_client_forwards.len(), 1);
        assert_eq!(fixture.runtime.automatic_exit_fetch_attempts.len(), 1);
        let attempt = &fixture.runtime.automatic_exit_fetch_attempts[0];
        assert_eq!(attempt.key, key);
        assert_eq!(attempt.request, request);
        assert_eq!(attempt.dispatch_attempts, 2);
        assert!(matches!(
            attempt.state,
            AutomaticExitFetchAttemptState::InFlight(_)
        ));
    }

    #[tokio::test]
    async fn exhausted_automatic_exit_fetch_lineages_rotate_to_an_untried_control() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let deadline_unix_ms = now_ms.saturating_add(25_000);
        let exit_peer = Identity::generate().peer_id().to_owned();
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, deadline_unix_ms);

        let mut controls = (1_u64..=3)
            .map(|sequence| {
                direct_capability(
                    &Identity::generate(),
                    &fixture.policy,
                    sequence,
                    now_ms.saturating_add(60_000),
                )
            })
            .collect::<Vec<_>>();
        controls.sort_by(|left, right| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()));
        for control in &controls {
            fixture
                .runtime
                .direct_relays
                .insert(control.peer_id, control.clone());
        }

        for control in &controls[..2] {
            fixture.runtime.automatic_exit_fetches.insert(
                ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                },
                deadline_unix_ms,
            );
        }

        fixture.runtime.schedule_exit_advertisement_fetches();

        assert_eq!(fixture.runtime.automatic_exit_fetch_attempts.len(), 1);
        assert_eq!(
            fixture.runtime.automatic_exit_fetch_attempts[0].key,
            ForwardedExitKey {
                control_relay_peer: controls[2].peer_id,
                exit_peer,
            }
        );
        assert_eq!(fixture.runtime.pending_client_forwards.len(), 1);
        assert!(
            fixture
                .runtime
                .pending_client_forwards
                .values()
                .all(|pending| {
                    pending.key.control_relay_peer == controls[2].peer_id
                        && pending.expected_exit_peer == exit_peer
                        && pending.operation == ExitForwardOperation::FetchExitAdvertisement
                })
        );
    }

    #[tokio::test]
    async fn exhausted_scale_controls_rotate_then_retry_inside_provider_lifetime() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let provider_expires_at_ms = now_ms.saturating_add(PROVIDER_OBSERVATION_TTL_MS);
        let request_deadline_ms = now_ms.saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS);
        let exit_peer = Identity::generate().peer_id().to_owned();
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, provider_expires_at_ms);

        let mut controls = (1_u64..=6)
            .map(|sequence| {
                direct_capability(
                    &Identity::generate(),
                    &fixture.policy,
                    sequence,
                    provider_expires_at_ms,
                )
            })
            .collect::<Vec<_>>();
        controls.sort_by(|left, right| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()));
        for control in &controls {
            fixture
                .runtime
                .direct_relays
                .insert(control.peer_id, control.clone());
        }

        for (index, control) in controls[..5].iter().enumerate() {
            let key = ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            };
            let request = fetch_request(
                control,
                exit_peer,
                [u8::try_from(index + 1).expect("bounded index"); FORWARD_ID_BYTES],
                request_deadline_ms,
            );
            let (reply, receiver) = oneshot::channel();
            drop(reply);
            fixture
                .runtime
                .automatic_exit_fetches
                .insert(key, request_deadline_ms);
            fixture
                .runtime
                .automatic_exit_fetch_attempts
                .push(AutomaticExitFetchAttempt {
                    key,
                    authorized_control: control.clone(),
                    request,
                    dispatch_attempts: MAX_DISPATCH_ATTEMPTS,
                    state: AutomaticExitFetchAttemptState::InFlight(receiver),
                });

            fixture.runtime.drive_automatic_exit_fetch_attempts(now_ms);

            assert_eq!(
                fixture.runtime.automatic_exit_fetches.get(&key),
                Some(&now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_EXHAUSTED_COOLDOWN_MS))
            );
            assert!(fixture.runtime.automatic_exit_fetch_attempts.is_empty());
        }

        fixture.runtime.schedule_exit_advertisement_fetches();

        assert_eq!(fixture.runtime.automatic_exit_fetch_attempts.len(), 1);
        assert_eq!(
            fixture.runtime.automatic_exit_fetch_attempts[0]
                .key
                .control_relay_peer,
            controls[5].peer_id
        );
    }

    #[tokio::test]
    async fn all_exhausted_exit_fetch_controls_have_a_bounded_quiet_period() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let provider_expires_at_ms = now_ms.saturating_add(PROVIDER_OBSERVATION_TTL_MS);
        let exit_peer = Identity::generate().peer_id().to_owned();
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, provider_expires_at_ms);

        let mut controls = (1_u64..=6)
            .map(|sequence| {
                direct_capability(
                    &Identity::generate(),
                    &fixture.policy,
                    sequence,
                    provider_expires_at_ms,
                )
            })
            .collect::<Vec<_>>();
        controls.sort_by(|left, right| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()));
        for control in &controls {
            fixture
                .runtime
                .direct_relays
                .insert(control.peer_id, control.clone());
            fixture.runtime.retain_exhausted_exit_fetch_control(
                ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                },
                now_ms,
            );
        }

        let retry_at_ms = now_ms.saturating_add(AUTOMATIC_EXIT_FETCH_EXHAUSTED_COOLDOWN_MS);
        assert!(
            fixture
                .runtime
                .next_untried_exit_control(&controls, exit_peer, retry_at_ms.saturating_sub(1))
                .is_none()
        );
        let first_retry = fixture
            .runtime
            .next_untried_exit_control(&controls, exit_peer, retry_at_ms)
            .expect("oldest exhausted control becomes retryable");
        assert_eq!(first_retry.peer_id, controls[0].peer_id);
        fixture.runtime.retain_exhausted_exit_fetch_control(
            ForwardedExitKey {
                control_relay_peer: first_retry.peer_id,
                exit_peer,
            },
            retry_at_ms,
        );
        let second_retry = fixture
            .runtime
            .next_untried_exit_control(&controls, exit_peer, retry_at_ms)
            .expect("rotation advances while first control cools down");
        assert_eq!(second_retry.peer_id, controls[1].peer_id);
    }

    #[tokio::test]
    async fn automatic_exit_fetch_stops_after_one_control_binds_the_exit() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let exit = Identity::generate();
        let exit_peer = exit.peer_id().to_owned();
        let first_control = install_control(&mut fixture, &Identity::generate(), now_ms);
        let _second_control = install_control(&mut fixture, &Identity::generate(), now_ms);
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, now_ms.saturating_add(25_000));
        fixture.runtime.forwarded_exits.insert(
            ForwardedExitKey {
                control_relay_peer: first_control.peer_id,
                exit_peer,
            },
            forwarded_capability_for_identity(
                &first_control,
                &exit,
                1,
                now_ms.saturating_add(25_000),
            ),
        );

        fixture.runtime.schedule_exit_advertisement_fetches();

        assert!(fixture.runtime.automatic_exit_fetch_attempts.is_empty());
        assert!(fixture.runtime.pending_client_forwards.is_empty());
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps all three control replacements and invalidation together"
    )]
    async fn automatic_exit_fetch_keeps_current_control_until_it_is_invalid() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(25_000);
        let exit = Identity::generate();
        let exit_peer = exit.peer_id().to_owned();
        let mut controls = (1_u64..=3)
            .map(|sequence| {
                direct_capability(
                    &Identity::generate(),
                    &fixture.policy,
                    sequence,
                    now_ms.saturating_add(60_000),
                )
            })
            .collect::<Vec<_>>();
        controls.sort_by(|left, right| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()));
        for control in &controls {
            fixture
                .runtime
                .direct_relays
                .insert(control.peer_id, control.clone());
        }
        let preferred = controls[2].clone();
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, deadline);
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(exit_peer, deadline)
        );
        let advertisement = service_advertisement(
            &exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement.clone(),
                    forwarded_provenance(&preferred, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );
        assert_eq!(
            fixture.runtime.preferred_exit_controls.get(&exit_peer),
            Some(&preferred.peer_id)
        );

        let alternate = controls[0].clone();
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement,
                    forwarded_provenance(&alternate, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );
        assert_eq!(
            fixture.runtime.preferred_exit_controls.get(&exit_peer),
            Some(&preferred.peer_id)
        );

        // Simulate expiry of only the request-bounded local forwarding capability. The hint is
        // non-authoritative, but a still-current fetch suppression must not rotate the Exit onto
        // another control lineage while the preferred Relay itself remains current.
        fixture.runtime.forwarded_exits.clear();
        let preferred_key = ForwardedExitKey {
            control_relay_peer: preferred.peer_id,
            exit_peer,
        };
        fixture
            .runtime
            .automatic_exit_fetches
            .insert(preferred_key, deadline);
        fixture.runtime.schedule_exit_advertisement_fetches();
        assert!(fixture.runtime.automatic_exit_fetch_attempts.is_empty());

        // Once that exact suppression expires, scheduling refreshes the same current control.
        fixture
            .runtime
            .automatic_exit_fetches
            .insert(preferred_key, now_ms);
        fixture.runtime.schedule_exit_advertisement_fetches();

        assert_eq!(fixture.runtime.automatic_exit_fetch_attempts.len(), 1);
        assert_eq!(
            fixture.runtime.automatic_exit_fetch_attempts[0].key,
            ForwardedExitKey {
                control_relay_peer: preferred.peer_id,
                exit_peer,
            }
        );
    }

    #[tokio::test]
    async fn forwarded_exit_capability_outlives_completed_fetch_operation() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let now_ms = unix_millis();
        let request_deadline_ms = now_ms.saturating_add(20_000);
        let control = install_control(&mut fixture, &control_identity, now_ms);
        let accepted = ingest_forwarded_snapshot_exit(
            &mut fixture,
            &control,
            &exit_identity,
            1,
            generate_nonce(),
            now_ms,
        )
        .await
        .expect("forwarded Exit advertisement");
        let capability = fixture
            .runtime
            .forwarded_exits
            .get(&ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            })
            .expect("committed forwarded Exit capability");

        assert_eq!(
            capability.expires_at_ms,
            accepted.expires_at_ms.min(control.expires_at_ms)
        );
        assert!(capability.expires_at_ms > request_deadline_ms);
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end regression covers lineage projection and selectable recovery"
    )]
    async fn refreshed_control_lineage_keeps_forwarded_exit_selectable() {
        let mut fixture = fixture(test_client_roles());
        let initial_ms = unix_millis();
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let original_control = install_valid_snapshot_route_for(
            &mut fixture,
            &control_identity,
            &exit_identity,
            initial_ms,
        )
        .await;
        let other_relay = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &other_relay,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                initial_ms,
            )
            .await
            .is_some()
        );

        let refresh_ms = unix_millis();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &control_identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                2,
                generate_nonce(),
                refresh_ms,
            )
            .await
            .is_some()
        );
        let refreshed_control = fixture
            .runtime
            .direct_relays
            .get(control_identity.peer_id())
            .expect("refreshed direct control")
            .clone();
        assert_ne!(
            original_control.advertisement_payload_hash,
            refreshed_control.advertisement_payload_hash
        );
        assert!(fixture.runtime.forwarded_exits.values().any(|capability| {
            capability.control_relay_advertisement_payload_hash
                == original_control.advertisement_payload_hash
        }));
        let lineage_snapshot = route_snapshot_at(&mut fixture, 10, refresh_ms)
            .await
            .expect("live control lineage remains in the route snapshot");
        assert_eq!(lineage_snapshot.forwarded_exits().len(), 1);
        assert!(
            narrow_route_candidate_snapshot(
                lineage_snapshot,
                PreselectionSamplingScope::new(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    Bandwidth::new(10, 10).expect("minimum capacity"),
                    1,
                    1,
                ),
            )
            .is_ok(),
            "a newer signed control advertisement from the same identity and policy must not hide the Exit"
        );

        fixture.runtime.exit_provider_peers.insert(
            exit_peer,
            refresh_ms.saturating_add(PROVIDER_OBSERVATION_TTL_MS),
        );
        fixture.runtime.schedule_exit_advertisement_fetches();
        assert!(fixture.runtime.automatic_exit_fetch_attempts.is_empty());
        assert!(fixture.runtime.pending_client_forwards.is_empty());
    }

    #[tokio::test]
    async fn affine_forwarded_capability_survives_refresh_but_not_policy_change() {
        let fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let now_ms = unix_millis();
        let control = direct_capability(
            &control_identity,
            &fixture.policy,
            7,
            now_ms.saturating_add(40_000),
        );
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let exit_peer_id = exit_identity.peer_id().to_owned();
        let capability = ForwardedExitCapability {
            control_relay_node_id: control.node_id,
            control_relay_peer_id: control.peer_id,
            control_relay_public_key: control.public_key,
            control_relay_advertisement_sequence: control.advertisement_sequence,
            control_relay_advertisement_expires_at_ms: control.advertisement_expires_at_ms,
            control_relay_advertisement_payload_hash: control.advertisement_payload_hash,
            exit_node_id,
            exit_peer_id,
            exit_public_key,
            exit_advertisement_sequence: 11,
            exit_advertisement_expires_at_ms: now_ms.saturating_add(35_000),
            exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(exit_node_id),
            policy_version: control.policy_version,
            policy_hash: control.policy_hash,
            policy_expires_at_ms: control.policy_expires_at_ms,
            expires_at_ms: now_ms.saturating_add(20_000),
        };
        assert!(forwarded_exit_capability_matches(
            &capability,
            &control,
            control.node_id,
            control.peer_id,
            control.public_key,
            exit_node_id,
            exit_peer_id,
            now_ms.saturating_add(10_000),
        ));
        assert!(forwarded_control_projection_lineage_matches(
            &capability,
            &control,
            now_ms.saturating_add(10_000),
        ));
        let mut refreshed = control.clone();
        refreshed.advertisement_sequence = refreshed.advertisement_sequence.saturating_add(1);
        refreshed.advertisement_payload_hash = refreshed.advertisement_payload_hash.xor_for_test();
        assert!(forwarded_exit_capability_matches(
            &capability,
            &refreshed,
            refreshed.node_id,
            refreshed.peer_id,
            refreshed.public_key,
            exit_node_id,
            exit_peer_id,
            now_ms.saturating_add(10_000),
        ));
        assert!(forwarded_control_projection_lineage_matches(
            &capability,
            &refreshed,
            now_ms.saturating_add(10_000),
        ));
        let mut substituted_same_sequence = control.clone();
        substituted_same_sequence.advertisement_payload_hash = substituted_same_sequence
            .advertisement_payload_hash
            .xor_for_test();
        assert!(!forwarded_control_projection_lineage_matches(
            &capability,
            &substituted_same_sequence,
            now_ms.saturating_add(10_000),
        ));
        let mut rolled_back = control.clone();
        rolled_back.advertisement_sequence = rolled_back.advertisement_sequence.saturating_sub(1);
        assert!(!forwarded_control_projection_lineage_matches(
            &capability,
            &rolled_back,
            now_ms.saturating_add(10_000),
        ));
        let mut policy_changed = control.clone();
        policy_changed.policy_hash[0] ^= 1;
        assert!(!forwarded_exit_capability_matches(
            &capability,
            &policy_changed,
            policy_changed.node_id,
            policy_changed.peer_id,
            policy_changed.public_key,
            exit_node_id,
            exit_peer_id,
            now_ms.saturating_add(10_000),
        ));
        assert!(!forwarded_control_projection_lineage_matches(
            &capability,
            &policy_changed,
            now_ms.saturating_add(10_000),
        ));
    }

    #[tokio::test]
    async fn ledger_reserves_max_response_bytes_globally_and_per_peer() {
        let mut global = fixture(test_client_roles());
        let frame_bytes = usize::try_from(MAX_FORWARDING_FRAME_BYTES).expect("frame bound");
        let reserved = ledger_reservation_bytes(frame_bytes).expect("max-frame reservation");
        let expires_at_ms = unix_millis().saturating_add(20_000);
        let mut global_entries = 0_usize;
        loop {
            let peer = Identity::generate().peer_id().to_owned();
            if !global.runtime.ledger_can_reserve(peer, reserved) {
                break;
            }
            let mut forward_id = [0_u8; FORWARD_ID_BYTES];
            forward_id[..8].copy_from_slice(
                &u64::try_from(global_entries)
                    .expect("bounded entry count")
                    .to_be_bytes(),
            );
            global.runtime.completed_client_forwards.insert(
                ClientForwardKey {
                    control_relay_peer: peer,
                    forward_id,
                },
                CompletedClientForward {
                    canonical_request: vec![0; frame_bytes],
                    target_peer: peer,
                    operation: ExitForwardOperation::FetchExitAdvertisement,
                    outcome: Err(OutboundReservationError::Capacity),
                    expires_at_ms,
                    reserved_bytes: reserved,
                },
            );
            global_entries = global_entries.saturating_add(1);
        }
        assert!(global_entries > 0);
        assert!(global_entries < MAX_LEDGER_ENTRIES);
        assert!(global.runtime.ledger_reserved_bytes() <= MAX_LEDGER_BYTES);
        let fresh_peer = Identity::generate().peer_id().to_owned();
        assert!(!global.runtime.ledger_can_reserve(fresh_peer, reserved));

        let mut per_peer = fixture(test_client_roles());
        let peer = Identity::generate().peer_id().to_owned();
        let mut peer_entries = 0_usize;
        while per_peer.runtime.ledger_can_reserve(peer, reserved) {
            let mut forward_id = [0_u8; FORWARD_ID_BYTES];
            forward_id[..8].copy_from_slice(
                &u64::try_from(peer_entries)
                    .expect("bounded entry count")
                    .to_be_bytes(),
            );
            per_peer.runtime.completed_client_forwards.insert(
                ClientForwardKey {
                    control_relay_peer: peer,
                    forward_id,
                },
                CompletedClientForward {
                    canonical_request: vec![0; frame_bytes],
                    target_peer: peer,
                    operation: ExitForwardOperation::FetchExitAdvertisement,
                    outcome: Err(OutboundReservationError::Capacity),
                    expires_at_ms,
                    reserved_bytes: reserved,
                },
            );
            peer_entries = peer_entries.saturating_add(1);
        }
        assert!(peer_entries > 0);
        assert!(per_peer.runtime.ledger_reserved_bytes_for_peer(peer) <= MAX_LEDGER_BYTES_PER_PEER);
        assert!(!per_peer.runtime.ledger_can_reserve(peer, reserved));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one regression covers all three completed route-ledger families"
    )]
    #[tokio::test]
    async fn completed_route_ledgers_charge_only_bytes_they_retain() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let expires_at_ms = now_ms.saturating_add(20_000);
        let relay_identity = Identity::generate();
        let relay = direct_capability(&relay_identity, &fixture.policy, 1, expires_at_ms);
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let frame_limit = usize::try_from(MAX_FORWARDING_FRAME_BYTES).expect("frame bound");

        let client_request = vec![0x11; 97];
        let client_reserved = ledger_reservation_bytes(client_request.len()).expect("reservation");
        let client_key = ClientForwardKey {
            control_relay_peer: relay.peer_id,
            forward_id: [0x12; FORWARD_ID_BYTES],
        };
        let client_pending = PendingClientForward {
            key: client_key,
            expected_exit_peer: exit_peer,
            operation: ExitForwardOperation::FetchExitAdvertisement,
            expected_exit_node_id: Some(exit_node_id),
            authorized_control: relay.clone(),
            authorized_exit: None,
            canonical_request: client_request.clone(),
            operation_expires_at_ms: expires_at_ms,
            attempt_deadline: Instant::now() + Duration::from_secs(5),
            dispatch_attempts: 1,
            reserved_bytes: client_reserved,
            waiters: Vec::new(),
        };
        fixture.runtime.cache_client_result(
            &client_pending,
            Err(OutboundReservationError::InvalidResponse),
        );
        assert_eq!(
            fixture.runtime.completed_client_forwards[&client_key].reserved_bytes,
            client_request.len()
        );

        let datapath_request = vec![0x21; 113];
        let datapath_reserved =
            ledger_reservation_bytes(datapath_request.len()).expect("reservation");
        let datapath_key = DatapathKey {
            relay_peer: relay.peer_id,
            request_id: [0x22; FORWARD_ID_BYTES],
        };
        let datapath_pending = PendingDatapath {
            key: datapath_key,
            operation: DatapathRelayOperation::NativeProbeReady,
            relay_node_id: relay.node_id,
            authorized_relay: relay.clone(),
            canonical_request: datapath_request.clone(),
            operation_expires_at_ms: expires_at_ms,
            attempt_deadline: Instant::now() + Duration::from_secs(5),
            dispatch_attempts: 1,
            reserved_bytes: datapath_reserved,
            waiters: Vec::new(),
        };
        let datapath_response = DatapathRelayResponse::unavailable(
            datapath_key.request_id.to_vec(),
            DatapathRelayOperation::NativeProbeReady,
            relay.node_id.to_vec(),
            relay.peer_id.to_bytes(),
        )
        .expect("Unavailable datapath response");
        let datapath_response_bytes = encode_canonical(&datapath_response, frame_limit)
            .expect("canonical datapath response")
            .len();
        fixture
            .runtime
            .cache_datapath_result(&datapath_pending, Ok(datapath_response));
        assert_eq!(
            fixture.runtime.completed_datapath[&datapath_key].reserved_bytes,
            datapath_request.len() + datapath_response_bytes
        );

        let client_identity = Identity::generate();
        let relay_request = vec![0x31; 131];
        let relay_reserved = ledger_reservation_bytes(relay_request.len()).expect("reservation");
        let relay_key = RelayForwardKey {
            authenticated_client_peer: client_identity.peer_id().to_owned(),
            forward_id: [0x32; FORWARD_ID_BYTES],
        };
        let relay_pending = PendingRelayForward {
            key: relay_key,
            expected_exit_peer: exit_peer,
            operation: ExitForwardOperation::FetchExitAdvertisement,
            expected_exit_node_id: Some(exit_node_id),
            authorized_control: relay,
            authorized_exit: None,
            canonical_request: relay_request.clone(),
            operation_expires_at_ms: expires_at_ms,
            attempt_deadline: Instant::now() + Duration::from_secs(5),
            dispatch_attempts: 1,
            reserved_bytes: relay_reserved,
            client_channels: Vec::new(),
            native_ready: None,
            native_authorization: None,
            native_result: None,
            udp_session: None,
            mptcp_session: None,
            mpquic_session: None,
        };
        let relay_response = ExitForwardResponse::unavailable(
            relay_key.forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
        )
        .expect("Unavailable relay response");
        let relay_response_bytes = encode_canonical(&relay_response, frame_limit)
            .expect("canonical relay response")
            .len();
        fixture
            .runtime
            .cache_relay_result(&relay_pending, Some(relay_response));
        assert_eq!(
            fixture.runtime.completed_relay_forwards[&relay_key].reserved_bytes,
            relay_request.len() + relay_response_bytes
        );

        assert_eq!(
            completed_ledger_reservation_bytes(usize::MAX, 1, relay_reserved),
            relay_reserved,
            "overflow must retain the conservative pending reservation"
        );
    }

    #[tokio::test]
    async fn full_tombstone_ledger_returns_exact_cached_result_without_dispatch() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let deadline = unix_millis().saturating_add(20_000);
        let forward_id = [42; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline,
        );
        let canonical_request = encode_canonical(
            &request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).expect("frame bound"),
        )
        .expect("canonical request");
        let exit_node_id = node_id_from_public_key(
            &exit_identity
                .ed25519_public_key_bytes()
                .expect("exit public key"),
        );
        let response = ExitForwardResponse::unavailable(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
        )
        .expect("Unavailable response");
        fixture.runtime.completed_client_forwards.insert(
            ClientForwardKey {
                control_relay_peer: control.peer_id,
                forward_id,
            },
            CompletedClientForward {
                canonical_request,
                target_peer: exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                outcome: Ok(response.clone()),
                expires_at_ms: deadline,
                reserved_bytes: 1,
            },
        );
        for index in 1..MAX_LEDGER_ENTRIES {
            let mut filler_id = [0_u8; FORWARD_ID_BYTES];
            filler_id[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("bounded entry count")
                    .to_be_bytes(),
            );
            fixture.runtime.completed_client_forwards.insert(
                ClientForwardKey {
                    control_relay_peer: control.peer_id,
                    forward_id: filler_id,
                },
                CompletedClientForward {
                    canonical_request: vec![0],
                    target_peer: exit_peer,
                    operation: ExitForwardOperation::FetchExitAdvertisement,
                    outcome: Err(OutboundReservationError::Capacity),
                    expires_at_ms: deadline,
                    reserved_bytes: 1,
                },
            );
        }
        assert_eq!(fixture.runtime.ledger_entry_count(), MAX_LEDGER_ENTRIES);
        assert!(!fixture.runtime.ledger_can_reserve(control.peer_id, 1));

        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        assert_eq!(received.await.expect("cached reply"), Ok(response));
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert_eq!(
            fixture.runtime.completed_client_forwards.len(),
            MAX_LEDGER_ENTRIES
        );
    }

    #[tokio::test]
    async fn local_ambiguity_dispatches_exactly_three_times_then_tombstones() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let deadline = unix_millis().saturating_add(20_000);
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            [51; FORWARD_ID_BYTES],
            deadline,
        );
        let expected = [
            OutboundReservationError::AmbiguousAfterDispatch,
            OutboundReservationError::AmbiguousAfterDispatch,
            OutboundReservationError::RetryExhausted,
        ];
        for expected_error in expected {
            let (reply, received) = oneshot::channel();
            fixture
                .runtime
                .begin_client_forward(control.peer_id, request.clone(), reply);
            let request_id = *fixture
                .runtime
                .pending_client_forwards
                .keys()
                .next()
                .expect("one dispatch");
            assert_eq!(
                fixture
                    .runtime
                    .fail_client_forward(request_id, control.peer_id),
                OutboundEventOutcome::Failed
            );
            assert_eq!(
                received
                    .await
                    .expect("ambiguity reply")
                    .expect_err("failed dispatch"),
                expected_error
            );
        }
        assert!(fixture.runtime.retry_client_forwards.is_empty());
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        assert_eq!(
            received
                .await
                .expect("tombstone reply")
                .expect_err("retry exhausted"),
            OutboundReservationError::RetryExhausted
        );
        assert!(fixture.runtime.pending_client_forwards.is_empty());
    }

    #[tokio::test]
    async fn received_unavailable_is_definitive_until_operation_expiry() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let deadline = unix_millis().saturating_add(25_000);
        let forward_id = [61; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline,
        );
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request.clone(), reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("one dispatch");
        let exit_node_id = node_id_from_public_key(
            &exit_identity
                .ed25519_public_key_bytes()
                .expect("exit public key"),
        );
        let response = ExitForwardResponse::unavailable(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
        )
        .expect("Unavailable response");
        assert_eq!(
            fixture
                .runtime
                .complete_client_forward(request_id, control.peer_id, &response, &fixture.state)
                .await,
            OutboundEventOutcome::Completed
        );
        assert_eq!(
            received.await.expect("definitive reply"),
            Ok(response.clone())
        );

        let logical_key = ClientForwardKey {
            control_relay_peer: control.peer_id,
            forward_id,
        };
        fixture
            .runtime
            .purge_completed_at(deadline.saturating_sub(1));
        assert!(
            fixture
                .runtime
                .completed_client_forwards
                .contains_key(&logical_key)
        );
        let (retry_reply, retry_received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, retry_reply);
        assert_eq!(
            retry_received.await.expect("cached Unavailable"),
            Ok(response)
        );
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert!(fixture.runtime.retry_client_forwards.is_empty());
        fixture.runtime.purge_completed_at(deadline);
        assert!(
            !fixture
                .runtime
                .completed_client_forwards
                .contains_key(&logical_key)
        );
    }

    #[tokio::test]
    async fn direct_or_pending_direct_exit_association_causes_zero_forward_dispatch() {
        let mut direct_fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let deadline = unix_millis().saturating_add(20_000);
        let (control, request) = authorize_fetch(
            &mut direct_fixture,
            &control_identity,
            exit_peer,
            [71; FORWARD_ID_BYTES],
            deadline,
        );
        let direct_exit = direct_capability(
            &exit_identity,
            &direct_fixture.policy,
            1,
            deadline.saturating_add(10_000),
        );
        direct_fixture
            .runtime
            .direct_relays
            .insert(exit_peer, direct_exit);
        let (reply, received) = oneshot::channel();
        direct_fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        assert_eq!(
            received
                .await
                .expect("direct conflict reply")
                .expect_err("must fail closed"),
            OutboundReservationError::InvalidRequest
        );
        assert!(direct_fixture.runtime.pending_client_forwards.is_empty());

        let mut pending_fixture = fixture(test_client_roles());
        let (control, request) = authorize_fetch(
            &mut pending_fixture,
            &control_identity,
            exit_peer,
            [72; FORWARD_ID_BYTES],
            deadline,
        );
        let advertisement_request = pending_fixture
            .runtime
            .service
            .request_relay_advertisement(&exit_peer)
            .expect("outbound advertisement request");
        pending_fixture
            .runtime
            .relay_advertisement_requests
            .insert(advertisement_request, exit_peer);
        let (reply, received) = oneshot::channel();
        pending_fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        assert_eq!(
            received
                .await
                .expect("pending direct conflict reply")
                .expect_err("must fail closed"),
            OutboundReservationError::InvalidRequest
        );
        assert!(pending_fixture.runtime.pending_client_forwards.is_empty());
    }

    #[tokio::test]
    async fn relay_provider_refreshes_live_advertisement_without_duplicate_requests() {
        let mut fixture = fixture(test_client_roles());
        let relay_identity = Identity::generate();
        let now_ms = unix_millis();
        let control = install_control(&mut fixture, &relay_identity, now_ms);
        assert!(control.expires_at_ms > now_ms.saturating_add(1_000));
        assert!(fixture.runtime.relay_advertisement_requests.is_empty());
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, HashSet::from([control.peer_id]));
        assert_eq!(fixture.runtime.relay_advertisement_requests.len(), 1);
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, HashSet::from([control.peer_id]));
        assert_eq!(fixture.runtime.relay_advertisement_requests.len(), 1);
    }

    #[tokio::test]
    async fn combined_role_provider_partition_keeps_exit_and_two_relays_in_either_event_order() {
        for (offers_exit, relay_first) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let combined_roles = RolesConfig {
                client: true,
                relay: true,
                exit: offers_exit,
            };
            let mut fixture = fixture(combined_roles);
            let peers = (0..3)
                .map(|_| *Identity::generate().peer_id())
                .collect::<HashSet<_>>();
            let first = if relay_first {
                ProviderQueryKind::Relay
            } else {
                ProviderQueryKind::Exit
            };
            let second = if relay_first {
                ProviderQueryKind::Exit
            } else {
                ProviderQueryKind::Relay
            };
            fixture.runtime.handle_provider_peers(first, peers.clone());
            assert!(fixture.runtime.relay_advertisement_requests.is_empty());
            fixture.runtime.handle_provider_peers(second, peers.clone());
            assert_eq!(fixture.runtime.reserved_provider_exit_peers.len(), 1);
            assert_eq!(fixture.runtime.relay_advertisement_requests.len(), 2);
            let reserved = *fixture
                .runtime
                .reserved_provider_exit_peers
                .keys()
                .next()
                .unwrap();
            assert!(
                fixture
                    .runtime
                    .forwarded_exit_peer_is_eligible(reserved, unix_millis())
            );
            assert!(
                fixture
                    .runtime
                    .relay_advertisement_requests
                    .values()
                    .all(|peer| *peer != reserved)
            );
            // A refreshed untrusted provider index neither changes an existing partition nor
            // creates selectable signed authority. The original Exit remains undialed.
            fixture
                .runtime
                .handle_provider_peers(ProviderQueryKind::Relay, peers.clone());
            fixture
                .runtime
                .handle_provider_peers(ProviderQueryKind::Exit, peers);
            assert!(
                fixture
                    .runtime
                    .reserved_provider_exit_peers
                    .contains_key(&reserved)
            );
            assert_eq!(fixture.runtime.relay_advertisement_requests.len(), 2);
            assert!(fixture.runtime.direct_relays.is_empty());
            assert!(fixture.runtime.forwarded_exits.is_empty());
        }
    }

    #[tokio::test]
    async fn provider_partition_preserves_square_neighbors_after_a_complete_result_stream() {
        for offers_exit in [true, false] {
            let mut fixture = fixture(RolesConfig {
                client: true,
                relay: true,
                exit: offers_exit,
            });
            let neighbors = [
                *Identity::generate().peer_id(),
                *Identity::generate().peer_id(),
            ];
            let opposite = *Identity::generate().peer_id();
            for peer in neighbors {
                fixture
                    .runtime
                    .observed_endpoints
                    .insert(peer, ("/ip4/44.12.34.1/udp/41000/quic-v1".to_owned(), None));
            }
            // Relay and Exit queries are independent; duplicate Exit queries are coalesced.
            let mut queries = Vec::new();
            for (capability_key, kind) in [
                (capability::EXIT, ProviderQueryKind::Exit),
                (capability::RELAY, ProviderQueryKind::Relay),
            ] {
                let query = fixture
                    .runtime
                    .service
                    .find_providers(capability_key)
                    .unwrap();
                fixture.runtime.provider_queries.insert(query, kind);
                queries.push(query);
            }
            fixture.runtime.handle_provider_peers(
                ProviderQueryKind::Relay,
                HashSet::from([neighbors[0], neighbors[1], opposite]),
            );
            fixture
                .runtime
                .handle_provider_peers(ProviderQueryKind::Exit, HashSet::from([neighbors[0]]));
            assert!(fixture.runtime.reserved_provider_exit_peers.is_empty());
            assert!(fixture.runtime.relay_advertisement_requests.is_empty());
            fixture.runtime.handle_provider_peers(
                ProviderQueryKind::Exit,
                HashSet::from([neighbors[1], opposite]),
            );
            assert!(fixture.runtime.reserved_provider_exit_peers.is_empty());
            fixture.runtime.finish_provider_query(queries[0]);
            assert_eq!(fixture.runtime.provider_queries.len(), 1);
            assert_eq!(fixture.runtime.reserved_provider_exit_peers.len(), 1);
            assert!(
                fixture
                    .runtime
                    .reserved_provider_exit_peers
                    .contains_key(&opposite)
            );
            assert_eq!(
                fixture
                    .runtime
                    .relay_advertisement_requests
                    .values()
                    .copied()
                    .collect::<HashSet<_>>(),
                HashSet::from(neighbors)
            );
            assert!(fixture.runtime.direct_relays.is_empty());
            assert!(fixture.runtime.forwarded_exits.is_empty());
        }
    }

    #[tokio::test]
    async fn provider_partition_waits_for_a_usable_pool_across_completed_queries() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: true,
            exit: true,
        });
        let neighbors = [
            *Identity::generate().peer_id(),
            *Identity::generate().peer_id(),
        ];
        for peer in neighbors {
            fixture
                .runtime
                .observed_endpoints
                .insert(peer, ("/ip4/44.12.34.1/udp/41000/quic-v1".to_owned(), None));
        }
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, HashSet::from(neighbors));
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Exit, HashSet::from(neighbors));
        // A first query has fully finished; the next provider is not merely another streamed chunk.
        assert!(fixture.runtime.provider_queries.is_empty());
        assert!(fixture.runtime.reserved_provider_exit_peers.is_empty());
        assert!(fixture.runtime.relay_advertisement_requests.is_empty());
        let opposite = *Identity::generate().peer_id();
        // The Relay index may finish ahead of the next Exit query. Its completeness must not
        // make either already-known neighbor into the permanently reserved Exit.
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, HashSet::from([opposite]));
        assert!(fixture.runtime.reserved_provider_exit_peers.is_empty());
        assert!(fixture.runtime.relay_advertisement_requests.is_empty());
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Exit, HashSet::from([opposite]));
        assert_eq!(
            fixture
                .runtime
                .reserved_provider_exit_peers
                .keys()
                .copied()
                .collect::<HashSet<_>>(),
            HashSet::from([opposite])
        );
        assert_eq!(
            fixture
                .runtime
                .relay_advertisement_requests
                .values()
                .copied()
                .collect::<HashSet<_>>(),
            HashSet::from(neighbors)
        );
    }

    #[tokio::test]
    async fn provider_partition_all_connected_fallback_is_deterministic_and_can_expand_privately() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: true,
            exit: true,
        });
        let peers = (0..3)
            .map(|_| *Identity::generate().peer_id())
            .collect::<HashSet<_>>();
        for peer in &peers {
            fixture.runtime.observed_endpoints.insert(
                *peer,
                ("/ip4/44.12.34.1/udp/41000/quic-v1".to_owned(), None),
            );
        }
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Exit, peers.clone());
        let first_partition = fixture.runtime.reserved_provider_exit_peers.clone();
        assert_eq!(first_partition.len(), 1);
        fixture.runtime.reserved_provider_exit_peers.clear();
        fixture
            .runtime
            .reserve_provider_exit_candidates(unix_millis());
        assert_eq!(
            fixture.runtime.reserved_provider_exit_peers,
            first_partition
        );
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, peers);
        assert_eq!(fixture.runtime.relay_advertisement_requests.len(), 2);

        let opposite = *Identity::generate().peer_id();
        // A logical connection through Circuit Relay is not a directly connected neighbor.
        fixture.runtime.observed_endpoints.insert(
            opposite,
            (
                format!(
                    "/ip4/44.12.34.1/udp/41000/quic-v1/p2p/{}/p2p-circuit",
                    fixture.runtime.service.local_peer_id()
                ),
                None,
            ),
        );
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Exit, HashSet::from([opposite]));
        assert!(
            fixture
                .runtime
                .reserved_provider_exit_peers
                .contains_key(&opposite)
        );
        assert!(first_partition.keys().all(|peer| {
            fixture
                .runtime
                .reserved_provider_exit_peers
                .contains_key(peer)
        }));
        assert!(
            fixture
                .runtime
                .relay_advertisement_requests
                .values()
                .all(|peer| *peer != opposite)
        );
        assert!(fixture.runtime.direct_relays.is_empty());
        assert!(fixture.runtime.forwarded_exits.is_empty());
    }

    #[tokio::test]
    async fn forwarded_target_blocks_direct_relay_provider_fetch_and_expires() {
        let mut fixture = fixture(test_client_roles());
        let exit_peer = Identity::generate().peer_id().to_owned();
        let now_ms = unix_millis();
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(exit_peer, now_ms.saturating_add(20_000))
        );
        fixture
            .runtime
            .handle_provider_peers(ProviderQueryKind::Relay, HashSet::from([exit_peer]));
        assert!(fixture.runtime.relay_advertisement_requests.is_empty());

        fixture
            .runtime
            .forwarded_exit_targets
            .insert(exit_peer, now_ms.saturating_sub(1));
        fixture.runtime.purge_completed(Instant::now());
        assert!(
            !fixture
                .runtime
                .forwarded_exit_targets
                .contains_key(&exit_peer)
        );
    }

    #[tokio::test]
    async fn direct_provenance_revokes_capless_inflight_fetch_and_late_response() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let deadline = unix_millis().saturating_add(20_000);
        let forward_id = [81; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline,
        );
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("one pending Fetch");
        let accepted = accepted_for_identity(
            &exit_identity,
            &fixture.policy,
            1,
            deadline.saturating_add(5_000),
        );
        fixture
            .runtime
            .revoke_for_direct_advertisement(exit_peer, &accepted, false, false);
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert_eq!(
            received
                .await
                .expect("revoked reply")
                .expect_err("revoked authority"),
            OutboundReservationError::InvalidResponse
        );

        let response = ExitForwardResponse::unavailable(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            accepted.node_id.to_vec(),
            exit_peer.to_bytes(),
        )
        .expect("late response");
        assert_eq!(
            fixture
                .runtime
                .complete_client_forward(request_id, control.peer_id, &response, &fixture.state)
                .await,
            OutboundEventOutcome::Unexpected
        );
        let completed = fixture
            .runtime
            .completed_client_forwards
            .values()
            .next()
            .expect("revocation tombstone");
        assert_eq!(
            completed.outcome,
            Err(OutboundReservationError::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn same_exit_ad_is_scoped_per_control_relay_but_replay_is_rejected_per_pair() {
        let mut fixture = fixture(test_client_roles());
        let relay_a = Identity::generate();
        let relay_b = Identity::generate();
        let exit = Identity::generate();
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let control_a = install_control(&mut fixture, &relay_a, now_ms);
        let control_b = install_control(&mut fixture, &relay_b, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        fixture
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let advertisement = service_advertisement(
            &exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement.clone(),
                    forwarded_provenance(&control_a, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement.clone(),
                    forwarded_provenance(&control_b, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement,
                    forwarded_provenance(&control_a, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_none()
        );
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control_a.peer_id,
                    exit_peer,
                })
        );
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control_b.peer_id,
                    exit_peer,
                })
        );
    }

    #[tokio::test]
    async fn relay_owned_exit_authority_coexists_with_local_client_relay_observations() {
        let roles = RolesConfig {
            client: true,
            relay: true,
            exit: true,
        };
        for direct_first in [false, true] {
            let mut fixture = fixture(roles);
            let now_ms = unix_millis();
            let deadline = now_ms.saturating_add(20_000);
            let local = direct_capability(
                &fixture.runtime.identity,
                &fixture.policy,
                1,
                deadline.saturating_add(10_000),
            );
            fixture.runtime.local_relay_snapshot = Some(local.clone());
            let exit = Identity::generate();
            let exit_peer = exit.peer_id().to_owned();
            let advertisement = service_advertisement(
                &exit,
                roles,
                &fixture.policy,
                1,
                generate_nonce(),
                now_ms,
                &fixture.directory,
            );
            let direct = AdvertisementProvenance::DirectRelay {
                authenticated_peer: exit_peer,
            };
            let forwarded = forwarded_provenance(&local, &exit, deadline);
            let provenances = if direct_first {
                [direct, forwarded]
            } else {
                [forwarded, direct]
            };
            for provenance in provenances {
                assert!(
                    fixture
                        .runtime
                        .ingest_advertisement(
                            exit_peer,
                            advertisement.clone(),
                            provenance,
                            &fixture.state,
                        )
                        .await
                        .is_some()
                );
            }
            let key = ForwardedExitKey {
                control_relay_peer: local.peer_id,
                exit_peer,
            };
            assert!(fixture.runtime.forwarded_exits.contains_key(&key));
            assert!(fixture.runtime.direct_relays.contains_key(&exit_peer));
            assert!(
                !fixture
                    .runtime
                    .peer_is_forwarded_exit_target(exit_peer, now_ms)
            );
            assert!(
                !fixture
                    .runtime
                    .forwarded_exit_peer_is_eligible(exit_peer, now_ms)
            );
            assert!(fixture.runtime.forwarded_exit_authority_is_eligible(
                local.peer_id,
                exit_peer,
                now_ms,
            ));

            // An actual signed policy change still invalidates server-owned Exit authority.
            let mut changed = accepted_for_identity(&exit, &fixture.policy, 2, deadline);
            changed.policy_hash[0] ^= 1;
            fixture
                .runtime
                .revoke_for_direct_advertisement(exit_peer, &changed, true, false);
            assert!(!fixture.runtime.forwarded_exits.contains_key(&key));
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "both provenance event orders are one invariant"
    )]
    #[tokio::test]
    async fn combined_advertisement_never_mints_both_direct_and_forwarded_exit_authority() {
        let roles = RolesConfig {
            client: false,
            relay: true,
            exit: true,
        };
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);

        let mut direct_first = fixture(test_client_roles());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let control = install_control(&mut direct_first, &relay, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        let advertisement = service_advertisement(
            &exit,
            roles,
            &direct_first.policy,
            1,
            generate_nonce(),
            now_ms,
            &direct_first.directory,
        );
        assert!(
            direct_first
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement.clone(),
                    AdvertisementProvenance::DirectRelay {
                        authenticated_peer: exit_peer,
                    },
                    &direct_first.state,
                )
                .await
                .is_some()
        );
        direct_first
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        assert!(
            direct_first
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement,
                    forwarded_provenance(&control, &exit, deadline),
                    &direct_first.state,
                )
                .await
                .is_none()
        );
        assert!(direct_first.runtime.direct_relays.contains_key(&exit_peer));
        assert!(
            !direct_first
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
        );

        let mut forwarded_first = fixture(test_client_roles());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let control = install_control(&mut forwarded_first, &relay, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        forwarded_first
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let advertisement = service_advertisement(
            &exit,
            roles,
            &forwarded_first.policy,
            1,
            generate_nonce(),
            now_ms,
            &forwarded_first.directory,
        );
        assert!(
            forwarded_first
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement.clone(),
                    forwarded_provenance(&control, &exit, deadline),
                    &forwarded_first.state,
                )
                .await
                .is_some()
        );
        assert!(
            forwarded_first
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement,
                    AdvertisementProvenance::DirectRelay {
                        authenticated_peer: exit_peer,
                    },
                    &forwarded_first.state,
                )
                .await
                .is_some()
        );
        assert!(
            forwarded_first
                .runtime
                .direct_relays
                .contains_key(&exit_peer)
        );
        assert!(
            !forwarded_first
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
        );
        assert!(
            !forwarded_first
                .runtime
                .forwarded_exit_peer_is_eligible(exit_peer, unix_millis())
        );
    }

    #[tokio::test]
    async fn higher_exit_sequence_with_role_withdrawal_revokes_old_authority() {
        let mut fixture = fixture(test_client_roles());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let control = install_control(&mut fixture, &relay, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        fixture
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let first = service_advertisement(
            &exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    first,
                    forwarded_provenance(&control, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );
        let withdrawal = service_advertisement(
            &exit,
            test_client_roles(),
            &fixture.policy,
            2,
            generate_nonce(),
            now_ms.saturating_add(1),
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    withdrawal,
                    forwarded_provenance(&control, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_none()
        );
        assert!(
            !fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
        );
        assert_eq!(
            fixture
                .runtime
                .accepted_advertisements
                .get(&node_id_from_public_key(
                    &exit.ed25519_public_key_bytes().expect("exit public key")
                ))
                .expect("higher sequence record")
                .sequence_number,
            2
        );
    }

    #[tokio::test]
    async fn direct_relay_role_withdrawal_revokes_control_and_forwarded_exit_authority() {
        let mut fixture = fixture(test_client_roles());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let relay_peer = relay.peer_id().to_owned();
        let exit_peer = exit.peer_id().to_owned();
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let relay_advertisement = service_advertisement(
            &relay,
            RolesConfig {
                client: false,
                relay: true,
                exit: false,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    relay_peer,
                    relay_advertisement,
                    AdvertisementProvenance::DirectRelay {
                        authenticated_peer: relay_peer,
                    },
                    &fixture.state,
                )
                .await
                .is_some()
        );
        let control = fixture
            .runtime
            .direct_relays
            .get(&relay_peer)
            .expect("direct Relay authority")
            .clone();
        fixture
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let exit_advertisement = service_advertisement(
            &exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    exit_advertisement,
                    forwarded_provenance(&control, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );

        let withdrawal = service_advertisement(
            &relay,
            test_client_roles(),
            &fixture.policy,
            2,
            generate_nonce(),
            now_ms.saturating_add(1),
            &fixture.directory,
        );
        let _ = fixture
            .runtime
            .ingest_advertisement(
                relay_peer,
                withdrawal,
                AdvertisementProvenance::DirectRelay {
                    authenticated_peer: relay_peer,
                },
                &fixture.state,
            )
            .await;

        assert!(!fixture.runtime.direct_relays.contains_key(&relay_peer));
        assert!(
            !fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: relay_peer,
                    exit_peer,
                })
        );
    }

    #[tokio::test]
    async fn active_policy_change_revokes_all_old_capability_authority() {
        let mut fixture = fixture(test_client_roles());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let control = install_control(&mut fixture, &relay, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        fixture
            .runtime
            .mark_forwarded_exit_target(exit_peer, deadline);
        let advertisement = service_advertisement(
            &exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    exit_peer,
                    advertisement,
                    forwarded_provenance(&control, &exit, deadline),
                    &fixture.state,
                )
                .await
                .is_some()
        );

        fixture.state.write().await.set_policy(None);
        fixture
            .runtime
            .revoke_capabilities_outside_active_policy(&fixture.state)
            .await;

        assert!(fixture.runtime.direct_relays.is_empty());
        assert!(fixture.runtime.forwarded_exits.is_empty());
        assert!(has_active_privacy_conflict(
            &fixture.runtime.privacy_conflicts,
            fixture.runtime.forwarded_exit_fail_closed_until_ms,
            control.peer_id,
            unix_millis(),
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one actor policy transaction covers both forwarding ledgers"
    )]
    #[tokio::test]
    async fn policy_apply_replies_after_cross_ledger_revocation_and_resolve_is_closed() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: true,
            exit: true,
        });
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        assert!(fixture.runtime.exit_service.is_some());
        let signed_local = fixture
            .runtime
            .publisher
            .sign(
                &fixture.runtime.identity,
                &local_advertisement_input(
                    RolesConfig {
                        client: true,
                        relay: true,
                        exit: true,
                    },
                    "operator-policy-barrier",
                    &fixture.policy,
                    BTreeSet::from(["/ip4/127.0.0.1/tcp/42100".to_owned()]),
                ),
                now_ms,
            )
            .expect("valid local signed advertisement");
        fixture
            .runtime
            .service
            .set_local_advertisement(signed_local.envelope.clone())
            .expect("installed local advertisement");
        fixture.runtime.served_local_advertisement = Some(signed_local.envelope);
        fixture
            .runtime
            .service
            .provide(capability::EXIT)
            .expect("active exit provider query");
        fixture
            .runtime
            .active_provider_keys
            .insert(capability::EXIT.to_owned());
        assert!(fixture.runtime.served_local_advertisement.is_some());
        assert!(fixture.runtime.service.is_serving_local_advertisement());
        assert!(!fixture.runtime.active_provider_keys.is_empty());
        let remote_control_identity = Identity::generate();
        let remote_control = install_control(&mut fixture, &remote_control_identity, now_ms);
        let local_control = DirectRelayCapability {
            node_id: fixture.runtime.local_node_id,
            peer_id: *fixture.runtime.service.local_peer_id(),
            public_key: fixture.runtime.local_public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms: deadline.saturating_add(10_000),
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(
                fixture.runtime.local_node_id,
            ),
            policy_version: fixture.policy.manifest_version(),
            policy_hash: *fixture.policy.policy_hash(),
            policy_expires_at_ms: fixture.policy.expires_at_ms(),
            expires_at_ms: deadline.saturating_add(10_000),
        };
        fixture.runtime.local_relay_snapshot = Some(local_control.clone());

        let client_exit = Identity::generate();
        let client_exit_peer = client_exit.peer_id().to_owned();
        let client_exit_capability =
            forwarded_capability_for_identity(&remote_control, &client_exit, 1, deadline);
        let relay_exit = Identity::generate();
        let relay_exit_peer = relay_exit.peer_id().to_owned();
        let relay_exit_capability =
            forwarded_capability_for_identity(&local_control, &relay_exit, 1, deadline);
        fixture.runtime.forwarded_exits.insert(
            ForwardedExitKey {
                control_relay_peer: remote_control.peer_id,
                exit_peer: client_exit_peer,
            },
            client_exit_capability,
        );
        fixture.runtime.forwarded_exits.insert(
            ForwardedExitKey {
                control_relay_peer: local_control.peer_id,
                exit_peer: relay_exit_peer,
            },
            relay_exit_capability,
        );
        fixture
            .runtime
            .exit_provider_peers
            .insert(client_exit_peer, deadline);
        fixture
            .runtime
            .exit_provider_peers
            .insert(relay_exit_peer, deadline);
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(client_exit_peer, deadline)
        );
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(relay_exit_peer, deadline)
        );

        let pending_client_forward_id = [181; FORWARD_ID_BYTES];
        let pending_client_request = fetch_request(
            &remote_control,
            client_exit_peer,
            pending_client_forward_id,
            deadline,
        );
        let (pending_client_reply, pending_client_received) = oneshot::channel();
        fixture.runtime.begin_client_forward(
            remote_control.peer_id,
            pending_client_request,
            pending_client_reply,
        );
        assert_eq!(fixture.runtime.pending_client_forwards.len(), 1);

        let pending_relay_forward_id = [182; FORWARD_ID_BYTES];
        let pending_relay_request = fetch_request(
            &local_control,
            relay_exit_peer,
            pending_relay_forward_id,
            deadline,
        );
        let pending_relay_canonical = encode_canonical(
            &pending_relay_request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).expect("frame bound"),
        )
        .expect("canonical relay request");
        let pending_relay_id = fixture
            .runtime
            .service
            .request_exit_forward_upstream(&relay_exit_peer, pending_relay_request.into())
            .expect("upstream dispatch");
        let pending_relay_key = RelayForwardKey {
            authenticated_client_peer: Identity::generate().peer_id().to_owned(),
            forward_id: pending_relay_forward_id,
        };
        fixture
            .runtime
            .relay_forward_index
            .insert(pending_relay_key, pending_relay_id);
        fixture.runtime.pending_relay_forwards.insert(
            pending_relay_id,
            PendingRelayForward {
                key: pending_relay_key,
                expected_exit_peer: relay_exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                expected_exit_node_id: None,
                authorized_control: local_control.clone(),
                authorized_exit: None,
                canonical_request: pending_relay_canonical,
                operation_expires_at_ms: deadline,
                attempt_deadline: Instant::now() + Duration::from_secs(5),
                dispatch_attempts: 1,
                reserved_bytes: 1,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );

        let retry_client_key = ClientForwardKey {
            control_relay_peer: remote_control.peer_id,
            forward_id: [183; FORWARD_ID_BYTES],
        };
        fixture.runtime.retry_client_forwards.insert(
            retry_client_key,
            RetryLedgerEntry {
                canonical_request: vec![1],
                operation: Some(ExitForwardOperation::FetchExitAdvertisement),
                dispatch_attempts: 1,
                expires_at_ms: deadline,
                reserved_bytes: 1,
                target_peer: client_exit_peer,
            },
        );
        let retry_relay_key = RelayForwardKey {
            authenticated_client_peer: Identity::generate().peer_id().to_owned(),
            forward_id: [184; FORWARD_ID_BYTES],
        };
        fixture.runtime.retry_relay_forwards.insert(
            retry_relay_key,
            RetryLedgerEntry {
                canonical_request: vec![2],
                operation: Some(ExitForwardOperation::FetchExitAdvertisement),
                dispatch_attempts: 1,
                expires_at_ms: deadline,
                reserved_bytes: 1,
                target_peer: relay_exit_peer,
            },
        );

        let completed_client_key = ClientForwardKey {
            control_relay_peer: remote_control.peer_id,
            forward_id: [185; FORWARD_ID_BYTES],
        };
        let client_unavailable = ExitForwardResponse::unavailable(
            completed_client_key.forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            node_id_from_public_key(
                &client_exit
                    .ed25519_public_key_bytes()
                    .expect("client exit public key"),
            )
            .to_vec(),
            client_exit_peer.to_bytes(),
        )
        .expect("client unavailable response");
        fixture.runtime.completed_client_forwards.insert(
            completed_client_key,
            CompletedClientForward {
                canonical_request: vec![3],
                target_peer: client_exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                outcome: Ok(client_unavailable),
                expires_at_ms: deadline,
                reserved_bytes: 1,
            },
        );
        let completed_relay_key = RelayForwardKey {
            authenticated_client_peer: Identity::generate().peer_id().to_owned(),
            forward_id: [186; FORWARD_ID_BYTES],
        };
        let relay_unavailable = ExitForwardResponse::unavailable(
            completed_relay_key.forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            node_id_from_public_key(
                &relay_exit
                    .ed25519_public_key_bytes()
                    .expect("relay exit public key"),
            )
            .to_vec(),
            relay_exit_peer.to_bytes(),
        )
        .expect("relay unavailable response");
        fixture.runtime.completed_relay_forwards.insert(
            completed_relay_key,
            CompletedRelayForward {
                canonical_request: vec![4],
                target_peer: relay_exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                response: Some(relay_unavailable),
                expires_at_ms: deadline,
                reserved_bytes: 1,
            },
        );

        let (barrier_reached, mut barrier_observed) = oneshot::channel();
        let (barrier_release, release_barrier) = oneshot::channel();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .policy_apply_pre_reply = Some(PolicyApplyPreReplyBarrier {
            reached: barrier_reached,
            release: release_barrier,
        });
        let state = Arc::clone(&fixture.state);
        let (apply_reply, mut apply_received) = oneshot::channel();
        let mut apply = Box::pin(fixture.runtime.handle_command(
            DiscoveryCommand::ApplyPolicy {
                policy: None,
                reply: apply_reply,
            },
            &state,
        ));
        let snapshot = timeout(Duration::from_secs(1), async {
            tokio::select! {
                snapshot = &mut barrier_observed => {
                    snapshot.expect("pre-reply policy snapshot")
                }
                () = &mut apply => panic!("policy apply replied before the test barrier"),
            }
        })
        .await
        .expect("policy apply reaches pre-reply barrier");
        assert_eq!(
            snapshot,
            PolicyApplyPreReplySnapshot {
                active_policy_version: 0,
                direct_relays: 0,
                local_relay_snapshots: 0,
                forwarded_exits: 0,
                pending_client_forwards: 0,
                client_forward_index: 0,
                retry_client_forwards: 0,
                completed_client_forwards: 3,
                invalid_client_tombstones: 3,
                pending_relay_forwards: 0,
                relay_forward_index: 0,
                retry_relay_forwards: 0,
                completed_relay_forwards: 3,
                withdrawn_relay_tombstones: 3,
                exit_services: 0,
                served_local_advertisements: 0,
                service_local_advertisements: 0,
                active_provider_keys: 0,
            }
        );
        assert!(matches!(
            apply_received.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        barrier_release.send(()).expect("release pre-reply barrier");
        timeout(Duration::from_secs(1), &mut apply)
            .await
            .expect("policy transaction completes");
        drop(apply);
        apply_received.await.expect("policy apply reply");

        assert!(!fixture.state.read().await.policy_active(unix_millis()));
        assert!(fixture.runtime.direct_relays.is_empty());
        assert!(fixture.runtime.local_relay_snapshot.is_none());
        assert!(fixture.runtime.forwarded_exits.is_empty());
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert!(fixture.runtime.client_forward_index.is_empty());
        assert!(fixture.runtime.pending_relay_forwards.is_empty());
        assert!(fixture.runtime.relay_forward_index.is_empty());
        assert!(fixture.runtime.retry_client_forwards.is_empty());
        assert!(fixture.runtime.retry_relay_forwards.is_empty());
        assert_eq!(
            pending_client_received.await.expect("revoked client reply"),
            Err(OutboundReservationError::InvalidResponse)
        );
        assert_eq!(fixture.runtime.completed_client_forwards.len(), 3);
        assert!(
            fixture
                .runtime
                .completed_client_forwards
                .values()
                .all(|entry| { entry.outcome == Err(OutboundReservationError::InvalidResponse) })
        );
        assert_eq!(fixture.runtime.completed_relay_forwards.len(), 3);
        assert!(
            fixture
                .runtime
                .completed_relay_forwards
                .values()
                .all(|entry| entry.response.is_none())
        );

        let (direct_reply, direct_received) = oneshot::channel();
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::ResolveDirectRelay {
                    expected_node_id: remote_control.node_id,
                    expected_peer_id: remote_control.peer_id,
                    reply: direct_reply,
                },
                &fixture.state,
            )
            .await;
        assert!(
            direct_received
                .await
                .expect("direct resolve reply")
                .is_none()
        );

        let (forwarded_reply, forwarded_received) = oneshot::channel();
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::ResolveForwardedExit {
                    control_relay_node_id: remote_control.node_id,
                    control_relay_peer_id: remote_control.peer_id,
                    exit_node_id: node_id_from_public_key(
                        &client_exit
                            .ed25519_public_key_bytes()
                            .expect("client exit public key"),
                    ),
                    exit_peer_id: client_exit_peer,
                    reply: forwarded_reply,
                },
                &fixture.state,
            )
            .await;
        assert!(
            forwarded_received
                .await
                .expect("forwarded resolve reply")
                .is_none()
        );
    }

    #[tokio::test]
    async fn stored_advertisement_revalidation_preserves_roles_without_minting_exit_authority() {
        let mut fixture = fixture(test_client_roles());
        let service = Identity::generate();
        let peer = service.peer_id().to_owned();
        let now_ms = unix_millis();
        fixture.runtime.observed_endpoints.insert(
            peer,
            (
                "/ip4/8.8.8.8/udp/443/quic-v1".to_owned(),
                Some(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))),
            ),
        );
        let advertisement = service_advertisement(
            &service,
            RolesConfig {
                client: false,
                relay: true,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        assert!(
            fixture
                .runtime
                .ingest_advertisement(
                    peer,
                    advertisement,
                    AdvertisementProvenance::DirectRelay {
                        authenticated_peer: peer,
                    },
                    &fixture.state,
                )
                .await
                .is_some()
        );
        let node_id = node_id_from_public_key(
            &service
                .ed25519_public_key_bytes()
                .expect("service public key"),
        );
        let stored = fixture
            .runtime
            .store
            .load_candidates(UnixTime::from_secs(now_ms / 1_000), 10)
            .expect("stored candidates")
            .into_iter()
            .find(|candidate| candidate.advertisement.node_id.as_str() == hex::encode(node_id))
            .expect("stored combined advertisement");
        let capability =
            revalidate_stored_advertisement(&stored, now_ms).expect("relay revalidation");
        assert!(capability.relay);
        assert!(capability.exit);
        assert_eq!(capability.peer_id, peer);
        assert!(fixture.runtime.direct_relays.contains_key(&peer));
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .values()
                .all(|forwarded| forwarded.exit_peer_id != peer)
        );
    }

    #[tokio::test]
    async fn route_candidate_snapshot_is_exact_bounded_and_deterministic() {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        for (index, identity) in (0_u8..3).map(|index| (index, Identity::generate())) {
            assert!(
                ingest_direct_snapshot_advertisement(
                    &mut fixture,
                    &identity,
                    RolesConfig {
                        client: false,
                        relay: true,
                        exit: false,
                    },
                    1,
                    [150 + index; 32],
                    now_ms,
                )
                .await
                .is_some()
            );
        }
        assert!(matches!(
            route_snapshot_at(&mut fixture, 0, now_ms).await,
            Err(RouteCandidateSnapshotError::InvalidLimit)
        ));
        assert!(matches!(
            route_snapshot_at(&mut fixture, MAXIMUM_SELECTION_CANDIDATES + 1, now_ms,).await,
            Err(RouteCandidateSnapshotError::InvalidLimit)
        ));
        let first = route_snapshot_at(&mut fixture, MAXIMUM_SELECTION_CANDIDATES, now_ms)
            .await
            .expect("bounded snapshot");
        let second = route_snapshot_at(&mut fixture, MAXIMUM_SELECTION_CANDIDATES, now_ms)
            .await
            .expect("deterministic snapshot");
        assert_eq!(first.captured_at_ms(), second.captured_at_ms());
        assert_eq!(first.policy(), second.policy());
        assert_eq!(first.direct_relays(), second.direct_relays());
        assert_eq!(first.forwarded_exits(), second.forwarded_exits());
        let first_subjects = first
            .preselection_subjects
            .availability_and_hashes_for_test();
        let second_subjects = second
            .preselection_subjects
            .availability_and_hashes_for_test();
        assert_eq!(first_subjects, second_subjects);
        assert!(first_subjects.0);
        assert!(
            first_subjects
                .1
                .iter()
                .all(|hash| { format!("{hash:?}") == "AdvertisementPayloadHash([REDACTED])" })
        );
        assert_eq!(first.direct_relays().len(), 3);
        assert!(first.forwarded_exits().is_empty());
        assert!(
            route_snapshot_at(&mut fixture, 1, now_ms)
                .await
                .expect("one-entry requested bound")
                .direct_relays()
                .len()
                <= 1
        );
        let identities = first
            .direct_relays()
            .iter()
            .map(|candidate| {
                (
                    candidate.capability().node_id,
                    candidate.capability().peer_id.to_bytes(),
                )
            })
            .collect::<Vec<_>>();
        assert!(identities.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            identities.iter().collect::<HashSet<_>>().len(),
            identities.len()
        );

        let first_node = first.direct_relays()[0].capability().node_id;
        fixture
            .runtime
            .accepted_advertisements
            .get_mut(&first_node)
            .expect("actor fingerprint")
            .fingerprint
            .signature[0] ^= 1;
        let mismatched = route_snapshot_at(&mut fixture, 200, now_ms)
            .await
            .expect("mismatch is excluded");
        assert_eq!(mismatched.direct_relays().len(), 2);
    }

    #[tokio::test]
    async fn route_candidate_snapshot_never_observes_half_committed_advertisement() {
        let mut fixture = fixture(test_client_roles());
        let identity = Identity::generate();
        let peer = identity.peer_id().to_owned();
        let now_ms = unix_millis();
        let response = service_advertisement(
            &identity,
            RolesConfig {
                client: false,
                relay: true,
                exit: false,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let before = route_snapshot_at(&mut fixture, 10, now_ms)
            .await
            .expect("empty pre-commit snapshot");
        assert!(before.direct_relays().is_empty());

        let prepared = PreparedAdvertisementCommit {
            peer,
            provenance: AdvertisementProvenance::DirectRelay {
                authenticated_peer: peer,
            },
            envelope: response.signed_envelope().to_vec(),
        };
        let state = fixture.state.read().await;
        let outcome = fixture.runtime.commit_advertisement(prepared, &state);
        drop(state);
        assert_eq!(outcome.status, AdvertisementCommitStatus::Committed);

        let after = route_snapshot_at(&mut fixture, 10, unix_millis())
            .await
            .expect("post-commit snapshot");
        assert_eq!(after.direct_relays().len(), 1);
        let exact = &after.direct_relays()[0];
        assert_eq!(exact.capability().peer_id, peer);
        assert_eq!(
            exact.advertisement().advertisement().sequence_number,
            exact.capability().advertisement_sequence
        );
        assert_eq!(
            exact.advertisement().signed_expires_at_ms(),
            exact.capability().advertisement_expires_at_ms
        );
        assert_exact_persisted_snapshot_time(&fixture, exact, &peer);

        let node_id = exact.capability().node_id;
        let accepted = fixture
            .runtime
            .accepted_advertisements
            .remove(&node_id)
            .expect("accepted actor record");
        assert!(
            route_snapshot_at(&mut fixture, 10, unix_millis())
                .await
                .expect("store plus capability is not enough")
                .direct_relays()
                .is_empty()
        );
        fixture
            .runtime
            .accepted_advertisements
            .insert(node_id, accepted);
        let capability = fixture
            .runtime
            .direct_relays
            .remove(&peer)
            .expect("actor capability");
        assert!(
            route_snapshot_at(&mut fixture, 10, unix_millis())
                .await
                .expect("store plus accepted record is not enough")
                .direct_relays()
                .is_empty()
        );
        fixture.runtime.direct_relays.insert(peer, capability);
        assert_eq!(
            route_snapshot_at(&mut fixture, 10, unix_millis())
                .await
                .expect("fully rejoined actor state")
                .direct_relays()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn route_candidate_snapshot_policy_revocation_linearizes_before_reply() {
        let mut fixture = fixture(test_client_roles());
        let identity = Identity::generate();
        let now_ms = unix_millis();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );
        assert_eq!(
            route_snapshot_at(&mut fixture, 10, now_ms)
                .await
                .expect("pre-revocation snapshot")
                .direct_relays()
                .len(),
            1
        );

        let (barrier_reached, mut barrier_observed) = oneshot::channel();
        let (barrier_release, release_barrier) = oneshot::channel();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .policy_apply_pre_reply = Some(PolicyApplyPreReplyBarrier {
            reached: barrier_reached,
            release: release_barrier,
        });
        let state = Arc::clone(&fixture.state);
        let (apply_reply, mut apply_received) = oneshot::channel();
        let mut apply = Box::pin(fixture.runtime.handle_command(
            DiscoveryCommand::ApplyPolicy {
                policy: None,
                reply: apply_reply,
            },
            &state,
        ));
        let barrier_snapshot = timeout(Duration::from_secs(1), async {
            tokio::select! {
                snapshot = &mut barrier_observed => {
                    snapshot.expect("pre-reply policy snapshot")
                }
                () = &mut apply => panic!("policy apply replied before the test barrier"),
            }
        })
        .await
        .expect("policy apply reaches pre-reply barrier");
        assert_eq!(barrier_snapshot.active_policy_version, 0);
        assert_eq!(barrier_snapshot.direct_relays, 0);
        assert!(matches!(
            apply_received.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        barrier_release.send(()).expect("release pre-reply barrier");
        timeout(Duration::from_secs(1), &mut apply)
            .await
            .expect("policy transaction completes");
        drop(apply);
        apply_received.await.expect("policy reply");
        assert!(fixture.runtime.direct_relays.is_empty());

        let (snapshot_reply, snapshot_received) = oneshot::channel();
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::RouteCandidateSnapshot {
                    requested_candidates: 10,
                    reply: snapshot_reply,
                },
                &fixture.state,
            )
            .await;
        assert!(matches!(
            snapshot_received.await.expect("snapshot reply"),
            Err(RouteCandidateSnapshotError::PolicyUnavailable)
        ));
    }

    async fn install_valid_snapshot_route(
        fixture: &mut RuntimeFixture,
        now_ms: u64,
    ) -> (DirectRelayCapability, Libp2pPeerId) {
        let control_identity = Identity::generate();
        let valid_exit = Identity::generate();
        let control =
            install_valid_snapshot_route_for(fixture, &control_identity, &valid_exit, now_ms).await;
        (control, valid_exit.peer_id().to_owned())
    }

    async fn install_valid_snapshot_route_for(
        fixture: &mut RuntimeFixture,
        control_identity: &Identity,
        valid_exit: &Identity,
        now_ms: u64,
    ) -> DirectRelayCapability {
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                control_identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generated_nonce_with_unique_network_discriminator(),
                now_ms,
            )
            .await
            .is_some()
        );
        let control = fixture
            .runtime
            .direct_relays
            .get(control_identity.peer_id())
            .expect("stored control capability")
            .clone();
        assert!(
            ingest_forwarded_snapshot_exit(
                fixture,
                &control,
                valid_exit,
                1,
                generated_nonce_with_unique_network_discriminator(),
                now_ms,
            )
            .await
            .is_some()
        );
        control
    }

    struct ActiveClientPreselectionFixture {
        fixture: RuntimeFixture,
        control_service: DiscoveryService,
        response: oneshot::Receiver<Result<PreparedPreselectionEvidence, ClientPreselectionError>>,
        began_before: Instant,
        began_after: Instant,
    }

    async fn active_client_preselection_fixture() -> ActiveClientPreselectionFixture {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });
        let now_ms = unix_millis();
        let control_identity = Identity::generate();
        let valid_exit = Identity::generate();
        let _control =
            install_valid_snapshot_route_for(&mut fixture, &control_identity, &valid_exit, now_ms)
                .await;
        let other_relay = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &other_relay,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generated_nonce_with_unique_network_discriminator(),
                now_ms,
            )
            .await
            .is_some()
        );

        let mut control_service = DiscoveryService::new_with_protocol_roles(
            control_identity.keypair().clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("control discovery service");
        connect_runtime_client_to_control(&mut fixture.runtime, &mut control_service).await;

        let (reply, response) = oneshot::channel();
        let began_before = Instant::now();
        fixture
            .runtime
            .begin_client_preselection(
                valid_client_preselection_parameters(),
                reply,
                &fixture.state,
            )
            .await;
        let began_after = Instant::now();
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Active(_)
        ));
        assert!(
            fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), 1);

        ActiveClientPreselectionFixture {
            fixture,
            control_service,
            response,
            began_before,
            began_after,
        }
    }

    async fn next_client_preselection_outbound_failure(
        runtime: &mut DiscoveryRuntime,
        control: &mut DiscoveryService,
    ) -> DiscoveryEvent {
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = runtime.service.next_event() => {
                        if matches!(
                            &event,
                            DiscoveryEvent::Other(SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservation(
                                    request_response::Event::OutboundFailure { .. },
                                ),
                            ))
                        ) {
                            break event;
                        }
                    }
                    _ = control.next_event() => {}
                }
            }
        })
        .await
        .expect("preselection outbound failure timeout")
    }

    async fn next_unconnected_client_preselection_outbound_failure(
        runtime: &mut DiscoveryRuntime,
    ) -> DiscoveryEvent {
        timeout(Duration::from_secs(10), async {
            loop {
                let event = runtime.service.next_event().await;
                if matches!(
                    &event,
                    DiscoveryEvent::Other(SwarmEvent::Behaviour(
                        BehaviourEvent::PreselectionObservation(
                            request_response::Event::OutboundFailure { .. },
                        ),
                    ))
                ) {
                    break event;
                }
            }
        })
        .await
        .expect("unconnected preselection outbound failure timeout")
    }

    #[tokio::test]
    async fn client_preselection_rejects_every_invalid_parameter_before_snapshot_or_gate() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });

        let mut unspecified_transport = valid_client_preselection_parameters();
        unspecified_transport.transport = Transport::Unspecified;
        let mut unspecified_family = valid_client_preselection_parameters();
        unspecified_family.address_family = ObservationAddressFamily::Unspecified;
        let mut zero_minimum_relays = valid_client_preselection_parameters();
        zero_minimum_relays.minimum_other_relays = 0;
        let mut inverted_relay_range = valid_client_preselection_parameters();
        inverted_relay_range.minimum_other_relays = 2;
        inverted_relay_range.maximum_other_relays = 1;
        let mut excessive_relays = valid_client_preselection_parameters();
        excessive_relays.maximum_other_relays = MAXIMUM_OTHER_RELAYS.saturating_add(1);
        let mut zero_candidate_bound = valid_client_preselection_parameters();
        zero_candidate_bound.requested_candidate_bound = 0;
        let mut excessive_candidate_bound = valid_client_preselection_parameters();
        excessive_candidate_bound.requested_candidate_bound =
            MAXIMUM_SELECTION_CANDIDATES.saturating_add(1);
        let mut zero_minimum_capacity = valid_client_preselection_parameters();
        zero_minimum_capacity.minimum_capacity =
            Bandwidth::new(0, 10).expect("bounded zero minimum capacity");
        let mut ceiling_below_minimum = valid_client_preselection_parameters();
        ceiling_below_minimum.conservative_capacity_ceiling =
            Bandwidth::new(5, 5).expect("bounded low ceiling");
        let mut local_below_ceiling = valid_client_preselection_parameters();
        local_below_ceiling.local_profile_capacity =
            Bandwidth::new(50, 50).expect("bounded low local capacity");

        for (case, invalid) in [
            ("unspecified transport", unspecified_transport),
            ("unspecified family", unspecified_family),
            ("zero minimum relay count", zero_minimum_relays),
            ("inverted relay range", inverted_relay_range),
            ("excessive relay bound", excessive_relays),
            ("zero candidate bound", zero_candidate_bound),
            ("excessive candidate bound", excessive_candidate_bound),
            ("zero minimum capacity", zero_minimum_capacity),
            ("ceiling below minimum capacity", ceiling_below_minimum),
            ("local profile below ceiling", local_below_ceiling),
        ] {
            let (reply, response) = oneshot::channel();
            fixture
                .runtime
                .begin_client_preselection(invalid, reply, &fixture.state)
                .await;
            assert!(
                matches!(
                    response.await.expect("typed rejection"),
                    Err(ClientPreselectionError::InvalidParameters)
                ),
                "case: {case}"
            );
            assert!(
                matches!(
                    fixture.runtime.client_preselection,
                    ClientPreselectionOwner::Available(_)
                ),
                "case: {case}"
            );
            assert_eq!(
                fixture.runtime.route_snapshot_build_attempts.get(),
                0,
                "case: {case}"
            );
        }
    }

    #[tokio::test]
    async fn connected_client_preselection_installs_active_slot_with_exact_owner_clocks() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            control_service: _control_service,
            response,
            began_before,
            began_after,
        } = Box::pin(active_client_preselection_fixture()).await;
        let ClientPreselectionOwner::Active(active) = &fixture.runtime.client_preselection else {
            panic!("connected dispatch must remain active");
        };
        let earliest_request_deadline = began_before
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .expect("request clock");
        let latest_request_deadline = began_after
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .expect("request clock");
        let earliest_attempt_deadline = began_before
            .checked_add(CLIENT_PRESELECTION_TIMEOUT)
            .expect("attempt clock");
        let latest_attempt_deadline = began_after
            .checked_add(CLIENT_PRESELECTION_TIMEOUT)
            .expect("attempt clock");
        assert!(active.request_deadline >= earliest_request_deadline);
        assert!(active.request_deadline <= latest_request_deadline);
        assert!(active.attempt_deadline >= earliest_attempt_deadline);
        assert!(active.attempt_deadline <= latest_attempt_deadline);
        assert!(active.request_deadline < active.attempt_deadline);

        fixture
            .runtime
            .cancel_client_preselection(ClientPreselectionError::Closed);
        assert!(matches!(
            response.await.expect("terminal cancellation"),
            Err(ClientPreselectionError::Closed)
        ));
        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
    }

    #[tokio::test]
    async fn active_client_preselection_caller_drop_vacates_exact_slot_and_cools() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            control_service: _control_service,
            response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        drop(response);

        fixture.runtime.maintain_client_preselection();

        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
    }

    #[tokio::test]
    async fn either_active_client_preselection_deadline_vacates_exact_slot_and_times_out() {
        for deadline in ["request", "attempt"] {
            let ActiveClientPreselectionFixture {
                mut fixture,
                control_service: _control_service,
                response,
                ..
            } = Box::pin(active_client_preselection_fixture()).await;
            let ClientPreselectionOwner::Active(active) = &mut fixture.runtime.client_preselection
            else {
                panic!("connected dispatch must remain active");
            };
            if deadline == "request" {
                active.request_deadline = Instant::now();
            } else {
                active.request_deadline = Instant::now()
                    .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
                    .expect("future request deadline");
                active.attempt_deadline = Instant::now();
            }

            fixture.runtime.maintain_client_preselection();

            assert!(
                matches!(
                    response.await.expect("terminal deadline"),
                    Err(ClientPreselectionError::Timeout)
                ),
                "deadline: {deadline}"
            );
            assert!(
                !fixture
                    .runtime
                    .service
                    .client_preselection_slot_active_for_test(),
                "deadline: {deadline}"
            );
            assert!(
                matches!(
                    fixture.runtime.client_preselection,
                    ClientPreselectionOwner::Cooling(_)
                ),
                "deadline: {deadline}"
            );
        }
    }

    #[tokio::test]
    async fn policy_revocation_cancels_active_client_preselection_and_vacates_slot() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            control_service: _control_service,
            response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        assert!(fixture.state.read().await.policy_active(unix_millis()));
        let (reply, applied) = oneshot::channel();

        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::ApplyPolicy {
                    policy: None,
                    reply,
                },
                &fixture.state,
            )
            .await;

        applied.await.expect("policy reply");
        assert!(matches!(
            response.await.expect("policy cancellation"),
            Err(ClientPreselectionError::Invalidated)
        ));
        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
        assert!(!fixture.state.read().await.policy_active(unix_millis()));
    }

    #[tokio::test]
    async fn shutdown_cancels_active_client_preselection_with_closed_result() {
        let ActiveClientPreselectionFixture {
            fixture,
            control_service: _control_service,
            response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        let RuntimeFixture {
            runtime,
            state,
            control: _control,
            policy: _policy,
            role_store: _role_store,
            directory: _directory,
        } = fixture;
        let (shutdown, shutdown_signal) = watch::channel(false);
        shutdown.send(true).expect("shutdown receiver");

        Box::pin(timeout(
            Duration::from_secs(2),
            runtime.run(state, shutdown_signal),
        ))
        .await
        .expect("runtime shutdown");

        assert!(matches!(
            response.await.expect("shutdown cancellation"),
            Err(ClientPreselectionError::Closed)
        ));
    }

    #[tokio::test]
    async fn exact_outbound_failure_releases_owner_after_bounded_short_cooldown() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            mut control_service,
            response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        let failure =
            next_client_preselection_outbound_failure(&mut fixture.runtime, &mut control_service)
                .await;

        Box::pin(
            fixture
                .runtime
                .handle_sanitized_event(failure, &fixture.state),
        )
        .await;

        assert!(matches!(
            response.await.expect("exact outbound failure"),
            Err(ClientPreselectionError::Transport)
        ));
        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));

        tokio::time::sleep(Duration::from_millis(300)).await;
        fixture.runtime.maintain_client_preselection();
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Available(_)
        ));
    }

    #[tokio::test]
    async fn foreign_service_cancel_retains_owner_until_originating_service_recovers_it() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            control_service: _control_service,
            mut response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        let foreign_identity = Identity::generate();
        let foreign_service = DiscoveryService::new_with_protocol_roles(
            foreign_identity.keypair().clone(),
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("foreign client service");
        let originating_service = std::mem::replace(&mut fixture.runtime.service, foreign_service);

        fixture
            .runtime
            .cancel_client_preselection(ClientPreselectionError::Invalidated);

        let ClientPreselectionOwner::Active(active) = &fixture.runtime.client_preselection else {
            panic!("foreign service must retain affine owner");
        };
        assert_eq!(
            active.terminal_error,
            Some(ClientPreselectionError::Invalidated)
        );
        assert!(originating_service.client_preselection_slot_active_for_test());
        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            response.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let foreign_service = std::mem::replace(&mut fixture.runtime.service, originating_service);
        drop(foreign_service);
        fixture.runtime.maintain_client_preselection();

        assert!(matches!(
            response.await.expect("retained terminal result"),
            Err(ClientPreselectionError::Invalidated)
        ));
        assert!(
            !fixture
                .runtime
                .service
                .client_preselection_slot_active_for_test()
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
    }

    #[tokio::test]
    async fn dropped_client_preselection_caller_stops_before_snapshot_or_state_change() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });
        let (reply, response) = oneshot::channel();
        drop(response);
        fixture
            .runtime
            .begin_client_preselection(
                valid_client_preselection_parameters(),
                reply,
                &fixture.state,
            )
            .await;
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Available(_)
        ));
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), 0);
    }

    #[tokio::test]
    async fn shutdown_rejects_queued_client_preselection_with_closed_result() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });
        let (reply, response) = oneshot::channel();
        fixture
            .control
            .sender
            .send(DiscoveryCommand::BeginClientPreselection {
                parameters: valid_client_preselection_parameters(),
                reply,
            })
            .await
            .expect("queue preselection command");
        fixture.runtime.reject_queued_outbound_commands();
        assert!(matches!(
            response.await.expect("queued shutdown reply"),
            Err(ClientPreselectionError::Closed)
        ));
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Available(_)
        ));
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end regression retains the complete refreshed control lineage"
    )]
    async fn production_client_preselection_accepts_same_lineage_control_refresh() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });
        let initial_ms = unix_millis().saturating_sub(2_000);
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let original_control = install_valid_snapshot_route_for(
            &mut fixture,
            &control_identity,
            &exit_identity,
            initial_ms,
        )
        .await;

        let refresh_ms = unix_millis();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &control_identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                2,
                generate_nonce(),
                refresh_ms,
            )
            .await
            .is_some()
        );
        let refreshed_control = fixture
            .runtime
            .direct_relays
            .get(control_identity.peer_id())
            .expect("refreshed control capability")
            .clone();
        assert_eq!(refreshed_control.node_id, original_control.node_id);
        assert_eq!(refreshed_control.peer_id, original_control.peer_id);
        assert_eq!(refreshed_control.public_key, original_control.public_key);
        assert_eq!(refreshed_control.policy_hash, original_control.policy_hash);
        assert_ne!(
            refreshed_control.advertisement_sequence,
            original_control.advertisement_sequence
        );
        assert_ne!(
            refreshed_control.advertisement_expires_at_ms,
            original_control.advertisement_expires_at_ms
        );
        assert_ne!(
            refreshed_control.advertisement_payload_hash,
            original_control.advertisement_payload_hash
        );

        let retained_exit = fixture
            .runtime
            .forwarded_exits
            .values()
            .next()
            .expect("same-lineage forwarded exit survives refresh");
        assert_eq!(
            retained_exit.control_relay_advertisement_sequence,
            original_control.advertisement_sequence
        );
        assert_eq!(
            retained_exit.control_relay_advertisement_expires_at_ms,
            original_control.advertisement_expires_at_ms
        );
        assert_eq!(
            retained_exit.control_relay_advertisement_payload_hash,
            original_control.advertisement_payload_hash
        );

        let other_relay = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &other_relay,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                refresh_ms,
            )
            .await
            .is_some()
        );

        let (reply, response) = oneshot::channel();
        fixture
            .runtime
            .begin_client_preselection(
                valid_client_preselection_parameters(),
                reply,
                &fixture.state,
            )
            .await;
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Active(_)
        ));
        let failure =
            next_unconnected_client_preselection_outbound_failure(&mut fixture.runtime).await;
        Box::pin(
            fixture
                .runtime
                .handle_sanitized_event(failure, &fixture.state),
        )
        .await;
        assert!(matches!(
            response.await.expect("terminal dispatch result"),
            Err(ClientPreselectionError::Transport)
        ));
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), 1);
    }

    #[tokio::test]
    async fn production_client_preselection_samples_before_request_derived_dispatch_and_cools() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: false,
            exit: false,
        });
        let now_ms = unix_millis();
        let _ = install_valid_snapshot_route(&mut fixture, now_ms).await;
        let other_relay = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                &mut fixture,
                &other_relay,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );

        let (reply, response) = oneshot::channel();
        fixture
            .runtime
            .begin_client_preselection(
                valid_client_preselection_parameters(),
                reply,
                &fixture.state,
            )
            .await;
        let failure =
            next_unconnected_client_preselection_outbound_failure(&mut fixture.runtime).await;
        Box::pin(
            fixture
                .runtime
                .handle_sanitized_event(failure, &fixture.state),
        )
        .await;
        assert!(matches!(
            response.await.expect("terminal dispatch result"),
            Err(ClientPreselectionError::Transport)
        ));
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Cooling(_)
        ));
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), 1);

        let (busy_reply, busy_response) = oneshot::channel();
        fixture
            .runtime
            .begin_client_preselection(
                valid_client_preselection_parameters(),
                busy_reply,
                &fixture.state,
            )
            .await;
        assert!(matches!(
            busy_response.await.expect("cooldown rejection"),
            Err(ClientPreselectionError::Busy)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source contract audits the complete private actor boundary"
    )]
    fn client_preselection_actor_surface_is_typed_private_affine_and_failure_opaque() {
        let source = include_str!("discovery.rs");
        let product = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("product/test boundary")
            .0;
        let parameters = braced_item(product, "pub(crate) struct ClientPreselectionParameters {");
        for field in [
            "transport: Transport,",
            "address_family: ObservationAddressFamily,",
            "minimum_capacity: Bandwidth,",
            "local_profile_capacity: Bandwidth,",
            "conservative_capacity_ceiling: Bandwidth,",
            "minimum_other_relays: usize,",
            "maximum_other_relays: usize,",
            "requested_candidate_bound: usize,",
        ] {
            assert!(parameters.contains(field), "missing typed input {field}");
        }
        for forbidden in [
            "peer",
            "target",
            "endpoint",
            "exit",
            "dispatch",
            "request_id",
            "authority",
        ] {
            assert!(
                !parameters.contains(forbidden),
                "authority input {forbidden}"
            );
        }
        assert!(!parameters.contains("#[derive("));

        let owner = braced_item(product, "enum ClientPreselectionOwner {");
        for state in [
            "Available(PreselectionAttemptGate),",
            "Active(ActiveClientPreselection),",
            "Cooling(CoolingPreselectionAttemptGate),",
            "Closed,",
            "Lost,",
        ] {
            assert!(owner.contains(state), "missing owner state {state}");
        }
        assert!(!product.contains("pub enum ClientPreselectionOwner"));
        assert!(!product.contains("impl Clone for ClientPreselectionOwner"));
        assert!(!product.contains("matches_request_id"));
        assert!(!product.contains("preselection_dispatch_id"));
        let active = braced_item(product, "struct ActiveClientPreselection {");
        assert!(active.contains("request_deadline: Instant,"));
        assert!(active.contains("attempt_deadline: Instant,"));
        assert!(active.contains("terminal_error: Option<ClientPreselectionError>,"));

        let begin = braced_item(product, "async fn begin_client_preselection(");
        let snapshot = begin
            .find("build_route_candidate_snapshot(")
            .expect("actor snapshot");
        let sampling = begin
            .find("narrow_route_candidate_snapshot(snapshot, scope)")
            .expect("actor sampler");
        let gate = begin.find("gate.begin(").expect("affine gate begin");
        let dispatch = begin
            .find("pending.dispatch(&mut self.service)")
            .expect("request-derived dispatch");
        let request_deadline = begin
            .find("let Some(request_deadline) = Instant::now()")
            .expect("conservative request deadline");
        assert!(
            snapshot < sampling
                && sampling < request_deadline
                && request_deadline < gate
                && gate < dispatch
        );
        assert!(begin.contains(
            ".checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)\n            .map(|deadline| deadline.min(attempt_deadline))"
        ));

        let response = braced_item(product, "fn handle_client_preselection_response(");
        let terminal = response
            .find("if let Some(error) = active.terminal_error")
            .expect("terminal Retained guard");
        let bind = response
            .find("dispatch.bind_response(&mut self.service, arrival)")
            .expect("opaque bind");
        let transition_clock = response
            .find("let transition_started_at = Instant::now();")
            .expect("pre-bind transition clock");
        let exact_join = response
            .find("completed.join_transport_proofs(transports)")
            .expect("exact transport join");
        let fresh = response
            .find("prepare_preselection_evidence(fresh)")
            .expect("private Fresh handoff");
        assert!(terminal < transition_clock && transition_clock < bind);
        assert!(bind < exact_join && exact_join < fresh);
        assert!(response.contains(
            "let Some(request_deadline) = transition_started_at\n                    .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)"
        ));
        let bind_failure = response
            .split_once("Err(failure) => {")
            .expect("bind failure")
            .1
            .split_once("return Some(\"PRESELECTION_RESPONSE_REJECTED\");")
            .expect("bind failure end")
            .0;
        assert!(
            bind_failure.contains("ClientPreselectionError::Transport,\n                    None,")
        );

        let local_failure = braced_item(product, "fn install_local_client_preselection_failure(");
        assert!(local_failure.contains("failure: PreselectionLocalRecovery,"));
        assert!(!local_failure.contains("Retained"));
        let retained = braced_item(
            product,
            "fn install_client_preselection_transition_failure(",
        );
        assert!(retained.contains("PreselectionOwnerTransitionFailure::Retained(dispatch)"));
        assert!(retained.contains("ClientPreselectionOwner::Active(ActiveClientPreselection"));
        assert!(retained.contains("terminal_error: retained_terminal_error,"));
        assert!(!retained.contains("PreselectionOwnerTransitionFailure::Retained(_)"));
        let cancel = braced_item(product, "fn cancel_active_client_preselection(");
        assert!(cancel.contains("Some(error),"));
        assert_eq!(
            product
                .matches("Some(ClientPreselectionError::Transport),")
                .count(),
            2,
        );

        let failure_handler =
            braced_item(product, "fn handle_client_preselection_outbound_failure(");
        assert!(failure_handler.contains("dispatch.consume_outbound_failure("));
        assert!(failure_handler.contains("PreselectionOwnerTransitionFailure::Retained(dispatch)"));
        assert!(product.contains("PRESELECTION_OUTBOUND_CONNECTION_CLOSED"));
        assert!(product.contains("PRESELECTION_OUTBOUND_FAILURE_UNOWNED"));
        let maintenance = braced_item(product, "fn maintain_client_preselection(");
        assert!(maintenance.contains("active.request_deadline"));
        assert!(maintenance.contains("active.attempt_deadline"));
        assert!(maintenance.contains("active.reply.is_closed()"));
        assert!(maintenance.contains("active.terminal_error.is_some()"));
        assert!(maintenance.contains("cancel_active_client_preselection("));

        let policy = product
            .split_once("DiscoveryCommand::ApplyPolicy { policy, reply } => {")
            .expect("policy arm")
            .1
            .split_once("DiscoveryCommand::RouteCandidateSnapshot")
            .expect("policy arm end")
            .0;
        assert!(
            policy
                .find("cancel_client_preselection(")
                .expect("policy owner cancellation")
                < policy
                    .find("state.write().await.set_policy(policy)")
                    .expect("policy state mutation")
        );
        assert!(
            product
                .find("self.cancel_client_preselection(ClientPreselectionError::Closed);")
                .expect("shutdown owner cancellation")
                < product
                    .find("self.fail_all_outbound_reservations(")
                    .expect("shutdown reservation failure")
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one provenance-drift matrix exercises every fail-closed mutation"
    )]
    async fn route_snapshot_rejects_external_and_forwarded_control_provenance_drift() {
        for mutation in 0_u8..7 {
            let mut fixture = fixture(test_client_roles());
            let now_ms = unix_millis();
            let (control, exit_peer) = install_valid_snapshot_route(&mut fixture, now_ms).await;
            let baseline = route_snapshot_at(&mut fixture, 10, now_ms)
                .await
                .expect("authentic baseline snapshot");
            assert!(
                baseline
                    .direct_relays()
                    .iter()
                    .any(|candidate| candidate.capability().peer_id == control.peer_id)
            );
            assert_eq!(baseline.forwarded_exits().len(), 1);

            let forwarded_key = ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            };
            let exit_node_id = fixture
                .runtime
                .forwarded_exits
                .get(&forwarded_key)
                .expect("forwarded baseline capability")
                .exit_node_id;
            match mutation {
                0 => {
                    let capability = fixture
                        .runtime
                        .direct_relays
                        .get_mut(&control.peer_id)
                        .expect("control capability");
                    capability.advertisement_payload_hash =
                        capability.advertisement_payload_hash.xor_for_test();
                }
                1 => {
                    let accepted = fixture
                        .runtime
                        .accepted_advertisements
                        .get_mut(&control.node_id)
                        .expect("control fingerprint");
                    accepted.fingerprint.payload_hash =
                        accepted.fingerprint.payload_hash.xor_for_test();
                }
                2 => {
                    let forwarded = fixture
                        .runtime
                        .forwarded_exits
                        .get_mut(&forwarded_key)
                        .expect("forwarded capability");
                    forwarded.control_relay_advertisement_payload_hash = forwarded
                        .control_relay_advertisement_payload_hash
                        .xor_for_test();
                }
                3 => {
                    let forwarded = fixture
                        .runtime
                        .forwarded_exits
                        .get_mut(&forwarded_key)
                        .expect("forwarded capability");
                    forwarded.exit_advertisement_payload_hash =
                        forwarded.exit_advertisement_payload_hash.xor_for_test();
                }
                4 => {
                    let accepted = fixture
                        .runtime
                        .accepted_advertisements
                        .get_mut(&exit_node_id)
                        .expect("exit fingerprint");
                    accepted.fingerprint.payload_hash =
                        accepted.fingerprint.payload_hash.xor_for_test();
                }
                5 => {
                    let forwarded = fixture
                        .runtime
                        .forwarded_exits
                        .get_mut(&forwarded_key)
                        .expect("forwarded capability");
                    forwarded.control_relay_advertisement_sequence = forwarded
                        .control_relay_advertisement_sequence
                        .saturating_add(1);
                }
                6 => {
                    let forwarded = fixture
                        .runtime
                        .forwarded_exits
                        .get_mut(&forwarded_key)
                        .expect("forwarded capability");
                    forwarded.control_relay_advertisement_expires_at_ms = forwarded
                        .control_relay_advertisement_expires_at_ms
                        .saturating_add(1_000);
                }
                _ => unreachable!(),
            }

            let drifted = route_snapshot_at(&mut fixture, 10, now_ms)
                .await
                .expect("hash drift is filtered, not surfaced");
            assert!(
                drifted.forwarded_exits().is_empty(),
                "forwarded control-advertisement drift must remain unavailable: mutation {mutation}"
            );
            let control_present = drifted
                .direct_relays()
                .iter()
                .any(|candidate| candidate.capability().peer_id == control.peer_id);
            assert_eq!(control_present, mutation >= 2, "mutation {mutation}");
        }
    }

    async fn install_direct_only_snapshot_exit(
        fixture: &mut RuntimeFixture,
        now_ms: u64,
    ) -> Libp2pPeerId {
        let identity = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                &identity,
                RolesConfig {
                    client: false,
                    relay: false,
                    exit: true,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_none(),
            "direct provenance never mints exit capability"
        );
        identity.peer_id().to_owned()
    }

    async fn install_conflicted_snapshot_relay(
        fixture: &mut RuntimeFixture,
        now_ms: u64,
    ) -> Libp2pPeerId {
        let identity = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                &identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );
        let capability = fixture
            .runtime
            .direct_relays
            .get(identity.peer_id())
            .expect("conflicted capability")
            .clone();
        fixture.runtime.record_privacy_conflict(
            capability.peer_id,
            capability.advertisement_sequence,
            capability.advertisement_expires_at_ms,
        );
        capability.peer_id
    }

    async fn install_expired_snapshot_relay(
        fixture: &mut RuntimeFixture,
        now_ms: u64,
    ) -> Libp2pPeerId {
        let identity = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                &identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );
        let peer = identity.peer_id().to_owned();
        fixture
            .runtime
            .direct_relays
            .get_mut(&peer)
            .expect("expired capability")
            .expires_at_ms = now_ms;
        peer
    }

    async fn install_self_snapshot_relay(
        fixture: &mut RuntimeFixture,
        now_ms: u64,
    ) -> Libp2pPeerId {
        let identity = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                &identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );
        let peer = identity.peer_id().to_owned();
        fixture.runtime.local_node_id = fixture
            .runtime
            .direct_relays
            .get(&peer)
            .expect("self candidate")
            .node_id;
        peer
    }

    async fn install_orphan_snapshot_exit(fixture: &mut RuntimeFixture, now_ms: u64) {
        let control_identity = Identity::generate();
        let control = install_control(fixture, &control_identity, now_ms);
        let exit = Identity::generate();
        assert!(
            ingest_forwarded_snapshot_exit(fixture, &control, &exit, 1, generate_nonce(), now_ms)
                .await
                .is_some()
        );
        fixture.runtime.direct_relays.remove(&control.peer_id);
    }

    async fn install_ambiguous_snapshot_exit(
        fixture: &mut RuntimeFixture,
        first_control: &DirectRelayCapability,
        now_ms: u64,
    ) -> (DirectRelayCapability, Libp2pPeerId) {
        let second_identity = Identity::generate();
        assert!(
            ingest_direct_snapshot_advertisement(
                fixture,
                &second_identity,
                RolesConfig {
                    client: false,
                    relay: true,
                    exit: false,
                },
                1,
                generate_nonce(),
                now_ms,
            )
            .await
            .is_some()
        );
        let second_control = fixture
            .runtime
            .direct_relays
            .get(second_identity.peer_id())
            .expect("second control")
            .clone();
        let ambiguous_exit = Identity::generate();
        let ambiguous_peer = ambiguous_exit.peer_id().to_owned();
        let deadline = now_ms.saturating_add(20_000);
        fixture
            .runtime
            .mark_forwarded_exit_target(ambiguous_peer, deadline);
        let advertisement = service_advertisement(
            &ambiguous_exit,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        for control in [first_control, &second_control] {
            assert!(
                fixture
                    .runtime
                    .ingest_advertisement(
                        ambiguous_peer,
                        advertisement.clone(),
                        forwarded_provenance(control, &ambiguous_exit, deadline),
                        &fixture.state,
                    )
                    .await
                    .is_some()
            );
        }
        (second_control, ambiguous_peer)
    }

    async fn install_pending_direct_snapshot_exit(
        fixture: &mut RuntimeFixture,
        control: &DirectRelayCapability,
        now_ms: u64,
    ) -> Libp2pPeerId {
        let exit = Identity::generate();
        assert!(
            ingest_forwarded_snapshot_exit(fixture, control, &exit, 1, generate_nonce(), now_ms)
                .await
                .is_some()
        );
        let peer = exit.peer_id().to_owned();
        let request = fixture
            .runtime
            .service
            .request_relay_advertisement(&peer)
            .expect("bounded pending direct request");
        fixture
            .runtime
            .relay_advertisement_requests
            .insert(request, peer);
        peer
    }

    #[tokio::test]
    async fn route_candidate_snapshot_excludes_expired_conflicted_unpaired_and_direct_exit_records()
    {
        let mut fixture = fixture(test_client_roles());
        let now_ms = unix_millis();

        let (control, valid_exit_peer) = install_valid_snapshot_route(&mut fixture, now_ms).await;
        let direct_exit_peer = install_direct_only_snapshot_exit(&mut fixture, now_ms).await;
        let conflicted_peer = install_conflicted_snapshot_relay(&mut fixture, now_ms).await;
        let expired_peer = install_expired_snapshot_relay(&mut fixture, now_ms).await;
        let self_peer = install_self_snapshot_relay(&mut fixture, now_ms).await;

        install_orphan_snapshot_exit(&mut fixture, now_ms).await;
        let (second_control, ambiguous_peer) =
            install_ambiguous_snapshot_exit(&mut fixture, &control, now_ms).await;
        let pending_peer =
            install_pending_direct_snapshot_exit(&mut fixture, &control, now_ms).await;

        let snapshot = route_snapshot_at(&mut fixture, 50, now_ms)
            .await
            .expect("fail-closed filtered snapshot");
        let direct_peers = snapshot
            .direct_relays()
            .iter()
            .map(|candidate| candidate.capability().peer_id)
            .collect::<HashSet<_>>();
        assert!(direct_peers.contains(&control.peer_id));
        assert!(direct_peers.contains(&second_control.peer_id));
        assert!(!direct_peers.contains(&conflicted_peer));
        assert!(!direct_peers.contains(&expired_peer));
        assert!(!direct_peers.contains(&self_peer));
        assert!(!direct_peers.contains(&direct_exit_peer));

        assert_eq!(snapshot.forwarded_exits().len(), 1);
        assert_eq!(
            snapshot.forwarded_exits()[0].capability().exit_peer_id,
            valid_exit_peer
        );
        assert!(
            snapshot
                .forwarded_exits()
                .iter()
                .all(|candidate| candidate.capability().exit_peer_id != ambiguous_peer)
        );
        assert!(
            snapshot
                .forwarded_exits()
                .iter()
                .all(|candidate| candidate.capability().exit_peer_id != pending_peer)
        );
    }

    #[tokio::test]
    async fn route_candidate_snapshot_store_failure_and_dropped_reply_fail_closed() {
        let mut fixture = fixture(test_client_roles());
        fixture.runtime.route_snapshot_store_failure = true;
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::RouteCandidateSnapshot {
                    requested_candidates: 10,
                    reply,
                },
                &fixture.state,
            )
            .await;
        assert!(matches!(
            received.await.expect("typed store failure"),
            Err(RouteCandidateSnapshotError::StoreUnavailable)
        ));

        fixture.runtime.route_snapshot_store_failure = false;
        let build_attempts_before_drop = fixture.runtime.route_snapshot_build_attempts.get();
        let expired = Identity::generate();
        let expired_capability = direct_capability(&expired, &fixture.policy, 1, 1);
        fixture
            .runtime
            .direct_relays
            .insert(expired_capability.peer_id, expired_capability.clone());
        let (dropped_reply, dropped_receiver) = oneshot::channel();
        drop(dropped_receiver);
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::RouteCandidateSnapshot {
                    requested_candidates: 200,
                    reply: dropped_reply,
                },
                &fixture.state,
            )
            .await;
        assert_eq!(
            fixture
                .runtime
                .direct_relays
                .get(&expired_capability.peer_id),
            Some(&expired_capability),
            "dropped callers trigger neither purge nor bounded crypto/store work"
        );
        assert_eq!(
            fixture.runtime.route_snapshot_build_attempts.get(),
            build_attempts_before_drop,
            "dropped callers never enter the store/crypto snapshot builder"
        );
    }

    #[test]
    fn non_fetch_wrapper_deadline_must_equal_signed_expiry() {
        let now_ms = unix_millis();
        let probe = signed_probe_datapath_fixture(now_ms);
        let exact = ExitForwardRequest::new(
            probe.request.nonce[..FORWARD_ID_BYTES].to_vec(),
            probe.request.control_relay_node_id.clone(),
            probe.request.control_relay_peer_id.clone(),
            probe.control_public_key.to_vec(),
            probe.request.exit_peer_id.clone(),
            probe.request.exit_node_id.clone(),
            probe.request.expires_at_ms,
            ExitForwardOperation::ProbePermit,
            probe.signed_request.clone(),
        )
        .expect("exact wrapper");
        assert!(forward_request_scope_matches(
            &exact,
            ExitForwardOperation::ProbePermit,
            now_ms
        ));

        for substituted_deadline in [
            probe.request.expires_at_ms.saturating_sub(1),
            probe.request.expires_at_ms.saturating_add(1),
        ] {
            let substituted = ExitForwardRequest::new(
                probe.request.nonce[..FORWARD_ID_BYTES].to_vec(),
                probe.request.control_relay_node_id.clone(),
                probe.request.control_relay_peer_id.clone(),
                probe.control_public_key.to_vec(),
                probe.request.exit_peer_id.clone(),
                probe.request.exit_node_id.clone(),
                substituted_deadline,
                ExitForwardOperation::ProbePermit,
                probe.signed_request.clone(),
            )
            .expect("well-formed substituted wrapper");
            assert!(!forward_request_scope_matches(
                &substituted,
                ExitForwardOperation::ProbePermit,
                now_ms
            ));
        }
    }

    #[test]
    fn execute_probe_requires_exact_typed_nested_authority() {
        let now_ms = unix_millis();
        let probe = signed_probe_datapath_fixture(now_ms);
        assert!(datapath_request_scope_matches(
            &probe.wrapper,
            DatapathRelayOperation::ExecuteProbe,
            now_ms
        ));

        let mut wrong_request_id = probe.wrapper.request_id().to_vec();
        wrong_request_id[0] ^= 0xff;
        let wrong_request_id = DatapathRelayRequest::new(
            wrong_request_id,
            probe.wrapper.relay_node_id().to_vec(),
            probe.wrapper.relay_peer_id().to_vec(),
            probe.wrapper.deadline_unix_ms(),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request.clone(),
            probe.signed_permit.clone(),
        )
        .expect("well-formed request-id substitution");
        assert!(!datapath_request_scope_matches(
            &wrong_request_id,
            DatapathRelayOperation::ExecuteProbe,
            now_ms
        ));

        let wrong_deadline = DatapathRelayRequest::new(
            probe.wrapper.request_id().to_vec(),
            probe.wrapper.relay_node_id().to_vec(),
            probe.wrapper.relay_peer_id().to_vec(),
            probe.wrapper.deadline_unix_ms().saturating_sub(1),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request.clone(),
            probe.signed_permit.clone(),
        )
        .expect("well-formed deadline substitution");
        assert!(!datapath_request_scope_matches(
            &wrong_deadline,
            DatapathRelayOperation::ExecuteProbe,
            now_ms
        ));

        let other_relay = Identity::generate();
        let other_relay_public_key = other_relay
            .ed25519_public_key_bytes()
            .expect("other relay public key");
        let wrong_relay = DatapathRelayRequest::new(
            probe.wrapper.request_id().to_vec(),
            node_id_from_public_key(&other_relay_public_key).to_vec(),
            other_relay.peer_id().to_bytes(),
            probe.wrapper.deadline_unix_ms(),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request.clone(),
            probe.signed_permit.clone(),
        )
        .expect("well-formed relay substitution");
        assert!(!datapath_request_scope_matches(
            &wrong_relay,
            DatapathRelayOperation::ExecuteProbe,
            now_ms
        ));

        let other_probe = signed_probe_datapath_fixture(now_ms);
        let cross_signed_permit = DatapathRelayRequest::new(
            probe.wrapper.request_id().to_vec(),
            probe.wrapper.relay_node_id().to_vec(),
            probe.wrapper.relay_peer_id().to_vec(),
            probe.wrapper.deadline_unix_ms(),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request,
            other_probe.signed_permit,
        )
        .expect("well-formed cross-signed permit");
        assert!(!datapath_request_scope_matches(
            &cross_signed_permit,
            DatapathRelayOperation::ExecuteProbe,
            now_ms
        ));
    }

    #[tokio::test]
    async fn inbound_datapath_replies_once_only_for_exact_typed_authority() {
        let fixture = fixture(test_client_roles());
        let now_ms = unix_millis();
        let local_node_id = fixture.runtime.local_node_id;
        let local_peer = *fixture.runtime.service.local_peer_id();
        let authenticated_client = Identity::generate().peer_id().to_owned();
        let probe =
            signed_probe_datapath_fixture_for_relay(now_ms, local_node_id, local_peer.to_bytes());
        let responses = inbound_datapath_unavailable_response(
            &probe.wrapper,
            authenticated_client,
            local_node_id,
            local_peer,
            true,
            now_ms,
        )
        .into_iter()
        .collect::<Vec<_>>();
        assert_eq!(responses.len(), 1);
        assert_eq!(
            responses[0].validated_status(),
            Ok(ForwardStatus::Unavailable)
        );

        let mut substituted_id = probe.wrapper.request_id().to_vec();
        substituted_id[0] ^= 0xff;
        let wrong_id = DatapathRelayRequest::new(
            substituted_id,
            local_node_id.to_vec(),
            local_peer.to_bytes(),
            probe.wrapper.deadline_unix_ms(),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request.clone(),
            probe.signed_permit.clone(),
        )
        .expect("well-formed request-id substitution");
        let wrong_deadline = DatapathRelayRequest::new(
            probe.wrapper.request_id().to_vec(),
            local_node_id.to_vec(),
            local_peer.to_bytes(),
            probe.wrapper.deadline_unix_ms().saturating_sub(1),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request.clone(),
            probe.signed_permit.clone(),
        )
        .expect("well-formed deadline substitution");
        let other_probe =
            signed_probe_datapath_fixture_for_relay(now_ms, local_node_id, local_peer.to_bytes());
        let cross_signed_permit = DatapathRelayRequest::new(
            probe.wrapper.request_id().to_vec(),
            local_node_id.to_vec(),
            local_peer.to_bytes(),
            probe.wrapper.deadline_unix_ms(),
            DatapathRelayOperation::ExecuteProbe,
            probe.signed_request,
            other_probe.signed_permit,
        )
        .expect("well-formed cross-signed permit");
        for substituted in [&wrong_id, &wrong_deadline, &cross_signed_permit] {
            assert!(
                inbound_datapath_unavailable_response(
                    substituted,
                    authenticated_client,
                    local_node_id,
                    local_peer,
                    true,
                    now_ms,
                )
                .is_none()
            );
        }
        assert!(
            inbound_datapath_unavailable_response(
                &probe.wrapper,
                local_peer,
                local_node_id,
                local_peer,
                true,
                now_ms,
            )
            .is_none()
        );
        assert!(
            inbound_datapath_unavailable_response(
                &probe.wrapper,
                authenticated_client,
                local_node_id,
                local_peer,
                false,
                now_ms,
            )
            .is_none()
        );
    }

    #[test]
    fn reserve_path_requires_exact_typed_nested_authority() {
        let now_ms = unix_millis();
        let route = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], now_ms)
            .expect("signed route fixture");
        let signed_request = route.relay_request(0).expect("relay request").to_vec();
        let mut replay = ReplayCache::new(8).expect("replay cache");
        let verified = verify_control_message::<RelayReservationRequest>(
            &signed_request,
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified relay request");
        let request_nonce = *verified.nonce();
        let request_timestamp_ms = verified.timestamp_ms();
        let request_expires_at_ms = verified.expires_at_ms();
        let mut request = verified.into_message();
        let relay_node_id = route.relay_node_id(0).expect("relay node");
        let relay_peer_id = route.relay_peer_id(0).expect("relay peer").to_vec();
        let wrapper = DatapathRelayRequest::new(
            request_nonce[..FORWARD_ID_BYTES].to_vec(),
            relay_node_id.to_vec(),
            relay_peer_id.clone(),
            request_expires_at_ms,
            DatapathRelayOperation::ReservePath,
            signed_request,
            Vec::new(),
        )
        .expect("valid ReservePath wrapper");
        assert!(datapath_request_scope_matches(
            &wrapper,
            DatapathRelayOperation::ReservePath,
            now_ms
        ));

        let other = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], now_ms)
            .expect("other signed route fixture");
        request.exit_authorization = other
            .relay_authorization(0)
            .expect("other exit authorization")
            .to_vec();
        let cross_nested_request = sign_control_message(
            &request,
            route.client_key(),
            request_timestamp_ms,
            request_expires_at_ms,
            request_nonce,
            TimePolicy::default(),
        )
        .expect("cross-nested request remains syntactically signed");
        let cross_nested = DatapathRelayRequest::new(
            request_nonce[..FORWARD_ID_BYTES].to_vec(),
            relay_node_id.to_vec(),
            relay_peer_id,
            request_expires_at_ms,
            DatapathRelayOperation::ReservePath,
            cross_nested_request,
            Vec::new(),
        )
        .expect("well-formed cross-nested wrapper");
        assert!(!datapath_request_scope_matches(
            &cross_nested,
            DatapathRelayOperation::ReservePath,
            now_ms
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "an exact test barrier proves expiry at the commit boundary is mutation-free"
    )]
    #[tokio::test]
    async fn forwarded_ingest_expiry_at_commit_boundary_has_no_response_mutation() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let advertisement_now_ms = unix_millis();
        let control = install_control(&mut fixture, &control_identity, advertisement_now_ms);
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            advertisement_now_ms,
            &fixture.directory,
        );
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);

        let gate = AdvertisementCommitTestGate::new();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .before_commit = Some(gate.clone());
        let operation_expires_at_ms = unix_millis().saturating_add(100);
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, operation_expires_at_ms);
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(exit_peer, operation_expires_at_ms)
        );
        let provenance = forwarded_provenance(&control, &exit_identity, operation_expires_at_ms);
        let ingest = fixture.runtime.ingest_advertisement(
            exit_peer,
            advertisement,
            provenance,
            &fixture.state,
        );
        let expire_at_boundary = async {
            gate.wait_until_entered().await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            gate.release();
        };
        let (accepted, ()) = tokio::join!(ingest, expire_at_boundary);
        assert!(accepted.is_none());

        assert!(fixture.runtime.forwarded_ad_replays.is_empty());
        assert!(
            !fixture
                .runtime
                .accepted_advertisements
                .contains_key(&exit_node_id)
        );
        assert!(
            !fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
        );
        let stored = fixture
            .runtime
            .store
            .load_candidates(UnixTime::from_secs(unix_millis() / 1_000), 10)
            .expect("stored candidates");
        assert!(stored.iter().all(|candidate| {
            candidate.advertisement.node_id.as_str() != hex::encode(exit_node_id)
        }));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "three pre-ingest fail-closed clocks/authority cases share one fixture"
    )]
    #[tokio::test]
    async fn client_fetch_rejects_late_or_revoked_response_before_ingest() {
        for case in 0_u8..3 {
            let mut fixture = fixture(test_client_roles());
            let control_identity = Identity::generate();
            let exit_identity = Identity::generate();
            let exit_peer = exit_identity.peer_id().to_owned();
            let now_ms = unix_millis();
            let deadline = now_ms.saturating_add(20_000);
            let forward_id = [140_u8.saturating_add(case); FORWARD_ID_BYTES];
            let (control, request) = authorize_fetch(
                &mut fixture,
                &control_identity,
                exit_peer,
                forward_id,
                deadline,
            );
            let (reply, received) = oneshot::channel();
            fixture
                .runtime
                .begin_client_forward(control.peer_id, request, reply);
            let request_id = *fixture
                .runtime
                .pending_client_forwards
                .keys()
                .next()
                .expect("one pending Fetch");
            match case {
                0 => {
                    fixture
                        .runtime
                        .pending_client_forwards
                        .get_mut(&request_id)
                        .expect("pending Fetch")
                        .attempt_deadline = Instant::now()
                        .checked_sub(Duration::from_millis(1))
                        .expect("past instant");
                }
                1 => {
                    fixture
                        .runtime
                        .pending_client_forwards
                        .get_mut(&request_id)
                        .expect("pending Fetch")
                        .operation_expires_at_ms = now_ms.saturating_sub(1);
                }
                2 => {
                    fixture.runtime.direct_relays.remove(&control.peer_id);
                }
                _ => unreachable!("bounded case range"),
            }

            let advertisement = service_advertisement(
                &exit_identity,
                RolesConfig {
                    client: false,
                    relay: false,
                    exit: true,
                },
                &fixture.policy,
                1,
                [150_u8.saturating_add(case); 32],
                now_ms,
                &fixture.directory,
            );
            let exit_public_key = exit_identity
                .ed25519_public_key_bytes()
                .expect("exit public key");
            let exit_node_id = node_id_from_public_key(&exit_public_key);
            let response = ExitForwardResponse::granted(
                forward_id.to_vec(),
                ExitForwardOperation::FetchExitAdvertisement,
                exit_node_id.to_vec(),
                exit_peer.to_bytes(),
                vec![advertisement.into_signed_envelope()],
            )
            .expect("Granted advertisement response");
            assert_eq!(
                fixture
                    .runtime
                    .complete_client_forward(
                        request_id,
                        control.peer_id,
                        &response,
                        &fixture.state,
                    )
                    .await,
                OutboundEventOutcome::InvalidResponse
            );
            assert_eq!(
                received.await.expect("definitive invalid response"),
                Err(OutboundReservationError::InvalidResponse)
            );
            assert!(fixture.runtime.pending_client_forwards.is_empty());
            assert!(fixture.runtime.client_forward_index.is_empty());
            assert!(
                !fixture
                    .runtime
                    .accepted_advertisements
                    .contains_key(&exit_node_id)
            );
            assert!(
                !fixture
                    .runtime
                    .forwarded_exits
                    .contains_key(&ForwardedExitKey {
                        control_relay_peer: control.peer_id,
                        exit_peer,
                    })
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one re-entrant advertisement refresh and idempotent completion invariant"
    )]
    #[tokio::test]
    async fn client_fetch_purges_expired_cap_after_owning_pending() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let forward_id = [160; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline,
        );
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("one pending Fetch");
        fixture.runtime.forwarded_exits.insert(
            ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            },
            ForwardedExitCapability {
                control_relay_node_id: control.node_id,
                control_relay_peer_id: control.peer_id,
                control_relay_public_key: control.public_key,
                control_relay_advertisement_sequence: control.advertisement_sequence,
                control_relay_advertisement_expires_at_ms: control.advertisement_expires_at_ms,
                control_relay_advertisement_payload_hash: control.advertisement_payload_hash,
                exit_node_id,
                exit_peer_id: exit_peer,
                exit_public_key,
                exit_advertisement_sequence: 1,
                exit_advertisement_expires_at_ms: now_ms.saturating_sub(1),
                exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(exit_node_id),
                policy_version: fixture.policy.manifest_version(),
                policy_hash: *fixture.policy.policy_hash(),
                policy_expires_at_ms: fixture.policy.expires_at_ms(),
                expires_at_ms: now_ms.saturating_sub(1),
            },
        );
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
                .expect("expired old capability")
                .expires_at_ms
                <= unix_millis()
        );
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            2,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let response = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
            vec![advertisement.into_signed_envelope()],
        )
        .expect("Granted advertisement response");
        assert_eq!(
            fixture
                .runtime
                .complete_client_forward(request_id, control.peer_id, &response, &fixture.state,)
                .await,
            OutboundEventOutcome::Completed
        );
        assert_eq!(
            received.await.expect("one completion"),
            Ok(response.clone())
        );
        assert!(fixture.runtime.pending_client_forwards.is_empty());
        assert!(fixture.runtime.client_forward_index.is_empty());
        assert_eq!(fixture.runtime.completed_client_forwards.len(), 1);
        assert_eq!(
            fixture
                .runtime
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
                .expect("refreshed exit capability")
                .exit_advertisement_sequence,
            2
        );
        assert_eq!(
            fixture
                .runtime
                .complete_client_forward(request_id, control.peer_id, &response, &fixture.state,)
                .await,
            OutboundEventOutcome::Unexpected
        );
        assert_eq!(fixture.runtime.completed_client_forwards.len(), 1);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one relay re-entrant advertisement refresh and completion invariant"
    )]
    #[tokio::test]
    async fn relay_fetch_purges_expired_cap_after_owning_pending() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: true,
            exit: false,
        });
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let local_peer = *fixture.runtime.service.local_peer_id();
        let control = DirectRelayCapability {
            node_id: fixture.runtime.local_node_id,
            peer_id: local_peer,
            public_key: fixture.runtime.local_public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms: now_ms.saturating_add(60_000),
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(
                fixture.runtime.local_node_id,
            ),
            policy_version: fixture.policy.manifest_version(),
            policy_hash: *fixture.policy.policy_hash(),
            policy_expires_at_ms: fixture.policy.expires_at_ms(),
            expires_at_ms: now_ms.saturating_add(60_000),
        };
        fixture.runtime.local_relay_snapshot = Some(control.clone());
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, deadline);
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(exit_peer, deadline)
        );
        let forward_id = [170; FORWARD_ID_BYTES];
        let request = fetch_request(&control, exit_peer, forward_id, deadline);
        let canonical_request = encode_canonical(
            &request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        )
        .expect("canonical relay request");
        let request_id = fixture
            .runtime
            .service
            .request_exit_forward_upstream(&exit_peer, request.into())
            .expect("upstream dispatch");
        let key = RelayForwardKey {
            authenticated_client_peer: Identity::generate().peer_id().to_owned(),
            forward_id,
        };
        fixture.runtime.relay_forward_index.insert(key, request_id);
        fixture.runtime.pending_relay_forwards.insert(
            request_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                expected_exit_node_id: None,
                authorized_control: control.clone(),
                authorized_exit: None,
                reserved_bytes: ledger_reservation_bytes(canonical_request.len())
                    .expect("ledger reservation"),
                canonical_request,
                operation_expires_at_ms: deadline,
                attempt_deadline: Instant::now() + Duration::from_secs(5),
                dispatch_attempts: 1,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        fixture.runtime.forwarded_exits.insert(
            ForwardedExitKey {
                control_relay_peer: local_peer,
                exit_peer,
            },
            ForwardedExitCapability {
                control_relay_node_id: control.node_id,
                control_relay_peer_id: control.peer_id,
                control_relay_public_key: control.public_key,
                control_relay_advertisement_sequence: control.advertisement_sequence,
                control_relay_advertisement_expires_at_ms: control.advertisement_expires_at_ms,
                control_relay_advertisement_payload_hash: control.advertisement_payload_hash,
                exit_node_id,
                exit_peer_id: exit_peer,
                exit_public_key,
                exit_advertisement_sequence: 1,
                exit_advertisement_expires_at_ms: now_ms.saturating_sub(1),
                exit_advertisement_payload_hash: AdvertisementPayloadHash::for_test(exit_node_id),
                policy_version: fixture.policy.manifest_version(),
                policy_hash: *fixture.policy.policy_hash(),
                policy_expires_at_ms: fixture.policy.expires_at_ms(),
                expires_at_ms: now_ms.saturating_sub(1),
            },
        );
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: local_peer,
                    exit_peer,
                })
                .expect("expired old capability")
                .expires_at_ms
                <= unix_millis()
        );
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            2,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let response = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
            vec![advertisement.into_signed_envelope()],
        )
        .expect("Granted advertisement response");
        assert_eq!(
            Box::pin(fixture.runtime.complete_relay_forward(
                request_id,
                exit_peer,
                response.clone().into(),
                &fixture.state,
            ))
            .await,
            OutboundEventOutcome::Completed
        );
        assert!(fixture.runtime.pending_relay_forwards.is_empty());
        assert!(fixture.runtime.relay_forward_index.is_empty());
        assert_eq!(fixture.runtime.completed_relay_forwards.len(), 1);
        assert_eq!(
            fixture
                .runtime
                .forwarded_exits
                .get(&ForwardedExitKey {
                    control_relay_peer: local_peer,
                    exit_peer,
                })
                .expect("refreshed exit capability")
                .exit_advertisement_sequence,
            2
        );
        assert_eq!(
            Box::pin(fixture.runtime.complete_relay_forward(
                request_id,
                exit_peer,
                response.into(),
                &fixture.state,
            ))
            .await,
            OutboundEventOutcome::Unexpected
        );
        assert_eq!(fixture.runtime.completed_relay_forwards.len(), 1);
    }
    #[allow(
        clippy::too_many_lines,
        reason = "the exact post-commit barrier proves client completion is not reclassified"
    )]
    #[tokio::test]
    async fn client_fetch_after_commit_deadline_is_not_reclassified() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let now_ms = unix_millis();
        let operation_deadline = now_ms.saturating_add(20_000);
        let forward_id = [180; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            operation_deadline,
        );
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("one pending client fetch");
        let attempt_deadline = Instant::now() + Duration::from_millis(500);
        fixture
            .runtime
            .pending_client_forwards
            .get_mut(&request_id)
            .expect("pending client fetch")
            .attempt_deadline = attempt_deadline;

        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let response = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
            vec![advertisement.into_signed_envelope()],
        )
        .expect("Granted advertisement response");
        let gate = AdvertisementCommitTestGate::new();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .after_commit = Some(gate.clone());

        let completion = fixture.runtime.complete_client_forward(
            request_id,
            control.peer_id,
            &response,
            &fixture.state,
        );
        let expire_after_commit = async {
            gate.wait_until_entered().await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            gate.release();
        };
        let (outcome, ()) = tokio::join!(completion, expire_after_commit);

        assert!(Instant::now() >= attempt_deadline);
        assert_eq!(outcome, OutboundEventOutcome::Completed);
        assert_eq!(received.await.expect("client completion"), Ok(response));
        assert_eq!(fixture.runtime.completed_client_forwards.len(), 1);
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: control.peer_id,
                    exit_peer,
                })
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exact post-commit barrier proves relay completion is not reclassified"
    )]
    #[tokio::test]
    async fn relay_fetch_after_commit_deadline_is_not_reclassified() {
        let mut fixture = fixture(RolesConfig {
            client: true,
            relay: true,
            exit: false,
        });
        let now_ms = unix_millis();
        let operation_deadline = now_ms.saturating_add(20_000);
        let local_peer = *fixture.runtime.service.local_peer_id();
        let control = DirectRelayCapability {
            node_id: fixture.runtime.local_node_id,
            peer_id: local_peer,
            public_key: fixture.runtime.local_public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms: now_ms.saturating_add(60_000),
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(
                fixture.runtime.local_node_id,
            ),
            policy_version: fixture.policy.manifest_version(),
            policy_hash: *fixture.policy.policy_hash(),
            policy_expires_at_ms: fixture.policy.expires_at_ms(),
            expires_at_ms: now_ms.saturating_add(60_000),
        };
        fixture.runtime.local_relay_snapshot = Some(control.clone());
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        fixture
            .runtime
            .exit_provider_peers
            .insert(exit_peer, operation_deadline);
        assert!(
            fixture
                .runtime
                .mark_forwarded_exit_target(exit_peer, operation_deadline)
        );
        let forward_id = [182; FORWARD_ID_BYTES];
        let request = fetch_request(&control, exit_peer, forward_id, operation_deadline);
        let canonical_request = encode_canonical(
            &request,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX),
        )
        .expect("canonical relay request");
        let request_id = fixture
            .runtime
            .service
            .request_exit_forward_upstream(&exit_peer, request.into())
            .expect("upstream dispatch");
        let key = RelayForwardKey {
            authenticated_client_peer: Identity::generate().peer_id().to_owned(),
            forward_id,
        };
        fixture.runtime.relay_forward_index.insert(key, request_id);
        let attempt_deadline = Instant::now() + Duration::from_millis(500);
        fixture.runtime.pending_relay_forwards.insert(
            request_id,
            PendingRelayForward {
                key,
                expected_exit_peer: exit_peer,
                operation: ExitForwardOperation::FetchExitAdvertisement,
                expected_exit_node_id: None,
                authorized_control: control,
                authorized_exit: None,
                reserved_bytes: ledger_reservation_bytes(canonical_request.len())
                    .expect("ledger reservation"),
                canonical_request,
                operation_expires_at_ms: operation_deadline,
                attempt_deadline,
                dispatch_attempts: 1,
                client_channels: Vec::new(),
                native_ready: None,
                native_authorization: None,
                native_result: None,
                udp_session: None,
                mptcp_session: None,
                mpquic_session: None,
            },
        );
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let response = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
            vec![advertisement.into_signed_envelope()],
        )
        .expect("Granted advertisement response");
        let gate = AdvertisementCommitTestGate::new();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .after_commit = Some(gate.clone());

        let completion = fixture.runtime.complete_relay_forward(
            request_id,
            exit_peer,
            response.into(),
            &fixture.state,
        );
        let expire_after_commit = async {
            gate.wait_until_entered().await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            gate.release();
        };
        let (outcome, ()) = tokio::join!(completion, expire_after_commit);

        assert!(Instant::now() >= attempt_deadline);
        assert_eq!(outcome, OutboundEventOutcome::Completed);
        assert_eq!(fixture.runtime.completed_relay_forwards.len(), 1);
        assert!(
            fixture
                .runtime
                .forwarded_exits
                .contains_key(&ForwardedExitKey {
                    control_relay_peer: local_peer,
                    exit_peer,
                })
        );
    }

    #[test]
    fn production_helper_expiry_is_rounded_within_signed_authority() {
        let now = unix_seconds();
        let setup_seconds = now.checked_add(60).expect("setup seconds");
        let hard_seconds = now.checked_add(120).expect("hard seconds");
        let finalize = ExitReservationFinalizeRequest {
            route_context_id: vec![0x91; FORWARD_ID_BYTES],
            relay_paths: vec![volparossa_protocol::FinalizedRelayPath {
                path_id: 1,
                ..Default::default()
            }],
            ..Default::default()
        };

        for residue_ms in [1_u64, 999] {
            let setup_ms = setup_seconds
                .checked_mul(1_000)
                .and_then(|value| value.checked_add(residue_ms))
                .expect("setup milliseconds");
            let hard_ms = hard_seconds
                .checked_mul(1_000)
                .and_then(|value| value.checked_add(residue_ms))
                .expect("hard milliseconds");
            let exit = production_exit_prepare_request(&finalize, setup_ms, hard_ms)
                .expect("Exit helper scope");
            let service = production_service_prepare_request(
                [0x92; FORWARD_ID_BYTES],
                ContextRole::Relay,
                1,
                setup_ms,
                hard_ms,
            )
            .expect("service helper scope");

            for prepare in [exit, service] {
                assert_eq!(prepare.setup_expires_at_unix, setup_seconds);
                assert_eq!(prepare.hard_expires_at_unix, hard_seconds);
                assert!(
                    prepare.setup_expires_at_unix * 1_000 <= setup_ms,
                    "helper setup ownership must not outlive signed authority"
                );
                assert!(
                    prepare.hard_expires_at_unix * 1_000 <= hard_ms,
                    "helper hard ownership must not outlive signed authority"
                );
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "a blocked finish proves the completion cache and reply precede refresh"
    )]
    #[tokio::test]
    async fn client_completion_is_cached_and_replied_before_refresh() {
        let mut fixture = fixture(test_client_roles());
        let control_identity = Identity::generate();
        let exit_identity = Identity::generate();
        let exit_peer = exit_identity.peer_id().to_owned();
        let now_ms = unix_millis();
        let deadline = now_ms.saturating_add(20_000);
        let forward_id = [184; FORWARD_ID_BYTES];
        let (control, request) = authorize_fetch(
            &mut fixture,
            &control_identity,
            exit_peer,
            forward_id,
            deadline,
        );
        let (reply, received) = oneshot::channel();
        fixture
            .runtime
            .begin_client_forward(control.peer_id, request, reply);
        let request_id = *fixture
            .runtime
            .pending_client_forwards
            .keys()
            .next()
            .expect("one pending client fetch");
        let exit_public_key = exit_identity
            .ed25519_public_key_bytes()
            .expect("exit public key");
        let exit_node_id = node_id_from_public_key(&exit_public_key);
        let advertisement = service_advertisement(
            &exit_identity,
            RolesConfig {
                client: false,
                relay: false,
                exit: true,
            },
            &fixture.policy,
            1,
            generate_nonce(),
            now_ms,
            &fixture.directory,
        );
        let response = ExitForwardResponse::granted(
            forward_id.to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node_id.to_vec(),
            exit_peer.to_bytes(),
            vec![advertisement.into_signed_envelope()],
        )
        .expect("Granted advertisement response");
        let expected = response.clone();
        let gate = AdvertisementCommitTestGate::new();
        fixture
            .runtime
            .advertisement_commit_test_barriers
            .before_finish = Some(gate.clone());

        let completion = fixture.runtime.complete_client_forward(
            request_id,
            control.peer_id,
            &response,
            &fixture.state,
        );
        let observe_reply_before_finish = async {
            gate.wait_until_entered().await;
            let delivered = timeout(Duration::from_secs(1), received)
                .await
                .expect("reply precedes finish")
                .expect("completion sender remains present");
            assert_eq!(delivered, Ok(expected));
            gate.release();
        };
        let (outcome, ()) = tokio::join!(completion, observe_reply_before_finish);

        assert_eq!(outcome, OutboundEventOutcome::Completed);
        assert_eq!(fixture.runtime.completed_client_forwards.len(), 1);
    }
}
