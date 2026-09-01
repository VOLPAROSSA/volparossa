//! Real libp2p privacy-v4 discovery, forwarding, and verified peerstore ingestion.

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
    collections::{BTreeSet, HashMap},
    fmt,
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use libp2p::{
    Multiaddr, PeerId as Libp2pPeerId, kad,
    multiaddr::Protocol,
    request_response,
    swarm::{ConnectionId, SwarmEvent},
};
use rand_core::{OsRng, RngCore};
#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::{
    sync::{RwLock, mpsc, oneshot, watch},
    time::{Instant, MissedTickBehavior, timeout},
};

use volparossa_config::{Config, RolesConfig};
use volparossa_core::{
    Bandwidth, CapacitySnapshot, NetworkMetadata, NodeAdvertisement as CoreAdvertisement,
    NodeCapabilities, NodeId, NodeQuality, NodeRoles, OperatorId, PeerId as CorePeerId, PolicyHash,
    UnixTime,
};
use volparossa_discovery::{
    AdvertisementResponse, BehaviourEvent, BoundClientPreselectionTransport,
    BoundNativeProbeControlConnection, ClientPreselectionResponseArrival,
    DATAPATH_RELAY_REQUEST_TIMEOUT, DatapathRelayOperation, DatapathRelayRequest,
    DatapathRelayResponse, DiscoveryEvent, DiscoveryProtocolRoles, DiscoveryService,
    EXIT_FORWARD_REQUEST_TIMEOUT, EXIT_FORWARD_UPSTREAM_TIMEOUT, ExitForwardOperation,
    ExitForwardRequest, ExitForwardResponse, ForwardStatus, LocalPreselectionPolicy,
    MAX_CONCURRENT_DATAPATH_RELAY_STREAMS, MAX_CONCURRENT_FORWARDING_STREAMS,
    MAX_FORWARDING_FRAME_BYTES, PRESELECTION_OBSERVATION_REQUEST_TIMEOUT, PeerLink,
    UpstreamExitForwardRequest, UpstreamExitForwardResponse, advertisement_envelope_matches_peer,
    capability, signed_envelope_matches_peer,
};
use volparossa_exit::{ExitService, ExitServiceConfig};
use volparossa_identity::Identity;
use volparossa_local_control::{
    LogLevel, PeerSummary, PolicySnapshot as AgentPolicySnapshot, Reachability,
};
use volparossa_metrics::MetricsRegistry;
use volparossa_peerstore::PeerStore;
use volparossa_policy::VerifiedManifest;
use volparossa_protocol::{
    AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork,
    ClientSessionCapability, ExitCapacityHold, ExitCapacityHoldRequest, ExitReservation,
    ExitReservationConfirmation, ExitReservationFinalizeRequest, MAX_NATIVE_PROBE_LIFETIME_MS,
    NativeProbePathScope, NativeProbePermitRequest, NativeProbeStart,
    NodeAdvertisement as WireAdvertisement, ObservationAddressFamily, PreselectionActorBinding,
    RelayAuthorization, RelayProbePermit, RelayProbePermitRequest, RelayReservationRequest,
    ReplayCache, SignedEnvelope, TimePolicy, Transport, decode_canonical, encode_canonical,
    node_id_from_public_key, verify_control_message, verify_native_probe_permit,
};
use volparossa_relay::{RelayService, RelayServiceConfig};
use volparossa_selection::MAXIMUM_SELECTION_CANDIDATES;

use crate::{
    advertisement::{AdvertisementPublisher, LocalAdvertisementInput},
    roles::RoleStore,
    route_setup::{PreparedPreselectionEvidence, prepare_preselection_evidence},
    state::AgentState,
    unix_millis, unix_seconds,
};

const PEERSTORE_LOAD_BOUND: usize = 1_000;
const PEER_RETENTION_SECONDS: u64 = 3_600;
const ROLE_COMMAND_CAPACITY: usize = 8;
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
const MAX_LEDGER_BYTES: usize = 8 * 1024 * 1024;
const MAX_LEDGER_BYTES_PER_PEER: usize = 2 * 1024 * 1024;
const MAX_EXIT_PROVIDER_PEERS: usize = 1_024;
const MAX_FORWARD_OPERATION_LIFETIME_MS: u64 = 30_000;
const PROVIDER_OBSERVATION_TTL_MS: u64 = 120_000;
const CLIENT_PRESELECTION_TIMEOUT: Duration = Duration::from_secs(TUNNEL_SETUP_TIMEOUT_SECONDS);

/// Single-owner resources installed into the discovery actor at startup.
pub(crate) struct DiscoveryRuntimeResources {
    pub(crate) roles: RolesConfig,
    pub(crate) policy: Option<VerifiedManifest>,
    pub(crate) role_store: RoleStore,
    pub(crate) metrics: MetricsRegistry,
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

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectRelayCandidateSnapshot {
    advertisement: RouteCandidateAdvertisement,
    capability: DirectRelayCapability,
}

impl DirectRelayCandidateSnapshot {
    pub(crate) const fn advertisement(&self) -> &RouteCandidateAdvertisement {
        &self.advertisement
    }

    pub(crate) const fn capability(&self) -> &DirectRelayCapability {
        &self.capability
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        advertisement: RouteCandidateAdvertisement,
        capability: DirectRelayCapability,
    ) -> Self {
        Self {
            advertisement,
            capability,
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
    relay_service: Option<RelayService>,
    exit_service: Option<ExitService>,
    metrics: MetricsRegistry,
    role_commands: mpsc::Receiver<DiscoveryCommand>,
    client_preselection: ClientPreselectionOwner,
    provider_queries: HashMap<kad::QueryId, ProviderQueryKind>,
    relay_advertisement_requests: HashMap<request_response::OutboundRequestId, Libp2pPeerId>,
    exit_provider_peers: HashMap<Libp2pPeerId, u64>,
    automatic_exit_fetches: HashMap<ForwardedExitKey, u64>,
    automatic_exit_fetch_receivers:
        Vec<oneshot::Receiver<Result<ExitForwardResponse, OutboundReservationError>>>,
    direct_relays: HashMap<Libp2pPeerId, DirectRelayCapability>,
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
    pending_datapath: HashMap<request_response::OutboundRequestId, PendingDatapath>,
    datapath_index: HashMap<DatapathKey, request_response::OutboundRequestId>,
    completed_datapath: HashMap<DatapathKey, CompletedDatapath>,
    retry_datapath: HashMap<DatapathKey, RetryLedgerEntry>,
    candidate_limit: usize,
    observed_endpoints: HashMap<Libp2pPeerId, (String, Option<IpAddr>)>,
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
        } = resources;
        let protocol_roles = DiscoveryProtocolRoles::new(roles.client, roles.relay, roles.exit);
        let mut service =
            DiscoveryService::new_with_protocol_roles(identity.keypair().clone(), protocol_roles)
                .map_err(|_| DiscoveryRuntimeError::Build)?;
        let local_public_key = identity
            .ed25519_public_key_bytes()
            .map_err(|_| DiscoveryRuntimeError::Build)?;
        let local_node_id = node_id_from_public_key(&local_public_key);
        configure_network(&mut service, config)?;
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
            relay_service,
            exit_service,
            metrics,
            role_commands,
            client_preselection,
            provider_queries: HashMap::new(),
            relay_advertisement_requests: HashMap::new(),
            exit_provider_peers: HashMap::new(),
            automatic_exit_fetches: HashMap::new(),
            automatic_exit_fetch_receivers: Vec::new(),
            direct_relays: HashMap::new(),
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
            pending_datapath: HashMap::new(),
            datapath_index: HashMap::new(),
            completed_datapath: HashMap::new(),
            retry_datapath: HashMap::new(),
            candidate_limit: config.network.candidate_pool_size.min(PEERSTORE_LOAD_BOUND),
            observed_endpoints: HashMap::new(),
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
                    let reaped = self.reap_outbound_reservations(Instant::now());
                    if reaped.ambiguous > 0 {
                        log_reservation_event(&state, "RESERVATION_RPC_TIMEOUT").await;
                    }
                    if reaped.canceled > 0 {
                        log_reservation_event(
                            &state,
                            "RESERVATION_RPC_CALLER_CLOSED",
                        ).await;
                    }
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
                    self.handle_sanitized_event(event, &state).await;
                }
                command = self.role_commands.recv() => {
                    let Some(command) = command else {
                        state.write().await.log(LogLevel::Error, "ROLE_ACTOR_CHANNEL_CLOSED", unix_millis());
                        break;
                    };
                    self.handle_command(command, &state).await;
                }
            }
        }
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
            DiscoveryEvent::Other(event) => self.handle_event(event, state).await,
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
            _ => {
                state.write().await.log(
                    LogLevel::Error,
                    "UNSUPPORTED_SANITIZED_DISCOVERY_EVENT",
                    unix_millis(),
                );
            }
        }
    }

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
                current == &pending.authorized_relay
                    && direct_relay_target_matches(
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

    fn reap_outbound_reservations(&mut self, now: Instant) -> OutboundReapCounts {
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
                self.finish_relay_ambiguity(pending);
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
        self.automatic_exit_fetches
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.automatic_exit_fetch_receivers.retain_mut(|receiver| {
            matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )
        });
        if self.forwarded_exit_fail_closed_until_ms <= now_ms {
            self.forwarded_exit_fail_closed_until_ms = 0;
        }
    }

    fn cache_client_result(
        &mut self,
        pending: &PendingClientForward,
        outcome: Result<ExitForwardResponse, OutboundReservationError>,
    ) {
        let previous = self.completed_client_forwards.insert(
            pending.key,
            CompletedClientForward {
                canonical_request: pending.canonical_request.clone(),
                target_peer: pending.expected_exit_peer,
                operation: pending.operation,
                outcome,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes: pending.reserved_bytes,
            },
        );
        debug_assert!(previous.is_none(), "logical client result already cached");
    }

    fn cache_datapath_result(
        &mut self,
        pending: &PendingDatapath,
        outcome: Result<DatapathRelayResponse, OutboundReservationError>,
    ) {
        let previous = self.completed_datapath.insert(
            pending.key,
            CompletedDatapath {
                canonical_request: pending.canonical_request.clone(),
                outcome,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes: pending.reserved_bytes,
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
    }

    fn ledger_reserved_bytes(&self) -> usize {
        let groups = [
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
        self.forwarded_exit_targets
            .get(&peer)
            .is_some_and(|expires_at_ms| *expires_at_ms > now_ms)
            || self.forwarded_exits.values().any(|capability| {
                capability.exit_peer_id == peer && capability.expires_at_ms > now_ms
            })
            || self
                .pending_client_forwards
                .values()
                .any(|pending| pending.expected_exit_peer == peer)
            || self
                .pending_relay_forwards
                .values()
                .any(|pending| pending.expected_exit_peer == peer)
            || self
                .retry_client_forwards
                .values()
                .any(|entry| entry.target_peer == peer && entry.expires_at_ms > now_ms)
            || self
                .retry_relay_forwards
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
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.observed_endpoints.remove(&peer_id);
                state.write().await.peer_disconnected(&peer_id.to_string());
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
                    self.provider_queries.remove(&id);
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
                self.withdraw_local();
                state.write().await.log(
                    LogLevel::Warn,
                    "ADVERTISEMENT_PROVIDER_FAILED",
                    unix_millis(),
                );
                self.provider_queries.remove(&id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { id, step, .. },
            )) => {
                if step.last {
                    self.provider_queries.remove(&id);
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
                request_response::Event::OutboundFailure { .. },
            )) => {
                // The opaque service slot remains active until its local timer consumes the exact
                // transaction. A raw failure cannot safely identify or cancel an affine owner.
                state.write().await.log(
                    LogLevel::Warn,
                    "PRESELECTION_OUTBOUND_FAILED",
                    unix_millis(),
                );
            }
            SwarmEvent::Behaviour(BehaviourEvent::ExitForward(event)) => {
                self.handle_exit_forward_event(event, state).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(event)) => {
                self.handle_exit_forward_upstream_event(event, state).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(event)) => {
                self.handle_datapath_event(event, state).await;
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

    fn handle_provider_peers(
        &mut self,
        kind: ProviderQueryKind,
        providers: std::collections::HashSet<Libp2pPeerId>,
    ) {
        self.purge_completed(Instant::now());
        let now_ms = unix_millis();
        let provider_expires_at_ms = now_ms.saturating_add(PROVIDER_OBSERVATION_TTL_MS);
        for peer in providers.into_iter().take(self.candidate_limit) {
            if peer == *self.service.local_peer_id() {
                continue;
            }
            match kind {
                ProviderQueryKind::Relay => {
                    if self.relay_advertisement_requests.len() >= self.candidate_limit.max(1)
                        || self.peer_is_forwarded_exit_target(peer, now_ms)
                        || self
                            .relay_advertisement_requests
                            .values()
                            .any(|pending_peer| *pending_peer == peer)
                    {
                        continue;
                    }
                    if let Ok(request_id) = self.service.request_relay_advertisement(&peer) {
                        self.relay_advertisement_requests.insert(request_id, peer);
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
        self.schedule_exit_advertisement_fetches();
    }

    /// Fetch provider-only Exit advertisements through one authenticated control Relay.
    ///
    /// A client never dials the Exit here. The actor sends the existing bounded fetch RPC to one
    /// current direct Relay, and only the normal forwarded-provenance commit can make the response
    /// selectable.
    fn schedule_exit_advertisement_fetches(&mut self) {
        if !self.roles.client
            || self.automatic_exit_fetch_receivers.len() >= self.candidate_limit.max(1)
        {
            return;
        }
        let now_ms = unix_millis();
        self.automatic_exit_fetches
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.automatic_exit_fetch_receivers.retain_mut(|receiver| {
            matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )
        });

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
            if self.automatic_exit_fetch_receivers.len() >= self.candidate_limit.max(1)
                || !self.forwarded_exit_peer_is_eligible(exit_peer, now_ms)
            {
                continue;
            }
            let Some(control) = controls
                .iter()
                .find(|control| control.peer_id != exit_peer)
                .cloned()
            else {
                continue;
            };
            let key = ForwardedExitKey {
                control_relay_peer: control.peer_id,
                exit_peer,
            };
            if self.forwarded_exits.contains_key(&key)
                || self
                    .automatic_exit_fetches
                    .get(&key)
                    .is_some_and(|expiry| *expiry > now_ms)
            {
                continue;
            }
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
            self.begin_client_forward(control.peer_id, request, reply);
            let request_key = ClientForwardKey {
                control_relay_peer: control.peer_id,
                forward_id,
            };
            if self.client_forward_index.contains_key(&request_key)
                || self.completed_client_forwards.contains_key(&request_key)
                || self.retry_client_forwards.contains_key(&request_key)
            {
                self.automatic_exit_fetch_receivers.push(receiver);
            } else {
                self.automatic_exit_fetches.remove(&key);
            }
        }
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
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let outcome = self.fail_client_forward(request_id, peer);
                log_outbound_event(state, outcome).await;
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
            } => self.answer_exit_forward_upstream(peer, connection_id, request, channel, state),
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
                    .complete_relay_forward(request_id, peer, response, state)
                    .await;
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let outcome = self.fail_relay_forward(request_id, peer);
                log_outbound_event(state, outcome).await;
            }
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => {}
        }
    }

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
            || !self.forwarded_exit_peer_is_eligible(exit_peer, now_ms)
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
        let Some(reserved_bytes) = retry
            .map(|entry| entry.reserved_bytes)
            .or_else(|| ledger_reservation_bytes(canonical_request.len()))
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
            || !self.mark_forwarded_exit_target(exit_peer, operation_expires_at_ms)
        {
            reject!("EXIT_FORWARD_RELAY_CAPACITY");
        }
        let attempt_deadline = rpc_deadline(operation_expires_at_ms, EXIT_FORWARD_UPSTREAM_TIMEOUT);
        let Ok(outbound_id) = self
            .service
            .request_exit_forward_upstream(&exit_peer, request.clone().into())
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
            },
        );
        log_relay_forward_admission(state, "EXIT_FORWARD_RELAY_DISPATCHED");
    }

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
        let Some(pending) = self.pending_relay_forwards.remove(&request_id) else {
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
            self.finish_relay_definitive(pending);
            log_reservation_event(state, "EXIT_FORWARD_RELAY_RESPONSE_INVALID").await;
            return OutboundEventOutcome::InvalidResponse;
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
            || !self.forwarded_exit_peer_is_eligible(pending.expected_exit_peer, now_ms)
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
            None => pending.operation == ExitForwardOperation::FetchExitAdvertisement,
        }
    }

    fn cache_relay_result(
        &mut self,
        pending: &PendingRelayForward,
        response: Option<ExitForwardResponse>,
    ) {
        let previous = self.completed_relay_forwards.insert(
            pending.key,
            CompletedRelayForward {
                canonical_request: pending.canonical_request.clone(),
                target_peer: pending.expected_exit_peer,
                operation: pending.operation,
                response,
                expires_at_ms: pending.operation_expires_at_ms,
                reserved_bytes: pending.reserved_bytes,
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

    fn finish_relay_definitive(&mut self, pending: PendingRelayForward) {
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
        if pending.dispatch_attempts < MAX_DISPATCH_ATTEMPTS
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

    fn fail_relay_forward(
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
        self.finish_relay_ambiguity(pending);
        OutboundEventOutcome::Failed
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one Exit admission path validates every forwarded operation and response"
    )]
    fn answer_exit_forward_upstream(
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
        if operation == ExitForwardOperation::NativeProbePermit {
            if let Some(prepared) = self.prepare_native_probe_permit_response(
                authenticated_control_relay,
                connection_id,
                &request,
                channel,
            ) {
                self.send_prepared_native_probe_permit_response(prepared);
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
        let valid_control_relay = operation == ExitForwardOperation::FetchExitAdvertisement
            || self
                .direct_relays
                .get(&authenticated_control_relay)
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
        let local_peer_bytes = local_peer.to_bytes();
        let response = if operation == ExitForwardOperation::FetchExitAdvertisement {
            self.served_local_advertisement
                .as_ref()
                .filter(|advertisement| {
                    decode_canonical::<SignedEnvelope>(
                        advertisement,
                        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
                    )
                    .is_ok_and(|envelope| envelope.expires_at_ms > now_ms)
                })
                .cloned()
                .and_then(|advertisement| {
                    ExitForwardResponse::granted(
                        request.forward_id().to_vec(),
                        operation,
                        self.local_node_id.to_vec(),
                        local_peer_bytes.clone(),
                        vec![advertisement],
                    )
                    .ok()
                })
        } else {
            ExitForwardResponse::unavailable(
                request.forward_id().to_vec(),
                operation,
                self.local_node_id.to_vec(),
                local_peer_bytes,
            )
            .ok()
        };
        if let Some(response) = response {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
            log_relay_forward_admission(Some(state), "EXIT_FORWARD_EXIT_RESPONDED");
        } else {
            log_relay_forward_admission(Some(state), "EXIT_FORWARD_EXIT_RESPONSE_UNAVAILABLE");
        }
    }

    /// Validate one native-Permit request and prepare its exact connection-owned response.
    ///
    /// Every state-free wrapper, signature, current-capability and local-advertisement check runs
    /// before connection provenance is bound. The bind itself precedes the only Exit replay/sign
    /// call. There is no suspension point from that bind through the returned response owner. The
    /// current product deliberately publishes no local Exit advertisement, so this composed
    /// handler remains fail-closed until a later truthful Exit-capability producer exists.
    fn prepare_native_probe_permit_response(
        &mut self,
        authenticated_control_relay: Libp2pPeerId,
        connection_id: ConnectionId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) -> Option<PreparedNativeProbePermitResponse> {
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
        let current_control = self.direct_relays.get(&authenticated_control_relay)?;
        if control_relay_peer != authenticated_control_relay
            || control_relay_public_key != current_control.public_key
            || exit_node_id != self.local_node_id
            || exit_peer != local_peer
            || exit_peer == authenticated_control_relay
            || !native_probe_control_capability_matches(
                current_control,
                control,
                &scope,
                authenticated_control_relay,
                request.deadline_unix_ms(),
            )
            || !self
                .served_local_advertisement
                .as_ref()
                .is_some_and(|advertisement| {
                    local_native_probe_exit_actor_matches(
                        advertisement,
                        exit,
                        &scope,
                        self.local_node_id,
                        local_peer,
                        self.local_public_key,
                        now_ms,
                    )
                })
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
        let authenticated_control_peer = authenticated_control_relay.to_bytes();
        let identity = &self.identity;
        let accepted = self
            .exit_service
            .as_mut()?
            .issue_native_probe_permit_with(
                request.canonical_request(),
                &control_relay_node_id,
                &authenticated_control_peer,
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
        Some(PreparedNativeProbePermitResponse {
            connection,
            authenticated_control_relay,
            channel,
            response: response.into(),
        })
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
        }) && self.forwarded_exit_peer_is_eligible(*exit_peer, clock.unix_ms)
            && self.peer_is_forwarded_exit_target(*exit_peer, clock.unix_ms)
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
                "ADVERTISEMENT_VERIFY_FAILED",
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
                    "ADVERTISEMENT_VERIFY_FAILED",
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
                "ADVERTISEMENT_VERIFY_FAILED",
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
                    || !self.forwarded_exit_peer_is_eligible(peer, now_ms)
                    || !self.peer_is_forwarded_exit_target(peer, now_ms)
                {
                    0
                } else {
                    accepted.expires_at_ms.min(*request_deadline_ms).min(
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
                let _ = self
                    .mark_forwarded_exit_target(exit_peer, accepted.advertisement_expires_at_ms);
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
        let mut keys = self
            .forwarded_exits
            .iter()
            .filter_map(|(key, capability)| {
                let target_conflict = key.exit_peer == peer;
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
        let local_control_peer = *self.service.local_peer_id();
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
            if pending.expected_exit_peer == peer
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
            if entry.target_peer == peer
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
            if entry.target_peer == peer
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
                self.completed_datapath.insert(
                    key,
                    CompletedDatapath {
                        canonical_request: entry.canonical_request,
                        outcome: Err(OutboundReservationError::InvalidResponse),
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes: entry.reserved_bytes,
                    },
                );
            }
        }
        for (key, entry) in &mut self.completed_datapath {
            if key.relay_peer == peer {
                entry.outcome = Err(OutboundReservationError::InvalidResponse);
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
                ((!preserve_fetch_attempts
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
                self.completed_client_forwards.insert(
                    key,
                    CompletedClientForward {
                        canonical_request: entry.canonical_request,
                        target_peer: entry.target_peer,
                        operation: entry.operation.expect("client retry operation"),
                        outcome: Err(OutboundReservationError::InvalidResponse),
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes: entry.reserved_bytes,
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
                self.completed_relay_forwards.insert(
                    key,
                    CompletedRelayForward {
                        canonical_request: entry.canonical_request,
                        target_peer: entry.target_peer,
                        operation: entry.operation.expect("relay retry operation"),
                        response: None,
                        expires_at_ms: entry.expires_at_ms,
                        reserved_bytes: entry.reserved_bytes,
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
            }
        }
        for entry in self.completed_relay_forwards.values_mut() {
            if keys.contains(&ForwardedExitKey {
                control_relay_peer: local_control_peer,
                exit_peer: entry.target_peer,
            }) {
                entry.response = None;
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
            && capability.control_relay_node_id == control.node_id
            && capability.control_relay_peer_id == control.peer_id
            && capability.control_relay_public_key == control.public_key
            && capability.control_relay_advertisement_sequence != 0
            && capability.control_relay_advertisement_expires_at_ms > captured_at_ms
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

fn optional_fixed_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    (!bytes.is_empty()).then(|| fixed_bytes(bytes)).flatten()
}

fn ledger_reservation_bytes(canonical_request_bytes: usize) -> Option<usize> {
    canonical_request_bytes
        .checked_add(usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?)
        .filter(|reserved| *reserved <= MAX_LEDGER_BYTES_PER_PEER)
}

fn deadline_is_bounded(deadline_unix_ms: u64, now_ms: u64) -> bool {
    deadline_unix_ms > now_ms
        && deadline_unix_ms <= now_ms.saturating_add(MAX_FORWARD_OPERATION_LIFETIME_MS)
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
        DatapathRelayOperation::NativeProbeStart => {
            native_probe_start_scope_matches(request, now_ms, &mut replay)
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
        && wrapper.deadline_unix_ms() == scope.attempt_expires_at_ms
        && wrapper.relay_node_id() == data_relay.node_id
        && wrapper.relay_peer_id() == data_relay.peer_id
}

fn native_probe_start_scope_matches(
    wrapper: &DatapathRelayRequest,
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
    wrapper.request_id() == &nonce[..FORWARD_ID_BYTES]
        && wrapper.deadline_unix_ms() == expires_at_ms
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
    inner_forward_scope_matches(
        request,
        verified.nonce(),
        verified.expires_at_ms(),
        &control.node_id,
        &control.peer_id,
        &exit.node_id,
        &exit.peer_id,
    )
    .then(|| scope.clone())
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
        && actor.capability_expires_at_ms == expected_capability_expiry
        && expected_capability_expiry > now_ms
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
        ExitForwardOperation::FetchExitAdvertisement | ExitForwardOperation::Unspecified => false,
    }
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
            || response
                .signed_responses()
                .iter()
                .all(|envelope| signed_envelope_matches_peer(envelope, &expected_exit_peer)))
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
            Arc,
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
        let fixture = fixture(RolesConfig::default());
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
            (RolesConfig::default(), active),
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
                format!(
                    "2606:4700:{:02x}{:02x}::/48",
                    nonce[0],
                    sequence_number % 255
                )
            })
            .unwrap_or_default();
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
        let control =
            direct_capability(&control_identity, &fixture.policy, 17, actor_expires_at_ms);
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
            [0x73; 32],
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
        };
        let nonce = [0x35; 32];
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
            scope,
            request,
            local_advertisement,
        }
    }

    #[tokio::test]
    async fn native_permit_forward_scope_requires_exact_signed_wrapper_lineage() {
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
        let wrong_deadline = rebuild(
            fixture.request.forward_id().to_vec(),
            fixture.request.deadline_unix_ms().saturating_sub(1),
            fixture.request.canonical_request().to_vec(),
        );
        assert!(verified_native_probe_forward_scope(&wrong_deadline, fixture.now_ms).is_none());

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
            [0x74; 32],
            fixture.now_ms,
            &fixture.fixture.directory,
        );
        assert!(!matches(
            relay_only.signed_envelope(),
            actor,
            &fixture.scope,
        ));
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
            .find("native_probe_control_capability_matches(")
            .expect("current control capability check");
        let local_advertisement_check = caller
            .find("local_native_probe_exit_actor_matches(")
            .expect("current local Exit advertisement check");
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
        let mut fixture = Box::new(fixture(RolesConfig::default()));
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
                [191; 32],
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
                [192; 32],
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
        let mut fixture = Box::new(fixture(RolesConfig::default()));
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
        let expected = RolesConfig::default();
        let mut fixture = fixture(expected);
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
            fixture
                .role_store
                .load_or_initialize(candidate)
                .expect("persisted roles"),
            expected
        );
    }

    #[tokio::test]
    async fn fetch_wrapper_deadline_is_bounded_to_thirty_seconds() {
        let fixture = fixture(RolesConfig::default());
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
    async fn affine_forwarded_capability_survives_refresh_but_not_policy_change() {
        let fixture = fixture(RolesConfig::default());
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
        let mut rekeyed = control.clone();
        rekeyed.advertisement_sequence = rekeyed.advertisement_sequence.saturating_add(1);
        assert!(forwarded_exit_capability_matches(
            &capability,
            &rekeyed,
            rekeyed.node_id,
            rekeyed.peer_id,
            rekeyed.public_key,
            exit_node_id,
            exit_peer_id,
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
    }

    #[tokio::test]
    async fn ledger_reserves_max_response_bytes_globally_and_per_peer() {
        let mut global = fixture(RolesConfig::default());
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

        let mut per_peer = fixture(RolesConfig::default());
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

    #[tokio::test]
    async fn full_tombstone_ledger_returns_exact_cached_result_without_dispatch() {
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
        let mut direct_fixture = fixture(RolesConfig::default());
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

        let mut pending_fixture = fixture(RolesConfig::default());
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
    async fn forwarded_target_blocks_direct_relay_provider_fetch_and_expires() {
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
            [91; 32],
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

        let mut direct_first = fixture(RolesConfig::default());
        let relay = Identity::generate();
        let exit = Identity::generate();
        let control = install_control(&mut direct_first, &relay, now_ms);
        let exit_peer = exit.peer_id().to_owned();
        let advertisement = service_advertisement(
            &exit,
            roles,
            &direct_first.policy,
            1,
            [101; 32],
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

        let mut forwarded_first = fixture(RolesConfig::default());
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
            [102; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
            [111; 32],
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
            RolesConfig::default(),
            &fixture.policy,
            2,
            [112; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
            [113; 32],
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
            [114; 32],
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
            RolesConfig::default(),
            &fixture.policy,
            2,
            [115; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
            [121; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
            [131; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
            [154; 32],
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
        let mut fixture = fixture(RolesConfig::default());
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
                [155; 32],
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
                [160; 32],
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
            ingest_forwarded_snapshot_exit(fixture, &control, valid_exit, 1, [161; 32], now_ms,)
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
                [162; 32],
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
    async fn raw_outbound_failure_retains_active_slot_until_owner_timeout() {
        let ActiveClientPreselectionFixture {
            mut fixture,
            mut control_service,
            mut response,
            ..
        } = Box::pin(active_client_preselection_fixture()).await;
        let failure =
            next_client_preselection_outbound_failure(&mut fixture.runtime, &mut control_service)
                .await;

        fixture
            .runtime
            .handle_sanitized_event(failure, &fixture.state)
            .await;

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
        assert!(matches!(
            response.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let ClientPreselectionOwner::Active(active) = &mut fixture.runtime.client_preselection
        else {
            panic!("raw failure must retain active owner");
        };
        active.request_deadline = Instant::now();
        fixture.runtime.maintain_client_preselection();
        assert!(matches!(
            response.await.expect("owner timeout"),
            Err(ClientPreselectionError::Timeout)
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
                [162; 32],
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

        let failure_arm = product
            .split_once(
                "BehaviourEvent::PreselectionObservation(\n                request_response::Event::OutboundFailure { .. },",
            )
            .expect("opaque outbound failure arm")
            .1
            .split_once("SwarmEvent::Behaviour(BehaviourEvent::ExitForward(event))")
            .expect("outbound failure arm end")
            .0;
        assert!(!failure_arm.contains("request_id"));
        assert!(!failure_arm.contains("cancel_client_preselection"));
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
    async fn route_snapshot_rejects_external_hash_drift_and_retains_affine_control_provenance() {
        for mutation in 0_u8..5 {
            let mut fixture = fixture(RolesConfig::default());
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
                _ => unreachable!(),
            }

            let drifted = route_snapshot_at(&mut fixture, 10, now_ms)
                .await
                .expect("hash drift is filtered, not surfaced");
            assert_eq!(
                drifted.forwarded_exits().is_empty(),
                mutation != 2,
                "a verified forwarded capability retains its original control-advertisement provenance across a same-lineage refresh"
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
                [162; 32],
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
                [163; 32],
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
                [164; 32],
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
                [165; 32],
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
            ingest_forwarded_snapshot_exit(fixture, &control, &exit, 1, [166; 32], now_ms)
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
                [167; 32],
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
            [168; 32],
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
            ingest_forwarded_snapshot_exit(fixture, control, &exit, 1, [169; 32], now_ms)
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
        let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
        let fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
            [139; 32],
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
            let mut fixture = fixture(RolesConfig::default());
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
        let mut fixture = fixture(RolesConfig::default());
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
            [161; 32],
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
            [171; 32],
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
                .complete_relay_forward(
                    request_id,
                    exit_peer,
                    response.clone().into(),
                    &fixture.state,
                )
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
            fixture
                .runtime
                .complete_relay_forward(request_id, exit_peer, response.into(), &fixture.state,)
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
        let mut fixture = fixture(RolesConfig::default());
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
            [181; 32],
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
            [183; 32],
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

    #[allow(
        clippy::too_many_lines,
        reason = "a blocked finish proves the completion cache and reply precede refresh"
    )]
    #[tokio::test]
    async fn client_completion_is_cached_and_replied_before_refresh() {
        let mut fixture = fixture(RolesConfig::default());
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
            [185; 32],
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
