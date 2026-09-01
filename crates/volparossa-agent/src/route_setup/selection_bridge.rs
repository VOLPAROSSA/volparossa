//! Proof-carrying, in-memory selection input for route setup.
//!
//! This boundary deliberately has no runtime caller yet. It can purpose-consume exact A1a/A1c
//! proofs into the existing private freshness batch, but that control-plane proof cannot establish
//! native dataplane-address usability or measured capacity. A later native-path sampler must add
//! that independent evidence before selection can advance. Missing evidence fails closed; this
//! module never substitutes neutral scores or advertised capacity for local observations.

mod native_preselection;

use std::{collections::HashSet, net::UdpSocket as StdUdpSocket, time::Duration};

use crate::{
    discovery::{
        AdvertisementPayloadHash, BoundPreselectionFreshnessProofBatch,
        CompletedPreselectionFreshnessAttempt, CoolingPreselectionAttemptGate,
        DirectRelayCandidateSnapshot, DirectRelayCapability, DiscoveryControlHandle,
        ForwardedExitCandidateSnapshot, ForwardedExitCapability,
        PreselectionTranscriptFreshnessFacts, PreselectionTransportFreshnessFacts,
        RouteCandidateAdvertisement, RouteCandidatePolicySnapshot, RouteCandidateSnapshot,
    },
    endpoint_leases::{
        EndpointLeaseBindingError, bind_prepared_endpoint_leases, protocol_endpoint_for_native,
    },
    helper::{HelperClient, RuntimeBoundPreparedLeaseBatch},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout},
};
use volparossa_core::{
    Bandwidth, IpFamily, NodeId, ObservedNetworkPrefix, OperatorId, PeerId, PolicyHash,
    ServiceRole, Transport as SelectionTransport, UnixTime,
};
#[cfg(test)]
use volparossa_peerstore::StoredPeer;
use volparossa_protocol::{
    NativeProbeEndpointBinding, NativeProbeLeaseProof, NativeProbePathScope,
    ObservationAddressFamily, PreselectionObservationRole, ProbeAddressFamily, TimePolicy,
    Transport as ProtocolTransport, WireguardEndpoint, native_probe_prepared_lease_commitment,
    node_id_from_public_key, verify_relay_reservation,
};
use volparossa_reservation::RelayPathIntent;
use volparossa_routing::{
    AcquireTransportSocket, ActivateLeaseBatch, ActivatedLeaseBatch, CommitLeaseBatch,
    CommittedLeaseBatch, ContextRole, DestroyContext, DestroyedContext, LeaseActivation,
    LeaseCommit, LeasePlan, NATIVE_PROBE_CLIENT_PORT, NATIVE_PROBE_DATAGRAM_BYTES,
    NATIVE_PROBE_EXIT_PORT, PrepareLeaseBatch, PublicUdpEndpoint, TransportSocketAddress,
    TransportSocketKind, WireguardRole,
};
use volparossa_selection::{
    Candidate, CandidateEvidence, CompleteRelayPathMetrics, DiversityAnchor, FilterRequirements,
    MAXIMUM_PROSPECTIVE_RELAYS, MAXIMUM_SELECTION_CANDIDATES, PrefixObservedCandidate,
    ProjectedRelayPath, ProspectiveRelayPolicy, RelaySelectionPolicy, RelaySelectionProjection,
    SelectedNode, SelectedPath, SelectionError, SelectionMix, select_exit_with_observed_prefixes,
    select_projected_relay_paths, select_prospective_relays_with_observed_prefixes,
    validate_relay_selection_policy,
};
use volparossa_wireguard::overlay_addresses;

use super::{
    DiversitySnapshot, ID_BYTES, LocalRouteBackend, MAXIMUM_REPLAY_CAPACITY,
    MAXIMUM_RESERVATION_LIFETIME_MS, MAXIMUM_SETUP_DURATION, PostProbeSelectionPolicy,
    ProbeProjection, ProspectiveDirectRelay, ProspectiveForwardedExit, ProspectivePeerIdentity,
    ProspectiveRouteRelay, ReservationSession, ReservationTransport, RouteCapabilityResolver,
    RouteSetupAuthorities, RouteSetupClock, RouteSetupError, RouteSetupFailure, RouteSetupHandle,
    RouteSetupLimits, RouteSetupManager, RouteSetupParameters, RouteSetupPath, RouteSetupPhase,
    RouteSetupRequest, RouteSetupTransaction, SelectedForwardedExit, SelectedRouteSetupPath,
    UnmeasuredRouteSetup, bounded_call,
};

const MAXIMUM_EVIDENCE_AGE_MS: u64 = 60_000;
const NATIVE_PROBE_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Eq, PartialEq)]
struct ActorRelayDiversity {
    operator_id: OperatorId,
    asn: u32,
    prefix: ObservedNetworkPrefix,
}

impl ActorRelayDiversity {
    fn from_snapshot(
        diversity: &DiversitySnapshot,
        address_family: Option<IpFamily>,
    ) -> Result<Self, RouteSetupError> {
        let prefix = diversity.observed_network_prefix;
        if diversity.asn == 0
            || !prefix.is_public_routable()
            || address_family.is_some_and(|family| family != prefix.family())
        {
            return Err(RouteSetupError::Invalid("relay diversity"));
        }
        Ok(Self {
            operator_id: diversity.operator_id.clone(),
            asn: diversity.asn,
            prefix,
        })
    }

    fn conflicts_with(&self, other: &Self) -> bool {
        self.operator_id == other.operator_id
            || self.asn == other.asn
            || self.prefix == other.prefix
    }
}

/// Affine authenticated actor and sanitized selection binding.
///
/// The only product mint consumes a private `VerifiedSelectionPeer` below. This value has no
/// Clone, Copy, Debug, serialization, constructor or decomposition API outside this child module.
pub(super) struct ActorBoundRelayProof {
    evidence_batch_id: [u8; ID_BYTES],
    relay: ProspectiveDirectRelay,
    forwarded_exit: ProspectiveForwardedExit,
    selection: RelaySelectionProjection,
    diversity: ActorRelayDiversity,
    advertisement_measured_at_ms: u64,
    advertisement_expires_at_ms: u64,
    actor_evidence_observed_at_ms: u64,
    evidence_valid_until_ms: u64,
    projected_at_ms: u64,
    static_requirements: FilterRequirements,
}

impl ActorBoundRelayProof {
    fn validate_preprobe_binding(
        &self,
        binding: &ProspectivePeerBinding,
        diversity: &DiversitySnapshot,
        selected_exit: &SelectedForwardedExit,
        trusted_now_ms: u64,
        requirements: &FilterRequirements,
        evidence_batch_id: EvidenceBatchId,
    ) -> Result<(), RouteSetupError> {
        self.revalidate_at(trusted_now_ms, requirements, evidence_batch_id.0)?;
        let expected_diversity =
            ActorRelayDiversity::from_snapshot(diversity, requirements.address_family)?;
        if self.relay.identity != binding.identity
            || self.forwarded_exit != selected_exit.authority
            || self.diversity != expected_diversity
            || self.advertisement_measured_at_ms != binding.advertisement_measured_at_ms
            || self.actor_evidence_observed_at_ms != binding.actor_evidence_observed_at_ms
            || self.evidence_valid_until_ms != binding.evidence_valid_until_ms
            || selected_exit.evidence_batch_id != evidence_batch_id.0
        {
            return Err(RouteSetupError::Invalid("pre-probe actor binding"));
        }
        Ok(())
    }

    fn revalidate_at(
        &self,
        trusted_now_ms: u64,
        requirements: &FilterRequirements,
        evidence_batch_id: [u8; ID_BYTES],
    ) -> Result<(), RouteSetupError> {
        let identity = &self.relay.identity;
        let freshness_ceiling = self
            .actor_evidence_observed_at_ms
            .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
            .ok_or(RouteSetupError::Invalid("relay evidence lifetime"))?;
        if self.evidence_batch_id != evidence_batch_id
            || evidence_batch_id.iter().all(|byte| *byte == 0)
            || identity.public_key.iter().all(|byte| *byte == 0)
            || node_id_from_public_key(&identity.public_key) != identity.wire_node_id
            || identity.advertisement_sequence == 0
            || identity.policy_version == 0
            || identity.advertisement_expires_at_ms != self.advertisement_expires_at_ms
            || identity.expires_at_ms
                != identity
                    .advertisement_expires_at_ms
                    .min(identity.policy_expires_at_ms)
            || self.evidence_valid_until_ms > freshness_ceiling
            || trusted_now_ms < self.projected_at_ms
            || trusted_now_ms < self.actor_evidence_observed_at_ms
            || trusted_now_ms >= self.advertisement_expires_at_ms
            || trusted_now_ms >= identity.expires_at_ms
            || trusted_now_ms >= identity.policy_expires_at_ms
            || trusted_now_ms >= self.evidence_valid_until_ms
            || self.advertisement_measured_at_ms > self.actor_evidence_observed_at_ms
            || requirements.now != UnixTime::from_secs(trusted_now_ms / 1_000)
            || requirements.role != self.static_requirements.role
            || requirements.transport != self.static_requirements.transport
            || requirements.policy_hash != self.static_requirements.policy_hash
            || requirements.minimum_capacity != self.static_requirements.minimum_capacity
            || requirements.address_family != self.static_requirements.address_family
            || requirements.region != self.static_requirements.region
            || requirements.require_reachable != self.static_requirements.require_reachable
        {
            return Err(RouteSetupError::Invalid("stale actor-bound relay proof"));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one request check binds the proof to exit, route windows and prior actors"
    )]
    pub(super) fn validate_request_binding(
        &self,
        trusted_now_ms: u64,
        setup_expires_at_ms: u64,
        hard_expires_at_ms: u64,
        requirements: &FilterRequirements,
        evidence_batch_id: [u8; ID_BYTES],
        control: &ProspectivePeerIdentity,
        exit: &ProspectivePeerIdentity,
        control_diversity: &DiversitySnapshot,
        exit_diversity: &DiversitySnapshot,
        prior_paths: &[RouteSetupPath],
    ) -> Result<(), RouteSetupError> {
        self.revalidate_at(trusted_now_ms, requirements, evidence_batch_id)?;
        let identity = &self.relay.identity;
        let control_diversity =
            ActorRelayDiversity::from_snapshot(control_diversity, requirements.address_family)?;
        let exit_diversity =
            ActorRelayDiversity::from_snapshot(exit_diversity, requirements.address_family)?;
        if setup_expires_at_ms > self.evidence_valid_until_ms
            || hard_expires_at_ms > self.advertisement_expires_at_ms
            || hard_expires_at_ms > identity.expires_at_ms
            || hard_expires_at_ms > identity.policy_expires_at_ms
            || identity.policy_version != exit.policy_version
            || identity.policy_version != control.policy_version
            || identity.policy_hash != exit.policy_hash
            || identity.policy_hash != control.policy_hash
            || identity.policy_hash != *requirements.policy_hash.as_bytes()
            || identity.policy_expires_at_ms != exit.policy_expires_at_ms
            || identity.policy_expires_at_ms != control.policy_expires_at_ms
            || self.forwarded_exit.control.identity != *control
            || self.forwarded_exit.exit != *exit
            || identity.wire_node_id == control.wire_node_id
            || identity.wire_node_id == exit.wire_node_id
            || identity.peer_id == control.peer_id
            || identity.peer_id == exit.peer_id
            || identity.public_key == control.public_key
            || identity.public_key == exit.public_key
            || self.diversity.conflicts_with(&control_diversity)
            || self.diversity.conflicts_with(&exit_diversity)
            || prior_paths.iter().any(|path| {
                let prior = &path.proof;
                identity.wire_node_id == prior.relay.identity.wire_node_id
                    || identity.peer_id == prior.relay.identity.peer_id
                    || identity.public_key == prior.relay.identity.public_key
                    || self.diversity.conflicts_with(&prior.diversity)
            })
        {
            return Err(RouteSetupError::Invalid("selected relay evidence"));
        }
        Ok(())
    }

    pub(super) fn revalidate_for_scoring(
        &self,
        trusted_now_ms: u64,
        requirements: &FilterRequirements,
        evidence_batch_id: [u8; ID_BYTES],
    ) -> Result<(), RouteSetupError> {
        self.revalidate_at(trusted_now_ms, requirements, evidence_batch_id)
    }

    pub(super) async fn resolve<R: RouteCapabilityResolver>(
        &self,
        resolver: &R,
    ) -> Result<DirectRelayCapability, RouteSetupError> {
        resolver
            .resolve_direct_relay(
                self.relay.identity.wire_node_id,
                self.relay.identity.peer_id,
            )
            .await
    }

    pub(super) fn capability_matches(
        &self,
        capability: &DirectRelayCapability,
        policy_hash: [u8; 32],
        required_expiry_ms: u64,
    ) -> bool {
        self.relay.identity.direct_matches(capability)
            && capability.policy_hash == policy_hash
            && capability.advertisement_expires_at_ms >= required_expiry_ms
            && capability.policy_expires_at_ms >= required_expiry_ms
            && capability.expires_at_ms >= required_expiry_ms
    }

    pub(super) fn relay_intent(&self, path_id: u32) -> RelayPathIntent {
        RelayPathIntent {
            path_id,
            relay_node_id: self.relay.identity.wire_node_id,
            relay_peer_id: self.relay.identity.peer_id.to_bytes(),
        }
    }

    pub(super) fn projected_path<'a>(
        &'a self,
        projection: &ProbeProjection,
        required_up: u32,
        required_down: u32,
    ) -> Result<ProjectedRelayPath<'a>, RouteSetupError> {
        let capacity = u32::try_from(projection.minimum_directional_capacity_mbps)
            .map_err(|_| RouteSetupError::Invalid("probe capacity"))?;
        Ok(ProjectedRelayPath::new(
            &self.selection,
            CompleteRelayPathMetrics::new(
                Bandwidth::new(capacity, capacity)
                    .map_err(|_| RouteSetupError::Invalid("probe capacity"))?,
                Bandwidth::new(capacity, capacity)
                    .map_err(|_| RouteSetupError::Invalid("probe capacity"))?,
                Bandwidth::new(required_up, required_down)
                    .map_err(|_| RouteSetupError::Invalid("probe capacity"))?,
                super::probe_rtt_millis(projection.client_to_relay_rtt_micros)?,
                super::probe_rtt_millis(projection.relay_to_exit_rtt_micros)?,
                projection.unique_throughput_gain_ratio,
                projection.meaningful_failover,
            ),
        ))
    }

    pub(super) fn matches_selected_path(&self, selected: &SelectedPath) -> bool {
        self.relay.selection_node_id().is_ok_and(|node_id| {
            node_id == selected.relay_node_id
                && self.relay.identity.peer_id.to_string() == selected.relay_peer_id.as_str()
        })
    }

    pub(super) fn into_selected(self, path_id: u32) -> SelectedRouteSetupPath {
        SelectedRouteSetupPath {
            path_id,
            relay: self.relay,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ActivePolicySnapshot {
    version: u64,
    hash: PolicyHash,
    expires_at_ms: u64,
}

#[derive(Clone, Debug)]
struct RouteSelectionScope {
    now_ms: u64,
    transport: SelectionTransport,
    policy: ActivePolicySnapshot,
    minimum_capacity: Bandwidth,
    address_family: Option<IpFamily>,
    region: Option<String>,
    exit_mix: SelectionMix,
    relay_policy: RelaySelectionPolicy,
}

impl RouteSelectionScope {
    fn validate(&self) -> Result<(), SelectionBridgeError> {
        if self.now_ms == 0
            || self.policy.version == 0
            || self.policy.expires_at_ms <= self.now_ms
            || self.policy.hash.as_bytes().iter().all(|byte| *byte == 0)
            || self.minimum_capacity.up_mbps == 0
            || self.minimum_capacity.down_mbps == 0
            || self.minimum_capacity.validate().is_err()
            || self.address_family.is_none()
        {
            return Err(SelectionBridgeError::InvalidScope);
        }
        Ok(())
    }

    fn requirements(&self, role: ServiceRole) -> FilterRequirements {
        FilterRequirements {
            now: UnixTime::from_secs(self.now_ms / 1_000),
            role,
            transport: self.transport,
            policy_hash: self.policy.hash,
            minimum_capacity: self.minimum_capacity,
            address_family: self.address_family,
            region: self.region.clone(),
            require_reachable: true,
        }
    }

    fn probe_address_family(&self) -> Result<ProbeAddressFamily, SelectionBridgeError> {
        match self.address_family {
            Some(IpFamily::Ipv4) => Ok(ProbeAddressFamily::Ipv4),
            Some(IpFamily::Ipv6) => Ok(ProbeAddressFamily::Ipv6),
            None => Err(SelectionBridgeError::InvalidScope),
        }
    }
}

/// Non-zero identity shared by every observation in one bounded measurement batch.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct EvidenceBatchId([u8; 16]);

impl EvidenceBatchId {
    #[cfg(test)]
    fn for_test(value: [u8; 16]) -> Self {
        assert!(value.iter().any(|byte| *byte != 0));
        Self(value)
    }

    fn is_valid(self) -> bool {
        self.0.iter().any(|byte| *byte != 0)
    }
}

impl std::fmt::Debug for EvidenceBatchId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EvidenceBatchId([OPAQUE])")
    }
}

/// Exact control-relay tuple carried only by forwarded-exit evidence.
#[derive(Clone, Eq, PartialEq)]
struct ForwardedControlBinding {
    node_id: NodeId,
    peer_id: PeerId,
    public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    capability_expires_at_ms: u64,
}

impl std::fmt::Debug for ForwardedControlBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ForwardedControlBinding([REDACTED])")
    }
}

/// Fresh local observation explicitly bound to one authenticated advertisement.
///
/// It is intentionally not serializable and contains no destination, browsing or application
/// origin, hostname or flow identity. Its conservative configured preselection ceiling is neither
/// a measurement, offer, hold, reservation nor admission authority. The production A1 proof join
/// below leaves dataplane-address usability false until a separate native-path sampler proves it.
/// A false `locally_blocked` value means only that this input carries no local blocklist hit; it is
/// not affirmative policy-compliance evidence.
#[derive(Clone)]
struct FreshPeerEvidence {
    batch_id: EvidenceBatchId,
    node_id: NodeId,
    peer_id: PeerId,
    capability_public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    capability_expires_at_ms: u64,
    role: ServiceRole,
    transport: SelectionTransport,
    policy_version: u64,
    policy_hash: PolicyHash,
    policy_expires_at_ms: u64,
    address_family: Option<IpFamily>,
    observed_at_ms: u64,
    valid_until_ms: u64,
    forwarded_control: Option<ForwardedControlBinding>,
    locally_measured_p25: Option<Bandwidth>,
    measurement_count: u32,
    preselection_capacity_ceiling: Bandwidth,
    uptime_score: f64,
    proximity_score: f64,
    recent_egress_quality: f64,
    rtt_ms: Option<f64>,
    reachable: bool,
    network_address_usable: bool,
    observed_network_prefix: Option<ObservedNetworkPrefix>,
    locally_blocked: bool,
}

impl std::fmt::Debug for FreshPeerEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreshPeerEvidence")
            .field("batch_id", &self.batch_id)
            .field("identity", &"[REDACTED]")
            .field("role", &self.role)
            .field("transport", &self.transport)
            .field("address_family", &self.address_family)
            .field("observed_at_ms", &self.observed_at_ms)
            .field("valid_until_ms", &self.valid_until_ms)
            .finish_non_exhaustive()
    }
}

/// Validated, bounded evidence owned by exactly one affine local-observation batch.
struct FreshEvidenceBatch {
    batch_id: EvidenceBatchId,
    entries: Vec<FreshPeerEvidence>,
}

impl FreshEvidenceBatch {
    /// One private, purpose-bound copy for the parallel native/route admission split.
    fn for_route_admission(&self) -> Self {
        Self {
            batch_id: self.batch_id,
            entries: self.entries.clone(),
        }
    }

    #[cfg(test)]
    fn for_test(
        entries: Vec<FreshPeerEvidence>,
        trusted_now_ms: u64,
    ) -> Result<Self, SelectionBridgeError> {
        let batch_id = validate_fresh_evidence_batch(&entries, trusted_now_ms)?;
        Ok(Self { batch_id, entries })
    }

    fn validate_at(&self, trusted_now_ms: u64) -> Result<(), SelectionBridgeError> {
        if validate_fresh_evidence_batch(&self.entries, trusted_now_ms)? != self.batch_id {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
        Ok(())
    }
}

/// Exact actor identity retained for later re-resolution, without a dispatch capability.
struct ProspectivePeerBinding {
    identity: ProspectivePeerIdentity,
    advertisement_measured_at_ms: u64,
    actor_evidence_observed_at_ms: u64,
    evidence_valid_until_ms: u64,
}

/// Exit-first identity binding retained by the dormant measurement slate.
struct ProspectiveForwardedExitBinding {
    selected: SelectedForwardedExit,
    control: ProspectivePeerBinding,
    exit: ProspectivePeerBinding,
    control_diversity: DiversitySnapshot,
    exit_diversity: DiversitySnapshot,
    control_peer_evidence: CandidateEvidence,
    exit_peer_evidence: CandidateEvidence,
}

/// One relay admitted to selected-exit-specific measurement.
struct ProspectiveRelayBinding {
    relay: ProspectivePeerBinding,
    diversity: DiversitySnapshot,
    peer_evidence: CandidateEvidence,
    proof: ActorBoundRelayProof,
}

/// Private, non-cloneable phase-one output for a later one-shot measurement continuation.
///
/// The plan intentionally has no `Debug` or serialization implementation. It carries no signed
/// envelope, control endpoint, hostname, destination, complete-path scalar, reservation/session
/// identifier, or actor dispatch authority.
struct ProspectiveRoutePlan {
    batch_id: EvidenceBatchId,
    selected_at_ms: u64,
    forwarded_exit: ProspectiveForwardedExitBinding,
    scope: RouteSelectionScope,
    prospective_relays: Vec<ProspectiveRelayBinding>,
    earliest_evidence_expiry_ms: u64,
}

/// One prospective relay assigned its route-attempt path number before any live evidence.
struct PlannedProspectivePath {
    path_id: u32,
    relay: ProspectiveRelayBinding,
}

/// Dormant, pre-dispatch ownership boundary for one future live measurement attempt.
///
/// This continuation deliberately has no `Clone`, `Copy`, `Debug`, serialization, getter or
/// decomposition API. Dropping it before dispatch is cancellation by abandonment: no external
/// state exists yet and no rollback or journal mutation is required.
pub(crate) struct PreProbeContinuation {
    batch_id: EvidenceBatchId,
    selected_at_ms: u64,
    attempt_started_at_ms: u64,
    scope: RouteSelectionScope,
    forwarded_exit: ProspectiveForwardedExitBinding,
    paths: Vec<PlannedProspectivePath>,
    earliest_evidence_expiry_ms: u64,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    deadline: Instant,
    route_authority: RouteSessionAuthority,
    reservation_session: ReservationSession,
}

/// Fully assembled, still unresolved handoff state owned by the one manager task.
struct PendingPreProbeResolve {
    batch_id: EvidenceBatchId,
    attempt_started_at_ms: u64,
    selection_scope: RouteSelectionScope,
    control: ProspectivePeerBinding,
    exit: ProspectivePeerBinding,
    evidence_expiry_ms: u64,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    deadline: Instant,
    request: RouteSetupRequest,
    reservation_session: ReservationSession,
}

/// Fully validated and allocated plan parts, before either attempt authority is minted.
struct ValidatedPreProbePlan {
    batch_id: EvidenceBatchId,
    selected_at_ms: u64,
    attempt_started_at_ms: u64,
    scope: RouteSelectionScope,
    forwarded_exit: ProspectiveForwardedExitBinding,
    paths: Vec<PlannedProspectivePath>,
    earliest_evidence_expiry_ms: u64,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    deadline: Instant,
    replay_capacity: usize,
}

#[derive(Clone, Debug)]
struct AuthenticatedSelectionAdvertisement {
    advertisement: volparossa_core::NodeAdvertisement,
    signed_measured_at_ms: u64,
    signed_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    historical_reputation_score: f64,
    serious_protocol_fault_until: Option<UnixTime>,
}

impl From<&RouteCandidateAdvertisement> for AuthenticatedSelectionAdvertisement {
    fn from(candidate: &RouteCandidateAdvertisement) -> Self {
        Self {
            advertisement: candidate.advertisement().clone(),
            signed_measured_at_ms: candidate.signed_measured_at_ms(),
            signed_expires_at_ms: candidate.signed_expires_at_ms(),
            advertisement_payload_hash: candidate.advertisement_payload_hash(),
            historical_reputation_score: candidate.historical_reputation_score(),
            serious_protocol_fault_until: candidate.serious_protocol_fault_until(),
        }
    }
}

#[derive(Clone, Debug)]
struct DirectRelaySelectionInput {
    authenticated: AuthenticatedSelectionAdvertisement,
    fresh: FreshPeerEvidence,
    capability: DirectRelayCapability,
}

#[derive(Clone, Debug)]
struct ForwardedExitSelectionInput {
    authenticated: AuthenticatedSelectionAdvertisement,
    fresh: FreshPeerEvidence,
    control: DirectRelaySelectionInput,
    capability: ForwardedExitCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedExitBinding {
    control_node_id: [u8; 32],
    control_peer_id: Vec<u8>,
    control_advertisement_sequence: u64,
    control_advertisement_payload_hash: AdvertisementPayloadHash,
    node_id: NodeId,
    peer_id: PeerId,
    advertisement_sequence: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    transport: SelectionTransport,
    policy_hash: PolicyHash,
    policy_expires_at_ms: u64,
}

/// Complete, selected-exit-specific path evidence.
///
/// The embedded relay peer evidence authenticates the relay advertisement. The repeated relay
/// binding below prevents complete-path measurements from being moved to another advertisement.
#[derive(Clone, Debug)]
struct CompleteRelayPathEvidence {
    exit: SelectedExitBinding,
    relay: DirectRelaySelectionInput,
    relay_node_id: NodeId,
    relay_peer_id: PeerId,
    relay_advertisement_sequence: u64,
    relay_advertisement_payload_hash: AdvertisementPayloadHash,
    transport: SelectionTransport,
    policy_hash: PolicyHash,
    policy_expires_at_ms: u64,
    probe_address_family: ProbeAddressFamily,
    observed_at_ms: u64,
    client_to_relay_capacity: Bandwidth,
    relay_to_exit_capacity: Bandwidth,
    exit_reserved_capacity: Bandwidth,
    client_to_relay_rtt_ms: f64,
    relay_to_exit_rtt_ms: f64,
    unique_throughput_gain_ratio: f64,
    meaningful_failover: bool,
}

#[derive(Clone, Copy, Debug)]
struct RouteDeadlines {
    setup_expires_at_ms: u64,
    hard_expires_at_ms: u64,
}

/// Non-serializable route requirements applied to one actor-owned discovery snapshot.
///
/// Time and policy are deliberately absent: preflight obtains both only from the snapshot.
#[derive(Clone, Debug)]
struct SnapshotPreflightParameters {
    transport: SelectionTransport,
    minimum_capacity: Bandwidth,
    address_family: Option<IpFamily>,
    region: Option<String>,
    exit_mix: SelectionMix,
    relay_policy: RelaySelectionPolicy,
}

/// Fresh complete-path measurement without any discovery or dispatch authority.
#[derive(Clone, Debug)]
struct SnapshotRelayPathEvidence {
    exit: SelectedExitBinding,
    relay_node_id: NodeId,
    relay_peer_id: PeerId,
    relay_advertisement_sequence: u64,
    relay_advertisement_payload_hash: AdvertisementPayloadHash,
    transport: SelectionTransport,
    policy_hash: PolicyHash,
    policy_expires_at_ms: u64,
    probe_address_family: ProbeAddressFamily,
    observed_at_ms: u64,
    client_to_relay_capacity: Bandwidth,
    relay_to_exit_capacity: Bandwidth,
    exit_reserved_capacity: Bandwidth,
    client_to_relay_rtt_ms: f64,
    relay_to_exit_rtt_ms: f64,
    unique_throughput_gain_ratio: f64,
    meaningful_failover: bool,
}

/// Non-cloneable one-shot authority for a new route transaction.
///
/// Production construction always obtains both opaque identifiers directly from the operating
/// system CSPRNG. There is no production constructor from caller-chosen bytes.
struct RouteSessionAuthority {
    reservation_id: [u8; 16],
    route_context_id: [u8; 16],
}

impl RouteSessionAuthority {
    fn generate() -> Result<Self, SelectionBridgeError> {
        let mut rng = OsRng;
        for _ in 0..8 {
            let mut reservation_id = [0_u8; 16];
            let mut route_context_id = [0_u8; 16];
            rng.try_fill_bytes(&mut reservation_id)
                .map_err(|_| SelectionBridgeError::EntropyUnavailable)?;
            rng.try_fill_bytes(&mut route_context_id)
                .map_err(|_| SelectionBridgeError::EntropyUnavailable)?;
            if reservation_id.iter().any(|byte| *byte != 0)
                && route_context_id.iter().any(|byte| *byte != 0)
                && reservation_id != route_context_id
            {
                return Ok(Self {
                    reservation_id,
                    route_context_id,
                });
            }
        }
        Err(SelectionBridgeError::EntropyUnavailable)
    }

    #[cfg(test)]
    fn for_test(reservation_id: [u8; 16], route_context_id: [u8; 16]) -> Self {
        assert!(reservation_id.iter().any(|byte| *byte != 0));
        assert!(route_context_id.iter().any(|byte| *byte != 0));
        assert_ne!(reservation_id, route_context_id);
        Self {
            reservation_id,
            route_context_id,
        }
    }

    fn into_ids(mut self) -> ([u8; 16], [u8; 16]) {
        (
            std::mem::take(&mut self.reservation_id),
            std::mem::take(&mut self.route_context_id),
        )
    }
}

impl std::fmt::Debug for RouteSessionAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteSessionAuthority")
            .field("reservation_id", &"[OPAQUE]")
            .field("route_context_id", &"[OPAQUE]")
            .finish()
    }
}

impl Drop for RouteSessionAuthority {
    fn drop(&mut self) {
        self.reservation_id.fill(0);
        self.route_context_id.fill(0);
    }
}

#[derive(Debug, Error, PartialEq)]
enum SelectionBridgeError {
    #[error("invalid route-selection scope")]
    InvalidScope,
    #[error("selection input exceeds its hard candidate bound")]
    TooManyCandidates,
    #[error("stored advertisement provenance is invalid")]
    AdvertisementProvenance,
    #[error("fresh evidence is not bound to the authenticated advertisement and route")]
    EvidenceBinding,
    #[error("fresh evidence is missing, from the future, or stale")]
    StaleEvidence,
    #[error("the actor snapshot contains no complete forwarded-exit candidate")]
    SnapshotCandidatesUnavailable,
    #[error("fresh identity-bound peer evidence is unavailable")]
    FreshPeerEvidenceUnavailable,
    #[error("complete selected-exit-specific relay-path evidence is unavailable")]
    CompletePathEvidenceUnavailable,
    #[error("duplicate node or peer identity in one selection stage")]
    DuplicateIdentity,
    #[error("selected identity cannot be mapped to exactly one authenticated capability")]
    SelectedIdentityMismatch,
    #[error("route deadline exceeds setup evidence, policy or selected-advertisement lifetime")]
    InvalidDeadline,
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
    #[error("route selection failed: {0}")]
    Selection(#[source] SelectionError),
    #[error("selected input cannot form a route-setup request: {0}")]
    RouteSetup(#[source] RouteSetupError),
}

impl From<SelectionError> for SelectionBridgeError {
    fn from(error: SelectionError) -> Self {
        Self::Selection(error)
    }
}

/// Original snapshot, exact A1 freshness batch, and the retained cooldown owner.
///
/// This value grants no discovery dispatch or route authority. The private evidence deliberately
/// remains unusable for dataplane selection until a later native-path sampler proves that the
/// advertised dataplane address can carry the requested transport.
struct JoinedPreselectionFreshEvidence {
    snapshot: RouteCandidateSnapshot,
    evidence_batch: FreshEvidenceBatch,
    gate: CoolingPreselectionAttemptGate,
}

/// Opaque, affine handoff from the discovery owner to the later native-path sampler.
///
/// This wrapper deliberately exposes neither the retained actor snapshot nor the private Fresh
/// batch. It grants no route, reservation, dispatch, or dataplane authority. Only the private
/// native-preselection child may consume it to mint a bounded probe attempt; the handoff itself
/// never establishes dataplane-address usability.
#[must_use = "prepared preselection evidence must remain with its route owner"]
pub(crate) struct PreparedPreselectionEvidence {
    snapshot: RouteCandidateSnapshot,
    evidence_batch: FreshEvidenceBatch,
}

/// Config-bound selection inputs retained only long enough to mint the real route continuation.
#[derive(Clone, Debug)]
pub(crate) struct ClientRouteAdmissionProfile {
    preflight: SnapshotPreflightParameters,
    hard_lifetime: Duration,
}

impl ClientRouteAdmissionProfile {
    pub(crate) fn new(
        transport: SelectionTransport,
        minimum_capacity: Bandwidth,
        address_family: IpFamily,
        exit_mix: SelectionMix,
        relay_policy: RelaySelectionPolicy,
        hard_lifetime: Duration,
    ) -> Self {
        Self {
            preflight: SnapshotPreflightParameters {
                transport,
                minimum_capacity,
                address_family: Some(address_family),
                region: None,
                exit_mix,
                relay_policy,
            },
            hard_lifetime,
        }
    }
}

/// Affine production continuation after the first Exit Permit crossed its selected control Relay.
///
/// The remaining candidates, replay cache, and verified Permit stay together for the later
/// Relay-ready/helper-backed stages; none is projected into the local control protocol.
#[must_use = "native client preselection must remain owned by the route coordinator"]
pub(crate) struct ClientNativePreselection {
    batch: ClientNativeProbeBatchOwner,
    awaiting_relay_ready: native_preselection::AwaitingNativeRelayReady,
}

/// Affine owner shared by every path in one native candidate-set attempt.
///
/// Ready authorities are collected before the helper is touched. They then advance through one
/// shared attempt-ID route context and one exact multi-lease helper lifecycle.
#[must_use = "native path-batch ownership must remain affine"]
struct ClientNativeProbeBatchOwner {
    owner: native_preselection::NativePreselectionAttemptOwner,
    route_plan: Option<ProspectiveRoutePlan>,
    route_hard_lifetime: Duration,
    replay: volparossa_protocol::ReplayCache,
    armed: Vec<native_preselection::ArmedNativeProbe>,
    proofs: Vec<native_preselection::BoundNativePathProof>,
    committed_owner: Option<RuntimeBoundPreparedLeaseBatch>,
}

/// Terminal proof-to-evidence rejection with cooldown ownership retained.
struct PreselectionEvidenceJoinFailure {
    gate: CoolingPreselectionAttemptGate,
    error: SelectionBridgeError,
}

/// Verified data-Relay readiness awaiting one same-runtime helper Prepare.
#[must_use = "verified Relay readiness must remain with its affine native attempt"]
pub(crate) struct ClientNativeRelayReady {
    batch: ClientNativeProbeBatchOwner,
    armed: native_preselection::ArmedNativeProbe,
}

/// Helper-prepared local endpoint awaiting exact activation before Start can be signed.
#[must_use = "a prepared native Client context must be activated or destroyed"]
pub(crate) struct PreparedClientNativeProbe {
    batch: ClientNativeProbeBatchOwner,
    prepared_owner: RuntimeBoundPreparedLeaseBatch,
    helper_runtime_id: [u8; 32],
    route_context_id: [u8; 16],
    context_handle: Vec<u8>,
    paths: Vec<PreparedClientNativePath>,
    hard_expires_at_unix: u64,
}

struct PreparedClientNativePath {
    armed: native_preselection::ArmedNativeProbe,
    path_id: u32,
    lease_handle: Vec<u8>,
    prepared_lease_commitment: [u8; 32],
    endpoint_binding: NativeProbeEndpointBinding,
    relay_endpoint: WireguardEndpoint,
}

/// Helper-prepared Client context with exact standard Relay activation authority attached.
#[must_use = "an authorized native Client context must be activated or destroyed"]
pub(crate) struct AuthorizedPreparedClientNativeProbe {
    batch: ClientNativeProbeBatchOwner,
    prepared_owner: RuntimeBoundPreparedLeaseBatch,
    helper_runtime_id: [u8; 32],
    route_context_id: [u8; 16],
    context_handle: Vec<u8>,
    paths: Vec<AuthorizedClientNativePath>,
    activation: ActivateLeaseBatch,
}

struct AuthorizedClientNativePath {
    awaiting: native_preselection::AwaitingNativeResult,
    path_id: u32,
    lease_handle: Vec<u8>,
    prepared_lease_commitment: [u8; 32],
}

/// Signed Start dispatched to the exact data Relay and awaiting local helper commit proof.
#[must_use = "a started native Client probe must consume helper proof or be destroyed"]
pub(crate) struct AwaitingClientNativeProbeResult {
    batch: ClientNativeProbeBatchOwner,
    prepared_owner: RuntimeBoundPreparedLeaseBatch,
    helper_runtime_id: [u8; 32],
    route_context_id: [u8; 16],
    context_handle: Vec<u8>,
    paths: Vec<AwaitingClientNativePathResult>,
}

struct AwaitingClientNativePathResult {
    awaiting: native_preselection::AwaitingNativeResult,
    path_id: u32,
    lease_handle: Vec<u8>,
    prepared_lease_commitment: [u8; 32],
}

/// One or more terminal cryptographic path proofs plus remaining affine candidate ownership.
#[must_use = "native proof-batch ownership must remain with later route admission"]
pub(crate) struct CompletedClientNativeProbe {
    batch: ClientNativeProbeBatchOwner,
    sampler_destroyed: bool,
}

/// Terminal sampler ownership plus the real, still-undispatched reservation continuation.
#[must_use = "native route admission must retire the sampler context and execute the continuation"]
pub(crate) struct PreparedNativeRouteAdmission {
    continuation: PreProbeContinuation,
    sampler_owner: RuntimeBoundPreparedLeaseBatch,
    remote_retirement: RemoteNativeSamplerRetirement,
}

enum RemoteNativeSamplerRetirement {
    AwaitingProtocolAcknowledgement,
}

impl PreparedNativeRouteAdmission {
    /// Consume the admission into its route handoff, local cleanup owner, and remote-ack status.
    pub(crate) fn into_parts(self) -> (PreProbeContinuation, RuntimeBoundPreparedLeaseBatch, bool) {
        let confirmed = !matches!(
            self.remote_retirement,
            RemoteNativeSamplerRetirement::AwaitingProtocolAcknowledgement
        );
        (self.continuation, self.sampler_owner, confirmed)
    }
}

// One path accepts Request, Permit, Relay Ready, Relay reservation, nested Exit authorization,
// Relay Result, and nested Exit Result envelopes into the shared fail-closed replay cache.
const CLIENT_NATIVE_REPLAY_ENTRIES_PER_PATH: usize = 7;

/// Failure while binding the exact helper lifecycle to the native probe transcript.
#[derive(Debug, Error)]
pub(crate) enum ClientNativeProbeError {
    #[error(transparent)]
    Native(#[from] native_preselection::NativePreselectionError),
    #[error(transparent)]
    Endpoint(#[from] EndpointLeaseBindingError),
    #[error("native Client helper response did not match its exact prepared context")]
    HelperCorrelation,
}

/// Exact Destroy authority retained when post-Prepare endpoint binding fails closed.
#[must_use = "a failed post-Prepare bind still owns one helper context cleanup"]
pub(crate) struct ClientNativePreparedBindFailure {
    error: ClientNativeProbeError,
    cleanup: DestroyContext,
}

impl ClientNativePreparedBindFailure {
    /// Borrow the binding failure classification.
    pub(crate) fn error(&self) -> &ClientNativeProbeError {
        &self.error
    }

    /// Consume the failure into its exact helper cleanup request.
    pub(crate) fn into_cleanup(self) -> DestroyContext {
        self.cleanup
    }
}

/// Consume one actor-owned A1 handoff and dispatch its first native Permit only through the exact
/// selected control Relay.
pub(crate) async fn begin_client_native_preselection(
    prepared: PreparedPreselectionEvidence,
    admission: ClientRouteAdmissionProfile,
    discovery: &DiscoveryControlHandle,
) -> Result<ClientNativePreselection, native_preselection::NativePreselectionError> {
    let replay_capacity = volparossa_protocol::MAX_NATIVE_PROBE_CANDIDATES
        .checked_mul(CLIENT_NATIVE_REPLAY_ENTRIES_PER_PATH)
        .ok_or(native_preselection::NativePreselectionError::InvalidCandidateSet)?;
    let route_plan = snapshot_route_plan(
        &prepared.snapshot,
        admission.preflight,
        prepared.evidence_batch.for_route_admission(),
        &mut OsRng,
    )
    .map_err(|_| native_preselection::NativePreselectionError::InvalidCandidateSet)?;
    let selected_data_relays = route_plan
        .prospective_relays
        .iter()
        .map(|relay| {
            native_preselection::NativeDataRelayIdentity::new(
                relay.relay.identity.wire_node_id,
                relay.relay.identity.peer_id.to_bytes(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ClientNativeProbeBatchOwner {
        owner: native_preselection::begin_native_preselection(prepared, &selected_data_relays)?,
        route_plan: Some(route_plan),
        route_hard_lifetime: admission.hard_lifetime,
        replay: volparossa_protocol::ReplayCache::new(replay_capacity)?,
        armed: Vec::new(),
        proofs: Vec::new(),
        committed_owner: None,
    }
    .dispatch_next_permit(discovery)
    .await
}

impl ClientNativeProbeBatchOwner {
    /// Consume exactly one remaining candidate into the selected control-Relay Permit RPC.
    async fn dispatch_next_permit(
        mut self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ClientNativePreselection, native_preselection::NativePreselectionError> {
        if !self.proofs.is_empty() || self.committed_owner.is_some() {
            return Err(native_preselection::NativePreselectionError::InvalidCandidateSet);
        }
        let awaiting = self
            .owner
            .begin_next()?
            .ok_or(native_preselection::NativePreselectionError::InvalidCandidateSet)?;
        let dispatch = awaiting.into_forward_dispatch()?;
        let awaiting_relay_ready = dispatch.execute(discovery, &mut self.replay).await?;
        Ok(ClientNativePreselection {
            batch: self,
            awaiting_relay_ready,
        })
    }
}

impl ClientNativePreselection {
    /// Dispatch the endpoint-free request/Permit pair only to the selected data Relay.
    pub(crate) async fn dispatch_relay_ready(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ClientNativeRelayReady, ClientNativeProbeError> {
        let Self {
            mut batch,
            awaiting_relay_ready,
        } = self;
        let armed = awaiting_relay_ready
            .into_relay_ready_dispatch()?
            .execute(discovery, &mut batch.replay)
            .await?;
        Ok(ClientNativeRelayReady { batch, armed })
    }
}

impl ClientNativeRelayReady {
    /// Total candidate-set paths that must prove native reachability before admission.
    pub(crate) fn candidate_path_count(&self) -> usize {
        self.batch.owner.candidate_count()
    }

    /// Number of exact Ready authorities retained for the shared helper lifecycle.
    pub(crate) fn ready_path_count(&self) -> usize {
        self.batch.armed.len() + 1
    }

    /// Retain this Ready authority and dispatch the next candidate without touching the helper.
    pub(crate) async fn retain_and_dispatch_next_permit(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ClientNativePreselection, ClientNativeProbeError> {
        let Self { mut batch, armed } = self;
        batch.armed.push(armed);
        Ok(batch.dispatch_next_permit(discovery).await?)
    }

    /// Exact shared-context Client plan a lifecycle owner may dispatch to the helper.
    pub(crate) fn prepare_request(&self) -> Result<PrepareLeaseBatch, ClientNativeProbeError> {
        let mut route_context_id = None;
        let mut path_ids = HashSet::with_capacity(self.ready_path_count());
        let mut expires_at_ms = u64::MAX;
        let mut leases = Vec::with_capacity(self.ready_path_count());
        for armed in self.batch.armed.iter().chain(std::iter::once(&self.armed)) {
            let (context, path_id, _relay_endpoint, path_expires_at_ms) = armed.helper_scope()?;
            if route_context_id.is_some_and(|expected| expected != context)
                || !path_ids.insert(path_id)
            {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
            route_context_id = Some(context);
            expires_at_ms = expires_at_ms.min(path_expires_at_ms);
            leases.push(LeasePlan {
                path_id,
                role: WireguardRole::Client as i32,
            });
        }
        leases.sort_by_key(|lease| lease.path_id);
        let route_context_id = route_context_id.ok_or(ClientNativeProbeError::HelperCorrelation)?;
        let expires_at_unix = expires_at_ms / 1_000;
        if expires_at_unix <= crate::unix_seconds() {
            return Err(native_preselection::NativePreselectionError::InvalidDeadline.into());
        }
        let path_count =
            u32::try_from(leases.len()).map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
        Ok(PrepareLeaseBatch {
            route_context_id: route_context_id.to_vec(),
            role: ContextRole::Client as i32,
            mptcp_accepted_addrs: path_count,
            mptcp_subflows: path_count,
            leases,
            setup_expires_at_unix: expires_at_unix,
            hard_expires_at_unix: expires_at_unix,
        })
    }

    /// Bind one same-runtime helper response while preserving exact cleanup on every rejection.
    pub(crate) fn bind_prepared_endpoint(
        self,
        request: &PrepareLeaseBatch,
        prepared: RuntimeBoundPreparedLeaseBatch,
    ) -> Result<PreparedClientNativeProbe, ClientNativePreparedBindFailure> {
        let cleanup = prepared.destroy_request();
        self.bind_prepared_endpoint_inner(request, prepared)
            .map_err(|error| ClientNativePreparedBindFailure { error, cleanup })
    }

    fn bind_prepared_endpoint_inner(
        self,
        request: &PrepareLeaseBatch,
        prepared: RuntimeBoundPreparedLeaseBatch,
    ) -> Result<PreparedClientNativeProbe, ClientNativeProbeError> {
        let Self { mut batch, armed } = self;
        batch.armed.push(armed);
        let armed = std::mem::take(&mut batch.armed);
        let endpoints = bind_prepared_endpoint_leases(request, prepared.prepared().clone())?;
        if endpoints.client_leases().len() != armed.len() {
            return Err(ClientNativeProbeError::HelperCorrelation);
        }
        let helper_runtime_id = prepared.helper_runtime_id();
        let route_context_id: [u8; 16] = request
            .route_context_id
            .as_slice()
            .try_into()
            .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
        let mut paths = Vec::with_capacity(armed.len());
        for armed in armed {
            let (context, path_id, relay_binding, _expires_at_ms) = armed.helper_scope()?;
            let lease = endpoints
                .client_leases()
                .iter()
                .find(|lease| lease.path_id() == path_id)
                .ok_or(ClientNativeProbeError::HelperCorrelation)?;
            if context != route_context_id {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
            let local_endpoint = protocol_endpoint_for_native(lease.public_endpoint());
            let lease_handle = *lease.lease_handle().as_bytes();
            let commitment = native_probe_prepared_lease_commitment(
                &helper_runtime_id,
                &route_context_id,
                &lease_handle,
                &local_endpoint,
            )
            .map_err(native_preselection::NativePreselectionError::from)?;
            let endpoint_binding = NativeProbeEndpointBinding {
                helper_runtime_id: helper_runtime_id.to_vec(),
                route_context_id: route_context_id.to_vec(),
                endpoint: Some(local_endpoint),
                prepared_lease_commitment: commitment.to_vec(),
                path_id,
            };
            let relay_endpoint = relay_binding
                .endpoint
                .as_ref()
                .ok_or(ClientNativeProbeError::HelperCorrelation)?
                .clone();
            paths.push(PreparedClientNativePath {
                armed,
                path_id,
                lease_handle: lease_handle.to_vec(),
                prepared_lease_commitment: commitment,
                endpoint_binding,
                relay_endpoint,
            });
        }
        paths.sort_by_key(|path| path.path_id);
        Ok(PreparedClientNativeProbe {
            batch,
            prepared_owner: prepared,
            helper_runtime_id,
            route_context_id,
            context_handle: endpoints.context_handle().as_bytes().to_vec(),
            paths,
            hard_expires_at_unix: request.hard_expires_at_unix,
        })
    }
}

impl PreparedClientNativeProbe {
    /// Destroy authority retained from this successful local Prepare.
    pub(crate) fn destroy_request(&self) -> DestroyContext {
        self.prepared_owner.destroy_request()
    }

    /// Sign Start, obtain one exact standard nested reservation, and bind it before activation.
    pub(crate) async fn request_activation_authority(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<AuthorizedPreparedClientNativeProbe, ClientNativePreparedBindFailure> {
        let cleanup = self.destroy_request();
        Box::pin(self.request_activation_authority_inner(discovery))
            .await
            .map_err(|error| ClientNativePreparedBindFailure { error, cleanup })
    }

    async fn request_activation_authority_inner(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<AuthorizedPreparedClientNativeProbe, ClientNativeProbeError> {
        let Self {
            mut batch,
            prepared_owner,
            helper_runtime_id,
            route_context_id,
            context_handle,
            paths,
            hard_expires_at_unix,
        } = self;
        let mut authorized_paths = Vec::with_capacity(paths.len());
        let mut activations = Vec::with_capacity(paths.len());
        for path in paths {
            let scope = path.armed.path_scope().clone();
            let awaiting = path.armed.start(path.endpoint_binding.clone())?;
            let (awaiting, signed_relay_reservation) = awaiting
                .into_relay_authorization_dispatch()?
                .execute(discovery)
                .await?;
            let now_ms = crate::unix_millis();
            verify_native_client_activation_authority(
                &scope,
                path.endpoint_binding
                    .endpoint
                    .as_ref()
                    .ok_or(ClientNativeProbeError::HelperCorrelation)?,
                &path.relay_endpoint,
                hard_expires_at_unix,
                awaiting.encoded_start(),
                &signed_relay_reservation,
                now_ms,
                &mut batch.replay,
            )?;
            activations.push(LeaseActivation {
                lease_handle: path.lease_handle.clone(),
                path_id: path.path_id,
                role: WireguardRole::Client as i32,
                peer_public_key: path.relay_endpoint.public_key.clone(),
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: path.relay_endpoint.underlay_ip.clone(),
                    port: path.relay_endpoint.listen_port,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation,
                signed_client_relay_request: Vec::new(),
            });
            authorized_paths.push(AuthorizedClientNativePath {
                awaiting,
                path_id: path.path_id,
                lease_handle: path.lease_handle,
                prepared_lease_commitment: path.prepared_lease_commitment,
            });
        }
        let activation = ActivateLeaseBatch {
            route_context_id: route_context_id.to_vec(),
            context_handle: context_handle.clone(),
            leases: activations,
        };
        Ok(AuthorizedPreparedClientNativeProbe {
            batch,
            prepared_owner,
            helper_runtime_id,
            route_context_id,
            context_handle,
            paths: authorized_paths,
            activation,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the native seam binds one signed route authority to both prepared endpoints and scope"
)]
fn verify_native_client_activation_authority(
    scope: &NativeProbePathScope,
    local_endpoint: &WireguardEndpoint,
    relay_endpoint: &WireguardEndpoint,
    hard_expires_at_unix: u64,
    signed_start: &[u8],
    signed_relay_reservation: &[u8],
    now_ms: u64,
    replay_cache: &mut volparossa_protocol::ReplayCache,
) -> Result<(), ClientNativeProbeError> {
    let (relay, exit) = verify_relay_reservation(
        signed_relay_reservation,
        now_ms,
        TimePolicy::default(),
        replay_cache,
    )
    .map_err(native_preselection::NativePreselectionError::from)?;
    let data_relay = scope
        .data_relay
        .as_ref()
        .ok_or(ClientNativeProbeError::HelperCorrelation)?;
    let selected_exit = scope
        .exit
        .as_ref()
        .ok_or(ClientNativeProbeError::HelperCorrelation)?;
    let control = scope
        .control
        .as_ref()
        .ok_or(ClientNativeProbeError::HelperCorrelation)?;
    let relay_message = relay.message();
    let signed_start_sha256: [u8; 32] = Sha256::digest(signed_start).into();
    let hard_expires_at_ms = hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(ClientNativeProbeError::HelperCorrelation)?;
    if relay.sender_id().as_slice() != data_relay.node_id
        || exit.sender_id().as_slice() != selected_exit.node_id
        || relay_message.reservation_id != scope.probe_id
        || relay_message.route_context_id != scope.attempt_id
        || relay_message.path_id != scope.candidate_ordinal
        || relay_message.relay_node_id != data_relay.node_id
        || relay_message.relay_peer_id != data_relay.peer_id
        || relay_message.exit_node_id != selected_exit.node_id
        || relay_message.exit_peer_id != selected_exit.peer_id
        || relay_message.control_relay_node_id != control.node_id
        || relay_message.control_relay_peer_id != control.peer_id
        || relay_message.client_session_id != scope.client_session_id
        || relay_message.client_session_public_key != scope.client_session_public_key
        || relay_message.capability_id != scope.attempt_id
        || relay_message.hold_id != scope.probe_id
        || !relay_message.allowed_transports.contains(&scope.transport)
        || relay_message.policy_hash != scope.policy_hash
        || relay_message.client_wireguard_public_key != local_endpoint.public_key
        || relay_message.relay_client_wireguard_endpoint.as_ref() != Some(relay_endpoint)
        || relay_message.signed_client_relay_request_sha256 != signed_start_sha256
        || relay.expires_at_ms() < hard_expires_at_ms
        || relay.expires_at_ms() > scope.attempt_expires_at_ms
    {
        return Err(ClientNativeProbeError::HelperCorrelation);
    }
    Ok(())
}

impl AuthorizedPreparedClientNativeProbe {
    /// Borrow the exact shared-context Client activation request.
    pub(crate) fn activation_request(&self) -> &ActivateLeaseBatch {
        &self.activation
    }

    /// Borrow the affine helper owner for the exact same-runtime activation call.
    pub(crate) fn runtime_owner_mut(&mut self) -> &mut RuntimeBoundPreparedLeaseBatch {
        &mut self.prepared_owner
    }

    /// Destroy authority retained throughout helper activation.
    pub(crate) fn destroy_request(&self) -> DestroyContext {
        self.prepared_owner.destroy_request()
    }

    /// Exchange each exact one-shot challenge through its Activated-only helper socket.
    pub(crate) async fn exchange_challenges(
        &self,
        helper: &HelperClient,
    ) -> Result<(), ClientNativeProbeError> {
        for path in &self.paths {
            let request = native_probe_client_socket_request(
                self.route_context_id,
                &self.context_handle,
                path.path_id,
            )?;
            let acquired = helper
                .acquire_transport_socket(request.clone())
                .await
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
            if acquired.metadata().path_id != request.path_id
                || acquired.metadata().role != request.role
                || acquired.metadata().descriptor_kind != request.descriptor_kind
                || acquired.metadata().local != request.expected_local
                || acquired.metadata().remote != request.expected_remote
            {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
            let (descriptor, _) = acquired.into_parts();
            let socket = StdUdpSocket::from(descriptor);
            socket
                .set_nonblocking(true)
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
            let socket = UdpSocket::from_std(socket)
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
            let challenge = path.awaiting.challenge();
            let sent = timeout(NATIVE_PROBE_CHALLENGE_TIMEOUT, socket.send(challenge))
                .await
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
            if sent != NATIVE_PROBE_DATAGRAM_BYTES {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
            let mut echoed = [0_u8; NATIVE_PROBE_DATAGRAM_BYTES];
            let received = timeout(NATIVE_PROBE_CHALLENGE_TIMEOUT, socket.recv(&mut echoed))
                .await
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?
                .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
            if received != NATIVE_PROBE_DATAGRAM_BYTES || echoed.as_slice() != challenge {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
        }
        Ok(())
    }

    /// Correlate the exact helper activation before any terminal Start is dispatched.
    pub(crate) fn accept_activation(
        self,
        activated: &ActivatedLeaseBatch,
    ) -> Result<AwaitingClientNativeProbeResult, ClientNativeProbeError> {
        if activated.context_handle != self.context_handle
            || activated
                .lease_handles
                .iter()
                .map(Vec::as_slice)
                .ne(self.paths.iter().map(|path| path.lease_handle.as_slice()))
        {
            return Err(ClientNativeProbeError::HelperCorrelation);
        }
        let mut paths = Vec::with_capacity(self.paths.len());
        for path in self.paths {
            paths.push(AwaitingClientNativePathResult {
                awaiting: path.awaiting,
                path_id: path.path_id,
                lease_handle: path.lease_handle,
                prepared_lease_commitment: path.prepared_lease_commitment,
            });
        }
        Ok(AwaitingClientNativeProbeResult {
            batch: self.batch,
            prepared_owner: self.prepared_owner,
            helper_runtime_id: self.helper_runtime_id,
            route_context_id: self.route_context_id,
            context_handle: self.context_handle,
            paths,
        })
    }
}

impl AwaitingClientNativeProbeResult {
    /// Borrow the affine helper owner for the exact same-runtime commit call.
    pub(crate) fn runtime_owner_mut(&mut self) -> &mut RuntimeBoundPreparedLeaseBatch {
        &mut self.prepared_owner
    }

    /// Exact helper commit request for every activated Client path.
    pub(crate) fn commit_request(&self) -> CommitLeaseBatch {
        CommitLeaseBatch {
            route_context_id: self.route_context_id.to_vec(),
            context_handle: self.context_handle.clone(),
            leases: self
                .paths
                .iter()
                .map(|path| LeaseCommit {
                    lease_handle: path.lease_handle.clone(),
                    path_id: path.path_id,
                    role: WireguardRole::Client as i32,
                })
                .collect(),
        }
    }

    /// Destroy authority retained throughout Start/result verification.
    pub(crate) fn destroy_request(&self) -> DestroyContext {
        self.prepared_owner.destroy_request()
    }

    /// Consume local commit facts, then dispatch every terminal Start concurrently.
    pub(crate) async fn accept_committed_and_dispatch(
        mut self,
        committed: CommittedLeaseBatch,
        discovery: &DiscoveryControlHandle,
    ) -> Result<CompletedClientNativeProbe, ClientNativeProbeError> {
        if committed.context_handle != self.context_handle
            || committed.leases.len() != self.paths.len()
        {
            return Err(ClientNativeProbeError::HelperCorrelation);
        }
        let mut dispatches = JoinSet::new();
        for (path, lease) in self.paths.into_iter().zip(committed.leases) {
            if lease.lease_handle != path.lease_handle
                || lease.latest_handshake_unix == 0
                || lease.received_bytes == 0
                || lease.transmitted_bytes == 0
            {
                return Err(ClientNativeProbeError::HelperCorrelation);
            }
            let discovery = discovery.clone();
            dispatches.spawn(async move {
                let dispatch = path.awaiting.into_relay_start_dispatch()?;
                let (awaiting, signed_relay_result) = dispatch.execute(&discovery).await?;
                Ok::<_, native_preselection::NativePreselectionError>((
                    path.path_id,
                    path.prepared_lease_commitment,
                    lease,
                    awaiting,
                    signed_relay_result,
                ))
            });
        }
        let mut results = Vec::with_capacity(dispatches.len());
        while let Some(joined) = dispatches.join_next().await {
            results.push(joined.map_err(|_| {
                ClientNativeProbeError::Native(
                    native_preselection::NativePreselectionError::RelayTransportUnavailable,
                )
            })??);
        }
        results.sort_unstable_by_key(|(path_id, ..)| *path_id);
        for (_path_id, prepared_lease_commitment, lease, awaiting, signed_relay_result) in results {
            let proof = awaiting.accept_result(
                NativeProbeLeaseProof {
                    helper_runtime_id: self.helper_runtime_id.to_vec(),
                    route_context_id: self.route_context_id.to_vec(),
                    prepared_lease_commitment: prepared_lease_commitment.to_vec(),
                    latest_handshake_unix: lease.latest_handshake_unix,
                    received_bytes_after_baseline: lease.received_bytes,
                    transmitted_bytes_after_baseline: lease.transmitted_bytes,
                },
                &signed_relay_result,
                &mut self.batch.replay,
            )?;
            self.batch.proofs.push(proof);
        }
        self.batch.committed_owner = Some(self.prepared_owner);
        Ok(CompletedClientNativeProbe {
            batch: self.batch,
            sampler_destroyed: false,
        })
    }
}

impl CompletedClientNativeProbe {
    /// Borrow the exact committed sampler owner for terminal confirmed destruction.
    pub(crate) fn runtime_owner(
        &self,
    ) -> Result<&RuntimeBoundPreparedLeaseBatch, ClientNativeProbeError> {
        self.batch
            .committed_owner
            .as_ref()
            .ok_or(ClientNativeProbeError::HelperCorrelation)
    }

    /// Consume a correlated helper Destroy acknowledgement before route admission can continue.
    pub(crate) fn accept_destroyed(
        mut self,
        _destroyed: DestroyedContext,
    ) -> Result<Self, ClientNativeProbeError> {
        self.batch
            .committed_owner
            .take()
            .ok_or(ClientNativeProbeError::HelperCorrelation)?;
        self.sampler_destroyed = true;
        Ok(self)
    }

    /// Number of exact per-path Result proofs retained with the shared committed helper context.
    pub(crate) fn completed_path_count(&self) -> usize {
        debug_assert!(self.batch.committed_owner.is_none());
        debug_assert!(self.sampler_destroyed);
        self.batch.proofs.len()
    }

    /// Consume terminal native evidence into the existing production route continuation.
    pub(crate) fn into_route_admission(
        mut self,
    ) -> Result<PreparedNativeRouteAdmission, ClientNativeProbeError> {
        let plan = self
            .batch
            .route_plan
            .take()
            .ok_or(ClientNativeProbeError::HelperCorrelation)?;
        let sampler_owner = self
            .batch
            .committed_owner
            .take()
            .ok_or(ClientNativeProbeError::HelperCorrelation)?;
        let proven_relays = self
            .batch
            .proofs
            .iter()
            .map(|proof| {
                let relay = proof.data_relay();
                (relay.node_id.clone(), relay.peer_id.clone())
            })
            .collect::<HashSet<_>>();
        let expected_relays = plan
            .prospective_relays
            .iter()
            .map(|relay| &relay.relay.identity)
            .map(|identity| (identity.wire_node_id.to_vec(), identity.peer_id.to_bytes()))
            .collect::<HashSet<_>>();
        if proven_relays.len() != self.batch.proofs.len()
            || expected_relays.len() != self.batch.proofs.len()
            || proven_relays != expected_relays
        {
            return Err(ClientNativeProbeError::HelperCorrelation);
        }
        let now_ms = crate::unix_millis();
        let setup_ceiling_ms = now_ms
            .checked_add(
                u64::try_from(MAXIMUM_SETUP_DURATION.as_millis())
                    .map_err(|_| ClientNativeProbeError::HelperCorrelation)?,
            )
            .ok_or(ClientNativeProbeError::HelperCorrelation)?
            .min(plan.earliest_evidence_expiry_ms);
        let actor_hard_ceiling_ms = std::iter::once(&plan.forwarded_exit.control.identity)
            .chain(std::iter::once(&plan.forwarded_exit.exit.identity))
            .chain(
                plan.prospective_relays
                    .iter()
                    .map(|relay| &relay.relay.identity),
            )
            .map(|identity| {
                identity
                    .advertisement_expires_at_ms
                    .min(identity.policy_expires_at_ms)
                    .min(identity.expires_at_ms)
            })
            .min()
            .ok_or(ClientNativeProbeError::HelperCorrelation)?;
        let hard_expires_at_ms = now_ms
            .checked_add(
                u64::try_from(self.batch.route_hard_lifetime.as_millis())
                    .map_err(|_| ClientNativeProbeError::HelperCorrelation)?,
            )
            .ok_or(ClientNativeProbeError::HelperCorrelation)?
            .min(plan.scope.policy.expires_at_ms)
            .min(actor_hard_ceiling_ms);
        if hard_expires_at_ms < setup_ceiling_ms {
            return Err(ClientNativeProbeError::HelperCorrelation);
        }
        let limits = RouteSetupLimits::new(
            MAXIMUM_SETUP_DURATION,
            super::MAXIMUM_CALL_DURATION,
            super::MAXIMUM_OUTBOUND_ATTEMPTS,
        )
        .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
        let continuation = consume_prospective_route_plan(
            plan,
            RouteDeadlines {
                setup_expires_at_ms: setup_ceiling_ms,
                hard_expires_at_ms,
            },
            limits,
            MAXIMUM_REPLAY_CAPACITY,
        )
        .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
        Ok(PreparedNativeRouteAdmission {
            continuation,
            sampler_owner,
            remote_retirement: RemoteNativeSamplerRetirement::AwaitingProtocolAcknowledgement,
        })
    }
}

fn native_probe_client_socket_request(
    route_context_id: [u8; 16],
    context_handle: &[u8],
    path_id: u32,
) -> Result<AcquireTransportSocket, ClientNativeProbeError> {
    let path_number =
        u8::try_from(path_id).map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
    let addresses = overlay_addresses(route_context_id, path_number)
        .map_err(|_| ClientNativeProbeError::HelperCorrelation)?;
    Ok(AcquireTransportSocket {
        route_context_id: route_context_id.to_vec(),
        context_handle: context_handle.to_vec(),
        path_id,
        role: WireguardRole::Client as i32,
        descriptor_kind: TransportSocketKind::NativeProbeUdpConnected as i32,
        expected_local: Some(TransportSocketAddress {
            address: addresses.client.octets().to_vec(),
            port: u32::from(NATIVE_PROBE_CLIENT_PORT),
        }),
        expected_remote: Some(TransportSocketAddress {
            address: addresses.exit.octets().to_vec(),
            port: u32::from(NATIVE_PROBE_EXIT_PORT),
        }),
    })
}

struct ActorFreshnessProjection {
    observed_network_prefix: ObservedNetworkPrefix,
    observed_at_ms: u64,
    round_trip: Duration,
    signed_valid_until_ms: u64,
}

/// Consume the complete discovery proof chain into one opaque selection-child handoff.
///
/// The discovery actor retains the returned cooldown gate. On failure it receives only that gate;
/// no partially minted Fresh evidence or reusable proof authority escapes this boundary.
pub(crate) fn prepare_preselection_evidence(
    completed: CompletedPreselectionFreshnessAttempt,
) -> Result<
    (PreparedPreselectionEvidence, CoolingPreselectionAttemptGate),
    CoolingPreselectionAttemptGate,
> {
    prepare_preselection_evidence_at(completed, crate::unix_millis())
}

fn prepare_preselection_evidence_at(
    completed: CompletedPreselectionFreshnessAttempt,
    trusted_now_ms: u64,
) -> Result<
    (PreparedPreselectionEvidence, CoolingPreselectionAttemptGate),
    CoolingPreselectionAttemptGate,
> {
    match join_preselection_fresh_evidence_at(completed, trusted_now_ms) {
        Ok(JoinedPreselectionFreshEvidence {
            snapshot,
            evidence_batch,
            gate,
        }) => Ok((
            PreparedPreselectionEvidence {
                snapshot,
                evidence_batch,
            },
            gate,
        )),
        Err(failure) => Err(failure.gate),
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the terminal error must retain the non-cloneable cooldown owner affinely"
)]
fn join_preselection_fresh_evidence_at(
    completed: CompletedPreselectionFreshnessAttempt,
    trusted_now_ms: u64,
) -> Result<JoinedPreselectionFreshEvidence, PreselectionEvidenceJoinFailure> {
    let (snapshot, proof_batch, gate) = completed.into_parts();
    match fresh_evidence_batch_from_preselection(&snapshot, proof_batch, trusted_now_ms) {
        Ok(evidence_batch) => Ok(JoinedPreselectionFreshEvidence {
            snapshot,
            evidence_batch,
            gate,
        }),
        Err(error) => Err(PreselectionEvidenceJoinFailure { gate, error }),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one auditable affine mint validates the complete exact-set before producing private evidence"
)]
fn fresh_evidence_batch_from_preselection(
    snapshot: &RouteCandidateSnapshot,
    proof_batch: BoundPreselectionFreshnessProofBatch,
    trusted_now_ms: u64,
) -> Result<FreshEvidenceBatch, SelectionBridgeError> {
    let (
        protocol_transport,
        protocol_family,
        batch_bytes,
        attempt_started_at_ms,
        attempt_deadline_ms,
        minimum_capacity,
        preselection_capacity_ceiling,
        records,
    ) = proof_batch.into_parts();
    let transport = selection_transport(protocol_transport)?;
    let family = selection_family(protocol_family)?;
    let direct_count = snapshot.direct_relays().len();
    if batch_bytes == [0; ID_BYTES]
        || snapshot.forwarded_exits().len() != 1
        || !(2..=9).contains(&direct_count)
        || records.len() != direct_count
        || attempt_started_at_ms == 0
        || attempt_started_at_ms > trusted_now_ms
        || trusted_now_ms >= attempt_deadline_ms
        || minimum_capacity.validate().is_err()
        || minimum_capacity.up_mbps == 0
        || minimum_capacity.down_mbps == 0
        || preselection_capacity_ceiling.validate().is_err()
        || !preselection_capacity_ceiling.satisfies(minimum_capacity)
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let forwarded = &snapshot.forwarded_exits()[0];
    let control_index = exact_control_candidate_index(snapshot, forwarded)?;
    let exit_subject = direct_count;
    let mut relay_projections = (0..direct_count).map(|_| None).collect::<Vec<_>>();
    let mut exit_projection = None;
    for record in records {
        let (subject, forwarded_control, role, transport_facts, transcript_facts) =
            record.into_parts();
        let local_projection = actor_projection(
            &transport_facts,
            transcript_facts.valid_until_ms(),
            family,
            attempt_started_at_ms,
            attempt_deadline_ms,
            trusted_now_ms,
        )?;
        match (role, forwarded_control, transcript_facts) {
            (
                PreselectionObservationRole::Exit,
                Some(control),
                PreselectionTranscriptFreshnessFacts::Forwarded {
                    valid_until_ms,
                    upstream_network_prefix,
                },
            ) if subject == exit_subject
                && control == control_index
                && relay_projections[control].is_none()
                && exit_projection.is_none() =>
            {
                validate_projection_prefix(upstream_network_prefix, family)?;
                let control_projection = local_projection;
                // The client observed one complete client-control-exit-control-client exchange.
                // It is a conservative forwarded-path RTT, never a direct client-to-exit sample.
                exit_projection = Some(ActorFreshnessProjection {
                    observed_network_prefix: upstream_network_prefix,
                    observed_at_ms: control_projection.observed_at_ms,
                    round_trip: control_projection.round_trip,
                    signed_valid_until_ms: valid_until_ms,
                });
                relay_projections[control] = Some(control_projection);
            }
            (
                PreselectionObservationRole::Relay,
                None,
                PreselectionTranscriptFreshnessFacts::Direct { .. },
            ) if subject < direct_count
                && subject != control_index
                && relay_projections[subject].is_none() =>
            {
                relay_projections[subject] = Some(local_projection);
            }
            _ => return Err(SelectionBridgeError::EvidenceBinding),
        }
    }
    let exit_projection = exit_projection.ok_or(SelectionBridgeError::EvidenceBinding)?;
    if relay_projections.iter().any(Option::is_none) {
        return Err(SelectionBridgeError::EvidenceBinding);
    }

    let batch_id = EvidenceBatchId(batch_bytes);
    let policy = snapshot.policy();
    let mut entries = Vec::with_capacity(direct_count.saturating_add(1));
    for (candidate, projection) in snapshot
        .direct_relays()
        .iter()
        .zip(relay_projections.into_iter())
    {
        entries.push(fresh_direct_preselection_evidence(
            candidate,
            &projection.ok_or(SelectionBridgeError::EvidenceBinding)?,
            batch_id,
            transport,
            family,
            policy,
            preselection_capacity_ceiling,
            attempt_deadline_ms,
            trusted_now_ms,
        )?);
    }
    let control = entries
        .get(control_index)
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    entries.push(fresh_forwarded_preselection_evidence(
        forwarded,
        control,
        &exit_projection,
        batch_id,
        transport,
        family,
        policy,
        preselection_capacity_ceiling,
        attempt_deadline_ms,
        trusted_now_ms,
    )?);
    if validate_fresh_evidence_batch(&entries, trusted_now_ms)? != batch_id
        || !evidence_batch_matches_snapshot(snapshot, &entries)
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(FreshEvidenceBatch { batch_id, entries })
}

fn exact_control_candidate_index(
    snapshot: &RouteCandidateSnapshot,
    forwarded: &ForwardedExitCandidateSnapshot,
) -> Result<usize, SelectionBridgeError> {
    let expected = forwarded.control().capability();
    let mut matches = snapshot
        .direct_relays()
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.capability() == expected);
    let (index, _) = matches
        .next()
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    if matches.next().is_some() {
        return Err(SelectionBridgeError::DuplicateIdentity);
    }
    Ok(index)
}

fn actor_projection(
    transport: &PreselectionTransportFreshnessFacts,
    signed_valid_until_ms: u64,
    family: IpFamily,
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    trusted_now_ms: u64,
) -> Result<ActorFreshnessProjection, SelectionBridgeError> {
    let prefix = transport.observed_network_prefix();
    validate_projection_prefix(prefix, family)?;
    let observed_at_ms = transport.observed_at_ms();
    let round_trip = transport.round_trip();
    if observed_at_ms < attempt_started_at_ms
        || observed_at_ms > trusted_now_ms
        || observed_at_ms >= attempt_deadline_ms
        || signed_valid_until_ms <= trusted_now_ms
        || round_trip.is_zero()
        || round_trip > MAXIMUM_SETUP_DURATION
    {
        return Err(SelectionBridgeError::StaleEvidence);
    }
    Ok(ActorFreshnessProjection {
        observed_network_prefix: prefix,
        observed_at_ms,
        round_trip,
        signed_valid_until_ms,
    })
}

fn validate_projection_prefix(
    prefix: ObservedNetworkPrefix,
    family: IpFamily,
) -> Result<(), SelectionBridgeError> {
    if prefix.family() != family || !prefix.is_public_routable() {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one private mint visibly binds every candidate, scope, proof, and lifetime field"
)]
fn fresh_direct_preselection_evidence(
    candidate: &DirectRelayCandidateSnapshot,
    projection: &ActorFreshnessProjection,
    batch_id: EvidenceBatchId,
    transport: SelectionTransport,
    family: IpFamily,
    policy: RouteCandidatePolicySnapshot,
    preselection_capacity_ceiling: Bandwidth,
    attempt_deadline_ms: u64,
    trusted_now_ms: u64,
) -> Result<FreshPeerEvidence, SelectionBridgeError> {
    let advertisement = candidate.advertisement().advertisement();
    let capability = candidate.capability();
    let valid_until_ms = fresh_valid_until(
        projection,
        attempt_deadline_ms,
        capability.advertisement_expires_at_ms,
        capability.expires_at_ms,
        policy.expires_at_ms(),
        trusted_now_ms,
    )?;
    conservative_preselection_evidence(
        batch_id,
        advertisement.node_id.clone(),
        advertisement.peer_id.clone(),
        capability.public_key,
        capability.advertisement_sequence,
        capability.advertisement_expires_at_ms,
        candidate.advertisement().advertisement_payload_hash(),
        capability.expires_at_ms,
        ServiceRole::Relay,
        transport,
        policy,
        family,
        projection,
        valid_until_ms,
        None,
        preselection_capacity_ceiling,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one private mint visibly binds forwarded Exit and exact control evidence"
)]
fn fresh_forwarded_preselection_evidence(
    candidate: &ForwardedExitCandidateSnapshot,
    control: &FreshPeerEvidence,
    projection: &ActorFreshnessProjection,
    batch_id: EvidenceBatchId,
    transport: SelectionTransport,
    family: IpFamily,
    policy: RouteCandidatePolicySnapshot,
    preselection_capacity_ceiling: Bandwidth,
    attempt_deadline_ms: u64,
    trusted_now_ms: u64,
) -> Result<FreshPeerEvidence, SelectionBridgeError> {
    let advertisement = candidate.advertisement().advertisement();
    let capability = candidate.capability();
    let valid_until_ms = fresh_valid_until(
        projection,
        attempt_deadline_ms,
        capability.exit_advertisement_expires_at_ms,
        capability.expires_at_ms,
        policy.expires_at_ms(),
        trusted_now_ms,
    )?;
    let forwarded_control = ForwardedControlBinding {
        node_id: control.node_id.clone(),
        peer_id: control.peer_id.clone(),
        public_key: control.capability_public_key,
        advertisement_sequence: control.advertisement_sequence,
        advertisement_expires_at_ms: control.advertisement_expires_at_ms,
        advertisement_payload_hash: control.advertisement_payload_hash,
        capability_expires_at_ms: control.capability_expires_at_ms,
    };
    conservative_preselection_evidence(
        batch_id,
        advertisement.node_id.clone(),
        advertisement.peer_id.clone(),
        capability.exit_public_key,
        capability.exit_advertisement_sequence,
        capability.exit_advertisement_expires_at_ms,
        candidate.advertisement().advertisement_payload_hash(),
        capability.expires_at_ms,
        ServiceRole::Exit,
        transport,
        policy,
        family,
        projection,
        valid_until_ms,
        Some(forwarded_control),
        preselection_capacity_ceiling,
    )
}

fn fresh_valid_until(
    projection: &ActorFreshnessProjection,
    attempt_deadline_ms: u64,
    advertisement_expires_at_ms: u64,
    capability_expires_at_ms: u64,
    policy_expires_at_ms: u64,
    trusted_now_ms: u64,
) -> Result<u64, SelectionBridgeError> {
    let freshness_ceiling = projection
        .observed_at_ms
        .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
        .ok_or(SelectionBridgeError::StaleEvidence)?;
    let valid_until_ms = projection
        .signed_valid_until_ms
        .min(freshness_ceiling)
        .min(attempt_deadline_ms)
        .min(advertisement_expires_at_ms)
        .min(capability_expires_at_ms)
        .min(policy_expires_at_ms);
    if valid_until_ms <= trusted_now_ms {
        return Err(SelectionBridgeError::StaleEvidence);
    }
    Ok(valid_until_ms)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the sole production evidence mint makes every non-authoritative field explicit"
)]
fn conservative_preselection_evidence(
    batch_id: EvidenceBatchId,
    node_id: NodeId,
    peer_id: PeerId,
    capability_public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    capability_expires_at_ms: u64,
    role: ServiceRole,
    transport: SelectionTransport,
    policy: RouteCandidatePolicySnapshot,
    family: IpFamily,
    projection: &ActorFreshnessProjection,
    valid_until_ms: u64,
    forwarded_control: Option<ForwardedControlBinding>,
    preselection_capacity_ceiling: Bandwidth,
) -> Result<FreshPeerEvidence, SelectionBridgeError> {
    let rtt_ms = projection.round_trip.as_secs_f64() * 1_000.0;
    if !rtt_ms.is_finite() || rtt_ms <= 0.0 || rtt_ms > 120_000.0 {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(FreshPeerEvidence {
        batch_id,
        node_id,
        peer_id,
        capability_public_key,
        advertisement_sequence,
        advertisement_expires_at_ms,
        advertisement_payload_hash,
        capability_expires_at_ms,
        role,
        transport,
        policy_version: policy.version(),
        policy_hash: PolicyHash::from_bytes(policy.hash()),
        policy_expires_at_ms: policy.expires_at_ms(),
        address_family: Some(family),
        observed_at_ms: projection.observed_at_ms,
        valid_until_ms,
        forwarded_control,
        locally_measured_p25: None,
        // Exactly one current control-plane transaction succeeded. This ratio describes only
        // that one-sample window; it is not durable or historical uptime evidence.
        measurement_count: 1,
        preselection_capacity_ceiling,
        uptime_score: 1.0,
        proximity_score: 0.0,
        recent_egress_quality: 0.0,
        rtt_ms: Some(rtt_ms),
        // Reachability is limited to the exact signed control exchange above. It does not prove
        // that the advertised native dataplane address is usable for this transport.
        reachable: true,
        network_address_usable: false,
        observed_network_prefix: Some(projection.observed_network_prefix),
        // The exact proof batch supplied no local blocklist hit. This is absence of a positive
        // local hit, not a proof that policy permits the peer or eventual destination.
        locally_blocked: false,
    })
}

const fn selection_transport(
    transport: ProtocolTransport,
) -> Result<SelectionTransport, SelectionBridgeError> {
    match transport {
        ProtocolTransport::TcpMptcp => Ok(SelectionTransport::TcpMptcp),
        ProtocolTransport::UdpSinglePath => Ok(SelectionTransport::UdpSinglePath),
        ProtocolTransport::MultipathQuic => Ok(SelectionTransport::MultipathQuic),
        ProtocolTransport::Unspecified => Err(SelectionBridgeError::EvidenceBinding),
    }
}

const fn selection_family(
    family: ObservationAddressFamily,
) -> Result<IpFamily, SelectionBridgeError> {
    match family {
        ObservationAddressFamily::Ipv4 => Ok(IpFamily::Ipv4),
        ObservationAddressFamily::Ipv6 => Ok(IpFamily::Ipv6),
        ObservationAddressFamily::Unspecified => Err(SelectionBridgeError::EvidenceBinding),
    }
}

fn validate_fresh_evidence_batch(
    evidence: &[FreshPeerEvidence],
    trusted_now_ms: u64,
) -> Result<EvidenceBatchId, SelectionBridgeError> {
    let Some(first) = evidence.first() else {
        return Err(SelectionBridgeError::FreshPeerEvidenceUnavailable);
    };
    if evidence.len() > MAXIMUM_SELECTION_CANDIDATES {
        return Err(SelectionBridgeError::TooManyCandidates);
    }
    if !first.batch_id.is_valid() || first.policy_version == 0 || first.address_family.is_none() {
        return Err(SelectionBridgeError::EvidenceBinding);
    }

    let mut node_ids = HashSet::with_capacity(evidence.len());
    let mut peer_ids = HashSet::with_capacity(evidence.len());
    for fresh in evidence {
        let prefix_is_exact = fresh.observed_network_prefix.is_some_and(|prefix| {
            prefix.is_public_routable() && fresh.address_family == Some(prefix.family())
        });
        let role_shape_is_exact = matches!(
            (fresh.role, &fresh.forwarded_control),
            (ServiceRole::Relay, None) | (ServiceRole::Exit, Some(_))
        );
        if fresh.batch_id != first.batch_id
            || fresh.transport != first.transport
            || fresh.policy_version != first.policy_version
            || fresh.policy_hash != first.policy_hash
            || fresh.policy_expires_at_ms != first.policy_expires_at_ms
            || fresh.address_family != first.address_family
            || fresh.advertisement_sequence == 0
            || fresh.capability_public_key.iter().all(|byte| *byte == 0)
            || !role_shape_is_exact
            || !prefix_is_exact
            || fresh.preselection_capacity_ceiling.validate().is_err()
            || fresh.preselection_capacity_ceiling.up_mbps == 0
            || fresh.preselection_capacity_ceiling.down_mbps == 0
            || !node_ids.insert(fresh.node_id.clone())
            || !peer_ids.insert(fresh.peer_id.clone())
        {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
        if fresh.forwarded_control.as_ref().is_some_and(|control| {
            control.advertisement_sequence == 0
                || control.public_key.iter().all(|byte| *byte == 0)
                || control.capability_expires_at_ms > control.advertisement_expires_at_ms
                || (control.node_id == fresh.node_id && control.peer_id == fresh.peer_id)
        }) {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
        let freshness_expires_at_ms = fresh
            .observed_at_ms
            .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
            .ok_or(SelectionBridgeError::StaleEvidence)?;
        if fresh.observed_at_ms > trusted_now_ms
            || trusted_now_ms.saturating_sub(fresh.observed_at_ms) > MAXIMUM_EVIDENCE_AGE_MS
            || trusted_now_ms >= fresh.valid_until_ms
            || fresh.valid_until_ms > freshness_expires_at_ms
            || fresh.valid_until_ms > fresh.policy_expires_at_ms
            || fresh.valid_until_ms > fresh.advertisement_expires_at_ms
            || fresh.valid_until_ms > fresh.capability_expires_at_ms
            || fresh.capability_expires_at_ms > fresh.policy_expires_at_ms
            || fresh.capability_expires_at_ms > fresh.advertisement_expires_at_ms
        {
            return Err(SelectionBridgeError::StaleEvidence);
        }
    }

    for fresh in evidence
        .iter()
        .filter(|fresh| fresh.role == ServiceRole::Exit)
    {
        let control = fresh
            .forwarded_control
            .as_ref()
            .ok_or(SelectionBridgeError::EvidenceBinding)?;
        let matches_exact_control = evidence.iter().any(|candidate| {
            candidate.role == ServiceRole::Relay
                && candidate.node_id == control.node_id
                && candidate.peer_id == control.peer_id
                && candidate.capability_public_key == control.public_key
                && candidate.advertisement_sequence == control.advertisement_sequence
                && candidate.advertisement_expires_at_ms == control.advertisement_expires_at_ms
                && candidate.advertisement_payload_hash == control.advertisement_payload_hash
                && candidate.capability_expires_at_ms == control.capability_expires_at_ms
        });
        if !matches_exact_control {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
    }
    Ok(first.batch_id)
}

fn exact_fresh_evidence(
    evidence: &[FreshPeerEvidence],
    candidate: &RouteCandidateAdvertisement,
) -> Result<FreshPeerEvidence, SelectionBridgeError> {
    let advertisement = candidate.advertisement();
    let mut matching = evidence.iter().filter(|fresh| {
        fresh.node_id == advertisement.node_id
            && fresh.peer_id == advertisement.peer_id
            && fresh.advertisement_sequence == advertisement.sequence_number
            && fresh.advertisement_payload_hash == candidate.advertisement_payload_hash()
    });
    let Some(exact) = matching.next() else {
        return Err(SelectionBridgeError::FreshPeerEvidenceUnavailable);
    };
    if matching.next().is_some() {
        return Err(SelectionBridgeError::DuplicateIdentity);
    }
    Ok(exact.clone())
}

fn direct_snapshot_input(
    candidate: &DirectRelayCandidateSnapshot,
    fresh: FreshPeerEvidence,
) -> DirectRelaySelectionInput {
    DirectRelaySelectionInput {
        authenticated: AuthenticatedSelectionAdvertisement::from(candidate.advertisement()),
        fresh,
        capability: candidate.capability().clone(),
    }
}

fn forwarded_snapshot_input(
    candidate: &ForwardedExitCandidateSnapshot,
    evidence: &[FreshPeerEvidence],
) -> Result<ForwardedExitSelectionInput, SelectionBridgeError> {
    let fresh = exact_fresh_evidence(evidence, candidate.advertisement())?;
    let control_fresh = exact_fresh_evidence(evidence, candidate.control().advertisement())?;
    Ok(ForwardedExitSelectionInput {
        authenticated: AuthenticatedSelectionAdvertisement::from(candidate.advertisement()),
        fresh,
        control: direct_snapshot_input(candidate.control(), control_fresh),
        capability: candidate.capability().clone(),
    })
}

fn scope_from_snapshot(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    now_ms: u64,
) -> Result<RouteSelectionScope, SelectionBridgeError> {
    if now_ms < snapshot.captured_at_ms() {
        return Err(SelectionBridgeError::StaleEvidence);
    }
    let policy = snapshot.policy();
    let scope = RouteSelectionScope {
        now_ms,
        transport: parameters.transport,
        policy: ActivePolicySnapshot {
            version: policy.version(),
            hash: PolicyHash::from_bytes(policy.hash()),
            expires_at_ms: policy.expires_at_ms(),
        },
        minimum_capacity: parameters.minimum_capacity,
        address_family: parameters.address_family,
        region: parameters.region,
        exit_mix: parameters.exit_mix,
        relay_policy: parameters.relay_policy,
    };
    scope.validate()?;
    Ok(scope)
}

fn evidence_batch_matches_snapshot(
    snapshot: &RouteCandidateSnapshot,
    evidence: &[FreshPeerEvidence],
) -> bool {
    if evidence.len()
        != snapshot
            .direct_relays()
            .len()
            .saturating_add(snapshot.forwarded_exits().len())
    {
        return false;
    }
    let direct_matches = snapshot.direct_relays().iter().all(|candidate| {
        let advertisement = candidate.advertisement().advertisement();
        evidence
            .iter()
            .filter(|fresh| {
                fresh.role == ServiceRole::Relay
                    && fresh.node_id == advertisement.node_id
                    && fresh.peer_id == advertisement.peer_id
                    && fresh.advertisement_sequence == advertisement.sequence_number
                    && fresh.advertisement_payload_hash
                        == candidate.advertisement().advertisement_payload_hash()
            })
            .count()
            == 1
    });
    let exit_matches = snapshot.forwarded_exits().iter().all(|candidate| {
        let advertisement = candidate.advertisement().advertisement();
        evidence
            .iter()
            .filter(|fresh| {
                fresh.role == ServiceRole::Exit
                    && fresh.node_id == advertisement.node_id
                    && fresh.peer_id == advertisement.peer_id
                    && fresh.advertisement_sequence == advertisement.sequence_number
                    && fresh.advertisement_payload_hash
                        == candidate.advertisement().advertisement_payload_hash()
            })
            .count()
            == 1
    });
    direct_matches && exit_matches
}

fn prospective_peer_binding(
    identity: &ProspectivePeerIdentity,
    advertisement_measured_at_ms: u64,
    actor_evidence_observed_at_ms: u64,
    evidence_valid_until_ms: u64,
) -> Result<ProspectivePeerBinding, SelectionBridgeError> {
    identity
        .selection_node_id()
        .map_err(SelectionBridgeError::RouteSetup)?;
    PeerId::new(identity.peer_id.to_string()).map_err(|_| SelectionBridgeError::EvidenceBinding)?;
    Ok(ProspectivePeerBinding {
        identity: identity.clone(),
        advertisement_measured_at_ms,
        actor_evidence_observed_at_ms,
        evidence_valid_until_ms,
    })
}

fn verify_prospective_relay_candidates(
    snapshot: &RouteCandidateSnapshot,
    evidence: &[FreshPeerEvidence],
    scope: &RouteSelectionScope,
) -> Result<Vec<VerifiedSelectionPeer<ProspectiveDirectRelay>>, SelectionBridgeError> {
    snapshot
        .direct_relays()
        .iter()
        .map(|relay| {
            let fresh = exact_fresh_evidence(evidence, relay.advertisement())?;
            verify_direct_relay_selection_peer(&direct_snapshot_input(relay, fresh), scope)
        })
        .collect()
}

fn prospective_diversity_anchors(
    selected: &SelectedExit,
) -> Result<[DiversityAnchor; 2], SelectionBridgeError> {
    let control_identity = &selected.forwarded_exit.authority.control.identity;
    let control_node_id = control_identity
        .selection_node_id()
        .map_err(SelectionBridgeError::RouteSetup)?;
    let control_peer_id = PeerId::new(control_identity.peer_id.to_string())
        .map_err(|_| SelectionBridgeError::EvidenceBinding)?;
    Ok([
        DiversityAnchor::from_observed_prefix(
            control_node_id,
            control_peer_id,
            selected
                .forwarded_exit
                .control_diversity
                .operator_id
                .clone(),
            selected.forwarded_exit.control_diversity.asn,
            selected
                .forwarded_exit
                .control_diversity
                .observed_network_prefix,
        )?,
        DiversityAnchor::from_observed_prefix(
            selected.selected.node_id.clone(),
            selected.selected.peer_id.clone(),
            selected.forwarded_exit.exit_diversity.operator_id.clone(),
            selected.forwarded_exit.exit_diversity.asn,
            selected
                .forwarded_exit
                .exit_diversity
                .observed_network_prefix,
        )?,
    ])
}

fn prospective_relay_bindings<R: RngCore + ?Sized>(
    selected: &SelectedExit,
    mut verified_relays: Vec<VerifiedSelectionPeer<ProspectiveDirectRelay>>,
    anchors: &[DiversityAnchor; 2],
    rng: &mut R,
) -> Result<(Vec<ProspectiveRelayBinding>, u64), SelectionBridgeError> {
    let relay_candidates = verified_relays
        .iter()
        .map(|relay| {
            PrefixObservedCandidate::new(&relay.candidate, relay.diversity.observed_network_prefix)
                .map_err(|reason| {
                    SelectionBridgeError::Selection(SelectionError::HardFilter(reason))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let policy = ProspectiveRelayPolicy::new(
        selected.scope.relay_policy.minimum_paths,
        MAXIMUM_PROSPECTIVE_RELAYS,
        selected.scope.relay_policy.mix,
    )?;
    let prospective = select_prospective_relays_with_observed_prefixes(
        &relay_candidates,
        &selected.scope.requirements(ServiceRole::Relay),
        anchors,
        policy,
        rng,
    )?;

    let mut earliest_expiry_ms = u64::MAX;
    let mut bindings = Vec::with_capacity(prospective.relays().len());
    for selected_relay in prospective.relays() {
        let mut matches = verified_relays.iter().enumerate().filter(|(_, relay)| {
            relay.candidate.advertisement.node_id == selected_relay.node_id
                && relay.candidate.advertisement.peer_id == selected_relay.peer_id
        });
        let (index, _) = matches
            .next()
            .ok_or(SelectionBridgeError::SelectedIdentityMismatch)?;
        if matches.next().is_some() {
            return Err(SelectionBridgeError::SelectedIdentityMismatch);
        }
        let relay = verified_relays.swap_remove(index);
        earliest_expiry_ms = earliest_expiry_ms.min(relay.actor_evidence_valid_until_ms);
        let relay_binding = prospective_peer_binding(
            &relay.prospective.identity,
            relay.advertisement_measured_at_ms,
            relay.actor_evidence_observed_at_ms,
            relay.actor_evidence_valid_until_ms,
        )?;
        let diversity = relay.diversity.clone();
        let peer_evidence = relay.candidate.evidence.clone();
        let proof = mint_actor_bound_relay_proof(
            relay,
            selected.scope.now_ms,
            selected.scope.requirements(ServiceRole::Relay),
            &selected.forwarded_exit.authority,
        )?;
        bindings.push(ProspectiveRelayBinding {
            relay: relay_binding,
            diversity,
            peer_evidence,
            proof,
        });
    }
    Ok((bindings, earliest_expiry_ms))
}

fn prospective_forwarded_exit_binding(
    selected: &SelectedExit,
    verified_relays: &[VerifiedSelectionPeer<ProspectiveDirectRelay>],
    control_anchor: &DiversityAnchor,
) -> Result<ProspectiveForwardedExitBinding, SelectionBridgeError> {
    let control_identity = &selected.forwarded_exit.authority.control.identity;
    let mut control_records = verified_relays.iter().filter(|relay| {
        relay.candidate.advertisement.node_id == *control_anchor.node_id()
            && relay.candidate.advertisement.peer_id == *control_anchor.peer_id()
    });
    let control_record = control_records
        .next()
        .ok_or(SelectionBridgeError::SelectedIdentityMismatch)?;
    if control_records.next().is_some()
        || control_record.evidence_batch_id != selected.evidence_batch_id
        || control_record.prospective.identity != *control_identity
        || control_record.advertisement_payload_hash != control_identity.advertisement_payload_hash
        || control_record.diversity != selected.forwarded_exit.control_diversity
    {
        return Err(SelectionBridgeError::SelectedIdentityMismatch);
    }
    let binding = ProspectiveForwardedExitBinding {
        selected: selected.forwarded_exit.clone(),
        control: prospective_peer_binding(
            control_identity,
            control_record.advertisement_measured_at_ms,
            control_record.actor_evidence_observed_at_ms,
            control_record.actor_evidence_valid_until_ms,
        )?,
        exit: prospective_peer_binding(
            &selected.forwarded_exit.authority.exit,
            selected.advertisement_measured_at_ms,
            selected.actor_evidence_observed_at_ms,
            selected.exit_evidence_valid_until_ms,
        )?,
        control_diversity: selected.forwarded_exit.control_diversity.clone(),
        exit_diversity: selected.forwarded_exit.exit_diversity.clone(),
        control_peer_evidence: control_record.candidate.evidence.clone(),
        exit_peer_evidence: selected.candidate.evidence.clone(),
    };
    if binding.exit.identity.selection_node_id().ok().as_ref() != Some(&selected.selected.node_id)
        || binding.exit.identity.peer_id.to_string() != selected.selected.peer_id.as_str()
        || binding.control.evidence_valid_until_ms != selected.control_evidence_valid_until_ms
    {
        return Err(SelectionBridgeError::SelectedIdentityMismatch);
    }
    Ok(binding)
}

fn snapshot_route_plan<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    evidence_batch: FreshEvidenceBatch,
    rng: &mut R,
) -> Result<ProspectiveRoutePlan, SelectionBridgeError> {
    snapshot_route_plan_with_trusted_now(
        snapshot,
        parameters,
        evidence_batch,
        crate::unix_millis(),
        rng,
    )
}

#[cfg(test)]
fn snapshot_route_plan_at<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    evidence_batch: FreshEvidenceBatch,
    now_ms: u64,
    rng: &mut R,
) -> Result<ProspectiveRoutePlan, SelectionBridgeError> {
    snapshot_route_plan_with_trusted_now(snapshot, parameters, evidence_batch, now_ms, rng)
}

fn snapshot_route_plan_with_trusted_now<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    evidence_batch: FreshEvidenceBatch,
    now_ms: u64,
    rng: &mut R,
) -> Result<ProspectiveRoutePlan, SelectionBridgeError> {
    evidence_batch.validate_at(now_ms)?;
    let FreshEvidenceBatch { batch_id, entries } = evidence_batch;
    let scope = scope_from_snapshot(snapshot, parameters, now_ms)?;
    if snapshot.forwarded_exits().is_empty() || snapshot.direct_relays().is_empty() {
        return Err(SelectionBridgeError::SnapshotCandidatesUnavailable);
    }
    if snapshot.forwarded_exits().len() > MAXIMUM_SELECTION_CANDIDATES
        || snapshot.direct_relays().len() > MAXIMUM_SELECTION_CANDIDATES
    {
        return Err(SelectionBridgeError::TooManyCandidates);
    }
    if !evidence_batch_matches_snapshot(snapshot, &entries) {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let exits = snapshot
        .forwarded_exits()
        .iter()
        .map(|candidate| forwarded_snapshot_input(candidate, &entries))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = select_exit_first(scope, &exits, rng)?;
    validate_relay_selection_policy(
        &selected.scope.requirements(ServiceRole::Relay),
        selected.scope.relay_policy,
    )?;

    let verified_relays = verify_prospective_relay_candidates(snapshot, &entries, &selected.scope)?;
    let anchors = prospective_diversity_anchors(&selected)?;
    let forwarded_exit =
        prospective_forwarded_exit_binding(&selected, &verified_relays, &anchors[0])?;
    let (prospective_relays, relay_evidence_expiry_ms) =
        prospective_relay_bindings(&selected, verified_relays, &anchors, rng)?;
    if prospective_relays.is_empty()
        || prospective_relays.len() > MAXIMUM_PROSPECTIVE_RELAYS
        || relay_evidence_expiry_ms <= now_ms
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }

    let earliest_evidence_expiry_ms = prospective_relays
        .iter()
        .map(|relay| relay.relay.evidence_valid_until_ms)
        .chain([
            forwarded_exit.control.evidence_valid_until_ms,
            forwarded_exit.exit.evidence_valid_until_ms,
        ])
        .min()
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    if earliest_evidence_expiry_ms
        != relay_evidence_expiry_ms
            .min(forwarded_exit.control.evidence_valid_until_ms)
            .min(forwarded_exit.exit.evidence_valid_until_ms)
        || earliest_evidence_expiry_ms <= now_ms
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(ProspectiveRoutePlan {
        batch_id,
        selected_at_ms: now_ms,
        forwarded_exit,
        scope: selected.scope,
        prospective_relays,
        earliest_evidence_expiry_ms,
    })
}

fn validate_preprobe_peer_binding(
    binding: &ProspectivePeerBinding,
    expected_capability_expires_at_ms: u64,
    scope: &RouteSelectionScope,
    trusted_now_ms: u64,
    node_ids: &mut HashSet<NodeId>,
    peer_ids: &mut HashSet<PeerId>,
    public_keys: &mut HashSet<[u8; 32]>,
) -> Result<u64, SelectionBridgeError> {
    let identity = &binding.identity;
    let expected_node_id = NodeId::new(hex::encode(node_id_from_public_key(&identity.public_key)))
        .map_err(|_| SelectionBridgeError::EvidenceBinding)?;
    let node_id = identity
        .selection_node_id()
        .map_err(SelectionBridgeError::RouteSetup)?;
    let peer_id = PeerId::new(identity.peer_id.to_string())
        .map_err(|_| SelectionBridgeError::EvidenceBinding)?;
    let freshness_ceiling_ms = binding
        .actor_evidence_observed_at_ms
        .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    if identity.public_key.iter().all(|byte| *byte == 0)
        || identity.advertisement_sequence == 0
        || identity.policy_version != scope.policy.version
        || identity.policy_hash != *scope.policy.hash.as_bytes()
        || identity.policy_expires_at_ms != scope.policy.expires_at_ms
        || identity.expires_at_ms != expected_capability_expires_at_ms
        || identity.expires_at_ms
            > identity
                .advertisement_expires_at_ms
                .min(identity.policy_expires_at_ms)
        || node_id != expected_node_id
        || binding.advertisement_measured_at_ms > binding.actor_evidence_observed_at_ms
        || binding.actor_evidence_observed_at_ms > scope.now_ms
        || trusted_now_ms.saturating_sub(binding.actor_evidence_observed_at_ms)
            > MAXIMUM_EVIDENCE_AGE_MS
        || identity.advertisement_expires_at_ms <= trusted_now_ms
        || identity.expires_at_ms <= trusted_now_ms
        || binding.evidence_valid_until_ms <= trusted_now_ms
        || binding.evidence_valid_until_ms > freshness_ceiling_ms
        || binding.evidence_valid_until_ms > identity.advertisement_expires_at_ms
        || binding.evidence_valid_until_ms > identity.expires_at_ms
        || binding.evidence_valid_until_ms > identity.policy_expires_at_ms
        || !node_ids.insert(node_id)
        || !peer_ids.insert(peer_id)
        || !public_keys.insert(identity.public_key)
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(identity
        .advertisement_expires_at_ms
        .min(identity.expires_at_ms)
        .min(identity.policy_expires_at_ms))
}

fn validate_preprobe_peer_evidence(
    evidence: &CandidateEvidence,
    diversity: &DiversitySnapshot,
    scope: &RouteSelectionScope,
    trusted_now_ms: u64,
    prior_diversity: &[&DiversitySnapshot],
) -> Result<(), SelectionBridgeError> {
    let prefix = diversity.observed_network_prefix;
    let observed_family_matches = scope.address_family == Some(prefix.family());
    if evidence.validate().is_err()
        || !evidence.reachable
        || evidence.rtt_ms.is_none()
        || !evidence.network_address_usable
        || evidence.locally_blocked
        || evidence
            .locally_measured_p25
            .is_some_and(|measured| !measured.satisfies(scope.minimum_capacity))
        || evidence.reserved_path_limit.up_mbps < scope.minimum_capacity.up_mbps
        || evidence.reserved_path_limit.down_mbps < scope.minimum_capacity.down_mbps
        || evidence.observed_network_origin.is_some()
        || !observed_family_matches
        || diversity.asn == 0
        || !prefix.is_public_routable()
        || evidence
            .serious_protocol_fault_until
            .is_some_and(|until| !until.is_expired_at(UnixTime::from_secs(trusted_now_ms / 1_000)))
        || prior_diversity
            .iter()
            .any(|prior| diversity.conflicts_with(prior))
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the affine consume boundary validates every binding and deadline before either mint"
)]
fn validate_and_allocate_preprobe_plan(
    plan: ProspectiveRoutePlan,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    replay_capacity: usize,
    trusted_now_ms: u64,
    monotonic_now: Instant,
) -> Result<ValidatedPreProbePlan, SelectionBridgeError> {
    let ProspectiveRoutePlan {
        batch_id,
        selected_at_ms,
        forwarded_exit,
        scope,
        prospective_relays,
        earliest_evidence_expiry_ms,
    } = plan;
    if !batch_id.is_valid()
        || selected_at_ms == 0
        || selected_at_ms != scope.now_ms
        || selected_at_ms > trusted_now_ms
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    scope.validate()?;
    validate_relay_selection_policy(&scope.requirements(ServiceRole::Relay), scope.relay_policy)?;
    if replay_capacity == 0 || replay_capacity > MAXIMUM_REPLAY_CAPACITY {
        return Err(SelectionBridgeError::RouteSetup(RouteSetupError::Invalid(
            "reservation replay capacity",
        )));
    }
    if prospective_relays.is_empty()
        || prospective_relays.len() > MAXIMUM_PROSPECTIVE_RELAYS
        || prospective_relays.len() < scope.relay_policy.minimum_paths
    {
        return Err(SelectionBridgeError::TooManyCandidates);
    }
    let limits = RouteSetupLimits::new(
        limits.setup_timeout,
        limits.call_timeout,
        limits.maximum_outbound_attempts,
    )
    .map_err(SelectionBridgeError::RouteSetup)?;

    let mut node_ids = HashSet::with_capacity(prospective_relays.len().saturating_add(2));
    let mut peer_ids = HashSet::with_capacity(prospective_relays.len().saturating_add(2));
    let mut public_keys = HashSet::with_capacity(prospective_relays.len().saturating_add(2));
    if forwarded_exit.selected.evidence_batch_id != batch_id.0
        || forwarded_exit.selected.authority.control.identity != forwarded_exit.control.identity
        || forwarded_exit.selected.authority.exit != forwarded_exit.exit.identity
        || forwarded_exit.selected.control_diversity != forwarded_exit.control_diversity
        || forwarded_exit.selected.exit_diversity != forwarded_exit.exit_diversity
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let control_expiry_ms = forwarded_exit
        .control
        .identity
        .advertisement_expires_at_ms
        .min(forwarded_exit.control.identity.policy_expires_at_ms);
    let exit_expiry_ms = forwarded_exit
        .exit
        .identity
        .advertisement_expires_at_ms
        .min(forwarded_exit.exit.identity.policy_expires_at_ms)
        .min(forwarded_exit.control.identity.expires_at_ms);
    let mut hard_expiry_ceiling_ms = scope.policy.expires_at_ms;
    hard_expiry_ceiling_ms = hard_expiry_ceiling_ms.min(validate_preprobe_peer_binding(
        &forwarded_exit.control,
        control_expiry_ms,
        &scope,
        trusted_now_ms,
        &mut node_ids,
        &mut peer_ids,
        &mut public_keys,
    )?);
    validate_preprobe_peer_evidence(
        &forwarded_exit.control_peer_evidence,
        &forwarded_exit.control_diversity,
        &scope,
        trusted_now_ms,
        &[],
    )?;
    hard_expiry_ceiling_ms = hard_expiry_ceiling_ms.min(validate_preprobe_peer_binding(
        &forwarded_exit.exit,
        exit_expiry_ms,
        &scope,
        trusted_now_ms,
        &mut node_ids,
        &mut peer_ids,
        &mut public_keys,
    )?);
    validate_preprobe_peer_evidence(
        &forwarded_exit.exit_peer_evidence,
        &forwarded_exit.exit_diversity,
        &scope,
        trusted_now_ms,
        &[&forwarded_exit.control_diversity],
    )?;

    let mut evidence_expiry_min_ms = forwarded_exit
        .control
        .evidence_valid_until_ms
        .min(forwarded_exit.exit.evidence_valid_until_ms);
    let mut current_scope = scope.clone();
    current_scope.now_ms = trusted_now_ms;
    let current_requirements = current_scope.requirements(ServiceRole::Relay);
    let mut diversity = vec![
        &forwarded_exit.control_diversity,
        &forwarded_exit.exit_diversity,
    ];
    for relay in &prospective_relays {
        let relay_expiry_ms = relay
            .relay
            .identity
            .advertisement_expires_at_ms
            .min(relay.relay.identity.policy_expires_at_ms);
        hard_expiry_ceiling_ms = hard_expiry_ceiling_ms.min(validate_preprobe_peer_binding(
            &relay.relay,
            relay_expiry_ms,
            &scope,
            trusted_now_ms,
            &mut node_ids,
            &mut peer_ids,
            &mut public_keys,
        )?);
        validate_preprobe_peer_evidence(
            &relay.peer_evidence,
            &relay.diversity,
            &scope,
            trusted_now_ms,
            &diversity,
        )?;
        relay
            .proof
            .validate_preprobe_binding(
                &relay.relay,
                &relay.diversity,
                &forwarded_exit.selected,
                trusted_now_ms,
                &current_requirements,
                batch_id,
            )
            .map_err(|_| SelectionBridgeError::EvidenceBinding)?;
        evidence_expiry_min_ms = evidence_expiry_min_ms.min(relay.relay.evidence_valid_until_ms);
        diversity.push(&relay.diversity);
    }
    if evidence_expiry_min_ms != earliest_evidence_expiry_ms
        || trusted_now_ms >= evidence_expiry_min_ms
    {
        return Err(SelectionBridgeError::StaleEvidence);
    }

    let maximum_setup_ms = u64::try_from(MAXIMUM_SETUP_DURATION.as_millis())
        .map_err(|_| SelectionBridgeError::InvalidDeadline)?;
    let setup_lifetime_ms = deadlines
        .setup_expires_at_ms
        .checked_sub(trusted_now_ms)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    let hard_lifetime_ms = deadlines
        .hard_expires_at_ms
        .checked_sub(trusted_now_ms)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    if setup_lifetime_ms == 0
        || setup_lifetime_ms > maximum_setup_ms
        || hard_lifetime_ms == 0
        || hard_lifetime_ms > MAXIMUM_RESERVATION_LIFETIME_MS
        || deadlines.setup_expires_at_ms > deadlines.hard_expires_at_ms
        || deadlines.setup_expires_at_ms > evidence_expiry_min_ms
        || deadlines.hard_expires_at_ms > hard_expiry_ceiling_ms
    {
        return Err(SelectionBridgeError::InvalidDeadline);
    }
    let now_unix = trusted_now_ms / 1_000;
    let setup_expires_at_unix = deadlines.setup_expires_at_ms / 1_000;
    let hard_expires_at_unix = deadlines.hard_expires_at_ms / 1_000;
    let hard_floor_ms = hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    if setup_expires_at_unix <= now_unix
        || setup_expires_at_unix > hard_expires_at_unix
        || hard_expires_at_unix <= now_unix
        || hard_floor_ms > hard_expiry_ceiling_ms
    {
        return Err(SelectionBridgeError::InvalidDeadline);
    }
    let deadline_budget = limits
        .setup_timeout
        .min(Duration::from_millis(setup_lifetime_ms))
        .min(Duration::from_millis(
            evidence_expiry_min_ms
                .checked_sub(trusted_now_ms)
                .ok_or(SelectionBridgeError::InvalidDeadline)?,
        ));
    if deadline_budget.is_zero() {
        return Err(SelectionBridgeError::InvalidDeadline);
    }
    let deadline = monotonic_now
        .checked_add(deadline_budget)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;

    let mut paths = Vec::with_capacity(prospective_relays.len());
    for (index, relay) in prospective_relays.into_iter().enumerate() {
        let path_id = u32::try_from(index.saturating_add(1))
            .map_err(|_| SelectionBridgeError::TooManyCandidates)?;
        paths.push(PlannedProspectivePath { path_id, relay });
    }
    Ok(ValidatedPreProbePlan {
        batch_id,
        selected_at_ms,
        attempt_started_at_ms: trusted_now_ms,
        scope,
        forwarded_exit,
        paths,
        earliest_evidence_expiry_ms: evidence_expiry_min_ms,
        deadlines,
        limits,
        deadline,
        replay_capacity,
    })
}

impl ValidatedPreProbePlan {
    fn into_continuation(
        self,
        route_authority: RouteSessionAuthority,
        reservation_session: ReservationSession,
    ) -> PreProbeContinuation {
        PreProbeContinuation {
            batch_id: self.batch_id,
            selected_at_ms: self.selected_at_ms,
            attempt_started_at_ms: self.attempt_started_at_ms,
            scope: self.scope,
            forwarded_exit: self.forwarded_exit,
            paths: self.paths,
            earliest_evidence_expiry_ms: self.earliest_evidence_expiry_ms,
            deadlines: self.deadlines,
            limits: self.limits,
            deadline: self.deadline,
            route_authority,
            reservation_session,
        }
    }

    fn mint(self) -> Result<PreProbeContinuation, SelectionBridgeError> {
        let route_authority = RouteSessionAuthority::generate()?;
        let reservation_session = ReservationSession::generate(self.replay_capacity)
            .map_err(SelectionBridgeError::RouteSetup)?;
        Ok(self.into_continuation(route_authority, reservation_session))
    }
}

fn consume_prospective_route_plan(
    plan: ProspectiveRoutePlan,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    replay_capacity: usize,
) -> Result<PreProbeContinuation, SelectionBridgeError> {
    let monotonic_now = Instant::now();
    let trusted_now_ms = crate::unix_millis();
    validate_and_allocate_preprobe_plan(
        plan,
        deadlines,
        limits,
        replay_capacity,
        trusted_now_ms,
        monotonic_now,
    )?
    .mint()
}

#[cfg(test)]
fn consume_prospective_route_plan_at(
    plan: ProspectiveRoutePlan,
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    replay_capacity: usize,
    trusted_now_ms: u64,
    monotonic_now: Instant,
) -> Result<PreProbeContinuation, SelectionBridgeError> {
    validate_and_allocate_preprobe_plan(
        plan,
        deadlines,
        limits,
        replay_capacity,
        trusted_now_ms,
        monotonic_now,
    )?
    .mint()
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct PreProbeConsumeTestContext {
    deadlines: RouteDeadlines,
    limits: RouteSetupLimits,
    replay_capacity: usize,
    trusted_now_ms: u64,
    monotonic_now: Instant,
}

#[cfg(test)]
fn consume_prospective_route_plan_with_minters<AuthorityMinter, SessionMinter>(
    plan: ProspectiveRoutePlan,
    context: PreProbeConsumeTestContext,
    mint_authority: AuthorityMinter,
    mint_session: SessionMinter,
) -> Result<PreProbeContinuation, SelectionBridgeError>
where
    AuthorityMinter: FnOnce() -> Result<RouteSessionAuthority, SelectionBridgeError>,
    SessionMinter: FnOnce(usize) -> Result<ReservationSession, RouteSetupError>,
{
    let PreProbeConsumeTestContext {
        deadlines,
        limits,
        replay_capacity,
        trusted_now_ms,
        monotonic_now,
    } = context;
    let validated = validate_and_allocate_preprobe_plan(
        plan,
        deadlines,
        limits,
        replay_capacity,
        trusted_now_ms,
        monotonic_now,
    )?;
    let route_authority = mint_authority()?;
    let reservation_session =
        mint_session(validated.replay_capacity).map_err(SelectionBridgeError::RouteSetup)?;
    Ok(validated.into_continuation(route_authority, reservation_session))
}

impl PendingPreProbeResolve {
    fn validate_after_resolve(
        &self,
        authorities: &RouteSetupAuthorities,
        initial_trusted_now_ms: u64,
        trusted_now_ms: u64,
        monotonic_now: Instant,
        cancellation: &watch::Receiver<bool>,
    ) -> Result<(), RouteSetupError> {
        if *cancellation.borrow() {
            return Err(RouteSetupError::Cancelled);
        }
        if monotonic_now >= self.deadline {
            return Err(RouteSetupError::Deadline(RouteSetupPhase::Validated));
        }
        if trusted_now_ms < initial_trusted_now_ms
            || trusted_now_ms < self.attempt_started_at_ms
            || trusted_now_ms >= self.deadlines.setup_expires_at_ms
            || trusted_now_ms >= self.evidence_expiry_ms
        {
            return Err(RouteSetupError::Expired);
        }
        let mut current_scope = self.selection_scope.clone();
        current_scope.now_ms = trusted_now_ms;
        current_scope
            .validate()
            .map_err(|_| RouteSetupError::Invalid("pre-probe route scope"))?;
        let requirements = current_scope.requirements(ServiceRole::Relay);
        for path in &self.request.paths {
            path.proof
                .revalidate_for_scoring(trusted_now_ms, &requirements, self.batch_id.0)?;
        }
        let mut node_ids = HashSet::with_capacity(2);
        let mut peer_ids = HashSet::with_capacity(2);
        let mut public_keys = HashSet::with_capacity(2);
        let control_expiry_ms = self
            .control
            .identity
            .advertisement_expires_at_ms
            .min(self.control.identity.policy_expires_at_ms);
        let exit_expiry_ms = self
            .exit
            .identity
            .advertisement_expires_at_ms
            .min(self.exit.identity.policy_expires_at_ms)
            .min(self.control.identity.expires_at_ms);
        validate_preprobe_peer_binding(
            &self.control,
            control_expiry_ms,
            &self.selection_scope,
            trusted_now_ms,
            &mut node_ids,
            &mut peer_ids,
            &mut public_keys,
        )
        .map_err(|_| RouteSetupError::Invalid("stale control actor evidence"))?;
        validate_preprobe_peer_binding(
            &self.exit,
            exit_expiry_ms,
            &self.selection_scope,
            trusted_now_ms,
            &mut node_ids,
            &mut peer_ids,
            &mut public_keys,
        )
        .map_err(|_| RouteSetupError::Invalid("stale exit actor evidence"))?;
        authorities.validate(&self.request)
    }
}

impl PreProbeContinuation {
    fn ensure_handoff_live_at(
        &self,
        trusted_now_ms: u64,
        monotonic_now: Instant,
        cancellation: &watch::Receiver<bool>,
    ) -> Result<(), RouteSetupError> {
        if *cancellation.borrow() {
            return Err(RouteSetupError::Cancelled);
        }
        if monotonic_now >= self.deadline {
            return Err(RouteSetupError::Deadline(RouteSetupPhase::Validated));
        }
        if trusted_now_ms < self.attempt_started_at_ms {
            return Err(RouteSetupError::Invalid("clock before pre-probe attempt"));
        }
        if trusted_now_ms >= self.deadlines.setup_expires_at_ms
            || trusted_now_ms >= self.earliest_evidence_expiry_ms
        {
            return Err(RouteSetupError::Expired);
        }
        Ok(())
    }

    fn recompute_expiry_ceilings(&self) -> Result<(u64, u64), RouteSetupError> {
        let mut hard_expiry_ms = self.scope.policy.expires_at_ms;
        let mut evidence_expiry_ms = u64::MAX;
        for binding in [&self.forwarded_exit.control, &self.forwarded_exit.exit]
            .into_iter()
            .chain(self.paths.iter().map(|path| &path.relay.relay))
        {
            hard_expiry_ms = hard_expiry_ms
                .min(binding.identity.advertisement_expires_at_ms)
                .min(binding.identity.expires_at_ms)
                .min(binding.identity.policy_expires_at_ms);
            evidence_expiry_ms = evidence_expiry_ms.min(binding.evidence_valid_until_ms);
        }
        if evidence_expiry_ms != self.earliest_evidence_expiry_ms
            || self.deadlines.setup_expires_at_ms > evidence_expiry_ms
            || self.deadlines.hard_expires_at_ms > hard_expiry_ms
        {
            return Err(RouteSetupError::Invalid("pre-probe expiry ceiling"));
        }
        Ok((hard_expiry_ms, evidence_expiry_ms))
    }

    fn into_pending_resolve(
        self,
        hard_expiry_ms: u64,
        evidence_expiry_ms: u64,
    ) -> Result<PendingPreProbeResolve, RouteSetupError> {
        let PreProbeContinuation {
            batch_id,
            selected_at_ms: _,
            attempt_started_at_ms,
            scope,
            forwarded_exit,
            paths,
            earliest_evidence_expiry_ms: _,
            deadlines,
            limits,
            deadline,
            route_authority,
            reservation_session,
        } = self;
        let ProspectiveForwardedExitBinding {
            selected,
            control,
            exit,
            control_diversity: _,
            exit_diversity: _,
            control_peer_evidence: _,
            exit_peer_evidence: _,
        } = forwarded_exit;
        let prospective_relays = paths
            .into_iter()
            .map(|path| ProspectiveRouteRelay {
                path_id: path.path_id,
                proof: path.relay.proof,
            })
            .collect();
        let mut attempt_scope = scope.clone();
        attempt_scope.now_ms = attempt_started_at_ms;
        let parameters = build_parameters(
            route_authority,
            &attempt_scope,
            deadlines,
            hard_expiry_ms,
            evidence_expiry_ms,
        )
        .map_err(|_| RouteSetupError::Invalid("pre-probe route parameters"))?;
        let request = RouteSetupRequest::new(selected, prospective_relays, parameters)?;
        Ok(PendingPreProbeResolve {
            batch_id,
            attempt_started_at_ms,
            selection_scope: scope,
            control,
            exit,
            evidence_expiry_ms,
            deadlines,
            limits,
            deadline,
            request,
            reservation_session,
        })
    }

    async fn resolve_into_unmeasured<R, C>(
        self,
        resolver: &R,
        clock: &C,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<UnmeasuredRouteSetup<ReservationSession>, RouteSetupError>
    where
        R: RouteCapabilityResolver,
        C: RouteSetupClock,
    {
        let monotonic_now = Instant::now();
        let trusted_now_ms = clock.unix_millis();
        self.ensure_handoff_live_at(trusted_now_ms, monotonic_now, cancellation)?;
        let initial_trusted_now_ms = trusted_now_ms;
        let (hard_expiry_ms, evidence_expiry_ms) = self.recompute_expiry_ceilings()?;
        let pending = self.into_pending_resolve(hard_expiry_ms, evidence_expiry_ms)?;
        let authorities = bounded_call(
            pending.deadline,
            pending.limits.call_timeout,
            cancellation,
            RouteSetupPhase::Validated,
            RouteSetupAuthorities::resolve(resolver, &pending.request),
        )
        .await??;

        let monotonic_now = Instant::now();
        let trusted_now_ms = clock.unix_millis();
        pending.validate_after_resolve(
            &authorities,
            initial_trusted_now_ms,
            trusted_now_ms,
            monotonic_now,
            cancellation,
        )?;
        let PendingPreProbeResolve {
            limits,
            deadline,
            request,
            reservation_session,
            ..
        } = pending;
        RouteSetupTransaction::with_protocol_and_deadline(
            request,
            authorities,
            limits,
            reservation_session,
            deadline,
        )
    }

    #[cfg(test)]
    fn ensure_live_at(
        &self,
        trusted_now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(), SelectionBridgeError> {
        if trusted_now_ms < self.attempt_started_at_ms
            || trusted_now_ms >= self.deadlines.setup_expires_at_ms
            || trusted_now_ms >= self.earliest_evidence_expiry_ms
            || monotonic_now >= self.deadline
        {
            return Err(SelectionBridgeError::InvalidDeadline);
        }
        Ok(())
    }
}

impl<L> RouteSetupManager<ReservationSession, L>
where
    L: LocalRouteBackend,
{
    pub(super) fn spawn_preprobe<R, C>(
        &self,
        continuation: PreProbeContinuation,
        resolver_and_transport: R,
        clock: C,
    ) -> RouteSetupHandle<ReservationSession>
    where
        R: RouteCapabilityResolver + ReservationTransport + Sync,
        C: RouteSetupClock,
    {
        self.spawn_owned(move |context, cancellation| async move {
            let mut cancellation = cancellation;
            let resolver_and_transport = resolver_and_transport;
            let unmeasured = match continuation
                .resolve_into_unmeasured(&resolver_and_transport, &clock, &mut cancellation)
                .await
            {
                Ok(unmeasured) => unmeasured,
                Err(cause) => return Err(RouteSetupFailure::before_dispatch(cause)),
            };
            unmeasured
                .execute_owned(context, resolver_and_transport, clock, cancellation)
                .await
        })
    }
}

struct SnapshotExitPreflight {
    selected: SelectedExit,
    selected_at_ms: u64,
    direct_relays: Vec<DirectRelayCandidateSnapshot>,
    fresh_peer_evidence: Vec<FreshPeerEvidence>,
}

impl SnapshotExitPreflight {
    fn selected_exit_binding(&self) -> SelectedExitBinding {
        self.selected.evidence_binding()
    }

    fn complete<R: RngCore + ?Sized>(
        self,
        complete_path_evidence: &[SnapshotRelayPathEvidence],
        deadlines: RouteDeadlines,
        authority: RouteSessionAuthority,
        rng: &mut R,
    ) -> Result<RouteSetupRequest, SelectionBridgeError> {
        self.complete_with_trusted_now(
            complete_path_evidence,
            deadlines,
            authority,
            crate::unix_millis(),
            rng,
        )
    }

    #[cfg(test)]
    fn complete_at<R: RngCore + ?Sized>(
        self,
        complete_path_evidence: &[SnapshotRelayPathEvidence],
        deadlines: RouteDeadlines,
        authority: RouteSessionAuthority,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<RouteSetupRequest, SelectionBridgeError> {
        self.complete_with_trusted_now(complete_path_evidence, deadlines, authority, now_ms, rng)
    }

    fn complete_with_trusted_now<R: RngCore + ?Sized>(
        mut self,
        complete_path_evidence: &[SnapshotRelayPathEvidence],
        deadlines: RouteDeadlines,
        authority: RouteSessionAuthority,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<RouteSetupRequest, SelectionBridgeError> {
        if complete_path_evidence.is_empty() {
            return Err(SelectionBridgeError::CompletePathEvidenceUnavailable);
        }
        if complete_path_evidence.len() > MAXIMUM_SELECTION_CANDIDATES {
            return Err(SelectionBridgeError::TooManyCandidates);
        }
        if now_ms < self.selected.scope.now_ms {
            return Err(SelectionBridgeError::StaleEvidence);
        }
        self.selected.scope.now_ms = now_ms;
        self.selected.scope.validate()?;
        let control = &self.selected.forwarded_exit.authority.control.identity;
        let exit = &self.selected.forwarded_exit.authority.exit;
        if self.selected.scope.policy.expires_at_ms <= now_ms
            || self.selected.advertisement_expires_at_ms <= now_ms
            || self.selected.evidence_valid_until_ms <= now_ms
            || control.advertisement_expires_at_ms <= now_ms
            || control.policy_expires_at_ms <= now_ms
            || control.expires_at_ms <= now_ms
            || exit.advertisement_expires_at_ms <= now_ms
            || exit.policy_expires_at_ms <= now_ms
            || exit.expires_at_ms <= now_ms
        {
            return Err(SelectionBridgeError::StaleEvidence);
        }
        let selected_binding = self.selected.evidence_binding();
        let mut complete = Vec::with_capacity(complete_path_evidence.len());
        for path in complete_path_evidence {
            if path.exit != selected_binding || path.observed_at_ms < self.selected_at_ms {
                return Err(SelectionBridgeError::EvidenceBinding);
            }
            let mut matching = self.direct_relays.iter().filter(|candidate| {
                let advertisement = candidate.advertisement().advertisement();
                advertisement.node_id == path.relay_node_id
                    && advertisement.peer_id == path.relay_peer_id
                    && advertisement.sequence_number == path.relay_advertisement_sequence
                    && candidate.advertisement().advertisement_payload_hash()
                        == path.relay_advertisement_payload_hash
            });
            let Some(relay) = matching.next() else {
                return Err(SelectionBridgeError::CompletePathEvidenceUnavailable);
            };
            if matching.next().is_some() {
                return Err(SelectionBridgeError::DuplicateIdentity);
            }
            let fresh = exact_fresh_evidence(&self.fresh_peer_evidence, relay.advertisement())?;
            complete.push(CompleteRelayPathEvidence {
                exit: path.exit.clone(),
                relay: direct_snapshot_input(relay, fresh),
                relay_node_id: path.relay_node_id.clone(),
                relay_peer_id: path.relay_peer_id.clone(),
                relay_advertisement_sequence: path.relay_advertisement_sequence,
                relay_advertisement_payload_hash: path.relay_advertisement_payload_hash,
                transport: path.transport,
                policy_hash: path.policy_hash,
                policy_expires_at_ms: path.policy_expires_at_ms,
                probe_address_family: path.probe_address_family,
                observed_at_ms: path.observed_at_ms,
                client_to_relay_capacity: path.client_to_relay_capacity,
                relay_to_exit_capacity: path.relay_to_exit_capacity,
                exit_reserved_capacity: path.exit_reserved_capacity,
                client_to_relay_rtt_ms: path.client_to_relay_rtt_ms,
                relay_to_exit_rtt_ms: path.relay_to_exit_rtt_ms,
                unique_throughput_gain_ratio: path.unique_throughput_gain_ratio,
                meaningful_failover: path.meaningful_failover,
            });
        }
        self.selected
            .select_relays_and_build(&complete, deadlines, authority, rng)
    }
}

fn snapshot_exit_preflight<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    fresh_peer_evidence: &[FreshPeerEvidence],
    rng: &mut R,
) -> Result<SnapshotExitPreflight, SelectionBridgeError> {
    snapshot_exit_preflight_with_trusted_now(
        snapshot,
        parameters,
        fresh_peer_evidence,
        crate::unix_millis(),
        rng,
    )
}

#[cfg(test)]
fn snapshot_exit_preflight_at<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    fresh_peer_evidence: &[FreshPeerEvidence],
    now_ms: u64,
    rng: &mut R,
) -> Result<SnapshotExitPreflight, SelectionBridgeError> {
    snapshot_exit_preflight_with_trusted_now(snapshot, parameters, fresh_peer_evidence, now_ms, rng)
}

fn snapshot_exit_preflight_with_trusted_now<R: RngCore + ?Sized>(
    snapshot: &RouteCandidateSnapshot,
    parameters: SnapshotPreflightParameters,
    fresh_peer_evidence: &[FreshPeerEvidence],
    now_ms: u64,
    rng: &mut R,
) -> Result<SnapshotExitPreflight, SelectionBridgeError> {
    let _batch_id = validate_fresh_evidence_batch(fresh_peer_evidence, now_ms)?;
    let scope = scope_from_snapshot(snapshot, parameters, now_ms)?;
    if snapshot.forwarded_exits().is_empty() {
        return Err(SelectionBridgeError::SnapshotCandidatesUnavailable);
    }
    let exits = snapshot
        .forwarded_exits()
        .iter()
        .map(|candidate| forwarded_snapshot_input(candidate, fresh_peer_evidence))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = select_exit_first(scope, &exits, rng)?;
    Ok(SnapshotExitPreflight {
        selected,
        selected_at_ms: now_ms,
        direct_relays: snapshot.direct_relays().to_vec(),
        fresh_peer_evidence: fresh_peer_evidence.to_vec(),
    })
}

struct VerifiedSelectionPeer<I> {
    evidence_batch_id: EvidenceBatchId,
    candidate: Candidate,
    prospective: I,
    diversity: DiversitySnapshot,
    advertisement_sequence: u64,
    advertisement_measured_at_ms: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    actor_evidence_observed_at_ms: u64,
    actor_evidence_valid_until_ms: u64,
    forwarded_control_evidence_valid_until_ms: Option<u64>,
    evidence_valid_until_ms: u64,
}

struct SelectedExit {
    evidence_batch_id: EvidenceBatchId,
    scope: RouteSelectionScope,
    selected: SelectedNode,
    forwarded_exit: SelectedForwardedExit,
    advertisement_sequence: u64,
    advertisement_measured_at_ms: u64,
    advertisement_expires_at_ms: u64,
    actor_evidence_observed_at_ms: u64,
    control_evidence_valid_until_ms: u64,
    exit_evidence_valid_until_ms: u64,
    evidence_valid_until_ms: u64,
    reserved_path_limit: Bandwidth,
    candidate: Candidate,
}

impl SelectedExit {
    fn evidence_binding(&self) -> SelectedExitBinding {
        let control = &self.forwarded_exit.authority.control.identity;
        SelectedExitBinding {
            control_node_id: control.wire_node_id,
            control_peer_id: control.peer_id.to_bytes(),
            control_advertisement_sequence: control.advertisement_sequence,
            control_advertisement_payload_hash: control.advertisement_payload_hash,
            node_id: self.selected.node_id.clone(),
            peer_id: self.selected.peer_id.clone(),
            advertisement_sequence: self.advertisement_sequence,
            advertisement_payload_hash: self
                .forwarded_exit
                .authority
                .exit
                .advertisement_payload_hash,
            transport: self.scope.transport,
            policy_hash: self.scope.policy.hash,
            policy_expires_at_ms: self.scope.policy.expires_at_ms,
        }
    }

    fn select_relays_and_build<R: RngCore + ?Sized>(
        self,
        paths: &[CompleteRelayPathEvidence],
        deadlines: RouteDeadlines,
        authority: RouteSessionAuthority,
        rng: &mut R,
    ) -> Result<RouteSetupRequest, SelectionBridgeError> {
        let (mut verified, projections, metrics) = verify_complete_relay_paths(&self, paths)?;
        if matches!(
            self.scope.transport,
            SelectionTransport::TcpMptcp | SelectionTransport::MultipathQuic
        ) && self.scope.relay_policy.minimum_paths < 2
        {
            return Err(SelectionBridgeError::SelectedIdentityMismatch);
        }
        let selection_paths = projections
            .iter()
            .zip(metrics)
            .map(|(projection, metrics)| ProjectedRelayPath::new(projection, metrics))
            .collect::<Vec<_>>();
        let selected_paths = select_projected_relay_paths(
            &selection_paths,
            &self.scope.requirements(ServiceRole::Relay),
            self.scope.relay_policy,
            rng,
        )?;
        if matches!(
            self.scope.transport,
            SelectionTransport::TcpMptcp | SelectionTransport::MultipathQuic
        ) && selected_paths.active.len() < 2
        {
            return Err(SelectionBridgeError::SelectedIdentityMismatch);
        }

        let mut relay_bindings = Vec::with_capacity(
            selected_paths
                .active
                .len()
                .saturating_add(selected_paths.warm_backups.len()),
        );
        let mut earliest_expiry_ms = self
            .advertisement_expires_at_ms
            .min(self.scope.policy.expires_at_ms);
        let mut earliest_setup_evidence_expiry_ms = self.evidence_valid_until_ms;
        let mut selected_identity = HashSet::new();
        for selected in &selected_paths.active {
            if !selected_identity.insert((
                selected.relay_node_id.clone(),
                selected.relay_peer_id.clone(),
            )) {
                return Err(SelectionBridgeError::SelectedIdentityMismatch);
            }
            let record = take_exact_selected_record(selected, &mut verified)?;
            earliest_expiry_ms = earliest_expiry_ms.min(record.advertisement_expires_at_ms);
            earliest_setup_evidence_expiry_ms =
                earliest_setup_evidence_expiry_ms.min(record.evidence_valid_until_ms);
            let path_id = u32::try_from(relay_bindings.len().saturating_add(1))
                .map_err(|_| SelectionBridgeError::TooManyCandidates)?;
            relay_bindings.push(ProspectiveRouteRelay {
                path_id,
                proof: mint_actor_bound_relay_proof(
                    record,
                    self.scope.now_ms,
                    self.scope.requirements(ServiceRole::Relay),
                    &self.forwarded_exit.authority,
                )?,
            });
        }
        for selected in &selected_paths.warm_backups {
            if !selected_identity.insert((
                selected.relay_node_id.clone(),
                selected.relay_peer_id.clone(),
            )) {
                return Err(SelectionBridgeError::SelectedIdentityMismatch);
            }
            let path = exact_complete_path_evidence(selected, paths)?;
            if !warm_path_is_admissible(
                path.unique_throughput_gain_ratio,
                path.meaningful_failover,
                self.scope.relay_policy,
            ) {
                continue;
            }
            let record = take_exact_selected_record(selected, &mut verified)?;
            earliest_expiry_ms = earliest_expiry_ms.min(record.advertisement_expires_at_ms);
            earliest_setup_evidence_expiry_ms =
                earliest_setup_evidence_expiry_ms.min(record.evidence_valid_until_ms);
            let path_id = u32::try_from(relay_bindings.len().saturating_add(1))
                .map_err(|_| SelectionBridgeError::TooManyCandidates)?;
            relay_bindings.push(ProspectiveRouteRelay {
                path_id,
                proof: mint_actor_bound_relay_proof(
                    record,
                    self.scope.now_ms,
                    self.scope.requirements(ServiceRole::Relay),
                    &self.forwarded_exit.authority,
                )?,
            });
        }

        let parameters = build_parameters(
            authority,
            &self.scope,
            deadlines,
            earliest_expiry_ms,
            earliest_setup_evidence_expiry_ms,
        )?;
        RouteSetupRequest::new(self.forwarded_exit, relay_bindings, parameters)
            .map_err(SelectionBridgeError::RouteSetup)
    }
}

type VerifiedCompleteRelayPaths = (
    Vec<VerifiedSelectionPeer<ProspectiveDirectRelay>>,
    Vec<RelaySelectionProjection>,
    Vec<CompleteRelayPathMetrics>,
);

fn verify_complete_relay_paths(
    selected_exit: &SelectedExit,
    paths: &[CompleteRelayPathEvidence],
) -> Result<VerifiedCompleteRelayPaths, SelectionBridgeError> {
    if paths.is_empty() || paths.len() > MAXIMUM_SELECTION_CANDIDATES {
        return Err(SelectionBridgeError::TooManyCandidates);
    }
    let expected_exit = selected_exit.evidence_binding();
    let expected_probe_address_family = selected_exit.scope.probe_address_family()?;
    let mut node_ids = HashSet::new();
    let mut peer_ids = HashSet::new();
    let mut verified = Vec::with_capacity(paths.len());
    let mut projections = Vec::with_capacity(paths.len());
    let mut metrics = Vec::with_capacity(paths.len());
    for path in paths {
        if path.exit != expected_exit
            || path.transport != selected_exit.scope.transport
            || path.policy_hash != selected_exit.scope.policy.hash
            || path.policy_expires_at_ms != selected_exit.scope.policy.expires_at_ms
            || path.probe_address_family != expected_probe_address_family
        {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
        validate_fresh_time(
            path.observed_at_ms,
            selected_exit.scope.now_ms,
            selected_exit.advertisement_measured_at_ms,
        )?;
        let mut relay = verify_direct_relay_selection_peer(&path.relay, &selected_exit.scope)?;
        let path_evidence_valid_until_ms = path
            .observed_at_ms
            .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
            .ok_or(SelectionBridgeError::StaleEvidence)?;
        relay.evidence_valid_until_ms = relay
            .evidence_valid_until_ms
            .min(path_evidence_valid_until_ms);
        if relay.evidence_batch_id != selected_exit.evidence_batch_id
            || path.relay_node_id != relay.candidate.advertisement.node_id
            || path.relay_peer_id != relay.candidate.advertisement.peer_id
            || path.relay_advertisement_sequence != relay.advertisement_sequence
            || path.relay_advertisement_payload_hash != relay.advertisement_payload_hash
            || path.relay_advertisement_payload_hash
                != relay.prospective.identity.advertisement_payload_hash
            || path.observed_at_ms < relay.advertisement_measured_at_ms
            || relay.candidate.advertisement.node_id == selected_exit.selected.node_id
            || relay.candidate.advertisement.peer_id == selected_exit.selected.peer_id
            || relay.prospective.identity.wire_node_id
                == selected_exit
                    .forwarded_exit
                    .authority
                    .control
                    .identity
                    .wire_node_id
            || relay.prospective.identity.peer_id
                == selected_exit
                    .forwarded_exit
                    .authority
                    .control
                    .identity
                    .peer_id
            || !node_ids.insert(relay.candidate.advertisement.node_id.clone())
            || !peer_ids.insert(relay.candidate.advertisement.peer_id.clone())
            || !selected_exit
                .reserved_path_limit
                .satisfies(path.exit_reserved_capacity)
        {
            return Err(SelectionBridgeError::EvidenceBinding);
        }
        if relay
            .diversity
            .conflicts_with(&selected_exit.forwarded_exit.control_diversity)
            || relay
                .diversity
                .conflicts_with(&selected_exit.forwarded_exit.exit_diversity)
        {
            continue;
        }
        let prefix_observed =
            PrefixObservedCandidate::new(&relay.candidate, relay.diversity.observed_network_prefix)
                .map_err(|reason| {
                    SelectionBridgeError::Selection(SelectionError::HardFilter(reason))
                })?;
        projections.push(RelaySelectionProjection::from_prefix_observed_candidate(
            &prefix_observed,
            &selected_exit.scope.requirements(ServiceRole::Relay),
        )?);
        metrics.push(CompleteRelayPathMetrics::new(
            path.client_to_relay_capacity,
            path.relay_to_exit_capacity,
            path.exit_reserved_capacity,
            path.client_to_relay_rtt_ms,
            path.relay_to_exit_rtt_ms,
            path.unique_throughput_gain_ratio,
            path.meaningful_failover,
        ));
        verified.push(relay);
    }
    Ok((verified, projections, metrics))
}

fn mint_actor_bound_relay_proof(
    record: VerifiedSelectionPeer<ProspectiveDirectRelay>,
    projected_at_ms: u64,
    requirements: FilterRequirements,
    forwarded_exit: &ProspectiveForwardedExit,
) -> Result<ActorBoundRelayProof, SelectionBridgeError> {
    let actor_evidence_observed_at_ms = record.actor_evidence_observed_at_ms;
    let freshness_ceiling = actor_evidence_observed_at_ms
        .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
        .ok_or(SelectionBridgeError::StaleEvidence)?;
    let identity = &record.prospective.identity;
    let advertisement = &record.candidate.advertisement;
    if !record.evidence_batch_id.is_valid()
        || !record.candidate.signature_verified
        || !advertisement.roles.relay
        || advertisement.node_id
            != record
                .prospective
                .selection_node_id()
                .map_err(SelectionBridgeError::RouteSetup)?
        || advertisement.peer_id.as_str() != identity.peer_id.to_string()
        || advertisement.sequence_number != identity.advertisement_sequence
        || record.advertisement_payload_hash != identity.advertisement_payload_hash
        || advertisement.measured_at.as_secs() != record.advertisement_measured_at_ms / 1_000
        || advertisement.expires_at.as_secs() != record.advertisement_expires_at_ms / 1_000
        || identity.advertisement_expires_at_ms != record.advertisement_expires_at_ms
        || identity.expires_at_ms
            != identity
                .advertisement_expires_at_ms
                .min(identity.policy_expires_at_ms)
        || identity.policy_hash != *requirements.policy_hash.as_bytes()
        || requirements.role != ServiceRole::Relay
        || requirements.now.as_secs() != projected_at_ms / 1_000
        || record.advertisement_measured_at_ms > actor_evidence_observed_at_ms
        || actor_evidence_observed_at_ms > projected_at_ms
        || projected_at_ms >= record.evidence_valid_until_ms
        || record.evidence_valid_until_ms > record.actor_evidence_valid_until_ms
        || record.evidence_valid_until_ms > freshness_ceiling
        || record.evidence_valid_until_ms
            > record
                .advertisement_expires_at_ms
                .min(identity.expires_at_ms)
                .min(identity.policy_expires_at_ms)
        || advertisement.network.operator_id != record.diversity.operator_id
        || advertisement.network.asn != Some(record.diversity.asn)
        || record.candidate.evidence.observed_network_origin.is_some()
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let diversity =
        ActorRelayDiversity::from_snapshot(&record.diversity, requirements.address_family)
            .map_err(SelectionBridgeError::RouteSetup)?;
    let prefix_observed =
        PrefixObservedCandidate::new(&record.candidate, record.diversity.observed_network_prefix)
            .map_err(|reason| SelectionBridgeError::Selection(SelectionError::HardFilter(reason)))?;
    let selection =
        RelaySelectionProjection::from_prefix_observed_candidate(&prefix_observed, &requirements)?;
    Ok(ActorBoundRelayProof {
        evidence_batch_id: record.evidence_batch_id.0,
        relay: record.prospective,
        forwarded_exit: forwarded_exit.clone(),
        selection,
        diversity,
        advertisement_measured_at_ms: record.advertisement_measured_at_ms,
        advertisement_expires_at_ms: record.advertisement_expires_at_ms,
        actor_evidence_observed_at_ms,
        evidence_valid_until_ms: record.evidence_valid_until_ms,
        projected_at_ms,
        static_requirements: requirements,
    })
}

#[cfg(test)]
pub(super) fn actor_bound_relay_proof_for_test(
    capability: &DirectRelayCapability,
    candidate: Candidate,
    diversity: DiversitySnapshot,
    forwarded_exit: &SelectedForwardedExit,
    evidence_batch_id: [u8; ID_BYTES],
    projected_at_ms: u64,
    requirements: FilterRequirements,
) -> ActorBoundRelayProof {
    let evidence_valid_until_ms = capability
        .expires_at_ms
        .min(projected_at_ms.saturating_add(MAXIMUM_EVIDENCE_AGE_MS));
    let record = VerifiedSelectionPeer {
        evidence_batch_id: EvidenceBatchId(evidence_batch_id),
        candidate,
        prospective: ProspectiveDirectRelay::from_capability(capability),
        diversity,
        advertisement_sequence: capability.advertisement_sequence,
        advertisement_measured_at_ms: projected_at_ms.saturating_sub(1_000),
        advertisement_expires_at_ms: capability.advertisement_expires_at_ms,
        advertisement_payload_hash: capability.advertisement_payload_hash,
        actor_evidence_observed_at_ms: projected_at_ms,
        actor_evidence_valid_until_ms: evidence_valid_until_ms,
        forwarded_control_evidence_valid_until_ms: None,
        evidence_valid_until_ms,
    };
    mint_actor_bound_relay_proof(
        record,
        projected_at_ms,
        requirements,
        &forwarded_exit.authority,
    )
    .expect("test actor proof")
}

fn select_exit_first<R: RngCore + ?Sized>(
    scope: RouteSelectionScope,
    exits: &[ForwardedExitSelectionInput],
    rng: &mut R,
) -> Result<SelectedExit, SelectionBridgeError> {
    scope.validate()?;
    if exits.is_empty() || exits.len() > MAXIMUM_SELECTION_CANDIDATES {
        return Err(SelectionBridgeError::TooManyCandidates);
    }
    let mut node_ids = HashSet::new();
    let mut peer_ids = HashSet::new();
    let mut verified = Vec::with_capacity(exits.len());
    for input in exits {
        let record = verify_forwarded_exit_selection_peer(input, &scope)?;
        if !node_ids.insert(record.candidate.advertisement.node_id.clone())
            || !peer_ids.insert(record.candidate.advertisement.peer_id.clone())
        {
            return Err(SelectionBridgeError::DuplicateIdentity);
        }
        verified.push(record);
    }
    let candidates = verified
        .iter()
        .map(|record| {
            PrefixObservedCandidate::new(
                &record.candidate,
                record.diversity.observed_network_prefix,
            )
            .map_err(|reason| SelectionBridgeError::Selection(SelectionError::HardFilter(reason)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selected = select_exit_with_observed_prefixes(
        &candidates,
        &scope.requirements(ServiceRole::Exit),
        scope.exit_mix,
        rng,
    )?;
    let selected_index = verified
        .iter()
        .position(|record| {
            record.candidate.advertisement.node_id == selected.node_id
                && record.candidate.advertisement.peer_id == selected.peer_id
        })
        .ok_or(SelectionBridgeError::SelectedIdentityMismatch)?;
    let record = verified.swap_remove(selected_index);
    Ok(SelectedExit {
        evidence_batch_id: record.evidence_batch_id,
        reserved_path_limit: record.candidate.evidence.reserved_path_limit,
        candidate: record.candidate,
        scope,
        selected,
        forwarded_exit: record.prospective,
        advertisement_sequence: record.advertisement_sequence,
        advertisement_measured_at_ms: record.advertisement_measured_at_ms,
        advertisement_expires_at_ms: record.advertisement_expires_at_ms,
        actor_evidence_observed_at_ms: record.actor_evidence_observed_at_ms,
        control_evidence_valid_until_ms: record
            .forwarded_control_evidence_valid_until_ms
            .ok_or(SelectionBridgeError::EvidenceBinding)?,
        exit_evidence_valid_until_ms: record.actor_evidence_valid_until_ms,
        evidence_valid_until_ms: record.evidence_valid_until_ms,
    })
}

fn verify_selection_metadata(
    authenticated: &AuthenticatedSelectionAdvertisement,
    fresh: &FreshPeerEvidence,
    scope: &RouteSelectionScope,
    expected_role: ServiceRole,
) -> Result<VerifiedSelectionPeer<()>, SelectionBridgeError> {
    let advertisement = &authenticated.advertisement;
    let observed_network_prefix = fresh
        .observed_network_prefix
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    let freshness_expires_at_ms = fresh
        .observed_at_ms
        .checked_add(MAXIMUM_EVIDENCE_AGE_MS)
        .ok_or(SelectionBridgeError::StaleEvidence)?;
    let asn = advertisement
        .network
        .asn
        .filter(|asn| *asn != 0)
        .ok_or(SelectionBridgeError::EvidenceBinding)?;
    let observed_family_matches = scope.address_family == Some(observed_network_prefix.family());
    if fresh.node_id != advertisement.node_id
        || fresh.peer_id != advertisement.peer_id
        || fresh.advertisement_sequence != advertisement.sequence_number
        || fresh.advertisement_expires_at_ms != authenticated.signed_expires_at_ms
        || fresh.advertisement_payload_hash != authenticated.advertisement_payload_hash
        || fresh.role != expected_role
        || fresh.transport != scope.transport
        || fresh.policy_version != scope.policy.version
        || fresh.policy_hash != scope.policy.hash
        || fresh.policy_expires_at_ms != scope.policy.expires_at_ms
        || fresh.address_family != scope.address_family
        || !observed_family_matches
        || (fresh.reachable && fresh.rtt_ms.is_none())
        || (!fresh.reachable && fresh.rtt_ms.is_some())
        || !observed_network_prefix.is_public_routable()
        || authenticated.signed_measured_at_ms == 0
        || authenticated.signed_measured_at_ms > authenticated.signed_expires_at_ms
    {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let measured_at_ms = authenticated.signed_measured_at_ms;
    let expires_at_ms = authenticated.signed_expires_at_ms;
    validate_fresh_time(fresh.observed_at_ms, scope.now_ms, measured_at_ms)?;
    if expires_at_ms <= scope.now_ms
        || fresh.valid_until_ms <= scope.now_ms
        || fresh.valid_until_ms > expires_at_ms
        || fresh.valid_until_ms > scope.policy.expires_at_ms
        || fresh.valid_until_ms > fresh.capability_expires_at_ms
        || fresh.valid_until_ms > freshness_expires_at_ms
    {
        return Err(SelectionBridgeError::StaleEvidence);
    }
    Ok(VerifiedSelectionPeer {
        evidence_batch_id: fresh.batch_id,
        candidate: Candidate {
            advertisement: advertisement.clone(),
            signature_verified: true,
            evidence: CandidateEvidence {
                locally_measured_p25: fresh.locally_measured_p25,
                reserved_path_limit: fresh.preselection_capacity_ceiling,
                uptime_score: fresh.uptime_score,
                reputation_score: authenticated.historical_reputation_score,
                proximity_score: fresh.proximity_score,
                recent_egress_quality: fresh.recent_egress_quality,
                rtt_ms: fresh.rtt_ms,
                measurement_count: fresh.measurement_count,
                reachable: fresh.reachable,
                network_address_usable: fresh.network_address_usable,
                observed_network_origin: None,
                locally_blocked: fresh.locally_blocked,
                serious_protocol_fault_until: authenticated.serious_protocol_fault_until,
            },
        },
        prospective: (),
        diversity: DiversitySnapshot {
            operator_id: advertisement.network.operator_id.clone(),
            asn,
            observed_network_prefix,
        },
        advertisement_sequence: advertisement.sequence_number,
        advertisement_measured_at_ms: measured_at_ms,
        advertisement_expires_at_ms: expires_at_ms,
        advertisement_payload_hash: authenticated.advertisement_payload_hash,
        actor_evidence_observed_at_ms: fresh.observed_at_ms,
        actor_evidence_valid_until_ms: fresh.valid_until_ms,
        forwarded_control_evidence_valid_until_ms: None,
        evidence_valid_until_ms: fresh.valid_until_ms,
    })
}

fn prospective_matches_metadata(
    identity: &ProspectivePeerIdentity,
    authenticated: &AuthenticatedSelectionAdvertisement,
    scope: &RouteSelectionScope,
) -> bool {
    let advertisement = &authenticated.advertisement;
    identity
        .selection_node_id()
        .is_ok_and(|node_id| node_id == advertisement.node_id)
        && identity.peer_id.to_string() == advertisement.peer_id.as_str()
        && identity.advertisement_sequence == advertisement.sequence_number
        && identity.advertisement_expires_at_ms == authenticated.signed_expires_at_ms
        && identity.advertisement_payload_hash == authenticated.advertisement_payload_hash
        && identity.policy_version == scope.policy.version
        && identity.policy_hash == *scope.policy.hash.as_bytes()
        && identity.policy_expires_at_ms == scope.policy.expires_at_ms
}

fn verify_direct_relay_selection_peer(
    input: &DirectRelaySelectionInput,
    scope: &RouteSelectionScope,
) -> Result<VerifiedSelectionPeer<ProspectiveDirectRelay>, SelectionBridgeError> {
    if !input.authenticated.advertisement.roles.relay {
        return Err(SelectionBridgeError::AdvertisementProvenance);
    }
    if input.fresh.forwarded_control.is_some() {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let metadata = verify_selection_metadata(
        &input.authenticated,
        &input.fresh,
        scope,
        ServiceRole::Relay,
    )?;
    let prospective = ProspectiveDirectRelay::from_capability(&input.capability);
    if !prospective_matches_metadata(&prospective.identity, &input.authenticated, scope)
        || input.fresh.capability_public_key != prospective.identity.public_key
        || metadata.advertisement_payload_hash != prospective.identity.advertisement_payload_hash
        || prospective.identity.expires_at_ms
            != prospective
                .identity
                .advertisement_expires_at_ms
                .min(prospective.identity.policy_expires_at_ms)
        || prospective.identity.expires_at_ms <= scope.now_ms
        || input.fresh.capability_expires_at_ms != prospective.identity.expires_at_ms
    {
        return Err(SelectionBridgeError::AdvertisementProvenance);
    }
    Ok(VerifiedSelectionPeer {
        evidence_batch_id: metadata.evidence_batch_id,
        candidate: metadata.candidate,
        prospective,
        diversity: metadata.diversity,
        advertisement_sequence: metadata.advertisement_sequence,
        advertisement_measured_at_ms: metadata.advertisement_measured_at_ms,
        advertisement_expires_at_ms: metadata.advertisement_expires_at_ms,
        advertisement_payload_hash: metadata.advertisement_payload_hash,
        actor_evidence_observed_at_ms: metadata.actor_evidence_observed_at_ms,
        actor_evidence_valid_until_ms: metadata.actor_evidence_valid_until_ms,
        forwarded_control_evidence_valid_until_ms: None,
        evidence_valid_until_ms: metadata.evidence_valid_until_ms,
    })
}

fn verify_forwarded_exit_selection_peer(
    input: &ForwardedExitSelectionInput,
    scope: &RouteSelectionScope,
) -> Result<VerifiedSelectionPeer<SelectedForwardedExit>, SelectionBridgeError> {
    if !input.authenticated.advertisement.roles.exit {
        return Err(SelectionBridgeError::AdvertisementProvenance);
    }
    let control = verify_direct_relay_selection_peer(&input.control, scope)?;
    let control_candidate = PrefixObservedCandidate::new(
        &control.candidate,
        control.diversity.observed_network_prefix,
    )
    .map_err(|reason| SelectionBridgeError::Selection(SelectionError::HardFilter(reason)))?;
    let _control_projection = RelaySelectionProjection::from_prefix_observed_candidate(
        &control_candidate,
        &scope.requirements(ServiceRole::Relay),
    )?;
    let expected_control = ForwardedControlBinding {
        node_id: control.candidate.advertisement.node_id.clone(),
        peer_id: control.candidate.advertisement.peer_id.clone(),
        public_key: control.prospective.identity.public_key,
        advertisement_sequence: control.advertisement_sequence,
        advertisement_expires_at_ms: control.advertisement_expires_at_ms,
        advertisement_payload_hash: control.advertisement_payload_hash,
        capability_expires_at_ms: control.prospective.identity.expires_at_ms,
    };
    if input.fresh.forwarded_control.as_ref() != Some(&expected_control) {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let metadata =
        verify_selection_metadata(&input.authenticated, &input.fresh, scope, ServiceRole::Exit)?;
    if control.evidence_batch_id != metadata.evidence_batch_id {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let prospective =
        ProspectiveForwardedExit::from_capabilities(&input.control.capability, &input.capability)
            .map_err(|_| SelectionBridgeError::AdvertisementProvenance)?;
    if !prospective_matches_metadata(&prospective.exit, &input.authenticated, scope)
        || input.fresh.capability_public_key != prospective.exit.public_key
        || metadata.advertisement_payload_hash != prospective.exit.advertisement_payload_hash
        || prospective.control != control.prospective
        || prospective.control.identity.policy_version != scope.policy.version
        || prospective.control.identity.policy_hash != *scope.policy.hash.as_bytes()
        || prospective.control.identity.policy_expires_at_ms != scope.policy.expires_at_ms
        || prospective.exit.expires_at_ms <= scope.now_ms
        || input.fresh.capability_expires_at_ms != prospective.exit.expires_at_ms
        || prospective.exit.expires_at_ms
            > prospective
                .exit
                .advertisement_expires_at_ms
                .min(prospective.exit.policy_expires_at_ms)
                .min(prospective.control.identity.expires_at_ms)
    {
        return Err(SelectionBridgeError::AdvertisementProvenance);
    }
    if control.diversity.conflicts_with(&metadata.diversity) {
        return Err(SelectionBridgeError::EvidenceBinding);
    }
    let exit_diversity = metadata.diversity;
    Ok(VerifiedSelectionPeer {
        evidence_batch_id: metadata.evidence_batch_id,
        candidate: metadata.candidate,
        prospective: SelectedForwardedExit {
            authority: prospective,
            control_diversity: control.diversity,
            exit_diversity: exit_diversity.clone(),
            evidence_batch_id: metadata.evidence_batch_id.0,
        },
        diversity: exit_diversity,
        advertisement_sequence: metadata.advertisement_sequence,
        advertisement_measured_at_ms: metadata.advertisement_measured_at_ms,
        advertisement_expires_at_ms: metadata.advertisement_expires_at_ms,
        advertisement_payload_hash: metadata.advertisement_payload_hash,
        actor_evidence_observed_at_ms: metadata.actor_evidence_observed_at_ms,
        actor_evidence_valid_until_ms: metadata.actor_evidence_valid_until_ms,
        forwarded_control_evidence_valid_until_ms: Some(control.actor_evidence_valid_until_ms),
        evidence_valid_until_ms: metadata
            .evidence_valid_until_ms
            .min(control.evidence_valid_until_ms),
    })
}

fn validate_fresh_time(
    observed_at_ms: u64,
    now_ms: u64,
    advertisement_measured_at_ms: u64,
) -> Result<(), SelectionBridgeError> {
    if observed_at_ms < advertisement_measured_at_ms
        || observed_at_ms > now_ms
        || now_ms.saturating_sub(observed_at_ms) > MAXIMUM_EVIDENCE_AGE_MS
    {
        return Err(SelectionBridgeError::StaleEvidence);
    }
    Ok(())
}

fn take_exact_selected_record(
    selected: &SelectedPath,
    verified: &mut Vec<VerifiedSelectionPeer<ProspectiveDirectRelay>>,
) -> Result<VerifiedSelectionPeer<ProspectiveDirectRelay>, SelectionBridgeError> {
    let mut matching = verified.iter().enumerate().filter(|(_, record)| {
        record.candidate.advertisement.node_id == selected.relay_node_id
            && record.candidate.advertisement.peer_id == selected.relay_peer_id
    });
    let (index, _) = matching
        .next()
        .ok_or(SelectionBridgeError::SelectedIdentityMismatch)?;
    if matching.next().is_some() {
        return Err(SelectionBridgeError::SelectedIdentityMismatch);
    }
    Ok(verified.swap_remove(index))
}

fn warm_path_is_admissible(
    unique_throughput_gain_ratio: f64,
    meaningful_failover: bool,
    policy: RelaySelectionPolicy,
) -> bool {
    unique_throughput_gain_ratio >= policy.minimum_unique_throughput_gain_ratio
        || meaningful_failover
}

fn exact_complete_path_evidence<'a>(
    selected: &SelectedPath,
    candidates: &'a [CompleteRelayPathEvidence],
) -> Result<&'a CompleteRelayPathEvidence, SelectionBridgeError> {
    let mut matching = candidates.iter().filter(|candidate| {
        candidate.relay_node_id == selected.relay_node_id
            && candidate.relay_peer_id == selected.relay_peer_id
    });
    let candidate = matching
        .next()
        .ok_or(SelectionBridgeError::SelectedIdentityMismatch)?;
    if matching.next().is_some() {
        return Err(SelectionBridgeError::SelectedIdentityMismatch);
    }
    Ok(candidate)
}

fn build_parameters(
    authority: RouteSessionAuthority,
    scope: &RouteSelectionScope,
    deadlines: RouteDeadlines,
    earliest_expiry_ms: u64,
    earliest_setup_evidence_expiry_ms: u64,
) -> Result<RouteSetupParameters, SelectionBridgeError> {
    let maximum_setup_ms = u64::try_from(MAXIMUM_SETUP_DURATION.as_millis())
        .map_err(|_| SelectionBridgeError::InvalidDeadline)?;
    let setup_lifetime = deadlines
        .setup_expires_at_ms
        .checked_sub(scope.now_ms)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    let hard_lifetime = deadlines
        .hard_expires_at_ms
        .checked_sub(scope.now_ms)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    if setup_lifetime == 0
        || setup_lifetime > maximum_setup_ms
        || hard_lifetime == 0
        || hard_lifetime > MAXIMUM_RESERVATION_LIFETIME_MS
        || deadlines.setup_expires_at_ms > deadlines.hard_expires_at_ms
        || deadlines.setup_expires_at_ms > earliest_setup_evidence_expiry_ms
        || deadlines.hard_expires_at_ms > earliest_expiry_ms
    {
        return Err(SelectionBridgeError::InvalidDeadline);
    }

    // Floor to helper seconds so the privileged lifetime can never exceed the exact millisecond
    // reservation/policy/advertisement ceiling. Reject sub-second rounding that is already expired.
    let now_unix = scope.now_ms / 1_000;
    let setup_expires_at_unix = deadlines.setup_expires_at_ms / 1_000;
    let hard_expires_at_unix = deadlines.hard_expires_at_ms / 1_000;
    let hard_floor_ms = hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(SelectionBridgeError::InvalidDeadline)?;
    if setup_expires_at_unix <= now_unix
        || setup_expires_at_unix > hard_expires_at_unix
        || hard_expires_at_unix <= now_unix
        || hard_floor_ms > earliest_expiry_ms
    {
        return Err(SelectionBridgeError::InvalidDeadline);
    }

    let probe_address_family = scope.probe_address_family()?;
    let post_probe_relay_policy = scope.relay_policy;
    let (reservation_id, route_context_id) = authority.into_ids();
    Ok(RouteSetupParameters {
        reservation_id,
        route_context_id,
        allowed_transports: vec![protocol_transport(scope.transport)],
        reserved_up_mbps: u64::from(scope.minimum_capacity.up_mbps),
        reserved_down_mbps: u64::from(scope.minimum_capacity.down_mbps),
        policy_hash: *scope.policy.hash.as_bytes(),
        probe_address_family,
        post_probe_policy: PostProbeSelectionPolicy {
            requirements: scope.requirements(ServiceRole::Relay),
            relay_policy: post_probe_relay_policy,
        },
        created_at_ms: scope.now_ms,
        expires_at_ms: deadlines.hard_expires_at_ms,
        setup_expires_at_unix,
        hard_expires_at_unix,
        client_native_route_scope: None,
    })
}

const fn protocol_transport(transport: SelectionTransport) -> ProtocolTransport {
    match transport {
        SelectionTransport::TcpMptcp => ProtocolTransport::TcpMptcp,
        SelectionTransport::UdpSinglePath => ProtocolTransport::UdpSinglePath,
        SelectionTransport::MultipathQuic => ProtocolTransport::MultipathQuic,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
    };

    use libp2p::PeerId as Libp2pPeerId;
    use tokio::sync::Notify;
    use volparossa_core::{
        CapacitySnapshot, NetworkMetadata, NodeAdvertisement as CoreAdvertisement,
        NodeCapabilities, NodeQuality, NodeRoles, ObservedNetworkOrigin, OperatorId,
        PROTOCOL_VERSION, PeerId as CorePeerId,
    };
    use volparossa_identity::Identity;
    use volparossa_peerstore::PeerStore;
    use volparossa_protocol::{
        AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork,
        AdvertisementPolicy, AdvertisementQuality, AdvertisementRoles, MAX_CONTROL_MESSAGE_SIZE,
        NodeAdvertisement as WireAdvertisement, SignedEnvelope, TimePolicy, decode_canonical,
        node_id_from_public_key, sign_control_message_with,
    };
    use volparossa_selection::{HardFilterReason, SelectionError};

    use super::super::{
        ActivateLeaseBatch, ActivatedLeaseBatch, CleanupStatus, CommitLeaseBatch,
        CommittedLeaseBatch, DestroyedContext, ExitForwardRequest, ExitForwardResponse,
        LocalPrepareFailure, PrepareLeaseBatch, PrepareReconciliationAuthority,
        ReconciledExpiredPrepare, RuntimeBoundPreparedLeaseBatch,
    };
    use super::*;

    const NOW_MS: u64 = 1_750_000_000_000;
    const POLICY_BYTES: [u8; 32] = [77; 32];
    const EVIDENCE_BATCH_BYTES: [u8; 16] = [33; 16];
    const ADVERTISEMENT_MEASURED_AT_MS: u64 = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS;

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one fixture keeps the signed wire body and exact persisted core body visibly identical"
    )]
    fn signed_peer(
        seed: u8,
        relay: bool,
        exit: bool,
        operator: &str,
        asn: u32,
        address: impl Into<IpAddr>,
        policy_hash: [u8; 32],
        expires_at_ms: u64,
    ) -> StoredPeer {
        let address = address.into();
        let (address_protocol, supports_ipv4, supports_ipv6) = match address {
            IpAddr::V4(_) => ("ip4", true, false),
            IpAddr::V6(_) => ("ip6", false, true),
        };
        let identity = Identity::generate();
        let public_key = identity.ed25519_public_key_bytes().expect("public key");
        let wire_node_id = node_id_from_public_key(&public_key);
        let peer_id = identity.peer_id().to_owned();
        let relay_limit = u64::from(relay) * 100;
        let exit_limit = u64::from(exit) * 100;
        let wire = WireAdvertisement {
            node_id: wire_node_id.to_vec(),
            peer_id: peer_id.to_bytes(),
            sequence_number: u64::from(seed) + 1,
            roles: Some(AdvertisementRoles {
                client: false,
                relay,
                exit,
            }),
            capabilities: Some(AdvertisementCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: supports_ipv4,
                ipv6: supports_ipv6,
                udp_hole_punching: false,
            }),
            control_addresses: vec![format!("/{address_protocol}/{address}/udp/4001/quic-v1")],
            capacity: Some(AdvertisementCapacity {
                operator_relay_limit_up_mbps: relay_limit,
                operator_relay_limit_down_mbps: relay_limit,
                operator_exit_limit_up_mbps: exit_limit,
                operator_exit_limit_down_mbps: exit_limit,
                currently_reserved_up_mbps: 0,
                currently_reserved_down_mbps: 0,
                estimated_free_up_mbps: 100,
                estimated_free_down_mbps: 100,
                active_relay_sessions: 0,
                active_exit_sessions: 0,
                free_relay_slots: u32::from(relay) * 4,
                free_exit_slots: u32::from(exit) * 4,
                sample_window_seconds: 30,
            }),
            network: Some(AdvertisementNetwork {
                region: "eu-west".to_owned(),
                country_code: "NL".to_owned(),
                asn,
                ipv4_prefix_hint: String::new(),
                ipv6_prefix_hint: String::new(),
                operator_id: operator.to_owned(),
            }),
            quality: Some(AdvertisementQuality {
                local_uptime_seconds: 600,
                historical_uptime_ppm: 900_000,
                historical_delivery_ratio_p25_ppm: 800_000,
            }),
            policy: Some(AdvertisementPolicy {
                whitelist_version: 7,
                whitelist_hash: policy_hash.to_vec(),
            }),
            measured_at_ms: ADVERTISEMENT_MEASURED_AT_MS,
            expires_at_ms,
        };
        let envelope = sign_control_message_with(
            &wire,
            public_key,
            ADVERTISEMENT_MEASURED_AT_MS,
            expires_at_ms,
            [seed.max(1); 32],
            TimePolicy::default(),
            |bytes| identity.sign(bytes).ok(),
        )
        .expect("signed advertisement");
        let relay_bandwidth = Bandwidth::new(u32::from(relay) * 100, u32::from(relay) * 100)
            .expect("relay bandwidth");
        let exit_bandwidth =
            Bandwidth::new(u32::from(exit) * 100, u32::from(exit) * 100).expect("exit bandwidth");
        let advertisement = CoreAdvertisement {
            protocol_version: PROTOCOL_VERSION,
            node_id: NodeId::new(hex::encode(wire_node_id)).expect("node id"),
            peer_id: CorePeerId::new(peer_id.to_string()).expect("peer id"),
            sequence_number: wire.sequence_number,
            roles: NodeRoles {
                client: false,
                relay,
                exit,
            },
            capabilities: NodeCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: supports_ipv4,
                ipv6: supports_ipv6,
                udp_hole_punching: false,
            },
            capacity: CapacitySnapshot {
                relay_limit: relay_bandwidth,
                exit_limit: exit_bandwidth,
                currently_reserved: Bandwidth::new(0, 0).expect("zero bandwidth"),
                estimated_free: Bandwidth::new(100, 100).expect("free bandwidth"),
                active_relay_sessions: 0,
                active_exit_sessions: 0,
                free_relay_slots: u32::from(relay) * 4,
                free_exit_slots: u32::from(exit) * 4,
                sample_window_seconds: 30,
            },
            network: NetworkMetadata {
                operator_id: OperatorId::new(operator).expect("operator"),
                region: "eu-west".to_owned(),
                country_code: "NL".to_owned(),
                asn: (asn != 0).then_some(asn),
                ipv4_prefix_hint: None,
                ipv6_prefix_hint: None,
            },
            quality: NodeQuality {
                local_uptime_seconds: 600,
                historical_uptime_score: 0.9,
                historical_delivery_ratio_p25: 0.8,
            },
            policy_hash: PolicyHash::from_bytes(policy_hash),
            control_endpoints: wire.control_addresses,
            measured_at: UnixTime::from_secs(ADVERTISEMENT_MEASURED_AT_MS / 1_000),
            expires_at: UnixTime::from_secs(expires_at_ms / 1_000),
        };
        let mut store = PeerStore::open_in_memory().expect("peerstore");
        store
            .upsert_advertisement(
                &advertisement,
                &envelope,
                UnixTime::from_secs(NOW_MS / 1_000),
            )
            .expect("persist signed evidence");
        store
            .load_candidates(UnixTime::from_secs(NOW_MS / 1_000), 1)
            .expect("load signed evidence")
            .pop()
            .expect("stored peer")
    }

    fn actor_identity(stored: &StoredPeer) -> ([u8; 32], Libp2pPeerId, [u8; 32]) {
        let envelope = decode_canonical::<SignedEnvelope>(
            stored.signed_advertisement_envelope(),
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("decode stored envelope");
        let public_key: [u8; 32] = envelope
            .sender_public_key
            .as_slice()
            .try_into()
            .expect("sender key");
        let node_id = node_id_from_public_key(&public_key);
        assert_eq!(stored.advertisement.node_id.as_str(), hex::encode(node_id));
        let peer_id =
            Libp2pPeerId::from_str(stored.advertisement.peer_id.as_str()).expect("libp2p peer id");
        (node_id, peer_id, public_key)
    }

    fn exact_advertisement_payload_hash(stored: &StoredPeer) -> AdvertisementPayloadHash {
        RouteCandidateAdvertisement::for_test(stored, NOW_MS)
            .expect("freshly revalidated test advertisement")
            .advertisement_payload_hash()
    }

    fn direct_capability(stored: &StoredPeer) -> DirectRelayCapability {
        let (node_id, peer_id, public_key) = actor_identity(stored);
        let advertisement_expires_at_ms = stored
            .advertisement
            .expires_at
            .as_secs()
            .checked_mul(1_000)
            .expect("advertisement expiry");
        let policy_expires_at_ms = NOW_MS + 90_000;
        DirectRelayCapability {
            node_id,
            peer_id,
            public_key,
            advertisement_sequence: stored.advertisement.sequence_number,
            advertisement_expires_at_ms,
            advertisement_payload_hash: exact_advertisement_payload_hash(stored),
            policy_version: 7,
            policy_hash: POLICY_BYTES,
            policy_expires_at_ms,
            expires_at_ms: advertisement_expires_at_ms.min(policy_expires_at_ms),
        }
    }

    fn fresh_evidence(stored: &StoredPeer, address: impl Into<IpAddr>) -> FreshPeerEvidence {
        let advertisement = &stored.advertisement;
        let address = address.into();
        let observed_network_prefix =
            ObservedNetworkPrefix::from_origin(ObservedNetworkOrigin { address });
        let (_, _, capability_public_key) = actor_identity(stored);
        let advertisement_expires_at_ms = advertisement
            .expires_at
            .as_secs()
            .checked_mul(1_000)
            .expect("advertisement expiry");
        let address_family = match address {
            IpAddr::V4(_) => IpFamily::Ipv4,
            IpAddr::V6(_) => IpFamily::Ipv6,
        };
        let role = if advertisement.roles.exit {
            ServiceRole::Exit
        } else {
            ServiceRole::Relay
        };
        FreshPeerEvidence {
            batch_id: EvidenceBatchId::for_test(EVIDENCE_BATCH_BYTES),
            node_id: advertisement.node_id.clone(),
            peer_id: advertisement.peer_id.clone(),
            capability_public_key,
            advertisement_sequence: advertisement.sequence_number,
            advertisement_expires_at_ms,
            advertisement_payload_hash: exact_advertisement_payload_hash(stored),
            capability_expires_at_ms: advertisement_expires_at_ms.min(NOW_MS + 90_000),
            role,
            transport: SelectionTransport::TcpMptcp,
            policy_version: 7,
            policy_hash: PolicyHash::from_bytes(POLICY_BYTES),
            policy_expires_at_ms: NOW_MS + 90_000,
            address_family: Some(address_family),
            observed_at_ms: NOW_MS,
            valid_until_ms: NOW_MS + MAXIMUM_EVIDENCE_AGE_MS,
            forwarded_control: None,
            locally_measured_p25: Some(
                Bandwidth::new(90, 90).expect("fresh measured delivery p25"),
            ),
            measurement_count: 8,
            preselection_capacity_ceiling: Bandwidth::new(80, 80)
                .expect("preselection capacity ceiling"),
            uptime_score: 0.9,
            proximity_score: 0.8,
            recent_egress_quality: 0.75,
            rtt_ms: Some(10.0),
            reachable: true,
            network_address_usable: true,
            observed_network_prefix: Some(observed_network_prefix),
            locally_blocked: false,
        }
    }

    fn relay_input(stored: &StoredPeer, address: impl Into<IpAddr>) -> DirectRelaySelectionInput {
        let capability = direct_capability(stored);
        let mut fresh = fresh_evidence(stored, address);
        fresh.role = ServiceRole::Relay;
        fresh.forwarded_control = None;
        let authenticated = AuthenticatedSelectionAdvertisement::from(
            &RouteCandidateAdvertisement::for_test(stored, NOW_MS)
                .expect("revalidated test advertisement"),
        );
        DirectRelaySelectionInput {
            authenticated,
            fresh,
            capability,
        }
    }

    fn scope() -> RouteSelectionScope {
        RouteSelectionScope {
            now_ms: NOW_MS,
            transport: SelectionTransport::TcpMptcp,
            policy: ActivePolicySnapshot {
                version: 7,
                hash: PolicyHash::from_bytes(POLICY_BYTES),
                expires_at_ms: NOW_MS + 90_000,
            },
            minimum_capacity: Bandwidth::new(10, 10).expect("minimum"),
            address_family: Some(IpFamily::Ipv4),
            region: Some("eu-west".to_owned()),
            exit_mix: SelectionMix {
                high: 1.0,
                diverse_middle: 0.0,
                exploration: 0.0,
            },
            relay_policy: RelaySelectionPolicy {
                active_paths: 2,
                minimum_paths: 2,
                maximum_paths: 4,
                warm_backup_paths: 0,
                maximum_rtt_spread_ms: 20.0,
                minimum_unique_throughput_gain_ratio: 0.10,
                mix: SelectionMix {
                    high: 1.0,
                    diverse_middle: 0.0,
                    exploration: 0.0,
                },
            },
        }
    }

    fn exit_input() -> ForwardedExitSelectionInput {
        exit_input_for_addresses(
            IpAddr::V4(Ipv4Addr::new(44, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(45, 1, 1, 1)),
        )
    }

    fn exit_input_for_addresses(
        control_address: IpAddr,
        exit_address: IpAddr,
    ) -> ForwardedExitSelectionInput {
        exit_input_for_addresses_with_asns(control_address, exit_address, 64_499, 64_500)
    }

    fn exit_input_for_addresses_with_asns(
        control_address: IpAddr,
        exit_address: IpAddr,
        control_asn: u32,
        exit_asn: u32,
    ) -> ForwardedExitSelectionInput {
        let control_stored = signed_peer(
            80,
            true,
            false,
            "operator-control",
            control_asn,
            control_address,
            POLICY_BYTES,
            NOW_MS + 120_000,
        );
        let stored = signed_peer(
            90,
            false,
            true,
            "operator-exit",
            exit_asn,
            exit_address,
            POLICY_BYTES,
            NOW_MS + 120_000,
        );
        let control = relay_input(&control_stored, control_address);
        let (exit_node_id, exit_peer_id, exit_public_key) = actor_identity(&stored);
        let exit_advertisement_expires_at_ms = stored
            .advertisement
            .expires_at
            .as_secs()
            .checked_mul(1_000)
            .expect("exit advertisement expiry");
        let capability = ForwardedExitCapability {
            control_relay_node_id: control.capability.node_id,
            control_relay_peer_id: control.capability.peer_id,
            control_relay_public_key: control.capability.public_key,
            control_relay_advertisement_sequence: control.capability.advertisement_sequence,
            control_relay_advertisement_expires_at_ms: control
                .capability
                .advertisement_expires_at_ms,
            control_relay_advertisement_payload_hash: control.capability.advertisement_payload_hash,
            exit_node_id,
            exit_peer_id,
            exit_public_key,
            exit_advertisement_sequence: stored.advertisement.sequence_number,
            exit_advertisement_expires_at_ms,
            exit_advertisement_payload_hash: exact_advertisement_payload_hash(&stored),
            policy_version: 7,
            policy_hash: POLICY_BYTES,
            policy_expires_at_ms: NOW_MS + 90_000,
            expires_at_ms: control
                .capability
                .expires_at_ms
                .min(exit_advertisement_expires_at_ms)
                .min(NOW_MS + 90_000),
        };
        let mut fresh = fresh_evidence(&stored, exit_address);
        fresh.capability_expires_at_ms = capability.expires_at_ms;
        fresh.forwarded_control = Some(ForwardedControlBinding {
            node_id: control.authenticated.advertisement.node_id.clone(),
            peer_id: control.authenticated.advertisement.peer_id.clone(),
            public_key: control.capability.public_key,
            advertisement_sequence: control.capability.advertisement_sequence,
            advertisement_expires_at_ms: control.capability.advertisement_expires_at_ms,
            advertisement_payload_hash: control.capability.advertisement_payload_hash,
            capability_expires_at_ms: control.capability.expires_at_ms,
        });
        let authenticated = AuthenticatedSelectionAdvertisement::from(
            &RouteCandidateAdvertisement::for_test(&stored, NOW_MS)
                .expect("revalidated test exit advertisement"),
        );
        ForwardedExitSelectionInput {
            authenticated,
            fresh,
            control,
            capability,
        }
    }

    fn selected_exit(scope: RouteSelectionScope) -> SelectedExit {
        select_exit_first(scope, &[exit_input()], &mut OsRng).expect("selected exit")
    }

    fn relay_path(
        exit: SelectedExitBinding,
        seed: u8,
        operator: &str,
        asn: u32,
        address: impl Into<IpAddr>,
        relay_to_exit_rtt_ms: f64,
    ) -> CompleteRelayPathEvidence {
        let address = address.into();
        let probe_address_family = match address {
            IpAddr::V4(_) => ProbeAddressFamily::Ipv4,
            IpAddr::V6(_) => ProbeAddressFamily::Ipv6,
        };
        let relay = relay_input(
            &signed_peer(
                seed,
                true,
                false,
                operator,
                asn,
                address,
                POLICY_BYTES,
                NOW_MS + 120_000,
            ),
            address,
        );
        let relay_advertisement_payload_hash = relay.authenticated.advertisement_payload_hash;
        CompleteRelayPathEvidence {
            exit,
            relay_node_id: relay.authenticated.advertisement.node_id.clone(),
            relay_peer_id: relay.authenticated.advertisement.peer_id.clone(),
            relay_advertisement_sequence: relay.authenticated.advertisement.sequence_number,
            relay_advertisement_payload_hash,
            relay,
            transport: SelectionTransport::TcpMptcp,
            policy_hash: PolicyHash::from_bytes(POLICY_BYTES),
            policy_expires_at_ms: NOW_MS + 90_000,
            probe_address_family,
            observed_at_ms: NOW_MS,
            client_to_relay_capacity: Bandwidth::new(70, 70).expect("client relay capacity"),
            relay_to_exit_capacity: Bandwidth::new(60, 60).expect("relay exit capacity"),
            exit_reserved_capacity: Bandwidth::new(50, 50).expect("exit capacity"),
            client_to_relay_rtt_ms: 10.0,
            relay_to_exit_rtt_ms,
            unique_throughput_gain_ratio: 0.20,
            meaningful_failover: true,
        }
    }

    fn two_relay_paths(exit: SelectedExitBinding) -> Vec<CompleteRelayPathEvidence> {
        vec![
            relay_path(
                exit.clone(),
                1,
                "operator-relay-a",
                64_501,
                Ipv4Addr::new(46, 1, 1, 1),
                15.0,
            ),
            relay_path(
                exit,
                2,
                "operator-relay-b",
                64_502,
                Ipv4Addr::new(47, 2, 2, 2),
                17.0,
            ),
        ]
    }

    fn ipv6_scope() -> RouteSelectionScope {
        let mut scope = scope();
        scope.address_family = Some(IpFamily::Ipv6);
        scope
    }

    fn ipv6_exit_input() -> ForwardedExitSelectionInput {
        exit_input_for_addresses(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x0100, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x0100, 0, 0, 0, 0, 1)),
        )
    }

    fn two_ipv6_relay_paths(exit: SelectedExitBinding) -> Vec<CompleteRelayPathEvidence> {
        vec![
            relay_path(
                exit.clone(),
                21,
                "operator-relay-v6-a",
                64_521,
                Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 1),
                15.0,
            ),
            relay_path(
                exit,
                22,
                "operator-relay-v6-b",
                64_522,
                Ipv6Addr::new(0x2a00, 0x1450, 0x4001, 0, 0, 0, 0, 1),
                17.0,
            ),
        ]
    }

    fn assert_cross_stage_conflict_is_filtered(
        selected: &SelectedExit,
        conflict: CompleteRelayPathEvidence,
        mut allowed: Vec<CompleteRelayPathEvidence>,
    ) {
        let conflict_node_id = conflict.relay_node_id.clone();
        allowed.insert(0, conflict);
        let (verified, projections, metrics) =
            verify_complete_relay_paths(selected, &allowed).expect("valid bound path evidence");
        assert_eq!(verified.len(), 2);
        assert_eq!(projections.len(), 2);
        assert_eq!(metrics.len(), 2);
        assert!(
            verified
                .iter()
                .all(|record| record.candidate.advertisement.node_id != conflict_node_id)
        );
    }

    fn deadlines() -> RouteDeadlines {
        RouteDeadlines {
            setup_expires_at_ms: NOW_MS + 20_000,
            hard_expires_at_ms: NOW_MS + 60_000,
        }
    }

    fn snapshot_direct_candidate(
        stored: &StoredPeer,
        address: impl Into<IpAddr>,
    ) -> (DirectRelayCandidateSnapshot, FreshPeerEvidence) {
        let address = address.into();
        let fresh = fresh_evidence(stored, address);
        let capability = direct_capability(stored);
        let advertisement = RouteCandidateAdvertisement::for_test(stored, NOW_MS)
            .expect("revalidated snapshot advertisement");
        (
            DirectRelayCandidateSnapshot::for_test(advertisement, capability),
            fresh,
        )
    }

    fn snapshot_forwarded_exit(
        control: &DirectRelayCandidateSnapshot,
    ) -> (ForwardedExitCandidateSnapshot, FreshPeerEvidence) {
        let exit_stored = signed_peer(
            90,
            false,
            true,
            "operator-exit",
            64_500,
            Ipv4Addr::new(45, 1, 1, 1),
            POLICY_BYTES,
            NOW_MS + 120_000,
        );
        let mut exit_fresh = fresh_evidence(&exit_stored, Ipv4Addr::new(45, 1, 1, 1));
        let exit_advertisement = RouteCandidateAdvertisement::for_test(&exit_stored, NOW_MS)
            .expect("revalidated snapshot exit");
        let (exit_node_id, exit_peer_id, exit_public_key) = actor_identity(&exit_stored);
        let control_capability = control.capability().clone();
        let exit_capability = ForwardedExitCapability {
            control_relay_node_id: control_capability.node_id,
            control_relay_peer_id: control_capability.peer_id,
            control_relay_public_key: control_capability.public_key,
            control_relay_advertisement_sequence: control_capability.advertisement_sequence,
            control_relay_advertisement_expires_at_ms: control_capability
                .advertisement_expires_at_ms,
            control_relay_advertisement_payload_hash: control_capability.advertisement_payload_hash,
            exit_node_id,
            exit_peer_id,
            exit_public_key,
            exit_advertisement_sequence: exit_stored.advertisement.sequence_number,
            exit_advertisement_expires_at_ms: exit_advertisement.signed_expires_at_ms(),
            exit_advertisement_payload_hash: exit_advertisement.advertisement_payload_hash(),
            policy_version: 7,
            policy_hash: POLICY_BYTES,
            policy_expires_at_ms: NOW_MS + 90_000,
            expires_at_ms: NOW_MS + 90_000,
        };
        exit_fresh.capability_expires_at_ms = exit_capability.expires_at_ms;
        exit_fresh.forwarded_control = Some(ForwardedControlBinding {
            node_id: control.advertisement().advertisement().node_id.clone(),
            peer_id: control.advertisement().advertisement().peer_id.clone(),
            public_key: control_capability.public_key,
            advertisement_sequence: control_capability.advertisement_sequence,
            advertisement_expires_at_ms: control_capability.advertisement_expires_at_ms,
            advertisement_payload_hash: control_capability.advertisement_payload_hash,
            capability_expires_at_ms: control_capability.expires_at_ms,
        });
        let forwarded = ForwardedExitCandidateSnapshot::for_test(
            exit_advertisement,
            control.clone(),
            exit_capability,
        );
        (forwarded, exit_fresh)
    }

    fn snapshot_fixture() -> (RouteCandidateSnapshot, Vec<FreshPeerEvidence>) {
        let (control, control_fresh) = snapshot_direct_candidate(
            &signed_peer(
                80,
                true,
                false,
                "operator-control",
                64_499,
                Ipv4Addr::new(44, 1, 1, 1),
                POLICY_BYTES,
                NOW_MS + 120_000,
            ),
            Ipv4Addr::new(44, 1, 1, 1),
        );
        let (forwarded, exit_fresh) = snapshot_forwarded_exit(&control);
        let (relay_a, first_relay_evidence) = snapshot_direct_candidate(
            &signed_peer(
                1,
                true,
                false,
                "operator-relay-a",
                64_501,
                Ipv4Addr::new(46, 1, 1, 1),
                POLICY_BYTES,
                NOW_MS + 120_000,
            ),
            Ipv4Addr::new(46, 1, 1, 1),
        );
        let (relay_b, second_relay_evidence) = snapshot_direct_candidate(
            &signed_peer(
                2,
                true,
                false,
                "operator-relay-b",
                64_502,
                Ipv4Addr::new(47, 2, 2, 2),
                POLICY_BYTES,
                NOW_MS + 120_000,
            ),
            Ipv4Addr::new(47, 2, 2, 2),
        );
        (
            RouteCandidateSnapshot::for_test(
                NOW_MS,
                RouteCandidatePolicySnapshot::for_test(7, POLICY_BYTES, NOW_MS + 90_000),
                vec![control, relay_a, relay_b],
                vec![forwarded],
            ),
            vec![
                control_fresh,
                exit_fresh,
                first_relay_evidence,
                second_relay_evidence,
            ],
        )
    }

    fn fresh_batch(evidence: Vec<FreshPeerEvidence>) -> FreshEvidenceBatch {
        FreshEvidenceBatch::for_test(evidence, NOW_MS).expect("valid fake evidence batch")
    }

    fn exact_control_binding(fresh: &FreshPeerEvidence) -> ForwardedControlBinding {
        ForwardedControlBinding {
            node_id: fresh.node_id.clone(),
            peer_id: fresh.peer_id.clone(),
            public_key: fresh.capability_public_key,
            advertisement_sequence: fresh.advertisement_sequence,
            advertisement_expires_at_ms: fresh.advertisement_expires_at_ms,
            advertisement_payload_hash: fresh.advertisement_payload_hash,
            capability_expires_at_ms: fresh.capability_expires_at_ms,
        }
    }

    #[test]
    fn fresh_batch_rejects_mixed_batch_role_shape_and_policy_bindings() {
        let (_, evidence) = snapshot_fixture();
        assert!(FreshEvidenceBatch::for_test(evidence.clone(), NOW_MS).is_ok());

        let mut zero_batch = evidence.clone();
        zero_batch[0].batch_id = EvidenceBatchId([0; 16]);
        assert!(matches!(
            FreshEvidenceBatch::for_test(zero_batch, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut mixed_batch = evidence.clone();
        mixed_batch[0].batch_id = EvidenceBatchId::for_test([34; 16]);
        assert!(matches!(
            FreshEvidenceBatch::for_test(mixed_batch, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut relay_with_forwarded_control = evidence.clone();
        relay_with_forwarded_control[2].forwarded_control =
            Some(exact_control_binding(&relay_with_forwarded_control[0]));
        assert!(matches!(
            FreshEvidenceBatch::for_test(relay_with_forwarded_control, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut exit_without_forwarded_control = evidence.clone();
        exit_without_forwarded_control[1].forwarded_control = None;
        assert!(matches!(
            FreshEvidenceBatch::for_test(exit_without_forwarded_control, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut wrong_policy = evidence;
        wrong_policy[0].policy_version += 1;
        assert!(matches!(
            FreshEvidenceBatch::for_test(wrong_policy, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn fresh_batch_rejects_zero_or_invalid_preselection_capacity_ceiling() {
        let (_, evidence) = snapshot_fixture();
        for invalid in [
            Bandwidth {
                up_mbps: 0,
                down_mbps: 80,
            },
            Bandwidth {
                up_mbps: 80,
                down_mbps: 0,
            },
            Bandwidth {
                up_mbps: 1_000_001,
                down_mbps: 80,
            },
        ] {
            let mut mutated = evidence.clone();
            mutated[0].preselection_capacity_ceiling = invalid;
            assert!(matches!(
                FreshEvidenceBatch::for_test(mutated, NOW_MS),
                Err(SelectionBridgeError::EvidenceBinding)
            ));
        }
    }

    fn phase_a_product_source() -> &'static str {
        include_str!("selection_bridge.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("product bridge source")
    }

    fn phase_a_observation_source(product: &str) -> &str {
        let observation_start = product
            .find("/// Fresh local observation explicitly bound")
            .expect("fresh observation documentation");
        let observation_end = product[observation_start..]
            .find("/// Exact actor identity retained")
            .map(|offset| observation_start + offset)
            .expect("fresh observation section end");
        &product[observation_start..observation_end]
    }

    fn assert_phase_a_observation_fields_and_tokens(product: &str, observation: &str) {
        assert_eq!(
            observation
                .matches("preselection_capacity_ceiling: Bandwidth")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("reserved_path_limit: fresh.preselection_capacity_ceiling")
                .count(),
            1
        );
        for forbidden in [
            "CapacityEvidenceKind",
            "capacity_kind",
            "RelayPathReservation",
            "ExitCapacityHold",
            "Serialize",
            "Deserialize",
        ] {
            assert!(
                !product.contains(forbidden),
                "forbidden phase-A product token: {forbidden}"
            );
        }
        for forbidden in [
            "pub struct FreshPeerEvidence",
            "pub(crate) struct FreshPeerEvidence",
            "pub(super) struct FreshPeerEvidence",
            "pub struct FreshEvidenceBatch",
            "pub(crate) struct FreshEvidenceBatch",
            "pub(super) struct FreshEvidenceBatch",
            "impl From",
            "impl TryFrom",
        ] {
            assert!(
                !observation.contains(forbidden),
                "forbidden observation surface: {forbidden}"
            );
        }
        assert_eq!(observation.matches("struct FreshPeerEvidence {").count(), 1);
        assert_eq!(
            observation
                .matches("observed_network_prefix: Option<ObservedNetworkPrefix>,")
                .count(),
            1
        );
        assert!(!observation.contains("observed_network_origin:"));
        assert_eq!(product.matches("observed_network_origin: None").count(), 1);
        assert_eq!(product.matches("PrefixObservedCandidate::new(").count(), 5);
        assert_eq!(
            product
                .matches("RelaySelectionProjection::from_prefix_observed_candidate(")
                .count(),
            3
        );
        for (call, expected) in [
            ("select_exit_with_observed_prefixes(", 1),
            ("select_prospective_relays_with_observed_prefixes(", 1),
            ("select_projected_relay_paths(", 1),
        ] {
            assert_eq!(
                product.matches(call).count(),
                expected,
                "prefix call {call}"
            );
        }
        for forbidden in [
            "ObservedNetworkOrigin",
            "IpAddr",
            "enum ObservedNetworkPrefix",
            "struct ObservedNetworkPrefix",
            "ObservedNetworkPrefix::",
            ".ipv4_24()",
            ".ipv6_48()",
            "is_public_routable_ip(",
            "hard_filter(",
            "select_exit(",
            "select_prospective_relays(",
            "select_relay_paths(",
        ] {
            assert!(!product.contains(forbidden), "prefix product {forbidden}");
        }
        assert_eq!(
            product.matches("FreshPeerEvidence {").count(),
            3,
            "only declaration, redacted Debug and the sole production mint may open this type"
        );
        assert_eq!(
            product.matches("FreshEvidenceBatch {").count(),
            4,
            "only declaration, impl, exact production mint and one consuming destructure may open this type"
        );
        assert!(!observation.contains("\n    pub "));
    }

    fn assert_phase_a_batch_surface(product: &str, observation: &str) {
        let batch_declaration = observation
            .find("struct FreshEvidenceBatch")
            .expect("affine batch declaration");
        let batch_guard_start = observation
            .find("impl std::fmt::Debug for FreshPeerEvidence")
            .expect("preceding observation item");
        assert!(
            !observation[batch_guard_start..batch_declaration].contains("#[derive"),
            "the affine batch must not gain a derive before its documentation"
        );
        let batch_start = observation
            .find("/// Validated, bounded evidence owned")
            .expect("affine batch documentation");
        let batch = &observation[batch_start..];
        assert!(!batch.contains("#[derive"));
        assert!(!product.contains(" for FreshEvidenceBatch"));

        let batch_impl = observation
            .split("impl FreshEvidenceBatch {")
            .nth(1)
            .expect("fresh batch implementation");
        assert_eq!(batch_impl.matches("fn ").count(), 3);
        assert_eq!(
            batch_impl.matches("#[cfg(test)]\n    fn for_test(").count(),
            1
        );
        assert_eq!(batch_impl.matches("fn validate_at(").count(), 1);
        assert_eq!(batch_impl.matches("fn for_route_admission(").count(), 1);
        assert!(!batch_impl.contains("fn new("));
        assert!(!batch_impl.contains("\n    pub "));

        let prepared_start = product
            .find("/// Opaque, affine handoff from the discovery owner")
            .expect("prepared evidence documentation");
        let prepared_end = product[prepared_start..]
            .find("/// Terminal proof-to-evidence rejection")
            .map(|offset| prepared_start + offset)
            .expect("prepared evidence section end");
        let prepared = &product[prepared_start..prepared_end];
        assert!(prepared.contains("pub(crate) struct PreparedPreselectionEvidence {"));
        assert!(!prepared.contains("#[derive"));
        assert!(!prepared.contains("\n    pub"));
        assert!(!product.contains("impl PreparedPreselectionEvidence"));
        assert_eq!(
            product.matches("PreparedPreselectionEvidence {").count(),
            2,
            "only the declaration and exact proof-consumer may open the handoff"
        );
        assert_eq!(
            product
                .matches("prepare_preselection_evidence_at(completed, crate::unix_millis())")
                .count(),
            1,
            "the production handoff must obtain its trusted wall clock internally"
        );
        assert_eq!(
            product
                .matches("fn prepare_preselection_evidence_at(")
                .count(),
            1
        );
        assert!(!product.contains("pub(crate) fn prepare_preselection_evidence_at("));
    }

    fn assert_phase_a_planner_is_dormant(product: &str) {
        let planner_start = product
            .find("fn validate_fresh_evidence_batch(")
            .expect("phase-A observation validator");
        let planner_end = product[planner_start..]
            .find("fn validate_preprobe_peer_binding(")
            .map(|offset| planner_start + offset)
            .expect("phase-A planner end");
        let planner = &product[planner_start..planner_end];
        for forbidden in [
            "RouteSessionAuthority::generate(",
            "ReservationSession::generate(",
            "exit_forward(",
            "datapath_relay(",
            "bounded_call(",
        ] {
            assert!(
                !planner.contains(forbidden),
                "forbidden phase-A action: {forbidden}"
            );
        }
        let planner_definition = ["fn snapshot_route_", "plan<"].concat();
        let planner_call = ["snapshot_route_", "plan("].concat();
        assert_eq!(product.matches(&planner_definition).count(), 1);
        assert_eq!(product.matches(&planner_call).count(), 0);
    }

    #[test]
    fn phase_a_observation_surface_is_private_affine_and_non_authoritative() {
        let product = phase_a_product_source();
        let observation = phase_a_observation_source(product);
        assert_phase_a_observation_fields_and_tokens(product, observation);
        assert_phase_a_batch_surface(product, observation);
        assert_phase_a_planner_is_dormant(product);
    }

    #[test]
    fn forwarded_exit_evidence_requires_exact_control_tuple() {
        let (snapshot, evidence) = snapshot_fixture();
        assert!(
            snapshot_route_plan_at(
                &snapshot,
                snapshot_parameters(),
                fresh_batch(evidence.clone()),
                NOW_MS,
                &mut OsRng,
            )
            .is_ok()
        );

        for field in 0..4 {
            let mut substituted = evidence.clone();
            let control = substituted[1]
                .forwarded_control
                .as_mut()
                .expect("exit control binding");
            match field {
                0 => control.public_key[0] ^= 1,
                1 => control.advertisement_sequence += 1,
                2 => control.advertisement_expires_at_ms -= 1,
                _ => control.capability_expires_at_ms -= 1,
            }
            assert!(matches!(
                FreshEvidenceBatch::for_test(substituted, NOW_MS),
                Err(SelectionBridgeError::EvidenceBinding)
            ));
        }

        let mut another_relay = evidence.clone();
        another_relay[1].forwarded_control = Some(exact_control_binding(&another_relay[2]));
        let batch = fresh_batch(another_relay);
        assert!(matches!(
            snapshot_route_plan_at(&snapshot, snapshot_parameters(), batch, NOW_MS, &mut OsRng,),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn fresh_batch_valid_until_is_explicit_and_bounded() {
        let (_, evidence) = snapshot_fixture();
        let batch = FreshEvidenceBatch::for_test(evidence.clone(), NOW_MS)
            .expect("explicit valid-until batch");
        assert_eq!(
            batch.entries[0].valid_until_ms,
            NOW_MS + MAXIMUM_EVIDENCE_AGE_MS
        );

        let mut already_expired = evidence.clone();
        already_expired[0].valid_until_ms = NOW_MS;
        assert!(matches!(
            FreshEvidenceBatch::for_test(already_expired, NOW_MS),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let mut beyond_freshness = evidence.clone();
        beyond_freshness[0].valid_until_ms = NOW_MS + MAXIMUM_EVIDENCE_AGE_MS + 1;
        assert!(matches!(
            FreshEvidenceBatch::for_test(beyond_freshness, NOW_MS),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        for bound in 0..3 {
            let mut beyond_bound = bounded_fake_evidence(1);
            beyond_bound[0].valid_until_ms = NOW_MS + 11;
            match bound {
                0 => {
                    beyond_bound[0].policy_expires_at_ms = NOW_MS + 10;
                    beyond_bound[0].capability_expires_at_ms = NOW_MS + 10;
                }
                1 => {
                    beyond_bound[0].advertisement_expires_at_ms = NOW_MS + 10;
                    beyond_bound[0].capability_expires_at_ms = NOW_MS + 10;
                }
                _ => beyond_bound[0].capability_expires_at_ms = NOW_MS + 10,
            }
            assert!(matches!(
                FreshEvidenceBatch::for_test(beyond_bound, NOW_MS),
                Err(SelectionBridgeError::StaleEvidence)
            ));
        }
    }

    #[test]
    fn fresh_batch_rejects_missing_private_or_wrong_family_prefix() {
        let (_, evidence) = snapshot_fixture();
        assert!(FreshEvidenceBatch::for_test(evidence.clone(), NOW_MS).is_ok());

        let mut missing = evidence.clone();
        missing[0].observed_network_prefix = None;
        assert!(matches!(
            FreshEvidenceBatch::for_test(missing, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut private = evidence.clone();
        private[0].observed_network_prefix = Some(ObservedNetworkPrefix::ipv4_24([10, 0, 0]));
        assert!(matches!(
            FreshEvidenceBatch::for_test(private, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut wrong_family = evidence;
        assert_eq!(wrong_family[0].address_family, Some(IpFamily::Ipv4));
        wrong_family[0].observed_network_prefix = Some(ObservedNetworkPrefix::ipv6_48([
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00,
        ]));
        assert!(matches!(
            FreshEvidenceBatch::for_test(wrong_family, NOW_MS),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    type TestPreselectionFreshnessRecord = (
        usize,
        Option<usize>,
        PreselectionObservationRole,
        ObservedNetworkPrefix,
        u64,
        Duration,
        PreselectionTranscriptFreshnessFacts,
    );

    fn exact_preselection_freshness_records() -> Vec<TestPreselectionFreshnessRecord> {
        vec![
            (
                3,
                Some(0),
                PreselectionObservationRole::Exit,
                ObservedNetworkPrefix::ipv4_24([44, 1, 1]),
                NOW_MS + 100,
                Duration::from_millis(12),
                PreselectionTranscriptFreshnessFacts::Forwarded {
                    valid_until_ms: NOW_MS + 5_000,
                    upstream_network_prefix: ObservedNetworkPrefix::ipv4_24([45, 1, 1]),
                },
            ),
            (
                1,
                None,
                PreselectionObservationRole::Relay,
                ObservedNetworkPrefix::ipv4_24([46, 1, 1]),
                NOW_MS + 200,
                Duration::from_millis(8),
                PreselectionTranscriptFreshnessFacts::Direct {
                    valid_until_ms: NOW_MS + 6_000,
                },
            ),
            (
                2,
                None,
                PreselectionObservationRole::Relay,
                ObservedNetworkPrefix::ipv4_24([47, 2, 2]),
                NOW_MS + 300,
                Duration::from_millis(9),
                PreselectionTranscriptFreshnessFacts::Direct {
                    valid_until_ms: NOW_MS + 7_000,
                },
            ),
        ]
    }

    fn preselection_freshness_attempt(
        snapshot: RouteCandidateSnapshot,
        records: Vec<TestPreselectionFreshnessRecord>,
        transport: ProtocolTransport,
        family: ObservationAddressFamily,
        batch_id: [u8; ID_BYTES],
        ceiling: Bandwidth,
    ) -> CompletedPreselectionFreshnessAttempt {
        CompletedPreselectionFreshnessAttempt::for_test(
            snapshot,
            transport,
            family,
            batch_id,
            NOW_MS,
            NOW_MS + 30_000,
            Bandwidth::new(10, 10).expect("minimum capacity"),
            ceiling,
            records,
        )
    }

    fn assert_first_native_permit_dispatch(
        owner: &mut native_preselection::NativePreselectionAttemptOwner,
        candidate_set: &volparossa_protocol::NativeProbeCandidateSet,
        minted_at_ms: u64,
        minted_at: Instant,
        expected_expiry: u64,
    ) {
        let awaiting = owner
            .begin_next_for_test(minted_at_ms + 1, minted_at + Duration::from_millis(1))
            .expect("live first candidate")
            .expect("first candidate exists");
        let dispatch = awaiting
            .into_forward_dispatch()
            .expect("exact client-hop wrapper");
        let (control_peer, request) = dispatch.request_for_test();
        let control = candidate_set.control.as_ref().expect("control actor");
        let exit = candidate_set.exit.as_ref().expect("Exit actor");
        assert_eq!(control_peer.to_bytes(), control.peer_id);
        assert_eq!(request.control_relay_node_id(), control.node_id);
        assert_eq!(request.control_relay_peer_id(), control.peer_id);
        assert_eq!(request.control_relay_public_key(), control.public_key);
        assert_eq!(request.exit_node_id(), exit.node_id);
        assert_eq!(request.exit_peer_id(), exit.peer_id);
        assert_ne!(request.control_relay_peer_id(), request.exit_peer_id());
        assert_eq!(
            request.validated_operation().expect("native operation"),
            volparossa_discovery::ExitForwardOperation::NativeProbePermit
        );
        assert_eq!(request.deadline_unix_ms(), expected_expiry);
        let envelope: SignedEnvelope =
            decode_canonical(request.canonical_request(), MAX_CONTROL_MESSAGE_SIZE)
                .expect("signed native Permit request");
        assert_eq!(request.forward_id(), &envelope.nonce[..ID_BYTES]);
    }

    #[test]
    fn exact_preselection_proofs_mint_conservative_affine_fresh_batch() {
        let (snapshot, _) = snapshot_fixture();
        let completed = preselection_freshness_attempt(
            snapshot,
            exact_preselection_freshness_records(),
            ProtocolTransport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
            EVIDENCE_BATCH_BYTES,
            Bandwidth::new(80, 80).expect("configured ceiling"),
        );
        let Ok(JoinedPreselectionFreshEvidence {
            snapshot,
            evidence_batch,
            gate,
        }) = join_preselection_fresh_evidence_at(completed, NOW_MS + 500)
        else {
            panic!("exact A1 proofs must mint fresh evidence");
        };
        assert_ne!(size_of_val(&gate), 0);
        assert_eq!(
            evidence_batch.batch_id,
            EvidenceBatchId::for_test(EVIDENCE_BATCH_BYTES)
        );
        assert_eq!(evidence_batch.entries.len(), 4);
        for evidence in &evidence_batch.entries {
            assert_eq!(evidence.transport, SelectionTransport::TcpMptcp);
            assert_eq!(evidence.address_family, Some(IpFamily::Ipv4));
            assert_eq!(evidence.locally_measured_p25, None);
            assert_eq!(evidence.measurement_count, 1);
            assert_eq!(evidence.uptime_score.to_bits(), 1.0_f64.to_bits());
            assert_eq!(evidence.proximity_score.to_bits(), 0.0_f64.to_bits());
            assert_eq!(evidence.recent_egress_quality.to_bits(), 0.0_f64.to_bits());
            assert!(evidence.reachable);
            assert!(evidence.rtt_ms.is_some_and(|rtt| rtt > 0.0));
            assert!(!evidence.network_address_usable);
            assert!(!evidence.locally_blocked);
        }
        assert!(
            evidence_batch.entries[0].observed_network_prefix
                == Some(ObservedNetworkPrefix::ipv4_24([44, 1, 1]))
        );
        assert_eq!(
            evidence_batch.entries[0].rtt_ms.map(f64::to_bits),
            Some(12.0_f64.to_bits())
        );
        assert_eq!(evidence_batch.entries[0].valid_until_ms, NOW_MS + 5_000);
        assert!(
            evidence_batch.entries[1].observed_network_prefix
                == Some(ObservedNetworkPrefix::ipv4_24([46, 1, 1]))
        );
        assert_eq!(
            evidence_batch.entries[1].rtt_ms.map(f64::to_bits),
            Some(8.0_f64.to_bits())
        );
        assert_eq!(evidence_batch.entries[1].valid_until_ms, NOW_MS + 6_000);
        assert!(
            evidence_batch.entries[2].observed_network_prefix
                == Some(ObservedNetworkPrefix::ipv4_24([47, 2, 2]))
        );
        assert_eq!(
            evidence_batch.entries[2].rtt_ms.map(f64::to_bits),
            Some(9.0_f64.to_bits())
        );
        assert_eq!(evidence_batch.entries[2].valid_until_ms, NOW_MS + 7_000);
        let exit = &evidence_batch.entries[3];
        assert_eq!(exit.role, ServiceRole::Exit);
        assert!(exit.observed_network_prefix == Some(ObservedNetworkPrefix::ipv4_24([45, 1, 1])));
        assert_eq!(exit.rtt_ms.map(f64::to_bits), Some(12.0_f64.to_bits()));
        assert_eq!(exit.valid_until_ms, NOW_MS + 5_000);
        let control = exit.forwarded_control.as_ref().expect("exact control");
        assert_eq!(control.node_id, evidence_batch.entries[0].node_id);
        assert_eq!(control.peer_id, evidence_batch.entries[0].peer_id);
        assert_eq!(
            control.advertisement_payload_hash,
            evidence_batch.entries[0].advertisement_payload_hash
        );

        assert!(matches!(
            snapshot_route_plan_at(
                &snapshot,
                snapshot_parameters(),
                evidence_batch,
                NOW_MS + 500,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::UnusableNetworkAddress
            )))
        ));
    }

    #[test]
    fn prepared_preselection_handoff_retains_only_private_evidence_and_cooldown() {
        let (snapshot, _) = snapshot_fixture();
        let completed = preselection_freshness_attempt(
            snapshot,
            exact_preselection_freshness_records(),
            ProtocolTransport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
            EVIDENCE_BATCH_BYTES,
            Bandwidth::new(80, 80).expect("configured ceiling"),
        );
        let Ok((prepared, gate)) = prepare_preselection_evidence_at(completed, NOW_MS + 500) else {
            panic!("exact A1 proofs must prepare opaque evidence");
        };
        assert_ne!(size_of_val(&gate), 0);
        assert_ne!(size_of_val(&prepared.snapshot), 0);
        assert_eq!(prepared.evidence_batch.entries.len(), 4);
        assert!(
            prepared
                .evidence_batch
                .entries
                .iter()
                .all(|evidence| !evidence.network_address_usable)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one affine-owner regression audits every queued candidate and expiry boundary"
    )]
    fn native_owner_consumes_live_a1_receipts_then_mints_an_independent_bounded_attempt() {
        let (snapshot, _) = snapshot_fixture();
        let completed = preselection_freshness_attempt(
            snapshot,
            exact_preselection_freshness_records(),
            ProtocolTransport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
            EVIDENCE_BATCH_BYTES,
            Bandwidth::new(80, 80).expect("configured ceiling"),
        );
        let Ok((prepared, _gate)) = prepare_preselection_evidence_at(completed, NOW_MS + 500)
        else {
            panic!("exact A1 proofs must prepare opaque evidence");
        };
        let minted_at_ms = NOW_MS + 4_999;
        let minted_at = Instant::now();
        let mut owner = native_preselection::begin_native_preselection_for_test(
            prepared,
            2,
            minted_at_ms,
            minted_at,
        )
        .expect("live handoff must mint native owner");
        let candidate_set = owner.candidate_set_for_test().clone();
        assert_eq!(candidate_set.preselection_batch_id, EVIDENCE_BATCH_BYTES);
        assert_eq!(candidate_set.data_relays.len(), 2);
        assert!(
            candidate_set
                .data_relays
                .iter()
                .all(|relay| Some(relay) != candidate_set.control.as_ref())
        );
        assert_eq!(candidate_set.transport, ProtocolTransport::TcpMptcp as i32);
        assert_eq!(
            candidate_set.address_family,
            ObservationAddressFamily::Ipv4 as i32
        );
        assert_eq!(candidate_set.policy_version, 7);
        assert_eq!(candidate_set.policy_hash, POLICY_BYTES);

        let expected_expiry = minted_at_ms + volparossa_protocol::MAX_NATIVE_PROBE_LIFETIME_MS;
        let (attempt_expiry, monotonic_expiry) = owner.deadline_for_test();
        assert_eq!(attempt_expiry, expected_expiry);
        assert_eq!(
            monotonic_expiry.duration_since(minted_at),
            Duration::from_millis(volparossa_protocol::MAX_NATIVE_PROBE_LIFETIME_MS)
        );
        assert!(
            attempt_expiry > NOW_MS + 5_000,
            "the new attempt must not pretend that the five-second A1 receipt stayed live"
        );

        let mut probe_ids = HashSet::new();
        let mut session_ids = HashSet::new();
        for (index, pending) in owner.pending_for_test().iter().enumerate() {
            let (ordinal, relay, exit, ceiling, encoded_request) = pending.candidate_for_test();
            assert_eq!(ordinal, u32::try_from(index + 1).expect("bounded ordinal"));
            assert_eq!(relay, &candidate_set.data_relays[index]);
            assert_eq!(Some(exit), candidate_set.exit.as_ref());
            assert_eq!(ceiling, Bandwidth::new(80, 80).expect("ceiling"));
            let envelope: SignedEnvelope =
                decode_canonical(encoded_request, MAX_CONTROL_MESSAGE_SIZE).expect("request");
            let request: volparossa_protocol::NativeProbePermitRequest = decode_canonical(
                &envelope.payload,
                volparossa_protocol::MAX_CONTROL_PAYLOAD_SIZE,
            )
            .expect("permit request payload");
            let scope = request.scope.expect("path scope");
            assert_eq!(scope.candidate_ordinal, ordinal);
            assert_eq!(scope.attempt_expires_at_ms, expected_expiry);
            assert_eq!(request.expires_at_ms, expected_expiry);
            assert!(probe_ids.insert(scope.probe_id));
            assert!(session_ids.insert(scope.client_session_id));
        }

        assert_first_native_permit_dispatch(
            &mut owner,
            &candidate_set,
            minted_at_ms,
            minted_at,
            expected_expiry,
        );
        for expected_ordinal in 2_u32..=2 {
            let awaiting = owner
                .begin_next_for_test(minted_at_ms + 1, minted_at + Duration::from_millis(1))
                .expect("live next candidate")
                .expect("required candidate exists");
            let dispatch = awaiting
                .into_forward_dispatch()
                .expect("exact client-hop wrapper");
            let (control_peer, request) = dispatch.request_for_test();
            let envelope: SignedEnvelope =
                decode_canonical(request.canonical_request(), MAX_CONTROL_MESSAGE_SIZE)
                    .expect("signed native Permit request");
            let request: volparossa_protocol::NativeProbePermitRequest = decode_canonical(
                &envelope.payload,
                volparossa_protocol::MAX_CONTROL_PAYLOAD_SIZE,
            )
            .expect("permit request payload");
            let scope = request.scope.expect("path scope");
            assert_eq!(scope.candidate_ordinal, expected_ordinal);
            assert_eq!(
                scope.data_relay.as_ref(),
                candidate_set
                    .data_relays
                    .get(usize::try_from(expected_ordinal - 1).expect("bounded ordinal"))
            );
            assert_eq!(scope.control, candidate_set.control);
            assert_eq!(scope.exit, candidate_set.exit);
            assert_eq!(
                control_peer.to_bytes(),
                candidate_set.control.as_ref().expect("control").peer_id
            );
        }
        assert!(
            owner
                .begin_next_for_test(minted_at_ms + 1, minted_at + Duration::from_millis(1))
                .expect("live exhausted owner")
                .is_none(),
            "every candidate must be consumed exactly once"
        );

        let (snapshot, _) = snapshot_fixture();
        let completed = preselection_freshness_attempt(
            snapshot,
            exact_preselection_freshness_records(),
            ProtocolTransport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
            EVIDENCE_BATCH_BYTES,
            Bandwidth::new(80, 80).expect("configured ceiling"),
        );
        let Ok((expired, _gate)) = prepare_preselection_evidence_at(completed, NOW_MS + 500) else {
            panic!("exact A1 proofs must prepare another opaque handoff");
        };
        assert!(matches!(
            native_preselection::begin_native_preselection_for_test(
                expired,
                2,
                NOW_MS + 5_000,
                Instant::now(),
            ),
            Err(native_preselection::NativePreselectionError::InvalidPreparedEvidence)
        ));
    }

    #[test]
    fn preselection_fresh_join_rejects_every_shape_family_time_and_capacity_substitution() {
        for case in 0_u8..14 {
            let (snapshot, _) = snapshot_fixture();
            let mut records = exact_preselection_freshness_records();
            let mut transport = ProtocolTransport::TcpMptcp;
            let mut family = ObservationAddressFamily::Ipv4;
            let mut batch_id = EVIDENCE_BATCH_BYTES;
            let mut ceiling = Bandwidth::new(80, 80).expect("configured ceiling");
            let mut trusted_now_ms = NOW_MS + 500;
            match case {
                0 => {
                    records.pop();
                }
                1 => records[1].0 = 2,
                2 => records[0].1 = Some(1),
                3 => records[1].2 = PreselectionObservationRole::Exit,
                4 => {
                    records[1].6 = PreselectionTranscriptFreshnessFacts::Forwarded {
                        valid_until_ms: NOW_MS + 6_000,
                        upstream_network_prefix: ObservedNetworkPrefix::ipv4_24([46, 1, 1]),
                    };
                }
                5 => records[1].3 = ObservedNetworkPrefix::ipv6_48([0x26, 6, 7, 8, 9, 10]),
                6 => {
                    records[0].6 = PreselectionTranscriptFreshnessFacts::Forwarded {
                        valid_until_ms: NOW_MS + 5_000,
                        upstream_network_prefix: ObservedNetworkPrefix::ipv6_48([
                            0x26, 6, 7, 8, 9, 10,
                        ]),
                    };
                }
                7 => records[1].4 = NOW_MS - 1,
                8 => records[1].4 = NOW_MS + 30_000,
                9 => records[1].5 = Duration::ZERO,
                10 => {
                    records[1].6 = PreselectionTranscriptFreshnessFacts::Direct {
                        valid_until_ms: trusted_now_ms,
                    };
                }
                11 => transport = ProtocolTransport::Unspecified,
                12 => family = ObservationAddressFamily::Unspecified,
                _ => {
                    batch_id = [0; ID_BYTES];
                    ceiling = Bandwidth::new(5, 5).expect("insufficient ceiling");
                    trusted_now_ms = NOW_MS + 30_000;
                }
            }
            let completed = preselection_freshness_attempt(
                snapshot, records, transport, family, batch_id, ceiling,
            );
            let failure = match join_preselection_fresh_evidence_at(completed, trusted_now_ms) {
                Ok(_) => panic!("substitution case {case} minted fresh evidence"),
                Err(failure) => failure,
            };
            assert_ne!(size_of_val(&failure.gate), 0);
            assert!(matches!(
                failure.error,
                SelectionBridgeError::EvidenceBinding | SelectionBridgeError::StaleEvidence
            ));
        }
    }

    fn bounded_fake_evidence(count: usize) -> Vec<FreshPeerEvidence> {
        let (_, fixture) = snapshot_fixture();
        (0..count)
            .map(|index| {
                let mut fresh = fixture[0].clone();
                fresh.node_id =
                    NodeId::new(format!("bounded-node-{index}")).expect("bounded fake node id");
                fresh.peer_id =
                    PeerId::new(format!("bounded-peer-{index}")).expect("bounded fake peer id");
                fresh.capability_public_key =
                    [u8::try_from(index % 255 + 1).expect("nonzero bounded key byte"); 32];
                fresh.advertisement_sequence = u64::try_from(index + 1).expect("bounded sequence");
                fresh
            })
            .collect()
    }

    #[test]
    fn phase_one_accepts_exactly_200_and_rejects_201() {
        assert!(FreshEvidenceBatch::for_test(bounded_fake_evidence(200), NOW_MS).is_ok());
        assert!(matches!(
            FreshEvidenceBatch::for_test(bounded_fake_evidence(201), NOW_MS),
            Err(SelectionBridgeError::TooManyCandidates)
        ));

        let (snapshot, evidence) = snapshot_fixture();
        let mut exact_direct = snapshot.direct_relays().to_vec();
        let exact_forwarded = snapshot.forwarded_exits().to_vec();
        let mut exact_evidence = evidence.clone();
        for index in 3_u8..=198 {
            let address = Ipv4Addr::new(60, index, 1, 1);
            let (relay, fresh) = snapshot_direct_candidate(
                &signed_peer(
                    index,
                    true,
                    false,
                    &format!("operator-bounded-{index}"),
                    65_000 + u32::from(index),
                    address,
                    POLICY_BYTES,
                    NOW_MS + 120_000,
                ),
                address,
            );
            exact_direct.push(relay);
            exact_evidence.push(fresh);
        }
        assert_eq!(exact_direct.len(), 199);
        assert_eq!(exact_evidence.len(), 200);
        let exact_snapshot = RouteCandidateSnapshot::for_test(
            NOW_MS,
            RouteCandidatePolicySnapshot::for_test(7, POLICY_BYTES, NOW_MS + 90_000),
            exact_direct,
            exact_forwarded,
        );
        let exact_plan = snapshot_route_plan_at(
            &exact_snapshot,
            snapshot_parameters(),
            fresh_batch(exact_evidence),
            NOW_MS,
            &mut OsRng,
        )
        .expect("exactly 200 phase-one records");
        assert_eq!(
            exact_plan.prospective_relays.len(),
            MAXIMUM_PROSPECTIVE_RELAYS
        );

        let oversized_snapshot = RouteCandidateSnapshot::for_test(
            NOW_MS,
            RouteCandidatePolicySnapshot::for_test(7, POLICY_BYTES, NOW_MS + 90_000),
            vec![snapshot.direct_relays()[0].clone(); 201],
            snapshot.forwarded_exits().to_vec(),
        );
        assert!(matches!(
            snapshot_route_plan_at(
                &oversized_snapshot,
                snapshot_parameters(),
                fresh_batch(evidence),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::TooManyCandidates)
        ));

        let oversized_exits = RouteCandidateSnapshot::for_test(
            NOW_MS,
            RouteCandidatePolicySnapshot::for_test(7, POLICY_BYTES, NOW_MS + 90_000),
            snapshot.direct_relays().to_vec(),
            vec![snapshot.forwarded_exits()[0].clone(); 201],
        );
        assert!(matches!(
            snapshot_route_plan_at(
                &oversized_exits,
                snapshot_parameters(),
                fresh_batch(snapshot_fixture().1),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::TooManyCandidates)
        ));
    }

    #[test]
    fn prospective_route_plan_binds_batch_exit_policy_and_at_most_eight_relays() {
        let (snapshot, mut evidence) = snapshot_fixture();
        evidence[2].valid_until_ms = NOW_MS + 30_000;
        let expected_exit = evidence[1].node_id.clone();
        let expected_control = evidence[0].node_id.clone();
        let plan = snapshot_route_plan_at(
            &snapshot,
            snapshot_parameters(),
            fresh_batch(evidence),
            NOW_MS,
            &mut OsRng,
        )
        .expect("bound prospective route plan");

        assert_eq!(
            plan.batch_id,
            EvidenceBatchId::for_test(EVIDENCE_BATCH_BYTES)
        );
        assert_eq!(plan.selected_at_ms, NOW_MS);
        assert_eq!(
            plan.forwarded_exit
                .exit
                .identity
                .selection_node_id()
                .expect("exit node id"),
            expected_exit
        );
        assert_eq!(
            plan.forwarded_exit
                .control
                .identity
                .selection_node_id()
                .expect("control node id"),
            expected_control
        );
        assert_eq!(plan.scope.policy.version, 7);
        assert_eq!(plan.scope.policy.hash, PolicyHash::from_bytes(POLICY_BYTES));
        assert_eq!(plan.scope.policy.expires_at_ms, NOW_MS + 90_000);
        assert!((1..=MAXIMUM_PROSPECTIVE_RELAYS).contains(&plan.prospective_relays.len()));
        assert_eq!(plan.prospective_relays.len(), 2);
        assert_eq!(plan.earliest_evidence_expiry_ms, NOW_MS + 30_000);
        assert_eq!(
            plan.forwarded_exit.control.evidence_valid_until_ms,
            NOW_MS + MAXIMUM_EVIDENCE_AGE_MS
        );
        assert_eq!(
            plan.forwarded_exit.exit.evidence_valid_until_ms,
            NOW_MS + MAXIMUM_EVIDENCE_AGE_MS
        );
        assert!(plan.prospective_relays.iter().all(|relay| {
            relay.relay.identity.wire_node_id != plan.forwarded_exit.control.identity.wire_node_id
                && relay.relay.identity.wire_node_id
                    != plan.forwarded_exit.exit.identity.wire_node_id
                && relay.relay.identity.advertisement_sequence > 0
                && relay
                    .relay
                    .identity
                    .public_key
                    .iter()
                    .any(|byte| *byte != 0)
                && relay.peer_evidence.observed_network_origin.is_none()
                && relay.diversity.observed_network_prefix.is_public_routable()
        }));
    }

    #[test]
    fn prospective_route_plan_preserves_actor_specific_evidence_windows() {
        let (snapshot, mut evidence) = snapshot_fixture();
        evidence[0].valid_until_ms = NOW_MS + 40_000;
        evidence[1].valid_until_ms = NOW_MS + 50_000;
        let plan = snapshot_route_plan_at(
            &snapshot,
            snapshot_parameters(),
            fresh_batch(evidence),
            NOW_MS,
            &mut OsRng,
        )
        .expect("actor-specific evidence windows");
        assert_eq!(
            plan.forwarded_exit.control.evidence_valid_until_ms,
            NOW_MS + 40_000
        );
        assert_eq!(
            plan.forwarded_exit.exit.evidence_valid_until_ms,
            NOW_MS + 50_000
        );
        assert_eq!(plan.earliest_evidence_expiry_ms, NOW_MS + 40_000);
    }

    fn prospective_plan() -> ProspectiveRoutePlan {
        let (snapshot, evidence) = snapshot_fixture();
        snapshot_route_plan_at(
            &snapshot,
            snapshot_parameters(),
            fresh_batch(evidence),
            NOW_MS,
            &mut OsRng,
        )
        .expect("prospective plan")
    }

    fn prospective_control_binding_fixture() -> (
        SelectedExit,
        Vec<VerifiedSelectionPeer<ProspectiveDirectRelay>>,
        [DiversityAnchor; 2],
    ) {
        let (snapshot, evidence) = snapshot_fixture();
        let scope =
            scope_from_snapshot(&snapshot, snapshot_parameters(), NOW_MS).expect("selection scope");
        let exits = snapshot
            .forwarded_exits()
            .iter()
            .map(|candidate| forwarded_snapshot_input(candidate, &evidence))
            .collect::<Result<Vec<_>, _>>()
            .expect("forwarded exits");
        let selected =
            select_exit_first(scope, &exits, &mut OsRng).expect("selected forwarded exit");
        let verified = verify_prospective_relay_candidates(&snapshot, &evidence, &selected.scope)
            .expect("verified relays");
        let anchors = prospective_diversity_anchors(&selected).expect("diversity anchors");
        (selected, verified, anchors)
    }

    #[test]
    fn prospective_forwarded_control_requires_one_exact_verified_record() {
        for mutation in 0_u8..9 {
            let (selected, mut verified, anchors) = prospective_control_binding_fixture();
            let control = &selected.forwarded_exit.authority.control.identity;
            let record = verified
                .iter_mut()
                .find(|record| {
                    record.prospective.identity.wire_node_id == control.wire_node_id
                        && record.prospective.identity.peer_id == control.peer_id
                })
                .expect("exact control record");
            match mutation {
                0 => record.prospective.identity.advertisement_sequence += 1,
                1 => record.prospective.identity.advertisement_expires_at_ms -= 1,
                2 => record.prospective.identity.expires_at_ms -= 1,
                3 => record.prospective.identity.policy_version += 1,
                4 => record.prospective.identity.public_key[0] ^= 1,
                5 => record.diversity = selected.forwarded_exit.exit_diversity.clone(),
                6 => record.evidence_batch_id.0[0] ^= 1,
                7 => {
                    record.advertisement_payload_hash =
                        record.advertisement_payload_hash.xor_for_test();
                }
                8 => {
                    record.prospective.identity.advertisement_payload_hash = record
                        .prospective
                        .identity
                        .advertisement_payload_hash
                        .xor_for_test();
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                prospective_forwarded_exit_binding(&selected, &verified, &anchors[0]),
                Err(SelectionBridgeError::SelectedIdentityMismatch)
            ));
        }

        let (selected, mut verified, anchors) = prospective_control_binding_fixture();
        let control = &selected.forwarded_exit.authority.control.identity;
        let source = verified
            .iter()
            .find(|record| {
                record.prospective.identity.wire_node_id == control.wire_node_id
                    && record.prospective.identity.peer_id == control.peer_id
            })
            .expect("duplicate control record");
        let duplicate = VerifiedSelectionPeer {
            evidence_batch_id: source.evidence_batch_id,
            candidate: source.candidate.clone(),
            prospective: source.prospective.clone(),
            diversity: source.diversity.clone(),
            advertisement_sequence: source.advertisement_sequence,
            advertisement_measured_at_ms: source.advertisement_measured_at_ms,
            advertisement_expires_at_ms: source.advertisement_expires_at_ms,
            advertisement_payload_hash: source.advertisement_payload_hash,
            actor_evidence_observed_at_ms: source.actor_evidence_observed_at_ms,
            actor_evidence_valid_until_ms: source.actor_evidence_valid_until_ms,
            forwarded_control_evidence_valid_until_ms: source
                .forwarded_control_evidence_valid_until_ms,
            evidence_valid_until_ms: source.evidence_valid_until_ms,
        };
        verified.push(duplicate);
        assert!(matches!(
            prospective_forwarded_exit_binding(&selected, &verified, &anchors[0]),
            Err(SelectionBridgeError::SelectedIdentityMismatch)
        ));
    }

    fn preprobe_limits() -> RouteSetupLimits {
        RouteSetupLimits::new(Duration::from_secs(30), Duration::from_secs(5), 2)
            .expect("preprobe limits")
    }

    #[derive(Clone)]
    struct HandoffClock {
        now_ms: Arc<AtomicU64>,
        reads: Arc<AtomicUsize>,
        cancel_on_read: Arc<AtomicUsize>,
        cancellation: Arc<Mutex<Option<watch::Sender<bool>>>>,
    }

    impl HandoffClock {
        fn new(now_ms: u64) -> Self {
            Self {
                now_ms: Arc::new(AtomicU64::new(now_ms)),
                reads: Arc::new(AtomicUsize::new(0)),
                cancel_on_read: Arc::new(AtomicUsize::new(0)),
                cancellation: Arc::new(Mutex::new(None)),
            }
        }

        fn set(&self, now_ms: u64) {
            self.now_ms.store(now_ms, Ordering::SeqCst);
        }

        fn cancel_on_read(&self, read: usize, cancellation: watch::Sender<bool>) {
            self.cancel_on_read.store(read, Ordering::SeqCst);
            *self.cancellation.lock().expect("handoff cancellation") = Some(cancellation);
        }
    }

    impl RouteSetupClock for HandoffClock {
        fn unix_millis(&self) -> u64 {
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            if self.cancel_on_read.load(Ordering::SeqCst) == read {
                if let Some(cancellation) = self
                    .cancellation
                    .lock()
                    .expect("handoff cancellation")
                    .as_ref()
                {
                    let _ = cancellation.send(true);
                }
            }
            self.now_ms.load(Ordering::SeqCst)
        }
    }

    struct HandoffState {
        calls: Mutex<Vec<&'static str>>,
        resolved_direct_nodes: Mutex<Vec<[u8; 32]>>,
        gate_call: AtomicUsize,
        resolve_started: Notify,
        resolve_release: Notify,
        resolve_dropped: Notify,
        pending_resolve_drops: AtomicUsize,
        post_resolve_wall_ms: AtomicU64,
        transport_calls: AtomicUsize,
        total_resolves: usize,
    }

    struct PendingResolveDrop<'a> {
        drops: &'a AtomicUsize,
        dropped: &'a Notify,
    }

    impl Drop for PendingResolveDrop<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            self.dropped.notify_one();
        }
    }

    struct HandoffIo {
        control: DirectRelayCapability,
        exit: ForwardedExitCapability,
        relays: Vec<DirectRelayCapability>,
        clock: HandoffClock,
        state: Arc<HandoffState>,
    }

    impl HandoffIo {
        fn from_plan(plan: &ProspectiveRoutePlan, clock: HandoffClock) -> Self {
            let selected = &plan.forwarded_exit.selected.authority;
            let control = prospective_direct_capability(&selected.control.identity);
            let exit_identity = &selected.exit;
            let exit = ForwardedExitCapability {
                control_relay_node_id: control.node_id,
                control_relay_peer_id: control.peer_id,
                control_relay_public_key: control.public_key,
                control_relay_advertisement_sequence: control.advertisement_sequence,
                control_relay_advertisement_expires_at_ms: control.advertisement_expires_at_ms,
                control_relay_advertisement_payload_hash: control.advertisement_payload_hash,
                exit_node_id: exit_identity.wire_node_id,
                exit_peer_id: exit_identity.peer_id,
                exit_public_key: exit_identity.public_key,
                exit_advertisement_sequence: exit_identity.advertisement_sequence,
                exit_advertisement_expires_at_ms: exit_identity.advertisement_expires_at_ms,
                exit_advertisement_payload_hash: exit_identity.advertisement_payload_hash,
                policy_version: exit_identity.policy_version,
                policy_hash: exit_identity.policy_hash,
                policy_expires_at_ms: exit_identity.policy_expires_at_ms,
                expires_at_ms: exit_identity.expires_at_ms,
            };
            let relays = plan
                .prospective_relays
                .iter()
                .map(|relay| prospective_direct_capability(&relay.relay.identity))
                .collect::<Vec<_>>();
            let state = Arc::new(HandoffState {
                calls: Mutex::new(Vec::new()),
                resolved_direct_nodes: Mutex::new(Vec::new()),
                gate_call: AtomicUsize::new(0),
                resolve_started: Notify::new(),
                resolve_release: Notify::new(),
                resolve_dropped: Notify::new(),
                pending_resolve_drops: AtomicUsize::new(0),
                post_resolve_wall_ms: AtomicU64::new(0),
                transport_calls: AtomicUsize::new(0),
                total_resolves: relays.len().saturating_add(2),
            });
            Self {
                control,
                exit,
                relays,
                clock,
                state,
            }
        }

        async fn before_resolve(&self, label: &'static str) {
            let call = {
                let mut calls = self.state.calls.lock().expect("handoff calls");
                calls.push(label);
                calls.len()
            };
            if self.state.gate_call.load(Ordering::SeqCst) == call {
                let _pending_drop = PendingResolveDrop {
                    drops: &self.state.pending_resolve_drops,
                    dropped: &self.state.resolve_dropped,
                };
                self.state.resolve_started.notify_one();
                self.state.resolve_release.notified().await;
            }
            let post_wall_ms = self.state.post_resolve_wall_ms.load(Ordering::SeqCst);
            if call == self.state.total_resolves && post_wall_ms != 0 {
                self.clock.set(post_wall_ms);
            }
        }
    }

    fn prospective_direct_capability(identity: &ProspectivePeerIdentity) -> DirectRelayCapability {
        DirectRelayCapability {
            node_id: identity.wire_node_id,
            peer_id: identity.peer_id,
            public_key: identity.public_key,
            advertisement_sequence: identity.advertisement_sequence,
            advertisement_expires_at_ms: identity.advertisement_expires_at_ms,
            advertisement_payload_hash: identity.advertisement_payload_hash,
            policy_version: identity.policy_version,
            policy_hash: identity.policy_hash,
            policy_expires_at_ms: identity.policy_expires_at_ms,
            expires_at_ms: identity.expires_at_ms,
        }
    }

    impl RouteCapabilityResolver for HandoffIo {
        async fn resolve_direct_relay(
            &self,
            expected_node_id: [u8; 32],
            expected_peer_id: Libp2pPeerId,
        ) -> Result<DirectRelayCapability, RouteSetupError> {
            self.state
                .resolved_direct_nodes
                .lock()
                .expect("resolved direct nodes")
                .push(expected_node_id);
            let is_control = self.control.node_id == expected_node_id
                && self.control.peer_id == expected_peer_id;
            self.before_resolve(if is_control {
                "resolve.control"
            } else {
                "resolve.relay"
            })
            .await;
            if is_control {
                return Ok(self.control.clone());
            }
            self.relays
                .iter()
                .find(|relay| {
                    relay.node_id == expected_node_id && relay.peer_id == expected_peer_id
                })
                .cloned()
                .ok_or(RouteSetupError::Capability)
        }

        async fn resolve_forwarded_exit(
            &self,
            control_relay_node_id: [u8; 32],
            control_relay_peer_id: Libp2pPeerId,
            exit_node_id: [u8; 32],
            exit_peer_id: Libp2pPeerId,
        ) -> Result<ForwardedExitCapability, RouteSetupError> {
            self.before_resolve("resolve.exit").await;
            if self.exit.control_relay_node_id != control_relay_node_id
                || self.exit.control_relay_peer_id != control_relay_peer_id
                || self.exit.exit_node_id != exit_node_id
                || self.exit.exit_peer_id != exit_peer_id
            {
                return Err(RouteSetupError::Capability);
            }
            Ok(self.exit.clone())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct HandoffTransportError;

    impl ReservationTransport for HandoffIo {
        type Error = HandoffTransportError;

        fn ambiguous_after_dispatch(_error: &Self::Error) -> bool {
            false
        }

        async fn exit_forward<'a>(
            &'a mut self,
            _control: &'a DirectRelayCapability,
            _request: &'a ExitForwardRequest,
        ) -> Result<ExitForwardResponse, Self::Error> {
            self.state.transport_calls.fetch_add(1, Ordering::SeqCst);
            Err(HandoffTransportError)
        }

        async fn datapath_relay<'a>(
            &'a mut self,
            _relay: &'a DirectRelayCapability,
            _request: &'a super::super::DatapathRelayRequest,
        ) -> Result<super::super::DatapathRelayResponse, Self::Error> {
            self.state.transport_calls.fetch_add(1, Ordering::SeqCst);
            Err(HandoffTransportError)
        }
    }

    #[derive(Clone)]
    struct NoopHandoffLocal {
        calls: Arc<AtomicUsize>,
    }

    #[derive(Clone, Copy, Debug)]
    struct NoopHandoffLocalError;

    impl LocalRouteBackend for NoopHandoffLocal {
        type Error = NoopHandoffLocalError;

        async fn prepare(
            &mut self,
            _request: &PrepareLeaseBatch,
        ) -> Result<RuntimeBoundPreparedLeaseBatch, LocalPrepareFailure<Self::Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(LocalPrepareFailure::Definitive(NoopHandoffLocalError))
        }

        async fn activate(
            &mut self,
            _owner: &mut RuntimeBoundPreparedLeaseBatch,
            _request: &ActivateLeaseBatch,
        ) -> Result<ActivatedLeaseBatch, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(NoopHandoffLocalError)
        }

        async fn commit(
            &mut self,
            _owner: &mut RuntimeBoundPreparedLeaseBatch,
            _request: &CommitLeaseBatch,
        ) -> Result<CommittedLeaseBatch, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(NoopHandoffLocalError)
        }

        async fn destroy(
            &mut self,
            _owner: &RuntimeBoundPreparedLeaseBatch,
        ) -> Result<DestroyedContext, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(NoopHandoffLocalError)
        }

        async fn reconcile_expired_prepare(
            &mut self,
            _authority: &PrepareReconciliationAuthority,
        ) -> Result<ReconciledExpiredPrepare, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(NoopHandoffLocalError)
        }
    }

    fn handoff_manager(
        calls: Arc<AtomicUsize>,
    ) -> RouteSetupManager<ReservationSession, NoopHandoffLocal> {
        RouteSetupManager::start(
            NoopHandoffLocal { calls },
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("handoff manager")
    }

    fn assert_before_dispatch_failure(failure: &RouteSetupFailure) {
        assert_eq!(failure.cleanup, CleanupStatus::NotRequired);
        assert_eq!(failure.released_local_leases, 0);
        assert!(!failure.remote_grants_expire_only);
    }

    struct ExpectedResolvedHandoff {
        batch_id: [u8; 16],
        control: ProspectivePeerIdentity,
        exit: ProspectivePeerIdentity,
        relays: Vec<ProspectivePeerIdentity>,
        direct_nodes: Vec<[u8; 32]>,
        path_ids: Vec<u32>,
        reservation_id: [u8; 16],
        route_context_id: [u8; 16],
        session_id: [u8; 32],
        deadline: Instant,
        limits: RouteSetupLimits,
    }

    impl ExpectedResolvedHandoff {
        fn consume(
            plan: ProspectiveRoutePlan,
            limits: RouteSetupLimits,
        ) -> (PreProbeContinuation, Self) {
            let control = plan
                .forwarded_exit
                .selected
                .authority
                .control
                .identity
                .clone();
            let relays = plan
                .prospective_relays
                .iter()
                .map(|relay| relay.relay.identity.clone())
                .collect::<Vec<_>>();
            let direct_nodes = std::iter::once(control.wire_node_id)
                .chain(relays.iter().map(|relay| relay.wire_node_id))
                .collect();
            let path_ids = (1..=u32::try_from(relays.len()).expect("bounded path count")).collect();
            let batch_id = plan.batch_id.0;
            let exit = plan.forwarded_exit.selected.authority.exit.clone();
            let continuation = consume_prospective_route_plan_at(
                plan,
                deadlines(),
                limits,
                128,
                NOW_MS + 1_001,
                Instant::now(),
            )
            .expect("preprobe continuation");
            let expected = Self {
                batch_id,
                control,
                exit,
                relays,
                direct_nodes,
                path_ids,
                reservation_id: continuation.route_authority.reservation_id,
                route_context_id: continuation.route_authority.route_context_id,
                session_id: *continuation
                    .reservation_session
                    .coordinator
                    .client_session_id(),
                deadline: continuation.deadline,
                limits,
            };
            (continuation, expected)
        }
    }

    fn assert_exact_resolved_handoff(
        unmeasured: &UnmeasuredRouteSetup<ReservationSession>,
        io: &HandoffIo,
        state: &HandoffState,
        expected: &ExpectedResolvedHandoff,
    ) {
        let transaction = &unmeasured.transaction;
        let request = &transaction.request;
        assert_eq!(request.parameters.reservation_id, expected.reservation_id);
        assert_eq!(
            request.parameters.route_context_id,
            expected.route_context_id
        );
        assert_eq!(request.evidence_batch_id, expected.batch_id);
        assert_eq!(request.control.identity, expected.control);
        assert_eq!(request.exit, expected.exit);
        assert_eq!(
            request
                .paths
                .iter()
                .map(|path| path.path_id)
                .collect::<Vec<_>>(),
            expected.path_ids
        );
        assert_eq!(
            request
                .paths
                .iter()
                .map(|path| path.proof.relay.identity.clone())
                .collect::<Vec<_>>(),
            expected.relays
        );
        assert_eq!(request.parameters.created_at_ms, NOW_MS + 1_001);
        assert_eq!(
            request.parameters.setup_expires_at_unix,
            deadlines().setup_expires_at_ms / 1_000
        );
        assert_eq!(
            request.parameters.expires_at_ms,
            deadlines().hard_expires_at_ms
        );
        assert_eq!(
            request.parameters.hard_expires_at_unix,
            deadlines().hard_expires_at_ms / 1_000
        );
        assert_eq!(unmeasured.deadline, expected.deadline);
        assert_eq!(
            transaction.limits.setup_timeout,
            expected.limits.setup_timeout
        );
        assert_eq!(
            transaction.limits.call_timeout,
            expected.limits.call_timeout
        );
        assert_eq!(
            transaction.limits.maximum_outbound_attempts,
            expected.limits.maximum_outbound_attempts
        );
        assert_eq!(
            transaction
                .protocol
                .as_ref()
                .expect("same reservation session")
                .coordinator
                .client_session_id(),
            &expected.session_id
        );
        assert_eq!(transaction.authorities.control, io.control);
        assert_eq!(transaction.authorities.exit, io.exit);
        assert_eq!(transaction.authorities.datapath_relays, io.relays);
        assert_eq!(
            *state
                .resolved_direct_nodes
                .lock()
                .expect("resolved direct nodes"),
            expected.direct_nodes
        );
        let calls = state.calls.lock().expect("handoff calls");
        assert_eq!(calls.first(), Some(&"resolve.control"));
        assert_eq!(calls.get(1), Some(&"resolve.exit"));
        assert!(calls[2..].iter().all(|call| *call == "resolve.relay"));
        assert_eq!(calls.len(), state.total_resolves);
        assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
    }

    fn peer_binding_fingerprint(binding: &ProspectivePeerBinding) -> PeerBindingFingerprint {
        (
            binding.identity.clone(),
            binding.advertisement_measured_at_ms,
            binding.actor_evidence_observed_at_ms,
            binding.evidence_valid_until_ms,
        )
    }

    type PeerBindingFingerprint = (ProspectivePeerIdentity, u64, u64, u64);
    type RelayBindingFingerprint = (PeerBindingFingerprint, DiversitySnapshot, bool);

    struct ExpectedPreProbeContinuation {
        batch_id: EvidenceBatchId,
        control: PeerBindingFingerprint,
        exit: PeerBindingFingerprint,
        control_diversity: DiversitySnapshot,
        exit_diversity: DiversitySnapshot,
        relays: Vec<RelayBindingFingerprint>,
        evidence_min: u64,
    }

    fn expected_preprobe_continuation(plan: &ProspectiveRoutePlan) -> ExpectedPreProbeContinuation {
        ExpectedPreProbeContinuation {
            batch_id: plan.batch_id,
            control: peer_binding_fingerprint(&plan.forwarded_exit.control),
            exit: peer_binding_fingerprint(&plan.forwarded_exit.exit),
            control_diversity: plan.forwarded_exit.control_diversity.clone(),
            exit_diversity: plan.forwarded_exit.exit_diversity.clone(),
            relays: plan
                .prospective_relays
                .iter()
                .map(|relay| {
                    (
                        peer_binding_fingerprint(&relay.relay),
                        relay.diversity.clone(),
                        relay.peer_evidence.observed_network_origin.is_none(),
                    )
                })
                .collect(),
            evidence_min: plan.earliest_evidence_expiry_ms,
        }
    }

    fn preprobe_consume_context(monotonic_now: Instant) -> PreProbeConsumeTestContext {
        PreProbeConsumeTestContext {
            deadlines: deadlines(),
            limits: preprobe_limits(),
            replay_capacity: 128,
            trusted_now_ms: NOW_MS,
            monotonic_now,
        }
    }

    fn assert_exact_preprobe_bindings(
        continuation: &PreProbeContinuation,
        expected: &ExpectedPreProbeContinuation,
    ) {
        assert_eq!(continuation.batch_id, expected.batch_id);
        assert_eq!(continuation.selected_at_ms, NOW_MS);
        assert_eq!(continuation.attempt_started_at_ms, NOW_MS);
        assert_eq!(continuation.scope.now_ms, NOW_MS);
        assert_eq!(
            peer_binding_fingerprint(&continuation.forwarded_exit.control),
            expected.control
        );
        assert_eq!(
            peer_binding_fingerprint(&continuation.forwarded_exit.exit),
            expected.exit
        );
        assert_eq!(
            continuation.forwarded_exit.control_diversity,
            expected.control_diversity
        );
        assert_eq!(
            continuation.forwarded_exit.exit_diversity,
            expected.exit_diversity
        );
        assert_eq!(
            continuation.earliest_evidence_expiry_ms,
            expected.evidence_min
        );
        assert_eq!(continuation.deadlines.setup_expires_at_ms, NOW_MS + 20_000);
        assert_eq!(continuation.deadlines.hard_expires_at_ms, NOW_MS + 60_000);
        assert_eq!(continuation.limits.setup_timeout, Duration::from_secs(30));
        assert_eq!(
            continuation
                .paths
                .iter()
                .map(|path| path.path_id)
                .collect::<Vec<_>>(),
            (1..=u32::try_from(expected.relays.len()).expect("bounded paths")).collect::<Vec<_>>()
        );
        assert_eq!(
            continuation
                .paths
                .iter()
                .map(|path| {
                    (
                        peer_binding_fingerprint(&path.relay.relay),
                        path.relay.diversity.clone(),
                        path.relay.peer_evidence.observed_network_origin.is_none(),
                    )
                })
                .collect::<Vec<_>>(),
            expected.relays
        );
    }

    fn assert_preprobe_authority_and_liveness(
        continuation: &PreProbeContinuation,
        monotonic_now: Instant,
    ) {
        assert_eq!(
            continuation.deadline,
            monotonic_now + Duration::from_secs(20),
            "the carried Tokio deadline is projected once from the injected monotonic sample"
        );
        assert!(
            continuation
                .route_authority
                .reservation_id
                .iter()
                .any(|byte| *byte != 0)
        );
        assert!(
            continuation
                .route_authority
                .route_context_id
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_ne!(
            continuation.route_authority.reservation_id,
            continuation.route_authority.route_context_id
        );
        assert!(
            continuation
                .reservation_session
                .coordinator
                .client_session_id()
                .iter()
                .any(|byte| *byte != 0)
        );
        let carried_deadline = continuation.deadline;
        assert!(
            continuation
                .ensure_live_at(
                    NOW_MS + 19_999,
                    monotonic_now + Duration::from_millis(19_999),
                )
                .is_ok()
        );
        assert!(
            continuation
                .ensure_live_at(NOW_MS + 20_000, carried_deadline)
                .is_err()
        );
        assert_eq!(
            continuation.deadline, carried_deadline,
            "deadline was not reset"
        );
    }

    fn assert_rejected_before_mint(
        plan: ProspectiveRoutePlan,
        route_deadlines: RouteDeadlines,
        limits: RouteSetupLimits,
        replay_capacity: usize,
    ) {
        assert_rejected_before_mint_at(plan, route_deadlines, limits, replay_capacity, NOW_MS);
    }

    fn assert_rejected_before_mint_at(
        plan: ProspectiveRoutePlan,
        route_deadlines: RouteDeadlines,
        limits: RouteSetupLimits,
        replay_capacity: usize,
        trusted_now_ms: u64,
    ) {
        let authority_mints = Cell::new(0_u32);
        let session_mints = Cell::new(0_u32);
        let result = consume_prospective_route_plan_with_minters(
            plan,
            PreProbeConsumeTestContext {
                deadlines: route_deadlines,
                limits,
                replay_capacity,
                trusted_now_ms,
                monotonic_now: Instant::now(),
            },
            || {
                authority_mints.set(authority_mints.get() + 1);
                RouteSessionAuthority::generate()
            },
            |capacity| {
                session_mints.set(session_mints.get() + 1);
                ReservationSession::generate(capacity)
            },
        );
        assert!(result.is_err());
        assert_eq!(
            authority_mints.get(),
            0,
            "authority minted before rejection"
        );
        assert_eq!(session_mints.get(), 0, "session minted before rejection");
    }

    #[test]
    fn preprobe_consumption_preserves_exact_bindings_paths_windows_and_deadline() {
        let plan = prospective_plan();
        let expected = expected_preprobe_continuation(&plan);
        let monotonic_now = Instant::now();
        let authority_mints = Cell::new(0_u32);
        let session_mints = Cell::new(0_u32);
        let continuation = consume_prospective_route_plan_with_minters(
            plan,
            preprobe_consume_context(monotonic_now),
            || {
                authority_mints.set(authority_mints.get() + 1);
                RouteSessionAuthority::generate()
            },
            |capacity| {
                session_mints.set(session_mints.get() + 1);
                ReservationSession::generate(capacity)
            },
        )
        .expect("one private preprobe continuation");

        assert_eq!(authority_mints.get(), 1);
        assert_eq!(session_mints.get(), 1);
        assert_exact_preprobe_bindings(&continuation, &expected);
        assert_preprobe_authority_and_liveness(&continuation, monotonic_now);
    }

    #[test]
    fn preprobe_delayed_consumption_advances_current_time_but_keeps_selected_actor_cutoff() {
        let delayed_now_ms = NOW_MS + 1_001;
        let continuation = consume_prospective_route_plan_at(
            prospective_plan(),
            deadlines(),
            preprobe_limits(),
            128,
            delayed_now_ms,
            Instant::now(),
        )
        .expect("fresh plan remains valid after a second boundary");
        assert_eq!(continuation.scope.now_ms, NOW_MS);
        assert_eq!(continuation.selected_at_ms, NOW_MS);
        assert_eq!(continuation.attempt_started_at_ms, delayed_now_ms);

        for mutate_control in [true, false] {
            let mut plan = prospective_plan();
            let binding = if mutate_control {
                &mut plan.forwarded_exit.control
            } else {
                &mut plan.forwarded_exit.exit
            };
            binding.actor_evidence_observed_at_ms = NOW_MS + 500;
            assert_rejected_before_mint_at(
                plan,
                deadlines(),
                preprobe_limits(),
                128,
                delayed_now_ms,
            );
        }
    }

    #[tokio::test]
    async fn preprobe_handoff_preserves_exact_ids_session_paths_deadline_and_resolve_order() {
        let plan = prospective_plan();
        let clock = HandoffClock::new(NOW_MS + 1_001);
        let io = HandoffIo::from_plan(&plan, clock.clone());
        let state = Arc::clone(&io.state);
        let expected_limits = preprobe_limits();
        let (continuation, expected) = ExpectedResolvedHandoff::consume(plan, expected_limits);
        let (_cancellation, mut cancelled) = watch::channel(false);

        let unmeasured = continuation
            .resolve_into_unmeasured(&io, &clock, &mut cancelled)
            .await
            .expect("same attempt enters phase B");
        assert_exact_resolved_handoff(&unmeasured, &io, &state, &expected);
    }

    #[tokio::test]
    async fn preprobe_handoff_rechecks_post_resolve_wall_and_cancellation() {
        for (post_resolve_wall_ms, succeeds) in [
            (NOW_MS + 1_001, true),
            (NOW_MS - 1, false),
            (NOW_MS + 20_000, false),
        ] {
            let plan = prospective_plan();
            let clock = HandoffClock::new(NOW_MS);
            let io = HandoffIo::from_plan(&plan, clock.clone());
            let state = Arc::clone(&io.state);
            state
                .post_resolve_wall_ms
                .store(post_resolve_wall_ms, Ordering::SeqCst);
            let continuation = consume_prospective_route_plan_at(
                plan,
                deadlines(),
                preprobe_limits(),
                128,
                NOW_MS,
                Instant::now(),
            )
            .expect("preprobe continuation");
            let (_cancellation, mut cancelled) = watch::channel(false);
            let result = continuation
                .resolve_into_unmeasured(&io, &clock, &mut cancelled)
                .await;
            assert_eq!(result.is_ok(), succeeds);
            if !succeeds {
                assert!(matches!(result, Err(RouteSetupError::Expired)));
            }
            assert_eq!(
                state.calls.lock().expect("handoff calls").len(),
                state.total_resolves
            );
            assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
        }

        let plan = prospective_plan();
        let clock = HandoffClock::new(NOW_MS);
        let io = HandoffIo::from_plan(&plan, clock.clone());
        let state = Arc::clone(&io.state);
        let continuation = consume_prospective_route_plan_at(
            plan,
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("preprobe continuation");
        let (cancellation, mut cancelled) = watch::channel(false);
        clock.cancel_on_read(2, cancellation);
        assert!(matches!(
            continuation
                .resolve_into_unmeasured(&io, &clock, &mut cancelled)
                .await,
            Err(RouteSetupError::Cancelled)
        ));
        assert_eq!(
            state.calls.lock().expect("handoff calls").len(),
            state.total_resolves
        );
        assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn preprobe_manager_cancellation_drops_first_and_last_pending_resolve_once() {
        for gate_last in [false, true] {
            let plan = prospective_plan();
            let clock = HandoffClock::new(NOW_MS);
            let io = HandoffIo::from_plan(&plan, clock);
            let state = Arc::clone(&io.state);
            state.gate_call.store(
                if gate_last { state.total_resolves } else { 1 },
                Ordering::SeqCst,
            );
            let continuation = consume_prospective_route_plan_at(
                plan,
                deadlines(),
                preprobe_limits(),
                128,
                NOW_MS,
                Instant::now(),
            )
            .expect("preprobe continuation");
            let local_calls = Arc::new(AtomicUsize::new(0));
            let manager = handoff_manager(Arc::clone(&local_calls));
            let handle = manager.spawn_preprobe(continuation, io, HandoffClock::new(NOW_MS));
            state.resolve_started.notified().await;
            handle.cancel();
            let failure = handle.wait().await.expect_err("cancelled handoff");
            assert!(matches!(failure.cause, RouteSetupError::Cancelled));
            assert_before_dispatch_failure(&failure);
            assert_eq!(state.pending_resolve_drops.load(Ordering::SeqCst), 1);
            state.resolve_release.notify_waiters();
            tokio::task::yield_now().await;
            assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
            assert_eq!(local_calls.load(Ordering::SeqCst), 0);
            assert!(!manager.has_network_state());
            manager.shutdown().await.expect("manager shutdown");
        }
    }

    #[tokio::test]
    async fn preprobe_manager_rejects_current_capability_drift_before_dispatch() {
        for mutation in 0_u8..7 {
            let plan = prospective_plan();
            let clock = HandoffClock::new(NOW_MS);
            let mut io = HandoffIo::from_plan(&plan, clock);
            match mutation {
                0 => io.control.expires_at_ms -= 1,
                1 => io.exit.exit_advertisement_sequence += 1,
                2 => {
                    io.relays
                        .last_mut()
                        .expect("last relay capability")
                        .policy_hash[0] ^= 1;
                }
                3 => {
                    io.control.advertisement_payload_hash =
                        io.control.advertisement_payload_hash.xor_for_test();
                }
                4 => {
                    io.exit.control_relay_advertisement_payload_hash = io
                        .exit
                        .control_relay_advertisement_payload_hash
                        .xor_for_test();
                }
                5 => {
                    io.exit.exit_advertisement_payload_hash =
                        io.exit.exit_advertisement_payload_hash.xor_for_test();
                }
                6 => {
                    let relay = io.relays.last_mut().expect("last relay capability");
                    relay.advertisement_payload_hash =
                        relay.advertisement_payload_hash.xor_for_test();
                }
                _ => unreachable!(),
            }
            let state = Arc::clone(&io.state);
            let continuation = consume_prospective_route_plan_at(
                plan,
                deadlines(),
                preprobe_limits(),
                128,
                NOW_MS,
                Instant::now(),
            )
            .expect("preprobe continuation");
            let local_calls = Arc::new(AtomicUsize::new(0));
            let manager = handoff_manager(Arc::clone(&local_calls));
            let failure = manager
                .spawn_preprobe(continuation, io, HandoffClock::new(NOW_MS))
                .wait()
                .await
                .expect_err("capability drift");
            assert!(matches!(failure.cause, RouteSetupError::Capability));
            assert_before_dispatch_failure(&failure);
            assert_eq!(
                state.calls.lock().expect("handoff calls").len(),
                state.total_resolves
            );
            assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
            assert_eq!(local_calls.load(Ordering::SeqCst), 0);
            assert!(!manager.has_network_state());
            manager.shutdown().await.expect("manager shutdown");
        }
    }

    #[tokio::test]
    async fn dropping_pending_preprobe_handle_drops_resolver_future_once_without_side_effects() {
        let plan = prospective_plan();
        let clock = HandoffClock::new(NOW_MS);
        let io = HandoffIo::from_plan(&plan, clock);
        let state = Arc::clone(&io.state);
        state.gate_call.store(1, Ordering::SeqCst);
        let continuation = consume_prospective_route_plan_at(
            plan,
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("preprobe continuation");
        let local_calls = Arc::new(AtomicUsize::new(0));
        let manager = handoff_manager(Arc::clone(&local_calls));
        let handle = manager.spawn_preprobe(continuation, io, HandoffClock::new(NOW_MS));
        state.resolve_started.notified().await;
        drop(handle);
        state.resolve_dropped.notified().await;
        assert_eq!(state.pending_resolve_drops.load(Ordering::SeqCst), 1);
        state.resolve_release.notify_waiters();
        tokio::task::yield_now().await;
        assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
        assert_eq!(local_calls.load(Ordering::SeqCst), 0);
        assert!(!manager.has_network_state());
        manager.shutdown().await.expect("manager shutdown");
    }

    #[tokio::test]
    async fn preprobe_manager_rejects_expired_and_times_out_pending_resolve_without_dispatch() {
        let plan = prospective_plan();
        let clock = HandoffClock::new(NOW_MS);
        let io = HandoffIo::from_plan(&plan, clock);
        let state = Arc::clone(&io.state);
        let mut continuation = consume_prospective_route_plan_at(
            plan,
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("preprobe continuation");
        continuation.deadline = Instant::now();
        let local_calls = Arc::new(AtomicUsize::new(0));
        let manager = handoff_manager(Arc::clone(&local_calls));
        let failure = manager
            .spawn_preprobe(continuation, io, HandoffClock::new(NOW_MS))
            .wait()
            .await
            .expect_err("expired carried deadline");
        assert!(matches!(
            failure.cause,
            RouteSetupError::Deadline(RouteSetupPhase::Validated)
        ));
        assert_before_dispatch_failure(&failure);
        assert!(state.calls.lock().expect("handoff calls").is_empty());
        assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
        assert_eq!(local_calls.load(Ordering::SeqCst), 0);
        manager.shutdown().await.expect("manager shutdown");

        let plan = prospective_plan();
        let clock = HandoffClock::new(NOW_MS);
        let io = HandoffIo::from_plan(&plan, clock);
        let state = Arc::clone(&io.state);
        state.gate_call.store(1, Ordering::SeqCst);
        let mut continuation = consume_prospective_route_plan_at(
            plan,
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("preprobe continuation");
        continuation.limits.call_timeout = Duration::from_millis(5);
        let local_calls = Arc::new(AtomicUsize::new(0));
        let manager = handoff_manager(Arc::clone(&local_calls));
        let handle = manager.spawn_preprobe(continuation, io, HandoffClock::new(NOW_MS));
        state.resolve_started.notified().await;
        let failure = handle.wait().await.expect_err("pending resolve timeout");
        assert!(matches!(
            failure.cause,
            RouteSetupError::CallTimeout(RouteSetupPhase::Validated)
        ));
        assert_before_dispatch_failure(&failure);
        assert_eq!(state.pending_resolve_drops.load(Ordering::SeqCst), 1);
        state.resolve_release.notify_waiters();
        tokio::task::yield_now().await;
        assert_eq!(state.transport_calls.load(Ordering::SeqCst), 0);
        assert_eq!(local_calls.load(Ordering::SeqCst), 0);
        assert!(!manager.has_network_state());
        manager.shutdown().await.expect("manager shutdown");
    }

    #[test]
    fn preprobe_deadline_uses_shorter_setup_limit_without_reset() {
        let monotonic_now = Instant::now();
        let limits = RouteSetupLimits::new(Duration::from_secs(7), Duration::from_secs(5), 2)
            .expect("shorter setup limit");
        let continuation = consume_prospective_route_plan_at(
            prospective_plan(),
            deadlines(),
            limits,
            128,
            NOW_MS,
            monotonic_now,
        )
        .expect("short-limit continuation");
        assert_eq!(
            continuation.deadline,
            monotonic_now + Duration::from_secs(7)
        );
        assert!(
            continuation
                .ensure_live_at(NOW_MS + 6_999, monotonic_now + Duration::from_millis(6_999))
                .is_ok()
        );
        assert!(
            continuation
                .ensure_live_at(NOW_MS + 7_000, continuation.deadline)
                .is_err()
        );
    }

    #[test]
    fn distinct_preprobe_attempts_mint_distinct_authority_and_session_ids() {
        let first = consume_prospective_route_plan_at(
            prospective_plan(),
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("first attempt");
        let second = consume_prospective_route_plan_at(
            prospective_plan(),
            deadlines(),
            preprobe_limits(),
            128,
            NOW_MS,
            Instant::now(),
        )
        .expect("second attempt");
        assert_ne!(
            first.route_authority.reservation_id,
            second.route_authority.reservation_id
        );
        assert_ne!(
            first.route_authority.route_context_id,
            second.route_authority.route_context_id
        );
        assert_ne!(
            first.reservation_session.coordinator.client_session_id(),
            second.reservation_session.coordinator.client_session_id()
        );
    }

    #[test]
    fn preprobe_mint_failures_preserve_authority_then_session_order() {
        let authority_mints = Cell::new(0_u32);
        let session_mints = Cell::new(0_u32);
        let authority_failure = consume_prospective_route_plan_with_minters(
            prospective_plan(),
            preprobe_consume_context(Instant::now()),
            || {
                authority_mints.set(authority_mints.get() + 1);
                Err(SelectionBridgeError::EntropyUnavailable)
            },
            |capacity| {
                session_mints.set(session_mints.get() + 1);
                ReservationSession::generate(capacity)
            },
        );
        assert!(matches!(
            authority_failure,
            Err(SelectionBridgeError::EntropyUnavailable)
        ));
        assert_eq!(authority_mints.get(), 1);
        assert_eq!(session_mints.get(), 0);

        authority_mints.set(0);
        session_mints.set(0);
        let session_failure = consume_prospective_route_plan_with_minters(
            prospective_plan(),
            preprobe_consume_context(Instant::now()),
            || {
                authority_mints.set(authority_mints.get() + 1);
                RouteSessionAuthority::generate()
            },
            |_| {
                session_mints.set(session_mints.get() + 1);
                Err(RouteSetupError::Invalid("injected session mint"))
            },
        );
        assert!(matches!(
            session_failure,
            Err(SelectionBridgeError::RouteSetup(RouteSetupError::Invalid(
                "injected session mint"
            )))
        ));
        assert_eq!(authority_mints.get(), 1);
        assert_eq!(session_mints.get(), 1);
    }

    #[test]
    fn preprobe_consumption_accepts_valid_exploration_evidence() {
        let mut plan = prospective_plan();
        plan.prospective_relays[0]
            .peer_evidence
            .locally_measured_p25 = None;
        plan.prospective_relays[0].peer_evidence.measurement_count = 1;
        assert!(
            consume_prospective_route_plan_at(
                plan,
                deadlines(),
                preprobe_limits(),
                128,
                NOW_MS,
                Instant::now(),
            )
            .is_ok()
        );
    }

    #[test]
    fn preprobe_rejects_future_mismatched_stale_or_spliced_evidence_before_mint() {
        let mut zero_batch = prospective_plan();
        zero_batch.batch_id = EvidenceBatchId([0; 16]);
        assert_rejected_before_mint(zero_batch, deadlines(), preprobe_limits(), 128);

        let mut selected_mismatch = prospective_plan();
        selected_mismatch.selected_at_ms += 1;
        assert_rejected_before_mint(selected_mismatch, deadlines(), preprobe_limits(), 128);

        let mut future = prospective_plan();
        future.selected_at_ms += 1;
        future.scope.now_ms += 1;
        assert_rejected_before_mint(future, deadlines(), preprobe_limits(), 128);

        let mut control_stale = prospective_plan();
        control_stale.forwarded_exit.control.evidence_valid_until_ms = NOW_MS;
        control_stale.earliest_evidence_expiry_ms = NOW_MS;
        assert_rejected_before_mint(control_stale, deadlines(), preprobe_limits(), 128);

        let mut exit_stale = prospective_plan();
        exit_stale.forwarded_exit.exit.evidence_valid_until_ms = NOW_MS;
        exit_stale.earliest_evidence_expiry_ms = NOW_MS;
        assert_rejected_before_mint(exit_stale, deadlines(), preprobe_limits(), 128);

        let mut relay_stale = prospective_plan();
        relay_stale.prospective_relays[0]
            .relay
            .evidence_valid_until_ms = NOW_MS;
        relay_stale.earliest_evidence_expiry_ms = NOW_MS;
        assert_rejected_before_mint(relay_stale, deadlines(), preprobe_limits(), 128);

        let mut scalar_splice = prospective_plan();
        scalar_splice.earliest_evidence_expiry_ms += 1;
        assert_rejected_before_mint(scalar_splice, deadlines(), preprobe_limits(), 128);
    }

    #[test]
    fn preprobe_rejects_control_exit_and_relay_payload_hash_splices_before_mint() {
        let mut control = prospective_plan();
        control
            .forwarded_exit
            .control
            .identity
            .advertisement_payload_hash = control
            .forwarded_exit
            .control
            .identity
            .advertisement_payload_hash
            .xor_for_test();
        assert_rejected_before_mint(control, deadlines(), preprobe_limits(), 128);

        let mut exit = prospective_plan();
        exit.forwarded_exit.exit.identity.advertisement_payload_hash = exit
            .forwarded_exit
            .exit
            .identity
            .advertisement_payload_hash
            .xor_for_test();
        assert_rejected_before_mint(exit, deadlines(), preprobe_limits(), 128);

        let mut relay = prospective_plan();
        relay.prospective_relays[0]
            .relay
            .identity
            .advertisement_payload_hash = relay.prospective_relays[0]
            .relay
            .identity
            .advertisement_payload_hash
            .xor_for_test();
        assert_rejected_before_mint(relay, deadlines(), preprobe_limits(), 128);
    }

    #[test]
    fn preprobe_rejects_identity_evidence_and_diversity_substitution_before_mint() {
        let mut duplicate_node = prospective_plan();
        duplicate_node.prospective_relays[0]
            .relay
            .identity
            .wire_node_id = duplicate_node.forwarded_exit.control.identity.wire_node_id;
        assert_rejected_before_mint(duplicate_node, deadlines(), preprobe_limits(), 128);

        let mut duplicate_peer = prospective_plan();
        duplicate_peer.prospective_relays[0].relay.identity.peer_id =
            duplicate_peer.forwarded_exit.control.identity.peer_id;
        assert_rejected_before_mint(duplicate_peer, deadlines(), preprobe_limits(), 128);

        let mut duplicate_key = prospective_plan();
        duplicate_key.prospective_relays[0]
            .relay
            .identity
            .public_key = duplicate_key.forwarded_exit.control.identity.public_key;
        assert_rejected_before_mint(duplicate_key, deadlines(), preprobe_limits(), 128);

        let mut zero_key = prospective_plan();
        zero_key.prospective_relays[0].relay.identity.public_key = [0; 32];
        assert_rejected_before_mint(zero_key, deadlines(), preprobe_limits(), 128);

        let mut zero_sequence = prospective_plan();
        zero_sequence.prospective_relays[0]
            .relay
            .identity
            .advertisement_sequence = 0;
        assert_rejected_before_mint(zero_sequence, deadlines(), preprobe_limits(), 128);
    }

    #[test]
    fn preprobe_rejects_peer_evidence_and_diversity_substitution_before_mint() {
        for actor in 0..3 {
            let mut missing_rtt = prospective_plan();
            match actor {
                0 => missing_rtt.forwarded_exit.control_peer_evidence.rtt_ms = None,
                1 => missing_rtt.forwarded_exit.exit_peer_evidence.rtt_ms = None,
                _ => missing_rtt.prospective_relays[0].peer_evidence.rtt_ms = None,
            }
            assert_rejected_before_mint(missing_rtt, deadlines(), preprobe_limits(), 128);
        }

        for mutation in 0..3 {
            let mut invalid_evidence = prospective_plan();
            let evidence = &mut invalid_evidence.prospective_relays[0].peer_evidence;
            match mutation {
                0 => evidence.reachable = false,
                1 => evidence.network_address_usable = false,
                _ => evidence.locally_blocked = true,
            }
            assert_rejected_before_mint(invalid_evidence, deadlines(), preprobe_limits(), 128);
        }

        let mut unreachable_with_rtt = prospective_plan();
        unreachable_with_rtt.prospective_relays[0]
            .peer_evidence
            .reachable = false;
        assert!(
            unreachable_with_rtt.prospective_relays[0]
                .peer_evidence
                .rtt_ms
                .is_some()
        );
        assert_rejected_before_mint(unreachable_with_rtt, deadlines(), preprobe_limits(), 128);

        let mut wrong_origin = prospective_plan();
        wrong_origin.prospective_relays[0]
            .peer_evidence
            .observed_network_origin = Some(ObservedNetworkOrigin {
            address: Ipv4Addr::new(80, 1, 1, 1).into(),
        });
        assert_rejected_before_mint(wrong_origin, deadlines(), preprobe_limits(), 128);

        let mut low_capacity = prospective_plan();
        low_capacity.prospective_relays[0]
            .peer_evidence
            .reserved_path_limit = Bandwidth::new(1, 1).expect("low capacity");
        assert_rejected_before_mint(low_capacity, deadlines(), preprobe_limits(), 128);

        let mut low_measured = prospective_plan();
        low_measured.prospective_relays[0]
            .peer_evidence
            .locally_measured_p25 = Some(Bandwidth::new(1, 1).expect("low measured capacity"));
        assert_rejected_before_mint(low_measured, deadlines(), preprobe_limits(), 128);

        let mut wrong_family = prospective_plan();
        wrong_family.prospective_relays[0]
            .diversity
            .observed_network_prefix =
            ObservedNetworkPrefix::ipv6_48([0x20, 0x01, 0x48, 0x60, 0x01, 0x00]);
        assert_rejected_before_mint(wrong_family, deadlines(), preprobe_limits(), 128);

        for expiry_mutation in 0..3 {
            let mut invalid_expiry = prospective_plan();
            let binding = &mut invalid_expiry.prospective_relays[0].relay;
            match expiry_mutation {
                0 => binding.identity.advertisement_expires_at_ms = NOW_MS,
                1 => binding.identity.expires_at_ms = NOW_MS,
                _ => {
                    binding.identity.expires_at_ms =
                        binding.identity.advertisement_expires_at_ms + 1;
                }
            }
            assert_rejected_before_mint(invalid_expiry, deadlines(), preprobe_limits(), 128);
        }

        let mut conflict = prospective_plan();
        conflict.prospective_relays[0].diversity =
            conflict.forwarded_exit.control_diversity.clone();
        assert_rejected_before_mint(conflict, deadlines(), preprobe_limits(), 128);
    }

    #[test]
    fn preprobe_rejects_invalid_counts_replay_limits_and_windows_before_mint() {
        let mut empty = prospective_plan();
        empty.prospective_relays.clear();
        assert_rejected_before_mint(empty, deadlines(), preprobe_limits(), 128);

        let mut below_minimum = prospective_plan();
        below_minimum.prospective_relays.truncate(1);
        assert_rejected_before_mint(below_minimum, deadlines(), preprobe_limits(), 128);

        let mut nine = prospective_plan();
        while nine.prospective_relays.len() < 9 {
            let mut fresh = prospective_plan();
            nine.prospective_relays.push(
                fresh
                    .prospective_relays
                    .pop()
                    .expect("fresh affine relay proof"),
            );
        }
        assert_rejected_before_mint(nine, deadlines(), preprobe_limits(), 128);

        assert_rejected_before_mint(prospective_plan(), deadlines(), preprobe_limits(), 0);
        assert_rejected_before_mint(
            prospective_plan(),
            deadlines(),
            preprobe_limits(),
            MAXIMUM_REPLAY_CAPACITY + 1,
        );
        let invalid_limits = RouteSetupLimits {
            setup_timeout: Duration::ZERO,
            call_timeout: Duration::from_secs(1),
            maximum_outbound_attempts: 1,
        };
        assert_rejected_before_mint(prospective_plan(), deadlines(), invalid_limits, 128);

        let mut invalid_policy = prospective_plan();
        invalid_policy.scope.relay_policy.minimum_paths = 1;
        assert_rejected_before_mint(invalid_policy, deadlines(), preprobe_limits(), 128);

        for invalid_deadlines in [
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS,
                hard_expires_at_ms: NOW_MS + 60_000,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 20_000,
                hard_expires_at_ms: NOW_MS + 10_000,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 61_000,
                hard_expires_at_ms: NOW_MS + 80_000,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 31_000,
                hard_expires_at_ms: NOW_MS + 60_000,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 20_000,
                hard_expires_at_ms: NOW_MS + 90_001,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 20_000,
                hard_expires_at_ms: u64::MAX,
            },
            RouteDeadlines {
                setup_expires_at_ms: NOW_MS + 999,
                hard_expires_at_ms: NOW_MS + 60_000,
            },
        ] {
            assert_rejected_before_mint(
                prospective_plan(),
                invalid_deadlines,
                preprobe_limits(),
                128,
            );
        }
    }

    #[test]
    fn preprobe_continuation_is_affine_and_exposes_only_the_orchestrator_handoff() {
        let source = include_str!("selection_bridge.rs");
        for type_name in ["PreProbeContinuation", "PendingPreProbeResolve"] {
            let declaration = source
                .find(&format!("struct {type_name}"))
                .expect("affine handoff declaration");
            let prefix = &source[declaration.saturating_sub(160)..declaration];
            assert!(!prefix.contains("#[derive"));
            let body_end = source[declaration..]
                .find("\n}")
                .map(|offset| declaration + offset)
                .expect("affine handoff body");
            assert!(!source[declaration..body_end].contains("\n    pub "));
            assert!(!source.contains(&format!(" for {type_name}")));
        }
        assert!(source.contains("pub(crate) struct PreProbeContinuation"));
        for visibility in ["pub ", "pub(crate) ", "pub(super) "] {
            assert!(!source.contains(&format!("{visibility}struct PendingPreProbeResolve")));
        }
        for forbidden in [
            ["fn into_", "parts"].concat(),
            ["fn as_", "inner"].concat(),
            ["fn dead", "line("].concat(),
            ["impl De", "ref"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
        let pending_impl = source
            .split("impl PendingPreProbeResolve")
            .nth(1)
            .and_then(|suffix| suffix.split("impl PreProbeContinuation").next())
            .expect("pending resolve impl");
        let continuation_impl = source
            .split("impl PreProbeContinuation")
            .nth(1)
            .and_then(|suffix| suffix.split("impl<L> RouteSetupManager").next())
            .expect("continuation impl");
        assert!(!pending_impl.contains("\n    pub "));
        assert!(!continuation_impl.contains("\n    pub "));
        let consume_name = ["consume_prospective_route_", "plan("].concat();
        assert_eq!(
            source.matches(&consume_name).count(),
            1,
            "the dormant product wrapper must have no caller"
        );
    }

    #[test]
    fn preprobe_handoff_source_has_one_task_borrowed_resolve_and_no_remint_or_caller() {
        let route_source = include_str!("../route_setup.rs");
        let bridge_source = include_str!("selection_bridge.rs");
        let product_bridge = bridge_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("product bridge source");
        let spawn_call = [".spawn_", "owned("].concat();
        assert_eq!(route_source.matches("fn spawn_owned<").count(), 1);
        assert_eq!(
            route_source.matches(&spawn_call).count() + product_bridge.matches(&spawn_call).count(),
            2,
            "only legacy spawn and C2c handoff may enter the one-task seam"
        );
        assert_eq!(product_bridge.matches("fn spawn_preprobe<").count(), 1);
        assert_eq!(
            product_bridge
                .matches("pub(super) fn spawn_preprobe")
                .count(),
            1,
            "the parent route actor is the only permitted caller"
        );
        let preprobe_call = [".spawn_", "preprobe("].concat();
        assert_eq!(product_bridge.matches(&preprobe_call).count(), 0);
        for forbidden in [
            "pub fn spawn_preprobe",
            "pub(crate) fn spawn_preprobe",
            "pub trait RouteCapabilityResolver",
            "pub(crate) trait RouteCapabilityResolver",
            "pub(super) trait RouteCapabilityResolver",
        ] {
            assert!(!route_source.contains(forbidden));
            assert!(!product_bridge.contains(forbidden));
        }

        let handoff_start = product_bridge
            .find("fn into_pending_resolve")
            .expect("handoff implementation");
        let handoff_end = product_bridge[handoff_start..]
            .find("struct SnapshotExitPreflight")
            .map(|offset| handoff_start + offset)
            .expect("handoff implementation end");
        let handoff = &product_bridge[handoff_start..handoff_end];
        let request_position = handoff
            .find("RouteSetupRequest::new(")
            .expect("sanitized request assembly");
        let resolve_position = handoff
            .find("RouteSetupAuthorities::resolve(")
            .expect("borrowed capability resolve");
        assert!(request_position < resolve_position);
        assert_eq!(handoff.matches("bounded_call(").count(), 1);
        for forbidden in [
            "RouteSessionAuthority::generate(",
            "ReservationSession::generate(",
            "Candidate {",
            "NodeAdvertisement",
            "control_endpoints",
            "checked_add(limits.setup_timeout)",
        ] {
            assert!(
                !handoff.contains(forbidden),
                "forbidden handoff source: {forbidden}"
            );
        }
    }

    fn assert_bound_identity_substitutions_are_rejected(
        snapshot: &RouteCandidateSnapshot,
        evidence: &[FreshPeerEvidence],
    ) {
        let mut control_substitution = evidence.to_vec();
        control_substitution[1].forwarded_control =
            Some(exact_control_binding(&control_substitution[2]));
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                snapshot_parameters(),
                fresh_batch(control_substitution),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut exit_substitution = evidence.to_vec();
        exit_substitution.swap(1, 2);
        exit_substitution[1].role = ServiceRole::Exit;
        exit_substitution[1].forwarded_control = Some(exact_control_binding(&exit_substitution[0]));
        exit_substitution[2].role = ServiceRole::Relay;
        exit_substitution[2].forwarded_control = None;
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                snapshot_parameters(),
                fresh_batch(exit_substitution),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut sybil_relay = evidence.to_vec();
        sybil_relay[2].observed_network_prefix = sybil_relay[0].observed_network_prefix;
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                snapshot_parameters(),
                fresh_batch(sybil_relay),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(
                SelectionError::InsufficientDiversePaths { .. }
            ))
        ));

        let mut actor_key_substitution = evidence.to_vec();
        actor_key_substitution[2].capability_public_key[0] ^= 1;
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                snapshot_parameters(),
                fresh_batch(actor_key_substitution),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));
    }

    fn assert_unknown_evidence_and_invalid_policy_are_rejected(
        snapshot: &RouteCandidateSnapshot,
        evidence: &[FreshPeerEvidence],
    ) {
        let mut unknown_extra = evidence.to_vec();
        let mut unknown = unknown_extra[2].clone();
        unknown.node_id = NodeId::new("unknown-extra-node").expect("unknown node");
        unknown.peer_id = PeerId::new("unknown-extra-peer").expect("unknown peer");
        unknown.capability_public_key = [99; 32];
        unknown.advertisement_sequence = 999;
        unknown_extra.push(unknown);
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                snapshot_parameters(),
                fresh_batch(unknown_extra),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut invalid_multipath = snapshot_parameters();
        invalid_multipath.relay_policy.minimum_paths = 1;
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                invalid_multipath,
                fresh_batch(evidence.to_vec()),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(
                SelectionError::InvalidPolicy
            ))
        ));

        let mut invalid_total = snapshot_parameters();
        invalid_total.relay_policy.active_paths = 8;
        invalid_total.relay_policy.maximum_paths = 8;
        invalid_total.relay_policy.warm_backup_paths = 1;
        assert!(matches!(
            snapshot_route_plan_at(
                snapshot,
                invalid_total,
                fresh_batch(evidence.to_vec()),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(
                SelectionError::InvalidPolicy
            ))
        ));
    }

    #[test]
    fn prospective_route_plan_rejects_control_exit_or_sybil_relay_substitution() {
        let (snapshot, evidence) = snapshot_fixture();
        assert_bound_identity_substitutions_are_rejected(&snapshot, &evidence);
        assert_unknown_evidence_and_invalid_policy_are_rejected(&snapshot, &evidence);
    }

    #[test]
    fn dormant_evidence_and_anchor_debug_are_redacted() {
        let (_, evidence) = snapshot_fixture();
        let rendered = format!("{:?}", evidence[0]);
        assert!(!rendered.contains(evidence[0].node_id.as_str()));
        assert!(!rendered.contains(evidence[0].peer_id.as_str()));
        assert!(!rendered.contains(&hex::encode(evidence[0].capability_public_key)));
        assert!(!rendered.contains("44.1.1.1"));

        let anchor = DiversityAnchor::from_observed_prefix(
            evidence[0].node_id.clone(),
            evidence[0].peer_id.clone(),
            OperatorId::new("debug-anchor").expect("operator"),
            64_990,
            evidence[0]
                .observed_network_prefix
                .expect("observed prefix"),
        )
        .expect("valid anchor");
        let anchor_rendered = format!("{anchor:?}");
        assert!(!anchor_rendered.contains(evidence[0].node_id.as_str()));
        assert!(!anchor_rendered.contains(evidence[0].peer_id.as_str()));
        assert!(!anchor_rendered.contains("44.1.1.1"));
    }

    fn snapshot_parameters() -> SnapshotPreflightParameters {
        let scope = scope();
        SnapshotPreflightParameters {
            transport: scope.transport,
            minimum_capacity: scope.minimum_capacity,
            address_family: scope.address_family,
            region: scope.region,
            exit_mix: scope.exit_mix,
            relay_policy: scope.relay_policy,
        }
    }

    fn snapshot_paths(preflight: &SnapshotExitPreflight) -> Vec<SnapshotRelayPathEvidence> {
        let binding = preflight.selected_exit_binding();
        preflight
            .direct_relays
            .iter()
            .filter(|candidate| {
                candidate.capability().peer_id
                    != preflight
                        .selected
                        .forwarded_exit
                        .authority
                        .control
                        .identity
                        .peer_id
            })
            .enumerate()
            .map(|(index, relay)| {
                let advertisement = relay.advertisement().advertisement();
                SnapshotRelayPathEvidence {
                    exit: binding.clone(),
                    relay_node_id: advertisement.node_id.clone(),
                    relay_peer_id: advertisement.peer_id.clone(),
                    relay_advertisement_sequence: advertisement.sequence_number,
                    relay_advertisement_payload_hash: relay
                        .advertisement()
                        .advertisement_payload_hash(),
                    transport: SelectionTransport::TcpMptcp,
                    policy_hash: PolicyHash::from_bytes(POLICY_BYTES),
                    policy_expires_at_ms: NOW_MS + 90_000,
                    probe_address_family: ProbeAddressFamily::Ipv4,
                    observed_at_ms: NOW_MS,
                    client_to_relay_capacity: Bandwidth::new(70, 70)
                        .expect("client relay capacity"),
                    relay_to_exit_capacity: Bandwidth::new(60, 60).expect("relay exit capacity"),
                    exit_reserved_capacity: Bandwidth::new(50, 50).expect("exit capacity"),
                    client_to_relay_rtt_ms: 10.0,
                    relay_to_exit_rtt_ms: 15.0
                        + f64::from(u32::try_from(index).expect("bounded relay index")),
                    unique_throughput_gain_ratio: 0.20,
                    meaningful_failover: true,
                }
            })
            .collect()
    }

    #[test]
    fn snapshot_preflight_requires_fresh_identity_bound_evidence() {
        let (snapshot, evidence) = snapshot_fixture();
        assert!(matches!(
            snapshot_exit_preflight_at(&snapshot, snapshot_parameters(), &[], NOW_MS, &mut OsRng,),
            Err(SelectionBridgeError::FreshPeerEvidenceUnavailable)
        ));

        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("fresh snapshot peer evidence");
        assert!(matches!(
            preflight.complete_at(
                &[],
                deadlines(),
                RouteSessionAuthority::for_test([41; 16], [42; 16]),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::CompletePathEvidenceUnavailable)
        ));
    }

    #[test]
    fn snapshot_preflight_rejects_policy_time_sequence_and_control_substitution() {
        assert_snapshot_phase_time_policy_and_sequence_binding();
        assert_snapshot_completion_time_and_control_binding();
    }

    fn assert_snapshot_phase_time_policy_and_sequence_binding() {
        let (snapshot, evidence) = snapshot_fixture();
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &evidence,
                NOW_MS - 1,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let mut wrong_policy = evidence.clone();
        wrong_policy[0].policy_hash = PolicyHash::from_bytes([88; 32]);
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &wrong_policy,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut post_snapshot = evidence.clone();
        post_snapshot[0].observed_at_ms = NOW_MS + 1;
        assert!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &post_snapshot,
                NOW_MS + 1,
                &mut OsRng,
            )
            .is_ok(),
            "fresh evidence may be collected after snapshot capture"
        );
        post_snapshot[0].observed_at_ms = NOW_MS + 2;
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &post_snapshot,
                NOW_MS + 1,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let mut wrong_sequence = evidence.clone();
        wrong_sequence[0].advertisement_sequence += 1;
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &wrong_sequence,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    fn assert_snapshot_completion_binding_rejections(
        snapshot: &RouteCandidateSnapshot,
        evidence: &[FreshPeerEvidence],
    ) {
        let preflight = snapshot_exit_preflight_at(
            snapshot,
            snapshot_parameters(),
            evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("valid exit-first preflight");
        let mut paths = snapshot_paths(&preflight);
        paths[0].exit.control_peer_id = paths[0].relay_peer_id.as_str().as_bytes().to_vec();
        assert!(matches!(
            preflight.complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([43; 16], [44; 16]),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let preflight = snapshot_exit_preflight_at(
            snapshot,
            snapshot_parameters(),
            evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("hash-bound exit-first preflight");
        let mut paths = snapshot_paths(&preflight);
        paths[0].relay_advertisement_payload_hash =
            paths[0].relay_advertisement_payload_hash.xor_for_test();
        assert!(matches!(
            preflight.complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([45; 16], [46; 16]),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::CompletePathEvidenceUnavailable)
        ));
    }

    fn assert_snapshot_completion_time_rejections(
        snapshot: &RouteCandidateSnapshot,
        evidence: &[FreshPeerEvidence],
    ) {
        let preflight = snapshot_exit_preflight_at(
            snapshot,
            snapshot_parameters(),
            evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("phase-one evidence");
        let paths = snapshot_paths(&preflight);
        assert!(matches!(
            preflight.complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([49; 16], [50; 16]),
                NOW_MS + MAXIMUM_EVIDENCE_AGE_MS + 1,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let preflight = snapshot_exit_preflight_at(
            snapshot,
            snapshot_parameters(),
            evidence,
            NOW_MS + 1,
            &mut OsRng,
        )
        .expect("later phase-one clock");
        let paths = snapshot_paths(&preflight);
        assert!(matches!(
            preflight.complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([53; 16], [54; 16]),
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let mut control_older = evidence.to_vec();
        control_older[0].observed_at_ms = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS + 1;
        control_older[0].valid_until_ms = NOW_MS + 1;
        let preflight = snapshot_exit_preflight_at(
            snapshot,
            snapshot_parameters(),
            &control_older,
            NOW_MS,
            &mut OsRng,
        )
        .expect("boundary-fresh control evidence");
        let paths = snapshot_paths(&preflight);
        assert!(matches!(
            preflight.complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([55; 16], [56; 16]),
                NOW_MS + 1,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::StaleEvidence)
        ));
    }

    fn assert_snapshot_completion_time_and_control_binding() {
        let (snapshot, evidence) = snapshot_fixture();
        assert_snapshot_completion_binding_rejections(&snapshot, &evidence);
        assert_snapshot_completion_time_rejections(&snapshot, &evidence);
    }

    #[test]
    fn snapshot_preflight_never_substitutes_advertised_capacity_or_stored_reachability() {
        assert_control_relay_hard_filters_are_applied();

        let (snapshot, mut evidence) = snapshot_fixture();
        for fresh in &mut evidence {
            fresh.locally_measured_p25 = None;
            fresh.measurement_count = 0;
        }
        let exploration = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("fresh unmeasured peer evidence remains bounded exploration");
        assert_eq!(
            exploration.selected.selected.band,
            volparossa_selection::SelectionBand::Exploration
        );

        let (snapshot, mut evidence) = snapshot_fixture();
        for fresh in &mut evidence {
            fresh.locally_measured_p25 = None;
            fresh.measurement_count = 0;
            fresh.preselection_capacity_ceiling =
                Bandwidth::new(5, 5).expect("low preselection ceiling");
        }
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &evidence,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::InsufficientCapacity
            )))
        ));

        let (snapshot, mut evidence) = snapshot_fixture();
        for fresh in &mut evidence {
            fresh.reachable = false;
            fresh.rtt_ms = None;
        }
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &evidence,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::Unreachable
            )))
        ));
    }

    fn verified_exit_capacity(input: &ForwardedExitSelectionInput) -> Bandwidth {
        verify_forwarded_exit_selection_peer(input, &scope())
            .expect("valid forwarded-exit observation")
            .candidate
            .conservative_capacity_for(ServiceRole::Exit)
            .bandwidth
    }

    #[test]
    fn preselection_capacity_uses_component_min_of_advertisement_p25_and_ceiling() {
        let mut advertised_minimum = exit_input();
        advertised_minimum
            .authenticated
            .advertisement
            .capacity
            .estimated_free = Bandwidth::new(40, 39).expect("advertised capacity");
        advertised_minimum.fresh.locally_measured_p25 =
            Some(Bandwidth::new(60, 60).expect("measured p25"));
        advertised_minimum.fresh.preselection_capacity_ceiling =
            Bandwidth::new(50, 50).expect("preselection ceiling");
        assert_eq!(
            verified_exit_capacity(&advertised_minimum),
            Bandwidth::new(40, 39).expect("advertised component minimum")
        );

        let mut measured_minimum = exit_input();
        measured_minimum.fresh.locally_measured_p25 =
            Some(Bandwidth::new(31, 30).expect("measured p25"));
        measured_minimum.fresh.preselection_capacity_ceiling =
            Bandwidth::new(50, 50).expect("preselection ceiling");
        assert_eq!(
            verified_exit_capacity(&measured_minimum),
            Bandwidth::new(31, 30).expect("measured component minimum")
        );

        let mut ceiling_minimum = exit_input();
        ceiling_minimum.fresh.locally_measured_p25 =
            Some(Bandwidth::new(60, 60).expect("measured p25"));
        ceiling_minimum.fresh.preselection_capacity_ceiling =
            Bandwidth::new(21, 20).expect("preselection ceiling");
        assert_eq!(
            verified_exit_capacity(&ceiling_minimum),
            Bandwidth::new(21, 20).expect("ceiling component minimum")
        );
    }

    fn assert_control_relay_hard_filters_are_applied() {
        let (snapshot, evidence) = snapshot_fixture();
        assert!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &evidence,
                NOW_MS,
                &mut OsRng,
            )
            .is_ok(),
            "valid control and exit evidence must reach exit preflight"
        );

        let (snapshot, mut low_reserve) = snapshot_fixture();
        low_reserve[0].preselection_capacity_ceiling =
            Bandwidth::new(5, 5).expect("low control preselection ceiling");
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &low_reserve,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::InsufficientCapacity
            )))
        ));

        let (snapshot, mut unreachable) = snapshot_fixture();
        unreachable[0].reachable = false;
        unreachable[0].rtt_ms = None;
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &unreachable,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::Unreachable
            )))
        ));

        let (snapshot, mut unusable_address) = snapshot_fixture();
        unusable_address[0].network_address_usable = false;
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &unusable_address,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::UnusableNetworkAddress
            )))
        ));

        let (snapshot, mut locally_blocked) = snapshot_fixture();
        locally_blocked[0].locally_blocked = true;
        assert!(matches!(
            snapshot_exit_preflight_at(
                &snapshot,
                snapshot_parameters(),
                &locally_blocked,
                NOW_MS,
                &mut OsRng,
            ),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::LocallyBlocked
            )))
        ));
    }

    #[test]
    fn snapshot_preflight_preserves_exit_first_and_exact_multipath_bounds() {
        assert_multipath_exit_first_and_path_time();
        assert_udp_exact_single_path();
        assert_total_path_bound();
    }

    fn assert_multipath_exit_first_and_path_time() {
        let (snapshot, evidence) = snapshot_fixture();
        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("exit selected before path evidence");
        let binding = preflight.selected_exit_binding();
        let paths = snapshot_paths(&preflight);
        let request = preflight
            .complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([45; 16], [46; 16]),
                NOW_MS,
                &mut OsRng,
            )
            .expect("exact two-path preflight");
        assert_eq!(
            request.exit.selection_node_id().expect("exit selection id"),
            binding.node_id
        );
        assert_eq!(request.paths.len(), 2);
        assert_eq!(
            request
                .paths
                .iter()
                .map(|path| path.path_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );

        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("exit-first binding for path-time regression");
        let mut preselected_path = snapshot_paths(&preflight);
        preselected_path[0].observed_at_ms = NOW_MS - 1;
        assert!(
            matches!(
                preflight.complete_at(
                    &preselected_path,
                    deadlines(),
                    RouteSessionAuthority::for_test([53; 16], [54; 16]),
                    NOW_MS,
                    &mut OsRng,
                ),
                Err(SelectionBridgeError::EvidenceBinding)
            ),
            "relay-to-exit path evidence must be observed after exit selection"
        );

        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("second exit-first preflight");
        let one_path = snapshot_paths(&preflight)
            .into_iter()
            .take(1)
            .collect::<Vec<_>>();
        assert!(
            preflight
                .complete_at(
                    &one_path,
                    deadlines(),
                    RouteSessionAuthority::for_test([47; 16], [48; 16]),
                    NOW_MS,
                    &mut OsRng,
                )
                .is_err()
        );
    }

    fn assert_udp_exact_single_path() {
        let (snapshot, mut udp_evidence) = snapshot_fixture();
        for fresh in &mut udp_evidence {
            fresh.transport = SelectionTransport::UdpSinglePath;
        }
        let mut udp_parameters = snapshot_parameters();
        udp_parameters.transport = SelectionTransport::UdpSinglePath;
        udp_parameters.relay_policy.active_paths = 1;
        udp_parameters.relay_policy.minimum_paths = 1;
        udp_parameters.relay_policy.maximum_paths = 1;
        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            udp_parameters,
            &udp_evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("single-path UDP exit preflight");
        let mut udp_paths = snapshot_paths(&preflight);
        for path in &mut udp_paths {
            path.transport = SelectionTransport::UdpSinglePath;
        }
        let request = preflight
            .complete_at(
                &udp_paths[..1],
                deadlines(),
                RouteSessionAuthority::for_test([51; 16], [52; 16]),
                NOW_MS,
                &mut OsRng,
            )
            .expect("exactly one UDP relay");
        assert_eq!(request.paths.len(), 1);
        assert_eq!(request.paths[0].path_id, 1);
    }

    fn assert_total_path_bound() {
        let (snapshot, evidence) = snapshot_fixture();
        let mut invalid_bound = snapshot_parameters();
        invalid_bound.relay_policy.active_paths = 8;
        invalid_bound.relay_policy.minimum_paths = 2;
        invalid_bound.relay_policy.maximum_paths = 8;
        invalid_bound.relay_policy.warm_backup_paths = 1;
        let preflight =
            snapshot_exit_preflight_at(&snapshot, invalid_bound, &evidence, NOW_MS, &mut OsRng)
                .expect("exit selection precedes relay-policy application");
        let paths = snapshot_paths(&preflight);
        assert!(
            matches!(
                preflight.complete_at(
                    &paths,
                    deadlines(),
                    RouteSessionAuthority::for_test([55; 16], [56; 16]),
                    NOW_MS,
                    &mut OsRng,
                ),
                Err(SelectionBridgeError::Selection(
                    SelectionError::InvalidPolicy
                ))
            ),
            "active plus warm relay paths may never exceed the hard maximum"
        );
    }

    #[test]
    fn verified_exit_is_selected_before_exact_complete_relay_paths() {
        let selected = selected_exit(scope());
        let exit_node = selected.selected.node_id.clone();
        let paths = two_relay_paths(selected.evidence_binding());
        let expected_relays = paths
            .iter()
            .map(|path| path.relay_node_id.clone())
            .collect::<HashSet<_>>();
        let request = selected
            .select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([1; 16], [2; 16]),
                &mut OsRng,
            )
            .expect("proof-bound setup input");

        assert_eq!(
            request.exit.selection_node_id().expect("exit selection id"),
            exit_node
        );
        assert_eq!(request.paths.len(), 2);
        assert_eq!(
            request
                .paths
                .iter()
                .map(|path| {
                    path.proof
                        .relay
                        .selection_node_id()
                        .expect("relay selection id")
                })
                .collect::<HashSet<_>>(),
            expected_relays
        );
        for path in &request.paths {
            let relay_node_id = path
                .proof
                .relay
                .selection_node_id()
                .expect("relay capability");
            assert!(expected_relays.contains(&relay_node_id));
            assert_eq!(path.proof.evidence_batch_id, EVIDENCE_BATCH_BYTES);
        }
        assert_eq!(
            request.parameters.allowed_transports,
            vec![ProtocolTransport::TcpMptcp]
        );
        assert_eq!(
            request.parameters.probe_address_family,
            ProbeAddressFamily::Ipv4
        );
        assert_eq!(
            request.parameters.post_probe_policy.requirements,
            scope().requirements(ServiceRole::Relay)
        );
        assert_eq!(
            request.parameters.post_probe_policy.relay_policy,
            scope().relay_policy
        );
        assert_eq!(request.parameters.policy_hash, POLICY_BYTES);
        assert_eq!(request.parameters.reserved_up_mbps, 10);
        assert_eq!(request.parameters.reserved_down_mbps, 10);
        assert_eq!(request.parameters.created_at_ms, NOW_MS);
        assert_eq!(request.parameters.expires_at_ms, NOW_MS + 60_000);
        assert_ne!(
            request.parameters.reservation_id,
            request.parameters.route_context_id
        );
    }

    #[test]
    fn os_random_session_authority_is_nonzero_distinct_and_redacted() {
        let authority = RouteSessionAuthority::generate().expect("OS randomness");
        assert!(authority.reservation_id.iter().any(|byte| *byte != 0));
        assert!(authority.route_context_id.iter().any(|byte| *byte != 0));
        assert_ne!(authority.reservation_id, authority.route_context_id);
        assert!(!format!("{authority:?}").contains(&hex::encode(authority.reservation_id)));
    }

    #[test]
    fn direct_combined_advertisement_remains_relay_only_metadata() {
        let stored = signed_peer(
            70,
            true,
            true,
            "operator-combined",
            64_498,
            Ipv4Addr::new(43, 1, 1, 1),
            POLICY_BYTES,
            NOW_MS + 120_000,
        );
        let input = relay_input(&stored, Ipv4Addr::new(43, 1, 1, 1));
        let verified =
            verify_direct_relay_selection_peer(&input, &scope()).expect("direct relay proof");

        assert!(verified.candidate.advertisement.roles.exit);
        let _: ProspectiveDirectRelay = verified.prospective;
        // The direct projection is relay-only by type; exit selection accepts only
        // ForwardedExitSelectionInput.
    }

    #[test]
    fn forwarded_exit_is_crossbound_to_control_and_exit_actor_snapshots() {
        let input = exit_input();
        let verified =
            verify_forwarded_exit_selection_peer(&input, &scope()).expect("forwarded exit proof");
        assert_ne!(
            verified.prospective.authority.control.identity.wire_node_id,
            verified.prospective.authority.exit.wire_node_id
        );
        assert_eq!(
            verified
                .prospective
                .authority
                .control
                .identity
                .advertisement_sequence,
            input.capability.control_relay_advertisement_sequence
        );
        assert_eq!(
            verified.prospective.authority.exit.advertisement_sequence,
            input.capability.exit_advertisement_sequence
        );
    }

    #[test]
    fn forwarded_exit_actor_identity_sequence_and_policy_substitution_fail_closed() {
        let mut request_bounded_exit = exit_input();
        request_bounded_exit.capability.expires_at_ms = NOW_MS + 30_000;
        request_bounded_exit.fresh.capability_expires_at_ms = NOW_MS + 30_000;
        request_bounded_exit.fresh.valid_until_ms = NOW_MS + 30_000;
        assert!(
            select_exit_first(scope(), &[request_bounded_exit], &mut OsRng).is_ok(),
            "a forwarded exit may be bounded below advertisement/policy expiry by its fetch authority"
        );

        let mut wrong_exit_sequence = exit_input();
        wrong_exit_sequence.capability.exit_advertisement_sequence += 1;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_exit_sequence], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut wrong_control_sequence = exit_input();
        wrong_control_sequence
            .capability
            .control_relay_advertisement_sequence += 1;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_control_sequence], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut wrong_control_identity = exit_input();
        wrong_control_identity.capability.control_relay_peer_id =
            wrong_control_identity.capability.exit_peer_id;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_control_identity], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut wrong_policy = exit_input();
        wrong_policy.capability.policy_hash = [88; 32];
        assert!(matches!(
            select_exit_first(scope(), &[wrong_policy], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut wrong_control_metadata = exit_input();
        wrong_control_metadata.control.fresh.advertisement_sequence += 1;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_control_metadata], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn stale_or_misbound_peer_and_complete_path_evidence_fails_closed() {
        let mut stale = exit_input();
        stale.fresh.observed_at_ms = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS - 1;
        assert!(matches!(
            select_exit_first(scope(), &[stale], &mut OsRng),
            Err(SelectionBridgeError::StaleEvidence)
        ));

        let mut wrong_sequence = exit_input();
        wrong_sequence.fresh.advertisement_sequence += 1;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_sequence], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].exit.advertisement_sequence += 1;
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([3; 16], [4; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    fn assert_payload_hash_selection_splices_fail_closed() {
        let mut exit_fresh = exit_input();
        exit_fresh.fresh.advertisement_payload_hash =
            exit_fresh.fresh.advertisement_payload_hash.xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[exit_fresh], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut exit_advertisement = exit_input();
        exit_advertisement.authenticated.advertisement_payload_hash = exit_advertisement
            .authenticated
            .advertisement_payload_hash
            .xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[exit_advertisement], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut exit_capability = exit_input();
        exit_capability.capability.exit_advertisement_payload_hash = exit_capability
            .capability
            .exit_advertisement_payload_hash
            .xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[exit_capability], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut control_binding = exit_input();
        let binding = control_binding
            .fresh
            .forwarded_control
            .as_mut()
            .expect("forwarded control binding");
        binding.advertisement_payload_hash = binding.advertisement_payload_hash.xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[control_binding], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut control_advertisement = exit_input();
        control_advertisement
            .control
            .authenticated
            .advertisement_payload_hash = control_advertisement
            .control
            .authenticated
            .advertisement_payload_hash
            .xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[control_advertisement], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut control_capability = exit_input();
        control_capability
            .capability
            .control_relay_advertisement_payload_hash = control_capability
            .capability
            .control_relay_advertisement_payload_hash
            .xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[control_capability], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut direct_control_capability = exit_input();
        direct_control_capability
            .control
            .capability
            .advertisement_payload_hash = direct_control_capability
            .control
            .capability
            .advertisement_payload_hash
            .xor_for_test();
        assert!(matches!(
            select_exit_first(scope(), &[direct_control_capability], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));
    }

    fn assert_payload_hash_path_splices_fail_closed() {
        for selected_hash in 0_u8..2 {
            let selected = selected_exit(scope());
            let mut paths = two_relay_paths(selected.evidence_binding());
            if selected_hash == 0 {
                paths[0].exit.control_advertisement_payload_hash = paths[0]
                    .exit
                    .control_advertisement_payload_hash
                    .xor_for_test();
            } else {
                paths[0].exit.advertisement_payload_hash =
                    paths[0].exit.advertisement_payload_hash.xor_for_test();
            }
            assert!(matches!(
                selected.select_relays_and_build(
                    &paths,
                    deadlines(),
                    RouteSessionAuthority::for_test(
                        [31 + selected_hash; 16],
                        [41 + selected_hash; 16],
                    ),
                    &mut OsRng,
                ),
                Err(SelectionBridgeError::EvidenceBinding)
            ));
        }

        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].relay_advertisement_payload_hash =
            paths[0].relay_advertisement_payload_hash.xor_for_test();
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([51; 16], [52; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn payload_hash_splices_fail_closed_at_every_selection_and_path_boundary() {
        assert_payload_hash_selection_splices_fail_closed();
        assert_payload_hash_path_splices_fail_closed();
    }

    #[test]
    fn policy_expiry_substitution_is_rejected_before_selection() {
        let mut wrong_policy_expiry = exit_input();
        wrong_policy_expiry.fresh.policy_expires_at_ms += 1;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_policy_expiry], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn active_policy_transport_and_capacity_are_hard_filters() {
        let mut wrong_policy_scope = scope();
        wrong_policy_scope.policy.hash = PolicyHash::from_bytes([88; 32]);
        let mut wrong_policy = exit_input();
        wrong_policy.fresh.policy_hash = wrong_policy_scope.policy.hash;
        wrong_policy.control.fresh.policy_hash = wrong_policy_scope.policy.hash;
        assert!(matches!(
            select_exit_first(wrong_policy_scope, &[wrong_policy], &mut OsRng),
            Err(SelectionBridgeError::AdvertisementProvenance)
        ));

        let mut wrong_transport = exit_input();
        wrong_transport.fresh.transport = SelectionTransport::UdpSinglePath;
        assert!(matches!(
            select_exit_first(scope(), &[wrong_transport], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut insufficient = exit_input();
        insufficient.fresh.preselection_capacity_ceiling =
            Bandwidth::new(5, 5).expect("small preselection ceiling");
        assert!(matches!(
            select_exit_first(scope(), &[insufficient], &mut OsRng),
            Err(SelectionBridgeError::Selection(SelectionError::HardFilter(
                HardFilterReason::InsufficientCapacity
            )))
        ));
    }

    #[test]
    fn missing_or_misbound_address_family_fails_closed() {
        let mut missing_family = scope();
        missing_family.address_family = None;
        assert!(matches!(
            select_exit_first(missing_family, &[exit_input()], &mut OsRng),
            Err(SelectionBridgeError::InvalidScope)
        ));

        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].probe_address_family = ProbeAddressFamily::Ipv6;
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([21; 16], [22; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn missing_asn_for_control_exit_or_relay_fails_closed() {
        let control_address = IpAddr::V4(Ipv4Addr::new(44, 1, 1, 1));
        let exit_address = IpAddr::V4(Ipv4Addr::new(45, 1, 1, 1));
        for input in [
            exit_input_for_addresses_with_asns(control_address, exit_address, 0, 64_500),
            exit_input_for_addresses_with_asns(control_address, exit_address, 64_499, 0),
        ] {
            assert!(matches!(
                select_exit_first(scope(), &[input], &mut OsRng),
                Err(SelectionBridgeError::EvidenceBinding)
            ));
        }

        let selected = selected_exit(scope());
        let binding = selected.evidence_binding();
        let mut paths = two_relay_paths(binding.clone());
        paths[0] = relay_path(
            binding,
            93,
            "operator-relay-missing-asn",
            0,
            Ipv4Addr::new(48, 3, 3, 3),
            15.0,
        );
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([25; 16], [26; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn ipv6_scope_projects_exact_probe_family_and_selector_requirements() {
        let selected = select_exit_first(ipv6_scope(), &[ipv6_exit_input()], &mut OsRng)
            .expect("selected IPv6 exit");
        let paths = two_ipv6_relay_paths(selected.evidence_binding());
        let request = selected
            .select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([23; 16], [24; 16]),
                &mut OsRng,
            )
            .expect("IPv6 setup request");

        assert_eq!(
            request.parameters.probe_address_family,
            ProbeAddressFamily::Ipv6
        );
        assert_eq!(
            request
                .parameters
                .post_probe_policy
                .requirements
                .address_family,
            Some(IpFamily::Ipv6)
        );
        assert!(
            request
                .paths
                .iter()
                .all(|path| path.proof.diversity.prefix.family() == IpFamily::Ipv6)
        );
    }

    #[test]
    fn control_and_exit_with_overlapping_origin_are_rejected_before_exit_scoring() {
        let input = exit_input_for_addresses(
            IpAddr::V4(Ipv4Addr::new(44, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(44, 1, 1, 2)),
        );
        assert!(matches!(
            select_exit_first(scope(), &[input], &mut OsRng),
            Err(SelectionBridgeError::EvidenceBinding)
        ));
    }

    #[test]
    fn relay_operator_overlap_with_control_is_filtered_before_scoring() {
        let selected = selected_exit(scope());
        let exit = selected.evidence_binding();
        let conflict = relay_path(
            exit.clone(),
            31,
            "operator-control",
            64_531,
            Ipv4Addr::new(48, 1, 1, 1),
            1.0,
        );
        assert_cross_stage_conflict_is_filtered(&selected, conflict, two_relay_paths(exit));
    }

    #[test]
    fn relay_asn_overlap_with_exit_is_filtered_before_scoring() {
        let selected = selected_exit(scope());
        let exit = selected.evidence_binding();
        let conflict = relay_path(
            exit.clone(),
            32,
            "operator-relay-asn-conflict",
            64_500,
            Ipv4Addr::new(48, 2, 2, 2),
            1.0,
        );
        assert_cross_stage_conflict_is_filtered(&selected, conflict, two_relay_paths(exit));
    }

    #[test]
    fn relay_ipv4_24_overlap_with_control_is_filtered_before_scoring() {
        let selected = selected_exit(scope());
        let exit = selected.evidence_binding();
        let conflict = relay_path(
            exit.clone(),
            33,
            "operator-relay-v4-conflict",
            64_533,
            Ipv4Addr::new(44, 1, 1, 99),
            1.0,
        );
        assert_cross_stage_conflict_is_filtered(&selected, conflict, two_relay_paths(exit));
    }

    #[test]
    fn relay_exact_origin_overlap_with_exit_is_filtered_before_scoring() {
        let selected = selected_exit(scope());
        let exit = selected.evidence_binding();
        let conflict = relay_path(
            exit.clone(),
            34,
            "operator-relay-origin-conflict",
            64_534,
            Ipv4Addr::new(45, 1, 1, 1),
            1.0,
        );
        assert_cross_stage_conflict_is_filtered(&selected, conflict, two_relay_paths(exit));
    }

    #[test]
    fn relay_ipv6_48_overlap_with_control_is_filtered_before_scoring() {
        let selected = select_exit_first(ipv6_scope(), &[ipv6_exit_input()], &mut OsRng)
            .expect("selected IPv6 exit");
        let exit = selected.evidence_binding();
        let conflict = relay_path(
            exit.clone(),
            35,
            "operator-relay-v6-conflict",
            64_535,
            Ipv6Addr::new(0x2606, 0x4700, 0x0100, 0xabcd, 0, 0, 0, 9),
            1.0,
        );
        assert_cross_stage_conflict_is_filtered(&selected, conflict, two_ipv6_relay_paths(exit));
    }

    #[test]
    fn post_probe_policy_preserves_selector_contract_and_warm_bound() {
        let mut route_scope = scope();
        route_scope.relay_policy.maximum_paths = 4;
        route_scope.relay_policy.warm_backup_paths = 2;
        let expected_policy = route_scope.relay_policy;
        let expected_requirements = route_scope.requirements(ServiceRole::Relay);
        let parameters = build_parameters(
            RouteSessionAuthority::for_test([25; 16], [26; 16]),
            &route_scope,
            deadlines(),
            NOW_MS + 90_000,
            NOW_MS + 60_000,
        )
        .expect("representable post-probe policy");

        assert_eq!(
            parameters.post_probe_policy.requirements,
            expected_requirements
        );
        assert_eq!(parameters.post_probe_policy.relay_policy, expected_policy);
    }

    #[test]
    fn non_finite_or_out_of_range_gain_policy_fails_closed() {
        for (index, invalid_ratio) in [f64::NAN, f64::INFINITY, f64::MAX].into_iter().enumerate() {
            let mut invalid_scope = scope();
            invalid_scope
                .relay_policy
                .minimum_unique_throughput_gain_ratio = invalid_ratio;
            let selected = selected_exit(invalid_scope);
            let paths = two_relay_paths(selected.evidence_binding());
            let id = u8::try_from(index).expect("small index");
            assert!(matches!(
                selected.select_relays_and_build(
                    &paths,
                    deadlines(),
                    RouteSessionAuthority::for_test([30 + id; 16], [40 + id; 16]),
                    &mut OsRng,
                ),
                Err(SelectionBridgeError::Selection(
                    SelectionError::InvalidPolicy
                ))
            ));
        }
    }

    #[test]
    fn weak_warm_projection_is_not_admitted_without_failover_evidence() {
        let selected = selected_exit(scope());
        let paths = two_relay_paths(selected.evidence_binding());
        let (_, projected, metrics) =
            verify_complete_relay_paths(&selected, &paths).expect("typed path projection");
        assert_eq!(projected.len(), paths.len());
        assert_eq!(metrics.len(), paths.len());
        assert!(!warm_path_is_admissible(0.0, false, scope().relay_policy,));
        assert!(warm_path_is_admissible(0.0, true, scope().relay_policy,));
    }

    #[test]
    fn setup_must_finish_before_selected_exit_or_path_evidence_expires() {
        let mut old_exit = exit_input();
        old_exit.fresh.observed_at_ms = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS + 1;
        old_exit.fresh.valid_until_ms = NOW_MS + 1;
        let selected =
            select_exit_first(scope(), &[old_exit], &mut OsRng).expect("boundary-fresh exit");
        let paths = two_relay_paths(selected.evidence_binding());
        let setup_after_exit_evidence = RouteDeadlines {
            setup_expires_at_ms: NOW_MS + 1_000,
            hard_expires_at_ms: NOW_MS + 60_000,
        };
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                setup_after_exit_evidence,
                RouteSessionAuthority::for_test([9; 16], [10; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::InvalidDeadline)
        ));

        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].relay.fresh.observed_at_ms = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS + 1;
        paths[0].relay.fresh.valid_until_ms = NOW_MS + 1;
        paths[0].observed_at_ms = NOW_MS - MAXIMUM_EVIDENCE_AGE_MS + 1;
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                setup_after_exit_evidence,
                RouteSessionAuthority::for_test([11; 16], [12; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::InvalidDeadline)
        ));
    }

    #[test]
    fn deadlines_and_multipath_active_count_fail_closed() {
        let selected = selected_exit(scope());
        let paths = two_relay_paths(selected.evidence_binding());
        let beyond_policy = RouteDeadlines {
            setup_expires_at_ms: NOW_MS + 20_000,
            hard_expires_at_ms: NOW_MS + 90_001,
        };
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                beyond_policy,
                RouteSessionAuthority::for_test([5; 16], [6; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::InvalidDeadline)
        ));

        let mut warm_is_not_active = scope();
        warm_is_not_active.relay_policy.active_paths = 1;
        warm_is_not_active.relay_policy.minimum_paths = 1;
        warm_is_not_active.relay_policy.maximum_paths = 2;
        warm_is_not_active.relay_policy.warm_backup_paths = 1;
        let selected = selected_exit(warm_is_not_active);
        let paths = two_relay_paths(selected.evidence_binding());
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([7; 16], [8; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::SelectedIdentityMismatch)
        ));
    }

    #[test]
    fn actor_freshness_precedes_later_complete_path_evidence_without_becoming_its_authority() {
        let (snapshot, evidence) = snapshot_fixture();
        let preflight = snapshot_exit_preflight_at(
            &snapshot,
            snapshot_parameters(),
            &evidence,
            NOW_MS,
            &mut OsRng,
        )
        .expect("selected exit at actor-evidence time");
        let mut paths = snapshot_paths(&preflight);
        for path in &mut paths {
            path.observed_at_ms = NOW_MS + 1_000;
        }
        let request = preflight
            .complete_at(
                &paths,
                deadlines(),
                RouteSessionAuthority::for_test([81; 16], [82; 16]),
                NOW_MS + 1_000,
                &mut OsRng,
            )
            .expect("later complete-path evidence remains distinct from actor freshness");
        assert!(request.paths.iter().all(|path| {
            path.proof.actor_evidence_observed_at_ms == NOW_MS
                && path.proof.projected_at_ms == NOW_MS + 1_000
        }));
    }

    #[test]
    fn actor_evidence_window_bounds_setup_before_request_construction() {
        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].relay.fresh.valid_until_ms = NOW_MS + 10_000;
        assert!(matches!(
            selected.select_relays_and_build(
                &paths,
                RouteDeadlines {
                    setup_expires_at_ms: NOW_MS + 10_001,
                    hard_expires_at_ms: NOW_MS + 60_000,
                },
                RouteSessionAuthority::for_test([83; 16], [84; 16]),
                &mut OsRng,
            ),
            Err(SelectionBridgeError::InvalidDeadline)
        ));

        let selected = selected_exit(scope());
        let mut paths = two_relay_paths(selected.evidence_binding());
        paths[0].relay.fresh.valid_until_ms = NOW_MS + 10_000;
        assert!(
            selected
                .select_relays_and_build(
                    &paths,
                    RouteDeadlines {
                        setup_expires_at_ms: NOW_MS + 10_000,
                        hard_expires_at_ms: NOW_MS + 60_000,
                    },
                    RouteSessionAuthority::for_test([85; 16], [86; 16]),
                    &mut OsRng,
                )
                .is_ok()
        );
    }

    #[test]
    fn actor_bound_mint_rejects_body_time_splices_and_future_actor_evidence() {
        let selected = selected_exit(scope());
        let path = two_relay_paths(selected.evidence_binding())
            .into_iter()
            .next()
            .expect("relay path");
        let mut measured_splice = verify_direct_relay_selection_peer(&path.relay, &selected.scope)
            .expect("verified actor record");
        measured_splice.candidate.advertisement.measured_at =
            UnixTime::from_secs(measured_splice.advertisement_measured_at_ms / 1_000 + 1);
        assert!(matches!(
            mint_actor_bound_relay_proof(
                measured_splice,
                NOW_MS,
                selected.scope.requirements(ServiceRole::Relay),
                &selected.forwarded_exit.authority,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut expiry_splice = verify_direct_relay_selection_peer(&path.relay, &selected.scope)
            .expect("verified actor record");
        expiry_splice.candidate.advertisement.expires_at =
            UnixTime::from_secs(expiry_splice.advertisement_expires_at_ms / 1_000 + 1);
        assert!(matches!(
            mint_actor_bound_relay_proof(
                expiry_splice,
                NOW_MS,
                selected.scope.requirements(ServiceRole::Relay),
                &selected.forwarded_exit.authority,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut widened_actor_window =
            verify_direct_relay_selection_peer(&path.relay, &selected.scope)
                .expect("verified actor record");
        widened_actor_window.actor_evidence_valid_until_ms -= 1;
        assert!(matches!(
            mint_actor_bound_relay_proof(
                widened_actor_window,
                NOW_MS,
                selected.scope.requirements(ServiceRole::Relay),
                &selected.forwarded_exit.authority,
            ),
            Err(SelectionBridgeError::EvidenceBinding)
        ));

        let mut future_actor = path.relay;
        future_actor.fresh.observed_at_ms = NOW_MS + 1;
        assert!(matches!(
            verify_direct_relay_selection_peer(&future_actor, &selected.scope),
            Err(SelectionBridgeError::StaleEvidence)
        ));
    }
}
