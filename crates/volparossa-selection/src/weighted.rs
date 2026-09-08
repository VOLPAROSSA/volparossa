use crate::{
    Candidate, FilterRequirements, HardFilterReason, PrefixObservedCandidate,
    candidate::hard_filter_with_observed_prefix, hard_filter,
};
use rand::Rng;
use std::{borrow::Borrow, collections::HashSet};
use thiserror::Error;
use volparossa_core::{
    Bandwidth, IpFamily, NodeId, ObservedNetworkOrigin, ObservedNetworkPrefix, OperatorId, PeerId,
    PolicyHash, ServiceRole, Transport, UnixTime,
};

/// Hard allocation bound for one exit or relay selection pass.
pub const MAXIMUM_SELECTION_CANDIDATES: usize = 200;
/// Hard limit for relays admitted to one prospective measurement slate.
pub const MAXIMUM_PROSPECTIVE_RELAYS: usize = 8;

const CAPACITY_WEIGHT: f64 = 0.30;
const HISTORY_WEIGHT: f64 = 0.20;
const UPTIME_WEIGHT: f64 = 0.15;
const PATH_OR_EGRESS_QUALITY_WEIGHT: f64 = 0.15;
const REPUTATION_WEIGHT: f64 = 0.10;
const BALANCE_OR_DIVERSITY_WEIGHT: f64 = 0.10;
const MAXIMUM_RTT_SPREAD_MS: f64 = 1_000.0;

/// Membership of one of the randomized 70/20/10 pools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionBand {
    /// High-scoring, locally measured candidates.
    High,
    /// Diverse candidates from the measured middle group.
    DiverseMiddle,
    /// New or sparsely measured candidates receiving bounded exploration.
    Exploration,
}

/// Probabilities for high, diverse-middle and exploration pools.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelectionMix {
    /// Probability of sampling the high-scoring pool.
    pub high: f64,
    /// Probability of sampling the diverse middle pool.
    pub diverse_middle: f64,
    /// Probability of sampling the exploration pool.
    pub exploration: f64,
}

impl Default for SelectionMix {
    fn default() -> Self {
        Self {
            high: 0.70,
            diverse_middle: 0.20,
            exploration: 0.10,
        }
    }
}

impl SelectionMix {
    fn validate(self) -> Result<(), SelectionError> {
        if [self.high, self.diverse_middle, self.exploration]
            .into_iter()
            .any(|value| !value.is_finite() || value < 0.0)
            || (self.high + self.diverse_middle + self.exploration - 1.0).abs() > 1e-9
        {
            return Err(SelectionError::InvalidPolicy);
        }
        Ok(())
    }
}

/// One already selected identity that prospective relays must remain diverse from.
#[derive(Clone, Eq, PartialEq)]
pub struct DiversityAnchor {
    node_id: NodeId,
    peer_id: PeerId,
    operator_id: OperatorId,
    asn: Option<u32>,
    observed_network_prefix: ObservedNetworkPrefix,
    legacy_origin_equality_key: Option<ObservedNetworkOrigin>,
}

impl std::fmt::Debug for DiversityAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiversityAnchor")
            .field("identity", &"[REDACTED]")
            .field("network_origin", &"[REDACTED]")
            .finish()
    }
}

impl DiversityAnchor {
    /// Creates one fully observed diversity anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::InvalidDiversityAnchors`] when the ASN is the reserved zero
    /// value or the observed origin is not a public-routable IP address.
    pub fn new(
        node_id: NodeId,
        peer_id: PeerId,
        operator_id: OperatorId,
        asn: u32,
        observed_network_origin: ObservedNetworkOrigin,
    ) -> Result<Self, SelectionError> {
        Self::from_parts(
            node_id,
            peer_id,
            operator_id,
            asn,
            ObservedNetworkPrefix::from_origin(observed_network_origin),
            Some(observed_network_origin),
            ServiceRole::Exit,
        )
    }

    /// Creates one fully observed prefix-native diversity anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::InvalidDiversityAnchors`] when the ASN is zero or the normalized
    /// prefix is not public-routable.
    pub fn from_observed_prefix(
        node_id: NodeId,
        peer_id: PeerId,
        operator_id: OperatorId,
        asn: u32,
        observed_network_prefix: ObservedNetworkPrefix,
    ) -> Result<Self, SelectionError> {
        Self::from_parts(
            node_id,
            peer_id,
            operator_id,
            asn,
            observed_network_prefix,
            None,
            ServiceRole::Exit,
        )
    }

    /// Creates an explicitly direct-Relay anchor with either public or local-LAN observations.
    ///
    /// A local prefix stays a local collision key, never a public origin claim. The ASN must
    /// still be a nonzero independent-uplink claim; this does not admit unknown-ASN local relays.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::InvalidDiversityAnchors`] for zero ASN or invalid scoped prefix.
    pub fn from_direct_relay_prefix(
        node_id: NodeId,
        peer_id: PeerId,
        operator_id: OperatorId,
        asn: u32,
        observed_network_prefix: ObservedNetworkPrefix,
    ) -> Result<Self, SelectionError> {
        Self::from_parts(
            node_id,
            peer_id,
            operator_id,
            asn,
            observed_network_prefix,
            None,
            ServiceRole::Relay,
        )
    }

    /// Creates an anchor from explicitly scoped authenticated prefix evidence.
    ///
    /// An absent Internet ASN is permitted only for a local-LAN Relay and occupies the route's
    /// single unknown-origin slot. It never proves a distinct Internet failure domain.
    ///
    /// # Errors
    ///
    /// Rejects zero ASN, unscoped prefixes, and unknown-origin Exit or public observations.
    pub fn from_scoped_prefix(
        node_id: NodeId,
        peer_id: PeerId,
        operator_id: OperatorId,
        asn: Option<u32>,
        observed_network_prefix: ObservedNetworkPrefix,
        role: ServiceRole,
    ) -> Result<Self, SelectionError> {
        let valid = match asn {
            Some(asn) => {
                asn != 0
                    && (observed_network_prefix.is_public_routable()
                        || observed_network_prefix.is_local_lan())
            }
            None => role == ServiceRole::Relay && observed_network_prefix.is_local_lan(),
        };
        if !valid {
            return Err(SelectionError::InvalidDiversityAnchors);
        }
        Ok(Self {
            node_id,
            peer_id,
            operator_id,
            asn,
            observed_network_prefix,
            legacy_origin_equality_key: None,
        })
    }

    fn from_parts(
        node_id: NodeId,
        peer_id: PeerId,
        operator_id: OperatorId,
        asn: u32,
        observed_network_prefix: ObservedNetworkPrefix,
        legacy_origin_equality_key: Option<ObservedNetworkOrigin>,
        role: ServiceRole,
    ) -> Result<Self, SelectionError> {
        if asn == 0
            || !(observed_network_prefix.is_public_routable()
                || (role == ServiceRole::Relay && observed_network_prefix.is_local_lan()))
        {
            return Err(SelectionError::InvalidDiversityAnchors);
        }
        Ok(Self {
            node_id,
            peer_id,
            operator_id,
            asn: Some(asn),
            observed_network_prefix,
            legacy_origin_equality_key,
        })
    }

    /// Permanent node identity represented by this anchor.
    #[must_use]
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Authenticated libp2p identity represented by this anchor.
    #[must_use]
    pub const fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// Bounds and randomized pool mix for prospective relay measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProspectiveRelayPolicy {
    minimum_relays: usize,
    maximum_relays: usize,
    mix: SelectionMix,
}

impl ProspectiveRelayPolicy {
    /// Creates bounded prospective-relay policy.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::InvalidPolicy`] unless `1 <= minimum <= maximum <= 8` and the
    /// supplied mix is valid.
    pub fn new(
        minimum_relays: usize,
        maximum_relays: usize,
        mix: SelectionMix,
    ) -> Result<Self, SelectionError> {
        let policy = Self {
            minimum_relays,
            maximum_relays,
            mix,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Fail-closed minimum slate size.
    #[must_use]
    pub const fn minimum_relays(self) -> usize {
        self.minimum_relays
    }

    /// Hard maximum slate size.
    #[must_use]
    pub const fn maximum_relays(self) -> usize {
        self.maximum_relays
    }

    fn validate(self) -> Result<(), SelectionError> {
        self.mix.validate()?;
        if self.minimum_relays == 0
            || self.minimum_relays > self.maximum_relays
            || self.maximum_relays > MAXIMUM_PROSPECTIVE_RELAYS
        {
            return Err(SelectionError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Getter-only prospective relay slate selected for later complete-path measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct ProspectiveRelaySelection {
    relays: Vec<SelectedNode>,
}

impl ProspectiveRelaySelection {
    /// Selected relay identities in randomized sampling order.
    #[must_use]
    pub fn relays(&self) -> &[SelectedNode] {
        &self.relays
    }
}

/// A selected exit or generic node and its auditable local score.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedNode {
    /// Permanent node identity.
    pub node_id: NodeId,
    /// Authenticated libp2p peer identity bound by the selected advertisement.
    pub peer_id: PeerId,
    /// Weighted local score in the inclusive range 0 through 1.
    pub score: f64,
    /// Pool from which the randomized sample was drawn.
    pub band: SelectionBand,
}

/// Route-specific evidence for `client -> relay -> selected exit`.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayPathCandidate {
    /// Relay advertisement and local peer evidence.
    pub relay: Candidate,
    /// Locally estimated client-to-relay capacity.
    pub client_to_relay_capacity: Bandwidth,
    /// Locally measured relay-to-exit capacity.
    pub relay_to_exit_capacity: Bandwidth,
    /// Capacity reserved at the already selected exit.
    pub exit_reserved_capacity: Bandwidth,
    /// Client-to-relay RTT in milliseconds.
    pub client_to_relay_rtt_ms: f64,
    /// Relay-to-exit RTT in milliseconds.
    pub relay_to_exit_rtt_ms: f64,
    /// Expected unique-throughput gain relative to the current active set.
    pub unique_throughput_gain_ratio: f64,
    /// Whether the path adds a meaningfully independent failover origin.
    pub meaningful_failover: bool,
}

impl RelayPathCandidate {
    /// Computes the four-way bottleneck for the complete relay path.
    #[must_use]
    pub fn path_capacity(&self) -> Bandwidth {
        self.client_to_relay_capacity
            .component_min(
                self.relay
                    .conservative_capacity_for(ServiceRole::Relay)
                    .bandwidth,
            )
            .component_min(self.relay_to_exit_capacity)
            .component_min(self.exit_reserved_capacity)
    }

    /// Computes end-to-end RTT across both `WireGuard` legs.
    #[must_use]
    pub fn end_to_end_rtt_ms(&self) -> f64 {
        self.client_to_relay_rtt_ms + self.relay_to_exit_rtt_ms
    }

    fn validate(&self) -> Result<(), SelectionError> {
        self.client_to_relay_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        self.relay_to_exit_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        self.exit_reserved_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        if !self.client_to_relay_rtt_ms.is_finite()
            || self.client_to_relay_rtt_ms <= 0.0
            || !self.relay_to_exit_rtt_ms.is_finite()
            || self.relay_to_exit_rtt_ms <= 0.0
            || self.end_to_end_rtt_ms() > 120_000.0
            || !self.unique_throughput_gain_ratio.is_finite()
            || self.unique_throughput_gain_ratio < 0.0
            || self.unique_throughput_gain_ratio > 10.0
        {
            return Err(SelectionError::InvalidPathEvidence);
        }
        Ok(())
    }
}

/// Opaque, endpoint-free relay metadata admitted through the canonical hard filter.
///
/// Legacy construction consumes a full Candidate; prefix-native construction borrows a candidate
/// that already discarded its raw observed address. The projection intentionally has no Clone,
/// Copy, Debug or serialization implementation and exposes no raw identity, origin or local
/// history getters. It can only be used as input to complete-path selection.
pub struct RelaySelectionProjection {
    node_id: NodeId,
    peer_id: PeerId,
    operator_id: OperatorId,
    asn: Option<u32>,
    network_prefix: ObservedNetworkPrefix,
    conservative_capacity: Bandwidth,
    evidence: ProjectedRelayEvidence,
    scope: ProjectedRelayScope,
    advertisement_expires_at: UnixTime,
}

struct ProjectedRelayEvidence {
    locally_measured_p25: Option<Bandwidth>,
    uptime_score: f64,
    reputation_score: f64,
    exploration: bool,
}

struct ProjectedRelayScope {
    projected_at: UnixTime,
    transport: Transport,
    policy_hash: PolicyHash,
    minimum_capacity: Bandwidth,
    address_family: Option<IpFamily>,
    region: Option<String>,
    require_reachable: bool,
}

impl RelaySelectionProjection {
    /// Consumes a full relay candidate after the canonical hard filter and strips its
    /// advertisement, control endpoints, raw observed IP and signature-state bit.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-relay scope or the exact hard-filter failure.
    pub fn from_candidate(
        candidate: Candidate,
        requirements: &FilterRequirements,
    ) -> Result<Self, SelectionError> {
        if requirements.role != ServiceRole::Relay {
            return Err(SelectionError::WrongSelectionRole);
        }
        let capacity = hard_filter(&candidate, requirements)
            .map_err(SelectionError::HardFilter)?
            .bandwidth;
        let origin =
            candidate
                .evidence
                .observed_network_origin
                .ok_or(SelectionError::HardFilter(
                    HardFilterReason::UnusableNetworkAddress,
                ))?;
        let network_prefix = ObservedNetworkPrefix::from_origin(origin);
        if !network_prefix.is_public_routable()
            || requirements
                .address_family
                .is_some_and(|family| family != network_prefix.family())
        {
            return Err(SelectionError::HardFilter(
                HardFilterReason::UnusableNetworkAddress,
            ));
        }
        Ok(Self::from_filtered_candidate(
            candidate,
            network_prefix,
            capacity,
            requirements,
        ))
    }

    /// Borrows a raw-address-free candidate and retains only its validated canonical prefix.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-relay scope or the exact prefix-native hard-filter failure.
    pub fn from_prefix_observed_candidate(
        candidate: &PrefixObservedCandidate<'_>,
        requirements: &FilterRequirements,
    ) -> Result<Self, SelectionError> {
        if requirements.role != ServiceRole::Relay {
            return Err(SelectionError::WrongSelectionRole);
        }
        let capacity = hard_filter_with_observed_prefix(candidate, requirements)
            .map_err(SelectionError::HardFilter)?
            .bandwidth;
        Ok(Self::from_filtered_candidate(
            candidate.candidate,
            candidate.observed_network_prefix,
            capacity,
            requirements,
        ))
    }

    fn from_legacy_candidate(
        candidate: Candidate,
        requirements: &FilterRequirements,
    ) -> Result<Self, SelectionError> {
        if requirements.role != ServiceRole::Relay {
            return Err(SelectionError::WrongSelectionRole);
        }
        let capacity = hard_filter(&candidate, requirements)
            .map_err(SelectionError::HardFilter)?
            .bandwidth;
        let origin =
            candidate
                .evidence
                .observed_network_origin
                .ok_or(SelectionError::HardFilter(
                    HardFilterReason::UnusableNetworkAddress,
                ))?;
        Ok(Self::from_filtered_candidate(
            candidate,
            ObservedNetworkPrefix::from_origin(origin),
            capacity,
            requirements,
        ))
    }

    fn from_filtered_candidate<C: Borrow<Candidate>>(
        candidate: C,
        network_prefix: ObservedNetworkPrefix,
        capacity: Bandwidth,
        requirements: &FilterRequirements,
    ) -> Self {
        let candidate = candidate.borrow();
        let advertisement = &candidate.advertisement;
        let evidence = &candidate.evidence;
        let exploration = evidence.measurement_count < 3 || evidence.locally_measured_p25.is_none();
        Self {
            node_id: advertisement.node_id.clone(),
            peer_id: advertisement.peer_id.clone(),
            operator_id: advertisement.network.operator_id.clone(),
            asn: advertisement.network.asn,
            network_prefix,
            conservative_capacity: capacity,
            evidence: ProjectedRelayEvidence {
                locally_measured_p25: evidence.locally_measured_p25,
                uptime_score: evidence.uptime_score,
                reputation_score: evidence.reputation_score,
                exploration,
            },
            scope: ProjectedRelayScope {
                projected_at: requirements.now,
                transport: requirements.transport,
                policy_hash: requirements.policy_hash,
                minimum_capacity: requirements.minimum_capacity,
                address_family: requirements.address_family,
                region: requirements.region.clone(),
                require_reachable: requirements.require_reachable,
            },
            advertisement_expires_at: advertisement.expires_at,
        }
    }

    fn requirements_match(&self, requirements: &FilterRequirements) -> bool {
        requirements.role == ServiceRole::Relay
            && requirements.now >= self.scope.projected_at
            && !self
                .advertisement_expires_at
                .is_expired_at(requirements.now)
            && requirements.transport == self.scope.transport
            && requirements.policy_hash == self.scope.policy_hash
            && requirements.minimum_capacity == self.scope.minimum_capacity
            && requirements.address_family == self.scope.address_family
            && requirements.region == self.scope.region
            && requirements.require_reachable == self.scope.require_reachable
            && self
                .conservative_capacity
                .satisfies(requirements.minimum_capacity)
    }

    const fn is_exploration_candidate(&self) -> bool {
        self.evidence.exploration
    }
}

/// Endpoint-free complete-path scalar measurements.
///
/// Construction does not validate values. The canonical selector validates all scalar bounds.
pub struct CompleteRelayPathMetrics {
    client_to_relay_capacity: Bandwidth,
    relay_to_exit_capacity: Bandwidth,
    exit_reserved_capacity: Bandwidth,
    client_to_relay_rtt_ms: f64,
    relay_to_exit_rtt_ms: f64,
    unique_throughput_gain_ratio: f64,
    meaningful_failover: bool,
}

impl CompleteRelayPathMetrics {
    /// Groups the measured scalars for one complete relay path.
    #[must_use]
    pub const fn new(
        client_to_relay_capacity: Bandwidth,
        relay_to_exit_capacity: Bandwidth,
        exit_reserved_capacity: Bandwidth,
        client_to_relay_rtt_ms: f64,
        relay_to_exit_rtt_ms: f64,
        unique_throughput_gain_ratio: f64,
        meaningful_failover: bool,
    ) -> Self {
        Self {
            client_to_relay_capacity,
            relay_to_exit_capacity,
            exit_reserved_capacity,
            client_to_relay_rtt_ms,
            relay_to_exit_rtt_ms,
            unique_throughput_gain_ratio,
            meaningful_failover,
        }
    }
}

/// Complete-path measurements paired with one opaque relay projection.
///
/// The projection is borrowed and the metrics are consumed; the path cannot outlive the borrowed
/// projection. Inputs remain untrusted until `select_projected_relay_paths` validates all scalar
/// bounds.
pub struct ProjectedRelayPath<'a> {
    relay: &'a RelaySelectionProjection,
    metrics: CompleteRelayPathMetrics,
}

impl<'a> ProjectedRelayPath<'a> {
    /// Binds measured complete-path scalars to an endpoint-free relay projection.
    #[must_use]
    pub const fn new(
        relay: &'a RelaySelectionProjection,
        metrics: CompleteRelayPathMetrics,
    ) -> Self {
        Self { relay, metrics }
    }

    fn path_capacity(&self) -> Bandwidth {
        self.metrics
            .client_to_relay_capacity
            .component_min(self.relay.conservative_capacity)
            .component_min(self.metrics.relay_to_exit_capacity)
            .component_min(self.metrics.exit_reserved_capacity)
    }

    fn end_to_end_rtt_ms(&self) -> f64 {
        self.metrics.client_to_relay_rtt_ms + self.metrics.relay_to_exit_rtt_ms
    }

    fn validate(&self) -> Result<(), SelectionError> {
        self.metrics
            .client_to_relay_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        self.metrics
            .relay_to_exit_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        self.metrics
            .exit_reserved_capacity
            .validate()
            .map_err(|_| SelectionError::InvalidPathEvidence)?;
        if !self.metrics.client_to_relay_rtt_ms.is_finite()
            || self.metrics.client_to_relay_rtt_ms <= 0.0
            || !self.metrics.relay_to_exit_rtt_ms.is_finite()
            || self.metrics.relay_to_exit_rtt_ms <= 0.0
            || self.end_to_end_rtt_ms() > 120_000.0
            || !self.metrics.unique_throughput_gain_ratio.is_finite()
            || self.metrics.unique_throughput_gain_ratio < 0.0
            || self.metrics.unique_throughput_gain_ratio > 10.0
        {
            return Err(SelectionError::InvalidPathEvidence);
        }
        Ok(())
    }
}

/// Bounds and defaults for active and warm relay-path selection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelaySelectionPolicy {
    /// Desired number of active paths.
    pub active_paths: usize,
    /// Fail-closed minimum active paths.
    pub minimum_paths: usize,
    /// Hard active-path maximum.
    pub maximum_paths: usize,
    /// Desired number of warm backup paths.
    pub warm_backup_paths: usize,
    /// Maximum RTT spread among active paths.
    pub maximum_rtt_spread_ms: f64,
    /// Minimum expected unique-throughput gain for paths beyond the minimum.
    pub minimum_unique_throughput_gain_ratio: f64,
    /// Randomized 70/20/10 pool mix.
    pub mix: SelectionMix,
}

impl Default for RelaySelectionPolicy {
    fn default() -> Self {
        Self {
            active_paths: 4,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 2,
            maximum_rtt_spread_ms: 20.0,
            minimum_unique_throughput_gain_ratio: 0.10,
            mix: SelectionMix::default(),
        }
    }
}

impl RelaySelectionPolicy {
    fn validate(self) -> Result<(), SelectionError> {
        self.mix.validate()?;
        if self.minimum_paths == 0
            || self.minimum_paths > self.active_paths
            || self.active_paths > self.maximum_paths
            || self.maximum_paths > 8
            || self.active_paths.saturating_add(self.warm_backup_paths) > self.maximum_paths
            || !self.maximum_rtt_spread_ms.is_finite()
            || self.maximum_rtt_spread_ms <= 0.0
            || self.maximum_rtt_spread_ms > MAXIMUM_RTT_SPREAD_MS
            || !self.minimum_unique_throughput_gain_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_unique_throughput_gain_ratio)
        {
            return Err(SelectionError::InvalidPolicy);
        }
        Ok(())
    }
}

/// A selected complete relay path.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedPath {
    /// Permanent relay node identity.
    pub relay_node_id: NodeId,
    /// Authenticated relay libp2p peer identity bound by the selected advertisement.
    pub relay_peer_id: PeerId,
    /// Conservative complete-path bottleneck.
    pub capacity: Bandwidth,
    /// Full client-relay-exit RTT.
    pub end_to_end_rtt_ms: f64,
    /// Weighted local score.
    pub score: f64,
    /// Randomization pool used for this choice.
    pub band: SelectionBand,
}

/// Active and warm paths for one already selected exit.
#[derive(Clone, Debug, PartialEq)]
pub struct RelaySelection {
    /// Paths eligible to carry multipath traffic immediately.
    pub active: Vec<SelectedPath>,
    /// Reserved warm paths that do not carry ordinary traffic yet.
    pub warm_backups: Vec<SelectedPath>,
}

/// Selection failure after fail-closed filtering.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum SelectionError {
    /// No candidate survived the hard filters.
    #[error("no eligible candidate")]
    NoEligibleCandidate,
    /// Too few diverse complete relay paths remain.
    #[error("only {available} diverse paths are available; {required} required")]
    InsufficientDiversePaths {
        /// Fail-closed minimum.
        required: usize,
        /// Number selected under all hard constraints.
        available: usize,
    },
    /// A policy contains invalid probabilities or path bounds.
    #[error("invalid selection policy")]
    InvalidPolicy,
    /// The selected control and exit do not form two complete, mutually diverse anchors.
    #[error("invalid control/exit diversity anchors")]
    InvalidDiversityAnchors,
    /// Route-specific path measurements are invalid or implausible.
    #[error("invalid complete-path evidence")]
    InvalidPathEvidence,
    /// A caller supplied requirements for the wrong selection stage.
    #[error("wrong selection role")]
    WrongSelectionRole,
    /// A bounded prospective input reused a permanent node or peer identity.
    #[error("duplicate node or peer identity in prospective relay input")]
    DuplicateIdentity,
    /// A caller supplied more candidates than one bounded selection pass may inspect.
    #[error("selection candidate count {supplied} exceeds the maximum {maximum}")]
    TooManyCandidates {
        /// Number supplied by the caller.
        supplied: usize,
        /// Defensive hard maximum.
        maximum: usize,
    },
    /// Every considered peer failed a hard filter.
    #[error("hard filter failure: {0}")]
    HardFilter(HardFilterReason),
}

#[derive(Clone, Copy, Debug)]
struct ScoredIndex {
    index: usize,
    score: f64,
    band: SelectionBand,
}

trait SelectionCandidate {
    fn candidate(&self) -> &Candidate;
    fn observed_network_prefix(&self) -> Option<ObservedNetworkPrefix>;
    fn filtered_capacity(
        &self,
        requirements: &FilterRequirements,
    ) -> Result<Bandwidth, HardFilterReason>;
}

impl SelectionCandidate for Candidate {
    fn candidate(&self) -> &Candidate {
        self
    }

    fn observed_network_prefix(&self) -> Option<ObservedNetworkPrefix> {
        self.evidence
            .observed_network_origin
            .map(ObservedNetworkPrefix::from_origin)
    }

    fn filtered_capacity(
        &self,
        requirements: &FilterRequirements,
    ) -> Result<Bandwidth, HardFilterReason> {
        hard_filter(self, requirements).map(|capacity| capacity.bandwidth)
    }
}

impl SelectionCandidate for PrefixObservedCandidate<'_> {
    fn candidate(&self) -> &Candidate {
        self.candidate
    }

    fn observed_network_prefix(&self) -> Option<ObservedNetworkPrefix> {
        Some(self.observed_network_prefix)
    }

    fn filtered_capacity(
        &self,
        requirements: &FilterRequirements,
    ) -> Result<Bandwidth, HardFilterReason> {
        hard_filter_with_observed_prefix(self, requirements).map(|capacity| capacity.bandwidth)
    }
}

/// Selects one exit using exact hard filters, exit weights and randomized
/// 70/20/10 stratified sampling.
///
/// # Errors
///
/// Returns an error for the wrong selection role, invalid sampling policy, or when every exit
/// candidate fails the hard filters.
pub fn select_exit<R: Rng + ?Sized>(
    candidates: &[Candidate],
    requirements: &FilterRequirements,
    mix: SelectionMix,
    rng: &mut R,
) -> Result<SelectedNode, SelectionError> {
    select_exit_core(candidates, requirements, mix, rng)
}

/// Selects one exit from raw-address-free candidates using canonical observed prefixes.
///
/// # Errors
///
/// Returns an error for the wrong role, invalid policy or when every candidate fails the shared
/// fail-closed filter.
pub fn select_exit_with_observed_prefixes<R: Rng + ?Sized>(
    candidates: &[PrefixObservedCandidate<'_>],
    requirements: &FilterRequirements,
    mix: SelectionMix,
    rng: &mut R,
) -> Result<SelectedNode, SelectionError> {
    select_exit_core(candidates, requirements, mix, rng)
}

fn select_exit_core<C: SelectionCandidate, R: Rng + ?Sized>(
    candidates: &[C],
    requirements: &FilterRequirements,
    mix: SelectionMix,
    rng: &mut R,
) -> Result<SelectedNode, SelectionError> {
    if requirements.role != ServiceRole::Exit {
        return Err(SelectionError::WrongSelectionRole);
    }
    mix.validate()?;
    validate_candidate_count(candidates.len())?;
    let mut eligible = Vec::new();
    let mut last_failure = None;
    let mut node_ids = HashSet::new();
    let mut peer_ids = HashSet::new();
    for (index, input) in candidates.iter().enumerate() {
        let candidate = input.candidate();
        match input.filtered_capacity(requirements) {
            Ok(capacity)
                if !node_ids.contains(&candidate.advertisement.node_id)
                    && !peer_ids.contains(&candidate.advertisement.peer_id) =>
            {
                node_ids.insert(candidate.advertisement.node_id.clone());
                peer_ids.insert(candidate.advertisement.peer_id.clone());
                eligible.push((index, capacity));
            }
            Ok(_) => {}
            Err(reason) => last_failure = Some(reason),
        }
    }
    if eligible.is_empty() {
        return Err(last_failure.map_or(
            SelectionError::NoEligibleCandidate,
            SelectionError::HardFilter,
        ));
    }
    let mut scored = score_exit_candidates(candidates, &eligible);
    assign_bands(candidates, &mut scored);
    let selected =
        choose_stratified(&scored, mix, rng).ok_or(SelectionError::NoEligibleCandidate)?;
    Ok(SelectedNode {
        node_id: candidates[selected.index]
            .candidate()
            .advertisement
            .node_id
            .clone(),
        peer_id: candidates[selected.index]
            .candidate()
            .advertisement
            .peer_id
            .clone(),
        score: selected.score,
        band: selected.band,
    })
}

/// Selects a bounded, diverse relay slate for later selected-exit-specific measurement.
///
/// This phase deliberately uses peer evidence only. It never manufactures complete-path RTT,
/// capacity, throughput-gain or failover values. Candidates are put in canonical identity order
/// before randomized 70/20/10 sampling, so a fixed seed is independent of caller input order.
///
/// # Errors
///
/// Returns an error for a non-relay role, invalid bounds or anchors, more than 200 candidates, or
/// when fewer than the requested minimum remain after hard filtering and strict diversity.
pub fn select_prospective_relays<R: Rng + ?Sized>(
    candidates: &[Candidate],
    requirements: &FilterRequirements,
    anchors: &[DiversityAnchor],
    policy: ProspectiveRelayPolicy,
    rng: &mut R,
) -> Result<ProspectiveRelaySelection, SelectionError> {
    select_prospective_relays_core(candidates, requirements, anchors, policy, false, rng)
}

/// Selects a bounded relay slate from raw-address-free, prefix-observed candidates.
///
/// # Errors
///
/// Returns an error for invalid role, bounds or anchors, oversized input, duplicate identities, or
/// too few candidates after the shared fail-closed filter and strict diversity checks.
pub fn select_prospective_relays_with_observed_prefixes<R: Rng + ?Sized>(
    candidates: &[PrefixObservedCandidate<'_>],
    requirements: &FilterRequirements,
    anchors: &[DiversityAnchor],
    policy: ProspectiveRelayPolicy,
    rng: &mut R,
) -> Result<ProspectiveRelaySelection, SelectionError> {
    select_prospective_relays_core(candidates, requirements, anchors, policy, true, rng)
}

fn select_prospective_relays_core<C: SelectionCandidate, R: Rng + ?Sized>(
    candidates: &[C],
    requirements: &FilterRequirements,
    anchors: &[DiversityAnchor],
    policy: ProspectiveRelayPolicy,
    require_matching_anchor_family: bool,
    rng: &mut R,
) -> Result<ProspectiveRelaySelection, SelectionError> {
    if requirements.role != ServiceRole::Relay {
        return Err(SelectionError::WrongSelectionRole);
    }
    policy.validate()?;
    validate_candidate_count(candidates.len())?;
    let mut diversity = DiversitySet::default();
    if anchors.len() != 2 {
        return Err(SelectionError::InvalidDiversityAnchors);
    }
    for anchor in anchors {
        if (require_matching_anchor_family
            && requirements
                .address_family
                .is_some_and(|family| family != anchor.observed_network_prefix.family()))
            || !diversity.allows_anchor(anchor)
        {
            return Err(SelectionError::InvalidDiversityAnchors);
        }
        diversity.insert_anchor(anchor);
    }

    let mut eligible = Vec::new();
    let mut node_ids = HashSet::new();
    let mut peer_ids = HashSet::new();
    for (index, input) in candidates.iter().enumerate() {
        let candidate = input.candidate();
        if !node_ids.insert(candidate.advertisement.node_id.clone())
            || !peer_ids.insert(candidate.advertisement.peer_id.clone())
        {
            return Err(SelectionError::DuplicateIdentity);
        }
        if let Ok(capacity) = input.filtered_capacity(requirements) {
            eligible.push((index, capacity));
        }
    }
    let mut scored = score_prospective_relay_candidates(candidates, &eligible);
    assign_bands(candidates, &mut scored);
    let mut selected = Vec::with_capacity(policy.maximum_relays);
    while selected.len() < policy.maximum_relays {
        let diverse = scored
            .iter()
            .copied()
            .filter(|score| {
                !selected
                    .iter()
                    .any(|existing: &ScoredIndex| existing.index == score.index)
                    && diversity.allows_strict(&candidates[score.index])
            })
            .collect::<Vec<_>>();
        let Some(choice) = choose_stratified(&diverse, policy.mix, rng) else {
            break;
        };
        diversity.insert_candidate(&candidates[choice.index]);
        selected.push(choice);
    }
    if selected.len() < policy.minimum_relays {
        return Err(SelectionError::InsufficientDiversePaths {
            required: policy.minimum_relays,
            available: selected.len(),
        });
    }
    Ok(ProspectiveRelaySelection {
        relays: selected
            .into_iter()
            .map(|selected| SelectedNode {
                node_id: candidates[selected.index]
                    .candidate()
                    .advertisement
                    .node_id
                    .clone(),
                peer_id: candidates[selected.index]
                    .candidate()
                    .advertisement
                    .peer_id
                    .clone(),
                score: selected.score,
                band: selected.band,
            })
            .collect(),
    })
}

/// Selects diverse complete relay paths after an exit has already been fixed.
///
/// # Errors
///
/// Returns an error for the wrong role, invalid path-count or sampling policy, invalid path
/// evidence, or when fewer than the required number of diverse complete paths survive fail-closed
/// filtering.
pub fn select_relay_paths<R: Rng + ?Sized>(
    paths: &[RelayPathCandidate],
    requirements: &FilterRequirements,
    policy: RelaySelectionPolicy,
    rng: &mut R,
) -> Result<RelaySelection, SelectionError> {
    validate_relay_selection_policy(requirements, policy)?;
    validate_candidate_count(paths.len())?;
    let mut invalid_path_evidence = false;
    let mut projections = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        if path.validate().is_err() {
            invalid_path_evidence = true;
            continue;
        }
        if let Ok(projection) =
            RelaySelectionProjection::from_legacy_candidate(path.relay.clone(), requirements)
        {
            projections.push((index, projection));
        }
    }
    let projected_paths = projections
        .iter()
        .map(|(index, projection)| {
            let path = &paths[*index];
            ProjectedRelayPath::new(
                projection,
                CompleteRelayPathMetrics::new(
                    path.client_to_relay_capacity,
                    path.relay_to_exit_capacity,
                    path.exit_reserved_capacity,
                    path.client_to_relay_rtt_ms,
                    path.relay_to_exit_rtt_ms,
                    path.unique_throughput_gain_ratio,
                    path.meaningful_failover,
                ),
            )
        })
        .collect::<Vec<_>>();
    select_projected_relay_paths_core(
        &projected_paths,
        requirements,
        policy,
        invalid_path_evidence,
        rng,
    )
}

/// Selects complete relay paths from consumed, endpoint-free relay projections.
///
/// This is the value-only post-probe boundary for callers that already consumed the full
/// advertisement through `RelaySelectionProjection::from_candidate`. It is neither authenticated
/// actor proof nor dispatch authority. The static scope must match exactly; only trusted time may
/// advance monotonically.
///
/// # Errors
///
/// Returns an error for invalid policy or measured scalars, a mismatched projected scope, more
/// than 200 inputs, or too few diverse complete paths.
pub fn select_projected_relay_paths<R: Rng + ?Sized>(
    paths: &[ProjectedRelayPath<'_>],
    requirements: &FilterRequirements,
    policy: RelaySelectionPolicy,
    rng: &mut R,
) -> Result<RelaySelection, SelectionError> {
    validate_relay_selection_policy(requirements, policy)?;
    validate_candidate_count(paths.len())?;
    select_projected_relay_paths_core(paths, requirements, policy, false, rng)
}

fn select_projected_relay_paths_core<R: Rng + ?Sized>(
    paths: &[ProjectedRelayPath<'_>],
    requirements: &FilterRequirements,
    policy: RelaySelectionPolicy,
    invalid_path_evidence: bool,
    rng: &mut R,
) -> Result<RelaySelection, SelectionError> {
    let eligible = eligible_projected_relay_paths(paths, requirements, invalid_path_evidence)?;
    if eligible.len() < policy.minimum_paths {
        return Err(SelectionError::InsufficientDiversePaths {
            required: policy.minimum_paths,
            available: eligible.len(),
        });
    }

    let mut scored = score_projected_relay_paths(paths, &eligible);
    assign_projected_bands(paths, &mut scored);
    let mut diversity = DiversitySet::default();
    let mut selected_indices = Vec::new();

    while selected_indices.len() < policy.minimum_paths {
        let Some(selected) = choose_diverse_projected_path(
            paths,
            &scored,
            PathChoiceConstraints {
                excluded: &selected_indices,
                rtt_reference: &selected_indices,
                diversity: &diversity,
                maximum_rtt_spread_ms: policy.maximum_rtt_spread_ms,
            },
            policy.mix,
            rng,
        ) else {
            break;
        };
        diversity.insert_projected(paths[selected.index].relay);
        selected_indices.push(selected);
    }
    if selected_indices.len() < policy.minimum_paths {
        return Err(SelectionError::InsufficientDiversePaths {
            required: policy.minimum_paths,
            available: selected_indices.len(),
        });
    }

    let additional_paths: Vec<ScoredIndex> = scored
        .iter()
        .copied()
        .filter(|candidate| {
            let path = &paths[candidate.index];
            path.metrics.unique_throughput_gain_ratio >= policy.minimum_unique_throughput_gain_ratio
                || path.metrics.meaningful_failover
        })
        .collect();
    while selected_indices.len() < policy.active_paths {
        let Some(selected) = choose_diverse_projected_path(
            paths,
            &additional_paths,
            PathChoiceConstraints {
                excluded: &selected_indices,
                rtt_reference: &selected_indices,
                diversity: &diversity,
                maximum_rtt_spread_ms: policy.maximum_rtt_spread_ms,
            },
            policy.mix,
            rng,
        ) else {
            break;
        };
        diversity.insert_projected(paths[selected.index].relay);
        selected_indices.push(selected);
    }

    let active = selected_indices
        .iter()
        .map(|selected| to_projected_selected_path(paths, *selected))
        .collect();
    let mut backups = Vec::new();
    while backups.len() < policy.warm_backup_paths {
        let Some(selected) = choose_diverse_projected_path(
            paths,
            &scored,
            PathChoiceConstraints {
                excluded: &selected_indices,
                rtt_reference: &[],
                diversity: &diversity,
                maximum_rtt_spread_ms: policy.maximum_rtt_spread_ms,
            },
            policy.mix,
            rng,
        ) else {
            break;
        };
        diversity.insert_projected(paths[selected.index].relay);
        selected_indices.push(selected);
        backups.push(to_projected_selected_path(paths, selected));
    }
    Ok(RelaySelection {
        active,
        warm_backups: backups,
    })
}

/// Validates complete-path relay policy against the exact route transport and hard bounds.
///
/// # Errors
///
/// Returns an error for a non-relay role, invalid path counts, sampling probabilities, RTT spread
/// or throughput-gain threshold, including a multipath route with fewer than two required paths.
pub fn validate_relay_selection_policy(
    requirements: &FilterRequirements,
    policy: RelaySelectionPolicy,
) -> Result<(), SelectionError> {
    if requirements.role != ServiceRole::Relay {
        return Err(SelectionError::WrongSelectionRole);
    }
    policy.validate()?;
    let path_count_is_valid = match requirements.transport {
        Transport::UdpSinglePath => policy.minimum_paths == 1 && policy.active_paths == 1,
        Transport::TcpMptcp | Transport::MultipathQuic => policy.minimum_paths >= 2,
    };
    if !path_count_is_valid {
        return Err(SelectionError::InvalidPolicy);
    }
    Ok(())
}

fn eligible_projected_relay_paths(
    paths: &[ProjectedRelayPath<'_>],
    requirements: &FilterRequirements,
    mut invalid_path_evidence: bool,
) -> Result<Vec<(usize, Bandwidth)>, SelectionError> {
    let mut eligible = Vec::new();
    let mut node_ids = HashSet::new();
    let mut peer_ids = HashSet::new();
    for (index, path) in paths.iter().enumerate() {
        if path.validate().is_err() {
            invalid_path_evidence = true;
            continue;
        }
        let capacity = path.path_capacity();
        if path.relay.requirements_match(requirements)
            && capacity.satisfies(requirements.minimum_capacity)
            && !node_ids.contains(&path.relay.node_id)
            && !peer_ids.contains(&path.relay.peer_id)
        {
            node_ids.insert(path.relay.node_id.clone());
            peer_ids.insert(path.relay.peer_id.clone());
            eligible.push((index, capacity));
        }
    }
    if eligible.is_empty() && invalid_path_evidence {
        return Err(SelectionError::InvalidPathEvidence);
    }
    Ok(eligible)
}

fn validate_candidate_count(candidate_count: usize) -> Result<(), SelectionError> {
    if candidate_count > MAXIMUM_SELECTION_CANDIDATES {
        return Err(SelectionError::TooManyCandidates {
            supplied: candidate_count,
            maximum: MAXIMUM_SELECTION_CANDIDATES,
        });
    }
    Ok(())
}

fn score_exit_candidates<C: SelectionCandidate>(
    candidates: &[C],
    eligible: &[(usize, Bandwidth)],
) -> Vec<ScoredIndex> {
    let max_capacity = eligible
        .iter()
        .map(|(_, capacity)| bottleneck(*capacity))
        .fold(1.0_f64, f64::max);
    let max_history = eligible
        .iter()
        .filter_map(|(index, _)| candidates[*index].candidate().evidence.locally_measured_p25)
        .map(bottleneck)
        .fold(1.0_f64, f64::max);
    eligible
        .iter()
        .map(|(index, capacity)| {
            let candidate = candidates[*index].candidate();
            let capacity_score = bottleneck(*capacity) / max_capacity;
            let history_score = candidate
                .evidence
                .locally_measured_p25
                .map_or(0.0, |history| bottleneck(history) / max_history);
            let active_sessions = candidate.advertisement.capacity.active_exit_sessions;
            let balance = 1.0 / (1.0 + f64::from(active_sessions));
            ScoredIndex {
                index: *index,
                score: (CAPACITY_WEIGHT * capacity_score
                    + HISTORY_WEIGHT * history_score
                    + UPTIME_WEIGHT * candidate.evidence.uptime_score
                    + PATH_OR_EGRESS_QUALITY_WEIGHT * candidate.evidence.recent_egress_quality
                    + REPUTATION_WEIGHT * candidate.evidence.reputation_score
                    + BALANCE_OR_DIVERSITY_WEIGHT * balance)
                    .clamp(0.0, 1.0),
                band: SelectionBand::DiverseMiddle,
            }
        })
        .collect()
}

fn score_projected_relay_paths(
    paths: &[ProjectedRelayPath<'_>],
    eligible: &[(usize, Bandwidth)],
) -> Vec<ScoredIndex> {
    let maximum_capacity = eligible
        .iter()
        .map(|(_, capacity)| bottleneck(*capacity))
        .fold(1.0_f64, f64::max);
    let maximum_history = eligible
        .iter()
        .filter_map(|(index, _)| paths[*index].relay.evidence.locally_measured_p25)
        .map(bottleneck)
        .fold(1.0_f64, f64::max);
    eligible
        .iter()
        .map(|(index, capacity)| {
            let path = &paths[*index];
            let relay = &path.relay;
            let capacity_score = bottleneck(*capacity) / maximum_capacity;
            let history_score = relay
                .evidence
                .locally_measured_p25
                .map_or(0.0, |history| bottleneck(history) / maximum_history);
            let complete_path_score = 1.0 / (1.0 + path.end_to_end_rtt_ms() / 100.0);
            let diversity_exploration = if relay.is_exploration_candidate() {
                1.0
            } else {
                0.5
            };
            ScoredIndex {
                index: *index,
                score: (CAPACITY_WEIGHT * capacity_score
                    + HISTORY_WEIGHT * history_score
                    + UPTIME_WEIGHT * relay.evidence.uptime_score
                    + PATH_OR_EGRESS_QUALITY_WEIGHT * complete_path_score
                    + REPUTATION_WEIGHT * relay.evidence.reputation_score
                    + BALANCE_OR_DIVERSITY_WEIGHT * diversity_exploration)
                    .clamp(0.0, 1.0),
                band: SelectionBand::DiverseMiddle,
            }
        })
        .collect()
}

fn score_prospective_relay_candidates<C: SelectionCandidate>(
    candidates: &[C],
    eligible: &[(usize, Bandwidth)],
) -> Vec<ScoredIndex> {
    let maximum_capacity = eligible
        .iter()
        .map(|(_, capacity)| bottleneck(*capacity))
        .fold(1.0_f64, f64::max);
    let maximum_history = eligible
        .iter()
        .filter_map(|(index, _)| candidates[*index].candidate().evidence.locally_measured_p25)
        .map(bottleneck)
        .fold(1.0_f64, f64::max);
    eligible
        .iter()
        .map(|(index, capacity)| {
            let candidate = candidates[*index].candidate();
            let capacity_score = bottleneck(*capacity) / maximum_capacity;
            let history_score = candidate
                .evidence
                .locally_measured_p25
                .map_or(0.0, |history| bottleneck(history) / maximum_history);
            let diversity_exploration = if candidate.is_exploration_candidate() {
                1.0
            } else {
                0.5
            };
            ScoredIndex {
                index: *index,
                score: (CAPACITY_WEIGHT * capacity_score
                    + HISTORY_WEIGHT * history_score
                    + UPTIME_WEIGHT * candidate.evidence.uptime_score
                    + PATH_OR_EGRESS_QUALITY_WEIGHT * candidate.evidence.proximity_score
                    + REPUTATION_WEIGHT * candidate.evidence.reputation_score
                    + BALANCE_OR_DIVERSITY_WEIGHT * diversity_exploration)
                    .clamp(0.0, 1.0),
                band: SelectionBand::DiverseMiddle,
            }
        })
        .collect()
}

fn assign_bands<C: SelectionCandidate>(candidates: &[C], scores: &mut [ScoredIndex]) {
    scores.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| {
                candidates[left.index]
                    .candidate()
                    .advertisement
                    .node_id
                    .cmp(&candidates[right.index].candidate().advertisement.node_id)
            })
            .then_with(|| {
                candidates[left.index]
                    .candidate()
                    .advertisement
                    .peer_id
                    .cmp(&candidates[right.index].candidate().advertisement.peer_id)
            })
    });
    let measured_count = scores
        .iter()
        .filter(|score| {
            !candidates[score.index]
                .candidate()
                .is_exploration_candidate()
        })
        .count();
    let high_count = measured_count.div_ceil(2);
    let mut measured_seen = 0;
    for score in scores {
        if candidates[score.index]
            .candidate()
            .is_exploration_candidate()
        {
            score.band = SelectionBand::Exploration;
        } else if measured_seen < high_count {
            score.band = SelectionBand::High;
            measured_seen += 1;
        } else {
            score.band = SelectionBand::DiverseMiddle;
            measured_seen += 1;
        }
    }
}

fn assign_projected_bands(paths: &[ProjectedRelayPath<'_>], scores: &mut [ScoredIndex]) {
    scores.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| {
                paths[left.index]
                    .relay
                    .node_id
                    .cmp(&paths[right.index].relay.node_id)
            })
            .then_with(|| {
                paths[left.index]
                    .relay
                    .peer_id
                    .cmp(&paths[right.index].relay.peer_id)
            })
    });
    let measured_count = scores
        .iter()
        .filter(|score| !paths[score.index].relay.is_exploration_candidate())
        .count();
    let high_count = measured_count.div_ceil(2);
    let mut measured_seen = 0;
    for score in scores {
        if paths[score.index].relay.is_exploration_candidate() {
            score.band = SelectionBand::Exploration;
        } else if measured_seen < high_count {
            score.band = SelectionBand::High;
            measured_seen += 1;
        } else {
            score.band = SelectionBand::DiverseMiddle;
            measured_seen += 1;
        }
    }
}

fn choose_stratified<R: Rng + ?Sized>(
    candidates: &[ScoredIndex],
    mix: SelectionMix,
    rng: &mut R,
) -> Option<ScoredIndex> {
    if candidates.is_empty() {
        return None;
    }
    let draw = rng.gen_range(0.0..1.0);
    let desired = if draw < mix.high {
        SelectionBand::High
    } else if draw < mix.high + mix.diverse_middle {
        SelectionBand::DiverseMiddle
    } else {
        SelectionBand::Exploration
    };
    let in_desired: Vec<ScoredIndex> = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.band == desired)
        .collect();
    if in_desired.is_empty() {
        return weighted_sample(candidates, rng);
    }
    weighted_sample(&in_desired, rng)
}

fn weighted_sample<R: Rng + ?Sized>(
    candidates: &[ScoredIndex],
    rng: &mut R,
) -> Option<ScoredIndex> {
    let total: f64 = candidates
        .iter()
        .map(|candidate| candidate.score.max(0.01))
        .sum();
    if !total.is_finite() || total <= 0.0 {
        return None;
    }
    let mut draw = rng.gen_range(0.0..total);
    for candidate in candidates {
        let weight = candidate.score.max(0.01);
        if draw < weight {
            return Some(*candidate);
        }
        draw -= weight;
    }
    candidates.last().copied()
}

#[derive(Clone, Copy)]
struct PathChoiceConstraints<'a> {
    excluded: &'a [ScoredIndex],
    rtt_reference: &'a [ScoredIndex],
    diversity: &'a DiversitySet,
    maximum_rtt_spread_ms: f64,
}

fn choose_diverse_projected_path<R: Rng + ?Sized>(
    paths: &[ProjectedRelayPath<'_>],
    scored: &[ScoredIndex],
    constraints: PathChoiceConstraints<'_>,
    mix: SelectionMix,
    rng: &mut R,
) -> Option<ScoredIndex> {
    let hard_eligible: Vec<ScoredIndex> = scored
        .iter()
        .copied()
        .filter(|candidate| {
            !constraints
                .excluded
                .iter()
                .any(|existing| existing.index == candidate.index)
                && constraints
                    .diversity
                    .allows_projected_hard(paths[candidate.index].relay)
                && projected_rtt_is_compatible(
                    paths,
                    constraints.rtt_reference,
                    candidate.index,
                    constraints.maximum_rtt_spread_ms,
                )
        })
        .collect();
    let unique_asn: Vec<ScoredIndex> = hard_eligible
        .iter()
        .copied()
        .filter(|candidate| {
            constraints
                .diversity
                .has_new_projected_asn(paths[candidate.index].relay)
        })
        .collect();
    if unique_asn.is_empty() {
        choose_stratified(&hard_eligible, mix, rng)
    } else {
        choose_stratified(&unique_asn, mix, rng)
    }
}

fn projected_rtt_is_compatible(
    paths: &[ProjectedRelayPath<'_>],
    selected: &[ScoredIndex],
    candidate_index: usize,
    maximum_spread: f64,
) -> bool {
    if selected.is_empty() {
        return true;
    }
    let candidate_rtt = paths[candidate_index].end_to_end_rtt_ms();
    let mut minimum = candidate_rtt;
    let mut maximum = candidate_rtt;
    for existing in selected {
        let rtt = paths[existing.index].end_to_end_rtt_ms();
        minimum = minimum.min(rtt);
        maximum = maximum.max(rtt);
    }
    maximum - minimum <= maximum_spread
}

fn to_projected_selected_path(
    paths: &[ProjectedRelayPath<'_>],
    selected: ScoredIndex,
) -> SelectedPath {
    let path = &paths[selected.index];
    SelectedPath {
        relay_node_id: path.relay.node_id.clone(),
        relay_peer_id: path.relay.peer_id.clone(),
        capacity: path.path_capacity(),
        end_to_end_rtt_ms: path.end_to_end_rtt_ms(),
        score: selected.score,
        band: selected.band,
    }
}

fn bottleneck(capacity: Bandwidth) -> f64 {
    f64::from(capacity.up_mbps.min(capacity.down_mbps))
}

#[derive(Default)]
struct DiversitySet {
    nodes: HashSet<NodeId>,
    peers: HashSet<PeerId>,
    operators: HashSet<OperatorId>,
    observed_network_prefixes: HashSet<ObservedNetworkPrefix>,
    // None is one shared unknown-origin occupancy, never an independent ASN identity.
    asns: HashSet<Option<u32>>,
}

impl DiversitySet {
    fn allows_anchor(&self, anchor: &DiversityAnchor) -> bool {
        !self.nodes.contains(&anchor.node_id)
            && !self.peers.contains(&anchor.peer_id)
            && !self.operators.contains(&anchor.operator_id)
            && !self.asns.contains(&anchor.asn)
            && !self
                .observed_network_prefixes
                .contains(&anchor.observed_network_prefix)
    }

    fn insert_anchor(&mut self, anchor: &DiversityAnchor) {
        self.nodes.insert(anchor.node_id.clone());
        self.peers.insert(anchor.peer_id.clone());
        self.operators.insert(anchor.operator_id.clone());
        self.asns.insert(anchor.asn);
        self.observed_network_prefixes
            .insert(anchor.observed_network_prefix);
    }

    fn allows_strict<C: SelectionCandidate>(&self, input: &C) -> bool {
        let candidate = input.candidate();
        let network = &candidate.advertisement.network;
        input.observed_network_prefix().is_some_and(|prefix| {
            (prefix.is_public_routable() || prefix.is_local_lan())
                && !self.nodes.contains(&candidate.advertisement.node_id)
                && !self.peers.contains(&candidate.advertisement.peer_id)
                && !self.operators.contains(&network.operator_id)
                && (network.asn.is_some_and(|asn| asn != 0)
                    || (network.uplink == volparossa_core::NetworkUplink::LocalOnly
                        && prefix.is_local_lan()))
                && !self.asns.contains(&network.asn)
                && !self.observed_network_prefixes.contains(&prefix)
        })
    }

    fn allows_projected_hard(&self, projection: &RelaySelectionProjection) -> bool {
        !self.nodes.contains(&projection.node_id)
            && !self.peers.contains(&projection.peer_id)
            && !self.operators.contains(&projection.operator_id)
            && (projection.asn.is_some() || !self.asns.contains(&None))
            && !self
                .observed_network_prefixes
                .contains(&projection.network_prefix)
    }

    fn has_new_projected_asn(&self, projection: &RelaySelectionProjection) -> bool {
        projection.asn.is_some() && !self.asns.contains(&projection.asn)
    }

    fn insert_candidate<C: SelectionCandidate>(&mut self, input: &C) {
        let candidate = input.candidate();
        let network = &candidate.advertisement.network;
        self.nodes.insert(candidate.advertisement.node_id.clone());
        self.peers.insert(candidate.advertisement.peer_id.clone());
        self.operators.insert(network.operator_id.clone());
        if let Some(prefix) = input.observed_network_prefix() {
            self.observed_network_prefixes.insert(prefix);
        }
        self.asns.insert(network.asn);
    }

    fn insert_projected(&mut self, projection: &RelaySelectionProjection) {
        self.nodes.insert(projection.node_id.clone());
        self.peers.insert(projection.peer_id.clone());
        self.operators.insert(projection.operator_id.clone());
        self.observed_network_prefixes
            .insert(projection.network_prefix);
        self.asns.insert(projection.asn);
    }
}
