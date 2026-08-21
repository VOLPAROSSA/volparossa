use thiserror::Error;
use volparossa_core::{
    AdvertisementError, Bandwidth, ConservativeCapacity, IpFamily, NodeAdvertisement,
    ObservedNetworkOrigin, ObservedNetworkPrefix, PolicyHash, ServiceRole, Transport, UnixTime,
};

const MAX_RTT_MS: f64 = 120_000.0;

/// Locally collected evidence associated with an advertised peer.
#[derive(Clone, Debug, PartialEq)]
pub struct CandidateEvidence {
    /// Locally measured p25 delivery capacity, or `None` for exploration peers.
    pub locally_measured_p25: Option<Bandwidth>,
    /// Capacity the remote side is prepared to reserve for this path.
    pub reserved_path_limit: Bandwidth,
    /// Locally observed uptime ratio from 0 through 1.
    pub uptime_score: f64,
    /// Local reputation ratio from 0 through 1.
    pub reputation_score: f64,
    /// Local RTT/region proximity score from 0 through 1.
    pub proximity_score: f64,
    /// Recent exit egress quality from 0 through 1.
    pub recent_egress_quality: f64,
    /// Most recent local RTT observation.
    pub rtt_ms: Option<f64>,
    /// Number of independent local performance observations.
    pub measurement_count: u32,
    /// Whether a current reachability check succeeded.
    pub reachable: bool,
    /// Whether the observed endpoint can carry the requested dataplane.
    pub network_address_usable: bool,
    /// Locally observed public network origin used for prefix diversity.
    pub observed_network_origin: Option<ObservedNetworkOrigin>,
    /// Whether the local operator blocked this peer.
    pub locally_blocked: bool,
    /// End of a local cool-down after a serious protocol fault.
    pub serious_protocol_fault_until: Option<UnixTime>,
}

impl CandidateEvidence {
    /// Checks locally supplied ratios, capacity and RTT bounds.
    ///
    /// # Errors
    ///
    /// Returns [`HardFilterReason::InvalidLocalEvidence`] for invalid capacity, non-finite or
    /// out-of-range ratios, or a non-positive or implausibly large RTT.
    pub fn validate(&self) -> Result<(), HardFilterReason> {
        self.reserved_path_limit
            .validate()
            .map_err(|_| HardFilterReason::InvalidLocalEvidence)?;
        if let Some(capacity) = self.locally_measured_p25 {
            capacity
                .validate()
                .map_err(|_| HardFilterReason::InvalidLocalEvidence)?;
        }
        for ratio in [
            self.uptime_score,
            self.reputation_score,
            self.proximity_score,
            self.recent_egress_quality,
        ] {
            if !ratio.is_finite() || !(0.0..=1.0).contains(&ratio) {
                return Err(HardFilterReason::InvalidLocalEvidence);
            }
        }
        if self
            .rtt_ms
            .is_some_and(|rtt| !rtt.is_finite() || rtt <= 0.0 || rtt > MAX_RTT_MS)
        {
            return Err(HardFilterReason::InvalidLocalEvidence);
        }
        Ok(())
    }
}

/// One untrusted advertisement plus local verification and measurements.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    /// The bounded advertisement body.
    pub advertisement: NodeAdvertisement,
    /// Set only after protocol-layer signature verification succeeds.
    pub signature_verified: bool,
    /// Local observations, never fetched from the DHT.
    pub evidence: CandidateEvidence,
}

impl Candidate {
    /// Returns conservative capacity from the generic advertised free-capacity field.
    ///
    /// Callers selecting a concrete service role should use
    /// [`Self::conservative_capacity_for`] so capacity assigned to another enabled role cannot be
    /// mistaken for usable relay or exit capacity.
    #[must_use]
    pub fn conservative_capacity(&self) -> ConservativeCapacity {
        self.conservative_capacity_with_advertised_limit(self.advertisement.capacity.estimated_free)
    }

    /// Returns conservative capacity bounded by the operator limit for the selected role.
    #[must_use]
    pub fn conservative_capacity_for(&self, role: ServiceRole) -> ConservativeCapacity {
        let role_limit = match role {
            ServiceRole::Relay => self.advertisement.capacity.relay_limit,
            ServiceRole::Exit => self.advertisement.capacity.exit_limit,
        };
        self.conservative_capacity_with_advertised_limit(
            self.advertisement
                .capacity
                .estimated_free
                .component_min(role_limit),
        )
    }

    fn conservative_capacity_with_advertised_limit(
        &self,
        advertised_limit: Bandwidth,
    ) -> ConservativeCapacity {
        ConservativeCapacity::estimate(
            advertised_limit,
            self.evidence.locally_measured_p25,
            self.evidence.reserved_path_limit,
        )
    }

    /// Returns whether the peer has too little history for the normal pool.
    #[must_use]
    pub const fn is_exploration_candidate(&self) -> bool {
        self.evidence.measurement_count < 3 || self.evidence.locally_measured_p25.is_none()
    }
}

/// A borrowed candidate paired with one canonical prefix-only local observation.
///
/// The wrapper rejects a candidate that still carries the legacy full observed address. It owns
/// only the copyable opaque prefix token and exposes no decomposition or raw-prefix API.
pub struct PrefixObservedCandidate<'a> {
    pub(crate) candidate: &'a Candidate,
    pub(crate) observed_network_prefix: ObservedNetworkPrefix,
}

impl<'a> PrefixObservedCandidate<'a> {
    /// Binds a raw-address-free candidate to one normalized network prefix.
    ///
    /// # Errors
    ///
    /// Returns [`HardFilterReason::UnusableNetworkAddress`] when the candidate also retains a
    /// legacy full observed address. Prefix publicness and family are checked by the canonical hard
    /// filter in its existing network-validation position.
    pub fn new(
        candidate: &'a Candidate,
        observed_network_prefix: ObservedNetworkPrefix,
    ) -> Result<Self, HardFilterReason> {
        if candidate.evidence.observed_network_origin.is_some() {
            return Err(HardFilterReason::UnusableNetworkAddress);
        }
        Ok(Self {
            candidate,
            observed_network_prefix,
        })
    }
}

enum ObservedNetworkInput {
    Legacy,
    Prefix(ObservedNetworkPrefix),
}

/// Exact requirements applied before any score is computed.
#[derive(Clone, Debug, PartialEq)]
pub struct FilterRequirements {
    /// Current wall-clock time for TTL and cool-down checks.
    pub now: UnixTime,
    /// Required voluntary service role.
    pub role: ServiceRole,
    /// Exact transport with no silent fallback.
    pub transport: Transport,
    /// Exact active whitelist hash.
    pub policy_hash: PolicyHash,
    /// Minimum capacity needed in both directions.
    pub minimum_capacity: Bandwidth,
    /// Required address family when fixed by the route.
    pub address_family: Option<IpFamily>,
    /// Required region, or any region when absent.
    pub region: Option<String>,
    /// Whether a current reachability observation is mandatory.
    pub require_reachable: bool,
}

/// A fail-closed reason for excluding a peer before weighted selection.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum HardFilterReason {
    /// Protocol-layer signature verification did not succeed.
    #[error("advertisement signature is not verified")]
    InvalidSignature,
    /// The advertisement itself is invalid, inconsistent or expired.
    #[error("invalid advertisement: {0}")]
    InvalidAdvertisement(AdvertisementError),
    /// The requested relay or exit role is not enabled.
    #[error("required role is not enabled")]
    WrongRole,
    /// The exact requested transport is unsupported.
    #[error("required transport is unsupported")]
    MissingTransport,
    /// The requested address family is unsupported.
    #[error("required address family is unsupported")]
    MissingAddressFamily,
    /// The peer uses a different whitelist manifest.
    #[error("whitelist hash mismatch")]
    PolicyMismatch,
    /// No slot remains for the requested service role.
    #[error("no service slot is available")]
    NoFreeSlot,
    /// Conservative usable capacity is insufficient.
    #[error("insufficient conservative capacity")]
    InsufficientCapacity,
    /// The peer is locally blocked.
    #[error("peer is locally blocked")]
    LocallyBlocked,
    /// A severe protocol-fault cool-down is still active.
    #[error("recent serious protocol fault")]
    SeriousProtocolFault,
    /// The observed network endpoint is unusable or missing.
    #[error("network endpoint is unusable")]
    UnusableNetworkAddress,
    /// Reachability is required and not currently established.
    #[error("peer is unreachable")]
    Unreachable,
    /// The route requires another region.
    #[error("peer is outside the required region")]
    WrongRegion,
    /// Local measurement data is non-finite, out of range or implausible.
    #[error("invalid local evidence")]
    InvalidLocalEvidence,
    /// Caller-supplied selection requirements violate defensive bounds.
    #[error("invalid selection requirements")]
    InvalidRequirements,
}

/// Applies every hard filter and returns conservative usable capacity.
///
/// # Errors
///
/// Returns the first fail-closed [`HardFilterReason`] caused by unauthenticated or invalid
/// advertisements, incompatible policy/capabilities, unusable local evidence, or low capacity.
pub fn hard_filter(
    candidate: &Candidate,
    requirements: &FilterRequirements,
) -> Result<ConservativeCapacity, HardFilterReason> {
    hard_filter_core(candidate, requirements, &ObservedNetworkInput::Legacy)
}

pub(crate) fn hard_filter_with_observed_prefix(
    candidate: &PrefixObservedCandidate<'_>,
    requirements: &FilterRequirements,
) -> Result<ConservativeCapacity, HardFilterReason> {
    hard_filter_core(
        candidate.candidate,
        requirements,
        &ObservedNetworkInput::Prefix(candidate.observed_network_prefix),
    )
}

fn hard_filter_core(
    candidate: &Candidate,
    requirements: &FilterRequirements,
    observed_network: &ObservedNetworkInput,
) -> Result<ConservativeCapacity, HardFilterReason> {
    requirements
        .minimum_capacity
        .validate()
        .map_err(|_| HardFilterReason::InvalidRequirements)?;
    if !candidate.signature_verified {
        return Err(HardFilterReason::InvalidSignature);
    }
    candidate
        .advertisement
        .validate_at(requirements.now)
        .map_err(HardFilterReason::InvalidAdvertisement)?;
    candidate.evidence.validate()?;
    if !candidate.advertisement.roles.supports(requirements.role) {
        return Err(HardFilterReason::WrongRole);
    }
    if !candidate
        .advertisement
        .capabilities
        .supports_transport(requirements.transport)
    {
        return Err(HardFilterReason::MissingTransport);
    }
    if requirements
        .address_family
        .is_some_and(|family| !candidate.advertisement.capabilities.supports_family(family))
    {
        return Err(HardFilterReason::MissingAddressFamily);
    }
    if candidate.advertisement.policy_hash != requirements.policy_hash {
        return Err(HardFilterReason::PolicyMismatch);
    }
    let free_slots = match requirements.role {
        ServiceRole::Relay => candidate.advertisement.capacity.free_relay_slots,
        ServiceRole::Exit => candidate.advertisement.capacity.free_exit_slots,
    };
    if free_slots == 0 {
        return Err(HardFilterReason::NoFreeSlot);
    }
    if candidate.evidence.locally_blocked {
        return Err(HardFilterReason::LocallyBlocked);
    }
    if candidate
        .evidence
        .serious_protocol_fault_until
        .is_some_and(|until| !until.is_expired_at(requirements.now))
    {
        return Err(HardFilterReason::SeriousProtocolFault);
    }
    let observed_network_is_usable = match observed_network {
        ObservedNetworkInput::Legacy => candidate.evidence.observed_network_origin.is_some(),
        ObservedNetworkInput::Prefix(prefix) => {
            candidate.evidence.observed_network_origin.is_none()
                && prefix.is_public_routable()
                && requirements
                    .address_family
                    .is_none_or(|family| family == prefix.family())
        }
    };
    if !candidate.evidence.network_address_usable || !observed_network_is_usable {
        return Err(HardFilterReason::UnusableNetworkAddress);
    }
    if requirements.require_reachable && !candidate.evidence.reachable {
        return Err(HardFilterReason::Unreachable);
    }
    if requirements
        .region
        .as_ref()
        .is_some_and(|region| region != &candidate.advertisement.network.region)
    {
        return Err(HardFilterReason::WrongRegion);
    }
    let usable = candidate.conservative_capacity_for(requirements.role);
    if !usable.bandwidth.satisfies(requirements.minimum_capacity) {
        return Err(HardFilterReason::InsufficientCapacity);
    }
    Ok(usable)
}
