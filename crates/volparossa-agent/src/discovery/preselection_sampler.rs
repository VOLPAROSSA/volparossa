//! Affine, discovery-private narrowing for one bounded A1 preselection slate.
//!
//! This stage uses only freshly revalidated advertisements, actor capabilities, signed network
//! hints and bounded local history. In particular, a signed prefix hint is not an observed network
//! origin. The later transport exact-set join must replace every hint with the direct
//! connection-derived or control-attested prefix before any record can become Fresh evidence.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use rand_core::{OsRng, RngCore};
use volparossa_core::{
    Bandwidth, IpFamily, NodeAdvertisement, ObservedNetworkPrefix, OperatorId, PolicyHash,
    ServiceRole, Transport as CoreTransport, UnixTime,
};
use volparossa_protocol::{ObservationAddressFamily, Transport};
use volparossa_selection::MAXIMUM_SELECTION_CANDIDATES;

use super::{
    DirectRelayCandidateSnapshot, ForwardedExitCandidateSnapshot, RouteCandidateAdvertisement,
    RouteCandidateSnapshot, preselection_observation::PreselectionSubjectSet,
};

const MAXIMUM_OTHER_RELAYS: usize = 8;
const MAXIMUM_LOCAL_MEASUREMENTS: usize = 64;
const HIGH_BAND_PERCENT: u64 = 70;
const MIDDLE_BAND_PERCENT: u64 = 20;
const SCORE_SCALE: f64 = 1_000.0;

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "A1 sampler prerequisite; no production client owner"
    )
)]
#[derive(Clone, Copy)]
pub(super) struct PreselectionSamplingScope {
    transport: Transport,
    address_family: ObservationAddressFamily,
    minimum_capacity: Bandwidth,
    minimum_other_relays: usize,
    maximum_other_relays: usize,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "A1 sampler prerequisite; no production client owner"
    )
)]
impl PreselectionSamplingScope {
    pub(super) const fn new(
        transport: Transport,
        address_family: ObservationAddressFamily,
        minimum_capacity: Bandwidth,
        minimum_other_relays: usize,
        maximum_other_relays: usize,
    ) -> Self {
        Self {
            transport,
            address_family,
            minimum_capacity,
            minimum_other_relays,
            maximum_other_relays,
        }
    }

    fn validated(self) -> Option<ValidatedSamplingScope> {
        if self.transport == Transport::Unspecified
            || self.address_family == ObservationAddressFamily::Unspecified
            || self.minimum_capacity.validate().is_err()
            || self.minimum_capacity.up_mbps == 0
            || self.minimum_capacity.down_mbps == 0
            || self.minimum_other_relays == 0
            || self.minimum_other_relays > self.maximum_other_relays
            || self.maximum_other_relays > MAXIMUM_OTHER_RELAYS
        {
            return None;
        }
        let (transport, family) = match (self.transport, self.address_family) {
            (Transport::TcpMptcp, ObservationAddressFamily::Ipv4) => {
                (CoreTransport::TcpMptcp, IpFamily::Ipv4)
            }
            (Transport::TcpMptcp, ObservationAddressFamily::Ipv6) => {
                (CoreTransport::TcpMptcp, IpFamily::Ipv6)
            }
            (Transport::UdpSinglePath, ObservationAddressFamily::Ipv4) => {
                (CoreTransport::UdpSinglePath, IpFamily::Ipv4)
            }
            (Transport::UdpSinglePath, ObservationAddressFamily::Ipv6) => {
                (CoreTransport::UdpSinglePath, IpFamily::Ipv6)
            }
            (Transport::MultipathQuic, ObservationAddressFamily::Ipv4) => {
                (CoreTransport::MultipathQuic, IpFamily::Ipv4)
            }
            (Transport::MultipathQuic, ObservationAddressFamily::Ipv6) => {
                (CoreTransport::MultipathQuic, IpFamily::Ipv6)
            }
            _ => return None,
        };
        Some(ValidatedSamplingScope {
            transport,
            family,
            minimum_capacity: self.minimum_capacity,
            minimum_other_relays: self.minimum_other_relays,
            maximum_other_relays: self.maximum_other_relays,
        })
    }
}

#[derive(Clone, Copy)]
struct ValidatedSamplingScope {
    transport: CoreTransport,
    family: IpFamily,
    minimum_capacity: Bandwidth,
    minimum_other_relays: usize,
    maximum_other_relays: usize,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "A1 sampler prerequisite; no production client owner"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreselectionSamplingError {
    InvalidPolicy,
    InvalidSnapshot,
    NoEligibleForwardedExit,
    InsufficientDiverseRelays,
    Entropy,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "A1 sampler prerequisite; no production client owner"
    )
)]
pub(super) struct PreselectionSamplingFailure {
    pub(super) snapshot: Box<RouteCandidateSnapshot>,
    pub(super) error: PreselectionSamplingError,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AdvertisedPrefixHint {
    Ipv4([u8; 3]),
    Ipv6([u8; 6]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdvertisedDiversityHint {
    operator_id: OperatorId,
    asn: u32,
    prefix: AdvertisedPrefixHint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SamplingBand {
    High,
    DiverseMiddle,
    Exploration,
}

#[derive(Clone)]
struct ScoredForwardedExit {
    exit_index: usize,
    control_index: usize,
    weight: u64,
    band: SamplingBand,
    exploration: bool,
    exit_diversity: AdvertisedDiversityHint,
    control_diversity: AdvertisedDiversityHint,
}

#[derive(Clone)]
struct ScoredRelay {
    index: usize,
    weight: u64,
    band: SamplingBand,
    exploration: bool,
    diversity: AdvertisedDiversityHint,
}

#[derive(Clone, Default)]
struct AdvertisedDiversitySet {
    operators: HashSet<OperatorId>,
    asns: HashSet<u32>,
    prefixes: HashSet<AdvertisedPrefixHint>,
}

impl AdvertisedDiversitySet {
    fn allows(&self, hint: &AdvertisedDiversityHint) -> bool {
        !self.operators.contains(&hint.operator_id)
            && !self.asns.contains(&hint.asn)
            && !self.prefixes.contains(&hint.prefix)
    }

    fn insert(&mut self, hint: &AdvertisedDiversityHint) {
        self.operators.insert(hint.operator_id.clone());
        self.asns.insert(hint.asn);
        self.prefixes.insert(hint.prefix);
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "A1 sampler prerequisite; no production client owner"
    )
)]
pub(super) fn narrow_route_candidate_snapshot(
    snapshot: RouteCandidateSnapshot,
    scope: PreselectionSamplingScope,
) -> Result<RouteCandidateSnapshot, PreselectionSamplingFailure> {
    let sampled_at_ms = crate::unix_millis();
    narrow_route_candidate_snapshot_at(snapshot, scope, sampled_at_ms, &mut OsRng)
}

fn narrow_route_candidate_snapshot_at<R: RngCore + ?Sized>(
    snapshot: RouteCandidateSnapshot,
    scope: PreselectionSamplingScope,
    sampled_at_ms: u64,
    rng: &mut R,
) -> Result<RouteCandidateSnapshot, PreselectionSamplingFailure> {
    let Some(scope) = scope.validated() else {
        return Err(failure(snapshot, PreselectionSamplingError::InvalidPolicy));
    };
    if !snapshot_shape_is_valid(&snapshot, scope, sampled_at_ms) {
        return Err(failure(
            snapshot,
            PreselectionSamplingError::InvalidSnapshot,
        ));
    }

    let mut exit_candidates = scored_forwarded_exits(&snapshot, scope, sampled_at_ms);
    if exit_candidates.is_empty() {
        return Err(failure(
            snapshot,
            PreselectionSamplingError::NoEligibleForwardedExit,
        ));
    }
    assign_exit_bands(&mut exit_candidates);
    canonicalize_exits(&snapshot, &mut exit_candidates);
    let selected_exit = match choose_exit(&exit_candidates, rng) {
        Ok(Some(selected)) => selected,
        Ok(None) => {
            return Err(failure(
                snapshot,
                PreselectionSamplingError::NoEligibleForwardedExit,
            ));
        }
        Err(error) => return Err(failure(snapshot, error)),
    };

    let mut diversity = AdvertisedDiversitySet::default();
    diversity.insert(&selected_exit.control_diversity);
    diversity.insert(&selected_exit.exit_diversity);

    let mut relays = scored_relays(&snapshot, selected_exit.control_index, scope, sampled_at_ms);
    assign_relay_bands(&mut relays);
    canonicalize_relays(&snapshot, &mut relays);
    let selected_relay_indices =
        match choose_relay_indices(&relays, diversity, scope.maximum_other_relays, rng) {
            Ok(selected) => selected,
            Err(error) => return Err(failure(snapshot, error)),
        };
    if selected_relay_indices.len() < scope.minimum_other_relays {
        return Err(failure(
            snapshot,
            PreselectionSamplingError::InsufficientDiverseRelays,
        ));
    }

    Ok(materialize_narrowed_snapshot(
        snapshot,
        selected_exit.control_index,
        selected_exit.exit_index,
        &selected_relay_indices,
    ))
}

fn choose_relay_indices<R: RngCore + ?Sized>(
    relays: &[ScoredRelay],
    mut diversity: AdvertisedDiversitySet,
    maximum_relays: usize,
    rng: &mut R,
) -> Result<Vec<usize>, PreselectionSamplingError> {
    let mut selected_relay_indices = Vec::with_capacity(maximum_relays);
    while selected_relay_indices.len() < maximum_relays {
        let eligible = relays
            .iter()
            .filter(|candidate| {
                !selected_relay_indices.contains(&candidate.index)
                    && diversity.allows(&candidate.diversity)
            })
            .cloned()
            .collect::<Vec<_>>();
        let selected = match choose_relay(&eligible, rng) {
            Ok(Some(selected)) => selected,
            Ok(None) => break,
            Err(error) => return Err(error),
        };
        diversity.insert(&selected.diversity);
        selected_relay_indices.push(selected.index);
    }
    Ok(selected_relay_indices)
}

fn failure(
    snapshot: RouteCandidateSnapshot,
    error: PreselectionSamplingError,
) -> PreselectionSamplingFailure {
    PreselectionSamplingFailure {
        snapshot: Box::new(snapshot),
        error,
    }
}

fn snapshot_shape_is_valid(
    snapshot: &RouteCandidateSnapshot,
    scope: ValidatedSamplingScope,
    sampled_at_ms: u64,
) -> bool {
    let direct_count = snapshot.direct_relays.len();
    let exit_count = snapshot.forwarded_exits.len();
    if sampled_at_ms == 0
        || sampled_at_ms < snapshot.captured_at_ms
        || snapshot.captured_at_ms == 0
        || snapshot.policy.version() == 0
        || snapshot.policy.hash() == [0; 32]
        || snapshot.policy.expires_at_ms() <= sampled_at_ms
        || direct_count < scope.minimum_other_relays.saturating_add(1)
        || exit_count == 0
        || direct_count.saturating_add(exit_count) > MAXIMUM_SELECTION_CANDIDATES
        || !snapshot.preselection_subjects.available
        || snapshot.preselection_subjects.entries.len() != direct_count.saturating_add(exit_count)
        || snapshot.preselection_subjects.forwarded_pairs.len() != exit_count
    {
        return false;
    }

    let mut nodes = HashSet::with_capacity(direct_count.saturating_add(exit_count));
    let mut peers = HashSet::with_capacity(direct_count.saturating_add(exit_count));
    let mut keys = HashSet::with_capacity(direct_count.saturating_add(exit_count));
    for relay in &snapshot.direct_relays {
        let capability = relay.capability();
        if !nodes.insert(capability.node_id)
            || !peers.insert(capability.peer_id)
            || !keys.insert(capability.public_key)
            || !direct_binding_is_valid(relay, snapshot, sampled_at_ms)
        {
            return false;
        }
    }

    let mut paired_exits = vec![false; exit_count];
    for &(control_index, exit_subject) in &snapshot.preselection_subjects.forwarded_pairs {
        let Some(exit_index) = exit_subject.checked_sub(direct_count) else {
            return false;
        };
        let Some(exit) = snapshot.forwarded_exits.get(exit_index) else {
            return false;
        };
        let Some(control) = snapshot.direct_relays.get(control_index) else {
            return false;
        };
        let capability = exit.capability();
        if paired_exits[exit_index]
            || exit.control() != control
            || !nodes.insert(capability.exit_node_id)
            || !peers.insert(capability.exit_peer_id)
            || !keys.insert(capability.exit_public_key)
            || !forwarded_binding_is_valid(exit, control, snapshot, sampled_at_ms)
        {
            return false;
        }
        paired_exits[exit_index] = true;
    }
    paired_exits.into_iter().all(|paired| paired)
}

fn direct_binding_is_valid(
    candidate: &DirectRelayCandidateSnapshot,
    snapshot: &RouteCandidateSnapshot,
    sampled_at_ms: u64,
) -> bool {
    let advertisement = candidate.advertisement();
    let body = advertisement.advertisement();
    let capability = candidate.capability();
    advertisement_projection_is_valid(advertisement, sampled_at_ms)
        && body.roles.relay
        && body.node_id.as_str() == hex::encode(capability.node_id)
        && body.peer_id.as_str() == capability.peer_id.to_string()
        && body.sequence_number == capability.advertisement_sequence
        && body.expires_at.as_secs() == capability.advertisement_expires_at_ms / 1_000
        && advertisement.advertisement_payload_hash() == capability.advertisement_payload_hash
        && capability.policy_version == snapshot.policy.version()
        && capability.policy_hash == snapshot.policy.hash()
        && capability.policy_expires_at_ms == snapshot.policy.expires_at_ms()
        && body.policy_hash == PolicyHash::from_bytes(snapshot.policy.hash())
        && capability.expires_at_ms
            == capability
                .advertisement_expires_at_ms
                .min(capability.policy_expires_at_ms)
        && capability.expires_at_ms > sampled_at_ms
}

fn forwarded_binding_is_valid(
    candidate: &ForwardedExitCandidateSnapshot,
    control: &DirectRelayCandidateSnapshot,
    snapshot: &RouteCandidateSnapshot,
    sampled_at_ms: u64,
) -> bool {
    let advertisement = candidate.advertisement();
    let body = advertisement.advertisement();
    let capability = candidate.capability();
    let control_capability = control.capability();
    let upper_expiry = capability
        .exit_advertisement_expires_at_ms
        .min(capability.policy_expires_at_ms)
        .min(control_capability.expires_at_ms);
    advertisement_projection_is_valid(advertisement, sampled_at_ms)
        && body.roles.exit
        && body.node_id.as_str() == hex::encode(capability.exit_node_id)
        && body.peer_id.as_str() == capability.exit_peer_id.to_string()
        && body.sequence_number == capability.exit_advertisement_sequence
        && body.expires_at.as_secs() == capability.exit_advertisement_expires_at_ms / 1_000
        && advertisement.advertisement_payload_hash() == capability.exit_advertisement_payload_hash
        && capability.control_relay_node_id == control_capability.node_id
        && capability.control_relay_peer_id == control_capability.peer_id
        && capability.control_relay_public_key == control_capability.public_key
        && capability.control_relay_advertisement_sequence
            == control_capability.advertisement_sequence
        && capability.control_relay_advertisement_expires_at_ms
            == control_capability.advertisement_expires_at_ms
        && capability.control_relay_advertisement_payload_hash
            == control_capability.advertisement_payload_hash
        && capability.policy_version == snapshot.policy.version()
        && capability.policy_hash == snapshot.policy.hash()
        && capability.policy_expires_at_ms == snapshot.policy.expires_at_ms()
        && body.policy_hash == PolicyHash::from_bytes(snapshot.policy.hash())
        && capability.expires_at_ms > sampled_at_ms
        && capability.expires_at_ms <= upper_expiry
        && capability.control_relay_node_id != capability.exit_node_id
        && capability.control_relay_peer_id != capability.exit_peer_id
        && capability.control_relay_public_key != capability.exit_public_key
}

fn advertisement_projection_is_valid(
    advertisement: &RouteCandidateAdvertisement,
    sampled_at_ms: u64,
) -> bool {
    let now = UnixTime::from_secs(sampled_at_ms / 1_000);
    advertisement.advertisement().validate_at(now).is_ok()
        && advertisement.signed_measured_at_ms() <= sampled_at_ms
        && advertisement.signed_expires_at_ms() > sampled_at_ms
        && advertisement.local_measurement_count() <= MAXIMUM_LOCAL_MEASUREMENTS
        && advertisement.historical_reputation_score().is_finite()
        && (0.0..=1.0).contains(&advertisement.historical_reputation_score())
        && advertisement
            .serious_protocol_fault_until()
            .is_none_or(|until| until.is_expired_at(now))
}

fn scored_forwarded_exits(
    snapshot: &RouteCandidateSnapshot,
    scope: ValidatedSamplingScope,
    sampled_at_ms: u64,
) -> Vec<ScoredForwardedExit> {
    let direct_count = snapshot.direct_relays.len();
    snapshot
        .preselection_subjects
        .forwarded_pairs
        .iter()
        .filter_map(|&(control_index, exit_subject)| {
            let exit_index = exit_subject.checked_sub(direct_count)?;
            let exit = snapshot.forwarded_exits.get(exit_index)?;
            let control = snapshot.direct_relays.get(control_index)?;
            let exit_static = static_candidate(exit.advertisement(), ServiceRole::Exit, scope)?;
            let control_static =
                static_candidate(control.advertisement(), ServiceRole::Relay, scope)?;
            if !diversity_hints_are_distinct(&exit_static.diversity, &control_static.diversity) {
                return None;
            }
            Some(ScoredForwardedExit {
                exit_index,
                control_index,
                weight: exit_static
                    .weight
                    .saturating_add(control_static.weight / 4)
                    .max(1),
                band: SamplingBand::DiverseMiddle,
                exploration: exit_static.exploration || control_static.exploration,
                exit_diversity: exit_static.diversity,
                control_diversity: control_static.diversity,
            })
        })
        .filter(|candidate| {
            snapshot.forwarded_exits[candidate.exit_index]
                .capability()
                .expires_at_ms
                > sampled_at_ms
        })
        .collect()
}

fn scored_relays(
    snapshot: &RouteCandidateSnapshot,
    control_index: usize,
    scope: ValidatedSamplingScope,
    _sampled_at_ms: u64,
) -> Vec<ScoredRelay> {
    snapshot
        .direct_relays
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != control_index)
        .filter_map(|(index, relay)| {
            let candidate = static_candidate(relay.advertisement(), ServiceRole::Relay, scope)?;
            Some(ScoredRelay {
                index,
                weight: candidate.weight,
                band: SamplingBand::DiverseMiddle,
                exploration: candidate.exploration,
                diversity: candidate.diversity,
            })
        })
        .collect()
}

struct StaticCandidate {
    weight: u64,
    exploration: bool,
    diversity: AdvertisedDiversityHint,
}

fn static_candidate(
    candidate: &RouteCandidateAdvertisement,
    role: ServiceRole,
    scope: ValidatedSamplingScope,
) -> Option<StaticCandidate> {
    let advertisement = candidate.advertisement();
    if !advertisement.roles.supports(role)
        || !advertisement
            .capabilities
            .supports_transport(scope.transport)
        || !advertisement.capabilities.supports_family(scope.family)
    {
        return None;
    }
    let (role_limit, free_slots, active_sessions) = match role {
        ServiceRole::Relay => (
            advertisement.capacity.relay_limit,
            advertisement.capacity.free_relay_slots,
            advertisement.capacity.active_relay_sessions,
        ),
        ServiceRole::Exit => (
            advertisement.capacity.exit_limit,
            advertisement.capacity.free_exit_slots,
            advertisement.capacity.active_exit_sessions,
        ),
    };
    let advertised_capacity = advertisement
        .capacity
        .estimated_free
        .component_min(role_limit);
    if free_slots == 0 || !advertised_capacity.satisfies(scope.minimum_capacity) {
        return None;
    }
    let asn = advertisement.network.asn.filter(|asn| *asn != 0)?;
    let prefix = advertised_prefix_hint(advertisement, scope.family)?;
    let diversity = AdvertisedDiversityHint {
        operator_id: advertisement.network.operator_id.clone(),
        asn,
        prefix,
    };
    let capacity = u64::from(
        advertised_capacity
            .up_mbps
            .min(advertised_capacity.down_mbps),
    )
    .min(100_000);
    let uptime = ratio_points(advertisement.quality.historical_uptime_score)?;
    let delivery = ratio_points(advertisement.quality.historical_delivery_ratio_p25)?;
    let reputation = ratio_points(candidate.historical_reputation_score())?;
    let balance = 1_000_u64 / u64::from(active_sessions.saturating_add(1));
    let slots = u64::from(free_slots.min(1_000));
    let weight = capacity
        .saturating_mul(35)
        .saturating_add(uptime.saturating_mul(20))
        .saturating_add(delivery.saturating_mul(15))
        .saturating_add(reputation.saturating_mul(15))
        .saturating_add(balance.saturating_mul(10))
        .saturating_add(slots.saturating_mul(5))
        .max(1);
    Some(StaticCandidate {
        weight,
        exploration: candidate.local_measurement_count() < 3,
        diversity,
    })
}

fn ratio_points(value: f64) -> Option<u64> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "validated unit ratio is scaled into the bounded integer sampler score"
    )]
    Some((value * SCORE_SCALE).round() as u64)
}

fn advertised_prefix_hint(
    advertisement: &NodeAdvertisement,
    family: IpFamily,
) -> Option<AdvertisedPrefixHint> {
    match family {
        IpFamily::Ipv4 => parse_ipv4_prefix(advertisement.network.ipv4_prefix_hint.as_deref()?),
        IpFamily::Ipv6 => parse_ipv6_prefix(advertisement.network.ipv6_prefix_hint.as_deref()?),
    }
}

fn parse_ipv4_prefix(value: &str) -> Option<AdvertisedPrefixHint> {
    let (address, length) = value.split_once('/')?;
    if length != "24" {
        return None;
    }
    let octets = address.parse::<Ipv4Addr>().ok()?.octets();
    if octets[3] != 0 {
        return None;
    }
    let prefix = [octets[0], octets[1], octets[2]];
    ObservedNetworkPrefix::ipv4_24(prefix)
        .is_public_routable()
        .then_some(AdvertisedPrefixHint::Ipv4(prefix))
}

fn parse_ipv6_prefix(value: &str) -> Option<AdvertisedPrefixHint> {
    let (address, length) = value.split_once('/')?;
    if length != "48" {
        return None;
    }
    let octets = address.parse::<Ipv6Addr>().ok()?.octets();
    if octets[6..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let prefix = [
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    ];
    ObservedNetworkPrefix::ipv6_48(prefix)
        .is_public_routable()
        .then_some(AdvertisedPrefixHint::Ipv6(prefix))
}

fn diversity_hints_are_distinct(
    left: &AdvertisedDiversityHint,
    right: &AdvertisedDiversityHint,
) -> bool {
    left.operator_id != right.operator_id && left.asn != right.asn && left.prefix != right.prefix
}

fn assign_exit_bands(candidates: &mut [ScoredForwardedExit]) {
    let measured_count = candidates
        .iter()
        .filter(|candidate| !candidate.exploration)
        .count();
    let high_count = measured_count.div_ceil(2);
    let mut measured = candidates
        .iter_mut()
        .filter(|candidate| !candidate.exploration)
        .collect::<Vec<_>>();
    measured.sort_by(|left, right| right.weight.cmp(&left.weight));
    for (offset, candidate) in measured.into_iter().enumerate() {
        candidate.band = if offset < high_count {
            SamplingBand::High
        } else {
            SamplingBand::DiverseMiddle
        };
    }
    for candidate in candidates
        .iter_mut()
        .filter(|candidate| candidate.exploration)
    {
        candidate.band = SamplingBand::Exploration;
    }
}

fn assign_relay_bands(candidates: &mut [ScoredRelay]) {
    let measured_count = candidates
        .iter()
        .filter(|candidate| !candidate.exploration)
        .count();
    let high_count = measured_count.div_ceil(2);
    let mut measured = candidates
        .iter_mut()
        .filter(|candidate| !candidate.exploration)
        .collect::<Vec<_>>();
    measured.sort_by(|left, right| right.weight.cmp(&left.weight));
    for (offset, candidate) in measured.into_iter().enumerate() {
        candidate.band = if offset < high_count {
            SamplingBand::High
        } else {
            SamplingBand::DiverseMiddle
        };
    }
    for candidate in candidates
        .iter_mut()
        .filter(|candidate| candidate.exploration)
    {
        candidate.band = SamplingBand::Exploration;
    }
}

fn canonicalize_exits(snapshot: &RouteCandidateSnapshot, candidates: &mut [ScoredForwardedExit]) {
    candidates.sort_by(|left, right| {
        let left_exit = snapshot.forwarded_exits[left.exit_index].capability();
        let right_exit = snapshot.forwarded_exits[right.exit_index].capability();
        (
            left_exit.exit_node_id,
            left_exit.exit_peer_id.to_bytes(),
            left_exit.control_relay_node_id,
            left_exit.control_relay_peer_id.to_bytes(),
        )
            .cmp(&(
                right_exit.exit_node_id,
                right_exit.exit_peer_id.to_bytes(),
                right_exit.control_relay_node_id,
                right_exit.control_relay_peer_id.to_bytes(),
            ))
    });
}

fn canonicalize_relays(snapshot: &RouteCandidateSnapshot, candidates: &mut [ScoredRelay]) {
    candidates.sort_by(|left, right| {
        let left_relay = snapshot.direct_relays[left.index].capability();
        let right_relay = snapshot.direct_relays[right.index].capability();
        (left_relay.node_id, left_relay.peer_id.to_bytes())
            .cmp(&(right_relay.node_id, right_relay.peer_id.to_bytes()))
    });
}

fn choose_exit<R: RngCore + ?Sized>(
    candidates: &[ScoredForwardedExit],
    rng: &mut R,
) -> Result<Option<ScoredForwardedExit>, PreselectionSamplingError> {
    choose_stratified(
        candidates,
        |candidate| candidate.band,
        |candidate| candidate.weight,
        rng,
    )
}

fn choose_relay<R: RngCore + ?Sized>(
    candidates: &[ScoredRelay],
    rng: &mut R,
) -> Result<Option<ScoredRelay>, PreselectionSamplingError> {
    choose_stratified(
        candidates,
        |candidate| candidate.band,
        |candidate| candidate.weight,
        rng,
    )
}

fn choose_stratified<T: Clone, R: RngCore + ?Sized>(
    candidates: &[T],
    band: impl Fn(&T) -> SamplingBand,
    weight: impl Fn(&T) -> u64,
    rng: &mut R,
) -> Result<Option<T>, PreselectionSamplingError> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let roll = uniform_below(rng, 100)?;
    let desired = if roll < HIGH_BAND_PERCENT {
        SamplingBand::High
    } else if roll < HIGH_BAND_PERCENT + MIDDLE_BAND_PERCENT {
        SamplingBand::DiverseMiddle
    } else {
        SamplingBand::Exploration
    };
    let desired_candidates = candidates
        .iter()
        .filter(|candidate| band(candidate) == desired)
        .collect::<Vec<_>>();
    if desired_candidates.is_empty() {
        weighted_choice(candidates.iter(), &weight, rng)
    } else {
        weighted_choice(desired_candidates, &weight, rng)
    }
}

fn weighted_choice<'a, T: Clone + 'a, R: RngCore + ?Sized>(
    candidates: impl IntoIterator<Item = &'a T>,
    weight: &impl Fn(&T) -> u64,
    rng: &mut R,
) -> Result<Option<T>, PreselectionSamplingError> {
    let candidates = candidates.into_iter().collect::<Vec<_>>();
    let Some(total) = candidates.iter().try_fold(0_u64, |total, candidate| {
        total.checked_add(weight(candidate).max(1))
    }) else {
        return Ok(None);
    };
    if total == 0 {
        return Ok(None);
    }
    let mut draw = uniform_below(rng, total)?;
    for candidate in candidates {
        let candidate_weight = weight(candidate).max(1);
        if draw < candidate_weight {
            return Ok(Some(candidate.clone()));
        }
        draw -= candidate_weight;
    }
    Ok(None)
}

fn uniform_below<R: RngCore + ?Sized>(
    rng: &mut R,
    upper: u64,
) -> Result<u64, PreselectionSamplingError> {
    if upper == 0 {
        return Err(PreselectionSamplingError::Entropy);
    }
    let rejection_ceiling = u64::MAX - (u64::MAX % upper);
    loop {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| PreselectionSamplingError::Entropy)?;
        let value = u64::from_le_bytes(bytes);
        if value < rejection_ceiling {
            return Ok(value % upper);
        }
    }
}

fn materialize_narrowed_snapshot(
    snapshot: RouteCandidateSnapshot,
    control_index: usize,
    exit_index: usize,
    relay_indices: &[usize],
) -> RouteCandidateSnapshot {
    let RouteCandidateSnapshot {
        captured_at_ms,
        policy,
        direct_relays,
        forwarded_exits,
        preselection_subjects,
    } = snapshot;
    let direct_count = direct_relays.len();
    let mut direct_slots = direct_relays.into_iter().map(Some).collect::<Vec<_>>();
    let mut exit_slots = forwarded_exits.into_iter().map(Some).collect::<Vec<_>>();
    let mut subject_slots = preselection_subjects
        .entries
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();

    let mut narrowed_direct = Vec::with_capacity(relay_indices.len().saturating_add(1));
    let mut narrowed_subjects = Vec::with_capacity(relay_indices.len().saturating_add(2));
    narrowed_direct.push(
        direct_slots[control_index]
            .take()
            .expect("validated unique control index"),
    );
    narrowed_subjects.push(
        subject_slots[control_index]
            .take()
            .expect("validated control subject"),
    );
    for &relay_index in relay_indices {
        narrowed_direct.push(
            direct_slots[relay_index]
                .take()
                .expect("validated unique relay index"),
        );
        narrowed_subjects.push(
            subject_slots[relay_index]
                .take()
                .expect("validated relay subject"),
        );
    }
    let narrowed_exit = exit_slots[exit_index].take().expect("validated exit index");
    narrowed_subjects.push(
        subject_slots[direct_count + exit_index]
            .take()
            .expect("validated exit subject"),
    );
    let exit_subject = narrowed_direct.len();
    RouteCandidateSnapshot {
        captured_at_ms,
        policy,
        direct_relays: narrowed_direct,
        forwarded_exits: vec![narrowed_exit],
        preselection_subjects: PreselectionSubjectSet {
            available: true,
            entries: narrowed_subjects,
            forwarded_pairs: vec![(0, exit_subject)],
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use rand_core::Error as RandError;

    use super::super::{
        preselection_observation::PreselectionAttemptGate,
        tests::{
            PreselectionTestCapabilities, preselection_multi_exit_snapshot_fixture,
            preselection_snapshot_fixture,
        },
    };
    use super::*;

    struct SeededRng(u64);

    impl SeededRng {
        fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }

        fn word(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }
    }

    impl RngCore for SeededRng {
        fn next_u32(&mut self) -> u32 {
            let bytes = self.word().to_le_bytes();
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }

        fn next_u64(&mut self) -> u64 {
            self.word()
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let word = self.word().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    struct CountingRng<'a> {
        calls: &'a Cell<usize>,
    }

    impl RngCore for CountingRng<'_> {
        fn next_u32(&mut self) -> u32 {
            self.calls.set(self.calls.get() + 1);
            1
        }

        fn next_u64(&mut self) -> u64 {
            self.calls.set(self.calls.get() + 1);
            1
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.calls.set(self.calls.get() + 1);
            destination.fill(1);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    fn bandwidth(value: u32) -> Bandwidth {
        Bandwidth::new(value, value).expect("valid test bandwidth")
    }

    fn sampling_scope(
        family: ObservationAddressFamily,
        minimum_relays: usize,
        maximum_relays: usize,
    ) -> PreselectionSamplingScope {
        PreselectionSamplingScope::new(
            Transport::UdpSinglePath,
            family,
            bandwidth(10),
            minimum_relays,
            maximum_relays,
        )
    }

    fn expect_narrowed(
        result: Result<RouteCandidateSnapshot, PreselectionSamplingFailure>,
        context: &str,
    ) -> RouteCandidateSnapshot {
        match result {
            Ok(snapshot) => snapshot,
            Err(failure) => panic!("{context}: {:?}", failure.error),
        }
    }

    fn expect_sampling_failure(
        result: Result<RouteCandidateSnapshot, PreselectionSamplingFailure>,
        context: &str,
    ) -> PreselectionSamplingFailure {
        match result {
            Ok(_) => panic!("{context}: unexpectedly succeeded"),
            Err(failure) => failure,
        }
    }

    fn output_diversity_is_strict(snapshot: &RouteCandidateSnapshot, family: IpFamily) -> bool {
        let scope = ValidatedSamplingScope {
            transport: CoreTransport::UdpSinglePath,
            family,
            minimum_capacity: bandwidth(10),
            minimum_other_relays: 1,
            maximum_other_relays: 8,
        };
        let exit = &snapshot.forwarded_exits[0];
        let control = &snapshot.direct_relays[0];
        let Some(exit) = static_candidate(exit.advertisement(), ServiceRole::Exit, scope) else {
            return false;
        };
        let Some(control) = static_candidate(control.advertisement(), ServiceRole::Relay, scope)
        else {
            return false;
        };
        let mut diversity = AdvertisedDiversitySet::default();
        if !diversity.allows(&control.diversity) {
            return false;
        }
        diversity.insert(&control.diversity);
        if !diversity.allows(&exit.diversity) {
            return false;
        }
        diversity.insert(&exit.diversity);
        snapshot.direct_relays[1..].iter().all(|relay| {
            static_candidate(relay.advertisement(), ServiceRole::Relay, scope).is_some_and(
                |candidate| {
                    let allowed = diversity.allows(&candidate.diversity);
                    if allowed {
                        diversity.insert(&candidate.diversity);
                    }
                    allowed
                },
            )
        })
    }

    #[test]
    fn advertised_prefix_parser_requires_exact_public_networks() {
        assert_eq!(
            parse_ipv4_prefix("44.10.20.0/24"),
            Some(AdvertisedPrefixHint::Ipv4([44, 10, 20]))
        );
        assert_eq!(
            parse_ipv6_prefix("2606:4700:1234::/48"),
            Some(AdvertisedPrefixHint::Ipv6([
                0x26, 0x06, 0x47, 0x00, 0x12, 0x34
            ]))
        );
        for invalid in [
            "44.10.20.1/24",
            "44.10.20.0/16",
            "10.10.20.0/24",
            "192.0.2.0/24",
        ] {
            assert_eq!(parse_ipv4_prefix(invalid), None, "{invalid}");
        }
        for invalid in [
            "2606:4700:1234::1/48",
            "2606:4700:1234::/64",
            "2001:db8:1234::/48",
        ] {
            assert_eq!(parse_ipv6_prefix(invalid), None, "{invalid}");
        }
    }

    #[tokio::test]
    async fn production_entropy_entrypoint_preserves_the_exact_slate_shape() {
        let snapshot = preselection_snapshot_fixture(1, false).await.snapshot;
        let narrowed = expect_narrowed(
            narrow_route_candidate_snapshot(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 1, 1),
            ),
            "production sampler entrypoint",
        );
        assert_eq!(narrowed.forwarded_exits.len(), 1);
        assert_eq!(narrowed.direct_relays.len(), 2);
        assert_eq!(narrowed.preselection_subjects.forwarded_pairs, [(0, 2)]);
    }

    #[tokio::test]
    async fn seeded_narrowing_returns_one_forwarded_exit_control_and_randomized_bounded_order() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            3,
            12,
            None,
            PreselectionTestCapabilities::default(),
        )
        .await;
        let sampled_at_ms = snapshot.captured_at_ms;
        let mut rng = SeededRng::new(0x9d7a_13c4_55aa_00ef);
        let narrowed = expect_narrowed(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 3, 4),
                sampled_at_ms,
                &mut rng,
            ),
            "diverse bounded slate",
        );

        assert_eq!(narrowed.forwarded_exits.len(), 1);
        assert_eq!(narrowed.direct_relays.len(), 5);
        assert_eq!(narrowed.preselection_subjects.forwarded_pairs, [(0, 5)]);
        assert_eq!(narrowed.preselection_subjects.entries.len(), 6);
        assert_eq!(
            narrowed.forwarded_exits[0].control(),
            &narrowed.direct_relays[0]
        );
        assert!(narrowed.direct_relays[1..].iter().all(|relay| {
            relay.capability().peer_id != narrowed.forwarded_exits[0].capability().exit_peer_id
        }));
        assert!(output_diversity_is_strict(&narrowed, IpFamily::Ipv4));

        let begin = PreselectionAttemptGate::new().expect("attempt gate").begin(
            narrowed,
            Transport::UdpSinglePath,
            ObservationAddressFamily::Ipv4,
            bandwidth(10),
            bandwidth(100),
            bandwidth(80),
        );
        assert!(begin.is_ok(), "narrowed snapshot remains exact A1a input");
    }

    #[tokio::test]
    async fn multiple_forwarded_exits_are_seed_sampled_not_silently_first_sorted() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            4,
            2,
            None,
            PreselectionTestCapabilities::default(),
        )
        .await;
        let scope = sampling_scope(ObservationAddressFamily::Ipv4, 1, 2)
            .validated()
            .expect("scope");
        let mut candidates = scored_forwarded_exits(&snapshot, scope, snapshot.captured_at_ms);
        assert_eq!(candidates.len(), 4);
        assign_exit_bands(&mut candidates);
        canonicalize_exits(&snapshot, &mut candidates);
        let first_exit = snapshot.forwarded_exits[candidates[0].exit_index]
            .capability()
            .exit_node_id;
        let mut selected = HashSet::new();
        for seed in 1..=64 {
            let choice = choose_exit(&candidates, &mut SeededRng::new(seed))
                .expect("entropy")
                .expect("candidate");
            selected.insert(
                snapshot.forwarded_exits[choice.exit_index]
                    .capability()
                    .exit_node_id,
            );
        }
        assert!(
            selected.len() > 1,
            "different seeds must explore multiple exits"
        );
        assert!(selected.iter().any(|exit| *exit != first_exit));
    }

    #[tokio::test]
    async fn same_seed_fixes_exit_and_relay_sampling_order() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            2,
            8,
            None,
            PreselectionTestCapabilities::default(),
        )
        .await;
        let scope = sampling_scope(ObservationAddressFamily::Ipv4, 2, 4)
            .validated()
            .expect("scope");
        let mut exits = scored_forwarded_exits(&snapshot, scope, snapshot.captured_at_ms);
        assign_exit_bands(&mut exits);
        canonicalize_exits(&snapshot, &mut exits);
        let mut left_rng = SeededRng::new(0xa511_cafe);
        let mut right_rng = SeededRng::new(0xa511_cafe);
        let left_exit = choose_exit(&exits, &mut left_rng)
            .expect("entropy")
            .expect("exit");
        let right_exit = choose_exit(&exits, &mut right_rng)
            .expect("entropy")
            .expect("exit");
        assert_eq!(left_exit.exit_index, right_exit.exit_index);
        assert_eq!(left_exit.control_index, right_exit.control_index);

        let mut relays = scored_relays(
            &snapshot,
            left_exit.control_index,
            scope,
            snapshot.captured_at_ms,
        );
        assign_relay_bands(&mut relays);
        canonicalize_relays(&snapshot, &mut relays);
        let mut diversity = AdvertisedDiversitySet::default();
        diversity.insert(&left_exit.exit_diversity);
        diversity.insert(&left_exit.control_diversity);
        let left_order = choose_relay_indices(&relays, diversity.clone(), 4, &mut left_rng)
            .expect("left relay slate");
        let right_order =
            choose_relay_indices(&relays, diversity, 4, &mut right_rng).expect("right relay slate");
        assert_eq!(left_order, right_order);
        assert_eq!(left_order.len(), 4);
        assert_eq!(left_order.iter().copied().collect::<HashSet<_>>().len(), 4);
    }

    #[tokio::test]
    async fn duplicate_hint_clusters_contribute_at_most_one_relay_each() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            3,
            12,
            Some(4),
            PreselectionTestCapabilities::default(),
        )
        .await;
        let sampled_at_ms = snapshot.captured_at_ms;
        let narrowed = expect_narrowed(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 4, 8),
                sampled_at_ms,
                &mut SeededRng::new(0x4433_2211),
            ),
            "four unique relay hint clusters",
        );
        // Four repeated ordinary-relay clusters plus the two non-selected exit controls survive;
        // no repeated operator/ASN/prefix cluster contributes twice.
        assert_eq!(narrowed.direct_relays.len(), 7);
        assert!(output_diversity_is_strict(&narrowed, IpFamily::Ipv4));
    }

    #[tokio::test]
    async fn exact_ipv6_48_hints_drive_the_ipv6_slate() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            2,
            6,
            None,
            PreselectionTestCapabilities::all(),
        )
        .await;
        let sampled_at_ms = snapshot.captured_at_ms;
        let narrowed = expect_narrowed(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv6, 3, 3),
                sampled_at_ms,
                &mut SeededRng::new(0x600d_f00d),
            ),
            "IPv6 /48-diverse slate",
        );
        assert_eq!(narrowed.direct_relays.len(), 4);
        assert!(output_diversity_is_strict(&narrowed, IpFamily::Ipv6));
    }

    #[tokio::test]
    async fn invalid_policy_and_ambiguous_pairing_fail_before_rng_and_retain_snapshot() {
        let snapshot = preselection_snapshot_fixture(2, false).await.snapshot;
        let original_direct = snapshot.direct_relays.len();
        let original_exits = snapshot.forwarded_exits.len();
        let sampled_at_ms = snapshot.captured_at_ms;
        let calls = Cell::new(0);
        let failure = expect_sampling_failure(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 0, 8),
                sampled_at_ms,
                &mut CountingRng { calls: &calls },
            ),
            "invalid bounds",
        );
        assert_eq!(failure.error, PreselectionSamplingError::InvalidPolicy);
        assert_eq!(failure.snapshot.direct_relays.len(), original_direct);
        assert_eq!(failure.snapshot.forwarded_exits.len(), original_exits);
        assert_eq!(calls.get(), 0);

        let mut snapshot = *failure.snapshot;
        snapshot
            .preselection_subjects
            .forwarded_pairs
            .push(snapshot.preselection_subjects.forwarded_pairs[0]);
        let failure = expect_sampling_failure(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 1, 2),
                sampled_at_ms,
                &mut CountingRng { calls: &calls },
            ),
            "duplicate pair ambiguity",
        );
        assert_eq!(failure.error, PreselectionSamplingError::InvalidSnapshot);
        assert_eq!(failure.snapshot.direct_relays.len(), original_direct);
        assert_eq!(failure.snapshot.forwarded_exits.len(), original_exits);
        assert_eq!(calls.get(), 0);
    }

    #[tokio::test]
    async fn insufficient_operator_asn_or_prefix_diversity_fails_closed() {
        let snapshot = preselection_multi_exit_snapshot_fixture(
            2,
            4,
            Some(2),
            PreselectionTestCapabilities::default(),
        )
        .await;
        let sampled_at_ms = snapshot.captured_at_ms;
        let failure = expect_sampling_failure(
            narrow_route_candidate_snapshot_at(
                snapshot,
                sampling_scope(ObservationAddressFamily::Ipv4, 4, 4),
                sampled_at_ms,
                &mut SeededRng::new(7),
            ),
            "two ordinary clusters plus one unselected control cannot satisfy four",
        );
        assert_eq!(
            failure.error,
            PreselectionSamplingError::InsufficientDiverseRelays
        );
        assert_eq!(failure.snapshot.forwarded_exits.len(), 2);
        assert_eq!(failure.snapshot.direct_relays.len(), 6);
    }
}
