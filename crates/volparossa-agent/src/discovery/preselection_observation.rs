//! Actor-owned affine state and exact A1a/A1c freshness join for one bounded attempt.
//!
//! This child owns challenge generation, replay state, exact snapshot/request binding, opaque A0
//! transcript tokens, and the one-way join with service-bound client transport proofs. The join
//! emits only endpoint-free prefixes, local arrival time/RTT, and signed validity ceilings; only
//! the route-selection child can mint its existing private evidence batch. Neither child can mint
//! measured capacity, dataplane-address usability, or route/session authority.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::time::Instant;
use volparossa_core::{Bandwidth, IpFamily, ObservedNetworkPrefix};
use volparossa_discovery::{
    BoundClientPreselectionTransport, ClientPreselectionBindFailure,
    ClientPreselectionObservationRequest, ClientPreselectionResponseArrival,
    ClientPreselectionTransaction, ClientPreselectionTransportFreshnessProof, DiscoveryService,
    PreselectionDispatchError, consume_bound_client_preselection_transport_for_freshness,
};
use volparossa_protocol::{
    BoundDirectPreselectionTranscript, BoundForwardedPreselectionTranscript,
    DirectPreselectionFreshnessProof, ForwardedPreselectionFreshnessProof,
    ObservationAddressFamily, PreselectionActorBinding, PreselectionObservationRequest,
    PreselectionObservationRole, PreselectionObservationScope, ReplayCache, TimePolicy, Transport,
    consume_bound_direct_preselection_transcript_for_freshness,
    consume_bound_forwarded_preselection_transcript_for_freshness,
    consume_direct_preselection_transcript, consume_forwarded_preselection_transcript,
    encode_canonical, preselection_observation_request_hash, verify_direct_preselection_transcript,
    verify_forwarded_preselection_transcript,
};

use super::{
    AdvertisementPayloadHash, DirectRelayCandidateSnapshot, ForwardedExitCandidateSnapshot,
    RevalidatedStoredCandidate, RouteCandidateSnapshot,
};

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const BATCH_ID_LENGTH: usize = 16;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const CHALLENGE_LENGTH: usize = 32;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_REQUEST_BYTES: usize = 4 * 1024;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_OTHER_RELAYS: usize = 8;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MINIMUM_REQUESTS: usize = 2;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_REQUESTS: usize = 9;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_ENVELOPES: usize = 10;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_TOMBSTONES: usize = 36;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const MAXIMUM_BATCH_TOMBSTONES: usize = 4;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const REPLAY_CAPACITY: usize = 40;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const REQUEST_LIFETIME_MS: u64 = 5_000;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const ATTEMPT_LIFETIME_MS: u64 = 30_000;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const TOMBSTONE_LIFETIME_MS: u64 = 120_000;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const TOMBSTONE_LIFETIME: Duration = Duration::from_secs(120);
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const COOLDOWN_MS: u64 = 30_000;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
const COOLDOWN: Duration = Duration::from_secs(30);

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PreselectionSubjectBinding {
    node_id: [u8; 32],
    peer_id: Vec<u8>,
    public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
    advertisement_payload_hash: AdvertisementPayloadHash,
    policy_version: u64,
    policy_hash: [u8; 32],
    policy_expires_at_ms: u64,
    capability_expires_at_ms: u64,
    local_discovery_authority_expires_at_ms: u64,
    relay: bool,
    exit: bool,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PreselectionSubjectSet {
    pub(super) available: bool,
    pub(super) entries: Vec<PreselectionSubjectBinding>,
    pub(super) forwarded_pairs: Vec<(usize, usize)>,
}

impl PreselectionSubjectSet {
    pub(super) fn from_snapshot(
        revalidated: &[RevalidatedStoredCandidate],
        direct_relays: &[DirectRelayCandidateSnapshot],
        forwarded_exits: &[ForwardedExitCandidateSnapshot],
    ) -> Self {
        Self::try_from_snapshot(revalidated, direct_relays, forwarded_exits)
            .unwrap_or_else(Self::unavailable)
    }

    fn try_from_snapshot(
        revalidated: &[RevalidatedStoredCandidate],
        direct_relays: &[DirectRelayCandidateSnapshot],
        forwarded_exits: &[ForwardedExitCandidateSnapshot],
    ) -> Option<Self> {
        let mut entries =
            Vec::with_capacity(direct_relays.len().saturating_add(forwarded_exits.len()));
        for candidate in direct_relays {
            entries.push(subject_for_direct(revalidated, candidate)?);
        }
        for candidate in forwarded_exits {
            entries.push(subject_for_exit(revalidated, candidate)?);
        }
        if entries.len() != direct_relays.len().saturating_add(forwarded_exits.len())
            || !subject_identities_are_unique(&entries)
        {
            return None;
        }
        let mut forwarded_pairs = Vec::with_capacity(forwarded_exits.len());
        for (exit_offset, forwarded) in forwarded_exits.iter().enumerate() {
            let control = forwarded.control().capability();
            let mut controls = direct_relays.iter().enumerate().filter(|(_, direct)| {
                let candidate = direct.capability();
                candidate.node_id == control.node_id
                    && candidate.peer_id == control.peer_id
                    && candidate.public_key == control.public_key
                    && candidate.advertisement_sequence == control.advertisement_sequence
                    && candidate.advertisement_expires_at_ms == control.advertisement_expires_at_ms
                    && candidate.advertisement_payload_hash == control.advertisement_payload_hash
            });
            let (control_index, _) = controls.next()?;
            if controls.next().is_some() {
                return None;
            }
            forwarded_pairs.push((control_index, direct_relays.len() + exit_offset));
        }
        Some(Self {
            available: true,
            entries,
            forwarded_pairs,
        })
    }

    const fn unavailable() -> Self {
        Self {
            available: false,
            entries: Vec::new(),
            forwarded_pairs: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) const fn unavailable_for_test() -> Self {
        Self::unavailable()
    }

    #[cfg(test)]
    pub(super) fn availability_and_hashes_for_test(&self) -> (bool, Vec<AdvertisementPayloadHash>) {
        (
            self.available,
            self.entries
                .iter()
                .map(|entry| entry.advertisement_payload_hash)
                .collect(),
        )
    }
}

fn subject_for_direct(
    revalidated: &[RevalidatedStoredCandidate],
    candidate: &DirectRelayCandidateSnapshot,
) -> Option<PreselectionSubjectBinding> {
    let capability = candidate.capability();
    let exact = unique_revalidated(
        revalidated,
        capability.node_id,
        &capability.peer_id.to_bytes(),
        capability.public_key,
        capability.advertisement_sequence,
        capability.advertisement_expires_at_ms,
    )?;
    if !exact.revalidated.relay
        || exact.revalidated.policy_version != capability.policy_version
        || exact.revalidated.policy_hash != capability.policy_hash
        || exact.revalidated.fingerprint.payload_hash != capability.advertisement_payload_hash
        || candidate.advertisement().advertisement_payload_hash()
            != capability.advertisement_payload_hash
    {
        return None;
    }
    Some(PreselectionSubjectBinding {
        node_id: capability.node_id,
        peer_id: capability.peer_id.to_bytes(),
        public_key: capability.public_key,
        advertisement_sequence: capability.advertisement_sequence,
        advertisement_expires_at_ms: capability.advertisement_expires_at_ms,
        advertisement_payload_hash: capability.advertisement_payload_hash,
        policy_version: capability.policy_version,
        policy_hash: capability.policy_hash,
        policy_expires_at_ms: capability.policy_expires_at_ms,
        capability_expires_at_ms: capability.expires_at_ms,
        local_discovery_authority_expires_at_ms: capability.expires_at_ms,
        relay: true,
        exit: false,
    })
}

fn subject_for_exit(
    revalidated: &[RevalidatedStoredCandidate],
    candidate: &ForwardedExitCandidateSnapshot,
) -> Option<PreselectionSubjectBinding> {
    let capability = candidate.capability();
    let exact = unique_revalidated(
        revalidated,
        capability.exit_node_id,
        &capability.exit_peer_id.to_bytes(),
        capability.exit_public_key,
        capability.exit_advertisement_sequence,
        capability.exit_advertisement_expires_at_ms,
    )?;
    if !exact.revalidated.exit
        || exact.revalidated.policy_version != capability.policy_version
        || exact.revalidated.policy_hash != capability.policy_hash
        || exact.revalidated.fingerprint.payload_hash != capability.exit_advertisement_payload_hash
        || candidate.advertisement().advertisement_payload_hash()
            != capability.exit_advertisement_payload_hash
    {
        return None;
    }
    let canonical_capability_expires_at_ms = capability
        .exit_advertisement_expires_at_ms
        .min(capability.policy_expires_at_ms)
        .min(candidate.control().capability().expires_at_ms);
    Some(PreselectionSubjectBinding {
        node_id: capability.exit_node_id,
        peer_id: capability.exit_peer_id.to_bytes(),
        public_key: capability.exit_public_key,
        advertisement_sequence: capability.exit_advertisement_sequence,
        advertisement_expires_at_ms: capability.exit_advertisement_expires_at_ms,
        advertisement_payload_hash: capability.exit_advertisement_payload_hash,
        policy_version: capability.policy_version,
        policy_hash: capability.policy_hash,
        policy_expires_at_ms: capability.policy_expires_at_ms,
        capability_expires_at_ms: canonical_capability_expires_at_ms,
        local_discovery_authority_expires_at_ms: capability.expires_at_ms,
        relay: false,
        exit: true,
    })
}

fn unique_revalidated<'a>(
    revalidated: &'a [RevalidatedStoredCandidate],
    node_id: [u8; 32],
    peer_id: &[u8],
    public_key: [u8; 32],
    advertisement_sequence: u64,
    advertisement_expires_at_ms: u64,
) -> Option<&'a RevalidatedStoredCandidate> {
    let mut matches = revalidated.iter().filter(|candidate| {
        candidate.revalidated.wire_node_id == node_id
            && candidate.revalidated.peer_id.to_bytes() == peer_id
            && candidate.revalidated.public_key == public_key
            && candidate.revalidated.sequence_number == advertisement_sequence
            && candidate.revalidated.signed_expires_at_ms == advertisement_expires_at_ms
    });
    let exact = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(exact)
}

fn subject_identities_are_unique(entries: &[PreselectionSubjectBinding]) -> bool {
    let mut nodes = HashSet::with_capacity(entries.len());
    let mut peers = HashSet::with_capacity(entries.len());
    let mut keys = HashSet::with_capacity(entries.len());
    entries.iter().all(|entry| {
        nodes.insert(entry.node_id)
            && peers.insert(entry.peer_id.clone())
            && keys.insert(entry.public_key)
    })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct ChallengeTombstone {
    challenge: [u8; CHALLENGE_LENGTH],
    expires_at: Instant,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct BatchTombstone {
    batch_id: [u8; BATCH_ID_LENGTH],
    expires_at: Instant,
}

/// Discovery-private single-owner admission token for A1a attempts.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PreselectionAttemptGate {
    tombstones: VecDeque<ChallengeTombstone>,
    batch_tombstones: VecDeque<BatchTombstone>,
    replay: Box<ReplayCache>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(crate) struct CoolingPreselectionAttemptGate {
    gate: PreselectionAttemptGate,
    ready_at_ms: u64,
    ready_at: Instant,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct MintedAttemptEntropy {
    batch_id: [u8; BATCH_ID_LENGTH],
    challenges: Vec<[u8; CHALLENGE_LENGTH]>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct ObservationDispatchId {
    batch_id: [u8; BATCH_ID_LENGTH],
    ordinal: u8,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
#[derive(Clone, Copy)]
enum PendingRequestKind {
    Direct,
    Forwarded,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct RequestPlan {
    subject: usize,
    forwarded_control: Option<usize>,
    role: PreselectionObservationRole,
    kind: PendingRequestKind,
    challenge: [u8; CHALLENGE_LENGTH],
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct PendingRequest {
    dispatch_id: ObservationDispatchId,
    expected_request: Vec<u8>,
    request_hash: [u8; 32],
    subject: usize,
    forwarded_control: Option<usize>,
    role: PreselectionObservationRole,
    created_at_ms: u64,
    prepared_at_mono: Instant,
    expires_at_mono: Instant,
    kind: PendingRequestKind,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
enum BoundTranscript {
    Direct(Box<BoundDirectPreselectionTranscript>),
    Forwarded(Box<BoundForwardedPreselectionTranscript>),
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct BoundTranscriptRecord {
    dispatch_id: ObservationDispatchId,
    request_hash: [u8; 32],
    subject: usize,
    forwarded_control: Option<usize>,
    role: PreselectionObservationRole,
    transcript: BoundTranscript,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PendingPreselectionAttempt {
    gate: PreselectionAttemptGate,
    snapshot: RouteCandidateSnapshot,
    transport: Transport,
    address_family: ObservationAddressFamily,
    batch_id: [u8; BATCH_ID_LENGTH],
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    attempt_started_at_mono: Instant,
    attempt_deadline_mono: Instant,
    minimum_capacity: Bandwidth,
    preselection_capacity_ceiling: Bandwidth,
    pending: PendingRequest,
    remaining: VecDeque<RequestPlan>,
    bound: Vec<BoundTranscriptRecord>,
}

/// Opaque affine owner of one exact service dispatch and its unchanged A1a attempt.
///
/// Only this child can construct or consume the wrapper. The parent actor can move it between
/// events, bind a service-sealed arrival, or cancel it through the originating service; it cannot
/// inspect or replace the target, request, deadline, dispatch identity, or retained attempt.
#[must_use = "a dispatched preselection attempt must be bound or cancelled"]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "opaque A1 dispatch transition used only by DiscoveryRuntime"
    )
)]
pub(super) struct DispatchedPreselectionAttempt {
    transaction: ClientPreselectionTransaction<PendingPreselectionAttempt>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) enum PreselectionResponseOutcome {
    Pending(PendingPreselectionAttempt),
    Ready(ReadyPreselectionAttempt),
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct ReadyPreselectionAttempt {
    gate: PreselectionAttemptGate,
    snapshot: RouteCandidateSnapshot,
    transport: Transport,
    address_family: ObservationAddressFamily,
    batch_id: [u8; BATCH_ID_LENGTH],
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    attempt_started_at_mono: Instant,
    attempt_deadline_mono: Instant,
    minimum_capacity: Bandwidth,
    preselection_capacity_ceiling: Bandwidth,
    last_verified_at_ms: u64,
    last_verified_at_mono: Instant,
    bound: Vec<BoundTranscriptRecord>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct BoundPreselectionTranscriptBatch {
    transport: Transport,
    address_family: ObservationAddressFamily,
    batch_id: [u8; BATCH_ID_LENGTH],
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    attempt_started_at_mono: Instant,
    attempt_deadline_mono: Instant,
    minimum_capacity: Bandwidth,
    preselection_capacity_ceiling: Bandwidth,
    transcripts: Vec<BoundTranscriptRecord>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(crate) struct CompletedPreselectionAttempt {
    snapshot: RouteCandidateSnapshot,
    batch: BoundPreselectionTranscriptBatch,
    gate: CoolingPreselectionAttemptGate,
}

/// Endpoint-free local facts purpose-consumed from one exact client-hop transport proof.
///
/// This value has no constructor or clone surface. It is produced only while the affine A1a
/// owner still holds the matching request hash, native family, and monotonic attempt window.
pub(crate) struct PreselectionTransportFreshnessFacts {
    observed_network_prefix: ObservedNetworkPrefix,
    observed_at_ms: u64,
    round_trip: Duration,
}

impl PreselectionTransportFreshnessFacts {
    pub(crate) const fn observed_network_prefix(&self) -> ObservedNetworkPrefix {
        self.observed_network_prefix
    }

    pub(crate) const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    pub(crate) const fn round_trip(&self) -> Duration {
        self.round_trip
    }
}

/// Actor-purpose cryptographic facts consumed from one exact verified transcript.
///
/// The direct form proves only its signed lifetime. The forwarded form additionally carries the
/// normalized endpoint-free Exit prefix signed by the exact control Relay. Neither form contains
/// reusable dispatch, signature, request, endpoint, or reservation authority.
pub(crate) enum PreselectionTranscriptFreshnessFacts {
    Direct {
        valid_until_ms: u64,
    },
    Forwarded {
        valid_until_ms: u64,
        upstream_network_prefix: ObservedNetworkPrefix,
    },
}

impl PreselectionTranscriptFreshnessFacts {
    pub(crate) const fn valid_until_ms(&self) -> u64 {
        match self {
            Self::Direct { valid_until_ms } | Self::Forwarded { valid_until_ms, .. } => {
                *valid_until_ms
            }
        }
    }

    pub(crate) const fn upstream_network_prefix(&self) -> Option<ObservedNetworkPrefix> {
        match self {
            Self::Direct { .. } => None,
            Self::Forwarded {
                upstream_network_prefix,
                ..
            } => Some(*upstream_network_prefix),
        }
    }
}

/// One exact A1a actor/request record joined affinely to its A1c transport proof.
///
/// Subject indexes are meaningful only beside the retained snapshot in the enclosing completed
/// attempt. Fields stay private, and the sole production mint consumes both opaque proof kinds.
pub(crate) struct PreselectionFreshnessProofRecord {
    subject: usize,
    forwarded_control: Option<usize>,
    role: PreselectionObservationRole,
    transport: PreselectionTransportFreshnessFacts,
    transcript: PreselectionTranscriptFreshnessFacts,
}

impl PreselectionFreshnessProofRecord {
    pub(crate) fn into_parts(
        self,
    ) -> (
        usize,
        Option<usize>,
        PreselectionObservationRole,
        PreselectionTransportFreshnessFacts,
        PreselectionTranscriptFreshnessFacts,
    ) {
        (
            self.subject,
            self.forwarded_control,
            self.role,
            self.transport,
            self.transcript,
        )
    }
}

/// Exact bounded proof batch after every request has both transport and actor proof.
pub(crate) struct BoundPreselectionFreshnessProofBatch {
    transport: Transport,
    address_family: ObservationAddressFamily,
    batch_id: [u8; BATCH_ID_LENGTH],
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    minimum_capacity: Bandwidth,
    preselection_capacity_ceiling: Bandwidth,
    records: Vec<PreselectionFreshnessProofRecord>,
}

impl BoundPreselectionFreshnessProofBatch {
    #[allow(
        clippy::type_complexity,
        reason = "one affine destructure has no reusable authority"
    )]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Transport,
        ObservationAddressFamily,
        [u8; BATCH_ID_LENGTH],
        u64,
        u64,
        Bandwidth,
        Bandwidth,
        Vec<PreselectionFreshnessProofRecord>,
    ) {
        (
            self.transport,
            self.address_family,
            self.batch_id,
            self.attempt_started_at_ms,
            self.attempt_deadline_ms,
            self.minimum_capacity,
            self.preselection_capacity_ceiling,
            self.records,
        )
    }
}

/// Original actor snapshot plus the exact purpose-consumed proof batch and cooldown owner.
pub(crate) struct CompletedPreselectionFreshnessAttempt {
    snapshot: RouteCandidateSnapshot,
    batch: BoundPreselectionFreshnessProofBatch,
    gate: CoolingPreselectionAttemptGate,
}

impl CompletedPreselectionFreshnessAttempt {
    pub(crate) fn into_parts(
        self,
    ) -> (
        RouteCandidateSnapshot,
        BoundPreselectionFreshnessProofBatch,
        CoolingPreselectionAttemptGate,
    ) {
        (self.snapshot, self.batch, self.gate)
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "selection-bridge tests need an authority-free proof-fact fixture"
    )]
    pub(crate) fn for_test(
        snapshot: RouteCandidateSnapshot,
        transport: Transport,
        address_family: ObservationAddressFamily,
        batch_id: [u8; BATCH_ID_LENGTH],
        attempt_started_at_ms: u64,
        attempt_deadline_ms: u64,
        minimum_capacity: Bandwidth,
        preselection_capacity_ceiling: Bandwidth,
        records: Vec<(
            usize,
            Option<usize>,
            PreselectionObservationRole,
            ObservedNetworkPrefix,
            u64,
            Duration,
            PreselectionTranscriptFreshnessFacts,
        )>,
    ) -> Self {
        let now = Instant::now();
        Self {
            snapshot,
            batch: BoundPreselectionFreshnessProofBatch {
                transport,
                address_family,
                batch_id,
                attempt_started_at_ms,
                attempt_deadline_ms,
                minimum_capacity,
                preselection_capacity_ceiling,
                records: records
                    .into_iter()
                    .map(
                        |(
                            subject,
                            forwarded_control,
                            role,
                            observed_network_prefix,
                            observed_at_ms,
                            round_trip,
                            transcript,
                        )| PreselectionFreshnessProofRecord {
                            subject,
                            forwarded_control,
                            role,
                            transport: PreselectionTransportFreshnessFacts {
                                observed_network_prefix,
                                observed_at_ms,
                                round_trip,
                            },
                            transcript,
                        },
                    )
                    .collect(),
            },
            gate: CoolingPreselectionAttemptGate {
                gate: PreselectionAttemptGate::new().expect("test freshness gate"),
                ready_at_ms: attempt_deadline_ms,
                ready_at: now,
            },
        }
    }
}

/// Terminal proof-join rejection with the attempt gate retained for bounded cooldown recovery.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the discovery actor retains this gate across client preselection cooldown"
    )
)]
pub(crate) struct PreselectionFreshnessJoinFailure {
    gate: CoolingPreselectionAttemptGate,
    error: PreselectionAttemptError,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the discovery actor purpose-consumes this exact proof-join failure"
    )
)]
impl PreselectionFreshnessJoinFailure {
    pub(crate) const fn error(&self) -> PreselectionAttemptError {
        self.error
    }

    pub(crate) fn into_gate(self) -> CoolingPreselectionAttemptGate {
        self.gate
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
struct ValidatedAttemptInput {
    snapshot: RouteCandidateSnapshot,
    transport: Transport,
    address_family: ObservationAddressFamily,
    preselection_capacity_ceiling: Bandwidth,
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    attempt_started_at_mono: Instant,
    attempt_deadline_mono: Instant,
    minimum_capacity: Bandwidth,
    other_relay_subjects: Vec<usize>,
    control_subject: usize,
    exit_subject: usize,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
#[derive(Clone, Copy)]
struct AttemptStart {
    transport: Transport,
    address_family: ObservationAddressFamily,
    minimum_capacity: Bandwidth,
    local_profile_capacity: Bandwidth,
    preselection_capacity_ceiling: Bandwidth,
    attempt_started_at_ms: u64,
    attempt_started_at_mono: Instant,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
#[derive(Clone, Copy)]
struct RequestPreparation<'a> {
    snapshot: &'a RouteCandidateSnapshot,
    transport: Transport,
    address_family: ObservationAddressFamily,
    batch_id: [u8; BATCH_ID_LENGTH],
    created_at_ms: u64,
    prepared_at_mono: Instant,
    attempt_deadline_ms: u64,
    attempt_deadline_mono: Instant,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
#[derive(Clone, Copy)]
struct RequestBinding<'a> {
    subject: &'a PreselectionSubjectBinding,
    forwarded_control: Option<&'a PreselectionSubjectBinding>,
    role: PreselectionObservationRole,
    transport: Transport,
    address_family: ObservationAddressFamily,
    policy: super::RouteCandidatePolicySnapshot,
    challenge: [u8; CHALLENGE_LENGTH],
    created_at_ms: u64,
    attempt_deadline_ms: u64,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreselectionAttemptError {
    InvalidSnapshot,
    InvalidCapacity,
    InvalidTime,
    Entropy,
    TombstoneCapacity,
    Request,
    UnknownDispatch,
    Transport,
    Protocol,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PreselectionBeginFailure {
    gate: Option<Box<PreselectionAttemptGate>>,
    cooling_gate: Option<Box<CoolingPreselectionAttemptGate>>,
    error: PreselectionAttemptError,
}

/// Exact affine recovery after attempt admission stops before or after entropy commitment.
pub(super) enum PreselectionGateRecovery {
    Available(Box<PreselectionAttemptGate>),
    Cooling(Box<CoolingPreselectionAttemptGate>),
    Closed,
}

/// Exact local recovery after an undispatched Pending or Ready owner terminates.
pub(super) enum PreselectionLocalRecovery {
    Cooling(CoolingPreselectionAttemptGate),
    Closed,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
pub(super) struct PreselectionAttemptFailure {
    gate: Option<CoolingPreselectionAttemptGate>,
    error: PreselectionAttemptError,
}

/// Fail-closed result of an owner-only dispatch, bind, or cancellation transition.
///
/// A foreign service cannot consume the transaction, so the exact opaque owner is retained for
/// cancellation through its origin. Every terminal path yields only cooling authority, or closes
/// permanently if a backwards clock makes even that authority unsafe to mint.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "opaque A1 dispatch transition used only by DiscoveryRuntime"
    )
)]
pub(super) enum PreselectionOwnerTransitionFailure {
    Retained(Box<DispatchedPreselectionAttempt>),
    Cooling(CoolingPreselectionAttemptGate),
    Closed,
}

/// Purpose-consume a failed begin without exposing its gate or admission classification.
pub(super) fn consume_preselection_begin_failure(
    failure: PreselectionBeginFailure,
) -> PreselectionGateRecovery {
    match (failure.gate, failure.cooling_gate) {
        (Some(gate), None) => PreselectionGateRecovery::Available(gate),
        (None, Some(gate)) => PreselectionGateRecovery::Cooling(gate),
        _ => PreselectionGateRecovery::Closed,
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
impl PreselectionAttemptGate {
    pub(super) fn new() -> Result<Self, PreselectionAttemptError> {
        let replay =
            ReplayCache::new(REPLAY_CAPACITY).map_err(|_| PreselectionAttemptError::Protocol)?;
        Ok(Self {
            tombstones: VecDeque::with_capacity(MAXIMUM_TOMBSTONES),
            batch_tombstones: VecDeque::with_capacity(MAXIMUM_BATCH_TOMBSTONES),
            replay: Box::new(replay),
        })
    }

    pub(super) fn begin(
        self,
        snapshot: RouteCandidateSnapshot,
        transport: Transport,
        address_family: ObservationAddressFamily,
        minimum_capacity: Bandwidth,
        local_profile_capacity: Bandwidth,
        preselection_capacity_ceiling: Bandwidth,
    ) -> Result<PendingPreselectionAttempt, PreselectionBeginFailure> {
        let attempt_started_at_ms = crate::unix_millis();
        let attempt_started_at_mono = Instant::now();
        self.begin_at(
            snapshot,
            AttemptStart {
                transport,
                address_family,
                minimum_capacity,
                local_profile_capacity,
                preselection_capacity_ceiling,
                attempt_started_at_ms,
                attempt_started_at_mono,
            },
        )
    }

    fn begin_at(
        self,
        snapshot: RouteCandidateSnapshot,
        start: AttemptStart,
    ) -> Result<PendingPreselectionAttempt, PreselectionBeginFailure> {
        let validated = match validate_attempt_input(snapshot, &start) {
            Ok(validated) => validated,
            Err(error) => {
                return Err(PreselectionBeginFailure {
                    gate: Some(Box::new(self)),
                    cooling_gate: None,
                    error,
                });
            }
        };
        self.begin_validated(validated)
    }

    #[cfg(test)]
    fn begin_at_with_entropy_for_test<F>(
        self,
        snapshot: RouteCandidateSnapshot,
        start: AttemptStart,
        mint_entropy: F,
    ) -> Result<PendingPreselectionAttempt, PreselectionBeginFailure>
    where
        F: FnOnce(usize) -> Result<MintedAttemptEntropy, PreselectionAttemptError>,
    {
        let validated = match validate_attempt_input(snapshot, &start) {
            Ok(validated) => validated,
            Err(error) => {
                return Err(PreselectionBeginFailure {
                    gate: Some(Box::new(self)),
                    cooling_gate: None,
                    error,
                });
            }
        };
        self.begin_validated_with(validated, mint_entropy)
    }

    fn begin_validated(
        self,
        validated: ValidatedAttemptInput,
    ) -> Result<PendingPreselectionAttempt, PreselectionBeginFailure> {
        self.begin_validated_with(validated, mint_attempt_entropy)
    }

    fn begin_validated_with<F>(
        mut self,
        validated: ValidatedAttemptInput,
        mint_entropy: F,
    ) -> Result<PendingPreselectionAttempt, PreselectionBeginFailure>
    where
        F: FnOnce(usize) -> Result<MintedAttemptEntropy, PreselectionAttemptError>,
    {
        self.tombstones
            .retain(|entry| entry.expires_at > validated.attempt_started_at_mono);
        self.batch_tombstones
            .retain(|entry| entry.expires_at > validated.attempt_started_at_mono);
        let request_count = validated.other_relay_subjects.len().saturating_add(1);
        if !(MINIMUM_REQUESTS..=MAXIMUM_REQUESTS).contains(&request_count)
            || self.tombstones.len().saturating_add(request_count) > MAXIMUM_TOMBSTONES
            || self.batch_tombstones.len().saturating_add(1) > MAXIMUM_BATCH_TOMBSTONES
        {
            return Err(PreselectionBeginFailure {
                gate: Some(Box::new(self)),
                cooling_gate: None,
                error: PreselectionAttemptError::TombstoneCapacity,
            });
        }
        let entropy = match mint_entropy(request_count) {
            Ok(entropy) => entropy,
            Err(error) => return Err(self.admitted_failure(&validated, error)),
        };
        if entropy.batch_id == [0; BATCH_ID_LENGTH]
            || entropy.challenges.len() != request_count
            || entropy
                .challenges
                .iter()
                .any(|challenge| *challenge == [0; CHALLENGE_LENGTH])
            || !all_challenges_unique(&entropy.challenges)
            || entropy.challenges.iter().any(|challenge| {
                self.tombstones
                    .iter()
                    .any(|entry| entry.challenge == *challenge)
            })
            || self
                .batch_tombstones
                .iter()
                .any(|entry| entry.batch_id == entropy.batch_id)
        {
            return Err(self.admitted_failure(&validated, PreselectionAttemptError::Entropy));
        }
        let mut remaining = match build_request_plans(&validated, &entropy) {
            Ok(requests) => requests,
            Err(error) => return Err(self.admitted_failure(&validated, error)),
        };
        let Some(first_plan) = remaining.pop_front() else {
            return Err(self.admitted_failure(&validated, PreselectionAttemptError::Request));
        };
        let first_challenge = first_plan.challenge;
        let pending = match prepare_request(
            &RequestPreparation {
                snapshot: &validated.snapshot,
                transport: validated.transport,
                address_family: validated.address_family,
                batch_id: entropy.batch_id,
                created_at_ms: validated.attempt_started_at_ms,
                prepared_at_mono: validated.attempt_started_at_mono,
                attempt_deadline_ms: validated.attempt_deadline_ms,
                attempt_deadline_mono: validated.attempt_deadline_mono,
            },
            &first_plan,
            1,
        ) {
            Ok(pending) => pending,
            Err(error) => return Err(self.admitted_failure(&validated, error)),
        };
        if let Err(error) = record_prepared_entropy(
            &mut self,
            entropy.batch_id,
            first_challenge,
            validated.attempt_started_at_mono,
        ) {
            return Err(self.admitted_failure(&validated, error));
        }
        Ok(PendingPreselectionAttempt {
            gate: self,
            snapshot: validated.snapshot,
            transport: validated.transport,
            address_family: validated.address_family,
            batch_id: entropy.batch_id,
            attempt_started_at_ms: validated.attempt_started_at_ms,
            attempt_deadline_ms: validated.attempt_deadline_ms,
            attempt_started_at_mono: validated.attempt_started_at_mono,
            attempt_deadline_mono: validated.attempt_deadline_mono,
            minimum_capacity: validated.minimum_capacity,
            preselection_capacity_ceiling: validated.preselection_capacity_ceiling,
            pending,
            remaining,
            bound: Vec::with_capacity(request_count),
        })
    }

    fn admitted_failure(
        self,
        validated: &ValidatedAttemptInput,
        error: PreselectionAttemptError,
    ) -> PreselectionBeginFailure {
        PreselectionBeginFailure {
            gate: None,
            cooling_gate: cooling_gate(
                self,
                validated.attempt_started_at_ms,
                validated.attempt_started_at_ms,
                validated.attempt_started_at_mono,
                validated.attempt_started_at_mono,
            )
            .map(Box::new),
            error,
        }
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
impl CoolingPreselectionAttemptGate {
    pub(super) fn resume(self) -> Result<PreselectionAttemptGate, CoolingPreselectionAttemptGate> {
        let now_ms = crate::unix_millis();
        let now = Instant::now();
        self.resume_at(now_ms, now)
    }

    fn resume_at(
        self,
        now_ms: u64,
        now: Instant,
    ) -> Result<PreselectionAttemptGate, CoolingPreselectionAttemptGate> {
        if now_ms < self.ready_at_ms || now < self.ready_at {
            return Err(self);
        }
        Ok(self.gate)
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
impl PendingPreselectionAttempt {
    /// Consume this exact attempt into one request-derived service dispatch.
    ///
    /// The parent supplies only its owning service. Canonical bytes and the monotonic deadline are
    /// copied from the private pending request, while `self` moves unchanged into the discovery
    /// transaction context. No target, family, request, deadline, or dispatch identity is accepted
    /// from the caller.
    pub(super) fn dispatch(
        self,
        service: &mut DiscoveryService,
    ) -> Result<DispatchedPreselectionAttempt, PreselectionOwnerTransitionFailure> {
        let absolute_deadline = self.pending.expires_at_mono;
        let Ok(request) = ClientPreselectionObservationRequest::from_canonical(Vec::from(
            self.pending.expected_request.as_slice(),
        )) else {
            return Err(self.terminal_owner_failure(PreselectionAttemptError::Request));
        };
        match service.dispatch_preselection_observation_with_context(
            request,
            absolute_deadline,
            self,
        ) {
            Ok(transaction) => Ok(DispatchedPreselectionAttempt { transaction }),
            Err(failure) => {
                let error = preselection_attempt_error(failure.error());
                Err(failure.into_context().terminal_owner_failure(error))
            }
        }
    }

    fn verify_response_from_exact_dispatch(
        self,
        encoded_response: &[u8],
    ) -> Result<PreselectionResponseOutcome, PreselectionAttemptFailure> {
        let transcript_verified_at_ms = crate::unix_millis();
        let transcript_verified_at_mono = Instant::now();
        if self.response_time_is_invalid(transcript_verified_at_ms, transcript_verified_at_mono) {
            return Err(self.fail(
                PreselectionAttemptError::InvalidTime,
                transcript_verified_at_ms,
                transcript_verified_at_mono,
            ));
        }
        self.verify_authenticated_response_at(
            encoded_response,
            transcript_verified_at_ms,
            transcript_verified_at_mono,
        )
    }

    #[cfg(test)]
    fn verify_response_at(
        self,
        dispatch_id: &ObservationDispatchId,
        encoded_response: &[u8],
        transcript_verified_at_ms: u64,
        transcript_verified_at_mono: Instant,
    ) -> Result<PreselectionResponseOutcome, PreselectionAttemptFailure> {
        if self.response_time_is_invalid(transcript_verified_at_ms, transcript_verified_at_mono) {
            return Err(self.fail(
                PreselectionAttemptError::InvalidTime,
                transcript_verified_at_ms,
                transcript_verified_at_mono,
            ));
        }
        if self.pending.dispatch_id.batch_id != dispatch_id.batch_id
            || self.pending.dispatch_id.ordinal != dispatch_id.ordinal
        {
            return Err(self.fail(
                PreselectionAttemptError::UnknownDispatch,
                transcript_verified_at_ms,
                transcript_verified_at_mono,
            ));
        }
        self.verify_authenticated_response_at(
            encoded_response,
            transcript_verified_at_ms,
            transcript_verified_at_mono,
        )
    }

    fn verify_authenticated_response_at(
        mut self,
        encoded_response: &[u8],
        transcript_verified_at_ms: u64,
        transcript_verified_at_mono: Instant,
    ) -> Result<PreselectionResponseOutcome, PreselectionAttemptFailure> {
        let Some(bound) = verify_and_bind_response(
            &self.pending,
            encoded_response,
            transcript_verified_at_ms,
            &mut self.gate.replay,
        ) else {
            return Err(self.fail(
                PreselectionAttemptError::Protocol,
                transcript_verified_at_ms,
                transcript_verified_at_mono,
            ));
        };
        if let Some(next_plan) = self.remaining.pop_front() {
            let next_challenge = next_plan.challenge;
            let Ok(ordinal) = u8::try_from(self.bound.len().saturating_add(2)) else {
                return Err(self.fail(
                    PreselectionAttemptError::Request,
                    transcript_verified_at_ms,
                    transcript_verified_at_mono,
                ));
            };
            let next_pending = match prepare_request(
                &RequestPreparation {
                    snapshot: &self.snapshot,
                    transport: self.transport,
                    address_family: self.address_family,
                    batch_id: self.batch_id,
                    created_at_ms: transcript_verified_at_ms,
                    prepared_at_mono: transcript_verified_at_mono,
                    attempt_deadline_ms: self.attempt_deadline_ms,
                    attempt_deadline_mono: self.attempt_deadline_mono,
                },
                &next_plan,
                ordinal,
            ) {
                Ok(pending) => pending,
                Err(error) => {
                    return Err(self.fail(
                        error,
                        transcript_verified_at_ms,
                        transcript_verified_at_mono,
                    ));
                }
            };
            if let Err(error) = record_prepared_entropy(
                &mut self.gate,
                self.batch_id,
                next_challenge,
                transcript_verified_at_mono,
            ) {
                return Err(self.fail(
                    error,
                    transcript_verified_at_ms,
                    transcript_verified_at_mono,
                ));
            }
            let previous = std::mem::replace(&mut self.pending, next_pending);
            self.bound.push(bound_transcript_record(previous, bound));
            return Ok(PreselectionResponseOutcome::Pending(self));
        }
        self.bound
            .push(bound_transcript_record(self.pending, bound));
        Ok(PreselectionResponseOutcome::Ready(
            ReadyPreselectionAttempt {
                gate: self.gate,
                snapshot: self.snapshot,
                transport: self.transport,
                address_family: self.address_family,
                batch_id: self.batch_id,
                attempt_started_at_ms: self.attempt_started_at_ms,
                attempt_deadline_ms: self.attempt_deadline_ms,
                attempt_started_at_mono: self.attempt_started_at_mono,
                attempt_deadline_mono: self.attempt_deadline_mono,
                minimum_capacity: self.minimum_capacity,
                preselection_capacity_ceiling: self.preselection_capacity_ceiling,
                last_verified_at_ms: transcript_verified_at_ms,
                last_verified_at_mono: transcript_verified_at_mono,
                bound: self.bound,
            },
        ))
    }

    fn response_time_is_invalid(&self, wall_ms: u64, monotonic: Instant) -> bool {
        wall_ms < self.pending.created_at_ms
            || wall_ms >= self.attempt_deadline_ms
            || monotonic < self.pending.prepared_at_mono
            || monotonic >= self.pending.expires_at_mono
            || monotonic >= self.attempt_deadline_mono
    }

    pub(super) fn cancel(
        self,
    ) -> Result<CoolingPreselectionAttemptGate, PreselectionAttemptFailure> {
        let terminal_ms = crate::unix_millis();
        let terminal_mono = Instant::now();
        self.cancel_at(terminal_ms, terminal_mono)
    }

    fn cancel_at(
        self,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) -> Result<CoolingPreselectionAttemptGate, PreselectionAttemptFailure> {
        if terminal_ms < self.pending.created_at_ms || terminal_mono < self.pending.prepared_at_mono
        {
            return Err(PreselectionAttemptFailure {
                gate: None,
                error: PreselectionAttemptError::InvalidTime,
            });
        }
        cooling_gate(
            self.gate,
            self.pending.created_at_ms,
            terminal_ms,
            self.pending.prepared_at_mono,
            terminal_mono,
        )
        .ok_or(PreselectionAttemptFailure {
            gate: None,
            error: PreselectionAttemptError::InvalidTime,
        })
    }

    fn fail(
        self,
        error: PreselectionAttemptError,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) -> PreselectionAttemptFailure {
        PreselectionAttemptFailure {
            gate: cooling_gate(
                self.gate,
                self.pending.created_at_ms,
                terminal_ms,
                self.pending.prepared_at_mono,
                terminal_mono,
            ),
            error,
        }
    }

    fn terminal_owner_failure(
        self,
        error: PreselectionAttemptError,
    ) -> PreselectionOwnerTransitionFailure {
        let terminal_ms = crate::unix_millis();
        let terminal_mono = Instant::now();
        into_owner_transition_failure(self.fail(error, terminal_ms, terminal_mono))
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "opaque A1 dispatch transition used only by DiscoveryRuntime"
    )
)]
impl DispatchedPreselectionAttempt {
    /// Bind one service-sealed arrival and verify it against the exact retained attempt context.
    ///
    /// The discovery transaction first proves the opaque dispatch identity and returns the same
    /// non-cloned attempt that was dispatched. Only then does this owner verify the signed response
    /// against that attempt's private canonical request and advance it affinely.
    pub(super) fn bind_response(
        self,
        service: &mut DiscoveryService,
        arrival: ClientPreselectionResponseArrival,
    ) -> Result<
        (
            PreselectionResponseOutcome,
            BoundClientPreselectionTransport,
        ),
        PreselectionOwnerTransitionFailure,
    > {
        match service.bind_preselection_observation_response_with_context(self.transaction, arrival)
        {
            Ok((attempt, transport, response)) => attempt
                .verify_response_from_exact_dispatch(response.as_encoded())
                .map(|outcome| (outcome, transport))
                .map_err(into_owner_transition_failure),
            Err(ClientPreselectionBindFailure::Retained {
                transaction,
                error: _,
            }) => Err(PreselectionOwnerTransitionFailure::Retained(Box::new(
                Self {
                    transaction: *transaction,
                },
            ))),
            Err(ClientPreselectionBindFailure::Released { context, error }) => {
                Err(context.terminal_owner_failure(preselection_attempt_error(error)))
            }
        }
    }

    /// Cancel through the originating service and cool the exact retained attempt authority.
    pub(super) fn cancel(
        self,
        service: &mut DiscoveryService,
    ) -> Result<CoolingPreselectionAttemptGate, PreselectionOwnerTransitionFailure> {
        match service.cancel_preselection_observation_transaction(self.transaction) {
            Ok(attempt) => attempt.cancel().map_err(into_owner_transition_failure),
            Err(failure) => Err(PreselectionOwnerTransitionFailure::Retained(Box::new(
                Self {
                    transaction: failure.into_transaction(),
                },
            ))),
        }
    }
}

fn preselection_attempt_error(error: PreselectionDispatchError) -> PreselectionAttemptError {
    match error {
        PreselectionDispatchError::Role | PreselectionDispatchError::Request => {
            PreselectionAttemptError::Request
        }
        PreselectionDispatchError::Correlation => PreselectionAttemptError::UnknownDispatch,
        PreselectionDispatchError::Time => PreselectionAttemptError::InvalidTime,
        _ => PreselectionAttemptError::Transport,
    }
}

fn into_owner_transition_failure(
    failure: PreselectionAttemptFailure,
) -> PreselectionOwnerTransitionFailure {
    match consume_local_preselection_attempt_failure(failure) {
        PreselectionLocalRecovery::Cooling(gate) => {
            PreselectionOwnerTransitionFailure::Cooling(gate)
        }
        PreselectionLocalRecovery::Closed => PreselectionOwnerTransitionFailure::Closed,
    }
}

/// Purpose-consume an undispatched local failure without admitting a Retained transaction state.
pub(super) fn consume_local_preselection_attempt_failure(
    failure: PreselectionAttemptFailure,
) -> PreselectionLocalRecovery {
    match failure.gate {
        Some(gate) => PreselectionLocalRecovery::Cooling(gate),
        None => PreselectionLocalRecovery::Closed,
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn verify_and_bind_response(
    pending: &PendingRequest,
    encoded_response: &[u8],
    transcript_verified_at_ms: u64,
    replay: &mut ReplayCache,
) -> Option<BoundTranscript> {
    match pending.kind {
        PendingRequestKind::Direct => verify_direct_preselection_transcript(
            encoded_response,
            &pending.expected_request,
            transcript_verified_at_ms,
            TimePolicy::default(),
            replay,
        )
        .and_then(|verified| {
            consume_direct_preselection_transcript(verified, &pending.expected_request)
        })
        .map(|transcript| BoundTranscript::Direct(Box::new(transcript)))
        .ok(),
        PendingRequestKind::Forwarded => verify_forwarded_preselection_transcript(
            encoded_response,
            &pending.expected_request,
            transcript_verified_at_ms,
            TimePolicy::default(),
            replay,
        )
        .and_then(|verified| {
            consume_forwarded_preselection_transcript(verified, &pending.expected_request)
        })
        .map(|transcript| BoundTranscript::Forwarded(Box::new(transcript)))
        .ok(),
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn bound_transcript_record(
    pending: PendingRequest,
    transcript: BoundTranscript,
) -> BoundTranscriptRecord {
    BoundTranscriptRecord {
        dispatch_id: pending.dispatch_id,
        request_hash: pending.request_hash,
        subject: pending.subject,
        forwarded_control: pending.forwarded_control,
        role: pending.role,
        transcript,
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
impl ReadyPreselectionAttempt {
    pub(super) fn finish(self) -> Result<CompletedPreselectionAttempt, PreselectionAttemptFailure> {
        let terminal_ms = crate::unix_millis();
        let terminal_mono = Instant::now();
        self.finish_at(terminal_ms, terminal_mono)
    }

    fn finish_at(
        self,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) -> Result<CompletedPreselectionAttempt, PreselectionAttemptFailure> {
        if terminal_ms < self.last_verified_at_ms
            || terminal_ms >= self.attempt_deadline_ms
            || terminal_mono < self.last_verified_at_mono
            || terminal_mono >= self.attempt_deadline_mono
        {
            return Err(self.fail(
                PreselectionAttemptError::InvalidTime,
                terminal_ms,
                terminal_mono,
            ));
        }
        let ReadyPreselectionAttempt {
            gate,
            snapshot,
            transport,
            address_family,
            batch_id,
            attempt_started_at_ms,
            attempt_deadline_ms,
            attempt_started_at_mono,
            attempt_deadline_mono,
            minimum_capacity,
            preselection_capacity_ceiling,
            last_verified_at_ms,
            last_verified_at_mono,
            bound,
        } = self;
        let Some(gate) = cooling_gate(
            gate,
            last_verified_at_ms,
            terminal_ms,
            last_verified_at_mono,
            terminal_mono,
        ) else {
            return Err(PreselectionAttemptFailure {
                gate: None,
                error: PreselectionAttemptError::InvalidTime,
            });
        };
        Ok(CompletedPreselectionAttempt {
            snapshot,
            batch: BoundPreselectionTranscriptBatch {
                transport,
                address_family,
                batch_id,
                attempt_started_at_ms,
                attempt_deadline_ms,
                attempt_started_at_mono,
                attempt_deadline_mono,
                minimum_capacity,
                preselection_capacity_ceiling,
                transcripts: bound,
            },
            gate,
        })
    }

    pub(super) fn cancel(
        self,
    ) -> Result<CoolingPreselectionAttemptGate, PreselectionAttemptFailure> {
        let terminal_ms = crate::unix_millis();
        let terminal_mono = Instant::now();
        self.cancel_at(terminal_ms, terminal_mono)
    }

    fn cancel_at(
        self,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) -> Result<CoolingPreselectionAttemptGate, PreselectionAttemptFailure> {
        if terminal_ms < self.last_verified_at_ms || terminal_mono < self.last_verified_at_mono {
            return Err(PreselectionAttemptFailure {
                gate: None,
                error: PreselectionAttemptError::InvalidTime,
            });
        }
        cooling_gate(
            self.gate,
            self.last_verified_at_ms,
            terminal_ms,
            self.last_verified_at_mono,
            terminal_mono,
        )
        .ok_or(PreselectionAttemptFailure {
            gate: None,
            error: PreselectionAttemptError::InvalidTime,
        })
    }

    fn fail(
        self,
        error: PreselectionAttemptError,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) -> PreselectionAttemptFailure {
        PreselectionAttemptFailure {
            gate: cooling_gate(
                self.gate,
                self.last_verified_at_ms,
                terminal_ms,
                self.last_verified_at_mono,
                terminal_mono,
            ),
            error,
        }
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the discovery actor hands bounded sealed transports to this exact owner"
    )
)]
impl CompletedPreselectionAttempt {
    /// Purpose-consume and join the exact client-hop transports for this completed A1a batch.
    ///
    /// Transport order is the canonical request ordinal order retained by the attempt. Every
    /// opaque transport rechecks the corresponding request hash, native family, and monotonic
    /// attempt window before either proof can become freshness input. A count, order, hash,
    /// actor-shape, family, or time mismatch consumes the unusable proofs and returns only the
    /// cooldown gate.
    pub(crate) fn join_transport_proofs(
        self,
        transports: Vec<BoundClientPreselectionTransport>,
    ) -> Result<CompletedPreselectionFreshnessAttempt, PreselectionFreshnessJoinFailure> {
        self.join_transport_proofs_at(transports, crate::unix_millis(), Instant::now())
    }

    fn join_transport_proofs_at(
        self,
        transports: Vec<BoundClientPreselectionTransport>,
        trusted_now_ms: u64,
        trusted_now_mono: Instant,
    ) -> Result<CompletedPreselectionFreshnessAttempt, PreselectionFreshnessJoinFailure> {
        let transport_count = transports.len();
        let mut transports = transports.into_iter();
        self.join_transport_facts_with_at(
            transport_count,
            trusted_now_ms,
            trusted_now_mono,
            move |request_hash, family, attempt_started_at_mono, attempt_deadline_mono| {
                let transport = transports
                    .next()
                    .ok_or(PreselectionAttemptError::Transport)?;
                let proof = consume_bound_client_preselection_transport_for_freshness(
                    transport,
                    request_hash,
                    family,
                    attempt_started_at_mono,
                    attempt_deadline_mono,
                )
                .map_err(|_| PreselectionAttemptError::Transport)?;
                Ok(transport_freshness_facts(proof))
            },
        )
    }

    #[cfg(test)]
    fn join_transport_facts_for_test(
        self,
        facts: Vec<PreselectionTransportFreshnessFacts>,
        trusted_now_ms: u64,
        trusted_now_mono: Instant,
    ) -> Result<CompletedPreselectionFreshnessAttempt, PreselectionFreshnessJoinFailure> {
        let transport_count = facts.len();
        let mut facts = facts.into_iter();
        self.join_transport_facts_with_at(
            transport_count,
            trusted_now_ms,
            trusted_now_mono,
            move |_, _, _, _| facts.next().ok_or(PreselectionAttemptError::Transport),
        )
    }

    fn join_transport_facts_with_at<F>(
        self,
        transport_count: usize,
        trusted_now_ms: u64,
        trusted_now_mono: Instant,
        consume_transport: F,
    ) -> Result<CompletedPreselectionFreshnessAttempt, PreselectionFreshnessJoinFailure>
    where
        F: FnMut(
            [u8; 32],
            IpFamily,
            Instant,
            Instant,
        ) -> Result<PreselectionTransportFreshnessFacts, PreselectionAttemptError>,
    {
        let CompletedPreselectionAttempt {
            snapshot,
            batch,
            gate,
        } = self;
        match join_transcript_and_transport_proofs(
            &snapshot,
            batch,
            transport_count,
            trusted_now_ms,
            trusted_now_mono,
            consume_transport,
        ) {
            Ok(batch) => Ok(CompletedPreselectionFreshnessAttempt {
                snapshot,
                batch,
                gate,
            }),
            Err(error) => Err(PreselectionFreshnessJoinFailure { gate, error }),
        }
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this is the deliberate affine sink for the opaque transport proof"
)]
fn transport_freshness_facts(
    proof: ClientPreselectionTransportFreshnessProof,
) -> PreselectionTransportFreshnessFacts {
    PreselectionTransportFreshnessFacts {
        observed_network_prefix: proof.observed_network_prefix(),
        observed_at_ms: proof.observed_at_unix_ms(),
        round_trip: proof.round_trip(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact proof join keeps both independent clocks and every affine binding visible"
)]
fn join_transcript_and_transport_proofs<F>(
    snapshot: &RouteCandidateSnapshot,
    batch: BoundPreselectionTranscriptBatch,
    transport_count: usize,
    trusted_now_ms: u64,
    trusted_now_mono: Instant,
    mut consume_transport: F,
) -> Result<BoundPreselectionFreshnessProofBatch, PreselectionAttemptError>
where
    F: FnMut(
        [u8; 32],
        IpFamily,
        Instant,
        Instant,
    ) -> Result<PreselectionTransportFreshnessFacts, PreselectionAttemptError>,
{
    validate_completed_transcript_shape(snapshot, &batch, transport_count)?;
    let BoundPreselectionTranscriptBatch {
        transport,
        address_family,
        batch_id,
        attempt_started_at_ms,
        attempt_deadline_ms,
        attempt_started_at_mono,
        attempt_deadline_mono,
        minimum_capacity,
        preselection_capacity_ceiling,
        transcripts,
    } = batch;
    if trusted_now_ms < attempt_started_at_ms
        || trusted_now_ms >= attempt_deadline_ms
        || trusted_now_mono < attempt_started_at_mono
        || trusted_now_mono >= attempt_deadline_mono
    {
        return Err(PreselectionAttemptError::InvalidTime);
    }
    let family = observation_ip_family(address_family)?;
    let mut records = Vec::with_capacity(transcripts.len());
    for record in transcripts {
        let transport_facts = consume_transport(
            record.request_hash,
            family,
            attempt_started_at_mono,
            attempt_deadline_mono,
        )?;
        validate_transport_freshness_facts(
            &transport_facts,
            family,
            attempt_started_at_ms,
            attempt_deadline_ms,
            trusted_now_ms,
        )?;
        let transcript = purpose_consume_transcript(record.transcript)?;
        if transcript.valid_until_ms() <= trusted_now_ms
            || transcript
                .upstream_network_prefix()
                .is_some_and(|prefix| prefix.family() != family || !prefix.is_public_routable())
        {
            return Err(PreselectionAttemptError::Protocol);
        }
        records.push(PreselectionFreshnessProofRecord {
            subject: record.subject,
            forwarded_control: record.forwarded_control,
            role: record.role,
            transport: transport_facts,
            transcript,
        });
    }
    Ok(BoundPreselectionFreshnessProofBatch {
        transport,
        address_family,
        batch_id,
        attempt_started_at_ms,
        attempt_deadline_ms,
        minimum_capacity,
        preselection_capacity_ceiling,
        records,
    })
}

fn validate_completed_transcript_shape(
    snapshot: &RouteCandidateSnapshot,
    batch: &BoundPreselectionTranscriptBatch,
    transport_count: usize,
) -> Result<(), PreselectionAttemptError> {
    let direct_count = snapshot.direct_relays.len();
    let subject_count = snapshot.preselection_subjects.entries.len();
    let Some(&(control_subject, exit_subject)) =
        snapshot.preselection_subjects.forwarded_pairs.first()
    else {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    };
    if batch.batch_id == [0; BATCH_ID_LENGTH]
        || batch.attempt_started_at_ms == 0
        || batch.attempt_started_at_ms >= batch.attempt_deadline_ms
        || batch.attempt_started_at_mono >= batch.attempt_deadline_mono
        || snapshot.forwarded_exits.len() != 1
        || snapshot.preselection_subjects.forwarded_pairs.len() != 1
        || exit_subject != direct_count
        || control_subject >= direct_count
        || subject_count != direct_count.saturating_add(1)
        || batch.transcripts.len() != direct_count
        || transport_count != batch.transcripts.len()
        || !(MINIMUM_REQUESTS..=MAXIMUM_REQUESTS).contains(&batch.transcripts.len())
    {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    let mut request_hashes = HashSet::with_capacity(batch.transcripts.len());
    let mut direct_subjects = HashSet::with_capacity(direct_count.saturating_sub(1));
    let mut saw_forwarded = false;
    for (index, record) in batch.transcripts.iter().enumerate() {
        let expected_ordinal = u8::try_from(index.saturating_add(1))
            .map_err(|_| PreselectionAttemptError::InvalidSnapshot)?;
        if record.dispatch_id.batch_id != batch.batch_id
            || record.dispatch_id.ordinal != expected_ordinal
            || record.request_hash == [0; 32]
            || !request_hashes.insert(record.request_hash)
        {
            return Err(PreselectionAttemptError::InvalidSnapshot);
        }
        match (&record.transcript, record.role, record.forwarded_control) {
            (BoundTranscript::Forwarded(_), PreselectionObservationRole::Exit, Some(control))
                if index == 0
                    && !saw_forwarded
                    && record.subject == exit_subject
                    && control == control_subject =>
            {
                saw_forwarded = true;
            }
            (BoundTranscript::Direct(_), PreselectionObservationRole::Relay, None)
                if index > 0
                    && record.subject < direct_count
                    && record.subject != control_subject
                    && direct_subjects.insert(record.subject) => {}
            _ => return Err(PreselectionAttemptError::InvalidSnapshot),
        }
    }
    if !saw_forwarded || direct_subjects.len() != direct_count.saturating_sub(1) {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_transport_freshness_facts(
    facts: &PreselectionTransportFreshnessFacts,
    family: IpFamily,
    attempt_started_at_ms: u64,
    attempt_deadline_ms: u64,
    trusted_now_ms: u64,
) -> Result<(), PreselectionAttemptError> {
    if facts.observed_network_prefix.family() != family
        || !facts.observed_network_prefix.is_public_routable()
    {
        return Err(PreselectionAttemptError::Transport);
    }
    if facts.observed_at_ms < attempt_started_at_ms
        || facts.observed_at_ms >= attempt_deadline_ms
        || facts.observed_at_ms > trusted_now_ms
        || facts.round_trip.is_zero()
        || facts.round_trip > Duration::from_millis(ATTEMPT_LIFETIME_MS)
    {
        return Err(PreselectionAttemptError::InvalidTime);
    }
    Ok(())
}

fn purpose_consume_transcript(
    transcript: BoundTranscript,
) -> Result<PreselectionTranscriptFreshnessFacts, PreselectionAttemptError> {
    match transcript {
        BoundTranscript::Direct(transcript) => {
            consume_bound_direct_preselection_transcript_for_freshness(*transcript)
                .map(direct_transcript_freshness_facts)
                .map_err(|_| PreselectionAttemptError::Protocol)
        }
        BoundTranscript::Forwarded(transcript) => {
            consume_bound_forwarded_preselection_transcript_for_freshness(*transcript)
                .map(forwarded_transcript_freshness_facts)
                .map_err(|_| PreselectionAttemptError::Protocol)
        }
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this is the deliberate affine sink for the opaque direct transcript proof"
)]
fn direct_transcript_freshness_facts(
    proof: DirectPreselectionFreshnessProof,
) -> PreselectionTranscriptFreshnessFacts {
    PreselectionTranscriptFreshnessFacts::Direct {
        valid_until_ms: proof.valid_until_ms(),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this is the deliberate affine sink for the opaque forwarded transcript proof"
)]
fn forwarded_transcript_freshness_facts(
    proof: ForwardedPreselectionFreshnessProof,
) -> PreselectionTranscriptFreshnessFacts {
    PreselectionTranscriptFreshnessFacts::Forwarded {
        valid_until_ms: proof.valid_until_ms(),
        upstream_network_prefix: proof.upstream_network_prefix(),
    }
}

const fn observation_ip_family(
    family: ObservationAddressFamily,
) -> Result<IpFamily, PreselectionAttemptError> {
    match family {
        ObservationAddressFamily::Ipv4 => Ok(IpFamily::Ipv4),
        ObservationAddressFamily::Ipv6 => Ok(IpFamily::Ipv6),
        ObservationAddressFamily::Unspecified => Err(PreselectionAttemptError::InvalidSnapshot),
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn validate_attempt_input(
    snapshot: RouteCandidateSnapshot,
    start: &AttemptStart,
) -> Result<ValidatedAttemptInput, PreselectionAttemptError> {
    let (attempt_deadline_ms, attempt_deadline_mono) = validate_attempt_start(start)?;
    let AttemptStart {
        transport,
        address_family,
        minimum_capacity,
        local_profile_capacity: _,
        preselection_capacity_ceiling,
        attempt_started_at_ms,
        attempt_started_at_mono,
    } = *start;
    if attempt_started_at_ms == 0
        || snapshot.captured_at_ms > attempt_started_at_ms
        || snapshot.policy.version == 0
        || snapshot.policy.hash == [0; 32]
        || snapshot.policy.expires_at_ms <= attempt_started_at_ms
        || snapshot.forwarded_exits.len() != 1
        || !snapshot.preselection_subjects.available
        || snapshot.preselection_subjects.entries.len()
            != snapshot
                .direct_relays
                .len()
                .saturating_add(snapshot.forwarded_exits.len())
    {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    if snapshot.preselection_subjects.forwarded_pairs.len() != 1 {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    let (control_subject, exit_subject) = snapshot.preselection_subjects.forwarded_pairs[0];
    if exit_subject != snapshot.direct_relays.len() {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    let other_relay_subjects = snapshot
        .direct_relays
        .iter()
        .enumerate()
        .filter_map(|(index, _)| (index != control_subject).then_some(index))
        .collect::<Vec<_>>();
    if !(1..=MAXIMUM_OTHER_RELAYS).contains(&other_relay_subjects.len())
        || snapshot.direct_relays.len() != other_relay_subjects.len().saturating_add(1)
        || snapshot.direct_relays.len().saturating_add(1) > MAXIMUM_ENVELOPES
    {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    validate_subject_set_matches_snapshot(
        &snapshot,
        control_subject,
        exit_subject,
        attempt_started_at_ms,
        transport,
        address_family,
    )?;
    Ok(ValidatedAttemptInput {
        snapshot,
        transport,
        address_family,
        preselection_capacity_ceiling,
        attempt_started_at_ms,
        attempt_deadline_ms,
        attempt_started_at_mono,
        attempt_deadline_mono,
        minimum_capacity,
        other_relay_subjects,
        control_subject,
        exit_subject,
    })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn validate_attempt_start(
    start: &AttemptStart,
) -> Result<(u64, Instant), PreselectionAttemptError> {
    if start.transport == Transport::Unspecified
        || start.address_family == ObservationAddressFamily::Unspecified
        || start.minimum_capacity.validate().is_err()
        || start.minimum_capacity.up_mbps == 0
        || start.minimum_capacity.down_mbps == 0
        || start.local_profile_capacity.validate().is_err()
        || start.preselection_capacity_ceiling.validate().is_err()
        || start.preselection_capacity_ceiling.up_mbps == 0
        || start.preselection_capacity_ceiling.down_mbps == 0
        || !start
            .preselection_capacity_ceiling
            .satisfies(start.minimum_capacity)
        || !start
            .local_profile_capacity
            .satisfies(start.preselection_capacity_ceiling)
    {
        return Err(PreselectionAttemptError::InvalidCapacity);
    }
    let deadline_ms = start
        .attempt_started_at_ms
        .checked_add(ATTEMPT_LIFETIME_MS)
        .ok_or(PreselectionAttemptError::InvalidTime)?;
    let deadline_mono = start
        .attempt_started_at_mono
        .checked_add(Duration::from_millis(ATTEMPT_LIFETIME_MS))
        .ok_or(PreselectionAttemptError::InvalidTime)?;
    if deadline_ms.checked_add(TOMBSTONE_LIFETIME_MS).is_none()
        || deadline_ms.checked_add(COOLDOWN_MS).is_none()
        || deadline_mono.checked_add(TOMBSTONE_LIFETIME).is_none()
        || deadline_mono.checked_add(COOLDOWN).is_none()
    {
        return Err(PreselectionAttemptError::InvalidTime);
    }
    Ok((deadline_ms, deadline_mono))
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn validate_subject_set_matches_snapshot(
    snapshot: &RouteCandidateSnapshot,
    control_subject: usize,
    exit_subject: usize,
    now_ms: u64,
    transport: Transport,
    address_family: ObservationAddressFamily,
) -> Result<(), PreselectionAttemptError> {
    for (index, relay) in snapshot.direct_relays.iter().enumerate() {
        let subject = snapshot
            .preselection_subjects
            .entries
            .get(index)
            .ok_or(PreselectionAttemptError::InvalidSnapshot)?;
        let capability = relay.capability();
        let advertised = relay.advertisement().advertisement();
        if !subject.relay
            || subject.exit
            || !advertised.roles.relay
            || !static_scope_supported(advertised, transport, address_family)
            || subject.node_id != capability.node_id
            || subject.peer_id != capability.peer_id.to_bytes()
            || subject.public_key != capability.public_key
            || subject.advertisement_sequence != capability.advertisement_sequence
            || subject.advertisement_expires_at_ms != capability.advertisement_expires_at_ms
            || subject.advertisement_payload_hash != capability.advertisement_payload_hash
            || subject.advertisement_payload_hash
                != relay.advertisement().advertisement_payload_hash()
            || subject.capability_expires_at_ms != capability.expires_at_ms
            || subject.local_discovery_authority_expires_at_ms != capability.expires_at_ms
            || subject.policy_version != capability.policy_version
            || subject.policy_hash != capability.policy_hash
            || subject.policy_expires_at_ms != capability.policy_expires_at_ms
            || capability.policy_version != snapshot.policy.version
            || capability.policy_hash != snapshot.policy.hash
            || capability.policy_expires_at_ms != snapshot.policy.expires_at_ms
            || capability.expires_at_ms
                != capability
                    .advertisement_expires_at_ms
                    .min(capability.policy_expires_at_ms)
            || capability.expires_at_ms <= now_ms
        {
            return Err(PreselectionAttemptError::InvalidSnapshot);
        }
    }
    let exit = snapshot
        .preselection_subjects
        .entries
        .get(exit_subject)
        .ok_or(PreselectionAttemptError::InvalidSnapshot)?;
    let forwarded_candidate = &snapshot.forwarded_exits[0];
    let forwarded = forwarded_candidate.capability();
    let exit_advertisement = forwarded_candidate.advertisement().advertisement();
    let nested_control = forwarded_candidate.control();
    let control = &snapshot.preselection_subjects.entries[control_subject];
    if !exit.exit
        || exit.relay
        || !exit_advertisement.roles.exit
        || !static_scope_supported(exit_advertisement, transport, address_family)
        || exit.node_id != forwarded.exit_node_id
        || exit.peer_id != forwarded.exit_peer_id.to_bytes()
        || exit.public_key != forwarded.exit_public_key
        || exit.advertisement_sequence != forwarded.exit_advertisement_sequence
        || exit.advertisement_expires_at_ms != forwarded.exit_advertisement_expires_at_ms
        || exit.advertisement_payload_hash != forwarded.exit_advertisement_payload_hash
        || exit.advertisement_payload_hash
            != snapshot.forwarded_exits[0]
                .advertisement()
                .advertisement_payload_hash()
        || exit.local_discovery_authority_expires_at_ms != forwarded.expires_at_ms
        || exit.policy_version != forwarded.policy_version
        || exit.policy_hash != forwarded.policy_hash
        || exit.policy_expires_at_ms != forwarded.policy_expires_at_ms
        || forwarded.policy_version != snapshot.policy.version
        || forwarded.policy_hash != snapshot.policy.hash
        || forwarded.policy_expires_at_ms != snapshot.policy.expires_at_ms
        || forwarded.expires_at_ms <= now_ms
        || exit.capability_expires_at_ms
            != forwarded
                .exit_advertisement_expires_at_ms
                .min(forwarded.policy_expires_at_ms)
                .min(control.capability_expires_at_ms)
        || forwarded.expires_at_ms > exit.capability_expires_at_ms
        || control.node_id != forwarded.control_relay_node_id
        || control.peer_id != forwarded.control_relay_peer_id.to_bytes()
        || control.public_key != forwarded.control_relay_public_key
        || control.advertisement_sequence != forwarded.control_relay_advertisement_sequence
        || control.advertisement_expires_at_ms
            != forwarded.control_relay_advertisement_expires_at_ms
        || control.advertisement_payload_hash != forwarded.control_relay_advertisement_payload_hash
        || control.advertisement_payload_hash
            != nested_control.advertisement().advertisement_payload_hash()
        || control.advertisement_payload_hash
            != nested_control.capability().advertisement_payload_hash
        || !control.relay
    {
        return Err(PreselectionAttemptError::InvalidSnapshot);
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn static_scope_supported(
    advertisement: &volparossa_core::NodeAdvertisement,
    transport: Transport,
    address_family: ObservationAddressFamily,
) -> bool {
    let transport = match transport {
        Transport::TcpMptcp => volparossa_core::Transport::TcpMptcp,
        Transport::UdpSinglePath => volparossa_core::Transport::UdpSinglePath,
        Transport::MultipathQuic => volparossa_core::Transport::MultipathQuic,
        Transport::Unspecified => return false,
    };
    let family = match address_family {
        ObservationAddressFamily::Ipv4 => IpFamily::Ipv4,
        ObservationAddressFamily::Ipv6 => IpFamily::Ipv6,
        ObservationAddressFamily::Unspecified => return false,
    };
    advertisement.capabilities.supports_transport(transport)
        && advertisement.capabilities.supports_family(family)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn mint_attempt_entropy(
    request_count: usize,
) -> Result<MintedAttemptEntropy, PreselectionAttemptError> {
    let mut batch_id = [0_u8; BATCH_ID_LENGTH];
    OsRng
        .try_fill_bytes(&mut batch_id)
        .map_err(|_| PreselectionAttemptError::Entropy)?;
    let mut challenges = Vec::with_capacity(request_count);
    for _ in 0..request_count {
        let mut challenge = [0_u8; CHALLENGE_LENGTH];
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| PreselectionAttemptError::Entropy)?;
        challenges.push(challenge);
    }
    Ok(MintedAttemptEntropy {
        batch_id,
        challenges,
    })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn all_challenges_unique(challenges: &[[u8; CHALLENGE_LENGTH]]) -> bool {
    let mut unique = HashSet::with_capacity(challenges.len());
    challenges.iter().all(|challenge| unique.insert(*challenge))
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn record_prepared_entropy(
    gate: &mut PreselectionAttemptGate,
    batch_id: [u8; BATCH_ID_LENGTH],
    challenge: [u8; CHALLENGE_LENGTH],
    prepared_at_mono: Instant,
) -> Result<(), PreselectionAttemptError> {
    if batch_id == [0; BATCH_ID_LENGTH]
        || challenge == [0; CHALLENGE_LENGTH]
        || gate.tombstones.len() >= MAXIMUM_TOMBSTONES
        || gate
            .tombstones
            .iter()
            .any(|entry| entry.challenge == challenge)
    {
        return Err(PreselectionAttemptError::Entropy);
    }
    let expires_at = prepared_at_mono
        .checked_add(TOMBSTONE_LIFETIME)
        .ok_or(PreselectionAttemptError::InvalidTime)?;
    let batch_index = gate
        .batch_tombstones
        .iter()
        .position(|entry| entry.batch_id == batch_id);
    if batch_index.is_none() && gate.batch_tombstones.len() >= MAXIMUM_BATCH_TOMBSTONES {
        return Err(PreselectionAttemptError::TombstoneCapacity);
    }
    gate.tombstones.push_back(ChallengeTombstone {
        challenge,
        expires_at,
    });
    match batch_index {
        Some(index) => {
            gate.batch_tombstones[index].expires_at =
                gate.batch_tombstones[index].expires_at.max(expires_at);
        }
        None => gate.batch_tombstones.push_back(BatchTombstone {
            batch_id,
            expires_at,
        }),
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn build_request_plans(
    validated: &ValidatedAttemptInput,
    entropy: &MintedAttemptEntropy,
) -> Result<VecDeque<RequestPlan>, PreselectionAttemptError> {
    if entropy.challenges.len() != validated.other_relay_subjects.len().saturating_add(1) {
        return Err(PreselectionAttemptError::Request);
    }
    let mut requests = VecDeque::with_capacity(entropy.challenges.len());
    requests.push_back(RequestPlan {
        subject: validated.exit_subject,
        forwarded_control: Some(validated.control_subject),
        role: PreselectionObservationRole::Exit,
        kind: PendingRequestKind::Forwarded,
        challenge: entropy.challenges[0],
    });
    for (offset, subject_index) in validated.other_relay_subjects.iter().enumerate() {
        requests.push_back(RequestPlan {
            subject: *subject_index,
            forwarded_control: None,
            role: PreselectionObservationRole::Relay,
            kind: PendingRequestKind::Direct,
            challenge: entropy.challenges[offset + 1],
        });
    }
    if requests.len() != entropy.challenges.len()
        || !(MINIMUM_REQUESTS..=MAXIMUM_REQUESTS).contains(&requests.len())
    {
        return Err(PreselectionAttemptError::Request);
    }
    Ok(requests)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn prepare_request(
    preparation: &RequestPreparation<'_>,
    plan: &RequestPlan,
    ordinal: u8,
) -> Result<PendingRequest, PreselectionAttemptError> {
    let RequestPreparation {
        snapshot,
        transport,
        address_family,
        batch_id,
        created_at_ms,
        prepared_at_mono,
        attempt_deadline_ms,
        attempt_deadline_mono,
    } = *preparation;
    let subjects = &snapshot.preselection_subjects;
    let policy = snapshot.policy;
    let subject = subjects
        .entries
        .get(plan.subject)
        .ok_or(PreselectionAttemptError::InvalidSnapshot)?;
    let forwarded_control = match plan.forwarded_control {
        Some(index) => Some(
            subjects
                .entries
                .get(index)
                .ok_or(PreselectionAttemptError::InvalidSnapshot)?,
        ),
        None => None,
    };
    let request = request_for_subject(&RequestBinding {
        subject,
        forwarded_control,
        role: plan.role,
        transport,
        address_family,
        policy,
        challenge: plan.challenge,
        created_at_ms,
        attempt_deadline_ms,
    })?;
    let expires_at_mono = prepared_at_mono
        .checked_add(Duration::from_millis(REQUEST_LIFETIME_MS))
        .ok_or(PreselectionAttemptError::InvalidTime)?
        .min(attempt_deadline_mono);
    if prepared_at_mono >= expires_at_mono {
        return Err(PreselectionAttemptError::InvalidTime);
    }
    let expected_request = encode_canonical(&request, MAXIMUM_REQUEST_BYTES)
        .map_err(|_| PreselectionAttemptError::Request)?;
    let request_hash = preselection_observation_request_hash(&expected_request)
        .map_err(|_| PreselectionAttemptError::Request)?;
    Ok(PendingRequest {
        dispatch_id: ObservationDispatchId { batch_id, ordinal },
        expected_request,
        request_hash,
        subject: plan.subject,
        forwarded_control: plan.forwarded_control,
        role: plan.role,
        created_at_ms,
        prepared_at_mono,
        expires_at_mono,
        kind: plan.kind,
    })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn request_for_subject(
    binding: &RequestBinding<'_>,
) -> Result<PreselectionObservationRequest, PreselectionAttemptError> {
    let RequestBinding {
        subject,
        forwarded_control,
        role,
        transport,
        address_family,
        policy,
        challenge,
        created_at_ms,
        attempt_deadline_ms,
    } = *binding;
    let expires_at_ms = created_at_ms
        .checked_add(REQUEST_LIFETIME_MS)
        .ok_or(PreselectionAttemptError::InvalidTime)?
        .min(attempt_deadline_ms)
        .min(subject.advertisement_expires_at_ms)
        .min(subject.capability_expires_at_ms)
        .min(subject.local_discovery_authority_expires_at_ms)
        .min(policy.expires_at_ms)
        .min(forwarded_control.map_or(u64::MAX, |control| {
            control
                .advertisement_expires_at_ms
                .min(control.capability_expires_at_ms)
        }));
    let request = PreselectionObservationRequest {
        protocol_version: volparossa_protocol::PROTOCOL_VERSION,
        challenge: challenge.to_vec(),
        actor: Some(actor_binding(subject)),
        scope: Some(PreselectionObservationScope {
            role: role as i32,
            transport: transport as i32,
            address_family: address_family as i32,
            policy_version: policy.version,
            policy_hash: policy.hash.to_vec(),
            policy_expires_at_ms: policy.expires_at_ms,
        }),
        forwarded_control: forwarded_control.map(actor_binding),
        created_at_ms,
        expires_at_ms,
    };
    request
        .validate()
        .map_err(|_| PreselectionAttemptError::Request)?;
    Ok(request)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn actor_binding(subject: &PreselectionSubjectBinding) -> PreselectionActorBinding {
    PreselectionActorBinding {
        node_id: subject.node_id.to_vec(),
        peer_id: subject.peer_id.clone(),
        public_key: subject.public_key.to_vec(),
        advertisement_sequence: subject.advertisement_sequence,
        advertisement_expires_at_ms: subject.advertisement_expires_at_ms,
        advertisement_payload_hash: subject.advertisement_payload_hash.0.to_vec(),
        capability_expires_at_ms: subject.capability_expires_at_ms,
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private affine A1 owner internals; only DiscoveryRuntime enters"
    )
)]
fn cooling_gate(
    gate: PreselectionAttemptGate,
    not_before_ms: u64,
    terminal_ms: u64,
    not_before_mono: Instant,
    terminal_mono: Instant,
) -> Option<CoolingPreselectionAttemptGate> {
    if terminal_ms < not_before_ms || terminal_mono < not_before_mono {
        return None;
    }
    Some(CoolingPreselectionAttemptGate {
        gate,
        ready_at_ms: terminal_ms.checked_add(COOLDOWN_MS)?,
        ready_at: terminal_mono.checked_add(COOLDOWN)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::{BTreeMap, HashSet},
    };

    use super::super::tests::{
        PreselectionTestCapabilities, preselection_snapshot_fixture,
        preselection_snapshot_fixture_with_capabilities,
    };
    use super::*;
    use libp2p::identity;
    use volparossa_discovery::DiscoveryProtocolRoles;
    use volparossa_identity::Identity;
    use volparossa_protocol::{
        ControlPayload, ForwardedPreselectionAttestation, ObservationNetworkPrefix,
        PreselectionObservationReceipt, ProtocolError, decode_canonical,
        preselection_observation_receipt_hash, sign_control_message_with, verify_control_message,
    };

    fn bandwidth(value: u32) -> Bandwidth {
        Bandwidth::new(value, value).expect("valid test bandwidth")
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SnapshotCandidateUnionIdentity {
        captured_at_ms: u64,
        policy: super::super::RouteCandidatePolicySnapshot,
        direct_relays: (*const DirectRelayCandidateSnapshot, usize, usize),
        forwarded_exits: (*const ForwardedExitCandidateSnapshot, usize, usize),
        subject_entries: (*const PreselectionSubjectBinding, usize, usize),
        forwarded_pairs: (*const (usize, usize), usize, usize),
    }

    fn snapshot_candidate_union_identity(
        snapshot: &RouteCandidateSnapshot,
    ) -> SnapshotCandidateUnionIdentity {
        assert!(!snapshot.direct_relays.is_empty());
        assert!(!snapshot.forwarded_exits.is_empty());
        assert!(!snapshot.preselection_subjects.entries.is_empty());
        assert!(!snapshot.preselection_subjects.forwarded_pairs.is_empty());
        SnapshotCandidateUnionIdentity {
            captured_at_ms: snapshot.captured_at_ms,
            policy: snapshot.policy,
            direct_relays: (
                snapshot.direct_relays.as_ptr(),
                snapshot.direct_relays.len(),
                snapshot.direct_relays.capacity(),
            ),
            forwarded_exits: (
                snapshot.forwarded_exits.as_ptr(),
                snapshot.forwarded_exits.len(),
                snapshot.forwarded_exits.capacity(),
            ),
            subject_entries: (
                snapshot.preselection_subjects.entries.as_ptr(),
                snapshot.preselection_subjects.entries.len(),
                snapshot.preselection_subjects.entries.capacity(),
            ),
            forwarded_pairs: (
                snapshot.preselection_subjects.forwarded_pairs.as_ptr(),
                snapshot.preselection_subjects.forwarded_pairs.len(),
                snapshot.preselection_subjects.forwarded_pairs.capacity(),
            ),
        }
    }

    fn attempt_start_at(
        transport: Transport,
        address_family: ObservationAddressFamily,
        minimum_capacity: Bandwidth,
        local_profile_capacity: Bandwidth,
        preselection_capacity_ceiling: Bandwidth,
        attempt_started_at_ms: u64,
        attempt_started_at_mono: Instant,
    ) -> AttemptStart {
        AttemptStart {
            transport,
            address_family,
            minimum_capacity,
            local_profile_capacity,
            preselection_capacity_ceiling,
            attempt_started_at_ms,
            attempt_started_at_mono,
        }
    }

    fn source_fields<'a>(source: &'a str, declaration: &str) -> Vec<&'a str> {
        source
            .split_once(declaration)
            .unwrap_or_else(|| panic!("missing source declaration {declaration}"))
            .1
            .split_once("\n}")
            .expect("bounded source item")
            .0
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn assert_source_fields(source: &str, declaration: &str, expected: &[&str]) {
        assert_eq!(
            source_fields(source, declaration),
            expected,
            "{declaration}"
        );
    }

    fn minted_entropy(request_count: usize, seed: u8) -> MintedAttemptEntropy {
        MintedAttemptEntropy {
            batch_id: [seed; BATCH_ID_LENGTH],
            challenges: (0..request_count)
                .map(|offset| {
                    [seed.wrapping_add(u8::try_from(offset).expect("bounded request count") + 1);
                        CHALLENGE_LENGTH]
                })
                .collect(),
        }
    }

    fn request(pending: &PendingPreselectionAttempt) -> PreselectionObservationRequest {
        decode_canonical(&pending.pending.expected_request, MAXIMUM_REQUEST_BYTES)
            .expect("canonical pending request")
    }

    fn signer_for<'a>(signers: &'a [Identity], actor: &PreselectionActorBinding) -> &'a Identity {
        signers
            .iter()
            .find(|identity| {
                identity
                    .ed25519_public_key_bytes()
                    .is_ok_and(|public_key| public_key.as_slice() == actor.public_key)
            })
            .expect("fixture signer for exact request actor")
    }

    fn assert_exact_persisted_payload_hashes(
        subjects: &PreselectionSubjectSet,
        persisted: &BTreeMap<[u8; 32], [u8; 32]>,
    ) {
        assert_eq!(subjects.entries.len(), persisted.len());
        let mut seen = HashSet::new();
        for subject in &subjects.entries {
            assert!(seen.insert(subject.public_key));
            assert_eq!(
                persisted.get(&subject.public_key),
                Some(&subject.advertisement_payload_hash.0),
                "subject hash must be the exact SignedEnvelope.payload_hash loaded from storage"
            );
        }
        assert_eq!(seen.len(), persisted.len());
    }

    async fn assert_unsupported_scope_precedes_entropy(
        transport: Transport,
        family: ObservationAddressFamily,
    ) {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let calls = Cell::new(0);
        let failure = match PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    transport,
                    family,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    Instant::now(),
                ),
                |request_count| {
                    calls.set(calls.get() + 1);
                    Ok(minted_entropy(request_count, 141))
                },
            ) {
            Ok(_) => panic!("signed advertisements do not support {transport:?}/{family:?}"),
            Err(failure) => failure,
        };
        assert_eq!(calls.get(), 0);
        assert_eq!(failure.error, PreselectionAttemptError::InvalidSnapshot);
        assert!(failure.gate.is_some());
    }

    fn sign_payload<T: ControlPayload>(
        payload: &T,
        signer: &Identity,
        timestamp_ms: u64,
        expires_at_ms: u64,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let public_key = signer
            .ed25519_public_key_bytes()
            .expect("Ed25519 fixture key");
        sign_control_message_with(
            payload,
            public_key,
            timestamp_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
            |bytes| signer.sign(bytes).ok(),
        )
        .expect("signed preselection fixture")
    }

    fn signed_response(
        pending: &PendingPreselectionAttempt,
        signers: &[Identity],
        verified_at_ms: u64,
        nonce_seed: u8,
    ) -> Vec<u8> {
        let request = request(pending);
        let actor = request.actor.as_ref().expect("request actor");
        let scope = request.scope.as_ref().expect("request scope");
        let receipt_valid_until_ms = verified_at_ms
            .checked_add(10_000)
            .expect("bounded receipt window")
            .min(actor.advertisement_expires_at_ms)
            .min(actor.capability_expires_at_ms)
            .min(scope.policy_expires_at_ms);
        let receipt = PreselectionObservationReceipt {
            request_hash: pending.pending.request_hash.to_vec(),
            challenge: request.challenge.clone(),
            actor: request.actor.clone(),
            scope: request.scope.clone(),
            observed_at_ms: verified_at_ms,
            valid_until_ms: receipt_valid_until_ms,
            nonce: vec![nonce_seed; 32],
        };
        let signed_receipt = sign_payload(
            &receipt,
            signer_for(signers, actor),
            receipt.observed_at_ms,
            receipt.valid_until_ms,
            [nonce_seed; 32],
        );
        if matches!(pending.pending.kind, PendingRequestKind::Direct) {
            return signed_receipt;
        }
        let control = request
            .forwarded_control
            .as_ref()
            .expect("forwarded control");
        let outer_nonce = nonce_seed.wrapping_add(1);
        let outer_valid_until_ms = verified_at_ms
            .checked_add(12_000)
            .expect("bounded attestation window")
            .min(actor.advertisement_expires_at_ms)
            .min(actor.capability_expires_at_ms)
            .min(control.advertisement_expires_at_ms)
            .min(control.capability_expires_at_ms)
            .min(scope.policy_expires_at_ms);
        let attestation = ForwardedPreselectionAttestation {
            request_hash: pending.pending.request_hash.to_vec(),
            challenge: request.challenge.clone(),
            signed_exit_receipt: signed_receipt.clone(),
            exit_receipt_hash: preselection_observation_receipt_hash(&signed_receipt)
                .expect("exit receipt digest")
                .to_vec(),
            control: Some(control.clone()),
            exit: request.actor.clone(),
            scope: request.scope.clone(),
            upstream_network_prefix: Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: vec![8, 8, 8],
            }),
            observed_at_ms: verified_at_ms,
            valid_until_ms: outer_valid_until_ms,
            nonce: vec![outer_nonce; 32],
        };
        sign_payload(
            &attestation,
            signer_for(signers, control),
            attestation.observed_at_ms,
            attestation.valid_until_ms,
            [outer_nonce; 32],
        )
    }

    fn assert_valid_begin_state(pending: &PendingPreselectionAttempt, started_at_mono: Instant) {
        assert_eq!(pending.batch_id, [61; BATCH_ID_LENGTH]);
        assert_eq!(pending.pending.dispatch_id.batch_id, pending.batch_id);
        assert_eq!(pending.pending.dispatch_id.ordinal, 1);
        assert!(matches!(
            pending.pending.kind,
            PendingRequestKind::Forwarded
        ));
        assert_eq!(pending.remaining.len(), 1);
        assert!(pending.bound.is_empty());
        assert_eq!(pending.gate.tombstones.len(), 1);
        assert_eq!(pending.gate.batch_tombstones.len(), 1);
        assert_eq!(
            pending.gate.tombstones[0].expires_at,
            started_at_mono + TOMBSTONE_LIFETIME
        );
        assert_eq!(
            pending.gate.batch_tombstones[0].expires_at,
            started_at_mono + TOMBSTONE_LIFETIME
        );
        assert_eq!(
            preselection_observation_request_hash(&pending.pending.expected_request)
                .expect("canonical request hash"),
            pending.pending.request_hash
        );
    }

    #[tokio::test]
    async fn owner_dispatch_fails_closed_and_cools_when_connection_provenance_is_absent() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let started_at_mono = Instant::now();
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 63)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let mut service = DiscoveryService::new_with_protocol_roles(
            identity::Keypair::generate_ed25519(),
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("client discovery service");

        let failure = match pending.dispatch(&mut service) {
            Ok(_) => panic!("a request-derived target without live provenance must not dispatch"),
            Err(failure) => failure,
        };
        let PreselectionOwnerTransitionFailure::Cooling(cooling) = failure else {
            panic!("terminal dispatch rejection must retain only cooling authority");
        };
        assert_eq!(cooling.gate.tombstones.len(), 1);
        assert_eq!(cooling.gate.batch_tombstones.len(), 1);
        assert!(cooling.gate.replay.is_empty());
        assert!(cooling.ready_at_ms >= crate::unix_millis());
        assert!(cooling.ready_at >= Instant::now());
    }

    #[tokio::test]
    async fn exact_dispatch_response_transition_advances_the_unchanged_affine_attempt() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let signers = fixture.signers;
        let original = snapshot_candidate_union_identity(&fixture.snapshot);
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    Instant::now(),
                ),
                |request_count| Ok(minted_entropy(request_count, 64)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let verified_at_ms = crate::unix_millis();
        let expected_request_hash = pending.pending.request_hash;
        let response = signed_response(&pending, &signers, verified_at_ms, 65);

        let Ok(PreselectionResponseOutcome::Pending(next)) =
            pending.verify_response_from_exact_dispatch(&response)
        else {
            panic!("the exact retained dispatch context must advance without an external ID");
        };
        assert_eq!(snapshot_candidate_union_identity(&next.snapshot), original);
        assert_eq!(next.bound.len(), 1);
        assert_eq!(next.bound[0].request_hash, expected_request_hash);
        assert_eq!(next.pending.dispatch_id.ordinal, 2);
        assert_eq!(next.gate.replay.len(), 2);
    }

    #[test]
    fn every_discovery_transition_rejection_maps_to_one_fail_closed_attempt_class() {
        for (error, expected) in [
            (
                PreselectionDispatchError::Role,
                PreselectionAttemptError::Request,
            ),
            (
                PreselectionDispatchError::Request,
                PreselectionAttemptError::Request,
            ),
            (
                PreselectionDispatchError::Provenance,
                PreselectionAttemptError::Transport,
            ),
            (
                PreselectionDispatchError::Correlation,
                PreselectionAttemptError::UnknownDispatch,
            ),
            (
                PreselectionDispatchError::Time,
                PreselectionAttemptError::InvalidTime,
            ),
            (
                PreselectionDispatchError::Busy,
                PreselectionAttemptError::Transport,
            ),
        ] {
            assert_eq!(preselection_attempt_error(error), expected);
        }
    }

    #[tokio::test]
    async fn begin_rejects_before_entropy_and_valid_begin_mints_exactly_once() {
        let invalid = preselection_snapshot_fixture(1, false).await;
        let invalid_calls = Cell::new(0);
        let invalid_result = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                invalid.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(9),
                    invalid.now_ms,
                    Instant::now(),
                ),
                |request_count| {
                    invalid_calls.set(invalid_calls.get() + 1);
                    Ok(minted_entropy(request_count, 41))
                },
            );
        let invalid_failure = match invalid_result {
            Ok(_) => panic!("below-minimum ceiling must fail"),
            Err(failure) => failure,
        };
        assert_eq!(invalid_calls.get(), 0);
        assert_eq!(
            invalid_failure.error,
            PreselectionAttemptError::InvalidCapacity
        );
        assert!(invalid_failure.gate.is_some());
        assert!(invalid_failure.cooling_gate.is_none());

        let mut unavailable = preselection_snapshot_fixture(1, false).await;
        unavailable.snapshot.preselection_subjects = PreselectionSubjectSet::unavailable_for_test();
        let unavailable_calls = Cell::new(0);
        let unavailable_result = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                unavailable.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    unavailable.now_ms,
                    Instant::now(),
                ),
                |request_count| {
                    unavailable_calls.set(unavailable_calls.get() + 1);
                    Ok(minted_entropy(request_count, 51))
                },
            );
        let unavailable_failure = match unavailable_result {
            Ok(_) => panic!("unavailable subject binding must fail"),
            Err(failure) => failure,
        };
        assert_eq!(unavailable_calls.get(), 0);
        assert_eq!(
            unavailable_failure.error,
            PreselectionAttemptError::InvalidSnapshot
        );
        assert!(unavailable_failure.gate.is_some());

        let valid = preselection_snapshot_fixture(1, false).await;
        let started_at_mono = Instant::now();
        let valid_calls = Cell::new(0);
        let Ok(pending) = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                valid.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    valid.now_ms,
                    started_at_mono,
                ),
                |request_count| {
                    valid_calls.set(valid_calls.get() + 1);
                    assert_eq!(request_count, 2);
                    Ok(minted_entropy(request_count, 61))
                },
            )
        else {
            panic!("fresh validated snapshot must begin");
        };
        assert_eq!(valid_calls.get(), 1);
        assert_valid_begin_state(&pending, started_at_mono);
    }

    fn splice_snapshot_candidate_payload_hash(snapshot: &mut RouteCandidateSnapshot, mutation: u8) {
        match mutation {
            0 => {
                let hash = snapshot.direct_relays[1]
                    .capability
                    .advertisement_payload_hash;
                snapshot.direct_relays[1]
                    .capability
                    .advertisement_payload_hash = hash.xor_for_test();
            }
            1 => {
                let hash = snapshot.direct_relays[1]
                    .advertisement
                    .advertisement_payload_hash;
                snapshot.direct_relays[1]
                    .advertisement
                    .advertisement_payload_hash = hash.xor_for_test();
            }
            2 => {
                let hash = snapshot.forwarded_exits[0]
                    .capability
                    .exit_advertisement_payload_hash;
                snapshot.forwarded_exits[0]
                    .capability
                    .exit_advertisement_payload_hash = hash.xor_for_test();
            }
            3 => {
                let hash = snapshot.forwarded_exits[0]
                    .advertisement
                    .advertisement_payload_hash;
                snapshot.forwarded_exits[0]
                    .advertisement
                    .advertisement_payload_hash = hash.xor_for_test();
            }
            4 => {
                let hash = snapshot.forwarded_exits[0]
                    .capability
                    .control_relay_advertisement_payload_hash;
                snapshot.forwarded_exits[0]
                    .capability
                    .control_relay_advertisement_payload_hash = hash.xor_for_test();
            }
            5 => {
                let hash = snapshot.forwarded_exits[0]
                    .control
                    .capability
                    .advertisement_payload_hash;
                snapshot.forwarded_exits[0]
                    .control
                    .capability
                    .advertisement_payload_hash = hash.xor_for_test();
            }
            6 => {
                let hash = snapshot.forwarded_exits[0]
                    .control
                    .advertisement
                    .advertisement_payload_hash;
                snapshot.forwarded_exits[0]
                    .control
                    .advertisement
                    .advertisement_payload_hash = hash.xor_for_test();
            }
            _ => unreachable!(),
        }
    }

    fn splice_snapshot_subject_payload_hash(snapshot: &mut RouteCandidateSnapshot, mutation: u8) {
        let (control_subject, exit_subject) = snapshot.preselection_subjects.forwarded_pairs[0];
        let subject_index = match mutation {
            7 => {
                let mut other_subjects = (0..snapshot.preselection_subjects.entries.len())
                    .filter(|index| *index != control_subject && *index != exit_subject);
                let other_subject = other_subjects.next().expect("other direct relay subject");
                assert!(other_subjects.next().is_none());
                other_subject
            }
            8 => exit_subject,
            9 => control_subject,
            _ => unreachable!(),
        };
        let subject = &mut snapshot.preselection_subjects.entries[subject_index];
        subject.advertisement_payload_hash = subject.advertisement_payload_hash.xor_for_test();
    }

    #[tokio::test]
    async fn every_snapshot_payload_hash_splice_is_rejected_before_entropy() {
        for mutation in 0_u8..10 {
            let mut fixture = preselection_snapshot_fixture(1, false).await;
            if mutation < 7 {
                splice_snapshot_candidate_payload_hash(&mut fixture.snapshot, mutation);
            } else {
                splice_snapshot_subject_payload_hash(&mut fixture.snapshot, mutation);
            }
            let calls = Cell::new(0);
            let result = PreselectionAttemptGate::new()
                .expect("gate")
                .begin_at_with_entropy_for_test(
                    fixture.snapshot,
                    attempt_start_at(
                        Transport::UdpSinglePath,
                        ObservationAddressFamily::Ipv4,
                        bandwidth(10),
                        bandwidth(100),
                        bandwidth(80),
                        fixture.now_ms,
                        Instant::now(),
                    ),
                    |request_count| {
                        calls.set(calls.get() + 1);
                        Ok(minted_entropy(request_count, 62 + mutation))
                    },
                );
            let failure = match result {
                Ok(_) => panic!("payload-hash splice {mutation} must fail"),
                Err(failure) => failure,
            };
            assert_eq!(calls.get(), 0, "mutation {mutation}");
            assert_eq!(failure.error, PreselectionAttemptError::InvalidSnapshot);
            assert!(failure.gate.is_some());
            assert!(failure.cooling_gate.is_none());
        }
    }

    #[tokio::test]
    async fn maximum_subject_set_is_bounded_and_dual_roles_project_to_required_roles() {
        let fixture = preselection_snapshot_fixture(MAXIMUM_OTHER_RELAYS, true).await;
        assert!(fixture.snapshot.direct_relays.iter().all(|relay| {
            let roles = relay.advertisement().advertisement().roles;
            roles.relay && roles.exit
        }));
        let forwarded_roles = fixture.snapshot.forwarded_exits[0]
            .advertisement()
            .advertisement()
            .roles;
        assert!(forwarded_roles.relay && forwarded_roles.exit);
        let Ok(pending) = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    Instant::now(),
                ),
                |request_count| {
                    assert_eq!(request_count, MAXIMUM_REQUESTS);
                    Ok(minted_entropy(request_count, 71))
                },
            )
        else {
            panic!("maximum bounded subject set must begin");
        };
        assert_eq!(
            pending.snapshot.preselection_subjects.entries.len(),
            MAXIMUM_ENVELOPES
        );
        let (control, exit) = pending.snapshot.preselection_subjects.forwarded_pairs[0];
        assert!(
            pending
                .snapshot
                .preselection_subjects
                .entries
                .iter()
                .enumerate()
                .all(|(index, subject)| if index == exit {
                    subject.exit && !subject.relay
                } else {
                    subject.relay && !subject.exit
                })
        );
        assert_ne!(control, exit);
        assert_eq!(pending.remaining.len(), MAXIMUM_OTHER_RELAYS);
        assert_eq!(pending.gate.tombstones.len(), 1);
    }

    struct ExpectedBoundRecord {
        batch_id: [u8; BATCH_ID_LENGTH],
        ordinal: u8,
        request_hash: [u8; 32],
        subject: usize,
        forwarded_control: Option<usize>,
        role: PreselectionObservationRole,
        forwarded: bool,
    }

    fn advance_authentic_responses(
        mut pending: PendingPreselectionAttempt,
        signers: &[Identity],
        started_at_ms: u64,
        started_at_mono: Instant,
    ) -> (ReadyPreselectionAttempt, Vec<ExpectedBoundRecord>) {
        let mut expected = Vec::new();
        let mut ready = None;
        for offset in 1_u8..=3 {
            let verified_at_ms = started_at_ms + u64::from(offset) * 500;
            let verified_at_mono = started_at_mono + Duration::from_millis(u64::from(offset) * 500);
            let dispatch = ObservationDispatchId {
                batch_id: pending.pending.dispatch_id.batch_id,
                ordinal: pending.pending.dispatch_id.ordinal,
            };
            let decoded_request = request(&pending);
            assert_eq!(
                decoded_request.actor.as_ref(),
                Some(&actor_binding(
                    &pending.snapshot.preselection_subjects.entries[pending.pending.subject]
                ))
            );
            assert_eq!(
                decoded_request.forwarded_control,
                pending.pending.forwarded_control.map(|index| {
                    actor_binding(&pending.snapshot.preselection_subjects.entries[index])
                })
            );
            expected.push(ExpectedBoundRecord {
                batch_id: dispatch.batch_id,
                ordinal: dispatch.ordinal,
                request_hash: pending.pending.request_hash,
                subject: pending.pending.subject,
                forwarded_control: pending.pending.forwarded_control,
                role: pending.pending.role,
                forwarded: matches!(pending.pending.kind, PendingRequestKind::Forwarded),
            });
            let response = signed_response(
                &pending,
                signers,
                verified_at_ms,
                100_u8.wrapping_add(offset * 2),
            );
            match pending.verify_response_at(&dispatch, &response, verified_at_ms, verified_at_mono)
            {
                Ok(PreselectionResponseOutcome::Pending(next)) => {
                    assert!(offset < 3);
                    assert_eq!(next.pending.dispatch_id.ordinal, offset + 1);
                    assert_eq!(next.pending.dispatch_id.batch_id, [81; BATCH_ID_LENGTH]);
                    assert_eq!(next.bound.len(), usize::from(offset));
                    assert_eq!(next.gate.tombstones.len(), usize::from(offset) + 1);
                    assert_eq!(next.gate.batch_tombstones.len(), 1);
                    assert_eq!(
                        next.gate.batch_tombstones[0].expires_at,
                        verified_at_mono + TOMBSTONE_LIFETIME
                    );
                    assert_eq!(
                        next.gate.tombstones[usize::from(offset)].expires_at,
                        verified_at_mono + TOMBSTONE_LIFETIME
                    );
                    assert_eq!(next.pending.created_at_ms, verified_at_ms);
                    assert_eq!(next.pending.prepared_at_mono, verified_at_mono);
                    pending = next;
                }
                Ok(PreselectionResponseOutcome::Ready(completed)) => {
                    assert_eq!(offset, 3);
                    ready = Some(completed);
                    break;
                }
                Err(failure) => panic!("valid raw response failed: {:?}", failure.error),
            }
        }
        (
            ready.expect("all exact responses produce ready state"),
            expected,
        )
    }

    fn assert_bound_records(
        ready: &ReadyPreselectionAttempt,
        expected: &[ExpectedBoundRecord],
        expected_control: usize,
        expected_exit: usize,
        expected_direct_subjects: &HashSet<usize>,
    ) {
        assert_eq!(ready.bound.len(), expected.len());
        for (record, expected) in ready.bound.iter().zip(expected) {
            assert_eq!(record.dispatch_id.batch_id, expected.batch_id);
            assert_eq!(record.dispatch_id.ordinal, expected.ordinal);
            assert_eq!(record.request_hash, expected.request_hash);
            assert_eq!(record.subject, expected.subject);
            assert_eq!(record.forwarded_control, expected.forwarded_control);
            assert_eq!(record.role, expected.role);
            let forwarded = match &record.transcript {
                BoundTranscript::Direct(proof) => {
                    assert_ne!(size_of_val(proof.as_ref()), 0);
                    false
                }
                BoundTranscript::Forwarded(proof) => {
                    assert_ne!(size_of_val(proof.as_ref()), 0);
                    true
                }
            };
            assert_eq!(forwarded, expected.forwarded);
        }
        assert_eq!(ready.bound[0].role, PreselectionObservationRole::Exit);
        assert_eq!(ready.bound[0].subject, expected_exit);
        assert_eq!(ready.bound[0].forwarded_control, Some(expected_control));
        assert!(ready.bound[1..].iter().all(|record| {
            record.role == PreselectionObservationRole::Relay && record.forwarded_control.is_none()
        }));
        assert_eq!(
            ready.bound[1..]
                .iter()
                .map(|record| record.subject)
                .collect::<HashSet<_>>(),
            *expected_direct_subjects
        );
        assert_eq!(ready.bound[1..].len(), expected_direct_subjects.len());
    }

    fn assert_completed_batch(
        completed: &CompletedPreselectionAttempt,
        started_at_ms: u64,
        started_at_mono: Instant,
        terminal_ms: u64,
        terminal_mono: Instant,
    ) {
        assert_eq!(completed.snapshot.preselection_subjects.entries.len(), 4);
        assert_eq!(
            completed.snapshot.preselection_subjects.entries.len(),
            completed.batch.transcripts.len() + 1,
            "the forwarding control is retained as a subject but not a second request"
        );
        assert_eq!(
            completed.snapshot.policy.version(),
            completed.snapshot.preselection_subjects.entries[0].policy_version
        );
        assert_eq!(
            completed.snapshot.policy.hash(),
            completed.snapshot.preselection_subjects.entries[0].policy_hash
        );
        assert_eq!(completed.batch.transport, Transport::UdpSinglePath);
        assert_eq!(
            completed.batch.address_family,
            ObservationAddressFamily::Ipv4
        );
        assert_eq!(completed.batch.batch_id, [81; BATCH_ID_LENGTH]);
        assert_eq!(completed.batch.transcripts.len(), 3);
        assert_eq!(completed.batch.attempt_started_at_ms, started_at_ms);
        assert_eq!(
            completed.batch.attempt_deadline_ms,
            started_at_ms + ATTEMPT_LIFETIME_MS
        );
        assert_eq!(completed.batch.attempt_started_at_mono, started_at_mono);
        assert_eq!(
            completed.batch.attempt_deadline_mono,
            started_at_mono + Duration::from_millis(ATTEMPT_LIFETIME_MS)
        );
        assert_eq!(completed.batch.minimum_capacity, bandwidth(10));
        assert_eq!(completed.batch.preselection_capacity_ceiling, bandwidth(80));
        assert_eq!(completed.gate.ready_at_ms, terminal_ms + COOLDOWN_MS);
        assert_eq!(completed.gate.ready_at, terminal_mono + COOLDOWN);
    }

    #[tokio::test]
    async fn original_snapshot_candidate_union_is_affinely_retained_through_finish() {
        let fixture = preselection_snapshot_fixture(2, false).await;
        let original = snapshot_candidate_union_identity(&fixture.snapshot);
        let signers = fixture.signers;
        let started_at_ms = fixture.now_ms;
        let started_at_mono = Instant::now();
        let Ok(pending) = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    started_at_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 81)),
            )
        else {
            panic!("valid transcript attempt");
        };
        assert_eq!(
            snapshot_candidate_union_identity(&pending.snapshot),
            original
        );
        let (ready, _) =
            advance_authentic_responses(pending, &signers, started_at_ms, started_at_mono);
        assert_eq!(snapshot_candidate_union_identity(&ready.snapshot), original);
        let Ok(completed) = ready.finish_at(
            started_at_ms + 1_600,
            started_at_mono + Duration::from_millis(1_600),
        ) else {
            panic!("ready attempt finishes with its original snapshot");
        };
        assert_eq!(
            snapshot_candidate_union_identity(&completed.snapshot),
            original
        );
    }

    #[tokio::test]
    async fn raw_responses_advance_one_jit_request_and_finish_exact_bound_records() {
        let fixture = preselection_snapshot_fixture(2, false).await;
        let signers = fixture.signers;
        let persisted_payload_hashes = fixture.advertisement_payload_hashes;
        let started_at_ms = fixture.now_ms;
        let started_at_mono = Instant::now();
        let Ok(pending) = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    started_at_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 81)),
            )
        else {
            panic!("valid transcript attempt");
        };
        assert_exact_persisted_payload_hashes(
            &pending.snapshot.preselection_subjects,
            &persisted_payload_hashes,
        );
        let (expected_control, expected_exit) =
            pending.snapshot.preselection_subjects.forwarded_pairs[0];
        let expected_direct_subjects = (0..pending.snapshot.preselection_subjects.entries.len()
            - 1)
            .filter(|subject| *subject != expected_control)
            .collect::<HashSet<_>>();
        let (ready, expected) =
            advance_authentic_responses(pending, &signers, started_at_ms, started_at_mono);
        assert_bound_records(
            &ready,
            &expected,
            expected_control,
            expected_exit,
            &expected_direct_subjects,
        );
        let terminal_ms = started_at_ms + 1_600;
        let terminal_mono = started_at_mono + Duration::from_millis(1_600);
        let Ok(completed) = ready.finish_at(terminal_ms, terminal_mono) else {
            panic!("ready attempt finishes before unchanged deadline");
        };
        assert_completed_batch(
            &completed,
            started_at_ms,
            started_at_mono,
            terminal_ms,
            terminal_mono,
        );
        assert!(
            completed
                .gate
                .resume_at(terminal_ms + COOLDOWN_MS, terminal_mono + COOLDOWN)
                .is_ok()
        );
    }

    async fn completed_attempt_for_freshness_join() -> (
        CompletedPreselectionAttempt,
        Vec<PreselectionTransportFreshnessFacts>,
        u64,
        Instant,
    ) {
        let fixture = preselection_snapshot_fixture(2, false).await;
        let started_at_ms = fixture.now_ms;
        let started_at_mono = Instant::now();
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    started_at_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 81)),
            )
            .unwrap_or_else(|_| panic!("valid proof-join attempt"));
        let (ready, _) =
            advance_authentic_responses(pending, &fixture.signers, started_at_ms, started_at_mono);
        let completed = ready
            .finish_at(
                started_at_ms + 1_600,
                started_at_mono + Duration::from_millis(1_600),
            )
            .unwrap_or_else(|_| panic!("proof-join attempt finishes"));
        let facts = vec![
            PreselectionTransportFreshnessFacts {
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([1, 1, 1]),
                observed_at_ms: started_at_ms + 600,
                round_trip: Duration::from_millis(6),
            },
            PreselectionTransportFreshnessFacts {
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([8, 8, 4]),
                observed_at_ms: started_at_ms + 1_100,
                round_trip: Duration::from_millis(7),
            },
            PreselectionTransportFreshnessFacts {
                observed_network_prefix: ObservedNetworkPrefix::ipv4_24([9, 9, 9]),
                observed_at_ms: started_at_ms + 1_600,
                round_trip: Duration::from_millis(8),
            },
        ];
        (completed, facts, started_at_ms, started_at_mono)
    }

    #[tokio::test]
    async fn exact_transport_and_transcript_proofs_join_affinely_by_request_and_subject() {
        let (completed, facts, started_at_ms, started_at_mono) =
            completed_attempt_for_freshness_join().await;
        let Ok(joined) = completed.join_transport_facts_for_test(
            facts,
            started_at_ms + 1_700,
            started_at_mono + Duration::from_millis(1_700),
        ) else {
            panic!("exact proof facts must join");
        };
        let (expected_control, expected_exit) =
            joined.snapshot.preselection_subjects.forwarded_pairs[0];
        let (snapshot, batch, gate) = joined.into_parts();
        assert_eq!(snapshot.direct_relays.len(), 3);
        assert_ne!(size_of_val(&gate), 0);
        let (transport, family, batch_id, started_ms, deadline_ms, minimum, ceiling, records) =
            batch.into_parts();
        assert_eq!(transport, Transport::UdpSinglePath);
        assert_eq!(family, ObservationAddressFamily::Ipv4);
        assert_eq!(batch_id, [81; BATCH_ID_LENGTH]);
        assert_eq!(started_ms, started_at_ms);
        assert_eq!(deadline_ms, started_at_ms + ATTEMPT_LIFETIME_MS);
        assert_eq!(minimum, bandwidth(10));
        assert_eq!(ceiling, bandwidth(80));
        assert_eq!(records.len(), 3);

        let (subject, control, role, transport, transcript) = records
            .into_iter()
            .next()
            .expect("forwarded record")
            .into_parts();
        assert_eq!(subject, expected_exit);
        assert_eq!(control, Some(expected_control));
        assert_eq!(role, PreselectionObservationRole::Exit);
        assert!(transport.observed_network_prefix() == ObservedNetworkPrefix::ipv4_24([1, 1, 1]));
        assert_eq!(transport.observed_at_ms(), started_at_ms + 600);
        assert_eq!(transport.round_trip(), Duration::from_millis(6));
        assert!(
            transcript.upstream_network_prefix() == Some(ObservedNetworkPrefix::ipv4_24([8, 8, 8]))
        );
        assert_eq!(transcript.valid_until_ms(), started_at_ms + 10_500);
    }

    #[tokio::test]
    async fn proof_join_rejects_count_hash_actor_family_and_independent_time_substitution() {
        for case in 0_u8..7 {
            let (mut completed, mut facts, started_at_ms, started_at_mono) =
                completed_attempt_for_freshness_join().await;
            let mut trusted_now_ms = started_at_ms + 1_700;
            let mut trusted_now_mono = started_at_mono + Duration::from_millis(1_700);
            let control_subject = completed.snapshot.preselection_subjects.forwarded_pairs[0].0;
            match case {
                0 => {
                    facts.pop();
                }
                1 => {
                    completed.batch.transcripts[1].request_hash =
                        completed.batch.transcripts[0].request_hash;
                }
                2 => completed.batch.transcripts[1].subject = control_subject,
                3 => {
                    facts[1].observed_network_prefix =
                        ObservedNetworkPrefix::ipv6_48([0x26, 6, 7, 8, 9, 10]);
                }
                4 => facts[1].observed_at_ms = started_at_ms - 1,
                5 => facts[1].round_trip = Duration::ZERO,
                _ => {
                    trusted_now_ms = started_at_ms + ATTEMPT_LIFETIME_MS;
                    trusted_now_mono = started_at_mono + Duration::from_millis(ATTEMPT_LIFETIME_MS);
                }
            }
            let failure = match completed.join_transport_facts_for_test(
                facts,
                trusted_now_ms,
                trusted_now_mono,
            ) {
                Ok(_) => panic!("proof substitution case {case} joined"),
                Err(failure) => failure,
            };
            let error = failure.error();
            assert!(matches!(
                error,
                PreselectionAttemptError::InvalidSnapshot
                    | PreselectionAttemptError::Transport
                    | PreselectionAttemptError::InvalidTime
            ));
            assert_ne!(size_of_val(&failure.into_gate()), 0);
        }
    }

    async fn assert_invalid_entropy_fails_closed_without_redraw() {
        for case in 0..4 {
            let fixture = preselection_snapshot_fixture(1, false).await;
            let calls = Cell::new(0);
            let result = PreselectionAttemptGate::new()
                .expect("gate")
                .begin_at_with_entropy_for_test(
                    fixture.snapshot,
                    attempt_start_at(
                        Transport::UdpSinglePath,
                        ObservationAddressFamily::Ipv4,
                        bandwidth(10),
                        bandwidth(100),
                        bandwidth(80),
                        fixture.now_ms,
                        Instant::now(),
                    ),
                    |request_count| {
                        calls.set(calls.get() + 1);
                        if case == 0 {
                            return Err(PreselectionAttemptError::Entropy);
                        }
                        let mut entropy = minted_entropy(request_count, 121 + case);
                        match case {
                            1 => entropy.batch_id = [0; BATCH_ID_LENGTH],
                            2 => entropy.challenges[0] = [0; CHALLENGE_LENGTH],
                            3 => entropy.challenges[1] = entropy.challenges[0],
                            _ => unreachable!(),
                        }
                        Ok(entropy)
                    },
                );
            let failure = match result {
                Ok(_) => panic!("invalid entropy must fail"),
                Err(failure) => failure,
            };
            assert_eq!(calls.get(), 1);
            assert_eq!(failure.error, PreselectionAttemptError::Entropy);
            assert!(failure.gate.is_none());
            assert!(failure.cooling_gate.is_some());
        }
    }

    async fn assert_recent_entropy_collisions_fail_closed() {
        for batch_collision in [false, true] {
            let fixture = preselection_snapshot_fixture(1, false).await;
            let started_at_mono = Instant::now();
            let mut gate = PreselectionAttemptGate::new().expect("gate");
            if batch_collision {
                gate.batch_tombstones.push_back(BatchTombstone {
                    batch_id: [131; BATCH_ID_LENGTH],
                    expires_at: started_at_mono + TOMBSTONE_LIFETIME,
                });
            } else {
                gate.tombstones.push_back(ChallengeTombstone {
                    challenge: [132; CHALLENGE_LENGTH],
                    expires_at: started_at_mono + TOMBSTONE_LIFETIME,
                });
            }
            let result = gate.begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    started_at_mono,
                ),
                |request_count| {
                    let mut entropy = minted_entropy(request_count, 131);
                    if !batch_collision {
                        entropy.challenges[0] = [132; CHALLENGE_LENGTH];
                    }
                    Ok(entropy)
                },
            );
            let failure = match result {
                Ok(_) => panic!("recent entropy must not be reused"),
                Err(failure) => failure,
            };
            assert_eq!(failure.error, PreselectionAttemptError::Entropy);
            assert!(failure.gate.is_none());
            assert!(failure.cooling_gate.is_some());
        }
    }

    async fn assert_live_challenge_tombstones_are_not_evicted() {
        let full_challenge_fixture = preselection_snapshot_fixture(1, false).await;
        let full_started_at_mono = Instant::now();
        let mut challenge_full = PreselectionAttemptGate::new().expect("gate");
        for value in 1_u8..=35 {
            challenge_full.tombstones.push_back(ChallengeTombstone {
                challenge: [value; CHALLENGE_LENGTH],
                expires_at: full_started_at_mono + TOMBSTONE_LIFETIME,
            });
        }
        let challenge_calls = Cell::new(0);
        let challenge_failure = match challenge_full.begin_at_with_entropy_for_test(
            full_challenge_fixture.snapshot,
            attempt_start_at(
                Transport::UdpSinglePath,
                ObservationAddressFamily::Ipv4,
                bandwidth(10),
                bandwidth(100),
                bandwidth(80),
                full_challenge_fixture.now_ms,
                full_started_at_mono,
            ),
            |request_count| {
                challenge_calls.set(challenge_calls.get() + 1);
                Ok(minted_entropy(request_count, 141))
            },
        ) {
            Ok(_) => panic!("live challenge tombstones must not be evicted"),
            Err(failure) => failure,
        };
        assert_eq!(challenge_calls.get(), 0);
        assert_eq!(
            challenge_failure.error,
            PreselectionAttemptError::TombstoneCapacity
        );
        assert_eq!(
            challenge_failure
                .gate
                .as_ref()
                .expect("unchanged gate")
                .tombstones
                .len(),
            35
        );
    }

    async fn assert_live_batch_tombstones_are_not_evicted() {
        let full_batch_fixture = preselection_snapshot_fixture(1, false).await;
        let batch_started_at_mono = Instant::now();
        let mut batch_full = PreselectionAttemptGate::new().expect("gate");
        for value in
            1_u8..=u8::try_from(MAXIMUM_BATCH_TOMBSTONES).expect("bounded batch tombstones")
        {
            batch_full.batch_tombstones.push_back(BatchTombstone {
                batch_id: [value; BATCH_ID_LENGTH],
                expires_at: batch_started_at_mono + TOMBSTONE_LIFETIME,
            });
        }
        let batch_calls = Cell::new(0);
        let batch_failure = match batch_full.begin_at_with_entropy_for_test(
            full_batch_fixture.snapshot,
            attempt_start_at(
                Transport::UdpSinglePath,
                ObservationAddressFamily::Ipv4,
                bandwidth(10),
                bandwidth(100),
                bandwidth(80),
                full_batch_fixture.now_ms,
                batch_started_at_mono,
            ),
            |request_count| {
                batch_calls.set(batch_calls.get() + 1);
                Ok(minted_entropy(request_count, 151))
            },
        ) {
            Ok(_) => panic!("live batch tombstones must not be evicted"),
            Err(failure) => failure,
        };
        assert_eq!(batch_calls.get(), 0);
        assert_eq!(
            batch_failure.error,
            PreselectionAttemptError::TombstoneCapacity
        );
        assert_eq!(
            batch_failure
                .gate
                .as_ref()
                .expect("unchanged gate")
                .batch_tombstones
                .len(),
            MAXIMUM_BATCH_TOMBSTONES
        );
    }

    async fn assert_expired_tombstones_purge_before_mint() {
        let expired_fixture = preselection_snapshot_fixture(1, false).await;
        let expired_started_at_mono = Instant::now();
        let mut expired = PreselectionAttemptGate::new().expect("gate");
        for value in 1_u8..=u8::try_from(MAXIMUM_TOMBSTONES).expect("bounded tombstones") {
            expired.tombstones.push_back(ChallengeTombstone {
                challenge: [value; CHALLENGE_LENGTH],
                expires_at: expired_started_at_mono,
            });
        }
        for value in
            1_u8..=u8::try_from(MAXIMUM_BATCH_TOMBSTONES).expect("bounded batch tombstones")
        {
            expired.batch_tombstones.push_back(BatchTombstone {
                batch_id: [value; BATCH_ID_LENGTH],
                expires_at: expired_started_at_mono,
            });
        }
        let expired_calls = Cell::new(0);
        let Ok(pending) = expired.begin_at_with_entropy_for_test(
            expired_fixture.snapshot,
            attempt_start_at(
                Transport::UdpSinglePath,
                ObservationAddressFamily::Ipv4,
                bandwidth(10),
                bandwidth(100),
                bandwidth(80),
                expired_fixture.now_ms,
                expired_started_at_mono,
            ),
            |request_count| {
                expired_calls.set(expired_calls.get() + 1);
                Ok(minted_entropy(request_count, 161))
            },
        ) else {
            panic!("expired tombstones must purge before one mint");
        };
        assert_eq!(expired_calls.get(), 1);
        assert_eq!(pending.gate.tombstones.len(), 1);
        assert_eq!(pending.gate.batch_tombstones.len(), 1);
    }

    #[tokio::test]
    async fn entropy_and_live_tombstone_limits_fail_closed_without_redraw_or_eviction() {
        assert_invalid_entropy_fails_closed_without_redraw().await;
        assert_recent_entropy_collisions_fail_closed().await;
        assert_live_challenge_tombstones_are_not_evicted().await;
        assert_live_batch_tombstones_are_not_evicted().await;
        assert_expired_tombstones_purge_before_mint().await;
    }

    async fn assert_unknown_dispatch_and_cooldown_fail_closed() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let signers = fixture.signers;
        let started_at_ms = fixture.now_ms;
        let started_at_mono = Instant::now();
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    started_at_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 171)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let response = signed_response(&pending, &signers, started_at_ms + 100, 181);
        let wrong_dispatch = ObservationDispatchId {
            batch_id: pending.batch_id,
            ordinal: pending.pending.dispatch_id.ordinal + 1,
        };
        let unknown = match pending.verify_response_at(
            &wrong_dispatch,
            &response,
            started_at_ms + 100,
            started_at_mono + Duration::from_millis(100),
        ) {
            Ok(_) => panic!("unknown dispatch must fail before crypto"),
            Err(failure) => failure,
        };
        assert_eq!(unknown.error, PreselectionAttemptError::UnknownDispatch);
        let mut cooling = unknown.gate.expect("valid terminal time returns cooldown");
        assert!(cooling.gate.replay.is_empty());
        let ready_at_ms = cooling.ready_at_ms;
        let ready_at = cooling.ready_at;
        cooling = match cooling.resume_at(ready_at_ms - 1, ready_at) {
            Ok(_) => panic!("wall cooldown is independent"),
            Err(cooling) => cooling,
        };
        cooling = match cooling.resume_at(ready_at_ms, ready_at - Duration::from_nanos(1)) {
            Ok(_) => panic!("monotonic cooldown is independent"),
            Err(cooling) => cooling,
        };
        assert!(cooling.resume_at(ready_at_ms, ready_at).is_ok());
    }

    async fn assert_exact_request_deadline_fails_before_decode() {
        let late_fixture = preselection_snapshot_fixture(1, false).await;
        let late_started_at_mono = Instant::now();
        let late = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                late_fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    late_fixture.now_ms,
                    late_started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 191)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let late_dispatch = ObservationDispatchId {
            batch_id: late.batch_id,
            ordinal: late.pending.dispatch_id.ordinal,
        };
        let expires_at_mono = late.pending.expires_at_mono;
        let late_failure = match late.verify_response_at(
            &late_dispatch,
            &[],
            late_fixture.now_ms + REQUEST_LIFETIME_MS,
            expires_at_mono,
        ) {
            Ok(_) => panic!("exact request deadline must fail before decode"),
            Err(failure) => failure,
        };
        assert_eq!(late_failure.error, PreselectionAttemptError::InvalidTime);
        assert!(
            late_failure
                .gate
                .as_ref()
                .expect("late terminal cooldown")
                .gate
                .replay
                .is_empty()
        );
    }

    async fn assert_committed_composite_replay_fails_closed() {
        let replay_fixture = preselection_snapshot_fixture(1, false).await;
        let replay_signers = replay_fixture.signers;
        let replay_started_at_mono = Instant::now();
        let replay_pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                replay_fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    replay_fixture.now_ms,
                    replay_started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 201)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let replay_dispatch = ObservationDispatchId {
            batch_id: replay_pending.batch_id,
            ordinal: replay_pending.pending.dispatch_id.ordinal,
        };
        let replay_response = signed_response(
            &replay_pending,
            &replay_signers,
            replay_fixture.now_ms + 100,
            211,
        );
        let replay_request = replay_pending.pending.expected_request.clone();
        let Ok(PreselectionResponseOutcome::Pending(next)) = replay_pending.verify_response_at(
            &replay_dispatch,
            &replay_response,
            replay_fixture.now_ms + 100,
            replay_started_at_mono + Duration::from_millis(100),
        ) else {
            panic!("first composite must commit with one direct request remaining");
        };
        assert_eq!(next.gate.replay.len(), 2);
        let mut next = next;
        let replay_error = match verify_forwarded_preselection_transcript(
            &replay_response,
            &replay_request,
            replay_fixture.now_ms + 200,
            TimePolicy::default(),
            &mut next.gate.replay,
        ) {
            Ok(_) => panic!("committed outer/inner transcript must not replay"),
            Err(error) => error,
        };
        assert!(matches!(replay_error, ProtocolError::Replay));
        assert_eq!(next.gate.replay.len(), 2);
    }

    async fn assert_backward_wall_time_loses_gate() {
        let backward_fixture = preselection_snapshot_fixture(1, false).await;
        let backward_started_at_mono = Instant::now();
        let backward = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                backward_fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    backward_fixture.now_ms,
                    backward_started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 221)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let backward_failure =
            match backward.cancel_at(backward_fixture.now_ms - 1, backward_started_at_mono) {
                Ok(_) => panic!("backward wall time loses gate fail closed"),
                Err(failure) => failure,
            };
        assert_eq!(
            backward_failure.error,
            PreselectionAttemptError::InvalidTime
        );
        assert!(backward_failure.gate.is_none());
    }

    #[tokio::test]
    async fn dispatch_replay_time_and_cooldown_paths_are_fail_closed() {
        assert_unknown_dispatch_and_cooldown_fail_closed().await;
        assert_exact_request_deadline_fails_before_decode().await;
        assert_committed_composite_replay_fails_closed().await;
        assert_backward_wall_time_loses_gate().await;
    }

    #[tokio::test]
    async fn forwarded_request_separates_canonical_actor_expiry_from_local_authority() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let started_at_ms = fixture.now_ms + 18_000;
        let started_at_mono = Instant::now();
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    started_at_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 231)),
            )
            .unwrap_or_else(|_| panic!("still-live local authority must begin"));
        let (_, exit_index) = pending.snapshot.preselection_subjects.forwarded_pairs[0];
        let exit = &pending.snapshot.preselection_subjects.entries[exit_index];
        assert!(
            exit.local_discovery_authority_expires_at_ms < exit.capability_expires_at_ms,
            "old discovery request deadline is deliberately stricter than the canonical actor cap"
        );
        let request = request(&pending);
        assert_eq!(
            request
                .actor
                .as_ref()
                .expect("exit actor")
                .capability_expires_at_ms,
            exit.capability_expires_at_ms
        );
        assert_eq!(
            request.expires_at_ms,
            exit.local_discovery_authority_expires_at_ms
        );
        assert!(request.expires_at_ms < started_at_ms + REQUEST_LIFETIME_MS);
    }

    #[tokio::test]
    async fn exact_tombstone_boundaries_accept_without_live_eviction() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let signers = fixture.signers;
        let started_at_mono = Instant::now();
        let mut gate = PreselectionAttemptGate::new().expect("gate");
        for value in 1_u8..=34 {
            gate.tombstones.push_back(ChallengeTombstone {
                challenge: [value; CHALLENGE_LENGTH],
                expires_at: started_at_mono + TOMBSTONE_LIFETIME,
            });
        }
        for value in 1_u8..=3 {
            gate.batch_tombstones.push_back(BatchTombstone {
                batch_id: [value; BATCH_ID_LENGTH],
                expires_at: started_at_mono + TOMBSTONE_LIFETIME,
            });
        }
        let pending = gate
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 241)),
            )
            .unwrap_or_else(|_| panic!("34+2 challenges and 3+1 batches fit exactly"));
        assert_eq!(pending.gate.tombstones.len(), 35);
        assert_eq!(pending.gate.batch_tombstones.len(), 4);
        let dispatch = ObservationDispatchId {
            batch_id: pending.batch_id,
            ordinal: pending.pending.dispatch_id.ordinal,
        };
        let response = signed_response(&pending, &signers, fixture.now_ms + 100, 251);
        let Ok(PreselectionResponseOutcome::Pending(next)) = pending.verify_response_at(
            &dispatch,
            &response,
            fixture.now_ms + 100,
            started_at_mono + Duration::from_millis(100),
        ) else {
            panic!("exact-capacity JIT preparation must leave one direct request");
        };
        assert_eq!(next.gate.tombstones.len(), MAXIMUM_TOMBSTONES);
        assert_eq!(next.gate.batch_tombstones.len(), MAXIMUM_BATCH_TOMBSTONES);
        assert_eq!(next.gate.tombstones[0].challenge, [1; CHALLENGE_LENGTH]);
        assert_eq!(next.gate.batch_tombstones[0].batch_id, [1; BATCH_ID_LENGTH]);
    }

    #[tokio::test]
    async fn owned_replay_cache_rejects_entry_forty_one_without_evicting_live_entries() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let signers = fixture.signers;
        let started_at_mono = Instant::now();
        let mut pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 31)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let expected = request(&pending);
        let actor = expected.actor.as_ref().expect("exit actor");
        let scope = expected.scope.as_ref().expect("request scope");
        let valid_until_ms = (fixture.now_ms + 10_000)
            .min(actor.advertisement_expires_at_ms)
            .min(actor.capability_expires_at_ms)
            .min(scope.policy_expires_at_ms);
        let mut first = None;
        for nonce in 1_u8..=u8::try_from(REPLAY_CAPACITY).expect("bounded replay capacity") {
            let receipt = PreselectionObservationReceipt {
                request_hash: pending.pending.request_hash.to_vec(),
                challenge: expected.challenge.clone(),
                actor: expected.actor.clone(),
                scope: expected.scope.clone(),
                observed_at_ms: fixture.now_ms,
                valid_until_ms,
                nonce: vec![nonce; 32],
            };
            let signed = sign_payload(
                &receipt,
                signer_for(&signers, actor),
                receipt.observed_at_ms,
                receipt.valid_until_ms,
                [nonce; 32],
            );
            verify_control_message::<PreselectionObservationReceipt>(
                &signed,
                fixture.now_ms,
                TimePolicy::default(),
                &mut pending.gate.replay,
            )
            .unwrap_or_else(|_| panic!("entry {nonce} fits owned replay cache"));
            if nonce == 1 {
                first = Some(signed);
            }
        }
        assert_eq!(pending.gate.replay.len(), REPLAY_CAPACITY);
        let overflow_receipt = PreselectionObservationReceipt {
            request_hash: pending.pending.request_hash.to_vec(),
            challenge: expected.challenge.clone(),
            actor: expected.actor.clone(),
            scope: expected.scope.clone(),
            observed_at_ms: fixture.now_ms,
            valid_until_ms,
            nonce: vec![41; 32],
        };
        let overflow = sign_payload(
            &overflow_receipt,
            signer_for(&signers, actor),
            overflow_receipt.observed_at_ms,
            overflow_receipt.valid_until_ms,
            [41; 32],
        );
        assert!(matches!(
            verify_control_message::<PreselectionObservationReceipt>(
                &overflow,
                fixture.now_ms,
                TimePolicy::default(),
                &mut pending.gate.replay,
            ),
            Err(ProtocolError::ReplayCapacity)
        ));
        assert_eq!(pending.gate.replay.len(), REPLAY_CAPACITY);
        assert!(matches!(
            verify_control_message::<PreselectionObservationReceipt>(
                &first.expect("first live replay entry"),
                fixture.now_ms,
                TimePolicy::default(),
                &mut pending.gate.replay,
            ),
            Err(ProtocolError::Replay)
        ));
        assert_eq!(pending.gate.replay.len(), REPLAY_CAPACITY);
    }

    async fn assert_checked_wall_and_monotonic_overflow_precede_entropy() {
        let wall_overflow = preselection_snapshot_fixture(1, false).await;
        let wall_calls = Cell::new(0);
        let wall_result = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                wall_overflow.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    u64::MAX - ATTEMPT_LIFETIME_MS,
                    Instant::now(),
                ),
                |request_count| {
                    wall_calls.set(wall_calls.get() + 1);
                    Ok(minted_entropy(request_count, 41))
                },
            );
        let wall_failure = match wall_result {
            Ok(_) => panic!("deadline plus tombstone horizon must not overflow"),
            Err(failure) => failure,
        };
        assert_eq!(wall_calls.get(), 0);
        assert_eq!(wall_failure.error, PreselectionAttemptError::InvalidTime);
        assert!(wall_failure.gate.is_some());

        let mono_overflow = preselection_snapshot_fixture(1, false).await;
        let base = Instant::now();
        let mut accepted_seconds = 0_u64;
        let mut rejected_seconds = u64::MAX;
        while accepted_seconds < rejected_seconds {
            let midpoint = accepted_seconds
                .saturating_add(rejected_seconds.saturating_sub(accepted_seconds) / 2)
                .saturating_add(1);
            if base.checked_add(Duration::from_secs(midpoint)).is_some() {
                accepted_seconds = midpoint;
            } else {
                rejected_seconds = midpoint - 1;
            }
        }
        let latest = base
            .checked_add(Duration::from_secs(accepted_seconds))
            .expect("maximum whole-second monotonic instant");
        let mono_calls = Cell::new(0);
        let mono_result = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                mono_overflow.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    mono_overflow.now_ms,
                    latest,
                ),
                |request_count| {
                    mono_calls.set(mono_calls.get() + 1);
                    Ok(minted_entropy(request_count, 51))
                },
            );
        let mono_failure = match mono_result {
            Ok(_) => panic!("monotonic attempt deadline must not overflow"),
            Err(failure) => failure,
        };
        assert_eq!(mono_calls.get(), 0);
        assert_eq!(mono_failure.error, PreselectionAttemptError::InvalidTime);
        assert!(mono_failure.gate.is_some());
    }

    async fn assert_local_expiry_equality_and_backward_mono_fail_closed() {
        let local_equal = preselection_snapshot_fixture(1, false).await;
        let (_, exit_index) = local_equal.snapshot.preselection_subjects.forwarded_pairs[0];
        let local_expiry = local_equal.snapshot.preselection_subjects.entries[exit_index]
            .local_discovery_authority_expires_at_ms;
        let local_calls = Cell::new(0);
        let local_result = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                local_equal.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    local_expiry,
                    Instant::now(),
                ),
                |request_count| {
                    local_calls.set(local_calls.get() + 1);
                    Ok(minted_entropy(request_count, 61))
                },
            );
        let local_failure = match local_result {
            Ok(_) => panic!("local discovery authority equality is stale"),
            Err(failure) => failure,
        };
        assert_eq!(local_calls.get(), 0);
        assert_eq!(
            local_failure.error,
            PreselectionAttemptError::InvalidSnapshot
        );
        assert!(local_failure.gate.is_some());

        let backward = preselection_snapshot_fixture(1, false).await;
        let backward_started_at_mono = Instant::now();
        let pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                backward.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    backward.now_ms,
                    backward_started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 71)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        let backward_failure = match pending.cancel_at(
            backward.now_ms,
            backward_started_at_mono - Duration::from_nanos(1),
        ) {
            Ok(_) => panic!("backward monotonic terminal loses gate"),
            Err(failure) => failure,
        };
        assert_eq!(
            backward_failure.error,
            PreselectionAttemptError::InvalidTime
        );
        assert!(backward_failure.gate.is_none());
    }

    #[tokio::test]
    async fn checked_clock_overflow_backward_mono_and_local_expiry_equality_precede_entropy() {
        Box::pin(assert_checked_wall_and_monotonic_overflow_precede_entropy()).await;
        Box::pin(assert_local_expiry_equality_and_backward_mono_fail_closed()).await;
    }

    #[tokio::test]
    async fn signed_advertisement_scope_matrix_and_unsupported_flags_precede_entropy() {
        let combinations = [
            (Transport::TcpMptcp, ObservationAddressFamily::Ipv4),
            (Transport::TcpMptcp, ObservationAddressFamily::Ipv6),
            (Transport::UdpSinglePath, ObservationAddressFamily::Ipv4),
            (Transport::UdpSinglePath, ObservationAddressFamily::Ipv6),
            (Transport::MultipathQuic, ObservationAddressFamily::Ipv4),
            (Transport::MultipathQuic, ObservationAddressFamily::Ipv6),
        ];
        for (offset, (transport, family)) in combinations.into_iter().enumerate() {
            let fixture = preselection_snapshot_fixture_with_capabilities(
                1,
                false,
                PreselectionTestCapabilities::all(),
            )
            .await;
            let persisted = fixture.advertisement_payload_hashes;
            let calls = Cell::new(0);
            let pending = PreselectionAttemptGate::new()
                .expect("gate")
                .begin_at_with_entropy_for_test(
                    fixture.snapshot,
                    attempt_start_at(
                        transport,
                        family,
                        bandwidth(10),
                        bandwidth(100),
                        bandwidth(80),
                        fixture.now_ms,
                        Instant::now(),
                    ),
                    |request_count| {
                        calls.set(calls.get() + 1);
                        Ok(minted_entropy(
                            request_count,
                            91_u8.wrapping_add(u8::try_from(offset).expect("six scopes") * 4),
                        ))
                    },
                )
                .unwrap_or_else(|_| panic!("signed scope {transport:?}/{family:?} must begin"));
            assert_eq!(calls.get(), 1);
            assert_exact_persisted_payload_hashes(
                &pending.snapshot.preselection_subjects,
                &persisted,
            );
            let decoded = request(&pending);
            let scope = decoded.scope.expect("request scope");
            assert_eq!(scope.transport, transport as i32);
            assert_eq!(scope.address_family, family as i32);
        }

        assert_unsupported_scope_precedes_entropy(
            Transport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
        )
        .await;
        assert_unsupported_scope_precedes_entropy(
            Transport::MultipathQuic,
            ObservationAddressFamily::Ipv4,
        )
        .await;
        assert_unsupported_scope_precedes_entropy(
            Transport::UdpSinglePath,
            ObservationAddressFamily::Ipv6,
        )
        .await;
    }

    #[tokio::test]
    async fn post_crypto_next_prepare_failure_retains_both_replay_commits() {
        let fixture = preselection_snapshot_fixture(1, false).await;
        let signers = fixture.signers;
        let started_at_mono = Instant::now();
        let mut pending = PreselectionAttemptGate::new()
            .expect("gate")
            .begin_at_with_entropy_for_test(
                fixture.snapshot,
                attempt_start_at(
                    Transport::UdpSinglePath,
                    ObservationAddressFamily::Ipv4,
                    bandwidth(10),
                    bandwidth(100),
                    bandwidth(80),
                    fixture.now_ms,
                    started_at_mono,
                ),
                |request_count| Ok(minted_entropy(request_count, 151)),
            )
            .unwrap_or_else(|_| panic!("valid attempt"));
        assert_eq!(pending.gate.replay.len(), 0);
        assert_eq!(pending.gate.tombstones.len(), 1);
        let dispatch = ObservationDispatchId {
            batch_id: pending.pending.dispatch_id.batch_id,
            ordinal: pending.pending.dispatch_id.ordinal,
        };
        let expected_request = pending.pending.expected_request.clone();
        let response = signed_response(&pending, &signers, fixture.now_ms + 100, 161);
        pending
            .remaining
            .front_mut()
            .expect("one next direct request")
            .subject = usize::MAX;
        let failure = match pending.verify_response_at(
            &dispatch,
            &response,
            fixture.now_ms + 100,
            started_at_mono + Duration::from_millis(100),
        ) {
            Ok(_) => panic!("corrupt next plan must fail after the composite commit"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error, PreselectionAttemptError::InvalidSnapshot);
        let cooling = failure.gate.expect("valid terminal time retains cooldown");
        assert_eq!(cooling.gate.replay.len(), 2);
        assert_eq!(cooling.gate.tombstones.len(), 1);
        let ready_at_ms = cooling.ready_at_ms;
        let ready_at = cooling.ready_at;
        let Ok(mut gate) = cooling.resume_at(ready_at_ms, ready_at) else {
            panic!("exact cooldown endpoint resumes");
        };
        let replay = verify_forwarded_preselection_transcript(
            &response,
            &expected_request,
            fixture.now_ms + 200,
            TimePolicy::default(),
            &mut gate.replay,
        );
        assert!(matches!(replay, Err(ProtocolError::Replay)));
        assert_eq!(gate.replay.len(), 2);
    }

    #[test]
    fn clock_sampling_entrypoints_remain_inside_the_affine_owner_module() {
        fn consume_owner_transition_for_test(failure: PreselectionOwnerTransitionFailure) {
            match failure {
                PreselectionOwnerTransitionFailure::Retained(owner) => drop(owner),
                PreselectionOwnerTransitionFailure::Cooling(gate) => drop(gate),
                PreselectionOwnerTransitionFailure::Closed => {}
            }
        }

        std::hint::black_box(PreselectionAttemptGate::begin);
        std::hint::black_box(PreselectionAttemptGate::begin_at);
        std::hint::black_box(PreselectionAttemptGate::begin_validated);
        std::hint::black_box(CoolingPreselectionAttemptGate::resume);
        std::hint::black_box(PendingPreselectionAttempt::dispatch);
        std::hint::black_box(PendingPreselectionAttempt::verify_response_from_exact_dispatch);
        std::hint::black_box(PendingPreselectionAttempt::cancel);
        std::hint::black_box(DispatchedPreselectionAttempt::bind_response);
        std::hint::black_box(DispatchedPreselectionAttempt::cancel);
        std::hint::black_box(ReadyPreselectionAttempt::finish);
        std::hint::black_box(ReadyPreselectionAttempt::cancel);
        std::hint::black_box(ReadyPreselectionAttempt::cancel_at);
        std::hint::black_box(CompletedPreselectionAttempt::join_transport_proofs);
        std::hint::black_box(mint_attempt_entropy);
        std::hint::black_box(consume_owner_transition_for_test);
    }

    fn assert_a1a_subject_and_transcript_fields(product: &str) {
        assert_source_fields(
            product,
            "pub(super) struct PreselectionSubjectBinding {",
            &[
                "node_id: [u8; 32],",
                "peer_id: Vec<u8>,",
                "public_key: [u8; 32],",
                "advertisement_sequence: u64,",
                "advertisement_expires_at_ms: u64,",
                "advertisement_payload_hash: AdvertisementPayloadHash,",
                "policy_version: u64,",
                "policy_hash: [u8; 32],",
                "policy_expires_at_ms: u64,",
                "capability_expires_at_ms: u64,",
                "local_discovery_authority_expires_at_ms: u64,",
                "relay: bool,",
                "exit: bool,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct PreselectionSubjectSet {",
            &[
                "pub(super) available: bool,",
                "pub(super) entries: Vec<PreselectionSubjectBinding>,",
                "pub(super) forwarded_pairs: Vec<(usize, usize)>,",
            ],
        );
        assert_source_fields(
            product,
            "struct ObservationDispatchId {",
            &["batch_id: [u8; BATCH_ID_LENGTH],", "ordinal: u8,"],
        );
        assert_source_fields(
            product,
            "enum BoundTranscript {",
            &[
                "Direct(Box<BoundDirectPreselectionTranscript>),",
                "Forwarded(Box<BoundForwardedPreselectionTranscript>),",
            ],
        );
        assert_source_fields(
            product,
            "struct BoundTranscriptRecord {",
            &[
                "dispatch_id: ObservationDispatchId,",
                "request_hash: [u8; 32],",
                "subject: usize,",
                "forwarded_control: Option<usize>,",
                "role: PreselectionObservationRole,",
                "transcript: BoundTranscript,",
            ],
        );
    }

    fn assert_a1a_pending_owner_fields(product: &str) {
        assert_source_fields(
            product,
            "pub(super) struct PreselectionAttemptGate {",
            &[
                "tombstones: VecDeque<ChallengeTombstone>,",
                "batch_tombstones: VecDeque<BatchTombstone>,",
                "replay: Box<ReplayCache>,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct CoolingPreselectionAttemptGate {",
            &[
                "gate: PreselectionAttemptGate,",
                "ready_at_ms: u64,",
                "ready_at: Instant,",
            ],
        );
        assert_source_fields(
            product,
            "struct PendingRequest {",
            &[
                "dispatch_id: ObservationDispatchId,",
                "expected_request: Vec<u8>,",
                "request_hash: [u8; 32],",
                "subject: usize,",
                "forwarded_control: Option<usize>,",
                "role: PreselectionObservationRole,",
                "created_at_ms: u64,",
                "prepared_at_mono: Instant,",
                "expires_at_mono: Instant,",
                "kind: PendingRequestKind,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct PendingPreselectionAttempt {",
            &[
                "gate: PreselectionAttemptGate,",
                "snapshot: RouteCandidateSnapshot,",
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "batch_id: [u8; BATCH_ID_LENGTH],",
                "attempt_started_at_ms: u64,",
                "attempt_deadline_ms: u64,",
                "attempt_started_at_mono: Instant,",
                "attempt_deadline_mono: Instant,",
                "minimum_capacity: Bandwidth,",
                "preselection_capacity_ceiling: Bandwidth,",
                "pending: PendingRequest,",
                "remaining: VecDeque<RequestPlan>,",
                "bound: Vec<BoundTranscriptRecord>,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct DispatchedPreselectionAttempt {",
            &["transaction: ClientPreselectionTransaction<PendingPreselectionAttempt>,"],
        );
        assert_source_fields(
            product,
            "struct ValidatedAttemptInput {",
            &[
                "snapshot: RouteCandidateSnapshot,",
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "preselection_capacity_ceiling: Bandwidth,",
                "attempt_started_at_ms: u64,",
                "attempt_deadline_ms: u64,",
                "attempt_started_at_mono: Instant,",
                "attempt_deadline_mono: Instant,",
                "minimum_capacity: Bandwidth,",
                "other_relay_subjects: Vec<usize>,",
                "control_subject: usize,",
                "exit_subject: usize,",
            ],
        );
        assert_source_fields(
            product,
            "struct RequestPreparation<'a> {",
            &[
                "snapshot: &'a RouteCandidateSnapshot,",
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "batch_id: [u8; BATCH_ID_LENGTH],",
                "created_at_ms: u64,",
                "prepared_at_mono: Instant,",
                "attempt_deadline_ms: u64,",
                "attempt_deadline_mono: Instant,",
            ],
        );
        assert!(!product.contains("Vec<PendingRequest>"));
        assert_source_fields(
            product,
            "pub(super) enum PreselectionResponseOutcome {",
            &[
                "Pending(PendingPreselectionAttempt),",
                "Ready(ReadyPreselectionAttempt),",
            ],
        );
    }

    fn assert_a1a_terminal_owner_fields(product: &str) {
        assert_source_fields(
            product,
            "pub(super) struct ReadyPreselectionAttempt {",
            &[
                "gate: PreselectionAttemptGate,",
                "snapshot: RouteCandidateSnapshot,",
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "batch_id: [u8; BATCH_ID_LENGTH],",
                "attempt_started_at_ms: u64,",
                "attempt_deadline_ms: u64,",
                "attempt_started_at_mono: Instant,",
                "attempt_deadline_mono: Instant,",
                "minimum_capacity: Bandwidth,",
                "preselection_capacity_ceiling: Bandwidth,",
                "last_verified_at_ms: u64,",
                "last_verified_at_mono: Instant,",
                "bound: Vec<BoundTranscriptRecord>,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct BoundPreselectionTranscriptBatch {",
            &[
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "batch_id: [u8; BATCH_ID_LENGTH],",
                "attempt_started_at_ms: u64,",
                "attempt_deadline_ms: u64,",
                "attempt_started_at_mono: Instant,",
                "attempt_deadline_mono: Instant,",
                "minimum_capacity: Bandwidth,",
                "preselection_capacity_ceiling: Bandwidth,",
                "transcripts: Vec<BoundTranscriptRecord>,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct CompletedPreselectionAttempt {",
            &[
                "snapshot: RouteCandidateSnapshot,",
                "batch: BoundPreselectionTranscriptBatch,",
                "gate: CoolingPreselectionAttemptGate,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct PreselectionBeginFailure {",
            &[
                "gate: Option<Box<PreselectionAttemptGate>>,",
                "cooling_gate: Option<Box<CoolingPreselectionAttemptGate>>,",
                "error: PreselectionAttemptError,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) struct PreselectionAttemptFailure {",
            &[
                "gate: Option<CoolingPreselectionAttemptGate>,",
                "error: PreselectionAttemptError,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) enum PreselectionGateRecovery {",
            &[
                "Available(Box<PreselectionAttemptGate>),",
                "Cooling(Box<CoolingPreselectionAttemptGate>),",
                "Closed,",
            ],
        );
        assert_source_fields(
            product,
            "pub(super) enum PreselectionLocalRecovery {",
            &["Cooling(CoolingPreselectionAttemptGate),", "Closed,"],
        );
        assert_source_fields(
            product,
            "pub(super) enum PreselectionOwnerTransitionFailure {",
            &[
                "Retained(Box<DispatchedPreselectionAttempt>),",
                "Cooling(CoolingPreselectionAttemptGate),",
                "Closed,",
            ],
        );
    }

    fn assert_a1c_exact_fresh_join_fields(product: &str) {
        assert_source_fields(
            product,
            "pub(crate) struct PreselectionTransportFreshnessFacts {",
            &[
                "observed_network_prefix: ObservedNetworkPrefix,",
                "observed_at_ms: u64,",
                "round_trip: Duration,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct PreselectionFreshnessProofRecord {",
            &[
                "subject: usize,",
                "forwarded_control: Option<usize>,",
                "role: PreselectionObservationRole,",
                "transport: PreselectionTransportFreshnessFacts,",
                "transcript: PreselectionTranscriptFreshnessFacts,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct BoundPreselectionFreshnessProofBatch {",
            &[
                "transport: Transport,",
                "address_family: ObservationAddressFamily,",
                "batch_id: [u8; BATCH_ID_LENGTH],",
                "attempt_started_at_ms: u64,",
                "attempt_deadline_ms: u64,",
                "minimum_capacity: Bandwidth,",
                "preselection_capacity_ceiling: Bandwidth,",
                "records: Vec<PreselectionFreshnessProofRecord>,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct CompletedPreselectionFreshnessAttempt {",
            &[
                "snapshot: RouteCandidateSnapshot,",
                "batch: BoundPreselectionFreshnessProofBatch,",
                "gate: CoolingPreselectionAttemptGate,",
            ],
        );
        assert_source_fields(
            product,
            "pub(crate) struct PreselectionFreshnessJoinFailure {",
            &[
                "gate: CoolingPreselectionAttemptGate,",
                "error: PreselectionAttemptError,",
            ],
        );
        assert!(product.contains("pub(crate) enum PreselectionTranscriptFreshnessFacts {"));
        assert_eq!(
            product
                .matches("consume_bound_client_preselection_transport_for_freshness(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("consume_bound_direct_preselection_transcript_for_freshness(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("consume_bound_forwarded_preselection_transcript_for_freshness(")
                .count(),
            1
        );
    }

    fn assert_a1a_affine_surface(product: &str) {
        const DEAD_CODE_REASON: &str =
            "private affine A1 owner internals; only DiscoveryRuntime enters";
        const DEAD_CODE_ATTRIBUTE: &str = "#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = \"private affine A1 owner internals; only DiscoveryRuntime enters\"
    )
)]";
        assert_eq!(product.matches(DEAD_CODE_REASON).count(), 59);
        assert_eq!(product.matches(DEAD_CODE_ATTRIBUTE).count(), 59);
        assert!(product.matches("cfg_attr(").count() >= 62);
        assert!(product.matches("allow(\n        dead_code,").count() >= 62);
        assert!(!product.contains(&format!("{DEAD_CODE_ATTRIBUTE}\nmod ")));
        assert_eq!(
            product
                .split(|character: char| { !character.is_ascii_alphanumeric() && character != '_' })
                .filter(|token| *token == "mod")
                .count(),
            0
        );
        assert!(!product.contains("#![cfg_attr"));
        assert!(!product.contains("#![allow(dead_code"));
        assert!(!product.contains("#[allow(dead_code"));
        assert_eq!(product.matches("#[derive(").count(), 5);
        assert!(product.contains("#[derive(Clone, Copy)]\nenum PendingRequestKind"));
        for record in [
            "AttemptStart",
            "RequestPreparation<'a>",
            "RequestBinding<'a>",
        ] {
            assert!(product.contains(&format!("#[derive(Clone, Copy)]\nstruct {record} {{")));
        }
        assert!(product.contains(
            "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(super) enum PreselectionAttemptError"
        ));
        for forbidden in [
            "impl Clone for",
            "impl Copy for",
            "impl Debug for",
            "impl Default for",
            "impl Drop for",
            "impl Deref for",
            "impl DerefMut for",
            "impl AsRef<",
            "impl Borrow<",
            "Serialize",
            "Deserialize",
            "serde",
            "ManuallyDrop",
            "mem::forget",
            "decompose",
            "get_pending",
            "get_request",
        ] {
            assert!(!product.contains(forbidden), "affine escape: {forbidden}");
        }
        assert!(!product.contains("let RouteCandidateSnapshot {"));
        assert_eq!(
            product.matches("snapshot: RouteCandidateSnapshot,").count(),
            10
        );
        assert_eq!(
            product
                .matches("snapshot: &'a RouteCandidateSnapshot,")
                .count(),
            1
        );
        assert_eq!(product.matches("pub(super) struct ").count(), 9);
        assert_eq!(product.matches("pub(super) enum ").count(), 5);
        assert_eq!(product.matches("pub(super) fn ").count(), 13);
        assert_eq!(product.matches("pub(crate) struct ").count(), 7);
        assert_eq!(product.matches("pub(crate) enum ").count(), 1);
        assert_eq!(product.matches("pub(crate) fn ").count(), 6);
        assert!(product.matches("fn ").count() >= 66);
        assert!(!product.contains("\npub struct "));
        assert!(!product.contains("\npub enum "));
        assert!(!product.contains("\npub fn "));

        let gate_impl = product
            .split_once("impl PreselectionAttemptGate {")
            .unwrap()
            .1
            .split_once("impl CoolingPreselectionAttemptGate {")
            .unwrap()
            .0;
        assert_eq!(gate_impl.matches("fn ").count(), 7);
        for method in [
            "fn new(",
            "fn begin(",
            "fn begin_at(",
            "fn begin_at_with_entropy_for_test<",
            "fn begin_validated(",
            "fn begin_validated_with<",
            "fn admitted_failure(",
        ] {
            assert_eq!(gate_impl.matches(method).count(), 1, "gate method {method}");
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one source contract keeps the complete opaque owner transition boundary together"
    )]
    fn assert_owner_only_dispatch_transitions(product: &str) {
        assert_eq!(
            product
                .matches("ClientPreselectionObservationRequest::from_canonical(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("dispatch_preselection_observation_with_context(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("bind_preselection_observation_response_with_context(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("cancel_preselection_observation_transaction(")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches(".verify_response_from_exact_dispatch(response.as_encoded())")
                .count(),
            1
        );
        assert_eq!(
            product
                .matches("#[cfg(test)]\n    fn verify_response_at(")
                .count(),
            1
        );
        assert!(!product.contains("pub(super) struct ObservationDispatchId"));
        assert!(!product.contains("pub(super) fn verify_response"));
        assert!(!product.contains("dispatch_preselection_observation("));

        let pending_impl = product
            .split_once("impl PendingPreselectionAttempt {")
            .expect("pending owner implementation")
            .1
            .split_once("impl DispatchedPreselectionAttempt {")
            .expect("dispatched owner implementation")
            .0;
        let dispatch = pending_impl
            .split_once("pub(super) fn dispatch(")
            .expect("owner dispatch")
            .1
            .split_once("\n    fn verify_response_from_exact_dispatch(")
            .expect("owner dispatch end")
            .0;
        let dispatch_arguments = dispatch
            .split_once(") ->")
            .expect("owner dispatch arguments")
            .0;
        assert!(dispatch_arguments.contains("self,"));
        assert!(dispatch_arguments.contains("service: &mut DiscoveryService,"));
        for forbidden in [
            "request",
            "target",
            "peer",
            "family",
            "deadline",
            "dispatch_id",
            "Instant",
            "now_ms",
            "entropy",
        ] {
            assert!(
                !dispatch_arguments.contains(forbidden),
                "external owner dispatch input: {forbidden}"
            );
        }
        assert!(dispatch.contains(
            "Vec::from(\n            self.pending.expected_request.as_slice(),\n        )"
        ));
        assert!(dispatch.contains("let absolute_deadline = self.pending.expires_at_mono;"));
        assert!(dispatch.contains("request,\n            absolute_deadline,\n            self,"));

        let dispatched_impl = product
            .split_once("impl DispatchedPreselectionAttempt {")
            .expect("dispatched owner implementation")
            .1
            .split_once("\n}\n\nfn preselection_attempt_error(")
            .expect("dispatched owner implementation end")
            .0;
        assert_eq!(dispatched_impl.matches("pub(super) fn ").count(), 2);
        assert!(dispatched_impl.contains("self.transaction, arrival"));
        assert!(dispatched_impl.contains("transaction: *transaction,"));
        assert!(dispatched_impl.contains("failure.into_transaction()"));
        for forbidden in [
            "impl Clone",
            "impl Debug",
            "Serialize",
            "Deserialize",
            "fn request(",
            "fn target(",
            "fn deadline(",
            "fn dispatch_id(",
            "fn transaction(",
        ] {
            assert!(
                !dispatched_impl.contains(forbidden),
                "opaque dispatch escape: {forbidden}"
            );
        }
    }

    fn assert_a1a_bounds_entropy_and_no_producer(product: &str) {
        for exact in [
            "const BATCH_ID_LENGTH: usize = 16;",
            "const CHALLENGE_LENGTH: usize = 32;",
            "const MAXIMUM_REQUEST_BYTES: usize = 4 * 1024;",
            "const MAXIMUM_OTHER_RELAYS: usize = 8;",
            "const MINIMUM_REQUESTS: usize = 2;",
            "const MAXIMUM_REQUESTS: usize = 9;",
            "const MAXIMUM_ENVELOPES: usize = 10;",
            "const MAXIMUM_TOMBSTONES: usize = 36;",
            "const MAXIMUM_BATCH_TOMBSTONES: usize = 4;",
            "const REPLAY_CAPACITY: usize = 40;",
            "const REQUEST_LIFETIME_MS: u64 = 5_000;",
            "const ATTEMPT_LIFETIME_MS: u64 = 30_000;",
            "const TOMBSTONE_LIFETIME_MS: u64 = 120_000;",
            "const TOMBSTONE_LIFETIME: Duration = Duration::from_secs(120);",
            "const COOLDOWN_MS: u64 = 30_000;",
            "const COOLDOWN: Duration = Duration::from_secs(30);",
        ] {
            assert_eq!(product.matches(exact).count(), 1, "missing bound {exact}");
        }
        assert_eq!(product.matches("OsRng").count(), 3);
        assert_eq!(product.matches("try_fill_bytes").count(), 2);
        assert_eq!(product.matches("mint_attempt_entropy").count(), 2);
        assert_eq!(product.matches("begin_at_with_entropy_for_test").count(), 1);
        let test_seam_prefix = product
            .split_once("fn begin_at_with_entropy_for_test")
            .unwrap()
            .0
            .rsplit_once("\n\n")
            .unwrap()
            .1;
        assert!(test_seam_prefix.contains("#[cfg(test)]"));
        let public_begin = product
            .split_once("pub(super) fn begin(")
            .unwrap()
            .1
            .split_once(" {")
            .unwrap()
            .0;
        for forbidden in ["challenge", "entropy", "rng", "Instant", "now_ms"] {
            assert!(!public_begin.contains(forbidden));
        }

        for forbidden in [
            "send_request",
            "spawn(",
            "tokio::spawn",
            "async ",
            "JoinHandle",
            "dial(",
            ".dial",
            "sign_control_message",
            "SigningKey",
            "SecretKey",
            "ed25519_dalek",
            "volparossa_identity::Identity",
        ] {
            assert!(
                !product.contains(forbidden),
                "producer surface: {forbidden}"
            );
        }
    }

    fn assert_a1a_transcript_only(product: &str) {
        for call in [
            "verify_direct_preselection_transcript(",
            "verify_forwarded_preselection_transcript(",
            "consume_direct_preselection_transcript(",
            "consume_forwarded_preselection_transcript(",
        ] {
            assert_eq!(product.matches(call).count(), 1, "exact owner call {call}");
        }
        let final_batch = source_fields(
            product,
            "pub(super) struct BoundPreselectionTranscriptBatch {",
        )
        .join("\n");
        let final_record = source_fields(product, "struct BoundTranscriptRecord {").join("\n");
        for forbidden in [
            "verified_at",
            "terminal",
            "observed_at",
            "arrival",
            "rtt",
            "round_trip",
            "origin",
            "prefix",
            "endpoint",
            "ConnectionId",
            "OutboundRequestId",
            "socket",
            "FreshPeerEvidence",
            "FreshEvidenceBatch",
            "CandidateEvidence",
        ] {
            assert!(!final_batch.contains(forbidden));
            assert!(!final_record.contains(forbidden));
        }
        let transitive = [
            source_fields(product, "pub(super) struct PreselectionSubjectBinding {").join("\n"),
            source_fields(product, "pub(super) struct PreselectionSubjectSet {").join("\n"),
            source_fields(product, "struct ObservationDispatchId {").join("\n"),
            source_fields(product, "enum BoundTranscript {").join("\n"),
            final_batch,
            final_record,
        ]
        .join("\n");
        for forbidden in [
            "raw_address",
            "raw_origin",
            "IpAddr",
            "SocketAddr",
            "Multiaddr",
            "endpoint",
            "arrival",
            "rtt",
            "round_trip",
            "source_port",
            "remote_port",
            "listen_port",
            "hostname",
            "destination",
            "underlay",
            "wireguard",
            "history",
        ] {
            assert!(
                !transitive.contains(forbidden),
                "transitive leak: {forbidden}"
            );
        }
        for forbidden in [
            "ConnectionId",
            "OutboundRequestId",
            "Multiaddr",
            "SocketAddr",
            "IpAddr",
            "tokio::spawn",
            "mpsc::",
            "oneshot::",
            "request_response",
            "NetworkBehaviour",
            "RouteSessionAuthority",
            "ReservationSession",
            "FreshPeerEvidence",
            "FreshEvidenceBatch",
            "CandidateEvidence",
            "ObservationNetworkPrefix",
            "native_prefix",
        ] {
            assert!(
                !product.contains(forbidden),
                "premature A1c surface: {forbidden}"
            );
        }
    }

    fn assert_a1b0_hash_surface(product: &str, parent_product: &str) {
        let declaration = "pub(crate) struct AdvertisementPayloadHash([u8; 32]);";
        assert_eq!(parent_product.matches(declaration).count(), 1);
        assert_eq!(
            parent_product.matches("AdvertisementPayloadHash(").count(),
            2
        );
        assert_eq!(
            parent_product
                .matches(
                    "#[derive(Clone, Copy, Eq, Hash, PartialEq)]\n\
                     pub(crate) struct AdvertisementPayloadHash([u8; 32]);"
                )
                .count(),
            1
        );
        let token_doc =
            "/// Opaque identity of one freshly verified canonical advertisement payload.";
        let token_start = parent_product
            .find(token_doc)
            .expect("opaque hash documentation");
        assert_eq!(
            parent_product[..token_start]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::trim),
            Some("}")
        );
        let token_surface = parent_product[token_start..]
            .split_once(
                "#[derive(Clone, Debug, Eq, PartialEq)]\n\
                 pub(crate) struct DirectRelayCapability",
            )
            .expect("opaque hash surface end")
            .0;
        assert_a1b0_hash_token_surface(token_surface, parent_product);
        assert_a1b0_hash_minting_and_privacy(product, parent_product);
    }

    fn assert_a1b0_hash_token_surface(token_surface: &str, parent_product: &str) {
        assert_eq!(token_surface.matches("#[derive(").count(), 1);
        assert_eq!(
            token_surface
                .matches("#[derive(Clone, Copy, Eq, Hash, PartialEq)]")
                .count(),
            1
        );
        assert_eq!(token_surface.matches("#[cfg(test)]").count(), 2);
        assert_eq!(token_surface.matches("fn ").count(), 6);
        assert_eq!(
            token_surface
                .matches("impl AdvertisementPayloadHash {")
                .count(),
            1
        );
        assert_eq!(
            token_surface
                .matches(" for AdvertisementPayloadHash {")
                .count(),
            1
        );
        assert_eq!(
            parent_product
                .matches("impl AdvertisementPayloadHash {")
                .count(),
            1
        );
        assert_eq!(
            parent_product
                .matches(" for AdvertisementPayloadHash {")
                .count(),
            1
        );
        assert_eq!(
            token_surface.matches("fn from_fresh_fingerprint(").count(),
            1
        );
        assert_eq!(token_surface.matches("Self(value)").count(), 1);
        assert!(!token_surface.contains("pub(crate) fn from_fresh_fingerprint("));
        assert_eq!(
            token_surface
                .matches("pub(crate) fn append_native_probe_commitment(")
                .count(),
            1
        );
        assert_eq!(
            token_surface
                .matches("fn matches_native_probe_commitment(")
                .count(),
            1
        );
        assert!(!token_surface.contains("pub(crate) fn matches_native_probe_commitment("));
        assert_eq!(
            token_surface
                .matches("AdvertisementPayloadHash([REDACTED])")
                .count(),
            1
        );
        for forbidden in [
            "Serialize",
            "Deserialize",
            "Default",
            "Display",
            "LowerHex",
            "UpperHex",
            "cfg_attr",
            "impl Deref",
            "impl DerefMut",
            "impl AsRef",
            "impl Borrow",
            "impl From",
            "impl TryFrom",
            "fn as_bytes(",
            "fn into_bytes(",
            "fn into_inner(",
            "-> [u8; 32]",
        ] {
            assert!(
                !token_surface.contains(forbidden),
                "hash surface {forbidden}"
            );
        }
    }

    fn assert_a1b0_hash_minting_and_privacy(product: &str, parent_product: &str) {
        let fingerprint = parent_product
            .split_once("fn advertisement_fingerprint(")
            .expect("fingerprint function")
            .1
            .split_once("\nfn has_active_privacy_conflict(")
            .expect("fingerprint function end")
            .0;
        assert_eq!(
            fingerprint
                .matches("decode_canonical::<SignedEnvelope>(")
                .count(),
            1
        );
        assert_eq!(
            fingerprint
                .matches("AdvertisementPayloadHash::from_fresh_fingerprint(")
                .count(),
            1
        );
        assert_eq!(
            parent_product.matches("advertisement_fingerprint(").count(),
            4,
            "stored ingest, local Relay publication and revalidation are the only fingerprint consumers"
        );
        assert_eq!(
            parent_product
                .matches("AdvertisementPayloadHash::from_fresh_fingerprint(")
                .count(),
            1
        );

        for (start, end, expected_verify_count) in [
            (
                "fn commit_advertisement(",
                "\n    fn rollback_advertisement_replay(",
                2,
            ),
            (
                "pub(crate) fn revalidate_stored_advertisement(",
                "\nfn convert_advertisement(",
                1,
            ),
        ] {
            let owner = parent_product
                .split_once(start)
                .unwrap_or_else(|| panic!("missing hash owner {start}"))
                .1
                .split_once(end)
                .unwrap_or_else(|| panic!("missing hash owner end {end}"))
                .0;
            assert_eq!(
                owner
                    .matches("verify_control_message::<WireAdvertisement>(")
                    .count(),
                expected_verify_count
            );
            assert_eq!(owner.matches("advertisement_fingerprint(").count(), 1);
            assert!(
                owner.find("verify_control_message::<WireAdvertisement>(")
                    < owner.find("advertisement_fingerprint(")
            );
        }

        assert_eq!(product.matches(".0").count(), 1);
        assert_eq!(product.matches("advertisement_payload_hash.0").count(), 1);
        assert_eq!(
            product
                .matches("subject.advertisement_payload_hash.0.to_vec()")
                .count(),
            1
        );
        for source in [
            parent_product,
            include_str!("../route_setup.rs")
                .split_once("\n#[cfg(test)]\nmod tests {")
                .expect("route product")
                .0,
            include_str!("../route_setup/selection_bridge.rs")
                .split_once("\n#[cfg(test)]\nmod tests {")
                .expect("bridge product")
                .0,
        ] {
            assert_eq!(source.matches("advertisement_payload_hash.0").count(), 0);
        }
    }

    fn assert_hash_fields(source: &str, declaration: &str, expected: &[&str]) {
        let actual = source_fields(source, declaration)
            .into_iter()
            .filter(|field| field.contains("payload_hash:"))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "typed hash fields for {declaration}");
    }

    fn assert_a1b0_typed_hash_fields(product: &str, parent_product: &str) {
        assert_hash_fields(
            parent_product,
            "struct AdvertisementFingerprint {",
            &["payload_hash: AdvertisementPayloadHash,"],
        );
        assert_hash_fields(
            parent_product,
            "pub(crate) struct DirectRelayCapability {",
            &["pub(crate) advertisement_payload_hash: AdvertisementPayloadHash,"],
        );
        assert_hash_fields(
            parent_product,
            "pub(crate) struct ForwardedExitCapability {",
            &[
                "pub(crate) control_relay_advertisement_payload_hash: AdvertisementPayloadHash,",
                "pub(crate) exit_advertisement_payload_hash: AdvertisementPayloadHash,",
            ],
        );
        assert_hash_fields(
            parent_product,
            "pub(crate) struct RouteCandidateAdvertisement {",
            &["advertisement_payload_hash: AdvertisementPayloadHash,"],
        );
        assert_hash_fields(
            product,
            "pub(super) struct PreselectionSubjectBinding {",
            &["advertisement_payload_hash: AdvertisementPayloadHash,"],
        );

        let route = include_str!("../route_setup.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("route product")
            .0;
        assert_hash_fields(
            route,
            "struct ProspectivePeerIdentity {",
            &["advertisement_payload_hash: AdvertisementPayloadHash,"],
        );

        let bridge = include_str!("../route_setup/selection_bridge.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("bridge product")
            .0;
        for (declaration, expected) in [
            (
                "struct ForwardedControlBinding {",
                &["advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
            (
                "struct FreshPeerEvidence {",
                &["advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
            (
                "struct AuthenticatedSelectionAdvertisement {",
                &["advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
            (
                "struct SelectedExitBinding {",
                &[
                    "control_advertisement_payload_hash: AdvertisementPayloadHash,",
                    "advertisement_payload_hash: AdvertisementPayloadHash,",
                ][..],
            ),
            (
                "struct CompleteRelayPathEvidence {",
                &["relay_advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
            (
                "struct SnapshotRelayPathEvidence {",
                &["relay_advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
            (
                "struct VerifiedSelectionPeer<I> {",
                &["advertisement_payload_hash: AdvertisementPayloadHash,"][..],
            ),
        ] {
            assert_hash_fields(bridge, declaration, expected);
        }
        for source in [product, parent_product, route, bridge] {
            assert!(!source.contains("advertisement_payload_hash: [u8; 32]"));
            assert!(!source.contains("advertisement_payload_hash(&self) -> [u8; 32]"));
        }
        assert_eq!(
            parent_product
                .matches("const fn advertisement_payload_hash(&self) -> AdvertisementPayloadHash")
                .count(),
            1
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one source-contract audit keeps the complete actor ownership boundary together"
    )]
    fn assert_a1a_parent_snapshot_and_actor_ownership(product: &str) {
        let parent = include_str!("../discovery.rs");
        let parent_test_marker = "\n#[cfg(test)]\nmod tests {";
        assert_eq!(parent.matches(parent_test_marker).count(), 1);
        let parent_product = parent.split_once(parent_test_marker).unwrap().0;
        assert_a1b0_hash_surface(product, parent_product);
        assert_a1b0_typed_hash_fields(product, parent_product);
        assert_source_fields(
            parent_product,
            "pub(crate) struct RouteCandidateSnapshot {",
            &[
                "captured_at_ms: u64,",
                "policy: RouteCandidatePolicySnapshot,",
                "direct_relays: Vec<DirectRelayCandidateSnapshot>,",
                "forwarded_exits: Vec<ForwardedExitCandidateSnapshot>,",
                "preselection_subjects: preselection_observation::PreselectionSubjectSet,",
            ],
        );
        assert_eq!(
            parent_product
                .matches("callerless A1a prerequisite; no production caller")
                .count(),
            0
        );
        let snapshot_item = parent_product
            .split_once("/// Bounded, actor-linearized input to route-selection preflight.")
            .unwrap()
            .1
            .split_once("impl RouteCandidateSnapshot {")
            .unwrap()
            .0;
        assert!(!snapshot_item.contains("#[derive("));
        let snapshot_impl = parent_product
            .split_once("impl RouteCandidateSnapshot {")
            .unwrap()
            .1
            .split_once("\n}\n\n#[cfg(test)]\nimpl RouteCandidatePolicySnapshot")
            .unwrap()
            .0;
        assert_eq!(snapshot_impl.matches("fn ").count(), 5);
        for method in [
            "fn captured_at_ms(",
            "fn policy(",
            "fn direct_relays(",
            "fn forwarded_exits(",
            "fn for_test(",
        ] {
            assert_eq!(
                snapshot_impl.matches(method).count(),
                1,
                "snapshot method {method}"
            );
        }
        assert_eq!(
            parent_product
                .matches("PreselectionSubjectSet::from_snapshot(")
                .count(),
            1
        );
        assert!(!parent_product.contains("fn preselection_subject"));
        let outside_actor = [
            include_str!("../advertisement.rs"),
            include_str!("../route_setup.rs"),
            include_str!("../route_setup/selection_bridge.rs"),
            include_str!("../route_setup/retirement.rs"),
            include_str!("../control.rs"),
            include_str!("../endpoint_leases.rs"),
            include_str!("../helper_v3.rs"),
            include_str!("../lib.rs"),
            include_str!("../main.rs"),
            include_str!("../paths.rs"),
            include_str!("../policy.rs"),
            include_str!("../roles.rs"),
            include_str!("../secret.rs"),
            include_str!("../state.rs"),
        ]
        .concat();
        for symbol in [
            "PreselectionAttemptGate",
            "PendingPreselectionAttempt",
            "DispatchedPreselectionAttempt",
            "ReadyPreselectionAttempt",
            "BoundPreselectionTranscriptBatch",
            "PreselectionResponseOutcome",
            "PreselectionOwnerTransitionFailure",
            "PreselectionLocalRecovery",
        ] {
            assert_eq!(
                outside_actor
                    .split(|character: char| {
                        !character.is_ascii_alphanumeric() && character != '_'
                    })
                    .filter(|token| *token == symbol)
                    .count(),
                0,
                "non-actor caller {symbol}"
            );
        }
        for symbol in [
            "PendingPreselectionAttempt",
            "ReadyPreselectionAttempt",
            "BoundPreselectionTranscriptBatch",
        ] {
            assert_eq!(
                parent_product
                    .split(|character: char| {
                        !character.is_ascii_alphanumeric() && character != '_'
                    })
                    .filter(|token| *token == symbol)
                    .count(),
                0,
                "actor escape {symbol}"
            );
        }
        assert!(parent_product.contains("enum ClientPreselectionOwner {"));
        assert!(parent_product.contains("dispatch: DispatchedPreselectionAttempt,"));
        assert!(
            parent_product.contains("match dispatch.bind_response(&mut self.service, arrival)")
        );
        assert!(parent_product.contains("match pending.dispatch(&mut self.service)"));
        assert!(parent_product.contains("completed.join_transport_proofs(transports)"));
        assert!(!parent_product.contains("pub struct ClientPreselectionOwner"));
        for forbidden in [
            "fn preselection_target(",
            "fn preselection_peer(",
            "fn preselection_endpoint(",
            "fn preselection_dispatch_id(",
            "fn preselection_authority(",
        ] {
            assert!(
                !parent_product.contains(forbidden),
                "actor escape {forbidden}"
            );
        }
    }

    #[test]
    fn a1a_a1c_product_surface_is_affine_bounded_actor_owned_and_exactly_joined() {
        let source = include_str!("preselection_observation.rs");
        let test_marker = "\n#[cfg(test)]\nmod tests {";
        assert_eq!(source.matches(test_marker).count(), 1);
        let product = source.split_once(test_marker).unwrap().0;
        assert_a1a_subject_and_transcript_fields(product);
        assert_a1a_pending_owner_fields(product);
        assert_a1a_terminal_owner_fields(product);
        assert_a1c_exact_fresh_join_fields(product);
        assert_a1a_affine_surface(product);
        assert_owner_only_dispatch_transitions(product);
        assert_a1a_bounds_entropy_and_no_producer(product);
        assert_a1a_transcript_only(product);
        assert_a1a_parent_snapshot_and_actor_ownership(product);
    }
}
