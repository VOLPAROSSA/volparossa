//! Private affine owner for endpoint-separated native-preselection attempts.
//!
//! This child consumes one exact A1 handoff while its five-second signed receipts are still
//! live, then discards every control-plane reachability observation. It retains only immutable
//! actor, policy, transport, family and configured-capacity commitments plus the opaque original
//! snapshot. The newly minted authority is independently bounded to five minutes. Nothing in
//! this module marks a network address usable or advances route selection.

use std::{
    collections::{HashSet, VecDeque},
    str::FromStr,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use libp2p::{PeerId as Libp2pPeerId, identity};
use rand_core::{CryptoRng, OsRng, RngCore};
use thiserror::Error;
use tokio::time::Instant;
use zeroize::Zeroizing;

use volparossa_core::{Bandwidth, IpFamily, ServiceRole, Transport as SelectionTransport};
use volparossa_discovery::{
    DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse, ExitForwardOperation,
    ExitForwardRequest, ExitForwardResponse, ForwardStatus,
};
use volparossa_protocol::{
    IssuedNativeProbeStart, MAX_NATIVE_PROBE_CANDIDATES, MAX_NATIVE_PROBE_LIFETIME_MS,
    MAX_NATIVE_PROBE_PATHS, MIN_NATIVE_PROBE_CANDIDATES, NativeProbeCandidateSet,
    NativeProbeEndpointBinding, NativeProbeLeaseProof, NativeProbePathScope,
    NativeProbePermitRequest, PreselectionActorBinding, ProtocolError, ReplayCache, TimePolicy,
    VerifiedNativeProbePermit, VerifiedNativeProbeRelayReady, VerifiedNativeProbeResult,
    native_probe_candidate_set_hash, native_probe_challenge_hash, node_id_from_public_key,
    sign_control_message, sign_native_probe_start, verify_native_probe_permit,
    verify_native_probe_relay_ready, verify_native_probe_result,
};

use super::{
    FreshEvidenceBatch, FreshPeerEvidence, PreparedPreselectionEvidence, RouteCandidateSnapshot,
    SelectionBridgeError, evidence_batch_matches_snapshot, protocol_transport,
};
use crate::discovery::{DiscoveryControlHandle, OutboundReservationError};

const ID_BYTES: usize = 16;
const KEY_BYTES: usize = 32;

fn authorization_request_id(mut start_request_id: [u8; ID_BYTES]) -> [u8; ID_BYTES] {
    start_request_id[0] ^= 0x80;
    if start_request_id.iter().all(|byte| *byte == 0) {
        start_request_id[ID_BYTES - 1] = 1;
    }
    start_request_id
}
const ENTROPY_ATTEMPTS: usize = 8;

fn native_operation_deadline(
    authority_expires_at_ms: u64,
    now_ms: u64,
) -> Result<u64, NativePreselectionError> {
    let deadline_unix_ms = now_ms
        .saturating_add(crate::discovery::MAX_FORWARD_OPERATION_LIFETIME_MS)
        .min(authority_expires_at_ms);
    if deadline_unix_ms <= now_ms {
        return Err(NativePreselectionError::InvalidDeadline);
    }
    Ok(deadline_unix_ms)
}

/// Failure to consume A1 evidence or advance one cryptographic native-probe phase.
#[derive(Debug, Error)]
pub(crate) enum NativePreselectionError {
    #[error("prepared A1 evidence is invalid or no longer fresh")]
    InvalidPreparedEvidence,
    #[error("native-preselection actor or exact candidate-set binding is invalid")]
    InvalidCandidateSet,
    #[error("native-preselection attempt deadline is invalid or expired")]
    InvalidDeadline,
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
    #[error("native-preselection protocol rejected the transition: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("native Permit forwarding wrapper is invalid")]
    InvalidPermitForwarding,
    #[error("native Permit forwarding transport is unavailable")]
    PermitTransportUnavailable,
    #[error("the selected Exit rejected the native Permit")]
    PermitRejected,
    #[error("the selected Exit is unavailable for native Permit")]
    PermitUnavailable,
    #[error("native data-Relay dispatch wrapper or response is invalid")]
    InvalidRelayDispatch,
    #[error("native data-Relay transport is unavailable")]
    RelayTransportUnavailable,
    #[error("the selected data Relay rejected the native phase")]
    RelayRejected,
    #[error("the selected data Relay is unavailable for the native phase")]
    RelayUnavailable,
}

/// Affine owner of one exact snapshot and every not-yet-dispatched path authority.
#[must_use = "native-preselection attempt ownership must remain affine"]
pub(super) struct NativePreselectionAttemptOwner {
    _snapshot: RouteCandidateSnapshot,
    candidate_set: NativeProbeCandidateSet,
    deadline: NativeAttemptDeadline,
    pending: VecDeque<PendingNativeProbeAuthority>,
}

/// One not-yet-dispatched path authority minted only by the attempt owner.
#[must_use = "pending native-probe authority must be consumed or dropped"]
pub(super) struct PendingNativeProbeAuthority {
    signed_request: Vec<u8>,
    session_key: SigningKey,
    challenge: Zeroizing<[u8; KEY_BYTES]>,
    start_nonce: [u8; KEY_BYTES],
    candidate: NativeCandidateTemplate,
    deadline: NativeAttemptDeadline,
}

/// Exact signed request awaiting one endpoint-free Exit permit.
#[must_use = "an issued permit request must be verified or dropped"]
pub(super) struct AwaitingNativePermit {
    signed_request: Vec<u8>,
    session_key: SigningKey,
    challenge: Zeroizing<[u8; KEY_BYTES]>,
    start_nonce: [u8; KEY_BYTES],
    candidate: NativeCandidateTemplate,
    deadline: NativeAttemptDeadline,
}

/// Affine client-hop dispatch through the exact selected control Relay.
#[must_use = "a native Permit dispatch must be executed or dropped"]
pub(super) struct NativePermitForwardDispatch {
    awaiting: AwaitingNativePermit,
    control_relay_peer: Libp2pPeerId,
    request: ExitForwardRequest,
}

/// Verified Exit permit awaiting client-visible readiness from the exact data Relay.
#[must_use = "a verified native permit must remain bound to its exact Relay"]
pub(super) struct AwaitingNativeRelayReady {
    verified_permit: VerifiedNativeProbePermit,
    relay_request: Vec<u8>,
    relay_permit: Vec<u8>,
    session_key: SigningKey,
    challenge: Zeroizing<[u8; KEY_BYTES]>,
    start_nonce: [u8; KEY_BYTES],
    candidate: NativeCandidateTemplate,
    deadline: NativeAttemptDeadline,
}

/// Affine Ready dispatch addressed only to the exact selected data Relay.
#[must_use = "a native Relay Ready dispatch must be executed or dropped"]
pub(super) struct NativeRelayReadyDispatch {
    awaiting: AwaitingNativeRelayReady,
    relay_peer: Libp2pPeerId,
    request: DatapathRelayRequest,
}

/// Relay readiness verified and waiting only for a local helper-prepared Client endpoint.
#[must_use = "an armed native probe must be started once or dropped"]
pub(super) struct ArmedNativeProbe {
    relay_ready: VerifiedNativeProbeRelayReady,
    session_key: SigningKey,
    challenge: Zeroizing<[u8; KEY_BYTES]>,
    start_nonce: [u8; KEY_BYTES],
    candidate: NativeCandidateTemplate,
    deadline: NativeAttemptDeadline,
}

/// Exact signed start and raw one-shot challenge awaiting local and remote helper results.
#[must_use = "an in-flight native probe result must be verified or dropped"]
pub(super) struct AwaitingNativeResult {
    issued_start: IssuedNativeProbeStart,
    challenge: Zeroizing<[u8; KEY_BYTES]>,
    candidate: NativeCandidateTemplate,
    deadline: NativeAttemptDeadline,
    response_deadline_ms: u64,
}

/// Affine Start dispatch addressed only to the data Relay that minted readiness.
#[must_use = "a native Relay Start dispatch must be executed or dropped"]
pub(super) struct NativeRelayStartDispatch {
    awaiting: AwaitingNativeResult,
    relay_peer: Libp2pPeerId,
    request: DatapathRelayRequest,
}

/// Pre-activation authorization dispatch addressed only to the readiness-signing data Relay.
#[must_use = "a native Relay authorization dispatch must be executed or dropped"]
pub(super) struct NativeRelayAuthorizationDispatch {
    awaiting: AwaitingNativeResult,
    relay_peer: Libp2pPeerId,
    request: DatapathRelayRequest,
}

/// Terminal exact cryptographic chain; deliberately not route-admission or usability evidence.
#[must_use = "a bound native path proof grants no route until a later provider validates it"]
pub(super) struct BoundNativePathProof {
    verified_result: VerifiedNativeProbeResult,
    candidate: NativeCandidateTemplate,
}

struct NativeCandidateProjection {
    actor: PreselectionActorBinding,
    role: ServiceRole,
    transport: SelectionTransport,
    address_family: IpFamily,
    policy_version: u64,
    policy_hash: [u8; KEY_BYTES],
    policy_expires_at_ms: u64,
    preselection_capacity_ceiling: Bandwidth,
}

struct NativeCandidateTemplate {
    candidate_ordinal: u32,
    data_relay: PreselectionActorBinding,
    control: PreselectionActorBinding,
    exit: PreselectionActorBinding,
    forward_id: [u8; ID_BYTES],
    probe_id: [u8; ID_BYTES],
    start_request_id: [u8; ID_BYTES],
    preselection_capacity_ceiling: Bandwidth,
}

struct NativeAttemptInputs {
    snapshot: RouteCandidateSnapshot,
    candidate_set: NativeProbeCandidateSet,
    relays: Vec<NativeCandidateProjection>,
    exit: NativeCandidateProjection,
    forwarding_authority_expires_at_ms: u64,
}

/// Exact selected data-Relay identity and order supplied by route planning.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct NativeDataRelayIdentity {
    node_id: [u8; KEY_BYTES],
    peer_id: Vec<u8>,
}

impl NativeDataRelayIdentity {
    /// Construct one selected identity from already authenticated plan material.
    pub(super) fn new(
        node_id: [u8; KEY_BYTES],
        peer_id: Vec<u8>,
    ) -> Result<Self, NativePreselectionError> {
        if node_id == [0; KEY_BYTES]
            || peer_id.is_empty()
            || Libp2pPeerId::from_bytes(&peer_id).is_err()
        {
            return Err(NativePreselectionError::InvalidCandidateSet);
        }
        Ok(Self { node_id, peer_id })
    }
}

#[derive(Clone, Copy)]
struct NativeAttemptDeadline {
    created_at_ms: u64,
    expires_at_ms: u64,
    monotonic_expires_at: Instant,
}

impl NativeAttemptDeadline {
    fn ensure_live(
        self,
        trusted_now_ms: u64,
        trusted_now: Instant,
    ) -> Result<(), NativePreselectionError> {
        if trusted_now_ms < self.created_at_ms
            || trusted_now_ms >= self.expires_at_ms
            || trusted_now >= self.monotonic_expires_at
        {
            return Err(NativePreselectionError::InvalidDeadline);
        }
        Ok(())
    }
}

/// Consume one opaque A1 handoff and mint a fresh, independently expiring sampler owner.
pub(super) fn begin_native_preselection(
    prepared: PreparedPreselectionEvidence,
    selected_data_relays: &[NativeDataRelayIdentity],
    reserved_capacity: Bandwidth,
) -> Result<NativePreselectionAttemptOwner, NativePreselectionError> {
    begin_native_preselection_at(
        prepared,
        selected_data_relays,
        reserved_capacity,
        crate::unix_millis(),
        Instant::now(),
        &mut OsRng,
    )
}

fn begin_native_preselection_at<R>(
    prepared: PreparedPreselectionEvidence,
    selected_data_relays: &[NativeDataRelayIdentity],
    reserved_capacity: Bandwidth,
    trusted_now_ms: u64,
    trusted_now: Instant,
    rng: &mut R,
) -> Result<NativePreselectionAttemptOwner, NativePreselectionError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    let NativeAttemptInputs {
        snapshot,
        candidate_set,
        relays,
        exit,
        forwarding_authority_expires_at_ms,
    } = consume_prepared_handoff(prepared, selected_data_relays, trusted_now_ms)?;
    let required_path_count = selected_data_relays.len();
    if !(1..=MAX_NATIVE_PROBE_PATHS).contains(&required_path_count)
        || required_path_count > relays.len()
        || reserved_capacity.validate().is_err()
        || reserved_capacity.up_mbps == 0
        || reserved_capacity.down_mbps == 0
        || !exit
            .preselection_capacity_ceiling
            .satisfies(reserved_capacity)
        || relays.iter().take(required_path_count).any(|relay| {
            !relay
                .preselection_capacity_ceiling
                .satisfies(reserved_capacity)
        })
        || matches!(
            volparossa_protocol::Transport::try_from(candidate_set.transport),
            Ok(volparossa_protocol::Transport::UdpSinglePath) if required_path_count != 1
        )
        || matches!(
            volparossa_protocol::Transport::try_from(candidate_set.transport),
            Ok(
                volparossa_protocol::Transport::TcpMptcp
                    | volparossa_protocol::Transport::MultipathQuic
            ) if required_path_count < 2
        )
    {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    let deadline = native_attempt_deadline(
        &candidate_set,
        forwarding_authority_expires_at_ms,
        trusted_now_ms,
        trusted_now,
    )?;
    let pending = mint_path_authorities(
        &candidate_set,
        relays,
        &exit,
        required_path_count,
        reserved_capacity,
        deadline,
        rng,
    )?;
    Ok(NativePreselectionAttemptOwner {
        _snapshot: snapshot,
        candidate_set,
        deadline,
        pending,
    })
}

fn consume_prepared_handoff(
    prepared: PreparedPreselectionEvidence,
    selected_data_relays: &[NativeDataRelayIdentity],
    trusted_now_ms: u64,
) -> Result<NativeAttemptInputs, NativePreselectionError> {
    let PreparedPreselectionEvidence {
        snapshot,
        evidence_batch,
    } = prepared;
    evidence_batch
        .validate_at(trusted_now_ms)
        .map_err(invalid_prepared)?;
    if snapshot.captured_at_ms() > trusted_now_ms
        || !evidence_batch_matches_snapshot(&snapshot, &evidence_batch.entries)
    {
        return Err(NativePreselectionError::InvalidPreparedEvidence);
    }
    let [forwarded_exit] = snapshot.forwarded_exits() else {
        return Err(NativePreselectionError::InvalidPreparedEvidence);
    };
    let forwarding_authority_expires_at_ms = forwarded_exit.capability().expires_at_ms;
    let FreshEvidenceBatch {
        batch_id,
        mut entries,
    } = evidence_batch;
    let exit_index = unique_role_index(&entries, ServiceRole::Exit)?;
    let exit = entries.remove(exit_index);
    let control_binding = exit
        .forwarded_control
        .as_ref()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    let control_index = unique_control_index(&entries, control_binding)?;
    let control = entries.remove(control_index);
    if !(MIN_NATIVE_PROBE_CANDIDATES..=MAX_NATIVE_PROBE_CANDIDATES).contains(&entries.len())
        || entries
            .iter()
            .any(|candidate| candidate.role != ServiceRole::Relay)
    {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }

    let exit = project_candidate(exit)?;
    let control = project_candidate(control)?;
    let mut available_relays = entries
        .into_iter()
        .map(project_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    if !(MIN_NATIVE_PROBE_CANDIDATES..=MAX_NATIVE_PROBE_CANDIDATES)
        .contains(&selected_data_relays.len())
        || selected_data_relays.iter().collect::<HashSet<_>>().len() != selected_data_relays.len()
    {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    let mut relays = Vec::with_capacity(selected_data_relays.len());
    for selected in selected_data_relays {
        let Some(index) = available_relays.iter().position(|candidate| {
            candidate.actor.node_id.as_slice() == selected.node_id
                && candidate.actor.peer_id == selected.peer_id
        }) else {
            return Err(NativePreselectionError::InvalidCandidateSet);
        };
        relays.push(available_relays.remove(index));
    }
    validate_shared_scope(&snapshot, &control, &relays, &exit)?;

    let policy = snapshot.policy();
    let candidate_set = NativeProbeCandidateSet {
        protocol_version: volparossa_protocol::PROTOCOL_VERSION,
        preselection_batch_id: batch_id.0.to_vec(),
        control: Some(control.actor.clone()),
        exit: Some(exit.actor.clone()),
        data_relays: relays
            .iter()
            .map(|candidate| candidate.actor.clone())
            .collect(),
        transport: protocol_transport(relays[0].transport) as i32,
        address_family: protocol_family(relays[0].address_family) as i32,
        policy_version: policy.version(),
        policy_hash: policy.hash().to_vec(),
        policy_expires_at_ms: policy.expires_at_ms(),
    };
    candidate_set.validate()?;
    Ok(NativeAttemptInputs {
        snapshot,
        candidate_set,
        relays,
        exit,
        forwarding_authority_expires_at_ms,
    })
}

fn native_attempt_deadline(
    candidate_set: &NativeProbeCandidateSet,
    forwarding_authority_expires_at_ms: u64,
    trusted_now_ms: u64,
    trusted_now: Instant,
) -> Result<NativeAttemptDeadline, NativePreselectionError> {
    let actor_expiry = candidate_set
        .data_relays
        .iter()
        .chain(candidate_set.exit.iter())
        .map(actor_expiry)
        .min()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    let expires_at_ms = trusted_now_ms
        .checked_add(MAX_NATIVE_PROBE_LIFETIME_MS)
        .ok_or(NativePreselectionError::InvalidDeadline)?
        .min(candidate_set.policy_expires_at_ms)
        .min(actor_expiry)
        .min(forwarding_authority_expires_at_ms);
    let lifetime_ms = expires_at_ms
        .checked_sub(trusted_now_ms)
        .filter(|lifetime| *lifetime != 0)
        .ok_or(NativePreselectionError::InvalidDeadline)?;
    let monotonic_expires_at = trusted_now
        .checked_add(Duration::from_millis(lifetime_ms))
        .ok_or(NativePreselectionError::InvalidDeadline)?;
    Ok(NativeAttemptDeadline {
        created_at_ms: trusted_now_ms,
        expires_at_ms,
        monotonic_expires_at,
    })
}

fn mint_path_authorities<R>(
    candidate_set: &NativeProbeCandidateSet,
    relays: Vec<NativeCandidateProjection>,
    exit: &NativeCandidateProjection,
    required_path_count: usize,
    reserved_capacity: Bandwidth,
    deadline: NativeAttemptDeadline,
    rng: &mut R,
) -> Result<VecDeque<PendingNativeProbeAuthority>, NativePreselectionError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    let candidate_set_hash = native_probe_candidate_set_hash(candidate_set)?;
    let attempt_id = random_nonzero::<ID_BYTES, _>(rng)?;
    let mut probe_ids = HashSet::with_capacity(relays.len());
    let mut challenges = HashSet::with_capacity(relays.len());
    let mut pending = VecDeque::with_capacity(relays.len());
    for (index, relay) in relays.into_iter().take(required_path_count).enumerate() {
        let candidate_ordinal =
            u32::try_from(index + 1).map_err(|_| NativePreselectionError::InvalidCandidateSet)?;
        let probe_id = unique_random::<ID_BYTES, _>(rng, &mut probe_ids)?;
        let challenge = unique_random::<KEY_BYTES, _>(rng, &mut challenges)?;
        let session_seed = Zeroizing::new(random_nonzero::<KEY_BYTES, _>(rng)?);
        let session_key = SigningKey::from_bytes(&session_seed);
        let session_public_key = session_key.verifying_key().to_bytes();
        let request_nonce = random_nonzero::<KEY_BYTES, _>(rng)?;
        let start_nonce = random_nonzero::<KEY_BYTES, _>(rng)?;
        let scope = NativeProbePathScope {
            attempt_id: attempt_id.to_vec(),
            probe_id: probe_id.to_vec(),
            candidate_set_hash: candidate_set_hash.to_vec(),
            candidate_ordinal,
            data_relay: Some(relay.actor.clone()),
            control: candidate_set.control.clone(),
            exit: candidate_set.exit.clone(),
            client_session_id: node_id_from_public_key(&session_public_key).to_vec(),
            client_session_public_key: session_public_key.to_vec(),
            transport: candidate_set.transport,
            address_family: candidate_set.address_family,
            policy_version: candidate_set.policy_version,
            policy_hash: candidate_set.policy_hash.clone(),
            policy_expires_at_ms: candidate_set.policy_expires_at_ms,
            challenge_hash: native_probe_challenge_hash(&challenge).to_vec(),
            attempt_expires_at_ms: deadline.expires_at_ms,
            required_path_count: u32::try_from(required_path_count)
                .map_err(|_| NativePreselectionError::InvalidCandidateSet)?,
            reserved_up_mbps: u64::from(reserved_capacity.up_mbps),
            reserved_down_mbps: u64::from(reserved_capacity.down_mbps),
        };
        let request = NativeProbePermitRequest {
            scope: Some(scope),
            created_at_ms: deadline.created_at_ms,
            expires_at_ms: deadline.expires_at_ms,
            nonce: request_nonce.to_vec(),
        };
        let signed_request = sign_control_message(
            &request,
            &session_key,
            deadline.created_at_ms,
            deadline.expires_at_ms,
            request_nonce,
            native_time_policy(),
        )?;
        pending.push_back(PendingNativeProbeAuthority {
            signed_request,
            session_key,
            challenge: Zeroizing::new(challenge),
            start_nonce,
            candidate: NativeCandidateTemplate {
                candidate_ordinal,
                data_relay: relay.actor,
                control: candidate_set
                    .control
                    .clone()
                    .ok_or(NativePreselectionError::InvalidCandidateSet)?,
                exit: exit.actor.clone(),
                forward_id: request_nonce[..ID_BYTES]
                    .try_into()
                    .map_err(|_| NativePreselectionError::InvalidCandidateSet)?,
                probe_id,
                start_request_id: start_nonce[..ID_BYTES]
                    .try_into()
                    .map_err(|_| NativePreselectionError::InvalidCandidateSet)?,
                preselection_capacity_ceiling: relay
                    .preselection_capacity_ceiling
                    .component_min(exit.preselection_capacity_ceiling),
            },
            deadline,
        });
    }
    if pending.len() != required_path_count {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    Ok(pending)
}

#[cfg(test)]
pub(super) fn begin_native_preselection_for_test(
    prepared: PreparedPreselectionEvidence,
    required_path_count: usize,
    reserved_capacity: Bandwidth,
    trusted_now_ms: u64,
    trusted_now: Instant,
) -> Result<NativePreselectionAttemptOwner, NativePreselectionError> {
    let selected = selected_data_relay_identities(&prepared, required_path_count)?;
    begin_native_preselection_at(
        prepared,
        &selected,
        reserved_capacity,
        trusted_now_ms,
        trusted_now,
        &mut OsRng,
    )
}

#[cfg(test)]
/// Project a deterministic exact subset for native-preselection unit fixtures.
pub(super) fn selected_data_relay_identities(
    prepared: &PreparedPreselectionEvidence,
    selected_count: usize,
) -> Result<Vec<NativeDataRelayIdentity>, NativePreselectionError> {
    if !(MIN_NATIVE_PROBE_CANDIDATES..=MAX_NATIVE_PROBE_CANDIDATES).contains(&selected_count) {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    let exit = prepared
        .evidence_batch
        .entries
        .iter()
        .find(|entry| entry.role == ServiceRole::Exit)
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    let control = exit
        .forwarded_control
        .as_ref()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    let mut selected = Vec::with_capacity(selected_count);
    for candidate in prepared.evidence_batch.entries.iter().filter(|entry| {
        entry.role == ServiceRole::Relay
            && (entry.node_id != control.node_id || entry.peer_id != control.peer_id)
    }) {
        let peer = Libp2pPeerId::from_str(candidate.peer_id.as_str())
            .map_err(|_| NativePreselectionError::InvalidCandidateSet)?;
        selected.push(NativeDataRelayIdentity::new(
            node_id_from_public_key(&candidate.capability_public_key),
            peer.to_bytes(),
        )?);
        if selected.len() == selected_count {
            break;
        }
    }
    if selected.len() != selected_count
        || selected.iter().collect::<HashSet<_>>().len() != selected.len()
    {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    Ok(selected)
}

impl NativePreselectionAttemptOwner {
    /// Exact native candidate-set cardinality retained across affine path dispatches.
    pub(super) fn candidate_count(&self) -> usize {
        self.candidate_set
            .data_relays
            .len()
            .min(MAX_NATIVE_PROBE_PATHS)
    }

    /// Remove and begin exactly one pending path, preserving all remaining ownership locally.
    pub(super) fn begin_next(
        &mut self,
    ) -> Result<Option<AwaitingNativePermit>, NativePreselectionError> {
        self.begin_next_at(crate::unix_millis(), Instant::now())
    }

    fn begin_next_at(
        &mut self,
        trusted_now_ms: u64,
        trusted_now: Instant,
    ) -> Result<Option<AwaitingNativePermit>, NativePreselectionError> {
        self.deadline.ensure_live(trusted_now_ms, trusted_now)?;
        Ok(self
            .pending
            .pop_front()
            .map(PendingNativeProbeAuthority::begin))
    }

    #[cfg(test)]
    pub(super) fn begin_next_for_test(
        &mut self,
        trusted_now_ms: u64,
        trusted_now: Instant,
    ) -> Result<Option<AwaitingNativePermit>, NativePreselectionError> {
        self.begin_next_at(trusted_now_ms, trusted_now)
    }

    #[cfg(test)]
    pub(super) fn candidate_set_for_test(&self) -> &NativeProbeCandidateSet {
        &self.candidate_set
    }

    #[cfg(test)]
    pub(super) fn deadline_for_test(&self) -> (u64, Instant) {
        (
            self.deadline.expires_at_ms,
            self.deadline.monotonic_expires_at,
        )
    }

    #[cfg(test)]
    pub(super) fn pending_for_test(&self) -> &VecDeque<PendingNativeProbeAuthority> {
        &self.pending
    }
}

impl BoundNativePathProof {
    /// Borrow the exact data-Relay actor whose terminal proof was verified.
    pub(super) fn data_relay(&self) -> &PreselectionActorBinding {
        &self.candidate.data_relay
    }

    /// Borrow the exact control Relay retained by the verified terminal chain.
    pub(super) fn control(&self) -> &PreselectionActorBinding {
        &self.candidate.control
    }

    /// Borrow the exact Exit retained by the verified terminal chain.
    pub(super) fn exit(&self) -> &PreselectionActorBinding {
        &self.candidate.exit
    }

    /// Borrow the exact Client helper incarnation committed into the signed terminal chain.
    pub(super) fn client_helper_runtime_id(&self) -> &[u8; KEY_BYTES] {
        self.verified_result.client_helper_runtime_id()
    }

    /// Copy the exact Exit helper incarnation together with its signed attempt correlation.
    pub(super) fn exit_helper_runtime_id(&self) -> super::VerifiedExitHelperRuntimeId {
        let scope = self.verified_result.scope();
        super::VerifiedExitHelperRuntimeId::new(
            *self.verified_result.exit_helper_runtime_id(),
            scope
                .attempt_id
                .as_slice()
                .try_into()
                .expect("verified native scope has one attempt identifier"),
            scope
                .candidate_set_hash
                .as_slice()
                .try_into()
                .expect("verified native scope has one candidate-set digest"),
        )
    }
}

impl PendingNativeProbeAuthority {
    fn begin(self) -> AwaitingNativePermit {
        AwaitingNativePermit {
            signed_request: self.signed_request,
            session_key: self.session_key,
            challenge: self.challenge,
            start_nonce: self.start_nonce,
            candidate: self.candidate,
            deadline: self.deadline,
        }
    }

    #[cfg(test)]
    pub(super) fn candidate_for_test(
        &self,
    ) -> (
        u32,
        &PreselectionActorBinding,
        &PreselectionActorBinding,
        Bandwidth,
        &[u8],
    ) {
        (
            self.candidate.candidate_ordinal,
            &self.candidate.data_relay,
            &self.candidate.exit,
            self.candidate.preselection_capacity_ceiling,
            &self.signed_request,
        )
    }
}

impl AwaitingNativePermit {
    /// Borrow the endpoint-free request for dispatch through the exact control Relay.
    pub(super) fn encoded_request(&self) -> &[u8] {
        &self.signed_request
    }

    /// Consume this exact request into a wrapper addressed only to its selected control Relay.
    pub(super) fn into_forward_dispatch(
        self,
    ) -> Result<NativePermitForwardDispatch, NativePreselectionError> {
        self.into_forward_dispatch_at(crate::unix_millis())
    }

    fn into_forward_dispatch_at(
        self,
        now_ms: u64,
    ) -> Result<NativePermitForwardDispatch, NativePreselectionError> {
        let control_relay_peer = Libp2pPeerId::from_bytes(&self.candidate.control.peer_id)
            .map_err(|_| NativePreselectionError::InvalidPermitForwarding)?;
        let exit_peer = Libp2pPeerId::from_bytes(&self.candidate.exit.peer_id)
            .map_err(|_| NativePreselectionError::InvalidPermitForwarding)?;
        let operation_deadline_ms = native_operation_deadline(self.deadline.expires_at_ms, now_ms)?;
        let request = ExitForwardRequest::new(
            self.candidate.forward_id.to_vec(),
            self.candidate.control.node_id.clone(),
            self.candidate.control.peer_id.clone(),
            self.candidate.control.public_key.clone(),
            exit_peer.to_bytes(),
            self.candidate.exit.node_id.clone(),
            operation_deadline_ms,
            ExitForwardOperation::NativeProbePermit,
            self.signed_request.clone(),
        )
        .map_err(|_| NativePreselectionError::InvalidPermitForwarding)?;
        Ok(NativePermitForwardDispatch {
            awaiting: self,
            control_relay_peer,
            request,
        })
    }

    #[cfg(test)]
    pub(super) fn into_forward_dispatch_for_test(
        self,
        now_ms: u64,
    ) -> Result<NativePermitForwardDispatch, NativePreselectionError> {
        self.into_forward_dispatch_at(now_ms)
    }

    /// Consume the request authority after verifying one exact Exit-signed permit.
    pub(super) fn accept_permit(
        self,
        signed_permit: Vec<u8>,
        replay: &mut ReplayCache,
    ) -> Result<AwaitingNativeRelayReady, NativePreselectionError> {
        let now_ms = crate::unix_millis();
        self.deadline.ensure_live(now_ms, Instant::now())?;
        let relay_request = self.signed_request.clone();
        let relay_permit = signed_permit.clone();
        let verified_permit =
            verify_native_probe_permit(self.signed_request, signed_permit, now_ms, replay)?;
        Ok(AwaitingNativeRelayReady {
            verified_permit,
            relay_request,
            relay_permit,
            session_key: self.session_key,
            challenge: self.challenge,
            start_nonce: self.start_nonce,
            candidate: self.candidate,
            deadline: self.deadline,
        })
    }
}

impl NativePermitForwardDispatch {
    /// Dispatch once through discovery's authenticated control-Relay RPC and consume its response.
    pub(super) async fn execute(
        self,
        discovery: &DiscoveryControlHandle,
        replay: &mut ReplayCache,
    ) -> Result<AwaitingNativeRelayReady, NativePreselectionError> {
        let Self {
            awaiting,
            control_relay_peer,
            request,
        } = self;
        let response = discovery
            .request_exit_forward(control_relay_peer, request)
            .await
            .map_err(map_forward_transport)?;
        accept_forwarded_permit(awaiting, &response, replay)
    }

    #[cfg(test)]
    pub(super) fn request_for_test(&self) -> (&Libp2pPeerId, &ExitForwardRequest) {
        (&self.control_relay_peer, &self.request)
    }
}

fn accept_forwarded_permit(
    awaiting: AwaitingNativePermit,
    response: &ExitForwardResponse,
    replay: &mut ReplayCache,
) -> Result<AwaitingNativeRelayReady, NativePreselectionError> {
    response
        .validate()
        .map_err(|_| NativePreselectionError::InvalidPermitForwarding)?;
    if response.forward_id() != awaiting.candidate.forward_id
        || response.validated_operation().ok() != Some(ExitForwardOperation::NativeProbePermit)
        || response.exit_node_id() != awaiting.candidate.exit.node_id
        || response.exit_peer_id() != awaiting.candidate.exit.peer_id
    {
        return Err(NativePreselectionError::InvalidPermitForwarding);
    }
    match response
        .validated_status()
        .map_err(|_| NativePreselectionError::InvalidPermitForwarding)?
    {
        ForwardStatus::Granted => {
            let signed_permit = response
                .signed_responses()
                .first()
                .cloned()
                .ok_or(NativePreselectionError::InvalidPermitForwarding)?;
            awaiting.accept_permit(signed_permit, replay)
        }
        ForwardStatus::Rejected => Err(NativePreselectionError::PermitRejected),
        ForwardStatus::Unavailable => Err(NativePreselectionError::PermitUnavailable),
        ForwardStatus::Unspecified => Err(NativePreselectionError::InvalidPermitForwarding),
    }
}

fn map_forward_transport(_: OutboundReservationError) -> NativePreselectionError {
    NativePreselectionError::PermitTransportUnavailable
}

impl AwaitingNativeRelayReady {
    /// Borrow the endpoint-free request/permit pair for the exact data Relay.
    pub(super) fn relay_authorization(&self) -> (&[u8], &[u8]) {
        (&self.relay_request, &self.relay_permit)
    }

    /// Consume this authority into a direct RPC targeting only its selected data Relay.
    pub(super) fn into_relay_ready_dispatch(
        self,
    ) -> Result<NativeRelayReadyDispatch, NativePreselectionError> {
        self.into_relay_ready_dispatch_at(crate::unix_millis())
    }

    fn into_relay_ready_dispatch_at(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayReadyDispatch, NativePreselectionError> {
        let relay_peer = Libp2pPeerId::from_bytes(&self.candidate.data_relay.peer_id)
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        let operation_deadline_ms = native_operation_deadline(self.deadline.expires_at_ms, now_ms)?;
        let request = DatapathRelayRequest::new(
            self.candidate.probe_id.to_vec(),
            self.candidate.data_relay.node_id.clone(),
            self.candidate.data_relay.peer_id.clone(),
            operation_deadline_ms,
            DatapathRelayOperation::NativeProbeReady,
            self.relay_request.clone(),
            self.relay_permit.clone(),
        )
        .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        Ok(NativeRelayReadyDispatch {
            awaiting: self,
            relay_peer,
            request,
        })
    }

    #[cfg(test)]
    fn into_relay_ready_dispatch_for_test(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayReadyDispatch, NativePreselectionError> {
        self.into_relay_ready_dispatch_at(now_ms)
    }

    /// Consume the permit after verifying readiness signed by the exact data Relay.
    pub(super) fn accept_relay_ready(
        self,
        signed_relay_ready: Vec<u8>,
        replay: &mut ReplayCache,
    ) -> Result<ArmedNativeProbe, NativePreselectionError> {
        let now_ms = crate::unix_millis();
        self.deadline.ensure_live(now_ms, Instant::now())?;
        let relay_ready = verify_native_probe_relay_ready(
            self.verified_permit,
            signed_relay_ready,
            now_ms,
            replay,
        )?;
        Ok(ArmedNativeProbe {
            relay_ready,
            session_key: self.session_key,
            challenge: self.challenge,
            start_nonce: self.start_nonce,
            candidate: self.candidate,
            deadline: self.deadline,
        })
    }
}

impl NativeRelayReadyDispatch {
    /// Dispatch readiness once and consume only an exactly correlated signed Relay response.
    pub(super) async fn execute(
        self,
        discovery: &DiscoveryControlHandle,
        replay: &mut ReplayCache,
    ) -> Result<ArmedNativeProbe, NativePreselectionError> {
        let Self {
            awaiting,
            relay_peer,
            request,
        } = self;
        let response = discovery
            .request_datapath_relay(relay_peer, request)
            .await
            .map_err(map_relay_transport)?;
        accept_relay_response(
            awaiting,
            &response,
            DatapathRelayOperation::NativeProbeReady,
            replay,
            AwaitingNativeRelayReady::accept_relay_ready,
        )
    }

    #[cfg(test)]
    pub(super) fn request_for_test(&self) -> (&Libp2pPeerId, &DatapathRelayRequest) {
        (&self.relay_peer, &self.request)
    }

    #[cfg(test)]
    fn accept_response_for_test(
        self,
        response: &DatapathRelayResponse,
        replay: &mut ReplayCache,
    ) -> Result<ArmedNativeProbe, NativePreselectionError> {
        accept_relay_response(
            self.awaiting,
            response,
            DatapathRelayOperation::NativeProbeReady,
            replay,
            AwaitingNativeRelayReady::accept_relay_ready,
        )
    }
}

impl ArmedNativeProbe {
    /// Borrow the immutable signed path scope for downstream authority binding.
    pub(super) fn path_scope(&self) -> &NativeProbePathScope {
        self.relay_ready.scope()
    }

    /// Consume readiness and bind the helper-prepared Client endpoint at one batch start barrier.
    pub(super) fn start_at(
        self,
        client_endpoint: NativeProbeEndpointBinding,
        started_at_ms: u64,
        started_at: Instant,
    ) -> Result<AwaitingNativeResult, NativePreselectionError> {
        self.deadline.ensure_live(started_at_ms, started_at)?;
        let response_deadline_ms = self.relay_ready.expires_at_ms();
        let issued_start = sign_native_probe_start(
            self.relay_ready,
            client_endpoint,
            &self.session_key,
            started_at_ms,
            self.start_nonce,
        )?;
        Ok(AwaitingNativeResult {
            issued_start,
            challenge: self.challenge,
            candidate: self.candidate,
            deadline: self.deadline,
            response_deadline_ms,
        })
    }

    /// Exact helper route context and remote `RelayClient` binding for local preparation.
    pub(super) fn helper_scope(
        &self,
    ) -> Result<([u8; ID_BYTES], u32, &NativeProbeEndpointBinding, u64), NativePreselectionError>
    {
        let route_context_id = self
            .relay_ready
            .scope()
            .attempt_id
            .as_slice()
            .try_into()
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        Ok((
            route_context_id,
            self.relay_ready.scope().candidate_ordinal,
            self.relay_ready.relay_client_endpoint(),
            self.relay_ready.expires_at_ms(),
        ))
    }
}

impl AwaitingNativeResult {
    /// Borrow the signed start for delivery only to the exact data Relay.
    pub(super) fn encoded_start(&self) -> &[u8] {
        self.issued_start.encoded_start()
    }

    /// Borrow the exact one-time challenge for the activated probe socket only.
    pub(super) fn challenge(&self) -> &[u8; KEY_BYTES] {
        &self.challenge
    }

    /// Consume the signed start into a direct RPC to the exact readiness-signing data Relay.
    pub(super) fn into_relay_start_dispatch(
        self,
    ) -> Result<NativeRelayStartDispatch, NativePreselectionError> {
        self.into_relay_start_dispatch_at(crate::unix_millis())
    }

    fn into_relay_start_dispatch_at(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayStartDispatch, NativePreselectionError> {
        let relay_peer = Libp2pPeerId::from_bytes(&self.candidate.data_relay.peer_id)
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        let operation_deadline_ms = native_operation_deadline(self.response_deadline_ms, now_ms)?;
        let request = DatapathRelayRequest::new(
            self.candidate.start_request_id.to_vec(),
            self.candidate.data_relay.node_id.clone(),
            self.candidate.data_relay.peer_id.clone(),
            operation_deadline_ms,
            DatapathRelayOperation::NativeProbeStart,
            self.issued_start.encoded_start().to_vec(),
            Vec::new(),
        )
        .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        Ok(NativeRelayStartDispatch {
            awaiting: self,
            relay_peer,
            request,
        })
    }

    #[cfg(test)]
    fn into_relay_start_dispatch_for_test(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayStartDispatch, NativePreselectionError> {
        self.into_relay_start_dispatch_at(now_ms)
    }

    /// Consume the signed Start into the pre-activation standard-reservation exchange.
    pub(super) fn into_relay_authorization_dispatch(
        self,
    ) -> Result<NativeRelayAuthorizationDispatch, NativePreselectionError> {
        self.into_relay_authorization_dispatch_at(crate::unix_millis())
    }

    fn into_relay_authorization_dispatch_at(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayAuthorizationDispatch, NativePreselectionError> {
        let relay_peer = Libp2pPeerId::from_bytes(&self.candidate.data_relay.peer_id)
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        let authorization_request_id = authorization_request_id(self.candidate.start_request_id);
        let operation_deadline_ms = native_operation_deadline(self.response_deadline_ms, now_ms)?;
        let request = DatapathRelayRequest::new(
            authorization_request_id.to_vec(),
            self.candidate.data_relay.node_id.clone(),
            self.candidate.data_relay.peer_id.clone(),
            operation_deadline_ms,
            DatapathRelayOperation::NativeProbeAuthorize,
            self.issued_start.encoded_start().to_vec(),
            Vec::new(),
        )
        .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        Ok(NativeRelayAuthorizationDispatch {
            awaiting: self,
            relay_peer,
            request,
        })
    }

    #[cfg(test)]
    fn into_relay_authorization_dispatch_for_test(
        self,
        now_ms: u64,
    ) -> Result<NativeRelayAuthorizationDispatch, NativePreselectionError> {
        self.into_relay_authorization_dispatch_at(now_ms)
    }

    /// Consume the in-flight authority after exact local and signed remote proof verification.
    pub(super) fn accept_result(
        self,
        client_lease: NativeProbeLeaseProof,
        signed_relay_result: &[u8],
        replay: &mut ReplayCache,
    ) -> Result<BoundNativePathProof, NativePreselectionError> {
        let now_ms = crate::unix_millis();
        self.deadline.ensure_live(now_ms, Instant::now())?;
        let verified_result = verify_native_probe_result(
            self.issued_start,
            client_lease,
            signed_relay_result,
            now_ms,
            replay,
        )?;
        Ok(BoundNativePathProof {
            verified_result,
            candidate: self.candidate,
        })
    }
}

impl NativeRelayStartDispatch {
    /// Dispatch Start once and retain the signed result until local helper proof is available.
    pub(super) async fn execute(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<(AwaitingNativeResult, Vec<u8>), NativePreselectionError> {
        let Self {
            awaiting,
            relay_peer,
            request,
        } = self;
        let response = discovery
            .request_datapath_relay(relay_peer, request)
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = ?error,
                    "native terminal Start transport failed"
                );
                map_relay_transport(error)
            })?;
        response
            .validate()
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        if response.request_id() != awaiting.candidate.start_request_id
            || response.validated_operation().ok() != Some(DatapathRelayOperation::NativeProbeStart)
            || response.relay_node_id() != awaiting.candidate.data_relay.node_id
            || response.relay_peer_id() != awaiting.candidate.data_relay.peer_id
        {
            return Err(NativePreselectionError::InvalidRelayDispatch);
        }
        match response
            .validated_status()
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?
        {
            ForwardStatus::Granted => Ok((awaiting, response.signed_response().to_vec())),
            ForwardStatus::Rejected => Err(NativePreselectionError::RelayRejected),
            ForwardStatus::Unavailable => Err(NativePreselectionError::RelayUnavailable),
            ForwardStatus::Unspecified => Err(NativePreselectionError::InvalidRelayDispatch),
        }
    }

    #[cfg(test)]
    pub(super) fn request_for_test(&self) -> (&Libp2pPeerId, &DatapathRelayRequest) {
        (&self.relay_peer, &self.request)
    }
}

impl NativeRelayAuthorizationDispatch {
    /// Dispatch the signed Start once and retain both it and the standard nested reservation.
    pub(super) async fn execute(
        self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<(AwaitingNativeResult, Vec<u8>), NativePreselectionError> {
        let Self {
            awaiting,
            relay_peer,
            request,
        } = self;
        let response = discovery
            .request_datapath_relay(relay_peer, request)
            .await
            .map_err(map_relay_transport)?;
        response
            .validate()
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
        if response.request_id() != authorization_request_id(awaiting.candidate.start_request_id)
            || response.validated_operation().ok()
                != Some(DatapathRelayOperation::NativeProbeAuthorize)
            || response.relay_node_id() != awaiting.candidate.data_relay.node_id
            || response.relay_peer_id() != awaiting.candidate.data_relay.peer_id
        {
            return Err(NativePreselectionError::InvalidRelayDispatch);
        }
        match response
            .validated_status()
            .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?
        {
            ForwardStatus::Granted => Ok((awaiting, response.signed_response().to_vec())),
            ForwardStatus::Rejected => Err(NativePreselectionError::RelayRejected),
            ForwardStatus::Unavailable => Err(NativePreselectionError::RelayUnavailable),
            ForwardStatus::Unspecified => Err(NativePreselectionError::InvalidRelayDispatch),
        }
    }

    #[cfg(test)]
    pub(super) fn request_for_test(&self) -> (&Libp2pPeerId, &DatapathRelayRequest) {
        (&self.relay_peer, &self.request)
    }
}

fn accept_relay_response<T, F>(
    awaiting: T,
    response: &DatapathRelayResponse,
    operation: DatapathRelayOperation,
    replay: &mut ReplayCache,
    accept: F,
) -> Result<ArmedNativeProbe, NativePreselectionError>
where
    T: RelayResponseExpectation,
    F: FnOnce(T, Vec<u8>, &mut ReplayCache) -> Result<ArmedNativeProbe, NativePreselectionError>,
{
    response
        .validate()
        .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?;
    if response.request_id() != awaiting.expected_request_id()
        || response.validated_operation().ok() != Some(operation)
        || response.relay_node_id() != awaiting.expected_relay_node_id()
        || response.relay_peer_id() != awaiting.expected_relay_peer_id()
    {
        return Err(NativePreselectionError::InvalidRelayDispatch);
    }
    match response
        .validated_status()
        .map_err(|_| NativePreselectionError::InvalidRelayDispatch)?
    {
        ForwardStatus::Granted => accept(awaiting, response.signed_response().to_vec(), replay),
        ForwardStatus::Rejected => Err(NativePreselectionError::RelayRejected),
        ForwardStatus::Unavailable => Err(NativePreselectionError::RelayUnavailable),
        ForwardStatus::Unspecified => Err(NativePreselectionError::InvalidRelayDispatch),
    }
}

trait RelayResponseExpectation {
    fn expected_request_id(&self) -> &[u8];
    fn expected_relay_node_id(&self) -> &[u8];
    fn expected_relay_peer_id(&self) -> &[u8];
}

impl RelayResponseExpectation for AwaitingNativeRelayReady {
    fn expected_request_id(&self) -> &[u8] {
        &self.candidate.probe_id
    }

    fn expected_relay_node_id(&self) -> &[u8] {
        &self.candidate.data_relay.node_id
    }

    fn expected_relay_peer_id(&self) -> &[u8] {
        &self.candidate.data_relay.peer_id
    }
}

fn map_relay_transport(_: OutboundReservationError) -> NativePreselectionError {
    NativePreselectionError::RelayTransportUnavailable
}

fn invalid_prepared(_: SelectionBridgeError) -> NativePreselectionError {
    NativePreselectionError::InvalidPreparedEvidence
}

fn unique_role_index(
    entries: &[FreshPeerEvidence],
    role: ServiceRole,
) -> Result<usize, NativePreselectionError> {
    let mut matching = entries
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.role == role);
    let (index, _) = matching
        .next()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    if matching.next().is_some() {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    Ok(index)
}

fn unique_control_index(
    relays: &[FreshPeerEvidence],
    control: &super::ForwardedControlBinding,
) -> Result<usize, NativePreselectionError> {
    let mut matching = relays.iter().enumerate().filter(|(_, candidate)| {
        candidate.role == ServiceRole::Relay
            && candidate.node_id == control.node_id
            && candidate.peer_id == control.peer_id
            && candidate.capability_public_key == control.public_key
            && candidate.advertisement_sequence == control.advertisement_sequence
            && candidate.advertisement_expires_at_ms == control.advertisement_expires_at_ms
            && candidate.advertisement_payload_hash == control.advertisement_payload_hash
            && candidate.capability_expires_at_ms == control.capability_expires_at_ms
    });
    let (index, _) = matching
        .next()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    if matching.next().is_some() {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    Ok(index)
}

fn project_candidate(
    candidate: FreshPeerEvidence,
) -> Result<NativeCandidateProjection, NativePreselectionError> {
    let FreshPeerEvidence {
        batch_id: _,
        node_id,
        peer_id,
        capability_public_key,
        advertisement_sequence,
        advertisement_expires_at_ms,
        advertisement_payload_hash,
        capability_expires_at_ms,
        role,
        transport,
        policy_version,
        policy_hash,
        policy_expires_at_ms,
        address_family,
        observed_at_ms: _,
        valid_until_ms: _,
        forwarded_control: _,
        locally_measured_p25: _,
        measurement_count: _,
        preselection_capacity_ceiling,
        uptime_score: _,
        proximity_score: _,
        recent_egress_quality: _,
        rtt_ms: _,
        reachable: _,
        network_address_usable: _,
        observed_network_prefix: _,
        locally_blocked: _,
    } = candidate;
    let wire_node_id = node_id_from_public_key(&capability_public_key);
    let parsed_peer = Libp2pPeerId::from_str(peer_id.as_str())
        .map_err(|_| NativePreselectionError::InvalidCandidateSet)?;
    let ed25519 = identity::ed25519::PublicKey::try_from_bytes(&capability_public_key)
        .map_err(|_| NativePreselectionError::InvalidCandidateSet)?;
    let derived_peer = identity::PublicKey::from(ed25519).to_peer_id();
    if node_id.as_str() != hex::encode(wire_node_id) || parsed_peer != derived_peer {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    let mut payload_hash = Vec::with_capacity(KEY_BYTES);
    advertisement_payload_hash.append_native_probe_commitment(&mut payload_hash);
    let actor = PreselectionActorBinding {
        node_id: wire_node_id.to_vec(),
        peer_id: parsed_peer.to_bytes(),
        public_key: capability_public_key.to_vec(),
        advertisement_sequence,
        advertisement_expires_at_ms,
        advertisement_payload_hash: payload_hash,
        capability_expires_at_ms,
    };
    Ok(NativeCandidateProjection {
        actor,
        role,
        transport,
        address_family: address_family.ok_or(NativePreselectionError::InvalidCandidateSet)?,
        policy_version,
        policy_hash: *policy_hash.as_bytes(),
        policy_expires_at_ms,
        preselection_capacity_ceiling,
    })
}

fn validate_shared_scope(
    snapshot: &RouteCandidateSnapshot,
    control: &NativeCandidateProjection,
    relays: &[NativeCandidateProjection],
    exit: &NativeCandidateProjection,
) -> Result<(), NativePreselectionError> {
    let first = relays
        .first()
        .ok_or(NativePreselectionError::InvalidCandidateSet)?;
    let policy = snapshot.policy();
    if control.role != ServiceRole::Relay
        || first.role != ServiceRole::Relay
        || exit.role != ServiceRole::Exit
        || relays.iter().any(|candidate| {
            candidate.role != ServiceRole::Relay
                || candidate.transport != first.transport
                || candidate.address_family != first.address_family
                || candidate.policy_version != first.policy_version
                || candidate.policy_hash != first.policy_hash
                || candidate.policy_expires_at_ms != first.policy_expires_at_ms
        })
        || control.transport != first.transport
        || control.address_family != first.address_family
        || control.policy_version != first.policy_version
        || control.policy_hash != first.policy_hash
        || control.policy_expires_at_ms != first.policy_expires_at_ms
        || exit.transport != first.transport
        || exit.address_family != first.address_family
        || exit.policy_version != first.policy_version
        || exit.policy_hash != first.policy_hash
        || exit.policy_expires_at_ms != first.policy_expires_at_ms
        || policy.version() != first.policy_version
        || policy.hash() != first.policy_hash
        || policy.expires_at_ms() != first.policy_expires_at_ms
    {
        return Err(NativePreselectionError::InvalidCandidateSet);
    }
    Ok(())
}

const fn protocol_family(family: IpFamily) -> volparossa_protocol::ObservationAddressFamily {
    match family {
        IpFamily::Ipv4 => volparossa_protocol::ObservationAddressFamily::Ipv4,
        IpFamily::Ipv6 => volparossa_protocol::ObservationAddressFamily::Ipv6,
    }
}

fn actor_expiry(actor: &PreselectionActorBinding) -> u64 {
    actor
        .advertisement_expires_at_ms
        .min(actor.capability_expires_at_ms)
}

fn native_time_policy() -> TimePolicy {
    TimePolicy {
        maximum_lifetime_ms: MAX_NATIVE_PROBE_LIFETIME_MS,
        maximum_clock_skew_ms: TimePolicy::default().maximum_clock_skew_ms,
    }
}

fn random_nonzero<const LENGTH: usize, R>(
    rng: &mut R,
) -> Result<[u8; LENGTH], NativePreselectionError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    for _ in 0..ENTROPY_ATTEMPTS {
        let mut value = [0_u8; LENGTH];
        rng.try_fill_bytes(&mut value)
            .map_err(|_| NativePreselectionError::EntropyUnavailable)?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(NativePreselectionError::EntropyUnavailable)
}

fn unique_random<const LENGTH: usize, R>(
    rng: &mut R,
    seen: &mut HashSet<[u8; LENGTH]>,
) -> Result<[u8; LENGTH], NativePreselectionError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    for _ in 0..ENTROPY_ATTEMPTS {
        let value = random_nonzero::<LENGTH, _>(rng)?;
        if seen.insert(value) {
            return Ok(value);
        }
    }
    Err(NativePreselectionError::EntropyUnavailable)
}

#[cfg(test)]
mod dispatch_tests {
    use libp2p::identity;
    use sha2::{Digest, Sha256};
    use volparossa_protocol::{
        NativeProbePermit, NativeProbeRelayReady, ObservationAddressFamily, RelayAuthorization,
        RelayReservation, SignedEnvelope, Transport, WireguardEndpoint, generate_nonce,
        native_probe_permit_hash, native_probe_permit_request_hash, verify_native_probe_permit,
    };

    use super::*;

    struct ReadyFixture {
        awaiting: AwaitingNativeRelayReady,
        relay_key: SigningKey,
        exit_key: SigningKey,
        scope: NativeProbePathScope,
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one affine Ready/Start smoke keeps the exact signed transcript visible"
    )]
    fn native_ready_and_start_dispatches_are_exact_and_relay_only() {
        let ReadyFixture {
            awaiting,
            relay_key: _,
            exit_key: _,
            scope,
        } = ready_fixture();
        let expected_relay = scope.data_relay.as_ref().expect("data Relay");
        let ready_operation_now_ms = scope.attempt_expires_at_ms - 60_000;
        let dispatch = awaiting
            .into_relay_ready_dispatch_for_test(ready_operation_now_ms)
            .expect("Ready dispatch");
        let (relay_peer, request) = dispatch.request_for_test();
        assert_eq!(relay_peer.to_bytes(), expected_relay.peer_id);
        assert_eq!(request.request_id(), scope.probe_id);
        assert_eq!(request.relay_node_id(), expected_relay.node_id);
        assert_eq!(request.relay_peer_id(), expected_relay.peer_id);
        assert_eq!(
            request.deadline_unix_ms(),
            ready_operation_now_ms + crate::discovery::MAX_FORWARD_OPERATION_LIFETIME_MS
        );
        assert!(request.deadline_unix_ms() < scope.attempt_expires_at_ms);
        assert_eq!(
            request.validated_operation().expect("Ready operation"),
            DatapathRelayOperation::NativeProbeReady
        );
        assert_envelope_type(
            request.client_signed_request(),
            volparossa_protocol::ControlMessageType::NativeProbePermitRequest,
        );
        assert_envelope_type(
            request.exit_signed_authorization(),
            volparossa_protocol::ControlMessageType::NativeProbePermit,
        );

        let (armed, scope, relay_endpoint) = armed_fixture();
        let (second_armed, second_scope, _) = armed_fixture();
        let (route_context, path_id, observed_relay, _) =
            armed.helper_scope().expect("helper scope");
        assert_eq!(route_context.as_slice(), scope.attempt_id);
        assert_eq!(path_id, scope.candidate_ordinal);
        assert_eq!(observed_relay, &relay_endpoint);
        let client_endpoint = endpoint_binding(&scope.attempt_id, 31, [1, 1, 1, 1], 42_001);
        let second_client_endpoint =
            endpoint_binding(&second_scope.attempt_id, 32, [1, 1, 1, 2], 42_002);
        let start_barrier_ms = crate::unix_millis();
        let start_barrier = Instant::now();
        let start = armed
            .start_at(client_endpoint, start_barrier_ms, start_barrier)
            .expect("first signed Start");
        let second_start = second_armed
            .start_at(second_client_endpoint, start_barrier_ms, start_barrier)
            .expect("second signed Start");
        assert_eq!(signed_start_time(&start), start_barrier_ms);
        assert_eq!(signed_start_time(&second_start), start_barrier_ms);
        let dispatch = start
            .into_relay_start_dispatch_for_test(start_barrier_ms)
            .expect("Start dispatch");
        let (relay_peer, request) = dispatch.request_for_test();
        let expected_relay = scope.data_relay.as_ref().expect("data Relay");
        assert_eq!(relay_peer.to_bytes(), expected_relay.peer_id);
        assert_eq!(request.request_id(), &[13; ID_BYTES]);
        assert_eq!(request.relay_node_id(), expected_relay.node_id);
        assert_eq!(request.relay_peer_id(), expected_relay.peer_id);
        assert_eq!(
            request.deadline_unix_ms(),
            start_barrier_ms + crate::discovery::MAX_FORWARD_OPERATION_LIFETIME_MS
        );
        assert!(request.deadline_unix_ms() < scope.attempt_expires_at_ms);
        assert_eq!(
            request.validated_operation().expect("Start operation"),
            DatapathRelayOperation::NativeProbeStart
        );
        assert!(request.exit_signed_authorization().is_empty());
        assert_envelope_type(
            request.client_signed_request(),
            volparossa_protocol::ControlMessageType::NativeProbeStart,
        );
        let authorization = second_start
            .into_relay_authorization_dispatch_for_test(start_barrier_ms)
            .expect("authorization dispatch");
        assert_eq!(
            authorization.request_for_test().1.deadline_unix_ms(),
            start_barrier_ms + crate::discovery::MAX_FORWARD_OPERATION_LIFETIME_MS
        );

        let ReadyFixture {
            awaiting,
            relay_key,
            exit_key: _,
            scope,
        } = ready_fixture();
        let ready_nonce = generate_nonce();
        let ready = NativeProbeRelayReady {
            permit_hash: native_probe_permit_hash(&awaiting.relay_permit)
                .expect("Permit hash")
                .to_vec(),
            exit_ready_hash: vec![7; KEY_BYTES],
            scope: Some(scope.clone()),
            relay_client_endpoint: Some(endpoint_binding(
                &scope.attempt_id,
                11,
                [8, 8, 8, 8],
                41_001,
            )),
            ready_at_ms: crate::unix_millis(),
            expires_at_ms: scope.attempt_expires_at_ms,
            nonce: ready_nonce.to_vec(),
        };
        let signed_ready = sign_control_message(
            &ready,
            &relay_key,
            ready.ready_at_ms,
            ready.expires_at_ms,
            ready_nonce,
            native_time_policy(),
        )
        .expect("signed Ready mutant");
        let relay = scope.data_relay.as_ref().expect("data Relay");
        let wrong_id = DatapathRelayResponse::granted(
            vec![99; ID_BYTES],
            DatapathRelayOperation::NativeProbeReady,
            relay.node_id.clone(),
            relay.peer_id.clone(),
            signed_ready,
        )
        .expect("wrong-ID response is structurally valid");
        let mut replay_cache = ReplayCache::new(4).expect("replay");
        assert!(matches!(
            awaiting
                .into_relay_ready_dispatch()
                .expect("Ready dispatch")
                .accept_response_for_test(&wrong_id, &mut replay_cache),
            Err(NativePreselectionError::InvalidRelayDispatch)
        ));
    }

    #[test]
    fn helper_activation_requires_exact_standard_relay_authority() {
        let ReadyFixture {
            awaiting: _,
            relay_key,
            exit_key,
            scope,
        } = ready_fixture();
        let now_ms = crate::unix_millis();
        let local = WireguardEndpoint {
            public_key: vec![32; KEY_BYTES],
            underlay_ip: vec![1, 1, 1, 1],
            listen_port: 42_001,
        };
        let remote = WireguardEndpoint {
            public_key: vec![12; KEY_BYTES],
            underlay_ip: vec![8, 8, 8, 8],
            listen_port: 41_001,
        };
        let signed_start = vec![52; KEY_BYTES];
        let signed = signed_relay_activation_authority(
            &scope,
            &relay_key,
            &exit_key,
            &local,
            &remote,
            &signed_start,
            now_ms,
        );
        let mut replay_cache = ReplayCache::new(4).expect("replay");
        super::super::verify_native_client_activation_authority(
            &scope,
            &local,
            &remote,
            scope.attempt_expires_at_ms / 1_000,
            &signed_start,
            &signed,
            now_ms,
            &mut replay_cache,
        )
        .expect("exact activation authority");

        let mut wrong_local = local;
        wrong_local.public_key = vec![99; KEY_BYTES];
        let mut replay_cache = ReplayCache::new(4).expect("mutant replay");
        assert!(matches!(
            super::super::verify_native_client_activation_authority(
                &scope,
                &wrong_local,
                &remote,
                scope.attempt_expires_at_ms / 1_000,
                &signed_start,
                &signed,
                now_ms,
                &mut replay_cache,
            ),
            Err(super::super::ClientNativeProbeError::HelperCorrelation)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs one complete signed native preselection lineage"
    )]
    fn ready_fixture() -> ReadyFixture {
        let now_ms = crate::unix_millis();
        let expires_at_ms = now_ms + MAX_NATIVE_PROBE_LIFETIME_MS;
        let relay_key = SigningKey::from_bytes(&[3; KEY_BYTES]);
        let control_key = SigningKey::from_bytes(&[4; KEY_BYTES]);
        let exit_key = SigningKey::from_bytes(&[5; KEY_BYTES]);
        let session_key = SigningKey::from_bytes(&[6; KEY_BYTES]);
        let relay = actor(&relay_key, expires_at_ms + 1_000);
        let control = actor(&control_key, expires_at_ms + 1_000);
        let exit = actor(&exit_key, expires_at_ms + 1_000);
        let session_public_key = session_key.verifying_key().to_bytes();
        let scope = NativeProbePathScope {
            attempt_id: vec![1; ID_BYTES],
            probe_id: vec![2; ID_BYTES],
            candidate_set_hash: vec![3; KEY_BYTES],
            candidate_ordinal: 1,
            data_relay: Some(relay.clone()),
            control: Some(control.clone()),
            exit: Some(exit.clone()),
            client_session_id: node_id_from_public_key(&session_public_key).to_vec(),
            client_session_public_key: session_public_key.to_vec(),
            transport: Transport::TcpMptcp as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version: 1,
            policy_hash: vec![4; KEY_BYTES],
            policy_expires_at_ms: expires_at_ms + 1_000,
            challenge_hash: native_probe_challenge_hash(&[12; KEY_BYTES]).to_vec(),
            attempt_expires_at_ms: expires_at_ms,
            required_path_count: 2,
            reserved_up_mbps: 8,
            reserved_down_mbps: 12,
        };
        let request_nonce = generate_nonce();
        let request = NativeProbePermitRequest {
            scope: Some(scope.clone()),
            created_at_ms: now_ms,
            expires_at_ms,
            nonce: request_nonce.to_vec(),
        };
        let signed_request = sign_control_message(
            &request,
            &session_key,
            now_ms,
            expires_at_ms,
            request_nonce,
            native_time_policy(),
        )
        .expect("signed request");
        let permit_nonce = generate_nonce();
        let permit = NativeProbePermit {
            request_hash: native_probe_permit_request_hash(&signed_request)
                .expect("request hash")
                .to_vec(),
            scope: Some(scope.clone()),
            issued_at_ms: now_ms,
            expires_at_ms,
            nonce: permit_nonce.to_vec(),
            exit_control_address: "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/exit".to_owned(),
        };
        let signed_permit = sign_control_message(
            &permit,
            &exit_key,
            now_ms,
            expires_at_ms,
            permit_nonce,
            native_time_policy(),
        )
        .expect("signed Permit");
        let mut replay_cache = ReplayCache::new(2).expect("replay");
        let verified_permit = verify_native_probe_permit(
            signed_request.clone(),
            signed_permit.clone(),
            now_ms,
            &mut replay_cache,
        )
        .expect("verified Permit");
        ReadyFixture {
            awaiting: AwaitingNativeRelayReady {
                verified_permit,
                relay_request: signed_request,
                relay_permit: signed_permit,
                session_key,
                challenge: Zeroizing::new([12; KEY_BYTES]),
                start_nonce: [13; KEY_BYTES],
                candidate: NativeCandidateTemplate {
                    candidate_ordinal: 1,
                    data_relay: relay,
                    control,
                    exit,
                    forward_id: [14; ID_BYTES],
                    probe_id: [2; ID_BYTES],
                    start_request_id: [13; ID_BYTES],
                    preselection_capacity_ceiling: Bandwidth::new(10, 10).expect("capacity"),
                },
                deadline: NativeAttemptDeadline {
                    created_at_ms: now_ms,
                    expires_at_ms,
                    monotonic_expires_at: Instant::now() + Duration::from_secs(30),
                },
            },
            relay_key,
            exit_key,
            scope,
        }
    }

    fn armed_fixture() -> (
        ArmedNativeProbe,
        NativeProbePathScope,
        NativeProbeEndpointBinding,
    ) {
        let ReadyFixture {
            awaiting,
            relay_key,
            exit_key: _,
            scope,
        } = ready_fixture();
        let now_ms = crate::unix_millis();
        let relay_endpoint = endpoint_binding(&scope.attempt_id, 11, [8, 8, 8, 8], 41_001);
        let ready_nonce = generate_nonce();
        let ready = NativeProbeRelayReady {
            permit_hash: native_probe_permit_hash(&awaiting.relay_permit)
                .expect("Permit hash")
                .to_vec(),
            exit_ready_hash: vec![7; KEY_BYTES],
            scope: Some(scope.clone()),
            relay_client_endpoint: Some(relay_endpoint.clone()),
            ready_at_ms: now_ms,
            expires_at_ms: scope.attempt_expires_at_ms,
            nonce: ready_nonce.to_vec(),
        };
        let signed_ready = sign_control_message(
            &ready,
            &relay_key,
            now_ms,
            ready.expires_at_ms,
            ready_nonce,
            native_time_policy(),
        )
        .expect("signed Ready");
        let relay = scope.data_relay.as_ref().expect("data Relay");
        let response = DatapathRelayResponse::granted(
            scope.probe_id.clone(),
            DatapathRelayOperation::NativeProbeReady,
            relay.node_id.clone(),
            relay.peer_id.clone(),
            signed_ready,
        )
        .expect("Ready response");
        let mut replay_cache = ReplayCache::new(4).expect("replay");
        let armed = awaiting
            .into_relay_ready_dispatch()
            .expect("Ready dispatch")
            .accept_response_for_test(&response, &mut replay_cache)
            .expect("verified Ready");
        (armed, scope, relay_endpoint)
    }

    fn signed_start_time(start: &AwaitingNativeResult) -> u64 {
        let envelope: SignedEnvelope = volparossa_protocol::decode_canonical(
            start.encoded_start(),
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("signed Start envelope");
        let start: volparossa_protocol::NativeProbeStart = volparossa_protocol::decode_canonical(
            &envelope.payload,
            volparossa_protocol::MAX_CONTROL_PAYLOAD_SIZE,
        )
        .expect("signed Start payload");
        start.started_at_ms
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture makes every nested signed Relay authority field explicit"
    )]
    fn signed_relay_activation_authority(
        scope: &NativeProbePathScope,
        relay_key: &SigningKey,
        exit_key: &SigningKey,
        local: &WireguardEndpoint,
        remote: &WireguardEndpoint,
        signed_start: &[u8],
        now_ms: u64,
    ) -> Vec<u8> {
        let relay = scope.data_relay.as_ref().expect("data Relay");
        let exit = scope.exit.as_ref().expect("Exit");
        let control = scope.control.as_ref().expect("control Relay");
        let relay_exit = WireguardEndpoint {
            public_key: vec![62; KEY_BYTES],
            underlay_ip: vec![9, 9, 9, 9],
            listen_port: 43_001,
        };
        let exit_endpoint = WireguardEndpoint {
            public_key: vec![72; KEY_BYTES],
            underlay_ip: vec![7, 7, 7, 7],
            listen_port: 44_001,
        };
        let authorization_nonce = generate_nonce();
        let authorization = RelayAuthorization {
            reservation_id: scope.probe_id.clone(),
            route_context_id: scope.attempt_id.clone(),
            path_id: scope.candidate_ordinal,
            relay_node_id: relay.node_id.clone(),
            exit_node_id: exit.node_id.clone(),
            client_session_id: scope.client_session_id.clone(),
            allowed_transports: vec![scope.transport],
            maximum_up_mbps: 10,
            maximum_down_mbps: 10,
            client_wireguard_public_key: local.public_key.clone(),
            exit_wireguard_endpoint: Some(exit_endpoint.clone()),
            policy_hash: scope.policy_hash.clone(),
            created_at_ms: now_ms,
            expires_at_ms: scope.attempt_expires_at_ms,
            nonce: authorization_nonce.to_vec(),
            relay_peer_id: relay.peer_id.clone(),
            capability_id: scope.attempt_id.clone(),
            client_session_public_key: scope.client_session_public_key.clone(),
            exit_boot_id: vec![43; ID_BYTES],
            hold_id: scope.probe_id.clone(),
            finalize_id: vec![45; ID_BYTES],
            control_relay_node_id: control.node_id.clone(),
            control_relay_peer_id: control.peer_id.clone(),
            exit_peer_id: exit.peer_id.clone(),
        };
        let signed_exit = sign_control_message(
            &authorization,
            exit_key,
            now_ms,
            scope.attempt_expires_at_ms,
            authorization_nonce,
            native_time_policy(),
        )
        .expect("signed Exit authorization");
        let reservation_nonce = generate_nonce();
        let reservation = RelayReservation {
            reservation_id: authorization.reservation_id.clone(),
            route_context_id: authorization.route_context_id.clone(),
            path_id: authorization.path_id,
            relay_node_id: authorization.relay_node_id.clone(),
            exit_node_id: authorization.exit_node_id.clone(),
            client_session_id: authorization.client_session_id.clone(),
            allowed_transports: authorization.allowed_transports.clone(),
            maximum_up_mbps: authorization.maximum_up_mbps,
            maximum_down_mbps: authorization.maximum_down_mbps,
            client_wireguard_public_key: authorization.client_wireguard_public_key.clone(),
            relay_client_wireguard_endpoint: Some(remote.clone()),
            relay_exit_wireguard_endpoint: Some(relay_exit),
            exit_wireguard_endpoint: authorization.exit_wireguard_endpoint.clone(),
            policy_hash: authorization.policy_hash.clone(),
            created_at_ms: authorization.created_at_ms,
            expires_at_ms: authorization.expires_at_ms,
            nonce: reservation_nonce.to_vec(),
            exit_authorization: signed_exit,
            relay_peer_id: authorization.relay_peer_id.clone(),
            capability_id: authorization.capability_id.clone(),
            client_session_public_key: authorization.client_session_public_key.clone(),
            exit_boot_id: authorization.exit_boot_id.clone(),
            hold_id: authorization.hold_id.clone(),
            finalize_id: authorization.finalize_id.clone(),
            control_relay_node_id: authorization.control_relay_node_id.clone(),
            control_relay_peer_id: authorization.control_relay_peer_id.clone(),
            exit_peer_id: authorization.exit_peer_id.clone(),
            signed_client_relay_request_sha256: Sha256::digest(signed_start).to_vec(),
        };
        sign_control_message(
            &reservation,
            relay_key,
            now_ms,
            scope.attempt_expires_at_ms,
            reservation_nonce,
            native_time_policy(),
        )
        .expect("signed Relay reservation")
    }

    fn actor(key: &SigningKey, expires_at_ms: u64) -> PreselectionActorBinding {
        let public_key = key.verifying_key().to_bytes();
        let ed25519 = identity::ed25519::PublicKey::try_from_bytes(&public_key).expect("Ed25519");
        let peer_id = identity::PublicKey::from(ed25519).to_peer_id();
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: peer_id.to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: 1,
            advertisement_expires_at_ms: expires_at_ms,
            advertisement_payload_hash: vec![5; KEY_BYTES],
            capability_expires_at_ms: expires_at_ms,
        }
    }

    fn endpoint_binding(
        route_context_id: &[u8],
        seed: u8,
        address: [u8; 4],
        port: u32,
    ) -> NativeProbeEndpointBinding {
        NativeProbeEndpointBinding {
            helper_runtime_id: vec![seed; KEY_BYTES],
            route_context_id: route_context_id.to_vec(),
            endpoint: Some(WireguardEndpoint {
                public_key: vec![seed + 1; KEY_BYTES],
                underlay_ip: address.to_vec(),
                listen_port: port,
            }),
            prepared_lease_commitment: vec![seed + 2; KEY_BYTES],
            path_id: 1,
        }
    }

    fn assert_envelope_type(encoded: &[u8], expected: volparossa_protocol::ControlMessageType) {
        let envelope: SignedEnvelope = volparossa_protocol::decode_canonical(
            encoded,
            volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("canonical envelope");
        assert_eq!(envelope.message_type, expected as i32);
    }
}

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn owner_is_affine_and_carries_no_a1_reachability_claim() {
        let source = include_str!("native_preselection.rs");
        let product = source
            .split_once("#[cfg(test)]\nmod dispatch_tests")
            .expect("source-contract test boundary")
            .0;
        for declaration in [
            "pub(super) struct NativePreselectionAttemptOwner {",
            "pub(super) struct PendingNativeProbeAuthority {",
            "pub(super) struct AwaitingNativePermit {",
            "pub(super) struct NativePermitForwardDispatch {",
            "pub(super) struct AwaitingNativeRelayReady {",
            "pub(super) struct NativeRelayReadyDispatch {",
            "pub(super) struct ArmedNativeProbe {",
            "pub(super) struct AwaitingNativeResult {",
            "pub(super) struct NativeRelayStartDispatch {",
            "pub(super) struct NativeRelayAuthorizationDispatch {",
            "pub(super) struct BoundNativePathProof {",
        ] {
            let before = product
                .split_once(declaration)
                .expect("authority declaration")
                .0;
            let preceding = before.lines().rev().take(5).collect::<Vec<_>>().join("\n");
            assert!(!preceding.contains("derive(Clone"));
            assert!(!preceding.contains("derive(Copy"));
        }
        let owner = product
            .split_once("pub(super) struct NativePreselectionAttemptOwner {")
            .expect("owner")
            .1
            .split_once("}\n")
            .expect("owner end")
            .0;
        for forbidden in [
            "observed_at_ms",
            "valid_until_ms",
            "rtt_ms",
            "reachable",
            "network_address_usable",
            "observed_network_prefix",
        ] {
            assert!(!owner.contains(forbidden), "stale owner field: {forbidden}");
        }
        assert!(!product.contains("network_address_usable: true"));
        assert!(!product.contains("native_dataplane_challenge"));
        assert!(!product.contains("control_endpoints"));
        assert!(!product.contains("underlay_ip"));
        assert!(!product.contains("WireguardEndpoint"));
    }
}
