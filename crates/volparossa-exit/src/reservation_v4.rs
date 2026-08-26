//! Hard-incompatible v4 exit reservation phases.

use sha2::{Digest as _, Sha256};
use volparossa_protocol::{
    ClientSessionCapability, ControlMessageType, ControlPayload, ExitCapacityHold,
    ExitCapacityHoldRequest, ExitConfirmationReceipt, ExitReservationConfirmation,
    ExitReservationFinalizeRequest, ProbeAddressFamily, ProbeLegEvidence, RelayAuthorization,
    RelayProbePermit, RelayProbePermitRequest, RelayProbeResult, SignedEnvelope,
    exit_confirmation_envelope_hash, finalized_reservation_bundle_hash, generate_nonce,
    sign_control_message_with, verify_control_message, verify_relay_reservation,
};

#[allow(
    clippy::wildcard_imports,
    reason = "private phase module extends parent service internals"
)]
use super::*;

/// Exit-signed coupled capability and short capacity-hold response.
#[derive(Clone)]
pub struct AcceptedExitCapacityHold {
    signed_capability: Vec<u8>,
    signed_hold: Vec<u8>,
    reservation_id: [u8; ID_BYTES],
    hold_id: [u8; ID_BYTES],
    expires_at_ms: u64,
}

impl AcceptedExitCapacityHold {
    /// Canonical exit-signed session capability.
    #[must_use]
    pub fn signed_capability(&self) -> &[u8] {
        &self.signed_capability
    }

    /// Canonical exit-signed short capacity hold.
    #[must_use]
    pub fn signed_hold(&self) -> &[u8] {
        &self.signed_hold
    }

    /// Opaque reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Opaque hold identifier.
    #[must_use]
    pub const fn hold_id(&self) -> &[u8; ID_BYTES] {
        &self.hold_id
    }

    /// Exclusive short hold expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedExitCapacityHold {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedExitCapacityHold")
            .field("reservation_id", &self.reservation_id)
            .field("hold_id", &self.hold_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Exit-signed authorization for one exact bounded probe.
#[derive(Clone)]
pub struct AcceptedRelayProbePermit {
    encoded: Vec<u8>,
    reservation_id: [u8; ID_BYTES],
    path_id: u32,
    expires_at_ms: u64,
}

impl AcceptedRelayProbePermit {
    /// Canonical exit-signed probe permit.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Opaque reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Context-local path number.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Exclusive short permit expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedRelayProbePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedRelayProbePermit")
            .field("path_id", &self.path_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Exit-signed acknowledgement for one exact client confirmation frame.
#[derive(Clone)]
pub struct AcceptedExitConfirmation {
    signed_receipt: Vec<u8>,
    confirmed_path: ConfirmedExitPath,
    expires_at_ms: u64,
}

impl AcceptedExitConfirmation {
    /// Canonical exit-signed positive receipt.
    #[must_use]
    pub fn signed_receipt(&self) -> &[u8] {
        &self.signed_receipt
    }

    /// Typed stored relay-to-exit endpoint binding.
    #[must_use]
    pub const fn confirmed_path(&self) -> &ConfirmedExitPath {
        &self.confirmed_path
    }

    /// Exclusive receipt expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedExitConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedExitConfirmation")
            .field("path_id", &self.confirmed_path.path_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Immutable, already signature- and scope-verified probe evidence.
pub struct ProbeEvidence<'a> {
    signed_permit: &'a [u8],
    signed_result: &'a [u8],
    permit: &'a RelayProbePermit,
    client_relay: &'a ProbeLegEvidence,
    relay_exit: &'a ProbeLegEvidence,
    transport: Transport,
    address_family: ProbeAddressFamily,
}

impl ProbeEvidence<'_> {
    /// Exact canonical exit-signed permit bytes.
    #[must_use]
    pub const fn signed_permit(&self) -> &[u8] {
        self.signed_permit
    }

    /// Exact canonical relay-signed result bytes.
    #[must_use]
    pub const fn signed_result(&self) -> &[u8] {
        self.signed_result
    }

    /// Context-local path number.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.permit.path_id
    }

    /// Typed transport measured by the probe.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Typed network family measured by the probe.
    #[must_use]
    pub const fn address_family(&self) -> ProbeAddressFamily {
        self.address_family
    }

    /// Required client-to-relay directional measurements.
    #[must_use]
    pub const fn client_relay(&self) -> &ProbeLegEvidence {
        self.client_relay
    }

    /// Required relay-to-exit directional measurements.
    #[must_use]
    pub const fn relay_exit(&self) -> &ProbeLegEvidence {
        self.relay_exit
    }
}

/// Failure returned by a real external probe-evidence verifier.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProbeEvidenceError {
    /// No producer with helper-proven endpoints and an exit receipt exists.
    #[error("probe evidence producer is unavailable")]
    Unavailable,
    /// The configured producer rejected the otherwise well-formed evidence.
    #[error("probe evidence rejected: {0}")]
    Rejected(&'static str),
}

/// Verification boundary for external, cryptographic probe evidence.
///
/// Structural relay results alone are never sufficient. A production
/// implementation must authenticate a real helper-proven client-to-relay-to-exit
/// probe and an exit-participating receipt. No such implementation ships yet.
pub trait ProbeEvidenceVerifier {
    /// Verify one immutable, signature- and scope-checked probe artifact.
    ///
    /// # Errors
    ///
    /// Returns unavailable until a real producer exists, or rejected when its
    /// cryptographic/external receipt does not match this exact artifact.
    fn verify(&self, evidence: &ProbeEvidence<'_>) -> Result<(), ProbeEvidenceError>;
}

struct UnavailableProbeEvidenceVerifier;

impl ProbeEvidenceVerifier for UnavailableProbeEvidenceVerifier {
    fn verify(&self, _evidence: &ProbeEvidence<'_>) -> Result<(), ProbeEvidenceError> {
        Err(ProbeEvidenceError::Unavailable)
    }
}

struct UnavailableExitNativeRouteIdentityProvider;

impl ExitNativeRouteIdentityProvider for UnavailableExitNativeRouteIdentityProvider {
    fn provide(
        &mut self,
        _request: &ExitNativeRouteIdentityRequest,
    ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
        Err(ExitNativeRouteIdentityError::Unavailable)
    }
}

struct VerifiedProbeArtifact {
    signed_permit: Vec<u8>,
    signed_result: Vec<u8>,
    permit: RelayProbePermit,
    result: RelayProbeResult,
}

impl VerifiedProbeArtifact {
    fn evidence(&self) -> Result<ProbeEvidence<'_>, ExitError> {
        Ok(ProbeEvidence {
            signed_permit: &self.signed_permit,
            signed_result: &self.signed_result,
            permit: &self.permit,
            client_relay: self
                .result
                .client_relay
                .as_ref()
                .ok_or(ExitError::InvalidGrant("client-relay probe evidence"))?,
            relay_exit: self
                .result
                .relay_exit
                .as_ref()
                .ok_or(ExitError::InvalidGrant("relay-exit probe evidence"))?,
            transport: Transport::try_from(self.result.transport)
                .map_err(|_| ExitError::InvalidGrant("probe transport"))?,
            address_family: ProbeAddressFamily::try_from(self.result.address_family)
                .map_err(|_| ExitError::InvalidGrant("probe address family"))?,
        })
    }
}

impl ExitService {
    /// Hold capacity without receiving or committing to any relay selection.
    ///
    /// The forwarding connection must authenticate the exact control-relay
    /// Node ID and Peer ID committed by the client-session-signed request.
    ///
    /// # Errors
    ///
    /// Rejects disabled mode, stale policy, wrong forwarding identity, replay,
    /// invalid session/exit scope, capacity exhaustion, or signing failure.
    #[allow(clippy::too_many_lines, reason = "single fail-atomic hold transaction")]
    pub fn hold_capacity_with<F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        mut signer: F,
    ) -> Result<AcceptedExitCapacityHold, ExitError>
    where
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_local_identity(local_public_key)?;
        self.purge_expired(now_ms);

        let request_hash: [u8; NODE_ID_BYTES] = Sha256::digest(encoded_request).into();
        if let Some(cached) = cached_response(
            self.hold_response_cache.get(&request_hash),
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
        )? {
            return Ok(cached);
        }
        self.ensure_response_cache_capacity()?;

        let verified = verify_control_message::<ExitCapacityHoldRequest>(
            encoded_request,
            now_ms,
            TimePolicy::default(),
            &mut self.hold_replay,
        )?;
        let replay_entry = (*verified.sender_id(), *verified.nonce());
        let request_public_key = *verified.sender_public_key();
        let request = verified.into_message();
        let outcome = (|| {
            let exit_peer_id = peer_id_from_public_key(&local_public_key)?;
            if request.exit_node_id.as_slice() != self.config.node_id
                || request.exit_peer_id != exit_peer_id
                || request.client_session_public_key.as_slice() != request_public_key
                || request.control_relay_node_id.as_slice() != authenticated_control_relay_node_id
                || request.control_relay_peer_id != authenticated_control_relay_peer_id
                || request.policy_hash.as_slice() != self.policy.policy_hash()
            {
                return Err(ExitError::InvalidGrant("capacity hold scope"));
            }

            let reservation_id = fixed(&request.reservation_id, "reservation id")?;
            let route_context_id = fixed(&request.route_context_id, "route context")?;
            let reservation_key = text_id::<ReservationId>(&reservation_id)?;
            if self.endpoint_states.contains_key(&reservation_key) {
                return Err(ExitError::InvalidGrant("reservation already exists"));
            }

            let capability_id = fresh_id();
            let hold_id = fresh_id();
            let capability_nonce = generate_nonce();
            let capability = ClientSessionCapability {
                capability_id: capability_id.to_vec(),
                reservation_id: request.reservation_id.clone(),
                route_context_id: request.route_context_id.clone(),
                client_session_id: request.client_session_id.clone(),
                client_session_public_key: request.client_session_public_key.clone(),
                exit_node_id: request.exit_node_id.clone(),
                exit_boot_id: self.exit_boot_id.to_vec(),
                control_relay_node_id: request.control_relay_node_id.clone(),
                control_relay_peer_id: request.control_relay_peer_id.clone(),
                policy_hash: request.policy_hash.clone(),
                allowed_transports: request.allowed_transports.clone(),
                reserved_up_mbps: request.reserved_up_mbps,
                reserved_down_mbps: request.reserved_down_mbps,
                maximum_paths: request.maximum_paths,
                probe_permit_limit: request.probe_permit_limit,
                created_at_ms: request.created_at_ms,
                expires_at_ms: request.reservation_expires_at_ms,
                nonce: capability_nonce.to_vec(),
                exit_peer_id: request.exit_peer_id.clone(),
            };
            let signed_capability = sign_control_message_with(
                &capability,
                local_public_key,
                capability.created_at_ms,
                capability.expires_at_ms,
                capability_nonce,
                TimePolicy::default(),
                |bytes| signer(bytes),
            )?;

            let hold_nonce = generate_nonce();
            let hold = ExitCapacityHold {
                hold_id: hold_id.to_vec(),
                client_session_capability: signed_capability.clone(),
                reservation_id: request.reservation_id.clone(),
                route_context_id: request.route_context_id.clone(),
                exit_node_id: request.exit_node_id.clone(),
                exit_boot_id: self.exit_boot_id.to_vec(),
                client_session_id: request.client_session_id.clone(),
                policy_hash: request.policy_hash.clone(),
                allowed_transports: request.allowed_transports.clone(),
                reserved_up_mbps: request.reserved_up_mbps,
                reserved_down_mbps: request.reserved_down_mbps,
                maximum_paths: request.maximum_paths,
                probe_permit_limit: request.probe_permit_limit,
                created_at_ms: request.created_at_ms,
                expires_at_ms: request.expires_at_ms,
                nonce: hold_nonce.to_vec(),
                exit_peer_id: request.exit_peer_id.clone(),
                control_relay_node_id: request.control_relay_node_id.clone(),
                control_relay_peer_id: request.control_relay_peer_id.clone(),
                reservation_expires_at_ms: request.reservation_expires_at_ms,
            };
            let signed_hold = sign_control_message_with(
                &hold,
                local_public_key,
                hold.created_at_ms,
                hold.expires_at_ms,
                hold_nonce,
                TimePolicy::default(),
                |bytes| signer(bytes),
            )?;

            let allocation = hold_allocation(&request, now_ms)?;
            self.ledger_mut()?
                .reserve(allocation, unix_seconds(now_ms))?;
            let state = ExitReservationState {
                phase: ExitReservationPhase::Held,
                route_context_id,
                client_session_id: fixed(&request.client_session_id, "client session id")?,
                client_session_public_key: request_public_key,
                capability_id,
                hold_id,
                exit_boot_id: self.exit_boot_id,
                exit_peer_id: request.exit_peer_id.clone(),
                control_relay_node_id: *authenticated_control_relay_node_id,
                control_relay_peer_id: authenticated_control_relay_peer_id.to_vec(),
                signed_capability: signed_capability.clone(),
                signed_hold: signed_hold.clone(),
                policy_hash: fixed(&request.policy_hash, "policy hash")?,
                allowed_transports: request.allowed_transports.clone(),
                reserved_up_mbps: request.reserved_up_mbps,
                reserved_down_mbps: request.reserved_down_mbps,
                maximum_paths: request.maximum_paths,
                probe_permit_limit: request.probe_permit_limit,
                created_at_ms: request.created_at_ms,
                hold_expires_at_ms: request.expires_at_ms,
                expires_at_ms: request.reservation_expires_at_ms,
                permits: HashMap::new(),
                finalize_id: None,
                finalized_bundle_hash: None,
                paths: Vec::new(),
            };
            if self
                .endpoint_states
                .insert(reservation_key.clone(), state)
                .is_some()
            {
                if self.ledger_mut()?.release(&reservation_key).is_err() {
                    return Err(ExitError::LedgerInvariant);
                }
                return Err(ExitError::LeaseInvariant);
            }
            self.sync_metrics();

            Ok(AcceptedExitCapacityHold {
                signed_capability,
                signed_hold,
                reservation_id,
                hold_id,
                expires_at_ms: request.expires_at_ms,
            })
        })();
        match outcome {
            Ok(response) => {
                self.hold_response_cache.insert(
                    request_hash,
                    CachedControlResponse {
                        request: encoded_request.to_vec(),
                        authenticated_control_relay_node_id: *authenticated_control_relay_node_id,
                        authenticated_control_relay_peer_id: authenticated_control_relay_peer_id
                            .to_vec(),
                        expires_at_ms: response.expires_at_ms,
                        response: response.clone(),
                    },
                );
                Ok(response)
            }
            Err(error) => {
                let _ = self.hold_replay.rollback(&replay_entry.0, &replay_entry.1);
                Err(error)
            }
        }
    }

    /// Issue one short exit-signed protocol permit for a selected relay probe.
    ///
    /// This is only a bounded protocol primitive. It neither provisions probe
    /// endpoints nor proves that a client-relay-exit probe can be produced.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign holds, wrong forwarding scope, duplicate relay/path
    /// selection, replay, expiry, or signing failure.
    #[allow(
        clippy::too_many_lines,
        reason = "single fail-atomic permit transaction"
    )]
    pub fn issue_probe_permit_with<F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        signer: F,
    ) -> Result<AcceptedRelayProbePermit, ExitError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_local_identity(local_public_key)?;
        self.purge_expired(now_ms);
        let request_hash: [u8; NODE_ID_BYTES] = Sha256::digest(encoded_request).into();
        if let Some(cached) = cached_response(
            self.permit_response_cache.get(&request_hash),
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
        )? {
            return Ok(cached);
        }
        self.ensure_response_cache_capacity()?;

        let verified = verify_control_message::<RelayProbePermitRequest>(
            encoded_request,
            now_ms,
            TimePolicy::default(),
            &mut self.permit_replay,
        )?;
        let replay_entry = (*verified.sender_id(), *verified.nonce());
        let request_public_key = *verified.sender_public_key();
        let request = verified.into_message();
        let outcome = (|| {
            let hold: ExitCapacityHold = decode_signed_payload(&request.exit_capacity_hold)?;
            if hold.exit_boot_id.as_slice() != self.exit_boot_id {
                return Err(ExitError::ExitBootMismatch);
            }
            let reservation_id = fixed(&hold.reservation_id, "reservation id")?;
            let reservation_key = text_id::<ReservationId>(&reservation_id)?;
            let state = self
                .endpoint_states
                .get(&reservation_key)
                .ok_or(ExitError::InvalidGrant("unknown capacity hold"))?;
            if state.phase != ExitReservationPhase::Held
                || state.signed_hold != request.exit_capacity_hold
                || state.signed_capability != request.client_session_capability
                || state.exit_boot_id != self.exit_boot_id
                || state.client_session_id.as_slice() != request.client_session_id
                || state.client_session_public_key != request_public_key
                || state.control_relay_node_id != *authenticated_control_relay_node_id
                || state.control_relay_peer_id != authenticated_control_relay_peer_id
                || request.control_relay_node_id.as_slice() != authenticated_control_relay_node_id
                || request.control_relay_peer_id != authenticated_control_relay_peer_id
                || request.exit_node_id.as_slice() != self.config.node_id
                || request.exit_peer_id != state.exit_peer_id
                || request.created_at_ms < state.created_at_ms
                || request.expires_at_ms > state.hold_expires_at_ms
                || !state.allowed_transports.contains(&request.transport)
            {
                return Err(ExitError::InvalidGrant("probe permit scope"));
            }
            if request.path_id > state.probe_permit_limit
                || state.permits.len()
                    >= usize::try_from(state.probe_permit_limit).unwrap_or(usize::MAX)
            {
                return Err(ExitError::InvalidGrant("probe permit limit"));
            }
            if state.permits.contains_key(&request.path_id)
                || state.permits.values().any(|permit| {
                    permit.relay_node_id.as_slice() == request.relay_node_id
                        || permit.relay_peer_id == request.relay_peer_id
                })
            {
                return Err(ExitError::InvalidGrant("duplicate probe path"));
            }

            let nonce = generate_nonce();
            let permit = RelayProbePermit {
                probe_id: request.probe_id.clone(),
                hold_id: state.hold_id.to_vec(),
                capability_id: state.capability_id.to_vec(),
                reservation_id: reservation_id.to_vec(),
                route_context_id: state.route_context_id.to_vec(),
                client_session_id: state.client_session_id.to_vec(),
                exit_node_id: self.config.node_id.to_vec(),
                exit_boot_id: self.exit_boot_id.to_vec(),
                control_relay_node_id: state.control_relay_node_id.to_vec(),
                control_relay_peer_id: state.control_relay_peer_id.clone(),
                relay_node_id: request.relay_node_id.clone(),
                relay_peer_id: request.relay_peer_id.clone(),
                path_id: request.path_id,
                created_at_ms: request.created_at_ms,
                expires_at_ms: request.expires_at_ms,
                nonce: nonce.to_vec(),
                exit_peer_id: state.exit_peer_id.clone(),
                policy_hash: state.policy_hash.to_vec(),
                transport: request.transport,
                address_family: request.address_family,
            };
            let encoded = sign_control_message_with(
                &permit,
                local_public_key,
                permit.created_at_ms,
                permit.expires_at_ms,
                nonce,
                TimePolicy::default(),
                signer,
            )?;
            let stored = ExitProbePermitState {
                encoded: encoded.clone(),
                probe_id: fixed(&permit.probe_id, "probe id")?,
                relay_node_id: fixed(&permit.relay_node_id, "relay node id")?,
                relay_peer_id: permit.relay_peer_id.clone(),
                path_id: permit.path_id,
                transport: permit.transport,
                address_family: permit.address_family,
                expires_at_ms: permit.expires_at_ms,
            };
            self.endpoint_states
                .get_mut(&reservation_key)
                .ok_or(ExitError::LeaseInvariant)?
                .permits
                .insert(permit.path_id, stored);
            Ok(AcceptedRelayProbePermit {
                encoded,
                reservation_id,
                path_id: permit.path_id,
                expires_at_ms: permit.expires_at_ms,
            })
        })();
        match outcome {
            Ok(response) => {
                self.permit_response_cache.insert(
                    request_hash,
                    CachedControlResponse {
                        request: encoded_request.to_vec(),
                        authenticated_control_relay_node_id: *authenticated_control_relay_node_id,
                        authenticated_control_relay_peer_id: authenticated_control_relay_peer_id
                            .to_vec(),
                        expires_at_ms: response.expires_at_ms,
                        response: response.clone(),
                    },
                );
                Ok(response)
            }
            Err(error) => {
                let _ = self
                    .permit_replay
                    .rollback(&replay_entry.0, &replay_entry.1);
                Err(error)
            }
        }
    }

    fn ensure_local_identity(
        &self,
        local_public_key: [u8; NODE_ID_BYTES],
    ) -> Result<(), ExitError> {
        if node_id_from_public_key(&local_public_key) != self.config.node_id {
            return Err(ExitError::LocalIdentityMismatch);
        }
        Ok(())
    }

    fn ensure_response_cache_capacity(&self) -> Result<(), ExitError> {
        let entries = self
            .hold_response_cache
            .len()
            .saturating_add(self.permit_response_cache.len())
            .saturating_add(self.finalize_response_cache.len())
            .saturating_add(self.confirmation_response_cache.len());
        if entries >= self.response_cache_capacity {
            Err(ExitError::IdempotencyCapacity)
        } else {
            Ok(())
        }
    }
}

pub(super) fn fresh_exit_boot_id() -> [u8; ID_BYTES] {
    loop {
        let nonce = generate_nonce();
        let mut boot_id = [0_u8; ID_BYTES];
        boot_id.copy_from_slice(&nonce[..ID_BYTES]);
        if boot_id != [0; ID_BYTES] {
            return boot_id;
        }
    }
}

fn fresh_id() -> [u8; ID_BYTES] {
    fresh_exit_boot_id()
}

fn cached_response<T: Clone>(
    cached: Option<&CachedControlResponse<T>>,
    request: &[u8],
    authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
    authenticated_control_relay_peer_id: &[u8],
) -> Result<Option<T>, ExitError> {
    let Some(cached) = cached else {
        return Ok(None);
    };
    if cached.request != request {
        return Err(ExitError::InvalidGrant(
            "idempotency request hash collision",
        ));
    }
    if cached.authenticated_control_relay_node_id != *authenticated_control_relay_node_id
        || cached.authenticated_control_relay_peer_id != authenticated_control_relay_peer_id
    {
        return Err(ExitError::ControlRelayMismatch);
    }
    Ok(Some(cached.response.clone()))
}

fn decode_signed_payload<T: ControlPayload>(encoded: &[u8]) -> Result<T, ExitError> {
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE)?;
    let actual = ControlMessageType::try_from(envelope.message_type)
        .map_err(|_| ProtocolError::UnknownMessageType(envelope.message_type))?;
    if actual != T::MESSAGE_TYPE {
        return Err(ProtocolError::WrongMessageType {
            expected: T::MESSAGE_TYPE,
            actual,
        }
        .into());
    }
    let message: T = decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
    message.validate()?;
    Ok(message)
}

fn peer_id_from_public_key(public_key: &[u8; NODE_ID_BYTES]) -> Result<Vec<u8>, ExitError> {
    let ed25519 = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map_err(|_| ExitError::InvalidGrant("Ed25519 Peer ID key"))?;
    Ok(libp2p_identity::PublicKey::from(ed25519)
        .to_peer_id()
        .to_bytes())
}

fn hold_allocation(
    request: &ExitCapacityHoldRequest,
    now_ms: u64,
) -> Result<AuthorizedReservation, ExitError> {
    let allowed_transports = request
        .allowed_transports
        .iter()
        .map(|value| match Transport::try_from(*value) {
            Ok(Transport::TcpMptcp) => Ok(CoreTransport::TcpMptcp),
            Ok(Transport::UdpSinglePath) => Ok(CoreTransport::UdpSinglePath),
            Ok(Transport::MultipathQuic) => Ok(CoreTransport::MultipathQuic),
            Ok(Transport::Unspecified) | Err(_) => Err(ExitError::InvalidGrant("transport")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let allocation = AuthorizedReservation {
        reservation_id: text_id::<ReservationId>(&request.reservation_id)?,
        route_context_id: text_id::<RouteContextId>(&request.route_context_id)?,
        service_node_id: text_id::<NodeId>(&request.exit_node_id)?,
        client_ephemeral_id: text_id::<ClientEphemeralId>(&request.client_session_id)?,
        role: ServiceRole::Exit,
        allowed_transports,
        bandwidth: Bandwidth::new(
            u32::try_from(request.reserved_up_mbps)
                .map_err(|_| ExitError::InvalidGrant("upload rate"))?,
            u32::try_from(request.reserved_down_mbps)
                .map_err(|_| ExitError::InvalidGrant("download rate"))?,
        )
        .map_err(|_| ExitError::InvalidGrant("bandwidth"))?,
        maximum_paths: u8::try_from(request.maximum_paths)
            .map_err(|_| ExitError::InvalidGrant("maximum paths"))?,
        created_at: unix_seconds(request.created_at_ms),
        expires_at: unix_seconds(request.reservation_expires_at_ms),
    };
    if allocation.expires_at <= allocation.created_at
        || allocation.expires_at.is_expired_at(unix_seconds(now_ms))
    {
        return Err(ExitError::InvalidGrant("millisecond lifetime"));
    }
    Ok(allocation)
}
struct PreparedFinalPath {
    path_id: u32,
    relay_node_id: [u8; NODE_ID_BYTES],
    relay_peer_id: Vec<u8>,
    client_public_key: WireGuardPublicKey,
    exit_endpoint: ExitEndpointLease,
}

impl ExitService {
    /// Finalize a held allocation through the production fail-closed evidence boundary.
    ///
    /// Structural probe messages are insufficient production evidence. Until a
    /// helper-proven, exit-participating producer is wired, this method returns
    /// `ProbeEvidenceUnavailable` after complete signature and scope checks and
    /// before endpoint allocation, signing, or state commit.
    ///
    /// # Errors
    ///
    /// Rejects stale or foreign artifacts, incomplete probe scope, unavailable
    /// production evidence, endpoint lease failures, replay, or signing failure.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit evidence and signing boundaries"
    )]
    pub fn finalize_reservation_with<E, F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        endpoint_provider: E,
        signer: F,
    ) -> Result<AcceptedExitReservationBundle, ExitError>
    where
        E: FnMut(u32) -> Option<ExitEndpointLease>,
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.finalize_reservation_with_evidence_verifier(
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
            now_ms,
            local_public_key,
            &UnavailableProbeEvidenceVerifier,
            endpoint_provider,
            signer,
        )
    }

    /// Finalize a held allocation with an explicit external proof verifier.
    ///
    /// The boundary is for a future cryptographic producer and tests which
    /// validate exact expected artifacts. An accept-all verifier is invalid.
    ///
    /// # Errors
    ///
    /// In addition to production failures, returns `ProbeEvidenceRejected`
    /// when the verifier rejects any exact artifact.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "single fail-atomic evidence/finalize transaction"
    )]
    pub fn finalize_reservation_with_evidence_verifier<V, E, F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        evidence_verifier: &V,
        endpoint_provider: E,
        signer: F,
    ) -> Result<AcceptedExitReservationBundle, ExitError>
    where
        V: ProbeEvidenceVerifier + ?Sized,
        E: FnMut(u32) -> Option<ExitEndpointLease>,
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.finalize_reservation_with_optional_native_identity(
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
            now_ms,
            local_public_key,
            evidence_verifier,
            &mut UnavailableExitNativeRouteIdentityProvider,
            None,
            endpoint_provider,
            signer,
        )
    }

    /// Finalize with explicit probe evidence and native-route identity providers.
    ///
    /// This is the only finalization boundary that can retain TLS ownership.
    /// `exit_native_instance_id` must be the exact non-zero process identity
    /// returned by the native exit preflight for this attempt.
    /// Neither a returned authorization nor the signed public response activates
    /// a native backend or listener.
    ///
    /// # Errors
    ///
    /// In addition to all normal finalization failures, rejects unavailable,
    /// malformed or request-mismatched native-route identity ownership.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "single fail-atomic evidence, identity and finalize transaction"
    )]
    pub fn finalize_reservation_with_providers<V, P, E, F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        evidence_verifier: &V,
        identity_provider: &mut P,
        exit_native_instance_id: [u8; NODE_ID_BYTES],
        endpoint_provider: E,
        signer: F,
    ) -> Result<AcceptedExitReservationBundle, ExitError>
    where
        V: ProbeEvidenceVerifier + ?Sized,
        P: ExitNativeRouteIdentityProvider + ?Sized,
        E: FnMut(u32) -> Option<ExitEndpointLease>,
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.finalize_reservation_with_optional_native_identity(
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
            now_ms,
            local_public_key,
            evidence_verifier,
            identity_provider,
            Some(exit_native_instance_id),
            endpoint_provider,
            signer,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "single fail-atomic evidence, identity and finalize transaction"
    )]
    fn finalize_reservation_with_optional_native_identity<V, P, E, F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        evidence_verifier: &V,
        identity_provider: &mut P,
        exit_native_instance_id: Option<[u8; NODE_ID_BYTES]>,
        mut endpoint_provider: E,
        mut signer: F,
    ) -> Result<AcceptedExitReservationBundle, ExitError>
    where
        V: ProbeEvidenceVerifier + ?Sized,
        P: ExitNativeRouteIdentityProvider + ?Sized,
        E: FnMut(u32) -> Option<ExitEndpointLease>,
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_local_identity(local_public_key)?;
        self.purge_expired(now_ms);

        let request_hash: [u8; NODE_ID_BYTES] = Sha256::digest(encoded_request).into();
        if let Some(cached) = cached_response(
            self.finalize_response_cache.get(&request_hash),
            encoded_request,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
        )? {
            return Ok(cached);
        }
        self.ensure_response_cache_capacity()?;

        let verified = verify_control_message::<ExitReservationFinalizeRequest>(
            encoded_request,
            now_ms,
            TimePolicy::default(),
            &mut self.finalize_replay,
        )?;
        let finalize_entry = (*verified.sender_id(), *verified.nonce());
        let request_public_key = *verified.sender_public_key();
        let request = verified.into_message();
        let phase_expires_at_ms = request.expires_at_ms;
        let mut probe_entries = Vec::with_capacity(request.relay_paths.len());

        let outcome = (|| {
            let capability: ClientSessionCapability =
                decode_signed_payload(&request.client_session_capability)?;
            let hold: ExitCapacityHold = decode_signed_payload(&request.exit_capacity_hold)?;
            if capability.exit_boot_id.as_slice() != self.exit_boot_id
                || hold.exit_boot_id.as_slice() != self.exit_boot_id
            {
                return Err(ExitError::ExitBootMismatch);
            }

            let reservation_id = fixed(&request.reservation_id, "reservation id")?;
            let reservation_key = text_id::<ReservationId>(&reservation_id)?;
            let state = self
                .endpoint_states
                .get(&reservation_key)
                .cloned()
                .ok_or(ExitError::InvalidGrant("unknown capacity hold"))?;
            let final_path_count = u32::try_from(request.relay_paths.len())
                .map_err(|_| ExitError::InvalidGrant("finalization path count"))?;
            if state.phase != ExitReservationPhase::Held
                || state.signed_capability != request.client_session_capability
                || state.signed_hold != request.exit_capacity_hold
                || state.exit_boot_id != self.exit_boot_id
                || state.client_session_id.as_slice() != request.client_session_id
                || state.client_session_public_key != request_public_key
                || state.route_context_id.as_slice() != request.route_context_id
                || request.exit_node_id.as_slice() != self.config.node_id
                || request.exit_peer_id != state.exit_peer_id
                || request.control_relay_node_id.as_slice() != authenticated_control_relay_node_id
                || request.control_relay_peer_id != authenticated_control_relay_peer_id
                || state.control_relay_node_id != *authenticated_control_relay_node_id
                || state.control_relay_peer_id != authenticated_control_relay_peer_id
                || request.created_at_ms < state.created_at_ms
                || request.expires_at_ms > state.hold_expires_at_ms
                || state.hold_expires_at_ms <= now_ms
                || !(1..=state.maximum_paths).contains(&final_path_count)
            {
                return Err(ExitError::InvalidGrant("finalization scope"));
            }
            if capability.capability_id.as_slice() != state.capability_id
                || capability.reservation_id.as_slice() != reservation_id
                || capability.route_context_id.as_slice() != state.route_context_id
                || capability.client_session_id.as_slice() != state.client_session_id
                || capability.client_session_public_key.as_slice()
                    != state.client_session_public_key
                || capability.exit_node_id.as_slice() != self.config.node_id
                || capability.exit_peer_id != state.exit_peer_id
                || capability.control_relay_node_id.as_slice() != state.control_relay_node_id
                || capability.control_relay_peer_id != state.control_relay_peer_id
                || capability.policy_hash.as_slice() != state.policy_hash
                || capability.allowed_transports != state.allowed_transports
                || capability.reserved_up_mbps != state.reserved_up_mbps
                || capability.reserved_down_mbps != state.reserved_down_mbps
                || capability.maximum_paths != state.maximum_paths
                || capability.probe_permit_limit != state.probe_permit_limit
                || capability.created_at_ms != state.created_at_ms
                || capability.expires_at_ms != state.expires_at_ms
                || hold.client_session_capability != state.signed_capability
                || hold.hold_id.as_slice() != state.hold_id
                || hold.reservation_id.as_slice() != reservation_id
                || hold.route_context_id.as_slice() != state.route_context_id
                || hold.client_session_id.as_slice() != state.client_session_id
                || hold.exit_node_id.as_slice() != self.config.node_id
                || hold.exit_peer_id != state.exit_peer_id
                || hold.control_relay_node_id.as_slice() != state.control_relay_node_id
                || hold.control_relay_peer_id != state.control_relay_peer_id
                || hold.policy_hash.as_slice() != state.policy_hash
                || hold.allowed_transports != state.allowed_transports
                || hold.reserved_up_mbps != state.reserved_up_mbps
                || hold.reserved_down_mbps != state.reserved_down_mbps
                || hold.maximum_paths != state.maximum_paths
                || hold.probe_permit_limit != state.probe_permit_limit
                || hold.created_at_ms != state.created_at_ms
                || hold.expires_at_ms != state.hold_expires_at_ms
                || hold.reservation_expires_at_ms != state.expires_at_ms
            {
                return Err(ExitError::InvalidGrant("held capability scope"));
            }

            let finalize_id = fixed(&request.finalize_id, "finalize id")?;
            if self
                .native_route_identity_owners
                .contains_key(&reservation_key)
            {
                return Err(ExitError::LeaseInvariant);
            }
            let mut artifacts = Vec::with_capacity(request.relay_paths.len());
            for path in &request.relay_paths {
                let stored = state
                    .permits
                    .get(&path.path_id)
                    .ok_or(ExitError::InvalidGrant("unknown probe permit"))?;
                if stored.encoded != path.relay_probe_permit || stored.expires_at_ms <= now_ms {
                    return Err(ExitError::InvalidGrant("probe permit scope"));
                }
                let permit: RelayProbePermit = decode_signed_payload(&path.relay_probe_permit)?;
                let verified_result = verify_control_message::<RelayProbeResult>(
                    &path.relay_probe_result,
                    now_ms,
                    TimePolicy::default(),
                    &mut self.probe_replay,
                )?;
                let entry = (*verified_result.sender_id(), *verified_result.nonce());
                let result_public_key = *verified_result.sender_public_key();
                let result = verified_result.into_message();
                probe_entries.push(entry);
                if entry.0.as_slice() != path.relay_node_id
                    || peer_id_from_public_key(&result_public_key)? != path.relay_peer_id
                    || !same_probe_scope(
                        &state,
                        self.config.node_id,
                        reservation_id,
                        path,
                        stored,
                        &permit,
                        &result,
                    )
                {
                    return Err(ExitError::InvalidGrant("relay probe scope"));
                }
                artifacts.push(VerifiedProbeArtifact {
                    signed_permit: path.relay_probe_permit.clone(),
                    signed_result: path.relay_probe_result.clone(),
                    permit,
                    result,
                });
            }

            for artifact in &artifacts {
                evidence_verifier
                    .verify(&artifact.evidence()?)
                    .map_err(map_probe_evidence_error)?;
            }

            let exit_native_instance_id =
                exit_native_instance_id.ok_or(ExitNativeRouteIdentityError::Unavailable)?;
            let native_identity_request = ExitNativeRouteIdentityRequest::new(
                reservation_id,
                state.route_context_id,
                finalize_id,
                fixed(&request.auth_commitment, "native auth commitment")?,
                request.masque_context_id,
                fixed(
                    &request.client_native_instance_id,
                    "client native instance id",
                )?,
                exit_native_instance_id,
            )?;
            let identity_owner = identity_provider.provide(&native_identity_request)?;
            if identity_owner.request() != &native_identity_request {
                return Err(ExitNativeRouteIdentityError::Rejected(
                    "native route identity provider scope",
                )
                .into());
            }

            let mut helper_handles = self
                .endpoint_states
                .values()
                .flat_map(|state| {
                    state.paths.iter().flat_map(|path| {
                        [
                            *path.exit_endpoint.context_handle().as_bytes(),
                            *path.exit_endpoint.lease_handle().as_bytes(),
                        ]
                    })
                })
                .collect::<HashSet<_>>();
            let mut wireguard_keys = self
                .endpoint_states
                .values()
                .flat_map(|state| {
                    state.paths.iter().flat_map(|path| {
                        [
                            path.client_public_key,
                            path.exit_endpoint.public_endpoint().public_key(),
                        ]
                    })
                })
                .collect::<HashSet<_>>();
            let mut listen_ports = self
                .endpoint_states
                .values()
                .flat_map(|state| {
                    state
                        .paths
                        .iter()
                        .map(|path| path.exit_endpoint.public_endpoint().listen_port())
                })
                .collect::<HashSet<_>>();
            let mut client_keys = Vec::with_capacity(request.relay_paths.len());
            for path in &request.relay_paths {
                let key = public_key(
                    &path.client_wireguard_public_key,
                    "client WireGuard public key",
                )?;
                if !wireguard_keys.insert(key) {
                    return Err(ExitError::InvalidGrant("distinct WireGuard endpoint keys"));
                }
                client_keys.push(key);
            }

            let mut expected_context_handle: Option<HelperContextHandle> = None;
            let mut prepared = Vec::with_capacity(request.relay_paths.len());
            for (path, client_public_key) in request.relay_paths.iter().zip(client_keys) {
                let endpoint =
                    endpoint_provider(path.path_id).ok_or(ExitError::EndpointUnavailable)?;
                if endpoint.route_context_id() != &state.route_context_id
                    || endpoint.path_id() != path.path_id
                {
                    return Err(ExitError::InvalidGrant("exit helper lease binding"));
                }
                match expected_context_handle {
                    Some(handle) if handle != endpoint.context_handle() => {
                        return Err(ExitError::InvalidGrant("exit helper context binding"));
                    }
                    Some(_) => {}
                    None => {
                        if !helper_handles.insert(*endpoint.context_handle().as_bytes()) {
                            return Err(ExitError::InvalidGrant("exit helper handle uniqueness"));
                        }
                        expected_context_handle = Some(endpoint.context_handle());
                    }
                }
                if !helper_handles.insert(*endpoint.lease_handle().as_bytes()) {
                    return Err(ExitError::InvalidGrant("exit helper handle uniqueness"));
                }
                let public = endpoint.public_endpoint();
                if !wireguard_keys.insert(public.public_key()) {
                    return Err(ExitError::InvalidGrant("distinct WireGuard endpoint keys"));
                }
                if !listen_ports.insert(public.listen_port()) {
                    return Err(ExitError::InvalidGrant(
                        "exit endpoint listen-port uniqueness",
                    ));
                }
                prepared.push(PreparedFinalPath {
                    path_id: path.path_id,
                    relay_node_id: fixed(&path.relay_node_id, "relay node id")?,
                    relay_peer_id: path.relay_peer_id.clone(),
                    client_public_key,
                    exit_endpoint: endpoint,
                });
            }

            let exit_nonce = generate_nonce();
            let exit_reservation = volparossa_protocol::ExitReservation {
                reservation_id: reservation_id.to_vec(),
                route_context_id: state.route_context_id.to_vec(),
                exit_node_id: self.config.node_id.to_vec(),
                client_session_id: state.client_session_id.to_vec(),
                allowed_transports: state.allowed_transports.clone(),
                reserved_up_mbps: state.reserved_up_mbps,
                reserved_down_mbps: state.reserved_down_mbps,
                maximum_paths: final_path_count,
                policy_hash: state.policy_hash.to_vec(),
                created_at_ms: state.created_at_ms,
                expires_at_ms: state.expires_at_ms,
                nonce: exit_nonce.to_vec(),
                capability_id: state.capability_id.to_vec(),
                client_session_public_key: state.client_session_public_key.to_vec(),
                exit_boot_id: self.exit_boot_id.to_vec(),
                hold_id: state.hold_id.to_vec(),
                finalize_id: finalize_id.to_vec(),
                control_relay_node_id: state.control_relay_node_id.to_vec(),
                control_relay_peer_id: state.control_relay_peer_id.clone(),
                exit_peer_id: state.exit_peer_id.clone(),
                native_route_identity: Some(identity_owner.public_identity().clone()),
            };
            let signed_exit_reservation = sign_control_message_with(
                &exit_reservation,
                local_public_key,
                exit_reservation.created_at_ms,
                exit_reservation.expires_at_ms,
                exit_nonce,
                TimePolicy::default(),
                |bytes| signer(bytes),
            )?;

            let mut relay_authorizations = Vec::with_capacity(prepared.len());
            let mut path_states = Vec::with_capacity(prepared.len());
            for path in prepared {
                let nonce = generate_nonce();
                let authorization = RelayAuthorization {
                    reservation_id: reservation_id.to_vec(),
                    route_context_id: state.route_context_id.to_vec(),
                    path_id: path.path_id,
                    relay_node_id: path.relay_node_id.to_vec(),
                    exit_node_id: self.config.node_id.to_vec(),
                    client_session_id: state.client_session_id.to_vec(),
                    allowed_transports: state.allowed_transports.clone(),
                    maximum_up_mbps: state.reserved_up_mbps,
                    maximum_down_mbps: state.reserved_down_mbps,
                    client_wireguard_public_key: path.client_public_key.as_bytes().to_vec(),
                    exit_wireguard_endpoint: Some(wire_endpoint(
                        path.exit_endpoint.public_endpoint(),
                    )),
                    policy_hash: state.policy_hash.to_vec(),
                    created_at_ms: state.created_at_ms,
                    expires_at_ms: state.expires_at_ms,
                    nonce: nonce.to_vec(),
                    relay_peer_id: path.relay_peer_id.clone(),
                    capability_id: state.capability_id.to_vec(),
                    client_session_public_key: state.client_session_public_key.to_vec(),
                    exit_boot_id: self.exit_boot_id.to_vec(),
                    hold_id: state.hold_id.to_vec(),
                    finalize_id: finalize_id.to_vec(),
                    control_relay_node_id: state.control_relay_node_id.to_vec(),
                    control_relay_peer_id: state.control_relay_peer_id.clone(),
                    exit_peer_id: state.exit_peer_id.clone(),
                };
                let encoded = sign_control_message_with(
                    &authorization,
                    local_public_key,
                    authorization.created_at_ms,
                    authorization.expires_at_ms,
                    nonce,
                    TimePolicy::default(),
                    |bytes| signer(bytes),
                )?;
                path_states.push(ExitPathState {
                    path_id: path.path_id,
                    relay_node_id: path.relay_node_id,
                    relay_peer_id: path.relay_peer_id,
                    client_public_key: path.client_public_key,
                    exit_endpoint: path.exit_endpoint,
                    authorization_hash: Sha256::digest(&encoded).into(),
                    relay_exit_endpoint: None,
                    relay_reservation_hash: None,
                });
                relay_authorizations.push(encoded);
            }
            let bundle_hash =
                finalized_reservation_bundle_hash(&signed_exit_reservation, &relay_authorizations)?;
            let accepted = AcceptedExitReservation {
                encoded: signed_exit_reservation,
                reservation_id,
                route_context_id: state.route_context_id,
                exit_node_id: self.config.node_id,
                allowed_transports: state.allowed_transports.clone(),
                maximum_paths: final_path_count,
                expires_at_ms: state.expires_at_ms,
                native_route_identity: identity_owner.public_identity().clone(),
                native_route_authorization_scope: identity_owner.authorization_scope(),
            };
            let response = AcceptedExitReservationBundle {
                accepted,
                relay_authorizations,
            };

            let live = self
                .endpoint_states
                .get_mut(&reservation_key)
                .ok_or(ExitError::LeaseInvariant)?;
            if live.phase != ExitReservationPhase::Held
                || live.signed_hold != state.signed_hold
                || live.signed_capability != state.signed_capability
            {
                return Err(ExitError::LeaseInvariant);
            }
            live.phase = ExitReservationPhase::Finalized;
            live.finalize_id = Some(finalize_id);
            live.finalized_bundle_hash = Some(bundle_hash);
            live.paths = path_states;
            live.permits.clear();
            Ok((response, reservation_key, identity_owner))
        })();

        match outcome {
            Ok((response, reservation_key, identity_owner)) => {
                let reservation_id = *response.reservation_id();
                self.permit_response_cache
                    .retain(|_, cached| cached.response.reservation_id() != &reservation_id);
                let previous_owner = self
                    .native_route_identity_owners
                    .insert(reservation_key, identity_owner);
                debug_assert!(previous_owner.is_none(), "checked unique owner insertion");
                self.finalize_response_cache.insert(
                    request_hash,
                    CachedControlResponse {
                        request: encoded_request.to_vec(),
                        authenticated_control_relay_node_id: *authenticated_control_relay_node_id,
                        authenticated_control_relay_peer_id: authenticated_control_relay_peer_id
                            .to_vec(),
                        response: response.clone(),
                        expires_at_ms: phase_expires_at_ms,
                    },
                );
                Ok(response)
            }
            Err(error) => {
                rollback_replay(&mut self.probe_replay, &probe_entries);
                let _ = self
                    .finalize_replay
                    .rollback(&finalize_entry.0, &finalize_entry.1);
                Err(error)
            }
        }
    }
}

fn same_probe_scope(
    state: &ExitReservationState,
    exit_node_id: [u8; NODE_ID_BYTES],
    reservation_id: [u8; ID_BYTES],
    path: &volparossa_protocol::FinalizedRelayPath,
    stored: &ExitProbePermitState,
    permit: &RelayProbePermit,
    result: &RelayProbeResult,
) -> bool {
    path.path_id == stored.path_id
        && path.relay_node_id.as_slice() == stored.relay_node_id
        && path.relay_peer_id == stored.relay_peer_id
        && permit.probe_id.as_slice() == stored.probe_id
        && permit.hold_id.as_slice() == state.hold_id
        && permit.capability_id.as_slice() == state.capability_id
        && permit.reservation_id.as_slice() == reservation_id
        && permit.route_context_id.as_slice() == state.route_context_id
        && permit.client_session_id.as_slice() == state.client_session_id
        && permit.exit_node_id.as_slice() == exit_node_id
        && permit.exit_boot_id.as_slice() == state.exit_boot_id
        && permit.control_relay_node_id.as_slice() == state.control_relay_node_id
        && permit.control_relay_peer_id == state.control_relay_peer_id
        && permit.relay_node_id.as_slice() == stored.relay_node_id
        && permit.relay_peer_id == stored.relay_peer_id
        && permit.path_id == stored.path_id
        && permit.exit_peer_id == state.exit_peer_id
        && permit.policy_hash.as_slice() == state.policy_hash
        && permit.transport == stored.transport
        && permit.address_family == stored.address_family
        && result.relay_probe_permit == stored.encoded
        && result.probe_id == permit.probe_id
        && result.relay_node_id == permit.relay_node_id
        && result.relay_peer_id == permit.relay_peer_id
        && result.exit_node_id == permit.exit_node_id
        && result.exit_peer_id == permit.exit_peer_id
        && result.exit_boot_id == permit.exit_boot_id
        && result.hold_id == permit.hold_id
        && result.capability_id == permit.capability_id
        && result.reservation_id == permit.reservation_id
        && result.route_context_id == permit.route_context_id
        && result.client_session_id == permit.client_session_id
        && result.policy_hash == permit.policy_hash
        && result.transport == permit.transport
        && result.address_family == permit.address_family
        && result.measured_at_ms >= permit.created_at_ms
        && result.expires_at_ms <= permit.expires_at_ms
}

fn map_probe_evidence_error(error: ProbeEvidenceError) -> ExitError {
    match error {
        ProbeEvidenceError::Unavailable => ExitError::ProbeEvidenceUnavailable,
        ProbeEvidenceError::Rejected(reason) => ExitError::ProbeEvidenceRejected(reason),
    }
}

fn rollback_replay(
    cache: &mut ReplayCache,
    entries: &[([u8; NODE_ID_BYTES], [u8; NODE_ID_BYTES])],
) {
    for (sender, nonce) in entries.iter().rev() {
        let _ = cache.rollback(sender, nonce);
    }
}
impl ExitService {
    /// Verify one exact relay grant and return an exit-signed positive receipt.
    ///
    /// Generic or unsigned transport status is never an acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects wrong forwarding identity, phase/session/boot mismatch, a relay
    /// grant other than the exact finalized authorization, replay, endpoint
    /// mismatch, duplicate non-identical confirmation, or signing failure.
    #[allow(
        clippy::too_many_lines,
        reason = "single fail-atomic confirmation transaction"
    )]
    pub fn confirm_relay_with<F>(
        &mut self,
        encoded_confirmation: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        signer: F,
    ) -> Result<AcceptedExitConfirmation, ExitError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_local_identity(local_public_key)?;
        self.purge_expired(now_ms);

        let request_hash: [u8; NODE_ID_BYTES] = Sha256::digest(encoded_confirmation).into();
        if let Some(cached) = cached_response(
            self.confirmation_response_cache.get(&request_hash),
            encoded_confirmation,
            authenticated_control_relay_node_id,
            authenticated_control_relay_peer_id,
        )? {
            return Ok(cached);
        }
        self.ensure_response_cache_capacity()?;

        let verified = verify_control_message::<ExitReservationConfirmation>(
            encoded_confirmation,
            now_ms,
            TimePolicy::default(),
            &mut self.confirmation_replay,
        )?;
        let confirmation_entry = (*verified.sender_id(), *verified.nonce());
        let confirmation_public_key = *verified.sender_public_key();
        let confirmation = verified.into_message();
        let phase_expires_at_ms = confirmation.expires_at_ms;
        let mut relay_entries = Vec::with_capacity(2);

        let outcome = (|| {
            if confirmation.exit_boot_id.as_slice() != self.exit_boot_id {
                return Err(ExitError::ExitBootMismatch);
            }
            let reservation_id = fixed(&confirmation.reservation_id, "reservation id")?;
            let reservation_key = text_id::<ReservationId>(&reservation_id)?;
            let state = self
                .endpoint_states
                .get(&reservation_key)
                .cloned()
                .ok_or(ExitError::InvalidGrant("unknown finalized reservation"))?;
            let finalize_id = state
                .finalize_id
                .ok_or(ExitError::InvalidGrant("missing finalize id"))?;
            let bundle_hash = state
                .finalized_bundle_hash
                .ok_or(ExitError::InvalidGrant("missing finalized bundle hash"))?;
            if state.phase != ExitReservationPhase::Finalized
                || state.exit_boot_id != self.exit_boot_id
                || state.client_session_id.as_slice() != confirmation.client_session_id
                || state.client_session_public_key != confirmation_public_key
                || state.route_context_id.as_slice() != confirmation.route_context_id
                || state.capability_id.as_slice() != confirmation.capability_id
                || state.hold_id.as_slice() != confirmation.hold_id
                || finalize_id.as_slice() != confirmation.finalize_id
                || confirmation.exit_node_id.as_slice() != self.config.node_id
                || confirmation.exit_peer_id != state.exit_peer_id
                || confirmation.control_relay_node_id.as_slice()
                    != authenticated_control_relay_node_id
                || confirmation.control_relay_peer_id != authenticated_control_relay_peer_id
                || state.control_relay_node_id != *authenticated_control_relay_node_id
                || state.control_relay_peer_id != authenticated_control_relay_peer_id
                || confirmation.policy_hash.as_slice() != state.policy_hash
                || confirmation.created_at_ms < state.created_at_ms
                || confirmation.expires_at_ms > state.expires_at_ms
            {
                return Err(ExitError::InvalidGrant("confirmation scope"));
            }
            let path = state
                .paths
                .iter()
                .find(|path| path.path_id == confirmation.path_id)
                .cloned()
                .ok_or(ExitError::InvalidGrant("unknown finalized path"))?;
            if path.relay_exit_endpoint.is_some() || path.relay_reservation_hash.is_some() {
                return Err(ExitError::InvalidGrant(
                    "only exact confirmation retry is allowed",
                ));
            }

            let (relay_verified, authorization_verified) = verify_relay_reservation(
                &confirmation.relay_reservation,
                now_ms,
                TimePolicy::default(),
                &mut self.relay_confirmation_replay,
            )?;
            let relay_entry = (*relay_verified.sender_id(), *relay_verified.nonce());
            let authorization_entry = (
                *authorization_verified.sender_id(),
                *authorization_verified.nonce(),
            );
            let relay_public_key = *relay_verified.sender_public_key();
            let authorization_public_key = *authorization_verified.sender_public_key();
            let relay = relay_verified.into_message();
            let authorization = authorization_verified.into_message();
            relay_entries.push(relay_entry);
            relay_entries.push(authorization_entry);

            let authorization_hash: [u8; NODE_ID_BYTES] =
                Sha256::digest(&relay.exit_authorization).into();
            if relay_entry.0 != path.relay_node_id
                || peer_id_from_public_key(&relay_public_key)? != path.relay_peer_id
                || authorization_entry.0 != self.config.node_id
                || authorization_public_key != local_public_key
                || authorization_hash != path.authorization_hash
                || confirmation.relay_node_id.as_slice() != path.relay_node_id
                || relay.reservation_id.as_slice() != reservation_id
                || relay.route_context_id.as_slice() != state.route_context_id
                || relay.path_id != path.path_id
                || relay.relay_node_id.as_slice() != path.relay_node_id
                || relay.relay_peer_id != path.relay_peer_id
                || relay.exit_node_id.as_slice() != self.config.node_id
                || relay.exit_peer_id != state.exit_peer_id
                || relay.client_session_id.as_slice() != state.client_session_id
                || relay.client_session_public_key.as_slice() != state.client_session_public_key
                || relay.capability_id.as_slice() != state.capability_id
                || relay.exit_boot_id.as_slice() != self.exit_boot_id
                || relay.hold_id.as_slice() != state.hold_id
                || relay.finalize_id.as_slice() != finalize_id
                || relay.control_relay_node_id.as_slice() != state.control_relay_node_id
                || relay.control_relay_peer_id != state.control_relay_peer_id
                || relay.policy_hash.as_slice() != state.policy_hash
                || relay.allowed_transports != state.allowed_transports
                || relay.maximum_up_mbps != state.reserved_up_mbps
                || relay.maximum_down_mbps != state.reserved_down_mbps
                || relay.client_wireguard_public_key.as_slice() != path.client_public_key.as_bytes()
                || relay.created_at_ms != state.created_at_ms
                || relay.expires_at_ms != state.expires_at_ms
                || authorization.exit_node_id.as_slice() != self.config.node_id
            {
                return Err(ExitError::InvalidGrant("relay confirmation grant scope"));
            }

            let relay_exit_endpoint = public_endpoint(
                relay
                    .relay_exit_wireguard_endpoint
                    .as_ref()
                    .ok_or(ExitError::InvalidGrant("relay-exit endpoint"))?,
                "relay-exit endpoint",
            )?;
            let signed_exit_endpoint = public_endpoint(
                relay
                    .exit_wireguard_endpoint
                    .as_ref()
                    .ok_or(ExitError::InvalidGrant("exit endpoint"))?,
                "exit endpoint",
            )?;
            if signed_exit_endpoint != path.exit_endpoint.public_endpoint() {
                return Err(ExitError::InvalidGrant("confirmed exit endpoint"));
            }

            let confirmation_hash = exit_confirmation_envelope_hash(encoded_confirmation)?;
            let receipt_nonce = generate_nonce();
            let receipt = ExitConfirmationReceipt {
                reservation_id: reservation_id.to_vec(),
                route_context_id: state.route_context_id.to_vec(),
                client_session_id: state.client_session_id.to_vec(),
                capability_id: state.capability_id.to_vec(),
                hold_id: state.hold_id.to_vec(),
                finalize_id: finalize_id.to_vec(),
                path_id: path.path_id,
                finalized_bundle_hash: bundle_hash.to_vec(),
                control_relay_node_id: state.control_relay_node_id.to_vec(),
                control_relay_peer_id: state.control_relay_peer_id.clone(),
                exit_node_id: self.config.node_id.to_vec(),
                exit_peer_id: state.exit_peer_id.clone(),
                exit_boot_id: self.exit_boot_id.to_vec(),
                created_at_ms: now_ms,
                expires_at_ms: confirmation.expires_at_ms,
                nonce: receipt_nonce.to_vec(),
                confirmation_envelope_hash: confirmation_hash.to_vec(),
            };
            let signed_receipt = sign_control_message_with(
                &receipt,
                local_public_key,
                receipt.created_at_ms,
                receipt.expires_at_ms,
                receipt_nonce,
                TimePolicy::default(),
                signer,
            )?;
            let relay_reservation_hash: [u8; NODE_ID_BYTES] =
                Sha256::digest(&confirmation.relay_reservation).into();
            let confirmed_path = ConfirmedExitPath {
                reservation_id,
                path_id: path.path_id,
                relay_exit_public_key: relay_exit_endpoint.public_key(),
                exit_public_key: path.exit_endpoint.public_endpoint().public_key(),
            };

            let live_path = self
                .endpoint_states
                .get_mut(&reservation_key)
                .and_then(|state| {
                    state
                        .paths
                        .iter_mut()
                        .find(|candidate| candidate.path_id == path.path_id)
                })
                .ok_or(ExitError::LeaseInvariant)?;
            if live_path.relay_exit_endpoint.is_some()
                || live_path.relay_reservation_hash.is_some()
                || live_path.authorization_hash != path.authorization_hash
            {
                return Err(ExitError::LeaseInvariant);
            }
            live_path.relay_exit_endpoint = Some(relay_exit_endpoint);
            live_path.relay_reservation_hash = Some(relay_reservation_hash);
            Ok(AcceptedExitConfirmation {
                signed_receipt,
                confirmed_path,
                expires_at_ms: confirmation.expires_at_ms,
            })
        })();

        match outcome {
            Ok(response) => {
                self.confirmation_response_cache.insert(
                    request_hash,
                    CachedControlResponse {
                        request: encoded_confirmation.to_vec(),
                        authenticated_control_relay_node_id: *authenticated_control_relay_node_id,
                        authenticated_control_relay_peer_id: authenticated_control_relay_peer_id
                            .to_vec(),
                        response: response.clone(),
                        expires_at_ms: phase_expires_at_ms,
                    },
                );
                Ok(response)
            }
            Err(error) => {
                rollback_replay(&mut self.relay_confirmation_replay, &relay_entries);
                let _ = self
                    .confirmation_replay
                    .rollback(&confirmation_entry.0, &confirmation_entry.1);
                Err(error)
            }
        }
    }
}
