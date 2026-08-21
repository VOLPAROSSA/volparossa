//! Typed client construction and verification for the hard-incompatible v3 reservation rounds.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use volparossa_protocol::{
    ClientSessionCapability, ControlMessageType, ControlPayload, ExitCapacityHold,
    ExitCapacityHoldRequest, ExitConfirmationReceipt, ExitReservation, ExitReservationConfirmation,
    ExitReservationFinalizeRequest, FinalizedRelayPath, MAX_CONTROL_MESSAGE_SIZE,
    MAX_CONTROL_PAYLOAD_SIZE, OpenTcp, ProbeAddressFamily, ProbeLegEvidence, ProtocolError,
    RelayAuthorization, RelayProbePermit, RelayProbePermitRequest, RelayProbeResult,
    RelayReservationRequest, ReplayCache, SignedEnvelope, TimePolicy, Transport,
    UdpFlowAuthorization, WireguardEndpoint, decode_canonical, exit_confirmation_envelope_hash,
    finalized_reservation_bundle_hash, generate_nonce, node_id_from_public_key,
    sign_control_message, verify_control_message, verify_relay_reservation,
};
use volparossa_wireguard::{
    ClientEndpointLease, HelperContextHandle, PublicWireGuardEndpoint, WireGuardPublicKey,
};

const KEY_BYTES: usize = 32;
const ID_BYTES: usize = 16;
const MAX_LOCAL_PATH_LEASES: usize = 64;
const MAX_PROTOCOL_PATHS: u32 = 8;

/// Exact client-selected scope for one relay path.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayPathIntent {
    /// Non-zero route-context-local path number.
    pub path_id: u32,
    /// Selected relay's stable node identifier.
    pub relay_node_id: [u8; KEY_BYTES],
    /// Selected relay's authenticated libp2p peer identifier.
    pub relay_peer_id: Vec<u8>,
}

/// Capacity scope requested before any relay is disclosed to the exit.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitReservationIntent {
    /// Random per-reservation identifier.
    pub reservation_id: [u8; ID_BYTES],
    /// Random route-context identifier.
    pub route_context_id: [u8; ID_BYTES],
    /// Selected exit node identifier.
    pub exit_node_id: [u8; KEY_BYTES],
    /// Selected exit's authenticated libp2p Peer ID.
    pub exit_peer_id: Vec<u8>,
    /// Forwarding control relay node identifier.
    pub control_relay_node_id: [u8; KEY_BYTES],
    /// Forwarding control relay's authenticated libp2p Peer ID.
    pub control_relay_peer_id: Vec<u8>,
    /// Exact sorted transports required by the route context.
    pub allowed_transports: Vec<Transport>,
    /// Requested upload capacity in Mbps.
    pub reserved_up_mbps: u64,
    /// Requested download capacity in Mbps.
    pub reserved_down_mbps: u64,
    /// Maximum final relay count accepted during finalization.
    pub maximum_paths: u32,
    /// Maximum short-lived prospective relay permits and path identifier.
    pub probe_permit_limit: u32,
    /// Active threshold-signed whitelist hash.
    pub policy_hash: [u8; KEY_BYTES],
    /// Signed phase creation time.
    pub created_at_ms: u64,
    /// Exclusive capacity-hold request and hold expiry, at most 30 seconds.
    pub hold_expires_at_ms: u64,
    /// Exclusive final capability and reservation expiry, at most 15 minutes.
    pub reservation_expires_at_ms: u64,
}

/// Verified exit-issued proof-of-possession and capacity hold.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedExitCapacityHold {
    signed_capability: Vec<u8>,
    signed_hold: Vec<u8>,
    capability: ClientSessionCapability,
    hold: ExitCapacityHold,
}

impl VerifiedExitCapacityHold {
    /// Canonical exit-signed client-session capability.
    #[must_use]
    pub fn signed_capability(&self) -> &[u8] {
        &self.signed_capability
    }

    /// Canonical exit-signed short capacity hold.
    #[must_use]
    pub fn signed_hold(&self) -> &[u8] {
        &self.signed_hold
    }

    /// Opaque capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &[u8] {
        &self.capability.capability_id
    }

    /// Opaque short capacity-hold identifier.
    #[must_use]
    pub fn hold_id(&self) -> &[u8] {
        &self.hold.hold_id
    }

    /// Maximum final relay count covered by this verified hold.
    #[must_use]
    pub const fn maximum_paths(&self) -> u32 {
        self.capability.maximum_paths
    }

    /// Maximum prospective relay permits and path identifier covered by this hold.
    #[must_use]
    pub const fn probe_permit_limit(&self) -> u32 {
        self.capability.probe_permit_limit
    }

    /// Exclusive hold expiry in Unix milliseconds.
    #[must_use]
    pub const fn hold_expires_at_ms(&self) -> u64 {
        self.hold.expires_at_ms
    }
}

/// Client-signed request retained to bind one returned probe permit.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedProbePermitRequest {
    encoded: Vec<u8>,
    request: RelayProbePermitRequest,
    hold: VerifiedExitCapacityHold,
}

impl SignedProbePermitRequest {
    /// Canonical client-session-signed request envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// Exit-signed probe permit verified against its exact client request.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedProbePermit {
    encoded: Vec<u8>,
    permit: RelayProbePermit,
    request: RelayProbePermitRequest,
    hold: VerifiedExitCapacityHold,
}

impl VerifiedProbePermit {
    /// Canonical exit-signed permit envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Exact path number authorized for probing.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.permit.path_id
    }
}

/// Structurally and cryptographically verified relay probe result.
///
/// This does not claim production reachability evidence. The exit must still
/// pass it through its configured `ProbeEvidenceVerifier`
/// boundary before finalization can succeed.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRelayProbe {
    permit: VerifiedProbePermit,
    encoded_result: Vec<u8>,
    result: RelayProbeResult,
    transport: Transport,
    address_family: ProbeAddressFamily,
    client_relay: ProbeLegEvidence,
    relay_exit: ProbeLegEvidence,
}

impl VerifiedRelayProbe {
    /// Exact route-local path number.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.permit.permit.path_id
    }

    /// Exact canonical relay-signed result bytes already verified above.
    #[must_use]
    pub fn signed_result(&self) -> &[u8] {
        &self.encoded_result
    }

    /// Typed transport covered by this verified probe.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Typed address family covered by this verified probe.
    #[must_use]
    pub const fn address_family(&self) -> ProbeAddressFamily {
        self.address_family
    }

    /// Required typed client-to-relay measurements.
    #[must_use]
    pub const fn client_relay(&self) -> &ProbeLegEvidence {
        &self.client_relay
    }

    /// Required typed relay-to-exit measurements.
    #[must_use]
    pub const fn relay_exit(&self) -> &ProbeLegEvidence {
        &self.relay_exit
    }
}

/// One client-session-signed exact finalization frame and its generated ID.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedExitFinalizeRequest {
    encoded: Vec<u8>,
    finalize_id: [u8; ID_BYTES],
    paths: Vec<RelayPathIntent>,
}

impl SignedExitFinalizeRequest {
    /// Canonical finalization request envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Opaque exact-attempt finalization identifier.
    #[must_use]
    pub const fn finalize_id(&self) -> &[u8; ID_BYTES] {
        &self.finalize_id
    }

    /// Exact selected relay paths in canonical increasing path order.
    #[must_use]
    pub fn relay_paths(&self) -> &[RelayPathIntent] {
        &self.paths
    }
}

/// Fully verified final exit grant and exact per-path authorizations.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedFinalizedExitBundle {
    signed_capability: Vec<u8>,
    signed_exit_reservation: Vec<u8>,
    relay_authorizations: Vec<Vec<u8>>,
    finalized_bundle_hash: [u8; KEY_BYTES],
}

impl VerifiedFinalizedExitBundle {
    /// Canonical exit-signed session capability.
    #[must_use]
    pub fn signed_capability(&self) -> &[u8] {
        &self.signed_capability
    }

    /// Canonical exit-signed finalized reservation.
    #[must_use]
    pub fn signed_exit_reservation(&self) -> &[u8] {
        &self.signed_exit_reservation
    }

    /// Canonical exit-signed relay authorizations in strict path order.
    #[must_use]
    pub fn relay_authorizations(&self) -> &[Vec<u8>] {
        &self.relay_authorizations
    }

    /// Exact final relay-path count bound by the signed exit grant.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.relay_authorizations.len()
    }

    /// Domain-separated digest acknowledged by confirmation receipts.
    #[must_use]
    pub const fn finalized_bundle_hash(&self) -> &[u8; KEY_BYTES] {
        &self.finalized_bundle_hash
    }
}

/// One relay grant whose outer relay and nested exit signatures and scope are verified.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRelayGrant {
    signed_relay_reservation: Vec<u8>,
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    path_id: u32,
    relay_node_id: [u8; KEY_BYTES],
    exit_node_id: [u8; KEY_BYTES],
    policy_hash: [u8; KEY_BYTES],
    capability_id: [u8; ID_BYTES],
    exit_boot_id: [u8; ID_BYTES],
    hold_id: [u8; ID_BYTES],
    finalize_id: [u8; ID_BYTES],
    control_relay_node_id: [u8; KEY_BYTES],
    control_relay_peer_id: Vec<u8>,
    exit_peer_id: Vec<u8>,
    finalized_bundle_hash: [u8; KEY_BYTES],
    relay_client_endpoint: PublicWireGuardEndpoint,
    expires_at_ms: u64,
}

impl VerifiedRelayGrant {
    /// Canonical relay-signed reservation returned by the selected relay.
    #[must_use]
    pub fn signed_relay_reservation(&self) -> &[u8] {
        &self.signed_relay_reservation
    }

    /// Reservation identifier shared by the full route.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Context-local path number.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }
    /// Verified relay endpoint facing this route-attempt client.
    #[must_use]
    pub const fn relay_client_endpoint(&self) -> PublicWireGuardEndpoint {
        self.relay_client_endpoint
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClientPathKey {
    reservation_id: [u8; ID_BYTES],
    path_id: u32,
}

#[derive(Debug)]
struct ClientPathState {
    endpoint: ClientEndpointLease,
    expires_at_ms: u64,
}

/// Client-side fresh session signer, replay state and bounded endpoint leases.
pub struct ReservationCoordinator {
    session_key: SigningKey,
    client_session_id: [u8; KEY_BYTES],
    exit_replay: ReplayCache,
    probe_replay: ReplayCache,
    relay_replay: ReplayCache,
    client_paths: HashMap<ClientPathKey, ClientPathState>,
}

impl fmt::Debug for ReservationCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservationCoordinator")
            .field("client_session_id", &self.client_session_id)
            .field("session_key", &"<redacted>")
            .field("client_paths", &self.client_paths.len())
            .finish_non_exhaustive()
    }
}

impl ReservationCoordinator {
    /// Generate one fresh route-attempt Ed25519 session and bounded replay state.
    ///
    /// # Errors
    ///
    /// Rejects a zero replay bound.
    pub fn new(replay_capacity: usize) -> Result<Self, CoordinatorError> {
        let session_key = SigningKey::generate(&mut OsRng);
        let client_session_id = node_id_from_public_key(&session_key.verifying_key().to_bytes());
        Ok(Self {
            session_key,
            client_session_id,
            exit_replay: ReplayCache::new(replay_capacity)?,
            probe_replay: ReplayCache::new(replay_capacity)?,
            relay_replay: ReplayCache::new(replay_capacity)?,
            client_paths: HashMap::new(),
        })
    }

    /// Return the fresh route-attempt session identifier.
    #[must_use]
    pub const fn client_session_id(&self) -> &[u8; KEY_BYTES] {
        &self.client_session_id
    }

    /// Return the fresh route-attempt Ed25519 public key.
    #[must_use]
    pub fn client_session_public_key(&self) -> [u8; KEY_BYTES] {
        self.session_key.verifying_key().to_bytes()
    }

    /// Sign one policy-bound TCP flow with this fresh route-attempt session.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname, port, scope, lifetime, or
    /// canonical signature frame.
    pub fn sign_open_tcp(
        &self,
        route_context_id: [u8; ID_BYTES],
        policy_hash: [u8; KEY_BYTES],
        hostname: &str,
        port: u16,
        timestamp_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        if timestamp_ms >= expires_at_ms {
            return Err(CoordinatorError::Scope("TCP flow lifetime"));
        }
        let nonce = generate_nonce();
        let message = OpenTcp {
            route_context_id: route_context_id.to_vec(),
            flow_id: random_nonzero_id().to_vec(),
            client_ephemeral_id: self.client_session_id.to_vec(),
            hostname: hostname.to_owned(),
            port: u32::from(port),
            policy_hash: policy_hash.to_vec(),
            timestamp_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        sign_control_message(
            &message,
            &self.session_key,
            timestamp_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Sign one hostname-pinned UDP flow with this fresh route-attempt session.
    ///
    /// The exit remains responsible for resolution; this constructor emits no
    /// client-supplied destination IP.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname, port, idle bound, scope,
    /// lifetime, or canonical signature frame.
    #[allow(clippy::too_many_arguments, reason = "fixed signed flow schema")]
    pub fn sign_udp_hostname(
        &self,
        route_context_id: [u8; ID_BYTES],
        policy_hash: [u8; KEY_BYTES],
        hostname: &str,
        port: u16,
        idle_timeout_ms: u32,
        timestamp_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        if timestamp_ms >= expires_at_ms {
            return Err(CoordinatorError::Scope("UDP flow lifetime"));
        }
        let nonce = generate_nonce();
        let message = UdpFlowAuthorization {
            route_context_id: route_context_id.to_vec(),
            flow_id: random_nonzero_id().to_vec(),
            client_ephemeral_id: self.client_session_id.to_vec(),
            hostname: hostname.to_owned(),
            destination_ip: Vec::new(),
            port: u32::from(port),
            policy_hash: policy_hash.to_vec(),
            idle_timeout_ms,
            timestamp_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        sign_control_message(
            &message,
            &self.session_key,
            timestamp_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Sign a short capacity-hold request that discloses no relay selection.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid scope, lifetime, identity, or encoding.
    pub fn sign_hold_request(
        &self,
        intent: &ExitReservationIntent,
    ) -> Result<Vec<u8>, CoordinatorError> {
        let nonce = generate_nonce();
        let request = ExitCapacityHoldRequest {
            reservation_id: intent.reservation_id.to_vec(),
            route_context_id: intent.route_context_id.to_vec(),
            exit_node_id: intent.exit_node_id.to_vec(),
            client_session_id: self.client_session_id.to_vec(),
            allowed_transports: transports(&intent.allowed_transports),
            reserved_up_mbps: intent.reserved_up_mbps,
            reserved_down_mbps: intent.reserved_down_mbps,
            maximum_paths: intent.maximum_paths,
            probe_permit_limit: intent.probe_permit_limit,
            policy_hash: intent.policy_hash.to_vec(),
            created_at_ms: intent.created_at_ms,
            expires_at_ms: intent.hold_expires_at_ms,
            nonce: nonce.to_vec(),
            client_session_public_key: self.client_session_public_key().to_vec(),
            control_relay_node_id: intent.control_relay_node_id.to_vec(),
            control_relay_peer_id: intent.control_relay_peer_id.clone(),
            exit_peer_id: intent.exit_peer_id.clone(),
            reservation_expires_at_ms: intent.reservation_expires_at_ms,
        };
        sign_control_message(
            &request,
            &self.session_key,
            intent.created_at_ms,
            intent.hold_expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Verify the coupled exit-signed capability and short capacity hold.
    ///
    /// # Errors
    ///
    /// Rejects invalid signatures, replay, time, authenticated exit Peer ID, or scope.
    pub fn verify_hold_response(
        &mut self,
        intent: &ExitReservationIntent,
        signed_capability: Vec<u8>,
        signed_hold: Vec<u8>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedExitCapacityHold, CoordinatorError> {
        let mut accepted = Vec::with_capacity(2);
        let outcome = (|| {
            let capability = verify_control_message::<ClientSessionCapability>(
                &signed_capability,
                now_ms,
                TimePolicy::default(),
                &mut self.exit_replay,
            )?;
            accepted.push((*capability.sender_id(), *capability.nonce()));
            if *capability.sender_id() != intent.exit_node_id
                || authenticated_exit_peer_id != intent.exit_peer_id
                || !same_capability_scope(capability.message(), intent, self)
            {
                return Err(CoordinatorError::Scope("client session capability"));
            }
            let hold = verify_control_message::<ExitCapacityHold>(
                &signed_hold,
                now_ms,
                TimePolicy::default(),
                &mut self.exit_replay,
            )?;
            accepted.push((*hold.sender_id(), *hold.nonce()));
            if *hold.sender_id() != intent.exit_node_id
                || !same_hold_scope(
                    hold.message(),
                    capability.message(),
                    &signed_capability,
                    intent,
                    self,
                )
            {
                return Err(CoordinatorError::Scope("exit capacity hold"));
            }
            Ok(VerifiedExitCapacityHold {
                signed_capability,
                signed_hold,
                capability: capability.message().clone(),
                hold: hold.message().clone(),
            })
        })();
        if outcome.is_err() {
            rollback(&mut self.exit_replay, &accepted);
        }
        outcome
    }

    /// Sign one exact short probe-permit request through the bound control relay.
    ///
    /// # Errors
    ///
    /// Rejects a phase outside the live hold or an invalid path/transport/family.
    pub fn sign_probe_permit_request(
        &self,
        hold: &VerifiedExitCapacityHold,
        path: &RelayPathIntent,
        transport: Transport,
        address_family: ProbeAddressFamily,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<SignedProbePermitRequest, CoordinatorError> {
        if path.path_id == 0
            || path.path_id > hold.capability.probe_permit_limit
            || !hold
                .capability
                .allowed_transports
                .contains(&(transport as i32))
            || expires_at_ms > hold.hold.expires_at_ms
            || created_at_ms >= expires_at_ms
        {
            return Err(CoordinatorError::Scope("probe request lifetime"));
        }
        let probe_id = random_nonzero_id();
        let nonce = generate_nonce();
        let request = RelayProbePermitRequest {
            probe_id: probe_id.to_vec(),
            exit_capacity_hold: hold.signed_hold.clone(),
            client_session_capability: hold.signed_capability.clone(),
            path_id: path.path_id,
            relay_node_id: path.relay_node_id.to_vec(),
            relay_peer_id: path.relay_peer_id.clone(),
            client_session_id: self.client_session_id.to_vec(),
            control_relay_node_id: hold.capability.control_relay_node_id.clone(),
            control_relay_peer_id: hold.capability.control_relay_peer_id.clone(),
            created_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
            exit_node_id: hold.capability.exit_node_id.clone(),
            exit_peer_id: hold.capability.exit_peer_id.clone(),
            transport: transport as i32,
            address_family: address_family as i32,
        };
        let encoded = sign_control_message(
            &request,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )?;
        Ok(SignedProbePermitRequest {
            encoded,
            request,
            hold: hold.clone(),
        })
    }

    /// Verify one exit-signed probe permit against the exact request frame.
    ///
    /// # Errors
    ///
    /// Rejects signature, replay, lifetime, exit, relay, path, family, or scope substitution.
    pub fn verify_probe_permit(
        &mut self,
        request: &SignedProbePermitRequest,
        signed_permit: Vec<u8>,
        now_ms: u64,
    ) -> Result<VerifiedProbePermit, CoordinatorError> {
        let verified = verify_control_message::<RelayProbePermit>(
            &signed_permit,
            now_ms,
            TimePolicy::default(),
            &mut self.exit_replay,
        )?;
        let entry = (*verified.sender_id(), *verified.nonce());
        let result = if same_probe_permit(verified.message(), &request.request, &request.hold) {
            Ok(VerifiedProbePermit {
                encoded: signed_permit,
                permit: verified.message().clone(),
                request: request.request.clone(),
                hold: request.hold.clone(),
            })
        } else {
            Err(CoordinatorError::Scope("relay probe permit"))
        };
        if result.is_err() {
            let _ = self.exit_replay.rollback(&entry.0, &entry.1);
        }
        result
    }

    /// Verify a relay-signed structured result for one exact permit.
    ///
    /// # Errors
    ///
    /// Rejects replay, signature, missing evidence, or any permit/scope substitution.
    pub fn verify_probe_result(
        &mut self,
        permit: VerifiedProbePermit,
        signed_result: Vec<u8>,
        now_ms: u64,
    ) -> Result<VerifiedRelayProbe, CoordinatorError> {
        let verified = verify_control_message::<RelayProbeResult>(
            &signed_result,
            now_ms,
            TimePolicy::default(),
            &mut self.probe_replay,
        )?;
        let entry = (*verified.sender_id(), *verified.nonce());
        let result = (|| {
            let message = verified.message();
            if !same_probe_result(message, &permit) {
                return Err(CoordinatorError::Scope("relay probe result"));
            }
            let transport = Transport::try_from(message.transport)
                .map_err(|_| CoordinatorError::Scope("relay probe transport"))?;
            let address_family = ProbeAddressFamily::try_from(message.address_family)
                .map_err(|_| CoordinatorError::Scope("relay probe address family"))?;
            let client_relay = message
                .client_relay
                .clone()
                .ok_or(CoordinatorError::Scope("client-relay probe evidence"))?;
            let relay_exit = message
                .relay_exit
                .clone()
                .ok_or(CoordinatorError::Scope("relay-exit probe evidence"))?;
            Ok(VerifiedRelayProbe {
                permit,
                encoded_result: signed_result,
                result: message.clone(),
                transport,
                address_family,
                client_relay,
                relay_exit,
            })
        })();
        if result.is_err() {
            let _ = self.probe_replay.rollback(&entry.0, &entry.1);
        }
        result
    }

    /// Allocate client endpoint leases and sign one exact-relay-set finalization request.
    ///
    /// Leases are retained only after every proof, helper lease, uniqueness check and signature
    /// succeeds.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, unordered, mismatched, expired or over-capacity path sets.
    #[allow(
        clippy::too_many_lines,
        reason = "single fail-atomic finalize transaction"
    )]
    pub fn sign_finalize_request<E>(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &VerifiedExitCapacityHold,
        probes: &[VerifiedRelayProbe],
        created_at_ms: u64,
        expires_at_ms: u64,
        mut endpoint_provider: E,
    ) -> Result<SignedExitFinalizeRequest, CoordinatorError>
    where
        E: FnMut(u32) -> Option<ClientEndpointLease>,
    {
        let final_path_count = u32::try_from(probes.len())
            .map_err(|_| CoordinatorError::Scope("finalize phase scope"))?;
        if !(1..=intent.maximum_paths).contains(&final_path_count)
            || intent.maximum_paths > intent.probe_permit_limit
            || intent.probe_permit_limit > MAX_PROTOCOL_PATHS
            || !same_capability_scope(&hold.capability, intent, self)
            || !same_hold_scope(
                &hold.hold,
                &hold.capability,
                &hold.signed_capability,
                intent,
                self,
            )
            || expires_at_ms > hold.hold.expires_at_ms
            || created_at_ms >= expires_at_ms
        {
            return Err(CoordinatorError::Scope("finalize phase scope"));
        }
        let next_count = self
            .client_paths
            .len()
            .checked_add(probes.len())
            .ok_or(CoordinatorError::Scope("client path capacity"))?;
        if next_count > MAX_LOCAL_PATH_LEASES {
            return Err(CoordinatorError::Scope("client path capacity"));
        }

        let mut paths = Vec::with_capacity(probes.len());
        let mut selected = Vec::with_capacity(probes.len());
        let mut relay_node_ids = HashSet::with_capacity(probes.len());
        let mut relay_peer_ids = HashSet::with_capacity(probes.len());
        let mut previous_path_id = 0;
        for probe in probes {
            let verified_permit = &probe.permit;
            let permit = &verified_permit.permit;
            let relay_node_id = fixed(&permit.relay_node_id, "probe relay node")?;
            if permit.path_id <= previous_path_id
                || permit.path_id > intent.probe_permit_limit
                || &verified_permit.hold != hold
                || !same_probe_permit(permit, &verified_permit.request, hold)
                || !same_probe_result(&probe.result, verified_permit)
            {
                return Err(CoordinatorError::Scope("finalize probe scope"));
            }
            if !relay_node_ids.insert(relay_node_id)
                || !relay_peer_ids.insert(permit.relay_peer_id.clone())
            {
                return Err(CoordinatorError::Scope("finalize relay uniqueness"));
            }
            previous_path_id = permit.path_id;
            paths.push(RelayPathIntent {
                path_id: permit.path_id,
                relay_node_id,
                relay_peer_id: permit.relay_peer_id.clone(),
            });
            selected.push((permit.path_id, probe));
        }

        let mut generated = Vec::with_capacity(probes.len());
        let mut public_keys = self
            .client_paths
            .values()
            .map(|state| state.endpoint.public_endpoint().public_key())
            .collect::<HashSet<_>>();
        let mut listen_ports = self
            .client_paths
            .values()
            .map(|state| state.endpoint.public_endpoint().listen_port())
            .collect::<HashSet<_>>();
        let mut helper_handles = self
            .client_paths
            .values()
            .flat_map(|state| {
                [
                    *state.endpoint.context_handle().as_bytes(),
                    *state.endpoint.lease_handle().as_bytes(),
                ]
            })
            .collect::<HashSet<_>>();
        let mut expected_context_handle: Option<HelperContextHandle> = None;
        for (path_id, probe) in selected {
            let endpoint =
                endpoint_provider(path_id).ok_or(CoordinatorError::EndpointUnavailable)?;
            if endpoint.route_context_id() != &intent.route_context_id
                || endpoint.path_id() != path_id
            {
                return Err(CoordinatorError::Scope("client helper lease binding"));
            }
            match expected_context_handle {
                Some(handle) if handle != endpoint.context_handle() => {
                    return Err(CoordinatorError::Scope("client helper context binding"));
                }
                Some(_) => {}
                None => {
                    if !helper_handles.insert(*endpoint.context_handle().as_bytes()) {
                        return Err(CoordinatorError::Scope("client helper handle uniqueness"));
                    }
                    expected_context_handle = Some(endpoint.context_handle());
                }
            }
            if !helper_handles.insert(*endpoint.lease_handle().as_bytes()) {
                return Err(CoordinatorError::Scope("client helper handle uniqueness"));
            }
            let public = endpoint.public_endpoint();
            if !public_keys.insert(public.public_key())
                || !listen_ports.insert(public.listen_port())
            {
                return Err(CoordinatorError::Scope("client endpoint uniqueness"));
            }
            generated.push((path_id, endpoint, probe));
        }

        let finalize_id = random_nonzero_id();
        let nonce = generate_nonce();
        let request = ExitReservationFinalizeRequest {
            reservation_id: intent.reservation_id.to_vec(),
            route_context_id: intent.route_context_id.to_vec(),
            exit_node_id: intent.exit_node_id.to_vec(),
            client_session_id: self.client_session_id.to_vec(),
            client_session_capability: hold.signed_capability.clone(),
            exit_capacity_hold: hold.signed_hold.clone(),
            relay_paths: generated
                .iter()
                .map(|(path_id, endpoint, probe)| FinalizedRelayPath {
                    path_id: *path_id,
                    relay_node_id: probe.permit.permit.relay_node_id.clone(),
                    relay_peer_id: probe.permit.permit.relay_peer_id.clone(),
                    client_wireguard_public_key: endpoint
                        .public_endpoint()
                        .public_key()
                        .as_bytes()
                        .to_vec(),
                    relay_probe_permit: probe.permit.encoded.clone(),
                    relay_probe_result: probe.encoded_result.clone(),
                })
                .collect(),
            created_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
            control_relay_node_id: intent.control_relay_node_id.to_vec(),
            control_relay_peer_id: intent.control_relay_peer_id.clone(),
            finalize_id: finalize_id.to_vec(),
            exit_peer_id: intent.exit_peer_id.clone(),
        };
        let encoded = sign_control_message(
            &request,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )?;
        for (path_id, endpoint, _) in generated {
            self.client_paths.insert(
                ClientPathKey {
                    reservation_id: intent.reservation_id,
                    path_id,
                },
                ClientPathState {
                    endpoint,
                    expires_at_ms: intent.reservation_expires_at_ms,
                },
            );
        }
        Ok(SignedExitFinalizeRequest {
            encoded,
            finalize_id,
            paths,
        })
    }

    /// Verify a final exit grant and all exact per-path authorizations.
    ///
    /// # Errors
    ///
    /// Rejects signature, replay, expiry, wrong exit/Peer ID, path, endpoint, capability, hold,
    /// finalization, policy or canonical bundle hash.
    #[allow(clippy::too_many_arguments, reason = "exact signed response scope")]
    pub fn verify_finalize_response(
        &mut self,
        intent: &ExitReservationIntent,
        hold: &VerifiedExitCapacityHold,
        request: &SignedExitFinalizeRequest,
        signed_exit_reservation: Vec<u8>,
        relay_authorizations: Vec<Vec<u8>>,
        authenticated_exit_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedFinalizedExitBundle, CoordinatorError> {
        if relay_authorizations.len() != request.paths.len()
            || authenticated_exit_peer_id != intent.exit_peer_id
        {
            return Err(CoordinatorError::Scope("finalized exit response count"));
        }
        let mut accepted = Vec::with_capacity(1 + relay_authorizations.len());
        let outcome = (|| {
            let exit = verify_control_message::<ExitReservation>(
                &signed_exit_reservation,
                now_ms,
                TimePolicy::default(),
                &mut self.exit_replay,
            )?;
            accepted.push((*exit.sender_id(), *exit.nonce()));
            if *exit.sender_id() != intent.exit_node_id
                || !same_final_exit_scope(exit.message(), intent, hold, request, self)
            {
                return Err(CoordinatorError::Scope("finalized exit reservation"));
            }
            for (encoded, path) in relay_authorizations.iter().zip(&request.paths) {
                let authorization = verify_control_message::<RelayAuthorization>(
                    encoded,
                    now_ms,
                    TimePolicy::default(),
                    &mut self.exit_replay,
                )?;
                accepted.push((*authorization.sender_id(), *authorization.nonce()));
                let local = self
                    .client_paths
                    .get(&ClientPathKey {
                        reservation_id: intent.reservation_id,
                        path_id: path.path_id,
                    })
                    .ok_or(CoordinatorError::Scope("client endpoint secret"))?;
                if *authorization.sender_id() != intent.exit_node_id
                    || !same_authorization_scope(
                        authorization.message(),
                        exit.message(),
                        path,
                        local.endpoint.public_endpoint().public_key(),
                    )
                {
                    return Err(CoordinatorError::Scope("relay authorization"));
                }
            }
            let bundle_hash =
                finalized_reservation_bundle_hash(&signed_exit_reservation, &relay_authorizations)?;
            Ok(VerifiedFinalizedExitBundle {
                signed_capability: hold.signed_capability.clone(),
                signed_exit_reservation,
                relay_authorizations,
                finalized_bundle_hash: bundle_hash,
            })
        })();
        if outcome.is_err() {
            rollback(&mut self.exit_replay, &accepted);
        }
        outcome
    }

    /// Sign one short relay request embedding the exact capability and final exit grants.
    ///
    /// # Errors
    ///
    /// Rejects a missing matching local endpoint or phase outside the grant lifetime.
    pub fn sign_relay_request(
        &self,
        bundle: &VerifiedFinalizedExitBundle,
        path_index: usize,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        let authorization = bundle
            .relay_authorizations
            .get(path_index)
            .ok_or(CoordinatorError::Scope("relay authorization index"))?;
        let envelope: SignedEnvelope = decode_canonical(authorization, MAX_CONTROL_MESSAGE_SIZE)?;
        if envelope.message_type != ControlMessageType::RelayAuthorization as i32 {
            return Err(CoordinatorError::Scope("relay authorization type"));
        }
        let authorization_message: RelayAuthorization =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
        authorization_message.validate()?;
        if created_at_ms >= expires_at_ms || expires_at_ms > authorization_message.expires_at_ms {
            return Err(CoordinatorError::Scope("relay request lifetime"));
        }
        let reservation_id = fixed(
            &authorization_message.reservation_id,
            "relay request reservation id",
        )?;
        let local = self
            .client_paths
            .get(&ClientPathKey {
                reservation_id,
                path_id: authorization_message.path_id,
            })
            .ok_or(CoordinatorError::EndpointUnavailable)?;
        if authorization_message.client_wireguard_public_key.as_slice()
            != local.endpoint.public_endpoint().public_key().as_bytes()
        {
            return Err(CoordinatorError::Scope("relay request client endpoint key"));
        }
        let nonce = generate_nonce();
        let request = RelayReservationRequest {
            client_session_id: self.client_session_id.to_vec(),
            exit_authorization: authorization.clone(),
            created_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
            client_wireguard_endpoint: Some(wire_endpoint(local.endpoint.public_endpoint())),
            client_session_capability: bundle.signed_capability.clone(),
            exit_reservation: bundle.signed_exit_reservation.clone(),
        };
        sign_control_message(
            &request,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Verify one relay response and its exact nested exit authorization.
    ///
    /// # Errors
    ///
    /// Rejects signature, replay, wrong relay Peer ID, finalization, endpoint, or capability scope.
    pub fn verify_relay_response(
        &mut self,
        bundle: &VerifiedFinalizedExitBundle,
        signed_relay_reservation: &[u8],
        expected_path_index: usize,
        expected_relay_node_id: [u8; KEY_BYTES],
        authenticated_relay_peer_id: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedRelayGrant, CoordinatorError> {
        let expected_authorization = bundle
            .relay_authorizations
            .get(expected_path_index)
            .ok_or(CoordinatorError::Scope("relay authorization index"))?;
        let (relay, exit) = verify_relay_reservation(
            signed_relay_reservation,
            now_ms,
            TimePolicy::default(),
            &mut self.relay_replay,
        )?;
        let entries = [
            (*relay.sender_id(), *relay.nonce()),
            (*exit.sender_id(), *exit.nonce()),
        ];
        let result = (|| {
            let message = relay.message();
            let reservation_id = fixed(&message.reservation_id, "relay reservation id")?;
            let route_context_id = fixed(&message.route_context_id, "relay route context")?;
            let relay_node_id = fixed(&message.relay_node_id, "relay node id")?;
            let exit_node_id = fixed(&message.exit_node_id, "relay exit node id")?;
            let policy_hash = fixed(&message.policy_hash, "relay policy hash")?;
            let local = self
                .client_paths
                .get(&ClientPathKey {
                    reservation_id,
                    path_id: message.path_id,
                })
                .ok_or(CoordinatorError::Scope("client endpoint secret"))?;
            if *relay.sender_id() != expected_relay_node_id
                || relay_node_id != expected_relay_node_id
                || message.client_session_id.as_slice() != self.client_session_id
                || message.exit_authorization != *expected_authorization
                || message.relay_peer_id != authenticated_relay_peer_id
                || message.client_wireguard_public_key.as_slice()
                    != local.endpoint.public_endpoint().public_key().as_bytes()
            {
                return Err(CoordinatorError::Scope("relay response"));
            }
            let relay_client_endpoint = public_endpoint(
                message
                    .relay_client_wireguard_endpoint
                    .as_ref()
                    .ok_or(CoordinatorError::Scope("relay client endpoint"))?,
                "relay client endpoint",
            )?;
            Ok(VerifiedRelayGrant {
                signed_relay_reservation: signed_relay_reservation.to_vec(),
                reservation_id,
                route_context_id,
                path_id: message.path_id,
                relay_node_id,
                exit_node_id,
                policy_hash,
                capability_id: fixed(&message.capability_id, "relay capability id")?,
                exit_boot_id: fixed(&message.exit_boot_id, "relay exit boot id")?,
                hold_id: fixed(&message.hold_id, "relay hold id")?,
                finalize_id: fixed(&message.finalize_id, "relay finalize id")?,
                control_relay_node_id: fixed(&message.control_relay_node_id, "relay control node")?,
                control_relay_peer_id: message.control_relay_peer_id.clone(),
                exit_peer_id: message.exit_peer_id.clone(),
                finalized_bundle_hash: bundle.finalized_bundle_hash,
                relay_client_endpoint,
                expires_at_ms: message.expires_at_ms,
            })
        })();
        if result.is_err() {
            rollback(&mut self.relay_replay, &entries);
        }
        result
    }

    /// Sign one short exact relay-grant confirmation for the exit.
    ///
    /// # Errors
    ///
    /// Rejects a phase outside the relay grant lifetime.
    pub fn sign_exit_confirmation(
        &self,
        grant: &VerifiedRelayGrant,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        if created_at_ms >= expires_at_ms || expires_at_ms > grant.expires_at_ms {
            return Err(CoordinatorError::Scope("exit confirmation lifetime"));
        }
        let nonce = generate_nonce();
        let confirmation = ExitReservationConfirmation {
            reservation_id: grant.reservation_id.to_vec(),
            route_context_id: grant.route_context_id.to_vec(),
            path_id: grant.path_id,
            relay_node_id: grant.relay_node_id.to_vec(),
            exit_node_id: grant.exit_node_id.to_vec(),
            client_session_id: self.client_session_id.to_vec(),
            policy_hash: grant.policy_hash.to_vec(),
            relay_reservation: grant.signed_relay_reservation.clone(),
            created_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
            capability_id: grant.capability_id.to_vec(),
            client_session_public_key: self.client_session_public_key().to_vec(),
            exit_boot_id: grant.exit_boot_id.to_vec(),
            hold_id: grant.hold_id.to_vec(),
            finalize_id: grant.finalize_id.to_vec(),
            control_relay_node_id: grant.control_relay_node_id.to_vec(),
            control_relay_peer_id: grant.control_relay_peer_id.clone(),
            exit_peer_id: grant.exit_peer_id.clone(),
        };
        sign_control_message(
            &confirmation,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Verify an exit-signed positive acknowledgement for one exact finalized bundle/path.
    ///
    /// # Errors
    ///
    /// Rejects unsigned status, replay, wrong exit, relay-forwarding binding, or bundle digest.
    pub fn verify_confirmation_receipt(
        &mut self,
        grant: &VerifiedRelayGrant,
        signed_confirmation: &[u8],
        signed_receipt: &[u8],
        now_ms: u64,
    ) -> Result<(), CoordinatorError> {
        let receipt = verify_control_message::<ExitConfirmationReceipt>(
            signed_receipt,
            now_ms,
            TimePolicy::default(),
            &mut self.exit_replay,
        )?;
        let entry = (*receipt.sender_id(), *receipt.nonce());
        let message = receipt.message();
        let confirmation_hash = exit_confirmation_envelope_hash(signed_confirmation)?;
        let valid = *receipt.sender_id() == grant.exit_node_id
            && message.reservation_id.as_slice() == grant.reservation_id
            && message.route_context_id.as_slice() == grant.route_context_id
            && message.client_session_id.as_slice() == self.client_session_id
            && message.capability_id.as_slice() == grant.capability_id
            && message.hold_id.as_slice() == grant.hold_id
            && message.finalize_id.as_slice() == grant.finalize_id
            && message.path_id == grant.path_id
            && message.finalized_bundle_hash.as_slice() == grant.finalized_bundle_hash
            && message.confirmation_envelope_hash.as_slice() == confirmation_hash
            && message.control_relay_node_id.as_slice() == grant.control_relay_node_id
            && message.control_relay_peer_id == grant.control_relay_peer_id
            && message.exit_node_id.as_slice() == grant.exit_node_id
            && message.exit_peer_id == grant.exit_peer_id
            && message.exit_boot_id.as_slice() == grant.exit_boot_id;
        if valid {
            Ok(())
        } else {
            let _ = self.exit_replay.rollback(&entry.0, &entry.1);
            Err(CoordinatorError::Scope("exit confirmation receipt"))
        }
    }

    /// Return the exact public endpoint lease and opaque helper capabilities.
    #[must_use]
    pub fn client_endpoint_lease(
        &self,
        reservation_id: [u8; ID_BYTES],
        path_id: u32,
    ) -> Option<ClientEndpointLease> {
        self.client_paths
            .get(&ClientPathKey {
                reservation_id,
                path_id,
            })
            .map(|state| state.endpoint)
    }

    /// Release every client-side opaque helper lease for one reservation.
    pub fn release(&mut self, reservation_id: [u8; ID_BYTES]) -> usize {
        let before = self.client_paths.len();
        self.client_paths
            .retain(|key, _| key.reservation_id != reservation_id);
        before - self.client_paths.len()
    }

    /// Drop all expired client-side opaque helper lease capabilities.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let before = self.client_paths.len();
        self.client_paths
            .retain(|_, state| state.expires_at_ms > now_ms);
        before - self.client_paths.len()
    }
}

fn same_capability_scope(
    capability: &ClientSessionCapability,
    intent: &ExitReservationIntent,
    coordinator: &ReservationCoordinator,
) -> bool {
    capability.reservation_id.as_slice() == intent.reservation_id
        && capability.route_context_id.as_slice() == intent.route_context_id
        && capability.client_session_id.as_slice() == coordinator.client_session_id
        && capability.client_session_public_key.as_slice()
            == coordinator.client_session_public_key()
        && capability.exit_node_id.as_slice() == intent.exit_node_id
        && capability.exit_peer_id == intent.exit_peer_id
        && capability.control_relay_node_id.as_slice() == intent.control_relay_node_id
        && capability.control_relay_peer_id == intent.control_relay_peer_id
        && capability.policy_hash.as_slice() == intent.policy_hash
        && capability.allowed_transports == transports(&intent.allowed_transports)
        && capability.reserved_up_mbps == intent.reserved_up_mbps
        && capability.reserved_down_mbps == intent.reserved_down_mbps
        && capability.maximum_paths == intent.maximum_paths
        && capability.probe_permit_limit == intent.probe_permit_limit
        && capability.created_at_ms == intent.created_at_ms
        && capability.expires_at_ms == intent.reservation_expires_at_ms
}

fn same_hold_scope(
    hold: &ExitCapacityHold,
    capability: &ClientSessionCapability,
    signed_capability: &[u8],
    intent: &ExitReservationIntent,
    coordinator: &ReservationCoordinator,
) -> bool {
    hold.client_session_capability == signed_capability
        && hold.reservation_id == capability.reservation_id
        && hold.route_context_id == capability.route_context_id
        && hold.exit_node_id == capability.exit_node_id
        && hold.exit_peer_id == capability.exit_peer_id
        && hold.exit_boot_id == capability.exit_boot_id
        && hold.client_session_id.as_slice() == coordinator.client_session_id
        && hold.policy_hash == capability.policy_hash
        && hold.allowed_transports == capability.allowed_transports
        && hold.reserved_up_mbps == capability.reserved_up_mbps
        && hold.reserved_down_mbps == capability.reserved_down_mbps
        && hold.maximum_paths == capability.maximum_paths
        && hold.probe_permit_limit == capability.probe_permit_limit
        && hold.created_at_ms == intent.created_at_ms
        && hold.expires_at_ms == intent.hold_expires_at_ms
        && hold.reservation_expires_at_ms == intent.reservation_expires_at_ms
        && hold.control_relay_node_id == capability.control_relay_node_id
        && hold.control_relay_peer_id == capability.control_relay_peer_id
}

fn same_probe_permit(
    permit: &RelayProbePermit,
    request: &RelayProbePermitRequest,
    hold: &VerifiedExitCapacityHold,
) -> bool {
    request.exit_capacity_hold == hold.signed_hold
        && request.client_session_capability == hold.signed_capability
        && permit.probe_id == request.probe_id
        && permit.hold_id == hold.hold.hold_id
        && permit.capability_id == hold.capability.capability_id
        && permit.reservation_id == hold.capability.reservation_id
        && permit.route_context_id == hold.capability.route_context_id
        && permit.client_session_id == request.client_session_id
        && permit.client_session_id == hold.capability.client_session_id
        && permit.exit_node_id == request.exit_node_id
        && permit.exit_node_id == hold.capability.exit_node_id
        && permit.exit_boot_id == hold.capability.exit_boot_id
        && permit.exit_peer_id == request.exit_peer_id
        && permit.exit_peer_id == hold.capability.exit_peer_id
        && permit.control_relay_node_id == request.control_relay_node_id
        && permit.control_relay_node_id == hold.capability.control_relay_node_id
        && permit.control_relay_peer_id == request.control_relay_peer_id
        && permit.control_relay_peer_id == hold.capability.control_relay_peer_id
        && permit.policy_hash == hold.capability.policy_hash
        && permit.relay_node_id == request.relay_node_id
        && permit.relay_peer_id == request.relay_peer_id
        && permit.path_id == request.path_id
        && permit.created_at_ms == request.created_at_ms
        && permit.expires_at_ms == request.expires_at_ms
        && permit.transport == request.transport
        && permit.address_family == request.address_family
}

fn same_probe_result(result: &RelayProbeResult, permit: &VerifiedProbePermit) -> bool {
    let expected = &permit.permit;
    result.relay_probe_permit == permit.encoded
        && result.probe_id == expected.probe_id
        && result.relay_node_id == expected.relay_node_id
        && result.relay_peer_id == expected.relay_peer_id
        && result.exit_node_id == expected.exit_node_id
        && result.exit_peer_id == expected.exit_peer_id
        && result.exit_boot_id == expected.exit_boot_id
        && result.hold_id == expected.hold_id
        && result.capability_id == expected.capability_id
        && result.reservation_id == expected.reservation_id
        && result.route_context_id == expected.route_context_id
        && result.client_session_id == expected.client_session_id
        && result.policy_hash == expected.policy_hash
        && result.transport == expected.transport
        && result.address_family == expected.address_family
        && result.measured_at_ms >= expected.created_at_ms
        && result.expires_at_ms <= expected.expires_at_ms
}

fn same_final_exit_scope(
    response: &ExitReservation,
    intent: &ExitReservationIntent,
    hold: &VerifiedExitCapacityHold,
    request: &SignedExitFinalizeRequest,
    coordinator: &ReservationCoordinator,
) -> bool {
    let Ok(final_path_count) = u32::try_from(request.paths.len()) else {
        return false;
    };
    response.reservation_id.as_slice() == intent.reservation_id
        && response.route_context_id.as_slice() == intent.route_context_id
        && response.exit_node_id.as_slice() == intent.exit_node_id
        && response.exit_peer_id == intent.exit_peer_id
        && response.client_session_id.as_slice() == coordinator.client_session_id
        && response.client_session_public_key.as_slice() == coordinator.client_session_public_key()
        && response.allowed_transports == transports(&intent.allowed_transports)
        && response.reserved_up_mbps == intent.reserved_up_mbps
        && response.reserved_down_mbps == intent.reserved_down_mbps
        && response.maximum_paths == final_path_count
        && response.maximum_paths <= intent.maximum_paths
        && response.policy_hash.as_slice() == intent.policy_hash
        && response.created_at_ms == intent.created_at_ms
        && response.expires_at_ms == intent.reservation_expires_at_ms
        && response.capability_id == hold.capability.capability_id
        && response.exit_boot_id == hold.capability.exit_boot_id
        && response.hold_id == hold.hold.hold_id
        && response.finalize_id.as_slice() == request.finalize_id
        && response.control_relay_node_id.as_slice() == intent.control_relay_node_id
        && response.control_relay_peer_id == intent.control_relay_peer_id
}

fn same_authorization_scope(
    response: &RelayAuthorization,
    exit: &ExitReservation,
    path: &RelayPathIntent,
    client_wireguard_public_key: WireGuardPublicKey,
) -> bool {
    response.reservation_id == exit.reservation_id
        && response.route_context_id == exit.route_context_id
        && response.path_id == path.path_id
        && response.relay_node_id.as_slice() == path.relay_node_id
        && response.relay_peer_id == path.relay_peer_id
        && response.exit_node_id == exit.exit_node_id
        && response.client_session_id == exit.client_session_id
        && response.allowed_transports == exit.allowed_transports
        && response.maximum_up_mbps == exit.reserved_up_mbps
        && response.maximum_down_mbps == exit.reserved_down_mbps
        && response.client_wireguard_public_key.as_slice() == client_wireguard_public_key.as_bytes()
        && response.policy_hash == exit.policy_hash
        && response.created_at_ms == exit.created_at_ms
        && response.expires_at_ms == exit.expires_at_ms
        && response.capability_id == exit.capability_id
        && response.client_session_public_key == exit.client_session_public_key
        && response.exit_boot_id == exit.exit_boot_id
        && response.hold_id == exit.hold_id
        && response.finalize_id == exit.finalize_id
        && response.control_relay_node_id == exit.control_relay_node_id
        && response.control_relay_peer_id == exit.control_relay_peer_id
        && response.exit_peer_id == exit.exit_peer_id
}

fn rollback(cache: &mut ReplayCache, entries: &[([u8; KEY_BYTES], [u8; KEY_BYTES])]) {
    for (sender, nonce) in entries.iter().rev() {
        let _ = cache.rollback(sender, nonce);
    }
}

fn transports(values: &[Transport]) -> Vec<i32> {
    values.iter().map(|value| *value as i32).collect()
}

fn random_nonzero_id() -> [u8; ID_BYTES] {
    loop {
        let mut value = [0_u8; ID_BYTES];
        OsRng.fill_bytes(&mut value);
        if value != [0; ID_BYTES] {
            return value;
        }
    }
}

fn wire_endpoint(endpoint: PublicWireGuardEndpoint) -> WireguardEndpoint {
    let underlay_ip = match endpoint.underlay_ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    WireguardEndpoint {
        public_key: endpoint.public_key().as_bytes().to_vec(),
        underlay_ip,
        listen_port: u32::from(endpoint.listen_port()),
    }
}

fn public_endpoint(
    endpoint: &WireguardEndpoint,
    field: &'static str,
) -> Result<PublicWireGuardEndpoint, CoordinatorError> {
    endpoint.validate(field)?;
    let public_key = WireGuardPublicKey::from_bytes(fixed(&endpoint.public_key, field)?);
    let underlay_ip = match endpoint.underlay_ip.as_slice() {
        [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
        bytes => IpAddr::from(fixed::<16>(bytes, field)?),
    };
    let listen_port =
        u16::try_from(endpoint.listen_port).map_err(|_| CoordinatorError::Scope(field))?;
    PublicWireGuardEndpoint::new(public_key, underlay_ip, listen_port)
        .map_err(|_| CoordinatorError::Scope(field))
}

fn fixed<const N: usize>(bytes: &[u8], field: &'static str) -> Result<[u8; N], CoordinatorError> {
    bytes.try_into().map_err(|_| CoordinatorError::Scope(field))
}

/// Fail-closed request construction or response verification error.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// Canonical signing, signature, replay, time or parser validation failed.
    #[error("reservation protocol verification failed: {0}")]
    Protocol(#[from] ProtocolError),
    /// A validly signed message did not match the selected route scope.
    #[error("reservation scope mismatch: {0}")]
    Scope(&'static str),
    /// No helper/orchestrator-confirmed local endpoint lease was available.
    #[error("route-specific WireGuard endpoint is unavailable")]
    EndpointUnavailable,
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ed25519_dalek::SigningKey;
    use volparossa_protocol::{
        ClientSessionCapability, ExitCapacityHold, ExitCapacityHoldRequest,
        MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, ProbeAddressFamily, ProbeLegEvidence,
        RelayProbePermit, RelayProbePermitRequest, RelayProbeResult, ReplayCache, SignedEnvelope,
        TimePolicy, Transport, decode_canonical, generate_nonce, node_id_from_public_key,
        sign_control_message, verify_control_message,
    };

    use super::{
        CoordinatorError, ExitReservationIntent, RelayPathIntent, ReservationCoordinator,
        VerifiedExitCapacityHold,
    };

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn coordinators_generate_distinct_route_attempt_sessions_and_hold_has_no_relays() {
        let first = ReservationCoordinator::new(8).unwrap();
        let second = ReservationCoordinator::new(8).unwrap();
        assert_ne!(first.client_session_id(), second.client_session_id());
        let intent = ExitReservationIntent {
            reservation_id: [1; 16],
            route_context_id: [2; 16],
            exit_node_id: [3; 32],
            exit_peer_id: vec![4; 38],
            control_relay_node_id: [5; 32],
            control_relay_peer_id: vec![6; 38],
            allowed_transports: vec![Transport::UdpSinglePath],
            reserved_up_mbps: 10,
            reserved_down_mbps: 10,
            maximum_paths: 2,
            probe_permit_limit: 5,
            policy_hash: [7; 32],
            created_at_ms: NOW,
            hold_expires_at_ms: NOW + 20_000,
            reservation_expires_at_ms: NOW + 300_000,
        };
        let encoded = first.sign_hold_request(&intent).unwrap();
        let mut replay = ReplayCache::new(2).unwrap();
        let verified = verify_control_message::<ExitCapacityHoldRequest>(
            &encoded,
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .unwrap();
        assert_eq!(verified.message().maximum_paths, 2);
        assert_eq!(verified.message().probe_permit_limit, 5);
        assert!(!encoded.windows(38).any(|bytes| bytes == [99; 38]));
    }

    struct HeldFixture {
        intent: ExitReservationIntent,
        exit_key: SigningKey,
        capability: ClientSessionCapability,
        capacity_hold: ExitCapacityHold,
        verified: VerifiedExitCapacityHold,
    }

    fn held_fixture(coordinator: &mut ReservationCoordinator, seed: u8) -> HeldFixture {
        let exit_key = SigningKey::from_bytes(&[seed; 32]);
        let created_at_ms = NOW - 100;
        let hold_expires_at_ms = NOW + 20_000;
        let reservation_expires_at_ms = NOW + 60_000;
        let intent = ExitReservationIntent {
            reservation_id: [seed.wrapping_add(1); 16],
            route_context_id: [seed.wrapping_add(2); 16],
            exit_node_id: node_id_from_public_key(&exit_key.verifying_key().to_bytes()),
            exit_peer_id: vec![seed.wrapping_add(3); 38],
            control_relay_node_id: [seed.wrapping_add(4); 32],
            control_relay_peer_id: vec![seed.wrapping_add(5); 38],
            allowed_transports: vec![Transport::UdpSinglePath],
            reserved_up_mbps: 10,
            reserved_down_mbps: 20,
            maximum_paths: 1,
            probe_permit_limit: 1,
            policy_hash: [seed.wrapping_add(6); 32],
            created_at_ms,
            hold_expires_at_ms,
            reservation_expires_at_ms,
        };
        let capability_nonce = generate_nonce();
        let capability = ClientSessionCapability {
            capability_id: vec![seed.wrapping_add(7); 16],
            reservation_id: intent.reservation_id.to_vec(),
            route_context_id: intent.route_context_id.to_vec(),
            client_session_id: coordinator.client_session_id().to_vec(),
            client_session_public_key: coordinator.client_session_public_key().to_vec(),
            exit_node_id: intent.exit_node_id.to_vec(),
            exit_boot_id: vec![seed.wrapping_add(8); 16],
            control_relay_node_id: intent.control_relay_node_id.to_vec(),
            control_relay_peer_id: intent.control_relay_peer_id.clone(),
            policy_hash: intent.policy_hash.to_vec(),
            allowed_transports: vec![Transport::UdpSinglePath as i32],
            reserved_up_mbps: intent.reserved_up_mbps,
            reserved_down_mbps: intent.reserved_down_mbps,
            maximum_paths: intent.maximum_paths,
            created_at_ms,
            expires_at_ms: reservation_expires_at_ms,
            nonce: capability_nonce.to_vec(),
            exit_peer_id: intent.exit_peer_id.clone(),
            probe_permit_limit: intent.probe_permit_limit,
        };
        let signed_capability = sign_control_message(
            &capability,
            &exit_key,
            created_at_ms,
            reservation_expires_at_ms,
            capability_nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let hold_nonce = generate_nonce();
        let capacity_hold = ExitCapacityHold {
            hold_id: vec![seed.wrapping_add(9); 16],
            client_session_capability: signed_capability.clone(),
            reservation_id: intent.reservation_id.to_vec(),
            route_context_id: intent.route_context_id.to_vec(),
            exit_node_id: intent.exit_node_id.to_vec(),
            exit_boot_id: capability.exit_boot_id.clone(),
            client_session_id: coordinator.client_session_id().to_vec(),
            policy_hash: intent.policy_hash.to_vec(),
            allowed_transports: vec![Transport::UdpSinglePath as i32],
            reserved_up_mbps: intent.reserved_up_mbps,
            reserved_down_mbps: intent.reserved_down_mbps,
            maximum_paths: intent.maximum_paths,
            created_at_ms,
            expires_at_ms: hold_expires_at_ms,
            nonce: hold_nonce.to_vec(),
            exit_peer_id: intent.exit_peer_id.clone(),
            control_relay_node_id: intent.control_relay_node_id.to_vec(),
            control_relay_peer_id: intent.control_relay_peer_id.clone(),
            reservation_expires_at_ms,
            probe_permit_limit: intent.probe_permit_limit,
        };
        let signed_hold = sign_control_message(
            &capacity_hold,
            &exit_key,
            created_at_ms,
            hold_expires_at_ms,
            hold_nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let verified = coordinator
            .verify_hold_response(
                &intent,
                signed_capability,
                signed_hold,
                &intent.exit_peer_id,
                NOW,
            )
            .unwrap();
        HeldFixture {
            intent,
            exit_key,
            capability,
            capacity_hold,
            verified,
        }
    }

    fn decode_probe_request(signed: &super::SignedProbePermitRequest) -> RelayProbePermitRequest {
        let envelope: SignedEnvelope =
            decode_canonical(signed.encoded(), MAX_CONTROL_MESSAGE_SIZE).unwrap();
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap()
    }

    fn permit_for(request: &RelayProbePermitRequest, fixture: &HeldFixture) -> RelayProbePermit {
        RelayProbePermit {
            probe_id: request.probe_id.clone(),
            hold_id: fixture.capacity_hold.hold_id.clone(),
            capability_id: fixture.capability.capability_id.clone(),
            reservation_id: fixture.capability.reservation_id.clone(),
            route_context_id: fixture.capability.route_context_id.clone(),
            client_session_id: request.client_session_id.clone(),
            exit_node_id: request.exit_node_id.clone(),
            exit_boot_id: fixture.capability.exit_boot_id.clone(),
            control_relay_node_id: request.control_relay_node_id.clone(),
            control_relay_peer_id: request.control_relay_peer_id.clone(),
            relay_node_id: request.relay_node_id.clone(),
            relay_peer_id: request.relay_peer_id.clone(),
            path_id: request.path_id,
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
            nonce: generate_nonce().to_vec(),
            exit_peer_id: request.exit_peer_id.clone(),
            policy_hash: fixture.capability.policy_hash.clone(),
            transport: request.transport,
            address_family: request.address_family,
        }
    }

    fn probe_leg() -> ProbeLegEvidence {
        ProbeLegEvidence {
            up_capacity_mbps: 10,
            down_capacity_mbps: 20,
            rtt_micros: 1_000,
            transmitted_bytes: 1_024,
            received_bytes: 1_024,
            window_started_at_ms: NOW - 10,
            window_ended_at_ms: NOW,
            measured_at_ms: NOW,
        }
    }

    #[derive(Clone, Copy)]
    enum PermitMutation {
        Hold,
        Capability,
        Reservation,
        RouteContext,
        ExitBoot,
        Policy,
    }

    #[test]
    fn probe_permit_binds_every_hold_field_and_scope_failure_rolls_replay_back() {
        for (index, mutation) in [
            PermitMutation::Hold,
            PermitMutation::Capability,
            PermitMutation::Reservation,
            PermitMutation::RouteContext,
            PermitMutation::ExitBoot,
            PermitMutation::Policy,
        ]
        .into_iter()
        .enumerate()
        {
            let mut coordinator = ReservationCoordinator::new(32).unwrap();
            let fixture = held_fixture(&mut coordinator, 30 + u8::try_from(index).unwrap());
            let relay_key = SigningKey::from_bytes(&[90 + u8::try_from(index).unwrap(); 32]);
            let path = RelayPathIntent {
                path_id: 1,
                relay_node_id: node_id_from_public_key(&relay_key.verifying_key().to_bytes()),
                relay_peer_id: vec![110 + u8::try_from(index).unwrap(); 38],
            };
            let signed_request = coordinator
                .sign_probe_permit_request(
                    &fixture.verified,
                    &path,
                    Transport::UdpSinglePath,
                    ProbeAddressFamily::Ipv4,
                    NOW,
                    NOW + 10_000,
                )
                .unwrap();
            let request = decode_probe_request(&signed_request);
            let valid = permit_for(&request, &fixture);
            let mut changed = valid.clone();
            match mutation {
                PermitMutation::Hold => changed.hold_id = vec![201; 16],
                PermitMutation::Capability => changed.capability_id = vec![202; 16],
                PermitMutation::Reservation => changed.reservation_id = vec![203; 16],
                PermitMutation::RouteContext => changed.route_context_id = vec![204; 16],
                PermitMutation::ExitBoot => changed.exit_boot_id = vec![205; 16],
                PermitMutation::Policy => changed.policy_hash = vec![206; 32],
            }
            let nonce: [u8; 32] = valid.nonce.as_slice().try_into().unwrap();
            let invalid = sign_control_message(
                &changed,
                &fixture.exit_key,
                changed.created_at_ms,
                changed.expires_at_ms,
                nonce,
                TimePolicy::default(),
            )
            .unwrap();
            assert!(matches!(
                coordinator.verify_probe_permit(&signed_request, invalid, NOW),
                Err(CoordinatorError::Scope("relay probe permit"))
            ));

            let original = sign_control_message(
                &valid,
                &fixture.exit_key,
                valid.created_at_ms,
                valid.expires_at_ms,
                nonce,
                TimePolicy::default(),
            )
            .unwrap();
            coordinator
                .verify_probe_permit(&signed_request, original, NOW)
                .unwrap();
        }
    }

    #[test]
    fn mixed_hold_probe_fails_before_endpoint_provider() {
        let mut coordinator = ReservationCoordinator::new(64).unwrap();
        let first = held_fixture(&mut coordinator, 50);
        let second = held_fixture(&mut coordinator, 70);
        let relay_key = SigningKey::from_bytes(&[100; 32]);
        let path = RelayPathIntent {
            path_id: 1,
            relay_node_id: node_id_from_public_key(&relay_key.verifying_key().to_bytes()),
            relay_peer_id: vec![101; 38],
        };
        let signed_request = coordinator
            .sign_probe_permit_request(
                &first.verified,
                &path,
                Transport::UdpSinglePath,
                ProbeAddressFamily::Ipv4,
                NOW,
                NOW + 10_000,
            )
            .unwrap();
        let request = decode_probe_request(&signed_request);
        let permit = permit_for(&request, &first);
        let permit_nonce = permit.nonce.as_slice().try_into().unwrap();
        let signed_permit = sign_control_message(
            &permit,
            &first.exit_key,
            permit.created_at_ms,
            permit.expires_at_ms,
            permit_nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let verified_permit = coordinator
            .verify_probe_permit(&signed_request, signed_permit.clone(), NOW)
            .unwrap();
        let result_nonce = generate_nonce();
        let result = RelayProbeResult {
            probe_id: permit.probe_id.clone(),
            relay_probe_permit: signed_permit,
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
            client_relay: Some(probe_leg()),
            relay_exit: Some(probe_leg()),
            measured_at_ms: NOW,
            expires_at_ms: permit.expires_at_ms,
            nonce: result_nonce.to_vec(),
        };
        let signed_result = sign_control_message(
            &result,
            &relay_key,
            NOW,
            result.expires_at_ms,
            result_nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let verified_probe = coordinator
            .verify_probe_result(verified_permit, signed_result, NOW)
            .unwrap();

        let provider_calls = Cell::new(0_u32);
        assert!(matches!(
            coordinator.sign_finalize_request(
                &second.intent,
                &second.verified,
                &[verified_probe],
                NOW,
                NOW + 5_000,
                |_path_id| {
                    provider_calls.set(provider_calls.get() + 1);
                    None
                },
            ),
            Err(CoordinatorError::Scope("finalize probe scope"))
        ));
        assert_eq!(provider_calls.get(), 0);
    }
}
