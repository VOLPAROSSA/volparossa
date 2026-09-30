//! Client ownership of one additive path transaction, separate from initial native activation.

#[allow(clippy::wildcard_imports, reason = "internal coordinator phase")]
use super::*;
use volparossa_protocol::{RouteExtension, RouteExtensionPhase, RouteExtensionRequest};

/// Exit-verified original-parent-bound extension response.
#[derive(Clone, Debug)]
pub struct VerifiedRouteExtension {
    encoded: Vec<u8>,
    message: RouteExtension,
}

impl VerifiedRouteExtension {
    /// Original canonical response bytes.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    /// Verified exact response scope and its effective path set.
    #[must_use]
    pub const fn message(&self) -> &RouteExtension {
        &self.message
    }
}

impl ReservationCoordinator {
    /// Sign one fresh extension phase using the same ephemeral session as the original route.
    ///
    /// # Errors
    /// Rejects another session, malformed phase or a lifetime outside the original hard expiry.
    pub fn sign_route_extension_request(
        &self,
        request: &RouteExtensionRequest,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        sign_control_message(
            request,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            generate_nonce(),
            TimePolicy::default(),
        )
        .map_err(CoordinatorError::from)
    }

    /// Verify the exact Exit response against the immutable original bundle and requested phase.
    ///
    /// # Errors
    /// Rejects replay, changed parent/session/identity, changed path, exceeded original capacity,
    /// mismatched nested grant/confirmation, or an extended lifetime.
    #[allow(clippy::too_many_lines, reason = "one complete response binding")]
    pub fn verify_route_extension_response(
        &mut self,
        original: &VerifiedFinalizedExitBundle,
        request: &RouteExtensionRequest,
        encoded: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedRouteExtension, CoordinatorError> {
        request.validate()?;
        let scope = request
            .scope
            .as_ref()
            .ok_or(CoordinatorError::Scope("extension scope"))?;
        let parent = scope.parent()?;
        let capability_envelope: SignedEnvelope =
            decode_canonical(&original.signed_capability, MAX_CONTROL_MESSAGE_SIZE)?;
        let capability: ClientSessionCapability =
            decode_canonical(&capability_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
        if scope.signed_exit_reservation != original.signed_exit_reservation
            || scope.finalized_bundle_hash.as_slice() != original.finalized_bundle_hash
            || parent.client_session_id.as_slice() != self.client_session_id
            || parent.client_session_public_key.as_slice() != self.client_session_public_key()
            || scope.path_id > capability.probe_permit_limit
        {
            return Err(CoordinatorError::Scope("extension original authority"));
        }
        let verified = verify_control_message::<RouteExtension>(
            encoded,
            now_ms,
            TimePolicy::default(),
            &mut self.exit_replay,
        )?;
        let replay = (*verified.sender_id(), *verified.nonce());
        let result = (|| {
            let message = verified.message();
            if message.scope != request.scope
                || message.phase != request.phase
                || verified.sender_id().as_slice() != parent.exit_node_id
                || message.hard_expires_at_ms != parent.expires_at_ms
                || message.selected_path_ids.len()
                    > usize::try_from(capability.maximum_paths).unwrap_or(0)
            {
                return Err(CoordinatorError::Scope("extension response"));
            }
            if !message.signed_probe_permit.is_empty() {
                let mut replay = ReplayCache::new(1)?;
                let permit = verify_control_message::<RelayProbePermit>(
                    &message.signed_probe_permit,
                    now_ms,
                    TimePolicy::default(),
                    &mut replay,
                )?;
                let p = permit.message();
                if permit.sender_id().as_slice() != parent.exit_node_id
                    || p.probe_id != scope.probe_id
                    || p.path_id != scope.path_id
                    || p.relay_node_id != scope.relay_node_id
                    || p.relay_peer_id != scope.relay_peer_id
                    || p.reservation_id != parent.reservation_id
                    || p.route_context_id != parent.route_context_id
                    || p.client_session_id != parent.client_session_id
                    || p.capability_id != parent.capability_id
                    || p.hold_id != parent.hold_id
                    || p.exit_boot_id != parent.exit_boot_id
                    || p.exit_node_id != parent.exit_node_id
                    || p.exit_peer_id != parent.exit_peer_id
                    || p.control_relay_node_id != parent.control_relay_node_id
                    || p.control_relay_peer_id != parent.control_relay_peer_id
                    || p.policy_hash != parent.policy_hash
                    || p.transport != Transport::TcpMptcp as i32
                    || p.address_family != scope.address_family
                    || p.expires_at_ms > parent.expires_at_ms
                {
                    return Err(CoordinatorError::Scope("extension permit"));
                }
            }
            if !message.signed_relay_authorization.is_empty() {
                let mut replay = ReplayCache::new(1)?;
                let grant = verify_control_message::<RelayAuthorization>(
                    &message.signed_relay_authorization,
                    now_ms,
                    TimePolicy::default(),
                    &mut replay,
                )?;
                let g = grant.message();
                if grant.sender_id().as_slice() != parent.exit_node_id
                    || g.path_id != scope.path_id
                    || g.relay_node_id != scope.relay_node_id
                    || g.relay_peer_id != scope.relay_peer_id
                    || g.reservation_id != parent.reservation_id
                    || g.route_context_id != parent.route_context_id
                    || g.client_session_id != parent.client_session_id
                    || g.client_session_public_key != parent.client_session_public_key
                    || g.exit_node_id != parent.exit_node_id
                    || g.exit_peer_id != parent.exit_peer_id
                    || g.capability_id != parent.capability_id
                    || g.hold_id != parent.hold_id
                    || g.finalize_id != parent.finalize_id
                    || g.exit_boot_id != parent.exit_boot_id
                    || g.policy_hash != parent.policy_hash
                    || g.control_relay_node_id != parent.control_relay_node_id
                    || g.control_relay_peer_id != parent.control_relay_peer_id
                    || g.allowed_transports != parent.allowed_transports
                    || g.maximum_up_mbps != parent.reserved_up_mbps
                    || g.maximum_down_mbps != parent.reserved_down_mbps
                    || g.created_at_ms != parent.created_at_ms
                    || g.expires_at_ms != parent.expires_at_ms
                    || request.path.as_ref().is_some_and(|p| {
                        p.client_wireguard_public_key != g.client_wireguard_public_key
                    })
                {
                    return Err(CoordinatorError::Scope("extension relay authorization"));
                }
            }
            if request.phase == RouteExtensionPhase::Commit as i32 {
                let mut replay = ReplayCache::new(1)?;
                let receipt = verify_control_message::<ExitConfirmationReceipt>(
                    &message.signed_confirmation_receipt,
                    now_ms,
                    TimePolicy::default(),
                    &mut replay,
                )?;
                let r = receipt.message();
                if receipt.sender_id().as_slice() != parent.exit_node_id
                    || r.path_id != scope.path_id
                    || r.reservation_id != parent.reservation_id
                    || r.route_context_id != parent.route_context_id
                    || r.finalized_bundle_hash != scope.finalized_bundle_hash
                    || r.confirmation_envelope_hash.as_slice()
                        != exit_confirmation_envelope_hash(&request.signed_confirmation)?
                {
                    return Err(CoordinatorError::Scope("extension commit receipt"));
                }
            }
            Ok(VerifiedRouteExtension {
                encoded: encoded.to_vec(),
                message: message.clone(),
            })
        })();
        if result.is_err() {
            let _ = self.exit_replay.rollback(&replay.0, &replay.1);
        }
        result
    }

    /// Retain only the new helper lease and sign its normal Relay capacity request.
    ///
    /// # Errors
    /// Rejects a non-Authorize response, wrong parent/context/key or duplicate local lease.
    pub fn sign_extension_relay_request(
        &mut self,
        original: &VerifiedFinalizedExitBundle,
        extension: &VerifiedRouteExtension,
        endpoint: ClientEndpointLease,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        let scope = extension
            .message
            .scope
            .as_ref()
            .ok_or(CoordinatorError::Scope("extension scope"))?;
        let parent = scope.parent()?;
        if extension.message.phase != RouteExtensionPhase::Authorize as i32
            || scope.signed_exit_reservation != original.signed_exit_reservation
            || scope.finalized_bundle_hash.as_slice() != original.finalized_bundle_hash
            || endpoint.route_context_id().as_slice() != parent.route_context_id
            || endpoint.path_id() != scope.path_id
            || self.client_paths.len() >= MAX_LOCAL_PATH_LEASES
        {
            return Err(CoordinatorError::Scope("extension endpoint scope"));
        }
        let key = ClientPathKey {
            reservation_id: fixed(&parent.reservation_id, "extension reservation")?,
            path_id: scope.path_id,
        };
        if self.client_paths.contains_key(&key) {
            return Err(CoordinatorError::Scope(
                "extension endpoint already retained",
            ));
        }
        let envelope: SignedEnvelope = decode_canonical(
            &extension.message.signed_relay_authorization,
            MAX_CONTROL_MESSAGE_SIZE,
        )?;
        let authorization: RelayAuthorization =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
        if authorization.client_wireguard_public_key.as_slice()
            != endpoint.public_endpoint().public_key().as_bytes()
        {
            return Err(CoordinatorError::Scope("extension endpoint key"));
        }
        let nonce = generate_nonce();
        let request = RelayReservationRequest {
            client_session_id: self.client_session_id.to_vec(),
            exit_authorization: extension.message.signed_relay_authorization.clone(),
            created_at_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
            client_wireguard_endpoint: Some(wire_endpoint(endpoint.public_endpoint())),
            client_session_capability: original.signed_capability.clone(),
            exit_reservation: original.signed_exit_reservation.clone(),
        };
        let encoded = sign_control_message(
            &request,
            &self.session_key,
            created_at_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )?;
        self.client_paths.insert(
            key,
            ClientPathState {
                endpoint,
                expires_at_ms: parent.expires_at_ms,
            },
        );
        Ok(encoded)
    }

    /// Verify the new Relay's real normal capacity grant against its exact extension grant.
    ///
    /// # Errors
    /// Rejects signature, replay, changed parent, wrong Relay or helper endpoint substitution.
    pub fn verify_extension_relay_response(
        &mut self,
        original: &VerifiedFinalizedExitBundle,
        extension: &VerifiedRouteExtension,
        encoded: &[u8],
        authenticated_peer: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedRelayGrant, CoordinatorError> {
        let scope = extension
            .message
            .scope
            .as_ref()
            .ok_or(CoordinatorError::Scope("extension scope"))?;
        if extension.message.phase != RouteExtensionPhase::Authorize as i32
            || scope.signed_exit_reservation != original.signed_exit_reservation
            || scope.finalized_bundle_hash.as_slice() != original.finalized_bundle_hash
            || scope.relay_peer_id != authenticated_peer
        {
            return Err(CoordinatorError::Scope("extension relay response scope"));
        }
        self.verify_relay_response_inner(
            &extension.message.signed_relay_authorization,
            original.finalized_bundle_hash,
            encoded,
            fixed(&scope.relay_node_id, "extension relay")?,
            authenticated_peer,
            now_ms,
        )
    }
}
