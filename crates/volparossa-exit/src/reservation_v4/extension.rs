//! Bounded one-path transactions retaining the original finalized route authority.

#[allow(
    clippy::wildcard_imports,
    reason = "extension is an internal reservation phase"
)]
use super::*;
use volparossa_protocol::{
    RouteExtension, RouteExtensionPhase, RouteExtensionRequest, RouteExtensionScope,
};

#[derive(Clone)]
pub(crate) struct ExtensionState {
    scope: RouteExtensionScope,
    deadline: u64,
    phase: RouteExtensionPhase,
    permit: Vec<u8>,
    authorization: Vec<u8>,
    responses: Vec<(Vec<u8>, AcceptedRouteExtension)>,
}

/// One Exit-signed result, without replacing its original finalized reservation.
#[derive(Clone)]
pub struct AcceptedRouteExtension {
    encoded: Vec<u8>,
    message: RouteExtension,
    confirmed: Option<ConfirmedExitPath>,
    signed_capability: Vec<u8>,
}

impl AcceptedRouteExtension {
    /// Exact original capability retained locally; never a replacement or newly signed lease.
    #[must_use]
    pub fn signed_capability(&self) -> &[u8] {
        &self.signed_capability
    }
    /// Canonical Exit-signed extension response.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    /// Exact typed signed result, including the effective path set only after Commit.
    #[must_use]
    pub const fn message(&self) -> &RouteExtension {
        &self.message
    }
    /// Independently confirmed new Relay endpoint, available only for Commit.
    #[must_use]
    pub const fn confirmed_path(&self) -> Option<ConfirmedExitPath> {
        self.confirmed
    }
}

impl ExitService {
    /// Execute one replay-bound phase of a one-path extension of a live finalized MPTCP route.
    ///
    /// The original signed reservation, native identity, capacity allocation and hard expiry
    /// remain unchanged. The caller owns helper preparation/commit/abort and supplies original
    /// real probe evidence. All invocations must arrive via the original authenticated control
    /// Relay. A committed extension is terminal; it is retired with the original route owner.
    ///
    /// # Errors
    /// Rejects a stale or substituted parent, nonfresh probe, duplicate/over-budget path, changed
    /// forwarding identity, phase replay, unavailable helper lease or failed signature.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one fail-closed signed phase transaction"
    )]
    pub fn extend_route_with<V, E, F>(
        &mut self,
        encoded_request: &[u8],
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        evidence_verifier: &V,
        mut endpoint_provider: E,
        mut signer: F,
    ) -> Result<AcceptedRouteExtension, ExitError>
    where
        V: ProbeEvidenceVerifier + ?Sized,
        E: FnMut(u32) -> Option<ExitEndpointLease>,
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_local_identity(local_public_key)?;
        self.purge_expired(now_ms);
        // Shape is inspected only to find an exact retained retry; signature is required below
        // for every new request. Retried bytes are never accepted under another forwarding peer.
        let request: RouteExtensionRequest = decode_signed_payload(encoded_request)?;
        let scope = request
            .scope
            .as_ref()
            .ok_or(ExitError::InvalidGrant("extension scope"))?;
        let parent = scope.parent()?;
        let reservation_id = fixed(&parent.reservation_id, "extension reservation")?;
        let key = text_id::<ReservationId>(&reservation_id)?;
        let state = self
            .endpoint_states
            .get(&key)
            .cloned()
            .ok_or(ExitError::InvalidGrant("extension parent absent"))?;
        let extension_id = fixed(&scope.extension_id, "extension id")?;
        if state.phase != ExitReservationPhase::Finalized
            || state.signed_exit_reservation != scope.signed_exit_reservation
            || state
                .finalized_bundle_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice)
                != Some(scope.finalized_bundle_hash.as_slice())
            || state.expires_at_ms <= now_ms
            || state.exit_boot_id != self.exit_boot_id
            || state.control_relay_node_id != *authenticated_control_relay_node_id
            || state.control_relay_peer_id != authenticated_control_relay_peer_id
            || state.policy_hash.as_slice() != self.policy.policy_hash()
        {
            return Err(ExitError::InvalidGrant("extension retained parent scope"));
        }
        if let Some(retained) = state.extensions.get(&extension_id) {
            if retained.scope != *scope {
                return Err(ExitError::InvalidGrant("extension id reused"));
            }
            if let Some((_, response)) = retained
                .responses
                .iter()
                .find(|(bytes, _)| bytes == encoded_request)
            {
                if request.phase != retained.phase as i32 {
                    return Err(ExitError::InvalidGrant("extension phase already advanced"));
                }
                let envelope: SignedEnvelope = decode_canonical(
                    encoded_request,
                    volparossa_protocol::MAX_ROUTE_EXTENSION_BYTES,
                )?;
                if envelope.expires_at_ms <= now_ms {
                    return Err(ExitError::InvalidGrant("extension retry expired"));
                }
                return Ok(response.clone());
            }
        }
        let verified = verify_control_message::<RouteExtensionRequest>(
            encoded_request,
            now_ms,
            TimePolicy::default(),
            &mut self.finalize_replay,
        )?;
        let replay = (*verified.sender_id(), *verified.nonce());
        let sender = *verified.sender_public_key();
        let envelope: SignedEnvelope = decode_canonical(
            encoded_request,
            volparossa_protocol::MAX_ROUTE_EXTENSION_BYTES,
        )?;
        let result = (|| {
            if sender != state.client_session_public_key {
                return Err(ExitError::InvalidGrant("extension session"));
            }
            let phase = RouteExtensionPhase::try_from(request.phase)
                .map_err(|_| ExitError::InvalidGrant("extension phase"))?;
            let mut retained = match (phase, state.extensions.get(&extension_id)) {
                (RouteExtensionPhase::Probe, None) => {
                    if state.paths.len() >= usize::try_from(state.maximum_paths).unwrap_or(0)
                        || state.paths.len() >= 8
                        || state.extensions.len() >= 8
                        || state
                            .paths
                            .iter()
                            .any(|p| p.relay_reservation_hash.is_none())
                        || scope.path_id > state.probe_permit_limit
                        || state.paths.iter().any(|p| {
                            p.path_id == scope.path_id
                                || p.relay_node_id.as_slice() == scope.relay_node_id
                                || p.relay_peer_id == scope.relay_peer_id
                        })
                        || state.extensions.values().any(|p| {
                            p.scope.path_id == scope.path_id
                                || p.scope.relay_node_id == scope.relay_node_id
                                || p.scope.relay_peer_id == scope.relay_peer_id
                                || p.scope.probe_id == scope.probe_id
                                || !matches!(
                                    p.phase,
                                    RouteExtensionPhase::Commit | RouteExtensionPhase::Abort
                                )
                        })
                    {
                        return Err(ExitError::InvalidGrant(
                            "extension new path budget or identity",
                        ));
                    }
                    ExtensionState {
                        scope: scope.clone(),
                        deadline: envelope.expires_at_ms,
                        phase,
                        permit: Vec::new(),
                        authorization: Vec::new(),
                        responses: Vec::new(),
                    }
                }
                (RouteExtensionPhase::Probe, Some(_)) | (_, None) => {
                    return Err(ExitError::InvalidGrant("extension phase order"));
                }
                (_, Some(retained)) => retained.clone(),
            };
            if (phase != RouteExtensionPhase::Abort
                && (retained.deadline <= now_ms || envelope.expires_at_ms > retained.deadline))
                || retained.phase == RouteExtensionPhase::Commit
                || (retained.phase == RouteExtensionPhase::Abort
                    && phase != RouteExtensionPhase::Abort)
            {
                return Err(ExitError::InvalidGrant("extension terminal or expired"));
            }
            let mut confirmed = None;
            let mut receipt = Vec::new();
            let mut new_path = None;
            let mut stored_permit = None;
            match phase {
                RouteExtensionPhase::Probe => {
                    let nonce = generate_nonce();
                    let permit = RelayProbePermit {
                        probe_id: scope.probe_id.clone(),
                        hold_id: state.hold_id.to_vec(),
                        capability_id: state.capability_id.to_vec(),
                        reservation_id: reservation_id.to_vec(),
                        route_context_id: state.route_context_id.to_vec(),
                        client_session_id: state.client_session_id.to_vec(),
                        exit_node_id: self.config.node_id.to_vec(),
                        exit_boot_id: self.exit_boot_id.to_vec(),
                        control_relay_node_id: state.control_relay_node_id.to_vec(),
                        control_relay_peer_id: state.control_relay_peer_id.clone(),
                        relay_node_id: scope.relay_node_id.clone(),
                        relay_peer_id: scope.relay_peer_id.clone(),
                        path_id: scope.path_id,
                        created_at_ms: envelope.timestamp_ms,
                        expires_at_ms: retained.deadline,
                        nonce: nonce.to_vec(),
                        exit_peer_id: state.exit_peer_id.clone(),
                        policy_hash: state.policy_hash.to_vec(),
                        transport: Transport::TcpMptcp as i32,
                        address_family: scope.address_family,
                    };
                    retained.permit = sign_control_message_with(
                        &permit,
                        local_public_key,
                        permit.created_at_ms,
                        permit.expires_at_ms,
                        nonce,
                        TimePolicy::default(),
                        &mut signer,
                    )?;
                    stored_permit = Some(ExitProbePermitState {
                        encoded: retained.permit.clone(),
                        probe_id: fixed(&scope.probe_id, "probe id")?,
                        relay_node_id: fixed(&scope.relay_node_id, "relay id")?,
                        relay_peer_id: scope.relay_peer_id.clone(),
                        path_id: scope.path_id,
                        transport: permit.transport,
                        address_family: scope.address_family,
                        expires_at_ms: retained.deadline,
                    });
                }
                RouteExtensionPhase::Authorize => {
                    if retained.phase != RouteExtensionPhase::Probe {
                        return Err(ExitError::InvalidGrant("extension authorization order"));
                    }
                    let path = request
                        .path
                        .as_ref()
                        .ok_or(ExitError::InvalidGrant("extension path"))?;
                    let stored = state
                        .permits
                        .get(&scope.path_id)
                        .ok_or(ExitError::InvalidGrant("extension permit absent"))?;
                    let permit: RelayProbePermit = decode_signed_payload(&retained.permit)?;
                    let mut replay = ReplayCache::new(1)?;
                    let measured = verify_control_message::<RelayProbeResult>(
                        &path.relay_probe_result,
                        now_ms,
                        TimePolicy::default(),
                        &mut replay,
                    )?;
                    if path.relay_probe_permit != retained.permit
                        || measured.sender_id().as_slice() != scope.relay_node_id
                        || peer_id_from_public_key(measured.sender_public_key())?
                            != scope.relay_peer_id
                        || !same_probe_scope(
                            &state,
                            self.config.node_id,
                            reservation_id,
                            path,
                            stored,
                            &permit,
                            measured.message(),
                        )
                        || measured.message().measured_at_ms < permit.created_at_ms
                    {
                        return Err(ExitError::InvalidGrant("extension fresh probe scope"));
                    }
                    let artifact = VerifiedProbeArtifact {
                        signed_permit: retained.permit.clone(),
                        signed_result: path.relay_probe_result.clone(),
                        permit,
                        result: measured.into_message(),
                    };
                    evidence_verifier
                        .verify(&artifact.evidence()?)
                        .map_err(map_probe_evidence_error)?;
                    let endpoint =
                        endpoint_provider(scope.path_id).ok_or(ExitError::EndpointUnavailable)?;
                    let client_public_key =
                        public_key(&path.client_wireguard_public_key, "extension Client key")?;
                    let first = state.paths.first().ok_or(ExitError::LeaseInvariant)?;
                    if endpoint.route_context_id() != &state.route_context_id
                        || endpoint.path_id() != scope.path_id
                        || endpoint.context_handle() != first.exit_endpoint.context_handle()
                        || endpoint.public_endpoint().public_key() == client_public_key
                        || self
                            .endpoint_states
                            .values()
                            .flat_map(|s| &s.paths)
                            .any(|p| {
                                p.exit_endpoint.lease_handle() == endpoint.lease_handle()
                                    || [
                                        p.client_public_key,
                                        p.exit_endpoint.public_endpoint().public_key(),
                                    ]
                                    .contains(&client_public_key)
                                    || [
                                        p.client_public_key,
                                        p.exit_endpoint.public_endpoint().public_key(),
                                    ]
                                    .contains(&endpoint.public_endpoint().public_key())
                                    || p.exit_endpoint.public_endpoint().listen_port()
                                        == endpoint.public_endpoint().listen_port()
                            })
                    {
                        return Err(ExitError::InvalidGrant("extension helper lease scope"));
                    }
                    let nonce = generate_nonce();
                    let authorization = RelayAuthorization {
                        reservation_id: reservation_id.to_vec(),
                        route_context_id: state.route_context_id.to_vec(),
                        path_id: scope.path_id,
                        relay_node_id: scope.relay_node_id.clone(),
                        exit_node_id: self.config.node_id.to_vec(),
                        client_session_id: state.client_session_id.to_vec(),
                        allowed_transports: state.allowed_transports.clone(),
                        maximum_up_mbps: state.reserved_up_mbps,
                        maximum_down_mbps: state.reserved_down_mbps,
                        client_wireguard_public_key: path.client_wireguard_public_key.clone(),
                        exit_wireguard_endpoint: Some(wire_endpoint(endpoint.public_endpoint())),
                        policy_hash: state.policy_hash.to_vec(),
                        created_at_ms: state.created_at_ms,
                        expires_at_ms: state.expires_at_ms,
                        nonce: nonce.to_vec(),
                        relay_peer_id: scope.relay_peer_id.clone(),
                        capability_id: state.capability_id.to_vec(),
                        client_session_public_key: state.client_session_public_key.to_vec(),
                        exit_boot_id: state.exit_boot_id.to_vec(),
                        hold_id: state.hold_id.to_vec(),
                        finalize_id: parent.finalize_id.clone(),
                        control_relay_node_id: state.control_relay_node_id.to_vec(),
                        control_relay_peer_id: state.control_relay_peer_id.clone(),
                        exit_peer_id: state.exit_peer_id.clone(),
                    };
                    retained.authorization = sign_control_message_with(
                        &authorization,
                        local_public_key,
                        authorization.created_at_ms,
                        authorization.expires_at_ms,
                        nonce,
                        TimePolicy::default(),
                        &mut signer,
                    )?;
                    new_path = Some(ExitPathState {
                        path_id: scope.path_id,
                        relay_node_id: fixed(&scope.relay_node_id, "relay id")?,
                        relay_peer_id: scope.relay_peer_id.clone(),
                        client_public_key,
                        exit_endpoint: endpoint,
                        authorization_hash: Sha256::digest(&retained.authorization).into(),
                        relay_exit_endpoint: None,
                        relay_reservation_hash: None,
                    });
                }
                RouteExtensionPhase::Commit => {
                    if retained.phase != RouteExtensionPhase::Authorize {
                        return Err(ExitError::InvalidGrant("extension commit order"));
                    }
                    let confirmation: ExitReservationConfirmation =
                        decode_signed_payload(&request.signed_confirmation)?;
                    if confirmation.path_id != scope.path_id
                        || confirmation.reservation_id != parent.reservation_id
                    {
                        return Err(ExitError::InvalidGrant("extension confirmation scope"));
                    }
                    let response = self.confirm_relay_with(
                        &request.signed_confirmation,
                        authenticated_control_relay_node_id,
                        authenticated_control_relay_peer_id,
                        now_ms,
                        local_public_key,
                        &mut signer,
                    )?;
                    receipt = response.signed_receipt().to_vec();
                    confirmed = Some(response.confirmed_path);
                }
                RouteExtensionPhase::Abort => {}
            }
            let mut selected_path_ids = state
                .paths
                .iter()
                .filter(|p| p.relay_reservation_hash.is_some())
                .map(|p| p.path_id)
                .collect::<Vec<_>>();
            if phase == RouteExtensionPhase::Commit {
                selected_path_ids.push(scope.path_id);
            }
            selected_path_ids.sort_unstable();
            selected_path_ids.dedup();
            let message = RouteExtension {
                scope: Some(scope.clone()),
                phase: phase as i32,
                signed_probe_permit: if phase == RouteExtensionPhase::Abort {
                    Vec::new()
                } else {
                    retained.permit.clone()
                },
                signed_relay_authorization: if phase == RouteExtensionPhase::Abort {
                    Vec::new()
                } else {
                    retained.authorization.clone()
                },
                signed_confirmation_receipt: receipt,
                selected_path_ids,
                hard_expires_at_ms: state.expires_at_ms,
            };
            let encoded = sign_control_message_with(
                &message,
                local_public_key,
                now_ms,
                if phase == RouteExtensionPhase::Commit {
                    state.expires_at_ms
                } else if phase == RouteExtensionPhase::Abort {
                    envelope.expires_at_ms
                } else {
                    retained.deadline
                },
                generate_nonce(),
                TimePolicy::default(),
                &mut signer,
            )?;
            let response = AcceptedRouteExtension {
                encoded,
                message,
                confirmed,
                signed_capability: state.signed_capability.clone(),
            };
            retained.phase = phase;
            if phase == RouteExtensionPhase::Abort {
                // Freshly signed cleanup retries may acknowledge the same terminal Abort after
                // a lost/expired response. They never renew the parent, reissue a permit, or
                // allocate another path. Retain only the latest acknowledgement so arbitrarily
                // many fresh request nonces cannot grow this per-extension response cache.
                retained.responses.clear();
                retained.permit.clear();
                retained.authorization.clear();
            }
            retained
                .responses
                .push((encoded_request.to_vec(), response.clone()));
            let live = self
                .endpoint_states
                .get_mut(&key)
                .ok_or(ExitError::LeaseInvariant)?;
            if let Some(permit) = stored_permit {
                live.permits.insert(scope.path_id, permit);
            }
            if let Some(path) = new_path {
                live.paths.push(path);
            }
            if phase == RouteExtensionPhase::Abort {
                live.paths.retain(|p| p.path_id != scope.path_id);
                live.permits.remove(&scope.path_id);
            }
            live.extensions.insert(extension_id, retained);
            Ok(response)
        })();
        if result.is_err() {
            let _ = self.finalize_replay.rollback(&replay.0, &replay.1);
        }
        result
    }
}
