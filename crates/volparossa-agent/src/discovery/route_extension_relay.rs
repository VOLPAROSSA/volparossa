//! Commit or discard only the newly added Relay's owned path, never the parent Exit session.

use super::{
    AgentState, Arc, DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse,
    DiscoveryRuntime, ExitReservation, ExitReservationConfirmation, FORWARD_ID_BYTES, Libp2pPeerId,
    RelayAuthorization, RelayProbePermit, ReplayCache, RwLock, SignedEnvelope, TimePolicy,
    Transport, decode_canonical, decoded_signed_payload, fixed_bytes, generate_nonce,
    log_relay_forward_admission, request_response, sign_control_message_with,
    signed_envelope_matches_peer, unix_millis, verify_control_message, verify_relay_reservation,
};
use sha2::{Digest, Sha256};
use volparossa_protocol::{
    MAX_ROUTE_EXTENSION_BYTES, RetirementReceipt, RouteExtension, RouteExtensionPhase,
    RouteExtensionRelayCommit, RouteExtensionRequest, RouteExtensionScope, RouteRetire,
    VerifiedControlMessage, route_retire_request_hash,
};

fn checked<T: volparossa_protocol::ControlPayload>(
    bytes: &[u8],
    now: u64,
) -> Option<VerifiedControlMessage<T>> {
    verify_control_message(
        bytes,
        now,
        TimePolicy::default(),
        &mut ReplayCache::new(1).ok()?,
    )
    .ok()
}

fn parent(scope: &RouteExtensionScope, now: u64) -> Option<ExitReservation> {
    let parent = checked::<ExitReservation>(&scope.signed_exit_reservation, now)?;
    let exit_peer = Libp2pPeerId::from_bytes(&parent.message().exit_peer_id).ok()?;
    (scope.parent().ok()? == *parent.message()
        && signed_envelope_matches_peer(&scope.signed_exit_reservation, &exit_peer))
    .then(|| parent.into_message())
}

fn wrapper_matches<T>(
    request: &DatapathRelayRequest,
    signed: &VerifiedControlMessage<T>,
    scope: &RouteExtensionScope,
    hard_expiry: u64,
    now: u64,
) -> bool {
    request.request_id() == &signed.nonce()[..FORWARD_ID_BYTES]
        && super::deadline_is_bounded(request.deadline_unix_ms(), now)
        && request.deadline_unix_ms() <= signed.expires_at_ms().min(hard_expiry)
        && request.relay_node_id() == scope.relay_node_id
        && request.relay_peer_id() == scope.relay_peer_id
}

fn permit_matches(
    permit: &RelayProbePermit,
    scope: &RouteExtensionScope,
    parent: &ExitReservation,
) -> bool {
    permit.probe_id == scope.probe_id
        && permit.path_id == scope.path_id
        && permit.relay_node_id == scope.relay_node_id
        && permit.relay_peer_id == scope.relay_peer_id
        && permit.address_family == scope.address_family
        && permit.reservation_id == parent.reservation_id
        && permit.route_context_id == parent.route_context_id
        && permit.client_session_id == parent.client_session_id
        && permit.capability_id == parent.capability_id
        && permit.hold_id == parent.hold_id
        && permit.exit_boot_id == parent.exit_boot_id
        && permit.exit_node_id == parent.exit_node_id
        && permit.exit_peer_id == parent.exit_peer_id
        && permit.control_relay_node_id == parent.control_relay_node_id
        && permit.control_relay_peer_id == parent.control_relay_peer_id
        && permit.policy_hash == parent.policy_hash
        && permit.transport == Transport::TcpMptcp as i32
        && permit.created_at_ms >= parent.created_at_ms
        && permit.expires_at_ms <= parent.expires_at_ms
}

pub(super) fn extension_probe_scope_matches(request: &DatapathRelayRequest, now: u64) -> bool {
    (|| {
        let signed = checked::<RouteExtensionRequest>(request.client_signed_request(), now)?;
        let scope = signed.message().scope.as_ref()?;
        let parent = parent(scope, now)?;
        let permit = checked::<RelayProbePermit>(request.exit_signed_authorization(), now)?;
        let exit_peer = Libp2pPeerId::from_bytes(&parent.exit_peer_id).ok()?;
        Some(
            request.validated_operation() == Ok(DatapathRelayOperation::ExtensionProbe)
                && signed.message().phase == RouteExtensionPhase::Probe as i32
                && wrapper_matches(request, &signed, scope, parent.expires_at_ms, now)
                && request.deadline_unix_ms() <= permit.expires_at_ms()
                && signed_envelope_matches_peer(request.exit_signed_authorization(), &exit_peer)
                && permit_matches(permit.message(), scope, &parent),
        )
    })()
    .unwrap_or(false)
}

struct AuthorizedExtension {
    extension: RouteExtension,
    parent: ExitReservation,
}

fn authorization_matches(
    grant: &RelayAuthorization,
    scope: &RouteExtensionScope,
    parent: &ExitReservation,
) -> bool {
    grant.path_id == scope.path_id
        && grant.relay_node_id == scope.relay_node_id
        && grant.relay_peer_id == scope.relay_peer_id
        && grant.reservation_id == parent.reservation_id
        && grant.route_context_id == parent.route_context_id
        && grant.client_session_id == parent.client_session_id
        && grant.client_session_public_key == parent.client_session_public_key
        && grant.exit_node_id == parent.exit_node_id
        && grant.exit_peer_id == parent.exit_peer_id
        && grant.capability_id == parent.capability_id
        && grant.hold_id == parent.hold_id
        && grant.finalize_id == parent.finalize_id
        && grant.exit_boot_id == parent.exit_boot_id
        && grant.policy_hash == parent.policy_hash
        && grant.control_relay_node_id == parent.control_relay_node_id
        && grant.control_relay_peer_id == parent.control_relay_peer_id
        && grant.allowed_transports == parent.allowed_transports
        && grant.maximum_up_mbps == parent.reserved_up_mbps
        && grant.maximum_down_mbps == parent.reserved_down_mbps
        && grant.created_at_ms == parent.created_at_ms
        && grant.expires_at_ms == parent.expires_at_ms
}

fn authorized_extension(
    request: &DatapathRelayRequest,
    now: u64,
    destruction_only: bool,
) -> Option<AuthorizedExtension> {
    // A fresh destruction request may use an expired setup envelope solely to identify what
    // must be removed. It never grants activation, renewal or a different parent reservation.
    let verification_time = if destruction_only {
        let envelope: SignedEnvelope = decode_canonical(
            request.exit_signed_authorization(),
            MAX_ROUTE_EXTENSION_BYTES,
        )
        .ok()?;
        now.min(envelope.expires_at_ms.checked_sub(1)?)
    } else {
        now
    };
    let signed = checked::<RouteExtension>(request.exit_signed_authorization(), verification_time)?;
    let extension = signed.message();
    let scope = extension.scope.as_ref()?;
    let parent = parent(scope, now)?;
    let exit_peer = Libp2pPeerId::from_bytes(&parent.exit_peer_id).ok()?;
    let grant = checked::<RelayAuthorization>(&extension.signed_relay_authorization, now)?;
    if extension.phase != RouteExtensionPhase::Authorize as i32
        || extension.selected_path_ids.contains(&scope.path_id)
        || !signed_envelope_matches_peer(request.exit_signed_authorization(), &exit_peer)
        || !signed_envelope_matches_peer(&extension.signed_relay_authorization, &exit_peer)
        || !authorization_matches(grant.message(), scope, &parent)
        || request.relay_node_id() != scope.relay_node_id
        || request.relay_peer_id() != scope.relay_peer_id
    {
        return None;
    }
    Some(AuthorizedExtension {
        extension: signed.into_message(),
        parent,
    })
}

struct CommitScope {
    authority: AuthorizedExtension,
    confirmation: ExitReservationConfirmation,
}

fn commit_scope(request: &DatapathRelayRequest, now: u64) -> Option<CommitScope> {
    if request.validated_operation().ok()? != DatapathRelayOperation::ExtensionCommit {
        return None;
    }
    let authority = authorized_extension(request, now, false)?;
    let scope = authority.extension.scope.as_ref()?;
    let parent = &authority.parent;
    let signed = checked::<ExitReservationConfirmation>(request.client_signed_request(), now)?;
    let confirmation = signed.message();
    let mut seen = ReplayCache::new(2).ok()?;
    let (relay, _) = verify_relay_reservation(
        &confirmation.relay_reservation,
        now,
        TimePolicy::default(),
        &mut seen,
    )
    .ok()?;
    let relay_peer = Libp2pPeerId::from_bytes(&scope.relay_peer_id).ok()?;
    if !wrapper_matches(request, &signed, scope, parent.expires_at_ms, now)
        || !signed_envelope_matches_peer(&confirmation.relay_reservation, &relay_peer)
        || relay.message().exit_authorization != authority.extension.signed_relay_authorization
        || confirmation.path_id != scope.path_id
        || confirmation.relay_node_id != scope.relay_node_id
        || confirmation.reservation_id != parent.reservation_id
        || confirmation.route_context_id != parent.route_context_id
        || confirmation.client_session_id != parent.client_session_id
        || confirmation.client_session_public_key != parent.client_session_public_key
        || confirmation.exit_node_id != parent.exit_node_id
        || confirmation.exit_peer_id != parent.exit_peer_id
        || confirmation.policy_hash != parent.policy_hash
        || confirmation.capability_id != parent.capability_id
        || confirmation.hold_id != parent.hold_id
        || confirmation.finalize_id != parent.finalize_id
        || confirmation.exit_boot_id != parent.exit_boot_id
        || confirmation.control_relay_node_id != parent.control_relay_node_id
        || confirmation.control_relay_peer_id != parent.control_relay_peer_id
        || confirmation.created_at_ms < parent.created_at_ms
        || confirmation.expires_at_ms > parent.expires_at_ms
    {
        return None;
    }
    Some(CommitScope {
        authority,
        confirmation: signed.into_message(),
    })
}

pub(super) fn extension_commit_scope_matches(request: &DatapathRelayRequest, now: u64) -> bool {
    commit_scope(request, now).is_some()
}

fn abort_scope(
    request: &DatapathRelayRequest,
    now: u64,
) -> Option<(AuthorizedExtension, VerifiedControlMessage<RouteRetire>)> {
    if request.validated_operation().ok()? != DatapathRelayOperation::ExtensionAbort {
        return None;
    }
    let authority = authorized_extension(request, now, true)?;
    let scope = authority.extension.scope.as_ref()?;
    let parent = &authority.parent;
    let signed = checked::<RouteRetire>(request.client_signed_request(), now)?;
    let retire = signed.message();
    if !wrapper_matches(request, &signed, scope, parent.expires_at_ms, now)
        || retire.route_context_id != parent.route_context_id
        || retire.reservation_id != parent.reservation_id
        || retire.policy_hash != parent.policy_hash
        || retire.client_session_id != parent.client_session_id
        || retire.client_session_public_key != parent.client_session_public_key
    {
        return None;
    }
    Some((authority, signed))
}

pub(super) fn extension_abort_scope_matches(request: &DatapathRelayRequest, now: u64) -> bool {
    abort_scope(request, now).is_some()
}

impl DiscoveryRuntime {
    pub(super) async fn answer_route_extension_relay(
        &mut self,
        authenticated_client_peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let Ok(
            operation @ (DatapathRelayOperation::ExtensionCommit
            | DatapathRelayOperation::ExtensionAbort),
        ) = request.validated_operation()
        else {
            return;
        };
        let local_peer = *self.service.local_peer_id();
        if request.validate().is_err()
            || authenticated_client_peer == local_peer
            || !self.roles.relay
            || self.relay_service.is_none()
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != local_peer.to_bytes()
        {
            self.send_native_datapath_unavailable(request, operation, channel);
            return;
        }
        let channel = if operation == DatapathRelayOperation::ExtensionCommit {
            let Some(channel) =
                self.defer_downlink_start_request(authenticated_client_peer, request, channel)
            else {
                return;
            };
            channel
        } else {
            channel
        };
        let result = if operation == DatapathRelayOperation::ExtensionCommit {
            self.commit_extension_relay(authenticated_client_peer, request)
                .await
        } else {
            self.abort_extension_relay(authenticated_client_peer, request)
                .await
        };
        let Some(signed) = result else {
            log_relay_forward_admission(Some(state), "ROUTE_EXTENSION_RELAY_REJECTED");
            self.send_native_datapath_unavailable(request, operation, channel);
            return;
        };
        let Ok(response) = DatapathRelayResponse::granted(
            request.request_id().to_vec(),
            operation,
            self.local_node_id.to_vec(),
            local_peer.to_bytes(),
            signed,
        ) else {
            self.send_native_datapath_unavailable(request, operation, channel);
            return;
        };
        // Delivery loss does not drop the committed affine owner; exact retries return its receipt.
        let _ = self.service.send_datapath_relay_response(channel, response);
        log_relay_forward_admission(Some(state), "ROUTE_EXTENSION_RELAY_COMPLETED");
    }

    async fn commit_extension_relay(
        &mut self,
        peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
    ) -> Option<Vec<u8>> {
        let now = unix_millis();
        let verified = commit_scope(request, now)?;
        let scope = verified.authority.extension.scope.as_ref()?;
        let context = fixed_bytes::<FORWARD_ID_BYTES>(&verified.authority.parent.route_context_id)?;
        let route = self.prepared_production_relay_routes.get(&context)?;
        let original_request: super::RelayReservationRequest =
            decoded_signed_payload(route.accepted.signed_client_relay_request())?;
        if !route.usable
            || route.authenticated_client_peer != peer
            || route.accepted.encoded() != verified.confirmation.relay_reservation
            || route.accepted.path_id() != scope.path_id
            || route.accepted.route_context_id() != &context
            || original_request.exit_reservation != scope.signed_exit_reservation
            || route.expires_at_ms != verified.authority.parent.expires_at_ms
            || route.expires_at_ms <= now
        {
            return None;
        }
        if let Some(prior) = &route.committed_start {
            let receipt = route.committed_signal.as_ref()?;
            let decoded: RouteExtensionRelayCommit = decoded_signed_payload(receipt)?;
            return (prior == request.client_signed_request()
                && decoded.authorization_sha256
                    == Sha256::digest(request.exit_signed_authorization()).to_vec()
                && decoded.confirmation_sha256
                    == Sha256::digest(request.client_signed_request()).to_vec())
            .then(|| receipt.clone());
        }
        let mut route = self.prepared_production_relay_routes.remove(&context)?;
        let commit = route.commit.take();
        let committed = if let Some(commit) = commit {
            self.helper
                .commit_lease_batch(&mut route.helper_owner, commit)
                .await
                .is_ok()
        } else {
            false
        };
        if !committed
            || self.relay_service.as_mut().is_none_or(|service| {
                service
                    .mark_tunnel_established(route.accepted.reservation_id(), unix_millis())
                    .is_err()
            })
        {
            self.retire_production_relay_route(context, route).await;
            return None;
        }
        let receipt = RouteExtensionRelayCommit {
            route_context_id: context.to_vec(),
            reservation_id: verified.authority.parent.reservation_id,
            extension_id: scope.extension_id.clone(),
            path_id: scope.path_id,
            relay_node_id: self.local_node_id.to_vec(),
            authorization_sha256: Sha256::digest(request.exit_signed_authorization()).to_vec(),
            confirmation_sha256: Sha256::digest(request.client_signed_request()).to_vec(),
            hard_expires_at_ms: route.expires_at_ms,
        };
        let timestamp = unix_millis();
        let signed = sign_control_message_with(
            &receipt,
            self.local_public_key,
            timestamp,
            timestamp
                .saturating_add(30_000)
                .min(request.deadline_unix_ms())
                .min(route.expires_at_ms),
            generate_nonce(),
            TimePolicy::default(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok();
        let Some(signed) = signed else {
            self.retire_production_relay_route(context, route).await;
            return None;
        };
        route.committed_start = Some(request.client_signed_request().to_vec());
        route.committed_signal = Some(signed.clone());
        self.prepared_production_relay_routes.insert(context, route);
        Some(signed)
    }

    async fn abort_extension_relay(
        &mut self,
        peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
    ) -> Option<Vec<u8>> {
        let (authority, signed) = abort_scope(request, unix_millis())?;
        let scope = authority.extension.scope.as_ref()?;
        let context = fixed_bytes::<FORWARD_ID_BYTES>(&authority.parent.route_context_id)?;
        if let Some(route) = self.prepared_production_relay_routes.get(&context) {
            let relay: super::RelayReservation = decoded_signed_payload(route.accepted.encoded())?;
            let original_request: super::RelayReservationRequest =
                decoded_signed_payload(route.accepted.signed_client_relay_request())?;
            if route.authenticated_client_peer != peer
                || route.accepted.path_id() != scope.path_id
                || relay.exit_authorization != authority.extension.signed_relay_authorization
                || original_request.exit_reservation != scope.signed_exit_reservation
            {
                return None;
            }
        }
        if !self.begin_extension_relay_retirement(
            context,
            peer,
            signed.message(),
            &authority.parent,
        ) {
            return None;
        }
        if let Some(route) = self.prepared_production_relay_routes.remove(&context) {
            if !self.retire_production_relay_route(context, route).await {
                return None;
            }
        }
        let receipt = RetirementReceipt {
            route_context_id: authority.parent.route_context_id,
            reservation_id: authority.parent.reservation_id,
            request_hash: route_retire_request_hash(request.client_signed_request())
                .ok()?
                .to_vec(),
            provider_node_id: self.local_node_id.to_vec(),
            confirmed_destroyed: true,
            signed_exit_receipt: Vec::new(),
        };
        sign_control_message_with(
            &receipt,
            self.local_public_key,
            unix_millis(),
            signed.expires_at_ms(),
            generate_nonce(),
            TimePolicy::default(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_protocol::{ProbeAddressFamily, sign_control_message};
    use volparossa_test_support::SignedRouteFixture;

    const NOW: u64 = 1_800_000_000_000;

    // Downstream wire-boundary fixture only; does not claim fresh discovery or kernel traffic.
    fn fixture() -> (SignedRouteFixture, RouteExtensionScope, Vec<u8>, Vec<u8>) {
        let fixture = SignedRouteFixture::new(3, &[Transport::TcpMptcp], NOW).unwrap();
        let parent: ExitReservation = decoded_signed_payload(fixture.exit_reservation()).unwrap();
        let scope = RouteExtensionScope {
            extension_id: vec![19; 16],
            signed_exit_reservation: fixture.exit_reservation().to_vec(),
            finalized_bundle_hash: fixture.finalized_bundle_hash().to_vec(),
            path_id: 3,
            relay_node_id: fixture.relay_node_id(2).unwrap().to_vec(),
            relay_peer_id: fixture.relay_peer_id(2).unwrap().to_vec(),
            probe_id: vec![20; 16],
            address_family: ProbeAddressFamily::Ipv4 as i32,
        };
        let authorization = RouteExtension {
            scope: Some(scope.clone()),
            phase: RouteExtensionPhase::Authorize as i32,
            signed_probe_permit: vec![1],
            signed_relay_authorization: fixture.relay_authorization(2).unwrap().to_vec(),
            signed_confirmation_receipt: Vec::new(),
            selected_path_ids: vec![1, 2],
            hard_expires_at_ms: parent.expires_at_ms,
        };
        let signed_authorization = sign_control_message(
            &authorization,
            fixture.exit_key(),
            NOW,
            NOW + 10_000,
            generate_nonce(),
            TimePolicy::default(),
        )
        .unwrap();
        let nonce = generate_nonce();
        let confirmation = ExitReservationConfirmation {
            reservation_id: parent.reservation_id,
            route_context_id: parent.route_context_id,
            path_id: 3,
            relay_node_id: scope.relay_node_id.clone(),
            exit_node_id: parent.exit_node_id,
            client_session_id: parent.client_session_id,
            policy_hash: parent.policy_hash,
            relay_reservation: fixture.relay_reservations()[2].clone(),
            created_at_ms: NOW,
            expires_at_ms: NOW + 10_000,
            nonce: nonce.to_vec(),
            capability_id: parent.capability_id,
            client_session_public_key: parent.client_session_public_key,
            exit_boot_id: parent.exit_boot_id,
            hold_id: parent.hold_id,
            finalize_id: parent.finalize_id,
            control_relay_node_id: parent.control_relay_node_id,
            control_relay_peer_id: parent.control_relay_peer_id,
            exit_peer_id: parent.exit_peer_id,
        };
        let signed_confirmation = sign_control_message(
            &confirmation,
            fixture.client_key(),
            NOW,
            NOW + 10_000,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        (fixture, scope, signed_authorization, signed_confirmation)
    }

    fn wrapper(
        scope: &RouteExtensionScope,
        operation: DatapathRelayOperation,
        client: Vec<u8>,
        authorization: Vec<u8>,
    ) -> DatapathRelayRequest {
        let envelope: SignedEnvelope =
            decode_canonical(&client, MAX_ROUTE_EXTENSION_BYTES).unwrap();
        DatapathRelayRequest::new(
            envelope.nonce[..16].to_vec(),
            scope.relay_node_id.clone(),
            scope.relay_peer_id.clone(),
            envelope.expires_at_ms,
            operation,
            client,
            authorization,
        )
        .unwrap()
    }

    #[test]
    fn extension_commit_checks_signed_original_parent_and_exact_new_relay_grant() {
        let (fixture, scope, authorization, confirmation) = fixture();
        let request = wrapper(
            &scope,
            DatapathRelayOperation::ExtensionCommit,
            confirmation.clone(),
            authorization.clone(),
        );
        assert!(extension_commit_scope_matches(&request, NOW + 1));
        let mut wrong =
            decoded_signed_payload::<ExitReservationConfirmation>(&confirmation).unwrap();
        wrong.route_context_id = vec![88; 16];
        let wrong = sign_control_message(
            &wrong,
            fixture.client_key(),
            NOW,
            NOW + 10_000,
            wrong.nonce.as_slice().try_into().unwrap(),
            TimePolicy::default(),
        )
        .unwrap();
        assert!(!extension_commit_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionCommit,
                wrong,
                authorization.clone()
            ),
            NOW + 1
        ));
        let mut wrong_target = scope.clone();
        wrong_target.relay_node_id = fixture.relay_node_id(0).unwrap().to_vec();
        wrong_target.relay_peer_id = fixture.relay_peer_id(0).unwrap().to_vec();
        assert!(!extension_commit_scope_matches(
            &wrapper(
                &wrong_target,
                DatapathRelayOperation::ExtensionCommit,
                confirmation.clone(),
                authorization.clone()
            ),
            NOW + 1
        ));
        let mut corrupted = authorization;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(!extension_commit_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionCommit,
                confirmation,
                corrupted
            ),
            NOW + 1
        ));
    }

    #[test]
    fn extension_abort_accepts_expired_setup_only_for_fresh_exact_destruction() {
        let (fixture, scope, authorization, confirmation) = fixture();
        let parent: ExitReservation = decoded_signed_payload(fixture.exit_reservation()).unwrap();
        let retire = RouteRetire {
            route_context_id: parent.route_context_id,
            reservation_id: parent.reservation_id,
            policy_hash: parent.policy_hash,
            client_session_id: parent.client_session_id,
            client_session_public_key: parent.client_session_public_key,
        };
        let signed = sign_control_message(
            &retire,
            fixture.client_key(),
            NOW + 11_000,
            NOW + 20_000,
            generate_nonce(),
            TimePolicy::default(),
        )
        .unwrap();
        assert!(extension_abort_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionAbort,
                signed,
                authorization.clone()
            ),
            NOW + 12_000
        ));
        assert!(!extension_commit_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionCommit,
                confirmation,
                authorization.clone()
            ),
            NOW + 12_000
        ));
        let mut wrong = retire;
        wrong.reservation_id = vec![44; 16];
        let signed = sign_control_message(
            &wrong,
            fixture.client_key(),
            NOW + 11_000,
            NOW + 20_000,
            generate_nonce(),
            TimePolicy::default(),
        )
        .unwrap();
        assert!(!extension_abort_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionAbort,
                signed,
                authorization
            ),
            NOW + 12_000
        ));
    }

    #[tokio::test]
    async fn extension_abort_before_reserve_keeps_admission_tombstone() {
        let (fixture, scope, _, _) = fixture();
        let (mut runtime, _, _directory) = super::super::tests::retirement_runtime_fixture();
        let parent: ExitReservation = decoded_signed_payload(fixture.exit_reservation()).unwrap();
        let context = fixed_bytes(&parent.route_context_id).unwrap();
        let peer = *volparossa_identity::Identity::generate().peer_id();
        let retire = RouteRetire {
            route_context_id: parent.route_context_id.clone(),
            reservation_id: parent.reservation_id.clone(),
            policy_hash: parent.policy_hash.clone(),
            client_session_id: parent.client_session_id.clone(),
            client_session_public_key: parent.client_session_public_key.clone(),
        };
        assert!(runtime.prepared_production_relay_routes.is_empty());
        assert!(runtime.begin_extension_relay_retirement(context, peer, &retire, &parent));
        assert!(runtime.begin_extension_relay_retirement(context, peer, &retire, &parent));
        let delayed = wrapper(
            &scope,
            DatapathRelayOperation::ReservePath,
            fixture.relay_request(2).unwrap().to_vec(),
            Vec::new(),
        );
        assert!(runtime.retired_relay_datapath(&delayed));
        let relay_request = decoded_signed_payload::<super::super::RelayReservationRequest>(
            delayed.client_signed_request(),
        )
        .unwrap();
        assert!(!runtime.retain_relay_retirement(peer, &relay_request));
        assert!(!runtime.begin_extension_relay_retirement(
            context,
            *volparossa_identity::Identity::generate().peer_id(),
            &retire,
            &parent
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one signed permit fixture exercises the nonce, family and probe bindings"
    )]
    fn extension_probe_checks_exact_permit_probe_family_and_client_nonce() {
        let (fixture, scope, _, _) = fixture();
        let parent: ExitReservation = decoded_signed_payload(fixture.exit_reservation()).unwrap();
        let request = RouteExtensionRequest {
            scope: Some(scope.clone()),
            phase: RouteExtensionPhase::Probe as i32,
            path: None,
            signed_confirmation: Vec::new(),
        };
        let signed = sign_control_message(
            &request,
            fixture.client_key(),
            NOW,
            NOW + 10_000,
            generate_nonce(),
            TimePolicy::default(),
        )
        .unwrap();
        let nonce = generate_nonce();
        let permit = RelayProbePermit {
            probe_id: scope.probe_id.clone(),
            path_id: scope.path_id,
            relay_node_id: scope.relay_node_id.clone(),
            relay_peer_id: scope.relay_peer_id.clone(),
            exit_node_id: parent.exit_node_id,
            exit_peer_id: parent.exit_peer_id,
            exit_boot_id: parent.exit_boot_id,
            hold_id: parent.hold_id,
            capability_id: parent.capability_id,
            reservation_id: parent.reservation_id,
            route_context_id: parent.route_context_id,
            client_session_id: parent.client_session_id,
            control_relay_node_id: parent.control_relay_node_id,
            control_relay_peer_id: parent.control_relay_peer_id,
            policy_hash: parent.policy_hash,
            transport: Transport::TcpMptcp as i32,
            address_family: scope.address_family,
            created_at_ms: NOW,
            expires_at_ms: NOW + 10_000,
            nonce: nonce.to_vec(),
        };
        let permit_bytes = sign_control_message(
            &permit,
            fixture.exit_key(),
            NOW,
            NOW + 10_000,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let wrong_nonce = DatapathRelayRequest::new(
            vec![55; 16],
            scope.relay_node_id.clone(),
            scope.relay_peer_id.clone(),
            NOW + 10_000,
            DatapathRelayOperation::ExtensionProbe,
            signed.clone(),
            permit_bytes.clone(),
        )
        .unwrap();
        assert!(!extension_probe_scope_matches(&wrong_nonce, NOW + 1));
        assert!(extension_probe_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionProbe,
                signed.clone(),
                permit_bytes
            ),
            NOW + 1
        ));
        let mut wrong = permit;
        wrong.probe_id = vec![45; 16];
        let permit_bytes = sign_control_message(
            &wrong,
            fixture.exit_key(),
            NOW,
            NOW + 10_000,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        assert!(!extension_probe_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionProbe,
                signed.clone(),
                permit_bytes
            ),
            NOW + 1
        ));
        wrong.probe_id = scope.probe_id.clone();
        wrong.address_family = ProbeAddressFamily::Ipv6 as i32;
        let wrong_family = sign_control_message(
            &wrong,
            fixture.exit_key(),
            NOW,
            NOW + 10_000,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        assert!(!extension_probe_scope_matches(
            &wrapper(
                &scope,
                DatapathRelayOperation::ExtensionProbe,
                signed,
                wrong_family
            ),
            NOW + 1
        ));
    }
}
