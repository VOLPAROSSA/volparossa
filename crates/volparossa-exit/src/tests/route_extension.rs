use super::*;
use volparossa_protocol::{
    ControlPayload, FinalizedRelayPath, RouteExtensionPhase, RouteExtensionRequest,
    RouteExtensionScope,
};
use volparossa_tcp_proxy::VerifiedMptcpRoute;

fn scope(route: &AdmittedRoute, relay: &SigningKey, path_id: u32) -> RouteExtensionScope {
    RouteExtensionScope {
        extension_id: vec![91; 16],
        signed_exit_reservation: route.bundle.signed_exit_reservation().to_vec(),
        finalized_bundle_hash: route.bundle.finalized_bundle_hash().to_vec(),
        path_id,
        relay_node_id: node_id(relay).to_vec(),
        relay_peer_id: peer_id(relay),
        probe_id: vec![92; 16],
        address_family: ProbeAddressFamily::Ipv4 as i32,
    }
}

fn invoke(
    service: &mut ExitService,
    route: &AdmittedRoute,
    encoded: &[u8],
    evidence: &ExactProbeVerifier,
) -> Result<super::super::AcceptedRouteExtension, ExitError> {
    invoke_at(service, route, encoded, evidence, NOW_MS)
}

fn invoke_at(
    service: &mut ExitService,
    route: &AdmittedRoute,
    encoded: &[u8],
    evidence: &ExactProbeVerifier,
    now_ms: u64,
) -> Result<super::super::AcceptedRouteExtension, ExitError> {
    let parent = scope(route, &ephemeral_signing_key(), 3).parent().unwrap();
    service.extend_route_with(
        encoded,
        &parent.control_relay_node_id.as_slice().try_into().unwrap(),
        &parent.control_relay_peer_id,
        now_ms,
        route.exit_key.verifying_key().to_bytes(),
        evidence,
        |id| exit_endpoint(route.route_context_id, id),
        |bytes| Some(route.exit_key.sign(bytes).to_bytes()),
    )
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one authenticated fresh retry transaction preserves terminal cleanup and its original owner"
)]
fn route_extension_fresh_abort_retry_confirms_cleanup_without_reopening_authority() {
    let (mut service, route) = admit_route_with_probe_selection(
        4,
        4,
        &[1, 2],
        &[Transport::TcpMptcp],
        Vec::new(),
        MetricsRegistry::new(),
    );
    let evidence = ExactProbeVerifier {
        expected: Vec::new(),
    };
    let mut request = RouteExtensionRequest {
        scope: Some(scope(&route, &ephemeral_signing_key(), 3)),
        phase: RouteExtensionPhase::Probe as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let probe = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 5_000)
        .unwrap();
    invoke(&mut service, &route, &probe, &evidence).unwrap();
    request.phase = RouteExtensionPhase::Abort as i32;
    let first_request = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS + 1, NOW_MS + 3_000)
        .unwrap();
    let first = invoke_at(&mut service, &route, &first_request, &evidence, NOW_MS + 1).unwrap();
    let before = service.available(NOW_MS + 1).unwrap();
    let retry = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS + 4_000, NOW_MS + 8_000)
        .unwrap();
    let parent = request.scope.as_ref().unwrap().parent().unwrap();
    let response = service
        .extend_route_with(
            &retry,
            &parent.control_relay_node_id.as_slice().try_into().unwrap(),
            &parent.control_relay_peer_id,
            NOW_MS + 4_000,
            route.exit_key.verifying_key().to_bytes(),
            &evidence,
            |_| panic!("already aborted extension cannot allocate another helper lease"),
            |bytes| Some(route.exit_key.sign(bytes).to_bytes()),
        )
        .unwrap();
    let verified = verify_control_message::<volparossa_protocol::RouteExtension>(
        response.encoded(),
        NOW_MS + 4_000,
        TimePolicy::default(),
        &mut ReplayCache::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(verified.sender_id(), &node_id(&route.exit_key));
    assert_eq!(verified.expires_at_ms(), NOW_MS + 8_000);
    assert_eq!(response.message(), first.message());
    assert_ne!(response.encoded(), first.encoded());
    assert!(response.confirmed_path().is_none());
    assert!(response.message().signed_probe_permit.is_empty());
    assert!(response.message().signed_relay_authorization.is_empty());
    assert_eq!(service.available(NOW_MS + 4_000).unwrap(), before);
    let state = service.endpoint_states.values().next().unwrap();
    assert_eq!(state.paths.len(), 2);
    assert!(!state.permits.contains_key(&3));
    assert_eq!(state.extensions.len(), 1);
    let exact = invoke_at(&mut service, &route, &retry, &evidence, NOW_MS + 4_001).unwrap();
    assert_eq!(exact.encoded(), response.encoded());
    assert!(
        invoke_at(
            &mut service,
            &route,
            &first_request,
            &evidence,
            NOW_MS + 4_001
        )
        .is_err()
    );
    assert!(invoke_at(&mut service, &route, &probe, &evidence, NOW_MS + 4_001).is_err());
    let mut forged: SignedEnvelope =
        decode_canonical(&retry, volparossa_protocol::MAX_ROUTE_EXTENSION_BYTES).unwrap();
    forged.nonce[0] ^= 1;
    let forged = volparossa_protocol::encode_canonical(
        &forged,
        volparossa_protocol::MAX_ROUTE_EXTENSION_BYTES,
    )
    .unwrap();
    assert!(invoke_at(&mut service, &route, &forged, &evidence, NOW_MS + 4_001).is_err());
    request.phase = RouteExtensionPhase::Authorize as i32;
    let scope = request.scope.as_ref().unwrap();
    request.path = Some(FinalizedRelayPath {
        path_id: scope.path_id,
        relay_node_id: scope.relay_node_id.clone(),
        relay_peer_id: scope.relay_peer_id.clone(),
        client_wireguard_public_key: vec![1; 32],
        relay_probe_permit: vec![1],
        relay_probe_result: vec![1],
    });
    let reopen = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS + 4_001, NOW_MS + 5_000)
        .unwrap();
    assert!(invoke_at(&mut service, &route, &reopen, &evidence, NOW_MS + 4_001).is_err());
    assert_eq!(
        service.endpoint_states.values().next().unwrap().paths.len(),
        2
    );
}

#[test]
fn route_extension_retains_live_parent_past_initial_setup_and_aborts_own_expired_attempt() {
    let (mut service, route) = admit_route_with_probe_selection(
        4,
        4,
        &[1, 2],
        &[Transport::TcpMptcp],
        Vec::new(),
        MetricsRegistry::new(),
    );
    assert!(
        service
            .mark_route_established(route.accepted.reservation_id(), NOW_MS)
            .is_err(),
        "unbound signed admission is not native adoption"
    );
    let active = service
        .bind_tcp_route(
            &route.accepted,
            &route
                .signed_relays
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            NOW_MS,
        )
        .unwrap();
    let _egress = service.detach_tcp_egress_route(active, NOW_MS).unwrap();
    service
        .mark_route_established(route.accepted.reservation_id(), NOW_MS)
        .unwrap();
    assert_eq!(service.purge_expired(NOW_MS + 25_000), 0);
    let relay = ephemeral_signing_key();
    let mut request = RouteExtensionRequest {
        scope: Some(scope(&route, &relay, 3)),
        phase: RouteExtensionPhase::Probe as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let evidence = ExactProbeVerifier {
        expected: Vec::new(),
    };
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS + 25_000, NOW_MS + 30_000)
        .unwrap();
    let permit = invoke_at(&mut service, &route, &signed, &evidence, NOW_MS + 25_000).unwrap();
    assert_eq!(permit.message().hard_expires_at_ms, route.expires_at_ms);
    assert!(
        invoke_at(&mut service, &route, &signed, &evidence, NOW_MS + 30_000).is_err(),
        "expired exact retry is not renewed"
    );
    request.phase = RouteExtensionPhase::Abort as i32;
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS + 31_000, NOW_MS + 32_000)
        .unwrap();
    let abort = invoke_at(&mut service, &route, &signed, &evidence, NOW_MS + 31_000).unwrap();
    assert_eq!(abort.message().selected_path_ids, [1, 2]);
    assert_eq!(abort.message().hard_expires_at_ms, route.expires_at_ms);
    assert_eq!(
        service.endpoint_states.values().next().unwrap().paths.len(),
        2
    );
    assert_eq!(
        service.available(NOW_MS + 31_000).unwrap().bandwidth,
        Bandwidth::new(400, 400).unwrap()
    );
    assert_eq!(service.purge_expired(route.expires_at_ms), 1);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real-signature fixture proves additive capacity without replacing original authority"
)]
async fn route_extension_adds_real_signed_capacity_without_reissuing_originals() {
    let rule = DestinationRule::exact_domain(
        "allowed.example",
        [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
    )
    .unwrap();
    let (mut service, mut route) = admit_route_with_probe_selection(
        4,
        4,
        &[1, 2],
        &[Transport::TcpMptcp],
        vec![rule],
        MetricsRegistry::new(),
    );
    let original = route.bundle.clone();
    let old_relays = route.signed_relays.clone();
    let before_capacity = service.available(NOW_MS).unwrap();
    let active = service
        .bind_tcp_route(
            &route.accepted,
            &old_relays.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            NOW_MS,
        )
        .unwrap();
    let egress = service.detach_tcp_egress_route(active, NOW_MS).unwrap();
    let relay_key = ephemeral_signing_key();
    let mut request = RouteExtensionRequest {
        scope: Some(scope(&route, &relay_key, 3)),
        phase: RouteExtensionPhase::Probe as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let evidence = ExactProbeVerifier {
        expected: Vec::new(),
    };
    let response = invoke(&mut service, &route, &signed, &evidence).unwrap();
    let retry = invoke(&mut service, &route, &signed, &evidence).unwrap();
    assert_eq!(response.encoded(), retry.encoded());
    let verified = route
        .coordinator
        .verify_route_extension_response(&original, &request, response.encoded(), NOW_MS)
        .unwrap();
    assert!(
        route
            .coordinator
            .verify_route_extension_response(&original, &request, response.encoded(), NOW_MS)
            .is_err(),
        "client replay is not a new authorization"
    );
    let permit = verify_control_message::<RelayProbePermit>(
        &verified.message().signed_probe_permit,
        NOW_MS,
        TimePolicy::default(),
        &mut ReplayCache::new(1).unwrap(),
    )
    .unwrap()
    .into_message();
    let nonce = generate_nonce();
    let result = RelayProbeResult {
        probe_id: permit.probe_id.clone(),
        relay_probe_permit: verified.message().signed_probe_permit.clone(),
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
        client_relay: Some(probe_leg(2_000)),
        relay_exit: Some(probe_leg(3_000)),
        measured_at_ms: NOW_MS,
        expires_at_ms: permit.expires_at_ms,
        nonce: nonce.to_vec(),
    };
    let result_bytes = sign_control_message(
        &result,
        &relay_key,
        NOW_MS,
        result.expires_at_ms,
        nonce,
        TimePolicy::default(),
    )
    .unwrap();
    let evidence = ExactProbeVerifier {
        expected: vec![(
            verified.message().signed_probe_permit.clone(),
            result_bytes.clone(),
        )],
    };
    let client = client_endpoint(route.route_context_id, 3).unwrap();
    request.phase = RouteExtensionPhase::Authorize as i32;
    request.path = Some(FinalizedRelayPath {
        path_id: 3,
        relay_node_id: node_id(&relay_key).to_vec(),
        relay_peer_id: peer_id(&relay_key),
        client_wireguard_public_key: client.public_endpoint().public_key().as_bytes().to_vec(),
        relay_probe_permit: verified.message().signed_probe_permit.clone(),
        relay_probe_result: result_bytes,
    });
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    assert!(
        invoke(
            &mut service,
            &route,
            &signed,
            &ExactProbeVerifier {
                expected: Vec::new()
            }
        )
        .is_err(),
        "cryptographic transcript is not substitute for real evidence provider"
    );
    let response = invoke(&mut service, &route, &signed, &evidence).unwrap();
    let authorization = route
        .coordinator
        .verify_route_extension_response(&original, &request, response.encoded(), NOW_MS)
        .unwrap();
    let signed_request = route
        .coordinator
        .sign_extension_relay_request(&original, &authorization, client, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let mut relay = RelayService::new(
        RelayServiceConfig::enabled(
            node_id(&relay_key),
            Bandwidth::new(500, 500).unwrap(),
            4,
            900,
            30,
            128,
        ),
        None,
    )
    .unwrap();
    let grant = relay
        .accept_request_with(
            &signed_request,
            NOW_MS,
            relay_key.verifying_key().to_bytes(),
            |id| relay_endpoint(route.route_context_id, id),
            |bytes| Some(relay_key.sign(bytes).to_bytes()),
        )
        .unwrap();
    let verified_grant = route
        .coordinator
        .verify_extension_relay_response(
            &original,
            &authorization,
            grant.encoded(),
            &peer_id(&relay_key),
            NOW_MS,
        )
        .unwrap();
    request.phase = RouteExtensionPhase::Commit as i32;
    request.path = None;
    request.signed_confirmation = route
        .coordinator
        .sign_exit_confirmation(&verified_grant, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let response = invoke(&mut service, &route, &signed, &evidence).unwrap();
    let committed = route
        .coordinator
        .verify_route_extension_response(&original, &request, response.encoded(), NOW_MS)
        .unwrap();
    assert_eq!(committed.message().selected_path_ids, [1, 2, 3]);
    assert_eq!(committed.message().hard_expires_at_ms, route.expires_at_ms);
    let abort_committed = RouteExtensionRequest {
        scope: request.scope.clone(),
        phase: RouteExtensionPhase::Abort as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let abort_committed = route
        .coordinator
        .sign_route_extension_request(&abort_committed, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    assert!(
        invoke(&mut service, &route, &abort_committed, &evidence).is_err(),
        "terminal Commit cannot be disguised as an idempotent Abort"
    );
    assert_eq!(route.bundle, original);
    assert_eq!(route.signed_relays, old_relays);
    assert_eq!(
        service.available(NOW_MS).unwrap(),
        before_capacity,
        "no second Exit allocation"
    );
    let all = old_relays
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(grant.encoded()))
        .collect::<Vec<_>>();
    assert!(
        VerifiedMptcpRoute::verify(
            original.signed_exit_reservation(),
            &all,
            NOW_MS,
            TimePolicy::default(),
            &mut ReplayCache::new(64).unwrap()
        )
        .is_err()
    );
    let effective = VerifiedMptcpRoute::verify_with_extensions(
        original.signed_exit_reservation(),
        &all,
        &[committed.encoded()],
        original.signed_capability(),
        NOW_MS,
        TimePolicy::default(),
        &mut ReplayCache::new(64).unwrap(),
    )
    .unwrap();
    assert_eq!(effective.path_count(), 3);
    assert_eq!(effective.expires_at_ms(), route.expires_at_ms);
    egress
        .install_extension(
            committed.encoded(),
            grant.encoded(),
            original.signed_capability(),
            NOW_MS,
        )
        .await
        .unwrap();
    egress
        .install_extension(
            committed.encoded(),
            grant.encoded(),
            original.signed_capability(),
            NOW_MS,
        )
        .await
        .unwrap();
    assert_eq!(egress.authority.read().await.route.path_count(), 3);
    let open = route.sign_open_tcp(service.policy_hash(), "allowed.example", 443);
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    volparossa_tcp_proxy::write_open_tcp(&mut writer, &open, Duration::from_secs(1))
        .await
        .unwrap();
    let _flow = egress
        .read_authorized_open_tcp(&mut reader, NOW_MS, Duration::from_secs(1))
        .await
        .unwrap();
}

#[test]
fn route_extension_rejects_overcap_changed_parent_expiry_and_reused_attempt() {
    let relay_key = ephemeral_signing_key();
    let (mut full, full_route) = admit_route_with_probe_selection(
        3,
        2,
        &[1, 2],
        &[Transport::TcpMptcp],
        Vec::new(),
        MetricsRegistry::new(),
    );
    let request = RouteExtensionRequest {
        scope: Some(scope(&full_route, &relay_key, 3)),
        phase: RouteExtensionPhase::Probe as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let signed = full_route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let evidence = ExactProbeVerifier {
        expected: Vec::new(),
    };
    assert!(invoke(&mut full, &full_route, &signed, &evidence).is_err());
    let (mut service, route) = admit_route_with_probe_selection(
        4,
        4,
        &[1, 2],
        &[Transport::TcpMptcp],
        Vec::new(),
        MetricsRegistry::new(),
    );
    let mut request = RouteExtensionRequest {
        scope: Some(scope(&route, &relay_key, 3)),
        ..request
    };
    assert!(
        route
            .coordinator
            .sign_route_extension_request(&request, NOW_MS + 110_000, route.expires_at_ms + 1)
            .is_err()
    );
    let correct = request.scope.clone();
    request.scope.as_mut().unwrap().finalized_bundle_hash[0] ^= 1;
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    assert!(invoke(&mut service, &route, &signed, &evidence).is_err());
    request.scope = correct;
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    invoke(&mut service, &route, &signed, &evidence).unwrap();
    request.phase = RouteExtensionPhase::Abort as i32;
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    let aborted = invoke(&mut service, &route, &signed, &evidence).unwrap();
    assert_eq!(aborted.message().selected_path_ids, [1, 2]);
    assert_eq!(
        service.endpoint_states.values().next().unwrap().paths.len(),
        2
    );
    request.phase = RouteExtensionPhase::Probe as i32;
    request.scope.as_mut().unwrap().extension_id[0] ^= 1;
    let signed = route
        .coordinator
        .sign_route_extension_request(&request, NOW_MS, NOW_MS + 15_000)
        .unwrap();
    assert!(
        invoke(&mut service, &route, &signed, &evidence).is_err(),
        "aborted path cannot silently reuse the old grant identity"
    );
    request.scope.as_mut().unwrap().path_id = 9;
    assert!(request.validate().is_err());
}
