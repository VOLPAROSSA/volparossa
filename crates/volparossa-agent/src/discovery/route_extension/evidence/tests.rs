//! Signed authority and synthetic retained-observation regression, not live packet evidence.

use super::super::super::{
    NativeProbePathScope, PreselectionActorBinding, ProbeLegEvidence,
    native_exit_path_binding_matches, native_exit_ticket_matches_result,
};
use super::*;
use volparossa_protocol::{
    FinalizedRelayPath, ProbeAddressFamily, generate_nonce, node_id_from_public_key,
    sign_control_message,
};
use volparossa_test_support::SignedRouteFixture;

struct Fixture {
    route: SignedRouteFixture,
    request: RouteExtensionRequest,
    permit: RelayProbePermit,
    result: RelayProbeResult,
    tickets: Vec<RecentNativeExitEvidence>,
    now: u64,
}

fn actor(node_id: Vec<u8>, peer_id: Vec<u8>) -> PreselectionActorBinding {
    PreselectionActorBinding {
        node_id,
        peer_id,
        ..PreselectionActorBinding::default()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one explicit signed parent/permit and two retained native observation fixtures"
)]
fn fixture() -> Fixture {
    let issued = crate::unix_millis();
    let route =
        SignedRouteFixture::new_with_path_ids(&[1, 2, 3], 4, 4, &[Transport::TcpMptcp], issued)
            .unwrap();
    let sample = SignedRouteFixture::new(2, &[Transport::TcpMptcp], issued).unwrap();
    let scope = RouteExtensionScope {
        extension_id: generate_nonce()[..16].to_vec(),
        signed_exit_reservation: route.exit_reservation().to_vec(),
        finalized_bundle_hash: route.finalized_bundle_hash().to_vec(),
        path_id: 4,
        relay_node_id: sample.relay_node_id(0).unwrap().to_vec(),
        relay_peer_id: sample.relay_peer_id(0).unwrap().to_vec(),
        probe_id: generate_nonce()[..16].to_vec(),
        address_family: ProbeAddressFamily::Ipv4 as i32,
    };
    let parent = scope.parent().unwrap();
    let permit = RelayProbePermit {
        probe_id: scope.probe_id.clone(),
        hold_id: parent.hold_id.clone(),
        capability_id: parent.capability_id.clone(),
        reservation_id: parent.reservation_id.clone(),
        route_context_id: parent.route_context_id.clone(),
        client_session_id: parent.client_session_id.clone(),
        exit_node_id: parent.exit_node_id.clone(),
        exit_boot_id: parent.exit_boot_id.clone(),
        control_relay_node_id: parent.control_relay_node_id.clone(),
        control_relay_peer_id: parent.control_relay_peer_id.clone(),
        relay_node_id: scope.relay_node_id.clone(),
        relay_peer_id: scope.relay_peer_id.clone(),
        path_id: 4,
        created_at_ms: issued,
        expires_at_ms: issued + 20_000,
        nonce: generate_nonce().to_vec(),
        exit_peer_id: parent.exit_peer_id.clone(),
        policy_hash: parent.policy_hash.clone(),
        transport: Transport::TcpMptcp as i32,
        address_family: scope.address_family,
    };
    let encoded = sign_control_message(
        &permit,
        route.exit_key(),
        issued,
        permit.expires_at_ms,
        permit.nonce.as_slice().try_into().unwrap(),
        TimePolicy::default(),
    )
    .unwrap();
    let leg = ProbeLegEvidence {
        up_capacity_mbps: 32,
        down_capacity_mbps: 32,
        rtt_micros: 1000,
        transmitted_bytes: 4096,
        received_bytes: 4096,
        window_started_at_ms: issued + 10,
        window_ended_at_ms: issued + 20,
        measured_at_ms: issued + 20,
    };
    let result = RelayProbeResult {
        probe_id: permit.probe_id.clone(),
        relay_probe_permit: encoded.clone(),
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
        client_relay: Some(leg.clone()),
        relay_exit: Some(leg),
        measured_at_ms: issued + 20,
        expires_at_ms: permit.expires_at_ms,
        nonce: generate_nonce().to_vec(),
    };
    let signed_result = sign_control_message(
        &result,
        sample.relay_key(0).unwrap(),
        result.measured_at_ms,
        result.expires_at_ms,
        result.nonce.as_slice().try_into().unwrap(),
        TimePolicy::default(),
    )
    .unwrap();
    let native_scope = NativeProbePathScope {
        attempt_id: generate_nonce()[..16].to_vec(),
        probe_id: generate_nonce()[..16].to_vec(),
        candidate_set_hash: generate_nonce().to_vec(),
        candidate_ordinal: 1,
        data_relay: Some(actor(
            scope.relay_node_id.clone(),
            scope.relay_peer_id.clone(),
        )),
        control: Some(actor(
            parent.control_relay_node_id,
            parent.control_relay_peer_id,
        )),
        exit: Some(actor(parent.exit_node_id, parent.exit_peer_id)),
        client_session_id: sample.client_session_id().to_vec(),
        client_session_public_key: sample.client_key().verifying_key().to_bytes().to_vec(),
        transport: permit.transport,
        address_family: permit.address_family,
        policy_hash: permit.policy_hash.clone(),
        policy_version: 1,
        policy_expires_at_ms: parent.expires_at_ms,
        challenge_hash: generate_nonce().to_vec(),
        attempt_expires_at_ms: issued + 25_000,
        required_path_count: 2,
        reserved_up_mbps: 32,
        reserved_down_mbps: 32,
    };
    let first = RecentNativeExitEvidence {
        evidence_id: generate_nonce(),
        scope: native_scope,
        authenticated_data_relay_node_id: sample.relay_node_id(0).unwrap(),
        authenticated_data_relay_peer_id: sample.relay_peer_id(0).unwrap().to_vec(),
        measured_at_ms: issued + 21,
        expires_at_ms: issued + 25_000,
    };
    let mut second = first.clone();
    second.evidence_id = generate_nonce();
    second.scope.candidate_ordinal = 2;
    second.scope.probe_id = generate_nonce()[..16].to_vec();
    second.scope.challenge_hash = generate_nonce().to_vec();
    let session_public_key = ed25519_dalek::SigningKey::from_bytes(&generate_nonce())
        .verifying_key()
        .to_bytes();
    second.scope.client_session_id = node_id_from_public_key(&session_public_key).to_vec();
    second.scope.client_session_public_key = session_public_key.to_vec();
    second.scope.data_relay = Some(actor(
        sample.relay_node_id(1).unwrap().to_vec(),
        sample.relay_peer_id(1).unwrap().to_vec(),
    ));
    second.authenticated_data_relay_node_id = sample.relay_node_id(1).unwrap();
    second.authenticated_data_relay_peer_id = sample.relay_peer_id(1).unwrap().to_vec();
    let request = RouteExtensionRequest {
        scope: Some(scope),
        phase: RouteExtensionPhase::Authorize as i32,
        path: Some(FinalizedRelayPath {
            path_id: 4,
            relay_node_id: permit.relay_node_id.clone(),
            relay_peer_id: permit.relay_peer_id.clone(),
            client_wireguard_public_key: generate_nonce().to_vec(),
            relay_probe_permit: encoded,
            relay_probe_result: signed_result,
        }),
        signed_confirmation: Vec::new(),
    };
    Fixture {
        route,
        request,
        permit,
        result,
        tickets: vec![first, second],
        now: issued + 30,
    }
}

fn accepted(fixture: &Fixture, binding: Option<&ExtensionEvidenceBinding>) -> bool {
    native_exit_ticket_matches_result(
        &fixture.tickets[0],
        &fixture.result,
        &fixture.permit,
        fixture.now,
    ) && native_exit_path_binding_matches(
        &fixture.tickets[0],
        &fixture.result,
        &fixture.permit,
        fixture.now,
        binding,
        &fixture.tickets,
    )
}

#[test]
fn extension_evidence_maps_fresh_batch_ordinal_one_to_path_four_only_with_exact_authority() {
    let mut fixture = fixture();
    assert_ne!(
        fixture.tickets[0].scope.client_session_id, fixture.tickets[1].scope.client_session_id,
        "the actual sampler mints a distinct ephemeral identity for each path"
    );
    assert_ne!(
        fixture.tickets[0].scope.client_session_public_key,
        fixture.tickets[1].scope.client_session_public_key
    );
    let binding = ExtensionEvidenceBinding::new(&fixture.request, fixture.now).unwrap();
    assert!(accepted(&fixture, Some(&binding)));
    assert!(
        !accepted(&fixture, None),
        "initial admission still requires the original path ordinal"
    );
    fixture.permit.path_id = 1;
    assert!(accepted(&fixture, None));
    assert!(
        !accepted(&fixture, Some(&binding)),
        "extension cannot select another retained path"
    );
}

#[test]
fn extension_evidence_rejects_parent_permit_path_and_fresh_batch_substitution() {
    let fixture = fixture();
    let binding = ExtensionEvidenceBinding::new(&fixture.request, fixture.now).unwrap();
    let mut wrong = fixture.request.clone();
    wrong.path.as_mut().unwrap().relay_probe_permit[0] ^= 1;
    assert!(ExtensionEvidenceBinding::new(&wrong, fixture.now).is_none());
    let mut wrong = fixture.request.clone();
    wrong.scope.as_mut().unwrap().signed_exit_reservation =
        SignedRouteFixture::new(3, &[Transport::TcpMptcp], fixture.now)
            .unwrap()
            .exit_reservation()
            .to_vec();
    assert!(ExtensionEvidenceBinding::new(&wrong, fixture.now).is_none());
    let mut wrong = fixture.request.clone();
    wrong.scope.as_mut().unwrap().path_id = 5;
    wrong.path.as_mut().unwrap().path_id = 5;
    assert!(ExtensionEvidenceBinding::new(&wrong, fixture.now).is_none());
    let mut another_permit = fixture.permit.clone();
    another_permit.nonce = generate_nonce().to_vec();
    let mut changed_result = fixture.result.clone();
    changed_result.relay_probe_permit = sign_control_message(
        &another_permit,
        fixture.route.exit_key(),
        another_permit.created_at_ms,
        another_permit.expires_at_ms,
        another_permit.nonce.as_slice().try_into().unwrap(),
        TimePolicy::default(),
    )
    .unwrap();
    assert!(!binding.matches(
        &fixture.tickets[0],
        &fixture.tickets,
        &changed_result,
        &another_permit,
        fixture.now
    ));
    for mutate in [
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets.pop();
        },
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets[1].scope.candidate_set_hash[0] ^= 1;
        },
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets[1].scope.candidate_ordinal = 1;
        },
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets[1].scope.attempt_id[0] ^= 1;
        },
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets[1].scope.policy_version += 1;
        },
        |tickets: &mut Vec<RecentNativeExitEvidence>| {
            tickets[0].measured_at_ms = 0;
        },
    ] {
        let mut tickets = fixture.tickets.clone();
        mutate(&mut tickets);
        assert!(!binding.matches(
            &tickets[0],
            &tickets,
            &fixture.result,
            &fixture.permit,
            fixture.now
        ));
    }
}

#[test]
fn extension_evidence_keeps_all_original_actor_policy_and_transport_checks() {
    for mutate in [
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.data_relay.as_mut().unwrap().node_id[0] ^= 1;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.control.as_mut().unwrap().node_id[0] ^= 1;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.exit.as_mut().unwrap().node_id[0] ^= 1;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.policy_hash[0] ^= 1;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.transport = Transport::UdpSinglePath as i32;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.scope.address_family = ProbeAddressFamily::Ipv6 as i32;
        },
        |ticket: &mut RecentNativeExitEvidence| {
            ticket.authenticated_data_relay_node_id[0] ^= 1;
        },
    ] {
        let mut fixture = fixture();
        let binding = ExtensionEvidenceBinding::new(&fixture.request, fixture.now).unwrap();
        mutate(&mut fixture.tickets[0]);
        assert!(!accepted(&fixture, Some(&binding)));
    }
    let mut fixture = fixture();
    let binding = ExtensionEvidenceBinding::new(&fixture.request, fixture.now).unwrap();
    fixture
        .result
        .client_relay
        .as_mut()
        .unwrap()
        .window_started_at_ms = fixture.permit.created_at_ms - 1;
    assert!(
        !accepted(&fixture, Some(&binding)),
        "native measurements must start after the extension permit"
    );
}
