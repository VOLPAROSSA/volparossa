//! Signed single-relay path, policy, replay, and tuple-pinning tests.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use volparossa_policy::{
    DestinationRule, ManifestSpec, PolicyMode, ProtocolPort, TransportProtocol, TrustStore,
    TrustedMaintainer, VerificationPolicy, VerifiedManifest, sign_manifest, verify_manifest,
};
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE,
    NativeRouteIdentity, ProtocolError, RelayAuthorization, RelayReservation,
    RelayReservationRequest, ReplayCache, SignedEnvelope, TimePolicy, Transport,
    UdpFlowAuthorization, WireguardEndpoint, decode_canonical, node_id_from_public_key,
    relay_reservation_request_sha256, sign_control_message,
};
use volparossa_udp::{
    UdpAuthorizationScope, UdpError, VerifiedSingleRelayPath, read_authorized_udp_flow,
    write_udp_authorization,
};

const NOW: u64 = 1_700_000_000_000;
const EXPIRY: u64 = NOW + 60_000;
const ALLOWED_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const PERMANENT_CLIENT_PEER_ID: [u8; 32] = [0xa5; 32];

struct V4GrantScope {
    client_session_signing_key: [u8; 32],
    client_session_id: Vec<u8>,
    client_session_public_key: Vec<u8>,
    capability_id: Vec<u8>,
    exit_boot_id: Vec<u8>,
    hold_id: Vec<u8>,
    finalize_id: Vec<u8>,
    control_relay_node_id: Vec<u8>,
    control_relay_peer_id: Vec<u8>,
    exit_peer_id: Vec<u8>,
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn node_id(key: &SigningKey) -> Vec<u8> {
    node_id_from_public_key(&key.verifying_key().to_bytes()).to_vec()
}

fn peer_id(key: &SigningKey) -> Vec<u8> {
    let mut peer_id = vec![0, 36, 8, 1, 18, 32];
    peer_id.extend_from_slice(&key.verifying_key().to_bytes());
    peer_id
}

fn v4_grant_scope(
    exit: &SigningKey,
    client_session: &SigningKey,
    control_relay: &SigningKey,
) -> V4GrantScope {
    V4GrantScope {
        client_session_signing_key: client_session.to_bytes(),
        client_session_id: node_id(client_session),
        client_session_public_key: client_session.verifying_key().to_bytes().to_vec(),
        capability_id: vec![4; 16],
        exit_boot_id: vec![5; 16],
        hold_id: vec![6; 16],
        finalize_id: vec![8; 16],
        control_relay_node_id: node_id(control_relay),
        control_relay_peer_id: peer_id(control_relay),
        exit_peer_id: peer_id(exit),
    }
}

fn signed_client_session_capability(exit: &SigningKey, scope: &V4GrantScope) -> Vec<u8> {
    let nonce = [4; 32];
    let capability = ClientSessionCapability {
        capability_id: scope.capability_id.clone(),
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        client_session_id: scope.client_session_id.clone(),
        client_session_public_key: scope.client_session_public_key.clone(),
        exit_node_id: node_id(exit),
        exit_boot_id: scope.exit_boot_id.clone(),
        control_relay_node_id: scope.control_relay_node_id.clone(),
        control_relay_peer_id: scope.control_relay_peer_id.clone(),
        policy_hash: vec![7; 32],
        allowed_transports: vec![Transport::UdpSinglePath as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths: 1,
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: nonce.to_vec(),
        exit_peer_id: scope.exit_peer_id.clone(),
        probe_permit_limit: 1,
    };
    sign_control_message(
        &capability,
        exit,
        capability.created_at_ms,
        capability.expires_at_ms,
        nonce,
        TimePolicy::default(),
    )
    .unwrap()
}

fn client_relay_request_sha256(
    exit: &SigningKey,
    scope: &V4GrantScope,
    signed_grant: &[u8],
) -> [u8; 32] {
    let nonce = [12; 32];
    let request = RelayReservationRequest {
        client_session_id: scope.client_session_id.clone(),
        exit_authorization: signed_grant.to_vec(),
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: nonce.to_vec(),
        client_wireguard_endpoint: Some(endpoint(30, 23_000)),
        client_session_capability: signed_client_session_capability(exit, scope),
        exit_reservation: signed_exit(exit, scope),
    };
    let client_session_key = SigningKey::from_bytes(&scope.client_session_signing_key);
    let signed_request = sign_control_message(
        &request,
        &client_session_key,
        request.created_at_ms,
        request.expires_at_ms,
        nonce,
        TimePolicy::default(),
    )
    .unwrap();
    relay_reservation_request_sha256(&signed_request).unwrap()
}

fn policy() -> VerifiedManifest {
    let maintainer = key(90);
    let trust = TrustStore::new(
        PolicyMode::Production,
        vec![TrustedMaintainer::production(maintainer.verifying_key())],
    )
    .unwrap();
    let mut specification = ManifestSpec::new(1, 1, NOW - 2_000, NOW - 1_000, NOW + 120_000)
        .unwrap()
        .with_required_signatures(1)
        .unwrap();
    specification
        .add_rule(
            DestinationRule::exact_ip(
                IpAddr::V4(ALLOWED_IP),
                [ProtocolPort::new(TransportProtocol::Udp, 12_345).unwrap()],
            )
            .unwrap(),
        )
        .unwrap();
    let encoded = sign_manifest(&specification, &trust, &[&maintainer]).unwrap();
    verify_manifest(
        &encoded,
        NOW,
        &trust,
        VerificationPolicy::new(1, 1, 300_000, 60_000).unwrap(),
    )
    .unwrap()
}

fn signed_exit(exit: &SigningKey, scope: &V4GrantScope) -> Vec<u8> {
    signed_exit_with(exit, scope, |_| {})
}

fn signed_exit_with<F>(exit: &SigningKey, scope: &V4GrantScope, mutate: F) -> Vec<u8>
where
    F: FnOnce(&mut ExitReservation),
{
    let mut message = ExitReservation {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        exit_node_id: node_id(exit),
        client_session_id: scope.client_session_id.clone(),
        allowed_transports: vec![Transport::UdpSinglePath as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths: 1,
        policy_hash: vec![7; 32],
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![3; 32],
        capability_id: scope.capability_id.clone(),
        client_session_public_key: scope.client_session_public_key.clone(),
        exit_boot_id: scope.exit_boot_id.clone(),
        hold_id: scope.hold_id.clone(),
        finalize_id: scope.finalize_id.clone(),
        control_relay_node_id: scope.control_relay_node_id.clone(),
        control_relay_peer_id: scope.control_relay_peer_id.clone(),
        exit_peer_id: scope.exit_peer_id.clone(),
        native_route_identity: Some(NativeRouteIdentity {
            auth_commitment: vec![11; 32],
            certificate_sha256: vec![12; 32],
            spki_sha256: vec![13; 32],
            tls_server_name: "exit.volparossa.test".to_owned(),
            masque_context_id: 1,
            client_native_instance_id: vec![14; 32],
            exit_native_instance_id: vec![15; 32],
        }),
    };
    mutate(&mut message);
    sign_control_message(
        &message,
        exit,
        message.created_at_ms,
        message.expires_at_ms,
        [3; 32],
        TimePolicy::default(),
    )
    .unwrap()
}

fn signed_relay(exit: &SigningKey, relay: &SigningKey, scope: &V4GrantScope) -> Vec<u8> {
    signed_relay_with(exit, relay, scope, |_| {})
}

fn signed_relay_with<F>(
    exit: &SigningKey,
    relay: &SigningKey,
    scope: &V4GrantScope,
    mutate: F,
) -> Vec<u8>
where
    F: FnOnce(&mut RelayAuthorization),
{
    let mut grant = RelayAuthorization {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        path_id: 1,
        relay_node_id: node_id(relay),
        exit_node_id: node_id(exit),
        client_session_id: scope.client_session_id.clone(),
        relay_peer_id: peer_id(relay),
        allowed_transports: vec![Transport::UdpSinglePath as i32],
        maximum_up_mbps: 25,
        maximum_down_mbps: 50,
        client_wireguard_public_key: vec![30; 32],
        exit_wireguard_endpoint: Some(endpoint(40, 20_000)),
        policy_hash: vec![7; 32],
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![10; 32],
        capability_id: scope.capability_id.clone(),
        client_session_public_key: scope.client_session_public_key.clone(),
        exit_boot_id: scope.exit_boot_id.clone(),
        hold_id: scope.hold_id.clone(),
        finalize_id: scope.finalize_id.clone(),
        control_relay_node_id: scope.control_relay_node_id.clone(),
        control_relay_peer_id: scope.control_relay_peer_id.clone(),
        exit_peer_id: scope.exit_peer_id.clone(),
    };
    mutate(&mut grant);
    let signed_grant = sign_control_message(
        &grant,
        exit,
        grant.created_at_ms,
        grant.expires_at_ms,
        [10; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let signed_client_relay_request_sha256 =
        client_relay_request_sha256(exit, scope, &signed_grant);
    let accepted = RelayReservation {
        reservation_id: grant.reservation_id,
        route_context_id: grant.route_context_id,
        path_id: grant.path_id,
        relay_node_id: grant.relay_node_id,
        exit_node_id: grant.exit_node_id,
        client_session_id: grant.client_session_id,
        relay_peer_id: grant.relay_peer_id,
        allowed_transports: grant.allowed_transports,
        maximum_up_mbps: grant.maximum_up_mbps,
        maximum_down_mbps: grant.maximum_down_mbps,
        client_wireguard_public_key: grant.client_wireguard_public_key,
        relay_client_wireguard_endpoint: Some(endpoint(50, 20_001)),
        relay_exit_wireguard_endpoint: Some(endpoint(60, 20_002)),
        exit_wireguard_endpoint: grant.exit_wireguard_endpoint,
        policy_hash: grant.policy_hash,
        created_at_ms: grant.created_at_ms,
        expires_at_ms: grant.expires_at_ms,
        nonce: vec![11; 32],
        exit_authorization: signed_grant,
        capability_id: grant.capability_id,
        client_session_public_key: grant.client_session_public_key,
        exit_boot_id: grant.exit_boot_id,
        hold_id: grant.hold_id,
        finalize_id: grant.finalize_id,
        control_relay_node_id: grant.control_relay_node_id,
        control_relay_peer_id: grant.control_relay_peer_id,
        exit_peer_id: grant.exit_peer_id,
        signed_client_relay_request_sha256: signed_client_relay_request_sha256.to_vec(),
    };
    sign_control_message(
        &accepted,
        relay,
        accepted.created_at_ms,
        accepted.expires_at_ms,
        [11; 32],
        TimePolicy::default(),
    )
    .unwrap()
}

fn endpoint(key: u8, port: u16) -> WireguardEndpoint {
    WireguardEndpoint {
        public_key: vec![key; 32],
        underlay_ip: vec![8, 8, 4, key],
        listen_port: u32::from(port),
    }
}

fn signed_flow(
    client: &SigningKey,
    route_context_id: &[u8],
    policy_hash: &[u8],
    destination: Ipv4Addr,
    nonce_byte: u8,
) -> Vec<u8> {
    let nonce = [nonce_byte; 32];
    let message = UdpFlowAuthorization {
        route_context_id: route_context_id.to_vec(),
        flow_id: vec![60; 16],
        client_ephemeral_id: node_id(client),
        hostname: String::new(),
        destination_ip: destination.octets().to_vec(),
        port: 12_345,
        policy_hash: policy_hash.to_vec(),
        idle_timeout_ms: 1_000,
        timestamp_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: nonce.to_vec(),
    };
    sign_control_message(&message, client, NOW, EXPIRY, nonce, TimePolicy::default()).unwrap()
}

#[tokio::test]
async fn signed_udp_flow_is_single_relay_policy_bound_and_immutable() {
    let control_relay = key(49);
    let exit = key(50);
    let relay = key(51);
    let client = key(52);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let signed_exit = signed_exit(&exit, &scope);
    let signed_relay = signed_relay(&exit, &relay, &scope);
    let mut replay_cache = ReplayCache::new(12).unwrap();
    let path = VerifiedSingleRelayPath::verify(
        &signed_exit,
        &signed_relay,
        NOW + 1,
        TimePolicy::default(),
        &mut replay_cache,
    )
    .unwrap();
    assert_eq!(path.path_id(), 1);
    assert_eq!(path.relay_node_id(), node_id(&relay).as_slice());

    let policy = policy();
    let signed_flow = signed_flow(
        &client,
        path.route_context_id(),
        policy.policy_hash(),
        ALLOWED_IP,
        70,
    );
    let scope = UdpAuthorizationScope::new(&path, &policy);
    let (mut writer, mut reader) = duplex(4_096);
    write_udp_authorization(&mut writer, &signed_flow, Duration::from_secs(1))
        .await
        .unwrap();
    let authorized = read_authorized_udp_flow(
        &mut reader,
        &scope,
        NOW + 2,
        TimePolicy::default(),
        &mut replay_cache,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(authorized.port(), 12_345);
    assert_eq!(authorized.idle_timeout(), Duration::from_secs(1));
    assert!(!format!("{authorized:?}").contains("93.184"));
    let pinned = authorized.resolve_and_pin(NOW + 3).await.unwrap();
    assert_eq!(
        pinned.destination(),
        SocketAddr::new(IpAddr::V4(ALLOWED_IP), 12_345)
    );
    assert!(!format!("{pinned:?}").contains("93.184"));

    assert!(matches!(
        scope.verify(
            &signed_flow,
            NOW + 4,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(UdpError::Protocol(ProtocolError::Replay))
    ));
}

#[test]
fn signed_destination_change_is_denied_by_exact_policy() {
    let control_relay = key(79);
    let exit = key(80);
    let relay = key(81);
    let client = key(82);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let mut replay_cache = ReplayCache::new(12).unwrap();
    let path = VerifiedSingleRelayPath::verify(
        &signed_exit(&exit, &scope),
        &signed_relay(&exit, &relay, &scope),
        NOW + 1,
        TimePolicy::default(),
        &mut replay_cache,
    )
    .unwrap();
    let policy = policy();
    let changed = signed_flow(
        &client,
        path.route_context_id(),
        policy.policy_hash(),
        Ipv4Addr::new(1, 1, 1, 1),
        83,
    );
    let scope = UdpAuthorizationScope::new(&path, &policy);
    let replay_entries = replay_cache.len();
    assert!(matches!(
        scope.verify(&changed, NOW + 2, TimePolicy::default(), &mut replay_cache,),
        Err(UdpError::Policy(volparossa_policy::PolicyError::Denied))
    ));
    assert_eq!(replay_cache.len(), replay_entries);

    let corrected = signed_flow(
        &client,
        path.route_context_id(),
        policy.policy_hash(),
        ALLOWED_IP,
        83,
    );
    let accepted = scope
        .verify(
            &corrected,
            NOW + 3,
            TimePolicy::default(),
            &mut replay_cache,
        )
        .expect("same sender and nonce remain usable after local policy rejection");
    assert_eq!(accepted.port(), 12_345);
}

#[test]
fn rejected_path_binding_does_not_consume_valid_reservations() {
    let control_relay = key(83);
    let exit = key(84);
    let relay = key(85);
    let client = key(86);
    let other_client = key(87);
    let client_id = node_id(&client);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let other_scope = v4_grant_scope(&exit, &other_client, &control_relay);
    let encoded_exit = signed_exit(&exit, &scope);
    let wrong_relay = signed_relay(&exit, &relay, &other_scope);
    let mut replay_cache = ReplayCache::new(12).unwrap();

    assert!(matches!(
        VerifiedSingleRelayPath::verify(
            &encoded_exit,
            &wrong_relay,
            NOW + 1,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(UdpError::InvalidBinding("client session identity"))
    ));
    assert!(replay_cache.is_empty());

    let valid_relay = signed_relay(&exit, &relay, &scope);
    let path = VerifiedSingleRelayPath::verify(
        &encoded_exit,
        &valid_relay,
        NOW + 2,
        TimePolicy::default(),
        &mut replay_cache,
    )
    .unwrap();
    assert_eq!(path.client_ephemeral_id(), client_id.as_slice());
}

#[derive(Clone, Copy)]
enum GrantSubstitution {
    ReservationId,
    RouteContext,
    SessionKey,
    PolicyHash,
    Transports,
    UploadCapacity,
    DownloadCapacity,
    CreatedAt,
    ExpiresAt,
    CapabilityId,
    ExitBootId,
    HoldId,
    FinalizeId,
    ControlRelayNode,
    ControlRelayPeer,
    ExitPeer,
}

impl GrantSubstitution {
    fn apply(self, grant: &mut RelayAuthorization) {
        match self {
            Self::ReservationId => {
                grant.reservation_id = vec![21; 16];
            }
            Self::RouteContext => {
                grant.route_context_id = vec![22; 16];
            }
            Self::SessionKey => {
                let alternate_session = key(200);
                grant.client_session_id = node_id(&alternate_session);
                grant.client_session_public_key =
                    alternate_session.verifying_key().to_bytes().to_vec();
            }
            Self::PolicyHash => {
                grant.policy_hash = vec![23; 32];
            }
            Self::Transports => {
                grant.allowed_transports =
                    vec![Transport::TcpMptcp as i32, Transport::UdpSinglePath as i32];
            }
            Self::UploadCapacity => {
                grant.maximum_up_mbps = 26;
            }
            Self::DownloadCapacity => {
                grant.maximum_down_mbps = 51;
            }
            Self::CreatedAt => {
                grant.created_at_ms = NOW + 1;
            }
            Self::ExpiresAt => {
                grant.expires_at_ms = EXPIRY - 1;
            }
            Self::CapabilityId => {
                grant.capability_id = vec![24; 16];
            }
            Self::ExitBootId => {
                grant.exit_boot_id = vec![25; 16];
            }
            Self::HoldId => {
                grant.hold_id = vec![26; 16];
            }
            Self::FinalizeId => {
                grant.finalize_id = vec![27; 16];
            }
            Self::ControlRelayNode => {
                grant.control_relay_node_id = vec![28; 32];
            }
            Self::ControlRelayPeer => {
                grant.control_relay_peer_id = peer_id(&key(201));
            }
            Self::ExitPeer => {
                grant.exit_peer_id = peer_id(&key(202));
            }
        }
    }
}

fn assert_scope_substitution_rejected(
    exit: &SigningKey,
    relay_key: &SigningKey,
    scope: &V4GrantScope,
    substitution: GrantSubstitution,
    expected: &str,
) {
    let signed_exit = signed_exit(exit, scope);
    let substituted = signed_relay_with(exit, relay_key, scope, |grant| {
        substitution.apply(grant);
    });
    let mut replay_cache = ReplayCache::new(12).unwrap();
    let result = VerifiedSingleRelayPath::verify(
        &signed_exit,
        &substituted,
        NOW + 2,
        TimePolicy::default(),
        &mut replay_cache,
    );
    assert!(
        matches!(result, Err(UdpError::InvalidBinding(field)) if field == expected),
        "substitution unexpectedly accepted: {expected}"
    );
    assert!(
        replay_cache.is_empty(),
        "rejected substitution consumed replay state"
    );
}

#[test]
fn path_rejects_every_substituted_final_scope_field() {
    let exit = key(100);
    let relay_key = key(101);
    let client = key(102);
    let control_relay = key(103);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    for (substitution, expected) in [
        (GrantSubstitution::ReservationId, "reservation id"),
        (GrantSubstitution::RouteContext, "route context"),
        (GrantSubstitution::SessionKey, "client session identity"),
        (GrantSubstitution::PolicyHash, "policy hash"),
        (GrantSubstitution::Transports, "allowed transports"),
        (
            GrantSubstitution::UploadCapacity,
            "reserved upload capacity",
        ),
        (
            GrantSubstitution::DownloadCapacity,
            "reserved download capacity",
        ),
        (GrantSubstitution::CreatedAt, "grant creation time"),
        (GrantSubstitution::ExpiresAt, "grant expiry"),
        (GrantSubstitution::CapabilityId, "capability id"),
        (GrantSubstitution::ExitBootId, "exit boot id"),
        (GrantSubstitution::HoldId, "hold id"),
        (GrantSubstitution::FinalizeId, "finalize id"),
        (
            GrantSubstitution::ControlRelayNode,
            "control relay identity",
        ),
        (
            GrantSubstitution::ControlRelayPeer,
            "control relay peer identity",
        ),
        (GrantSubstitution::ExitPeer, "exit peer identity"),
    ] {
        assert_scope_substitution_rejected(&exit, &relay_key, &scope, substitution, expected);
    }

    let foreign_exit = key(107);
    let foreign = signed_relay(&foreign_exit, &relay_key, &scope);
    let signed_exit = signed_exit(&exit, &scope);
    let mut replay_cache = ReplayCache::new(12).unwrap();
    assert!(matches!(
        VerifiedSingleRelayPath::verify(
            &signed_exit,
            &foreign,
            NOW + 2,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(UdpError::InvalidBinding("exit identity"))
    ));
    assert!(replay_cache.is_empty());
}

#[test]
fn path_requires_exact_single_path_exit_cardinality() {
    let exit = key(108);
    let relay_key = key(109);
    let client = key(110);
    let control_relay = key(111);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let multi_path_exit = signed_exit_with(&exit, &scope, |grant| {
        grant.maximum_paths = 2;
    });
    let signed_relay = signed_relay(&exit, &relay_key, &scope);
    let mut replay_cache = ReplayCache::new(12).unwrap();
    assert!(matches!(
        VerifiedSingleRelayPath::verify(
            &multi_path_exit,
            &signed_relay,
            NOW + 1,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(UdpError::InvalidBinding("exit exact path count"))
    ));
    assert!(replay_cache.is_empty());
}

#[test]
fn v4_route_grants_reject_retired_permanent_client_peer_id_tags() {
    let control_relay = key(89);
    let exit = key(90);
    let relay = key(91);
    let client = key(92);
    let scope = v4_grant_scope(&exit, &client, &control_relay);

    let exit_envelope: SignedEnvelope =
        decode_canonical(&signed_exit(&exit, &scope), MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut exit_payload = exit_envelope.payload;
    exit_payload.extend_from_slice(&[0x2a, 32]);
    exit_payload.extend_from_slice(&PERMANENT_CLIENT_PEER_ID);
    assert!(matches!(
        decode_canonical::<ExitReservation>(&exit_payload, MAX_CONTROL_PAYLOAD_SIZE),
        Err(ProtocolError::NonCanonical)
    ));

    let relay_envelope: SignedEnvelope = decode_canonical(
        &signed_relay(&exit, &relay, &scope),
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let relay_message: RelayReservation =
        decode_canonical(&relay_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let mut relay_payload = relay_envelope.payload;
    relay_payload.extend_from_slice(&[0x3a, 32]);
    relay_payload.extend_from_slice(&PERMANENT_CLIENT_PEER_ID);
    assert!(matches!(
        decode_canonical::<RelayReservation>(&relay_payload, MAX_CONTROL_PAYLOAD_SIZE),
        Err(ProtocolError::NonCanonical)
    ));

    let authorization_envelope: SignedEnvelope =
        decode_canonical(&relay_message.exit_authorization, MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut authorization_payload = authorization_envelope.payload;
    authorization_payload.extend_from_slice(&[0x3a, 32]);
    authorization_payload.extend_from_slice(&PERMANENT_CLIENT_PEER_ID);
    assert!(matches!(
        decode_canonical::<RelayAuthorization>(&authorization_payload, MAX_CONTROL_PAYLOAD_SIZE),
        Err(ProtocolError::NonCanonical)
    ));
}
