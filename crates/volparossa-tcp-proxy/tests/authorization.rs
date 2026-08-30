//! Signed route, whitelist, replay, and opening-frame tests.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use volparossa_policy::{
    DestinationRule, ManifestSpec, PolicyMode, ProtocolPort, TransportProtocol, TrustStore,
    TrustedMaintainer, VerificationPolicy, VerifiedManifest, sign_manifest, verify_manifest,
};
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE,
    NativeRouteIdentity, OpenTcp, ProtocolError, RelayAuthorization, RelayReservation,
    RelayReservationRequest, ReplayCache, SignedEnvelope, TimePolicy, Transport, WireguardEndpoint,
    decode_canonical, node_id_from_public_key, relay_reservation_request_sha256,
    sign_control_message,
};
use volparossa_tcp_proxy::{
    TcpAuthorizationScope, TcpProxyError, VerifiedMptcpRoute, read_authorized_open_tcp,
    write_open_tcp,
};

const NOW: u64 = 1_700_000_000_000;
const EXPIRY: u64 = NOW + 60_000;
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
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths: 8,
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: nonce.to_vec(),
        exit_peer_id: scope.exit_peer_id.clone(),
        probe_permit_limit: 8,
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
    path_byte: u8,
    nonce_discriminator: u8,
) -> [u8; 32] {
    let nonce = [70 + nonce_discriminator; 32];
    let request = RelayReservationRequest {
        client_session_id: scope.client_session_id.clone(),
        exit_authorization: signed_grant.to_vec(),
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: nonce.to_vec(),
        client_wireguard_endpoint: Some(endpoint(30 + path_byte, 23_000 + u16::from(path_byte))),
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
    policy_for_domain("www.example.com")
}

fn policy_for_domain(domain: &str) -> VerifiedManifest {
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
            DestinationRule::exact_domain(
                domain,
                [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
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
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths: 2,
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

fn signed_relay(
    exit: &SigningKey,
    relay: &SigningKey,
    scope: &V4GrantScope,
    path_id: u32,
) -> Vec<u8> {
    let nonce_discriminator = u8::try_from(path_id).unwrap();
    signed_relay_with(exit, relay, scope, path_id, nonce_discriminator, |_| {})
}

fn signed_relay_with<F>(
    exit: &SigningKey,
    relay: &SigningKey,
    scope: &V4GrantScope,
    path_id: u32,
    nonce_discriminator: u8,
    mutate: F,
) -> Vec<u8>
where
    F: FnOnce(&mut RelayAuthorization),
{
    let path_byte = u8::try_from(path_id).unwrap();
    let grant_nonce = [10 + nonce_discriminator; 32];
    let relay_nonce = [20 + nonce_discriminator; 32];
    let mut grant = RelayAuthorization {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        path_id,
        relay_node_id: node_id(relay),
        exit_node_id: node_id(exit),
        client_session_id: scope.client_session_id.clone(),
        relay_peer_id: peer_id(relay),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        maximum_up_mbps: 25,
        maximum_down_mbps: 50,
        client_wireguard_public_key: vec![30 + path_byte; 32],
        exit_wireguard_endpoint: Some(endpoint(40 + path_byte, 20_000 + u16::from(path_byte))),
        policy_hash: vec![7; 32],
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: grant_nonce.to_vec(),
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
        grant_nonce,
        TimePolicy::default(),
    )
    .unwrap();
    let signed_client_relay_request_sha256 =
        client_relay_request_sha256(exit, scope, &signed_grant, path_byte, nonce_discriminator);
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
        relay_client_wireguard_endpoint: Some(endpoint(
            50 + path_byte,
            21_000 + u16::from(path_byte),
        )),
        relay_exit_wireguard_endpoint: Some(endpoint(
            60 + path_byte,
            22_000 + u16::from(path_byte),
        )),
        exit_wireguard_endpoint: grant.exit_wireguard_endpoint,
        policy_hash: grant.policy_hash,
        created_at_ms: grant.created_at_ms,
        expires_at_ms: grant.expires_at_ms,
        nonce: relay_nonce.to_vec(),
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
        relay_nonce,
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

#[tokio::test]
async fn signed_open_frame_is_bound_to_multipath_route_and_policy() {
    let control_relay = key(49);
    let exit = key(50);
    let relay_one = key(51);
    let relay_two = key(52);
    let client = key(53);
    let client_id = node_id(&client);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let signed_exit = signed_exit(&exit, &scope);
    let signed_relay_one = signed_relay(&exit, &relay_one, &scope, 1);
    let signed_relay_two = signed_relay(&exit, &relay_two, &scope, 2);
    let mut replay = ReplayCache::new(16).unwrap();
    let route = VerifiedMptcpRoute::verify(
        &signed_exit,
        &[&signed_relay_one, &signed_relay_two],
        NOW + 1,
        TimePolicy::default(),
        &mut replay,
    )
    .unwrap();
    assert_eq!(route.path_count(), 2);

    let policy = policy();
    let open_nonce = [60; 32];
    let open = OpenTcp {
        route_context_id: route.route_context_id().to_vec(),
        flow_id: vec![61; 16],
        client_ephemeral_id: client_id,
        hostname: "www.example.com".to_owned(),
        port: 443,
        policy_hash: policy.policy_hash().to_vec(),
        timestamp_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: open_nonce.to_vec(),
    };
    let signed_open = sign_control_message(
        &open,
        &client,
        NOW,
        EXPIRY,
        open_nonce,
        TimePolicy::default(),
    )
    .unwrap();
    let scope = TcpAuthorizationScope::new(&route, &policy);
    let stale_policy = policy_for_domain("stale.example.com");
    let stale_scope = TcpAuthorizationScope::new(&route, &stale_policy);
    let replay_entries = replay.len();
    assert!(matches!(
        stale_scope.verify(&signed_open, NOW + 2, TimePolicy::default(), &mut replay),
        Err(TcpProxyError::InvalidBinding("policy hash"))
    ));
    assert_eq!(replay.len(), replay_entries);

    let (mut writer, mut reader) = duplex(4_096);
    write_open_tcp(&mut writer, &signed_open, Duration::from_secs(1))
        .await
        .unwrap();
    let authorized = read_authorized_open_tcp(
        &mut reader,
        &scope,
        NOW + 2,
        TimePolicy::default(),
        &mut replay,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(authorized.hostname(), "www.example.com");
    assert_eq!(authorized.port(), 443);
    assert!(!format!("{authorized:?}").contains("example.com"));

    let error = scope
        .verify(&signed_open, NOW + 3, TimePolicy::default(), &mut replay)
        .unwrap_err();
    assert!(matches!(
        error,
        TcpProxyError::Protocol(ProtocolError::Replay)
    ));
}

#[test]
fn route_rejects_reusing_one_relay_for_two_paths() {
    let control_relay = key(69);
    let exit = key(70);
    let relay = key(71);
    let client = key(72);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let signed_exit = signed_exit(&exit, &scope);
    let first = signed_relay(&exit, &relay, &scope, 1);
    let second = signed_relay(&exit, &relay, &scope, 2);
    let mut replay_cache = ReplayCache::new(16).unwrap();
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &signed_exit,
            &[&first, &second],
            NOW + 1,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(TcpProxyError::InvalidBinding("duplicate relay identity"))
    ));
    assert!(replay_cache.is_empty());

    let distinct_relay = key(73);
    let valid_second = signed_relay(&exit, &distinct_relay, &scope, 2);
    let route = VerifiedMptcpRoute::verify(
        &signed_exit,
        &[&first, &valid_second],
        NOW + 2,
        TimePolicy::default(),
        &mut replay_cache,
    )
    .unwrap();
    assert_eq!(route.path_count(), 2);
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
    first_relay: &SigningKey,
    second_relay: &SigningKey,
    scope: &V4GrantScope,
    substitution: GrantSubstitution,
    expected: &str,
) {
    let signed_exit = signed_exit(exit, scope);
    let substituted = signed_relay_with(exit, first_relay, scope, 1, 1, |grant| {
        substitution.apply(grant);
    });
    let second = signed_relay(exit, second_relay, scope, 2);
    let mut replay_cache = ReplayCache::new(16).unwrap();
    let result = VerifiedMptcpRoute::verify(
        &signed_exit,
        &[&substituted, &second],
        NOW + 2,
        TimePolicy::default(),
        &mut replay_cache,
    );
    assert!(
        matches!(result, Err(TcpProxyError::InvalidBinding(field)) if field == expected),
        "substitution unexpectedly accepted: {expected}"
    );
    assert!(
        replay_cache.is_empty(),
        "rejected substitution consumed replay state"
    );
}

#[test]
fn route_rejects_every_substituted_final_scope_field() {
    let exit = key(100);
    let first_relay = key(101);
    let second_relay = key(102);
    let client = key(103);
    let control_relay = key(104);
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
        assert_scope_substitution_rejected(
            &exit,
            &first_relay,
            &second_relay,
            &scope,
            substitution,
            expected,
        );
    }

    let foreign_exit = key(108);
    let foreign = signed_relay(&foreign_exit, &first_relay, &scope, 1);
    let second = signed_relay(&exit, &second_relay, &scope, 2);
    let signed_exit = signed_exit(&exit, &scope);
    let mut replay_cache = ReplayCache::new(16).unwrap();
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &signed_exit,
            &[&foreign, &second],
            NOW + 2,
            TimePolicy::default(),
            &mut replay_cache,
        ),
        Err(TcpProxyError::InvalidBinding("exit identity"))
    ));
    assert!(replay_cache.is_empty());
}

#[test]
fn route_requires_exact_final_path_cardinality() {
    let exit = key(109);
    let relays = [key(110), key(111), key(112)];
    let client = key(113);
    let control_relay = key(114);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let three_path_exit = signed_exit_with(&exit, &scope, |grant| {
        grant.maximum_paths = 3;
    });
    let first = signed_relay(&exit, &relays[0], &scope, 1);
    let second = signed_relay(&exit, &relays[1], &scope, 2);
    let third = signed_relay(&exit, &relays[2], &scope, 3);

    let mut replay = ReplayCache::new(20).unwrap();
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &three_path_exit,
            &[&first, &second],
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        ),
        Err(TcpProxyError::InvalidBinding("exit exact path count"))
    ));
    assert!(replay.is_empty());

    let two_path_exit = signed_exit(&exit, &scope);
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &two_path_exit,
            &[&first, &second, &third],
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        ),
        Err(TcpProxyError::InvalidBinding("exit exact path count"))
    ));
    assert!(replay.is_empty());
}

#[test]
fn route_requires_unique_path_ids_and_relay_peer_ids() {
    let exit = key(115);
    let first_relay = key(116);
    let second_relay = key(117);
    let client = key(118);
    let control_relay = key(119);
    let scope = v4_grant_scope(&exit, &client, &control_relay);
    let signed_exit = signed_exit(&exit, &scope);
    let first = signed_relay(&exit, &first_relay, &scope, 1);
    let duplicate_path = signed_relay_with(&exit, &second_relay, &scope, 1, 2, |_| {});
    let mut replay = ReplayCache::new(16).unwrap();
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &signed_exit,
            &[&first, &duplicate_path],
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        ),
        Err(TcpProxyError::InvalidBinding("duplicate relay path id"))
    ));
    assert!(replay.is_empty());

    let duplicate_peer = signed_relay_with(&exit, &second_relay, &scope, 2, 2, |grant| {
        grant.relay_peer_id = peer_id(&first_relay);
    });
    assert!(matches!(
        VerifiedMptcpRoute::verify(
            &signed_exit,
            &[&first, &duplicate_peer],
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        ),
        Err(TcpProxyError::InvalidBinding(
            "duplicate relay peer identity"
        ))
    ));
    assert!(replay.is_empty());
}

#[test]
fn v4_route_grants_reject_retired_permanent_client_peer_id_tags() {
    let control_relay = key(79);
    let exit = key(80);
    let relay = key(81);
    let client = key(82);
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
        &signed_relay(&exit, &relay, &scope, 1),
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
