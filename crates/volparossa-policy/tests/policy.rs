//! Integration tests for threshold-signed fail-closed policy manifests.

use std::net::{IpAddr, Ipv4Addr};

use ed25519_dalek::SigningKey;
use volparossa_policy::{
    DestinationRule, ManifestSpec, POLICY_PROTOCOL_VERSION, PolicyError, PolicyMode, ProtocolPort,
    TransportProtocol, TrustStore, TrustedMaintainer, VerificationPolicy, sign_manifest,
    verify_manifest,
};

fn keys() -> Vec<SigningKey> {
    (1_u8..=5)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect()
}

fn production_store(keys: &[SigningKey]) -> TrustStore {
    TrustStore::new(
        PolicyMode::Production,
        keys.iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect(),
    )
    .unwrap()
}

fn tcp(port: u16) -> ProtocolPort {
    ProtocolPort::new(TransportProtocol::Tcp, port).unwrap()
}

fn udp(port: u16) -> ProtocolPort {
    ProtocolPort::new(TransportProtocol::Udp, port).unwrap()
}

#[test]
fn three_of_five_manifest_enforces_domains_ip_protocol_and_port() {
    let signing_keys = keys();
    let store = production_store(&signing_keys);
    let mut specification = ManifestSpec::new(9, 1, 1_000, 1_000, 20_000).unwrap();
    specification
        .add_rule(DestinationRule::exact_domain("BÜCHER.example", [tcp(443)]).unwrap())
        .unwrap();
    specification
        .add_rule(
            DestinationRule::wildcard_domain("*.services.example", [tcp(443), udp(443)]).unwrap(),
        )
        .unwrap();
    let permitted_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    specification
        .add_rule(DestinationRule::exact_ip(permitted_ip, [udp(53)]).unwrap())
        .unwrap();

    let encoded = sign_manifest(
        &specification,
        &store,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    )
    .unwrap();
    let manifest = verify_manifest(&encoded, 2_000, &store, VerificationPolicy::default()).unwrap();

    assert_eq!(manifest.verified_signatures(), 3);
    assert!(
        manifest
            .authorize_domain(2_000, "xn--bcher-kva.example.", TransportProtocol::Tcp, 443)
            .is_ok()
    );
    assert!(
        manifest
            .authorize_domain(2_000, "a.services.example", TransportProtocol::Udp, 443)
            .is_ok()
    );
    assert!(
        manifest
            .authorize_domain(
                2_000,
                "deep.a.services.example",
                TransportProtocol::Tcp,
                443,
            )
            .is_ok()
    );
    assert!(matches!(
        manifest.authorize_domain(2_000, "services.example", TransportProtocol::Tcp, 443),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        manifest.authorize_domain(2_000, "badservices.example", TransportProtocol::Tcp, 443),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        manifest.authorize_domain(2_000, "a.services.example", TransportProtocol::Tcp, 80),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        manifest.authorize_domain(2_000, "192.0.2.20", TransportProtocol::Udp, 53),
        Err(PolicyError::RawIpAsDomain)
    ));
    assert!(
        manifest
            .authorize_ip(2_000, permitted_ip, TransportProtocol::Udp, 53)
            .is_ok()
    );
    assert!(matches!(
        manifest.authorize_ip(
            2_000,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)),
            TransportProtocol::Udp,
            53,
        ),
        Err(PolicyError::Denied)
    ));
}

#[test]
fn local_threshold_cannot_be_lowered_by_the_manifest() {
    let signing_keys = keys();
    let store = production_store(&signing_keys);
    let specification = ManifestSpec::new(1, 1, 1_000, 1_000, 20_000)
        .unwrap()
        .with_required_signatures(2)
        .unwrap();
    let encoded = sign_manifest(
        &specification,
        &store,
        &[&signing_keys[0], &signing_keys[1]],
    )
    .unwrap();
    assert!(matches!(
        verify_manifest(&encoded, 2_000, &store, VerificationPolicy::default()),
        Err(PolicyError::InsufficientSignatures {
            required: 3,
            valid: 2
        })
    ));
}

#[test]
fn protocol_and_time_checks_remain_fail_closed_at_flow_time() {
    let signing_keys = keys();
    let store = production_store(&signing_keys);
    let future_protocol =
        ManifestSpec::new(1, POLICY_PROTOCOL_VERSION + 1, 1_000, 1_000, 20_000).unwrap();
    let encoded = sign_manifest(
        &future_protocol,
        &store,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    )
    .unwrap();
    assert!(matches!(
        verify_manifest(&encoded, 2_000, &store, VerificationPolicy::default()),
        Err(PolicyError::UnsupportedProtocolVersion { .. })
    ));

    let mut short_lived = ManifestSpec::new(2, 1, 1_000, 2_000, 3_000).unwrap();
    short_lived
        .add_rule(DestinationRule::exact_domain("example.com", [tcp(443)]).unwrap())
        .unwrap();
    let encoded = sign_manifest(
        &short_lived,
        &store,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    )
    .unwrap();
    assert!(matches!(
        verify_manifest(&encoded, 1_999, &store, VerificationPolicy::default()),
        Err(PolicyError::NotYetValid)
    ));
    let manifest = verify_manifest(&encoded, 2_500, &store, VerificationPolicy::default()).unwrap();
    assert!(matches!(
        manifest.authorize_domain(3_000, "example.com", TransportProtocol::Tcp, 443),
        Err(PolicyError::Expired)
    ));
}

#[test]
fn production_mode_rejects_development_maintainers() {
    let signing_keys = keys();
    let maintainers = signing_keys
        .iter()
        .map(|key| TrustedMaintainer::development(key.verifying_key()))
        .collect();
    assert!(matches!(
        TrustStore::new(PolicyMode::Production, maintainers),
        Err(PolicyError::DevelopmentKeyRejected)
    ));
}

#[test]
fn canonical_output_is_independent_of_rule_and_signer_order() {
    let signing_keys = keys();
    let store = production_store(&signing_keys);
    let rule_a = DestinationRule::exact_domain("a.example", [tcp(443)]).unwrap();
    let rule_b = DestinationRule::exact_domain("b.example", [udp(443)]).unwrap();
    let mut first = ManifestSpec::new(4, 1, 1_000, 1_000, 20_000).unwrap();
    first.add_rule(rule_b.clone()).unwrap();
    first.add_rule(rule_a.clone()).unwrap();
    let mut second = ManifestSpec::new(4, 1, 1_000, 1_000, 20_000).unwrap();
    second.add_rule(rule_a).unwrap();
    second.add_rule(rule_b).unwrap();

    let first = sign_manifest(
        &first,
        &store,
        &[&signing_keys[2], &signing_keys[0], &signing_keys[1]],
    )
    .unwrap();
    let second = sign_manifest(
        &second,
        &store,
        &[&signing_keys[1], &signing_keys[2], &signing_keys[0]],
    )
    .unwrap();
    assert_eq!(first, second);
}
