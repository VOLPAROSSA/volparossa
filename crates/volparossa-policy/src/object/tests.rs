use super::*;
use crate::{
    DestinationRule, PolicyMode, ProtocolPort, TransportProtocol, TrustedMaintainer, sign_manifest,
    verify_manifest,
};

fn fixture() -> (
    Vec<SigningKey>,
    TrustStore,
    VerifiedManifest,
    ObjectDecision,
) {
    let keys: Vec<_> = (1_u8..=5)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect();
    let trust = store(&keys);
    let mut specification = ManifestSpec::new(7, 1, 1000, 1000, 20_000).unwrap();
    specification
        .add_rule(
            DestinationRule::exact_domain(
                "example.com",
                [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
            )
            .unwrap(),
        )
        .unwrap();
    let encoded = sign_manifest(&specification, &trust, &[&keys[0], &keys[1], &keys[2]]).unwrap();
    let current = verify_manifest(&encoded, 2000, &trust, VerificationPolicy::default()).unwrap();
    let body = ObjectDecision {
        policy_hash: *current.policy_hash(),
        policy_version: current.manifest_version(),
        decision_revision: 1,
        subject: ObjectSubject {
            publisher_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            manifest_id: [10; 32],
            object_sha256: [11; 32],
        },
        framework_sha256: [12; 32],
        evidence_sha256: [13; 32],
        outcome: ObjectOutcome::Deny,
        issued_at_ms: 2000,
        expires_at_ms: 10_000,
        nonce: [14; 32],
    };
    (keys, trust, current, body)
}

fn store(keys: &[SigningKey]) -> TrustStore {
    TrustStore::new(
        PolicyMode::Production,
        keys.iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect(),
    )
    .unwrap()
}

fn signed(body: &ObjectDecision, keys: &[SigningKey]) -> SignedObjectDecision {
    let mut signed = SignedObjectDecision::new(body.clone()).unwrap();
    for key in keys {
        signed.endorse(key).unwrap();
    }
    signed
}

fn verify(
    signed: &SignedObjectDecision,
    trust: &TrustStore,
    current: &VerifiedManifest,
) -> Result<VerifiedObjectDecision, PolicyError> {
    verify_object_decision(
        &signed.encode()?,
        3000,
        trust,
        VerificationPolicy::default(),
        current,
    )
}

#[test]
fn canonical_roundtrip_and_quorum_bind_all_original_fields() {
    let (keys, trust, current, body) = fixture();
    for outcome in [
        ObjectOutcome::Allow,
        ObjectOutcome::Deny,
        ObjectOutcome::Undetermined,
    ] {
        let body = ObjectDecision {
            outcome,
            ..body.clone()
        };
        let mut proposal = signed(&body, &keys[..2]);
        assert!(matches!(
            verify(&proposal, &trust, &current),
            Err(PolicyError::InsufficientSignatures {
                required: 3,
                valid: 2
            })
        ));
        proposal.endorse(&keys[2]).unwrap();
        let bytes = proposal.encode().unwrap();
        let decoded = SignedObjectDecision::decode(&bytes).unwrap();
        assert_eq!(decoded.body(), &body);
        assert_eq!(decoded.encode().unwrap(), bytes);
        let verified = verify(&decoded, &trust, &current).unwrap();
        assert_eq!(verified.body(), &body);
        let hash = *verified.decision_hash();
        proposal.endorse(&keys[3]).unwrap();
        assert_eq!(
            verify(&proposal, &trust, &current).unwrap().decision_hash(),
            &hash
        );
    }
}

#[test]
fn merge_requires_identical_body_and_never_renews_or_replaces() {
    let (keys, trust, current, body) = fixture();
    let mut first = signed(&body, &keys[..1]);
    first.merge(&signed(&body, &keys[1..3])).unwrap();
    assert_eq!(verify(&first, &trust, &current).unwrap().body(), &body);
    let original = first.encode().unwrap();
    for changed in [
        ObjectDecision {
            expires_at_ms: 11_000,
            ..body.clone()
        },
        ObjectDecision {
            outcome: ObjectOutcome::Allow,
            ..body.clone()
        },
        ObjectDecision {
            nonce: [15; 32],
            ..body.clone()
        },
    ] {
        assert!(first.merge(&signed(&changed, &keys[3..4])).is_err());
        assert_eq!(first.encode().unwrap(), original);
    }
    assert!(matches!(
        first.merge(&signed(&body, &keys[..1])),
        Err(PolicyError::DuplicateItem(_))
    ));
    assert_eq!(first.encode().unwrap(), original);
    assert!(matches!(
        first.endorse(&keys[0]),
        Err(PolicyError::DuplicateItem(_))
    ));
}

#[test]
fn policy_epoch_time_and_original_expiry_are_not_transferable() {
    let (keys, trust, current, body) = fixture();
    for changed in [
        ObjectDecision {
            policy_hash: [24; 32],
            ..body.clone()
        },
        ObjectDecision {
            policy_version: 8,
            ..body.clone()
        },
        ObjectDecision {
            expires_at_ms: 20_001,
            ..body.clone()
        },
        ObjectDecision {
            issued_at_ms: 999,
            ..body.clone()
        },
        ObjectDecision {
            issued_at_ms: 4000,
            ..body.clone()
        },
    ] {
        assert!(verify(&signed(&changed, &keys[..3]), &trust, &current).is_err());
    }
    let encoded = signed(&body, &keys[..3]).encode().unwrap();
    assert!(matches!(
        verify_object_decision(
            &encoded,
            10_000,
            &trust,
            VerificationPolicy::default(),
            &current
        ),
        Err(PolicyError::Expired)
    ));
    assert!(matches!(
        verify_object_decision(
            &encoded,
            20_000,
            &trust,
            VerificationPolicy::default(),
            &current
        ),
        Err(PolicyError::Expired)
    ));
}

#[test]
fn separately_selected_trust_set_must_belong_to_the_current_manifest() {
    let (_, _, current, body) = fixture();
    let other: Vec<_> = (20_u8..25)
        .map(|value| SigningKey::from_bytes(&[value; 32]))
        .collect();
    // A complete different quorum signing the original policy hash cannot adopt authority.
    assert!(matches!(
        verify(&signed(&body, &other[..3]), &store(&other), &current),
        Err(PolicyError::TrustRootMismatch)
    ));
}

#[test]
fn untrusted_or_invalid_extra_signatures_are_not_ignored() {
    let (keys, trust, current, body) = fixture();
    let mut untrusted = signed(&body, &keys[..3]);
    untrusted
        .endorse(&SigningKey::from_bytes(&[80; 32]))
        .unwrap();
    assert!(matches!(
        verify(&untrusted, &trust, &current),
        Err(PolicyError::UntrustedSigner)
    ));
    let mut invalid = signed(&body, &keys[..4]);
    invalid.signatures[3].signature[0] ^= 1;
    assert!(matches!(
        verify(&invalid, &trust, &current),
        Err(PolicyError::InvalidSignature)
    ));
    let stricter = VerificationPolicy::new(4, 5, 20_000, 0).unwrap();
    assert!(matches!(
        verify_object_decision(
            &signed(&body, &keys[..3]).encode().unwrap(),
            3000,
            &trust,
            stricter,
            &current
        ),
        Err(PolicyError::InsufficientSignatures {
            required: 4,
            valid: 3
        })
    ));
}

#[test]
fn canonical_decoder_rejects_duplicate_signers_unknown_fields_and_hash_tampering() {
    let (keys, _, _, body) = fixture();
    let encoded = signed(&body, &keys[..3]).encode().unwrap();
    let mut wire: EnvelopeProto = decode_canonical(&encoded, MAX_OBJECT_DECISION_BYTES).unwrap();
    wire.signatures.insert(0, wire.signatures[0].clone());
    assert!(matches!(
        SignedObjectDecision::decode(&encode_canonical(&wire, MAX_OBJECT_DECISION_BYTES).unwrap()),
        Err(PolicyError::DuplicateItem(_))
    ));
    let mut wire: EnvelopeProto = decode_canonical(&encoded, MAX_OBJECT_DECISION_BYTES).unwrap();
    wire.body_hash[0] ^= 1;
    assert!(matches!(
        SignedObjectDecision::decode(&encode_canonical(&wire, MAX_OBJECT_DECISION_BYTES).unwrap()),
        Err(PolicyError::ManifestHashMismatch)
    ));
    let mut extra = encoded;
    extra.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert!(matches!(
        SignedObjectDecision::decode(&extra),
        Err(PolicyError::NonCanonicalProtobuf)
    ));
    assert!(SignedObjectDecision::decode(&vec![0; MAX_OBJECT_DECISION_BYTES + 1]).is_err());
}

#[test]
fn zero_identity_nonce_revision_and_unknown_types_are_rejected() {
    let (_, _, _, body) = fixture();
    for changed in [
        ObjectDecision {
            nonce: [0; 32],
            ..body.clone()
        },
        ObjectDecision {
            framework_sha256: [0; 32],
            ..body.clone()
        },
        ObjectDecision {
            decision_revision: 0,
            ..body.clone()
        },
    ] {
        assert!(SignedObjectDecision::new(changed).is_err());
    }
    for (version, message_type, outcome) in [(2, 1, 2), (1, 2, 2), (1, 1, 0)] {
        let mut wire = wire_body(&body);
        wire.version = version;
        wire.message_type = message_type;
        wire.outcome = outcome;
        assert!(semantic(&wire).is_err());
    }
}
