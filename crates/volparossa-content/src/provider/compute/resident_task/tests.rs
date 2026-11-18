//! Public signing fixtures only: no fabricated attestation or model execution.

use ed25519_dalek::Signer as _;
use prost::Message;
use sha2::{Digest as _, Sha256};

use super::*;

const INPUTS: [[u8; 32]; 2] = [[41; 32], [42; 32]];
const DOMAIN: &[u8] = b"VOLPAROSSA/resident-public-fixture-task/v1\0";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

fn limits() -> GrantLimits {
    GrantLimits {
        maximum_requests: 2,
        maximum_turn_seconds: 600,
        threads: 2,
    }
}

fn expectations() -> GrantExpectations {
    GrantExpectations {
        requester_key: key().verifying_key().to_bytes(),
        guest_tls_spki_sha256: [21; 32],
        workload_sha256: [22; 32],
        model: GrantModel::Qwen3FourBInstruct2507,
        backend: GrantBackend::LlamaCppBf16V1,
        tls_exporter: [23; 32],
        limits: limits(),
        public_input_sha256: INPUTS,
    }
}

fn verifier() -> GrantVerifier {
    GrantVerifier::new(expectations()).expect("valid public expectations")
}

fn spec(verifier: &GrantVerifier) -> GrantSpec {
    GrantSpec {
        requester_key: key().verifying_key().to_bytes(),
        guest_tls_spki_sha256: [21; 32],
        workload_sha256: [22; 32],
        model: GrantModel::Qwen3FourBInstruct2507,
        backend: GrantBackend::LlamaCppBf16V1,
        nonce: *verifier.nonce(),
        tls_exporter: [23; 32],
        issued_at_ms: verifier.issued_at_ms(),
        expires_at_ms: verifier.maximum_expires_at_ms(),
        limits: limits(),
        public_input_sha256: INPUTS,
    }
}

fn envelope() -> wire::Envelope {
    let verifier = verifier();
    let bytes = sign(&key(), &spec(&verifier)).expect("public fixture signing");
    wire::Envelope::decode(bytes.as_slice()).expect("canonical envelope")
}

fn resign(mut envelope: wire::Envelope) -> Vec<u8> {
    let body = envelope.body.as_ref().expect("body");
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&body.encode_to_vec());
    envelope.signature = key().sign(&message).to_bytes().to_vec();
    envelope.encode_to_vec()
}

fn rewrite_payload(change: impl FnOnce(&mut wire::Payload)) -> Vec<u8> {
    let mut envelope = envelope();
    let body = envelope.body.as_mut().expect("body");
    let mut payload = wire::Payload::decode(body.payload.as_slice()).expect("payload");
    change(&mut payload);
    body.payload = payload.encode_to_vec();
    body.payload_sha256 = Sha256::digest(&body.payload).to_vec();
    resign(envelope)
}

#[test]
fn public_grant_canonical_signed_roundtrip_and_two_ordered_inputs() {
    let verifier = verifier();
    let deadline = verifier.deadline();
    let grant = spec(&verifier);
    let encoded = sign(&key(), &grant).expect("sign");
    assert!(encoded.len() <= MAX_GRANT_BYTES);
    let decoded = wire::decode(&encoded).expect("decode");
    assert_eq!(sign(&key(), &decoded).expect("resign"), encoded);
    let mut allowance = verifier.verify(&encoded).expect("verify");
    assert_eq!(allowance.deadline(), deadline);
    assert_eq!(allowance.limits(), limits());
    assert_eq!(allowance.check(), Ok(()));
    assert_eq!(allowance.consume_input(&INPUTS[0]), Ok(()));
    assert_eq!(allowance.consume_input(&INPUTS[1]), Ok(()));
    assert_eq!(
        allowance.consume_input(&INPUTS[0]),
        Err(GrantError::Exhausted)
    );
}

#[test]
fn public_grant_wrong_signer_and_signature_are_rejected() {
    let verifier = verifier();
    let grant = spec(&verifier);
    let wrong = SigningKey::from_bytes(&[12; 32]);
    assert_eq!(sign(&wrong, &grant).err(), Some(GrantError::Authentication));
    let mut envelope = envelope();
    envelope.signature[0] ^= 1;
    assert_eq!(
        wire::decode(&envelope.encode_to_vec()).err(),
        Some(GrantError::Authentication)
    );
    envelope.signature.pop();
    assert_eq!(
        wire::decode(&envelope.encode_to_vec()).err(),
        Some(GrantError::Invalid)
    );
}

#[test]
fn public_grant_domain_and_payload_hash_are_authenticated() {
    let mut envelope = envelope();
    let body = envelope.body.as_ref().expect("body");
    envelope.signature = key().sign(&body.encode_to_vec()).to_bytes().to_vec();
    assert_eq!(
        wire::decode(&envelope.encode_to_vec()).err(),
        Some(GrantError::Authentication)
    );
    envelope.body.as_mut().expect("body").payload_sha256[0] ^= 1;
    assert_eq!(
        wire::decode(&resign(envelope)).err(),
        Some(GrantError::Invalid)
    );
}

#[test]
fn public_grant_wrong_nonce_channel_spki_workload_and_inputs_are_rejected() {
    for index in 0..5 {
        let verifier = verifier();
        let mut grant = spec(&verifier);
        match index {
            0 => grant.nonce[0] ^= 1,
            1 => grant.tls_exporter[0] ^= 1,
            2 => grant.guest_tls_spki_sha256[0] ^= 1,
            3 => grant.workload_sha256[0] ^= 1,
            4 => grant.public_input_sha256.swap(0, 1),
            _ => unreachable!(),
        }
        let bytes = sign(&key(), &grant).expect("valid differently bound grant");
        assert_eq!(
            verifier.verify(&bytes).err(),
            Some(GrantError::Authentication)
        );
    }
}

#[test]
fn public_grant_different_requester_requires_independent_authorization() {
    let verifier = verifier();
    let mut grant = spec(&verifier);
    let other = SigningKey::from_bytes(&[12; 32]);
    grant.requester_key = other.verifying_key().to_bytes();
    let bytes = sign(&other, &grant).expect("other actual signature");
    assert_eq!(
        verifier.verify(&bytes).err(),
        Some(GrantError::Authentication)
    );
}

#[test]
fn public_grant_replay_into_new_verifier_is_rejected() {
    let first = verifier();
    let second = verifier();
    assert_ne!(first.nonce(), second.nonce());
    let bytes = sign(&key(), &spec(&first)).expect("sign");
    let _allowance = first.verify(&bytes).expect("first use");
    assert_eq!(
        second.verify(&bytes).err(),
        Some(GrantError::Authentication)
    );
}

#[test]
fn public_grant_even_matching_nonce_cannot_cross_tls_exporters() {
    let first = verifier();
    let mut second = verifier();
    // Test-only forced nonce collision still cannot remove the channel binding.
    second.nonce = *first.nonce();
    second.expected.tls_exporter[0] ^= 1;
    let bytes = sign(&key(), &spec(&first)).expect("sign");
    assert_eq!(
        second.verify(&bytes).err(),
        Some(GrantError::Authentication)
    );
}

#[test]
fn public_grant_outer_unknown_duplicate_and_reordered_fields_are_noncanonical() {
    let envelope = envelope();
    let original = envelope.encode_to_vec();
    let mut unknown = original.clone();
    unknown.extend_from_slice(&[0x78, 1]);
    let mut duplicate = original.clone();
    duplicate.extend_from_slice(&[0x12, 64]);
    duplicate.extend_from_slice(&envelope.signature);
    let mut reordered = vec![0x12, 64];
    reordered.extend_from_slice(&envelope.signature);
    reordered.extend_from_slice(&original[..original.len() - 66]);
    for bytes in [unknown, duplicate, reordered] {
        assert_eq!(wire::decode(&bytes).err(), Some(GrantError::Invalid));
    }
}

#[test]
fn public_grant_signed_nested_unknown_duplicate_and_overlong_fields_are_rejected() {
    for extra in [vec![0x78, 1], vec![0x18, 1], vec![0x18, 0x81, 0]] {
        let mut envelope = envelope();
        let body = envelope.body.as_mut().expect("body");
        body.payload.extend_from_slice(&extra);
        body.payload_sha256 = Sha256::digest(&body.payload).to_vec();
        assert_eq!(
            wire::decode(&resign(envelope)).err(),
            Some(GrantError::Invalid)
        );
    }
}

#[test]
fn public_grant_size_truncation_missing_body_and_signature_lengths_are_rejected() {
    for bytes in [vec![], vec![0; MAX_GRANT_BYTES + 1], vec![0x0a, 0x80]] {
        assert_eq!(wire::decode(&bytes).err(), Some(GrantError::Invalid));
    }
    let mut missing_body = envelope();
    missing_body.body = None;
    assert_eq!(
        wire::decode(&missing_body.encode_to_vec()).err(),
        Some(GrantError::Invalid)
    );
    for size in [0, 63, 65] {
        let mut envelope = envelope();
        envelope.signature = vec![1; size];
        assert_eq!(
            wire::decode(&envelope.encode_to_vec()).err(),
            Some(GrantError::Invalid)
        );
    }
}

#[test]
fn public_grant_version_kind_profile_and_fixed_width_fields_are_closed() {
    for index in 0..6 {
        let mut envelope = envelope();
        let body = envelope.body.as_mut().expect("body");
        match index {
            0 => body.version = 2,
            1 => body.kind = 2,
            2 => {
                body.requester_key.pop().expect("key");
            }
            3 => body.nonce.push(1),
            4 => {
                body.payload_sha256.pop().expect("digest");
            }
            5 => body.nonce.fill(0),
            _ => unreachable!(),
        }
        assert_eq!(
            wire::decode(&resign(envelope)).err(),
            Some(GrantError::Invalid)
        );
    }
    for index in 0..6 {
        let bytes = rewrite_payload(|payload| match index {
            0 => payload.model = 2,
            1 => payload.backend = 2,
            2 => payload.guest_tls_spki_sha256.push(0),
            3 => payload.workload_sha256.clear(),
            4 => {
                payload.tls_exporter.pop().expect("exporter");
            }
            5 => payload.public_input_sha256[1].clear(),
            _ => unreachable!(),
        });
        assert_eq!(wire::decode(&bytes).err(), Some(GrantError::Invalid));
    }
}

#[test]
fn public_grant_requires_exactly_two_preapproved_input_digests() {
    for count in [0, 1, 3] {
        let bytes = rewrite_payload(|payload| {
            payload.public_input_sha256 = vec![vec![41; 32]; count];
        });
        assert_eq!(wire::decode(&bytes).err(), Some(GrantError::Invalid));
    }
}

#[test]
fn public_grant_numeric_limits_reject_zero_overflow_and_excess() {
    for (requests, turn, threads) in [
        (0, 600, 2),
        (3, 600, 2),
        (2, 0, 2),
        (2, 601, 2),
        (2, 600, 0),
        (2, 600, 3),
        (u32::MAX, 600, 2),
        (2, u32::MAX, 2),
        (2, 600, u32::MAX),
    ] {
        let bytes = rewrite_payload(|payload| {
            payload.maximum_requests = requests;
            payload.maximum_turn_seconds = turn;
            payload.threads = threads;
        });
        assert_eq!(wire::decode(&bytes).err(), Some(GrantError::Invalid));
    }
}

#[test]
fn public_grant_independent_resource_ceilings_cannot_be_enlarged() {
    for index in 0..3 {
        let mut expected = expectations();
        match index {
            0 => expected.limits.maximum_requests = 1,
            1 => expected.limits.maximum_turn_seconds = 300,
            2 => expected.limits.threads = 1,
            _ => unreachable!(),
        }
        let verifier = GrantVerifier::new(expected).expect("valid lower ceiling");
        let bytes = sign(&key(), &spec(&verifier)).expect("valid global ceilings");
        assert_eq!(
            verifier.verify(&bytes).err(),
            Some(GrantError::Authentication)
        );
    }
    let mut expected = expectations();
    expected.limits.maximum_requests = 0;
    assert_eq!(
        GrantVerifier::new(expected).err(),
        Some(GrantError::Invalid)
    );
}

#[test]
fn public_grant_signing_rejects_zero_nonce_and_invalid_time_intervals() {
    for index in 0..5 {
        let verifier = verifier();
        let mut grant = spec(&verifier);
        match index {
            0 => grant.nonce = [0; 32],
            1 => grant.issued_at_ms = 0,
            2 => grant.expires_at_ms = grant.issued_at_ms,
            3 => grant.expires_at_ms = grant.issued_at_ms - 1,
            4 => grant.expires_at_ms += 1,
            _ => unreachable!(),
        }
        assert_eq!(sign(&key(), &grant).err(), Some(GrantError::Invalid));
    }
}

#[test]
fn public_grant_original_challenge_wall_bounds_reject_stale_future_and_rollback() {
    for index in 0..5 {
        let verifier = verifier();
        let mut grant = spec(&verifier);
        let mut wall_ms = verifier.issued_at_ms() + 10;
        match index {
            0 => {
                grant.issued_at_ms -= 1;
                grant.expires_at_ms -= 1;
            }
            1 => grant.issued_at_ms += 11,
            2 => grant.expires_at_ms = wall_ms,
            3 => {
                grant.issued_at_ms += 1;
                grant.expires_at_ms += 1;
            }
            4 => wall_ms = verifier.issued_at_ms() - 1,
            _ => unreachable!(),
        }
        let bytes = sign(&key(), &grant).expect("structurally valid time interval");
        let decoded = wire::decode(&bytes).expect("signature and canonical fields");
        let now = Stamp {
            monotonic: verifier.started.monotonic + Duration::from_millis(10),
            wall_ms,
        };
        assert_eq!(
            verifier.finish(&decoded, &now).err(),
            Some(GrantError::Expired)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn public_grant_delayed_verification_does_not_rebase_original_deadline() {
    let verifier = verifier();
    let deadline = verifier.deadline();
    let bytes = sign(&key(), &spec(&verifier)).expect("sign");
    tokio::time::advance(Duration::from_secs(700)).await;
    let mut allowance = verifier.verify(&bytes).expect("still fresh");
    assert_eq!(allowance.deadline(), deadline);
    assert_eq!(allowance.consume_input(&INPUTS[0]), Ok(()));
    tokio::time::advance(Duration::from_secs(1700)).await;
    assert_eq!(allowance.check(), Err(GrantError::Expired));
    assert_eq!(
        allowance.consume_input(&INPUTS[1]),
        Err(GrantError::Expired)
    );
}

#[tokio::test(start_paused = true)]
async fn public_grant_late_signed_grant_is_rejected_despite_unchanged_wall_clock() {
    let verifier = verifier();
    let bytes = sign(&key(), &spec(&verifier)).expect("sign");
    tokio::time::advance(Duration::from_secs(MAX_GRANT_SECONDS)).await;
    assert_eq!(verifier.verify(&bytes).err(), Some(GrantError::Expired));
}

#[tokio::test(start_paused = true)]
async fn public_grant_shorter_signed_expiry_caps_before_preparation() {
    let verifier = verifier();
    let started = verifier.started.monotonic;
    let mut grant = spec(&verifier);
    grant.expires_at_ms = grant.issued_at_ms + 1000;
    let bytes = sign(&key(), &grant).expect("sign");
    tokio::time::advance(Duration::from_millis(750)).await;
    let allowance = verifier.verify(&bytes).expect("250 ms remain");
    assert_eq!(allowance.deadline(), started + Duration::from_secs(1));
    tokio::time::advance(Duration::from_millis(250)).await;
    assert_eq!(allowance.check(), Err(GrantError::Expired));
}

#[tokio::test(start_paused = true)]
async fn public_grant_tighter_expiry_cannot_be_renewed_during_signature_validation() {
    let verifier = verifier();
    let mut grant = spec(&verifier);
    grant.expires_at_ms = grant.issued_at_ms + 1000;
    let bytes = sign(&key(), &grant).expect("sign");
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(verifier.verify(&bytes).err(), Some(GrantError::Expired));
}

#[test]
fn public_grant_one_request_limit_and_wrong_input_poison_are_enforced() {
    let one_request = verifier();
    let mut grant = spec(&one_request);
    grant.limits.maximum_requests = 1;
    let bytes = sign(&key(), &grant).expect("sign");
    let mut allowance = one_request.verify(&bytes).expect("verify");
    assert_eq!(allowance.consume_input(&INPUTS[0]), Ok(()));
    assert_eq!(
        allowance.consume_input(&INPUTS[1]),
        Err(GrantError::Exhausted)
    );
    for wrong in [INPUTS[1], [0; 32]] {
        let verifier = verifier();
        let bytes = sign(&key(), &spec(&verifier)).expect("sign");
        let mut allowance = verifier.verify(&bytes).expect("verify");
        assert_eq!(allowance.consume_input(&wrong), Err(GrantError::Input));
        assert_eq!(
            allowance.consume_input(&INPUTS[0]),
            Err(GrantError::Exhausted)
        );
    }
}

#[test]
fn public_grant_error_messages_are_closed_and_do_not_echo_wire_bytes() {
    for error in [
        GrantError::Invalid,
        GrantError::Authentication,
        GrantError::Expired,
        GrantError::Exhausted,
        GrantError::Input,
        GrantError::Entropy,
    ] {
        let text = error.to_string();
        assert!(
            text.starts_with("public resident task") || text.starts_with("invalid public resident")
        );
        assert!(text.len() < 80);
        assert!(!text.contains("TLS_EXPORTER_CANARY"));
    }
    let malformed = b"TLS_EXPORTER_CANARY";
    let error = verifier().verify(malformed).err().expect("invalid wire");
    assert_eq!(error.to_string(), "invalid public resident task grant");
}
