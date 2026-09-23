//! Synthetic signed transport records only; never an actual model execution claim.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

use super::*;
use crate::{
    provider::{
        PublicationRegistry,
        compute::{
            ComputeBackend, ComputeChallenge, ComputeFuture, ComputeService, begin, exchange,
            exchange_attested,
        },
        serve_publication,
    },
    transfer::TransferLimits,
};

fn keys() -> (SigningKey, SigningKey) {
    (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    )
}

fn signed_records(request_size: usize, response_size: usize) -> Transcript {
    let (provider, requester) = keys();
    let challenge = Record::challenge(&provider, 100).unwrap();
    let request = Record::request(&requester, &challenge, vec![b'r'; request_size], 101).unwrap();
    let reply = Record::reply(
        &provider,
        &challenge,
        Sha256::digest(request.encode()).into(),
        vec![b's'; response_size],
        102,
    )
    .unwrap();
    Transcript {
        version: 1,
        challenge: challenge.encode(),
        request: request.encode(),
        reply: reply.encode(),
    }
}

fn verify(transcript: &Transcript) -> Result<VerifiedTranscript, ComputeError> {
    let (provider, requester) = keys();
    verify_transcript(
        &transcript.encode_to_vec(),
        &provider.verifying_key().to_bytes(),
        &requester.verifying_key().to_bytes(),
    )
}

#[test]
fn historical_signature_evidence_retains_original_times_and_exact_bytes() {
    let original = signed_records(7, 9);
    let verified = verify(&original).unwrap();
    assert_eq!(verified.request_payload(), b"rrrrrrr");
    assert_eq!(verified.response_payload(), b"sssssssss");
    assert_eq!(verified.signed_created(), 102);
    assert_eq!(verified.signed_expires(), 130);
    // A fresh exchange cannot use this now-expired record. Historical proof can
    // still verify it, without accepting an invented fresh/current expiry.
    assert!(matches!(
        Record::decode(&original.reply, Kind::Reply, 130),
        Err(ComputeError::Expired)
    ));
    let challenge = Record::decode_historical(&original.challenge, Kind::Challenge).unwrap();
    let request = Record::decode_historical(&original.request, Kind::Request).unwrap();
    let reply = Record::decode_historical(&original.reply, Kind::Reply).unwrap();
    let exchange = authenticated(&challenge, &request, &reply).unwrap();
    assert_eq!(exchange.transcript_bytes(), original.encode_to_vec());
    assert_eq!(exchange.response_payload(), verified.response_payload());
    let (response, proof) = exchange.into_parts();
    assert_eq!(response, verified.response_payload());
    assert_eq!(proof, original.encode_to_vec());
}

#[test]
fn every_original_signature_and_expected_identity_is_required() {
    let original = signed_records(7, 9);
    for position in 0..3 {
        let mut changed = original.clone();
        let bytes = match position {
            0 => &mut changed.challenge,
            1 => &mut changed.request,
            _ => &mut changed.reply,
        };
        *bytes.last_mut().unwrap() ^= 1;
        assert!(verify(&changed).is_err());
    }
    let (provider, requester) = keys();
    let other = SigningKey::from_bytes(&[3; 32]);
    for (expected_provider, expected_requester) in [
        (other.verifying_key(), requester.verifying_key()),
        (provider.verifying_key(), other.verifying_key()),
    ] {
        assert!(
            verify_transcript(
                &original.encode_to_vec(),
                &expected_provider.to_bytes(),
                &expected_requester.to_bytes()
            )
            .is_err()
        );
    }
    // A correctly signed response from a different key still cannot replace the
    // independently selected provider, even with the exact original request hash.
    let challenge = Record::decode_historical(&original.challenge, Kind::Challenge).unwrap();
    let mut changed = original.clone();
    changed.reply = Record::reply(
        &other,
        &challenge,
        Sha256::digest(&original.request).into(),
        b"other signed response".to_vec(),
        102,
    )
    .unwrap()
    .encode();
    assert!(verify(&changed).is_err());
}

#[test]
fn signed_other_stream_requests_and_backdated_replies_cannot_be_spliced() {
    let (provider, requester) = keys();
    let original = signed_records(7, 9);
    let challenge = Record::decode_historical(&original.challenge, Kind::Challenge).unwrap();
    let mut changed = original.clone();
    changed.challenge = Record::challenge(&provider, 100).unwrap().encode();
    assert!(verify(&changed).is_err());
    changed = original.clone();
    changed.request = Record::request(&requester, &challenge, b"different request".to_vec(), 101)
        .unwrap()
        .encode();
    assert!(verify(&changed).is_err());
    changed = original.clone();
    changed.reply = Record::reply(
        &provider,
        &challenge,
        Sha256::digest(&original.request).into(),
        b"reply before request".to_vec(),
        100,
    )
    .unwrap()
    .encode();
    assert!(verify(&changed).is_err());
    let other = Record::challenge(&provider, 101).unwrap();
    changed.reply = Record::reply(
        &provider,
        &other,
        Sha256::digest(&original.request).into(),
        b"same request hash but different challenge and expiry".to_vec(),
        102,
    )
    .unwrap()
    .encode();
    assert!(verify(&changed).is_err());
}

#[test]
fn canonical_binary_framing_payload_hashes_and_exact_size_limits_are_checked() {
    let (provider, requester) = keys();
    let original = signed_records(MAX_TRANSCRIPT_REQUEST_BYTES, MAX_RESPONSE_BYTES);
    assert!(original.encode_to_vec().len() < MAX_TRANSCRIPT_BYTES);
    verify(&original).unwrap();
    assert!(verify(&signed_records(MAX_TRANSCRIPT_REQUEST_BYTES + 1, 1)).is_err());
    for extra in [
        &[0x28, 0x01][..], // Unknown outer field.
        &[0x08, 0x01][..], // Duplicate outer version.
    ] {
        let mut changed = original.encode_to_vec();
        changed.extend_from_slice(extra);
        assert!(
            verify_transcript(
                &changed,
                &provider.verifying_key().to_bytes(),
                &requester.verifying_key().to_bytes()
            )
            .is_err()
        );
    }
    let mut changed = original.clone();
    changed.request.extend_from_slice(&[0x18, 0x01]);
    assert!(verify(&changed).is_err());
    changed = original.clone();
    changed.version = 2;
    assert!(verify(&changed).is_err());
    changed = original.clone();
    let payload_start = changed
        .request
        .windows(32)
        .position(|bytes| bytes == [b'r'; 32])
        .unwrap();
    changed.request[payload_start] = b'x';
    assert!(verify(&changed).is_err());
    for bytes in [&[][..], &vec![0; MAX_TRANSCRIPT_BYTES + 1]] {
        assert!(
            verify_transcript(
                bytes,
                &provider.verifying_key().to_bytes(),
                &requester.verifying_key().to_bytes()
            )
            .is_err()
        );
    }
}

struct StatusOnly;

impl ComputeBackend for StatusOnly {
    fn exchange(&self, _requester: [u8; 32], _request: Vec<u8>) -> ComputeFuture<'_> {
        Box::pin(async { Ok(b"synthetic status".to_vec()) })
    }
}

#[tokio::test]
async fn live_attested_exchange_and_legacy_larger_requests_keep_distinct_bounds() {
    let (provider, requester) = keys();
    let provider = Arc::new(provider);
    let mut registry = PublicationRegistry::new();
    registry.set_compute(Arc::new(ComputeService::new(
        provider.clone(),
        Arc::new(StatusOnly),
    )));
    for attest in [true, false] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let serving = serve_publication(&mut server, &registry, TransferLimits::default());
        let requesting = async {
            let challenge = begin(&mut client, &provider.verifying_key().to_bytes())
                .await
                .unwrap();
            if attest {
                let result = exchange_attested(
                    &mut client,
                    challenge,
                    &requester,
                    b"synthetic poll".to_vec(),
                )
                .await
                .unwrap();
                let checked = verify_transcript(
                    result.transcript_bytes(),
                    &provider.verifying_key().to_bytes(),
                    &requester.verifying_key().to_bytes(),
                )
                .unwrap();
                assert_eq!(checked.request_payload(), b"synthetic poll");
                assert_eq!(checked.response_payload(), result.response_payload());
                result.into_parts().0
            } else {
                exchange(
                    &mut client,
                    challenge,
                    &requester,
                    vec![b'x'; MAX_TRANSCRIPT_REQUEST_BYTES + 1],
                )
                .await
                .unwrap()
            }
        };
        let (service_result, result) = tokio::join!(serving, requesting);
        service_result.unwrap();
        assert_eq!(result, b"synthetic status");
    }
}

#[tokio::test]
async fn oversized_attestation_request_is_rejected_before_any_request_write() {
    let (provider, requester) = keys();
    let challenge = ComputeChallenge(Record::challenge(&provider, 100).unwrap());
    let (mut client, mut server) = tokio::io::duplex(4096);
    let result = exchange_attested(
        &mut client,
        challenge,
        &requester,
        vec![b'x'; MAX_TRANSCRIPT_REQUEST_BYTES + 1],
    )
    .await;
    assert!(matches!(result, Err(ComputeError::Invalid)));
    drop(client);
    let mut written = Vec::new();
    server.read_to_end(&mut written).await.unwrap();
    assert!(written.is_empty());
}
