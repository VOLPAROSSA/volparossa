//! Integration tests for canonical signed VOLPAROSSA control-plane messages.

use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use volparossa_protocol::{
    AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork, AdvertisementPolicy,
    AdvertisementQuality, AdvertisementRoles, ClientSessionCapability, ControlMessageType,
    ControlPayload, ExitCapacityHold, ExitCapacityHoldRequest, ExitReservation,
    ExitReservationConfirmation, ExitReservationFinalizeRequest, FinalizedRelayPath,
    ForwardedPreselectionAttestation, MAX_CONTROL_PAYLOAD_SIZE, MAX_MASQUE_CONTEXT_ID,
    NATIVE_ROUTE_AUTH_BEARER_LENGTH, NATIVE_ROUTE_AUTH_COMMITMENT_DOMAIN, NativeRouteIdentity,
    NodeAdvertisement, ObservationAddressFamily, ObservationNetworkPrefix, OpenTcp,
    PROTOCOL_VERSION, PreselectionActorBinding, PreselectionObservationReceipt,
    PreselectionObservationRequest, PreselectionObservationRole, PreselectionObservationScope,
    ProtocolError, RelayAuthorization, RelayReservation, RelayReservationRequest, ReplayCache,
    SignedEnvelope, TimePolicy, Transport, UdpFlowAuthorization, WireguardEndpoint,
    consume_direct_preselection_transcript, consume_forwarded_preselection_transcript,
    decode_canonical, encode_canonical, exit_confirmation_envelope_hash,
    finalized_reservation_bundle_hash, frame_control_message, generate_nonce,
    native_route_auth_commitment, node_id_from_public_key, preselection_observation_receipt_hash,
    preselection_observation_request_hash, relay_reservation_request_sha256, sign_control_message,
    sign_control_message_with, unframe_control_message, verify_control_message,
    verify_direct_preselection_transcript, verify_forwarded_preselection_transcript,
    verify_relay_reservation,
};

const NOW: u64 = 1_700_000_000_000;
const EXPIRY: u64 = NOW + 60_000;

#[test]
fn protocol_version_matches_core_contract() {
    assert_eq!(
        PROTOCOL_VERSION,
        u32::from(volparossa_core::PROTOCOL_VERSION)
    );
}

#[test]
fn generated_control_nonces_are_nonzero_and_fresh() {
    let first = generate_nonce();
    let second = generate_nonce();

    assert!(first.iter().any(|byte| *byte != 0));
    assert!(second.iter().any(|byte| *byte != 0));
    assert_ne!(first, second);
}

#[test]
fn native_route_auth_commitment_has_one_exact_canonical_vector() {
    const BEARER: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const EXPECTED: [u8; 32] = [
        0x2b, 0x80, 0x72, 0x70, 0xdb, 0xd6, 0x15, 0x73, 0xcc, 0x59, 0x14, 0x25, 0x11, 0x62, 0x1e,
        0xd6, 0xf3, 0xc3, 0x3d, 0xd1, 0x40, 0x77, 0x4c, 0xc2, 0x4a, 0x04, 0x12, 0x71, 0xc6, 0x31,
        0x08, 0x85,
    ];

    assert_eq!(NATIVE_ROUTE_AUTH_BEARER_LENGTH, 43);
    assert_eq!(
        NATIVE_ROUTE_AUTH_COMMITMENT_DOMAIN,
        b"VOLPAROSSA-NATIVE-ROUTE-AUTH-COMMITMENT-V4\0"
    );
    assert_eq!(native_route_auth_commitment(BEARER).unwrap(), EXPECTED);

    for malformed in [
        &BEARER[..42],
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_slice(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".as_slice(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/".as_slice(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB".as_slice(),
    ] {
        assert!(matches!(
            native_route_auth_commitment(malformed),
            Err(ProtocolError::InvalidField(
                "native route authentication bearer"
            ))
        ));
    }
}

#[test]
fn preselection_schema_tags_and_callerless_surface_are_exact() {
    assert_eq!(
        ControlMessageType::PreselectionObservationReceipt as i32,
        17
    );
    assert_eq!(
        ControlMessageType::ForwardedPreselectionAttestation as i32,
        18
    );

    let schema = include_str!("../../../proto/volparossa/control/v4/control.proto");
    let messages = include_str!("../src/messages.rs");
    assert_preselection_message_type_tags(schema, messages);
    assert_preselection_schema_fields(schema);
    assert_preselection_product_surface();
}

#[test]
fn preselection_request_is_v4_role_exact_short_and_bounded() {
    let relay_key = key(91);
    let actor = preselection_actor(&relay_key, 92, NOW + 60_000, NOW + 60_000);
    let mut request =
        preselection_request(PreselectionObservationRole::Relay, actor.clone(), None, 93);
    request.validate().unwrap();
    request.expires_at_ms = NOW + 5_000;
    request.validate().expect("exact five-second challenge");
    request.expires_at_ms += 1;
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::InvalidLifetime)
    ));

    request = preselection_request(PreselectionObservationRole::Relay, actor.clone(), None, 93);
    request.protocol_version = 2;
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::UnsupportedVersion(2))
    ));
    request.protocol_version = PROTOCOL_VERSION;
    request.challenge.fill(0);
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::InvalidField(
            "preselection request challenge"
        ))
    ));
    for length in [31, 33] {
        request.challenge = vec![1; length];
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidField(
                "preselection request challenge"
            ))
        ));
    }

    request = preselection_request(PreselectionObservationRole::Relay, actor.clone(), None, 93);
    let control_key = key(94);
    request.forwarded_control = Some(preselection_actor(
        &control_key,
        95,
        NOW + 60_000,
        NOW + 60_000,
    ));
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::InvalidField(
            "preselection request role shape"
        ))
    ));

    request = preselection_request(PreselectionObservationRole::Exit, actor.clone(), None, 93);
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::InvalidField(
            "preselection request role shape"
        ))
    ));

    request = preselection_request(PreselectionObservationRole::Relay, actor, None, 93);
    request.actor.as_mut().unwrap().capability_expires_at_ms -= 1;
    assert!(matches!(
        request.validate(),
        Err(ProtocolError::InvalidField(
            "preselection direct capability expiry"
        ))
    ));
    request = preselection_request(
        PreselectionObservationRole::Relay,
        preselection_actor(&relay_key, 92, NOW + 60_000, NOW + 60_000),
        None,
        93,
    );
    request
        .actor
        .as_mut()
        .unwrap()
        .advertisement_payload_hash
        .fill(0);
    assert!(request.validate().is_err());

    let mut oversized = encode_preselection_request(&preselection_request(
        PreselectionObservationRole::Relay,
        preselection_actor(&relay_key, 96, NOW + 60_000, NOW + 60_000),
        None,
        97,
    ));
    oversized.resize(4 * 1024 + 1, 0);
    assert!(matches!(
        preselection_observation_request_hash(&oversized),
        Err(ProtocolError::Oversized { maximum: 4096, .. })
    ));
}

#[test]
fn direct_preselection_transcript_uses_local_challenge_time_not_actor_clock() {
    let (request, signed_receipt) = direct_preselection_fixture();
    assert!(request.expires_at_ms < NOW + 30_000);
    let encoded_request = encode_preselection_request(&request);
    let mut cache = ReplayCache::new(8).unwrap();
    verify_direct_preselection_transcript(
        &signed_receipt,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .expect("actor clock may be ahead within its signed TimePolicy");
    assert_eq!(cache.len(), 1);

    let mut expired_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_direct_preselection_transcript(
            &signed_receipt,
            &encoded_request,
            request.expires_at_ms,
            TimePolicy::default(),
            &mut expired_cache,
        ),
        Err(ProtocolError::Expired)
    ));
    assert!(expired_cache.is_empty());

    let relay_key = key(80);
    let mut future_request = request.clone();
    future_request.created_at_ms = NOW + 2;
    future_request.expires_at_ms = NOW + 4_002;
    let future_receipt =
        signed_preselection_receipt(&future_request, &relay_key, NOW + 30_000, NOW + 40_000, 98);
    let mut future_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_direct_preselection_transcript(
            &future_receipt,
            &encode_preselection_request(&future_request),
            NOW + 1,
            TimePolicy::default(),
            &mut future_cache,
        ),
        Err(ProtocolError::NotYetValid)
    ));
    assert!(future_cache.is_empty());

    let (_, signed_receipt) = direct_preselection_fixture();
    let mut envelope: SignedEnvelope = decode_canonical(
        &signed_receipt,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let mut loose_relay: PreselectionObservationReceipt =
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    loose_relay.actor.as_mut().unwrap().capability_expires_at_ms -= 1;
    envelope.payload = encode_canonical(&loose_relay, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let loose_relay = adversarially_resign_envelope(envelope, &relay_key);
    let mut loose_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_control_message::<PreselectionObservationReceipt>(
            &loose_relay,
            NOW + 1,
            TimePolicy::default(),
            &mut loose_cache,
        ),
        Err(ProtocolError::InvalidField(
            "preselection direct capability expiry"
        ))
    ));
    assert!(loose_cache.is_empty());
}

#[test]
fn verified_direct_transcript_is_consumed_only_for_its_exact_canonical_request() {
    let (request, signed_receipt) = direct_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);
    let mut success_cache = ReplayCache::new(8).unwrap();
    let verified = verify_direct_preselection_transcript(
        &signed_receipt,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut success_cache,
    )
    .unwrap();
    let bound = consume_direct_preselection_transcript(verified, &encoded_request).unwrap();
    drop(bound);

    let mut changed_request = request.clone();
    changed_request.challenge[0] ^= 1;
    changed_request.validate().unwrap();
    let mut mismatch_cache = ReplayCache::new(8).unwrap();
    let verified = verify_direct_preselection_transcript(
        &signed_receipt,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut mismatch_cache,
    )
    .unwrap();
    assert!(matches!(
        consume_direct_preselection_transcript(
            verified,
            &encode_preselection_request(&changed_request)
        ),
        Err(ProtocolError::InvalidField(
            "direct preselection transcript request"
        ))
    ));
    assert_eq!(mismatch_cache.len(), 1);
    assert!(matches!(
        verify_direct_preselection_transcript(
            &signed_receipt,
            &encoded_request,
            NOW + 2,
            TimePolicy::default(),
            &mut mismatch_cache,
        ),
        Err(ProtocolError::Replay)
    ));

    let mut noncanonical = encoded_request.clone();
    noncanonical.extend_from_slice(&[0xf8, 0x07, 0x01]);
    let mut canonical_cache = ReplayCache::new(8).unwrap();
    let verified = verify_direct_preselection_transcript(
        &signed_receipt,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut canonical_cache,
    )
    .unwrap();
    assert!(matches!(
        consume_direct_preselection_transcript(verified, &noncanonical),
        Err(ProtocolError::NonCanonical)
    ));
    assert_eq!(canonical_cache.len(), 1);
}

#[test]
fn verified_forwarded_transcript_is_consumed_only_for_its_exact_canonical_request() {
    let (request, _, signed_attestation, _, _) = forwarded_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);
    let mut success_cache = ReplayCache::new(8).unwrap();
    let verified = verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut success_cache,
    )
    .unwrap();
    let bound = consume_forwarded_preselection_transcript(verified, &encoded_request).unwrap();
    drop(bound);

    let mut changed_request = request;
    changed_request.challenge[0] ^= 1;
    changed_request.validate().unwrap();
    let mut mismatch_cache = ReplayCache::new(8).unwrap();
    let verified = verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut mismatch_cache,
    )
    .unwrap();
    assert!(matches!(
        consume_forwarded_preselection_transcript(
            verified,
            &encode_preselection_request(&changed_request)
        ),
        Err(ProtocolError::InvalidField(
            "forwarded preselection transcript request"
        ))
    ));
    assert_eq!(mismatch_cache.len(), 2);
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_request,
            NOW + 2,
            TimePolicy::default(),
            &mut mismatch_cache,
        ),
        Err(ProtocolError::Replay)
    ));
    assert_eq!(mismatch_cache.len(), 2);
}

#[test]
fn forwarded_preselection_requires_both_signers_and_accepts_earlier_control_ceiling() {
    let (request, signed_exit, signed_attestation, _, _) = forwarded_preselection_fixture();
    let control = request.forwarded_control.as_ref().unwrap();
    let exit = request.actor.as_ref().unwrap();
    assert!(control.capability_expires_at_ms < exit.advertisement_expires_at_ms);
    assert_eq!(
        exit.capability_expires_at_ms,
        control.capability_expires_at_ms
    );
    assert!(
        exit.capability_expires_at_ms
            < exit
                .advertisement_expires_at_ms
                .min(request.scope.as_ref().unwrap().policy_expires_at_ms)
    );
    let nested: SignedEnvelope =
        decode_canonical(&signed_exit, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let outer: SignedEnvelope = decode_canonical(
        &signed_attestation,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let receipt: PreselectionObservationReceipt =
        decode_canonical(&nested.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let attestation: ForwardedPreselectionAttestation =
        decode_canonical(&outer.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    assert_eq!(request.challenge, receipt.challenge);
    assert_eq!(request.challenge, attestation.challenge);
    assert_ne!(nested.nonce, outer.nonce);
    assert!(outer.timestamp_ms < nested.timestamp_ms);
    assert!(outer.expires_at_ms > nested.expires_at_ms);

    let encoded_request = encode_preselection_request(&request);
    let mut cache = ReplayCache::new(8).unwrap();
    verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(cache.len(), 2);

    let mut direct_only_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_exit,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut direct_only_cache,
        ),
        Err(ProtocolError::WrongMessageType { .. })
    ));
    assert!(direct_only_cache.is_empty());

    let outer: SignedEnvelope = decode_canonical(
        &signed_attestation,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let mut attestation: ForwardedPreselectionAttestation =
        decode_canonical(&outer.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    attestation
        .upstream_network_prefix
        .as_mut()
        .unwrap()
        .network_prefix = vec![10, 0, 0];
    assert!(matches!(
        attestation.validate(),
        Err(ProtocolError::InvalidField("observation network prefix"))
    ));
}

#[test]
fn expected_request_binding_precedes_committed_nested_replay() {
    let (request, signed_exit, signed_attestation, _, _) = forwarded_preselection_fixture();
    let mut wrong_request = request.clone();
    wrong_request.challenge[0] ^= 1;
    let encoded_wrong = encode_preselection_request(&wrong_request);

    let mut empty_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_wrong,
            NOW + 1,
            TimePolicy::default(),
            &mut empty_cache,
        ),
        Err(ProtocolError::InvalidField(
            "forwarded preselection observation binding"
        ))
    ));
    assert!(empty_cache.is_empty());
    verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encode_preselection_request(&request),
        NOW + 1,
        TimePolicy::default(),
        &mut empty_cache,
    )
    .expect("corrected exact request succeeds after rolled-back mismatch");
    assert_eq!(empty_cache.len(), 2);

    let mut cache = ReplayCache::new(8).unwrap();
    verify_control_message::<PreselectionObservationReceipt>(
        &signed_exit,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(cache.len(), 1);
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_wrong,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidField(
            "forwarded preselection observation binding"
        ))
    ));
    assert_eq!(cache.len(), 1, "outer insertion must be rolled back");
    assert!(matches!(
        verify_control_message::<PreselectionObservationReceipt>(
            &signed_exit,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::Replay)
    ));
}

#[test]
fn forwarded_structural_and_signature_failures_leave_replay_empty() {
    let (request, _, signed_attestation, control_key, _) = forwarded_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);

    let (outer, attestation) = decode_forwarded_attestation(&signed_attestation);
    let adversarial_control = resign_attestation(outer, &attestation, &control_key);
    let mut control_cache = ReplayCache::new(8).unwrap();
    verify_forwarded_preselection_transcript(
        &adversarial_control,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut control_cache,
    )
    .expect("test-local adversarial signer must reproduce a valid outer signature");
    assert_eq!(control_cache.len(), 2);

    let mut bad_outer_signature = signed_attestation.clone();
    *bad_outer_signature.last_mut().unwrap() ^= 1;
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &bad_outer_signature,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidSignature)
    ));
    assert!(cache.is_empty());

    let (outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
    let mut nested: SignedEnvelope = decode_canonical(
        &attestation.signed_exit_receipt,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let mut malformed_receipt: PreselectionObservationReceipt =
        decode_canonical(&nested.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    malformed_receipt.challenge.fill(0);
    nested.payload = encode_canonical(&malformed_receipt, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    attestation.signed_exit_receipt =
        encode_canonical(&nested, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    attestation.exit_receipt_hash =
        preselection_observation_receipt_hash(&attestation.signed_exit_receipt)
            .unwrap()
            .to_vec();
    let malformed_outer = resign_attestation(outer, &attestation, &control_key);
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(
        verify_forwarded_preselection_transcript(
            &malformed_outer,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        )
        .is_err()
    );
    assert!(
        cache.is_empty(),
        "nested structural failure precedes replay insertion"
    );

    let (_outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
    let mut nested: SignedEnvelope = decode_canonical(
        &attestation.signed_exit_receipt,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    nested.signature[0] ^= 1;
    attestation.signed_exit_receipt =
        encode_canonical(&nested, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    attestation.exit_receipt_hash =
        preselection_observation_receipt_hash(&attestation.signed_exit_receipt)
            .unwrap()
            .to_vec();
    let bad_nested = sign_control_message(
        &attestation,
        &control_key,
        attestation.observed_at_ms,
        attestation.valid_until_ms,
        [90; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &bad_nested,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidSignature)
    ));
    assert!(
        cache.is_empty(),
        "bad nested signature rolls outer replay back"
    );
}

#[test]
fn forwarded_nested_replay_and_capacity_roll_back_outer_only() {
    let (request, signed_exit, signed_attestation, _, _) = forwarded_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);
    let mut committed_inner = ReplayCache::new(8).unwrap();
    verify_control_message::<PreselectionObservationReceipt>(
        &signed_exit,
        NOW + 1,
        TimePolicy::default(),
        &mut committed_inner,
    )
    .unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut committed_inner,
        ),
        Err(ProtocolError::Replay)
    ));
    assert_eq!(
        committed_inner.len(),
        1,
        "prior inner remains; new outer is removed"
    );
    assert!(matches!(
        verify_control_message::<PreselectionObservationReceipt>(
            &signed_exit,
            NOW + 1,
            TimePolicy::default(),
            &mut committed_inner,
        ),
        Err(ProtocolError::Replay)
    ));

    let mut one_entry = ReplayCache::new(1).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut one_entry,
        ),
        Err(ProtocolError::ReplayCapacity)
    ));
    assert!(
        one_entry.is_empty(),
        "inner capacity failure rolls outer back"
    );
    let mut corrected_capacity = ReplayCache::new(2).unwrap();
    verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut corrected_capacity,
    )
    .expect("same bytes succeed when both replay entries fit");
    assert_eq!(corrected_capacity.len(), 2);
}

#[test]
fn forwarded_success_commits_both_and_replays_outer() {
    let (request, _, signed_attestation, _, _) = forwarded_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);
    let mut cache = ReplayCache::new(8).unwrap();
    verify_forwarded_preselection_transcript(
        &signed_attestation,
        &encoded_request,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(cache.len(), 2);
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &signed_attestation,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::Replay)
    ));
    assert_eq!(cache.len(), 2);
}

#[test]
fn preselection_receipt_and_wrapper_lifetimes_are_exact() {
    let relay_key = key(116);
    let actor = preselection_actor(&relay_key, 117, NOW + 120_000, NOW + 120_000);
    let mut request = preselection_request(PreselectionObservationRole::Relay, actor, None, 118);
    request.scope.as_mut().unwrap().policy_expires_at_ms = NOW + 120_000;
    request.validate().unwrap();
    let receipt = PreselectionObservationReceipt {
        request_hash: preselection_observation_request_hash(&encode_preselection_request(&request))
            .unwrap()
            .to_vec(),
        challenge: request.challenge.clone(),
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        observed_at_ms: NOW + 10_000,
        valid_until_ms: NOW + 70_000,
        nonce: vec![119; 32],
    };
    let signed = sign_control_message(
        &receipt,
        &relay_key,
        receipt.observed_at_ms,
        receipt.valid_until_ms,
        [119; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(8).unwrap();
    verify_direct_preselection_transcript(
        &signed,
        &encode_preselection_request(&request),
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(cache.len(), 1);
    let mut too_long = receipt;
    too_long.valid_until_ms += 1;
    too_long.nonce = vec![120; 32];
    assert!(matches!(
        sign_control_message(
            &too_long,
            &relay_key,
            too_long.observed_at_ms,
            too_long.valid_until_ms,
            [120; 32],
            TimePolicy::default(),
        ),
        Err(ProtocolError::InvalidLifetime)
    ));

    let (request, _, signed_outer, control_key, _) = forwarded_preselection_fixture();
    let (mut outer, mut attestation) = decode_forwarded_attestation(&signed_outer);
    assert_eq!(
        attestation.valid_until_ms - attestation.observed_at_ms,
        60_000
    );
    attestation.valid_until_ms += 1;
    outer.expires_at_ms = attestation.valid_until_ms;
    let overlong = resign_attestation(outer, &attestation, &control_key);
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &overlong,
            &encode_preselection_request(&request),
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidLifetime)
    ));
    assert!(cache.is_empty());
}

#[test]
fn preselection_request_receipt_and_wrapper_sizes_are_bounded() {
    let (request, signed_receipt) = direct_preselection_fixture();
    let mut oversized_receipt = signed_receipt;
    oversized_receipt.resize(4 * 1024 + 1, 0);
    assert!(matches!(
        preselection_observation_receipt_hash(&oversized_receipt),
        Err(ProtocolError::Oversized { maximum: 4096, .. })
    ));

    let (_, _, signed_outer, _, _) = forwarded_preselection_fixture();
    let mut oversized_outer = signed_outer.clone();
    oversized_outer.resize(8 * 1024 + 1, 0);
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &oversized_outer,
            &encode_preselection_request(&request),
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::Oversized { maximum: 8192, .. })
    ));
    assert!(cache.is_empty());

    let (_, mut attestation) = decode_forwarded_attestation(&signed_outer);
    attestation.signed_exit_receipt.resize(4 * 1024 + 1, 0);
    assert!(matches!(
        attestation.validate(),
        Err(ProtocolError::Oversized { maximum: 4096, .. })
    ));
}

#[test]
fn direct_preselection_actor_and_scope_bindings_are_field_exact() {
    for actor_case in 0..5 {
        assert_direct_request_mutation_rejected(|request| {
            let actor = request.actor.as_mut().unwrap();
            match actor_case {
                0 => {
                    let alternate = key(111);
                    actor.node_id = node_id(&alternate);
                    actor.public_key = alternate.verifying_key().to_bytes().to_vec();
                }
                1 => actor.peer_id[0] ^= 1,
                2 => actor.advertisement_sequence += 1,
                3 => {
                    actor.advertisement_expires_at_ms -= 1;
                    actor.capability_expires_at_ms -= 1;
                }
                4 => actor.advertisement_payload_hash[0] ^= 1,
                _ => unreachable!(),
            }
        });
    }
    for scope_case in 0..5 {
        assert_direct_request_mutation_rejected(|request| {
            let scope = request.scope.as_mut().unwrap();
            match scope_case {
                0 => scope.transport = Transport::UdpSinglePath as i32,
                1 => scope.address_family = ObservationAddressFamily::Ipv6 as i32,
                2 => scope.policy_version += 1,
                3 => scope.policy_hash[0] ^= 1,
                4 => {
                    scope.policy_expires_at_ms -= 1;
                    request.actor.as_mut().unwrap().capability_expires_at_ms -= 1;
                }
                _ => unreachable!(),
            }
        });
    }
}

#[test]
fn forwarded_control_binding_is_field_exact() {
    for control_case in 0..5 {
        let (mut request, _, signed_attestation, _, _) = forwarded_preselection_fixture();
        let control = request.forwarded_control.as_mut().unwrap();
        match control_case {
            0 => {
                let alternate = key(112);
                control.node_id = node_id(&alternate);
                control.public_key = alternate.verifying_key().to_bytes().to_vec();
            }
            1 => control.peer_id[0] ^= 1,
            2 => control.advertisement_sequence += 1,
            3 => {
                control.advertisement_expires_at_ms -= 1;
                control.capability_expires_at_ms -= 1;
                request.actor.as_mut().unwrap().capability_expires_at_ms -= 1;
            }
            4 => control.advertisement_payload_hash[0] ^= 1,
            _ => unreachable!(),
        }
        request.validate().unwrap();
        let mut cache = ReplayCache::new(8).unwrap();
        assert!(matches!(
            verify_forwarded_preselection_transcript(
                &signed_attestation,
                &encode_preselection_request(&request),
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::InvalidField(
                "forwarded preselection observation binding"
            ))
        ));
        assert!(
            cache.is_empty(),
            "control mutation {control_case} leaked replay"
        );
    }
}

#[test]
fn forwarded_exit_binding_is_field_exact() {
    for exit_case in 0..5 {
        let (mut request, _, signed_attestation, _, _) = forwarded_preselection_fixture();
        let exit = request.actor.as_mut().unwrap();
        match exit_case {
            0 => {
                let alternate = key(113);
                exit.node_id = node_id(&alternate);
                exit.public_key = alternate.verifying_key().to_bytes().to_vec();
            }
            1 => exit.peer_id[0] ^= 1,
            2 => exit.advertisement_sequence += 1,
            3 => exit.advertisement_expires_at_ms -= 1,
            4 => exit.advertisement_payload_hash[0] ^= 1,
            _ => unreachable!(),
        }
        request.validate().unwrap();
        let mut cache = ReplayCache::new(8).unwrap();
        assert!(matches!(
            verify_forwarded_preselection_transcript(
                &signed_attestation,
                &encode_preselection_request(&request),
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::InvalidField(
                "forwarded preselection observation binding"
            ))
        ));
        assert!(cache.is_empty());
    }
}

#[test]
fn forwarded_request_scope_binding_is_field_exact() {
    for scope_case in 0..5 {
        let (mut request, _, signed_attestation, _, _) = forwarded_preselection_fixture();
        let scope = request.scope.as_mut().unwrap();
        match scope_case {
            0 => scope.transport = Transport::UdpSinglePath as i32,
            1 => scope.address_family = ObservationAddressFamily::Ipv6 as i32,
            2 => scope.policy_version += 1,
            3 => scope.policy_hash[0] ^= 1,
            4 => scope.policy_expires_at_ms += 1,
            _ => unreachable!(),
        }
        request.validate().unwrap();
        let mut cache = ReplayCache::new(8).unwrap();
        assert!(matches!(
            verify_forwarded_preselection_transcript(
                &signed_attestation,
                &encode_preselection_request(&request),
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::InvalidField(
                "forwarded preselection observation binding"
            ))
        ));
        assert!(cache.is_empty());
    }
}

#[test]
fn forwarded_nested_duplicate_binding_precedes_committed_inner_replay() {
    for binding_case in 0..4 {
        let (request, signed_exit, signed_attestation, control_key, _) =
            forwarded_preselection_fixture();
        let (outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
        match binding_case {
            0 => attestation.request_hash[0] ^= 1,
            1 => attestation.challenge[0] ^= 1,
            2 => attestation.exit.as_mut().unwrap().peer_id[0] ^= 1,
            3 => {
                attestation.scope.as_mut().unwrap().transport = Transport::UdpSinglePath as i32;
            }
            _ => unreachable!(),
        }
        let signed_attestation = resign_attestation(outer, &attestation, &control_key);
        let mut cache = ReplayCache::new(8).unwrap();
        verify_control_message::<PreselectionObservationReceipt>(
            &signed_exit,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        )
        .unwrap();
        assert!(matches!(
            verify_forwarded_preselection_transcript(
                &signed_attestation,
                &encode_preselection_request(&request),
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::InvalidField(
                "forwarded observation nested binding"
            ))
        ));
        assert_eq!(cache.len(), 1);
        assert!(matches!(
            verify_control_message::<PreselectionObservationReceipt>(
                &signed_exit,
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::Replay)
        ));
    }
}

#[test]
fn forwarded_signer_hash_and_nested_type_bindings_are_exact() {
    let (request, _, signed_attestation, control_key, exit_key) = forwarded_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);

    let (mut wrong_outer, _) = decode_forwarded_attestation(&signed_attestation);
    let wrong_key = key(114);
    wrong_outer.sender_id = node_id(&wrong_key);
    wrong_outer.sender_public_key = wrong_key.verifying_key().to_bytes().to_vec();
    let wrong_outer = adversarially_resign_envelope(wrong_outer, &wrong_key);
    assert_forwarded_rejected_without_replay(&wrong_outer, &encoded_request);

    let (outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
    let mut wrong_nested: SignedEnvelope = decode_canonical(
        &attestation.signed_exit_receipt,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    let wrong_key = key(115);
    wrong_nested.sender_id = node_id(&wrong_key);
    wrong_nested.sender_public_key = wrong_key.verifying_key().to_bytes().to_vec();
    attestation.signed_exit_receipt = adversarially_resign_envelope(wrong_nested, &wrong_key);
    attestation.exit_receipt_hash =
        preselection_observation_receipt_hash(&attestation.signed_exit_receipt)
            .unwrap()
            .to_vec();
    let wrong_nested = resign_attestation(outer, &attestation, &control_key);
    assert_forwarded_rejected_without_replay(&wrong_nested, &encoded_request);

    let (outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
    attestation.exit_receipt_hash[0] ^= 1;
    let wrong_hash = resign_attestation(outer, &attestation, &control_key);
    assert_forwarded_rejected_without_replay(&wrong_hash, &encoded_request);

    let (outer, mut attestation) = decode_forwarded_attestation(&signed_attestation);
    let mut wrong_type: SignedEnvelope = decode_canonical(
        &attestation.signed_exit_receipt,
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap();
    wrong_type.message_type = ControlMessageType::NodeAdvertisement as i32;
    attestation.signed_exit_receipt = adversarially_resign_envelope(wrong_type, &exit_key);
    attestation.exit_receipt_hash = receipt_hash_for_test(&attestation.signed_exit_receipt);
    let wrong_type = resign_attestation(outer, &attestation, &control_key);
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_forwarded_preselection_transcript(
            &wrong_type,
            &encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidField(
            "forwarded observation signed_exit_receipt"
        ))
    ));
    assert!(cache.is_empty());
}

#[test]
fn forwarded_prefix_is_public_family_exact_ipv4_24_or_ipv6_48() {
    for (family, prefix) in [
        (ObservationAddressFamily::Ipv4, vec![8, 8, 4]),
        (
            ObservationAddressFamily::Ipv6,
            vec![0x20, 0x01, 0x48, 0x60, 0, 0],
        ),
    ] {
        let (request, _, signed, _, _) = forwarded_preselection_fixture_with_prefix(family, prefix);
        let mut cache = ReplayCache::new(8).unwrap();
        verify_forwarded_preselection_transcript(
            &signed,
            &encode_preselection_request(&request),
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        )
        .unwrap();
        assert_eq!(cache.len(), 2);
    }

    for prefix in [vec![8, 8], vec![8, 8, 4, 4], vec![10, 0, 0]] {
        assert_forwarded_prefix_invalid(ObservationAddressFamily::Ipv4, prefix);
    }
    for prefix in [
        vec![0x20, 0x01, 0x48, 0x60, 0],
        vec![0x20, 0x01, 0x48, 0x60, 0, 0, 0],
        vec![0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        vec![0; 6],
    ] {
        assert_forwarded_prefix_invalid(ObservationAddressFamily::Ipv6, prefix);
    }

    let (_, _, signed, _, _) = forwarded_preselection_fixture();
    let (_, mut attestation) = decode_forwarded_attestation(&signed);
    attestation.upstream_network_prefix = Some(ObservationNetworkPrefix {
        address_family: ObservationAddressFamily::Ipv6 as i32,
        network_prefix: vec![0x20, 0x01, 0x48, 0x60, 0, 0],
    });
    assert!(matches!(
        attestation.validate(),
        Err(ProtocolError::InvalidField(
            "forwarded observation address_family"
        ))
    ));

    let (request, _, signed, control_key, _) = forwarded_preselection_fixture();
    let (outer, mut attestation) = decode_forwarded_attestation(&signed);
    attestation
        .upstream_network_prefix
        .as_mut()
        .unwrap()
        .network_prefix = vec![10, 0, 0];
    let signed = resign_attestation(outer, &attestation, &control_key);
    assert_forwarded_rejected_without_replay(&signed, &encode_preselection_request(&request));

    let (request, _, signed, control_key, _) = forwarded_preselection_fixture_with_prefix(
        ObservationAddressFamily::Ipv6,
        vec![0x20, 0x01, 0x48, 0x60, 0, 0],
    );
    let (outer, mut attestation) = decode_forwarded_attestation(&signed);
    attestation
        .upstream_network_prefix
        .as_mut()
        .unwrap()
        .network_prefix
        .pop();
    let signed = resign_attestation(outer, &attestation, &control_key);
    assert_forwarded_rejected_without_replay(&signed, &encode_preselection_request(&request));

    let (request, _, signed, control_key, _) = forwarded_preselection_fixture();
    let (outer, mut attestation) = decode_forwarded_attestation(&signed);
    attestation.upstream_network_prefix = Some(ObservationNetworkPrefix {
        address_family: ObservationAddressFamily::Ipv6 as i32,
        network_prefix: vec![0x20, 0x01, 0x48, 0x60, 0, 0],
    });
    let signed = resign_attestation(outer, &attestation, &control_key);
    assert_forwarded_rejected_without_replay(&signed, &encode_preselection_request(&request));
}

fn assert_forwarded_prefix_invalid(family: ObservationAddressFamily, network_prefix: Vec<u8>) {
    let (_, _, signed, _, _) = forwarded_preselection_fixture_with_prefix(
        family,
        match family {
            ObservationAddressFamily::Ipv4 => vec![8, 8, 4],
            ObservationAddressFamily::Ipv6 => vec![0x20, 0x01, 0x48, 0x60, 0, 0],
            ObservationAddressFamily::Unspecified => unreachable!(),
        },
    );
    let (_, mut attestation) = decode_forwarded_attestation(&signed);
    attestation
        .upstream_network_prefix
        .as_mut()
        .unwrap()
        .network_prefix = network_prefix;
    assert!(matches!(
        attestation.validate(),
        Err(ProtocolError::InvalidField("observation network prefix"))
    ));
}

fn assert_forwarded_rejected_without_replay(encoded: &[u8], encoded_request: &[u8]) {
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(
        verify_forwarded_preselection_transcript(
            encoded,
            encoded_request,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        )
        .is_err()
    );
    assert!(cache.is_empty());
}

fn assert_direct_request_mutation_rejected(
    mutate: impl FnOnce(&mut PreselectionObservationRequest),
) {
    let (mut request, signed_receipt) = direct_preselection_fixture();
    mutate(&mut request);
    request.validate().unwrap();
    let mut cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_direct_preselection_transcript(
            &signed_receipt,
            &encode_preselection_request(&request),
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::InvalidField(
            "direct preselection observation binding"
        ))
    ));
    assert!(cache.is_empty());
}

#[test]
fn preselection_request_and_receipt_digests_are_domain_separated_and_exact() {
    let (request, signed_receipt) = direct_preselection_fixture();
    let encoded_request = encode_preselection_request(&request);
    let request_hash = preselection_observation_request_hash(&encoded_request).unwrap();
    let receipt_hash = preselection_observation_receipt_hash(&signed_receipt).unwrap();
    assert_eq!(
        request_hash,
        [
            216, 142, 65, 204, 34, 124, 56, 151, 79, 130, 129, 47, 88, 237, 192, 161, 21, 192, 95,
            215, 53, 213, 137, 125, 66, 59, 175, 163, 197, 123, 49, 217,
        ]
    );
    assert_eq!(
        receipt_hash,
        [
            22, 105, 28, 104, 225, 157, 217, 134, 82, 157, 168, 161, 61, 100, 157, 247, 35, 206,
            110, 37, 165, 66, 129, 214, 26, 131, 90, 9, 35, 175, 211, 127,
        ]
    );

    let mut changed_request = request;
    changed_request.challenge[0] ^= 1;
    assert_ne!(
        preselection_observation_request_hash(&encode_preselection_request(&changed_request))
            .unwrap(),
        request_hash
    );
    let mut changed_receipt = signed_receipt;
    *changed_receipt.last_mut().unwrap() ^= 1;
    assert_ne!(
        preselection_observation_receipt_hash(&changed_receipt).unwrap(),
        receipt_hash
    );
}

#[derive(Clone, PartialEq, Message)]
struct EnvelopeSignatureInputForTest {
    #[prost(uint32, tag = "1")]
    protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    sender_public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    timestamp_ms: u64,
    #[prost(uint64, tag = "5")]
    expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    nonce: Vec<u8>,
    #[prost(int32, tag = "7")]
    message_type: i32,
    #[prost(bytes = "vec", tag = "8")]
    payload_hash: Vec<u8>,
}

fn adversarially_resign_envelope(mut envelope: SignedEnvelope, key: &SigningKey) -> Vec<u8> {
    envelope.payload_hash = Sha256::digest(&envelope.payload).to_vec();
    let input = EnvelopeSignatureInputForTest {
        protocol_version: envelope.protocol_version,
        sender_id: envelope.sender_id.clone(),
        sender_public_key: envelope.sender_public_key.clone(),
        timestamp_ms: envelope.timestamp_ms,
        expires_at_ms: envelope.expires_at_ms,
        nonce: envelope.nonce.clone(),
        message_type: envelope.message_type,
        payload_hash: envelope.payload_hash.clone(),
    };
    let encoded_input = encode_canonical(&input, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let mut signed_input = b"volparossa/control-envelope/v4\0".to_vec();
    signed_input.extend_from_slice(&encoded_input);
    envelope.signature = key.sign(&signed_input).to_bytes().to_vec();
    encode_canonical(&envelope, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap()
}

fn decode_forwarded_attestation(
    encoded: &[u8],
) -> (SignedEnvelope, ForwardedPreselectionAttestation) {
    let outer =
        decode_canonical::<SignedEnvelope>(encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE)
            .unwrap();
    let attestation = decode_canonical(&outer.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    (outer, attestation)
}

fn resign_attestation(
    mut outer: SignedEnvelope,
    attestation: &ForwardedPreselectionAttestation,
    control_key: &SigningKey,
) -> Vec<u8> {
    outer.payload = encode_canonical(attestation, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    adversarially_resign_envelope(outer, control_key)
}

fn receipt_hash_for_test(encoded: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"volparossa/preselection-observation-receipt/v4\0");
    hasher.update(u32::try_from(encoded.len()).unwrap().to_be_bytes());
    hasher.update(encoded);
    hasher.finalize().to_vec()
}

fn item_body<'a>(source: &'a str, declaration: &str) -> &'a str {
    source
        .split_once(declaration)
        .unwrap_or_else(|| panic!("missing declaration: {declaration}"))
        .1
        .split_once("\n}")
        .unwrap_or_else(|| panic!("unterminated declaration: {declaration}"))
        .0
}

fn assert_preselection_message_type_tags(schema: &str, messages: &str) {
    let schema_enum = item_body(schema, "enum ControlMessageType {");
    let rust_enum = item_body(messages, "pub enum ControlMessageType {");
    let names = [
        "UNSPECIFIED",
        "NODE_ADVERTISEMENT",
        "EXIT_RESERVATION",
        "RELAY_AUTHORIZATION",
        "RELAY_RESERVATION",
        "OPEN_TCP",
        "UDP_FLOW_AUTHORIZATION",
        "EXIT_CAPACITY_HOLD_REQUEST",
        "RELAY_RESERVATION_REQUEST",
        "EXIT_RESERVATION_CONFIRMATION",
        "CLIENT_SESSION_CAPABILITY",
        "EXIT_CAPACITY_HOLD",
        "RELAY_PROBE_PERMIT_REQUEST",
        "RELAY_PROBE_PERMIT",
        "RELAY_PROBE_RESULT",
        "EXIT_RESERVATION_FINALIZE_REQUEST",
        "EXIT_CONFIRMATION_RECEIPT",
        "PRESELECTION_OBSERVATION_RECEIPT",
        "FORWARDED_PRESELECTION_ATTESTATION",
    ];
    let rust_names = [
        "Unspecified",
        "NodeAdvertisement",
        "ExitReservation",
        "RelayAuthorization",
        "RelayReservation",
        "OpenTcp",
        "UdpFlowAuthorization",
        "ExitCapacityHoldRequest",
        "RelayReservationRequest",
        "ExitReservationConfirmation",
        "ClientSessionCapability",
        "ExitCapacityHold",
        "RelayProbePermitRequest",
        "RelayProbePermit",
        "RelayProbeResult",
        "ExitReservationFinalizeRequest",
        "ExitConfirmationReceipt",
        "PreselectionObservationReceipt",
        "ForwardedPreselectionAttestation",
    ];
    assert_eq!(schema_enum.matches(';').count(), names.len());
    assert_eq!(
        rust_enum
            .lines()
            .filter(|line| line.trim_end().ends_with(','))
            .count(),
        rust_names.len()
    );
    for (tag, (schema_name, rust_name)) in names.iter().zip(rust_names).enumerate() {
        assert!(schema_enum.contains(&format!("CONTROL_MESSAGE_TYPE_{schema_name} = {tag};")));
        assert!(rust_enum.contains(&format!("{rust_name} = {tag},")));
    }
    let rust = include_str!("../src/preselection_observation.rs");
    assert_small_enum(
        schema,
        rust,
        "PreselectionObservationRole",
        "PRESELECTION_OBSERVATION_ROLE_",
        ["UNSPECIFIED", "RELAY", "EXIT"],
        ["Unspecified", "Relay", "Exit"],
    );
    assert_small_enum(
        schema,
        rust,
        "ObservationAddressFamily",
        "OBSERVATION_ADDRESS_FAMILY_",
        ["UNSPECIFIED", "IPV4", "IPV6"],
        ["Unspecified", "Ipv4", "Ipv6"],
    );
}

fn assert_small_enum(
    schema: &str,
    rust: &str,
    name: &str,
    prefix: &str,
    schema_names: [&str; 3],
    rust_names: [&str; 3],
) {
    let schema_enum = item_body(schema, &format!("enum {name} {{"));
    let rust_enum = item_body(rust, &format!("pub enum {name} {{"));
    assert_eq!(schema_enum.matches(';').count(), 3);
    assert_eq!(
        rust_enum
            .lines()
            .filter(|line| line.trim_end().ends_with(','))
            .count(),
        3
    );
    for (tag, (schema_name, rust_name)) in schema_names.iter().zip(rust_names).enumerate() {
        assert!(schema_enum.contains(&format!("{prefix}{schema_name} = {tag};")));
        assert!(rust_enum.contains(&format!("{rust_name} = {tag},")));
    }
}

fn assert_preselection_schema_fields(schema: &str) {
    let rust = include_str!("../src/preselection_observation.rs");
    assert_preselection_actor_scope_schema(rust, schema);
    assert_preselection_request_receipt_schema(rust, schema);
    assert_preselection_prefix_attestation_schema(rust, schema);
}

fn assert_preselection_actor_scope_schema(rust: &str, schema: &str) {
    assert_schema_message(
        rust,
        schema,
        "PreselectionActorBinding",
        &[
            (
                "#[prost(bytes = \"vec\", tag = \"1\")]",
                "pub node_id: Vec<u8>,",
                "bytes node_id = 1;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"2\")]",
                "pub peer_id: Vec<u8>,",
                "bytes peer_id = 2;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"3\")]",
                "pub public_key: Vec<u8>,",
                "bytes public_key = 3;",
            ),
            (
                "#[prost(uint64, tag = \"4\")]",
                "pub advertisement_sequence: u64,",
                "uint64 advertisement_sequence = 4;",
            ),
            (
                "#[prost(uint64, tag = \"5\")]",
                "pub advertisement_expires_at_ms: u64,",
                "uint64 advertisement_expires_at_ms = 5;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"6\")]",
                "pub advertisement_payload_hash: Vec<u8>,",
                "bytes advertisement_payload_hash = 6;",
            ),
            (
                "#[prost(uint64, tag = \"7\")]",
                "pub capability_expires_at_ms: u64,",
                "uint64 capability_expires_at_ms = 7;",
            ),
        ],
    );
    assert_schema_message(
        rust,
        schema,
        "PreselectionObservationScope",
        &[
            (
                "#[prost(enumeration = \"PreselectionObservationRole\", tag = \"1\")]",
                "pub role: i32,",
                "PreselectionObservationRole role = 1;",
            ),
            (
                "#[prost(enumeration = \"Transport\", tag = \"2\")]",
                "pub transport: i32,",
                "Transport transport = 2;",
            ),
            (
                "#[prost(enumeration = \"ObservationAddressFamily\", tag = \"3\")]",
                "pub address_family: i32,",
                "ObservationAddressFamily address_family = 3;",
            ),
            (
                "#[prost(uint64, tag = \"4\")]",
                "pub policy_version: u64,",
                "uint64 policy_version = 4;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"5\")]",
                "pub policy_hash: Vec<u8>,",
                "bytes policy_hash = 5;",
            ),
            (
                "#[prost(uint64, tag = \"6\")]",
                "pub policy_expires_at_ms: u64,",
                "uint64 policy_expires_at_ms = 6;",
            ),
        ],
    );
}

fn assert_preselection_request_receipt_schema(rust: &str, schema: &str) {
    assert_schema_message(
        rust,
        schema,
        "PreselectionObservationRequest",
        &[
            (
                "#[prost(uint32, tag = \"1\")]",
                "pub protocol_version: u32,",
                "uint32 protocol_version = 1;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"2\")]",
                "pub challenge: Vec<u8>,",
                "bytes challenge = 2;",
            ),
            (
                "#[prost(message, optional, tag = \"3\")]",
                "pub actor: Option<PreselectionActorBinding>,",
                "PreselectionActorBinding actor = 3;",
            ),
            (
                "#[prost(message, optional, tag = \"4\")]",
                "pub scope: Option<PreselectionObservationScope>,",
                "PreselectionObservationScope scope = 4;",
            ),
            (
                "#[prost(message, optional, tag = \"5\")]",
                "pub forwarded_control: Option<PreselectionActorBinding>,",
                "PreselectionActorBinding forwarded_control = 5;",
            ),
            (
                "#[prost(uint64, tag = \"6\")]",
                "pub created_at_ms: u64,",
                "uint64 created_at_ms = 6;",
            ),
            (
                "#[prost(uint64, tag = \"7\")]",
                "pub expires_at_ms: u64,",
                "uint64 expires_at_ms = 7;",
            ),
        ],
    );
    assert_schema_message(
        rust,
        schema,
        "PreselectionObservationReceipt",
        &[
            (
                "#[prost(bytes = \"vec\", tag = \"1\")]",
                "pub request_hash: Vec<u8>,",
                "bytes request_hash = 1;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"2\")]",
                "pub challenge: Vec<u8>,",
                "bytes challenge = 2;",
            ),
            (
                "#[prost(message, optional, tag = \"3\")]",
                "pub actor: Option<PreselectionActorBinding>,",
                "PreselectionActorBinding actor = 3;",
            ),
            (
                "#[prost(message, optional, tag = \"4\")]",
                "pub scope: Option<PreselectionObservationScope>,",
                "PreselectionObservationScope scope = 4;",
            ),
            (
                "#[prost(uint64, tag = \"5\")]",
                "pub observed_at_ms: u64,",
                "uint64 observed_at_ms = 5;",
            ),
            (
                "#[prost(uint64, tag = \"6\")]",
                "pub valid_until_ms: u64,",
                "uint64 valid_until_ms = 6;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"7\")]",
                "pub nonce: Vec<u8>,",
                "bytes nonce = 7;",
            ),
        ],
    );
}

fn assert_preselection_prefix_attestation_schema(rust: &str, schema: &str) {
    assert_schema_message(
        rust,
        schema,
        "ObservationNetworkPrefix",
        &[
            (
                "#[prost(enumeration = \"ObservationAddressFamily\", tag = \"1\")]",
                "pub address_family: i32,",
                "ObservationAddressFamily address_family = 1;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"2\")]",
                "pub network_prefix: Vec<u8>,",
                "bytes network_prefix = 2;",
            ),
        ],
    );
    assert_schema_message(
        rust,
        schema,
        "ForwardedPreselectionAttestation",
        &[
            (
                "#[prost(bytes = \"vec\", tag = \"1\")]",
                "pub request_hash: Vec<u8>,",
                "bytes request_hash = 1;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"2\")]",
                "pub challenge: Vec<u8>,",
                "bytes challenge = 2;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"3\")]",
                "pub signed_exit_receipt: Vec<u8>,",
                "bytes signed_exit_receipt = 3;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"4\")]",
                "pub exit_receipt_hash: Vec<u8>,",
                "bytes exit_receipt_hash = 4;",
            ),
            (
                "#[prost(message, optional, tag = \"5\")]",
                "pub control: Option<PreselectionActorBinding>,",
                "PreselectionActorBinding control = 5;",
            ),
            (
                "#[prost(message, optional, tag = \"6\")]",
                "pub exit: Option<PreselectionActorBinding>,",
                "PreselectionActorBinding exit = 6;",
            ),
            (
                "#[prost(message, optional, tag = \"7\")]",
                "pub scope: Option<PreselectionObservationScope>,",
                "PreselectionObservationScope scope = 7;",
            ),
            (
                "#[prost(message, optional, tag = \"8\")]",
                "pub upstream_network_prefix: Option<ObservationNetworkPrefix>,",
                "ObservationNetworkPrefix upstream_network_prefix = 8;",
            ),
            (
                "#[prost(uint64, tag = \"9\")]",
                "pub observed_at_ms: u64,",
                "uint64 observed_at_ms = 9;",
            ),
            (
                "#[prost(uint64, tag = \"10\")]",
                "pub valid_until_ms: u64,",
                "uint64 valid_until_ms = 10;",
            ),
            (
                "#[prost(bytes = \"vec\", tag = \"11\")]",
                "pub nonce: Vec<u8>,",
                "bytes nonce = 11;",
            ),
        ],
    );
}

fn assert_schema_message(rust: &str, schema: &str, name: &str, fields: &[(&str, &str, &str)]) {
    let rust_body = item_body(rust, &format!("pub struct {name} {{"));
    let schema_body = item_body(schema, &format!("message {name} {{"));
    assert_eq!(rust_body.matches("#[prost(").count(), fields.len());
    assert_eq!(
        rust_body
            .lines()
            .filter(|line| line.trim_start().starts_with("pub "))
            .count(),
        fields.len()
    );
    assert_eq!(
        schema_body
            .lines()
            .filter(|line| line.trim_end().ends_with(';'))
            .count(),
        fields.len()
    );
    for (attribute, rust_field, schema_field) in fields {
        let rust_pair = format!("{attribute}\n    {rust_field}");
        assert!(
            rust_body.contains(&rust_pair),
            "missing Rust tag/field pair: {rust_pair}"
        );
        assert!(
            schema_body.contains(schema_field),
            "missing proto field: {schema_field}"
        );
    }
}

fn assert_preselection_product_surface() {
    let source = include_str!("../src/preselection_observation.rs");
    let test_marker = "\n#[cfg(test)]\nmod tests {";
    assert_eq!(source.matches(test_marker).count(), 1);
    let product = source.split_once(test_marker).unwrap().0;
    for declaration in [
        "pub struct PreselectionActorBinding",
        "pub struct PreselectionObservationScope",
        "pub struct PreselectionObservationRequest",
        "pub struct PreselectionObservationReceipt",
        "pub struct ObservationNetworkPrefix",
        "pub struct ForwardedPreselectionAttestation",
    ] {
        let body = item_body(product, declaration);
        for forbidden in [
            "capacity_mbps",
            "capacity_ceiling",
            "capacity_",
            "pub capacity",
            "reserved_",
            "offer",
            "hold_id",
            "hold_",
            "pub hold",
            "permit",
            "authority",
            "reservation_id",
            "reservation_",
            "pub reservation",
            "route_",
            "pub route:",
            "route_context",
            "session_id",
            "pub session",
            "batch_id",
            "pub batch",
            "client_id",
            "pub client",
            "path_id",
            "path_",
            "pub path",
            "endpoint",
            "multiaddr",
            "listen_port",
            "pub port:",
            "source_port",
            "remote_port",
            "destination",
            "hostname",
            "history",
            "underlay",
            "socket",
            "flow_id",
            "wireguard",
            "up_mbps",
            "down_mbps",
            "raw_origin",
            "origin_ip",
            "raw_ip",
            "IpAddr",
        ] {
            assert!(
                !body.contains(forbidden),
                "{declaration} leaked {forbidden}"
            );
        }
    }
    for forbidden in [
        "FreshPeerEvidence",
        "FreshEvidenceBatch",
        "CandidateEvidence",
        "into_fresh",
        "impl From<",
        "impl TryFrom<",
        "impl ControlPayload for PreselectionObservationRequest",
        "impl ControlPayload for PreselectionActorBinding",
        "impl ControlPayload for PreselectionObservationScope",
        "impl ControlPayload for ObservationNetworkPrefix",
        "ControlMessageType::PreselectionObservationRequest",
        "std::net::",
        "IpAddr",
        "Ipv4Addr",
        "Ipv6Addr",
        "is_public_routable_ip",
        "ObservedNetworkPrefix::from_origin",
    ] {
        assert!(!product.contains(forbidden));
    }
    assert_eq!(
        product.matches("ObservedNetworkPrefix::ipv4_24(").count(),
        1
    );
    assert_eq!(
        product.matches("ObservedNetworkPrefix::ipv6_48(").count(),
        1
    );
    assert_eq!(product.matches("prefix.is_public_routable()").count(), 1);
    assert_opaque_transcript_surface(product);
    assert_preselection_callerlessness(product);
    assert_post_inner_replay_surface(product);
}

fn assert_opaque_transcript_surface(product: &str) {
    let after_attestation = product
        .split_once("pub struct ForwardedPreselectionAttestation")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .1;
    let opaque = after_attestation
        .split_once("impl PreselectionActorBinding")
        .unwrap()
        .0;
    assert!(!opaque.contains("derive("));
    assert_opaque_transcript_type_counts(product);
    let bodies = assert_opaque_transcript_field_shapes(product);
    assert_opaque_transcript_bodies_are_sanitized(&bodies);
    for forbidden in ["serde", "Serialize", "Deserialize"] {
        assert!(!product.contains(forbidden));
    }
    for forbidden in [
        "into_parts",
        "decompose",
        "as_request",
        "receipt(&self",
        "attestation(&self",
        "Serialize",
        "Deserialize",
    ] {
        assert!(!opaque.contains(forbidden));
    }
}

fn assert_opaque_transcript_type_counts(product: &str) {
    for (name, count) in [
        ("VerifiedDirectPreselectionTranscript", 5),
        ("VerifiedForwardedPreselectionTranscript", 5),
        ("BoundDirectPreselectionTranscript", 3),
        ("BoundForwardedPreselectionTranscript", 3),
    ] {
        assert_eq!(product.matches(name).count(), count);
        assert_eq!(product.matches(&format!("pub struct {name} {{")).count(), 1);
        assert!(!item_body(product, &format!("pub struct {name} {{")).contains("\n    pub "));
        assert!(
            !product
                .lines()
                .any(|line| { line.trim_start().starts_with("impl") && line.contains(name) })
        );
    }
}

fn assert_opaque_transcript_field_shapes(product: &str) -> [&str; 4] {
    let direct_body = item_body(product, "pub struct VerifiedDirectPreselectionTranscript {");
    let direct_fields: Vec<_> = direct_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        direct_fields,
        [
            "request: PreselectionObservationRequest,",
            "_receipt: VerifiedControlMessage<PreselectionObservationReceipt>,",
        ]
    );
    let forwarded_body = item_body(
        product,
        "pub struct VerifiedForwardedPreselectionTranscript {",
    );
    let forwarded_fields: Vec<_> = forwarded_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        forwarded_fields,
        [
            "request: PreselectionObservationRequest,",
            "_attestation: VerifiedControlMessage<ForwardedPreselectionAttestation>,",
            "_exit_receipt: VerifiedControlMessage<PreselectionObservationReceipt>,",
        ]
    );
    let bound_direct_body = item_body(product, "pub struct BoundDirectPreselectionTranscript {");
    assert_eq!(
        bound_direct_body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>(),
        ["_transcript: VerifiedDirectPreselectionTranscript,"]
    );
    let bound_forwarded_body =
        item_body(product, "pub struct BoundForwardedPreselectionTranscript {");
    assert_eq!(
        bound_forwarded_body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>(),
        ["_transcript: VerifiedForwardedPreselectionTranscript,"]
    );
    [
        direct_body,
        forwarded_body,
        bound_direct_body,
        bound_forwarded_body,
    ]
}

fn assert_opaque_transcript_bodies_are_sanitized(bodies: &[&str]) {
    for body in bodies {
        for forbidden in [
            "IpAddr",
            "SocketAddr",
            "endpoint",
            "address",
            "origin",
            "port",
            "capacity",
            "hold",
            "permit",
            "authority",
            "reservation",
            "route",
            "session",
            "batch",
            "path",
            "client",
            "serde",
            "Serialize",
            "Deserialize",
        ] {
            assert!(
                !body.contains(forbidden),
                "opaque transcript leaked {forbidden}"
            );
        }
    }
}

fn assert_preselection_callerlessness(product: &str) {
    let direct_name = ["verify_direct_preselection_", "transcript"].concat();
    let forwarded_name = ["verify_forwarded_preselection_", "transcript"].concat();
    let direct = format!("{direct_name}(");
    let forwarded = format!("{forwarded_name}(");
    assert_eq!(product.matches(&direct).count(), 1);
    assert_eq!(product.matches(&forwarded).count(), 1);
    assert_protocol_preselection_surface(&direct_name, &forwarded_name);
    assert_a1_owner_preselection_calls(&direct_name, &forwarded_name);
    assert_runtime_preselection_callerlessness(&direct, &forwarded);
    assert_no_preselection_producer_surface(product);
}

fn assert_protocol_preselection_surface(direct_name: &str, forwarded_name: &str) {
    let protocol_implementation_siblings = [
        include_str!("../src/canonical.rs"),
        include_str!("../src/envelope.rs"),
        include_str!("../src/messages.rs"),
        include_str!("../src/reservation_requests.rs"),
    ]
    .concat();
    assert_eq!(
        protocol_implementation_siblings
            .matches(&direct_name)
            .count(),
        0
    );
    assert_eq!(
        protocol_implementation_siblings
            .matches(&forwarded_name)
            .count(),
        0
    );
    let protocol_exports = include_str!("../src/lib.rs");
    for symbol in [
        direct_name,
        forwarded_name,
        "VerifiedDirectPreselectionTranscript",
        "VerifiedForwardedPreselectionTranscript",
        "BoundDirectPreselectionTranscript",
        "BoundForwardedPreselectionTranscript",
        "consume_direct_preselection_transcript",
        "consume_forwarded_preselection_transcript",
    ] {
        assert_eq!(protocol_exports.matches(symbol).count(), 1);
    }
}

fn assert_a1_owner_preselection_calls(direct_name: &str, forwarded_name: &str) {
    let a1_owner = include_str!("../../volparossa-agent/src/discovery/preselection_observation.rs");
    let owner_test_marker = "\n#[cfg(test)]\nmod tests {";
    assert_eq!(a1_owner.matches(owner_test_marker).count(), 1);
    let a1_owner = a1_owner.split_once(owner_test_marker).unwrap().0;
    for symbol in [
        direct_name,
        forwarded_name,
        "consume_direct_preselection_transcript",
        "consume_forwarded_preselection_transcript",
    ] {
        assert_eq!(a1_owner.matches(symbol).count(), 2);
    }
}

fn assert_runtime_preselection_callerlessness(direct: &str, forwarded: &str) {
    let runtime = [
        include_str!("../../volparossa-agent/src/control.rs"),
        include_str!("../../volparossa-agent/src/advertisement.rs"),
        include_str!("../../volparossa-agent/src/discovery.rs"),
        include_str!("../../volparossa-agent/src/endpoint_leases.rs"),
        include_str!("../../volparossa-agent/src/helper_v3.rs"),
        include_str!("../../volparossa-agent/src/lib.rs"),
        include_str!("../../volparossa-agent/src/main.rs"),
        include_str!("../../volparossa-agent/src/paths.rs"),
        include_str!("../../volparossa-agent/src/policy.rs"),
        include_str!("../../volparossa-agent/src/roles.rs"),
        include_str!("../../volparossa-agent/src/route_setup.rs"),
        include_str!("../../volparossa-agent/src/route_setup/retirement.rs"),
        include_str!("../../volparossa-agent/src/route_setup/selection_bridge.rs"),
        include_str!("../../volparossa-agent/src/secret.rs"),
        include_str!("../../volparossa-agent/src/state.rs"),
        include_str!("../../volparossa-discovery/src/advertisement_budget.rs"),
        include_str!("../../volparossa-discovery/src/advertisement_tests.rs"),
        include_str!("../../volparossa-discovery/src/advertisements.rs"),
        include_str!("../../volparossa-discovery/src/forwarding.rs"),
        include_str!("../../volparossa-discovery/src/lib.rs"),
        include_str!("../../volparossa-discovery/src/peerlink.rs"),
        include_str!("../../volparossa-discovery/src/reservations.rs"),
        include_str!("../../volparossa-exit/src/lib.rs"),
        include_str!("../../volparossa-exit/src/reservation_v4.rs"),
        include_str!("../../volparossa-relay/src/lib.rs"),
    ]
    .concat();
    assert_eq!(runtime.matches(&direct).count(), 0);
    assert_eq!(runtime.matches(&forwarded).count(), 0);
    for identifier in [
        "PreselectionObservationRequest",
        "PreselectionObservationReceipt",
        "ForwardedPreselectionAttestation",
    ] {
        assert!(
            !contains_exact_identifier(&runtime, identifier),
            "runtime caller surface: {identifier}"
        );
    }
    for symbol in [
        "verify_direct_preselection_transcript",
        "verify_forwarded_preselection_transcript",
        "verify_control_message::<Preselection",
    ] {
        assert!(
            !runtime.contains(symbol),
            "runtime caller surface: {symbol}"
        );
    }
    assert_discovery_preselection_wire_shell();
}

fn contains_exact_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(offset, _)| {
        let before = source[..offset].bytes().next_back();
        let after = source[offset + identifier.len()..].bytes().next();
        !before.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && !after.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn assert_discovery_preselection_wire_shell() {
    let source = include_str!("../../volparossa-discovery/src/preselection_wire.rs");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("preselection wire production source");
    for expected in [
        "PreselectionObservationRequest",
        "PreselectionObservationReceipt",
        "ForwardedPreselectionAttestation",
        "decode_canonical",
        ".validate()",
        ".validate_envelope(&envelope)",
        "take(limit)",
    ] {
        assert!(
            production.contains(expected),
            "missing wire shell {expected}"
        );
    }
    for forbidden in [
        "verify_direct_preselection_transcript(",
        "verify_forwarded_preselection_transcript(",
        "consume_direct_preselection_transcript(",
        "consume_forwarded_preselection_transcript(",
        "verify_control_message::<Preselection",
        "sign_control_message",
        "SigningKey",
        "generate_nonce(",
        "ReplayCache",
        "send_request(",
        "send_response(",
        "HashMap",
        "BoundPreselectionTranscriptBatch",
        "ConnectionWitness",
        "FreshPeerEvidence",
        "FreshEvidenceBatch",
        "CandidateEvidence",
        "RouteSessionAuthority",
        "ReservationSession",
    ] {
        assert!(
            !production.contains(forbidden),
            "wire shell caller/authority surface: {forbidden}"
        );
    }
}

#[test]
fn exact_identifier_guard_ignores_wrapper_prefixes_and_suffixes() {
    assert!(contains_exact_identifier(
        "use PreselectionObservationRequest;",
        "PreselectionObservationRequest"
    ));
    assert!(!contains_exact_identifier(
        "ClientPreselectionObservationRequest",
        "PreselectionObservationRequest"
    ));
    assert!(!contains_exact_identifier(
        "PreselectionObservationRequestWire",
        "PreselectionObservationRequest"
    ));
}

fn assert_no_preselection_producer_surface(product: &str) {
    for forbidden in [
        "sign_control_message",
        "ed25519_dalek",
        "OsRng",
        "getrandom",
        "fill_bytes",
        "rand::",
        "rand_core",
        "SigningKey",
        "generate_nonce(",
        "async fn ",
        "tokio::",
        "libp2p",
        "RouteSessionAuthority",
        "ReservationSession",
        "pub fn handle_",
        "spawn(",
    ] {
        assert!(
            !product.contains(forbidden),
            "unexpected producer surface: {forbidden}"
        );
    }
}

fn assert_post_inner_replay_surface(product: &str) {
    let post_inner = product
        .split_once("let inner_sender = *exit_receipt.sender_id();")
        .unwrap()
        .1
        .split_once("Ok(VerifiedForwardedPreselectionTranscript")
        .unwrap()
        .0;
    let (before_pair, after_pair) = post_inner.split_once("rollback_pair_inserted(").unwrap();
    assert!(!before_pair.contains('?'));
    assert!(!before_pair.contains("return"));
    for forbidden in ["unwrap(", "expect(", "panic!("] {
        assert!(!post_inner.contains(forbidden));
    }
    assert_eq!(after_pair.matches("rollback_pair_inserted(").count(), 0);
    assert_eq!(after_pair.matches("?;").count(), 1);
    assert_eq!(after_pair.matches("return Err(").count(), 1);
    let pair = product
        .split_once("fn rollback_pair_inserted(")
        .unwrap()
        .1
        .split_once("fn validate_actor_envelope(")
        .unwrap()
        .0;
    let inner = pair.find("rollback(inner.0, inner.1)").unwrap();
    let outer = pair.find("rollback(outer.0, outer.1)").unwrap();
    assert!(inner < outer);
    assert!(!pair[..outer].contains('?'));
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn node_id(key: &SigningKey) -> Vec<u8> {
    node_id_from_public_key(&key.verifying_key().to_bytes()).to_vec()
}

fn preselection_actor(
    signing_key: &SigningKey,
    peer_byte: u8,
    advertisement_expiry: u64,
    capability_expiry: u64,
) -> PreselectionActorBinding {
    PreselectionActorBinding {
        node_id: node_id(signing_key),
        peer_id: vec![peer_byte; 38],
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        advertisement_sequence: u64::from(peer_byte),
        advertisement_expires_at_ms: advertisement_expiry,
        advertisement_payload_hash: vec![peer_byte.wrapping_add(1); 32],
        capability_expires_at_ms: capability_expiry,
    }
}

fn preselection_scope(role: PreselectionObservationRole) -> PreselectionObservationScope {
    PreselectionObservationScope {
        role: role as i32,
        transport: Transport::TcpMptcp as i32,
        address_family: ObservationAddressFamily::Ipv4 as i32,
        policy_version: 7,
        policy_hash: vec![70; 32],
        policy_expires_at_ms: NOW + 60_000,
    }
}

fn preselection_request(
    role: PreselectionObservationRole,
    actor: PreselectionActorBinding,
    forwarded_control: Option<PreselectionActorBinding>,
    challenge_byte: u8,
) -> PreselectionObservationRequest {
    PreselectionObservationRequest {
        protocol_version: PROTOCOL_VERSION,
        challenge: vec![challenge_byte; 32],
        actor: Some(actor),
        scope: Some(preselection_scope(role)),
        forwarded_control,
        created_at_ms: NOW,
        expires_at_ms: NOW + 4_000,
    }
}

fn encode_preselection_request(request: &PreselectionObservationRequest) -> Vec<u8> {
    encode_canonical(request, 4 * 1024).unwrap()
}

fn signed_preselection_receipt(
    request: &PreselectionObservationRequest,
    signing_key: &SigningKey,
    observed_at_ms: u64,
    valid_until_ms: u64,
    nonce_byte: u8,
) -> Vec<u8> {
    let encoded_request = encode_preselection_request(request);
    let receipt = PreselectionObservationReceipt {
        request_hash: preselection_observation_request_hash(&encoded_request)
            .unwrap()
            .to_vec(),
        challenge: request.challenge.clone(),
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        observed_at_ms,
        valid_until_ms,
        nonce: vec![nonce_byte; 32],
    };
    sign_control_message(
        &receipt,
        signing_key,
        observed_at_ms,
        valid_until_ms,
        [nonce_byte; 32],
        TimePolicy::default(),
    )
    .unwrap()
}

fn direct_preselection_fixture() -> (PreselectionObservationRequest, Vec<u8>) {
    let relay_key = key(80);
    let actor = preselection_actor(&relay_key, 81, NOW + 60_000, NOW + 60_000);
    let request = preselection_request(PreselectionObservationRole::Relay, actor, None, 82);
    let receipt = signed_preselection_receipt(&request, &relay_key, NOW + 30_000, NOW + 40_000, 83);
    (request, receipt)
}

fn forwarded_preselection_fixture() -> (
    PreselectionObservationRequest,
    Vec<u8>,
    Vec<u8>,
    SigningKey,
    SigningKey,
) {
    forwarded_preselection_fixture_with_prefix(ObservationAddressFamily::Ipv4, vec![8, 8, 4])
}

fn forwarded_preselection_fixture_with_prefix(
    family: ObservationAddressFamily,
    network_prefix: Vec<u8>,
) -> (
    PreselectionObservationRequest,
    Vec<u8>,
    Vec<u8>,
    SigningKey,
    SigningKey,
) {
    let control_key = key(84);
    let exit_key = key(85);
    let control = preselection_actor(&control_key, 86, NOW + 60_000, NOW + 60_000);
    let exit = preselection_actor(&exit_key, 87, NOW + 90_000, NOW + 60_000);
    let mut request = preselection_request(
        PreselectionObservationRole::Exit,
        exit.clone(),
        Some(control.clone()),
        88,
    );
    let scope = request.scope.as_mut().unwrap();
    scope.address_family = family as i32;
    scope.policy_expires_at_ms = NOW + 90_000;
    let signed_exit =
        signed_preselection_receipt(&request, &exit_key, NOW + 20_000, NOW + 40_000, 89);
    let encoded_request = encode_preselection_request(&request);
    let attestation = ForwardedPreselectionAttestation {
        request_hash: preselection_observation_request_hash(&encoded_request)
            .unwrap()
            .to_vec(),
        challenge: request.challenge.clone(),
        signed_exit_receipt: signed_exit.clone(),
        exit_receipt_hash: preselection_observation_receipt_hash(&signed_exit)
            .unwrap()
            .to_vec(),
        control: Some(control),
        exit: Some(exit),
        scope: request.scope.clone(),
        upstream_network_prefix: Some(ObservationNetworkPrefix {
            address_family: family as i32,
            network_prefix,
        }),
        observed_at_ms: NOW - 10_000,
        valid_until_ms: NOW + 50_000,
        nonce: vec![90; 32],
    };
    let signed_attestation = sign_control_message(
        &attestation,
        &control_key,
        attestation.observed_at_ms,
        attestation.valid_until_ms,
        [90; 32],
        TimePolicy::default(),
    )
    .unwrap();
    (
        request,
        signed_exit,
        signed_attestation,
        control_key,
        exit_key,
    )
}

fn open_tcp(signing_key: &SigningKey, nonce: [u8; 32]) -> OpenTcp {
    OpenTcp {
        route_context_id: vec![1; 16],
        flow_id: vec![2; 16],
        client_ephemeral_id: node_id(signing_key),
        hostname: "www.example.com".to_owned(),
        port: 443,
        policy_hash: vec![3; 32],
        timestamp_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: nonce.to_vec(),
    }
}

fn capacity_hold_request(maximum_paths: u32, probe_permit_limit: u32) -> ExitCapacityHoldRequest {
    let client_key = key(50);
    ExitCapacityHoldRequest {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        exit_node_id: node_id(&key(51)),
        client_session_id: node_id(&client_key),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths,
        policy_hash: vec![3; 32],
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: vec![4; 32],
        client_session_public_key: client_key.verifying_key().to_bytes().to_vec(),
        control_relay_node_id: node_id(&key(52)),
        control_relay_peer_id: vec![5; 38],
        exit_peer_id: vec![6; 38],
        reservation_expires_at_ms: EXPIRY,
        probe_permit_limit,
    }
}

fn session_capability(maximum_paths: u32, probe_permit_limit: u32) -> ClientSessionCapability {
    let client_key = key(50);
    ClientSessionCapability {
        capability_id: vec![7; 16],
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        client_session_id: node_id(&client_key),
        client_session_public_key: client_key.verifying_key().to_bytes().to_vec(),
        exit_node_id: node_id(&key(51)),
        exit_boot_id: vec![8; 16],
        control_relay_node_id: node_id(&key(52)),
        control_relay_peer_id: vec![5; 38],
        policy_hash: vec![3; 32],
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths,
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![9; 32],
        exit_peer_id: vec![6; 38],
        probe_permit_limit,
    }
}

fn capacity_hold(maximum_paths: u32, probe_permit_limit: u32) -> ExitCapacityHold {
    let exit_key = key(51);
    let capability = session_capability(1, 1);
    let signed_capability = sign_control_message(
        &capability,
        &exit_key,
        NOW,
        EXPIRY,
        [9; 32],
        TimePolicy::default(),
    )
    .unwrap();
    ExitCapacityHold {
        hold_id: vec![10; 16],
        client_session_capability: signed_capability,
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        exit_node_id: node_id(&exit_key),
        exit_boot_id: vec![8; 16],
        client_session_id: node_id(&key(50)),
        policy_hash: vec![3; 32],
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths,
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: vec![11; 32],
        exit_peer_id: vec![6; 38],
        control_relay_node_id: node_id(&key(52)),
        control_relay_peer_id: vec![5; 38],
        reservation_expires_at_ms: EXPIRY,
        probe_permit_limit,
    }
}

fn structural_signed_type(message_type: ControlMessageType) -> Vec<u8> {
    encode_canonical(
        &SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            message_type: message_type as i32,
            ..SignedEnvelope::default()
        },
        volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE,
    )
    .unwrap()
}

fn finalize_request() -> ExitReservationFinalizeRequest {
    let client_key = key(50);
    let exit_key = key(51);
    let capability = session_capability(1, 1);
    let signed_capability = sign_control_message(
        &capability,
        &exit_key,
        NOW,
        EXPIRY,
        [9; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let hold = capacity_hold(1, 1);
    let signed_hold = sign_control_message(
        &hold,
        &exit_key,
        NOW,
        NOW + 20_000,
        [11; 32],
        TimePolicy::default(),
    )
    .unwrap();

    ExitReservationFinalizeRequest {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        exit_node_id: node_id(&exit_key),
        client_session_id: node_id(&client_key),
        client_session_capability: signed_capability,
        exit_capacity_hold: signed_hold,
        relay_paths: vec![FinalizedRelayPath {
            path_id: 1,
            relay_node_id: vec![12; 32],
            relay_peer_id: vec![13; 38],
            client_wireguard_public_key: vec![14; 32],
            relay_probe_permit: structural_signed_type(ControlMessageType::RelayProbePermit),
            relay_probe_result: structural_signed_type(ControlMessageType::RelayProbeResult),
        }],
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: vec![15; 32],
        control_relay_node_id: node_id(&key(52)),
        control_relay_peer_id: vec![5; 38],
        finalize_id: vec![16; 16],
        exit_peer_id: vec![6; 38],
        auth_commitment: vec![17; 32],
        masque_context_id: 18,
        client_native_instance_id: vec![19; 32],
    }
}

#[test]
fn finalize_request_requires_exact_native_auth_context_and_instance_binding() {
    let client_key = key(50);
    let request = finalize_request();
    request.validate().unwrap();

    for invalid in [Vec::new(), vec![0; 32], vec![1; 31], vec![1; 33]] {
        let mut changed = request.clone();
        changed.auth_commitment = invalid.clone();
        assert!(matches!(
            changed.validate(),
            Err(ProtocolError::InvalidField(
                "finalize_request.auth_commitment"
            ))
        ));

        let mut changed = request.clone();
        changed.client_native_instance_id = invalid;
        assert!(matches!(
            changed.validate(),
            Err(ProtocolError::InvalidField(
                "finalize_request.client_native_instance_id"
            ))
        ));
    }
    for invalid in [0, MAX_MASQUE_CONTEXT_ID + 1] {
        let mut changed = request.clone();
        changed.masque_context_id = invalid;
        assert!(matches!(
            changed.validate(),
            Err(ProtocolError::InvalidField(
                "finalize_request.masque_context_id"
            ))
        ));
    }
    let mut maximum_context = request.clone();
    maximum_context.masque_context_id = MAX_MASQUE_CONTEXT_ID;
    maximum_context.validate().unwrap();

    let signed = sign_control_message(
        &request,
        &client_key,
        NOW,
        NOW + 20_000,
        [15; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    verify_control_message::<ExitReservationFinalizeRequest>(
        &signed,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();

    let mut envelope: SignedEnvelope =
        decode_canonical(&signed, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut changed: ExitReservationFinalizeRequest =
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    changed.client_native_instance_id[0] ^= 1;
    envelope.payload = encode_canonical(&changed, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let tampered =
        encode_canonical(&envelope, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut tamper_cache = ReplayCache::new(2).unwrap();
    assert!(matches!(
        verify_control_message::<ExitReservationFinalizeRequest>(
            &tampered,
            NOW + 1,
            TimePolicy::default(),
            &mut tamper_cache,
        ),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    assert!(tamper_cache.is_empty());
}

#[test]
fn prospective_probe_limit_is_mandatory_and_bounds_final_upper_count() {
    for (maximum_paths, probe_permit_limit) in [(1, 1), (1, 8), (3, 8), (8, 8)] {
        capacity_hold_request(maximum_paths, probe_permit_limit)
            .validate()
            .unwrap();
        session_capability(maximum_paths, probe_permit_limit)
            .validate()
            .unwrap();
        capacity_hold(maximum_paths, probe_permit_limit)
            .validate()
            .unwrap();
    }

    for (maximum_paths, probe_permit_limit) in [(0, 1), (1, 0), (3, 2), (1, 9), (9, 9)] {
        assert!(
            capacity_hold_request(maximum_paths, probe_permit_limit)
                .validate()
                .is_err()
        );
        assert!(
            session_capability(maximum_paths, probe_permit_limit)
                .validate()
                .is_err()
        );
        assert!(
            capacity_hold(maximum_paths, probe_permit_limit)
                .validate()
                .is_err()
        );
    }
}

#[test]
fn old_v3_without_probe_limit_decodes_to_zero_and_is_rejected() {
    let request = capacity_hold_request(1, 0);
    let encoded = request.encode_to_vec();
    let decoded =
        decode_canonical::<ExitCapacityHoldRequest>(&encoded, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    assert_eq!(decoded.probe_permit_limit, 0);
    assert!(matches!(
        decoded.validate(),
        Err(ProtocolError::InvalidField(
            "reservation_scope.probe_permit_limit"
        ))
    ));

    let capability = session_capability(1, 0);
    let encoded = capability.encode_to_vec();
    let decoded =
        decode_canonical::<ClientSessionCapability>(&encoded, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    assert_eq!(decoded.probe_permit_limit, 0);
    assert!(matches!(
        decoded.validate(),
        Err(ProtocolError::InvalidField(
            "reservation_scope.probe_permit_limit"
        ))
    ));

    let hold = capacity_hold(1, 0);
    let encoded = hold.encode_to_vec();
    let decoded = decode_canonical::<ExitCapacityHold>(&encoded, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    assert_eq!(decoded.probe_permit_limit, 0);
    assert!(matches!(
        decoded.validate(),
        Err(ProtocolError::InvalidField(
            "reservation_scope.probe_permit_limit"
        ))
    ));
}

#[test]
fn retired_v3_schema_preserves_exact_probe_limit_tags() {
    let schema = include_str!("../../../proto/volparossa/control/v3/control.proto");
    for (message, tag) in [
        ("ExitCapacityHoldRequest", 20),
        ("ClientSessionCapability", 19),
        ("ExitCapacityHold", 20),
    ] {
        let section = schema
            .split_once(&format!("message {message} {{"))
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(
            section.contains(&format!("uint32 probe_permit_limit = {tag};")),
            "{message} must expose probe_permit_limit at tag {tag}"
        );
    }
}

#[test]
fn checked_in_v4_schema_has_exact_native_route_tags() {
    let schema = include_str!("../../../proto/volparossa/control/v4/control.proto");
    let identity = schema
        .split_once("message NativeRouteIdentity {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    for (field, kind, tag) in [
        ("auth_commitment", "bytes", 1),
        ("certificate_sha256", "bytes", 2),
        ("spki_sha256", "bytes", 3),
        ("tls_server_name", "string", 4),
        ("masque_context_id", "uint64", 5),
        ("client_native_instance_id", "bytes", 6),
        ("exit_native_instance_id", "bytes", 7),
    ] {
        assert!(
            identity.contains(&format!("{kind} {field} = {tag};")),
            "NativeRouteIdentity.{field} must retain tag {tag}"
        );
    }
    assert_eq!(
        identity
            .lines()
            .filter(|line| line.trim_end().ends_with(';'))
            .count(),
        7,
        "NativeRouteIdentity must expose only its seven committed fields"
    );

    let reservation = schema
        .split_once("message ExitReservation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(reservation.contains("NativeRouteIdentity native_route_identity = 22;"));

    let finalize = schema
        .split_once("message ExitReservationFinalizeRequest {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    for (field, kind, tag) in [
        ("auth_commitment", "bytes", 15),
        ("masque_context_id", "uint64", 16),
        ("client_native_instance_id", "bytes", 17),
    ] {
        assert!(
            finalize.contains(&format!("{kind} {field} = {tag};")),
            "ExitReservationFinalizeRequest.{field} must retain tag {tag}"
        );
    }
    assert_eq!(
        finalize
            .lines()
            .filter(|line| line.trim_end().ends_with(';'))
            .count(),
        17,
        "ExitReservationFinalizeRequest must expose only its seventeen v4 fields"
    );
}

#[test]
fn checked_in_v4_schema_binds_relay_acceptance_to_exact_client_request_at_tag_30() {
    let schema = include_str!("../../../proto/volparossa/control/v4/control.proto");
    let reservation = schema
        .split_once("message RelayReservation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(reservation.contains("bytes signed_client_relay_request_sha256 = 30;"));

    let retired = include_str!("../../../proto/volparossa/control/v3/control.proto");
    let retired_reservation = retired
        .split_once("message RelayReservation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(!retired_reservation.contains("signed_client_relay_request_sha256"));
}

#[test]
fn v4_schemas_are_active_while_v3_remains_retired_evidence() {
    let control_v3 = include_str!("../../../proto/volparossa/control/v3/control.proto");
    let control_v4 = include_str!("../../../proto/volparossa/control/v4/control.proto");
    let discovery_v3 = include_str!("../../../proto/volparossa/discovery/v3/discovery.proto");
    let discovery_v4 = include_str!("../../../proto/volparossa/discovery/v4/discovery.proto");

    assert!(control_v3.contains("package volparossa.control.v3;"));
    assert!(!control_v3.contains("message NativeRouteIdentity {"));
    assert!(control_v4.contains("package volparossa.control.v4;"));
    assert!(control_v4.contains("Protocol v1, v2, v3,"));
    assert!(control_v4.contains("volparossa/control-envelope/v4"));

    assert!(discovery_v3.contains("package volparossa.discovery.v3;"));
    assert!(discovery_v3.contains("/volparossa/advertisement/3"));
    assert!(discovery_v4.contains("package volparossa.discovery.v4;"));
    assert!(discovery_v4.contains("Protocol v1, v2, v3,"));
    assert!(discovery_v4.contains("/volparossa/advertisement/4"));
    assert!(discovery_v4.contains("volparossa.control.v4.SignedEnvelope"));
}

#[test]
fn canonical_decode_rejects_unknown_and_duplicate_representations() {
    let message = open_tcp(&key(7), [8; 32]);
    let mut encoded = encode_canonical(&message, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    encoded.extend_from_slice(&[0xf8, 0x07, 0x01]);

    assert!(matches!(
        decode_canonical::<OpenTcp>(&encoded, MAX_CONTROL_PAYLOAD_SIZE),
        Err(ProtocolError::NonCanonical)
    ));
}
#[test]
fn v2_identity_and_retired_prefix_tags_are_noncanonical() {
    fn assert_old_tag_is_noncanonical<M: Message + Default>(tag_key: u8) {
        let mut encoded = M::default().encode_to_vec();
        encoded.extend_from_slice(&[tag_key, 1, 0x7f]);
        assert!(matches!(
            decode_canonical::<M>(&encoded, MAX_CONTROL_PAYLOAD_SIZE),
            Err(ProtocolError::NonCanonical)
        ));
    }

    assert_old_tag_is_noncanonical::<ExitCapacityHoldRequest>(0x2a);
    assert_old_tag_is_noncanonical::<ExitCapacityHoldRequest>(0x52);
    assert_old_tag_is_noncanonical::<RelayReservationRequest>(0x12);
    assert_old_tag_is_noncanonical::<ExitReservation>(0x2a);
    assert_old_tag_is_noncanonical::<RelayAuthorization>(0x3a);
    assert_old_tag_is_noncanonical::<RelayAuthorization>(0x6a);
    assert_old_tag_is_noncanonical::<RelayReservation>(0x3a);
    assert_old_tag_is_noncanonical::<RelayReservation>(0x7a);
    assert_old_tag_is_noncanonical::<ExitReservationConfirmation>(0x3a);
    assert_old_tag_is_noncanonical::<FinalizedRelayPath>(0x2a);
}

#[test]
fn signature_ttl_replay_and_payload_hash_are_enforced() {
    let signing_key = key(7);
    let message = open_tcp(&signing_key, [8; 32]);
    let encoded = sign_control_message(
        &message,
        &signing_key,
        NOW,
        EXPIRY,
        [8; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(8).unwrap();
    let verified =
        verify_control_message::<OpenTcp>(&encoded, NOW + 1, TimePolicy::default(), &mut cache)
            .unwrap();
    assert_eq!(verified.message(), &message);

    assert!(matches!(
        verify_control_message::<OpenTcp>(&encoded, NOW + 2, TimePolicy::default(), &mut cache),
        Err(ProtocolError::Replay)
    ));

    let mut altered: SignedEnvelope =
        decode_canonical(&encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    altered.payload[0] ^= 1;
    let altered =
        encode_canonical(&altered, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut fresh_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_control_message::<OpenTcp>(
            &altered,
            NOW + 1,
            TimePolicy::default(),
            &mut fresh_cache
        ),
        Err(ProtocolError::PayloadHashMismatch)
    ));

    let mut expiry_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_control_message::<OpenTcp>(
            &encoded,
            EXPIRY,
            TimePolicy::default(),
            &mut expiry_cache
        ),
        Err(ProtocolError::Expired)
    ));
}

#[test]
fn control_envelopes_reject_v1_v2_v3_and_future_versions_before_signature_use() {
    let signing_key = key(8);
    let message = open_tcp(&signing_key, [9; 32]);
    let encoded = sign_control_message(
        &message,
        &signing_key,
        NOW,
        EXPIRY,
        [9; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut envelope: SignedEnvelope =
        decode_canonical(&encoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    for version in [1, 2, 3, PROTOCOL_VERSION + 1] {
        envelope.protocol_version = version;
        let changed =
            encode_canonical(&envelope, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let mut cache = ReplayCache::new(2).unwrap();
        assert!(matches!(
            verify_control_message::<OpenTcp>(
                &changed,
                NOW + 1,
                TimePolicy::default(),
                &mut cache,
            ),
            Err(ProtocolError::UnsupportedVersion(received)) if received == version
        ));
    }
}

#[test]
fn external_identity_provider_signature_is_checked_before_encoding() {
    let signing_key = key(9);
    let message = open_tcp(&signing_key, [10; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let encoded = sign_control_message_with(
        &message,
        public_key,
        NOW,
        EXPIRY,
        [10; 32],
        TimePolicy::default(),
        |bytes| Some(signing_key.sign(bytes).to_bytes()),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    verify_control_message::<OpenTcp>(&encoded, NOW + 1, TimePolicy::default(), &mut cache)
        .unwrap();

    let wrong_key = key(10);
    assert!(matches!(
        sign_control_message_with(
            &message,
            public_key,
            NOW,
            EXPIRY,
            [10; 32],
            TimePolicy::default(),
            |bytes| Some(wrong_key.sign(bytes).to_bytes())
        ),
        Err(ProtocolError::SigningFailed)
    ));
}

#[test]
fn future_messages_and_overlong_lifetimes_fail_closed() {
    let signing_key = key(1);
    let mut message = open_tcp(&signing_key, [2; 32]);
    message.timestamp_ms = NOW + 120_000;
    message.expires_at_ms = message.timestamp_ms + 1_000;
    let encoded = sign_control_message(
        &message,
        &signing_key,
        message.timestamp_ms,
        message.expires_at_ms,
        [2; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    assert!(matches!(
        verify_control_message::<OpenTcp>(&encoded, NOW, TimePolicy::default(), &mut cache),
        Err(ProtocolError::NotYetValid)
    ));

    message.timestamp_ms = NOW;
    message.expires_at_ms = NOW + TimePolicy::default().maximum_lifetime_ms + 1;
    assert!(matches!(
        sign_control_message(
            &message,
            &signing_key,
            message.timestamp_ms,
            message.expires_at_ms,
            [2; 32],
            TimePolicy::default()
        ),
        Err(ProtocolError::InvalidLifetime)
    ));
}

#[test]
fn framing_is_exact_and_bounded() {
    let body = vec![1, 2, 3, 4];
    let frame = frame_control_message(&body).unwrap();
    assert_eq!(unframe_control_message(&frame).unwrap(), body);

    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(matches!(
        unframe_control_message(&trailing),
        Err(ProtocolError::InvalidFrame)
    ));
    assert!(matches!(
        unframe_control_message(&frame[..3]),
        Err(ProtocolError::InvalidFrame)
    ));
}

fn relay_advertisement(signing_key: &SigningKey) -> NodeAdvertisement {
    NodeAdvertisement {
        node_id: node_id(signing_key),
        peer_id: vec![0, 36, 8, 1, 18, 32, 9],
        sequence_number: 12,
        roles: Some(AdvertisementRoles {
            client: true,
            relay: true,
            exit: false,
        }),
        capabilities: Some(AdvertisementCapabilities {
            tcp_mptcp: true,
            udp_single_path: true,
            multipath_quic: true,
            ipv4: true,
            ipv6: true,
            udp_hole_punching: true,
        }),
        control_addresses: vec!["/ip4/192.0.2.10/udp/4001/quic-v1".to_owned()],
        capacity: Some(AdvertisementCapacity {
            operator_relay_limit_up_mbps: 100,
            operator_relay_limit_down_mbps: 100,
            operator_exit_limit_up_mbps: 0,
            operator_exit_limit_down_mbps: 0,
            currently_reserved_up_mbps: 20,
            currently_reserved_down_mbps: 20,
            estimated_free_up_mbps: 80,
            estimated_free_down_mbps: 80,
            active_relay_sessions: 1,
            active_exit_sessions: 0,
            free_relay_slots: 4,
            free_exit_slots: 0,
            sample_window_seconds: 15,
        }),
        network: Some(AdvertisementNetwork {
            region: "eu-west".to_owned(),
            country_code: "NL".to_owned(),
            asn: 64_496,
            ipv4_prefix_hint: "192.0.2.0/24".to_owned(),
            ipv6_prefix_hint: String::new(),
            operator_id: "operator-a".to_owned(),
        }),
        quality: Some(AdvertisementQuality {
            local_uptime_seconds: 3_600,
            historical_uptime_ppm: 990_000,
            historical_delivery_ratio_p25_ppm: 950_000,
        }),
        policy: Some(AdvertisementPolicy {
            whitelist_version: 4,
            whitelist_hash: vec![13; 32],
        }),
        measured_at_ms: NOW,
        expires_at_ms: EXPIRY,
    }
}

#[test]
fn advertisement_is_bound_to_its_signer_and_expiry() {
    let signing_key = key(11);
    let advertisement = relay_advertisement(&signing_key);
    let encoded = sign_control_message(
        &advertisement,
        &signing_key,
        NOW,
        EXPIRY,
        [14; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(4).unwrap();
    verify_control_message::<NodeAdvertisement>(
        &encoded,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();

    let mut wrong_node = advertisement;
    wrong_node.node_id = vec![99; 32];
    assert!(matches!(
        sign_control_message(
            &wrong_node,
            &signing_key,
            NOW,
            EXPIRY,
            [15; 32],
            TimePolicy::default()
        ),
        Err(ProtocolError::InvalidField(
            "advertisement envelope binding"
        ))
    ));
}

#[test]
fn advertisement_v2_rejects_removed_static_endpoint_and_invalid_operator() {
    let signing_key = key(12);
    let relay = relay_advertisement(&signing_key);
    let signed_relay = sign_control_message(
        &relay,
        &signing_key,
        NOW,
        EXPIRY,
        [15; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    verify_control_message::<NodeAdvertisement>(
        &signed_relay,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();

    let mut legacy_wire = encode_canonical(&relay, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    // Removed v1 field 7 encoded as an empty length-delimited nested endpoint.
    legacy_wire.extend_from_slice(&[0x3a, 0x00]);
    assert!(matches!(
        decode_canonical::<NodeAdvertisement>(&legacy_wire, MAX_CONTROL_PAYLOAD_SIZE),
        Err(ProtocolError::NonCanonical)
    ));

    let mut invalid_operator = relay.clone();
    invalid_operator.network.as_mut().unwrap().operator_id = "operator with spaces".to_owned();
    assert!(matches!(
        invalid_operator.validate(),
        Err(ProtocolError::InvalidField(
            "advertisement.network.operator_id"
        ))
    ));

    let mut bounded_operator = relay;
    bounded_operator.network.as_mut().unwrap().operator_id = "a".repeat(128);
    bounded_operator.validate().unwrap();
    bounded_operator.network.as_mut().unwrap().operator_id = "a".repeat(129);
    assert!(matches!(
        bounded_operator.validate(),
        Err(ProtocolError::InvalidField(
            "advertisement.network.operator_id"
        ))
    ));
}

fn relay_authorization(exit_key: &SigningKey, relay_key: &SigningKey) -> RelayAuthorization {
    RelayAuthorization {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        path_id: 1,
        relay_node_id: node_id(relay_key),
        exit_node_id: node_id(exit_key),
        client_session_id: node_id(&key(19)),
        relay_peer_id: relay_key.verifying_key().to_bytes().to_vec(),
        allowed_transports: vec![Transport::UdpSinglePath as i32],
        maximum_up_mbps: 25,
        maximum_down_mbps: 50,
        client_wireguard_public_key: vec![4; 32],
        exit_wireguard_endpoint: Some(endpoint(5, 20_000)),
        policy_hash: vec![9; 32],
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![6; 32],
        capability_id: vec![10; 16],
        client_session_public_key: key(19).verifying_key().to_bytes().to_vec(),
        exit_boot_id: vec![11; 16],
        hold_id: vec![12; 16],
        finalize_id: vec![13; 16],
        control_relay_node_id: vec![14; 32],
        control_relay_peer_id: vec![15; 38],
        exit_peer_id: vec![16; 38],
    }
}

fn native_route_identity() -> NativeRouteIdentity {
    NativeRouteIdentity {
        auth_commitment: vec![20; 32],
        certificate_sha256: vec![21; 32],
        spki_sha256: vec![22; 32],
        tls_server_name: "exit.example".to_owned(),
        masque_context_id: 23,
        client_native_instance_id: vec![24; 32],
        exit_native_instance_id: vec![25; 32],
    }
}

#[test]
fn finalized_bundle_hash_is_domain_separated_framed_and_ordered() {
    let exit_key = key(20);
    let first_relay_key = key(21);
    let second_relay_key = key(22);
    let first = relay_authorization(&exit_key, &first_relay_key);
    let mut second = first.clone();
    second.path_id = 2;
    second.relay_node_id = node_id(&second_relay_key);
    second.relay_peer_id = second_relay_key.verifying_key().to_bytes().to_vec();
    second.nonce = vec![17; 32];

    let signed_first = sign_control_message(
        &first,
        &exit_key,
        NOW,
        EXPIRY,
        [6; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let signed_second = sign_control_message(
        &second,
        &exit_key,
        NOW,
        EXPIRY,
        [17; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let exit_grant = ExitReservation {
        reservation_id: first.reservation_id.clone(),
        route_context_id: first.route_context_id.clone(),
        exit_node_id: first.exit_node_id.clone(),
        client_session_id: first.client_session_id.clone(),
        allowed_transports: first.allowed_transports.clone(),
        reserved_up_mbps: first.maximum_up_mbps,
        reserved_down_mbps: first.maximum_down_mbps,
        maximum_paths: 2,
        policy_hash: first.policy_hash.clone(),
        created_at_ms: first.created_at_ms,
        expires_at_ms: first.expires_at_ms,
        nonce: vec![18; 32],
        capability_id: first.capability_id.clone(),
        client_session_public_key: first.client_session_public_key.clone(),
        exit_boot_id: first.exit_boot_id.clone(),
        hold_id: first.hold_id.clone(),
        finalize_id: first.finalize_id.clone(),
        control_relay_node_id: first.control_relay_node_id.clone(),
        control_relay_peer_id: first.control_relay_peer_id.clone(),
        exit_peer_id: first.exit_peer_id.clone(),
        native_route_identity: Some(native_route_identity()),
    };
    let signed_exit = sign_control_message(
        &exit_grant,
        &exit_key,
        NOW,
        EXPIRY,
        [18; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let authorizations = vec![signed_first, signed_second];
    let actual = finalized_reservation_bundle_hash(&signed_exit, &authorizations).unwrap();

    let mut expected = Sha256::new();
    expected.update(b"volparossa/finalized-reservation-bundle/v4\0");
    for member in std::iter::once(&signed_exit).chain(authorizations.iter()) {
        expected.update(u32::try_from(member.len()).unwrap().to_be_bytes());
        expected.update(member);
    }
    assert_eq!(actual.as_slice(), expected.finalize().as_slice());

    let mut changed_identity = exit_grant.clone();
    changed_identity
        .native_route_identity
        .as_mut()
        .unwrap()
        .tls_server_name = "other.example".to_owned();
    let changed_signed_exit = sign_control_message(
        &changed_identity,
        &exit_key,
        NOW,
        EXPIRY,
        [18; 32],
        TimePolicy::default(),
    )
    .unwrap();
    assert_ne!(
        finalized_reservation_bundle_hash(&changed_signed_exit, &authorizations).unwrap(),
        actual
    );

    let reversed = vec![authorizations[1].clone(), authorizations[0].clone()];
    assert!(matches!(
        finalized_reservation_bundle_hash(&signed_exit, &reversed),
        Err(ProtocolError::InvalidField(
            "finalized bundle authorization scope"
        ))
    ));
}

fn assert_relay_scope_mismatch(changed: &RelayReservation, relay_key: &SigningKey) {
    let signed_changed = sign_control_message(
        changed,
        relay_key,
        NOW,
        EXPIRY,
        [7; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut mismatch_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_relay_reservation(
            &signed_changed,
            NOW + 1,
            TimePolicy::default(),
            &mut mismatch_cache,
        ),
        Err(ProtocolError::InvalidField(
            "relay reservation differs from exit authorization"
        ))
    ));
    assert!(mismatch_cache.is_empty());
}

fn relay_reservation_fixture(exit_key: &SigningKey, relay_key: &SigningKey) -> RelayReservation {
    let grant = relay_authorization(exit_key, relay_key);
    let signed_grant = sign_control_message(
        &grant,
        exit_key,
        NOW,
        EXPIRY,
        [6; 32],
        TimePolicy::default(),
    )
    .unwrap();
    RelayReservation {
        reservation_id: grant.reservation_id.clone(),
        route_context_id: grant.route_context_id.clone(),
        path_id: grant.path_id,
        relay_node_id: grant.relay_node_id.clone(),
        exit_node_id: grant.exit_node_id.clone(),
        client_session_id: grant.client_session_id.clone(),
        relay_peer_id: grant.relay_peer_id.clone(),
        allowed_transports: grant.allowed_transports.clone(),
        maximum_up_mbps: grant.maximum_up_mbps,
        maximum_down_mbps: grant.maximum_down_mbps,
        client_wireguard_public_key: grant.client_wireguard_public_key.clone(),
        relay_client_wireguard_endpoint: Some(endpoint(6, 20_001)),
        relay_exit_wireguard_endpoint: Some(endpoint(7, 20_002)),
        exit_wireguard_endpoint: grant.exit_wireguard_endpoint.clone(),
        policy_hash: grant.policy_hash.clone(),
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![7; 32],
        exit_authorization: signed_grant,
        capability_id: grant.capability_id.clone(),
        client_session_public_key: grant.client_session_public_key.clone(),
        exit_boot_id: grant.exit_boot_id.clone(),
        hold_id: grant.hold_id.clone(),
        finalize_id: grant.finalize_id.clone(),
        control_relay_node_id: grant.control_relay_node_id.clone(),
        control_relay_peer_id: grant.control_relay_peer_id.clone(),
        exit_peer_id: grant.exit_peer_id.clone(),
        signed_client_relay_request_sha256: vec![18; 32],
    }
}

#[test]
fn relay_acceptance_requires_matching_exit_authorization() {
    let exit_key = key(20);
    let relay_key = key(21);
    let reservation = relay_reservation_fixture(&exit_key, &relay_key);
    let signed_reservation = sign_control_message(
        &reservation,
        &relay_key,
        NOW,
        EXPIRY,
        [7; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(8).unwrap();
    let (relay, exit) = verify_relay_reservation(
        &signed_reservation,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(relay.message().path_id, exit.message().path_id);

    let mut wrong_context = reservation.clone();
    wrong_context.route_context_id = vec![22; 16];
    let mut wrong_path = reservation.clone();
    wrong_path.path_id = 2;
    assert_relay_scope_mismatch(&wrong_context, &relay_key);
    assert_relay_scope_mismatch(&wrong_path, &relay_key);
    let mut changed = reservation;
    changed.maximum_down_mbps += 1;
    let signed_changed = sign_control_message(
        &changed,
        &relay_key,
        NOW,
        EXPIRY,
        [7; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut mismatch_cache = ReplayCache::new(8).unwrap();
    assert!(matches!(
        verify_relay_reservation(
            &signed_changed,
            NOW + 1,
            TimePolicy::default(),
            &mut mismatch_cache
        ),
        Err(ProtocolError::InvalidField(
            "relay reservation differs from exit authorization"
        ))
    ));
    assert!(mismatch_cache.is_empty());
    let (relay, exit) = verify_relay_reservation(
        &signed_reservation,
        NOW + 1,
        TimePolicy::default(),
        &mut mismatch_cache,
    )
    .unwrap();
    assert_eq!(relay.message().path_id, exit.message().path_id);
}

#[test]
fn relay_acceptance_commitment_is_required_nonzero_and_canonical_at_tag_30() {
    let reservation = relay_reservation_fixture(&key(20), &key(21));
    let payload = encode_canonical(&reservation, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let commitment_field = [vec![0xf2, 0x01, 0x20], vec![18; 32]].concat();
    assert!(payload.ends_with(&commitment_field));

    for invalid_commitment in [Vec::new(), vec![0; 32], vec![19; 31], vec![19; 33]] {
        let mut invalid = reservation.clone();
        invalid.signed_client_relay_request_sha256 = invalid_commitment;
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolError::InvalidField(
                "relay signed client request SHA-256"
            ))
        ));
    }
}

#[test]
fn relay_request_commitment_hashes_the_complete_canonical_signed_envelope() {
    let client_key = key(70);
    let request = RelayReservationRequest {
        client_session_id: node_id(&client_key),
        exit_authorization: structural_signed_type(ControlMessageType::RelayAuthorization),
        created_at_ms: NOW,
        expires_at_ms: NOW + 20_000,
        nonce: vec![71; 32],
        client_wireguard_endpoint: Some(endpoint(72, 20_010)),
        client_session_capability: structural_signed_type(
            ControlMessageType::ClientSessionCapability,
        ),
        exit_reservation: structural_signed_type(ControlMessageType::ExitReservation),
    };
    let signed = sign_control_message(
        &request,
        &client_key,
        request.created_at_ms,
        request.expires_at_ms,
        [71; 32],
        TimePolicy::default(),
    )
    .unwrap();
    assert_eq!(
        relay_reservation_request_sha256(&signed)
            .unwrap()
            .as_slice(),
        Sha256::digest(&signed).as_slice()
    );

    let wrong_type = sign_control_message(
        &open_tcp(&client_key, [73; 32]),
        &client_key,
        NOW,
        EXPIRY,
        [73; 32],
        TimePolicy::default(),
    )
    .unwrap();
    assert!(matches!(
        relay_reservation_request_sha256(&wrong_type),
        Err(ProtocolError::InvalidField(
            "relay reservation request SHA-256"
        ))
    ));

    let mut noncanonical = signed;
    noncanonical.extend_from_slice(&[0xf8, 0x07, 0x01]);
    assert!(matches!(
        relay_reservation_request_sha256(&noncanonical),
        Err(ProtocolError::NonCanonical)
    ));
}

fn endpoint(key: u8, port: u16) -> WireguardEndpoint {
    WireguardEndpoint {
        public_key: vec![key; 32],
        underlay_ip: vec![8, 8, 4, key],
        listen_port: u32::from(port),
    }
}

#[test]
fn wireguard_endpoint_rejects_private_loopback_and_iana_special_ranges() {
    let mut value = endpoint(1, 51_820);
    value.validate("endpoint").expect("ordinary public address");
    for address in [
        vec![10, 0, 0, 1],
        vec![127, 0, 0, 1],
        vec![169, 254, 0, 1],
        vec![192, 0, 2, 1],
        vec![192, 31, 196, 1],
        vec![198, 51, 100, 1],
        vec![203, 0, 113, 1],
        vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        value.underlay_ip = address;
        assert!(matches!(
            value.validate("endpoint"),
            Err(ProtocolError::InvalidField("endpoint"))
        ));
    }
}

fn exit_reservation_for_identity() -> ExitReservation {
    let exit_key = key(30);
    ExitReservation {
        reservation_id: vec![1; 16],
        route_context_id: vec![2; 16],
        exit_node_id: node_id(&exit_key),
        client_session_id: node_id(&key(31)),
        allowed_transports: vec![
            Transport::TcpMptcp as i32,
            Transport::UdpSinglePath as i32,
            Transport::MultipathQuic as i32,
        ],
        reserved_up_mbps: 25,
        reserved_down_mbps: 50,
        maximum_paths: 4,
        policy_hash: vec![6; 32],
        created_at_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![4; 32],
        capability_id: vec![7; 16],
        client_session_public_key: key(31).verifying_key().to_bytes().to_vec(),
        exit_boot_id: vec![8; 16],
        hold_id: vec![9; 16],
        finalize_id: vec![10; 16],
        control_relay_node_id: vec![11; 32],
        control_relay_peer_id: vec![12; 38],
        exit_peer_id: vec![13; 38],
        native_route_identity: Some(native_route_identity()),
    }
}

fn assert_invalid_native_identity(identity: NativeRouteIdentity, expected_field: &'static str) {
    let mut reservation = exit_reservation_for_identity();
    reservation.native_route_identity = Some(identity);
    assert!(matches!(
        reservation.validate(),
        Err(ProtocolError::InvalidField(field)) if field == expected_field
    ));
}

#[test]
fn exit_reservation_transports_are_known_sorted_and_unique() {
    let exit_key = key(30);
    let mut reservation = exit_reservation_for_identity();
    let signed = sign_control_message(
        &reservation,
        &exit_key,
        NOW,
        EXPIRY,
        [4; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(4).unwrap();
    verify_control_message::<ExitReservation>(&signed, NOW + 1, TimePolicy::default(), &mut cache)
        .unwrap();

    reservation.allowed_transports =
        vec![Transport::UdpSinglePath as i32, Transport::TcpMptcp as i32];
    assert!(reservation.validate().is_err());
}

#[test]
fn signed_native_route_identity_is_required_canonical_and_tamper_evident() {
    let exit_key = key(30);
    let reservation = exit_reservation_for_identity();
    reservation.validate().unwrap();

    let mut missing = reservation.clone();
    missing.native_route_identity = None;
    assert!(matches!(
        sign_control_message(
            &missing,
            &exit_key,
            NOW,
            EXPIRY,
            [4; 32],
            TimePolicy::default(),
        ),
        Err(ProtocolError::InvalidField(
            "exit_reservation.native_route_identity"
        ))
    ));

    for invalid in [Vec::new(), vec![0; 32], vec![1; 31], vec![1; 33]] {
        let mut identity = native_route_identity();
        identity.auth_commitment = invalid.clone();
        assert_invalid_native_identity(identity, "native_route_identity.auth_commitment");

        let mut identity = native_route_identity();
        identity.certificate_sha256 = invalid.clone();
        assert_invalid_native_identity(identity, "native_route_identity.certificate_sha256");

        let mut identity = native_route_identity();
        identity.spki_sha256 = invalid.clone();
        assert_invalid_native_identity(identity, "native_route_identity.spki_sha256");

        let mut identity = native_route_identity();
        identity.client_native_instance_id = invalid.clone();
        assert_invalid_native_identity(identity, "native_route_identity.client_native_instance_id");

        let mut identity = native_route_identity();
        identity.exit_native_instance_id = invalid;
        assert_invalid_native_identity(identity, "native_route_identity.exit_native_instance_id");
    }

    for invalid in [
        "",
        "exit",
        "EXIT.example",
        "exit.example.",
        "-exit.example",
        "exit-.example",
        "exit_name.example",
        "192.0.2.1",
        "exit.exämple",
    ] {
        let mut identity = native_route_identity();
        identity.tls_server_name = invalid.to_owned();
        assert_invalid_native_identity(identity, "native_route_identity.tls_server_name");
    }
    for invalid in [0, MAX_MASQUE_CONTEXT_ID + 1] {
        let mut identity = native_route_identity();
        identity.masque_context_id = invalid;
        assert_invalid_native_identity(identity, "native_route_identity.masque_context_id");
    }
    let mut maximum_context = reservation.clone();
    maximum_context
        .native_route_identity
        .as_mut()
        .unwrap()
        .masque_context_id = MAX_MASQUE_CONTEXT_ID;
    maximum_context.validate().unwrap();

    let signed = sign_control_message(
        &reservation,
        &exit_key,
        NOW,
        EXPIRY,
        [4; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut envelope: SignedEnvelope =
        decode_canonical(&signed, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut changed: ExitReservation =
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    changed
        .native_route_identity
        .as_mut()
        .unwrap()
        .certificate_sha256[0] ^= 1;
    envelope.payload = encode_canonical(&changed, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
    let tampered =
        encode_canonical(&envelope, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    assert!(matches!(
        verify_control_message::<ExitReservation>(
            &tampered,
            NOW + 1,
            TimePolicy::default(),
            &mut cache,
        ),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    assert!(cache.is_empty());
}

#[test]
fn udp_authorization_pins_exactly_one_destination() {
    let client_key = key(40);
    let mut authorization = UdpFlowAuthorization {
        route_context_id: vec![1; 16],
        flow_id: vec![2; 16],
        client_ephemeral_id: node_id(&client_key),
        hostname: "dns.example.com".to_owned(),
        destination_ip: Vec::new(),
        port: 53,
        policy_hash: vec![3; 32],
        idle_timeout_ms: 30_000,
        timestamp_ms: NOW,
        expires_at_ms: EXPIRY,
        nonce: vec![4; 32],
    };
    let signed = sign_control_message(
        &authorization,
        &client_key,
        NOW,
        EXPIRY,
        [4; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    verify_control_message::<UdpFlowAuthorization>(
        &signed,
        NOW + 1,
        TimePolicy::default(),
        &mut cache,
    )
    .unwrap();

    authorization.destination_ip = vec![192, 0, 2, 53];
    assert!(authorization.validate().is_err());
    authorization.hostname.clear();
    assert!(authorization.validate().is_ok());
}

#[test]
fn wrong_payload_type_does_not_consume_replay_nonce() {
    let client_key = key(50);
    let message = open_tcp(&client_key, [5; 32]);
    let signed = sign_control_message(
        &message,
        &client_key,
        NOW,
        EXPIRY,
        [5; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut cache = ReplayCache::new(2).unwrap();
    assert!(matches!(
        verify_control_message::<UdpFlowAuthorization>(
            &signed,
            NOW + 1,
            TimePolicy::default(),
            &mut cache
        ),
        Err(ProtocolError::WrongMessageType { .. })
    ));
    verify_control_message::<OpenTcp>(&signed, NOW + 1, TimePolicy::default(), &mut cache).unwrap();
}

#[test]
fn confirmation_hash_binds_exact_canonical_envelope_bytes() {
    let session_key = key(70);
    let signed = sign_control_message(
        &open_tcp(&session_key, [70; 32]),
        &session_key,
        NOW,
        EXPIRY,
        [70; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let mut first: SignedEnvelope =
        decode_canonical(&signed, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    first.message_type = ControlMessageType::ExitReservationConfirmation as i32;
    let first = encode_canonical(&first, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    let mut second: SignedEnvelope =
        decode_canonical(&first, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();
    second.signature[0] ^= 1;
    let second = encode_canonical(&second, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap();

    assert_ne!(
        exit_confirmation_envelope_hash(&first).unwrap(),
        exit_confirmation_envelope_hash(&second).unwrap()
    );
}

#[test]
fn encoded_envelopes_are_stable_across_round_trip() {
    let client_key = key(60);
    let message = open_tcp(&client_key, [6; 32]);
    let signed = sign_control_message(
        &message,
        &client_key,
        NOW,
        EXPIRY,
        [6; 32],
        TimePolicy::default(),
    )
    .unwrap();
    let decoded = SignedEnvelope::decode(signed.as_slice()).unwrap();
    assert_eq!(
        encode_canonical(&decoded, volparossa_protocol::MAX_CONTROL_MESSAGE_SIZE).unwrap(),
        signed
    );
}
