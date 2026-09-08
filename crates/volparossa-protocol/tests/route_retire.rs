//! Signed retirement and receipt scope regression tests.

use ed25519_dalek::SigningKey;
use volparossa_protocol::{
    ControlPayload, MAX_ROUTE_RETIRE_BYTES, MAX_ROUTE_RETIRE_LIFETIME_MS, ProtocolError,
    ReplayCache, RetirementReceipt, RouteRetire, SignedEnvelope, TimePolicy, decode_canonical,
    encode_canonical, node_id_from_public_key, route_retire_request_hash, sign_control_message,
    verify_control_message,
};

const NOW: u64 = 10_000;
const EXPIRES: u64 = 20_000;

fn request(key: &SigningKey) -> RouteRetire {
    let public = key.verifying_key().to_bytes();
    RouteRetire {
        route_context_id: vec![1; 16],
        reservation_id: vec![2; 16],
        policy_hash: vec![3; 32],
        client_session_id: node_id_from_public_key(&public).to_vec(),
        client_session_public_key: public.to_vec(),
    }
}

fn sign<T: ControlPayload>(payload: &T, key: &SigningKey, nonce: u8) -> Vec<u8> {
    sign_control_message(
        payload,
        key,
        NOW,
        EXPIRES,
        [nonce; 32],
        TimePolicy::default(),
    )
    .unwrap()
}

#[test]
fn route_retire_signature_session_nonce_expiry_and_canonical_bounds() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let payload = request(&key);
    let encoded = sign(&payload, &key, 1);
    let mut replay = ReplayCache::new(4).unwrap();
    assert_eq!(
        verify_control_message::<RouteRetire>(&encoded, NOW, TimePolicy::default(), &mut replay)
            .unwrap()
            .message(),
        &payload,
    );
    assert!(
        verify_control_message::<RouteRetire>(&encoded, NOW, TimePolicy::default(), &mut replay,)
            .is_err()
    );
    assert!(
        verify_control_message::<RouteRetire>(
            &encoded,
            EXPIRES,
            TimePolicy::default(),
            &mut ReplayCache::new(1).unwrap(),
        )
        .is_err()
    );
    let second = sign(&payload, &key, 2);
    assert_ne!(
        route_retire_request_hash(&encoded).unwrap(),
        route_retire_request_hash(&second).unwrap()
    );
    let wrong = SigningKey::from_bytes(&[5; 32]);
    assert!(
        sign_control_message(
            &payload,
            &wrong,
            NOW,
            EXPIRES,
            [1; 32],
            TimePolicy::default()
        )
        .is_err()
    );
    assert!(
        sign_control_message(
            &payload,
            &key,
            NOW,
            NOW + MAX_ROUTE_RETIRE_LIFETIME_MS + 1,
            [1; 32],
            TimePolicy::default()
        )
        .is_err()
    );
    let mut corrupted: SignedEnvelope = decode_canonical(&encoded, MAX_ROUTE_RETIRE_BYTES).unwrap();
    corrupted.signature[0] ^= 1;
    assert!(
        verify_control_message::<RouteRetire>(
            &encode_canonical(&corrupted, MAX_ROUTE_RETIRE_BYTES).unwrap(),
            NOW,
            TimePolicy::default(),
            &mut ReplayCache::new(1).unwrap(),
        )
        .is_err()
    );
    let mut noncanonical = encoded.clone();
    noncanonical.extend([0x78, 1]);
    assert!(route_retire_request_hash(&noncanonical).is_err());
    assert!(route_retire_request_hash(&vec![0; MAX_ROUTE_RETIRE_BYTES + 1]).is_err());
    let mut wrong_session = payload;
    wrong_session.client_session_id[0] ^= 1;
    assert!(wrong_session.validate().is_err());
}

#[test]
fn retirement_receipt_requires_exact_single_nested_completion_and_signer() {
    let session = SigningKey::from_bytes(&[4; 32]);
    let exit = SigningKey::from_bytes(&[5; 32]);
    let relay = SigningKey::from_bytes(&[6; 32]);
    let payload = request(&session);
    let hash = route_retire_request_hash(&sign(&payload, &session, 1)).unwrap();
    let exit_receipt = RetirementReceipt {
        route_context_id: payload.route_context_id.clone(),
        reservation_id: payload.reservation_id.clone(),
        request_hash: hash.to_vec(),
        provider_node_id: node_id_from_public_key(&exit.verifying_key().to_bytes()).to_vec(),
        confirmed_destroyed: true,
        signed_exit_receipt: Vec::new(),
    };
    let signed_exit = sign(&exit_receipt, &exit, 2);
    let relay_receipt = RetirementReceipt {
        provider_node_id: node_id_from_public_key(&relay.verifying_key().to_bytes()).to_vec(),
        signed_exit_receipt: signed_exit.clone(),
        ..exit_receipt.clone()
    };
    let signed_relay = sign(&relay_receipt, &relay, 3);
    let mut seen_nonces = ReplayCache::new(4).unwrap();
    let verified = verify_control_message::<RetirementReceipt>(
        &signed_relay,
        NOW,
        TimePolicy::default(),
        &mut seen_nonces,
    )
    .unwrap();
    // The outer signature does not substitute for independent Exit signature verification.
    let verified_exit = verify_control_message::<RetirementReceipt>(
        &verified.message().signed_exit_receipt,
        NOW,
        TimePolicy::default(),
        &mut seen_nonces,
    )
    .unwrap();
    assert_eq!(verified_exit.message().request_hash, hash);
    assert!(
        sign_control_message(
            &exit_receipt,
            &relay,
            NOW,
            EXPIRES,
            [1; 32],
            TimePolicy::default()
        )
        .is_err()
    );
    for malformed in [
        RetirementReceipt {
            confirmed_destroyed: false,
            ..relay_receipt.clone()
        },
        RetirementReceipt {
            request_hash: vec![9; 32],
            ..relay_receipt.clone()
        },
        RetirementReceipt {
            route_context_id: vec![9; 16],
            ..relay_receipt.clone()
        },
        RetirementReceipt {
            signed_exit_receipt: signed_relay,
            ..relay_receipt.clone()
        },
        RetirementReceipt {
            provider_node_id: exit_receipt.provider_node_id,
            ..relay_receipt
        },
    ] {
        assert!(matches!(
            malformed.validate(),
            Err(ProtocolError::InvalidField(_))
        ));
    }
}
