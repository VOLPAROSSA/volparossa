//! Typed path-state signatures and bounds, not a live-subflow proof.

use super::*;
use volparossa_protocol::{MptcpPathsRequest, MptcpPathsState, mptcp_paths_request_hash};

fn request() -> MptcpPathsRequest {
    let mut parent = exit_reservation_for_identity();
    parent.allowed_transports = vec![Transport::TcpMptcp as i32];
    MptcpPathsRequest {
        signed_exit_reservation: sign_control_message(
            &parent,
            &key(30),
            NOW,
            EXPIRY,
            [4; 32],
            TimePolicy::default(),
        )
        .unwrap(),
    }
}

fn signed<T: ControlPayload>(payload: &T, signer: &SigningKey, nonce: u8) -> Vec<u8> {
    sign_control_message(
        payload,
        signer,
        NOW,
        NOW + 5_000,
        [nonce; 32],
        TimePolicy::default(),
    )
    .unwrap()
}

#[test]
fn mptcp_paths_request_binds_original_session_nonce_expiry_and_transport() {
    let payload = request();
    payload.parent().unwrap();
    let bytes = signed(&payload, &key(31), 21);
    let mut replay = ReplayCache::new(4).unwrap();
    assert_eq!(
        verify_control_message::<MptcpPathsRequest>(
            &bytes,
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .unwrap()
        .message(),
        &payload
    );
    assert!(
        verify_control_message::<MptcpPathsRequest>(
            &bytes,
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .is_err()
    );
    assert_ne!(
        mptcp_paths_request_hash(&bytes),
        mptcp_paths_request_hash(&signed(&payload, &key(31), 22))
    );
    for (signer, expiry) in [(key(30), NOW + 5_000), (key(31), NOW + 5_001)] {
        assert!(
            sign_control_message(
                &payload,
                &signer,
                NOW,
                expiry,
                [21; 32],
                TimePolicy::default()
            )
            .is_err()
        );
    }
    assert!(
        verify_control_message::<MptcpPathsRequest>(
            &bytes,
            NOW + 5_000,
            TimePolicy::default(),
            &mut ReplayCache::new(1).unwrap(),
        )
        .is_err()
    );
    let mut parent = payload.parent().unwrap();
    parent.allowed_transports = vec![Transport::UdpSinglePath as i32];
    let wrong = MptcpPathsRequest {
        signed_exit_reservation: sign_control_message(
            &parent,
            &key(30),
            NOW,
            EXPIRY,
            [4; 32],
            TimePolicy::default(),
        )
        .unwrap(),
    };
    assert!(wrong.validate().is_err());
    assert!(
        MptcpPathsRequest {
            signed_exit_reservation: vec![0; 8193]
        }
        .validate()
        .is_err()
    );
    let mut noncanonical = payload;
    noncanonical.signed_exit_reservation.extend([0xf8, 0x07, 1]);
    assert!(noncanonical.validate().is_err());
}

fn state() -> MptcpPathsState {
    MptcpPathsState {
        request_sha256: mptcp_paths_request_hash(&signed(&request(), &key(31), 21)).to_vec(),
        route_context_id: vec![2; 16],
        reservation_id: vec![1; 16],
        exit_node_id: node_id(&key(30)),
        hard_expires_at_ms: EXPIRY,
        revision: 2,
        active_path_ids: vec![1, 2, 4],
        retired_path_ids: vec![3],
    }
}

#[test]
fn mptcp_paths_state_rejects_wrong_signer_replay_and_malformed_path_sets() {
    let payload = state();
    let encoded = signed(&payload, &key(30), 23);
    let mut replay = ReplayCache::new(2).unwrap();
    assert_eq!(
        verify_control_message::<MptcpPathsState>(
            &encoded,
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .unwrap()
        .message(),
        &payload
    );
    assert!(
        verify_control_message::<MptcpPathsState>(
            &encoded,
            NOW + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .is_err()
    );
    assert!(
        sign_control_message(
            &payload,
            &key(31),
            NOW,
            NOW + 5_000,
            [23; 32],
            TimePolicy::default()
        )
        .is_err()
    );
    for (active, retired) in [
        (vec![1], vec![]),
        (vec![1, 1], vec![]),
        (vec![2, 1], vec![]),
        (vec![0, 1], vec![]),
        (vec![1, 9], vec![]),
        (vec![1, 2], vec![2]),
        (vec![1, 2], vec![4, 3]),
        (vec![1, 2], vec![3, 3]),
    ] {
        let mut wrong = payload.clone();
        wrong.active_path_ids = active;
        wrong.retired_path_ids = retired;
        assert!(wrong.validate().is_err());
    }
    let mut expired = payload.clone();
    expired.hard_expires_at_ms = NOW + 4_999;
    assert!(
        sign_control_message(
            &expired,
            &key(30),
            NOW,
            NOW + 5_000,
            [23; 32],
            TimePolicy::default()
        )
        .is_err()
    );
    let mut corrupted: SignedEnvelope = decode_canonical(&encoded, 8192).unwrap();
    corrupted.signature[0] ^= 1;
    assert!(
        verify_control_message::<MptcpPathsState>(
            &encode_canonical(&corrupted, 8192).unwrap(),
            NOW + 1,
            TimePolicy::default(),
            &mut ReplayCache::new(1).unwrap(),
        )
        .is_err()
    );
}
