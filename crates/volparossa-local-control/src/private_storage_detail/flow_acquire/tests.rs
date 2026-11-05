use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
    PrivateStorageChallengeDetail, PrivateStorageRemoteDetail, PrivateStorageRemoteRequest,
    control_request::Operation, control_response::Payload, decode_request, decode_response,
    encode_request, encode_response,
};

fn summary(stage: i32, reason: i32) -> PrivateStorageFlowAcquireDetail {
    let failure = PrivateStorageFlowAcquireFailure { stage, reason };
    PrivateStorageFlowAcquireDetail {
        rounds: 1,
        first: Some(failure),
        last: Some(failure),
    }
}

fn response() -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Unavailable as i32,
        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
        private_storage_remote_detail: Some(PrivateStorageRemoteDetail {
            stage: 6,
            deadline_scope: 0,
            tls_failure: None,
            stream_failure: Some(4),
            challenge: None,
            flow_acquire: Some(summary(5, 9)),
        }),
        payload: Some(Payload::Ack(Empty {})),
    }
}

fn validity(value: &ControlResponse, expected: bool) {
    assert_eq!(encode_response(value).is_ok(), expected);
    let decoded = decode_response(&value.encode_to_vec());
    assert_eq!(decoded.is_ok(), expected);
    if expected {
        assert_eq!(decoded.unwrap(), *value);
        assert!(value.encoded_len() < 128);
    }
}

#[test]
fn flow_acquire_wire_accepts_exactly_the_35_reachable_boundary_pairs() {
    // Independent numeric table binds the public discriminants, not validator logic.
    let allowed: [&[i32]; 8] = [
        &[1],
        &[5, 6, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19],
        &[2, 7],
        &[3, 4, 5],
        &[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        &[6],
        &[2, 6],
        &[2],
    ];
    let mut accepted = 0;
    for stage in 0..=8 {
        for reason in 0..=19 {
            let valid = stage > 0 && allowed[usize::try_from(stage - 1).unwrap()].contains(&reason);
            let mut value = response();
            value
                .private_storage_remote_detail
                .as_mut()
                .unwrap()
                .flow_acquire = Some(summary(stage, reason));
            validity(&value, valid);
            accepted += usize::from(valid);
        }
    }
    assert_eq!(accepted, 35);
}

#[test]
fn flow_acquire_wire_rejects_unknown_stage_and_reason_on_either_endpoint() {
    for first in [true, false] {
        for stage in [true, false] {
            for invalid in [i32::MIN, -1, 0, 20, 99, i32::MAX] {
                let mut detail = summary(5, 9);
                detail.rounds = 2;
                let endpoint = if first {
                    &mut detail.first
                } else {
                    &mut detail.last
                };
                if stage {
                    endpoint.as_mut().unwrap().stage = invalid;
                } else {
                    endpoint.as_mut().unwrap().reason = invalid;
                }
                assert!(detail.validate().is_err());
            }
        }
    }
}

#[test]
fn flow_acquire_wire_binds_rounds_and_requires_both_endpoints() {
    let mut detail = summary(5, 9);
    for rounds in 1..=8 {
        detail.rounds = rounds;
        detail.validate().unwrap();
        detail.last = Some(PrivateStorageFlowAcquireFailure {
            stage: 4,
            reason: 3,
        });
        assert_eq!(detail.validate().is_ok(), rounds != 1);
        detail.last = detail.first;
    }
    for rounds in [0, 9, u32::MAX] {
        detail.rounds = rounds;
        assert!(detail.validate().is_err());
    }
    for (first, last) in [(None, detail.last), (detail.first, None), (None, None)] {
        assert!(
            PrivateStorageFlowAcquireDetail {
                rounds: 2,
                first,
                last,
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn flow_acquire_wire_requires_stream_open_without_enclosing_deadline() {
    for stage in 0..=8 {
        for deadline_scope in 0..=2 {
            for stream_failure in [None, Some(0), Some(1), Some(4), Some(10), Some(99)] {
                let mut value = response();
                let detail = value.private_storage_remote_detail.as_mut().unwrap();
                detail.stage = stage;
                detail.deadline_scope = deadline_scope;
                detail.stream_failure = stream_failure;
                validity(
                    &value,
                    stage == 6 && deadline_scope == 0 && stream_failure == Some(4),
                );
            }
        }
    }
    let mut value = response();
    value
        .private_storage_remote_detail
        .as_mut()
        .unwrap()
        .tls_failure = Some(6);
    validity(&value, false);
    let mut value = response();
    value
        .private_storage_remote_detail
        .as_mut()
        .unwrap()
        .challenge = Some(PrivateStorageChallengeDetail {
        read: None,
        phase: 1,
        before_challenge: 1,
        in_challenge: 1,
    });
    validity(&value, false);
}

#[test]
fn flow_acquire_wire_requires_original_unavailable_rejection_and_ack() {
    for (result, code) in [
        (ControlResult::Ok, "CONTENT_OK"),
        (ControlResult::InvalidRequest, "CONTENT_INVALID"),
        (ControlResult::InvalidState, "CONTENT_BUSY"),
        (ControlResult::Policy, "CONTENT_POLICY"),
        (ControlResult::Unavailable, "PRIVATE-ERROR-CANARY"),
        (ControlResult::Ok, "CONTENT_UNAVAILABLE"),
    ] {
        let mut value = response();
        value.result = result as i32;
        value.diagnostic_code = code.into();
        validity(&value, false);
    }
    for payload in [
        None,
        Some(Payload::Status(crate::StatusSnapshot::default())),
    ] {
        let mut value = response();
        value.payload = payload;
        validity(&value, false);
    }
}

#[test]
fn flow_acquire_request_default_is_the_exact_historical_wire() {
    #[derive(Clone, PartialEq, Message)]
    struct PreviousRequest {
        #[prost(bytes = "vec", tag = "1")]
        provider_key: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        grant: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        maintenance_turn: Vec<u8>,
    }
    for maintenance_turn in [vec![], vec![2; 32]] {
        let original = PreviousRequest {
            provider_key: ed25519_dalek::SigningKey::from_bytes(&[29; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            grant: vec![1; 128],
            maintenance_turn,
        };
        let wire = original.encode_to_vec();
        let mut request = PrivateStorageRemoteRequest::decode(wire.as_slice()).unwrap();
        assert!(!request.include_flow_acquire_detail);
        request.validate().unwrap();
        assert_eq!(request.encode_to_vec(), wire);
        request.include_flow_acquire_detail = true;
        let mut selected = wire;
        selected.extend_from_slice(&[32, 1]); // bool tag4, true; no new operation.
        assert_eq!(request.encode_to_vec(), selected);
        assert_eq!(
            PreviousRequest::decode(selected.as_slice()).unwrap(),
            original
        );
        let envelope = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![8; 16],
            operation: Some(Operation::PrivateStorageRemote(request)),
        };
        assert_eq!(
            decode_request(&encode_request(&envelope).unwrap()).unwrap(),
            envelope
        );
    }
}

#[test]
fn flow_acquire_optional_tag_six_preserves_historical_detail_goldens() {
    for wire in [
        vec![8, 3],                            // provider lookup.
        vec![8, 7, 24, 6],                     // TLS I/O.
        vec![8, 6, 32, 4],                     // Existing undifferentiated flow acquisition.
        vec![8, 8, 42, 6, 8, 3, 16, 1, 24, 8], // Challenge with coarse buckets.
    ] {
        let detail = PrivateStorageRemoteDetail::decode(wire.as_slice()).unwrap();
        detail.validate().unwrap();
        assert!(detail.flow_acquire.is_none());
        assert_eq!(detail.encode_to_vec(), wire);
    }
    let detail = response().private_storage_remote_detail.unwrap();
    let expected = vec![
        8, 6, 32, 4, 50, 14, 8, 1, 18, 4, 8, 5, 16, 9, 26, 4, 8, 5, 16, 9,
    ];
    assert_eq!(detail.encode_to_vec(), expected);
    assert_eq!(
        PrivateStorageRemoteDetail::decode(expected.as_slice()).unwrap(),
        detail
    );
}
