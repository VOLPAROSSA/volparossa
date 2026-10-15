use super::*;
use crate::{CONTROL_PROTOCOL_VERSION, Empty, decode_response, encode_response};

mod challenge;

fn rejected() -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Unavailable as i32,
        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
        private_storage_remote_detail: Some(PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: PrivateStorageRemoteStage::ProviderLookup as i32,
            deadline_scope: PrivateStorageDeadlineScope::None as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: None,
        }),
        payload: Some(Payload::Ack(Empty {})),
    }
}

#[test]
fn private_storage_detail_is_additive_to_the_original_ack_wire() {
    #[derive(Clone, PartialEq, Message)]
    struct OriginalResponse {
        #[prost(uint32, tag = "1")]
        protocol_version: u32,
        #[prost(bytes = "vec", tag = "2")]
        request_id: Vec<u8>,
        #[prost(enumeration = "ControlResult", tag = "3")]
        result: i32,
        #[prost(string, tag = "4")]
        diagnostic_code: String,
        #[prost(message, optional, tag = "10")]
        ack: Option<Empty>,
    }
    let original = OriginalResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Unavailable as i32,
        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
        ack: Some(Empty {}),
    };
    let old_wire = original.encode_to_vec();
    let old = decode_response(&old_wire).unwrap();
    assert!(old.private_storage_remote_detail.is_none());
    assert_eq!(encode_response(&old).unwrap(), old_wire);
    let new = rejected();
    let new_wire = encode_response(&new).unwrap();
    assert_eq!(decode_response(&new_wire).unwrap(), new);
    // The previous schema still observes exactly the same result, code and Ack.
    assert_eq!(
        OriginalResponse::decode(new_wire.as_slice()).unwrap(),
        original
    );
}

#[test]
fn private_storage_detail_rejects_unknown_enums_success_payload_and_code_mismatch() {
    for field in ["stage", "deadline"] {
        let mut response = rejected();
        let detail = response.private_storage_remote_detail.as_mut().unwrap();
        if field == "stage" {
            detail.stage = 99;
        } else {
            detail.deadline_scope = 99;
        }
        assert!(encode_response(&response).is_err());
        assert!(decode_response(&response.encode_to_vec()).is_err());
    }
    for (result, code) in [
        (ControlResult::Ok, "CONTENT_OK"),
        (ControlResult::Unavailable, "PRIVATE_UNLISTED_CODE"),
        (ControlResult::Unavailable, "CONTENT_BUSY"),
        (ControlResult::InvalidState, "CONTENT_NAME_CONFLICT"),
    ] {
        let mut response = rejected();
        response.result = result as i32;
        response.diagnostic_code = code.into();
        assert!(encode_response(&response).is_err());
    }
    let mut response = rejected();
    response.payload = Some(Payload::Status(crate::StatusSnapshot::default()));
    assert!(encode_response(&response).is_err());
    for (result, code) in [
        (ControlResult::InvalidRequest, "CONTENT_INVALID"),
        (ControlResult::Unavailable, "CONTENT_UNAVAILABLE"),
        (ControlResult::InvalidState, "CONTENT_BUSY"),
        (ControlResult::Policy, "CONTENT_POLICY"),
    ] {
        response = rejected();
        response.result = result as i32;
        response.diagnostic_code = code.into();
        assert!(encode_response(&response).is_ok());
    }
}

#[test]
fn private_storage_detail_has_only_closed_bounded_stage_and_deadline_values() {
    for stage in 0..=8 {
        for deadline_scope in 0..=2 {
            let mut response = rejected();
            response.private_storage_remote_detail = Some(PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage,
                deadline_scope,
                tls_failure: None,
                stream_failure: None,
                challenge: None,
            });
            let allowed = match deadline_scope {
                0 => stage != 0,
                1 => true,
                2 => stage >= 6,
                _ => unreachable!(),
            };
            let wire = encode_response(&response);
            assert_eq!(wire.is_ok(), allowed);
            if let Ok(wire) = wire {
                assert!(wire.len() < 80);
                assert_eq!(decode_response(&wire).unwrap(), response);
            }
            response.diagnostic_code = "CONTENT_POLICY".into();
            response.result = ControlResult::Policy as i32;
            assert_eq!(
                encode_response(&response).is_ok(),
                allowed && deadline_scope == 0
            );
        }
    }
}

#[test]
fn optional_tls_failure_preserves_original_detail_wire_and_old_reader() {
    #[derive(Clone, PartialEq, Message)]
    struct OriginalDetail {
        #[prost(enumeration = "PrivateStorageRemoteStage", tag = "1")]
        stage: i32,
        #[prost(enumeration = "PrivateStorageDeadlineScope", tag = "2")]
        deadline_scope: i32,
    }
    let original = OriginalDetail {
        stage: PrivateStorageRemoteStage::TlsHandshake as i32,
        deadline_scope: PrivateStorageDeadlineScope::None as i32,
    };
    let wire = original.encode_to_vec();
    let mut detail = PrivateStorageRemoteDetail::decode(wire.as_slice()).unwrap();
    assert_eq!(detail.tls_failure, None);
    assert_eq!(detail.encode_to_vec(), wire);
    for failure in 1..=6 {
        detail.tls_failure = Some(failure);
        detail.validate().unwrap();
        let wire = detail.encode_to_vec();
        assert!(wire.len() <= 6);
        assert_eq!(OriginalDetail::decode(wire.as_slice()).unwrap(), original);
        assert_eq!(
            PrivateStorageRemoteDetail::decode(wire.as_slice()).unwrap(),
            detail
        );
    }
}

fn tls_rejected(failure: i32) -> ControlResponse {
    let mut response = rejected();
    response.private_storage_remote_detail = Some(PrivateStorageRemoteDetail {
        flow_acquire: None,
        stage: PrivateStorageRemoteStage::TlsHandshake as i32,
        deadline_scope: PrivateStorageDeadlineScope::None as i32,
        tls_failure: Some(failure),
        stream_failure: None,
        challenge: None,
    });
    response
}

fn assert_response_validity(response: &ControlResponse, allowed: bool) {
    assert_eq!(encode_response(response).is_ok(), allowed);
    let decoded = decode_response(&response.encode_to_vec());
    assert_eq!(decoded.is_ok(), allowed);
    if allowed {
        assert_eq!(decoded.unwrap(), *response);
        assert!(response.encoded_len() < 80);
    }
}

#[test]
fn tls_failure_roundtrips_only_six_closed_nonzero_values() {
    for failure in 1..=6 {
        assert_response_validity(&tls_rejected(failure), true);
    }
    for failure in [i32::MIN, -1, 0, 7, 99, i32::MAX] {
        assert_response_validity(&tls_rejected(failure), false);
    }
}

#[test]
fn tls_failure_requires_handshake_boundary_without_an_enclosing_deadline() {
    for failure in 1..=6 {
        for stage in 0..=8 {
            for deadline_scope in 0..=2 {
                let mut response = tls_rejected(failure);
                response.private_storage_remote_detail = Some(PrivateStorageRemoteDetail {
                    flow_acquire: None,
                    stage,
                    deadline_scope,
                    tls_failure: Some(failure),
                    stream_failure: None,
                    challenge: None,
                });
                let allowed = stage == PrivateStorageRemoteStage::TlsHandshake as i32
                    && deadline_scope == PrivateStorageDeadlineScope::None as i32;
                assert_response_validity(&response, allowed);
            }
        }
    }
}

#[test]
fn tls_failure_rejects_success_other_failure_codes_and_non_ack_payloads() {
    for failure in 1..=6 {
        for (result, code) in [
            (ControlResult::Ok, "CONTENT_OK"),
            (ControlResult::InvalidRequest, "CONTENT_INVALID"),
            (ControlResult::InvalidState, "CONTENT_BUSY"),
            (ControlResult::Policy, "CONTENT_POLICY"),
            (ControlResult::Unavailable, "PRIVATE_UNLISTED_CODE"),
            (ControlResult::Unavailable, "CONTENT_BUSY"),
            (ControlResult::Ok, "CONTENT_UNAVAILABLE"),
        ] {
            let mut response = tls_rejected(failure);
            response.result = result as i32;
            response.diagnostic_code = code.into();
            assert_response_validity(&response, false);
        }
        for payload in [
            None,
            Some(Payload::Status(crate::StatusSnapshot::default())),
        ] {
            let mut response = tls_rejected(failure);
            response.payload = payload;
            assert_response_validity(&response, false);
        }
    }
}

fn stream_rejected(failure: i32) -> ControlResponse {
    let mut response = rejected();
    response.private_storage_remote_detail = Some(PrivateStorageRemoteDetail {
        flow_acquire: None,
        stage: PrivateStorageRemoteStage::StreamOpen as i32,
        deadline_scope: PrivateStorageDeadlineScope::None as i32,
        tls_failure: None,
        stream_failure: Some(failure),
        challenge: None,
    });
    response
}

#[test]
fn stream_failure_is_additive_and_old_detail_reader_keeps_original_fields() {
    #[derive(Clone, PartialEq, Message)]
    struct TlsDetail {
        #[prost(enumeration = "PrivateStorageRemoteStage", tag = "1")]
        stage: i32,
        #[prost(enumeration = "PrivateStorageDeadlineScope", tag = "2")]
        deadline_scope: i32,
        #[prost(enumeration = "PrivateStorageTlsFailure", optional, tag = "3")]
        tls_failure: Option<i32>,
    }
    let old = TlsDetail {
        stage: PrivateStorageRemoteStage::StreamOpen as i32,
        deadline_scope: PrivateStorageDeadlineScope::None as i32,
        tls_failure: None,
    };
    let old_wire = old.encode_to_vec();
    let current = PrivateStorageRemoteDetail::decode(old_wire.as_slice()).unwrap();
    assert_eq!(current.stream_failure, None);
    assert_eq!(current.encode_to_vec(), old_wire);
    for failure in 1..=10 {
        let response = stream_rejected(failure);
        assert_response_validity(&response, true);
        let wire = response
            .private_storage_remote_detail
            .unwrap()
            .encode_to_vec();
        assert_eq!(TlsDetail::decode(wire.as_slice()).unwrap(), old);
    }
}

#[test]
fn stream_failure_requires_exact_boundary_code_and_no_enclosing_deadline() {
    for failure in 1..=10 {
        for stage in 0..=8 {
            for deadline in 0..=2 {
                let mut response = stream_rejected(failure);
                let detail = response.private_storage_remote_detail.as_mut().unwrap();
                detail.stage = stage;
                detail.deadline_scope = deadline;
                assert_response_validity(
                    &response,
                    stage == PrivateStorageRemoteStage::StreamOpen as i32 && deadline == 0,
                );
            }
        }
        for (result, code) in [
            (ControlResult::Ok, "CONTENT_OK"),
            (ControlResult::Policy, "CONTENT_POLICY"),
            (ControlResult::InvalidRequest, "CONTENT_INVALID"),
            (ControlResult::InvalidState, "CONTENT_BUSY"),
        ] {
            let mut response = stream_rejected(failure);
            response.result = result as i32;
            response.diagnostic_code = code.into();
            assert_response_validity(&response, false);
        }
    }
}

#[test]
fn stream_failure_rejects_unknown_values_tls_combination_and_non_ack() {
    for failure in [i32::MIN, -1, 0, 11, 99, i32::MAX] {
        assert_response_validity(&stream_rejected(failure), false);
    }
    let mut response = stream_rejected(PrivateStorageStreamFailure::TransportTls as i32);
    response
        .private_storage_remote_detail
        .as_mut()
        .unwrap()
        .tls_failure = Some(PrivateStorageTlsFailure::Io as i32);
    assert_response_validity(&response, false);
    for payload in [
        None,
        Some(Payload::Status(crate::StatusSnapshot::default())),
    ] {
        let mut response = stream_rejected(PrivateStorageStreamFailure::FlowAcquire as i32);
        response.payload = payload;
        assert_response_validity(&response, false);
    }
}
