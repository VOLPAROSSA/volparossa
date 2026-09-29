use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, control_request::Operation, decode_request,
    encode_request,
};

#[test]
fn local_named_fetch_has_explicit_bounds_and_no_remote_or_cache_options() {
    let named = ContentLocalFetchNameRequest {
        publisher_key: vec![2; 32],
        name: "policy-request".into(),
        min_revision: 1,
        expected_content_type: "application/vnd.volparossa.policy-request.v1".into(),
        max_object_bytes: 2 * 1024 * 1024 + 8192 + 32,
    };
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![3; 16],
        operation: Some(Operation::ContentLocalFetchName(named.clone())),
    };
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    for bytes in [0, 256 * 1024 * 1024 + 1] {
        assert!(
            ContentLocalFetchNameRequest {
                max_object_bytes: bytes,
                ..named.clone()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        ContentLocalFetchNameRequest {
            min_revision: 0,
            ..named.clone()
        }
        .validate()
        .is_err()
    );
    for value in ["", "text/plain\nprivate", &"x".repeat(129)] {
        assert!(
            ContentLocalFetchNameRequest {
                expected_content_type: value.into(),
                ..named.clone()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        ContentLocalFetchNameRequest {
            publisher_key: vec![2; 31],
            ..named
        }
        .validate()
        .is_err()
    );
}
