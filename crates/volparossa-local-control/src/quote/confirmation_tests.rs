use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, MAX_CONTROL_FRAME,
    control_request::Operation, control_response::Payload,
};

fn attach() -> QuoteAttachRequest {
    QuoteAttachRequest {
        bind_address: "127.0.0.1:8443".into(),
        advertised_hostname: "provider.example".into(),
        requester_key: vec![1; 32],
        expires_at: 1000,
        maximum_attempts: 1,
        confirmation_version: None,
    }
}

fn request(operation: Operation) -> ControlRequest {
    ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![3; 16],
        operation: Some(operation),
    }
}

fn response(ready: QuoteReady) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![3; 16],
        result: ControlResult::Ok.into(),
        diagnostic_code: "QUOTE_READY".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::QuoteReady(ready)),
    }
}

#[test]
fn quote_confirmation_absent_fields_preserve_all_three_legacy_encodings() {
    let mut expected = vec![10, 14];
    expected.extend_from_slice(b"127.0.0.1:8443");
    expected.extend_from_slice(&[18, 16]);
    expected.extend_from_slice(b"provider.example");
    expected.extend_from_slice(&[26, 32]);
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[32, 232, 7, 40, 1]);
    assert_eq!(attach().encode_to_vec(), expected);
    let remote = QuoteRemoteRequest {
        provider_key: vec![1; 32],
        confirmation_version: None,
    };
    let mut expected = vec![10, 32];
    expected.extend_from_slice(&[1; 32]);
    assert_eq!(remote.encode_to_vec(), expected);
    let ready = QuoteReady {
        provider_key: vec![1; 32],
        requester_key: vec![2; 32],
        confirmation_version: None,
    };
    expected.extend_from_slice(&[18, 32]);
    expected.extend_from_slice(&[2; 32]);
    assert_eq!(ready.encode_to_vec(), expected);
    assert_eq!(QuoteReady::decode(expected.as_slice()).unwrap(), ready);
}

#[test]
fn quote_confirmation_mode_is_explicit_and_roundtrips_in_request_and_ready() {
    for operation in [
        Operation::QuoteAttach(QuoteAttachRequest {
            confirmation_version: Some(1),
            ..attach()
        }),
        Operation::QuoteRemote(QuoteRemoteRequest {
            provider_key: vec![1; 32],
            confirmation_version: Some(1),
        }),
    ] {
        let request = request(operation);
        let encoded = crate::encode_request(&request).unwrap();
        assert_eq!(crate::decode_request(&encoded).unwrap(), request);
    }
    let response = response(QuoteReady {
        provider_key: vec![1; 32],
        requester_key: vec![2; 32],
        confirmation_version: Some(1),
    });
    let encoded = crate::encode_response(&response).unwrap();
    assert_eq!(crate::decode_response(&encoded).unwrap(), response);
}

#[test]
fn quote_confirmation_unknown_or_explicit_zero_version_is_not_legacy() {
    for version in [0, 2, u32::MAX] {
        for operation in [
            Operation::QuoteAttach(QuoteAttachRequest {
                confirmation_version: Some(version),
                ..attach()
            }),
            Operation::QuoteRemote(QuoteRemoteRequest {
                provider_key: vec![1; 32],
                confirmation_version: Some(version),
            }),
        ] {
            let request = request(operation);
            assert!(crate::encode_request(&request).is_err());
            assert!(crate::decode_request(&request.encode_to_vec()).is_err());
        }
        let response = response(QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: Some(version),
        });
        assert!(crate::encode_response(&response).is_err());
        assert!(crate::decode_response(&response.encode_to_vec()).is_err());
    }
}

#[tokio::test]
async fn quote_confirmation_control_framing_rejects_bad_lengths_eof_and_outer_version() {
    let request = request(Operation::QuoteRemote(QuoteRemoteRequest {
        provider_key: vec![1; 32],
        confirmation_version: Some(1),
    }));
    let payload = crate::encode_request(&request).unwrap();
    let mut valid = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    valid.extend_from_slice(&payload);
    assert_eq!(
        crate::read_request(&mut valid.as_slice()).await.unwrap(),
        request
    );
    let mut invalid_version = request.clone();
    invalid_version.protocol_version = CONTROL_PROTOCOL_VERSION + 1;
    assert!(crate::decode_request(&invalid_version.encode_to_vec()).is_err());
    for frame in [
        Vec::new(),
        vec![0, 0, 0],
        vec![0; 4],
        u32::try_from(MAX_CONTROL_FRAME + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
        valid[..valid.len() - 1].to_vec(),
    ] {
        assert!(crate::read_request(&mut frame.as_slice()).await.is_err());
        assert!(crate::read_response(&mut frame.as_slice()).await.is_err());
    }
}
