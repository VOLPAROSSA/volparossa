use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
    control_request::Operation, control_response::Payload, decode_request, decode_response,
    encode_request, encode_response,
};

fn key(seed: u8) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn discovery() -> ComputeDiscoverRequest {
    ComputeDiscoverRequest {
        publisher_keys: vec![key(1), key(2)],
        model_fingerprint: None,
        model_profile: None,
        require_task_derivation_v1: true,
        require_document_inference_v2: true,
        require_derived_inference_v3: true,
        maximum: 4,
        minimum: 0,
    }
}

#[test]
fn bounded_discovery_roundtrip_retains_exact_requirements() {
    assert_eq!(discovery().effective_minimum(), 2);
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![1; 16],
        operation: Some(Operation::ComputeDiscover(discovery())),
    };
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    let query = discovery().eligibility().unwrap();
    assert_eq!(query.publisher_keys.len(), 2);
    assert!(
        query.require_task_derivation_v1
            && query.require_document_inference_v2
            && query.require_derived_inference_v3
    );
    for variant in 0..6 {
        let mut invalid = discovery();
        match variant {
            0 => invalid.maximum = 1,
            1 => invalid.maximum = 5,
            2 => invalid.publisher_keys.push(key(1)),
            3 => invalid.publisher_keys[0] = vec![0; 32],
            4 => invalid.publisher_keys = vec![key(1); 33],
            _ => invalid.model_fingerprint = Some("A".repeat(64)),
        }
        let mut rejected = request.clone();
        rejected.operation = Some(Operation::ComputeDiscover(invalid));
        assert!(encode_request(&rejected).is_err());
    }
}

#[test]
fn explicit_single_replacement_does_not_change_legacy_initial_minimum() {
    let legacy = ComputeDiscoverRequest::decode(discovery().encode_to_vec().as_slice()).unwrap();
    assert_eq!(legacy.minimum, 0);
    assert_eq!(legacy.effective_minimum(), 2);
    assert!(legacy.eligibility().is_ok());
    let recovery = ComputeDiscoverRequest {
        minimum: 1,
        maximum: 1,
        ..legacy.clone()
    };
    let decoded = ComputeDiscoverRequest::decode(recovery.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, recovery);
    assert_eq!(decoded.effective_minimum(), 1);
    assert!(decoded.eligibility().is_ok());
    for (minimum, maximum) in [(0, 1), (2, 1), (5, 4), (1, 0), (1, 5)] {
        let rejected = ComputeDiscoverRequest {
            maximum,
            minimum,
            ..legacy.clone()
        };
        assert!(rejected.eligibility().is_err());
    }
}

#[test]
fn discovery_base_profile_tag_eight_preserves_absent_frames_and_reaches_eligibility() {
    let legacy = discovery();
    let legacy_bytes = legacy.encode_to_vec();
    let decoded = ComputeDiscoverRequest::decode(legacy_bytes.as_slice()).unwrap();
    assert_eq!(decoded.model_profile, None);
    assert_eq!(decoded.eligibility().unwrap().model_profile, None);
    for profile in ["smollm2-135m-v1", "smollm2-360m-v1"] {
        let mut selected = legacy.clone();
        selected.model_profile = Some(profile.into());
        let mut expected = legacy_bytes.clone();
        expected.extend_from_slice(&[0x42, u8::try_from(profile.len()).unwrap()]);
        expected.extend_from_slice(profile.as_bytes());
        assert_eq!(selected.encode_to_vec(), expected);
        let decoded = ComputeDiscoverRequest::decode(expected.as_slice()).unwrap();
        assert_eq!(decoded, selected);
        assert_eq!(
            decoded.eligibility().unwrap().model_profile.as_deref(),
            Some(profile)
        );
    }
    for profile in ["", "smollm2-360m", "SMOLLM2-135M-V1"] {
        let mut invalid = legacy.clone();
        invalid.model_profile = Some(profile.into());
        assert!(invalid.eligibility().is_err());
    }
}

#[test]
fn discovered_frame_rejects_duplicate_mixed_or_unbounded_observations() {
    // Structural local-control fixture only: the agent separately verifies the pinned profile.
    let caps = serde_json::json!({
        "model":{"model_id":"fixture","model_revision":"fixture",
            "base_weights":{"bytes":1,"sha256":"a".repeat(64)},"adapter_files":null},
        "model_fingerprint":"b".repeat(64),"accepting_work":true,
        "public_inference_only":true,"runtime_slots":1,"max_threads":2,
        "max_job_seconds":600,"max_dataset_bytes":1_048_576,"max_rows":4,
    })
    .to_string();
    let mut discovered = ComputeDiscovered {
        providers: vec![
            ComputeDiscoveredProvider {
                provider_key: key(1),
                capabilities_json: caps.clone(),
            },
            ComputeDiscoveredProvider {
                provider_key: key(2),
                capabilities_json: caps,
            },
        ],
    };
    let response = ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![1; 16],
        result: ControlResult::Ok.into(),
        diagnostic_code: "COMPUTE_DISCOVERED".into(),
        payload: Some(Payload::ComputeDiscovered(discovered.clone())),
    };
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );
    discovered.providers[1].provider_key = key(1);
    assert!(discovered.validate().is_err());
    discovered.providers[1].provider_key = key(2);
    discovered.providers[1].capabilities_json = discovered.providers[1]
        .capabilities_json
        .replace(&"b".repeat(64), &"c".repeat(64));
    assert!(discovered.validate().is_err());
    discovered.providers[1].capabilities_json = "x".repeat(16 * 1024 + 1);
    assert!(discovered.validate().is_err());
}
