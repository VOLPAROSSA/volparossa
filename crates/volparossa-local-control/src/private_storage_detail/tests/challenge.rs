use super::*;

fn challenge_rejected() -> ControlResponse {
    let mut response = rejected();
    let detail = response.private_storage_remote_detail.as_mut().unwrap();
    detail.stage = PrivateStorageRemoteStage::Challenge as i32;
    detail.challenge = Some(PrivateStorageChallengeDetail {
        phase: PrivateStorageChallengePhase::SelectorWriteFlush as i32,
        before_challenge: PrivateStorageElapsedBucket::Under1s as i32,
        in_challenge: PrivateStorageElapsedBucket::Under1s as i32,
    });
    response
}

#[test]
fn challenge_observation_is_additive_and_preserves_absent_field_bytes() {
    #[derive(Clone, PartialEq, Message)]
    struct PreviousDetail {
        #[prost(enumeration = "PrivateStorageRemoteStage", tag = "1")]
        stage: i32,
        #[prost(enumeration = "PrivateStorageDeadlineScope", tag = "2")]
        deadline_scope: i32,
        #[prost(enumeration = "PrivateStorageTlsFailure", optional, tag = "3")]
        tls_failure: Option<i32>,
        #[prost(enumeration = "PrivateStorageStreamFailure", optional, tag = "4")]
        stream_failure: Option<i32>,
    }
    let original = PreviousDetail {
        stage: PrivateStorageRemoteStage::Challenge as i32,
        deadline_scope: PrivateStorageDeadlineScope::Operation as i32,
        tls_failure: None,
        stream_failure: None,
    };
    let old_wire = original.encode_to_vec();
    let mut detail = PrivateStorageRemoteDetail::decode(old_wire.as_slice()).unwrap();
    assert!(detail.challenge.is_none());
    detail.validate().unwrap();
    assert_eq!(detail.encode_to_vec(), old_wire);
    detail.challenge = challenge_rejected()
        .private_storage_remote_detail
        .unwrap()
        .challenge;
    detail.validate().unwrap();
    assert_eq!(
        PreviousDetail::decode(detail.encode_to_vec().as_slice()).unwrap(),
        original
    );
}

#[test]
fn challenge_observation_accepts_only_three_phases_eight_buckets_and_challenge_scope() {
    for phase in 1..=3 {
        for before_challenge in 1..=8 {
            for in_challenge in 1..=8 {
                for deadline in 0..=2 {
                    let mut response = challenge_rejected();
                    let detail = response.private_storage_remote_detail.as_mut().unwrap();
                    detail.deadline_scope = deadline;
                    detail.challenge = Some(PrivateStorageChallengeDetail {
                        phase,
                        before_challenge,
                        in_challenge,
                    });
                    assert_response_validity(&response, true);
                }
            }
        }
    }
    for stage in 0..=8 {
        let mut response = challenge_rejected();
        response
            .private_storage_remote_detail
            .as_mut()
            .unwrap()
            .stage = stage;
        assert_response_validity(
            &response,
            stage == PrivateStorageRemoteStage::Challenge as i32,
        );
    }
}

#[test]
fn challenge_observation_rejects_unknown_or_unpopulated_fields() {
    for field in ["phase", "before", "during"] {
        for value in [i32::MIN, -1, 0, 9, 99, i32::MAX] {
            let mut response = challenge_rejected();
            let challenge = response
                .private_storage_remote_detail
                .as_mut()
                .unwrap()
                .challenge
                .as_mut()
                .unwrap();
            match field {
                "phase" => challenge.phase = value,
                "before" => challenge.before_challenge = value,
                _ => challenge.in_challenge = value,
            }
            assert_response_validity(&response, false);
        }
    }
    for phase in 4..=8 {
        let mut response = challenge_rejected();
        response
            .private_storage_remote_detail
            .as_mut()
            .unwrap()
            .challenge
            .as_mut()
            .unwrap()
            .phase = phase;
        assert_response_validity(&response, false);
    }
}

#[test]
fn challenge_observation_rejects_tls_stream_other_codes_and_non_ack() {
    for tls in [true, false] {
        let mut response = challenge_rejected();
        let detail = response.private_storage_remote_detail.as_mut().unwrap();
        if tls {
            detail.tls_failure = Some(PrivateStorageTlsFailure::Io as i32);
        } else {
            detail.stream_failure = Some(PrivateStorageStreamFailure::FlowAcquire as i32);
        }
        assert_response_validity(&response, false);
    }
    for (result, code) in [
        (ControlResult::Ok, "CONTENT_OK"),
        (ControlResult::InvalidRequest, "CONTENT_INVALID"),
        (ControlResult::InvalidState, "CONTENT_BUSY"),
        (ControlResult::Policy, "CONTENT_POLICY"),
        (ControlResult::Unavailable, "PRIVATE_UNLISTED_CODE"),
        (ControlResult::Ok, "CONTENT_UNAVAILABLE"),
    ] {
        let mut response = challenge_rejected();
        response.result = result as i32;
        response.diagnostic_code = code.into();
        assert_response_validity(&response, false);
    }
    let mut response = challenge_rejected();
    response.payload = Some(Payload::Status(crate::StatusSnapshot::default()));
    assert_response_validity(&response, false);
}
