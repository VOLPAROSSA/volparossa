use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
    control_request::Operation, control_response::Payload, decode_request, decode_response,
    encode_request, encode_response,
};
use prost::Message;

const NOW: u64 = 1_000_000;

fn frame() -> PositionFrame {
    PositionFrame {
        kind: FrameKind::Wgs84Ecef as i32,
        local_frame_id: vec![],
    }
}

fn local_frame(id: u8) -> PositionFrame {
    PositionFrame {
        kind: FrameKind::LocalCartesian as i32,
        local_frame_id: vec![id; 16],
    }
}

fn observation(id: u8) -> PositionObservation {
    PositionObservation {
        observation_id: vec![id; 16],
        source_id: vec![id; 16],
        declared_independence_group: vec![id; 16],
        source_kind: SourceKind::Gnss as i32,
        frame: Some(frame()),
        x_metres: 6_378_137.0,
        y_metres: 0.0,
        z_metres: 0.0,
        supplied_radius_metres: 5.0,
        observed_at_unix_ms: NOW - 100,
        navigation_authentication: NavigationAuthentication::Unknown as i32,
    }
}

fn request(observations: Vec<PositionObservation>) -> DpsAssessRequest {
    DpsAssessRequest {
        dps_version: DPS_SERVICE_VERSION,
        desired_frame: Some(frame()),
        maximum_age_ms: 1000,
        observations,
    }
}

fn control(request: DpsAssessRequest) -> ControlRequest {
    ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![9; 16],
        operation: Some(Operation::DpsAssess(request)),
    }
}

fn assessed(request: &DpsAssessRequest) -> DpsAssessment {
    let assessment = request.assess(NOW).unwrap();
    assessment.validate().unwrap();
    assessment
}

#[test]
fn dps_request_and_response_use_golden_field_64_without_prototype_aliases() {
    // Protobuf-only fixtures deliberately omit application headers and validation.
    // Field 64, wire type 2, zero-length nested message: 82 04 00.
    // These empty messages prove field allocation, never valid service authority.
    let golden = [0x82, 0x04, 0x00];
    let request = ControlRequest {
        operation: Some(Operation::DpsAssess(DpsAssessRequest::default())),
        ..Default::default()
    };
    assert_eq!(request.encode_to_vec(), golden);
    assert_eq!(ControlRequest::decode(golden.as_slice()).unwrap(), request);
    let response = ControlResponse {
        payload: Some(Payload::DpsAssessment(DpsAssessment::default())),
        ..Default::default()
    };
    assert_eq!(response.encode_to_vec(), golden);
    assert_eq!(
        ControlResponse::decode(golden.as_slice()).unwrap(),
        response
    );

    // Unreleased prototype fields collide with retained Storage assignments.
    // They must never decode as DPS aliases; retained Storage may use them.
    let old_request = [0xf2, 0x02, 0x00]; // Field 46.
    let old_response = [0x92, 0x02, 0x00]; // Field 34.
    assert!(!matches!(
        ControlRequest::decode(old_request.as_slice())
            .unwrap()
            .operation,
        Some(Operation::DpsAssess(_))
    ));
    assert!(!matches!(
        ControlResponse::decode(old_response.as_slice())
            .unwrap()
            .payload,
        Some(Payload::DpsAssessment(_))
    ));
}

#[test]
fn dps_request_and_quality_response_roundtrip_in_existing_control_envelope() {
    let input = request(vec![observation(1)]);
    let wire = control(input.clone());
    assert_eq!(
        decode_request(&encode_request(&wire).unwrap()).unwrap(),
        wire
    );
    let quality = assessed(&input);
    assert_eq!(quality.status, AssessmentStatus::SingleClaim as i32);
    assert_eq!(quality.unverified_input_position, Some(observation(1)));
    assert_eq!(quality.maximum_age_ms, input.maximum_age_ms);
    let reply = ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![9; 16],
        result: ControlResult::Ok as i32,
        diagnostic_code: "DPS_ASSESSED".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::DpsAssessment(quality)),
    };
    assert_eq!(
        decode_response(&encode_response(&reply).unwrap()).unwrap(),
        reply
    );
}

#[test]
fn dps_structural_bounds_versions_and_source_group_binding_fail_closed() {
    let valid = request(vec![observation(1)]);
    let mut invalid_inputs = vec![];
    for version in [0, 2, u32::MAX] {
        invalid_inputs.push(DpsAssessRequest {
            dps_version: version,
            ..valid.clone()
        });
    }
    for maximum_age_ms in [0, MAX_DPS_AGE_MS + 1, u64::MAX] {
        invalid_inputs.push(DpsAssessRequest {
            maximum_age_ms,
            ..valid.clone()
        });
    }
    invalid_inputs.push(DpsAssessRequest {
        desired_frame: None,
        ..valid.clone()
    });
    invalid_inputs.push(request(vec![observation(1); MAX_DPS_OBSERVATIONS + 1]));
    invalid_inputs.push(request(vec![observation(1), observation(1)]));
    for kind in [FrameKind::Unspecified as i32, i32::MAX] {
        invalid_inputs.push(DpsAssessRequest {
            desired_frame: Some(PositionFrame {
                kind,
                local_frame_id: vec![],
            }),
            ..valid.clone()
        });
    }
    for bytes in [vec![], vec![1; 15], vec![1; 17], vec![1; 1000]] {
        let mut input = observation(1);
        input.source_id = bytes;
        invalid_inputs.push(request(vec![input]));
    }
    let mut bad = observation(1);
    bad.frame = None;
    invalid_inputs.push(request(vec![bad]));
    let mut bad = observation(1);
    bad.source_kind = SourceKind::Unspecified as i32;
    invalid_inputs.push(request(vec![bad]));
    let mut bad = observation(1);
    bad.source_kind = i32::MAX;
    invalid_inputs.push(request(vec![bad]));
    let mut bad = observation(1);
    bad.navigation_authentication = i32::MAX;
    invalid_inputs.push(request(vec![bad]));
    let mut bad = observation(1);
    bad.source_kind = SourceKind::Inertial as i32;
    bad.navigation_authentication = NavigationAuthentication::ClaimedAuthenticated as i32;
    invalid_inputs.push(request(vec![bad]));
    let mut same_source = observation(2);
    same_source.source_id = observation(1).source_id;
    invalid_inputs.push(request(vec![observation(1), same_source]));
    for input in invalid_inputs {
        assert!(input.assess(NOW).is_err());
        assert!(encode_request(&control(input)).is_err());
    }
    assert!(valid.assess(0).is_err());
}

#[test]
fn dps_empty_stale_future_missing_and_invalid_inputs_never_produce_a_position() {
    let empty = assessed(&request(vec![]));
    assert_eq!(empty.status, AssessmentStatus::Unavailable as i32);
    assert!(empty.unverified_input_position.is_none());
    assert_eq!(empty.declared_independence_groups, 0);
    let cases = [
        (NOW - 1001, ObservationDisposition::Stale),
        (NOW + 1, ObservationDisposition::FutureTimestamp),
        (0, ObservationDisposition::MissingTimestamp),
    ];
    for (observed_at_unix_ms, reason) in cases {
        let result = assessed(&request(vec![PositionObservation {
            observed_at_unix_ms,
            ..observation(1)
        }]));
        assert_eq!(result.status, AssessmentStatus::Unavailable as i32);
        assert_eq!(result.observations[0].disposition, reason as i32);
        assert!(result.unverified_input_position.is_none());
    }
    let boundary = assessed(&request(vec![PositionObservation {
        observed_at_unix_ms: NOW - 1000,
        ..observation(1)
    }]));
    assert_eq!(boundary.status, AssessmentStatus::SingleClaim as i32);
    assert_eq!(boundary.observations[0].claimed_age_ms, Some(1000));
    let maximum_time = request(vec![PositionObservation {
        observed_at_unix_ms: u64::MAX,
        ..observation(1)
    }])
    .assess(u64::MAX)
    .unwrap();
    assert_eq!(maximum_time.status, AssessmentStatus::SingleClaim as i32);
    maximum_time.validate().unwrap();
}

#[test]
fn dps_adversarial_geometry_is_excluded_without_nonfinite_distance_math() {
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        -f64::MAX,
        MAX_DPS_COMPONENT_METRES + 1.0,
    ] {
        for component in 0..3 {
            let mut input = observation(1);
            match component {
                0 => input.x_metres = value,
                1 => input.y_metres = value,
                _ => input.z_metres = value,
            }
            let result = assessed(&request(vec![input]));
            assert_eq!(
                result.observations[0].disposition,
                ObservationDisposition::InvalidGeometry as i32
            );
            assert!(result.unverified_input_position.is_none());
        }
    }
    for supplied_radius_metres in [
        f64::NAN,
        f64::INFINITY,
        0.0,
        -0.0,
        -1.0,
        f64::MAX,
        MAX_DPS_RADIUS_METRES + 1.0,
    ] {
        let result = assessed(&request(vec![PositionObservation {
            supplied_radius_metres,
            ..observation(1)
        }]));
        assert_eq!(
            result.observations[0].disposition,
            ObservationDisposition::InvalidGeometry as i32
        );
        assert!(result.unverified_input_position.is_none());
    }
    let largest = PositionObservation {
        x_metres: MAX_DPS_COMPONENT_METRES,
        y_metres: MAX_DPS_COMPONENT_METRES,
        z_metres: MAX_DPS_COMPONENT_METRES,
        supplied_radius_metres: MAX_DPS_RADIUS_METRES,
        ..observation(1)
    };
    let opposite = PositionObservation {
        x_metres: -MAX_DPS_COMPONENT_METRES,
        y_metres: -MAX_DPS_COMPONENT_METRES,
        z_metres: -MAX_DPS_COMPONENT_METRES,
        supplied_radius_metres: MAX_DPS_RADIUS_METRES,
        ..observation(2)
    };
    assert_eq!(
        assessed(&request(vec![largest, opposite])).status,
        AssessmentStatus::Conflict as i32
    );
}

#[test]
fn dps_relative_frames_do_not_establish_an_absolute_position_or_mix_local_origins() {
    let relative = PositionObservation {
        frame: Some(local_frame(1)),
        ..observation(1)
    };
    let other = PositionObservation {
        frame: Some(local_frame(2)),
        ..observation(2)
    };
    let absolute = observation(3);
    let result = assessed(&request(vec![relative.clone()]));
    assert_eq!(result.status, AssessmentStatus::Unavailable as i32);
    assert_eq!(
        result.observations[0].disposition,
        ObservationDisposition::DifferentFrame as i32
    );
    let result = assessed(&DpsAssessRequest {
        desired_frame: Some(local_frame(1)),
        ..request(vec![relative.clone(), other, absolute])
    });
    assert_eq!(result.status, AssessmentStatus::SingleClaim as i32);
    assert_eq!(result.unverified_input_position, Some(relative));
    assert_eq!(
        result
            .observations
            .iter()
            .filter(|item| item.disposition == ObservationDisposition::DifferentFrame as i32)
            .count(),
        2
    );
    let mut invalid = frame();
    invalid.local_frame_id = vec![1; 16];
    assert!(invalid.validate().is_err());
    assert!(
        PositionFrame {
            kind: FrameKind::LocalCartesian as i32,
            local_frame_id: vec![]
        }
        .validate()
        .is_err()
    );
}

#[test]
fn dps_correlated_duplicates_never_reduce_radius_or_hide_conflict() {
    let original = observation(1);
    let duplicate = PositionObservation {
        source_id: original.source_id.clone(),
        declared_independence_group: original.declared_independence_group.clone(),
        ..observation(2)
    };
    let result = assessed(&request(vec![original.clone(), duplicate.clone()]));
    assert_eq!(result.status, AssessmentStatus::ConsistentClaims as i32);
    assert_eq!(result.declared_independence_groups, 1);
    assert_eq!(result.unverified_input_position, Some(original.clone()));
    assert_eq!(result.limitations, LIMITATIONS);
    let conflict = PositionObservation {
        x_metres: original.x_metres + 11.0,
        ..duplicate
    };
    let result = assessed(&request(vec![original, conflict]));
    assert_eq!(result.status, AssessmentStatus::Conflict as i32);
    assert_eq!(result.declared_independence_groups, 1);
    assert_eq!(result.conflicts.len(), 1);
    assert!(result.unverified_input_position.is_none());
}

#[test]
fn dps_navigation_authentication_never_resolves_or_upgrades_physical_claims() {
    let gnss = PositionObservation {
        navigation_authentication: NavigationAuthentication::ClaimedAuthenticated as i32,
        ..observation(1)
    };
    let external = PositionObservation {
        x_metres: gnss.x_metres + 11.0,
        source_kind: SourceKind::FixedReference as i32,
        ..observation(2)
    };
    let result = assessed(&request(vec![gnss.clone(), external]));
    assert_eq!(result.status, AssessmentStatus::Conflict as i32);
    assert!(result.unverified_input_position.is_none());
    let result = assessed(&request(vec![gnss.clone()]));
    assert_eq!(result.status, AssessmentStatus::SingleClaim as i32);
    assert_eq!(result.unverified_input_position, Some(gnss));
    assert!(
        result
            .limitations
            .contains(&(AssessmentLimitation::PhysicalIntegrityUnverified as i32))
    );
    assert!(
        result
            .limitations
            .contains(&(AssessmentLimitation::PhysicalIndependenceUnverified as i32))
    );
}

#[test]
fn dps_ecef_antimeridian_and_poles_have_no_geographic_wrap_or_implied_reference_validation() {
    // Explicit synthetic ECEF fixtures near +/-180 degrees and the north pole.
    // No sensor, geodetic conversion, geographic anchor or real accuracy is tested.
    let west = PositionObservation {
        x_metres: -6_378_137.0,
        y_metres: -1.0,
        ..observation(1)
    };
    let east = PositionObservation {
        x_metres: -6_378_137.0,
        y_metres: 1.0,
        ..observation(2)
    };
    assert_eq!(
        assessed(&request(vec![west, east])).status,
        AssessmentStatus::ConsistentClaims as i32
    );
    let polar = PositionObservation {
        x_metres: 0.0,
        y_metres: 0.0,
        z_metres: 6_356_752.0,
        ..observation(1)
    };
    let adjacent = PositionObservation {
        x_metres: 1.0,
        y_metres: 0.0,
        z_metres: 6_356_752.0,
        ..observation(2)
    };
    assert_eq!(
        assessed(&request(vec![polar, adjacent])).status,
        AssessmentStatus::ConsistentClaims as i32
    );
}

fn permutations(
    inputs: &mut [PositionObservation],
    start: usize,
    results: &mut Vec<DpsAssessment>,
) {
    if start == inputs.len() {
        results.push(assessed(&request(inputs.to_vec())));
        return;
    }
    for index in start..inputs.len() {
        inputs.swap(start, index);
        permutations(inputs, start + 1, results);
        inputs.swap(start, index);
    }
}

#[test]
fn dps_input_permutations_produce_identical_selection_exclusions_and_all_conflicts() {
    let mut inputs = [
        observation(1),
        observation(2),
        PositionObservation {
            x_metres: observation(1).x_metres + 11.0,
            ..observation(3)
        },
        PositionObservation {
            observed_at_unix_ms: 0,
            ..observation(4)
        },
    ];
    let mut results = vec![];
    permutations(&mut inputs, 0, &mut results);
    assert_eq!(results.len(), 24);
    assert_eq!(results[0].conflicts.len(), 2);
    assert!(results.iter().all(|result| result == &results[0]));
    inputs[2].x_metres = observation(1).x_metres + 1.0;
    results.clear();
    permutations(&mut inputs, 0, &mut results);
    assert!(results.iter().all(|result| result == &results[0]));
    assert_eq!(results[0].unverified_input_position, Some(observation(1)));
}

#[test]
fn dps_no_state_or_position_carries_between_assessments() {
    let first = assessed(&request(vec![observation(1)]));
    let empty = assessed(&request(vec![]));
    let later = assessed(&request(vec![observation(2)]));
    assert!(empty.unverified_input_position.is_none());
    assert_eq!(empty.observations, [] as [ObservationAssessment; 0]);
    assert_eq!(later.unverified_input_position, Some(observation(2)));
    assert_ne!(
        first.unverified_input_position,
        later.unverified_input_position
    );
}

#[test]
fn dps_maximum_pairs_are_bounded_and_invalid_responses_fail_closed() {
    let inputs: Vec<_> = (1..=32)
        .map(|id| PositionObservation {
            x_metres: f64::from(id) * 100.0,
            ..observation(id)
        })
        .collect();
    let result = assessed(&request(inputs));
    assert_eq!(result.conflicts.len(), 496);
    let mut bad = result.clone();
    bad.unverified_input_position = Some(observation(1));
    assert!(bad.validate().is_err());
    let mut bad = result.clone();
    bad.limitations.clear();
    assert!(bad.validate().is_err());
    let mut bad = result.clone();
    bad.conflicts[0].second_observation_id = vec![99; 16];
    assert!(bad.validate().is_err());
    let mut bad = result;
    bad.declared_independence_groups = 100;
    assert!(bad.validate().is_err());
}

#[test]
fn dps_debug_redacts_coordinates_identifiers_frames_timestamps_and_quality() {
    let input = request(vec![observation(1)]);
    let result = assessed(&input);
    for debug in [
        format!("{input:?}"),
        format!("{result:?}"),
        format!("{:?}", input.observations[0]),
        format!("{:?}", control(input)),
        format!("{:?}", result.observations[0]),
        format!("{:?}", frame()),
    ] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("6378137"));
        assert!(!debug.contains("999900"));
        assert!(!debug.contains("Wgs84"));
        assert!(!debug.contains("supplied_radius_metres"));
    }
}

#[test]
fn dps_untrusted_quality_cannot_omit_limits_or_contradict_input_metadata_and_age() {
    let original = assessed(&request(vec![observation(1)]));
    let mut invalid_results = vec![];
    for status in [
        AssessmentStatus::Unavailable,
        AssessmentStatus::Conflict,
        AssessmentStatus::ConsistentClaims,
    ] {
        let mut bad = original.clone();
        bad.status = status as i32;
        invalid_results.push(bad);
    }
    let mut bad = original.clone();
    bad.unverified_input_position = None;
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.unverified_input_position.as_mut().unwrap().source_id = vec![9; 16];
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.unverified_input_position
        .as_mut()
        .unwrap()
        .navigation_authentication = NavigationAuthentication::ClaimedAuthenticated as i32;
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.observations[0].claimed_age_ms = None;
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.observations[0].claimed_age_ms = Some(original.maximum_age_ms + 1);
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.observations[0].disposition = ObservationDisposition::FutureTimestamp as i32;
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.maximum_age_ms = 0;
    invalid_results.push(bad);
    let mut bad = original.clone();
    bad.limitations.pop();
    invalid_results.push(bad);
    for bad in invalid_results {
        assert!(bad.validate().is_err());
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![9; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "DPS_ASSESSED".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::DpsAssessment(bad)),
        };
        assert!(encode_response(&response).is_err());
    }
    let correlated = PositionObservation {
        source_id: observation(1).source_id,
        declared_independence_group: observation(1).declared_independence_group,
        ..observation(2)
    };
    let mut bad = assessed(&request(vec![observation(1), correlated]));
    bad.observations[1].declared_independence_group = vec![9; 16];
    bad.declared_independence_groups = 2;
    assert!(bad.validate().is_err());
}
