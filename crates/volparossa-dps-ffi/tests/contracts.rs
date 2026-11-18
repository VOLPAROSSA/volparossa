//! Synthetic interop vectors; no Android, sensor or physical-position evidence.

use prost::Message;
use volparossa_dps_ffi::{
    DpsBridgeError, DpsQualityV1, MAX_DPS_INPUT_BYTES, REQUIRED_LIMITATIONS_MASK, assess_quality,
};
use volparossa_local_control::dps::{
    AssessmentLimitation, AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, FrameKind,
    MAX_DPS_AGE_MS, MAX_DPS_COMPONENT_METRES, MAX_DPS_OBSERVATIONS, MAX_DPS_RADIUS_METRES,
    NavigationAuthentication, ObservationDisposition, PositionFrame, PositionObservation,
    SourceKind,
};

const NOW: u64 = 1_000_000;
const CONSISTENT: &[u8] = include_bytes!("fixtures/relative_consistent.pb");
const CONFLICT: &[u8] = include_bytes!("fixtures/relative_conflict.pb");
const STALE: &[u8] = include_bytes!("fixtures/stale.pb");
const EMPTY: &[u8] = include_bytes!("fixtures/empty.pb");

fn frame() -> PositionFrame {
    PositionFrame {
        kind: FrameKind::LocalCartesian as i32,
        local_frame_id: vec![7; 16],
    }
}

fn observation(id: u8, x: f64) -> PositionObservation {
    PositionObservation {
        observation_id: vec![id; 16],
        source_id: vec![id; 16],
        declared_independence_group: vec![id; 16],
        source_kind: SourceKind::Other as i32,
        frame: Some(frame()),
        x_metres: x,
        y_metres: 2.0,
        z_metres: 3.0,
        supplied_radius_metres: 2.0,
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

fn summary(status: u32, observations: u32, eligible: u32, conflicts: u32) -> DpsQualityV1 {
    DpsQualityV1 {
        abi_version: 1,
        dps_version: 1,
        status,
        frame_kind: 2,
        observation_count: observations,
        eligible_count: eligible,
        excluded_count: observations - eligible,
        conflict_count: conflicts,
        limitations_mask: REQUIRED_LIMITATIONS_MASK,
    }
}

#[test]
fn native_quality_golden_vectors_regenerate_and_match_direct_assessor() {
    let mut old = observation(1, 1.0);
    old.observed_at_unix_ms = NOW - 1001;
    let cases = [
        (
            CONSISTENT,
            request(vec![observation(1, 1.0), observation(2, 2.0)]),
            summary(2, 2, 2, 0),
        ),
        (
            CONFLICT,
            request(vec![observation(1, 1.0), observation(2, 20.0)]),
            summary(3, 2, 2, 1),
        ),
        (STALE, request(vec![old]), summary(0, 1, 0, 0)),
        (EMPTY, request(vec![]), summary(0, 0, 0, 0)),
    ];
    for (bytes, input, expected) in cases {
        assert_eq!(input.encode_to_vec(), bytes);
        assert_eq!(DpsAssessRequest::decode(bytes).unwrap(), input);
        let direct = input.assess(NOW).unwrap();
        direct.validate().unwrap();
        let actual = assess_quality(bytes, NOW).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(i32::try_from(actual.status).unwrap(), direct.status);
        assert_eq!(
            usize::try_from(actual.observation_count).unwrap(),
            direct.observations.len()
        );
        assert_eq!(
            usize::try_from(actual.conflict_count).unwrap(),
            direct.conflicts.len()
        );
        assert_eq!(direct.limitations, (0..=6).collect::<Vec<_>>());
        actual.validate().unwrap();
    }
}

#[test]
fn native_quality_canonical_v1_maximum_is_4156_bytes() {
    let inputs = (1..=32)
        .map(|id| {
            let mut input = observation(id, MAX_DPS_COMPONENT_METRES);
            input.y_metres = MAX_DPS_COMPONENT_METRES;
            input.z_metres = MAX_DPS_COMPONENT_METRES;
            input.supplied_radius_metres = MAX_DPS_RADIUS_METRES;
            input.source_kind = SourceKind::Gnss as i32;
            input.navigation_authentication = NavigationAuthentication::ClaimedAuthenticated as i32;
            input.observed_at_unix_ms = u64::MAX;
            input
        })
        .collect();
    let mut input = request(inputs);
    input.maximum_age_ms = MAX_DPS_AGE_MS;
    input.validate().unwrap();
    // Each maximum observation is 127 body bytes + 2 tag/length bytes.
    // Request version, desired local frame and age add 2 + 22 + 4 bytes.
    assert!(
        input
            .observations
            .iter()
            .all(|row| row.encoded_len() == 127)
    );
    let maximum = MAX_DPS_OBSERVATIONS * (127 + 2) + 2 + 22 + 4;
    assert_eq!(maximum, 4156);
    assert_eq!(input.encoded_len(), maximum);
    assert!(maximum < MAX_DPS_INPUT_BYTES);
    assert_eq!(
        assess_quality(&input.encode_to_vec(), u64::MAX)
            .unwrap()
            .eligible_count,
        32
    );
}

#[test]
fn native_quality_rejects_noncanonical_protobuf_without_second_schema() {
    let mut unknown = EMPTY.to_vec();
    unknown.extend_from_slice(&[0x78, 1]);
    let mut duplicate = EMPTY.to_vec();
    duplicate.extend_from_slice(&[0x08, 1]);
    let mut reordered = EMPTY[2..].to_vec();
    reordered.extend_from_slice(&EMPTY[..2]);
    let mut overlong = vec![0x08, 0x81, 0];
    overlong.extend_from_slice(&EMPTY[2..]);
    // Valid empty ECEF request, but its empty local-frame ID is explicitly encoded.
    let explicit_default = vec![0x08, 1, 0x12, 4, 0x08, 1, 0x12, 0, 0x18, 0xe8, 0x07];
    for bytes in [unknown, duplicate, reordered, overlong, explicit_default] {
        assert_eq!(
            assess_quality(&bytes, NOW),
            Err(DpsBridgeError::InvalidMessage)
        );
    }
    for bytes in [vec![0x80], vec![0x12, 0xff], vec![0x0f]] {
        assert_eq!(
            assess_quality(&bytes, NOW),
            Err(DpsBridgeError::InvalidMessage)
        );
    }
    assert_eq!(assess_quality(&[], NOW), Err(DpsBridgeError::InputBound));
    assert_eq!(
        assess_quality(&vec![0; MAX_DPS_INPUT_BYTES + 1], NOW),
        Err(DpsBridgeError::InputBound)
    );
}

#[test]
fn native_quality_rejects_service_clock_and_structural_errors() {
    assert_eq!(
        assess_quality(EMPTY, 0),
        Err(DpsBridgeError::InvalidRequest)
    );
    let mut input = request(vec![observation(1, 1.0)]);
    input.dps_version = 2;
    assert_eq!(
        assess_quality(&input.encode_to_vec(), NOW),
        Err(DpsBridgeError::InvalidRequest)
    );
    input.dps_version = 1;
    input.observations = vec![observation(1, 1.0); 33];
    assert_eq!(
        assess_quality(&input.encode_to_vec(), NOW),
        Err(DpsBridgeError::InvalidRequest)
    );
    input.observations = vec![observation(1, 1.0); 2];
    assert_eq!(
        assess_quality(&input.encode_to_vec(), NOW),
        Err(DpsBridgeError::InvalidRequest)
    );
    input.observations[1] = observation(2, 2.0);
    input.observations[1].source_id = input.observations[0].source_id.clone();
    assert_eq!(
        assess_quality(&input.encode_to_vec(), NOW),
        Err(DpsBridgeError::InvalidRequest)
    );
}

#[test]
fn native_quality_preserves_exclusions_conflicts_and_statelessness() {
    let mut input = request(vec![observation(1, 1.0)]);
    for (timestamp, geometry, local_id, reason) in [
        (NOW - 1001, 1.0, 7, ObservationDisposition::Stale),
        (0, 1.0, 7, ObservationDisposition::MissingTimestamp),
        (NOW + 1, 1.0, 7, ObservationDisposition::FutureTimestamp),
        (
            NOW - 100,
            f64::NAN,
            7,
            ObservationDisposition::InvalidGeometry,
        ),
        (NOW - 100, 1.0, 8, ObservationDisposition::DifferentFrame),
    ] {
        let row = &mut input.observations[0];
        row.observed_at_unix_ms = timestamp;
        row.x_metres = geometry;
        row.frame.as_mut().unwrap().local_frame_id = vec![local_id; 16];
        assert_eq!(
            input.assess(NOW).unwrap().observations[0].disposition,
            reason as i32
        );
        assert_eq!(
            assess_quality(&input.encode_to_vec(), NOW).unwrap(),
            summary(0, 1, 0, 0)
        );
    }
    assert_eq!(
        assess_quality(CONSISTENT, NOW).unwrap(),
        summary(2, 2, 2, 0)
    );
    assert_eq!(assess_quality(CONFLICT, NOW).unwrap(), summary(3, 2, 2, 1));
    assert_eq!(assess_quality(EMPTY, NOW).unwrap(), summary(0, 0, 0, 0));
    assert_eq!(
        assess_quality(CONSISTENT, NOW).unwrap(),
        summary(2, 2, 2, 0)
    );
}

#[test]
fn native_quality_summary_rejects_missing_limits_and_contradictory_counts() {
    let good = summary(2, 2, 2, 0);
    for bit in 0..=6 {
        assert_eq!(
            DpsQualityV1 {
                limitations_mask: REQUIRED_LIMITATIONS_MASK ^ (1 << bit),
                ..good
            }
            .validate(),
            Err(DpsBridgeError::Internal)
        );
    }
    for bad in [
        DpsQualityV1 {
            abi_version: 2,
            ..good
        },
        DpsQualityV1 {
            dps_version: 2,
            ..good
        },
        DpsQualityV1 { status: 9, ..good },
        DpsQualityV1 { status: 0, ..good },
        DpsQualityV1 { status: 1, ..good },
        DpsQualityV1 { status: 3, ..good },
        DpsQualityV1 {
            frame_kind: 0,
            ..good
        },
        DpsQualityV1 {
            observation_count: 33,
            ..good
        },
        DpsQualityV1 {
            eligible_count: 3,
            ..good
        },
        DpsQualityV1 {
            excluded_count: 1,
            ..good
        },
        DpsQualityV1 {
            conflict_count: 1,
            ..good
        },
        DpsQualityV1 {
            limitations_mask: 0xff,
            ..good
        },
    ] {
        assert_eq!(bad.validate(), Err(DpsBridgeError::Internal));
    }
    assert_eq!(AssessmentStatus::ConsistentClaims as i32, 2);
    assert_eq!(AssessmentLimitation::PairwiseConsistencyOnly as i32, 6);
}
