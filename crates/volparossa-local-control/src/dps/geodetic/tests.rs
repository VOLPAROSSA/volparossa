// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
    control_request::Operation,
    control_response::Payload,
    decode_request, decode_response,
    dps::{
        AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, FrameKind,
        NavigationAuthentication, ObservationDisposition, PositionFrame, PositionObservation,
        SourceKind,
    },
    encode_request, encode_response,
};

fn input(
    latitude_degrees: f64,
    longitude_degrees: f64,
    height_metres: f64,
) -> Wgs84GeodeticPosition {
    Wgs84GeodeticPosition {
        latitude_degrees,
        longitude_degrees,
        height_metres,
        height_reference: HeightReference::Wgs84Ellipsoid,
    }
}

fn near(actual: [f64; 3], expected: [f64; 3], tolerance_metres: f64) {
    // Failure output deliberately does not interpolate any coordinate values.
    for (actual, expected) in actual.into_iter().zip(expected) {
        assert!((actual - expected).abs() <= tolerance_metres);
    }
}

#[test]
fn published_iogp_north_sea_forward_vector_matches_to_one_centimetre() {
    // IOGP 373-7-2 (September 2019), section 4.1.1, pp. 95-96, EPSG 9602.
    // Fixed published rounded output, independent of this implementation.
    // https://www.iogp.org/wp-content/uploads/2019/09/373-07-02.pdf
    let position = input(
        53.0 + 48.0 / 60.0 + 33.82 / 3600.0,
        2.0 + 7.0 / 60.0 + 46.38 / 3600.0,
        73.0,
    );
    near(
        position.to_ecef().unwrap().components_metres(),
        [3_771_793.968, 140_253.342, 5_124_304.349],
        0.01,
    );
}

#[test]
fn analytic_axes_poles_and_antimeridian_use_degrees_and_metres() {
    // Independent WGS84 cardinal-axis values; no forward formula in the test.
    let equatorial = 6_378_137.0;
    let polar = 6_356_752.314_245_179;
    for (latitude, longitude, height, expected) in [
        (0.0, 0.0, 0.0, [equatorial, 0.0, 0.0]),
        (0.0, 90.0, 0.0, [0.0, equatorial, 0.0]),
        (0.0, -90.0, 0.0, [0.0, -equatorial, 0.0]),
        (0.0, 180.0, 0.0, [-equatorial, 0.0, 0.0]),
        (0.0, -180.0, 0.0, [-equatorial, 0.0, 0.0]),
        (90.0, 0.0, 0.0, [0.0, 0.0, polar]),
        (-90.0, 0.0, 0.0, [0.0, 0.0, -polar]),
        (90.0, 180.0, 0.0, [0.0, 0.0, polar]),
        (-90.0, -180.0, 0.0, [0.0, 0.0, -polar]),
        (0.0, 0.0, 2.0, [equatorial + 2.0, 0.0, 0.0]),
        (0.0, 0.0, -50.0, [equatorial - 50.0, 0.0, 0.0]),
        (90.0, 0.0, -50.0, [0.0, 0.0, polar - 50.0]),
    ] {
        near(
            input(latitude, longitude, height)
                .to_ecef()
                .unwrap()
                .components_metres(),
            expected,
            0.000_001,
        );
    }
}

#[test]
fn hemisphere_and_quarter_turn_symmetries_preserve_axis_orientation() {
    let position = input(37.0, 24.0, -20.0);
    let [x, y, z] = position.to_ecef().unwrap().components_metres();
    for (latitude, longitude, expected) in [
        (-37.0, 24.0, [x, y, -z]),
        (37.0, -24.0, [x, -y, z]),
        (-37.0, -24.0, [x, -y, -z]),
        (37.0, 114.0, [-y, x, z]),
    ] {
        near(
            input(latitude, longitude, -20.0)
                .to_ecef()
                .unwrap()
                .components_metres(),
            expected,
            0.000_001,
        );
    }
}

#[test]
fn unsupported_or_unknown_vertical_reference_is_never_assumed_ellipsoidal() {
    for height_reference in [HeightReference::MeanSeaLevel, HeightReference::Unknown] {
        for height_metres in [-30.0, 0.0, 73.0] {
            let position = Wgs84GeodeticPosition {
                height_reference,
                ..input(20.0, 30.0, height_metres)
            };
            assert_eq!(
                position.to_ecef(),
                Err(GeodeticError::UnsupportedHeightReference)
            );
        }
    }
}

#[test]
fn every_nonfinite_angle_or_height_is_rejected() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        for position in [
            input(value, 0.0, 0.0),
            input(0.0, value, 0.0),
            input(0.0, 0.0, value),
        ] {
            assert_eq!(position.to_ecef(), Err(GeodeticError::NonFiniteInput));
        }
    }
}

#[test]
fn immediately_outside_degree_bounds_is_rejected_without_wrapping_or_clamping() {
    for latitude in [90.0_f64.next_up(), (-90.0_f64).next_down(), 180.0, -180.0] {
        assert_eq!(
            input(latitude, 0.0, 0.0).to_ecef(),
            Err(GeodeticError::LatitudeOutOfRange)
        );
    }
    for longitude in [180.0_f64.next_up(), (-180.0_f64).next_down(), 360.0, -360.0] {
        assert_eq!(
            input(0.0, longitude, 0.0).to_ecef(),
            Err(GeodeticError::LongitudeOutOfRange)
        );
    }
}

#[test]
fn existing_component_bound_is_inclusive_and_rejects_extreme_finite_heights() {
    for (height, expected) in [
        (
            MAX_DPS_COMPONENT_METRES - 6_378_137.0,
            MAX_DPS_COMPONENT_METRES,
        ),
        (
            -MAX_DPS_COMPONENT_METRES - 6_378_137.0,
            -MAX_DPS_COMPONENT_METRES,
        ),
    ] {
        near(
            input(0.0, 0.0, height)
                .to_ecef()
                .unwrap()
                .components_metres(),
            [expected, 0.0, 0.0],
            0.0,
        );
    }
    for height in [
        MAX_DPS_COMPONENT_METRES - 6_378_137.0 + 1.0,
        -MAX_DPS_COMPONENT_METRES - 6_378_137.0 - 1.0,
        f64::MAX,
        f64::MIN,
    ] {
        assert_eq!(
            input(0.0, 0.0, height).to_ecef(),
            Err(GeodeticError::EcefOutOfRange)
        );
    }
}

#[test]
fn debug_and_closed_error_output_do_not_expose_input_or_result_coordinates() {
    let position = input(12.345_678, -98.765_432, 123.456_789);
    assert_eq!(
        format!("{position:?}"),
        "Wgs84GeodeticPosition { [REDACTED] }"
    );
    assert_eq!(
        format!("{:?}", position.to_ecef().unwrap()),
        "EcefCoordinates { [REDACTED] }"
    );
    for (error, name, message) in [
        (
            GeodeticError::UnsupportedHeightReference,
            "UnsupportedHeightReference",
            "unsupported geodetic height reference",
        ),
        (
            GeodeticError::NonFiniteInput,
            "NonFiniteInput",
            "non-finite geodetic input",
        ),
        (
            GeodeticError::LatitudeOutOfRange,
            "LatitudeOutOfRange",
            "geodetic latitude outside degree range",
        ),
        (
            GeodeticError::LongitudeOutOfRange,
            "LongitudeOutOfRange",
            "geodetic longitude outside degree range",
        ),
        (
            GeodeticError::EcefOutOfRange,
            "EcefOutOfRange",
            "geodetic result exceeds DPS component bound",
        ),
    ] {
        assert_eq!(format!("{error:?}"), name);
        assert_eq!(error.to_string(), message);
    }
}

const NOW: u64 = 1_000_000;

fn frame() -> PositionFrame {
    PositionFrame {
        kind: FrameKind::Wgs84Ecef as i32,
        local_frame_id: vec![],
    }
}

fn observation(id: u8, height: f64) -> PositionObservation {
    let [x_metres, y_metres, z_metres] = input(0.0, 0.0, height)
        .to_ecef()
        .unwrap()
        .components_metres();
    PositionObservation {
        observation_id: vec![id; 16],
        source_id: vec![id; 16],
        declared_independence_group: vec![id; 16],
        source_kind: SourceKind::Gnss as i32,
        frame: Some(frame()),
        x_metres,
        y_metres,
        z_metres,
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

fn envelope(input: DpsAssessRequest) -> ControlRequest {
    ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![9; 16],
        operation: Some(Operation::DpsAssess(input)),
    }
}

#[test]
fn converted_equatorial_input_preserves_existing_canonical_request_and_response_bytes() {
    let converted = request(vec![observation(1, 0.0), observation(2, 2.0)]);
    let mut previous = converted.clone();
    for (position, x_metres) in previous
        .observations
        .iter_mut()
        .zip([6_378_137.0, 6_378_139.0])
    {
        position.x_metres = x_metres;
        position.y_metres = 0.0;
        position.z_metres = 0.0;
    }
    let old_bytes = encode_request(&envelope(previous)).unwrap();
    let wire = envelope(converted.clone());
    assert_eq!(encode_request(&wire).unwrap(), old_bytes);
    assert_eq!(decode_request(&old_bytes).unwrap(), wire);
    let quality = converted.assess(NOW).unwrap();
    quality.validate().unwrap();
    assert_eq!(quality.status, AssessmentStatus::ConsistentClaims as i32);
    assert_eq!(quality.limitations, [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        quality.unverified_input_position,
        Some(converted.observations[0].clone())
    );
    let response = ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![9; 16],
        result: ControlResult::Ok as i32,
        diagnostic_code: "DPS_ASSESSED".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::DpsAssessment(quality)),
    };
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode_response(&bytes).unwrap(), response);
    assert_eq!(
        encode_response(&decode_response(&bytes).unwrap()).unwrap(),
        bytes
    );
}

#[test]
fn converted_claim_order_does_not_change_assessment_or_turn_it_into_a_fused_fix() {
    let inputs = [
        observation(1, 0.0),
        observation(2, 2.0),
        observation(3, 4.0),
    ];
    let expected = request(inputs.to_vec()).assess(NOW).unwrap();
    assert_eq!(expected.status, AssessmentStatus::ConsistentClaims as i32);
    assert_eq!(expected.unverified_input_position, Some(inputs[0].clone()));
    assert_eq!(expected.limitations, [0, 1, 2, 3, 4, 5, 6]);
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let input = request(order.map(|index| inputs[index].clone()).to_vec());
        let actual = input.assess(NOW).unwrap();
        actual.validate().unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn conversion_does_not_supply_time_uncertainty_frame_authority_or_integrity() {
    let mut stale = observation(2, 0.0);
    stale.observed_at_unix_ms = NOW - 1001;
    let mut other_frame = observation(3, 0.0);
    other_frame.frame = Some(PositionFrame {
        kind: FrameKind::LocalCartesian as i32,
        local_frame_id: vec![7; 16],
    });
    let input = request(vec![observation(1, 0.0), stale, other_frame]);
    let quality = input.assess(NOW).unwrap();
    quality.validate().unwrap();
    assert_eq!(quality.status, AssessmentStatus::SingleClaim as i32);
    assert_eq!(
        quality
            .observations
            .iter()
            .map(|value| value.disposition)
            .collect::<Vec<_>>(),
        [
            ObservationDisposition::Eligible as i32,
            ObservationDisposition::Stale as i32,
            ObservationDisposition::DifferentFrame as i32,
        ]
    );
    assert_eq!(quality.limitations, [0, 1, 2, 3, 4, 5, 6]);
    let mut claimed_authenticated = observation(2, 20.0);
    claimed_authenticated.navigation_authentication =
        NavigationAuthentication::ClaimedAuthenticated as i32;
    let conflicting = request(vec![observation(1, 0.0), claimed_authenticated])
        .assess(NOW)
        .unwrap();
    conflicting.validate().unwrap();
    assert_eq!(conflicting.status, AssessmentStatus::Conflict as i32);
    assert!(conflicting.unverified_input_position.is_none());
    assert_eq!(conflicting.limitations, [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(format!("{conflicting:?}"), "DpsAssessment { [REDACTED] }");
}
