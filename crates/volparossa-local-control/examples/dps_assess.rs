//! Synthetic one-shot DPS example. Never collects sensors or changes OS location.
//!
//! Run without arguments for an in-process assessment, or pass an already-authorized
//! agent Unix socket for one actual framed local request. That socket also grants other
//! administrative operations: this is not a least-authority app credential or mobile port.
//! All positions and metadata below are synthetic, including when sent to a real agent.

use std::{
    error::Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{net::UnixStream, time::timeout};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResult,
    control_request::Operation,
    control_response::Payload,
    dps::{
        AssessmentLimitation, AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, FrameKind,
        NavigationAuthentication, PositionFrame, PositionObservation, SourceKind,
        geodetic::{HeightReference, Wgs84GeodeticPosition},
    },
    read_response, write_request,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = arguments.next();
    if arguments.next().is_some() {
        return Err("usage: dps_assess [already-authorized-agent-unix-socket]".into());
    }
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let frame = PositionFrame {
        kind: FrameKind::Wgs84Ecef as i32,
        local_frame_id: vec![],
    };
    // Synthetic ellipsoidal heights preserve the original two ECEF input points.
    let synthetic = Wgs84GeodeticPosition {
        latitude_degrees: 0.0,
        longitude_degrees: 0.0,
        height_metres: 0.0,
        height_reference: HeightReference::Wgs84Ellipsoid,
    };
    let [first_x, first_y, first_z] = synthetic.to_ecef()?.components_metres();
    let [second_x, second_y, second_z] = Wgs84GeodeticPosition {
        height_metres: 2.0,
        ..synthetic
    }
    .to_ecef()?
    .components_metres();
    let first = PositionObservation {
        observation_id: vec![1; 16],
        source_id: vec![2; 16],
        declared_independence_group: vec![3; 16],
        source_kind: SourceKind::Gnss as i32,
        frame: Some(frame.clone()),
        x_metres: first_x,
        y_metres: first_y,
        z_metres: first_z,
        supplied_radius_metres: 10.0,
        observed_at_unix_ms: now,
        navigation_authentication: NavigationAuthentication::Unknown as i32,
    };
    let second = PositionObservation {
        observation_id: vec![4; 16],
        source_id: vec![5; 16],
        declared_independence_group: vec![6; 16],
        source_kind: SourceKind::FixedReference as i32,
        x_metres: second_x,
        y_metres: second_y,
        z_metres: second_z,
        ..first.clone()
    };
    let request = DpsAssessRequest {
        dps_version: DPS_SERVICE_VERSION,
        desired_frame: Some(frame),
        maximum_age_ms: 5000,
        observations: vec![first, second],
    };
    let assessment = if let Some(socket) = socket {
        let mut request_id = [0_u8; 16];
        getrandom::fill(&mut request_id).map_err(|_| "cannot generate request correlation ID")?;
        let envelope = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            operation: Some(Operation::DpsAssess(request)),
        };
        timeout(Duration::from_secs(5), async {
            let mut stream = UnixStream::connect(socket).await?;
            write_request(&mut stream, &envelope).await?;
            let response = read_response(&mut stream).await?;
            if response.request_id != request_id || response.result != ControlResult::Ok as i32 {
                return Err::<_, Box<dyn Error>>(
                    "DPS response correlation or result failed".into(),
                );
            }
            let Some(Payload::DpsAssessment(assessment)) = response.payload else {
                return Err("agent did not return a DPS assessment".into());
            };
            Ok(assessment)
        })
        .await??
    } else {
        request.assess(now)?
    };
    assessment.validate()?;
    // Deliberately print quality only, never coordinates, source IDs or observation times.
    println!(
        "Synthetic input assessment: {:?}; candidate present: {}; declared groups: {}",
        AssessmentStatus::try_from(assessment.status)?,
        assessment.unverified_input_position.is_some(),
        assessment.declared_independence_groups
    );
    for limitation in assessment.limitations {
        println!(
            "Limitation: {:?}",
            AssessmentLimitation::try_from(limitation)?
        );
    }
    Ok(())
}
