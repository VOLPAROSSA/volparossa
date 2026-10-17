use super::*;
use crate::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
    MAX_CONTROL_FRAME, control_request::Operation, control_response::Payload, decode_request,
    decode_response, encode_request, encode_response, read_request,
};

type Action = StorageFixtureCorrelationAction;
type State = StorageFixtureCorrelationState;
type Role = StorageFixtureCorrelationRole;
type Phase = StorageFixtureCorrelationPhase;
type Terminal = StorageFixtureCorrelationTerminal;

fn request(action: Action) -> StorageFixtureCorrelationRequest {
    StorageFixtureCorrelationRequest {
        version: 1,
        action: action as i32,
        epoch: vec![7; 16],
        fingerprints: if action == Action::Providers {
            vec![vec![8; 32]]
        } else {
            Vec::new()
        },
    }
}

fn record() -> StorageFixtureCorrelationRecord {
    StorageFixtureCorrelationRecord {
        flow_acquire: None,
        role: Role::Client as i32,
        fingerprint: None,
        phase: Phase::ClientChallenge as i32,
        terminal: Terminal::Active as i32,
    }
}

fn snapshot() -> StorageFixtureCorrelationResponse {
    StorageFixtureCorrelationResponse {
        version: 1,
        state: State::Observed as i32,
        incomplete: false,
        records: vec![record()],
    }
}

fn acquire_summary() -> StorageFixtureAcquireSummary {
    let failure = StorageFixtureAcquireFailure {
        failure: Some(crate::PrivateStorageFlowAcquireFailure {
            stage: crate::PrivateStorageFlowAcquireStage::HelperAcquire as i32,
            reason: crate::PrivateStorageFlowAcquireReason::HelperCleanupIncomplete as i32,
        }),
        helper_diagnostic: Some(StorageFixtureHelperDiagnostic::Unknown as i32),
    };
    StorageFixtureAcquireSummary {
        rounds: 1,
        first: Some(failure),
        last: Some(failure),
    }
}

#[test]
fn fixture_v2_summary_is_closed_bounded_and_unknown_differs_from_absent() {
    let valid = acquire_summary();
    valid.validate().unwrap();
    for code in 0..=8 {
        let mut value = valid;
        value.rounds = 2;
        value.last.as_mut().unwrap().helper_diagnostic = Some(code);
        value.validate().unwrap();
        assert_eq!(
            StorageFixtureAcquireSummary::decode(value.encode_to_vec().as_slice()).unwrap(),
            value
        );
    }
    for code in [-1, 9, i32::MAX] {
        let mut value = valid;
        value.first.as_mut().unwrap().helper_diagnostic = Some(code);
        assert!(value.validate().is_err());
    }
    for rounds in [0, 9, u32::MAX] {
        assert!(
            StorageFixtureAcquireSummary { rounds, ..valid }
                .validate()
                .is_err()
        );
    }
    let mut absent = valid;
    absent.first.as_mut().unwrap().helper_diagnostic = None;
    assert!(absent.validate().is_err()); // One round must be the identical observation.
    absent.last = absent.first;
    absent.validate().unwrap();
    assert_ne!(valid.encode_to_vec(), absent.encode_to_vec());
    absent.first.as_mut().unwrap().failure = None;
    assert!(absent.validate().is_err());
}

#[test]
fn fixture_v2_detail_is_only_returned_client_flow_failure() {
    let mut value = snapshot();
    value.version = 2;
    value.records[0].phase = Phase::FlowAcquire as i32;
    value.records[0].terminal = Terminal::OperationError as i32;
    value.records[0].flow_acquire = Some(acquire_summary());
    value.validate().unwrap();
    value.version = 1;
    assert!(value.validate().is_err());
    value.version = 2;
    for phase in [Phase::TlsHandshake, Phase::Closing] {
        let mut invalid = value.clone();
        invalid.records[0].phase = phase as i32;
        assert!(invalid.validate().is_err());
    }
    for terminal in [Terminal::Active, Terminal::Cancelled, Terminal::Complete] {
        let mut invalid = value.clone();
        invalid.records[0].terminal = terminal as i32;
        assert!(invalid.validate().is_err());
    }
    value.records[0].role = Role::Provider as i32;
    assert!(value.validate().is_err());
}

#[test]
fn fixture_v2_request_response_versions_cannot_silently_downgrade() {
    let mut request = request(Action::Clients);
    request.version = 2;
    request.validate().unwrap();
    let mut response = snapshot();
    assert!(response.validate_for(&request).is_err());
    response.version = 2;
    response.validate_for(&request).unwrap();
    request.version = 1;
    assert!(response.validate_for(&request).is_err());
}

#[test]
fn fixture_v1_record_has_exact_original_wire_bytes() {
    assert_eq!(record().encode_to_vec(), vec![8, 1, 24, 9, 32, 1]);
    assert_eq!(
        snapshot().encode_to_vec(),
        vec![8, 1, 16, 2, 34, 6, 8, 1, 24, 9, 32, 1]
    );
}

fn envelope(snapshot: StorageFixtureCorrelationResponse) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Ok as i32,
        diagnostic_code: "STORAGE_FIXTURE_CORRELATION".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::StorageFixtureCorrelation(snapshot)),
    }
}

#[test]
fn fixture_actions_and_private_argument_bounds_are_closed() {
    for action in [
        Action::Arm,
        Action::Clients,
        Action::Providers,
        Action::Disarm,
    ] {
        let valid = request(action);
        valid.validate().unwrap();
        for version in [0, 3, u32::MAX] {
            assert!(
                StorageFixtureCorrelationRequest {
                    version,
                    ..valid.clone()
                }
                .validate()
                .is_err()
            );
        }
        for length in [0, 15, 17, MAX_FIXTURE_MESSAGE + 1] {
            assert!(
                StorageFixtureCorrelationRequest {
                    epoch: vec![9; length],
                    ..valid.clone()
                }
                .validate()
                .is_err()
            );
        }
        let mut invalid = valid.clone();
        invalid.fingerprints = if action == Action::Providers {
            Vec::new()
        } else {
            vec![vec![8; 32]]
        };
        assert!(invalid.validate().is_err());
    }
    for action in [0, -1, 5, i32::MAX] {
        assert!(
            StorageFixtureCorrelationRequest {
                action,
                ..request(Action::Arm)
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn fixture_provider_lookup_is_unique_and_at_most_eight() {
    let mut value = request(Action::Providers);
    value.fingerprints = (0..8).map(|byte| vec![byte; 32]).collect();
    value.validate().unwrap();
    value.fingerprints.push(vec![8; 32]);
    assert!(value.validate().is_err());
    value.fingerprints = vec![vec![8; 32]; 2];
    assert!(value.validate().is_err());
    for length in [0, 31, 33] {
        value.fingerprints = vec![vec![8; length]];
        assert!(value.validate().is_err());
    }
}

#[test]
fn fixture_state_action_and_unavailable_are_distinct() {
    for (action, state) in [
        (Action::Arm, State::Armed),
        (Action::Clients, State::Observed),
        (Action::Providers, State::Observed),
        (Action::Disarm, State::Disarmed),
    ] {
        let request = request(action);
        let mut response = StorageFixtureCorrelationResponse {
            version: 1,
            state: state as i32,
            incomplete: false,
            records: Vec::new(),
        };
        response.validate_for(&request).unwrap();
        StorageFixtureCorrelationResponse::unavailable()
            .validate_for(&request)
            .unwrap();
        response.state = if state == State::Armed {
            State::Disarmed
        } else {
            State::Armed
        } as i32;
        assert!(response.validate_for(&request).is_err());
    }
    let mut unavailable = StorageFixtureCorrelationResponse::unavailable();
    unavailable.incomplete = false;
    assert!(unavailable.validate().is_err());
    unavailable.incomplete = true;
    unavailable.records.push(record());
    assert!(unavailable.validate().is_err());
    for state in [0, -1, 5] {
        assert!(
            StorageFixtureCorrelationResponse {
                state,
                ..snapshot()
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn fixture_role_phase_terminal_matrix_is_exact() {
    for role in 0..=3 {
        for phase in 0..=13 {
            for terminal in 0..=7 {
                let value = StorageFixtureCorrelationRecord {
                    flow_acquire: None,
                    role,
                    phase,
                    terminal,
                    fingerprint: Some(vec![8; 32]),
                };
                let phase_allowed = match role {
                    1 => [1, 2, 9, 10, 12].contains(&phase),
                    2 => [2, 3, 4, 5, 6, 7, 8, 11, 12].contains(&phase),
                    _ => false,
                };
                let expected = phase_allowed
                    && (1..=6).contains(&terminal)
                    && (![3, 4].contains(&terminal) || phase == 2);
                assert_eq!(value.validate().is_ok(), expected);
            }
        }
    }
}

#[test]
fn fixture_snapshot_is_bounded_and_provider_records_match_lookup() {
    let clients = request(Action::Clients);
    let mut response = snapshot();
    response.records = vec![record(); MAX_FIXTURE_RECORDS];
    response.validate_for(&clients).unwrap();
    response.records.push(record());
    assert!(response.validate().is_err());
    response.records = vec![StorageFixtureCorrelationRecord {
        flow_acquire: None,
        role: Role::Provider as i32,
        fingerprint: Some(vec![8; 32]),
        phase: Phase::StorageChallengeWriteFlush as i32,
        terminal: Terminal::Active as i32,
    }];
    response.validate_for(&request(Action::Providers)).unwrap();
    assert!(response.validate_for(&clients).is_err());
    response.records[0].fingerprint = Some(vec![9; 32]);
    assert!(response.validate_for(&request(Action::Providers)).is_err());
    response.records[0].fingerprint = None;
    assert!(response.validate().is_err());
    for length in [0, 31, 33, MAX_FIXTURE_MESSAGE + 1] {
        response.records[0].fingerprint = Some(vec![9; length]);
        assert!(response.validate().is_err());
    }
}

#[test]
fn fixture_wire_tags_are_additive_and_legacy_bytes_stay_exact() {
    let mut value = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        operation: Some(Operation::Status(Empty {})),
    };
    let mut legacy = vec![8, 2, 18, 16];
    legacy.extend([7; 16]);
    legacy.extend([82, 0]);
    assert_eq!(encode_request(&value).unwrap(), legacy);
    let payload = request(Action::Arm);
    value.operation = Some(Operation::StorageFixtureCorrelation(payload.clone()));
    let bytes = encode_request(&value).unwrap();
    assert_eq!(decode_request(&bytes).unwrap(), value);
    assert_eq!(&bytes[20..23], &[138, 3, 22]); // Tag 49, length 22.
    assert_eq!(&bytes[23..], payload.encode_to_vec());
    let response = envelope(StorageFixtureCorrelationResponse::unavailable());
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode_response(&bytes).unwrap(), response);
    assert!(bytes.ends_with(&[170, 2, 6, 8, 1, 16, 4, 24, 1])); // Tag 37.
    let mut ack = envelope(StorageFixtureCorrelationResponse::unavailable());
    ack.diagnostic_code = "OK".into();
    ack.payload = Some(Payload::Ack(Empty {}));
    let mut legacy = vec![8, 2, 18, 16];
    legacy.extend([7; 16]);
    legacy.extend([34, 2, b'O', b'K', 82, 0]);
    assert_eq!(encode_response(&ack).unwrap(), legacy);
}

#[test]
fn fixture_wrong_envelope_unknown_wire_values_and_versions_fail_closed() {
    let response = envelope(snapshot());
    for result in [
        ControlResult::InvalidRequest as i32,
        ControlResult::Unavailable as i32,
    ] {
        assert!(
            encode_response(&ControlResponse {
                result,
                ..response.clone()
            })
            .is_err()
        );
    }
    let wrong = ControlResponse {
        diagnostic_code: "PRIVATE_CANARY".into(),
        ..response.clone()
    };
    let error = encode_response(&wrong).unwrap_err().to_string();
    assert!(!error.contains("PRIVATE_CANARY"));
    for version in [0, 3] {
        let invalid = envelope(StorageFixtureCorrelationResponse {
            version,
            ..snapshot()
        });
        assert!(decode_response(&invalid.encode_to_vec()).is_err());
    }
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        operation: Some(Operation::StorageFixtureCorrelation(
            StorageFixtureCorrelationRequest {
                action: 99,
                ..request(Action::Arm)
            },
        )),
    };
    assert!(decode_request(&request.encode_to_vec()).is_err());
    assert!(decode_request(&vec![0; MAX_CONTROL_FRAME + 1]).is_err());
}

#[tokio::test]
async fn fixture_frames_reject_truncation_and_oversized_length_before_payload() {
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        operation: Some(Operation::StorageFixtureCorrelation(request(Action::Arm))),
    };
    let payload = encode_request(&request).unwrap();
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend(payload);
    assert_eq!(read_request(&mut frame.as_slice()).await.unwrap(), request);
    for length in [0, 1, 3, frame.len() - 1] {
        assert!(read_request(&mut &frame[..length]).await.is_err());
    }
    let oversized = u32::try_from(MAX_CONTROL_FRAME + 1).unwrap().to_be_bytes();
    assert!(read_request(&mut oversized.as_slice()).await.is_err());
}
