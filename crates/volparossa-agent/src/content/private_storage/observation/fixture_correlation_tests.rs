use super::*;
use crate::content::ContentRuntime;
use volparossa_local_control::{
    StorageFixtureCorrelationAction as Action, StorageFixtureCorrelationRecord,
    StorageFixtureCorrelationRequest as Request,
};

const UID: u32 = 1000;

fn request(action: Action) -> Request {
    Request {
        version: 1,
        action: action as i32,
        epoch: vec![7; 16],
        fingerprints: Vec::new(),
    }
}

async fn fixture() -> (ContentRuntime, Observation) {
    let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
    runtime
        .fixture_correlation(UID, &request(Action::Arm))
        .await
        .unwrap();
    let observation = Observation::new(false).with_fixture(runtime.fixture_correlation.client(UID));
    (runtime, observation)
}

async fn row(runtime: &ContentRuntime) -> StorageFixtureCorrelationRecord {
    let response = runtime
        .fixture_correlation(UID, &request(Action::Clients))
        .await
        .unwrap();
    assert_eq!(response.records.len(), 1);
    response.records.into_iter().next().unwrap()
}

fn flow_summary() -> crate::mptcp_transport::acquire_diagnostic::Summary {
    use crate::mptcp_transport::acquire_diagnostic::{Failure, Reason, Stage, Summary};
    use volparossa_local_control::StorageFixtureHelperDiagnostic as Code;
    Summary {
        rounds: 2,
        first: Failure {
            stage: Stage::HelperAcquire,
            reason: Reason::HelperKernel,
            helper_diagnostic: Some(Code::TransportUnavailable),
        },
        last: Failure {
            stage: Stage::HelperAcquire,
            reason: Reason::HelperCleanupIncomplete,
            helper_diagnostic: Some(Code::FlowIdentityUnavailable),
        },
    }
}

async fn fixture_version(version: u32) -> (ContentRuntime, Observation) {
    let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
    runtime
        .fixture_correlation(
            UID,
            &Request {
                version,
                ..request(Action::Arm)
            },
        )
        .await
        .unwrap();
    let observation = Observation::new(true).with_fixture(runtime.fixture_correlation.client(UID));
    (runtime, observation)
}

async fn version_row(runtime: &ContentRuntime, version: u32) -> StorageFixtureCorrelationRecord {
    runtime
        .fixture_correlation(
            UID,
            &Request {
                version,
                ..request(Action::Clients)
            },
        )
        .await
        .unwrap()
        .records
        .into_iter()
        .next()
        .unwrap()
}

#[tokio::test]
async fn fixture_v2_same_request_summary_without_tls_or_copy_binding_preserves_legacy_detail() {
    let mut legacy = None;
    for version in [1, 2] {
        let (runtime, observation) = fixture_version(version).await;
        let result: Result<(), _> = observation
            .boundary(Stage::StreamOpen, async {
                observation.record_stream_failure(PrivateStorageStreamFailure::FlowAcquire);
                observation.record_flow_acquire(Some(flow_summary()));
                Err(ContentError::Unavailable)
            })
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        if version == 1 {
            legacy = observation.detail();
        }
        assert_eq!(observation.detail(), legacy);
        observation
            .fixture()
            .finish(FixtureTerminal::OperationError);
        let row = version_row(&runtime, version).await;
        assert_eq!(row.fingerprint, None);
        assert_eq!(row.phase, FixturePhase::FlowAcquire as i32);
        assert_eq!(row.flow_acquire.is_some(), version == 2);
        if let Some(value) = row.flow_acquire {
            assert_eq!(value, flow_acquire::fixture_detail(flow_summary()));
        }
    }
}

#[tokio::test]
async fn fixture_v2_stage_advance_and_cancellation_clear_acquire_detail() {
    for cancelled in [false, true] {
        let (runtime, observation) = fixture_version(2).await;
        let _: Result<(), _> = observation
            .boundary(Stage::StreamOpen, async {
                observation.record_stream_failure(PrivateStorageStreamFailure::FlowAcquire);
                observation.record_flow_acquire(Some(flow_summary()));
                Err(ContentError::Unavailable)
            })
            .await;
        if cancelled {
            observation.fixture().finish(FixtureTerminal::Cancelled);
        } else {
            observation
                .boundary(Stage::TlsHandshake, async { Ok(()) })
                .await
                .unwrap();
            observation
                .fixture()
                .finish(FixtureTerminal::OperationError);
        }
        assert_eq!(version_row(&runtime, 2).await.flow_acquire, None);
    }
}

#[tokio::test(start_paused = true)]
async fn fixture_v2_deadline_does_not_keep_an_earlier_returned_failure() {
    let (runtime, observation) = fixture_version(2).await;
    let result: Result<(), _> = observation
        .budget(
            Deadline::Operation,
            Duration::from_secs(1),
            observation.boundary(Stage::StreamOpen, async {
                observation.record_stream_failure(PrivateStorageStreamFailure::FlowAcquire);
                observation.record_flow_acquire(Some(flow_summary()));
                std::future::pending().await
            }),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(version_row(&runtime, 2).await.flow_acquire, None);
}

#[tokio::test]
async fn fixture_correlation_tls_failure_keeps_typed_class_and_legacy_detail() {
    for (failure, expected) in [
        (
            PrivateStorageTlsFailure::HandshakeDeadline,
            FixtureTerminal::TlsTimeout,
        ),
        (
            PrivateStorageTlsFailure::Authentication,
            FixtureTerminal::TlsError,
        ),
        (
            PrivateStorageTlsFailure::TlsOther,
            FixtureTerminal::TlsError,
        ),
        (PrivateStorageTlsFailure::Io, FixtureTerminal::TlsError),
        (
            PrivateStorageTlsFailure::Offer,
            FixtureTerminal::OperationError,
        ),
        (
            PrivateStorageTlsFailure::Configuration,
            FixtureTerminal::OperationError,
        ),
    ] {
        let (runtime, observation) = fixture().await;
        let result: Result<(), _> = observation
            .boundary(Stage::TlsHandshake, async {
                observation.record_tls_failure(failure);
                Err(ContentError::Unavailable)
            })
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        assert_eq!(
            observation.detail().unwrap().tls_failure,
            Some(failure as i32)
        );
        let record = row(&runtime).await;
        assert_eq!(record.phase, FixturePhase::TlsHandshake as i32);
        assert_eq!(record.terminal, expected as i32);
    }
}

#[tokio::test(start_paused = true)]
async fn fixture_correlation_operation_deadline_is_not_a_tls_timeout() {
    let (runtime, observation) = fixture().await;
    let result: Result<(), _> = observation
        .budget(
            Deadline::Operation,
            Duration::from_secs(2),
            observation.boundary(Stage::TlsHandshake, std::future::pending()),
        )
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert_eq!(observation.deadline(), Deadline::Operation);
    let record = row(&runtime).await;
    assert_eq!(record.phase, FixturePhase::TlsHandshake as i32);
    assert_eq!(record.terminal, FixtureTerminal::OperationError as i32);
}

#[tokio::test]
async fn fixture_correlation_requester_eof_keeps_cancel_and_original_rejection() {
    let (runtime, observation) = fixture().await;
    let (client, mut local) = UnixStream::pair().unwrap();
    drop(client);
    local.readable().await.unwrap();
    let result: Result<(), _> = observation
        .requester_boundary(Stage::TlsHandshake, &mut local, std::future::pending())
        .await;
    assert!(result.is_err());
    assert!(observation.detail().is_none());
    let record = row(&runtime).await;
    assert_eq!(record.phase, FixturePhase::FlowAcquire as i32);
    assert_eq!(record.terminal, FixtureTerminal::Cancelled as i32);
}

#[tokio::test]
async fn fixture_correlation_reset_does_not_erase_phase_or_invent_completion() {
    let (runtime, observation) = fixture().await;
    observation
        .boundary(Stage::Challenge, async { Ok(()) })
        .await
        .unwrap();
    assert!(observation.detail().is_none());
    let record = row(&runtime).await;
    assert_eq!(record.phase, FixturePhase::ClientChallenge as i32);
    assert_eq!(record.terminal, FixtureTerminal::Active as i32);
    drop(observation);
    assert_eq!(
        row(&runtime).await.terminal,
        FixtureTerminal::Cancelled as i32
    );
}
