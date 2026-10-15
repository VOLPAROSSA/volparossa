use std::future::pending;

use tokio::{net::UnixStream, sync::oneshot};

use super::super::Stage as RemoteStage;
use super::super::{ContentError, Deadline, Observation, PrivateStorageStreamFailure};
use super::*;

fn summary() -> source::Summary {
    source::Summary {
        rounds: 2,
        first: source::Failure {
            stage: source::Stage::HelperAcquire,
            reason: source::Reason::HelperCapacity,
        },
        last: source::Failure {
            stage: source::Stage::SlotReservation,
            reason: source::Reason::LocalCapacity,
        },
    }
}

fn record(observation: &Observation) {
    observation.record_stream_failure(PrivateStorageStreamFailure::FlowAcquire);
    observation.record_flow_acquire(Some(summary()));
}

#[test]
fn flow_acquire_projection_maps_every_internal_variant_without_strings() {
    let stages = [
        source::Stage::SourcePort,
        source::Stage::RetirementDrain,
        source::Stage::Material,
        source::Stage::SlotReservation,
        source::Stage::HelperAcquire,
        source::Stage::DescriptorClone,
        source::Stage::DescriptorAdoption,
        source::Stage::FlowMetadata,
    ];
    let reasons = [
        source::Reason::Entropy,
        source::Reason::Metadata,
        source::Reason::LocalCapacity,
        source::Reason::LocalUnavailable,
        source::Reason::Unconfirmed,
        source::Reason::Io,
        source::Reason::Topology,
        source::Reason::HelperKernel,
        source::Reason::HelperCapacity,
        source::Reason::HelperUnavailable,
        source::Reason::HelperNotFound,
        source::Reason::HelperCleanupIncomplete,
        source::Reason::HelperOtherRejection,
        source::Reason::HelperTimeout,
        source::Reason::HelperIo,
        source::Reason::HelperValidation,
        source::Reason::HelperAuthority,
        source::Reason::HelperCorrelation,
        source::Reason::HelperRuntimeChanged,
    ];
    let progress = Progress::new(true);
    let mut count = 0;
    for (index, stage) in stages.into_iter().enumerate() {
        for (reason_index, reason) in reasons.into_iter().enumerate() {
            let source = source::Failure { stage, reason };
            let expected = Failure {
                stage: i32::try_from(index + 1).unwrap(),
                reason: i32::try_from(reason_index + 1).unwrap(),
            };
            assert_eq!(failure(source), expected);
            let detail = Detail {
                rounds: 1,
                first: Some(expected),
                last: Some(expected),
            };
            progress.record(Some(source::Summary {
                rounds: 1,
                first: source,
                last: source,
            }));
            assert_eq!(progress.detail(), detail.validate().ok().map(|()| detail));
            count += usize::from(progress.detail().is_some());
        }
    }
    assert_eq!(count, 35);
}

#[test]
fn flow_acquire_projection_is_opt_in_bounded_and_omits_missing_history() {
    for progress in [Progress::default(), Progress::new(false)] {
        progress.record(Some(summary()));
        assert_eq!(progress.detail(), None);
    }
    let progress = Progress::new(true);
    for rounds in 2..=8 {
        let source = source::Summary {
            rounds,
            ..summary()
        };
        progress.record(Some(source));
        let detail = progress.detail().unwrap();
        assert_eq!(detail.rounds, u32::from(rounds));
        assert_eq!(detail.first, Some(failure(source.first)));
        assert_eq!(detail.last, Some(failure(source.last)));
    }
    for rounds in [0, 1, 9, u8::MAX] {
        progress.record(Some(source::Summary {
            rounds,
            ..summary()
        }));
        assert_eq!(progress.detail(), None);
    }
    progress.record(Some(summary()));
    progress.record(None);
    assert_eq!(progress.detail(), None);
    progress.record(Some(summary()));
    progress.reset();
    assert_eq!(progress.detail(), None);
}

#[tokio::test]
async fn flow_acquire_observation_retains_original_failure_and_legacy_bytes() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, control_response::Payload,
        decode_response, encode_response,
    };

    for enabled in [false, true] {
        let observation = Observation::new(enabled);
        let other = Observation::new(true);
        let result = observation
            .boundary(RemoteStage::StreamOpen, async {
                record(&observation);
                tokio::task::yield_now().await;
                assert_eq!(other.detail(), None);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        let detail = observation.detail().unwrap();
        assert_eq!(detail.flow_acquire.is_some(), enabled);
        assert_eq!(
            detail.stream_failure,
            Some(PrivateStorageStreamFailure::FlowAcquire as i32)
        );
        assert_eq!(detail.deadline_scope, Deadline::None as i32);
        if enabled {
            let flow = detail.flow_acquire.unwrap();
            assert_eq!(flow.rounds, 2);
            assert_eq!(flow.first, Some(failure(summary().first)));
            assert_eq!(flow.last, Some(failure(summary().last)));
        } else {
            let response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![7; 16],
                result: ControlResult::Unavailable as i32,
                diagnostic_code: "CONTENT_UNAVAILABLE".into(),
                private_storage_remote_detail: Some(detail),
                payload: Some(Payload::Ack(Empty {})),
            };
            let mut expected = vec![8, 2, 18, 16];
            expected.extend_from_slice(&[7; 16]);
            expected.extend_from_slice(&[24, 5, 34, 19]);
            expected.extend_from_slice(b"CONTENT_UNAVAILABLE");
            // Detail tag five retains the exact original four bytes; then Ack tag ten.
            expected.extend_from_slice(&[42, 4, 8, 6, 32, 4, 82, 0]);
            assert_eq!(encode_response(&response).unwrap(), expected);
            assert_eq!(decode_response(&expected).unwrap(), response);
        }
        observation.reset(); // Same reset used by the existing maintenance-cancel path.
        assert_eq!(observation.detail(), None);
    }
}

#[tokio::test]
async fn flow_acquire_observation_is_erased_by_success_or_a_different_boundary() {
    let observation = Observation::new(true);
    observation
        .boundary(RemoteStage::StreamOpen, async {
            record(&observation);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(observation.detail(), None);
    for stage in [
        RemoteStage::RouteConnect,
        RemoteStage::TlsHandshake,
        RemoteStage::Challenge,
    ] {
        let _ = observation
            .boundary(RemoteStage::StreamOpen, async {
                record(&observation);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        assert!(observation.detail().unwrap().flow_acquire.is_some());
        let _ = observation
            .boundary(stage, async {
                record(&observation); // Cannot attach stream detail to an unrelated boundary.
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        let detail = observation.detail().unwrap();
        assert_eq!(detail.stage, stage as i32);
        assert_eq!(detail.flow_acquire, None);
    }
}

#[tokio::test]
async fn flow_acquire_observation_does_not_survive_original_enclosing_timeouts() {
    let observation = Observation::new(true);
    for deadline in [Deadline::Operation, Deadline::Exchange] {
        let result = observation
            .budget(
                deadline,
                std::time::Duration::ZERO,
                observation.boundary(RemoteStage::StreamOpen, async {
                    record(&observation);
                    pending::<Result<(), ContentError>>().await
                }),
            )
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        let detail = observation.detail().unwrap();
        assert_eq!(detail.deadline_scope, deadline as i32);
        assert_eq!(detail.flow_acquire, None);
        assert_eq!(detail.stream_failure, None);
    }
}

#[tokio::test]
async fn flow_acquire_requester_cancellation_clears_the_same_request_observation() {
    let (client, mut local) = UnixStream::pair().unwrap();
    let (started, waiting) = oneshot::channel();
    let task = tokio::spawn(async move {
        let observation = Observation::new(true);
        let result = observation
            .requester_boundary(RemoteStage::StreamOpen, &mut local, async {
                record(&observation);
                started.send(()).unwrap();
                pending::<Result<(), ContentError>>().await
            })
            .await;
        assert!(result.is_err());
        assert_eq!(observation.detail(), None);
    });
    waiting.await.unwrap();
    drop(client);
    task.await.unwrap();
}

#[tokio::test]
async fn flow_acquire_already_closed_requester_does_not_start_the_observer() {
    let (client, mut local) = UnixStream::pair().unwrap();
    drop(client);
    local.readable().await.unwrap();
    let observation = Observation::new(true);
    let mut polled = false;
    let result = observation
        .requester_boundary(RemoteStage::StreamOpen, &mut local, async {
            polled = true;
            record(&observation);
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    assert!(result.is_err());
    assert!(!polled);
    assert_eq!(observation.detail(), None);
}
