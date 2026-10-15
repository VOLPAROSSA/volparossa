use std::{
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{io::AsyncWriteExt, sync::oneshot, time::timeout};

use super::*;

#[tokio::test]
async fn every_observed_boundary_keeps_original_error_and_success_resets_detail() {
    let observation = Observation::default();
    assert!(observation.detail().is_none());
    for stage in [
        Stage::RouteConnect,
        Stage::ControlSelection,
        Stage::ProviderLookup,
        Stage::ProviderCardinality,
        Stage::OfferValidity,
        Stage::StreamOpen,
        Stage::TlsHandshake,
        Stage::Challenge,
    ] {
        assert!(matches!(
            observation
                .boundary(stage, async { Err::<(), _>(ContentError::Invalid) })
                .await,
            Err(ContentError::Invalid)
        ));
        assert_eq!(
            observation.detail(),
            Some(PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage: stage as i32,
                deadline_scope: Deadline::None as i32,
                tls_failure: None,
                stream_failure: None,
                challenge: None,
            })
        );
        observation.boundary(stage, async { Ok(()) }).await.unwrap();
        assert!(observation.detail().is_none());
    }
}

#[tokio::test]
async fn requester_eof_or_input_before_inner_poll_never_invents_a_boundary() {
    for premature_input in [false, true] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        if premature_input {
            client.write_all(b"private-canary").await.unwrap();
        }
        drop(client);
        server.readable().await.unwrap();
        let observation = Observation::default();
        // A previous boundary must not leak into a later cancelled phase.
        let _ = observation
            .boundary(Stage::RouteConnect, async {
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        let mut polled = false;
        let result = observation
            .requester_boundary(Stage::TlsHandshake, &mut server, async {
                polled = true;
                Ok(())
            })
            .await;
        assert!(!polled);
        assert!(observation.detail().is_none());
        if premature_input {
            assert!(matches!(result, Err(ContentError::Invalid)));
        } else {
            assert!(matches!(result, Err(ContentError::Unavailable)));
        }
    }
}

#[tokio::test]
async fn requester_cancellation_drops_pending_owned_work_and_clears_detail() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let (client, mut server) = UnixStream::pair().unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let child_dropped = Arc::clone(&dropped);
    let (started, running) = oneshot::channel();
    let task = tokio::spawn(async move {
        let observation = Observation::default();
        let result = observation
            .requester_boundary(Stage::StreamOpen, &mut server, async {
                let _owned = DropFlag(child_dropped);
                started.send(()).unwrap();
                pending::<Result<(), ContentError>>().await
            })
            .await;
        assert!(observation.detail().is_none());
        result
    });
    timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
    drop(client);
    assert!(matches!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Err(ContentError::Unavailable)
    ));
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn only_actual_elapsed_budget_sets_its_exact_operation_or_exchange_scope() {
    let observation = Observation::default();
    let outer = observation
        .budget(
            Deadline::Operation,
            Duration::ZERO,
            pending::<Result<(), ContentError>>(),
        )
        .await;
    assert!(matches!(outer, Err(ContentError::Unavailable)));
    assert_eq!(
        observation.detail(),
        Some(PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: Stage::Unobserved as i32,
            deadline_scope: Deadline::Operation as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: None,
        })
    );
    observation.reset();
    let result = observation
        .budget(
            Deadline::Operation,
            Duration::from_secs(2),
            observation.budget(
                Deadline::Exchange,
                Duration::ZERO,
                observation.boundary(Stage::Challenge, pending::<Result<(), ContentError>>()),
            ),
        )
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert_eq!(
        observation.detail(),
        Some(PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: Stage::Challenge as i32,
            deadline_scope: Deadline::Exchange as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: None,
        })
    );
    observation.reset();
    let result = observation
        .budget(
            Deadline::Operation,
            Duration::ZERO,
            observation.budget(
                Deadline::Exchange,
                Duration::from_secs(2),
                observation.boundary(Stage::TlsHandshake, pending::<Result<(), ContentError>>()),
            ),
        )
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert_eq!(
        observation.detail(),
        Some(PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: Stage::TlsHandshake as i32,
            deadline_scope: Deadline::Operation as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: None,
        })
    );
    observation.reset();
    let result = observation
        .budget(Deadline::Operation, Duration::from_secs(2), async {
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert!(observation.detail().is_none());
}

#[tokio::test]
async fn uninstrumented_inner_policy_deadline_and_explicit_cancel_have_no_detail() {
    let observation = Observation::default();
    let result = observation
        .budget(
            Deadline::Exchange,
            Duration::ZERO,
            pending::<Result<(), ContentError>>(),
        )
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert!(observation.detail().is_none());
    let _ = observation
        .boundary(Stage::ProviderLookup, async {
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    observation.reset(); // Same explicit reset as the outer maintenance-cancel arm.
    assert!(observation.detail().is_none());
    let result = observation
        .budget(Deadline::Operation, Duration::from_secs(2), async {
            Err::<(), _>(ContentError::Policy)
        })
        .await;
    assert!(matches!(result, Err(ContentError::Policy)));
    assert!(observation.detail().is_none());
}

#[test]
fn stream_failure_mapping_is_closed_and_exhaustive() {
    for (cause, expected) in [
        (ContentStreamOpenCause::Policy, 1),
        (ContentStreamOpenCause::RouteState, 2),
        (ContentStreamOpenCause::RouteMaterial, 3),
        (ContentStreamOpenCause::FlowAcquire, 4),
        (ContentStreamOpenCause::TransportCertificate, 5),
        (ContentStreamOpenCause::TransportTls, 6),
        (ContentStreamOpenCause::InitialPaths, 7),
        (ContentStreamOpenCause::OpenTcpWrite, 8),
        (ContentStreamOpenCause::SubflowReadiness, 9),
        (ContentStreamOpenCause::StreamAttachment, 10),
    ] {
        assert_eq!(stream_failure(cause) as i32, expected);
    }
}

#[tokio::test]
async fn stream_failure_is_request_local_and_success_or_other_boundary_clears_it() {
    let first = Observation::default();
    let second = Observation::default();
    for value in 1..=10 {
        let failure = PrivateStorageStreamFailure::try_from(value).unwrap();
        let _ = first
            .boundary(Stage::StreamOpen, async {
                first.record_stream_failure(failure);
                tokio::task::yield_now().await;
                assert!(second.detail().is_none());
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        let detail = first.detail().unwrap();
        assert_eq!(detail.stream_failure, Some(value));
        assert_eq!(detail.tls_failure, None);
        assert_eq!(detail.stage, Stage::StreamOpen as i32);
        first
            .boundary(Stage::StreamOpen, async { Ok(()) })
            .await
            .unwrap();
        assert!(first.detail().is_none());
        let _ = first
            .boundary(Stage::TlsHandshake, async {
                first.record_stream_failure(failure);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        assert!(first.detail().unwrap().stream_failure.is_none());
    }
    first.reset();
    first.record_stream_failure(PrivateStorageStreamFailure::FlowAcquire);
    assert!(first.detail().is_none());
}

#[tokio::test]
async fn enclosing_deadlines_and_requester_cancellation_clear_stream_failure() {
    let observation = Observation::default();
    for scope in [Deadline::Operation, Deadline::Exchange] {
        let _ = observation
            .budget(
                scope,
                Duration::ZERO,
                observation.boundary(Stage::StreamOpen, async {
                    observation.record_stream_failure(PrivateStorageStreamFailure::TransportTls);
                    pending::<Result<(), ContentError>>().await
                }),
            )
            .await;
        let detail = observation.detail().unwrap();
        assert_eq!(detail.deadline_scope, scope as i32);
        assert!(detail.stream_failure.is_none());
        assert!(detail.tls_failure.is_none());
    }
    let (client, mut server) = UnixStream::pair().unwrap();
    let (started, running) = oneshot::channel();
    let task = tokio::spawn(async move {
        let observation = Observation::default();
        let result = observation
            .requester_boundary(Stage::StreamOpen, &mut server, async {
                observation.record_stream_failure(PrivateStorageStreamFailure::InitialPaths);
                started.send(()).unwrap();
                pending::<Result<(), ContentError>>().await
            })
            .await;
        assert!(result.is_err());
        assert!(observation.detail().is_none());
    });
    running.await.unwrap();
    drop(client);
    task.await.unwrap();
}

#[tokio::test]
async fn tls_failure_is_request_local_and_reset_by_success_or_another_boundary() {
    let observation = Observation::default();
    for failure in [
        PrivateStorageTlsFailure::Offer,
        PrivateStorageTlsFailure::Configuration,
        PrivateStorageTlsFailure::HandshakeDeadline,
        PrivateStorageTlsFailure::Authentication,
        PrivateStorageTlsFailure::TlsOther,
        PrivateStorageTlsFailure::Io,
    ] {
        let result = observation
            .boundary(Stage::TlsHandshake, async {
                observation.record_tls_failure(failure);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        assert_eq!(
            observation.detail(),
            Some(PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage: Stage::TlsHandshake as i32,
                deadline_scope: Deadline::None as i32,
                tls_failure: Some(failure as i32),
                stream_failure: None,
                challenge: None,
            })
        );
        observation
            .boundary(Stage::TlsHandshake, async {
                observation.record_tls_failure(failure);
                Ok(())
            })
            .await
            .unwrap();
        assert!(observation.detail().is_none());
        let _ = observation
            .boundary(Stage::Challenge, async {
                observation.record_tls_failure(failure);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await;
        assert_eq!(observation.detail().unwrap().tls_failure, None);
    }
    observation.reset();
    observation.record_tls_failure(PrivateStorageTlsFailure::Io);
    assert!(observation.detail().is_none());
}

#[tokio::test]
async fn enclosing_deadlines_clear_tls_failure_and_keep_their_original_scope() {
    let observation = Observation::default();
    for scope in [Deadline::Operation, Deadline::Exchange] {
        let result = observation
            .budget(
                scope,
                Duration::ZERO,
                observation.boundary(Stage::TlsHandshake, async {
                    // Even a retained earlier fact cannot masquerade as a result
                    // from work cancelled by the enclosing operation deadline.
                    observation.record_tls_failure(PrivateStorageTlsFailure::Io);
                    pending::<Result<(), ContentError>>().await
                }),
            )
            .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        assert_eq!(
            observation.detail(),
            Some(PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage: Stage::TlsHandshake as i32,
                deadline_scope: scope as i32,
                tls_failure: None,
                stream_failure: None,
                challenge: None,
            })
        );
    }
}

#[tokio::test]
async fn requester_cancellation_and_maintenance_reset_clear_tls_failure() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let (started, running) = oneshot::channel();
    let task = tokio::spawn(async move {
        let observation = Observation::default();
        let result = observation
            .requester_boundary(Stage::TlsHandshake, &mut server, async {
                observation.record_tls_failure(PrivateStorageTlsFailure::Io);
                started.send(()).unwrap();
                pending::<Result<(), ContentError>>().await
            })
            .await;
        assert!(observation.detail().is_none());
        observation
            .boundary(Stage::TlsHandshake, async {
                observation.record_tls_failure(PrivateStorageTlsFailure::Io);
                Err::<(), _>(ContentError::Unavailable)
            })
            .await
            .unwrap_err();
        observation.reset();
        assert!(observation.detail().is_none());
        result
    });
    timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
    drop(client);
    assert!(matches!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Err(ContentError::Unavailable)
    ));
}
