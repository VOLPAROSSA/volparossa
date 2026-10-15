//! Actual bounded Unix IPC queries; these observations never prove provider custody.

use super::*;
use tokio::net::UnixListener;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, read_request, write_response,
};

fn observed() -> PrivateStorageOutcome {
    PrivateStorageOutcome {
        status: PrivateStorageOutcomeStatus::Observed as i32,
        phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
        category: PrivateStorageOutcomeCategory::Timeout as i32,
        deadline: PrivateStorageOutcomeDeadline::RemoteWire as i32,
        append_timing: None,
    }
}

fn wire_status(status: PrivateStorageOutcomeStatus) -> PrivateStorageOutcome {
    PrivateStorageOutcome {
        status: status as i32,
        ..PrivateStorageOutcome::default()
    }
}

async fn answer(listener: UnixListener, original: [u8; 16], replies: Vec<PrivateStorageOutcome>) {
    let mut query_ids = Vec::new();
    for outcome in replies {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::PrivateStorageOutcome(query)) = request.operation else {
            panic!("diagnostics must not retry a storage operation");
        };
        assert_eq!(query.original_request_id, original);
        assert!(!query.include_append_timing);
        assert_eq!(request.request_id.len(), 16);
        assert!(!query_ids.contains(&request.request_id));
        query_ids.push(request.request_id.clone());
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageOutcome(outcome)),
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn query_correlates_original_id_and_polls_only_pending() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("query.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(answer(
        listener,
        [17; 16],
        vec![
            wire_status(PrivateStorageOutcomeStatus::Pending),
            observed(),
        ],
    ));
    let outcome = query(&socket, &[17; 16]).await;
    server.await.unwrap();
    assert!(outcome.valid());
    assert_eq!(
        serde_json::to_value(outcome).unwrap(),
        serde_json::json!({
            "status": "observed", "detail": {
                "phase": "remote_receipt_read", "category": "timeout",
                "deadline_scope": "remote_wire"
            }
        })
    );
}

#[tokio::test]
async fn unavailable_observations_are_distinct_and_pending_is_bounded() {
    for (status, expected, count) in [
        (PrivateStorageOutcomeStatus::Missing, Status::Missing, 1),
        (PrivateStorageOutcomeStatus::Expired, Status::Expired, 1),
        (
            PrivateStorageOutcomeStatus::Pending,
            Status::Pending,
            MAX_QUERIES,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("query.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(answer(listener, [19; 16], vec![wire_status(status); count]));
        let outcome = query(&socket, &[19; 16]).await;
        server.await.unwrap();
        assert_eq!(outcome.status, expected);
        assert!(outcome.detail.is_none());
        assert!(outcome.valid());
    }
}

#[tokio::test]
async fn old_agent_wrong_correlation_and_wrong_payload_never_replace_original_error() {
    for case in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("query.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let mut response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageOutcome(observed())),
            };
            match case {
                0 => return, // Older agent closes when it cannot decode the new operation.
                1 => response.request_id[0] ^= 1,
                _ => {
                    response.diagnostic_code = "UNKNOWN_REPLY".into();
                    response.payload = Some(Payload::Ack(Empty {}));
                }
            }
            write_response(&mut stream, &response).await.unwrap();
        });
        let outcome = query(&socket, &[23; 16]).await;
        server.await.unwrap();
        assert_eq!(outcome.status, Status::QueryFailed);
        let error = anyhow::Error::new(std::io::Error::other("/private/canary")).context(outcome);
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(error.downcast_ref::<AgentOutcome>().is_some());
        let encoded = serde_json::to_string(&outcome).unwrap();
        assert!(!encoded.contains("canary"));
        assert!(!encoded.contains("UNKNOWN_REPLY"));
        assert!(outcome.valid());
    }
}

#[tokio::test]
async fn stalled_query_has_one_total_deadline_and_no_storage_retry() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("query.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert!(matches!(
            request.operation,
            Some(Operation::PrivateStorageOutcome(_))
        ));
        std::future::pending::<()>().await;
        drop(stream);
    });
    let outcome = tokio::time::timeout(Duration::from_secs(3), query(&socket, &[29; 16]))
        .await
        .unwrap();
    assert_eq!(outcome.status, Status::QueryTimeout);
    assert!(outcome.detail.is_none());
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn append_timing_is_requested_in_same_query_and_unsolicited_or_invalid_data_is_rejected() {
    for (enabled, timed, malformed, expected) in [
        (true, true, false, Status::Observed),
        (true, false, false, Status::Observed),
        (false, false, false, Status::Observed),
        (false, true, false, Status::QueryFailed),
        (true, true, true, Status::QueryFailed),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("query.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let Some(Operation::PrivateStorageOutcome(query)) = request.operation else {
                panic!("only the existing outcome query is allowed");
            };
            assert_eq!(query.original_request_id, [43; 16]);
            assert_eq!(query.include_append_timing, enabled);
            let mut outcome = observed();
            if timed {
                outcome.append_timing = Some(PrivateStorageAppendTiming {
                    before_payload: 4,
                    in_payload_write_flush: 3,
                    in_receipt_read: Some(6),
                });
            }
            let response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageOutcome(outcome)),
            };
            if malformed {
                // This type-valid protobuf is deliberately rejected by the response decoder.
                use tokio::io::AsyncWriteExt;
                let mut bytes = volparossa_local_control::encode_response(&response).unwrap();
                let offset = bytes
                    .windows(8)
                    .rposition(|value| value == [0x2a, 6, 8, 4, 16, 3, 24, 6])
                    .unwrap();
                bytes[offset + 3] = 0;
                stream
                    .write_u32(u32::try_from(bytes.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.flush().await.unwrap();
            } else {
                write_response(&mut stream, &response).await.unwrap();
            }
            // The closed listener makes any unexpected second query fail the expected status.
        });
        let outcome =
            super::super::diagnostics::with_append_timing(enabled, query(&socket, &[43; 16])).await;
        server.await.unwrap();
        assert_eq!(outcome.status, expected);
        assert!(outcome.valid());
        assert_eq!(outcome.has_append_timing(), enabled && timed && !malformed);
        assert!(
            serde_json::to_value(outcome)
                .unwrap()
                .get("append_timing")
                .is_none()
        );
        let v7 = serde_json::to_value(AppendOutcome::from(outcome)).unwrap();
        assert_eq!(
            v7["append_timing"].is_object(),
            enabled && timed && !malformed
        );
        assert!(!super::super::diagnostics::append_timing_enabled());
    }
}
