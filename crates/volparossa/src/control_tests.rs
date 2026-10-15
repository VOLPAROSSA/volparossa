use super::*;
use volparossa_local_control::{
    Empty, PrivateStorageChallengeDetail, PrivateStorageChallengePhase,
    PrivateStorageDeadlineScope, PrivateStorageElapsedBucket, PrivateStorageRemoteRequest,
    PrivateStorageRemoteStage, control_response::Payload, read_request, write_response,
};

#[tokio::test]
async fn private_storage_detail_requires_initial_operation_and_exact_correlation() {
    for detail in [
        PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: PrivateStorageRemoteStage::ProviderLookup as i32,
            deadline_scope: PrivateStorageDeadlineScope::Operation as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: None,
        },
        PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: PrivateStorageRemoteStage::Challenge as i32,
            deadline_scope: PrivateStorageDeadlineScope::Operation as i32,
            tls_failure: None,
            stream_failure: None,
            challenge: Some(PrivateStorageChallengeDetail {
                phase: PrivateStorageChallengePhase::ChallengeReadVerify as i32,
                before_challenge: PrivateStorageElapsedBucket::Under1s as i32,
                in_challenge: PrivateStorageElapsedBucket::AtLeast120s as i32,
            }),
        },
    ] {
        initial_detail_correlation_case(detail).await;
    }
}

async fn initial_detail_correlation_case(detail: PrivateStorageRemoteDetail) {
    for (private_storage, correlated) in [(true, true), (false, true), (true, false)] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let detail = Some(detail);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let mut id = request.request_id;
            if !correlated {
                id[0] ^= 1;
            }
            write_response(
                &mut stream,
                &ControlResponse {
                    protocol_version: CONTROL_PROTOCOL_VERSION,
                    request_id: id,
                    result: ControlResult::Unavailable as i32,
                    diagnostic_code: "CONTENT_UNAVAILABLE".into(),
                    private_storage_remote_detail: detail,
                    payload: Some(Payload::Ack(Empty {})),
                },
            )
            .await
            .unwrap();
        });
        let operation = if private_storage {
            Operation::PrivateStorageRemote(PrivateStorageRemoteRequest {
                include_flow_acquire_detail: false,
                provider_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
                grant: vec![1],
                maintenance_turn: Vec::new(),
            })
        } else {
            Operation::Status(Empty {})
        };
        let error = begin_request(&socket, operation).await.unwrap_err();
        let rejected = error.downcast_ref::<AgentRejected>();
        if private_storage && correlated {
            assert_eq!(rejected.unwrap().private_storage_remote_detail, detail);
        } else {
            assert!(rejected.is_none());
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn terminal_response_cannot_export_a_pre_ready_detail() {
    let (mut owner, mut agent) = UnixStream::pair().unwrap();
    write_response(
        &mut agent,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            result: ControlResult::Unavailable as i32,
            diagnostic_code: "CONTENT_UNAVAILABLE".into(),
            private_storage_remote_detail: Some(PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage: PrivateStorageRemoteStage::Challenge as i32,
                deadline_scope: PrivateStorageDeadlineScope::None as i32,
                tls_failure: None,
                stream_failure: None,
                challenge: None,
            }),
            payload: Some(Payload::Ack(Empty {})),
        },
    )
    .await
    .unwrap();
    let error = finish_request(&mut owner, &[1; 16]).await.unwrap_err();
    assert!(error.downcast_ref::<AgentRejected>().is_none());
}
