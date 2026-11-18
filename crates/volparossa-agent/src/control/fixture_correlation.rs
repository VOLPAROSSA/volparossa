//! Explicit development-only fixture observation on the existing authorized Unix stream.
//!
//! The runtime owns the short-lived RAM records. The caller cannot supply a Unix UID,
//! request a production exception, enable telemetry or change any storage deadline.

use tokio::net::UnixStream;
use volparossa_config::RuntimeMode;
use volparossa_local_control::{
    ControlResponse, ControlResult, StorageFixtureCorrelationRequest, control_response::Payload,
};

use crate::content::{ContentError, ContentRuntime};

pub(super) async fn respond(
    mode: RuntimeMode,
    runtime: &ContentRuntime,
    request_id: Vec<u8>,
    query: &StorageFixtureCorrelationRequest,
    stream: &UnixStream,
) -> ControlResponse {
    // Refuse before examining an epoch or touching the diagnostic runtime. The actual
    // stream supplies SO_PEERCRED; generic UID-less dispatch rejects this operation.
    let result = if mode == RuntimeMode::Development {
        match stream.peer_cred() {
            Ok(credentials) => runtime.fixture_correlation(credentials.uid(), query).await,
            Err(_) => Err(ContentError::Invalid),
        }
    } else {
        Err(ContentError::Policy)
    };
    match result {
        Ok(snapshot) => super::response(
            request_id,
            ControlResult::Ok,
            "STORAGE_FIXTURE_CORRELATION",
            Payload::StorageFixtureCorrelation(snapshot),
        ),
        Err(error) => super::content_response(request_id, Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_local_control::{
        StorageFixtureCorrelationAction as Action, StorageFixtureCorrelationState as State,
        encode_response,
    };

    fn request(action: Action) -> StorageFixtureCorrelationRequest {
        StorageFixtureCorrelationRequest {
            target: None,
            version: 1,
            action: action as i32,
            epoch: vec![17; 16],
            fingerprints: if action == Action::Providers {
                vec![vec![23; 32]]
            } else {
                Vec::new()
            },
        }
    }

    fn runtime() -> ContentRuntime {
        ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap()
    }

    fn assert_state(
        response: &ControlResponse,
        query: &StorageFixtureCorrelationRequest,
        state: State,
    ) {
        assert_eq!(response.result, ControlResult::Ok as i32);
        assert_eq!(response.request_id, vec![9; 16]);
        let Some(Payload::StorageFixtureCorrelation(snapshot)) = &response.payload else {
            panic!("typed fixture snapshot required");
        };
        snapshot.validate_for(query).unwrap();
        assert_eq!(snapshot.state, state as i32);
        assert!(encode_response(response).is_ok());
    }

    #[tokio::test]
    async fn production_refuses_every_fixture_action_without_arming() {
        let runtime = runtime();
        let (_client, server) = UnixStream::pair().unwrap();
        for action in [
            Action::Arm,
            Action::Clients,
            Action::Providers,
            Action::Disarm,
        ] {
            let response = respond(
                RuntimeMode::Production,
                &runtime,
                vec![9; 16],
                &request(action),
                &server,
            )
            .await;
            assert_eq!(response.result, ControlResult::Policy as i32);
            assert_eq!(response.diagnostic_code, "CONTENT_POLICY");
            assert!(matches!(response.payload, Some(Payload::Ack(_))));
            assert!(encode_response(&response).is_ok());
        }
        // The denied Arm has not occupied a diagnostic epoch in the shared runtime.
        let query = request(Action::Arm);
        let response = respond(
            RuntimeMode::Development,
            &runtime,
            vec![9; 16],
            &query,
            &server,
        )
        .await;
        assert_state(&response, &query, State::Armed);
        let query = request(Action::Disarm);
        let response = respond(
            RuntimeMode::Development,
            &runtime,
            vec![9; 16],
            &query,
            &server,
        )
        .await;
        assert_state(&response, &query, State::Disarmed);
    }

    #[tokio::test]
    async fn development_fixture_uses_socket_owner_and_disarms_without_storage_service() {
        let runtime = runtime();
        let (_client, server) = UnixStream::pair().unwrap();
        for (action, state) in [
            (Action::Arm, State::Armed),
            (Action::Clients, State::Observed),
            (Action::Providers, State::Observed),
            (Action::Disarm, State::Disarmed),
        ] {
            let query = request(action);
            let response = respond(
                RuntimeMode::Development,
                &runtime,
                vec![9; 16],
                &query,
                &server,
            )
            .await;
            assert_state(&response, &query, state);
        }
    }

    #[tokio::test]
    async fn fixture_query_cannot_impersonate_another_unix_owner() {
        let runtime = runtime();
        let (_client, server) = UnixStream::pair().unwrap();
        let query = request(Action::Arm);
        let response = respond(
            RuntimeMode::Development,
            &runtime,
            vec![9; 16],
            &query,
            &server,
        )
        .await;
        assert_state(&response, &query, State::Armed);
        let different_uid = server.peer_cred().unwrap().uid().wrapping_add(1);
        assert!(
            runtime
                .fixture_correlation(different_uid, &request(Action::Clients))
                .await
                .is_err()
        );
        assert!(
            runtime
                .fixture_correlation(different_uid, &request(Action::Disarm))
                .await
                .is_err()
        );
        let query = request(Action::Clients);
        let response = respond(
            RuntimeMode::Development,
            &runtime,
            vec![9; 16],
            &query,
            &server,
        )
        .await;
        assert_state(&response, &query, State::Observed);
        let query = request(Action::Disarm);
        let response = respond(
            RuntimeMode::Development,
            &runtime,
            vec![9; 16],
            &query,
            &server,
        )
        .await;
        assert_state(&response, &query, State::Disarmed);
    }
}
