//! Diagnostic-only finite projection, with no operator correlation ID in JSON.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use volparossa_local_control::{
    ContentProviderActivity, Empty, ProviderActivityElapsedBucket, ProviderActivityStage,
    ProviderActivityState, control_request::Operation, control_response::Payload,
};

pub(super) async fn run(socket: &Path) -> Result<()> {
    println!("{}", query(socket).await?);
    Ok(())
}

async fn query(socket: &Path) -> Result<Value> {
    let response =
        crate::control::request(socket, Operation::ContentProviderActivity(Empty {})).await?;
    let Some(Payload::ContentProviderActivity(snapshot)) = response.payload else {
        bail!("agent returned no provider activity snapshot");
    };
    project(&snapshot)
}

fn project(snapshot: &ContentProviderActivity) -> Result<Value> {
    snapshot.validate()?;
    let groups = snapshot
        .groups
        .iter()
        .map(|group| {
            Ok(json!({
                "stage": ProviderActivityStage::try_from(group.stage)?,
                "elapsed_bucket": ProviderActivityElapsedBucket::try_from(group.elapsed_bucket)?,
                "count": group.count,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "version": 1,
        "kind": "content-provider-activity",
        "state": ProviderActivityState::try_from(snapshot.state)?,
        "active_sessions": snapshot.active_sessions,
        "groups": groups,
        "diagnostic_only": true,
        "acceptance_evidence": false,
        "causal_attribution": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_local_control::ProviderActivityGroup;

    #[test]
    fn provider_activity_json_is_exact_and_cannot_claim_acceptance() {
        let snapshot = ContentProviderActivity {
            version: 1,
            state: ProviderActivityState::Observed as i32,
            active_sessions: Some(1),
            groups: vec![ProviderActivityGroup {
                stage: ProviderActivityStage::StorageGrantReadVerify as i32,
                elapsed_bucket: ProviderActivityElapsedBucket::From90To120s as i32,
                count: 1,
            }],
        };
        assert_eq!(
            project(&snapshot).unwrap(),
            json!({
                "version":1, "kind":"content-provider-activity", "state":"observed",
                "active_sessions":1,
                "groups":[{"stage":"storage_grant_read_verify", "elapsed_bucket":"90_to_120s", "count":1}],
                "diagnostic_only":true, "acceptance_evidence":false, "causal_attribution":false,
            })
        );
    }

    #[test]
    fn unavailable_is_not_an_empty_observation_and_invalid_data_is_rejected() {
        let mut snapshot = ContentProviderActivity::unavailable();
        let value = project(&snapshot).unwrap();
        assert_eq!(value["state"], "unavailable");
        assert!(value["active_sessions"].is_null());
        assert_eq!(value["groups"], json!([]));
        snapshot.active_sessions = Some(0);
        assert!(project(&snapshot).is_err());
    }

    #[test]
    fn all_stage_and_bucket_spellings_are_closed() {
        let stages = [
            "tls_handshake",
            "registry_snapshot",
            "selector_read",
            "storage_grant_read_verify",
            "storage_challenge_write_flush",
            "storage_request_read_verify",
            "storage_operation",
            "other_protocol",
            "closing",
        ];
        let buckets = [
            "under_1s",
            "1_to_5s",
            "5_to_15s",
            "15_to_30s",
            "30_to_60s",
            "60_to_90s",
            "90_to_120s",
            "at_least_120s",
        ];
        for (index, name) in stages.into_iter().enumerate() {
            let stage = ProviderActivityStage::try_from(i32::try_from(index + 1).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(stage).unwrap(), name);
        }
        for (index, name) in buckets.into_iter().enumerate() {
            let bucket =
                ProviderActivityElapsedBucket::try_from(i32::try_from(index + 1).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(bucket).unwrap(), name);
        }
    }

    #[tokio::test]
    async fn provider_activity_uses_correlated_typed_local_control_and_rejects_other_payloads() {
        use volparossa_local_control::{
            CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, read_request, write_response,
        };

        for expected in [true, false] {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("operator.sock");
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await.unwrap();
                assert!(matches!(
                    request.operation,
                    Some(Operation::ContentProviderActivity(_))
                ));
                write_response(
                    &mut stream,
                    &ControlResponse {
                        protocol_version: CONTROL_PROTOCOL_VERSION,
                        request_id: request.request_id,
                        result: ControlResult::Ok as i32,
                        diagnostic_code: if expected {
                            "CONTENT_PROVIDER_ACTIVITY"
                        } else {
                            "OK"
                        }
                        .into(),
                        private_storage_remote_detail: None,
                        payload: Some(if expected {
                            Payload::ContentProviderActivity(ContentProviderActivity::unavailable())
                        } else {
                            Payload::Ack(Empty {})
                        }),
                    },
                )
                .await
                .unwrap();
            });
            let value = tokio::time::timeout(std::time::Duration::from_secs(5), query(&path))
                .await
                .unwrap();
            assert_eq!(value.is_ok(), expected);
            if let Ok(value) = value {
                assert!(value.get("request_id").is_none());
                assert!(value.get("path").is_none());
                assert_eq!(value["state"], "unavailable");
            }
            task.await.unwrap();
        }
    }
}
