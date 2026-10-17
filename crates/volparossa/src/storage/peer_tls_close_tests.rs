use super::*;
use clap::Parser;
use serde_json::{Value, json};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, PrivateStorageOutcome,
    PrivateStorageOutcomeCategory, PrivateStorageOutcomePhase, PrivateStorageOutcomeStatus,
    PrivateStorageTlsCloseFailure, control_request::Operation as ControlOperation,
    control_response::Payload, read_request, write_response,
};

use super::super::{outcome, with_all_diagnostics};

fn report() -> Value {
    json!({"version": 9, "failures": [{
        "fragment_index": null, "copy_index": 0, "operation": "reserve",
        "stage": "agent_terminal", "category": "io", "agent_code": null,
        "agent_detail": null,
        "agent_outcome": {"status": "observed", "detail": {
            "phase": "transport_tls_close", "category": "unavailable", "deadline_scope": "none"
        }, "append_timing": null, "tls_close_failure": "read_io"}
    }], "omitted_failures": 0})
}

fn replay(value: Value) -> Value {
    serde_json::to_value(serde_json::from_value::<Diagnostics>(value).unwrap()).unwrap()
}

#[test]
fn tls_close_v9_json_accepts_exact_four_reasons_and_nullable_older_agent() {
    for failure in [
        Value::Null,
        json!("shutdown_io"),
        json!("read_io"),
        json!("trailing_data"),
        json!("internal_deadline"),
    ] {
        let mut value = report();
        value["failures"][0]["agent_outcome"]["tls_close_failure"] = failure;
        assert_eq!(replay(value.clone()), value);
    }
    for status in [
        "missing",
        "pending",
        "expired",
        "query_failed",
        "query_timeout",
    ] {
        let mut value = report();
        value["failures"][0]["agent_outcome"] = json!({
            "status": status, "detail": null, "append_timing": null, "tls_close_failure": null
        });
        assert_eq!(replay(value.clone()), value);
    }
}

#[test]
fn tls_close_v9_json_rejects_unknown_missing_private_and_impossible_fields() {
    for invalid in [
        json!(0),
        json!(1),
        json!(true),
        json!({}),
        json!("unspecified"),
        json!("reset"),
        json!("private-canary"),
    ] {
        let mut value = report();
        value["failures"][0]["agent_outcome"]["tls_close_failure"] = invalid;
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for (field, invalid) in [
        ("phase", "provider_tls_close"),
        ("category", "io"),
        ("category", "timeout"),
        ("deadline_scope", "exchange"),
    ] {
        let mut value = report();
        value["failures"][0]["agent_outcome"]["detail"][field] = invalid.into();
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for field in ["tls_close_failure", "append_timing"] {
        let mut value = report();
        value["failures"][0]["agent_outcome"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for field in [
        "original_request_id",
        "errno",
        "raw_error",
        "payload",
        "provider",
    ] {
        let mut value = report();
        value["failures"][0]["agent_outcome"][field] = "private-canary".into();
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for path in ["stage", "operation"] {
        let mut value = report();
        if path == "stage" {
            value["failures"][0][path] = "agent_ready".into();
        } else {
            value["failures"][0]["agent_outcome"]["append_timing"] = json!({
                "before_payload": "under_1s", "in_payload_write_flush": "under_1s",
                "in_receipt_read": null
            });
        }
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
}

#[test]
fn tls_close_v9_json_does_not_change_any_historical_outcome_encoding() {
    for version in 1..=8 {
        let mut value = report();
        value["version"] = version.into();
        let failure = value["failures"][0].as_object_mut().unwrap();
        if version < 4 {
            failure.remove("agent_outcome");
        } else {
            let outcome = failure["agent_outcome"].as_object_mut().unwrap();
            outcome.remove("tls_close_failure");
            if version < 7 {
                outcome.remove("append_timing");
            }
        }
        if version == 1 {
            failure.remove("agent_detail");
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(serde_json::to_vec(&replay(value.clone())).unwrap(), bytes);
        if version >= 4 {
            value["failures"][0]["agent_outcome"]["tls_close_failure"] = Value::Null;
            assert!(serde_json::from_value::<Diagnostics>(value).is_err());
        }
    }
    let mut future = report();
    future["version"] = 10.into();
    assert!(serde_json::from_value::<Diagnostics>(future).is_err());
}

#[test]
fn tls_close_v9_retains_v8_flow_and_v7_append_fields() {
    let mut value = report();
    value["failures"][0] = json!({
        "fragment_index": null, "copy_index": 0, "operation": "reserve",
        "stage": "agent_ready", "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_outcome": null, "agent_detail": {
            "stage": "stream_open", "deadline_scope": "none", "tls_failure": null,
            "stream_failure": "flow_acquire", "challenge": null,
            "flow_acquire": {"rounds": 1,
                "first": {"stage": "helper_acquire", "reason": "helper_capacity"},
                "last": {"stage": "helper_acquire", "reason": "helper_capacity"}}
        }
    });
    assert_eq!(replay(value.clone()), value);
    let mut value = report();
    value["failures"][0]["operation"] = "append".into();
    let outcome = &mut value["failures"][0]["agent_outcome"];
    outcome["tls_close_failure"] = Value::Null;
    outcome["detail"]["phase"] = "remote_payload_write".into();
    outcome["append_timing"] = json!({
        "before_payload": "under_1s", "in_payload_write_flush": "under_1s", "in_receipt_read": null
    });
    assert_eq!(replay(value.clone()), value);
}

#[tokio::test]
async fn tls_close_v9_same_error_chain_keeps_original_failure_fragment_copy_and_bound() {
    Box::pin(with_all_diagnostics(false, false, true, async {
        let outcome: outcome::CloseOutcome =
            serde_json::from_value(report()["failures"][0]["agent_outcome"].clone()).unwrap();
        let outcome = AgentOutcome::from(outcome);
        let error = Error::new(io::Error::other("private-canary"))
            .context(outcome)
            .context(Boundary {
                operation: Operation::Reserve,
                stage: Stage::AgentTerminal,
            });
        let mut child = Diagnostics::default();
        child.push(
            1,
            &error,
            Boundary {
                operation: Operation::Prepare,
                stage: Stage::Unknown,
            },
        );
        assert!(error.downcast_ref::<io::Error>().is_some());
        let child = json!({"deposit_diagnostics": child});
        let mut parent = Diagnostics::default();
        for fragment in 0..10 {
            parent.append_fragment(fragment, &child).unwrap();
        }
        let value = serde_json::to_value(parent).unwrap();
        assert_eq!(value["failures"].as_array().unwrap().len(), 8);
        assert_eq!(value["omitted_failures"], 2);
        for (fragment, failure) in value["failures"].as_array().unwrap().iter().enumerate() {
            assert_eq!(failure["fragment_index"], fragment);
            assert_eq!(failure["copy_index"], 1);
            assert_eq!(failure["operation"], "reserve");
            assert_eq!(failure["agent_outcome"]["tls_close_failure"], "read_io");
        }
        assert!(!value.to_string().contains("private-canary"));
        assert_eq!(replay(value.clone()), value);
        let mut old = child;
        old["deposit_diagnostics"]["version"] = 8.into();
        let mut parent = Diagnostics::default();
        assert!(parent.append_fragment(0, &old).is_err());
    }))
    .await;
}

async fn answer_close(
    listener: tokio::net::UnixListener,
    enabled: bool,
    replies: Vec<PrivateStorageOutcome>,
) {
    let mut query_ids = Vec::new();
    for outcome in replies {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(ControlOperation::PrivateStorageOutcome(query)) = request.operation else {
            panic!();
        };
        assert_eq!(query.original_request_id, [45; 16]);
        assert_eq!(query.include_tls_close_failure, enabled);
        assert_eq!(query.include_append_timing, enabled);
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

fn wire_close() -> PrivateStorageOutcome {
    PrivateStorageOutcome {
        status: PrivateStorageOutcomeStatus::Observed as i32,
        phase: PrivateStorageOutcomePhase::TransportTlsClose as i32,
        category: PrivateStorageOutcomeCategory::Unavailable as i32,
        tls_close_failure: Some(PrivateStorageTlsCloseFailure::ReadIo as i32),
        ..PrivateStorageOutcome::default()
    }
}

#[tokio::test]
async fn tls_close_v9_real_ipc_opt_in_pending_and_unsolicited_detail_are_closed() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("query.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let pending = PrivateStorageOutcome {
            status: PrivateStorageOutcomeStatus::Pending as i32,
            ..PrivateStorageOutcome::default()
        };
        let server = tokio::spawn(answer_close(listener, enabled, vec![pending, wire_close()]));
        let observed = Box::pin(with_all_diagnostics(
            false,
            false,
            enabled,
            outcome::query(&socket, &[45; 16]),
        ))
        .await;
        server.await.unwrap();
        assert!(observed.valid());
        let value = serde_json::to_value(outcome::CloseOutcome::from(observed)).unwrap();
        assert_eq!(
            value["status"],
            if enabled { "observed" } else { "query_failed" }
        );
        assert_eq!(
            value["tls_close_failure"],
            if enabled {
                json!("read_io")
            } else {
                Value::Null
            }
        );
    }
}

#[tokio::test]
async fn tls_close_v9_real_ipc_pending_stops_after_three_queries() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("query.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let pending = PrivateStorageOutcome {
        status: PrivateStorageOutcomeStatus::Pending as i32,
        ..PrivateStorageOutcome::default()
    };
    let server = tokio::spawn(answer_close(listener, true, vec![pending; 3]));
    let observed = Box::pin(with_all_diagnostics(
        false,
        false,
        true,
        outcome::query(&socket, &[45; 16]),
    ))
    .await;
    server.await.unwrap();
    assert_eq!(
        serde_json::to_value(outcome::CloseOutcome::from(observed)).unwrap()["status"],
        "pending"
    );
}

#[tokio::test]
async fn tls_close_v9_real_ipc_stall_keeps_one_second_query_budget() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("query.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(ControlOperation::PrivateStorageOutcome(query)) = request.operation else {
            panic!();
        };
        assert!(query.include_tls_close_failure);
        std::future::pending::<()>().await;
        drop(stream);
    });
    let started = tokio::time::Instant::now();
    let observed = Box::pin(tokio::time::timeout(
        std::time::Duration::from_secs(3),
        with_all_diagnostics(false, false, true, outcome::query(&socket, &[45; 16])),
    ))
    .await;
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let observed = observed.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    let value = serde_json::to_value(outcome::CloseOutcome::from(observed)).unwrap();
    assert_eq!(value["status"], "query_timeout");
    assert!(value["tls_close_failure"].is_null());
}

#[tokio::test]
async fn tls_close_v9_task_local_selection_does_not_leak_into_legacy_scope() {
    with_all_diagnostics(false, false, true, async {
        assert!(tls_close_enabled());
        assert!(flow_acquire_enabled());
        assert!(append_timing_enabled());
        assert_eq!(
            serde_json::to_value(Diagnostics::default()).unwrap()["version"],
            9
        );
        with_all_diagnostics(false, true, false, async {
            assert!(!tls_close_enabled());
            assert_eq!(
                serde_json::to_value(Diagnostics::default()).unwrap()["version"],
                8
            );
        })
        .await;
        assert!(tls_close_enabled());
    })
    .await;
    assert!(!tls_close_enabled());
    assert_eq!(
        serde_json::to_value(Diagnostics::default()).unwrap()["version"],
        6
    );
}

#[tokio::test]
async fn tls_close_v9_cli_is_explicit_and_all_mixed_selectors_reject_before_io() {
    for group in ["replicas", "fragments"] {
        for before in [false, true] {
            let mut args = vec!["volparossa", "storage", group];
            if before {
                args.push("--tls-close-diagnostics-v9");
            }
            args.extend(["status", "--state", "/not-opened"]);
            if !before {
                args.push("--tls-close-diagnostics-v9");
            }
            let cli = crate::Cli::try_parse_from(args).unwrap();
            let crate::CliCommand::Storage { command } = cli.command else {
                panic!();
            };
            let (crate::storage::Command::Replicas {
                tls_close_diagnostics_v9,
                ..
            }
            | crate::storage::Command::Fragments {
                tls_close_diagnostics_v9,
                ..
            }) = command
            else {
                panic!();
            };
            assert!(tls_close_diagnostics_v9);
        }
        for old in ["--append-diagnostics-v7", "--flow-acquire-diagnostics-v8"] {
            for (first, second) in [
                (old, "--tls-close-diagnostics-v9"),
                ("--tls-close-diagnostics-v9", old),
            ] {
                for (a, b) in [(true, true), (true, false), (false, true), (false, false)] {
                    let mut args = vec!["volparossa", "storage", group];
                    if a {
                        args.push(first);
                    }
                    if b {
                        args.push(second);
                    }
                    args.extend(["status", "--state", "/not-opened"]);
                    if !a {
                        args.push(first);
                    }
                    if !b {
                        args.push(second);
                    }
                    let kind = match crate::Cli::try_parse_from(args) {
                        Err(error) => error.kind(),
                        Ok(cli) => crate::dispatch(cli)
                            .await
                            .unwrap_err()
                            .downcast::<clap::Error>()
                            .unwrap()
                            .kind(),
                    };
                    assert_eq!(kind, clap::error::ErrorKind::ArgumentConflict);
                }
            }
        }
    }
}
