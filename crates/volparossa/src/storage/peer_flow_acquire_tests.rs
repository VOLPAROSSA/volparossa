//! Synthetic closed observations and real local IPC, not route or remote-cause proof.

use std::time::Duration;

use serde_json::{Value, json};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, PrivateStorageAppendTiming,
    PrivateStorageDeadlineScope, PrivateStorageFlowAcquireDetail, PrivateStorageFlowAcquireFailure,
    PrivateStorageFlowAcquireReason, PrivateStorageFlowAcquireStage, PrivateStorageOutcome,
    PrivateStorageOutcomeCategory, PrivateStorageOutcomeDeadline, PrivateStorageOutcomePhase,
    PrivateStorageOutcomeStatus, PrivateStorageRemoteDetail, PrivateStorageRemoteStage,
    PrivateStorageStreamFailure, control_request::Operation as ControlOperation,
    control_response::Payload, read_request, write_response,
};

use super::super::{
    diagnostics::{Boundary, Diagnostics, Stage, append_timing_enabled, flow_acquire_enabled},
    outcome, with_diagnostics,
};
use super::*;

const HELPER_REASONS: [&str; 12] = [
    "helper_kernel",
    "helper_capacity",
    "helper_unavailable",
    "helper_not_found",
    "helper_cleanup_incomplete",
    "helper_other_rejection",
    "helper_timeout",
    "helper_io",
    "helper_validation",
    "helper_authority",
    "helper_correlation",
    "helper_runtime_changed",
];

fn report() -> Value {
    json!({"version": 8, "failures": [{
        "fragment_index": null, "copy_index": 0, "operation": "reserve",
        "stage": "agent_ready", "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "stream_open", "deadline_scope": "none",
            "tls_failure": null, "stream_failure": "flow_acquire", "challenge": null,
            "flow_acquire": {"rounds": 1,
                "first": {"stage": "helper_acquire", "reason": "helper_capacity"},
                "last": {"stage": "helper_acquire", "reason": "helper_capacity"}}},
        "agent_outcome": null
    }], "omitted_failures": 0})
}

fn replay(value: Value) -> Value {
    serde_json::to_value(serde_json::from_value::<Diagnostics>(value).unwrap()).unwrap()
}

fn allowed(stage: &str, reason: &str) -> bool {
    match stage {
        "source_port" => reason == "entropy",
        "retirement_drain" => {
            matches!(reason, "unconfirmed" | "io")
                || (HELPER_REASONS.contains(&reason) && reason != "helper_not_found")
        }
        "material" => matches!(reason, "metadata" | "topology"),
        "slot_reservation" => {
            matches!(
                reason,
                "unconfirmed" | "local_capacity" | "local_unavailable"
            )
        }
        "helper_acquire" => HELPER_REASONS.contains(&reason),
        "descriptor_clone" => reason == "io",
        "descriptor_adoption" => matches!(reason, "metadata" | "io"),
        "flow_metadata" => reason == "metadata",
        _ => false,
    }
}

#[test]
fn flow_acquire_v8_accepts_exactly_35_pairs_on_each_endpoint() {
    for endpoint in ["first", "last"] {
        let mut accepted = 0;
        for stage in 0..=8 {
            let stage =
                serde_json::to_value(PrivateStorageFlowAcquireStage::try_from(stage).unwrap())
                    .unwrap();
            for reason in 0..=19 {
                let reason = serde_json::to_value(
                    PrivateStorageFlowAcquireReason::try_from(reason).unwrap(),
                )
                .unwrap();
                let mut value = report();
                let summary = &mut value["failures"][0]["agent_detail"]["flow_acquire"];
                summary["rounds"] = 2.into();
                summary[endpoint] = json!({"stage": stage, "reason": reason});
                let expected = allowed(stage.as_str().unwrap(), reason.as_str().unwrap());
                let decoded = serde_json::from_value::<Diagnostics>(value.clone());
                assert_eq!(decoded.is_ok(), expected, "{endpoint} {stage} {reason}");
                if let Ok(decoded) = decoded {
                    accepted += 1;
                    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
                }
            }
        }
        assert_eq!(accepted, 35);
    }
}

#[test]
fn flow_acquire_v8_binds_round_count_and_first_last_equality() {
    for rounds in 1..=8 {
        let mut value = report();
        value["failures"][0]["agent_detail"]["flow_acquire"]["rounds"] = rounds.into();
        assert_eq!(replay(value.clone()), value);
        value["failures"][0]["agent_detail"]["flow_acquire"]["last"]["reason"] =
            "helper_timeout".into();
        assert_eq!(
            serde_json::from_value::<Diagnostics>(value).is_ok(),
            rounds > 1
        );
    }
    for invalid in [
        json!(0),
        json!(9),
        json!(-1),
        json!(1.0),
        json!(true),
        Value::Null,
    ] {
        let mut value = report();
        value["failures"][0]["agent_detail"]["flow_acquire"]["rounds"] = invalid;
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
}

#[test]
fn flow_acquire_v8_rejects_missing_unknown_and_private_fields() {
    for pointer in [
        "/failures/0/agent_detail/flow_acquire",
        "/failures/0/agent_detail/flow_acquire/first",
        "/failures/0/agent_detail/flow_acquire/last",
    ] {
        let original = report();
        let keys: Vec<_> = original
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .collect();
        for key in keys {
            let mut missing = original.clone();
            missing
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
            for invalid in [
                json!(true),
                json!(9),
                json!("/private/prompt-canary"),
                Value::Null,
            ] {
                let mut value = original.clone();
                value.pointer_mut(pointer).unwrap()[key] = invalid;
                assert!(serde_json::from_value::<Diagnostics>(value).is_err());
            }
        }
        for key in ["raw_error", "request_id", "provider", "path", "elapsed_ns"] {
            let mut value = original.clone();
            value.pointer_mut(pointer).unwrap()[key] = json!("/private/prompt-canary");
            assert!(serde_json::from_value::<Diagnostics>(value).is_err());
        }
    }
    for pointer in ["/failures/0", "/failures/0/agent_detail"] {
        let mut value = report();
        value.pointer_mut(pointer).unwrap()["raw_error"] = json!("/private/canary");
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for invalid in [json!(0), json!(9), json!(true)] {
        let mut value = report();
        value["version"] = invalid;
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
}

#[test]
fn flow_acquire_v8_requires_the_original_ready_stream_unavailable_boundary() {
    for (pointer, invalid) in [
        ("/failures/0/stage", json!("wire_receipt")),
        ("/failures/0/category", json!("io")),
        ("/failures/0/agent_code", json!("CONTENT_POLICY")),
        ("/failures/0/agent_code", json!("CONTENT_INVALID")),
        ("/failures/0/agent_code", json!("CONTENT_BUSY")),
        ("/failures/0/agent_code", json!("unknown")),
        ("/failures/0/agent_code", Value::Null),
        ("/failures/0/agent_detail/stage", json!("challenge")),
        (
            "/failures/0/agent_detail/deadline_scope",
            json!("operation"),
        ),
        ("/failures/0/agent_detail/deadline_scope", json!("exchange")),
        ("/failures/0/agent_detail/tls_failure", json!("io")),
        (
            "/failures/0/agent_detail/stream_failure",
            json!("route_state"),
        ),
        ("/failures/0/agent_detail/stream_failure", Value::Null),
        (
            "/failures/0/agent_detail/challenge",
            json!({
                "phase":"challenge_read_verify", "before_challenge":"under_1s",
                "in_challenge":"under_1s"
            }),
        ),
        (
            "/failures/0/agent_outcome",
            json!({
                "status":"missing", "detail":null, "append_timing":null
            }),
        ),
    ] {
        let mut value = report();
        *value.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            serde_json::from_value::<Diagnostics>(value).is_err(),
            "{pointer}"
        );
    }
    let mut missing = report();
    missing["failures"][0]["agent_detail"]
        .as_object_mut()
        .unwrap()
        .remove("flow_acquire");
    assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
    let mut absent = report();
    absent["failures"][0]["agent_detail"]["flow_acquire"] = Value::Null;
    assert_eq!(replay(absent.clone()), absent);
    absent["failures"][0]["agent_detail"] = Value::Null;
    assert_eq!(replay(absent.clone()), absent);
}

#[test]
fn flow_acquire_v8_preserves_exact_historical_json_bytes_and_rejects_cross_generation_keys() {
    for version in 1..=7 {
        let mut detail = String::new();
        if version >= 2 {
            detail.push_str(
                ",\"agent_detail\":{\"stage\":\"provider_lookup\",\"deadline_scope\":\"none\"",
            );
            if version >= 3 {
                detail.push_str(",\"tls_failure\":null");
            }
            if version >= 5 {
                detail.push_str(",\"stream_failure\":null");
            }
            if version >= 6 {
                detail.push_str(",\"challenge\":null");
            }
            detail.push('}');
        }
        if version >= 4 {
            detail.push_str(",\"agent_outcome\":null");
        }
        let original = format!(
            "{{\"version\":{version},\"failures\":[{{\"fragment_index\":null,\"copy_index\":0,\"operation\":\"reserve\",\"stage\":\"agent_ready\",\"category\":\"agent_rejected\",\"agent_code\":\"CONTENT_UNAVAILABLE\"{detail}}}],\"omitted_failures\":0}}"
        );
        let decoded: Diagnostics = serde_json::from_str(&original).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), original);
        for extra in [
            Value::Null,
            report()["failures"][0]["agent_detail"]["flow_acquire"].clone(),
        ] {
            let mut changed: Value = serde_json::from_str(&original).unwrap();
            if version == 1 {
                changed["failures"][0]["agent_detail"] = json!({"flow_acquire":extra});
            } else {
                changed["failures"][0]["agent_detail"]["flow_acquire"] = extra;
            }
            assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
        }
    }
}

#[test]
fn flow_acquire_v8_keeps_the_explicit_v7_append_shape_and_validation() {
    let mut value = report();
    let failure = &mut value["failures"][0];
    failure["operation"] = "append".into();
    failure["stage"] = "wire_receipt".into();
    failure["category"] = "io".into();
    failure["agent_code"] = Value::Null;
    failure["agent_detail"] = Value::Null;
    failure["agent_outcome"] = json!({"status":"observed", "detail":{
        "phase":"remote_receipt_read", "category":"io", "deadline_scope":"none"
    }, "append_timing":{
        "before_payload":"under_1s", "in_payload_write_flush":"1_to_5s",
        "in_receipt_read":"90_to_120s"
    }});
    let mut historical = value.clone();
    historical["version"] = 7.into();
    assert_eq!(replay(historical.clone()), historical);
    assert_eq!(replay(value.clone()), value);
    let mut missing = value.clone();
    missing["failures"][0]["agent_outcome"]
        .as_object_mut()
        .unwrap()
        .remove("append_timing");
    assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
    value["failures"][0]["operation"] = "reserve".into();
    assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    historical["version"] = 6.into();
    assert!(serde_json::from_value::<Diagnostics>(historical).is_err());
}

#[test]
fn flow_acquire_v8_fragment_join_keeps_summaries_and_original_eight_failure_bound() {
    let mut parent: Diagnostics = serde_json::from_value(json!({
        "version":8, "failures":[], "omitted_failures":0
    }))
    .unwrap();
    for fragment in 0..9 {
        let mut child = report();
        child["omitted_failures"] = 2.into();
        parent
            .append_fragment(fragment, &json!({"deposit_diagnostics":child}))
            .unwrap();
    }
    let joined = serde_json::to_value(&parent).unwrap();
    assert_eq!(joined["omitted_failures"], 19);
    assert_eq!(joined["failures"].as_array().unwrap().len(), 8);
    for (fragment, failure) in joined["failures"].as_array().unwrap().iter().enumerate() {
        assert_eq!(failure["fragment_index"], fragment);
        assert_eq!(
            failure["agent_detail"],
            report()["failures"][0]["agent_detail"]
        );
    }
    for version in [6, 7, 9] {
        let other = json!({"version":version,"failures":[],"omitted_failures":5});
        assert!(
            parent
                .append_fragment(12, &json!({"deposit_diagnostics":other}))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&parent).unwrap(), joined);
    }
    let mut oversized = joined;
    oversized["failures"]
        .as_array_mut()
        .unwrap()
        .push(report()["failures"][0].clone());
    assert!(serde_json::from_value::<Diagnostics>(oversized).is_err());
}

#[tokio::test]
async fn flow_acquire_v8_cli_is_explicit_and_mutually_exclusive_with_v7() {
    for group in ["replicas", "fragments"] {
        for (flag, expected) in [
            (None, (false, false)),
            (Some("--append-diagnostics-v7"), (true, false)),
            (Some("--flow-acquire-diagnostics-v8"), (false, true)),
        ] {
            for before in [false, true] {
                let mut args = vec!["volparossa", "storage", group];
                if before {
                    args.extend(flag);
                }
                args.extend(["status", "--state", "/private/not-opened"]);
                if !before {
                    args.extend(flag);
                }
                let cli = crate::Cli::try_parse_from(args).unwrap();
                let crate::CliCommand::Storage { command } = cli.command else {
                    panic!();
                };
                let (crate::storage::Command::Replicas {
                    append_diagnostics_v7,
                    flow_acquire_diagnostics_v8,
                    ..
                }
                | crate::storage::Command::Fragments {
                    append_diagnostics_v7,
                    flow_acquire_diagnostics_v8,
                    ..
                }) = command
                else {
                    panic!();
                };
                assert_eq!(
                    (append_diagnostics_v7, flow_acquire_diagnostics_v8),
                    expected
                );
            }
        }
        for first in ["--append-diagnostics-v7", "--flow-acquire-diagnostics-v8"] {
            let second = if first == "--append-diagnostics-v7" {
                "--flow-acquire-diagnostics-v8"
            } else {
                "--append-diagnostics-v7"
            };
            for (first_before, second_before) in
                [(true, true), (true, false), (false, true), (false, false)]
            {
                let mut args = vec!["volparossa", "storage", group];
                if first_before {
                    args.push(first);
                }
                if second_before {
                    args.push(second);
                }
                args.extend(["status", "--state", "/not-opened"]);
                if !first_before {
                    args.push(first);
                }
                if !second_before {
                    args.push(second);
                }
                let kind = match crate::Cli::try_parse_from(args) {
                    Err(error) => error.kind(),
                    Ok(cli) => crate::dispatch(cli)
                        .await
                        .expect_err("conflict must precede all storage work")
                        .downcast::<clap::Error>()
                        .expect("typed argument conflict, not a later state or socket error")
                        .kind(),
                };
                assert_eq!(kind, clap::error::ErrorKind::ArgumentConflict);
            }
        }
    }
    for group in ["local", "peer"] {
        let error = crate::Cli::try_parse_from([
            "volparossa",
            "storage",
            group,
            "--flow-acquire-diagnostics-v8",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}

fn selected_version() -> Value {
    serde_json::to_value(Diagnostics::default()).unwrap()["version"].clone()
}

#[tokio::test(start_paused = true)]
async fn flow_acquire_v8_selection_is_cleared_on_error_cancel_and_nested_command() {
    assert_eq!(selected_version(), 6);
    let result = with_diagnostics(false, true, async {
        assert!(flow_acquire_enabled() && append_timing_enabled());
        assert_eq!(selected_version(), 8);
        with_diagnostics(false, false, async {
            assert!(!flow_acquire_enabled() && !append_timing_enabled());
            assert_eq!(selected_version(), 6);
        })
        .await;
        with_diagnostics(true, false, async {
            assert!(!flow_acquire_enabled() && append_timing_enabled());
            assert_eq!(selected_version(), 7);
        })
        .await;
        assert_eq!(selected_version(), 8);
        assert_eq!(tokio::spawn(async { selected_version() }).await.unwrap(), 6);
        Err::<(), _>("original-error")
    })
    .await;
    assert_eq!(result, Err("original-error"));
    assert!(!flow_acquire_enabled() && !append_timing_enabled());
    let cancelled = tokio::time::timeout(
        Duration::from_secs(1),
        with_diagnostics(false, true, async {
            assert_eq!(selected_version(), 8);
            std::future::pending::<()>().await;
        }),
    )
    .await;
    assert!(cancelled.is_err());
    assert!(!flow_acquire_enabled() && !append_timing_enabled());
    assert_eq!(selected_version(), 6);
}

#[tokio::test]
async fn flow_acquire_v8_concurrent_commands_never_share_opt_in() {
    let barrier = tokio::sync::Barrier::new(3);
    let command = |append, flow, version| {
        let barrier = &barrier;
        async move {
            with_diagnostics(append, flow, async {
                barrier.wait().await;
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                    assert_eq!(flow_acquire_enabled(), flow);
                    assert_eq!(append_timing_enabled(), append || flow);
                    assert_eq!(selected_version(), version);
                }
            })
            .await;
        }
    };
    tokio::join!(
        command(false, false, 6),
        command(true, false, 7),
        command(false, true, 8)
    );
    assert_eq!(selected_version(), 6);
}

fn wire_detail() -> PrivateStorageRemoteDetail {
    let endpoint = PrivateStorageFlowAcquireFailure {
        stage: PrivateStorageFlowAcquireStage::HelperAcquire as i32,
        reason: PrivateStorageFlowAcquireReason::HelperCapacity as i32,
    };
    PrivateStorageRemoteDetail {
        stage: PrivateStorageRemoteStage::StreamOpen as i32,
        deadline_scope: PrivateStorageDeadlineScope::None as i32,
        tls_failure: None,
        stream_failure: Some(PrivateStorageStreamFailure::FlowAcquire as i32),
        challenge: None,
        flow_acquire: Some(PrivateStorageFlowAcquireDetail {
            rounds: 1,
            first: Some(endpoint),
            last: Some(endpoint),
        }),
    }
}

#[tokio::test]
async fn flow_acquire_v8_real_transfer_sets_only_opted_request_and_projects_correlated_failure() {
    for (append, flow, version) in [(false, false, 6), (true, false, 7), (false, true, 8)] {
        Box::pin(with_diagnostics(append, flow, async {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("private-canary.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let (_provider, owner, grant) = fixture_grant();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await.unwrap();
                let Some(ControlOperation::PrivateStorageRemote(remote)) = request.operation else {
                    panic!("expected the original transfer request");
                };
                assert_eq!(remote.include_flow_acquire_detail, flow);
                write_response(
                    &mut stream,
                    &ControlResponse {
                        protocol_version: CONTROL_PROTOCOL_VERSION,
                        request_id: request.request_id,
                        result: ControlResult::Unavailable as i32,
                        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
                        // Even an unsolicited typed detail never expands a legacy report.
                        private_storage_remote_detail: Some(wire_detail()),
                        payload: Some(Payload::Ack(Empty {})),
                    },
                )
                .await
                .unwrap();
                listener
            });
            let target = StorageTarget {
                archive_id: [5; 32],
                lease_id: None,
                ciphertext_bytes: 32,
                sha256: [7; 32],
            };
            let operation = StorageOperation::Reserve {
                expires_at: crate::storage::now().unwrap() + 600,
            };
            let error = transfer::remote(&socket, &grant, &owner, target, operation, &[])
                .await
                .err()
                .unwrap();
            let listener = server.await.unwrap();
            // A pre-READY rejection does not start the later one-use outcome query.
            assert!(
                tokio::time::timeout(Duration::ZERO, listener.accept())
                    .await
                    .is_err()
            );
            let mut diagnostics = Diagnostics::default();
            diagnostics.push(0, &error, Boundary::new(operation, Stage::Unknown));
            let actual = serde_json::to_value(diagnostics).unwrap();
            assert_eq!(actual["version"], version);
            assert_eq!(actual["failures"][0]["stage"], "agent_ready");
            assert_eq!(actual["failures"][0]["agent_code"], "CONTENT_UNAVAILABLE");
            assert!(actual["failures"][0]["agent_outcome"].is_null());
            if flow {
                assert_eq!(actual, report());
            } else {
                assert!(
                    actual["failures"][0]["agent_detail"]
                        .get("flow_acquire")
                        .is_none()
                );
            }
            assert_eq!(replay(actual.clone()), actual);
            assert!(!actual.to_string().contains("private-canary"));
        }))
        .await;
    }
}

#[tokio::test]
async fn flow_acquire_v8_reuses_the_same_bounded_append_outcome_query() {
    with_diagnostics(false, true, async {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("query.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let Some(ControlOperation::PrivateStorageOutcome(query)) = request.operation else {
                panic!("only the existing outcome query is allowed");
            };
            assert_eq!(query.original_request_id, [43; 16]);
            assert!(query.include_append_timing);
            write_response(
                &mut stream,
                &ControlResponse {
                    protocol_version: CONTROL_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: ControlResult::Ok as i32,
                    diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
                    private_storage_remote_detail: None,
                    payload: Some(Payload::PrivateStorageOutcome(PrivateStorageOutcome {
                        status: PrivateStorageOutcomeStatus::Observed as i32,
                        phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
                        category: PrivateStorageOutcomeCategory::Io as i32,
                        deadline: PrivateStorageOutcomeDeadline::None as i32,
                        append_timing: Some(PrivateStorageAppendTiming {
                            before_payload: 1,
                            in_payload_write_flush: 2,
                            in_receipt_read: Some(7),
                        }),
                    })),
                },
            )
            .await
            .unwrap();
            listener
        });
        let observed = outcome::query(&socket, &[43; 16]).await;
        let listener = server.await.unwrap();
        assert!(observed.valid() && observed.has_append_timing());
        assert!(
            tokio::time::timeout(Duration::ZERO, listener.accept())
                .await
                .is_err()
        );
        let value = serde_json::to_value(outcome::AppendOutcome::from(observed)).unwrap();
        assert_eq!(
            value["append_timing"],
            json!({
                "before_payload":"under_1s", "in_payload_write_flush":"1_to_5s",
                "in_receipt_read":"90_to_120s"
            })
        );
    })
    .await;
}

#[tokio::test]
async fn flow_acquire_v8_never_classifies_free_text_or_exports_private_error_context() {
    with_diagnostics(false, true, async {
        let mut diagnostics = Diagnostics::default();
        diagnostics.push(
            0,
            &anyhow::anyhow!(
                "CONTENT_UNAVAILABLE flow_acquire helper_capacity /private/prompt-canary"
            ),
            Boundary::new(StorageOperation::Finalize, Stage::AgentReady),
        );
        let value = serde_json::to_value(diagnostics).unwrap();
        assert_eq!(value["version"], 8);
        assert_eq!(value["failures"][0]["category"], "unknown");
        for field in ["agent_code", "agent_detail", "agent_outcome"] {
            assert!(value["failures"][0][field].is_null());
        }
        for private in [
            "CONTENT_UNAVAILABLE",
            "flow_acquire",
            "helper_capacity",
            "prompt-canary",
        ] {
            assert!(!value.to_string().contains(private));
        }
    })
    .await;
}
