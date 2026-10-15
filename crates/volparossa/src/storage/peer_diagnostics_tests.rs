//! Synthetic boundary/error tests; none proves a protected route or remote denial.

use super::*;

#[path = "peer_append_diagnostics_tests.rs"]
mod append_tests;

#[path = "peer_challenge_diagnostics_tests.rs"]
mod challenge_tests;

fn value(error: &Error) -> serde_json::Value {
    let mut diagnostics = Diagnostics::default();
    diagnostics.push(
        1,
        error,
        Boundary {
            operation: Operation::Prepare,
            stage: Stage::Unknown,
        },
    );
    serde_json::to_value(diagnostics).unwrap()
}

#[test]
fn closed_diagnostic_preserves_typed_boundary_without_private_error_text() {
    let error = Error::new(io::Error::other(
        "/private/owner.key secret-key provider-id",
    ))
    .context(Boundary::new(
        StorageOperation::Finalize,
        Stage::JournalSave,
    ));
    let report = value(&error);
    assert_eq!(
        report["failures"][0],
        serde_json::json!({
            "fragment_index": null, "copy_index": 1, "operation": "finalize",
            "stage": "journal_save", "category": "io", "agent_code": null,
            "agent_detail": null, "agent_outcome": null
        })
    );
    let encoded = report.to_string();
    for secret in ["private", "owner.key", "secret-key", "provider-id"] {
        assert!(!encoded.contains(secret));
    }
    let unknown = value(&anyhow::anyhow!("CONTENT_BUSY provider quota /secret"));
    assert_eq!(unknown["failures"][0]["category"], "unknown");
    assert!(unknown["failures"][0]["agent_code"].is_null());
    // The real terminal reader wraps EOF in the typed local-control error.
    let closed = value(
        &Error::new(volparossa_local_control::ControlProtocolError::Io(
            io::Error::from(io::ErrorKind::UnexpectedEof),
        ))
        .context(Boundary::new(
            StorageOperation::Reserve { expires_at: 123 },
            Stage::AgentTerminal,
        )),
    );
    assert_eq!(closed["failures"][0]["category"], "io");
    assert_eq!(closed["failures"][0]["stage"], "agent_terminal");
}

#[test]
fn all_wire_error_families_remain_observations_not_invented_provider_denials() {
    let cases = [
        (
            WireError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
            "io",
        ),
        (WireError::Protocol(ProtocolError::Expired), "protocol"),
        (WireError::Invalid, "invalid"),
        (WireError::Busy, "busy"),
        (WireError::Store, "store"),
        (WireError::Timeout, "timeout"),
    ];
    for (error, expected) in cases {
        let report = value(&Error::new(error).context(Boundary::new(
            StorageOperation::Reserve { expires_at: 123 },
            Stage::WireReceipt,
        )));
        assert_eq!(report["failures"][0]["category"], expected);
        assert_eq!(report["failures"][0]["stage"], "wire_receipt");
        assert!(report["failures"][0]["agent_code"].is_null());
    }
}

#[tokio::test]
async fn agent_code_requires_actual_correlated_rejection_and_is_closed() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, control_response::Payload,
        write_response,
    };
    for (code, expected) in [
        ("CONTENT_INVALID", "CONTENT_INVALID"),
        ("CONTENT_UNAVAILABLE", "CONTENT_UNAVAILABLE"),
        ("CONTENT_BUSY", "CONTENT_BUSY"),
        ("CONTENT_POLICY", "CONTENT_POLICY"),
        ("PRIVATE_UNLISTED_CODE", "unknown"),
    ] {
        let (mut owner, mut agent) = tokio::net::UnixStream::pair().unwrap();
        write_response(
            &mut agent,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![1; 16],
                result: ControlResult::Unavailable as i32,
                diagnostic_code: code.into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::Ack(Empty {})),
            },
        )
        .await
        .unwrap();
        let error = crate::control::finish_request(&mut owner, &[1; 16])
            .await
            .unwrap_err();
        let report =
            value(&error.context(Boundary::new(StorageOperation::Progress, Stage::AgentReady)));
        assert_eq!(report["failures"][0]["category"], "agent_rejected");
        assert_eq!(report["failures"][0]["agent_code"], expected);
        assert!(!report.to_string().contains("private"));
        assert!(!report.to_string().contains("secret"));
        assert!(!report.to_string().contains("PRIVATE_UNLISTED_CODE"));
    }
}

#[tokio::test]
async fn actual_timeout_error_is_typed_without_exporting_context_text() {
    let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    let report = value(
        &Error::new(elapsed).context(Boundary::new(StorageOperation::Finalize, Stage::Deadline)),
    );
    assert_eq!(report["failures"][0]["category"], "timeout");
    assert_eq!(report["failures"][0]["stage"], "deadline");
    assert!(report["failures"][0]["agent_code"].is_null());
}

#[test]
fn fragment_aggregation_retains_first_eight_failures_and_exact_omission_count() {
    let mut parent = Diagnostics::default();
    for fragment in 0..256 {
        let mut child = Diagnostics::default();
        for copy in 0..8 {
            child.push(
                copy,
                &anyhow::anyhow!("synthetic"),
                Boundary {
                    operation: Operation::Prepare,
                    stage: Stage::JournalOpen,
                },
            );
        }
        parent
            .append_fragment(fragment, &serde_json::json!({"deposit_diagnostics": child}))
            .unwrap();
    }
    let report = serde_json::to_value(parent).unwrap();
    assert_eq!(report["omitted_failures"], 2040);
    let failures = report["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 8);
    for (copy, failure) in failures.iter().enumerate() {
        assert_eq!(failure["fragment_index"], 0);
        assert_eq!(failure["copy_index"], copy);
    }
    assert!(report.to_string().len() < 2048);
}

#[test]
fn diagnostic_enum_decoding_rejects_uncontrolled_fields_and_categories() {
    let report = value(&anyhow::anyhow!("synthetic"));
    for field in ["operation", "stage", "category", "agent_code"] {
        let mut changed = report.clone();
        changed["failures"][0][field] = "private-arbitrary-text".into();
        assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    }
    let mut changed = report;
    changed["failures"][0]["raw_error"] = "private-arbitrary-text".into();
    assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
}

#[test]
fn diagnostic_v1_replay_is_exact_and_v2_requires_its_new_nullable_field() {
    let historical = serde_json::json!({"version": 1, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 0, "operation": "reserve", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE"
    }]});
    let decoded: Diagnostics = serde_json::from_value(historical.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), historical);
    let mut changed = historical.clone();
    changed["version"] = 2.into();
    assert!(serde_json::from_value::<Diagnostics>(changed.clone()).is_err());
    changed["failures"][0]["agent_detail"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Diagnostics>(changed.clone()).is_ok());
    changed["version"] = 1.into();
    assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    let current = value(&anyhow::anyhow!("private-canary"));
    assert_eq!(current["version"], 6);
    assert_eq!(current["failures"][0].as_object().unwrap().len(), 8);
    assert!(current["failures"][0]["agent_detail"].is_null());
    assert!(current["failures"][0]["agent_outcome"].is_null());
    for version in [0, 7] {
        let mut changed = historical.clone();
        changed["version"] = version.into();
        assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    }
}

#[test]
fn diagnostic_v2_detail_is_closed_and_bound_to_agent_ready_rejection() {
    let mut report = serde_json::json!({"version": 2, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 0, "operation": "reserve", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "provider_lookup", "deadline_scope": "operation"}
    }]});
    let decoded: Diagnostics = serde_json::from_value(report.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), report);
    for field in ["stage", "deadline_scope", "private-canary"] {
        let mut changed = report.clone();
        changed["failures"][0]["agent_detail"][field] = "private-canary".into();
        assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    }
    for (field, replacement) in [
        ("stage", "agent_terminal"),
        ("category", "io"),
        ("agent_code", "unknown"),
    ] {
        let mut changed = report.clone();
        changed["failures"][0][field] = replacement.into();
        assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    }
    let failure = report["failures"][0].clone();
    report["failures"] = serde_json::Value::Array(vec![failure; 9]);
    assert!(serde_json::from_value::<Diagnostics>(report).is_err());
}

#[tokio::test]
async fn correlated_agent_detail_reaches_only_the_bounded_ready_failure_projection() {
    correlated_projection_case(
        PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: PrivateStorageRemoteStage::TlsHandshake as i32,
            deadline_scope: PrivateStorageDeadlineScope::None as i32,
            tls_failure: Some(PrivateStorageTlsFailure::Io as i32),
            stream_failure: None,
            challenge: None,
        },
        serde_json::json!({"stage":"tls_handshake","deadline_scope":"none","tls_failure":"io",
            "stream_failure":null,"challenge":null}),
    )
    .await;
    for code in 1..=10 {
        let failure = PrivateStorageStreamFailure::try_from(code).unwrap();
        correlated_projection_case(
            PrivateStorageRemoteDetail {
                flow_acquire: None,
                stage: PrivateStorageRemoteStage::StreamOpen as i32,
                deadline_scope: PrivateStorageDeadlineScope::None as i32,
                tls_failure: None,
                stream_failure: Some(code),
                challenge: None,
            },
            serde_json::json!({"stage":"stream_open","deadline_scope":"none","tls_failure":null,
                "stream_failure":failure,"challenge":null}),
        )
        .await;
    }
}

async fn correlated_projection_case(
    detail: PrivateStorageRemoteDetail,
    expected: serde_json::Value,
) {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, Empty, PrivateStorageRemoteRequest,
        control_request, control_response::Payload, read_request, write_response,
    };
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("private-canary.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Unavailable as i32,
                diagnostic_code: "CONTENT_UNAVAILABLE".into(),
                private_storage_remote_detail: Some(detail),
                payload: Some(Payload::Ack(Empty {})),
            },
        )
        .await
        .unwrap();
    });
    let error = crate::control::begin_request(
        &socket,
        control_request::Operation::PrivateStorageRemote(PrivateStorageRemoteRequest {
            include_flow_acquire_detail: false,
            provider_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            grant: vec![1],
            maintenance_turn: Vec::new(),
        }),
    )
    .await
    .unwrap_err();
    server.await.unwrap();
    let hidden = value(&error);
    assert!(hidden["failures"][0]["agent_detail"].is_null());
    let mut diagnostics = Diagnostics::default();
    let error = error.context(Boundary::new(StorageOperation::Progress, Stage::AgentReady));
    for copy in 0..9 {
        diagnostics.push(
            copy,
            &error,
            Boundary {
                operation: Operation::Prepare,
                stage: Stage::Unknown,
            },
        );
    }
    let report = serde_json::to_value(diagnostics).unwrap();
    assert_eq!(report["version"], 6);
    assert_eq!(report["omitted_failures"], 1);
    assert_eq!(report["failures"].as_array().unwrap().len(), 8);
    for (copy, failure) in report["failures"].as_array().unwrap().iter().enumerate() {
        assert_eq!(failure["copy_index"], copy);
        assert_eq!(failure["agent_detail"], expected);
        assert!(failure["agent_outcome"].is_null());
        assert_eq!(failure.as_object().unwrap().len(), 8);
    }
    assert!(report.to_string().len() < 4096);
    assert!(!report.to_string().contains("private-canary"));
    assert!(serde_json::from_value::<Diagnostics>(report.clone()).is_ok());
    let mut fragments = Diagnostics::default();
    for fragment in 0..9 {
        fragments
            .append_fragment(
                fragment,
                &serde_json::json!({"deposit_diagnostics": report}),
            )
            .unwrap();
    }
    let joined = serde_json::to_value(fragments).unwrap();
    assert_eq!(joined["omitted_failures"], 73);
    assert_eq!(joined["failures"].as_array().unwrap().len(), 8);
    for failure in joined["failures"].as_array().unwrap() {
        assert_eq!(failure["fragment_index"], 0);
        assert_eq!(failure["agent_detail"], expected);
    }
}

#[test]
fn diagnostic_v2_uses_the_same_deadline_stage_code_matrix_as_the_wire() {
    let mut report = serde_json::json!({"version": 2, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 0, "operation": "reserve", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "unobserved", "deadline_scope": "operation"}
    }]});
    for stage in [
        "unobserved",
        "route_connect",
        "control_selection",
        "provider_lookup",
        "provider_cardinality",
        "offer_validity",
        "stream_open",
        "tls_handshake",
        "challenge",
    ] {
        for deadline in ["none", "operation", "exchange"] {
            for code in [
                "CONTENT_INVALID",
                "CONTENT_UNAVAILABLE",
                "CONTENT_BUSY",
                "CONTENT_POLICY",
            ] {
                report["failures"][0]["agent_code"] = code.into();
                report["failures"][0]["agent_detail"] =
                    serde_json::json!({"stage": stage, "deadline_scope": deadline});
                let allowed = match deadline {
                    "none" => stage != "unobserved",
                    "operation" => code == "CONTENT_UNAVAILABLE",
                    "exchange" => {
                        code == "CONTENT_UNAVAILABLE"
                            && matches!(stage, "stream_open" | "tls_handshake" | "challenge")
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    serde_json::from_value::<Diagnostics>(report.clone()).is_ok(),
                    allowed,
                    "{stage} {deadline} {code}"
                );
                let mut current = report.clone();
                current["version"] = 3.into();
                current["failures"][0]["agent_detail"]["tls_failure"] = serde_json::Value::Null;
                assert_eq!(
                    serde_json::from_value::<Diagnostics>(current).is_ok(),
                    allowed,
                    "v3 null {stage} {deadline} {code}"
                );
            }
        }
    }
}

#[test]
fn diagnostic_v3_preserves_historical_dtos_without_accepting_the_new_field() {
    let old = serde_json::json!({"version": 2, "omitted_failures": 0, "failures": [{
        "fragment_index": 0, "copy_index": 1, "operation": "finalize", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "tls_handshake", "deadline_scope": "none"}
    }]});
    let restored: Diagnostics = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), old);
    let mut current = old.clone();
    current["version"] = 3.into();
    assert!(serde_json::from_value::<Diagnostics>(current.clone()).is_err());
    current["failures"][0]["agent_detail"]["tls_failure"] = serde_json::Value::Null;
    let restored: Diagnostics = serde_json::from_value(current.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), current);
    for version in [1, 2] {
        current["version"] = version.into();
        assert!(serde_json::from_value::<Diagnostics>(current.clone()).is_err());
    }
}

#[test]
fn diagnostic_v3_tls_class_requires_the_exact_observed_stage_deadline_and_code() {
    let mut report = serde_json::json!({"version": 3, "omitted_failures": 0, "failures": [{
        "fragment_index": 0, "copy_index": 1, "operation": "finalize", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE", "agent_detail": null
    }]});
    for failure in [
        "offer",
        "configuration",
        "handshake_deadline",
        "authentication",
        "tls_other",
        "io",
    ] {
        for stage in ["tls_handshake", "stream_open", "challenge", "unobserved"] {
            for deadline in ["none", "operation", "exchange"] {
                for code in [
                    "CONTENT_UNAVAILABLE",
                    "CONTENT_INVALID",
                    "CONTENT_BUSY",
                    "CONTENT_POLICY",
                    "unknown",
                ] {
                    report["failures"][0]["agent_code"] = code.into();
                    report["failures"][0]["agent_detail"] = serde_json::json!({
                        "stage": stage, "deadline_scope": deadline, "tls_failure": failure
                    });
                    assert_eq!(
                        serde_json::from_value::<Diagnostics>(report.clone()).is_ok(),
                        stage == "tls_handshake"
                            && deadline == "none"
                            && code == "CONTENT_UNAVAILABLE",
                        "{failure} {stage} {deadline} {code}"
                    );
                }
            }
        }
    }
}

#[test]
fn diagnostic_v3_rejects_unknown_tls_values_fields_and_wrong_failure_boundaries() {
    let baseline = serde_json::json!({"version": 3, "omitted_failures": 0, "failures": [{
        "fragment_index": 0, "copy_index": 1, "operation": "finalize", "stage": "agent_ready",
        "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "tls_handshake", "deadline_scope": "none", "tls_failure": "authentication"}
    }]});
    for invalid in [
        serde_json::json!("unobserved"),
        serde_json::json!("private-error-canary"),
        serde_json::json!(0),
        serde_json::json!(4),
        serde_json::json!(false),
        serde_json::json!({}),
    ] {
        let mut report = baseline.clone();
        report["failures"][0]["agent_detail"]["tls_failure"] = invalid;
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for (field, invalid) in [("stage", "agent_terminal"), ("category", "io")] {
        let mut report = baseline.clone();
        report["failures"][0][field] = invalid.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    let mut report = baseline;
    report["failures"][0]["agent_detail"]["raw"] = "private-error-canary".into();
    assert!(serde_json::from_value::<Diagnostics>(report).is_err());
}

#[test]
fn diagnostic_v4_preserves_exact_v3_and_requires_nullable_outcome() {
    let historical = serde_json::json!({"version": 3, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 1, "operation": "finalize",
        "stage": "wire_receipt", "category": "io", "agent_code": null, "agent_detail": null
    }]});
    let decoded: Diagnostics = serde_json::from_value(historical.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), historical);
    let mut current = historical.clone();
    current["version"] = 4.into();
    assert!(serde_json::from_value::<Diagnostics>(current.clone()).is_err());
    current["failures"][0]["agent_outcome"] = serde_json::Value::Null;
    let decoded: Diagnostics = serde_json::from_value(current.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), current);
    current["version"] = 3.into();
    assert!(serde_json::from_value::<Diagnostics>(current).is_err());
}

#[test]
fn diagnostic_v5_retains_exact_v3_v4_details_and_requires_its_new_field() {
    for version in [3, 4] {
        let mut historical = serde_json::json!({"version": version, "omitted_failures": 0, "failures": [{
            "fragment_index": null, "copy_index": 1, "operation": "reserve",
            "stage": "agent_ready", "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
            "agent_detail": {"stage": "stream_open", "deadline_scope": "none", "tls_failure": null}
        }]});
        if version == 4 {
            historical["failures"][0]["agent_outcome"] = serde_json::Value::Null;
        }
        let decoded: Diagnostics = serde_json::from_value(historical.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), historical);
        let mut expanded = historical.clone();
        expanded["failures"][0]["agent_detail"]["stream_failure"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Diagnostics>(expanded.clone()).is_err());
        expanded["version"] = 5.into();
        expanded["failures"][0]["agent_outcome"] = serde_json::Value::Null;
        let decoded: Diagnostics = serde_json::from_value(expanded.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), expanded);
        expanded["failures"][0]["agent_detail"]
            .as_object_mut()
            .unwrap()
            .remove("stream_failure");
        assert!(serde_json::from_value::<Diagnostics>(expanded).is_err());
    }
}

fn stream_report() -> serde_json::Value {
    serde_json::json!({"version": 5, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 1, "operation": "reserve",
        "stage": "agent_ready", "category": "agent_rejected", "agent_code": "CONTENT_UNAVAILABLE",
        "agent_detail": {"stage": "stream_open", "deadline_scope": "none", "tls_failure": null,
            "stream_failure": "transport_tls"}, "agent_outcome": null
    }]})
}

#[test]
fn diagnostic_v5_stream_failures_require_the_same_closed_wire_matrix() {
    for failure in [
        "policy",
        "route_state",
        "route_material",
        "flow_acquire",
        "transport_certificate",
        "transport_tls",
        "initial_paths",
        "open_tcp_write",
        "subflow_readiness",
        "stream_attachment",
    ] {
        for stage in ["stream_open", "tls_handshake", "challenge", "unobserved"] {
            for deadline in ["none", "operation", "exchange"] {
                for code in [
                    "CONTENT_UNAVAILABLE",
                    "CONTENT_INVALID",
                    "CONTENT_POLICY",
                    "CONTENT_BUSY",
                ] {
                    let mut report = stream_report();
                    report["failures"][0]["agent_code"] = code.into();
                    report["failures"][0]["agent_detail"] = serde_json::json!({
                        "stage": stage, "deadline_scope": deadline, "tls_failure": null,
                        "stream_failure": failure
                    });
                    assert_eq!(
                        serde_json::from_value::<Diagnostics>(report).is_ok(),
                        stage == "stream_open"
                            && deadline == "none"
                            && code == "CONTENT_UNAVAILABLE"
                    );
                }
            }
        }
    }
}

#[test]
fn diagnostic_v5_stream_failures_reject_unknown_values_and_unrelated_scopes() {
    for invalid in [
        serde_json::json!("unobserved"),
        serde_json::json!("private-error-canary"),
        serde_json::json!(0),
        serde_json::json!(6),
        serde_json::json!(true),
        serde_json::json!({}),
    ] {
        let mut report = stream_report();
        report["failures"][0]["agent_detail"]["stream_failure"] = invalid;
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for (field, invalid) in [("stage", "agent_terminal"), ("category", "io")] {
        let mut report = stream_report();
        report["failures"][0][field] = invalid.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for (field, invalid) in [("tls_failure", "io"), ("raw", "private-error-canary")] {
        let mut report = stream_report();
        report["failures"][0]["agent_detail"][field] = invalid.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    let mut joined = Diagnostics::default();
    joined
        .append_fragment(
            2,
            &serde_json::json!({"deposit_diagnostics": stream_report()}),
        )
        .unwrap();
    let report = serde_json::to_value(joined).unwrap();
    assert_eq!(report["version"], 6);
    assert_eq!(report["failures"][0]["fragment_index"], 2);
    assert_eq!(
        report["failures"][0]["agent_detail"]["stream_failure"],
        "transport_tls"
    );
    assert!(report.to_string().len() < 4096);
    assert!(!report.to_string().contains("private-error-canary"));
}

fn outcome_report() -> serde_json::Value {
    serde_json::json!({"version": 4, "omitted_failures": 0, "failures": [{
        "fragment_index": null, "copy_index": 1, "operation": "finalize",
        "stage": "wire_receipt", "category": "io", "agent_code": null, "agent_detail": null,
        "agent_outcome": {"status": "observed", "detail": {
            "phase": "remote_receipt_read", "category": "timeout", "deadline_scope": "remote_wire"
        }}
    }]})
}

#[test]
fn diagnostic_v4_outcome_is_closed_and_requires_a_real_post_ready_boundary() {
    let baseline = outcome_report();
    let decoded: Diagnostics = serde_json::from_value(baseline.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), baseline);
    for (field, invalid) in [
        ("phase", "private-canary"),
        ("phase", "unobserved"),
        ("phase", "local_request_read"), // Not within the remote-wire budget.
        ("category", "private-canary"),
        ("category", "cancelled"), // Cancellation does not invent a deadline.
        ("deadline_scope", "none"), // A timeout must name an observed budget.
        ("deadline_scope", "private-canary"),
        ("raw", "private-canary"),
    ] {
        let mut report = baseline.clone();
        report["failures"][0]["agent_outcome"]["detail"][field] = invalid.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for stage in [
        "agent_ready",
        "authorization",
        "signed_request",
        "accounting",
        "unknown",
    ] {
        let mut report = baseline.clone();
        report["failures"][0]["stage"] = stage.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for status in [
        "observed",
        "missing",
        "pending",
        "expired",
        "query_failed",
        "query_timeout",
    ] {
        let mut report = baseline.clone();
        report["failures"][0]["agent_outcome"]["status"] = status.into();
        assert_eq!(
            serde_json::from_value::<Diagnostics>(report.clone()).is_ok(),
            status == "observed"
        );
        report["failures"][0]["agent_outcome"]["detail"] = serde_json::Value::Null;
        assert_eq!(
            serde_json::from_value::<Diagnostics>(report.clone()).is_ok(),
            status != "observed"
        );
        report["failures"][0]["agent_outcome"]
            .as_object_mut()
            .unwrap()
            .remove("detail");
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for field in ["status", "original_request_id", "provider", "raw_error"] {
        let mut report = baseline.clone();
        report["failures"][0]["agent_outcome"][field] = "private-canary".into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
}

#[test]
fn diagnostic_v6_keeps_original_error_and_bounded_fragment_outcomes_without_identifiers() {
    let outcome: AgentOutcome =
        serde_json::from_value(outcome_report()["failures"][0]["agent_outcome"].clone()).unwrap();
    let error = Error::new(WireError::Io(io::Error::other("/private/id-and-keys")))
        .context(Boundary::new(
            StorageOperation::Finalize,
            Stage::WireReceipt,
        ))
        .context(outcome);
    assert!(error.downcast_ref::<WireError>().is_some());
    assert!(error.downcast_ref::<Boundary>().is_some());
    let report = value(&error);
    let mut expected = outcome_report();
    expected["version"] = 6.into();
    assert_eq!(report, expected);
    let hidden = value(&Error::new(io::Error::other("private")).context(outcome));
    assert!(hidden["failures"][0]["agent_outcome"].is_null());
    let mut fragments = Diagnostics::default();
    for fragment in 0..10 {
        fragments
            .append_fragment(
                fragment,
                &serde_json::json!({"deposit_diagnostics": report}),
            )
            .unwrap();
    }
    let joined = serde_json::to_value(fragments).unwrap();
    assert_eq!(joined["omitted_failures"], 2);
    assert_eq!(joined["failures"].as_array().unwrap().len(), 8);
    for (index, failure) in joined["failures"].as_array().unwrap().iter().enumerate() {
        assert_eq!(failure["fragment_index"], index);
        assert_eq!(failure["category"], "io");
        assert_eq!(failure["agent_outcome"]["detail"]["category"], "timeout");
    }
    assert!(joined.to_string().len() < 4096);
    for canary in [
        "private",
        "id-and-keys",
        "request_id",
        "provider",
        "archive",
        "raw_error",
    ] {
        assert!(!joined.to_string().contains(canary));
    }
}
