//! Closed challenge observations; these tests do not establish a remote stall cause.

use super::*;

const PHASES: [&str; 3] = [
    "selector_write_flush",
    "grant_write_flush",
    "challenge_read_verify",
];
const BUCKETS: [&str; 8] = [
    "under_1s",
    "1_to_5s",
    "5_to_15s",
    "15_to_30s",
    "30_to_60s",
    "60_to_90s",
    "90_to_120s",
    "at_least_120s",
];

fn challenge_report() -> serde_json::Value {
    let mut report = stream_report();
    report["version"] = 6.into();
    report["failures"][0]["agent_detail"] = serde_json::json!({
        "stage": "challenge", "deadline_scope": "operation",
        "tls_failure": null, "stream_failure": null,
        "challenge": {"phase": "challenge_read_verify",
            "before_challenge": "90_to_120s", "in_challenge": "under_1s"}
    });
    report
}

#[test]
fn diagnostic_v6_preserves_exact_historical_versions_without_new_fields() {
    for version in 1..=5 {
        let mut historical = stream_report();
        historical["version"] = version.into();
        let failure = historical["failures"][0].as_object_mut().unwrap();
        failure.insert(
            "agent_detail".into(),
            serde_json::json!({"stage":"challenge","deadline_scope":"operation",
                "tls_failure":null,"stream_failure":null}),
        );
        if version == 1 {
            failure.remove("agent_detail");
        } else {
            let detail = failure
                .get_mut("agent_detail")
                .unwrap()
                .as_object_mut()
                .unwrap();
            if version < 3 {
                detail.remove("tls_failure");
            }
            if version < 5 {
                detail.remove("stream_failure");
            }
        }
        if version < 4 {
            failure.remove("agent_outcome");
        }
        let decoded: Diagnostics = serde_json::from_value(historical.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), historical);
        let mut expanded = historical;
        if version == 1 {
            expanded["failures"][0]["agent_detail"] = serde_json::Value::Null;
        } else {
            expanded["failures"][0]["agent_detail"]["challenge"] = serde_json::Value::Null;
        }
        assert!(serde_json::from_value::<Diagnostics>(expanded).is_err());
    }
    let mut current = stream_report();
    current["version"] = 6.into();
    assert!(serde_json::from_value::<Diagnostics>(current.clone()).is_err());
    current["failures"][0]["agent_detail"]["challenge"] = serde_json::Value::Null;
    let decoded: Diagnostics = serde_json::from_value(current.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), current);
}

#[test]
fn diagnostic_v6_challenge_accepts_only_the_closed_phase_bucket_matrix() {
    for phase in PHASES {
        for before in BUCKETS {
            for during in BUCKETS {
                for deadline in ["none", "operation", "exchange"] {
                    let mut report = challenge_report();
                    report["failures"][0]["agent_detail"]["deadline_scope"] = deadline.into();
                    report["failures"][0]["agent_detail"]["challenge"] = serde_json::json!({
                        "phase":phase,"before_challenge":before,"in_challenge":during
                    });
                    let decoded: Diagnostics = serde_json::from_value(report.clone()).unwrap();
                    assert_eq!(serde_json::to_value(decoded).unwrap(), report);
                }
            }
        }
    }
}

#[test]
fn diagnostic_v6_challenge_requires_exact_agent_ready_unavailable_scope() {
    for stage in ["agent_ready", "agent_terminal", "challenge", "wire_receipt"] {
        for category in ["agent_rejected", "io", "unknown"] {
            for code in [
                "CONTENT_UNAVAILABLE",
                "CONTENT_INVALID",
                "CONTENT_BUSY",
                "CONTENT_POLICY",
                "unknown",
            ] {
                let mut report = challenge_report();
                report["failures"][0]["agent_detail"]["deadline_scope"] = "none".into();
                report["failures"][0]["stage"] = stage.into();
                report["failures"][0]["category"] = category.into();
                report["failures"][0]["agent_code"] = code.into();
                assert_eq!(
                    serde_json::from_value::<Diagnostics>(report).is_ok(),
                    stage == "agent_ready"
                        && category == "agent_rejected"
                        && code == "CONTENT_UNAVAILABLE"
                );
            }
        }
    }
    for stage in [
        "unobserved",
        "route_connect",
        "control_selection",
        "provider_lookup",
        "provider_cardinality",
        "offer_validity",
        "stream_open",
        "tls_handshake",
    ] {
        let mut report = challenge_report();
        report["failures"][0]["agent_detail"]["stage"] = stage.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for (field, value) in [("tls_failure", "io"), ("stream_failure", "transport_tls")] {
        let mut report = challenge_report();
        report["failures"][0]["agent_detail"][field] = value.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
}

#[test]
fn diagnostic_v6_challenge_rejects_absent_unknown_and_private_values() {
    for field in ["phase", "before_challenge", "in_challenge"] {
        let mut missing = challenge_report();
        missing["failures"][0]["agent_detail"]["challenge"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
        for invalid in [
            serde_json::json!("unobserved"),
            serde_json::json!("PRIVATE-secret-path"),
            serde_json::json!(0),
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!({}),
        ] {
            let mut report = challenge_report();
            report["failures"][0]["agent_detail"]["challenge"][field] = invalid;
            assert!(serde_json::from_value::<Diagnostics>(report).is_err());
        }
    }
    for field in ["elapsed_ms", "pid", "provider", "request_id", "raw_error"] {
        let mut report = challenge_report();
        report["failures"][0]["agent_detail"]["challenge"][field] = "PRIVATE-secret-path".into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    let report = challenge_report();
    let mut aggregate = Diagnostics::default();
    for fragment in 0..10 {
        aggregate
            .append_fragment(fragment, &serde_json::json!({"deposit_diagnostics":report}))
            .unwrap();
    }
    let joined = serde_json::to_value(aggregate).unwrap();
    assert_eq!(joined["version"], 6);
    assert_eq!(joined["omitted_failures"], 2);
    assert_eq!(joined["failures"].as_array().unwrap().len(), 8);
    assert!(joined.to_string().len() < 4096);
    for (fragment, failure) in joined["failures"].as_array().unwrap().iter().enumerate() {
        assert_eq!(failure["fragment_index"], fragment);
        assert_eq!(
            failure["agent_detail"],
            report["failures"][0]["agent_detail"]
        );
    }
    for canary in [
        "PRIVATE",
        "secret-path",
        "elapsed_ms",
        "pid",
        "request_id",
        "provider",
    ] {
        assert!(!joined.to_string().contains(canary));
    }
}

#[tokio::test]
async fn diagnostic_v6_real_correlated_response_preserves_challenge_and_fragment_bounds() {
    for (phase_index, phase) in PHASES.iter().enumerate() {
        for (bucket_index, bucket) in BUCKETS.iter().enumerate() {
            let deadline =
                PrivateStorageDeadlineScope::try_from(i32::try_from(phase_index).unwrap()).unwrap();
            correlated_projection_case(
                PrivateStorageRemoteDetail {
                    flow_acquire: None,
                    stage: PrivateStorageRemoteStage::Challenge as i32,
                    deadline_scope: deadline as i32,
                    tls_failure: None,
                    stream_failure: None,
                    challenge: Some(PrivateStorageChallengeDetail {
                        phase: i32::try_from(phase_index + 1).unwrap(),
                        before_challenge: i32::try_from(bucket_index + 1).unwrap(),
                        in_challenge: i32::try_from(8 - bucket_index).unwrap(),
                    }),
                },
                serde_json::json!({"stage":"challenge","deadline_scope":deadline,
                    "tls_failure":null,"stream_failure":null,
                    "challenge":{"phase":phase,"before_challenge":bucket,
                        "in_challenge":BUCKETS[7-bucket_index]}}),
            )
            .await;
        }
    }
}
