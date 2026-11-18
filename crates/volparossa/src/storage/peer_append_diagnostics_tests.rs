//! Optional local timing is not proof of arrival, custody or the cause of a remote failure.

use super::*;

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

fn append_report() -> serde_json::Value {
    let mut report = outcome_report();
    report["version"] = 7.into();
    report["failures"][0]["operation"] = "append".into();
    report["failures"][0]["agent_outcome"]["append_timing"] = serde_json::json!({
        "before_payload": "90_to_120s",
        "in_payload_write_flush": "under_1s",
        "in_receipt_read": "5_to_15s"
    });
    report
}

#[test]
fn append_diagnostics_v7_keeps_exact_historical_outcome_shapes() {
    for version in 4..=6 {
        let mut original = outcome_report();
        original["version"] = version.into();
        let before = original.to_string();
        let decoded: Diagnostics = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap().to_string(), before);
        for timing in [
            serde_json::Value::Null,
            append_report()["failures"][0]["agent_outcome"]["append_timing"].clone(),
        ] {
            let mut expanded = original.clone();
            expanded["failures"][0]["agent_outcome"]["append_timing"] = timing;
            assert!(serde_json::from_value::<Diagnostics>(expanded).is_err());
        }
    }
    let report = append_report();
    let decoded: Diagnostics = serde_json::from_value(report.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), report);
    let mut missing = report.clone();
    missing["failures"][0]["agent_outcome"]
        .as_object_mut()
        .unwrap()
        .remove("append_timing");
    assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
    for status in [
        "observed",
        "missing",
        "pending",
        "expired",
        "query_failed",
        "query_timeout",
    ] {
        let mut nullable = report.clone();
        nullable["failures"][0]["agent_outcome"]["status"] = status.into();
        if status != "observed" {
            nullable["failures"][0]["agent_outcome"]["detail"] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Diagnostics>(nullable.clone()).is_err());
        }
        nullable["failures"][0]["agent_outcome"]["append_timing"] = serde_json::Value::Null;
        let decoded: Diagnostics = serde_json::from_value(nullable.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), nullable);
    }
}

#[test]
fn append_diagnostics_v7_closes_bucket_nullable_and_operation_phase_domains() {
    for field in [
        "before_payload",
        "in_payload_write_flush",
        "in_receipt_read",
    ] {
        for bucket in BUCKETS {
            let mut report = append_report();
            report["failures"][0]["agent_outcome"]["append_timing"][field] = bucket.into();
            let decoded: Diagnostics = serde_json::from_value(report.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), report);
        }
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!("unobserved"),
            serde_json::json!("/private/payload-canary"),
            serde_json::json!(1),
            serde_json::json!(true),
            serde_json::json!({}),
        ] {
            let mut report = append_report();
            report["failures"][0]["agent_outcome"]["append_timing"][field] = invalid;
            assert!(serde_json::from_value::<Diagnostics>(report).is_err());
        }
        let mut missing = append_report();
        missing["failures"][0]["agent_outcome"]["append_timing"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<Diagnostics>(missing).is_err());
    }
    for (phase, receipt, expected) in [
        ("remote_payload_write", serde_json::Value::Null, true),
        ("remote_payload_write", serde_json::json!("under_1s"), false),
        ("remote_receipt_read", serde_json::Value::Null, false),
        ("remote_receipt_read", serde_json::json!("under_1s"), true),
        (
            "remote_receipt_verify",
            serde_json::json!("under_1s"),
            false,
        ),
        ("remote_request_write", serde_json::Value::Null, false),
    ] {
        let mut report = append_report();
        report["failures"][0]["agent_outcome"]["detail"]["phase"] = phase.into();
        report["failures"][0]["agent_outcome"]["append_timing"]["in_receipt_read"] = receipt;
        assert_eq!(
            serde_json::from_value::<Diagnostics>(report).is_ok(),
            expected
        );
    }
    for operation in [
        "prepare",
        "reserve",
        "progress",
        "finalize",
        "renew",
        "read_range",
        "delete",
    ] {
        let mut report = append_report();
        report["failures"][0]["operation"] = operation.into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
    for field in ["raw", "elapsed_ns", "provider", "request_id", "path"] {
        let mut report = append_report();
        report["failures"][0]["agent_outcome"]["append_timing"][field] = "/private/canary".into();
        assert!(serde_json::from_value::<Diagnostics>(report).is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn append_diagnostics_scope_restores_after_success_error_cancel_and_nested_scopes() {
    use std::time::Duration;

    assert!(!append_timing_enabled());
    assert_eq!(Diagnostics::default().version, 6);
    with_append_timing(true, async {
        assert!(append_timing_enabled());
        assert_eq!(Diagnostics::default().version, 7);
        with_append_timing(false, async {
            assert!(!append_timing_enabled());
            assert_eq!(Diagnostics::default().version, 6);
        })
        .await;
        assert!(append_timing_enabled());
        // Detached work is not a supported transfer path and never inherits opt-in.
        assert!(
            !tokio::spawn(async { append_timing_enabled() })
                .await
                .unwrap()
        );
    })
    .await;
    assert!(!append_timing_enabled());
    let failure = with_append_timing(true, async { Err::<(), _>("original-error") }).await;
    assert_eq!(failure, Err("original-error"));
    assert!(!append_timing_enabled());
    let cancelled = tokio::time::timeout(
        Duration::from_millis(1),
        with_append_timing(true, async {
            assert!(append_timing_enabled());
            std::future::pending::<()>().await;
        }),
    )
    .await;
    assert!(cancelled.is_err());
    assert!(!append_timing_enabled());
    // A subsequent ordinary invocation, including resume, does not inherit v7.
    assert_eq!(Diagnostics::default().version, 6);
}

#[tokio::test]
async fn append_diagnostics_two_concurrent_commands_keep_independent_versions() {
    let barrier = tokio::sync::Barrier::new(2);
    let command = |enabled| {
        let barrier = &barrier;
        async move {
            with_append_timing(enabled, async {
                barrier.wait().await;
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                    assert_eq!(append_timing_enabled(), enabled);
                    assert_eq!(Diagnostics::default().version, if enabled { 7 } else { 6 });
                }
                serde_json::to_value(Diagnostics::default()).unwrap()
            })
            .await
        }
    };
    let (v6, v7) = tokio::join!(command(false), command(true));
    assert_eq!(v6["version"], 6);
    assert_eq!(v7["version"], 7);
    assert!(!append_timing_enabled());
}

#[tokio::test]
async fn append_diagnostics_fragment_join_rejects_opt_in_profile_mixing_without_mutation() {
    for enabled in [false, true] {
        with_append_timing(enabled, async {
            let mut diagnostics = Diagnostics::default();
            let mut legacy = outcome_report();
            legacy["version"] = 6.into();
            let report = if enabled { legacy } else { append_report() };
            let original = serde_json::to_value(&diagnostics).unwrap();
            assert!(
                diagnostics
                    .append_fragment(0, &serde_json::json!({"deposit_diagnostics": report}))
                    .is_err()
            );
            assert_eq!(serde_json::to_value(diagnostics).unwrap(), original);
        })
        .await;
    }
}

#[test]
fn append_diagnostics_cli_is_explicit_per_replica_or_fragment_command() {
    use clap::Parser as _;

    for group in ["replicas", "fragments"] {
        for enabled in [false, true] {
            for before in [false, true] {
                let mut args = vec!["volparossa", "storage", group];
                if enabled && before {
                    args.push("--append-diagnostics-v7");
                }
                args.extend(["status", "--state", "/private/not-opened-by-parser"]);
                if enabled && !before {
                    args.push("--append-diagnostics-v7");
                }
                let cli = crate::Cli::try_parse_from(args).unwrap();
                let crate::CliCommand::Storage { command } = cli.command else {
                    panic!();
                };
                let (crate::storage::Command::Replicas {
                    append_diagnostics_v7: selected,
                    ..
                }
                | crate::storage::Command::Fragments {
                    append_diagnostics_v7: selected,
                    ..
                }) = command
                else {
                    panic!();
                };
                assert_eq!(selected, enabled);
            }
        }
    }
    for group in ["local", "peer"] {
        let error =
            crate::Cli::try_parse_from(["volparossa", "storage", group, "--append-diagnostics-v7"])
                .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
