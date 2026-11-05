use super::*;
use clap::Parser as _;

fn sample() -> serde_json::Value {
    serde_json::json!({"version":10,"omitted_failures":0,"failures":[{
        "fragment_index":3,"copy_index":1,"operation":"append","stage":"agent_ready",
        "category":"agent_rejected","agent_code":"CONTENT_UNAVAILABLE","agent_outcome":null,
        "agent_detail":{"stage":"challenge","deadline_scope":"operation","tls_failure":null,
            "stream_failure":null,"flow_acquire":null,"challenge":{"phase":"challenge_read_verify",
                "before_challenge":"1_to_5s","in_challenge":"90_to_120s",
                "read":{"step":"body_read","returned_outcome":null}}}}]})
}

#[test]
fn challenge_read_v10_roundtrips_finite_matrix_and_retains_fragment_copy_operation() {
    for step in ["length_read", "body_read", "verification"] {
        for outcome in [
            None,
            Some("io_eof"),
            Some("io_other"),
            Some("invalid"),
            Some("verification_rejected"),
            Some("wire_timeout"),
        ] {
            let mut value = sample();
            value["failures"][0]["agent_detail"]["challenge"]["read"] =
                serde_json::json!({"step":step,"returned_outcome":outcome});
            let expected = matches!(
                (step, outcome),
                (
                    "length_read" | "body_read",
                    None | Some("io_eof" | "io_other" | "wire_timeout"),
                ) | ("length_read" | "verification", Some("invalid"))
                    | ("verification", None | Some("verification_rejected"))
            );
            let decoded = serde_json::from_value::<Diagnostics>(value.clone());
            assert_eq!(decoded.is_ok(), expected);
            if let Ok(decoded) = decoded {
                assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            }
        }
    }
}

#[test]
fn challenge_read_v10_rejects_legacy_reinterpretation_unknown_fields_and_wrong_phase() {
    for version in 1..=9 {
        let mut value = sample();
        value["version"] = version.into();
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    for read in [
        serde_json::json!({"step":"private-canary","returned_outcome":null}),
        serde_json::json!({"step":"body_read"}),
        serde_json::json!({"step":"body_read","returned_outcome":null,"raw":"private-canary"}),
    ] {
        let mut value = sample();
        value["failures"][0]["agent_detail"]["challenge"]["read"] = read;
        assert!(serde_json::from_value::<Diagnostics>(value).is_err());
    }
    let mut value = sample();
    value["failures"][0]["agent_detail"]["challenge"]["phase"] = "grant_write_flush".into();
    assert!(serde_json::from_value::<Diagnostics>(value).is_err());
}

#[tokio::test]
async fn challenge_read_v10_is_explicit_scoped_and_mixed_cli_flags_reject_before_io() {
    assert!(!challenge_read_enabled());
    super::super::with_challenge_read_diagnostics(
        true,
        super::super::with_all_diagnostics(false, false, true, async {
            assert!(challenge_read_enabled());
            assert!(flow_acquire_enabled() && tls_close_enabled() && append_timing_enabled());
            assert_eq!(Diagnostics::default().version, 10);
        }),
    )
    .await;
    assert!(!challenge_read_enabled());
    assert_eq!(Diagnostics::default().version, 6);
    for group in ["replicas", "fragments"] {
        let cli = crate::Cli::try_parse_from([
            "volparossa",
            "storage",
            group,
            "--challenge-read-diagnostics-v10",
            "status",
            "--state",
            "/not-opened",
        ])
        .unwrap();
        let crate::CliCommand::Storage { command } = cli.command else {
            panic!()
        };
        assert!(command.validate_diagnostics().is_ok());
        for old in [
            "--append-diagnostics-v7",
            "--flow-acquire-diagnostics-v8",
            "--tls-close-diagnostics-v9",
        ] {
            let parsed = crate::Cli::try_parse_from([
                "volparossa",
                "storage",
                group,
                old,
                "status",
                "--state",
                "/not-opened",
                "--challenge-read-diagnostics-v10",
            ]);
            if let Ok(cli) = parsed {
                let crate::CliCommand::Storage { command } = cli.command else {
                    panic!()
                };
                assert!(command.validate_diagnostics().is_err());
            }
        }
    }
}
