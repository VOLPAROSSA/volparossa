use super::*;
use std::{io::Cursor, time::Duration};

use clap::Parser as _;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty,
    StorageFixtureCorrelationRecord, read_request, write_response,
};

fn input(action: &str) -> Value {
    json!({
        "version": 1,
        "action": action,
        "epoch": "ab".repeat(16),
        "fingerprints": if action == "providers" { vec!["cd".repeat(32)] } else { Vec::new() },
    })
}

fn parse(value: &Value) -> Result<StorageFixtureCorrelationRequest> {
    read_input(serde_json::to_vec(value)?.as_slice())
}

fn snapshot() -> StorageFixtureCorrelationResponse {
    StorageFixtureCorrelationResponse {
        version: 1,
        state: State::Observed as i32,
        incomplete: false,
        records: vec![StorageFixtureCorrelationRecord {
            role: Role::Provider as i32,
            fingerprint: Some(vec![0xcd; 32]),
            phase: Phase::StorageChallengeWriteFlush as i32,
            terminal: Terminal::Active as i32,
        }],
    }
}

#[test]
fn fixture_cli_has_no_private_argument_or_implicit_action() {
    let command = ["volparossa", "content", "fixture-correlation"];
    let cli = crate::Cli::try_parse_from(command).unwrap();
    let crate::CliCommand::Content { command: content } = cli.command else {
        panic!("expected content command");
    };
    assert!(matches!(
        *content,
        crate::content::Command::FixtureCorrelation
    ));
    for extra in ["--epoch", "--fingerprint", "--action", "arm", "--input"] {
        assert!(crate::Cli::try_parse_from(command.into_iter().chain([extra])).is_err());
    }
}

#[test]
fn fixture_cli_input_requires_exact_fields_types_and_lowercase_hex() {
    for action in ["arm", "clients", "providers", "disarm"] {
        parse(&input(action)).unwrap();
    }
    let valid = input("providers");
    for field in ["version", "action", "epoch", "fingerprints"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(parse(&missing).is_err());
        for invalid in [Value::Null, json!(true), json!(123), json!({})] {
            let mut value = valid.clone();
            value[field] = invalid;
            assert!(parse(&value).is_err());
        }
    }
    for epoch in [
        "AB".repeat(16),
        "ab".repeat(15),
        "ab".repeat(17),
        "xy".repeat(16),
    ] {
        let mut value = valid.clone();
        value["epoch"] = json!(epoch);
        assert!(parse(&value).is_err());
    }
    for fingerprints in [
        json!([]),
        json!(["CD".repeat(32)]),
        json!(["cd".repeat(31)]),
        json!(["cd".repeat(32), "cd".repeat(32)]),
        json!(vec!["cd".repeat(32); 9]),
    ] {
        let mut value = valid.clone();
        value["fingerprints"] = fingerprints;
        assert!(parse(&value).is_err());
    }
    let mut value = input("arm");
    value["fingerprints"] = json!(["cd".repeat(32)]);
    assert!(parse(&value).is_err());
}

#[test]
fn fixture_cli_duplicate_unknown_and_trailing_input_never_reflect_private_text() {
    let valid = serde_json::to_string(&input("arm")).unwrap();
    let mut invalid = vec![
        String::new(),
        format!("{valid}{valid}"),
        valid.replacen('{', "{\"PRIVATE_CANARY\":0,", 1),
        valid.replace("\"arm\"", "\"PRIVATE_CANARY\""),
    ];
    for (field, value) in [
        ("version", "1"),
        ("action", "\"arm\""),
        ("epoch", "\"PRIVATE_CANARY\""),
        ("fingerprints", "[]"),
    ] {
        invalid.push(valid.replacen('{', &format!("{{\"{field}\":{value},"), 1));
    }
    for value in invalid {
        let error = read_input(value.as_bytes()).unwrap_err().to_string();
        assert_eq!(error, "invalid private fixture correlation input");
        assert!(!error.contains("PRIVATE_CANARY"));
    }
}

#[test]
fn fixture_cli_input_read_stops_at_fixed_bound() {
    let valid = serde_json::to_string(&input("clients")).unwrap();
    let mut exact = valid.into_bytes();
    exact.resize(MAX_REQUEST_BYTES, b' ');
    read_input(exact.as_slice()).unwrap();
    exact.resize(MAX_REQUEST_BYTES * 3, b' ');
    let mut reader = Cursor::new(exact);
    assert!(read_input(&mut reader).is_err());
    assert_eq!(reader.position(), (MAX_REQUEST_BYTES + 1) as u64);
}

#[test]
fn fixture_cli_projection_is_private_exact_and_not_acceptance() {
    let request = parse(&input("providers")).unwrap();
    let value = project(&snapshot(), &request).unwrap();
    assert_eq!(
        value,
        json!({
            "version": 1,
            "kind": "storage-fixture-correlation",
            "state": "observed",
            "incomplete": false,
            "records": [{
                "role": "provider", "fingerprint": "cd".repeat(32),
                "phase": "storage_challenge_write_flush", "terminal": "active",
            }],
            "diagnostic_only": true,
            "acceptance_evidence": false,
        })
    );
    let encoded = render(&value).unwrap();
    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(
        !String::from_utf8(encoded)
            .unwrap()
            .contains(&"ab".repeat(16))
    );
    let unavailable = project(&StorageFixtureCorrelationResponse::unavailable(), &request).unwrap();
    assert_eq!(unavailable["state"], "unavailable");
    assert_eq!(unavailable["incomplete"], true);
    assert_eq!(unavailable["records"], json!([]));
}

#[test]
fn fixture_cli_null_client_and_maximum_reply_remain_bounded() {
    let request = parse(&input("clients")).unwrap();
    let mut response = snapshot();
    response.records[0] = StorageFixtureCorrelationRecord {
        role: Role::Client as i32,
        fingerprint: None,
        phase: Phase::FlowAcquire as i32,
        terminal: Terminal::OperationError as i32,
    };
    response.incomplete = true;
    let value = project(&response, &request).unwrap();
    assert!(value["records"][0]["fingerprint"].is_null());
    response.records[0].fingerprint = Some(vec![0xcd; 32]);
    response.records = vec![response.records[0].clone(); 64];
    assert!(
        render(&project(&response, &request).unwrap())
            .unwrap()
            .len()
            < MAX_REPLY_BYTES
    );
    response.records.push(response.records[0].clone());
    assert!(project(&response, &request).is_err());
    assert!(render(&json!("x".repeat(MAX_REPLY_BYTES))).is_err());
}

#[test]
fn fixture_cli_all_finite_enum_spellings_are_stable() {
    let phases = [
        "flow_acquire",
        "tls_handshake",
        "registry_snapshot",
        "selector_read",
        "storage_grant_read_verify",
        "storage_challenge_write_flush",
        "storage_request_read_verify",
        "storage_operation",
        "client_challenge",
        "client_exchange",
        "other_protocol",
        "closing",
    ];
    for (index, name) in phases.iter().enumerate() {
        let value = Phase::try_from(i32::try_from(index + 1).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), *name);
    }
    let terminals = [
        "active",
        "complete",
        "tls_timeout",
        "tls_error",
        "operation_error",
        "cancelled",
    ];
    for (index, name) in terminals.iter().enumerate() {
        let value = Terminal::try_from(i32::try_from(index + 1).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), *name);
    }
}

#[tokio::test]
async fn fixture_cli_socket_roundtrip_rejects_cross_request_and_cross_action_data() {
    for mode in 0..8 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let Some(Operation::StorageFixtureCorrelation(inner)) = request.operation else {
                panic!("expected fixture correlation operation");
            };
            assert_eq!(inner, parse(&input("providers")).unwrap());
            if mode == 7 {
                return;
            }
            let mut response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "STORAGE_FIXTURE_CORRELATION".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::StorageFixtureCorrelation(snapshot())),
            };
            match mode {
                1 => response.request_id[0] ^= 1,
                2 | 6 => {
                    response.payload = Some(Payload::Ack(Empty {}));
                    response.diagnostic_code = "PRIVATE_CANARY".into();
                    if mode == 6 {
                        response.result = ControlResult::InvalidRequest as i32;
                    }
                }
                3..=5 => {
                    let mut altered = snapshot();
                    if mode == 3 {
                        altered.records[0].fingerprint = Some(vec![9; 32]);
                    } else if mode == 4 {
                        altered.records[0].role = Role::Client as i32;
                        altered.records[0].phase = Phase::ClientChallenge as i32;
                    } else {
                        altered.state = State::Armed as i32;
                        altered.records.clear();
                    }
                    response.payload = Some(Payload::StorageFixtureCorrelation(altered));
                }
                _ => {}
            }
            write_response(&mut stream, &response).await.unwrap();
        });
        let request = parse(&input("providers")).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), query(&path, &request))
            .await
            .unwrap();
        assert_eq!(result.is_ok(), mode == 0);
        if let Err(error) = result {
            assert!(!format!("{error:#}").contains("PRIVATE_CANARY"));
        }
        task.await.unwrap();
    }
}
