//! CLI scope, private output and real framed-IPC checks; not an overlay datapath proof.

use std::{fs, os::unix::fs::MetadataExt as _, path::Path};

use clap::Parser as _;
use rand_core::{OsRng, RngCore as _};
use tokio::net::UnixListener;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, read_request, write_response,
};

use super::*;

fn random_bytes() -> [u8; 32] {
    let mut value = [0; 32];
    OsRng.fill_bytes(&mut value);
    value
}

fn args(output: &Path) -> Grant {
    Grant {
        app_uid: 1000,
        hostname: "example.com".to_owned(),
        port: 443,
        partition: random_bytes(),
        lifetime_seconds: 60,
        output: output.to_path_buf(),
    }
}

fn reply(args: &Grant, now: u64) -> BrowserGatewayGranted {
    BrowserGatewayGranted {
        app_socket: "/run/volparossa/apps/browser.sock".to_owned(),
        capability: random_bytes().to_vec(),
        expires_at_ms: now + u64::from(args.lifetime_seconds) * 1000,
        hostname: args.hostname.clone(),
        port: u32::from(args.port),
        partition: args.partition.to_vec(),
    }
}

#[test]
fn browser_grant_cli_requires_explicit_canonical_scope_and_private_output() {
    let partition = hex::encode(random_bytes());
    let command = [
        "volparossa",
        "browser",
        "grant",
        "--app-uid",
        "1000",
        "--hostname",
        "example.com",
        "--port",
        "443",
        "--partition",
        &partition,
        "--lifetime-seconds",
        "300",
        "--output",
        "/tmp/new-browser-grant.json",
    ];
    assert!(crate::Cli::try_parse_from(command).is_ok());
    for (index, value) in [
        (4, "4294967295"),
        (6, "Example.com"),
        (6, "example.com."),
        (6, "127.1"),
        (6, "https://example.com"),
        (6, "example.com/path"),
        (6, "*.example.com"),
        (8, "0"),
        (8, "65536"),
        (10, "42"),
        (12, "0"),
        (12, "301"),
    ] {
        let mut invalid = command;
        invalid[index] = value;
        assert!(crate::Cli::try_parse_from(invalid).is_err());
    }
    assert!(crate::Cli::try_parse_from(&command[..13]).is_err());
}

#[tokio::test]
async fn browser_grant_framed_reply_is_written_privately_without_secret_in_report() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("admin.sock");
    let output = directory.path().join("grant.json");
    let args = args(&output);
    let granted = reply(&args, crate::doctor::unix_millis().unwrap());
    let expected_capability = hex::encode(&granted.capability);
    let expected_partition = args.partition;
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::BrowserGatewayGrant(scope)) = request.operation else {
            panic!("explicit typed gateway grant required")
        };
        assert_eq!(scope.app_uid, 1000);
        assert_eq!(scope.hostname, "example.com");
        assert_eq!(scope.port, 443);
        assert_eq!(scope.partition, expected_partition);
        assert_eq!(scope.lifetime_seconds, 60);
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "BROWSER_GATEWAY_GRANTED".into(),
                payload: Some(Payload::BrowserGatewayGranted(granted)),
            },
        )
        .await
        .unwrap();
    });
    let report = grant(&args, &socket).await.unwrap();
    server.await.unwrap();
    let file: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(file["version"], 1);
    assert_eq!(file["capability"], expected_capability);
    assert_eq!(file["partition"], hex::encode(expected_partition));
    assert_eq!(file["app_uid"], 1000);
    assert_eq!(file["hostname"], "example.com");
    assert_eq!(file["port"], 443);
    assert_eq!(file["overlay_only"], true);
    let metadata = fs::symlink_metadata(&output).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(report["grant_written"], true);
    for private in [
        &expected_capability,
        &hex::encode(expected_partition),
        &args.hostname,
    ] {
        assert!(!report.to_string().contains(private));
    }
    let original = fs::read(&output).unwrap();
    assert!(grant(&args, &socket).await.is_err());
    assert_eq!(fs::read(&output).unwrap(), original);
}

#[test]
fn browser_grant_reply_cannot_widen_scope_or_replace_new_output() {
    let directory = tempfile::tempdir().unwrap();
    let args = args(&directory.path().join("grant.json"));
    let now = crate::doctor::unix_millis().unwrap();
    let original = reply(&args, now);
    validate_reply(&args, &original, now).unwrap();
    for changed in [
        BrowserGatewayGranted {
            hostname: "other.example".into(),
            ..original.clone()
        },
        BrowserGatewayGranted {
            port: 8443,
            ..original.clone()
        },
        BrowserGatewayGranted {
            partition: random_bytes().to_vec(),
            ..original.clone()
        },
        BrowserGatewayGranted {
            capability: vec![],
            ..original.clone()
        },
        BrowserGatewayGranted {
            expires_at_ms: now,
            ..original.clone()
        },
        BrowserGatewayGranted {
            expires_at_ms: now + 60_001,
            ..original.clone()
        },
        BrowserGatewayGranted {
            app_socket: "relative.sock".into(),
            ..original.clone()
        },
        BrowserGatewayGranted {
            app_socket: "/run/../other.sock".into(),
            ..original
        },
    ] {
        assert!(validate_reply(&args, &changed, now).is_err());
    }
    let target = directory.path().join("existing");
    fs::write(&target, b"keep existing owner data").unwrap();
    std::os::unix::fs::symlink(&target, &args.output).unwrap();
    assert!(save_new(&args.output, b"never replace").is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep existing owner data");
    assert!(save_new(Path::new("relative.json"), b"never create").is_err());
}
