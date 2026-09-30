//! Local protocol/admission tests, not claims of peer inference or browser execution.

use super::*;
use clap::Parser;
use tokio::io::AsyncWriteExt as _;

const FIRST: &str = "01010101010101010101010101010101";
const SECOND: &str = "02020202020202020202020202020202";
const THIRD: &str = "03030303030303030303030303030303";

fn request(id: &str, operation: Value) -> Value {
    let mut request = json!({"version":1,"id":id});
    request["operation"] = operation;
    request
}

fn submit() -> Value {
    json!({"type":"submit","question":"What is described?","context":"Public source.",
        "license":"CC0-1.0","public_content":true,"rights_confirmed":true})
}

fn config(root: &Path) -> Config {
    #[derive(Parser)]
    struct Arguments {
        #[command(flatten)]
        options: Options,
    }
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .as_bytes(),
    );
    let other = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[2; 32])
            .verifying_key()
            .as_bytes(),
    );
    let options = Arguments::try_parse_from([
        "public-serve",
        "--runtime-root",
        "/unused/runtime",
        "--model-root",
        "/unused/model",
        "--identity",
        "/unused/identity",
        "--passphrase-file",
        "/unused/passphrase",
        "--publisher-key",
        &key,
        "--provider-key",
        &key,
        "--provider-key",
        &other,
        "--state-parent",
        root.to_str().unwrap(),
        "--socket",
        "/unused/public.sock",
    ])
    .unwrap()
    .options;
    Config {
        backend: options.backend,
        state_parent: root.to_owned(),
        agent_socket: root.join("agent.sock"),
        max_task_seconds: options.max_task_seconds,
    }
}

#[test]
fn public_serve_schema_requires_separate_public_consent_and_rights_without_paths() {
    let valid = request(FIRST, submit());
    serde_json::from_value::<wire::Request>(valid.clone())
        .unwrap()
        .validate()
        .unwrap();
    for field in ["public_content", "rights_confirmed"] {
        let mut invalid = valid.clone();
        invalid["operation"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<wire::Request>(invalid).is_err());
        let mut invalid = valid.clone();
        invalid["operation"][field] = false.into();
        assert!(
            serde_json::from_value::<wire::Request>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for (field, value) in [
        ("runtime_root", json!("/untrusted/runtime")),
        ("provider_key", json!("untrusted")),
        ("command", json!("untrusted")),
        ("model_profile", json!("untrusted")),
        ("private_content", json!(true)),
        ("max_seconds", json!(999_999)),
    ] {
        let mut invalid = valid.clone();
        invalid["operation"][field] = value;
        assert!(serde_json::from_value::<wire::Request>(invalid).is_err());
    }
    for (field, value) in [
        ("question", json!("é".repeat(257))),
        ("context", json!("x".repeat(4097))),
        ("question", json!("Q\0")),
        ("context", json!(" ")),
        ("license", json!("unknown")),
    ] {
        let mut invalid = valid.clone();
        invalid["operation"][field] = value;
        assert!(
            serde_json::from_value::<wire::Request>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for invalid in [
        json!({"version":2,"id":FIRST,"operation":{"type":"capabilities"}}),
        request("not-a-task-id", json!({"type":"capabilities"})),
        request(FIRST, json!({"type":"cancel","task_id":".."})),
    ] {
        assert!(
            serde_json::from_value::<wire::Request>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let duplicate = format!(
        r#"{{"version":1,"id":"{FIRST}","id":"{SECOND}","operation":{{"type":"capabilities"}}}}"#
    );
    assert!(serde_json::from_str::<wire::Request>(&duplicate).is_err());
}

#[tokio::test]
async fn public_serve_framing_rejects_oversize_truncation_and_hides_input_details() {
    for bytes in [
        vec![0; 4],
        u32::try_from(wire::MAX_REQUEST_BYTES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
        vec![0, 0],
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&bytes).await.unwrap();
        drop(writer);
        assert!(wire::read::<wire::Request>(&mut reader).await.is_err());
    }
    let (mut writer, mut reader) = tokio::io::duplex(256);
    let bytes = br#"{"untrusted-canary":true}"#;
    writer
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    writer.write_all(bytes).await.unwrap();
    assert_eq!(
        wire::read::<wire::Request>(&mut reader)
            .await
            .err()
            .unwrap()
            .to_string(),
        "public_ipc_invalid_request"
    );
}

#[tokio::test]
async fn public_serve_handshake_and_global_busy_use_real_local_frames_without_inference() {
    let root = tempfile::tempdir().unwrap();
    let configuration = Arc::new(config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let permit = gate.clone().acquire_owned().await.unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection(server, configuration, gate.clone(), shutdown));
    wire::write(&mut client, &request(FIRST, submit()))
        .await
        .unwrap();
    let response: Value = wire::read(&mut client).await.unwrap().unwrap();
    assert_eq!(response["code"], "handshake_required");
    wire::write(
        &mut client,
        &request(SECOND, json!({"type":"capabilities"})),
    )
    .await
    .unwrap();
    let response: Value = wire::read(&mut client).await.unwrap().unwrap();
    assert_eq!(response["capabilities"]["visibility"], "public_cooperative");
    assert_eq!(response["capabilities"]["network_access"], true);
    assert_eq!(response["capabilities"]["private_data_supported"], false);
    assert_eq!(response["capabilities"]["model_execution_proven"], false);
    wire::write(&mut client, &request(THIRD, submit()))
        .await
        .unwrap();
    let response: Value = wire::read(&mut client).await.unwrap().unwrap();
    assert_eq!(response["code"], "busy");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap();
    drop(permit);
    assert!(!gate.is_closed());
}

#[tokio::test]
async fn public_serve_uncertain_cleanup_closes_admission_and_retains_marker() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Semaphore::new(1));
    let slot = ExecutionSlot {
        _permit: gate.clone().acquire_owned().await.unwrap(),
        gate: gate.clone(),
        parent: root.path().to_owned(),
        confirmed: false,
    };
    drop(slot);
    assert!(gate.is_closed());
    assert!(root.path().join(".cleanup-unconfirmed").is_file());
    let gate = Arc::new(Semaphore::new(1));
    let slot = ExecutionSlot {
        _permit: gate.clone().acquire_owned().await.unwrap(),
        gate: gate.clone(),
        parent: root.path().to_owned(),
        confirmed: true,
    };
    drop(slot);
    assert!(!gate.is_closed());
    // Success on a separate slot never silently removes an earlier uncertain receipt.
    assert!(root.path().join(".cleanup-unconfirmed").is_file());
}

#[test]
fn public_serve_retained_task_bound_preserves_existing_data() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first = new_task(root.path()).unwrap();
    fs::write(first.join("input.txt"), "retained public input").unwrap();
    for _ in 1..MAX_RETAINED_TASKS {
        new_task(root.path()).unwrap();
    }
    assert!(new_task(root.path()).is_err());
    assert_eq!(
        fs::read_to_string(first.join("input.txt")).unwrap(),
        "retained public input"
    );
}
