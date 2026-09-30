//! Protocol and lifecycle tests. Synthetic job futures below test admission only,
//! not model inference, a Firefox UI or real sandbox-process cleanup.

use super::*;
use tokio::io::AsyncWriteExt as _;

const FIRST: &str = "01010101010101010101010101010101";
const SECOND: &str = "02020202020202020202020202020202";
const THIRD: &str = "03030303030303030303030303030303";

fn request(id: &str, operation: Value) -> Value {
    let mut request = json!({"version":1,"id":id});
    request["operation"] = operation;
    request
}

fn config(root: &std::path::Path) -> private_task::ExecutionConfig {
    private_task::ExecutionConfig {
        runtime_root: root.join("runtime"),
        model_root: root.join("model"),
        work_parent: root.join("work"),
        model_profile: ModelProfile::Smol360,
        threads: 1,
        max_seconds: 1,
    }
}

#[test]
fn private_serve_schema_rejects_private_path_commands_public_scope_and_duplicate_fields() {
    let valid = request(
        FIRST,
        json!({"type":"submit","question":"Question?","context":"Private context."}),
    );
    let decoded: wire::Request = serde_json::from_value(valid.clone()).unwrap();
    decoded.validate().unwrap();
    for (field, value) in [
        ("runtime_root", json!("/untrusted/runtime")),
        ("command", json!("execute a command")),
        ("visibility", json!("public")),
        ("model_profile", json!("smollm2-1.7b-v1")),
        ("max_seconds", json!(999_999)),
    ] {
        let mut invalid = valid.clone();
        invalid["operation"][field] = value;
        assert!(serde_json::from_value::<wire::Request>(invalid).is_err());
    }
    for change in [
        json!({"version":2,"id":FIRST,"operation":{"type":"capabilities"}}),
        request("owner-private-id", json!({"type":"capabilities"})),
        request(
            FIRST,
            json!({"type":"submit","question":"x".repeat(513),"context":"C"}),
        ),
        request(FIRST, json!({"type":"submit","question":"Q","context":""})),
    ] {
        let invalid: wire::Request = serde_json::from_value(change).unwrap();
        assert!(invalid.validate().is_err());
    }
    for raw in [
        format!(
            r#"{{"version":1,"version":1,"id":"{FIRST}","operation":{{"type":"capabilities"}}}}"#
        ),
        format!(
            r#"{{"version":1,"id":"{FIRST}","operation":{{"type":"submit","question":"Q","question":"private-canary","context":"C"}}}}"#
        ),
        format!(r#"{{"version":1,"id":"{FIRST}","operation":{{"type":"public_infer"}}}}"#),
    ] {
        assert!(serde_json::from_str::<wire::Request>(&raw).is_err());
    }
    assert!(
        serde_json::from_value::<wire::Request>(request(
            FIRST,
            json!({"type":"capabilities","private-canary":"unrecognized"})
        ))
        .is_err()
    );
}

#[tokio::test]
async fn private_serve_framing_is_bounded_and_never_echoes_parser_details() {
    for raw in [
        vec![0, 0, 0, 0],
        u32::try_from(wire::MAX_REQUEST_BYTES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&raw).await.unwrap();
        assert!(
            wire::read::<wire::Request>(&mut reader, wire::MAX_REQUEST_BYTES)
                .await
                .is_err()
        );
    }
    let (mut writer, mut reader) = tokio::io::duplex(256);
    let invalid = br#"{"private-canary-unknown":true}"#;
    writer
        .write_all(&u32::try_from(invalid.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    writer.write_all(invalid).await.unwrap();
    let error = wire::read::<wire::Request>(&mut reader, wire::MAX_REQUEST_BYTES)
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "private_ipc_invalid_request");
    assert!(!error.to_string().contains("canary"));
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&[0, 0]).await.unwrap();
    drop(writer);
    assert!(
        wire::read::<wire::Request>(&mut reader, wire::MAX_REQUEST_BYTES)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn private_serve_same_connection_handshake_busy_and_foreign_cancel_use_real_unix_frames() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Semaphore::new(1));
    // Hold the production admission primitive; no synthetic inference is reported.
    let mut occupied = ExecutionSlot::admit(&gate).unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection(
        server,
        Arc::new(config(root.path())),
        gate.clone(),
        shutdown,
    ));
    wire::write(
        &mut client,
        &request(FIRST, json!({"type":"submit","question":"Q","context":"C"})),
    )
    .await
    .unwrap();
    let response: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["code"], "handshake_required");
    wire::write(
        &mut client,
        &request(SECOND, json!({"type":"capabilities"})),
    )
    .await
    .unwrap();
    let response: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["id"], SECOND);
    assert_eq!(response["event"], "capabilities");
    assert_eq!(response["capabilities"]["visibility"], "private_local");
    assert_eq!(response["capabilities"]["network_access"], false);
    wire::write(
        &mut client,
        &request(THIRD, json!({"type":"submit","question":"Q","context":"C"})),
    )
    .await
    .unwrap();
    let response: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["code"], "busy");
    wire::write(
        &mut client,
        &request(
            "04040404040404040404040404040404",
            json!({"type":"cancel","task_id":FIRST}),
        ),
    )
    .await
    .unwrap();
    let response: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["code"], "no_such_task");
    stop.send(true).unwrap();
    serving.await.unwrap();
    occupied.finish(&Err(anyhow::anyhow!("no worker started")));
}

#[tokio::test]
async fn private_serve_cancel_or_disconnect_keeps_admission_until_execution_returns() {
    for disconnect in [false, true] {
        let gate = Arc::new(Semaphore::new(1));
        let mut slot = ExecutionSlot::admit(&gate).unwrap();
        let (activity, mut signal) = watch::channel(true);
        let (cancel_seen, cancelled) = tokio::sync::oneshot::channel();
        let (permit_finish, finish) = tokio::sync::oneshot::channel();
        let execution = tokio::spawn(async move {
            signal.changed().await.unwrap();
            assert!(!*signal.borrow());
            cancel_seen.send(()).unwrap();
            finish.await.unwrap();
            let result = Err(anyhow::anyhow!("synthetic lifecycle test only"));
            slot.finish(&result);
            result
        });
        let mut task = Active {
            id: FIRST.into(),
            activity,
            execution: Some(execution),
            cancelled: false,
        };
        if disconnect {
            let execution = task.execution.take().unwrap();
            drop(task);
            cancelled.await.unwrap();
            assert!(ExecutionSlot::admit(&gate).is_none());
            permit_finish.send(()).unwrap();
            assert!(execution.await.unwrap().is_err());
        } else {
            task.cancel();
            cancelled.await.unwrap();
            assert!(ExecutionSlot::admit(&gate).is_none());
            permit_finish.send(()).unwrap();
            assert!(task.reap().await.is_err());
        }
        assert!(!gate.is_closed());
        assert_eq!(gate.available_permits(), 1);
    }
}

#[test]
fn private_serve_unconfirmed_cleanup_or_dropped_execution_quarantines_admission() {
    for unconfirmed in [false, true] {
        let gate = Arc::new(Semaphore::new(1));
        let mut slot = ExecutionSlot::admit(&gate).unwrap();
        if unconfirmed {
            slot.finish(&Err(private_task::CleanupUnconfirmed.into()));
        }
        drop(slot);
        assert!(gate.is_closed());
        assert!(ExecutionSlot::admit(&gate).is_none());
    }
}

#[tokio::test]
async fn conversation_handshake_is_separate_but_shares_the_private_execution_slot() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Semaphore::new(1));
    let mut occupied = ExecutionSlot::admit(&gate).unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection(
        server,
        Arc::new(config(root.path())),
        gate.clone(),
        shutdown,
    ));
    let submit = json!({"type":"submit_conversation","conversation":{
        "version":1,"visibility":"private_local","instructions":"Review synthetic code.",
        "history":[{"type":"message","role":"user","text":"Explain 1+1."}],"tools":[]}});
    for (index, operation, expected) in [
        (1, json!({"type":"capabilities"}), "capabilities"),
        (2, submit.clone(), "handshake_required"),
        (
            3,
            json!({"type":"conversation_capabilities"}),
            "conversation_capabilities",
        ),
        (4, submit.clone(), "busy"),
    ] {
        wire::write(&mut client, &request(&format!("{index:032x}"), operation))
            .await
            .unwrap();
        let reply: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reply[if reply["event"] == "error" {
                "code"
            } else {
                "event"
            }],
            expected
        );
        if expected == "capabilities" {
            assert!(reply["capabilities"].get("max_prompt_tokens").is_none());
        }
        if expected == "conversation_capabilities" {
            assert_eq!(reply["capabilities"]["max_prompt_tokens"], 1024);
            assert_eq!(reply["capabilities"]["tool_execution"], false);
        }
    }
    gate.close();
    wire::write(&mut client, &request(&format!("{:032x}", 5), submit))
        .await
        .unwrap();
    let reply: Value = wire::read(&mut client, wire::MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply["code"], "cleanup_unconfirmed");
    stop.send(true).unwrap();
    serving.await.unwrap();
    occupied.finish(&Err(anyhow::anyhow!("no model invoked")));
}

#[tokio::test]
async fn private_serve_uses_real_private_staging_and_cleans_it_on_backend_validation_failure() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    for directory in [
        &config.runtime_root,
        &config.model_root,
        &config.work_parent,
    ] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (_owner, activity) = watch::channel(true);
    let input = wire::input_bytes(
        "Private question?",
        "Private canary, never a public dataset.",
    )
    .unwrap();
    let result = private_task::execute_bytes(&config, input, activity.clone()).await;
    // No runtime/model was provisioned: this exercises the real validation and
    // staging cleanup path, not an inference-success or sandbox-reaping claim.
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&config.work_parent).unwrap().count(), 0);
    assert!(fs::read_dir(&config.runtime_root).unwrap().next().is_none());
    let input = serde_json::to_vec(&json!({"version":1,"visibility":"private_local",
        "instructions":"Review synthetic code.","history":[{"type":"message","role":"user","text":"Explain 1+1."}],
        "tools":[]})).unwrap();
    let result = private_task::execute_mode(
        &config,
        input,
        activity,
        super::super::Mode::PrivateConversation,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&config.work_parent).unwrap().count(), 0);
    assert!(fs::read_dir(&config.runtime_root).unwrap().next().is_none());
}
