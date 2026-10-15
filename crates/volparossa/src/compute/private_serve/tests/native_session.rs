//! Inert connection/ownership futures only. No model, worker or sandbox is run.
use super::*;

use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::super::super::supervise::native_session::{Command, Event};

fn native_config(root: &std::path::Path) -> private_task::ExecutionConfig {
    let mut config = output_constraint::native_config(root, true);
    let manifest = config
        .native_backend
        .native_backend_root
        .as_ref()
        .unwrap()
        .join("backend.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["version"] = 3.into();
    value["native_sessions"] = json!(["connection_bound_v1"]);
    let raw = serde_json::to_vec(&value).unwrap();
    fs::write(manifest, &raw).unwrap();
    config.native_backend.native_backend_sha256 = Some(hex::encode(Sha256::digest(raw)));
    config
}

fn cleanup() -> Value {
    json!({"version":1,"child_reaped":true,"private_state_removed":true})
}

fn answer() -> Value {
    json!({"version":2,"answer":"inert wire fixture","cleanup":{
        "version":2,"request_files_removed":true,"session_closed":false,
        "session_private_state_retained":true}})
}

fn conversation(instructions: &str) -> Value {
    json!({"type":"submit_conversation","conversation":{
        "version":1,"visibility":"private_local","instructions":instructions,
        "history":[{"type":"message","role":"user","text":"Hello"}],
        "tools":[],"generation_policy":"greedy_v1"}})
}

fn fake_session(
    id: String,
    _config: Arc<private_task::ExecutionConfig>,
    slot: ExecutionSlot,
    handshakes: Handshakes,
) -> NativeSession {
    fake_session_mode(id, slot, handshakes, false)
}

fn unconfirmed_session(
    id: String,
    _config: Arc<private_task::ExecutionConfig>,
    slot: ExecutionSlot,
    handshakes: Handshakes,
) -> NativeSession {
    fake_session_mode(id, slot, handshakes, true)
}

fn idle_session(
    id: String,
    _config: Arc<private_task::ExecutionConfig>,
    slot: ExecutionSlot,
    handshakes: Handshakes,
) -> NativeSession {
    NativeSession::spawn(
        id,
        slot,
        handshakes,
        |_commands, events, _activity| async move {
            events.send(Event::Opened).await.unwrap();
            Ok(cleanup())
        },
    )
}

fn unknown_failure_session(
    id: String,
    _config: Arc<private_task::ExecutionConfig>,
    slot: ExecutionSlot,
    handshakes: Handshakes,
) -> NativeSession {
    NativeSession::spawn(
        id,
        slot,
        handshakes,
        |_commands, events, _activity| async move {
            events.send(Event::Opened).await.unwrap();
            Err(anyhow::anyhow!("PRIVATE-CANARY-unknown-cleanup"))
        },
    )
}

fn fake_session_mode(
    id: String,
    slot: ExecutionSlot,
    handshakes: Handshakes,
    unconfirmed: bool,
) -> NativeSession {
    NativeSession::spawn(
        id,
        slot,
        handshakes,
        move |mut commands, events, mut activity| async move {
            events.send(Event::Opened).await.unwrap();
            loop {
                tokio::select! {
                    _ = activity.changed() => break,
                    command = commands.recv() => {
                        match command {
                            Some(Command::Submit { id, input }) => {
                                let value: Value = serde_json::from_slice(&input).unwrap();
                                if value["instructions"] != "hold" {
                                    let mut result = answer();
                                    if value["instructions"] == "wrong cleanup" {
                                        result["answer"] = "PRIVATE-CANARY-never-export".into();
                                        result["cleanup"] = cleanup();
                                    }
                                    events.send(Event::Result { id, value: result }).await.unwrap();
                                }
                            }
                            Some(Command::Close) | None => break,
                        }
                    }
                }
            }
            if unconfirmed {
                Err(private_task::CleanupUnconfirmed.into())
            } else {
                Ok(cleanup())
            }
        },
    )
}

async fn receive(client: &mut UnixStream) -> Value {
    tokio::time::timeout(
        Duration::from_secs(3),
        wire::read(client, wire::MAX_RESPONSE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap()
}

async fn send(client: &mut UnixStream, id: &str, operation: Value) {
    wire::write(client, &request(id, operation)).await.unwrap();
}

async fn negotiate(client: &mut UnixStream) {
    send(
        client,
        FIRST,
        json!({"type":"conversation_capabilities",
        "generation_policy_version":1,"execution_error_version":1,
        "output_constraint_version":1,"native_session_version":1}),
    )
    .await;
    let reply = receive(client).await;
    assert_eq!(reply["capabilities"]["native_session_version"], 1);
    assert_eq!(
        reply["capabilities"]["native_session"],
        json!({"version":1,"max_task_seconds":2400,"max_idle_seconds":300,"max_requests":128})
    );
}

#[test]
fn native_session_version_and_operations_reject_unknown_null_duplicate_and_free_fields() {
    for version in [
        json!(1),
        json!(0),
        json!(2),
        Value::Null,
        json!(true),
        json!("1"),
    ] {
        let value = request(
            FIRST,
            json!({"type":"conversation_capabilities","native_session_version":version}),
        );
        let accepted = serde_json::from_value::<wire::Request>(value).is_ok_and(|request| {
            request
                .validate_profile(ModelProfile::Qwen4bInstruct2507)
                .is_ok()
        });
        assert_eq!(accepted, version == json!(1));
    }
    let duplicate = format!(
        r#"{{"version":1,"id":"{FIRST}","operation":{{"type":"conversation_capabilities","native_session_version":1,"native_session_version":1}}}}"#
    );
    assert!(serde_json::from_str::<wire::Request>(&duplicate).is_err());
    for operation in ["open_native_session", "close_native_session"] {
        assert!(
            serde_json::from_value::<wire::Request>(request(FIRST, json!({"type":operation})))
                .is_ok()
        );
        for key in ["session_id", "owner", "path", "max_seconds", "model"] {
            let mut value = json!({"type":operation});
            value[key] = "PRIVATE-CANARY".into();
            assert!(serde_json::from_value::<wire::Request>(request(FIRST, value)).is_err());
        }
    }
}

#[test]
fn session_capability_requires_opt_in_and_exact_owner_manifest_and_legacy_caps_stay_exact() {
    let root = tempfile::tempdir().unwrap();
    let mut config = native_config(root.path());
    let gate = Semaphore::new(1);
    let mut handshake = Handshakes::default();
    let original = conversation_capabilities(&config, &gate, &handshake);
    assert!(original.get("native_session").is_none());
    handshake.native_session = Some(1);
    let mut extended = conversation_capabilities(&config, &gate, &handshake);
    assert_eq!(
        extended
            .as_object_mut()
            .unwrap()
            .remove("native_session_version"),
        Some(json!(1))
    );
    assert_eq!(
        extended.as_object_mut().unwrap().remove("native_session"),
        Some(
            json!({"version":1,"max_task_seconds":2400,"max_idle_seconds":300,"max_requests":128})
        )
    );
    assert_eq!(extended, original);
    config.native_backend.native_backend_sha256 = Some("0".repeat(64));
    assert_eq!(
        conversation_capabilities(&config, &gate, &handshake)["native_session"],
        Value::Null
    );
}

#[tokio::test]
async fn same_connection_two_turns_retain_slot_until_explicit_session_close_and_eof() {
    let root = tempfile::tempdir().unwrap();
    let config = Arc::new(native_config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let (server, mut client) = UnixStream::pair().unwrap();
    let (_stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection_with_native(
        server,
        config,
        gate.clone(),
        shutdown,
        fake_session,
    ));
    negotiate(&mut client).await;
    send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
    assert_eq!(
        receive(&mut client).await,
        wire::response(SECOND, "native_session_opened")
    );
    assert_eq!(gate.available_permits(), 0);
    for id in [THIRD, "04040404040404040404040404040404"] {
        send(&mut client, id, conversation("Reply")).await;
        assert_eq!(receive(&mut client).await, wire::response(id, "admitted"));
        let reply = receive(&mut client).await;
        assert_eq!(reply["result"], answer());
        assert!(reply["result"]["cleanup"].get("child_reaped").is_none());
        assert_eq!(gate.available_permits(), 0);
    }
    let close = "05050505050505050505050505050505";
    send(&mut client, close, json!({"type":"close_native_session"})).await;
    assert_eq!(
        receive(&mut client).await,
        json!({"version":1,"id":close,"event":"native_session_closed","cleanup":cleanup()})
    );
    assert!(
        wire::read::<Value>(&mut client, wire::MAX_RESPONSE_BYTES)
            .await
            .unwrap()
            .is_none()
    );
    serving.await.unwrap();
    assert_eq!(gate.available_permits(), 1);
    assert!(!gate.is_closed());
}

#[tokio::test]
async fn close_during_turn_cancels_before_closed_and_unconfirmed_cleanup_quarantines() {
    for unconfirmed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = Arc::new(native_config(root.path()));
        let gate = Arc::new(Semaphore::new(1));
        let (server, mut client) = UnixStream::pair().unwrap();
        let (_stop, shutdown) = watch::channel(false);
        let start: NativeSessionStart = if unconfirmed {
            unconfirmed_session
        } else {
            fake_session
        };
        let serving = tokio::spawn(connection_with_native(
            server,
            config,
            gate.clone(),
            shutdown,
            start,
        ));
        negotiate(&mut client).await;
        send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
        assert_eq!(receive(&mut client).await["event"], "native_session_opened");
        send(&mut client, THIRD, conversation("hold")).await;
        assert_eq!(receive(&mut client).await["event"], "admitted");
        let close = "04040404040404040404040404040404";
        send(&mut client, close, json!({"type":"close_native_session"})).await;
        let reply = receive(&mut client).await;
        assert_eq!(reply["id"], THIRD);
        assert_eq!(
            reply["code"],
            if unconfirmed {
                "cleanup_unconfirmed"
            } else {
                "cancelled"
            }
        );
        assert_eq!(
            reply["session_cleanup"],
            if unconfirmed { Value::Null } else { cleanup() }
        );
        if !unconfirmed {
            assert_eq!(
                receive(&mut client).await,
                json!({"version":1,"id":close,"event":"native_session_closed","cleanup":cleanup()})
            );
        }
        serving.await.unwrap();
        assert_eq!(gate.is_closed(), unconfirmed);
    }
}

#[tokio::test]
async fn eof_shutdown_and_invalid_turn_cleanup_wait_for_session_and_never_export_raw_output() {
    for mode in ["eof", "shutdown", "invalid"] {
        let root = tempfile::tempdir().unwrap();
        let config = Arc::new(native_config(root.path()));
        let gate = Arc::new(Semaphore::new(1));
        let (server, mut client) = UnixStream::pair().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let serving = tokio::spawn(connection_with_native(
            server,
            config,
            gate.clone(),
            shutdown,
            fake_session,
        ));
        negotiate(&mut client).await;
        send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
        receive(&mut client).await;
        let instruction = if mode == "invalid" {
            "wrong cleanup"
        } else {
            "hold"
        };
        send(&mut client, THIRD, conversation(instruction)).await;
        assert_eq!(receive(&mut client).await["event"], "admitted");
        if mode == "invalid" {
            let reply = receive(&mut client).await;
            assert_eq!(reply["code"], "execution_failed");
            assert_eq!(reply["session_cleanup"], cleanup());
            assert!(!reply.to_string().contains("PRIVATE-CANARY"));
        } else if mode == "shutdown" {
            stop.send(true).unwrap();
        } else {
            drop(client);
        }
        tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gate.available_permits(), 1);
        assert!(!gate.is_closed());
    }
}

#[tokio::test]
async fn session_slot_is_connection_exclusive_and_open_requires_its_own_handshake() {
    let root = tempfile::tempdir().unwrap();
    let config = Arc::new(native_config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let (first_server, mut first) = UnixStream::pair().unwrap();
    let (second_server, mut second) = UnixStream::pair().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let owner = tokio::spawn(connection_with_native(
        first_server,
        config.clone(),
        gate.clone(),
        shutdown.clone(),
        fake_session,
    ));
    let other = tokio::spawn(connection_with_native(
        second_server,
        config,
        gate.clone(),
        shutdown,
        fake_session,
    ));
    negotiate(&mut first).await;
    send(&mut first, SECOND, json!({"type":"open_native_session"})).await;
    receive(&mut first).await;
    send(&mut second, THIRD, json!({"type":"open_native_session"})).await;
    assert_eq!(
        receive(&mut second).await,
        wire::error(Some(THIRD), "handshake_required")
    );
    negotiate(&mut second).await;
    send(&mut second, SECOND, json!({"type":"open_native_session"})).await;
    assert_eq!(
        receive(&mut second).await,
        wire::error(Some(SECOND), "busy")
    );
    assert_eq!(gate.available_permits(), 0);
    stop.send(true).unwrap();
    owner.await.unwrap();
    other.await.unwrap();
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn automatic_idle_close_uses_original_open_id_and_requires_joined_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let config = Arc::new(native_config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let (server, mut client) = UnixStream::pair().unwrap();
    let (_stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection_with_native(
        server,
        config,
        gate.clone(),
        shutdown,
        idle_session,
    ));
    negotiate(&mut client).await;
    send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
    assert_eq!(
        receive(&mut client).await,
        wire::response(SECOND, "native_session_opened")
    );
    assert_eq!(
        receive(&mut client).await,
        json!({"version":1,"id":SECOND,"event":"native_session_closed","cleanup":cleanup()})
    );
    serving.await.unwrap();
    assert!(!gate.is_closed());
}

#[tokio::test]
async fn turn_count_and_negotiated_constraint_are_fixed_for_the_owner_session() {
    let gate = Arc::new(Semaphore::new(1));
    let slot = ExecutionSlot::admit(&gate).unwrap();
    let mut session = NativeSession::spawn(
        FIRST.into(),
        slot,
        Handshakes::default(),
        |_commands, _events, mut activity| async move {
            activity.changed().await.unwrap();
            Ok(cleanup())
        },
    );
    session.opened = true;
    session.requests = 128;
    let query = serde_json::from_value(request(SECOND, conversation("Reply"))).unwrap();
    assert_eq!(
        session.request(query),
        Some(wire::error(Some(SECOND), "invalid_request"))
    );
    assert!(session.pending.is_none());
    session.requests = 0;
    let constrained = serde_json::from_value(request(
        THIRD,
        json!({"type":"submit_conversation","conversation":{
            "version":1,"visibility":"private_local","instructions":"Reply",
            "history":[{"type":"message","role":"user","text":"Hello"}],
            "tools":[{"type":"custom","name":"read","description":"Read"}],
            "generation_policy":"greedy_v1","output_constraint":"qwen_tagged_tool_json_v1"}}),
    ))
    .unwrap();
    assert_eq!(
        session.request(constrained),
        Some(wire::error(Some(THIRD), "invalid_request"))
    );
    session.cancel();
    session.execution.take().unwrap().await.unwrap().unwrap();
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn ordinary_cancel_closes_the_session_only_after_confirmed_join() {
    let root = tempfile::tempdir().unwrap();
    let config = Arc::new(native_config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let (server, mut client) = UnixStream::pair().unwrap();
    let (_stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection_with_native(
        server,
        config,
        gate.clone(),
        shutdown,
        fake_session,
    ));
    negotiate(&mut client).await;
    send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
    receive(&mut client).await;
    send(&mut client, THIRD, conversation("hold")).await;
    assert_eq!(receive(&mut client).await["event"], "admitted");
    let cancel = "04040404040404040404040404040404";
    send(
        &mut client,
        cancel,
        json!({"type":"cancel","task_id":THIRD}),
    )
    .await;
    assert_eq!(
        receive(&mut client).await,
        json!({"version":1,"id":cancel,"event":"cancel_requested","task_id":THIRD})
    );
    assert_eq!(
        receive(&mut client).await,
        json!({"version":1,"id":THIRD,"event":"error","code":"cancelled","session_cleanup":cleanup()})
    );
    serving.await.unwrap();
    assert_eq!(gate.available_permits(), 1);
    assert!(!gate.is_closed());
}

#[tokio::test]
async fn opaque_engine_failure_without_cleanup_facts_quarantines_before_slot_release() {
    let root = tempfile::tempdir().unwrap();
    let config = Arc::new(native_config(root.path()));
    let gate = Arc::new(Semaphore::new(1));
    let (server, mut client) = UnixStream::pair().unwrap();
    let (_stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(connection_with_native(
        server,
        config,
        gate.clone(),
        shutdown,
        unknown_failure_session,
    ));
    negotiate(&mut client).await;
    send(&mut client, SECOND, json!({"type":"open_native_session"})).await;
    assert_eq!(receive(&mut client).await["event"], "native_session_opened");
    let reply = receive(&mut client).await;
    assert_eq!(
        reply,
        json!({"version":1,"id":SECOND,"event":"error",
            "code":"cleanup_unconfirmed","session_cleanup":null})
    );
    assert!(!reply.to_string().contains("PRIVATE-CANARY"));
    assert!(gate.is_closed());
    assert!(ExecutionSlot::admit(&gate).is_none());
    serving.await.unwrap();
}
