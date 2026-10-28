//! Real TLS/signatures/framing, deliberately inert injected worker. Not model proof.
use super::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::{io::DuplexStream, task::JoinHandle, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream};
use volparossa_content::provider::compute::resident_task::{GrantSpec, sign};

fn inputs() -> [Vec<u8>; 2] {
    ["First public test question", "Second public test question"].map(|text| serde_json::to_vec(&json!({
        "version":1,"visibility":"private_local","instructions":"Answer the public fixture question.",
        "history":[{"type":"message","role":"user","text":text}],"tools":[],"generation_policy":"greedy_v1"
    })).unwrap())
}

fn config() -> private_task::ExecutionConfig {
    private_task::ExecutionConfig {
        runtime_root: "/not-opened/runtime".into(),
        model_root: "/not-opened/model".into(),
        work_parent: "/not-opened/work".into(),
        model_profile: ModelProfile::Qwen4bInstruct2507,
        native_backend: native_cpu::Options::default(),
        threads: 2,
        max_seconds: 600,
    }
}

enum InertEnd {
    Failure(Option<tokio::sync::oneshot::Receiver<()>>),
    Abort(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    Unconfirmed,
    Panic,
}

impl InertEnd {
    async fn finish(
        self,
        joined: &AtomicBool,
        activity: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<serde_json::Value> {
        match self {
            Self::Failure(gate) => {
                if let Some(gate) = gate {
                    gate.await.unwrap();
                }
            }
            Self::Abort(gate, cancelled) => {
                activity.changed().await.unwrap();
                assert!(!*activity.borrow());
                cancelled.send(()).unwrap();
                gate.await.unwrap();
            }
            Self::Unconfirmed => return Err(private_task::CleanupUnconfirmed.into()),
            Self::Panic => panic!("inert_join_failure"),
        }
        joined.store(true, Ordering::SeqCst);
        Err(native_session::public_fixture_test_failure(
            anyhow::anyhow!("PRIVATE_CANARY /private/prompt").context("compute_memory_budget"),
        ))
    }
}

struct Fixture {
    stream: TlsStream<DuplexStream>,
    serving: JoinHandle<Result<()>>,
    spki: [u8; 32],
    started: Arc<AtomicUsize>,
    turns: Arc<AtomicUsize>,
    joined: Arc<AtomicBool>,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_end(None).await
    }

    async fn with_end(mut end: Option<InertEnd>) -> Self {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
        let (acceptor, spki) = tls_config(cert.der().to_vec(), key_pair.serialize_der()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![ALPN.to_vec()];
        let (client_io, server_io) = tokio::io::duplex(4096);
        let policy = Policy {
            version: 1,
            visibility: "public_fixture".into(),
            requester_key: hex::encode(signer().verifying_key().to_bytes()),
            workload_sha256: hex::encode([7; 32]),
            public_input_sha256: inputs().map(|bytes| hex::encode(Sha256::digest(bytes))),
        };
        let started = Arc::new(AtomicUsize::new(0));
        let turns = Arc::new(AtomicUsize::new(0));
        let joined = Arc::new(AtomicBool::new(false));
        let (start, turn, join) = (started.clone(), turns.clone(), joined.clone());
        let serving = tokio::spawn(serve(
            server_io,
            acceptor,
            spki,
            policy,
            config(),
            move |_, mut commands, events, mut activity, _budget| async move {
                start.fetch_add(1, Ordering::SeqCst);
                if events.send(native_session::Event::Opened).await.is_ok() {
                    loop {
                        tokio::select! {
                            biased;
                            _ = activity.changed() => break,
                            command = commands.recv() => match command {
                                Some(native_session::Command::Submit { id, .. }) => {
                                    turn.fetch_add(1, Ordering::SeqCst);
                                    if let Some(end) = end.take() { return end.finish(&join, &mut activity).await; }
                                    let value = json!({"version":2,"answer":"inert worker fixture","cleanup":{
                                        "version":2,"request_files_removed":true,"session_closed":false,"session_private_state_retained":true}});
                                    if events.send(native_session::Event::Result { id, value }).await.is_err() { break; }
                                },
                                _ => break,
                            }
                        }
                    }
                }
                join.store(true, Ordering::SeqCst);
                Ok(json!({"version":1,"child_reaped":true,"private_state_removed":true}))
            },
        ));
        let stream = TlsConnector::from(Arc::new(client))
            .connect(
                rustls::pki_types::ServerName::try_from("resident.test").unwrap(),
                client_io,
            )
            .await
            .unwrap();
        Self {
            stream,
            serving,
            spki,
            started,
            turns,
            joined,
        }
    }

    async fn grant(&mut self, duration_ms: u64, wrong_exporter: bool) -> Vec<u8> {
        let frame = wire::read(&mut self.stream, deadline()).await.unwrap();
        assert_eq!(frame.kind, wire::CHALLENGE);
        let challenge = wire::Challenge::decode(frame.body.as_slice()).unwrap();
        let mut exporter = self
            .stream
            .get_ref()
            .1
            .export_keying_material([0; 32], EXPORTER, None)
            .unwrap();
        if wrong_exporter {
            exporter[0] ^= 1;
        }
        sign(
            &signer(),
            &GrantSpec {
                requester_key: signer().verifying_key().to_bytes(),
                guest_tls_spki_sha256: self.spki,
                workload_sha256: [7; 32],
                model: GrantModel::Qwen3FourBInstruct2507,
                backend: GrantBackend::LlamaCppBf16V1,
                nonce: challenge.nonce.try_into().unwrap(),
                tls_exporter: exporter,
                issued_at_ms: challenge.issued_at_ms,
                expires_at_ms: challenge.issued_at_ms + duration_ms,
                limits: GrantLimits {
                    maximum_requests: 2,
                    maximum_turn_seconds: 600,
                    threads: 2,
                },
                public_input_sha256: inputs().map(|bytes| Sha256::digest(bytes).into()),
            },
        )
        .unwrap()
    }

    async fn admit(&mut self) {
        let grant = self.grant(10_000, false).await;
        wire::write(
            &mut self.stream,
            wire::frame(wire::GRANT, 0, grant),
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(
            wire::read(&mut self.stream, deadline()).await.unwrap().kind,
            wire::ACCEPTED
        );
    }

    async fn turn(&mut self, sequence: u32) {
        wire::write(
            &mut self.stream,
            wire::frame(
                wire::SUBMIT,
                sequence,
                inputs()[sequence as usize - 1].clone(),
            ),
            deadline(),
        )
        .await
        .unwrap();
        let admitted = wire::read(&mut self.stream, deadline()).await.unwrap();
        assert_eq!(
            (admitted.kind, admitted.sequence),
            (wire::ADMITTED, sequence)
        );
        let result = wire::read(&mut self.stream, deadline()).await.unwrap();
        assert_eq!((result.kind, result.sequence), (wire::RESULT, sequence));
    }
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[23; 32])
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn two_turns_share_one_tls_channel_and_worker_then_join() {
    let mut fixture = Fixture::new().await;
    fixture.admit().await;
    fixture.turn(1).await;
    fixture.turn(2).await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::CLOSE, 3, vec![]),
        deadline(),
    )
    .await
    .unwrap();
    let closed = wire::read(&mut fixture.stream, deadline()).await.unwrap();
    assert_eq!(closed.kind, wire::CLOSED);
    assert!(fixture.joined.load(Ordering::SeqCst));
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert_eq!(fixture.started.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.turns.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn third_turn_is_rejected_and_owner_joins() {
    let mut fixture = Fixture::new().await;
    fixture.admit().await;
    fixture.turn(1).await;
    fixture.turn(2).await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 3, inputs()[0].clone()),
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.turns.load(Ordering::SeqCst), 2);
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[tokio::test]
async fn unapproved_input_rejects_before_worker_turn() {
    let mut fixture = Fixture::new().await;
    fixture.admit().await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 1, b"not approved public input".to_vec()),
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.turns.load(Ordering::SeqCst), 0);
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[tokio::test]
async fn disconnect_cancels_and_joins_the_same_worker() {
    let mut fixture = Fixture::new().await;
    fixture.admit().await;
    fixture.turn(1).await;
    drop(fixture.stream);
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[tokio::test]
async fn wrong_tls_exporter_never_starts_a_worker() {
    let mut fixture = Fixture::new().await;
    let grant = fixture.grant(10_000, true).await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::GRANT, 0, grant),
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.started.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signature_tampering_never_starts_a_worker() {
    let mut fixture = Fixture::new().await;
    let mut grant = fixture.grant(10_000, false).await;
    *grant.last_mut().unwrap() ^= 1;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::GRANT, 0, grant),
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.started.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn idle_grant_expiry_cancels_and_joins() {
    let mut fixture = Fixture::new().await;
    let grant = fixture.grant(1000, false).await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::GRANT, 0, grant),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        wire::read(&mut fixture.stream, deadline())
            .await
            .unwrap()
            .kind,
        wire::ACCEPTED
    );
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[tokio::test]
async fn repeated_sequence_rejects_without_duplicate_execution() {
    let mut fixture = Fixture::new().await;
    fixture.admit().await;
    fixture.turn(1).await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 1, inputs()[0].clone()),
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_secs(5), fixture.serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.turns.load(Ordering::SeqCst), 1);
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[test]
fn private_or_unknown_policy_is_not_a_public_fixture() {
    for visibility in ["private", "private_local", "public"] {
        let policy = json!({"version":1,"visibility":visibility,"requester_key":hex::encode([1;32]),"workload_sha256":hex::encode([2;32]),"public_input_sha256":[hex::encode([3;32]),hex::encode([4;32])]});
        assert!(Policy::decode(&serde_json::to_vec(&policy).unwrap()).is_err());
    }
}

#[tokio::test]
async fn canonical_frame_rejects_unknown_fields_and_oversize_length() {
    use tokio::io::AsyncWriteExt as _;
    for bytes in [vec![8, 1, 16, 1, 80, 1], vec![]] {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let length = if bytes.is_empty() {
            u32::try_from(wire::MAX_FRAME + 1).unwrap()
        } else {
            u32::try_from(bytes.len()).unwrap()
        };
        writer.write_u32(length).await.unwrap();
        writer.write_all(&bytes).await.unwrap();
        assert!(wire::read(&mut reader, deadline()).await.is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn expired_wire_budget_rejects_even_when_io_is_ready() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    wire::write(&mut writer, wire::frame(wire::CLOSE, 1, vec![]), deadline())
        .await
        .unwrap();
    let expired = Instant::now();
    assert!(wire::read(&mut reader, expired).await.is_err());
    assert!(
        wire::write(&mut writer, wire::frame(wire::CLOSE, 2, vec![]), expired)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_failure_frame_follows_join_gate_and_preserves_original_failure() {
    let (release, gate) = tokio::sync::oneshot::channel();
    let mut fixture = Fixture::with_end(Some(InertEnd::Failure(Some(gate)))).await;
    fixture.admit().await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 1, inputs()[0].clone()),
        deadline(),
    )
    .await
    .unwrap();
    let admitted = wire::read(&mut fixture.stream, deadline()).await.unwrap();
    assert_eq!((admitted.kind, admitted.sequence), (wire::ADMITTED, 1));
    assert!(
        timeout(
            Duration::from_millis(25),
            wire::read(&mut fixture.stream, deadline())
        )
        .await
        .is_err()
    );
    assert!(!fixture.joined.load(Ordering::SeqCst));
    release.send(()).unwrap();
    let frame = wire::read(&mut fixture.stream, deadline()).await.unwrap();
    let value = wire::failure_body(&frame, 1).unwrap();
    assert!(fixture.joined.load(Ordering::SeqCst));
    assert_eq!(value["detail"]["code"], "compute_memory_budget");
    assert!(!value.to_string().contains("PRIVATE_CANARY"));
    assert_eq!(
        value["cleanup"],
        json!({"version":1,"child_reaped":true,"private_state_removed":true})
    );
    let error = fixture.serving.await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    // The old reader's existing kind/order predicate still rejects this frame.
    assert_ne!((frame.kind, frame.sequence), (wire::RESULT, 1));
}

#[tokio::test]
async fn unconfirmed_cleanup_or_join_panic_cannot_emit_failure_frame() {
    for end in [InertEnd::Unconfirmed, InertEnd::Panic] {
        let mut fixture = Fixture::with_end(Some(end)).await;
        fixture.admit().await;
        wire::write(
            &mut fixture.stream,
            wire::frame(wire::SUBMIT, 1, inputs()[0].clone()),
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(
            wire::read(&mut fixture.stream, deadline())
                .await
                .unwrap()
                .kind,
            wire::ADMITTED
        );
        assert!(wire::read(&mut fixture.stream, deadline()).await.is_err());
        let error = fixture.serving.await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "resident_cleanup_unconfirmed");
        assert!(!fixture.joined.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn disconnect_before_native_finish_cannot_export_cancelled_worker_diagnostic() {
    let (release, gate) = tokio::sync::oneshot::channel();
    let (cancelled, cancellation) = tokio::sync::oneshot::channel();
    let mut fixture = Fixture::with_end(Some(InertEnd::Abort(gate, cancelled))).await;
    fixture.admit().await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 1, inputs()[0].clone()),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        wire::read(&mut fixture.stream, deadline())
            .await
            .unwrap()
            .kind,
        wire::ADMITTED
    );
    drop(fixture.stream);
    timeout(Duration::from_secs(5), cancellation)
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    let error = fixture.serving.await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn diagnostic_write_is_optional_and_never_renews_expired_budget() {
    use tokio::io::AsyncReadExt as _;
    let error =
        native_session::public_fixture_test_failure(anyhow::anyhow!("compute_memory_budget"));
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let started = Instant::now();
    let stop = started + Duration::from_millis(50);
    session::observe_native_failure(&mut writer, &error, 1, stop).await;
    assert_eq!(Instant::now(), stop);
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    assert_eq!(
        native_session::cleanup(&error),
        Some(json!({"version":1,"child_reaped":true,"private_state_removed":true}))
    );
    let mut bytes = [0];
    reader.read_exact(&mut bytes).await.unwrap();
    session::observe_native_failure(&mut writer, &error, 1, stop).await;
    assert_eq!(Instant::now(), stop);
}

#[tokio::test]
async fn failed_diagnostic_sink_or_unsealed_error_cannot_replace_owner_error() {
    let error =
        native_session::public_fixture_test_failure(anyhow::anyhow!("compute_memory_budget"));
    let (mut writer, reader) = tokio::io::duplex(1024);
    drop(reader);
    session::observe_native_failure(&mut writer, &error, 1, deadline()).await;
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    session::observe_native_failure(
        &mut writer,
        &anyhow::anyhow!("PRIVATE_CANARY"),
        1,
        deadline(),
    )
    .await;
    drop(writer);
    assert!(wire::read(&mut reader, deadline()).await.is_err());
}

#[test]
fn terminal_failure_schema_is_closed_canonical_and_turn_bound() {
    let detail = json!({"code":"NATIVE_MODEL_LOAD_FAILED","io_kind":"none",
        "exit_code":null,"signal":null,"stderr_class":null});
    let frame = wire::failure(1, &detail).unwrap();
    assert!(wire::failure_body(&frame, 1).is_ok());
    assert!(wire::failure(0, &detail).is_err());
    assert!(wire::failure(3, &detail).is_err());
    assert!(wire::failure_body(&frame, 2).is_err());
    for (path, replacement) in [
        (vec!["version"], json!(2)),
        (vec!["scope"], json!("private")),
        (vec!["extra"], json!("PRIVATE_CANARY")),
        (
            vec!["detail", "code"],
            json!("NATIVE_MODEL_LOAD_FAILED PRIVATE_CANARY"),
        ),
        (vec!["detail", "io_kind"], json!("PRIVATE_CANARY")),
        (vec!["detail", "exit_code"], json!(0)),
        (vec!["cleanup", "private_state_removed"], json!(false)),
    ] {
        let mut value = wire::failure_body(&frame, 1).unwrap();
        let mut field = &mut value;
        for key in path {
            field = &mut field[key];
        }
        *field = replacement;
        let changed = wire::frame(wire::FAILURE, 1, serde_json::to_vec(&value).unwrap());
        assert!(wire::failure_body(&changed, 1).is_err());
    }
    for bytes in [
        [b" ".as_slice(), &frame.body].concat(),
        [b"{\"version\":1,".as_slice(), &frame.body[1..]].concat(),
        vec![b'x'; wire::MAX_FAILURE + 1],
        b"{".to_vec(),
    ] {
        assert!(wire::failure_body(&wire::frame(wire::FAILURE, 1, bytes), 1).is_err());
    }
}

#[tokio::test]
async fn pending_protocol_abort_keeps_tls_open_and_cannot_emit_native_failure() {
    let (release, gate) = tokio::sync::oneshot::channel();
    let (cancelled, cancellation) = tokio::sync::oneshot::channel();
    let mut fixture = Fixture::with_end(Some(InertEnd::Abort(gate, cancelled))).await;
    fixture.admit().await;
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::SUBMIT, 1, inputs()[0].clone()),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        wire::read(&mut fixture.stream, deadline())
            .await
            .unwrap()
            .kind,
        wire::ADMITTED
    );
    wire::write(
        &mut fixture.stream,
        wire::frame(wire::CLOSE, 2, vec![]),
        deadline(),
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(5), cancellation)
        .await
        .unwrap()
        .unwrap();
    assert!(!fixture.joined.load(Ordering::SeqCst));
    release.send(()).unwrap();
    // Retain the authenticated reader: an accidentally sent kind9 would succeed.
    assert!(wire::read(&mut fixture.stream, deadline()).await.is_err());
    let error = fixture.serving.await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    assert!(fixture.joined.load(Ordering::SeqCst));
}

#[test]
fn public_bubblewrap_stage_frame_roundtrip_requires_exact_cleanup_and_scope() {
    // Wire-contract fixture only; this fabricates no runtime cleanup evidence.
    for class in [
        "bubblewrap_namespace_setup",
        "bubblewrap_root_setup",
        "bubblewrap_source_setup",
        "bubblewrap_destination_setup",
        "bubblewrap_bind_mount",
    ] {
        let detail = json!({"code":"compute_native_session_stdout_closed","io_kind":"none",
            "exit_code":1,"signal":0,"stderr_class":class});
        let frame = wire::failure(1, &detail).unwrap();
        let body = wire::failure_body(&frame, 1).unwrap();
        assert_eq!(body["detail"], detail);
        let mut invalid = body.clone();
        invalid["cleanup"]["child_reaped"] = false.into();
        let changed = wire::frame(wire::FAILURE, 1, serde_json::to_vec(&invalid).unwrap());
        assert!(wire::failure_body(&changed, 1).is_err());
        let mut wrong = detail.clone();
        wrong["code"] = "startup_missing_result".into();
        assert!(wire::failure(1, &wrong).is_err());
        let mut private = detail.clone();
        private["stderr_class"] = format!("{class} PRIVATE_CANARY").into();
        assert!(wire::failure(1, &private).is_err());
    }
}
