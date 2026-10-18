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
