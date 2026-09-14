//! Real bounded duplex exchanges; no network sockets or receiver-credit fallback.

use super::*;
use crate::{Metadata, Publication, publish};
use ed25519_dalek::SigningKey;
use tokio::io::duplex;

fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 8 * CHUNK_BYTES as u64,
        max_entries: 32,
        min_free_bytes: 0,
    }
}

struct Fixture {
    temporary: tempfile::TempDir,
    source_root: PathBuf,
    registry: PublicationRegistry,
    signed: SignedManifest,
    verified: VerifiedManifest,
}

impl Fixture {
    fn new(chunks: usize) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let source_root = temporary.path().join("source");
        let mut source = ChunkStore::create(&source_root, cache_limits()).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let bytes: Vec<_> = (1..=chunks)
            .flat_map(|index| vec![u8::try_from(index).unwrap(); CHUNK_BYTES])
            .collect();
        let created = now().unwrap();
        let signed = publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "explicit replica".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created,
                    expires: created + 600,
                },
            },
            &key,
            &mut source,
        )
        .unwrap();
        let verified = signed.verify(&key.verifying_key(), created).unwrap();
        drop(source);
        let mut registry = PublicationRegistry::new();
        registry
            .register_shareable(
                signed.clone(),
                &key.verifying_key(),
                source_root.clone(),
                cache_limits(),
                created,
            )
            .unwrap();
        Self {
            temporary,
            source_root,
            registry,
            signed,
            verified,
        }
    }

    fn store(&self, name: &str) -> ChunkStore {
        ChunkStore::create(&self.temporary.path().join(name), cache_limits()).unwrap()
    }
}

#[tokio::test]
async fn credit_stall_sends_nothing_and_releases_cache_for_real_foreground_pull() {
    let fixture = Fixture::new(2);
    let snapshot = fixture.registry.clone();
    let (mut client, mut server) = duplex(4096);
    let receive = async {
        let mut budget = Budget::new(MAX_WIRE_BYTES);
        write(
            &mut client,
            &selector(CREDIT_VERSION),
            super::super::MAX_SELECTOR_BYTES,
            &mut budget,
        )
        .await
        .unwrap();
        let request = Request::new(
            ReplicationLimits::default(),
            &ReplicationExclusions::default(),
            CREDIT_VERSION,
        )
        .unwrap();
        write(&mut client, &request, MAX_REQUEST_BYTES, &mut budget)
            .await
            .unwrap();
        // Even before the first credit, an available registered chunk cannot be sent.
        assert!(
            tokio::time::timeout(Duration::from_millis(25), client.read_u8())
                .await
                .is_err()
        );
        write(
            &mut client,
            &Credit::new(true),
            MAX_CREDIT_BYTES,
            &mut budget,
        )
        .await
        .unwrap();
        let first: Frame = read(&mut client, MAX_FRAME_BYTES, &mut budget)
            .await
            .unwrap();
        assert_eq!(first.data, vec![1; CHUNK_BYTES]);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), client.read_u8())
                .await
                .is_err()
        );
        // A stalled optional stream cannot hold the registered cache's exclusive lock.
        drop(ChunkStore::open(&fixture.source_root, cache_limits()).unwrap());
        let mut consumer = fixture.store("foreground");
        let (mut foreground, mut provider) = duplex(4096);
        let (received, sent) = tokio::join!(
            super::super::pull_publication(
                &mut foreground,
                &fixture.verified,
                &mut consumer,
                TransferLimits::default()
            ),
            super::super::serve_publication(
                &mut provider,
                &fixture.registry,
                TransferLimits::default()
            ),
        );
        assert_eq!(received.unwrap().bytes, (2 * CHUNK_BYTES) as u64);
        assert_eq!(sent.unwrap().chunks, 2);
        write(
            &mut client,
            &Credit::new(false),
            MAX_CREDIT_BYTES,
            &mut budget,
        )
        .await
        .unwrap();
        let finish: Frame = read(&mut client, MAX_FRAME_BYTES, &mut budget)
            .await
            .unwrap();
        assert!(finish == Frame::finish(CREDIT_VERSION));
    };
    let serve = super::super::serve_publication(&mut server, &snapshot, TransferLimits::default());
    let ((), sent) = tokio::join!(receive, serve);
    assert_eq!(sent.unwrap().chunks, 1);
}

#[tokio::test]
async fn admission_pause_resumes_the_same_stream_with_verified_partial_and_original_bounds() {
    let fixture = Fixture::new(2);
    let mut target = fixture.store("target");
    let (mut client, mut server) = duplex(4096);
    let exclusions = ReplicationExclusions::default();
    let (paused, observed_pause) = tokio::sync::oneshot::channel();
    let mut paused = Some(paused);
    let quiet = tokio::sync::Notify::new();
    let mut checks = 0;
    let (received, sent) = {
        let exchange = async {
            tokio::join!(
                pull_replicas_with_admission(
                    &mut client,
                    &mut target,
                    ReplicationLimits::default(),
                    &exclusions,
                    || {
                        checks += 1;
                        let paused = if checks == 2 { paused.take() } else { None };
                        let quiet = &quiet;
                        async move {
                            if let Some(paused) = paused {
                                // The first chunk is already verified before this callback.
                                // Simulated owner activity blocks only the next credit.
                                paused.send(()).unwrap();
                                quiet.notified().await;
                            }
                            true
                        }
                    }
                ),
                super::super::serve_publication(
                    &mut server,
                    &fixture.registry,
                    TransferLimits::default()
                ),
            )
        };
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => panic!("exchange ended before credit pause: {result:?}"),
            paused = tokio::time::timeout(Duration::from_secs(2), observed_pause) => {
                paused.unwrap().unwrap();
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut exchange)
                .await
                .is_err()
        );
        // No source-cache lock is held while the optional exchange awaits credit.
        drop(ChunkStore::open(&fixture.source_root, cache_limits()).unwrap());
        quiet.notify_one();
        tokio::time::timeout(Duration::from_secs(2), exchange)
            .await
            .unwrap()
    };
    let received = received.unwrap();
    assert_eq!(checks, 3); // Two chunks and the final credit, without a new exchange.
    assert_eq!(
        (received.chunks, received.bytes),
        (2, (2 * CHUNK_BYTES) as u64)
    );
    assert_eq!(sent.unwrap().chunks, 2);
    assert_eq!(received.replicas[0].validity(), fixture.verified.validity());
    assert!(received.wire_bytes > received.bytes && received.wire_bytes <= MAX_WIRE_BYTES);
    for (index, chunk) in fixture.verified.chunks().iter().enumerate() {
        assert_eq!(
            target.get(chunk.id()).unwrap().unwrap(),
            vec![u8::try_from(index + 1).unwrap(); CHUNK_BYTES]
        );
    }
}

#[tokio::test]
async fn owner_busy_stop_returns_verified_partial_with_original_expiry_and_no_eviction() {
    let fixture = Fixture::new(2);
    let mut target = fixture.store("target");
    let foreground = target.put(b"already held foreground").unwrap();
    let (mut client, mut server) = duplex(4096);
    let mut checks = 0;
    let exclusions = ReplicationExclusions::default();
    let (received, sent) = tokio::join!(
        pull_replicas_with_admission(
            &mut client,
            &mut target,
            ReplicationLimits::default(),
            &exclusions,
            || {
                checks += 1;
                std::future::ready(checks == 1)
            }
        ),
        super::super::serve_publication(&mut server, &fixture.registry, TransferLimits::default()),
    );
    let received = received.unwrap();
    assert_eq!(checks, 2);
    assert_eq!((received.chunks, received.bytes), (1, CHUNK_BYTES as u64));
    assert_eq!(sent.unwrap().chunks, 1);
    assert_eq!(received.replicas[0].validity(), fixture.verified.validity());
    assert_eq!(received.replicas[0].hops(), 1);
    assert_eq!(
        target.get(&foreground).unwrap().unwrap(),
        b"already held foreground"
    );
    assert_eq!(
        target
            .get(fixture.verified.chunks()[0].id())
            .unwrap()
            .unwrap(),
        vec![1; CHUNK_BYTES]
    );
    assert!(
        target
            .get(fixture.verified.chunks()[1].id())
            .unwrap()
            .is_none()
    );
    assert!(received.wire_bytes > received.bytes);
}

#[tokio::test]
async fn wire_budget_includes_every_credit_and_final_finish_without_extra_chunk() {
    let fixture = Fixture::new(4);
    let mut target = fixture.store("target");
    let (mut client, mut server) = duplex(4096);
    let exclusions = ReplicationExclusions::default();
    let limits = ReplicationLimits::default();
    let (received, sent) = tokio::join!(
        pull_replicas_with_admission(&mut client, &mut target, limits, &exclusions, || {
            std::future::ready(true)
        }),
        super::super::serve_publication(&mut server, &fixture.registry, TransferLimits::default()),
    );
    let received = received.unwrap();
    assert_eq!(received.chunks, 3);
    assert_eq!(sent.unwrap().chunks, 3);
    let mut expected = selector(CREDIT_VERSION).encoded_len()
        + 4
        + Request::new(limits, &exclusions, CREDIT_VERSION)
            .unwrap()
            .encoded_len()
        + 4
        + 4 * (Credit::new(true).encoded_len() + 4)
        + Frame::finish(CREDIT_VERSION).encoded_len()
        + 4;
    for index in 0..3 {
        expected += Frame {
            version: CREDIT_VERSION,
            finished: false,
            publisher: fixture.verified.publisher().to_vec(),
            manifest: fixture.signed.encode(),
            hops: 0,
            chunk_index: index,
            data: vec![u8::try_from(index + 1).unwrap(); CHUNK_BYTES],
        }
        .encoded_len()
            + 4;
    }
    assert_eq!(received.wire_bytes, expected as u64);
    assert!(received.wire_bytes <= MAX_WIRE_BYTES);
}

#[tokio::test]
async fn admission_and_provider_credit_waits_keep_the_original_deadline_and_reject_v2() {
    let fixture = Fixture::new(1);
    let mut target = fixture.store("target");
    let exclusions = ReplicationExclusions::default();
    let (mut client, mut server) = duplex(4096);
    let limits = ReplicationLimits {
        session_timeout: Duration::from_millis(40),
        ..Default::default()
    };
    let serve_limits = TransferLimits {
        session_timeout: Duration::from_millis(60),
        ..Default::default()
    };
    let (received, sent) = tokio::join!(
        pull_replicas_with_admission(
            &mut client,
            &mut target,
            limits,
            &exclusions,
            std::future::pending::<bool>
        ),
        super::super::serve_publication(&mut server, &fixture.registry, serve_limits),
    );
    assert!(matches!(received, Err(ProviderError::Timeout)));
    assert!(matches!(sent, Err(ProviderError::Timeout)));
    assert_eq!(target.usage().entries, 0);
    let (mut client, mut old_provider) = duplex(4096);
    let old_reply = async {
        let mut budget = Budget::new(MAX_WIRE_BYTES);
        let selected: Selector = read(
            &mut old_provider,
            super::super::MAX_SELECTOR_BYTES,
            &mut budget,
        )
        .await
        .unwrap();
        assert_eq!(selected.version, CREDIT_VERSION);
        let _: Request = read(&mut old_provider, MAX_REQUEST_BYTES, &mut budget)
            .await
            .unwrap();
        let _: Credit = read(&mut old_provider, MAX_CREDIT_BYTES, &mut budget)
            .await
            .unwrap();
        write(
            &mut old_provider,
            &Frame::finish(VERSION),
            MAX_FRAME_BYTES,
            &mut budget,
        )
        .await
        .unwrap();
    };
    let (received, ()) = tokio::join!(
        pull_replicas_with_admission(
            &mut client,
            &mut target,
            ReplicationLimits::default(),
            &exclusions,
            || std::future::ready(true)
        ),
        old_reply,
    );
    assert!(matches!(received, Err(ProviderError::Protocol)));
}
