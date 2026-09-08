//! Local public-download admission and real provider protocol, without a host socket.

use super::*;
use ed25519_dalek::SigningKey;
use volparossa_content::provider::{pull_publication, serve_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{CHUNK_BYTES, Metadata, Publication, Validity, publish, reassemble};
use volparossa_identity::Identity;

pub(super) fn fixture(
    root: &std::path::Path,
) -> (Arc<ContributionRuntime>, PublicationRegistry, CacheLimits) {
    let config = ContentContributionConfig {
        enabled: true,
        cache: root.to_string_lossy().into_owned(),
        quota_bytes: 1024 * 1024,
        max_entries: 8,
        min_free_bytes: 0,
        ..ContentContributionConfig::default()
    };
    let mut registry = PublicationRegistry::new();
    registry.set_name_lookup(true);
    let replication =
        ReplicationRuntime::create_public(replication_config(&config).unwrap(), &mut registry)
            .unwrap();
    let limits = CacheLimits {
        max_bytes: config.quota_bytes,
        max_entries: 8,
        min_free_bytes: 0,
    };
    (
        Arc::new(ContributionRuntime {
            config,
            replication,
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            worker: Mutex::new(None),
        }),
        registry,
        limits,
    )
}

pub(super) fn publication(
    store: &mut ChunkStore,
    key: &SigningKey,
    mut payload: &[u8],
    kind: &str,
) -> SignedManifest {
    let length = payload.len() as u64;
    publish(
        &mut payload,
        Publication {
            metadata: Metadata {
                name: "public-contribution".into(),
                revision: 1,
                content_type: kind.into(),
            },
            length,
            validity: Validity {
                created: now(),
                expires: now() + 300,
            },
        },
        key,
        store,
    )
    .unwrap()
}

#[tokio::test]
async fn automatic_public_admission_restores_and_serves_without_explicit_registration() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("download");
    let contribution_root = temporary.path().join("contribution");
    let (contributor, registry, limits) = fixture(&contribution_root);
    assert!(
        !registry.has_live_publications(now()),
        "an empty service cannot advertise useful content"
    );
    let mut source = ChunkStore::create(&source_root, limits).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let mut payload = vec![37; CHUNK_BYTES];
    payload.extend_from_slice(b"last verified bytes");
    let envelope = publication(&mut source, &key, &payload, "application/octet-stream");
    let authorized = envelope.verify(&key.verifying_key(), now()).unwrap();
    drop(source);
    let runtime = ContentRuntime::new(&Identity::generate()).unwrap();
    *runtime.contribution.lock().await = Some(Arc::clone(&contributor));
    runtime
        .contribute_native(envelope, authorized.clone(), source_root, limits)
        .await;
    let pending = contributor.queue.lock().await.pop_front().unwrap();
    let slot = contributor.replication.try_background_slot().unwrap();
    assert!(
        contributor.replication.try_background_slot().is_none(),
        "extra network work shares the same slot"
    );
    assert_eq!(
        contributor.copy_one(&pending, 1024 * 1024).unwrap(),
        Some(CHUNK_BYTES as u64)
    );
    assert_eq!(
        contributor.copy_one(&pending, 1024 * 1024).unwrap(),
        Some(19)
    );
    assert_eq!(contributor.copy_one(&pending, 1024 * 1024).unwrap(), None);
    drop(slot);
    // Reopening restores only durable admission, with no manual register/Serve call.
    let (reopened, registry, _) = fixture(&contribution_root);
    assert!(registry.has_live_publications(now()));
    let mut destination = ChunkStore::create(&temporary.path().join("consumer"), limits).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let (received, sent) = tokio::join!(
        pull_publication(
            &mut client,
            &authorized,
            &mut destination,
            TransferLimits::default()
        ),
        serve_publication(&mut server, &registry, TransferLimits::default()),
    );
    assert_eq!(received.unwrap(), sent.unwrap());
    let mut actual = Vec::new();
    reassemble(&authorized, &mut [&mut destination], now(), &mut actual).unwrap();
    assert_eq!(actual, payload);
    assert!(reopened.replication.try_background_slot().is_some());
    assert!(!registry.has_live_publications(authorized.validity().expires));
}

#[tokio::test]
async fn automatic_contribution_rejects_private_and_does_not_renew_queued_admission() {
    let temporary = tempfile::tempdir().unwrap();
    let (contributor, _, limits) = fixture(&temporary.path().join("contribution"));
    let source_root = temporary.path().join("download");
    let mut source = ChunkStore::create(&source_root, limits).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let runtime = ContentRuntime::new(&Identity::generate()).unwrap();
    *runtime.contribution.lock().await = Some(Arc::clone(&contributor));
    for kind in [PRIVATE_MESSAGE_CONTENT_TYPE, "application/octet-stream"] {
        let envelope = publication(&mut source, &key, b"verified local data", kind);
        let authorized = envelope.verify(&key.verifying_key(), now()).unwrap();
        runtime
            .contribute_native(
                envelope.clone(),
                authorized.clone(),
                source_root.clone(),
                limits,
            )
            .await;
        if kind == PRIVATE_MESSAGE_CONTENT_TYPE {
            assert!(contributor.queue.lock().await.is_empty());
        } else {
            let original = contributor.queue.lock().await[0].deadline;
            runtime
                .contribute_native(envelope, authorized, source_root.clone(), limits)
                .await;
            assert_eq!(contributor.queue.lock().await.len(), 1);
            assert_eq!(contributor.queue.lock().await[0].deadline, original);
        }
    }
    drop(source);
    let mut expired = contributor.queue.lock().await.pop_front().unwrap();
    expired.expires = now();
    assert_eq!(contributor.copy_one(&expired, 1024 * 1024).unwrap(), None);
    assert_eq!(
        ChunkStore::open(&PathBuf::from(&contributor.config.cache), limits)
            .unwrap()
            .usage()
            .entries,
        0
    );
}

#[tokio::test]
async fn automatic_restore_never_promotes_legacy_private_journal() {
    use volparossa_content::provider::replication::{
        ReplicationExclusions, ReplicationLimits, persist_replicas, pull_replicas,
    };
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("explicit-source");
    let cache_root = temporary.path().join("explicit-replicas");
    let limits = CacheLimits {
        max_bytes: 1024 * 1024,
        max_entries: 8,
        min_free_bytes: 0,
    };
    let mut source = ChunkStore::create(&source_root, limits).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let envelope = publication(
        &mut source,
        &key,
        b"private-sentinel-fixture",
        PRIVATE_MESSAGE_CONTENT_TYPE,
    );
    drop(source);
    let mut original = PublicationRegistry::new();
    original
        .register_shareable(envelope, &key.verifying_key(), source_root, limits, now())
        .unwrap();
    let mut cache = ChunkStore::create(&cache_root, limits).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let exclusions = ReplicationExclusions::default();
    let (received, sent) = tokio::join!(
        pull_replicas(
            &mut client,
            &mut cache,
            ReplicationLimits::default(),
            &exclusions
        ),
        serve_publication(&mut server, &original, TransferLimits::default()),
    );
    sent.unwrap();
    persist_replicas(&mut cache, &received.unwrap().replicas, now()).unwrap();
    drop(cache);
    let (automatic, registry, _) = fixture(&cache_root);
    assert!(!registry.has_live_publications(now()));
    let registry = Mutex::new(registry);
    automatic
        .replication
        .reclaim(&registry, now())
        .await
        .unwrap();
    assert!(!registry.lock().await.has_live_publications(now()));
    assert_eq!(
        ChunkStore::open(&cache_root, limits)
            .unwrap()
            .usage()
            .entries,
        1,
        "filtering may not delete explicitly retained private ciphertext"
    );
}
