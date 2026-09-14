//! Real v3 uptake before/after explicit library-clock expiry; not wall-clock or VM evidence.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use volparossa_content::mailbox::store::MailboxStore;
use volparossa_content::provider::replication::{
    ReplicationExclusions, ReplicationLimits, ReplicationProgress, persist_replicas,
    pull_replicas_with_admission, restore_replicas,
};
use volparossa_content::provider::{ProviderError, PublicationRegistry, serve_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, CacheUsage, ChunkId, ChunkStore, Error, Metadata, Publication,
    SignedManifest, Validity, publish,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn limits(entries: usize) -> CacheLimits {
    CacheLimits {
        max_bytes: u64::try_from(entries * CHUNK_BYTES).unwrap(),
        max_entries: entries,
        min_free_bytes: 0,
    }
}

fn publish_object(
    store: &mut ChunkStore,
    key: &SigningKey,
    name: &str,
    bytes: &[u8],
    validity: Validity,
) -> SignedManifest {
    publish(
        &mut &bytes[..],
        Publication {
            metadata: Metadata {
                name: name.into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: u64::try_from(bytes.len()).unwrap(),
            validity,
        },
        key,
        store,
    )
    .unwrap()
}

fn provider(signed: SignedManifest, key: &SigningKey, root: &Path, at: u64) -> PublicationRegistry {
    let mut registry = PublicationRegistry::new();
    registry
        .register_shareable(signed, &key.verifying_key(), root.to_owned(), limits(4), at)
        .unwrap();
    registry
}

async fn uptake(
    registry: &PublicationRegistry,
    store: &mut ChunkStore,
) -> Result<ReplicationProgress, ProviderError> {
    let (mut client, mut server) = duplex(4096);
    let (received, sent) = tokio::join!(
        async move {
            pull_replicas_with_admission(
                &mut client,
                store,
                ReplicationLimits::default(),
                &ReplicationExclusions::default(),
                || async { true },
            )
            .await
        },
        async move { serve_publication(&mut server, registry, TransferLimits::default()).await },
    );
    // A rejected admission closes its owned client stream; successful uptake must also finish
    // the actual provider protocol, not merely report locally inserted bytes.
    if received.is_ok() {
        assert!(sent.is_ok());
    }
    received
}

struct Sources {
    expired: SignedManifest,
    live: SignedManifest,
    foreground: SignedManifest,
    next: SignedManifest,
    shared: Vec<u8>,
    obsolete: Vec<u8>,
    foreground_bytes: Vec<u8>,
    next_bytes: Vec<u8>,
}

impl Sources {
    fn new(root: &Path, key: &SigningKey, at: u64) -> Self {
        let mut source = ChunkStore::create(root, limits(4)).unwrap();
        let shared = vec![1; CHUNK_BYTES];
        let obsolete = vec![2; CHUNK_BYTES];
        let foreground_bytes = vec![3; CHUNK_BYTES];
        let next_bytes = vec![4; CHUNK_BYTES];
        let short = Validity {
            created: at,
            expires: at + 60,
        };
        let long = Validity {
            created: at,
            expires: at + 600,
        };
        let expired = publish_object(
            &mut source,
            key,
            "expired replica",
            &[shared.clone(), obsolete.clone(), foreground_bytes.clone()].concat(),
            short,
        );
        let live = publish_object(&mut source, key, "live shared hash", &shared, long);
        // Even an expired explicit foreground registration must not be mistaken for a replica.
        let foreground = publish_object(
            &mut source,
            key,
            "explicit foreground",
            &foreground_bytes,
            short,
        );
        let next = publish_object(&mut source, key, "next uptake", &next_bytes, long);
        Self {
            expired,
            live,
            foreground,
            next,
            shared,
            obsolete,
            foreground_bytes,
            next_bytes,
        }
    }
}

#[tokio::test]
async fn full_replica_cache_reclaims_only_expired_unshared_chunks_then_accepts_real_uptake() {
    let directory = tempfile::tempdir().unwrap();
    let source_root = directory.path().join("source");
    let root = directory.path().join("replica");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let at = now();
    let sources = Sources::new(&source_root, &key, at);
    let mut cache = ChunkStore::create(&root, limits(3)).unwrap();
    let expired = uptake(
        &provider(sources.expired.clone(), &key, &source_root, at),
        &mut cache,
    )
    .await
    .unwrap();
    assert_eq!(expired.chunks, 3);
    assert_eq!(expired.bytes, limits(3).max_bytes);
    persist_replicas(&mut cache, &expired.replicas, at).unwrap();
    let live = uptake(
        &provider(sources.live.clone(), &key, &source_root, at),
        &mut cache,
    )
    .await
    .unwrap();
    assert_eq!((live.chunks, live.bytes, live.replicas.len()), (0, 0, 1));
    persist_replicas(&mut cache, &live.replicas, at).unwrap();
    let new_provider = provider(sources.next.clone(), &key, &source_root, at);
    assert!(matches!(
        uptake(&new_provider, &mut cache).await,
        Err(ProviderError::Content(Error::Quota))
    ));
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: limits(3).max_bytes,
            entries: 3
        }
    );
    // A late uptake/persistence pass must not erase expired ownership before reclamation.
    // Only the explicit library clock advances; no wall-clock expiry is claimed here.
    persist_replicas(&mut cache, &[], at + 61).unwrap();
    drop(cache);

    let mut registry = PublicationRegistry::new();
    for replica in expired.replicas.iter().chain(&live.replicas) {
        registry
            .register_replica(replica.clone(), root.clone(), limits(3), at)
            .unwrap();
    }
    registry
        .register_signed(
            sources.foreground.clone(),
            &key.verifying_key(),
            root.clone(),
            limits(3),
            at,
        )
        .unwrap();
    let orphan = ChunkId::digest(b"unindexed owner data");
    fs::write(root.join(orphan.to_string()), b"unindexed owner data").unwrap();

    // Maintenance/persistence receive explicit advanced time; real duplex peers keep their clock.
    // This proves library expiry selection, not that sixty seconds elapsed in a runtime/VM.
    let later = at + 61;
    let reclaimed = registry
        .reclaim_replica_cache(&root, limits(3), later)
        .unwrap();
    assert_eq!(
        reclaimed.expired_manifest_ids,
        vec![*expired.replicas[0].manifest_id()]
    );
    assert_eq!(
        reclaimed.removed_chunks,
        vec![ChunkId::digest(&sources.obsolete)]
    );
    assert_eq!(
        reclaimed.usage,
        CacheUsage {
            bytes: limits(2).max_bytes,
            entries: 2
        }
    );
    assert_eq!(reclaimed.live.len(), 1);
    assert_eq!(reclaimed.live[0].validity(), live.replicas[0].validity());
    assert!(!registry.contains(expired.replicas[0].manifest_id()));
    assert!(registry.contains(live.replicas[0].manifest_id()));
    let foreground = sources.foreground.verify(&key.verifying_key(), at).unwrap();
    assert!(registry.contains(foreground.manifest_id()));

    use_reclaimed_capacity(&root, &new_provider, &sources, orphan, later).await;
    let again = registry
        .reclaim_replica_cache(&root, limits(3), later)
        .unwrap();
    assert!(again.removed_chunks.is_empty());
    assert!(again.expired_manifest_ids.is_empty());
    assert_eq!(again.usage.entries, 3);
}

async fn use_reclaimed_capacity(
    root: &Path,
    new_provider: &PublicationRegistry,
    sources: &Sources,
    orphan: ChunkId,
    later: u64,
) {
    let mut cache = ChunkStore::open(root, limits(3)).unwrap();
    assert_eq!(
        cache
            .get(&ChunkId::digest(&sources.shared))
            .unwrap()
            .unwrap(),
        sources.shared
    );
    assert_eq!(
        cache
            .get(&ChunkId::digest(&sources.foreground_bytes))
            .unwrap()
            .unwrap(),
        sources.foreground_bytes
    );
    assert!(
        cache
            .get(&ChunkId::digest(&sources.obsolete))
            .unwrap()
            .is_none()
    );
    assert!(cache.get(&orphan).unwrap().is_none());
    assert_eq!(
        fs::read(root.join(orphan.to_string())).unwrap(),
        b"unindexed owner data"
    );
    assert_eq!(restore_replicas(&mut cache, later).unwrap().len(), 1);
    let fresh = uptake(new_provider, &mut cache).await.unwrap();
    assert_eq!((fresh.chunks, fresh.bytes), (1, limits(1).max_bytes));
    assert_eq!(
        cache
            .get(&ChunkId::digest(&sources.next_bytes))
            .unwrap()
            .unwrap(),
        sources.next_bytes
    );
    persist_replicas(&mut cache, &fresh.replicas, later).unwrap();
    drop(cache);
    let mut reopened = ChunkStore::open(root, limits(3)).unwrap();
    assert_eq!(
        reopened.usage(),
        CacheUsage {
            bytes: limits(3).max_bytes,
            entries: 3
        }
    );
    assert_eq!(restore_replicas(&mut reopened, later).unwrap().len(), 2);
}

#[test]
fn stopped_mailbox_cache_is_refused_without_touching_its_durable_journal() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("mailbox");
    let at = now();
    let mailbox = MailboxStore::create(&root, limits(3), at).unwrap();
    let usage = mailbox.usage();
    drop(mailbox);
    let journal = root.join(".volparossa-mailbox-v1");
    let before = fs::read(&journal).unwrap();
    let mut registry = PublicationRegistry::new();
    assert!(matches!(
        registry.reclaim_replica_cache(&root, limits(3), at + 61),
        Err(ProviderError::Content(Error::Limit(
            "mailbox cache is not opportunistic replica storage"
        )))
    ));
    assert_eq!(fs::read(&journal).unwrap(), before);
    assert_eq!(
        MailboxStore::open(&root, limits(3), at + 61)
            .unwrap()
            .usage(),
        usage
    );
    assert!(!root.join(".volparossa-replicas-v1").exists());
}
