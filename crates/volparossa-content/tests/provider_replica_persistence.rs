//! Restart proof for storage-only replicas; no peer-selected key becomes consumer authority.

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use tokio::io::duplex;
use volparossa_content::provider::replication::{
    Replica, ReplicationExclusions, ReplicationLimits, persist_replicas,
    pull_replicas_with_admission, restore_replicas,
};
use volparossa_content::provider::{PublicationRegistry, pull_publication, serve_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, Error, Metadata, Publication, Validity,
    VerifiedManifest, publish, reassemble,
};

const JOURNAL: &str = ".volparossa-replicas-v1";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 4,
        min_free_bytes: 0,
    }
}

struct Fixture {
    publisher_directory: TempDir,
    registry: PublicationRegistry,
    trusted: VerifiedManifest,
    other: VerifiedManifest,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let publisher_directory = tempfile::tempdir().unwrap();
        let root = publisher_directory.path().join("publisher");
        let mut store = ChunkStore::create(&root, limits()).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let mut bytes = vec![7; CHUNK_BYTES];
        bytes.extend_from_slice(&vec![9; CHUNK_BYTES]);
        let mut registry = PublicationRegistry::new();
        let mut manifests = Vec::new();
        for input in [bytes.as_slice(), b"other retained publication"] {
            let created = now();
            let manifest = publish(
                &mut &input[..],
                Publication {
                    metadata: Metadata {
                        name: "restart object".into(),
                        revision: 1,
                        content_type: "application/octet-stream".into(),
                    },
                    length: input.len() as u64,
                    validity: Validity {
                        created,
                        expires: created + 600,
                    },
                },
                &key,
                &mut store,
            )
            .unwrap();
            manifests.push(manifest);
        }
        drop(store);
        let trusted = manifests[0].verify(&key.verifying_key(), now()).unwrap();
        let other = manifests[1].verify(&key.verifying_key(), now()).unwrap();
        for manifest in manifests {
            registry
                .register_shareable(
                    manifest,
                    &key.verifying_key(),
                    root.clone(),
                    limits(),
                    now(),
                )
                .unwrap();
        }
        // Only independently established public authority remains; no signing key is retained.
        drop(key);
        Self {
            publisher_directory,
            registry,
            trusted,
            other,
            bytes,
        }
    }

    async fn take(
        &self,
        store: &mut ChunkStore,
        excluded: [u8; 32],
        chunks: Vec<ChunkId>,
    ) -> Replica {
        let (mut client, mut server) = duplex(4096);
        let exclusions = ReplicationExclusions {
            manifest_ids: vec![excluded],
            chunk_ids: chunks,
        };
        let (received, sent) = tokio::join!(
            pull_replicas_with_admission(
                &mut client,
                store,
                ReplicationLimits {
                    max_chunks: 1,
                    ..Default::default()
                },
                &exclusions,
                || async { true }
            ),
            serve_publication(&mut server, &self.registry, TransferLimits::default()),
        );
        sent.unwrap();
        let mut received = received.unwrap();
        assert_eq!(received.chunks, 1);
        assert_eq!(received.replicas.len(), 1);
        received.replicas.remove(0)
    }
}

#[tokio::test]
async fn reopened_union_re_serves_after_publisher_removal_without_renewing_authority() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("mirror");
    let mut store = ChunkStore::create(&root, limits()).unwrap();
    assert!(restore_replicas(&mut store, now()).unwrap().is_empty());
    let other = fixture
        .take(&mut store, *fixture.trusted.manifest_id(), vec![])
        .await;
    persist_replicas(&mut store, &[other], now()).unwrap();
    let first = fixture
        .take(&mut store, *fixture.other.manifest_id(), vec![])
        .await;
    persist_replicas(&mut store, std::slice::from_ref(&first), now()).unwrap();
    let second = fixture
        .take(
            &mut store,
            *fixture.other.manifest_id(),
            first.chunk_ids().to_vec(),
        )
        .await;
    persist_replicas(&mut store, &[second], now()).unwrap();
    let usage = store.usage();
    drop(store);
    let Fixture {
        publisher_directory,
        registry,
        trusted,
        other: _,
        bytes,
    } = fixture;
    drop(registry);
    let original_path = publisher_directory.path().to_owned();
    publisher_directory.close().unwrap();
    assert!(!original_path.exists());

    let mut restarted = ChunkStore::open(&root, limits()).unwrap();
    assert_eq!(restarted.usage(), usage);
    let restored = restore_replicas(&mut restarted, now()).unwrap();
    assert_eq!(restored.len(), 2); // Earlier different publication was not overwritten.
    let merged = restored
        .iter()
        .find(|r| r.manifest_id() == trusted.manifest_id())
        .unwrap();
    assert_eq!(merged.chunk_ids().len(), 2); // Later same-manifest chunks were unioned.
    assert_eq!(merged.validity(), trusted.validity());
    assert_eq!(merged.hops(), 1);
    drop(restarted);
    let mut provider = PublicationRegistry::new();
    for replica in restored {
        provider
            .register_replica(replica, root.clone(), limits(), now())
            .unwrap();
    }
    let mut consumer = ChunkStore::create(&directory.path().join("consumer"), limits()).unwrap();
    let (mut client, mut server) = duplex(4096);
    let (received, sent) = tokio::join!(
        pull_publication(
            &mut client,
            &trusted,
            &mut consumer,
            TransferLimits::default()
        ),
        serve_publication(&mut server, &provider, TransferLimits::default()),
    );
    assert_eq!(received.unwrap().bytes, bytes.len() as u64);
    assert_eq!(sent.unwrap().chunks, 2);
    let mut output = Vec::new();
    reassemble(&trusted, &mut [&mut consumer], now(), &mut output).unwrap();
    assert_eq!(output, bytes);
    let mut restarted = ChunkStore::open(&root, limits()).unwrap();
    assert!(
        restore_replicas(&mut restarted, trusted.validity().expires + 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(restarted.usage(), usage); // Expiry removes no payload and grants no new lifetime.
}

async fn journaled_fixture() -> (TempDir, PathBuf, Replica) {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("mirror");
    let mut store = ChunkStore::create(&root, limits()).unwrap();
    let replica = fixture
        .take(&mut store, *fixture.other.manifest_id(), vec![])
        .await;
    persist_replicas(&mut store, std::slice::from_ref(&replica), now()).unwrap();
    (directory, root, replica)
}

#[tokio::test]
async fn foreign_journal_corruption_and_busy_cache_are_rejected_without_cleanup() {
    let (directory, root, _) = journaled_fixture().await;
    let original = fs::read(root.join(JOURNAL)).unwrap();
    let mut store = ChunkStore::open(&root, limits()).unwrap();
    assert!(ChunkStore::open(&root, limits()).is_err());
    let foreign_root = directory.path().join("foreign");
    let mut foreign = ChunkStore::create(&foreign_root, limits()).unwrap();
    fs::copy(root.join(JOURNAL), foreign_root.join(JOURNAL)).unwrap();
    assert!(matches!(
        restore_replicas(&mut foreign, now()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(fs::read(foreign_root.join(JOURNAL)).unwrap(), original);
    let mut corrupt = original;
    corrupt[45] ^= 1;
    fs::write(root.join(JOURNAL), &corrupt).unwrap();
    assert!(matches!(
        restore_replicas(&mut store, now()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(fs::read(root.join(JOURNAL)).unwrap(), corrupt);
}

#[tokio::test]
async fn absent_or_corrupt_live_chunk_cannot_restore_or_register() {
    let (_directory, root, replica) = journaled_fixture().await;
    let path = root.join(replica.chunk_ids()[0].to_string());
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    let mut store = ChunkStore::open(&root, limits()).unwrap();
    assert!(matches!(
        restore_replicas(&mut store, now()),
        Err(Error::Integrity(_))
    ));
    drop(store);
    fs::remove_file(&path).unwrap();
    assert!(ChunkStore::open(&root, limits()).is_err());
    assert!(root.join(JOURNAL).exists());
    assert!(
        PublicationRegistry::new()
            .register_replica(replica, root, limits(), now())
            .is_err()
    );
}
