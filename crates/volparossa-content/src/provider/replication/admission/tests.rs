//! Actual owned-store copies and reopen; explicit library-clock expiry, not elapsed VM time.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use super::*;
use crate::{
    CHUNK_BYTES, CacheLimits, Metadata, Publication, Validity,
    mailbox::store::MailboxStore,
    provider::PublicationRegistry,
    provider::replication::{persist_replicas, restore_replicas},
    publish,
};

const AT: u64 = 1_800_000_000;

struct Fixture {
    directory: tempfile::TempDir,
    key: SigningKey,
    source: ChunkStore,
    destination: ChunkStore,
    destination_root: PathBuf,
    destination_limits: CacheLimits,
    signed: SignedManifest,
    checked: VerifiedManifest,
    foreground: crate::ChunkId,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let mut source = ChunkStore::create(&directory.path().join("source"), limits(8)).unwrap();
        let bytes = [11_u8, 29, 71]
            .into_iter()
            .flat_map(|byte| vec![byte; CHUNK_BYTES])
            .collect::<Vec<_>>();
        let signed = publication(&mut source, &key, &bytes, "application/octet-stream");
        let checked = signed.verify(&key.verifying_key(), AT).unwrap();
        let destination_root = directory.path().join("contribution");
        let destination_limits = CacheLimits {
            max_bytes: 2 * CHUNK_BYTES as u64 + 17,
            max_entries: 3,
            min_free_bytes: 0,
        };
        let mut destination = ChunkStore::create(&destination_root, destination_limits).unwrap();
        let foreground = crate::ChunkId::digest(&[91; 17]);
        destination.put_verified(foreground, &[91; 17]).unwrap();
        Self {
            directory,
            key,
            source,
            destination,
            destination_root,
            destination_limits,
            signed,
            checked,
            foreground,
        }
    }

    fn admit(&mut self, limits: LocalReplicaLimits) -> ReplicationProgress {
        admit_public_replica(
            &self.signed,
            &self.checked,
            &mut self.source,
            &mut self.destination,
            limits,
            AT,
        )
        .unwrap()
    }

    fn reject_private_and_mailbox(&mut self) {
        let private = publication(
            &mut self.source,
            &self.key,
            b"opaque ciphertext",
            PRIVATE_MESSAGE_CONTENT_TYPE,
        );
        let authorized = private.verify(&self.key.verifying_key(), AT).unwrap();
        assert!(
            admit_public_replica(
                &private,
                &authorized,
                &mut self.source,
                &mut self.destination,
                LocalReplicaLimits::default(),
                AT
            )
            .is_err()
        );
        let other = publication(
            &mut self.source,
            &self.key,
            b"different public object",
            "application/octet-stream",
        );
        assert!(
            admit_public_replica(
                &other,
                &self.checked,
                &mut self.source,
                &mut self.destination,
                LocalReplicaLimits::default(),
                AT
            )
            .is_err()
        );
        let mailbox_root = self.directory.path().join("mailbox");
        drop(MailboxStore::create(&mailbox_root, limits(8), AT).unwrap());
        let mut mailbox = ChunkStore::open(&mailbox_root, limits(8)).unwrap();
        assert!(restore_public_replicas(&mut mailbox, AT).is_err());
        assert!(
            admit_public_replica(
                &self.signed,
                &self.checked,
                &mut self.source,
                &mut mailbox,
                LocalReplicaLimits::default(),
                AT
            )
            .is_err()
        );
        assert!(
            admit_public_replica(
                &self.signed,
                &self.checked,
                &mut mailbox,
                &mut self.destination,
                LocalReplicaLimits::default(),
                AT
            )
            .is_err()
        );
        assert_eq!(mailbox.usage().bytes, 0);
    }
}

fn limits(entries: usize) -> CacheLimits {
    CacheLimits {
        max_bytes: u64::try_from(entries * CHUNK_BYTES).unwrap(),
        max_entries: entries,
        min_free_bytes: 0,
    }
}

fn publication(
    store: &mut ChunkStore,
    key: &SigningKey,
    bytes: &[u8],
    content_type: &str,
) -> SignedManifest {
    publication_at(store, key, bytes, content_type, AT)
}

fn publication_at(
    store: &mut ChunkStore,
    key: &SigningKey,
    bytes: &[u8],
    content_type: &str,
    at: u64,
) -> SignedManifest {
    let mut input = bytes;
    publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: "received-publication".into(),
                content_type: content_type.into(),
                revision: 1,
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 60,
            },
        },
        key,
        store,
    )
    .unwrap()
}

#[test]
fn local_public_admission_copies_incrementally_reopens_without_eviction_or_expiry_renewal() {
    let mut fixture = Fixture::new();
    fixture.reject_private_and_mailbox();
    let first = fixture.admit(LocalReplicaLimits {
        max_chunks: 1,
        max_bytes: CHUNK_BYTES as u64,
    });
    assert_eq!(
        (first.bytes, first.chunks, first.wire_bytes),
        (CHUNK_BYTES as u64, 1, 0)
    );
    assert_eq!(first.replicas.len(), 1);
    assert_eq!(
        first.replicas[0].signed_manifest().encode(),
        fixture.signed.encode()
    );
    assert_eq!(first.replicas[0].validity(), fixture.checked.validity());
    assert_eq!(first.replicas[0].hops(), 1);
    // This is a retained local metadata bound, not a claim of seven actual network hops.
    let mut retained = first.replicas[0].clone();
    retained.hops = 7;
    persist_replicas(&mut fixture.destination, &[retained], AT).unwrap();
    let second = fixture.admit(LocalReplicaLimits::default());
    assert_eq!(
        (second.bytes, second.chunks, second.wire_bytes),
        (CHUNK_BYTES as u64, 1, 0)
    );
    assert_eq!(second.replicas[0].hops(), 7);
    assert_eq!(second.replicas[0].chunk_ids().len(), 2);
    let full = fixture.admit(LocalReplicaLimits::default());
    assert!(full.replicas.is_empty());
    assert_eq!((full.bytes, full.chunks), (0, 0));
    assert_eq!(
        fixture
            .destination
            .get(&fixture.foreground)
            .unwrap()
            .unwrap(),
        [91; 17]
    );
    assert!(
        fixture
            .destination
            .get(fixture.checked.chunks()[2].id())
            .unwrap()
            .is_none()
    );
    assert_reopened_and_expired(fixture);
}

fn assert_reopened_and_expired(fixture: Fixture) {
    let Fixture {
        directory: _directory,
        mut source,
        destination,
        destination_root,
        destination_limits,
        signed,
        checked,
        foreground,
        ..
    } = fixture;
    drop(destination);
    let mut destination = ChunkStore::open(&destination_root, destination_limits).unwrap();
    let mut restored = restore_public_replicas(&mut destination, AT).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].hops(), 7);
    assert_eq!(restored[0].chunk_ids().len(), 2);
    for chunk in checked.chunks().iter().take(2) {
        assert_eq!(
            destination.get(chunk.id()).unwrap().unwrap(),
            source.get(chunk.id()).unwrap().unwrap()
        );
    }
    assert!(
        admit_public_replica(
            &signed,
            &checked,
            &mut source,
            &mut destination,
            LocalReplicaLimits::default(),
            AT + 60
        )
        .is_err()
    );
    assert!(
        restore_replicas(&mut destination, AT + 60)
            .unwrap()
            .is_empty()
    );
    drop(destination);
    let mut registry = PublicationRegistry::new();
    assert!(!registry.has_mailbox());
    assert!(!registry.has_live_publications(AT));
    registry
        .register_replica(
            restored.remove(0),
            destination_root.clone(),
            destination_limits,
            AT,
        )
        .unwrap();
    assert!(registry.has_live_publications(AT));
    assert!(!registry.has_live_publications(AT + 60));
    let reclaimed = registry
        .reclaim_replica_cache(&destination_root, destination_limits, AT + 60)
        .unwrap();
    assert_eq!(reclaimed.removed_chunks.len(), 2);
    assert_eq!((reclaimed.usage.bytes, reclaimed.usage.entries), (17, 1));
    let mut destination = ChunkStore::open(&destination_root, destination_limits).unwrap();
    assert_eq!(destination.get(&foreground).unwrap().unwrap(), [91; 17]);
}

#[tokio::test]
async fn automatic_public_replication_rejects_private_before_store_and_preserves_explicit_v3() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for (private, public_only) in [(false, true), (true, true), (true, false)] {
            public_gate_exchange(private, public_only).await;
        }
    })
    .await
    .unwrap();
}

async fn public_gate_exchange(private: bool, public_only: bool) {
    use crate::provider::replication::{
        ReplicationExclusions, ReplicationLimits, pull_public_replicas_with_admission,
        pull_replicas_with_admission,
    };
    let directory = tempfile::tempdir().unwrap();
    let at = crate::provider::now().unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let source_root = directory.path().join("source");
    let mut source = ChunkStore::create(&source_root, limits(8)).unwrap();
    let content_type = if private {
        PRIVATE_MESSAGE_CONTENT_TYPE
    } else {
        "application/octet-stream"
    };
    let signed = publication_at(&mut source, &key, &[57; 123], content_type, at);
    drop(source);
    let mut registry = PublicationRegistry::new();
    registry
        .register_shareable(signed, &key.verifying_key(), source_root, limits(8), at)
        .unwrap();
    let mut destination =
        ChunkStore::create(&directory.path().join("destination"), limits(8)).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let (received, sent) = tokio::join!(
        async {
            let result = if public_only {
                pull_public_replicas_with_admission(
                    &mut client,
                    &mut destination,
                    ReplicationLimits::default(),
                    &ReplicationExclusions::default(),
                    || std::future::ready(true),
                )
                .await
            } else {
                pull_replicas_with_admission(
                    &mut client,
                    &mut destination,
                    ReplicationLimits::default(),
                    &ReplicationExclusions::default(),
                    || std::future::ready(true),
                )
                .await
            };
            drop(client);
            result
        },
        crate::provider::serve_publication(
            &mut server,
            &registry,
            crate::transfer::TransferLimits::default()
        )
    );
    if private && public_only {
        assert!(received.is_err());
        assert!(sent.is_err());
        assert_eq!(
            (destination.usage().bytes, destination.usage().entries),
            (0, 0)
        );
        assert!(restore_replicas(&mut destination, at).unwrap().is_empty());
    } else {
        let received = received.unwrap();
        assert_eq!(received.bytes, 123);
        assert_eq!(received.chunks, 1);
        assert!(received.wire_bytes > received.bytes);
        assert_eq!(sent.unwrap().bytes, 123);
        assert_eq!(destination.usage().bytes, 123);
        persist_replicas(&mut destination, &received.replicas, at).unwrap();
        assert_eq!(restore_replicas(&mut destination, at).unwrap().len(), 1);
        let public = restore_public_replicas(&mut destination, at).unwrap();
        assert_eq!(public.len(), usize::from(!private));
        assert_eq!(destination.usage().bytes, 123);
    }
}
