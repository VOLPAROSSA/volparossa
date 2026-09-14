//! Owned-store restart and protected-stream library proof, not a live overlay claim.

use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use tokio::io::duplex;

use super::*;
use crate::{
    CHUNK_BYTES, Metadata, Publication, Validity,
    mailbox::store::MailboxStore,
    provider::{
        named::{NameQuery, NameResolution, lookup_publication},
        pull_publication, serve_publication,
    },
    publish, reassemble,
    transfer::TransferLimits,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn limits(entries: usize) -> CacheLimits {
    CacheLimits {
        max_bytes: (entries * CHUNK_BYTES) as u64,
        max_entries: entries,
        min_free_bytes: 0,
    }
}

fn publication(
    source: &mut ChunkStore,
    publisher: &SigningKey,
    bytes: &[u8],
    content_type: &str,
    at: u64,
) -> (SignedManifest, VerifiedManifest) {
    let signed = publish(
        &mut &bytes[..],
        Publication {
            metadata: Metadata {
                name: "public-custody".into(),
                revision: 1,
                content_type: content_type.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 600,
            },
        },
        publisher,
        source,
    )
    .unwrap();
    let manifest = signed.verify(&publisher.verifying_key(), at).unwrap();
    (signed, manifest)
}

#[tokio::test]
async fn restarted_custody_serves_original_by_name_and_hash_after_source_is_gone() {
    let at = now();
    for bytes in [
        [7_u8, 13, 7]
            .into_iter()
            .flat_map(|byte| vec![byte; CHUNK_BYTES])
            .collect(),
        Vec::new(),
    ] {
        let source_directory = tempfile::tempdir().unwrap();
        let custody_directory = tempfile::tempdir().unwrap();
        let receiver_directory = tempfile::tempdir().unwrap();
        let mut source =
            ChunkStore::create(&source_directory.path().join("source"), limits(8)).unwrap();
        let root = custody_directory.path().join("custody");
        drop(ChunkStore::create(&root, limits(8)).unwrap());
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let (signed, manifest) =
            publication(&mut source, &key, &bytes, "application/octet-stream", at);
        let custody = PublicCustodyStore::open(root.clone(), limits(8)).unwrap();
        let replica = custody.admit(&signed, &manifest, &mut source, at).unwrap();
        assert_eq!(replica.signed_manifest().encode(), signed.encode());
        let usage = ChunkStore::open(&root, limits(8)).unwrap().usage();
        let repeated = custody
            .admit(&signed, &manifest, &mut source, at + 1)
            .unwrap();
        assert_eq!(repeated.validity(), manifest.validity());
        assert_eq!(repeated.hops(), replica.hops());
        assert_eq!(ChunkStore::open(&root, limits(8)).unwrap().usage(), usage);
        drop(source);
        source_directory.close().unwrap();
        drop(custody);

        let custody = PublicCustodyStore::open(root.clone(), limits(8)).unwrap();
        let restored = custody
            .inspect_complete(manifest.manifest_id(), at + 2)
            .unwrap()
            .unwrap();
        assert_eq!(restored.signed_manifest().encode(), signed.encode());
        assert_eq!(restored.validity(), manifest.validity());
        let mut registry = PublicationRegistry::new();
        registry.set_name_lookup(true);
        assert_eq!(custody.register_complete(&mut registry, at + 2).unwrap(), 1);
        assert_eq!(custody.register_complete(&mut registry, at + 2).unwrap(), 0);
        assert!(registry.contains_at(manifest.manifest_id(), &root));
        // Both the backend and registry remain alive: neither may retain the cache lock.
        let query = NameQuery::new(*manifest.publisher(), &manifest.metadata().name, 1).unwrap();
        let (mut client, mut server) = duplex(4096);
        let (candidate, name_response) = tokio::join!(
            lookup_publication(&mut client, &query, TransferLimits::default()),
            serve_publication(&mut server, &registry, TransferLimits::default()),
        );
        name_response.unwrap();
        let NameResolution::Candidate(candidate) = candidate.unwrap() else {
            panic!("complete original public name must be served after publisher removal");
        };
        assert_eq!(candidate.signed().encode(), signed.encode());
        let mut receiver =
            ChunkStore::create(&receiver_directory.path().join("receiver"), limits(8)).unwrap();
        let (mut client, mut server) = duplex(4096);
        let (download, upload) = tokio::join!(
            pull_publication(
                &mut client,
                &manifest,
                &mut receiver,
                TransferLimits::default()
            ),
            serve_publication(&mut server, &registry, TransferLimits::default()),
        );
        download.unwrap();
        upload.unwrap();
        let mut output = Vec::new();
        reassemble(&manifest, &mut [&mut receiver], at + 2, &mut output).unwrap();
        assert_eq!(output, bytes);
        assert!(
            custody
                .inspect_complete(manifest.manifest_id(), manifest.validity().expires)
                .unwrap()
                .is_none()
        );
        assert_eq!(ChunkStore::open(&root, limits(8)).unwrap().usage(), usage);
    }
}

#[test]
fn quota_refusal_keeps_prior_copy_and_never_promotes_a_durable_prefix() {
    for custody_limits in [
        limits(2),
        CacheLimits {
            max_bytes: (CHUNK_BYTES + b"retain this copy".len()) as u64,
            ..limits(8)
        },
    ] {
        quota_refusal(custody_limits);
    }
}

fn quota_refusal(custody_limits: CacheLimits) {
    let at = now();
    let directory = tempfile::tempdir().unwrap();
    let mut source = ChunkStore::create(&directory.path().join("source"), limits(8)).unwrap();
    let root = directory.path().join("custody");
    drop(ChunkStore::create(&root, custody_limits).unwrap());
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let (first, first_manifest) =
        publication(&mut source, &key, b"retain this copy", "text/plain", at);
    let bytes = [11_u8, 29]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let (second, second_manifest) =
        publication(&mut source, &key, &bytes, "application/octet-stream", at);
    let custody = PublicCustodyStore::open(root.clone(), custody_limits).unwrap();
    custody
        .admit(&first, &first_manifest, &mut source, at)
        .unwrap();
    assert!(matches!(
        custody.admit(&second, &second_manifest, &mut source, at),
        Err(ProviderError::Content(Error::Quota))
    ));
    drop(custody);
    let custody = PublicCustodyStore::open(root.clone(), custody_limits).unwrap();
    let mut store = ChunkStore::open(&root, custody_limits).unwrap();
    let records = restore_replicas(&mut store, at + 1).unwrap();
    assert_eq!(
        records.len(),
        2,
        "failed admission retains its verified journaled prefix"
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record.manifest_id() == second_manifest.manifest_id())
            .unwrap()
            .chunk_ids()
            .len(),
        1
    );
    let usage = store.usage();
    let mut output = Vec::new();
    reassemble(&first_manifest, &mut [&mut store], at + 1, &mut output).unwrap();
    assert_eq!(output, b"retain this copy");
    drop(store);
    assert!(
        custody
            .inspect_complete(second_manifest.manifest_id(), at + 1)
            .unwrap()
            .is_none()
    );
    let mut registry = PublicationRegistry::new();
    assert_eq!(custody.register_complete(&mut registry, at + 1).unwrap(), 1);
    assert!(registry.contains(first_manifest.manifest_id()));
    assert!(!registry.contains(second_manifest.manifest_id()));
    assert!(matches!(
        custody.admit(&second, &second_manifest, &mut source, at + 1),
        Err(ProviderError::Content(Error::Quota))
    ));
    assert_eq!(
        ChunkStore::open(&root, custody_limits).unwrap().usage(),
        usage
    );
}

#[test]
fn private_mailbox_and_corrupt_restarted_bytes_cannot_become_complete_custody() {
    let at = now();
    let directory = tempfile::tempdir().unwrap();
    let mut source = ChunkStore::create(&directory.path().join("source"), limits(8)).unwrap();
    let root = directory.path().join("custody");
    drop(ChunkStore::create(&root, limits(8)).unwrap());
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let (private, private_manifest) = publication(
        &mut source,
        &key,
        b"ciphertext",
        PRIVATE_MESSAGE_CONTENT_TYPE,
        at,
    );
    let (public, public_manifest) = publication(
        &mut source,
        &key,
        b"original public content",
        "text/plain",
        at,
    );
    let custody = PublicCustodyStore::open(root.clone(), limits(8)).unwrap();
    assert!(
        custody
            .admit(&private, &private_manifest, &mut source, at)
            .is_err()
    );
    assert!(
        custody
            .admit(&private, &public_manifest, &mut source, at)
            .is_err()
    );
    assert!(custody.restore_complete(at).unwrap().is_empty());
    let mailbox = directory.path().join("mailbox");
    drop(MailboxStore::create(&mailbox, limits(8), at).unwrap());
    assert!(PublicCustodyStore::open(mailbox.clone(), limits(8)).is_err());
    let mut mailbox_source = ChunkStore::open(&mailbox, limits(8)).unwrap();
    assert!(
        custody
            .admit(&public, &public_manifest, &mut mailbox_source, at)
            .is_err()
    );
    custody
        .admit(&public, &public_manifest, &mut source, at)
        .unwrap();
    drop(custody);
    // Same-length corruption passes the structural reopen, but must fail actual SHA verification.
    let chunk = &public_manifest.chunks()[0];
    fs::write(
        root.join(chunk.id().to_string()),
        vec![0; chunk.length() as usize],
    )
    .unwrap();
    let custody = PublicCustodyStore::open(root, limits(8)).unwrap();
    assert!(matches!(
        custody.inspect_complete(public_manifest.manifest_id(), at + 1),
        Err(ProviderError::Content(Error::Integrity(_)))
    ));
    let mut registry = PublicationRegistry::new();
    assert!(custody.register_complete(&mut registry, at + 1).is_err());
    assert!(registry.is_empty());
}
