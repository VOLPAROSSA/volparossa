//! Real bounded provider streams and owned-cache floors; not an overlay/network acceptance claim.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Error, Metadata, Publication, SignedManifest, Validity,
    provider::{
        PublicationRegistry,
        named::{NameQuery, NameResolution, lookup_publication},
        pull_publication, serve_publication,
    },
    publish, reassemble_to_file,
    transfer::TransferLimits,
};

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

fn sign(
    key: &SigningKey,
    source: &mut ChunkStore,
    name: &str,
    revision: u64,
    validity: Validity,
    bytes: &[u8],
) -> SignedManifest {
    let mut input = bytes;
    publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: name.into(),
                revision,
                content_type: "text/html".into(),
            },
            length: bytes.len() as u64,
            validity,
        },
        key,
        source,
    )
    .unwrap()
}

async fn lookup(registry: &PublicationRegistry, query: &NameQuery) -> NameResolution {
    let (mut client, mut server) = duplex(1024);
    let (resolved, sent) = tokio::join!(
        lookup_publication(&mut client, query, TransferLimits::default()),
        serve_publication(&mut server, registry, TransferLimits::default()),
    );
    assert_eq!(
        sent.unwrap().bytes,
        0,
        "metadata is not a chunk delivery claim"
    );
    resolved.unwrap()
}

fn partial_registry(
    root: &Path,
    index: usize,
    source: &mut ChunkStore,
    signed: &SignedManifest,
    key: &SigningKey,
) -> PublicationRegistry {
    let cache_root = root.join(format!("replica-{index}"));
    let mut cache = ChunkStore::create(&cache_root, limits()).unwrap();
    let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
    for (position, chunk) in manifest.chunks().iter().enumerate() {
        if position % 2 == index {
            cache
                .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
                .unwrap();
        }
    }
    drop(cache);
    let mut registry = PublicationRegistry::new();
    registry
        .register_signed(
            signed.clone(),
            &key.verifying_key(),
            cache_root,
            limits(),
            now(),
        )
        .unwrap();
    registry
}

#[tokio::test]
async fn named_two_partial_providers_reconstruct_without_the_publisher_or_manifest_file() {
    let directory = tempfile::tempdir().unwrap();
    let original = tempfile::tempdir_in(directory.path()).unwrap();
    let mut source = ChunkStore::create(&original.path().join("source"), limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let trusted = key.verifying_key().to_bytes();
    let mut bytes = vec![0x31; CHUNK_BYTES];
    bytes.extend(vec![0x62; CHUNK_BYTES]);
    bytes.extend(b"<html>original publisher offline</html>");
    let signed = sign(
        &key,
        &mut source,
        "site/index",
        7,
        Validity {
            created: now(),
            expires: now() + 300,
        },
        &bytes,
    );
    let mut registries = [
        partial_registry(directory.path(), 0, &mut source, &signed, &key),
        partial_registry(directory.path(), 1, &mut source, &signed, &key),
    ];
    let query = NameQuery::new(trusted, "site/index", 0).unwrap();
    assert!(matches!(
        lookup(&registries[0], &query).await,
        NameResolution::Missing
    ));
    for registry in &mut registries {
        registry.set_name_lookup(true);
    }
    drop((source, key, signed));
    original.close().unwrap();
    // The consumer starts with only the independent key and exact name, no signed file.
    let NameResolution::Candidate(candidate) = lookup(&registries[0], &query).await else {
        panic!(
            "explicit public-name service must retain original signed bytes without replication opt-in"
        );
    };
    let manifest = query.verify_candidate(candidate.signed(), now()).unwrap();
    assert_eq!(manifest.metadata().revision, 7);
    let NameResolution::Candidate(second) = lookup(&registries[1], &query).await else {
        panic!("second provider");
    };
    assert_eq!(second.manifest().manifest_id(), manifest.manifest_id());
    let cache_root = directory.path().join("consumer");
    let mut cache = ChunkStore::create(&cache_root, limits()).unwrap();
    cache.observe_name_revision(&manifest, now()).unwrap();
    assert_eq!(cache.usage().bytes, 0, "pin precedes all content bytes");
    let mut transferred = 0;
    for registry in &registries {
        let (mut client, mut server) = duplex(1024);
        let (received, sent) = tokio::join!(
            pull_publication(
                &mut client,
                &manifest,
                &mut cache,
                TransferLimits::default()
            ),
            serve_publication(&mut server, registry, TransferLimits::default()),
        );
        let received = received.unwrap();
        assert_eq!(sent.unwrap(), received);
        transferred += received.bytes;
    }
    assert_eq!(transferred, bytes.len() as u64);
    let output = directory.path().join("site.html");
    reassemble_to_file(&manifest, &mut [&mut cache], now(), &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), bytes);
    assert!(matches!(
        lookup(
            &registries[0],
            &NameQuery::new(trusted, "other", 0).unwrap()
        )
        .await,
        NameResolution::Missing
    ));
    assert!(matches!(
        lookup(
            &registries[0],
            &NameQuery::new(trusted, "site/index", 8).unwrap()
        )
        .await,
        NameResolution::Missing
    ));
}

#[tokio::test]
async fn signed_conflict_and_durable_floors_survive_expiry_eviction_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let source_root = directory.path().join("source");
    let mut source = ChunkStore::create(&source_root, limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let live = Validity {
        created: now(),
        expires: now() + 300,
    };
    let second = sign(&key, &mut source, "site", 2, live, b"new");
    // Even byte-identical re-signing has a different nonce/envelope ID at the same revision.
    let conflict = sign(&key, &mut source, "site", 2, live, b"new");
    let old = sign(&key, &mut source, "site", 1, live, b"old");
    let third = sign(&key, &mut source, "site", 3, live, b"newest");
    drop(source);
    let mut registry = PublicationRegistry::new();
    for signed in [&second, &conflict] {
        registry
            .register_signed(
                signed.clone(),
                &key.verifying_key(),
                source_root.clone(),
                limits(),
                now(),
            )
            .unwrap();
    }
    registry.set_name_lookup(true);
    let query = NameQuery::new(key.verifying_key().to_bytes(), "site", 0).unwrap();
    let NameResolution::Conflict(pair) = lookup(&registry, &query).await else {
        panic!("verified equivocation");
    };
    assert_ne!(
        pair[0].manifest().manifest_id(),
        pair[1].manifest().manifest_id()
    );
    let cache_root = directory.path().join("consumer");
    let small = CacheLimits {
        max_bytes: 4,
        max_entries: 1,
        min_free_bytes: 0,
    };
    let mut cache = ChunkStore::create(&cache_root, small).unwrap();
    cache
        .observe_name_revision(pair[0].manifest(), now())
        .unwrap();
    assert!(matches!(
        cache.observe_name_revision(pair[1].manifest(), now()),
        Err(Error::NameConflict)
    ));
    let first_chunk = cache.put(b"aaaa").unwrap();
    cache.put(b"bbbb").unwrap();
    assert!(
        cache.get(&first_chunk).unwrap().is_none(),
        "actual LRU eviction occurred"
    );
    drop(cache);
    let mut cache = ChunkStore::open(&cache_root, small).unwrap();
    let pin = cache
        .name_revision_floor(&key.verifying_key().to_bytes(), "site")
        .unwrap()
        .unwrap();
    assert_eq!(pin.revision(), 2);
    assert!(pin.conflicted());
    assert!(matches!(
        cache.observe_name_revision(&old.verify(&key.verifying_key(), now()).unwrap(), now()),
        Err(Error::NameRollback)
    ));
    cache
        .observe_name_revision(&third.verify(&key.verifying_key(), now()).unwrap(), now())
        .unwrap();
    assert!(
        !cache
            .name_revision_floor(&key.verifying_key().to_bytes(), "site")
            .unwrap()
            .unwrap()
            .conflicted()
    );
    drop(cache);
    let cache = ChunkStore::open(&cache_root, small).unwrap();
    // Floor lookup has deliberately no clock: it remains even after the original manifest expired.
    assert!(third.verify(&key.verifying_key(), live.expires).is_err());
    assert_eq!(
        cache
            .name_revision_floor(&key.verifying_key().to_bytes(), "site")
            .unwrap()
            .unwrap()
            .revision(),
        3
    );
    drop(cache);
    let mut new_scope = ChunkStore::create(&directory.path().join("new-scope"), small).unwrap();
    assert!(
        new_scope
            .name_revision_floor(&key.verifying_key().to_bytes(), "site")
            .unwrap()
            .is_none()
    );
    new_scope
        .observe_name_revision(&old.verify(&key.verifying_key(), now()).unwrap(), now())
        .unwrap();
}
