//! Real bounded uptake and re-serving, without promoting peer-selected publication authority.

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use volparossa_content::provider::replication::{
    Replica, ReplicationExclusions, ReplicationLimits, ReplicationProgress, pull_replicas,
};
use volparossa_content::provider::{
    ProviderError, PublicationRegistry, pull_publication, serve_publication,
};
use volparossa_content::transfer::{TransferLimits, TransferProgress};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, Error, Metadata, Publication, SignedManifest,
    Validity, publish,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 8 * CHUNK_BYTES as u64,
        max_entries: 32,
        min_free_bytes: 0,
    }
}
fn publication(
    bytes: &[u8],
    key: &SigningKey,
    store: &mut ChunkStore,
    validity: Validity,
) -> SignedManifest {
    let mut input = bytes;
    publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: "explicit shareable object".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: bytes.len() as u64,
            validity,
        },
        key,
        store,
    )
    .unwrap()
}
fn validity() -> Validity {
    let created = now();
    Validity {
        created,
        expires: created + 600,
    }
}

async fn replicate(
    registry: &PublicationRegistry,
    store: &mut ChunkStore,
    limits: ReplicationLimits,
    exclusions: &ReplicationExclusions,
) -> (
    Result<ReplicationProgress, ProviderError>,
    Result<TransferProgress, ProviderError>,
) {
    let (mut client, mut server) = duplex(4096);
    tokio::join!(
        async move { pull_replicas(&mut client, store, limits, exclusions).await },
        async move { serve_publication(&mut server, registry, TransferLimits::default()).await },
    )
}

async fn foreground(
    registry: &PublicationRegistry,
    manifest: &volparossa_content::VerifiedManifest,
    store: &mut ChunkStore,
) -> TransferProgress {
    let (mut client, mut server) = duplex(4096);
    let (received, sent) = tokio::join!(
        pull_publication(&mut client, manifest, store, TransferLimits::default()),
        serve_publication(&mut server, registry, TransferLimits::default()),
    );
    let received = received.unwrap();
    assert_eq!(sent.unwrap(), received);
    received
}

#[tokio::test]
async fn small_replica_of_another_publication_is_reserved_then_served_to_independent_consumer() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let mut source = ChunkStore::create(&source_root, cache_limits()).unwrap();
    let main_key = SigningKey::generate(&mut rand_core::OsRng);
    let other_key = SigningKey::generate(&mut rand_core::OsRng);
    let main = publication(b"foreground", &main_key, &mut source, validity());
    let mut other_bytes = vec![7; CHUNK_BYTES];
    other_bytes.extend_from_slice(b"unimported tail");
    let other = publication(&other_bytes, &other_key, &mut source, validity());
    let trusted_main = main.verify(&main_key.verifying_key(), now()).unwrap();
    let trusted_other = other.verify(&other_key.verifying_key(), now()).unwrap();
    drop(source);
    let mut registry = PublicationRegistry::new();
    registry
        .register_shareable(
            main,
            &main_key.verifying_key(),
            source_root.clone(),
            cache_limits(),
            now(),
        )
        .unwrap();
    registry
        .register_shareable(
            other,
            &other_key.verifying_key(),
            source_root,
            cache_limits(),
            now(),
        )
        .unwrap();
    let mirror_root = temporary.path().join("mirror");
    // This cache cannot hold the entire other object. It must not evict its foreground chunk.
    let mirror_limits = CacheLimits {
        max_bytes: CHUNK_BYTES as u64 + 10,
        max_entries: 2,
        min_free_bytes: 0,
    };
    let mut mirror = ChunkStore::create(&mirror_root, mirror_limits).unwrap();
    assert_eq!(
        foreground(&registry, &trusted_main, &mut mirror)
            .await
            .bytes,
        10
    );
    drop((main_key, other_key));
    let exclusions = ReplicationExclusions {
        manifest_ids: vec![*trusted_main.manifest_id()],
        ..Default::default()
    };
    let (received, sent) = replicate(
        &registry,
        &mut mirror,
        ReplicationLimits {
            max_chunks: 1,
            ..Default::default()
        },
        &exclusions,
    )
    .await;
    let mut received = received.unwrap();
    assert_eq!(received.chunks, 1);
    assert_eq!(received.bytes, CHUNK_BYTES as u64);
    assert_eq!(sent.unwrap().bytes, received.bytes);
    assert!(received.wire_bytes > received.bytes && received.wire_bytes <= 1024 * 1024);
    let replica = received.replicas.pop().unwrap();
    assert_eq!(replica.hops(), 1);
    assert_eq!(replica.manifest_id(), trusted_other.manifest_id());
    assert_eq!(replica.validity(), trusted_other.validity());
    assert!(matches!(
        replica.signed_manifest().verify(
            &ed25519_dalek::VerifyingKey::from_bytes(trusted_main.publisher()).unwrap(),
            now()
        ),
        Err(Error::WrongPublisher)
    ));
    assert!(mirror.get(trusted_main.chunks()[0].id()).unwrap().is_some());
    drop(mirror);
    let mut mirror_registry = PublicationRegistry::new();
    mirror_registry
        .register_replica(replica, mirror_root, mirror_limits, now())
        .unwrap();
    let mut consumer =
        ChunkStore::create(&temporary.path().join("consumer"), cache_limits()).unwrap();
    let received = foreground(&mirror_registry, &trusted_other, &mut consumer).await;
    assert_eq!(received.chunks, 1);
    assert_eq!(received.missing, 1);
    assert_eq!(
        consumer
            .get(trusted_other.chunks()[0].id())
            .unwrap()
            .unwrap(),
        other_bytes[..CHUNK_BYTES]
    );
}

#[tokio::test]
async fn quotas_duplicates_exclusions_and_explicit_opt_in_do_not_displace_existing_data() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let mut source = ChunkStore::create(&source_root, cache_limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let signed = publication(b"extra chunk", &key, &mut source, validity());
    let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
    drop(source);
    let mut registry = PublicationRegistry::new();
    registry
        .register(manifest.clone(), source_root.clone(), cache_limits(), now())
        .unwrap();
    let target = temporary.path().join("target");
    let tiny = CacheLimits {
        max_bytes: 11,
        max_entries: 1,
        min_free_bytes: 0,
    };
    let mut store = ChunkStore::create(&target, tiny).unwrap();
    let (received, _) = replicate(
        &registry,
        &mut store,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    assert!(
        received.unwrap().replicas.is_empty(),
        "ordinary registration is not a catalogue export"
    );
    registry.remove(manifest.manifest_id());
    registry
        .register_shareable(
            signed,
            &key.verifying_key(),
            source_root,
            cache_limits(),
            now(),
        )
        .unwrap();
    let (received, _) = replicate(
        &registry,
        &mut store,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    assert_eq!(received.unwrap().bytes, 11);
    let (received, _) = replicate(
        &registry,
        &mut store,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    let received = received.unwrap();
    assert_eq!((received.chunks, received.bytes), (0, 0));
    assert_eq!(
        received.replicas.len(),
        1,
        "verified cached chunks may recover lost registration metadata"
    );
    let replica = received.replicas.into_iter().next().unwrap();
    let exclusions = ReplicationExclusions {
        chunk_ids: vec![*manifest.chunks()[0].id()],
        ..Default::default()
    };
    let (received, _) = replicate(
        &registry,
        &mut store,
        ReplicationLimits::default(),
        &exclusions,
    )
    .await;
    assert_eq!(received.unwrap().chunks, 0);
    assert!(matches!(
        store.put_verified_if_space(ChunkId::digest(b"foreground"), b"foreground"),
        Err(Error::Quota)
    ));
    assert_eq!(
        store.get(manifest.chunks()[0].id()).unwrap().unwrap(),
        b"extra chunk"
    );
    let mut full = ChunkStore::create(&temporary.path().join("full"), tiny).unwrap();
    let foreground = full.put(b"foreground!").unwrap();
    let (received, _) = replicate(
        &registry,
        &mut full,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    assert!(matches!(
        received,
        Err(ProviderError::Content(Error::Quota))
    ));
    assert_eq!(full.get(&foreground).unwrap().unwrap(), b"foreground!");
    assert_eq!(full.usage().entries, 1);
    drop(store);
    check_replica_registration(replica, &target, temporary.path(), tiny);
}

fn check_replica_registration(
    replica: Replica,
    target: &Path,
    temporary: &Path,
    tiny: CacheLimits,
) {
    let mut mirror = PublicationRegistry::new();
    assert!(matches!(
        mirror.register_replica(replica.clone(), target.to_path_buf(), tiny, now() + 1000),
        Err(ProviderError::Content(Error::Expired))
    ));
    let empty_root = temporary.join("empty");
    drop(ChunkStore::create(&empty_root, tiny).unwrap());
    assert!(matches!(
        mirror.register_replica(replica.clone(), empty_root, tiny, now()),
        Err(ProviderError::Missing)
    ));
    mirror
        .register_replica(replica.clone(), target.to_path_buf(), tiny, now())
        .unwrap();
    assert!(matches!(
        mirror.register_replica(replica, target.to_path_buf(), tiny, now()),
        Err(ProviderError::Registry)
    ));
}

#[tokio::test]
async fn wire_budget_includes_manifests_and_hop_eight_cannot_be_forwarded_as_an_extra() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let mut source = ChunkStore::create(&source_root, cache_limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let mut data = Vec::new();
    for byte in 1..=4 {
        data.extend(vec![byte; CHUNK_BYTES]);
    }
    let signed = publication(&data, &key, &mut source, validity());
    drop(source);
    let mut registry = PublicationRegistry::new();
    registry
        .register_shareable(
            signed,
            &key.verifying_key(),
            source_root,
            cache_limits(),
            now(),
        )
        .unwrap();
    let mut target =
        ChunkStore::create(&temporary.path().join("wire-limit"), cache_limits()).unwrap();
    let (received, _) = replicate(
        &registry,
        &mut target,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    let received = received.unwrap();
    assert_eq!(
        received.chunks, 3,
        "four full chunks plus manifests exceed a one-MiB wire budget"
    );
    assert!(received.wire_bytes > 3 * CHUNK_BYTES as u64 && received.wire_bytes <= 1024 * 1024);
    for hop in 1..=8 {
        let root = temporary.path().join(format!("hop-{hop}"));
        let mut store = ChunkStore::create(&root, cache_limits()).unwrap();
        let (received, _) = replicate(
            &registry,
            &mut store,
            ReplicationLimits {
                max_chunks: 1,
                ..Default::default()
            },
            &ReplicationExclusions::default(),
        )
        .await;
        let replica = received.unwrap().replicas.pop().unwrap();
        assert_eq!(replica.hops(), hop);
        drop(store);
        registry = PublicationRegistry::new();
        registry
            .register_replica(replica, root, cache_limits(), now())
            .unwrap();
    }
    let (received, _) = replicate(
        &registry,
        &mut target,
        ReplicationLimits::default(),
        &ReplicationExclusions::default(),
    )
    .await;
    assert!(received.unwrap().replicas.is_empty());
}

#[derive(Clone, PartialEq, Message)]
struct Frame {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bool, tag = "2")]
    finished: bool,
    #[prost(bytes = "vec", tag = "3")]
    publisher: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    manifest: Vec<u8>,
    #[prost(uint32, tag = "5")]
    hops: u32,
    #[prost(uint32, tag = "6")]
    chunk_index: u32,
    #[prost(bytes = "vec", tag = "7")]
    data: Vec<u8>,
}

async fn malicious_response(
    frames: Vec<Frame>,
    store: &mut ChunkStore,
) -> Result<ReplicationProgress, ProviderError> {
    let (mut client, mut server) = duplex(4096);
    let receive = async move {
        pull_replicas(
            &mut client,
            store,
            ReplicationLimits::default(),
            &ReplicationExclusions::default(),
        )
        .await
    };
    let send = async move {
        for _ in 0..2 {
            let length = server.read_u32().await? as usize;
            let mut request = vec![0; length];
            server.read_exact(&mut request).await?;
        }
        for frame in frames.into_iter().chain([Frame {
            version: 2,
            finished: true,
            ..Default::default()
        }]) {
            let bytes = frame.encode_to_vec();
            server
                .write_u32(u32::try_from(bytes.len()).unwrap())
                .await?;
            server.write_all(&bytes).await?;
        }
        Ok::<_, std::io::Error>(())
    };
    tokio::join!(receive, send).0
}

#[tokio::test]
async fn forged_expired_corrupt_duplicate_and_over_hop_frames_never_become_useful_replicas() {
    let temporary = tempfile::tempdir().unwrap();
    let mut source = ChunkStore::create(&temporary.path().join("source"), cache_limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let signed = publication(b"valid payload", &key, &mut source, validity());
    let frame = Frame {
        version: 2,
        publisher: key.verifying_key().as_bytes().to_vec(),
        manifest: signed.encode(),
        data: b"valid payload".to_vec(),
        ..Default::default()
    };
    let mut cases = Vec::new();
    let mut corrupt = frame.clone();
    corrupt.data[0] ^= 1;
    cases.push(vec![corrupt]);
    let mut forged = frame.clone();
    *forged.manifest.last_mut().unwrap() ^= 1;
    cases.push(vec![forged]);
    let mut over_hop = frame.clone();
    over_hop.hops = 8;
    cases.push(vec![over_hop]);
    let mut expired = frame.clone();
    expired.manifest = publication(
        b"valid payload",
        &key,
        &mut source,
        Validity {
            created: now() - 30,
            expires: now() - 10,
        },
    )
    .encode();
    cases.push(vec![expired]);
    cases.push(vec![frame.clone(), frame]);
    for (index, frames) in cases.into_iter().enumerate() {
        let mut store = ChunkStore::create(
            &temporary.path().join(format!("bad-{index}")),
            cache_limits(),
        )
        .unwrap();
        assert!(malicious_response(frames, &mut store).await.is_err());
        assert_eq!(
            store.usage().entries,
            usize::from(index == 4),
            "only the verified prefix of the duplicate case may remain"
        );
    }
}

#[tokio::test]
async fn invalid_resource_bounds_and_silent_peers_stop_before_unbounded_work() {
    let root = tempfile::tempdir().unwrap();
    let mut store = ChunkStore::create(&root.path().join("cache"), cache_limits()).unwrap();
    for limits in [
        ReplicationLimits {
            max_chunks: 5,
            ..Default::default()
        },
        ReplicationLimits {
            max_wire_bytes: 1024 * 1024 + 1,
            ..Default::default()
        },
        ReplicationLimits {
            max_hops: 9,
            ..Default::default()
        },
    ] {
        let (mut client, _server) = duplex(4096);
        assert!(matches!(
            pull_replicas(
                &mut client,
                &mut store,
                limits,
                &ReplicationExclusions::default()
            )
            .await,
            Err(ProviderError::Limit)
        ));
    }
    let (mut client, _server) = duplex(4096);
    assert!(matches!(
        pull_replicas(
            &mut client,
            &mut store,
            ReplicationLimits {
                session_timeout: Duration::from_millis(10),
                ..Default::default()
            },
            &ReplicationExclusions::default()
        )
        .await,
        Err(ProviderError::Timeout)
    ));
    assert_eq!(store.usage().entries, 0);
}
