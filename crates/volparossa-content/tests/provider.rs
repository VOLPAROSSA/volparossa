//! Actual exact-publication selection and bounded, independently signed provider offers.

use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Error, Metadata, Publication, SignedManifest, Validity,
    VerifiedManifest,
    provider::{
        MAX_PROVIDER_OFFER_BYTES, MAX_REGISTERED_PUBLICATIONS, ProviderEndpoint, ProviderError,
        PublicationRegistry, SignedProviderOffer, pull_publication, serve_publication,
    },
    publish, reassemble_to_file,
    transfer::{TransferError, TransferLimits},
};

#[tokio::test]
async fn two_registered_disjoint_replicas_fill_exact_manifest_after_publisher_disappears() {
    let root = tempfile::tempdir().expect("root");
    let origin = tempfile::tempdir_in(root.path()).expect("publisher directory");
    let mut source =
        ChunkStore::create(&origin.path().join("source"), cache_limits()).expect("source");
    let sender = SigningKey::generate(&mut rand_core::OsRng);
    let mut content = vec![0x31; CHUNK_BYTES];
    content.extend(vec![0x42; CHUNK_BYTES]);
    content.extend(b"exact registered publication offline");
    let signed = publication(&content, &sender, &mut source);
    let manifest = signed
        .verify(&sender.verifying_key(), now())
        .expect("publisher authority");
    assert_eq!(
        *manifest.manifest_id(),
        <[u8; 32]>::from(Sha256::digest(signed.encode()))
    );
    let mut registries = Vec::new();
    for index in 0..2 {
        let cache_root = root.path().join(format!("replica-{index}"));
        let mut cache = ChunkStore::create(&cache_root, cache_limits()).expect("replica");
        for (position, chunk) in manifest.chunks().iter().enumerate() {
            if position % 2 == index {
                let bytes = source
                    .get(chunk.id())
                    .expect("source read")
                    .expect("source chunk");
                cache.put_verified(*chunk.id(), &bytes).expect("replicate");
            }
        }
        drop(cache);
        let mut registry = PublicationRegistry::new();
        registry
            .register(manifest.clone(), cache_root, cache_limits(), now())
            .expect("explicit owned registration");
        registries.push(registry);
    }
    drop((source, sender, signed));
    origin
        .close()
        .expect("publisher storage gone before retrieval");
    let cache_root = root.path().join("consumer");
    drop(ChunkStore::create(&cache_root, cache_limits()).expect("consumer"));
    let mut bytes = 0;
    for (index, registry) in registries.iter().enumerate() {
        let mut cache = ChunkStore::open(&cache_root, cache_limits()).expect("consumer restart");
        let (mut consumer, mut provider) = duplex(4096);
        let (received, sent) = tokio::join!(
            pull_publication(
                &mut consumer,
                &manifest,
                &mut cache,
                TransferLimits::default()
            ),
            serve_publication(&mut provider, registry, TransferLimits::default()),
        );
        let received = received.expect("exact registered provider");
        assert_eq!(sent.expect("registered server"), received);
        assert_eq!(received.chunks, if index == 0 { 2 } else { 1 });
        assert_eq!(received.missing, usize::from(index == 0));
        bytes += received.bytes;
    }
    assert_eq!(bytes, content.len() as u64);
    let mut cache = ChunkStore::open(&cache_root, cache_limits()).expect("complete restart");
    let output = root.path().join("output.bin");
    reassemble_to_file(&manifest, &mut [&mut cache], now(), &output).expect("verified object");
    assert_eq!(fs::read(output).expect("output"), content);
}

#[test]
fn provider_offers_authenticate_only_expected_identity_exact_endpoint_and_original_lifetime() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let expected = key.verifying_key();
    let endpoint = ProviderEndpoint::new("cache.volparossa.test", 18443).expect("endpoint");
    let validity = Validity {
        created: 100,
        expires: 400,
    };
    let first = SignedProviderOffer::sign(&key, endpoint.clone(), validity).expect("offer");
    let wire = first.encode();
    assert!(wire.len() <= MAX_PROVIDER_OFFER_BYTES);
    let decoded = SignedProviderOffer::decode(&wire).expect("canonical offer");
    assert_eq!(decoded.provider_key_hint(), expected.to_bytes());
    let verified = decoded
        .verify(&expected, 101)
        .expect("independent provider authority");
    assert_eq!(verified.endpoint(), &endpoint);
    assert_eq!(verified.endpoint().hostname(), "cache.volparossa.test");
    assert_eq!(verified.endpoint().port(), 18443);
    assert_eq!(verified.provider_key(), expected.as_bytes());
    assert_eq!(verified.validity(), validity);
    let other = SigningKey::generate(&mut rand_core::OsRng);
    assert!(matches!(
        decoded.verify(&other.verifying_key(), 101),
        Err(ProviderError::WrongProvider)
    ));
    for time in [99, 400] {
        assert!(matches!(
            decoded.verify(&expected, time),
            Err(ProviderError::Expired)
        ));
    }
    assert!(matches!(
        SignedProviderOffer::sign(
            &key,
            endpoint.clone(),
            Validity {
                created: 100,
                expires: 401
            }
        ),
        Err(ProviderError::Offer)
    ));
    assert_ne!(
        SignedProviderOffer::sign(&key, endpoint, validity)
            .expect("fresh nonce")
            .encode(),
        wire
    );
    let mut forged = wire.clone();
    *forged.last_mut().expect("signature") ^= 1;
    assert!(matches!(
        SignedProviderOffer::decode(&forged)
            .expect("structural offer")
            .verify(&expected, 101),
        Err(ProviderError::Signature)
    ));
    let mut corrupt = wire.clone();
    let position = corrupt
        .windows(21)
        .position(|bytes| bytes == b"cache.volparossa.test")
        .expect("hostname payload");
    corrupt[position] ^= 1;
    assert!(matches!(
        SignedProviderOffer::decode(&corrupt),
        Err(ProviderError::Offer)
    ));
    let mut noncanonical = wire;
    noncanonical.extend([0x18, 1]);
    assert!(SignedProviderOffer::decode(&noncanonical).is_err());
    assert!(matches!(
        SignedProviderOffer::decode(&vec![0; MAX_PROVIDER_OFFER_BYTES + 1]),
        Err(ProviderError::Limit)
    ));
    for hostname in [
        "",
        "Cache.example",
        "cache.example/path",
        "https://cache.example",
        "127.0.0.1",
        "127.1",
        "2130706433",
        "cache.example.",
        "-cache.example",
    ] {
        assert!(ProviderEndpoint::new(hostname, 443).is_err());
    }
    assert!(ProviderEndpoint::new("cache.example", 0).is_err());
}

#[tokio::test]
async fn exact_id_misses_busy_store_and_corrupt_chunks_never_claim_successful_content() {
    let root = tempfile::tempdir().expect("root");
    let cache_root = root.path().join("provider");
    let mut cache = ChunkStore::create(&cache_root, cache_limits()).expect("provider cache");
    let sender = SigningKey::generate(&mut rand_core::OsRng);
    let first = publication(b"exact byte identity", &sender, &mut cache)
        .verify(&sender.verifying_key(), now())
        .expect("first");
    let second = publication(b"exact byte identity", &sender, &mut cache)
        .verify(&sender.verifying_key(), now())
        .expect("second");
    assert_ne!(first.manifest_id(), second.manifest_id());
    assert_eq!(first.chunks()[0].id(), second.chunks()[0].id());
    drop(cache);
    let mut registry = PublicationRegistry::new();
    registry
        .register(first.clone(), cache_root.clone(), cache_limits(), now())
        .expect("only first registered");
    let mut consumer =
        ChunkStore::create(&root.path().join("consumer"), cache_limits()).expect("consumer");
    let (received, sent) = transfer(&second, &mut consumer, &registry).await;
    assert!(matches!(received, Err(ProviderError::Missing)));
    assert!(matches!(sent, Err(ProviderError::Missing)));
    let held =
        ChunkStore::open(&cache_root, cache_limits()).expect("another local owner holds cache");
    let (received, sent) = transfer(&first, &mut consumer, &registry).await;
    assert!(matches!(received, Err(ProviderError::Unavailable)));
    assert!(matches!(sent, Err(ProviderError::Content(Error::Io(_)))));
    drop(held);
    let chunk_path = cache_root.join(first.chunks()[0].id().to_string());
    let mut bytes = fs::read(&chunk_path).expect("chunk");
    bytes[0] ^= 1;
    fs::write(chunk_path, bytes).expect("same-length disk corruption");
    let (received, sent) = transfer(&first, &mut consumer, &registry).await;
    assert!(received.is_err());
    assert!(matches!(
        sent,
        Err(ProviderError::Transfer(TransferError::Content(
            Error::Integrity(_)
        )))
    ));
    assert_eq!(consumer.usage().entries, 0);
}

#[tokio::test]
async fn registry_selector_and_receiver_quotas_are_bounded_without_adopting_foreign_files() {
    let root = tempfile::tempdir().expect("root");
    let cache_root = root.path().join("owned");
    let mut cache = ChunkStore::create(&cache_root, cache_limits()).expect("owned cache");
    let sender = SigningKey::generate(&mut rand_core::OsRng);
    let manifests: Vec<_> = (0..=MAX_REGISTERED_PUBLICATIONS)
        .map(|_| {
            publication(b"public", &sender, &mut cache)
                .verify(&sender.verifying_key(), now())
                .expect("publication")
        })
        .collect();
    drop(cache);
    let mut registry = PublicationRegistry::new();
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).expect("foreign directory");
    fs::write(foreign.join("keep"), b"unrelated user file").expect("foreign data");
    assert!(
        registry
            .register(manifests[0].clone(), foreign.clone(), cache_limits(), now())
            .is_err()
    );
    assert_eq!(
        fs::read(foreign.join("keep")).expect("preserved"),
        b"unrelated user file"
    );
    for manifest in &manifests[..MAX_REGISTERED_PUBLICATIONS] {
        registry
            .register(manifest.clone(), cache_root.clone(), cache_limits(), now())
            .expect("bounded entry");
    }
    assert_eq!(registry.len(), MAX_REGISTERED_PUBLICATIONS);
    assert!(matches!(
        registry.register(
            manifests[MAX_REGISTERED_PUBLICATIONS].clone(),
            cache_root.clone(),
            cache_limits(),
            now()
        ),
        Err(ProviderError::Limit)
    ));
    assert!(registry.remove(manifests[0].manifest_id()));
    assert!(!registry.remove(manifests[0].manifest_id()));
    registry
        .register(
            manifests[MAX_REGISTERED_PUBLICATIONS].clone(),
            cache_root,
            cache_limits(),
            now(),
        )
        .expect("reuse removed slot");
    let (mut peer, mut server) = duplex(128);
    peer.write_u32(65).await.expect("oversized selector prefix");
    assert!(matches!(
        serve_publication(&mut server, &registry, TransferLimits::default()).await,
        Err(ProviderError::Protocol)
    ));
    let (_silent, mut server) = duplex(128);
    assert!(matches!(
        serve_publication(
            &mut server,
            &registry,
            TransferLimits {
                exchange_timeout: Duration::from_millis(10),
                ..TransferLimits::default()
            }
        )
        .await,
        Err(ProviderError::Timeout)
    ));
    let mut tiny = ChunkStore::create(
        &root.path().join("tiny"),
        CacheLimits {
            max_bytes: 1,
            max_entries: 1,
            min_free_bytes: 0,
        },
    )
    .expect("small consumer");
    let (mut client, mut untouched) = duplex(128);
    assert!(matches!(
        pull_publication(
            &mut client,
            &manifests[1],
            &mut tiny,
            TransferLimits::default()
        )
        .await,
        Err(ProviderError::Content(Error::Quota))
    ));
    drop(client);
    assert_eq!(
        untouched
            .read(&mut [0; 1])
            .await
            .expect("no selector for impossible cache"),
        0
    );
}

async fn transfer(
    manifest: &VerifiedManifest,
    consumer: &mut ChunkStore,
    registry: &PublicationRegistry,
) -> (
    Result<volparossa_content::transfer::TransferProgress, ProviderError>,
    Result<volparossa_content::transfer::TransferProgress, ProviderError>,
) {
    let (mut client, mut server) = duplex(4096);
    let receiving = async {
        let result =
            pull_publication(&mut client, manifest, consumer, TransferLimits::default()).await;
        drop(client);
        result
    };
    let sending = async {
        let result = serve_publication(&mut server, registry, TransferLimits::default()).await;
        drop(server);
        result
    };
    tokio::join!(receiving, sending)
}
fn publication(mut content: &[u8], sender: &SigningKey, store: &mut ChunkStore) -> SignedManifest {
    let created = now();
    let length = content.len() as u64;
    publish(
        &mut content,
        Publication {
            metadata: Metadata {
                name: "registered-publication".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length,
            validity: Validity {
                created,
                expires: created + 300,
            },
        },
        sender,
        store,
    )
    .expect("publish")
}
fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 0,
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}
