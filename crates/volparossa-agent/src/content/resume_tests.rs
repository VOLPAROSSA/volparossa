//! Actual owned-cache reopening and selective chunk pulls; not a network privacy proof.

use super::*;
use std::fs;
use tokio::io::duplex;
use volparossa_content::provider::pull_publication;
use volparossa_content::{CHUNK_BYTES, Metadata, Publication, publish, reassemble_to_file};

fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 1024 * 1024,
        max_entries: 16,
        min_free_bytes: 0,
    }
}

fn resume_cache(path: &std::path::Path, reuse: bool) -> Result<ChunkStore, ContentError> {
    download_cache(
        path.to_str().expect("temporary path"),
        cache_limits(),
        reuse,
    )
}

#[tokio::test]
async fn content_resume_reopens_failed_download_and_requests_only_missing_chunks() {
    let root = tempfile::tempdir().expect("owned temporary caches");
    let source_path = root.path().join("source");
    let mut source = resume_cache(&source_path, false).expect("source");
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let mut payload = vec![73; CHUNK_BYTES];
    payload.extend_from_slice(b"the independently verified final chunk");
    let created = now();
    let publication = publish(
        &mut payload.as_slice(),
        Publication {
            metadata: Metadata {
                name: "resume".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: payload.len() as u64,
            validity: Validity {
                created,
                expires: created + 300,
            },
        },
        &signer,
        &mut source,
    )
    .expect("publication");
    let manifest = verified(&publication.encode(), signer.verifying_key().as_bytes())
        .expect("independent authority");
    let partial_path = root.path().join("partial-provider");
    let mut partial = resume_cache(&partial_path, false).expect("partial provider");
    let first = &manifest.chunks()[0];
    partial
        .put_verified(*first.id(), &source.get(first.id()).unwrap().unwrap())
        .unwrap();
    drop((partial, source));
    let mut partial_registry = PublicationRegistry::new();
    partial_registry
        .register(manifest.clone(), partial_path, cache_limits(), now())
        .unwrap();
    let cache_path = root.path().join("download");
    let mut cache = resume_cache(&cache_path, false).expect("new download");
    let first_progress = transfer(&partial_registry, &manifest, &mut cache).await;
    assert_eq!((first_progress.chunks, first_progress.missing), (1, 1));
    let output = root.path().join("verified-output");
    assert!(reassemble_to_file(&manifest, &mut [&mut cache], now(), &output).is_err());
    assert!(!output.exists());
    drop(cache);
    assert!(
        resume_cache(&cache_path, false).is_err(),
        "default may not reopen a cache"
    );
    let mut cache = resume_cache(&cache_path, true).expect("explicit owned-cache resume");
    let mut full_registry = PublicationRegistry::new();
    full_registry
        .register(manifest.clone(), source_path, cache_limits(), now())
        .unwrap();
    let fresh_manifest =
        verified(&publication.encode(), signer.verifying_key().as_bytes()).unwrap();
    let resumed = transfer(&full_registry, &fresh_manifest, &mut cache).await;
    assert_eq!((resumed.chunks, resumed.missing), (1, 0));
    assert_eq!(resumed.bytes, u64::from(manifest.chunks()[1].length()));
    reassemble_to_file(&fresh_manifest, &mut [&mut cache], now(), &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), payload);
    assert!(reassemble_to_file(&fresh_manifest, &mut [&mut cache], now(), &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), payload);
    let cached = transfer(&full_registry, &fresh_manifest, &mut cache).await;
    assert_eq!((cached.chunks, cached.bytes), (0, 0));
}

async fn transfer(
    registry: &PublicationRegistry,
    manifest: &VerifiedManifest,
    cache: &mut ChunkStore,
) -> TransferProgress {
    let (mut client, mut server) = duplex(4096);
    let (received, sent) = tokio::join!(
        pull_publication(&mut client, manifest, cache, TransferLimits::default()),
        serve_publication(&mut server, registry, TransferLimits::default()),
    );
    let received = received.expect("bounded chunk pull");
    assert_eq!(received, sent.expect("actual provider byte counts"));
    received
}

#[test]
fn content_resume_rejects_unowned_or_missing_directories_without_adoption() {
    let root = tempfile::tempdir().unwrap();
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("keep"), b"unrelated file").unwrap();
    assert!(resume_cache(&foreign, true).is_err());
    assert_eq!(fs::read(foreign.join("keep")).unwrap(), b"unrelated file");
    let missing = root.path().join("missing");
    assert!(resume_cache(&missing, true).is_err());
    assert!(!missing.exists());
}

#[tokio::test]
async fn content_resume_partial_failure_counts_received_bytes_despite_cache_eviction() {
    let root = tempfile::tempdir().unwrap();
    let source_path = root.path().join("source");
    let mut source = resume_cache(&source_path, false).unwrap();
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let mut payload = vec![11; CHUNK_BYTES];
    payload.extend(vec![22; CHUNK_BYTES]);
    let created = now();
    let publication = publish(
        &mut payload.as_slice(),
        Publication {
            metadata: Metadata {
                name: "interrupted".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: payload.len() as u64,
            validity: Validity {
                created,
                expires: created + 300,
            },
        },
        &signer,
        &mut source,
    )
    .unwrap();
    let manifest = verified(&publication.encode(), signer.verifying_key().as_bytes()).unwrap();
    drop(source);
    let mut registry = PublicationRegistry::new();
    registry
        .register(manifest.clone(), source_path, cache_limits(), now())
        .unwrap();
    let cache_path = root.path().join("resumed-full-cache");
    let tight = CacheLimits {
        max_bytes: (2 * CHUNK_BYTES) as u64,
        max_entries: 2,
        min_free_bytes: 0,
    };
    let mut cache = download_cache(cache_path.to_str().unwrap(), tight, false).unwrap();
    cache.put(&vec![33; CHUNK_BYTES]).unwrap();
    cache.put(&vec![44; CHUNK_BYTES]).unwrap();
    drop(cache);
    let mut cache = download_cache(cache_path.to_str().unwrap(), tight, true).unwrap();
    let before = cache.usage().bytes;
    let (mut client, mut server) = duplex(4096);
    let mut progress = TransferProgress::default();
    let (received, sent) = tokio::join!(
        pull_publication_with_progress(
            &mut client,
            &manifest,
            &mut cache,
            TransferLimits::default(),
            &mut progress,
        ),
        async move {
            serve_publication(
                &mut server,
                &registry,
                TransferLimits {
                    max_requests: 1,
                    ..TransferLimits::default()
                },
            )
            .await
        },
    );
    assert!(received.is_err() && sent.is_err());
    assert_eq!(
        cache.usage().bytes,
        before,
        "new verified chunk evicts old unrelated chunk"
    );
    assert_eq!(progress.chunks, 1);
    assert_eq!(progress.bytes, CHUNK_BYTES as u64);
    assert!(cache.get(manifest.chunks()[0].id()).unwrap().is_some());
    assert!(cache.get(manifest.chunks()[1].id()).unwrap().is_none());
}
