//! Real selector/chunk exchanges: a failed first stream must not cancel its live sibling.

use std::{sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use tokio::sync::Notify;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, Validity, VerifiedManifest,
    provider::{PublicationRegistry, pull_publication_worker, serve_publication},
    publish, reassemble,
    transfer::{TransferLimits, parallel::ParallelDownload},
};

use super::{ContentError, now, receive_pair};

#[tokio::test]
async fn failed_peer_preserves_verified_counts_and_allows_sibling_and_partial_fallback() {
    for (missing_last, policy_failure) in [(false, false), (true, false), (false, true)] {
        tokio::time::timeout(
            Duration::from_secs(8),
            transfer(missing_last, policy_failure),
        )
        .await
        .expect("bounded actual transfer");
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    manifest: VerifiedManifest,
    cache: ChunkStore,
    registries: [PublicationRegistry; 2],
    bytes: Vec<u8>,
}

fn fixture(missing_last: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 4,
        min_free_bytes: 0,
    };
    let mut first = ChunkStore::create(&directory.path().join("first"), limits).unwrap();
    let mut second = ChunkStore::create(&directory.path().join("second"), limits).unwrap();
    let cache = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    let bytes = [31_u8, 47, 91]
        .into_iter()
        .flat_map(|value| vec![value; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let created = now();
    let publication = publish(
        &mut bytes.as_slice(),
        Publication {
            length: bytes.len() as u64,
            metadata: Metadata {
                name: "partial-transfer".into(),
                content_type: "application/octet-stream".into(),
                revision: 1,
            },
            validity: Validity {
                created,
                expires: created + 60,
            },
        },
        &signer,
        &mut first,
    )
    .unwrap();
    let manifest = publication
        .verify(&signer.verifying_key(), created)
        .unwrap();
    for chunk in manifest
        .chunks()
        .iter()
        .take(if missing_last { 2 } else { 3 })
    {
        second
            .put_verified(*chunk.id(), &first.get(chunk.id()).unwrap().unwrap())
            .unwrap();
    }
    drop((signer, first, second));
    let mut a = PublicationRegistry::new();
    let mut b = PublicationRegistry::new();
    a.register(
        manifest.clone(),
        directory.path().join("first"),
        limits,
        created,
    )
    .unwrap();
    b.register(
        manifest.clone(),
        directory.path().join("second"),
        limits,
        created,
    )
    .unwrap();
    Fixture {
        _directory: directory,
        manifest,
        cache,
        registries: [a, b],
        bytes,
    }
}

async fn transfer(missing_last: bool, policy_failure: bool) {
    let Fixture {
        _directory,
        manifest,
        mut cache,
        registries: [a, b],
        bytes,
    } = fixture(missing_last);
    let limits = TransferLimits {
        exchange_timeout: Duration::from_secs(3),
        session_timeout: Duration::from_secs(5),
        max_requests: 4,
        max_bytes: 4 * CHUNK_BYTES as u64,
    };
    let (download, [mut first, mut second]) =
        ParallelDownload::new(&manifest, &mut cache, limits).unwrap();
    let (mut client_a, mut server_a) = tokio::io::duplex(4096);
    let (mut client_b, mut server_b) = tokio::io::duplex(4096);
    let failed = Arc::new(Notify::new());
    let wait = failed.clone();
    let server_a = tokio::spawn(async move {
        serve_publication(
            &mut server_a,
            &a,
            TransferLimits {
                max_requests: 1,
                ..limits
            },
        )
        .await
    });
    let server_b = tokio::spawn(async move {
        // Its assigned response cannot finish before A actually fails. try_join! used to
        // drop this client at that boundary, although its independently verified data is useful.
        wait.notified().await;
        serve_publication(&mut server_b, &b, limits).await
    });
    let result = receive_pair(
        download,
        &mut cache,
        async move {
            assert!(
                pull_publication_worker(&mut client_a, &mut first)
                    .await
                    .is_err()
            );
            drop(first);
            failed.notify_one();
            Err(if policy_failure {
                ContentError::Policy
            } else {
                ContentError::Unavailable
            })
        },
        async move {
            pull_publication_worker(&mut client_b, &mut second)
                .await
                .map_err(|_| ContentError::Unavailable)
        },
    )
    .await;
    assert!(server_a.await.unwrap().is_err());
    let sent_b = server_b
        .await
        .unwrap()
        .expect("sibling finishes its real stream");
    assert_eq!(sent_b.chunks, if missing_last { 1 } else { 2 });
    if policy_failure {
        assert!(matches!(result, Err(ContentError::Policy)));
        return;
    }
    let (progress, timed_out) = result.unwrap();
    assert!(!timed_out);
    assert_eq!(progress[0].chunks, 1);
    assert_eq!(progress[0].bytes, CHUNK_BYTES as u64);
    assert_eq!(progress[1].chunks, sent_b.chunks);
    assert_eq!(progress[1].bytes, sent_b.bytes);
    let mut output = Vec::new();
    let complete = reassemble(&manifest, &mut [&mut cache], now(), &mut output);
    if missing_last {
        assert!(
            complete.is_err(),
            "missing origin range is not declared complete"
        );
        assert!(cache.get(manifest.chunks()[2].id()).unwrap().is_none());
    } else {
        complete.unwrap();
        assert_eq!(output, bytes);
    }
}
