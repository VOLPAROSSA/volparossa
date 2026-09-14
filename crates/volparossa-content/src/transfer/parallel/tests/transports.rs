//! Different original public indexes, unchanged production v1 selection and chunk handlers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use super::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, ParallelDownload, ProviderError, Publication,
    PublicationRegistry, TransferError, TransferLimits, TransferProgress, Validity,
    VerifiedManifest, publish, pull_publication_worker, reassemble, serve_publication,
};
use crate::{SignedManifest, private_message::PRIVATE_MESSAGE_CONTENT_TYPE};

fn alternate(
    expected: &VerifiedManifest,
    signer: &SigningKey,
    validity: Validity,
    content_type: &str,
    chunks: Vec<crate::Chunk>,
) -> (SignedManifest, VerifiedManifest) {
    let envelope = SignedManifest::sign(
        Publication {
            metadata: Metadata {
                name: "independent-cache-index".into(),
                revision: 9,
                content_type: content_type.into(),
            },
            length: chunks.iter().map(|chunk| u64::from(chunk.length())).sum(),
            validity,
        },
        chunks,
        *expected.object_sha256(),
        signer,
    )
    .unwrap();
    let checked = envelope
        .verify(&signer.verifying_key(), validity.created)
        .unwrap();
    (envelope, checked)
}

#[tokio::test]
async fn different_transport_manifests_combine_complementary_public_caches_over_existing_v1() {
    tokio::time::timeout(Duration::from_secs(10), transfer())
        .await
        .unwrap();
}

async fn transfer() {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: 8 * CHUNK_BYTES as u64,
        max_entries: 8,
        min_free_bytes: 0,
    };
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let first_key = SigningKey::generate(&mut OsRng);
    let second_key = SigningKey::generate(&mut OsRng);
    let mut source = ChunkStore::create(&directory.path().join("source"), limits).unwrap();
    // Five ordered chunks, four unique payloads: the repeated first chunk is never requested twice.
    let original = [1_u8, 2, 3, 4, 1]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let signed_a = publish(
        &mut original.as_slice(),
        Publication {
            metadata: Metadata {
                name: "first-cache-index".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: original.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 300,
            },
        },
        &first_key,
        &mut source,
    )
    .unwrap();
    let expected = signed_a.verify(&first_key.verifying_key(), at).unwrap();
    let (signed_b, transport_b) = alternate(
        &expected,
        &second_key,
        Validity {
            created: at,
            expires: at + 180,
        },
        "application/octet-stream",
        expected.chunks().to_vec(),
    );
    assert_ne!(expected.publisher(), transport_b.publisher());
    assert_ne!(expected.manifest_id(), transport_b.manifest_id());
    assert_ne!(expected.validity().expires, transport_b.validity().expires);
    let registries = partial_registries(
        directory.path(),
        limits,
        &mut source,
        &expected,
        [(&signed_a, &first_key), (&signed_b, &second_key)],
    );
    drop(source);
    let mut output = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    rejects_incompatible_indexes(&expected, &second_key, &mut output, at);
    exact_selector_does_not_alias(&expected, &mut output, &registries[1]).await;

    let (download, [mut worker_a, mut worker_b]) = ParallelDownload::new_with_transport_manifests(
        &expected,
        [&expected, &transport_b],
        &mut output,
        TransferLimits::default(),
    )
    .unwrap();
    assert_eq!(worker_a.manifest().manifest_id(), expected.manifest_id());
    assert_eq!(worker_b.manifest().manifest_id(), transport_b.manifest_id());
    assert_eq!(worker_b.manifest().validity(), transport_b.validity());
    let (mut client_a, mut server_a) = tokio::io::duplex(1024);
    let (mut client_b, mut server_b) = tokio::io::duplex(1024);
    let mut progress = [TransferProgress::default(); 2];
    let (written, received_a, received_b, sent_a, sent_b) = tokio::join!(
        download.run(&mut output, &mut progress),
        pull_publication_worker(&mut client_a, &mut worker_a),
        pull_publication_worker(&mut client_b, &mut worker_b),
        serve_publication(&mut server_a, &registries[0], TransferLimits::default()),
        serve_publication(&mut server_b, &registries[1], TransferLimits::default()),
    );
    written.unwrap();
    received_a.unwrap();
    received_b.unwrap();
    for (received, sent) in progress.into_iter().zip([sent_a.unwrap(), sent_b.unwrap()]) {
        assert_eq!(received.chunks, 2);
        assert_eq!(received.bytes, 2 * CHUNK_BYTES as u64);
        assert_eq!(sent.bytes, received.bytes);
        assert_eq!(sent.chunks, received.chunks);
    }
    let mut bytes = Vec::new();
    reassemble(&expected, &mut [&mut output], at, &mut bytes).unwrap();
    assert_eq!(bytes, original);
}

fn partial_registries(
    directory: &std::path::Path,
    limits: CacheLimits,
    source: &mut ChunkStore,
    expected: &VerifiedManifest,
    indexes: [(&SignedManifest, &SigningKey); 2],
) -> [PublicationRegistry; 2] {
    let mut registries = [PublicationRegistry::new(), PublicationRegistry::new()];
    for (index, (signed, key)) in indexes.into_iter().enumerate() {
        let root = directory.join(format!("provider-{index}"));
        let mut cache = ChunkStore::create(&root, limits).unwrap();
        for (position, chunk) in expected.chunks().iter().take(4).enumerate() {
            if position % 2 == index {
                cache
                    .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
                    .unwrap();
            }
        }
        drop(cache);
        registries[index]
            .register_signed(
                signed.clone(),
                &key.verifying_key(),
                root,
                limits,
                expected.validity().created,
            )
            .unwrap();
        assert_eq!(registries[index].len(), 1);
    }
    registries
}

async fn exact_selector_does_not_alias(
    expected: &VerifiedManifest,
    output: &mut ChunkStore,
    registry: &PublicationRegistry,
) {
    // The unchanged native constructor must still fail B's selector: B never registered A's ID.
    let (old, [unused, mut worker]) =
        ParallelDownload::new(expected, output, TransferLimits::default()).unwrap();
    let (mut client, mut server) = tokio::io::duplex(1024);
    let (received, sent) = tokio::join!(
        pull_publication_worker(&mut client, &mut worker),
        serve_publication(&mut server, registry, TransferLimits::default())
    );
    assert!(matches!(received, Err(ProviderError::Missing)));
    assert!(matches!(sent, Err(ProviderError::Missing)));
    drop((old, unused, worker));
}

fn rejects_incompatible_indexes(
    expected: &VerifiedManifest,
    key: &SigningKey,
    output: &mut ChunkStore,
    at: u64,
) {
    let current = Validity {
        created: at,
        expires: at + 180,
    };
    let mut reordered = expected.chunks().to_vec();
    reordered.swap(0, 1);
    let mut shortened = expected.chunks().to_vec();
    shortened.pop();
    let mut wrong_digest = expected.clone();
    wrong_digest.whole_hash[0] ^= 1;
    let (_, private) = alternate(
        expected,
        key,
        current,
        PRIVATE_MESSAGE_CONTENT_TYPE,
        expected.chunks().to_vec(),
    );
    let (_, expired) = alternate(
        expected,
        key,
        Validity {
            created: at - 120,
            expires: at - 60,
        },
        "application/octet-stream",
        expected.chunks().to_vec(),
    );
    let candidates = [
        alternate(
            expected,
            key,
            current,
            "application/octet-stream",
            reordered,
        )
        .1,
        alternate(
            expected,
            key,
            current,
            "application/octet-stream",
            shortened,
        )
        .1,
        alternate(
            expected,
            key,
            current,
            "text/plain",
            expected.chunks().to_vec(),
        )
        .1,
        wrong_digest,
        private.clone(),
        expired,
    ];
    for candidate in &candidates {
        assert!(
            ParallelDownload::new_with_transport_manifests(
                expected,
                [expected, candidate],
                output,
                TransferLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        ParallelDownload::new_with_transport_manifests(
            &private,
            [&private; 2],
            output,
            TransferLimits::default()
        )
        .is_err()
    );
    assert!(
        ParallelDownload::new(&private, output, TransferLimits::default()).is_ok(),
        "legacy explicit private transfer is unchanged"
    );
    assert_eq!(output.usage().bytes, 0, "rejected indexes admit no payload");
    // Content/expiry failures remain typed; nothing is mapped to a successful empty transfer.
    assert!(matches!(
        ParallelDownload::new_with_transport_manifests(
            expected,
            [expected, &candidates[5]],
            output,
            TransferLimits::default()
        ),
        Err(TransferError::Content(crate::Error::Expired))
    ));
}
