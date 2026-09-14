use std::path::Path;

use ed25519_dalek::SigningKey;
use tokio::io::duplex;

use super::*;
use crate::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, Validity,
    provider::{pull_publication, serve_publication},
    publish, reassemble,
};

fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 4,
        min_free_bytes: 0,
    }
}

fn publication(
    directory: &Path,
    content_type: &str,
    bytes: &[u8],
) -> (PublicationRegistry, SignedManifest, VerifiedManifest) {
    let root = directory.join("source");
    let mut cache = ChunkStore::create(&root, cache_limits()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let at = now().unwrap();
    let mut input = bytes;
    let envelope = publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: "opaque-transport-index".into(),
                revision: 1,
                content_type: content_type.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 300,
            },
        },
        &key,
        &mut cache,
    )
    .unwrap();
    let manifest = envelope.verify(&key.verifying_key(), at).unwrap();
    drop(cache);
    let mut registry = PublicationRegistry::new();
    registry
        .register_signed(
            envelope.clone(),
            &key.verifying_key(),
            root,
            cache_limits(),
            at,
        )
        .unwrap();
    (registry, envelope, manifest)
}

async fn lookup(registry: &PublicationRegistry, query: &DigestQuery) -> Option<DigestCandidate> {
    let (mut client, mut server) = duplex(1024);
    let (received, sent) = tokio::join!(
        lookup_publication(&mut client, query, TransferLimits::default()),
        serve_publication(&mut server, registry, TransferLimits::default()),
    );
    assert_eq!(
        sent.unwrap(),
        TransferProgress::default(),
        "metadata is not payload"
    );
    received.unwrap()
}

#[tokio::test]
async fn digest_lookup_preserves_original_index_and_existing_chunk_transfer() {
    let directory = tempfile::tempdir().unwrap();
    let mut bytes = vec![0x42; CHUNK_BYTES];
    bytes.extend_from_slice(b"exact digest transport, not origin authority");
    let (registry, original, manifest) =
        publication(directory.path(), "application/octet-stream", &bytes);
    let query = DigestQuery::new(*manifest.object_sha256(), manifest.length()).unwrap();
    let candidate = lookup(&registry, &query).await.unwrap();
    assert_eq!(candidate.signed().encode(), original.encode());
    assert_eq!(
        candidate.transport_manifest().manifest_id(),
        manifest.manifest_id()
    );
    let unrelated_authority = SigningKey::generate(&mut rand_core::OsRng);
    assert!(
        candidate
            .signed()
            .verify(&unrelated_authority.verifying_key(), now().unwrap())
            .is_err()
    );
    assert!(
        lookup(
            &registry,
            &DigestQuery::new(*query.object_sha256(), query.length() + 1).unwrap()
        )
        .await
        .is_none()
    );
    assert!(
        lookup(
            &registry,
            &DigestQuery::new([0; 32], query.length()).unwrap()
        )
        .await
        .is_none()
    );

    let mut cache = ChunkStore::create(&directory.path().join("consumer"), cache_limits()).unwrap();
    let (mut client, mut server) = duplex(1024);
    let (received, sent) = tokio::join!(
        pull_publication(
            &mut client,
            candidate.transport_manifest(),
            &mut cache,
            TransferLimits::default()
        ),
        serve_publication(&mut server, &registry, TransferLimits::default()),
    );
    let received = received.unwrap();
    assert_eq!(sent.unwrap(), received);
    assert_eq!(received.bytes, bytes.len() as u64);
    assert_eq!(received.chunks, 2);
    let mut output = Vec::new();
    reassemble(
        candidate.transport_manifest(),
        &mut [&mut cache],
        now().unwrap(),
        &mut output,
    )
    .unwrap();
    assert_eq!(output, bytes);

    let private_root = tempfile::tempdir().unwrap();
    let (private, _, private_manifest) = publication(
        private_root.path(),
        PRIVATE_MESSAGE_CONTENT_TYPE,
        b"not publicly indexed",
    );
    let private_query =
        DigestQuery::new(*private_manifest.object_sha256(), private_manifest.length()).unwrap();
    assert!(lookup(&private, &private_query).await.is_none());
}

async fn incorrect_reply(case: u8) -> Result<Option<DigestCandidate>, ProviderError> {
    let (mut client, mut server) = duplex(1024);
    let query = DigestQuery::new([7; 32], 1).unwrap();
    let peer = async {
        let selector: Selector = super::super::read_frame(&mut server).await.unwrap();
        assert_eq!((selector.version, selector.operation), (VERSION, OPERATION));
        assert!(selector.manifest_id.is_empty());
        let request: Request = read_frame(&mut server, MAX_QUERY_BYTES).await.unwrap();
        if case == 2 {
            server
                .write_u32(u32::try_from(MAX_REPLY_BYTES + 1).unwrap())
                .await
                .unwrap();
            return;
        }
        let mut reply = Reply {
            version: VERSION,
            nonce: request.nonce,
            sha256: request.sha256,
            length: request.length,
            created: request.created,
            expires: request.expires,
            status: MISSING,
            manifest: Vec::new(),
        };
        if case == 0 {
            reply.nonce[0] ^= 1;
        } else {
            reply.expires = reply.created;
        }
        write_frame(&mut server, &reply, MAX_REPLY_BYTES)
            .await
            .unwrap();
    };
    let (received, ()) = tokio::join!(
        lookup_publication(&mut client, &query, TransferLimits::default()),
        peer
    );
    received
}

#[tokio::test]
async fn digest_lookup_rejects_uncorrelated_expired_and_oversized_replies() {
    assert!(matches!(
        incorrect_reply(0).await,
        Err(ProviderError::Protocol)
    ));
    assert!(matches!(
        incorrect_reply(1).await,
        Err(ProviderError::Expired)
    ));
    assert!(matches!(
        incorrect_reply(2).await,
        Err(ProviderError::Limit)
    ));
    assert!(DigestQuery::new([0; 32], MAX_OBJECT_BYTES + 1).is_err());
    assert!(check_time(100, 116, 101).is_err());
}
