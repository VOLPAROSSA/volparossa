//! Actual bounded stream and disk transfers, not overlay routing or HTTPS-origin evidence.

use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::oneshot,
    time::timeout,
};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, CacheUsage, ChunkStore, Error, Metadata, Publication, Validity,
    VerifiedManifest, publish, reassemble_to_file,
    transfer::{TransferError, TransferLimits, TransferProgress, pull_from_peer, serve_peer},
};

#[tokio::test]
async fn two_partial_peers_fill_a_persistent_cache_after_publisher_disappears() {
    let root = tempfile::tempdir().expect("test root");
    let origin = tempfile::tempdir_in(root.path()).expect("publisher directory");
    let mut expected = vec![0x31; CHUNK_BYTES];
    expected.extend(vec![0xa4; CHUNK_BYTES]);
    expected.extend(b"native stream final piece");
    let (manifest, mut publisher) = publication(origin.path(), &expected);
    let mut first = ChunkStore::create(&root.path().join("first"), cache_limits()).expect("peer 1");
    let mut second =
        ChunkStore::create(&root.path().join("second"), cache_limits()).expect("peer 2");
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = publisher
            .get(chunk.id())
            .expect("origin read")
            .expect("chunk");
        let replica = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        replica
            .put_verified(*chunk.id(), &bytes)
            .expect("authentic replica");
    }
    drop(publisher);
    origin
        .close()
        .expect("remove publisher directory before stream transfers");

    let cache_path = root.path().join("consumer");
    let mut cache = ChunkStore::create(&cache_path, cache_limits()).expect("consumer");
    let first_bytes = expected.len() as u64 - CHUNK_BYTES as u64;
    {
        let (received, sent) = transfer_once(&manifest, &mut cache, &mut first).await;
        let progress = TransferProgress {
            chunks: 2,
            bytes: first_bytes,
            missing: 1,
        };
        assert_eq!(received, progress);
        assert_eq!(sent, progress);
    }
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: first_bytes,
            entries: 2
        }
    );
    let incomplete = root.path().join("incomplete.bin");
    assert!(matches!(
        reassemble_to_file(&manifest, &mut [&mut cache], now(), &incomplete),
        Err(Error::MissingChunk(_))
    ));
    assert!(!incomplete.exists());
    drop(cache);

    let mut cache = ChunkStore::open(&cache_path, cache_limits()).expect("persistent consumer");
    {
        let (received, sent) = transfer_once(&manifest, &mut cache, &mut second).await;
        // The two persisted hits are skipped, so peer 2 receives only its one missing request.
        let progress = TransferProgress {
            chunks: 1,
            bytes: CHUNK_BYTES as u64,
            missing: 0,
        };
        assert_eq!(received, progress);
        assert_eq!(sent, progress);
    }
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: expected.len() as u64,
            entries: 3
        }
    );
    drop(cache);
    let mut cache =
        ChunkStore::open(&cache_path, cache_limits()).expect("complete persisted cache");
    let output = root.path().join("complete.bin");
    assert_eq!(
        reassemble_to_file(&manifest, &mut [&mut cache], now(), &output).expect("reassemble"),
        expected.len() as u64
    );
    assert_eq!(fs::read(output).expect("complete output"), expected);
}

#[tokio::test]
async fn a_corrupt_response_with_the_expected_hash_and_length_never_enters_the_cache() {
    let root = tempfile::tempdir().expect("root");
    let payload = b"authentic native content";
    let (manifest, _publisher) = publication(root.path(), payload);
    let mut cache =
        ChunkStore::create(&root.path().join("consumer"), cache_limits()).expect("cache");
    let (mut consumer_stream, mut provider_stream) = duplex(257);
    let corrupt_provider = async {
        let request = read_request(&mut provider_stream).await;
        assert_eq!(request.hash, manifest.chunks()[0].id().as_bytes());
        assert_eq!(request.length as usize, payload.len());
        let mut data = payload.to_vec();
        data[0] ^= 1;
        let encoded = Response {
            version: 1,
            hash: request.hash,
            length: request.length,
            found: true,
            data,
        }
        .encode_to_vec();
        provider_stream
            .write_u32(u32::try_from(encoded.len()).expect("frame bound"))
            .await
            .expect("response prefix");
        provider_stream
            .write_all(&encoded)
            .await
            .expect("corrupt response");
    };
    let (result, ()) = tokio::join!(
        pull_from_peer(
            &mut consumer_stream,
            &manifest,
            &mut cache,
            transfer_limits()
        ),
        corrupt_provider,
    );
    assert!(
        matches!(result, Err(TransferError::Content(Error::Integrity(id)))
        if id == *manifest.chunks()[0].id())
    );
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: 0,
            entries: 0
        }
    );
    assert!(
        cache
            .get(manifest.chunks()[0].id())
            .expect("cache read")
            .is_none()
    );
}

#[tokio::test]
async fn oversized_response_prefix_is_rejected_without_waiting_for_a_body() {
    let root = tempfile::tempdir().expect("root");
    let (manifest, _publisher) = publication(root.path(), b"a bounded object");
    let mut cache =
        ChunkStore::create(&root.path().join("consumer"), cache_limits()).expect("cache");
    let (mut consumer_stream, mut provider_stream) = duplex(257);
    let (finished, observe_finished) = oneshot::channel();
    let consumer = async {
        let result = pull_from_peer(
            &mut consumer_stream,
            &manifest,
            &mut cache,
            transfer_limits(),
        )
        .await;
        finished.send(()).expect("provider remains open");
        result
    };
    let provider = async {
        let _request = read_request(&mut provider_stream).await;
        provider_stream
            .write_u32(u32::MAX)
            .await
            .expect("oversized prefix");
        // No body or EOF is supplied: Protocol must win, not an I/O/deadline error.
        observe_finished.await.expect("consumer returned");
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(consumer, provider)
    })
    .await
    .expect("bounded oversized-prefix rejection");
    assert!(matches!(result, Err(TransferError::Protocol)));
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: 0,
            entries: 0
        }
    );
}

#[tokio::test]
async fn a_silent_peer_expires_the_exchange_without_mutating_the_cache() {
    let root = tempfile::tempdir().expect("root");
    let (manifest, _publisher) = publication(root.path(), b"deadline-bound object");
    let mut cache =
        ChunkStore::create(&root.path().join("consumer"), cache_limits()).expect("cache");
    let (mut consumer_stream, _open_silent_peer) = duplex(257);
    let limits = TransferLimits {
        exchange_timeout: Duration::from_millis(30),
        ..transfer_limits()
    };
    let result = timeout(
        Duration::from_secs(2),
        pull_from_peer(&mut consumer_stream, &manifest, &mut cache, limits),
    )
    .await
    .expect("exchange deadline is bounded");
    assert!(matches!(result, Err(TransferError::Timeout)));
    assert_eq!(
        cache.usage(),
        CacheUsage {
            bytes: 0,
            entries: 0
        }
    );
}

async fn transfer_once(
    manifest: &VerifiedManifest,
    consumer: &mut ChunkStore,
    provider: &mut ChunkStore,
) -> (TransferProgress, TransferProgress) {
    // Capacity is smaller than either full chunk, exercising actual stream backpressure.
    let (mut consumer_stream, mut provider_stream) = duplex(257);
    let (received, sent) = tokio::join!(
        pull_from_peer(&mut consumer_stream, manifest, consumer, transfer_limits()),
        serve_peer(&mut provider_stream, manifest, provider, transfer_limits()),
    );
    (
        received.expect("partial pull"),
        sent.expect("partial serve"),
    )
}

fn publication(directory: &Path, bytes: &[u8]) -> (VerifiedManifest, ChunkStore) {
    let mut store =
        ChunkStore::create(&directory.join("publisher"), cache_limits()).expect("publisher");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let timestamp = now();
    let signed = publish(
        &mut &*bytes,
        Publication {
            metadata: Metadata {
                name: "explicit-stream-publication".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: timestamp - 1,
                expires: timestamp + 3600,
            },
        },
        &key,
        &mut store,
    )
    .expect("native publication");
    let manifest = signed
        .verify(&key.verifying_key(), timestamp)
        .expect("publisher authentication");
    (manifest, store)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time")
        .as_secs()
}

fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 3 * CHUNK_BYTES as u64,
        max_entries: 3,
        min_free_bytes: 0,
    }
}

fn transfer_limits() -> TransferLimits {
    TransferLimits {
        exchange_timeout: Duration::from_secs(5),
        session_timeout: Duration::from_secs(20),
        max_requests: 3,
        max_bytes: 3 * CHUNK_BYTES as u64,
    }
}

// Test-only v1 wire frames let a hostile provider retain valid correlation fields.
#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "3")]
    length: u32,
    #[prost(bool, tag = "4")]
    finish: bool,
}

#[derive(Clone, PartialEq, Message)]
struct Response {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "3")]
    length: u32,
    #[prost(bool, tag = "4")]
    found: bool,
    #[prost(bytes = "vec", tag = "5")]
    data: Vec<u8>,
}

async fn read_request(stream: &mut DuplexStream) -> Request {
    let length = stream.read_u32().await.expect("request prefix");
    assert!((1..=64).contains(&length));
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.expect("request frame");
    let request = Request::decode(bytes.as_slice()).expect("canonical request");
    assert_eq!(request.encode_to_vec(), bytes);
    assert_eq!(request.version, 1);
    assert!(!request.finish);
    request
}
