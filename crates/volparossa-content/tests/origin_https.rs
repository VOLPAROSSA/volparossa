//! Real TLS origin authentication before any HTTPS cache authority is created.

use std::{fs, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio_rustls::TlsAcceptor;
use volparossa_content::origin_https::{
    ORIGIN_DESCRIPTOR_CONTENT_TYPE, OriginAuthorizedManifest, OriginClient, OriginError,
    OriginLimits, OriginRequest, encode_origin_descriptor, format_http_date,
};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Error, Metadata, Publication, SignedManifest, Validity,
    publish,
};

const NOW: u64 = 1000;
const URL: &str = "https://destination.volparossa.test:18443/asset.bin";
const METADATA: &str = "/.well-known/volparossa/content/asset";

#[tokio::test]
async fn https_metadata_authorizes_replica_reconstruction_and_same_version_origin_fallback() {
    let mut fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let mut first = fixture.store("replica-a");
    let mut second = fixture.store("replica-b");
    for (index, chunk) in authorized.manifest().chunks().iter().enumerate() {
        let bytes = fixture
            .source
            .get(chunk.id())
            .expect("source read")
            .expect("chunk");
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target.put_verified(*chunk.id(), &bytes).expect("replica");
    }
    let peer_output = fixture.root.path().join("peers.bin");
    authorized
        .reassemble_to_file(&mut [&mut first, &mut second], NOW, &peer_output)
        .expect("origin-authenticated peer result");
    assert_eq!(fs::read(peer_output).expect("peer output"), fixture.content);

    let fallback_output = fixture.root.path().join("fallback.bin");
    assert!(matches!(
        authorized.reassemble_to_file(&mut [&mut first], NOW, &fallback_output),
        Err(OriginError::Content(Error::MissingChunk(_)))
    ));
    assert!(!fallback_output.exists());
    let (stream, server) = fixture
        .origin
        .respond(response(&fixture.content, "application/octet-stream"));
    let received = fixture
        .client()
        .fill_from_origin(stream, &authorized, &mut first, NOW)
        .await
        .expect("full same-version origin fallback");
    assert_eq!(received, fixture.content.len() as u64);
    let request = server.await.expect("origin process");
    assert!(request.starts_with(b"GET /asset.bin HTTP/1.1\r\n"));
    authorized
        .reassemble_to_file(&mut [&mut first], NOW, &fallback_output)
        .expect("complete original representation");
    assert_eq!(
        fs::read(fallback_output).expect("fallback output"),
        fixture.content
    );
}

#[tokio::test]
async fn real_tls_rejects_wrong_ca_wrong_hostname_and_plain_peer_bytes() {
    let fixture = Fixture::new();
    let wrong_authority = TestOrigin::new("destination.volparossa.test");
    let client =
        OriginClient::new(wrong_authority.roots(), OriginLimits::default()).expect("client");
    let (stream, server) = fixture.origin.respond(fixture.metadata_response());
    assert!(matches!(
        client
            .authenticate_manifest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Tls)
    ));
    server.await.expect("failed TLS server stopped");

    let wrong_name = TestOrigin::new("different.volparossa.test");
    let client =
        OriginClient::new(wrong_name.roots(), OriginLimits::default()).expect("trusted CA");
    let (stream, server) = wrong_name.respond(fixture.metadata_response());
    assert!(matches!(
        client
            .authenticate_manifest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Tls)
    ));
    server.await.expect("name mismatch stopped");

    let (stream, mut peer) = duplex(4096);
    let bytes = fixture.metadata_response();
    let server = tokio::spawn(async move {
        let _ = peer.write_all(&bytes).await;
    });
    assert!(matches!(
        fixture
            .client()
            .authenticate_manifest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Tls)
    ));
    server.await.expect("plain peer stopped");
}

#[tokio::test]
async fn descriptor_rejects_wrong_resource_changed_signature_and_noncanonical_bytes() {
    let fixture = Fixture::new();
    let different = OriginRequest::new(
        "https://destination.volparossa.test:18443/other.bin",
        METADATA,
    )
    .expect("different resource");
    let wrong = encode_origin_descriptor(
        &different,
        &fixture.signed,
        &fixture.sender.verifying_key(),
        NOW + 200,
        NOW,
    )
    .expect("different origin-authorized resource");
    let mut noncanonical = fixture.descriptor();
    noncanonical.extend([0x58, 1]); // Unknown descriptor field 11.
    let mut changed_signature = fixture.descriptor();
    *changed_signature
        .last_mut()
        .expect("signed-manifest signature") ^= 1;
    for bytes in [wrong, noncanonical, changed_signature] {
        let (stream, server) = fixture
            .origin
            .respond(response(&bytes, ORIGIN_DESCRIPTOR_CONTENT_TYPE));
        assert!(
            fixture
                .client()
                .authenticate_manifest(stream, &fixture.request, NOW)
                .await
                .is_err()
        );
        server.await.expect("bounded metadata server");
    }
}

#[tokio::test]
async fn nonshareable_aged_ambiguous_and_oversized_http_metadata_is_rejected() {
    let fixture = Fixture::new();
    let valid = fixture.metadata_response();
    let head_end = valid
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("headers");
    let head = std::str::from_utf8(&valid[..head_end]).expect("ASCII headers");
    for extra in [
        "Age: 1",
        "Vary: Accept-Language",
        "Set-Cookie: session=private",
        "Content-Length: 10",
        "Transfer-Encoding: chunked",
        "Content-Encoding: gzip",
    ] {
        let mut bytes = format!("{head}\r\n{extra}\r\n\r\n").into_bytes();
        bytes.extend_from_slice(&valid[head_end + 4..]);
        let (stream, server) = fixture.origin.respond(bytes);
        assert!(matches!(
            fixture
                .client()
                .authenticate_manifest(stream, &fixture.request, NOW)
                .await,
            Err(OriginError::Response)
        ));
        server.await.expect("rejected header server");
    }
    for cache in ["private", "no-store", "public, max-age=0"] {
        let mut bytes = head.replace("public, max-age=300", cache).into_bytes();
        bytes.extend_from_slice(b"\r\n\r\n");
        bytes.extend_from_slice(&valid[head_end + 4..]);
        let (stream, server) = fixture.origin.respond(bytes);
        assert!(matches!(
            fixture
                .client()
                .authenticate_manifest(stream, &fixture.request, NOW)
                .await,
            Err(OriginError::Response)
        ));
        server.await.expect("private response stopped");
    }
    let date = format_http_date(NOW).expect("Date");
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\nContent-Type: {ORIGIN_DESCRIPTOR_CONTENT_TYPE}\r\nDate: {date}\r\nCache-Control: public, max-age=300\r\n\r\n"
    );
    let (stream, server) = fixture.origin.respond(oversized.into_bytes());
    assert!(matches!(
        fixture
            .client()
            .authenticate_manifest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Response)
    ));
    server.await.expect("oversized response stopped");
    for date in [
        format_http_date(NOW - 400).expect("old Date"),
        "invalid-date".into(),
    ] {
        let bytes = head.replace(&format_http_date(NOW).expect("Date"), &date);
        let mut bytes = format!("{bytes}\r\n\r\n").into_bytes();
        bytes.extend_from_slice(&valid[head_end + 4..]);
        let (stream, server) = fixture.origin.respond(bytes);
        assert!(
            fixture
                .client()
                .authenticate_manifest(stream, &fixture.request, NOW)
                .await
                .is_err()
        );
        server.await.expect("bad HTTP freshness stopped");
    }
}

#[tokio::test]
async fn changed_origin_cannot_replace_the_authorized_version_or_publish_partial_output() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let mut store = fixture.store("consumer");
    let mut changed = fixture.content.clone();
    changed[CHUNK_BYTES + 3] ^= 1;
    let (stream, server) = fixture
        .origin
        .respond(response(&changed, "application/octet-stream"));
    assert!(matches!(
        fixture
            .client()
            .fill_from_origin(stream, &authorized, &mut store, NOW)
            .await,
        Err(OriginError::Content(Error::Integrity(_)))
    ));
    server.await.expect("changed origin stopped");
    assert_eq!(store.usage().entries, 1); // Only the unchanged, authenticated first chunk survives.
    let output = fixture.root.path().join("not-published.bin");
    assert!(
        authorized
            .reassemble_to_file(&mut [&mut store], NOW, &output)
            .is_err()
    );
    assert!(!output.exists());
}

#[tokio::test]
async fn expiry_includes_monotonic_elapsed_time_and_complete_request_deadlines() {
    let fixture = Fixture::new();
    let descriptor = encode_origin_descriptor(
        &fixture.request,
        &fixture.signed,
        &fixture.sender.verifying_key(),
        NOW + 1,
        NOW,
    )
    .expect("short-lived descriptor");
    let (stream, server) = fixture
        .origin
        .respond(response(&descriptor, ORIGIN_DESCRIPTOR_CONTENT_TYPE));
    let authorized = fixture
        .client()
        .authenticate_manifest(stream, &fixture.request, NOW)
        .await
        .expect("initially valid origin metadata");
    server.await.expect("server");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut store = fixture.store("expired");
    let output = fixture.root.path().join("expired.bin");
    assert!(matches!(
        authorized.reassemble_to_file(&mut [&mut store], NOW, &output),
        Err(OriginError::Expired)
    ));
    assert!(!output.exists());

    let client = OriginClient::new(
        fixture.origin.roots(),
        OriginLimits {
            handshake_timeout: Duration::from_millis(20),
            session_timeout: Duration::from_millis(30),
            ..OriginLimits::default()
        },
    )
    .expect("bounded client");
    let (stream, _silent_peer) = duplex(4096);
    assert!(matches!(
        client
            .authenticate_manifest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Timeout)
    ));
}

#[tokio::test]
async fn origin_range_fetches_disjoint_missing_runs_without_retrieving_present_chunks() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let mut store = fixture.store("ranged");
    store
        .put_verified(
            *authorized.manifest().chunks()[1].id(),
            &fixture.content[CHUNK_BYTES..2 * CHUNK_BYTES],
        )
        .expect("middle chunk from replica");
    for (start, end, complete) in [
        (0, CHUNK_BYTES - 1, false),
        (2 * CHUNK_BYTES, fixture.content.len() - 1, true),
    ] {
        let expected = authorized
            .next_missing_range(&mut store, NOW)
            .expect("cache scan")
            .expect("missing range");
        assert_eq!(
            (expected.start(), expected.end_inclusive(), expected.total()),
            (start as u64, end as u64, fixture.content.len() as u64)
        );
        let (stream, server) = fixture.origin.respond(range_response(
            &fixture.content[start..=end],
            start,
            end,
            fixture.content.len(),
        ));
        let progress = fixture
            .client()
            .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
            .await
            .expect("exact authenticated 206");
        assert_eq!(progress.requested, Some(expected));
        assert_eq!(progress.bytes_received, (end - start + 1) as u64);
        assert_eq!(progress.chunks_verified, 1);
        assert_eq!(progress.complete, complete);
        assert!(!progress.full_response);
        let request = String::from_utf8(server.await.expect("range server")).expect("request");
        assert!(request.contains(&format!("\r\nRange: bytes={start}-{end}\r\n")));
        assert!(!request.contains("If-Range"));
    }
    assert!(
        authorized
            .next_missing_range(&mut store, NOW)
            .expect("complete scan")
            .is_none()
    );
    let (stream, mut untouched) = duplex(4096);
    let progress = fixture
        .client()
        .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
        .await
        .expect("complete cache does not use stream");
    assert!(progress.complete);
    assert_eq!(
        (
            progress.bytes_received,
            progress.chunks_verified,
            progress.requested
        ),
        (0, 0, None)
    );
    assert_eq!(
        untouched
            .read(&mut [0; 1])
            .await
            .expect("no TLS or request bytes"),
        0
    );
    let output = fixture.root.path().join("range-output.bin");
    authorized
        .reassemble_to_file(&mut [&mut store], NOW, &output)
        .expect("complete origin-authorized output");
    assert_eq!(fs::read(output).expect("output bytes"), fixture.content);
}

#[tokio::test]
async fn origin_range_groups_adjacent_missing_chunks_and_counts_ignored_range_full_response() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    for full in [false, true] {
        let mut store = fixture.store(if full {
            "range-ignored"
        } else {
            "adjacent-range"
        });
        store
            .put_verified(
                *authorized.manifest().chunks()[2].id(),
                &fixture.content[2 * CHUNK_BYTES..],
            )
            .expect("last chunk from replica");
        let expected = authorized
            .next_missing_range(&mut store, NOW)
            .expect("scan")
            .expect("missing");
        assert_eq!(
            (
                expected.start(),
                expected.end_inclusive(),
                expected.length()
            ),
            (0, 2 * CHUNK_BYTES as u64 - 1, 2 * CHUNK_BYTES as u64)
        );
        let bytes = if full {
            response(&fixture.content, "application/octet-stream")
        } else {
            range_response(
                &fixture.content[..2 * CHUNK_BYTES],
                0,
                2 * CHUNK_BYTES - 1,
                fixture.content.len(),
            )
        };
        let (stream, server) = fixture.origin.respond(bytes);
        let progress = fixture
            .client()
            .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
            .await
            .expect("range or verified complete response");
        server.await.expect("server");
        assert_eq!(progress.requested, Some(expected));
        assert_eq!(progress.full_response, full);
        assert_eq!(progress.chunks_verified, if full { 3 } else { 2 });
        assert_eq!(
            progress.bytes_received,
            if full {
                fixture.content.len() as u64
            } else {
                expected.length()
            }
        );
        assert!(progress.complete);
    }
}

#[tokio::test]
async fn https_resume_reopens_partial_tls_download_and_reauthenticates_original_expiry() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let cache_path = fixture.root.path().join("resume");
    let mut store = fixture.store("resume");
    let mut truncated = response(&fixture.content, "application/octet-stream");
    truncated.truncate(truncated.len() - fixture.content.len() + CHUNK_BYTES);
    let (stream, server) = fixture.origin.respond(truncated);
    assert!(
        fixture
            .client()
            .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
            .await
            .is_err()
    );
    server.await.expect("truncated TLS response finished");
    assert_eq!(
        store.usage().entries,
        1,
        "the verified prefix survives the transfer error"
    );
    let output = fixture.root.path().join("resumed.bin");
    assert!(
        authorized
            .reassemble_to_file(&mut [&mut store], NOW, &output)
            .is_err()
    );
    assert!(!output.exists());
    drop((store, authorized));

    let later = NOW + 10;
    let (stream, server) = fixture.origin.respond(fixture.metadata_response());
    let authorized = fixture
        .client()
        .authenticate_manifest(stream, &fixture.request, later)
        .await
        .expect("fresh origin TLS, not authority from persisted chunks");
    assert!(
        server
            .await
            .unwrap()
            .starts_with(format!("GET {METADATA} HTTP/1.1\r\n").as_bytes())
    );
    let mut store = ChunkStore::open(&cache_path, limits()).expect("owned persisted cache");
    let missing = authorized
        .next_missing_range(&mut store, later)
        .unwrap()
        .unwrap();
    assert_eq!(missing.start(), CHUNK_BYTES as u64);
    let end = fixture.content.len() - 1;
    let (stream, server) = fixture.origin.respond(range_response(
        &fixture.content[CHUNK_BYTES..],
        CHUNK_BYTES,
        end,
        fixture.content.len(),
    ));
    let progress = fixture
        .client()
        .fill_next_missing_from_origin(stream, &authorized, &mut store, later)
        .await
        .expect("resume only the missing exact range");
    let request = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(request.contains(&format!("\r\nRange: bytes={CHUNK_BYTES}-{end}\r\n")));
    assert_eq!(
        progress.bytes_received,
        (fixture.content.len() - CHUNK_BYTES) as u64
    );
    assert_eq!(progress.chunks_verified, 2);
    assert!(progress.complete);
    authorized
        .reassemble_to_file(&mut [&mut store], later, &output)
        .unwrap();
    assert_eq!(fs::read(output).unwrap(), fixture.content);
    assert!(
        authorized
            .next_missing_range(&mut store, NOW + 200)
            .is_err(),
        "cache reopening and a second metadata request must not renew original expiry"
    );
}

#[tokio::test]
async fn origin_range_rejects_wrong_offsets_total_framing_freshness_corruption_and_truncation() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let start = CHUNK_BYTES;
    let end = 2 * CHUNK_BYTES - 1;
    let total = fixture.content.len();
    let valid = range_response(&fixture.content[start..=end], start, end, total);
    let split = valid
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("headers")
        + 4;
    let head = std::str::from_utf8(&valid[..split]).expect("headers");
    let content_range = format!("Content-Range: bytes {start}-{end}/{total}\r\n");
    let headers = [
        head.replace(
            &content_range,
            &format!("Content-Range: bytes {}-{end}/{total}\r\n", start + 1),
        ),
        head.replace(
            &content_range,
            &format!("Content-Range: bytes {start}-{}/{total}\r\n", end - 1),
        ),
        head.replace(
            &content_range,
            &format!("Content-Range: bytes {start}-{end}/{}\r\n", total + 1),
        ),
        head.replace(
            &content_range,
            &format!("Content-Range: bytes {start}-{end}/*\r\n"),
        ),
        head.replace(&content_range, ""),
        head.replace("206 Partial Content", "200 OK"),
        head.replace(
            "application/octet-stream",
            "multipart/byteranges;boundary=x",
        ),
        head.replace(
            &format!("Content-Length: {CHUNK_BYTES}"),
            "Content-Length: 1",
        ),
        head.replace(
            &format_http_date(NOW).expect("Date"),
            &format_http_date(NOW - 400).expect("stale Date"),
        ),
    ];
    let mut cases: Vec<Vec<u8>> = headers
        .into_iter()
        .map(|header| {
            let mut bytes = header.into_bytes();
            bytes.extend_from_slice(&valid[split..]);
            bytes
        })
        .collect();
    let mut corrupt = valid.clone();
    *corrupt.last_mut().expect("payload") ^= 1;
    cases.push(corrupt);
    cases.push(valid[..valid.len() - 1].to_vec());
    for (index, bytes) in cases.into_iter().enumerate() {
        let mut store = fixture.store(&format!("bad-range-{index}"));
        put_outer_chunks(&fixture, &authorized, &mut store);
        let (stream, server) = fixture.origin.respond(bytes);
        assert!(
            fixture
                .client()
                .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
                .await
                .is_err()
        );
        server.await.expect("rejected range stopped");
        assert_eq!(store.usage().entries, 2);
        let output = fixture
            .root
            .path()
            .join(format!("bad-range-output-{index}"));
        assert!(
            authorized
                .reassemble_to_file(&mut [&mut store], NOW, &output)
                .is_err()
        );
        assert!(!output.exists());
    }
    let mut store = fixture.store("full-request-rejects-partial");
    let (stream, server) = fixture.origin.respond(valid);
    assert!(matches!(
        fixture
            .client()
            .fill_from_origin(stream, &authorized, &mut store, NOW)
            .await,
        Err(OriginError::Response)
    ));
    server.await.expect("full request does not accept 206");
}

#[tokio::test]
async fn origin_range_rejects_unfit_quota_expiry_and_silent_stream_without_false_completion() {
    let fixture = Fixture::new();
    let authorized = fixture.authenticate().await;
    let mut small = ChunkStore::create(
        &fixture.root.path().join("too-small"),
        CacheLimits {
            max_bytes: CHUNK_BYTES as u64,
            max_entries: 1,
            min_free_bytes: 0,
        },
    )
    .expect("small cache");
    assert!(matches!(
        authorized.next_missing_range(&mut small, NOW),
        Err(OriginError::Content(Error::Quota))
    ));
    let (stream, mut untouched) = duplex(4096);
    assert!(matches!(
        fixture
            .client()
            .fill_next_missing_from_origin(stream, &authorized, &mut small, NOW)
            .await,
        Err(OriginError::Content(Error::Quota))
    ));
    assert_eq!(
        untouched
            .read(&mut [0; 1])
            .await
            .expect("no network for impossible quota"),
        0
    );
    let mut store = fixture.store("expired-range");
    let (stream, mut untouched) = duplex(4096);
    assert!(matches!(
        fixture
            .client()
            .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW + 200)
            .await,
        Err(OriginError::Expired)
    ));
    assert_eq!(
        untouched
            .read(&mut [0; 1])
            .await
            .expect("no network after expiry"),
        0
    );
    let client = OriginClient::new(
        fixture.origin.roots(),
        OriginLimits {
            handshake_timeout: Duration::from_millis(20),
            session_timeout: Duration::from_millis(30),
            ..OriginLimits::default()
        },
    )
    .expect("deadline client");
    let (stream, _silent_peer) = duplex(4096);
    assert!(matches!(
        client
            .fill_next_missing_from_origin(stream, &authorized, &mut store, NOW)
            .await,
        Err(OriginError::Timeout)
    ));
    assert_eq!(store.usage().entries, 0);
}

#[test]
fn noncanonical_cross_origin_and_credentialed_resource_requests_are_not_supported() {
    for resource in [
        "http://destination.volparossa.test/asset.bin",
        "https://user:password@destination.volparossa.test/asset.bin",
        "https://destination.volparossa.test/asset.bin#fragment",
        "https://47.163.4.2/asset.bin",
    ] {
        assert!(OriginRequest::new(resource, METADATA).is_err());
    }
    for metadata in [
        "//other.test/manifest",
        "/../manifest",
        "/manifest#fragment",
        "/bad\r\nHeader: x",
    ] {
        assert!(OriginRequest::new(URL, metadata).is_err());
    }
}

struct Fixture {
    root: tempfile::TempDir,
    source: ChunkStore,
    sender: SigningKey,
    signed: SignedManifest,
    content: Vec<u8>,
    request: OriginRequest,
    origin: TestOrigin,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let mut source = ChunkStore::create(&root.path().join("source"), limits()).expect("source");
        let sender = SigningKey::generate(&mut rand_core::OsRng);
        let mut content = vec![0x31; CHUNK_BYTES];
        content.extend(vec![0x42; CHUNK_BYTES]);
        content.extend(b"cooperative origin, not a peer claim");
        let signed = publish(
            &mut content.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "opaque-public-binary".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: content.len() as u64,
                validity: Validity {
                    created: NOW,
                    expires: NOW + 600,
                },
            },
            &sender,
            &mut source,
        )
        .expect("native manifest");
        Self {
            root,
            source,
            sender,
            signed,
            content,
            request: OriginRequest::new(URL, METADATA).expect("request"),
            origin: TestOrigin::new("destination.volparossa.test"),
        }
    }
    fn client(&self) -> OriginClient {
        OriginClient::new(self.origin.roots(), OriginLimits::default()).expect("trusted TLS client")
    }
    fn descriptor(&self) -> Vec<u8> {
        encode_origin_descriptor(
            &self.request,
            &self.signed,
            &self.sender.verifying_key(),
            NOW + 200,
            NOW,
        )
        .expect("origin descriptor")
    }
    fn metadata_response(&self) -> Vec<u8> {
        response(&self.descriptor(), ORIGIN_DESCRIPTOR_CONTENT_TYPE)
    }
    fn store(&self, name: &str) -> ChunkStore {
        ChunkStore::create(&self.root.path().join(name), limits()).expect("cache")
    }
    async fn authenticate(&self) -> OriginAuthorizedManifest {
        let (stream, server) = self.origin.respond(self.metadata_response());
        let authorized = self
            .client()
            .authenticate_manifest(stream, &self.request, NOW)
            .await
            .expect("real origin TLS authentication");
        let request = server.await.expect("origin task");
        assert!(request.starts_with(format!("GET {METADATA} HTTP/1.1\r\n").as_bytes()));
        assert!(!request.windows(7).any(|bytes| bytes == b"Cookie:"));
        assert!(!request.windows(14).any(|bytes| bytes == b"Authorization:"));
        authorized
    }
}

struct TestOrigin {
    certificate: rustls::pki_types::CertificateDer<'static>,
    configuration: Arc<ServerConfig>,
}
impl TestOrigin {
    fn new(name: &str) -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![name.into()]).expect("fresh test certificate");
        let certificate = cert.der().clone();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS13")
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
                )
                .expect("server certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            certificate,
            configuration: Arc::new(config),
        }
    }
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(self.certificate.clone())
            .expect("independent application trust root");
        roots
    }
    fn respond(&self, response: Vec<u8>) -> (DuplexStream, tokio::task::JoinHandle<Vec<u8>>) {
        let (client, peer) = duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(self.configuration.clone());
        let server = tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(peer).await else {
                return Vec::new();
            };
            let mut request = Vec::new();
            while request.len() < 16 * 1024 && !request.ends_with(b"\r\n\r\n") {
                let Ok(byte) = tls.read_u8().await else {
                    return request;
                };
                request.push(byte);
            }
            let _ = tls.write_all(&response).await;
            let _ = tls.shutdown().await;
            request
        });
        (client, server)
    }
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 10,
        min_free_bytes: 0,
    }
}
fn response(body: &[u8], content_type: &str) -> Vec<u8> {
    let date = format_http_date(NOW).expect("HTTP Date");
    let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nDate: {date}\r\nCache-Control: public, max-age=300\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn range_response(body: &[u8], start: usize, end: usize, total: usize) -> Vec<u8> {
    let date = format_http_date(NOW).expect("HTTP Date");
    let mut bytes = format!("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nDate: {date}\r\nCache-Control: public, max-age=300\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn put_outer_chunks(
    fixture: &Fixture,
    authorized: &OriginAuthorizedManifest,
    store: &mut ChunkStore,
) {
    for index in [0, 2] {
        let start = index * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(fixture.content.len());
        store
            .put_verified(
                *authorized.manifest().chunks()[index].id(),
                &fixture.content[start..end],
            )
            .expect("valid outer cached chunks");
    }
}
