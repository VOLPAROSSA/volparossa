//! Actual TLS over duplex, with an explicit library clock; no network or elapsed-VM claim.

use std::sync::Arc;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::io::{DuplexStream, duplex};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::{
    CacheLimits,
    origin_https::{MAX_HEADER_BYTES, OriginLimits, format_http_date},
    publish,
};

const NOW: u64 = 1_800_000_000;
const URL: &str = "https://digest.volparossa.test:18443/public.bin";
const ABC_DIGEST: &str = "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:";

struct Fixture {
    root: tempfile::TempDir,
    signer: SigningKey,
    client: OriginClient,
    server: TlsAcceptor,
    request: OriginRequest,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["digest.volparossa.test".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
                )
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            root: tempfile::tempdir().unwrap(),
            signer: SigningKey::generate(&mut rand_core::OsRng),
            client: OriginClient::new(
                roots,
                OriginLimits {
                    handshake_timeout: Duration::from_secs(2),
                    session_timeout: Duration::from_secs(5),
                    ..OriginLimits::default()
                },
            )
            .unwrap(),
            server: TlsAcceptor::from(Arc::new(config)),
            request: OriginRequest::resource(URL).unwrap(),
            bytes: vec![71; CHUNK_BYTES + 123],
        }
    }

    fn store(&self, name: &str) -> ChunkStore {
        ChunkStore::create(
            &self.root.path().join(name),
            CacheLimits {
                max_bytes: 4 * CHUNK_BYTES as u64,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap()
    }

    fn response(&self, digest: Option<&str>, body: Option<&[u8]>) -> Vec<u8> {
        let digest = digest.map_or_else(String::new, |digest| format!("Repr-Digest: {digest}\r\n"));
        let date = format_http_date(NOW).unwrap();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nDate: {date}\r\nCache-Control: public, max-age=120\r\n{digest}Connection: close\r\n\r\n", self.bytes.len()).into_bytes();
        response.extend_from_slice(body.unwrap_or_default());
        response
    }

    fn respond(&self, response: Vec<u8>) -> (DuplexStream, tokio::task::JoinHandle<Vec<u8>>) {
        let (client, server) = duplex(4096);
        let acceptor = self.server.clone();
        let task = tokio::spawn(async move {
            let mut tls = acceptor.accept(server).await.unwrap();
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let mut request = Vec::new();
            while request.len() < MAX_HEADER_BYTES && !request.ends_with(b"\r\n\r\n") {
                request.push(tls.read_u8().await.unwrap());
            }
            let _ = tls.write_all(&response).await;
            let _ = tls.shutdown().await;
            request
        });
        (client, task)
    }

    fn digest(&self) -> String {
        format!("sha-256=:{}:", encode64(&Sha256::digest(&self.bytes)))
    }

    async fn authorize(&self) -> OriginAuthorizedDigest {
        let (stream, task) = self.respond(self.response(Some(&self.digest()), None));
        let authorized = self
            .client
            .authenticate_digest(stream, &self.request, NOW)
            .await
            .unwrap();
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(request.starts_with("HEAD /public.bin HTTP/1.1\r\n"));
        assert!(request.contains("Want-Repr-Digest: sha-256=10\r\n"));
        assert!(!request.contains("Cookie:") && !request.contains("Authorization:"));
        assert!(self.request.metadata_path.is_none());
        authorized
    }

    fn publish(&self, store: &mut ChunkStore, bytes: &[u8]) -> SignedManifest {
        let mut input = bytes;
        publish(
            &mut input,
            Publication {
                metadata: Metadata {
                    name: "untrusted-index".into(),
                    content_type: BINARY_TYPE.into(),
                    revision: 1,
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: NOW,
                    expires: NOW + 600,
                },
            },
            &self.signer,
            store,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn real_head_tls_binds_complete_peer_bytes_and_streaming_get_without_manifest_metadata() {
    let fixture = Fixture::new();
    let mut authorized = fixture.authorize().await;
    assert_eq!(authorized.length(), fixture.bytes.len() as u64);
    assert_eq!(
        authorized.object_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&fixture.bytes))
    );
    assert_eq!(authorized.check_validity(NOW).unwrap(), NOW + 120);
    let mut peer = fixture.store("peer");
    let signed = fixture.publish(&mut peer, &fixture.bytes);
    let candidate = authorized.verify_candidate(&signed, NOW).unwrap();
    assert_eq!(
        authorized
            .verify_cached(&candidate, &mut peer, NOW)
            .unwrap(),
        authorized.length()
    );
    let output = fixture.root.path().join("peer-output");
    authorized
        .reassemble_to_file(&candidate, &mut [&mut peer], NOW, &output)
        .unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), fixture.bytes);
    assert!(
        authorized
            .reassemble_to_file(&candidate, &mut [&mut peer], NOW, &output)
            .is_err()
    );
    let mut fallback = fixture.store("fallback");
    let (stream, task) = fixture.respond(fixture.response(None, Some(&fixture.bytes)));
    let local = fixture
        .client
        .fill_digest_from_origin(stream, &authorized, &mut fallback, &fixture.signer, NOW)
        .await
        .unwrap();
    let request = String::from_utf8(task.await.unwrap()).unwrap();
    assert!(request.starts_with("GET /public.bin HTTP/1.1\r\n"));
    assert!(!request.contains("Range:") && !request.contains("metadata"));
    let local = authorized.verify_candidate(&local, NOW).unwrap();
    assert_eq!(local.validity().expires, NOW + 120);
    assert_eq!(local.chunks().len(), 2);
    assert_eq!(
        authorized
            .verify_cached(&local, &mut fallback, NOW)
            .unwrap(),
        authorized.length()
    );
    assert!(authorized.check_validity(NOW + 120).is_err());
    // Advance the internal monotonic observation, not the wall clock, without sleeping.
    authorized.clock.start = Instant::now() - Duration::from_secs(121);
    assert!(
        authorized
            .verify_cached(&local, &mut fallback, NOW)
            .is_err()
    );
}

#[tokio::test]
async fn digest_unavailable_head_body_and_false_whole_object_claims_never_authorize_output() {
    assert_eq!(
        parse_digest(Some(ABC_DIGEST)).unwrap(),
        <[u8; 32]>::from(Sha256::digest(b"abc"))
    );
    let fixture = Fixture::new();
    for response in [
        fixture.response(None, None),
        String::from_utf8(fixture.response(Some(ABC_DIGEST), None))
            .unwrap()
            .replace("Repr-Digest:", "Content-Digest:")
            .into_bytes(),
    ] {
        let (stream, task) = fixture.respond(response);
        assert!(matches!(
            fixture
                .client
                .authenticate_digest(stream, &fixture.request, NOW)
                .await,
            Err(OriginError::DigestUnavailable)
        ));
        task.await.unwrap();
    }
    let (stream, task) = fixture.respond(fixture.response(Some(&fixture.digest()), Some(b"x")));
    assert!(matches!(
        fixture
            .client
            .authenticate_digest(stream, &fixture.request, NOW)
            .await,
        Err(OriginError::Response)
    ));
    task.await.unwrap();
    let authorized = fixture.authorize().await;
    assert_false_candidate(&fixture, &authorized);
    let mut fallback = fixture.store("bad-get");
    let changed = vec![72; fixture.bytes.len()];
    let (stream, task) = fixture.respond(fixture.response(None, Some(&changed)));
    assert!(matches!(
        fixture
            .client
            .fill_digest_from_origin(stream, &authorized, &mut fallback, &fixture.signer, NOW,)
            .await,
        Err(OriginError::DigestMismatch)
    ));
    task.await.unwrap();
    for value in [
        "sha-256=:AAAA:",
        "sha-256=:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=:",
    ] {
        assert!(parse_digest(Some(value)).is_err());
    }
}

fn assert_false_candidate(fixture: &Fixture, authorized: &OriginAuthorizedDigest) {
    let mut wrong_store = fixture.store("false-peer");
    let wrong = fixture.publish(&mut wrong_store, &vec![72; fixture.bytes.len()]);
    assert!(matches!(
        authorized.verify_candidate(&wrong, NOW),
        Err(OriginError::DigestMismatch)
    ));
    let wrong = wrong.verify(&fixture.signer.verifying_key(), NOW).unwrap();
    // A malicious peer can sign a false whole-hash claim alongside internally hashed chunks.
    let dishonest = SignedManifest::sign(
        Publication {
            metadata: wrong.metadata().clone(),
            length: wrong.length(),
            validity: wrong.validity(),
        },
        wrong.chunks().to_vec(),
        *authorized.object_sha256(),
        &fixture.signer,
    )
    .unwrap();
    let transport = authorized.verify_candidate(&dishonest, NOW).unwrap();
    assert!(
        authorized
            .verify_cached(&transport, &mut wrong_store, NOW)
            .is_err()
    );
    let output = fixture.root.path().join("must-not-appear");
    assert!(
        authorized
            .reassemble_to_file(&transport, &mut [&mut wrong_store], NOW, &output)
            .is_err()
    );
    assert!(!output.exists());
}

fn encode64(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for group in bytes.chunks(3) {
        let a = group[0];
        let b = group.get(1).copied().unwrap_or(0);
        let c = group.get(2).copied().unwrap_or(0);
        output.push(char::from(alphabet[usize::from(a >> 2)]));
        output.push(char::from(alphabet[usize::from(((a & 3) << 4) | (b >> 4))]));
        output.push(if group.len() > 1 {
            char::from(alphabet[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        output.push(if group.len() > 2 {
            char::from(alphabet[usize::from(c & 63)])
        } else {
            '='
        });
    }
    output
}
