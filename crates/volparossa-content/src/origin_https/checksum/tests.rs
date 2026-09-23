//! Own-origin TLS over duplex; no host network, origin substitution or peer authority.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    time::Instant,
};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::{
    CHUNK_BYTES, CacheLimits,
    origin_https::{BINARY_TYPE, OriginLimits, format_http_date},
};

const NOW: u64 = 1_800_000_000;
const URL: &str = "https://checksum.volparossa.test:18443/releases/public.bin";
const PATH: &str = "/releases/SHA256SUMS";

struct Fixture {
    root: tempfile::TempDir,
    client: OriginClient,
    server: TlsAcceptor,
    request: OriginRequest,
    body: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["checksum.volparossa.test".into()]).unwrap();
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
            body: vec![71; CHUNK_BYTES + 123],
        }
    }

    fn checksum(&self) -> Vec<u8> {
        format!("{}  public.bin\n", hex::encode(Sha256::digest(&self.body))).into_bytes()
    }

    fn response(kind: &str, length: usize, body: &[u8], freshness: u64, extra: &str) -> Vec<u8> {
        let date = format_http_date(NOW).unwrap();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {length}\r\nDate: {date}\r\nCache-Control: public, max-age={freshness}\r\n{extra}Connection: close\r\n\r\n").into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn respond(&self, response: Vec<u8>) -> (DuplexStream, tokio::task::JoinHandle<Vec<u8>>) {
        let (client, server) = duplex(4096);
        let acceptor = self.server.clone();
        let task = tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(server).await else {
                return Vec::new();
            };
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let mut request = Vec::new();
            while request.len() < super::super::MAX_HEADER_BYTES && !request.ends_with(b"\r\n\r\n")
            {
                let Ok(byte) = tls.read_u8().await else {
                    return request;
                };
                request.push(byte);
            }
            let _ = tls.write_all(&response).await;
            let _ = tls.shutdown().await;
            request
        });
        (client, task)
    }

    async fn token(&self, freshness: u64) -> OriginAuthenticatedChecksum {
        let body = self.checksum();
        let (stream, task) = self.respond(Self::response(
            CHECKSUM_TYPE,
            body.len(),
            &body,
            freshness,
            "",
        ));
        let token = self
            .client
            .authenticate_checksum(stream, &self.request, PATH, NOW)
            .await
            .unwrap();
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /releases/SHA256SUMS HTTP/1.1\r\n"));
        assert!(request.contains("Accept: text/plain\r\n"));
        assert!(!request.contains("Cookie:") && !request.contains("Authorization:"));
        token
    }

    async fn authorize(
        &self,
        checksum_freshness: u64,
        resource_freshness: u64,
    ) -> OriginAuthorizedDigest {
        let token = self.token(checksum_freshness).await;
        let (stream, task) = self.respond(Self::response(
            BINARY_TYPE,
            self.body.len(),
            &[],
            resource_freshness,
            "",
        ));
        let digest = self
            .client
            .authenticate_checksum_resource(stream, token, NOW)
            .await
            .unwrap();
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(request.starts_with("HEAD /releases/public.bin HTTP/1.1\r\n"));
        assert!(!request.contains("Cookie:") && !request.contains("Authorization:"));
        digest
    }

    fn store(&self, name: &str) -> crate::ChunkStore {
        crate::ChunkStore::create(
            &self.root.path().join(name),
            CacheLimits {
                max_bytes: (4 * CHUNK_BYTES) as u64,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap()
    }
}

#[test]
fn checksum_selectors_and_rows_are_exact_bounded_and_not_peer_hash_claims() {
    let request = OriginRequest::resource(URL).unwrap();
    assert!(request.validate_checksum_path(PATH).is_ok());
    for path in [
        "https://other.test/releases/SHA256SUMS",
        "//other.test/releases/SHA256SUMS",
        "/other/SHA256SUMS",
        "/releases/../SHA256SUMS",
        "/releases/SHA256SUMS?variant=1",
        "/releases/%53HA256SUMS",
        "/releases/public.bin",
        "/releases/a\\b",
    ] {
        assert!(request.validate_checksum_path(path).is_err(), "{path}");
    }
    for resource in [
        "https://checksum.volparossa.test/releases/public.bin?variant=1",
        "https://checksum.volparossa.test/releases/a%20b",
        "https://checksum.volparossa.test/releases/a%2fb",
        "https://checksum.volparossa.test/releases/-",
        "https://checksum.volparossa.test/releases/",
    ] {
        assert!(
            OriginRequest::resource(resource)
                .unwrap()
                .validate_checksum_path(PATH)
                .is_err()
        );
    }
    let hash = "ab".repeat(32);
    for marker in ["  ", " *"] {
        assert_eq!(
            selected_hash(
                format!("{hash}{marker}public.bin\n").as_bytes(),
                "public.bin"
            )
            .unwrap(),
            [0xab; 32]
        );
    }
    for text in [
        format!("{hash}  public.bin\n{hash}  public.bin\n"),
        format!("{hash}  other.bin\n"),
        format!("{}  public.bin\n", "z".repeat(64)),
        format!("\\{hash}  public.bin\n"),
        format!("{hash}  ./public.bin\n"),
        format!("{hash}  public.bin\nmalformed-other-row\n"),
    ] {
        assert!(selected_hash(text.as_bytes(), "public.bin").is_err());
    }
    assert!(
        selected_hash(
            &vec![b'x'; usize::try_from(MAX_CHECKSUM_BYTES).unwrap() + 1],
            "public.bin"
        )
        .is_err()
    );
}

#[tokio::test]
async fn real_checksum_get_then_head_preserves_earliest_expiry_and_complete_body_verification() {
    let fixture = Fixture::new();
    let authority = fixture.authorize(60, 120).await;
    assert_eq!(
        authority.object_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&fixture.body))
    );
    assert_eq!(authority.length(), fixture.body.len() as u64);
    assert_eq!(authority.checksum_path(), Some(PATH));
    assert_eq!(
        authority.authority_body_bytes(),
        fixture.checksum().len() as u64
    );
    assert_eq!(authority.check_validity(NOW).unwrap(), NOW + 60);
    let identity = SigningKey::generate(&mut rand_core::OsRng);
    let mut store = fixture.store("origin");
    let (stream, task) = fixture.respond(Fixture::response(
        BINARY_TYPE,
        fixture.body.len(),
        &fixture.body,
        120,
        "",
    ));
    let signed = fixture
        .client
        .fill_digest_from_origin(stream, &authority, &mut store, &identity, NOW)
        .await
        .unwrap();
    assert!(
        String::from_utf8(task.await.unwrap())
            .unwrap()
            .starts_with("GET /releases/public.bin HTTP/1.1\r\n")
    );
    let manifest = authority.verify_candidate(&signed, NOW).unwrap();
    assert_eq!(
        authority.verify_cached(&manifest, &mut store, NOW).unwrap(),
        fixture.body.len() as u64
    );
    assert_eq!(manifest.validity().expires, NOW + 60);
    let output = fixture.root.path().join("output.bin");
    authority
        .reassemble_to_file(&manifest, &mut [&mut store], NOW, &output)
        .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), fixture.body);
    assert!(authority.check_validity(NOW + 60).is_err());
    let shorter_resource = fixture.authorize(120, 30).await;
    assert_eq!(shorter_resource.check_validity(NOW).unwrap(), NOW + 30);
}

#[tokio::test]
async fn checksum_tls_rejects_wrong_origin_duplicate_rows_private_and_conflicting_resource() {
    let fixture = Fixture::new();
    let body = fixture.checksum();
    let wrong = OriginRequest::resource("https://other.test/releases/public.bin").unwrap();
    let (stream, task) =
        fixture.respond(Fixture::response(CHECKSUM_TYPE, body.len(), &body, 120, ""));
    assert!(matches!(
        fixture
            .client
            .authenticate_checksum(stream, &wrong, PATH, NOW)
            .await,
        Err(OriginError::Tls)
    ));
    task.await.unwrap();
    let duplicate = [body.clone(), body.clone()].concat();
    for (body, extra) in [
        (duplicate, ""),
        (body.clone(), "Set-Cookie: secret=yes\r\n"),
    ] {
        let (stream, task) = fixture.respond(Fixture::response(
            CHECKSUM_TYPE,
            body.len(),
            &body,
            120,
            extra,
        ));
        assert!(
            fixture
                .client
                .authenticate_checksum(stream, &fixture.request, PATH, NOW)
                .await
                .is_err()
        );
        task.await.unwrap();
    }
    for extra in [
        "Repr-Digest: sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:\r\n",
        "Set-Cookie: private=yes\r\n",
    ] {
        let token = fixture.token(120).await;
        let (stream, task) = fixture.respond(Fixture::response(
            BINARY_TYPE,
            fixture.body.len(),
            &[],
            120,
            extra,
        ));
        assert!(
            fixture
                .client
                .authenticate_checksum_resource(stream, token, NOW)
                .await
                .is_err()
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn checksum_expiry_cannot_be_renewed_by_second_head_or_wrong_resource_bytes() {
    let fixture = Fixture::new();
    let mut token = fixture.token(30).await;
    token.clock.start = Instant::now() - Duration::from_secs(31);
    let (stream, server) = duplex(1024);
    assert!(matches!(
        fixture
            .client
            .authenticate_checksum_resource(stream, token, NOW)
            .await,
        Err(OriginError::Expired)
    ));
    drop(server);
    let authority = fixture.authorize(120, 120).await;
    let mut store = fixture.store("wrong-body");
    let wrong = vec![88; fixture.body.len()];
    let (stream, task) =
        fixture.respond(Fixture::response(BINARY_TYPE, wrong.len(), &wrong, 120, ""));
    let result = fixture
        .client
        .fill_digest_from_origin(
            stream,
            &authority,
            &mut store,
            &SigningKey::generate(&mut rand_core::OsRng),
            NOW,
        )
        .await;
    assert!(matches!(result, Err(OriginError::DigestMismatch)));
    task.await.unwrap();
}
