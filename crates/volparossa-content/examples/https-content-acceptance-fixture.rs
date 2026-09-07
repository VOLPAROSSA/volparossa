//! Explicit disposable HTTPS-origin/cache fixture. Never run sockets on the host network.
//!
//! The consumer trusts only its application-local fixture CA, authenticates metadata over
//! actual origin TLS, and keeps that authority in memory across peer retrieval/fallback.
//! No browser hook, peer discovery, system CA installation or generic HTTPS claim is made.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use volparossa_content::origin_https::{
    OriginClient, OriginLimits, OriginRequest, encode_origin_descriptor, format_http_date,
};
use volparossa_content::transfer::{TransferLimits, pull_from_peer, serve_peer};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, MAX_MANIFEST_BYTES, Metadata, Publication,
    SignedManifest, Validity, VerifiedManifest, publish,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const HOST: &str = "destination.volparossa.test";
const RESOURCE: &str = "https://destination.volparossa.test:18443/asset.bin";
const METADATA: &str = "/.well-known/volparossa/content/asset";
const OBJECT_BYTES: usize = 2 * 1024 * 1024 + 123;
const OBJECT_SHA256: &str = "add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767";
const DEADLINE: Duration = Duration::from_secs(90);

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, root] if mode == "seed" => seed(Path::new(root)),
        [mode, root, listen, cert, report, connections] if mode == "origin" => {
            let count = connections.parse()?;
            if !(1..=8).contains(&count) {
                return Err("origin connection count must be 1..8".into());
            }
            origin(Path::new(root), listen.parse()?, Path::new(cert), Path::new(report), count).await
        }
        [mode, root, listen, variant, report] if mode == "peers" => {
            peers(Path::new(root), listen.parse()?, variant, Path::new(report)).await
        }
        [mode, root, origin, cert, peer, variant, report] if mode == "consume" => {
            consume(Path::new(root), origin.parse()?, Path::new(cert), peer.parse()?, variant, Path::new(report)).await
        }
        _ => Err("usage: seed ROOT | origin ROOT LISTEN CERT REPORT CONNECTIONS | peers ROOT LISTEN complete|missing REPORT | consume CLIENT_ROOT ORIGIN CERT PEER complete|missing REPORT".into()),
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 16 * CHUNK_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 1024 * 1024,
    }
}

fn seed(root: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let mut store = ChunkStore::create(&root.join("origin-cache"), limits())?;
    let mut first = ChunkStore::create(&root.join("replica-a"), limits())?;
    let mut second = ChunkStore::create(&root.join("replica-b"), limits())?;
    let mut bytes = Vec::with_capacity(OBJECT_BYTES);
    for index in 0_u8..8 {
        bytes.extend(vec![b'A' + index; CHUNK_BYTES]);
    }
    bytes.extend(vec![b'Z'; 123]);
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let time = now()?;
    let signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "https-origin-fixture".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: time,
                expires: time + 3600,
            },
        },
        &signing_key,
        &mut store,
    )?;
    let trusted = signing_key.verifying_key();
    let manifest = signed.verify(&trusted, time)?;
    let descriptor = encode_origin_descriptor(
        &OriginRequest::new(RESOURCE, METADATA)?,
        &signed,
        &trusted,
        time + 300,
        time,
    )?;
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = store.get(chunk.id())?.ok_or("origin chunk missing")?;
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target.put_verified(*chunk.id(), &bytes)?;
    }
    // Signing key is never persisted. Only the origin/provider fixtures receive these files.
    write_new(&root.join("object.bin"), &bytes)?;
    write_new(&root.join("manifest.bin"), &signed.encode())?;
    write_new(&root.join("descriptor.bin"), &descriptor)?;
    write_report(
        &root.join("publication.json"),
        &json!({
            "report_kind": "volparossa-https-content-seed", "bytes": bytes.len(),
            "object_sha256": ChunkId::digest(&bytes).to_string(), "chunks": manifest.chunks().len(),
            "publisher_hex": hex::encode(trusted.as_bytes()), "publisher_private_key_persisted": false,
            "metadata_bytes": descriptor.len(), "replica_a_chunks": first.usage().entries,
            "replica_b_chunks": second.usage().entries,
        }),
    )
}

async fn origin(
    root: &Path,
    listen: SocketAddr,
    cert_path: &Path,
    report: &Path,
    connections: usize,
) -> Result<()> {
    let generated = generate_simple_self_signed(vec![HOST.to_owned()])?;
    let certificate = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(listen).await?;
    let descriptor = read_bounded(&root.join("descriptor.bin"), MAX_MANIFEST_BYTES + 8192)?;
    let object = read_bounded(&root.join("object.bin"), OBJECT_BYTES)?;
    write_new(cert_path, certificate.as_ref())?;
    ready(report)?;
    let mut records = Vec::new();
    for _ in 0..connections {
        let (socket, source) = timeout(DEADLINE, listener.accept()).await??;
        let record = timeout(DEADLINE, async {
            let mut stream = acceptor.accept(socket).await?;
            if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
                || stream.get_ref().1.alpn_protocol() != Some(b"http/1.1") {
                return Err("fixture TLS version or ALPN mismatch".into());
            }
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                if request.len() >= 8192 { return Err("fixture request too large".into()); }
                request.push(stream.read_u8().await?);
            }
            let request = std::str::from_utf8(&request)?;
            if !request.contains("\r\nHost: destination.volparossa.test:18443\r\n")
                && !request.contains("\r\nhost: destination.volparossa.test:18443\r\n") {
                return Err("fixture request has wrong Host".into());
            }
            let payload = origin_payload(request, &descriptor, &object)?;
            let status = if payload.range.is_some() { 206 } else { 200 };
            let status_line = if status == 206 { "206 Partial Content" } else { "200 OK" };
            let range_header = payload.range.map_or_else(String::new, |(start, end)| {
                format!("Content-Range: bytes {start}-{end}/{}\r\n", object.len())
            });
            let date = format_http_date(now()?)?;
            let response = format!("HTTP/1.1 {status_line}\r\nDate: {date}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{range_header}Cache-Control: public, max-age=300\r\nAge: 0\r\nConnection: close\r\n\r\n", payload.bytes.len(), payload.content_type);
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(payload.bytes).await?;
            stream.flush().await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error>>(json!({
                "kind": payload.kind, "payload_bytes": payload.bytes.len(), "source": source.to_string(),
                "tls13": true, "alpn_http11": true, "status":status,
                "range_start":payload.range.map(|range| range.0),
                "range_end":payload.range.map(|range| range.1),
                "range_total":payload.range.map(|_| object.len()),
            }))
        }).await??;
        records.push(record);
    }
    write_report(
        report,
        &json!({"report_kind":"volparossa-https-content-origin", "pid":std::process::id(), "connections":records}),
    )
}

struct OriginPayload<'a> {
    kind: &'static str,
    content_type: &'static str,
    bytes: &'a [u8],
    range: Option<(usize, usize)>,
}

fn origin_payload<'a>(
    request: &str,
    descriptor: &'a [u8],
    object: &'a [u8],
) -> Result<OriginPayload<'a>> {
    let ranges: Vec<_> = request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("range"))
        .map(|(_, value)| value.trim())
        .collect();
    if request.starts_with(&format!("GET {METADATA} HTTP/1.1\r\n")) && ranges.is_empty() {
        return Ok(OriginPayload {
            kind: "metadata",
            content_type: "application/vnd.volparossa.origin-manifest.v1",
            bytes: descriptor,
            range: None,
        });
    }
    if !request.starts_with("GET /asset.bin HTTP/1.1\r\n") || ranges.len() > 1 {
        return Err("fixture request has wrong resource or repeated Range".into());
    }
    let range = ranges
        .first()
        .map(|value| -> Result<_> {
            let (start, end) = value
                .strip_prefix("bytes=")
                .and_then(|value| value.split_once('-'))
                .ok_or("fixture expects one explicit byte range")?;
            let start: usize = start.parse()?;
            let end: usize = end.parse()?;
            if start > end || end >= object.len() {
                return Err("fixture byte range outside object".into());
            }
            Ok((start, end))
        })
        .transpose()?;
    Ok(OriginPayload {
        kind: if range.is_some() {
            "body_range"
        } else {
            "body"
        },
        content_type: "application/octet-stream",
        bytes: range.map_or(object, |(start, end)| &object[start..=end]),
        range,
    })
}

fn provider_manifest(root: &Path) -> Result<VerifiedManifest> {
    let publication: Value =
        serde_json::from_slice(&read_bounded(&root.join("publication.json"), 8192)?)?;
    let bytes: [u8; 32] = hex::decode(
        publication["publisher_hex"]
            .as_str()
            .ok_or("missing fixture publisher")?,
    )?
    .try_into()
    .map_err(|_| "invalid publisher length")?;
    Ok(SignedManifest::decode(&read_bounded(
        &root.join("manifest.bin"),
        MAX_MANIFEST_BYTES,
    )?)?
    .verify(&VerifyingKey::from_bytes(&bytes)?, now()?)?)
}

fn rounds(variant: &str) -> Result<usize> {
    match variant {
        "complete" => Ok(2),
        "missing" => Ok(1),
        _ => Err("invalid fixture variant".into()),
    }
}

async fn peers(root: &Path, listen: SocketAddr, variant: &str, report: &Path) -> Result<()> {
    let count = rounds(variant)?;
    let manifest = provider_manifest(root)?;
    let listener = TcpListener::bind(listen).await?;
    ready(report)?;
    let mut records = Vec::new();
    for replica in ["replica-a", "replica-b"].into_iter().take(count) {
        let mut store = ChunkStore::open(&root.join(replica), limits())?;
        let (mut socket, source) = timeout(DEADLINE, listener.accept()).await??;
        let progress = serve_peer(
            &mut socket,
            &manifest,
            &mut store,
            TransferLimits::default(),
        )
        .await?;
        records.push(json!({"replica":replica,"chunks":progress.chunks,"bytes":progress.bytes,"missing":progress.missing,"source":source.to_string()}));
    }
    write_report(
        report,
        &json!({"report_kind":"volparossa-https-content-replicas","pid":std::process::id(),"sessions":records}),
    )
}

async fn consume(
    root: &Path,
    origin: SocketAddr,
    cert_path: &Path,
    peer: SocketAddr,
    variant: &str,
    report: &Path,
) -> Result<()> {
    let count = rounds(variant)?;
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let mut store = ChunkStore::create(&root.join("cache"), limits())?;
    // Fixture-only trust input copied out-of-band, not a serving peer's certificate.
    let cert = CertificateDer::from(read_bounded(cert_path, 64 * 1024)?);
    let mut roots = RootCertStore::empty();
    roots.add(cert)?;
    let client = OriginClient::new(roots, OriginLimits::default())?;
    let start = Instant::now();
    let stream = timeout(DEADLINE, TcpStream::connect(origin)).await??;
    let authorized = client
        .authenticate_manifest(stream, &OriginRequest::new(RESOURCE, METADATA)?, now()?)
        .await?;
    let metadata_elapsed = start.elapsed().as_millis();
    let mut peer_bytes = 0;
    let mut peer_chunks = 0;
    for _ in 0..count {
        let mut stream = timeout(DEADLINE, TcpStream::connect(peer)).await??;
        let progress = pull_from_peer(
            &mut stream,
            authorized.manifest(),
            &mut store,
            TransferLimits::default(),
        )
        .await?;
        peer_bytes += progress.bytes;
        peer_chunks += progress.chunks;
    }
    let missing = authorized.next_missing_range(&mut store, now()?)?.is_some();
    let mut origin_body_bytes = 0;
    let mut range_requests = Vec::new();
    while authorized.next_missing_range(&mut store, now()?)?.is_some() {
        if range_requests.len() >= authorized.manifest().chunks().len() {
            return Err("origin fallback did not complete within chunk bound".into());
        }
        let stream = timeout(DEADLINE, TcpStream::connect(origin)).await??;
        let progress = client
            .fill_next_missing_from_origin(stream, &authorized, &mut store, now()?)
            .await?;
        let range = progress
            .requested
            .ok_or("missing chunk produced no origin request")?;
        if progress.chunks_verified == 0 {
            return Err("origin fallback made no verified progress".into());
        }
        origin_body_bytes += progress.bytes_received;
        range_requests.push(json!({
            "start":range.start(),"end":range.end_inclusive(),"total":range.total(),
            "bytes_received":progress.bytes_received,"chunks_verified":progress.chunks_verified,
            "full_response":progress.full_response,
        }));
    }
    let output = root.join("object.bin");
    let bytes = authorized.reassemble_to_file(&mut [&mut store], now()?, &output)?;
    let digest = ChunkId::digest(&read_bounded(&output, OBJECT_BYTES)?).to_string();
    if bytes != OBJECT_BYTES as u64 || digest != OBJECT_SHA256 || missing != (variant == "missing")
    {
        return Err("HTTPS cache fixture output/fallback mismatch".into());
    }
    write_report(
        report,
        &json!({
            "report_kind":"volparossa-https-content-consumer","pid":std::process::id(),
            "variant":variant,"bytes":bytes,"object_sha256":digest,"peer_bytes":peer_bytes,
            "peer_chunks":peer_chunks,"origin_body_bytes":origin_body_bytes,"fallback_used":missing,
            "range_requests":range_requests,
            "metadata_elapsed_ms":metadata_elapsed,"total_elapsed_ms":start.elapsed().as_millis(),
            "origin_authenticated_before_peers":true,"tls_interception_ca_installed":false,
            "origin_authority_persisted":false,"browser_integration_claimed":false,
        }),
    )
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("fixture input too large".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("output needs parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.persist_noclobber(path)?;
    Ok(())
}

fn ready(report: &Path) -> Result<()> {
    let mut path = report.as_os_str().to_os_string();
    path.push(".ready");
    write_new(Path::new(&path), b"ready\n")
}

fn write_report(path: &Path, value: &Value) -> Result<()> {
    write_new(path, &serde_json::to_vec(value)?)?;
    println!("{value}");
    Ok(())
}
