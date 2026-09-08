//! Explicit disposable HTTPS-origin/cache fixture. Never run sockets on the host network.
//!
//! The consumer trusts only its application-local fixture CA, authenticates metadata over
//! actual origin TLS, and keeps that authority in memory across peer retrieval/fallback.
//! No browser hook, peer discovery, system CA installation or generic HTTPS claim is made.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::pem::PemObject as _;
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
const OBJECT_REPR_DIGEST: &str = "sha-256=:rdByTY2+aEB9VEwkcUEocyopxIgM/zDSg7GtqTYuN2c=:";
const ADAPTIVE_BYTES: usize = 15 * CHUNK_BYTES;
const ADAPTIVE_SHA256: &str = "26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011";
const ADAPTIVE_REPR_DIGEST: &str = "sha-256=:JvxGlvDrzX42o8CgNp4thDdCs5FaIirVe0nNUwIKkBE=:";
const DEADLINE: Duration = Duration::from_secs(90);

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, root] if mode == "seed" => seed(Path::new(root)),
        [mode, root, manifest, publisher] if mode == "seed-from-publication" => {
            seed_from_publication(Path::new(root), Path::new(manifest), publisher)
        }
        [mode, root, manifest, publisher] if mode == "seed-adaptive-origin" => {
            seed_publication_profile(Path::new(root), Path::new(manifest), publisher, true)
        }
        [mode, root, manifest, publisher, cache] if mode == "independent-index" => {
            independent_index(Path::new(root), Path::new(manifest), publisher, Path::new(cache))
        }
        [mode, root, manifest, publisher, cache, shard] if mode == "independent-adaptive-index" => {
            independent_index_profile(Path::new(root), Path::new(manifest), publisher,
                Path::new(cache), Some(shard.parse()?))
        }
        [mode, root, listen, cert, report, connections] if matches!(mode.as_str(), "origin" | "origin-pem" | "origin-pem-bounded") => {
            let count = connections.parse()?;
            let graceful = mode == "origin-pem-bounded";
            if !(1..=if graceful { 31 } else { 8 }).contains(&count) {
                return Err("origin connection count outside explicit fixture bound".into());
            }
            origin(Path::new(root), listen.parse()?, Path::new(cert), Path::new(report), count, mode != "origin", graceful).await
        }
        [mode, root, listen, variant, report] if mode == "peers" => {
            peers(Path::new(root), listen.parse()?, variant, Path::new(report)).await
        }
        [mode, root, origin, cert, peer, variant, report] if mode == "consume" => {
            consume(Path::new(root), origin.parse()?, Path::new(cert), peer.parse()?, variant, Path::new(report)).await
        }
        [mode, parent, origin, cert, report] if mode == "origin-baseline" => {
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            tokio::select! {
                result = timeout(DEADLINE, origin_baseline(Path::new(parent), origin.parse()?, Path::new(cert), Path::new(report))) => result?,
                _ = terminate.recv() => Err("origin baseline stopped; private spool discarded".into()),
                _ = interrupt.recv() => Err("origin baseline interrupted; private spool discarded".into()),
            }
        }
        _ => Err("usage: seed ROOT | seed-from-publication|seed-adaptive-origin ROOT MANIFEST PUBLISHER_HEX | independent-index ROOT MANIFEST PUBLISHER_HEX EXISTING_B_CACHE | independent-adaptive-index ROOT MANIFEST PUBLISHER_HEX EXISTING_CACHE SHARD_0_1_2 | origin|origin-pem|origin-pem-bounded ROOT LISTEN CERT REPORT CONNECTIONS | peers ROOT LISTEN complete|missing REPORT | consume CLIENT_ROOT ORIGIN CERT PEER complete|missing REPORT | origin-baseline PRIVATE_PARENT ORIGIN_ADDR CERT_PEM REPORT".into()),
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
    let bytes = fixture_bytes();
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

fn fixture_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OBJECT_BYTES);
    for index in 0_u8..8 {
        bytes.extend(vec![b'A' + index; CHUNK_BYTES]);
    }
    bytes.extend(vec![b'Z'; 123]);
    bytes
}

/// Authorize the exact already-published fixture manifest at this independent HTTPS origin.
/// The origin receives only the publisher public key; it does not re-sign or substitute objects.
fn seed_from_publication(root: &Path, manifest_path: &Path, publisher: &str) -> Result<()> {
    seed_publication_profile(root, manifest_path, publisher, false)
}

fn checked_fixture_bytes(manifest: &VerifiedManifest, adaptive: bool) -> Result<Vec<u8>> {
    let bytes = if adaptive {
        (b'A'..=b'O')
            .flat_map(|value| vec![value; CHUNK_BYTES])
            .collect()
    } else {
        fixture_bytes()
    };
    let hash = if adaptive {
        ADAPTIVE_SHA256
    } else {
        OBJECT_SHA256
    };
    if manifest.length() != bytes.len() as u64
        || hex::encode(manifest.object_sha256()) != hash
        || manifest.metadata().content_type != "application/octet-stream"
        || manifest.chunks().len() != bytes.chunks(CHUNK_BYTES).len()
        || manifest
            .chunks()
            .iter()
            .zip(bytes.chunks(CHUNK_BYTES))
            .any(|(chunk, part)| {
                chunk.id() != &ChunkId::digest(part) || chunk.length() as usize != part.len()
            })
    {
        return Err("not the exact selected public fixture representation".into());
    }
    Ok(bytes)
}

fn seed_publication_profile(
    root: &Path,
    manifest_path: &Path,
    publisher: &str,
    adaptive: bool,
) -> Result<()> {
    let public: [u8; 32] = hex::decode(publisher)?
        .try_into()
        .map_err(|_| "publisher key length")?;
    let public = VerifyingKey::from_bytes(&public)?;
    let signed = SignedManifest::decode(&read_bounded(manifest_path, MAX_MANIFEST_BYTES)?)?;
    let time = now()?;
    let manifest = signed.verify(&public, time)?;
    let bytes = checked_fixture_bytes(&manifest, adaptive)?;
    let descriptor = encode_origin_descriptor(
        &OriginRequest::new(RESOURCE, METADATA)?,
        &signed,
        &public,
        time + 300,
        time,
    )?;
    fs::DirBuilder::new().mode(0o700).create(root)?;
    write_new(&root.join("object.bin"), &bytes)?;
    write_new(&root.join("manifest.bin"), &signed.encode())?;
    write_new(&root.join("descriptor.bin"), &descriptor)?;
    write_report(
        &root.join("publication.json"),
        &json!({
            "report_kind":"volparossa-https-content-seed", "bytes":bytes.len(),
            "object_sha256":hex::encode(manifest.object_sha256()), "chunks":manifest.chunks().len(),
            "publisher_hex":hex::encode(public.as_bytes()), "publisher_private_key_persisted":false,
            "manifest_id":hex::encode(manifest.manifest_id()), "metadata_bytes":descriptor.len(),
            "existing_publication_reused":true,
        }),
    )
}

/// Independently publish the fixture bytes without adding payload to B's existing partial cache.
/// This changes the test registration only, never an HTTPS authority or production envelope.
fn independent_index(
    root: &Path,
    manifest_path: &Path,
    publisher: &str,
    cache: &Path,
) -> Result<()> {
    independent_index_profile(root, manifest_path, publisher, cache, None)
}

fn independent_index_profile(
    root: &Path,
    manifest_path: &Path,
    publisher: &str,
    cache: &Path,
    shard: Option<usize>,
) -> Result<()> {
    if shard.is_some_and(|value| value >= 3) {
        return Err("adaptive shard must be one of the three fixed disjoint caches".into());
    }
    let public: [u8; 32] = hex::decode(publisher)?
        .try_into()
        .map_err(|_| "publisher key length")?;
    let original = SignedManifest::decode(&read_bounded(manifest_path, MAX_MANIFEST_BYTES)?)?
        .verify(&VerifyingKey::from_bytes(&public)?, now()?)?;
    let bytes = checked_fixture_bytes(&original, shard.is_some())?;
    let before = partial_cache_snapshot(cache, &original, shard)?;
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let temporary = tempfile::tempdir_in(root)?;
    let mut store = ChunkStore::create(&temporary.path().join("publisher-cache"), limits())?;
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let envelope = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: original.metadata().clone(),
            length: original.length(),
            validity: original.validity(),
        },
        &signer,
        &mut store,
    )?;
    let alternate = envelope.verify(&signer.verifying_key(), now()?)?;
    if alternate.manifest_id() == original.manifest_id()
        || alternate.publisher() == original.publisher()
        || alternate.chunks() != original.chunks()
        || alternate.object_sha256() != original.object_sha256()
    {
        return Err("independent public index did not preserve exact layout and digest".into());
    }
    drop(store);
    drop(signer);
    temporary.close()?;
    let after = partial_cache_snapshot(cache, &original, shard)?;
    if before != after {
        return Err("independent publication changed provider B's original cache".into());
    }
    write_new(&root.join("manifest.bin"), &envelope.encode())?;
    write_report(
        &root.join("publication.json"),
        &json!({"report_kind":"volparossa-https-independent-index",
            "original":index_summary(&original), "independent":index_summary(&alternate),
            "checked_unix_seconds":now()?, "cache_before":before, "cache_after":after,
            "publisher_private_key_persisted":false, "temporary_full_copy_removed":true}),
    )
}

fn index_summary(manifest: &VerifiedManifest) -> Value {
    json!({"manifest_id":hex::encode(manifest.manifest_id()),
        "publisher_hex":hex::encode(manifest.publisher()),
        "object_sha256":hex::encode(manifest.object_sha256()), "bytes":manifest.length(),
        "name":manifest.metadata().name, "revision":manifest.metadata().revision,
        "content_type":manifest.metadata().content_type,
        "created_unix_seconds":manifest.validity().created,
        "expires_unix_seconds":manifest.validity().expires,
        "chunks":manifest.chunks().iter().map(|chunk| json!({
            "sha256":chunk.id().to_string(),"bytes":chunk.length()})).collect::<Vec<_>>()})
}

fn partial_cache_snapshot(
    cache: &Path,
    manifest: &VerifiedManifest,
    shard: Option<usize>,
) -> Result<Value> {
    let metadata = fs::symlink_metadata(cache)?;
    let mut store = ChunkStore::open(cache, limits())?;
    if !metadata.is_dir()
        || store.usage().entries != if shard.is_some() { 5 } else { 4 }
        || store.usage().bytes != if shard.is_some() { 5 } else { 4 } * CHUNK_BYTES as u64
    {
        return Err("provider B must retain exactly its four original odd chunks".into());
    }
    let mut present = Vec::new();
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let payload = store.get(chunk.id())?;
        if payload.is_some() != shard.map_or(index % 2 == 1, |shard| index % 3 == shard)
            || payload
                .as_ref()
                .is_some_and(|bytes| bytes.len() != chunk.length() as usize)
        {
            return Err("provider B's partial cache contains a wrong or additional chunk".into());
        }
        if payload.is_some() {
            present.push(chunk.id().to_string());
        }
    }
    Ok(
        json!({"path":cache, "device":metadata.dev(), "inode":metadata.ino(),
        "entries":store.usage().entries, "bytes":store.usage().bytes, "chunk_ids":present}),
    )
}

async fn origin(
    root: &Path,
    listen: SocketAddr,
    cert_path: &Path,
    report: &Path,
    connections: usize,
    certificate_pem: bool,
    graceful: bool,
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
    let object = read_bounded(&root.join("object.bin"), ADAPTIVE_BYTES)?;
    let (object_hash, representation_digest) = origin_object_profile(&object)?;
    if certificate_pem {
        write_new(cert_path, generated.cert.pem().as_bytes())?;
    } else {
        write_new(cert_path, certificate.as_ref())?;
    }
    let mut terminate = if graceful {
        Some(tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?)
    } else {
        None
    };
    ready(report)?;
    let mut records = Vec::new();
    let stopped = loop {
        if !graceful && records.len() == connections {
            break false;
        }
        // Finish an already accepted bounded TLS request before observing stop. No
        // per-request cancellation may masquerade as a complete origin response.
        let accepted = tokio::select! {
            accepted = timeout(DEADLINE, listener.accept()) => Some(accepted??),
            () = async {
                if let Some(signal) = &mut terminate { signal.recv().await; }
                else { std::future::pending::<()>().await; }
            } => None,
        };
        let Some((socket, source)) = accepted else {
            break true;
        };
        if records.len() >= connections {
            return Err("origin fixture request limit exceeded".into());
        }
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
            let length = if payload.head { object.len() } else { payload.bytes.len() };
            let digest_header = if payload.kind == "metadata" { String::new() }
                else { format!("Repr-Digest: {representation_digest}\r\n") };
            let response = format!("HTTP/1.1 {status_line}\r\nDate: {date}\r\nContent-Length: {length}\r\nContent-Type: {}\r\n{range_header}{digest_header}Cache-Control: public, max-age=300\r\nAge: 0\r\nConnection: close\r\n\r\n", payload.content_type);
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
                "content_length":length, "method":if payload.head { "HEAD" } else { "GET" },
                "representation_digest":if payload.kind == "metadata" { None } else { Some(representation_digest) },
                "object_sha256":if payload.kind == "metadata" { None } else { Some(object_hash) },
            }))
        }).await??;
        records.push(record);
    };
    drop(listener);
    write_report(
        report,
        &json!({"report_kind":"volparossa-https-content-origin", "pid":std::process::id(), "connections":records,
            "request_limit":connections, "stop_requested":stopped, "listener_closed":true, "inflight_drained":true}),
    )
}

fn origin_object_profile(object: &[u8]) -> Result<(&'static str, &'static str)> {
    let (hash, digest) = match object.len() {
        OBJECT_BYTES => (OBJECT_SHA256, OBJECT_REPR_DIGEST),
        ADAPTIVE_BYTES => (ADAPTIVE_SHA256, ADAPTIVE_REPR_DIGEST),
        _ => return Err("origin representation is not a fixed fixture object".into()),
    };
    if ChunkId::digest(object).to_string() != hash {
        return Err("origin representation does not match its fixed digest".into());
    }
    Ok((hash, digest))
}

struct OriginPayload<'a> {
    kind: &'static str,
    content_type: &'static str,
    bytes: &'a [u8],
    range: Option<(usize, usize)>,
    head: bool,
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
            head: false,
        });
    }
    if request.starts_with("HEAD /asset.bin HTTP/1.1\r\n") && ranges.is_empty() {
        return Ok(OriginPayload {
            kind: "digest_head",
            content_type: "application/octet-stream",
            bytes: &[],
            range: None,
            head: true,
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
        head: false,
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

/// An ordinary HTTPS application in the disposable Client namespace: the kernel's existing
/// transparent ingress must carry these sockets. No peer, cached descriptor or local origin
/// files enter the reference fetch. The surrounding harness proves the actual protected path.
async fn origin_baseline(
    parent: &Path,
    origin: SocketAddr,
    cert_path: &Path,
    report: &Path,
) -> Result<()> {
    let effective_uid = fs::metadata("/proc/self")?.uid();
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o700
        || effective_uid == 0
    {
        return Err("origin baseline requires a private unprivileged fixture directory".into());
    }
    let namespace = fs::read_link("/proc/self/ns/net")?;
    let certificates = read_bounded(cert_path, 64 * 1024)?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&certificates) {
        roots.add(certificate?)?;
    }
    if roots.len() != 1 {
        return Err("baseline expects exactly one explicit fixture root".into());
    }
    let client = OriginClient::new(roots, OriginLimits::default())?;
    let directory = tempfile::Builder::new()
        .prefix("volparossa-origin-baseline-")
        .tempdir_in(parent)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let mut store = ChunkStore::create(&directory.path().join("cache"), limits())?;
    if store.usage().bytes != 0 {
        return Err("reference cache was not cold".into());
    }
    let start = Instant::now();
    let authorized = client
        .authenticate_manifest(
            TcpStream::connect(origin).await?,
            &OriginRequest::new(RESOURCE, METADATA)?,
            now()?,
        )
        .await?;
    let metadata_elapsed = start.elapsed();
    let body_start = Instant::now();
    let received = client
        .fill_from_origin(
            TcpStream::connect(origin).await?,
            &authorized,
            &mut store,
            now()?,
        )
        .await?;
    let body_elapsed = body_start.elapsed();
    let reconstruct_start = Instant::now();
    let output = directory.path().join("object.bin");
    let bytes = authorized.reassemble_to_file(&mut [&mut store], now()?, &output)?;
    let digest = ChunkId::digest(&read_bounded(&output, OBJECT_BYTES)?).to_string();
    let output_metadata = fs::symlink_metadata(&output)?;
    if received != bytes
        || bytes != OBJECT_BYTES as u64
        || digest != OBJECT_SHA256
        || !output_metadata.is_file()
        || output_metadata.uid() != effective_uid
        || output_metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err("origin-only reference output failed verification".into());
    }
    let reconstruct_elapsed = reconstruct_start.elapsed();
    let total_elapsed = start.elapsed();
    let chunks = authorized.manifest().chunks().len();
    drop((store, authorized));
    directory.close()?;
    write_report(
        report,
        &json!({
            "report_kind":"volparossa-https-origin-baseline", "pid":std::process::id(),
            "effective_uid":effective_uid, "network_namespace":namespace.to_str().ok_or("namespace encoding")?,
            "bytes":bytes, "chunks":chunks, "object_sha256":digest,
            "origin_body_bytes":received, "peer_bytes":0, "metadata_requests":1, "body_requests":1,
            "metadata_elapsed_ns":metadata_elapsed.as_nanos(), "body_elapsed_ns":body_elapsed.as_nanos(),
            "reconstruct_elapsed_ns":reconstruct_elapsed.as_nanos(), "total_elapsed_ns":total_elapsed.as_nanos(),
            "origin_authenticated":true, "origin_authority_persisted":false,
            "reference_cache_initially_empty":true, "private_spool_removed":true,
            "output_mode":"0600", "application_socket":"ordinary_tcp_transparent_ingress",
            "scope":"same-overlay origin-only reference; not direct Internet or universal speedup",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_fixture_adaptive_preserves_three_disjoint_caches_and_original_indexes() -> Result<()>
    {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let bytes = (b'A'..=b'O')
            .flat_map(|value| vec![value; CHUNK_BYTES])
            .collect::<Vec<_>>();
        let mut source = ChunkStore::create(&root.join("source"), limits())?;
        let signer = SigningKey::generate(&mut rand_core::OsRng);
        let time = now()?;
        let signed = publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "disposable-adaptive-native-publication".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: ADAPTIVE_BYTES as u64,
                validity: Validity {
                    created: time,
                    expires: time + 3600,
                },
            },
            &signer,
            &mut source,
        )?;
        let original = signed.verify(&signer.verifying_key(), time)?;
        let manifest = root.join("manifest.bin");
        write_new(&manifest, &signed.encode())?;
        let publisher = hex::encode(original.publisher());
        let origin = root.join("origin");
        seed_publication_profile(&origin, &manifest, &publisher, true)?;
        assert_eq!(fs::read(origin.join("manifest.bin"))?, signed.encode());
        assert_eq!(
            origin_object_profile(&fs::read(origin.join("object.bin"))?)?,
            (ADAPTIVE_SHA256, ADAPTIVE_REPR_DIGEST)
        );
        let mut identities = vec![*original.manifest_id()];
        for shard in 0..3 {
            let cache = root.join(format!("shard-{shard}"));
            let mut destination = ChunkStore::create(&cache, limits())?;
            for (index, chunk) in original.chunks().iter().enumerate() {
                if index % 3 == shard {
                    destination.put(&source.get(chunk.id())?.ok_or("missing chunk")?)?;
                }
            }
            drop(destination);
            let before = partial_cache_snapshot(&cache, &original, Some(shard))?;
            if shard == 0 {
                continue;
            }
            let index = root.join(format!("index-{shard}"));
            independent_index_profile(&index, &manifest, &publisher, &cache, Some(shard))?;
            let envelope = SignedManifest::decode(&fs::read(index.join("manifest.bin"))?)?;
            let verified = envelope.verify(
                &VerifyingKey::from_bytes(&envelope.publisher_key_hint())?,
                time,
            )?;
            assert!(!identities.contains(verified.manifest_id()));
            identities.push(*verified.manifest_id());
            assert_eq!(verified.chunks(), original.chunks());
            assert_eq!(verified.validity(), original.validity());
            assert_eq!(
                before,
                partial_cache_snapshot(&cache, &original, Some(shard))?
            );
            assert_eq!(
                fs::read_dir(&index)?.count(),
                2,
                "no full source or signer persisted"
            );
            assert!(partial_cache_snapshot(&cache, &original, Some(0)).is_err());
        }
        assert_eq!(identities.len(), 3);
        assert!(seed_from_publication(&root.join("old-mode"), &manifest, &publisher).is_err());
        Ok(())
    }

    #[test]
    fn origin_fixture_independent_index_keeps_expiry_and_only_original_partial_cache() -> Result<()>
    {
        let temporary = tempfile::tempdir()?;
        let publisher = temporary.path().join("publisher");
        seed(&publisher)?;
        let original = provider_manifest(&publisher)?;
        let root = temporary.path().join("independent-index");
        let cache = publisher.join("replica-b");
        independent_index(
            &root,
            &publisher.join("manifest.bin"),
            &hex::encode(original.publisher()),
            &cache,
        )?;
        let report: Value =
            serde_json::from_slice(&read_bounded(&root.join("publication.json"), 8192)?)?;
        let envelope = SignedManifest::decode(&fs::read(root.join("manifest.bin"))?)?;
        let alternate = envelope.verify(
            &VerifyingKey::from_bytes(&envelope.publisher_key_hint())?,
            now()?,
        )?;
        assert_ne!(original.publisher(), alternate.publisher());
        assert_ne!(original.manifest_id(), alternate.manifest_id());
        assert_eq!(original.metadata(), alternate.metadata());
        assert_eq!(original.validity(), alternate.validity());
        assert_eq!(original.chunks(), alternate.chunks());
        assert_eq!(original.object_sha256(), alternate.object_sha256());
        assert_eq!(report["cache_before"], report["cache_after"]);
        assert_eq!(report["cache_after"]["entries"], 4);
        assert_eq!(report["temporary_full_copy_removed"], true);
        assert_eq!(
            fs::read_dir(&root)?.count(),
            2,
            "no private key or full-copy cache survives"
        );
        // A full/incorrect provider cache must never masquerade as a complementary source.
        let rejected = temporary.path().join("full-cache-rejected");
        assert!(
            independent_index(
                &rejected,
                &publisher.join("manifest.bin"),
                &hex::encode(original.publisher()),
                &publisher.join("origin-cache")
            )
            .is_err()
        );
        assert!(!rejected.exists());
        Ok(())
    }

    #[test]
    fn origin_fixture_head_is_bodyless_and_get_preserves_the_whole_representation() -> Result<()> {
        let object = fixture_bytes();
        let head = origin_payload(
            "HEAD /asset.bin HTTP/1.1\r\n\r\n",
            b"unused descriptor",
            &object,
        )?;
        assert!(head.head && head.bytes.is_empty());
        assert_eq!(head.kind, "digest_head");
        assert_eq!(head.content_type, "application/octet-stream");
        let get = origin_payload(
            "GET /asset.bin HTTP/1.1\r\n\r\n",
            b"unused descriptor",
            &object,
        )?;
        assert!(!get.head && get.range.is_none());
        assert_eq!(get.kind, "body");
        assert_eq!(get.bytes.len(), OBJECT_BYTES);
        assert_eq!(ChunkId::digest(get.bytes).to_string(), OBJECT_SHA256);
        assert!(
            origin_payload(
                "HEAD /asset.bin HTTP/1.1\r\nRange: bytes=0-9\r\n\r\n",
                &[],
                &object
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn origin_fixture_preserves_the_independently_existing_native_manifest() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let publisher = temporary.path().join("publisher");
        seed(&publisher)?;
        let report: Value =
            serde_json::from_slice(&read_bounded(&publisher.join("publication.json"), 8192)?)?;
        let public = report["publisher_hex"].as_str().ok_or("publisher absent")?;
        let root = temporary.path().join("independent-origin");
        seed_from_publication(&root, &publisher.join("manifest.bin"), public)?;
        assert_eq!(
            fs::read(root.join("manifest.bin"))?,
            fs::read(publisher.join("manifest.bin"))?
        );
        assert_eq!(
            ChunkId::digest(&fs::read(root.join("object.bin"))?).to_string(),
            OBJECT_SHA256
        );
        let wrong = SigningKey::generate(&mut rand_core::OsRng).verifying_key();
        let rejected = temporary.path().join("wrong-publisher");
        assert!(
            seed_from_publication(
                &rejected,
                &publisher.join("manifest.bin"),
                &hex::encode(wrong.as_bytes())
            )
            .is_err()
        );
        assert!(!rejected.exists());
        assert!(seed_from_publication(&root, &publisher.join("manifest.bin"), public).is_err());
        Ok(())
    }
}
