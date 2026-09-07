//! Disposable topology fixture, not a public listener or a normal-client direct route.
//!
//! In KVM the ordinary application TCP socket is captured by the existing transparent
//! ingress and carried over genuine MPTCP/TLS and both `WireGuard` legs. Loopback use only
//! proves this application's protocol; it does not prove any overlay or HTTPS property.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use volparossa_content::transfer::{TransferLimits, pull_from_peer, serve_peer};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, MAX_MANIFEST_BYTES, Metadata, Publication,
    SignedManifest, Validity, VerifiedManifest, publish, reassemble_to_file,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, root] if mode == "seed" => seed(Path::new(root)),
        [mode, root, replica, listen, report] if mode == "serve" => {
            serve(Path::new(root), replica, listen.parse()?, Path::new(report)).await
        }
        [mode, root, manifest, publisher, connect, report] if mode == "fetch" => {
            fetch(
                Path::new(root),
                Path::new(manifest),
                publisher,
                connect.parse()?,
                Path::new(report),
            )
            .await
        }
        _ => Err("usage: seed ROOT | serve ROOT a|b LISTEN REPORT | fetch CLIENT_ROOT MANIFEST PUBLISHER_HEX CONNECT REPORT".into()),
    }
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 16 * CHUNK_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 1024 * 1024,
    }
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn seed(root: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let origin = tempfile::tempdir_in(root)?;
    let origin_path = origin.path().to_path_buf();
    let mut source = ChunkStore::create(&origin.path().join("source"), limits())?;
    let mut first = ChunkStore::create(&root.join("replica-a"), limits())?;
    let mut second = ChunkStore::create(&root.join("replica-b"), limits())?;
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let trusted_publisher = publisher.verifying_key();
    let now = unix_seconds()?;
    // Distinct, deterministic public fixture bytes: every full chunk has a different hash.
    let mut content = Vec::with_capacity(8 * CHUNK_BYTES + 123);
    for index in 0_u8..8 {
        content.extend(vec![b'A' + index; CHUNK_BYTES]);
    }
    content.extend(vec![b'Z'; 123]);
    let expected_hash = ChunkId::digest(&content);
    let signed = publish(
        &mut content.as_slice(),
        Publication {
            metadata: Metadata {
                name: "disposable-native-network-publication".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: content.len() as u64,
            validity: Validity {
                created: now,
                expires: now + 3600,
            },
        },
        &publisher,
        &mut source,
    )?;
    let manifest = signed.verify(&trusted_publisher, now)?;
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = source.get(chunk.id())?.ok_or("publisher chunk missing")?;
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target.put_verified(*chunk.id(), &bytes)?;
    }
    let first_count = first.usage().entries;
    let second_count = second.usage().entries;
    drop(source);
    drop(publisher);
    drop(content);
    drop(first);
    drop(second);
    origin.close()?;
    if origin_path.exists() {
        return Err("publisher directory survived removal".into());
    }
    write_new(&root.join("manifest.bin"), &signed.encode())?;
    let report = json!({
        "report_kind": "volparossa-content-seed",
        "publisher_hex": hex::encode(trusted_publisher.as_bytes()),
        "object_sha256": expected_hash.to_string(),
        "bytes": manifest.length(),
        "chunks": manifest.chunks().len(),
        "replica_a_chunks": first_count,
        "replica_b_chunks": second_count,
        "publisher_removed": true,
        "publisher_private_key_persisted": false,
    });
    write_report(&root.join("publication.json"), &report)
}

async fn serve(root: &Path, replica: &str, listen: SocketAddr, report: &Path) -> Result<()> {
    let cache = match replica {
        "a" => "replica-a",
        "b" => "replica-b",
        _ => return Err("replica must be a or b".into()),
    };
    let publication: Value =
        serde_json::from_slice(&read_bounded(&root.join("publication.json"), 4096)?)?;
    let publisher = publication["publisher_hex"]
        .as_str()
        .ok_or("missing publisher")?;
    let manifest = manifest(&root.join("manifest.bin"), publisher)?;
    let mut store = ChunkStore::open(&root.join(cache), limits())?;
    let listener = TcpListener::bind(listen).await?;
    let mut ready = report.as_os_str().to_os_string();
    ready.push(".ready");
    write_new(&PathBuf::from(ready), b"ready\n")?;
    let (mut stream, peer) = timeout(Duration::from_secs(45), listener.accept()).await??;
    let progress = serve_peer(
        &mut stream,
        &manifest,
        &mut store,
        TransferLimits::default(),
    )
    .await?;
    write_report(
        report,
        &json!({
            "report_kind": "volparossa-content-provider",
            "replica": replica,
            "pid": std::process::id(),
            "peer": peer.to_string(),
            "source": {"ip": peer.ip().to_string(), "port": peer.port()},
            "listen": {"ip": listen.ip().to_string(), "port": listen.port()},
            "chunks_sent": progress.chunks,
            "bytes_sent": progress.bytes,
            "missing": progress.missing,
        }),
    )
}

async fn fetch(
    root: &Path,
    manifest_path: &Path,
    publisher: &str,
    connect: SocketAddr,
    report: &Path,
) -> Result<()> {
    let manifest = manifest(manifest_path, publisher)?;
    let path = root.join("cache");
    let mut store = if path.try_exists()? {
        ChunkStore::open(&path, limits())?
    } else {
        ChunkStore::create(&path, limits())?
    };
    let mut stream = timeout(Duration::from_secs(15), TcpStream::connect(connect)).await??;
    let progress = pull_from_peer(
        &mut stream,
        &manifest,
        &mut store,
        TransferLimits::default(),
    )
    .await?;
    drop(stream);
    let mut complete = true;
    for chunk in manifest.chunks() {
        if store.get(chunk.id())?.is_none() {
            complete = false;
        }
    }
    let mut object_hash = None;
    let mut output_bytes = 0;
    if complete {
        let destination = root.join("object.bin");
        output_bytes =
            reassemble_to_file(&manifest, &mut [&mut store], unix_seconds()?, &destination)?;
        object_hash =
            Some(ChunkId::digest(&read_bounded(&destination, 16 * CHUNK_BYTES)?).to_string());
    }
    write_report(
        report,
        &json!({
            "report_kind": "volparossa-content-consumer",
            "chunks_received": progress.chunks,
            "bytes_received": progress.bytes,
            "missing": progress.missing,
            "cached_chunks": store.usage().entries,
            "complete": complete,
            "output_bytes": output_bytes,
            "object_sha256": object_hash,
            "pid": std::process::id(),
        }),
    )
}

fn manifest(path: &Path, publisher: &str) -> Result<VerifiedManifest> {
    let key: [u8; 32] = hex::decode(publisher)?
        .try_into()
        .map_err(|_| "invalid publisher length")?;
    let key = VerifyingKey::from_bytes(&key)?;
    Ok(
        SignedManifest::decode(&read_bounded(path, MAX_MANIFEST_BYTES)?)?
            .verify(&key, unix_seconds()?)?,
    )
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("fixture input exceeds its bound".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("output needs a parent directory")?;
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    output.write_all(bytes)?;
    output.persist_noclobber(path)?;
    Ok(())
}

fn write_report(path: &Path, report: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(report)?;
    write_new(path, &bytes)?;
    println!("{report}");
    Ok(())
}
