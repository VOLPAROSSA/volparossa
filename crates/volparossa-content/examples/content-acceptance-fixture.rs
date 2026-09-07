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
use volparossa_content::private_message::{
    RecipientKeyPair, open_private_message, publish_private_message,
};
use volparossa_content::transfer::{TransferLimits, pull_from_peer, serve_peer};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, MAX_MANIFEST_BYTES, Metadata, Publication,
    SignedManifest, Validity, VerifiedManifest, publish, reassemble, reassemble_to_file,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, root] if mode == "seed" => seed(Path::new(root), None),
        [mode, root, first, second] if mode == "seed-providers" => {
            seed_replicas(Path::new(root), None, Path::new(first), Path::new(second))
        }
        [mode, root, foreground, reserve] if mode == "seed-replication" => {
            seed_replication(Path::new(root), Path::new(foreground), Path::new(reserve))
        }
        [mode, root, public] if mode == "seed-private" => {
            let public: [u8; 32] = hex::decode(public)?.try_into().map_err(|_| "invalid recipient public key")?;
            seed(Path::new(root), Some(public))
        }
        [mode, root, report] if mode == "recipient-init" => {
            recipient_init(Path::new(root), Path::new(report))
        }
        [mode, root, manifest, publisher, report] if mode == "open-message" => {
            open_message(Path::new(root), Path::new(manifest), publisher, Path::new(report))
        }
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
        _ => Err("usage: seed ROOT | seed-providers ROOT CACHE_A CACHE_B | seed-replication ROOT CACHE_P CACHE_Q | seed-private ROOT RECIPIENT_PUBLIC_HEX | recipient-init CLIENT_ROOT REPORT | serve ROOT a|b LISTEN REPORT | fetch CLIENT_ROOT MANIFEST PUBLISHER_HEX CONNECT REPORT | open-message CLIENT_ROOT MANIFEST PUBLISHER_HEX REPORT".into()),
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

fn seed(root: &Path, recipient: Option<[u8; 32]>) -> Result<()> {
    seed_replicas(
        root,
        recipient,
        &root.join("replica-a"),
        &root.join("replica-b"),
    )
}

// Create caches at their final paths as the current UID. Cache owner markers bind the UID and
// directory inode, so moving or chowning a pre-seeded store is deliberately not supported.
fn seed_replicas(
    root: &Path,
    recipient: Option<[u8; 32]>,
    first: &Path,
    second: &Path,
) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let origin = tempfile::tempdir_in(root)?;
    let origin_path = origin.path().to_path_buf();
    let mut source = ChunkStore::create(&origin.path().join("source"), limits())?;
    let mut first = ChunkStore::create(first, limits())?;
    let mut second = ChunkStore::create(second, limits())?;
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let trusted_publisher = publisher.verifying_key();
    let now = unix_seconds()?;
    // Distinct, deterministic public fixture bytes: every full chunk has a different hash.
    let mut content = Vec::with_capacity(8 * CHUNK_BYTES + 123);
    for index in 0_u8..8 {
        content.extend(vec![b'A' + index; CHUNK_BYTES]);
    }
    content.extend(vec![b'Z'; 123]);
    let validity = Validity {
        created: now,
        expires: now + 3600,
    };
    let signed = if let Some(recipient) = recipient {
        publish_private_message(&content, &recipient, &publisher, validity, &mut source)?
    } else {
        publish(
            &mut content.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "disposable-native-network-publication".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: content.len() as u64,
                validity,
            },
            &publisher,
            &mut source,
        )?
    };
    let manifest = signed.verify(&trusted_publisher, now)?;
    let mut published_bytes = Vec::new();
    reassemble(&manifest, &mut [&mut source], now, &mut published_bytes)?;
    let expected_hash = ChunkId::digest(&published_bytes);
    drop(published_bytes);
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = source.get(chunk.id())?.ok_or("publisher chunk missing")?;
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target.put_verified(*chunk.id(), &bytes)?;
    }
    let first_usage = first.usage();
    let second_usage = second.usage();
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
        "manifest_id": hex::encode(manifest.manifest_id()),
        "object_sha256": expected_hash.to_string(),
        "bytes": manifest.length(),
        "chunks": manifest.chunks().len(),
        "replica_a_chunks": first_usage.entries,
        "replica_b_chunks": second_usage.entries,
        "replica_a_bytes": first_usage.bytes,
        "replica_b_bytes": second_usage.bytes,
        "publisher_removed": true,
        "publisher_private_key_persisted": false,
        "recipient_encrypted": recipient.is_some(),
    });
    write_report(&root.join("publication.json"), &report)
}

// Both final cache paths belong to the sole initial provider. No consumer/replicator path is
// accepted here: its cache must start empty and acquire Q over the separately tested network.
fn seed_replication(root: &Path, foreground: &Path, reserve: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let origin = tempfile::tempdir_in(root)?;
    let origin_path = origin.path().to_path_buf();
    let mut source = ChunkStore::create(&origin.path().join("publisher"), limits())?;
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let now = unix_seconds()?;
    let mut publications = Vec::new();
    for (label, path, full_chunks, first_byte, tail) in [
        ("p", foreground, 2, b'1', 321),
        ("q", reserve, 1, b'q', 123),
    ] {
        let mut bytes = Vec::with_capacity(full_chunks * CHUNK_BYTES + tail);
        for offset in 0..full_chunks {
            let byte = first_byte + u8::try_from(offset)?;
            bytes.extend(vec![byte; CHUNK_BYTES]);
        }
        bytes.extend(vec![first_byte + u8::try_from(full_chunks)?; tail]);
        let signed = publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: format!("disposable-replication-{label}"),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: u64::try_from(bytes.len())?,
                validity: Validity {
                    created: now,
                    expires: now + 3600,
                },
            },
            &publisher,
            &mut source,
        )?;
        let manifest = signed.verify(&publisher.verifying_key(), now)?;
        let mut cache = ChunkStore::create(path, limits())?;
        for chunk in manifest.chunks() {
            let chunk_bytes = source.get(chunk.id())?.ok_or("publisher chunk absent")?;
            cache.put_verified(*chunk.id(), &chunk_bytes)?;
        }
        let mut actual = Vec::new();
        reassemble(&manifest, &mut [&mut cache], now, &mut actual)?;
        if actual != bytes {
            return Err("replication publication seed mismatch".into());
        }
        let report = json!({
            "report_kind": "volparossa-replication-publication",
            "label": label,
            "publisher_hex": hex::encode(publisher.verifying_key().as_bytes()),
            "manifest_id": hex::encode(manifest.manifest_id()),
            "object_sha256": ChunkId::digest(&actual).to_string(),
            "bytes": manifest.length(),
            "chunks": manifest.chunks().len(),
            "seeded_cache_bytes": cache.usage().bytes,
            "seeded_cache_entries": cache.usage().entries,
            "publisher_removed": true,
            "publisher_private_key_persisted": false,
        });
        publications.push((label, signed, report));
    }
    drop(source);
    drop(publisher);
    origin.close()?;
    if origin_path.exists() {
        return Err("replication publisher directory survived removal".into());
    }
    // Emit success metadata only after the private publisher state has actually gone.
    for (label, signed, report) in &publications {
        write_new(
            &root.join(format!("manifest-{label}.bin")),
            &signed.encode(),
        )?;
        write_report(&root.join(format!("publication-{label}.json")), report)?;
    }
    write_report(
        &root.join("replication.json"),
        &json!({
            "report_kind": "volparossa-content-replication-seed",
            "foreground": publications[0].2,
            "reserve": publications[1].2,
            "publisher_removed": true,
            "publisher_private_key_persisted": false,
            "replicator_seeded": false,
        }),
    )
}

// Explicit disposable test key material, not the product's recipient-key storage API.
// No key bytes appear in arguments, environment, stdout or retained CI artifacts.
fn recipient_init(root: &Path, report: &Path) -> Result<()> {
    let private = root.join("private");
    fs::DirBuilder::new().mode(0o700).create(&private)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| "recipient entropy unavailable")?;
    let recipient = RecipientKeyPair::from_private_key(Zeroizing::new(*key))?;
    write_new(&private.join("recipient.key"), key.as_slice())?;
    write_report(
        report,
        &json!({
            "report_kind": "volparossa-disposable-recipient",
            "recipient_public_hex": hex::encode(recipient.public_key()),
            "recipient_private_key_persisted_for_fixture_only": true,
        }),
    )
}

fn open_message(root: &Path, manifest_path: &Path, publisher: &str, report: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let key_path = root.join("private/recipient.key");
    let metadata = fs::symlink_metadata(&key_path)?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() != 32
    {
        return Err("invalid private fixture key ownership or format".into());
    }
    let bytes = Zeroizing::new(read_bounded(&key_path, 32)?);
    let key = Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid private key length")?,
    );
    let recipient = RecipientKeyPair::from_private_key(key)?;
    let manifest = manifest(manifest_path, publisher)?;
    let mut store = ChunkStore::open(&root.join("cache"), limits())?;
    let wrong = RecipientKeyPair::generate()?;
    if open_private_message(&manifest, &mut [&mut store], unix_seconds()?, &wrong).is_ok() {
        return Err("wrong recipient unexpectedly decrypted the message".into());
    }
    let plaintext =
        open_private_message(&manifest, &mut [&mut store], unix_seconds()?, &recipient)?;
    let length = plaintext.len();
    let digest = ChunkId::digest(&plaintext).to_string();
    // This fixed public test vector is the only plaintext accepted by this fixture.
    // The real library accepts arbitrary caller-authorized bytes and does not log them.
    if length != 2 * 1024 * 1024 + 123
        || digest != "add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767"
    {
        return Err("private fixture plaintext mismatch".into());
    }
    write_new(&root.join("private/message.bin"), &plaintext)?;
    write_report(
        report,
        &json!({
            "report_kind": "volparossa-private-content-recipient",
            "plaintext_bytes": length,
            "plaintext_sha256": digest,
            "wrong_recipient_rejected": true,
            "recipient_private_key_persisted_for_fixture_only": true,
        }),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replication_seed_keeps_distinct_objects_only_in_original_provider_caches() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("public-metadata");
        let foreground = temporary.path().join("provider-b-p");
        let reserve = temporary.path().join("provider-b-q");
        seed_replication(&root, &foreground, &reserve)?;
        let read_report = |label| -> Result<Value> {
            Ok(serde_json::from_slice(&read_bounded(
                &root.join(format!("publication-{label}.json")),
                4096,
            )?)?)
        };
        let p = read_report("p")?;
        let q = read_report("q")?;
        assert_eq!(
            p["object_sha256"],
            "507a1f72e20863b91dbd92265ad6d58499cc16fab5a9d753676c56bbe87cb836"
        );
        assert_eq!(
            q["object_sha256"],
            "b5a1801633b0bb108ee611668a11f438f46f4d6d630f0bc394485a41ff2a401d"
        );
        assert_eq!(p["publisher_hex"], q["publisher_hex"]);
        assert_ne!(p["manifest_id"], q["manifest_id"]);
        let mut caches = [
            ChunkStore::open(&foreground, limits())?,
            ChunkStore::open(&reserve, limits())?,
        ];
        for (index, label, report, length, chunks) in
            [(0, "p", &p, 524_609, 3), (1, "q", &q, 262_267, 2)]
        {
            assert_eq!(report["publisher_removed"], true);
            assert_eq!(report["publisher_private_key_persisted"], false);
            assert_eq!(report["bytes"], length);
            assert_eq!(report["chunks"], chunks);
            assert_eq!(report["seeded_cache_bytes"], length);
            assert_eq!(report["seeded_cache_entries"], chunks);
            let verified = manifest(
                &root.join(format!("manifest-{label}.bin")),
                report["publisher_hex"].as_str().ok_or("publisher absent")?,
            )?;
            assert_eq!(report["manifest_id"], hex::encode(verified.manifest_id()));
            for chunk in verified.chunks() {
                assert!(caches[1 - index].get(chunk.id())?.is_none());
            }
            let mut bytes = Vec::new();
            reassemble(
                &verified,
                &mut [&mut caches[index]],
                unix_seconds()?,
                &mut bytes,
            )?;
            assert_eq!(report["object_sha256"], ChunkId::digest(&bytes).to_string());
            assert_eq!(bytes.len(), usize::try_from(length)?);
        }
        let report: Value =
            serde_json::from_slice(&read_bounded(&root.join("replication.json"), 4096)?)?;
        assert_eq!(report["foreground"], p);
        assert_eq!(report["reserve"], q);
        assert_eq!(report["replicator_seeded"], false);
        // Exactly the four public per-object files and combined report remain, no publisher.
        assert_eq!(fs::read_dir(&root)?.count(), 5);
        assert_eq!(fs::read_dir(temporary.path())?.count(), 3);
        assert!(seed_replication(&root, &foreground, &reserve).is_err());
        Ok(())
    }

    #[test]
    fn provider_seed_reopens_exact_replica_paths_after_publisher_removal() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("publication");
        let first = temporary.path().join("provider-a-cache");
        let second = temporary.path().join("provider-b-cache");
        seed_replicas(&root, None, &first, &second)?;
        let report: Value =
            serde_json::from_slice(&read_bounded(&root.join("publication.json"), 4096)?)?;
        assert_eq!(report["publisher_removed"], true);
        assert_eq!(report["publisher_private_key_persisted"], false);
        assert_eq!(report["replica_a_chunks"], 5);
        assert_eq!(report["replica_b_chunks"], 4);
        assert_eq!(report["replica_a_bytes"], 1_048_699);
        assert_eq!(report["replica_b_bytes"], 1_048_576);
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        let manifest = manifest(
            &root.join("manifest.bin"),
            report["publisher_hex"].as_str().ok_or("publisher absent")?,
        )?;
        assert_eq!(report["manifest_id"], hex::encode(manifest.manifest_id()));
        let mut first = ChunkStore::open(&first, limits())?;
        let mut second = ChunkStore::open(&second, limits())?;
        let mut output = Vec::new();
        reassemble(
            &manifest,
            &mut [&mut first, &mut second],
            unix_seconds()?,
            &mut output,
        )?;
        assert_eq!(output.len(), 2_097_275);
        assert_eq!(
            ChunkId::digest(&output).to_string(),
            "add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767"
        );
        Ok(())
    }
}
