//! Reconstruct a native object from two real disk caches after deleting its publisher store.

use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    publish, reassemble_to_file,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let origin = tempfile::tempdir_in(root.path())?;
    let limits = CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 4,
        min_free_bytes: 1024 * 1024,
    };
    let mut source = ChunkStore::create(&origin.path().join("source"), limits)?;
    let mut first = ChunkStore::create(&root.path().join("replica-a"), limits)?;
    let mut second = ChunkStore::create(&root.path().join("replica-b"), limits)?;
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    // This demo consumer trusts its own publisher key before receiving any manifest.
    // A network consumer must establish publisher authority independently of serving peers.
    let trusted_publisher = publisher.verifying_key();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut content = vec![b'A'; CHUNK_BYTES];
    content.extend(vec![b'B'; CHUNK_BYTES]);
    content.extend(b"This final native piece survives the publisher going offline.");
    let expected_hash = ChunkId::digest(&content);
    let signed = publish(
        &mut content.as_slice(),
        Publication {
            metadata: Metadata {
                name: "offline-native-example".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: content.len() as u64,
            validity: Validity {
                created: now,
                expires: now + 600,
            },
        },
        &publisher,
        &mut source,
    )?;
    let wire = signed.encode();
    let manifest = signed.verify(&trusted_publisher, now)?;
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = source.get(chunk.id())?.ok_or("source chunk missing")?;
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target.put_verified(*chunk.id(), &bytes)?;
    }
    drop(source);
    drop(publisher);
    drop(content);
    origin.close()?;

    let verified = SignedManifest::decode(&wire)?.verify(&trusted_publisher, now)?;
    let output = root.path().join("reconstructed.bin");
    let length = reassemble_to_file(&verified, &mut [&mut first, &mut second], now, &output)?;
    if ChunkId::digest(&fs::read(output)?) != expected_hash {
        return Err("reconstructed content mismatch".into());
    }
    println!(
        "offline_local_publication: {length} bytes, {} chunks, 2 disk stores, SHA-256 {expected_hash}",
        verified.chunks().len()
    );
    println!(
        "Publisher directory removed; native publisher signature verified. No network or HTTPS claim."
    );
    Ok(())
}
