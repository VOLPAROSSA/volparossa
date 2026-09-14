//! Additive three-provider fixture. Existing two-provider and replication vectors stay fixed.

use super::{
    CHUNK_BYTES, ChunkId, ChunkStore, DirBuilderExt, Metadata, Path, Publication, Result,
    SigningKey, Validity, fs, json, limits, publish, reassemble, unix_seconds, write_new,
    write_report,
};

const CHUNKS: usize = 15;
const SHA256: &str = "26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011";

pub(super) fn seed(root: &Path, paths: [&Path; 3]) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let origin = tempfile::tempdir_in(root)?;
    let origin_path = origin.path().to_path_buf();
    let mut source = ChunkStore::create(&origin.path().join("source"), limits())?;
    let mut caches = [
        ChunkStore::create(paths[0], limits())?,
        ChunkStore::create(paths[1], limits())?,
        ChunkStore::create(paths[2], limits())?,
    ];
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let trusted = publisher.verifying_key();
    let now = unix_seconds()?;
    let bytes: Vec<_> = (b'A'..=b'O')
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect();
    let signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "disposable-adaptive-native-publication".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: now,
                expires: now + 3600,
            },
        },
        &publisher,
        &mut source,
    )?;
    let manifest = signed.verify(&trusted, now)?;
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let payload = source
            .get(chunk.id())?
            .ok_or("adaptive publisher chunk missing")?;
        caches[index % 3].put_verified(*chunk.id(), &payload)?;
    }
    let usage = caches.each_ref().map(ChunkStore::usage);
    let mut restored = Vec::new();
    reassemble(&manifest, &mut caches.each_mut(), now, &mut restored)?;
    if restored != bytes
        || ChunkId::digest(&restored).to_string() != SHA256
        || manifest.chunks().len() != CHUNKS
        || usage
            .iter()
            .any(|item| item.entries != 5 || item.bytes != 5 * CHUNK_BYTES as u64)
    {
        return Err("adaptive three-cache seed mismatch".into());
    }
    drop((source, publisher, bytes, restored, caches));
    origin.close()?;
    if origin_path.exists() {
        return Err("adaptive publisher directory survived removal".into());
    }
    write_new(&root.join("manifest.bin"), &signed.encode())?;
    write_report(
        &root.join("publication.json"),
        &json!({
            "report_kind": "volparossa-content-adaptive-provider-seed",
            "publisher_hex": hex::encode(trusted.as_bytes()),
            "manifest_id": hex::encode(manifest.manifest_id()),
            "object_sha256": SHA256,
            "bytes": manifest.length(),
            "chunks": manifest.chunks().len(),
            "created_unix_seconds": manifest.validity().created,
            "expires_unix_seconds": manifest.validity().expires,
            "replica_a_chunks": usage[0].entries,
            "replica_b_chunks": usage[1].entries,
            "replica_c_chunks": usage[2].entries,
            "replica_a_bytes": usage[0].bytes,
            "replica_b_bytes": usage[1].bytes,
            "replica_c_bytes": usage[2].bytes,
            "publisher_removed": true,
            "publisher_private_key_persisted": false,
            "recipient_encrypted": false,
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

    use super::*;
    use crate::{Value, manifest, read_bounded};

    #[test]
    fn adaptive_seed_reopens_three_disjoint_caches_with_original_envelope_and_no_publisher()
    -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("publication");
        let paths = ["a", "b", "c"].map(|label| temporary.path().join(label));
        seed(&root, paths.each_ref().map(|path| path.as_path()))?;
        let report: Value =
            serde_json::from_slice(&read_bounded(&root.join("publication.json"), 4096)?)?;
        assert_eq!(report["bytes"], 3_932_160);
        assert_eq!(report["chunks"], 15);
        assert_eq!(report["object_sha256"], SHA256);
        assert_eq!(report["publisher_removed"], true);
        assert_eq!(report["publisher_private_key_persisted"], false);
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        assert_eq!(fs::read_dir(temporary.path())?.count(), 4);
        assert_eq!(fs::metadata(&root)?.permissions().mode() & 0o777, 0o700);
        for filename in ["manifest.bin", "publication.json"] {
            assert_eq!(
                fs::metadata(root.join(filename))?.permissions().mode() & 0o777,
                0o600
            );
        }
        let verified = manifest(
            &root.join("manifest.bin"),
            report["publisher_hex"].as_str().ok_or("publisher absent")?,
        )?;
        assert_eq!(report["manifest_id"], hex::encode(verified.manifest_id()));
        assert_eq!(report["created_unix_seconds"], verified.validity().created);
        assert_eq!(report["expires_unix_seconds"], verified.validity().expires);
        let mut caches = [
            ChunkStore::open(&paths[0], limits())?,
            ChunkStore::open(&paths[1], limits())?,
            ChunkStore::open(&paths[2], limits())?,
        ];
        let mut unique = BTreeSet::new();
        for (index, chunk) in verified.chunks().iter().enumerate() {
            assert_eq!(chunk.length() as usize, CHUNK_BYTES);
            assert!(unique.insert(*chunk.id()));
            for (provider, cache) in caches.iter_mut().enumerate() {
                assert_eq!(cache.get(chunk.id())?.is_some(), index % 3 == provider);
            }
        }
        for (label, cache) in ["a", "b", "c"].into_iter().zip(&caches) {
            assert_eq!(cache.usage().entries, 5);
            assert_eq!(cache.usage().bytes, 1_310_720);
            assert_eq!(report[format!("replica_{label}_chunks")], 5);
            assert_eq!(report[format!("replica_{label}_bytes")], 1_310_720);
        }
        let mut bytes = Vec::new();
        reassemble(
            &verified,
            &mut caches.each_mut(),
            unix_seconds()?,
            &mut bytes,
        )?;
        assert_eq!(bytes.len(), 3_932_160);
        assert_eq!(ChunkId::digest(&bytes).to_string(), SHA256);
        assert!(seed(&root, paths.each_ref().map(|path| path.as_path())).is_err());
        Ok(())
    }
}
