//! Seed healthy incomplete custody for a disposable restart/repair scenario.
//! This is explicit test setup, not proof of initial network placement. Both services must
//! be stopped; the existing final owned stores must be empty. Never remove a journaled chunk
//! to imitate an incomplete replica: that would create corruption, not recoverable work.

use super::{
    CHUNK_BYTES, CacheLimits, ChunkStore, DirBuilderExt, Metadata, Path, Publication, Result,
    SigningKey, Validity, fs, json, publish, unix_seconds, write_new, write_report,
};
use volparossa_content::provider::{
    custody_storage::PublicCustodyStore,
    replication::{LocalReplicaLimits, admit_public_replica, restore_public_replicas},
};

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 16 * 1024 * 1024,
        max_entries: 64,
        min_free_bytes: 256 * 1024 * 1024,
    }
}

pub(super) fn seed(root: &Path, holder: &Path, receiver: &Path) -> Result<()> {
    if !holder.is_absolute() || !receiver.is_absolute() || holder == receiver {
        return Err("repair needs two distinct absolute owned cache paths".into());
    }
    // Opening both together rejects aliases and live cache owners before any seeding.
    let mut first = ChunkStore::open(holder, limits())?;
    let mut second = ChunkStore::open(receiver, limits())?;
    let at = unix_seconds()?;
    for cache in [&mut first, &mut second] {
        if cache.usage().entries != 0
            || cache.usage().bytes != 0
            || !restore_public_replicas(cache, at)?.is_empty()
        {
            return Err("repair seed refuses a populated or invalid cache".into());
        }
    }
    drop(first);
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let original = tempfile::tempdir_in(root)?;
    let original_path = original.path().to_path_buf();
    let mut source = ChunkStore::create(&original.path().join("publisher"), limits())?;
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let public = publisher.verifying_key();
    let payload: Vec<_> = [17_u8, 59, 101]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect();
    let signed = publish(
        &mut payload.as_slice(),
        Publication {
            metadata: Metadata {
                name: "disposable-public-repair".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: payload.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 7200,
            },
        },
        &publisher,
        &mut source,
    )?;
    let manifest = signed.verify(&public, at)?;
    let custody = PublicCustodyStore::open(holder.to_path_buf(), limits())?;
    custody.admit(&signed, &manifest, &mut source, at)?;
    let partial = admit_public_replica(
        &signed,
        &manifest,
        &mut source,
        &mut second,
        LocalReplicaLimits {
            max_chunks: 1,
            max_bytes: CHUNK_BYTES as u64,
        },
        at,
    )?;
    let partial_bytes = second.usage().bytes;
    if partial.chunks != 1 || partial_bytes != CHUNK_BYTES as u64 {
        return Err("repair receiver seed was not exactly one public chunk".into());
    }
    drop((source, second, publisher, payload));
    original.close()?;
    if original_path.exists() {
        return Err("repair publisher source survived cleanup".into());
    }
    // Reopen both final journals after source and private signing key disappear.
    if custody
        .inspect_complete(manifest.manifest_id(), at)?
        .is_none()
        || PublicCustodyStore::open(receiver.to_path_buf(), limits())?
            .inspect_complete(manifest.manifest_id(), at)?
            .is_some()
    {
        return Err("repair initial complete/partial states are incorrect".into());
    }
    write_new(&root.join("manifest.bin"), &signed.encode())?;
    write_report(
        &root.join("publication.json"),
        &json!({
            "report_kind": "volparossa-public-repair-seed",
            "publisher_hex": hex::encode(public.as_bytes()),
            "manifest_id": hex::encode(manifest.manifest_id()),
            "object_sha256": hex::encode(manifest.object_sha256()),
            "bytes": manifest.length(),
            "chunks": manifest.chunks().len(),
            "created_unix_seconds": manifest.validity().created,
            "expires_unix_seconds": manifest.validity().expires,
            "holder_chunks": 3,
            "receiver_chunks": 1,
            "receiver_bytes": partial_bytes,
            "missing_chunks": 2,
            "missing_bytes": 2 * CHUNK_BYTES,
            "publisher_removed": true,
            "publisher_private_key_persisted": false,
            "initial_placement_over_network": false,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_retains_full_and_healthy_partial_journals_without_a_publisher() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("metadata");
        let holder = temporary.path().join("holder");
        let receiver = temporary.path().join("receiver");
        drop(ChunkStore::create(&holder, limits())?);
        drop(ChunkStore::create(&receiver, limits())?);
        seed(&root, &holder, &receiver)?;
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("publication.json"))?)?;
        assert_eq!(report["bytes"], 3 * CHUNK_BYTES);
        assert_eq!(report["receiver_bytes"], CHUNK_BYTES);
        assert_eq!(report["initial_placement_over_network"], false);
        let at = unix_seconds()?;
        let mut cache = ChunkStore::open(&receiver, limits())?;
        let replicas = restore_public_replicas(&mut cache, at)?;
        assert_eq!(replicas.len(), 1);
        assert_eq!(replicas[0].chunk_ids().len(), 1);
        assert_eq!(
            Some(replicas[0].validity().expires),
            report["expires_unix_seconds"].as_u64()
        );
        drop(cache);
        assert!(seed(&temporary.path().join("second"), &holder, &receiver).is_err());
        assert!(!temporary.path().join("second").exists());
        assert!(seed(&temporary.path().join("aliased"), &holder, &holder).is_err());
        Ok(())
    }
}
