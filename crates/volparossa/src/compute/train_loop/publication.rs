//! Durable publication retry for already completed, owner-authorized public training.

use super::{
    Context, Cycle, Options, Path, Phase, Result, SignedManifest, Snapshot, State, Store, Value,
    VerifyingKey, active, content, ensure, json, now, read_file, watch,
};
use volparossa_content::{VerifiedManifest, agent_artifact::ADAPTER_CONTENT_TYPE};

struct Binding<'a> {
    key: VerifyingKey,
    name: &'a str,
    revision: u64,
    snapshot: &'a Snapshot,
    source_expires: u64,
}

pub(super) async fn pending(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let Some(name) = &args.publish_name else {
        return Ok(());
    };
    let mut prepared = Vec::new();
    let mut changed = false;
    for (index, cycle) in state.cycles.iter_mut().enumerate() {
        if !active(activity) {
            break;
        }
        if !matches!(cycle.phase, Phase::Trained | Phase::PublishPending)
            || cycle.next_publication_attempt > now()?
        {
            continue;
        }
        let previous = serde_json::to_value(&*cycle)?;
        if let Some(verified) = prepare(args, socket, store, cycle, name).await? {
            prepared.push((index, verified));
        }
        changed |= previous != serde_json::to_value(&*cycle)?;
    }
    // Exact signed identities must be durable before any network handoff.
    if changed {
        store.save_state(&serde_json::to_value(&*state)?)?;
    }
    changed = false;
    for (index, verified) in prepared {
        if !active(activity) {
            break;
        }
        let cycle = &mut state.cycles[index];
        let request = content::Contribute::existing(
            store.cycle_path(cycle.sequence)?.join("publication.pb"),
            args.publication_key.context("train_loop_publication_key")?,
            args.publish_cache
                .clone()
                .context("train_loop_publish_cache")?,
            args.limits.clone(),
        )
        .expect_manifest_id(*verified.manifest_id());
        let mut receiver = activity.clone();
        let receipt = tokio::select! {
            biased;
            _ = receiver.changed() => None,
            result = content::contribute_existing(&request, socket) => Some(result)
        };
        if let Some(Ok(mut receipt)) = receipt {
            validate_receipt(&receipt, &verified)?;
            let observed = now()?;
            ensure!(
                observed >= verified.validity().created && observed < verified.validity().expires,
                "train_loop_receipt_expired"
            );
            // Local recovery evidence, not a portable signed remote attestation.
            receipt["coordinator_verified_at_unix_seconds"] = observed.into();
            store.write_cycle_json(cycle.sequence, "contribution.json", &receipt)?;
            cycle.phase = Phase::Complete;
        } else {
            defer(cycle, args.poll_seconds)?;
        }
        changed = true;
    }
    if changed {
        store.save_state(&serde_json::to_value(state)?)?;
    }
    Ok(())
}

async fn prepare(
    args: &Options,
    socket: &Path,
    store: &Store,
    cycle: &mut Cycle,
    name: &str,
) -> Result<Option<VerifiedManifest>> {
    let snapshot = cycle
        .snapshot
        .as_ref()
        .context("train_loop_snapshot_required")?;
    store.validate_snapshot(cycle.sequence, snapshot)?;
    let root = store.cycle_path(cycle.sequence)?;
    let result = store.read_cycle_json(cycle.sequence, "result.json")?;
    let source_expires = result["source_expires_unix_seconds"]
        .as_u64()
        .context("train_loop_source_expiry")?;
    let binding = Binding {
        key: args.publication_key.context("train_loop_publication_key")?,
        name,
        revision: expected_revision(args.first_publication_revision, cycle.sequence)?,
        snapshot,
        source_expires,
    };
    let manifest = root.join("publication.pb");
    if present(&root.join("contribution.json"))? {
        // A receipt may already have been fsynced immediately before a crash.
        // Recover that historical handoff; do not rewrite it or renew its lease.
        let receipt = store.read_cycle_json(cycle.sequence, "contribution.json")?;
        let verified = read_publication(&manifest, &binding, receipt_time(&receipt, now()?)?)?;
        validate_record(cycle.publication.as_ref(), &verified)?;
        validate_receipt(&receipt, &verified)?;
        cycle.phase = Phase::Complete;
        return Ok(None);
    }
    if source_expires <= now()? {
        cycle.phase = Phase::PublicationExpired;
        return Ok(None);
    }
    if cycle.phase == Phase::Trained
        && !present(&manifest)?
        && create_publication(args, socket, &root, &binding)
            .await
            .is_err()
    {
        defer(cycle, args.poll_seconds)?;
        return Ok(None);
    }
    let verified = match read_publication(&manifest, &binding, now()?) {
        Ok(verified) => verified,
        Err(error)
            if matches!(
                error.downcast_ref::<volparossa_content::Error>(),
                Some(volparossa_content::Error::Expired)
            ) =>
        {
            cycle.phase = Phase::PublicationExpired;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if cycle.phase == Phase::Trained {
        cycle.publication = Some(publication_record(&verified));
        cycle.phase = Phase::PublishPending;
    } else {
        validate_record(cycle.publication.as_ref(), &verified)?;
    }
    Ok(Some(verified))
}

async fn create_publication(
    args: &Options,
    socket: &Path,
    root: &Path,
    binding: &Binding<'_>,
) -> Result<()> {
    let publication = content::Publish::training_bundle(content::TrainingPublication {
        input: root.join("adapter.bundle"),
        cache: args
            .publish_cache
            .clone()
            .context("train_loop_publish_cache")?,
        reuse_cache: true,
        manifest: root.join("publication.pb"),
        name: binding.name.to_owned(),
        revision: binding.revision,
        lifetime_seconds: 3600,
        expires_not_after: binding.source_expires,
        identity: args.identity.clone().context("train_loop_identity")?,
        passphrase_file: args
            .passphrase_file
            .clone()
            .context("train_loop_passphrase_file")?,
        limits: args.limits.clone(),
    });
    content::publish_command(&publication, socket).await?;
    Ok(())
}

fn expected_revision(first: u64, sequence: u64) -> Result<u64> {
    let revision = first
        .checked_add(
            sequence
                .checked_sub(1)
                .context("train_loop_publication_revision")?,
        )
        .context("train_loop_publication_revision")?;
    ensure!(revision > 0, "train_loop_publication_revision");
    Ok(revision)
}

fn present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn defer(cycle: &mut Cycle, seconds: u16) -> Result<()> {
    cycle.next_publication_attempt = now()?.saturating_add(u64::from(seconds));
    Ok(())
}

fn read_publication(path: &Path, binding: &Binding<'_>, at: u64) -> Result<VerifiedManifest> {
    let signed = SignedManifest::decode(&read_file(path, 64 * 1024)?)?;
    let verified = signed.verify(&binding.key, at)?;
    let bundle = binding
        .snapshot
        .get("adapter.bundle")
        .context("train_loop_bundle_snapshot")?;
    ensure!(
        verified.metadata().name == binding.name
            && verified.metadata().revision == binding.revision
            && verified.metadata().content_type == ADAPTER_CONTENT_TYPE
            && verified.length() == bundle.bytes
            && hex::encode(verified.object_sha256()) == bundle.sha256
            && verified.validity().expires <= binding.source_expires,
        "train_loop_publication_binding"
    );
    Ok(verified)
}

fn publication_record(verified: &VerifiedManifest) -> Value {
    json!({"manifest_id":hex::encode(verified.manifest_id()),"expires":verified.validity().expires})
}

fn validate_record(record: Option<&Value>, verified: &VerifiedManifest) -> Result<()> {
    ensure!(
        record == Some(&publication_record(verified)),
        "train_loop_publication_record"
    );
    Ok(())
}

fn receipt_time(receipt: &Value, current: u64) -> Result<u64> {
    let observed = receipt["coordinator_verified_at_unix_seconds"]
        .as_u64()
        .context("train_loop_receipt_verification_time")?;
    ensure!(
        observed > 0 && observed <= current,
        "train_loop_receipt_verification_time"
    );
    Ok(observed)
}

fn validate_receipt(receipt: &Value, verified: &VerifiedManifest) -> Result<()> {
    ensure!(
        receipt["operation"] == "content_contribute"
            && receipt["network_publication"] == true
            && receipt["serving"] == true
            && receipt["publications"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && receipt["manifest_id"] == hex::encode(verified.manifest_id())
            && receipt["publisher_key_hex"] == hex::encode(verified.publisher())
            && receipt["name"] == verified.metadata().name
            && receipt["revision"] == verified.metadata().revision
            && receipt["content_type"] == verified.metadata().content_type
            && receipt["bytes"] == verified.length()
            && receipt["chunks"].as_u64() == u64::try_from(verified.chunks().len()).ok()
            && receipt["expires_unix_seconds"] == verified.validity().expires
            && receipt["original_signature_reused"] == true
            && receipt["private_keys_transferred"] == false
            && receipt["ownership_changed"] == false
            && receipt["origin_authenticated"] == false,
        "train_loop_contribution_binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::storage;
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

    struct Fixture {
        root: tempfile::TempDir,
        key: VerifyingKey,
        snapshot: Snapshot,
    }

    impl Fixture {
        fn new(content_type: &str) -> Self {
            // Opaque public bytes exercise signature/recovery, never model quality.
            let root = tempfile::tempdir().unwrap();
            let bytes = b"opaque publication binding fixture";
            let identity = SigningKey::from_bytes(&[113; 32]);
            let mut cache = ChunkStore::create(
                &root.path().join("cache"),
                CacheLimits {
                    max_bytes: 1024,
                    max_entries: 4,
                    min_free_bytes: 0,
                },
            )
            .unwrap();
            let signed = volparossa_content::publish(
                &mut bytes.as_slice(),
                Publication {
                    metadata: Metadata {
                        name: "trained".into(),
                        revision: 4,
                        content_type: content_type.into(),
                    },
                    length: bytes.len() as u64,
                    validity: Validity {
                        created: 1000,
                        expires: 1300,
                    },
                },
                &identity,
                &mut cache,
            )
            .unwrap();
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(root.path().join("publication.pb"))
                .unwrap()
                .write_all(&signed.encode())
                .unwrap();
            Self {
                root,
                key: identity.verifying_key(),
                snapshot: Snapshot::from([(
                    "adapter.bundle".into(),
                    storage::FileSnapshot {
                        sha256: hex::encode(Sha256::digest(bytes)),
                        bytes: bytes.len() as u64,
                    },
                )]),
            }
        }
        fn binding(&self) -> Binding<'_> {
            Binding {
                key: self.key,
                name: "trained",
                revision: 4,
                snapshot: &self.snapshot,
                source_expires: 1400,
            }
        }
        fn manifest(&self) -> PathBuf {
            self.root.path().join("publication.pb")
        }
    }

    #[test]
    fn saved_publication_requires_exact_bundle_issuer_name_revision_and_source_expiry() {
        let mut fixture = Fixture::new(ADAPTER_CONTENT_TYPE);
        let path = fixture.manifest();
        let mut binding = fixture.binding();
        let verified = read_publication(&path, &binding, 1100).unwrap();
        validate_record(Some(&publication_record(&verified)), &verified).unwrap();
        assert!(
            validate_record(
                Some(&json!({"manifest_id":"other","expires":1300})),
                &verified
            )
            .is_err()
        );
        binding.key = SigningKey::from_bytes(&[114; 32]).verifying_key();
        assert!(read_publication(&path, &binding, 1100).is_err());
        binding = fixture.binding();
        binding.name = "other";
        assert!(read_publication(&path, &binding, 1100).is_err());
        binding = fixture.binding();
        binding.revision = 5;
        assert!(read_publication(&path, &binding, 1100).is_err());
        binding = fixture.binding();
        binding.source_expires = 1299;
        assert!(read_publication(&path, &binding, 1100).is_err());
        assert!(read_publication(&path, &fixture.binding(), 1300).is_err());
        fixture.snapshot.get_mut("adapter.bundle").unwrap().bytes += 1;
        assert!(read_publication(&path, &fixture.binding(), 1100).is_err());
        fixture.snapshot.get_mut("adapter.bundle").unwrap().bytes -= 1;
        fixture.snapshot.get_mut("adapter.bundle").unwrap().sha256 = "0".repeat(64);
        assert!(read_publication(&path, &fixture.binding(), 1100).is_err());
        let wrong_type = Fixture::new("text/plain");
        assert!(read_publication(&wrong_type.manifest(), &wrong_type.binding(), 1100).is_err());
        assert_eq!(expected_revision(2, 3).unwrap(), 4);
        assert!(expected_revision(u64::MAX, 2).is_err());
        assert!(expected_revision(1, 0).is_err());
    }

    #[test]
    fn terminal_receipt_recovery_keeps_exact_original_identity_without_renewal() {
        let fixture = Fixture::new(ADAPTER_CONTENT_TYPE);
        let verified = read_publication(&fixture.manifest(), &fixture.binding(), 1100).unwrap();
        // A simulated local completed receipt is not proof of remote ML execution.
        let receipt = json!({
            "operation":"content_contribute","network_publication":true,
            "manifest_id":hex::encode(verified.manifest_id()),
            "publisher_key_hex":hex::encode(verified.publisher()),
            "name":"trained","revision":4,"content_type":ADAPTER_CONTENT_TYPE,
            "bytes":verified.length(),"chunks":verified.chunks().len(),
            "expires_unix_seconds":1300,"serving":true,"publications":1,
            "original_signature_reused":true,"private_keys_transferred":false,
            "ownership_changed":false,"origin_authenticated":false,
            "coordinator_verified_at_unix_seconds":1100,
        });
        validate_receipt(&receipt, &verified).unwrap();
        let recorded = receipt_time(&receipt, 1500).unwrap();
        let historical =
            read_publication(&fixture.manifest(), &fixture.binding(), recorded).unwrap();
        validate_record(Some(&publication_record(&verified)), &historical).unwrap();
        validate_receipt(&receipt, &historical).unwrap();
        assert!(read_publication(&fixture.manifest(), &fixture.binding(), 1500).is_err());
        assert!(receipt_time(&receipt, 1099).is_err());
        for field in [
            "manifest_id",
            "publisher_key_hex",
            "name",
            "revision",
            "content_type",
            "bytes",
            "chunks",
            "expires_unix_seconds",
            "serving",
            "publications",
            "network_publication",
            "original_signature_reused",
        ] {
            let mut changed = receipt.clone();
            changed[field] = Value::Null;
            assert!(validate_receipt(&changed, &verified).is_err(), "{field}");
        }
    }
}
