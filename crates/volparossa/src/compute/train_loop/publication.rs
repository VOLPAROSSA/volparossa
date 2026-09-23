//! Durable publication retry for already completed, owner-authorized public training.

use std::{future::Future, time::Duration};

use serde::Serialize;
use tokio::time::Instant;

use super::{
    Context, Cycle, Options, Path, Phase, Result, SignedManifest, Snapshot, State, Store, Value,
    VerifyingKey, active, content, ensure, json, now, read_file, watch,
};
use volparossa_content::{VerifiedManifest, agent_artifact::ADAPTER_CONTENT_TYPE};

mod joint;
pub(super) use joint::restore_order;

struct Binding<'a> {
    key: VerifyingKey,
    name: &'a str,
    revision: u64,
    snapshot: &'a Snapshot,
    source_expires: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DrainOutcome {
    Complete,
    Retired,
    Expired,
    Cancelled,
    Deadline,
}

fn settled(state: &State) -> Option<DrainOutcome> {
    if state.cycles.iter().any(|cycle| {
        cycle.retirement.is_none() && matches!(cycle.phase, Phase::Trained | Phase::PublishPending)
    }) || state.aggregate_updates.as_ref().is_some_and(|registry| {
        !super::aggregate_updates::publication::pending_sequences(registry).is_empty()
    }) {
        None
    } else if state.cycles.iter().any(|cycle| cycle.retirement.is_some())
        || state
            .aggregate_updates
            .as_ref()
            .is_some_and(super::aggregate_updates::publication::has_retired)
    {
        Some(DrainOutcome::Retired)
    } else if state
        .cycles
        .iter()
        .any(|cycle| cycle.phase == Phase::PublicationExpired)
        || state
            .aggregate_updates
            .as_ref()
            .is_some_and(super::aggregate_updates::publication::has_expired)
    {
        Some(DrainOutcome::Expired)
    } else {
        Some(DrainOutcome::Complete)
    }
}

/// One fixed post-cycle window for the entire retained set, never more model execution.
pub(super) async fn drain(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<DrainOutcome> {
    let deadline = Instant::now() + Duration::from_secs(u64::from(args.max_seconds));
    loop {
        if let Some(outcome) = settled(state) {
            return Ok(outcome);
        }
        if !active(activity) {
            return Ok(DrainOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(DrainOutcome::Deadline);
        }
        pending_until(args, socket, store, state, activity, Some(deadline)).await?;
        if let Some(outcome) = settled(state) {
            return Ok(outcome);
        }
        let mut receiver = activity.clone();
        tokio::select! {
            biased;
            _ = receiver.changed() => {},
            () = tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_millis(250))) => {},
        }
    }
}

pub(super) async fn pending(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    pending_until(args, socket, store, state, activity, None).await
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep durable publication preparation before every bounded handoff and terminal state save"
)]
async fn pending_until(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
    deadline: Option<Instant>,
) -> Result<()> {
    let Some(name) = &args.publish_name else {
        return Ok(());
    };
    if args.aggregate_plan.is_some() {
        return joint::pending(args, socket, store, state, activity, deadline).await;
    }
    let mut prepared = Vec::new();
    let mut changed = false;
    for (index, cycle) in state.cycles.iter_mut().enumerate() {
        if !active(activity) || deadline.is_some_and(|limit| Instant::now() >= limit) {
            break;
        }
        if !retry_due(cycle, store, now()?)? {
            continue;
        }
        let previous = serde_json::to_value(&*cycle)?;
        if let Some(verified) = prepare(args, socket, store, cycle, name, None).await? {
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
        if !active(activity) || deadline.is_some_and(|limit| Instant::now() >= limit) {
            break;
        }
        let cycle = &mut state.cycles[index];
        deliver(args, socket, store, cycle, &verified, activity, deadline).await?;
        changed = true;
    }
    if changed {
        store.save_state(&serde_json::to_value(state)?)?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Reuse one original manifest handoff in legacy and shared revision queues"
)]
async fn deliver(
    args: &Options,
    socket: &Path,
    store: &Store,
    cycle: &mut Cycle,
    verified: &VerifiedManifest,
    activity: &watch::Receiver<bool>,
    deadline: Option<Instant>,
) -> Result<()> {
    let request = content::Contribute::existing(
        store.cycle_path(cycle.sequence)?.join("publication.pb"),
        args.publication_key.context("train_loop_publication_key")?,
        args.publish_cache
            .clone()
            .context("train_loop_publish_cache")?,
        args.limits.clone(),
    )
    .expect_manifest_id(*verified.manifest_id());
    let expiry_deadline =
        Instant::now() + Duration::from_secs(verified.validity().expires.saturating_sub(now()?));
    let until = deadline.map_or(expiry_deadline, |limit| limit.min(expiry_deadline));
    // Only the affine IPC transfer is droppable, never a model worker.
    let receipt = handoff(
        activity,
        until,
        content::contribute_existing(&request, socket),
    )
    .await;
    let reason = match receipt {
        Handoff::Received(Ok(mut receipt)) => {
            validate_receipt(&receipt, verified)?;
            let observed = now()?;
            ensure!(
                observed >= verified.validity().created && observed < verified.validity().expires,
                "train_loop_receipt_expired"
            );
            receipt["coordinator_verified_at_unix_seconds"] = observed.into();
            store.write_cycle_json(cycle.sequence, "contribution.json", &receipt)?;
            cycle.phase = Phase::Complete;
            None
        }
        Handoff::Received(Err(error)) => Some(failure_reason(&error)),
        Handoff::Cancelled => Some("owner_cancelled"),
        Handoff::Deadline => Some("deadline"),
    };
    if let Some(reason) = reason {
        eprintln!("compute loop_event=publication_handoff_deferred reason={reason}");
        if now()? >= verified.validity().expires {
            cycle.phase = Phase::PublicationExpired;
        } else {
            defer(cycle, args.poll_seconds)?;
        }
    }
    Ok(())
}

fn retry_due(cycle: &Cycle, store: &Store, at: u64) -> Result<bool> {
    if cycle.retirement.is_some() || !matches!(cycle.phase, Phase::Trained | Phase::PublishPending)
    {
        return Ok(false);
    }
    if cycle.next_publication_attempt <= at {
        return Ok(true);
    }
    // Expiry retirement must not wait for a later retry slot. prepare() still independently
    // verifies the original envelope/binding before changing its durable phase.
    let expires = if let Some(publication) = &cycle.publication {
        publication["expires"]
            .as_u64()
            .context("train_loop_publication_expiry")?
    } else {
        authority_expiry(&store.read_cycle_json(cycle.sequence, "result.json")?)?
    };
    Ok(expires <= at)
}

enum Handoff {
    Received(Result<Value>),
    Cancelled,
    Deadline,
}

pub(super) fn authority_expiry(result: &Value) -> Result<u64> {
    let source = result["source_expires_unix_seconds"]
        .as_u64()
        .context("train_loop_source_expiry")?;
    result
        .get("authority_expires_unix_seconds")
        .map_or(Ok(source), |value| {
            Ok(source.min(value.as_u64().context("train_loop_inherited_expiry")?))
        })
}

async fn handoff(
    activity: &watch::Receiver<bool>,
    deadline: Instant,
    transfer: impl Future<Output = Result<Value>>,
) -> Handoff {
    let mut receiver = activity.clone();
    tokio::select! {
        biased;
        () = async {
            while active(&receiver) {
                if receiver.changed().await.is_err() { break; }
            }
        } => Handoff::Cancelled,
        () = tokio::time::sleep_until(deadline) => Handoff::Deadline,
        result = transfer => Handoff::Received(result),
    }
}

// Never persist a formatted upstream exception, path, publisher name or payload. These
// complete fixed rejection strings are produced by the existing typed control response.
fn failure_reason(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if cause.is::<tokio::time::error::Elapsed>() {
            return "timeout";
        }
        if let Some(content) = cause.downcast_ref::<volparossa_content::Error>() {
            return match content {
                volparossa_content::Error::Io(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    "cache_busy"
                }
                volparossa_content::Error::Quota => "cache_quota",
                volparossa_content::Error::Expired => "expired",
                _ => "content_invalid",
            };
        }
        if cause.is::<volparossa_content::transfer::TransferError>() {
            return "transfer";
        }
        if cause.is::<std::io::Error>() {
            return "io";
        }
    }
    match error.root_cause().to_string().as_str() {
        "agent rejected request: CONTENT_BUSY (InvalidState)" => "agent_busy",
        "agent rejected request: CONTENT_UNAVAILABLE (Unavailable)" => "agent_unavailable",
        "agent rejected request: CONTENT_POLICY (Policy)" => "agent_policy",
        "agent rejected request: CONTENT_INVALID (InvalidRequest)" => "agent_invalid",
        _ => "unconfirmed",
    }
}

async fn prepare(
    args: &Options,
    socket: &Path,
    store: &Store,
    cycle: &mut Cycle,
    name: &str,
    assigned_revision: Option<u64>,
) -> Result<Option<VerifiedManifest>> {
    ensure!(cycle.retirement.is_none(), "train_loop_retired_publication");
    let snapshot = cycle
        .snapshot
        .as_ref()
        .context("train_loop_snapshot_required")?;
    store.validate_snapshot(cycle.sequence, snapshot)?;
    let decision = super::evaluation::verify(store, cycle.sequence)?;
    ensure!(
        decision.approved && decision.has_validation() == args.validation_source.is_some(),
        "train_loop_unapproved_publication"
    );
    let root = store.cycle_path(cycle.sequence)?;
    let result = store.read_cycle_json(cycle.sequence, "result.json")?;
    let source_expires = authority_expiry(&result)?;
    let binding = Binding {
        key: args.publication_key.context("train_loop_publication_key")?,
        name,
        revision: match assigned_revision {
            Some(revision) => revision,
            None => expected_revision(args.first_publication_revision, cycle.sequence)?,
        },
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

    #[test]
    fn inherited_aggregate_authority_cannot_be_renewed_by_a_later_source() {
        assert_eq!(
            authority_expiry(&json!({"source_expires_unix_seconds":3000})).unwrap(),
            3000
        );
        assert_eq!(
            authority_expiry(&json!({"source_expires_unix_seconds":3000,
            "authority_expires_unix_seconds":2000}))
            .unwrap(),
            2000
        );
        assert_eq!(
            authority_expiry(&json!({"source_expires_unix_seconds":1500,
            "authority_expires_unix_seconds":2000}))
            .unwrap(),
            1500
        );
        assert!(
            authority_expiry(&json!({"source_expires_unix_seconds":3000,
            "authority_expires_unix_seconds":"renewed"}))
            .is_err()
        );
    }
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

    #[tokio::test]
    async fn all_handoffs_share_one_deadline_and_drop_only_the_transfer() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct TransferOwner(Arc<AtomicBool>);
        impl Drop for TransferOwner {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let (_owner, activity) = watch::channel(true);
        let deadline = Instant::now() + Duration::from_millis(100);
        let first = handoff(&activity, deadline, async {
            Err(anyhow::anyhow!(
                "agent rejected request: CONTENT_BUSY (InvalidState)"
            ))
        })
        .await;
        assert!(matches!(first, Handoff::Received(Err(_))));
        let closed = Arc::new(AtomicBool::new(false));
        let transfer_owner = TransferOwner(Arc::clone(&closed));
        let transfer = async move {
            let _owner = transfer_owner;
            std::future::pending().await
        };
        assert!(matches!(
            handoff(&activity, deadline, transfer).await,
            Handoff::Deadline
        ));
        assert!(closed.load(Ordering::SeqCst));
        assert!(matches!(
            handoff(&activity, deadline, async {
                panic!("a later item must not receive a fresh transfer window")
            })
            .await,
            Handoff::Deadline
        ));
        let (_owner, cancelled) = watch::channel(false);
        assert!(matches!(
            handoff(
                &cancelled,
                Instant::now() + Duration::from_secs(60),
                async { panic!("cancelled owner cannot start another handoff") }
            )
            .await,
            Handoff::Cancelled
        ));
    }

    #[test]
    fn expired_publications_are_not_complete_and_failure_reasons_are_fixed() {
        let mut state = State::new(1);
        assert_eq!(settled(&state), Some(DrainOutcome::Complete));
        state.cycles.push(Cycle {
            sequence: 1,
            source: 0,
            phase: Phase::PublicationExpired,
            snapshot: None,
            training: None,
            publication: None,
            retirement: None,
            next_publication_attempt: 0,
        });
        assert_eq!(settled(&state), Some(DrainOutcome::Expired));
        state.cycles[0].phase = Phase::PublishPending;
        assert_eq!(settled(&state), None);
        let secret = "/private/key-and-publisher-name";
        assert_eq!(failure_reason(&anyhow::anyhow!(secret)), "unconfirmed");
        let io = anyhow::Error::new(std::io::Error::other(secret)).context("private source");
        assert_eq!(failure_reason(&io), "io");
        let busy = anyhow::Error::new(volparossa_content::Error::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            secret,
        )));
        assert_eq!(failure_reason(&busy), "cache_busy");
        let rejected =
            anyhow::anyhow!("agent rejected request: CONTENT_BUSY (InvalidState)").context(secret);
        assert_eq!(failure_reason(&rejected), "agent_busy");
        let spoof =
            anyhow::anyhow!("agent rejected request: CONTENT_BUSY (InvalidState): {secret}");
        assert_eq!(failure_reason(&spoof), "unconfirmed");
    }

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
