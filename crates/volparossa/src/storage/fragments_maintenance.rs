//! Explicit owner-private maintenance. The core grants each turn; journals own every retry.

use super::super::retained::{Charge, HandoffPhase};
use super::{operations, placement, repair, retained::LockedFragments, state, transfer};
use crate::content::{IdentityUnlock, parse_publisher_key};
use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};
use tokio::io::AsyncReadExt as _;
use volparossa_content::private_storage::{
    MAX_LEASE_SECONDS,
    protocol::{SignedStorageGrant, VerifiedStorageGrant},
};
use volparossa_local_control::{
    PrivateStorageMaintenanceRequest, control_request::Operation, control_response::Payload,
};

const DOMAIN: &[u8] = b"VOLPAROSSA/private-storage-maintenance-enrollment/v1\0";
const MAX_ENROLLMENT: u64 = 32768;

#[cfg(test)]
#[path = "fragments_maintenance_tests.rs"]
mod tests;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Enroll exactly one already retained archive; signs authority but performs no networking.
    Enroll(Box<Enroll>),
    /// Wait for core-issued turns, keeping owner signing and archive paths in this process.
    Serve(Serve),
    /// Read private enrollment/checkpoint state, without unlock or network access.
    Status {
        #[arg(long)]
        enrollment: PathBuf,
    },
}

#[derive(Debug, Args)]
pub(crate) struct Enroll {
    #[arg(long)]
    enrollment: PathBuf,
    #[arg(long)]
    state: PathBuf,
    #[arg(long, value_parser = parse_publisher_key)]
    from_provider_key: VerifyingKey,
    #[arg(long, required = true, value_parser = parse_publisher_key)]
    provider_key: Vec<VerifyingKey>,
    #[arg(long, required = true)]
    grant: Vec<PathBuf>,
    /// Finite permission for maintenance, not an extension of provider-issued grants.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    authorization_seconds: u64,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    renew_before_seconds: u64,
    /// Includes originals, replacement copies and all uncertain retained obligations.
    #[arg(long)]
    maximum_charged_bytes: u64,
    #[arg(long, default_value_t = 134_217_728, value_parser = clap::value_parser!(u64).range(1..=134_217_728))]
    maximum_turn_bytes: u64,
    #[command(flatten)]
    unlock: IdentityUnlock,
}

#[derive(Debug, Args)]
pub(crate) struct Serve {
    #[arg(long)]
    enrollment: PathBuf,
    /// Optional finite run bound for explicit supervised trials; no independent work timer.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=4096))]
    maximum_turns: Option<u32>,
    #[command(flatten)]
    unlock: IdentityUnlock,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    id: [u8; 32],
    owner: [u8; 32],
    root: [u8; 32],
    archive: PathBuf,
    source: [u8; 32],
    providers: Vec<[u8; 32]>,
    grants: Vec<String>,
    created: u64,
    expires: u64,
    lifetime: u64,
    renew_before: u64,
    maximum_charged: u64,
    maximum_turn: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnrollment {
    enrollment: Enrollment,
    signature: String,
}

fn signing(enrollment: &Enrollment) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(enrollment)?);
    ensure!(
        bytes.len() as u64 <= MAX_ENROLLMENT,
        "maintenance enrollment too large"
    );
    Ok(bytes)
}

fn save(directory: &File, name: &str, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_ENROLLMENT,
        "maintenance record too large"
    );
    let mut output = tempfile::NamedTempFile::new_in(state::anchored(directory))?;
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    output.write_all(&bytes)?;
    output.as_file().sync_all()?;
    output.persist(state::anchored(directory).join(name))?;
    directory.sync_all()?;
    Ok(())
}

fn load(directory: &File) -> Result<Enrollment> {
    let bytes = state::read_private(
        &state::anchored(directory).join("enrollment.json"),
        MAX_ENROLLMENT,
    )?;
    let signed: SignedEnrollment = serde_json::from_slice(&bytes)?;
    let key = VerifyingKey::from_bytes(&signed.enrollment.owner)?;
    key.verify_strict(
        &signing(&signed.enrollment)?,
        &Signature::from_slice(&hex::decode(&signed.signature)?)?,
    )?;
    let enrollment = signed.enrollment;
    ensure!(
        enrollment.version == 1
            && enrollment.created < enrollment.expires
            && enrollment.expires - enrollment.created <= MAX_LEASE_SECONDS
            && (1..=8).contains(&enrollment.providers.len())
            && enrollment.providers.len() == enrollment.grants.len()
            && (1..=MAX_LEASE_SECONDS).contains(&enrollment.lifetime)
            && (1..=MAX_LEASE_SECONDS).contains(&enrollment.renew_before)
            && (1..=134_217_728).contains(&enrollment.maximum_turn)
            && enrollment.maximum_charged > 0,
        "invalid maintenance enrollment"
    );
    crate::storage::require_absolute(&enrollment.archive)?;
    Ok(enrollment)
}

fn candidates(enrollment: &Enrollment) -> Result<Vec<VerifiedStorageGrant>> {
    let now = crate::storage::now()?;
    ensure!(
        enrollment
            .providers
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == enrollment.providers.len(),
        "duplicate maintenance provider"
    );
    enrollment
        .providers
        .iter()
        .zip(&enrollment.grants)
        .map(|(key, encoded)| {
            let grant = SignedStorageGrant::decode(&hex::decode(encoded)?)?
                .verify(&VerifyingKey::from_bytes(key)?, now)?;
            ensure!(
                grant.owner_key().to_bytes() == enrollment.owner
                    && grant.provider_key().to_bytes() != enrollment.source
                    && grant.provider_key() != grant.owner_key(),
                "maintenance candidate authority mismatch"
            );
            Ok(grant)
        })
        .collect()
}

fn checkpoint(
    directory: &File,
    stage: &str,
    turn: u64,
    detail: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    let value = serde_json::json!({"version":1,"scope":"owner-private-maintenance","stage":stage,
        "turns":turn,"at":crate::storage::now()?,"detail":detail,"core_coordinated":true,
        "new_network_node":false,"automatic_grant_refresh":false,"private_key_exported":false});
    save(directory, "checkpoint.json", &value)?;
    Ok(value)
}

fn check_turn_size(set: &LockedFragments, maximum: u64) -> Result<()> {
    for fragment in &set.data.fragments {
        let chunks = fragment
            .length
            .div_ceil(volparossa_content::CHUNK_BYTES as u64);
        let expected = fragment
            .length
            .saturating_mul(3)
            .saturating_add((chunks * 3 + 24) * 8192);
        ensure!(
            expected <= maximum,
            "fragment exceeds maintenance byte ceiling; explicit foreground repair remains available"
        );
    }
    Ok(())
}

fn enroll(args: Enroll) -> Result<serde_json::Value> {
    ensure!(
        (1..=8).contains(&args.provider_key.len()) && args.provider_key.len() == args.grant.len(),
        "candidate pairs required"
    );
    crate::storage::require_absolute(&args.enrollment)?;
    crate::storage::require_absolute(&args.state)?;
    let signer = args.unlock.signer()?;
    let set = LockedFragments::open(&args.state)?;
    set.check_owner(&signer)?;
    check_turn_size(&set, args.maximum_turn_bytes)?;
    ensure!(
        placement::providers(&set).contains(&args.from_provider_key.to_bytes()),
        "unknown maintenance source"
    );
    let charge = set.report("status")?["physical_payload_charge_upper_bound"]
        .as_u64()
        .context("missing charge")?;
    ensure!(
        args.maximum_charged_bytes >= charge && args.maximum_charged_bytes != 0,
        "maintenance charge ceiling too small"
    );
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    let created = crate::storage::now()?;
    let enrollment = Enrollment {
        version: 1,
        id,
        owner: signer.verifying_key().to_bytes(),
        root: set.root_sha256,
        archive: args.state,
        source: args.from_provider_key.to_bytes(),
        providers: args
            .provider_key
            .iter()
            .map(VerifyingKey::to_bytes)
            .collect(),
        grants: args
            .grant
            .iter()
            .map(|path| state::read_private(path, 2048).map(hex::encode))
            .collect::<Result<_>>()?,
        created,
        expires: created
            .checked_add(args.authorization_seconds)
            .context("expiry overflow")?,
        lifetime: args.lifetime_seconds,
        renew_before: args.renew_before_seconds,
        maximum_charged: args.maximum_charged_bytes,
        maximum_turn: args.maximum_turn_bytes,
    };
    candidates(&enrollment)?;
    let signature = hex::encode(signer.sign(&signing(&enrollment)?).to_bytes());
    fs::DirBuilder::new().mode(0o700).create(&args.enrollment)?;
    let directory = state::directory(&args.enrollment)?;
    save(
        &directory,
        "enrollment.json",
        &SignedEnrollment {
            enrollment,
            signature,
        },
    )?;
    checkpoint(&directory, "enrolled", 0, None)
}

/// No new ledger: inspect the exact retained journals to decide whether their existing renewal is due.
fn renewal_due(
    set: &LockedFragments,
    index: usize,
    enrollment: &Enrollment,
    signer: &SigningKey,
) -> Result<bool> {
    let now = crate::storage::now()?;
    let requested = now
        .checked_add(enrollment.lifetime)
        .context("expiry overflow")?
        .min(enrollment.expires);
    let mut due = false;
    {
        let copies = set.fragment(index)?;
        let mut retiring = placement::retired(set, index);
        if let Some(intent) = &copies.data.handoff {
            if intent.phase == HandoffPhase::Copying {
                retiring.remove(&intent.from);
            }
        }
        for (copy_index, copy) in copies.data.copies.iter().enumerate() {
            if retiring.contains(&copy_index) || copy.charge == Charge::Deleted {
                continue;
            }
            let journal = copies.copy(copy_index)?;
            let grant = journal.journal.grant(
                &VerifyingKey::from_bytes(&copy.provider_key)?,
                &signer.verifying_key(),
            )?;
            ensure!(
                grant.limits().rights.allows(
                    volparossa_content::private_storage::protocol::StorageOperation::Renew {
                        expires_at: requested
                    }
                ) && requested <= grant.validity().expires
                    && requested.saturating_sub(now) <= grant.limits().max_retention_seconds,
                "grant_refresh_required"
            );
            due |= journal.journal.last_expiry <= now.saturating_add(enrollment.renew_before);
        }
    }
    Ok(due)
}

async fn maintain(
    enrollment: &Enrollment,
    socket: &Path,
    signer: &SigningKey,
    scan: u64,
) -> Result<serde_json::Value> {
    let mut set = LockedFragments::open(&enrollment.archive)?;
    set.check_owner(signer)?;
    ensure!(
        set.root_sha256 == enrollment.root,
        "maintenance reconstruction root changed"
    );
    check_turn_size(&set, enrollment.maximum_turn)?;
    let now = crate::storage::now()?;
    ensure!(
        now >= enrollment.created && now < enrollment.expires,
        "enrollment_expired"
    );
    let Ok(grants) = candidates(enrollment) else {
        return Ok(serde_json::json!({"maintenance_stage":"grant_refresh_required"}));
    };
    // Rotate one fragment, rather than restarting an unbounded full-archive scan on every
    // short resource turn. The durable turn count is a cursor, never another custody ledger.
    let index = usize::try_from(scan % u64::try_from(set.data.fragments.len())?)?;
    let renewal = match renewal_due(&set, index, enrollment, signer) {
        Ok(true) => Some(enrollment.lifetime.min(enrollment.expires - now)),
        Ok(false) => None,
        Err(_) => return Ok(serde_json::json!({"maintenance_stage":"grant_refresh_required"})),
    };
    let refreshed =
        operations::refresh_fragment(&set, index, socket, signer, renewal, true).await?;
    // Keep the lower engine's closed outcomes, not its owner/provider identifiers or journal.
    let refresh = serde_json::json!({"fragment_index":index,"renewal":renewal.is_some(),
        "operation_complete":refreshed["operation_complete"],"copy_outcomes":refreshed["copy_outcomes"]});
    let mut needs_repair = false;
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        needs_repair |= copies
            .data
            .handoff
            .as_ref()
            .is_some_and(|intent| intent.phase != HandoffPhase::Complete)
            || copies.data.copies.iter().any(|copy| {
                copy.provider_key == enrollment.source && copy.charge == Charge::Uncertain
            });
    }
    if !needs_repair {
        return Ok(serde_json::json!({"maintenance_stage":"observed","refresh":refresh}));
    }
    let from = VerifyingKey::from_bytes(&enrollment.source)?;
    let charged = set.report("status")?["physical_payload_charge_upper_bound"]
        .as_u64()
        .context("missing charge")?;
    if charged.saturating_add(repair::next_additional_charge(&set, &from)?)
        > enrollment.maximum_charged
    {
        return Ok(serde_json::json!({"maintenance_stage":"charge_limit","refresh":refresh}));
    }
    let repaired = repair::repair(
        &mut set,
        socket,
        signer,
        from,
        &grants,
        enrollment.lifetime.min(enrollment.expires - now),
        1,
    )
    .await?;
    Ok(
        serde_json::json!({"maintenance_stage":"maintained","refresh":refresh,
        "repair_stage":repaired["repair_stage"],"attempted_handoffs":repaired["attempted_handoffs"],
        "fragment_outcomes":repaired["fragment_outcomes"],
        "freshly_verified_replacements":repaired["freshly_verified_replacements"],
        "pending_retirements":repaired["pending_retirements"],
        "physical_payload_charge_upper_bound":repaired["physical_payload_charge_upper_bound"]}),
    )
}

async fn serve(args: Serve, socket: &Path) -> Result<()> {
    let directory = state::directory(&args.enrollment)?;
    let enrollment = load(&directory)?;
    let mut turns = checkpoint_turns(&directory)?;
    let signer = match args.unlock.signer() {
        Ok(key) if key.verifying_key().to_bytes() == enrollment.owner => key,
        _ => {
            crate::storage::print(&checkpoint(&directory, "owner_locked", turns, None)?)?;
            bail!("owner_locked");
        }
    };
    let mut served = 0;
    loop {
        if crate::storage::now()? >= enrollment.expires {
            crate::storage::print(&checkpoint(&directory, "enrollment_expired", turns, None)?)?;
            return Ok(());
        }
        checkpoint(&directory, "waiting_for_core", turns, None)?;
        let request = Operation::PrivateStorageMaintenance(PrivateStorageMaintenanceRequest {
            owner_key: enrollment.owner.to_vec(),
            enrollment_id: enrollment.id.to_vec(),
            maximum_bytes: enrollment.maximum_turn,
        });
        let grant = tokio::select! {
            _ = tokio::signal::ctrl_c() => { checkpoint(&directory,"paused",turns,None)?; return Ok(()); },
            () = tokio::time::sleep(std::time::Duration::from_secs(enrollment.expires.saturating_sub(crate::storage::now()?))) => {
                crate::storage::print(&checkpoint(&directory,"enrollment_expired",turns,None)?)?;
                return Ok(());
            },
            grant = crate::control::begin_request(socket,request) => grant,
        };
        let Ok((mut control, _, response)) = grant else {
            checkpoint(&directory, "core_unavailable", turns, None)?;
            bail!("core_unavailable");
        };
        let Some(Payload::PrivateStorageMaintenanceReady(ready)) = response.payload else {
            bail!("maintenance allowance unavailable");
        };
        ensure!(
            response.diagnostic_code == "PRIVATE_STORAGE_MAINTENANCE_READY"
                && ready.maximum_bytes == enrollment.maximum_turn
                && ready.expires > crate::storage::now()?,
            "invalid maintenance allowance"
        );
        turns = turns
            .checked_add(1)
            .context("maintenance turn cursor exhausted")?;
        served += 1;
        checkpoint(&directory, "working", turns, None)?;
        let mut closed = [0];
        let remaining = ready
            .expires
            .min(enrollment.expires)
            .saturating_sub(crate::storage::now()?);
        let result = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => { checkpoint(&directory,"paused",turns,None)?; return Ok(()); },
            () = tokio::time::sleep(std::time::Duration::from_secs(remaining)) => None,
            _ = control.read(&mut closed) => None,
            result = transfer::with_maintenance_turn(ready.turn,maintain(&enrollment,socket,&signer,turns-1)) => Some(result),
        };
        drop(control);
        let report = match result {
            Some(Ok(detail)) => checkpoint(&directory, "turn_completed", turns, Some(&detail))?,
            Some(Err(_)) => checkpoint(&directory, "retry_pending", turns, None)?,
            None => checkpoint(&directory, "core_turn_revoked", turns, None)?,
        };
        crate::storage::print(&report)?;
        if args.maximum_turns.is_some_and(|maximum| served >= maximum) {
            return Ok(());
        }
    }
}

fn checkpoint_turns(directory: &File) -> Result<u64> {
    let bytes = state::read_private(
        &state::anchored(directory).join("checkpoint.json"),
        MAX_ENROLLMENT,
    )?;
    let checkpoint: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(
        checkpoint["version"] == 1 && checkpoint["scope"] == "owner-private-maintenance",
        "invalid maintenance checkpoint"
    );
    checkpoint["turns"]
        .as_u64()
        .context("invalid maintenance cursor")
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    match command {
        Command::Enroll(args) => crate::storage::print(&enroll(*args)?),
        Command::Serve(args) => Box::pin(serve(args, socket)).await,
        Command::Status { enrollment } => {
            let directory = state::directory_readonly(&enrollment)?;
            let _ = load(&directory)?;
            let bytes = state::read_private(
                &state::anchored(&directory).join("checkpoint.json"),
                MAX_ENROLLMENT,
            )?;
            crate::storage::print(&serde_json::from_slice::<serde_json::Value>(&bytes)?)
        }
    }
}
