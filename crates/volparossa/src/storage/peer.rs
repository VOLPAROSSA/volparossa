//! Private archive commands. The owner signs locally; only the agent opens overlay routes.

#[path = "replicas.rs"]
pub(super) mod replicas;
#[path = "peer_state.rs"]
mod state;
#[path = "peer_transfer.rs"]
mod transfer;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use volparossa_content::private_storage::{
    MAX_CAPACITY_BYTES, MAX_LEASE_SECONDS,
    protocol::{SignedStorageGrant, StorageRights},
};
use volparossa_local_control::{
    PrivateStorageAdmissionRequest, PrivateStorageGrantRequest, PrivateStorageServeRequest,
    control_request::Operation, control_response::Payload,
};

use crate::content::{IdentityUnlock, parse_publisher_key};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Attach an explicitly owned private store to the running agent's provider service.
    Serve(Serve),
    /// Have the local provider issue a bounded grant for one independently known owner.
    Grant(Grant),
    /// Inspect or set the attached LOCAL provider's admission target, without removing leases.
    Admission(Admission),
    /// Upload already encrypted bytes; retain private state for interrupted-upload retries.
    Deposit(Deposit),
    /// Query the exact retained archive without reading, renewing or consuming it.
    Progress(Existing),
    /// Restore into a NEW 0600 file, exposing it only after full length and SHA-256 checks.
    Restore(Restore),
    /// Explicitly extend this copy's finite lease within the original provider grant.
    Renew(Renew),
    /// Delete this exact provider copy; reads never delete or acknowledge storage.
    Delete(Existing),
}

#[derive(Debug, Args)]
pub(crate) struct Serve {
    #[arg(long)]
    bind: SocketAddr,
    /// Exact DNS hostname admitted by the current Exit policy.
    #[arg(long)]
    advertised_hostname: String,
    #[arg(long)]
    store: PathBuf,
    #[arg(long, required_unless_present = "reuse_store", conflicts_with = "reuse_store",
        value_parser = clap::value_parser!(u64).range(1..=MAX_CAPACITY_BYTES))]
    capacity_bytes: Option<u64>,
    /// New-store free-space floor; defaults to 256 MiB. Cannot override a reused store.
    #[arg(long, conflicts_with = "reuse_store",
        value_parser = clap::value_parser!(u64).range(0..=MAX_CAPACITY_BYTES))]
    min_free_bytes: Option<u64>,
    #[arg(long)]
    reuse_store: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Grant {
    /// Independently known LOCAL provider public key; never inferred from the reply.
    #[arg(long, value_parser = parse_publisher_key)]
    provider_key: VerifyingKey,
    #[arg(long, value_parser = parse_publisher_key)]
    owner_key: VerifyingKey,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=MAX_CAPACITY_BYTES))]
    max_payload_bytes: u64,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=256))]
    max_leases: u32,
    #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    max_retention_seconds: u64,
    /// Known protocol rights bitmask (127 grants all seven current operations).
    #[arg(long, default_value_t = 127, value_parser = clap::value_parser!(u32).range(1..=127))]
    rights: u32,
    #[arg(long, default_value_t = MAX_LEASE_SECONDS, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    /// NEW private grant file. Deliver it separately to the named owner.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct Admission {
    /// Independently pinned LOCAL provider key; this command never contacts a remote provider.
    #[arg(long, value_parser = parse_publisher_key)]
    provider_key: VerifyingKey,
    /// Omit to inspect; zero closes new reservation admission but retains all existing custody.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..=MAX_CAPACITY_BYTES))]
    target_bytes: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct Existing {
    /// Original owned 0700 archive state directory; contains private metadata, not owner keys.
    #[arg(long)]
    state: PathBuf,
    /// Independently trusted provider key, which must match the retained journal exactly.
    #[arg(long, value_parser = parse_publisher_key)]
    provider_key: VerifyingKey,
    #[command(flatten)]
    unlock: IdentityUnlock,
}

#[derive(Debug, Args)]
pub(crate) struct Deposit {
    /// Original provider-signed grant, obtained separately from provider-key trust.
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    input: PathBuf,
    /// Independently pinned SHA-256 of the complete already encrypted archive.
    #[arg(long)]
    sha256: String,
    /// Acknowledge that encryption happened before this command; no plaintext encryption is added.
    #[arg(long, required = true)]
    already_encrypted: bool,
    /// Retry this exact journal/archive/reservation, never allocate another archive identity.
    #[arg(long)]
    resume: bool,
    #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    #[command(flatten)]
    existing: Existing,
}

#[derive(Debug, Args)]
pub(crate) struct Restore {
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    existing: Existing,
}

#[derive(Debug, Args)]
pub(crate) struct Renew {
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    #[command(flatten)]
    existing: Existing,
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Serve(args) => return serve(args, socket).await,
        Command::Grant(args) => grant(args, socket).await?,
        Command::Admission(args) => admission(&args, socket).await?,
        Command::Deposit(args) => Box::pin(transfer::deposit(args, socket)).await?,
        Command::Progress(args) => transfer::existing(args, socket, None, false).await?,
        Command::Restore(args) => Box::pin(transfer::restore(args, socket)).await?,
        Command::Renew(args) => {
            transfer::existing(args.existing, socket, Some(args.lifetime_seconds), false).await?
        }
        Command::Delete(args) => transfer::existing(args, socket, None, true).await?,
    };
    super::print(&report)
}

async fn serve(args: Serve, socket: &Path) -> Result<()> {
    super::require_absolute(&args.store)?;
    let request = PrivateStorageServeRequest {
        bind_address: args.bind.to_string(),
        advertised_hostname: args.advertised_hostname,
        store: args
            .store
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("store path is not UTF-8"))?
            .into(),
        capacity_bytes: args.capacity_bytes.unwrap_or(0),
        min_free_bytes: if args.reuse_store {
            0
        } else {
            args.min_free_bytes.unwrap_or(256 * 1024 * 1024)
        },
        reuse_store: args.reuse_store,
    };
    crate::print_response(
        tokio::time::timeout(
            Duration::from_secs(120),
            crate::control::request(socket, Operation::PrivateStorageServe(request)),
        )
        .await??,
    )
}

async fn admission(args: &Admission, socket: &Path) -> Result<serde_json::Value> {
    let request = PrivateStorageAdmissionRequest {
        provider_key: args.provider_key.to_bytes().to_vec(),
        target_bytes: args.target_bytes,
    };
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        crate::control::request(socket, Operation::PrivateStorageAdmission(request)),
    )
    .await??;
    ensure!(
        response.diagnostic_code == "PRIVATE_STORAGE_ADMISSION",
        "missing private storage admission result"
    );
    let Some(Payload::PrivateStorageAdmission(status)) = response.payload else {
        anyhow::bail!("missing typed private storage admission status")
    };
    ensure!(
        status.provider_key == args.provider_key.as_bytes()
            && args
                .target_bytes
                .is_none_or(|target| target == status.target_bytes),
        "local provider or admission target differs from the explicit request"
    );
    Ok(serde_json::json!({
        "operation": "private_storage_local_admission", "scope": "local-provider-only",
        "provider_key": hex::encode(status.provider_key), "capacity_bytes": status.capacity_bytes,
        "target_bytes": status.target_bytes, "reserved_bytes": status.reserved_bytes,
        "committed_bytes": status.committed_bytes, "leases": status.leases,
        "retained_payload_bytes": status.retained_payload_bytes,
        "pending_drain_bytes": status.pending_drain_bytes,
        "pending_drain": status.pending_drain_bytes > 0,
        "available_for_new_reservations_bytes": status.available_for_new_reservations_bytes,
        "accounting_unit": "ciphertext-payload-bytes-per-copy", "metadata_overhead_measured": false,
        "automatic_migration": false, "automatic_contribution_resize": false,
        "remote_replication": false, "network_contribution_verified": false,
    }))
}

async fn grant(args: Grant, socket: &Path) -> Result<serde_json::Value> {
    state::new_output(&args.output)?;
    let request = PrivateStorageGrantRequest {
        owner_key: args.owner_key.to_bytes().to_vec(),
        max_payload_bytes: args.max_payload_bytes,
        max_leases: args.max_leases,
        max_retention_seconds: args.max_retention_seconds,
        rights: args.rights,
        lifetime_seconds: args.lifetime_seconds,
    };
    let before = super::now()?;
    let response = tokio::time::timeout(
        Duration::from_secs(120),
        crate::control::request(socket, Operation::PrivateStorageGrant(request)),
    )
    .await??;
    let Some(Payload::PrivateStorageGrant(reply)) = response.payload else {
        anyhow::bail!("missing private storage provider grant")
    };
    ensure!(
        reply.provider_key == args.provider_key.as_bytes(),
        "grant provider differs from independent trust"
    );
    let verified =
        SignedStorageGrant::decode(&reply.grant)?.verify(&args.provider_key, super::now()?)?;
    let limits = verified.limits();
    ensure!(
        verified.owner_key() == &args.owner_key
            && limits.max_payload_bytes == args.max_payload_bytes
            && limits.max_leases == args.max_leases
            && limits.max_retention_seconds == args.max_retention_seconds
            && limits.rights == StorageRights::from_bits(args.rights)?
            && verified.validity().created >= before
            && verified.validity().expires - verified.validity().created == args.lifetime_seconds,
        "provider grant differs from explicitly requested scope"
    );
    state::private_output(&args.output, &reply.grant)?;
    Ok(serde_json::json!({
        "operation": "private_storage_peer_grant", "grant_written": true,
        "max_payload_bytes": limits.max_payload_bytes, "max_leases": limits.max_leases,
        "expires_unix_seconds": verified.validity().expires,
        "reserved_bytes": 0, "network_contribution_credit": false
    }))
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
