//! Explicit owner-selected copies, retaining the existing authenticated peer transfer path.

#[path = "replicas_transfer.rs"]
mod operations;
#[path = "replicas_state.rs"]
mod retained;

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use volparossa_content::private_storage::{
    MAX_LEASE_SECONDS,
    protocol::{MAX_GRANT_BYTES, SignedStorageGrant},
};

use super::{state, transfer};
use crate::content::{IdentityUnlock, parse_publisher_key};
use retained::LockedSet;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Prepare a NEW private set with 2..8 explicit provider/grant pairs; no network writes.
    Create(Create),
    /// Upload or resume the same ciphertext on every remaining selected provider.
    Deposit(Deposit),
    /// Read local accounting, including uncertain and expired-but-not-deleted copies.
    Status {
        #[arg(long)]
        state: PathBuf,
    },
    /// Refresh each known lease through its independently pinned provider.
    Progress(Existing),
    /// Try retained copies in order; publish only a fully verified NEW output file.
    Restore(Restore),
    /// Explicitly renew remaining known copies within each original grant.
    Renew(Renew),
    /// Explicitly delete ONE provider copy; never roll back or delete other copies.
    Delete(Delete),
}

#[derive(Debug, Args)]
pub(crate) struct Existing {
    /// Original owned 0700 replica-set directory; never contains an owner private key.
    #[arg(long)]
    state: PathBuf,
    #[command(flatten)]
    unlock: IdentityUnlock,
}

#[derive(Debug, Args)]
pub(crate) struct Create {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    sha256: String,
    #[arg(long, required = true)]
    already_encrypted: bool,
    /// Repeat once per provider, in the same order as --grant. Keys must be independently trusted.
    #[arg(long, value_parser = parse_publisher_key, required = true)]
    provider_key: Vec<VerifyingKey>,
    /// Repeat once per provider. Grants remain bound to the single unlocked owner.
    #[arg(long, required = true)]
    grant: Vec<PathBuf>,
    #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    #[command(flatten)]
    existing: Existing,
}

#[derive(Debug, Args)]
pub(crate) struct Deposit {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, required = true)]
    already_encrypted: bool,
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

#[derive(Debug, Args)]
pub(crate) struct Delete {
    /// Exact independently pinned provider to delete; all other copies are left untouched.
    #[arg(long, value_parser = parse_publisher_key)]
    provider_key: VerifyingKey,
    #[command(flatten)]
    existing: Existing,
}

pub(in crate::storage) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Create(args) => create(&args)?,
        Command::Status { state } => LockedSet::open(&state)?.report("status")?,
        Command::Deposit(args) => {
            ensure!(
                args.already_encrypted,
                "already-encrypted acknowledgement is required"
            );
            let signer = args.existing.unlock.signer()?;
            let mut set = LockedSet::open(&args.existing.state)?;
            set.check_owner(&signer)?;
            let (mut input, length) = transfer::checked_input(&args.input, set.data.sha256)?;
            ensure!(
                length == set.data.ciphertext_bytes,
                "replica ciphertext length changed"
            );
            operations::deposit(&mut set, socket, &signer, &mut input).await?
        }
        Command::Progress(args) => {
            let signer = args.unlock.signer()?;
            let mut set = LockedSet::open(&args.state)?;
            operations::refresh(&mut set, socket, &signer, None).await?
        }
        Command::Restore(args) => {
            state::new_output(&args.output)?;
            let signer = args.existing.unlock.signer()?;
            let mut set = LockedSet::open(&args.existing.state)?;
            operations::restore(&mut set, socket, &signer, &args.output).await?
        }
        Command::Renew(args) => {
            let signer = args.existing.unlock.signer()?;
            let mut set = LockedSet::open(&args.existing.state)?;
            operations::refresh(&mut set, socket, &signer, Some(args.lifetime_seconds)).await?
        }
        Command::Delete(args) => {
            let signer = args.existing.unlock.signer()?;
            let mut set = LockedSet::open(&args.existing.state)?;
            operations::delete(&mut set, socket, &signer, args.provider_key).await?
        }
    };
    let complete = report["operation_complete"].as_bool().unwrap_or(true);
    crate::storage::print(&report)?;
    ensure!(
        complete,
        "replica operation incomplete; retained copies and uncertain accounting preserved"
    );
    Ok(())
}

fn create(args: &Create) -> Result<serde_json::Value> {
    ensure!(
        args.already_encrypted,
        "already-encrypted acknowledgement is required"
    );
    ensure!(
        (2..=retained::MAX_COPIES).contains(&args.provider_key.len())
            && args.provider_key.len() == args.grant.len(),
        "specify 2..8 distinct provider keys with one grant each, in the same order"
    );
    let signer = args.existing.unlock.signer()?;
    let expected = crate::storage::parse_hash(&args.sha256)?;
    let (_, length) = transfer::checked_input(&args.input, expected)?;
    let mut grants = Vec::with_capacity(args.grant.len());
    for (provider, path) in args.provider_key.iter().zip(&args.grant) {
        let encoded = state::read_private(path, MAX_GRANT_BYTES as u64)?;
        grants
            .push(SignedStorageGrant::decode(&encoded)?.verify(provider, crate::storage::now()?)?);
    }
    LockedSet::create(
        &args.existing.state,
        &signer.verifying_key(),
        length,
        expected,
        &grants,
        args.lifetime_seconds,
    )?
    .report("create")
}

#[cfg(test)]
#[path = "replicas_tests.rs"]
mod tests;
