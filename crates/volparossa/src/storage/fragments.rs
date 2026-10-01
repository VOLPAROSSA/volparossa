//! Distinct ciphertext fragments, each using the existing authenticated replica lifecycle.

#[path = "fragments_transfer.rs"]
mod operations;
#[path = "fragments_placement.rs"]
mod placement;
#[path = "fragments_state.rs"]
mod retained;

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use volparossa_content::private_storage::{
    ARCHIVE_COPY_TARGET, MAX_LEASE_SECONDS,
    protocol::{MAX_GRANT_BYTES, SignedStorageGrant},
};

use super::super::{state, transfer};
use crate::content::{IdentityUnlock, parse_publisher_key};
use retained::LockedFragments;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a NEW reconstruction manifest for 3..8 explicit trusted providers; no network writes.
    Create(Create),
    /// Deposit or resume the original fragments and exact per-provider reservations.
    Deposit(Deposit),
    /// Inspect conservative per-fragment/per-copy accounting; does not contact providers.
    Status {
        #[arg(long)]
        state: PathBuf,
    },
    /// Reconcile all known retained leases; never allocate an unknown reservation.
    Progress(Existing),
    /// Reassemble surviving copies into a NEW file only after fragment and full-archive checks.
    Restore(Restore),
    /// Renew remaining retained fragment copies within their original grants.
    Renew(Renew),
    /// Explicitly delete every owned fragment copy; incomplete confirmations remain charged.
    Delete(Existing),
    /// Replace one fragment copy; verify replacement bytes before retiring its original.
    Replace(Box<Replace>),
}

#[derive(Debug, Args)]
pub(crate) struct Existing {
    /// Original owner-only reconstruction directory; retain it independently with recovery keys.
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
    /// Repeat with each corresponding --grant; no trust is inferred from discovery.
    #[arg(long, value_parser = parse_publisher_key, required = true)]
    provider_key: Vec<VerifyingKey>,
    #[arg(long, required = true)]
    grant: Vec<PathBuf>,
    /// Upper fragment size; smaller archives split further to spread distinct fragments.
    #[arg(long, default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=retained::MAX_FRAGMENT_BYTES))]
    fragment_bytes: u64,
    /// Compatibility assertion only; redundancy is owned by the core, not the application.
    #[arg(long, hide = true, default_value_t = ARCHIVE_COPY_TARGET, value_parser = parse_copy_target)]
    copies: usize,
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
pub(crate) struct Replace {
    #[arg(long, value_parser = clap::value_parser!(u16).range(0..256))]
    fragment_index: u16,
    #[arg(long, value_parser = parse_publisher_key)]
    from_provider_key: VerifyingKey,
    #[arg(long, value_parser = parse_publisher_key)]
    provider_key: VerifyingKey,
    #[arg(long)]
    grant: PathBuf,
    #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(1..=MAX_LEASE_SECONDS))]
    lifetime_seconds: u64,
    #[command(flatten)]
    existing: Existing,
}

pub(in crate::storage) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Create(args) => create(&args)?,
        Command::Status { state } => LockedFragments::open(&state)?.report("status")?,
        Command::Deposit(args) => {
            ensure!(
                args.already_encrypted,
                "already-encrypted acknowledgement is required"
            );
            let signer = args.existing.unlock.signer()?;
            let set = LockedFragments::open(&args.existing.state)?;
            set.check_owner(&signer)?;
            let (mut input, length) = transfer::checked_input(&args.input, set.data.sha256)?;
            ensure!(
                length == set.data.ciphertext_bytes,
                "fragmented archive length changed"
            );
            operations::deposit(&set, socket, &signer, &mut input).await?
        }
        Command::Progress(args) => {
            let signer = args.unlock.signer()?;
            let set = LockedFragments::open(&args.state)?;
            operations::refresh(&set, socket, &signer, None).await?
        }
        Command::Restore(args) => {
            state::new_output(&args.output)?;
            let signer = args.existing.unlock.signer()?;
            let set = LockedFragments::open(&args.existing.state)?;
            operations::restore(&set, socket, &signer, &args.output).await?
        }
        Command::Renew(args) => {
            let signer = args.existing.unlock.signer()?;
            let set = LockedFragments::open(&args.existing.state)?;
            operations::refresh(&set, socket, &signer, Some(args.lifetime_seconds)).await?
        }
        Command::Delete(args) => {
            let signer = args.unlock.signer()?;
            let set = LockedFragments::open(&args.state)?;
            operations::delete(&set, socket, &signer).await?
        }
        Command::Replace(args) => {
            let signer = args.existing.unlock.signer()?;
            let mut set = LockedFragments::open(&args.existing.state)?;
            let encoded = state::read_private(&args.grant, MAX_GRANT_BYTES as u64)?;
            let grant = SignedStorageGrant::decode(&encoded)?
                .verify(&args.provider_key, crate::storage::now()?)?;
            placement::replace(
                &mut set,
                socket,
                &signer,
                usize::from(args.fragment_index),
                args.from_provider_key,
                &grant,
                args.lifetime_seconds,
            )
            .await?
        }
    };
    let complete = report["operation_complete"].as_bool().unwrap_or(true);
    crate::storage::print(&report)?;
    ensure!(
        complete,
        "fragment operation incomplete; original identities and charged copies retained"
    );
    Ok(())
}

fn parse_copy_target(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(copies) if copies == ARCHIVE_COPY_TARGET => Ok(copies),
        _ => Err(format!(
            "storage redundancy is core-owned: {ARCHIVE_COPY_TARGET} copies"
        )),
    }
}

fn create(args: &Create) -> Result<serde_json::Value> {
    ensure!(
        args.already_encrypted,
        "already-encrypted acknowledgement is required"
    );
    ensure!(
        (3..=8).contains(&args.provider_key.len()) && args.provider_key.len() == args.grant.len(),
        "specify 3..8 distinct provider keys and corresponding grants"
    );
    let signer = args.existing.unlock.signer()?;
    let expected = crate::storage::parse_hash(&args.sha256)?;
    let (mut input, length) = transfer::checked_input(&args.input, expected)?;
    let mut grants = Vec::with_capacity(args.grant.len());
    for (provider, path) in args.provider_key.iter().zip(&args.grant) {
        let encoded = state::read_private(path, MAX_GRANT_BYTES as u64)?;
        grants
            .push(SignedStorageGrant::decode(&encoded)?.verify(provider, crate::storage::now()?)?);
    }
    LockedFragments::create(
        &args.existing.state,
        &signer,
        &mut input,
        retained::Plan {
            ciphertext_bytes: length,
            sha256: expected,
            fragment_bytes: args.fragment_bytes,
            copies: args.copies,
        },
        &grants,
        args.lifetime_seconds,
    )?
    .report("create")
}

#[cfg(test)]
#[path = "fragments_tests.rs"]
mod tests;
