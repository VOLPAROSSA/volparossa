//! Explicit local custody and protected peer transfers; not a reciprocal-credit service.

mod peer;

use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::json;
use volparossa_content::private_storage::{
    LeaseId, MAX_ARCHIVE_BYTES, MAX_CAPACITY_BYTES, MAX_LEASE_SECONDS, PrivateStorageStore,
    StorageLimits, StoredArchive,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Operate an explicitly owned local provider store; never contacts peers.
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
    /// Private provider grants and resumable transfers through the running agent only.
    Peer {
        #[command(subcommand)]
        command: Box<peer::Command>,
    },
    /// Retain explicit independently pinned provider copies, with non-consuming restore failover.
    Replicas {
        #[command(subcommand)]
        command: Box<peer::replicas::Command>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum LocalCommand {
    /// Create a new private, non-evicting store; refuses an existing directory.
    Init {
        #[arg(long)]
        store: PathBuf,
        /// Maximum reserved plus committed ciphertext payload bytes.
        #[arg(long)]
        capacity_bytes: u64,
        /// Space that must remain free, separate from the payload quota.
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        min_free_bytes: u64,
    },
    /// Show local reserved/committed bytes, not network contribution credit.
    Status {
        #[arg(long)]
        store: PathBuf,
    },
    /// Set new-reservation admission only; occupied bytes remain protected and pending drain.
    Target {
        #[arg(long)]
        store: PathBuf,
        /// Zero closes new admission. Cannot exceed the store's original payload capacity.
        #[arg(long, value_parser = clap::value_parser!(u64).range(0..=MAX_CAPACITY_BYTES))]
        target_bytes: u64,
    },
    /// Stream an already-encrypted archive into one local lease, verifying its full hash.
    Deposit {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Expected SHA-256 obtained from the owner's original ciphertext archive.
        #[arg(long)]
        sha256: String,
        #[arg(long, default_value_t = 7 * 24 * 60 * 60)]
        lifetime_seconds: u64,
        /// Confirm the input is already encrypted; this command does NOT encrypt it.
        #[arg(long, required = true)]
        already_encrypted: bool,
    },
    /// Reconstruct verified ciphertext to a new file; retains the stored backup.
    Restore {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Renew local retention without changing ciphertext or its hash.
    Renew {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long)]
        lifetime_seconds: u64,
    },
    /// Permanently remove this store's copy/reservation; does not delete the source file.
    Delete {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        lease: String,
    },
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    let command = match command {
        Command::Local { command } => command,
        Command::Peer { command } => return peer::run(*command, socket).await,
        Command::Replicas { command } => return peer::replicas::run(*command, socket).await,
    };
    match command {
        LocalCommand::Init {
            store,
            capacity_bytes,
            min_free_bytes,
        } => {
            require_absolute(&store)?;
            if capacity_bytes == 0 || capacity_bytes > MAX_CAPACITY_BYTES {
                bail!("invalid private storage capacity");
            }
            let store = PrivateStorageStore::create(
                &store,
                StorageLimits {
                    capacity_bytes,
                    min_free_bytes,
                },
            )?;
            status(&store)
        }
        LocalCommand::Status { store } => status(&open(&store)?),
        LocalCommand::Target {
            store,
            target_bytes,
        } => {
            let mut store = open(&store)?;
            store.set_admission_target(target_bytes)?;
            status(&store)
        }
        LocalCommand::Deposit {
            store,
            input,
            sha256,
            lifetime_seconds,
            already_encrypted,
        } => {
            if !already_encrypted {
                bail!("input must already be encrypted; this command does not encrypt it");
            }
            deposit(&store, &input, &sha256, lifetime_seconds)
        }
        LocalCommand::Restore {
            store,
            lease,
            output,
        } => restore(&store, parse_lease(&lease)?, &output),
        LocalCommand::Renew {
            store,
            lease,
            lifetime_seconds,
        } => {
            let now = now()?;
            let result =
                open(&store)?.renew(parse_lease(&lease)?, expiry(now, lifetime_seconds)?, now)?;
            report(&result)
        }
        LocalCommand::Delete { store, lease } => {
            let removed = open(&store)?.delete(parse_lease(&lease)?)?;
            print(&json!({"schema": 1, "scope": "local-provider-only", "removed": removed}))
        }
    }
}

fn open(path: &Path) -> Result<PrivateStorageStore> {
    require_absolute(path)?;
    Ok(PrivateStorageStore::open_existing(path)?)
}

fn status(store: &PrivateStorageStore) -> Result<()> {
    let usage = store.admission_status()?;
    print(&json!({
        "schema": 1,
        "scope": "local-provider-only",
        "reserved_bytes": usage.reserved_bytes,
        "committed_bytes": usage.committed_bytes,
        "leases": usage.leases,
        "capacity_bytes": usage.capacity_bytes,
        "target_bytes": usage.target_bytes,
        "retained_payload_bytes": usage.retained_payload_bytes,
        "pending_drain_bytes": usage.pending_drain_bytes,
        "pending_drain": usage.pending_drain_bytes > 0,
        "available_for_new_reservations_bytes": usage.available_for_new_reservations_bytes,
        "accounting_unit": "ciphertext-payload-bytes-per-copy",
        "metadata_overhead_measured": false,
        "automatic_migration": false,
        "automatic_contribution_resize": false,
        "remote_replication": false,
        "network_contribution_verified": false,
    }))
}

fn deposit(path: &Path, input: &Path, expected: &str, lifetime: u64) -> Result<()> {
    require_absolute(input)?;
    let hash = parse_hash(expected)?;
    let now = now()?;
    let expires = expiry(now, lifetime)?;
    let mut reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(input)
        .context("cannot open supplied ciphertext file")?;
    let metadata = reader
        .metadata()
        .context("cannot inspect ciphertext file")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ARCHIVE_BYTES {
        bail!("ciphertext must be a nonempty regular file within the archive limit");
    }
    let mut store = open(path)?;
    let lease = store.reserve(metadata.len(), hash, expires, now)?;
    // A failed or interrupted deposit keeps its reservation charged. Identify it for
    // the explicit owner without claiming a completed archive or deleting unrelated data.
    let result = store
        .write_reserved(lease, &mut reader, now)
        .with_context(|| {
            format!("deposit incomplete; local reservation {lease} remains charged")
        })?;
    report(&result)
}

fn restore(path: &Path, lease: LeaseId, output: &Path) -> Result<()> {
    require_absolute(output)?;
    if output.symlink_metadata().is_ok() {
        bail!("restore refuses to overwrite any existing output");
    }
    let parent = output.parent().context("restore output needs a parent")?;
    let store = open(path)?;
    // Unverified partial bytes are never published at the requested output path.
    let mut temporary = tempfile::Builder::new()
        .prefix(".volparossa-ciphertext-")
        .tempfile_in(parent)
        .context("cannot stage private restore output")?;
    let result = store.restore(lease, temporary.as_file_mut(), now()?)?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync complete ciphertext restore")?;
    temporary
        .persist_noclobber(output)
        .map_err(|_| anyhow::anyhow!("cannot publish verified ciphertext without overwriting"))?;
    OpenOptions::new()
        .read(true)
        .open(parent)
        .and_then(|directory| directory.sync_all())
        .context("restore output created, but directory sync failed")?;
    report(&result)
}

fn report(archive: &StoredArchive) -> Result<()> {
    print(&json!({
        "schema": 1,
        "scope": "local-provider-only",
        "lease_id": archive.lease_id.to_string(),
        "ciphertext_bytes": archive.ciphertext_bytes,
        "sha256": hex::encode(archive.sha256),
        "expires_at_unix": archive.expires_at_unix,
        "committed": archive.committed,
        "remote_replication": false,
    }))
}

fn print(value: &serde_json::Value) -> Result<()> {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn parse_hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("expected SHA-256 must be exactly 64 hexadecimal characters");
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).context("invalid SHA-256 encoding")?;
    Ok(bytes)
}

fn parse_lease(value: &str) -> Result<LeaseId> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid local lease identifier"))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn expiry(now: u64, lifetime: u64) -> Result<u64> {
    if lifetime == 0 || lifetime > MAX_LEASE_SECONDS {
        bail!("invalid private storage lease lifetime");
    }
    now.checked_add(lifetime)
        .context("private storage expiry overflow")
}

fn require_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("storage paths must be explicit absolute paths");
    }
    Ok(())
}
