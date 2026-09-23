//! Owner-approved immutable adapters for serving; not a network trust decision.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use volparossa_local_control::compute::FileIdentity;

use super::{is_hex, private_directory, read_file};

const RECORD_LIMIT: u64 = 64 * 1024;
const FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u32,
    producer_id: String,
    runtime: PathBuf,
    runtime_device: u64,
    runtime_inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    owner: Owner,
    expires_unix_seconds: u64,
    adapter_files: BTreeMap<String, FileIdentity>,
    provenance: Value,
}

/// Local owner withdrawal, not evidence of misconduct by a model publisher.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Withdrawal {
    version: u32,
    owner: Owner,
    selection_id: String,
}

#[derive(Clone, Debug)]
pub(super) struct Selection {
    pub(super) id: String,
    pub(super) expires_unix_seconds: u64,
    pub(super) adapter_files: BTreeMap<String, FileIdentity>,
    record: Record,
}

impl Selection {
    fn from_record(record: Record) -> Result<Self> {
        ensure!(
            record.owner.version == 1
                && is_hex(&record.owner.producer_id, 64)
                && record.owner.runtime.is_absolute()
                && record.expires_unix_seconds > 0
                && record.provenance.is_object()
                && record.adapter_files.len() == FILES.len(),
            "serving_snapshot_record"
        );
        for (name, maximum) in FILES {
            let identity = record
                .adapter_files
                .get(name)
                .context("serving_snapshot_file_missing")?;
            ensure!(
                (1..=maximum).contains(&identity.bytes) && is_hex(&identity.sha256, 64),
                "serving_snapshot_file_identity"
            );
        }
        ensure!(
            record.provenance["approved"] == true
                && matches!(
                    record.provenance["kind"].as_str(),
                    Some("approved_local_successor" | "approved_peer_update")
                )
                && record.provenance["adapter_files"]
                    == serde_json::to_value(&record.adapter_files)?,
            "serving_snapshot_approval_binding"
        );
        let bytes = encoded(&record)?;
        Ok(Self {
            id: digest(&bytes),
            expires_unix_seconds: record.expires_unix_seconds,
            adapter_files: record.adapter_files.clone(),
            record,
        })
    }
}

pub(super) struct Snapshot {
    pub(super) directory: TempDir,
    pub(super) selection: Selection,
}

impl Snapshot {
    pub(super) fn adapter_path(&self) -> &Path {
        self.directory.path()
    }
}

/// The loop keeps this publisher lock while running; another loop cannot overwrite its authority.
pub(super) struct Publisher {
    root: PathBuf,
    owner: Owner,
    _lock: Flock<File>,
}

impl Publisher {
    pub(super) fn open(root: &Path, runtime: &Path, producer_id: &str) -> Result<Self> {
        private_directory(root)?;
        let owner = owner(runtime, producer_id)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".publisher.lock"))?;
        let info = lock.metadata()?;
        ensure!(
            info.is_file()
                && info.uid() == nix::unistd::geteuid().as_raw()
                && info.nlink() == 1
                && info.mode() & 0o777 == 0o600,
            "serving_snapshot_lock"
        );
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|_| anyhow::anyhow!("serving_snapshot_publisher_busy"))?;
        let owner_path = root.join("owner.json");
        if present(&owner_path)? {
            let saved: Owner = serde_json::from_slice(&read_file(&owner_path, RECORD_LIMIT)?)?;
            ensure!(saved == owner, "serving_snapshot_owner_changed");
        } else {
            ensure!(
                fs::read_dir(root)?.count() == 1,
                "serving_snapshot_new_owner_directory"
            );
            write_new(&owner_path, &encoded(&owner)?)?;
        }
        let publisher = Self {
            root: root.to_owned(),
            owner,
            _lock: lock,
        };
        publisher.clean_staging()?;
        Ok(publisher)
    }

    pub(super) fn publish(
        &self,
        adapter: &Path,
        expires: u64,
        provenance: &Value,
        at: u64,
    ) -> Result<Selection> {
        ensure!(expires > at, "serving_snapshot_expired");
        let contents = adapter_bytes(adapter)?;
        let record = Record {
            owner: self.owner.clone(),
            expires_unix_seconds: expires,
            adapter_files: contents
                .iter()
                .map(|(name, bytes)| (name.clone(), identity(bytes)))
                .collect(),
            provenance: provenance.clone(),
        };
        let selected = Selection::from_record(record)?;
        ensure!(
            withdrawal(&self.root, &self.owner)?
                .is_none_or(|record| record.selection_id != selected.id),
            "serving_snapshot_withdrawn"
        );
        let current = current(&self.root)?;
        if let Some(previous) = &current {
            ensure!(
                previous.record.owner == self.owner,
                "serving_snapshot_owner_changed"
            );
            if previous.id == selected.id {
                verify_files(&snapshot_path(&self.root, previous), previous)?;
                return Ok(selected);
            }
        }
        self.clean_staging()?;
        // Keep current while preparing its successor, but reclaim only our previous
        // immutable copy. At most two bounded copies (current + staged/previous) exist.
        self.prune_except(current.as_ref().map(|value| value.id.as_str()))?;
        let staging = self.root.join("staging");
        fs::DirBuilder::new().mode(0o700).create(&staging)?;
        for (name, bytes) in &contents {
            write_new(&staging.join(name), bytes)?;
        }
        write_new(&staging.join("selection.json"), &encoded(&selected.record)?)?;
        File::open(&staging)?.sync_all()?;
        fs::rename(&staging, snapshot_path(&self.root, &selected))?;
        File::open(&self.root)?.sync_all()?;
        write_new(
            &self.root.join("current.pending"),
            &encoded(&selected.record)?,
        )?;
        fs::rename(
            self.root.join("current.pending"),
            self.root.join("current.json"),
        )?;
        File::open(&self.root)?.sync_all()?;
        Ok(selected)
    }

    /// Preserve the original pointer/expiry but stop admission, including from
    /// brokers holding independent copies. Repeating the same withdrawal is inert.
    pub(super) fn withdraw_current(&self) -> Result<()> {
        let Some(selected) = current(&self.root)? else {
            return Ok(());
        };
        ensure!(
            selected.record.owner == self.owner,
            "serving_snapshot_owner_changed"
        );
        let record = Withdrawal {
            version: 1,
            owner: self.owner.clone(),
            selection_id: selected.id,
        };
        if withdrawal(&self.root, &self.owner)?.as_ref() == Some(&record) {
            return Ok(());
        }
        self.clean_staging()?;
        write_new(&self.root.join("withdrawal.pending"), &encoded(&record)?)?;
        fs::rename(
            self.root.join("withdrawal.pending"),
            self.root.join("withdrawal.json"),
        )?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn clean_staging(&self) -> Result<()> {
        let staging = self.root.join("staging");
        if present(&staging)? {
            remove_copy(&staging)?;
        }
        for name in ["current.pending", "withdrawal.pending"] {
            let pending = self.root.join(name);
            if present(&pending)? {
                read_file(&pending, RECORD_LIMIT)?;
                fs::remove_file(pending)?;
            }
        }
        Ok(())
    }

    fn prune_except(&self, keep: Option<&str>) -> Result<()> {
        let entries = fs::read_dir(&self.root)?.collect::<std::io::Result<Vec<_>>>()?;
        ensure!(entries.len() <= 7, "serving_snapshot_storage_bound");
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().context("serving_snapshot_entry")?;
            if matches!(
                name,
                "owner.json" | ".publisher.lock" | "current.json" | "withdrawal.json"
            ) {
                continue;
            }
            let id = name
                .strip_prefix("snapshot-")
                .filter(|id| is_hex(id, 64))
                .context("serving_snapshot_unknown_entry")?;
            if Some(id) != keep {
                remove_copy(&entry.path())?;
            }
        }
        Ok(())
    }
}

/// Once the owner withdraws a selection, stale owned copies cannot keep taking
/// new work. A checked replacement (including an approved predecessor) must be
/// the actual current selection. One fixed-size record suffices: overwriting it
/// cannot reauthorize an older broker copy, and no original expiry is extended.
pub(super) fn admission_allowed(root: &Path, runtime: &Path, selected: &Selection) -> Result<bool> {
    private_directory(root)?;
    ensure!(
        selected.record.owner == owner(runtime, &selected.record.owner.producer_id)?,
        "serving_snapshot_runtime_changed"
    );
    let Some(withdrawn) = withdrawal(root, &selected.record.owner)? else {
        return Ok(true);
    };
    Ok(withdrawn.selection_id != selected.id
        && peek(root, runtime)?.is_some_and(|current| current.id == selected.id))
}

fn withdrawal(root: &Path, expected: &Owner) -> Result<Option<Withdrawal>> {
    let path = root.join("withdrawal.json");
    if !present(&path)? {
        return Ok(None);
    }
    let record: Withdrawal = serde_json::from_slice(&read_file(&path, RECORD_LIMIT)?)?;
    ensure!(
        record.version == 1 && record.owner == *expected && is_hex(&record.selection_id, 64),
        "serving_snapshot_withdrawal_binding"
    );
    Ok(Some(record))
}

/// Metadata only. Expired selections remain distinguishable from a never-selected
/// directory; the broker must withhold new admission rather than fall back to base.
pub(super) fn peek(root: &Path, runtime: &Path) -> Result<Option<Selection>> {
    private_directory(root)?;
    let Some(selection) = current(root)? else {
        let mut count = 0;
        for entry in fs::read_dir(root)? {
            count += 1;
            let name = entry?.file_name();
            ensure!(
                count <= 2 && (name == "owner.json" || name == ".publisher.lock"),
                "serving_snapshot_missing_current"
            );
        }
        let path = root.join("owner.json");
        if present(&path)? {
            let saved: Owner = serde_json::from_slice(&read_file(&path, RECORD_LIMIT)?)?;
            ensure!(
                saved == owner(runtime, &saved.producer_id)?,
                "serving_snapshot_owner_changed"
            );
        }
        return Ok(None);
    };
    ensure!(
        selection.record.owner == owner(runtime, &selection.record.owner.producer_id)?,
        "serving_snapshot_runtime_changed"
    );
    let saved: Owner = serde_json::from_slice(&read_file(&root.join("owner.json"), RECORD_LIMIT)?)?;
    ensure!(
        saved == selection.record.owner,
        "serving_snapshot_owner_changed"
    );
    Ok(Some(selection))
}

/// Independent owned bytes survive both training-loop pruning and subsequent selection changes.
pub(super) fn copy_selection(
    root: &Path,
    selection: &Selection,
    workroot: &Path,
) -> Result<Snapshot> {
    private_directory(root)?;
    private_directory(workroot)?;
    let source = snapshot_path(root, selection);
    let saved: Record =
        serde_json::from_slice(&read_file(&source.join("selection.json"), RECORD_LIMIT)?)?;
    ensure!(
        saved == selection.record,
        "serving_snapshot_selection_changed"
    );
    let bytes = verify_files(&source, selection)?;
    let directory = tempfile::Builder::new()
        .prefix("serving-adapter-")
        .tempdir_in(workroot)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in bytes {
        write_new(&directory.path().join(name), &bytes)?;
    }
    File::open(directory.path())?.sync_all()?;
    Ok(Snapshot {
        directory,
        selection: selection.clone(),
    })
}

fn owner(runtime: &Path, producer_id: &str) -> Result<Owner> {
    private_directory(runtime)?;
    ensure!(
        runtime.is_absolute() && is_hex(producer_id, 64),
        "serving_snapshot_owner"
    );
    let info = fs::symlink_metadata(runtime)?;
    Ok(Owner {
        version: 1,
        producer_id: producer_id.into(),
        runtime: fs::canonicalize(runtime)?,
        runtime_device: info.dev(),
        runtime_inode: info.ino(),
    })
}

fn current(root: &Path) -> Result<Option<Selection>> {
    let path = root.join("current.json");
    if !present(&path)? {
        return Ok(None);
    }
    Selection::from_record(serde_json::from_slice(&read_file(&path, RECORD_LIMIT)?)?).map(Some)
}

fn snapshot_path(root: &Path, selection: &Selection) -> PathBuf {
    root.join(format!("snapshot-{}", selection.id))
}

fn adapter_bytes(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    private_directory(root)?;
    FILES
        .into_iter()
        .map(|(name, limit)| {
            let bytes = read_file(&root.join(name), limit)?;
            ensure!(!bytes.is_empty(), "serving_snapshot_empty_adapter");
            Ok((name.to_owned(), bytes))
        })
        .collect()
}

fn verify_files(root: &Path, selected: &Selection) -> Result<BTreeMap<String, Vec<u8>>> {
    let contents = adapter_bytes(root)?;
    for (name, bytes) in &contents {
        ensure!(
            selected.adapter_files.get(name) == Some(&identity(bytes)),
            "serving_snapshot_adapter_changed"
        );
    }
    Ok(contents)
}

fn remove_copy(root: &Path) -> Result<()> {
    private_directory(root)?;
    let entries = fs::read_dir(root)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= 4, "serving_snapshot_cleanup_bound");
    for entry in &entries {
        let name = entry.file_name();
        let name = name.to_str().context("serving_snapshot_cleanup_entry")?;
        let limit = FILES
            .iter()
            .find(|(expected, _)| *expected == name)
            .map(|(_, size)| *size)
            .or_else(|| (name == "selection.json").then_some(RECORD_LIMIT))
            .context("serving_snapshot_cleanup_unknown")?;
        read_file(&entry.path(), limit)?;
    }
    for entry in entries {
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(root)?;
    Ok(())
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= RECORD_LIMIT,
        "serving_snapshot_metadata_bound"
    );
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
