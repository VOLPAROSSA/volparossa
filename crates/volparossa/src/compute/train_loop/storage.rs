//! Bounded private coordinator checkpoints. Retention policy belongs to the caller.

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::private_directory;

// Up to sixteen bounded signed catalog snapshots and 128 stable source slots.
const JSON_LIMIT: u64 = 4 * 1024 * 1024;
const ENROLLMENT_LIMIT: u64 = 64 * 1024;
const TREE_ENTRIES: usize = 32;
const TREE_BYTES: u64 = 16 * 1024 * 1024;
const CONTENT_FILES: [(&str, u64); 12] = [
    ("selection.json", 256 * 1024),
    ("dataset.json", 1024 * 1024),
    ("dataset.manifest", 64 * 1024),
    ("source-provenance.json", 64 * 1024),
    ("training-report.json", 32 * 1024),
    ("result.json", 64 * 1024),
    ("evaluation.json", 64 * 1024),
    ("adapter.bundle", 4 * 1024 * 1024),
    ("training/report.json", 16 * 1024),
    ("training/adapter/README.md", 16 * 1024),
    ("training/adapter/adapter_config.json", 16 * 1024),
    (
        "training/adapter/adapter_model.safetensors",
        2 * 1024 * 1024,
    ),
];
const PUBLICATION_FILES: [(&str, u64); 3] = [
    ("publication.pb", 64 * 1024),
    ("publication.json", 64 * 1024),
    ("contribution.json", 64 * 1024),
];
const VALIDATION_FILES: [(&str, u64); 8] = [
    ("validation/dataset.json", 1024 * 1024),
    ("validation/dataset.manifest", 64 * 1024),
    ("validation/provenance.json", 64 * 1024),
    ("validation/baseline/report.json", 16 * 1024),
    ("validation/candidate/report.json", 16 * 1024),
    ("baseline-report.json", 64 * 1024),
    ("candidate-report.json", 64 * 1024),
    ("validation.json", 64 * 1024),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileSnapshot {
    pub(super) sha256: String,
    pub(super) bytes: u64,
}

pub(super) type Snapshot = BTreeMap<String, FileSnapshot>;

pub(super) struct Store {
    root: PathBuf,
    directory: File,
    lock: Flock<File>,
}

impl Store {
    pub(super) fn open(root: &Path, enrollment: &Value, resume: bool) -> Result<Self> {
        ensure!(root.is_absolute(), "train_loop_store_absolute");
        let enrollment_bytes = json_bytes(enrollment, ENROLLMENT_LIMIT)?;
        if !resume {
            let parent = root.parent().context("train_loop_store_parent")?;
            private_directory(parent)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root)
                .context("train_loop_new_store_required")?;
            File::open(parent)?.sync_all()?;
        }
        private_directory(root)?;
        let directory = File::open(root)?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!resume)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".coordinator.lock"))?;
        private_file(&lock_file.metadata()?, 0)?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| anyhow::anyhow!("train_loop_store_busy"))?;
        let store = Self {
            root: root.to_path_buf(),
            directory,
            lock,
        };
        if resume {
            let stored: Value =
                serde_json::from_slice(&store.read_root("enrollment.json", ENROLLMENT_LIMIT)?)?;
            ensure!(&stored == enrollment, "train_loop_enrollment_mismatch");
        } else {
            store.atomic_write(&store.root, "enrollment.json", &enrollment_bytes, false)?;
        }
        store.check_owner()?;
        Ok(store)
    }

    pub(super) fn load_state(&self) -> Result<Option<Value>> {
        self.check_owner()?;
        match fs::symlink_metadata(self.root.join("state.json")) {
            Ok(_) => Ok(Some(serde_json::from_slice(
                &self.read_root("state.json", JSON_LIMIT)?,
            )?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn save_state(&self, state: &Value) -> Result<()> {
        let bytes = json_bytes(state, JSON_LIMIT)?;
        self.check_owner()?;
        self.atomic_write(&self.root, "state.json", &bytes, true)
    }

    /// Return only the deterministic cycle path. The cycle executor itself must
    /// create a new directory; an existing private path is available for recovery.
    pub(super) fn cycle_path(&self, sequence: u64) -> Result<PathBuf> {
        self.check_owner()?;
        let path = self.root.join(format!("cycle-{sequence:016x}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => private_directory(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }

    pub(super) fn read_cycle_json(&self, sequence: u64, name: &str) -> Result<Value> {
        ensure!(
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "json"),
            "train_loop_cycle_json_name"
        );
        let limit = fixed_limit(name).context("train_loop_cycle_json_name")?;
        let cycle = self.cycle_path(sequence)?;
        private_directory(&cycle)?;
        let file = cycle.join(name);
        private_directory(file.parent().context("train_loop_cycle_parent")?)?;
        Ok(serde_json::from_slice(&read_private(&file, limit)?)?)
    }

    /// Decisions are written once before the completed-content snapshot; later
    /// publication receipts remain separate. Existing records are never replaced.
    pub(super) fn write_cycle_json(&self, sequence: u64, name: &str, value: &Value) -> Result<()> {
        ensure!(
            matches!(
                name,
                "evaluation.json"
                    | "publication.json"
                    | "contribution.json"
                    | "validation.json"
                    | "baseline-report.json"
                    | "candidate-report.json"
            ),
            "train_loop_receipt_name"
        );
        let bytes = json_bytes(value, 64 * 1024)?;
        let cycle = self.cycle_path(sequence)?;
        private_directory(&cycle)?;
        self.atomic_write(&cycle, name, &bytes, false)
    }

    pub(super) fn snapshot_cycle(&self, sequence: u64) -> Result<Snapshot> {
        self.snapshot_files(sequence, true)
    }

    pub(super) fn snapshot_training(&self, sequence: u64) -> Result<Snapshot> {
        self.snapshot_files(sequence, false)
    }

    pub(super) fn validate_training(&self, sequence: u64, expected: &Snapshot) -> Result<()> {
        ensure!(
            &self.snapshot_training(sequence)? == expected,
            "train_loop_training_changed"
        );
        Ok(())
    }

    fn snapshot_files(&self, sequence: u64, complete: bool) -> Result<Snapshot> {
        let cycle = self.cycle_path(sequence)?;
        let entries = checked_tree(&cycle)?;
        ensure!(
            entries.iter().all(|entry| !temporary_name(&entry.relative)),
            "train_loop_cycle_incomplete_temporary"
        );
        let mut snapshot = Snapshot::new();
        let validation = complete && fs::symlink_metadata(cycle.join("validation.json")).is_ok();
        for (name, limit) in CONTENT_FILES
            .into_iter()
            .filter(|(name, _)| complete || *name != "evaluation.json")
            .chain(VALIDATION_FILES.into_iter().filter(|_| validation))
        {
            let bytes = read_private(&cycle.join(name), limit)?;
            ensure!(!bytes.is_empty(), "train_loop_cycle_empty_file");
            snapshot.insert(
                name.to_owned(),
                FileSnapshot {
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    bytes: bytes.len() as u64,
                },
            );
        }
        Ok(snapshot)
    }

    pub(super) fn validate_snapshot(&self, sequence: u64, snapshot: &Snapshot) -> Result<()> {
        ensure!(
            &self.snapshot_cycle(sequence)? == snapshot,
            "train_loop_cycle_snapshot_changed"
        );
        Ok(())
    }

    /// Remove one exact derived cycle only after validating its entire bounded
    /// private tree. The caller must exclude active/latest/unpublished cycles.
    pub(super) fn prune_sequence(&self, sequence: u64) -> Result<bool> {
        let cycle = self.cycle_path(sequence)?;
        match fs::symlink_metadata(&cycle) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let root_identity = fs::symlink_metadata(&cycle)?;
        let mut entries = checked_tree(&cycle)?;
        // Validate everything before the first unlink, then delete deepest first.
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.relative.components().count()));
        for entry in entries {
            self.check_owner()?;
            private_directory(&cycle)?;
            same_inode(&fs::symlink_metadata(&cycle)?, &root_identity)?;
            let path = cycle.join(&entry.relative);
            private_directory(path.parent().context("train_loop_prune_parent")?)?;
            let current = fs::symlink_metadata(&path)?;
            same_inode(&current, &entry.metadata)?;
            if current.is_dir() {
                private_directory(&path)?;
                fs::remove_dir(&path)?;
            } else {
                private_file(&current, TREE_BYTES)?;
                fs::remove_file(&path)?;
            }
        }
        same_inode(&fs::symlink_metadata(&cycle)?, &root_identity)?;
        fs::remove_dir(cycle)?;
        self.directory.sync_all()?;
        Ok(true)
    }

    fn check_owner(&self) -> Result<()> {
        private_directory(&self.root)?;
        same_inode(
            &fs::symlink_metadata(&self.root)?,
            &self.directory.metadata()?,
        )?;
        let path = fs::symlink_metadata(self.root.join(".coordinator.lock"))?;
        private_file(&path, 0)?;
        same_inode(&path, &self.lock.metadata()?)
    }

    fn read_root(&self, name: &str, limit: u64) -> Result<Vec<u8>> {
        self.check_owner()?;
        read_private(&self.root.join(name), limit)
    }

    fn atomic_write(
        &self,
        directory: &Path,
        name: &str,
        bytes: &[u8],
        replace: bool,
    ) -> Result<()> {
        self.check_owner()?;
        private_directory(directory)?;
        let destination = directory.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                ensure!(replace, "train_loop_file_already_exists");
                private_file(&metadata, JSON_LIMIT)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut pending = tempfile::NamedTempFile::new_in(directory)?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        pending.write_all(bytes)?;
        pending.as_file().sync_all()?;
        if replace {
            pending.persist(destination).map_err(|error| error.error)?;
        } else {
            pending
                .persist_noclobber(destination)
                .map_err(|error| error.error)?;
        }
        File::open(directory)?.sync_all()?;
        Ok(())
    }
}

fn json_bytes(value: &Value, limit: u64) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() as u64 <= limit, "train_loop_json_limit");
    Ok(bytes)
}

fn same_inode(current: &Metadata, expected: &Metadata) -> Result<()> {
    ensure!(
        current.dev() == expected.dev()
            && current.ino() == expected.ino()
            && current.file_type() == expected.file_type(),
        "train_loop_store_identity_changed"
    );
    Ok(())
}

fn private_file(info: &Metadata, maximum: u64) -> Result<()> {
    ensure!(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.nlink() == 1
            && info.mode().trailing_zeros() >= 6
            && info.len() <= maximum,
        "train_loop_private_file_invalid"
    );
    Ok(())
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    private_directory(path.parent().context("train_loop_file_parent")?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    private_file(&file.metadata()?, limit)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "train_loop_file_limit");
    Ok(bytes)
}

fn fixed_limit(name: &str) -> Option<u64> {
    CONTENT_FILES
        .into_iter()
        .chain(PUBLICATION_FILES)
        .chain(VALIDATION_FILES)
        .find_map(|(known, limit)| (known == name).then_some(limit))
}

fn temporary_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(".tmp")
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        })
}

struct Entry {
    relative: PathBuf,
    metadata: Metadata,
}

fn checked_tree(cycle: &Path) -> Result<Vec<Entry>> {
    private_directory(cycle)?;
    let mut pending = vec![PathBuf::new()];
    let mut entries = Vec::new();
    let mut total = 0_u64;
    while let Some(relative) = pending.pop() {
        let directory = cycle.join(&relative);
        private_directory(&directory)?;
        for item in fs::read_dir(directory)? {
            ensure!(entries.len() < TREE_ENTRIES, "train_loop_cycle_entry_limit");
            let item = item?;
            let relative = relative.join(item.file_name());
            let metadata = fs::symlink_metadata(item.path())?;
            let name = relative.to_str().context("train_loop_cycle_name")?;
            if metadata.is_dir() {
                ensure!(
                    matches!(
                        name,
                        "training"
                            | "training/adapter"
                            | "validation"
                            | "validation/baseline"
                            | "validation/candidate"
                    ),
                    "train_loop_cycle_directory"
                );
                private_directory(&item.path())?;
                pending.push(relative.clone());
            } else {
                let maximum = if temporary_name(&relative) {
                    4 * 1024 * 1024
                } else {
                    fixed_limit(name).context("train_loop_cycle_unknown_file")?
                };
                private_file(&metadata, maximum)?;
                total = total
                    .checked_add(metadata.len())
                    .context("train_loop_cycle_byte_limit")?;
                ensure!(total <= TREE_BYTES, "train_loop_cycle_byte_limit");
            }
            entries.push(Entry { relative, metadata });
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn owner() -> (tempfile::TempDir, PathBuf, Value) {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().join("coordinator");
        (
            temporary,
            root,
            serde_json::json!({"version":1,"publisher":"explicit-public-owner"}),
        )
    }

    fn cycle(store: &Store, sequence: u64) -> PathBuf {
        let root = store.cycle_path(sequence).unwrap();
        for path in [
            &root,
            &root.join("training"),
            &root.join("training/adapter"),
        ] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        for (name, _) in CONTENT_FILES {
            let file = root.join(name);
            fs::write(&file, b"{}\n").unwrap();
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        root
    }

    #[test]
    fn exclusive_owner_exact_enrollment_and_durable_state_survive_reopen() {
        let (_temporary, root, enrollment) = owner();
        let store = Store::open(&root, &enrollment, false).unwrap();
        assert!(Store::open(&root, &enrollment, true).is_err());
        assert!(store.load_state().unwrap().is_none());
        store
            .save_state(&serde_json::json!({"sequence":1}))
            .unwrap();
        store
            .save_state(&serde_json::json!({"sequence":2}))
            .unwrap();
        drop(store);
        assert!(Store::open(&root, &serde_json::json!({"version":2}), true).is_err());
        let store = Store::open(&root, &enrollment, true).unwrap();
        assert_eq!(
            store.load_state().unwrap(),
            Some(serde_json::json!({"sequence":2}))
        );
        assert!(
            store
                .save_state(&Value::String(
                    "x".repeat(usize::try_from(JSON_LIMIT).unwrap())
                ))
                .is_err()
        );
        assert_eq!(
            store.load_state().unwrap(),
            Some(serde_json::json!({"sequence":2}))
        );
    }

    #[test]
    fn snapshot_binds_actual_complete_bytes_and_excludes_later_publication_receipts() {
        let (_temporary, root, enrollment) = owner();
        let store = Store::open(&root, &enrollment, false).unwrap();
        let cycle = cycle(&store, 1);
        let snapshot = store.snapshot_cycle(1).unwrap();
        assert_eq!(snapshot.len(), CONTENT_FILES.len());
        store
            .write_cycle_json(
                1,
                "publication.json",
                &serde_json::json!({"published":true}),
            )
            .unwrap();
        assert!(
            store
                .write_cycle_json(1, "publication.json", &Value::Null)
                .is_err()
        );
        assert_eq!(
            store.read_cycle_json(1, "publication.json").unwrap()["published"],
            true
        );
        store.validate_snapshot(1, &snapshot).unwrap();
        fs::write(cycle.join("dataset.json"), b"{\"changed\":true}").unwrap();
        assert!(store.validate_snapshot(1, &snapshot).is_err());
        fs::remove_file(cycle.join("training/report.json")).unwrap();
        assert!(store.snapshot_cycle(1).is_err());
        assert!(store.read_cycle_json(1, "../enrollment.json").is_err());
        assert!(
            store
                .write_cycle_json(1, "../../state.json", &Value::Null)
                .is_err()
        );
    }

    #[test]
    fn pruning_rejects_linked_or_foreign_tree_before_removal_and_keeps_other_cycles() {
        let (_temporary, root, enrollment) = owner();
        let store = Store::open(&root, &enrollment, false).unwrap();
        let first = cycle(&store, 1);
        let second = cycle(&store, 2);
        let snapshot = store.snapshot_cycle(2).unwrap();
        fs::hard_link(second.join("dataset.json"), first.join(".tmpLinked")).unwrap();
        assert!(store.prune_sequence(1).is_err());
        assert!(first.join("selection.json").exists());
        fs::remove_file(first.join(".tmpLinked")).unwrap();
        symlink(&second, first.join(".tmpSymlink")).unwrap();
        assert!(store.prune_sequence(1).is_err());
        assert!(first.join("selection.json").exists());
        fs::remove_file(first.join(".tmpSymlink")).unwrap();
        fs::write(first.join(".tmpInterrupted"), b"partial").unwrap();
        fs::set_permissions(
            first.join(".tmpInterrupted"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(store.snapshot_cycle(1).is_err());
        assert!(store.prune_sequence(1).unwrap());
        assert!(!store.prune_sequence(1).unwrap());
        store.validate_snapshot(2, &snapshot).unwrap();
        assert!(root.join("enrollment.json").is_file());
        assert!(root.join(".coordinator.lock").is_file());
    }
}
