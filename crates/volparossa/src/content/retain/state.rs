//! Private owner checkpoints. Historical custody observations are never live availability.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{MAX_PROVIDERS, custody, sha};

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct Store {
    root: PathBuf,
    _lock: Flock<File>,
}

fn private_directory(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o700
            && fs::canonicalize(path)? == path,
        "content_retain_private_directory"
    );
    Ok(())
}

impl Store {
    pub(super) fn open(root: &Path, resume: bool) -> Result<Self> {
        let parent = root.parent().context("content_retain_parent")?;
        private_directory(parent)?;
        if !resume {
            fs::DirBuilder::new().mode(0o700).create(root)?;
            File::open(parent)?.sync_all()?;
        }
        private_directory(root)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!resume)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".retain.lock"))?;
        let info = file.metadata()?;
        ensure!(
            info.is_file()
                && info.len() == 0
                && info.uid() == nix::unistd::geteuid().as_raw()
                && info.nlink() == 1
                && info.mode() & 0o777 == 0o600,
            "content_retain_private_lock"
        );
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| anyhow::anyhow!("content_retain_already_running"))?;
        Ok(Self {
            root: root.to_path_buf(),
            _lock: lock,
        })
    }

    pub(super) fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.root.join(name))?;
        let info = file.metadata()?;
        ensure!(
            info.is_file()
                && info.nlink() == 1
                && info.uid() == nix::unistd::geteuid().as_raw()
                && info.mode() & 0o777 == 0o600
                && info.len() <= maximum as u64,
            "content_retain_private_record"
        );
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= maximum, "content_retain_record_bound");
        Ok(bytes)
    }

    pub(super) fn write(&self, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
        ensure!(bytes.len() <= MAX_STATE_BYTES, "content_retain_state_bound");
        let path = self.root.join(name);
        if let Ok(info) = fs::symlink_metadata(&path) {
            ensure!(
                replace
                    && info.is_file()
                    && info.nlink() == 1
                    && info.uid() == nix::unistd::geteuid().as_raw(),
                "content_retain_existing_record"
            );
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        if replace {
            temporary.persist(path).map_err(|error| error.error)?;
        } else {
            temporary
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        }
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub(super) fn load(&self) -> Result<State> {
        Ok(serde_json::from_slice(
            &self.read("state.json", MAX_STATE_BYTES)?,
        )?)
    }

    pub(super) fn checkpoint(&self, state: &State, manifest_id: &str, expires: u64) -> Result<()> {
        let bytes = serde_json::to_vec(state)?;
        self.write("state.json", &bytes, true)?;
        self.write(
            "status.json",
            &serde_json::to_vec(&json!({
                "operation":"content_retain", "state_sha256":sha(&bytes),
                "manifest_id":manifest_id, "original_expiry_unix_seconds":expires,
                "started_at_unix_seconds":state.started_at, "deadline_unix_seconds":state.deadline,
                "completed_polls":state.completed_polls, "attempt_sequence":state.attempt_sequence,
                "uploads_reserved_bytes":state.uploads_reserved_bytes, "pending":state.pending,
                "confirmed_holders":state.confirmed_holders, "last_outcome":state.last_outcome,
                "last_observed_unix_seconds":state.last_observed,
                "future_availability_guaranteed":false, "maintenance_while_owner_offline":false
            }))?,
            true,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub(super) sequence: u64,
    pub(super) provider_key: String,
    pub(super) operation: String,
    pub(super) started_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub(super) sequence: u64,
    pub(super) operation: String,
    pub(super) checked_at: u64,
    pub(super) outcome: String,
    pub(super) original: Option<custody::RetainedExchange>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) version: u32,
    pub(super) enrollment_sha256: String,
    pub(super) started_at: u64,
    pub(super) deadline: u64,
    pub(super) completed_polls: u64,
    pub(super) attempt_sequence: u64,
    pub(super) uploads_reserved_bytes: u64,
    pub(super) pending: Option<Pending>,
    pub(super) observations: BTreeMap<String, Observation>,
    pub(super) confirmed_holders: Vec<String>,
    pub(super) last_observed: u64,
    pub(super) last_outcome: String,
}

impl State {
    pub(super) fn new(enrollment: &[u8], at: u64, seconds: u32, expires: u64) -> Result<Self> {
        Ok(Self {
            version: 1,
            enrollment_sha256: sha(enrollment),
            started_at: at,
            deadline: at
                .checked_add(u64::from(seconds))
                .context("content_retain_deadline")?
                .min(expires),
            completed_polls: 0,
            attempt_sequence: 0,
            uploads_reserved_bytes: 0,
            pending: None,
            observations: BTreeMap::new(),
            confirmed_holders: Vec::new(),
            last_observed: at,
            last_outcome: "enrolled".into(),
        })
    }

    pub(super) fn validate(
        &self,
        enrollment: &[u8],
        seconds: u32,
        expires: u64,
        budget: u64,
    ) -> Result<()> {
        ensure!(
            self.version == 1
                && self.enrollment_sha256 == sha(enrollment)
                && self.started_at > 0
                && self.deadline > self.started_at
                && self.deadline
                    == self
                        .started_at
                        .checked_add(u64::from(seconds))
                        .context("content_retain_deadline")?
                        .min(expires)
                && self.uploads_reserved_bytes <= budget
                && self.observations.len() <= MAX_PROVIDERS
                && self.confirmed_holders.len() <= MAX_PROVIDERS
                && self.last_observed >= self.started_at,
            "content_retain_original_state"
        );
        let mut unique = std::collections::BTreeSet::new();
        for key in &self.confirmed_holders {
            ensure!(
                unique.insert(key)
                    && self
                        .observations
                        .get(key)
                        .is_some_and(|record| record.outcome == "complete"),
                "content_retain_holder_record"
            );
        }
        for (key, record) in &self.observations {
            validate_key(key)?;
            ensure!(
                record.sequence > 0
                    && record.sequence <= self.attempt_sequence
                    && record.checked_at >= self.started_at
                    && record.checked_at <= self.last_observed
                    && matches!(record.operation.as_str(), "inspect" | "deposit")
                    && matches!(
                        record.outcome.as_str(),
                        "complete" | "missing" | "unavailable" | "interrupted"
                    ),
                "content_retain_observation_record"
            );
        }
        if let Some(pending) = &self.pending {
            validate_key(&pending.provider_key)?;
            ensure!(
                pending.sequence == self.attempt_sequence
                    && pending.sequence > 0
                    && pending.started_at >= self.started_at
                    && pending.started_at < self.deadline
                    && matches!(pending.operation.as_str(), "inspect" | "deposit"),
                "content_retain_pending_record"
            );
        }
        Ok(())
    }

    /// Reserve the full logical object before any possibly partial upload. Unused
    /// credits are deliberately not refunded after interruption or local failure.
    pub(super) fn reserve(
        &mut self,
        provider: String,
        operation: &str,
        bytes: u64,
        budget: u64,
        at: u64,
    ) -> Result<bool> {
        ensure!(
            self.pending.is_none() && matches!(operation, "inspect" | "deposit"),
            "content_retain_pending"
        );
        let Some(next) = self.uploads_reserved_bytes.checked_add(bytes) else {
            return Ok(false);
        };
        if next > budget {
            return Ok(false);
        }
        self.attempt_sequence = self
            .attempt_sequence
            .checked_add(1)
            .context("content_retain_sequence")?;
        self.uploads_reserved_bytes = next;
        self.pending = Some(Pending {
            sequence: self.attempt_sequence,
            provider_key: provider,
            operation: operation.into(),
            started_at: at,
        });
        Ok(true)
    }
}

fn validate_key(key: &str) -> Result<()> {
    let parsed = super::super::parse_publisher_key(key).map_err(anyhow::Error::msg)?;
    ensure!(
        hex::encode(parsed.as_bytes()) == key,
        "content_retain_canonical_provider"
    );
    Ok(())
}
