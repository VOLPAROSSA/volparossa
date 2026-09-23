//! Durable exact-object decisions. Original authority bytes are verified on every restart.
//!
//! No decision or trust key comes from a cache provider. Historical validation does
//! not revive an old epoch: the shared runtime gate separately checks current epoch/time.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use volparossa_config::Config;
use volparossa_content::object_policy::{
    MAX_OBJECT_POLICY_RULES, ObjectPolicyGate, ObjectRule, ObjectSubject,
};
use volparossa_policy::{
    MAX_SIGNED_MANIFEST_BYTES, TrustStore, VerifiedManifest,
    object::{
        MAX_OBJECT_DECISION_BYTES, ObjectOutcome, SignedObjectDecision, VerifiedObjectDecision,
        verify_object_decision,
    },
    verify_manifest,
};

use super::ContentError;
use crate::policy::{load_authority, read_integrity_file};

const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const JOURNAL: &str = "journal.json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    envelope_hex: String,
    epoch_manifest_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    entries: Vec<Entry>,
}

struct State {
    journal: Journal,
    decisions: BTreeMap<[u8; 32], VerifiedObjectDecision>,
    authority: Option<TrustStore>,
}

/// One lifetime-locked owner; concurrent requests serialize the durable revision transition.
pub(crate) struct ObjectPolicyOwner {
    config: Config,
    trust_path: PathBuf,
    directory: PathBuf,
    directory_file: File,
    _lock: Flock<File>,
    gate: ObjectPolicyGate,
    state: Mutex<State>,
}

impl ObjectPolicyOwner {
    pub(crate) fn load(
        config: &Config,
        trust_path: &Path,
        state_directory: &Path,
        current: Option<&VerifiedManifest>,
        gate: ObjectPolicyGate,
    ) -> Result<Self, ContentError> {
        let parent = open_directory(state_directory)?;
        let directory = state_directory.join("object-policy");
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => parent.sync_all().map_err(|_| ContentError::Invalid)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ContentError::Invalid),
        }
        let directory_file = open_directory(&directory)?;
        let (lock, initialized) = lock_file(&directory)?;
        let journal = match read_journal(&directory) {
            Ok(journal) => journal,
            Err(ReadError::Missing) if initialized => {
                let journal = Journal {
                    version: 1,
                    entries: Vec::new(),
                };
                persist(&directory, &directory_file, &journal)?;
                journal
            }
            Err(_) => return Err(ContentError::Invalid),
        };
        // Even expired entries need the still-configured original authority, not
        // a self-declared key list recovered from the signed envelope.
        let mut decisions = BTreeMap::new();
        let mut authority = None;
        if !journal.entries.is_empty() {
            let (trust, verification) =
                load_authority(config, trust_path).map_err(|_| ContentError::Policy)?;
            let mut previous = None;
            for entry in &journal.entries {
                let envelope = bytes(&entry.envelope_hex, MAX_OBJECT_DECISION_BYTES)?;
                let original =
                    SignedObjectDecision::decode(&envelope).map_err(|_| ContentError::Policy)?;
                let epoch_bytes = bytes(&entry.epoch_manifest_hex, MAX_SIGNED_MANIFEST_BYTES)?;
                let historical = original.body().issued_at_ms;
                let epoch = verify_manifest(&epoch_bytes, historical, &trust, verification)
                    .map_err(|_| ContentError::Policy)?;
                let verified =
                    verify_object_decision(&envelope, historical, &trust, verification, &epoch)
                        .map_err(|_| ContentError::Policy)?;
                let id = verified.body().subject.manifest_id;
                if previous.is_some_and(|old| old >= id) {
                    return Err(ContentError::Invalid);
                }
                previous = Some(id);
                if decisions
                    .insert(verified.body().subject.manifest_id, verified)
                    .is_some()
                {
                    return Err(ContentError::Invalid);
                }
            }
            authority = Some(trust);
        }
        // Validate every retained original before changing the live gate. A caller
        // must not start a service if loading fails; no half-loaded journal is usable.
        gate.set_epoch(None);
        for decision in decisions.values() {
            gate.install(rule(decision))
                .map_err(|_| ContentError::Unavailable)?;
        }
        gate.set_epoch(current.map(|manifest| *manifest.policy_hash()));
        Ok(Self {
            config: config.clone(),
            trust_path: trust_path.into(),
            directory,
            directory_file,
            _lock: lock,
            gate,
            state: Mutex::new(State {
                journal,
                decisions,
                authority,
            }),
        })
    }

    /// Apply only after its original quorum and current configured epoch are verified.
    /// Durability precedes live enforcement; an error never claims successful activation.
    pub(crate) fn apply(
        &self,
        envelope: &[u8],
        current: &VerifiedManifest,
    ) -> Result<VerifiedObjectDecision, ContentError> {
        self.apply_at(envelope, current, crate::unix_millis())
    }

    fn apply_at(
        &self,
        envelope: &[u8],
        current: &VerifiedManifest,
        now: u64,
    ) -> Result<VerifiedObjectDecision, ContentError> {
        let mut state = self.state.lock().map_err(|_| ContentError::Unavailable)?;
        if self.gate.epoch() != Some(*current.policy_hash()) {
            return Err(ContentError::Policy);
        }
        let (trust, verification) =
            load_authority(&self.config, &self.trust_path).map_err(|_| ContentError::Policy)?;
        if state
            .authority
            .as_ref()
            .is_some_and(|old| !same_authority(old, &trust))
        {
            return Err(ContentError::Policy);
        }
        let epoch_path = Path::new(&self.config.policy.manifest_path);
        if !epoch_path.is_absolute() {
            return Err(ContentError::Policy);
        }
        let epoch_bytes = read_integrity_file(epoch_path, MAX_SIGNED_MANIFEST_BYTES as u64)
            .map_err(|_| ContentError::Policy)?;
        let epoch = verify_manifest(&epoch_bytes, now, &trust, verification)
            .map_err(|_| ContentError::Policy)?;
        if epoch.policy_hash() != current.policy_hash()
            || epoch.manifest_version() != current.manifest_version()
        {
            return Err(ContentError::Policy);
        }
        let decision = verify_object_decision(envelope, now, &trust, verification, &epoch)
            .map_err(|_| ContentError::Policy)?;
        let id = decision.body().subject.manifest_id;
        if let Some(old) = state.decisions.get(&id) {
            if old.body().subject != decision.body().subject
                || decision.body().decision_revision < old.body().decision_revision
                || (decision.body().decision_revision == old.body().decision_revision
                    && decision.decision_hash() != old.decision_hash())
            {
                return Err(ContentError::Policy);
            }
            if decision.decision_hash() == old.decision_hash() {
                // Preserve the very first original envelope, even if a retry adds
                // endorsements. The body, revision and expiry are already identical.
                self.gate
                    .install(rule(old))
                    .map_err(|_| ContentError::Unavailable)?;
                if self.gate.epoch() != Some(*current.policy_hash()) {
                    return Err(ContentError::Policy);
                }
                return Ok(old.clone());
            }
        } else if state.decisions.len() >= MAX_OBJECT_POLICY_RULES {
            return Err(ContentError::Busy);
        }
        let mut journal = state.journal.clone();
        let entry = Entry {
            envelope_hex: hex::encode(envelope),
            epoch_manifest_hex: hex::encode(epoch_bytes),
        };
        if let Some(index) = state.decisions.keys().position(|existing| existing == &id) {
            journal.entries[index] = entry;
        } else {
            let index = state
                .decisions
                .keys()
                .filter(|existing| **existing < id)
                .count();
            journal.entries.insert(index, entry);
        }
        persist(&self.directory, &self.directory_file, &journal)?;
        state.journal = journal;
        state.authority = Some(trust);
        state.decisions.insert(id, decision.clone());
        self.gate
            .install(rule(&decision))
            .map_err(|_| ContentError::Unavailable)?;
        if self.gate.epoch() != Some(*current.policy_hash()) {
            return Err(ContentError::Policy);
        }
        Ok(decision)
    }
}

fn same_authority(left: &TrustStore, right: &TrustStore) -> bool {
    left.mode() == right.mode()
        && left.maintainers().len() == right.maintainers().len()
        && left
            .maintainers()
            .iter()
            .zip(right.maintainers())
            .all(|(left, right)| {
                left.key_id() == right.key_id() && left.environment() == right.environment()
            })
}

fn rule(decision: &VerifiedObjectDecision) -> ObjectRule {
    let body = decision.body();
    ObjectRule {
        subject: ObjectSubject {
            publisher_key: body.subject.publisher_key,
            manifest_id: body.subject.manifest_id,
            object_sha256: body.subject.object_sha256,
        },
        policy_hash: body.policy_hash,
        allow: body.outcome == ObjectOutcome::Allow,
        expires_at_ms: body.expires_at_ms,
    }
}

fn bytes(encoded: &str, maximum: usize) -> Result<Vec<u8>, ContentError> {
    if encoded.is_empty() || encoded.len() > maximum * 2 {
        return Err(ContentError::Invalid);
    }
    hex::decode(encoded).map_err(|_| ContentError::Invalid)
}

fn open_directory(path: &Path) -> Result<File, ContentError> {
    if !path.is_absolute() {
        return Err(ContentError::Invalid);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ContentError::Invalid)?;
    let metadata = directory.metadata().map_err(|_| ContentError::Invalid)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ContentError::Invalid);
    }
    Ok(directory)
}

fn safe_file(file: &File, path: &Path, maximum: u64, empty: bool) -> Result<(), ContentError> {
    let actual = file.metadata().map_err(|_| ContentError::Invalid)?;
    let named = fs::symlink_metadata(path).map_err(|_| ContentError::Invalid)?;
    if !actual.is_file()
        || !named.is_file()
        || actual.dev() != named.dev()
        || actual.ino() != named.ino()
        || actual.nlink() != 1
        || actual.uid() != nix::unistd::geteuid().as_raw()
        || actual.mode() & 0o777 != 0o600
        || actual.len() > maximum
        || (empty && actual.len() != 0)
        || (!empty && actual.len() == 0)
    {
        return Err(ContentError::Invalid);
    }
    Ok(())
}

fn lock_file(directory: &Path) -> Result<(Flock<File>, bool), ContentError> {
    let path = directory.join(".lock");
    let (file, created) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| ContentError::Invalid)?,
            false,
        ),
        Err(_) => return Err(ContentError::Invalid),
    };
    safe_file(&file, &path, 0, true)?;
    let locked =
        Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| ContentError::Busy)?;
    Ok((locked, created))
}

enum ReadError {
    Missing,
    Invalid,
}

fn read_journal(directory: &Path) -> Result<Journal, ReadError> {
    let path = directory.join(JOURNAL);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReadError::Missing
            } else {
                ReadError::Invalid
            }
        })?;
    safe_file(&file, &path, MAX_JOURNAL_BYTES, false).map_err(|_| ReadError::Invalid)?;
    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| ReadError::Invalid)?;
    if raw.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(ReadError::Invalid);
    }
    let journal: Journal = serde_json::from_slice(&raw).map_err(|_| ReadError::Invalid)?;
    if journal.version != 1 || journal.entries.len() > MAX_OBJECT_POLICY_RULES {
        return Err(ReadError::Invalid);
    }
    Ok(journal)
}

fn persist(directory: &Path, parent: &File, journal: &Journal) -> Result<(), ContentError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| ContentError::Invalid)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES || journal.entries.len() > MAX_OBJECT_POLICY_RULES {
        return Err(ContentError::Busy);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".journal-")
        .tempfile_in(directory)
        .map_err(|_| ContentError::Invalid)?;
    temporary
        .write_all(&bytes)
        .map_err(|_| ContentError::Invalid)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| ContentError::Invalid)?;
    let path = directory.join(JOURNAL);
    let committed = temporary
        .persist(&path)
        .map_err(|_| ContentError::Invalid)?;
    safe_file(&committed, &path, MAX_JOURNAL_BYTES, false)?;
    parent.sync_all().map_err(|_| ContentError::Invalid)
}

#[cfg(test)]
mod tests;
