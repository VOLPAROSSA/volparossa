//! Durable high-water marks for independently provisioned policy authority namespaces.
//!
//! Only namespace/version/body hash are retained, never rules, browsing data or keys. A
//! different configured trust set is a different authority: this does not authenticate key
//! rotation or claim rollback resistance across arbitrary changes of local trust authority.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path},
};

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use volparossa_policy::{
    MaintainerEnvironment, POLICY_PROTOCOL_VERSION, PolicyMode, TrustStore, VerifiedManifest,
};

const FLOOR_FILE: &str = "policy-floor.json";
const LOCK_FILE: &str = ".policy-floor.lock";
const MAX_BYTES: u64 = 32 * 1024;
const MAX_AUTHORITIES: usize = 64;

#[cfg(test)]
mod tests;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u32,
    authorities: Vec<Record>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    namespace: [u8; 32],
    version: u64,
    body_hash: [u8; 32],
}

/// An activation cannot proceed when its durable policy floor is unavailable.
#[derive(Debug, thiserror::Error)]
pub enum FloorError {
    /// Unsafe state ownership, path, permissions or bounded persisted structure.
    #[error("policy floor state is unsafe or invalid")]
    Invalid,
    /// An already accepted authority version cannot be replaced by a lower one.
    #[error("policy manifest version is below the retained authority floor")]
    Rollback,
    /// One authority/version cannot identify two different canonical policy bodies.
    #[error("policy manifest conflicts with the retained hash at this version")]
    Conflict,
    /// Another cooperating process is currently comparing/updating the floor.
    #[error("policy floor is busy")]
    Busy,
    /// Filesystem failure: no success or fallback floor is fabricated.
    #[error("policy floor filesystem operation failed")]
    Io(#[from] std::io::Error),
}

pub(super) fn accept(
    directory: &Path,
    trust: &TrustStore,
    manifest: &VerifiedManifest,
) -> Result<(), FloorError> {
    let parent = open_directory(directory)?;
    let (coordination, created) = lock_file(directory)?;
    let _locked =
        Flock::lock(coordination, FlockArg::LockExclusiveNonblock).map_err(|_| FloorError::Busy)?;
    let mut state = match read(directory) {
        Ok(state) => state,
        // A pre-existing lock and missing floor is interrupted/lost state, not first startup.
        Err(FloorError::Io(error)) if created && error.kind() == std::io::ErrorKind::NotFound => {
            State {
                schema_version: 1,
                authorities: Vec::new(),
            }
        }
        Err(error) => return Err(error),
    };
    let namespace = namespace(trust);
    let record = Record {
        namespace,
        version: manifest.manifest_version(),
        body_hash: *manifest.policy_hash(),
    };
    match state
        .authorities
        .binary_search_by_key(&namespace, |record| record.namespace)
    {
        Ok(index) => {
            let retained = &state.authorities[index];
            if record.version < retained.version {
                return Err(FloorError::Rollback);
            }
            if record.version == retained.version {
                return if record.body_hash == retained.body_hash {
                    Ok(())
                } else {
                    Err(FloorError::Conflict)
                };
            }
            state.authorities[index] = record;
        }
        Err(index) => {
            if state.authorities.len() >= MAX_AUTHORITIES {
                return Err(FloorError::Invalid);
            }
            state.authorities.insert(index, record);
        }
    }
    persist(directory, &parent, &state)
}

fn namespace(trust: &TrustStore) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"VOLPAROSSA/policy-floor/authority/v1\0");
    digest.update(POLICY_PROTOCOL_VERSION.to_be_bytes());
    digest.update([match trust.mode() {
        PolicyMode::Production => 1,
        PolicyMode::Development => 2,
    }]);
    // TrustStore already sorts and rejects duplicate keys. Reordering JSON or changing its
    // filename/whitespace must not create a new authority or reset its retained floor.
    for key in trust.maintainers() {
        digest.update(key.verifying_key().as_bytes());
        digest.update([match key.environment() {
            MaintainerEnvironment::Production => 1,
            MaintainerEnvironment::Development => 2,
        }]);
    }
    digest.finalize().into()
}

fn open_directory(path: &Path) -> Result<File, FloorError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.as_os_str().len() > 4096
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(FloorError::Invalid);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(FloorError::Invalid);
    }
    Ok(directory)
}

fn lock_file(directory: &Path) -> Result<(File, bool), FloorError> {
    let path = directory.join(LOCK_FILE);
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
                .open(&path)?,
            false,
        ),
        Err(error) => return Err(error.into()),
    };
    validate_file(&file, &path, true)?;
    Ok((file, created))
}

fn validate_file(file: &File, path: &Path, empty: bool) -> Result<(), FloorError> {
    let actual = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !actual.is_file()
        || !named.is_file()
        || actual.dev() != named.dev()
        || actual.ino() != named.ino()
        || actual.nlink() != 1
        || actual.uid() != nix::unistd::geteuid().as_raw()
        || actual.mode() & 0o777 != 0o600
        || if empty {
            actual.len() != 0
        } else {
            actual.len() == 0 || actual.len() > MAX_BYTES
        }
    {
        return Err(FloorError::Invalid);
    }
    Ok(())
}

fn read(directory: &Path) -> Result<State, FloorError> {
    let path = directory.join(FLOOR_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    validate_file(&file, &path, false)?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_BYTES).expect("small local state bound") {
        return Err(FloorError::Invalid);
    }
    let state: State = serde_json::from_slice(&bytes).map_err(|_| FloorError::Invalid)?;
    if state.schema_version != 1
        || state.authorities.is_empty()
        || state.authorities.len() > MAX_AUTHORITIES
        || state.authorities.iter().any(|record| record.version == 0)
        || state
            .authorities
            .windows(2)
            .any(|pair| pair[0].namespace >= pair[1].namespace)
    {
        return Err(FloorError::Invalid);
    }
    Ok(state)
}

fn persist(directory: &Path, parent: &File, state: &State) -> Result<(), FloorError> {
    let bytes = serde_json::to_vec(state).map_err(|_| FloorError::Invalid)?;
    if bytes.len() > usize::try_from(MAX_BYTES).expect("small local state bound") {
        return Err(FloorError::Invalid);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".policy-floor-")
        .tempfile_in(directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    let path = directory.join(FLOOR_FILE);
    let committed = temporary.persist(&path).map_err(|error| error.error)?;
    validate_file(&committed, &path, false)?;
    parent.sync_all()?;
    Ok(())
}
