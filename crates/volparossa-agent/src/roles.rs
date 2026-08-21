//! Atomic, private persistence for explicitly configured runtime roles.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use volparossa_config::RolesConfig;

const ROLE_STATE_VERSION: u32 = 1;
const MAX_ROLE_FILE_BYTES: u64 = 4_096;
const MAX_ROLE_FILE_LENGTH: usize = 4_096;

/// Versioned role state. Client operation remains enabled in v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRoles {
    schema_version: u32,
    client: bool,
    relay: bool,
    exit: bool,
}

impl PersistedRoles {
    const fn from_config(roles: RolesConfig) -> Self {
        Self {
            schema_version: ROLE_STATE_VERSION,
            client: roles.client,
            relay: roles.relay,
            exit: roles.exit,
        }
    }

    fn into_config(self) -> Result<RolesConfig, RoleStoreError> {
        if self.schema_version != ROLE_STATE_VERSION || !self.client {
            return Err(RoleStoreError::Invalid);
        }
        Ok(RolesConfig {
            client: self.client,
            relay: self.relay,
            exit: self.exit,
        })
    }
}

/// Private atomic role-state store below the service state directory.
#[derive(Clone, Debug)]
pub struct RoleStore {
    path: PathBuf,
}

impl RoleStore {
    /// Constructs a store at an already validated absolute path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Loads existing state, or durably records the safe configuration default.
    pub fn load_or_initialize(
        &self,
        configured: RolesConfig,
    ) -> Result<RolesConfig, RoleStoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                validate_role_metadata(&metadata)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(&self.path)
                    .map_err(RoleStoreError::Io)?;
                let mut bytes = Vec::with_capacity(
                    usize::try_from(metadata.len()).map_err(|_| RoleStoreError::Invalid)?,
                );
                Read::by_ref(&mut file)
                    .take(MAX_ROLE_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(RoleStoreError::Io)?;
                if bytes.is_empty() || bytes.len() > MAX_ROLE_FILE_LENGTH {
                    return Err(RoleStoreError::Invalid);
                }
                serde_json::from_slice::<PersistedRoles>(&bytes)
                    .map_err(|_| RoleStoreError::Invalid)?
                    .into_config()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.persist(configured)?;
                Ok(configured)
            }
            Err(error) => Err(RoleStoreError::Io(error)),
        }
    }

    /// Atomically persists one fully validated role snapshot.
    pub fn persist(&self, roles: RolesConfig) -> Result<(), RoleStoreError> {
        if !roles.client {
            return Err(RoleStoreError::Invalid);
        }
        let parent = self.path.parent().ok_or(RoleStoreError::Invalid)?;
        validate_private_directory(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            validate_role_metadata(&metadata)?;
        }
        let bytes = serde_json::to_vec(&PersistedRoles::from_config(roles))
            .map_err(|_| RoleStoreError::Invalid)?;
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let temporary = parent.join(format!(".roles-{}.tmp", hex::encode(nonce)));
        let result = write_and_replace(&temporary, &self.path, &bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)
            .map_err(RoleStoreError::Io)?;
        directory.sync_all().map_err(RoleStoreError::Io)
    }
}

fn write_and_replace(
    temporary: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), RoleStoreError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(RoleStoreError::Io)?;
    file.write_all(bytes).map_err(RoleStoreError::Io)?;
    file.sync_all().map_err(RoleStoreError::Io)?;
    fs::rename(temporary, destination).map_err(RoleStoreError::Io)?;
    let metadata = fs::symlink_metadata(destination).map_err(RoleStoreError::Io)?;
    validate_role_metadata(&metadata)
}

fn validate_role_metadata(metadata: &fs::Metadata) -> Result<(), RoleStoreError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_ROLE_FILE_BYTES
    {
        return Err(RoleStoreError::UnsafeFile);
    }
    Ok(())
}

/// Creates or validates the private service state directory.
pub fn ensure_private_state_directory(path: &Path) -> Result<(), RoleStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(RoleStoreError::Io)?;
            validate_private_directory(path)
        }
        Err(error) => Err(RoleStoreError::Io(error)),
    }
}

fn validate_private_directory(path: &Path) -> Result<(), RoleStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(RoleStoreError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(RoleStoreError::UnsafeDirectory);
    }
    Ok(())
}

/// Role-state persistence error.
#[derive(Debug, Error)]
pub enum RoleStoreError {
    /// Filesystem operation failed.
    #[error("role-state filesystem operation failed")]
    Io(#[source] std::io::Error),
    /// State directory ownership or mode is unsafe.
    #[error("role-state directory must be owned by the agent with mode 0700")]
    UnsafeDirectory,
    /// Existing role file is not a single regular `0600` file.
    #[error("role-state file is unsafe")]
    UnsafeFile,
    /// Versioned state is malformed or would disable the client role.
    #[error("role-state contents are invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn initial_state_and_updates_survive_reopen() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let store = RoleStore::new(directory.path().join("roles.json"));
        let initial = RolesConfig {
            client: true,
            relay: false,
            exit: false,
        };
        assert_eq!(
            store.load_or_initialize(initial).expect("initialize"),
            initial
        );
        let updated = RolesConfig {
            client: true,
            relay: true,
            exit: false,
        };
        store.persist(updated).expect("persist");
        assert_eq!(store.load_or_initialize(initial).expect("reload"), updated);
        assert_eq!(
            fs::symlink_metadata(directory.path().join("roles.json"))
                .expect("metadata")
                .mode()
                & 0o777,
            0o600
        );
    }
}
