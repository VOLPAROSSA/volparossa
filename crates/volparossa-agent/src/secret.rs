//! Bounded no-follow loading for the systemd identity credential.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Take},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use thiserror::Error;
use volparossa_identity::{MAX_PASSPHRASE_BYTES, Passphrase};
use zeroize::{Zeroize, Zeroizing};

/// Reads a passphrase from a protected systemd credential or equivalently
/// protected provisioning file. Secret bytes are zeroed after construction.
pub fn read_identity_credential(path: &Path) -> Result<Passphrase, CredentialError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CredentialError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(CredentialError::UnsafeFile);
    }
    let mode = metadata.mode() & 0o777;
    if !credential_mode_is_safe(mode, metadata.uid(), metadata.gid()) {
        return Err(CredentialError::UnsafeMode(mode));
    }
    let maximum = MAX_PASSPHRASE_BYTES
        .checked_add(2)
        .ok_or(CredentialError::Length)?;
    if metadata.len() == 0 || metadata.len() > u64::try_from(maximum).expect("small bound") {
        return Err(CredentialError::Length);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| CredentialError::Io {
            path: path.to_owned(),
            source,
        })?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum));
    let take_limit = u64::try_from(maximum).expect("small bound");
    let mut bounded: Take<&mut fs::File> = file.by_ref().take(take_limit);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|source| CredentialError::Io {
            path: path.to_owned(),
            source,
        })?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    let result = Passphrase::new(bytes.as_slice()).map_err(CredentialError::Identity);
    bytes.zeroize();
    result
}

fn credential_mode_is_safe(mode: u32, uid: u32, gid: u32) -> bool {
    let owner_only = mode & 0o177 == 0 && mode & 0o400 != 0;
    // systemd creates service credentials as root:root mode 0400, then grants the
    // service UID read access with a POSIX ACL. The ACL mask is represented in
    // st_mode as the group-read bit, yielding 0440 even though group:: has no
    // access. Accept only that exact root-owned projection.
    let systemd_service_acl = mode == 0o440 && uid == 0 && gid == 0;
    owner_only || systemd_service_acl
}

/// Credential validation or loading failure. Its display form contains no
/// secret bytes.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// File metadata or contents could not be read.
    #[error("cannot read protected identity credential at {path}")]
    Io {
        /// Credential location.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The credential is a symlink, hard link, or non-regular file.
    #[error("identity credential is not one regular non-linked file")]
    UnsafeFile,
    /// The credential is executable, group/world accessible, or not owner-readable.
    #[error("identity credential has unsafe mode {0:#06o}")]
    UnsafeMode(u32),
    /// The bounded credential length was invalid.
    #[error("identity credential length is outside the accepted bound")]
    Length,
    /// The passphrase policy rejected the credential without exposing it.
    #[error("identity credential does not satisfy the passphrase policy")]
    Identity(#[source] volparossa_identity::IdentityError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs::Permissions,
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reads_owner_only_credential_and_redacts_debug() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("credential");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .expect("credential");
        file.write_all(b"a sufficiently long passphrase\n")
            .expect("write");
        let passphrase = read_identity_credential(&path).expect("read");
        assert_eq!(format!("{passphrase:?}"), "Passphrase([REDACTED])");
    }

    #[test]
    fn rejects_world_access_and_symlinks() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("credential");
        fs::write(&path, b"a sufficiently long passphrase").expect("write");
        fs::set_permissions(&path, Permissions::from_mode(0o644)).expect("permissions");
        assert!(matches!(
            read_identity_credential(&path),
            Err(CredentialError::UnsafeMode(_))
        ));
        fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("permissions");
        let link = directory.path().join("link");
        symlink(&path, &link).expect("symlink");
        assert!(matches!(
            read_identity_credential(&link),
            Err(CredentialError::UnsafeFile)
        ));
    }

    #[test]
    fn accepts_exact_root_owned_systemd_acl_projection() {
        assert!(credential_mode_is_safe(0o440, 0, 0));
        assert!(!credential_mode_is_safe(0o440, 1_000, 0));
        assert!(!credential_mode_is_safe(0o440, 0, 1_000));
        assert!(!credential_mode_is_safe(0o460, 0, 0));
        assert!(!credential_mode_is_safe(0o444, 0, 0));
    }
}
