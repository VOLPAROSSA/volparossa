//! Fixed root-owned runtime files; no path is accepted from an agent request.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use nix::unistd::{Gid, Group, Uid, User, getegid, geteuid};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Dedicated unprivileged system account allowed to call the helper.
pub const AGENT_ACCOUNT: &str = "volparossa";
/// Root-owned runtime directory, normally created by systemd `RuntimeDirectory=`.
pub const RUNTIME_DIRECTORY: &str = "/run/volparossa";
/// Fixed local helper endpoint.
pub const SOCKET_PATH: &str = "/run/volparossa/helper.sock";
/// Fixed short-lived cleanup capability file readable only by the agent group.
pub const TOKEN_PATH: &str = "/run/volparossa/helper.cleanup-token";

pub(crate) struct ProductionRuntime {
    pub(crate) agent_uid: u32,
    pub(crate) agent_gid: u32,
    pub(crate) cleanup_token: Zeroizing<[u8; 32]>,
}

pub(crate) fn production_agent_uid() -> Result<u32, io::Error> {
    let user = User::from_name(AGENT_ACCOUNT)
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "agent account missing"))?;
    if user.uid.is_root() || user.uid.as_raw() == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent account must be a dedicated unprivileged UID",
        ));
    }
    Ok(user.uid.as_raw())
}

pub(crate) fn prepare_production_runtime() -> Result<ProductionRuntime, io::Error> {
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "volparossa-helper must run as root",
        ));
    }
    let user = User::from_name(AGENT_ACCOUNT)
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "agent account missing"))?;
    if user.uid.as_raw() != production_agent_uid()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent account identity changed during startup",
        ));
    }
    let group = Group::from_name(AGENT_ACCOUNT)
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "agent group missing"))?;
    if user.gid != group.gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent primary group mismatch",
        ));
    }
    validate_service_group(getegid().as_raw(), group.gid.as_raw())?;

    let directory = Path::new(RUNTIME_DIRECTORY);
    if !directory.exists() {
        DirBuilder::new().mode(0o750).create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    validate_directory(directory, 0, group.gid.as_raw())?;

    let mut cleanup_token = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(cleanup_token.as_mut());
    write_token(
        Path::new(TOKEN_PATH),
        &cleanup_token,
        Uid::from_raw(0),
        group.gid,
    )?;
    Ok(ProductionRuntime {
        agent_uid: user.uid.as_raw(),
        agent_gid: group.gid.as_raw(),
        cleanup_token,
    })
}

pub(crate) fn remove_stale_socket(path: &Path, expected_gid: u32) -> Result<(), io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe pre-existing helper socket",
        ));
    }
    fs::remove_file(path)
}

pub(crate) fn secure_socket(path: &Path, expected_gid: Gid) -> Result<(), io::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_gid.as_raw()
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper socket ownership validation failed",
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o750
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe helper runtime directory",
        ));
    }
    Ok(())
}

fn write_token(path: &Path, token: &[u8; 32], owner: Uid, group: Gid) -> Result<(), io::Error> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner.as_raw()
            || metadata.gid() != group.as_raw()
            || metadata.mode() & 0o777 != 0o640
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe cleanup token file",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o640))?;
    file.write_all(token)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.uid() != owner.as_raw()
        || metadata.gid() != group.as_raw()
        || metadata.mode() & 0o777 != 0o640
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cleanup token ownership validation failed",
        ));
    }
    Ok(())
}

pub(crate) struct SocketPathGuard {
    path: PathBuf,
    expected_gid: u32,
}

impl SocketPathGuard {
    pub(crate) fn new(path: &Path, expected_gid: u32) -> Self {
        Self {
            path: path.to_owned(),
            expected_gid,
        }
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.uid() == 0
            && metadata.gid() == self.expected_gid
            && metadata.mode() & 0o777 == 0o660
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_service_group(effective_gid: u32, agent_gid: u32) -> Result<(), io::Error> {
    if effective_gid != agent_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper effective group must be the dedicated agent group",
        ));
    }
    Ok(())
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{getegid, geteuid};
    use std::fs::File;

    #[test]
    fn runtime_directory_validation_rejects_world_access() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
            .expect("permissions");
        validate_directory(directory.path(), geteuid().as_raw(), getegid().as_raw())
            .expect("secure directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
            .expect("permissions");
        assert!(
            validate_directory(directory.path(), geteuid().as_raw(), getegid().as_raw(),).is_err()
        );
    }

    #[test]
    fn service_group_must_match_the_agent_group_without_chown_capability() {
        let agent_gid = getegid().as_raw();
        validate_service_group(agent_gid, agent_gid).expect("matching service group");
        assert!(validate_service_group(agent_gid.wrapping_add(1), agent_gid).is_err());
    }

    #[test]
    fn token_creation_restores_exact_mode_without_chown() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.cleanup-token");
        write_token(&path, &[7; 32], geteuid(), getegid()).expect("token");
        let metadata = fs::symlink_metadata(path).expect("metadata");
        assert_eq!(metadata.uid(), geteuid().as_raw());
        assert_eq!(metadata.gid(), getegid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o640);
    }

    #[test]
    fn stale_cleanup_refuses_regular_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.sock");
        File::create(&path).expect("file");
        assert!(remove_stale_socket(&path, getegid().as_raw()).is_err());
        assert!(path.exists());
    }
}
