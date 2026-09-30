//! Fixed Client-only userspace-PM selection inside an authenticated private worker netns.

use std::io;

use nix::unistd::geteuid;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat2};

use crate::{
    deadline::HardDeadline,
    worker_sandbox::{NetworkNamespaceIdentity, current_network_namespace_identity},
};

/// Called before identity drop and before any transport socket is created. No configurable
/// path/value is accepted, and both the anonymous netns and fixed procfs object are verified.
pub(super) fn enable(
    parent: NetworkNamespaceIdentity,
    worker: NetworkNamespaceIdentity,
    deadline: HardDeadline,
) -> io::Result<()> {
    deadline.ensure_remaining()?;
    let current = current_network_namespace_identity().map_err(|_| invalid())?;
    authenticate(parent, worker, current, geteuid().as_raw())?;
    let root = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let knob = openat2(
        &root,
        "sys/net/mptcp/pm_type",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS,
    )?;
    let root_stat = fstat(&root)?;
    let stat = fstat(&knob)?;
    if i128::from(fstatfs(&root)?.f_type) != 0x9fa0
        || i128::from(fstatfs(&knob)?.f_type) != 0x9fa0
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || stat.st_dev != root_stat.st_dev
    {
        return Err(invalid());
    }
    let mut value = [0_u8; 3];
    let length = rustix::io::pread(&knob, &mut value, 0)?;
    if !matches!(&value[..length], b"0\n" | b"1\n") {
        return Err(invalid());
    }
    deadline.ensure_remaining()?;
    if &value[..length] != b"1\n" && rustix::io::write(&knob, b"1\n")? != 2 {
        return Err(invalid());
    }
    value.fill(0);
    let length = rustix::io::pread(&knob, &mut value, 0)?;
    if &value[..length] != b"1\n" {
        return Err(invalid());
    }
    deadline.ensure_remaining()?;
    authenticate(
        parent,
        worker,
        current_network_namespace_identity().map_err(|_| invalid())?,
        geteuid().as_raw(),
    )
}

fn authenticate(
    parent: NetworkNamespaceIdentity,
    worker: NetworkNamespaceIdentity,
    current: NetworkNamespaceIdentity,
    uid: u32,
) -> io::Result<()> {
    if uid != 0
        || parent == worker
        || worker != current
        || worker.parts().0 == 0
        || worker.parts().1 == 0
        || parent.parts().0 == 0
        || parent.parts().1 == 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::other("Client private MPTCP PM bootstrap unconfirmed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pm_bootstrap_requires_exact_distinct_private_root_namespace() {
        let parent = NetworkNamespaceIdentity::fixture(1, 2);
        let worker = NetworkNamespaceIdentity::fixture(1, 3);
        assert!(authenticate(parent, worker, worker, 0).is_ok());
        assert!(authenticate(parent, parent, parent, 0).is_err());
        assert!(authenticate(parent, worker, parent, 0).is_err());
        assert!(authenticate(parent, worker, worker, 1000).is_err());
    }
}
