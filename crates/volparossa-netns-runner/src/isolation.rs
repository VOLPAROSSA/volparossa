use std::{fs, io};

use nix::{
    errno::Errno,
    sched::{CloneFlags, unshare},
    unistd::{getresgid, getresuid},
};

use crate::{
    evidence::verify_current_single_extent_mappings,
    namespace::{LauncherNamespaceMembership, NamespaceSnapshot},
};

pub(crate) enum IsolationAttempt {
    Created(LauncherIsolation),
    Unavailable,
}

pub(crate) struct LauncherIsolation {
    outer_user_id: u32,
    outer_group_id: u32,
    membership: LauncherNamespaceMembership,
}

impl LauncherIsolation {
    pub(crate) fn verify_installed_mappings(&self) -> io::Result<()> {
        verify_current_single_extent_mappings(self.outer_user_id, self.outer_group_id)?;
        let user_ids = getresuid().map_err(errno_io)?;
        let group_ids = getresgid().map_err(errno_io)?;
        if user_ids.real.as_raw() != 0
            || user_ids.effective.as_raw() != 0
            || user_ids.saved.as_raw() != 0
            || group_ids.real.as_raw() != 0
            || group_ids.effective.as_raw() != 0
            || group_ids.saved.as_raw() != 0
            || !has_exact_single_task()?
        {
            return Err(invalid_data(
                "launcher credentials or namespace identity changed after mapping",
            ));
        }
        let membership = NamespaceSnapshot::capture_launcher_membership()?;
        let pending_pid_namespace = NamespaceSnapshot::pending_pid_namespace_identity()?;
        if !self.membership.matches_membership(membership) || pending_pid_namespace.is_some() {
            return Err(invalid_data(
                "launcher namespace identity changed after mapping",
            ));
        }
        Ok(())
    }

    pub(crate) const fn outer_user_id(&self) -> u32 {
        self.outer_user_id
    }

    pub(crate) const fn outer_group_id(&self) -> u32 {
        self.outer_group_id
    }
}

pub(crate) fn create_launcher_namespaces() -> io::Result<IsolationAttempt> {
    let before = NamespaceSnapshot::capture()?;
    let user_ids = getresuid().map_err(errno_io)?;
    let group_ids = getresgid().map_err(errno_io)?;
    if user_ids.real != user_ids.effective
        || user_ids.real != user_ids.saved
        || group_ids.real != group_ids.effective
        || group_ids.real != group_ids.saved
        || !has_exact_single_task()?
    {
        return Err(invalid_data(
            "launcher must have one task and non-setid credentials",
        ));
    }
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWPID;
    if let Err(error) = unshare(flags) {
        return if is_namespace_unavailable(error) {
            Ok(IsolationAttempt::Unavailable)
        } else {
            Err(errno_io(error))
        };
    }
    let membership = match NamespaceSnapshot::capture_launcher_membership() {
        Ok(membership) => membership,
        Err(error) if is_proof_unavailable(&error) => return Ok(IsolationAttempt::Unavailable),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("post-unshare namespace capture failed: {error}"),
            ));
        }
    };
    let pending_pid_namespace = match NamespaceSnapshot::pending_pid_namespace_identity() {
        Ok(identity) => identity,
        Err(error) if is_proof_unavailable(&error) => return Ok(IsolationAttempt::Unavailable),
        Err(error) => return Err(error),
    };
    let single_task = match has_exact_single_task() {
        Ok(single_task) => single_task,
        Err(error) if is_proof_unavailable(&error) => return Ok(IsolationAttempt::Unavailable),
        Err(error) => return Err(error),
    };
    if !membership.is_isolated_launcher_from(before)
        || pending_pid_namespace.is_some()
        || !single_task
    {
        return Err(invalid_data(
            "kernel did not establish the fixed launcher namespaces",
        ));
    }
    Ok(IsolationAttempt::Created(LauncherIsolation {
        outer_user_id: user_ids.effective.as_raw(),
        outer_group_id: group_ids.effective.as_raw(),
        membership,
    }))
}

pub(crate) fn has_exact_single_task() -> io::Result<bool> {
    let mut entries = fs::read_dir("/proc/self/task")?;
    let Some(entry) = entries.next() else {
        return Ok(false);
    };
    let _ = entry?;
    Ok(entries.next().is_none())
}

const fn is_namespace_unavailable(error: Errno) -> bool {
    matches!(
        error,
        Errno::EPERM | Errno::EACCES | Errno::ENOSPC | Errno::EUSERS | Errno::EINVAL
    )
}

fn is_proof_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn errno_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fixed_kernel_capability_errors_are_classified_as_unavailable() {
        for error in [
            Errno::EPERM,
            Errno::EACCES,
            Errno::ENOSPC,
            Errno::EUSERS,
            Errno::EINVAL,
        ] {
            assert!(is_namespace_unavailable(error));
        }
        for error in [Errno::EIO, Errno::EBADF, Errno::EFAULT, Errno::ENOMEM] {
            assert!(!is_namespace_unavailable(error));
        }
    }

    #[test]
    fn only_permission_denial_makes_post_unshare_proof_unavailable() {
        assert!(is_proof_unavailable(
            &io::ErrorKind::PermissionDenied.into()
        ));
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::NotFound,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(!is_proof_unavailable(&kind.into()));
        }
    }
}
