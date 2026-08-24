use std::{io, os::fd::OwnedFd};

use rustix::{
    fd::AsFd,
    fs::{FileType, Mode, OFlags, fstat, open, openat},
};
use volparossa_test_support::NamespaceIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceSnapshot {
    pub(crate) user: NamespaceIdentity,
    pub(crate) network: NamespaceIdentity,
    pub(crate) mount: NamespaceIdentity,
    pub(crate) pid: NamespaceIdentity,
    pub(crate) pid_for_children: NamespaceIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LauncherNamespaceMembership {
    pub(crate) user: NamespaceIdentity,
    pub(crate) network: NamespaceIdentity,
    pub(crate) mount: NamespaceIdentity,
    pub(crate) pid: NamespaceIdentity,
}

impl NamespaceSnapshot {
    pub(crate) fn capture() -> io::Result<Self> {
        Self::capture_at("/proc/thread-self/ns")
    }

    fn capture_at(namespace_directory: &str) -> io::Result<Self> {
        Ok(Self {
            user: open_identity(&format!("{namespace_directory}/user"))?,
            network: open_identity(&format!("{namespace_directory}/net"))?,
            mount: open_identity(&format!("{namespace_directory}/mnt"))?,
            pid: open_identity(&format!("{namespace_directory}/pid"))?,
            pid_for_children: open_identity(&format!("{namespace_directory}/pid_for_children"))?,
        })
    }

    pub(crate) fn is_isolated_launcher_from(self, host: Self) -> bool {
        host.pid == host.pid_for_children
            && self.user != host.user
            && self.network != host.network
            && self.mount != host.mount
            && self.pid == host.pid
            && self.pid_for_children != host.pid_for_children
            && self.pid_for_children != self.pid
    }

    pub(crate) fn is_pid_one_child_of(self, launcher: Self) -> bool {
        launcher.pid != launcher.pid_for_children
            && self.user == launcher.user
            && self.network == launcher.network
            && self.mount == launcher.mount
            && self.pid == launcher.pid_for_children
            && self.pid_for_children == self.pid
    }

    pub(crate) fn capture_launcher_membership() -> io::Result<LauncherNamespaceMembership> {
        LauncherNamespaceMembership::capture_launcher_membership()
    }

    /// Observe whether a pending PID namespace has acquired its init process.
    ///
    /// Linux deliberately leaves `pid_for_children` unopenable after
    /// `unshare(CLONE_NEWPID)` until the first child is created. The caller
    /// captures the complete identity only after that exact child exists.
    pub(crate) fn pending_pid_namespace_identity() -> io::Result<Option<NamespaceIdentity>> {
        LauncherNamespaceMembership::pending_pid_namespace_identity()
    }
}

impl LauncherNamespaceMembership {
    pub(crate) fn capture_launcher_membership() -> io::Result<Self> {
        let namespace_directory = "/proc/thread-self/ns";
        Ok(Self {
            user: open_identity(&format!("{namespace_directory}/user"))?,
            network: open_identity(&format!("{namespace_directory}/net"))?,
            mount: open_identity(&format!("{namespace_directory}/mnt"))?,
            pid: open_identity(&format!("{namespace_directory}/pid"))?,
        })
    }

    /// Observe the selected child PID namespace without treating an arbitrary
    /// missing proc record as an environmental policy outcome.
    ///
    /// Linux leaves the `pid_for_children` magic link unresolved between
    /// `unshare(CLONE_NEWPID)` and creation of the namespace init. An `ENOENT`
    /// result is accepted only after an `O_PATH|O_NOFOLLOW` descriptor proves
    /// that the exact proc magic-link entry itself exists and is a symlink.
    pub(crate) fn pending_pid_namespace_identity() -> io::Result<Option<NamespaceIdentity>> {
        match open_identity("/proc/thread-self/ns/pid_for_children") {
            Ok(identity) => Ok(Some(identity)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let process_directory = open(
                    "/proc/thread-self",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(rustix_io)?;
                let _ = pin_unresolved_pid_for_children(&process_directory)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn is_isolated_launcher_from(self, host: NamespaceSnapshot) -> bool {
        host.pid == host.pid_for_children
            && self.user != host.user
            && self.network != host.network
            && self.mount != host.mount
            && self.pid == host.pid
    }

    pub(crate) fn matches_membership(self, other: Self) -> bool {
        self == other
    }

    pub(crate) fn matches_snapshot(self, snapshot: NamespaceSnapshot) -> bool {
        self.user == snapshot.user
            && self.network == snapshot.network
            && self.mount == snapshot.mount
            && self.pid == snapshot.pid
    }
}

/// Stable pre-child pins for the launcher's namespaces and unresolved child-PID link.
///
/// The pending child PID namespace cannot itself be opened before its namespace
/// init exists. Retaining the proc magic-link descriptor closes the distinction
/// between an intentionally unresolved target and a missing/substituted proc
/// entry while the four already-resolvable namespace descriptors remain pinned.
pub(crate) struct LauncherNamespacePins {
    user: OwnedFd,
    network: OwnedFd,
    mount: OwnedFd,
    pid: OwnedFd,
    pending_pid_for_children_link: OwnedFd,
    membership: LauncherNamespaceMembership,
    pending_link_device: u64,
    pending_link_inode: u64,
}

impl LauncherNamespacePins {
    pub(crate) fn pin_process<Fd: AsFd>(process_directory: Fd) -> io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC;
        let user = open_namespace(&process_directory, "ns/user", flags)?;
        let network = open_namespace(&process_directory, "ns/net", flags)?;
        let mount = open_namespace(&process_directory, "ns/mnt", flags)?;
        let pid = open_namespace(&process_directory, "ns/pid", flags)?;
        let pending_pid_for_children_link = pin_unresolved_pid_for_children(&process_directory)?;
        let pending_link_metadata = fstat(&pending_pid_for_children_link).map_err(rustix_io)?;
        let membership = LauncherNamespaceMembership {
            user: file_identity(&user)?,
            network: file_identity(&network)?,
            mount: file_identity(&mount)?,
            pid: file_identity(&pid)?,
        };
        Ok(Self {
            user,
            network,
            mount,
            pid,
            pending_pid_for_children_link,
            membership,
            pending_link_device: pending_link_metadata.st_dev,
            pending_link_inode: pending_link_metadata.st_ino,
        })
    }

    pub(crate) const fn membership(&self) -> LauncherNamespaceMembership {
        self.membership
    }

    pub(crate) fn still_matches(&self) -> io::Result<bool> {
        let pending_link_metadata =
            fstat(&self.pending_pid_for_children_link).map_err(rustix_io)?;
        Ok(LauncherNamespaceMembership {
            user: file_identity(&self.user)?,
            network: file_identity(&self.network)?,
            mount: file_identity(&self.mount)?,
            pid: file_identity(&self.pid)?,
        } == self.membership
            && FileType::from_raw_mode(pending_link_metadata.st_mode).is_symlink()
            && pending_link_metadata.st_dev == self.pending_link_device
            && pending_link_metadata.st_ino == self.pending_link_inode)
    }

    pub(crate) fn matches_process_membership<Fd: AsFd>(
        &self,
        process_directory: Fd,
    ) -> io::Result<bool> {
        let current = Self::pin_process(process_directory)?;
        Ok(self.still_matches()?
            && current.still_matches()?
            && self.membership.matches_membership(current.membership)
            && self.pending_link_device == current.pending_link_device
            && self.pending_link_inode == current.pending_link_inode)
    }

    pub(crate) fn matches_resolved_process_membership<Fd: AsFd>(
        &self,
        process_directory: Fd,
        snapshot: NamespaceSnapshot,
    ) -> io::Result<bool> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC;
        let current = LauncherNamespaceMembership {
            user: file_identity(open_namespace(&process_directory, "ns/user", flags)?)?,
            network: file_identity(open_namespace(&process_directory, "ns/net", flags)?)?,
            mount: file_identity(open_namespace(&process_directory, "ns/mnt", flags)?)?,
            pid: file_identity(open_namespace(&process_directory, "ns/pid", flags)?)?,
        };
        let pending_link = pin_pid_for_children_link(&process_directory)?;
        let pending_link_metadata = fstat(pending_link).map_err(rustix_io)?;
        Ok(self.still_matches()?
            && current.matches_membership(self.membership)
            && current.matches_snapshot(snapshot)
            && pending_link_metadata.st_dev == self.pending_link_device
            && pending_link_metadata.st_ino == self.pending_link_inode)
    }
}

pub(crate) struct NamespacePins {
    user: OwnedFd,
    network: OwnedFd,
    mount: OwnedFd,
    pid: OwnedFd,
    pid_for_children: OwnedFd,
    snapshot: NamespaceSnapshot,
}

impl NamespacePins {
    pub(crate) fn pin_process<Fd: AsFd>(process_directory: Fd) -> io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC;
        let user = open_namespace(&process_directory, "ns/user", flags)?;
        let network = open_namespace(&process_directory, "ns/net", flags)?;
        let mount = open_namespace(&process_directory, "ns/mnt", flags)?;
        let pid = open_namespace(&process_directory, "ns/pid", flags)?;
        let pid_for_children = open_namespace(&process_directory, "ns/pid_for_children", flags)?;
        let snapshot = NamespaceSnapshot {
            user: file_identity(&user)?,
            network: file_identity(&network)?,
            mount: file_identity(&mount)?,
            pid: file_identity(&pid)?,
            pid_for_children: file_identity(&pid_for_children)?,
        };
        Ok(Self {
            user,
            network,
            mount,
            pid,
            pid_for_children,
            snapshot,
        })
    }

    pub(crate) const fn snapshot(&self) -> NamespaceSnapshot {
        self.snapshot
    }

    pub(crate) fn still_matches(&self) -> io::Result<bool> {
        Ok(NamespaceSnapshot {
            user: file_identity(&self.user)?,
            network: file_identity(&self.network)?,
            mount: file_identity(&self.mount)?,
            pid: file_identity(&self.pid)?,
            pid_for_children: file_identity(&self.pid_for_children)?,
        } == self.snapshot)
    }

    pub(crate) fn matches_process_membership<Fd: AsFd>(
        &self,
        process_directory: Fd,
    ) -> io::Result<bool> {
        let current = Self::pin_process(process_directory)?;
        Ok(self.still_matches()? && current.still_matches()? && current.snapshot == self.snapshot)
    }
}

fn open_namespace<Fd: AsFd>(
    process_directory: Fd,
    name: &'static str,
    flags: OFlags,
) -> io::Result<OwnedFd> {
    openat(process_directory, name, flags, Mode::empty())
        .map_err(rustix_io)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to pin process {name}: {error}"),
            )
        })
}

fn pin_unresolved_pid_for_children<Fd: AsFd>(process_directory: Fd) -> io::Result<OwnedFd> {
    const NAME: &str = "ns/pid_for_children";
    let link = pin_pid_for_children_link(&process_directory)?;
    match openat(
        process_directory,
        NAME,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(link),
        Err(error) => Err(io::Error::new(
            io::Error::from_raw_os_error(error.raw_os_error()).kind(),
            format!("failed to resolve process {NAME}: {error}"),
        )),
        Ok(_) => Err(invalid_data(
            "process pid_for_children became resolvable before PID one existed",
        )),
    }
}

fn pin_pid_for_children_link<Fd: AsFd>(process_directory: Fd) -> io::Result<OwnedFd> {
    const NAME: &str = "ns/pid_for_children";
    let link = openat(
        &process_directory,
        NAME,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to pin unresolved process {NAME} link: {error}"),
        )
    })?;
    let metadata = fstat(&link).map_err(rustix_io)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_symlink() {
        return Err(invalid_data(
            "process pid_for_children proc entry is not a magic link",
        ));
    }
    Ok(link)
}

fn open_identity(path: &str) -> io::Result<NamespaceIdentity> {
    let descriptor = open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(rustix_io)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to open namespace identity {path}: {error}"),
            )
        })?;
    file_identity(&descriptor)
}

fn file_identity<Fd: AsFd>(file: Fd) -> io::Result<NamespaceIdentity> {
    let metadata = fstat(file).map_err(rustix_io)?;
    NamespaceIdentity::new(metadata.st_dev, metadata.st_ino)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    fn identity(value: u64) -> NamespaceIdentity {
        NamespaceIdentity::new(value, value).expect("nonzero namespace identity")
    }

    fn host_snapshot() -> NamespaceSnapshot {
        NamespaceSnapshot {
            user: identity(1),
            network: identity(2),
            mount: identity(3),
            pid: identity(4),
            pid_for_children: identity(4),
        }
    }

    #[test]
    fn snapshot_reads_stable_typed_namespace_identities() {
        let first = NamespaceSnapshot::capture().expect("first namespace snapshot");
        let second = NamespaceSnapshot::capture().expect("second namespace snapshot");
        assert_eq!(first, second);
        assert_eq!(first.pid, first.pid_for_children);
        assert_ne!(first.user, first.network);
        assert_ne!(first.network, first.mount);
        assert_ne!(first.network, first.pid);
        assert_ne!(first.mount, first.pid);
    }

    #[test]
    fn pinned_current_process_namespaces_remain_stable() {
        let process_directory = open(
            format!("/proc/{}", std::process::id()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("process directory");
        let pins = NamespacePins::pin_process(&process_directory).expect("namespace pins");
        assert_eq!(
            pins.snapshot(),
            NamespaceSnapshot::capture().expect("snapshot")
        );
        assert!(pins.still_matches().expect("stable pins"));
        assert!(
            pins.matches_process_membership(&process_directory)
                .expect("current process membership")
        );
    }

    #[test]
    fn process_membership_reopens_the_live_proc_namespace_links() {
        let process_directory = open(
            format!("/proc/{}", std::process::id()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("process directory");
        let mut pins = NamespacePins::pin_process(&process_directory).expect("namespace pins");
        pins.snapshot.network = pins.snapshot.mount;
        assert!(
            !pins
                .matches_process_membership(&process_directory)
                .expect("mismatched process membership")
        );
    }

    #[test]
    fn launcher_identity_requires_user_mount_network_and_pending_pid_isolation() {
        let host = host_snapshot();
        let isolated = NamespaceSnapshot {
            user: identity(5),
            network: identity(6),
            mount: identity(7),
            pid: host.pid,
            pid_for_children: identity(8),
        };
        assert!(isolated.is_isolated_launcher_from(host));

        for rejected in [
            NamespaceSnapshot {
                user: host.user,
                ..isolated
            },
            NamespaceSnapshot {
                network: host.network,
                ..isolated
            },
            NamespaceSnapshot {
                mount: host.mount,
                ..isolated
            },
            NamespaceSnapshot {
                pid: identity(9),
                ..isolated
            },
            NamespaceSnapshot {
                pid_for_children: host.pid_for_children,
                ..isolated
            },
            NamespaceSnapshot {
                pid_for_children: isolated.pid,
                ..isolated
            },
        ] {
            assert!(!rejected.is_isolated_launcher_from(host));
        }

        let inconsistent_host = NamespaceSnapshot {
            pid_for_children: identity(9),
            ..host
        };
        assert!(!isolated.is_isolated_launcher_from(inconsistent_host));
    }

    #[test]
    fn pre_mapping_membership_must_match_the_later_pinned_snapshot() {
        let host = host_snapshot();
        let membership = LauncherNamespaceMembership {
            user: identity(5),
            network: identity(6),
            mount: identity(7),
            pid: host.pid,
        };
        let snapshot = NamespaceSnapshot {
            user: membership.user,
            network: membership.network,
            mount: membership.mount,
            pid: membership.pid,
            pid_for_children: identity(8),
        };
        assert!(membership.is_isolated_launcher_from(host));
        assert!(membership.matches_snapshot(snapshot));
        assert!(membership.matches_membership(membership));
        assert!(!membership.is_isolated_launcher_from(NamespaceSnapshot {
            pid_for_children: identity(9),
            ..host
        }));
        assert!(
            !LauncherNamespaceMembership {
                network: identity(8),
                ..membership
            }
            .matches_snapshot(snapshot)
        );
    }

    #[test]
    fn unresolved_pid_for_children_requires_an_existing_symlink_and_exact_enoent_target() {
        let directory = tempdir().expect("temporary proc fixture");
        let namespace_directory = directory.path().join("ns");
        fs::create_dir(&namespace_directory).expect("namespace fixture directory");
        let link = namespace_directory.join("pid_for_children");
        symlink("missing-namespace-target", &link).expect("unresolved namespace link");
        let process_directory = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("process fixture directory");

        let pinned = pin_unresolved_pid_for_children(&process_directory)
            .expect("existing unresolved symlink");
        assert!(
            FileType::from_raw_mode(fstat(&pinned).expect("link metadata").st_mode).is_symlink()
        );

        fs::remove_file(&link).expect("remove unresolved link");
        assert_eq!(
            pin_unresolved_pid_for_children(&process_directory)
                .expect_err("missing proc entry must not alias unresolved magic link")
                .kind(),
            io::ErrorKind::NotFound
        );

        fs::write(namespace_directory.join("target"), b"namespace").expect("namespace target");
        symlink("target", &link).expect("resolved namespace link");
        assert_eq!(
            pin_unresolved_pid_for_children(&process_directory)
                .expect_err("resolved link must not be accepted before PID one")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn pid_one_relation_requires_exact_inheritance_and_pending_pid_membership() {
        let launcher = NamespaceSnapshot {
            user: identity(5),
            network: identity(6),
            mount: identity(7),
            pid: identity(4),
            pid_for_children: identity(8),
        };
        let pid_one = NamespaceSnapshot {
            user: launcher.user,
            network: launcher.network,
            mount: launcher.mount,
            pid: launcher.pid_for_children,
            pid_for_children: launcher.pid_for_children,
        };
        assert!(pid_one.is_pid_one_child_of(launcher));

        for rejected in [
            NamespaceSnapshot {
                user: identity(9),
                ..pid_one
            },
            NamespaceSnapshot {
                network: identity(9),
                ..pid_one
            },
            NamespaceSnapshot {
                mount: identity(9),
                ..pid_one
            },
            NamespaceSnapshot {
                pid: identity(9),
                ..pid_one
            },
            NamespaceSnapshot {
                pid_for_children: identity(9),
                ..pid_one
            },
        ] {
            assert!(!rejected.is_pid_one_child_of(launcher));
        }

        let launcher_without_pending_pid_namespace = NamespaceSnapshot {
            pid_for_children: launcher.pid,
            ..launcher
        };
        assert!(!pid_one.is_pid_one_child_of(launcher_without_pending_pid_namespace));
    }
}
