use std::{io, os::fd::OwnedFd};

use rustix::{
    fd::AsFd,
    fs::{Mode, OFlags, fstat, open, openat},
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
            && self.pid_for_children == host.pid_for_children
    }

    pub(crate) fn capture_launcher_membership() -> io::Result<LauncherNamespaceMembership> {
        let namespace_directory = "/proc/thread-self/ns";
        Ok(LauncherNamespaceMembership {
            user: open_identity(&format!("{namespace_directory}/user"))?,
            network: open_identity(&format!("{namespace_directory}/net"))?,
            mount: open_identity(&format!("{namespace_directory}/mnt"))?,
            pid: open_identity(&format!("{namespace_directory}/pid"))?,
        })
    }
}

impl LauncherNamespaceMembership {
    pub(crate) fn is_isolated_launcher_from(self, host: NamespaceSnapshot) -> bool {
        self.user != host.user
            && self.network != host.network
            && self.mount != host.mount
            && self.pid == host.pid
    }

    pub(crate) fn matches(self, snapshot: NamespaceSnapshot) -> bool {
        self.user == snapshot.user
            && self.network == snapshot.network
            && self.mount == snapshot.mount
            && self.pid == snapshot.pid
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
                format!("failed to pin launcher {name}: {error}"),
            )
        })
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

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
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
    fn launcher_identity_requires_exactly_user_mount_and_network_isolation() {
        let host = host_snapshot();
        let isolated = NamespaceSnapshot {
            user: identity(5),
            network: identity(6),
            mount: identity(7),
            pid: host.pid,
            pid_for_children: host.pid_for_children,
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
                pid: identity(8),
                ..isolated
            },
            NamespaceSnapshot {
                pid_for_children: identity(8),
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
            pid_for_children: host.pid_for_children,
        };
        assert!(membership.is_isolated_launcher_from(host));
        assert!(membership.matches(snapshot));
        assert!(
            !LauncherNamespaceMembership {
                network: identity(8),
                ..membership
            }
            .matches(snapshot)
        );
    }
}
