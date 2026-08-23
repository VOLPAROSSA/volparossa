use std::{fs, io, os::unix::fs::MetadataExt};

use volparossa_test_support::NamespaceIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceSnapshot {
    pub(crate) network: NamespaceIdentity,
    pub(crate) mount: NamespaceIdentity,
    pub(crate) pid: NamespaceIdentity,
}

impl NamespaceSnapshot {
    pub(crate) fn capture() -> io::Result<Self> {
        Ok(Self {
            network: identity("/proc/self/ns/net")?,
            mount: identity("/proc/self/ns/mnt")?,
            pid: identity("/proc/self/ns/pid")?,
        })
    }
}

fn identity(path: &str) -> io::Result<NamespaceIdentity> {
    let metadata = fs::metadata(path)?;
    NamespaceIdentity::new(metadata.dev(), metadata.ino())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reads_three_stable_nonzero_namespace_identities() {
        let first = NamespaceSnapshot::capture().expect("first namespace snapshot");
        let second = NamespaceSnapshot::capture().expect("second namespace snapshot");
        assert_eq!(first, second);
        assert_ne!(first.network, first.mount);
        assert_ne!(first.network, first.pid);
        assert_ne!(first.mount, first.pid);
    }
}
