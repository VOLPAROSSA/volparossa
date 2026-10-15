//! Best-effort cache advice for one owner-authorized, unchanged native GGUF.
//! This is not memory admission, guaranteed reclaim, or evidence of a cache cause.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::Result;
use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};
use serde_json::{Value, json};

use super::super::{ModelProfile, private_directory, resources, spare_capacity::memory};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn read(info: &Metadata) -> Self {
        Self {
            device: info.dev(),
            inode: info.ino(),
            owner: info.uid(),
            links: info.nlink(),
            mode: info.mode(),
            bytes: info.len(),
            modified: (info.mtime(), info.mtime_nsec()),
            changed: (info.ctime(), info.ctime_nsec()),
        }
    }

    fn valid(self, expected_bytes: u64) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
            && self.owner == nix::unistd::geteuid().as_raw()
            && self.links == 1
            && self.mode.trailing_zeros() >= 6
            && self.bytes == expected_bytes
            && (1..=9 * 1024 * 1024 * 1024).contains(&self.bytes)
    }
}

pub(in crate::compute) struct CacheHint {
    file: File,
    root: PathBuf,
    root_identity: (u64, u64),
    identity: Identity,
}

pub(in crate::compute) struct Binding {
    pub(super) hint: Option<CacheHint>,
    pub(super) reason: &'static str,
}

impl Binding {
    pub(super) fn unavailable(reason: &'static str) -> Self {
        Self { hint: None, reason }
    }

    pub(in crate::compute) fn after_supervisor<T>(
        self,
        result: &Result<T>,
        profile: ModelProfile,
        diagnostic: bool,
    ) {
        let observe = diagnostic && memory::enabled();
        let record = self.observe_with(result, profile, observe, memory::sample, |file, bytes| {
            posix_fadvise(file, 0, bytes, PosixFadviseAdvice::POSIX_FADV_DONTNEED)
        });
        if observe {
            memory::emit(&record);
        }
    }

    fn observe_with<T>(
        self,
        result: &Result<T>,
        profile: ModelProfile,
        observe: bool,
        mut sample: impl FnMut(bool) -> memory::Sample,
        advise: impl FnOnce(&File, libc::off_t) -> nix::Result<()>,
    ) -> Value {
        let mut record = json!({"version":1,"phase":"cache_hint","binding":self.reason,
            "outcome":"supervisor_error","supervisor_ok":result.is_ok(),
            "before":null,"after":null,"syscall_error":null});
        if result.is_err() {
            return record;
        }
        let Some(hint) = self.hint else {
            record["outcome"] = json!("not_bound");
            return record;
        };
        let before = sample(observe);
        if observe {
            record["before"] = before.snapshot();
        }
        let outcome = if before.headroom.is_none() {
            "headroom_unknown"
        } else if !needs_hint(profile, before.headroom) {
            "headroom_sufficient"
        } else if !hint.unchanged() {
            "identity_changed"
        } else if let Ok(bytes) = libc::off_t::try_from(hint.identity.bytes) {
            // Preserve one synchronous, unchanged-file advice call under the lease.
            // The following observation is not proof that this hint freed memory.
            let syscall = advise(&hint.file, bytes);
            if observe {
                record["after"] = sample(true).snapshot();
            }
            if let Err(error) = syscall {
                record["syscall_error"] = json!(match error {
                    nix::errno::Errno::EBADF => "bad_fd",
                    nix::errno::Errno::EINVAL => "invalid",
                    nix::errno::Errno::ENOSYS | nix::errno::Errno::EOPNOTSUPP => "unsupported",
                    nix::errno::Errno::EINTR => "interrupted",
                    _ => "other",
                });
                "error"
            } else {
                "advised"
            }
        } else {
            "range_invalid"
        };
        record["outcome"] = json!(outcome);
        record
    }
}

impl CacheHint {
    // Called only from a request already bound to the owner's manifest digest.
    #[cfg(test)]
    pub(super) fn bind(root: &Path, expected_bytes: u64) -> Option<Self> {
        Self::bind_observed(root, expected_bytes).ok()
    }

    pub(super) fn bind_observed(
        root: &Path,
        expected_bytes: u64,
    ) -> std::result::Result<Self, &'static str> {
        private_directory(root).map_err(|_| "root_invalid")?;
        let directory = fs::symlink_metadata(root).map_err(|_| "root_invalid")?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(root.join("model.gguf"))
            .map_err(|_| "open_failed")?;
        let identity = Identity::read(&file.metadata().map_err(|_| "file_invalid")?);
        if !identity.valid(expected_bytes) {
            return Err("file_invalid");
        }
        let hint = Self {
            file,
            root: root.to_owned(),
            root_identity: (directory.dev(), directory.ino()),
            identity,
        };
        if hint.unchanged() {
            Ok(hint)
        } else {
            Err("path_changed")
        }
    }

    fn unchanged(&self) -> bool {
        let check = || -> Option<bool> {
            private_directory(&self.root).ok()?;
            let directory = fs::symlink_metadata(&self.root).ok()?;
            let descriptor = Identity::read(&self.file.metadata().ok()?);
            let path = Identity::read(&fs::symlink_metadata(self.root.join("model.gguf")).ok()?);
            Some(
                (directory.dev(), directory.ino()) == self.root_identity
                    && descriptor.valid(self.identity.bytes)
                    && descriptor == self.identity
                    && path == self.identity,
            )
        };
        check() == Some(true)
    }

    #[cfg(test)]
    fn after_supervisor_with<T>(
        self,
        result: &Result<T>,
        profile: ModelProfile,
        headroom: impl FnOnce() -> Option<u64>,
        advise: impl FnOnce(&File, libc::off_t) -> nix::Result<()>,
    ) {
        let mut headroom = Some(headroom);
        Binding {
            hint: Some(self),
            reason: "bound",
        }
        .observe_with(
            result,
            profile,
            false,
            |_| memory::Sample::for_test(headroom.take().expect("one sample")()),
            advise,
        );
    }
}

fn needs_hint(profile: ModelProfile, headroom: Option<u64>) -> bool {
    profile == ModelProfile::Qwen4bInstruct2507
        && headroom.is_some_and(|available| {
            resources::limits(profile)
                .admission_headroom
                .is_some_and(|required| available < required)
        })
}

#[cfg(test)]
mod tests;
