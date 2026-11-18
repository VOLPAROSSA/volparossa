//! Advice only for the three fixed source shards read by a successful native worker.
//! Source hashes remain mandatory. File-cache charges are not attributed to these
//! files, and advisory success is neither reclaimed memory nor admission credit.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::Result;
use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};
use serde_json::{Value, json};
use volparossa_content::model_profile::ModelFileSpec;

use super::super::{
    ModelProfile, private_directory, private_task, resources, spare_capacity::memory,
};
use super::{KIND, Options, Request};

const PROFILE: ModelProfile = ModelProfile::Qwen4bInstruct2507;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
            && (1..=4 * 1024 * 1024 * 1024).contains(&self.bytes)
    }
}

struct Shard {
    file: File,
    name: &'static str,
    identity: Identity,
}

impl Shard {
    fn bind(root: &Path, spec: &ModelFileSpec) -> std::result::Result<Self, &'static str> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(root.join(spec.name))
            .map_err(|_| "open_failed")?;
        let identity = Identity::read(&file.metadata().map_err(|_| "file_invalid")?);
        if !identity.valid(spec.bytes) {
            return Err("file_invalid");
        }
        Ok(Self {
            file,
            name: spec.name,
            identity,
        })
    }

    fn unchanged(&self, root: &Path) -> bool {
        let check = || -> Option<bool> {
            let descriptor = Identity::read(&self.file.metadata().ok()?);
            let path = Identity::read(&fs::symlink_metadata(root.join(self.name)).ok()?);
            Some(descriptor == self.identity && path == self.identity)
        };
        check() == Some(true)
    }
}

struct Hints {
    root: PathBuf,
    root_identity: (u64, u64),
    shards: [Shard; 3],
}

impl Hints {
    // Production callers pass only PROFILE.sharded_weight_files()[1..]. There is
    // no user filename, remote index, glob, recursive traversal or content read.
    fn bind(root: &Path, specs: &[ModelFileSpec; 3]) -> std::result::Result<Self, &'static str> {
        private_directory(root).map_err(|_| "root_invalid")?;
        let directory = fs::symlink_metadata(root).map_err(|_| "root_invalid")?;
        let hints = Self {
            root: root.to_owned(),
            root_identity: (directory.dev(), directory.ino()),
            shards: [
                Shard::bind(root, &specs[0])?,
                Shard::bind(root, &specs[1])?,
                Shard::bind(root, &specs[2])?,
            ],
        };
        if hints.parent_unchanged() && hints.shards.iter().all(|shard| shard.unchanged(root)) {
            Ok(hints)
        } else {
            Err("path_changed")
        }
    }

    fn parent_unchanged(&self) -> bool {
        private_directory(&self.root).is_ok()
            && fs::symlink_metadata(&self.root)
                .is_ok_and(|info| (info.dev(), info.ino()) == self.root_identity)
    }
}

pub(in crate::compute) struct Binding {
    hints: Option<Hints>,
    reason: &'static str,
}

impl Binding {
    pub(in crate::compute) fn bind(
        request: &Request,
        options: &Options,
        profile: ModelProfile,
        model_root: &Path,
    ) -> Self {
        let unavailable = |reason| Self {
            hints: None,
            reason,
        };
        if profile != PROFILE
            || request.inference_backend != Some(KIND)
            || request.native_backend_sha256 != options.native_backend_sha256
            || options.native_backend_root.is_none()
            || request.expected_report.is_none()
        {
            return unavailable("not_applicable");
        }
        let Some([_, first, second, third]) = PROFILE.sharded_weight_files() else {
            return unavailable("not_applicable");
        };
        match Hints::bind(model_root, &[*first, *second, *third]) {
            Ok(hints) => Self {
                hints: Some(hints),
                reason: "bound",
            },
            Err(reason) => unavailable(reason),
        }
    }

    pub(in crate::compute) fn after_supervisor(self, result: &Result<Value>, diagnostic: bool) {
        // Separate opt-in: the existing memory diagnostic target/marker/schema
        // remains unchanged and old collectors ignore this new marker entirely.
        let observe = diagnostic
            && tracing::enabled!(target: "volparossa::compute::private_source_weight_cache_diagnostic", tracing::Level::DEBUG);
        let record = self.observe_with(result, observe, memory::sample, |file, bytes| {
            posix_fadvise(file, 0, bytes, PosixFadviseAdvice::POSIX_FADV_DONTNEED)
        });
        if observe {
            tracing::debug!(target: "volparossa::compute::private_source_weight_cache_diagnostic",
                "private_source_weight_cache_diagnostic {record}");
        }
    }

    fn observe_with(
        self,
        result: &Result<Value>,
        observe: bool,
        mut sample: impl FnMut(bool) -> memory::Sample,
        mut advise: impl FnMut(&File, libc::off_t) -> nix::Result<()>,
    ) -> Value {
        let mut record = json!({"version":1,"phase":"source_weights","binding":self.reason,
            "outcome":"supervisor_error","supervisor_ok":result.is_ok(),
            "before":null,"after":null,"shards":[]});
        let Ok(result) = result else { return record };
        let Some(hints) = self.hints else {
            record["outcome"] = json!("not_bound");
            return record;
        };
        // The real caller has already validated this after joining every worker
        // lifetime. Retain an explicit closed provenance gate at the advice edge.
        if private_task::validate_model_weights(&result["model"], PROFILE).is_err() {
            record["outcome"] = json!("provenance_unconfirmed");
            return record;
        }
        let before = sample(observe);
        if observe {
            record["before"] = before.snapshot();
        }
        let Some(headroom) = before.headroom else {
            record["outcome"] = json!("headroom_unknown");
            return record;
        };
        if resources::admits(PROFILE, Some(headroom)) {
            record["outcome"] = json!("headroom_sufficient");
            return record;
        }
        if !hints.parent_unchanged()
            || !hints
                .shards
                .iter()
                .all(|shard| shard.unchanged(&hints.root))
        {
            record["outcome"] = json!("identity_changed");
            return record;
        }
        let mut shards = Vec::with_capacity(3);
        for (index, shard) in hints.shards.iter().enumerate() {
            let mut item =
                json!({"ordinal":index+1,"outcome":"identity_changed","syscall_error":null});
            if hints.parent_unchanged() && shard.unchanged(&hints.root) {
                if let Ok(bytes) = libc::off_t::try_from(shard.identity.bytes) {
                    match advise(&shard.file, bytes) {
                        Ok(()) => item["outcome"] = json!("advised"),
                        Err(error) => {
                            item["outcome"] = json!("error");
                            item["syscall_error"] = json!(syscall_kind(error));
                        }
                    }
                } else {
                    item["outcome"] = json!("range_invalid");
                }
            }
            shards.push(item);
        }
        record["outcome"] = json!("shards_checked");
        record["shards"] = json!(shards);
        if observe {
            // One sequential observation, never an admission or reclaim proof.
            record["after"] = sample(true).snapshot();
        }
        record
    }
}

fn syscall_kind(error: nix::errno::Errno) -> &'static str {
    match error {
        nix::errno::Errno::EBADF => "bad_fd",
        nix::errno::Errno::EINVAL => "invalid",
        nix::errno::Errno::ENOSYS | nix::errno::Errno::EOPNOTSUPP => "unsupported",
        nix::errno::Errno::EINTR => "interrupted",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
