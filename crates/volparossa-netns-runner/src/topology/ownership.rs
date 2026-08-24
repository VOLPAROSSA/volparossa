use std::{
    fs::File,
    io,
    marker::PhantomData,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd},
    rc::Rc,
};

use nix::unistd::{getegid, geteuid};
use rustix::{
    fd::OwnedFd,
    fs::{
        AtFlags, FileType, Mode, OFlags, RawDir, ResolveFlags, Stat, Statx, StatxFlags, fchmod,
        fstat, fsync, inotify, makedev, mkdirat, openat2, statat, statx, unlinkat,
    },
    io::Errno,
};
use thiserror::Error;
use volparossa_test_support::{MutationAuthorization, RunId};

const NETNS_ROOT_LEAF: &str = "netns";
const WORKSPACE_ROOT_LEAF: &str = "volparossa-netns-runner";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const EMPTY_SLOT_MODE: u32 = 0o000;
const DIRECTORY_BUFFER_BYTES: usize = 4_096;
const MAX_ROOT_ENTRIES: usize = 2;
const MAX_JOURNAL_ENTRIES: usize = 5;

const IDENTITY_STATX_FLAGS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::NLINK)
    .union(StatxFlags::UID)
    .union(StatxFlags::GID)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MNT_ID);

/// Failure to create, prove, verify, or roll back one authorized private-run layout.
#[derive(Debug, Error)]
pub(crate) enum AuthorizedPrivateRunError {
    /// A descriptor-relative filesystem operation failed.
    #[error("authorized private-run operation {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// An object, exact set, run binding, or rollback proof was ambiguous.
    #[error("authorized private-run proof failed: {0}")]
    Unsafe(&'static str),
}

impl AuthorizedPrivateRunError {
    fn io(operation: &'static str, error: Errno) -> Self {
        Self::Io {
            operation,
            source: io::Error::from_raw_os_error(error.raw_os_error()),
        }
    }

    #[cfg(test)]
    fn from_io_for_test(source: io::Error) -> Self {
        Self::Io {
            operation: "apply injected test mutation",
            source,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    file_type: FileType,
}

impl StableIdentity {
    fn from_observations(
        metadata: &Stat,
        extended: &Statx,
    ) -> Result<Self, AuthorizedPrivateRunError> {
        let mask = StatxFlags::from_bits_retain(extended.stx_mask);
        if !mask.contains(IDENTITY_STATX_FLAGS)
            || extended.stx_mnt_id == 0
            || metadata.st_dev == 0
            || metadata.st_ino == 0
            || makedev(extended.stx_dev_major, extended.stx_dev_minor) != metadata.st_dev
            || extended.stx_ino != metadata.st_ino
            || u32::from(extended.stx_mode) != metadata.st_mode
            || u64::from(extended.stx_nlink) != metadata.st_nlink
            || extended.stx_uid != metadata.st_uid
            || extended.stx_gid != metadata.st_gid
            || extended.stx_size
                != u64::try_from(metadata.st_size)
                    .map_err(|_| AuthorizedPrivateRunError::Unsafe("negative object size"))?
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "stat and statx identity observations differ",
            ));
        }
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mount_id: extended.stx_mnt_id,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            file_type: FileType::from_raw_mode(metadata.st_mode),
        })
    }

    fn permissions(self) -> u32 {
        self.mode & 0o7777
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectSnapshot {
    identity: StableIdentity,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl ObjectSnapshot {
    fn from_observations(
        metadata: &Stat,
        extended: &Statx,
    ) -> Result<Self, AuthorizedPrivateRunError> {
        Ok(Self {
            identity: StableIdentity::from_observations(metadata, extended)?,
            links: metadata.st_nlink,
            size: u64::try_from(metadata.st_size)
                .map_err(|_| AuthorizedPrivateRunError::Unsafe("negative object size"))?,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        })
    }
}

fn descriptor_statx<Fd: AsFd>(descriptor: Fd) -> Result<Statx, AuthorizedPrivateRunError> {
    statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        IDENTITY_STATX_FLAGS,
    )
    .map_err(|error| AuthorizedPrivateRunError::io("measure retained object", error))
}

fn entry_statx<Fd: AsFd>(parent: Fd, name: &str) -> Result<Statx, AuthorizedPrivateRunError> {
    statx(
        parent,
        name,
        AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        IDENTITY_STATX_FLAGS,
    )
    .map_err(|error| AuthorizedPrivateRunError::io("measure retained directory entry", error))
}

fn object_snapshot<Fd: AsFd>(descriptor: Fd) -> Result<ObjectSnapshot, AuthorizedPrivateRunError> {
    let metadata = fstat(&descriptor)
        .map_err(|error| AuthorizedPrivateRunError::io("read retained object metadata", error))?;
    let extended = descriptor_statx(descriptor)?;
    ObjectSnapshot::from_observations(&metadata, &extended)
}

fn entry_snapshot<Fd: AsFd>(
    parent: Fd,
    name: &str,
) -> Result<ObjectSnapshot, AuthorizedPrivateRunError> {
    let metadata = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| AuthorizedPrivateRunError::io("read directory-entry metadata", error))?;
    let extended = entry_statx(parent, name)?;
    ObjectSnapshot::from_observations(&metadata, &extended)
}

#[derive(Clone, Copy)]
struct RunFilesystemIdentity {
    device: u64,
    mount_id: u64,
    uid: u32,
    gid: u32,
}

impl RunFilesystemIdentity {
    fn from_root(root: StableIdentity) -> Result<Self, AuthorizedPrivateRunError> {
        if !root.file_type.is_dir()
            || root.permissions() != PRIVATE_DIRECTORY_MODE
            || root.uid != geteuid().as_raw()
            || root.gid != getegid().as_raw()
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private run root metadata is not exact",
            ));
        }
        Ok(Self {
            device: root.device,
            mount_id: root.mount_id,
            uid: root.uid,
            gid: root.gid,
        })
    }

    fn contains(self, identity: StableIdentity) -> bool {
        identity.device == self.device
            && identity.mount_id == self.mount_id
            && identity.uid == self.uid
            && identity.gid == self.gid
    }
}

struct PinnedDirectory {
    descriptor: File,
    identity: StableIdentity,
    filesystem: RunFilesystemIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

struct ExpectedEntry<'a> {
    name: &'a str,
    descriptor: &'a File,
    identity: StableIdentity,
}

impl PinnedDirectory {
    fn pin_root(run_descriptor: &OwnedFd) -> Result<Self, AuthorizedPrivateRunError> {
        let descriptor = openat2(
            run_descriptor,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|error| AuthorizedPrivateRunError::io("pin private run root", error))?;
        let descriptor = File::from(descriptor);
        let snapshot = object_snapshot(&descriptor)?;
        let filesystem = RunFilesystemIdentity::from_root(snapshot.identity)?;
        let pinned = Self {
            descriptor,
            identity: snapshot.identity,
            filesystem,
            _thread_bound: PhantomData,
        };
        pinned.verify()?;
        Ok(pinned)
    }

    fn from_created(
        descriptor: File,
        identity: StableIdentity,
        filesystem: RunFilesystemIdentity,
    ) -> Result<Self, AuthorizedPrivateRunError> {
        let pinned = Self {
            descriptor,
            identity,
            filesystem,
            _thread_bound: PhantomData,
        };
        pinned.verify()?;
        Ok(pinned)
    }

    fn verify(&self) -> Result<(), AuthorizedPrivateRunError> {
        let current = object_snapshot(&self.descriptor)?.identity;
        if current != self.identity
            || !current.file_type.is_dir()
            || current.permissions() != PRIVATE_DIRECTORY_MODE
            || !self.filesystem.contains(current)
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "retained private directory identity changed",
            ));
        }
        Ok(())
    }

    fn verify_exact_entries(
        &self,
        expected: &[ExpectedEntry<'_>],
    ) -> Result<(), AuthorizedPrivateRunError> {
        self.verify()?;
        if expected.len() > MAX_ROOT_ENTRIES
            || expected.iter().enumerate().any(|(index, entry)| {
                invalid_leaf(entry.name)
                    || expected[index + 1..]
                        .iter()
                        .any(|other| other.name == entry.name || other.identity == entry.identity)
            })
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "invalid expected private-directory set",
            ));
        }
        let before = object_snapshot(&self.descriptor)?;
        for entry in expected {
            verify_expected_entry(&self.descriptor, entry, self.filesystem)?;
        }
        let reopened = openat2(
            &self.descriptor,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|error| AuthorizedPrivateRunError::io("reopen exact-set directory", error))?;
        let mut storage = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut directory = RawDir::new(reopened, &mut storage);
        let mut seen = vec![false; expected.len()];
        let mut count = 0_usize;
        while let Some(entry) = directory.next() {
            let entry = entry
                .map_err(|error| AuthorizedPrivateRunError::io("enumerate exact set", error))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(AuthorizedPrivateRunError::Unsafe(
                    "directory entry count overflowed",
                ))?;
            if count > MAX_ROOT_ENTRIES {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "private directory contains too many entries",
                ));
            }
            let Some(index) = expected
                .iter()
                .position(|candidate| candidate.name.as_bytes() == name)
            else {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "private directory contains a foreign entry",
                ));
            };
            if seen[index] {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "private directory contains a duplicate observation",
                ));
            }
            verify_expected_entry(&self.descriptor, &expected[index], self.filesystem)?;
            seen[index] = true;
        }
        if count != expected.len() || seen.contains(&false) {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private directory exact set is incomplete",
            ));
        }
        for entry in expected {
            verify_expected_entry(&self.descriptor, entry, self.filesystem)?;
        }
        if object_snapshot(&self.descriptor)? != before {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private directory changed during exact-set proof",
            ));
        }
        self.verify()
    }

    fn verify_exact_names(&self, expected: &[&str]) -> Result<(), AuthorizedPrivateRunError> {
        self.verify()?;
        if expected.len() > MAX_ROOT_ENTRIES
            || expected
                .iter()
                .enumerate()
                .any(|(index, name)| invalid_leaf(name) || expected[index + 1..].contains(name))
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "invalid expected private-directory name set",
            ));
        }
        let before = object_snapshot(&self.descriptor)?;
        let reopened = openat2(
            &self.descriptor,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|error| AuthorizedPrivateRunError::io("reopen exact-name directory", error))?;
        let mut storage = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut directory = RawDir::new(reopened, &mut storage);
        let mut seen = vec![false; expected.len()];
        let mut count = 0_usize;
        while let Some(entry) = directory.next() {
            let entry = entry.map_err(|error| {
                AuthorizedPrivateRunError::io("enumerate exact-name set", error)
            })?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(AuthorizedPrivateRunError::Unsafe(
                    "directory entry count overflowed",
                ))?;
            let Some(index) = expected
                .iter()
                .position(|candidate| candidate.as_bytes() == name)
            else {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "private directory contains a foreign name",
                ));
            };
            if seen[index] {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "private directory contains a duplicate name observation",
                ));
            }
            seen[index] = true;
        }
        if count != expected.len() || seen.contains(&false) {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private directory exact-name set is incomplete",
            ));
        }
        if object_snapshot(&self.descriptor)? != before {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private directory changed during exact-name proof",
            ));
        }
        self.verify()
    }
}

fn verify_expected_entry(
    parent: &File,
    expected: &ExpectedEntry<'_>,
    filesystem: RunFilesystemIdentity,
) -> Result<(), AuthorizedPrivateRunError> {
    let held = object_snapshot(expected.descriptor)?;
    let visible = entry_snapshot(parent, expected.name)?;
    if held != visible || held.identity != expected.identity || !filesystem.contains(held.identity)
    {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "retained entry and directory name do not identify the same object",
        ));
    }
    Ok(())
}

fn invalid_leaf(name: &str) -> bool {
    name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalEntryKind {
    EmptyFile,
    EmptyDirectory,
}

struct JournalEntry {
    parent: File,
    parent_identity: StableIdentity,
    descriptor: File,
    identity: StableIdentity,
    filesystem: RunFilesystemIdentity,
    name: String,
    kind: JournalEntryKind,
}

struct ProvisionalCreationGuard {
    parent: Option<File>,
    parent_identity: StableIdentity,
    descriptor: Option<File>,
    identity: Option<StableIdentity>,
    filesystem: RunFilesystemIdentity,
    name: String,
    kind: JournalEntryKind,
    scoped_cleanup_eligible: bool,
    armed: bool,
}

impl ProvisionalCreationGuard {
    fn newly_created_name(
        parent: File,
        parent_identity: StableIdentity,
        filesystem: RunFilesystemIdentity,
        name: String,
        kind: JournalEntryKind,
    ) -> Self {
        Self {
            parent: Some(parent),
            parent_identity,
            descriptor: None,
            identity: None,
            filesystem,
            name,
            kind,
            scoped_cleanup_eligible: false,
            armed: true,
        }
    }

    fn attach_descriptor(&mut self, descriptor: File) -> Result<(), AuthorizedPrivateRunError> {
        if self.descriptor.is_some() || self.identity.is_some() {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "provisional creation descriptor was already attached",
            ));
        }
        self.descriptor = Some(descriptor);
        Ok(())
    }

    fn descriptor(&self) -> Result<&File, AuthorizedPrivateRunError> {
        self.descriptor
            .as_ref()
            .ok_or(AuthorizedPrivateRunError::Unsafe(
                "provisional creation descriptor is unavailable",
            ))
    }

    fn mark_scoped_cleanup_eligible(&mut self) -> Result<(), AuthorizedPrivateRunError> {
        if self.scoped_cleanup_eligible || self.descriptor.is_none() || self.identity.is_some() {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "provisional scoped-cleanup transition is invalid",
            ));
        }
        self.scoped_cleanup_eligible = true;
        Ok(())
    }

    fn parent(&self) -> Result<&File, AuthorizedPrivateRunError> {
        self.parent
            .as_ref()
            .ok_or(AuthorizedPrivateRunError::Unsafe(
                "provisional creation parent is unavailable",
            ))
    }

    fn clone_parent(&self) -> Result<File, AuthorizedPrivateRunError> {
        self.parent()?
            .try_clone()
            .map_err(|source| AuthorizedPrivateRunError::Io {
                operation: "retain created-object parent",
                source,
            })
    }

    fn clone_descriptor(&self) -> Result<File, AuthorizedPrivateRunError> {
        self.descriptor()?
            .try_clone()
            .map_err(|source| AuthorizedPrivateRunError::Io {
                operation: "retain created object",
                source,
            })
    }

    fn upgrade(&mut self, expected: ObjectSnapshot) -> Result<(), AuthorizedPrivateRunError> {
        if self.identity.is_some() || !self.scoped_cleanup_eligible {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "provisional creation guard was already upgraded",
            ));
        }
        verify_private_parent_identity(self.parent()?, self.parent_identity, self.filesystem)?;
        let held = object_snapshot(self.descriptor()?)?;
        let visible = entry_snapshot(self.parent()?, &self.name)?;
        validate_created_shape(self.kind, held, self.filesystem, true)?;
        if held != expected || visible != expected {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "created object changed before guard upgrade",
            ));
        }
        self.identity = Some(expected.identity);
        Ok(())
    }

    fn into_entry(
        mut self,
        journal_parent: File,
    ) -> Result<JournalEntry, AuthorizedPrivateRunError> {
        let identity = self.identity.ok_or(AuthorizedPrivateRunError::Unsafe(
            "provisional creation guard was not upgraded",
        ))?;
        if !self.scoped_cleanup_eligible {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "created object is not eligible for scoped cleanup",
            ));
        }
        let descriptor = self
            .descriptor
            .take()
            .ok_or(AuthorizedPrivateRunError::Unsafe(
                "created-object descriptor was already consumed",
            ))?;
        let name = std::mem::take(&mut self.name);
        self.armed = false;
        Ok(JournalEntry {
            parent: journal_parent,
            parent_identity: self.parent_identity,
            descriptor,
            identity,
            filesystem: self.filesystem,
            name,
            kind: self.kind,
        })
    }
}

impl Drop for ProvisionalCreationGuard {
    fn drop(&mut self) {
        if !self.armed || !self.scoped_cleanup_eligible {
            return;
        }
        let (Some(parent), Some(descriptor)) = (self.parent.as_ref(), self.descriptor.as_ref())
        else {
            // `mkdirat` does not return an object descriptor. If opening the
            // created name fails, the fixed-runner cleanup checks cannot bind
            // the name to an object; retain it for disposable-mount teardown.
            return;
        };
        let _ = remove_provisional_entry(
            parent,
            self.parent_identity,
            descriptor,
            self.filesystem,
            &self.name,
            self.kind,
        );
    }
}

struct RollbackJournal {
    entries: Vec<JournalEntry>,
    armed: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl RollbackJournal {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_JOURNAL_ENTRIES),
            armed: true,
            _thread_bound: PhantomData,
        }
    }

    fn push(&mut self, entry: JournalEntry) -> Result<(), AuthorizedPrivateRunError> {
        if self.entries.len() == MAX_JOURNAL_ENTRIES {
            let _ = remove_journal_entry(&entry, |_| Ok(()));
            let _ = self.rollback();
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private-run rollback journal is full",
            ));
        }
        self.entries.push(entry);
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), AuthorizedPrivateRunError> {
        self.rollback_with_hooks(|_| {}, |_, _| Ok(()))
    }

    fn rollback_with_hooks<Removed, Boundary>(
        &mut self,
        mut removed: Removed,
        mut boundary: Boundary,
    ) -> Result<(), AuthorizedPrivateRunError>
    where
        Removed: FnMut(&str),
        Boundary: FnMut(&str, RemovalBoundary) -> Result<(), AuthorizedPrivateRunError>,
    {
        let mut proof_error = None;
        while let Some(entry) = self.entries.last() {
            let name = entry.name.clone();
            match remove_journal_entry(entry, |point| boundary(&name, point)) {
                Ok(()) => {
                    self.entries.pop();
                    removed(&name);
                }
                Err(failure) if failure.unlinked => {
                    self.entries.pop();
                    removed(&name);
                    proof_error.get_or_insert(failure.error);
                }
                Err(failure) => return Err(failure.error),
            }
        }
        self.armed = false;
        proof_error.map_or(Ok(()), Err)
    }

    #[cfg(test)]
    fn abandon(&mut self) {
        self.armed = false;
    }
}

impl Drop for RollbackJournal {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.rollback();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalBoundary {
    Unlinked,
    AbsenceProved,
    ParentSynced,
}

struct RemovalFailure {
    error: AuthorizedPrivateRunError,
    unlinked: bool,
}

fn verify_private_parent_identity(
    parent: &File,
    expected: StableIdentity,
    filesystem: RunFilesystemIdentity,
) -> Result<(), AuthorizedPrivateRunError> {
    let current = object_snapshot(parent)?.identity;
    if current != expected
        || !current.file_type.is_dir()
        || current.permissions() != PRIVATE_DIRECTORY_MODE
        || !filesystem.contains(current)
    {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "created-object parent identity changed",
        ));
    }
    Ok(())
}

fn validate_created_shape(
    kind: JournalEntryKind,
    snapshot: ObjectSnapshot,
    filesystem: RunFilesystemIdentity,
    require_final_mode: bool,
) -> Result<AtFlags, AuthorizedPrivateRunError> {
    if !filesystem.contains(snapshot.identity) {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "created object escaped the private run filesystem",
        ));
    }
    match kind {
        JournalEntryKind::EmptyFile
            if snapshot.identity.file_type.is_file()
                && snapshot.identity.permissions() == EMPTY_SLOT_MODE
                && snapshot.links == 1
                && snapshot.size == 0 =>
        {
            Ok(AtFlags::empty())
        }
        JournalEntryKind::EmptyDirectory
            if snapshot.identity.file_type.is_dir()
                && (snapshot.identity.permissions() == PRIVATE_DIRECTORY_MODE
                    || !require_final_mode
                        && snapshot.identity.permissions() & !PRIVATE_DIRECTORY_MODE == 0) =>
        {
            Ok(AtFlags::REMOVEDIR)
        }
        JournalEntryKind::EmptyFile | JournalEntryKind::EmptyDirectory => Err(
            AuthorizedPrivateRunError::Unsafe("created object shape is not exact"),
        ),
    }
}

fn remove_provisional_entry(
    parent: &File,
    parent_identity: StableIdentity,
    descriptor: &File,
    filesystem: RunFilesystemIdentity,
    name: &str,
    kind: JournalEntryKind,
) -> Result<(), RemovalFailure> {
    verify_private_parent_identity(parent, parent_identity, filesystem).map_err(|error| {
        RemovalFailure {
            error,
            unlinked: false,
        }
    })?;
    let before = object_snapshot(descriptor).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    let visible_before = entry_snapshot(parent, name).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    let flags = validate_created_shape(kind, before, filesystem, false).map_err(|error| {
        RemovalFailure {
            error,
            unlinked: false,
        }
    })?;
    if before != visible_before
        || kind == JournalEntryKind::EmptyDirectory
            && verify_directory_has_no_entries(descriptor).is_err()
    {
        return Err(RemovalFailure {
            error: AuthorizedPrivateRunError::Unsafe(
                "provisional created object was substituted or populated",
            ),
            unlinked: false,
        });
    }
    verify_private_parent_identity(parent, parent_identity, filesystem).map_err(|error| {
        RemovalFailure {
            error,
            unlinked: false,
        }
    })?;
    let after = object_snapshot(descriptor).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    let visible_after = entry_snapshot(parent, name).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    if after != before || visible_after != after {
        return Err(RemovalFailure {
            error: AuthorizedPrivateRunError::Unsafe(
                "provisional created object changed before cleanup",
            ),
            unlinked: false,
        });
    }
    unlink_proved_name(parent, parent_identity, filesystem, name, flags, |_| Ok(()))
}

fn remove_journal_entry<Boundary>(
    entry: &JournalEntry,
    mut boundary: Boundary,
) -> Result<(), RemovalFailure>
where
    Boundary: FnMut(RemovalBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    let flags = validate_journal_entry(entry)?;
    unlink_proved_entry(entry, flags, &mut boundary)
}

fn validate_journal_entry(entry: &JournalEntry) -> Result<AtFlags, RemovalFailure> {
    let parent = object_snapshot(&entry.parent).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    if parent.identity != entry.parent_identity
        || !parent.identity.file_type.is_dir()
        || parent.identity.permissions() != PRIVATE_DIRECTORY_MODE
        || !entry.filesystem.contains(parent.identity)
    {
        return Err(RemovalFailure {
            error: AuthorizedPrivateRunError::Unsafe("rollback parent identity changed"),
            unlinked: false,
        });
    }
    let held = object_snapshot(&entry.descriptor).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    let visible = entry_snapshot(&entry.parent, &entry.name).map_err(|error| RemovalFailure {
        error,
        unlinked: false,
    })?;
    if held != visible
        || held.identity != entry.identity
        || !entry.filesystem.contains(held.identity)
    {
        return Err(RemovalFailure {
            error: AuthorizedPrivateRunError::Unsafe("rollback entry identity changed"),
            unlinked: false,
        });
    }
    let flags = match entry.kind {
        JournalEntryKind::EmptyFile => {
            if !held.identity.file_type.is_file()
                || held.identity.permissions() != EMPTY_SLOT_MODE
                || held.links != 1
                || held.size != 0
            {
                return Err(RemovalFailure {
                    error: AuthorizedPrivateRunError::Unsafe("rollback slot shape changed"),
                    unlinked: false,
                });
            }
            AtFlags::empty()
        }
        JournalEntryKind::EmptyDirectory => {
            if !held.identity.file_type.is_dir()
                || held.identity.permissions() != PRIVATE_DIRECTORY_MODE
                || verify_empty_directory(&entry.descriptor).is_err()
            {
                return Err(RemovalFailure {
                    error: AuthorizedPrivateRunError::Unsafe("rollback directory is not empty"),
                    unlinked: false,
                });
            }
            AtFlags::REMOVEDIR
        }
    };
    Ok(flags)
}

fn unlink_proved_entry<Boundary>(
    entry: &JournalEntry,
    flags: AtFlags,
    boundary: Boundary,
) -> Result<(), RemovalFailure>
where
    Boundary: FnMut(RemovalBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    unlink_proved_name(
        &entry.parent,
        entry.parent_identity,
        entry.filesystem,
        &entry.name,
        flags,
        boundary,
    )
}

fn unlink_proved_name<Boundary>(
    parent: &File,
    parent_identity: StableIdentity,
    filesystem: RunFilesystemIdentity,
    name: &str,
    flags: AtFlags,
    mut boundary: Boundary,
) -> Result<(), RemovalFailure>
where
    Boundary: FnMut(RemovalBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    unlinkat(parent, name, flags).map_err(|error| RemovalFailure {
        error: AuthorizedPrivateRunError::io("unlink owned private-run object", error),
        unlinked: false,
    })?;
    boundary(RemovalBoundary::Unlinked).map_err(|error| RemovalFailure {
        error,
        unlinked: true,
    })?;
    for _ in 0..2 {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            Ok(_) => {
                return Err(RemovalFailure {
                    error: AuthorizedPrivateRunError::Unsafe(
                        "removed private-run object remains visible",
                    ),
                    unlinked: true,
                });
            }
            Err(error) => {
                return Err(RemovalFailure {
                    error: AuthorizedPrivateRunError::io("prove private-run object absence", error),
                    unlinked: true,
                });
            }
        }
    }
    boundary(RemovalBoundary::AbsenceProved).map_err(|error| RemovalFailure {
        error,
        unlinked: true,
    })?;
    fsync(parent).map_err(|error| RemovalFailure {
        error: AuthorizedPrivateRunError::io("sync private-run rollback parent", error),
        unlinked: true,
    })?;
    boundary(RemovalBoundary::ParentSynced).map_err(|error| RemovalFailure {
        error,
        unlinked: true,
    })?;
    let parent_after = object_snapshot(parent).map_err(|error| RemovalFailure {
        error,
        unlinked: true,
    })?;
    if parent_after.identity != parent_identity || !filesystem.contains(parent_after.identity) {
        return Err(RemovalFailure {
            error: AuthorizedPrivateRunError::Unsafe(
                "rollback parent identity changed after unlink",
            ),
            unlinked: true,
        });
    }
    Ok(())
}

fn verify_empty_directory(directory: &File) -> Result<(), AuthorizedPrivateRunError> {
    let pinned = PinnedDirectory {
        descriptor: directory
            .try_clone()
            .map_err(|source| AuthorizedPrivateRunError::Io {
                operation: "clone empty-directory proof pin",
                source,
            })?,
        identity: object_snapshot(directory)?.identity,
        filesystem: RunFilesystemIdentity::from_root_like(object_snapshot(directory)?.identity)?,
        _thread_bound: PhantomData,
    };
    pinned.verify_exact_entries(&[])
}

fn verify_directory_has_no_entries(directory: &File) -> Result<(), AuthorizedPrivateRunError> {
    let reopened = openat2(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| AuthorizedPrivateRunError::io("reopen provisional directory", error))?;
    let mut storage = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
    let mut entries = RawDir::new(reopened, &mut storage);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|error| {
            AuthorizedPrivateRunError::io("enumerate provisional directory", error)
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "provisional directory is not empty",
            ));
        }
    }
    Ok(())
}

impl RunFilesystemIdentity {
    fn from_root_like(identity: StableIdentity) -> Result<Self, AuthorizedPrivateRunError> {
        if !identity.file_type.is_dir()
            || identity.permissions() != PRIVATE_DIRECTORY_MODE
            || identity.uid != geteuid().as_raw()
            || identity.gid != getegid().as_raw()
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private directory shape is not exact",
            ));
        }
        Ok(Self {
            device: identity.device,
            mount_id: identity.mount_id,
            uid: identity.uid,
            gid: identity.gid,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationHandoffBoundary {
    BeforeDescriptorOpen,
    DescriptorRetained,
    BeforeSnapshot,
    BeforeParentClone,
    BeforeGuardUpgrade,
    BeforePinnedClone,
}

/// Fail-closed detector for mutations during the fixed runner's `mkdirat` handoff.
///
/// This is deliberately not a synchronization primitive or hostile-peer
/// unlink authority. The disposable test runner has one fixed PID-1 task and
/// one trusted launcher; adversarial processes with a pre-opened writable
/// descriptor into its private mount are outside this transaction's scope.
struct DirectoryMutationWatch {
    descriptor: OwnedFd,
    watch_descriptor: i32,
}

impl DirectoryMutationWatch {
    fn install(parent: &File) -> Result<Self, AuthorizedPrivateRunError> {
        let descriptor = inotify::init(
            inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK,
        )
        .map_err(|error| AuthorizedPrivateRunError::io("create directory-mutation watch", error))?;
        let parent_path = format!("/proc/self/fd/{}", parent.as_raw_fd());
        let watch_descriptor = inotify::add_watch(
            &descriptor,
            parent_path,
            inotify::WatchFlags::CREATE
                | inotify::WatchFlags::DELETE
                | inotify::WatchFlags::MOVED_FROM
                | inotify::WatchFlags::MOVED_TO
                | inotify::WatchFlags::DELETE_SELF
                | inotify::WatchFlags::MOVE_SELF
                | inotify::WatchFlags::ONLYDIR
                | inotify::WatchFlags::EXCL_UNLINK
                | inotify::WatchFlags::MASK_CREATE,
        )
        .map_err(|error| {
            AuthorizedPrivateRunError::io("install directory-mutation watch", error)
        })?;
        let watch = Self {
            descriptor,
            watch_descriptor,
        };
        watch.require_no_event("initialize directory-mutation watch")?;
        Ok(watch)
    }

    fn require_single_create_event(&self, name: &str) -> Result<(), AuthorizedPrivateRunError> {
        let mut storage = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut events = inotify::Reader::new(&self.descriptor, &mut storage);
        let event = events.next().map_err(|error| {
            AuthorizedPrivateRunError::io("read directory-mutation create event", error)
        })?;
        let expected_events = inotify::ReadFlags::CREATE | inotify::ReadFlags::ISDIR;
        if event.wd() != self.watch_descriptor
            || event.events() != expected_events
            || event.cookie() != 0
            || event.file_name().map(std::ffi::CStr::to_bytes) != Some(name.as_bytes())
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "directory mutation event is not the expected single create",
            ));
        }
        match events.next() {
            Err(Errno::AGAIN) => Ok(()),
            Err(error) => Err(AuthorizedPrivateRunError::io(
                "complete directory-mutation event check",
                error,
            )),
            Ok(_) => Err(AuthorizedPrivateRunError::Unsafe(
                "directory handoff contains an additional mutation event",
            )),
        }
    }

    fn require_no_event(&self, operation: &'static str) -> Result<(), AuthorizedPrivateRunError> {
        let mut storage = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut events = inotify::Reader::new(&self.descriptor, &mut storage);
        match events.next() {
            Err(Errno::AGAIN) => Ok(()),
            Err(error) => Err(AuthorizedPrivateRunError::io(operation, error)),
            Ok(_) => Err(AuthorizedPrivateRunError::Unsafe(
                "directory-mutation watch was not initially empty",
            )),
        }
    }
}

fn create_directory(
    parent: &PinnedDirectory,
    name: String,
) -> Result<(PinnedDirectory, JournalEntry), AuthorizedPrivateRunError> {
    create_directory_with_hook(parent, name, |_| Ok(()))
}

fn create_directory_with_hook<Hook>(
    parent: &PinnedDirectory,
    name: String,
    mut boundary: Hook,
) -> Result<(PinnedDirectory, JournalEntry), AuthorizedPrivateRunError>
where
    Hook: FnMut(CreationHandoffBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    if invalid_leaf(&name) {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "invalid private directory name",
        ));
    }
    parent.verify()?;
    let guard_parent =
        parent
            .descriptor
            .try_clone()
            .map_err(|source| AuthorizedPrivateRunError::Io {
                operation: "prepare created-directory parent guard",
                source,
            })?;
    let mutation_watch = DirectoryMutationWatch::install(&parent.descriptor)?;
    parent.verify()?;
    mkdirat(
        &parent.descriptor,
        &name,
        Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE),
    )
    .map_err(|error| AuthorizedPrivateRunError::io("create private directory", error))?;
    let mut guard = ProvisionalCreationGuard::newly_created_name(
        guard_parent,
        parent.identity,
        parent.filesystem,
        name,
        JournalEntryKind::EmptyDirectory,
    );
    boundary(CreationHandoffBoundary::BeforeDescriptorOpen)?;
    let descriptor = openat2(
        &parent.descriptor,
        &guard.name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| AuthorizedPrivateRunError::io("pin newly created private directory", error))?;
    guard.attach_descriptor(File::from(descriptor))?;
    mutation_watch.require_single_create_event(&guard.name)?;
    guard.mark_scoped_cleanup_eligible()?;
    boundary(CreationHandoffBoundary::DescriptorRetained)?;
    fchmod(
        guard.descriptor()?,
        Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE),
    )
    .map_err(|error| AuthorizedPrivateRunError::io("harden private directory mode", error))?;
    boundary(CreationHandoffBoundary::BeforeSnapshot)?;
    let current = object_snapshot(guard.descriptor()?)?;
    validate_created_shape(
        JournalEntryKind::EmptyDirectory,
        current,
        parent.filesystem,
        true,
    )?;
    if entry_snapshot(&parent.descriptor, &guard.name)? != current
        || verify_directory_has_no_entries(guard.descriptor()?).is_err()
    {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "created private directory identity is not exact",
        ));
    }
    fsync(&parent.descriptor)
        .map_err(|error| AuthorizedPrivateRunError::io("sync created-directory parent", error))?;
    parent.verify()?;
    boundary(CreationHandoffBoundary::BeforeParentClone)?;
    let journal_parent = guard.clone_parent()?;
    boundary(CreationHandoffBoundary::BeforeGuardUpgrade)?;
    guard.upgrade(current)?;
    boundary(CreationHandoffBoundary::BeforePinnedClone)?;
    let pinned_descriptor = guard.clone_descriptor()?;
    let pinned =
        PinnedDirectory::from_created(pinned_descriptor, current.identity, parent.filesystem)?;
    let entry = guard.into_entry(journal_parent)?;
    Ok((pinned, entry))
}

struct PinnedEmptySlot {
    descriptor: File,
    identity: StableIdentity,
    name: String,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PinnedEmptySlot {
    fn verify_hidden_at(&self, parent: &PinnedDirectory) -> Result<(), AuthorizedPrivateRunError> {
        let held = object_snapshot(&self.descriptor)?;
        if held.identity != self.identity
            || !held.identity.file_type.is_file()
            || held.identity.permissions() != EMPTY_SLOT_MODE
            || held.links != 1
            || held.size != 0
            || !parent.filesystem.contains(held.identity)
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "retained hidden namespace slot changed",
            ));
        }
        parent.verify()
    }

    fn verify_at(&self, parent: &PinnedDirectory) -> Result<(), AuthorizedPrivateRunError> {
        self.verify_hidden_at(parent)?;
        let held = object_snapshot(&self.descriptor)?;
        if held.identity != self.identity || held != entry_snapshot(&parent.descriptor, &self.name)?
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "retained empty namespace slot changed",
            ));
        }
        parent.verify()
    }
}

fn create_empty_slot(
    parent: &PinnedDirectory,
    name: String,
) -> Result<(PinnedEmptySlot, JournalEntry), AuthorizedPrivateRunError> {
    create_empty_slot_with_hook(parent, name, |_| Ok(()))
}

fn create_empty_slot_with_hook<Hook>(
    parent: &PinnedDirectory,
    name: String,
    mut boundary: Hook,
) -> Result<(PinnedEmptySlot, JournalEntry), AuthorizedPrivateRunError>
where
    Hook: FnMut(CreationHandoffBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    if invalid_leaf(&name) {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "invalid namespace slot name",
        ));
    }
    parent.verify()?;
    let guard_parent =
        parent
            .descriptor
            .try_clone()
            .map_err(|source| AuthorizedPrivateRunError::Io {
                operation: "prepare namespace-slot parent guard",
                source,
            })?;
    boundary(CreationHandoffBoundary::BeforeDescriptorOpen)?;
    let descriptor = openat2(
        &parent.descriptor,
        &name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(EMPTY_SLOT_MODE),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| AuthorizedPrivateRunError::io("create empty namespace slot", error))?;
    let mut guard = ProvisionalCreationGuard::newly_created_name(
        guard_parent,
        parent.identity,
        parent.filesystem,
        name,
        JournalEntryKind::EmptyFile,
    );
    guard.attach_descriptor(File::from(descriptor))?;
    guard.mark_scoped_cleanup_eligible()?;
    boundary(CreationHandoffBoundary::DescriptorRetained)?;
    fchmod(guard.descriptor()?, Mode::from_raw_mode(EMPTY_SLOT_MODE))
        .map_err(|error| AuthorizedPrivateRunError::io("harden namespace-slot mode", error))?;
    boundary(CreationHandoffBoundary::BeforeSnapshot)?;
    let current = object_snapshot(guard.descriptor()?)?;
    validate_created_shape(
        JournalEntryKind::EmptyFile,
        current,
        parent.filesystem,
        true,
    )?;
    if entry_snapshot(&parent.descriptor, &guard.name)? != current {
        return Err(AuthorizedPrivateRunError::Unsafe(
            "created namespace slot identity is not exact",
        ));
    }
    fsync(guard.descriptor()?)
        .map_err(|error| AuthorizedPrivateRunError::io("sync empty namespace slot", error))?;
    fsync(&parent.descriptor)
        .map_err(|error| AuthorizedPrivateRunError::io("sync namespace-slot parent", error))?;
    parent.verify()?;
    boundary(CreationHandoffBoundary::BeforeParentClone)?;
    let journal_parent = guard.clone_parent()?;
    boundary(CreationHandoffBoundary::BeforeGuardUpgrade)?;
    guard.upgrade(current)?;
    boundary(CreationHandoffBoundary::BeforePinnedClone)?;
    let pinned = PinnedEmptySlot {
        descriptor: guard.clone_descriptor()?,
        identity: current.identity,
        name: guard.name.clone(),
        _thread_bound: PhantomData,
    };
    pinned.verify_at(parent)?;
    let entry = guard.into_entry(journal_parent)?;
    Ok((pinned, entry))
}

fn namespace_slot_name(run_id: &RunId, endpoint: char) -> String {
    format!("vpl-{}-{endpoint}", run_id.as_str())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageBoundary {
    PristineRootPinned,
    NetnsRootStored,
    WorkspaceRootStored,
    RunDirectoryStored,
    EndpointAStored,
    EndpointBStored,
    ExactLayoutProved,
}

#[cfg(test)]
impl StageBoundary {
    const ALL: [Self; 7] = [
        Self::PristineRootPinned,
        Self::NetnsRootStored,
        Self::WorkspaceRootStored,
        Self::RunDirectoryStored,
        Self::EndpointAStored,
        Self::EndpointBStored,
        Self::ExactLayoutProved,
    ];
}

/// Affine post-`GO` owner of one run-bound private root and two empty namespace slots.
///
/// The authorization token remains private to this state. Namespace authority
/// is confined to consuming this owner into the exact two-pin transition; it
/// grants no ownership-manifest, veth, configured-network, or lifecycle-attestation authority.
/// Cleanup is scoped to the disposable runner's fixed single-task PID 1 and
/// trusted launcher. It does not claim synchronization against a hostile
/// mapped-same-UID process that already holds a writable private-`/run` descriptor;
/// the production helper requires separately enforced root-owned exclusivity.
pub(crate) struct AuthorizedPrivateRun {
    authorization: Option<MutationAuthorization>,
    journal: RollbackJournal,
    run_root: PinnedDirectory,
    netns_root: PinnedDirectory,
    workspace_root: PinnedDirectory,
    run_directory: PinnedDirectory,
    slots: [PinnedEmptySlot; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

struct StagedLayout {
    netns_root: PinnedDirectory,
    workspace_root: PinnedDirectory,
    run_directory: PinnedDirectory,
    slots: [PinnedEmptySlot; 2],
}

#[derive(Clone, Copy)]
pub(super) struct NamespacePinTarget<'a> {
    pub(super) parent: &'a File,
    pub(super) hidden_slot: &'a File,
    pub(super) name: &'a str,
}

impl AuthorizedPrivateRun {
    /// Create and prove the fixed run-bound directory and empty-slot transaction.
    pub(crate) fn stage(
        run_descriptor: &OwnedFd,
        authorization: MutationAuthorization,
    ) -> Result<Self, AuthorizedPrivateRunError> {
        Self::stage_with_hook(run_descriptor, authorization, |_| Ok(()))
    }

    fn stage_with_hook<Hook>(
        run_descriptor: &OwnedFd,
        authorization: MutationAuthorization,
        mut boundary: Hook,
    ) -> Result<Self, AuthorizedPrivateRunError>
    where
        Hook: FnMut(StageBoundary) -> Result<(), AuthorizedPrivateRunError>,
    {
        let run_id = authorization.run_id().clone();
        let run_root = PinnedDirectory::pin_root(run_descriptor)?;
        run_root.verify_exact_entries(&[])?;
        boundary(StageBoundary::PristineRootPinned)?;
        let mut journal = RollbackJournal::new();

        let staged = stage_layout(&run_root, &mut journal, &run_id, &mut boundary);
        let StagedLayout {
            netns_root,
            workspace_root,
            run_directory,
            slots,
        } = match staged {
            Ok(staged) => staged,
            Err(error) => {
                if journal.rollback().is_err() {
                    return Err(AuthorizedPrivateRunError::Unsafe(
                        "authorized private-run staging and rollback both failed",
                    ));
                }
                run_root.verify_exact_entries(&[])?;
                return Err(error);
            }
        };
        let mut state = Self {
            authorization: Some(authorization),
            journal,
            run_root,
            netns_root,
            workspace_root,
            run_directory,
            slots,
            _thread_bound: PhantomData,
        };
        let final_proof = state
            .verify()
            .and_then(|()| boundary(StageBoundary::ExactLayoutProved));
        if let Err(error) = final_proof {
            drop(state.authorization.take());
            if state.journal.rollback().is_err() {
                return Err(AuthorizedPrivateRunError::Unsafe(
                    "authorized private-run final proof and rollback both failed",
                ));
            }
            state.run_root.verify_exact_entries(&[])?;
            return Err(error);
        }
        Ok(state)
    }

    /// Reprove the authorization binding, fixed exact sets, modes, and retained identities.
    pub(crate) fn verify(&self) -> Result<(), AuthorizedPrivateRunError> {
        let run_id = self.verify_fixed_directories()?;
        for slot in &self.slots {
            slot.verify_at(&self.netns_root)?;
        }
        if self.slots[0].name != namespace_slot_name(run_id, 'a')
            || self.slots[1].name != namespace_slot_name(run_id, 'b')
            || self.slots[0].identity == self.slots[1].identity
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "namespace slots are not exactly run-bound A and B",
            ));
        }
        self.netns_root.verify_exact_entries(&[
            ExpectedEntry {
                name: &self.slots[0].name,
                descriptor: &self.slots[0].descriptor,
                identity: self.slots[0].identity,
            },
            ExpectedEntry {
                name: &self.slots[1].name,
                descriptor: &self.slots[1].descriptor,
                identity: self.slots[1].identity,
            },
        ])
    }

    fn verify_fixed_directories(&self) -> Result<&RunId, AuthorizedPrivateRunError> {
        let run_id = self
            .authorization
            .as_ref()
            .ok_or(AuthorizedPrivateRunError::Unsafe(
                "authorized private-run token was consumed",
            ))?
            .run_id();
        if self.run_directory.identity == self.workspace_root.identity
            || self.workspace_root.identity == self.netns_root.identity
            || self.netns_root.identity == self.run_root.identity
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "private-run directories are not distinct",
            ));
        }
        self.run_root.verify_exact_entries(&[
            ExpectedEntry {
                name: NETNS_ROOT_LEAF,
                descriptor: &self.netns_root.descriptor,
                identity: self.netns_root.identity,
            },
            ExpectedEntry {
                name: WORKSPACE_ROOT_LEAF,
                descriptor: &self.workspace_root.descriptor,
                identity: self.workspace_root.identity,
            },
        ])?;
        self.workspace_root.verify_exact_entries(&[ExpectedEntry {
            name: run_id.as_str(),
            descriptor: &self.run_directory.descriptor,
            identity: self.run_directory.identity,
        }])?;
        self.run_directory.verify_exact_entries(&[])?;
        Ok(run_id)
    }

    /// Reprove the fixed directory binding and expose its canonical naming authority.
    pub(super) fn verified_run_id(&self) -> Result<&RunId, AuthorizedPrivateRunError> {
        self.verify_fixed_directories()
    }

    pub(super) fn verify_namespace_pin_backing(&self) -> Result<(), AuthorizedPrivateRunError> {
        let run_id = self.verify_fixed_directories()?;
        for slot in &self.slots {
            slot.verify_hidden_at(&self.netns_root)?;
        }
        if self.slots[0].name != namespace_slot_name(run_id, 'a')
            || self.slots[1].name != namespace_slot_name(run_id, 'b')
            || self.slots[0].identity == self.slots[1].identity
        {
            return Err(AuthorizedPrivateRunError::Unsafe(
                "namespace slots are not exactly run-bound A and B",
            ));
        }
        self.netns_root
            .verify_exact_names(&[&self.slots[0].name, &self.slots[1].name])
    }

    pub(super) fn namespace_pin_targets(&self) -> [NamespacePinTarget<'_>; 2] {
        [
            NamespacePinTarget {
                parent: &self.netns_root.descriptor,
                hidden_slot: &self.slots[0].descriptor,
                name: &self.slots[0].name,
            },
            NamespacePinTarget {
                parent: &self.netns_root.descriptor,
                hidden_slot: &self.slots[1].descriptor,
                name: &self.slots[1].name,
            },
        ]
    }

    /// Consume the internal authorization and remove B, A, run, workspace, then netns.
    pub(crate) fn rollback(mut self) -> Result<(), AuthorizedPrivateRunError> {
        self.verify()?;
        drop(self.authorization.take());
        let result = self.journal.rollback();
        let pristine = self.run_root.verify_exact_entries(&[]);
        match (result, pristine) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }
}

fn stage_layout<Hook>(
    run_root: &PinnedDirectory,
    journal: &mut RollbackJournal,
    run_id: &RunId,
    boundary: &mut Hook,
) -> Result<StagedLayout, AuthorizedPrivateRunError>
where
    Hook: FnMut(StageBoundary) -> Result<(), AuthorizedPrivateRunError>,
{
    let (netns_root, netns_entry) = create_directory(run_root, NETNS_ROOT_LEAF.to_owned())?;
    journal.push(netns_entry)?;
    run_root.verify_exact_entries(&[ExpectedEntry {
        name: NETNS_ROOT_LEAF,
        descriptor: &netns_root.descriptor,
        identity: netns_root.identity,
    }])?;
    boundary(StageBoundary::NetnsRootStored)?;

    let (workspace_root, workspace_entry) =
        create_directory(run_root, WORKSPACE_ROOT_LEAF.to_owned())?;
    journal.push(workspace_entry)?;
    run_root.verify_exact_entries(&[
        ExpectedEntry {
            name: NETNS_ROOT_LEAF,
            descriptor: &netns_root.descriptor,
            identity: netns_root.identity,
        },
        ExpectedEntry {
            name: WORKSPACE_ROOT_LEAF,
            descriptor: &workspace_root.descriptor,
            identity: workspace_root.identity,
        },
    ])?;
    boundary(StageBoundary::WorkspaceRootStored)?;

    let (run_directory, run_entry) = create_directory(&workspace_root, run_id.as_str().to_owned())?;
    journal.push(run_entry)?;
    workspace_root.verify_exact_entries(&[ExpectedEntry {
        name: run_id.as_str(),
        descriptor: &run_directory.descriptor,
        identity: run_directory.identity,
    }])?;
    run_directory.verify_exact_entries(&[])?;
    boundary(StageBoundary::RunDirectoryStored)?;

    let (alpha_slot, alpha_cleanup) =
        create_empty_slot(&netns_root, namespace_slot_name(run_id, 'a'))?;
    journal.push(alpha_cleanup)?;
    netns_root.verify_exact_entries(&[ExpectedEntry {
        name: &alpha_slot.name,
        descriptor: &alpha_slot.descriptor,
        identity: alpha_slot.identity,
    }])?;
    boundary(StageBoundary::EndpointAStored)?;

    let (omega_slot, omega_cleanup) =
        create_empty_slot(&netns_root, namespace_slot_name(run_id, 'b'))?;
    journal.push(omega_cleanup)?;
    netns_root.verify_exact_entries(&[
        ExpectedEntry {
            name: &alpha_slot.name,
            descriptor: &alpha_slot.descriptor,
            identity: alpha_slot.identity,
        },
        ExpectedEntry {
            name: &omega_slot.name,
            descriptor: &omega_slot.descriptor,
            identity: omega_slot.identity,
        },
    ])?;
    boundary(StageBoundary::EndpointBStored)?;
    Ok(StagedLayout {
        netns_root,
        workspace_root,
        run_directory,
        slots: [alpha_slot, omega_slot],
    })
}

#[cfg(test)]
mod authorized_private_run_tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::Path,
    };

    use tempfile::TempDir;
    use volparossa_test_support::{BootstrapReady, Go, InnerLifecycleState, NamespaceIdentity};

    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_RUN: &str = "fedcba9876543210fedcba9876543210";

    fn identity(device: u64, inode: u64) -> NamespaceIdentity {
        NamespaceIdentity::new(device, inode).expect("nonzero namespace identity")
    }

    fn authorization(encoded_run: &str) -> MutationAuthorization {
        let run_id = RunId::parse(encoded_run).expect("canonical run ID");
        let mut lifecycle = InnerLifecycleState::new(
            run_id.clone(),
            identity(1, 1),
            identity(1, 2),
            identity(1, 3),
        );
        let bootstrap = BootstrapReady::new(
            run_id.clone(),
            identity(2, 4),
            identity(2, 5),
            identity(2, 6),
        )
        .expect("distinct inner namespaces");
        lifecycle
            .bootstrap_ready(&bootstrap)
            .expect("advance lifecycle to awaiting GO");
        lifecycle
            .accept_go(Go::new(run_id).encode().expect("canonical GO").as_bytes())
            .expect("affine authorization")
    }

    fn private_run_fixture() -> (TempDir, OwnedFd) {
        let fixture = TempDir::new().expect("private-run fixture");
        fs::set_permissions(
            fixture.path(),
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .expect("exact fixture mode");
        let descriptor: OwnedFd = File::open(fixture.path())
            .expect("open private-run fixture")
            .into();
        (fixture, descriptor)
    }

    fn entry_names(path: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(path)
            .expect("enumerate fixture")
            .map(|entry| {
                entry
                    .expect("fixture entry")
                    .file_name()
                    .into_string()
                    .expect("ASCII fixture name")
            })
            .collect();
        names.sort_unstable();
        names
    }

    fn assert_mode(path: &Path, expected: u32) {
        assert_eq!(
            fs::symlink_metadata(path)
                .expect("fixture metadata")
                .permissions()
                .mode()
                & 0o7777,
            expected
        );
    }

    #[test]
    fn authorization_stages_exact_run_bound_roots_and_affine_rollback() {
        let (fixture, descriptor) = private_run_fixture();
        let state = AuthorizedPrivateRun::stage(&descriptor, authorization(RUN))
            .expect("stage authorized roots");
        state.verify().expect("reverify authorized roots");

        assert_eq!(
            entry_names(fixture.path()),
            vec![NETNS_ROOT_LEAF.to_owned(), WORKSPACE_ROOT_LEAF.to_owned()]
        );
        let netns = fixture.path().join(NETNS_ROOT_LEAF);
        let workspace = fixture.path().join(WORKSPACE_ROOT_LEAF);
        let run_directory = workspace.join(RUN);
        assert_eq!(
            entry_names(&netns),
            vec![
                namespace_slot_name(&RunId::parse(RUN).expect("run"), 'a'),
                namespace_slot_name(&RunId::parse(RUN).expect("run"), 'b'),
            ]
        );
        assert_eq!(entry_names(&workspace), vec![RUN.to_owned()]);
        assert!(entry_names(&run_directory).is_empty());
        for directory in [&netns, &workspace, &run_directory] {
            assert_mode(directory, PRIVATE_DIRECTORY_MODE);
        }
        for slot in entry_names(&netns) {
            let slot = netns.join(slot);
            assert_mode(&slot, EMPTY_SLOT_MODE);
            let metadata = fs::metadata(slot).expect("slot metadata");
            assert_eq!(metadata.len(), 0);
            assert_eq!(metadata.nlink(), 1);
        }

        state.rollback().expect("affine reverse rollback");
        assert!(entry_names(fixture.path()).is_empty());
    }

    #[test]
    fn authorization_run_id_is_the_only_naming_authority() {
        let (fixture, descriptor) = private_run_fixture();
        let state = AuthorizedPrivateRun::stage(&descriptor, authorization(OTHER_RUN))
            .expect("stage other authorized run");
        let workspace = fixture.path().join(WORKSPACE_ROOT_LEAF);
        let netns = fixture.path().join(NETNS_ROOT_LEAF);
        assert_eq!(entry_names(&workspace), vec![OTHER_RUN.to_owned()]);
        assert_eq!(
            entry_names(&netns),
            vec![
                namespace_slot_name(&RunId::parse(OTHER_RUN).expect("other run"), 'a'),
                namespace_slot_name(&RunId::parse(OTHER_RUN).expect("other run"), 'b'),
            ]
        );
        assert!(!workspace.join(RUN).exists());
        assert!(entry_names(&netns).iter().all(|name| !name.contains(RUN)));
        state.rollback().expect("rollback other authorized run");
        assert!(entry_names(fixture.path()).is_empty());
    }

    #[test]
    fn every_stage_boundary_rolls_back_to_the_exact_pristine_set() {
        for target in StageBoundary::ALL {
            let (fixture, descriptor) = private_run_fixture();
            let mut injected = false;
            let result = AuthorizedPrivateRun::stage_with_hook(
                &descriptor,
                authorization(RUN),
                |boundary| {
                    if boundary == target {
                        injected = true;
                        Err(AuthorizedPrivateRunError::Unsafe("injected stage boundary"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "stage boundary {target:?}");
            assert!(injected, "stage boundary {target:?}");
            assert!(
                entry_names(fixture.path()).is_empty(),
                "stage boundary {target:?}"
            );
        }
    }

    #[test]
    fn rollback_order_is_exact_and_post_unlink_failures_continue_cleanup() {
        let expected = vec![
            namespace_slot_name(&RunId::parse(RUN).expect("run"), 'b'),
            namespace_slot_name(&RunId::parse(RUN).expect("run"), 'a'),
            RUN.to_owned(),
            WORKSPACE_ROOT_LEAF.to_owned(),
            NETNS_ROOT_LEAF.to_owned(),
        ];
        for target in [
            RemovalBoundary::Unlinked,
            RemovalBoundary::AbsenceProved,
            RemovalBoundary::ParentSynced,
        ] {
            let (fixture, descriptor) = private_run_fixture();
            let mut state = AuthorizedPrivateRun::stage(&descriptor, authorization(RUN))
                .expect("stage rollback failpoint fixture");
            drop(state.authorization.take());
            let mut removed = Vec::new();
            let mut injected = false;
            let result = state.journal.rollback_with_hooks(
                |name| removed.push(name.to_owned()),
                |name, boundary| {
                    if !injected && name.ends_with("-b") && boundary == target {
                        injected = true;
                        Err(AuthorizedPrivateRunError::Unsafe(
                            "injected rollback boundary",
                        ))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "rollback boundary {target:?}");
            assert!(injected, "rollback boundary {target:?}");
            assert_eq!(removed, expected, "rollback boundary {target:?}");
            assert!(state.journal.entries.is_empty());
            assert!(!state.journal.armed);
            assert!(entry_names(fixture.path()).is_empty());
        }
    }

    #[test]
    fn exact_sets_reject_foreign_input_and_rollback_never_adopts_replacement() {
        let (foreign_fixture, foreign_descriptor) = private_run_fixture();
        fs::write(foreign_fixture.path().join("foreign"), b"foreign").expect("foreign root entry");
        assert!(AuthorizedPrivateRun::stage(&foreign_descriptor, authorization(RUN)).is_err());
        assert_eq!(entry_names(foreign_fixture.path()), vec!["foreign"]);

        let (replacement_fixture, replacement_descriptor) = private_run_fixture();
        let mut state = AuthorizedPrivateRun::stage(&replacement_descriptor, authorization(RUN))
            .expect("stage replacement fixture");
        let slot_b = replacement_fixture
            .path()
            .join(NETNS_ROOT_LEAF)
            .join(namespace_slot_name(&RunId::parse(RUN).expect("run"), 'b'));
        fs::remove_file(&slot_b).expect("remove owned B slot");
        fs::write(&slot_b, b"foreign replacement").expect("install foreign replacement");
        fs::set_permissions(&slot_b, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
            .expect("replacement mode");
        drop(state.authorization.take());
        assert!(state.journal.rollback().is_err());
        assert_eq!(
            fs::metadata(&slot_b).expect("replacement retained").len(),
            b"foreign replacement".len() as u64
        );
        state.journal.abandon();
    }

    #[test]
    fn directory_handoff_failpoints_cleanup_only_after_a_descriptor_is_retained() {
        let (open_fixture, open_descriptor) = private_run_fixture();
        let open_root = PinnedDirectory::pin_root(&open_descriptor).expect("pin open fixture");
        assert!(
            create_directory_with_hook(&open_root, "guarded-directory".to_owned(), |boundary| {
                if boundary == CreationHandoffBoundary::BeforeDescriptorOpen {
                    Err(AuthorizedPrivateRunError::Unsafe(
                        "injected directory open handoff",
                    ))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(entry_names(open_fixture.path()), vec!["guarded-directory"]);

        for target in [
            CreationHandoffBoundary::DescriptorRetained,
            CreationHandoffBoundary::BeforeSnapshot,
            CreationHandoffBoundary::BeforeParentClone,
            CreationHandoffBoundary::BeforeGuardUpgrade,
            CreationHandoffBoundary::BeforePinnedClone,
        ] {
            let (fixture, descriptor) = private_run_fixture();
            let root = PinnedDirectory::pin_root(&descriptor).expect("pin directory fixture");
            let mut injected = false;
            assert!(
                create_directory_with_hook(&root, "guarded-directory".to_owned(), |boundary| {
                    if boundary == target {
                        injected = true;
                        Err(AuthorizedPrivateRunError::Unsafe(
                            "injected directory handoff",
                        ))
                    } else {
                        Ok(())
                    }
                },)
                .is_err(),
                "directory boundary {target:?}"
            );
            assert!(injected, "directory boundary {target:?}");
            assert!(
                entry_names(fixture.path()).is_empty(),
                "directory boundary {target:?}"
            );
            root.verify_exact_entries(&[])
                .expect("directory guard restored pristine root");
        }
    }

    #[test]
    fn slot_handoff_failpoints_have_no_pre_guard_window() {
        for target in [
            CreationHandoffBoundary::BeforeDescriptorOpen,
            CreationHandoffBoundary::DescriptorRetained,
            CreationHandoffBoundary::BeforeSnapshot,
            CreationHandoffBoundary::BeforeParentClone,
            CreationHandoffBoundary::BeforeGuardUpgrade,
            CreationHandoffBoundary::BeforePinnedClone,
        ] {
            let (fixture, descriptor) = private_run_fixture();
            let root = PinnedDirectory::pin_root(&descriptor).expect("pin slot fixture");
            let mut injected = false;
            assert!(
                create_empty_slot_with_hook(&root, "guarded-empty-slot".to_owned(), |boundary| {
                    if boundary == target {
                        injected = true;
                        Err(AuthorizedPrivateRunError::Unsafe("injected slot handoff"))
                    } else {
                        Ok(())
                    }
                },)
                .is_err(),
                "slot boundary {target:?}"
            );
            assert!(injected, "slot boundary {target:?}");
            assert!(
                entry_names(fixture.path()).is_empty(),
                "slot boundary {target:?}"
            );
            root.verify_exact_entries(&[])
                .expect("slot guard restored pristine root");
        }
    }

    #[test]
    fn directory_handoff_rejects_and_retains_observed_substitutions() {
        for target in [
            CreationHandoffBoundary::BeforeDescriptorOpen,
            CreationHandoffBoundary::DescriptorRetained,
        ] {
            let (fixture, descriptor) = private_run_fixture();
            let root = PinnedDirectory::pin_root(&descriptor).expect("pin substitution fixture");
            let created_path = fixture.path().join("guarded-directory");
            let displaced_path = fixture.path().join("displaced-created-directory");
            let mut substituted = false;
            let mut replacement_inode = None;
            assert!(
                create_directory_with_hook(&root, "guarded-directory".to_owned(), |boundary| {
                    if boundary == target {
                        substituted = true;
                        if target == CreationHandoffBoundary::BeforeDescriptorOpen {
                            fs::remove_dir(&created_path)
                                .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                            fs::create_dir(&created_path)
                                .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                            replacement_inode = Some(
                                fs::metadata(&created_path)
                                    .map_err(AuthorizedPrivateRunError::from_io_for_test)?
                                    .ino(),
                            );
                            Ok(())
                        } else {
                            fs::rename(&created_path, &displaced_path)
                                .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                            fs::create_dir(&created_path)
                                .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                            fs::write(created_path.join("foreign-marker"), b"foreign")
                                .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                            Err(AuthorizedPrivateRunError::Unsafe(
                                "injected directory substitution",
                            ))
                        }
                    } else {
                        Ok(())
                    }
                },)
                .is_err(),
                "directory substitution boundary {target:?}"
            );
            assert!(substituted, "directory substitution boundary {target:?}");
            if target == CreationHandoffBoundary::BeforeDescriptorOpen {
                assert_eq!(
                    fs::metadata(&created_path)
                        .expect("foreign empty directory retained")
                        .ino(),
                    replacement_inode.expect("replacement inode captured")
                );
                assert!(entry_names(&created_path).is_empty());
                assert!(!displaced_path.exists());
            } else {
                assert_eq!(
                    fs::read(created_path.join("foreign-marker"))
                        .expect("foreign directory retained"),
                    b"foreign"
                );
                assert!(displaced_path.exists());
            }
        }
    }

    #[test]
    fn slot_handoff_rejects_and_retains_the_observed_replacement() {
        let (fixture, descriptor) = private_run_fixture();
        let root = PinnedDirectory::pin_root(&descriptor).expect("pin slot substitution fixture");
        let slot_path = fixture.path().join("guarded-empty-slot");
        let mut substituted = false;
        assert!(
            create_empty_slot_with_hook(&root, "guarded-empty-slot".to_owned(), |boundary| {
                if boundary == CreationHandoffBoundary::DescriptorRetained {
                    fs::remove_file(&slot_path)
                        .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                    fs::write(&slot_path, b"foreign replacement")
                        .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                    fs::set_permissions(&slot_path, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
                        .map_err(AuthorizedPrivateRunError::from_io_for_test)?;
                    substituted = true;
                    Err(AuthorizedPrivateRunError::Unsafe(
                        "injected slot substitution",
                    ))
                } else {
                    Ok(())
                }
            },)
            .is_err()
        );
        assert!(substituted);
        assert_eq!(
            fs::metadata(&slot_path)
                .expect("foreign slot retained")
                .len(),
            b"foreign replacement".len() as u64
        );
    }

    #[test]
    fn slot_exclusive_open_collision_retains_the_foreign_entry() {
        let (fixture, descriptor) = private_run_fixture();
        let root = PinnedDirectory::pin_root(&descriptor).expect("pin slot collision fixture");
        let slot_path = fixture.path().join("guarded-empty-slot");
        fs::write(&slot_path, b"foreign collision").expect("foreign collision fixture");
        fs::set_permissions(&slot_path, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
            .expect("foreign collision mode");
        assert!(
            create_empty_slot(&root, "guarded-empty-slot".to_owned()).is_err(),
            "O_EXCL collision must fail"
        );
        assert_eq!(
            fs::metadata(&slot_path)
                .expect("foreign collision retained")
                .len(),
            b"foreign collision".len() as u64
        );
    }
}

#[cfg(test)]
#[path = "ownership_publication_model.rs"]
mod publication_model;
