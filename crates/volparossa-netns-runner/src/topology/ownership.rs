use std::{
    collections::HashSet, fs::File, io, marker::PhantomData, mem::MaybeUninit, os::fd::AsFd, rc::Rc,
};

use nix::unistd::geteuid;
use rustix::{
    fs::{
        AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, ResolveFlags, Stat, Statx,
        StatxFlags, fchmod, fstat, fsync, makedev, openat2, renameat_with, statat, statx, unlinkat,
    },
    io::{Errno, pread, write},
};
use thiserror::Error;
use volparossa_test_support::{LifecycleSha256, NamespaceIdentity, OwnedNamespace, RunId};

const MANIFEST_MAGIC: &str = "VOLPAROSSA_NETNS_OWNERSHIP_V1";
const MANIFEST_LEAF: &str = "ownership.v1";
const MANIFEST_PENDING_LEAF: &str = "ownership.pending";
const MAX_MANIFEST_BYTES: usize = 4_096;
const MAX_MANIFEST_RECORDS: usize = 2;
const MANIFEST_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const EMPTY_SLOT_MODE: u32 = 0o000;
const DIRECTORY_BUFFER_BYTES: usize = 4_096;
const MAX_PRIVATE_DIRECTORY_ENTRIES: usize = 3;
#[cfg(test)]
const PRIVATE_NETNS_ROOT_PATH: &str = "/run/netns";
#[cfg(test)]
const PRIVATE_WORKSPACE_ROOT_PATH: &str = "/run/volparossa-netns-runner";
const MAX_ROLLBACK_ENTRIES: usize = 3;

const IDENTITY_STATX_FLAGS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::NLINK)
    .union(StatxFlags::UID)
    .union(StatxFlags::GID)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MNT_ID);

fn descriptor_statx<Fd: AsFd>(descriptor: Fd) -> Result<Statx, OwnershipError> {
    statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        IDENTITY_STATX_FLAGS,
    )
    .map_err(rustix_ownership_io)
}

fn entry_statx<Fd: AsFd>(parent: Fd, name: &str) -> Result<Statx, OwnershipError> {
    statx(
        parent,
        name,
        AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        IDENTITY_STATX_FLAGS,
    )
    .map_err(rustix_ownership_io)
}

fn verify_statx_identity(metadata: &Stat, extended: &Statx) -> Result<(), OwnershipError> {
    let mask = StatxFlags::from_bits_retain(extended.stx_mask);
    let size = u64::try_from(metadata.st_size).map_err(|_| OwnershipError::UnsafeMetadata)?;
    if !mask.contains(IDENTITY_STATX_FLAGS)
        || extended.stx_mnt_id == 0
        || makedev(extended.stx_dev_major, extended.stx_dev_minor) != metadata.st_dev
        || extended.stx_ino != metadata.st_ino
        || u32::from(extended.stx_mode) != metadata.st_mode
        || u64::from(extended.stx_nlink) != metadata.st_nlink
        || extended.stx_uid != metadata.st_uid
        || extended.stx_gid != metadata.st_gid
        || extended.stx_size != size
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NamespaceEndpoint {
    A,
    B,
}

impl NamespaceEndpoint {
    const ALL: [Self; 2] = [Self::A, Self::B];

    const fn suffix(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

fn namespace_name(run_id: &RunId, endpoint: NamespaceEndpoint) -> String {
    format!("vpl-{}-{}", run_id.as_str(), endpoint.suffix())
}

#[cfg(test)]
fn private_workspace_path(run_id: &RunId) -> String {
    format!("{PRIVATE_WORKSPACE_ROOT_PATH}/{}", run_id.as_str())
}

#[derive(Debug, Error)]
enum OwnershipError {
    #[error("namespace ownership manifest is not canonical")]
    Manifest,
    #[error("namespace ownership metadata is unsafe or changed")]
    UnsafeMetadata,
    #[error("namespace ownership observation failed")]
    Io(#[source] io::Error),
}

impl From<io::Error> for OwnershipError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
struct OwnershipManifest {
    run_id: RunId,
    records: Vec<OwnedNamespace>,
}

impl OwnershipManifest {
    fn new(run_id: RunId, records: Vec<OwnedNamespace>) -> Result<Self, OwnershipError> {
        if records.is_empty() || records.len() > MAX_MANIFEST_RECORDS {
            return Err(OwnershipError::Manifest);
        }
        let mut previous_name: Option<&str> = None;
        let mut identities = HashSet::with_capacity(records.len());
        for record in &records {
            let endpoint =
                endpoint_for_name(&run_id, record.name()).ok_or(OwnershipError::Manifest)?;
            if namespace_name(&run_id, endpoint) != record.name()
                || previous_name.is_some_and(|previous| previous >= record.name())
                || !identities.insert(record.identity())
            {
                return Err(OwnershipError::Manifest);
            }
            previous_name = Some(record.name());
        }
        Ok(Self { run_id, records })
    }

    fn parse(expected_run_id: &RunId, bytes: &[u8]) -> Result<Self, OwnershipError> {
        if bytes.is_empty()
            || bytes.len() > MAX_MANIFEST_BYTES
            || !bytes.ends_with(b"\n")
            || bytes.contains(&b'\r')
            || bytes.contains(&0)
        {
            return Err(OwnershipError::Manifest);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| OwnershipError::Manifest)?;
        let body = text.strip_suffix('\n').ok_or(OwnershipError::Manifest)?;
        let lines: Vec<&str> = body.split('\n').collect();
        if !(4..=5).contains(&lines.len())
            || lines[0] != MANIFEST_MAGIC
            || lines.last() != Some(&"END")
            || lines.iter().any(|line| line.is_empty())
        {
            return Err(OwnershipError::Manifest);
        }
        let encoded_run = lines[1]
            .strip_prefix("run_id=")
            .ok_or(OwnershipError::Manifest)?;
        let run_id = RunId::parse(encoded_run).map_err(|_| OwnershipError::Manifest)?;
        if &run_id != expected_run_id {
            return Err(OwnershipError::Manifest);
        }
        let mut records = Vec::with_capacity(lines.len() - 3);
        for line in &lines[2..lines.len() - 1] {
            let mut fields = line.split('\t');
            if fields.next() != Some("namespace") {
                return Err(OwnershipError::Manifest);
            }
            let name = fields.next().ok_or(OwnershipError::Manifest)?;
            let encoded_identity = fields.next().ok_or(OwnershipError::Manifest)?;
            if fields.next().is_some() {
                return Err(OwnershipError::Manifest);
            }
            let (device, inode) = encoded_identity
                .split_once(':')
                .ok_or(OwnershipError::Manifest)?;
            if inode.contains(':') {
                return Err(OwnershipError::Manifest);
            }
            let identity = NamespaceIdentity::new(
                parse_canonical_nonzero_u64(device)?,
                parse_canonical_nonzero_u64(inode)?,
            )
            .map_err(|_| OwnershipError::Manifest)?;
            records.push(
                OwnedNamespace::new(name.to_owned(), identity)
                    .map_err(|_| OwnershipError::Manifest)?,
            );
        }
        let manifest = Self::new(run_id, records)?;
        if manifest.encode().as_bytes() != bytes {
            return Err(OwnershipError::Manifest);
        }
        Ok(manifest)
    }

    fn encode(&self) -> String {
        let mut encoded = format!("{MANIFEST_MAGIC}\nrun_id={}\n", self.run_id.as_str());
        for record in &self.records {
            encoded.push_str(&format!(
                "namespace\t{}\t{}:{}\n",
                record.name(),
                record.identity().device(),
                record.identity().inode()
            ));
        }
        encoded.push_str("END\n");
        encoded
    }

    fn record(&self, endpoint: NamespaceEndpoint) -> Option<&OwnedNamespace> {
        let expected = namespace_name(&self.run_id, endpoint);
        self.records.iter().find(|record| record.name() == expected)
    }

    fn complete_records(&self) -> Result<Vec<OwnedNamespace>, OwnershipError> {
        if self.records.len() != NamespaceEndpoint::ALL.len()
            || NamespaceEndpoint::ALL
                .iter()
                .any(|endpoint| self.record(*endpoint).is_none())
        {
            return Err(OwnershipError::Manifest);
        }
        Ok(self.records.clone())
    }
}

/// Synthetic exact A+B records used only by the tempfile publication model.
///
/// This is deliberately not a live ownership witness. A later production
/// constructor must retain and verify both real nsfs pins before publication.
struct CompleteOwnershipFixture {
    manifest: OwnershipManifest,
    _thread_bound: PhantomData<Rc<()>>,
}

#[cfg(test)]
fn complete_ownership_fixture(
    run_id: RunId,
    endpoint_a: NamespaceIdentity,
    endpoint_b: NamespaceIdentity,
) -> Result<CompleteOwnershipFixture, OwnershipError> {
    let name_a = namespace_name(&run_id, NamespaceEndpoint::A);
    let name_b = namespace_name(&run_id, NamespaceEndpoint::B);
    let manifest = OwnershipManifest::new(
        run_id,
        vec![
            OwnedNamespace::new(name_a, endpoint_a).map_err(|_| OwnershipError::Manifest)?,
            OwnedNamespace::new(name_b, endpoint_b).map_err(|_| OwnershipError::Manifest)?,
        ],
    )?;
    manifest.complete_records()?;
    Ok(CompleteOwnershipFixture {
        manifest,
        _thread_bound: PhantomData,
    })
}

fn endpoint_for_name(run_id: &RunId, name: &str) -> Option<NamespaceEndpoint> {
    NamespaceEndpoint::ALL
        .into_iter()
        .find(|endpoint| namespace_name(run_id, *endpoint) == name)
}

fn parse_canonical_nonzero_u64(value: &str) -> Result<u64, OwnershipError> {
    if value.is_empty()
        || value == "0"
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(OwnershipError::Manifest);
    }
    value.parse().map_err(|_| OwnershipError::Manifest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
}

impl FileIdentity {
    fn from_observations(metadata: &Stat, extended: &Statx) -> Result<Self, OwnershipError> {
        verify_statx_identity(metadata, extended)?;
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mount_id: extended.stx_mnt_id,
            mode: metadata.st_mode,
            links: metadata.st_nlink,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
        })
    }

    fn namespace_identity(self) -> Result<NamespaceIdentity, OwnershipError> {
        NamespaceIdentity::new(self.device, self.inode).map_err(|_| OwnershipError::UnsafeMetadata)
    }

    fn is_regular(self) -> bool {
        FileType::from_raw_mode(self.mode).is_file()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: FileIdentity,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl FileSnapshot {
    fn from_observations(metadata: &Stat, extended: &Statx) -> Result<Self, OwnershipError> {
        Ok(Self {
            identity: FileIdentity::from_observations(metadata, extended)?,
            size: u64::try_from(metadata.st_size).map_err(|_| OwnershipError::UnsafeMetadata)?,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl DirectoryIdentity {
    fn from_observations(metadata: &Stat, extended: &Statx) -> Result<Self, OwnershipError> {
        verify_statx_identity(metadata, extended)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_dir()
            || metadata.st_dev == 0
            || metadata.st_ino == 0
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mount_id: extended.stx_mnt_id,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
        })
    }

    fn is_exclusive_for(self, expected_uid: u32) -> bool {
        self.uid == expected_uid && self.mode & 0o7777 == PRIVATE_DIRECTORY_MODE
    }
}

struct PinnedPrivateDirectory {
    descriptor: File,
    identity: DirectoryIdentity,
    expected_uid: u32,
    _thread_bound: PhantomData<Rc<()>>,
}

struct ExpectedDirectoryEntry<'a> {
    name: &'a str,
    descriptor: &'a File,
    identity: FileIdentity,
}

impl PinnedPrivateDirectory {
    fn pin_at<Fd: AsFd>(directory: Fd) -> Result<Self, OwnershipError> {
        let expected_uid = geteuid().as_raw();
        let before = directory_identity(&directory)?;
        let descriptor = openat2(
            &directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(rustix_ownership_io)?;
        let descriptor = File::from(descriptor);
        let identity = directory_identity(&descriptor)?;
        if before != identity || !identity.is_exclusive_for(expected_uid) {
            return Err(OwnershipError::UnsafeMetadata);
        }
        let pin = Self {
            descriptor,
            identity,
            expected_uid,
            _thread_bound: PhantomData,
        };
        pin.verify()?;
        Ok(pin)
    }

    fn verify(&self) -> Result<(), OwnershipError> {
        let current = directory_identity(&self.descriptor)?;
        if current != self.identity || !current.is_exclusive_for(self.expected_uid) {
            return Err(OwnershipError::UnsafeMetadata);
        }
        Ok(())
    }

    fn verify_exact_entries(
        &self,
        expected: &[ExpectedDirectoryEntry<'_>],
    ) -> Result<(), OwnershipError> {
        self.verify_exact_entries_with_hook(expected, || Ok(()))
    }

    fn verify_exact_entries_with_hook<Hook>(
        &self,
        expected: &[ExpectedDirectoryEntry<'_>],
        after_enumeration: Hook,
    ) -> Result<(), OwnershipError>
    where
        Hook: FnOnce() -> Result<(), OwnershipError>,
    {
        self.verify()?;
        if expected.len() > MAX_PRIVATE_DIRECTORY_ENTRIES
            || expected.iter().enumerate().any(|(index, entry)| {
                entry.name.is_empty()
                    || entry.name == "."
                    || entry.name == ".."
                    || entry.name.as_bytes().contains(&b'/')
                    || entry.name.as_bytes().contains(&0)
                    || expected[index + 1..]
                        .iter()
                        .any(|other| other.name == entry.name || other.identity == entry.identity)
            })
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        let before = file_snapshot(&self.descriptor)?;
        for entry in expected {
            self.verify_expected_entry(entry)?;
        }
        let descriptor = openat2(
            &self.descriptor,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(rustix_ownership_io)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut entries = RawDir::new(descriptor, &mut buffer);
        let mut seen = vec![false; expected.len()];
        let mut count = 0_usize;
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(rustix_ownership_io)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count.checked_add(1).ok_or(OwnershipError::UnsafeMetadata)?;
            if count > MAX_PRIVATE_DIRECTORY_ENTRIES {
                return Err(OwnershipError::UnsafeMetadata);
            }
            let Some(index) = expected
                .iter()
                .position(|expected_entry| expected_entry.name.as_bytes() == name)
            else {
                return Err(OwnershipError::UnsafeMetadata);
            };
            if seen[index] {
                return Err(OwnershipError::UnsafeMetadata);
            }
            if entry_file_identity(&self.descriptor, expected[index].name)?
                != expected[index].identity
            {
                return Err(OwnershipError::UnsafeMetadata);
            }
            seen[index] = true;
        }
        if count != expected.len() || seen.contains(&false) {
            return Err(OwnershipError::UnsafeMetadata);
        }
        after_enumeration()?;
        for entry in expected {
            self.verify_expected_entry(entry)?;
        }
        let after = file_snapshot(&self.descriptor)?;
        if before != after {
            return Err(OwnershipError::UnsafeMetadata);
        }
        self.verify()
    }

    fn verify_expected_entry(
        &self,
        expected: &ExpectedDirectoryEntry<'_>,
    ) -> Result<(), OwnershipError> {
        if file_identity(expected.descriptor)? != expected.identity
            || entry_file_identity(&self.descriptor, expected.name)? != expected.identity
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        Ok(())
    }
}

struct PinnedEmptySlot {
    descriptor: File,
    name: String,
    identity: FileIdentity,
    expected_uid: u32,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PinnedEmptySlot {
    fn verify_at(&self, parent: &PinnedPrivateDirectory) -> Result<(), OwnershipError> {
        parent.verify()?;
        let held = file_snapshot(&self.descriptor)?;
        validate_empty_slot(held, self.expected_uid)?;
        if held.identity != self.identity
            || entry_file_identity(&parent.descriptor, &self.name)? != self.identity
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        parent.verify()
    }
}

struct RollbackEntry {
    parent: File,
    parent_identity: DirectoryIdentity,
    expected_uid: u32,
    descriptor: File,
    identity: FileIdentity,
    name: String,
}

#[derive(Clone, Copy)]
enum ProvisionalEntryShape {
    EmptySlot,
    PendingManifest,
}

#[derive(Clone, Copy)]
enum CreatedEntryState {
    Provisional(ProvisionalEntryShape),
    Validated(FileIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationBoundary {
    OriginBound,
    BeforeModeHardening,
    ModeHardened,
    BeforeSnapshot,
    BeforeValidation,
    BeforePromotion,
}

struct CreatedEntryGuard {
    parent: File,
    parent_identity: DirectoryIdentity,
    expected_uid: u32,
    descriptor: Option<File>,
    state: CreatedEntryState,
    name: String,
}

impl CreatedEntryGuard {
    fn descriptor(&self) -> Result<&File, OwnershipError> {
        self.descriptor
            .as_ref()
            .ok_or(OwnershipError::UnsafeMetadata)
    }

    fn promote_validated(&mut self, expected: FileSnapshot) -> Result<(), OwnershipError> {
        let CreatedEntryState::Provisional(shape) = self.state else {
            return Err(OwnershipError::UnsafeMetadata);
        };
        validate_final_created_entry(shape, expected, self.expected_uid)?;
        verify_private_parent(&self.parent, self.parent_identity, self.expected_uid)?;
        if file_snapshot(self.descriptor()?)? != expected
            || file_snapshot_at(&self.parent, &self.name)? != expected
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        self.state = CreatedEntryState::Validated(expected.identity);
        Ok(())
    }

    fn into_parts(self, expected: FileIdentity) -> Result<(File, RollbackEntry), OwnershipError> {
        self.into_parts_with_hook(expected, || Ok(()))
    }

    fn into_parts_with_hook<Hook>(
        mut self,
        expected: FileIdentity,
        before_handoff: Hook,
    ) -> Result<(File, RollbackEntry), OwnershipError>
    where
        Hook: FnOnce() -> Result<(), OwnershipError>,
    {
        let CreatedEntryState::Validated(identity) = self.state else {
            return Err(OwnershipError::UnsafeMetadata);
        };
        if identity != expected {
            return Err(OwnershipError::UnsafeMetadata);
        }
        before_handoff()?;
        if file_identity(self.descriptor()?)? != expected
            || entry_file_identity(&self.parent, &self.name)? != expected
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        let descriptor = self.descriptor()?;
        let rollback_descriptor = descriptor.try_clone()?;
        let rollback_parent = self.parent.try_clone()?;
        let descriptor = self
            .descriptor
            .take()
            .ok_or(OwnershipError::UnsafeMetadata)?;
        let name = std::mem::take(&mut self.name);
        let entry = RollbackEntry {
            parent: rollback_parent,
            parent_identity: self.parent_identity,
            expected_uid: self.expected_uid,
            descriptor: rollback_descriptor,
            identity: expected,
            name,
        };
        Ok((descriptor, entry))
    }
}

impl Drop for CreatedEntryGuard {
    fn drop(&mut self) {
        let Some(descriptor) = self.descriptor.as_ref() else {
            return;
        };
        match self.state {
            CreatedEntryState::Provisional(shape) => {
                let _ = remove_provisional_entry(
                    &self.parent,
                    self.parent_identity,
                    self.expected_uid,
                    descriptor,
                    shape,
                    &self.name,
                );
            }
            CreatedEntryState::Validated(identity) => {
                let _ = remove_owned_entry(
                    &self.parent,
                    self.parent_identity,
                    self.expected_uid,
                    descriptor,
                    identity,
                    &self.name,
                    |_| Ok(()),
                );
            }
        }
    }
}

struct PreparedJournalRename {
    entry_index: usize,
    new_name: String,
}

#[derive(Clone, Copy)]
struct CommittedJournalRename {
    entry_index: usize,
}

struct RollbackJournal {
    entries: Vec<RollbackEntry>,
    armed: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

struct RemovalFailure {
    error: OwnershipError,
    entry_unlinked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalBoundary {
    UnlinkCommitted,
    AbsenceProved,
    DirectorySynced,
}

impl RollbackJournal {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_ROLLBACK_ENTRIES),
            armed: true,
            _thread_bound: PhantomData,
        }
    }

    fn push(&mut self, entry: RollbackEntry) -> Result<(), Box<RollbackEntry>> {
        if self.entries.len() == MAX_ROLLBACK_ENTRIES {
            return Err(Box::new(entry));
        }
        self.entries.push(entry);
        Ok(())
    }

    fn prepare_last_rename(
        &self,
        old_name: &str,
        new_name: &str,
    ) -> Result<PreparedJournalRename, OwnershipError> {
        let entry_index = self
            .entries
            .len()
            .checked_sub(1)
            .ok_or(OwnershipError::UnsafeMetadata)?;
        let entry = self
            .entries
            .get(entry_index)
            .ok_or(OwnershipError::UnsafeMetadata)?;
        if entry.name != old_name
            || file_identity(&entry.descriptor)? != entry.identity
            || entry_file_identity(&entry.parent, old_name)? != entry.identity
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        Ok(PreparedJournalRename {
            entry_index,
            new_name: new_name.to_owned(),
        })
    }

    fn mark_rename_succeeded(&mut self, prepared: PreparedJournalRename) -> CommittedJournalRename {
        self.entries[prepared.entry_index].name = prepared.new_name;
        CommittedJournalRename {
            entry_index: prepared.entry_index,
        }
    }

    fn verify_committed_rename(
        &self,
        committed: CommittedJournalRename,
    ) -> Result<(), OwnershipError> {
        let entry = self
            .entries
            .get(committed.entry_index)
            .ok_or(OwnershipError::UnsafeMetadata)?;
        if committed.entry_index + 1 != self.entries.len()
            || file_identity(&entry.descriptor)? != entry.identity
            || entry_file_identity(&entry.parent, &entry.name)? != entry.identity
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        Ok(())
    }

    fn rollback_all(&mut self) -> Result<(), OwnershipError> {
        self.rollback_with_hook(|_| {})
    }

    fn rollback_with_hook<Hook>(&mut self, mut removed: Hook) -> Result<(), OwnershipError>
    where
        Hook: FnMut(&str),
    {
        self.rollback_with_hooks(&mut removed, |_, _| Ok(()))
    }

    fn rollback_with_hooks<Removed, Boundary>(
        &mut self,
        mut removed: Removed,
        mut boundary: Boundary,
    ) -> Result<(), OwnershipError>
    where
        Removed: FnMut(&str),
        Boundary: FnMut(&str, RemovalBoundary) -> Result<(), OwnershipError>,
    {
        let mut proof_error = None;
        while let Some(entry) = self.entries.last() {
            let name = entry.name.clone();
            match remove_owned_entry(
                &entry.parent,
                entry.parent_identity,
                entry.expected_uid,
                &entry.descriptor,
                entry.identity,
                &entry.name,
                |point| boundary(&name, point),
            ) {
                Ok(()) => {
                    self.entries.pop();
                    removed(&name);
                }
                Err(failure) if failure.entry_unlinked => {
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
    fn abandon_for_test(&mut self) {
        self.armed = false;
    }
}

fn push_or_rollback(
    journal: &mut RollbackJournal,
    entry: RollbackEntry,
) -> Result<(), OwnershipError> {
    let Err(untracked) = journal.push(entry) else {
        return Ok(());
    };
    let _ = remove_rollback_entry(&untracked);
    let _ = journal.rollback_all();
    Err(OwnershipError::UnsafeMetadata)
}

impl Drop for RollbackJournal {
    fn drop(&mut self) {
        if self.armed {
            // A failed proof must never broaden deletion authority. If an
            // identity or parent check fails, retain the object for the outer
            // disposable-run teardown rather than unlinking an ambiguity.
            let _ = self.rollback_all();
        }
    }
}

fn remove_rollback_entry(entry: &RollbackEntry) -> Result<(), RemovalFailure> {
    remove_owned_entry(
        &entry.parent,
        entry.parent_identity,
        entry.expected_uid,
        &entry.descriptor,
        entry.identity,
        &entry.name,
        |_| Ok(()),
    )
}

fn remove_owned_entry<Boundary>(
    parent: &File,
    parent_identity: DirectoryIdentity,
    expected_uid: u32,
    descriptor: &File,
    identity: FileIdentity,
    name: &str,
    mut boundary: Boundary,
) -> Result<(), RemovalFailure>
where
    Boundary: FnMut(RemovalBoundary) -> Result<(), OwnershipError>,
{
    verify_private_parent(parent, parent_identity, expected_uid).map_err(|error| {
        RemovalFailure {
            error,
            entry_unlinked: false,
        }
    })?;
    let held = file_identity(descriptor).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    let visible = entry_file_identity(parent, name).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    if held != identity || visible != identity {
        return Err(RemovalFailure {
            error: OwnershipError::UnsafeMetadata,
            entry_unlinked: false,
        });
    }
    unlink_verified_entry(parent, parent_identity, expected_uid, name, &mut boundary)
}

fn remove_provisional_entry(
    parent: &File,
    parent_identity: DirectoryIdentity,
    expected_uid: u32,
    descriptor: &File,
    shape: ProvisionalEntryShape,
    name: &str,
) -> Result<(), RemovalFailure> {
    verify_private_parent(parent, parent_identity, expected_uid).map_err(|error| {
        RemovalFailure {
            error,
            entry_unlinked: false,
        }
    })?;
    let held_before = file_snapshot(descriptor).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    let visible_before = file_snapshot_at(parent, name).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    validate_provisional_created_entry(shape, held_before, expected_uid).map_err(|error| {
        RemovalFailure {
            error,
            entry_unlinked: false,
        }
    })?;
    if visible_before != held_before {
        return Err(RemovalFailure {
            error: OwnershipError::UnsafeMetadata,
            entry_unlinked: false,
        });
    }
    verify_private_parent(parent, parent_identity, expected_uid).map_err(|error| {
        RemovalFailure {
            error,
            entry_unlinked: false,
        }
    })?;
    let held_after = file_snapshot(descriptor).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    let visible_after = file_snapshot_at(parent, name).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: false,
    })?;
    validate_provisional_created_entry(shape, held_after, expected_uid).map_err(|error| {
        RemovalFailure {
            error,
            entry_unlinked: false,
        }
    })?;
    if held_before != held_after || visible_after != held_after {
        return Err(RemovalFailure {
            error: OwnershipError::UnsafeMetadata,
            entry_unlinked: false,
        });
    }
    unlink_verified_entry(parent, parent_identity, expected_uid, name, |_| Ok(()))
}

fn unlink_verified_entry<Boundary>(
    parent: &File,
    parent_identity: DirectoryIdentity,
    expected_uid: u32,
    name: &str,
    mut boundary: Boundary,
) -> Result<(), RemovalFailure>
where
    Boundary: FnMut(RemovalBoundary) -> Result<(), OwnershipError>,
{
    unlinkat(parent, name, AtFlags::empty())
        .map_err(rustix_ownership_io)
        .map_err(|error| RemovalFailure {
            error,
            entry_unlinked: false,
        })?;
    boundary(RemovalBoundary::UnlinkCommitted).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: true,
    })?;
    for _ in 0..2 {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            Ok(_) => {
                return Err(RemovalFailure {
                    error: OwnershipError::UnsafeMetadata,
                    entry_unlinked: true,
                });
            }
            Err(error) => {
                return Err(RemovalFailure {
                    error: rustix_ownership_io(error),
                    entry_unlinked: true,
                });
            }
        }
    }
    boundary(RemovalBoundary::AbsenceProved).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: true,
    })?;
    fsync(parent)
        .map_err(rustix_ownership_io)
        .map_err(|error| RemovalFailure {
            error,
            entry_unlinked: true,
        })?;
    boundary(RemovalBoundary::DirectorySynced).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: true,
    })?;
    verify_private_parent(parent, parent_identity, expected_uid).map_err(|error| RemovalFailure {
        error,
        entry_unlinked: true,
    })
}

fn verify_private_parent<Fd: AsFd>(
    descriptor: Fd,
    expected: DirectoryIdentity,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    let current = directory_identity(descriptor)?;
    if current != expected || !current.is_exclusive_for(expected_uid) {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn file_identity<Fd: AsFd>(descriptor: Fd) -> Result<FileIdentity, OwnershipError> {
    Ok(file_snapshot(descriptor)?.identity)
}

fn file_snapshot<Fd: AsFd>(descriptor: Fd) -> Result<FileSnapshot, OwnershipError> {
    let metadata = fstat(&descriptor).map_err(rustix_ownership_io)?;
    let extended = descriptor_statx(descriptor)?;
    FileSnapshot::from_observations(&metadata, &extended)
}

fn file_snapshot_at<Fd: AsFd>(parent: Fd, name: &str) -> Result<FileSnapshot, OwnershipError> {
    let metadata = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_ownership_io)?;
    let extended = entry_statx(parent, name)?;
    FileSnapshot::from_observations(&metadata, &extended)
}

fn entry_file_identity<Fd: AsFd>(parent: Fd, name: &str) -> Result<FileIdentity, OwnershipError> {
    Ok(file_snapshot_at(parent, name)?.identity)
}

fn validate_empty_slot(snapshot: FileSnapshot, expected_uid: u32) -> Result<(), OwnershipError> {
    if !snapshot.identity.is_regular()
        || snapshot.identity.device == 0
        || snapshot.identity.inode == 0
        || snapshot.identity.uid != expected_uid
        || snapshot.identity.mode & 0o7777 != EMPTY_SLOT_MODE
        || snapshot.identity.links != 1
        || snapshot.size != 0
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn validate_pending_manifest_empty(
    snapshot: FileSnapshot,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    if !snapshot.identity.is_regular()
        || snapshot.identity.device == 0
        || snapshot.identity.inode == 0
        || snapshot.identity.uid != expected_uid
        || snapshot.identity.mode & 0o7777 != MANIFEST_MODE
        || snapshot.identity.links != 1
        || snapshot.size != 0
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn validate_provisional_created_entry(
    shape: ProvisionalEntryShape,
    snapshot: FileSnapshot,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    let permissions = snapshot.identity.mode & 0o7777;
    let permissions_are_bounded = match shape {
        ProvisionalEntryShape::EmptySlot => permissions == EMPTY_SLOT_MODE,
        ProvisionalEntryShape::PendingManifest => permissions & !MANIFEST_MODE == 0,
    };
    if geteuid().as_raw() != expected_uid
        || !snapshot.identity.is_regular()
        || snapshot.identity.device == 0
        || snapshot.identity.inode == 0
        || snapshot.identity.uid != expected_uid
        || snapshot.identity.links != 1
        || snapshot.size != 0
        || !permissions_are_bounded
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn validate_final_created_entry(
    shape: ProvisionalEntryShape,
    snapshot: FileSnapshot,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    match shape {
        ProvisionalEntryShape::EmptySlot => validate_empty_slot(snapshot, expected_uid),
        ProvisionalEntryShape::PendingManifest => {
            validate_pending_manifest_empty(snapshot, expected_uid)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageBoundary {
    RootsPinned,
    EndpointAStored,
    EndpointBStored,
}

struct StagedPrivateRunLayout {
    // Keep the affine cleanup authority first, so normal field destruction
    // cannot discard the pins which its rollback proof relies upon.
    journal: RollbackJournal,
    workspace: PinnedPrivateDirectory,
    netns_root: PinnedPrivateDirectory,
    slots: [PinnedEmptySlot; 2],
    run_id: RunId,
    _thread_bound: PhantomData<Rc<()>>,
}

impl StagedPrivateRunLayout {
    fn verify_roots_and_slots(&self) -> Result<(), OwnershipError> {
        self.workspace.verify()?;
        self.netns_root.verify()?;
        if self.workspace.identity == self.netns_root.identity {
            return Err(OwnershipError::UnsafeMetadata);
        }
        for slot in &self.slots {
            slot.verify_at(&self.netns_root)?;
        }
        self.netns_root.verify_exact_entries(&[
            ExpectedDirectoryEntry {
                name: &self.slots[0].name,
                descriptor: &self.slots[0].descriptor,
                identity: self.slots[0].identity,
            },
            ExpectedDirectoryEntry {
                name: &self.slots[1].name,
                descriptor: &self.slots[1].descriptor,
                identity: self.slots[1].identity,
            },
        ])?;
        Ok(())
    }

    fn verify_staged(&self) -> Result<(), OwnershipError> {
        self.verify_roots_and_slots()?;
        self.workspace.verify_exact_entries(&[])
    }

    fn rollback(mut self) -> Result<(), OwnershipError> {
        self.journal.rollback_all()
    }
}

fn stage_private_run_at<WorkspaceFd: AsFd, NetnsFd: AsFd>(
    workspace: WorkspaceFd,
    netns_root: NetnsFd,
    run_id: RunId,
) -> Result<StagedPrivateRunLayout, OwnershipError> {
    stage_private_run_at_with_hook(workspace, netns_root, run_id, |_| Ok(()))
}

fn stage_private_run_at_with_hook<WorkspaceFd: AsFd, NetnsFd: AsFd, Hook>(
    workspace: WorkspaceFd,
    netns_root: NetnsFd,
    run_id: RunId,
    mut boundary: Hook,
) -> Result<StagedPrivateRunLayout, OwnershipError>
where
    Hook: FnMut(StageBoundary) -> Result<(), OwnershipError>,
{
    let workspace = PinnedPrivateDirectory::pin_at(workspace)?;
    let netns_root = PinnedPrivateDirectory::pin_at(netns_root)?;
    if workspace.identity == netns_root.identity {
        return Err(OwnershipError::UnsafeMetadata);
    }
    workspace.verify_exact_entries(&[])?;
    netns_root.verify_exact_entries(&[])?;
    boundary(StageBoundary::RootsPinned)?;

    let mut journal = RollbackJournal::new();
    let (endpoint_a, entry_a) =
        match create_empty_slot(&netns_root, namespace_name(&run_id, NamespaceEndpoint::A)) {
            Ok(created) => created,
            Err(error) => return Err(error_after_rollback(&mut journal, error)),
        };
    push_or_rollback(&mut journal, entry_a)?;
    if let Err(error) = netns_root.verify_exact_entries(&[ExpectedDirectoryEntry {
        name: &endpoint_a.name,
        descriptor: &endpoint_a.descriptor,
        identity: endpoint_a.identity,
    }]) {
        return Err(error_after_rollback(&mut journal, error));
    }
    if let Err(error) = boundary(StageBoundary::EndpointAStored) {
        return Err(error_after_rollback(&mut journal, error));
    }

    let (endpoint_b, entry_b) =
        match create_empty_slot(&netns_root, namespace_name(&run_id, NamespaceEndpoint::B)) {
            Ok(created) => created,
            Err(error) => return Err(error_after_rollback(&mut journal, error)),
        };
    push_or_rollback(&mut journal, entry_b)?;
    if let Err(error) = netns_root.verify_exact_entries(&[
        ExpectedDirectoryEntry {
            name: &endpoint_a.name,
            descriptor: &endpoint_a.descriptor,
            identity: endpoint_a.identity,
        },
        ExpectedDirectoryEntry {
            name: &endpoint_b.name,
            descriptor: &endpoint_b.descriptor,
            identity: endpoint_b.identity,
        },
    ]) {
        return Err(error_after_rollback(&mut journal, error));
    }
    if let Err(error) = boundary(StageBoundary::EndpointBStored) {
        return Err(error_after_rollback(&mut journal, error));
    }

    let layout = StagedPrivateRunLayout {
        journal,
        workspace,
        netns_root,
        slots: [endpoint_a, endpoint_b],
        run_id,
        _thread_bound: PhantomData,
    };
    layout.verify_staged()?;
    Ok(layout)
}

fn create_empty_slot(
    parent: &PinnedPrivateDirectory,
    name: String,
) -> Result<(PinnedEmptySlot, RollbackEntry), OwnershipError> {
    create_empty_slot_with_hooks(parent, name, |_| Ok(()), CreatedEntryGuard::into_parts)
}

fn create_empty_slot_with_handoff_hook<Hook>(
    parent: &PinnedPrivateDirectory,
    name: String,
    before_handoff: Hook,
) -> Result<(PinnedEmptySlot, RollbackEntry), OwnershipError>
where
    Hook: FnOnce() -> Result<(), OwnershipError>,
{
    create_empty_slot_with_hooks(
        parent,
        name,
        |_| Ok(()),
        |guard, identity| guard.into_parts_with_hook(identity, before_handoff),
    )
}

fn create_empty_slot_with_creation_hook<Boundary>(
    parent: &PinnedPrivateDirectory,
    name: String,
    boundary: Boundary,
) -> Result<(PinnedEmptySlot, RollbackEntry), OwnershipError>
where
    Boundary: FnMut(CreationBoundary) -> Result<(), OwnershipError>,
{
    create_empty_slot_with_hooks(parent, name, boundary, CreatedEntryGuard::into_parts)
}

fn create_empty_slot_with_hooks<Boundary, Finalize>(
    parent: &PinnedPrivateDirectory,
    name: String,
    mut boundary: Boundary,
    finalize: Finalize,
) -> Result<(PinnedEmptySlot, RollbackEntry), OwnershipError>
where
    Boundary: FnMut(CreationBoundary) -> Result<(), OwnershipError>,
    Finalize:
        FnOnce(CreatedEntryGuard, FileIdentity) -> Result<(File, RollbackEntry), OwnershipError>,
{
    parent.verify()?;
    let rollback_parent = parent.descriptor.try_clone()?;
    let guard_name = name.clone();
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
    .map_err(rustix_ownership_io)?;
    let mut guard = CreatedEntryGuard {
        parent: rollback_parent,
        parent_identity: parent.identity,
        expected_uid: parent.expected_uid,
        descriptor: Some(File::from(descriptor)),
        state: CreatedEntryState::Provisional(ProvisionalEntryShape::EmptySlot),
        name: guard_name,
    };
    boundary(CreationBoundary::OriginBound)?;
    boundary(CreationBoundary::BeforeSnapshot)?;
    let snapshot = file_snapshot(guard.descriptor()?)?;
    boundary(CreationBoundary::BeforeValidation)?;
    validate_empty_slot(snapshot, parent.expected_uid)?;
    parent.verify()?;
    if entry_file_identity(&parent.descriptor, &name)? != snapshot.identity {
        return Err(OwnershipError::UnsafeMetadata);
    }
    boundary(CreationBoundary::BeforePromotion)?;
    guard.promote_validated(snapshot)?;
    let (descriptor, entry) = finalize(guard, snapshot.identity)?;
    Ok((
        PinnedEmptySlot {
            descriptor,
            name,
            identity: snapshot.identity,
            expected_uid: parent.expected_uid,
            _thread_bound: PhantomData,
        },
        entry,
    ))
}

fn error_after_rollback(journal: &mut RollbackJournal, original: OwnershipError) -> OwnershipError {
    if journal.rollback_all().is_ok() {
        original
    } else {
        OwnershipError::UnsafeMetadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishBoundary {
    PendingCreated,
    BytesWritten,
    FileSynced,
    ReadBack,
    Renamed,
    DirectorySynced,
    ManifestPinned,
}

struct PublishedPrivateRunLayout {
    layout: StagedPrivateRunLayout,
    manifest_pin: ManifestPin,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PublishedPrivateRunLayout {
    fn verify(&self) -> Result<(), OwnershipError> {
        self.layout.verify_roots_and_slots()?;
        self.layout
            .workspace
            .verify_exact_entries(&[ExpectedDirectoryEntry {
                name: MANIFEST_LEAF,
                descriptor: &self.manifest_pin.descriptor,
                identity: self.manifest_pin.metadata.identity,
            }])?;
        self.manifest_pin
            .verify_at(&self.layout.workspace.descriptor)
    }

    fn rollback(self) -> Result<(), OwnershipError> {
        self.layout.rollback()
    }
}

fn publish_ownership_manifest(
    layout: StagedPrivateRunLayout,
    witness: CompleteOwnershipFixture,
) -> Result<PublishedPrivateRunLayout, OwnershipError> {
    publish_ownership_manifest_with_hook(layout, witness, |_| Ok(()))
}

fn publish_ownership_manifest_with_hook<Hook>(
    mut layout: StagedPrivateRunLayout,
    witness: CompleteOwnershipFixture,
    mut boundary: Hook,
) -> Result<PublishedPrivateRunLayout, OwnershipError>
where
    Hook: FnMut(PublishBoundary) -> Result<(), OwnershipError>,
{
    let CompleteOwnershipFixture {
        manifest,
        _thread_bound,
    } = witness;
    let result = (|| {
        layout.verify_staged()?;
        manifest.complete_records()?;
        if manifest.run_id != layout.run_id {
            return Err(OwnershipError::Manifest);
        }
        let bytes = manifest.encode().into_bytes();
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(OwnershipError::Manifest);
        }

        let (pending, entry) = create_pending_manifest(&layout.workspace)?;
        let pending_identity = entry.identity;
        push_or_rollback(&mut layout.journal, entry)?;
        layout
            .workspace
            .verify_exact_entries(&[ExpectedDirectoryEntry {
                name: MANIFEST_PENDING_LEAF,
                descriptor: &pending,
                identity: pending_identity,
            }])?;
        boundary(PublishBoundary::PendingCreated)?;

        write_exact(&pending, &bytes)?;
        boundary(PublishBoundary::BytesWritten)?;
        fsync(&pending).map_err(rustix_ownership_io)?;
        boundary(PublishBoundary::FileSynced)?;

        let readback = snapshot_manifest_descriptor(
            &pending,
            &manifest.run_id,
            layout.workspace.expected_uid,
        )?;
        if readback.bytes != bytes || readback.manifest.encode() != manifest.encode() {
            return Err(OwnershipError::UnsafeMetadata);
        }
        boundary(PublishBoundary::ReadBack)?;

        layout.workspace.verify()?;
        let prepared_rename = layout
            .journal
            .prepare_last_rename(MANIFEST_PENDING_LEAF, MANIFEST_LEAF)?;
        renameat_with(
            &layout.workspace.descriptor,
            MANIFEST_PENDING_LEAF,
            &layout.workspace.descriptor,
            MANIFEST_LEAF,
            RenameFlags::NOREPLACE,
        )
        .map_err(rustix_ownership_io)?;
        let committed_rename = layout.journal.mark_rename_succeeded(prepared_rename);
        boundary(PublishBoundary::Renamed)?;
        layout.journal.verify_committed_rename(committed_rename)?;
        layout
            .workspace
            .verify_exact_entries(&[ExpectedDirectoryEntry {
                name: MANIFEST_LEAF,
                descriptor: &pending,
                identity: pending_identity,
            }])?;

        fsync(&layout.workspace.descriptor).map_err(rustix_ownership_io)?;
        boundary(PublishBoundary::DirectorySynced)?;
        let manifest_pin = pin_manifest_at(&layout.workspace.descriptor, &manifest.run_id)?;
        if manifest_pin.metadata.identity != readback.metadata.identity
            || manifest_pin.bytes != bytes
            || manifest_pin.digest != readback.digest
        {
            return Err(OwnershipError::UnsafeMetadata);
        }
        manifest_pin.verify_at(&layout.workspace.descriptor)?;
        layout.verify_roots_and_slots()?;
        layout
            .workspace
            .verify_exact_entries(&[ExpectedDirectoryEntry {
                name: MANIFEST_LEAF,
                descriptor: &manifest_pin.descriptor,
                identity: manifest_pin.metadata.identity,
            }])?;
        boundary(PublishBoundary::ManifestPinned)?;
        Ok(manifest_pin)
    })();

    match result {
        Ok(manifest_pin) => Ok(PublishedPrivateRunLayout {
            layout,
            manifest_pin,
            _thread_bound: PhantomData,
        }),
        Err(error) => Err(error_after_rollback(&mut layout.journal, error)),
    }
}

fn create_pending_manifest(
    parent: &PinnedPrivateDirectory,
) -> Result<(File, RollbackEntry), OwnershipError> {
    create_pending_manifest_with_hooks(parent, |_| Ok(()), CreatedEntryGuard::into_parts)
}

fn create_pending_manifest_with_handoff_hook<Hook>(
    parent: &PinnedPrivateDirectory,
    before_handoff: Hook,
) -> Result<(File, RollbackEntry), OwnershipError>
where
    Hook: FnOnce() -> Result<(), OwnershipError>,
{
    create_pending_manifest_with_hooks(
        parent,
        |_| Ok(()),
        |guard, identity| guard.into_parts_with_hook(identity, before_handoff),
    )
}

fn create_pending_manifest_with_creation_hook<Boundary>(
    parent: &PinnedPrivateDirectory,
    boundary: Boundary,
) -> Result<(File, RollbackEntry), OwnershipError>
where
    Boundary: FnMut(CreationBoundary) -> Result<(), OwnershipError>,
{
    create_pending_manifest_with_hooks(parent, boundary, CreatedEntryGuard::into_parts)
}

fn create_pending_manifest_with_hooks<Boundary, Finalize>(
    parent: &PinnedPrivateDirectory,
    mut boundary: Boundary,
    finalize: Finalize,
) -> Result<(File, RollbackEntry), OwnershipError>
where
    Boundary: FnMut(CreationBoundary) -> Result<(), OwnershipError>,
    Finalize:
        FnOnce(CreatedEntryGuard, FileIdentity) -> Result<(File, RollbackEntry), OwnershipError>,
{
    parent.verify()?;
    let rollback_parent = parent.descriptor.try_clone()?;
    let guard_name = MANIFEST_PENDING_LEAF.to_owned();
    let descriptor = openat2(
        &parent.descriptor,
        MANIFEST_PENDING_LEAF,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(MANIFEST_MODE),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(rustix_ownership_io)?;
    let mut guard = CreatedEntryGuard {
        parent: rollback_parent,
        parent_identity: parent.identity,
        expected_uid: parent.expected_uid,
        descriptor: Some(File::from(descriptor)),
        state: CreatedEntryState::Provisional(ProvisionalEntryShape::PendingManifest),
        name: guard_name,
    };
    boundary(CreationBoundary::OriginBound)?;
    boundary(CreationBoundary::BeforeModeHardening)?;
    fchmod(guard.descriptor()?, Mode::from_raw_mode(MANIFEST_MODE)).map_err(rustix_ownership_io)?;
    boundary(CreationBoundary::ModeHardened)?;
    boundary(CreationBoundary::BeforeSnapshot)?;
    let snapshot = file_snapshot(guard.descriptor()?)?;
    boundary(CreationBoundary::BeforeValidation)?;
    validate_pending_manifest_empty(snapshot, parent.expected_uid)?;
    if entry_file_identity(&parent.descriptor, MANIFEST_PENDING_LEAF)? != snapshot.identity {
        return Err(OwnershipError::UnsafeMetadata);
    }
    parent.verify()?;
    boundary(CreationBoundary::BeforePromotion)?;
    guard.promote_validated(snapshot)?;
    let (descriptor, entry) = finalize(guard, snapshot.identity)?;
    Ok((descriptor, entry))
}

fn write_exact<Fd: AsFd>(descriptor: Fd, bytes: &[u8]) -> Result<(), OwnershipError> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match write(&descriptor, remaining) {
            Ok(0) => return Err(OwnershipError::UnsafeMetadata),
            Ok(written) => remaining = &remaining[written..],
            Err(Errno::INTR) => {}
            Err(error) => return Err(rustix_ownership_io(error)),
        }
    }
    Ok(())
}

struct ManifestSnapshot {
    metadata: FileSnapshot,
    bytes: Vec<u8>,
    digest: LifecycleSha256,
    manifest: OwnershipManifest,
}

struct ManifestPin {
    descriptor: File,
    expected_uid: u32,
    workspace_identity: DirectoryIdentity,
    metadata: FileSnapshot,
    bytes: Vec<u8>,
    digest: LifecycleSha256,
    manifest: OwnershipManifest,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ManifestPin {
    fn verify_at<Fd: AsFd>(&self, workspace: Fd) -> Result<(), OwnershipError> {
        verify_directory(&workspace, self.workspace_identity)?;
        let held = snapshot_manifest_descriptor(
            &self.descriptor,
            &self.manifest.run_id,
            self.expected_uid,
        )?;
        ensure_same_manifest(self, &held)?;
        verify_manifest_entry(&workspace, &held.metadata)?;

        let (reopened, current) =
            open_manifest_at(&workspace, &self.manifest.run_id, self.expected_uid)?;
        ensure_same_manifest(self, &current)?;
        drop(reopened);
        verify_directory(&workspace, self.workspace_identity)?;
        Ok(())
    }
}

fn ensure_same_manifest(
    pin: &ManifestPin,
    snapshot: &ManifestSnapshot,
) -> Result<(), OwnershipError> {
    if snapshot.metadata != pin.metadata
        || snapshot.bytes != pin.bytes
        || snapshot.digest != pin.digest
        || snapshot.manifest.encode() != pin.manifest.encode()
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn pin_manifest_at<Fd: AsFd>(
    workspace: Fd,
    expected_run_id: &RunId,
) -> Result<ManifestPin, OwnershipError> {
    let expected_uid = geteuid().as_raw();
    let workspace_identity = directory_identity(&workspace)?;
    let (descriptor, snapshot) = open_manifest_at(&workspace, expected_run_id, expected_uid)?;
    verify_directory(&workspace, workspace_identity)?;
    Ok(ManifestPin {
        descriptor,
        expected_uid,
        workspace_identity,
        metadata: snapshot.metadata,
        bytes: snapshot.bytes,
        digest: snapshot.digest,
        manifest: snapshot.manifest,
        _thread_bound: PhantomData,
    })
}

fn open_manifest_at<Fd: AsFd>(
    workspace: Fd,
    expected_run_id: &RunId,
    expected_uid: u32,
) -> Result<(File, ManifestSnapshot), OwnershipError> {
    open_manifest_at_with_hook(workspace, expected_run_id, expected_uid, || Ok(()))
}

fn open_manifest_at_with_hook<Fd: AsFd, Hook>(
    workspace: Fd,
    expected_run_id: &RunId,
    expected_uid: u32,
    before_entry_recheck: Hook,
) -> Result<(File, ManifestSnapshot), OwnershipError>
where
    Hook: FnOnce() -> Result<(), OwnershipError>,
{
    let descriptor = openat2(
        &workspace,
        MANIFEST_LEAF,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| OwnershipError::Io(rustix_io(error)))?;
    let descriptor = File::from(descriptor);
    let snapshot = snapshot_manifest_descriptor(&descriptor, expected_run_id, expected_uid)?;
    before_entry_recheck()?;
    verify_manifest_entry(workspace, &snapshot.metadata)?;
    Ok((descriptor, snapshot))
}

fn snapshot_manifest_descriptor(
    descriptor: &File,
    expected_run_id: &RunId,
    expected_uid: u32,
) -> Result<ManifestSnapshot, OwnershipError> {
    snapshot_manifest_descriptor_with_hook(descriptor, expected_run_id, expected_uid, || Ok(()))
}

fn snapshot_manifest_descriptor_with_hook<Hook>(
    descriptor: &File,
    expected_run_id: &RunId,
    expected_uid: u32,
    between_reads: Hook,
) -> Result<ManifestSnapshot, OwnershipError>
where
    Hook: FnOnce() -> Result<(), OwnershipError>,
{
    let before = file_snapshot(descriptor)?;
    validate_manifest_metadata(before, expected_uid)?;
    let first = read_bounded_at(descriptor)?;
    between_reads()?;
    let middle = file_snapshot(descriptor)?;
    let second = read_bounded_at(descriptor)?;
    let after = file_snapshot(descriptor)?;
    if before != middle || middle != after || first != second || first.len() as u64 != before.size {
        return Err(OwnershipError::UnsafeMetadata);
    }
    let manifest = OwnershipManifest::parse(expected_run_id, &first)?;
    let digest = LifecycleSha256::digest(&first);
    Ok(ManifestSnapshot {
        metadata: before,
        bytes: first,
        digest,
        manifest,
    })
}

fn validate_manifest_metadata(
    metadata: FileSnapshot,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    if !metadata.identity.is_regular()
        || metadata.identity.device == 0
        || metadata.identity.inode == 0
        || metadata.identity.uid != expected_uid
        || metadata.identity.mode & 0o7777 != MANIFEST_MODE
        || metadata.identity.links != 1
        || metadata.size == 0
        || metadata.size > MAX_MANIFEST_BYTES as u64
    {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn read_bounded_at<Fd: AsFd>(descriptor: Fd) -> Result<Vec<u8>, OwnershipError> {
    let mut bytes = Vec::with_capacity(MAX_MANIFEST_BYTES + 1);
    while bytes.len() <= MAX_MANIFEST_BYTES {
        let mut chunk = [0_u8; 512];
        let remaining = MAX_MANIFEST_BYTES + 1 - bytes.len();
        let read = pread(
            &descriptor,
            &mut chunk[..remaining.min(512)],
            bytes.len() as u64,
        )
        .map_err(rustix_ownership_io)?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(OwnershipError::Manifest);
        }
    }
    Err(OwnershipError::Manifest)
}

fn verify_manifest_entry<Fd: AsFd>(
    workspace: Fd,
    expected: &FileSnapshot,
) -> Result<(), OwnershipError> {
    let entry = file_snapshot_at(workspace, MANIFEST_LEAF)?;
    if &entry != expected {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

enum OwnershipObservation {
    Absent,
    Owned(NamespacePin),
    Foreign,
}

struct NamespacePin {
    descriptor: File,
    root_identity: DirectoryIdentity,
    endpoint: NamespaceEndpoint,
    name: String,
    identity: NamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

impl NamespacePin {
    fn verify_at<Fd: AsFd>(&self, netns_root: Fd) -> Result<(), OwnershipError> {
        verify_directory(&netns_root, self.root_identity)?;
        let held = namespace_metadata(&self.descriptor)?;
        if held.identity.namespace_identity()? != self.identity || !held.identity.is_regular() {
            return Err(OwnershipError::UnsafeMetadata);
        }
        let (descriptor, reopened) = open_namespace_at(&netns_root, &self.name)?;
        if reopened.identity.namespace_identity()? != self.identity || reopened != held {
            return Err(OwnershipError::UnsafeMetadata);
        }
        verify_namespace_entry(&netns_root, &self.name, &reopened)?;
        drop(descriptor);
        verify_directory(&netns_root, self.root_identity)?;
        Ok(())
    }
}

fn observe_namespace_at<ManifestFd: AsFd, NetnsFd: AsFd>(
    manifest_workspace: ManifestFd,
    netns_root: NetnsFd,
    manifest_pin: &ManifestPin,
    endpoint: NamespaceEndpoint,
) -> Result<OwnershipObservation, OwnershipError> {
    manifest_pin.verify_at(&manifest_workspace)?;
    let root_identity = directory_identity(&netns_root)?;
    let expected = manifest_pin
        .manifest
        .record(endpoint)
        .ok_or(OwnershipError::Manifest)?;
    let name = namespace_name(&manifest_pin.manifest.run_id, endpoint);
    let first = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => file_snapshot_at(&netns_root, &name)?,
        Err(Errno::NOENT) => {
            manifest_pin.verify_at(&manifest_workspace)?;
            let observation = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => OwnershipObservation::Absent,
                Ok(_) => OwnershipObservation::Foreign,
                Err(error) => return Err(rustix_ownership_io(error)),
            };
            manifest_pin.verify_at(&manifest_workspace)?;
            if matches!(observation, OwnershipObservation::Absent) {
                verify_directory(&netns_root, root_identity)?;
            }
            return Ok(observation);
        }
        Err(error) => return Err(rustix_ownership_io(error)),
    };
    if !first.identity.is_regular() || first.identity.namespace_identity()? != expected.identity() {
        manifest_pin.verify_at(&manifest_workspace)?;
        verify_directory(&netns_root, root_identity)?;
        return Ok(OwnershipObservation::Foreign);
    }
    let (descriptor, opened) = open_namespace_at(&netns_root, &name)?;
    let final_entry = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => file_snapshot_at(&netns_root, &name)?,
        Err(error) => return Err(rustix_ownership_io(error)),
    };
    manifest_pin.verify_at(&manifest_workspace)?;
    verify_directory(&netns_root, root_identity)?;
    if first != opened
        || opened != final_entry
        || !opened.identity.is_regular()
        || opened.identity.namespace_identity()? != expected.identity()
    {
        return Ok(OwnershipObservation::Foreign);
    }
    Ok(OwnershipObservation::Owned(NamespacePin {
        descriptor,
        root_identity,
        endpoint,
        name,
        identity: expected.identity(),
        _thread_bound: PhantomData,
    }))
}

fn open_namespace_at<Fd: AsFd>(
    netns_root: Fd,
    name: &str,
) -> Result<(File, FileSnapshot), OwnershipError> {
    let descriptor = openat2(
        netns_root,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(rustix_ownership_io)?;
    let descriptor = File::from(descriptor);
    let metadata = namespace_metadata(&descriptor)?;
    Ok((descriptor, metadata))
}

fn namespace_metadata<Fd: AsFd>(descriptor: Fd) -> Result<FileSnapshot, OwnershipError> {
    file_snapshot(descriptor)
}

fn directory_identity<Fd: AsFd>(descriptor: Fd) -> Result<DirectoryIdentity, OwnershipError> {
    let metadata = fstat(&descriptor).map_err(rustix_ownership_io)?;
    let extended = descriptor_statx(descriptor)?;
    DirectoryIdentity::from_observations(&metadata, &extended)
}

fn verify_directory<Fd: AsFd>(
    descriptor: Fd,
    expected: DirectoryIdentity,
) -> Result<(), OwnershipError> {
    if directory_identity(descriptor)? != expected {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn verify_namespace_entry<Fd: AsFd>(
    netns_root: Fd,
    name: &str,
    expected: &FileSnapshot,
) -> Result<(), OwnershipError> {
    if file_snapshot_at(netns_root, name)? != *expected {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn rustix_ownership_io(error: Errno) -> OwnershipError {
    OwnershipError::Io(rustix_io(error))
}

fn rustix_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

    use rustix::fs::{Mode, mkfifoat};
    use tempfile::TempDir;

    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_RUN: &str = "fedcba9876543210fedcba9876543210";

    fn run_id() -> RunId {
        RunId::parse(RUN).expect("fixed run id")
    }

    fn owned(
        run_id: &RunId,
        endpoint: NamespaceEndpoint,
        device: u64,
        inode: u64,
    ) -> OwnedNamespace {
        OwnedNamespace::new(
            namespace_name(run_id, endpoint),
            NamespaceIdentity::new(device, inode).expect("nonzero fixture identity"),
        )
        .expect("fixed owned namespace")
    }

    fn complete_manifest() -> OwnershipManifest {
        let run_id = run_id();
        OwnershipManifest::new(
            run_id.clone(),
            vec![
                owned(&run_id, NamespaceEndpoint::A, 11, 101),
                owned(&run_id, NamespaceEndpoint::B, 11, 102),
            ],
        )
        .expect("complete manifest")
    }

    fn open_directory(path: &Path) -> File {
        File::open(path).expect("open fixture directory")
    }

    fn write_private_manifest(directory: &Path, encoded: &[u8]) {
        let path = directory.join(MANIFEST_LEAF);
        fs::write(&path, encoded).expect("write manifest fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(MANIFEST_MODE))
            .expect("set manifest fixture mode");
    }

    fn record_for_path(run_id: &RunId, endpoint: NamespaceEndpoint, path: &Path) -> OwnedNamespace {
        let metadata = fs::metadata(path).expect("namespace fixture metadata");
        owned(run_id, endpoint, metadata.dev(), metadata.ino())
    }

    struct PrivateRoots {
        _fixture: TempDir,
        workspace_path: PathBuf,
        netns_path: PathBuf,
        workspace: File,
        netns_root: File,
    }

    fn private_roots() -> PrivateRoots {
        let fixture = TempDir::new().expect("private roots fixture");
        let workspace_path = fixture.path().join("workspace");
        let netns_path = fixture.path().join("netns");
        fs::create_dir(&workspace_path).expect("workspace root");
        fs::create_dir(&netns_path).expect("netns root");
        for path in [&workspace_path, &netns_path] {
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .expect("private root mode");
        }
        let workspace = open_directory(&workspace_path);
        let netns_root = open_directory(&netns_path);
        PrivateRoots {
            _fixture: fixture,
            workspace_path,
            netns_path,
            workspace,
            netns_root,
        }
    }

    fn fixture_witness() -> CompleteOwnershipFixture {
        complete_ownership_fixture(
            run_id(),
            NamespaceIdentity::new(21, 201).expect("endpoint A identity"),
            NamespaceIdentity::new(21, 202).expect("endpoint B identity"),
        )
        .expect("complete witness")
    }

    fn assert_empty(path: &Path) {
        assert_eq!(fs::read_dir(path).expect("read private root").count(), 0);
    }

    #[test]
    fn canonical_manifest_matches_shell_names_bytes_and_topology_records() {
        let manifest = complete_manifest();
        let expected = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\n\
             namespace\tvpl-{RUN}-a\t11:101\n\
             namespace\tvpl-{RUN}-b\t11:102\n\
             END\n"
        );
        assert_eq!(manifest.encode(), expected);
        let parsed = OwnershipManifest::parse(&run_id(), expected.as_bytes())
            .expect("canonical manifest parses");
        assert_eq!(parsed.encode(), expected);
        assert_eq!(
            namespace_name(&run_id(), NamespaceEndpoint::A),
            format!("vpl-{RUN}-a")
        );
        assert_eq!(
            namespace_name(&run_id(), NamespaceEndpoint::B),
            format!("vpl-{RUN}-b")
        );
        assert!(namespace_name(&run_id(), NamespaceEndpoint::A).len() <= 63);

        let records = parsed.complete_records().expect("complete records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name(), format!("vpl-{RUN}-a"));
        assert_eq!(records[1].name(), format!("vpl-{RUN}-b"));

        let partial = OwnershipManifest::new(
            run_id(),
            vec![owned(&run_id(), NamespaceEndpoint::A, 11, 101)],
        )
        .expect("partial rollback manifest");
        assert!(partial.complete_records().is_err());

        let maximum = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\nnamespace\tvpl-{RUN}-a\t18446744073709551615:18446744073709551615\nEND\n"
        );
        assert_eq!(
            OwnershipManifest::parse(&run_id(), maximum.as_bytes())
                .expect("u64 maximum")
                .encode(),
            maximum
        );
    }

    #[test]
    fn manifest_codec_rejects_every_noncanonical_shape_identity_and_scope() {
        let valid = complete_manifest().encode();
        let other_run = valid.replace(RUN, OTHER_RUN);
        let reverse = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\nnamespace\tvpl-{RUN}-b\t11:102\nnamespace\tvpl-{RUN}-a\t11:101\nEND\n"
        );
        let duplicate_name = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\nnamespace\tvpl-{RUN}-a\t11:101\nnamespace\tvpl-{RUN}-a\t11:102\nEND\n"
        );
        let duplicate_identity = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\nnamespace\tvpl-{RUN}-a\t11:101\nnamespace\tvpl-{RUN}-b\t11:101\nEND\n"
        );
        let three_records = format!(
            "{MANIFEST_MAGIC}\nrun_id={RUN}\nnamespace\tvpl-{RUN}-a\t11:101\nnamespace\tvpl-{RUN}-b\t11:102\nnamespace\tvpl-{RUN}-b\t11:103\nEND\n"
        );
        let mut non_utf8 = valid.clone().into_bytes();
        non_utf8[0] = 0xff;
        let mut vectors = vec![
            Vec::new(),
            valid.trim_end_matches('\n').as_bytes().to_vec(),
            valid.replace(MANIFEST_MAGIC, "WRONG").into_bytes(),
            other_run.into_bytes(),
            valid.replace("-a\t", "-c\t").into_bytes(),
            reverse.into_bytes(),
            duplicate_name.into_bytes(),
            duplicate_identity.into_bytes(),
            valid.replace("11:101", "011:101").into_bytes(),
            valid.replace("11:101", "11:0").into_bytes(),
            valid
                .replace("11:101", "18446744073709551616:101")
                .into_bytes(),
            valid.replace('\n', "\r\n").into_bytes(),
            format!("{valid}EXTRA\n").into_bytes(),
            valid.replace("\nEND", "\n\nEND").into_bytes(),
            valid.replace("namespace\t", "namespace\t\t").into_bytes(),
            valid.replace("11:101", "11:101:1").into_bytes(),
            three_records.into_bytes(),
            non_utf8,
        ];
        let mut nul = valid.into_bytes();
        nul[0] = 0;
        vectors.push(nul);
        vectors.push(vec![b'x'; MAX_MANIFEST_BYTES + 1]);
        for vector in vectors {
            assert!(OwnershipManifest::parse(&run_id(), &vector).is_err());
        }
    }

    #[test]
    fn private_manifest_pin_is_stable_and_detects_content_and_entry_replacement() {
        let fixture = TempDir::new().expect("fixture");
        let encoded = complete_manifest().encode();
        write_private_manifest(fixture.path(), encoded.as_bytes());
        let root = open_directory(fixture.path());
        let uid = geteuid().as_raw();
        let pin = pin_manifest_at(&root, &run_id()).expect("pin manifest");
        pin.verify_at(&root).expect("stable manifest");
        assert_eq!(pin.manifest.complete_records().expect("complete").len(), 2);
        let mut wrong_uid = pin.metadata;
        wrong_uid.identity.uid = uid.saturating_add(1);
        assert!(validate_manifest_metadata(wrong_uid, uid).is_err());
        let mut zero_device = pin.metadata;
        zero_device.identity.device = 0;
        assert!(validate_manifest_metadata(zero_device, uid).is_err());
        let mut zero_inode = pin.metadata;
        zero_inode.identity.inode = 0;
        assert!(validate_manifest_metadata(zero_inode, uid).is_err());

        let changed = encoded.replace("11:101", "11:103");
        fs::write(fixture.path().join(MANIFEST_LEAF), changed).expect("rewrite manifest");
        assert!(pin.verify_at(&root).is_err());

        let replacement_fixture = TempDir::new().expect("replacement fixture");
        write_private_manifest(replacement_fixture.path(), encoded.as_bytes());
        let replacement_root = open_directory(replacement_fixture.path());
        let replacement_pin =
            pin_manifest_at(&replacement_root, &run_id()).expect("pin replacement manifest");
        let replacement = replacement_fixture.path().join("replacement");
        fs::write(&replacement, encoded.as_bytes()).expect("write replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(MANIFEST_MODE))
            .expect("replacement mode");
        fs::rename(&replacement, replacement_fixture.path().join(MANIFEST_LEAF))
            .expect("replace manifest entry");
        assert!(replacement_pin.verify_at(&replacement_root).is_err());

        let interleaved = TempDir::new().expect("interleaved fixture");
        write_private_manifest(interleaved.path(), encoded.as_bytes());
        let interleaved_path = interleaved.path().join(MANIFEST_LEAF);
        let descriptor = File::open(&interleaved_path).expect("open interleaved manifest");
        let interleaved_change = encoded.replace("11:101", "11:103");
        assert!(
            snapshot_manifest_descriptor_with_hook(&descriptor, &run_id(), uid, || {
                fs::write(&interleaved_path, interleaved_change).map_err(OwnershipError::from)
            })
            .is_err()
        );

        let entry_race = TempDir::new().expect("entry race fixture");
        write_private_manifest(entry_race.path(), encoded.as_bytes());
        let entry_replacement = entry_race.path().join("entry-replacement");
        fs::write(&entry_replacement, encoded.as_bytes()).expect("entry replacement");
        fs::set_permissions(
            &entry_replacement,
            fs::Permissions::from_mode(MANIFEST_MODE),
        )
        .expect("entry replacement mode");
        let entry_root = open_directory(entry_race.path());
        assert!(
            open_manifest_at_with_hook(&entry_root, &run_id(), uid, || {
                fs::rename(&entry_replacement, entry_race.path().join(MANIFEST_LEAF))
                    .map_err(OwnershipError::from)
            })
            .is_err()
        );
    }

    #[test]
    fn manifest_pin_rejects_unsafe_modes_links_sizes_and_file_types_without_blocking() {
        let encoded = complete_manifest().encode();

        let wrong_mode = TempDir::new().expect("wrong mode");
        write_private_manifest(wrong_mode.path(), encoded.as_bytes());
        fs::set_permissions(
            wrong_mode.path().join(MANIFEST_LEAF),
            fs::Permissions::from_mode(0o644),
        )
        .expect("wrong mode fixture");
        assert!(pin_manifest_at(open_directory(wrong_mode.path()), &run_id()).is_err());

        let hardlinked = TempDir::new().expect("hardlink");
        write_private_manifest(hardlinked.path(), encoded.as_bytes());
        fs::hard_link(
            hardlinked.path().join(MANIFEST_LEAF),
            hardlinked.path().join("second-link"),
        )
        .expect("hardlink fixture");
        assert!(pin_manifest_at(open_directory(hardlinked.path()), &run_id()).is_err());

        let empty = TempDir::new().expect("empty");
        write_private_manifest(empty.path(), b"");
        assert!(pin_manifest_at(open_directory(empty.path()), &run_id()).is_err());

        let oversized = TempDir::new().expect("oversized");
        write_private_manifest(oversized.path(), &vec![b'x'; MAX_MANIFEST_BYTES + 1]);
        assert!(pin_manifest_at(open_directory(oversized.path()), &run_id()).is_err());

        let linked = TempDir::new().expect("symlink");
        fs::write(linked.path().join("target"), encoded.as_bytes()).expect("symlink target");
        symlink("target", linked.path().join(MANIFEST_LEAF)).expect("symlink fixture");
        assert!(pin_manifest_at(open_directory(linked.path()), &run_id()).is_err());

        let fifo = TempDir::new().expect("fifo");
        let fifo_root = open_directory(fifo.path());
        mkfifoat(
            &fifo_root,
            MANIFEST_LEAF,
            Mode::from_raw_mode(MANIFEST_MODE),
        )
        .expect("fifo fixture");
        assert!(pin_manifest_at(&fifo_root, &run_id()).is_err());

        let directory = TempDir::new().expect("directory");
        fs::create_dir(directory.path().join(MANIFEST_LEAF)).expect("directory fixture");
        assert!(pin_manifest_at(open_directory(directory.path()), &run_id()).is_err());
    }

    #[test]
    fn complete_fixture_stages_exact_private_slots_and_publishes_atomically() {
        assert_eq!(PRIVATE_NETNS_ROOT_PATH, "/run/netns");
        assert_eq!(PRIVATE_WORKSPACE_ROOT_PATH, "/run/volparossa-netns-runner");
        assert_eq!(
            private_workspace_path(&run_id()),
            format!("/run/volparossa-netns-runner/{RUN}")
        );
        assert!(
            complete_ownership_fixture(
                run_id(),
                NamespaceIdentity::new(21, 201).expect("identity"),
                NamespaceIdentity::new(21, 201).expect("duplicate identity"),
            )
            .is_err()
        );

        let roots = private_roots();
        let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage private layout");
        layout.verify_staged().expect("pinned layout");
        assert_ne!(layout.workspace.identity.mount_id, 0);
        assert_ne!(layout.netns_root.identity.mount_id, 0);
        assert_eq!(
            layout.workspace.identity.mount_id,
            layout.netns_root.identity.mount_id
        );
        for endpoint in NamespaceEndpoint::ALL {
            let slot = roots.netns_path.join(namespace_name(&run_id(), endpoint));
            let metadata = fs::metadata(slot).expect("empty slot metadata");
            assert_eq!(metadata.mode() & 0o7777, EMPTY_SLOT_MODE);
            assert_eq!(metadata.len(), 0);
        }

        let witness = fixture_witness();
        let expected = witness.manifest.encode();
        let published = publish_ownership_manifest(layout, witness).expect("publish ownership");
        published.verify().expect("published pins");
        assert_ne!(published.manifest_pin.metadata.identity.mount_id, 0);
        assert_eq!(
            fs::read(roots.workspace_path.join(MANIFEST_LEAF)).expect("published bytes"),
            expected.as_bytes()
        );
        assert!(!roots.workspace_path.join(MANIFEST_PENDING_LEAF).exists());
        assert_eq!(
            fs::metadata(roots.workspace_path.join(MANIFEST_LEAF))
                .expect("manifest metadata")
                .mode()
                & 0o7777,
            MANIFEST_MODE
        );

        published.rollback().expect("affine rollback");
        assert_empty(&roots.workspace_path);
        assert_empty(&roots.netns_path);
    }

    #[test]
    fn every_stage_and_publish_boundary_rolls_back_all_self_created_entries() {
        for target in [
            StageBoundary::RootsPinned,
            StageBoundary::EndpointAStored,
            StageBoundary::EndpointBStored,
        ] {
            let roots = private_roots();
            let result = stage_private_run_at_with_hook(
                &roots.workspace,
                &roots.netns_root,
                run_id(),
                |boundary| {
                    if boundary == target {
                        Err(OwnershipError::UnsafeMetadata)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "stage boundary {target:?}");
            assert_empty(&roots.workspace_path);
            assert_empty(&roots.netns_path);
        }

        for target in [
            PublishBoundary::PendingCreated,
            PublishBoundary::BytesWritten,
            PublishBoundary::FileSynced,
            PublishBoundary::ReadBack,
            PublishBoundary::Renamed,
            PublishBoundary::DirectorySynced,
            PublishBoundary::ManifestPinned,
        ] {
            let roots = private_roots();
            let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
                .expect("stage before publish failure");
            let result =
                publish_ownership_manifest_with_hook(layout, fixture_witness(), |boundary| {
                    if boundary == target {
                        Err(OwnershipError::UnsafeMetadata)
                    } else {
                        Ok(())
                    }
                });
            assert!(result.is_err(), "publish boundary {target:?}");
            assert_empty(&roots.workspace_path);
            assert_empty(&roots.netns_path);
        }
    }

    #[test]
    fn provisional_entry_guards_cleanup_every_creation_boundary() {
        for target in [
            CreationBoundary::OriginBound,
            CreationBoundary::BeforeSnapshot,
            CreationBoundary::BeforeValidation,
            CreationBoundary::BeforePromotion,
        ] {
            let roots = private_roots();
            let parent =
                PinnedPrivateDirectory::pin_at(&roots.netns_root).expect("pin slot parent");
            let mut reached = false;
            let result = create_empty_slot_with_creation_hook(
                &parent,
                namespace_name(&run_id(), NamespaceEndpoint::A),
                |boundary| {
                    if boundary == target {
                        reached = true;
                        Err(OwnershipError::UnsafeMetadata)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "slot creation boundary {target:?}");
            assert!(reached, "slot creation boundary {target:?}");
            assert_empty(&roots.netns_path);
            parent
                .verify_exact_entries(&[])
                .expect("provisional slot cleanup");
        }

        for target in [
            CreationBoundary::OriginBound,
            CreationBoundary::BeforeModeHardening,
            CreationBoundary::ModeHardened,
            CreationBoundary::BeforeSnapshot,
            CreationBoundary::BeforeValidation,
            CreationBoundary::BeforePromotion,
        ] {
            let roots = private_roots();
            let parent =
                PinnedPrivateDirectory::pin_at(&roots.workspace).expect("pin manifest parent");
            let mut reached = false;
            let result = create_pending_manifest_with_creation_hook(&parent, |boundary| {
                if boundary == target {
                    reached = true;
                    Err(OwnershipError::UnsafeMetadata)
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "manifest creation boundary {target:?}");
            assert!(reached, "manifest creation boundary {target:?}");
            assert_empty(&roots.workspace_path);
            parent
                .verify_exact_entries(&[])
                .expect("provisional manifest cleanup");
        }
    }

    #[test]
    fn provisional_entry_guards_retain_substituted_entries() {
        let slot_roots = private_roots();
        let slot_parent =
            PinnedPrivateDirectory::pin_at(&slot_roots.netns_root).expect("pin slot parent");
        let slot_name = namespace_name(&run_id(), NamespaceEndpoint::A);
        let slot_path = slot_roots.netns_path.join(&slot_name);
        assert!(
            create_empty_slot_with_creation_hook(&slot_parent, slot_name, |boundary| {
                if boundary == CreationBoundary::OriginBound {
                    fs::remove_file(&slot_path).map_err(OwnershipError::from)?;
                    fs::write(&slot_path, b"foreign slot").map_err(OwnershipError::from)?;
                    fs::set_permissions(&slot_path, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
                        .map_err(OwnershipError::from)?;
                    Err(OwnershipError::UnsafeMetadata)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(
            fs::metadata(&slot_path)
                .expect("provisional slot replacement retained")
                .len(),
            b"foreign slot".len() as u64
        );

        let manifest_roots = private_roots();
        let manifest_parent =
            PinnedPrivateDirectory::pin_at(&manifest_roots.workspace).expect("pin manifest parent");
        let manifest_path = manifest_roots.workspace_path.join(MANIFEST_PENDING_LEAF);
        assert!(
            create_pending_manifest_with_creation_hook(&manifest_parent, |boundary| {
                if boundary == CreationBoundary::OriginBound {
                    fs::remove_file(&manifest_path).map_err(OwnershipError::from)?;
                    fs::write(&manifest_path, b"foreign manifest").map_err(OwnershipError::from)?;
                    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(MANIFEST_MODE))
                        .map_err(OwnershipError::from)?;
                    Err(OwnershipError::UnsafeMetadata)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(
            fs::read(&manifest_path).expect("provisional manifest replacement retained"),
            b"foreign manifest"
        );
    }

    #[test]
    fn provisional_entry_guards_retain_hardlinked_entries() {
        let slot_roots = private_roots();
        let slot_parent =
            PinnedPrivateDirectory::pin_at(&slot_roots.netns_root).expect("pin slot parent");
        let slot_name = namespace_name(&run_id(), NamespaceEndpoint::A);
        let slot_path = slot_roots.netns_path.join(&slot_name);
        let slot_link = slot_roots.netns_path.join("slot-hardlink");
        assert!(
            create_empty_slot_with_creation_hook(&slot_parent, slot_name, |boundary| {
                if boundary == CreationBoundary::OriginBound {
                    fs::hard_link(&slot_path, &slot_link).map_err(OwnershipError::from)?;
                    Err(OwnershipError::UnsafeMetadata)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let slot_metadata = fs::metadata(&slot_path).expect("original slot retained");
        let slot_link_metadata = fs::metadata(&slot_link).expect("slot hardlink retained");
        assert_eq!(slot_metadata.ino(), slot_link_metadata.ino());
        assert_eq!(slot_metadata.nlink(), 2);

        let manifest_roots = private_roots();
        let manifest_parent =
            PinnedPrivateDirectory::pin_at(&manifest_roots.workspace).expect("pin manifest parent");
        let manifest_path = manifest_roots.workspace_path.join(MANIFEST_PENDING_LEAF);
        let manifest_link = manifest_roots.workspace_path.join("manifest-hardlink");
        assert!(
            create_pending_manifest_with_creation_hook(&manifest_parent, |boundary| {
                if boundary == CreationBoundary::OriginBound {
                    fs::hard_link(&manifest_path, &manifest_link).map_err(OwnershipError::from)?;
                    Err(OwnershipError::UnsafeMetadata)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let manifest_metadata =
            fs::metadata(&manifest_path).expect("original pending manifest retained");
        let manifest_link_metadata =
            fs::metadata(&manifest_link).expect("manifest hardlink retained");
        assert_eq!(manifest_metadata.ino(), manifest_link_metadata.ino());
        assert_eq!(manifest_metadata.nlink(), 2);
    }

    #[test]
    fn created_entry_guards_cleanup_after_handoff_failure_without_adopting_replacements() {
        let roots = private_roots();
        let netns_root = PinnedPrivateDirectory::pin_at(&roots.netns_root).expect("pin netns root");
        let name = namespace_name(&run_id(), NamespaceEndpoint::A);
        assert!(
            create_empty_slot_with_handoff_hook(&netns_root, name, || {
                Err(OwnershipError::UnsafeMetadata)
            })
            .is_err()
        );
        assert_empty(&roots.netns_path);
        netns_root
            .verify_exact_entries(&[])
            .expect("slot guard removed its validated entry");

        let workspace =
            PinnedPrivateDirectory::pin_at(&roots.workspace).expect("pin workspace root");
        assert!(
            create_pending_manifest_with_handoff_hook(&workspace, || {
                Err(OwnershipError::UnsafeMetadata)
            })
            .is_err()
        );
        assert_empty(&roots.workspace_path);
        workspace
            .verify_exact_entries(&[])
            .expect("manifest guard removed its validated entry");

        let replacement_roots = private_roots();
        let replacement_root = PinnedPrivateDirectory::pin_at(&replacement_roots.netns_root)
            .expect("pin replacement root");
        let replacement_name = namespace_name(&run_id(), NamespaceEndpoint::A);
        let replacement_path = replacement_roots.netns_path.join(&replacement_name);
        assert!(
            create_empty_slot_with_handoff_hook(&replacement_root, replacement_name, || {
                fs::remove_file(&replacement_path).map_err(OwnershipError::from)?;
                fs::write(&replacement_path, b"foreign replacement")
                    .map_err(OwnershipError::from)?;
                fs::set_permissions(
                    &replacement_path,
                    fs::Permissions::from_mode(EMPTY_SLOT_MODE),
                )
                .map_err(OwnershipError::from)?;
                Err(OwnershipError::UnsafeMetadata)
            },)
            .is_err()
        );
        assert_eq!(
            fs::metadata(&replacement_path)
                .expect("replacement retained")
                .len(),
            b"foreign replacement".len() as u64
        );
    }

    #[test]
    fn post_unlink_proof_failures_pop_journal_and_continue_reverse_cleanup() {
        let expected_order = vec![
            MANIFEST_LEAF.to_owned(),
            namespace_name(&run_id(), NamespaceEndpoint::B),
            namespace_name(&run_id(), NamespaceEndpoint::A),
        ];
        for target in [
            RemovalBoundary::UnlinkCommitted,
            RemovalBoundary::AbsenceProved,
            RemovalBoundary::DirectorySynced,
        ] {
            let roots = private_roots();
            let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
                .expect("stage cleanup failpoint fixture");
            let mut published = publish_ownership_manifest(layout, fixture_witness())
                .expect("publish cleanup failpoint fixture");
            let mut removed = Vec::new();
            let mut injected = false;
            let result = published.layout.journal.rollback_with_hooks(
                |name| removed.push(name.to_owned()),
                |name, boundary| {
                    if !injected && name == MANIFEST_LEAF && boundary == target {
                        injected = true;
                        Err(OwnershipError::UnsafeMetadata)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "removal boundary {target:?}");
            assert!(injected, "removal boundary {target:?}");
            assert_eq!(removed, expected_order, "removal boundary {target:?}");
            assert!(published.layout.journal.entries.is_empty());
            assert!(!published.layout.journal.armed);
            drop(published);
            assert_empty(&roots.workspace_path);
            assert_empty(&roots.netns_path);
        }
    }

    #[test]
    fn post_unlink_replacement_is_retained_without_drop_retry() {
        let roots = private_roots();
        let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage replacement cleanup fixture");
        let mut published = publish_ownership_manifest(layout, fixture_witness())
            .expect("publish replacement cleanup fixture");
        let replacement_path = roots.workspace_path.join(MANIFEST_LEAF);
        let mut removed = Vec::new();
        let mut replacement_installed = false;
        let result = published.layout.journal.rollback_with_hooks(
            |name| removed.push(name.to_owned()),
            |name, boundary| {
                if !replacement_installed
                    && name == MANIFEST_LEAF
                    && boundary == RemovalBoundary::UnlinkCommitted
                {
                    fs::write(&replacement_path, b"foreign replacement")
                        .map_err(OwnershipError::from)?;
                    fs::set_permissions(
                        &replacement_path,
                        fs::Permissions::from_mode(MANIFEST_MODE),
                    )
                    .map_err(OwnershipError::from)?;
                    replacement_installed = true;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(replacement_installed);
        assert_eq!(
            removed,
            vec![
                MANIFEST_LEAF.to_owned(),
                namespace_name(&run_id(), NamespaceEndpoint::B),
                namespace_name(&run_id(), NamespaceEndpoint::A),
            ]
        );
        assert!(published.layout.journal.entries.is_empty());
        assert!(!published.layout.journal.armed);
        drop(published);
        assert_eq!(
            fs::read(&replacement_path).expect("replacement survives journal drop"),
            b"foreign replacement"
        );
        assert_empty(&roots.netns_path);
    }

    #[test]
    fn rollback_is_reverse_order_and_fails_closed_on_parent_or_entry_identity_change() {
        let roots = private_roots();
        let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage layout");
        let mut published =
            publish_ownership_manifest(layout, fixture_witness()).expect("publish ownership");
        let mut removed = Vec::new();
        published
            .layout
            .journal
            .rollback_with_hook(|name| removed.push(name.to_owned()))
            .expect("reverse rollback");
        assert_eq!(
            removed,
            vec![
                MANIFEST_LEAF.to_owned(),
                namespace_name(&run_id(), NamespaceEndpoint::B),
                namespace_name(&run_id(), NamespaceEndpoint::A),
            ]
        );
        assert_empty(&roots.workspace_path);
        assert_empty(&roots.netns_path);

        let roots = private_roots();
        let mut layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage parent-mode fixture");
        fs::set_permissions(
            &roots.netns_path,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE | 0o020),
        )
        .expect("weaken parent mode");
        assert!(layout.journal.rollback_all().is_err());
        assert_eq!(fs::read_dir(&roots.netns_path).expect("slots").count(), 2);
        fs::set_permissions(
            &roots.netns_path,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .expect("restore parent mode");
        layout
            .journal
            .rollback_all()
            .expect("cleanup after restored identity");

        let roots = private_roots();
        let mut layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage replacement fixture");
        let endpoint_b = roots
            .netns_path
            .join(namespace_name(&run_id(), NamespaceEndpoint::B));
        fs::remove_file(&endpoint_b).expect("remove owned slot");
        fs::write(&endpoint_b, b"").expect("foreign replacement");
        fs::set_permissions(&endpoint_b, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
            .expect("replacement mode");
        assert!(layout.journal.rollback_all().is_err());
        assert!(endpoint_b.exists());
        assert!(
            roots
                .netns_path
                .join(namespace_name(&run_id(), NamespaceEndpoint::A))
                .exists()
        );
        layout.journal.abandon_for_test();
    }

    #[test]
    fn exact_sets_reject_foreign_entries_and_no_replace_preserves_foreign_symlink() {
        let roots = private_roots();
        let layout = stage_private_run_at(&roots.workspace, &roots.netns_root, run_id())
            .expect("stage layout");
        fs::write(roots.netns_path.join("unrelated"), b"foreign")
            .expect("change directory timestamps");
        assert!(layout.verify_staged().is_err());
        fs::remove_file(roots.netns_path.join("unrelated")).expect("remove unrelated fixture");
        layout
            .verify_staged()
            .expect("exact set restored despite changed directory timestamps");

        symlink("foreign-target", roots.workspace_path.join(MANIFEST_LEAF))
            .expect("foreign destination symlink");
        assert!(publish_ownership_manifest(layout, fixture_witness()).is_err());
        assert!(
            fs::symlink_metadata(roots.workspace_path.join(MANIFEST_LEAF))
                .expect("foreign symlink retained")
                .file_type()
                .is_symlink()
        );
        assert!(!roots.workspace_path.join(MANIFEST_PENDING_LEAF).exists());
        assert_empty(&roots.netns_path);

        let substitution_roots = private_roots();
        let mut substitution_layout = stage_private_run_at(
            &substitution_roots.workspace,
            &substitution_roots.netns_root,
            run_id(),
        )
        .expect("stage exact-entry substitution fixture");
        let replacement = substitution_roots.netns_path.with_file_name("replacement");
        fs::write(&replacement, b"").expect("preallocate exact-entry replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(EMPTY_SLOT_MODE))
            .expect("replacement mode");
        let endpoint_b = substitution_roots
            .netns_path
            .join(namespace_name(&run_id(), NamespaceEndpoint::B));
        let expected = [
            ExpectedDirectoryEntry {
                name: &substitution_layout.slots[0].name,
                descriptor: &substitution_layout.slots[0].descriptor,
                identity: substitution_layout.slots[0].identity,
            },
            ExpectedDirectoryEntry {
                name: &substitution_layout.slots[1].name,
                descriptor: &substitution_layout.slots[1].descriptor,
                identity: substitution_layout.slots[1].identity,
            },
        ];
        assert!(
            substitution_layout
                .netns_root
                .verify_exact_entries_with_hook(&expected, || {
                    fs::rename(&replacement, &endpoint_b).map_err(OwnershipError::from)
                })
                .is_err()
        );
        substitution_layout.journal.abandon_for_test();

        let volatile_roots = private_roots();
        let volatile_layout = stage_private_run_at(
            &volatile_roots.workspace,
            &volatile_roots.netns_root,
            run_id(),
        )
        .expect("stage volatile directory fixture");
        let expected = [
            ExpectedDirectoryEntry {
                name: &volatile_layout.slots[0].name,
                descriptor: &volatile_layout.slots[0].descriptor,
                identity: volatile_layout.slots[0].identity,
            },
            ExpectedDirectoryEntry {
                name: &volatile_layout.slots[1].name,
                descriptor: &volatile_layout.slots[1].descriptor,
                identity: volatile_layout.slots[1].identity,
            },
        ];
        let transient = volatile_roots.netns_path.join("transient");
        assert!(
            volatile_layout
                .netns_root
                .verify_exact_entries_with_hook(&expected, || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    fs::write(&transient, b"foreign").map_err(OwnershipError::from)?;
                    fs::remove_file(&transient).map_err(OwnershipError::from)
                })
                .is_err()
        );
        volatile_layout
            .rollback()
            .expect("cleanup after volatile snapshot detection");
    }

    #[test]
    fn namespace_observation_is_affine_exact_and_detects_retained_pin_substitution() {
        let fixture = TempDir::new().expect("fixture");
        let workspace_path = fixture.path().join("workspace");
        let netns_path = fixture.path().join("netns");
        fs::create_dir(&workspace_path).expect("workspace");
        fs::create_dir(&netns_path).expect("netns root");
        let name_a = namespace_name(&run_id(), NamespaceEndpoint::A);
        let name_b = namespace_name(&run_id(), NamespaceEndpoint::B);
        fs::write(netns_path.join(&name_a), b"").expect("namespace a");
        fs::write(netns_path.join(&name_b), b"").expect("namespace b");
        let manifest = OwnershipManifest::new(
            run_id(),
            vec![
                record_for_path(&run_id(), NamespaceEndpoint::A, &netns_path.join(&name_a)),
                record_for_path(&run_id(), NamespaceEndpoint::B, &netns_path.join(&name_b)),
            ],
        )
        .expect("fixture manifest");
        write_private_manifest(&workspace_path, manifest.encode().as_bytes());
        let workspace = open_directory(&workspace_path);
        let netns_root = open_directory(&netns_path);
        let manifest_pin = pin_manifest_at(&workspace, &run_id()).expect("manifest pin");

        let namespace_pin = match observe_namespace_at(
            &workspace,
            &netns_root,
            &manifest_pin,
            NamespaceEndpoint::A,
        )
        .expect("owned observation")
        {
            OwnershipObservation::Owned(pin) => pin,
            OwnershipObservation::Absent | OwnershipObservation::Foreign => {
                panic!("expected owned namespace")
            }
        };
        assert_eq!(namespace_pin.endpoint, NamespaceEndpoint::A);
        namespace_pin
            .verify_at(&netns_root)
            .expect("stable namespace pin");

        let replacement = netns_path.join("replacement-a");
        fs::write(&replacement, b"").expect("preallocated replacement");
        fs::rename(&replacement, netns_path.join(&name_a)).expect("substitute entry");
        assert!(namespace_pin.verify_at(&netns_root).is_err());

        fs::remove_file(netns_path.join(&name_b)).expect("remove namespace b");
        assert!(matches!(
            observe_namespace_at(&workspace, &netns_root, &manifest_pin, NamespaceEndpoint::B,)
                .expect("absent observation"),
            OwnershipObservation::Absent
        ));
    }

    #[test]
    fn existing_namespace_substitutions_are_foreign_and_partial_manifest_is_invalid() {
        for kind in ["replacement", "symlink", "fifo", "directory"] {
            let fixture = TempDir::new().expect("fixture");
            let workspace_path = fixture.path().join("workspace");
            let netns_path = fixture.path().join("netns");
            fs::create_dir(&workspace_path).expect("workspace");
            fs::create_dir(&netns_path).expect("netns root");
            let name = namespace_name(&run_id(), NamespaceEndpoint::A);
            let owned_path = netns_path.join(&name);
            fs::write(&owned_path, b"").expect("owned fixture");
            let manifest = OwnershipManifest::new(
                run_id(),
                vec![record_for_path(
                    &run_id(),
                    NamespaceEndpoint::A,
                    &owned_path,
                )],
            )
            .expect("partial fixture manifest");
            write_private_manifest(&workspace_path, manifest.encode().as_bytes());
            let workspace = open_directory(&workspace_path);
            let netns_root = open_directory(&netns_path);
            let manifest_pin = pin_manifest_at(&workspace, &run_id()).expect("manifest pin");

            let replacement = netns_path.join("preallocated-replacement");
            if kind == "replacement" {
                fs::write(&replacement, b"foreign").expect("preallocate replacement");
            }
            fs::remove_file(&owned_path).expect("remove owned fixture");
            match kind {
                "replacement" => fs::rename(&replacement, &owned_path).expect("replacement"),
                "symlink" => symlink("missing", &owned_path).expect("symlink"),
                "fifo" => mkfifoat(&netns_root, &name, Mode::from_raw_mode(0o600)).expect("fifo"),
                "directory" => fs::create_dir(&owned_path).expect("directory"),
                _ => unreachable!(),
            }
            assert!(matches!(
                observe_namespace_at(&workspace, &netns_root, &manifest_pin, NamespaceEndpoint::A,)
                    .expect("foreign observation"),
                OwnershipObservation::Foreign
            ));
            assert!(matches!(
                observe_namespace_at(&workspace, &netns_root, &manifest_pin, NamespaceEndpoint::B,),
                Err(OwnershipError::Manifest)
            ));
        }
    }
}
