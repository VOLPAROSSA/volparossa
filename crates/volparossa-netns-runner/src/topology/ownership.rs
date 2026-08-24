use std::{collections::HashSet, fs::File, io, marker::PhantomData, os::fd::AsFd, rc::Rc};

use nix::unistd::geteuid;
use rustix::{
    fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat2, statat},
    io::{Errno, pread},
};
use thiserror::Error;
use volparossa_test_support::{LifecycleSha256, NamespaceIdentity, OwnedNamespace, RunId};

const MANIFEST_MAGIC: &str = "VOLPAROSSA_NETNS_OWNERSHIP_V1";
const MANIFEST_LEAF: &str = "ownership.v1";
const MAX_MANIFEST_BYTES: usize = 4_096;
const MAX_MANIFEST_RECORDS: usize = 2;
const MANIFEST_MODE: u32 = 0o600;

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
struct StableMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl StableMetadata {
    fn from_stat(metadata: &Stat) -> Result<Self, OwnershipError> {
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            links: metadata.st_nlink,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            size: u64::try_from(metadata.st_size).map_err(|_| OwnershipError::UnsafeMetadata)?,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        })
    }

    fn namespace_identity(self) -> Result<NamespaceIdentity, OwnershipError> {
        NamespaceIdentity::new(self.device, self.inode).map_err(|_| OwnershipError::UnsafeMetadata)
    }

    fn is_regular(self) -> bool {
        FileType::from_raw_mode(self.mode).is_file()
    }

    fn is_directory(self) -> bool {
        FileType::from_raw_mode(self.mode).is_dir()
    }
}

struct ManifestSnapshot {
    metadata: StableMetadata,
    bytes: Vec<u8>,
    digest: LifecycleSha256,
    manifest: OwnershipManifest,
}

struct ManifestPin {
    descriptor: File,
    expected_uid: u32,
    workspace_metadata: StableMetadata,
    metadata: StableMetadata,
    bytes: Vec<u8>,
    digest: LifecycleSha256,
    manifest: OwnershipManifest,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ManifestPin {
    fn verify_at<Fd: AsFd>(&self, workspace: Fd) -> Result<(), OwnershipError> {
        verify_directory(&workspace, self.workspace_metadata)?;
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
        verify_directory(&workspace, self.workspace_metadata)?;
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
    let workspace_metadata = directory_metadata(&workspace)?;
    let (descriptor, snapshot) = open_manifest_at(&workspace, expected_run_id, expected_uid)?;
    verify_directory(&workspace, workspace_metadata)?;
    Ok(ManifestPin {
        descriptor,
        expected_uid,
        workspace_metadata,
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
    let before = StableMetadata::from_stat(&fstat(descriptor).map_err(rustix_ownership_io)?)?;
    validate_manifest_metadata(before, expected_uid)?;
    let first = read_bounded_at(descriptor)?;
    between_reads()?;
    let middle = StableMetadata::from_stat(&fstat(descriptor).map_err(rustix_ownership_io)?)?;
    let second = read_bounded_at(descriptor)?;
    let after = StableMetadata::from_stat(&fstat(descriptor).map_err(rustix_ownership_io)?)?;
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
    metadata: StableMetadata,
    expected_uid: u32,
) -> Result<(), OwnershipError> {
    if !metadata.is_regular()
        || metadata.device == 0
        || metadata.inode == 0
        || metadata.uid != expected_uid
        || metadata.mode & 0o7777 != MANIFEST_MODE
        || metadata.links != 1
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
    expected: &StableMetadata,
) -> Result<(), OwnershipError> {
    let entry =
        statat(workspace, MANIFEST_LEAF, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_ownership_io)?;
    let entry = StableMetadata::from_stat(&entry)?;
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
    root_metadata: StableMetadata,
    endpoint: NamespaceEndpoint,
    name: String,
    identity: NamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

impl NamespacePin {
    fn verify_at<Fd: AsFd>(&self, netns_root: Fd) -> Result<(), OwnershipError> {
        verify_directory(&netns_root, self.root_metadata)?;
        let held = namespace_metadata(&self.descriptor)?;
        if held.namespace_identity()? != self.identity || !held.is_regular() {
            return Err(OwnershipError::UnsafeMetadata);
        }
        let (descriptor, reopened) = open_namespace_at(&netns_root, &self.name)?;
        if reopened.namespace_identity()? != self.identity || reopened != held {
            return Err(OwnershipError::UnsafeMetadata);
        }
        verify_namespace_entry(&netns_root, &self.name, &reopened)?;
        drop(descriptor);
        verify_directory(&netns_root, self.root_metadata)?;
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
    let root_metadata = directory_metadata(&netns_root)?;
    let expected = manifest_pin
        .manifest
        .record(endpoint)
        .ok_or(OwnershipError::Manifest)?;
    let name = namespace_name(&manifest_pin.manifest.run_id, endpoint);
    let first = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => StableMetadata::from_stat(&metadata)?,
        Err(Errno::NOENT) => {
            manifest_pin.verify_at(&manifest_workspace)?;
            let observation = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => OwnershipObservation::Absent,
                Ok(_) => OwnershipObservation::Foreign,
                Err(error) => return Err(rustix_ownership_io(error)),
            };
            manifest_pin.verify_at(&manifest_workspace)?;
            if matches!(observation, OwnershipObservation::Absent) {
                verify_directory(&netns_root, root_metadata)?;
            }
            return Ok(observation);
        }
        Err(error) => return Err(rustix_ownership_io(error)),
    };
    if !first.is_regular() || first.namespace_identity()? != expected.identity() {
        manifest_pin.verify_at(&manifest_workspace)?;
        verify_directory(&netns_root, root_metadata)?;
        return Ok(OwnershipObservation::Foreign);
    }
    let (descriptor, opened) = open_namespace_at(&netns_root, &name)?;
    let final_entry = match statat(&netns_root, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => StableMetadata::from_stat(&metadata)?,
        Err(error) => return Err(rustix_ownership_io(error)),
    };
    manifest_pin.verify_at(&manifest_workspace)?;
    verify_directory(&netns_root, root_metadata)?;
    if first != opened
        || opened != final_entry
        || !opened.is_regular()
        || opened.namespace_identity()? != expected.identity()
    {
        return Ok(OwnershipObservation::Foreign);
    }
    Ok(OwnershipObservation::Owned(NamespacePin {
        descriptor,
        root_metadata,
        endpoint,
        name,
        identity: expected.identity(),
        _thread_bound: PhantomData,
    }))
}

fn open_namespace_at<Fd: AsFd>(
    netns_root: Fd,
    name: &str,
) -> Result<(File, StableMetadata), OwnershipError> {
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

fn namespace_metadata<Fd: AsFd>(descriptor: Fd) -> Result<StableMetadata, OwnershipError> {
    StableMetadata::from_stat(&fstat(descriptor).map_err(rustix_ownership_io)?)
}

fn directory_metadata<Fd: AsFd>(descriptor: Fd) -> Result<StableMetadata, OwnershipError> {
    let metadata = StableMetadata::from_stat(&fstat(descriptor).map_err(rustix_ownership_io)?)?;
    if !metadata.is_directory() {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(metadata)
}

fn verify_directory<Fd: AsFd>(
    descriptor: Fd,
    expected: StableMetadata,
) -> Result<(), OwnershipError> {
    if directory_metadata(descriptor)? != expected {
        return Err(OwnershipError::UnsafeMetadata);
    }
    Ok(())
}

fn verify_namespace_entry<Fd: AsFd>(
    netns_root: Fd,
    name: &str,
    expected: &StableMetadata,
) -> Result<(), OwnershipError> {
    let entry = statat(netns_root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_ownership_io)?;
    if StableMetadata::from_stat(&entry)? != *expected {
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
        path::Path,
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
        wrong_uid.uid = uid.saturating_add(1);
        assert!(validate_manifest_metadata(wrong_uid, uid).is_err());
        let mut zero_device = pin.metadata;
        zero_device.device = 0;
        assert!(validate_manifest_metadata(zero_device, uid).is_err());
        let mut zero_inode = pin.metadata;
        zero_inode.inode = 0;
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
