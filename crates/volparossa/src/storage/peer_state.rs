//! Bounded, owner-only resumable metadata, locked for the whole transfer.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::fd::AsRawFd as _,
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use volparossa_content::private_storage::{
    MAX_ARCHIVE_BYTES,
    protocol::{
        MAX_GRANT_BYTES, ReceiptResult, SignedStorageGrant, StorageTarget, VerifiedStorageGrant,
    },
};

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const JOURNAL: &str = "archive.json";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    version: u32,
    pub(super) provider_key: [u8; 32],
    pub(super) owner_key: [u8; 32],
    pub(super) grant_hex: String,
    pub(super) archive_id: [u8; 32],
    pub(super) ciphertext_bytes: u64,
    pub(super) sha256: [u8; 32],
    pub(super) requested_expiry: u64,
    pub(super) lease: Option<String>,
    pub(super) last_stored_bytes: u64,
    pub(super) last_expiry: u64,
    pub(super) last_state: Option<i32>,
}

impl Journal {
    pub(super) fn new(
        grant: &VerifiedStorageGrant,
        length: u64,
        sha256: [u8; 32],
        requested_expiry: u64,
    ) -> Result<Self> {
        ensure!(
            (1..=MAX_ARCHIVE_BYTES).contains(&length),
            "invalid private archive length"
        );
        let mut archive_id = [0; 32];
        OsRng
            .try_fill_bytes(&mut archive_id)
            .context("cannot generate private archive identity")?;
        Ok(Self {
            version: 1,
            provider_key: grant.provider_key().to_bytes(),
            owner_key: grant.owner_key().to_bytes(),
            grant_hex: hex::encode(grant.signed().encode()),
            archive_id,
            ciphertext_bytes: length,
            sha256,
            requested_expiry,
            lease: None,
            last_stored_bytes: 0,
            last_expiry: 0,
            last_state: None,
        })
    }

    pub(super) fn grant(
        &self,
        provider: &VerifyingKey,
        owner: &VerifyingKey,
    ) -> Result<VerifiedStorageGrant> {
        ensure!(
            self.version == 1
                && self.provider_key == provider.to_bytes()
                && self.owner_key == owner.to_bytes(),
            "private archive journal does not match independently selected provider/owner"
        );
        ensure!(
            self.archive_id != [0; 32]
                && (1..=MAX_ARCHIVE_BYTES).contains(&self.ciphertext_bytes)
                && self.last_stored_bytes <= self.ciphertext_bytes
                && self.grant_hex.len() <= 2 * MAX_GRANT_BYTES,
            "invalid private archive journal"
        );
        let grant = SignedStorageGrant::decode(&hex::decode(&self.grant_hex)?)?
            .verify(provider, super::super::now()?)?;
        ensure!(
            grant.owner_key() == owner,
            "private archive grant has a different owner"
        );
        self.target()?;
        Ok(grant)
    }

    pub(super) fn target(&self) -> Result<StorageTarget> {
        Ok(StorageTarget {
            archive_id: self.archive_id,
            lease_id: self.lease.as_deref().map(str::parse).transpose()?,
            ciphertext_bytes: self.ciphertext_bytes,
            sha256: self.sha256,
        })
    }

    pub(super) fn apply(&mut self, result: ReceiptResult) -> Result<()> {
        if let Some(lease) = &self.lease {
            ensure!(
                lease == &result.lease_id.to_string(),
                "provider changed the retained lease"
            );
        }
        self.lease = Some(result.lease_id.to_string());
        self.last_stored_bytes = result.stored_bytes;
        self.last_expiry = result.expires_at;
        self.last_state = Some(result.state as i32);
        Ok(())
    }
}

pub(super) struct LockedJournal {
    directory: File,
    pub(super) journal: Journal,
}

impl LockedJournal {
    pub(super) fn create(path: &Path, journal: Journal) -> Result<Self> {
        super::super::require_absolute(path)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .context("cannot create NEW private archive state directory")?;
        let result = Self {
            directory: directory(path)?,
            journal,
        };
        result.save()?;
        Ok(result)
    }

    pub(super) fn open(path: &Path) -> Result<Self> {
        super::super::require_absolute(path)?;
        let directory = directory(path)?;
        let bytes = read_private(&anchored(&directory).join(JOURNAL), MAX_JOURNAL_BYTES)?;
        let journal = serde_json::from_slice(&bytes).context("invalid private archive journal")?;
        Ok(Self { directory, journal })
    }

    pub(super) fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.journal)?;
        ensure!(
            bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "private archive journal too large"
        );
        let mut output = tempfile::NamedTempFile::new_in(anchored(&self.directory))?;
        output
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        output.write_all(&bytes)?;
        output.as_file().sync_all()?;
        // Only this exact owned journal is replaceable; flock prevents concurrent upload/renew/delete.
        output
            .persist(anchored(&self.directory).join(JOURNAL))
            .map_err(|error| error.error)?;
        self.directory.sync_all()?;
        Ok(())
    }
}

pub(super) fn directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o777 == 0o700
            && metadata.uid() == rustix::process::geteuid().as_raw(),
        "archive state directory must be owned by this user with mode 0700"
    );
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("private archive state is already in use")?;
    Ok(file)
}

pub(super) fn anchored(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

pub(super) fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    super::super::require_absolute(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.len() <= maximum,
        "private metadata must be an owned bounded 0600 regular file"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "private metadata exceeded size bound"
    );
    Ok(bytes)
}

pub(super) fn new_output(path: &Path) -> Result<()> {
    super::super::require_absolute(path)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!("private output must be a new file"),
    }
}

pub(super) fn private_output(path: &Path, bytes: &[u8]) -> Result<()> {
    new_output(path)?;
    let parent = path.parent().context("missing private output parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
