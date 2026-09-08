use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};

use crate::{CHUNK_BYTES, ChunkId, Error, MAX_CHUNKS};

mod names;
pub use names::RevisionPin;

const MAX_CACHE_ENTRIES: usize = 65_536;
const OWNER_FILE: &str = ".volparossa-owner-v1";
const INDEX_FILE: &str = ".volparossa-index-v1";
const INDEX_STAGE: &str = ".volparossa-index-next-v1";
const CHUNK_STAGE: &str = ".volparossa-chunk-next-v1";
const REPLICA_FILE: &str = ".volparossa-replicas-v1";
const REPLICA_STAGE: &str = ".volparossa-replicas-next-v1";
const REPLICA_MAGIC: &[u8; 8] = b"VPCR0001";
const MAILBOX_FILE: &str = ".volparossa-mailbox-v1";
const MAILBOX_STAGE: &str = ".volparossa-mailbox-next-v1";
const MAILBOX_MAGIC: &[u8; 8] = b"VPCM0001";
pub(crate) const MAX_MAILBOX_METADATA_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_REPLICA_METADATA_BYTES: usize = 8 * 1024 * 1024;
const REPLICA_OVERHEAD: usize = 8 + 32 + CHECKSUM_BYTES;
const OWNER_MAGIC: &[u8; 8] = b"VPCC0001";
const INDEX_MAGIC: &[u8; 8] = b"VPCI0001";
const OWNER_BYTES: usize = 60;
const INDEX_HEADER_BYTES: usize = 44;
const INDEX_ENTRY_BYTES: usize = 36;
const CHECKSUM_BYTES: usize = 32;
const MAX_INDEX_BYTES: usize =
    INDEX_HEADER_BYTES + MAX_CACHE_ENTRIES * INDEX_ENTRY_BYTES + CHECKSUM_BYTES;

/// Explicit local-owner limits; no cache is enabled or sized from spare disk automatically.
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    /// Maximum stored chunk payload bytes, excluding filesystem metadata.
    pub max_bytes: u64,
    /// Maximum chunks, bounding tiny-file count and in-memory index size too.
    pub max_entries: usize,
    /// Free bytes that must remain on the filesystem before each insertion.
    pub min_free_bytes: u64,
}

/// Accounted disk payload and entry consumption of this owned cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheUsage {
    /// Sum of stored chunk lengths.
    pub bytes: u64,
    /// Number of stored chunks, including tiny chunks.
    pub entries: usize,
}

/// An exclusively created private local chunk cache with least-recently-used eviction.
///
/// Creation refuses existing paths. Reopening requires its private owner marker, bound to the
/// creating UID and directory device/inode, and a bounded checksummed index. Only indexed files
/// are loaded or evicted; arbitrary directories/files are never scanned or adopted. An exclusive
/// lock prevents two cooperating processes from mutating the cache concurrently.
///
/// Successful mutations persist the exact index and chunks before returning. Read touches are
/// checkpointed with the next mutation, so LRU recency can be approximate after restart. Dropping
/// the handle releases the lock and leaves data on disk. Incomplete/crash-interrupted mutations
/// are rejected on reopen without automatic deletion or recovery. Access remains synchronous.
#[derive(Debug)]
pub struct ChunkStore {
    directory: File,
    _ownership_lock: File,
    cache_id: [u8; 32],
    limits: CacheLimits,
    entries: BTreeMap<ChunkId, u64>,
    lru: VecDeque<ChunkId>,
    bytes: u64,
    healthy: bool,
}

impl ChunkStore {
    /// Create a fresh mode-0700 cache directory beneath a caller-selected trusted parent.
    ///
    /// # Errors
    /// Rejects existing paths, invalid limits, insufficient free space or filesystem failures.
    /// Failure after directory creation may leave its own incomplete cache, never adopted later.
    pub fn create(directory: &Path, limits: CacheLimits) -> Result<Self, Error> {
        validate_limits(limits)?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        let directory = open_directory(directory)?;
        let mut ownership_lock = create_file(&directory, OWNER_FILE)?;
        lock_owner(&ownership_lock)?;
        let mut cache_id = [0; 32];
        getrandom::fill(&mut cache_id).map_err(|_| Error::Entropy)?;
        ownership_lock.write_all(&owner_record(&directory, &cache_id)?)?;
        ownership_lock.sync_all()?;
        let mut store = Self {
            directory,
            _ownership_lock: ownership_lock,
            cache_id,
            limits,
            entries: BTreeMap::new(),
            lru: VecDeque::new(),
            bytes: 0,
            healthy: false,
        };
        store.persist_index()?;
        store.healthy = true;
        Ok(store)
    }

    /// Reopen a cache previously created by this API for the current local user.
    ///
    /// Reconstructs only the bounded persisted index, checking its checksum, owner identity,
    /// duplicate/length constraints and every indexed file's type/length. SHA-256 is checked
    /// on each subsequent read. New limits apply immediately; this method never evicts to make
    /// an oversized old cache fit. Renaming the directory is supported; copied markers bound
    /// to a different directory inode are rejected. No signing keys or manifests are loaded.
    ///
    /// # Errors
    /// Rejects foreign/private-ownership failures, a busy lock, corrupt/incomplete indexes or
    /// chunks, and byte/entry/free-space limit violations. No files are removed on failure.
    pub fn open(directory: &Path, limits: CacheLimits) -> Result<Self, Error> {
        validate_limits(limits)?;
        let directory = open_directory(directory)?;
        let mut ownership_lock = open_private_file(&directory, OWNER_FILE, OWNER_BYTES as u64)?;
        lock_owner(&ownership_lock)?;
        let mut owner = Vec::with_capacity(OWNER_BYTES);
        Read::by_ref(&mut ownership_lock)
            .take(OWNER_BYTES as u64 + 1)
            .read_to_end(&mut owner)?;
        if owner.len() != OWNER_BYTES || &owner[..8] != OWNER_MAGIC {
            return Err(Error::InvalidStore);
        }
        let cache_id: [u8; 32] = owner[8..40].try_into().map_err(|_| Error::InvalidStore)?;
        if owner != owner_record(&directory, &cache_id)? {
            return Err(Error::InvalidStore);
        }
        ensure_absent(&directory, INDEX_STAGE)?;
        ensure_absent(&directory, CHUNK_STAGE)?;
        ensure_absent(&directory, REPLICA_STAGE)?;
        ensure_absent(&directory, MAILBOX_STAGE)?;
        let mut index = Vec::new();
        open_private_file(&directory, INDEX_FILE, MAX_INDEX_BYTES as u64)?
            .take(MAX_INDEX_BYTES as u64 + 1)
            .read_to_end(&mut index)?;
        let mut store = Self {
            directory,
            _ownership_lock: ownership_lock,
            cache_id,
            limits,
            entries: BTreeMap::new(),
            lru: VecDeque::new(),
            bytes: 0,
            healthy: true,
        };
        store.load_index(&index)?;
        store.check_name_metadata()?;
        store.check_free_space(0)?;
        for (id, length) in &store.entries {
            let file = open_private_file(&store.directory, &id.to_string(), CHUNK_BYTES as u64)?;
            if file.metadata()?.len() != *length {
                return Err(Error::Integrity(*id));
            }
        }
        Ok(store)
    }

    /// Current bounded payload/entry usage; filesystem metadata is not included.
    pub fn usage(&self) -> CacheUsage {
        CacheUsage {
            bytes: self.bytes,
            entries: self.entries.len(),
        }
    }

    // Only this fixed metadata name is available: callers cannot use the owned directory
    // handle to read/write arbitrary paths. The envelope binds it to this exact cache ID.
    pub(crate) fn read_replica_metadata(&self) -> Result<Option<Vec<u8>>, Error> {
        self.ensure_healthy()?;
        ensure_absent(&self.directory, REPLICA_STAGE)?;
        let maximum = MAX_REPLICA_METADATA_BYTES + REPLICA_OVERHEAD;
        let file = match open_private_file(&self.directory, REPLICA_FILE, maximum as u64) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() < REPLICA_OVERHEAD
            || bytes.len() > maximum
            || &bytes[..8] != REPLICA_MAGIC
            || bytes[8..40] != self.cache_id
        {
            return Err(Error::InvalidStore);
        }
        let end = bytes.len() - CHECKSUM_BYTES;
        if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
            return Err(Error::InvalidStore);
        }
        Ok(Some(bytes[40..end].to_vec()))
    }

    pub(crate) fn replace_replica_metadata(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > MAX_REPLICA_METADATA_BYTES {
            return Err(Error::Limit("replica metadata"));
        }
        // Never overwrite an unsafe, foreign or corrupt existing journal.
        self.read_replica_metadata()?;
        let mut bytes = Vec::with_capacity(payload.len() + REPLICA_OVERHEAD);
        bytes.extend_from_slice(REPLICA_MAGIC);
        bytes.extend_from_slice(&self.cache_id);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        self.check_free_space(bytes.len() as u64)?;
        self.healthy = false;
        let mut output = create_file(&self.directory, REPLICA_STAGE)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        rustix::fs::renameat(
            &self.directory,
            REPLICA_STAGE,
            &self.directory,
            REPLICA_FILE,
        )
        .map_err(io_error)?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }

    // A separate fixed-name journal keeps mailbox ownership out of the opportunistic replica
    // registry. Its original cache ID binding forbids copying/adopting another cache's index.
    pub(crate) fn read_mailbox_metadata(&self) -> Result<Option<Vec<u8>>, Error> {
        self.ensure_healthy()?;
        ensure_absent(&self.directory, MAILBOX_STAGE)?;
        let maximum = MAX_MAILBOX_METADATA_BYTES + REPLICA_OVERHEAD;
        let file = match open_private_file(&self.directory, MAILBOX_FILE, maximum as u64) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() < REPLICA_OVERHEAD
            || bytes.len() > maximum
            || &bytes[..8] != MAILBOX_MAGIC
            || bytes[8..40] != self.cache_id
        {
            return Err(Error::InvalidStore);
        }
        let end = bytes.len() - CHECKSUM_BYTES;
        if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
            return Err(Error::InvalidStore);
        }
        Ok(Some(bytes[40..end].to_vec()))
    }

    pub(crate) fn replace_mailbox_metadata(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > MAX_MAILBOX_METADATA_BYTES {
            return Err(Error::Limit("mailbox metadata"));
        }
        self.read_mailbox_metadata()?;
        let mut bytes = Vec::with_capacity(payload.len() + REPLICA_OVERHEAD);
        bytes.extend_from_slice(MAILBOX_MAGIC);
        bytes.extend_from_slice(&self.cache_id);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        self.check_free_space(bytes.len() as u64)?;
        self.healthy = false;
        let mut output = create_file(&self.directory, MAILBOX_STAGE)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        rustix::fs::renameat(
            &self.directory,
            MAILBOX_STAGE,
            &self.directory,
            MAILBOX_FILE,
        )
        .map_err(io_error)?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }

    /// Remove only one indexed, verified owned chunk; higher layers retain reference ownership.
    /// Never scans directories or changes ordinary LRU admission behavior.
    pub(crate) fn remove_owned_chunk(&mut self, id: ChunkId) -> Result<(), Error> {
        if self.get(&id)?.is_none() {
            return Ok(());
        }
        self.healthy = false;
        rustix::fs::unlinkat(&self.directory, id.to_string(), AtFlags::empty())
            .map_err(io_error)?;
        self.forget(&id);
        self.persist_index()?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }

    /// Insert a nonempty chunk under its SHA-256 name, atomically and without overwriting.
    ///
    /// Least recently used owned chunks are evicted when needed for byte/entry limits.
    /// Empty chunks are rejected; an empty object has an empty authenticated chunk list.
    ///
    /// # Errors
    /// Rejects empty/oversized data, insufficient quota/free space, corrupt existing bytes,
    /// and filesystem failures. Failure can leave earlier cache entries evicted.
    pub fn put(&mut self, bytes: &[u8]) -> Result<ChunkId, Error> {
        if bytes.is_empty() || bytes.len() > CHUNK_BYTES {
            return Err(Error::Limit("chunk length"));
        }
        let id = ChunkId::digest(bytes);
        self.put_verified(id, bytes)?;
        Ok(id)
    }

    /// Insert downloaded bytes only if their digest matches the requested content address.
    ///
    /// # Errors
    /// Returns an integrity error on mismatch, otherwise the same failures as [`Self::put`].
    pub fn put_verified(&mut self, expected: ChunkId, bytes: &[u8]) -> Result<(), Error> {
        self.ensure_healthy()?;
        if bytes.is_empty() || bytes.len() > CHUNK_BYTES {
            return Err(Error::Limit("chunk length"));
        }
        if ChunkId::digest(bytes) != expected {
            return Err(Error::Integrity(expected));
        }
        if self.entries.contains_key(&expected) && self.get(&expected)?.is_some() {
            return Ok(());
        }
        let length = bytes.len() as u64;
        if length > self.limits.max_bytes {
            return Err(Error::Quota);
        }
        while self.entries.len() >= self.limits.max_entries
            || self.bytes > self.limits.max_bytes - length
        {
            self.evict_oldest()?;
        }
        ensure_absent(&self.directory, &expected.to_string())?;
        let index_bytes =
            INDEX_HEADER_BYTES + (self.entries.len() + 1) * INDEX_ENTRY_BYTES + CHECKSUM_BYTES;
        self.check_free_space(length.checked_add(index_bytes as u64).ok_or(Error::Quota)?)?;
        // Reserve ownership durably before creating payload files. An interrupted insertion
        // therefore cannot become an unindexed/orphan chunk silently accepted on restart.
        self.healthy = false;
        self.bytes += length;
        self.entries.insert(expected, length);
        self.touch(expected);
        self.persist_index()?;
        let mut output = create_file(&self.directory, CHUNK_STAGE)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        rustix::fs::renameat_with(
            &self.directory,
            CHUNK_STAGE,
            &self.directory,
            expected.to_string(),
            RenameFlags::NOREPLACE,
        )
        .map_err(io_error)?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }

    /// Admit an opportunistic chunk without evicting any existing owned data.
    ///
    /// Returns `true` for a new insertion and `false` for an already-present verified chunk.
    /// The ordinary insertion integrity, atomic index and filesystem free-floor checks apply.
    ///
    /// # Errors
    /// Rejects invalid/corrupt bytes or stores, exhausted byte/entry/free-space capacity, and
    /// filesystem failures. In particular, quota pressure never evicts foreground chunks.
    pub fn put_verified_if_space(
        &mut self,
        expected: ChunkId,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        self.ensure_healthy()?;
        if bytes.is_empty() || bytes.len() > CHUNK_BYTES {
            return Err(Error::Limit("chunk length"));
        }
        if self.get(&expected)?.is_some() {
            self.put_verified(expected, bytes)?;
            return Ok(false);
        }
        if self.entries.len() >= self.limits.max_entries
            || self
                .bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.limits.max_bytes)
        {
            return Err(Error::Quota);
        }
        // The exclusively held store cannot change between this capacity check and insertion.
        self.put_verified(expected, bytes)?;
        Ok(true)
    }

    /// Load at most one chunk and verify its on-disk length and digest on every access.
    ///
    /// # Errors
    /// Rejects corrupt/nonregular files or filesystem errors. An absent chunk returns `None`.
    pub fn get(&mut self, id: &ChunkId) -> Result<Option<Vec<u8>>, Error> {
        self.ensure_healthy()?;
        let Some(&length) = self.entries.get(id) else {
            return Ok(None);
        };
        let file = match open_private_file(&self.directory, &id.to_string(), CHUNK_BYTES as u64) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.healthy = false;
                self.forget(id);
                self.persist_index()?;
                self.healthy = true;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() != length {
            return Err(Error::Integrity(*id));
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(length).map_err(|_| Error::Limit("chunk length"))?);
        file.take(CHUNK_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length || ChunkId::digest(&bytes) != *id {
            return Err(Error::Integrity(*id));
        }
        self.touch(*id);
        Ok(Some(bytes))
    }

    pub(crate) fn require_object_capacity(&self, length: u64) -> Result<(), Error> {
        self.ensure_healthy()?;
        let chunks = length.div_ceil(CHUNK_BYTES as u64);
        if length > self.limits.max_bytes
            || chunks > self.limits.max_entries as u64
            || chunks > MAX_CHUNKS as u64
        {
            return Err(Error::Quota);
        }
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), Error> {
        if !self.healthy {
            return Err(Error::InvalidStore);
        }
        Ok(())
    }

    fn check_free_space(&self, additional: u64) -> Result<(), Error> {
        let required = self
            .limits
            .min_free_bytes
            .checked_add(additional)
            .ok_or(Error::Quota)?;
        let filesystem = rustix::fs::fstatvfs(&self.directory).map_err(io_error)?;
        let available = filesystem
            .f_bavail
            .checked_mul(filesystem.f_frsize)
            .ok_or(Error::Quota)?;
        if available < required {
            return Err(Error::Quota);
        }
        Ok(())
    }

    fn persist_index(&self) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(
            INDEX_HEADER_BYTES + self.entries.len() * INDEX_ENTRY_BYTES + CHECKSUM_BYTES,
        );
        bytes.extend_from_slice(INDEX_MAGIC);
        bytes.extend_from_slice(&self.cache_id);
        bytes.extend_from_slice(
            &u32::try_from(self.entries.len())
                .map_err(|_| Error::InvalidStore)?
                .to_le_bytes(),
        );
        for id in &self.lru {
            let length = *self.entries.get(id).ok_or(Error::InvalidStore)?;
            bytes.extend_from_slice(id.as_bytes());
            bytes.extend_from_slice(
                &u32::try_from(length)
                    .map_err(|_| Error::InvalidStore)?
                    .to_le_bytes(),
            );
        }
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        self.check_free_space(bytes.len() as u64)?;
        let mut output = create_file(&self.directory, INDEX_STAGE)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        rustix::fs::renameat(&self.directory, INDEX_STAGE, &self.directory, INDEX_FILE)
            .map_err(io_error)?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn load_index(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() < INDEX_HEADER_BYTES + CHECKSUM_BYTES
            || bytes.len() > MAX_INDEX_BYTES
            || &bytes[..8] != INDEX_MAGIC
            || bytes[8..40] != self.cache_id
        {
            return Err(Error::InvalidStore);
        }
        let count =
            u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| Error::InvalidStore)?) as usize;
        if count > MAX_CACHE_ENTRIES
            || bytes.len() != INDEX_HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES
        {
            return Err(Error::InvalidStore);
        }
        let payload_end = bytes.len() - CHECKSUM_BYTES;
        if Sha256::digest(&bytes[..payload_end]).as_slice() != &bytes[payload_end..] {
            return Err(Error::InvalidStore);
        }
        if count > self.limits.max_entries {
            return Err(Error::Quota);
        }
        for entry in bytes[INDEX_HEADER_BYTES..payload_end].chunks_exact(INDEX_ENTRY_BYTES) {
            let id = ChunkId(entry[..32].try_into().map_err(|_| Error::InvalidStore)?);
            let length = u64::from(u32::from_le_bytes(
                entry[32..].try_into().map_err(|_| Error::InvalidStore)?,
            ));
            if length == 0 || length > CHUNK_BYTES as u64 || self.entries.contains_key(&id) {
                return Err(Error::InvalidStore);
            }
            self.bytes = self.bytes.checked_add(length).ok_or(Error::Quota)?;
            if self.bytes > self.limits.max_bytes {
                return Err(Error::Quota);
            }
            self.entries.insert(id, length);
            self.lru.push_back(id);
        }
        Ok(())
    }

    fn touch(&mut self, id: ChunkId) {
        self.lru.retain(|entry| *entry != id);
        self.lru.push_back(id);
    }

    fn forget(&mut self, id: &ChunkId) {
        if let Some(length) = self.entries.remove(id) {
            self.bytes -= length;
        }
        self.lru.retain(|entry| entry != id);
    }

    fn evict_oldest(&mut self) -> Result<(), Error> {
        let id = *self.lru.front().ok_or(Error::Quota)?;
        self.healthy = false;
        match rustix::fs::unlinkat(&self.directory, id.to_string(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(io_error(error)),
        }
        self.forget(&id);
        self.persist_index()?;
        self.healthy = true;
        Ok(())
    }
}

fn validate_limits(limits: CacheLimits) -> Result<(), Error> {
    if limits.max_bytes == 0 || limits.max_entries == 0 || limits.max_entries > MAX_CACHE_ENTRIES {
        return Err(Error::Limit("cache configuration"));
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, Error> {
    let directory = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?,
    );
    let metadata = directory.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(Error::InvalidStore);
    }
    Ok(directory)
}

fn create_file(directory: &File, name: &str) -> Result<File, Error> {
    Ok(File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io_error)?,
    ))
}

fn open_private_file(directory: &File, name: &str, maximum: u64) -> Result<File, Error> {
    let file = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?,
    );
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() > maximum
    {
        return Err(Error::InvalidStore);
    }
    Ok(file)
}

fn lock_owner(owner: &File) -> Result<(), Error> {
    rustix::fs::flock(owner, FlockOperation::NonBlockingLockExclusive).map_err(io_error)
}

fn owner_record(directory: &File, cache_id: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let metadata = directory.metadata()?;
    let mut owner = Vec::with_capacity(OWNER_BYTES);
    owner.extend_from_slice(OWNER_MAGIC);
    owner.extend_from_slice(cache_id);
    owner.extend_from_slice(&metadata.dev().to_le_bytes());
    owner.extend_from_slice(&metadata.ino().to_le_bytes());
    owner.extend_from_slice(&metadata.uid().to_le_bytes());
    Ok(owner)
}

fn ensure_absent(directory: &File, name: &str) -> Result<(), Error> {
    match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => Err(Error::InvalidStore),
        Err(error) => Err(io_error(error)),
    }
}

fn io_error(error: rustix::io::Errno) -> Error {
    Error::Io(error.into())
}
