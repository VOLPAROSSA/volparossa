use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::{CHUNK_BYTES, ChunkId, Error, MAX_CHUNKS};

const MAX_CACHE_ENTRIES: usize = 65_536;

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
/// Creation refuses every existing path, including symlinks. Only files this handle created
/// enter its index or can be evicted. No arbitrary directory scanning/adoption is performed.
/// This initial API does not reopen a cache after process restart. Dropping the handle leaves
/// its files on disk for the caller to retain/remove explicitly; there is no automatic sweep.
/// Cache access is synchronous and requires exclusive mutable access through this handle.
#[derive(Debug)]
pub struct ChunkStore {
    directory: PathBuf,
    limits: CacheLimits,
    entries: BTreeMap<ChunkId, u64>,
    lru: VecDeque<ChunkId>,
    bytes: u64,
}

impl ChunkStore {
    /// Create a fresh mode-0700 cache directory beneath a caller-selected trusted parent.
    ///
    /// # Errors
    /// Rejects existing paths, zero/excessive limits or failure to create the directory.
    pub fn create(directory: &Path, limits: CacheLimits) -> Result<Self, Error> {
        if limits.max_bytes == 0
            || limits.max_entries == 0
            || limits.max_entries > MAX_CACHE_ENTRIES
        {
            return Err(Error::Limit("cache configuration"));
        }
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            limits,
            entries: BTreeMap::new(),
            lru: VecDeque::new(),
            bytes: 0,
        })
    }

    /// Current bounded payload/entry usage; filesystem metadata is not included.
    pub fn usage(&self) -> CacheUsage {
        CacheUsage {
            bytes: self.bytes,
            entries: self.entries.len(),
        }
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
        let required_free = self
            .limits
            .min_free_bytes
            .checked_add(length)
            .ok_or(Error::Quota)?;
        let filesystem =
            rustix::fs::statvfs(&self.directory).map_err(|error| Error::Io(error.into()))?;
        let available = filesystem
            .f_bavail
            .checked_mul(filesystem.f_frsize)
            .ok_or(Error::Quota)?;
        if available < required_free {
            return Err(Error::Quota);
        }
        let mut output = tempfile::NamedTempFile::new_in(&self.directory)?;
        output.write_all(bytes)?;
        output.as_file_mut().sync_all()?;
        output
            .persist_noclobber(self.path(&expected))
            .map_err(|error| Error::Io(error.error))?;
        self.bytes += length;
        self.entries.insert(expected, length);
        self.touch(expected);
        Ok(())
    }

    /// Load at most one chunk and verify its on-disk length and digest on every access.
    ///
    /// # Errors
    /// Rejects corrupt/nonregular files or filesystem errors. An absent chunk returns `None`.
    pub fn get(&mut self, id: &ChunkId) -> Result<Option<Vec<u8>>, Error> {
        let Some(&length) = self.entries.get(id) else {
            return Ok(None);
        };
        let path = self.path(id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.forget(id);
                return Ok(None);
            }
            Err(error) => return Err(Error::Io(error)),
        };
        if !metadata.file_type().is_file() || metadata.len() != length {
            return Err(Error::Integrity(*id));
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(length).map_err(|_| Error::Limit("chunk length"))?);
        File::open(path)?
            .take(CHUNK_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length || ChunkId::digest(&bytes) != *id {
            return Err(Error::Integrity(*id));
        }
        self.touch(*id);
        Ok(Some(bytes))
    }

    pub(crate) fn require_object_capacity(&self, length: u64) -> Result<(), Error> {
        let chunks = length.div_ceil(CHUNK_BYTES as u64);
        if length > self.limits.max_bytes
            || chunks > self.limits.max_entries as u64
            || chunks > MAX_CHUNKS as u64
        {
            return Err(Error::Quota);
        }
        Ok(())
    }

    fn path(&self, id: &ChunkId) -> PathBuf {
        self.directory.join(hex::encode(id.0))
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
        match fs::remove_file(self.path(&id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        self.forget(&id);
        Ok(())
    }
}
