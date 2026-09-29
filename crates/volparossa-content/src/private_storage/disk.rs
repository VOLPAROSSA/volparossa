use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _},
    path::Path,
    time::Duration,
};

use rusqlite::{OpenFlags, params};
use rustix::fs::{FlockOperation, Mode, OFlags};

use super::{
    APPLICATION_ID, PrivateStorageStore, StorageError, StorageLimits, VERSION, admission,
    valid_limits,
};

const OWNER: &str = ".volparossa-private-storage-v1";
const DATABASE: &str = "private-storage.sqlite3";
const MAGIC: &[u8; 8] = b"VPST0001";
const OWNER_BYTES: usize = 60;

impl PrivateStorageStore {
    /// Create a new mode-0700 owned store. An existing directory is never adopted.
    ///
    /// # Errors
    /// Rejects invalid limits/paths, existing directories, unavailable space or disk failures.
    pub fn create(path: &Path, limits: StorageLimits) -> Result<Self, StorageError> {
        valid_limits(limits)?;
        valid_path(path)?;
        fs::DirBuilder::new().mode(0o700).create(path)?;
        let directory = directory(path)?;
        check_space(&directory, 64 * 1024, limits.min_free_bytes)?;
        let mut owner = create_file(&directory, OWNER)?;
        lock(&owner)?;
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| StorageError::Entropy)?;
        owner.write_all(&owner_record(&directory, &id)?)?;
        owner.sync_all()?;
        drop(create_file(&directory, DATABASE)?);
        let connection = connection(&directory, path)?;
        connection.execute_batch(
            "PRAGMA auto_vacuum = FULL;
             CREATE TABLE storage_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL, store_id BLOB NOT NULL CHECK(length(store_id) = 32),
                capacity_bytes INTEGER NOT NULL CHECK(capacity_bytes > 0),
                min_free_bytes INTEGER NOT NULL CHECK(min_free_bytes >= 0),
                admission_target_bytes INTEGER NOT NULL
                    CHECK(admission_target_bytes >= 0 AND admission_target_bytes <= capacity_bytes)
             ) STRICT;
             CREATE TABLE leases (
                lease_id BLOB PRIMARY KEY CHECK(length(lease_id) = 16),
                ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes >= 0),
                sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
                expires INTEGER NOT NULL CHECK(expires > 0),
                committed INTEGER NOT NULL CHECK(committed IN (0,1))
             ) STRICT;
             CREATE TABLE chunks (
                lease_id BLOB NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
                payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 262144),
                PRIMARY KEY(lease_id, ordinal)
             ) STRICT;",
        )?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", VERSION)?;
        connection.execute(
            "INSERT INTO storage_meta VALUES (1, ?1, ?2, ?3, ?4, ?3)",
            params![
                VERSION,
                id.as_slice(),
                limits.capacity_bytes,
                limits.min_free_bytes
            ],
        )?;
        directory.sync_all()?;
        Ok(Self {
            connection,
            directory,
            _owner: owner,
            limits,
        })
    }

    /// Open an owned store, requiring exactly its original persisted limits.
    ///
    /// # Errors
    /// Rejects changed limits, foreign/busy ownership, invalid metadata or `SQLite` failures.
    pub fn open(path: &Path, limits: StorageLimits) -> Result<Self, StorageError> {
        valid_limits(limits)?;
        let store = Self::open_existing(path)?;
        if store.limits != limits {
            return Err(StorageError::InvalidInput);
        }
        Ok(store)
    }

    /// Reopen the exact owned store with its durable configured limits. No data is evicted.
    /// Committed chunks are verified when restored, not fully rehashed on every status query.
    /// Version-one stores are upgraded atomically with their original capacity as the target.
    ///
    /// # Errors
    /// Rejects foreign/busy ownership, unsafe database files, corrupt metadata or `SQLite` errors.
    pub fn open_existing(path: &Path) -> Result<Self, StorageError> {
        valid_path(path)?;
        let directory = directory(path)?;
        let mut owner = private_file(&directory, OWNER, OWNER_BYTES as u64)?;
        lock(&owner)?;
        let mut bytes = Vec::with_capacity(OWNER_BYTES);
        owner.read_to_end(&mut bytes)?;
        if bytes.len() != OWNER_BYTES || &bytes[..8] != MAGIC {
            return Err(StorageError::InvalidStore);
        }
        let id: [u8; 32] = bytes[8..40]
            .try_into()
            .map_err(|_| StorageError::InvalidStore)?;
        if bytes != owner_record(&directory, &id)? {
            return Err(StorageError::InvalidStore);
        }
        drop(private_file(&directory, DATABASE, u64::MAX)?);
        let connection = connection(&directory, path)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if application != APPLICATION_ID || !matches!(version, 1 | VERSION) {
            return Err(StorageError::InvalidStore);
        }
        let (stored_version, stored_id, capacity_bytes, min_free_bytes): (i64, Vec<u8>, u64, u64) =
            connection.query_row("SELECT version, store_id, capacity_bytes, min_free_bytes FROM storage_meta WHERE singleton = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
        let limits = StorageLimits {
            capacity_bytes,
            min_free_bytes,
        };
        valid_limits(limits).map_err(|_| StorageError::InvalidStore)?;
        if stored_version != version || stored_id != id {
            return Err(StorageError::InvalidStore);
        }
        let mut store = Self {
            connection,
            directory,
            _owner: owner,
            limits,
        };
        store.usage()?;
        if version == 1 {
            admission::upgrade(&mut store)?;
        }
        store.admission_status()?;
        Ok(store)
    }
}

pub(super) fn check_space(directory: &File, bytes: u64, floor: u64) -> Result<(), StorageError> {
    let space = rustix::fs::fstatvfs(directory).map_err(io)?;
    let available = u128::from(space.f_bavail) * u128::from(space.f_frsize);
    if available < u128::from(bytes) + u128::from(floor) {
        return Err(StorageError::Quota);
    }
    Ok(())
}

fn connection(
    directory: &File,
    original_path: &Path,
) -> Result<rusqlite::Connection, StorageError> {
    // SQLite's NOFOLLOW rejects the procfs descriptor symlink too. Resolve the explicit local
    // directory, then verify both its identity and the checked private database leaf around
    // opening. The owner lock remains held; callers must not rename an actively open store.
    let path = original_path.canonicalize()?;
    same_file(directory, &path)?;
    let database = private_file(directory, DATABASE, u64::MAX)?;
    let database_path = path.join(DATABASE);
    same_file(&database, &database_path)?;
    let connection = rusqlite::Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    same_file(directory, &path)?;
    same_file(&database, &database_path)?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -8192;",
    )?;
    Ok(connection)
}

fn same_file(expected: &File, path: &Path) -> Result<(), StorageError> {
    let opened = expected.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.uid() != named.uid()
        || named.mode() & 0o077 != 0
    {
        return Err(StorageError::InvalidStore);
    }
    Ok(())
}

fn valid_path(path: &Path) -> Result<(), StorageError> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}

fn directory(path: &Path) -> Result<File, StorageError> {
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?,
    );
    let metadata = file.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(StorageError::InvalidStore);
    }
    Ok(file)
}

fn create_file(directory: &File, name: &str) -> Result<File, StorageError> {
    Ok(File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io)?,
    ))
}

fn private_file(directory: &File, name: &str, maximum: u64) -> Result<File, StorageError> {
    let file = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?,
    );
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() > maximum
    {
        return Err(StorageError::InvalidStore);
    }
    Ok(file)
}

fn lock(file: &File) -> Result<(), StorageError> {
    rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            StorageError::Busy
        } else {
            io(error)
        }
    })
}

fn owner_record(directory: &File, id: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
    let metadata = directory.metadata()?;
    let mut bytes = Vec::with_capacity(OWNER_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(&metadata.dev().to_le_bytes());
    bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    bytes.extend_from_slice(&metadata.uid().to_le_bytes());
    Ok(bytes)
}

fn io(error: rustix::io::Errno) -> StorageError {
    StorageError::Io(error.into())
}
