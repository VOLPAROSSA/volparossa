//! Explicit local custody of caller-supplied, already encrypted archives.
//!
//! This store does not encrypt or recognize Signal formats. It preserves opaque bytes and
//! checks caller-pinned SHA-256 identities. It neither publishes content nor enrolls it for
//! compute/training. The local store supplies no network-wide contribution credit or
//! replication guarantee. The separate protocol/provider/wire modules authenticate bounded
//! owner operations and retain durable ownership; their caller must supply an independently
//! authenticated protected stream. They do not establish overlay routes or global reciprocity.
//!
//! Each lease owns its own physical ciphertext copy: no cross-lease deduplication changes
//! accounting. Payload capacity excludes SQLite/filesystem overhead, for which a separate
//! free-space floor is enforced. Complete payload space is reserved durably before writing.
//! Failed uploads retain their reservation; expired leases remain charged until deletion.

mod admission;
mod archive;
mod disk;
mod lease;
pub mod protocol;
pub mod provider;
mod resumable;
pub mod wire;

pub use admission::StorageAdmissionStatus;
pub use resumable::{ArchiveRange, MAX_RANGE_BYTES, MAX_RANGE_CHUNKS, UploadProgress};

use std::{fmt, fs::File, str::FromStr};

use rusqlite::Connection;

/// Maximum streamed ciphertext archive: 64 GiB; no whole-archive allocation is used.
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Maximum explicitly configured ciphertext payload capacity: 1 TiB.
pub const MAX_CAPACITY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Maximum new lease interval. Renewal changes the lease, never immutable archive identity.
pub const MAX_LEASE_SECONDS: u64 = 31 * 24 * 60 * 60;
const MAX_LEASES: u64 = 256;
const VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x5650_5331;

/// Explicit, persisted local contribution limits, not proof of network-wide contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLimits {
    /// Maximum summed reserved and committed ciphertext bytes, counting every copy.
    pub capacity_bytes: u64,
    /// Filesystem free bytes preserved before reservations and every chunk write.
    pub min_free_bytes: u64,
}

/// Exact retained payload accounting. Database and filesystem metadata are additional.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageUsage {
    /// Pending reservations, including failed uploads and expired undeleted reservations.
    pub reserved_bytes: u64,
    /// Verified committed ciphertext payload, including expired undeleted copies.
    pub committed_bytes: u64,
    /// Pending plus committed leases; bounded independently of payload size.
    pub leases: u64,
}

/// Opaque local storage identifier, not a bearer capability or authenticated remote lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LeaseId([u8; 16]);

impl LeaseId {
    /// Construct the fixed-width identifier used by local commands.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Original opaque identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for LeaseId {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StorageError::InvalidInput);
        }
        let mut bytes = [0; 16];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| StorageError::InvalidInput)?;
        Ok(Self(bytes))
    }
}

/// Local immutable archive identity with its separately mutable retention lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredArchive {
    /// Exact storage lease/copy identifier.
    pub lease_id: LeaseId,
    /// Exact supplied ciphertext length; each copy is charged separately.
    pub ciphertext_bytes: u64,
    /// Caller-pinned SHA-256 of the complete ordered ciphertext archive.
    pub sha256: [u8; 32],
    /// Current finite lease deadline; it is not part of the immutable ciphertext identity.
    pub expires_at_unix: u64,
    /// Only complete verified uploads become readable; inspection does not rehash payload.
    pub committed: bool,
}

/// Private local custody failure; no error is a successful storage or availability receipt.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Local filesystem or caller-supplied stream failed.
    #[error("private storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The owned `SQLite` journal failed; no mutation success may be inferred.
    #[error("private storage database failed")]
    Database(#[from] rusqlite::Error),
    /// Private directory, owner marker, database or stored metadata is invalid.
    #[error("invalid owned private storage")]
    InvalidStore,
    /// Explicit limits, length, identifier or finite lease interval is invalid.
    #[error("invalid private storage request")]
    InvalidInput,
    /// Another process owns this store; no concurrent admission is permitted.
    #[error("private storage is already open")]
    Busy,
    /// Full reservation, lease count or actual filesystem floor cannot be accommodated.
    #[error("private storage quota or free-space floor exceeded")]
    Quota,
    /// Reads/uploads require a current lease; explicit local renewal can retain old bytes.
    #[error("private storage lease expired")]
    Expired,
    /// No exact local lease exists.
    #[error("private storage lease not found")]
    NotFound,
    /// The reservation has not completed a verified upload.
    #[error("private storage archive is not committed")]
    NotCommitted,
    /// A committed copy cannot be overwritten by another upload.
    #[error("private storage archive is already committed")]
    AlreadyCommitted,
    /// Ordered chunk lengths, chunk hashes or whole-archive hash do not agree.
    #[error("private storage archive integrity failure")]
    Integrity,
    /// Operating-system randomness failed before allocating an identifier.
    #[error("private storage randomness unavailable")]
    Entropy,
}

/// One exclusively owned, durable local ciphertext store. Dropping it closes the owner lock.
/// No listener, network publication, plaintext inspection or automatic deletion is started.
pub struct PrivateStorageStore {
    connection: Connection,
    directory: File,
    _owner: File,
    limits: StorageLimits,
}

impl PrivateStorageStore {
    /// Immutable limits persisted when this store was created.
    #[must_use]
    pub const fn limits(&self) -> StorageLimits {
        self.limits
    }
}

fn valid_limits(limits: StorageLimits) -> Result<(), StorageError> {
    if !(1..=MAX_CAPACITY_BYTES).contains(&limits.capacity_bytes)
        || limits.min_free_bytes > MAX_CAPACITY_BYTES
    {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}

fn valid_expiry(expires: u64, now: u64) -> Result<(), StorageError> {
    if now == 0 || expires <= now || expires - now > MAX_LEASE_SECONDS || expires > i64::MAX as u64
    {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}
