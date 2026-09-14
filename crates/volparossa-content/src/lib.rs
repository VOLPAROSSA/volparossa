//! Local, bounded storage for explicitly published native content.
//!
//! A manifest authenticates a publisher only against a caller's independently established
//! key. It is **not** proof of an HTTPS origin, current-name resolution, durable retention,
//! peer discovery, network retrieval, or an accepted content-network milestone.
//! The separate [`origin_https`] wrapper obtains narrowly scoped HTTPS resource authority
//! through the consumer's own authenticated origin connection, not from a native signature.

pub mod mailbox;
mod manifest;
pub mod origin_https;
pub mod private_message;
pub mod provider;
pub mod site;
mod store;
pub mod transfer;

use std::io::{Read, Write};
use std::path::Path;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

pub use manifest::{Chunk, Metadata, Publication, SignedManifest, Validity, VerifiedManifest};
pub use store::{CacheLimits, CacheUsage, ChunkStore, RevisionPin};

/// Maximum bytes in a chunk; reconstruction needs only one chunk buffer at a time.
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Maximum ordered chunks in one manifest.
pub const MAX_CHUNKS: usize = 1024;
/// Maximum encoded signed manifest length, checked before protobuf decoding.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum object length, independent of available disk space.
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum manifest lifetime; cache hits never extend it.
pub const MAX_VALIDITY_SECONDS: u64 = 31 * 24 * 60 * 60;
/// Maximum local stores considered for each reconstruction.
pub const MAX_SOURCES: usize = 16;

/// SHA-256 content address; neither a publisher identity nor an origin trust anchor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChunkId([u8; 32]);

impl ChunkId {
    /// Hash bytes using SHA-256. Insertion separately enforces chunk size limits.
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Return the binary SHA-256 digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ChunkId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

/// Failures are explicit: missing or corrupt bytes never become a successful cache hit.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The filesystem or input/output stream failed.
    #[error("content I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A protobuf, field, length, metadata value or canonical encoding was invalid.
    #[error("invalid native content manifest")]
    InvalidManifest,
    /// Cache ownership, its persisted index or an incomplete disk mutation was invalid.
    #[error("invalid or incomplete owned content cache")]
    InvalidStore,
    /// Current time is outside the signed validity interval.
    #[error("native content manifest is expired or not yet valid")]
    Expired,
    /// A peer supplied a manifest from a publisher other than the pre-established key.
    #[error("native content publisher is not the expected publisher")]
    WrongPublisher,
    /// A trusted named publication is older than this owned cache's retained revision floor.
    #[error("native content revision would roll back a retained observation")]
    NameRollback,
    /// The same trusted publisher/name/revision has two distinct signed envelope identities.
    #[error("native content revision has conflicting signed manifests")]
    NameConflict,
    /// The expected publisher did not authenticate these exact manifest bytes.
    #[error("invalid native content publisher signature")]
    InvalidSignature,
    /// A chunk's bytes or length do not match the authenticated manifest.
    #[error("content integrity failure for chunk {0}")]
    Integrity(ChunkId),
    /// No supplied store held an authenticated required chunk.
    #[error("missing content chunk {0}")]
    MissingChunk(ChunkId),
    /// A resource limit was exceeded before using the corresponding resource.
    #[error("content resource limit exceeded: {0}")]
    Limit(&'static str),
    /// The cache cannot accommodate this data or preserve its free-space floor.
    #[error("content cache quota or free-space floor exceeded")]
    Quota,
    /// The operating system could not supply a fresh manifest nonce.
    #[error("content manifest secure randomness unavailable")]
    Entropy,
}

/// Publish an explicitly sized native object to a local store and sign its exact manifest.
///
/// Reads at most one chunk at a time. The store must fit the complete declared object;
/// publishing cannot silently evict the object's own preceding chunks. Existing unrelated
/// chunks may be evicted. A failed read can leave unreferenced, quota-accounted chunks.
/// This is explicit native publishing, not permission to cache arbitrary captured traffic.
///
/// # Errors
/// Rejects invalid metadata/validity, oversized or incorrectly sized input, unavailable
/// randomness, insufficient cache resources, or filesystem failures.
pub fn publish<R: Read>(
    reader: &mut R,
    publication: Publication,
    publisher: &SigningKey,
    store: &mut ChunkStore,
) -> Result<SignedManifest, Error> {
    publication.validate()?;
    store.require_object_capacity(publication.length)?;
    let mut remaining = publication.length;
    let mut chunks = Vec::new();
    let mut whole_hash = Sha256::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    while remaining != 0 {
        let length = usize::try_from(remaining.min(CHUNK_BYTES as u64))
            .map_err(|_| Error::Limit("chunk length"))?;
        reader.read_exact(&mut buffer[..length])?;
        whole_hash.update(&buffer[..length]);
        let id = store.put(&buffer[..length])?;
        chunks.push(Chunk {
            id,
            length: u32::try_from(length).map_err(|_| Error::Limit("chunk length"))?,
        });
        remaining -= length as u64;
    }
    if reader.read(&mut [0; 1])? != 0 {
        return Err(Error::Limit("input exceeds declared object length"));
    }
    SignedManifest::sign(publication, chunks, whole_hash.finalize().into(), publisher)
}

/// Reconstruct exact, still-valid publisher-authenticated bytes from bounded local stores.
///
/// Missing chunks are sought in each supplied store. A corrupt copy fails explicitly;
/// this foundation does not implement source scoring or network fallback. Every emitted
/// chunk has its authenticated length and SHA-256 checked first. A later failure can leave
/// a verified prefix in `writer`; callers must honor the result before publishing output.
/// Use [`reassemble_to_file`] when partial output must not become visible at its final path.
/// `now_unix_seconds` is caller-supplied trusted time at the start of the operation.
///
/// # Errors
/// Rejects expired manifests, too many/no stores, absent or corrupt chunks and output errors.
pub fn reassemble<W: Write>(
    manifest: &VerifiedManifest,
    stores: &mut [&mut ChunkStore],
    now_unix_seconds: u64,
    writer: &mut W,
) -> Result<u64, Error> {
    manifest.check_time(now_unix_seconds)?;
    if stores.is_empty() || stores.len() > MAX_SOURCES {
        return Err(Error::Limit("reconstruction source count"));
    }
    let mut whole_hash = Sha256::new();
    for chunk in manifest.chunks() {
        let mut found = None;
        for store in stores.iter_mut() {
            if let Some(bytes) = store.get(chunk.id())? {
                found = Some(bytes);
                break;
            }
        }
        let bytes = found.ok_or(Error::MissingChunk(*chunk.id()))?;
        if bytes.len() as u64 != u64::from(chunk.length()) {
            return Err(Error::Integrity(*chunk.id()));
        }
        whole_hash.update(&bytes);
        writer.write_all(&bytes)?;
    }
    if <[u8; 32]>::from(whole_hash.finalize()) != manifest.whole_hash {
        return Err(Error::InvalidManifest);
    }
    Ok(manifest.length())
}

/// Reconstruct into a private temporary file, exposing the destination only on success.
///
/// The caller chooses a trusted local destination directory. Existing destination files
/// are never overwritten; failed reconstruction removes its own temporary output.
///
/// # Errors
/// Returns reconstruction failures or filesystem errors, including an existing destination.
pub fn reassemble_to_file(
    manifest: &VerifiedManifest,
    stores: &mut [&mut ChunkStore],
    now_unix_seconds: u64,
    destination: &Path,
) -> Result<u64, Error> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let length = reassemble(manifest, stores, now_unix_seconds, output.as_file_mut())?;
    output.as_file_mut().sync_all()?;
    output
        .persist_noclobber(destination)
        .map_err(|error| Error::Io(error.error))?;
    Ok(length)
}
