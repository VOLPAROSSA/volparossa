//! Durable ciphertext prefixes within an already charged local reservation.
//!
//! These synchronous operations do not authenticate remote callers. A network service must
//! independently authorize the exact owner, lease, operation and range before calling them.

use std::io::Write;

use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{
    LeaseId, PrivateStorageStore, StorageError, StoredArchive, disk::check_space, lease::load,
};
use crate::CHUNK_BYTES;

/// Maximum chunks in a single range, independent of the whole archive size.
pub const MAX_RANGE_CHUNKS: u32 = 64;
/// Maximum bytes in a single range: 64 chunks of 256 KiB.
pub const MAX_RANGE_BYTES: u64 = MAX_RANGE_CHUNKS as u64 * CHUNK_BYTES as u64;

/// Durable upload position, not a fresh integrity proof or remote custody receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadProgress {
    /// Original archive identity, current lease deadline and commit state.
    pub archive: StoredArchive,
    /// Next contiguous ordinal; smaller ordinals can only be retried identically.
    pub next_chunk: u64,
    /// Persisted prefix length. The full archive remains charged while incomplete.
    pub received_bytes: u64,
}

/// Exact successfully emitted range; reading never consumes or renews a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveRange {
    /// Committed archive identity; callers still verify its whole hash after reconstruction.
    pub archive: StoredArchive,
    /// First included chunk, starting at zero.
    pub first_chunk: u64,
    /// Exact number of included chunks, at most [`MAX_RANGE_CHUNKS`].
    pub chunk_count: u32,
    /// Exact emitted ciphertext bytes, at most [`MAX_RANGE_BYTES`].
    pub ciphertext_bytes: u64,
}

impl PrivateStorageStore {
    /// Append one exact chunk or accept an identical retry without writing another copy.
    ///
    /// The ordinal must be the next prefix chunk, or an already stored identical chunk.
    /// Every non-final chunk is exactly 256 KiB; the final length follows the original
    /// reservation. The supplied chunk hash is checked, but only [`Self::finalize`] checks
    /// the original whole-archive hash. Success durably preserves the prefix across restart.
    /// Identical retries also work after commit; committed bytes can never be replaced.
    ///
    /// # Errors
    /// Rejects invalid ordinals/lengths, expired leases, conflicting retries, incorrect
    /// hashes, missing/corrupt prefix metadata, free-space exhaustion or journal failures.
    pub fn append_chunk(
        &mut self,
        id: LeaseId,
        ordinal: u64,
        expected_sha256: [u8; 32],
        bytes: &[u8],
        now: u64,
    ) -> Result<UploadProgress, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let archive = current_archive(&transaction, id, now)?;
        if bytes.len() as u64 != chunk_length(&archive, ordinal)? {
            return Err(StorageError::InvalidInput);
        }
        if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
            return Err(StorageError::Integrity);
        }
        let mut progress = progress(&transaction, archive)?;
        if ordinal < progress.next_chunk {
            verify_retry(&transaction, id, ordinal, &expected_sha256, bytes)?;
        } else {
            if ordinal != progress.next_chunk {
                return Err(StorageError::InvalidInput);
            }
            if archive.committed {
                return Err(StorageError::AlreadyCommitted);
            }
            check_space(
                &self.directory,
                bytes.len() as u64 + 64 * 1024,
                self.limits.min_free_bytes,
            )?;
            transaction.execute(
                "INSERT INTO chunks (lease_id, ordinal, sha256, payload) VALUES (?1, ?2, ?3, ?4)",
                params![
                    id.as_bytes().as_slice(),
                    ordinal,
                    expected_sha256.as_slice(),
                    bytes
                ],
            )?;
            progress.next_chunk += 1;
            progress.received_bytes += bytes.len() as u64;
        }
        transaction.commit()?;
        Ok(progress)
    }

    /// Read the durable contiguous prefix position without rehashing the whole archive.
    ///
    /// This checks contiguous ordinal metadata and the last chunk's exact length. Stored
    /// payload integrity is verified during identical retries, finalization and range reads,
    /// not inferred from this metadata observation. An incomplete prefix is never readable.
    ///
    /// # Errors
    /// Rejects absent/expired leases, malformed prefix metadata and journal failures.
    pub fn upload_progress(&self, id: LeaseId, now: u64) -> Result<UploadProgress, StorageError> {
        progress(
            &self.connection,
            current_archive(&self.connection, id, now)?,
        )
    }

    /// Verify every ordered chunk and the complete original hash, then durably commit.
    ///
    /// Memory use is bounded by a single borrowed chunk. A retry on a committed archive
    /// revalidates its actual bytes rather than returning cached metadata as fresh proof.
    /// Failure leaves the existing prefix and full reservation intact for inspection or
    /// explicit deletion; incorrect bytes are never exposed as a completed archive.
    /// The trusted caller supplies `now` at operation start, as with local full restores.
    ///
    /// # Errors
    /// Rejects expired/absent leases, missing/reordered/corrupt chunks, a mismatched whole
    /// hash or journal failures. No partial archive becomes committed on failure.
    pub fn finalize(&mut self, id: LeaseId, now: u64) -> Result<StoredArchive, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut archive = current_archive(&transaction, id, now)?;
        verify_archive(&transaction, &archive)?;
        if !archive.committed {
            transaction.execute(
                "UPDATE leases SET committed = 1 WHERE lease_id = ?1 AND committed = 0",
                [id.as_bytes().as_slice()],
            )?;
        }
        transaction.commit()?;
        archive.committed = true;
        Ok(archive)
    }

    /// Stream an exact range of 1–64 chunks from a committed archive without consuming it.
    ///
    /// Each returned chunk's ordinal, length and stored hash are verified. This is not a
    /// rehash of bytes outside the requested range: the recipient must check the original
    /// whole-archive hash after assembling all ranges. No whole-range allocation is used.
    /// Errors can leave a verified prefix in `writer`; publish a restored file only after
    /// complete reconstruction and hash verification. A range never extends past EOF.
    ///
    /// # Errors
    /// Rejects zero/oversized/out-of-bounds ranges, absent/expired/incomplete leases,
    /// missing or corrupt chunks and writer/journal failures.
    pub fn read_range<W: Write>(
        &self,
        id: LeaseId,
        first_chunk: u64,
        chunk_count: u32,
        writer: &mut W,
        now: u64,
    ) -> Result<ArchiveRange, StorageError> {
        let archive = current_archive(&self.connection, id, now)?;
        if !archive.committed {
            return Err(StorageError::NotCommitted);
        }
        let end = first_chunk
            .checked_add(u64::from(chunk_count))
            .filter(|end| *end <= total_chunks(&archive))
            .ok_or(StorageError::InvalidInput)?;
        if !(1..=MAX_RANGE_CHUNKS).contains(&chunk_count) {
            return Err(StorageError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT ordinal, sha256, payload FROM chunks
             WHERE lease_id = ?1 AND ordinal >= ?2 AND ordinal < ?3 ORDER BY ordinal",
        )?;
        let mut rows = statement.query(params![id.as_bytes().as_slice(), first_chunk, end])?;
        let mut next = first_chunk;
        let mut ciphertext_bytes = 0;
        while let Some(row) = rows.next()? {
            let bytes = checked_chunk(row, &archive, next)?;
            writer.write_all(bytes)?;
            ciphertext_bytes += bytes.len() as u64;
            next += 1;
        }
        if next != end {
            return Err(StorageError::Integrity);
        }
        Ok(ArchiveRange {
            archive,
            first_chunk,
            chunk_count,
            ciphertext_bytes,
        })
    }
}

fn current_archive(
    connection: &Connection,
    id: LeaseId,
    now: u64,
) -> Result<StoredArchive, StorageError> {
    if now == 0 {
        return Err(StorageError::InvalidInput);
    }
    let archive = load(connection, id)?;
    if archive.expires_at_unix <= now {
        return Err(StorageError::Expired);
    }
    Ok(archive)
}

fn total_chunks(archive: &StoredArchive) -> u64 {
    archive.ciphertext_bytes.div_ceil(CHUNK_BYTES as u64)
}

fn chunk_length(archive: &StoredArchive, ordinal: u64) -> Result<u64, StorageError> {
    if ordinal >= total_chunks(archive) {
        return Err(StorageError::InvalidInput);
    }
    Ok((archive.ciphertext_bytes - ordinal * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64))
}

fn progress(
    connection: &Connection,
    archive: StoredArchive,
) -> Result<UploadProgress, StorageError> {
    // Count only the index, not all payload BLOBs, on each append. Complete payload checking
    // belongs to finalization; the unique primary key plus min/max checks detects gaps.
    let (count, first, last): (u64, Option<u64>, Option<u64>) = connection.query_row(
        "SELECT count(*), min(ordinal), max(ordinal) FROM chunks WHERE lease_id = ?1",
        [archive.lease_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if count > total_chunks(&archive)
        || (count == 0 && (first.is_some() || last.is_some()))
        || (count > 0 && (first != Some(0) || last != Some(count - 1)))
        || (archive.committed && count != total_chunks(&archive))
    {
        return Err(StorageError::Integrity);
    }
    let received_bytes = if count == 0 {
        0
    } else {
        let length: u64 = connection.query_row(
            "SELECT length(payload) FROM chunks WHERE lease_id = ?1 AND ordinal = ?2",
            params![archive.lease_id.as_bytes().as_slice(), count - 1],
            |row| row.get(0),
        )?;
        if length != chunk_length(&archive, count - 1)? {
            return Err(StorageError::Integrity);
        }
        (count - 1) * CHUNK_BYTES as u64 + length
    };
    Ok(UploadProgress {
        archive,
        next_chunk: count,
        received_bytes,
    })
}

fn verify_retry(
    connection: &Connection,
    id: LeaseId,
    ordinal: u64,
    hash: &[u8; 32],
    bytes: &[u8],
) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("SELECT sha256, payload FROM chunks WHERE lease_id = ?1 AND ordinal = ?2")?;
    let mut rows = statement.query(params![id.as_bytes().as_slice(), ordinal])?;
    let row = rows.next()?.ok_or(StorageError::Integrity)?;
    let saved_hash = row
        .get_ref(0)?
        .as_blob()
        .map_err(|_| StorageError::Integrity)?;
    let saved_bytes = row
        .get_ref(1)?
        .as_blob()
        .map_err(|_| StorageError::Integrity)?;
    if saved_hash != hash || saved_bytes != bytes {
        return Err(StorageError::Integrity);
    }
    Ok(())
}

fn checked_chunk<'a>(
    row: &'a rusqlite::Row<'_>,
    archive: &StoredArchive,
    expected_ordinal: u64,
) -> Result<&'a [u8], StorageError> {
    let ordinal: u64 = row.get(0)?;
    let saved_hash = row
        .get_ref(1)?
        .as_blob()
        .map_err(|_| StorageError::Integrity)?;
    let bytes = row
        .get_ref(2)?
        .as_blob()
        .map_err(|_| StorageError::Integrity)?;
    if ordinal != expected_ordinal
        || bytes.len() as u64
            != chunk_length(archive, ordinal).map_err(|_| StorageError::Integrity)?
        || saved_hash != Sha256::digest(bytes).as_slice()
    {
        return Err(StorageError::Integrity);
    }
    Ok(bytes)
}

fn verify_archive(connection: &Connection, archive: &StoredArchive) -> Result<(), StorageError> {
    let mut statement = connection.prepare(
        "SELECT ordinal, sha256, payload FROM chunks WHERE lease_id = ?1 ORDER BY ordinal",
    )?;
    let mut rows = statement.query([archive.lease_id.as_bytes().as_slice()])?;
    let mut next = 0;
    let mut whole = Sha256::new();
    while let Some(row) = rows.next()? {
        whole.update(checked_chunk(row, archive, next)?);
        next += 1;
    }
    if next != total_chunks(archive) || <[u8; 32]>::from(whole.finalize()) != archive.sha256 {
        return Err(StorageError::Integrity);
    }
    Ok(())
}
