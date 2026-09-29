use std::io::{Read, Write};

use rusqlite::{TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{
    LeaseId, PrivateStorageStore, StorageError, StoredArchive, disk::check_space, lease::load,
};
use crate::CHUNK_BYTES;

impl PrivateStorageStore {
    /// Stream an already encrypted archive into its existing durable reservation.
    /// SHA-256, exact length and ordered chunks are verified before the upload transaction
    /// commits. Failure rolls back all new chunks, but retains the original charged reservation
    /// for explicit retry or deletion. No complete archive is allocated in memory.
    ///
    /// # Errors
    /// Rejects expired/absent/already committed leases, changed input, bad hashes, exhausted
    /// free-space floor, input failures or `SQLite` failures. No failed upload is readable.
    pub fn write_reserved<R: Read>(
        &mut self,
        id: LeaseId,
        reader: &mut R,
        now: u64,
    ) -> Result<StoredArchive, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut archive = load(&transaction, id)?;
        if archive.committed {
            return Err(StorageError::AlreadyCommitted);
        }
        if archive.expires_at_unix <= now {
            return Err(StorageError::Expired);
        }
        let old_chunks: u64 = transaction.query_row(
            "SELECT count(*) FROM chunks WHERE lease_id = ?1",
            [id.0.as_slice()],
            |row| row.get(0),
        )?;
        if old_chunks != 0 {
            return Err(StorageError::InvalidStore);
        }
        let mut remaining = archive.ciphertext_bytes;
        let mut ordinal = 0_u64;
        let mut whole = Sha256::new();
        let mut buffer = vec![0; CHUNK_BYTES];
        {
            let mut insert = transaction.prepare_cached(
                "INSERT INTO chunks (lease_id, ordinal, sha256, payload) VALUES (?1, ?2, ?3, ?4)",
            )?;
            while remaining != 0 {
                let length = usize::try_from(remaining.min(CHUNK_BYTES as u64))
                    .map_err(|_| StorageError::InvalidStore)?;
                reader.read_exact(&mut buffer[..length])?;
                check_space(
                    &self.directory,
                    length as u64 + 64 * 1024,
                    self.limits.min_free_bytes,
                )?;
                whole.update(&buffer[..length]);
                let hash: [u8; 32] = Sha256::digest(&buffer[..length]).into();
                insert.execute(params![
                    id.0.as_slice(),
                    ordinal,
                    hash.as_slice(),
                    &buffer[..length]
                ])?;
                remaining -= length as u64;
                ordinal += 1;
            }
        }
        if reader.read(&mut [0; 1])? != 0 || <[u8; 32]>::from(whole.finalize()) != archive.sha256 {
            return Err(StorageError::Integrity);
        }
        transaction.execute(
            "UPDATE leases SET committed = 1 WHERE lease_id = ?1 AND committed = 0",
            [id.0.as_slice()],
        )?;
        transaction.commit()?;
        archive.committed = true;
        Ok(archive)
    }

    /// Restore unchanged ciphertext from a current committed lease without consuming it.
    /// Every ordered chunk and the complete archive are verified. A later error can leave a
    /// verified prefix in `writer`; use a private temporary destination and expose it only on
    /// success. The trusted caller supplies `now` at the start of this bounded-memory operation.
    ///
    /// # Errors
    /// Rejects absent/expired/pending leases, missing/reordered/corrupt chunks and writer/DB errors.
    pub fn restore<W: Write>(
        &self,
        id: LeaseId,
        writer: &mut W,
        now: u64,
    ) -> Result<StoredArchive, StorageError> {
        let archive = load(&self.connection, id)?;
        if !archive.committed {
            return Err(StorageError::NotCommitted);
        }
        if archive.expires_at_unix <= now {
            return Err(StorageError::Expired);
        }
        let mut statement = self.connection.prepare(
            "SELECT ordinal, sha256, payload FROM chunks WHERE lease_id = ?1 ORDER BY ordinal",
        )?;
        let mut rows = statement.query([id.0.as_slice()])?;
        let mut remaining = archive.ciphertext_bytes;
        let mut ordinal = 0_u64;
        let mut whole = Sha256::new();
        while let Some(row) = rows.next()? {
            let index: u64 = row.get(0)?;
            let expected: Vec<u8> = row.get(1)?;
            // Check the SQLite BLOB's borrowed length before allocating the one chunk buffer.
            let bytes = row
                .get_ref(2)?
                .as_blob()
                .map_err(|_| StorageError::InvalidStore)?;
            let length = remaining.min(CHUNK_BYTES as u64);
            if index != ordinal
                || length == 0
                || bytes.len() as u64 != length
                || expected.as_slice() != Sha256::digest(bytes).as_slice()
            {
                return Err(StorageError::Integrity);
            }
            whole.update(bytes);
            writer.write_all(bytes)?;
            remaining -= length;
            ordinal += 1;
        }
        if remaining != 0 || <[u8; 32]>::from(whole.finalize()) != archive.sha256 {
            return Err(StorageError::Integrity);
        }
        Ok(archive)
    }
}
