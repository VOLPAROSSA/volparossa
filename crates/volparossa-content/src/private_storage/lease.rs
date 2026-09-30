use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::{
    LeaseId, MAX_ARCHIVE_BYTES, MAX_LEASES, PrivateStorageStore, StorageError, StorageLimits,
    StorageUsage, StoredArchive, admission, disk::check_space, valid_expiry,
};

impl PrivateStorageStore {
    /// Durably reserve the complete ciphertext length before any payload write.
    /// Reservations and committed copies share one capacity; even identical archives are
    /// independent physical copies. No external contribution credit is authenticated here.
    ///
    /// # Errors
    /// Rejects invalid length/expiry, exhausted capacity/count/free space or journal failures.
    pub fn reserve(
        &mut self,
        ciphertext_bytes: u64,
        expected_sha256: [u8; 32],
        expires_at_unix: u64,
        now: u64,
    ) -> Result<LeaseId, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = reserve_in_transaction(
            &transaction,
            &self.directory,
            self.limits,
            Reservation {
                ciphertext_bytes,
                expected_sha256,
                expires_at_unix,
                now,
            },
        )?;
        transaction.commit()?;
        Ok(id)
    }

    /// Return pending and complete ciphertext accounting, including expired undeleted leases.
    ///
    /// # Errors
    /// Rejects invalid persisted accounting or database failures.
    pub fn usage(&self) -> Result<StorageUsage, StorageError> {
        usage(&self.connection, self.limits.capacity_bytes)
    }

    /// Inspect one exact lease's metadata without claiming a fresh payload integrity check.
    ///
    /// # Errors
    /// Rejects absent leases, invalid metadata or database failures.
    pub fn inspect(&self, id: LeaseId) -> Result<StoredArchive, StorageError> {
        load(&self.connection, id)
    }

    /// Explicitly renew this local owner's retained copy without changing its ciphertext.
    /// Expired but undeleted copies may be renewed locally; this is not remote authorization.
    /// Renewal never shortens a current lease and never revives an explicitly deleted copy.
    ///
    /// # Errors
    /// Rejects absent leases, invalid/shorter intervals or journal failures.
    pub fn renew(
        &mut self,
        id: LeaseId,
        new_expiry: u64,
        now: u64,
    ) -> Result<StoredArchive, StorageError> {
        valid_expiry(new_expiry, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut archive = load(&transaction, id)?;
        if new_expiry < archive.expires_at_unix {
            return Err(StorageError::InvalidInput);
        }
        transaction.execute(
            "UPDATE leases SET expires = ?2 WHERE lease_id = ?1",
            params![id.0.as_slice(), new_expiry],
        )?;
        transaction.commit()?;
        archive.expires_at_unix = new_expiry;
        Ok(archive)
    }

    /// Delete only this exact reservation/copy and release its accounted payload capacity.
    /// Other leases, including identical ciphertext copies, are untouched. Absent retries
    /// return `false`. This is ordinary deletion, not a secure-erase guarantee for an SSD.
    ///
    /// # Errors
    /// Returns journal errors; callers must not infer capacity release from a failed deletion.
    pub fn delete(&mut self, id: LeaseId) -> Result<bool, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted =
            transaction.execute("DELETE FROM leases WHERE lease_id = ?1", [id.0.as_slice()])?;
        transaction.commit()?;
        Ok(deleted != 0)
    }
}

/// Shared transaction-local insertion; the caller alone commits the lease and any owner
/// binding together. This is not a public authorization bypass or a separate transaction.
#[derive(Clone, Copy)]
pub(super) struct Reservation {
    pub ciphertext_bytes: u64,
    pub expected_sha256: [u8; 32],
    pub expires_at_unix: u64,
    pub now: u64,
}

pub(super) fn reserve_in_transaction(
    transaction: &Transaction<'_>,
    directory: &std::fs::File,
    limits: StorageLimits,
    reservation: Reservation,
) -> Result<LeaseId, StorageError> {
    let Reservation {
        ciphertext_bytes,
        expected_sha256,
        expires_at_unix,
        now,
    } = reservation;
    valid_expiry(expires_at_unix, now)?;
    if ciphertext_bytes > MAX_ARCHIVE_BYTES {
        return Err(StorageError::InvalidInput);
    }
    let usage = usage(transaction, limits.capacity_bytes)?;
    let target_bytes = admission::target(transaction, limits.capacity_bytes)?;
    if usage.leases >= MAX_LEASES
        || target_bytes == 0
        || usage.reserved_bytes + usage.committed_bytes >= target_bytes
        || usage
            .reserved_bytes
            .checked_add(usage.committed_bytes)
            .and_then(|bytes| bytes.checked_add(ciphertext_bytes))
            .is_none_or(|bytes| bytes > target_bytes)
    {
        return Err(StorageError::Quota);
    }
    check_space(
        directory,
        usage
            .reserved_bytes
            .saturating_add(ciphertext_bytes)
            .saturating_add(64 * 1024),
        limits.min_free_bytes,
    )?;
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| StorageError::Entropy)?;
    transaction.execute(
        "INSERT INTO leases (lease_id, ciphertext_bytes, sha256, expires, committed) VALUES (?1, ?2, ?3, ?4, 0)",
        params![id.as_slice(), ciphertext_bytes, expected_sha256.as_slice(), expires_at_unix],
    )?;
    Ok(LeaseId(id))
}

pub(super) fn load(connection: &Connection, id: LeaseId) -> Result<StoredArchive, StorageError> {
    let record: Option<(u64, Vec<u8>, u64, i64)> = connection
        .query_row(
            "SELECT ciphertext_bytes, sha256, expires, committed FROM leases WHERE lease_id = ?1",
            [id.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (ciphertext_bytes, sha256, expires_at_unix, committed) =
        record.ok_or(StorageError::NotFound)?;
    if ciphertext_bytes > MAX_ARCHIVE_BYTES || expires_at_unix == 0 || !(0..=1).contains(&committed)
    {
        return Err(StorageError::InvalidStore);
    }
    Ok(StoredArchive {
        lease_id: id,
        ciphertext_bytes,
        sha256: sha256.try_into().map_err(|_| StorageError::InvalidStore)?,
        expires_at_unix,
        committed: committed == 1,
    })
}

pub(super) fn usage(connection: &Connection, capacity: u64) -> Result<StorageUsage, StorageError> {
    let usage = connection.query_row(
        "SELECT coalesce(sum(CASE WHEN committed = 0 THEN ciphertext_bytes ELSE 0 END), 0),
                coalesce(sum(CASE WHEN committed = 1 THEN ciphertext_bytes ELSE 0 END), 0),
                count(*) FROM leases",
        [],
        |row| {
            Ok(StorageUsage {
                reserved_bytes: row.get(0)?,
                committed_bytes: row.get(1)?,
                leases: row.get(2)?,
            })
        },
    )?;
    if usage.leases > MAX_LEASES
        || usage
            .reserved_bytes
            .checked_add(usage.committed_bytes)
            .is_none_or(|bytes| bytes > capacity)
    {
        return Err(StorageError::InvalidStore);
    }
    Ok(usage)
}
