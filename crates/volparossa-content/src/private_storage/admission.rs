//! A local admission target never revokes an existing ciphertext lease.

use rusqlite::{Connection, TransactionBehavior};

use super::{PrivateStorageStore, StorageError, VERSION, lease};

#[cfg(test)]
mod tests;

/// Local ciphertext obligations and the target for admitting additional reservations.
/// This is not measured free disk space or verified network-wide contribution. Database,
/// filesystem and temporary migration overhead are not included in these payload counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageAdmissionStatus {
    /// Original immutable payload capacity; existing usage remains checked against it.
    pub capacity_bytes: u64,
    /// Durable local target, which may be below retained obligations. Zero closes admission.
    pub target_bytes: u64,
    /// Complete expected lengths of incomplete uploads, including expired reservations.
    pub reserved_bytes: u64,
    /// Verified committed ciphertext lengths, including expired undeleted copies.
    pub committed_bytes: u64,
    /// All retained leases, whether pending, committed or expired.
    pub leases: u64,
    /// Reserved plus committed payload obligations, counting each copy separately.
    pub retained_payload_bytes: u64,
    /// Retained obligations above the target; no migration or deletion is implied.
    pub pending_drain_bytes: u64,
    /// Payload allowance only. Lease count and the real filesystem floor still apply.
    pub available_for_new_reservations_bytes: u64,
}

impl PrivateStorageStore {
    /// Read the durable admission target and actual retained payload obligations.
    ///
    /// # Errors
    /// Rejects invalid persisted limits/accounting or database errors.
    pub fn admission_status(&self) -> Result<StorageAdmissionStatus, StorageError> {
        status(&self.connection, self.limits.capacity_bytes)
    }

    /// Set the local owner's target without deleting, shortening or changing any lease.
    /// A lower target prevents new reservations while existing obligations drain through
    /// explicit authorized deletion. Raising the target cannot exceed original capacity.
    /// This neither migrates foreign archives nor verifies network contribution.
    ///
    /// # Errors
    /// Rejects targets above original capacity, invalid accounting or database errors.
    pub fn set_admission_target(
        &mut self,
        target_bytes: u64,
    ) -> Result<StorageAdmissionStatus, StorageError> {
        if target_bytes > self.limits.capacity_bytes {
            return Err(StorageError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Validate the previous target too: a mutation must not silently repair corruption.
        status(&transaction, self.limits.capacity_bytes)?;
        if transaction.execute(
            "UPDATE storage_meta SET admission_target_bytes = ?1 WHERE singleton = 1",
            [target_bytes],
        )? != 1
        {
            return Err(StorageError::InvalidStore);
        }
        let result = status(&transaction, self.limits.capacity_bytes)?;
        transaction.commit()?;
        Ok(result)
    }
}

pub(super) fn target(connection: &Connection, capacity: u64) -> Result<u64, StorageError> {
    let bytes: u64 = connection.query_row(
        "SELECT admission_target_bytes FROM storage_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if bytes > capacity {
        return Err(StorageError::InvalidStore);
    }
    Ok(bytes)
}

fn status(connection: &Connection, capacity: u64) -> Result<StorageAdmissionStatus, StorageError> {
    let usage = lease::usage(connection, capacity)?;
    let target_bytes = target(connection, capacity)?;
    // The checked usage validation above bounds this sum by the original hard capacity.
    let retained_payload_bytes = usage.reserved_bytes + usage.committed_bytes;
    Ok(StorageAdmissionStatus {
        capacity_bytes: capacity,
        target_bytes,
        reserved_bytes: usage.reserved_bytes,
        committed_bytes: usage.committed_bytes,
        leases: usage.leases,
        retained_payload_bytes,
        pending_drain_bytes: retained_payload_bytes.saturating_sub(target_bytes),
        available_for_new_reservations_bytes: target_bytes.saturating_sub(retained_payload_bytes),
    })
}

/// Upgrade only an authenticated, exclusively owned v1 store. The schema/version change is
/// atomic; an old executable will reject v2 instead of ignoring a later lowered target.
pub(super) fn upgrade(store: &mut PrivateStorageStore) -> Result<(), StorageError> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "ALTER TABLE storage_meta ADD COLUMN admission_target_bytes INTEGER NOT NULL
            DEFAULT 0 CHECK(admission_target_bytes >= 0 AND admission_target_bytes <= capacity_bytes);
         UPDATE storage_meta SET admission_target_bytes = capacity_bytes;",
    )?;
    transaction.execute("UPDATE storage_meta SET version = ?1", [VERSION])?;
    transaction.pragma_update(None, "user_version", VERSION)?;
    status(&transaction, store.limits.capacity_bytes)?;
    transaction.commit()?;
    Ok(())
}
