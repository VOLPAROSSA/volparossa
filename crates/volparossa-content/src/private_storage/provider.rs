//! Durable authorization bindings around the real local ciphertext store.
//!
//! A provider key is pinned by the operator, not learned from a request. All operations
//! require a verified owner request; the service must additionally consume its challenge
//! once on the issuing connection before calling this synchronous backend. This module
//! neither issues grants nor implements global reciprocity, encryption or a network listener.
//! Execute it in a bounded blocking worker: `SQLite` fsync and full finalization are real work.

use ed25519_dalek::VerifyingKey;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{
    LeaseId, PrivateStorageStore, StorageError, StorageUsage, StoredArchive, UploadProgress,
    lease::{self, Reservation},
    protocol::{
        ProtocolError, ReceiptResult, ReceiptState, StorageOperation, StorageTarget,
        VerifiedStorageGrant, VerifiedStorageRequest,
    },
};
use crate::CHUNK_BYTES;

/// Metadata is retained rather than silently evicted and replayed as a new authorization.
pub const MAX_PROVIDER_GRANTS: u64 = 256;
/// Includes live bindings and deletion tombstones. Saturation fails closed; data is not
/// deleted to make room and an operator must provision a separate store for further history.
pub const MAX_PROVIDER_BINDINGS: u64 = 4096;

/// An executed, durable outcome, suitable for signing by the separately owned service key.
#[derive(Debug)]
pub struct ProviderResult {
    /// Exact observed lifecycle/prefix state, not a promise of future availability.
    pub receipt: ReceiptResult,
    /// Only `ReadRange` returns ciphertext; at most the protocol's 16 MiB range bound.
    pub payload: Vec<u8>,
}

/// Constant authorization errors contain no private archive bytes or identifying strings.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// Verified authorization expired or is otherwise invalid at execution start.
    #[error("storage authorization rejected")]
    Protocol(#[from] ProtocolError),
    /// Existing local store, payload verification or physical quota failure.
    #[error("storage operation failed")]
    Storage(#[from] StorageError),
    /// Persistent provider, capability, owner, archive or lease scope does not match.
    #[error("storage ownership rejected")]
    Unauthorized,
    /// The same owner/archive identifier was used with a different immutable identity.
    #[error("storage archive identity conflict")]
    Conflict,
    /// Explicit deletion is durable and must not be undone by a reserve/upload retry.
    #[error("storage archive was deleted")]
    Deleted,
    /// Metadata is bounded independently of charged payload capacity.
    #[error("storage authorization metadata capacity exhausted")]
    MetadataQuota,
}

impl From<rusqlite::Error> for ProviderError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(StorageError::Database(error))
    }
}

/// One exclusively locked local store with its permanently pinned provider public key.
/// Existing version-one local stores remain readable; authorization uses additive tables.
pub struct PrivateStorageProvider {
    store: PrivateStorageStore,
    provider: VerifyingKey,
}

impl PrivateStorageProvider {
    /// Add/open authorization metadata on an already owned local store, without storing a
    /// signing key. A store first pinned to one provider cannot be reopened as another.
    ///
    /// # Errors
    /// Rejects changed provider identity, invalid metadata, exceeded bounds or journal errors.
    pub fn new(
        mut store: PrivateStorageStore,
        provider: VerifyingKey,
    ) -> Result<Self, ProviderError> {
        if provider.is_weak() {
            return Err(ProviderError::Unauthorized);
        }
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT OR IGNORE INTO storage_provider (singleton, version, public_key) VALUES (1, 1, ?1)",
            [provider.as_bytes().as_slice()],
        )?;
        let pinned: (u64, Vec<u8>) = transaction.query_row(
            "SELECT version, public_key FROM storage_provider WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if pinned.0 != 1 || pinned.1.as_slice() != provider.as_bytes() {
            return Err(ProviderError::Unauthorized);
        }
        if count(&transaction, "SELECT count(*) FROM storage_grants")? > MAX_PROVIDER_GRANTS
            || count(&transaction, "SELECT count(*) FROM storage_bindings")? > MAX_PROVIDER_BINDINGS
        {
            return Err(StorageError::InvalidStore.into());
        }
        transaction.commit()?;
        Ok(Self { store, provider })
    }

    /// Provider identity is independent of incoming grant/request bytes.
    #[must_use]
    pub const fn provider_key(&self) -> &VerifyingKey {
        &self.provider
    }

    /// Local full-payload accounting, including expired and incomplete copies.
    ///
    /// # Errors
    /// Rejects invalid durable accounting or journal failures.
    pub fn usage(&self) -> Result<StorageUsage, StorageError> {
        self.store.usage()
    }

    /// Execute one verified exact operation. The transport must first consume its original
    /// connection's fresh challenge once. A retry requires a newly authorized request; it
    /// never changes owner, grant, immutable identity, lease or retention implicitly.
    ///
    /// Append ciphertext is supplied separately and bounded by the signed chunk length.
    /// Failed uploads retain full payload charge; reads are non-consuming. Only explicit
    /// Delete releases payload quota, while bounded deletion metadata remains durable.
    ///
    /// # Errors
    /// Rejects stale/wrong authorization, changed archive scope, deletion tombstones,
    /// exhausted grants/store/metadata, invalid ciphertext or durable storage errors.
    pub fn apply(
        &mut self,
        request: &VerifiedStorageRequest,
        append_payload: &[u8],
        now: u64,
    ) -> Result<ProviderResult, ProviderError> {
        request.current(now)?;
        if request.grant().provider_key() != &self.provider {
            return Err(ProviderError::Unauthorized);
        }
        match request.operation() {
            StorageOperation::Append { length, .. }
                if append_payload.len() as u64 == u64::from(length) => {}
            StorageOperation::Append { .. } => return Err(StorageError::InvalidInput.into()),
            _ if !append_payload.is_empty() => return Err(StorageError::InvalidInput.into()),
            _ => {}
        }
        if let StorageOperation::Reserve { expires_at } = request.operation() {
            return self.reserve(request, expires_at, now);
        }
        check_grant(&self.store.connection, request.grant())?;
        let binding = authorized_binding(&self.store.connection, request)?;
        if request.operation() == StorageOperation::Delete {
            return self.delete(&binding);
        }
        if binding.deleted {
            return Err(ProviderError::Deleted);
        }
        check_archive(&self.store.connection, &binding)?;
        let id = binding.lease_id;
        let receipt = match request.operation() {
            StorageOperation::Append { offset, sha256, .. } => {
                progress_receipt(self.store.append_chunk(
                    id,
                    offset / CHUNK_BYTES as u64,
                    sha256,
                    append_payload,
                    now,
                )?)
            }
            StorageOperation::Progress => progress_receipt(self.store.upload_progress(id, now)?),
            StorageOperation::Finalize => {
                let archive = self.store.finalize(id, now)?;
                archive_receipt(archive, ReceiptState::Committed, archive.ciphertext_bytes)
            }
            StorageOperation::ReadRange { offset, length } => {
                let chunks = u32::try_from(length.div_ceil(CHUNK_BYTES as u64))
                    .map_err(|_| StorageError::InvalidInput)?;
                let mut payload = Vec::with_capacity(
                    usize::try_from(length).map_err(|_| StorageError::InvalidInput)?,
                );
                let range = self.store.read_range(
                    id,
                    offset / CHUNK_BYTES as u64,
                    chunks,
                    &mut payload,
                    now,
                )?;
                if range.ciphertext_bytes != length || payload.len() as u64 != length {
                    return Err(StorageError::Integrity.into());
                }
                let mut receipt = archive_receipt(
                    range.archive,
                    ReceiptState::Committed,
                    range.archive.ciphertext_bytes,
                );
                receipt.range_sha256 = Some(Sha256::digest(&payload).into());
                return Ok(ProviderResult { receipt, payload });
            }
            StorageOperation::Renew { expires_at } => {
                self.store.renew(id, expires_at, now)?;
                let progress = self.store.upload_progress(id, now)?;
                archive_receipt(
                    progress.archive,
                    ReceiptState::Renewed,
                    progress.received_bytes,
                )
            }
            StorageOperation::Reserve { .. } | StorageOperation::Delete => {
                return Err(StorageError::InvalidInput.into());
            }
        };
        Ok(ProviderResult {
            receipt,
            payload: Vec::new(),
        })
    }

    fn reserve(
        &mut self,
        request: &VerifiedStorageRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<ProviderResult, ProviderError> {
        let transaction = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        register_grant(&transaction, request.grant())?;
        let target = request.target();
        let id = if let Some(binding) = find_binding(&transaction, request.grant(), target)? {
            check_binding(&binding, request)?;
            if binding.deleted {
                return Err(ProviderError::Deleted);
            }
            let archive = check_archive(&transaction, &binding)?;
            if archive.expires_at_unix <= now {
                return Err(StorageError::Expired.into());
            }
            binding.lease_id
        } else {
            if count(&transaction, "SELECT count(*) FROM storage_bindings")?
                >= MAX_PROVIDER_BINDINGS
            {
                return Err(ProviderError::MetadataQuota);
            }
            let (charged, leases): (u64, u64) = transaction.query_row(
                "SELECT coalesce(sum(ciphertext_bytes), 0), count(*) FROM storage_bindings WHERE grant_id = ?1 AND deleted = 0",
                [request.grant().id().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let limits = request.grant().limits();
            if leases >= u64::from(limits.max_leases)
                || charged
                    .checked_add(target.ciphertext_bytes)
                    .is_none_or(|bytes| bytes > limits.max_payload_bytes)
            {
                return Err(StorageError::Quota.into());
            }
            let id = lease::reserve_in_transaction(
                &transaction,
                &self.store.directory,
                self.store.limits,
                Reservation {
                    ciphertext_bytes: target.ciphertext_bytes,
                    expected_sha256: target.sha256,
                    expires_at_unix: expires_at,
                    now,
                },
            )?;
            transaction.execute(
                "INSERT INTO storage_bindings (owner, archive_id, grant_id, lease_id, ciphertext_bytes, sha256, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                params![request.grant().owner_key().as_bytes().as_slice(), target.archive_id.as_slice(), request.grant().id().as_slice(),
                    id.as_bytes().as_slice(), target.ciphertext_bytes, target.sha256.as_slice()],
            )?;
            id
        };
        transaction.commit()?;
        // Reuse the real contiguous-prefix inspection, including on an idempotent Reserve.
        Ok(ProviderResult {
            receipt: progress_receipt(self.store.upload_progress(id, now)?),
            payload: Vec::new(),
        })
    }

    fn delete(&mut self, binding: &Binding) -> Result<ProviderResult, ProviderError> {
        let transaction = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !binding.deleted {
            check_archive(&transaction, binding)?;
            // The trigger changes the exact binding into a tombstone in this transaction.
            // A failed tombstone update rolls the payload/chunk deletion back as well.
            if transaction.execute(
                "DELETE FROM leases WHERE lease_id = ?1",
                [binding.lease_id.as_bytes().as_slice()],
            )? != 1
            {
                return Err(StorageError::InvalidStore.into());
            }
        }
        transaction.commit()?;
        Ok(ProviderResult {
            receipt: ReceiptResult {
                state: ReceiptState::Deleted,
                lease_id: binding.lease_id,
                stored_bytes: 0,
                expires_at: 0,
                range_sha256: None,
            },
            payload: Vec::new(),
        })
    }
}

struct Binding {
    grant_id: [u8; 32],
    lease_id: LeaseId,
    ciphertext_bytes: u64,
    sha256: [u8; 32],
    deleted: bool,
}

fn find_binding(
    connection: &Connection,
    grant: &VerifiedStorageGrant,
    target: StorageTarget,
) -> Result<Option<Binding>, ProviderError> {
    type Record = (Vec<u8>, Vec<u8>, u64, Vec<u8>, u8);
    let record: Option<Record> = connection.query_row(
        "SELECT grant_id, lease_id, ciphertext_bytes, sha256, deleted FROM storage_bindings WHERE owner = ?1 AND archive_id = ?2",
        params![grant.owner_key().as_bytes().as_slice(), target.archive_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    record
        .map(|(grant_id, lease_id, ciphertext_bytes, sha256, deleted)| {
            if deleted > 1 {
                return Err(StorageError::InvalidStore.into());
            }
            Ok(Binding {
                grant_id: grant_id
                    .try_into()
                    .map_err(|_| StorageError::InvalidStore)?,
                lease_id: LeaseId::from_bytes(
                    lease_id
                        .try_into()
                        .map_err(|_| StorageError::InvalidStore)?,
                ),
                ciphertext_bytes,
                sha256: sha256.try_into().map_err(|_| StorageError::InvalidStore)?,
                deleted: deleted != 0,
            })
        })
        .transpose()
}

fn check_binding(binding: &Binding, request: &VerifiedStorageRequest) -> Result<(), ProviderError> {
    if binding.grant_id != request.grant().id()
        || request
            .target()
            .lease_id
            .is_some_and(|id| id != binding.lease_id)
    {
        return Err(ProviderError::Unauthorized);
    }
    if binding.ciphertext_bytes != request.target().ciphertext_bytes
        || binding.sha256 != request.target().sha256
    {
        return Err(ProviderError::Conflict);
    }
    Ok(())
}

fn authorized_binding(
    connection: &Connection,
    request: &VerifiedStorageRequest,
) -> Result<Binding, ProviderError> {
    let binding = find_binding(connection, request.grant(), request.target())?
        .ok_or(ProviderError::Unauthorized)?;
    check_binding(&binding, request)?;
    Ok(binding)
}

fn check_archive(
    connection: &Connection,
    binding: &Binding,
) -> Result<StoredArchive, ProviderError> {
    let archive = lease::load(connection, binding.lease_id)?;
    if archive.ciphertext_bytes != binding.ciphertext_bytes || archive.sha256 != binding.sha256 {
        return Err(StorageError::InvalidStore.into());
    }
    Ok(archive)
}

fn check_grant(connection: &Connection, grant: &VerifiedStorageGrant) -> Result<(), ProviderError> {
    let encoded: Option<Vec<u8>> = connection.query_row(
        "SELECT signed_grant FROM storage_grants WHERE grant_id = ?1 AND capability_id = ?2 AND owner = ?3",
        params![grant.id().as_slice(), grant.capability_id().as_slice(), grant.owner_key().as_bytes().as_slice()],
        |row| row.get(0),
    ).optional()?;
    if encoded.as_deref() != Some(grant.signed().encode().as_slice()) {
        return Err(ProviderError::Unauthorized);
    }
    Ok(())
}

fn register_grant(
    connection: &Connection,
    grant: &VerifiedStorageGrant,
) -> Result<(), ProviderError> {
    let existing: Option<Vec<u8>> = connection
        .query_row(
            "SELECT grant_id FROM storage_grants WHERE capability_id = ?1",
            [grant.capability_id().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        if id.as_slice() != grant.id() {
            return Err(ProviderError::Unauthorized);
        }
        return check_grant(connection, grant);
    }
    if count(connection, "SELECT count(*) FROM storage_grants")? >= MAX_PROVIDER_GRANTS {
        return Err(ProviderError::MetadataQuota);
    }
    connection.execute(
        "INSERT INTO storage_grants (grant_id, capability_id, owner, signed_grant) VALUES (?1, ?2, ?3, ?4)",
        params![grant.id().as_slice(), grant.capability_id().as_slice(), grant.owner_key().as_bytes().as_slice(), grant.signed().encode()],
    )?;
    Ok(())
}

fn count(connection: &Connection, sql: &str) -> Result<u64, ProviderError> {
    Ok(connection.query_row(sql, [], |row| row.get(0))?)
}

fn progress_receipt(progress: UploadProgress) -> ReceiptResult {
    let state = if progress.archive.committed {
        ReceiptState::Committed
    } else if progress.received_bytes == 0 {
        ReceiptState::Reserved
    } else {
        ReceiptState::Partial
    };
    archive_receipt(progress.archive, state, progress.received_bytes)
}

fn archive_receipt(
    archive: StoredArchive,
    state: ReceiptState,
    stored_bytes: u64,
) -> ReceiptResult {
    ReceiptResult {
        state,
        lease_id: archive.lease_id,
        stored_bytes,
        expires_at: archive.expires_at_unix,
        range_sha256: None,
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS storage_provider (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = 1),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32)
) STRICT;
CREATE TABLE IF NOT EXISTS storage_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 32),
    capability_id BLOB UNIQUE NOT NULL CHECK (length(capability_id) = 32),
    owner BLOB NOT NULL CHECK (length(owner) = 32),
    signed_grant BLOB NOT NULL CHECK (length(signed_grant) BETWEEN 1 AND 2048)
) STRICT;
CREATE TABLE IF NOT EXISTS storage_bindings (
    owner BLOB NOT NULL CHECK (length(owner) = 32),
    archive_id BLOB NOT NULL CHECK (length(archive_id) = 32),
    grant_id BLOB NOT NULL REFERENCES storage_grants(grant_id),
    lease_id BLOB UNIQUE NOT NULL CHECK (length(lease_id) = 16),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 68719476736),
    sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    PRIMARY KEY (owner, archive_id)
) STRICT;
CREATE TRIGGER IF NOT EXISTS storage_binding_delete AFTER DELETE ON leases BEGIN
    UPDATE storage_bindings SET deleted = 1 WHERE lease_id = OLD.lease_id;
END;
";

#[cfg(test)]
mod tests;
