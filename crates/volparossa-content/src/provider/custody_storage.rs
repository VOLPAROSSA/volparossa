//! Complete public custody in the existing non-evicting replica journal.
//!
//! This owner retains configuration, not an exclusive cache handle. Admission, restart checks
//! and registry registration release their handles before returning so ordinary serving can
//! reopen the same cache. Network authentication, spare-capacity admission and service lifetime
//! remain the caller's responsibility; this module never creates a peer-selected directory.

use std::{collections::BTreeSet, path::PathBuf};

use ed25519_dalek::VerifyingKey;

use super::{
    ProviderError, PublicationRegistry,
    replication::{Replica, admit_public_publication, restore_replicas},
};
use crate::{
    CacheLimits, ChunkStore, Error, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
};

#[cfg(test)]
mod tests;

/// An explicitly configured public contribution cache, not a publisher trust database.
///
/// All admissions are non-evicting and use the existing sixty-four-record replica quota plus
/// the configured chunk-count, byte and free-space quotas. Callers must not reuse this cache
/// for unrelated LRU admissions that could discard a promised copy. Expired references can
/// be reclaimed by the existing [`PublicationRegistry::reclaim_replica_cache`] operation.
#[derive(Clone, Debug)]
pub struct PublicCustodyStore {
    root: PathBuf,
    limits: CacheLimits,
}

impl PublicCustodyStore {
    /// Bind to an existing, explicitly owned public cache without retaining its lock.
    ///
    /// This validates ownership and index structure, not a complete-custody claim. Use
    /// [`Self::restore_complete`] or [`Self::inspect_complete`] to revalidate original manifests
    /// and actual bytes before exposing a live copy after restart.
    ///
    /// # Errors
    /// Rejects relative/overlong paths, mailbox caches, busy/foreign stores and invalid quotas.
    pub fn open(root: PathBuf, limits: CacheLimits) -> Result<Self, ProviderError> {
        if !root.is_absolute() || root.as_os_str().len() > 4096 {
            return Err(ProviderError::Registry);
        }
        let custody = Self { root, limits };
        drop(custody.owned_cache()?);
        Ok(custody)
    }

    /// Durably admit one complete original public object from a caller-owned staging cache.
    ///
    /// The original signature, exact manifest identity, every chunk and whole-object hash are
    /// verified before success. Identical retries add no payload or renewed lifetime. A quota
    /// or I/O failure may retain a verified journaled prefix, never a completed receipt; no
    /// live previous copy is evicted. The returned replica does not authorize its publisher
    /// for consumers and must still be registered in the caller's active service before ACK.
    ///
    /// # Errors
    /// Rejects private/mailbox content, wrong authority, incomplete/corrupt/expired objects,
    /// exhausted quotas and the existing owned-cache/journal errors.
    pub fn admit(
        &self,
        signed: &SignedManifest,
        authorized: &VerifiedManifest,
        source: &mut ChunkStore,
        now_unix: u64,
    ) -> Result<Replica, ProviderError> {
        let mut destination = self.owned_cache()?;
        public_records(&mut destination, now_unix)?;
        admit_public_publication(signed, authorized, source, &mut destination, now_unix)
    }

    /// Restore only complete, still-valid journaled public copies from actual owned bytes.
    ///
    /// Partial records remain owned but are not promoted to complete custody, even if unrelated
    /// objects happen to supply their missing chunks. Exact original chunk references, chunk
    /// hashes and the whole-object hash must all agree. Copying/restart never extends expiry.
    /// Expired records are omitted, not deleted; no directory catalogue or trust is inferred.
    ///
    /// # Errors
    /// Rejects corrupt/missing journaled bytes, signatures, future metadata, private/mailbox
    /// storage, unsafe/busy roots and the existing bounded persistence errors.
    pub fn restore_complete(&self, now_unix: u64) -> Result<Vec<Replica>, ProviderError> {
        let mut store = self.owned_cache()?;
        let mut complete = Vec::new();
        for replica in public_records(&mut store, now_unix)? {
            let publisher = VerifyingKey::from_bytes(&replica.publisher_key_hint())
                .map_err(|_| ProviderError::Registry)?;
            // Self-consistent storage authority only. Consumers independently select their key.
            let manifest = replica.signed_manifest().verify(&publisher, now_unix)?;
            let expected: BTreeSet<_> = manifest.chunks().iter().map(|chunk| *chunk.id()).collect();
            if replica.chunk_ids().iter().copied().collect::<BTreeSet<_>>() != expected {
                continue;
            }
            crate::reassemble(&manifest, &mut [&mut store], now_unix, &mut std::io::sink())?;
            complete.push(replica);
        }
        Ok(complete)
    }

    /// Inspect one exact original manifest after revalidating durable metadata and actual bytes.
    ///
    /// `None` means absent, expired or incomplete; storage failure never means complete.
    /// This does not itself prove that a protected provider service is currently reachable.
    ///
    /// # Errors
    /// Returns the same explicit storage failures as [`Self::restore_complete`].
    pub fn inspect_complete(
        &self,
        manifest_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<Option<Replica>, ProviderError> {
        Ok(self
            .restore_complete(now_unix)?
            .into_iter()
            .find(|replica| replica.manifest_id() == manifest_id))
    }

    /// Register newly verified complete copies without retaining an exclusive store handle.
    ///
    /// Existing exact-root registrations remain unchanged. An ID registered at a different
    /// root is a conflict, not implicit permission to replace it. The caller's registry changes
    /// only after every new registration succeeds. Name lookup is neither enabled nor disabled
    /// here; the active service explicitly controls that existing setting.
    ///
    /// # Errors
    /// Rejects restore/registration failures, conflicting roots and the registry's count quota.
    pub fn register_complete(
        &self,
        registry: &mut PublicationRegistry,
        now_unix: u64,
    ) -> Result<usize, ProviderError> {
        let replicas = self.restore_complete(now_unix)?;
        let mut updated = registry.clone();
        let mut registered = 0;
        for replica in replicas {
            if updated.contains(replica.manifest_id()) {
                if !updated.contains_at(replica.manifest_id(), &self.root) {
                    return Err(ProviderError::Registry);
                }
                continue;
            }
            updated.register_replica(replica, self.root.clone(), self.limits, now_unix)?;
            registered += 1;
        }
        *registry = updated;
        Ok(registered)
    }

    fn owned_cache(&self) -> Result<ChunkStore, ProviderError> {
        let store = ChunkStore::open(&self.root, self.limits)?;
        if store.read_mailbox_metadata()?.is_some() {
            return Err(Error::InvalidStore.into());
        }
        Ok(store)
    }
}

fn public_records(store: &mut ChunkStore, now_unix: u64) -> Result<Vec<Replica>, ProviderError> {
    let records = restore_replicas(store, now_unix)?;
    if records
        .iter()
        .any(|replica| replica.content_type() == PRIVATE_MESSAGE_CONTENT_TYPE)
    {
        return Err(ProviderError::Registry);
    }
    Ok(records)
}
