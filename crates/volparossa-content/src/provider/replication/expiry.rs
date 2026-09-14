//! Reuse bounded replica capacity after original expiry, never evicting live or mailbox data.

use std::{collections::BTreeSet, path::Path};

use super::{Replica, persistence};
use crate::provider::{ProviderError, PublicationRegistry};
use crate::{CacheLimits, CacheUsage, ChunkId, ChunkStore, Error};

/// Actual result from one exclusive owned-store maintenance operation.
#[derive(Debug)]
pub struct ReplicaReclamation {
    /// Still-valid original storage records, including ones not currently registered for serving.
    pub live: Vec<Replica>,
    /// Original expired replica registrations, not explicit foreground publications.
    pub expired_manifest_ids: Vec<[u8; 32]>,
    /// Exact owned indexed chunks removed; unknown/orphan files are never scanned or adopted.
    pub removed_chunks: Vec<ChunkId>,
    /// Measured payload/entry usage after maintenance, not an estimated quota credit.
    pub usage: CacheUsage,
}

impl PublicationRegistry {
    /// Reclaim only expired journaled replicas in this exact caller-selected owned cache.
    ///
    /// Live journal references and every explicit foreground registration retain their chunks.
    /// Expired storage-only registry entries are removed without changing original lifetimes.
    /// A cache containing a mailbox journal is refused, including while its service is stopped.
    /// No provider connection, new directory, arbitrary file removal or LRU eviction is performed.
    ///
    /// # Errors
    /// Rejects an unsafe/busy/foreign cache, corrupt journal or candidate chunk, future metadata,
    /// mailbox ownership, and bounded filesystem failure. Earlier completed removals can persist.
    pub fn reclaim_replica_cache(
        &mut self,
        root: &Path,
        limits: CacheLimits,
        now_unix: u64,
    ) -> Result<ReplicaReclamation, ProviderError> {
        if !root.is_absolute() || root.as_os_str().len() > 4096 {
            return Err(ProviderError::Registry);
        }
        // This private handle admits no payload: reclamation must also work when the filesystem
        // has reached its admission reserve. Subsequent normal opens/inserts retain that reserve.
        let mut store = ChunkStore::open(
            root,
            CacheLimits {
                min_free_bytes: 0,
                ..limits
            },
        )?;
        if store.read_mailbox_metadata()?.is_some() {
            return Err(Error::Limit("mailbox cache is not opportunistic replica storage").into());
        }
        let records = persistence::read_records(&store)?;
        let mut retained = BTreeSet::new();
        for entry in self.entries.values().filter(|entry| entry.root == root) {
            let expired_replica = entry
                .replication
                .as_ref()
                .is_some_and(|replica| replica.hops > 0)
                && entry.manifest.validity().expires <= now_unix;
            if !expired_replica {
                retained.extend(entry.manifest.chunks().iter().map(|chunk| *chunk.id()));
            }
        }
        let mut live = Vec::new();
        let mut expired = Vec::new();
        for replica in records {
            if now_unix < replica.validity().created {
                return Err(Error::Expired.into());
            }
            if now_unix < replica.validity().expires {
                persistence::check_chunks(&mut store, &replica)?;
                retained.extend(replica.chunk_ids().iter().copied());
                live.push(replica);
            } else {
                expired.push(replica);
            }
        }
        let candidates: BTreeSet<_> = expired
            .iter()
            .flat_map(|replica| replica.chunk_ids().iter().copied())
            .filter(|id| !retained.contains(id))
            .collect();
        // Verify the entire bounded plan before deleting anything. Already absent indexed
        // chunks are not invented as reclaimed bytes; unknown directory entries remain untouched.
        let mut removed_chunks = Vec::new();
        for id in candidates {
            if store.get(&id)?.is_some() {
                removed_chunks.push(id);
            }
        }
        for id in &removed_chunks {
            store.remove_owned_chunk(*id)?;
        }
        if !expired.is_empty() {
            persistence::replace_records(&mut store, live.iter())?;
        }
        let expired_manifest_ids: Vec<_> = expired.iter().map(|r| *r.manifest_id()).collect();
        self.entries.retain(|id, entry| {
            !(entry.root == root
                && expired_manifest_ids.contains(id)
                && entry
                    .replication
                    .as_ref()
                    .is_some_and(|replica| replica.hops > 0))
        });
        Ok(ReplicaReclamation {
            live,
            expired_manifest_ids,
            removed_chunks,
            usage: store.usage(),
        })
    }
}
