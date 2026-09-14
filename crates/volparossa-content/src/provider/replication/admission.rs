//! Bounded local public-content contribution, not a new network or consumer trust path.

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;

use super::{MAX_CHUNKS, MAX_WIRE_BYTES, Replica, ReplicationProgress, persistence};
use crate::{
    ChunkStore, Error, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE, provider::ProviderError,
};

/// Hard limits for one local non-evicting contribution batch, independent of network framing.
#[derive(Clone, Copy, Debug)]
pub struct LocalReplicaLimits {
    /// At most four distinct source chunks inspected for admission in this batch.
    pub max_chunks: usize,
    /// At most one MiB of inspected source payload, including already held duplicate payload.
    /// Returned progress counts only actual new destination bytes; no wire bytes are exchanged.
    pub max_bytes: u64,
}

impl Default for LocalReplicaLimits {
    fn default() -> Self {
        Self {
            max_chunks: MAX_CHUNKS,
            max_bytes: MAX_WIRE_BYTES,
        }
    }
}

impl LocalReplicaLimits {
    fn validate(self) -> Result<Self, ProviderError> {
        if !(1..=MAX_CHUNKS).contains(&self.max_chunks)
            || !(1..=MAX_WIRE_BYTES).contains(&self.max_bytes)
        {
            return Err(ProviderError::Limit);
        }
        Ok(self)
    }
}

/// Restore journaled public replicas for an explicitly enabled automatic contribution cache.
///
/// Keeps the existing signature, chunk-hash, hop and original-expiry checks. Private-message
/// entries are not returned or deleted; explicit replication retains its existing restore API.
/// This storage-only result confers no native-publisher or HTTPS-origin authority.
///
/// # Errors
/// Rejects mailbox-owned caches and every unsafe/corrupt journal, chunk or filesystem condition
/// rejected by [`super::restore_replicas`].
pub fn restore_public_replicas(
    store: &mut ChunkStore,
    now_unix: u64,
) -> Result<Vec<Replica>, Error> {
    if store.read_mailbox_metadata()?.is_some() {
        return Err(Error::InvalidStore);
    }
    let mut replicas = persistence::restore_replicas(store, now_unix)?;
    replicas.retain(|replica| replica.content_type() != PRIVATE_MESSAGE_CONTENT_TYPE);
    Ok(replicas)
}

/// Copy a few already received public chunks into an explicitly selected contribution cache.
///
/// `authorized` must be the caller's independently authorized exact native manifest. The original
/// envelope is verified again against that authority and its exact ID must match. HTTPS callers
/// must separately retain their live original origin authorization and explicit sharing intent;
/// this helper records no URL, origin proof, provider contact or trusted publisher database.
/// Private-message manifests and either a source or destination mailbox journal are refused.
///
/// Existing journal references are skipped so later bounded batches can admit remaining chunks.
/// Existing chunks may add new metadata but never count as new payload. Quota exhaustion returns
/// useful partial progress without eviction. A returned replica includes the complete merged
/// local chunk references, and is returned only when this batch added a journal reference.
/// New foreground admissions start a locally counted hop of one; an existing journal hop is
/// preserved, never decreased. The foreground v1 protocol carries no historical hop proof.
///
/// Original signed expiry is unchanged. The caller supplies the current library clock and must
/// recheck time/role/policy before advertising; this synchronous batch performs no network I/O.
/// Empty objects or a cache without admissible chunks produce no replica/serving claim.
///
/// # Errors
/// Rejects mismatched/private/expired manifests, mailbox ownership, invalid limits, corrupt
/// chunks or journals and bounded filesystem errors. Verified prefix ownership is journaled
/// even if a later source read fails. Filesystem failure may leave owned chunks; it never
/// authorizes adoption of arbitrary files or deletion/eviction to recover capacity.
pub fn admit_public_replica(
    signed: &SignedManifest,
    authorized: &VerifiedManifest,
    source: &mut ChunkStore,
    destination: &mut ChunkStore,
    limits: LocalReplicaLimits,
    now_unix: u64,
) -> Result<ReplicationProgress, ProviderError> {
    let limits = limits.validate()?;
    authorized.check_time(now_unix)?;
    let key = VerifyingKey::from_bytes(authorized.publisher())
        .map_err(|_| ProviderError::WrongProvider)?;
    let checked = signed.verify(&key, now_unix)?;
    if checked.manifest_id() != authorized.manifest_id()
        || checked.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        || source.read_mailbox_metadata()?.is_some()
        || destination.read_mailbox_metadata()?.is_some()
    {
        return Err(ProviderError::Registry);
    }
    if checked.chunks().is_empty() {
        return Ok(ReplicationProgress::default());
    }
    let mut replica = retained_replica(destination, signed, checked, now_unix)?;
    let prior_references = replica.chunk_ids.len();
    let mut progress = ReplicationProgress::default();
    let result = copy_batch(source, destination, &mut replica, limits, &mut progress);
    if replica.chunk_ids.len() > prior_references {
        persistence::persist_replicas(destination, std::slice::from_ref(&replica), now_unix)?;
        progress.replicas.push(replica);
    }
    result?;
    Ok(progress)
}

/// Admit a complete explicitly published public object into the configured owned cache.
///
/// Unlike an opportunistic batch, this foreground operation succeeds only after complete
/// source/destination hash verification and durable original-envelope ownership. It uses the
/// same non-evicting insertion and journal, so background limits and network framing do not
/// change. Empty public objects retain their original signed metadata without claiming bytes.
/// Existing matching references and their original hop count/expiry are preserved.
///
/// # Errors
/// Rejects private/mailbox content, wrong authority, incomplete/corrupt sources, expiry,
/// capacity exhaustion and the existing bounded storage errors. An interrupted or failed
/// admission may leave a verified journaled prefix, never a completed-publication receipt.
/// Callers must recheck current role/policy/time before registering or announcing the result.
pub fn admit_public_publication(
    signed: &SignedManifest,
    authorized: &VerifiedManifest,
    source: &mut ChunkStore,
    destination: &mut ChunkStore,
    now_unix: u64,
) -> Result<Replica, ProviderError> {
    authorized.check_time(now_unix)?;
    let key = VerifyingKey::from_bytes(authorized.publisher())
        .map_err(|_| ProviderError::WrongProvider)?;
    let checked = signed.verify(&key, now_unix)?;
    if checked.manifest_id() != authorized.manifest_id()
        || checked.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        || source.read_mailbox_metadata()?.is_some()
        || destination.read_mailbox_metadata()?.is_some()
    {
        return Err(ProviderError::Registry);
    }
    crate::reassemble(
        authorized,
        &mut [&mut *source],
        now_unix,
        &mut std::io::sink(),
    )?;
    let mut replica = retained_replica(destination, signed, checked, now_unix)?;
    let mut progress = ReplicationProgress::default();
    let copied = copy_batch(
        source,
        destination,
        &mut replica,
        LocalReplicaLimits {
            max_chunks: crate::MAX_CHUNKS,
            max_bytes: crate::MAX_OBJECT_BYTES,
        },
        &mut progress,
    );
    if !replica.chunk_ids.is_empty() || replica.is_empty_publication() {
        persistence::persist_replicas(destination, std::slice::from_ref(&replica), now_unix)?;
    }
    copied?;
    let expected: BTreeSet<_> = authorized
        .chunks()
        .iter()
        .map(|chunk| *chunk.id())
        .collect();
    if replica.chunk_ids.iter().copied().collect::<BTreeSet<_>>() != expected {
        return Err(Error::Quota.into());
    }
    crate::reassemble(
        authorized,
        &mut [destination],
        now_unix,
        &mut std::io::sink(),
    )?;
    Ok(replica)
}

fn retained_replica(
    destination: &mut ChunkStore,
    signed: &SignedManifest,
    checked: VerifiedManifest,
    now_unix: u64,
) -> Result<Replica, ProviderError> {
    let records = persistence::read_records(destination)?;
    let mut retained = None;
    for record in &records {
        if now_unix < record.validity().created {
            return Err(Error::Expired.into());
        }
        if now_unix < record.validity().expires {
            persistence::check_chunks(destination, record)?;
        }
        if record.manifest_id() == checked.manifest_id() {
            retained = Some(record.clone());
        }
    }
    if let Some(retained) = retained {
        return Ok(retained);
    }
    if records.len() >= persistence::MAX_RECORDS {
        return Err(ProviderError::Limit);
    }
    Ok(Replica {
        signed: signed.clone(),
        checked,
        hops: 1,
        chunk_ids: Vec::new(),
    })
}

fn copy_batch(
    source: &mut ChunkStore,
    destination: &mut ChunkStore,
    replica: &mut Replica,
    limits: LocalReplicaLimits,
    progress: &mut ReplicationProgress,
) -> Result<(), ProviderError> {
    let known: BTreeSet<_> = replica.chunk_ids.iter().copied().collect();
    let mut seen = BTreeSet::new();
    let mut inspected_chunks = 0;
    let mut inspected_bytes = 0_u64;
    for chunk in replica.checked.chunks() {
        if inspected_chunks == limits.max_chunks || inspected_bytes == limits.max_bytes {
            break;
        }
        if known.contains(chunk.id()) || !seen.insert(*chunk.id()) {
            continue;
        }
        let length = u64::from(chunk.length());
        if length > limits.max_bytes - inspected_bytes {
            continue;
        }
        let Some(bytes) = source.get(chunk.id())? else {
            continue;
        };
        if bytes.len() as u64 != length {
            return Err(Error::Integrity(*chunk.id()).into());
        }
        inspected_chunks += 1;
        inspected_bytes += length;
        let inserted = match destination.put_verified_if_space(*chunk.id(), &bytes) {
            Ok(inserted) => inserted,
            Err(Error::Quota) => break,
            Err(error) => return Err(error.into()),
        };
        if inserted {
            progress.chunks += 1;
            progress.bytes += length;
        }
        replica.chunk_ids.push(*chunk.id());
    }
    Ok(())
}
