//! Explicit owned-cache storage metadata, not a publisher/origin trust database.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use prost::Message;

use super::{MAX_HOPS, Replica};
use crate::store::MAX_REPLICA_METADATA_BYTES;
use crate::{ChunkId, ChunkStore, Error, MAX_CHUNKS, MAX_MANIFEST_BYTES, SignedManifest};

const MAX_RECORDS: usize = 64;
const MAX_RECORD_BYTES: usize = MAX_MANIFEST_BYTES + MAX_CHUNKS * 32 + 128;

// Count and length framing bound allocation before decoding each canonical protobuf record.
// Repeated chunk hashes are one fixed-width blob, not arbitrarily many protobuf allocations.
#[derive(Clone, PartialEq, Message)]
struct Record {
    #[prost(bytes = "vec", tag = "1")]
    signed: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    publisher_hint: Vec<u8>,
    #[prost(uint64, tag = "3")]
    created: u64,
    #[prost(uint32, tag = "4")]
    hops: u32,
    #[prost(bytes = "vec", tag = "5")]
    chunk_ids: Vec<u8>,
}

/// Merge explicitly received replicas into the owned cache's bounded durable journal.
///
/// Preserves earlier valid publications and unions additional chunks of the exact same
/// signed manifest. Original signed expiry is never renewed; local hops never decrease.
/// Contains no provider contacts, browsing URLs, private keys or independent trust anchors.
/// The journal is private, cache-ID-bound and atomically replaced under the cache lock.
///
/// # Errors
/// Rejects invalid/expired new replicas, absent/corrupt chunks, unsafe or corrupt old metadata,
/// more than sixty-four live publications, metadata above eight MiB, and filesystem failures.
/// No chunk is evicted or deleted to admit metadata.
pub fn persist_replicas(
    store: &mut ChunkStore,
    replicas: &[Replica],
    now_unix: u64,
) -> Result<(), Error> {
    if replicas.len() > MAX_RECORDS {
        return Err(Error::Limit("replica metadata count"));
    }
    let mut combined: BTreeMap<_, _> = restore_replicas(store, now_unix)?
        .into_iter()
        .map(|replica| (*replica.manifest_id(), replica))
        .collect();
    for replica in replicas {
        replica.checked.check_time(now_unix)?;
        check_chunks(store, replica)?;
        let id = *replica.manifest_id();
        if let Some(previous) = combined.get_mut(&id) {
            let chunks: BTreeSet<_> = previous
                .chunk_ids
                .iter()
                .chain(&replica.chunk_ids)
                .copied()
                .collect();
            if chunks.len() > MAX_CHUNKS {
                return Err(Error::Limit("replica chunk count"));
            }
            previous.chunk_ids = chunks.into_iter().collect();
            previous.hops = previous.hops.max(replica.hops);
        } else {
            if combined.len() >= MAX_RECORDS {
                return Err(Error::Limit("replica metadata count"));
            }
            combined.insert(id, replica.clone());
        }
    }
    let count = u32::try_from(combined.len()).map_err(|_| Error::InvalidStore)?;
    let mut bytes = count.to_le_bytes().to_vec();
    for replica in combined.values() {
        let record = encode_record(replica);
        if record.len() > MAX_RECORD_BYTES
            || bytes.len() + 4 + record.len() > MAX_REPLICA_METADATA_BYTES
        {
            return Err(Error::Limit("replica metadata"));
        }
        let length = u32::try_from(record.len()).map_err(|_| Error::InvalidStore)?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&record);
    }
    store.replace_replica_metadata(&bytes)
}

/// Restore only storage-only registrations explicitly journaled in this exact owned cache.
///
/// Rechecks original signatures, validity, bounded hops and every referenced chunk's hash.
/// A missing journal returns an empty set, never an inferred directory catalogue. Correctly
/// signed expired records are skipped without deleting chunks. The result does not establish
/// publisher/HTTPS trust: foreground consumers must still independently authorize a manifest.
///
/// # Errors
/// Rejects foreign, corrupt or unfinished metadata, future validity, missing/corrupt live
/// chunks, duplicate records, excessive resources, and filesystem failures.
pub fn restore_replicas(store: &mut ChunkStore, now_unix: u64) -> Result<Vec<Replica>, Error> {
    let Some(bytes) = store.read_replica_metadata()? else {
        return Ok(Vec::new());
    };
    let mut remaining = bytes.as_slice();
    let count = read_length(&mut remaining)?;
    if count > MAX_RECORDS {
        return Err(Error::Limit("replica metadata count"));
    }
    let mut restored = Vec::with_capacity(count);
    let mut ids = BTreeSet::new();
    for _ in 0..count {
        let length = read_length(&mut remaining)?;
        if length > MAX_RECORD_BYTES || length > remaining.len() {
            return Err(Error::InvalidStore);
        }
        let (record, rest) = remaining.split_at(length);
        remaining = rest;
        let replica = decode_record(record)?;
        if !ids.insert(*replica.manifest_id()) {
            return Err(Error::InvalidStore);
        }
        if now_unix < replica.validity().created {
            return Err(Error::Expired);
        }
        if now_unix < replica.validity().expires {
            check_chunks(store, &replica)?;
            restored.push(replica);
        }
    }
    if !remaining.is_empty() {
        return Err(Error::InvalidStore);
    }
    Ok(restored)
}

fn encode_record(replica: &Replica) -> Vec<u8> {
    let chunks: BTreeSet<_> = replica.chunk_ids.iter().copied().collect();
    Record {
        signed: replica.signed.encode(),
        publisher_hint: replica.publisher_key_hint().to_vec(),
        created: replica.validity().created,
        hops: u32::from(replica.hops),
        chunk_ids: chunks.iter().flat_map(|id| *id.as_bytes()).collect(),
    }
    .encode_to_vec()
}

fn decode_record(bytes: &[u8]) -> Result<Replica, Error> {
    let record = Record::decode(bytes).map_err(|_| Error::InvalidStore)?;
    if record.encode_to_vec() != bytes
        || record.chunk_ids.is_empty()
        || record.chunk_ids.len() > MAX_CHUNKS * 32
        || record.chunk_ids.len() % 32 != 0
        || !(1..=u32::from(MAX_HOPS)).contains(&record.hops)
    {
        return Err(Error::InvalidStore);
    }
    let key = VerifyingKey::from_bytes(
        &record
            .publisher_hint
            .try_into()
            .map_err(|_| Error::InvalidStore)?,
    )
    .map_err(|_| Error::InvalidStore)?;
    let signed = SignedManifest::decode(&record.signed)?;
    // The hint is deliberately not independently trusted. Verify at the persisted original
    // creation time first so even expired records must carry a valid original signature.
    let checked = signed.verify(&key, record.created)?;
    if checked.validity().created != record.created {
        return Err(Error::InvalidStore);
    }
    let chunk_ids = record
        .chunk_ids
        .chunks_exact(32)
        .map(|bytes| {
            bytes
                .try_into()
                .map(ChunkId)
                .map_err(|_| Error::InvalidStore)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let replica = Replica {
        signed,
        checked,
        hops: u8::try_from(record.hops).map_err(|_| Error::InvalidStore)?,
        chunk_ids,
    };
    check_shape(&replica)?;
    Ok(replica)
}

fn check_shape(replica: &Replica) -> Result<(), Error> {
    if replica.chunk_ids.is_empty()
        || replica.chunk_ids.len() > MAX_CHUNKS
        || !(1..=MAX_HOPS).contains(&replica.hops)
    {
        return Err(Error::InvalidStore);
    }
    let mut seen = BTreeSet::new();
    for id in &replica.chunk_ids {
        if !seen.insert(*id) || !replica.checked.chunks().iter().any(|chunk| chunk.id == *id) {
            return Err(Error::InvalidStore);
        }
    }
    Ok(())
}

fn check_chunks(store: &mut ChunkStore, replica: &Replica) -> Result<(), Error> {
    check_shape(replica)?;
    for id in &replica.chunk_ids {
        store.get(id)?.ok_or(Error::MissingChunk(*id))?;
    }
    Ok(())
}

fn read_length(bytes: &mut &[u8]) -> Result<usize, Error> {
    let Some(length) = bytes.get(..4) else {
        return Err(Error::InvalidStore);
    };
    let value = u32::from_le_bytes(length.try_into().map_err(|_| Error::InvalidStore)?);
    *bytes = &bytes[4..];
    usize::try_from(value).map_err(|_| Error::InvalidStore)
}
