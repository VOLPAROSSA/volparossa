//! Durable revision observations scoped only to an explicitly selected owned consumer cache.
//! These are independent of chunk LRU and expiring storage-only replica registrations.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};

use prost::Message;
use sha2::{Digest as _, Sha256};

use super::{ChunkStore, create_file, ensure_absent, io_error, open_private_file};
use crate::{Error, VerifiedManifest};

const PIN_FILE: &str = ".volparossa-name-revisions-v1";
const PIN_STAGE: &str = ".volparossa-name-revisions-next-v1";
const MAGIC: &[u8; 8] = b"VPNR0001";
const MAX_PINS: usize = 64;
const MAX_RECORD_BYTES: usize = 256;
const HEADER_BYTES: usize = 44;
const CHECKSUM_BYTES: usize = 32;
const MAX_BYTES: usize = HEADER_BYTES + MAX_PINS * (4 + MAX_RECORD_BYTES) + CHECKSUM_BYTES;
type PinMap = BTreeMap<([u8; 32], String), RevisionPin>;

/// A local high-water observation, never proof of global freshness or a live manifest.
/// Remains after manifest expiry, chunk eviction and restart; a newer revision may supersede it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionPin {
    revision: u64,
    manifest_id: [u8; 32],
    conflicted: bool,
}

impl RevisionPin {
    /// Largest independently verified revision observed in this cache for the exact key/name.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Original envelope identity first observed at this revision.
    pub const fn manifest_id(&self) -> &[u8; 32] {
        &self.manifest_id
    }
    /// Another valid envelope with a different identity was observed at this same revision.
    pub const fn conflicted(&self) -> bool {
        self.conflicted
    }
}

impl ChunkStore {
    /// Read the retained floor for one explicitly trusted publisher and exact native name.
    /// No expiration, LRU operation or missing chunk can remove or lower a retained floor.
    /// A new/deliberately deleted cache starts a new observation scope, not global freshness.
    ///
    /// # Errors
    /// Rejects invalid names, foreign/corrupt metadata and interrupted writes; never repairs it.
    pub fn name_revision_floor(
        &self,
        publisher: &[u8; 32],
        name: &str,
    ) -> Result<Option<RevisionPin>, Error> {
        crate::manifest::validate_name(name)?;
        Ok(self
            .read_name_pins()?
            .get(&(*publisher, name.into()))
            .copied())
    }

    /// Durably observe an independently publisher-authorized, current native manifest.
    ///
    /// The caller must verify against its pre-established key, not a peer-supplied key hint.
    /// Call before requesting chunks: a missing newer object must not cause an older fallback.
    /// Same-revision conflicts are persisted before returning `NameConflict`; lower revisions
    /// cannot change this floor. A higher verified revision supersedes an earlier conflict.
    /// At most 64 key/name pins are retained, with no automatic eviction to make another fit.
    /// No provider contacts, URLs, private keys or transferable publisher authority are stored.
    ///
    /// # Errors
    /// Rejects expiry, rollback, same-revision conflicts, full pin capacity and unsafe I/O.
    pub fn observe_name_revision(
        &mut self,
        manifest: &VerifiedManifest,
        now_unix: u64,
    ) -> Result<RevisionPin, Error> {
        manifest.check_time(now_unix)?;
        let mut pins = self.read_name_pins()?;
        let key = (*manifest.publisher(), manifest.metadata().name.clone());
        let candidate = RevisionPin {
            revision: manifest.metadata().revision,
            manifest_id: *manifest.manifest_id(),
            conflicted: false,
        };
        if let Some(previous) = pins.get_mut(&key) {
            if candidate.revision < previous.revision {
                return Err(Error::NameRollback);
            }
            if candidate.revision == previous.revision {
                if previous.conflicted {
                    return Err(Error::NameConflict);
                }
                if candidate.manifest_id == previous.manifest_id {
                    return Ok(*previous);
                }
                previous.conflicted = true;
                self.persist_name_pins(&pins)?;
                return Err(Error::NameConflict);
            }
        } else if pins.len() >= MAX_PINS {
            return Err(Error::Limit("named publication revision pins"));
        }
        pins.insert(key, candidate);
        self.persist_name_pins(&pins)?;
        Ok(candidate)
    }

    pub(super) fn check_name_metadata(&self) -> Result<(), Error> {
        self.read_name_pins().map(|_| ())
    }

    fn read_name_pins(&self) -> Result<PinMap, Error> {
        self.ensure_healthy()?;
        ensure_absent(&self.directory, PIN_STAGE)?;
        let file = match open_private_file(&self.directory, PIN_FILE, MAX_BYTES as u64) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PinMap::new());
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        decode_pins(&bytes, &self.cache_id)
    }

    fn persist_name_pins(&mut self, pins: &PinMap) -> Result<(), Error> {
        self.ensure_healthy()?;
        ensure_absent(&self.directory, PIN_STAGE)?;
        let bytes = encode_pins(pins, &self.cache_id)?;
        self.check_free_space(bytes.len() as u64)?;
        self.healthy = false;
        let mut output = create_file(&self.directory, PIN_STAGE)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        rustix::fs::renameat(&self.directory, PIN_STAGE, &self.directory, PIN_FILE)
            .map_err(io_error)?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
struct PinRecord {
    #[prost(bytes = "vec", tag = "1")]
    publisher: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(uint64, tag = "3")]
    revision: u64,
    #[prost(bytes = "vec", tag = "4")]
    manifest_id: Vec<u8>,
    #[prost(bool, tag = "5")]
    conflicted: bool,
}

fn encode_pins(pins: &PinMap, cache_id: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if pins.len() > MAX_PINS {
        return Err(Error::InvalidStore);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(cache_id);
    bytes.extend_from_slice(
        &u32::try_from(pins.len())
            .map_err(|_| Error::InvalidStore)?
            .to_le_bytes(),
    );
    for ((publisher, name), pin) in pins {
        let record = PinRecord {
            publisher: publisher.to_vec(),
            name: name.clone(),
            revision: pin.revision,
            manifest_id: pin.manifest_id.to_vec(),
            conflicted: pin.conflicted,
        }
        .encode_to_vec();
        if record.len() > MAX_RECORD_BYTES {
            return Err(Error::InvalidStore);
        }
        bytes.extend_from_slice(
            &u32::try_from(record.len())
                .map_err(|_| Error::InvalidStore)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&record);
    }
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    Ok(bytes)
}

fn decode_pins(bytes: &[u8], cache_id: &[u8; 32]) -> Result<PinMap, Error> {
    if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES
        || bytes.len() > MAX_BYTES
        || &bytes[..8] != MAGIC
        || &bytes[8..40] != cache_id
    {
        return Err(Error::InvalidStore);
    }
    let end = bytes.len() - CHECKSUM_BYTES;
    if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err(Error::InvalidStore);
    }
    let count = usize::try_from(u32::from_le_bytes(
        bytes[40..44].try_into().map_err(|_| Error::InvalidStore)?,
    ))
    .map_err(|_| Error::InvalidStore)?;
    if count > MAX_PINS {
        return Err(Error::InvalidStore);
    }
    let mut remaining = &bytes[HEADER_BYTES..end];
    let mut pins = PinMap::new();
    for _ in 0..count {
        let length = usize::try_from(u32::from_le_bytes(
            remaining
                .get(..4)
                .ok_or(Error::InvalidStore)?
                .try_into()
                .map_err(|_| Error::InvalidStore)?,
        ))
        .map_err(|_| Error::InvalidStore)?;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(Error::InvalidStore);
        }
        let encoded = remaining.get(4..4 + length).ok_or(Error::InvalidStore)?;
        let record = PinRecord::decode(encoded).map_err(|_| Error::InvalidStore)?;
        if record.encode_to_vec() != encoded {
            return Err(Error::InvalidStore);
        }
        crate::manifest::validate_name(&record.name).map_err(|_| Error::InvalidStore)?;
        let publisher = record
            .publisher
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidStore)?;
        let pin = RevisionPin {
            revision: record.revision,
            manifest_id: record
                .manifest_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidStore)?,
            conflicted: record.conflicted,
        };
        let key = (publisher, record.name);
        if pin.revision == 0
            || pins
                .last_key_value()
                .is_some_and(|(previous, _)| previous >= &key)
        {
            return Err(Error::InvalidStore);
        }
        pins.insert(key, pin);
        remaining = &remaining[4 + length..];
    }
    if !remaining.is_empty() {
        return Err(Error::InvalidStore);
    }
    Ok(pins)
}
