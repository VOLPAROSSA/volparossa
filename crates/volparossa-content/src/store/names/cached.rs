//! Original public-native envelopes, separate from the irreversible revision floor.
//! A floor is persisted first: interruption can make a cache unavailable, never roll it back.

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
};

use ed25519_dalek::VerifyingKey;
use prost::Message;
use sha2::{Digest as _, Sha256};

use super::{CHECKSUM_BYTES, HEADER_BYTES, MAX_PINS, RevisionPin};
use crate::{
    ChunkStore, Error, MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    store::{create_file, ensure_absent, io_error, open_private_file},
};

const FILE: &str = ".volparossa-named-manifests-v1";
const STAGE: &str = ".volparossa-named-manifests-next-v1";
const MAGIC: &[u8; 8] = b"VPNM0001";
const MAX_RECORD: usize = MAX_MANIFEST_BYTES + 16;
const MAX_BYTES: usize = HEADER_BYTES + MAX_PINS * (4 + MAX_RECORD) + CHECKSUM_BYTES;
type SavedMap = BTreeMap<([u8; 32], String), Saved>;

struct Saved {
    signed: SignedManifest,
    created: u64,
}

impl ChunkStore {
    /// Retain an original public-native envelope under the caller's independent publisher key.
    ///
    /// Call after verifying the requested exact name and complete object. This stores metadata,
    /// not a claim that chunks remain present. The durable revision/conflict floor is updated
    /// before the envelope; neither LRU nor expiry erases that floor. No HTTP authority is stored.
    ///
    /// # Errors
    /// Rejects wrong publisher/signature, expiry, private messages, rollback/conflict, more than
    /// 64 names, or unsafe/incomplete owned metadata. A failed snapshot write cannot lower a floor.
    pub fn remember_named_manifest(
        &mut self,
        signed: &SignedManifest,
        trusted: &VerifyingKey,
        now_unix: u64,
    ) -> Result<RevisionPin, Error> {
        let manifest = public_manifest(signed, trusted, now_unix)?;
        let mut saved = self.read_named_manifests()?;
        let key = (*manifest.publisher(), manifest.metadata().name.clone());
        if !saved.contains_key(&key) && saved.len() >= MAX_PINS {
            return Err(Error::Limit("cached named manifests"));
        }
        let pin = self.observe_name_revision(&manifest, now_unix)?;
        if saved
            .get(&key)
            .is_some_and(|old| old.signed.encode() == signed.encode())
        {
            return Ok(pin);
        }
        saved.insert(
            key,
            Saved {
                signed: signed.clone(),
                created: manifest.validity().created,
            },
        );
        self.persist_named_manifests(&saved)?;
        Ok(pin)
    }

    /// Load an original public-native envelope without discovery, routing or expiry renewal.
    ///
    /// The supplied publisher is independently trusted, never taken from the stored hint.
    /// Zero minimum adds no caller floor. Missing snapshots return `None`; a newer observation
    /// or conflict never falls back to an older envelope. Consumers must still verify all chunks
    /// and the whole object before output; this API does not establish global latestness.
    ///
    /// # Errors
    /// Rejects invalid keys/names, unsafe storage, signature/expiry errors, private content,
    /// conflicts and a snapshot below either the retained or explicitly requested revision floor.
    pub fn cached_named_manifest(
        &self,
        publisher: &[u8; 32],
        name: &str,
        min_revision: u64,
        now_unix: u64,
    ) -> Result<Option<SignedManifest>, Error> {
        crate::manifest::validate_name(name)?;
        let trusted = VerifyingKey::from_bytes(publisher).map_err(|_| Error::InvalidManifest)?;
        let Some(pin) = self.name_revision_floor(publisher, name)? else {
            return Ok(None);
        };
        if pin.conflicted() {
            return Err(Error::NameConflict);
        }
        if pin.revision() < min_revision {
            return Err(Error::NameRollback);
        }
        let mut saved = self.read_named_manifests()?;
        let Some(candidate) = saved.remove(&(*publisher, name.into())) else {
            return Ok(None);
        };
        let checked = public_manifest(&candidate.signed, &trusted, now_unix)?;
        if checked.metadata().name != name {
            return Err(Error::InvalidStore);
        }
        if checked.metadata().revision != pin.revision()
            || checked.manifest_id() != pin.manifest_id()
            || checked.metadata().revision < min_revision
        {
            return Err(Error::NameRollback);
        }
        Ok(Some(candidate.signed))
    }

    pub(super) fn check_cached_name_metadata(&self) -> Result<(), Error> {
        let pins = self.read_name_pins()?;
        if self
            .read_named_manifests()?
            .keys()
            .any(|key| !pins.contains_key(key))
        {
            return Err(Error::InvalidStore);
        }
        Ok(())
    }

    fn read_named_manifests(&self) -> Result<SavedMap, Error> {
        self.ensure_healthy()?;
        ensure_absent(&self.directory, STAGE)?;
        let file = match open_private_file(&self.directory, FILE, MAX_BYTES as u64) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        decode(&bytes, &self.cache_id).map_err(|_| Error::InvalidStore)
    }

    fn persist_named_manifests(&mut self, saved: &SavedMap) -> Result<(), Error> {
        let bytes = encode(saved, &self.cache_id)?;
        self.check_free_space(bytes.len() as u64)?;
        self.healthy = false;
        let mut output = create_file(&self.directory, STAGE)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        rustix::fs::renameat(&self.directory, STAGE, &self.directory, FILE).map_err(io_error)?;
        self.directory.sync_all()?;
        self.healthy = true;
        Ok(())
    }
}

fn public_manifest(
    signed: &SignedManifest,
    key: &VerifyingKey,
    at: u64,
) -> Result<VerifiedManifest, Error> {
    let checked = signed.verify(key, at)?;
    if checked.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        return Err(Error::InvalidManifest);
    }
    Ok(checked)
}

#[derive(Clone, PartialEq, Message)]
struct Record {
    #[prost(bytes = "vec", tag = "1")]
    signed: Vec<u8>,
    #[prost(uint64, tag = "2")]
    created: u64,
}

fn encode(saved: &SavedMap, cache_id: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(cache_id);
    bytes.extend_from_slice(
        &u32::try_from(saved.len())
            .map_err(|_| Error::InvalidStore)?
            .to_le_bytes(),
    );
    for value in saved.values() {
        let record = Record {
            signed: value.signed.encode(),
            created: value.created,
        }
        .encode_to_vec();
        if record.len() > MAX_RECORD || saved.len() > MAX_PINS {
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

fn decode(bytes: &[u8], cache_id: &[u8; 32]) -> Result<SavedMap, Error> {
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
    let mut remaining = &bytes[40..end];
    let count = take_length(&mut remaining)?;
    if count > MAX_PINS {
        return Err(Error::InvalidStore);
    }
    let mut saved = SavedMap::new();
    for _ in 0..count {
        let length = take_length(&mut remaining)?;
        if length == 0 || length > MAX_RECORD {
            return Err(Error::InvalidStore);
        }
        let encoded = remaining.get(..length).ok_or(Error::InvalidStore)?;
        let record = Record::decode(encoded).map_err(|_| Error::InvalidStore)?;
        if record.encode_to_vec() != encoded {
            return Err(Error::InvalidStore);
        }
        let signed = SignedManifest::decode(&record.signed)?;
        // Structural storage consistency only. Lookup still verifies the caller's independent key.
        let key = VerifyingKey::from_bytes(&signed.publisher_key_hint())
            .map_err(|_| Error::InvalidStore)?;
        let checked = public_manifest(&signed, &key, record.created)?;
        let key = (*checked.publisher(), checked.metadata().name.clone());
        if checked.validity().created != record.created
            || saved
                .last_key_value()
                .is_some_and(|(previous, _)| previous >= &key)
        {
            return Err(Error::InvalidStore);
        }
        saved.insert(
            key,
            Saved {
                signed,
                created: record.created,
            },
        );
        remaining = &remaining[length..];
    }
    if !remaining.is_empty() {
        return Err(Error::InvalidStore);
    }
    Ok(saved)
}

fn take_length(bytes: &mut &[u8]) -> Result<usize, Error> {
    let raw = bytes
        .get(..4)
        .ok_or(Error::InvalidStore)?
        .try_into()
        .map_err(|_| Error::InvalidStore)?;
    *bytes = &bytes[4..];
    usize::try_from(u32::from_le_bytes(raw)).map_err(|_| Error::InvalidStore)
}
