//! Durable ciphertext custody, not remote authentication or guaranteed provider availability.
//!
//! The protocol layer authenticates registration, deposit, listing, retrieval and ACK callers.
//! This dedicated owned cache never performs LRU admission. Only fully verified messages enter
//! its index; ACK tombstones prevent a sender retry from resurrecting a delivered message.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use ed25519_dalek::VerifyingKey;
use prost::Message;
use sha2::{Digest as _, Sha256};

use super::{SignedMailboxGrant, VerifiedMailboxGrant};
use crate::{
    CacheLimits, CacheUsage, ChunkId, ChunkStore, SignedManifest, VerifiedManifest,
    private_message::{
        MAX_PRIVATE_MESSAGE_BYTES, PRIVATE_MESSAGE_CONTENT_TYPE, validate_private_message_envelope,
    },
    store::MAX_MAILBOX_METADATA_BYTES,
};

const MAX_MAILBOXES: usize = 16;
const MAX_MESSAGES: usize = 64;
const MAX_PAYLOAD: u64 = 256 * 1024 * 1024;
const MAX_SIGNED_MANIFEST: usize = 4096;
const MAX_GRANT: usize = 4096;
const MAX_RECORD: usize = MAX_SIGNED_MANIFEST + 128;
const MAX_CIPHERTEXT: usize = MAX_PRIVATE_MESSAGE_BYTES + 64;

/// One live message's original authenticated envelope, never a storage peer's replacement.
#[derive(Clone, Debug)]
pub struct StoreEntry {
    /// SHA-256 identifier of the exact canonical signed manifest.
    pub message_id: [u8; 32],
    /// Original sender-signed manifest; consumers authenticate their own trusted sender.
    pub signed: SignedManifest,
    /// Original manifest expiry, not a renewed cache deadline.
    pub expires_at: u64,
}

/// Bounded, fully checked ciphertext; plaintext and recipient secrets never enter this store.
pub struct StoredMessage {
    /// Original public sender/manifest metadata.
    pub entry: StoreEntry,
    /// Complete canonical private-message envelope, at most 4 MiB plus 64 bytes.
    pub ciphertext: Vec<u8>,
}

/// A local durable-state result; a higher layer creates any authenticated network receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositOutcome {
    /// Exact original manifest ID.
    pub message_id: [u8; 32],
    /// Original manifest expiry.
    pub expires_at: u64,
    /// This exact manifest was already indexed or acknowledged.
    pub already_present: bool,
    /// A durable ACK prevents reinsertion; this is not a new stored-message success.
    pub acknowledged: bool,
}

/// Detail-free store failures; caller authentication remains the enclosing protocol's job.
#[derive(Debug, thiserror::Error)]
pub enum MailboxStoreError {
    /// Invalid grant, message, original signature or private-message envelope.
    #[error("invalid mailbox object")]
    Invalid,
    /// No live matching mailbox or message authority.
    #[error("mailbox authority expired or unavailable")]
    Unavailable,
    /// A live slot already retains a different immutable grant.
    #[error("mailbox registration conflicts with retained authority")]
    Conflict,
    /// Configured count, payload or metadata bounds cannot admit this operation.
    #[error("mailbox quota exhausted")]
    Quota,
    /// Disk ownership, journal or chunk failure; no successful custody claim follows it.
    #[error("mailbox storage failed")]
    Storage(#[from] crate::Error),
}

#[derive(Clone)]
struct Entry {
    signed: SignedManifest,
    checked: VerifiedManifest,
    acknowledged: bool,
}

impl Entry {
    fn summary(&self) -> StoreEntry {
        StoreEntry {
            message_id: *self.checked.manifest_id(),
            signed: self.signed.clone(),
            expires_at: self.checked.validity().expires,
        }
    }
}

#[derive(Clone)]
struct Inbox {
    grant: VerifiedMailboxGrant,
    entries: BTreeMap<[u8; 32], Entry>,
}

type Inboxes = BTreeMap<[u8; 32], Inbox>;

/// Explicitly owned, exclusive mailbox storage with original-grant and ciphertext persistence.
///
/// At most sixteen mailboxes retain at most sixty-four records each, including ACK tombstones
/// until original expiry. Physical chunk payload is globally bounded by 256 MiB and caller
/// limits. Registration reserves no future space: only a completed deposit promises custody.
pub struct MailboxStore {
    chunks: ChunkStore,
    limits: CacheLimits,
    inboxes: Inboxes,
}

impl MailboxStore {
    /// Create a new private cache. Never adopts an existing directory or imports its contents.
    ///
    /// # Errors
    /// Rejects invalid limits/time, existing paths, unavailable space or unsafe storage.
    pub fn create(path: &Path, limits: CacheLimits, now: u64) -> Result<Self, MailboxStoreError> {
        validate_limits(limits, now)?;
        let mut result = Self {
            chunks: ChunkStore::create(path, limits)?,
            limits,
            inboxes: BTreeMap::new(),
        };
        result.persist(&BTreeMap::new())?;
        Ok(result)
    }

    /// Reopen this exact owned mailbox cache, rechecking original signatures and live ciphertext.
    /// Correctly expired records are pruned without extending any grant or manifest lifetime.
    ///
    /// # Errors
    /// Rejects busy/foreign caches, missing or corrupt mailbox journals, limits and live corruption.
    pub fn open(path: &Path, limits: CacheLimits, now: u64) -> Result<Self, MailboxStoreError> {
        validate_limits(limits, now)?;
        let chunks = ChunkStore::open(path, limits)?;
        let bytes = chunks
            .read_mailbox_metadata()?
            .ok_or(MailboxStoreError::Invalid)?;
        let inboxes = decode_index(&bytes)?;
        let mut result = Self {
            chunks,
            limits,
            inboxes,
        };
        for inbox in result.inboxes.values() {
            if inbox.grant.validity().created > now {
                return Err(MailboxStoreError::Invalid);
            }
            if inbox.grant.validity().expires <= now {
                continue;
            }
            for entry in inbox.entries.values() {
                if entry.checked.validity().created > now {
                    return Err(MailboxStoreError::Invalid);
                }
                if !entry.acknowledged && entry.checked.validity().expires > now {
                    read_ciphertext(&mut result.chunks, entry, now)?;
                }
            }
        }
        result.prune(now)?;
        Ok(result)
    }

    /// Register an already protocol-authorized immutable invitation; an exact retry is harmless.
    ///
    /// # Errors
    /// Rejects invalid/expired grants, changed authority for a live slot, count or disk limits.
    pub fn register(
        &mut self,
        grant: &VerifiedMailboxGrant,
        now: u64,
    ) -> Result<(), MailboxStoreError> {
        self.prune(now)?;
        let original = grant.signed().encode();
        if original.len() > MAX_GRANT {
            return Err(MailboxStoreError::Invalid);
        }
        let checked = grant
            .signed()
            .verify(&key(grant.owner_key())?, now)
            .map_err(|_| MailboxStoreError::Invalid)?;
        if let Some(existing) = self.inboxes.get(checked.mailbox_id()) {
            return if existing.grant.signed().encode() == original {
                Ok(())
            } else {
                Err(MailboxStoreError::Conflict)
            };
        }
        if self.inboxes.len() >= MAX_MAILBOXES {
            return Err(MailboxStoreError::Quota);
        }
        let mut next = self.inboxes.clone();
        next.insert(
            *checked.mailbox_id(),
            Inbox {
                grant: checked,
                entries: BTreeMap::new(),
            },
        );
        self.persist(&next)?;
        self.inboxes = next;
        Ok(())
    }

    /// Retain one exact original message, verifying its authorized sender and complete ciphertext.
    /// Existing data is never evicted to admit it. Acknowledged retries never recreate custody.
    ///
    /// # Errors
    /// Rejects unregistered/expired senders, invalid messages, quotas and incomplete persistence.
    pub fn deposit(
        &mut self,
        mailbox: &[u8; 32],
        signed: &SignedManifest,
        ciphertext: &[u8],
        now: u64,
    ) -> Result<DepositOutcome, MailboxStoreError> {
        self.prune(now)?;
        let inbox = self
            .inboxes
            .get(mailbox)
            .ok_or(MailboxStoreError::Unavailable)?;
        let checked = check_message(&inbox.grant, signed, now)?;
        let message_id = *checked.manifest_id();
        if let Some(entry) = inbox.entries.get(&message_id) {
            if !entry.acknowledged {
                read_ciphertext(&mut self.chunks, entry, now)?;
            }
            return Ok(DepositOutcome {
                message_id,
                expires_at: checked.validity().expires,
                already_present: true,
                acknowledged: entry.acknowledged,
            });
        }
        let retained = live_bytes(inbox)?;
        if inbox.entries.len() >= inbox.grant.max_messages() as usize
            || retained
                .checked_add(checked.length())
                .is_none_or(|bytes| bytes > inbox.grant.max_bytes())
        {
            return Err(MailboxStoreError::Quota);
        }
        check_ciphertext_hashes(&checked, ciphertext)?;
        self.check_capacity(&checked)?;
        let entry = Entry {
            signed: signed.clone(),
            checked,
            acknowledged: false,
        };
        let mut next = self.inboxes.clone();
        next.get_mut(mailbox)
            .ok_or(MailboxStoreError::Unavailable)?
            .entries
            .insert(message_id, entry.clone());
        let index = encode_index(&next)?;
        let mut inserted = Vec::new();
        let stored = self.store_ciphertext(&entry, ciphertext, now, &mut inserted);
        if let Err(error) = stored {
            self.release_unreferenced(&inserted, &self.inboxes.clone())?;
            return Err(error);
        }
        // Every chunk and its exact cache index have been fsynced before the mailbox becomes visible.
        self.chunks.replace_mailbox_metadata(&index)?;
        self.inboxes = next;
        Ok(DepositOutcome {
            message_id,
            expires_at: entry.checked.validity().expires,
            already_present: false,
            acknowledged: false,
        })
    }

    /// List at most sixty-four original live manifests, after higher-layer owner authentication.
    ///
    /// # Errors
    /// Rejects unavailable mailbox authority or failed expiry cleanup.
    pub fn list(
        &mut self,
        mailbox: &[u8; 32],
        now: u64,
    ) -> Result<Vec<StoreEntry>, MailboxStoreError> {
        self.prune(now)?;
        let inbox = self
            .inboxes
            .get(mailbox)
            .ok_or(MailboxStoreError::Unavailable)?;
        Ok(inbox
            .entries
            .values()
            .filter(|entry| !entry.acknowledged)
            .map(Entry::summary)
            .collect())
    }

    /// Retrieve at most one fully verified 4 MiB ciphertext object, never plaintext.
    ///
    /// # Errors
    /// Rejects unavailable mailbox authority and missing/corrupt ciphertext or failed cleanup.
    pub fn get(
        &mut self,
        mailbox: &[u8; 32],
        message: &[u8; 32],
        now: u64,
    ) -> Result<Option<StoredMessage>, MailboxStoreError> {
        self.prune(now)?;
        let inbox = self
            .inboxes
            .get(mailbox)
            .ok_or(MailboxStoreError::Unavailable)?;
        let Some(entry) = inbox
            .entries
            .get(message)
            .filter(|entry| !entry.acknowledged)
        else {
            return Ok(None);
        };
        let ciphertext = read_ciphertext(&mut self.chunks, entry, now)?;
        Ok(Some(StoredMessage {
            entry: entry.summary(),
            ciphertext,
        }))
    }

    /// Retire only this exact message after higher-layer recipient authentication. Preserve its
    /// ACK until original expiry, and reclaim chunks only when no other live entry needs them.
    ///
    /// # Errors
    /// Rejects unavailable mailboxes or failed durable acknowledgement/owned-chunk removal.
    pub fn acknowledge(
        &mut self,
        mailbox: &[u8; 32],
        message: &[u8; 32],
        now: u64,
    ) -> Result<bool, MailboxStoreError> {
        self.prune(now)?;
        let mut next = self.inboxes.clone();
        let inbox = next
            .get_mut(mailbox)
            .ok_or(MailboxStoreError::Unavailable)?;
        let Some(entry) = inbox.entries.get_mut(message) else {
            return Ok(false);
        };
        let candidates: Vec<_> = entry
            .checked
            .chunks()
            .iter()
            .map(|chunk| *chunk.id())
            .collect();
        entry.acknowledged = true;
        self.persist(&next)?;
        self.inboxes = next;
        self.release_unreferenced(&candidates, &self.inboxes.clone())?;
        Ok(true)
    }

    /// Physical chunk payload/entry accounting, including any retained incomplete writes.
    pub fn usage(&self) -> CacheUsage {
        self.chunks.usage()
    }

    /// Return only this store's actual live registration for higher-layer request authentication.
    ///
    /// # Errors
    /// Rejects invalid time or failed expiry cleanup; absence grants no request authority.
    pub fn grant(
        &mut self,
        mailbox: &[u8; 32],
        now: u64,
    ) -> Result<Option<VerifiedMailboxGrant>, MailboxStoreError> {
        self.prune(now)?;
        Ok(self.inboxes.get(mailbox).map(|inbox| inbox.grant.clone()))
    }

    fn check_capacity(&mut self, manifest: &VerifiedManifest) -> Result<(), MailboxStoreError> {
        let mut new_ids = BTreeSet::new();
        let mut extra = 0_u64;
        for chunk in manifest.chunks() {
            if self.chunks.get(chunk.id())?.is_none() && new_ids.insert(*chunk.id()) {
                extra = extra
                    .checked_add(u64::from(chunk.length()))
                    .ok_or(MailboxStoreError::Quota)?;
            }
        }
        let usage = self.chunks.usage();
        if usage
            .bytes
            .checked_add(extra)
            .is_none_or(|bytes| bytes > self.limits.max_bytes)
            || usage
                .entries
                .checked_add(new_ids.len())
                .is_none_or(|entries| entries > self.limits.max_entries)
        {
            return Err(MailboxStoreError::Quota);
        }
        Ok(())
    }

    fn store_ciphertext(
        &mut self,
        entry: &Entry,
        bytes: &[u8],
        now: u64,
        inserted: &mut Vec<ChunkId>,
    ) -> Result<(), MailboxStoreError> {
        let mut remaining = bytes;
        for chunk in entry.checked.chunks() {
            let (part, rest) = remaining.split_at(chunk.length() as usize);
            remaining = rest;
            if self.chunks.put_verified_if_space(*chunk.id(), part)? {
                inserted.push(*chunk.id());
            }
        }
        validate_private_message_envelope(&entry.checked, &mut [&mut self.chunks], now)
            .map_err(|_| MailboxStoreError::Invalid)
    }

    fn persist(&mut self, inboxes: &Inboxes) -> Result<(), MailboxStoreError> {
        let bytes = encode_index(inboxes)?;
        self.chunks.replace_mailbox_metadata(&bytes)?;
        Ok(())
    }

    fn prune(&mut self, now: u64) -> Result<(), MailboxStoreError> {
        if now == 0 {
            return Err(MailboxStoreError::Invalid);
        }
        if self.inboxes.values().any(|inbox| {
            inbox.grant.validity().created > now
                || inbox
                    .entries
                    .values()
                    .any(|entry| entry.checked.validity().created > now)
        }) {
            return Err(MailboxStoreError::Unavailable);
        }
        let mut next = self.inboxes.clone();
        let mut candidates = Vec::new();
        let mut changed = false;
        next.retain(|_, inbox| {
            let expired = inbox.grant.validity().expires <= now;
            inbox.entries.retain(|_, entry| {
                let remove = expired || entry.checked.validity().expires <= now;
                if remove || entry.acknowledged {
                    candidates.extend(entry.checked.chunks().iter().map(|chunk| *chunk.id()));
                }
                changed |= remove;
                !remove
            });
            changed |= expired;
            !expired
        });
        // Removed records are already expired; deleting their unshared payload first leaves any
        // crash-interrupted old journal sufficient to repeat exact cleanup on the next open.
        self.release_unreferenced(&candidates, &next)?;
        if changed {
            self.persist(&next)?;
            self.inboxes = next;
        }
        Ok(())
    }

    fn release_unreferenced(
        &mut self,
        candidates: &[ChunkId],
        remaining: &Inboxes,
    ) -> Result<(), MailboxStoreError> {
        let retained: BTreeSet<_> = remaining
            .values()
            .flat_map(|inbox| inbox.entries.values())
            .filter(|entry| !entry.acknowledged)
            .flat_map(|entry| entry.checked.chunks().iter().map(|chunk| *chunk.id()))
            .collect();
        for id in candidates.iter().copied().collect::<BTreeSet<_>>() {
            if !retained.contains(&id) {
                self.chunks.remove_owned_chunk(id)?;
            }
        }
        Ok(())
    }
}

fn validate_limits(limits: CacheLimits, now: u64) -> Result<(), MailboxStoreError> {
    if limits.max_bytes == 0 || limits.max_bytes > MAX_PAYLOAD || now == 0 {
        return Err(MailboxStoreError::Quota);
    }
    Ok(())
}

fn key(bytes: &[u8; 32]) -> Result<VerifyingKey, MailboxStoreError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| MailboxStoreError::Invalid)
}

fn check_message(
    grant: &VerifiedMailboxGrant,
    signed: &SignedManifest,
    now: u64,
) -> Result<VerifiedManifest, MailboxStoreError> {
    if signed.encode().len() > MAX_SIGNED_MANIFEST {
        return Err(MailboxStoreError::Invalid);
    }
    let checked = signed.verify(&key(grant.sender_key())?, now)?;
    let metadata = checked.metadata();
    if metadata.content_type != PRIVATE_MESSAGE_CONTENT_TYPE
        || metadata.revision != 1
        || metadata.name.len() != 64
        || !metadata
            .name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || checked.length() < 54
        || checked.validity().expires > grant.validity().expires
        || checked.length() > MAX_CIPHERTEXT as u64
    {
        return Err(MailboxStoreError::Invalid);
    }
    Ok(checked)
}

fn check_ciphertext_hashes(
    manifest: &VerifiedManifest,
    bytes: &[u8],
) -> Result<(), MailboxStoreError> {
    if bytes.len() > MAX_CIPHERTEXT
        || bytes.len() as u64 != manifest.length()
        || Sha256::digest(bytes).as_slice() != manifest.object_sha256()
    {
        return Err(MailboxStoreError::Invalid);
    }
    let mut remaining = bytes;
    for chunk in manifest.chunks() {
        let length = chunk.length() as usize;
        if remaining.len() < length {
            return Err(MailboxStoreError::Invalid);
        }
        let (part, rest) = remaining.split_at(length);
        if ChunkId::digest(part) != *chunk.id() {
            return Err(MailboxStoreError::Invalid);
        }
        remaining = rest;
    }
    if !remaining.is_empty() {
        return Err(MailboxStoreError::Invalid);
    }
    Ok(())
}

fn read_ciphertext(
    chunks: &mut ChunkStore,
    entry: &Entry,
    now: u64,
) -> Result<Vec<u8>, MailboxStoreError> {
    validate_private_message_envelope(&entry.checked, &mut [&mut *chunks], now)
        .map_err(|_| MailboxStoreError::Invalid)?;
    let length = usize::try_from(entry.checked.length()).map_err(|_| MailboxStoreError::Invalid)?;
    let mut bytes = Vec::with_capacity(length);
    crate::reassemble(&entry.checked, &mut [chunks], now, &mut bytes)?;
    Ok(bytes)
}

fn live_bytes(inbox: &Inbox) -> Result<u64, MailboxStoreError> {
    inbox
        .entries
        .values()
        .filter(|entry| !entry.acknowledged)
        .try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.checked.length())
                .ok_or(MailboxStoreError::Quota)
        })
}

#[derive(Clone, PartialEq, Message)]
struct RegistrationRecord {
    #[prost(bytes = "vec", tag = "1")]
    grant: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    owner: Vec<u8>,
    #[prost(uint64, tag = "3")]
    created: u64,
}

#[derive(Clone, PartialEq, Message)]
struct MessageRecord {
    #[prost(bytes = "vec", tag = "1")]
    mailbox: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed: Vec<u8>,
    #[prost(uint64, tag = "3")]
    created: u64,
    #[prost(bool, tag = "4")]
    acknowledged: bool,
}

fn encode_index(inboxes: &Inboxes) -> Result<Vec<u8>, MailboxStoreError> {
    if inboxes.len() > MAX_MAILBOXES {
        return Err(MailboxStoreError::Quota);
    }
    let mut bytes = vec![1_u8];
    append_count(&mut bytes, inboxes.len())?;
    for inbox in inboxes.values() {
        let record = RegistrationRecord {
            grant: inbox.grant.signed().encode(),
            owner: inbox.grant.owner_key().to_vec(),
            created: inbox.grant.validity().created,
        };
        append_record(&mut bytes, &record, MAX_GRANT + 128)?;
        append_count(&mut bytes, inbox.entries.len())?;
        for entry in inbox.entries.values() {
            let record = MessageRecord {
                mailbox: inbox.grant.mailbox_id().to_vec(),
                signed: entry.signed.encode(),
                created: entry.checked.validity().created,
                acknowledged: entry.acknowledged,
            };
            append_record(&mut bytes, &record, MAX_RECORD)?;
        }
    }
    Ok(bytes)
}

fn append_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), MailboxStoreError> {
    bytes.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| MailboxStoreError::Quota)?
            .to_le_bytes(),
    );
    Ok(())
}

fn append_record<M: Message>(
    bytes: &mut Vec<u8>,
    message: &M,
    maximum: usize,
) -> Result<(), MailboxStoreError> {
    let record = message.encode_to_vec();
    if record.len() > maximum || bytes.len() + 4 + record.len() > MAX_MAILBOX_METADATA_BYTES {
        return Err(MailboxStoreError::Quota);
    }
    append_count(bytes, record.len())?;
    bytes.extend_from_slice(&record);
    Ok(())
}

fn decode_index(bytes: &[u8]) -> Result<Inboxes, MailboxStoreError> {
    let Some((&1, mut remaining)) = bytes.split_first() else {
        return Err(MailboxStoreError::Invalid);
    };
    let count = read_count(&mut remaining, MAX_MAILBOXES)?;
    let mut inboxes = BTreeMap::new();
    for _ in 0..count {
        let record: RegistrationRecord = read_record(&mut remaining, MAX_GRANT + 128)?;
        let owner = record
            .owner
            .as_slice()
            .try_into()
            .map_err(|_| MailboxStoreError::Invalid)?;
        let grant = SignedMailboxGrant::decode(&record.grant)
            .map_err(|_| MailboxStoreError::Invalid)?
            .verify(&key(owner)?, record.created)
            .map_err(|_| MailboxStoreError::Invalid)?;
        if grant.validity().created != record.created {
            return Err(MailboxStoreError::Invalid);
        }
        let count = read_count(
            &mut remaining,
            MAX_MESSAGES.min(grant.max_messages() as usize),
        )?;
        let mut inbox = Inbox {
            grant,
            entries: BTreeMap::new(),
        };
        for _ in 0..count {
            let record: MessageRecord = read_record(&mut remaining, MAX_RECORD)?;
            if record.mailbox.as_slice() != inbox.grant.mailbox_id() {
                return Err(MailboxStoreError::Invalid);
            }
            let signed = SignedManifest::decode(&record.signed)?;
            let checked = check_message(&inbox.grant, &signed, record.created)?;
            if checked.validity().created != record.created {
                return Err(MailboxStoreError::Invalid);
            }
            let id = *checked.manifest_id();
            if inbox
                .entries
                .insert(
                    id,
                    Entry {
                        signed,
                        checked,
                        acknowledged: record.acknowledged,
                    },
                )
                .is_some()
            {
                return Err(MailboxStoreError::Invalid);
            }
        }
        if live_bytes(&inbox)? > inbox.grant.max_bytes()
            || inboxes.insert(*inbox.grant.mailbox_id(), inbox).is_some()
        {
            return Err(MailboxStoreError::Invalid);
        }
    }
    if !remaining.is_empty() || encode_index(&inboxes)? != bytes {
        return Err(MailboxStoreError::Invalid);
    }
    Ok(inboxes)
}

fn read_count(bytes: &mut &[u8], maximum: usize) -> Result<usize, MailboxStoreError> {
    let header = bytes.get(..4).ok_or(MailboxStoreError::Invalid)?;
    let count =
        u32::from_le_bytes(header.try_into().map_err(|_| MailboxStoreError::Invalid)?) as usize;
    if count > maximum {
        return Err(MailboxStoreError::Invalid);
    }
    *bytes = &bytes[4..];
    Ok(count)
}

fn read_record<M: Message + Default>(
    bytes: &mut &[u8],
    maximum: usize,
) -> Result<M, MailboxStoreError> {
    let length = read_count(bytes, maximum)?;
    let record = bytes.get(..length).ok_or(MailboxStoreError::Invalid)?;
    let decoded = M::decode(record).map_err(|_| MailboxStoreError::Invalid)?;
    if decoded.encode_to_vec() != record {
        return Err(MailboxStoreError::Invalid);
    }
    *bytes = &bytes[length..];
    Ok(decoded)
}
