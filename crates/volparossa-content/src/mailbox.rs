//! Explicit known-contact mailboxes on independently selected content providers.
//!
//! Invitations authenticate a recipient's application key and one allowed sender. They are
//! not a public name index, proof of retention, or permission to expose private-message
//! manifests through public lookup. Message encryption remains the existing RFC 9180 profile.
//! Mailbox signing keys may be independently created encrypted application identities; no
//! permanent network identity or decryption key is required by storage providers.

pub mod store;
pub mod wire;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{MAX_VALIDITY_SECONDS, Validity};

const VERSION: u32 = 1;
const GRANT_TYPE: u32 = 1;
const SIGNING_DOMAIN: &[u8] = b"VOLPAROSSA/native-mailbox/v1\0";
/// Hard bound before decoding an invitation, independent of peer-controlled fields.
pub const MAX_GRANT_BYTES: usize = 2048;
/// Maximum promised payload capacity of one bounded invitation.
pub const MAX_MAILBOX_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum messages admitted by one invitation, including unexpired receipt tombstones.
pub const MAX_MAILBOX_MESSAGES: u32 = 64;

/// No authorization is inferred from a public key found in an untrusted invitation.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// The supplied protected stream failed; this never authorizes another transport.
    #[error("mailbox stream I/O failed")]
    Io(#[from] std::io::Error),
    /// Noncanonical, missing, duplicated, out-of-bounds or unsupported fields.
    #[error("invalid bounded mailbox message")]
    Invalid,
    /// The trusted participant did not authorize the exact request or invitation.
    #[error("mailbox authorization failed")]
    Unauthorized,
    /// Original validity has elapsed or has not begun.
    #[error("mailbox authorization is expired or not yet valid")]
    Expired,
    /// Operating-system secure randomness could not be obtained.
    #[error("mailbox secure randomness unavailable")]
    Entropy,
    /// A bounded operation did not finish before its retained deadline.
    #[error("mailbox operation timed out")]
    Timeout,
    /// The explicit provider could not retain or retrieve the requested exact object.
    #[error("mailbox storage unavailable or quota exceeded")]
    Store,
}

/// Explicit immutable limits for one known-sender mailbox invitation.
#[derive(Clone, Copy, Debug)]
pub struct MailboxQuota {
    /// Maximum retained ciphertext bytes, never automatically selected from disk size.
    pub max_bytes: u64,
    /// Maximum retained messages plus unexpired acknowledgement tombstones.
    pub max_messages: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Body {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    sender: Vec<u8>,
    #[prost(uint64, tag = "3")]
    created: u64,
    #[prost(uint64, tag = "4")]
    expires: u64,
    #[prost(bytes = "vec", tag = "5")]
    nonce: Vec<u8>,
    #[prost(uint32, tag = "6")]
    message_type: u32,
    #[prost(bytes = "vec", tag = "7")]
    payload_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct Envelope {
    #[prost(message, optional, tag = "1")]
    body: Option<Body>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct GrantPayload {
    #[prost(bytes = "vec", tag = "1")]
    mailbox_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    allowed_sender: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    recipient: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    providers: Vec<Vec<u8>>,
    #[prost(uint64, tag = "5")]
    max_bytes: u64,
    #[prost(uint32, tag = "6")]
    max_messages: u32,
}

/// Original signed recipient invitation. Decoding does not establish independent trust.
#[derive(Clone, Debug)]
pub struct SignedMailboxGrant {
    envelope: Envelope,
    payload: GrantPayload,
}

/// Independently verified immutable mailbox permissions and original signed bytes.
#[derive(Clone, Debug)]
pub struct VerifiedMailboxGrant {
    signed: SignedMailboxGrant,
    mailbox_id: [u8; 32],
    owner: [u8; 32],
    sender: [u8; 32],
    recipient: [u8; 32],
    providers: [[u8; 32]; 2],
    validity: Validity,
}

impl SignedMailboxGrant {
    /// Create a fresh opaque mailbox for one independently known sender and two providers.
    ///
    /// `recipient_key` must be the recipient's independently authenticated encryption key;
    /// signing binds that association but cannot prove possession of its decryption key.
    /// Provider enrollment/storage has not happened until actual remote receipts arrive.
    ///
    /// # Errors
    /// Rejects invalid keys, duplicate providers, quota/lifetime bounds and failed randomness.
    pub fn sign(
        owner: &SigningKey,
        sender: [u8; 32],
        recipient_key: [u8; 32],
        mut providers: [[u8; 32]; 2],
        validity: Validity,
        quota: MailboxQuota,
    ) -> Result<Self, MailboxError> {
        providers.sort_unstable();
        let mut mailbox_id = [0; 32];
        getrandom::fill(&mut mailbox_id).map_err(|_| MailboxError::Entropy)?;
        let payload = GrantPayload {
            mailbox_id: mailbox_id.to_vec(),
            allowed_sender: sender.to_vec(),
            recipient: recipient_key.to_vec(),
            providers: providers.iter().map(|key| key.to_vec()).collect(),
            max_bytes: quota.max_bytes,
            max_messages: quota.max_messages,
        };
        let envelope = sign_envelope(owner, GRANT_TYPE, payload.encode_to_vec(), validity)?;
        let signed = Self { envelope, payload };
        signed.verify(&owner.verifying_key(), validity.created)?;
        Ok(signed)
    }

    /// Encode the original canonical signed invitation, without extending its validity.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Decode bounded canonical fields without treating the embedded owner key as trusted.
    ///
    /// # Errors
    /// Rejects oversize/noncanonical envelopes, invalid types, lengths and payload hashes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxError> {
        let envelope: Envelope = decode_canonical(bytes, MAX_GRANT_BYTES)?;
        let body = envelope.body.as_ref().ok_or(MailboxError::Invalid)?;
        validate_body(body, GRANT_TYPE, MAX_VALIDITY_SECONDS)?;
        if envelope.signature.len() != 64 {
            return Err(MailboxError::Invalid);
        }
        let payload = decode_canonical(&body.payload, MAX_GRANT_BYTES)?;
        let signed = Self { envelope, payload };
        signed.validate_payload()?;
        Ok(signed)
    }

    /// Untrusted embedded key used only to select already authorized state or self-registration.
    ///
    /// # Errors
    /// Rejects a missing body or invalid fixed-length owner hint.
    pub fn owner_key_hint(&self) -> Result<[u8; 32], MailboxError> {
        fixed(
            &self
                .envelope
                .body
                .as_ref()
                .ok_or(MailboxError::Invalid)?
                .sender,
        )
    }

    /// Verify the exact invitation against an independently established recipient signing key.
    ///
    /// A storage provider may verify self-registration against its embedded key, but that
    /// confers no trust in the recipient for callers and cannot replace a previously owned ID.
    ///
    /// # Errors
    /// Rejects wrong owner, signature, original lifetime and structural/quota constraints.
    pub fn verify(
        &self,
        expected_owner: &VerifyingKey,
        now: u64,
    ) -> Result<VerifiedMailboxGrant, MailboxError> {
        self.validate_payload()?;
        let body = verify_envelope(
            &self.envelope,
            expected_owner,
            GRANT_TYPE,
            MAX_VALIDITY_SECONDS,
            now,
        )?;
        Ok(VerifiedMailboxGrant {
            signed: self.clone(),
            mailbox_id: fixed(&self.payload.mailbox_id)?,
            owner: expected_owner.to_bytes(),
            sender: fixed(&self.payload.allowed_sender)?,
            recipient: fixed(&self.payload.recipient)?,
            providers: [
                fixed(&self.payload.providers[0])?,
                fixed(&self.payload.providers[1])?,
            ],
            validity: Validity {
                created: body.created,
                expires: body.expires,
            },
        })
    }

    fn validate_payload(&self) -> Result<(), MailboxError> {
        let payload = &self.payload;
        fixed(&payload.mailbox_id)?;
        public_key(&payload.allowed_sender)?;
        fixed(&payload.recipient)?;
        if payload.providers.len() != 2
            || payload.providers[0] >= payload.providers[1]
            || payload.max_bytes == 0
            || payload.max_bytes > MAX_MAILBOX_BYTES
            || payload.max_messages == 0
            || payload.max_messages > MAX_MAILBOX_MESSAGES
        {
            return Err(MailboxError::Invalid);
        }
        for provider in &payload.providers {
            public_key(provider)?;
        }
        Ok(())
    }
}

impl VerifiedMailboxGrant {
    /// Original immutable signed bytes.
    pub fn signed(&self) -> &SignedMailboxGrant {
        &self.signed
    }
    /// Random opaque inbox identity, never a DHT key.
    pub const fn mailbox_id(&self) -> &[u8; 32] {
        &self.mailbox_id
    }
    /// Recipient's mailbox signing identity; not necessarily its network identity.
    pub const fn owner_key(&self) -> &[u8; 32] {
        &self.owner
    }
    /// Only sender allowed to deposit original signed ciphertext publications.
    pub const fn sender_key(&self) -> &[u8; 32] {
        &self.sender
    }
    /// Recipient HPKE key authenticated by the invitation owner.
    pub const fn recipient_key(&self) -> &[u8; 32] {
        &self.recipient
    }
    /// Exactly two independently supplied provider signing keys, in canonical order.
    pub const fn provider_keys(&self) -> &[[u8; 32]; 2] {
        &self.providers
    }
    /// Original absolute grant lifetime, not refreshed by deposit, lookup or restart.
    pub const fn validity(&self) -> Validity {
        self.validity
    }
    /// Granted ciphertext-byte capacity; registration alone does not reserve actual storage.
    pub const fn max_bytes(&self) -> u64 {
        self.signed.payload.max_bytes
    }
    /// Maximum admitted messages and unexpired acknowledgement tombstones.
    pub const fn max_messages(&self) -> u32 {
        self.signed.payload.max_messages
    }
    /// Exact immutable invitation identity, not a public-key trust anchor.
    pub fn grant_id(&self) -> [u8; 32] {
        Sha256::digest(self.signed.encode()).into()
    }
    /// Check original validity at the actual operation time.
    ///
    /// # Errors
    /// Rejects expiry or not-yet-valid use.
    pub fn check_time(&self, now: u64) -> Result<(), MailboxError> {
        check_time(self.validity, now)
    }
}

fn fixed(bytes: &[u8]) -> Result<[u8; 32], MailboxError> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| MailboxError::Invalid)?;
    if value == [0; 32] {
        return Err(MailboxError::Invalid);
    }
    Ok(value)
}

fn public_key(bytes: &[u8]) -> Result<VerifyingKey, MailboxError> {
    let key = VerifyingKey::from_bytes(&fixed(bytes)?).map_err(|_| MailboxError::Invalid)?;
    if key.is_weak() {
        return Err(MailboxError::Invalid);
    }
    Ok(key)
}

fn decode_canonical<M: Message + Default>(bytes: &[u8], maximum: usize) -> Result<M, MailboxError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(MailboxError::Invalid);
    }
    let value = M::decode(bytes).map_err(|_| MailboxError::Invalid)?;
    if value.encode_to_vec() != bytes {
        return Err(MailboxError::Invalid);
    }
    Ok(value)
}

fn sign_envelope(
    signer: &SigningKey,
    message_type: u32,
    payload: Vec<u8>,
    validity: Validity,
) -> Result<Envelope, MailboxError> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| MailboxError::Entropy)?;
    let body = Body {
        version: VERSION,
        sender: signer.verifying_key().to_bytes().to_vec(),
        created: validity.created,
        expires: validity.expires,
        nonce: nonce.to_vec(),
        message_type,
        payload_hash: Sha256::digest(&payload).to_vec(),
        payload,
    };
    validate_body(&body, message_type, MAX_VALIDITY_SECONDS)?;
    let signature = signer.sign(&signing_bytes(&body)).to_bytes().to_vec();
    Ok(Envelope {
        body: Some(body),
        signature,
    })
}

fn signing_bytes(body: &Body) -> Vec<u8> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend_from_slice(&body.encode_to_vec());
    bytes
}

fn validate_body(body: &Body, kind: u32, max_lifetime: u64) -> Result<(), MailboxError> {
    public_key(&body.sender)?;
    fixed(&body.nonce)?;
    if body.version != VERSION
        || body.message_type != kind
        || body.created == 0
        || body.expires <= body.created
        || body.expires - body.created > max_lifetime
        || body.payload_hash.as_slice() != Sha256::digest(&body.payload).as_slice()
    {
        return Err(MailboxError::Invalid);
    }
    Ok(())
}

fn check_time(validity: Validity, now: u64) -> Result<(), MailboxError> {
    if now < validity.created || now >= validity.expires {
        return Err(MailboxError::Expired);
    }
    Ok(())
}

fn verify_envelope<'a>(
    envelope: &'a Envelope,
    expected: &VerifyingKey,
    kind: u32,
    max_lifetime: u64,
    now: u64,
) -> Result<&'a Body, MailboxError> {
    let body = envelope.body.as_ref().ok_or(MailboxError::Invalid)?;
    validate_body(body, kind, max_lifetime)?;
    if body.sender != expected.as_bytes() {
        return Err(MailboxError::Unauthorized);
    }
    check_time(
        Validity {
            created: body.created,
            expires: body.expires,
        },
        now,
    )?;
    let signature =
        Signature::from_slice(&envelope.signature).map_err(|_| MailboxError::Invalid)?;
    expected
        .verify_strict(&signing_bytes(body), &signature)
        .map_err(|_| MailboxError::Unauthorized)?;
    Ok(body)
}
