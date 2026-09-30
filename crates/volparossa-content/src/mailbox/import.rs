//! Owner-authenticated local handoff, separate from provider custody and application import.
//!
//! This reuses the mailbox canonical envelope and signature domain with distinct type 5.
//! It authorizes no provider operation by itself: confirmation still needs the owner key
//! and a fresh authenticated network challenge. A consumer's confirmation is an attestation,
//! not independent proof that Thunderbird, Signal or another application committed its data.

use ed25519_dalek::{SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{
    Envelope, MailboxError, SignedMailboxGrant, VerifiedMailboxGrant, decode_canonical, fixed,
    sign_envelope, verify_envelope,
};
use crate::{
    MAX_VALIDITY_SECONDS, SignedManifest, Validity,
    private_message::{MAX_PRIVATE_MESSAGE_BYTES, PRIVATE_MESSAGE_CONTENT_TYPE},
};

const IMPORT_TYPE: u32 = 5;
/// Original grant, message manifest and fixed-width handoff metadata only.
pub const MAX_IMPORT_RECEIPT_BYTES: usize = 8192;

#[derive(Clone, PartialEq, Message)]
struct Payload {
    #[prost(bytes = "vec", tag = "1")]
    grant: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    manifest: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    plaintext_sha256: Vec<u8>,
    #[prost(uint64, tag = "4")]
    plaintext_bytes: u64,
    #[prost(bytes = "vec", tag = "5")]
    confirmation_token_sha256: Vec<u8>,
}

/// Immutable local handoff receipt; decoding does not establish the owner's identity.
#[derive(Clone, Debug)]
pub struct SignedImportReceipt {
    envelope: Envelope,
    payload: Payload,
}

/// Exact independently verified owner, grant, original message and handoff binding.
pub struct VerifiedImportReceipt {
    grant: VerifiedMailboxGrant,
    message_id: [u8; 32],
    plaintext_sha256: [u8; 32],
    plaintext_bytes: u64,
    token_sha256: [u8; 32],
    expires: u64,
}

impl SignedImportReceipt {
    /// Sign a completed, private local download for later explicit consumer confirmation.
    ///
    /// The caller must already have authenticated and decrypted the original message. This
    /// statement cannot itself prove decryption or an application's later durable import.
    ///
    /// # Errors
    /// Rejects a different owner/sender, altered authority, invalid message, size or expiry.
    pub fn sign(
        signer: &SigningKey,
        grant: &VerifiedMailboxGrant,
        manifest: &SignedManifest,
        plaintext: &[u8],
        confirmation_token: &[u8; 32],
        now: u64,
    ) -> Result<Self, MailboxError> {
        if grant.owner_key() != signer.verifying_key().as_bytes()
            || plaintext.len() > MAX_PRIVATE_MESSAGE_BYTES
        {
            return Err(MailboxError::Unauthorized);
        }
        let checked = manifest
            .verify(&super::public_key(grant.sender_key())?, now)
            .map_err(|_| MailboxError::Invalid)?;
        let payload = Payload {
            grant: grant.signed().encode(),
            manifest: manifest.encode(),
            plaintext_sha256: Sha256::digest(plaintext).to_vec(),
            plaintext_bytes: plaintext.len() as u64,
            confirmation_token_sha256: Sha256::digest(confirmation_token).to_vec(),
        };
        let envelope = sign_envelope(
            signer,
            IMPORT_TYPE,
            payload.encode_to_vec(),
            Validity {
                created: now,
                expires: checked.validity().expires.min(grant.validity().expires),
            },
        )?;
        let signed = Self { envelope, payload };
        if signed.encode().len() > MAX_IMPORT_RECEIPT_BYTES {
            return Err(MailboxError::Invalid);
        }
        signed.verify(&signer.verifying_key(), now)?;
        Ok(signed)
    }

    /// Canonical original mailbox-domain envelope; never public-cache publication.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Decode bounded canonical fields, rejecting unknown/duplicate protobuf encodings.
    ///
    /// # Errors
    /// Rejects unsupported or malformed envelope/payload encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxError> {
        let envelope: Envelope = decode_canonical(bytes, MAX_IMPORT_RECEIPT_BYTES)?;
        let body = envelope.body.as_ref().ok_or(MailboxError::Invalid)?;
        super::validate_body(body, IMPORT_TYPE, MAX_VALIDITY_SECONDS)?;
        if envelope.signature.len() != 64 {
            return Err(MailboxError::Invalid);
        }
        let payload = decode_canonical(&body.payload, MAX_IMPORT_RECEIPT_BYTES)?;
        Ok(Self { envelope, payload })
    }

    /// Authenticate against the caller's unlocked owner, never a key taken from the file.
    ///
    /// # Errors
    /// Rejects substitution, expiry, wrong owner/sender, overlong grant/message or binding.
    pub fn verify(
        &self,
        owner: &VerifyingKey,
        now: u64,
    ) -> Result<VerifiedImportReceipt, MailboxError> {
        let body = verify_envelope(
            &self.envelope,
            owner,
            IMPORT_TYPE,
            MAX_VALIDITY_SECONDS,
            now,
        )?;
        let grant = SignedMailboxGrant::decode(&self.payload.grant)?.verify(owner, now)?;
        if self.payload.manifest.len() > super::wire::MAX_MESSAGE_MANIFEST_BYTES {
            return Err(MailboxError::Invalid);
        }
        let signed =
            SignedManifest::decode(&self.payload.manifest).map_err(|_| MailboxError::Invalid)?;
        let checked = signed
            .verify(&super::public_key(grant.sender_key())?, now)
            .map_err(|_| MailboxError::Invalid)?;
        if checked.metadata().content_type != PRIVATE_MESSAGE_CONTENT_TYPE
            || checked.metadata().revision != 1
            || checked.validity().expires > grant.validity().expires
            || body.expires > checked.validity().expires
            || self.payload.plaintext_bytes > MAX_PRIVATE_MESSAGE_BYTES as u64
            || checked.length() > super::wire::MAX_CIPHERTEXT_BYTES as u64
        {
            return Err(MailboxError::Invalid);
        }
        Ok(VerifiedImportReceipt {
            grant,
            message_id: *checked.manifest_id(),
            plaintext_sha256: fixed(&self.payload.plaintext_sha256)?,
            plaintext_bytes: self.payload.plaintext_bytes,
            token_sha256: fixed(&self.payload.confirmation_token_sha256)?,
            expires: body.expires,
        })
    }
}

impl VerifiedImportReceipt {
    /// Unchanged original authority, including exact sender, recipient and provider keys.
    pub const fn grant(&self) -> &VerifiedMailboxGrant {
        &self.grant
    }
    /// Identity of the original signed ciphertext, unchanged across retries or restart.
    pub const fn message_id(&self) -> &[u8; 32] {
        &self.message_id
    }
    /// Digest of the exact bytes handed to the local consumer.
    pub const fn plaintext_sha256(&self) -> &[u8; 32] {
        &self.plaintext_sha256
    }
    /// Length of those local bytes; not a network retention allocation.
    pub const fn plaintext_bytes(&self) -> u64 {
        self.plaintext_bytes
    }
    /// Original hard expiry; consumer confirmation cannot extend retention.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Verify explicit consumer confirmation before initiating any provider ACK.
    ///
    /// The authenticating token digest is compared in constant time.
    /// This does not certify the consumer's database commit or erase remote copies.
    ///
    /// # Errors
    /// Rejects a different confirmation token or imported-byte digest.
    pub fn confirm(
        &self,
        token: &[u8; 32],
        imported_sha256: &[u8; 32],
    ) -> Result<(), MailboxError> {
        let token_hash: [u8; 32] = Sha256::digest(token).into();
        if !bool::from(token_hash.ct_eq(&self.token_sha256))
            || imported_sha256 != &self.plaintext_sha256
        {
            return Err(MailboxError::Unauthorized);
        }
        Ok(())
    }
}
