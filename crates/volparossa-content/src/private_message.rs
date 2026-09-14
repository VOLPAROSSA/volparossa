//! Recipient-encrypted native publications, using the existing RFC 9180 HPKE profile.
//!
//! The caller independently authenticates the recipient's X25519 encryption key and the
//! sender's Ed25519 signing key. Neither key discovery nor a mailbox is implemented here.
//! HPKE base mode encrypts to the recipient; the verified native manifest authenticates
//! the sender. Public metadata exposes the sender, opaque name, lifetime and message size,
//! but not a subject or recipient identifier. This is not HTTPS-origin authentication,
//! forward secrecy after recipient-key compromise, a ratchet, or duplicate-delivery control.

use ed25519_dalek::SigningKey;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use prost::Message;
use rand_chacha_10::{ChaCha20Rng, rand_core::SeedableRng};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{ChunkStore, Metadata, Publication, SignedManifest, Validity, VerifiedManifest};

type MessageKem = X25519HkdfSha256;
type MessageKdf = HkdfSha256;
type MessageAead = ChaCha20Poly1305;

const VERSION: u32 = 1;
const INFO: &[u8] = b"volparossa/private-native-message/rfc9180/v1";
const KEY_BYTES: usize = 32;
const IDENTITY_KEY_DOMAIN: &[u8] = b"volparossa/message-recipient/v1\0";
const TAG_BYTES: usize = 16;
const MAX_ENVELOPE_BYTES: usize = MAX_PRIVATE_MESSAGE_BYTES + 64;

/// Bounded in-memory plaintext size: 4 MiB. Ciphertext adds fewer than 64 bytes.
pub const MAX_PRIVATE_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// The only public content type accepted by this private-message format.
pub const PRIVATE_MESSAGE_CONTENT_TYPE: &str = "application/vnd.volparossa.private-message.v1";

/// Explicit recipient encryption key, separate from an Ed25519 signing key.
///
/// The private key is zeroized on drop and is never persisted by this module. Provisioning
/// and securely retaining it across application restarts are the caller's responsibility.
pub struct RecipientKeyPair {
    private_key: Zeroizing<[u8; KEY_BYTES]>,
    public_key: [u8; KEY_BYTES],
}

impl RecipientKeyPair {
    /// Reproduce a recipient key from an unlocked, securely generated node identity.
    ///
    /// This application profile supplies `"volparossa/message-recipient/v1\0" || seed`
    /// to the existing DHKEM `DeriveKeyPair` implementation from RFC 9180 section 7.1.3.
    /// It is not an Ed25519-to-X25519 key conversion. The fixed domain separates this use
    /// from signing and other derivations. Only the existing encrypted identity needs
    /// persistence; changing its passphrase preserves this key, rotating it does not.
    /// Compromise of that identity also compromises messages encrypted to this key;
    /// this profile provides neither forward secrecy nor recipient-key discovery.
    ///
    /// # Errors
    /// Returns an error if HPKE rejects the derived private-key serialization.
    pub fn from_node_identity(identity: &SigningKey) -> Result<Self, PrivateMessageError> {
        let mut ikm = Zeroizing::new([0; IDENTITY_KEY_DOMAIN.len() + KEY_BYTES]);
        ikm[..IDENTITY_KEY_DOMAIN.len()].copy_from_slice(IDENTITY_KEY_DOMAIN);
        ikm[IDENTITY_KEY_DOMAIN.len()..].copy_from_slice(identity.as_bytes());
        let (secret, _) = MessageKem::derive_keypair(ikm.as_slice());
        let mut serialized = secret.to_bytes();
        let mut private_key = Zeroizing::new([0; KEY_BYTES]);
        private_key.copy_from_slice(serialized.as_slice());
        serialized.as_mut_slice().zeroize();
        Self::from_private_key(private_key)
    }

    /// Generate a fresh DHKEM(X25519, HKDF-SHA256) recipient keypair.
    ///
    /// # Errors
    /// Returns an error if fresh operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, PrivateMessageError> {
        let mut rng = fresh_rng()?;
        let (secret, _) = MessageKem::gen_keypair_with_rng(&mut rng);
        let mut serialized = secret.to_bytes();
        let mut private_key = Zeroizing::new([0; KEY_BYTES]);
        private_key.copy_from_slice(serialized.as_slice());
        serialized.as_mut_slice().zeroize();
        Self::from_private_key(private_key)
    }

    /// Import an explicitly provisioned, secret X25519 private key into memory.
    ///
    /// This does not authenticate its public-key association with a user, derive it from
    /// another identity, or read/write a key file. Callers must supply securely generated
    /// key material; this import cannot establish its entropy or provenance.
    ///
    /// # Errors
    /// Returns an error if HPKE rejects the serialized private key.
    pub fn from_private_key(
        private_key: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Result<Self, PrivateMessageError> {
        let secret = <MessageKem as KemTrait>::PrivateKey::from_bytes(&*private_key)
            .map_err(|_| PrivateMessageError::InvalidKey)?;
        let public = MessageKem::sk_to_pk(&secret).to_bytes();
        let public_key = public
            .as_slice()
            .try_into()
            .map_err(|_| PrivateMessageError::InvalidKey)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Public encryption key which the sender must authenticate independently.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; KEY_BYTES] {
        &self.public_key
    }
}

/// Encrypt a bounded message before publishing any bytes to a native content cache.
///
/// `recipient_public_key` must already be authenticated by the caller, independently of
/// the storage peers. A fresh HPKE encapsulation and an opaque 32-byte random name are used
/// for each publication. No plaintext, subject, recipient identifier or private key is
/// written to the cache; only the ciphertext envelope is passed to [`crate::publish`].
/// The caller retains responsibility for the original plaintext buffer and signing key.
///
/// # Errors
/// Rejects plaintext above 4 MiB, invalid keys/validity, failed HPKE/randomness, and cache
/// quota or filesystem failures. A cache failure may leave only encrypted orphan chunks.
pub fn publish_private_message(
    plaintext: &[u8],
    recipient_public_key: &[u8; KEY_BYTES],
    sender: &SigningKey,
    validity: Validity,
    store: &mut ChunkStore,
) -> Result<SignedManifest, PrivateMessageError> {
    if plaintext.len() > MAX_PRIVATE_MESSAGE_BYTES {
        return Err(PrivateMessageError::TooLarge);
    }
    let mut name = [0; KEY_BYTES];
    getrandom::fill(&mut name).map_err(|_| PrivateMessageError::Random)?;
    let length = envelope_length(plaintext.len() + TAG_BYTES);
    let publication = Publication {
        metadata: Metadata {
            name: hex::encode(name),
            revision: 1,
            content_type: PRIVATE_MESSAGE_CONTENT_TYPE.into(),
        },
        length: length as u64,
        validity,
    };
    publication.validate()?;
    store.require_object_capacity(publication.length)?;
    let public_key = <MessageKem as KemTrait>::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| PrivateMessageError::InvalidKey)?;
    let aad = associated_data(&sender.verifying_key().to_bytes(), &publication);
    let mut rng = fresh_rng()?;
    let (encapsulated_key, ciphertext) =
        single_shot_seal_with_rng::<MessageAead, MessageKdf, MessageKem>(
            &OpModeS::Base,
            &public_key,
            INFO,
            plaintext,
            &aad,
            &mut rng,
        )
        .map_err(|_| PrivateMessageError::Seal)?;
    let envelope = Envelope {
        version: VERSION,
        encapsulated_key: encapsulated_key.to_bytes().to_vec(),
        ciphertext,
    }
    .encode_to_vec();
    if envelope.len() != length {
        return Err(PrivateMessageError::InvalidEnvelope);
    }
    Ok(crate::publish(
        &mut envelope.as_slice(),
        publication,
        sender,
        store,
    )?)
}

/// Reconstruct all authenticated ciphertext, then decrypt only for the intended recipient.
///
/// The caller must first obtain `manifest` via [`SignedManifest::verify`] against its
/// independently trusted sender key. All ordered chunk lengths/hashes and the full object
/// hash are verified before HPKE decryption. Only bounded ciphertext is buffered during
/// reconstruction; plaintext is returned in zeroizing memory, never written to a store.
/// `now_unix_seconds` is trusted caller time at the start of the operation. Reopening the
/// same still-valid message is allowed; this is not mailbox replay/ratchet handling.
///
/// # Errors
/// Rejects expiry, malformed/noncanonical envelopes, wrong recipients, modified associated
/// metadata/ciphertext, missing/corrupt chunks, or oversized messages before allocating them.
pub fn open_private_message(
    manifest: &VerifiedManifest,
    stores: &mut [&mut ChunkStore],
    now_unix_seconds: u64,
    recipient: &RecipientKeyPair,
) -> Result<Zeroizing<Vec<u8>>, PrivateMessageError> {
    let envelope = verified_envelope(manifest, stores, now_unix_seconds)?;
    let secret = <MessageKem as KemTrait>::PrivateKey::from_bytes(&*recipient.private_key)
        .map_err(|_| PrivateMessageError::InvalidKey)?;
    let encapsulated_key =
        <MessageKem as KemTrait>::EncappedKey::from_bytes(&envelope.encapsulated_key)
            .map_err(|_| PrivateMessageError::InvalidKey)?;
    let aad = associated_data(
        manifest.publisher(),
        &Publication {
            metadata: manifest.metadata().clone(),
            length: manifest.length(),
            validity: manifest.validity(),
        },
    );
    let plaintext = single_shot_open::<MessageAead, MessageKdf, MessageKem>(
        &OpModeR::Base,
        &secret,
        &encapsulated_key,
        INFO,
        &envelope.ciphertext,
        &aad,
    )
    .map_err(|_| PrivateMessageError::Open)?;
    Ok(Zeroizing::new(plaintext))
}

/// Verify the full signed object's hashes and bounded canonical private-message envelope.
///
/// No recipient key is read and no bytes are decrypted. This checks the supported ciphertext
/// format, not that a malicious publisher truly encrypted its input or which recipient it chose.
/// The caller must independently authenticate the manifest's sender before calling this method.
///
/// # Errors
/// Rejects expired manifests, unsupported metadata, missing/corrupt chunks, or malformed envelopes.
pub fn validate_private_message_envelope(
    manifest: &VerifiedManifest,
    stores: &mut [&mut ChunkStore],
    now_unix_seconds: u64,
) -> Result<(), PrivateMessageError> {
    verified_envelope(manifest, stores, now_unix_seconds).map(|_| ())
}

fn verified_envelope(
    manifest: &VerifiedManifest,
    stores: &mut [&mut ChunkStore],
    now_unix_seconds: u64,
) -> Result<Envelope, PrivateMessageError> {
    manifest.check_time(now_unix_seconds)?;
    let metadata = manifest.metadata();
    if metadata.content_type != PRIVATE_MESSAGE_CONTENT_TYPE
        || metadata.revision != 1
        || metadata.name.len() != KEY_BYTES * 2
        || !metadata
            .name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || manifest.length() < envelope_length(TAG_BYTES) as u64
    {
        return Err(PrivateMessageError::InvalidEnvelope);
    }
    if manifest.length() > MAX_ENVELOPE_BYTES as u64 {
        return Err(PrivateMessageError::TooLarge);
    }
    let length = usize::try_from(manifest.length()).map_err(|_| PrivateMessageError::TooLarge)?;
    let mut wire = Vec::with_capacity(length);
    crate::reassemble(manifest, stores, now_unix_seconds, &mut wire)?;
    let envelope =
        Envelope::decode(wire.as_slice()).map_err(|_| PrivateMessageError::InvalidEnvelope)?;
    if envelope.version != VERSION
        || envelope.encapsulated_key.len() != KEY_BYTES
        || envelope.ciphertext.len() < TAG_BYTES
        || envelope.ciphertext.len() > MAX_PRIVATE_MESSAGE_BYTES + TAG_BYTES
        || envelope.encode_to_vec() != wire
    {
        return Err(PrivateMessageError::InvalidEnvelope);
    }
    Ok(envelope)
}

// For version 1: version tag/value (2), encapsulated-key tag/length/key (34),
// ciphertext tag (1), ciphertext length varint, and the ciphertext itself.
fn envelope_length(ciphertext_length: usize) -> usize {
    37 + prost::encoding::encoded_len_varint(ciphertext_length as u64) + ciphertext_length
}

fn associated_data(sender: &[u8; KEY_BYTES], publication: &Publication) -> Vec<u8> {
    AssociatedData {
        version: VERSION,
        sender: sender.to_vec(),
        name: publication.metadata.name.clone(),
        revision: publication.metadata.revision,
        content_type: publication.metadata.content_type.clone(),
        created: publication.validity.created,
        expires: publication.validity.expires,
        envelope_length: publication.length,
    }
    .encode_to_vec()
}

fn fresh_rng() -> Result<ChaCha20Rng, PrivateMessageError> {
    let mut seed = Zeroizing::new([0; KEY_BYTES]);
    getrandom::fill(&mut *seed).map_err(|_| PrivateMessageError::Random)?;
    let rng = ChaCha20Rng::from_seed(*seed);
    seed.zeroize();
    Ok(rng)
}

#[derive(Clone, PartialEq, Message)]
struct Envelope {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    encapsulated_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct AssociatedData {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    sender: Vec<u8>,
    #[prost(string, tag = "3")]
    name: String,
    #[prost(uint64, tag = "4")]
    revision: u64,
    #[prost(string, tag = "5")]
    content_type: String,
    #[prost(uint64, tag = "6")]
    created: u64,
    #[prost(uint64, tag = "7")]
    expires: u64,
    #[prost(uint64, tag = "8")]
    envelope_length: u64,
}

/// Explicit errors from encryption, sender-authenticated reconstruction and decryption.
#[derive(Debug, thiserror::Error)]
pub enum PrivateMessageError {
    /// The existing manifest or chunk-store layer rejected the operation.
    #[error(transparent)]
    Content(#[from] crate::Error),
    /// The private-message profile supports at most 4 MiB plaintext.
    #[error("private native message exceeds its size limit")]
    TooLarge,
    /// The envelope or its public metadata is not the canonical supported format.
    #[error("invalid private native message envelope")]
    InvalidEnvelope,
    /// HPKE could not decode key material for the fixed suite.
    #[error("invalid private native message encryption key")]
    InvalidKey,
    /// Operating-system CSPRNG seed/name generation failed.
    #[error("private native message secure randomness unavailable")]
    Random,
    /// HPKE refused to encrypt for this recipient key.
    #[error("private native message encryption failed")]
    Seal,
    /// Wrong recipient, altered ciphertext or altered associated publication metadata.
    #[error("private native message authentication/decryption failed")]
    Open,
}
