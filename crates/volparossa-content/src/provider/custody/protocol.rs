use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use super::{CustodyError, CustodyState};
use crate::{
    MAX_MANIFEST_BYTES, SignedManifest, Validity, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
};

const DOMAIN: &[u8] = b"VOLPAROSSA/public-custody/v1\0";
const CHALLENGE: u32 = 1;
const AUTHORIZATION: u32 = 2;
const RECEIPT: u32 = 3;
pub(super) const LIFETIME: u64 = 900;
pub(super) const SMALL_FRAME: usize = 2048;
pub(super) const AUTH_FRAME: usize = MAX_MANIFEST_BYTES + SMALL_FRAME;

/// One publisher-authorized operation consumes one provider connection challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum CustodyOperation {
    /// Transfer and durably register one complete original public publication.
    Deposit = 1,
    /// Inspect its actual complete retained and ready-served state, without uploading.
    Inspect = 2,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Body {
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
pub(super) struct Envelope {
    #[prost(message, optional, tag = "1")]
    body: Option<Body>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct ChallengePayload {
    #[prost(bytes = "vec", tag = "1")]
    random: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct AuthorizationPayload {
    #[prost(bytes = "vec", tag = "1")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
    #[prost(enumeration = "CustodyOperation", tag = "3")]
    operation: i32,
    #[prost(bytes = "vec", tag = "4")]
    manifest: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct ReceiptPayload {
    #[prost(bytes = "vec", tag = "1")]
    request: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    publisher: Vec<u8>,
    #[prost(enumeration = "CustodyOperation", tag = "5")]
    operation: i32,
    #[prost(enumeration = "CustodyState", tag = "6")]
    state: i32,
    #[prost(bytes = "vec", tag = "7")]
    manifest_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    object_sha256: Vec<u8>,
    #[prost(uint64, tag = "9")]
    object_bytes: u64,
    #[prost(uint32, tag = "10")]
    unique_chunks: u32,
    #[prost(uint64, tag = "11")]
    original_expiry: u64,
}

/// Fresh provider-signed connection challenge, independently pinned to the selected provider.
#[derive(Clone, Debug)]
pub struct CustodyChallenge {
    envelope: Envelope,
    provider: [u8; 32],
}

impl CustodyChallenge {
    pub(super) fn new(signer: &SigningKey, now: u64) -> Result<Self, CustodyError> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| CustodyError::Entropy)?;
        let envelope = sign(
            signer,
            CHALLENGE,
            ChallengePayload {
                random: random.to_vec(),
            }
            .encode_to_vec(),
            now,
            now.checked_add(LIFETIME).ok_or(CustodyError::Expired)?,
        )?;
        Ok(Self {
            envelope,
            provider: signer.verifying_key().to_bytes(),
        })
    }
    /// Original canonical signed bytes for local private-key handoff.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }
    /// Verify against a provider key established outside this protocol.
    ///
    /// # Errors
    /// Rejects malformed, stale, wrong-provider or invalidly signed challenges.
    pub fn decode(bytes: &[u8], provider: &[u8; 32], now: u64) -> Result<Self, CustodyError> {
        let envelope = canonical::<Envelope>(bytes, SMALL_FRAME)?;
        let body = verify(&envelope, provider, CHALLENGE, now)?;
        let payload = canonical::<ChallengePayload>(&body.payload, 128)?;
        fixed(&payload.random)?;
        Ok(Self {
            envelope,
            provider: *provider,
        })
    }
    /// Exact already authenticated provider, never an origin or publisher trust root.
    pub const fn provider_key(&self) -> &[u8; 32] {
        &self.provider
    }
    pub(super) fn id(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub(super) fn expires(&self) -> u64 {
        self.envelope.body.as_ref().map_or(0, |b| b.expires)
    }
}

/// Original publisher-signed request, sealed to this provider/challenge/publication/operation.
#[derive(Clone, Debug)]
pub struct CustodyAuthorization {
    envelope: Envelope,
    challenge: [u8; 32],
    provider: [u8; 32],
    operation: CustodyOperation,
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

impl CustodyAuthorization {
    /// Sign explicit custody consent with the original publication's publisher key.
    ///
    /// # Errors
    /// Rejects another publisher, private content, invalid expiry or a stale challenge.
    pub fn sign(
        challenge: &CustodyChallenge,
        operation: CustodyOperation,
        signed: SignedManifest,
        publisher: &SigningKey,
        now: u64,
    ) -> Result<Self, CustodyError> {
        let checked = public_manifest(&signed, now)?;
        if checked.publisher() != publisher.verifying_key().as_bytes() {
            return Err(CustodyError::Unauthorized);
        }
        CustodyChallenge::decode(&challenge.encode(), &challenge.provider, now)?;
        let payload = AuthorizationPayload {
            challenge: challenge.id().to_vec(),
            provider: challenge.provider.to_vec(),
            operation: operation as i32,
            manifest: signed.encode(),
        };
        let expires = challenge.expires().min(checked.validity().expires);
        let envelope = sign(
            publisher,
            AUTHORIZATION,
            payload.encode_to_vec(),
            now,
            expires,
        )?;
        if envelope.encoded_len() > AUTH_FRAME {
            return Err(CustodyError::Invalid);
        }
        Ok(Self {
            envelope,
            challenge: challenge.id(),
            provider: challenge.provider,
            operation,
            signed,
            manifest: checked,
        })
    }
    /// Original canonical public authorization; contains no private keys or filesystem paths.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }
    /// Verify the signed request against the fresh original connection challenge.
    ///
    /// The embedded publisher authenticates its own explicit deposit, not arbitrary content
    /// consumers or a website origin. The backend separately controls storage admission.
    ///
    /// # Errors
    /// Rejects replay/substitution, unsupported fields, private content and original expiry.
    pub fn decode(
        bytes: &[u8],
        challenge: &CustodyChallenge,
        now: u64,
    ) -> Result<Self, CustodyError> {
        CustodyChallenge::decode(&challenge.encode(), &challenge.provider, now)?;
        let envelope = canonical::<Envelope>(bytes, AUTH_FRAME)?;
        let body = envelope.body.as_ref().ok_or(CustodyError::Invalid)?;
        let payload = canonical::<AuthorizationPayload>(&body.payload, AUTH_FRAME)?;
        if payload.challenge.as_slice() != challenge.id()
            || payload.provider.as_slice() != challenge.provider
        {
            return Err(CustodyError::Unauthorized);
        }
        let signed =
            SignedManifest::decode(&payload.manifest).map_err(|_| CustodyError::Invalid)?;
        let manifest = public_manifest(&signed, now)?;
        let checked = verify(&envelope, manifest.publisher(), AUTHORIZATION, now)?;
        if checked.expires > challenge.expires().min(manifest.validity().expires) {
            return Err(CustodyError::Expired);
        }
        let operation =
            CustodyOperation::try_from(payload.operation).map_err(|_| CustodyError::Invalid)?;
        Ok(Self {
            envelope,
            challenge: challenge.id(),
            provider: challenge.provider,
            operation,
            signed,
            manifest,
        })
    }
    /// Exact requested operation.
    pub const fn operation(&self) -> CustodyOperation {
        self.operation
    }
    /// Original signed public publication, not a re-signed transport index.
    pub const fn signed_manifest(&self) -> &SignedManifest {
        &self.signed
    }
    /// The original publisher/ordered chunk layout/hash/lifetime authenticated by the request.
    pub const fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
    pub(super) fn id(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub(super) fn expires(&self) -> u64 {
        self.envelope.body.as_ref().map_or(0, |b| b.expires)
    }
    pub(super) fn check(&self, now: u64) -> Result<(), CustodyError> {
        verify(
            &self.envelope,
            self.manifest.publisher(),
            AUTHORIZATION,
            now,
        )?;
        self.manifest
            .check_time(now)
            .map_err(|_| CustodyError::Expired)
    }
}

/// Provider-signed complete custody observation or explicit absence for one fresh request.
#[derive(Clone, Debug)]
pub struct CustodyReceipt {
    envelope: Envelope,
    payload: ReceiptPayload,
    state: CustodyState,
    provider: [u8; 32],
    manifest_id: [u8; 32],
}

impl CustodyReceipt {
    pub(super) fn new(
        signer: &SigningKey,
        auth: &CustodyAuthorization,
        state: CustodyState,
        now: u64,
    ) -> Result<Self, CustodyError> {
        auth.check(now)?;
        let payload = receipt_payload(auth, state)?;
        let envelope = sign(
            signer,
            RECEIPT,
            payload.encode_to_vec(),
            now,
            auth.expires(),
        )?;
        Self::decode(&envelope.encode_to_vec(), auth, now)
    }
    /// Original canonical signed observation, not a guarantee of future availability.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }
    /// Verify exact request/provider/publication/complete-coverage and original expiry binding.
    ///
    /// # Errors
    /// Rejects stale/substituted receipts or a deposit falsely reported successful when missing.
    pub fn decode(
        bytes: &[u8],
        auth: &CustodyAuthorization,
        now: u64,
    ) -> Result<Self, CustodyError> {
        auth.check(now)?;
        let envelope = canonical::<Envelope>(bytes, SMALL_FRAME)?;
        let body = verify(&envelope, &auth.provider, RECEIPT, now)?;
        if body.expires > auth.expires() {
            return Err(CustodyError::Expired);
        }
        let payload = canonical::<ReceiptPayload>(&body.payload, SMALL_FRAME)?;
        let state = CustodyState::try_from(payload.state).map_err(|_| CustodyError::Invalid)?;
        if payload != receipt_payload(auth, state)? {
            return Err(CustodyError::Unauthorized);
        }
        Ok(Self {
            envelope,
            payload,
            state,
            provider: auth.provider,
            manifest_id: *auth.manifest.manifest_id(),
        })
    }
    /// Current complete/missing state; only `Complete` is a custody statement.
    pub const fn state(&self) -> CustodyState {
        self.state
    }
    /// Independently selected provider that signed this observation.
    pub const fn provider_key(&self) -> &[u8; 32] {
        &self.provider
    }
    /// Exact original signed manifest commits every ordered chunk and its length.
    pub const fn manifest_id(&self) -> &[u8; 32] {
        &self.manifest_id
    }
    /// Original publication expiry. Inspect/deposit retries never renew it.
    pub const fn original_expiry(&self) -> u64 {
        self.payload.original_expiry
    }
    /// Full logical object length (not wire bytes or a partial upload count).
    pub const fn object_bytes(&self) -> u64 {
        self.payload.object_bytes
    }
    /// Complete unique chunk-set size committed by the exact original manifest ID.
    pub const fn unique_chunks(&self) -> u32 {
        self.payload.unique_chunks
    }
}

fn receipt_payload(
    auth: &CustodyAuthorization,
    state: CustodyState,
) -> Result<ReceiptPayload, CustodyError> {
    if auth.operation == CustodyOperation::Deposit && state != CustodyState::Complete {
        return Err(CustodyError::Store);
    }
    let manifest = &auth.manifest;
    let count = manifest
        .chunks()
        .iter()
        .map(|chunk| *chunk.id())
        .collect::<BTreeSet<_>>()
        .len();
    Ok(ReceiptPayload {
        request: auth.id().to_vec(),
        challenge: auth.challenge.to_vec(),
        provider: auth.provider.to_vec(),
        publisher: manifest.publisher().to_vec(),
        operation: auth.operation as i32,
        state: state as i32,
        manifest_id: manifest.manifest_id().to_vec(),
        object_sha256: manifest.object_sha256().to_vec(),
        object_bytes: manifest.length(),
        unique_chunks: u32::try_from(count).map_err(|_| CustodyError::Invalid)?,
        original_expiry: manifest.validity().expires,
    })
}

fn public_manifest(signed: &SignedManifest, now: u64) -> Result<VerifiedManifest, CustodyError> {
    let key = VerifyingKey::from_bytes(&signed.publisher_key_hint())
        .map_err(|_| CustodyError::Invalid)?;
    let manifest = signed
        .verify(&key, now)
        .map_err(|_| CustodyError::Unauthorized)?;
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        return Err(CustodyError::Invalid);
    }
    Ok(manifest)
}

pub(super) fn now() -> Result<u64, CustodyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| CustodyError::Expired)
}

pub(super) fn canonical<M: Message + Default>(
    bytes: &[u8],
    limit: usize,
) -> Result<M, CustodyError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(CustodyError::Invalid);
    }
    let value = M::decode(bytes).map_err(|_| CustodyError::Invalid)?;
    if value.encode_to_vec() != bytes {
        return Err(CustodyError::Invalid);
    }
    Ok(value)
}

fn fixed(bytes: &[u8]) -> Result<[u8; 32], CustodyError> {
    bytes.try_into().map_err(|_| CustodyError::Invalid)
}

fn sign(
    key: &SigningKey,
    message_type: u32,
    payload: Vec<u8>,
    created: u64,
    expires: u64,
) -> Result<Envelope, CustodyError> {
    validity(Validity { created, expires }, created)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| CustodyError::Entropy)?;
    let body = Body {
        version: 1,
        sender: key.verifying_key().to_bytes().to_vec(),
        created,
        expires,
        nonce: nonce.to_vec(),
        message_type,
        payload_hash: Sha256::digest(&payload).to_vec(),
        payload,
    };
    let mut signed = DOMAIN.to_vec();
    signed.extend(body.encode_to_vec());
    Ok(Envelope {
        signature: key.sign(&signed).to_bytes().to_vec(),
        body: Some(body),
    })
}

fn validity(value: Validity, now: u64) -> Result<(), CustodyError> {
    if value.created == 0
        || value.expires <= value.created
        || value.expires - value.created > LIFETIME
        || now < value.created
        || now >= value.expires
    {
        return Err(CustodyError::Expired);
    }
    Ok(())
}

fn verify<'a>(
    envelope: &'a Envelope,
    expected: &[u8; 32],
    message_type: u32,
    now: u64,
) -> Result<&'a Body, CustodyError> {
    let body = envelope.body.as_ref().ok_or(CustodyError::Invalid)?;
    if body.version != 1
        || body.message_type != message_type
        || body.sender.as_slice() != expected
        || body.payload_hash.as_slice() != Sha256::digest(&body.payload).as_slice()
    {
        return Err(CustodyError::Unauthorized);
    }
    fixed(&body.nonce)?;
    validity(
        Validity {
            created: body.created,
            expires: body.expires,
        },
        now,
    )?;
    let signature =
        Signature::from_slice(&envelope.signature).map_err(|_| CustodyError::Invalid)?;
    let key = VerifyingKey::from_bytes(expected).map_err(|_| CustodyError::Invalid)?;
    let mut signed = DOMAIN.to_vec();
    signed.extend(body.encode_to_vec());
    key.verify_strict(&signed, &signature)
        .map_err(|_| CustodyError::Unauthorized)?;
    Ok(body)
}
