use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ComputeError, EXCHANGE_SECONDS, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};

const DOMAIN: &[u8] = b"VOLPAROSSA/compute-control/v1\0";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum Kind {
    Challenge = 1,
    Request = 2,
    Reply = 3,
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
    kind: u32,
    #[prost(bytes = "vec", tag = "7")]
    payload_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    request_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    challenge_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct Envelope {
    #[prost(message, tag = "1")]
    body: Option<Body>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

pub(super) struct Record {
    body: Body,
    signature: [u8; 64],
    sender: [u8; 32],
}

impl Record {
    pub(super) fn challenge(key: &SigningKey, now: u64) -> Result<Self, ComputeError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| ComputeError::Entropy)?;
        let expires = now
            .checked_add(EXCHANGE_SECONDS)
            .ok_or(ComputeError::Expired)?;
        Self::sign(
            key,
            Kind::Challenge,
            nonce.to_vec(),
            now,
            expires,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    pub(super) fn request(
        key: &SigningKey,
        challenge: &Self,
        payload: Vec<u8>,
        now: u64,
    ) -> Result<Self, ComputeError> {
        challenge.check(Kind::Challenge, now)?;
        Self::sign(
            key,
            Kind::Request,
            challenge.body.nonce.clone(),
            now,
            challenge.body.expires,
            payload,
            Vec::new(),
            Sha256::digest(challenge.encode()).to_vec(),
        )
    }

    pub(super) fn reply(
        key: &SigningKey,
        challenge: &Self,
        request_hash: [u8; 32],
        payload: Vec<u8>,
        now: u64,
    ) -> Result<Self, ComputeError> {
        challenge.check(Kind::Challenge, now)?;
        Self::sign(
            key,
            Kind::Reply,
            challenge.body.nonce.clone(),
            now,
            challenge.body.expires,
            payload,
            request_hash.to_vec(),
            Sha256::digest(challenge.encode()).to_vec(),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Complete domain-separated signed record fields"
    )]
    fn sign(
        key: &SigningKey,
        kind: Kind,
        nonce: Vec<u8>,
        created: u64,
        expires: u64,
        payload: Vec<u8>,
        request_hash: Vec<u8>,
        challenge_hash: Vec<u8>,
    ) -> Result<Self, ComputeError> {
        let sender = key.verifying_key().to_bytes();
        let body = Body {
            version: 1,
            sender: sender.to_vec(),
            created,
            expires,
            nonce,
            kind: kind as u32,
            payload_hash: Sha256::digest(&payload).to_vec(),
            payload,
            request_hash,
            challenge_hash,
        };
        let signature = key.sign(&signing_bytes(&body)).to_bytes();
        let record = Self {
            body,
            signature,
            sender,
        };
        record.check(kind, created)?;
        Ok(record)
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        Envelope {
            body: Some(self.body.clone()),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }

    pub(super) fn decode(bytes: &[u8], kind: Kind, now: u64) -> Result<Self, ComputeError> {
        Self::decode_at(bytes, kind, Some(now))
    }

    /// Check an original signature and its internally bounded signed validity.
    /// No wall-clock freshness or current authorization follows from this check.
    pub(super) fn decode_historical(bytes: &[u8], kind: Kind) -> Result<Self, ComputeError> {
        Self::decode_at(bytes, kind, None)
    }

    fn decode_at(bytes: &[u8], kind: Kind, now: Option<u64>) -> Result<Self, ComputeError> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES + super::FRAME_OVERHEAD {
            return Err(ComputeError::Invalid);
        }
        let envelope = Envelope::decode(bytes).map_err(|_| ComputeError::Invalid)?;
        if envelope.encode_to_vec() != bytes {
            return Err(ComputeError::Invalid);
        }
        let body = envelope.body.ok_or(ComputeError::Invalid)?;
        let sender = body
            .sender
            .as_slice()
            .try_into()
            .map_err(|_| ComputeError::Invalid)?;
        let signature = envelope
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ComputeError::Invalid)?;
        let result = Self {
            body,
            signature,
            sender,
        };
        result.check(kind, now.unwrap_or(result.body.created))?;
        VerifyingKey::from_bytes(&sender)
            .map_err(|_| ComputeError::Authentication)?
            .verify_strict(
                &signing_bytes(&result.body),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ComputeError::Authentication)?;
        Ok(result)
    }

    fn check(&self, kind: Kind, now: u64) -> Result<(), ComputeError> {
        let b = &self.body;
        if b.version != 1
            || b.kind != kind as u32
            || b.sender.len() != 32
            || b.nonce.len() != 32
            || b.payload_hash.as_slice() != Sha256::digest(&b.payload).as_slice()
        {
            return Err(ComputeError::Invalid);
        }
        let payload_valid = match kind {
            Kind::Challenge => {
                b.payload.is_empty() && b.request_hash.is_empty() && b.challenge_hash.is_empty()
            }
            Kind::Request => {
                !b.payload.is_empty()
                    && b.payload.len() <= MAX_REQUEST_BYTES
                    && b.request_hash.is_empty()
                    && b.challenge_hash.len() == 32
            }
            Kind::Reply => {
                !b.payload.is_empty()
                    && b.payload.len() <= MAX_RESPONSE_BYTES
                    && b.request_hash.len() == 32
                    && b.challenge_hash.len() == 32
            }
        };
        if !payload_valid {
            return Err(ComputeError::Invalid);
        }
        if b.created == 0
            || b.expires <= b.created
            || b.expires - b.created > EXCHANGE_SECONDS
            || now < b.created
            || now >= b.expires
        {
            return Err(ComputeError::Expired);
        }
        Ok(())
    }

    pub(super) fn matches_challenge(&self, challenge: &Self) -> Result<(), ComputeError> {
        if self.body.nonce != challenge.body.nonce
            || self.body.expires != challenge.body.expires
            || self.body.created < challenge.body.created
            || self.body.challenge_hash.as_slice() != Sha256::digest(challenge.encode()).as_slice()
        {
            return Err(ComputeError::Authentication);
        }
        Ok(())
    }
    pub(super) const fn sender(&self) -> [u8; 32] {
        self.sender
    }
    pub(super) fn payload(&self) -> &[u8] {
        &self.body.payload
    }
    pub(super) fn request_hash(&self) -> &[u8] {
        &self.body.request_hash
    }
    pub(super) const fn created(&self) -> u64 {
        self.body.created
    }
    pub(super) const fn expires(&self) -> u64 {
        self.body.expires
    }
}

fn signing_bytes(body: &Body) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&body.encode_to_vec());
    bytes
}

#[test]
fn copied_nonce_signed_by_another_provider_cannot_forward_client_authorization() {
    let destination = SigningKey::from_bytes(&[1; 32]);
    let intermediary = SigningKey::from_bytes(&[2; 32]);
    let client = SigningKey::from_bytes(&[3; 32]);
    let original = Record::challenge(&destination, 100).unwrap();
    // A malicious endpoint can copy nonce/time fields into its own signed challenge.
    let mut forwarded = Record::challenge(&intermediary, 100).unwrap();
    forwarded.body.nonce.clone_from(&original.body.nonce);
    forwarded.signature = intermediary
        .sign(&signing_bytes(&forwarded.body))
        .to_bytes();
    let verified = Record::decode(&forwarded.encode(), Kind::Challenge, 101).unwrap();
    let request = Record::request(&client, &verified, b"submit".to_vec(), 101).unwrap();
    assert!(request.matches_challenge(&verified).is_ok());
    assert!(matches!(
        request.matches_challenge(&original),
        Err(ComputeError::Authentication)
    ));
}

pub(super) fn now() -> Result<u64, ComputeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| ComputeError::Expired)
}

pub(super) async fn read<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> Result<Vec<u8>, ComputeError> {
    let size = usize::try_from(stream.read_u32().await?).map_err(|_| ComputeError::Invalid)?;
    if size == 0 || size > maximum {
        return Err(ComputeError::Invalid);
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(super) async fn write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ComputeError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ComputeError::Invalid);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| ComputeError::Invalid)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
