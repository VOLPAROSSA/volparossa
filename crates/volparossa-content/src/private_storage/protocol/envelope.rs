use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest as _, Sha256};

use super::ProtocolError;
use crate::Validity;

const DOMAIN: &[u8] = b"VOLPAROSSA/private-storage/v1\0";
pub(super) const GRANT: u32 = 1;
pub(super) const CHALLENGE: u32 = 2;
pub(super) const REQUEST: u32 = 3;
pub(super) const RECEIPT: u32 = 4;

#[derive(Clone, PartialEq, Message)]
pub(super) struct Body {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub sender: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub created: u64,
    #[prost(uint64, tag = "4")]
    pub expires: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub nonce: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub message_type: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub payload_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Envelope {
    #[prost(message, optional, tag = "1")]
    pub body: Option<Body>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

pub(super) fn decode<M: Message + Default>(
    bytes: &[u8],
    maximum: usize,
) -> Result<M, ProtocolError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ProtocolError::Invalid);
    }
    let value = M::decode(bytes).map_err(|_| ProtocolError::Invalid)?;
    if value.encode_to_vec() != bytes {
        return Err(ProtocolError::Invalid);
    }
    Ok(value)
}

pub(super) fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError::Invalid)
}

pub(super) fn identifier<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    let value = fixed(bytes)?;
    if value == [0; N] {
        return Err(ProtocolError::Invalid);
    }
    Ok(value)
}

pub(super) fn key(bytes: &[u8]) -> Result<VerifyingKey, ProtocolError> {
    let value = VerifyingKey::from_bytes(&fixed(bytes)?).map_err(|_| ProtocolError::Invalid)?;
    if value.is_weak() {
        return Err(ProtocolError::Invalid);
    }
    Ok(value)
}

pub(super) fn random_id() -> Result<[u8; 32], ProtocolError> {
    let mut value = [0; 32];
    getrandom::fill(&mut value).map_err(|_| ProtocolError::Entropy)?;
    identifier(&value)
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(super) fn validity(body: &Body) -> Validity {
    Validity {
        created: body.created,
        expires: body.expires,
    }
}

pub(super) fn body(
    envelope: &Envelope,
    kind: u32,
    max_lifetime: u64,
) -> Result<&Body, ProtocolError> {
    let body = envelope.body.as_ref().ok_or(ProtocolError::Invalid)?;
    key(&body.sender)?;
    identifier::<32>(&body.nonce)?;
    if envelope.signature.len() != 64
        || body.version != 1
        || body.message_type != kind
        || body.created == 0
        || body.expires <= body.created
        || body.expires > i64::MAX as u64
        || body.expires - body.created > max_lifetime
        || body.payload_hash.as_slice() != digest(&body.payload)
    {
        return Err(ProtocolError::Invalid);
    }
    Ok(body)
}

fn signing_bytes(body: &Body) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&body.encode_to_vec());
    bytes
}

pub(super) fn sign(
    signer: &SigningKey,
    kind: u32,
    payload: Vec<u8>,
    validity: Validity,
    max_lifetime: u64,
) -> Result<Envelope, ProtocolError> {
    let body = Body {
        version: 1,
        sender: signer.verifying_key().to_bytes().to_vec(),
        created: validity.created,
        expires: validity.expires,
        nonce: random_id()?.to_vec(),
        message_type: kind,
        payload_hash: digest(&payload).to_vec(),
        payload,
    };
    let signature = signer.sign(&signing_bytes(&body)).to_bytes().to_vec();
    let envelope = Envelope {
        body: Some(body),
        signature,
    };
    self::body(&envelope, kind, max_lifetime)?;
    Ok(envelope)
}

pub(super) fn verify<'a>(
    envelope: &'a Envelope,
    trusted: &VerifyingKey,
    kind: u32,
    max_lifetime: u64,
    now: u64,
) -> Result<&'a Body, ProtocolError> {
    let body = body(envelope, kind, max_lifetime)?;
    if body.sender.as_slice() != trusted.as_bytes() {
        return Err(ProtocolError::Unauthorized);
    }
    if now < body.created || now >= body.expires {
        return Err(ProtocolError::Expired);
    }
    let signature =
        Signature::from_slice(&envelope.signature).map_err(|_| ProtocolError::Invalid)?;
    trusted
        .verify_strict(&signing_bytes(body), &signature)
        .map_err(|_| ProtocolError::Unauthorized)?;
    Ok(body)
}

pub(super) fn within(child: Validity, parent: Validity) -> Result<(), ProtocolError> {
    if child.created < parent.created || child.expires > parent.expires {
        return Err(ProtocolError::Unauthorized);
    }
    Ok(())
}
