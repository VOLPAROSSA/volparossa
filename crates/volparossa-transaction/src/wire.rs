//! Canonical, domain-separated Ed25519 authorization using existing core primitives.
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest as _, Sha256};
use volparossa_protocol::{decode_canonical, encode_canonical};

use crate::{Action, Command, Error, LedgerId, MAX_UNITS, TEST_UNIT};

const DOMAIN: &[u8] = b"volparossa/transaction/test-unit-command/v1\0";
const MAX_BYTES: usize = 4096;
const MAX_LIFETIME: u64 = 3600;

#[derive(Clone, PartialEq, Message)]
struct Body {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(string, tag = "2")]
    unit: String,
    #[prost(bytes = "vec", tag = "3")]
    ledger: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    operation: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    payer: Vec<u8>,
    #[prost(uint32, tag = "6")]
    kind: u32,
    #[prost(bytes = "vec", tag = "7")]
    target: Vec<u8>,
    #[prost(uint64, tag = "8")]
    units: u64,
}

#[derive(Clone, PartialEq, Message)]
struct Envelope {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    sender: Vec<u8>,
    #[prost(uint64, tag = "3")]
    valid_from: u64,
    #[prost(uint64, tag = "4")]
    expires: u64,
    #[prost(bytes = "vec", tag = "5")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    payload_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    signature: Vec<u8>,
}

/// Original signed bytes, not evidence of account enrollment or accepted mutation.
#[derive(Clone, Debug)]
pub struct SignedCommand(Vec<u8>);

impl SignedCommand {
    /// Sign exact TEST-unit terms using a separately supplied financial test key.
    /// No key is fetched, persisted or inferred from network identity.
    /// Validity uses a caller-supplied seconds timebase and lasts at most one hour.
    ///
    /// # Errors
    /// Rejects invalid identifiers, payer/key mismatch, bounds or validity interval.
    pub fn sign(
        ledger: LedgerId,
        key: &SigningKey,
        command: Command,
        valid_from: u64,
        expires: u64,
        nonce: [u8; 32],
    ) -> Result<Self, Error> {
        let (kind, target, units) = match command.action {
            Action::Reserve { recipient, units } => (1, recipient, units),
            Action::Commit { reservation_id } => (2, reservation_id, 0),
            Action::Cancel { reservation_id } => (3, reservation_id, 0),
        };
        let body = Body {
            version: 1,
            unit: TEST_UNIT.to_owned(),
            ledger: ledger.to_vec(),
            operation: command.operation_id.to_vec(),
            payer: command.payer.to_vec(),
            kind,
            target: target.to_vec(),
            units,
        };
        let payload = encode_canonical(&body, MAX_BYTES).map_err(|_| Error::Invalid)?;
        let mut envelope = Envelope {
            version: 1,
            sender: key.verifying_key().to_bytes().to_vec(),
            valid_from,
            expires,
            nonce: nonce.to_vec(),
            payload_hash: Sha256::digest(&payload).to_vec(),
            payload,
            signature: Vec::new(),
        };
        envelope.signature = key.sign(&signing_bytes(&envelope)?).to_bytes().to_vec();
        let bytes = encode_canonical(&envelope, MAX_BYTES).map_err(|_| Error::Invalid)?;
        verify(&bytes, ledger)?;
        Ok(Self(bytes))
    }

    /// Exact original canonical envelope, unchanged across retries.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }
}

pub(super) struct Verified {
    pub command: Command,
    pub nonce: [u8; 32],
    pub valid_from: u64,
    pub expires: u64,
}

fn signing_bytes(value: &Envelope) -> Result<Vec<u8>, Error> {
    let mut unsigned = value.clone();
    unsigned.signature.clear();
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(encode_canonical(&unsigned, MAX_BYTES).map_err(|_| Error::Invalid)?);
    Ok(bytes)
}

fn identifier(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| Error::Invalid)?;
    if value == [0; 32] {
        return Err(Error::Invalid);
    }
    Ok(value)
}

pub(super) fn verify(bytes: &[u8], ledger: LedgerId) -> Result<Verified, Error> {
    let envelope: Envelope = decode_canonical(bytes, MAX_BYTES).map_err(|_| Error::Invalid)?;
    let body: Body = decode_canonical(&envelope.payload, MAX_BYTES).map_err(|_| Error::Invalid)?;
    if envelope.version != 1
        || body.version != 1
        || body.unit != TEST_UNIT
        || envelope
            .expires
            .checked_sub(envelope.valid_from)
            .is_none_or(|n| n == 0 || n > MAX_LIFETIME)
        || envelope.expires > MAX_UNITS
        || envelope.payload_hash != Sha256::digest(&envelope.payload).as_slice()
    {
        return Err(Error::Invalid);
    }
    if identifier(&body.ledger)? != ledger {
        return Err(Error::WrongLedger);
    }
    let payer = identifier(&body.payer)?;
    if envelope.sender != payer {
        return Err(Error::Unauthorized);
    }
    let sender = VerifyingKey::from_bytes(&payer).map_err(|_| Error::Unauthorized)?;
    let signature = Signature::from_slice(&envelope.signature).map_err(|_| Error::Unauthorized)?;
    sender
        .verify_strict(&signing_bytes(&envelope)?, &signature)
        .map_err(|_| Error::Unauthorized)?;
    let target = identifier(&body.target)?;
    let action = match body.kind {
        1 if body.units > 0 && body.units <= MAX_UNITS && target != payer => Action::Reserve {
            recipient: target,
            units: body.units,
        },
        2 if body.units == 0 => Action::Commit {
            reservation_id: target,
        },
        3 if body.units == 0 => Action::Cancel {
            reservation_id: target,
        },
        _ => return Err(Error::Invalid),
    };
    Ok(Verified {
        command: Command {
            operation_id: identifier(&body.operation)?,
            payer,
            action,
        },
        nonce: identifier(&envelope.nonce)?,
        valid_from: envelope.valid_from,
        expires: envelope.expires,
    })
}

#[cfg(test)]
pub(super) fn mutate_and_resign(bytes: &[u8], key: &SigningKey, mutation: &str) -> Vec<u8> {
    let mut envelope: Envelope = Envelope::decode(bytes).unwrap();
    let mut body: Body = Body::decode(envelope.payload.as_slice()).unwrap();
    match mutation {
        "wrong-payer" => envelope.sender = key.verifying_key().to_bytes().to_vec(),
        "version" => body.version = 2,
        "real-asset" => body.unit = "EUR".into(),
        "amount" => body.units += 1,
        _ => panic!("unknown synthetic mutation"),
    }
    envelope.payload = body.encode_to_vec();
    envelope.payload_hash = Sha256::digest(&envelope.payload).to_vec();
    envelope.signature = key
        .sign(&signing_bytes(&envelope).unwrap())
        .to_bytes()
        .to_vec();
    envelope.encode_to_vec()
}
