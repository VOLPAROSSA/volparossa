//! Private canonical PUBLIC-fixture wire profile; not a generic signing service.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest as _, Sha256};

use super::{GrantBackend, GrantError, GrantLimits, GrantModel, GrantSpec, MAX_GRANT_BYTES};

const DOMAIN: &[u8] = b"VOLPAROSSA/resident-public-fixture-task/v1\0";
const PUBLIC_FIXTURE: u32 = 1;

#[derive(Clone, PartialEq, Message)]
pub(super) struct Payload {
    #[prost(bytes = "vec", tag = "1")]
    pub(super) guest_tls_spki_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) workload_sha256: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub(super) model: u32,
    #[prost(uint32, tag = "4")]
    pub(super) backend: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub(super) tls_exporter: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub(super) maximum_requests: u32,
    #[prost(uint32, tag = "7")]
    pub(super) maximum_turn_seconds: u32,
    #[prost(uint32, tag = "8")]
    pub(super) threads: u32,
    #[prost(bytes = "vec", repeated, tag = "9")]
    pub(super) public_input_sha256: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Body {
    #[prost(uint32, tag = "1")]
    pub(super) version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) requester_key: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub(super) issued_at_ms: u64,
    #[prost(uint64, tag = "4")]
    pub(super) expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub(super) nonce: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub(super) kind: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub(super) payload_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Envelope {
    #[prost(message, optional, tag = "1")]
    pub(super) body: Option<Body>,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) signature: Vec<u8>,
}

fn signing_bytes(body: &Body) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    body.encode(&mut bytes)
        .expect("bounded protobuf encoding into a vector cannot fail");
    bytes
}

pub(super) fn sign(key: &SigningKey, spec: &GrantSpec) -> Result<Vec<u8>, GrantError> {
    let payload = Payload {
        guest_tls_spki_sha256: spec.guest_tls_spki_sha256.to_vec(),
        workload_sha256: spec.workload_sha256.to_vec(),
        model: match spec.model {
            GrantModel::Qwen3FourBInstruct2507 => 1,
        },
        backend: match spec.backend {
            GrantBackend::LlamaCppBf16V1 => 1,
        },
        tls_exporter: spec.tls_exporter.to_vec(),
        maximum_requests: u32::from(spec.limits.maximum_requests),
        maximum_turn_seconds: u32::from(spec.limits.maximum_turn_seconds),
        threads: u32::from(spec.limits.threads),
        public_input_sha256: spec
            .public_input_sha256
            .iter()
            .map(|hash| hash.to_vec())
            .collect(),
    }
    .encode_to_vec();
    let body = Body {
        version: 1,
        requester_key: spec.requester_key.to_vec(),
        issued_at_ms: spec.issued_at_ms,
        expires_at_ms: spec.expires_at_ms,
        nonce: spec.nonce.to_vec(),
        kind: PUBLIC_FIXTURE,
        payload_sha256: Sha256::digest(&payload).to_vec(),
        payload,
    };
    let signature = key.sign(&signing_bytes(&body)).to_bytes().to_vec();
    let bytes = Envelope {
        body: Some(body),
        signature,
    }
    .encode_to_vec();
    if bytes.len() > MAX_GRANT_BYTES {
        return Err(GrantError::Invalid);
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<GrantSpec, GrantError> {
    if bytes.is_empty() || bytes.len() > MAX_GRANT_BYTES {
        return Err(GrantError::Invalid);
    }
    let envelope = Envelope::decode(bytes).map_err(|_| GrantError::Invalid)?;
    if envelope.encode_to_vec() != bytes {
        return Err(GrantError::Invalid);
    }
    let body = envelope.body.ok_or(GrantError::Invalid)?;
    if body.version != 1
        || body.kind != PUBLIC_FIXTURE
        || body.payload_sha256.as_slice() != Sha256::digest(&body.payload).as_slice()
    {
        return Err(GrantError::Invalid);
    }
    let requester_key = array(&body.requester_key)?;
    let signature = Signature::from_slice(&envelope.signature).map_err(|_| GrantError::Invalid)?;
    VerifyingKey::from_bytes(&requester_key)
        .map_err(|_| GrantError::Authentication)?
        .verify_strict(&signing_bytes(&body), &signature)
        .map_err(|_| GrantError::Authentication)?;
    let payload = Payload::decode(body.payload.as_slice()).map_err(|_| GrantError::Invalid)?;
    if payload.encode_to_vec() != body.payload
        || payload.model != 1
        || payload.backend != 1
        || payload.public_input_sha256.len() != 2
    {
        return Err(GrantError::Invalid);
    }
    let spec = GrantSpec {
        requester_key,
        guest_tls_spki_sha256: array(&payload.guest_tls_spki_sha256)?,
        workload_sha256: array(&payload.workload_sha256)?,
        model: GrantModel::Qwen3FourBInstruct2507,
        backend: GrantBackend::LlamaCppBf16V1,
        nonce: array(&body.nonce)?,
        tls_exporter: array(&payload.tls_exporter)?,
        issued_at_ms: body.issued_at_ms,
        expires_at_ms: body.expires_at_ms,
        limits: GrantLimits {
            maximum_requests: payload
                .maximum_requests
                .try_into()
                .map_err(|_| GrantError::Invalid)?,
            maximum_turn_seconds: payload
                .maximum_turn_seconds
                .try_into()
                .map_err(|_| GrantError::Invalid)?,
            threads: payload
                .threads
                .try_into()
                .map_err(|_| GrantError::Invalid)?,
        },
        public_input_sha256: [
            array(&payload.public_input_sha256[0])?,
            array(&payload.public_input_sha256[1])?,
        ],
    };
    spec.validate()?;
    Ok(spec)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], GrantError> {
    bytes.try_into().map_err(|_| GrantError::Invalid)
}
