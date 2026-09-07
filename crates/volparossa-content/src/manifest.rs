use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    CHUNK_BYTES, ChunkId, Error, MAX_CHUNKS, MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES,
    MAX_VALIDITY_SECONDS,
};

const VERSION: u32 = 1;
const NATIVE_MANIFEST_TYPE: u32 = 1;
const SIGNING_DOMAIN: &[u8] = b"VOLPAROSSA/native-content-manifest/v1\0";
const MAX_METADATA_BYTES: usize = 128;

/// Native object metadata, authenticated together with every chunk and its order.
///
/// A name is a publisher-local label, not an authenticated DNS name, URL or HTTPS origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Nonempty publisher-local label, at most 128 UTF-8 bytes, without control characters.
    pub name: String,
    /// Nonzero publisher-defined revision; latest-version resolution is not implemented.
    pub revision: u64,
    /// Nonempty ASCII content type without whitespace/control characters, at most 128 bytes.
    pub content_type: String,
}

impl Metadata {
    fn validate(&self) -> Result<(), Error> {
        if self.name.is_empty()
            || self.name.len() > MAX_METADATA_BYTES
            || self.name.chars().any(char::is_control)
            || self.revision == 0
            || self.content_type.is_empty()
            || self.content_type.len() > MAX_METADATA_BYTES
            || !self
                .content_type
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::InvalidManifest);
        }
        Ok(())
    }
}

/// Signed Unix-time validity. Reuse never renews this interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Exclusive expiration time, at most 31 days after creation.
    pub expires: u64,
}

impl Validity {
    fn validate(self) -> Result<(), Error> {
        if self.created == 0
            || self.expires <= self.created
            || self.expires - self.created > MAX_VALIDITY_SECONDS
        {
            return Err(Error::InvalidManifest);
        }
        Ok(())
    }

    fn check_time(self, now: u64) -> Result<(), Error> {
        if now < self.created || now >= self.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// Exact object size and metadata supplied by its native publisher.
#[derive(Clone, Debug)]
pub struct Publication {
    /// Publisher-local metadata, not web-origin authority.
    pub metadata: Metadata,
    /// Exact input length; never inferred from an unbounded stream.
    pub length: u64,
    /// Authenticated validity interval.
    pub validity: Validity,
}

impl Publication {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.metadata.validate()?;
        self.validity.validate()?;
        if self.length > MAX_OBJECT_BYTES {
            return Err(Error::Limit("object length"));
        }
        Ok(())
    }
}

/// One ordered, authenticated chunk reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk {
    pub(crate) id: ChunkId,
    pub(crate) length: u32,
}

impl Chunk {
    /// SHA-256 of this exact chunk's bytes.
    pub fn id(&self) -> &ChunkId {
        &self.id
    }

    /// Expected number of bytes, at most [`CHUNK_BYTES`].
    pub fn length(&self) -> u32 {
        self.length
    }
}

#[derive(Clone, PartialEq, Message)]
struct WireChunk {
    #[prost(bytes = "vec", tag = "1")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "2")]
    length: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Payload {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(uint64, tag = "2")]
    revision: u64,
    #[prost(string, tag = "3")]
    content_type: String,
    #[prost(uint64, tag = "4")]
    length: u64,
    #[prost(message, repeated, tag = "5")]
    chunks: Vec<WireChunk>,
    #[prost(bytes = "vec", tag = "6")]
    whole_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct Body {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    publisher: Vec<u8>,
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

/// Canonical, bounded signed bytes. Decoding alone confers no publisher trust.
#[derive(Clone, Debug)]
pub struct SignedManifest {
    body: Body,
    signature: [u8; 64],
}

impl SignedManifest {
    pub(crate) fn sign(
        publication: Publication,
        chunks: Vec<Chunk>,
        whole_hash: [u8; 32],
        publisher: &SigningKey,
    ) -> Result<Self, Error> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
        let payload = Payload {
            name: publication.metadata.name,
            revision: publication.metadata.revision,
            content_type: publication.metadata.content_type,
            length: publication.length,
            chunks: chunks
                .into_iter()
                .map(|chunk| WireChunk {
                    hash: chunk.id.0.to_vec(),
                    length: chunk.length,
                })
                .collect(),
            whole_hash: whole_hash.to_vec(),
        }
        .encode_to_vec();
        let body = Body {
            version: VERSION,
            publisher: publisher.verifying_key().to_bytes().to_vec(),
            created: publication.validity.created,
            expires: publication.validity.expires,
            nonce: nonce.to_vec(),
            message_type: NATIVE_MANIFEST_TYPE,
            payload_hash: Sha256::digest(&payload).to_vec(),
            payload,
        };
        let signature = publisher.sign(&signing_bytes(&body)).to_bytes();
        let result = Self { body, signature };
        result.validate()?;
        if result.encode().len() > MAX_MANIFEST_BYTES {
            return Err(Error::Limit("manifest length"));
        }
        Ok(result)
    }

    /// Encode the complete canonical protobuf envelope, bounded by [`MAX_MANIFEST_BYTES`].
    pub fn encode(&self) -> Vec<u8> {
        Envelope {
            body: Some(self.body.clone()),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }

    /// Decode bounded canonical protobuf, rejecting unknown/duplicate/noncanonical fields.
    ///
    /// # Errors
    /// Rejects excessive wire size, invalid fields or payload hash, and noncanonical encoding.
    /// This does not check publisher trust or signature; callers must use [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Limit("manifest length"));
        }
        let envelope = Envelope::decode(bytes).map_err(|_| Error::InvalidManifest)?;
        if envelope.encode_to_vec() != bytes {
            return Err(Error::InvalidManifest);
        }
        let result = Self {
            body: envelope.body.ok_or(Error::InvalidManifest)?,
            signature: envelope
                .signature
                .try_into()
                .map_err(|_| Error::InvalidManifest)?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Authenticate the exact manifest against a caller's **pre-established** publisher key.
    ///
    /// Never select this key from the manifest or from an untrusted content provider.
    /// A valid native signature is not HTTPS/DNS authority. Re-reading the same still-valid
    /// object is intentional; freshness/latest-revision anti-rollback needs separate naming.
    ///
    /// # Errors
    /// Rejects wrong publisher, invalid signature, invalid payload or signed validity failure.
    pub fn verify(
        &self,
        expected_publisher: &VerifyingKey,
        now_unix_seconds: u64,
    ) -> Result<VerifiedManifest, Error> {
        if self.body.publisher != expected_publisher.as_bytes() {
            return Err(Error::WrongPublisher);
        }
        expected_publisher
            .verify_strict(
                &signing_bytes(&self.body),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::InvalidSignature)?;
        let result = self.validate()?;
        result.check_time(now_unix_seconds)?;
        Ok(result)
    }

    fn validate(&self) -> Result<VerifiedManifest, Error> {
        if self.body.version != VERSION
            || self.body.message_type != NATIVE_MANIFEST_TYPE
            || self.body.publisher.len() != 32
            || self.body.nonce.len() != 32
            || self.body.payload_hash.as_slice() != Sha256::digest(&self.body.payload).as_slice()
        {
            return Err(Error::InvalidManifest);
        }
        let validity = Validity {
            created: self.body.created,
            expires: self.body.expires,
        };
        validity.validate()?;
        let payload =
            Payload::decode(self.body.payload.as_slice()).map_err(|_| Error::InvalidManifest)?;
        if payload.encode_to_vec() != self.body.payload
            || payload.chunks.len() > MAX_CHUNKS
            || payload.length > MAX_OBJECT_BYTES
        {
            return Err(Error::InvalidManifest);
        }
        let metadata = Metadata {
            name: payload.name,
            revision: payload.revision,
            content_type: payload.content_type,
        };
        metadata.validate()?;
        let mut total = 0_u64;
        let chunk_count = payload.chunks.len();
        let mut chunks = Vec::with_capacity(chunk_count);
        for (index, chunk) in payload.chunks.into_iter().enumerate() {
            if chunk.length == 0
                || u64::from(chunk.length) > CHUNK_BYTES as u64
                || (index + 1 < chunk_count && u64::from(chunk.length) != CHUNK_BYTES as u64)
            {
                return Err(Error::InvalidManifest);
            }
            total += u64::from(chunk.length);
            chunks.push(Chunk {
                id: ChunkId(chunk.hash.try_into().map_err(|_| Error::InvalidManifest)?),
                length: chunk.length,
            });
        }
        if total != payload.length {
            return Err(Error::InvalidManifest);
        }
        Ok(VerifiedManifest {
            publisher: self
                .body
                .publisher
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidManifest)?,
            metadata,
            length: total,
            validity,
            chunks,
            whole_hash: payload
                .whole_hash
                .try_into()
                .map_err(|_| Error::InvalidManifest)?,
        })
    }
}

fn signing_bytes(body: &Body) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + body.encoded_len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&body.encode_to_vec());
    bytes
}

/// Exact manifest verified against the expected publisher. Fields cannot be forged by callers.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    publisher: [u8; 32],
    metadata: Metadata,
    length: u64,
    validity: Validity,
    chunks: Vec<Chunk>,
    pub(crate) whole_hash: [u8; 32],
}

impl VerifiedManifest {
    /// Exact pre-established Ed25519 publisher key that authenticated this native object.
    ///
    /// Names and revisions are scoped to this identity, not an inferred web origin.
    pub fn publisher(&self) -> &[u8; 32] {
        &self.publisher
    }

    /// Authenticated publisher-local metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Exact reconstructed length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Authenticated chunk order and lengths.
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// Original signed interval, unchanged by copying or cache access.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    pub(crate) fn check_time(&self, now: u64) -> Result<(), Error> {
        self.validity.check_time(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CacheLimits, ChunkStore, publish};

    #[test]
    fn signature_binds_order_metadata_and_envelope_not_peer_chosen_key() {
        let directory = tempfile::tempdir().expect("test directory");
        let mut store =
            ChunkStore::create(&directory.path().join("cache"), limits()).expect("store");
        let publisher = SigningKey::generate(&mut rand_core::OsRng);
        let mut bytes = vec![1; CHUNK_BYTES];
        bytes.extend(vec![2; CHUNK_BYTES]);
        let signed = publish(
            &mut bytes.as_slice(),
            publication(bytes.len() as u64),
            &publisher,
            &mut store,
        )
        .expect("publish");
        let decoded = SignedManifest::decode(&signed.encode()).expect("canonical manifest");
        decoded
            .verify(&publisher.verifying_key(), 101)
            .expect("verify");
        let other_key = SigningKey::generate(&mut rand_core::OsRng);
        assert!(matches!(
            decoded.verify(&other_key.verifying_key(), 101),
            Err(Error::WrongPublisher)
        ));

        for alteration in 0..8 {
            let mut changed = signed.clone();
            let mut payload = Payload::decode(changed.body.payload.as_slice()).expect("payload");
            match alteration {
                0 => payload.chunks.swap(0, 1),
                1 => payload.content_type = "text/html".into(),
                2 => payload.name = "different-name".into(),
                3 => payload.revision += 1,
                4 => changed.body.expires += 1,
                5 => changed.body.nonce[0] ^= 1,
                6 => changed.body.created += 1,
                _ => payload.whole_hash[0] ^= 1,
            }
            changed.body.payload = payload.encode_to_vec();
            changed.body.payload_hash = Sha256::digest(&changed.body.payload).to_vec();
            assert!(matches!(
                changed.verify(&publisher.verifying_key(), 101),
                Err(Error::InvalidSignature)
            ));
        }
        let second = publish(
            &mut bytes.as_slice(),
            publication(bytes.len() as u64),
            &publisher,
            &mut store,
        )
        .expect("republish");
        assert_ne!(signed.body.nonce, second.body.nonce);
    }

    #[test]
    fn manifest_rejects_noncanonical_invalid_lengths_and_expiry() {
        let directory = tempfile::tempdir().expect("directory");
        let mut store =
            ChunkStore::create(&directory.path().join("cache"), limits()).expect("store");
        let publisher = SigningKey::generate(&mut rand_core::OsRng);
        let signed =
            publish(&mut &b"object"[..], publication(6), &publisher, &mut store).expect("publish");
        for now in [99, 200, 201] {
            assert!(matches!(
                signed.verify(&publisher.verifying_key(), now),
                Err(Error::Expired)
            ));
        }
        for boundary in [100, 199] {
            signed
                .verify(&publisher.verifying_key(), boundary)
                .expect("valid interval");
        }
        let mut unknown = signed.encode();
        unknown.extend([0x78, 0x01]);
        assert!(matches!(
            SignedManifest::decode(&unknown),
            Err(Error::InvalidManifest)
        ));
        assert!(matches!(
            SignedManifest::decode(&vec![0; MAX_MANIFEST_BYTES + 1]),
            Err(Error::Limit(_))
        ));
        for alteration in 0..7 {
            let mut changed = signed.clone();
            let mut payload = Payload::decode(changed.body.payload.as_slice()).expect("payload");
            match alteration {
                0 => payload.length += 1,
                1 => payload.chunks[0].length = 0,
                2 => payload.chunks[0].hash.pop().map(|_| ()).expect("hash"),
                3 => changed.body.version += 1,
                4 => changed.body.message_type += 1,
                5 => changed.body.nonce.clear(),
                _ => changed.body.expires = changed.body.created + MAX_VALIDITY_SECONDS + 1,
            }
            changed.body.payload = payload.encode_to_vec();
            changed.body.payload_hash = Sha256::digest(&changed.body.payload).to_vec();
            assert!(matches!(
                SignedManifest::decode(&changed.encode()),
                Err(Error::InvalidManifest)
            ));
        }
    }

    fn publication(length: u64) -> Publication {
        Publication {
            metadata: Metadata {
                name: "native-object".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length,
            validity: Validity {
                created: 100,
                expires: 200,
            },
        }
    }

    fn limits() -> CacheLimits {
        CacheLimits {
            max_bytes: 4 * CHUNK_BYTES as u64,
            max_entries: 4,
            min_free_bytes: 0,
        }
    }
}
