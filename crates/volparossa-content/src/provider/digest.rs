//! Exact whole-object digest lookup over an already authorized protected provider stream.
//!
//! Self-consistent signed manifests are transport indexes, never trusted publishers or HTTPS
//! authority. The consumer must independently authorize the digest and check the complete body.

use ed25519_dalek::VerifyingKey;
use prost::Message;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use super::{ProviderError, PublicationRegistry, Selector, SelectorSession, now};
use crate::{
    MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    transfer::{TransferLimits, TransferProgress},
};

pub(super) const VERSION: u32 = 6;
pub(super) const OPERATION: u32 = 4;
const MAX_QUERY_BYTES: usize = 128;
const MAX_REPLY_BYTES: usize = MAX_MANIFEST_BYTES + 256;
const LIFETIME: u64 = 15;
const CANDIDATE: u32 = 1;
const MISSING: u32 = 2;

#[cfg(test)]
mod tests;

/// Exact externally authorized object identity, with no URL or publisher trust assertion.
#[derive(Clone, Debug)]
pub struct DigestQuery {
    sha256: [u8; 32],
    length: u64,
}

impl DigestQuery {
    /// Construct a bounded query. This constructor does not establish origin authority.
    ///
    /// # Errors
    /// Rejects lengths above the native bounded-object limit.
    pub fn new(sha256: [u8; 32], length: u64) -> Result<Self, ProviderError> {
        if length > MAX_OBJECT_BYTES {
            return Err(ProviderError::Limit);
        }
        Ok(Self { sha256, length })
    }

    /// Requested whole-object digest, never a hash of a URL or a DHT key.
    pub const fn object_sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Exact requested representation length.
    pub const fn length(&self) -> u64 {
        self.length
    }

    fn candidate(&self, bytes: &[u8], at: u64) -> Result<DigestCandidate, ProviderError> {
        let signed = SignedManifest::decode(bytes)?;
        let key = VerifyingKey::from_bytes(&signed.publisher_key_hint())
            .map_err(|_| ProviderError::Protocol)?;
        // Only signature self-consistency: the untrusted envelope supplied this key.
        let manifest = signed.verify(&key, at)?;
        if manifest.object_sha256() != &self.sha256
            || manifest.length() != self.length
            || manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        {
            return Err(ProviderError::Protocol);
        }
        Ok(DigestCandidate { signed, manifest })
    }
}

/// One self-consistent transport index, NOT independently trusted native/HTTPS authority.
#[derive(Clone, Debug)]
pub struct DigestCandidate {
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

impl DigestCandidate {
    /// Original envelope, requiring the consumer's independent origin-digest validation.
    pub fn signed(&self) -> &SignedManifest {
        &self.signed
    }

    /// Chunk layout only. Do not release content based on this peer-selected key/signature;
    /// independently authorize the expected whole digest and verify every reconstructed byte.
    pub fn transport_manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
}

/// Lookup a transport index on one caller-protected stream without dialing or discovery.
///
/// At most one original manifest is returned. Competing indexes are not a publisher consensus;
/// only a later independently authorized whole-object hash check can validate the actual bytes.
///
/// # Errors
/// Rejects bounds, noncanonical messages, wrong nonce/query, expiry and bad index signatures.
pub async fn lookup_publication<S>(
    stream: &mut S,
    query: &DigestQuery,
    limits: TransferLimits,
) -> Result<Option<DigestCandidate>, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = SelectorSession::new(limits)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| ProviderError::Entropy)?;
    let created = now()?;
    let request = Request {
        version: VERSION,
        nonce: nonce.to_vec(),
        sha256: query.sha256.to_vec(),
        length: query.length,
        created,
        expires: created
            .checked_add(LIFETIME)
            .ok_or(ProviderError::Expired)?,
    };
    let response: Reply = timeout_at(session.selector_deadline, async {
        super::write_frame(
            stream,
            &Selector {
                version: VERSION,
                operation: OPERATION,
                manifest_id: Vec::new(),
            },
        )
        .await?;
        write_frame(stream, &request, MAX_QUERY_BYTES).await?;
        read_frame(stream, MAX_REPLY_BYTES).await
    })
    .await
    .map_err(|_| ProviderError::Timeout)??;
    session.check_deadline()?;
    let at = now()?;
    if Instant::now() >= session.selector_deadline
        || response.version != VERSION
        || response.nonce != request.nonce
        || response.sha256 != request.sha256
        || response.length != request.length
        || response.created != request.created
        || response.expires > request.expires
    {
        return Err(ProviderError::Protocol);
    }
    check_time(response.created, response.expires, at)?;
    match response.status {
        MISSING if response.manifest.is_empty() => Ok(None),
        CANDIDATE if !response.manifest.is_empty() => {
            let candidate = query.candidate(&response.manifest, at)?;
            if response.expires > candidate.manifest.validity().expires {
                return Err(ProviderError::Expired);
            }
            Ok(Some(candidate))
        }
        _ => Err(ProviderError::Protocol),
    }
}

pub(super) async fn serve<S>(
    stream: &mut S,
    registry: &PublicationRegistry,
    session: &SelectorSession,
) -> Result<TransferProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout_at(session.selector_deadline, async {
        let request: Request = read_frame(stream, MAX_QUERY_BYTES).await?;
        let at = now()?;
        if request.version != VERSION || request.nonce.len() != 32 {
            return Err(ProviderError::Protocol);
        }
        check_time(request.created, request.expires, at)?;
        let query = DigestQuery::new(
            request
                .sha256
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::Protocol)?,
            request.length,
        )?;
        // Existing registry bound is 64. No cache walk, mailbox query or new index is made.
        let mut selected = None;
        for entry in registry.entries.values() {
            session.check_deadline()?;
            if entry.manifest.object_sha256() == query.object_sha256()
                && entry.manifest.length() == query.length()
                && entry.manifest.metadata().content_type != PRIVATE_MESSAGE_CONTENT_TYPE
                && entry.manifest.check_time(at).is_ok()
            {
                if let Some(signed) = entry.signed.as_ref() {
                    selected = Some((signed.encode(), entry.manifest.validity().expires));
                    break;
                }
            }
        }
        let (manifest, expires) = selected.map_or_else(
            || (Vec::new(), request.expires),
            |(signed, expires)| (signed, request.expires.min(expires)),
        );
        let reply = Reply {
            version: VERSION,
            nonce: request.nonce,
            sha256: request.sha256,
            length: request.length,
            created: request.created,
            expires,
            status: if manifest.is_empty() {
                MISSING
            } else {
                CANDIDATE
            },
            manifest,
        };
        write_frame(stream, &reply, MAX_REPLY_BYTES).await?;
        check_time(reply.created, reply.expires, now()?)?;
        session.check_deadline()?;
        Ok(TransferProgress::default())
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

fn check_time(created: u64, expires: u64, at: u64) -> Result<(), ProviderError> {
    if created == 0
        || created > at
        || expires <= at
        || expires <= created
        || expires - created > LIFETIME
    {
        return Err(ProviderError::Expired);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    sha256: Vec<u8>,
    #[prost(uint64, tag = "4")]
    length: u64,
    #[prost(uint64, tag = "5")]
    created: u64,
    #[prost(uint64, tag = "6")]
    expires: u64,
}

#[derive(Clone, PartialEq, Message)]
struct Reply {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    sha256: Vec<u8>,
    #[prost(uint64, tag = "4")]
    length: u64,
    #[prost(uint64, tag = "5")]
    created: u64,
    #[prost(uint64, tag = "6")]
    expires: u64,
    #[prost(uint32, tag = "7")]
    status: u32,
    #[prost(bytes = "vec", tag = "8")]
    manifest: Vec<u8>,
}

async fn read_frame<S: AsyncRead + Unpin, M: Message + Default>(
    stream: &mut S,
    maximum: usize,
) -> Result<M, ProviderError> {
    let length = usize::try_from(stream.read_u32().await?).map_err(|_| ProviderError::Limit)?;
    if length == 0 || length > maximum {
        return Err(ProviderError::Limit);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let message = M::decode(bytes.as_slice()).map_err(|_| ProviderError::Protocol)?;
    if message.encode_to_vec() != bytes {
        return Err(ProviderError::Protocol);
    }
    Ok(message)
}

async fn write_frame<S: AsyncWrite + Unpin, M: Message>(
    stream: &mut S,
    message: &M,
    maximum: usize,
) -> Result<(), ProviderError> {
    let bytes = message.encode_to_vec();
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ProviderError::Limit);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| ProviderError::Limit)?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
