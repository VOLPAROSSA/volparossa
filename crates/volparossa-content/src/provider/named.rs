//! Exact publisher-local name lookup inside the caller's existing protected provider stream.
//!
//! No name is advertised in discovery. Replies retain original signed envelopes; neither a
//! provider nor the highest observed revision proves global freshness or HTTPS authority.

use ed25519_dalek::VerifyingKey;
use prost::Message;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use super::{ProviderError, PublicationRegistry, Selector, SelectorSession, now};
use crate::{
    MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    transfer::{TransferLimits, TransferProgress},
};

pub(super) const VERSION: u32 = 4;
pub(super) const OPERATION: u32 = 2;
const MAX_QUERY_BYTES: usize = 256;
const MAX_REPLY_BYTES: usize = 2 * MAX_MANIFEST_BYTES + 128;
const CANDIDATE: u32 = 1;
const MISSING: u32 = 2;
const CONFLICT: u32 = 4;

/// Explicit independent publisher trust and one exact native label, not a DNS name or URL.
#[derive(Clone)]
pub struct NameQuery {
    publisher: VerifyingKey,
    name: String,
    min_revision: u64,
}

impl NameQuery {
    /// Construct an exact bounded label query. Zero imposes no additional revision floor.
    ///
    /// # Errors
    /// Rejects invalid Ed25519 keys, empty/overlong names and Unicode control characters.
    pub fn new(publisher: [u8; 32], name: &str, min_revision: u64) -> Result<Self, ProviderError> {
        crate::manifest::validate_name(name)?;
        Ok(Self {
            publisher: VerifyingKey::from_bytes(&publisher).map_err(|_| ProviderError::Protocol)?,
            name: name.into(),
            min_revision,
        })
    }

    /// Independently supplied trust anchor; never derived from provider metadata.
    pub fn publisher(&self) -> &[u8; 32] {
        self.publisher.as_bytes()
    }

    /// Exact UTF-8 publisher-local label; case and byte identity are preserved.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Explicit caller floor, separate from a durable cache's higher retained floor.
    pub const fn min_revision(&self) -> u64 {
        self.min_revision
    }

    /// Verify a returned envelope against this exact independently authorized query.
    ///
    /// # Errors
    /// Rejects wrong keys/names, stale or below-floor revisions, and private-message objects.
    /// This public-name protocol is not a private-message mailbox or latest-version oracle.
    pub fn verify_candidate(
        &self,
        signed: &SignedManifest,
        now_unix: u64,
    ) -> Result<VerifiedManifest, ProviderError> {
        let manifest = signed.verify(&self.publisher, now_unix)?;
        if manifest.metadata().name != self.name
            || manifest.metadata().revision < self.min_revision
            || manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        {
            return Err(ProviderError::Protocol);
        }
        Ok(manifest)
    }
}

/// An original envelope independently verified against this operation's publisher/name.
#[derive(Clone, Debug)]
pub struct NameCandidate {
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

impl NameCandidate {
    /// Original signed bytes; re-signing or copying never renews their validity.
    pub fn signed(&self) -> &SignedManifest {
        &self.signed
    }

    /// Independent native publisher authority, not service identity or HTTPS authority.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
}

/// One bounded provider observation, not a global name-resolution consensus.
#[derive(Debug)]
pub enum NameResolution {
    /// No current public candidate, including a service whose name lookup is disabled.
    Missing,
    /// Highest matching revision retained by this provider.
    Candidate(Box<NameCandidate>),
    /// Two independently verified envelopes at the same revision with different IDs.
    /// A provider's bare assertion can never create this result or a durable conflict pin.
    Conflict(Box<[NameCandidate; 2]>),
}

/// Ask one provider through a caller-supplied protected stream; never dial or choose a route.
///
/// The caller combines at most its bounded discovery round and persists independently verified
/// revision observations before fetching chunks. Old peers reject the new selector version;
/// there is no fallback to a name catalogue, direct connection or peer-supplied trust anchor.
///
/// # Errors
/// Rejects bounds, noncanonical frames, nonce mismatch, invalid signatures and timeouts.
pub async fn lookup_publication<S>(
    stream: &mut S,
    query: &NameQuery,
    limits: TransferLimits,
) -> Result<NameResolution, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = SelectorSession::new(limits)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| ProviderError::Entropy)?;
    let request = NameRequest {
        version: VERSION,
        nonce: nonce.to_vec(),
        publisher: query.publisher().to_vec(),
        name: query.name.clone(),
        min_revision: query.min_revision,
    };
    let response: NameReply = timeout_at(session.selector_deadline, async {
        super::write_frame(
            stream,
            &Selector {
                version: VERSION,
                manifest_id: Vec::new(),
                operation: OPERATION,
            },
        )
        .await?;
        write_frame(stream, &request, MAX_QUERY_BYTES).await?;
        read_frame(stream, MAX_REPLY_BYTES).await
    })
    .await
    .map_err(|_| ProviderError::Timeout)??;
    session.check_deadline()?;
    if Instant::now() >= session.selector_deadline
        || response.version != VERSION
        || response.nonce != nonce
    {
        return Err(ProviderError::Protocol);
    }
    decode_resolution(&response, query, now()?)
}

fn decode_resolution(
    reply: &NameReply,
    query: &NameQuery,
    now_unix: u64,
) -> Result<NameResolution, ProviderError> {
    if reply.first.len() > MAX_MANIFEST_BYTES || reply.second.len() > MAX_MANIFEST_BYTES {
        return Err(ProviderError::Limit);
    }
    match reply.status {
        MISSING if reply.first.is_empty() && reply.second.is_empty() => Ok(NameResolution::Missing),
        CANDIDATE if !reply.first.is_empty() && reply.second.is_empty() => Ok(
            NameResolution::Candidate(Box::new(candidate(&reply.first, query, now_unix)?)),
        ),
        CONFLICT if !reply.first.is_empty() && !reply.second.is_empty() => {
            let first = candidate(&reply.first, query, now_unix)?;
            let second = candidate(&reply.second, query, now_unix)?;
            if first.manifest.metadata().revision != second.manifest.metadata().revision
                || first.manifest.manifest_id() == second.manifest.manifest_id()
            {
                return Err(ProviderError::Protocol);
            }
            Ok(NameResolution::Conflict(Box::new([first, second])))
        }
        _ => Err(ProviderError::Protocol),
    }
}

fn candidate(
    bytes: &[u8],
    query: &NameQuery,
    now_unix: u64,
) -> Result<NameCandidate, ProviderError> {
    let signed = SignedManifest::decode(bytes)?;
    let manifest = query.verify_candidate(&signed, now_unix)?;
    Ok(NameCandidate { signed, manifest })
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
        let request: NameRequest = read_frame(stream, MAX_QUERY_BYTES).await?;
        if request.version != VERSION || request.nonce.len() != 32 {
            return Err(ProviderError::Protocol);
        }
        let query = NameQuery::new(
            request
                .publisher
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::Protocol)?,
            &request.name,
            request.min_revision,
        )?;
        let selected = select(registry, &query, now()?, session)?;
        let reply = NameReply {
            version: VERSION,
            nonce: request.nonce,
            status: match selected.len() {
                0 => MISSING,
                1 => CANDIDATE,
                _ => CONFLICT,
            },
            first: selected
                .first()
                .map_or_else(Vec::new, |signed| signed.encode()),
            second: selected
                .get(1)
                .map_or_else(Vec::new, |signed| signed.encode()),
        };
        write_frame(stream, &reply, MAX_REPLY_BYTES).await?;
        session.check_deadline()?;
        Ok(TransferProgress::default())
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

fn select<'a>(
    registry: &'a PublicationRegistry,
    query: &NameQuery,
    now_unix: u64,
    session: &SelectorSession,
) -> Result<Vec<&'a SignedManifest>, ProviderError> {
    let mut selected = Vec::new();
    let mut revision = 0;
    if !registry.name_lookup {
        return Ok(selected);
    }
    // Metadata-only bounded scan: no cache lock or file access while answering a name query.
    for entry in registry.entries.values() {
        session.check_deadline()?;
        let Some(signed) = entry.signed.as_deref() else {
            continue;
        };
        let manifest = &entry.manifest;
        if manifest.publisher() != query.publisher()
            || manifest.metadata().name != query.name
            || manifest.metadata().revision < query.min_revision
            || manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
            || manifest.check_time(now_unix).is_err()
        {
            continue;
        }
        let found = manifest.metadata().revision;
        if found > revision {
            selected.clear();
            revision = found;
        }
        if found == revision && selected.len() < 2 {
            selected.push(signed);
        }
    }
    Ok(selected)
}

#[derive(Clone, PartialEq, Message)]
struct NameRequest {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    publisher: Vec<u8>,
    #[prost(string, tag = "4")]
    name: String,
    #[prost(uint64, tag = "5")]
    min_revision: u64,
}

#[derive(Clone, PartialEq, Message)]
struct NameReply {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(uint32, tag = "3")]
    status: u32,
    #[prost(bytes = "vec", tag = "4")]
    first: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    second: Vec<u8>,
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
