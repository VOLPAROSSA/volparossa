//! Short-lived service hints and exact-manifest selection for explicitly registered replicas.
//!
//! Provider identity authenticates a service offer, not a publication, hostname ownership,
//! available throughput or whitelist permission. The caller independently establishes the
//! provider key and supplies a policy-authorized protected stream. This module never dials,
//! listens, discovers peers, or adopts a directory named by a network request.

pub mod digest;
pub mod named;
pub mod replication;

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use crate::{
    CacheLimits, ChunkStore, MAX_CHUNKS, MAX_OBJECT_BYTES, SignedManifest, Validity,
    VerifiedManifest,
    transfer::{
        TransferError, TransferLimits, TransferProgress, pull_from_peer_with_progress, serve_peer,
    },
};

const VERSION: u32 = 1;
const OFFER_TYPE: u32 = 1;
const OFFER_DOMAIN: &[u8] = b"VOLPAROSSA/content-provider-offer/v1\0";
const MAX_SELECTOR_BYTES: usize = 64;
const ACCEPTED: u32 = 1;
const MISSING: u32 = 2;
const UNAVAILABLE: u32 = 3;

/// Maximum canonical signed service-offer wire length.
pub const MAX_PROVIDER_OFFER_BYTES: usize = 2048;
/// Maximum signed service-offer lifetime; copying it cannot renew this interval.
pub const MAX_PROVIDER_OFFER_TTL_SECONDS: u64 = 300;
/// Maximum explicit publications retained by one local registry.
pub const MAX_REGISTERED_PUBLICATIONS: usize = 64;

/// Canonical DNS hostname and port; this is only a provider-signed endpoint hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEndpoint {
    hostname: String,
    port: u16,
}

impl ProviderEndpoint {
    /// Construct a bounded lower-case ASCII DNS endpoint, without URL/path/IP literals.
    ///
    /// # Errors
    /// Rejects zero ports, overlong or noncanonical hostnames, empty/invalid DNS labels and IPs.
    pub fn new(hostname: &str, port: u16) -> Result<Self, ProviderError> {
        if port == 0
            || hostname.len() > 253
            || hostname.is_empty()
            || !matches!(url::Host::parse(hostname), Ok(url::Host::Domain(domain)) if domain == hostname)
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(ProviderError::Offer);
        }
        Ok(Self {
            hostname: hostname.into(),
            port,
        })
    }
    /// Exact hostname hint; not permission to bypass DNS or egress policy.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    /// Nonzero service port hint.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Canonical signed offer. Decode/hint inspection alone confers no provider authority.
#[derive(Clone)]
pub struct SignedProviderOffer {
    body: OfferBody,
    signature: [u8; 64],
    provider_key: [u8; 32],
}

impl SignedProviderOffer {
    /// Sign a fresh, at-most-five-minute service offer using the caller's stable provider key.
    ///
    /// # Errors
    /// Rejects invalid validity or unavailable operating-system nonce randomness.
    pub fn sign(
        provider: &SigningKey,
        endpoint: ProviderEndpoint,
        validity: Validity,
    ) -> Result<Self, ProviderError> {
        validate_validity(validity)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| ProviderError::Entropy)?;
        let payload = EndpointPayload {
            hostname: endpoint.hostname,
            port: u32::from(endpoint.port),
        }
        .encode_to_vec();
        let provider_key = provider.verifying_key().to_bytes();
        let body = OfferBody {
            version: VERSION,
            provider: provider_key.to_vec(),
            created: validity.created,
            expires: validity.expires,
            nonce: nonce.to_vec(),
            message_type: OFFER_TYPE,
            payload_hash: Sha256::digest(&payload).to_vec(),
            payload,
        };
        let signature = provider.sign(&offer_signing_bytes(&body)).to_bytes();
        Ok(Self {
            body,
            signature,
            provider_key,
        })
    }
    /// Encode the exact canonical, bounded signed offer.
    pub fn encode(&self) -> Vec<u8> {
        OfferEnvelope {
            body: Some(self.body.clone()),
            signature: self.signature.to_vec(),
        }
        .encode_to_vec()
    }
    /// Decode and structurally validate bounded canonical bytes; this does not verify trust.
    ///
    /// # Errors
    /// Rejects oversize, unknown/duplicate/noncanonical fields, bad lengths, version/type or hash.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProviderError> {
        if bytes.len() > MAX_PROVIDER_OFFER_BYTES {
            return Err(ProviderError::Limit);
        }
        let envelope = OfferEnvelope::decode(bytes).map_err(|_| ProviderError::Offer)?;
        if envelope.encode_to_vec() != bytes {
            return Err(ProviderError::Offer);
        }
        let body = envelope.body.ok_or(ProviderError::Offer)?;
        let provider_key = body
            .provider
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Offer)?;
        let offer = Self {
            body,
            provider_key,
            signature: envelope
                .signature
                .try_into()
                .map_err(|_| ProviderError::Offer)?,
        };
        offer.endpoint()?;
        Ok(offer)
    }
    /// Untrusted key hint, only for matching to an independently authenticated peer identity.
    ///
    /// Never treat this hint, its signature, or a peer-provided key as a new trust anchor.
    /// The caller must still invoke [`Self::verify`] against its independently established key.
    pub const fn provider_key_hint(&self) -> [u8; 32] {
        self.provider_key
    }

    /// Verify the offer against the independently authenticated expected provider identity.
    ///
    /// Re-reading the same still-valid offer is allowed; this is not a naming/anti-rollback
    /// protocol or proof that any particular publication exists at the endpoint.
    ///
    /// # Errors
    /// Rejects wrong provider, invalid signature/fields or expiry/not-yet-valid time.
    pub fn verify(
        &self,
        expected_provider: &VerifyingKey,
        now_unix: u64,
    ) -> Result<VerifiedProviderOffer, ProviderError> {
        if expected_provider.as_bytes() != &self.provider_key {
            return Err(ProviderError::WrongProvider);
        }
        expected_provider
            .verify_strict(
                &offer_signing_bytes(&self.body),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ProviderError::Signature)?;
        let endpoint = self.endpoint()?;
        let validity = Validity {
            created: self.body.created,
            expires: self.body.expires,
        };
        check_validity(validity, now_unix)?;
        Ok(VerifiedProviderOffer {
            endpoint,
            provider_key: self.provider_key,
            validity,
        })
    }
    fn endpoint(&self) -> Result<ProviderEndpoint, ProviderError> {
        if self.body.version != VERSION
            || self.body.message_type != OFFER_TYPE
            || self.body.provider.as_slice() != self.provider_key
            || self.body.nonce.len() != 32
            || self.body.payload_hash.as_slice() != Sha256::digest(&self.body.payload).as_slice()
        {
            return Err(ProviderError::Offer);
        }
        validate_validity(Validity {
            created: self.body.created,
            expires: self.body.expires,
        })?;
        let payload = EndpointPayload::decode(self.body.payload.as_slice())
            .map_err(|_| ProviderError::Offer)?;
        if payload.encode_to_vec() != self.body.payload {
            return Err(ProviderError::Offer);
        }
        ProviderEndpoint::new(
            &payload.hostname,
            u16::try_from(payload.port).map_err(|_| ProviderError::Offer)?,
        )
    }
}

/// Provider-authenticated service hint, distinct from publication and Internet egress authority.
#[derive(Clone, Debug)]
pub struct VerifiedProviderOffer {
    endpoint: ProviderEndpoint,
    provider_key: [u8; 32],
    validity: Validity,
}
impl VerifiedProviderOffer {
    /// Signed endpoint hint. The caller still authorizes its actual connection separately.
    pub fn endpoint(&self) -> &ProviderEndpoint {
        &self.endpoint
    }
    /// Independently authenticated provider signing key.
    pub const fn provider_key(&self) -> &[u8; 32] {
        &self.provider_key
    }
    /// Original signed lifetime, never renewed by verification or forwarding.
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

/// Bounded, explicit local publication allowlist. No path comes from a network selector.
/// Cloning snapshots metadata only (at most 64 entries), never open cache handles or locks.
#[derive(Clone, Default)]
pub struct PublicationRegistry {
    entries: BTreeMap<[u8; 32], RegisteredPublication>,
    name_lookup: bool,
    mailbox: Option<Arc<crate::mailbox::wire::MailboxService>>,
}
#[derive(Clone)]
struct RegisteredPublication {
    manifest: VerifiedManifest,
    signed: Option<Arc<SignedManifest>>,
    root: PathBuf,
    limits: CacheLimits,
    replication: Option<replication::SharedPublication>,
}

impl PublicationRegistry {
    /// Construct an empty registry; nothing is served until explicitly registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicitly enable public publisher/name queries for this service snapshot.
    /// Defaults off; no DHT index, background replication or private-message lookup is enabled.
    pub fn set_name_lookup(&mut self, enabled: bool) {
        self.name_lookup = enabled;
    }

    /// Attach an explicitly owned private mailbox service; public-name lookup remains separate.
    /// Cloned registries share this bounded service owner, not copied keys or cache handles.
    pub fn set_mailbox(&mut self, service: Arc<crate::mailbox::wire::MailboxService>) {
        self.mailbox = Some(service);
    }

    /// Whether an explicitly attached mailbox still owns this service independently of public content.
    pub fn has_mailbox(&self) -> bool {
        self.mailbox.is_some()
    }

    /// Register the original independently verified envelope without opting into replication.
    /// Retaining these bounded bytes alone does not enable name lookup.
    ///
    /// # Errors
    /// Rejects wrong signatures/publishers and the same ownership, expiry and bounds as register.
    pub fn register_signed(
        &mut self,
        signed: SignedManifest,
        trusted: &VerifyingKey,
        root: PathBuf,
        limits: CacheLimits,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        let manifest = signed.verify(trusted, now_unix)?;
        let id = *manifest.manifest_id();
        self.register(manifest, root, limits, now_unix)?;
        self.entries
            .get_mut(&id)
            .ok_or(ProviderError::Registry)?
            .signed = Some(Arc::new(signed));
        Ok(())
    }
    /// Register one verified publication and an existing caller-owned absolute cache root.
    ///
    /// Partial replicas are allowed. Registration checks the cache ownership/index/quota but
    /// does not scan or adopt arbitrary directories. The cache is reopened only for serving;
    /// callers must release other store handles so its exclusive lock can be acquired.
    ///
    /// # Errors
    /// Rejects duplicate IDs, expired manifests, unsafe/unowned stores or more than 64 entries.
    pub fn register(
        &mut self,
        manifest: VerifiedManifest,
        root: PathBuf,
        limits: CacheLimits,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        manifest.check_time(now_unix)?;
        if !root.is_absolute() || root.as_os_str().len() > 4096 {
            return Err(ProviderError::Registry);
        }
        let id = *manifest.manifest_id();
        if self.entries.contains_key(&id) {
            return Err(ProviderError::Registry);
        }
        if self.entries.len() >= MAX_REGISTERED_PUBLICATIONS {
            return Err(ProviderError::Limit);
        }
        drop(ChunkStore::open(&root, limits)?);
        self.entries.insert(
            id,
            RegisteredPublication {
                manifest,
                signed: None,
                root,
                limits,
                replication: None,
            },
        );
        Ok(())
    }
    /// Remove one explicit registration without deleting any cached files.
    pub fn remove(&mut self, manifest_id: &[u8; 32]) -> bool {
        self.entries.remove(manifest_id).is_some()
    }
    /// Number of explicitly registered publication IDs, including entries awaiting expiry cleanup.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no publications are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a nonempty, currently valid publication is explicitly registered.
    ///
    /// Metadata only: this never scans a directory or creates authority. Automatic services
    /// must first restore/admit and verify actual replica chunks; a mailbox is separate.
    pub fn has_live_publications(&self, now_unix: u64) -> bool {
        self.entries.values().any(|entry| {
            !entry.manifest.chunks().is_empty() && entry.manifest.check_time(now_unix).is_ok()
        })
    }
}

/// Select one exact independently verified signed-manifest ID, then pull its bounded chunks.
///
/// The provider's offer/key is not used as the publication's trust root. The caller supplies
/// an already protected and policy-authorized stream; close it on any error. A missing or
/// unavailable publication is an explicit error, not a successful zero-byte retrieval.
///
/// # Errors
/// Rejects mismatched selectors/replies, expiry, quotas, corrupt chunks or bounded deadlines.
pub async fn pull_publication<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    limits: TransferLimits,
) -> Result<TransferProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut progress = TransferProgress::default();
    pull_publication_with_progress(stream, manifest, store, limits, &mut progress).await?;
    Ok(progress)
}

/// Pull an exact publication while retaining its verified progress on partial failure.
///
/// Resets `progress` before selector exchange. A later timeout, EOF or malformed frame
/// preserves successfully verified and stored payload counts, never old cache hits or
/// unverified bytes. Success is still determined only by the returned result and eventual
/// full independently authenticated reassembly, not a nonzero progress count.
///
/// # Errors
/// Same failures and stream-close requirement as [`pull_publication`].
pub async fn pull_publication_with_progress<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    limits: TransferLimits,
    progress: &mut TransferProgress,
) -> Result<(), ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    *progress = TransferProgress::default();
    store.require_object_capacity(manifest.length())?;
    let session = select_publication(stream, manifest, limits).await?;
    timeout_at(session.deadline, async {
        pull_from_peer_with_progress(
            stream,
            manifest,
            store,
            session.remaining(limits)?,
            progress,
        )
        .await?;
        session.check_deadline()?;
        Ok(())
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

/// Select the same exact publication, then serve one parallel coordinator worker's v1 requests.
///
/// This API never dials and never chooses publisher authority. The worker owns an independently
/// verified manifest and an original deadline that includes the caller's protected stream setup.
///
/// # Errors
/// Rejects selector mismatch, unavailable publications, corrupt chunks, expiry and bounded time.
/// The caller must close the supplied stream after any error.
pub async fn pull_publication_worker<S>(
    stream: &mut S,
    worker: &mut crate::transfer::parallel::ChunkWorker,
) -> Result<(), ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = select_publication(stream, worker.manifest(), worker.remaining_limits()?).await?;
    timeout_at(session.deadline, worker.run(stream))
        .await
        .map_err(|_| ProviderError::Timeout)??;
    session.check_deadline()
}

async fn select_publication<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    limits: TransferLimits,
) -> Result<SelectorSession, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = SelectorSession::new(limits)?;
    manifest.check_time(now()?)?;
    let selector = Selector {
        version: VERSION,
        manifest_id: manifest.manifest_id().to_vec(),
        operation: 0,
    };
    timeout_at(session.deadline, async {
        let reply: SelectorReply = timeout_at(session.selector_deadline, async {
            write_frame(stream, &selector).await?;
            read_frame(stream).await
        })
        .await
        .map_err(|_| ProviderError::Timeout)??;
        if Instant::now() >= session.selector_deadline {
            return Err(ProviderError::Timeout);
        }
        if reply.version != VERSION || reply.manifest_id != selector.manifest_id {
            return Err(ProviderError::Protocol);
        }
        match reply.status {
            ACCEPTED => {}
            MISSING => return Err(ProviderError::Missing),
            UNAVAILABLE => return Err(ProviderError::Unavailable),
            _ => return Err(ProviderError::Protocol),
        }
        session.check_deadline()?;
        Ok(())
    })
    .await
    .map_err(|_| ProviderError::Timeout)??;
    Ok(session)
}

/// Serve only an exact signed-manifest ID in the local registry, then its approved chunks.
///
/// Selector frames contain no hostname, root path or arbitrary chunk authority. Reopening a
/// registered root retains the existing cache owner/index checks. An expired, unknown or busy
/// publication cannot become an accepted transfer. The caller bounds concurrent sessions.
///
/// # Errors
/// Rejects malformed/unknown selectors, unavailable stores, expired/corrupt data or deadlines.
pub async fn serve_publication<S>(
    stream: &mut S,
    registry: &PublicationRegistry,
    limits: TransferLimits,
) -> Result<TransferProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = SelectorSession::new(limits)?;
    timeout_at(session.deadline, async {
        let selector: Selector = timeout_at(session.selector_deadline, read_frame(stream))
            .await
            .map_err(|_| ProviderError::Timeout)??;
        if selector.version == crate::mailbox::wire::SELECTOR_VERSION
            && selector.operation == crate::mailbox::wire::SELECTOR_OPERATION
            && selector.manifest_id.is_empty()
        {
            registry
                .mailbox
                .as_ref()
                .ok_or(ProviderError::Missing)?
                .serve(stream)
                .await
                .map_err(|_| ProviderError::Protocol)?;
            return Ok(TransferProgress::default());
        }
        if selector.version == named::VERSION
            && selector.operation == named::OPERATION
            && selector.manifest_id.is_empty()
        {
            return named::serve(stream, registry, &session).await;
        }
        if selector.version == digest::VERSION
            && selector.operation == digest::OPERATION
            && selector.manifest_id.is_empty()
        {
            return digest::serve(stream, registry, &session).await;
        }
        if selector.version == replication::VERSION
            && selector.operation == replication::OPERATION
            && selector.manifest_id.is_empty()
        {
            return replication::serve(stream, registry, &session, limits).await;
        }
        if selector.version == replication::CREDIT_VERSION
            && selector.operation == replication::OPERATION
            && selector.manifest_id.is_empty()
        {
            return replication::serve_with_credit(stream, registry, &session, limits).await;
        }
        if selector.version != VERSION || selector.operation != 0 {
            return Err(ProviderError::Protocol);
        }
        let id: [u8; 32] = selector
            .manifest_id
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Protocol)?;
        let current_time = now()?;
        let entry = registry
            .entries
            .get(&id)
            .filter(|entry| entry.manifest.check_time(current_time).is_ok());
        let Some(entry) = entry else {
            reply(stream, &id, MISSING, session.selector_deadline).await?;
            return Err(ProviderError::Missing);
        };
        let mut store = match ChunkStore::open(&entry.root, entry.limits) {
            Ok(store) => store,
            Err(error) => {
                reply(stream, &id, UNAVAILABLE, session.selector_deadline).await?;
                return Err(ProviderError::Content(error));
            }
        };
        session.check_deadline()?;
        reply(stream, &id, ACCEPTED, session.selector_deadline).await?;
        let result = serve_peer(
            stream,
            &entry.manifest,
            &mut store,
            session.remaining(limits)?,
        )
        .await?;
        session.check_deadline()?;
        Ok(result)
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

struct SelectorSession {
    deadline: Instant,
    selector_deadline: Instant,
}
impl SelectorSession {
    fn new(limits: TransferLimits) -> Result<Self, ProviderError> {
        // Match the existing transfer ceilings before exchanging selector bytes.
        if limits.exchange_timeout.is_zero()
            || limits.exchange_timeout > Duration::from_secs(60)
            || limits.session_timeout.is_zero()
            || limits.session_timeout > Duration::from_secs(900)
            || limits.max_requests == 0
            || limits.max_requests > MAX_CHUNKS
            || limits.max_bytes == 0
            || limits.max_bytes > MAX_OBJECT_BYTES
        {
            return Err(ProviderError::Limit);
        }
        let started = Instant::now();
        let deadline = started + limits.session_timeout;
        Ok(Self {
            deadline,
            selector_deadline: deadline.min(started + limits.exchange_timeout),
        })
    }
    fn check_deadline(&self) -> Result<(), ProviderError> {
        if Instant::now() >= self.deadline {
            return Err(ProviderError::Timeout);
        }
        Ok(())
    }
    fn remaining(&self, mut limits: TransferLimits) -> Result<TransferLimits, ProviderError> {
        self.check_deadline()?;
        limits.session_timeout = self.deadline.saturating_duration_since(Instant::now());
        if limits.session_timeout.is_zero() {
            return Err(ProviderError::Timeout);
        }
        Ok(limits)
    }
}

async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    id: &[u8; 32],
    status: u32,
    deadline: Instant,
) -> Result<(), ProviderError> {
    if Instant::now() >= deadline {
        return Err(ProviderError::Timeout);
    }
    timeout_at(
        deadline,
        write_frame(
            stream,
            &SelectorReply {
                version: VERSION,
                manifest_id: id.to_vec(),
                status,
            },
        ),
    )
    .await
    .map_err(|_| ProviderError::Timeout)?
}
async fn read_frame<S: AsyncRead + Unpin, M: Message + Default>(
    stream: &mut S,
) -> Result<M, ProviderError> {
    let length = usize::try_from(stream.read_u32().await?).map_err(|_| ProviderError::Protocol)?;
    if length == 0 || length > MAX_SELECTOR_BYTES {
        return Err(ProviderError::Protocol);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let result = M::decode(bytes.as_slice()).map_err(|_| ProviderError::Protocol)?;
    if result.encode_to_vec() != bytes {
        return Err(ProviderError::Protocol);
    }
    Ok(result)
}
async fn write_frame<S: AsyncWrite + Unpin, M: Message>(
    stream: &mut S,
    message: &M,
) -> Result<(), ProviderError> {
    let bytes = message.encode_to_vec();
    if bytes.is_empty() || bytes.len() > MAX_SELECTOR_BYTES {
        return Err(ProviderError::Protocol);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| ProviderError::Protocol)?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
fn now() -> Result<u64, ProviderError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| ProviderError::Expired)
}
fn validate_validity(validity: Validity) -> Result<(), ProviderError> {
    if validity.created == 0
        || validity.expires <= validity.created
        || validity.expires - validity.created > MAX_PROVIDER_OFFER_TTL_SECONDS
    {
        return Err(ProviderError::Offer);
    }
    Ok(())
}
fn check_validity(validity: Validity, now: u64) -> Result<(), ProviderError> {
    if now < validity.created || now >= validity.expires {
        return Err(ProviderError::Expired);
    }
    Ok(())
}
fn offer_signing_bytes(body: &OfferBody) -> Vec<u8> {
    let mut bytes = OFFER_DOMAIN.to_vec();
    bytes.extend(body.encode_to_vec());
    bytes
}

#[derive(Clone, PartialEq, Message)]
struct EndpointPayload {
    #[prost(string, tag = "1")]
    hostname: String,
    #[prost(uint32, tag = "2")]
    port: u32,
}
#[derive(Clone, PartialEq, Message)]
struct OfferBody {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
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
struct OfferEnvelope {
    #[prost(message, optional, tag = "1")]
    body: Option<OfferBody>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct Selector {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    manifest_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    operation: u32,
}
#[derive(Clone, PartialEq, Message)]
struct SelectorReply {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    manifest_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    status: u32,
}

/// Explicit service-offer, registry, selector and chunk-transfer failures.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// Native manifest/cache validation failed locally.
    #[error(transparent)]
    Content(#[from] crate::Error),
    /// The existing authenticated chunk transfer failed.
    #[error(transparent)]
    Transfer(#[from] TransferError),
    /// The supplied protected stream failed.
    #[error("content provider stream failed: {0}")]
    Io(#[from] std::io::Error),
    /// Offer fields, endpoint, bounded encoding or validity were invalid.
    #[error("invalid content provider offer")]
    Offer,
    /// The offered key is not the independently authenticated provider identity.
    #[error("content provider identity mismatch")]
    WrongProvider,
    /// Provider signature did not authenticate the exact offer body.
    #[error("invalid content provider signature")]
    Signature,
    /// Operating-system nonce randomness was unavailable.
    #[error("content provider secure randomness unavailable")]
    Entropy,
    /// Offer or trusted time is outside its lifetime.
    #[error("content provider offer expired or not yet valid")]
    Expired,
    /// Registry root or duplicate registration was invalid.
    #[error("invalid content publication registration")]
    Registry,
    /// Registry, frame or transfer resource limits were exceeded.
    #[error("content provider resource limit exceeded")]
    Limit,
    /// Selector encoding, version, exact identity or reply correlation was invalid.
    #[error("invalid content publication selector")]
    Protocol,
    /// The exact requested publication was absent or expired in this registry.
    #[error("content publication is not registered")]
    Missing,
    /// The registered publication could not currently be opened safely.
    #[error("content publication is unavailable")]
    Unavailable,
    /// Selector or combined selector/transfer exceeded its original deadline.
    #[error("content provider deadline exceeded")]
    Timeout,
}
