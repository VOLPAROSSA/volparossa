//! Cooperative-origin HTTPS metadata for explicitly shared anonymous binary resources.
//!
//! Every consumer authenticates the origin itself over TLS before accepting its manifest.
//! Peers cannot construct origin authority. This first profile supports only anonymous GET,
//! 200, identity encoding, `application/octet-stream`, explicit public freshness and no
//! variants, cookies, redirects or authentication. Unsupported web responses are not admitted
//! to shared storage. This is not a browser adapter, generic web proof or offline origin trust.
//! URLs and HTTP metadata remain in the caller's in-memory authorization, not the chunk store.

use std::{path::Path, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use http::{HeaderMap, HeaderName, HeaderValue};
use prost::Message;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

use crate::{
    CHUNK_BYTES, ChunkStore, MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES, MAX_VALIDITY_SECONDS,
    SignedManifest, VerifiedManifest,
};

const VERSION: u32 = 1;
// Anonymous GET, Accept: application/octet-stream, Accept-Encoding: identity, no credentials.
const REQUEST_PROFILE: u32 = 1;
const BINARY_TYPE: &str = "application/octet-stream";
const ALPN: &[u8] = b"http/1.1";
const MAX_TARGET_BYTES: usize = 4096;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_DESCRIPTOR_BYTES: usize = MAX_MANIFEST_BYTES + 16 * 1024;

/// HTTP content type for the canonical cooperative-origin descriptor.
pub const ORIGIN_DESCRIPTOR_CONTENT_TYPE: &str = "application/vnd.volparossa.origin-manifest.v1";

/// Exact requested HTTPS resource and same-origin metadata path. No dial or DNS authority.
#[derive(Clone)]
pub struct OriginRequest {
    resource: Url,
    metadata_path: String,
}

impl OriginRequest {
    /// Select a canonical HTTPS URL and an explicit same-origin metadata path.
    ///
    /// # Errors
    /// Rejects non-HTTPS, credentials/fragments, non-domain hosts, excessive lengths and
    /// noncanonical/ambiguous metadata paths. The supplied stream is still caller-authorized.
    pub fn new(resource_https_url: &str, metadata_path: &str) -> Result<Self, OriginError> {
        if resource_https_url.len() > MAX_TARGET_BYTES || metadata_path.len() > MAX_TARGET_BYTES {
            return Err(OriginError::Limit);
        }
        let resource = Url::parse(resource_https_url).map_err(|_| OriginError::Request)?;
        if resource.scheme() != "https"
            || resource.domain().is_none()
            || !resource.username().is_empty()
            || resource.password().is_some()
            || resource.fragment().is_some()
            || resource.as_str() != resource_https_url
            || !metadata_path.starts_with('/')
            || metadata_path.starts_with("//")
            || !metadata_path.bytes().all(|byte| byte.is_ascii_graphic())
            || metadata_path.contains(['#', '\\'])
        {
            return Err(OriginError::Request);
        }
        let metadata = resource
            .join(metadata_path)
            .map_err(|_| OriginError::Request)?;
        if metadata.origin() != resource.origin() || target(&metadata) != metadata_path {
            return Err(OriginError::Request);
        }
        Ok(Self {
            resource,
            metadata_path: metadata_path.into(),
        })
    }
}

/// Bounded TLS handshakes and complete HTTP operations, never reset by byte trickling.
#[derive(Clone, Copy, Debug)]
pub struct OriginLimits {
    /// Maximum TLS handshake time, at most 60 seconds.
    pub handshake_timeout: Duration,
    /// Maximum complete metadata or full-body operation, at most 15 minutes.
    pub session_timeout: Duration,
    /// Maximum authenticated object length, at most the native object limit.
    pub max_object_bytes: u64,
}

impl Default for OriginLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(15),
            session_timeout: Duration::from_secs(300),
            max_object_bytes: MAX_OBJECT_BYTES,
        }
    }
}

/// Standards-verified origin TLS. The constructor accepts trust roots, not a custom verifier.
pub struct OriginClient {
    connector: TlsConnector,
    limits: OriginLimits,
}

impl OriginClient {
    /// Configure real TLS 1.3 and HTTP/1.1 against independently provisioned origin roots.
    ///
    /// # Errors
    /// Rejects empty roots, invalid limits or an unavailable TLS cryptographic suite.
    pub fn new(roots: RootCertStore, limits: OriginLimits) -> Result<Self, OriginError> {
        if roots.is_empty()
            || limits.handshake_timeout.is_zero()
            || limits.handshake_timeout > Duration::from_secs(60)
            || limits.session_timeout.is_zero()
            || limits.session_timeout > Duration::from_secs(900)
            || limits.max_object_bytes == 0
            || limits.max_object_bytes > MAX_OBJECT_BYTES
        {
            return Err(OriginError::Limit);
        }
        let mut configuration =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| OriginError::Tls)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        configuration.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Self {
            connector: TlsConnector::from(Arc::new(configuration)),
            limits,
        })
    }

    /// Authenticate origin metadata through this call's own hostname-verified TLS handshake.
    ///
    /// The caller supplies a policy-authorized application stream, normally through the
    /// existing transparent MPTCP overlay. This method never dials, resolves or redirects.
    /// `now_unix` is trusted caller time; elapsed monotonic time counts throughout the call.
    ///
    /// # Errors
    /// Rejects TLS/name errors, HTTP ambiguity, noncanonical descriptors, wrong resource or
    /// representation, expiry, invalid origin-authorized signatures and resource exhaustion.
    pub async fn authenticate_manifest<S>(
        &self,
        stream: S,
        request: &OriginRequest,
        now_unix: u64,
    ) -> Result<OriginAuthorizedManifest, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let clock = Clock::new(now_unix)?;
        timeout(self.limits.session_timeout, async {
            let mut tls = self.connect(stream, request).await?;
            send_request(
                &mut tls,
                request,
                &request.metadata_path,
                ORIGIN_DESCRIPTOR_CONTENT_TYPE,
            )
            .await?;
            let response = read_response(&mut tls).await?;
            if response.content_type != ORIGIN_DESCRIPTOR_CONTENT_TYPE
                || response.length > MAX_DESCRIPTOR_BYTES as u64
            {
                return Err(OriginError::Response);
            }
            let mut bytes =
                vec![0; usize::try_from(response.length).map_err(|_| OriginError::Limit)?];
            tls.read_exact(&mut bytes).await?;
            let descriptor =
                Descriptor::decode(bytes.as_slice()).map_err(|_| OriginError::Descriptor)?;
            if descriptor.encode_to_vec() != bytes {
                return Err(OriginError::Descriptor);
            }
            let now = clock.now(now_unix)?;
            let manifest =
                validate_descriptor(&descriptor, request, now, self.limits.max_object_bytes)?;
            let expires = descriptor
                .expires_unix
                .min(response.deadline(clock.unix)?)
                .min(
                    descriptor
                        .issued_unix
                        .checked_add(response.max_age)
                        .ok_or(OriginError::Expired)?,
                );
            if now >= expires {
                return Err(OriginError::Expired);
            }
            Ok(OriginAuthorizedManifest {
                request: request.clone(),
                manifest,
                expires,
                clock,
            })
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }

    /// Fetch one complete origin representation against the *same* authenticated manifest.
    ///
    /// Existing peer chunks may be reused afterward, but every origin chunk and the whole
    /// response must match the original manifest. An origin update is not silently adopted.
    /// A failure can leave only individually authenticated original-version chunks in cache;
    /// it never returns a successful mixed/new object. Output publication remains separate.
    ///
    /// # Errors
    /// Rejects expired authority, changed HTTP metadata/bytes, TLS errors, deadlines or quotas.
    pub async fn fill_from_origin<S>(
        &self,
        stream: S,
        authorized: &OriginAuthorizedManifest,
        store: &mut ChunkStore,
        now_unix: u64,
    ) -> Result<u64, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request_started = authorized.check_time(now_unix)?;
        let lifetime = Duration::from_secs(authorized.expires - request_started);
        store.require_object_capacity(authorized.manifest.length())?;
        timeout(self.limits.session_timeout.min(lifetime), async {
            let mut tls = self.connect(stream, &authorized.request).await?;
            send_request(
                &mut tls,
                &authorized.request,
                &target(&authorized.request.resource),
                BINARY_TYPE,
            )
            .await?;
            let response = read_response(&mut tls).await?;
            authorized.check_time(now_unix)?;
            if response.content_type != BINARY_TYPE
                || response.length != authorized.manifest.length()
                || response.deadline(request_started)? < authorized.expires
                || response.length > self.limits.max_object_bytes
            {
                return Err(OriginError::Response);
            }
            let mut buffer = vec![0; CHUNK_BYTES];
            let mut whole = Sha256::new();
            for chunk in authorized.manifest.chunks() {
                authorized.check_time(now_unix)?;
                let length = usize::try_from(chunk.length()).map_err(|_| OriginError::Limit)?;
                tls.read_exact(&mut buffer[..length]).await?;
                whole.update(&buffer[..length]);
                store.put_verified(*chunk.id(), &buffer[..length])?;
            }
            if <[u8; 32]>::from(whole.finalize()) != authorized.manifest.whole_hash {
                return Err(OriginError::Descriptor);
            }
            authorized.check_time(now_unix)?;
            Ok(response.length)
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }

    async fn connect<S>(
        &self,
        stream: S,
        request: &OriginRequest,
    ) -> Result<TlsStream<S>, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let name = ServerName::try_from(
            request
                .resource
                .domain()
                .ok_or(OriginError::Request)?
                .to_owned(),
        )
        .map_err(|_| OriginError::Request)?;
        let tls = timeout(
            self.limits.handshake_timeout,
            self.connector.connect(name, stream),
        )
        .await
        .map_err(|_| OriginError::Timeout)?
        .map_err(|_| OriginError::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(OriginError::Tls);
        }
        Ok(tls)
    }
}

/// Origin authority produced only by this module's real verified HTTPS exchange.
///
/// It cannot be deserialized from peer data or reopened from a disk label. Callers must retain
/// this in-memory authority or authenticate the origin again after application restart.
pub struct OriginAuthorizedManifest {
    request: OriginRequest,
    manifest: VerifiedManifest,
    expires: u64,
    clock: Clock,
}

impl OriginAuthorizedManifest {
    /// Native chunk authority for the existing protected-stream transfer protocol.
    ///
    /// This reference alone does not carry HTTP freshness/identity. Use this wrapper's
    /// reconstruction method before presenting the result as the requested HTTPS resource.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }

    /// Atomically expose the complete verified resource while origin authority is still valid.
    ///
    /// # Errors
    /// Rejects expired origin metadata, missing/corrupt chunks, existing output or I/O errors.
    pub fn reassemble_to_file(
        &self,
        stores: &mut [&mut ChunkStore],
        now_unix: u64,
        destination: &Path,
    ) -> Result<u64, OriginError> {
        let now = self.check_time(now_unix)?;
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        let length = crate::reassemble(&self.manifest, stores, now, output.as_file_mut())?;
        output.as_file_mut().sync_all()?;
        self.check_time(now_unix)?;
        output
            .persist_noclobber(destination)
            .map_err(|error| OriginError::Io(error.error))?;
        Ok(length)
    }

    fn check_time(&self, supplied_now: u64) -> Result<u64, OriginError> {
        let now = self.clock.now(supplied_now)?;
        if now >= self.expires {
            return Err(OriginError::Expired);
        }
        self.manifest.check_time(now)?;
        Ok(now)
    }
}

/// Encode a cooperative origin's exact resource-to-manifest authorization document.
///
/// These bytes have no authority by themselves: consumers must fetch them through their own
/// authenticated origin HTTPS connection. The descriptor is not a transferable TLS proof.
///
/// # Errors
/// Rejects invalid publication signatures/validity, unsupported content or invalid expiry.
pub fn encode_origin_descriptor(
    request: &OriginRequest,
    signed: &SignedManifest,
    publisher: &VerifyingKey,
    expires_unix: u64,
    now_unix: u64,
) -> Result<Vec<u8>, OriginError> {
    let manifest = signed.verify(publisher, now_unix)?;
    let descriptor = Descriptor {
        version: VERSION,
        resource_url: request.resource.as_str().into(),
        request_profile: REQUEST_PROFILE,
        status: 200,
        content_type: manifest.metadata().content_type.clone(),
        content_length: manifest.length(),
        issued_unix: now_unix,
        expires_unix,
        publisher: publisher.to_bytes().to_vec(),
        signed_manifest: signed.encode(),
    };
    validate_descriptor(&descriptor, request, now_unix, MAX_OBJECT_BYTES)?;
    Ok(descriptor.encode_to_vec())
}

fn validate_descriptor(
    descriptor: &Descriptor,
    request: &OriginRequest,
    now: u64,
    maximum: u64,
) -> Result<VerifiedManifest, OriginError> {
    if descriptor.version != VERSION
        || descriptor.resource_url != request.resource.as_str()
        || descriptor.request_profile != REQUEST_PROFILE
        || descriptor.status != 200
        || descriptor.content_type != BINARY_TYPE
        || descriptor.content_length > maximum
        || descriptor.signed_manifest.len() > MAX_MANIFEST_BYTES
    {
        return Err(OriginError::Descriptor);
    }
    if descriptor.issued_unix == 0
        || descriptor.issued_unix > now
        || descriptor.expires_unix <= now
        || descriptor.expires_unix <= descriptor.issued_unix
        || descriptor.expires_unix - descriptor.issued_unix > MAX_VALIDITY_SECONDS
    {
        return Err(OriginError::Expired);
    }
    let publisher = VerifyingKey::from_bytes(
        &descriptor
            .publisher
            .as_slice()
            .try_into()
            .map_err(|_| OriginError::Descriptor)?,
    )
    .map_err(|_| OriginError::Descriptor)?;
    let manifest = SignedManifest::decode(&descriptor.signed_manifest)?.verify(&publisher, now)?;
    if manifest.length() != descriptor.content_length
        || manifest.metadata().content_type != descriptor.content_type
        || descriptor.expires_unix > manifest.validity().expires
    {
        return Err(OriginError::Descriptor);
    }
    Ok(manifest)
}

struct Clock {
    start: Instant,
    unix: u64,
}
impl Clock {
    fn new(unix: u64) -> Result<Self, OriginError> {
        if unix == 0 {
            return Err(OriginError::Expired);
        }
        Ok(Self {
            start: Instant::now(),
            unix,
        })
    }
    fn now(&self, supplied: u64) -> Result<u64, OriginError> {
        Ok(supplied.max(
            self.unix
                .checked_add(self.start.elapsed().as_secs())
                .ok_or(OriginError::Expired)?,
        ))
    }
}

fn target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().into(),
    }
}

async fn send_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &OriginRequest,
    path: &str,
    accept: &str,
) -> Result<(), OriginError> {
    let host = request.resource.domain().ok_or(OriginError::Request)?;
    let authority = match request.resource.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.into(),
    };
    let bytes = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(bytes.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

struct Response {
    length: u64,
    content_type: String,
    max_age: u64,
    date_unix: u64,
}

impl Response {
    // With Age=0, current_age is at least both the apparent age from Date and the
    // complete response delay. A future Date never grants extra freshness.
    fn deadline(&self, request_started_unix: u64) -> Result<u64, OriginError> {
        self.date_unix
            .min(request_started_unix)
            .checked_add(self.max_age)
            .ok_or(OriginError::Expired)
    }
}

async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Response, OriginError> {
    let mut bytes = Vec::with_capacity(1024);
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER_BYTES {
            return Err(OriginError::Limit);
        }
        bytes.push(stream.read_u8().await?);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| OriginError::Response)?;
    if !text.is_ascii() {
        return Err(OriginError::Response);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines.next().ok_or(OriginError::Response)?;
    if !status.starts_with("HTTP/1.1 200 ") || status.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(OriginError::Response);
    }
    let mut headers = HeaderMap::new();
    for line in lines {
        if headers.len() == MAX_HEADERS {
            return Err(OriginError::Limit);
        }
        let (name, value) = line.split_once(':').ok_or(OriginError::Response)?;
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| OriginError::Response)?;
        let value = HeaderValue::from_str(value.trim()).map_err(|_| OriginError::Response)?;
        if headers.insert(name, value).is_some() {
            return Err(OriginError::Response);
        }
    }
    for forbidden in [
        "transfer-encoding",
        "content-encoding",
        "vary",
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "location",
        "content-range",
        "trailer",
        "expires",
    ] {
        if headers.contains_key(forbidden) {
            return Err(OriginError::Response);
        }
    }
    if headers.get("age").is_some_and(|age| age.as_bytes() != b"0") {
        return Err(OriginError::Response);
    }
    let length = decimal(header(&headers, "content-length")?)?;
    let date_unix = parse_http_date(header(&headers, "date")?)?;
    let content_type = header(&headers, "content-type")?.to_owned();
    let mut public = false;
    let mut max_age = None;
    for directive in header(&headers, "cache-control")?.split(',').map(str::trim) {
        if directive.eq_ignore_ascii_case("public") && !public {
            public = true;
        } else if let Some(value) = directive.strip_prefix("max-age=") {
            if max_age.replace(decimal(value)?).is_some() {
                return Err(OriginError::Response);
            }
        } else {
            return Err(OriginError::Response);
        }
    }
    let max_age = max_age
        .filter(|age| *age > 0 && *age <= MAX_VALIDITY_SECONDS)
        .ok_or(OriginError::Response)?;
    if !public {
        return Err(OriginError::Response);
    }
    Ok(Response {
        length,
        content_type,
        max_age,
        date_unix,
    })
}

/// Format a cooperative origin's HTTP `Date` using standard IMF-fixdate in GMT.
///
/// # Errors
/// Rejects a timestamp outside the supported UTC calendar range.
pub fn format_http_date(unix_seconds: u64) -> Result<String, OriginError> {
    let timestamp = i64::try_from(unix_seconds).map_err(|_| OriginError::Response)?;
    let date = DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or(OriginError::Response)?;
    Ok(date.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

fn parse_http_date(value: &str) -> Result<u64, OriginError> {
    let date = DateTime::parse_from_rfc2822(value).map_err(|_| OriginError::Response)?;
    let unix = u64::try_from(date.timestamp()).map_err(|_| OriginError::Response)?;
    if format_http_date(unix)? != value {
        return Err(OriginError::Response);
    }
    Ok(unix)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, OriginError> {
    headers
        .get(name)
        .ok_or(OriginError::Response)?
        .to_str()
        .map_err(|_| OriginError::Response)
}
fn decimal(value: &str) -> Result<u64, OriginError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OriginError::Response);
    }
    value.parse().map_err(|_| OriginError::Response)
}

#[derive(Clone, PartialEq, Message)]
struct Descriptor {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(string, tag = "2")]
    resource_url: String,
    #[prost(uint32, tag = "3")]
    request_profile: u32,
    #[prost(uint32, tag = "4")]
    status: u32,
    #[prost(string, tag = "5")]
    content_type: String,
    #[prost(uint64, tag = "6")]
    content_length: u64,
    #[prost(uint64, tag = "7")]
    issued_unix: u64,
    #[prost(uint64, tag = "8")]
    expires_unix: u64,
    #[prost(bytes = "vec", tag = "9")]
    publisher: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    signed_manifest: Vec<u8>,
}

/// Bounded HTTPS-origin authorization and retrieval failure, without URL logging.
#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    /// Existing chunk/manifest verification or storage failed.
    #[error(transparent)]
    Content(#[from] crate::Error),
    /// The caller-supplied stream or explicit output file failed.
    #[error("origin content I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The resource request does not match the supported HTTPS profile.
    #[error("invalid origin content request")]
    Request,
    /// Standard TLS certificate, hostname or protocol verification failed.
    #[error("origin TLS authentication failed")]
    Tls,
    /// HTTP status, cache semantics, representation or framing is unsupported/ambiguous.
    #[error("unsupported or invalid origin HTTP response")]
    Response,
    /// The descriptor does not authorize the exact resource/manifest.
    #[error("invalid origin content descriptor")]
    Descriptor,
    /// Signed, origin or monotonic operation validity has expired.
    #[error("origin content authority expired or not yet valid")]
    Expired,
    /// A configured bound or fixed format size was exceeded.
    #[error("origin content resource limit exceeded")]
    Limit,
    /// TLS or a complete request exceeded its deadline.
    #[error("origin content operation timed out")]
    Timeout,
}
