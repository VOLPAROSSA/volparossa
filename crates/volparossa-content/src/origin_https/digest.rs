//! Whole-representation authority from the consumer's own HEAD/TLS exchange.
//! Peer chunk indexes remain untrusted until complete reassembly matches that digest.

#[cfg(test)]
mod tests;

use ed25519_dalek::SigningKey;

use super::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BINARY_TYPE, CHUNK_BYTES, ChunkStore,
    Clock, Digest, Duration, OriginClient, OriginError, OriginRequest, Path, Response, Sha256,
    SignedManifest, VerifiedManifest, VerifyingKey, finish_http_tls, read_response, send_request,
    target, timeout,
};
use crate::{Chunk, ChunkId, Metadata, Publication, Validity};

/// Live resource authority, created only by a hostname-verified origin HEAD exchange.
///
/// This is neither a signed chunk-list capability nor a reusable/offline HTTPS proof.
/// Candidate chunks must not be delivered or contributed until full object verification.
pub struct OriginAuthorizedDigest {
    request: OriginRequest,
    hash: [u8; 32],
    length: u64,
    expires: u64,
    clock: Clock,
}

impl OriginAuthorizedDigest {
    /// SHA-256 of the complete identity-encoded representation, not of an individual range.
    pub const fn object_sha256(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Exact complete representation length from the same authenticated response.
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Retain the original HTTP expiry; copying or accepting a candidate never extends it.
    ///
    /// # Errors
    /// Rejects expired original wall/monotonic authority or invalid caller time.
    pub fn check_validity(&self, now_unix: u64) -> Result<u64, OriginError> {
        self.check_time(now_unix)?;
        Ok(self.expires)
    }

    /// Check a bounded, self-consistent peer index against the expected whole-object identity.
    ///
    /// The key hint is not a trusted publisher. The returned manifest only permits transport
    /// and private staging: its individual chunk claims have not been authenticated by origin.
    ///
    /// # Errors
    /// Rejects bad signatures, time/bounds and mismatched digest, length or representation.
    pub fn verify_candidate(
        &self,
        signed: &SignedManifest,
        now_unix: u64,
    ) -> Result<VerifiedManifest, OriginError> {
        let now = self.check_time(now_unix)?;
        let key = VerifyingKey::from_bytes(&signed.publisher_key_hint())
            .map_err(|_| OriginError::DigestMismatch)?;
        let manifest = signed.verify(&key, now)?;
        self.check_candidate(&manifest, now_unix)?;
        Ok(manifest)
    }

    /// Verify all ordered chunks and the complete digest without exposing output bytes.
    ///
    /// Call this before local Ready or automatic contribution; recheck validity at completion.
    ///
    /// # Errors
    /// Rejects missing/corrupt chunks, false chunk lists, mismatched metadata or expired authority.
    pub fn verify_cached(
        &self,
        manifest: &VerifiedManifest,
        store: &mut ChunkStore,
        now_unix: u64,
    ) -> Result<u64, OriginError> {
        self.check_candidate(manifest, now_unix)?;
        let length = crate::reassemble(
            manifest,
            &mut [store],
            self.check_time(now_unix)?,
            &mut std::io::sink(),
        )?;
        self.check_candidate(manifest, now_unix)?;
        Ok(length)
    }

    /// Publish only the fully verified object through an atomic non-overwriting private file.
    ///
    /// # Errors
    /// Rejects incomplete/mismatched bytes, expired authority, unsafe output or filesystem errors.
    pub fn reassemble_to_file(
        &self,
        manifest: &VerifiedManifest,
        stores: &mut [&mut ChunkStore],
        now_unix: u64,
        destination: &Path,
    ) -> Result<u64, OriginError> {
        self.check_candidate(manifest, now_unix)?;
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        let length = crate::reassemble(
            manifest,
            stores,
            self.check_time(now_unix)?,
            temporary.as_file_mut(),
        )?;
        temporary.as_file().sync_all()?;
        self.check_candidate(manifest, now_unix)?;
        temporary
            .persist_noclobber(destination)
            .map_err(|error| OriginError::Io(error.error))?;
        Ok(length)
    }

    fn check_candidate(
        &self,
        manifest: &VerifiedManifest,
        now_unix: u64,
    ) -> Result<(), OriginError> {
        let now = self.check_time(now_unix)?;
        manifest.check_time(now)?;
        if manifest.object_sha256() != &self.hash
            || manifest.length() != self.length
            || manifest.metadata().content_type != BINARY_TYPE
        {
            return Err(OriginError::DigestMismatch);
        }
        Ok(())
    }

    fn check_time(&self, supplied: u64) -> Result<u64, OriginError> {
        let now = self.clock.now(supplied)?;
        if now >= self.expires {
            return Err(OriginError::Expired);
        }
        Ok(now)
    }
}

impl OriginClient {
    /// Authenticate a SHA-256 Repr-Digest using HEAD on this exact resource over real TLS 1.3.
    ///
    /// The caller provides its existing policy-authorized stream. The same strict anonymous
    /// binary/public/no-variants profile applies. Content-Digest is never substituted: on HEAD
    /// it describes empty message content, not the complete representation (RFC 9530 B.2).
    ///
    /// # Errors
    /// Returns `DigestUnavailable` if no supported digest exists; rejects TLS/HTTP ambiguity,
    /// body bytes on HEAD, invalid digests, content-location indirection, expiry and limits.
    pub async fn authenticate_digest<S>(
        &self,
        stream: S,
        request: &OriginRequest,
        now_unix: u64,
    ) -> Result<OriginAuthorizedDigest, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let clock = Clock::new(now_unix)?;
        timeout(self.limits.session_timeout, async {
            let mut tls = self.connect(stream, request).await?;
            send_head(&mut tls, request).await?;
            let response = read_response(&mut tls).await?;
            check_response(&response, self.limits.max_object_bytes)?;
            let hash = parse_digest(response.representation_digest.as_deref())?;
            let expires = response.deadline(clock.unix)?;
            if clock.now(now_unix)? >= expires {
                return Err(OriginError::Expired);
            }
            // Content-Length on HEAD describes the representation; consume no body.
            finish_http_tls(&mut tls).await?;
            let authorized = OriginAuthorizedDigest {
                request: request.clone(),
                hash,
                length: response.length,
                expires,
                clock,
            };
            authorized.check_validity(now_unix)?;
            Ok(authorized)
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }

    /// Fetch one full original representation; sign only a local transport index after verification.
    ///
    /// Streams at most one chunk buffer, never starts a peer/body race and does not upgrade the
    /// local signing key to origin authority. Staged chunks may remain after failure but cannot
    /// be contributed as this object. GET need not repeat Repr-Digest: full bytes must match HEAD.
    ///
    /// # Errors
    /// Rejects changed bytes/metadata, stale authority, TLS/HTTP errors, timeouts and cache bounds.
    pub async fn fill_digest_from_origin<S>(
        &self,
        stream: S,
        authorized: &OriginAuthorizedDigest,
        store: &mut ChunkStore,
        local_signer: &SigningKey,
        now_unix: u64,
    ) -> Result<SignedManifest, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let now = authorized.check_time(now_unix)?;
        store.require_object_capacity(authorized.length)?;
        let lifetime = Duration::from_secs(authorized.expires - now);
        timeout(self.limits.session_timeout.min(lifetime), async {
            let mut tls = self.connect(stream, &authorized.request).await?;
            send_request(
                &mut tls,
                &authorized.request,
                &target(&authorized.request.resource),
                BINARY_TYPE,
                None,
            )
            .await?;
            let response = read_response(&mut tls).await?;
            check_response(&response, self.limits.max_object_bytes)?;
            if response.length != authorized.length || response.deadline(now)? < authorized.expires
            {
                return Err(OriginError::Response);
            }
            if response.representation_digest.is_some()
                && parse_digest(response.representation_digest.as_deref())? != authorized.hash
            {
                return Err(OriginError::DigestMismatch);
            }
            let chunks = receive_body(&mut tls, authorized, store, now_unix).await?;
            finish_http_tls(&mut tls).await?;
            authorized.check_time(now_unix)?;
            let signed = SignedManifest::sign(
                Publication {
                    metadata: Metadata {
                        name: hex::encode(authorized.hash),
                        content_type: BINARY_TYPE.into(),
                        revision: 1,
                    },
                    length: authorized.length,
                    validity: Validity {
                        created: authorized.clock.unix,
                        expires: authorized.expires,
                    },
                },
                chunks,
                authorized.hash,
                local_signer,
            )?;
            authorized.check_time(now_unix)?;
            Ok(signed)
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }
}

async fn receive_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    authorized: &OriginAuthorizedDigest,
    store: &mut ChunkStore,
    now_unix: u64,
) -> Result<Vec<Chunk>, OriginError> {
    let mut remaining = authorized.length;
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    while remaining > 0 {
        authorized.check_time(now_unix)?;
        let length =
            usize::try_from(remaining.min(CHUNK_BYTES as u64)).map_err(|_| OriginError::Limit)?;
        stream.read_exact(&mut buffer[..length]).await?;
        authorized.check_time(now_unix)?;
        whole.update(&buffer[..length]);
        let id = ChunkId::digest(&buffer[..length]);
        store.put_verified(id, &buffer[..length])?;
        chunks.push(Chunk {
            id,
            length: u32::try_from(length).map_err(|_| OriginError::Limit)?,
        });
        remaining -= length as u64;
    }
    if <[u8; 32]>::from(whole.finalize()) != authorized.hash {
        return Err(OriginError::DigestMismatch);
    }
    Ok(chunks)
}

fn check_response(response: &Response, max_bytes: u64) -> Result<(), OriginError> {
    if response.status != 200
        || response.content_type != BINARY_TYPE
        || response.length > max_bytes
        || response.has_content_location
    {
        return Err(OriginError::Response);
    }
    Ok(())
}

async fn send_head<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &OriginRequest,
) -> Result<(), OriginError> {
    let host = request.resource.domain().ok_or(OriginError::Request)?;
    let authority = request
        .resource
        .port()
        .map_or_else(|| host.into(), |port| format!("{host}:{port}"));
    let target = target(&request.resource);
    let head = format!(
        "HEAD {target} HTTP/1.1\r\nHost: {authority}\r\nAccept: {BINARY_TYPE}\r\nAccept-Encoding: identity\r\nWant-Repr-Digest: sha-256=10\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

// Initial explicit RFC 9530 subset: a single SHA-256 byte-sequence dictionary member,
// without parameters or additional algorithms. Unsupported forms never grant authority.
fn parse_digest(value: Option<&str>) -> Result<[u8; 32], OriginError> {
    let value = value.ok_or(OriginError::DigestUnavailable)?;
    if value.contains([',', ';']) {
        return Err(OriginError::DigestUnavailable);
    }
    let encoded = value
        .strip_prefix("sha-256=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or(OriginError::DigestUnavailable)?;
    let bytes = encoded.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return Err(OriginError::Response);
    }
    let mut decoded = [0_u8; 32];
    for (index, group) in bytes[..40].chunks_exact(4).enumerate() {
        let [a, b, c, d] = [
            base64_digit(group[0])?,
            base64_digit(group[1])?,
            base64_digit(group[2])?,
            base64_digit(group[3])?,
        ];
        decoded[index * 3..index * 3 + 3].copy_from_slice(&[
            (a << 2) | (b >> 4),
            (b << 4) | (c >> 2),
            (c << 6) | d,
        ]);
    }
    let [a, b, c] = [
        base64_digit(bytes[40])?,
        base64_digit(bytes[41])?,
        base64_digit(bytes[42])?,
    ];
    if c & 3 != 0 {
        return Err(OriginError::Response);
    }
    decoded[30] = (a << 2) | (b >> 4);
    decoded[31] = (b << 4) | (c >> 2);
    Ok(decoded)
}

fn base64_digit(byte: u8) -> Result<u8, OriginError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(OriginError::Response),
    }
}
