//! Explicit same-directory sha256sum metadata, authenticated only by the consumer's own TLS.

#[cfg(test)]
mod tests;

use super::{
    AsyncRead, AsyncReadExt, AsyncWrite, Clock, Duration, OriginAuthorizedDigest, OriginClient,
    OriginError, OriginRequest, digest, finish_http_tls, read_response, send_request, target,
    timeout,
};

const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
const MAX_FILENAME_BYTES: usize = 255;
const CHECKSUM_TYPE: &str = "text/plain";

/// An original TLS-authenticated checksum document, not yet usable resource authority.
/// Private fields prevent a peer or caller from substituting a claimed expected hash.
/// Only a second own-origin HEAD can establish length, public eligibility and resource expiry.
pub struct OriginAuthenticatedChecksum {
    request: OriginRequest,
    path: String,
    body: Vec<u8>,
    hash: [u8; 32],
    expires: u64,
    clock: Clock,
}

impl OriginAuthenticatedChecksum {
    fn check_time(&self, now_unix: u64) -> Result<u64, OriginError> {
        let now = self.clock.now(now_unix)?;
        if now >= self.expires {
            return Err(OriginError::Expired);
        }
        Ok(now)
    }
}

fn simple_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FILENAME_BYTES
        && value != "."
        && value != ".."
        && value != "-"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

/// Return the exact resource basename; no percent decoding or filesystem resolution.
pub(super) fn validate_path<'a>(
    request: &'a OriginRequest,
    path: &str,
) -> Result<&'a str, OriginError> {
    if request.metadata_path.is_some()
        || request.resource.query().is_some()
        || path.len() > super::MAX_TARGET_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '%', '\\'])
    {
        return Err(OriginError::Request);
    }
    let resource = request.resource.path();
    let (directory, basename) = resource.rsplit_once('/').ok_or(OriginError::Request)?;
    let (checksum_directory, checksum_name) = path.rsplit_once('/').ok_or(OriginError::Request)?;
    if !simple_filename(basename)
        || !simple_filename(checksum_name)
        || checksum_name == basename
        || directory != checksum_directory
        || directory
            .split('/')
            .skip(1)
            .any(|segment| !simple_filename(segment))
    {
        return Err(OriginError::Request);
    }
    let checksum = request
        .resource
        .join(path)
        .map_err(|_| OriginError::Request)?;
    if checksum.origin() != request.resource.origin() || target(&checksum) != path {
        return Err(OriginError::Request);
    }
    Ok(basename)
}

/// Bounded GNU sha256sum text/binary lines; reject ambiguous, escaped or malformed rows,
/// including unrelated malformed rows. Exactly one basename must match the selected resource.
fn selected_hash(body: &[u8], basename: &str) -> Result<[u8; 32], OriginError> {
    if body.is_empty() || body.len() as u64 > MAX_CHECKSUM_BYTES || !body.is_ascii() {
        return Err(OriginError::Response);
    }
    let text = std::str::from_utf8(body).map_err(|_| OriginError::Response)?;
    let mut selected = None;
    for row in text.lines() {
        if row.len() < 67
            || row.as_bytes()[64] != b' '
            || !matches!(row.as_bytes()[65], b' ' | b'*')
            || !row.as_bytes()[..64].iter().all(u8::is_ascii_hexdigit)
            || !simple_filename(&row[66..])
        {
            return Err(OriginError::Response);
        }
        if &row[66..] == basename {
            if selected.is_some() {
                return Err(OriginError::Response);
            }
            let mut digest = [0; 32];
            hex::decode_to_slice(&row[..64], &mut digest).map_err(|_| OriginError::Response)?;
            selected = Some(digest);
        }
    }
    selected.ok_or(OriginError::DigestUnavailable)
}

impl OriginClient {
    /// Authenticate a small public checksum document over this origin's own TLS connection.
    /// The path is an explicit same-directory sibling, never taken from a peer advertisement.
    /// This token alone cannot authorize resource delivery.
    ///
    /// # Errors
    /// Rejects ambiguous selectors/rows, private or variant responses, wrong TLS identity,
    /// missing/duplicate hashes, excessive bodies, stale metadata or bounded-I/O failure.
    pub async fn authenticate_checksum<S>(
        &self,
        stream: S,
        request: &OriginRequest,
        checksum_path: &str,
        now_unix: u64,
    ) -> Result<OriginAuthenticatedChecksum, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let basename = validate_path(request, checksum_path)?;
        let clock = Clock::new(now_unix)?;
        timeout(self.limits.session_timeout, async {
            let mut tls = self.connect(stream, request).await?;
            send_request(&mut tls, request, checksum_path, CHECKSUM_TYPE, None).await?;
            let response = read_response(&mut tls).await?;
            if response.status != 200
                || response.content_type != CHECKSUM_TYPE
                || response.has_content_location
                || response.length == 0
                || response.length > MAX_CHECKSUM_BYTES
            {
                return Err(OriginError::Response);
            }
            let expires = response.deadline(clock.unix)?;
            if clock.now(now_unix)? >= expires {
                return Err(OriginError::Expired);
            }
            let mut body =
                vec![0; usize::try_from(response.length).map_err(|_| OriginError::Limit)?];
            tls.read_exact(&mut body).await?;
            let hash = selected_hash(&body, basename)?;
            finish_http_tls(&mut tls).await?;
            let token = OriginAuthenticatedChecksum {
                request: request.clone(),
                path: checksum_path.into(),
                body,
                hash,
                expires,
                clock,
            };
            token.check_time(now_unix)?;
            Ok(token)
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }

    /// Complete authority with an independent own-origin resource HEAD, consuming the token.
    /// Absence of Repr-Digest is supported; a supplied digest must match the checksum.
    /// The original checksum clock and earliest HTTP expiry survive both exchanges.
    ///
    /// # Errors
    /// Rejects expired checksum authority, private/ambiguous resource metadata, wrong TLS,
    /// digest conflicts, excessive resources and bounded-I/O failures.
    pub async fn authenticate_checksum_resource<S>(
        &self,
        stream: S,
        token: OriginAuthenticatedChecksum,
        now_unix: u64,
    ) -> Result<OriginAuthorizedDigest, OriginError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let started = token.check_time(now_unix)?;
        let lifetime = Duration::from_secs(token.expires - started);
        timeout(self.limits.session_timeout.min(lifetime), async {
            let mut tls = self.connect(stream, &token.request).await?;
            digest::send_head(&mut tls, &token.request).await?;
            let response = read_response(&mut tls).await?;
            digest::check_response(&response, self.limits.max_object_bytes)?;
            if response.representation_digest.is_some()
                && digest::parse_digest(response.representation_digest.as_deref())? != token.hash
            {
                return Err(OriginError::DigestMismatch);
            }
            let expires = token.expires.min(response.deadline(started)?);
            finish_http_tls(&mut tls).await?;
            let authorized = OriginAuthorizedDigest::from_checksum(
                token.request,
                token.hash,
                response.length,
                expires,
                token.clock,
                token.path,
                token.body.len() as u64,
            );
            authorized.check_validity(now_unix)?;
            Ok(authorized)
        })
        .await
        .map_err(|_| OriginError::Timeout)?
    }
}
