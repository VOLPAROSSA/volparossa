//! Explicit unprivileged content-service and retrieval operations.

use prost::Message;

use crate::ControlProtocolError;

/// Explicit transfer of one native object from a user cache to the agent; private by default.
#[derive(Clone, PartialEq, Message)]
pub struct ContentImportRequest {
    /// Exact canonical manifest signed by the independently trusted sender.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Independently trusted sender's Ed25519 public key.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// New absolute agent-owned cache path; existing directories are never adopted.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// Explicit agent cache budget.
    #[prost(message, optional, tag = "4")]
    pub limits: Option<ContentCacheLimits>,
    /// Explicitly allow ordinary native publications; never confers HTTPS-origin authority.
    #[prost(bool, tag = "5")]
    pub allow_public_content: bool,
}

/// Explicit transfer from an existing agent-owned cache to the user; private by default.
#[derive(Clone, PartialEq, Message)]
pub struct ContentExportRequest {
    /// Exact canonical manifest signed by the independently trusted sender.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Independently trusted sender's Ed25519 public key.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// Existing absolute agent-owned cache path; no ownership changes are made.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// Explicit agent cache budget.
    #[prost(message, optional, tag = "4")]
    pub limits: Option<ContentCacheLimits>,
    /// Explicitly allow ordinary native publications; private-message validation is unchanged.
    #[prost(bool, tag = "5")]
    pub allow_public_content: bool,
}

/// Permission to begin a bounded chunk exchange on this same local socket, not completion.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ContentTransferReady {
    /// SHA-256 of the exact independently verified canonical signed manifest.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest_id: Vec<u8>,
    /// Expected complete object bytes, not bytes already transferred.
    #[prost(uint64, tag = "2")]
    pub bytes: u64,
    /// Expected complete ordered chunk count, not chunks already transferred.
    #[prost(uint32, tag = "3")]
    pub chunks: u32,
}

impl ContentImportRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        validate_path(&self.cache)?;
        validate_limits(self.limits)
    }
}

impl ContentExportRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        validate_path(&self.cache)?;
        validate_limits(self.limits)
    }
}

impl ContentTransferReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.manifest_id.len() != 32
            || self.bytes > 256 * 1024 * 1024
            || self.chunks > 1024
            || u64::from(self.chunks) != self.bytes.div_ceil(256 * 1024)
        {
            return Err(ControlProtocolError::Invalid(
                "invalid content transfer readiness",
            ));
        }
        Ok(())
    }
}

/// Resource limits for explicitly selected owned caches; never a privileged operation.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct ContentCacheLimits {
    /// Maximum cached payload bytes.
    #[prost(uint64, tag = "1")]
    pub quota_bytes: u64,
    /// Maximum indexed chunks.
    #[prost(uint32, tag = "2")]
    pub max_entries: u32,
    /// Filesystem free-space floor.
    #[prost(uint64, tag = "3")]
    pub min_free_bytes: u64,
}

/// Explicit bounded background uptake and re-serving; absent configuration starts no cache job.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ContentReplicationConfig {
    /// Private agent-owned replica store, distinct from the primary publication cache.
    #[prost(string, tag = "1")]
    pub replica_cache: String,
    /// One shared byte/entry/free-space budget for the entire replica store.
    #[prost(message, optional, tag = "2")]
    pub limits: Option<ContentCacheLimits>,
    /// Maximum encoded bytes per replication exchange, from 64 bytes through 1 MiB.
    #[prost(uint64, tag = "3")]
    pub max_bytes: u64,
    /// Maximum accepted chunks per exchange, at most four.
    #[prost(uint32, tag = "4")]
    pub max_chunks: u32,
    /// Explicitly reopen an owned replica store and restore its original storage-only records.
    /// False preserves exclusive creation; neither setting activates a listener on its own.
    #[prost(bool, tag = "5")]
    pub reuse_replica_cache: bool,
}

/// Register one explicit publication and start/reuse the agent's bounded public content service.
#[derive(Clone, PartialEq, Message)]
pub struct ContentServeRequest {
    /// Exact canonical signed manifest; not extracted from browsing.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Publisher key already trusted by the local operator.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// Absolute existing cache directory owned by the unprivileged agent account.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// Explicit local socket address; no network listener is enabled by default.
    #[prost(string, tag = "4")]
    pub bind_address: String,
    /// Canonical published DNS hostname; does not grant destination-policy authority.
    #[prost(string, tag = "5")]
    pub advertised_hostname: String,
    /// Explicit cache budget.
    #[prost(message, optional, tag = "6")]
    pub limits: Option<ContentCacheLimits>,
    /// Explicit opt-in to bounded background replication; absence preserves prior behavior.
    #[prost(message, optional, tag = "7")]
    pub replication: Option<ContentReplicationConfig>,
    /// Explicit service-wide publisher/name metadata lookup; false preserves exact-ID serving.
    #[prost(bool, tag = "8")]
    pub name_lookup: bool,
}

/// Resolve a native publisher-local name and deliver verified bytes on this same local socket.
/// A cache-local revision floor prevents silent rollback; no global latest-version claim.
#[derive(Clone, PartialEq, Message)]
pub struct ContentFetchNameRequest {
    /// Publisher key independently trusted by the caller, never adopted from a provider.
    #[prost(bytes = "vec", tag = "1")]
    pub publisher_key: Vec<u8>,
    /// Exact publisher-local UTF-8 label, not a DNS name or URL.
    #[prost(string, tag = "2")]
    pub name: String,
    /// Optional positive initial floor, in addition to the cache's retained observations.
    #[prost(uint64, optional, tag = "3")]
    pub min_revision: Option<u64>,
    /// Private agent-owned cache; no user output path is sent to the agent.
    #[prost(string, tag = "4")]
    pub cache: String,
    /// Explicit cache budget.
    #[prost(message, optional, tag = "5")]
    pub limits: Option<ContentCacheLimits>,
    /// Reopen only a previously owned cache, preserving its durable observed revision floor.
    #[prost(bool, tag = "6")]
    pub reuse_cache: bool,
}

impl ContentFetchNameRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.publisher_key.len() != 32
            || self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
            || self.min_revision == Some(0)
        {
            return Err(ControlProtocolError::Invalid("invalid native name request"));
        }
        validate_path(&self.cache)?;
        validate_limits(self.limits)
    }
}

/// Original signed envelope for this request's following bounded local transfer, not completion.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct NamedContentTransferReady {
    /// Caller verifies this against its original publisher key, exact name and minimum revision.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
}

impl NamedContentTransferReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.manifest.is_empty() || self.manifest.len() > 64 * 1024 {
            return Err(ControlProtocolError::Invalid(
                "invalid native name readiness",
            ));
        }
        Ok(())
    }
}

/// Discover providers and reconstruct one exact independently authenticated native publication.
#[derive(Clone, PartialEq, Message)]
pub struct ContentFetchRequest {
    /// Exact canonical signed manifest, not a name/URL lookup.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Publisher key already trusted by the local operator.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// Private cache directory created by default; explicit reuse opens only an owned cache.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// New output path exposed only after complete verification; never overwritten.
    #[prost(string, tag = "4")]
    pub output: String,
    /// Explicit cache budget.
    #[prost(message, optional, tag = "5")]
    pub limits: Option<ContentCacheLimits>,
    /// Explicitly reopen a previously created agent-owned cache; never adopt another directory.
    #[prost(bool, tag = "6")]
    pub reuse_cache: bool,
}

/// Bounded source selection after fresh HTTPS authorization; never a policy or trust bypass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum HttpsSourceStrategy {
    /// Select available sources without requiring provider-first discovery.
    Auto = 0,
    /// Explicitly prefer peers; this choice does not promise a speed improvement.
    PeersFirst = 1,
    /// Use the authenticated origin and already verified local chunks, without peer retrieval.
    OriginOnly = 2,
}

/// Fetch public chunks authorized by the requested resource's own authenticated HTTPS origin.
#[derive(Clone, PartialEq, Message)]
pub struct HttpsContentFetchRequest {
    /// Exact canonical HTTPS resource; not persisted as a browsing history entry.
    #[prost(string, tag = "1")]
    pub resource_url: String,
    /// Explicit metadata path on that same origin; never an independently trusted manifest.
    #[prost(string, tag = "2")]
    pub metadata_path: String,
    /// Private cache directory created by default; explicit reuse opens only an owned cache.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// New verified output path; existing entries are never overwritten.
    #[prost(string, tag = "4")]
    pub output: String,
    /// Explicit bounded cache budget.
    #[prost(message, optional, tag = "5")]
    pub limits: Option<ContentCacheLimits>,
    /// Optional explicitly selected public PEM trust roots, at most 128 KiB.
    /// Empty means the agent uses Debian system roots; no certificates are installed.
    #[prost(bytes = "vec", tag = "6")]
    pub ca_certificates_pem: Vec<u8>,
    /// Reopen only an owned cache; cached chunks never replace fresh HTTPS origin authorization.
    #[prost(bool, tag = "7")]
    pub reuse_cache: bool,
    /// Source preference; omitted legacy fields select Auto, with unchanged origin authorization.
    #[prost(enumeration = "HttpsSourceStrategy", tag = "8")]
    pub source_strategy: i32,
}

/// Same-operation local handoff after the agent's own fresh HTTPS authorization.
/// Never a transferable origin proof or authority accepted from storage peers/disk.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct HttpsContentTransferReady {
    /// Original canonical native manifest authenticated by the requested HTTPS origin.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Publisher key from that origin authorization, not a separate peer trust anchor.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// Exact resource from the correlated local request.
    #[prost(string, tag = "3")]
    pub resource_url: String,
    /// Original HTTP/manifest expiry, never renewed by this local transfer.
    #[prost(uint64, tag = "4")]
    pub expires_unix_seconds: u64,
}

impl HttpsContentTransferReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        if self.resource_url.len() > 4096
            || !self.resource_url.starts_with("https://")
            || self.resource_url.bytes().any(|b| b.is_ascii_control())
            || self.expires_unix_seconds == 0
        {
            return Err(ControlProtocolError::Invalid(
                "invalid local HTTPS readiness",
            ));
        }
        Ok(())
    }
}

/// Actual successful content work, separate from route or generic alpha readiness.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ContentReceipt {
    /// Fully reconstructed output bytes, zero for service management.
    #[prost(uint64, tag = "1")]
    pub bytes: u64,
    /// Verified ordered chunks in the reconstructed object.
    #[prost(uint32, tag = "2")]
    pub chunks: u32,
    /// Independent providers that supplied verified payload, not merely DHT hints.
    #[prost(uint32, tag = "3")]
    pub providers_used: u32,
    /// Whether the explicit local provider listener remains active.
    #[prost(bool, tag = "4")]
    pub serving: bool,
    /// Explicit registered manifests on that local service.
    #[prost(uint32, tag = "5")]
    pub publications: u32,
    /// Verified suppliers for this explicit operation only; never a background browsing log.
    #[prost(string, repeated, tag = "6")]
    pub provider_peer_ids: Vec<String>,
    /// Carrying route's control Relay, or empty when no route is retained.
    #[prost(string, tag = "7")]
    pub control_relay_peer_id: String,
    /// Whether this operation authenticated its descriptor through genuine origin HTTPS.
    #[prost(bool, tag = "8")]
    pub origin_authenticated: bool,
    /// Body bytes received from the authenticated origin, excluding metadata/TLS overhead.
    #[prost(uint64, tag = "9")]
    pub origin_body_bytes: u64,
    /// Verified payload bytes obtained from content peers for this operation.
    #[prost(uint64, tag = "10")]
    pub peer_bytes: u64,
    /// Actual origin range requests; not a statement about browser integration or speed.
    #[prost(uint32, tag = "11")]
    pub origin_range_requests: u32,
    /// Whether the explicit opportunistic replica job is enabled.
    #[prost(bool, tag = "12")]
    pub replication_enabled: bool,
    /// Actual currently cached replica chunks, not configured capacity or received hints.
    #[prost(uint32, tag = "13")]
    pub replica_chunks: u32,
    /// Actual payload bytes retained in the shared replica cache.
    #[prost(uint64, tag = "14")]
    pub replica_bytes: u64,
    /// Actual replica publications registered for re-serving.
    #[prost(uint32, tag = "15")]
    pub replica_publications: u32,
}

impl ContentReplicationConfig {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_path(&self.replica_cache)?;
        validate_limits(self.limits)?;
        if self
            .limits
            .is_none_or(|limits| limits.quota_bytes > 256 * 1024 * 1024)
            || !(64..=1024 * 1024).contains(&self.max_bytes)
            || !(1..=4).contains(&self.max_chunks)
        {
            return Err(ControlProtocolError::Invalid(
                "invalid content replication limits",
            ));
        }
        Ok(())
    }
}

impl ContentServeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        validate_path(&self.cache)?;
        validate_limits(self.limits)?;
        if let Some(replication) = &self.replication {
            replication.validate()?;
            if replication.replica_cache == self.cache {
                return Err(ControlProtocolError::Invalid(
                    "replica cache must differ from primary cache",
                ));
            }
        }
        let address: std::net::SocketAddr = self
            .bind_address
            .parse()
            .map_err(|_| ControlProtocolError::Invalid("invalid content listen address"))?;
        if self.bind_address.len() > 64
            || address.port() == 0
            || self.advertised_hostname.is_empty()
            || self.advertised_hostname.len() > 253
            || !self
                .advertised_hostname
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        {
            return Err(ControlProtocolError::Invalid("invalid content endpoint"));
        }
        Ok(())
    }
}

impl ContentFetchRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        validate_path(&self.cache)?;
        validate_path(&self.output)?;
        validate_limits(self.limits)
    }
}

impl HttpsContentFetchRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        self.validate_common()?;
        validate_path(&self.output)
    }

    pub(crate) fn validate_download(&self) -> Result<(), ControlProtocolError> {
        self.validate_common()?;
        if !self.output.is_empty() {
            return Err(ControlProtocolError::Invalid(
                "local HTTPS download must not send an output path",
            ));
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ControlProtocolError> {
        if HttpsSourceStrategy::try_from(self.source_strategy).is_err()
            || self.resource_url.len() > 4096
            || !self.resource_url.starts_with("https://")
            || self.resource_url.bytes().any(|b| b.is_ascii_control())
            || self.metadata_path.len() > 4096
            || !self.metadata_path.starts_with('/')
            || self.metadata_path.starts_with("//")
            || !self.metadata_path.bytes().all(|b| b.is_ascii_graphic())
            || self.metadata_path.contains(['#', '\\'])
            || self.ca_certificates_pem.len() > 128 * 1024
        {
            return Err(ControlProtocolError::Invalid(
                "invalid HTTPS content request",
            ));
        }
        // Full URL/metadata canonicalization is repeated by the CLI and agent's OriginRequest.
        validate_path(&self.cache)?;
        validate_limits(self.limits)
    }
}

fn validate_publication(manifest: &[u8], key: &[u8]) -> Result<(), ControlProtocolError> {
    if manifest.is_empty() || manifest.len() > 64 * 1024 || key.len() != 32 {
        return Err(ControlProtocolError::Invalid(
            "invalid content manifest or publisher key",
        ));
    }
    Ok(())
}

pub(super) fn validate_path(value: &str) -> Result<(), ControlProtocolError> {
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|b| b.is_ascii_control())
        || !std::path::Path::new(value).is_absolute()
    {
        return Err(ControlProtocolError::Invalid(
            "content path must be bounded and absolute",
        ));
    }
    Ok(())
}

pub(super) fn validate_limits(
    value: Option<ContentCacheLimits>,
) -> Result<(), ControlProtocolError> {
    if !value.is_some_and(|v| v.quota_bytes > 0 && (1..=65_536).contains(&v.max_entries)) {
        return Err(ControlProtocolError::Invalid(
            "invalid content cache limits",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
        control_request::Operation, control_response::Payload, decode_request, decode_response,
        encode_request, encode_response,
    };

    #[test]
    fn named_content_request_and_ready_are_bounded_and_opt_in() {
        let named = ContentFetchNameRequest {
            publisher_key: vec![2; 32],
            name: "Exact Naam".into(),
            min_revision: Some(3),
            cache: "/private/name-cache".into(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 1024,
                max_entries: 4,
                min_free_bytes: 0,
            }),
            reuse_cache: true,
        };
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            operation: Some(Operation::ContentFetchName(named.clone())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "NAMED_CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::NamedContentTransferReady(
                NamedContentTransferReady {
                    manifest: vec![4; 1024],
                },
            )),
        };
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
        for invalid in ["", "line\nbreak", &"é".repeat(65)] {
            let mut changed = named.clone();
            changed.name = invalid.into();
            assert!(changed.validate().is_err());
        }
        let mut changed = named;
        changed.min_revision = Some(0);
        assert!(changed.validate().is_err());
        changed.min_revision = None;
        assert!(changed.validate().is_ok());
        assert!(
            NamedContentTransferReady {
                manifest: vec![0; 64 * 1024 + 1]
            }
            .validate()
            .is_err()
        );
        let mut serve = ContentServeRequest::default();
        assert!(
            !ContentServeRequest::decode(serve.encode_to_vec().as_slice())
                .unwrap()
                .name_lookup
        );
        let mut original = serve.encode_to_vec();
        original.extend([0x40, 1]);
        serve.name_lookup = true;
        assert_eq!(serve.encode_to_vec(), original);
    }

    #[test]
    fn content_ciphertext_handoff_has_distinct_ready_and_unchanged_frame_limit() {
        let import = ContentImportRequest {
            manifest: vec![1; 256],
            publisher_key: vec![2; 32],
            cache: "/owned/new-cache".into(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 8 * 1024 * 1024,
                max_entries: 32,
                min_free_bytes: 0,
            }),
            allow_public_content: false,
        };
        let export = ContentExportRequest {
            manifest: import.manifest.clone(),
            publisher_key: import.publisher_key.clone(),
            cache: import.cache.clone(),
            limits: import.limits,
            allow_public_content: false,
        };
        for operation in [
            Operation::ContentImport(import.clone()),
            Operation::ContentExport(export),
        ] {
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![3; 16],
                operation: Some(operation),
            };
            assert_eq!(
                decode_request(&encode_request(&request).expect("encode")).expect("decode"),
                request
            );
        }
        // The absent tag remains false for old callers; public transfer is an explicit opt-in.
        let encoded_private = import.encode_to_vec();
        assert!(
            !ContentImportRequest::decode(encoded_private.as_slice())
                .unwrap()
                .allow_public_content
        );
        let mut public = import.clone();
        public.allow_public_content = true;
        let mut expected_public = encoded_private;
        expected_public.extend([0x28, 0x01]); // bool field 5, true; no new frame or protocol version.
        assert_eq!(public.encode_to_vec(), expected_public);
        assert!(
            ContentImportRequest::decode(expected_public.as_slice())
                .unwrap()
                .allow_public_content
        );
        let mut ready = ContentTransferReady {
            manifest_id: vec![4; 32],
            bytes: 4 * 1024 * 1024 + 64,
            chunks: 17,
        };
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::ContentTransferReady(ready.clone())),
        };
        assert_eq!(
            decode_response(&encode_response(&response).expect("encode")).expect("decode"),
            response
        );
        ready.bytes = 0;
        ready.chunks = 0;
        assert!(ready.validate().is_ok());
        ready.bytes = 1;
        assert!(ready.validate().is_err());
        ready.bytes = 256 * 1024 * 1024;
        ready.chunks = 1024;
        assert!(ready.validate().is_ok());
        ready.bytes = 256 * 1024 * 1024 + 1;
        assert!(ready.validate().is_err());
        let mut invalid = import;
        invalid.cache = "relative".into();
        assert!(invalid.validate().is_err());
        assert_eq!(crate::MAX_CONTROL_FRAME, 256 * 1024);
    }

    #[test]
    fn content_requests_are_typed_bounded_and_require_explicit_trust_and_paths() {
        let mut fetch = ContentFetchRequest {
            reuse_cache: false,
            manifest: vec![1; 256],
            publisher_key: vec![2; 32],
            cache: "/private/new-cache".into(),
            output: "/private/new-output".into(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 1024 * 1024,
                max_entries: 16,
                min_free_bytes: 0,
            }),
        };
        let serve = ContentServeRequest {
            manifest: fetch.manifest.clone(),
            publisher_key: fetch.publisher_key.clone(),
            cache: "/private/owned-cache".into(),
            bind_address: "127.0.0.1:18080".into(),
            advertised_hostname: "provider.example".into(),
            limits: fetch.limits,
            replication: None,
            name_lookup: false,
        };
        for operation in [
            Operation::ContentFetch(fetch.clone()),
            Operation::ContentServe(serve.clone()),
            Operation::ContentStop(crate::Empty {}),
            Operation::ContentStatus(crate::Empty {}),
        ] {
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![3; 16],
                operation: Some(operation),
            };
            assert_eq!(
                decode_request(&encode_request(&request).expect("encode")).expect("decode"),
                request
            );
        }
        fetch.publisher_key.pop();
        assert!(fetch.validate().is_err());
        fetch.publisher_key.push(2);
        fetch.cache = "relative-cache".into();
        assert!(fetch.validate().is_err());
        fetch.cache = "/private/new-cache".into();
        fetch.manifest.resize(64 * 1024 + 1, 0);
        assert!(fetch.validate().is_err());
        let mut invalid_serve = serve;
        invalid_serve.bind_address = "127.0.0.1:0".into();
        assert!(invalid_serve.validate().is_err());
    }

    #[test]
    fn content_receipt_roundtrip_rejects_inconsistent_or_duplicate_suppliers() {
        let receipt = ContentReceipt {
            bytes: 2_097_275,
            chunks: 9,
            providers_used: 2,
            provider_peer_ids: vec!["12D3ProviderA".into(), "12D3ProviderB".into()],
            ..ContentReceipt::default()
        };
        let response = |value| ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![4; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_OK".into(),
            payload: Some(Payload::Content(value)),
        };
        let valid = response(receipt.clone());
        assert_eq!(
            decode_response(&encode_response(&valid).expect("encode")).expect("decode"),
            valid
        );
        let mut invalid = receipt.clone();
        invalid.providers_used = 3;
        assert!(encode_response(&response(invalid)).is_err());
        let mut invalid = receipt.clone();
        invalid.provider_peer_ids[1] = invalid.provider_peer_ids[0].clone();
        assert!(encode_response(&response(invalid)).is_err());
        let mut invalid = receipt;
        invalid.provider_peer_ids[0] = "https://a.example/secret".into();
        assert!(encode_response(&response(invalid)).is_err());
    }

    fn https_request() -> HttpsContentFetchRequest {
        HttpsContentFetchRequest {
            reuse_cache: false,
            source_strategy: HttpsSourceStrategy::Auto as i32,
            resource_url: "https://origin.example/object.bin".into(),
            metadata_path: "/.well-known/volparossa/object".into(),
            cache: "/private/new-cache".into(),
            output: "/private/new-output".into(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 256 * 1024 * 1024,
                max_entries: 1024,
                min_free_bytes: 0,
            }),
            ca_certificates_pem: Vec::new(),
        }
    }

    #[test]
    fn https_local_download_has_distinct_operation_ready_and_no_user_path() {
        let mut fetch = https_request();
        assert!(fetch.validate().is_ok());
        assert!(fetch.validate_download().is_err());
        fetch.output.clear();
        assert!(fetch.validate().is_err());
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            operation: Some(Operation::ContentDownloadHttps(fetch.clone())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        let mut ready = HttpsContentTransferReady {
            manifest: vec![1; 256],
            publisher_key: vec![2; 32],
            resource_url: fetch.resource_url,
            expires_unix_seconds: 1,
        };
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id,
            result: ControlResult::Ok as i32,
            diagnostic_code: "HTTPS_CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::HttpsContentTransferReady(ready.clone())),
        };
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
        ready.manifest = vec![0; 64 * 1024 + 1];
        assert!(ready.validate().is_err());
        assert_eq!(crate::MAX_CONTROL_FRAME, 256 * 1024);
        assert_eq!(CONTROL_PROTOCOL_VERSION, 2);
    }

    #[test]
    fn content_resume_flag_is_explicit_and_roundtrips_for_both_fetch_types() {
        for reuse_cache in [false, true] {
            let mut https = https_request();
            https.reuse_cache = reuse_cache;
            let native = ContentFetchRequest {
                manifest: vec![1; 256],
                publisher_key: vec![2; 32],
                cache: https.cache.clone(),
                output: https.output.clone(),
                limits: https.limits,
                reuse_cache,
            };
            assert!(!ContentFetchRequest::default().reuse_cache);
            assert!(!HttpsContentFetchRequest::default().reuse_cache);
            for operation in [
                Operation::ContentFetch(native),
                Operation::ContentFetchHttps(https),
            ] {
                let request = ControlRequest {
                    protocol_version: CONTROL_PROTOCOL_VERSION,
                    request_id: vec![8; 16],
                    operation: Some(operation),
                };
                assert_eq!(
                    decode_request(&encode_request(&request).expect("encode resume request"))
                        .expect("decode resume request"),
                    request
                );
            }
        }
    }

    #[test]
    fn https_source_strategy_roundtrips_and_rejects_unknown_values() {
        let original = https_request();
        let legacy = original.encode_to_vec();
        let decoded = HttpsContentFetchRequest::decode(legacy.as_slice()).unwrap();
        assert_eq!(decoded.source_strategy(), HttpsSourceStrategy::Auto);
        assert_eq!(decoded.encode_to_vec(), legacy);
        for strategy in [
            HttpsSourceStrategy::Auto,
            HttpsSourceStrategy::PeersFirst,
            HttpsSourceStrategy::OriginOnly,
        ] {
            let mut fetch = original.clone();
            fetch.source_strategy = strategy as i32;
            if strategy != HttpsSourceStrategy::Auto {
                let mut expected = legacy.clone();
                expected.extend([0x40, u8::try_from(strategy as i32).unwrap()]);
                assert_eq!(fetch.encode_to_vec(), expected, "field eight");
            }
            assert!(fetch.validate().is_ok());
            fetch.output.clear();
            assert!(fetch.validate_download().is_ok());
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![5; 16],
                operation: Some(Operation::ContentDownloadHttps(fetch)),
            };
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        for unknown in [-1, 3, i32::MAX] {
            let mut fetch = original.clone();
            fetch.source_strategy = unknown;
            assert!(fetch.validate().is_err());
            fetch.output.clear();
            assert!(fetch.validate_download().is_err());
        }
    }

    #[test]
    fn https_content_request_roundtrip_bounds_paths_roots_and_metadata() {
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![5; 16],
            operation: Some(Operation::ContentFetchHttps(https_request())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).expect("encode")).expect("decode"),
            request
        );
        for (url, metadata) in [
            ("http://origin.example/object", "/metadata"),
            ("https://origin.example/\nobject", "/metadata"),
            ("https://origin.example/object", "//other.example/metadata"),
            (
                "https://origin.example/object",
                "/metadata\r\nHeader: value",
            ),
            ("https://origin.example/object", "/metadata#fragment"),
        ] {
            let mut invalid = https_request();
            invalid.resource_url = url.into();
            invalid.metadata_path = metadata.into();
            assert!(invalid.validate().is_err());
        }
        for field in ["url", "metadata", "cache", "output", "ca"] {
            let mut invalid = https_request();
            match field {
                "url" => {
                    invalid.resource_url = format!("https://origin.example/{}", "a".repeat(4096));
                }
                "metadata" => invalid.metadata_path = format!("/{}", "a".repeat(4096)),
                "cache" => invalid.cache = "relative".into(),
                "output" => invalid.output = "relative".into(),
                "ca" => invalid.ca_certificates_pem.resize(128 * 1024 + 1, 0),
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "{field}");
        }
    }

    #[test]
    fn https_receipt_requires_origin_auth_and_allows_overlapping_fallback_bytes() {
        let receipt = ContentReceipt {
            bytes: 2_097_275,
            chunks: 9,
            providers_used: 1,
            provider_peer_ids: vec!["12D3ProviderA".into()],
            origin_authenticated: true,
            origin_body_bytes: 2_097_275,
            peer_bytes: 1_048_699,
            origin_range_requests: 1,
            ..ContentReceipt::default()
        };
        let response = |value| ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![6; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_HTTPS_OK".into(),
            payload: Some(Payload::Content(value)),
        };
        let valid = response(receipt.clone());
        assert_eq!(
            decode_response(&encode_response(&valid).expect("overlapping full fallback"))
                .expect("decode"),
            valid
        );
        let mut mixed_origin = receipt.clone();
        mixed_origin.bytes = 256 * 1024 * 1024;
        mixed_origin.chunks = 1024;
        mixed_origin.origin_body_bytes = 384 * 1024 * 1024;
        mixed_origin.peer_bytes = 64 * 1024 * 1024;
        mixed_origin.origin_range_requests = 513;
        let mixed = response(mixed_origin);
        assert_eq!(
            decode_response(&encode_response(&mixed).expect("206 pieces then full 200 body"))
                .expect("decode"),
            mixed
        );
        for field in ["authentication", "origin", "peer", "ranges"] {
            let mut invalid = receipt.clone();
            match field {
                "authentication" => invalid.origin_authenticated = false,
                "origin" => invalid.origin_body_bytes = 512 * 1024 * 1024 + 1,
                "peer" => invalid.peer_bytes = 256 * 1024 * 1024 + 1,
                "ranges" => invalid.origin_range_requests = 1025,
                _ => unreachable!(),
            }
            assert!(encode_response(&response(invalid)).is_err(), "{field}");
        }
        assert!(encode_response(&response(ContentReceipt::default())).is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One opt-in fixture preserves legacy defaults and both budgets.
    fn content_replication_is_explicit_bounded_and_preserves_absent_field_roundtrip() {
        let limits = ContentCacheLimits {
            quota_bytes: 64 * 1024 * 1024,
            max_entries: 256,
            min_free_bytes: 64 * 1024 * 1024,
        };
        let replication = ContentReplicationConfig {
            replica_cache: "/private/new-replicas".into(),
            limits: Some(limits),
            max_bytes: 1024 * 1024,
            max_chunks: 4,
            reuse_replica_cache: false,
        };
        let mut serve = ContentServeRequest {
            manifest: vec![1; 256],
            publisher_key: vec![2; 32],
            cache: "/private/primary".into(),
            bind_address: "127.0.0.1:18080".into(),
            advertised_hostname: "provider.example".into(),
            limits: Some(limits),
            replication: None,
            name_lookup: false,
        };
        let mut resumed = replication.clone();
        resumed.reuse_replica_cache = true;
        let mut expected_reuse_wire = replication.encode_to_vec();
        expected_reuse_wire.extend_from_slice(&[0x28, 0x01]); // New bool tag5, absent when false.
        assert_eq!(resumed.encode_to_vec(), expected_reuse_wire);
        assert!(
            !ContentReplicationConfig::decode(replication.encode_to_vec().as_slice())
                .unwrap()
                .reuse_replica_cache
        );
        for option in [None, Some(replication.clone()), Some(resumed)] {
            serve.replication = option;
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![7; 16],
                operation: Some(Operation::ContentServe(serve.clone())),
            };
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        for field in [
            "path", "same", "quota", "entries", "bytes", "chunks", "zero", "minimum", "limits",
        ] {
            let mut invalid = replication.clone();
            match field {
                "path" => invalid.replica_cache = "relative".into(),
                "same" => invalid.replica_cache.clone_from(&serve.cache),
                "quota" => invalid.limits.as_mut().unwrap().quota_bytes = 256 * 1024 * 1024 + 1,
                "entries" => invalid.limits.as_mut().unwrap().max_entries = 65_537,
                "bytes" => invalid.max_bytes = 1024 * 1024 + 1,
                "chunks" => invalid.max_chunks = 5,
                "zero" => invalid.max_bytes = 0,
                "minimum" => invalid.max_bytes = 63,
                "limits" => invalid.limits = None,
                _ => unreachable!(),
            }
            serve.replication = Some(invalid);
            assert!(serve.validate().is_err(), "{field}");
        }
        let receipt = ContentReceipt {
            serving: true,
            replication_enabled: true,
            replica_chunks: 4,
            replica_bytes: 1024 * 1024,
            replica_publications: 1,
            ..ContentReceipt::default()
        };
        let response = |value| ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![8; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_OK".into(),
            payload: Some(Payload::Content(value)),
        };
        let valid = response(receipt.clone());
        assert_eq!(
            decode_response(&encode_response(&valid).unwrap()).unwrap(),
            valid
        );
        for field in ["bytes", "chunks", "publications"] {
            let mut invalid = receipt.clone();
            match field {
                "bytes" => invalid.replica_bytes = 256 * 1024 * 1024 + 1,
                "chunks" => invalid.replica_chunks = 65_537,
                "publications" => invalid.replica_publications = 65,
                _ => unreachable!(),
            }
            assert!(encode_response(&response(invalid)).is_err(), "{field}");
        }
        let inert = ContentReceipt::default();
        assert!(!inert.replication_enabled);
        assert_eq!(
            (
                inert.replica_chunks,
                inert.replica_bytes,
                inert.replica_publications
            ),
            (0, 0, 0)
        );
    }
}
