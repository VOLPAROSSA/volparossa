//! Explicit unprivileged content-service and retrieval operations.

use prost::Message;

use crate::ControlProtocolError;

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
    /// New private cache directory created by the agent; no arbitrary directory adoption.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// New output path exposed only after complete verification; never overwritten.
    #[prost(string, tag = "4")]
    pub output: String,
    /// Explicit cache budget.
    #[prost(message, optional, tag = "5")]
    pub limits: Option<ContentCacheLimits>,
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
    /// New private cache directory created by the unprivileged agent account.
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
}

impl ContentServeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        validate_publication(&self.manifest, &self.publisher_key)?;
        validate_path(&self.cache)?;
        validate_limits(self.limits)?;
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
        if self.resource_url.len() > 4096
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
        validate_path(&self.output)?;
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

fn validate_path(value: &str) -> Result<(), ControlProtocolError> {
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

fn validate_limits(value: Option<ContentCacheLimits>) -> Result<(), ControlProtocolError> {
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
    fn content_requests_are_typed_bounded_and_require_explicit_trust_and_paths() {
        let mut fetch = ContentFetchRequest {
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
}
