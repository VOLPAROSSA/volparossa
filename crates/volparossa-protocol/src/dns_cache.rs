//! Signed cache-only DNSSEC exchange; signatures authenticate peers, never DNS answers.

use prost::Message;
use sha2::{Digest as _, Sha256};

use crate::{ControlMessageType, ControlPayload, ProtocolError};

/// Maximum opaque DNSSEC proof carried by a cache reply.
pub const MAX_DNS_CACHE_BUNDLE_BYTES: usize = 128 * 1024;
/// Short signed RPC lifetime, independent of the DNS proof's original expiry.
pub const MAX_DNS_CACHE_LIFETIME_MS: u64 = 10_000;

/// Positive address lookup scoped to an already authorized policy. Never placed in DHT.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct DnsCacheQuery {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint32, tag = "2")]
    pub query_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub policy_hash: Vec<u8>,
}

impl ControlPayload for DnsCacheQuery {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::DnsCacheQuery;

    fn validate(&self) -> Result<(), ProtocolError> {
        crate::messages::validate_canonical_dns_name(&self.name, "DNS cache question")?;
        if !matches!(self.query_type, 1 | 28) || self.policy_hash.len() != 32 {
            return Err(ProtocolError::InvalidField("DNS cache query"));
        }
        Ok(())
    }
}

/// Correlated opaque proof, or an empty bundle for a cache miss. Not DNS trust authority.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct DnsCacheReply {
    #[prost(bytes = "vec", tag = "1")]
    pub request_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub bundle: Vec<u8>,
}

impl ControlPayload for DnsCacheReply {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::DnsCacheReply;

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.request_hash.len() != 32 || self.bundle.len() > MAX_DNS_CACHE_BUNDLE_BYTES {
            return Err(ProtocolError::InvalidField("DNS cache reply"));
        }
        Ok(())
    }
}

/// Domain-separated correlation digest of the exact signed request (not signature validation).
#[must_use]
pub fn dns_cache_request_hash(request: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"volparossa/dns-cache-request/v1\0");
    digest.update(request);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ReplayCache, TimePolicy, generate_nonce, sign_control_message, verify_control_message,
    };
    use ed25519_dalek::SigningKey;

    #[test]
    fn dns_cache_signatures_replay_expiry_and_exact_reply_correlation() {
        let key = SigningKey::from_bytes(&generate_nonce());
        let policy = TimePolicy {
            maximum_lifetime_ms: MAX_DNS_CACHE_LIFETIME_MS,
            maximum_clock_skew_ms: 0,
        };
        let query = DnsCacheQuery {
            name: "www.example.org".into(),
            query_type: 1,
            policy_hash: vec![1; 32],
        };
        let signed =
            sign_control_message(&query, &key, 1000, 6000, generate_nonce(), policy).unwrap();
        let mut seen = ReplayCache::new(8).unwrap();
        assert_eq!(
            verify_control_message::<DnsCacheQuery>(&signed, 1001, policy, &mut seen)
                .unwrap()
                .message(),
            &query
        );
        assert!(verify_control_message::<DnsCacheQuery>(&signed, 1002, policy, &mut seen).is_err());
        assert!(
            verify_control_message::<DnsCacheQuery>(
                &signed,
                6000,
                policy,
                &mut ReplayCache::new(8).unwrap()
            )
            .is_err()
        );
        let reply = DnsCacheReply {
            request_hash: dns_cache_request_hash(&signed).to_vec(),
            bundle: Vec::new(),
        };
        let receipt =
            sign_control_message(&reply, &key, 1001, 6000, generate_nonce(), policy).unwrap();
        assert_eq!(
            verify_control_message::<DnsCacheReply>(&receipt, 1002, policy, &mut seen)
                .unwrap()
                .message(),
            &reply
        );
        let fresh =
            sign_control_message(&query, &key, 1000, 6000, generate_nonce(), policy).unwrap();
        assert_ne!(
            dns_cache_request_hash(&signed),
            dns_cache_request_hash(&fresh)
        );
        let invalid = DnsCacheQuery {
            query_type: 255,
            ..query
        };
        assert!(invalid.validate().is_err());
        assert!(
            DnsCacheReply {
                bundle: vec![0; MAX_DNS_CACHE_BUNDLE_BYTES + 1],
                ..reply
            }
            .validate()
            .is_err()
        );
    }
}
