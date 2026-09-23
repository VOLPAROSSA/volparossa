//! One publisher-authorized public custody operation on the existing protected local socket.

use prost::Message;

use crate::ControlProtocolError;

/// Select an independently known provider; no cache path or signing secret reaches the agent.
#[derive(Clone, PartialEq, Message)]
pub struct ContentCustodyRequest {
    /// Expected remote provider Ed25519 key, independently authenticated by the caller.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original canonical signed public manifest.
    #[prost(bytes = "vec", tag = "2")]
    pub manifest: Vec<u8>,
    /// Independently selected publisher; its signature authorizes the following transaction.
    #[prost(bytes = "vec", tag = "3")]
    pub publisher_key: Vec<u8>,
    /// Public custody operation: Deposit=1 or Inspect=2.
    #[prost(int32, tag = "4")]
    pub operation: i32,
    /// Opt-in spare-capacity work; false preserves explicit foreground custody.
    #[prost(bool, tag = "5")]
    pub background: bool,
}

/// Discover public storage candidates without publishing object selectors to discovery.
#[derive(Clone, PartialEq, Message)]
pub struct ContentCustodyDiscoverRequest {
    /// Exact original public manifest, checked only by the local agent.
    #[prost(bytes = "vec", tag = "1")]
    pub manifest: Vec<u8>,
    /// Independently selected original publisher.
    #[prost(bytes = "vec", tag = "2")]
    pub publisher_key: Vec<u8>,
    /// One bounded discovery round, at most sixteen authenticated offers.
    #[prost(uint32, tag = "3")]
    pub max_providers: u32,
}

/// Authenticated service hint, not a capacity claim or storage commitment.
#[derive(Clone, PartialEq, Message)]
pub struct ContentCustodyProvider {
    /// Offer's authenticated provider identity.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original signed offer expiry in Unix seconds.
    #[prost(uint64, tag = "2")]
    pub offer_expires_unix_seconds: u64,
}

/// Current route-distinct candidates; only actual custody receipts establish retention.
#[derive(Clone, PartialEq, Message)]
pub struct ContentCustodyDiscovered {
    /// At most sixteen distinct, currently authenticated service hints.
    #[prost(message, repeated, tag = "1")]
    pub providers: Vec<ContentCustodyProvider>,
    /// Carrying route's exact control relay, never a new authority.
    #[prost(string, tag = "2")]
    pub control_relay_peer_id: String,
}

impl ContentCustodyDiscoverRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.publisher_key.len() != 32
            || self.manifest.is_empty()
            || self.manifest.len() > 64 * 1024
            || !(1..=16).contains(&self.max_providers)
        {
            return Err(ControlProtocolError::Invalid(
                "public custody discovery scope",
            ));
        }
        Ok(())
    }
}

impl ContentCustodyDiscovered {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        let mut keys = std::collections::BTreeSet::new();
        if self.providers.len() > 16
            || self.control_relay_peer_id.is_empty()
            || self.control_relay_peer_id.len() > crate::MAX_PEER_ID_BYTES
            || self.providers.iter().any(|provider| {
                provider.provider_key.len() != 32
                    || provider.offer_expires_unix_seconds == 0
                    || !keys.insert(&provider.provider_key)
            })
        {
            return Err(ControlProtocolError::Invalid(
                "public custody discovery result",
            ));
        }
        Ok(())
    }
}

/// Connection-specific signed challenge; this is not a storage receipt.
#[derive(Clone, PartialEq, Message)]
pub struct ContentCustodyReady {
    /// Exact provider selected in the original request.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original bounded provider-signed challenge for this protected stream.
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
}

impl ContentCustodyRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32
            || self.publisher_key.len() != 32
            || self.manifest.is_empty()
            || self.manifest.len() > 64 * 1024
            || !matches!(self.operation, 1 | 2)
        {
            return Err(ControlProtocolError::Invalid("public custody scope"));
        }
        Ok(())
    }
}

impl ContentCustodyReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 || self.challenge.is_empty() || self.challenge.len() > 2048
        {
            return Err(ControlProtocolError::Invalid("public custody readiness"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, control_request::Operation, decode_request,
        encode_request,
    };

    #[test]
    fn public_custody_local_scope_roundtrips_and_rejects_unknown_operations() {
        let mut custody = ContentCustodyRequest {
            provider_key: vec![1; 32],
            publisher_key: vec![2; 32],
            manifest: vec![3; 256],
            operation: 1,
            background: false,
        };
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![4; 16],
            operation: Some(Operation::ContentCustody(custody.clone())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        custody.operation = 2;
        assert!(custody.validate().is_ok());
        custody.operation = 3;
        assert!(custody.validate().is_err());
        custody.operation = 1;
        custody.provider_key.pop();
        assert!(custody.validate().is_err());
    }

    #[test]
    fn custody_discovery_is_bounded_and_background_is_explicit() {
        let discover = ContentCustodyDiscoverRequest {
            manifest: vec![3; 256],
            publisher_key: vec![2; 32],
            max_providers: 16,
        };
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![4; 16],
            operation: Some(Operation::ContentCustodyDiscover(discover.clone())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        for maximum in [0, 17, u32::MAX] {
            assert!(
                ContentCustodyDiscoverRequest {
                    max_providers: maximum,
                    ..discover.clone()
                }
                .validate()
                .is_err()
            );
        }
        let original = ContentCustodyRequest {
            provider_key: vec![1; 32],
            manifest: vec![3; 256],
            publisher_key: vec![2; 32],
            operation: 1,
            background: false,
        };
        assert!(
            !ContentCustodyRequest::decode(original.encode_to_vec().as_slice())
                .unwrap()
                .background
        );
        let background = ContentCustodyRequest {
            background: true,
            ..original
        };
        assert!(
            ContentCustodyRequest::decode(background.encode_to_vec().as_slice())
                .unwrap()
                .background
        );
    }

    #[test]
    fn custody_discovery_hints_reject_duplicates_and_malformed_bounds() {
        let provider = ContentCustodyProvider {
            provider_key: vec![1; 32],
            offer_expires_unix_seconds: 7,
        };
        let mut found = ContentCustodyDiscovered {
            providers: vec![provider.clone()],
            control_relay_peer_id: "selected-control-peer".into(),
        };
        assert!(found.validate().is_ok());
        found.providers.push(provider.clone());
        assert!(found.validate().is_err());
        found.providers = (0..17)
            .map(|byte| ContentCustodyProvider {
                provider_key: vec![byte; 32],
                ..provider.clone()
            })
            .collect();
        assert!(found.validate().is_err());
        found.providers = vec![ContentCustodyProvider {
            offer_expires_unix_seconds: 0,
            ..provider
        }];
        assert!(found.validate().is_err());
        found.providers.clear();
        assert!(found.validate().is_ok()); // An empty discovery round never claims retention.
    }
}
