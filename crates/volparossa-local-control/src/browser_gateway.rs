//! Operator-delegated TCP application gateway. This is not an administrative app API.

use prost::Message;

use crate::ControlProtocolError;

/// Delegate one finite, exact destination/partition scope to an application UID.
#[derive(Clone, PartialEq, Message)]
pub struct BrowserGatewayGrantRequest {
    /// Kernel UID required at the separate application Unix bootstrap socket.
    #[prost(uint32, tag = "1")]
    pub app_uid: u32,
    /// Canonical lowercase ASCII hostname, never an IP address or URL.
    #[prost(string, tag = "2")]
    pub hostname: String,
    /// Exact policy-authorized TCP destination port.
    #[prost(uint32, tag = "3")]
    pub port: u32,
    /// Opaque browser isolation partition; not a URL, account or browsing history.
    #[prost(bytes = "vec", tag = "4")]
    pub partition: Vec<u8>,
    /// Finite grant and attachment lifetime, at most five minutes.
    #[prost(uint32, tag = "5")]
    pub lifetime_seconds: u32,
}

/// Single-use app bootstrap capability. Never log or print this secret generically.
#[derive(Clone, PartialEq, Message)]
pub struct BrowserGatewayGranted {
    /// Separate application socket; it accepts no administrative operations.
    #[prost(string, tag = "1")]
    pub app_socket: String,
    /// Unpredictable, single-use capability bound to the requested kernel UID.
    #[prost(bytes = "vec", tag = "2")]
    pub capability: Vec<u8>,
    /// Hard wall-clock deadline; the agent additionally retains a monotonic deadline.
    #[prost(uint64, tag = "3")]
    pub expires_at_ms: u64,
    /// Exact canonical destination hostname.
    #[prost(string, tag = "4")]
    pub hostname: String,
    /// Exact TCP port.
    #[prost(uint32, tag = "5")]
    pub port: u32,
    /// Exact caller-selected opaque partition.
    #[prost(bytes = "vec", tag = "6")]
    pub partition: Vec<u8>,
}

impl BrowserGatewayGrantRequest {
    /// Check bounds and canonical ASCII authority shape before any delegation.
    ///
    /// # Errors
    /// Rejects ambiguous authority forms, zero/oversized ports or invalid finite scope.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        authority(&self.hostname, self.port, &self.partition)?;
        if !(1..=300).contains(&self.lifetime_seconds) || self.app_uid == u32::MAX {
            return Err(ControlProtocolError::Invalid("application grant scope"));
        }
        Ok(())
    }
}

impl BrowserGatewayGranted {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        authority(&self.hostname, self.port, &self.partition)?;
        if self.capability.len() != 32
            || self.expires_at_ms == 0
            || self.app_socket.len() > 4096
            || !self.app_socket.starts_with('/')
            || self.app_socket.bytes().any(|byte| byte == 0)
        {
            return Err(ControlProtocolError::Invalid("application grant response"));
        }
        Ok(())
    }
}

fn authority(hostname: &str, port: u32, partition: &[u8]) -> Result<(), ControlProtocolError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.bytes().any(|byte| byte.is_ascii_lowercase())
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || !(1..=65_535).contains(&port)
        || partition.len() != 32
    {
        return Err(ControlProtocolError::Invalid("application authority"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CONTROL_PROTOCOL_VERSION, ControlRequest, control_request::Operation};

    #[test]
    fn gateway_grant_is_exact_bounded_and_typed() {
        let scope = BrowserGatewayGrantRequest {
            app_uid: 1000,
            hostname: "example.com".into(),
            port: 443,
            partition: vec![1; 32],
            lifetime_seconds: 300,
        };
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            operation: Some(Operation::BrowserGatewayGrant(scope.clone())),
        };
        assert_eq!(
            crate::decode_request(&crate::encode_request(&request).unwrap()).unwrap(),
            request
        );
        for bad in [
            "Example.com",
            "example.com.",
            "127.0.0.1",
            "127.1",
            "[::1]",
            "example.com/path",
            "a..com",
            "a\r\n.com",
        ] {
            let mut invalid = scope.clone();
            invalid.hostname = bad.into();
            assert!(invalid.validate().is_err());
        }
        let mut invalid = scope;
        invalid.lifetime_seconds = 301;
        assert!(invalid.validate().is_err());
        invalid.lifetime_seconds = 1;
        invalid.partition.pop();
        assert!(invalid.validate().is_err());
    }
}
