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
}
