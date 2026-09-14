//! Explicit mailbox setup and one signed same-socket operation; no private keys or output paths.

use prost::Message;

use crate::{ContentCacheLimits, ControlProtocolError};

/// Start an explicitly selected owned durable mailbox store and protected provider listener.
#[derive(Clone, PartialEq, Message)]
pub struct MailboxServeRequest {
    /// Explicit unprivileged TCP bind tuple.
    #[prost(string, tag = "1")]
    pub bind_address: String,
    /// Exact hostname already authorized by the current Exit policy.
    #[prost(string, tag = "2")]
    pub advertised_hostname: String,
    /// New owned mailbox cache, or explicit reopening when requested.
    #[prost(string, tag = "3")]
    pub cache: String,
    /// Bounded physical storage budget; no reservation is implied by registration.
    #[prost(message, optional, tag = "4")]
    pub limits: Option<ContentCacheLimits>,
    /// Reopen only a previously owned durable mailbox store.
    #[prost(bool, tag = "5")]
    pub reuse_cache: bool,
}

/// Locate one independently trusted provider and bridge one exact signed mailbox operation.
#[derive(Clone, PartialEq, Message)]
pub struct MailboxRemoteRequest {
    /// Explicit provider Ed25519 key, also bound in the signed invitation.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original canonical recipient-signed invitation, not a private key.
    #[prost(bytes = "vec", tag = "2")]
    pub grant: Vec<u8>,
    /// Existing mailbox wire operation: Register=1, Deposit=2, List=3, Get=4, Acknowledge=5.
    #[prost(int32, tag = "3")]
    pub operation: i32,
    /// Original encrypted-message manifest for Deposit only.
    #[prost(bytes = "vec", tag = "4")]
    pub manifest: Vec<u8>,
    /// Exact message identity for Get/Acknowledge only.
    #[prost(bytes = "vec", tag = "5")]
    pub message_id: Vec<u8>,
}

/// Original signed provider challenge for this exact connection; not a storage success receipt.
#[derive(Clone, PartialEq, Message)]
pub struct MailboxReady {
    /// Provider already selected by the caller; must match independently.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Bounded canonical signed one-use challenge.
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
}

impl MailboxServeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        let bind: std::net::SocketAddr = self
            .bind_address
            .parse()
            .map_err(|_| ControlProtocolError::Invalid("mailbox bind address"))?;
        let hostname = &self.advertised_hostname;
        if bind.port() == 0
            || hostname.is_empty()
            || hostname.len() > 253
            || hostname.parse::<std::net::IpAddr>().is_ok()
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            })
        {
            return Err(ControlProtocolError::Invalid("mailbox endpoint"));
        }
        crate::content::validate_path(&self.cache)?;
        crate::content::validate_limits(self.limits)?;
        if self
            .limits
            .is_some_and(|limits| limits.quota_bytes > 256 * 1024 * 1024)
        {
            return Err(ControlProtocolError::Invalid("mailbox storage quota"));
        }
        Ok(())
    }
}

impl MailboxRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32
            || self.grant.is_empty()
            || self.grant.len() > 2048
            || !(1..=5).contains(&self.operation)
            || (self.operation == 2 && (self.manifest.is_empty() || self.manifest.len() > 4096))
            || (self.operation != 2 && !self.manifest.is_empty())
            || (matches!(self.operation, 4 | 5) && self.message_id.len() != 32)
            || (!matches!(self.operation, 4 | 5) && !self.message_id.is_empty())
        {
            return Err(ControlProtocolError::Invalid("mailbox operation scope"));
        }
        Ok(())
    }
}

impl MailboxReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 || self.challenge.is_empty() || self.challenge.len() > 2048
        {
            return Err(ControlProtocolError::Invalid("mailbox readiness"));
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
    fn mailbox_local_scope_is_typed_bounded_and_contains_no_output_or_secret() {
        let mut remote = MailboxRemoteRequest {
            provider_key: vec![1; 32],
            grant: vec![2; 128],
            operation: 3,
            manifest: Vec::new(),
            message_id: Vec::new(),
        };
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            operation: Some(Operation::MailboxRemote(remote.clone())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        remote.message_id = vec![4; 32];
        assert!(remote.validate().is_err());
        remote.operation = 4;
        assert!(remote.validate().is_ok());
        remote.operation = 2;
        remote.manifest = vec![5; 4096];
        remote.message_id.clear();
        assert!(remote.validate().is_ok());
        remote.manifest.push(0);
        assert!(remote.validate().is_err());
        remote.operation = 6;
        assert!(remote.validate().is_err());
        assert!(
            MailboxReady {
                provider_key: vec![1; 32],
                challenge: vec![0; 2049]
            }
            .validate()
            .is_err()
        );
    }
}
