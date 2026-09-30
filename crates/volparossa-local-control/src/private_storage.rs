//! Explicit provider custody and one owner-signed same-socket operation; no owner secrets.

use ed25519_dalek::VerifyingKey;
use prost::Message;

use crate::ControlProtocolError;

const MAX_CAPACITY: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_LIFETIME: u64 = 31 * 24 * 60 * 60;

/// Attach one explicitly owned private store to a policy-authorized provider endpoint.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageServeRequest {
    /// Explicit unprivileged TCP bind tuple; never an arbitrary outbound destination.
    #[prost(string, tag = "1")]
    pub bind_address: String,
    /// Exact provider hostname, independently admitted by the current Exit policy.
    #[prost(string, tag = "2")]
    pub advertised_hostname: String,
    /// New owner-only store directory, or the exact existing directory when reopening.
    #[prost(string, tag = "3")]
    pub store: String,
    /// New store's payload quota, at most 1 TiB. Must be zero on reuse, retaining its limit.
    #[prost(uint64, tag = "4")]
    pub capacity_bytes: u64,
    /// New store's filesystem free-space floor. Must be zero on reuse, retaining its floor.
    #[prost(uint64, tag = "5")]
    pub min_free_bytes: u64,
    /// Open only a previously owned store; never overwrite it or silently resize its quota.
    #[prost(bool, tag = "6")]
    pub reuse_store: bool,
}

/// Explicit local operator authority to grant bounded custody to one known application owner.
/// The agent signs with its node key only while its private provider service is attached.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageGrantRequest {
    /// Independently selected application owner's Ed25519 public key; never its private key.
    #[prost(bytes = "vec", tag = "1")]
    pub owner_key: Vec<u8>,
    /// Aggregate full-payload allowance across this grant's live, partial and expired copies.
    #[prost(uint64, tag = "2")]
    pub max_payload_bytes: u64,
    /// Aggregate undeleted lease bound, 1 through 256.
    #[prost(uint32, tag = "3")]
    pub max_leases: u32,
    /// Maximum per-operation retention request, at most 31 days and never past grant expiry.
    #[prost(uint64, tag = "4")]
    pub max_retention_seconds: u64,
    /// Protocol rights bitmask: Reserve=1, Append=2, Progress=4, Finalize=8,
    /// ReadRange=16, Renew=32, Delete=64. Unknown bits and the empty set are rejected.
    #[prost(uint32, tag = "5")]
    pub rights: u32,
    /// Finite provider-grant lifetime, at most 31 days; not a reachability guarantee.
    #[prost(uint64, tag = "6")]
    pub lifetime_seconds: u64,
}

/// Open one exact independently pinned provider route, then upgrade this same Unix socket.
/// After readiness, the original owner-signed protocol request contains the exact operation,
/// archive identity and lease; no duplicate unsigned command or caller file path is accepted.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageRemoteRequest {
    /// Provider key supplied independently by the application, not discovered from the grant.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original bounded provider-signed custody grant.
    #[prost(bytes = "vec", tag = "2")]
    pub grant: Vec<u8>,
}

/// Fresh challenge for the already selected protected provider connection, not success.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageReady {
    /// Must match the caller's independently pinned provider.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original provider signature, nonce, grant binding and finite validity.
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
}

/// Explicitly issued provider capability; not a completed upload or measured contribution.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageGrant {
    /// Local node public key that signed the grant.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Exact original signed grant for the requested owner and limits.
    #[prost(bytes = "vec", tag = "2")]
    pub grant: Vec<u8>,
}

/// Local operator control of the currently attached provider; never forwarded to a peer.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageAdmissionRequest {
    /// Independently pinned local provider key, not a caller-selected directory.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Absent reads status; present sets the durable payload admission target, including zero.
    #[prost(uint64, optional, tag = "2")]
    pub target_bytes: Option<u64>,
}

/// Local payload admission and retained custody. This is not physical overhead or remote credit.
#[derive(Clone, PartialEq, Message)]
pub struct PrivateStorageAdmission {
    /// Exact attached provider identity.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Original maximum payload quota; existing custody remains valid up to this limit.
    #[prost(uint64, tag = "2")]
    pub capacity_bytes: u64,
    /// Durable target used only for new reservations.
    #[prost(uint64, tag = "3")]
    pub target_bytes: u64,
    /// Full payload reservations, including partial and expired undeleted leases.
    #[prost(uint64, tag = "4")]
    pub reserved_bytes: u64,
    /// Verified committed payload, including expired undeleted copies.
    #[prost(uint64, tag = "5")]
    pub committed_bytes: u64,
    /// Exact current pending plus committed lease count.
    #[prost(uint64, tag = "6")]
    pub leases: u64,
    /// Reserved plus committed payload. No target change deletes these bytes.
    #[prost(uint64, tag = "7")]
    pub retained_payload_bytes: u64,
    /// Retained payload above target, not permission to evict it.
    #[prost(uint64, tag = "8")]
    pub pending_drain_bytes: u64,
    /// Target minus retained payload, saturating at zero; not a free-disk guarantee.
    #[prost(uint64, tag = "9")]
    pub available_for_new_reservations_bytes: u64,
}

impl PrivateStorageAdmissionRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.provider_key)?;
        if self
            .target_bytes
            .is_some_and(|target| target > MAX_CAPACITY)
        {
            return Err(ControlProtocolError::Invalid(
                "private storage admission target",
            ));
        }
        Ok(())
    }
}

impl PrivateStorageAdmission {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.provider_key)?;
        if !(1..=MAX_CAPACITY).contains(&self.capacity_bytes)
            || self.target_bytes > self.capacity_bytes
            || self.leases > 256
            || self.reserved_bytes.checked_add(self.committed_bytes)
                != Some(self.retained_payload_bytes)
            || self.retained_payload_bytes > self.capacity_bytes
            || self.pending_drain_bytes
                != self
                    .retained_payload_bytes
                    .saturating_sub(self.target_bytes)
            || self.available_for_new_reservations_bytes
                != self
                    .target_bytes
                    .saturating_sub(self.retained_payload_bytes)
        {
            return Err(ControlProtocolError::Invalid(
                "private storage admission accounting",
            ));
        }
        Ok(())
    }
}

impl PrivateStorageServeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        let bind: std::net::SocketAddr = self
            .bind_address
            .parse()
            .map_err(|_| ControlProtocolError::Invalid("private storage bind address"))?;
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
            return Err(ControlProtocolError::Invalid("private storage endpoint"));
        }
        crate::content::validate_path(&self.store)?;
        if (self.reuse_store && (self.capacity_bytes != 0 || self.min_free_bytes != 0))
            || (!self.reuse_store
                && (!(1..=MAX_CAPACITY).contains(&self.capacity_bytes)
                    || self.min_free_bytes > MAX_CAPACITY))
        {
            return Err(ControlProtocolError::Invalid("private storage limits"));
        }
        Ok(())
    }
}

impl PrivateStorageGrantRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.owner_key)?;
        if !(1..=MAX_CAPACITY).contains(&self.max_payload_bytes)
            || !(1..=256).contains(&self.max_leases)
            || !(1..=MAX_LIFETIME).contains(&self.max_retention_seconds)
            || !(1..=MAX_LIFETIME).contains(&self.lifetime_seconds)
            || self.rights == 0
            || self.rights & !127 != 0
        {
            return Err(ControlProtocolError::Invalid("private storage grant scope"));
        }
        Ok(())
    }
}

impl PrivateStorageRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.provider_key)?;
        blob(&self.grant, 2048)
    }
}

impl PrivateStorageReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.provider_key)?;
        blob(&self.challenge, 1024)
    }
}

impl PrivateStorageGrant {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.provider_key)?;
        blob(&self.grant, 2048)
    }
}

fn key(bytes: &[u8]) -> Result<(), ControlProtocolError> {
    let bytes: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| ControlProtocolError::Invalid("private storage key"))?;
    if VerifyingKey::from_bytes(bytes).map_or(true, |key| key.is_weak()) {
        return Err(ControlProtocolError::Invalid("private storage key"));
    }
    Ok(())
}

fn blob(bytes: &[u8], maximum: usize) -> Result<(), ControlProtocolError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ControlProtocolError::Invalid("private storage metadata"));
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

    fn public_key() -> Vec<u8> {
        ed25519_dalek::SigningKey::from_bytes(&[29; 32])
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn private_storage_ipc_roundtrips_typed_scope_without_owner_secrets_or_output_paths() {
        let operations = [
            Operation::PrivateStorageServe(PrivateStorageServeRequest {
                bind_address: "127.0.0.1:8443".into(),
                advertised_hostname: "provider.example".into(),
                store: "/owned/private-store".into(),
                capacity_bytes: 1024,
                min_free_bytes: 0,
                reuse_store: false,
            }),
            Operation::PrivateStorageGrant(PrivateStorageGrantRequest {
                owner_key: public_key(),
                max_payload_bytes: 1024,
                max_leases: 2,
                max_retention_seconds: 3600,
                rights: 127,
                lifetime_seconds: 3600,
            }),
            Operation::PrivateStorageRemote(PrivateStorageRemoteRequest {
                provider_key: public_key(),
                grant: vec![1; 2048],
            }),
            Operation::PrivateStorageAdmission(PrivateStorageAdmissionRequest {
                provider_key: public_key(),
                target_bytes: Some(0),
            }),
        ];
        for operation in operations {
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![7; 16],
                operation: Some(operation),
            };
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        for payload in [
            Payload::PrivateStorageReady(PrivateStorageReady {
                provider_key: public_key(),
                challenge: vec![1; 1024],
            }),
            Payload::PrivateStorageGrant(PrivateStorageGrant {
                provider_key: public_key(),
                grant: vec![1; 2048],
            }),
            Payload::PrivateStorageAdmission(PrivateStorageAdmission {
                provider_key: public_key(),
                capacity_bytes: 2048,
                target_bytes: 1024,
                reserved_bytes: 256,
                committed_bytes: 1792,
                leases: 2,
                retained_payload_bytes: 2048,
                pending_drain_bytes: 1024,
                available_for_new_reservations_bytes: 0,
            }),
        ] {
            let response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![7; 16],
                result: ControlResult::Ok as i32,
                diagnostic_code: "PRIVATE_STORAGE_READY".into(),
                payload: Some(payload),
            };
            assert_eq!(
                decode_response(&encode_response(&response).unwrap()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn private_storage_ipc_rejects_ambiguous_reuse_keys_and_unbounded_grants() {
        let mut serve = PrivateStorageServeRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            store: "/owned/private-store".into(),
            capacity_bytes: 1024,
            min_free_bytes: 0,
            reuse_store: true,
        };
        assert!(serve.validate().is_err());
        serve.capacity_bytes = 0;
        assert!(serve.validate().is_ok());
        serve.advertised_hostname = "127.0.0.1".into();
        assert!(serve.validate().is_err());
        let mut grant = PrivateStorageGrantRequest {
            owner_key: public_key(),
            max_payload_bytes: MAX_CAPACITY,
            max_leases: 256,
            max_retention_seconds: MAX_LIFETIME,
            rights: 127,
            lifetime_seconds: MAX_LIFETIME,
        };
        assert!(grant.validate().is_ok());
        grant.rights = 128;
        assert!(grant.validate().is_err());
        grant.rights = 0;
        assert!(grant.validate().is_err());
        grant.rights = 1;
        grant.max_leases += 1;
        assert!(grant.validate().is_err());
        assert!(
            PrivateStorageRemoteRequest {
                provider_key: vec![0; 32],
                grant: vec![1; 128]
            }
            .validate()
            .is_err()
        );
        assert!(
            PrivateStorageRemoteRequest {
                provider_key: public_key(),
                grant: vec![1; 2049]
            }
            .validate()
            .is_err()
        );
        assert!(
            PrivateStorageReady {
                provider_key: public_key(),
                challenge: vec![1; 1025]
            }
            .validate()
            .is_err()
        );
    }
}
