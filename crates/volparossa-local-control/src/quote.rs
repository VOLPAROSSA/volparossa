//! Explicit local quote authority and same-socket readiness, never raw hardware evidence.

use prost::Message;

use crate::ControlProtocolError;

#[cfg(test)]
mod confirmation_tests;

/// Operator authorization for exactly one requester on the existing protected provider.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteAttachRequest {
    /// Explicit unprivileged listener address and port.
    #[prost(string, tag = "1")]
    pub bind_address: String,
    /// Existing policy-authorized provider hostname.
    #[prost(string, tag = "2")]
    pub advertised_hostname: String,
    /// Exact requester Ed25519 key, not a wildcard or discovery-derived permission.
    #[prost(bytes = "vec", tag = "3")]
    pub requester_key: Vec<u8>,
    /// Absolute local authorization deadline; the agent additionally checks the 600-second cap.
    #[prost(uint64, tag = "4")]
    pub expires_at: u64,
    /// Nonrefundable quote attempts, independent of the single firmware slot.
    #[prost(uint32, tag = "5")]
    pub maximum_attempts: u32,
    /// Absent keeps quote-only authority; version one explicitly permits key confirmation.
    #[prost(uint32, optional, tag = "6")]
    pub confirmation_version: Option<u32>,
}

/// Select one provider, then wait for route/TLS/authenticated quote-challenge readiness.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteRemoteRequest {
    /// Independently selected provider Ed25519 key.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Explicit confirmation profile, never inferred from remote support.
    #[prost(uint32, optional, tag = "2")]
    pub confirmation_version: Option<u32>,
}

/// Content-free readiness. The following bounded binary frames are not generic control payloads.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteReady {
    /// Exact selected provider.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Agent identity that will sign the quote request.
    #[prost(bytes = "vec", tag = "2")]
    pub requester_key: Vec<u8>,
    /// Exact negotiated mode; an opted-in caller must reject an absent version.
    #[prost(uint32, optional, tag = "3")]
    pub confirmation_version: Option<u32>,
}

fn key(bytes: &[u8]) -> Result<(), ControlProtocolError> {
    if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
        return Err(ControlProtocolError::Invalid("quote identity"));
    }
    Ok(())
}

fn confirmation(version: Option<u32>) -> Result<(), ControlProtocolError> {
    if !matches!(version, None | Some(1)) {
        return Err(ControlProtocolError::Invalid("quote confirmation version"));
    }
    Ok(())
}

impl QuoteAttachRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.requester_key)?;
        confirmation(self.confirmation_version)?;
        if self.bind_address.is_empty()
            || self.bind_address.len() > 128
            || self.advertised_hostname.is_empty()
            || self.advertised_hostname.len() > 253
            || self.expires_at == 0
            || !(1..=64).contains(&self.maximum_attempts)
        {
            return Err(ControlProtocolError::Invalid("quote attachment"));
        }
        Ok(())
    }
}

impl QuoteRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        confirmation(self.confirmation_version)?;
        key(&self.provider_key)
    }
}

impl QuoteReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        confirmation(self.confirmation_version)?;
        key(&self.provider_key)?;
        key(&self.requester_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
        PrivateStorageMaintenanceReady, PrivateStorageMaintenanceRequest,
        control_request::Operation, control_response::Payload,
    };

    fn request(operation: Option<Operation>) -> ControlRequest {
        ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            operation,
        }
    }

    fn response(payload: Option<Payload>) -> ControlResponse {
        ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_READY".into(),
            private_storage_remote_detail: None,
            payload,
        }
    }

    fn tagged(mut prefix: Vec<u8>, tag: [u8; 2], body: &impl Message) -> Vec<u8> {
        // Literal canonical field keys freeze the published/candidate tag
        // assignments independently of the current oneof declarations.
        prefix.extend_from_slice(&tag);
        body.encode_length_delimited(&mut prefix).unwrap();
        prefix
    }

    fn maintenance_request() -> PrivateStorageMaintenanceRequest {
        PrivateStorageMaintenanceRequest {
            owner_key: ed25519_dalek::SigningKey::from_bytes(&[29; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            enrollment_id: vec![2; 32],
            maximum_bytes: 134_217_728,
        }
    }

    fn maintenance_ready() -> PrivateStorageMaintenanceReady {
        PrivateStorageMaintenanceReady {
            turn: vec![2; 32],
            expires: 3600,
            maximum_bytes: 134_217_728,
        }
    }

    #[test]
    fn published_quote_request_tags_remain_fixed_and_maintenance_uses_46() {
        assert_eq!(CONTROL_PROTOCOL_VERSION, 2);
        let attach = QuoteAttachRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            requester_key: vec![1; 32],
            expires_at: 1000,
            maximum_attempts: 1,
            confirmation_version: None,
        };
        let remote = QuoteRemoteRequest {
            provider_key: vec![2; 32],
            confirmation_version: None,
        };
        let maintenance = maintenance_request();
        let prefix = request(None).encode_to_vec();
        for (operation, wire) in [
            (
                Operation::QuoteAttach(attach.clone()),
                tagged(prefix.clone(), [0xda, 0x02], &attach),
            ),
            (
                Operation::QuoteDetach(Empty {}),
                tagged(prefix.clone(), [0xe2, 0x02], &Empty {}),
            ),
            (
                Operation::QuoteRemote(remote.clone()),
                tagged(prefix.clone(), [0xea, 0x02], &remote),
            ),
            (
                Operation::PrivateStorageMaintenance(maintenance.clone()),
                tagged(prefix, [0xf2, 0x02], &maintenance),
            ),
        ] {
            let expected = request(Some(operation));
            assert_eq!(crate::encode_request(&expected).unwrap(), wire);
            assert_eq!(crate::decode_request(&wire).unwrap(), expected);
        }
    }

    #[test]
    fn published_quote_ready_tag_remains_33_and_maintenance_uses_34() {
        let quote = QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: None,
        };
        let maintenance = maintenance_ready();
        let prefix = response(None).encode_to_vec();
        for (payload, wire) in [
            (
                Payload::QuoteReady(quote.clone()),
                tagged(prefix.clone(), [0x8a, 0x02], &quote),
            ),
            (
                Payload::PrivateStorageMaintenanceReady(maintenance.clone()),
                tagged(prefix, [0x92, 0x02], &maintenance),
            ),
        ] {
            let expected = response(Some(payload));
            assert_eq!(crate::encode_response(&expected).unwrap(), wire);
            assert_eq!(crate::decode_response(&wire).unwrap(), expected);
        }
    }

    #[test]
    fn unmerged_maintenance_tags_are_rejected_instead_of_becoming_quote_authority() {
        let maintenance = maintenance_request();
        let ready = maintenance_ready();
        maintenance.validate().unwrap();
        ready.validate().unwrap();
        // These were valid storage-only candidate payloads. Request field 3
        // and response field 2 have incompatible wire types in quote messages.
        let old_request = tagged(request(None).encode_to_vec(), [0xda, 0x02], &maintenance);
        let old_ready = tagged(response(None).encode_to_vec(), [0x8a, 0x02], &ready);
        assert!(crate::decode_request(&old_request).is_err());
        assert!(crate::decode_response(&old_ready).is_err());

        let quote = QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: None,
        };
        let wrong_new_ready = tagged(response(None).encode_to_vec(), [0x92, 0x02], &quote);
        assert!(crate::decode_response(&wrong_new_ready).is_err());
        let attach = QuoteAttachRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            requester_key: vec![1; 32],
            expires_at: 1000,
            maximum_attempts: 1,
            confirmation_version: None,
        };
        let wrong_new_request = tagged(request(None).encode_to_vec(), [0xf2, 0x02], &attach);
        assert!(crate::decode_request(&wrong_new_request).is_err());
    }

    #[test]
    fn default_legacy_payloads_still_require_closed_quote_validation() {
        // Omitted incompatible fields can be parsed structurally as quote
        // defaults, but may never bypass mandatory quote identity/authority.
        let old_request = tagged(
            request(None).encode_to_vec(),
            [0xda, 0x02],
            &PrivateStorageMaintenanceRequest::default(),
        );
        let old_ready = tagged(
            response(None).encode_to_vec(),
            [0x8a, 0x02],
            &PrivateStorageMaintenanceReady::default(),
        );
        assert!(matches!(
            ControlRequest::decode(old_request.as_slice())
                .unwrap()
                .operation,
            Some(Operation::QuoteAttach(_))
        ));
        assert!(matches!(
            ControlResponse::decode(old_ready.as_slice())
                .unwrap()
                .payload,
            Some(Payload::QuoteReady(_))
        ));
        assert!(crate::decode_request(&old_request).is_err());
        assert!(crate::decode_response(&old_ready).is_err());
    }

    #[test]
    fn quote_local_operations_are_distinct_bounded_and_roundtrip() {
        let attach = QuoteAttachRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            requester_key: vec![1; 32],
            expires_at: 1000,
            maximum_attempts: 1,
            confirmation_version: None,
        };
        for operation in [
            Operation::QuoteAttach(attach.clone()),
            Operation::QuoteDetach(Empty {}),
            Operation::QuoteRemote(QuoteRemoteRequest {
                provider_key: vec![2; 32],
                confirmation_version: None,
            }),
        ] {
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![3; 16],
                operation: Some(operation),
            };
            assert_eq!(
                crate::decode_request(&crate::encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        for attempts in [0, 65, u32::MAX] {
            assert!(
                QuoteAttachRequest {
                    maximum_attempts: attempts,
                    ..attach.clone()
                }
                .validate()
                .is_err()
            );
        }
        for bytes in [vec![], vec![0; 32], vec![1; 31], vec![1; 33]] {
            assert!(
                QuoteRemoteRequest {
                    provider_key: bytes.clone(),
                    confirmation_version: None,
                }
                .validate()
                .is_err()
            );
            assert!(
                QuoteAttachRequest {
                    requester_key: bytes,
                    ..attach.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            QuoteAttachRequest {
                expires_at: 0,
                ..attach
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn quote_ready_has_only_two_public_identity_fields() {
        let ready = QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: None,
        };
        assert!(ready.validate().is_ok());
        assert_eq!(ready.encoded_len(), 68);
        assert!(
            QuoteReady {
                requester_key: vec![0; 32],
                ..ready
            }
            .validate()
            .is_err()
        );
    }
}
