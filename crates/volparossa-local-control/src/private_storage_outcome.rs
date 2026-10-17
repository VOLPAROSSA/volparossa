//! One-use, caller-bound observations of failed local stream handoffs, not custody receipts.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{ControlProtocolError, PrivateStorageElapsedBucket};

/// Query only the caller's original unpredictable local request identifier.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PrivateStorageOutcomeRequest {
    /// Original 16-byte request ID; no provider, archive, path or signing key.
    #[prost(bytes = "vec", tag = "1")]
    pub original_request_id: Vec<u8>,
    /// Explicitly include coarse APPEND timing in this same one-use query.
    #[prost(bool, tag = "2")]
    pub include_append_timing: bool,
    /// Explicitly include the closed outer TLS failure in this same one-use query.
    #[prost(bool, tag = "3")]
    pub include_tls_close_failure: bool,
}

impl PrivateStorageOutcomeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.original_request_id.len() != 16 {
            return Err(ControlProtocolError::Invalid("private storage outcome ID"));
        }
        Ok(())
    }
}

/// Availability in the querying Unix UID's short-lived local namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeStatus {
    /// Missing, omitted at capacity, consumed, successfully completed, or already purged.
    Missing = 0,
    /// The original operation has not terminated; the query consumes nothing.
    Pending = 1,
    /// One failed post-READY handoff was observed and consumed by this query.
    Observed = 2,
    /// This exact retained observation expired; it has now been removed.
    Expired = 3,
}

/// Last locally entered boundary; never evidence of a provider commit or rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomePhase {
    /// No observation, allowed only for a non-observed query result.
    Unobserved = 0,
    /// Writing the initial READY frame, possibly only partially.
    ReadyWrite = 1,
    /// Reading the owner's signed request.
    LocalRequestRead = 2,
    /// Authenticating the owner's request.
    LocalRequestVerify = 3,
    /// Reading append ciphertext.
    LocalPayloadRead = 4,
    /// Verifying append ciphertext.
    LocalPayloadVerify = 5,
    /// Waiting for the existing resource admission.
    Admission = 6,
    /// Rechecking authorization before forwarding.
    RemoteRequestVerify = 7,
    /// Writing the signed request to the protected provider stream.
    RemoteRequestWrite = 8,
    /// Writing append ciphertext to that stream.
    RemotePayloadWrite = 9,
    /// Reading the provider receipt frame.
    RemoteReceiptRead = 10,
    /// Authenticating the provider receipt.
    RemoteReceiptVerify = 11,
    /// Reading the authorized range.
    RemotePayloadRead = 12,
    /// Verifying the range and final request validity.
    RemotePayloadVerify = 13,
    /// Forwarding the verified receipt to the local owner.
    LocalReceiptWrite = 14,
    /// Forwarding the authorized ciphertext range.
    LocalPayloadWrite = 15,
    /// Closing provider application TLS.
    ProviderTlsClose = 16,
    /// Closing the protected transport TLS.
    TransportTlsClose = 17,
    /// Rechecking the carrying route and policy.
    FinalRouteCheck = 18,
    /// Rechecking grant validity.
    FinalGrantCheck = 19,
    /// Rechecking offer and challenge validity.
    FinalLifetimeCheck = 20,
    /// Writing the existing final local success frame.
    TerminalWrite = 21,
}

/// Closed local error families; no formatted nested errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeCategory {
    /// No failure observation.
    Unobserved = 0,
    /// Stream I/O, not evidence of a remote cause.
    Io = 1,
    /// Signed metadata authentication failed.
    Auth = 2,
    /// Invalid framing, state or metadata.
    Invalid = 3,
    /// Resource admission declined.
    Busy = 4,
    /// Local store or worker unavailable.
    Store = 5,
    /// Signed authority expired.
    Expired = 6,
    /// Randomness unavailable.
    Entropy = 7,
    /// An explicitly observed local budget elapsed.
    Timeout = 8,
    /// Policy or route authority check failed.
    Policy = 9,
    /// Other bounded local unavailability, including TLS closure.
    Unavailable = 10,
    /// The owning task or maintenance turn was cancelled, not a timeout claim.
    Cancelled = 11,
}

/// Exactly which existing local timeout fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeDeadline {
    /// No operation/exchange/bridge/wire timeout was observed (legacy projection).
    None = 0,
    /// Whole agent operation budget.
    Operation = 1,
    /// Grant/offer-bounded agent exchange budget.
    Exchange = 2,
    /// Whole local-to-provider wire bridge budget.
    Bridge = 3,
    /// Inner provider wire operation budget.
    RemoteWire = 4,
}

/// Fixed-size outcome metadata. Never grants authority or asserts successful custody.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageOutcome {
    /// Availability, scoped by both original request ID and actual Unix peer UID.
    #[prost(enumeration = "PrivateStorageOutcomeStatus", tag = "1")]
    pub status: i32,
    /// Actual local boundary, only when status is Observed.
    #[prost(enumeration = "PrivateStorageOutcomePhase", tag = "2")]
    pub phase: i32,
    /// Actual closed error family, only when status is Observed.
    #[prost(enumeration = "PrivateStorageOutcomeCategory", tag = "3")]
    pub category: i32,
    /// Existing deadline that elapsed, if any.
    #[prost(enumeration = "PrivateStorageOutcomeDeadline", tag = "4")]
    pub deadline: i32,
    /// Optional local APPEND timing, returned only on an explicit query opt-in.
    #[prost(message, optional, tag = "5")]
    pub append_timing: Option<PrivateStorageAppendTiming>,
    /// Opt-in outer TLS close detail; does not change the legacy coarse projection.
    #[prost(enumeration = "PrivateStorageTlsCloseFailure", optional, tag = "6")]
    pub tls_close_failure: Option<i32>,
}

/// Exactly which local outer TLS close boundary failed; never a remote-cause claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageTlsCloseFailure {
    /// Not an observation; rejected when the optional field is present.
    Unspecified = 0,
    /// The shutdown future returned an I/O error.
    ShutdownIo = 1,
    /// The read future returned an I/O error, including abrupt EOF.
    ReadIo = 2,
    /// A byte followed the expected end of the application stream.
    TrailingData = 3,
    /// The existing internal TLS close budget elapsed.
    InternalDeadline = 4,
}

/// Coarse local APPEND progress, never provider arrival, custody or reservation proof.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageAppendTiming {
    /// Original operation budget already spent before entering payload write/flush.
    #[prost(enumeration = "PrivateStorageElapsedBucket", tag = "1")]
    pub before_payload: i32,
    /// Time in payload write/flush, ending at its return or the first failure/cancel.
    #[prost(enumeration = "PrivateStorageElapsedBucket", tag = "2")]
    pub in_payload_write_flush: i32,
    /// Time since payload flush returned and receipt read began; absent before that return.
    #[prost(enumeration = "PrivateStorageElapsedBucket", optional, tag = "3")]
    pub in_receipt_read: Option<i32>,
}

impl PrivateStorageAppendTiming {
    /// Validate the finite vocabulary and exact locally observed boundary.
    ///
    /// # Errors
    /// Reject unknown buckets, unobserved timing and impossible payload/receipt states.
    pub fn validate(&self, phase: PrivateStorageOutcomePhase) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("private storage append timing");
        for value in [
            Some(self.before_payload),
            Some(self.in_payload_write_flush),
            self.in_receipt_read,
        ]
        .into_iter()
        .flatten()
        {
            if PrivateStorageElapsedBucket::try_from(value).map_err(|_| invalid())?
                == PrivateStorageElapsedBucket::Unobserved
            {
                return Err(invalid());
            }
        }
        match (phase, self.in_receipt_read) {
            (PrivateStorageOutcomePhase::RemotePayloadWrite, None)
            | (PrivateStorageOutcomePhase::RemoteReceiptRead, Some(_)) => Ok(()),
            _ => Err(invalid()),
        }
    }
}

impl PrivateStorageOutcome {
    /// Reject unknown values and impossible status/deadline combinations.
    ///
    /// # Errors
    /// Rejects observations on missing results and counterfeit timeout combinations.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("private storage outcome");
        let status = PrivateStorageOutcomeStatus::try_from(self.status).map_err(|_| invalid())?;
        let phase = PrivateStorageOutcomePhase::try_from(self.phase).map_err(|_| invalid())?;
        let category =
            PrivateStorageOutcomeCategory::try_from(self.category).map_err(|_| invalid())?;
        let deadline =
            PrivateStorageOutcomeDeadline::try_from(self.deadline).map_err(|_| invalid())?;
        if status != PrivateStorageOutcomeStatus::Observed {
            return if self.phase == 0
                && self.category == 0
                && self.deadline == 0
                && self.append_timing.is_none()
                && self.tls_close_failure.is_none()
            {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if phase == PrivateStorageOutcomePhase::Unobserved
            || category == PrivateStorageOutcomeCategory::Unobserved
            || (category == PrivateStorageOutcomeCategory::Timeout)
                != (deadline != PrivateStorageOutcomeDeadline::None)
            || (deadline == PrivateStorageOutcomeDeadline::Bridge
                && !(2..=15).contains(&self.phase))
            || (deadline == PrivateStorageOutcomeDeadline::RemoteWire
                && !(7..=13).contains(&self.phase))
        {
            return Err(invalid());
        }
        if let Some(timing) = self.append_timing {
            timing.validate(phase)?;
        }
        if let Some(failure) = self.tls_close_failure {
            if PrivateStorageTlsCloseFailure::try_from(failure).map_err(|_| invalid())?
                == PrivateStorageTlsCloseFailure::Unspecified
                || phase != PrivateStorageOutcomePhase::TransportTlsClose
                || category != PrivateStorageOutcomeCategory::Unavailable
                || deadline != PrivateStorageOutcomeDeadline::None
                || self.append_timing.is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
        control_request::Operation, control_response::Payload, decode_request, decode_response,
        encode_request, encode_response,
    };

    fn close_outcome(failure: i32) -> PrivateStorageOutcome {
        PrivateStorageOutcome {
            status: PrivateStorageOutcomeStatus::Observed as i32,
            phase: PrivateStorageOutcomePhase::TransportTlsClose as i32,
            category: PrivateStorageOutcomeCategory::Unavailable as i32,
            deadline: PrivateStorageOutcomeDeadline::None as i32,
            append_timing: None,
            tls_close_failure: Some(failure),
        }
    }

    #[test]
    fn tls_close_v9_opt_in_keeps_exact_historical_wire_bytes() {
        let mut query = PrivateStorageOutcomeRequest {
            original_request_id: vec![7; 16],
            include_append_timing: false,
            include_tls_close_failure: false,
        };
        let mut old = vec![10, 16];
        old.extend_from_slice(&[7; 16]);
        assert_eq!(query.encode_to_vec(), old);
        query.include_tls_close_failure = true;
        old.extend_from_slice(&[24, 1]);
        assert_eq!(query.encode_to_vec(), old);
        assert_eq!(
            PrivateStorageOutcomeRequest::decode(old.as_slice()).unwrap(),
            query
        );
        let mut outcome = close_outcome(2);
        outcome.tls_close_failure = None;
        assert_eq!(outcome.encode_to_vec(), [8, 2, 16, 17, 24, 10]);
        for reason in 1..=4 {
            outcome.tls_close_failure = Some(reason);
            let encoded = outcome.encode_to_vec();
            assert_eq!(
                encoded,
                [8, 2, 16, 17, 24, 10, 48, u8::try_from(reason).unwrap()]
            );
            let decoded = PrivateStorageOutcome::decode(encoded.as_slice()).unwrap();
            decoded.validate().unwrap();
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn tls_close_v9_wire_accepts_only_four_exact_outer_failure_states() {
        let mut accepted = 0;
        for status in 0..=3 {
            for phase in 0..=21 {
                for category in 0..=11 {
                    for deadline in 0..=4 {
                        for failure in 0..=5 {
                            let value = PrivateStorageOutcome {
                                status,
                                phase,
                                category,
                                deadline,
                                append_timing: None,
                                tls_close_failure: Some(failure),
                            };
                            let expected = status == 2
                                && phase == 17
                                && category == 10
                                && deadline == 0
                                && (1..=4).contains(&failure);
                            assert_eq!(value.validate().is_ok(), expected);
                            accepted += usize::from(expected);
                        }
                    }
                }
            }
        }
        assert_eq!(accepted, 4);
    }

    #[test]
    fn tls_close_v9_wire_rejects_unknown_values_and_append_timing_overlap() {
        for invalid in [i32::MIN, -1, 0, 5, i32::MAX] {
            assert!(close_outcome(invalid).validate().is_err());
        }
        let mut value = close_outcome(2);
        value.append_timing = Some(PrivateStorageAppendTiming {
            before_payload: 1,
            in_payload_write_flush: 1,
            in_receipt_read: None,
        });
        assert!(value.validate().is_err());
        for phase in [9, 10] {
            value.phase = phase;
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn tls_close_v9_closed_names_do_not_change_legacy_enum_domains() {
        for (value, name) in [
            (1, "shutdown_io"),
            (2, "read_io"),
            (3, "trailing_data"),
            (4, "internal_deadline"),
        ] {
            let failure = PrivateStorageTlsCloseFailure::try_from(value).unwrap();
            assert_eq!(serde_json::to_value(failure).unwrap(), name);
        }
        assert!(PrivateStorageOutcomePhase::try_from(22).is_err());
        assert!(PrivateStorageOutcomeCategory::try_from(12).is_err());
        assert!(PrivateStorageOutcomeDeadline::try_from(5).is_err());
        let mut old = close_outcome(4);
        old.tls_close_failure = None;
        old.category = PrivateStorageOutcomeCategory::Timeout as i32;
        assert!(old.validate().is_err());
    }

    #[test]
    fn append_timing_opt_in_preserves_original_protobuf_bytes_and_tags() {
        let mut query = PrivateStorageOutcomeRequest {
            include_tls_close_failure: false,
            original_request_id: vec![1; 16],
            include_append_timing: false,
        };
        let mut original = vec![0x0a, 16];
        original.extend_from_slice(&[1; 16]);
        assert_eq!(query.encode_to_vec(), original);
        assert!(
            !PrivateStorageOutcomeRequest::decode(original.as_slice())
                .unwrap()
                .include_append_timing
        );
        query.include_append_timing = true;
        original.extend_from_slice(&[0x10, 1]);
        assert_eq!(query.encode_to_vec(), original);
        assert_eq!(
            PrivateStorageOutcomeRequest::decode(original.as_slice()).unwrap(),
            query
        );
        let mut outcome = PrivateStorageOutcome {
            tls_close_failure: None,
            status: PrivateStorageOutcomeStatus::Observed as i32,
            phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
            category: PrivateStorageOutcomeCategory::Timeout as i32,
            deadline: PrivateStorageOutcomeDeadline::Operation as i32,
            append_timing: None,
        };
        let original = vec![8, 2, 16, 10, 24, 8, 32, 1];
        assert_eq!(outcome.encode_to_vec(), original);
        assert_eq!(
            PrivateStorageOutcome::decode(original.as_slice()).unwrap(),
            outcome
        );
        outcome.append_timing = Some(PrivateStorageAppendTiming {
            before_payload: 1,
            in_payload_write_flush: 2,
            in_receipt_read: Some(3),
        });
        let mut extended = original;
        extended.extend_from_slice(&[0x2a, 6, 8, 1, 16, 2, 24, 3]);
        outcome.validate().unwrap();
        assert_eq!(outcome.encode_to_vec(), extended);
        assert_eq!(
            PrivateStorageOutcome::decode(extended.as_slice()).unwrap(),
            outcome
        );
    }

    #[test]
    fn append_timing_accepts_only_known_buckets_at_the_two_actual_payload_boundaries() {
        use PrivateStorageOutcomePhase as Phase;
        for before in 1..=8 {
            for payload in 1..=8 {
                for receipt in std::iter::once(None).chain((1..=8).map(Some)) {
                    let timing = PrivateStorageAppendTiming {
                        before_payload: before,
                        in_payload_write_flush: payload,
                        in_receipt_read: receipt,
                    };
                    for phase in 0..=21 {
                        let phase = Phase::try_from(phase).unwrap();
                        assert_eq!(
                            timing.validate(phase).is_ok(),
                            matches!(
                                (phase, receipt),
                                (Phase::RemotePayloadWrite, None)
                                    | (Phase::RemoteReceiptRead, Some(_))
                            )
                        );
                    }
                }
            }
        }
        for invalid in [i32::MIN, -1, 0, 9, i32::MAX] {
            for field in 0..3 {
                let mut timing = PrivateStorageAppendTiming {
                    before_payload: 1,
                    in_payload_write_flush: 1,
                    in_receipt_read: Some(1),
                };
                match field {
                    0 => timing.before_payload = invalid,
                    1 => timing.in_payload_write_flush = invalid,
                    _ => timing.in_receipt_read = Some(invalid),
                }
                assert!(timing.validate(Phase::RemoteReceiptRead).is_err());
                for status in 0..=3 {
                    let outcome = PrivateStorageOutcome {
                        status,
                        phase: Phase::RemoteReceiptRead as i32,
                        category: PrivateStorageOutcomeCategory::Io as i32,
                        append_timing: Some(timing),
                        ..PrivateStorageOutcome::default()
                    };
                    assert!(outcome.validate().is_err());
                }
            }
        }
        let timing = PrivateStorageAppendTiming {
            before_payload: 1,
            in_payload_write_flush: 1,
            in_receipt_read: None,
        };
        for status in [0, 1, 3] {
            assert!(
                PrivateStorageOutcome {
                    status,
                    append_timing: Some(timing),
                    ..PrivateStorageOutcome::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn outcome_tags_roundtrip_without_reusing_quote_or_maintenance_tags() {
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![2; 16],
            operation: Some(Operation::PrivateStorageOutcome(
                PrivateStorageOutcomeRequest {
                    include_tls_close_failure: false,
                    original_request_id: vec![1; 16],
                    include_append_timing: false,
                },
            )),
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), request);
        assert!(bytes.windows(2).any(|key| key == [0xfa, 0x02])); // field 47
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![2; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::PrivateStorageOutcome(PrivateStorageOutcome {
                tls_close_failure: None,
                status: PrivateStorageOutcomeStatus::Observed as i32,
                phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
                category: PrivateStorageOutcomeCategory::Io as i32,
                deadline: PrivateStorageOutcomeDeadline::None as i32,
                append_timing: None,
            })),
        };
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), response);
        assert!(bytes.windows(2).any(|key| key == [0x9a, 0x02])); // field 35
    }

    #[test]
    fn outcome_response_rejects_wrong_result_or_code_on_both_wire_boundaries() {
        for (result, code) in [
            (ControlResult::Unavailable, "PRIVATE_STORAGE_OUTCOME"),
            (ControlResult::Ok, "UNKNOWN_REPLY"),
        ] {
            let response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![2; 16],
                result: result as i32,
                diagnostic_code: code.into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageOutcome(
                    PrivateStorageOutcome::default(),
                )),
            };
            assert!(matches!(
                encode_response(&response),
                Err(ControlProtocolError::Invalid(
                    "private storage outcome envelope"
                ))
            ));
            assert!(matches!(
                decode_response(&response.encode_to_vec()),
                Err(ControlProtocolError::Invalid(
                    "private storage outcome envelope"
                ))
            ));
        }
    }

    #[test]
    fn outcome_rejects_unknown_enums_bad_ids_and_counterfeit_timeout_or_status() {
        for length in [0, 15, 17, 4096] {
            assert!(
                PrivateStorageOutcomeRequest {
                    include_tls_close_failure: false,
                    original_request_id: vec![0; length],
                    include_append_timing: false,
                }
                .validate()
                .is_err()
            );
        }
        let valid = PrivateStorageOutcome {
            tls_close_failure: None,
            status: PrivateStorageOutcomeStatus::Observed as i32,
            phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
            category: PrivateStorageOutcomeCategory::Io as i32,
            deadline: PrivateStorageOutcomeDeadline::None as i32,
            append_timing: None,
        };
        valid.validate().unwrap();
        for bad in [
            PrivateStorageOutcome {
                status: 99,
                ..valid
            },
            PrivateStorageOutcome { phase: 99, ..valid },
            PrivateStorageOutcome {
                category: 99,
                ..valid
            },
            PrivateStorageOutcome {
                deadline: 99,
                ..valid
            },
            PrivateStorageOutcome {
                status: PrivateStorageOutcomeStatus::Missing as i32,
                ..valid
            },
            PrivateStorageOutcome {
                category: PrivateStorageOutcomeCategory::Timeout as i32,
                ..valid
            },
            PrivateStorageOutcome {
                deadline: PrivateStorageOutcomeDeadline::Operation as i32,
                ..valid
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
