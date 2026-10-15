//! Closed aggregate receiving-side observations, never custody or route acceptance evidence.

use prost::Message;
use serde::Serialize;

use crate::ControlProtocolError;

/// The existing content listener's unchanged concurrent-session limit.
pub const MAX_PROVIDER_SESSIONS: usize = 4;

/// Whether an internally consistent nonblocking snapshot was available.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum ProviderActivityState {
    /// Reserved and rejected on the wire.
    Unspecified = 0,
    /// A bounded aggregate snapshot, including a genuinely empty snapshot.
    Observed = 1,
    /// No reliable snapshot; not an empty or successful operation.
    Unavailable = 2,
}

/// Closed receiving-side stages; no peer, request or storage identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum ProviderActivityStage {
    /// Reserved and rejected on the wire.
    Unspecified = 0,
    /// Application TLS accept.
    TlsHandshake = 1,
    /// Bounded registry clone.
    RegistrySnapshot = 2,
    /// Initial selector read.
    SelectorRead = 3,
    /// Private grant read and verification.
    StorageGrantReadVerify = 4,
    /// Signed challenge write and flush.
    StorageChallengeWriteFlush = 5,
    /// Owner request read and verification, only after challenge flush returned.
    StorageRequestReadVerify = 6,
    /// Verified operation and receipt handling.
    StorageOperation = 7,
    /// Another selected protocol.
    OtherProtocol = 8,
    /// Closing or recording terminal failure.
    Closing = 9,
}

/// Monotone time since entering the current stage, not a timestamp or total request age.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[repr(i32)]
pub enum ProviderActivityElapsedBucket {
    /// Reserved and rejected on the wire.
    #[serde(rename = "unspecified")]
    Unspecified = 0,
    /// Less than one second.
    #[serde(rename = "under_1s")]
    Under1s = 1,
    /// At least one, less than five seconds.
    #[serde(rename = "1_to_5s")]
    From1To5s = 2,
    /// At least five, less than fifteen seconds.
    #[serde(rename = "5_to_15s")]
    From5To15s = 3,
    /// At least fifteen, less than thirty seconds.
    #[serde(rename = "15_to_30s")]
    From15To30s = 4,
    /// At least thirty, less than sixty seconds.
    #[serde(rename = "30_to_60s")]
    From30To60s = 5,
    /// At least sixty, less than ninety seconds.
    #[serde(rename = "60_to_90s")]
    From60To90s = 6,
    /// At least ninety, less than 120 seconds.
    #[serde(rename = "90_to_120s")]
    From90To120s = 7,
    /// At least 120 seconds.
    #[serde(rename = "at_least_120s")]
    AtLeast120s = 8,
}

/// One aggregate group; not an individually identifiable session.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct ProviderActivityGroup {
    /// Closed current stage.
    #[prost(enumeration = "ProviderActivityStage", tag = "1")]
    pub stage: i32,
    /// Closed monotone elapsed bucket.
    #[prost(enumeration = "ProviderActivityElapsedBucket", tag = "2")]
    pub elapsed_bucket: i32,
    /// One through four currently observed sessions.
    #[prost(uint32, tag = "3")]
    pub count: u32,
}

/// Versioned read-only snapshot on the existing protected local control socket.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ContentProviderActivity {
    /// Exactly one; independent from the unchanged outer control version.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Observed or unavailable, never inferred from an empty group vector.
    #[prost(enumeration = "ProviderActivityState", tag = "2")]
    pub state: i32,
    /// Present only for observed snapshots, zero through four.
    #[prost(uint32, optional, tag = "3")]
    pub active_sessions: Option<u32>,
    /// Canonically ordered unique stage/bucket groups; at most four.
    #[prost(message, repeated, tag = "4")]
    pub groups: Vec<ProviderActivityGroup>,
}

impl ContentProviderActivity {
    /// Construct an explicitly unavailable observation without inventing zero activity.
    pub fn unavailable() -> Self {
        Self {
            version: 1,
            state: ProviderActivityState::Unavailable as i32,
            active_sessions: None,
            groups: Vec::new(),
        }
    }

    /// Validate all finite domains, canonical ordering and the shared four-session bound.
    ///
    /// # Errors
    /// Rejects unknown versions/states, inconsistent counts and noncanonical groups.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("content provider activity");
        if self.version != 1 || self.groups.len() > MAX_PROVIDER_SESSIONS {
            return Err(invalid());
        }
        match ProviderActivityState::try_from(self.state).map_err(|_| invalid())? {
            ProviderActivityState::Unspecified => return Err(invalid()),
            ProviderActivityState::Unavailable => {
                return if self.active_sessions.is_none() && self.groups.is_empty() {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            ProviderActivityState::Observed => {}
        }
        let active = self.active_sessions.ok_or_else(invalid)?;
        let maximum = u32::try_from(MAX_PROVIDER_SESSIONS).map_err(|_| invalid())?;
        if active > maximum {
            return Err(invalid());
        }
        let mut previous = None;
        let mut total = 0;
        for group in &self.groups {
            let stage = ProviderActivityStage::try_from(group.stage).map_err(|_| invalid())?;
            let bucket = ProviderActivityElapsedBucket::try_from(group.elapsed_bucket)
                .map_err(|_| invalid())?;
            let key = (group.stage, group.elapsed_bucket);
            if stage == ProviderActivityStage::Unspecified
                || bucket == ProviderActivityElapsedBucket::Unspecified
                || !(1..=maximum).contains(&group.count)
                || previous.is_some_and(|prior| prior >= key)
            {
                return Err(invalid());
            }
            previous = Some(key);
            total += group.count;
        }
        if total != active {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
        control_request::Operation, control_response::Payload, decode_request, decode_response,
        encode_request, encode_response,
    };

    fn snapshot() -> ContentProviderActivity {
        ContentProviderActivity {
            version: 1,
            state: ProviderActivityState::Observed as i32,
            active_sessions: Some(1),
            groups: vec![ProviderActivityGroup {
                stage: ProviderActivityStage::StorageGrantReadVerify as i32,
                elapsed_bucket: ProviderActivityElapsedBucket::From90To120s as i32,
                count: 1,
            }],
        }
    }

    #[test]
    fn provider_activity_round_trips_on_additive_tags_only() {
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            operation: Some(Operation::ContentProviderActivity(Empty {})),
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(&bytes[bytes.len() - 3..], &[0x82, 0x03, 0]); // tag 48
        assert_eq!(decode_request(&bytes).unwrap(), request);
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_PROVIDER_ACTIVITY".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::ContentProviderActivity(snapshot())),
        };
        let bytes = encode_response(&response).unwrap();
        assert!(bytes.windows(2).any(|bytes| bytes == [0xa2, 0x02])); // tag 36
        assert_eq!(decode_response(&bytes).unwrap(), response);
        for (result, code) in [
            (ControlResult::Unavailable, "CONTENT_PROVIDER_ACTIVITY"),
            (ControlResult::Ok, "OK"),
        ] {
            assert!(
                encode_response(&ControlResponse {
                    result: result as i32,
                    diagnostic_code: code.into(),
                    ..response.clone()
                })
                .is_err()
            );
        }
    }

    #[test]
    fn historical_empty_status_and_ack_bytes_remain_exact() {
        let request = ControlRequest {
            protocol_version: 2,
            request_id: vec![7; 16],
            operation: Some(Operation::Status(Empty {})),
        };
        let mut expected = vec![0x08, 0x02, 0x12, 0x10];
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&[0x52, 0x00]);
        assert_eq!(encode_request(&request).unwrap(), expected);
        let response = ControlResponse {
            protocol_version: 2,
            request_id: vec![7; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "OK".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::Ack(Empty {})),
        };
        expected.truncate(20);
        expected.extend_from_slice(&[0x22, 0x02, b'O', b'K', 0x52, 0x00]);
        assert_eq!(encode_response(&response).unwrap(), expected);
    }

    #[test]
    fn unknown_domains_counts_and_noncanonical_groups_fail_closed() {
        let original = snapshot();
        for unknown in [0, -1, 99] {
            let mut value = original.clone();
            value.state = unknown;
            assert!(value.validate().is_err());
            value = original.clone();
            value.groups[0].stage = unknown;
            assert!(value.validate().is_err());
            value = original.clone();
            value.groups[0].elapsed_bucket = unknown;
            assert!(value.validate().is_err());
        }
        for count in [0, 2, 5, u32::MAX] {
            let mut value = original.clone();
            value.groups[0].count = count;
            assert!(value.validate().is_err());
        }
        let mut value = original;
        value.groups.push(value.groups[0]);
        value.active_sessions = Some(2);
        assert!(value.validate().is_err());
        value.groups[1].stage = 3;
        assert!(value.validate().is_err());
        value.groups.reverse();
        value.validate().unwrap();
        value.version = 2;
        assert!(value.validate().is_err());
    }

    #[test]
    fn missing_snapshot_is_not_zero_and_more_than_four_is_rejected() {
        let mut value = ContentProviderActivity::unavailable();
        value.validate().unwrap();
        value.active_sessions = Some(0);
        assert!(value.validate().is_err());
        value.state = ProviderActivityState::Observed as i32;
        value.validate().unwrap();
        value.active_sessions = None;
        assert!(value.validate().is_err());
        value = snapshot();
        value.active_sessions = Some(5);
        value.groups = (1..=5)
            .map(|stage| ProviderActivityGroup {
                stage,
                elapsed_bucket: 1,
                count: 1,
            })
            .collect();
        assert!(value.validate().is_err());
    }
}
