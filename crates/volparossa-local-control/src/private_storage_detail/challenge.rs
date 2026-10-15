//! Closed local challenge progress; no exact timestamps or remote-cause attribution.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::ControlProtocolError;

/// Last existing grant/challenge I/O boundary actually entered by this request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageChallengePhase {
    /// Reserved; an absent observation uses no optional message.
    Unobserved = 0,
    /// Write and flush the existing private-storage selector frame.
    SelectorWriteFlush = 1,
    /// Write and flush the existing signed grant frame.
    GrantWriteFlush = 2,
    /// Read and verify the provider's existing signed challenge frame.
    ChallengeReadVerify = 3,
}

/// Coarse elapsed intervals, lower bound inclusive and upper bound exclusive.
/// These are observations, not new deadlines or advice to enlarge a budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[repr(i32)]
pub enum PrivateStorageElapsedBucket {
    /// Reserved; all fields of an observed challenge must be populated.
    #[serde(rename = "unobserved")]
    Unobserved = 0,
    /// Less than one second, including zero.
    #[serde(rename = "under_1s")]
    Under1s = 1,
    /// At least one second and less than five seconds.
    #[serde(rename = "1_to_5s")]
    S1To5 = 2,
    /// At least five seconds and less than fifteen seconds.
    #[serde(rename = "5_to_15s")]
    S5To15 = 3,
    /// At least fifteen seconds and less than thirty seconds.
    #[serde(rename = "15_to_30s")]
    S15To30 = 4,
    /// At least thirty seconds and less than sixty seconds.
    #[serde(rename = "30_to_60s")]
    S30To60 = 5,
    /// At least sixty seconds and less than ninety seconds.
    #[serde(rename = "60_to_90s")]
    S60To90 = 6,
    /// At least ninety seconds and less than one hundred twenty seconds.
    #[serde(rename = "90_to_120s")]
    S90To120 = 7,
    /// At least one hundred twenty seconds; no claim of timely reactor polling.
    #[serde(rename = "at_least_120s")]
    AtLeast120s = 8,
}

/// Bounded request-local observation, present only on a failed initial challenge.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageChallengeDetail {
    /// Last observed substep of the existing challenge exchange.
    #[prost(enumeration = "PrivateStorageChallengePhase", tag = "1")]
    pub phase: i32,
    /// Operation budget already spent when the challenge boundary was entered.
    #[prost(enumeration = "PrivateStorageElapsedBucket", tag = "2")]
    pub before_challenge: i32,
    /// Elapsed time within that challenge boundary when failure was observed.
    #[prost(enumeration = "PrivateStorageElapsedBucket", tag = "3")]
    pub in_challenge: i32,
}

impl PrivateStorageChallengeDetail {
    pub(super) fn validate(self) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("private storage challenge detail");
        let phase = PrivateStorageChallengePhase::try_from(self.phase).map_err(|_| invalid())?;
        if phase == PrivateStorageChallengePhase::Unobserved {
            return Err(invalid());
        }
        for value in [self.before_challenge, self.in_challenge] {
            let bucket = PrivateStorageElapsedBucket::try_from(value).map_err(|_| invalid())?;
            if bucket == PrivateStorageElapsedBucket::Unobserved {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
