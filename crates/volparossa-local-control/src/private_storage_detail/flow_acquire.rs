//! Returned local flow-acquisition boundaries, not remote cause or cleanup authority.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::ControlProtocolError;

/// Existing acquisition boundary that returned a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageFlowAcquireStage {
    /// Reserved; missing detail uses no optional message.
    Unobserved = 0,
    /// Select the original random source port.
    SourcePort = 1,
    /// Drain previously owned descriptor retirements.
    RetirementDrain = 2,
    /// Obtain and validate existing route material.
    Material = 3,
    /// Reserve a slot in the existing local retirement owner.
    SlotReservation = 4,
    /// Acquire a descriptor through the original helper request.
    HelperAcquire = 5,
    /// Clone the acquired descriptor for retirement ownership.
    DescriptorClone = 6,
    /// Adopt the descriptor as the existing MPTCP stream.
    DescriptorAdoption = 7,
    /// Bind validated flow metadata to its existing path owner.
    FlowMetadata = 8,
}

/// Closed typed error class, with no error message or inferred remote cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageFlowAcquireReason {
    /// Reserved; never an observed failure.
    Unobserved = 0,
    /// The original randomness operation failed.
    Entropy = 1,
    /// Required local metadata was missing or invalid.
    Metadata = 2,
    /// The original local semaphore returned `NoPermits`.
    LocalCapacity = 3,
    /// The original local semaphore was closed.
    LocalUnavailable = 4,
    /// Earlier acquisition ownership still requires confirmed retirement.
    Unconfirmed = 5,
    /// Local I/O failed, without inferring capacity or a deadline.
    Io = 6,
    /// Existing route topology validation failed.
    Topology = 7,
    /// The helper returned its closed Kernel result.
    HelperKernel = 8,
    /// The helper returned its closed Capacity result.
    HelperCapacity = 9,
    /// The helper returned its closed Unavailable result.
    HelperUnavailable = 10,
    /// The helper returned `NotFound`; retirement consumes it as success instead.
    HelperNotFound = 11,
    /// The helper returned `CleanupIncomplete`; no cleanup success is implied.
    HelperCleanupIncomplete = 12,
    /// Another known closed helper rejection result.
    HelperOtherRejection = 13,
    /// The existing helper-client deadline returned Timeout.
    HelperTimeout = 14,
    /// Helper-client I/O failed, without inferring capacity.
    HelperIo = 15,
    /// Protocol, descriptor or one-use-capability validation failed.
    HelperValidation = 16,
    /// Existing helper token/server authority validation failed.
    HelperAuthority = 17,
    /// The helper response did not correlate with its request.
    HelperCorrelation = 18,
    /// The helper-client runtime changed.
    HelperRuntimeChanged = 19,
}

/// One returned boundary; no timing, identity or transport-success assertion.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageFlowAcquireFailure {
    /// Observed local boundary.
    #[prost(enumeration = "PrivateStorageFlowAcquireStage", tag = "1")]
    pub stage: i32,
    /// Typed returned failure class.
    #[prost(enumeration = "PrivateStorageFlowAcquireReason", tag = "2")]
    pub reason: i32,
}

impl PrivateStorageFlowAcquireFailure {
    fn validate(self) -> Result<(), ControlProtocolError> {
        use PrivateStorageFlowAcquireReason as Reason;
        use PrivateStorageFlowAcquireStage as Stage;

        let invalid = || ControlProtocolError::Invalid("private storage flow acquisition failure");
        let stage = Stage::try_from(self.stage).map_err(|_| invalid())?;
        let reason = Reason::try_from(self.reason).map_err(|_| invalid())?;
        let helper = matches!(
            reason,
            Reason::HelperKernel
                | Reason::HelperCapacity
                | Reason::HelperUnavailable
                | Reason::HelperNotFound
                | Reason::HelperCleanupIncomplete
                | Reason::HelperOtherRejection
                | Reason::HelperTimeout
                | Reason::HelperIo
                | Reason::HelperValidation
                | Reason::HelperAuthority
                | Reason::HelperCorrelation
                | Reason::HelperRuntimeChanged
        );
        let valid = match stage {
            Stage::Unobserved => false,
            Stage::SourcePort => reason == Reason::Entropy,
            Stage::RetirementDrain => {
                matches!(reason, Reason::Unconfirmed | Reason::Io)
                    || (helper && reason != Reason::HelperNotFound)
            }
            Stage::Material => matches!(reason, Reason::Metadata | Reason::Topology),
            Stage::SlotReservation => matches!(
                reason,
                Reason::Unconfirmed | Reason::LocalCapacity | Reason::LocalUnavailable
            ),
            Stage::HelperAcquire => helper,
            Stage::DescriptorClone => reason == Reason::Io,
            Stage::DescriptorAdoption => matches!(reason, Reason::Metadata | Reason::Io),
            Stage::FlowMetadata => reason == Reason::Metadata,
        };
        if !valid {
            return Err(invalid());
        }
        Ok(())
    }
}

/// First and last failures in the original bounded acquisition loop.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageFlowAcquireDetail {
    /// Existing loop iterations, 1..=8; not helper requests or remote operations.
    #[prost(uint32, tag = "1")]
    pub rounds: u32,
    /// First returned failing boundary; mandatory when this message is present.
    #[prost(message, optional, tag = "2")]
    pub first: Option<PrivateStorageFlowAcquireFailure>,
    /// Last returned failing boundary; mandatory when this message is present.
    #[prost(message, optional, tag = "3")]
    pub last: Option<PrivateStorageFlowAcquireFailure>,
}

impl PrivateStorageFlowAcquireDetail {
    /// Validate the fixed 35-pair boundary matrix and original loop bound.
    ///
    /// # Errors
    /// Rejects missing endpoints, unknown/zero enums, invalid combinations or counts.
    pub fn validate(self) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("private storage flow acquisition detail");
        let first = self.first.ok_or_else(invalid)?;
        let last = self.last.ok_or_else(invalid)?;
        if !(1..=8).contains(&self.rounds) || (self.rounds == 1 && first != last) {
            return Err(invalid());
        }
        first.validate()?;
        last.validate()
    }
}

#[cfg(test)]
mod tests;
