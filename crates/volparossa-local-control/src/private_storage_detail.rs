//! Closed pre-READY observations, not a diagnosis of a remote provider's cause.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{ControlProtocolError, ControlResponse, ControlResult, control_response::Payload};

mod challenge;
mod flow_acquire;
pub use challenge::{
    PrivateStorageChallengeDetail, PrivateStorageChallengePhase, PrivateStorageChallengeReadDetail,
    PrivateStorageChallengeReadOutcome, PrivateStorageChallengeReadStep,
    PrivateStorageElapsedBucket,
};
pub use flow_acquire::{
    PrivateStorageFlowAcquireDetail, PrivateStorageFlowAcquireFailure,
    PrivateStorageFlowAcquireReason, PrivateStorageFlowAcquireStage,
};

/// Last polled private-storage preparation boundary; never a remote denial claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageRemoteStage {
    /// No preparation boundary was observed, for example while awaiting admission.
    Unobserved = 0,
    /// Establishing the existing protected client route.
    RouteConnect = 1,
    /// Selecting the route's current content discovery control.
    ControlSelection = 2,
    /// Looking up the independently selected provider.
    ProviderLookup = 3,
    /// Checking the returned provider count and identity.
    ProviderCardinality = 4,
    /// Checking the selected offer's remaining validity.
    OfferValidity = 5,
    /// Opening the selected provider's protected stream.
    StreamOpen = 6,
    /// Performing the provider TLS handshake.
    TlsHandshake = 7,
    /// Beginning the original signed-grant challenge exchange.
    Challenge = 8,
}

/// Which existing local deadline actually elapsed, not why the remote work stalled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageDeadlineScope {
    /// Neither enclosing local timeout was observed to elapse.
    None = 0,
    /// The outer complete private-storage operation budget elapsed.
    Operation = 1,
    /// The inner grant/offer-bounded exchange budget elapsed.
    Exchange = 2,
}

/// Request-local TLS failure class, never a diagnosis of the remote provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageTlsFailure {
    /// Reserved; an absent observation must be encoded as no optional field.
    Unobserved = 0,
    /// The existing offer identity, hostname or lifetime check failed.
    Offer = 1,
    /// The existing local TLS configuration could not be constructed.
    Configuration = 2,
    /// The existing local ten-second handshake timeout actually elapsed.
    HandshakeDeadline = 3,
    /// A typed TLS certificate error was returned, possibly by the outer stream.
    Authentication = 4,
    /// Another typed TLS error or the existing ALPN/version check failed.
    TlsOther = 5,
    /// Another I/O error was returned, not proof of a local handshake deadline.
    Io = 6,
}

/// Returned protected-stream opening boundary, without a raw transport error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageStreamFailure {
    /// Reserved; absence is encoded with no optional field.
    Unobserved = 0,
    /// The current route policy does not permit this stream.
    Policy = 1,
    /// The route is not in a usable established state.
    RouteState = 2,
    /// Required route transport material is unavailable.
    RouteMaterial = 3,
    /// Existing bounded flow acquisition or descriptor adoption failed.
    FlowAcquire = 4,
    /// Transport certificate construction failed.
    TransportCertificate = 5,
    /// The outer transport TLS handshake failed, including its own deadline.
    TransportTls = 6,
    /// Initial transport path setup failed.
    InitialPaths = 7,
    /// Writing or flushing the original `OPEN_TCP` frame failed; not a remote ACK.
    OpenTcpWrite = 8,
    /// Required kernel subflows did not become ready.
    SubflowReadiness = 9,
    /// Attaching the stream to its existing observation owner failed.
    StreamAttachment = 10,
}

/// Optional bounded detail on a failed initial private-storage control response.
/// Old peers ignore this additive field and still receive the same result/code/Ack.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageRemoteDetail {
    /// Closed observed preparation boundary.
    #[prost(enumeration = "PrivateStorageRemoteStage", tag = "1")]
    pub stage: i32,
    /// Closed enclosing timeout observation.
    #[prost(enumeration = "PrivateStorageDeadlineScope", tag = "2")]
    pub deadline_scope: i32,
    /// Optional returned TLS failure; no payload, identity, address or error text.
    #[prost(enumeration = "PrivateStorageTlsFailure", optional, tag = "3")]
    pub tls_failure: Option<i32>,
    /// Optional protected-stream failure; distinct from the later provider TLS.
    #[prost(enumeration = "PrivateStorageStreamFailure", optional, tag = "4")]
    pub stream_failure: Option<i32>,
    /// Optional request-local challenge progress and coarse elapsed budgets.
    #[prost(message, optional, tag = "5")]
    pub challenge: Option<PrivateStorageChallengeDetail>,
    /// Optional first/last returned flow-acquisition failures; no runtime identifiers.
    #[prost(message, optional, tag = "6")]
    pub flow_acquire: Option<PrivateStorageFlowAcquireDetail>,
}

impl PrivateStorageRemoteDetail {
    /// Validate the same closed stage/deadline matrix used by wire and JSON readers.
    ///
    /// # Errors
    /// Rejects unknown enums and combinations this observer cannot produce.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        let stage = PrivateStorageRemoteStage::try_from(self.stage)
            .map_err(|_| ControlProtocolError::Invalid("private storage detail stage"))?;
        let deadline = PrivateStorageDeadlineScope::try_from(self.deadline_scope)
            .map_err(|_| ControlProtocolError::Invalid("private storage detail deadline"))?;
        let valid = match deadline {
            PrivateStorageDeadlineScope::None => stage != PrivateStorageRemoteStage::Unobserved,
            PrivateStorageDeadlineScope::Operation => true,
            PrivateStorageDeadlineScope::Exchange => matches!(
                stage,
                PrivateStorageRemoteStage::StreamOpen
                    | PrivateStorageRemoteStage::TlsHandshake
                    | PrivateStorageRemoteStage::Challenge
            ),
        };
        if !valid {
            return Err(ControlProtocolError::Invalid(
                "private storage detail combination",
            ));
        }
        if let Some(failure) = self.tls_failure {
            let failure = PrivateStorageTlsFailure::try_from(failure)
                .map_err(|_| ControlProtocolError::Invalid("private storage TLS failure"))?;
            if failure == PrivateStorageTlsFailure::Unobserved
                || stage != PrivateStorageRemoteStage::TlsHandshake
                || deadline != PrivateStorageDeadlineScope::None
            {
                return Err(ControlProtocolError::Invalid(
                    "private storage TLS combination",
                ));
            }
        }
        if let Some(failure) = self.stream_failure {
            let failure = PrivateStorageStreamFailure::try_from(failure)
                .map_err(|_| ControlProtocolError::Invalid("private storage stream failure"))?;
            if failure == PrivateStorageStreamFailure::Unobserved
                || stage != PrivateStorageRemoteStage::StreamOpen
                || deadline != PrivateStorageDeadlineScope::None
                || self.tls_failure.is_some()
            {
                return Err(ControlProtocolError::Invalid(
                    "private storage stream combination",
                ));
            }
        }
        if let Some(challenge) = self.challenge {
            challenge.validate()?;
            if stage != PrivateStorageRemoteStage::Challenge
                || self.tls_failure.is_some()
                || self.stream_failure.is_some()
            {
                return Err(ControlProtocolError::Invalid(
                    "private storage challenge combination",
                ));
            }
        }
        if let Some(flow) = self.flow_acquire {
            flow.validate()?;
            if stage != PrivateStorageRemoteStage::StreamOpen
                || deadline != PrivateStorageDeadlineScope::None
                || self.stream_failure != Some(PrivateStorageStreamFailure::FlowAcquire as i32)
                || self.tls_failure.is_some()
                || self.challenge.is_some()
            {
                return Err(ControlProtocolError::Invalid(
                    "private storage flow acquisition combination",
                ));
            }
        }
        Ok(())
    }

    /// Validate a closed failure code/result against this observed detail.
    ///
    /// # Errors
    /// Rejects success, other codes/results, and a timeout without the existing unavailable result.
    pub fn validate_rejection(
        &self,
        result: ControlResult,
        code: &str,
    ) -> Result<(), ControlProtocolError> {
        self.validate()?;
        let expected = match code {
            "CONTENT_INVALID" => ControlResult::InvalidRequest,
            "CONTENT_UNAVAILABLE" => ControlResult::Unavailable,
            "CONTENT_BUSY" => ControlResult::InvalidState,
            "CONTENT_POLICY" => ControlResult::Policy,
            _ => return Err(ControlProtocolError::Invalid("private storage detail code")),
        };
        if result != expected
            || ((self.deadline_scope != PrivateStorageDeadlineScope::None as i32
                || self.tls_failure.is_some()
                || self.stream_failure.is_some()
                || self.challenge.is_some()
                || self.flow_acquire.is_some())
                && result != ControlResult::Unavailable)
        {
            return Err(ControlProtocolError::Invalid(
                "private storage detail result",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate(response: &ControlResponse) -> Result<(), ControlProtocolError> {
    let Some(detail) = response.private_storage_remote_detail else {
        return Ok(());
    };
    let result = ControlResult::try_from(response.result)
        .map_err(|_| ControlProtocolError::Invalid("result"))?;
    detail.validate_rejection(result, &response.diagnostic_code)?;
    if !matches!(response.payload, Some(Payload::Ack(_))) {
        return Err(ControlProtocolError::Invalid(
            "private storage detail envelope",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
