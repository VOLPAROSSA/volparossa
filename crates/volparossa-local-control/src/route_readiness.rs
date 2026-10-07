//! Read-only, endpoint-free observation of the current advertisement preselection slate.

use prost::{Enumeration, Message};

use crate::{ControlProtocolError, SessionTransport};

/// Observe the configured MPTCP profile without selecting endpoints or connecting.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct RouteReadinessRequest {
    /// Explicit transport; this initial observation interface supports MPTCP only.
    #[prost(enumeration = "SessionTransport", optional, tag = "1")]
    pub transport: Option<i32>,
}

impl RouteReadinessRequest {
    pub(crate) fn validate(self) -> Result<(), ControlProtocolError> {
        if self.transport != Some(SessionTransport::Mptcp as i32) {
            return Err(ControlProtocolError::Invalid("readiness transport"));
        }
        Ok(())
    }
}

/// A bounded observation, never route, reservation, dispatch or dataplane authority.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct RouteReadinessObservation {
    /// Exact request transport.
    #[prost(enumeration = "SessionTransport", optional, tag = "1")]
    pub transport: Option<i32>,
    /// Time the actor captured its current signed advertisement/capability projection.
    #[prost(uint64, tag = "2")]
    pub captured_at_unix_ms: u64,
    /// Closed sampler outcome. Absence or an unknown value is never success.
    #[prost(enumeration = "RouteReadinessOutcome", tag = "3")]
    pub outcome: i32,
}

impl RouteReadinessObservation {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        RouteReadinessRequest {
            transport: self.transport,
        }
        .validate()?;
        if self.captured_at_unix_ms == 0
            || !matches!(RouteReadinessOutcome::try_from(self.outcome), Ok(value) if value != RouteReadinessOutcome::Unspecified)
        {
            return Err(ControlProtocolError::Invalid("readiness observation"));
        }
        Ok(())
    }
}

/// Static advertisement eligibility is weaker than measured dataplane availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum RouteReadinessOutcome {
    /// Invalid default.
    Unspecified = 0,
    /// One complete slate passed the unchanged production sampler; the slate was discarded.
    EligibleAdvertisementSlate = 1,
    /// Live signed snapshot or its exact capability bindings were incomplete.
    IncompleteSnapshot = 2,
    /// No forwarded Exit/control pair passed static eligibility.
    NoEligibleExitPair = 3,
    /// This bounded draw lacked sufficient eligible, diverse other relays.
    InsufficientDiverseRelays = 4,
    /// The bounded sampler could not obtain its required entropy.
    ObservationUnavailable = 5,
}

#[cfg(test)]
mod tests {
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, control_request,
        control_response, decode_request, decode_response, encode_request, encode_response,
    };

    use super::*;

    #[test]
    fn route_readiness_wire_roundtrip_is_additive_and_strict() {
        let mut request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            operation: Some(control_request::Operation::RouteReadiness(
                RouteReadinessRequest {
                    transport: Some(SessionTransport::Mptcp as i32),
                },
            )),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        for transport in [
            None,
            Some(1),
            Some(-1),
            Some(999),
            Some(SessionTransport::ProtectedDns as i32),
        ] {
            request.operation = Some(control_request::Operation::RouteReadiness(
                RouteReadinessRequest { transport },
            ));
            assert!(encode_request(&request).is_err());
        }
        for outcome in 1..=5 {
            let mut response = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![3; 16],
                result: ControlResult::Ok as i32,
                diagnostic_code: "ROUTE_ADVERTISEMENT_OBSERVED".into(),
                payload: Some(control_response::Payload::RouteReadiness(
                    RouteReadinessObservation {
                        transport: Some(SessionTransport::Mptcp as i32),
                        captured_at_unix_ms: 1000,
                        outcome,
                    },
                )),
            };
            assert_eq!(
                decode_response(&encode_response(&response).unwrap()).unwrap(),
                response
            );
            for bad in [0, -1, 6, 999] {
                response.payload = Some(control_response::Payload::RouteReadiness(
                    RouteReadinessObservation {
                        transport: Some(SessionTransport::Mptcp as i32),
                        captured_at_unix_ms: 1000,
                        outcome: bad,
                    },
                ));
                assert!(encode_response(&response).is_err());
            }
        }
    }

    #[test]
    fn route_readiness_missing_time_or_transport_is_not_an_observation() {
        let mut observation = RouteReadinessObservation {
            transport: Some(SessionTransport::Mptcp as i32),
            captured_at_unix_ms: 0,
            outcome: RouteReadinessOutcome::EligibleAdvertisementSlate as i32,
        };
        assert!(observation.validate().is_err());
        observation.captured_at_unix_ms = 1;
        observation.transport = None;
        assert!(observation.validate().is_err());
    }
}
