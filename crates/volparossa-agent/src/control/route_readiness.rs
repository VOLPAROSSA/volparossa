//! Existing operator socket, read-only observation only; never route/helper authority.

use volparossa_local_control::RouteReadinessRequest;

use super::{
    ControlContext, ControlResponse, ControlResult, Empty, SessionTransport, control_response,
    requested_connect_profile, response,
};
use crate::{discovery::RouteReadinessError, route_setup::client_preselection_parameters};

pub(super) async fn respond(
    request_id: Vec<u8>,
    request: RouteReadinessRequest,
    context: &ControlContext,
) -> ControlResponse {
    let result = match requested_connect_profile(&context.config, request.transport) {
        Some(profile) if request.transport == Some(SessionTransport::Mptcp as i32) => {
            match client_preselection_parameters(&profile) {
                Ok(parameters) => context.discovery.observe_route_readiness(parameters).await,
                Err(_) => Err(RouteReadinessError::InvalidProfile),
            }
        }
        _ => Err(RouteReadinessError::InvalidProfile),
    };
    match result {
        Ok(observation) => response(
            request_id,
            ControlResult::Ok,
            "ROUTE_ADVERTISEMENT_OBSERVED",
            control_response::Payload::RouteReadiness(observation),
        ),
        Err(error) => {
            let (result, diagnostic) = match error {
                RouteReadinessError::ClientDisabled => {
                    (ControlResult::InvalidState, "CLIENT_ROLE_DISABLED")
                }
                RouteReadinessError::PolicyUnavailable => {
                    (ControlResult::Policy, "POLICY_UNAVAILABLE")
                }
                RouteReadinessError::InvalidProfile => (
                    ControlResult::InvalidRequest,
                    "CLIENT_ROUTE_PROFILE_INVALID",
                ),
                RouteReadinessError::Timeout
                | RouteReadinessError::Closed
                | RouteReadinessError::StoreUnavailable => {
                    (ControlResult::Unavailable, "ROUTE_OBSERVATION_UNAVAILABLE")
                }
            };
            response(
                request_id,
                result,
                diagnostic,
                control_response::Payload::Ack(Empty {}),
            )
        }
    }
}
