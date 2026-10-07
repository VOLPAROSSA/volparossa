//! Read-only actor observation. No affine owner, probe, reservation or route is acquired.

use volparossa_local_control::{
    RouteReadinessObservation, RouteReadinessOutcome, SessionTransport,
};

use super::{
    AgentPolicySnapshot, AgentState, ClientPreselectionParameters, DiscoveryCommand,
    DiscoveryControlHandle, DiscoveryRuntime, PreselectionSamplingError, PreselectionSamplingScope,
    ROLE_COMMAND_TIMEOUT, RouteCandidateSnapshotError, Transport,
    client_preselection_parameters_are_valid, narrow_route_candidate_snapshot, oneshot, timeout,
    unix_millis,
};

/// Operational failures are distinct from a completed, negative sampler observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteReadinessError {
    Timeout,
    Closed,
    ClientDisabled,
    PolicyUnavailable,
    InvalidProfile,
    StoreUnavailable,
}

impl DiscoveryControlHandle {
    pub(crate) async fn observe_route_readiness(
        &self,
        parameters: ClientPreselectionParameters,
    ) -> Result<RouteReadinessObservation, RouteReadinessError> {
        let (reply, response) = oneshot::channel();
        timeout(ROLE_COMMAND_TIMEOUT, async {
            self.sender
                .send(DiscoveryCommand::ObserveRouteReadiness { parameters, reply })
                .await
                .map_err(|_| RouteReadinessError::Closed)?;
            response.await.map_err(|_| RouteReadinessError::Closed)?
        })
        .await
        .map_err(|_| RouteReadinessError::Timeout)?
    }
}

impl DiscoveryRuntime {
    pub(super) fn reply_route_readiness(
        &self,
        parameters: &ClientPreselectionParameters,
        reply: oneshot::Sender<Result<RouteReadinessObservation, RouteReadinessError>>,
        state: &AgentState,
    ) {
        if reply.is_closed() {
            return;
        }
        let captured_at_ms = unix_millis();
        let result = if state.roles().client {
            self.observe_advertisement_slate(
                parameters,
                captured_at_ms,
                &state.policy_snapshot(captured_at_ms),
            )
        } else {
            Err(RouteReadinessError::ClientDisabled)
        };
        // Keep role/policy observation coherent with this actor turn; no writes or await
        // occur during projection and sampling. In particular do not purge capabilities.
        let _ = reply.send(result);
    }

    pub(super) fn observe_advertisement_slate(
        &self,
        parameters: &ClientPreselectionParameters,
        captured_at_ms: u64,
        policy: &AgentPolicySnapshot,
    ) -> Result<RouteReadinessObservation, RouteReadinessError> {
        if !client_preselection_parameters_are_valid(parameters)
            || parameters.transport != Transport::TcpMptcp
            || parameters.restriction.is_some()
        {
            return Err(RouteReadinessError::InvalidProfile);
        }
        let scope = PreselectionSamplingScope::new(
            parameters.transport,
            parameters.address_family,
            parameters.minimum_capacity,
            parameters.minimum_other_relays,
            parameters.maximum_other_relays,
        );
        let snapshot = self
            .build_route_candidate_snapshot_with_scope(
                parameters.requested_candidate_bound,
                captured_at_ms,
                policy,
                None,
                Some(scope),
            )
            .map_err(|error| match error {
                RouteCandidateSnapshotError::InvalidLimit => RouteReadinessError::InvalidProfile,
                RouteCandidateSnapshotError::PolicyUnavailable => {
                    RouteReadinessError::PolicyUnavailable
                }
                _ => RouteReadinessError::StoreUnavailable,
            })?;
        // The unchanged sampler consumes a temporary slate, not its affine attempt gate.
        // Drop both successful and failed slates. A later Connect draws/checks independently.
        let outcome = match narrow_route_candidate_snapshot(snapshot, scope) {
            Ok(_) => RouteReadinessOutcome::EligibleAdvertisementSlate,
            Err(failure) => match failure.error {
                PreselectionSamplingError::InvalidPolicy => {
                    return Err(RouteReadinessError::InvalidProfile);
                }
                PreselectionSamplingError::InvalidSnapshot => {
                    RouteReadinessOutcome::IncompleteSnapshot
                }
                PreselectionSamplingError::NoEligibleForwardedExit => {
                    RouteReadinessOutcome::NoEligibleExitPair
                }
                PreselectionSamplingError::InsufficientDiverseRelays => {
                    RouteReadinessOutcome::InsufficientDiverseRelays
                }
                PreselectionSamplingError::Entropy => RouteReadinessOutcome::ObservationUnavailable,
            },
        };
        Ok(RouteReadinessObservation {
            transport: Some(SessionTransport::Mptcp as i32),
            captured_at_unix_ms: captured_at_ms,
            outcome: outcome as i32,
        })
    }
}
