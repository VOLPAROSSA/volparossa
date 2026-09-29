//! A native sample ordinal is not an established route path ID. Only this
//! authenticated extension binding may project a new two-path sample onto one
//! new retained path; initial admission keeps its original ordinal equality.

use volparossa_protocol::{
    ControlPayload, ExitReservation, RelayProbePermit, RelayProbeResult, ReplayCache,
    RouteExtensionPhase, RouteExtensionRequest, RouteExtensionScope, TimePolicy, Transport,
    verify_control_message,
};

use super::super::{RecentNativeExitEvidence, native_ready};

pub(in super::super) struct ExtensionEvidenceBinding {
    permit: Vec<u8>,
    path_id: u32,
    created_at_ms: u64,
}

impl ExtensionEvidenceBinding {
    pub(in super::super) fn new(request: &RouteExtensionRequest, now_ms: u64) -> Option<Self> {
        request.validate().ok()?;
        if request.phase != RouteExtensionPhase::Authorize as i32 {
            return None;
        }
        let scope = request.scope.as_ref()?;
        let path = request.path.as_ref()?;
        let parent = verify_control_message::<ExitReservation>(
            &scope.signed_exit_reservation,
            now_ms,
            TimePolicy::default(),
            &mut ReplayCache::new(1).ok()?,
        )
        .ok()?;
        let permit = verify_control_message::<RelayProbePermit>(
            &path.relay_probe_permit,
            now_ms,
            TimePolicy::default(),
            &mut ReplayCache::new(1).ok()?,
        )
        .ok()?;
        if parent.sender_id().as_slice() != parent.message().exit_node_id
            || permit.sender_id() != parent.sender_id()
            || !matches_parent(permit.message(), scope, parent.message())
        {
            return None;
        }
        Some(Self {
            permit: path.relay_probe_permit.clone(),
            path_id: scope.path_id,
            created_at_ms: permit.message().created_at_ms,
        })
    }

    pub(in super::super) fn matches(
        &self,
        ticket: &RecentNativeExitEvidence,
        tickets: &[RecentNativeExitEvidence],
        result: &RelayProbeResult,
        permit: &RelayProbePermit,
        now_ms: u64,
    ) -> bool {
        // The exact signed permit pins parent/session/control/Exit/Relay and the
        // retained path. It does not rename or modify the native signed scope.
        result.relay_probe_permit == self.permit
            && permit.path_id == self.path_id
            && permit.created_at_ms == self.created_at_ms
            && ticket.measured_at_ms >= self.created_at_ms
            && [&result.client_relay, &result.relay_exit]
                .into_iter()
                .all(|leg| {
                    leg.as_ref()
                        .is_some_and(|leg| leg.window_started_at_ms >= self.created_at_ms)
                })
            && same_complete_batch(ticket, tickets, self.created_at_ms, now_ms)
    }
}

fn matches_parent(
    p: &RelayProbePermit,
    scope: &RouteExtensionScope,
    parent: &ExitReservation,
) -> bool {
    p.path_id == scope.path_id
        && p.probe_id == scope.probe_id
        && p.relay_node_id == scope.relay_node_id
        && p.relay_peer_id == scope.relay_peer_id
        && p.address_family == scope.address_family
        && p.reservation_id == parent.reservation_id
        && p.route_context_id == parent.route_context_id
        && p.client_session_id == parent.client_session_id
        && p.exit_node_id == parent.exit_node_id
        && p.exit_peer_id == parent.exit_peer_id
        && p.exit_boot_id == parent.exit_boot_id
        && p.capability_id == parent.capability_id
        && p.hold_id == parent.hold_id
        && p.policy_hash == parent.policy_hash
        && p.control_relay_node_id == parent.control_relay_node_id
        && p.control_relay_peer_id == parent.control_relay_peer_id
        && p.transport == Transport::TcpMptcp as i32
        && p.created_at_ms >= parent.created_at_ms
        && p.expires_at_ms <= parent.expires_at_ms
}

fn same_complete_batch(
    ticket: &RecentNativeExitEvidence,
    tickets: &[RecentNativeExitEvidence],
    permit_created_ms: u64,
    now_ms: u64,
) -> bool {
    let scope = &ticket.scope;
    if scope.required_path_count != 2 || !(1..=2).contains(&scope.candidate_ordinal) {
        return false;
    }
    let batch = tickets
        .iter()
        .filter(|entry| entry.scope.attempt_id == scope.attempt_id)
        .collect::<Vec<_>>();
    if batch.len() != 2 || batch[0].scope.candidate_ordinal == batch[1].scope.candidate_ordinal {
        return false;
    }
    let (Some(first), Some(second)) = (&batch[0].scope.data_relay, &batch[1].scope.data_relay)
    else {
        return false;
    };
    first.node_id != second.node_id
        && first.peer_id != second.peer_id
        && batch.into_iter().all(|entry| {
            let candidate = &entry.scope;
            let Some(relay) = candidate.data_relay.as_ref() else {
                return false;
            };
            // Reuse the Ready collector's exact common-attempt comparison. Session
            // identities, probe IDs and challenges are independently signed per path;
            // requiring their equality would reject the real sampler's fresh keys.
            native_ready::same_attempt(candidate, scope)
                && candidate.required_path_count == 2
                && (1..=2).contains(&candidate.candidate_ordinal)
                && entry.authenticated_data_relay_node_id.as_slice() == relay.node_id
                && entry.authenticated_data_relay_peer_id == relay.peer_id
                && entry.measured_at_ms >= permit_created_ms
                && entry.measured_at_ms <= now_ms
                && entry.expires_at_ms > now_ms
                && entry.expires_at_ms <= candidate.attempt_expires_at_ms
        })
}

#[cfg(test)]
mod tests;
