//! Verify signed adjacent budgets against retained exact activation authority before worker IPC.

use super::{
    BackendAction, BackendBinding, BackendError, ContextRole, FunctionalAlphaLeaseBackend,
    HardDeadline, OpenLeasePhase, OpenLineageKey, OperationKind, SocketAddr, WireguardRole,
    current_boottime_nanos, ensure_hard_is_live, entry_generation, exact_entry, exact_entry_mut,
    internal_worker_request, internal_worker_response, lock_replay_cache, lock_state,
    prepare_deadline, response_error, unix_milliseconds, worker_request,
};
use crate::{
    internal_protocol::ApplyWorkerDownlinkBudget, kernel::receive_accounting::ReceiveTuple,
};
use std::{collections::BTreeMap, time::Duration};
use volparossa_protocol::verify_adjacent_receive_budget;
use volparossa_routing::{AppliedDownlinkBudget, ApplyDownlinkBudget, LeaseActivation};

pub(super) struct BudgetLeaseState {
    lease_handle: Vec<u8>,
    signed_grant: Vec<u8>,
    sequence: u64,
}

pub(super) fn activated_budget_grants(
    activations: &[LeaseActivation],
    required: &[u32],
) -> BTreeMap<u32, BudgetLeaseState> {
    activations
        .iter()
        .filter(|activation| required.contains(&activation.path_id))
        .map(|activation| {
            (
                activation.path_id,
                BudgetLeaseState {
                    lease_handle: activation.lease_handle.clone(),
                    signed_grant: activation.signed_relay_reservation.clone(),
                    sequence: 0,
                },
            )
        })
        .collect()
}

impl FunctionalAlphaLeaseBackend {
    #[expect(
        clippy::too_many_lines,
        reason = "retain exact signed authority and worker mutation in one bounded operation"
    )]
    pub(super) async fn apply_downlink_one(
        &self,
        binding: BackendBinding,
        value: ApplyDownlinkBudget,
    ) -> Result<AppliedDownlinkBudget, BackendError> {
        let key = OpenLineageKey::from(binding.lineage);
        if binding.action != BackendAction::ApplyDownlinkBudget
            || binding.operation_kind != OperationKind::DownlinkBudget
            || value.route_context_id.as_slice() != key.context_id
            || binding.operation_generation != key.backend_generation
            || binding.operation_sequence == 0
            || !matches!(
                binding.prior_phase,
                Some(super::ContextPhase::Activated | super::ContextPhase::Committed)
            )
        {
            return Err(BackendError::Invalid);
        }
        ensure_hard_is_live(key)?;
        let outer_deadline = prepare_deadline(binding)?;
        // Leave sufficient signed TTL for the kernel gate. This does not extend the engine's
        // absolute deadline or retry any ambiguous privileged mutation.
        let deadline = HardDeadline::at(
            outer_deadline
                .expires_at()
                .min(std::time::Instant::now() + Duration::from_millis(500)),
        )
        .map_err(|_| BackendError::Unavailable)?;
        let now_ms = unix_milliseconds()?;
        let now_boot = current_boottime_nanos()?;
        let operation = {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            if entry.context_role != ContextRole::Exit
                || !matches!(
                    entry.phase,
                    OpenLeasePhase::Activated | OpenLeasePhase::Committed
                )
            {
                return Err(BackendError::Invalid);
            }
            let (path_id, owner) = entry
                .downlink
                .iter_mut()
                .find(|(_, owner)| owner.lease_handle == value.lease_handle)
                .ok_or(BackendError::Invalid)?;
            let mut replay = lock_replay_cache(&self.relay_replay);
            let verified = verify_adjacent_receive_budget(
                &value.signed_budget,
                &owner.signed_grant,
                now_ms,
                owner.sequence,
                &mut replay,
            )
            .map_err(|_| BackendError::Invalid)?;
            let message = verified.message();
            if message.route_context_id.as_slice() != key.context_id || message.path_id != *path_id
            {
                return Err(BackendError::Invalid);
            }
            let remaining_ms = message
                .expires_at_ms
                .checked_sub(now_ms)
                .ok_or(BackendError::Unavailable)?;
            if remaining_ms <= 600 {
                return Err(BackendError::Unavailable);
            }
            let expires_boot = now_boot
                .checked_add(remaining_ms * 1_000_000)
                .ok_or(BackendError::Invalid)?;
            if expires_boot > key.hard_expires_at_boottime_ns {
                return Err(BackendError::Invalid);
            }
            owner.sequence = message.sequence;
            ApplyWorkerDownlinkBudget {
                route_context_id: key.context_id.to_vec(),
                path_id: *path_id,
                sequence: message.sequence,
                rate_bytes_per_second: message.rate_bytes_per_second,
                burst_bytes: message.burst_bytes,
                expires_at_ms: message.expires_at_ms,
                expires_at_boottime_ns: expires_boot,
            }
        };
        let generation = entry_generation(&self.state, key)?;
        let request = worker_request(
            binding.request_id,
            internal_worker_request::Operation::ApplyDownlinkBudget(operation.clone()),
        );
        let execution = self
            .coordinator
            .execute_until(key.context_id, generation, request, deadline)
            .await;
        let maximum_queued_bytes = match execution {
            Ok(execution) if execution.descriptor.is_none() => {
                match execution.response.outcome.as_ref() {
                    Some(internal_worker_response::Outcome::DownlinkBudgetApplied(applied))
                        if applied.sequence == operation.sequence =>
                    {
                        applied.maximum_queued_bytes
                    }
                    _ => return Err(BackendError::CleanupIncomplete),
                }
            }
            other => return Err(response_error(other)),
        };
        Ok(AppliedDownlinkBudget {
            route_context_id: key.context_id.to_vec(),
            lease_handle: value.lease_handle,
            sequence: operation.sequence,
            rate_bytes_per_second: operation.rate_bytes_per_second,
            burst_bytes: operation.burst_bytes,
            expires_at_ms: operation.expires_at_ms,
            maximum_queued_bytes,
        })
    }

    /// Register all managed roles using only verified helper underlay and activation metadata.
    /// The controller treats Client and uncontrolled directions as owner/unmanaged traffic.
    pub(super) fn register_receive_tuples(
        &self,
        key: OpenLineageKey,
        activations: &[LeaseActivation],
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let tuples = {
            let state = lock_state(&self.state);
            let entry = exact_entry(&state, key)?;
            let mut tuples = Vec::with_capacity(activations.len());
            for activation in activations {
                let identity = (activation.path_id, activation.role);
                let prepared = entry
                    .prepared
                    .iter()
                    .find(|lease| (lease.path_id, lease.role) == identity)
                    .ok_or(BackendError::Invalid)?;
                let underlay = entry
                    .underlays
                    .get(&identity)
                    .ok_or(BackendError::Invalid)?
                    .candidate;
                let (remote, port) =
                    super::parse_public_udp_endpoint(activation.peer_endpoint.as_ref())
                        .ok_or(BackendError::Invalid)?;
                tuples.push((
                    underlay.ifindex,
                    ReceiveTuple {
                        context_id: key.context_id,
                        path_id: u8::try_from(activation.path_id)
                            .map_err(|_| BackendError::Invalid)?,
                        role: WireguardRole::try_from(activation.role)
                            .map_err(|_| BackendError::Invalid)?,
                        local: SocketAddr::new(underlay.address, prepared.listen_port),
                        remote: SocketAddr::new(remote, port),
                    },
                ));
            }
            tuples
        };
        let mut slot = self
            .accounting_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(accounting) = slot.as_mut() else {
            return Ok(());
        };
        if accounting.binding.helper_runtime_id != key.helper_runtime_id {
            return Err(BackendError::Invalid);
        }
        for (ifindex, tuple) in tuples {
            if ifindex == accounting.owner.config().ifindex {
                accounting
                    .owner
                    .register(tuple, deadline)
                    .map_err(|_| BackendError::CleanupIncomplete)?;
            }
        }
        Ok(())
    }

    pub(super) fn unregister_receive_tuples(
        &self,
        key: OpenLineageKey,
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        let identities: Vec<_> = {
            let state = lock_state(&self.state);
            let entry = exact_entry(&state, key)?;
            entry
                .prepared
                .iter()
                .map(|lease| (lease.path_id, lease.role))
                .collect()
        };
        let mut slot = self
            .accounting_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(accounting) = slot.as_mut() else {
            return Ok(());
        };
        if accounting.binding.helper_runtime_id != key.helper_runtime_id {
            return Err(BackendError::Invalid);
        }
        for (path, role) in identities {
            accounting
                .owner
                .unregister(
                    key.context_id,
                    u8::try_from(path).map_err(|_| BackendError::Invalid)?,
                    WireguardRole::try_from(role).map_err(|_| BackendError::Invalid)?,
                    deadline,
                )
                .map_err(|_| BackendError::CleanupIncomplete)?;
        }
        Ok(())
    }
}
