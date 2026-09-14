//! Exact context-generation mutation owner for receiver-signed sender queue updates.

use super::{
    BackendAction, BackendBinding, BackendError, BackendPhase, BackendRequest, ContextPhase,
    HelperEngine, HelperExecution, HelperRequest, HelperResult, Instant, OperationKind,
    ResolvedCall, backend_response, begin_operation, context_backend_lineage, deadline_live,
    execution, expiry_now, fixed, helper_response, invalid_response, matches_handle,
    operation_digest, response,
};
use volparossa_routing::{ApplyDownlinkBudget, WireguardRole};

impl HelperEngine {
    #[expect(
        clippy::too_many_lines,
        reason = "keep one bounded mutation and its settlement/rollback paths together"
    )]
    pub(super) async fn apply_downlink_async(
        &self,
        request: &HelperRequest,
        value: &ApplyDownlinkBudget,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let context_id = fixed::<16>(&value.route_context_id)?;
        let (owner, phase) = {
            let mut state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(request, HelperResult::NotFound, "CONTEXT_ABSENT", None),
                    None,
                ));
            };
            if !matches!(
                context.phase,
                ContextPhase::Activated | ContextPhase::Committed
            ) || !matches_handle(&context.handle, &value.context_handle)
                || !context.leases.iter().any(|((_, role), lease)| {
                    *role == WireguardRole::Exit as i32
                        && matches_handle(&lease.handle, &value.lease_handle)
                })
                || !deadline_live(
                    expiry_now(self.inner.clock.as_ref()),
                    context.hard_expires_at_unix,
                    context.hard_expires_at_boottime_ns,
                )
            {
                return Some(execution(invalid_response(request), None));
            }
            let phase = context.phase;
            let generation = context.generation;
            let lineage = context_backend_lineage(context_id, context);
            let Some(owner) = begin_operation(
                &mut state,
                fixed(&request.request_id)?,
                operation_digest(request).ok()?,
                context_id,
                generation,
                Some(phase),
                OperationKind::DownlinkBudget,
                lineage,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return Some(execution(
                    response(request, HelperResult::Capacity, "OPERATION_CAPACITY", None),
                    None,
                ));
            };
            state.cleanup_pending.insert((context_id, generation));
            (owner, phase)
        };
        let backend_phase = if phase == ContextPhase::Activated {
            BackendPhase::Activated
        } else {
            BackendPhase::Committed
        };
        let binding = BackendBinding::for_owner(
            &owner,
            backend_phase,
            BackendAction::ApplyDownlinkBudget,
            owner.call_deadline(),
        );
        let backend = self.inner.backend.clone();
        let input = BackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.apply_downlink_budget(input)
            })
            .await;
        let resolved = self
            .resolve_mutating_call(call, owner, binding, request, sender)
            .await?;
        let (owner, applied) = match resolved {
            ResolvedCall::Definite {
                owner,
                result: Ok(applied),
            } => (*owner, applied),
            ResolvedCall::Definite {
                owner,
                result: Err(BackendError::CleanupIncomplete),
            } => {
                let cleanup = self.rollback_context(*owner, request, sender).await;
                if cleanup.response_sent {
                    return None;
                }
                return Some(execution(
                    backend_response(
                        request,
                        BackendError::CleanupIncomplete,
                        "DOWNLINK_BUDGET_CLEANUP_INCOMPLETE",
                    ),
                    None,
                ));
            }
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                self.clear_operation(*owner).await;
                return Some(execution(
                    backend_response(request, error, "DOWNLINK_BUDGET_REJECTED"),
                    None,
                ));
            }
            ResolvedCall::Ambiguous => {
                return Some(execution(
                    backend_response(
                        request,
                        BackendError::CleanupIncomplete,
                        "DOWNLINK_BUDGET_AMBIGUOUS",
                    ),
                    None,
                ));
            }
        };
        let mut state = self.inner.state.lock().await;
        let exact = state.in_flight == Some(owner.token())
            && state.contexts.get(&context_id).is_some_and(|context| {
                context.phase == phase
                    && context_backend_lineage(context_id, context) == owner.lineage()
                    && matches_handle(&context.handle, &value.context_handle)
                    && deadline_live(
                        expiry_now(self.inner.clock.as_ref()),
                        context.hard_expires_at_unix,
                        context.hard_expires_at_boottime_ns,
                    )
            });
        if !exact {
            drop(state);
            let cleanup = self.rollback_context(owner, request, sender).await;
            if cleanup.response_sent {
                return None;
            }
            return Some(execution(
                backend_response(
                    request,
                    BackendError::CleanupIncomplete,
                    "DOWNLINK_BUDGET_STALE",
                ),
                None,
            ));
        }
        state
            .cleanup_pending
            .remove(&(context_id, owner.token().generation));
        state.in_flight = None;
        drop(state);
        let _ = owner.settle();
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "DOWNLINK_BUDGET_APPLIED",
                Some(helper_response::Outcome::AppliedDownlinkBudget(applied)),
            ),
            None,
        ))
    }
}
