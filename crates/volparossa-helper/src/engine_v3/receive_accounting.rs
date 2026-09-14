//! Daemon-wide receive accounting ownership; never a route or ingress capability.

use super::{
    BackendCall, BackendError, BackendFuture, EngineState, HelperEngine, HelperExecution,
    HelperRequest, HelperResult, Instant, backend_response, execution, fixed, helper_request,
    helper_response, operation_digest, response,
};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use volparossa_routing::{
    DestroyedReceiveAccounting, InstallReceiveAccounting, InstalledReceiveAccounting,
    ManagedReceiveCounter, ReceiveAccountingSnapshot, ReceiveByteCounters,
};

pub(super) struct AccountingRecord {
    runtime_id: [u8; 16],
    pub(super) handle: [u8; 32],
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccountingBackendAction {
    Install,
    Inspect,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AccountingBackendBinding {
    pub(crate) helper_runtime_id: [u8; 32],
    pub(crate) accounting_runtime_id: [u8; 16],
    pub(crate) accounting_handle: [u8; 32],
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: [u8; 32],
    pub(crate) action: AccountingBackendAction,
    pub(crate) call_deadline: Instant,
}

pub(crate) struct AccountingBackendRequest<T> {
    binding: AccountingBackendBinding,
    value: T,
}

impl<T> AccountingBackendRequest<T> {
    pub(crate) const fn new(binding: AccountingBackendBinding, value: T) -> Self {
        Self { binding, value }
    }

    pub(crate) fn into_parts(self) -> (AccountingBackendBinding, T) {
        (self.binding, self.value)
    }

    pub(crate) fn complete<U>(
        self,
        result: Result<U, BackendError>,
    ) -> AccountingBackendCompletion<U> {
        AccountingBackendCompletion {
            binding: self.binding,
            result,
        }
    }
}

pub(crate) struct AccountingBackendCompletion<T> {
    pub(crate) binding: AccountingBackendBinding,
    pub(crate) result: Result<T, BackendError>,
}

impl HelperEngine {
    pub(super) async fn execute_accounting(
        &self,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> HelperExecution {
        let result = match request.operation.as_ref() {
            Some(helper_request::Operation::InstallReceiveAccounting(value)) => {
                self.install_accounting(request, value, sender).await
            }
            Some(helper_request::Operation::InspectReceiveAccounting(value)) => {
                self.inspect_accounting(
                    request,
                    &value.accounting_runtime_id,
                    &value.accounting_handle,
                )
                .await
            }
            Some(helper_request::Operation::DestroyReceiveAccounting(value)) => {
                self.destroy_accounting(
                    request,
                    &value.accounting_runtime_id,
                    &value.accounting_handle,
                )
                .await
            }
            _ => super::invalid_response(request),
        };
        execution(result, None)
    }

    fn accounting_binding(
        &self,
        record: &AccountingRecord,
        action: AccountingBackendAction,
        request: Option<&HelperRequest>,
    ) -> AccountingBackendBinding {
        AccountingBackendBinding {
            helper_runtime_id: self.inner.runtime_id,
            accounting_runtime_id: record.runtime_id,
            accounting_handle: record.handle,
            request_id: request
                .and_then(|value| fixed(&value.request_id))
                .unwrap_or([0; 16]),
            request_digest: request
                .and_then(|value| operation_digest(value).ok())
                .unwrap_or([0; 32]),
            action,
            call_deadline: Instant::now() + self.inner.backend_timeout,
        }
    }

    async fn install_accounting(
        &self,
        request: &HelperRequest,
        value: &InstallReceiveAccounting,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> super::HelperResponse {
        let binding = {
            let mut state = self.inner.state.lock().await;
            if state.accounting.is_some() {
                return response(
                    request,
                    HelperResult::AlreadyExists,
                    "ACCOUNTING_ALREADY_OWNED",
                    None,
                );
            }
            let Some(handle) = self.unique_handle(&state, &BTreeSet::new()) else {
                return response(
                    request,
                    HelperResult::Capacity,
                    "ACCOUNTING_HANDLE_CAPACITY",
                    None,
                );
            };
            let Some(runtime_id) = fixed(&value.accounting_runtime_id) else {
                return super::invalid_response(request);
            };
            let record = AccountingRecord {
                runtime_id,
                handle,
                active: false,
            };
            let binding =
                self.accounting_binding(&record, AccountingBackendAction::Install, Some(request));
            // The supervisor owns cleanup before CALL, including a lost or panicking completion.
            state.accounting = Some(record);
            binding
        };
        let backend = self.inner.backend.clone();
        let input = AccountingBackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.install_receive_accounting(input)
            })
            .await;
        let completion = match call {
            BackendCall::Complete(completion) => Some(completion),
            BackendCall::TimedOut(task) => {
                self.send_ambiguous(request, sender).await;
                let _ = task.await; // Settle the bounded backend before exact rollback.
                None
            }
            BackendCall::Ambiguous => None,
        };
        let result = completion
            .filter(|value| value.binding == binding)
            .map_or(Err(BackendError::CleanupIncomplete), |value| value.result);
        if let Ok(ingress_ifindex) = result {
            if ingress_ifindex > 1 && i32::try_from(ingress_ifindex).is_ok() {
                self.inner
                    .state
                    .lock()
                    .await
                    .accounting
                    .as_mut()
                    .expect("reserved accounting owner")
                    .active = true;
                return response(
                    request,
                    HelperResult::Ok,
                    "RECEIVE_ACCOUNTING_INSTALLED",
                    Some(helper_response::Outcome::InstalledReceiveAccounting(
                        InstalledReceiveAccounting {
                            accounting_runtime_id: binding.accounting_runtime_id.to_vec(),
                            accounting_handle: binding.accounting_handle.to_vec(),
                            ingress_ifindex,
                        },
                    )),
                );
            }
        }
        let error = result.err().unwrap_or(BackendError::Kernel);
        let complete = self.cleanup_accounting().await;
        // Unavailable/Invalid backends promise no mutation; still require exact absence proof
        // unless the default unavailable seam never accepted the operation at all.
        if !complete && error == BackendError::Unavailable {
            self.clear_accounting(binding).await;
        }
        backend_response(
            request,
            if complete || error == BackendError::Unavailable {
                error
            } else {
                BackendError::CleanupIncomplete
            },
            "RECEIVE_ACCOUNTING_INSTALL_FAILED",
        )
    }

    async fn inspect_accounting(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_accounting_binding(
                request,
                runtime_id,
                handle,
                AccountingBackendAction::Inspect,
            )
            .await
        {
            Ok(Some(binding)) => binding,
            Ok(None) => {
                return response(
                    request,
                    HelperResult::NotFound,
                    "ACCOUNTING_NOT_FOUND",
                    None,
                );
            }
            Err(result) => return response(request, result, "ACCOUNTING_OWNER_MISMATCH", None),
        };
        let backend = self.inner.backend.clone();
        let input = AccountingBackendRequest::new(binding, ());
        match self
            .settle_accounting_call(binding, move || backend.inspect_receive_accounting(input))
            .await
        {
            Ok(counters) => response(
                request,
                HelperResult::Ok,
                "RECEIVE_ACCOUNTING_COUNTERS",
                Some(helper_response::Outcome::ReceiveAccountingSnapshot(
                    ReceiveAccountingSnapshot {
                        accounting_runtime_id: binding.accounting_runtime_id.to_vec(),
                        accounting_handle: binding.accounting_handle.to_vec(),
                        total: Some(byte_counters(counters.total)),
                        managed: managed_counters(counters.tuples),
                    },
                )),
            ),
            Err(error) => backend_response(request, error, "RECEIVE_ACCOUNTING_INSPECT_FAILED"),
        }
    }

    async fn destroy_accounting(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_accounting_binding(
                request,
                runtime_id,
                handle,
                AccountingBackendAction::Destroy,
            )
            .await
        {
            Ok(value) => value,
            Err(result) => return response(request, result, "ACCOUNTING_OWNER_MISMATCH", None),
        };
        if let Some(binding) = binding {
            if !self.destroy_accounting_binding(binding).await {
                return backend_response(
                    request,
                    BackendError::CleanupIncomplete,
                    "RECEIVE_ACCOUNTING_CLEANUP_INCOMPLETE",
                );
            }
        }
        response(
            request,
            HelperResult::Ok,
            "RECEIVE_ACCOUNTING_DESTROYED",
            Some(helper_response::Outcome::DestroyedReceiveAccounting(
                DestroyedReceiveAccounting {
                    accounting_runtime_id: runtime_id.to_vec(),
                    accounting_handle: handle.to_vec(),
                    existed: binding.is_some(),
                },
            )),
        )
    }

    async fn exact_accounting_binding(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
        action: AccountingBackendAction,
    ) -> Result<Option<AccountingBackendBinding>, HelperResult> {
        let state = self.inner.state.lock().await;
        let Some(record) = state.accounting.as_ref() else {
            return Ok(None);
        };
        if record.runtime_id.ct_eq(runtime_id).unwrap_u8() != 1
            || record.handle.ct_eq(handle).unwrap_u8() != 1
        {
            return Err(HelperResult::UnauthorisedPeer);
        }
        if action == AccountingBackendAction::Inspect && !record.active {
            return Err(HelperResult::CleanupIncomplete);
        }
        Ok(Some(self.accounting_binding(record, action, Some(request))))
    }

    pub(super) async fn cleanup_accounting(&self) -> bool {
        let binding = self
            .inner
            .state
            .lock()
            .await
            .accounting
            .as_ref()
            .map(|record| self.accounting_binding(record, AccountingBackendAction::Destroy, None));
        match binding {
            Some(binding) => self.destroy_accounting_binding(binding).await,
            None => true,
        }
    }

    async fn destroy_accounting_binding(&self, binding: AccountingBackendBinding) -> bool {
        let backend = self.inner.backend.clone();
        let input = AccountingBackendRequest::new(binding, ());
        if self
            .settle_accounting_call(binding, move || backend.destroy_receive_accounting(input))
            .await
            .is_ok()
        {
            self.clear_accounting(binding).await;
            true
        } else {
            if let Some(record) = self.inner.state.lock().await.accounting.as_mut() {
                record.active = false;
            }
            false
        }
    }

    async fn clear_accounting(&self, binding: AccountingBackendBinding) {
        let mut state = self.inner.state.lock().await;
        if state.accounting.as_ref().is_some_and(|record| {
            record.runtime_id == binding.accounting_runtime_id
                && record.handle == binding.accounting_handle
        }) {
            state.accounting = None;
            purge_accounting_cache(&mut state, binding);
        }
    }

    async fn settle_accounting_call<T: Send + 'static>(
        &self,
        binding: AccountingBackendBinding,
        call: impl FnOnce() -> BackendFuture<AccountingBackendCompletion<T>> + Send + 'static,
    ) -> Result<T, BackendError> {
        let completion = match self.call_backend(binding.call_deadline, call).await {
            BackendCall::Complete(value) => value,
            BackendCall::TimedOut(task) => {
                task.await.map_err(|_| BackendError::CleanupIncomplete)?
            }
            BackendCall::Ambiguous => return Err(BackendError::CleanupIncomplete),
        };
        if completion.binding == binding {
            completion.result
        } else {
            Err(BackendError::CleanupIncomplete)
        }
    }
}

fn purge_accounting_cache(state: &mut EngineState, binding: AccountingBackendBinding) {
    state
        .cache
        .retain(|_, cached| match cached.response.outcome.as_ref() {
            Some(helper_response::Outcome::InstalledReceiveAccounting(value)) => {
                value.accounting_handle != binding.accounting_handle
            }
            Some(helper_response::Outcome::ReceiveAccountingSnapshot(value)) => {
                value.accounting_handle != binding.accounting_handle
            }
            _ => true,
        });
    state
        .cache_order
        .retain(|key| state.cache.contains_key(key));
}

fn byte_counters(value: crate::kernel::receive_accounting::ReceiveCounters) -> ReceiveByteCounters {
    ReceiveByteCounters {
        bytes: value.bytes,
        packets: value.packets,
    }
}

fn managed_counters(
    mut values: Vec<crate::kernel::receive_accounting::ReceiveTupleCounters>,
) -> Vec<ManagedReceiveCounter> {
    values.sort_by_key(|value| {
        (
            value.tuple.context_id,
            value.tuple.path_id,
            value.tuple.role as i32,
        )
    });
    values
        .into_iter()
        .map(|value| ManagedReceiveCounter {
            route_context_id: value.tuple.context_id.to_vec(),
            path_id: u32::from(value.tuple.path_id),
            role: value.tuple.role as i32,
            counters: Some(byte_counters(value.counters)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::managed_counters;
    use crate::kernel::receive_accounting::{ReceiveCounters, ReceiveTuple, ReceiveTupleCounters};
    use volparossa_routing::WireguardRole;

    #[test]
    fn receive_accounting_projection_preserves_client_role_and_canonical_identity_order() {
        let entry = |context, role| ReceiveTupleCounters {
            tuple: ReceiveTuple {
                context_id: [context; 16],
                path_id: 1,
                role,
                local: "10.244.8.1:18081".parse().unwrap(),
                remote: "10.244.8.2:28081".parse().unwrap(),
            },
            counters: ReceiveCounters {
                bytes: 1028,
                packets: 1,
            },
        };
        let projected = managed_counters(vec![
            entry(2, WireguardRole::RelayExit),
            entry(1, WireguardRole::Client),
        ]);
        assert_eq!(projected[0].route_context_id, [1; 16]);
        assert_eq!(projected[0].role, WireguardRole::Client as i32);
        assert_eq!(projected[1].role, WireguardRole::RelayExit as i32);
        assert!(projected.iter().all(|entry| {
            entry
                .counters
                .as_ref()
                .is_some_and(|counter| counter.bytes == 1028 && counter.packets == 1)
        }));
    }
}
