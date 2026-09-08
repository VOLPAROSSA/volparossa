//! Daemon-wide upload scheduling ownership; never a route or ingress capability.

use super::{
    BackendCall, BackendError, BackendFuture, EngineState, HelperEngine, HelperExecution,
    HelperRequest, HelperResult, Instant, backend_response, execution, fixed, helper_request,
    helper_response, operation_digest, response,
};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use volparossa_routing::{
    DestroyedSharing, InstallUplinkSharing, InstalledUplinkSharing, SharingCounters,
    SharingQueueCounters,
};

pub(super) struct SharingRecord {
    runtime_id: [u8; 16],
    pub(super) handle: [u8; 32],
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharingBackendAction {
    Install,
    Inspect,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharingBackendBinding {
    pub(crate) helper_runtime_id: [u8; 32],
    pub(crate) sharing_runtime_id: [u8; 16],
    pub(crate) sharing_handle: [u8; 32],
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: [u8; 32],
    pub(crate) action: SharingBackendAction,
    pub(crate) call_deadline: Instant,
}

pub(crate) struct SharingBackendRequest<T> {
    binding: SharingBackendBinding,
    value: T,
}

impl<T> SharingBackendRequest<T> {
    pub(crate) const fn new(binding: SharingBackendBinding, value: T) -> Self {
        Self { binding, value }
    }

    pub(crate) fn into_parts(self) -> (SharingBackendBinding, T) {
        (self.binding, self.value)
    }

    pub(crate) fn complete<U>(
        self,
        result: Result<U, BackendError>,
    ) -> SharingBackendCompletion<U> {
        SharingBackendCompletion {
            binding: self.binding,
            result,
        }
    }
}

pub(crate) struct SharingBackendCompletion<T> {
    pub(crate) binding: SharingBackendBinding,
    pub(crate) result: Result<T, BackendError>,
}

impl HelperEngine {
    pub(super) async fn execute_sharing(
        &self,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> HelperExecution {
        let result = match request.operation.as_ref() {
            Some(helper_request::Operation::InstallUplinkSharing(value)) => {
                self.install_sharing(request, value, sender).await
            }
            Some(helper_request::Operation::InspectUplinkSharing(value)) => {
                self.inspect_sharing(request, &value.sharing_runtime_id, &value.sharing_handle)
                    .await
            }
            Some(helper_request::Operation::DestroyUplinkSharing(value)) => {
                self.destroy_sharing(request, &value.sharing_runtime_id, &value.sharing_handle)
                    .await
            }
            _ => super::invalid_response(request),
        };
        execution(result, None)
    }

    fn sharing_binding(
        &self,
        record: &SharingRecord,
        action: SharingBackendAction,
        request: Option<&HelperRequest>,
    ) -> SharingBackendBinding {
        SharingBackendBinding {
            helper_runtime_id: self.inner.runtime_id,
            sharing_runtime_id: record.runtime_id,
            sharing_handle: record.handle,
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

    async fn install_sharing(
        &self,
        request: &HelperRequest,
        value: &InstallUplinkSharing,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> super::HelperResponse {
        let binding = {
            let mut state = self.inner.state.lock().await;
            if state.sharing.is_some() {
                return response(
                    request,
                    HelperResult::AlreadyExists,
                    "SHARING_ALREADY_OWNED",
                    None,
                );
            }
            let Some(handle) = self.unique_handle(&state, &BTreeSet::new()) else {
                return response(
                    request,
                    HelperResult::Capacity,
                    "SHARING_HANDLE_CAPACITY",
                    None,
                );
            };
            let Some(runtime_id) = fixed(&value.sharing_runtime_id) else {
                return super::invalid_response(request);
            };
            let record = SharingRecord {
                runtime_id,
                handle,
                active: false,
            };
            let binding =
                self.sharing_binding(&record, SharingBackendAction::Install, Some(request));
            // The supervisor owns cleanup before CALL, including a lost or panicking completion.
            state.sharing = Some(record);
            binding
        };
        let backend = self.inner.backend.clone();
        let input = SharingBackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.install_uplink_sharing(input)
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
        if let Ok(egress_ifindex) = result {
            if egress_ifindex > 1 && i32::try_from(egress_ifindex).is_ok() {
                self.inner
                    .state
                    .lock()
                    .await
                    .sharing
                    .as_mut()
                    .expect("reserved sharing owner")
                    .active = true;
                return response(
                    request,
                    HelperResult::Ok,
                    "UPLINK_SHARING_INSTALLED",
                    Some(helper_response::Outcome::InstalledUplinkSharing(
                        InstalledUplinkSharing {
                            sharing_runtime_id: binding.sharing_runtime_id.to_vec(),
                            sharing_handle: binding.sharing_handle.to_vec(),
                            egress_ifindex,
                        },
                    )),
                );
            }
        }
        let error = result.err().unwrap_or(BackendError::Kernel);
        let complete = self.cleanup_sharing().await;
        // Unavailable/Invalid backends promise no mutation; still require exact absence proof
        // unless the default unavailable seam never accepted the operation at all.
        if !complete && error == BackendError::Unavailable {
            self.clear_sharing(binding).await;
        }
        backend_response(
            request,
            if complete || error == BackendError::Unavailable {
                error
            } else {
                BackendError::CleanupIncomplete
            },
            "UPLINK_SHARING_INSTALL_FAILED",
        )
    }

    async fn inspect_sharing(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_sharing_binding(request, runtime_id, handle, SharingBackendAction::Inspect)
            .await
        {
            Ok(Some(binding)) => binding,
            Ok(None) => {
                return response(request, HelperResult::NotFound, "SHARING_NOT_FOUND", None);
            }
            Err(result) => return response(request, result, "SHARING_OWNER_MISMATCH", None),
        };
        let backend = self.inner.backend.clone();
        let input = SharingBackendRequest::new(binding, ());
        match self
            .settle_sharing_call(binding, move || backend.inspect_uplink_sharing(input))
            .await
        {
            Ok(counters) => response(
                request,
                HelperResult::Ok,
                "UPLINK_SHARING_COUNTERS",
                Some(helper_response::Outcome::SharingCounters(SharingCounters {
                    sharing_runtime_id: binding.sharing_runtime_id.to_vec(),
                    sharing_handle: binding.sharing_handle.to_vec(),
                    total: Some(queue_counters(counters.total)),
                    owner: Some(queue_counters(counters.owner)),
                    contribution: Some(queue_counters(counters.contribution)),
                })),
            ),
            Err(error) => backend_response(request, error, "UPLINK_SHARING_INSPECT_FAILED"),
        }
    }

    async fn destroy_sharing(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_sharing_binding(request, runtime_id, handle, SharingBackendAction::Destroy)
            .await
        {
            Ok(value) => value,
            Err(result) => return response(request, result, "SHARING_OWNER_MISMATCH", None),
        };
        if let Some(binding) = binding {
            if !self.destroy_sharing_binding(binding).await {
                return backend_response(
                    request,
                    BackendError::CleanupIncomplete,
                    "UPLINK_SHARING_CLEANUP_INCOMPLETE",
                );
            }
        }
        response(
            request,
            HelperResult::Ok,
            "UPLINK_SHARING_DESTROYED",
            Some(helper_response::Outcome::DestroyedSharing(
                DestroyedSharing {
                    existed: binding.is_some(),
                },
            )),
        )
    }

    async fn exact_sharing_binding(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
        action: SharingBackendAction,
    ) -> Result<Option<SharingBackendBinding>, HelperResult> {
        let state = self.inner.state.lock().await;
        let Some(record) = state.sharing.as_ref() else {
            return Ok(None);
        };
        if record.runtime_id.ct_eq(runtime_id).unwrap_u8() != 1
            || record.handle.ct_eq(handle).unwrap_u8() != 1
        {
            return Err(HelperResult::UnauthorisedPeer);
        }
        if action == SharingBackendAction::Inspect && !record.active {
            return Err(HelperResult::CleanupIncomplete);
        }
        Ok(Some(self.sharing_binding(record, action, Some(request))))
    }

    pub(super) async fn cleanup_sharing(&self) -> bool {
        let binding = self
            .inner
            .state
            .lock()
            .await
            .sharing
            .as_ref()
            .map(|record| self.sharing_binding(record, SharingBackendAction::Destroy, None));
        match binding {
            Some(binding) => self.destroy_sharing_binding(binding).await,
            None => true,
        }
    }

    async fn destroy_sharing_binding(&self, binding: SharingBackendBinding) -> bool {
        let backend = self.inner.backend.clone();
        let input = SharingBackendRequest::new(binding, ());
        if self
            .settle_sharing_call(binding, move || backend.destroy_uplink_sharing(input))
            .await
            .is_ok()
        {
            self.clear_sharing(binding).await;
            true
        } else {
            if let Some(record) = self.inner.state.lock().await.sharing.as_mut() {
                record.active = false;
            }
            false
        }
    }

    async fn clear_sharing(&self, binding: SharingBackendBinding) {
        let mut state = self.inner.state.lock().await;
        if state.sharing.as_ref().is_some_and(|record| {
            record.runtime_id == binding.sharing_runtime_id
                && record.handle == binding.sharing_handle
        }) {
            state.sharing = None;
            purge_sharing_cache(&mut state, binding);
        }
    }

    async fn settle_sharing_call<T: Send + 'static>(
        &self,
        binding: SharingBackendBinding,
        call: impl FnOnce() -> BackendFuture<SharingBackendCompletion<T>> + Send + 'static,
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

fn purge_sharing_cache(state: &mut EngineState, binding: SharingBackendBinding) {
    state
        .cache
        .retain(|_, cached| match cached.response.outcome.as_ref() {
            Some(helper_response::Outcome::InstalledUplinkSharing(value)) => {
                value.sharing_handle != binding.sharing_handle
            }
            Some(helper_response::Outcome::SharingCounters(value)) => {
                value.sharing_handle != binding.sharing_handle
            }
            _ => true,
        });
    state
        .cache_order
        .retain(|key| state.cache.contains_key(key));
}

fn queue_counters(value: crate::kernel::underlay_sharing::QueueCounters) -> SharingQueueCounters {
    SharingQueueCounters {
        bytes: value.bytes,
        packets: value.packets,
        drops: u64::from(value.drops),
        overlimits: u64::from(value.overlimits),
        backlog_bytes: u64::from(value.backlog_bytes),
    }
}
