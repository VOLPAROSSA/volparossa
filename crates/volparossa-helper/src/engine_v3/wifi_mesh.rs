//! Daemon-wide direct mesh ownership, independent of route, ingress and sharing capabilities.

use super::{
    BackendCall, BackendError, BackendFuture, EngineState, HelperEngine, HelperExecution,
    HelperRequest, HelperResult, Instant, backend_response, execution, fixed, helper_request,
    helper_response, operation_digest, response,
};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use volparossa_routing::{
    DestroyedWifiMesh, InstallWifiMesh, InstalledWifiMesh, WifiMeshPeer, WifiMeshSnapshot,
    validate_wifi_mesh_response,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeshInterfaceIdentity {
    pub(crate) interface: String,
    pub(crate) ifindex: u32,
    pub(crate) wiphy: u32,
}

pub(super) struct MeshRecord {
    runtime_id: [u8; 16],
    pub(super) handle: [u8; 32],
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MeshBackendAction {
    Install,
    Inspect,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MeshBackendBinding {
    pub(crate) helper_runtime_id: [u8; 32],
    pub(crate) mesh_runtime_id: [u8; 16],
    pub(crate) mesh_handle: [u8; 32],
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: [u8; 32],
    pub(crate) action: MeshBackendAction,
    pub(crate) call_deadline: Instant,
}

pub(crate) struct MeshBackendRequest<T> {
    binding: MeshBackendBinding,
    value: T,
}

impl<T> MeshBackendRequest<T> {
    pub(crate) const fn new(binding: MeshBackendBinding, value: T) -> Self {
        Self { binding, value }
    }

    pub(crate) fn into_parts(self) -> (MeshBackendBinding, T) {
        (self.binding, self.value)
    }

    pub(crate) fn complete<U>(self, result: Result<U, BackendError>) -> MeshBackendCompletion<U> {
        MeshBackendCompletion {
            binding: self.binding,
            result,
        }
    }
}

pub(crate) struct MeshBackendCompletion<T> {
    pub(crate) binding: MeshBackendBinding,
    pub(crate) result: Result<T, BackendError>,
}

impl HelperEngine {
    pub(super) async fn execute_mesh(
        &self,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> HelperExecution {
        let result = match request.operation.as_ref() {
            Some(helper_request::Operation::InstallWifiMesh(value)) => {
                self.install_mesh(request, value, sender).await
            }
            Some(helper_request::Operation::InspectWifiMesh(value)) => {
                self.inspect_mesh(request, &value.mesh_runtime_id, &value.mesh_handle)
                    .await
            }
            Some(helper_request::Operation::DestroyWifiMesh(value)) => {
                self.destroy_mesh(request, &value.mesh_runtime_id, &value.mesh_handle)
                    .await
            }
            _ => super::invalid_response(request),
        };
        execution(result, None)
    }

    fn mesh_binding(
        &self,
        record: &MeshRecord,
        action: MeshBackendAction,
        request: Option<&HelperRequest>,
    ) -> MeshBackendBinding {
        MeshBackendBinding {
            helper_runtime_id: self.inner.runtime_id,
            mesh_runtime_id: record.runtime_id,
            mesh_handle: record.handle,
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

    async fn install_mesh(
        &self,
        request: &HelperRequest,
        value: &InstallWifiMesh,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> super::HelperResponse {
        let binding = {
            let mut state = self.inner.state.lock().await;
            if state.mesh.is_some() {
                return response(
                    request,
                    HelperResult::AlreadyExists,
                    "MESH_ALREADY_OWNED",
                    None,
                );
            }
            let Some(handle) = self.unique_handle(&state, &BTreeSet::new()) else {
                return response(
                    request,
                    HelperResult::Capacity,
                    "MESH_HANDLE_CAPACITY",
                    None,
                );
            };
            let Some(runtime_id) = fixed(&value.mesh_runtime_id) else {
                return super::invalid_response(request);
            };
            let record = MeshRecord {
                runtime_id,
                handle,
                active: false,
            };
            let binding = self.mesh_binding(&record, MeshBackendAction::Install, Some(request));
            // The supervisor owns cleanup before CALL, including a lost or panicking completion.
            state.mesh = Some(record);
            binding
        };
        let backend = self.inner.backend.clone();
        let input = MeshBackendRequest::new(binding, value.clone());
        let call = self
            .call_backend(binding.call_deadline, move || {
                backend.install_wifi_mesh(input)
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
        if let Ok(identity) = &result {
            let installed = response(
                request,
                HelperResult::Ok,
                "WIFI_MESH_INSTALLED",
                Some(helper_response::Outcome::InstalledWifiMesh(
                    InstalledWifiMesh {
                        mesh_runtime_id: binding.mesh_runtime_id.to_vec(),
                        mesh_handle: binding.mesh_handle.to_vec(),
                        interface: identity.interface.clone(),
                        ifindex: identity.ifindex,
                        wiphy: identity.wiphy,
                    },
                )),
            );
            if validate_wifi_mesh_response(request, &installed).is_ok() {
                self.inner
                    .state
                    .lock()
                    .await
                    .mesh
                    .as_mut()
                    .expect("reserved mesh owner")
                    .active = true;
                return installed;
            }
        }
        let error = result.err().unwrap_or(BackendError::Kernel);
        let complete = self.cleanup_mesh().await;
        // Unavailable/Invalid backends promise no mutation; still require exact absence proof
        // unless the default unavailable seam never accepted the operation at all.
        if !complete && error == BackendError::Unavailable {
            self.clear_mesh(binding).await;
        }
        backend_response(
            request,
            if complete || error == BackendError::Unavailable {
                error
            } else {
                BackendError::CleanupIncomplete
            },
            "WIFI_MESH_INSTALL_FAILED",
        )
    }

    async fn inspect_mesh(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_mesh_binding(request, runtime_id, handle, MeshBackendAction::Inspect)
            .await
        {
            Ok(Some(binding)) => binding,
            Ok(None) => {
                return response(request, HelperResult::NotFound, "MESH_NOT_FOUND", None);
            }
            Err(result) => return response(request, result, "MESH_OWNER_MISMATCH", None),
        };
        let backend = self.inner.backend.clone();
        let input = MeshBackendRequest::new(binding, ());
        match self
            .settle_mesh_call(binding, move || backend.inspect_wifi_mesh(input))
            .await
        {
            Ok(snapshot) => {
                let result = response(
                    request,
                    HelperResult::Ok,
                    "WIFI_MESH_SNAPSHOT",
                    Some(helper_response::Outcome::WifiMeshSnapshot(wire_snapshot(
                        binding, snapshot,
                    ))),
                );
                if validate_wifi_mesh_response(request, &result).is_ok() {
                    result
                } else {
                    backend_response(request, BackendError::Kernel, "WIFI_MESH_SNAPSHOT_INVALID")
                }
            }
            Err(error) => backend_response(request, error, "WIFI_MESH_INSPECT_FAILED"),
        }
    }

    async fn destroy_mesh(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
    ) -> super::HelperResponse {
        let binding = match self
            .exact_mesh_binding(request, runtime_id, handle, MeshBackendAction::Destroy)
            .await
        {
            Ok(value) => value,
            Err(result) => return response(request, result, "MESH_OWNER_MISMATCH", None),
        };
        if let Some(binding) = binding {
            if !self.destroy_mesh_binding(binding).await {
                return backend_response(
                    request,
                    BackendError::CleanupIncomplete,
                    "WIFI_MESH_CLEANUP_INCOMPLETE",
                );
            }
        }
        response(
            request,
            HelperResult::Ok,
            "WIFI_MESH_DESTROYED",
            Some(helper_response::Outcome::DestroyedWifiMesh(
                DestroyedWifiMesh {
                    existed: binding.is_some(),
                },
            )),
        )
    }

    async fn exact_mesh_binding(
        &self,
        request: &HelperRequest,
        runtime_id: &[u8],
        handle: &[u8],
        action: MeshBackendAction,
    ) -> Result<Option<MeshBackendBinding>, HelperResult> {
        let state = self.inner.state.lock().await;
        let Some(record) = state.mesh.as_ref() else {
            return Ok(None);
        };
        if record.runtime_id.ct_eq(runtime_id).unwrap_u8() != 1
            || record.handle.ct_eq(handle).unwrap_u8() != 1
        {
            return Err(HelperResult::UnauthorisedPeer);
        }
        if action == MeshBackendAction::Inspect && !record.active {
            return Err(HelperResult::CleanupIncomplete);
        }
        Ok(Some(self.mesh_binding(record, action, Some(request))))
    }

    pub(super) async fn cleanup_mesh(&self) -> bool {
        let binding = self
            .inner
            .state
            .lock()
            .await
            .mesh
            .as_ref()
            .map(|record| self.mesh_binding(record, MeshBackendAction::Destroy, None));
        match binding {
            Some(binding) => self.destroy_mesh_binding(binding).await,
            None => true,
        }
    }

    async fn destroy_mesh_binding(&self, binding: MeshBackendBinding) -> bool {
        let backend = self.inner.backend.clone();
        let input = MeshBackendRequest::new(binding, ());
        if self
            .settle_mesh_call(binding, move || backend.destroy_wifi_mesh(input))
            .await
            .is_ok()
        {
            self.clear_mesh(binding).await;
            true
        } else {
            if let Some(record) = self.inner.state.lock().await.mesh.as_mut() {
                record.active = false;
            }
            false
        }
    }

    async fn clear_mesh(&self, binding: MeshBackendBinding) {
        let mut state = self.inner.state.lock().await;
        if state.mesh.as_ref().is_some_and(|record| {
            record.runtime_id == binding.mesh_runtime_id && record.handle == binding.mesh_handle
        }) {
            state.mesh = None;
            purge_mesh_cache(&mut state, binding);
        }
    }

    async fn settle_mesh_call<T: Send + 'static>(
        &self,
        binding: MeshBackendBinding,
        call: impl FnOnce() -> BackendFuture<MeshBackendCompletion<T>> + Send + 'static,
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

fn purge_mesh_cache(state: &mut EngineState, binding: MeshBackendBinding) {
    state
        .cache
        .retain(|_, cached| match cached.response.outcome.as_ref() {
            Some(helper_response::Outcome::InstalledWifiMesh(value)) => {
                value.mesh_handle != binding.mesh_handle
            }
            Some(helper_response::Outcome::WifiMeshSnapshot(value)) => {
                value.mesh_handle != binding.mesh_handle
            }
            _ => true,
        });
    state
        .cache_order
        .retain(|key| state.cache.contains_key(key));
}

fn wire_snapshot(
    binding: MeshBackendBinding,
    snapshot: crate::kernel::wifi_mesh::MeshSnapshot,
) -> WifiMeshSnapshot {
    WifiMeshSnapshot {
        mesh_runtime_id: binding.mesh_runtime_id.to_vec(),
        mesh_handle: binding.mesh_handle.to_vec(),
        ifindex: snapshot.ifindex,
        wiphy: snapshot.wiphy,
        frequency_mhz: snapshot.frequency_mhz,
        joined: snapshot.joined,
        peers: snapshot
            .peers
            .into_iter()
            .map(|peer| WifiMeshPeer {
                address: peer.mac.to_vec(),
                established: peer.established,
                received_bytes: peer.rx_bytes,
                transmitted_bytes: peer.tx_bytes,
                received_packets: peer.rx_packets,
                transmitted_packets: peer.tx_packets,
            })
            .collect(),
    }
}
