//! One parent-namespace direct mesh owner, independent of route-worker generations.

use std::sync::Arc;
use volparossa_routing::InstallWifiMesh;

use super::{BackendError, ConfirmedAbsent, FunctionalAlphaLeaseBackend, HardDeadline};
use crate::{
    engine::{
        MeshBackendAction, MeshBackendBinding, MeshBackendCompletion, MeshBackendRequest,
        MeshInterfaceIdentity,
    },
    kernel::wifi_mesh::{self, MeshOwner, MeshSnapshot, WifiMeshConfig},
};

pub(super) struct OpenMeshEntry {
    binding: MeshBackendBinding,
    owner: MeshOwner,
}

impl FunctionalAlphaLeaseBackend {
    pub(super) async fn install_mesh_backend(
        self: Arc<Self>,
        request: MeshBackendRequest<InstallWifiMesh>,
    ) -> MeshBackendCompletion<MeshInterfaceIdentity> {
        let (binding, value) = request.into_parts();
        // The syscall sequence is bounded by the absolute caller deadline. Its owner remains in
        // this backend, never in a detached temporary task or a route-generation map.
        let result = tokio::task::spawn_blocking(move || self.install_mesh_kernel(binding, &value))
            .await
            .unwrap_or(Err(BackendError::CleanupIncomplete));
        MeshBackendCompletion { binding, result }
    }

    fn install_mesh_kernel(
        &self,
        binding: MeshBackendBinding,
        value: &InstallWifiMesh,
    ) -> Result<MeshInterfaceIdentity, BackendError> {
        validate_binding(binding, MeshBackendAction::Install)?;
        if value.mesh_runtime_id != binding.mesh_runtime_id {
            return Err(BackendError::Invalid);
        }
        let deadline = deadline(binding)?;
        let mut slot = self
            .mesh_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Err(BackendError::Capacity);
        }
        let config = WifiMeshConfig {
            parent_interface: value.parent_interface.clone(),
            mesh_id: value.mesh_id.clone(),
            frequency_mhz: value.frequency_mhz,
            local_address: value.local_address.clone(),
            prefix_len: u8::try_from(value.prefix_len).map_err(|_| BackendError::Invalid)?,
            maximum_peers: u16::try_from(value.maximum_peers).map_err(|_| BackendError::Invalid)?,
            runtime_id: binding.mesh_runtime_id,
        };
        match wifi_mesh::install(config.clone(), deadline) {
            Ok(owner) => {
                let exact_config = owner.config() == &config;
                let identity = MeshInterfaceIdentity {
                    interface: owner.interface_name().to_owned(),
                    ifindex: owner.ifindex(),
                    wiphy: owner.wiphy(),
                };
                *slot = Some(OpenMeshEntry { binding, owner });
                if exact_config {
                    Ok(identity)
                } else {
                    Err(BackendError::CleanupIncomplete)
                }
            }
            Err(failure) => {
                if let Some(owner) = failure.cleanup {
                    *slot = Some(OpenMeshEntry {
                        binding,
                        owner: *owner,
                    });
                    Err(BackendError::CleanupIncomplete)
                } else {
                    Err(match failure.source {
                        crate::kernel::KernelError::Invalid => BackendError::Invalid,
                        crate::kernel::KernelError::Unsupported => BackendError::Unavailable,
                        _ => BackendError::Kernel,
                    })
                }
            }
        }
    }

    pub(super) async fn inspect_mesh_backend(
        self: Arc<Self>,
        request: MeshBackendRequest<()>,
    ) -> MeshBackendCompletion<MeshSnapshot> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, MeshBackendAction::Inspect)?;
            let mut slot = self
                .mesh_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = slot.as_mut().ok_or(BackendError::Invalid)?;
            if !same_owner(entry.binding, binding) {
                return Err(BackendError::Invalid);
            }
            entry
                .owner
                .inspect(deadline(binding)?)
                .map_err(|_| BackendError::Kernel)
        })
        .await
        .unwrap_or(Err(BackendError::CleanupIncomplete));
        MeshBackendCompletion { binding, result }
    }

    pub(super) async fn destroy_mesh_backend(
        self: Arc<Self>,
        request: MeshBackendRequest<()>,
    ) -> MeshBackendCompletion<ConfirmedAbsent> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, MeshBackendAction::Destroy)?;
            let mut slot = self
                .mesh_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = slot.as_mut() {
                if !same_owner(entry.binding, binding) {
                    return Err(BackendError::Invalid);
                }
                entry
                    .owner
                    .remove(deadline(binding)?)
                    .map_err(|_| BackendError::CleanupIncomplete)?;
                *slot = None;
            }
            Ok(ConfirmedAbsent)
        })
        .await
        .unwrap_or(Err(BackendError::CleanupIncomplete));
        MeshBackendCompletion { binding, result }
    }

    pub(super) async fn shutdown_mesh_backend(
        self: Arc<Self>,
        helper_runtime_id: [u8; 32],
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        tokio::task::spawn_blocking(move || {
            let mut slot = self
                .mesh_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = slot.as_mut() {
                if entry.binding.helper_runtime_id != helper_runtime_id {
                    return Err(BackendError::Invalid);
                }
                entry
                    .owner
                    .remove(deadline)
                    .map_err(|_| BackendError::CleanupIncomplete)?;
                *slot = None;
            }
            Ok(())
        })
        .await
        .unwrap_or(Err(BackendError::CleanupIncomplete))
    }
}

fn validate_binding(
    binding: MeshBackendBinding,
    action: MeshBackendAction,
) -> Result<(), BackendError> {
    if binding.helper_runtime_id == [0; 32]
        || binding.mesh_runtime_id == [0; 16]
        || binding.mesh_handle == [0; 32]
        || binding.action != action
    {
        return Err(BackendError::Invalid);
    }
    deadline(binding).map(|_| ())
}

fn deadline(binding: MeshBackendBinding) -> Result<HardDeadline, BackendError> {
    HardDeadline::at(binding.call_deadline.into_std()).map_err(|_| BackendError::CleanupIncomplete)
}

fn same_owner(first: MeshBackendBinding, second: MeshBackendBinding) -> bool {
    first.helper_runtime_id == second.helper_runtime_id
        && first.mesh_runtime_id == second.mesh_runtime_id
        && first.mesh_handle == second.mesh_handle
}
