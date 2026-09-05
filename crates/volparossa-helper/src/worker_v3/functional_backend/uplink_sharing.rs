//! One parent-namespace scheduler owner, independent of namespace-worker route generations.

use std::sync::Arc;
use volparossa_routing::InstallUplinkSharing;

use super::{BackendError, ConfirmedAbsent, FunctionalAlphaLeaseBackend, HardDeadline};
use crate::{
    engine::{
        SharingBackendAction, SharingBackendBinding, SharingBackendCompletion,
        SharingBackendRequest,
    },
    kernel::underlay_sharing::{self, SharingConfig, SharingCounters, SharingOwner},
};

pub(super) struct OpenSharingEntry {
    binding: SharingBackendBinding,
    owner: SharingOwner,
}

impl FunctionalAlphaLeaseBackend {
    pub(super) async fn install_sharing_backend(
        self: Arc<Self>,
        request: SharingBackendRequest<InstallUplinkSharing>,
    ) -> SharingBackendCompletion<u32> {
        let (binding, value) = request.into_parts();
        // The syscall sequence is bounded by the absolute caller deadline. Its owner remains in
        // this backend, never in a detached temporary task or a route-generation map.
        let result =
            tokio::task::spawn_blocking(move || self.install_sharing_kernel(binding, &value))
                .await
                .unwrap_or(Err(BackendError::CleanupIncomplete));
        SharingBackendCompletion { binding, result }
    }

    fn install_sharing_kernel(
        &self,
        binding: SharingBackendBinding,
        value: &InstallUplinkSharing,
    ) -> Result<u32, BackendError> {
        validate_binding(binding, SharingBackendAction::Install)?;
        if value.sharing_runtime_id != binding.sharing_runtime_id {
            return Err(BackendError::Invalid);
        }
        let deadline = deadline(binding)?;
        let mut slot = self
            .sharing_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Err(BackendError::Capacity);
        }
        let egress_ifindex = underlay_sharing::resolve_interface(&value.interface, deadline)
            .map_err(|_| BackendError::Invalid)?;
        let config = SharingConfig {
            egress_ifindex,
            runtime_id: binding.sharing_runtime_id,
            total_upload_mbps: value.total_upload_mbps,
            contribution_upload_mbps: value.contribution_upload_ceiling_mbps,
        };
        match underlay_sharing::install(config, deadline) {
            Ok(owner) => {
                *slot = Some(OpenSharingEntry { binding, owner });
                Ok(egress_ifindex)
            }
            Err(failure) => {
                if let Some(owner) = failure.cleanup {
                    *slot = Some(OpenSharingEntry {
                        binding,
                        owner: *owner,
                    });
                    Err(BackendError::CleanupIncomplete)
                } else {
                    Err(BackendError::Kernel)
                }
            }
        }
    }

    pub(super) async fn inspect_sharing_backend(
        self: Arc<Self>,
        request: SharingBackendRequest<()>,
    ) -> SharingBackendCompletion<SharingCounters> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, SharingBackendAction::Inspect)?;
            let slot = self
                .sharing_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = slot.as_ref().ok_or(BackendError::Invalid)?;
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
        SharingBackendCompletion { binding, result }
    }

    pub(super) async fn destroy_sharing_backend(
        self: Arc<Self>,
        request: SharingBackendRequest<()>,
    ) -> SharingBackendCompletion<ConfirmedAbsent> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, SharingBackendAction::Destroy)?;
            let mut slot = self
                .sharing_state
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
        SharingBackendCompletion { binding, result }
    }

    pub(super) async fn shutdown_sharing_backend(
        self: Arc<Self>,
        helper_runtime_id: [u8; 32],
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        tokio::task::spawn_blocking(move || {
            let mut slot = self
                .sharing_state
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
    binding: SharingBackendBinding,
    action: SharingBackendAction,
) -> Result<(), BackendError> {
    if binding.helper_runtime_id == [0; 32]
        || binding.sharing_runtime_id == [0; 16]
        || binding.sharing_handle == [0; 32]
        || binding.action != action
    {
        return Err(BackendError::Invalid);
    }
    deadline(binding).map(|_| ())
}

fn deadline(binding: SharingBackendBinding) -> Result<HardDeadline, BackendError> {
    HardDeadline::at(binding.call_deadline.into_std()).map_err(|_| BackendError::CleanupIncomplete)
}

fn same_owner(first: SharingBackendBinding, second: SharingBackendBinding) -> bool {
    first.helper_runtime_id == second.helper_runtime_id
        && first.sharing_runtime_id == second.sharing_runtime_id
        && first.sharing_handle == second.sharing_handle
}

#[cfg(test)]
mod tests;
