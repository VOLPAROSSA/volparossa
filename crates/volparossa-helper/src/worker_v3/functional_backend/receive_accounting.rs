//! One parent-namespace receive-counter owner, independent of namespace-worker route generations.

use std::sync::Arc;
use volparossa_routing::InstallReceiveAccounting;

use super::{BackendError, ConfirmedAbsent, FunctionalAlphaLeaseBackend, HardDeadline};
use crate::{
    engine::{
        AccountingBackendAction, AccountingBackendBinding, AccountingBackendCompletion,
        AccountingBackendRequest,
    },
    kernel::receive_accounting::{
        self, ReceiveAccountingConfig, ReceiveAccountingOwner, ReceiveAccountingSnapshot,
    },
};

pub(super) struct OpenAccountingEntry {
    pub(super) binding: AccountingBackendBinding,
    pub(super) owner: ReceiveAccountingOwner,
}

impl FunctionalAlphaLeaseBackend {
    pub(super) async fn install_accounting_backend(
        self: Arc<Self>,
        request: AccountingBackendRequest<InstallReceiveAccounting>,
    ) -> AccountingBackendCompletion<u32> {
        let (binding, value) = request.into_parts();
        // The syscall sequence is bounded by the absolute caller deadline. Its owner remains in
        // this backend, never in a detached temporary task or a route-generation map.
        let result =
            tokio::task::spawn_blocking(move || self.install_accounting_kernel(binding, &value))
                .await
                .unwrap_or(Err(BackendError::CleanupIncomplete));
        AccountingBackendCompletion { binding, result }
    }

    fn install_accounting_kernel(
        &self,
        binding: AccountingBackendBinding,
        value: &InstallReceiveAccounting,
    ) -> Result<u32, BackendError> {
        validate_binding(binding, AccountingBackendAction::Install)?;
        if value.accounting_runtime_id != binding.accounting_runtime_id {
            return Err(BackendError::Invalid);
        }
        let deadline = deadline(binding)?;
        let mut slot = self
            .accounting_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Err(BackendError::Capacity);
        }
        let ingress_ifindex =
            crate::kernel::underlay_sharing::resolve_interface(&value.interface, deadline)
                .map_err(|_| BackendError::Invalid)?;
        let config = ReceiveAccountingConfig {
            ifindex: ingress_ifindex,
            interface_name: value.interface.clone(),
            runtime_id: binding.accounting_runtime_id,
        };
        match receive_accounting::install(config, deadline) {
            Ok(owner) => {
                *slot = Some(OpenAccountingEntry { binding, owner });
                Ok(ingress_ifindex)
            }
            Err(failure) => {
                if let Some(owner) = failure.cleanup {
                    *slot = Some(OpenAccountingEntry {
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

    pub(super) async fn inspect_accounting_backend(
        self: Arc<Self>,
        request: AccountingBackendRequest<()>,
    ) -> AccountingBackendCompletion<ReceiveAccountingSnapshot> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, AccountingBackendAction::Inspect)?;
            let mut slot = self
                .accounting_state
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
        AccountingBackendCompletion { binding, result }
    }

    pub(super) async fn destroy_accounting_backend(
        self: Arc<Self>,
        request: AccountingBackendRequest<()>,
    ) -> AccountingBackendCompletion<ConfirmedAbsent> {
        let (binding, ()) = request.into_parts();
        let result = tokio::task::spawn_blocking(move || {
            validate_binding(binding, AccountingBackendAction::Destroy)?;
            let mut slot = self
                .accounting_state
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
        AccountingBackendCompletion { binding, result }
    }

    pub(super) async fn shutdown_accounting_backend(
        self: Arc<Self>,
        helper_runtime_id: [u8; 32],
        deadline: HardDeadline,
    ) -> Result<(), BackendError> {
        tokio::task::spawn_blocking(move || {
            let mut slot = self
                .accounting_state
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
    binding: AccountingBackendBinding,
    action: AccountingBackendAction,
) -> Result<(), BackendError> {
    if binding.helper_runtime_id == [0; 32]
        || binding.accounting_runtime_id == [0; 16]
        || binding.accounting_handle == [0; 32]
        || binding.action != action
    {
        return Err(BackendError::Invalid);
    }
    deadline(binding).map(|_| ())
}

fn deadline(binding: AccountingBackendBinding) -> Result<HardDeadline, BackendError> {
    HardDeadline::at(binding.call_deadline.into_std()).map_err(|_| BackendError::CleanupIncomplete)
}

pub(super) fn same_owner(
    first: AccountingBackendBinding,
    second: AccountingBackendBinding,
) -> bool {
    first.helper_runtime_id == second.helper_runtime_id
        && first.accounting_runtime_id == second.accounting_runtime_id
        && first.accounting_handle == second.accounting_handle
}

#[cfg(test)]
mod tests {
    use super::{AccountingBackendAction, AccountingBackendBinding, same_owner, validate_binding};

    #[test]
    fn receive_accounting_backend_keeps_runtime_handle_action_and_deadline_scope() {
        let binding = AccountingBackendBinding {
            helper_runtime_id: [1; 32],
            accounting_runtime_id: [2; 16],
            accounting_handle: [3; 32],
            request_id: [4; 16],
            request_digest: [5; 32],
            action: AccountingBackendAction::Inspect,
            call_deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        };
        assert!(validate_binding(binding, AccountingBackendAction::Inspect).is_ok());
        assert!(validate_binding(binding, AccountingBackendAction::Destroy).is_err());
        assert!(!same_owner(
            binding,
            AccountingBackendBinding {
                accounting_handle: [6; 32],
                ..binding
            }
        ));
        assert!(!same_owner(
            binding,
            AccountingBackendBinding {
                helper_runtime_id: [7; 32],
                ..binding
            }
        ));
        assert!(!same_owner(
            binding,
            AccountingBackendBinding {
                accounting_runtime_id: [8; 16],
                ..binding
            }
        ));
        assert!(
            validate_binding(
                AccountingBackendBinding {
                    call_deadline: tokio::time::Instant::now() - std::time::Duration::from_secs(1),
                    ..binding
                },
                AccountingBackendAction::Inspect
            )
            .is_err()
        );
    }
}
