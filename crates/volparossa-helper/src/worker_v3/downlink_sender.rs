//! Worker-lifetime sender ownership; the parent verifies signed receiver authority.

#[cfg(test)]
mod tests;

use super::{
    ActivateLeases, HardDeadline, InternalWorkerResult, RoutingContextRole, WorkerContext,
    WorkerLeaseLifecycle, WorkerLeaseOwnership, WorkerNamespaceKernel,
    relay_fence::downlink_gate::DownlinkGate,
};
use crate::{
    internal_protocol::{ApplyWorkerDownlinkBudget, WorkerDownlinkBudgetApplied},
    kernel::underlay_sharing::downlink::DownlinkQueue,
};

pub(super) struct WorkerDownlinkSender {
    gate: DownlinkGate,
    queue: Option<Box<DownlinkQueue>>,
    sequence: u64,
}

impl<Kernel: WorkerNamespaceKernel> WorkerContext<Kernel> {
    pub(super) fn install_downlink_senders(
        &mut self,
        ownerships: &[WorkerLeaseOwnership],
        operation: &ActivateLeases,
        deadline: HardDeadline,
    ) -> Result<(), InternalWorkerResult> {
        if operation.receive_budget_required_paths.is_empty() {
            return Ok(());
        }
        if self.role != RoutingContextRole::Exit || !self.downlink_senders.is_empty() {
            return Err(InternalWorkerResult::Invalid);
        }
        for path in &operation.receive_budget_required_paths {
            let lease = ownerships
                .iter()
                .find(|lease| u32::from(lease.resource.key().0) == *path)
                .ok_or(InternalWorkerResult::Invalid)?;
            let proof = lease.proof.ok_or(InternalWorkerResult::Invalid)?;
            let gate = DownlinkGate::new(self.route_context_id, &lease.resource, proof.ifindex)
                .map_err(|_| InternalWorkerResult::Kernel)?;
            self.downlink_senders.insert(
                *path,
                WorkerDownlinkSender {
                    gate,
                    queue: None,
                    sequence: 0,
                },
            );
            let owner = self
                .downlink_senders
                .get_mut(path)
                .ok_or(InternalWorkerResult::Invalid)?;
            owner
                .gate
                .close(deadline)
                .map_err(|_| InternalWorkerResult::Kernel)?;
            match DownlinkQueue::install(&lease.resource, proof.ifindex, deadline) {
                Ok(queue) => owner.queue = Some(Box::new(queue)),
                Err(failure) => {
                    owner.queue = failure.cleanup;
                    return Err(InternalWorkerResult::Kernel);
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_downlink_budget(
        &mut self,
        operation: &ApplyWorkerDownlinkBudget,
        deadline: HardDeadline,
    ) -> Result<WorkerDownlinkBudgetApplied, InternalWorkerResult> {
        if operation.route_context_id.as_slice() != self.route_context_id
            || self.role != RoutingContextRole::Exit
            || !matches!(
                self.lease,
                Some(WorkerLeaseLifecycle::Activated(_) | WorkerLeaseLifecycle::Committed(_))
            )
        {
            return Err(InternalWorkerResult::Invalid);
        }
        let owner = self
            .downlink_senders
            .get_mut(&operation.path_id)
            .ok_or(InternalWorkerResult::Invalid)?;
        if operation.sequence <= owner.sequence {
            return Err(InternalWorkerResult::Conflict);
        }
        let queue = owner
            .queue
            .as_mut()
            .ok_or(InternalWorkerResult::CleanupIncomplete)?;
        // Monotone sequences are consumed before privileged mutation, including failed/lost ACKs.
        owner.sequence = operation.sequence;
        owner
            .gate
            .close(deadline)
            .map_err(|_| InternalWorkerResult::CleanupIncomplete)?;
        if operation.rate_bytes_per_second > 0 {
            queue
                .set_rate(
                    operation.rate_bytes_per_second,
                    operation.burst_bytes,
                    deadline,
                )
                .map_err(|_| InternalWorkerResult::CleanupIncomplete)?;
            owner
                .gate
                .open(
                    operation.expires_at_ms,
                    operation.expires_at_boottime_ns,
                    deadline,
                )
                .map_err(|_| InternalWorkerResult::CleanupIncomplete)?;
        }
        Ok(WorkerDownlinkBudgetApplied {
            sequence: operation.sequence,
            maximum_queued_bytes: queue.maximum_queued_bytes(),
        })
    }

    /// Called only after exact `WireGuard` link absence: deleting those links also deletes qdiscs.
    /// Persistent gates are then retired explicitly while namespace custody is still pinned.
    pub(super) fn cleanup_downlink_after_links(&mut self, deadline: HardDeadline) -> bool {
        for sender in self.downlink_senders.values_mut() {
            if sender.gate.remove(deadline).is_err() {
                return false;
            }
        }
        self.downlink_senders.clear();
        true
    }
}
