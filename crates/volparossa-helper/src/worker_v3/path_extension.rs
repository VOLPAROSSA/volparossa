//! Independently staged worker resources for live Client/Exit path additions.
use super::{
    ActivatedLeases, BTreeMap, ChildOperationOutcome, ContextDestroyed, ContextId,
    ContextInitialised, DurableWireguardResource, HardDeadline, InternalWorkerResult, MptcpLimits,
    PrepareLeases, PreparedLeases, ProbedLeases, RoutingContextRole, WorkerActivateOutcome,
    WorkerContext, WorkerKeySource, WorkerLeaseLifecycle, WorkerLeaseOwnership,
    WorkerMptcpPathManager, WorkerNamespaceKernel, WorkerPrepareOutcome, WorkerProbeOutcome,
    WorkerV3Error, cleanup_unadopted_worker_resources, context_id, downlink_sender,
    internal_worker_response, validate_worker_prepare,
};
use crate::internal_protocol::path_extension::{Action, PathExtension};

pub(super) struct WorkerExtension {
    prepare: PrepareLeases,
    resources: Vec<DurableWireguardResource>,
    lifecycle: Option<WorkerLeaseLifecycle>,
    downlink: BTreeMap<u32, downlink_sender::WorkerDownlinkSender>,
    aborted: bool,
}

impl<Kernel: WorkerNamespaceKernel> WorkerContext<Kernel> {
    fn stage_extension(&mut self, id: ContextId, prepare: &PrepareLeases) -> InternalWorkerResult {
        if !matches!(
            self.role,
            RoutingContextRole::Client | RoutingContextRole::Exit
        ) || !matches!(self.lease, Some(WorkerLeaseLifecycle::Committed(_)))
        {
            return InternalWorkerResult::Conflict;
        }
        if let Some(existing) = self.extensions.get(&id) {
            return if existing.prepare == *prepare && !existing.aborted {
                InternalWorkerResult::Ok
            } else {
                InternalWorkerResult::Conflict
            };
        }
        let Some(resources) = validate_worker_prepare(prepare, self.route_context_id, self.role)
        else {
            return InternalWorkerResult::Invalid;
        };
        let [resource] = resources.as_slice() else {
            return InternalWorkerResult::Invalid;
        };
        let original = self.staged_resources.as_deref().unwrap_or_default();
        if original.len() + self.extensions.len() >= 8
            || original.iter().any(|old| {
                old.key() == resource.key()
                    || old.hard_expires_at_unix() != resource.hard_expires_at_unix()
            })
            || self
                .extensions
                .values()
                .any(|old| old.resources.iter().any(|old| old.key() == resource.key()))
            || self.extensions.values().any(|old| {
                !old.aborted && !matches!(old.lifecycle, Some(WorkerLeaseLifecycle::Committed(_)))
            })
        {
            return InternalWorkerResult::Conflict;
        }
        self.extensions.insert(
            id,
            WorkerExtension {
                prepare: prepare.clone(),
                resources,
                lifecycle: None,
                downlink: BTreeMap::new(),
                aborted: false,
            },
        );
        InternalWorkerResult::Ok
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive transition table for the staged extension owner"
    )]
    pub(super) fn extension_operation(
        &mut self,
        value: &PathExtension,
        keys: &mut impl WorkerKeySource,
        deadline: HardDeadline,
    ) -> Result<ChildOperationOutcome, WorkerV3Error> {
        let id = context_id(&value.extension_id)?;
        let Some(action) = value.action.as_ref() else {
            return Err(WorkerV3Error::Invalid);
        };
        if let Action::Stage(prepare) = action {
            let result = self.stage_extension(id, prepare);
            let outcome = (result == InternalWorkerResult::Ok).then(|| {
                internal_worker_response::Outcome::Initialised(ContextInitialised {
                    route_context_id: self.route_context_id.to_vec(),
                })
            });
            return Ok((result, outcome, false));
        }
        if let Action::Abort(scope) = action {
            if scope.route_context_id.as_slice() != self.route_context_id {
                return Ok((InternalWorkerResult::Invalid, None, false));
            }
            let result = self.abort_extension(id, deadline);
            return Ok((
                result,
                (result == InternalWorkerResult::Ok).then_some(
                    internal_worker_response::Outcome::Destroyed(ContextDestroyed {}),
                ),
                false,
            ));
        }
        let Some(mut extension) = self.extensions.remove(&id) else {
            return Ok((InternalWorkerResult::NotFound, None, false));
        };
        if extension.aborted || !matches!(self.lease, Some(WorkerLeaseLifecycle::Committed(_))) {
            self.extensions.insert(id, extension);
            return Ok((InternalWorkerResult::Conflict, None, false));
        }
        // Existing implementations operate on an exact lifecycle. Temporarily lend them only
        // the new resource and its sender queue; failure cleanup cannot see original leases.
        let original = self.lease.take();
        let staged = self
            .staged_resources
            .replace(std::mem::take(&mut extension.resources));
        let original_downlink = std::mem::replace(
            &mut self.downlink_senders,
            std::mem::take(&mut extension.downlink),
        );
        self.lease = extension.lifecycle.take();
        let outcome = match action {
            Action::Prepare(prepare) if *prepare == extension.prepare => {
                match self.prepare(prepare, keys, deadline) {
                    WorkerPrepareOutcome::Prepared(leases) => (
                        InternalWorkerResult::Ok,
                        Some(internal_worker_response::Outcome::Prepared(
                            PreparedLeases { leases },
                        )),
                        false,
                    ),
                    WorkerPrepareOutcome::Failed(result) => (result, None, false),
                }
            }
            Action::Activate(activate) => match self.activate(activate, deadline) {
                WorkerActivateOutcome::Activated(leases) => (
                    InternalWorkerResult::Ok,
                    Some(internal_worker_response::Outcome::Activated(
                        ActivatedLeases { leases },
                    )),
                    false,
                ),
                WorkerActivateOutcome::Failed(result) => (result, None, false),
                WorkerActivateOutcome::Terminate => {
                    (InternalWorkerResult::CleanupIncomplete, None, false)
                }
            },
            Action::Commit(probe) => match self.probe_commit(probe, deadline) {
                WorkerProbeOutcome::Committed(leases) => (
                    InternalWorkerResult::Ok,
                    Some(internal_worker_response::Outcome::ProbedCommitted(
                        ProbedLeases { leases },
                    )),
                    false,
                ),
                WorkerProbeOutcome::Failed(result) => (result, None, false),
                WorkerProbeOutcome::Terminate => {
                    (InternalWorkerResult::CleanupIncomplete, None, false)
                }
            },
            _ => (InternalWorkerResult::Invalid, None, false),
        };
        extension.lifecycle = self.lease.take();
        extension.downlink = std::mem::replace(&mut self.downlink_senders, original_downlink);
        extension.resources = std::mem::replace(&mut self.staged_resources, staged)
            .expect("temporarily lent extension resources");
        self.lease = original;
        let mut outcome = outcome;
        if outcome.0 == InternalWorkerResult::Ok && matches!(action, Action::Activate(_)) {
            self.downlink_senders.append(&mut extension.downlink);
        }
        if outcome.0 == InternalWorkerResult::Ok && matches!(action, Action::Commit(_)) {
            let count = self.staged_resources.as_ref().map_or(0, Vec::len)
                + self
                    .extensions
                    .values()
                    .filter(|entry| {
                        matches!(entry.lifecycle, Some(WorkerLeaseLifecycle::Committed(_)))
                    })
                    .count()
                + 1;
            if self
                .mptcp
                .as_ref()
                .is_none_or(|manager| manager.extend_limits(count).is_err())
            {
                outcome = (InternalWorkerResult::Kernel, None, false);
            }
            self.downlink_senders.append(&mut extension.downlink);
        }
        self.extensions.insert(id, extension);
        Ok(outcome)
    }

    pub(super) fn abort_extension(
        &mut self,
        id: ContextId,
        deadline: HardDeadline,
    ) -> InternalWorkerResult {
        let Some(mut extension) = self.extensions.remove(&id) else {
            // No staged authority means this worker never accepted mutation for this ID.
            return InternalWorkerResult::Ok;
        };
        if extension.aborted {
            self.extensions.insert(id, extension);
            return InternalWorkerResult::Ok;
        }
        let path_id = extension.resources[0].key().0;
        let path = u32::from(path_id);
        if matches!(
            extension.lifecycle,
            Some(WorkerLeaseLifecycle::Committed(_))
        ) && self
            .mptcp
            .as_ref()
            .is_some_and(|manager| manager.remove(path_id).is_err())
        {
            self.extensions.insert(id, extension);
            return InternalWorkerResult::CleanupIncomplete;
        }
        if let Some(sender) = self.downlink_senders.remove(&path) {
            extension.downlink.insert(path, sender);
        }
        let original_downlink = std::mem::replace(&mut self.downlink_senders, extension.downlink);
        let absent =
            cleanup_unadopted_worker_resources(&mut self.kernel, &extension.resources, deadline)
                && self.cleanup_downlink_after_links(deadline);
        extension.downlink = std::mem::replace(&mut self.downlink_senders, original_downlink);
        if absent {
            extension.lifecycle = None;
            extension.aborted = true;
        }
        self.extensions.insert(id, extension);
        if absent {
            InternalWorkerResult::Ok
        } else {
            InternalWorkerResult::CleanupIncomplete
        }
    }

    pub(super) fn extension_committed_lease(
        &self,
        path: u8,
        role: i32,
    ) -> Option<&WorkerLeaseOwnership> {
        self.extensions
            .values()
            .find_map(|entry| match entry.lifecycle.as_ref() {
                Some(WorkerLeaseLifecycle::Committed(leases)) if !entry.aborted => leases
                    .iter()
                    .find(|lease| lease.resource.key() == (path, role)),
                _ => None,
            })
    }
}

impl WorkerMptcpPathManager {
    fn extend_limits(&self, paths: usize) -> Result<(), ()> {
        if !(1..=8).contains(&paths) {
            return Err(());
        }
        // Room is not path authority: the helper still admits only exact committed leases.
        let bound = 8;
        self.backend
            .update_context_limits(
                &self.route_context_id,
                MptcpLimits {
                    accepted_addrs: bound,
                    subflows: bound,
                },
            )
            .map_err(|_| ())
    }
}
