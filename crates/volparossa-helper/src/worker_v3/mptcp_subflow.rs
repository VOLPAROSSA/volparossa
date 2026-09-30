//! Per-worker userspace-PM ownership with no retained data descriptor.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use volparossa_mptcp::{
    EndpointFlags, MptcpEndpoint, MptcpEventKind, MptcpEventSubscription, MptcpNetlinkClient,
};

use super::{
    ChildOperationOutcome, ContextId, HardDeadline, InternalWorkerResult, Ipv6Addr,
    MptcpEndpointAdded, MptcpEndpointRemoved, NamespaceKernel, RoutingContextRole, WorkerContext,
    WorkerNamespaceKernel, internal_worker_response,
};
use crate::internal_protocol::mptcp_subflow::{Action, UpdateMptcpSubflow};

const MAX_FLOWS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathState {
    Requested,
    Observed(u16),
    Closed,
}

fn create_pending_or_observed(state: Option<&PathState>) -> bool {
    matches!(state, Some(PathState::Requested | PathState::Observed(_)))
}

struct OwnedFlow {
    token: u32,
    cookie: u64,
    primary: u32,
    remote_port: u16,
    paths: BTreeMap<u8, PathState>,
}

pub(super) struct ClientPathManager {
    events: MptcpEventSubscription,
    flows: BTreeMap<[u8; 32], OwnedFlow>,
}

impl ClientPathManager {
    pub(super) fn connect() -> Result<Self, ()> {
        Ok(Self {
            events: MptcpEventSubscription::connect().map_err(|_| ())?,
            flows: BTreeMap::new(),
        })
    }

    fn drain(&mut self) -> Result<(), InternalWorkerResult> {
        for event in self
            .events
            .drain()
            .map_err(|_| InternalWorkerResult::Kernel)?
        {
            let Some(token) = event.token else {
                continue;
            };
            if event.kind == MptcpEventKind::Closed {
                self.flows.retain(|_, flow| flow.token != token);
                continue;
            }
            if !matches!(
                event.kind,
                MptcpEventKind::SubflowClosed | MptcpEventKind::SubflowEstablished
            ) {
                continue;
            }
            let (Some(SocketAddr::V6(local)), Some(SocketAddr::V6(remote))) =
                (event.local, event.remote)
            else {
                return Err(InternalWorkerResult::Invalid);
            };
            let segments = local.ip().segments();
            let Ok(path) = u8::try_from(segments[5]) else {
                return Err(InternalWorkerResult::Invalid);
            };
            for flow in self.flows.values_mut().filter(|flow| flow.token == token) {
                if flow.remote_port != remote.port()
                    || segments[..7] != remote.ip().segments()[..7]
                    || segments[7] != 1
                    || remote.ip().segments()[7] != 4
                {
                    return Err(InternalWorkerResult::Invalid);
                }
                if let Some(state) = flow.paths.get_mut(&path) {
                    *state = if event.kind == MptcpEventKind::SubflowClosed {
                        PathState::Closed
                    } else {
                        PathState::Observed(local.port())
                    };
                }
            }
        }
        Ok(())
    }

    fn update(
        &mut self,
        request: &UpdateMptcpSubflow,
        mut endpoint: MptcpEndpoint,
    ) -> Result<(), InternalWorkerResult> {
        self.drain()?;
        let handle: [u8; 32] = request
            .flow_handle
            .as_slice()
            .try_into()
            .map_err(|_| InternalWorkerResult::Invalid)?;
        let remote_port =
            u16::try_from(request.remote_port).map_err(|_| InternalWorkerResult::Invalid)?;
        if !self.flows.contains_key(&handle) {
            if self.flows.len() >= MAX_FLOWS
                || self
                    .flows
                    .values()
                    .any(|flow| flow.token == request.token || flow.cookie == request.cookie)
            {
                return Err(InternalWorkerResult::Conflict);
            }
            self.flows.insert(
                handle,
                OwnedFlow {
                    token: request.token,
                    cookie: request.cookie,
                    primary: request.primary_path_id,
                    remote_port,
                    paths: BTreeMap::new(),
                },
            );
        }
        let flow = self
            .flows
            .get_mut(&handle)
            .ok_or(InternalWorkerResult::Invalid)?;
        if (flow.token, flow.cookie, flow.primary, flow.remote_port)
            != (
                request.token,
                request.cookie,
                request.primary_path_id,
                remote_port,
            )
        {
            return Err(InternalWorkerResult::Invalid);
        }
        let action = Action::try_from(request.action).map_err(|_| InternalWorkerResult::Invalid)?;
        if request.path_id == flow.primary {
            return if action == Action::Ensure && request.observed_local_port != 0 {
                Ok(())
            } else {
                Err(InternalWorkerResult::Invalid)
            };
        }
        let IpAddr::V6(address) = endpoint.address else {
            return Err(InternalWorkerResult::Invalid);
        };
        let mut remote_segments = address.segments();
        remote_segments[7] = 4;
        let remote = SocketAddr::new(Ipv6Addr::from(remote_segments).into(), remote_port);
        let port = u16::try_from(request.observed_local_port)
            .map_err(|_| InternalWorkerResult::Invalid)?;
        match action {
            Action::Ensure if port != 0 => {
                flow.paths.insert(endpoint.id, PathState::Observed(port));
                Ok(())
            }
            Action::Ensure => {
                // A prior ACK may still be connecting. Never turn a retry into a second subflow.
                if create_pending_or_observed(flow.paths.get(&endpoint.id)) {
                    return Ok(());
                }
                if flow.paths.len() >= 8 && !flow.paths.contains_key(&endpoint.id) {
                    return Err(InternalWorkerResult::Conflict);
                }
                endpoint.flags = EndpointFlags::SUBFLOW;
                let mut client =
                    MptcpNetlinkClient::connect().map_err(|_| InternalWorkerResult::Kernel)?;
                client
                    .create_subflow(flow.token, &endpoint, remote)
                    .map_err(|_| InternalWorkerResult::Kernel)?;
                flow.paths.insert(endpoint.id, PathState::Requested);
                Ok(())
            }
            Action::Retire if port == 0 => {
                // The parent observed complete same-FD absence. A known pending create without
                // a CLOSED event remains ambiguous; do not falsely acknowledge cancellation.
                if matches!(flow.paths.get(&endpoint.id), Some(PathState::Requested)) {
                    return Err(InternalWorkerResult::Conflict);
                }
                flow.paths.insert(endpoint.id, PathState::Closed);
                Ok(())
            }
            Action::Retire => {
                let mut client =
                    MptcpNetlinkClient::connect().map_err(|_| InternalWorkerResult::Kernel)?;
                client
                    .destroy_subflow(flow.token, SocketAddr::new(endpoint.address, port), remote)
                    .map_err(|_| InternalWorkerResult::Kernel)?;
                flow.paths.insert(endpoint.id, PathState::Closed);
                Ok(())
            }
            Action::Unspecified => Err(InternalWorkerResult::Invalid),
        }
    }
}

impl<Kernel: WorkerNamespaceKernel> WorkerContext<Kernel> {
    pub(super) fn update_mptcp_subflow(
        &self,
        operation: &UpdateMptcpSubflow,
        deadline: HardDeadline,
    ) -> InternalWorkerResult {
        if self.role != RoutingContextRole::Client
            || operation.route_context_id.as_slice() != self.route_context_id
            || deadline.ensure_remaining().is_err()
        {
            return InternalWorkerResult::Invalid;
        }
        let endpoint = match self.committed_mptcp_endpoint(operation.path_id) {
            Ok(endpoint) => endpoint,
            Err(error) => return error,
        };
        // Both the issued original path and the additional target remain committed/live.
        if self
            .committed_mptcp_endpoint(operation.primary_path_id)
            .is_err()
        {
            return InternalWorkerResult::Invalid;
        }
        let Some(manager) = self.mptcp_flows.as_ref() else {
            return InternalWorkerResult::Invalid;
        };
        let Ok(mut manager) = manager.lock() else {
            return InternalWorkerResult::Kernel;
        };
        match manager.update(operation, endpoint) {
            Ok(()) if deadline.ensure_remaining().is_ok() => InternalWorkerResult::Ok,
            Ok(()) => InternalWorkerResult::Kernel,
            Err(error) => error,
        }
    }
}

pub(super) fn execute(
    context: Option<&WorkerContext<NamespaceKernel>>,
    request: &UpdateMptcpSubflow,
    bound: ContextId,
    deadline: HardDeadline,
) -> ChildOperationOutcome {
    let Some(context) = context.filter(|context| {
        context.route_context_id == bound && request.route_context_id.as_slice() == bound
    }) else {
        return (InternalWorkerResult::NotFound, None, false);
    };
    let result = context.update_mptcp_subflow(request, deadline);
    let outcome = (result == InternalWorkerResult::Ok).then_some({
        if request.action == Action::Ensure as i32 {
            internal_worker_response::Outcome::MptcpEndpointAdded(MptcpEndpointAdded {
                path_id: request.path_id,
            })
        } else {
            internal_worker_response::Outcome::MptcpEndpointRemoved(MptcpEndpointRemoved {
                path_id: request.path_id,
            })
        }
    });
    (result, outcome, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledged_pending_create_is_not_duplicated_by_an_ensure_retry() {
        assert!(create_pending_or_observed(Some(&PathState::Requested)));
        assert!(create_pending_or_observed(Some(&PathState::Observed(
            45123
        ))));
        assert!(!create_pending_or_observed(Some(&PathState::Closed)));
        assert!(!create_pending_or_observed(None));
    }
}
