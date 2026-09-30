//! Descriptorless, generation-owned Client flow capabilities and transient mutation ownership.

use super::{
    AcquireTransportSocket, BTreeSet, BackendAction, ContextPhase, EngineState, HelperEngine,
    HelperExecution, HelperRequest, MptcpEndpointMutation, OwnedFd, RoutingTransportSocketKind,
    WireguardRole, deadline_live, execution, expiry_now, fixed, invalid_response, matches_handle,
};
use crate::mptcp_flow::MptcpFlowIdentity;
use volparossa_routing::{MptcpSubflowAction, UpdateMptcpSubflow};

pub(super) const MAX_MPTCP_FLOWS_PER_CONTEXT: usize = 64;

/// No socket is retained by this ledger; context destruction drops all issued capabilities.
#[derive(Clone, Copy)]
pub(super) struct IssuedMptcpFlow {
    identity: MptcpFlowIdentity,
    generation: u64,
    initial_path: u32,
}

/// A live descriptor pins exactly this stream until the privileged worker operation settles.
pub(crate) struct BackendMptcpSubflow {
    pub(crate) operation: UpdateMptcpSubflow,
    pub(crate) descriptor: OwnedFd,
    pub(crate) flow: MptcpFlowIdentity,
    pub(crate) initial_path: u32,
}

impl HelperEngine {
    pub(super) fn register_mptcp_flow(
        &self,
        state: &mut EngineState,
        context_id: [u8; 16],
        request: &AcquireTransportSocket,
        descriptor: &OwnedFd,
    ) -> Option<Vec<u8>> {
        if request.role != WireguardRole::Client as i32
            || request.descriptor_kind != RoutingTransportSocketKind::MptcpConnected as i32
        {
            return Some(Vec::new());
        }
        let identity = MptcpFlowIdentity::capture(descriptor).ok()?;
        let handle = self.unique_handle(state, &BTreeSet::new())?;
        let context = state.contexts.get_mut(&context_id)?;
        if context.mptcp_flows.len() >= MAX_MPTCP_FLOWS_PER_CONTEXT {
            return None;
        }
        context.mptcp_flows.insert(
            handle,
            IssuedMptcpFlow {
                identity,
                generation: context.generation,
                initial_path: request.path_id,
            },
        );
        Some(handle.to_vec())
    }

    pub(super) async fn validate_mptcp_flow_input(
        &self,
        value: &UpdateMptcpSubflow,
        descriptor: &OwnedFd,
    ) -> Option<IssuedMptcpFlow> {
        let context_id = fixed::<16>(&value.route_context_id)?;
        let flow_handle = fixed::<32>(&value.mptcp_flow_handle)?;
        let state = self.inner.state.lock().await;
        let context = state.contexts.get(&context_id)?;
        let flow = *context.mptcp_flows.get(&flow_handle)?;
        if context.phase != ContextPhase::Committed
            || context.generation != flow.generation
            || !matches_handle(&context.handle, &value.context_handle)
            || !context
                .leases
                .contains_key(&(value.path_id, WireguardRole::Client as i32))
            || !deadline_live(
                expiry_now(self.inner.clock.as_ref()),
                context.hard_expires_at_unix,
                context.hard_expires_at_boottime_ns,
            )
            || value.path_id == flow.initial_path
            || !matches!(
                MptcpSubflowAction::try_from(value.action),
                Ok(MptcpSubflowAction::Ensure | MptcpSubflowAction::Retire)
            )
        {
            return None;
        }
        flow.identity.verify(descriptor).ok()?;
        Some(flow)
    }

    pub(super) async fn update_mptcp_subflow_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &UpdateMptcpSubflow,
        descriptor: OwnedFd,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(flow) = self.validate_mptcp_flow_input(value, &descriptor).await else {
            return Some(execution(invalid_response(request), None));
        };
        self.mutate_mptcp_endpoint_async(
            request,
            request_id,
            digest,
            &value.route_context_id,
            &value.context_handle,
            value.path_id,
            BackendAction::UpdateMptcpSubflow,
            MptcpEndpointMutation::Subflow(BackendMptcpSubflow {
                operation: value.clone(),
                descriptor,
                flow: flow.identity,
                initial_path: flow.initial_path,
            }),
            sender,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_routing::{HELPER_PROTOCOL_VERSION, HelperResult, helper_request};

    fn update() -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            operation: Some(helper_request::Operation::UpdateMptcpSubflow(
                UpdateMptcpSubflow {
                    route_context_id: vec![2; 16],
                    context_handle: vec![3; 32],
                    mptcp_flow_handle: vec![4; 32],
                    path_id: 2,
                    action: MptcpSubflowAction::Ensure as i32,
                },
            )),
        }
    }

    #[tokio::test]
    async fn mptcp_subflow_requires_issued_context_and_actual_request_descriptor() {
        let engine = HelperEngine::new([1; 32], 1000);
        let request = update();
        assert_eq!(
            engine.execute(request.clone()).await.result,
            HelperResult::InvalidRequest as i32
        );
        let (descriptor, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let result = engine
            .execute_with_input_descriptor(request, Some(descriptor.into()))
            .await;
        assert_eq!(result.response.result, HelperResult::InvalidRequest as i32);
        assert!(result.descriptor.is_none());
        assert!(engine.inner.state.lock().await.contexts.is_empty());
    }
}
