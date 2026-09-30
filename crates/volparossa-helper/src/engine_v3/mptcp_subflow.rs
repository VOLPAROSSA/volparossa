//! Descriptorless, generation-owned Client flow capabilities and transient mutation ownership.

use super::{
    AcquireTransportSocket, BackendAction, ContextPhase, ContextRecord, EngineState, HelperEngine,
    HelperExecution, HelperRequest, MptcpEndpointMutation, OwnedFd, RoutingTransportSocketKind,
    WireguardRole, deadline_live, execution, expiry_now, fixed, invalid_response, matches_handle,
    response,
};
use crate::mptcp_flow::MptcpFlowIdentity;
use std::collections::BTreeMap;
use volparossa_routing::{HelperResult, MptcpSubflowAction, RetireMptcpFlow, UpdateMptcpSubflow};

pub(super) const MAX_MPTCP_FLOWS_PER_CONTEXT: usize = 64;

/// No socket is retained by this ledger; terminal retirement or context destruction revokes it.
#[derive(Clone, Copy)]
pub(super) struct IssuedMptcpFlow {
    identity: MptcpFlowIdentity,
    generation: u64,
    initial_path: u32,
}

#[derive(Default)]
pub(super) struct MptcpFlowLedger {
    flows: BTreeMap<[u8; 32], IssuedMptcpFlow>,
    sequence: u64,
}

impl MptcpFlowLedger {
    pub(super) fn len(&self) -> usize {
        self.flows.len()
    }
    pub(super) fn contains_key(&self, handle: &[u8; 32]) -> bool {
        self.flows.contains_key(handle)
    }
    pub(super) fn get(&self, handle: &[u8; 32]) -> Option<&IssuedMptcpFlow> {
        self.flows.get(handle)
    }
    pub(super) fn remove(&mut self, handle: &[u8; 32]) {
        self.flows.remove(handle);
    }

    fn issue(&mut self, flow: IssuedMptcpFlow, random: [u8; 32]) -> Option<[u8; 32]> {
        if self.len() >= MAX_MPTCP_FLOWS_PER_CONTEXT {
            return None;
        }
        let handle = sequence_flow_handle(&mut self.sequence, random)?;
        self.flows.insert(handle, flow);
        Some(handle)
    }
}

/// A live descriptor pins exactly this stream until the privileged worker operation settles.
pub(crate) struct BackendMptcpSubflow {
    pub(crate) operation: UpdateMptcpSubflow,
    pub(crate) descriptor: OwnedFd,
    pub(crate) flow: MptcpFlowIdentity,
    pub(crate) initial_path: u32,
}

pub(crate) struct BackendMptcpFlowRetirement {
    pub(crate) operation: RetireMptcpFlow,
    pub(crate) descriptor: OwnedFd,
    pub(crate) flow: MptcpFlowIdentity,
    pub(crate) initial_path: u32,
}

fn sequence_flow_handle(sequence: &mut u64, mut random: [u8; 32]) -> Option<[u8; 32]> {
    *sequence = sequence.checked_add(1)?;
    // A context-scoped monotonic prefix prevents reissue without retaining retired tombstones.
    // The remaining 192 OS-random bits are the capability, not a new cryptographic primitive.
    random[..8].copy_from_slice(&sequence.to_be_bytes());
    Some(random)
}

fn retirement_flow(
    context: &ContextRecord,
    value: &RetireMptcpFlow,
) -> Result<IssuedMptcpFlow, HelperResult> {
    // Absence is only meaningful under the exact live context capability. Never let a
    // missing flow bypass authorization, or turn it into a fabricated shutdown receipt.
    if context.phase != ContextPhase::Committed
        || !matches_handle(&context.handle, &value.context_handle)
    {
        return Err(HelperResult::InvalidRequest);
    }
    let handle = fixed::<32>(&value.mptcp_flow_handle).ok_or(HelperResult::InvalidRequest)?;
    let flow = context
        .mptcp_flows
        .get(&handle)
        .ok_or(HelperResult::NotFound)?;
    if flow.generation != context.generation {
        return Err(HelperResult::InvalidRequest);
    }
    Ok(*flow)
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
        let context = state.contexts.get_mut(&context_id)?;
        let mut random = [0; 32];
        self.inner.handles.fill(&mut random);
        let handle = context.mptcp_flows.issue(
            IssuedMptcpFlow {
                identity,
                generation: context.generation,
                initial_path: request.path_id,
            },
            random,
        )?;
        Some(handle.to_vec())
    }

    pub(super) async fn retire_mptcp_flow_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &RetireMptcpFlow,
        descriptor: OwnedFd,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let context_id = fixed::<16>(&value.route_context_id)?;
        let flow = {
            let state = self.inner.state.lock().await;
            let Some(context) = state.contexts.get(&context_id) else {
                return Some(execution(
                    response(request, HelperResult::NotFound, "CONTEXT_ABSENT", None),
                    None,
                ));
            };
            match retirement_flow(context, value) {
                Ok(flow) => flow,
                Err(HelperResult::NotFound) => {
                    // Issued handles are never reused. The original retirement ACK may have
                    // expired/been evicted, but absent authority needs no descriptor inspection
                    // or backend mutation and proves only that the capability no longer exists.
                    return Some(execution(
                        response(
                            request,
                            HelperResult::NotFound,
                            "MPTCP_FLOW_CAPABILITY_ABSENT",
                            None,
                        ),
                        None,
                    ));
                }
                Err(_) => return Some(execution(invalid_response(request), None)),
            }
        };
        if flow.identity.verify_for_retirement(&descriptor).is_err() {
            return Some(execution(invalid_response(request), None));
        }
        self.mutate_mptcp_endpoint_async(
            request,
            request_id,
            digest,
            &value.route_context_id,
            &value.context_handle,
            flow.initial_path,
            BackendAction::RetireMptcpFlow,
            MptcpEndpointMutation::RetireFlow(BackendMptcpFlowRetirement {
                operation: value.clone(),
                descriptor,
                flow: flow.identity,
                initial_path: flow.initial_path,
            }),
            sender,
        )
        .await
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
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use volparossa_routing::{HELPER_PROTOCOL_VERSION, helper_request};

    fn issued() -> IssuedMptcpFlow {
        IssuedMptcpFlow {
            identity: MptcpFlowIdentity::fixture(),
            generation: 7,
            initial_path: 1,
        }
    }

    #[test]
    fn mptcp_flow_retirement_reuses_slots_not_capabilities_past_sixty_four() {
        let mut ledger = MptcpFlowLedger::default();
        let mut previous = std::collections::BTreeSet::new();
        // Intentionally repeated random bytes: the issuance counter alone guarantees no reissue.
        for _ in 0..256 {
            let handle = ledger.issue(issued(), [9; 32]).unwrap();
            assert!(previous.insert(handle));
            assert_eq!(ledger.get(&handle).unwrap().generation, 7);
            assert_eq!(ledger.len(), 1);
            ledger.remove(&handle);
            assert!(ledger.get(&handle).is_none());
            assert_eq!(ledger.len(), 0);
        }
        for _ in 0..MAX_MPTCP_FLOWS_PER_CONTEXT {
            assert!(ledger.issue(issued(), [9; 32]).is_some());
        }
        let sequence = ledger.sequence;
        assert!(ledger.issue(issued(), [9; 32]).is_none());
        assert_eq!(ledger.sequence, sequence);
        let retired = *ledger.flows.keys().next().unwrap();
        ledger.remove(&retired);
        let replacement = ledger.issue(issued(), [9; 32]).unwrap();
        assert_ne!(replacement, retired);
        assert!(ledger.get(&retired).is_none());
        assert_eq!(ledger.len(), MAX_MPTCP_FLOWS_PER_CONTEXT);
        ledger.flows.clear();
        ledger.sequence = u64::MAX;
        assert!(ledger.issue(issued(), [9; 32]).is_none());
        assert_eq!(ledger.sequence, u64::MAX);
    }

    fn committed_context() -> ContextRecord {
        ContextRecord {
            generation: 7,
            backend_generation: 1,
            handle: [3; 32],
            helper_runtime_id: [1; 32],
            prepare_request_id: [1; 16],
            prepare_operation_digest: [2; 32],
            setup_expires_at_unix: u64::MAX,
            hard_expires_at_unix: u64::MAX,
            setup_expires_at_boottime_ns: u64::MAX,
            hard_expires_at_boottime_ns: u64::MAX,
            phase: ContextPhase::Committed,
            activated_at_unix: Some(90),
            leases: BTreeMap::new(),
            extensions: BTreeMap::new(),
            mptcp_flows: MptcpFlowLedger::default(),
        }
    }

    #[test]
    fn terminal_flow_absence_never_bypasses_context_capability_phase_or_generation() {
        let mut context = committed_context();
        let handle = context.mptcp_flows.issue(issued(), [9; 32]).unwrap();
        let request = RetireMptcpFlow {
            route_context_id: vec![1; 16],
            context_handle: vec![3; 32],
            mptcp_flow_handle: handle.to_vec(),
        };
        assert!(retirement_flow(&context, &request).is_ok());
        let mut wrong = request.clone();
        wrong.context_handle[0] ^= 1;
        assert!(matches!(
            retirement_flow(&context, &wrong),
            Err(HelperResult::InvalidRequest)
        ));
        context.generation += 1;
        assert!(matches!(
            retirement_flow(&context, &request),
            Err(HelperResult::InvalidRequest)
        ));
        context.generation -= 1;
        context.mptcp_flows.remove(&handle);
        assert!(matches!(
            retirement_flow(&context, &request),
            Err(HelperResult::NotFound)
        ));
        assert!(matches!(
            retirement_flow(&context, &wrong),
            Err(HelperResult::InvalidRequest)
        ));
        context.phase = ContextPhase::Prepared;
        assert!(matches!(
            retirement_flow(&context, &request),
            Err(HelperResult::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn mptcp_flow_retirement_absent_context_requires_fd_but_never_inspects_it() {
        let engine = HelperEngine::new([1; 32], 1000);
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            operation: Some(helper_request::Operation::RetireMptcpFlow(
                RetireMptcpFlow {
                    route_context_id: vec![2; 16],
                    context_handle: vec![3; 32],
                    mptcp_flow_handle: vec![4; 32],
                },
            )),
        };
        assert_eq!(
            engine.execute(request.clone()).await.result,
            HelperResult::InvalidRequest as i32
        );
        let (socket, peer) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = socket.try_clone().unwrap().into();
        assert!(
            MptcpFlowIdentity::fixture()
                .verify_for_retirement(&descriptor)
                .is_err()
        );
        let result = engine
            .execute_with_input_descriptor(request, Some(descriptor))
            .await;
        assert_eq!(result.response.result, HelperResult::NotFound as i32);
        assert_eq!(result.response.diagnostic_code, "CONTEXT_ABSENT");
        assert!(result.response.outcome.is_none() && result.descriptor.is_none());
        assert!(engine.inner.state.lock().await.contexts.is_empty());
        assert_unix_stream_untouched(&socket, &peer);
    }

    fn assert_unix_stream_untouched(mut socket: &UnixStream, mut peer: &UnixStream) {
        let deadline = Some(std::time::Duration::from_secs(1));
        socket.set_read_timeout(deadline).unwrap();
        peer.set_read_timeout(deadline).unwrap();
        peer.write_all(b"a").unwrap();
        let mut received = [0];
        socket.read_exact(&mut received).unwrap();
        assert_eq!(received, *b"a");
        socket.write_all(b"b").unwrap();
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, *b"b");
    }

    #[tokio::test]
    async fn retired_flow_retry_after_ack_eviction_is_absence_without_fd_or_other_flow_mutation() {
        let engine = HelperEngine::new([1; 32], 1000);
        let mut context = committed_context();
        let retired = context.mptcp_flows.issue(issued(), [9; 32]).unwrap();
        let live = context.mptcp_flows.issue(issued(), [9; 32]).unwrap();
        let sequence = context.mptcp_flows.sequence;
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            operation: Some(helper_request::Operation::RetireMptcpFlow(
                RetireMptcpFlow {
                    route_context_id: vec![2; 16],
                    context_handle: vec![3; 32],
                    mptcp_flow_handle: retired.to_vec(),
                },
            )),
        };
        // Construct only the settled ledger/cache postcondition. This is not a successful
        // kernel retirement or MPTCP datapath proof; Unix sockets reject real flow verification.
        context.mptcp_flows.remove(&retired);
        engine
            .inner
            .state
            .lock()
            .await
            .contexts
            .insert([2; 16], context);
        engine
            .cache_execution(
                &request,
                &execution(
                    response(&request, HelperResult::Ok, "FIXTURE_ACK", None),
                    None,
                ),
                true,
            )
            .await;
        {
            let mut state = engine.inner.state.lock().await;
            assert!(state.cache.remove(&[1; 16]).is_some());
            state.cache_order.retain(|id| id != &[1; 16]);
        }
        let (socket, peer) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = socket.try_clone().unwrap().into();
        assert!(
            issued()
                .identity
                .verify_for_retirement(&descriptor)
                .is_err()
        );
        let result = engine
            .execute_with_input_descriptor(request, Some(descriptor))
            .await;
        assert_eq!(result.response.result, HelperResult::NotFound as i32);
        assert_eq!(
            result.response.diagnostic_code,
            "MPTCP_FLOW_CAPABILITY_ABSENT"
        );
        assert!(result.response.outcome.is_none() && result.descriptor.is_none());
        assert_unix_stream_untouched(&socket, &peer);
        let state = engine.inner.state.lock().await;
        assert_eq!(state.next_operation, 0);
        assert!(state.in_flight.is_none() && state.cleanup_pending.is_empty());
        let context = state.contexts.get(&[2; 16]).unwrap();
        assert_eq!(context.mptcp_flows.sequence, sequence);
        assert_eq!(context.mptcp_flows.len(), 1);
        assert!(!context.mptcp_flows.contains_key(&retired));
        assert_eq!(
            context.mptcp_flows.get(&live).unwrap().identity,
            issued().identity
        );
        assert_eq!(context.mptcp_flows.get(&live).unwrap().generation, 7);
    }

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
        let (descriptor, _peer) = UnixStream::pair().unwrap();
        let result = engine
            .execute_with_input_descriptor(request, Some(descriptor.into()))
            .await;
        assert_eq!(result.response.result, HelperResult::InvalidRequest as i32);
        assert!(result.descriptor.is_none());
        assert!(engine.inner.state.lock().await.contexts.is_empty());
    }
}
