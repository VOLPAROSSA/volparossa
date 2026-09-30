//! Issued-flow, transient-FD-bound userspace PM dispatch into the exact committed worker.

use super::*;
use crate::{
    engine::{BackendMptcpFlowRetirement, BackendMptcpSubflow},
    internal_protocol::mptcp_subflow::{Action, RetireMptcpFlow, UpdateMptcpSubflow},
};
use volparossa_linux_uapi::mptcp_subflow_info;
use volparossa_routing::MptcpSubflowAction;

const STAGE_UPDATE_MPTCP_SUBFLOW: u8 = 22;
const STAGE_RETIRE_MPTCP_FLOW: u8 = 23;

impl FunctionalAlphaLeaseBackend {
    pub(super) async fn retire_mptcp_flow_one(
        &self,
        binding: BackendBinding,
        request: BackendMptcpFlowRetirement,
    ) -> Result<(), BackendError> {
        use socket2::SockRef;
        use std::{io::ErrorKind, net::Shutdown};
        use subtle::ConstantTimeEq;

        let operation = &request.operation;
        let (key, generation, role) = validate_mptcp_endpoint_binding(
            &self.state,
            binding,
            &operation.route_context_id,
            &operation.context_handle,
            request.initial_path,
            BackendAction::RetireMptcpFlow,
        )?;
        if role != ContextRole::Client {
            return Err(BackendError::Invalid);
        }
        request
            .flow
            .verify_for_retirement(&request.descriptor)
            .map_err(|_| BackendError::Invalid)?;
        let primary = overlay_addresses(
            key.context_id,
            u8::try_from(request.initial_path).map_err(|_| BackendError::Invalid)?,
        )
        .map_err(|_| BackendError::Invalid)?;
        if request.flow.local.ip() != IpAddr::V6(primary.client)
            || request.flow.remote.ip() != IpAddr::V6(primary.exit)
        {
            return Err(BackendError::Invalid);
        }
        let deadline = prepare_deadline(binding)?;
        // Releasing a capability cannot create room while another duplicate can still perform
        // application I/O. SHUT_RDWR affects the exact original socket and every duplicate.
        if let Err(error) = SockRef::from(&request.descriptor).shutdown(Shutdown::Both) {
            if error.kind() != ErrorKind::NotConnected {
                return Err(BackendError::CleanupIncomplete);
            }
        }
        // Every failure after shutdown is mutating/ambiguous, so retain rollback authority.
        let command = worker_request(
            worker_attempt_request_id(key, STAGE_RETIRE_MPTCP_FLOW, binding),
            internal_worker_request::Operation::RetireMptcpFlow(RetireMptcpFlow {
                route_context_id: key.context_id.to_vec(),
                flow_handle: operation.mptcp_flow_handle.clone(),
                token: request.flow.token,
                cookie: request.flow.cookie,
                primary_path_id: request.initial_path,
                remote_port: u32::from(request.flow.remote.port()),
            }),
        );
        let execution = self
            .coordinator
            .execute_until(
                key.context_id,
                generation,
                command,
                worker_operation_deadline(deadline).map_err(|_| BackendError::CleanupIncomplete)?,
            )
            .await
            .map_err(|_| BackendError::CleanupIncomplete)?;
        let exact = execution.response.result == InternalWorkerResult::Ok as i32
            && execution.descriptor.is_none()
            && matches!(execution.response.outcome.as_ref(),
                Some(internal_worker_response::Outcome::MptcpFlowRetired(value))
                    if value.flow_handle.ct_eq(&operation.mptcp_flow_handle).unwrap_u8() == 1);
        if !exact {
            return Err(BackendError::CleanupIncomplete);
        }
        request
            .flow
            .verify_for_retirement(&request.descriptor)
            .map_err(|_| BackendError::CleanupIncomplete)?;
        validate_mptcp_endpoint_binding(
            &self.state,
            binding,
            &operation.route_context_id,
            &operation.context_handle,
            request.initial_path,
            BackendAction::RetireMptcpFlow,
        )
        .map_err(|_| BackendError::CleanupIncomplete)?;
        deadline
            .complete(())
            .map_err(|_| BackendError::CleanupIncomplete)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep the affine actual-FD lifetime, kernel mutation and post-mutation revalidation in one operation."
    )]
    pub(super) async fn update_mptcp_subflow_one(
        &self,
        binding: BackendBinding,
        request: BackendMptcpSubflow,
    ) -> Result<(), BackendError> {
        let operation = &request.operation;
        let (key, generation, role) = validate_mptcp_endpoint_binding(
            &self.state,
            binding,
            &operation.route_context_id,
            &operation.context_handle,
            operation.path_id,
            BackendAction::UpdateMptcpSubflow,
        )?;
        if role != ContextRole::Client || request.initial_path == operation.path_id {
            return Err(BackendError::Invalid);
        }
        validate_mptcp_endpoint_binding(
            &self.state,
            binding,
            &operation.route_context_id,
            &operation.context_handle,
            request.initial_path,
            BackendAction::UpdateMptcpSubflow,
        )?;
        request
            .flow
            .verify(&request.descriptor)
            .map_err(|_| BackendError::Invalid)?;
        let primary = overlay_addresses(
            key.context_id,
            u8::try_from(request.initial_path).map_err(|_| BackendError::Invalid)?,
        )
        .map_err(|_| BackendError::Invalid)?;
        if request.flow.local.ip() != IpAddr::V6(primary.client)
            || request.flow.remote.ip() != IpAddr::V6(primary.exit)
        {
            return Err(BackendError::Invalid);
        }
        let action = match MptcpSubflowAction::try_from(operation.action) {
            Ok(MptcpSubflowAction::Ensure) => Action::Ensure,
            Ok(MptcpSubflowAction::Retire) => Action::Retire,
            _ => return Err(BackendError::Invalid),
        };
        let observations =
            mptcp_subflow_info(&request.descriptor, 8).map_err(|_| BackendError::Invalid)?;
        let local_port = observed_port(
            key.context_id,
            operation.path_id,
            request.flow.remote.port(),
            &observations,
        )?;
        let deadline = prepare_deadline(binding)?;
        let command = worker_request(
            worker_attempt_request_id(key, STAGE_UPDATE_MPTCP_SUBFLOW, binding),
            internal_worker_request::Operation::UpdateMptcpSubflow(UpdateMptcpSubflow {
                route_context_id: key.context_id.to_vec(),
                flow_handle: operation.mptcp_flow_handle.clone(),
                token: request.flow.token,
                cookie: request.flow.cookie,
                path_id: operation.path_id,
                action: action as i32,
                primary_path_id: request.initial_path,
                remote_port: u32::from(request.flow.remote.port()),
                observed_local_port: u32::from(local_port),
            }),
        );
        let execution = self
            .coordinator
            .execute_until(
                key.context_id,
                generation,
                command,
                worker_operation_deadline(deadline)?,
            )
            .await
            .map_err(|_| BackendError::CleanupIncomplete)?;
        let exact = execution.response.result == InternalWorkerResult::Ok as i32
            && execution.descriptor.is_none()
            && match (action, execution.response.outcome.as_ref()) {
                (
                    Action::Ensure,
                    Some(internal_worker_response::Outcome::MptcpEndpointAdded(value)),
                ) => value.path_id == operation.path_id,
                (
                    Action::Retire,
                    Some(internal_worker_response::Outcome::MptcpEndpointRemoved(value)),
                ) => value.path_id == operation.path_id,
                _ => false,
            };
        if !exact {
            return Err(response_error(Ok(execution)));
        }
        // Retain the transient actual meta FD through the full worker mutation and revalidation.
        // Closing this command duplicate never closes the application's independently owned FD.
        request
            .flow
            .verify(&request.descriptor)
            .map_err(|_| BackendError::CleanupIncomplete)?;
        validate_mptcp_endpoint_binding(
            &self.state,
            binding,
            &operation.route_context_id,
            &operation.context_handle,
            operation.path_id,
            BackendAction::UpdateMptcpSubflow,
        )?;
        deadline
            .complete(())
            .map_err(|_| BackendError::CleanupIncomplete)
    }
}

fn observed_port(
    context: [u8; 16],
    path: u32,
    remote_port: u16,
    observations: &[volparossa_linux_uapi::MptcpSubflowInfo],
) -> Result<u16, BackendError> {
    let addresses = overlay_addresses(
        context,
        u8::try_from(path).map_err(|_| BackendError::Invalid)?,
    )
    .map_err(|_| BackendError::Invalid)?;
    let mut found = None;
    for observation in observations {
        if observation.local.ip() != IpAddr::V6(addresses.client)
            && observation.remote.ip() != IpAddr::V6(addresses.exit)
        {
            continue;
        }
        if observation.local.ip() != IpAddr::V6(addresses.client)
            || observation.remote != SocketAddr::new(addresses.exit.into(), remote_port)
            || observation.local.port() == 0
            || found.replace(observation.local.port()).is_some()
        {
            return Err(BackendError::Invalid);
        }
    }
    Ok(found.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_linux_uapi::MptcpSubflowInfo;

    #[test]
    fn subflow_mutation_uses_only_exact_derived_path_and_complete_unique_tuple() {
        let context = [31; 16];
        let address = overlay_addresses(context, 3).unwrap();
        let mut row = MptcpSubflowInfo {
            subflow_id: 3,
            local: SocketAddr::new(address.client.into(), 49123),
            remote: SocketAddr::new(address.exit.into(), 44443),
            tcp_state: 1,
            bytes_acked: 100,
            bytes_received: 100,
            lost_packets: 0,
            total_retransmissions: 0,
            data_segments_sent: 1,
            smoothed_rtt_us: 100,
        };
        assert_eq!(observed_port(context, 3, 44443, &[row]), Ok(49123));
        assert_eq!(observed_port(context, 4, 44443, &[row]), Ok(0));
        assert!(observed_port(context, 3, 44443, &[row, row]).is_err());
        row.remote.set_port(44444);
        assert!(observed_port(context, 3, 44443, &[row]).is_err());
        row.remote = SocketAddr::new(overlay_addresses(context, 4).unwrap().exit.into(), 44443);
        assert!(observed_port(context, 3, 44443, &[row]).is_err());
    }
}
