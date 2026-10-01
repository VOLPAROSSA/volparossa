//! A live Client meta socket authorizes only helper-derived selected-path subflows.

use prost::Message;

use super::{
    HelperProtocolError, HelperRequest, MAX_HELPER_PATHS, bound_context, handle, helper_request,
    validate_request,
};

/// One bounded operation; addresses, ports and kernel tokens are never caller-selected.
#[derive(Clone, PartialEq, Message)]
pub struct UpdateMptcpSubflow {
    /// Exact committed route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original helper-issued context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Issued alongside the original Client meta descriptor.
    #[prost(bytes = "vec", tag = "3")]
    pub mptcp_flow_handle: Vec<u8>,
    /// An already committed Client path in this same context.
    #[prost(uint32, tag = "4")]
    pub path_id: u32,
    /// Ensure or retire only this exact derived subflow.
    #[prost(enumeration = "MptcpSubflowAction", tag = "5")]
    pub action: i32,
}

/// Terminal release of one issued Client meta socket, not a route or path retirement.
/// The helper verifies the accompanying descriptor and shuts down that exact socket before
/// reclaiming its flow slot. Keeping another duplicate cannot bypass the live-flow bound.
#[derive(Clone, PartialEq, Message)]
pub struct RetireMptcpFlow {
    /// Exact route context that issued the flow.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original helper-issued context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact original flow capability; never a caller-supplied kernel token.
    #[prost(bytes = "vec", tag = "3")]
    pub mptcp_flow_handle: Vec<u8>,
}

pub(super) fn validate_retire(value: &RetireMptcpFlow) -> Result<(), HelperProtocolError> {
    bound_context(&value.route_context_id, &value.context_handle)?;
    handle(&value.mptcp_flow_handle)
}

/// Closed actions for the Client userspace path manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum MptcpSubflowAction {
    /// Invalid default.
    Unspecified = 0,
    /// Request a subflow using one exact selected path.
    Ensure = 1,
    /// Remove the exact previously requested non-primary subflow.
    Retire = 2,
}

pub(super) fn validate(value: &UpdateMptcpSubflow) -> Result<(), HelperProtocolError> {
    bound_context(&value.route_context_id, &value.context_handle)?;
    handle(&value.mptcp_flow_handle)?;
    if !(1..=MAX_HELPER_PATHS).contains(&value.path_id)
        || !matches!(
            MptcpSubflowAction::try_from(value.action),
            Ok(MptcpSubflowAction::Ensure | MptcpSubflowAction::Retire)
        )
    {
        return Err(HelperProtocolError::Invalid("MPTCP subflow operation"));
    }
    Ok(())
}

/// Bind one request's transient descriptor to its complete canonical typed operation.
///
/// # Errors
///
/// Rejects malformed or descriptorless operation kinds. This hash must accompany
/// exactly one `SCM_RIGHTS` descriptor after the framed request; it is not authority alone.
pub fn request_descriptor_fd_binding(
    value: &HelperRequest,
) -> Result<[u8; 32], HelperProtocolError> {
    validate_request(value)?;
    if !matches!(
        value.operation.as_ref(),
        Some(
            helper_request::Operation::UpdateMptcpSubflow(_)
                | helper_request::Operation::RetireMptcpFlow(_)
        )
    ) {
        return Err(HelperProtocolError::Invalid("request descriptor operation"));
    }
    let canonical = value.encode_to_vec();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VOLPAROSSA helper request descriptor binding v3\0");
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HELPER_PROTOCOL_VERSION, decode_request, encode_request, safe_preview};

    #[test]
    fn terminal_mptcp_flow_request_binds_exact_capabilities_and_descriptor() {
        let original = HelperRequest {
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
            decode_request(&encode_request(&original).unwrap()[4..]).unwrap(),
            original
        );
        let binding = request_descriptor_fd_binding(&original).unwrap();
        for field in 0..4 {
            let mut changed = original.clone();
            let Some(helper_request::Operation::RetireMptcpFlow(value)) =
                changed.operation.as_mut()
            else {
                unreachable!()
            };
            match field {
                0 => changed.request_id[0] += 1,
                1 => value.route_context_id[0] += 1,
                2 => value.context_handle[0] += 1,
                _ => value.mptcp_flow_handle[0] += 1,
            }
            assert_ne!(request_descriptor_fd_binding(&changed).unwrap(), binding);
        }
        let mut bad = original.clone();
        let Some(helper_request::Operation::RetireMptcpFlow(value)) = bad.operation.as_mut() else {
            unreachable!()
        };
        value.mptcp_flow_handle.fill(0);
        assert!(encode_request(&bad).is_err());
        assert!(
            safe_preview(&original)
                .unwrap()
                .starts_with("retire one owned MPTCP flow;")
        );
    }

    fn request() -> HelperRequest {
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

    #[test]
    fn mptcp_subflow_request_is_bounded_and_descriptor_binding_is_exact() {
        let original = request();
        let encoded = encode_request(&original).unwrap();
        assert_eq!(decode_request(&encoded[4..]).unwrap(), original);
        let binding = request_descriptor_fd_binding(&original).unwrap();
        for mutation in 0..6 {
            let mut changed = original.clone();
            let Some(helper_request::Operation::UpdateMptcpSubflow(value)) =
                changed.operation.as_mut()
            else {
                unreachable!()
            };
            match mutation {
                0 => changed.request_id[0] += 1,
                1 => value.route_context_id[0] += 1,
                2 => value.context_handle[0] += 1,
                3 => value.mptcp_flow_handle[0] += 1,
                4 => value.path_id += 1,
                _ => value.action = MptcpSubflowAction::Retire as i32,
            }
            assert_ne!(request_descriptor_fd_binding(&changed).unwrap(), binding);
        }
        for mutation in 0..5 {
            let mut changed = original.clone();
            let Some(helper_request::Operation::UpdateMptcpSubflow(value)) =
                changed.operation.as_mut()
            else {
                unreachable!()
            };
            match mutation {
                0 => value.mptcp_flow_handle.clear(),
                1 => value.mptcp_flow_handle.fill(0),
                2 => value.path_id = 0,
                3 => value.path_id = 9,
                _ => value.action = 3,
            }
            assert!(encode_request(&changed).is_err());
        }
        assert!(
            safe_preview(&original)
                .unwrap()
                .starts_with("update one owned live MPTCP subflow;")
        );
    }
}
