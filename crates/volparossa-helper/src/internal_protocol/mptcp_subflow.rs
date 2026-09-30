//! Parent-derived flow selectors, never accepted directly from agent wire input.

use prost::Message;

use super::{InternalProtocolError, path, route_id};

/// Parent-authenticated socket has already been shut down. Forget only its exact PM ownership.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct RetireMptcpFlow {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) flow_handle: Vec<u8>,
    #[prost(fixed32, tag = "3")]
    pub(crate) token: u32,
    #[prost(fixed64, tag = "4")]
    pub(crate) cookie: u64,
    #[prost(uint32, tag = "5")]
    pub(crate) primary_path_id: u32,
    #[prost(uint32, tag = "6")]
    pub(crate) remote_port: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MptcpFlowRetired {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) flow_handle: Vec<u8>,
}

impl RetireMptcpFlow {
    pub(super) fn validate(&self) -> Result<(), InternalProtocolError> {
        route_id(&self.route_context_id)?;
        path(self.primary_path_id)?;
        validate_flow_handle(&self.flow_handle)?;
        if self.cookie == 0 || !(1..=u32::from(u16::MAX)).contains(&self.remote_port) {
            return Err(InternalProtocolError::Invalid);
        }
        Ok(())
    }
}

pub(super) fn validate_flow_handle(handle: &[u8]) -> Result<(), InternalProtocolError> {
    if handle.len() != 32 || handle.iter().all(|byte| *byte == 0) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum Action {
    Unspecified = 0,
    Ensure = 1,
    Retire = 2,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct UpdateMptcpSubflow {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) flow_handle: Vec<u8>,
    #[prost(fixed32, tag = "3")]
    pub(crate) token: u32,
    #[prost(fixed64, tag = "4")]
    pub(crate) cookie: u64,
    #[prost(uint32, tag = "5")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "Action", tag = "6")]
    pub(crate) action: i32,
    #[prost(uint32, tag = "7")]
    pub(crate) primary_path_id: u32,
    #[prost(uint32, tag = "8")]
    pub(crate) remote_port: u32,
    /// Zero means a complete same-FD kernel snapshot observed no subflow on this path.
    #[prost(uint32, tag = "9")]
    pub(crate) observed_local_port: u32,
}

impl UpdateMptcpSubflow {
    pub(super) fn validate(&self) -> Result<(), InternalProtocolError> {
        route_id(&self.route_context_id)?;
        path(self.path_id)?;
        path(self.primary_path_id)?;
        if self.flow_handle.len() != 32
            || self.flow_handle.iter().all(|b| *b == 0)
            || self.cookie == 0
            || self.remote_port == 0
            || self.remote_port > u32::from(u16::MAX)
            || self.observed_local_port > u32::from(u16::MAX)
            || !matches!(
                Action::try_from(self.action),
                Ok(Action::Ensure | Action::Retire)
            )
            || (self.action == Action::Retire as i32 && self.path_id == self.primary_path_id)
        {
            return Err(InternalProtocolError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_protocol::{
        INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION, InternalWorkerRequest,
        decode_request, encode_request, internal_worker_request,
    };

    #[test]
    fn internal_terminal_flow_request_is_exact_and_canonical() {
        let operation = RetireMptcpFlow {
            route_context_id: vec![1; 16],
            flow_handle: vec![2; 32],
            token: 3,
            cookie: 4,
            primary_path_id: 1,
            remote_port: 44443,
        };
        let request = InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![5; 16],
            operation: Some(internal_worker_request::Operation::RetireMptcpFlow(
                operation.clone(),
            )),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        for changed in [
            RetireMptcpFlow {
                route_context_id: vec![0; 16],
                ..operation.clone()
            },
            RetireMptcpFlow {
                flow_handle: vec![0; 32],
                ..operation.clone()
            },
            RetireMptcpFlow {
                cookie: 0,
                ..operation.clone()
            },
            RetireMptcpFlow {
                primary_path_id: 0,
                ..operation.clone()
            },
            RetireMptcpFlow {
                remote_port: 65536,
                ..operation
            },
        ] {
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn internal_subflow_selector_is_canonical_bounded_and_cannot_retire_primary() {
        let operation = UpdateMptcpSubflow {
            route_context_id: vec![1; 16],
            flow_handle: vec![2; 32],
            cookie: 3,
            token: 4,
            path_id: 2,
            action: Action::Ensure as i32,
            primary_path_id: 1,
            remote_port: 44443,
            observed_local_port: 0,
        };
        let request = InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![5; 16],
            operation: Some(internal_worker_request::Operation::UpdateMptcpSubflow(
                operation.clone(),
            )),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
        for changed in [
            UpdateMptcpSubflow {
                flow_handle: vec![2; 31],
                ..operation.clone()
            },
            UpdateMptcpSubflow {
                cookie: 0,
                ..operation.clone()
            },
            UpdateMptcpSubflow {
                remote_port: 65536,
                ..operation.clone()
            },
            UpdateMptcpSubflow {
                observed_local_port: 65536,
                ..operation.clone()
            },
            UpdateMptcpSubflow {
                action: Action::Retire as i32,
                path_id: 1,
                ..operation.clone()
            },
        ] {
            assert!(changed.validate().is_err());
        }
    }
}
