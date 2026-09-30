//! Authenticated parent/worker additive path transaction.
use super::{
    ActivateLeases, DestroyContext, INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION,
    InternalProtocolError, InternalWorkerRequest, Message, PrepareLeases, ProbeCommitLeases,
    internal_worker_request, internal_worker_response, response_matches_operation, route_id,
    validate_request,
};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct PathExtension {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) extension_id: Vec<u8>,
    #[prost(oneof = "Action", tags = "2, 3, 4, 5, 6")]
    pub(crate) action: Option<Action>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum Action {
    #[prost(message, tag = "2")]
    Stage(PrepareLeases),
    #[prost(message, tag = "3")]
    Prepare(PrepareLeases),
    #[prost(message, tag = "4")]
    Activate(ActivateLeases),
    #[prost(message, tag = "5")]
    Commit(ProbeCommitLeases),
    #[prost(message, tag = "6")]
    Abort(DestroyContext),
}

impl PathExtension {
    pub(crate) fn context_id(&self) -> Result<&[u8], InternalProtocolError> {
        match self.action.as_ref().ok_or(InternalProtocolError::Invalid)? {
            Action::Stage(value) | Action::Prepare(value) => Ok(&value.route_context_id),
            Action::Activate(value) => Ok(&value.route_context_id),
            Action::Commit(value) => Ok(&value.route_context_id),
            Action::Abort(value) => Ok(&value.route_context_id),
        }
    }
}

pub(super) fn validate(value: &PathExtension) -> Result<(), InternalProtocolError> {
    route_id(&value.extension_id)?;
    let operation = match value
        .action
        .as_ref()
        .ok_or(InternalProtocolError::Invalid)?
    {
        Action::Stage(value) | Action::Prepare(value) if value.leases.len() == 1 => {
            internal_worker_request::Operation::PrepareLeases(value.clone())
        }
        Action::Activate(value) if value.leases.len() == 1 => {
            internal_worker_request::Operation::ActivateLeases(value.clone())
        }
        Action::Commit(value) if value.leases.len() == 1 => {
            internal_worker_request::Operation::ProbeCommitLeases(value.clone())
        }
        Action::Abort(value) => internal_worker_request::Operation::DestroyContext(value.clone()),
        _ => return Err(InternalProtocolError::Invalid),
    };
    validate_request(&InternalWorkerRequest {
        protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
        magic: INTERNAL_WORKER_MAGIC.to_vec(),
        request_id: value.extension_id.clone(),
        operation: Some(operation),
    })
}

pub(super) fn matches(value: &PathExtension, outcome: &internal_worker_response::Outcome) -> bool {
    use internal_worker_request::Operation;
    use internal_worker_response::Outcome;
    match value.action.as_ref() {
        Some(Action::Stage(value)) => {
            matches!(outcome, Outcome::Initialised(response) if response.route_context_id == value.route_context_id)
        }
        Some(Action::Abort(_)) => matches!(outcome, Outcome::Destroyed(_)),
        Some(Action::Prepare(value)) => {
            response_matches_operation(&Operation::PrepareLeases(value.clone()), outcome)
        }
        Some(Action::Activate(value)) => {
            response_matches_operation(&Operation::ActivateLeases(value.clone()), outcome)
        }
        Some(Action::Commit(value)) => {
            response_matches_operation(&Operation::ProbeCommitLeases(value.clone()), outcome)
        }
        None => false,
    }
}
