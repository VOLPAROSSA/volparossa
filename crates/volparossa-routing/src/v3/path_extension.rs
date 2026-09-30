//! Additive authority for one new path in an already committed Client/Exit context.

use prost::Message;

use super::{
    ActivateLeaseBatch, ActivatedLeaseBatch, CommitLeaseBatch, CommittedLease, CommittedLeaseBatch,
    HelperProtocolError, HelperRequest, LeaseActivation, LeaseCommit, LeasePlan, PreparedLease,
    PreparedLeaseBatch, TraversalEndpointHint, WireguardRole, bound_context, context,
    helper_request, helper_response, validate_outcome, validate_request, validate_traversal_hints,
};

/// Prepare exactly one new lease without replacing the original context authority.
#[derive(Clone, PartialEq, Message)]
pub struct PreparePathExtension {
    /// Existing committed route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original helper-issued context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Fresh nonzero 16-byte extension identity.
    #[prost(bytes = "vec", tag = "3")]
    pub extension_id: Vec<u8>,
    /// One previously unused Client or Exit path identity.
    #[prost(message, optional, tag = "4")]
    pub lease: Option<LeasePlan>,
    /// Fresh setup deadline, bounded by 30 seconds and the original hard deadline.
    #[prost(uint64, tag = "5")]
    pub setup_expires_at_unix: u64,
    /// Exact-peer observations subject to the ordinary underlay validation.
    #[prost(message, repeated, tag = "6")]
    pub traversal_hints: Vec<TraversalEndpointHint>,
}

/// Activate only the new extension lease with its independently signed authority.
#[derive(Clone, PartialEq, Message)]
pub struct ActivatePathExtension {
    /// Existing context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact prepared extension identity.
    #[prost(bytes = "vec", tag = "3")]
    pub extension_id: Vec<u8>,
    /// Exact new lease, never an existing lease replacement.
    #[prost(message, optional, tag = "4")]
    pub lease: Option<LeaseActivation>,
    /// Exact original Exit-signed additive authorization; never an initial-route transcript.
    #[prost(bytes = "vec", tag = "5")]
    pub signed_route_extension: Vec<u8>,
}

/// Prove the new lease before admitting its endpoint into the established context.
#[derive(Clone, PartialEq, Message)]
pub struct CommitPathExtension {
    /// Existing context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact activated extension identity.
    #[prost(bytes = "vec", tag = "3")]
    pub extension_id: Vec<u8>,
    /// Exact extension lease capability.
    #[prost(message, optional, tag = "4")]
    pub lease: Option<LeaseCommit>,
}

/// Remove only the named extension's resources, never the original context.
#[derive(Clone, PartialEq, Message)]
pub struct AbortPathExtension {
    /// Existing context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Original context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact extension identity; replay does not create a new extension.
    #[prost(bytes = "vec", tag = "3")]
    pub extension_id: Vec<u8>,
}

/// One prepared extension, retaining the original context handle and hard expiry.
#[derive(Clone, PartialEq, Message)]
pub struct PreparedPathExtension {
    /// Original context capability.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Exact requested extension.
    #[prost(bytes = "vec", tag = "2")]
    pub extension_id: Vec<u8>,
    /// One lease and the unchanged original context authority.
    #[prost(message, optional, tag = "3")]
    pub lease: Option<PreparedLease>,
}

/// One activated extension, not proof that its transport endpoint is yet admitted.
#[derive(Clone, PartialEq, Message)]
pub struct ActivatedPathExtension {
    /// Original context capability.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Exact requested extension.
    #[prost(bytes = "vec", tag = "2")]
    pub extension_id: Vec<u8>,
    /// The single new activated lease.
    #[prost(bytes = "vec", tag = "3")]
    pub lease_handle: Vec<u8>,
}

/// Kernel-proven new lease; adding an MPTCP endpoint remains a separate operation.
#[derive(Clone, PartialEq, Message)]
pub struct CommittedPathExtension {
    /// Original context capability.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Exact requested extension.
    #[prost(bytes = "vec", tag = "2")]
    pub extension_id: Vec<u8>,
    /// The single new committed lease.
    #[prost(message, optional, tag = "3")]
    pub lease: Option<CommittedLease>,
}

pub(super) fn validate_prepare(value: &PreparePathExtension) -> Result<(), HelperProtocolError> {
    bound_context(&value.route_context_id, &value.context_handle)?;
    context(&value.extension_id)?;
    let lease = value
        .lease
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("extension lease"))?;
    endpoint_role(lease.path_id, lease.role)?;
    if value.setup_expires_at_unix == 0 {
        return Err(HelperProtocolError::Invalid("extension setup deadline"));
    }
    validate_traversal_hints(std::slice::from_ref(lease), &value.traversal_hints)
}

pub(super) fn validate_activate(value: &ActivatePathExtension) -> Result<(), HelperProtocolError> {
    context(&value.extension_id)?;
    if value.signed_route_extension.is_empty()
        || value.signed_route_extension.len() > super::MAX_HELPER_FRAME
    {
        return Err(HelperProtocolError::Invalid("signed extension authority"));
    }
    let lease = value
        .lease
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("extension lease"))?;
    endpoint_role(lease.path_id, lease.role)?;
    validate_nested(helper_request::Operation::ActivateLeaseBatch(
        ActivateLeaseBatch {
            route_context_id: value.route_context_id.clone(),
            context_handle: value.context_handle.clone(),
            leases: vec![lease.clone()],
        },
    ))
}

pub(super) fn validate_commit(value: &CommitPathExtension) -> Result<(), HelperProtocolError> {
    context(&value.extension_id)?;
    let lease = value
        .lease
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("extension lease"))?;
    endpoint_role(lease.path_id, lease.role)?;
    validate_nested(helper_request::Operation::CommitLeaseBatch(
        CommitLeaseBatch {
            route_context_id: value.route_context_id.clone(),
            context_handle: value.context_handle.clone(),
            leases: vec![lease.clone()],
        },
    ))
}

pub(super) fn validate_abort(value: &AbortPathExtension) -> Result<(), HelperProtocolError> {
    bound_context(&value.route_context_id, &value.context_handle)?;
    context(&value.extension_id)
}

fn validate_nested(operation: helper_request::Operation) -> Result<(), HelperProtocolError> {
    validate_request(&HelperRequest {
        protocol_version: super::HELPER_PROTOCOL_VERSION,
        request_id: vec![1; 16],
        operation: Some(operation),
    })
}

fn endpoint_role(path_id: u32, role: i32) -> Result<(), HelperProtocolError> {
    super::path(path_id)?;
    if !matches!(
        WireguardRole::try_from(role),
        Ok(WireguardRole::Client | WireguardRole::Exit)
    ) {
        return Err(HelperProtocolError::Invalid("extension endpoint role"));
    }
    Ok(())
}

pub(super) fn validate_prepared(value: &PreparedPathExtension) -> Result<(), HelperProtocolError> {
    context(&value.extension_id)?;
    let lease = value
        .lease
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("extension prepared"))?;
    endpoint_role(lease.path_id, lease.role)?;
    validate_outcome(&helper_response::Outcome::PreparedLeaseBatch(
        PreparedLeaseBatch {
            context_handle: value.context_handle.clone(),
            leases: vec![lease.clone()],
        },
    ))
}

pub(super) fn validate_activated(
    value: &ActivatedPathExtension,
) -> Result<(), HelperProtocolError> {
    context(&value.extension_id)?;
    validate_outcome(&helper_response::Outcome::ActivatedLeaseBatch(
        ActivatedLeaseBatch {
            context_handle: value.context_handle.clone(),
            lease_handles: vec![value.lease_handle.clone()],
        },
    ))
}

pub(super) fn validate_committed(
    value: &CommittedPathExtension,
) -> Result<(), HelperProtocolError> {
    context(&value.extension_id)?;
    let lease = value
        .lease
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("extension committed"))?;
    validate_outcome(&helper_response::Outcome::CommittedLeaseBatch(
        CommittedLeaseBatch {
            context_handle: value.context_handle.clone(),
            leases: vec![lease.clone()],
        },
    ))
}
