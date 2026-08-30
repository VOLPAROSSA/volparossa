//! Private parent-to-worker protocol for helper v3.
//!
//! This wire format is deliberately independent from the authenticated agent protocol. It has
//! its own magic, version and typed operation set. Private `WireGuard` keys are never representable:
//! the namespace worker generates and retains them.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use prost::Message;
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const INTERNAL_WORKER_PROTOCOL_VERSION: u32 = 3;
pub(crate) const INTERNAL_WORKER_MAGIC: &[u8; 8] = b"VPWKR3\0\0";
pub(crate) const MAX_INTERNAL_WORKER_FRAME: usize = 128 * 1024;
const INTERNAL_WORKER_DEADLINE_ENVELOPE_VERSION: u32 = 1;
const INTERNAL_WORKER_DEADLINE_ENVELOPE_MAGIC: &[u8; 8] = b"VPDLN1\0\0";
const MAX_PATHS: u32 = 8;
const MAX_LEASES: usize = 16;
const MAX_PREFIXES: usize = 8;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InternalWorkerRequest {
    #[prost(uint32, tag = "1")]
    pub(crate) protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) magic: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) request_id: Vec<u8>,
    #[prost(
        oneof = "internal_worker_request::Operation",
        tags = "10, 11, 12, 13, 15, 16, 17, 19"
    )]
    pub(crate) operation: Option<internal_worker_request::Operation>,
}

/// One logical request bound to the parent's absolute Linux `CLOCK_MONOTONIC` deadline.
///
/// The deadline is transport authority rather than operation identity, so it deliberately wraps
/// the canonical request instead of changing its request digest or idempotent cache key.
#[derive(Clone, PartialEq, Message)]
struct DeadlineBoundInternalWorkerRequest {
    #[prost(uint32, tag = "1")]
    envelope_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    magic: Vec<u8>,
    #[prost(fixed64, tag = "3")]
    monotonic_deadline_ns: u64,
    #[prost(message, optional, tag = "4")]
    request: Option<InternalWorkerRequest>,
}

pub(crate) struct DeadlineBoundWorkerRequest {
    pub(crate) monotonic_deadline_ns: u64,
    pub(crate) request: InternalWorkerRequest,
}

pub(crate) mod internal_worker_request {
    use prost::Oneof;

    use super::{
        AcquireTransportSocket, ActivateLeases, AddMptcpEndpoint, DestroyContext,
        InitialiseContext, PrepareLeases, ProbeCommitLeases, RemoveMptcpEndpoint,
    };

    #[derive(Clone, PartialEq, Oneof)]
    pub(crate) enum Operation {
        #[prost(message, tag = "10")]
        Initialise(InitialiseContext),
        #[prost(message, tag = "11")]
        PrepareLeases(PrepareLeases),
        #[prost(message, tag = "12")]
        ActivateLeases(ActivateLeases),
        #[prost(message, tag = "13")]
        ProbeCommitLeases(ProbeCommitLeases),
        #[prost(message, tag = "15")]
        AddMptcpEndpoint(AddMptcpEndpoint),
        #[prost(message, tag = "16")]
        RemoveMptcpEndpoint(RemoveMptcpEndpoint),
        #[prost(message, tag = "17")]
        AcquireTransportSocket(AcquireTransportSocket),
        #[prost(message, tag = "19")]
        DestroyContext(DestroyContext),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum InternalContextRole {
    Unspecified = 0,
    Client = 1,
    Relay = 2,
    Exit = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum InternalEndpointRole {
    Unspecified = 0,
    Client = 1,
    RelayClient = 2,
    RelayExit = 3,
    Exit = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum InternalMptcpMode {
    Unspecified = 0,
    Signal = 1,
    Subflow = 2,
    SignalAndSubflow = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum InternalTransportSocketKind {
    Unspecified = 0,
    MptcpConnected = 1,
    MptcpListener = 2,
    QuicUdpUnconnected = 3,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InternalIpPrefix {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) prefix_length: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InternalUdpEndpoint {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) port: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InternalSocketAddress {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) port: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InitialiseContext {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(enumeration = "InternalContextRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(uint32, tag = "3")]
    pub(crate) mptcp_accepted_addrs: u32,
    #[prost(uint32, tag = "4")]
    pub(crate) mptcp_subflows: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct LeasePlan {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(message, optional, tag = "3")]
    pub(crate) local_overlay_address: Option<InternalIpPrefix>,
    #[prost(uint64, tag = "4")]
    pub(crate) setup_expires_at_unix: u64,
    #[prost(uint64, tag = "5")]
    pub(crate) hard_expires_at_unix: u64,
    /// Fixed public ownership marker produced from the durable record by the trusted parent.
    #[prost(string, tag = "6")]
    pub(crate) ownership_alias: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct PrepareLeases {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) leases: Vec<LeasePlan>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct LeaseActivation {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) peer_public_key: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub(crate) peer_endpoint: Option<InternalUdpEndpoint>,
    #[prost(message, repeated, tag = "5")]
    pub(crate) allowed_prefixes: Vec<InternalIpPrefix>,
    #[prost(uint32, tag = "6")]
    pub(crate) persistent_keepalive_seconds: u32,
    #[prost(uint32, tag = "7")]
    pub(crate) maximum_up_mbps: u32,
    #[prost(uint32, tag = "8")]
    pub(crate) maximum_down_mbps: u32,
    #[prost(uint64, tag = "9")]
    pub(crate) hard_expires_at_unix: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ActivateLeases {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) leases: Vec<LeaseActivation>,
    /// Parent-frozen Linux `CLOCK_BOOTTIME` hard expiry for this exact route context.
    #[prost(uint64, tag = "3")]
    pub(crate) hard_expires_at_boottime_ns: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct LeaseProbe {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) expected_peer_public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub(crate) not_before_unix: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProbeCommitLeases {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) leases: Vec<LeaseProbe>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct AddMptcpEndpoint {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalMptcpMode", tag = "3")]
    pub(crate) mode: i32,
    #[prost(bool, tag = "4")]
    pub(crate) backup: bool,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RemoveMptcpEndpoint {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) path_id: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct AcquireTransportSocket {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "3")]
    pub(crate) role: i32,
    #[prost(enumeration = "InternalTransportSocketKind", tag = "4")]
    pub(crate) descriptor_kind: i32,
    #[prost(message, optional, tag = "5")]
    pub(crate) expected_local: Option<InternalSocketAddress>,
    #[prost(message, optional, tag = "6")]
    pub(crate) expected_remote: Option<InternalSocketAddress>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DestroyContext {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum InternalWorkerResult {
    Unspecified = 0,
    Ok = 1,
    Invalid = 2,
    Conflict = 3,
    NotFound = 4,
    Kernel = 5,
    CleanupIncomplete = 6,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct InternalWorkerResponse {
    #[prost(uint32, tag = "1")]
    pub(crate) protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) magic: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) request_id: Vec<u8>,
    #[prost(enumeration = "InternalWorkerResult", tag = "4")]
    pub(crate) result: i32,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) request_digest: Vec<u8>,
    #[prost(
        oneof = "internal_worker_response::Outcome",
        tags = "10, 11, 12, 13, 15, 16, 17, 19"
    )]
    pub(crate) outcome: Option<internal_worker_response::Outcome>,
}

pub(crate) mod internal_worker_response {
    use prost::Oneof;

    use super::{
        ActivatedLeases, ContextDestroyed, ContextInitialised, MptcpEndpointAdded,
        MptcpEndpointRemoved, PreparedLeases, ProbedLeases, TransportSocketReady,
    };

    #[derive(Clone, PartialEq, Oneof)]
    pub(crate) enum Outcome {
        #[prost(message, tag = "10")]
        Initialised(ContextInitialised),
        #[prost(message, tag = "11")]
        Prepared(PreparedLeases),
        #[prost(message, tag = "12")]
        Activated(ActivatedLeases),
        #[prost(message, tag = "13")]
        ProbedCommitted(ProbedLeases),
        #[prost(message, tag = "15")]
        MptcpEndpointAdded(MptcpEndpointAdded),
        #[prost(message, tag = "16")]
        MptcpEndpointRemoved(MptcpEndpointRemoved),
        #[prost(message, tag = "17")]
        TransportSocketReady(TransportSocketReady),
        #[prost(message, tag = "19")]
        Destroyed(ContextDestroyed),
    }
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ContextInitialised {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) route_context_id: Vec<u8>,
}

/// A key and kernel-assigned port proven by the worker's correlated GET after binding.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct PreparedLease {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) public_key: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub(crate) listen_port: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct PreparedLeases {
    #[prost(message, repeated, tag = "1")]
    pub(crate) leases: Vec<PreparedLease>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ActivatedLease {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) public_key: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub(crate) listen_port: u32,
    /// Exact initial handshake seconds read from the configured kernel peer.
    #[prost(uint64, tag = "5")]
    pub(crate) latest_handshake_unix: u64,
    /// Exact initial handshake nanoseconds read from the configured kernel peer.
    #[prost(uint32, tag = "6")]
    pub(crate) latest_handshake_nanoseconds: u32,
    /// Exact initial received-byte counter read from the configured kernel peer.
    #[prost(uint64, tag = "7")]
    pub(crate) received_bytes: u64,
    /// Exact initial transmitted-byte counter read from the configured kernel peer.
    #[prost(uint64, tag = "8")]
    pub(crate) transmitted_bytes: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ActivatedLeases {
    #[prost(message, repeated, tag = "1")]
    pub(crate) leases: Vec<ActivatedLease>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProbedLease {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(uint64, tag = "3")]
    pub(crate) latest_handshake_unix: u64,
    #[prost(uint64, tag = "4")]
    pub(crate) received_bytes: u64,
    #[prost(uint64, tag = "5")]
    pub(crate) transmitted_bytes: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProbedLeases {
    #[prost(message, repeated, tag = "1")]
    pub(crate) leases: Vec<ProbedLease>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MptcpEndpointAdded {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MptcpEndpointRemoved {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TransportSocketReady {
    #[prost(uint32, tag = "1")]
    pub(crate) path_id: u32,
    #[prost(enumeration = "InternalEndpointRole", tag = "2")]
    pub(crate) role: i32,
    #[prost(enumeration = "InternalTransportSocketKind", tag = "3")]
    pub(crate) descriptor_kind: i32,
    #[prost(message, optional, tag = "4")]
    pub(crate) local: Option<InternalSocketAddress>,
    #[prost(message, optional, tag = "5")]
    pub(crate) remote: Option<InternalSocketAddress>,
}

fn response_matches_operation(
    operation: &internal_worker_request::Operation,
    outcome: &internal_worker_response::Outcome,
) -> bool {
    use internal_worker_request::Operation;
    use internal_worker_response::Outcome;

    match (operation, outcome) {
        (Operation::Initialise(request), Outcome::Initialised(response)) => {
            request.route_context_id == response.route_context_id
        }
        (Operation::PrepareLeases(request), Outcome::Prepared(response)) => request
            .leases
            .iter()
            .map(|lease| (lease.path_id, lease.role))
            .eq(response
                .leases
                .iter()
                .map(|lease| (lease.path_id, lease.role))),
        (Operation::ActivateLeases(request), Outcome::Activated(response)) => request
            .leases
            .iter()
            .map(|lease| (lease.path_id, lease.role))
            .eq(response
                .leases
                .iter()
                .map(|lease| (lease.path_id, lease.role))),
        (Operation::ProbeCommitLeases(request), Outcome::ProbedCommitted(response)) => request
            .leases
            .iter()
            .map(|lease| (lease.path_id, lease.role))
            .eq(response
                .leases
                .iter()
                .map(|lease| (lease.path_id, lease.role))),
        (Operation::AddMptcpEndpoint(request), Outcome::MptcpEndpointAdded(response)) => {
            request.path_id == response.path_id
        }
        (Operation::RemoveMptcpEndpoint(request), Outcome::MptcpEndpointRemoved(response)) => {
            request.path_id == response.path_id
        }
        (Operation::DestroyContext(_), Outcome::Destroyed(_)) => true,
        (Operation::AcquireTransportSocket(request), Outcome::TransportSocketReady(response)) => {
            request.path_id == response.path_id
                && request.role == response.role
                && request.descriptor_kind == response.descriptor_kind
                && request.expected_local == response.local
                && request.expected_remote == response.remote
        }
        _ => false,
    }
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ContextDestroyed {}

#[derive(Debug, Error)]
pub(crate) enum InternalProtocolError {
    #[error("malformed internal worker protobuf")]
    Decode(#[from] prost::DecodeError),
    #[error("internal worker frame exceeds the fixed bound")]
    TooLarge,
    #[error("invalid internal worker message")]
    Invalid,
}

pub(crate) fn encode_request(
    value: &InternalWorkerRequest,
) -> Result<Zeroizing<Vec<u8>>, InternalProtocolError> {
    validate_request(value)?;
    encode(value)
}

pub(crate) fn encode_deadline_bound_request(
    request: &InternalWorkerRequest,
    monotonic_deadline_ns: u64,
) -> Result<Zeroizing<Vec<u8>>, InternalProtocolError> {
    let value = DeadlineBoundInternalWorkerRequest {
        envelope_version: INTERNAL_WORKER_DEADLINE_ENVELOPE_VERSION,
        magic: INTERNAL_WORKER_DEADLINE_ENVELOPE_MAGIC.to_vec(),
        monotonic_deadline_ns,
        request: Some(request.clone()),
    };
    validate_deadline_bound_request(&value)?;
    encode(&value)
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<InternalWorkerRequest, InternalProtocolError> {
    decode(bytes, validate_request)
}

pub(crate) fn decode_deadline_bound_request(
    bytes: &[u8],
) -> Result<DeadlineBoundWorkerRequest, InternalProtocolError> {
    let value: DeadlineBoundInternalWorkerRequest = decode(bytes, validate_deadline_bound_request)?;
    Ok(DeadlineBoundWorkerRequest {
        monotonic_deadline_ns: value.monotonic_deadline_ns,
        request: value.request.ok_or(InternalProtocolError::Invalid)?,
    })
}

pub(crate) fn encode_response(
    value: &InternalWorkerResponse,
) -> Result<Zeroizing<Vec<u8>>, InternalProtocolError> {
    validate_response(value)?;
    encode(value)
}

pub(crate) fn decode_response(
    bytes: &[u8],
) -> Result<InternalWorkerResponse, InternalProtocolError> {
    decode(bytes, validate_response)
}

/// Validate correlation, digest and the operation-specific success outcome.
pub(crate) fn validate_response_for_request(
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
) -> Result<(), InternalProtocolError> {
    let encoded_request = encode_request(request)?;
    validate_response(response)?;
    let expected_digest = blake3::hash(encoded_request.as_slice());
    if response.request_id.as_slice() != request.request_id.as_slice()
        || response.request_digest.as_slice() != expected_digest.as_bytes()
    {
        return Err(InternalProtocolError::Invalid);
    }

    if response.result == InternalWorkerResult::Ok as i32 {
        let operation = request
            .operation
            .as_ref()
            .ok_or(InternalProtocolError::Invalid)?;
        let outcome = response
            .outcome
            .as_ref()
            .ok_or(InternalProtocolError::Invalid)?;
        if !response_matches_operation(operation, outcome) {
            return Err(InternalProtocolError::Invalid);
        }
    }
    Ok(())
}

/// Derives the exact completion binding for one internal transport response.
pub(crate) fn transport_descriptor_binding(
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
) -> Result<[u8; 32], InternalProtocolError> {
    transport_descriptor_event_binding(
        b"VOLPAROSSA internal worker transport completion v1\0",
        request,
        response,
    )
}

/// Derives the exact acknowledgement binding emitted after the worker drops its source descriptor.
pub(crate) fn transport_descriptor_source_released_binding(
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
) -> Result<[u8; 32], InternalProtocolError> {
    if response.result != InternalWorkerResult::Ok as i32 {
        return Err(InternalProtocolError::Invalid);
    }
    transport_descriptor_event_binding(
        b"VOLPAROSSA internal worker transport descriptor source released v1\0",
        request,
        response,
    )
}

fn transport_descriptor_event_binding(
    domain: &[u8],
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
) -> Result<[u8; 32], InternalProtocolError> {
    validate_response_for_request(request, response)?;
    let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
        request.operation.as_ref()
    else {
        return Err(InternalProtocolError::Invalid);
    };
    let kind = InternalTransportSocketKind::try_from(operation.descriptor_kind)
        .map_err(|_| InternalProtocolError::Invalid)?;
    let canonical = response.encode_to_vec();
    let length = u32::try_from(canonical.len()).map_err(|_| InternalProtocolError::TooLarge)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&request.protocol_version.to_be_bytes());
    hasher.update(&request.magic);
    hasher.update(&request.request_id);
    hasher.update(&response.request_digest);
    hasher.update(&(kind as i32).to_be_bytes());
    hasher.update(&length.to_be_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

fn encode<M: Message>(value: &M) -> Result<Zeroizing<Vec<u8>>, InternalProtocolError> {
    let payload = Zeroizing::new(value.encode_to_vec());
    if payload.is_empty() || payload.len() > MAX_INTERNAL_WORKER_FRAME {
        return Err(InternalProtocolError::TooLarge);
    }
    Ok(payload)
}

fn decode<M: Message + Default>(
    bytes: &[u8],
    validate: fn(&M) -> Result<(), InternalProtocolError>,
) -> Result<M, InternalProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_INTERNAL_WORKER_FRAME {
        return Err(InternalProtocolError::TooLarge);
    }
    let value = M::decode(bytes)?;
    validate(&value)?;
    let canonical = Zeroizing::new(value.encode_to_vec());
    if canonical.as_slice() != bytes {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(value)
}

fn validate_envelope(
    version: u32,
    magic: &[u8],
    request_id: &[u8],
) -> Result<(), InternalProtocolError> {
    if version != INTERNAL_WORKER_PROTOCOL_VERSION
        || magic != INTERNAL_WORKER_MAGIC
        || request_id.len() != 16
        || request_id.iter().all(|byte| *byte == 0)
    {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn validate_deadline_bound_request(
    value: &DeadlineBoundInternalWorkerRequest,
) -> Result<(), InternalProtocolError> {
    if value.envelope_version != INTERNAL_WORKER_DEADLINE_ENVELOPE_VERSION
        || value.magic != INTERNAL_WORKER_DEADLINE_ENVELOPE_MAGIC
        || value.monotonic_deadline_ns == 0
    {
        return Err(InternalProtocolError::Invalid);
    }
    validate_request(
        value
            .request
            .as_ref()
            .ok_or(InternalProtocolError::Invalid)?,
    )
}

#[allow(clippy::too_many_lines)] // One exhaustive match keeps the operation allowlist auditable.
fn validate_request(value: &InternalWorkerRequest) -> Result<(), InternalProtocolError> {
    use internal_worker_request::Operation;
    validate_envelope(value.protocol_version, &value.magic, &value.request_id)?;
    match value
        .operation
        .as_ref()
        .ok_or(InternalProtocolError::Invalid)?
    {
        Operation::Initialise(operation) => {
            route_id(&operation.route_context_id)?;
            let role = InternalContextRole::try_from(operation.role)
                .map_err(|_| InternalProtocolError::Invalid)?;
            if role == InternalContextRole::Unspecified {
                return Err(InternalProtocolError::Invalid);
            }
            bounded_limit(operation.mptcp_accepted_addrs)?;
            bounded_limit(operation.mptcp_subflows)
        }
        Operation::PrepareLeases(operation) => {
            route_id(&operation.route_context_id)?;
            validate_lease_batch(&operation.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                validate_host_prefix(
                    lease
                        .local_overlay_address
                        .as_ref()
                        .ok_or(InternalProtocolError::Invalid)?,
                )?;
                if lease.setup_expires_at_unix == 0
                    || lease.hard_expires_at_unix < lease.setup_expires_at_unix
                    || !crate::lease_spec::ownership_alias_has_valid_shape(&lease.ownership_alias)
                {
                    return Err(InternalProtocolError::Invalid);
                }
                Ok((lease.path_id, lease.role))
            })
        }
        Operation::ActivateLeases(operation) => {
            route_id(&operation.route_context_id)?;
            if operation.hard_expires_at_boottime_ns == 0 {
                return Err(InternalProtocolError::Invalid);
            }
            validate_lease_batch(&operation.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                let role = InternalEndpointRole::try_from(lease.role)
                    .map_err(|_| InternalProtocolError::Invalid)?;
                public_key(&lease.peer_public_key)?;
                endpoint(
                    lease
                        .peer_endpoint
                        .as_ref()
                        .ok_or(InternalProtocolError::Invalid)?,
                )?;
                if lease.allowed_prefixes.is_empty()
                    || lease.allowed_prefixes.len() > MAX_PREFIXES
                    || lease.persistent_keepalive_seconds > 120
                    || lease.hard_expires_at_unix == 0
                {
                    return Err(InternalProtocolError::Invalid);
                }
                match role {
                    InternalEndpointRole::RelayClient | InternalEndpointRole::RelayExit => {
                        if lease.maximum_up_mbps == 0
                            || lease.maximum_down_mbps == 0
                            || lease.maximum_up_mbps > volparossa_routing::MAX_HELPER_RATE_MBPS
                            || lease.maximum_down_mbps > volparossa_routing::MAX_HELPER_RATE_MBPS
                        {
                            return Err(InternalProtocolError::Invalid);
                        }
                    }
                    InternalEndpointRole::Client | InternalEndpointRole::Exit => {
                        if lease.maximum_up_mbps != 0 || lease.maximum_down_mbps != 0 {
                            return Err(InternalProtocolError::Invalid);
                        }
                    }
                    InternalEndpointRole::Unspecified => {
                        return Err(InternalProtocolError::Invalid);
                    }
                }
                for prefix in &lease.allowed_prefixes {
                    validate_prefix(prefix)?;
                }
                Ok((lease.path_id, lease.role))
            })
        }
        Operation::ProbeCommitLeases(operation) => {
            route_id(&operation.route_context_id)?;
            validate_lease_batch(&operation.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                public_key(&lease.expected_peer_public_key)?;
                if lease.not_before_unix == 0 {
                    return Err(InternalProtocolError::Invalid);
                }
                Ok((lease.path_id, lease.role))
            })
        }
        Operation::AddMptcpEndpoint(operation) => {
            route_id(&operation.route_context_id)?;
            path(operation.path_id)?;
            let mode = InternalMptcpMode::try_from(operation.mode)
                .map_err(|_| InternalProtocolError::Invalid)?;
            if mode == InternalMptcpMode::Unspecified {
                return Err(InternalProtocolError::Invalid);
            }
            Ok(())
        }
        Operation::RemoveMptcpEndpoint(operation) => {
            route_id(&operation.route_context_id)?;
            path(operation.path_id)
        }
        Operation::AcquireTransportSocket(operation) => {
            route_id(&operation.route_context_id)?;
            path_role(operation.path_id, operation.role)?;
            validate_transport_tuple(
                operation.descriptor_kind,
                operation.expected_local.as_ref(),
                operation.expected_remote.as_ref(),
            )
        }
        Operation::DestroyContext(operation) => route_id(&operation.route_context_id),
    }
}

fn validate_response(value: &InternalWorkerResponse) -> Result<(), InternalProtocolError> {
    use internal_worker_response::Outcome;
    validate_envelope(value.protocol_version, &value.magic, &value.request_id)?;
    let result =
        InternalWorkerResult::try_from(value.result).map_err(|_| InternalProtocolError::Invalid)?;
    if result == InternalWorkerResult::Unspecified {
        return Err(InternalProtocolError::Invalid);
    }
    if value.request_digest.len() != 32 {
        return Err(InternalProtocolError::Invalid);
    }
    match (result, value.outcome.as_ref()) {
        (InternalWorkerResult::Ok, Some(outcome)) => match outcome {
            Outcome::Initialised(outcome) => route_id(&outcome.route_context_id),
            Outcome::Prepared(outcome) => validate_lease_batch(&outcome.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                public_key(&lease.public_key)?;
                if !(1..=u32::from(u16::MAX)).contains(&lease.listen_port) {
                    return Err(InternalProtocolError::Invalid);
                }
                Ok((lease.path_id, lease.role))
            }),
            Outcome::Activated(outcome) => validate_lease_batch(&outcome.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                public_key(&lease.public_key)?;
                if !(1..=u32::from(u16::MAX)).contains(&lease.listen_port)
                    || lease.latest_handshake_nanoseconds >= 1_000_000_000
                    || (lease.latest_handshake_unix == 0 && lease.latest_handshake_nanoseconds != 0)
                {
                    return Err(InternalProtocolError::Invalid);
                }
                Ok((lease.path_id, lease.role))
            }),
            Outcome::ProbedCommitted(outcome) => validate_lease_batch(&outcome.leases, |lease| {
                path_role(lease.path_id, lease.role)?;
                if lease.latest_handshake_unix == 0 {
                    return Err(InternalProtocolError::Invalid);
                }
                Ok((lease.path_id, lease.role))
            }),
            Outcome::Destroyed(_) => Ok(()),
            Outcome::MptcpEndpointAdded(outcome) => path(outcome.path_id),
            Outcome::MptcpEndpointRemoved(outcome) => path(outcome.path_id),
            Outcome::TransportSocketReady(outcome) => {
                path_role(outcome.path_id, outcome.role)?;
                validate_transport_tuple(
                    outcome.descriptor_kind,
                    outcome.local.as_ref(),
                    outcome.remote.as_ref(),
                )
            }
        },
        (InternalWorkerResult::Ok, None)
        | (InternalWorkerResult::Unspecified, _)
        | (_, Some(_)) => Err(InternalProtocolError::Invalid),
        (_, None) => Ok(()),
    }
}

fn validate_lease_batch<T>(
    values: &[T],
    mut validate: impl FnMut(&T) -> Result<(u32, i32), InternalProtocolError>,
) -> Result<(), InternalProtocolError> {
    if values.is_empty() || values.len() > MAX_LEASES {
        return Err(InternalProtocolError::Invalid);
    }
    let mut identities = BTreeSet::new();
    for value in values {
        if !identities.insert(validate(value)?) {
            return Err(InternalProtocolError::Invalid);
        }
    }
    Ok(())
}

fn route_id(value: &[u8]) -> Result<(), InternalProtocolError> {
    if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn bounded_limit(value: u32) -> Result<(), InternalProtocolError> {
    if value > MAX_PATHS {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn path(value: u32) -> Result<(), InternalProtocolError> {
    if !(1..=MAX_PATHS).contains(&value) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn path_role(path_id: u32, role: i32) -> Result<(), InternalProtocolError> {
    path(path_id)?;
    let role = InternalEndpointRole::try_from(role).map_err(|_| InternalProtocolError::Invalid)?;
    if role == InternalEndpointRole::Unspecified {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn public_key(value: &[u8]) -> Result<(), InternalProtocolError> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn endpoint(value: &InternalUdpEndpoint) -> Result<(), InternalProtocolError> {
    if !matches!(value.address.len(), 4 | 16)
        || !(1..=u32::from(u16::MAX)).contains(&value.port)
        || value.address.iter().all(|byte| *byte == 0)
    {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn validate_transport_tuple(
    descriptor_kind: i32,
    local: Option<&InternalSocketAddress>,
    remote: Option<&InternalSocketAddress>,
) -> Result<(), InternalProtocolError> {
    let kind = InternalTransportSocketKind::try_from(descriptor_kind)
        .map_err(|_| InternalProtocolError::Invalid)?;
    if kind == InternalTransportSocketKind::Unspecified {
        return Err(InternalProtocolError::Invalid);
    }
    let local = transport_address(local.ok_or(InternalProtocolError::Invalid)?)?;
    match kind {
        InternalTransportSocketKind::MptcpConnected => {
            let remote = transport_address(remote.ok_or(InternalProtocolError::Invalid)?)?;
            if std::mem::discriminant(&local) != std::mem::discriminant(&remote) || local == remote
            {
                return Err(InternalProtocolError::Invalid);
            }
            Ok(())
        }
        InternalTransportSocketKind::MptcpListener
        | InternalTransportSocketKind::QuicUdpUnconnected => {
            if remote.is_some() {
                return Err(InternalProtocolError::Invalid);
            }
            Ok(())
        }
        InternalTransportSocketKind::Unspecified => Err(InternalProtocolError::Invalid),
    }
}

fn transport_address(value: &InternalSocketAddress) -> Result<IpAddr, InternalProtocolError> {
    if !(1..=u32::from(u16::MAX)).contains(&value.port) {
        return Err(InternalProtocolError::Invalid);
    }
    let address = match value.address.as_slice() {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| InternalProtocolError::Invalid)?,
        )),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| InternalProtocolError::Invalid)?,
        )),
        _ => return Err(InternalProtocolError::Invalid),
    };
    if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
        return Err(InternalProtocolError::Invalid);
    }
    if matches!(address, IpAddr::V4(value) if value == Ipv4Addr::BROADCAST)
        || matches!(address, IpAddr::V6(value) if value.is_unicast_link_local())
    {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(address)
}

fn validate_host_prefix(value: &InternalIpPrefix) -> Result<(), InternalProtocolError> {
    validate_prefix(value)?;
    if !matches!(
        (value.address.len(), value.prefix_length),
        (4, 32) | (16, 128)
    ) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

fn validate_prefix(value: &InternalIpPrefix) -> Result<(), InternalProtocolError> {
    let valid = match value.address.len() {
        4 => value.prefix_length <= 32,
        16 => value.prefix_length <= 128,
        _ => false,
    };
    if !valid || value.address.iter().all(|byte| *byte == 0) {
        return Err(InternalProtocolError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: internal_worker_request::Operation) -> InternalWorkerRequest {
        InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![7; 16],
            operation: Some(operation),
        }
    }

    fn prefix() -> InternalIpPrefix {
        InternalIpPrefix {
            address: vec![0xfd, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7],
            prefix_length: 128,
        }
    }

    fn plan_with_role(path_id: u32, role: InternalEndpointRole) -> LeasePlan {
        LeasePlan {
            path_id,
            role: role as i32,
            local_overlay_address: Some(prefix()),
            setup_expires_at_unix: 100,
            hard_expires_at_unix: 200,
            ownership_alias: format!(
                "{}vpc{path_id:09}:{}",
                crate::lease_spec::DURABLE_WIREGUARD_ALIAS_PREFIX,
                "ab".repeat(32)
            ),
        }
    }

    fn plan(path_id: u32) -> LeasePlan {
        plan_with_role(path_id, InternalEndpointRole::Client)
    }

    fn relay_leases() -> Vec<LeasePlan> {
        (1..=MAX_PATHS)
            .flat_map(|path_id| {
                [
                    InternalEndpointRole::RelayClient,
                    InternalEndpointRole::RelayExit,
                ]
                .map(|role| plan_with_role(path_id, role))
            })
            .collect()
    }

    fn relay_activations(plans: &[LeasePlan]) -> Vec<LeaseActivation> {
        plans
            .iter()
            .map(|lease| LeaseActivation {
                path_id: lease.path_id,
                role: lease.role,
                peer_public_key: vec![9; 32],
                peer_endpoint: Some(InternalUdpEndpoint {
                    address: vec![8, 8, 8, 8],
                    port: 51_820,
                }),
                allowed_prefixes: vec![prefix()],
                persistent_keepalive_seconds: 15,
                maximum_up_mbps: 100,
                maximum_down_mbps: 100,
                hard_expires_at_unix: lease.hard_expires_at_unix,
            })
            .collect()
    }

    fn activation_with_role(role: InternalEndpointRole) -> LeaseActivation {
        let relay = matches!(
            role,
            InternalEndpointRole::RelayClient | InternalEndpointRole::RelayExit
        );
        LeaseActivation {
            path_id: 1,
            role: role as i32,
            peer_public_key: vec![9; 32],
            peer_endpoint: Some(InternalUdpEndpoint {
                address: vec![8, 8, 8, 8],
                port: 51_820,
            }),
            allowed_prefixes: vec![prefix()],
            persistent_keepalive_seconds: 15,
            maximum_up_mbps: u32::from(relay) * 100,
            maximum_down_mbps: u32::from(relay) * 100,
            hard_expires_at_unix: 200,
        }
    }

    fn socket_address(address: [u8; 4], port: u32) -> InternalSocketAddress {
        InternalSocketAddress {
            address: address.to_vec(),
            port,
        }
    }

    fn acquire() -> InternalWorkerRequest {
        request(internal_worker_request::Operation::AcquireTransportSocket(
            AcquireTransportSocket {
                route_context_id: vec![1; 16],
                path_id: 1,
                role: InternalEndpointRole::Client as i32,
                descriptor_kind: InternalTransportSocketKind::MptcpConnected as i32,
                expected_local: Some(socket_address([10, 77, 0, 2], 42_000)),
                expected_remote: Some(socket_address([10, 77, 0, 3], 443)),
            },
        ))
    }

    #[test]
    fn protocol_identity_and_operation_tags_are_fixed() {
        assert_eq!(INTERNAL_WORKER_PROTOCOL_VERSION, 3);
        assert_eq!(INTERNAL_WORKER_MAGIC, b"VPWKR3\0\0");
        assert_eq!(INTERNAL_WORKER_DEADLINE_ENVELOPE_VERSION, 1);
        assert_eq!(INTERNAL_WORKER_DEADLINE_ENVELOPE_MAGIC, b"VPDLN1\0\0");

        let operations = [
            internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id: vec![1; 16],
                role: InternalContextRole::Client as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
            }),
            internal_worker_request::Operation::PrepareLeases(PrepareLeases {
                route_context_id: vec![1; 16],
                leases: vec![plan(1)],
            }),
            internal_worker_request::Operation::ActivateLeases(ActivateLeases {
                route_context_id: vec![1; 16],
                hard_expires_at_boottime_ns: 1,
                leases: vec![LeaseActivation {
                    path_id: 1,
                    role: InternalEndpointRole::Client as i32,
                    peer_public_key: vec![9; 32],
                    peer_endpoint: Some(InternalUdpEndpoint {
                        address: vec![8, 8, 8, 8],
                        port: 51_820,
                    }),
                    allowed_prefixes: vec![prefix()],
                    persistent_keepalive_seconds: 15,
                    maximum_up_mbps: 0,
                    maximum_down_mbps: 0,
                    hard_expires_at_unix: 200,
                }],
            }),
            internal_worker_request::Operation::ProbeCommitLeases(ProbeCommitLeases {
                route_context_id: vec![1; 16],
                leases: vec![LeaseProbe {
                    path_id: 1,
                    role: InternalEndpointRole::Client as i32,
                    expected_peer_public_key: vec![9; 32],
                    not_before_unix: 100,
                }],
            }),
            internal_worker_request::Operation::AddMptcpEndpoint(AddMptcpEndpoint {
                route_context_id: vec![1; 16],
                path_id: 1,
                mode: InternalMptcpMode::Subflow as i32,
                backup: false,
            }),
            internal_worker_request::Operation::RemoveMptcpEndpoint(RemoveMptcpEndpoint {
                route_context_id: vec![1; 16],
                path_id: 1,
            }),
            acquire().operation.expect("Acquire operation"),
            internal_worker_request::Operation::DestroyContext(DestroyContext {
                route_context_id: vec![1; 16],
            }),
        ];
        for operation in operations {
            let value = request(operation);
            let encoded = encode_request(&value).expect("encode");
            assert_eq!(decode_request(&encoded).expect("decode"), value);
        }
        let encoded = acquire().encode_to_vec();
        assert!(
            encoded.windows(2).any(|bytes| bytes == [0x8a, 0x01]),
            "AcquireTransportSocket stays on internal protobuf tag 17"
        );
        let mut retired_interception = encoded;
        retired_interception.extend_from_slice(&[0x72, 0]);
        assert!(decode_request(&retired_interception).is_err());
    }

    #[test]
    fn deadline_envelope_is_canonical_bounded_and_separate_from_operation_identity() {
        let request = acquire();
        let first = encode_deadline_bound_request(&request, 1_000).expect("first envelope");
        let second = encode_deadline_bound_request(&request, 2_000).expect("second envelope");
        assert_ne!(first, second, "wire deadline must be transmitted");

        let decoded = decode_deadline_bound_request(&first).expect("deadline envelope");
        assert_eq!(decoded.monotonic_deadline_ns, 1_000);
        assert_eq!(decoded.request, request);
        assert_eq!(
            encode_request(&decoded.request).expect("logical request"),
            encode_request(&request).expect("same logical request"),
            "deadline transport metadata must not change operation identity"
        );

        assert!(encode_deadline_bound_request(&request, 0).is_err());
        let raw_request = encode_request(&request).expect("legacy raw request");
        assert!(decode_deadline_bound_request(&raw_request).is_err());

        let mut noncanonical = first.to_vec();
        noncanonical.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(decode_deadline_bound_request(&noncanonical).is_err());
    }

    #[test]
    fn envelope_and_canonical_encoding_fail_closed() {
        let value = request(internal_worker_request::Operation::PrepareLeases(
            PrepareLeases {
                route_context_id: vec![1; 16],
                leases: vec![plan(1)],
            },
        ));
        let encoded = encode_request(&value).expect("encode");

        let mut wrong = value.clone();
        wrong.protocol_version = 1;
        assert!(encode_request(&wrong).is_err());
        wrong = value.clone();
        wrong.magic[0] ^= 1;
        assert!(encode_request(&wrong).is_err());
        wrong = value.clone();
        wrong.request_id.fill(0);
        assert!(encode_request(&wrong).is_err());

        let mut noncanonical = encoded.to_vec();
        noncanonical.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(decode_request(&noncanonical).is_err());
        assert!(decode_request(&vec![0; MAX_INTERNAL_WORKER_FRAME + 1]).is_err());
    }

    #[test]
    fn lease_batches_reject_empty_over_limit_invalid_path_and_duplicate_identity() {
        let make = |leases| {
            request(internal_worker_request::Operation::PrepareLeases(
                PrepareLeases {
                    route_context_id: vec![1; 16],
                    leases,
                },
            ))
        };

        assert!(encode_request(&make(Vec::new())).is_err());

        let relay_leases = relay_leases();
        assert_eq!(relay_leases.len(), MAX_LEASES);

        let mut over_limit = relay_leases.clone();
        over_limit.push(plan(1));
        assert_eq!(over_limit.len(), MAX_LEASES + 1);
        assert!(encode_request(&make(over_limit)).is_err());

        let mut invalid_path = relay_leases.clone();
        invalid_path[0].path_id = MAX_PATHS + 1;
        assert!(encode_request(&make(invalid_path)).is_err());

        let mut duplicate = relay_leases;
        duplicate[1] = duplicate[0].clone();
        assert!(encode_request(&make(duplicate)).is_err());

        let mut free_form_alias = plan(1);
        free_form_alias.ownership_alias = "caller-selected-interface".to_owned();
        assert!(encode_request(&make(vec![free_form_alias])).is_err());

        let mut uppercase_digest = plan(1);
        uppercase_digest.ownership_alias = uppercase_digest.ownership_alias.to_ascii_uppercase();
        assert!(encode_request(&make(vec![uppercase_digest])).is_err());
    }

    #[test]
    fn activation_boundary_rejects_missing_expiry_and_role_incoherent_rates() {
        let make = |lease| {
            request(internal_worker_request::Operation::ActivateLeases(
                ActivateLeases {
                    route_context_id: vec![1; 16],
                    hard_expires_at_boottime_ns: 1,
                    leases: vec![lease],
                },
            ))
        };
        let rejected = |lease: LeaseActivation| {
            let value = make(lease);
            assert!(encode_request(&value).is_err());
            assert!(decode_request(&value.encode_to_vec()).is_err());
        };

        for role in [
            InternalEndpointRole::Client,
            InternalEndpointRole::Exit,
            InternalEndpointRole::RelayClient,
            InternalEndpointRole::RelayExit,
        ] {
            let valid = make(activation_with_role(role));
            let encoded = encode_request(&valid).expect("role-coherent activation");
            assert_eq!(decode_request(&encoded).expect("decode"), valid);

            let mut missing_expiry = activation_with_role(role);
            missing_expiry.hard_expires_at_unix = 0;
            rejected(missing_expiry);
        }

        let mut missing_boot_expiry = make(activation_with_role(InternalEndpointRole::Client));
        let Some(internal_worker_request::Operation::ActivateLeases(operation)) =
            missing_boot_expiry.operation.as_mut()
        else {
            panic!("activation fixture");
        };
        operation.hard_expires_at_boottime_ns = 0;
        assert!(encode_request(&missing_boot_expiry).is_err());
        assert!(decode_request(&missing_boot_expiry.encode_to_vec()).is_err());

        for role in [InternalEndpointRole::Client, InternalEndpointRole::Exit] {
            let mut rated = activation_with_role(role);
            rated.maximum_up_mbps = 1;
            rejected(rated);
        }

        for role in [
            InternalEndpointRole::RelayClient,
            InternalEndpointRole::RelayExit,
        ] {
            let mut zero = activation_with_role(role);
            zero.maximum_down_mbps = 0;
            rejected(zero);

            let mut excessive = activation_with_role(role);
            excessive.maximum_up_mbps = volparossa_routing::MAX_HELPER_RATE_MBPS + 1;
            rejected(excessive);
        }
    }

    fn correlated_response(
        request: &InternalWorkerRequest,
        result: InternalWorkerResult,
        outcome: Option<internal_worker_response::Outcome>,
    ) -> InternalWorkerResponse {
        let encoded = encode_request(request).expect("valid request");
        InternalWorkerResponse {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: request.request_id.clone(),
            result: result as i32,
            request_digest: blake3::hash(encoded.as_slice()).as_bytes().to_vec(),
            outcome,
        }
    }

    #[test]
    fn all_lease_batches_accept_sixteen_relay_leases_across_eight_paths() {
        let plans = relay_leases();
        assert_eq!(plans.len(), MAX_LEASES);

        let requests = [
            request(internal_worker_request::Operation::PrepareLeases(
                PrepareLeases {
                    route_context_id: vec![1; 16],
                    leases: plans.clone(),
                },
            )),
            request(internal_worker_request::Operation::ActivateLeases(
                ActivateLeases {
                    route_context_id: vec![1; 16],
                    hard_expires_at_boottime_ns: 1,
                    leases: relay_activations(&plans),
                },
            )),
            request(internal_worker_request::Operation::ProbeCommitLeases(
                ProbeCommitLeases {
                    route_context_id: vec![1; 16],
                    leases: plans
                        .iter()
                        .map(|lease| LeaseProbe {
                            path_id: lease.path_id,
                            role: lease.role,
                            expected_peer_public_key: vec![9; 32],
                            not_before_unix: 100,
                        })
                        .collect(),
                },
            )),
        ];
        for value in requests {
            let encoded = encode_request(&value).expect("sixteen-lease request");
            assert_eq!(decode_request(&encoded).expect("decode"), value);
        }

        let outcomes = [
            internal_worker_response::Outcome::Prepared(PreparedLeases {
                leases: plans
                    .iter()
                    .map(|lease| PreparedLease {
                        path_id: lease.path_id,
                        role: lease.role,
                        public_key: vec![9; 32],
                        listen_port: 51_820,
                    })
                    .collect(),
            }),
            internal_worker_response::Outcome::Activated(ActivatedLeases {
                leases: plans
                    .iter()
                    .map(|lease| ActivatedLease {
                        path_id: lease.path_id,
                        role: lease.role,
                        public_key: vec![9; 32],
                        listen_port: 51_820,
                        latest_handshake_unix: 0,
                        latest_handshake_nanoseconds: 0,
                        received_bytes: 0,
                        transmitted_bytes: 0,
                    })
                    .collect(),
            }),
            internal_worker_response::Outcome::ProbedCommitted(ProbedLeases {
                leases: plans
                    .iter()
                    .map(|lease| ProbedLease {
                        path_id: lease.path_id,
                        role: lease.role,
                        latest_handshake_unix: 100,
                        received_bytes: 1,
                        transmitted_bytes: 1,
                    })
                    .collect(),
            }),
        ];
        for outcome in outcomes {
            let value = InternalWorkerResponse {
                protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
                magic: INTERNAL_WORKER_MAGIC.to_vec(),
                request_id: vec![7; 16],
                result: InternalWorkerResult::Ok as i32,
                request_digest: vec![8; 32],
                outcome: Some(outcome),
            };
            let encoded = encode_response(&value).expect("sixteen-lease response");
            assert_eq!(decode_response(&encoded).expect("decode"), value);
        }
    }

    #[test]
    fn non_lease_path_limits_remain_eight() {
        let initialise = |mptcp_accepted_addrs, mptcp_subflows| {
            request(internal_worker_request::Operation::Initialise(
                InitialiseContext {
                    route_context_id: vec![1; 16],
                    role: InternalContextRole::Relay as i32,
                    mptcp_accepted_addrs,
                    mptcp_subflows,
                },
            ))
        };
        assert!(encode_request(&initialise(MAX_PATHS, MAX_PATHS)).is_ok());
        assert!(encode_request(&initialise(MAX_PATHS + 1, MAX_PATHS)).is_err());
        assert!(encode_request(&initialise(MAX_PATHS, MAX_PATHS + 1)).is_err());

        let add_endpoint = |path_id| {
            request(internal_worker_request::Operation::AddMptcpEndpoint(
                AddMptcpEndpoint {
                    route_context_id: vec![1; 16],
                    path_id,
                    mode: InternalMptcpMode::Subflow as i32,
                    backup: false,
                },
            ))
        };
        assert!(encode_request(&add_endpoint(MAX_PATHS)).is_ok());
        assert!(encode_request(&add_endpoint(MAX_PATHS + 1)).is_err());
    }

    #[test]
    fn omitted_enum_defaults_are_rejected() {
        let initialise = request(internal_worker_request::Operation::Initialise(
            InitialiseContext {
                route_context_id: vec![1; 16],
                role: InternalContextRole::Unspecified as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
            },
        ));
        assert!(encode_request(&initialise).is_err());
        assert!(decode_request(&initialise.encode_to_vec()).is_err());

        let mut lease = plan(1);
        lease.role = InternalEndpointRole::Unspecified as i32;
        let prepare = request(internal_worker_request::Operation::PrepareLeases(
            PrepareLeases {
                route_context_id: vec![1; 16],
                leases: vec![lease],
            },
        ));
        assert!(encode_request(&prepare).is_err());
        assert!(decode_request(&prepare.encode_to_vec()).is_err());

        let add = request(internal_worker_request::Operation::AddMptcpEndpoint(
            AddMptcpEndpoint {
                route_context_id: vec![1; 16],
                path_id: 1,
                mode: InternalMptcpMode::Unspecified as i32,
                backup: false,
            },
        ));
        assert!(encode_request(&add).is_err());
        assert!(decode_request(&add.encode_to_vec()).is_err());
    }

    #[test]
    fn prepared_response_requires_kernel_proven_nonzero_port() {
        let prepare = request(internal_worker_request::Operation::PrepareLeases(
            PrepareLeases {
                route_context_id: vec![1; 16],
                leases: vec![plan(1)],
            },
        ));
        let prepared = |listen_port| {
            correlated_response(
                &prepare,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::Prepared(
                    PreparedLeases {
                        leases: vec![PreparedLease {
                            path_id: 1,
                            role: InternalEndpointRole::Client as i32,
                            public_key: vec![9; 32],
                            listen_port,
                        }],
                    },
                )),
            )
        };

        let response = prepared(51_820);
        assert!(encode_response(&response).is_ok());
        assert!(validate_response_for_request(&prepare, &response).is_ok());
        assert!(encode_response(&prepared(0)).is_err());
    }

    #[test]
    fn successful_batch_and_endpoint_responses_bind_exact_request_order_and_identity() {
        let prepare = request(internal_worker_request::Operation::PrepareLeases(
            PrepareLeases {
                route_context_id: vec![1; 16],
                leases: vec![plan(1), plan(2)],
            },
        ));
        let prepared = |identities: [(u32, i32); 2]| {
            correlated_response(
                &prepare,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::Prepared(
                    PreparedLeases {
                        leases: identities
                            .into_iter()
                            .map(|(path_id, role)| PreparedLease {
                                path_id,
                                role,
                                public_key: vec![u8::try_from(path_id).expect("path byte"); 32],
                                listen_port: 51_820 + path_id,
                            })
                            .collect(),
                    },
                )),
            )
        };
        let client = InternalEndpointRole::Client as i32;
        assert!(
            validate_response_for_request(&prepare, &prepared([(1, client), (2, client)])).is_ok()
        );
        assert!(
            validate_response_for_request(&prepare, &prepared([(2, client), (1, client)])).is_err(),
            "a set-equal permutation must not rebind affine lease owners"
        );

        let add = request(internal_worker_request::Operation::AddMptcpEndpoint(
            AddMptcpEndpoint {
                route_context_id: vec![1; 16],
                path_id: 1,
                mode: InternalMptcpMode::Subflow as i32,
                backup: false,
            },
        ));
        let mismatched = correlated_response(
            &add,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::MptcpEndpointAdded(
                MptcpEndpointAdded { path_id: 2 },
            )),
        );
        assert!(validate_response_for_request(&add, &mismatched).is_err());
    }

    #[test]
    fn result_and_operation_specific_outcome_are_bound_fail_closed() {
        let initialise = request(internal_worker_request::Operation::Initialise(
            InitialiseContext {
                route_context_id: vec![1; 16],
                role: InternalContextRole::Client as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
            },
        ));
        let success = correlated_response(
            &initialise,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Initialised(
                ContextInitialised {
                    route_context_id: vec![1; 16],
                },
            )),
        );
        assert!(validate_response_for_request(&initialise, &success).is_ok());

        let mut unspecified = success.clone();
        unspecified.result = InternalWorkerResult::Unspecified as i32;
        unspecified.outcome = None;
        assert!(encode_response(&unspecified).is_err());

        let mut missing_success = success.clone();
        missing_success.outcome = None;
        assert!(encode_response(&missing_success).is_err());

        let mut contradictory_failure = success.clone();
        contradictory_failure.result = InternalWorkerResult::Invalid as i32;
        assert!(encode_response(&contradictory_failure).is_err());

        let mut failure = success.clone();
        failure.result = InternalWorkerResult::Kernel as i32;
        failure.outcome = None;
        assert!(encode_response(&failure).is_ok());
        assert!(validate_response_for_request(&initialise, &failure).is_ok());

        let mut mismatched = success.clone();
        mismatched.outcome = Some(internal_worker_response::Outcome::Destroyed(
            ContextDestroyed {},
        ));
        assert!(encode_response(&mismatched).is_ok());
        assert!(validate_response_for_request(&initialise, &mismatched).is_err());

        let mut wrong_id = success.clone();
        wrong_id.request_id[0] ^= 1;
        assert!(validate_response_for_request(&initialise, &wrong_id).is_err());
        let mut wrong_digest = success;
        wrong_digest.request_digest[0] ^= 1;
        assert!(validate_response_for_request(&initialise, &wrong_digest).is_err());
    }

    #[test]
    fn transport_success_echo_and_completion_binding_are_exact() {
        let acquire = acquire();
        let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
            acquire.operation.as_ref()
        else {
            panic!("Acquire operation");
        };
        let success = correlated_response(
            &acquire,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: operation.path_id,
                    role: operation.role,
                    descriptor_kind: operation.descriptor_kind,
                    local: operation.expected_local.clone(),
                    remote: operation.expected_remote.clone(),
                },
            )),
        );
        assert!(validate_response_for_request(&acquire, &success).is_ok());
        let binding = transport_descriptor_binding(&acquire, &success).expect("binding");

        let mut wrong_path = success.clone();
        let Some(internal_worker_response::Outcome::TransportSocketReady(ready)) =
            wrong_path.outcome.as_mut()
        else {
            panic!("transport outcome");
        };
        ready.path_id = 2;
        assert!(validate_response_for_request(&acquire, &wrong_path).is_err());
        assert!(transport_descriptor_binding(&acquire, &wrong_path).is_err());

        let mut changed_response = success;
        changed_response.request_id[0] ^= 1;
        assert!(transport_descriptor_binding(&acquire, &changed_response).is_err());
        assert_ne!(binding, [0; 32]);
    }

    #[test]
    fn transport_source_release_binding_is_deterministic_and_domain_separated() {
        let acquire = acquire();
        let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
            acquire.operation.as_ref()
        else {
            panic!("Acquire operation");
        };
        let success = correlated_response(
            &acquire,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: operation.path_id,
                    role: operation.role,
                    descriptor_kind: operation.descriptor_kind,
                    local: operation.expected_local.clone(),
                    remote: operation.expected_remote.clone(),
                },
            )),
        );

        let released =
            transport_descriptor_source_released_binding(&acquire, &success).expect("released");
        assert_eq!(
            transport_descriptor_source_released_binding(&acquire, &success)
                .expect("repeat released"),
            released
        );
        assert_ne!(
            transport_descriptor_binding(&acquire, &success).expect("descriptor"),
            released
        );
        assert_ne!(released, [0; 32]);

        let failure = correlated_response(&acquire, InternalWorkerResult::Kernel, None);
        assert!(transport_descriptor_source_released_binding(&acquire, &failure).is_err());
    }

    #[test]
    fn transport_source_release_binding_commits_to_request_response_and_context() {
        fn successful_response(request: &InternalWorkerRequest) -> InternalWorkerResponse {
            let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
                request.operation.as_ref()
            else {
                panic!("Acquire operation");
            };
            correlated_response(
                request,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::TransportSocketReady(
                    TransportSocketReady {
                        path_id: operation.path_id,
                        role: operation.role,
                        descriptor_kind: operation.descriptor_kind,
                        local: operation.expected_local.clone(),
                        remote: operation.expected_remote.clone(),
                    },
                )),
            )
        }

        let acquire = acquire();
        let success = successful_response(&acquire);
        let baseline = transport_descriptor_source_released_binding(&acquire, &success)
            .expect("baseline released");

        let mut changed_request_id = acquire.clone();
        changed_request_id.request_id[0] ^= 1;
        let changed_response = successful_response(&changed_request_id);
        assert_ne!(
            transport_descriptor_source_released_binding(&changed_request_id, &changed_response)
                .expect("request-id mutation"),
            baseline
        );

        let mut changed_context = acquire.clone();
        let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
            changed_context.operation.as_mut()
        else {
            panic!("Acquire operation");
        };
        operation.route_context_id[0] ^= 1;
        let changed_response = successful_response(&changed_context);
        assert_ne!(
            transport_descriptor_source_released_binding(&changed_context, &changed_response)
                .expect("context mutation"),
            baseline
        );

        let mut changed_tuple = acquire.clone();
        let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
            changed_tuple.operation.as_mut()
        else {
            panic!("Acquire operation");
        };
        operation.expected_local.as_mut().expect("local").port += 1;
        let changed_response = successful_response(&changed_tuple);
        assert_ne!(
            transport_descriptor_source_released_binding(&changed_tuple, &changed_response)
                .expect("response mutation"),
            baseline
        );

        let mut mismatched_response = success.clone();
        let Some(internal_worker_response::Outcome::TransportSocketReady(ready)) =
            mismatched_response.outcome.as_mut()
        else {
            panic!("transport outcome");
        };
        ready.remote.as_mut().expect("remote").port += 1;
        assert!(
            transport_descriptor_source_released_binding(&acquire, &mismatched_response).is_err()
        );

        let mut uncorrelated = success;
        uncorrelated.request_digest[0] ^= 1;
        assert!(transport_descriptor_source_released_binding(&acquire, &uncorrelated).is_err());
    }

    #[test]
    fn response_requires_typed_outcome_and_request_digest() {
        let value = InternalWorkerResponse {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![7; 16],
            result: InternalWorkerResult::Ok as i32,
            request_digest: vec![8; 32],
            outcome: Some(internal_worker_response::Outcome::Activated(
                ActivatedLeases {
                    leases: vec![ActivatedLease {
                        path_id: 1,
                        role: InternalEndpointRole::Exit as i32,
                        public_key: vec![9; 32],
                        listen_port: 51_820,
                        latest_handshake_unix: 0,
                        latest_handshake_nanoseconds: 0,
                        received_bytes: 0,
                        transmitted_bytes: 0,
                    }],
                },
            )),
        };
        let encoded = encode_response(&value).expect("encode response");
        assert_eq!(decode_response(&encoded).expect("decode response"), value);

        let mut wrong = value.clone();
        wrong.request_digest.clear();
        assert!(encode_response(&wrong).is_err());

        for (seconds, nanoseconds) in [(0, 1), (1, 1_000_000_000)] {
            let mut wrong = value.clone();
            let Some(internal_worker_response::Outcome::Activated(activated)) =
                wrong.outcome.as_mut()
            else {
                panic!("activated response")
            };
            activated.leases[0].latest_handshake_unix = seconds;
            activated.leases[0].latest_handshake_nanoseconds = nanoseconds;
            assert!(encode_response(&wrong).is_err());
        }
    }
}
