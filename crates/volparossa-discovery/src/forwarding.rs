//! Canonical, bounded two-hop exit forwarding frames.
//!
//! The client-facing and exit-facing protocols deliberately use distinct libp2p
//! behaviours. Their Rust request and response types are different so the
//! generated `NetworkBehaviour` events cannot be confused, while their protobuf
//! wire representation remains byte-for-byte identical when no upstream-only control proof is
//! attached. The control Relay may attach its own advertisement only to a native Permit request.

use std::{io, time::Duration};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol, identity, request_response};
use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, ControlPayload, ExitReservation, MAX_CONTROL_MESSAGE_SIZE,
    MAX_CONTROL_PAYLOAD_SIZE, MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE,
    NativeProbeAuthorizationChain, NativeProbeEndpointBinding, NodeAdvertisement, PROTOCOL_VERSION,
    RelayAuthorization, SignedEnvelope, decode_canonical, encode_canonical,
    node_id_from_public_key,
};

/// Client-to-control-relay exit-forwarding protocol.
pub const EXIT_FORWARD_PROTOCOL: &str = "/volparossa/exit-forward/4";
/// Control-relay-to-exit forwarding protocol.
pub const EXIT_FORWARD_UPSTREAM_PROTOCOL: &str = "/volparossa/exit-forward-upstream/4";
/// Exact forwarding RPC schema version.
pub const FORWARDING_RPC_VERSION: u32 = 4;
/// Maximum canonical request or response frame size.
pub const MAX_FORWARDING_FRAME_BYTES: u64 = 512 * 1024;
/// Maximum combined inbound and outbound streams for either forwarding hop.
pub const MAX_CONCURRENT_FORWARDING_STREAMS: usize = 64;
/// Client-hop transport timeout. Application deadlines remain absolute and shorter if required.
pub const EXIT_FORWARD_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
/// Exit-hop transport timeout. The relay performs no internal retry.
pub const EXIT_FORWARD_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

const REQUEST_ID_LENGTH: usize = 16;
const NODE_ID_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const MAX_PEER_ID_LENGTH: usize = 64;
const MAX_RELAY_PATHS: usize = 8;

/// Operation carried through exactly one selected control relay.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ExitForwardOperation {
    Unspecified = 0,
    FetchExitAdvertisement = 1,
    CapacityHold = 2,
    ProbePermit = 3,
    FinalizeReservation = 4,
    ConfirmRelay = 5,
    NativeProbePermit = 6,
    /// Data-Relay-to-Exit native Start chain requesting one standard Relay authorization.
    NativeProbeAuthorize = 7,
    /// Data-Relay-to-Exit readiness request carrying its exact helper-prepared Exit-facing endpoint.
    NativeProbeReady = 8,
    /// Data-Relay-to-Exit terminal Start chain requesting one helper-proven Exit result.
    NativeProbeResult = 9,
    /// Data-Relay-to-Exit activation after the Client committed the exact final UDP route.
    UdpSessionStart = 10,
    /// Data-Relay-to-Exit activation framing for one exact committed MPTCP path set.
    MptcpSessionStart = 11,
    /// Data-Relay-to-Exit activation framing for one exact committed MPQUIC path set.
    MpquicSessionStart = 12,
}

/// Endpoint-bearing data-Relay request for the selected Exit's private readiness phase.
///
/// The authenticated upstream connection supplies the data-Relay identity. These bytes add no
/// authority: the Exit independently verifies both signed Permit phases, the exact signed Relay
/// advertisement and the endpoint binding before consuming its retained Permit owner.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeReadyForwardRequest {
    #[prost(bytes = "vec", tag = "1")]
    signed_permit_request: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed_permit: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    relay_exit_endpoint: Option<NativeProbeEndpointBinding>,
    #[prost(bytes = "vec", tag = "4")]
    signed_relay_advertisement: Vec<u8>,
}

impl NativeProbeReadyForwardRequest {
    /// Construct one canonical readiness request.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong signed phase types or malformed endpoint material.
    pub fn new(
        signed_permit_request: Vec<u8>,
        signed_permit: Vec<u8>,
        relay_exit_endpoint: NativeProbeEndpointBinding,
        signed_relay_advertisement: Vec<u8>,
    ) -> Result<Self, ForwardingRpcError> {
        let value = Self {
            signed_permit_request,
            signed_permit,
            relay_exit_endpoint: Some(relay_exit_endpoint),
            signed_relay_advertisement,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate bounded transport framing without claiming cryptographic authority.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong phase types or incomplete endpoint material.
    pub fn validate(&self) -> Result<(), ForwardingRpcError> {
        validate_signed_type(
            &self.signed_permit_request,
            ControlMessageType::NativeProbePermitRequest,
        )?;
        validate_signed_type(&self.signed_permit, ControlMessageType::NativeProbePermit)?;
        validate_signed_type(
            &self.signed_relay_advertisement,
            ControlMessageType::NodeAdvertisement,
        )?;
        let endpoint = self
            .relay_exit_endpoint
            .as_ref()
            .ok_or(ForwardingRpcError::InvalidFrame)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&endpoint.helper_runtime_id)?;
        validate_fixed_nonzero::<REQUEST_ID_LENGTH>(&endpoint.route_context_id)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&endpoint.prepared_lease_commitment)?;
        let wire = endpoint
            .endpoint
            .as_ref()
            .ok_or(ForwardingRpcError::InvalidFrame)?;
        validate_fixed_nonzero::<PUBLIC_KEY_LENGTH>(&wire.public_key)?;
        if !(1..=u32::try_from(MAX_RELAY_PATHS).unwrap_or(u32::MAX)).contains(&endpoint.path_id)
            || !matches!(wire.underlay_ip.len(), 4 | 16)
            || wire.underlay_ip.iter().all(|byte| *byte == 0)
            || u16::try_from(wire.listen_port)
                .ok()
                .is_none_or(|port| port == 0)
        {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        Ok(())
    }

    /// Borrow the exact client-session-signed Permit request.
    #[must_use]
    pub fn signed_permit_request(&self) -> &[u8] {
        &self.signed_permit_request
    }

    /// Borrow the exact Exit-signed Permit.
    #[must_use]
    pub fn signed_permit(&self) -> &[u8] {
        &self.signed_permit
    }

    /// Borrow the data Relay's helper-prepared Exit-facing endpoint binding when present.
    #[must_use]
    pub const fn relay_exit_endpoint(&self) -> Option<&NativeProbeEndpointBinding> {
        self.relay_exit_endpoint.as_ref()
    }

    /// Borrow the data Relay's exact signed advertisement committed by the Permit scope.
    #[must_use]
    pub fn signed_relay_advertisement(&self) -> &[u8] {
        &self.signed_relay_advertisement
    }
}

/// Detail-free forwarding result.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ForwardStatus {
    Unspecified = 0,
    Granted = 1,
    Rejected = 2,
    /// The receiving service is definitively unavailable for this operation.
    Unavailable = 3,
}

/// Canonical client-hop forwarding request.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitForwardRequest {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    forward_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    control_relay_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    exit_node_id: Vec<u8>,
    #[prost(uint64, tag = "8")]
    deadline_unix_ms: u64,
    #[prost(enumeration = "ExitForwardOperation", tag = "9")]
    operation: i32,
    #[prost(bytes = "vec", tag = "10")]
    canonical_request: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    control_advertisement: Vec<u8>,
}

impl ExitForwardRequest {
    /// Construct and validate one canonical forwarding request.
    ///
    /// The exit node ID and canonical request are both empty only for an
    /// advertisement fetch. Every other operation carries one v4 signed envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for identity contradictions, unsupported operations,
    /// invalid envelope types, or fixed-bound violations.
    #[allow(clippy::too_many_arguments, reason = "fixed flat protobuf schema")]
    pub fn new(
        forward_id: Vec<u8>,
        control_relay_node_id: Vec<u8>,
        control_relay_peer_id: Vec<u8>,
        control_relay_public_key: Vec<u8>,
        exit_peer_id: Vec<u8>,
        exit_node_id: Vec<u8>,
        deadline_unix_ms: u64,
        operation: ExitForwardOperation,
        canonical_request: Vec<u8>,
    ) -> Result<Self, ForwardingRpcError> {
        let request = Self {
            rpc_version: FORWARDING_RPC_VERSION,
            forward_id,
            control_relay_node_id,
            control_relay_peer_id,
            control_relay_public_key,
            exit_peer_id,
            exit_node_id,
            deadline_unix_ms,
            operation: operation as i32,
            canonical_request,
            control_advertisement: Vec::new(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate the complete transport wrapper without mutating replay state.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-v4, ambiguous, oversized, identity-inconsistent,
    /// or operation-inconsistent request.
    pub fn validate(&self) -> Result<(), ForwardingRpcError> {
        validate_version(self.rpc_version)?;
        validate_fixed_nonzero::<REQUEST_ID_LENGTH>(&self.forward_id)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.control_relay_node_id)?;
        validate_fixed_nonzero::<PUBLIC_KEY_LENGTH>(&self.control_relay_public_key)?;
        let relay_peer = validate_peer_id(&self.control_relay_peer_id)?;
        let exit_peer = validate_peer_id(&self.exit_peer_id)?;
        if relay_peer == exit_peer {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = self
            .control_relay_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ForwardingRpcError::InvalidFrame)?;
        if node_id_from_public_key(&public_key_bytes).as_slice()
            != self.control_relay_node_id.as_slice()
        {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        let public_key = identity::ed25519::PublicKey::try_from_bytes(&public_key_bytes)
            .map_err(|_| ForwardingRpcError::InvalidFrame)?;
        if identity::PublicKey::from(public_key).to_peer_id() != relay_peer {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        if self.deadline_unix_ms == 0 {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        let operation = self.validated_operation()?;
        validate_control_advertisement(self)?;
        match operation {
            ExitForwardOperation::FetchExitAdvertisement => {
                if !self.exit_node_id.is_empty() || !self.canonical_request.is_empty() {
                    return Err(ForwardingRpcError::InvalidFrame);
                }
            }
            ExitForwardOperation::CapacityHold
            | ExitForwardOperation::ProbePermit
            | ExitForwardOperation::FinalizeReservation
            | ExitForwardOperation::ConfirmRelay
            | ExitForwardOperation::NativeProbePermit => {
                validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.exit_node_id)?;
                if self.exit_node_id == self.control_relay_node_id {
                    return Err(ForwardingRpcError::InvalidFrame);
                }
                validate_signed_type(&self.canonical_request, request_type(operation)?)?;
            }
            ExitForwardOperation::NativeProbeAuthorize
            | ExitForwardOperation::NativeProbeResult => {
                validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.exit_node_id)?;
                if self.exit_node_id == self.control_relay_node_id {
                    return Err(ForwardingRpcError::InvalidFrame);
                }
                validate_native_probe_authorization_chain(&self.canonical_request)?;
            }
            ExitForwardOperation::NativeProbeReady => {
                validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.exit_node_id)?;
                if self.exit_node_id == self.control_relay_node_id {
                    return Err(ForwardingRpcError::InvalidFrame);
                }
                decode_canonical::<NativeProbeReadyForwardRequest>(
                    &self.canonical_request,
                    frame_limit(),
                )
                .map_err(|_| ForwardingRpcError::InvalidFrame)?
                .validate()?;
            }
            ExitForwardOperation::UdpSessionStart => {
                decode_canonical::<crate::UdpSessionStartRequest>(
                    &self.canonical_request,
                    frame_limit(),
                )
                .map_err(|_| ForwardingRpcError::InvalidFrame)?
                .validate()
                .map_err(|_| ForwardingRpcError::InvalidFrame)?;
            }
            ExitForwardOperation::MptcpSessionStart => {
                validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.exit_node_id)?;
                if self.exit_node_id == self.control_relay_node_id {
                    return Err(ForwardingRpcError::InvalidFrame);
                }
                decode_canonical::<crate::MptcpSessionStartRequest>(
                    &self.canonical_request,
                    frame_limit(),
                )
                .map_err(|_| ForwardingRpcError::InvalidFrame)?
                .validate()
                .map_err(|_| ForwardingRpcError::InvalidFrame)?;
            }
            ExitForwardOperation::MpquicSessionStart => {
                validate_mpquic_session_request(self)?;
            }
            ExitForwardOperation::Unspecified => {
                return Err(ForwardingRpcError::InvalidOperation(self.operation));
            }
        }
        Ok(())
    }

    pub(super) fn validate_client_hop(&self) -> Result<(), ForwardingRpcError> {
        if !self.control_advertisement.is_empty() {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        self.validate()
    }

    /// Borrow the upstream control Relay's exact signed advertisement, if attached.
    ///
    /// This is framing, not verified authority. The Exit must independently verify the signature,
    /// authenticated transport identity, signed Permit actor binding, policy and freshness.
    #[must_use]
    pub fn control_advertisement(&self) -> &[u8] {
        &self.control_advertisement
    }

    /// Explicit forwarding identifier retained unchanged across both hops.
    #[must_use]
    pub fn forward_id(&self) -> &[u8] {
        &self.forward_id
    }

    /// Selected control relay node identifier.
    #[must_use]
    pub fn control_relay_node_id(&self) -> &[u8] {
        &self.control_relay_node_id
    }

    /// Selected control relay libp2p peer identifier.
    #[must_use]
    pub fn control_relay_peer_id(&self) -> &[u8] {
        &self.control_relay_peer_id
    }

    /// Selected control relay permanent Ed25519 public key.
    #[must_use]
    pub fn control_relay_public_key(&self) -> &[u8] {
        &self.control_relay_public_key
    }

    /// Target exit libp2p peer identifier.
    #[must_use]
    pub fn exit_peer_id(&self) -> &[u8] {
        &self.exit_peer_id
    }

    /// Target exit node ID, empty only while fetching its advertisement.
    #[must_use]
    pub fn exit_node_id(&self) -> &[u8] {
        &self.exit_node_id
    }

    /// Unchanged absolute end-to-end application deadline.
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    /// Validated operation discriminator.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_operation(&self) -> Result<ExitForwardOperation, ForwardingRpcError> {
        let operation = ExitForwardOperation::try_from(self.operation)
            .map_err(|_| ForwardingRpcError::InvalidOperation(self.operation))?;
        if operation == ExitForwardOperation::Unspecified {
            return Err(ForwardingRpcError::InvalidOperation(self.operation));
        }
        Ok(operation)
    }

    /// Exact signed request bytes, empty only for advertisement retrieval.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }
}

fn validate_mpquic_session_request(request: &ExitForwardRequest) -> Result<(), ForwardingRpcError> {
    validate_fixed_nonzero::<NODE_ID_LENGTH>(&request.exit_node_id)?;
    if request.exit_node_id == request.control_relay_node_id {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    decode_canonical::<crate::MpquicSessionStartRequest>(&request.canonical_request, frame_limit())
        .map_err(|_| ForwardingRpcError::InvalidFrame)?
        .validate()
        .map_err(|_| ForwardingRpcError::InvalidFrame)
}

/// Canonical response returned over the client-facing forwarding hop.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitForwardResponse {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    forward_id: Vec<u8>,
    #[prost(enumeration = "ExitForwardOperation", tag = "3")]
    operation: i32,
    #[prost(enumeration = "ForwardStatus", tag = "4")]
    status: i32,
    #[prost(bytes = "vec", tag = "5")]
    exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    signed_responses: Vec<Vec<u8>>,
}

impl ExitForwardResponse {
    /// Construct a successful response with operation-specific signed payloads.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, envelope types, ordering, or cardinality.
    pub fn granted(
        forward_id: Vec<u8>,
        operation: ExitForwardOperation,
        exit_node_id: Vec<u8>,
        exit_peer_id: Vec<u8>,
        signed_responses: Vec<Vec<u8>>,
    ) -> Result<Self, ForwardingRpcError> {
        Self::new(
            forward_id,
            operation,
            ForwardStatus::Granted,
            exit_node_id,
            exit_peer_id,
            signed_responses,
        )
    }

    /// Construct a definitive, detail-free application rejection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities or operation values.
    pub fn rejected(
        forward_id: Vec<u8>,
        operation: ExitForwardOperation,
        exit_node_id: Vec<u8>,
        exit_peer_id: Vec<u8>,
    ) -> Result<Self, ForwardingRpcError> {
        Self::new(
            forward_id,
            operation,
            ForwardStatus::Rejected,
            exit_node_id,
            exit_peer_id,
            Vec::new(),
        )
    }

    /// Construct a detail-free, definitive unavailable response.
    ///
    /// This is an authenticated protocol response, not a local no-response transport
    /// ambiguity. Callers must not redispatch it as an exact-byte retry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities or operation values.
    pub fn unavailable(
        forward_id: Vec<u8>,
        operation: ExitForwardOperation,
        exit_node_id: Vec<u8>,
        exit_peer_id: Vec<u8>,
    ) -> Result<Self, ForwardingRpcError> {
        Self::new(
            forward_id,
            operation,
            ForwardStatus::Unavailable,
            exit_node_id,
            exit_peer_id,
            Vec::new(),
        )
    }

    fn new(
        forward_id: Vec<u8>,
        operation: ExitForwardOperation,
        status: ForwardStatus,
        exit_node_id: Vec<u8>,
        exit_peer_id: Vec<u8>,
        signed_responses: Vec<Vec<u8>>,
    ) -> Result<Self, ForwardingRpcError> {
        let response = Self {
            rpc_version: FORWARDING_RPC_VERSION,
            forward_id,
            operation: operation as i32,
            status: status as i32,
            exit_node_id,
            exit_peer_id,
            signed_responses,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate status-dependent cardinality and signed-envelope types.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, ambiguous, oversized, or non-v4 response.
    pub fn validate(&self) -> Result<(), ForwardingRpcError> {
        validate_version(self.rpc_version)?;
        validate_fixed_nonzero::<REQUEST_ID_LENGTH>(&self.forward_id)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.exit_node_id)?;
        validate_peer_id(&self.exit_peer_id)?;
        let operation = self.validated_operation()?;
        match self.validated_status()? {
            ForwardStatus::Granted => validate_granted_responses(operation, &self.signed_responses),
            ForwardStatus::Rejected | ForwardStatus::Unavailable
                if self.signed_responses.is_empty() =>
            {
                Ok(())
            }
            ForwardStatus::Rejected | ForwardStatus::Unavailable => {
                Err(ForwardingRpcError::InvalidFrame)
            }
            ForwardStatus::Unspecified => Err(ForwardingRpcError::InvalidStatus(self.status)),
        }
    }

    /// Explicit forwarding identifier echoed unchanged by the exit.
    #[must_use]
    pub fn forward_id(&self) -> &[u8] {
        &self.forward_id
    }

    /// Validated operation discriminator.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_operation(&self) -> Result<ExitForwardOperation, ForwardingRpcError> {
        let operation = ExitForwardOperation::try_from(self.operation)
            .map_err(|_| ForwardingRpcError::InvalidOperation(self.operation))?;
        if operation == ExitForwardOperation::Unspecified {
            return Err(ForwardingRpcError::InvalidOperation(self.operation));
        }
        Ok(operation)
    }

    /// Validated detail-free response status.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_status(&self) -> Result<ForwardStatus, ForwardingRpcError> {
        let status = ForwardStatus::try_from(self.status)
            .map_err(|_| ForwardingRpcError::InvalidStatus(self.status))?;
        if status == ForwardStatus::Unspecified {
            return Err(ForwardingRpcError::InvalidStatus(self.status));
        }
        Ok(status)
    }

    /// Exit node identifier asserted by all successful signed payloads.
    #[must_use]
    pub fn exit_node_id(&self) -> &[u8] {
        &self.exit_node_id
    }

    /// Target exit libp2p peer identifier.
    #[must_use]
    pub fn exit_peer_id(&self) -> &[u8] {
        &self.exit_peer_id
    }

    /// Operation-specific signed response envelopes.
    #[must_use]
    pub fn signed_responses(&self) -> &[Vec<u8>] {
        &self.signed_responses
    }
}

/// Wire-transparent request type used only on the relay-to-exit behaviour.
#[derive(Clone, Debug, PartialEq)]
pub struct UpstreamExitForwardRequest(ExitForwardRequest);

impl UpstreamExitForwardRequest {
    /// Attach the control Relay's signed self-advertisement to one native Permit request.
    ///
    /// The original client-session-signed request is retained byte-for-byte. Client-hop codecs
    /// and request APIs refuse the additional field.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized or noncanonical advertisement material, a different
    /// actor or message type, or any operation other than a native Permit request.
    pub fn with_control_advertisement(
        mut self,
        advertisement: Vec<u8>,
    ) -> Result<Self, ForwardingRpcError> {
        if advertisement.is_empty() || !self.0.control_advertisement.is_empty() {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        self.0.control_advertisement = advertisement;
        self.validate()?;
        Ok(self)
    }

    /// Borrow the canonical forwarding fields.
    #[must_use]
    pub const fn as_forward_request(&self) -> &ExitForwardRequest {
        &self.0
    }

    /// Consume this hop marker and recover the canonical forwarding request.
    #[must_use]
    pub fn into_forward_request(self) -> ExitForwardRequest {
        self.0
    }

    /// Validate the canonical forwarding request.
    ///
    /// # Errors
    ///
    /// Returns any forwarding frame validation error unchanged.
    pub fn validate(&self) -> Result<(), ForwardingRpcError> {
        self.0.validate()
    }
}

impl From<ExitForwardRequest> for UpstreamExitForwardRequest {
    fn from(value: ExitForwardRequest) -> Self {
        Self(value)
    }
}

impl From<UpstreamExitForwardRequest> for ExitForwardRequest {
    fn from(value: UpstreamExitForwardRequest) -> Self {
        value.0
    }
}

/// Wire-transparent response type used only on the relay-to-exit behaviour.
#[derive(Clone, Debug, PartialEq)]
pub struct UpstreamExitForwardResponse(ExitForwardResponse);

impl UpstreamExitForwardResponse {
    /// Borrow the canonical forwarding fields.
    #[must_use]
    pub const fn as_forward_response(&self) -> &ExitForwardResponse {
        &self.0
    }

    /// Consume this hop marker and recover the canonical forwarding response.
    #[must_use]
    pub fn into_forward_response(self) -> ExitForwardResponse {
        self.0
    }

    /// Validate the canonical forwarding response.
    ///
    /// # Errors
    ///
    /// Returns any forwarding frame validation error unchanged.
    pub fn validate(&self) -> Result<(), ForwardingRpcError> {
        self.0.validate()
    }
}

impl From<ExitForwardResponse> for UpstreamExitForwardResponse {
    fn from(value: ExitForwardResponse) -> Self {
        Self(value)
    }
}

impl From<UpstreamExitForwardResponse> for ExitForwardResponse {
    fn from(value: UpstreamExitForwardResponse) -> Self {
        value.0
    }
}

/// Forwarding-frame validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForwardingRpcError {
    /// The frame used an obsolete or unknown RPC version.
    #[error("unsupported forwarding RPC version {0}")]
    UnsupportedVersion(u32),
    /// The operation discriminator was zero or unknown.
    #[error("invalid forwarding operation {0}")]
    InvalidOperation(i32),
    /// The status discriminator was zero or unknown.
    #[error("invalid forwarding status {0}")]
    InvalidStatus(i32),
    /// The frame was empty, oversized, non-canonical, or semantically ambiguous.
    #[error("invalid canonical forwarding RPC frame")]
    InvalidFrame,
}

/// Canonical codec for the client-to-control-relay hop.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExitForwardCodec;

/// Canonical codec for the control-relay-to-exit hop.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpstreamExitForwardCodec;

pub(crate) fn exit_forward_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<ExitForwardCodec> {
    request_response::Behaviour::with_codec(
        ExitForwardCodec,
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(EXIT_FORWARD_PROTOCOL), support)),
        request_response::Config::default()
            .with_request_timeout(EXIT_FORWARD_REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_CONCURRENT_FORWARDING_STREAMS),
    )
}

pub(crate) fn exit_forward_upstream_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<UpstreamExitForwardCodec> {
    request_response::Behaviour::with_codec(
        UpstreamExitForwardCodec,
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(EXIT_FORWARD_UPSTREAM_PROTOCOL), support)),
        request_response::Config::default()
            .with_request_timeout(EXIT_FORWARD_UPSTREAM_TIMEOUT)
            .with_max_concurrent_streams(MAX_CONCURRENT_FORWARDING_STREAMS),
    )
}

#[async_trait]
impl request_response::Codec for ExitForwardCodec {
    type Protocol = StreamProtocol;
    type Request = ExitForwardRequest;
    type Response = ExitForwardResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_PROTOCOL)?;
        let request = read_request(io).await?;
        request.validate_client_hop().map_err(invalid_data)?;
        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_PROTOCOL)?;
        read_response(io).await
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_PROTOCOL)?;
        request.validate_client_hop().map_err(invalid_data)?;
        write_request(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_PROTOCOL)?;
        write_response(io, &response).await
    }
}

#[async_trait]
impl request_response::Codec for UpstreamExitForwardCodec {
    type Protocol = StreamProtocol;
    type Request = UpstreamExitForwardRequest;
    type Response = UpstreamExitForwardResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_UPSTREAM_PROTOCOL)?;
        read_request(io).await.map(Into::into)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_UPSTREAM_PROTOCOL)?;
        read_response(io).await.map(Into::into)
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_UPSTREAM_PROTOCOL)?;
        write_request(io, request.as_forward_request()).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        require_protocol(protocol, EXIT_FORWARD_UPSTREAM_PROTOCOL)?;
        write_response(io, response.as_forward_response()).await
    }
}

async fn read_request<T>(io: &mut T) -> io::Result<ExitForwardRequest>
where
    T: AsyncRead + Unpin + Send,
{
    let encoded = read_bounded(io).await?;
    let request =
        decode_canonical::<ExitForwardRequest>(&encoded, frame_limit()).map_err(invalid_data)?;
    request.validate().map_err(invalid_data)?;
    Ok(request)
}

async fn read_response<T>(io: &mut T) -> io::Result<ExitForwardResponse>
where
    T: AsyncRead + Unpin + Send,
{
    let encoded = read_bounded(io).await?;
    let response =
        decode_canonical::<ExitForwardResponse>(&encoded, frame_limit()).map_err(invalid_data)?;
    response.validate().map_err(invalid_data)?;
    Ok(response)
}

async fn write_request<T>(io: &mut T, request: &ExitForwardRequest) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    request.validate().map_err(invalid_data)?;
    let encoded = encode_canonical(request, frame_limit()).map_err(invalid_data)?;
    io.write_all(&encoded).await
}

async fn write_response<T>(io: &mut T, response: &ExitForwardResponse) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    response.validate().map_err(invalid_data)?;
    let encoded = encode_canonical(response, frame_limit()).map_err(invalid_data)?;
    io.write_all(&encoded).await
}

async fn read_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut encoded = Vec::new();
    io.take(MAX_FORWARDING_FRAME_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)
        .await?;
    if encoded.is_empty() || encoded.len() > frame_limit() {
        return Err(invalid_data(ForwardingRpcError::InvalidFrame));
    }
    Ok(encoded)
}

fn validate_granted_responses(
    operation: ExitForwardOperation,
    responses: &[Vec<u8>],
) -> Result<(), ForwardingRpcError> {
    match operation {
        ExitForwardOperation::FetchExitAdvertisement => {
            validate_exact_types(responses, &[ControlMessageType::NodeAdvertisement])
        }
        ExitForwardOperation::CapacityHold => validate_exact_types(
            responses,
            &[
                ControlMessageType::ClientSessionCapability,
                ControlMessageType::ExitCapacityHold,
            ],
        ),
        ExitForwardOperation::ProbePermit => {
            validate_exact_types(responses, &[ControlMessageType::RelayProbePermit])
        }
        ExitForwardOperation::FinalizeReservation => validate_finalized_response(responses),
        ExitForwardOperation::ConfirmRelay => {
            validate_exact_types(responses, &[ControlMessageType::ExitConfirmationReceipt])
        }
        ExitForwardOperation::NativeProbePermit => {
            validate_exact_types(responses, &[ControlMessageType::NativeProbePermit])
        }
        ExitForwardOperation::NativeProbeAuthorize => {
            validate_exact_types(responses, &[ControlMessageType::RelayAuthorization])
        }
        ExitForwardOperation::NativeProbeReady => {
            validate_exact_types(responses, &[ControlMessageType::NativeProbeExitReady])
        }
        ExitForwardOperation::NativeProbeResult => {
            validate_exact_types(responses, &[ControlMessageType::NativeProbeExitResult])
        }
        ExitForwardOperation::UdpSessionStart => validate_udp_session_signal(responses),
        ExitForwardOperation::MptcpSessionStart => validate_mptcp_session_signal(responses),
        ExitForwardOperation::MpquicSessionStart => validate_mpquic_session_signal(responses),
        ExitForwardOperation::Unspecified => Err(ForwardingRpcError::InvalidOperation(0)),
    }
}

fn validate_exact_types(
    responses: &[Vec<u8>],
    expected: &[ControlMessageType],
) -> Result<(), ForwardingRpcError> {
    if responses.len() != expected.len() {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    for (encoded, expected) in responses.iter().zip(expected) {
        validate_signed_type(encoded, *expected)?;
    }
    Ok(())
}

fn validate_finalized_response(responses: &[Vec<u8>]) -> Result<(), ForwardingRpcError> {
    if !(2..=MAX_RELAY_PATHS + 1).contains(&responses.len()) {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    let exit_envelope = validate_signed_type(&responses[0], ControlMessageType::ExitReservation)?;
    let exit =
        decode_canonical::<ExitReservation>(&exit_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
            .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    let expected_paths =
        usize::try_from(exit.maximum_paths).map_err(|_| ForwardingRpcError::InvalidFrame)?;
    if !(1..=MAX_RELAY_PATHS).contains(&expected_paths)
        || responses.len() != expected_paths.saturating_add(1)
    {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    let mut previous_path_id = 0;
    for encoded in &responses[1..] {
        let envelope = validate_signed_type(encoded, ControlMessageType::RelayAuthorization)?;
        let authorization =
            decode_canonical::<RelayAuthorization>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
                .map_err(|_| ForwardingRpcError::InvalidFrame)?;
        if !(1..=u32::try_from(MAX_RELAY_PATHS).unwrap_or(u32::MAX))
            .contains(&authorization.path_id)
            || authorization.path_id <= previous_path_id
        {
            return Err(ForwardingRpcError::InvalidFrame);
        }
        previous_path_id = authorization.path_id;
    }
    Ok(())
}

fn validate_signed_type(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<SignedEnvelope, ForwardingRpcError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32 {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    Ok(envelope)
}

fn validate_control_advertisement(request: &ExitForwardRequest) -> Result<(), ForwardingRpcError> {
    if request.control_advertisement.is_empty() {
        return Ok(());
    }
    if request.validated_operation()? != ExitForwardOperation::NativeProbePermit {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    let envelope = validate_signed_type(
        &request.control_advertisement,
        ControlMessageType::NodeAdvertisement,
    )?;
    let advertisement =
        decode_canonical::<NodeAdvertisement>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
            .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    advertisement
        .validate()
        .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    advertisement
        .validate_envelope(&envelope)
        .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    if envelope.sender_id != request.control_relay_node_id
        || envelope.sender_public_key != request.control_relay_public_key
        || advertisement.peer_id != request.control_relay_peer_id
        || !advertisement
            .roles
            .as_ref()
            .is_some_and(|roles| roles.relay)
    {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    Ok(())
}

fn request_type(operation: ExitForwardOperation) -> Result<ControlMessageType, ForwardingRpcError> {
    match operation {
        ExitForwardOperation::CapacityHold => Ok(ControlMessageType::ExitCapacityHoldRequest),
        ExitForwardOperation::ProbePermit => Ok(ControlMessageType::RelayProbePermitRequest),
        ExitForwardOperation::FinalizeReservation => {
            Ok(ControlMessageType::ExitReservationFinalizeRequest)
        }
        ExitForwardOperation::ConfirmRelay => Ok(ControlMessageType::ExitReservationConfirmation),
        ExitForwardOperation::NativeProbePermit => Ok(ControlMessageType::NativeProbePermitRequest),
        ExitForwardOperation::FetchExitAdvertisement
        | ExitForwardOperation::NativeProbeAuthorize
        | ExitForwardOperation::NativeProbeReady
        | ExitForwardOperation::NativeProbeResult
        | ExitForwardOperation::UdpSessionStart
        | ExitForwardOperation::MptcpSessionStart
        | ExitForwardOperation::MpquicSessionStart
        | ExitForwardOperation::Unspecified => {
            Err(ForwardingRpcError::InvalidOperation(operation as i32))
        }
    }
}

fn validate_udp_session_signal(responses: &[Vec<u8>]) -> Result<(), ForwardingRpcError> {
    let [encoded] = responses else {
        return Err(ForwardingRpcError::InvalidFrame);
    };
    decode_canonical::<crate::UdpExitSessionSignal>(encoded, frame_limit())
        .map_err(|_| ForwardingRpcError::InvalidFrame)?
        .validate()
        .map_err(|_| ForwardingRpcError::InvalidFrame)
}

fn validate_mptcp_session_signal(responses: &[Vec<u8>]) -> Result<(), ForwardingRpcError> {
    let [encoded] = responses else {
        return Err(ForwardingRpcError::InvalidFrame);
    };
    decode_canonical::<crate::ExitMptcpSessionSignal>(encoded, frame_limit())
        .map_err(|_| ForwardingRpcError::InvalidFrame)?
        .validate()
        .map_err(|_| ForwardingRpcError::InvalidFrame)
}

fn validate_mpquic_session_signal(responses: &[Vec<u8>]) -> Result<(), ForwardingRpcError> {
    let [encoded] = responses else {
        return Err(ForwardingRpcError::InvalidFrame);
    };
    decode_canonical::<crate::ExitMpquicSessionSignal>(encoded, frame_limit())
        .map_err(|_| ForwardingRpcError::InvalidFrame)?
        .validate()
        .map_err(|_| ForwardingRpcError::InvalidFrame)
}

fn validate_native_probe_authorization_chain(encoded: &[u8]) -> Result<(), ForwardingRpcError> {
    let chain = decode_canonical::<NativeProbeAuthorizationChain>(
        encoded,
        MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE,
    )
    .map_err(|_| ForwardingRpcError::InvalidFrame)?;
    for (signed, expected) in [
        (
            chain.signed_permit_request.as_slice(),
            ControlMessageType::NativeProbePermitRequest,
        ),
        (
            chain.signed_permit.as_slice(),
            ControlMessageType::NativeProbePermit,
        ),
        (
            chain.signed_exit_ready.as_slice(),
            ControlMessageType::NativeProbeExitReady,
        ),
        (
            chain.signed_relay_ready.as_slice(),
            ControlMessageType::NativeProbeRelayReady,
        ),
        (
            chain.signed_start.as_slice(),
            ControlMessageType::NativeProbeStart,
        ),
    ] {
        validate_signed_type(signed, expected)?;
    }
    Ok(())
}

fn validate_version(version: u32) -> Result<(), ForwardingRpcError> {
    if version != FORWARDING_RPC_VERSION {
        return Err(ForwardingRpcError::UnsupportedVersion(version));
    }
    Ok(())
}

fn validate_fixed_nonzero<const N: usize>(value: &[u8]) -> Result<(), ForwardingRpcError> {
    if value.len() != N || value.iter().all(|byte| *byte == 0) {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_peer_id(value: &[u8]) -> Result<PeerId, ForwardingRpcError> {
    if value.is_empty() || value.len() > MAX_PEER_ID_LENGTH {
        return Err(ForwardingRpcError::InvalidFrame);
    }
    PeerId::from_bytes(value).map_err(|_| ForwardingRpcError::InvalidFrame)
}

fn require_protocol(protocol: &StreamProtocol, expected: &str) -> io::Result<()> {
    if protocol.as_ref() != expected {
        return Err(invalid_data(ForwardingRpcError::UnsupportedVersion(0)));
    }
    Ok(())
}

fn frame_limit() -> usize {
    usize::try_from(MAX_FORWARDING_FRAME_BYTES).unwrap_or(usize::MAX)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;
    use volparossa_protocol::WireguardEndpoint;

    use super::*;

    const DEADLINE: u64 = 1_700_000_012_000;

    #[tokio::test]
    async fn control_advertisement_is_upstream_only_and_preserves_client_request_bytes() {
        let (request, advertisement) = native_permit_control_fixture();
        let client_request = request.canonical_request().to_vec();
        let plain = encode_canonical(&request, frame_limit()).expect("plain request");
        assert!(request.control_advertisement().is_empty());
        // Compare with the pre-extension field sequence: an empty tag 11 is absent on wire.
        let mut explicit_empty = plain.clone();
        explicit_empty.extend_from_slice(&[0x5a, 0]);
        assert!(decode_canonical::<ExitForwardRequest>(&explicit_empty, frame_limit()).is_err());

        let upstream = UpstreamExitForwardRequest::from(request)
            .with_control_advertisement(advertisement.clone())
            .expect("bounded signed Relay advertisement");
        assert_eq!(
            upstream.as_forward_request().canonical_request(),
            client_request
        );
        assert_eq!(
            upstream.as_forward_request().control_advertisement(),
            advertisement
        );
        let mut wire = Cursor::new(Vec::new());
        let mut codec = UpstreamExitForwardCodec;
        let protocol = StreamProtocol::new(EXIT_FORWARD_UPSTREAM_PROTOCOL);
        codec
            .write_request(&protocol, &mut wire, upstream.clone())
            .await
            .expect("upstream write");
        let decoded = codec
            .read_request(&protocol, &mut Cursor::new(wire.get_ref()))
            .await
            .expect("upstream read");
        assert_eq!(decoded, upstream);

        let mut client = ExitForwardCodec;
        let protocol = StreamProtocol::new(EXIT_FORWARD_PROTOCOL);
        assert!(
            client
                .read_request(&protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .is_err()
        );
        assert!(
            client
                .write_request(
                    &protocol,
                    &mut Cursor::new(Vec::new()),
                    upstream.into_forward_request()
                )
                .await
                .is_err()
        );
    }

    #[test]
    fn control_advertisement_rejects_wrong_operation_actor_type_and_bounds() {
        let (request, advertisement) = native_permit_control_fixture();
        for malformed in [
            Vec::new(),
            vec![1; MAX_CONTROL_MESSAGE_SIZE + 1],
            envelope(ControlMessageType::NativeProbePermit, Vec::new()),
            envelope(ControlMessageType::NodeAdvertisement, Vec::new()),
        ] {
            assert!(
                UpstreamExitForwardRequest::from(request.clone())
                    .with_control_advertisement(malformed)
                    .is_err()
            );
        }
        assert!(
            UpstreamExitForwardRequest::from(advertisement_request())
                .with_control_advertisement(advertisement.clone())
                .is_err()
        );
        let (foreign, _) = native_permit_control_fixture();
        assert!(
            UpstreamExitForwardRequest::from(foreign)
                .with_control_advertisement(advertisement.clone())
                .is_err()
        );
        let mut noncanonical = advertisement.clone();
        noncanonical.extend_from_slice(&[0x78, 0]);
        assert!(
            UpstreamExitForwardRequest::from(request.clone())
                .with_control_advertisement(noncanonical)
                .is_err()
        );
        let attached = UpstreamExitForwardRequest::from(request)
            .with_control_advertisement(advertisement.clone())
            .unwrap();
        assert!(attached.with_control_advertisement(advertisement).is_err());
    }

    fn native_permit_control_fixture() -> (ExitForwardRequest, Vec<u8>) {
        use volparossa_protocol::{
            AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork,
            AdvertisementPolicy, AdvertisementQuality, AdvertisementRoles, TimePolicy,
            sign_control_message_with,
        };

        let key = identity::Keypair::generate_ed25519();
        let public = key.public().try_into_ed25519().unwrap().to_bytes();
        let mut request = advertisement_request();
        request.control_relay_node_id = node_id_from_public_key(&public).to_vec();
        request.control_relay_public_key = public.to_vec();
        request.control_relay_peer_id = key.public().to_peer_id().to_bytes();
        request.exit_node_id = vec![9; NODE_ID_LENGTH];
        request.operation = ExitForwardOperation::NativeProbePermit as i32;
        request.canonical_request =
            envelope(ControlMessageType::NativeProbePermitRequest, Vec::new());
        let advertisement = NodeAdvertisement {
            node_id: request.control_relay_node_id.clone(),
            peer_id: request.control_relay_peer_id.clone(),
            sequence_number: 1,
            roles: Some(AdvertisementRoles {
                relay: true,
                ..Default::default()
            }),
            capabilities: Some(AdvertisementCapabilities {
                tcp_mptcp: true,
                ipv4: true,
                ..Default::default()
            }),
            control_addresses: vec!["/ip4/8.8.4.4/udp/4001/quic-v1".to_owned()],
            capacity: Some(AdvertisementCapacity {
                operator_relay_limit_up_mbps: 1,
                operator_relay_limit_down_mbps: 1,
                estimated_free_up_mbps: 1,
                estimated_free_down_mbps: 1,
                free_relay_slots: 1,
                sample_window_seconds: 15,
                ..Default::default()
            }),
            network: Some(AdvertisementNetwork {
                region: "eu".to_owned(),
                country_code: "NL".to_owned(),
                asn: 64510,
                ipv4_prefix_hint: "8.8.4.0/24".to_owned(),
                operator_id: "test-relay".to_owned(),
                ..Default::default()
            }),
            quality: Some(AdvertisementQuality::default()),
            policy: Some(AdvertisementPolicy {
                whitelist_version: 1,
                whitelist_hash: vec![1; 32],
            }),
            measured_at_ms: 1,
            expires_at_ms: 2,
        };
        let signed = sign_control_message_with(
            &advertisement,
            public,
            1,
            2,
            [1; 32],
            TimePolicy::default(),
            |message| key.sign(message).ok()?.try_into().ok(),
        )
        .expect("signed self advertisement");
        (request, signed)
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "both hop codecs share one wire regression"
    )]
    async fn codecs_are_canonical_bounded_hop_distinct_and_wire_identical() {
        let request = advertisement_request();
        let protocol = StreamProtocol::new(EXIT_FORWARD_PROTOCOL);
        let upstream_protocol = StreamProtocol::new(EXIT_FORWARD_UPSTREAM_PROTOCOL);
        let mut client_codec = ExitForwardCodec;
        let mut upstream_codec = UpstreamExitForwardCodec;

        let mut client_bytes = Cursor::new(Vec::new());
        client_codec
            .write_request(&protocol, &mut client_bytes, request.clone())
            .await
            .expect("client request");
        let mut upstream_bytes = Cursor::new(Vec::new());
        upstream_codec
            .write_request(
                &upstream_protocol,
                &mut upstream_bytes,
                request.clone().into(),
            )
            .await
            .expect("upstream request");
        assert_eq!(client_bytes.get_ref(), upstream_bytes.get_ref());

        let raw = client_bytes.into_inner();
        let decoded = client_codec
            .read_request(&protocol, &mut Cursor::new(raw.clone()))
            .await
            .expect("canonical request");
        assert_eq!(decoded, request);
        assert!(raw.len() <= frame_limit());

        let upstream_decoded = upstream_codec
            .read_request(&upstream_protocol, &mut Cursor::new(raw.clone()))
            .await
            .expect("canonical upstream request");
        assert_eq!(upstream_decoded.as_forward_request(), &request);

        let response = ExitForwardResponse::rejected(
            request.forward_id().to_vec(),
            ExitForwardOperation::FetchExitAdvertisement,
            vec![9; NODE_ID_LENGTH],
            request.exit_peer_id().to_vec(),
        )
        .expect("response");
        let mut client_response_bytes = Cursor::new(Vec::new());
        client_codec
            .write_response(&protocol, &mut client_response_bytes, response.clone())
            .await
            .expect("client response");
        let mut upstream_response_bytes = Cursor::new(Vec::new());
        upstream_codec
            .write_response(
                &upstream_protocol,
                &mut upstream_response_bytes,
                response.clone().into(),
            )
            .await
            .expect("upstream response");
        assert_eq!(
            client_response_bytes.get_ref(),
            upstream_response_bytes.get_ref()
        );
        let canonical_response = client_response_bytes.into_inner();
        assert_eq!(
            client_codec
                .read_response(&protocol, &mut Cursor::new(canonical_response.clone()))
                .await
                .expect("canonical client response"),
            response
        );
        assert_eq!(
            upstream_codec
                .read_response(&upstream_protocol, &mut Cursor::new(canonical_response),)
                .await
                .expect("canonical upstream response")
                .as_forward_response(),
            &response
        );

        for wrong in [
            "/volparossa/exit-forward/1",
            "/volparossa/exit-forward/2",
            "/volparossa/exit-forward/3",
            EXIT_FORWARD_UPSTREAM_PROTOCOL,
        ] {
            assert!(
                client_codec
                    .read_request(
                        &StreamProtocol::try_from_owned(wrong.to_owned()).expect("protocol"),
                        &mut Cursor::new(raw.clone()),
                    )
                    .await
                    .is_err()
            );
        }

        for wrong in [
            "/volparossa/exit-forward-upstream/1",
            "/volparossa/exit-forward-upstream/2",
            "/volparossa/exit-forward-upstream/3",
            EXIT_FORWARD_PROTOCOL,
        ] {
            assert!(
                upstream_codec
                    .read_request(
                        &StreamProtocol::try_from_owned(wrong.to_owned()).expect("protocol"),
                        &mut Cursor::new(raw.clone()),
                    )
                    .await
                    .is_err()
            );
        }

        let mut noncanonical = raw.clone();
        noncanonical.extend_from_slice(&[0x58, 0x01]);
        assert!(
            client_codec
                .read_request(&protocol, &mut Cursor::new(noncanonical))
                .await
                .is_err()
        );
        let mut oversized = Cursor::new(vec![0xff; frame_limit() + 1]);
        assert!(
            client_codec
                .read_request(&protocol, &mut oversized)
                .await
                .is_err()
        );
        assert_eq!(oversized.position(), MAX_FORWARDING_FRAME_BYTES + 1);
    }

    #[test]
    fn versions_operations_identities_and_request_types_fail_closed() {
        let mut request = advertisement_request();
        for version in [1, 2, 3, 5] {
            request.rpc_version = version;
            assert!(matches!(
                request.validate(),
                Err(ForwardingRpcError::UnsupportedVersion(value)) if value == version
            ));
        }
        request.rpc_version = FORWARDING_RPC_VERSION;
        request.operation = 99;
        assert!(matches!(
            request.validate(),
            Err(ForwardingRpcError::InvalidOperation(99))
        ));

        let (relay_node, relay_peer, relay_public) = relay_identity();
        let exit_peer = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        for (operation, expected_type) in [
            (
                ExitForwardOperation::CapacityHold,
                ControlMessageType::ExitCapacityHoldRequest,
            ),
            (
                ExitForwardOperation::ProbePermit,
                ControlMessageType::RelayProbePermitRequest,
            ),
            (
                ExitForwardOperation::FinalizeReservation,
                ControlMessageType::ExitReservationFinalizeRequest,
            ),
            (
                ExitForwardOperation::ConfirmRelay,
                ControlMessageType::ExitReservationConfirmation,
            ),
            (
                ExitForwardOperation::NativeProbePermit,
                ControlMessageType::NativeProbePermitRequest,
            ),
        ] {
            let request = ExitForwardRequest::new(
                vec![1; REQUEST_ID_LENGTH],
                relay_node.clone(),
                relay_peer.clone(),
                relay_public.clone(),
                exit_peer.clone(),
                vec![2; NODE_ID_LENGTH],
                DEADLINE,
                operation,
                envelope(expected_type, Vec::new()),
            )
            .expect("valid operation mapping");
            assert_eq!(request.validated_operation().expect("operation"), operation);
        }

        let native_chain = native_authorization_chain();
        let request = ExitForwardRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node.clone(),
            relay_peer.clone(),
            relay_public.clone(),
            exit_peer.clone(),
            vec![2; NODE_ID_LENGTH],
            DEADLINE,
            ExitForwardOperation::NativeProbeAuthorize,
            native_chain,
        )
        .expect("valid native authorization chain mapping");
        assert_eq!(
            request.validated_operation().expect("operation"),
            ExitForwardOperation::NativeProbeAuthorize
        );

        let wrong_type = ExitForwardRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node,
            relay_peer,
            relay_public,
            exit_peer,
            vec![2; NODE_ID_LENGTH],
            DEADLINE,
            ExitForwardOperation::CapacityHold,
            envelope(ControlMessageType::RelayProbePermitRequest, Vec::new()),
        );
        assert!(matches!(wrong_type, Err(ForwardingRpcError::InvalidFrame)));
    }

    #[test]
    fn native_ready_request_is_bounded_typed_and_endpoint_complete() {
        let (relay_node, relay_peer, relay_public) = relay_identity();
        let exit_peer = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        let native_ready = NativeProbeReadyForwardRequest::new(
            envelope(ControlMessageType::NativeProbePermitRequest, Vec::new()),
            envelope(ControlMessageType::NativeProbePermit, Vec::new()),
            native_endpoint_binding(),
            envelope(ControlMessageType::NodeAdvertisement, Vec::new()),
        )
        .expect("native ready frame");
        let request = ExitForwardRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node,
            relay_peer,
            relay_public,
            exit_peer,
            vec![2; NODE_ID_LENGTH],
            DEADLINE,
            ExitForwardOperation::NativeProbeReady,
            encode_canonical(&native_ready, frame_limit()).expect("native ready request"),
        )
        .expect("valid native readiness mapping");
        assert_eq!(
            request.validated_operation().expect("operation"),
            ExitForwardOperation::NativeProbeReady
        );

        let mut invalid_binding = native_endpoint_binding();
        invalid_binding.prepared_lease_commitment.fill(0);
        assert!(matches!(
            NativeProbeReadyForwardRequest::new(
                envelope(ControlMessageType::NativeProbePermitRequest, Vec::new()),
                envelope(ControlMessageType::NativeProbePermit, Vec::new()),
                invalid_binding,
                envelope(ControlMessageType::NodeAdvertisement, Vec::new()),
            ),
            Err(ForwardingRpcError::InvalidFrame)
        ));
        assert!(matches!(
            NativeProbeReadyForwardRequest::new(
                envelope(ControlMessageType::NativeProbePermitRequest, Vec::new()),
                envelope(ControlMessageType::NativeProbePermit, Vec::new()),
                native_endpoint_binding(),
                envelope(ControlMessageType::NativeProbeExitReady, Vec::new()),
            ),
            Err(ForwardingRpcError::InvalidFrame)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "operation cardinalities form one matrix"
    )]
    fn response_status_and_operation_cardinality_are_exact() {
        let exit_peer = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        let forward_id = vec![1; REQUEST_ID_LENGTH];
        let exit_node = vec![2; NODE_ID_LENGTH];

        let advertisement = ExitForwardResponse::granted(
            forward_id.clone(),
            ExitForwardOperation::FetchExitAdvertisement,
            exit_node.clone(),
            exit_peer.clone(),
            vec![envelope(ControlMessageType::NodeAdvertisement, Vec::new())],
        )
        .expect("advertisement response");
        assert_eq!(
            advertisement.validated_status().expect("status"),
            ForwardStatus::Granted
        );

        let hold = ExitForwardResponse::granted(
            forward_id.clone(),
            ExitForwardOperation::CapacityHold,
            exit_node.clone(),
            exit_peer.clone(),
            vec![
                envelope(ControlMessageType::ClientSessionCapability, Vec::new()),
                envelope(ControlMessageType::ExitCapacityHold, Vec::new()),
            ],
        );
        assert!(hold.is_ok());

        let rejected = ExitForwardResponse::rejected(
            forward_id.clone(),
            ExitForwardOperation::CapacityHold,
            exit_node.clone(),
            exit_peer.clone(),
        )
        .expect("rejected");
        assert_eq!(
            rejected.validated_status().expect("status"),
            ForwardStatus::Rejected
        );
        let unavailable = ExitForwardResponse::unavailable(
            forward_id.clone(),
            ExitForwardOperation::CapacityHold,
            exit_node.clone(),
            exit_peer.clone(),
        )
        .expect("unavailable");
        assert_eq!(
            unavailable.validated_status().expect("status"),
            ForwardStatus::Unavailable
        );

        let mut leaked = unavailable;
        leaked.signed_responses = vec![envelope(ControlMessageType::ExitCapacityHold, Vec::new())];
        assert!(matches!(
            leaked.validate(),
            Err(ForwardingRpcError::InvalidFrame)
        ));

        let wrong_cardinality = ExitForwardResponse::granted(
            forward_id.clone(),
            ExitForwardOperation::ConfirmRelay,
            exit_node.clone(),
            exit_peer.clone(),
            Vec::new(),
        );
        assert!(matches!(
            wrong_cardinality,
            Err(ForwardingRpcError::InvalidFrame)
        ));

        let exit_payload = ExitReservation {
            maximum_paths: 2,
            ..ExitReservation::default()
        };
        let authorization_one = RelayAuthorization {
            path_id: 1,
            ..RelayAuthorization::default()
        };
        let authorization_two = RelayAuthorization {
            path_id: 2,
            ..RelayAuthorization::default()
        };
        let finalized = ExitForwardResponse::granted(
            forward_id.clone(),
            ExitForwardOperation::FinalizeReservation,
            exit_node.clone(),
            exit_peer.clone(),
            vec![
                envelope(
                    ControlMessageType::ExitReservation,
                    encode_canonical(&exit_payload, MAX_CONTROL_PAYLOAD_SIZE).expect("payload"),
                ),
                envelope(
                    ControlMessageType::RelayAuthorization,
                    encode_canonical(&authorization_one, MAX_CONTROL_PAYLOAD_SIZE)
                        .expect("payload"),
                ),
                envelope(
                    ControlMessageType::RelayAuthorization,
                    encode_canonical(&authorization_two, MAX_CONTROL_PAYLOAD_SIZE)
                        .expect("payload"),
                ),
            ],
        );
        assert!(finalized.is_ok());

        let receipt = ExitForwardResponse::granted(
            forward_id,
            ExitForwardOperation::ConfirmRelay,
            exit_node,
            exit_peer,
            vec![envelope(
                ControlMessageType::ExitConfirmationReceipt,
                Vec::new(),
            )],
        );
        assert!(receipt.is_ok());

        let native_exit_peer = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        let native_permit = ExitForwardResponse::granted(
            vec![1; REQUEST_ID_LENGTH],
            ExitForwardOperation::NativeProbePermit,
            vec![2; NODE_ID_LENGTH],
            native_exit_peer.clone(),
            vec![envelope(ControlMessageType::NativeProbePermit, Vec::new())],
        );
        assert!(native_permit.is_ok());
        for responses in [
            Vec::new(),
            vec![
                envelope(ControlMessageType::NativeProbePermit, Vec::new()),
                envelope(ControlMessageType::NativeProbePermit, Vec::new()),
            ],
            vec![envelope(ControlMessageType::RelayProbePermit, Vec::new())],
        ] {
            assert!(matches!(
                ExitForwardResponse::granted(
                    vec![1; REQUEST_ID_LENGTH],
                    ExitForwardOperation::NativeProbePermit,
                    vec![2; NODE_ID_LENGTH],
                    native_exit_peer.clone(),
                    responses,
                ),
                Err(ForwardingRpcError::InvalidFrame)
            ));
        }

        let native_authorization = ExitForwardResponse::granted(
            vec![1; REQUEST_ID_LENGTH],
            ExitForwardOperation::NativeProbeAuthorize,
            vec![2; NODE_ID_LENGTH],
            native_exit_peer.clone(),
            vec![envelope(ControlMessageType::RelayAuthorization, Vec::new())],
        );
        assert!(native_authorization.is_ok());
        let native_ready = ExitForwardResponse::granted(
            vec![1; REQUEST_ID_LENGTH],
            ExitForwardOperation::NativeProbeReady,
            vec![2; NODE_ID_LENGTH],
            native_exit_peer.clone(),
            vec![envelope(
                ControlMessageType::NativeProbeExitReady,
                Vec::new(),
            )],
        );
        assert!(native_ready.is_ok());
        assert!(matches!(
            ExitForwardResponse::granted(
                vec![1; REQUEST_ID_LENGTH],
                ExitForwardOperation::NativeProbeAuthorize,
                vec![2; NODE_ID_LENGTH],
                native_exit_peer,
                vec![envelope(ControlMessageType::NativeProbePermit, Vec::new())],
            ),
            Err(ForwardingRpcError::InvalidFrame)
        ));
    }

    fn native_authorization_chain() -> Vec<u8> {
        encode_canonical(
            &NativeProbeAuthorizationChain {
                signed_permit_request: envelope(
                    ControlMessageType::NativeProbePermitRequest,
                    Vec::new(),
                ),
                signed_permit: envelope(ControlMessageType::NativeProbePermit, Vec::new()),
                signed_exit_ready: envelope(ControlMessageType::NativeProbeExitReady, Vec::new()),
                signed_relay_ready: envelope(ControlMessageType::NativeProbeRelayReady, Vec::new()),
                signed_start: envelope(ControlMessageType::NativeProbeStart, Vec::new()),
            },
            MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE,
        )
        .expect("native authorization chain")
    }

    fn native_endpoint_binding() -> NativeProbeEndpointBinding {
        NativeProbeEndpointBinding {
            helper_runtime_id: vec![3; NODE_ID_LENGTH],
            route_context_id: vec![4; REQUEST_ID_LENGTH],
            endpoint: Some(WireguardEndpoint {
                underlay_scope: 0,
                public_key: vec![5; PUBLIC_KEY_LENGTH],
                underlay_ip: vec![8, 8, 8, 8],
                listen_port: 40_001,
            }),
            prepared_lease_commitment: vec![6; NODE_ID_LENGTH],
            path_id: 1,
        }
    }

    fn advertisement_request() -> ExitForwardRequest {
        let (relay_node, relay_peer, relay_public) = relay_identity();
        let exit_peer = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        ExitForwardRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node,
            relay_peer,
            relay_public,
            exit_peer,
            Vec::new(),
            DEADLINE,
            ExitForwardOperation::FetchExitAdvertisement,
            Vec::new(),
        )
        .expect("advertisement request")
    }

    fn relay_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = identity::Keypair::generate_ed25519();
        let public = key
            .clone()
            .try_into_ed25519()
            .expect("Ed25519")
            .public()
            .to_bytes();
        (
            node_id_from_public_key(&public).to_vec(),
            key.public().to_peer_id().to_bytes(),
            public.to_vec(),
        )
    }

    fn envelope(message_type: ControlMessageType, payload: Vec<u8>) -> Vec<u8> {
        encode_canonical(
            &SignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                sender_id: vec![3; NODE_ID_LENGTH],
                sender_public_key: vec![4; PUBLIC_KEY_LENGTH],
                timestamp_ms: 1,
                expires_at_ms: 2,
                nonce: vec![5; 32],
                message_type: message_type as i32,
                payload,
                payload_hash: vec![6; 32],
                signature: vec![7; 64],
            },
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("envelope")
    }
}
