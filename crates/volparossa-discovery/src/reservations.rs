//! Canonical, bounded client-to-datapath-relay request-response frames.

use std::{io, time::Duration};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol, request_response};
use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, SignedEnvelope,
    decode_canonical, encode_canonical,
};

use crate::forwarding::ForwardStatus;

/// Direct client-to-datapath-relay protocol.
pub const DATAPATH_RELAY_PROTOCOL: &str = "/volparossa/datapath-relay/4";
/// Retired direct client-to-exit v2 protocol, retained only for refusal tests.
pub const LEGACY_EXIT_RESERVATION_PROTOCOL_V2: &str = "/volparossa/reservation/exit/2";
/// Retired direct client-to-relay v2 protocol, retained only for refusal tests.
pub const LEGACY_RELAY_RESERVATION_PROTOCOL_V2: &str = "/volparossa/reservation/relay/2";
/// Retired direct client-to-exit confirmation v2 protocol, retained only for refusal tests.
pub const LEGACY_EXIT_CONFIRMATION_PROTOCOL_V2: &str =
    "/volparossa/reservation/exit-confirmation/2";
/// Exact datapath-relay RPC schema version.
pub const DATAPATH_RELAY_RPC_VERSION: u32 = 4;
/// Fixed direct datapath-relay transport timeout.
pub const DATAPATH_RELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum combined inbound and outbound datapath-relay streams.
pub const MAX_CONCURRENT_DATAPATH_RELAY_STREAMS: usize = 64;
/// Maximum canonical datapath-relay request or response frame size.
pub const MAX_DATAPATH_RELAY_FRAME_BYTES: u64 = 512 * 1024;

const REQUEST_ID_LENGTH: usize = 16;
const NODE_ID_LENGTH: usize = 32;
const MAX_PEER_ID_LENGTH: usize = 64;

/// Direct operation addressed to one selected datapath relay.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum DatapathRelayOperation {
    Unspecified = 0,
    /// Wire framing only. Production remains unavailable until a safe probe handshake exists.
    ExecuteProbe = 1,
    ReservePath = 2,
}

/// Canonical direct datapath-relay request.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct DatapathRelayRequest {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    request_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    relay_peer_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    deadline_unix_ms: u64,
    #[prost(enumeration = "DatapathRelayOperation", tag = "6")]
    operation: i32,
    #[prost(bytes = "vec", tag = "7")]
    client_signed_request: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    exit_signed_authorization: Vec<u8>,
}

impl DatapathRelayRequest {
    /// Construct one direct, operation-specific relay request.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, discriminators, signed-envelope
    /// types, or fixed resource bounds.
    #[allow(clippy::too_many_arguments, reason = "fixed flat protobuf schema")]
    pub fn new(
        request_id: Vec<u8>,
        relay_node_id: Vec<u8>,
        relay_peer_id: Vec<u8>,
        deadline_unix_ms: u64,
        operation: DatapathRelayOperation,
        client_signed_request: Vec<u8>,
        exit_signed_authorization: Vec<u8>,
    ) -> Result<Self, DatapathRelayRpcError> {
        let request = Self {
            rpc_version: DATAPATH_RELAY_RPC_VERSION,
            request_id,
            relay_node_id,
            relay_peer_id,
            deadline_unix_ms,
            operation: operation as i32,
            client_signed_request,
            exit_signed_authorization,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate canonical wrapper invariants without claiming probe readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, ambiguous, oversized, or wrong-type input.
    pub fn validate(&self) -> Result<(), DatapathRelayRpcError> {
        validate_version(self.rpc_version)?;
        validate_fixed_nonzero::<REQUEST_ID_LENGTH>(&self.request_id)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.relay_node_id)?;
        validate_peer_id(&self.relay_peer_id)?;
        if self.deadline_unix_ms == 0 {
            return Err(DatapathRelayRpcError::InvalidFrame);
        }
        match self.validated_operation()? {
            DatapathRelayOperation::ExecuteProbe => {
                validate_signed_type(
                    &self.client_signed_request,
                    ControlMessageType::RelayProbePermitRequest,
                )?;
                validate_signed_type(
                    &self.exit_signed_authorization,
                    ControlMessageType::RelayProbePermit,
                )
            }
            DatapathRelayOperation::ReservePath => {
                if !self.exit_signed_authorization.is_empty() {
                    return Err(DatapathRelayRpcError::InvalidFrame);
                }
                validate_signed_type(
                    &self.client_signed_request,
                    ControlMessageType::RelayReservationRequest,
                )
            }
            DatapathRelayOperation::Unspecified => {
                Err(DatapathRelayRpcError::InvalidOperation(self.operation))
            }
        }
    }

    /// Stable direct-RPC idempotency identifier.
    #[must_use]
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }

    /// Selected relay node identifier.
    #[must_use]
    pub fn relay_node_id(&self) -> &[u8] {
        &self.relay_node_id
    }

    /// Selected relay libp2p peer identifier.
    #[must_use]
    pub fn relay_peer_id(&self) -> &[u8] {
        &self.relay_peer_id
    }

    /// Absolute application deadline.
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    /// Validated operation discriminator.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_operation(&self) -> Result<DatapathRelayOperation, DatapathRelayRpcError> {
        let operation = DatapathRelayOperation::try_from(self.operation)
            .map_err(|_| DatapathRelayRpcError::InvalidOperation(self.operation))?;
        if operation == DatapathRelayOperation::Unspecified {
            return Err(DatapathRelayRpcError::InvalidOperation(self.operation));
        }
        Ok(operation)
    }

    /// Exact client-session-signed request envelope.
    #[must_use]
    pub fn client_signed_request(&self) -> &[u8] {
        &self.client_signed_request
    }

    /// Exact exit-signed probe permit, populated only for the probe framing operation.
    #[must_use]
    pub fn exit_signed_authorization(&self) -> &[u8] {
        &self.exit_signed_authorization
    }
}

/// Canonical response from one authenticated datapath relay.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct DatapathRelayResponse {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    request_id: Vec<u8>,
    #[prost(enumeration = "DatapathRelayOperation", tag = "3")]
    operation: i32,
    #[prost(enumeration = "ForwardStatus", tag = "4")]
    status: i32,
    #[prost(bytes = "vec", tag = "5")]
    relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    signed_response: Vec<u8>,
}

impl DatapathRelayResponse {
    /// Construct a successful response carrying one operation-specific signed envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, status, or signed response type.
    pub fn granted(
        request_id: Vec<u8>,
        operation: DatapathRelayOperation,
        relay_node_id: Vec<u8>,
        relay_peer_id: Vec<u8>,
        signed_response: Vec<u8>,
    ) -> Result<Self, DatapathRelayRpcError> {
        Self::new(
            request_id,
            operation,
            ForwardStatus::Granted,
            relay_node_id,
            relay_peer_id,
            signed_response,
        )
    }

    /// Construct a definitive, detail-free rejection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities or operation values.
    pub fn rejected(
        request_id: Vec<u8>,
        operation: DatapathRelayOperation,
        relay_node_id: Vec<u8>,
        relay_peer_id: Vec<u8>,
    ) -> Result<Self, DatapathRelayRpcError> {
        Self::new(
            request_id,
            operation,
            ForwardStatus::Rejected,
            relay_node_id,
            relay_peer_id,
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
        request_id: Vec<u8>,
        operation: DatapathRelayOperation,
        relay_node_id: Vec<u8>,
        relay_peer_id: Vec<u8>,
    ) -> Result<Self, DatapathRelayRpcError> {
        Self::new(
            request_id,
            operation,
            ForwardStatus::Unavailable,
            relay_node_id,
            relay_peer_id,
            Vec::new(),
        )
    }

    fn new(
        request_id: Vec<u8>,
        operation: DatapathRelayOperation,
        status: ForwardStatus,
        relay_node_id: Vec<u8>,
        relay_peer_id: Vec<u8>,
        signed_response: Vec<u8>,
    ) -> Result<Self, DatapathRelayRpcError> {
        let response = Self {
            rpc_version: DATAPATH_RELAY_RPC_VERSION,
            request_id,
            operation: operation as i32,
            status: status as i32,
            relay_node_id,
            relay_peer_id,
            signed_response,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate the status-dependent signed response type and fixed bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, ambiguous, oversized, or non-v4 response.
    pub fn validate(&self) -> Result<(), DatapathRelayRpcError> {
        validate_version(self.rpc_version)?;
        validate_fixed_nonzero::<REQUEST_ID_LENGTH>(&self.request_id)?;
        validate_fixed_nonzero::<NODE_ID_LENGTH>(&self.relay_node_id)?;
        validate_peer_id(&self.relay_peer_id)?;
        let operation = self.validated_operation()?;
        match self.validated_status()? {
            ForwardStatus::Granted => {
                let expected = match operation {
                    DatapathRelayOperation::ExecuteProbe => ControlMessageType::RelayProbeResult,
                    DatapathRelayOperation::ReservePath => ControlMessageType::RelayReservation,
                    DatapathRelayOperation::Unspecified => {
                        return Err(DatapathRelayRpcError::InvalidOperation(self.operation));
                    }
                };
                validate_signed_type(&self.signed_response, expected)
            }
            ForwardStatus::Rejected | ForwardStatus::Unavailable
                if self.signed_response.is_empty() =>
            {
                Ok(())
            }
            ForwardStatus::Rejected | ForwardStatus::Unavailable => {
                Err(DatapathRelayRpcError::InvalidFrame)
            }
            ForwardStatus::Unspecified => Err(DatapathRelayRpcError::InvalidStatus(self.status)),
        }
    }

    /// Stable direct-RPC identifier echoed by the relay.
    #[must_use]
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }

    /// Validated operation discriminator.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_operation(&self) -> Result<DatapathRelayOperation, DatapathRelayRpcError> {
        let operation = DatapathRelayOperation::try_from(self.operation)
            .map_err(|_| DatapathRelayRpcError::InvalidOperation(self.operation))?;
        if operation == DatapathRelayOperation::Unspecified {
            return Err(DatapathRelayRpcError::InvalidOperation(self.operation));
        }
        Ok(operation)
    }

    /// Validated detail-free status.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an unknown future discriminator.
    pub fn validated_status(&self) -> Result<ForwardStatus, DatapathRelayRpcError> {
        let status = ForwardStatus::try_from(self.status)
            .map_err(|_| DatapathRelayRpcError::InvalidStatus(self.status))?;
        if status == ForwardStatus::Unspecified {
            return Err(DatapathRelayRpcError::InvalidStatus(self.status));
        }
        Ok(status)
    }

    /// Relay node identifier.
    #[must_use]
    pub fn relay_node_id(&self) -> &[u8] {
        &self.relay_node_id
    }

    /// Relay libp2p peer identifier.
    #[must_use]
    pub fn relay_peer_id(&self) -> &[u8] {
        &self.relay_peer_id
    }

    /// Operation-specific signed response, empty for rejection or unavailability.
    #[must_use]
    pub fn signed_response(&self) -> &[u8] {
        &self.signed_response
    }
}

/// Datapath-relay frame validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DatapathRelayRpcError {
    /// The frame used an obsolete or unknown RPC version.
    #[error("unsupported datapath-relay RPC version {0}")]
    UnsupportedVersion(u32),
    /// The operation discriminator was zero or unknown.
    #[error("invalid datapath-relay operation {0}")]
    InvalidOperation(i32),
    /// The status discriminator was zero or unknown.
    #[error("invalid datapath-relay status {0}")]
    InvalidStatus(i32),
    /// The frame was empty, oversized, non-canonical, or semantically ambiguous.
    #[error("invalid canonical datapath-relay RPC frame")]
    InvalidFrame,
}

/// Canonical codec for direct datapath-relay operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct DatapathRelayCodec;

pub(crate) fn datapath_relay_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<DatapathRelayCodec> {
    request_response::Behaviour::with_codec(
        DatapathRelayCodec,
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(DATAPATH_RELAY_PROTOCOL), support)),
        request_response::Config::default()
            .with_request_timeout(DATAPATH_RELAY_REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_CONCURRENT_DATAPATH_RELAY_STREAMS),
    )
}

#[async_trait]
impl request_response::Codec for DatapathRelayCodec {
    type Protocol = StreamProtocol;
    type Request = DatapathRelayRequest;
    type Response = DatapathRelayResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol)?;
        let encoded = read_bounded(io).await?;
        let request = decode_canonical::<DatapathRelayRequest>(&encoded, frame_limit())
            .map_err(invalid_data)?;
        request.validate().map_err(invalid_data)?;
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
        require_protocol(protocol)?;
        let encoded = read_bounded(io).await?;
        let response = decode_canonical::<DatapathRelayResponse>(&encoded, frame_limit())
            .map_err(invalid_data)?;
        response.validate().map_err(invalid_data)?;
        Ok(response)
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
        require_protocol(protocol)?;
        request.validate().map_err(invalid_data)?;
        let encoded = encode_canonical(&request, frame_limit()).map_err(invalid_data)?;
        io.write_all(&encoded).await
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
        require_protocol(protocol)?;
        response.validate().map_err(invalid_data)?;
        let encoded = encode_canonical(&response, frame_limit()).map_err(invalid_data)?;
        io.write_all(&encoded).await
    }
}

async fn read_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut encoded = Vec::new();
    io.take(MAX_DATAPATH_RELAY_FRAME_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)
        .await?;
    if encoded.is_empty() || encoded.len() > frame_limit() {
        return Err(invalid_data(DatapathRelayRpcError::InvalidFrame));
    }
    Ok(encoded)
}

fn validate_signed_type(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<(), DatapathRelayRpcError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(DatapathRelayRpcError::InvalidFrame);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| DatapathRelayRpcError::InvalidFrame)?;
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32 {
        return Err(DatapathRelayRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_version(version: u32) -> Result<(), DatapathRelayRpcError> {
    if version != DATAPATH_RELAY_RPC_VERSION {
        return Err(DatapathRelayRpcError::UnsupportedVersion(version));
    }
    Ok(())
}

fn validate_fixed_nonzero<const N: usize>(value: &[u8]) -> Result<(), DatapathRelayRpcError> {
    if value.len() != N || value.iter().all(|byte| *byte == 0) {
        return Err(DatapathRelayRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_peer_id(value: &[u8]) -> Result<PeerId, DatapathRelayRpcError> {
    if value.is_empty() || value.len() > MAX_PEER_ID_LENGTH {
        return Err(DatapathRelayRpcError::InvalidFrame);
    }
    PeerId::from_bytes(value).map_err(|_| DatapathRelayRpcError::InvalidFrame)
}

fn require_protocol(protocol: &StreamProtocol) -> io::Result<()> {
    if protocol.as_ref() != DATAPATH_RELAY_PROTOCOL {
        return Err(invalid_data(DatapathRelayRpcError::UnsupportedVersion(0)));
    }
    Ok(())
}

fn frame_limit() -> usize {
    usize::try_from(MAX_DATAPATH_RELAY_FRAME_BYTES).unwrap_or(usize::MAX)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::{identity, request_response::Codec as _};

    use super::*;

    const DEADLINE: u64 = 1_700_000_005_000;

    #[tokio::test]
    async fn codec_is_canonical_bounded_and_refuses_retired_protocol_names() {
        let protocol = StreamProtocol::new(DATAPATH_RELAY_PROTOCOL);
        let mut codec = DatapathRelayCodec;
        let request = reserve_request();
        let mut encoded = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut encoded, request.clone())
            .await
            .expect("request");
        let raw = encoded.into_inner();
        assert_eq!(
            codec
                .read_request(&protocol, &mut Cursor::new(raw.clone()))
                .await
                .expect("canonical request"),
            request
        );

        for legacy in [
            LEGACY_EXIT_RESERVATION_PROTOCOL_V2,
            LEGACY_RELAY_RESERVATION_PROTOCOL_V2,
            LEGACY_EXIT_CONFIRMATION_PROTOCOL_V2,
            "/volparossa/datapath-relay/1",
            "/volparossa/datapath-relay/2",
            "/volparossa/datapath-relay/3",
        ] {
            assert!(
                codec
                    .read_request(
                        &StreamProtocol::try_from_owned(legacy.to_owned()).expect("protocol"),
                        &mut Cursor::new(raw.clone()),
                    )
                    .await
                    .is_err()
            );
        }

        let mut noncanonical = raw;
        noncanonical.extend_from_slice(&[0x48, 0x01]);
        assert!(
            codec
                .read_request(&protocol, &mut Cursor::new(noncanonical))
                .await
                .is_err()
        );
        let mut oversized = Cursor::new(vec![0xff; frame_limit() + 1]);
        assert!(codec.read_request(&protocol, &mut oversized).await.is_err());
        assert_eq!(oversized.position(), MAX_DATAPATH_RELAY_FRAME_BYTES + 1);
    }

    #[test]
    fn operation_and_status_shapes_are_exact_without_probe_readiness_claim() {
        let (relay_node, relay_peer) = relay_identity();
        let probe = DatapathRelayRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node.clone(),
            relay_peer.clone(),
            DEADLINE,
            DatapathRelayOperation::ExecuteProbe,
            envelope(ControlMessageType::RelayProbePermitRequest),
            envelope(ControlMessageType::RelayProbePermit),
        );
        assert!(probe.is_ok(), "probe framing types are representable");

        let unavailable = DatapathRelayResponse::unavailable(
            vec![1; REQUEST_ID_LENGTH],
            DatapathRelayOperation::ExecuteProbe,
            relay_node.clone(),
            relay_peer.clone(),
        )
        .expect("unavailable probe framing");
        assert_eq!(
            unavailable.validated_status().expect("status"),
            ForwardStatus::Unavailable
        );

        let reserved = DatapathRelayResponse::granted(
            vec![2; REQUEST_ID_LENGTH],
            DatapathRelayOperation::ReservePath,
            relay_node.clone(),
            relay_peer.clone(),
            envelope(ControlMessageType::RelayReservation),
        );
        assert!(reserved.is_ok());

        let leaked = DatapathRelayResponse::new(
            vec![3; REQUEST_ID_LENGTH],
            DatapathRelayOperation::ReservePath,
            ForwardStatus::Rejected,
            relay_node,
            relay_peer,
            envelope(ControlMessageType::RelayReservation),
        );
        assert!(matches!(leaked, Err(DatapathRelayRpcError::InvalidFrame)));
    }

    #[test]
    fn versions_unknown_discriminators_and_wrong_envelope_types_fail_closed() {
        let mut request = reserve_request();
        for version in [1, 2, 3, 5] {
            request.rpc_version = version;
            assert!(matches!(
                request.validate(),
                Err(DatapathRelayRpcError::UnsupportedVersion(value)) if value == version
            ));
        }
        request.rpc_version = DATAPATH_RELAY_RPC_VERSION;
        request.operation = 99;
        assert!(matches!(
            request.validate(),
            Err(DatapathRelayRpcError::InvalidOperation(99))
        ));

        let (relay_node, relay_peer) = relay_identity();
        let wrong = DatapathRelayRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node,
            relay_peer,
            DEADLINE,
            DatapathRelayOperation::ReservePath,
            envelope(ControlMessageType::RelayProbeResult),
            Vec::new(),
        );
        assert!(matches!(wrong, Err(DatapathRelayRpcError::InvalidFrame)));
    }

    fn reserve_request() -> DatapathRelayRequest {
        let (relay_node, relay_peer) = relay_identity();
        DatapathRelayRequest::new(
            vec![1; REQUEST_ID_LENGTH],
            relay_node,
            relay_peer,
            DEADLINE,
            DatapathRelayOperation::ReservePath,
            envelope(ControlMessageType::RelayReservationRequest),
            Vec::new(),
        )
        .expect("reservation request")
    }

    fn relay_identity() -> (Vec<u8>, Vec<u8>) {
        let key = identity::Keypair::generate_ed25519();
        (
            vec![2; NODE_ID_LENGTH],
            key.public().to_peer_id().to_bytes(),
        )
    }

    fn envelope(message_type: ControlMessageType) -> Vec<u8> {
        encode_canonical(
            &SignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                sender_id: vec![3; NODE_ID_LENGTH],
                sender_public_key: vec![4; 32],
                timestamp_ms: 1,
                expires_at_ms: 2,
                nonce: vec![5; 32],
                message_type: message_type as i32,
                payload: Vec::new(),
                payload_hash: vec![6; 32],
                signature: vec![7; 64],
            },
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("envelope")
    }
}
