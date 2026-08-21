//! Canonical, versioned and resource-bounded direct advertisement retrieval.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol, identity, request_response};
use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, NodeAdvertisement,
    PROTOCOL_VERSION, SignedEnvelope, decode_canonical, encode_canonical, node_id_from_public_key,
};

/// Direct signed-advertisement request protocol.
pub const ADVERTISEMENT_PROTOCOL: &str = "/volparossa/advertisement/3";
/// Unsupported v1 protocol identifier, retained only for raw refusal tests.
pub const LEGACY_ADVERTISEMENT_PROTOCOL_V1: &str = "/volparossa/advertisement/1";
/// Unsupported v2 protocol identifier, retained only for raw refusal tests.
pub const LEGACY_ADVERTISEMENT_PROTOCOL_V2: &str = "/volparossa/advertisement/2";
/// Exact advertisement RPC schema version.
pub const ADVERTISEMENT_RPC_VERSION: u32 = 3;
/// Largest signed advertisement envelope accepted through discovery.
pub const MAX_ADVERTISEMENT_BYTES: usize = MAX_CONTROL_MESSAGE_SIZE;
/// Maximum encoded direct-advertisement request frame.
pub const MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES: u64 = 64;
/// Maximum encoded response frame: one maximal envelope plus fixed protobuf overhead.
pub const MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES: u64 = 512 * 1024;
/// Maximum combined inbound and outbound advertisement streams.
pub const MAX_CONCURRENT_ADVERTISEMENT_STREAMS: usize = 64;

/// Empty, exactly-versioned direct advertisement query.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementRequest {
    #[prost(uint32, tag = "1")]
    protocol_version: u32,
}

impl AdvertisementRequest {
    /// Construct the only supported request version.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            protocol_version: ADVERTISEMENT_RPC_VERSION,
        }
    }

    /// Return the exact RPC version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Reject v1, v2, future versions and non-empty future request shapes.
    ///
    /// # Errors
    ///
    /// Returns an unsupported-version error unless this is exactly a v3 request.
    pub fn validate(&self) -> Result<(), AdvertisementRpcError> {
        if self.protocol_version != ADVERTISEMENT_RPC_VERSION {
            return Err(AdvertisementRpcError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        Ok(())
    }
}

/// Signed advertisement envelope returned directly by its authenticated node.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementResponse {
    #[prost(bytes = "vec", tag = "1")]
    signed_envelope: Vec<u8>,
}

impl AdvertisementResponse {
    /// Construct a response after enforcing the signed-envelope bound.
    ///
    /// # Errors
    ///
    /// Returns an invalid-frame error for an empty or oversized envelope.
    pub fn new(signed_envelope: Vec<u8>) -> Result<Self, AdvertisementRpcError> {
        let response = Self { signed_envelope };
        response.validate()?;
        Ok(response)
    }

    /// Borrow the canonical signed control envelope.
    #[must_use]
    pub fn signed_envelope(&self) -> &[u8] {
        &self.signed_envelope
    }

    /// Consume the response and return its signed envelope.
    #[must_use]
    pub fn into_signed_envelope(self) -> Vec<u8> {
        self.signed_envelope
    }

    /// Enforce the fixed signed-envelope allocation bound and v3 advertisement type.
    ///
    /// # Errors
    ///
    /// Returns an invalid-frame error for an empty, oversized, non-canonical,
    /// wrong-version, or wrong-type envelope.
    pub fn validate(&self) -> Result<(), AdvertisementRpcError> {
        if self.signed_envelope.is_empty() || self.signed_envelope.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(AdvertisementRpcError::InvalidFrame);
        }
        let envelope =
            decode_canonical::<SignedEnvelope>(&self.signed_envelope, MAX_CONTROL_MESSAGE_SIZE)
                .map_err(|_| AdvertisementRpcError::InvalidFrame)?;
        if envelope.protocol_version != PROTOCOL_VERSION
            || envelope.message_type != ControlMessageType::NodeAdvertisement as i32
        {
            return Err(AdvertisementRpcError::InvalidFrame);
        }
        decode_canonical::<NodeAdvertisement>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
            .map_err(|_| AdvertisementRpcError::InvalidFrame)?;
        Ok(())
    }
}

/// Direct-advertisement RPC validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdvertisementRpcError {
    /// The request is v1, v2, or another unsupported version.
    #[error("unsupported advertisement RPC version {0}")]
    UnsupportedVersion(u32),
    /// A frame is empty, oversized, malformed, or non-canonical.
    #[error("invalid canonical advertisement RPC frame")]
    InvalidFrame,
}

/// Canonical protobuf codec for the advertisement v3 request-response protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdvertisementCodec;

pub(crate) fn advertisement_codec() -> AdvertisementCodec {
    AdvertisementCodec
}

pub(crate) fn advertisement_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<AdvertisementCodec> {
    request_response::Behaviour::with_codec(
        advertisement_codec(),
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(ADVERTISEMENT_PROTOCOL), support)),
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(10))
            .with_max_concurrent_streams(MAX_CONCURRENT_ADVERTISEMENT_STREAMS),
    )
}

#[async_trait]
impl request_response::Codec for AdvertisementCodec {
    type Protocol = StreamProtocol;
    type Request = AdvertisementRequest;
    type Response = AdvertisementResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_v3_protocol(protocol)?;
        let encoded = read_bounded(io, MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES).await?;
        let request = decode_canonical::<AdvertisementRequest>(
            &encoded,
            usize::try_from(MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES).map_err(invalid_data)?,
        )
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
        require_v3_protocol(protocol)?;
        let encoded = read_bounded(io, MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES).await?;
        let response = decode_canonical::<AdvertisementResponse>(
            &encoded,
            usize::try_from(MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES).map_err(invalid_data)?,
        )
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
        require_v3_protocol(protocol)?;
        request.validate().map_err(invalid_data)?;
        let encoded = encode_canonical(
            &request,
            usize::try_from(MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES).map_err(invalid_data)?,
        )
        .map_err(invalid_data)?;
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
        require_v3_protocol(protocol)?;
        response.validate().map_err(invalid_data)?;
        let encoded = encode_canonical(
            &response,
            usize::try_from(MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES).map_err(invalid_data)?,
        )
        .map_err(invalid_data)?;
        io.write_all(&encoded).await
    }
}

async fn read_bounded<T>(io: &mut T, maximum: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut encoded = Vec::new();
    io.take(maximum.saturating_add(1))
        .read_to_end(&mut encoded)
        .await?;
    if encoded.is_empty() || encoded.len() > usize::try_from(maximum).map_err(invalid_data)? {
        return Err(invalid_data(AdvertisementRpcError::InvalidFrame));
    }
    Ok(encoded)
}

fn require_v3_protocol(protocol: &StreamProtocol) -> io::Result<()> {
    if protocol.as_ref() != ADVERTISEMENT_PROTOCOL {
        return Err(invalid_data(AdvertisementRpcError::UnsupportedVersion(0)));
    }
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// Bind every advertisement identity to the authenticated libp2p peer before replay mutation.
#[must_use]
pub fn advertisement_envelope_matches_peer(envelope: &[u8], peer_id: &PeerId) -> bool {
    if envelope.is_empty() || envelope.len() > MAX_CONTROL_MESSAGE_SIZE {
        return false;
    }
    let Ok(envelope) = decode_canonical::<SignedEnvelope>(envelope, MAX_CONTROL_MESSAGE_SIZE)
    else {
        return false;
    };
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::NodeAdvertisement as i32
    {
        return false;
    }
    let Ok(public_key_bytes) = <[u8; 32]>::try_from(envelope.sender_public_key.as_slice()) else {
        return false;
    };
    let derived_node_id = node_id_from_public_key(&public_key_bytes);
    if envelope.sender_id != derived_node_id {
        return false;
    }
    let Ok(public_key) = identity::ed25519::PublicKey::try_from_bytes(&public_key_bytes) else {
        return false;
    };
    if identity::PublicKey::from(public_key).to_peer_id() != *peer_id {
        return false;
    }
    let Ok(payload) =
        decode_canonical::<NodeAdvertisement>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
    else {
        return false;
    };
    payload.node_id == derived_node_id && payload.peer_id == peer_id.to_bytes()
}
