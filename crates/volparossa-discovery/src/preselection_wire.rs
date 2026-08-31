//! Bounded request-response wire types for the dormant A1c transaction boundary.
//!
//! Sibling modules own affine client-hop and relay-to-exit dispatch, connection binding, and
//! role-gated response seams. The direct-Relay hop also has a signed response poll seam. The
//! upstream hop remains callerless and has no signer or responder; the direct responder has no
//! agent/runtime caller.
//!
//! Both codecs preserve exact canonical A0 bytes. They perform only state-free canonical,
//! version, type, payload-local, and envelope-binding validation. Cryptographic verification,
//! replay mutation, request correlation, signing, provenance binding, and evidence minting remain
//! outside this precursor.

use std::{fmt, io, time::Duration};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, ControlPayload, ForwardedPreselectionAttestation, MAX_CONTROL_PAYLOAD_SIZE,
    PROTOCOL_VERSION, PreselectionObservationReceipt, PreselectionObservationRequest,
    PreselectionObservationRole, ProtocolError, SignedEnvelope, decode_canonical,
    preselection_observation_receipt_hash, preselection_observation_request_hash,
};

pub use volparossa_protocol::{
    MAX_FORWARDED_ATTESTATION_SIZE, MAX_PRESELECTION_RECEIPT_SIZE, MAX_PRESELECTION_REQUEST_SIZE,
};

/// Client-to-control/direct-relay preselection observation protocol.
pub const PRESELECTION_OBSERVATION_PROTOCOL: &str = "/volparossa/preselection-observation/4";
/// Control-relay-to-exit preselection observation protocol.
pub const PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL: &str =
    "/volparossa/preselection-observation-upstream/4";
/// Exact transport timeout for both preselection observation behaviours.
pub const PRESELECTION_OBSERVATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-behaviour concurrent inbound plus outbound stream ceiling.
pub const MAX_CONCURRENT_PRESELECTION_OBSERVATION_STREAMS: usize = 64;

/// Detail-free preselection observation wire rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreselectionObservationRpcError {
    /// The A0 message or negotiated VOLPAROSSA protocol used another version.
    #[error("unsupported preselection observation version {0}")]
    UnsupportedVersion(u32),
    /// The frame was empty, oversized, non-canonical, wrong-type, or structurally invalid.
    #[error("invalid canonical preselection observation frame")]
    InvalidFrame,
}

/// Opaque exact canonical client-hop A0 request bytes.
#[derive(Eq, PartialEq)]
pub struct ClientPreselectionObservationRequest {
    encoded: Vec<u8>,
}

/// Opaque exact canonical client-hop signed response bytes.
#[derive(Eq, PartialEq)]
pub struct ClientPreselectionObservationResponse {
    encoded: Vec<u8>,
    kind: ClientResponseKind,
}

/// Opaque exact canonical upstream-hop forwarded Exit request bytes.
#[derive(Eq, PartialEq)]
pub struct UpstreamPreselectionObservationRequest {
    encoded: Vec<u8>,
}

/// Opaque exact canonical upstream-hop exit-signed receipt bytes.
#[derive(Eq, PartialEq)]
pub struct UpstreamPreselectionObservationResponse {
    encoded: Vec<u8>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientResponseKind {
    DirectRelayReceipt,
    ForwardedExitAttestation,
}

impl ClientPreselectionObservationRequest {
    /// Admit exact canonical Relay or forwarded Exit request bytes for the client hop.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for any invalid A0 request or fixed-bound violation.
    pub fn from_canonical(encoded: Vec<u8>) -> Result<Self, PreselectionObservationRpcError> {
        validate_request(&encoded, None)?;
        Ok(Self { encoded })
    }

    /// Borrow the unchanged exact canonical A0 request bytes.
    #[must_use]
    pub fn as_encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Consume the wrapper and return the unchanged exact canonical A0 request bytes.
    #[must_use]
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

impl ClientPreselectionObservationResponse {
    /// Admit exact canonical Relay receipt or forwarded Exit attestation bytes.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a bare Exit receipt, wrong type, malformed message, or
    /// type-specific fixed-bound violation.
    pub fn from_canonical(encoded: Vec<u8>) -> Result<Self, PreselectionObservationRpcError> {
        let kind = match signed_message_type(&encoded, MAX_FORWARDED_ATTESTATION_SIZE)? {
            ControlMessageType::PreselectionObservationReceipt => {
                validate_receipt(&encoded, PreselectionObservationRole::Relay)?;
                ClientResponseKind::DirectRelayReceipt
            }
            ControlMessageType::ForwardedPreselectionAttestation => {
                validate_forwarded_attestation(&encoded)?;
                ClientResponseKind::ForwardedExitAttestation
            }
            _ => return Err(PreselectionObservationRpcError::InvalidFrame),
        };
        Ok(Self { encoded, kind })
    }

    /// Borrow the unchanged exact canonical signed-envelope bytes.
    #[must_use]
    pub fn as_encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Consume the wrapper and return the unchanged exact canonical signed-envelope bytes.
    #[must_use]
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

impl UpstreamPreselectionObservationRequest {
    /// Admit exact canonical forwarded Exit request bytes for the upstream hop.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a Relay request, malformed A0 request, or fixed-bound
    /// violation.
    pub fn from_canonical(encoded: Vec<u8>) -> Result<Self, PreselectionObservationRpcError> {
        validate_request(&encoded, Some(PreselectionObservationRole::Exit))?;
        Ok(Self { encoded })
    }

    /// Borrow the unchanged exact canonical A0 request bytes.
    #[must_use]
    pub fn as_encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Consume the wrapper and return the unchanged exact canonical A0 request bytes.
    #[must_use]
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

impl UpstreamPreselectionObservationResponse {
    /// Admit exact canonical Exit-role signed receipt bytes for the upstream hop.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a Relay receipt, forwarded attestation, malformed message,
    /// or fixed-bound violation.
    pub fn from_canonical(encoded: Vec<u8>) -> Result<Self, PreselectionObservationRpcError> {
        validate_receipt(&encoded, PreselectionObservationRole::Exit)?;
        Ok(Self { encoded })
    }

    /// Borrow the unchanged exact canonical signed-envelope bytes.
    #[must_use]
    pub fn as_encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Consume the wrapper and return the unchanged exact canonical signed-envelope bytes.
    #[must_use]
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

impl fmt::Debug for ClientPreselectionObservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientPreselectionObservationRequest")
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

impl fmt::Debug for ClientPreselectionObservationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ClientPreselectionObservationResponse {{ encoded_len: {} }}",
            self.encoded.len()
        )
    }
}

impl fmt::Debug for UpstreamPreselectionObservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamPreselectionObservationRequest")
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

impl fmt::Debug for UpstreamPreselectionObservationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamPreselectionObservationResponse")
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

/// Client-facing preselection observation codec. The private module prevents external use.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientPreselectionObservationCodec;

/// Upstream preselection observation codec. The private module prevents external use.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpstreamPreselectionObservationCodec;

pub(crate) fn client_preselection_observation_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<ClientPreselectionObservationCodec> {
    request_response::Behaviour::with_codec(
        ClientPreselectionObservationCodec,
        support.into_iter().map(|support| {
            (
                StreamProtocol::new(PRESELECTION_OBSERVATION_PROTOCOL),
                support,
            )
        }),
        request_response_config(),
    )
}

pub(crate) fn upstream_preselection_observation_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<UpstreamPreselectionObservationCodec> {
    request_response::Behaviour::with_codec(
        UpstreamPreselectionObservationCodec,
        support.into_iter().map(|support| {
            (
                StreamProtocol::new(PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL),
                support,
            )
        }),
        request_response_config(),
    )
}

fn request_response_config() -> request_response::Config {
    request_response::Config::default()
        .with_request_timeout(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
        .with_max_concurrent_streams(MAX_CONCURRENT_PRESELECTION_OBSERVATION_STREAMS)
}

#[async_trait]
impl request_response::Codec for ClientPreselectionObservationCodec {
    type Protocol = StreamProtocol;
    type Request = ClientPreselectionObservationRequest;
    type Response = ClientPreselectionObservationResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, PRESELECTION_OBSERVATION_PROTOCOL)?;
        ClientPreselectionObservationRequest::from_canonical(
            read_bounded(io, MAX_PRESELECTION_REQUEST_SIZE).await?,
        )
        .map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, PRESELECTION_OBSERVATION_PROTOCOL)?;
        ClientPreselectionObservationResponse::from_canonical(
            read_bounded(io, MAX_FORWARDED_ATTESTATION_SIZE).await?,
        )
        .map_err(invalid_data)
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
        require_protocol(protocol, PRESELECTION_OBSERVATION_PROTOCOL)?;
        validate_request(request.as_encoded(), None).map_err(invalid_data)?;
        io.write_all(request.as_encoded()).await
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
        require_protocol(protocol, PRESELECTION_OBSERVATION_PROTOCOL)?;
        validate_client_response(&response).map_err(invalid_data)?;
        io.write_all(response.as_encoded()).await
    }
}

#[async_trait]
impl request_response::Codec for UpstreamPreselectionObservationCodec {
    type Protocol = StreamProtocol;
    type Request = UpstreamPreselectionObservationRequest;
    type Response = UpstreamPreselectionObservationResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL)?;
        UpstreamPreselectionObservationRequest::from_canonical(
            read_bounded(io, MAX_PRESELECTION_REQUEST_SIZE).await?,
        )
        .map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_protocol(protocol, PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL)?;
        UpstreamPreselectionObservationResponse::from_canonical(
            read_bounded(io, MAX_PRESELECTION_RECEIPT_SIZE).await?,
        )
        .map_err(invalid_data)
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
        require_protocol(protocol, PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL)?;
        validate_request(
            request.as_encoded(),
            Some(PreselectionObservationRole::Exit),
        )
        .map_err(invalid_data)?;
        io.write_all(request.as_encoded()).await
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
        require_protocol(protocol, PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL)?;
        validate_receipt(response.as_encoded(), PreselectionObservationRole::Exit)
            .map_err(invalid_data)?;
        io.write_all(response.as_encoded()).await
    }
}

fn validate_client_response(
    response: &ClientPreselectionObservationResponse,
) -> Result<(), PreselectionObservationRpcError> {
    match response.kind {
        ClientResponseKind::DirectRelayReceipt => {
            validate_receipt(response.as_encoded(), PreselectionObservationRole::Relay)
        }
        ClientResponseKind::ForwardedExitAttestation => {
            validate_forwarded_attestation(response.as_encoded())
        }
    }
}

fn validate_request(
    encoded: &[u8],
    required_role: Option<PreselectionObservationRole>,
) -> Result<(), PreselectionObservationRpcError> {
    if encoded.is_empty() || encoded.len() > MAX_PRESELECTION_REQUEST_SIZE {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    preselection_observation_request_hash(encoded).map_err(|error| map_protocol_error(&error))?;
    let request: PreselectionObservationRequest =
        decode_canonical(encoded, MAX_PRESELECTION_REQUEST_SIZE)
            .map_err(|error| map_protocol_error(&error))?;
    let role = request
        .scope
        .as_ref()
        .and_then(|scope| PreselectionObservationRole::try_from(scope.role).ok())
        .ok_or(PreselectionObservationRpcError::InvalidFrame)?;
    if required_role.is_some_and(|required| role != required) {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_receipt(
    encoded: &[u8],
    required_role: PreselectionObservationRole,
) -> Result<(), PreselectionObservationRpcError> {
    if encoded.is_empty() || encoded.len() > MAX_PRESELECTION_RECEIPT_SIZE {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    preselection_observation_receipt_hash(encoded).map_err(|error| map_protocol_error(&error))?;
    let (envelope, receipt) = decode_signed_payload::<PreselectionObservationReceipt>(
        encoded,
        MAX_PRESELECTION_RECEIPT_SIZE,
        ControlMessageType::PreselectionObservationReceipt,
    )?;
    receipt
        .validate()
        .map_err(|error| map_protocol_error(&error))?;
    receipt
        .validate_envelope(&envelope)
        .map_err(|error| map_protocol_error(&error))?;
    let role = receipt
        .scope
        .as_ref()
        .and_then(|scope| PreselectionObservationRole::try_from(scope.role).ok())
        .ok_or(PreselectionObservationRpcError::InvalidFrame)?;
    if role != required_role {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_forwarded_attestation(encoded: &[u8]) -> Result<(), PreselectionObservationRpcError> {
    let (envelope, attestation) = decode_signed_payload::<ForwardedPreselectionAttestation>(
        encoded,
        MAX_FORWARDED_ATTESTATION_SIZE,
        ControlMessageType::ForwardedPreselectionAttestation,
    )?;
    attestation
        .validate()
        .map_err(|error| map_protocol_error(&error))?;
    attestation
        .validate_envelope(&envelope)
        .map_err(|error| map_protocol_error(&error))
}

fn decode_signed_payload<T>(
    encoded: &[u8],
    maximum: usize,
    expected_type: ControlMessageType,
) -> Result<(SignedEnvelope, T), PreselectionObservationRpcError>
where
    T: prost::Message + Default,
{
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    let envelope: SignedEnvelope =
        decode_canonical(encoded, maximum).map_err(|error| map_protocol_error(&error))?;
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(PreselectionObservationRpcError::UnsupportedVersion(
            envelope.protocol_version,
        ));
    }
    if envelope.message_type != expected_type as i32 {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    let payload = decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
        .map_err(|error| map_protocol_error(&error))?;
    Ok((envelope, payload))
}

fn signed_message_type(
    encoded: &[u8],
    maximum: usize,
) -> Result<ControlMessageType, PreselectionObservationRpcError> {
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(PreselectionObservationRpcError::InvalidFrame);
    }
    let envelope: SignedEnvelope =
        decode_canonical(encoded, maximum).map_err(|error| map_protocol_error(&error))?;
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(PreselectionObservationRpcError::UnsupportedVersion(
            envelope.protocol_version,
        ));
    }
    ControlMessageType::try_from(envelope.message_type)
        .map_err(|_| PreselectionObservationRpcError::InvalidFrame)
}

async fn read_bounded<T>(io: &mut T, maximum: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let limit = u64::try_from(maximum)
        .map_err(invalid_data)?
        .saturating_add(1);
    let mut encoded = Vec::new();
    io.take(limit).read_to_end(&mut encoded).await?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(invalid_data(PreselectionObservationRpcError::InvalidFrame));
    }
    Ok(encoded)
}

fn require_protocol(protocol: &StreamProtocol, expected: &str) -> io::Result<()> {
    if protocol.as_ref() == expected {
        return Ok(());
    }
    let error = protocol
        .as_ref()
        .rsplit_once('/')
        .and_then(|(_, version)| version.parse::<u32>().ok())
        .filter(|_| {
            protocol
                .as_ref()
                .starts_with("/volparossa/preselection-observation")
                && !matches!(
                    protocol.as_ref(),
                    PRESELECTION_OBSERVATION_PROTOCOL | PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL
                )
        })
        .map_or(
            PreselectionObservationRpcError::InvalidFrame,
            PreselectionObservationRpcError::UnsupportedVersion,
        );
    Err(invalid_data(error))
}

fn map_protocol_error(error: &ProtocolError) -> PreselectionObservationRpcError {
    match error {
        ProtocolError::UnsupportedVersion(version) => {
            PreselectionObservationRpcError::UnsupportedVersion(*version)
        }
        _ => PreselectionObservationRpcError::InvalidFrame,
    }
}

fn invalid_data(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::{StreamProtocol, identity, request_response::Codec as _};
    use volparossa_protocol::{
        ObservationAddressFamily, ObservationNetworkPrefix, PreselectionActorBinding,
        PreselectionObservationScope, TimePolicy, Transport, encode_canonical,
        node_id_from_public_key, sign_control_message_with,
    };

    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "all four exact hop shapes form one matrix"
    )]
    async fn codecs_round_trip_all_four_exact_hop_shapes() {
        let direct = direct_fixture();
        let forwarded = forwarded_fixture();
        let client_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_PROTOCOL);
        let upstream_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL);
        let mut client_codec = ClientPreselectionObservationCodec;
        let mut upstream_codec = UpstreamPreselectionObservationCodec;

        for request_bytes in [&direct.request, &forwarded.request] {
            let request =
                ClientPreselectionObservationRequest::from_canonical(request_bytes.clone())
                    .expect("client request");
            let mut wire = Cursor::new(Vec::new());
            client_codec
                .write_request(&client_protocol, &mut wire, request)
                .await
                .expect("client request write");
            assert_eq!(wire.get_ref(), request_bytes);
            let decoded = client_codec
                .read_request(&client_protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .expect("client request read");
            assert_eq!(decoded.as_encoded(), request_bytes);
        }

        let upstream_request =
            UpstreamPreselectionObservationRequest::from_canonical(forwarded.request.clone())
                .expect("upstream request");
        let mut upstream_request_wire = Cursor::new(Vec::new());
        upstream_codec
            .write_request(
                &upstream_protocol,
                &mut upstream_request_wire,
                upstream_request,
            )
            .await
            .expect("upstream request write");
        assert_eq!(upstream_request_wire.get_ref(), &forwarded.request);
        assert_eq!(
            upstream_request_wire.get_ref(),
            &encode_canonical(&forwarded.typed_request, MAX_PRESELECTION_REQUEST_SIZE)
                .expect("canonical forwarded request")
        );
        let decoded = upstream_codec
            .read_request(
                &upstream_protocol,
                &mut Cursor::new(upstream_request_wire.into_inner()),
            )
            .await
            .expect("upstream request read");
        assert_eq!(decoded.as_encoded(), &forwarded.request);

        for response_bytes in [&direct.receipt, &forwarded.attestation] {
            let response =
                ClientPreselectionObservationResponse::from_canonical(response_bytes.clone())
                    .expect("client response");
            let mut wire = Cursor::new(Vec::new());
            client_codec
                .write_response(&client_protocol, &mut wire, response)
                .await
                .expect("client response write");
            assert_eq!(wire.get_ref(), response_bytes);
            let decoded = client_codec
                .read_response(&client_protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .expect("client response read");
            assert_eq!(decoded.as_encoded(), response_bytes);
        }

        let upstream_response =
            UpstreamPreselectionObservationResponse::from_canonical(forwarded.exit_receipt.clone())
                .expect("upstream response");
        let mut upstream_response_wire = Cursor::new(Vec::new());
        upstream_codec
            .write_response(
                &upstream_protocol,
                &mut upstream_response_wire,
                upstream_response,
            )
            .await
            .expect("upstream response write");
        assert_eq!(upstream_response_wire.get_ref(), &forwarded.exit_receipt);
        let decoded = upstream_codec
            .read_response(
                &upstream_protocol,
                &mut Cursor::new(upstream_response_wire.into_inner()),
            )
            .await
            .expect("upstream response read");
        assert_eq!(decoded.as_encoded(), &forwarded.exit_receipt);
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fail-closed wire matrix is one boundary"
    )]
    async fn codecs_reject_cross_hop_roles_types_versions_and_noncanonical_bytes() {
        let direct = direct_fixture();
        let forwarded = forwarded_fixture();
        assert!(
            ClientPreselectionObservationResponse::from_canonical(forwarded.exit_receipt.clone())
                .is_err()
        );
        assert!(
            UpstreamPreselectionObservationRequest::from_canonical(direct.request.clone()).is_err()
        );
        assert!(
            UpstreamPreselectionObservationResponse::from_canonical(direct.receipt.clone())
                .is_err()
        );
        assert!(
            UpstreamPreselectionObservationResponse::from_canonical(forwarded.attestation.clone())
                .is_err()
        );

        let mut wrong_type: SignedEnvelope =
            decode_canonical(&direct.receipt, MAX_PRESELECTION_RECEIPT_SIZE).expect("envelope");
        wrong_type.message_type = ControlMessageType::NodeAdvertisement as i32;
        let wrong_type = encode_canonical(&wrong_type, MAX_FORWARDED_ATTESTATION_SIZE)
            .expect("wrong type envelope");
        assert!(ClientPreselectionObservationResponse::from_canonical(wrong_type).is_err());

        let mut wrong_version = direct.typed_request.clone();
        wrong_version.protocol_version = 2;
        let wrong_version = encode_canonical(&wrong_version, MAX_PRESELECTION_REQUEST_SIZE)
            .expect("wrong version request");
        assert_eq!(
            ClientPreselectionObservationRequest::from_canonical(wrong_version),
            Err(PreselectionObservationRpcError::UnsupportedVersion(2))
        );

        let client_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_PROTOCOL);
        let upstream_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL);
        let mut client_codec = ClientPreselectionObservationCodec;
        let mut upstream_codec = UpstreamPreselectionObservationCodec;
        for wrong in [
            "/volparossa/preselection-observation/1",
            "/volparossa/preselection-observation/2",
            "/volparossa/preselection-observation/3",
            PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL,
        ] {
            assert!(
                client_codec
                    .read_request(
                        &StreamProtocol::try_from_owned(wrong.to_owned()).expect("protocol"),
                        &mut Cursor::new(direct.request.clone()),
                    )
                    .await
                    .is_err()
            );
        }
        assert!(
            upstream_codec
                .read_request(
                    &client_protocol,
                    &mut Cursor::new(forwarded.request.clone()),
                )
                .await
                .is_err()
        );
        for wrong in [
            "/volparossa/preselection-observation-upstream/1",
            "/volparossa/preselection-observation-upstream/2",
            "/volparossa/preselection-observation-upstream/3",
            PRESELECTION_OBSERVATION_PROTOCOL,
        ] {
            assert!(
                upstream_codec
                    .read_request(
                        &StreamProtocol::try_from_owned(wrong.to_owned()).expect("protocol"),
                        &mut Cursor::new(forwarded.request.clone()),
                    )
                    .await
                    .is_err()
            );
        }
        assert!(
            client_codec
                .read_request(&upstream_protocol, &mut Cursor::new(direct.request.clone()),)
                .await
                .is_err()
        );

        for suffix in [vec![0x48, 0x01], vec![0x08, 0x03], vec![0x00]] {
            let mut noncanonical = direct.request.clone();
            noncanonical.extend_from_slice(&suffix);
            assert!(ClientPreselectionObservationRequest::from_canonical(noncanonical).is_err());
        }
        assert!(ClientPreselectionObservationRequest::from_canonical(Vec::new()).is_err());
        assert!(ClientPreselectionObservationResponse::from_canonical(Vec::new()).is_err());

        for version in [1, 2, 3, 5] {
            let mut envelope: SignedEnvelope =
                decode_canonical(&direct.receipt, MAX_PRESELECTION_RECEIPT_SIZE)
                    .expect("receipt envelope");
            envelope.protocol_version = version;
            let encoded = encode_canonical(&envelope, MAX_PRESELECTION_RECEIPT_SIZE)
                .expect("versioned envelope");
            assert_eq!(
                ClientPreselectionObservationResponse::from_canonical(encoded),
                Err(PreselectionObservationRpcError::UnsupportedVersion(version))
            );
        }

        let mut envelope: SignedEnvelope =
            decode_canonical(&direct.receipt, MAX_PRESELECTION_RECEIPT_SIZE)
                .expect("receipt envelope");
        envelope.timestamp_ms += 1;
        let bad_binding =
            encode_canonical(&envelope, MAX_PRESELECTION_RECEIPT_SIZE).expect("binding mutation");
        assert!(ClientPreselectionObservationResponse::from_canonical(bad_binding).is_err());

        let mut envelope: SignedEnvelope =
            decode_canonical(&direct.receipt, MAX_PRESELECTION_RECEIPT_SIZE)
                .expect("receipt envelope");
        let mut payload: PreselectionObservationReceipt =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("receipt payload");
        payload.nonce.fill(0);
        envelope.payload =
            encode_canonical(&payload, MAX_CONTROL_PAYLOAD_SIZE).expect("invalid payload shape");
        let bad_payload =
            encode_canonical(&envelope, MAX_PRESELECTION_RECEIPT_SIZE).expect("payload mutation");
        assert!(ClientPreselectionObservationResponse::from_canonical(bad_payload).is_err());
    }

    #[tokio::test]
    async fn codec_writes_privately_revalidate_every_hop_wrapper() {
        let direct = direct_fixture();
        let forwarded = forwarded_fixture();
        let client_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_PROTOCOL);
        let upstream_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL);

        let invalid_client_request = ClientPreselectionObservationRequest {
            encoded: Vec::new(),
        };
        assert!(
            ClientPreselectionObservationCodec
                .write_request(
                    &client_protocol,
                    &mut Cursor::new(Vec::new()),
                    invalid_client_request,
                )
                .await
                .is_err()
        );
        let wrong_client_kind = ClientPreselectionObservationResponse {
            encoded: forwarded.attestation,
            kind: ClientResponseKind::DirectRelayReceipt,
        };
        assert!(
            ClientPreselectionObservationCodec
                .write_response(
                    &client_protocol,
                    &mut Cursor::new(Vec::new()),
                    wrong_client_kind,
                )
                .await
                .is_err()
        );
        let relay_upstream_request = UpstreamPreselectionObservationRequest {
            encoded: direct.request,
        };
        assert!(
            UpstreamPreselectionObservationCodec
                .write_request(
                    &upstream_protocol,
                    &mut Cursor::new(Vec::new()),
                    relay_upstream_request,
                )
                .await
                .is_err()
        );
        let relay_upstream_response = UpstreamPreselectionObservationResponse {
            encoded: direct.receipt,
        };
        assert!(
            UpstreamPreselectionObservationCodec
                .write_response(
                    &upstream_protocol,
                    &mut Cursor::new(Vec::new()),
                    relay_upstream_response,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn read_limits_are_inclusive_and_type_specific() {
        let exact_request = vec![1; MAX_PRESELECTION_REQUEST_SIZE];
        assert_eq!(
            read_bounded(
                &mut Cursor::new(exact_request.clone()),
                MAX_PRESELECTION_REQUEST_SIZE
            )
            .await
            .expect("inclusive request read"),
            exact_request
        );
        let mut oversized_request = Cursor::new(vec![1; MAX_PRESELECTION_REQUEST_SIZE + 1]);
        assert!(
            read_bounded(&mut oversized_request, MAX_PRESELECTION_REQUEST_SIZE)
                .await
                .is_err()
        );
        assert_eq!(
            oversized_request.position(),
            u64::try_from(MAX_PRESELECTION_REQUEST_SIZE + 1).unwrap()
        );

        let direct = direct_fixture();
        let mut oversized_receipt: SignedEnvelope =
            decode_canonical(&direct.receipt, MAX_PRESELECTION_RECEIPT_SIZE).expect("envelope");
        oversized_receipt
            .signature
            .resize(MAX_PRESELECTION_RECEIPT_SIZE + 1, 7);
        let oversized_receipt =
            encode_canonical(&oversized_receipt, MAX_FORWARDED_ATTESTATION_SIZE)
                .expect("canonical oversized receipt");
        assert!(oversized_receipt.len() > MAX_PRESELECTION_RECEIPT_SIZE);
        assert!(oversized_receipt.len() <= MAX_FORWARDED_ATTESTATION_SIZE);
        let protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_PROTOCOL);
        assert!(
            ClientPreselectionObservationCodec
                .read_response(&protocol, &mut Cursor::new(oversized_receipt))
                .await
                .is_err()
        );
        let mut oversized_attestation = Cursor::new(vec![1; MAX_FORWARDED_ATTESTATION_SIZE + 1]);
        assert!(
            ClientPreselectionObservationCodec
                .read_response(&protocol, &mut oversized_attestation)
                .await
                .is_err()
        );
        assert_eq!(
            oversized_attestation.position(),
            u64::try_from(MAX_FORWARDED_ATTESTATION_SIZE + 1).unwrap()
        );

        let upstream_protocol = StreamProtocol::new(PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL);
        let mut oversized_upstream_receipt =
            Cursor::new(vec![1; MAX_PRESELECTION_RECEIPT_SIZE + 1]);
        assert!(
            UpstreamPreselectionObservationCodec
                .read_response(&upstream_protocol, &mut oversized_upstream_receipt)
                .await
                .is_err()
        );
        assert_eq!(
            oversized_upstream_receipt.position(),
            u64::try_from(MAX_PRESELECTION_RECEIPT_SIZE + 1).unwrap()
        );
    }

    #[test]
    fn public_surface_is_exact_and_codecs_have_no_transaction_caller() {
        let source = include_str!("preselection_wire.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert_eq!(production.matches("pub fn from_canonical(").count(), 4);
        assert_eq!(production.matches("pub fn as_encoded(").count(), 4);
        assert_eq!(production.matches("pub fn into_encoded(").count(), 4);
        assert_eq!(production.matches("pub fn ").count(), 12);
        for forbidden in [
            "impl From<Vec<u8>>",
            "impl AsRef",
            "impl Deref",
            "Serialize",
            "Deserialize",
            "pub enum ClientResponseKind",
            "pub encoded:",
            "pub kind:",
            concat!("Vec", "Deque"),
            concat!("re", "try"),
            concat!("back", "off"),
            concat!("spawn", "("),
            concat!("chan", "nel"),
            concat!("Response", "Channel"),
            concat!("Outbound", "RequestId"),
            concat!("BoundConnection", "Observation"),
            concat!("unique_", "witness"),
            concat!("send_", "request"),
            concat!("send_", "response"),
            concat!("sign_control_", "message"),
            concat!("verify_", "direct_preselection_transcript"),
            concat!("verify_", "forwarded_preselection_transcript"),
            concat!("consume_", "direct_preselection_transcript"),
            concat!("consume_", "forwarded_preselection_transcript"),
            concat!("Replay", "Cache"),
            concat!("Hash", "Map"),
            concat!("Connection", "Witness"),
            concat!("Fresh", "Evidence"),
            concat!("Candidate", "Evidence"),
            concat!("PreselectionAttempt", "Gate"),
            concat!("BoundPreselectionTranscript", "Batch"),
            concat!("Route", "Context"),
            concat!("Route", "Candidate"),
            concat!("Reservation", "Id"),
            concat!("Exit", "Reservation"),
            concat!("ClientSession", "Capability"),
            concat!("Observation", "DispatchId"),
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface {forbidden}"
            );
        }
        assert_eq!(
            production
                .matches("request_response::Behaviour::with_codec")
                .count(),
            2
        );
        assert_eq!(production.matches("with_request_timeout").count(), 1);
        assert_eq!(
            PRESELECTION_OBSERVATION_REQUEST_TIMEOUT,
            Duration::from_secs(5)
        );
        assert_eq!(MAX_PRESELECTION_REQUEST_SIZE, 4096);
        assert_eq!(MAX_PRESELECTION_RECEIPT_SIZE, 4096);
        assert_eq!(MAX_FORWARDED_ATTESTATION_SIZE, 8192);
        assert_eq!(MAX_CONCURRENT_PRESELECTION_OBSERVATION_STREAMS, 64);

        for wrapper in [
            "ClientPreselectionObservationRequest",
            "ClientPreselectionObservationResponse",
            "UpstreamPreselectionObservationRequest",
            "UpstreamPreselectionObservationResponse",
        ] {
            let declaration = production
                .find(&format!("pub struct {wrapper}"))
                .expect("public hop wrapper");
            let before_declaration = &production[..declaration];
            let derive = before_declaration
                .rsplit_once("#[derive(")
                .map(|(_, derive)| derive)
                .and_then(|derive| derive.split_once(")]"))
                .map(|(derive, _)| derive)
                .expect("wrapper derive");
            assert!(
                !derive
                    .split(',')
                    .any(|trait_name| trait_name.trim() == "Clone")
            );
            assert!(!production.contains(&format!("impl Clone for {wrapper}")));
        }
    }

    #[test]
    fn debug_output_contains_only_wrapper_name_and_encoded_length() {
        let direct = direct_fixture();
        let forwarded = forwarded_fixture();
        let values = [
            (
                format!(
                    "{:?}",
                    ClientPreselectionObservationRequest::from_canonical(direct.request.clone())
                        .expect("client request")
                ),
                format!(
                    "ClientPreselectionObservationRequest {{ encoded_len: {} }}",
                    direct.request.len()
                ),
            ),
            (
                format!(
                    "{:?}",
                    ClientPreselectionObservationResponse::from_canonical(direct.receipt.clone())
                        .expect("client response")
                ),
                format!(
                    "ClientPreselectionObservationResponse {{ encoded_len: {} }}",
                    direct.receipt.len()
                ),
            ),
            (
                format!(
                    "{:?}",
                    UpstreamPreselectionObservationRequest::from_canonical(
                        forwarded.request.clone()
                    )
                    .expect("upstream request")
                ),
                format!(
                    "UpstreamPreselectionObservationRequest {{ encoded_len: {} }}",
                    forwarded.request.len()
                ),
            ),
            (
                format!(
                    "{:?}",
                    UpstreamPreselectionObservationResponse::from_canonical(
                        forwarded.exit_receipt.clone()
                    )
                    .expect("upstream response")
                ),
                format!(
                    "UpstreamPreselectionObservationResponse {{ encoded_len: {} }}",
                    forwarded.exit_receipt.len()
                ),
            ),
        ];
        for (actual, expected) in values {
            assert_eq!(actual, expected);
            assert!(!actual.contains("kind"));
        }
        let source = include_str!("preselection_wire.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(!production.contains(".field(\"kind\""));
        let client_response_debug = production
            .split("impl fmt::Debug for ClientPreselectionObservationResponse")
            .nth(1)
            .and_then(|source| {
                source.split_once("impl fmt::Debug for UpstreamPreselectionObservationRequest")
            })
            .map(|(debug_impl, _)| debug_impl)
            .expect("client response Debug implementation");
        for forbidden in [
            "kind",
            "ClientResponseKind",
            "DirectRelayReceipt",
            "ForwardedExitAttestation",
        ] {
            assert!(!client_response_debug.contains(forbidden));
        }
    }

    #[test]
    fn discovery_composition_keeps_codecs_private_and_delegates_one_affine_transaction_module() {
        let source = include_str!("lib.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("discovery production source");
        let compact: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(compact.matches("modpreselection_wire;").count(), 1);
        assert!(!compact.contains("pubmodpreselection_wire;"));
        assert_eq!(compact.matches("modpreselection_transaction;").count(), 1);
        assert!(!compact.contains("pubmodpreselection_transaction;"));
        assert_eq!(
            compact
                .matches("preselection_observation:request_response::Behaviour<")
                .count(),
            1
        );
        assert_eq!(
            compact
                .matches("preselection_observation_upstream:request_response::Behaviour<")
                .count(),
            1
        );
        assert!(!compact.contains("pubpreselection_observation:"));
        assert!(!compact.contains("pubpreselection_observation_upstream:"));
        assert_eq!(
            compact
                .matches("client_preselection_observation_behaviour(protocol_support(")
                .count(),
            1
        );
        assert_eq!(
            compact
                .matches("upstream_preselection_observation_behaviour(")
                .count(),
            1
        );
        assert_eq!(
            compact
                .matches("PreselectionObservation(request_response::Event<")
                .count(),
            1
        );
        assert_eq!(
            compact
                .matches("PreselectionObservationUpstream(request_response::Event<")
                .count(),
            1
        );
        let service = production
            .split("pub struct DiscoveryService")
            .nth(1)
            .expect("discovery service");
        for forbidden in [
            "pub fn request_preselection",
            "pub fn respond_preselection",
            "pub fn handle_preselection",
            "send_preselection",
            "pending_preselection",
            "PreselectionAttemptGate",
            "BoundPreselectionTranscriptBatch",
            "ConnectionWitness",
            "FreshEvidence",
            "CandidateEvidence",
            "ClientPreselectionObservationRequest",
            "ClientPreselectionObservationResponse",
            "UpstreamPreselectionObservationRequest",
            "UpstreamPreselectionObservationResponse",
            ".from_canonical(",
            ".as_encoded(",
            ".into_encoded(",
        ] {
            assert!(
                !service.contains(forbidden),
                "discovery service caller surface: {forbidden}"
            );
        }
    }

    fn assert_compact_method_once(production: &str, signature: &str) {
        assert_eq!(production.matches(signature).count(), 1, "{signature}");
    }

    #[test]
    fn private_transaction_module_contains_only_affine_outbound_transport_seams() {
        let transaction_source = include_str!("preselection_transaction.rs");
        let transaction_production = transaction_source
            .split("#[cfg(test)]")
            .next()
            .expect("transaction production");
        let transaction_compact: String = transaction_production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for method in [
            "pubfndispatch_preselection_observation(",
            "pubfndispatch_preselection_observation_with_context<",
            "pubfnbind_preselection_observation_response(",
            "pubfnbind_preselection_observation_response_with_context<",
            "pubfncancel_preselection_observation_dispatch(",
            "pubfncancel_preselection_observation_transaction<",
            "pubfndispatch_preselection_observation_upstream(",
            "pubfndispatch_preselection_observation_upstream_with_context<",
            "pubfnbind_preselection_observation_upstream_response(",
            "pubfnbind_preselection_observation_upstream_response_with_context<",
            "pubfncancel_preselection_observation_upstream_dispatch(",
            "pubfncancel_preselection_observation_upstream_transaction<",
        ] {
            assert_compact_method_once(&transaction_compact, method);
        }
        assert!(!transaction_compact.contains("send_preselection_observation_response"));
        assert!(!transaction_compact.contains("send_preselection_observation_upstream_response"));
        assert!(!transaction_compact.contains("ResponseChannel"));
        assert!(!transaction_compact.contains(".send_response("));
        for forbidden in [
            "respond_preselection",
            "handle_preselection",
            "sign_control_message",
            "ReplayCache",
            "FreshEvidence",
            "CandidateEvidence",
            "BoundPreselectionTranscriptBatch",
        ] {
            assert!(
                !transaction_production.contains(forbidden),
                "transaction crossed A1c2 codec/owner boundary: {forbidden}"
            );
        }
    }

    struct DirectFixture {
        typed_request: PreselectionObservationRequest,
        request: Vec<u8>,
        receipt: Vec<u8>,
    }

    struct ForwardedFixture {
        typed_request: PreselectionObservationRequest,
        request: Vec<u8>,
        exit_receipt: Vec<u8>,
        attestation: Vec<u8>,
    }

    fn direct_fixture() -> DirectFixture {
        let relay_key = identity::Keypair::generate_ed25519();
        let relay = actor(&relay_key, 1, NOW + 60_000, NOW + 60_000);
        let typed_request = request(PreselectionObservationRole::Relay, relay, None, 2);
        let request =
            encode_canonical(&typed_request, MAX_PRESELECTION_REQUEST_SIZE).expect("request");
        let receipt = signed_receipt(&typed_request, &relay_key, 3);
        DirectFixture {
            typed_request,
            request,
            receipt,
        }
    }

    fn forwarded_fixture() -> ForwardedFixture {
        let control_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let control = actor(&control_key, 4, NOW + 60_000, NOW + 60_000);
        let exit = actor(&exit_key, 5, NOW + 90_000, NOW + 60_000);
        let typed_request = request(
            PreselectionObservationRole::Exit,
            exit.clone(),
            Some(control.clone()),
            6,
        );
        let request =
            encode_canonical(&typed_request, MAX_PRESELECTION_REQUEST_SIZE).expect("request");
        let exit_receipt = signed_receipt(&typed_request, &exit_key, 7);
        let attestation = ForwardedPreselectionAttestation {
            request_hash: preselection_observation_request_hash(&request)
                .expect("request hash")
                .to_vec(),
            challenge: typed_request.challenge.clone(),
            signed_exit_receipt: exit_receipt.clone(),
            exit_receipt_hash: preselection_observation_receipt_hash(&exit_receipt)
                .expect("receipt hash")
                .to_vec(),
            control: Some(control),
            exit: Some(exit),
            scope: typed_request.scope.clone(),
            upstream_network_prefix: Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: vec![8, 8, 4],
            }),
            observed_at_ms: NOW + 20_000,
            valid_until_ms: NOW + 50_000,
            nonce: vec![8; 32],
        };
        let attestation = sign(&attestation, &control_key, NOW + 20_000, NOW + 50_000, 8);
        ForwardedFixture {
            typed_request,
            request,
            exit_receipt,
            attestation,
        }
    }

    fn actor(
        key: &identity::Keypair,
        marker: u8,
        advertisement_expiry: u64,
        capability_expiry: u64,
    ) -> PreselectionActorBinding {
        let public_key = raw_public_key(key);
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: key.public().to_peer_id().to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: u64::from(marker),
            advertisement_expires_at_ms: advertisement_expiry,
            advertisement_payload_hash: vec![marker; 32],
            capability_expires_at_ms: capability_expiry,
        }
    }

    fn request(
        role: PreselectionObservationRole,
        actor: PreselectionActorBinding,
        forwarded_control: Option<PreselectionActorBinding>,
        challenge: u8,
    ) -> PreselectionObservationRequest {
        PreselectionObservationRequest {
            protocol_version: PROTOCOL_VERSION,
            challenge: vec![challenge; 32],
            actor: Some(actor),
            scope: Some(PreselectionObservationScope {
                role: role as i32,
                transport: Transport::TcpMptcp as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: 1,
                policy_hash: vec![9; 32],
                policy_expires_at_ms: NOW + 60_000,
            }),
            forwarded_control,
            created_at_ms: NOW,
            expires_at_ms: NOW + 4_000,
        }
    }

    fn signed_receipt(
        request: &PreselectionObservationRequest,
        key: &identity::Keypair,
        nonce: u8,
    ) -> Vec<u8> {
        let encoded_request =
            encode_canonical(request, MAX_PRESELECTION_REQUEST_SIZE).expect("request");
        let receipt = PreselectionObservationReceipt {
            request_hash: preselection_observation_request_hash(&encoded_request)
                .expect("request hash")
                .to_vec(),
            challenge: request.challenge.clone(),
            actor: request.actor.clone(),
            scope: request.scope.clone(),
            observed_at_ms: NOW + 10_000,
            valid_until_ms: NOW + 40_000,
            nonce: vec![nonce; 32],
        };
        sign(&receipt, key, NOW + 10_000, NOW + 40_000, nonce)
    }

    fn sign<T: ControlPayload>(
        payload: &T,
        key: &identity::Keypair,
        created_at_ms: u64,
        expires_at_ms: u64,
        nonce: u8,
    ) -> Vec<u8> {
        sign_control_message_with(
            payload,
            raw_public_key(key),
            created_at_ms,
            expires_at_ms,
            [nonce; 32],
            TimePolicy::default(),
            |message| key.sign(message).ok()?.try_into().ok(),
        )
        .expect("signed payload")
    }

    fn raw_public_key(key: &identity::Keypair) -> [u8; 32] {
        key.clone()
            .try_into_ed25519()
            .expect("Ed25519 key")
            .public()
            .to_bytes()
    }
}
