//! Strict local control protocol shared by `volparossa` and `volparossa-agent`.
//!
//! Frames are fixed-version Protocol Buffers with an unsigned big-endian
//! length prefix. Every variable-size field is checked after a bounded read and
//! before use. This socket is never a privileged command channel; privileged
//! network operations use the narrower `volparossa-routing` protocol.

#![forbid(unsafe_code)]

use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Local control protocol version implemented by v1.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
/// Maximum complete local control payload.
pub const MAX_CONTROL_FRAME: usize = 256 * 1024;
/// Maximum list entries returned in one response.
pub const MAX_LIST_ITEMS: usize = 4_096;
/// Maximum length of a public peer ID.
pub const MAX_PEER_ID_BYTES: usize = 128;
/// Maximum length of a stable diagnostic or log code.
pub const MAX_CODE_BYTES: usize = 96;

/// Request sent by the user-facing CLI.
#[derive(Clone, PartialEq, Message)]
pub struct ControlRequest {
    /// Exact protocol version.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Random 16-byte correlation identifier.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// One allowlisted operation.
    #[prost(
        oneof = "control_request::Operation",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19"
    )]
    pub operation: Option<control_request::Operation>,
}

/// Request operations.
pub mod control_request {
    use prost::Oneof;

    use super::{Empty, LogQuery, RoleChange};

    /// Exactly one supported CLI-to-agent operation.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Operation {
        /// Return a compact health snapshot.
        #[prost(message, tag = "10")]
        Status(Empty),
        /// Establish route contexts according to current policy.
        #[prost(message, tag = "11")]
        Connect(Empty),
        /// Drain and remove all route contexts.
        #[prost(message, tag = "12")]
        Disconnect(Empty),
        /// List locally known public peers.
        #[prost(message, tag = "13")]
        Peers(Empty),
        /// List selected paths.
        #[prost(message, tag = "14")]
        Paths(Empty),
        /// List ephemeral sessions.
        #[prost(message, tag = "15")]
        Sessions(Empty),
        /// Return active policy metadata.
        #[prost(message, tag = "16")]
        PolicyStatus(Empty),
        /// Enable or disable a service role.
        #[prost(message, tag = "17")]
        SetRole(RoleChange),
        /// Return role state.
        #[prost(message, tag = "18")]
        Roles(Empty),
        /// Return a bounded recent in-memory log window.
        #[prost(message, tag = "19")]
        Logs(LogQuery),
    }
}

/// Empty operation payload.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct Empty {}

/// Independently configurable node role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum NodeRole {
    /// Local client role, always enabled in v1 production configuration.
    Client = 0,
    /// Relay forwarding role.
    Relay = 1,
    /// Policy-enforcing exit role.
    Exit = 2,
}

/// A typed role update.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct RoleChange {
    /// Role to update.
    #[prost(enumeration = "NodeRole", tag = "1")]
    pub role: i32,
    /// Desired state.
    #[prost(bool, tag = "2")]
    pub enabled: bool,
}

/// Query for recent privacy-safe log records.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct LogQuery {
    /// Maximum number of records, 1 through 1,000.
    #[prost(uint32, tag = "1")]
    pub maximum_records: u32,
}

/// Overall result category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ControlResult {
    /// The operation succeeded.
    Ok = 0,
    /// Request syntax or semantics were invalid.
    InvalidRequest = 1,
    /// Operation cannot run in the current lifecycle state.
    InvalidState = 2,
    /// Active policy rejected or prevented the operation.
    Policy = 3,
    /// Privileged helper was unavailable or rejected an operation.
    Helper = 4,
    /// An internal resource was unavailable.
    Unavailable = 5,
}

/// Response returned by the agent.
#[derive(Clone, PartialEq, Message)]
pub struct ControlResponse {
    /// Exact protocol version.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Exact echoed request ID.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// Stable result category.
    #[prost(enumeration = "ControlResult", tag = "3")]
    pub result: i32,
    /// Stable diagnostic code, never an arbitrary upstream error string.
    #[prost(string, tag = "4")]
    pub diagnostic_code: String,
    /// Typed response body.
    #[prost(
        oneof = "control_response::Payload",
        tags = "10, 11, 12, 13, 14, 15, 16, 17"
    )]
    pub payload: Option<control_response::Payload>,
}

/// Response payloads.
pub mod control_response {
    use prost::Oneof;

    use super::{
        Empty, LogList, PathList, PeerList, PolicySnapshot, RoleSnapshot, SessionList,
        StatusSnapshot,
    };

    /// Exactly one response body.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Payload {
        /// Generic acknowledgement.
        #[prost(message, tag = "10")]
        Ack(Empty),
        /// Agent health and connection state.
        #[prost(message, tag = "11")]
        Status(StatusSnapshot),
        /// Known peers.
        #[prost(message, tag = "12")]
        Peers(PeerList),
        /// Route paths.
        #[prost(message, tag = "13")]
        Paths(PathList),
        /// Sessions.
        #[prost(message, tag = "14")]
        Sessions(SessionList),
        /// Active policy metadata.
        #[prost(message, tag = "15")]
        Policy(PolicySnapshot),
        /// Role state.
        #[prost(message, tag = "16")]
        Roles(RoleSnapshot),
        /// Recent in-memory privacy-safe logs.
        #[prost(message, tag = "17")]
        Logs(LogList),
    }
}

/// Compact agent status.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct StatusSnapshot {
    /// Whether at least one usable route context is active.
    #[prost(bool, tag = "1")]
    pub connected: bool,
    /// Number of connected libp2p peers.
    #[prost(uint32, tag = "2")]
    pub active_peers: u32,
    /// Number of usable candidates.
    #[prost(uint32, tag = "3")]
    pub candidate_pool: u32,
    /// Number of active route contexts.
    #[prost(uint32, tag = "4")]
    pub active_contexts: u32,
    /// Number of data-carrying MPTCP subflows.
    #[prost(uint32, tag = "5")]
    pub mptcp_subflows: u32,
    /// Number of data-carrying outer MPQUIC paths.
    #[prost(uint32, tag = "6")]
    pub mpquic_paths: u32,
}

/// Reachability derived from local observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum Reachability {
    /// No observation yet.
    Unknown = 0,
    /// Recently reachable directly.
    Direct = 1,
    /// Reachable only through control-plane circuit relay.
    RelayedControl = 2,
    /// Recently unreachable.
    Unreachable = 3,
}

/// Public peer metadata safe for local display.
#[derive(Clone, PartialEq, Message)]
pub struct PeerSummary {
    /// libp2p Peer ID.
    #[prost(string, tag = "1")]
    pub peer_id: String,
    /// Bit zero client, bit one relay, bit two exit.
    #[prost(uint32, tag = "2")]
    pub role_bits: u32,
    /// Locally observed reachability.
    #[prost(enumeration = "Reachability", tag = "3")]
    pub reachability: i32,
    /// Monotonic advertisement sequence.
    #[prost(uint64, tag = "4")]
    pub advertisement_sequence: u64,
}

/// Bounded peer response.
#[derive(Clone, PartialEq, Message)]
pub struct PeerList {
    /// Known peers.
    #[prost(message, repeated, tag = "1")]
    pub peers: Vec<PeerSummary>,
}

/// Route-local path state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum PathState {
    /// Reachability not yet proven.
    Cold = 0,
    /// Both legs reachable.
    Reachable = 1,
    /// Ready but not scheduled.
    Warm = 2,
    /// Carries user data.
    Active = 3,
    /// Warm failover path.
    Backup = 4,
    /// Still usable but below quality bounds.
    Degraded = 5,
    /// Unusable and pending cleanup.
    Dead = 6,
}

/// One selected client-relay-exit path.
#[derive(Clone, PartialEq, Message)]
pub struct PathSummary {
    /// Random route-context ID, always 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Route-local path number, 1 through 8.
    #[prost(uint32, tag = "2")]
    pub path_id: u32,
    /// Relay Peer ID.
    #[prost(string, tag = "3")]
    pub relay_peer_id: String,
    /// Exit Peer ID.
    #[prost(string, tag = "4")]
    pub exit_peer_id: String,
    /// Current lifecycle state.
    #[prost(enumeration = "PathState", tag = "5")]
    pub state: i32,
    /// Smoothed complete-path RTT in microseconds.
    #[prost(uint64, tag = "6")]
    pub smoothed_rtt_micros: u64,
    /// Bytes carried in this context without durable destination metadata.
    #[prost(uint64, tag = "7")]
    pub user_bytes: u64,
}

/// Bounded path response.
#[derive(Clone, PartialEq, Message)]
pub struct PathList {
    /// Selected paths.
    #[prost(message, repeated, tag = "1")]
    pub paths: Vec<PathSummary>,
}

/// Session transport class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum SessionTransport {
    /// MPTCP-backed streaming proxy.
    Mptcp = 0,
    /// One-relay QUIC DATAGRAM association.
    SinglePathUdp = 1,
    /// MASQUE over genuine Multipath QUIC.
    MultipathQuic = 2,
}

/// One ephemeral local session without destination metadata.
#[derive(Clone, PartialEq, Message)]
pub struct SessionSummary {
    /// Random ephemeral session ID, always 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// Transport class.
    #[prost(enumeration = "SessionTransport", tag = "2")]
    pub transport: i32,
    /// Current number of usable paths.
    #[prost(uint32, tag = "3")]
    pub active_paths: u32,
    /// Net user bytes, separate from tunnel bytes.
    #[prost(uint64, tag = "4")]
    pub user_bytes: u64,
    /// Physical outer tunnel bytes.
    #[prost(uint64, tag = "5")]
    pub tunnel_bytes: u64,
}

/// Bounded session response.
#[derive(Clone, PartialEq, Message)]
pub struct SessionList {
    /// Active sessions.
    #[prost(message, repeated, tag = "1")]
    pub sessions: Vec<SessionSummary>,
}

/// Active threshold-verified policy metadata.
#[derive(Clone, PartialEq, Message)]
pub struct PolicySnapshot {
    /// Monotonic manifest version.
    #[prost(uint64, tag = "1")]
    pub manifest_version: u64,
    /// Canonical 32-byte manifest hash.
    #[prost(bytes = "vec", tag = "2")]
    pub policy_hash: Vec<u8>,
    /// Unix millisecond expiration time.
    #[prost(uint64, tag = "3")]
    pub expires_at_ms: u64,
    /// Verified unique production signatures.
    #[prost(uint32, tag = "4")]
    pub verified_signatures: u32,
    /// Whether it is active at the agent's checked clock time.
    #[prost(bool, tag = "5")]
    pub active: bool,
}

/// Independently enabled role state.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct RoleSnapshot {
    /// Client role.
    #[prost(bool, tag = "1")]
    pub client: bool,
    /// Relay role.
    #[prost(bool, tag = "2")]
    pub relay: bool,
    /// Exit role.
    #[prost(bool, tag = "3")]
    pub exit: bool,
}

/// Log severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum LogLevel {
    /// Diagnostic detail.
    Debug = 0,
    /// Normal operation.
    Info = 1,
    /// Recoverable degradation.
    Warn = 2,
    /// Operation failed.
    Error = 3,
}

/// Privacy-safe in-memory log record.
#[derive(Clone, PartialEq, Message)]
pub struct LogRecord {
    /// Unix millisecond timestamp.
    #[prost(uint64, tag = "1")]
    pub timestamp_ms: u64,
    /// Severity.
    #[prost(enumeration = "LogLevel", tag = "2")]
    pub level: i32,
    /// Stable bounded event code.
    #[prost(string, tag = "3")]
    pub event_code: String,
    /// Optional 16-byte ephemeral session ID.
    #[prost(bytes = "vec", tag = "4")]
    pub session_id: Vec<u8>,
    /// Optional path number.
    #[prost(uint32, optional, tag = "5")]
    pub path_id: Option<u32>,
}

/// Bounded log response.
#[derive(Clone, PartialEq, Message)]
pub struct LogList {
    /// Recent records.
    #[prost(message, repeated, tag = "1")]
    pub records: Vec<LogRecord>,
}

/// Local protocol failures.
#[derive(Debug, Error)]
pub enum ControlProtocolError {
    /// Socket I/O failed.
    #[error("local control socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Protocol Buffer input was malformed.
    #[error("malformed local control protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    /// Complete frame exceeds the fixed resource bound.
    #[error("local control frame exceeds {MAX_CONTROL_FRAME} bytes")]
    TooLarge,
    /// A typed invariant failed.
    #[error("invalid local control message: {0}")]
    Invalid(&'static str),
}

/// Validate and encode a request without its length prefix.
///
/// # Errors
///
/// Returns an error when request validation fails or the encoded message exceeds the hard limit.
pub fn encode_request(request: &ControlRequest) -> Result<Vec<u8>, ControlProtocolError> {
    validate_request(request)?;
    encode_message(request)
}

/// Validate and encode a response without its length prefix.
///
/// # Errors
///
/// Returns an error when response validation fails or the encoded message exceeds the hard limit.
pub fn encode_response(response: &ControlResponse) -> Result<Vec<u8>, ControlProtocolError> {
    validate_response(response)?;
    encode_message(response)
}

/// Decode and validate a bounded request payload.
///
/// # Errors
///
/// Returns an error for empty, oversized, malformed, or semantically invalid payloads.
pub fn decode_request(payload: &[u8]) -> Result<ControlRequest, ControlProtocolError> {
    bounded(payload)?;
    let request = ControlRequest::decode(payload)?;
    validate_request(&request)?;
    Ok(request)
}

/// Decode and validate a bounded response payload.
///
/// # Errors
///
/// Returns an error for empty, oversized, malformed, or semantically invalid payloads.
pub fn decode_response(payload: &[u8]) -> Result<ControlResponse, ControlProtocolError> {
    bounded(payload)?;
    let response = ControlResponse::decode(payload)?;
    validate_response(&response)?;
    Ok(response)
}

/// Read one length-prefixed request.
///
/// # Errors
///
/// Returns an error when the stream cannot be read or its frame is empty, oversized, malformed,
/// or semantically invalid.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlRequest, ControlProtocolError> {
    decode_request(&read_frame(reader).await?)
}

/// Read one length-prefixed response.
///
/// # Errors
///
/// Returns an error when the stream cannot be read or its frame is empty, oversized, malformed,
/// or semantically invalid.
pub async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlResponse, ControlProtocolError> {
    decode_response(&read_frame(reader).await?)
}

/// Validate and write one length-prefixed request.
///
/// # Errors
///
/// Returns an error when request validation, framing, or stream writing fails.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &ControlRequest,
) -> Result<(), ControlProtocolError> {
    write_frame(writer, &encode_request(request)?).await
}

/// Validate and write one length-prefixed response.
///
/// # Errors
///
/// Returns an error when response validation, framing, or stream writing fails.
pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &ControlResponse,
) -> Result<(), ControlProtocolError> {
    write_frame(writer, &encode_response(response)?).await
}

fn encode_message<M: Message>(message: &M) -> Result<Vec<u8>, ControlProtocolError> {
    if message.encoded_len() > MAX_CONTROL_FRAME {
        return Err(ControlProtocolError::TooLarge);
    }
    Ok(message.encode_to_vec())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, ControlProtocolError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_CONTROL_FRAME {
        return Err(ControlProtocolError::TooLarge);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), ControlProtocolError> {
    bounded(payload)?;
    let length = u32::try_from(payload.len()).map_err(|_| ControlProtocolError::TooLarge)?;
    writer.write_u32(length).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn bounded(payload: &[u8]) -> Result<(), ControlProtocolError> {
    if payload.is_empty() || payload.len() > MAX_CONTROL_FRAME {
        Err(ControlProtocolError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_request(request: &ControlRequest) -> Result<(), ControlProtocolError> {
    validate_header(request.protocol_version, &request.request_id)?;
    match request
        .operation
        .as_ref()
        .ok_or(ControlProtocolError::Invalid("missing operation"))?
    {
        control_request::Operation::SetRole(change) => {
            let role = NodeRole::try_from(change.role)
                .map_err(|_| ControlProtocolError::Invalid("role"))?;
            if role == NodeRole::Client && !change.enabled {
                return Err(ControlProtocolError::Invalid(
                    "client role cannot be disabled",
                ));
            }
        }
        control_request::Operation::Logs(query) => {
            if !(1..=1_000).contains(&query.maximum_records) {
                return Err(ControlProtocolError::Invalid("log result bound"));
            }
        }
        control_request::Operation::Status(_)
        | control_request::Operation::Connect(_)
        | control_request::Operation::Disconnect(_)
        | control_request::Operation::Peers(_)
        | control_request::Operation::Paths(_)
        | control_request::Operation::Sessions(_)
        | control_request::Operation::PolicyStatus(_)
        | control_request::Operation::Roles(_) => {}
    }
    Ok(())
}

fn validate_response(response: &ControlResponse) -> Result<(), ControlProtocolError> {
    validate_header(response.protocol_version, &response.request_id)?;
    ControlResult::try_from(response.result)
        .map_err(|_| ControlProtocolError::Invalid("result"))?;
    safe_code(&response.diagnostic_code)?;
    let payload = response
        .payload
        .as_ref()
        .ok_or(ControlProtocolError::Invalid("missing response payload"))?;
    match payload {
        control_response::Payload::Peers(list) => {
            list_len(list.peers.len())?;
            for peer in &list.peers {
                peer_id(&peer.peer_id)?;
                Reachability::try_from(peer.reachability)
                    .map_err(|_| ControlProtocolError::Invalid("reachability"))?;
                if peer.role_bits & !0b111 != 0 {
                    return Err(ControlProtocolError::Invalid("peer role bits"));
                }
            }
        }
        control_response::Payload::Paths(list) => {
            list_len(list.paths.len())?;
            for path in &list.paths {
                fixed_or_empty(&path.route_context_id, 16, false)?;
                if !(1..=8).contains(&path.path_id) {
                    return Err(ControlProtocolError::Invalid("path ID"));
                }
                peer_id(&path.relay_peer_id)?;
                peer_id(&path.exit_peer_id)?;
                PathState::try_from(path.state)
                    .map_err(|_| ControlProtocolError::Invalid("path state"))?;
            }
        }
        control_response::Payload::Sessions(list) => {
            list_len(list.sessions.len())?;
            for session in &list.sessions {
                fixed_or_empty(&session.session_id, 16, false)?;
                SessionTransport::try_from(session.transport)
                    .map_err(|_| ControlProtocolError::Invalid("session transport"))?;
                if session.active_paths > 8 {
                    return Err(ControlProtocolError::Invalid("session path count"));
                }
            }
        }
        control_response::Payload::Policy(policy) => {
            fixed_or_empty(&policy.policy_hash, 32, !policy.active)?;
            if policy.active
                && (policy.manifest_version == 0
                    || policy.expires_at_ms == 0
                    || policy.verified_signatures == 0)
            {
                return Err(ControlProtocolError::Invalid("active policy metadata"));
            }
        }
        control_response::Payload::Logs(list) => {
            if list.records.len() > 1_000 {
                return Err(ControlProtocolError::Invalid("log result bound"));
            }
            for record in &list.records {
                LogLevel::try_from(record.level)
                    .map_err(|_| ControlProtocolError::Invalid("log level"))?;
                safe_code(&record.event_code)?;
                fixed_or_empty(&record.session_id, 16, true)?;
                if record.path_id.is_some_and(|path| !(1..=8).contains(&path)) {
                    return Err(ControlProtocolError::Invalid("log path ID"));
                }
            }
        }
        control_response::Payload::Ack(_)
        | control_response::Payload::Status(_)
        | control_response::Payload::Roles(_) => {}
    }
    Ok(())
}

fn validate_header(version: u32, request_id: &[u8]) -> Result<(), ControlProtocolError> {
    if version != CONTROL_PROTOCOL_VERSION {
        return Err(ControlProtocolError::Invalid("protocol version"));
    }
    fixed_or_empty(request_id, 16, false)
}

fn fixed_or_empty(
    value: &[u8],
    exact: usize,
    empty_allowed: bool,
) -> Result<(), ControlProtocolError> {
    if value.len() == exact || (empty_allowed && value.is_empty()) {
        Ok(())
    } else {
        Err(ControlProtocolError::Invalid("fixed-width field"))
    }
}

fn peer_id(value: &str) -> Result<(), ControlProtocolError> {
    if value.is_empty()
        || value.len() > MAX_PEER_ID_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(ControlProtocolError::Invalid("peer ID"));
    }
    Ok(())
}

fn safe_code(value: &str) -> Result<(), ControlProtocolError> {
    if value.is_empty()
        || value.len() > MAX_CODE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ControlProtocolError::Invalid("diagnostic code"));
    }
    Ok(())
}

fn list_len(length: usize) -> Result<(), ControlProtocolError> {
    if length > MAX_LIST_ITEMS {
        Err(ControlProtocolError::Invalid("list bound"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_request() -> ControlRequest {
        ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            operation: Some(control_request::Operation::Status(Empty {})),
        }
    }

    #[test]
    fn request_round_trip_is_bounded_and_typed() {
        let encoded = encode_request(&status_request()).expect("valid request");
        assert_eq!(decode_request(&encoded).expect("decode"), status_request());
    }

    #[test]
    fn rejects_unknown_version_and_client_disable() {
        let mut request = status_request();
        request.protocol_version = CONTROL_PROTOCOL_VERSION + 1;
        assert!(encode_request(&request).is_err());

        request.protocol_version = CONTROL_PROTOCOL_VERSION;
        request.operation = Some(control_request::Operation::SetRole(RoleChange {
            role: NodeRole::Client as i32,
            enabled: false,
        }));
        assert!(encode_request(&request).is_err());
    }

    #[test]
    fn response_rejects_destination_like_free_text() {
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            result: ControlResult::Policy as i32,
            diagnostic_code: "example.com".to_owned(),
            payload: Some(control_response::Payload::Ack(Empty {})),
        };
        assert!(encode_response(&response).is_err());
    }

    #[tokio::test]
    async fn frame_reader_rejects_length_before_allocation() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME + 1)
            .expect("bound fits")
            .to_be_bytes();
        let mut input = oversized.as_slice();
        assert!(matches!(
            read_request(&mut input).await,
            Err(ControlProtocolError::TooLarge)
        ));
    }
}
