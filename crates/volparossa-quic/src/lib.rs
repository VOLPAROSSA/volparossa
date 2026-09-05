//! Bound-checked QUIC classification and genuine-multipath scheduling primitives.

mod client;
mod control;
mod initial;
mod scheduler;

pub use client::{NativeClient, NativeClientError, VerifiedExitMpquicEndpoint};
pub use control::{
    AUTH_SECRET_LEN, AddPath, ControlError, GetStatus, MAX_AUTH_SECRET,
    MAX_AUTHORIZATION_FUTURE_MS, MAX_CONTROL_FRAME, MAX_INNER_PACKET, MAX_MASQUE_CONTEXT_ID,
    MAX_TLS_CERTIFICATE_PEM, MAX_TLS_PRIVATE_KEY_PEM, MAX_TLS_SERVER_NAME,
    NATIVE_REQUEST_DIGEST_DOMAIN, NativePathStatus, NativeProcessIdentity, NativeProcessRole,
    NativeRequest, NativeResponse, NativeResultCode, Preflight, ReceiveDatagram, ReceivedDatagram,
    RemovePath, SendDatagram, StartExitSession, StartSession, StopSession, TransportMode,
    TunnelAssignment, decode_request, decode_response, encode_request, encode_response,
    native_request, read_request, read_response, request_sha256,
};
pub use initial::{QuicInitial, QuicInitialError, parse_initial};
pub use scheduler::{
    Direction, MultipathSet, PathState, PathTelemetry, ScheduleError, Scheduler,
    WeightedLatencyBandwidthScheduler,
};

/// Native control API version spoken by this Rust release.
pub const NATIVE_API_VERSION: u32 = 6;
