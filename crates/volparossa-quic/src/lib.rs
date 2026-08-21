//! Bound-checked QUIC classification and genuine-multipath scheduling primitives.

mod client;
mod control;
mod initial;
mod scheduler;

pub use client::{NativeClient, NativeClientError};
pub use control::{
    AddPath, ControlError, GetStatus, MAX_AUTH_SECRET, MAX_AUTHORIZATION_FUTURE_MS,
    MAX_CONTROL_FRAME, MAX_INNER_PACKET, MAX_MASQUE_CONTEXT_ID, MAX_TLS_SERVER_NAME,
    NativePathStatus, NativeRequest, NativeResponse, NativeResultCode, ReceiveDatagram,
    ReceivedDatagram, RemovePath, SendDatagram, StartExitSession, StartSession, StopSession,
    TransportMode, decode_request, decode_response, encode_request, encode_response,
    native_request, read_request, read_response,
};
pub use initial::{QuicInitial, QuicInitialError, parse_initial};
pub use scheduler::{
    Direction, MultipathSet, PathState, PathTelemetry, ScheduleError, Scheduler,
    WeightedLatencyBandwidthScheduler,
};

/// Native control API version spoken by this Rust release.
pub const NATIVE_API_VERSION: u32 = 4;
