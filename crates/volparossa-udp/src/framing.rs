use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, ReplayCache, TimePolicy, frame_control_message,
};

use crate::{AuthorizedUdpFlow, UdpAuthorizationScope, UdpError};

/// Write one bounded client-signed UDP flow authorization to a protected QUIC
/// control stream before any flow datagram is accepted.
///
/// # Errors
///
/// Returns an oversized-frame, I/O, or timeout error.
pub async fn write_udp_authorization<W>(
    writer: &mut W,
    signed_authorization: &[u8],
    timeout: Duration,
) -> Result<(), UdpError>
where
    W: AsyncWrite + Unpin,
{
    if timeout.is_zero() {
        return Err(UdpError::InvalidBinding("UDP authorization write timeout"));
    }
    let frame = frame_control_message(signed_authorization)?;
    time::timeout(timeout, writer.write_all(&frame))
        .await
        .map_err(|_| UdpError::IdleTimeout)??;
    time::timeout(timeout, writer.flush())
        .await
        .map_err(|_| UdpError::IdleTimeout)??;
    Ok(())
}

/// Read exactly one bounded control-stream frame and apply all signature,
/// replay, route, expiry, policy-hash, and tuple checks.
///
/// # Errors
///
/// Fails closed for malformed/truncated/oversized framing, timeout, signature,
/// replay, binding, expiry, or whitelist denial.
pub async fn read_authorized_udp_flow<R>(
    reader: &mut R,
    scope: &UdpAuthorizationScope<'_>,
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
    timeout: Duration,
) -> Result<AuthorizedUdpFlow, UdpError>
where
    R: AsyncRead + Unpin,
{
    if timeout.is_zero() {
        return Err(UdpError::InvalidBinding("UDP authorization read timeout"));
    }
    let mut length_bytes = [0_u8; 4];
    time::timeout(timeout, reader.read_exact(&mut length_bytes))
        .await
        .map_err(|_| UdpError::IdleTimeout)??;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| UdpError::InvalidBinding("UDP authorization frame length"))?;
    if length == 0 || length > MAX_CONTROL_MESSAGE_SIZE {
        return Err(volparossa_protocol::ProtocolError::InvalidFrame.into());
    }
    let mut payload = vec![0_u8; length];
    time::timeout(timeout, reader.read_exact(&mut payload))
        .await
        .map_err(|_| UdpError::IdleTimeout)??;
    scope.verify(&payload, now_ms, time_policy, replay_cache)
}
