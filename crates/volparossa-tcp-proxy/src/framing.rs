use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, ReplayCache, TimePolicy, frame_control_message,
};

use crate::{AuthorizedTcpFlow, TcpAuthorizationScope, TcpProxyError};

/// Write one complete, length-prefixed signed `OPEN_TCP` before payload bytes.
///
/// # Errors
///
/// Returns a framing error for an oversized envelope, an I/O error, or an idle
/// timeout while the frame is being written.
pub async fn write_open_tcp<W>(
    writer: &mut W,
    signed_open_tcp: &[u8],
    timeout: Duration,
) -> Result<(), TcpProxyError>
where
    W: AsyncWrite + Unpin,
{
    if timeout.is_zero() {
        return Err(TcpProxyError::InvalidBinding("OPEN_TCP write timeout"));
    }
    let frame = frame_control_message(signed_open_tcp)?;
    time::timeout(timeout, writer.write_all(&frame))
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    time::timeout(timeout, writer.flush())
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    Ok(())
}

/// Read exactly one bounded opening frame and verify its signature, replay
/// status, route scope, expiry, policy hash, and destination rule.
///
/// Bytes after the frame remain unread and can be streamed immediately.
///
/// # Errors
///
/// Fails closed for malformed/truncated/oversized framing, timeout, signature,
/// replay, route binding, expiry, or whitelist denial.
pub async fn read_authorized_open_tcp<R>(
    reader: &mut R,
    scope: &TcpAuthorizationScope<'_>,
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
    timeout: Duration,
) -> Result<AuthorizedTcpFlow, TcpProxyError>
where
    R: AsyncRead + Unpin,
{
    let payload = read_frame(reader, timeout).await?;
    scope.verify(&payload, now_ms, time_policy, replay_cache)
}

async fn read_frame<R>(reader: &mut R, timeout: Duration) -> Result<Vec<u8>, TcpProxyError>
where
    R: AsyncRead + Unpin,
{
    if timeout.is_zero() {
        return Err(TcpProxyError::InvalidBinding("OPEN_TCP read timeout"));
    }
    let mut length_bytes = [0_u8; 4];
    time::timeout(timeout, reader.read_exact(&mut length_bytes))
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| TcpProxyError::InvalidBinding("OPEN_TCP frame length"))?;
    if length == 0 || length > MAX_CONTROL_MESSAGE_SIZE {
        return Err(volparossa_protocol::ProtocolError::InvalidFrame.into());
    }
    let mut payload = vec![0_u8; length];
    time::timeout(timeout, reader.read_exact(&mut payload))
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    Ok(payload)
}
