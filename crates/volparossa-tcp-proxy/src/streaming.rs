use std::time::Duration;

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{self, Instant},
};

use crate::TcpProxyError;

/// Hard maximum for each directional userspace streaming buffer.
pub const MAX_STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// Fixed memory, byte, and idle bounds for one proxied TCP flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamTransferLimits {
    buffer_bytes: usize,
    maximum_client_to_exit_bytes: u64,
    maximum_exit_to_client_bytes: u64,
    idle_timeout: Duration,
}

impl StreamTransferLimits {
    /// Construct explicit per-flow streaming limits.
    ///
    /// # Errors
    ///
    /// Zero limits, zero idle time, and buffers above 64 KiB are rejected.
    pub fn new(
        buffer_bytes: usize,
        maximum_client_to_exit_bytes: u64,
        maximum_exit_to_client_bytes: u64,
        idle_timeout: Duration,
    ) -> Result<Self, TcpProxyError> {
        if buffer_bytes == 0 || buffer_bytes > MAX_STREAM_BUFFER_BYTES {
            return Err(TcpProxyError::InvalidBinding("stream buffer size"));
        }
        if maximum_client_to_exit_bytes == 0 || maximum_exit_to_client_bytes == 0 {
            return Err(TcpProxyError::InvalidBinding("stream byte limit"));
        }
        if idle_timeout.is_zero() {
            return Err(TcpProxyError::InvalidBinding("stream idle timeout"));
        }
        Ok(Self {
            buffer_bytes,
            maximum_client_to_exit_bytes,
            maximum_exit_to_client_bytes,
            idle_timeout,
        })
    }

    /// Return the allocation bound for each direction.
    #[must_use]
    pub const fn buffer_bytes(self) -> usize {
        self.buffer_bytes
    }

    /// Return the maximum bytes accepted from the local application.
    #[must_use]
    pub const fn maximum_client_to_exit_bytes(self) -> u64 {
        self.maximum_client_to_exit_bytes
    }

    /// Return the maximum bytes accepted from the exit.
    #[must_use]
    pub const fn maximum_exit_to_client_bytes(self) -> u64 {
        self.maximum_exit_to_client_bytes
    }

    /// Return the whole-flow idle timeout.
    #[must_use]
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }
}

/// Byte counts returned after both stream directions close cleanly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamTransferStats {
    /// Bytes forwarded from the client application toward the exit.
    pub client_to_exit_bytes: u64,
    /// Bytes forwarded from the exit toward the client application.
    pub exit_to_client_bytes: u64,
}

/// Forward available contiguous bytes in both directions without message-sized
/// buffering, batching, duplication, or application-protocol reassembly.
///
/// The two buffers are fixed at construction. A single idle timer is reset by
/// successfully forwarded bytes in either direction. EOF is propagated as a
/// half-close so response data can continue after a request-side shutdown.
///
/// # Errors
///
/// Returns an I/O error, whole-flow idle timeout, or directional byte-limit
/// error. The caller should then close both transports.
pub async fn proxy_bidirectional<C, E>(
    client: C,
    exit: E,
    limits: StreamTransferLimits,
) -> Result<StreamTransferStats, TcpProxyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    E: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = io::split(client);
    let (mut exit_reader, mut exit_writer) = io::split(exit);
    let mut client_buffer = vec![0_u8; limits.buffer_bytes];
    let mut exit_buffer = vec![0_u8; limits.buffer_bytes];
    let mut client_open = true;
    let mut exit_open = true;
    let mut statistics = StreamTransferStats::default();
    let idle = time::sleep(limits.idle_timeout);
    tokio::pin!(idle);

    while client_open || exit_open {
        tokio::select! {
            result = client_reader.read(&mut client_buffer), if client_open => {
                let count = result?;
                if count == 0 {
                    client_open = false;
                    timed_shutdown(&mut exit_writer, limits.idle_timeout).await?;
                    continue;
                }
                statistics.client_to_exit_bytes = checked_total(
                    statistics.client_to_exit_bytes,
                    count,
                    limits.maximum_client_to_exit_bytes,
                )?;
                timed_write(&mut exit_writer, &client_buffer[..count], limits.idle_timeout).await?;
                idle.as_mut().reset(Instant::now() + limits.idle_timeout);
            }
            result = exit_reader.read(&mut exit_buffer), if exit_open => {
                let count = result?;
                if count == 0 {
                    exit_open = false;
                    timed_shutdown(&mut client_writer, limits.idle_timeout).await?;
                    continue;
                }
                statistics.exit_to_client_bytes = checked_total(
                    statistics.exit_to_client_bytes,
                    count,
                    limits.maximum_exit_to_client_bytes,
                )?;
                timed_write(&mut client_writer, &exit_buffer[..count], limits.idle_timeout).await?;
                idle.as_mut().reset(Instant::now() + limits.idle_timeout);
            }
            () = &mut idle => return Err(TcpProxyError::IdleTimeout),
        }
    }

    Ok(statistics)
}

fn checked_total(current: u64, count: usize, maximum: u64) -> Result<u64, TcpProxyError> {
    let count = u64::try_from(count).map_err(|_| TcpProxyError::ByteLimit)?;
    let total = current.checked_add(count).ok_or(TcpProxyError::ByteLimit)?;
    if total > maximum {
        return Err(TcpProxyError::ByteLimit);
    }
    Ok(total)
}

async fn timed_write<W>(
    writer: &mut W,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), TcpProxyError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.write_all(bytes))
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    Ok(())
}

async fn timed_shutdown<W>(writer: &mut W, timeout: Duration) -> Result<(), TcpProxyError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.shutdown())
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
    Ok(())
}
