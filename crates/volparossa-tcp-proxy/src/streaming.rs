use std::time::Duration;

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
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

#[derive(Clone, Copy)]
struct StreamProgress {
    last_forwarded: Instant,
    operations_in_flight: usize,
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
    let (client_reader, client_writer) = io::split(client);
    let (exit_reader, exit_writer) = io::split(exit);
    let (progress, mut changes) = watch::channel(StreamProgress {
        last_forwarded: Instant::now(),
        operations_in_flight: 0,
    });
    // A blocked write in either direction must not prevent draining the other one.
    // Both futures stay owned here: cancellation drops both streams and buffers;
    // no detached copy task or additional per-flow byte queue is created.
    let transfer = async {
        let (client_to_exit_bytes, exit_to_client_bytes) = tokio::try_join!(
            copy_direction(
                client_reader,
                exit_writer,
                limits.buffer_bytes,
                limits.maximum_client_to_exit_bytes,
                limits.idle_timeout,
                &progress,
            ),
            copy_direction(
                exit_reader,
                client_writer,
                limits.buffer_bytes,
                limits.maximum_exit_to_client_bytes,
                limits.idle_timeout,
                &progress,
            ),
        )?;
        Ok(StreamTransferStats {
            client_to_exit_bytes,
            exit_to_client_bytes,
        })
    };
    tokio::pin!(transfer);
    let idle = time::sleep(limits.idle_timeout);
    tokio::pin!(idle);

    loop {
        let observed = *changes.borrow_and_update();
        idle.as_mut()
            .reset(observed.last_forwarded + limits.idle_timeout);
        tokio::select! {
            biased;
            result = &mut transfer => return result,
            // The sender remains owned by this function until both directions finish.
            _ = changes.changed() => {},
            () = &mut idle, if observed.operations_in_flight == 0 => {
                // Polling transfer may just have started or completed a write. Recheck
                // its latest observation rather than expiring a stale read-idle budget.
                let current = *changes.borrow();
                if current.operations_in_flight == 0
                    && Instant::now() >= current.last_forwarded + limits.idle_timeout
                {
                    return Err(TcpProxyError::IdleTimeout);
                }
            },
        }
    }
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_bytes: usize,
    maximum_bytes: u64,
    idle_timeout: Duration,
    progress: &watch::Sender<StreamProgress>,
) -> Result<u64, TcpProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; buffer_bytes];
    let mut total = 0;
    loop {
        let count = reader.read(&mut buffer).await?;
        total = checked_total(total, count, maximum_bytes)?;
        // Preserve the original operation bounds: the shared read-idle timer was
        // suspended during write/flush and EOF propagation, each independently
        // bounded by idle_timeout. Reverse traffic must not extend a blocked write.
        progress.send_modify(|state| state.operations_in_flight += 1);
        let result = if count == 0 {
            timed_shutdown(&mut writer, idle_timeout).await
        } else {
            timed_write(&mut writer, &buffer[..count], idle_timeout).await
        };
        progress.send_modify(|state| {
            state.operations_in_flight -= 1;
            if count != 0 && result.is_ok() {
                state.last_forwarded = Instant::now();
            }
        });
        result?;
        if count == 0 {
            return Ok(total);
        }
    }
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
    time::timeout(timeout, async {
        writer.write_all(bytes).await?;
        // TLS can accept plaintext while its final encrypted record is still buffered
        // by transport backpressure. Deliver it before waiting for another read; the
        // peer may be waiting for this exact request before producing any response.
        writer.flush().await
    })
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
