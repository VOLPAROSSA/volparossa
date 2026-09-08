//! Count actual incoming bytes after pressure has drained the other stream leases.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

pub(super) struct MeasuredStream {
    pub inner: DuplexStream,
    pub active: Arc<AtomicUsize>,
    pub allowance: Arc<AtomicUsize>,
    pub drained_payload: Arc<AtomicUsize>,
}

impl AsyncRead for MeasuredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if result.is_ready()
            && self.allowance.load(Ordering::SeqCst) == 1
            && self.active.load(Ordering::SeqCst) == 1
        {
            self.drained_payload
                .fetch_add(buffer.filled().len() - before, Ordering::SeqCst);
        }
        result
    }
}

impl AsyncWrite for MeasuredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
