//! Pass through every poll exactly once; hash only bytes the original I/O transferred.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Guard;

pub(in super::super) struct Observed<'a, S> {
    inner: S,
    guard: &'a Guard,
    client: bool,
}

impl<'a, S> Observed<'a, S> {
    pub(in super::super) const fn client(inner: S, guard: &'a Guard) -> Self {
        Self {
            inner,
            guard,
            client: true,
        }
    }

    pub(in super::super) const fn provider(inner: S, guard: &'a Guard) -> Self {
        Self {
            inner,
            guard,
            client: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Observed<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if !self.client && matches!(result, Poll::Ready(Ok(()))) {
            self.guard.bytes(&buf.filled()[before..]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Observed<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            if self.client {
                self.guard.bytes(&bytes[..*count]);
            }
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(count)) = &result {
            if self.client {
                let mut remaining = *count;
                for bytes in bufs {
                    let used = remaining.min(bytes.len());
                    self.guard.bytes(&bytes[..used]);
                    remaining -= used;
                    if remaining == 0 {
                        break;
                    }
                }
            }
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
