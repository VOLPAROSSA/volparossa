//! Preserve MPTCP joinability while TLS carries an authenticated directional EOF.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

/// The exact negotiated MPTCP socket owned by a TLS session, without descriptor duplication.
///
/// TLS `close_notify` carries the application's directional EOF. Closing the underlying
/// MPTCP write half at that point puts the peers in FIN-WAIT/CLOSE-WAIT and prevents Linux
/// from joining newly signalled paths during the remaining response. Rustls still flushes
/// and authenticates its close notification; this adapter defers only the transport FIN.
/// Dropping the completed or cancelled TLS flow closes its one owned descriptor normally.
pub struct TlsMptcpIo(TcpStream);

impl TlsMptcpIo {
    pub(super) const fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
}

impl AsFd for TlsMptcpIo {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsyncRead for TlsMptcpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for TlsMptcpIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Tokio-rustls has already queued close_notify and drains its ciphertext before
        // invoking this method. Do not discard that EOF or shutdown the MPTCP write half.
        self.poll_flush(context)
    }
}
