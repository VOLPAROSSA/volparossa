use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

#[derive(Default)]
struct CloseIo {
    shutdown_error: Option<io::ErrorKind>,
    read_error: Option<io::ErrorKind>,
    shutdown_pending: bool,
    read_pending: bool,
    trailing: bool,
    reads: usize,
    shutdowns: usize,
}

impl AsyncRead for CloseIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        assert_eq!(buffer.remaining(), 1);
        if self.read_pending {
            return Poll::Pending;
        }
        if let Some(kind) = self.read_error {
            return Poll::Ready(Err(io::Error::new(kind, "private-close-canary")));
        }
        if self.trailing {
            buffer.put_slice(&[93]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CloseIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("finish must not write application bytes")
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("finish must retain its original shutdown/read sequence")
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        if self.shutdown_pending {
            return Poll::Pending;
        }
        Poll::Ready(self.shutdown_error.map_or(Ok(()), |kind| {
            Err(io::Error::new(kind, "private-close-canary"))
        }))
    }
}

#[tokio::test]
async fn tls_close_v9_shutdown_io_does_not_poll_read_or_export_error_text() {
    for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::TimedOut] {
        let mut stream = CloseIo {
            shutdown_error: Some(kind),
            ..CloseIo::default()
        };
        let failure = finish_classified(&mut stream).await.unwrap_err();
        assert_eq!(failure, PrivateStorageTlsCloseFailure::ShutdownIo);
        assert_eq!((stream.shutdowns, stream.reads), (1, 0));
        assert!(!format!("{failure:?}").contains("private-close-canary"));
    }
}

#[tokio::test]
async fn tls_close_v9_read_io_is_distinct_from_clean_eof_and_internal_deadline() {
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::TimedOut,
    ] {
        let mut stream = CloseIo {
            read_error: Some(kind),
            ..CloseIo::default()
        };
        assert_eq!(
            finish_classified(&mut stream).await,
            Err(PrivateStorageTlsCloseFailure::ReadIo)
        );
        assert_eq!((stream.shutdowns, stream.reads), (1, 1));
    }
}

#[tokio::test]
async fn tls_close_v9_trailing_byte_is_rejected_without_exporting_its_value() {
    let mut stream = CloseIo {
        trailing: true,
        ..CloseIo::default()
    };
    assert_eq!(
        finish_classified(&mut stream).await,
        Err(PrivateStorageTlsCloseFailure::TrailingData)
    );
    assert_eq!((stream.shutdowns, stream.reads), (1, 1));
    let mut clean = CloseIo::default();
    assert_eq!(finish_classified(&mut clean).await, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn tls_close_v9_internal_deadline_keeps_original_ten_second_budget() {
    for shutdown_pending in [false, true] {
        let mut stream = CloseIo {
            shutdown_pending,
            read_pending: true,
            ..CloseIo::default()
        };
        let started = tokio::time::Instant::now();
        assert_eq!(
            finish_classified(&mut stream).await,
            Err(PrivateStorageTlsCloseFailure::InternalDeadline)
        );
        assert_eq!(tokio::time::Instant::now() - started, CLOSE_TIMEOUT);
        assert_eq!(CLOSE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(stream.reads == 0, shutdown_pending);
    }
}

#[tokio::test]
async fn tls_close_v9_legacy_wrapper_keeps_error_and_success_semantics() {
    for mut stream in [
        CloseIo {
            shutdown_error: Some(io::ErrorKind::BrokenPipe),
            ..CloseIo::default()
        },
        CloseIo {
            read_error: Some(io::ErrorKind::UnexpectedEof),
            ..CloseIo::default()
        },
        CloseIo {
            trailing: true,
            ..CloseIo::default()
        },
    ] {
        assert!(matches!(
            finish(&mut stream).await,
            Err(ContentTlsError::Close)
        ));
    }
    let (mut local, mut peer) = tokio::io::duplex(16);
    peer.shutdown().await.unwrap();
    finish(&mut local).await.unwrap();
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}
