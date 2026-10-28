//! One fixed virtio console port. No host listener, network setup or arbitrary path.

use anyhow::{Result, ensure};
use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _},
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use volparossa_linux_uapi::OwnedAsyncFd;

pub(super) struct Port(OwnedAsyncFd);

impl Port {
    pub(super) fn open() -> Result<Self> {
        // /dev/virtio-ports is a kernel/udev alias. Resolve exactly this trusted
        // name; do not accept a request-supplied path or follow a replacement at open.
        let path = std::fs::canonicalize("/dev/virtio-ports/org.volparossa.resident")?;
        ensure!(
            path.parent() == Some(std::path::Path::new("/dev")),
            "resident_port_path"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            file.metadata()?.file_type().is_char_device(),
            "resident_port_type"
        );
        Ok(Self(OwnedAsyncFd::register(file.into())?))
    }
}

impl AsyncRead for Port {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut ready = ready!(self.0.poll_read_ready(cx))?;
            match ready.try_io(|fd| {
                nix::unistd::read(fd.get_ref(), buffer.initialize_unfilled())
                    .map_err(io::Error::from)
            }) {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => {}
            }
        }
    }
}

impl AsyncWrite for Port {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = ready!(self.0.poll_write_ready(cx))?;
            if let Ok(result) =
                ready.try_io(|fd| nix::unistd::write(fd.get_ref(), bytes).map_err(io::Error::from))
            {
                return Poll::Ready(result);
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, time::Duration};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        time::timeout,
    };

    fn pair() -> (Port, tokio::net::UnixStream) {
        // Exercise reactor ownership and I/O without opening the privileged device.
        // This socket pair does not prove virtio hardware or guest execution.
        let (port, peer) = UnixStream::pair().unwrap();
        port.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        (
            Port(OwnedAsyncFd::register(port.into()).unwrap()),
            tokio::net::UnixStream::from_std(peer).unwrap(),
        )
    }

    #[tokio::test]
    async fn owned_port_preserves_duplex_io_empty_read_and_eof() {
        timeout(Duration::from_secs(2), async {
            let (mut port, mut peer) = pair();
            assert_eq!(port.read(&mut []).await.unwrap(), 0);
            peer.write_all(b"request").await.unwrap();
            let mut request = [0; 7];
            port.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            port.write_all(b"response").await.unwrap();
            port.flush().await.unwrap();
            let mut response = [0; 8];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
            drop(peer);
            assert_eq!(port.read(&mut request).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_read_keeps_port_usable_and_drop_closes_owned_descriptor() {
        timeout(Duration::from_secs(2), async {
            let (mut port, mut peer) = pair();
            let mut byte = [0];
            assert!(
                timeout(Duration::from_millis(10), port.read(&mut byte))
                    .await
                    .is_err()
            );
            peer.write_all(b"x").await.unwrap();
            port.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
            drop(port);
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_backpressured_write_releases_readiness_and_descriptor() {
        timeout(Duration::from_secs(2), async {
            let (mut port, mut peer) = pair();
            socket2::SockRef::from(port.0.get_ref())
                .set_send_buffer_size(4096)
                .unwrap();
            let payload = vec![0x31; 4 * 1024 * 1024];
            assert!(
                timeout(Duration::from_millis(20), port.write_all(&payload))
                    .await
                    .is_err()
            );
            drop(port);
            let mut received = Vec::new();
            peer.read_to_end(&mut received).await.unwrap();
            assert!(!received.is_empty() && received.len() < payload.len());
            assert!(received.iter().all(|byte| *byte == 0x31));
        })
        .await
        .unwrap();
    }
}
