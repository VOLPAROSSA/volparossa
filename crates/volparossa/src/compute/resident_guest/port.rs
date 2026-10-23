//! One fixed virtio console port. No host listener, network setup or arbitrary path.

use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _},
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};

pub(super) struct Port(AsyncFd<File>);

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
        Ok(Self(AsyncFd::new(file)?))
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
            match ready.try_io(|fd| fd.get_ref().read(buffer.initialize_unfilled())) {
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
            if let Ok(result) = ready.try_io(|fd| fd.get_ref().write(bytes)) {
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
