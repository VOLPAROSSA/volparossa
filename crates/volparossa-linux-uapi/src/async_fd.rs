//! Ownership-sealed registration of an owned descriptor with Tokio's reactor.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};

/// A reactor registration whose owned descriptor cannot be replaced or closed by safe callers.
///
/// Tokio 1.53.3 makes `AsyncFd::register` unsafe: `AsRawFd` alone does not promise a stable,
/// live descriptor (see <https://github.com/tokio-rs/tokio/pull/8587>). This wrapper owns only `OwnedFd` and exposes no mutable inner reference,
/// owned `AsyncFd`, or mutable readiness guard. Shared readiness guards expose only shared
/// references to the registration and descriptor, so they cannot break this ownership seal.
///
/// ```compile_fail
/// use std::os::fd::OwnedFd;
/// use volparossa_linux_uapi::OwnedAsyncFd;
/// fn replace(registration: &mut OwnedAsyncFd, other: OwnedFd) {
///     *registration.get_mut() = other;
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::OwnedFd;
/// use tokio::io::unix::AsyncFd;
/// use volparossa_linux_uapi::OwnedAsyncFd;
/// fn escape(registration: OwnedAsyncFd) -> AsyncFd<OwnedFd> {
///     registration.into_inner()
/// }
/// ```
pub struct OwnedAsyncFd {
    inner: AsyncFd<OwnedFd>,
}

impl OwnedAsyncFd {
    /// Register an owned descriptor, already configured for nonblocking I/O, on the current reactor.
    ///
    /// Registration failure drops the descriptor and preserves the original I/O error.
    /// As with Tokio's constructor, this panics without a current I/O-enabled runtime.
    pub fn register(descriptor: OwnedFd) -> io::Result<Self> {
        // SAFETY: OwnedFd owns one valid descriptor with a stable AsRawFd value. Moving it into
        // the private AsyncFd keeps that descriptor open until AsyncFd deregisters and drops it.
        // No method exposes mutable/owned access to either inner object; shared guards cannot
        // replace it. Safe users therefore cannot invalidate Tokio's registration lifetime.
        let inner = unsafe { AsyncFd::register(descriptor) }.map_err(io::Error::from)?;
        Ok(Self { inner })
    }

    /// Borrow the stable owned descriptor without transferring or mutating its ownership.
    pub fn get_ref(&self) -> &OwnedFd {
        self.inner.get_ref()
    }

    /// Wait for readable readiness while borrowing this registration and its descriptor.
    pub async fn readable(&self) -> io::Result<AsyncFdReadyGuard<'_, OwnedFd>> {
        self.inner.readable().await
    }
}

impl AsFd for OwnedAsyncFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, os::fd::AsRawFd as _};

    use nix::{
        fcntl::{Flock, FlockArg, OFlag},
        sys::memfd::{MFdFlags, memfd_create},
        unistd::{pipe2, read, write},
    };

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
    }

    #[test]
    fn registration_failure_preserves_error_and_closes_owned_descriptor() {
        let runtime = runtime();
        let _entered = runtime.enter();
        let descriptor =
            memfd_create(c"async-fd-registration-failure", MFdFlags::MFD_CLOEXEC).unwrap();
        let observer = File::open(format!("/proc/self/fd/{}", descriptor.as_raw_fd())).unwrap();
        // SAFETY: descriptor owns a valid anonymous regular file. The fixed nonblocking flock
        // is used only by this test; closing the last descriptor for this description releases it.
        assert_eq!(
            unsafe { libc::flock(descriptor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let (observer, error) = Flock::lock(observer, FlockArg::LockExclusiveNonblock).unwrap_err();
        assert_eq!(error, nix::errno::Errno::EWOULDBLOCK);
        let error = OwnedAsyncFd::register(descriptor)
            .err()
            .expect("epoll rejects regular files");
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        // Lock release proves error ownership was dropped, independently of FD-number reuse.
        let _observer_lock = Flock::lock(observer, FlockArg::LockExclusiveNonblock).unwrap();
    }

    #[test]
    fn registration_drop_closes_descriptor_after_deregistration() {
        let runtime = runtime();
        let _entered = runtime.enter();
        let (descriptor, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();
        let raw = descriptor.as_raw_fd();
        let registration = OwnedAsyncFd::register(descriptor).unwrap();
        assert_eq!(registration.as_fd().as_raw_fd(), raw);
        drop(registration);
        assert_eq!(write(&writer, b"x"), Err(nix::errno::Errno::EPIPE));
    }

    #[test]
    fn shared_readiness_retains_owned_descriptor_and_observes_pipe_eof() {
        let runtime = runtime();
        runtime.block_on(async {
            let (descriptor, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();
            let registration = OwnedAsyncFd::register(descriptor).unwrap();
            let raw = registration.get_ref().as_raw_fd();
            write(&writer, b"x").unwrap();
            let mut ready = registration.readable().await.unwrap();
            assert_eq!(ready.get_inner().as_raw_fd(), raw);
            let mut byte = [0];
            assert_eq!(read(registration.get_ref(), &mut byte).unwrap(), 1);
            assert_eq!(byte, *b"x");
            ready.clear_ready();
            drop(ready);
            drop(writer);
            let _ready = registration.readable().await.unwrap();
            assert_eq!(read(registration.get_ref(), &mut byte).unwrap(), 0);
        });
    }
}
