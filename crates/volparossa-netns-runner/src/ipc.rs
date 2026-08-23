use std::{
    io,
    net::Shutdown,
    os::fd::{AsRawFd, OwnedFd},
    time::Duration,
};

use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::socket::{SockType, UnixAddr, getpeername, getsockname, getsockopt, sockopt},
};
use socket2::{Domain, Protocol, Socket, Type};
use volparossa_linux_uapi::{receive_seqpacket_without_fd, send_seqpacket_without_fd};
use volparossa_test_support::MAX_LIFECYCLE_FRAME_BYTES;

/// One endpoint of a private, unnamed, descriptor-free lifecycle channel.
///
/// The channel is always an `AF_UNIX` connected `SOCK_SEQPACKET` socket with
/// `FD_CLOEXEC`. Each send and receive preserves exactly one record boundary;
/// ancillary file descriptors are rejected by the audited Linux-UAPI helper.
pub(crate) struct LifecycleChannel {
    socket: Socket,
}

impl LifecycleChannel {
    /// Create a connected unnamed socket pair with close-on-exec set atomically.
    ///
    /// # Errors
    ///
    /// Returns the kernel error or rejects a socket whose type, address, peer,
    /// or descriptor flags do not read back as the fixed channel contract.
    pub(crate) fn pair() -> io::Result<(Self, Self)> {
        let (first, second) =
            Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)?;
        let first = Self::from_socket(first)?;
        let second = Self::from_socket(second)?;
        Ok((first, second))
    }

    /// Send exactly one non-empty descriptor-free lifecycle-sized record.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized record, channel substitution,
    /// a short send, or another kernel failure.
    pub(crate) fn send(&self, record: &[u8]) -> io::Result<()> {
        validate_socket(&self.socket)?;
        if record.len() > MAX_LIFECYCLE_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lifecycle record exceeds its fixed size bound",
            ));
        }
        send_seqpacket_without_fd(&self.socket, record)
    }

    /// Receive exactly one descriptor-free lifecycle-sized record.
    ///
    /// # Errors
    ///
    /// EOF, channel substitution, truncation, any ancillary descriptor, or
    /// another kernel failure is rejected.
    pub(crate) fn receive(&self) -> io::Result<Vec<u8>> {
        validate_socket(&self.socket)?;
        receive_seqpacket_without_fd(&self.socket, MAX_LIFECYCLE_FRAME_BYTES)
    }

    pub(crate) fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_read_timeout(Some(timeout))
    }

    pub(crate) fn finish_sending(&self) -> io::Result<()> {
        self.socket.shutdown(Shutdown::Write)
    }

    pub(crate) fn peer_credentials(&self) -> io::Result<nix::sys::socket::UnixCredentials> {
        validate_socket(&self.socket)?;
        getsockopt(&self.socket, sockopt::PeerCredentials).map_err(errno_io)
    }

    pub(crate) fn from_owned_fd(descriptor: OwnedFd) -> io::Result<Self> {
        Self::from_socket(Socket::from(descriptor))
    }

    pub(crate) fn into_owned_fd(self) -> OwnedFd {
        self.socket.into()
    }

    fn from_socket(socket: Socket) -> io::Result<Self> {
        validate_socket(&socket)?;
        Ok(Self { socket })
    }
}

fn validate_socket(socket: &Socket) -> io::Result<()> {
    if socket.domain()? != Domain::UNIX
        || getsockopt(socket, sockopt::SockType).map_err(errno_io)? != SockType::SeqPacket
        || getsockopt(socket, sockopt::AcceptConn).map_err(errno_io)?
    {
        return Err(invalid_data("lifecycle channel type is invalid"));
    }
    let local = getsockname::<UnixAddr>(socket.as_raw_fd()).map_err(errno_io)?;
    let peer = getpeername::<UnixAddr>(socket.as_raw_fd()).map_err(errno_io)?;
    if !local.is_unnamed() || !peer.is_unnamed() {
        return Err(invalid_data("lifecycle channel must be unnamed"));
    }
    let descriptor_flags =
        FdFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFD).map_err(errno_io)?);
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) {
        return Err(invalid_data("lifecycle channel is not close-on-exec"));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_is_unnamed_seqpacket_cloexec_and_preserves_records() {
        let (first, second) = LifecycleChannel::pair().expect("channel pair");

        validate_socket(&first.socket).expect("first contract");
        validate_socket(&second.socket).expect("second contract");
        first.send(b"first-record").expect("send first");
        first.send(b"second-record").expect("send second");
        assert_eq!(second.receive().expect("receive first"), b"first-record");
        assert_eq!(second.receive().expect("receive second"), b"second-record");
        assert_eq!(
            first
                .send(&vec![0_u8; MAX_LIFECYCLE_FRAME_BYTES + 1])
                .expect_err("oversized record must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn stream_socket_substitution_is_rejected() {
        let (stream, _peer) = Socket::pair(Domain::UNIX, Type::STREAM.cloexec(), None::<Protocol>)
            .expect("stream pair");
        assert_eq!(
            LifecycleChannel::from_socket(stream)
                .err()
                .expect("stream must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
