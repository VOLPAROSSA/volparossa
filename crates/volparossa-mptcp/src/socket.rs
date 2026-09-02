use std::{io, net::SocketAddr, os::fd::OwnedFd, time::Duration};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{net, time};

/// Tokio stream whose underlying Linux socket was explicitly created with `IPPROTO_MPTCP`.
#[derive(Debug)]
pub struct MptcpStream(net::TcpStream);

impl MptcpStream {
    /// Adopts one already-connected socket received from a trusted namespace owner.
    ///
    /// The descriptor is consumed on both success and failure. It is accepted only when the
    /// kernel proves that the peer completed genuine MPTCP negotiation without ordinary-TCP
    /// fallback. This permits a privileged route-namespace worker to hand a connected socket to
    /// the unprivileged agent without moving either process between network namespaces.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is not a connected TCP-compatible socket, cannot be
    /// made nonblocking, cannot be registered with Tokio, or lacks genuine MPTCP negotiation.
    pub fn from_connected_owned_fd(
        descriptor: OwnedFd,
        expected_local: SocketAddr,
        expected_remote: SocketAddr,
    ) -> io::Result<Self> {
        validate_concrete_address(expected_local)?;
        validate_concrete_address(expected_remote)?;
        let stream = std::net::TcpStream::from(descriptor);
        if stream.local_addr()? != expected_local || stream.peer_addr()? != expected_remote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTCP descriptor addresses do not match the helper response",
            ));
        }
        stream.set_nonblocking(true)?;
        let wrapped = Self(net::TcpStream::from_std(stream)?);
        wrapped.require_negotiated()?;
        Ok(wrapped)
    }

    /// Borrows the Tokio stream for split or copy operations.
    #[must_use]
    pub fn as_tcp_stream(&self) -> &net::TcpStream {
        &self.0
    }

    /// Mutably borrows the Tokio stream.
    pub fn as_tcp_stream_mut(&mut self) -> &mut net::TcpStream {
        &mut self.0
    }

    /// Returns the local transport address.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket error when its local address cannot be queried.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Returns the remote transport address.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket error when its peer address cannot be queried.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Reads kernel evidence for the negotiated MPTCP connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel rejects or cannot satisfy the `MPTCP_INFO` query.
    pub fn negotiation_info(&self) -> io::Result<volparossa_linux_uapi::MptcpInfo> {
        volparossa_linux_uapi::mptcp_info(&self.0)
    }

    /// Fails closed unless the kernel proves `MP_CAPABLE` negotiation without TCP fallback.
    ///
    /// # Errors
    ///
    /// Returns the `MPTCP_INFO` kernel error, or `ConnectionAborted` when the
    /// peer did not complete genuine MPTCP negotiation.
    pub fn require_negotiated(&self) -> io::Result<volparossa_linux_uapi::MptcpInfo> {
        let info = self.negotiation_info()?;
        if !info.is_negotiated() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "kernel did not negotiate MPTCP without fallback",
            ));
        }
        Ok(info)
    }

    /// Consumes the wrapper after callers have already enforced MPTCP negotiation evidence.
    #[must_use]
    pub fn into_inner(self) -> net::TcpStream {
        self.0
    }
}

/// Listener whose underlying Linux socket was explicitly created with `IPPROTO_MPTCP`.
#[derive(Debug)]
pub struct MptcpListener(net::TcpListener);

impl MptcpListener {
    /// Adopts one already-bound MPTCP listener received from a trusted namespace owner.
    ///
    /// The descriptor is consumed on both success and failure. The kernel-reported socket type,
    /// protocol, and listening state are checked before it is registered with Tokio. This lets a
    /// privileged route-namespace worker create the listener while the unprivileged service keeps
    /// its own network namespace unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is not a listening `IPPROTO_MPTCP` stream socket,
    /// cannot be made nonblocking, or cannot be registered with Tokio.
    pub fn from_bound_owned_fd(
        descriptor: OwnedFd,
        expected_local: SocketAddr,
    ) -> io::Result<Self> {
        validate_concrete_address(expected_local)?;
        Self::from_owned_fd_at(descriptor, expected_local, false)
    }

    /// Adopts an MPTCP listener bound to the wildcard address for an authorised concrete tuple.
    ///
    /// Linux requires a wildcard-bound listening meta-socket when `MP_JOIN` subflows target
    /// additional locally signalled addresses. The concrete address still authorises the address
    /// family and nonzero port; only the kernel-reported bind address is expected to be wildcard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the authority is concrete and the descriptor is an exact
    /// wildcard-bound, listening `IPPROTO_MPTCP` socket in the same family and on the same port.
    pub fn from_wildcard_owned_fd(
        descriptor: OwnedFd,
        authorised_local: SocketAddr,
    ) -> io::Result<Self> {
        validate_concrete_address(authorised_local)?;
        Self::from_owned_fd_at(descriptor, wildcard_address(authorised_local), true)
    }

    fn from_owned_fd_at(
        descriptor: OwnedFd,
        expected_local: SocketAddr,
        require_ipv6_only: bool,
    ) -> io::Result<Self> {
        let socket = Socket::from(descriptor);
        if socket.r#type()? != Type::STREAM
            || socket.protocol()? != Some(Protocol::MPTCP)
            || !socket.is_listener()?
            || (require_ipv6_only && expected_local.is_ipv6() && !socket.only_v6()?)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor is not a listening MPTCP stream socket",
            ));
        }
        if socket.local_addr()?.as_socket() != Some(expected_local) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTCP listener address does not match the helper response",
            ));
        }
        socket.set_nonblocking(true)?;
        let listener: std::net::TcpListener = socket.into();
        net::TcpListener::from_std(listener).map(Self)
    }

    /// Accepts a client on the MPTCP listener.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket error when accepting a connection fails, and rejects any
    /// accepted connection for which the kernel reports ordinary-TCP fallback.
    pub async fn accept(&self) -> io::Result<(MptcpStream, SocketAddr)> {
        let (stream, address) = self.0.accept().await?;
        let stream = MptcpStream(stream);
        stream.require_negotiated()?;
        Ok((stream, address))
    }

    /// Returns the bound listener address.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket error when its local address cannot be queried.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// Verifies that the running Linux kernel accepts `IPPROTO_MPTCP` sockets.
///
/// # Errors
///
/// Returns an error when the kernel cannot create an IPv6 MPTCP socket.
pub fn probe_kernel_support() -> io::Result<()> {
    create_socket(Domain::IPV6).map(drop)
}

/// Opens a nonblocking MPTCP stream, optionally binding a selected overlay address first.
///
/// # Errors
///
/// Returns an error for mismatched address families, socket setup or connection failures, and
/// connection timeouts.
pub async fn connect(
    remote: SocketAddr,
    local: Option<SocketAddr>,
    timeout: Duration,
) -> io::Result<MptcpStream> {
    let domain = domain_for(remote);
    if let Some(local) = local {
        if domain_for(local) != domain {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTCP local and remote address families differ",
            ));
        }
    }

    let socket = create_socket(domain)?;
    socket.set_nonblocking(true)?;
    if let Some(local) = local {
        socket.bind(&SockAddr::from(local))?;
    }

    match socket.connect(&SockAddr::from(remote)) {
        Ok(()) => {}
        Err(error)
            if matches!(error.raw_os_error(), Some(code)
                if code == libc::EINPROGRESS
                    || code == libc::EALREADY
                    || code == libc::EWOULDBLOCK) => {}
        Err(error) => return Err(error),
    }

    let stream = net::TcpStream::from_std(socket.into())?;
    time::timeout(timeout, stream.writable())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MPTCP connect timed out"))??;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(MptcpStream(stream))
}

/// Binds a real Linux MPTCP listener.
///
/// # Errors
///
/// Returns an error for a zero or oversized backlog, or when socket creation or binding fails.
pub fn listen(address: SocketAddr, backlog: u32) -> io::Result<MptcpListener> {
    if backlog == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MPTCP listener backlog cannot be zero",
        ));
    }
    let socket = create_socket(domain_for(address))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    let backlog = i32::try_from(backlog).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "MPTCP listener backlog exceeds i32",
        )
    })?;
    socket.listen(backlog)?;
    net::TcpListener::from_std(socket.into()).map(MptcpListener)
}

fn create_socket(domain: Domain) -> io::Result<Socket> {
    Socket::new(domain, Type::STREAM, Some(Protocol::MPTCP))
}

fn domain_for(address: SocketAddr) -> Domain {
    match address {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    }
}

fn wildcard_address(authorised_local: SocketAddr) -> SocketAddr {
    match authorised_local {
        SocketAddr::V4(address) => {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, address.port()))
        }
        SocketAddr::V6(address) => {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, address.port()))
        }
    }
}

fn validate_concrete_address(address: SocketAddr) -> io::Result<()> {
    if address.ip().is_unspecified() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper socket address must be concrete and use a nonzero port",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io, net::TcpListener, os::fd::OwnedFd, thread};

    use super::{MptcpListener, MptcpStream};

    #[test]
    fn wildcard_listener_address_preserves_only_family_and_port() {
        assert_eq!(
            super::wildcard_address("10.1.2.3:44443".parse().expect("IPv4 authority")),
            "0.0.0.0:44443".parse().expect("IPv4 wildcard")
        );
        assert_eq!(
            super::wildcard_address("[fd76::4]:44443".parse().expect("IPv6 authority")),
            "[::]:44443".parse().expect("IPv6 wildcard")
        );
    }

    #[tokio::test]
    async fn adopted_ordinary_tcp_descriptor_is_rejected_and_closed() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let address = listener.local_addr().expect("listener address");
        let connector = thread::spawn(move || std::net::TcpStream::connect(address));
        let (accepted, _) = listener.accept().expect("accept");
        connector.join().expect("connector task").expect("connect");

        let local = accepted.local_addr().expect("accepted local address");
        let remote = accepted.peer_addr().expect("accepted remote address");
        let descriptor = OwnedFd::from(accepted);
        let error = MptcpStream::from_connected_owned_fd(descriptor, local, remote)
            .expect_err("ordinary TCP must never be adopted as MPTCP");
        assert!(error.raw_os_error().is_some());
    }

    #[tokio::test]
    async fn adopted_ordinary_tcp_listener_is_rejected() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let local = listener.local_addr().expect("listener local address");
        let descriptor = OwnedFd::from(listener);
        let error = MptcpListener::from_bound_owned_fd(descriptor, local)
            .expect_err("ordinary TCP listener must never be adopted as MPTCP");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
