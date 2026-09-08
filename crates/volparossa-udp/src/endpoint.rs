//! Route-namespace UDP socket adoption for Quinn endpoints.

use std::{
    future::Future,
    net::SocketAddr,
    os::fd::OwnedFd,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use quinn::{
    AsyncTimer, AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, Runtime, ServerConfig,
    TokioRuntime,
};
use socket2::{Protocol, Socket, Type};
use tokio::sync::Notify;

use crate::UdpError;

#[derive(Debug, Default)]
struct EndpointTaskState {
    active: AtomicUsize,
    zero: Notify,
}

impl EndpointTaskState {
    async fn wait_for_zero(&self) {
        loop {
            let zero = self.zero.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            zero.await;
        }
    }
}

struct EndpointTaskGuard {
    state: Arc<EndpointTaskState>,
}

impl EndpointTaskGuard {
    fn new(state: Arc<EndpointTaskState>) -> Self {
        state
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_add(1)
            })
            .unwrap_or_else(|_| std::process::abort());
        Self { state }
    }
}

impl Drop for EndpointTaskGuard {
    fn drop(&mut self) {
        let previous = self.state.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        if previous == 1 {
            self.state.zero.notify_waiters();
        }
    }
}

#[derive(Debug)]
struct CountingTokioRuntime {
    inner: TokioRuntime,
    tasks: Arc<EndpointTaskState>,
}

impl Runtime for CountingTokioRuntime {
    fn new_timer(&self, value: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(value)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let guard = EndpointTaskGuard::new(Arc::clone(&self.tasks));
        self.inner.spawn(Box::pin(async move {
            let _guard = guard;
            future.await;
        }));
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn AsyncUdpSocket>> {
        self.inner.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

/// Affine Quinn endpoint which retains the exact adopted helper descriptor.
///
/// The underlying cloneable Quinn endpoint is never exposed. Consuming
/// [`shutdown`](Self::shutdown) closes every connection and waits until the
/// endpoint driver has released the socket, providing the barrier required
/// before its helper-owned route namespace may be destroyed.
#[must_use = "the managed endpoint must be retained or shut down"]
pub struct ManagedQuinnEndpoint {
    endpoint: Option<Endpoint>,
    tasks: Arc<EndpointTaskState>,
}

impl ManagedQuinnEndpoint {
    /// Return the exact kernel local tuple of the adopted endpoint.
    ///
    /// # Errors
    ///
    /// Returns an I/O error after shutdown.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint().map_err(std::io::Error::other)?.local_addr()
    }

    pub(crate) fn set_default_client_config(
        &mut self,
        configuration: ClientConfig,
    ) -> Result<(), UdpError> {
        self.endpoint_mut()?
            .set_default_client_config(configuration);
        Ok(())
    }

    pub(crate) async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, UdpError> {
        Ok(self.endpoint()?.connect(remote, server_name)?.await?)
    }

    pub(crate) async fn accept(&self) -> Result<quinn::Connection, UdpError> {
        let incoming = self
            .endpoint()?
            .accept()
            .await
            .ok_or(UdpError::InvalidBinding("closed QUIC endpoint"))?;
        Ok(incoming.await?)
    }

    /// Close all connections and wait until the endpoint driver releases the
    /// adopted socket.
    pub async fn shutdown(mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(quinn::VarInt::from_u32(0), b"route retired");
            endpoint.wait_idle().await;
            drop(endpoint);
        }
        self.tasks.wait_for_zero().await;
    }

    fn endpoint(&self) -> Result<&Endpoint, UdpError> {
        self.endpoint
            .as_ref()
            .ok_or(UdpError::InvalidBinding("closed QUIC endpoint"))
    }

    fn endpoint_mut(&mut self) -> Result<&mut Endpoint, UdpError> {
        self.endpoint
            .as_mut()
            .ok_or(UdpError::InvalidBinding("closed QUIC endpoint"))
    }

    #[cfg(test)]
    fn active_tasks(&self) -> usize {
        self.tasks.active.load(Ordering::Acquire)
    }
}

impl Drop for ManagedQuinnEndpoint {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(quinn::VarInt::from_u32(0), b"route owner dropped");
            drop(endpoint);
        }
    }
}

/// Adopts one helper-bound route-namespace UDP socket as a Quinn endpoint.
///
/// The descriptor is consumed on success and failure. Its kernel-reported type, protocol, and
/// bound address must exactly match the typed helper response supplied as `expected_local`.
/// Consequently Quinn cannot silently create a replacement socket in the agent's own network
/// namespace. Passing `None` creates an outgoing-only endpoint; a server configuration permits
/// incoming connections on the same already-bound socket.
///
/// # Errors
///
/// Returns an error outside a Tokio runtime, for an unspecified or zero-port expected address,
/// when the descriptor is not an unconnected UDP datagram socket bound to that exact address, or
/// when Quinn cannot adopt it.
pub fn endpoint_from_bound_owned_fd(
    descriptor: OwnedFd,
    expected_local: SocketAddr,
    server_config: Option<ServerConfig>,
) -> Result<ManagedQuinnEndpoint, UdpError> {
    tokio::runtime::Handle::try_current().map_err(|_| UdpError::RuntimeUnavailable)?;
    if expected_local.ip().is_unspecified() || expected_local.port() == 0 {
        return Err(UdpError::InvalidBinding("QUIC local socket address"));
    }

    let socket = Socket::from(descriptor);
    if socket.r#type()? != Type::DGRAM || socket.protocol()? != Some(Protocol::UDP) {
        return Err(UdpError::InvalidBinding("QUIC UDP socket protocol"));
    }
    if socket.local_addr()?.as_socket() != Some(expected_local) {
        return Err(UdpError::InvalidBinding("QUIC local socket address"));
    }
    match socket.peer_addr() {
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
        Ok(_) => return Err(UdpError::InvalidBinding("QUIC UDP socket connection state")),
        Err(error) => return Err(UdpError::Io(error)),
    }
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    let tasks = Arc::new(EndpointTaskState::default());
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(CountingTokioRuntime {
            inner: TokioRuntime,
            tasks: Arc::clone(&tasks),
        }),
    )
    .map_err(UdpError::Io)?;
    Ok(ManagedQuinnEndpoint {
        endpoint: Some(endpoint),
        tasks,
    })
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, os::fd::OwnedFd};

    use super::*;

    #[tokio::test]
    async fn adopts_exact_bound_udp_descriptor() {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
        let expected = socket.local_addr().expect("local address");
        let endpoint = endpoint_from_bound_owned_fd(OwnedFd::from(socket), expected, None)
            .expect("adopt exact UDP descriptor");
        assert_eq!(endpoint.local_addr().expect("endpoint address"), expected);
        assert_eq!(endpoint.active_tasks(), 1);
        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_wrong_address_and_non_udp_descriptor() {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
        let mut wrong = socket.local_addr().expect("local address");
        wrong.set_port(wrong.port().checked_add(1).unwrap_or(1));
        assert!(matches!(
            endpoint_from_bound_owned_fd(OwnedFd::from(socket), wrong, None),
            Err(UdpError::InvalidBinding("QUIC local socket address"))
        ));

        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind TCP");
        let expected = listener.local_addr().expect("TCP address");
        assert!(matches!(
            endpoint_from_bound_owned_fd(OwnedFd::from(listener), expected, None),
            Err(UdpError::InvalidBinding("QUIC UDP socket protocol"))
        ));
    }

    #[tokio::test]
    async fn rejects_zero_port_and_unspecified_expected_addresses() {
        for expected in [
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 9)),
        ] {
            let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
            assert!(matches!(
                endpoint_from_bound_owned_fd(OwnedFd::from(socket), expected, None),
                Err(UdpError::InvalidBinding("QUIC local socket address"))
            ));
        }
    }

    #[tokio::test]
    async fn rejects_a_preconnected_udp_descriptor() {
        let peer = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind peer");
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
        socket
            .connect(peer.local_addr().expect("peer address"))
            .expect("connect UDP");
        let expected = socket.local_addr().expect("local address");
        assert!(matches!(
            endpoint_from_bound_owned_fd(OwnedFd::from(socket), expected, None),
            Err(UdpError::InvalidBinding("QUIC UDP socket connection state"))
        ));
    }
}
