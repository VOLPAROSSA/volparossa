//! Route-namespace UDP socket adoption for Quinn endpoints.

use std::{net::SocketAddr, os::fd::OwnedFd, sync::Arc};

use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use socket2::{Protocol, Socket, Type};

use crate::UdpError;

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
) -> Result<Endpoint, UdpError> {
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
    Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(UdpError::Io)
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
