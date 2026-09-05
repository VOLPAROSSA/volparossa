//! Runtime owners for one helper-committed single-relay UDP transport.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::OwnedFd,
    time::Duration,
};

use bytes::Bytes;
use quinn::{ClientConfig, ServerConfig};
use tokio::sync::watch;
use volparossa_linux_uapi::IndependentEgress;
use volparossa_policy::VerifiedManifest;
use volparossa_protocol::{ReplayCache, TimePolicy};
use volparossa_routing::{
    AcquireTransportSocket, TransportSocketAddress, TransportSocketKind, TransportSocketReady,
    WireguardRole,
};
use volparossa_wireguard::{HelperContextHandle, overlay_addresses};

use crate::{
    AuthorizedUdpFlow, DatagramLimits, ExitUdpBridge, ManagedQuinnEndpoint, QuicUdpAssociation,
    UdpAuthorizationScope, UdpBridgeStats, UdpError, VerifiedSingleRelayPath, dns::ExitDnsBridge,
    endpoint_from_bound_owned_fd, read_authorized_udp_flow, write_udp_authorization,
};

/// Endpoint role permitted for a committed single-path UDP descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedUdpRole {
    /// Client socket inside the Client endpoint of the selected path.
    Client,
    /// Exit socket inside the Exit endpoint of the selected path.
    Exit,
}

impl CommittedUdpRole {
    const fn wire_role(self) -> WireguardRole {
        match self {
            Self::Client => WireguardRole::Client,
            Self::Exit => WireguardRole::Exit,
        }
    }
}

/// Build the exact helper request for a Client or Exit QUIC socket in a committed route.
///
/// The local address is derived from the verified single-Relay path. The returned request is
/// always explicitly unconnected; callers cannot supply an underlay address or direct Exit peer.
///
/// # Errors
///
/// Rejects an invalid helper handle, zero port, or route/path that cannot derive its canonical
/// overlay endpoint.
pub fn committed_quic_udp_socket_request(
    context_handle: &[u8],
    path: &VerifiedSingleRelayPath,
    role: CommittedUdpRole,
    local_port: u16,
) -> Result<AcquireTransportSocket, UdpError> {
    if local_port == 0 {
        return Err(UdpError::InvalidBinding("helper UDP local port"));
    }
    let handle = HelperContextHandle::try_from(context_handle)
        .map_err(|_| UdpError::InvalidBinding("helper route context handle"))?;
    let path_id = u8::try_from(path.path_id())
        .map_err(|_| UdpError::InvalidBinding("single-relay path id"))?;
    let addresses = overlay_addresses(*path.route_context_id(), path_id)
        .map_err(|_| UdpError::InvalidBinding("single-relay overlay"))?;
    let address = match role {
        CommittedUdpRole::Client => addresses.client,
        CommittedUdpRole::Exit => addresses.exit,
    };
    Ok(AcquireTransportSocket {
        route_context_id: path.route_context_id().to_vec(),
        context_handle: handle.as_bytes().to_vec(),
        path_id: path.path_id(),
        role: role.wire_role() as i32,
        descriptor_kind: TransportSocketKind::QuicUdpUnconnected as i32,
        expected_local: Some(TransportSocketAddress {
            address: address.octets().to_vec(),
            port: u32::from(local_port),
        }),
        expected_remote: None,
    })
}

/// Affine helper-returned QUIC UDP descriptor bound to one verified route path.
///
/// Construction consumes the `SCM_RIGHTS` capability and checks its complete
/// typed helper metadata. The local address must be the canonical Client or
/// Exit overlay address for the verified path; Relay roles, underlay binds,
/// connected UDP sockets and other descriptor kinds are rejected.
#[must_use = "a committed transport descriptor is an affine route capability"]
pub struct CommittedQuicUdpTransport {
    descriptor: OwnedFd,
    local: SocketAddr,
    role: CommittedUdpRole,
    route_context_id: [u8; 16],
    path_id: u32,
}

impl CommittedQuicUdpTransport {
    /// Bind one received descriptor and its correlated helper metadata to a
    /// verified single-relay path.
    ///
    /// # Errors
    ///
    /// Fails closed for a different path, role, kind, remote tuple, malformed
    /// address, or non-canonical overlay bind.
    pub fn from_helper_handoff(
        descriptor: OwnedFd,
        metadata: &TransportSocketReady,
        path: &VerifiedSingleRelayPath,
        role: CommittedUdpRole,
    ) -> Result<Self, UdpError> {
        if metadata.path_id != path.path_id() {
            return Err(UdpError::InvalidBinding("helper transport path"));
        }
        if WireguardRole::try_from(metadata.role).ok() != Some(role.wire_role()) {
            return Err(UdpError::InvalidBinding("helper transport role"));
        }
        if TransportSocketKind::try_from(metadata.descriptor_kind).ok()
            != Some(TransportSocketKind::QuicUdpUnconnected)
        {
            return Err(UdpError::InvalidBinding("helper transport kind"));
        }
        if metadata.remote.is_some() {
            return Err(UdpError::InvalidBinding("helper UDP remote address"));
        }
        let local = transport_address(
            metadata
                .local
                .as_ref()
                .ok_or(UdpError::InvalidBinding("helper UDP local address"))?,
        )?;
        let path_id = u8::try_from(path.path_id())
            .map_err(|_| UdpError::InvalidBinding("single-relay path id"))?;
        let addresses = overlay_addresses(*path.route_context_id(), path_id)
            .map_err(|_| UdpError::InvalidBinding("single-relay overlay"))?;
        let expected_ip = match role {
            CommittedUdpRole::Client => IpAddr::V6(addresses.client),
            CommittedUdpRole::Exit => IpAddr::V6(addresses.exit),
        };
        if local.ip() != expected_ip {
            return Err(UdpError::InvalidBinding("helper UDP overlay address"));
        }
        Ok(Self {
            descriptor,
            local,
            role,
            route_context_id: *path.route_context_id(),
            path_id: path.path_id(),
        })
    }

    /// Return the exact helper- and kernel-validated local socket tuple.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn adopt(
        self,
        required_role: CommittedUdpRole,
        path: &VerifiedSingleRelayPath,
        server_config: Option<ServerConfig>,
    ) -> Result<ManagedQuinnEndpoint, UdpError> {
        if self.role != required_role {
            return Err(UdpError::InvalidBinding("committed UDP endpoint role"));
        }
        if self.route_context_id != *path.route_context_id() || self.path_id != path.path_id() {
            return Err(UdpError::InvalidBinding("committed UDP endpoint path"));
        }
        endpoint_from_bound_owned_fd(self.descriptor, self.local, server_config)
    }

    #[cfg(test)]
    fn from_test_socket(
        descriptor: OwnedFd,
        local: SocketAddr,
        role: CommittedUdpRole,
        path: &VerifiedSingleRelayPath,
    ) -> Self {
        Self {
            descriptor,
            local,
            role,
            route_context_id: *path.route_context_id(),
            path_id: path.path_id(),
        }
    }
}

/// Canonical Exit overlay destination for one verified single-relay path.
///
/// The address is derived rather than supplied, so this value cannot name an
/// Exit underlay socket or encode a direct Client-to-Exit bypass. Its port is
/// the non-zero port returned for the committed Exit QUIC descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedExitUdpTarget {
    address: SocketAddr,
    route_context_id: [u8; 16],
    path_id: u32,
}

impl ProtectedExitUdpTarget {
    /// Derive the only permitted peer address for this route path.
    ///
    /// # Errors
    ///
    /// Rejects port zero or an invalid route path identifier.
    pub fn new(path: &VerifiedSingleRelayPath, committed_exit_port: u16) -> Result<Self, UdpError> {
        if committed_exit_port == 0 {
            return Err(UdpError::InvalidBinding("committed Exit QUIC port"));
        }
        let path_id = u8::try_from(path.path_id())
            .map_err(|_| UdpError::InvalidBinding("single-relay path id"))?;
        let exit = overlay_addresses(*path.route_context_id(), path_id)
            .map_err(|_| UdpError::InvalidBinding("single-relay overlay"))?
            .exit;
        Ok(Self {
            address: SocketAddr::new(IpAddr::V6(exit), committed_exit_port),
            route_context_id: *path.route_context_id(),
            path_id: path.path_id(),
        })
    }

    /// Return the canonical protected Exit overlay tuple.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.address
    }

    #[cfg(test)]
    const fn for_test(address: SocketAddr, path: &VerifiedSingleRelayPath) -> Self {
        Self {
            address,
            route_context_id: *path.route_context_id(),
            path_id: path.path_id(),
        }
    }

    fn ensure_path(self, path: &VerifiedSingleRelayPath) -> Result<(), UdpError> {
        if self.route_context_id != *path.route_context_id() || self.path_id != path.path_id() {
            return Err(UdpError::InvalidBinding("protected Exit UDP path"));
        }
        Ok(())
    }
}

/// Active Client owner for one dedicated, authorized UDP-over-QUIC flow.
#[must_use = "the active UDP flow must remain owned until shutdown"]
pub struct SingleRelayUdpClient {
    endpoint: ManagedQuinnEndpoint,
    association: QuicUdpAssociation,
}

impl SingleRelayUdpClient {
    /// Adopt a committed Client descriptor, connect to the canonical protected
    /// Exit overlay tuple, send the signed flow authorization on the dedicated
    /// control stream and start one QUIC DATAGRAM association.
    ///
    /// `flow` is the Client's locally verified view of the same signed bytes;
    /// the Exit independently verifies `signed_authorization` before egress.
    ///
    /// # Errors
    ///
    /// Fails for descriptor/path mismatch, QUIC/TLS failure, authorization
    /// framing failure, expiry, or missing DATAGRAM negotiation. On failure the
    /// adopted endpoint is shut down before returning.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        transport: CommittedQuicUdpTransport,
        target: ProtectedExitUdpTarget,
        client_config: ClientConfig,
        server_name: &str,
        path: VerifiedSingleRelayPath,
        flow: &AuthorizedUdpFlow,
        signed_authorization: &[u8],
        authorization_timeout: Duration,
        now_ms: u64,
    ) -> Result<Self, UdpError> {
        target.ensure_path(&path)?;
        let mut endpoint = transport.adopt(CommittedUdpRole::Client, &path, None)?;
        endpoint.set_default_client_config(client_config)?;
        let attempt = async {
            let connection = endpoint.connect(target.socket_addr(), server_name).await?;
            if connection.remote_address() != target.socket_addr() {
                return Err(UdpError::InvalidBinding("protected Exit QUIC peer"));
            }
            let mut authorization = connection.open_uni().await?;
            write_udp_authorization(
                &mut authorization,
                signed_authorization,
                authorization_timeout,
            )
            .await?;
            authorization
                .finish()
                .map_err(|_| UdpError::InvalidBinding("UDP authorization stream finish"))?;
            QuicUdpAssociation::new(connection, path, flow, now_ms)
        }
        .await;
        match attempt {
            Ok(association) => Ok(Self {
                endpoint,
                association,
            }),
            Err(error) => {
                endpoint.shutdown().await;
                Err(error)
            }
        }
    }

    /// Send one original UDP datagram without a stream fallback.
    ///
    /// # Errors
    ///
    /// Returns an association or negotiated-size error.
    pub fn send_payload(&self, payload: &[u8]) -> Result<(), UdpError> {
        self.association.send_payload(payload)
    }

    /// Receive one complete UDP response datagram.
    ///
    /// # Errors
    ///
    /// Returns an association, framing, closure, or expiry error.
    pub async fn receive_payload(&self) -> Result<Bytes, UdpError> {
        self.association.receive_payload().await
    }

    /// Close the QUIC flow and wait until Quinn releases the committed socket.
    pub async fn shutdown(self) {
        let Self {
            endpoint,
            association,
        } = self;
        association.close();
        drop(association);
        endpoint.shutdown().await;
    }
}

/// Exit owner for one authorized and destination-pinned UDP bridge.
#[must_use = "the accepted UDP bridge must be run or dropped before route destruction"]
pub struct SingleRelayUdpExit {
    endpoint: ManagedQuinnEndpoint,
    bridge: SingleRelayExitBridge,
}

enum SingleRelayExitBridge {
    Datagram(ExitUdpBridge),
    Dns(ExitDnsBridge),
}

/// Bound QUIC listener for one committed Exit route.
///
/// Construction adopts the helper descriptor synchronously. Returning this owner therefore proves
/// that the exact protected-overlay socket is listening before public certificate readiness is
/// signalled to the Client; flow authorization and destination egress still happen only in
/// [`accept`](Self::accept).
#[must_use = "the committed Exit listener must be accepted or shut down"]
pub struct SingleRelayUdpExitListener {
    endpoint: ManagedQuinnEndpoint,
    path: VerifiedSingleRelayPath,
}

impl SingleRelayUdpExitListener {
    /// Adopt the committed Exit descriptor and start its bounded QUIC listener.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor, role, path, address, or TLS configuration mismatch.
    pub fn listen(
        transport: CommittedQuicUdpTransport,
        server_config: ServerConfig,
        path: VerifiedSingleRelayPath,
    ) -> Result<Self, UdpError> {
        let endpoint = transport.adopt(CommittedUdpRole::Exit, &path, Some(server_config))?;
        Ok(Self { endpoint, path })
    }

    /// Accept and authorize exactly one Client flow on this committed listener.
    ///
    /// # Errors
    ///
    /// Fails for any peer, reservation, authorization, policy, replay, expiry, DNS, QUIC, or
    /// destination-socket error. The endpoint is shut down before an error is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept(
        self,
        policy: &VerifiedManifest,
        replay_cache: &mut ReplayCache,
        time_policy: TimePolicy,
        authorization_timeout: Duration,
        limits: DatagramLimits,
        now_ms: u64,
    ) -> Result<SingleRelayUdpExit, UdpError> {
        let (_keep_alive, mut shutdown) = watch::channel(false);
        self.accept_with_egress_until_shutdown(
            policy,
            replay_cache,
            time_policy,
            authorization_timeout,
            limits,
            now_ms,
            None,
            &mut shutdown,
        )
        .await
    }

    /// Accept using the selected destination uplink and an explicit contribution lifetime.
    ///
    /// # Errors
    ///
    /// Authorization and binding failures remain closed. A true or closed shutdown channel
    /// cancels acceptance and fully shuts down the owned endpoint before returning.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_with_egress_until_shutdown(
        self,
        policy: &VerifiedManifest,
        replay_cache: &mut ReplayCache,
        time_policy: TimePolicy,
        authorization_timeout: Duration,
        limits: DatagramLimits,
        now_ms: u64,
        independent_egress: Option<&IndependentEgress>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<SingleRelayUdpExit, UdpError> {
        let Self { endpoint, path } = self;
        let attempt = async {
            let connection = endpoint.accept().await?;
            let path_id = u8::try_from(path.path_id())
                .map_err(|_| UdpError::InvalidBinding("single-relay path id"))?;
            let expected_client = overlay_addresses(*path.route_context_id(), path_id)
                .map_err(|_| UdpError::InvalidBinding("single-relay overlay"))?
                .client;
            if connection.remote_address().ip() != IpAddr::V6(expected_client) {
                return Err(UdpError::InvalidBinding("protected Client QUIC peer"));
            }
            let mut authorization = connection.accept_uni().await?;
            let scope = UdpAuthorizationScope::new(&path, policy);
            let flow = read_authorized_udp_flow(
                &mut authorization,
                &scope,
                now_ms,
                time_policy,
                replay_cache,
                authorization_timeout,
            )
            .await?;
            let association = QuicUdpAssociation::new(connection, path, &flow, now_ms)?;
            if flow.dns_name().is_some() {
                ExitDnsBridge::new(association, &flow, now_ms, limits)
                    .map(SingleRelayExitBridge::Dns)
            } else {
                let pinned = flow.resolve_and_pin(now_ms).await?;
                ExitUdpBridge::connect_with_egress(
                    association,
                    pinned,
                    now_ms,
                    limits,
                    independent_egress,
                )
                .await
                .map(SingleRelayExitBridge::Datagram)
            }
        };
        let attempt = tokio::select! {
            biased;
            () = wait_for_exit_shutdown(shutdown) => {
                Err(UdpError::InvalidBinding("Exit contribution unavailable"))
            }
            result = attempt => result,
        };
        match attempt {
            Ok(bridge) => Ok(SingleRelayUdpExit { endpoint, bridge }),
            Err(error) => {
                endpoint.shutdown().await;
                Err(error)
            }
        }
    }

    /// Close the listener and wait until Quinn releases the committed socket.
    pub async fn shutdown(self) {
        self.endpoint.shutdown().await;
    }
}

impl SingleRelayUdpExit {
    /// Adopt a committed Exit descriptor and accept exactly one QUIC flow from
    /// the canonical Client overlay address of the verified relay path.
    ///
    /// The first unidirectional stream must carry one signed authorization.
    /// The Exit verifies it against the current whitelist, resolves and pins
    /// the destination once, and only then creates the egress bridge.
    ///
    /// # Errors
    ///
    /// Fails for any descriptor, peer, reservation, authorization, policy,
    /// replay, expiry, DNS, QUIC, or destination-socket error. The endpoint is
    /// shut down before an error is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept(
        transport: CommittedQuicUdpTransport,
        server_config: ServerConfig,
        path: VerifiedSingleRelayPath,
        policy: &VerifiedManifest,
        replay_cache: &mut ReplayCache,
        time_policy: TimePolicy,
        authorization_timeout: Duration,
        limits: DatagramLimits,
        now_ms: u64,
    ) -> Result<Self, UdpError> {
        SingleRelayUdpExitListener::listen(transport, server_config, path)?
            .accept(
                policy,
                replay_cache,
                time_policy,
                authorization_timeout,
                limits,
                now_ms,
            )
            .await
    }

    /// Run both datagram pumps until closure, expiry, or the configured bounded
    /// datagram counts have been reached, then release the committed socket.
    ///
    /// # Errors
    ///
    /// Returns the first association, socket, size, or resource-limit error.
    pub async fn run(self) -> Result<UdpBridgeStats, UdpError> {
        let (_keep_alive, mut shutdown) = watch::channel(false);
        self.run_until_shutdown(&mut shutdown).await
    }

    /// Run until the flow ends or contribution is withdrawn, then release the endpoint.
    ///
    /// # Errors
    ///
    /// Returns forwarding errors or an explicit contribution-withdrawal error. Cancellation
    /// waits for endpoint shutdown rather than dropping its asynchronous socket owner.
    pub async fn run_until_shutdown(
        self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<UdpBridgeStats, UdpError> {
        let Self { endpoint, bridge } = self;
        let forwarding = async {
            match bridge {
                SingleRelayExitBridge::Datagram(bridge) => bridge.run().await,
                SingleRelayExitBridge::Dns(bridge) => bridge.run().await,
            }
        };
        let result = tokio::select! {
            biased;
            () = wait_for_exit_shutdown(shutdown) => {
                Err(UdpError::InvalidBinding("Exit contribution unavailable"))
            }
            result = forwarding => result,
        };
        endpoint.shutdown().await;
        result
    }
}

async fn wait_for_exit_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        let stopping = *shutdown.borrow_and_update();
        if stopping || shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn transport_address(address: &TransportSocketAddress) -> Result<SocketAddr, UdpError> {
    let ip = match address.address.as_slice() {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| UdpError::InvalidBinding("helper UDP local address"))?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(UdpError::InvalidBinding("helper UDP local address")),
    };
    let port = u16::try_from(address.port)
        .map_err(|_| UdpError::InvalidBinding("helper UDP local port"))?;
    if ip.is_unspecified() || port == 0 {
        return Err(UdpError::InvalidBinding("helper UDP local address"));
    }
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, UdpSocket as StdUdpSocket},
        os::fd::OwnedFd,
        sync::Arc,
        time::Duration,
    };

    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use tokio::net::UdpSocket;
    use volparossa_routing::{TransportSocketAddress, WireguardRole};
    use volparossa_wireguard::overlay_addresses;

    use super::{
        CommittedQuicUdpTransport, CommittedUdpRole, ProtectedExitUdpTarget,
        committed_quic_udp_socket_request,
    };
    use crate::{
        AuthorizedUdpFlow, DatagramLimits, ExitUdpBridge, QuicUdpAssociation,
        VerifiedSingleRelayPath,
    };

    #[test]
    fn helper_requests_derive_client_and_exit_sockets_from_one_verified_path() {
        let path = VerifiedSingleRelayPath::test_path(1_700_000_005_000);
        let client =
            committed_quic_udp_socket_request(&[9; 32], &path, CommittedUdpRole::Client, 40_001)
                .expect("Client helper request");
        let exit = committed_quic_udp_socket_request(
            &[9; 32],
            &path,
            CommittedUdpRole::Exit,
            crate::SINGLE_RELAY_UDP_EXIT_PORT,
        )
        .expect("Exit helper request");
        let addresses = overlay_addresses(*path.route_context_id(), 1).expect("overlay");

        assert_eq!(client.route_context_id, path.route_context_id());
        assert_eq!(client.path_id, path.path_id());
        assert_eq!(client.role, WireguardRole::Client as i32);
        assert_eq!(
            client.expected_local,
            Some(TransportSocketAddress {
                address: addresses.client.octets().to_vec(),
                port: 40_001,
            })
        );
        assert!(client.expected_remote.is_none());
        assert_eq!(exit.route_context_id, client.route_context_id);
        assert_eq!(exit.context_handle, client.context_handle);
        assert_eq!(exit.path_id, client.path_id);
        assert_eq!(exit.role, WireguardRole::Exit as i32);
        assert_eq!(
            exit.expected_local,
            Some(TransportSocketAddress {
                address: addresses.exit.octets().to_vec(),
                port: u32::from(crate::SINGLE_RELAY_UDP_EXIT_PORT),
            })
        );
        assert!(exit.expected_remote.is_none());
    }

    #[tokio::test]
    async fn adopted_client_and_exit_descriptors_carry_one_udp_echo() {
        real_udp_echo_retirement(false).await;
    }

    #[tokio::test]
    async fn uplink_withdrawal_retires_a_live_udp_echo_and_releases_its_exact_listener() {
        real_udp_echo_retirement(true).await;
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one real QUIC echo compares normal and withdrawn endpoint lifetimes"
    )]
    async fn real_udp_echo_retirement(withdraw_uplink: bool) {
        let _installation = rustls::crypto::ring::default_provider().install_default();
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())
                .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();

        let client_socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_local = client_socket.local_addr().unwrap();
        let exit_socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let exit_local = exit_socket.local_addr().unwrap();
        let test_path = VerifiedSingleRelayPath::test_path(1_700_000_005_000);
        let client_transport = CommittedQuicUdpTransport::from_test_socket(
            OwnedFd::from(client_socket),
            client_local,
            CommittedUdpRole::Client,
            &test_path,
        );
        let exit_transport = CommittedQuicUdpTransport::from_test_socket(
            OwnedFd::from(exit_socket),
            exit_local,
            CommittedUdpRole::Exit,
            &test_path,
        );
        let mut client_endpoint = client_transport
            .adopt(CommittedUdpRole::Client, &test_path, None)
            .unwrap();
        client_endpoint
            .set_default_client_config(client_config)
            .unwrap();
        let exit_endpoint = exit_transport
            .adopt(CommittedUdpRole::Exit, &test_path, Some(server_config))
            .unwrap();
        let target = ProtectedExitUdpTarget::for_test(exit_local, &test_path);
        let (client_connection, exit_connection) = tokio::join!(
            client_endpoint.connect(target.socket_addr(), "localhost"),
            exit_endpoint.accept(),
        );
        let client_connection = client_connection.unwrap();
        let exit_connection = exit_connection.unwrap();

        let destination = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (length, peer) = destination.recv_from(&mut payload).await.unwrap();
            destination.send_to(&payload[..length], peer).await.unwrap();
        });

        let now_ms = 1_700_000_000_000;
        let flow = AuthorizedUdpFlow::test_flow_to(
            destination_address,
            Duration::from_secs(2),
            now_ms + 5_000,
        );
        let client_association = QuicUdpAssociation::new(
            client_connection,
            VerifiedSingleRelayPath::test_path(now_ms + 5_000),
            &flow,
            now_ms,
        )
        .unwrap();
        let exit_association = QuicUdpAssociation::new(
            exit_connection,
            VerifiedSingleRelayPath::test_path(now_ms + 5_000),
            &flow,
            now_ms,
        )
        .unwrap();
        let pinned = crate::PinnedUdpFlow::test_pin(&flow, destination_address);
        let bridge = ExitUdpBridge::connect(
            exit_association,
            pinned,
            now_ms,
            DatagramLimits::new(
                1_200,
                if withdraw_uplink { 1_000 } else { 1 },
                if withdraw_uplink { 1_000 } else { 1 },
            )
            .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            bridge.destination_socket_priority().unwrap(),
            volparossa_core::CONTRIBUTION_SOCKET_PRIORITY,
        );
        client_association
            .send_payload(b"single-relay-udp-echo")
            .unwrap();
        let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let active = super::SingleRelayUdpExit {
            endpoint: exit_endpoint,
            bridge: super::SingleRelayExitBridge::Datagram(bridge),
        };
        let bridge_task =
            tokio::spawn(async move { active.run_until_shutdown(&mut shutdown_rx).await });
        let received = client_association.receive_payload().await.unwrap();
        assert_eq!(received, b"single-relay-udp-echo"[..]);
        if withdraw_uplink {
            assert!(
                !bridge_task.is_finished(),
                "real flow is still active before withdrawal"
            );
            shutdown.send(true).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), bridge_task)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                result,
                Err(crate::UdpError::InvalidBinding(
                    "Exit contribution unavailable"
                ))
            ));
        } else {
            client_association.close();
            let statistics = bridge_task.await.unwrap().unwrap();
            assert_eq!(statistics.tunnel_to_destination_datagrams, 1);
            assert_eq!(statistics.destination_to_tunnel_datagrams, 1);
        }

        echo.await.unwrap();
        drop(client_association);
        client_endpoint.shutdown().await;
        let reclaimed = StdUdpSocket::bind(exit_local).expect("exact Exit listener released");
        drop(reclaimed);
    }

    #[test]
    fn helper_transport_metadata_cannot_bind_an_underlay_address() {
        let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = socket.local_addr().unwrap();
        let metadata = volparossa_routing::TransportSocketReady {
            path_id: 1,
            role: WireguardRole::Client as i32,
            descriptor_kind: volparossa_routing::TransportSocketKind::QuicUdpUnconnected as i32,
            local: Some(TransportSocketAddress {
                address: match local.ip() {
                    IpAddr::V4(address) => address.octets().to_vec(),
                    IpAddr::V6(address) => address.octets().to_vec(),
                },
                port: u32::from(local.port()),
            }),
            remote: None,
        };
        let result = CommittedQuicUdpTransport::from_helper_handoff(
            OwnedFd::from(socket),
            &metadata,
            &VerifiedSingleRelayPath::test_path(1_700_000_005_000),
            CommittedUdpRole::Client,
        );
        assert!(matches!(
            result,
            Err(crate::UdpError::InvalidBinding(
                "helper UDP overlay address"
            ))
        ));
    }
}
