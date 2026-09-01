//! Callable ownership seam for the native multipath QUIC client process.

use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::OwnedFd,
    time::Duration,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::{Instant, sleep_until};
use volparossa_quic::{
    AddPath, NativeClient, NativeClientError, NativeProcessRole, NativeResultCode, ReceiveDatagram,
    ReceivedDatagram, SendDatagram, StartSession, StopSession, TransportMode, TunnelAssignment,
    VerifiedExitMpquicEndpoint,
};
use volparossa_reservation::{ClientNativeRouteAuthorization, VerifiedRelayGrant};
use volparossa_routing::{TransportSocketAddress, TransportSocketKind, WireguardRole};
use volparossa_wireguard::overlay_addresses;

use crate::helper::AcquiredTransportSocket;

const MINIMUM_MULTIPATH_PATHS: usize = 2;
const MINIMUM_MULTIPATH_PATHS_U32: u32 = 2;
const MAXIMUM_MULTIPATH_PATHS: usize = 8;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAXIMUM_READY_WAIT: Duration = Duration::from_secs(10);

/// One affine helper-returned Client UDP path plus its independently verified Relay grant.
///
/// The descriptor is consumed by the native process on every `AddPath` result.
#[must_use = "a committed MPQUIC path descriptor is affine"]
pub struct CommittedMpquicPath {
    descriptor: OwnedFd,
    add: AddPath,
    reservation_id: [u8; 16],
    relay_node_id: [u8; 32],
    exit_native_instance_id: [u8; 32],
    expires_at_ms: u64,
    listener_set_ready: bool,
}

impl CommittedMpquicPath {
    /// Bind a helper-correlated committed descriptor to one verified Relay grant and Exit port.
    ///
    /// # Errors
    ///
    /// Returns an error when descriptor metadata, overlay addressing, or the Exit port does not
    /// match the verified path.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the affine endpoint authority is deliberately consumed by the committed path"
    )]
    pub fn from_helper_handoff(
        acquired: AcquiredTransportSocket,
        grant: &VerifiedRelayGrant,
        exit_endpoint: VerifiedExitMpquicEndpoint,
    ) -> Result<Self, ProductionMpquicError> {
        let (descriptor, metadata) = acquired.into_parts();
        if metadata.path_id != grant.path_id()
            || WireguardRole::try_from(metadata.role).ok() != Some(WireguardRole::Client)
            || TransportSocketKind::try_from(metadata.descriptor_kind).ok()
                != Some(TransportSocketKind::QuicUdpUnconnected)
            || metadata.remote.is_some()
        {
            return Err(ProductionMpquicError::Invalid(
                "committed MPQUIC descriptor metadata",
            ));
        }
        let local = transport_address(metadata.local.as_ref().ok_or(
            ProductionMpquicError::Invalid("committed MPQUIC local address"),
        )?)?;
        let path_id = u8::try_from(grant.path_id())
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC path id"))?;
        let addresses = overlay_addresses(*grant.route_context_id(), path_id)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC overlay"))?;
        let reservation_hash: [u8; 32] = Sha256::digest(grant.signed_relay_reservation()).into();
        if local.ip() != IpAddr::V6(addresses.client)
            || exit_endpoint.route_context_id() != grant.route_context_id()
            || exit_endpoint.path_id() != grant.path_id()
            || exit_endpoint.listener_ip() != &addresses.exit.octets()
            || exit_endpoint.expected_client_ip() != &addresses.client.octets()
            || exit_endpoint.expected_client_port() != local.port()
            || exit_endpoint.reservation_hash() != &reservation_hash
            || exit_endpoint.minimum_paths() < MINIMUM_MULTIPATH_PATHS_U32
        {
            return Err(ProductionMpquicError::Invalid(
                "committed MPQUIC Client/Exit endpoint",
            ));
        }
        Ok(Self {
            descriptor,
            add: AddPath {
                route_context_id: grant.route_context_id().to_vec(),
                path_id: grant.path_id(),
                local_ip: addresses.client.octets().to_vec(),
                remote_ip: addresses.exit.octets().to_vec(),
                remote_port: u32::from(exit_endpoint.listener_port()),
                reservation_hash: reservation_hash.to_vec(),
                local_port: u32::from(local.port()),
            },
            reservation_id: *grant.reservation_id(),
            relay_node_id: *grant.relay_node_id(),
            exit_native_instance_id: *exit_endpoint.exit_native_instance_id(),
            expires_at_ms: grant.expires_at_ms(),
            listener_set_ready: exit_endpoint.listener_set_ready(),
        })
    }

    #[cfg(test)]
    fn for_test(
        descriptor: OwnedFd,
        route_context_id: [u8; 16],
        reservation_id: [u8; 16],
        path_id: u32,
        relay_node_id: [u8; 32],
    ) -> Self {
        let path_number = u8::try_from(path_id).unwrap();
        let addresses = overlay_addresses(route_context_id, path_number).unwrap();
        Self {
            descriptor,
            add: AddPath {
                route_context_id: route_context_id.to_vec(),
                path_id,
                local_ip: addresses.client.octets().to_vec(),
                remote_ip: addresses.exit.octets().to_vec(),
                remote_port: 44_443,
                reservation_hash: vec![path_number; 32],
                local_port: 40_000 + path_id,
            },
            reservation_id,
            relay_node_id,
            exit_native_instance_id: [8; 32],
            expires_at_ms: 1_700_000_060_000,
            listener_set_ready: path_id == 2,
        }
    }
}

/// Affine owner of one native CONNECT-IP association over genuine Multipath QUIC.
#[must_use = "the native MPQUIC session must remain owned until shutdown"]
pub struct ProductionMpquicSession {
    client: NativeClient,
    authorization: ClientNativeRouteAuthorization,
    route_context_id: [u8; 16],
    masque_context_id: u64,
    active_path_ids: Vec<u32>,
    assignment: TunnelAssignment,
}

impl ProductionMpquicSession {
    /// Preflight one client-side native process and establish a hard-multipath session.
    ///
    /// # Errors
    ///
    /// Returns an error unless the authorization, native instance, and at least two distinct live
    /// committed Relay paths bind exactly, or when the native process cannot make every path ready.
    pub async fn establish(
        client: NativeClient,
        authorization: ClientNativeRouteAuthorization,
        paths: Vec<CommittedMpquicPath>,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<Self, ProductionMpquicError> {
        if ready_wait.is_zero() || ready_wait > MAXIMUM_READY_WAIT {
            return Err(ProductionMpquicError::Invalid("MPQUIC ready wait"));
        }
        let client = client.preflight(NativeProcessRole::Client).await?;
        let expected_instance = authorization
            .native_route_identity()
            .client_native_instance_id
            .as_slice();
        if client.native_instance_id().map(<[u8; 32]>::as_slice) != Some(expected_instance) {
            return Err(ProductionMpquicError::Invalid(
                "authorized native Client instance",
            ));
        }
        let start = start_request(&authorization, paths.len(), now_ms)?;
        let path_ids = validate_complete_path_set(&start, &paths, now_ms)?;
        let assignment = setup_native_session(&client, &start, paths, ready_wait).await?;
        Ok(Self {
            client,
            authorization,
            route_context_id: start
                .route_context_id
                .as_slice()
                .try_into()
                .map_err(|_| ProductionMpquicError::Invalid("MPQUIC route context"))?,
            masque_context_id: start.masque_context_id,
            active_path_ids: path_ids,
            assignment,
        })
    }

    /// Borrow the path IDs which were required before the native tunnel became ready.
    #[must_use]
    pub fn active_path_ids(&self) -> &[u32] {
        &self.active_path_ids
    }

    /// Borrow the native CONNECT-IP tunnel assignment.
    #[must_use]
    pub const fn assignment(&self) -> &TunnelAssignment {
        &self.assignment
    }

    /// Submit one already policy-authorized complete inner IP datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded native process rejects or cannot send the datagram.
    pub async fn send_inner_ip(&self, packet: Vec<u8>) -> Result<(), ProductionMpquicError> {
        send_inner_ip(
            &self.client,
            self.route_context_id,
            self.masque_context_id,
            packet,
        )
        .await
    }

    /// Poll one reverse CONNECT-IP datagram without an ordinary-QUIC fallback.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded native process rejects or cannot poll the association.
    pub async fn receive_inner_ip(&self) -> Result<Option<Vec<u8>>, ProductionMpquicError> {
        receive_inner_ip(&self.client, self.route_context_id, self.masque_context_id).await
    }

    /// Stop and wipe the exact native session before the helper route is destroyed.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded native process cannot stop the exact route context.
    pub async fn shutdown(self) -> Result<(), ProductionMpquicError> {
        let Self {
            client,
            authorization,
            route_context_id,
            ..
        } = self;
        let result = client
            .stop_session(StopSession {
                route_context_id: route_context_id.to_vec(),
            })
            .await;
        drop(authorization);
        result.map_err(Into::into)
    }
}

fn start_request(
    authorization: &ClientNativeRouteAuthorization,
    path_count: usize,
    now_ms: u64,
) -> Result<StartSession, ProductionMpquicError> {
    if !(MINIMUM_MULTIPATH_PATHS..=MAXIMUM_MULTIPATH_PATHS).contains(&path_count)
        || now_ms >= authorization.expires_at_ms()
    {
        return Err(ProductionMpquicError::Invalid(
            "live MPQUIC path cardinality",
        ));
    }
    let identity = authorization.native_route_identity();
    Ok(StartSession {
        route_context_id: authorization.route_context_id().to_vec(),
        exit_spki_sha256: identity.spki_sha256.clone(),
        minimum_paths: u32::try_from(path_count)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC path cardinality"))?,
        masque_context_id: identity.masque_context_id,
        transport_mode: TransportMode::MultipathQuic as i32,
        auth_secret: authorization.auth_bearer().to_vec(),
        tls_server_name: identity.tls_server_name.as_bytes().to_vec(),
        expires_at_ms: authorization.expires_at_ms(),
        reservation_id: authorization.reservation_id().to_vec(),
        finalize_id: authorization.finalize_id().to_vec(),
        auth_commitment: identity.auth_commitment.clone(),
        certificate_sha256: identity.certificate_sha256.clone(),
        client_native_instance_id: identity.client_native_instance_id.clone(),
        exit_native_instance_id: identity.exit_native_instance_id.clone(),
    })
}

fn validate_complete_path_set(
    start: &StartSession,
    paths: &[CommittedMpquicPath],
    now_ms: u64,
) -> Result<Vec<u32>, ProductionMpquicError> {
    let route_context: [u8; 16] = start
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC route context"))?;
    let reservation_id: [u8; 16] = start
        .reservation_id
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC reservation"))?;
    let mut path_ids = BTreeSet::new();
    let mut relay_ids = BTreeSet::new();
    let expected_exit_instance: [u8; 32] = start
        .exit_native_instance_id
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("Exit native instance"))?;
    let mut listener_set_ready = false;
    for path in paths {
        if path.add.route_context_id.as_slice() != route_context
            || path.reservation_id != reservation_id
            || path.expires_at_ms <= now_ms
            || path.exit_native_instance_id != expected_exit_instance
            || !path_ids.insert(path.add.path_id)
            || !relay_ids.insert(path.relay_node_id)
        {
            return Err(ProductionMpquicError::Invalid(
                "distinct committed MPQUIC paths",
            ));
        }
        listener_set_ready |= path.listener_set_ready;
    }
    if path_ids.len() < MINIMUM_MULTIPATH_PATHS
        || path_ids.len() != paths.len()
        || !listener_set_ready
    {
        return Err(ProductionMpquicError::Invalid(
            "distinct committed MPQUIC paths",
        ));
    }
    Ok(path_ids.into_iter().collect())
}

enum StartReadiness {
    Pending,
    Ready(TunnelAssignment),
}

trait MultipathNativeControl {
    fn start(
        &self,
        request: StartSession,
    ) -> impl Future<Output = Result<StartReadiness, ProductionMpquicError>> + Send;

    fn add_path(
        &self,
        request: AddPath,
        descriptor: OwnedFd,
    ) -> impl Future<Output = Result<(), ProductionMpquicError>> + Send;

    fn stop(
        &self,
        request: StopSession,
    ) -> impl Future<Output = Result<(), ProductionMpquicError>> + Send;

    fn send(
        &self,
        request: SendDatagram,
    ) -> impl Future<Output = Result<(), ProductionMpquicError>> + Send;

    fn receive(
        &self,
        request: ReceiveDatagram,
    ) -> impl Future<Output = Result<Option<ReceivedDatagram>, ProductionMpquicError>> + Send;
}

impl MultipathNativeControl for NativeClient {
    async fn start(&self, request: StartSession) -> Result<StartReadiness, ProductionMpquicError> {
        match self.start_session(request).await {
            Ok(assignment) => Ok(StartReadiness::Ready(assignment)),
            Err(NativeClientError::Rejected {
                result: NativeResultCode::InsufficientPaths,
                ..
            }) => Ok(StartReadiness::Pending),
            Err(error) => Err(error.into()),
        }
    }

    async fn add_path(
        &self,
        request: AddPath,
        descriptor: OwnedFd,
    ) -> Result<(), ProductionMpquicError> {
        NativeClient::add_path(self, request, descriptor)
            .await
            .map_err(Into::into)
    }

    async fn stop(&self, request: StopSession) -> Result<(), ProductionMpquicError> {
        NativeClient::stop_session(self, request)
            .await
            .map_err(Into::into)
    }

    async fn send(&self, request: SendDatagram) -> Result<(), ProductionMpquicError> {
        NativeClient::send_datagram(self, request)
            .await
            .map_err(Into::into)
    }

    async fn receive(
        &self,
        request: ReceiveDatagram,
    ) -> Result<Option<ReceivedDatagram>, ProductionMpquicError> {
        NativeClient::receive_datagram(self, request)
            .await
            .map_err(Into::into)
    }
}

async fn send_inner_ip<C: MultipathNativeControl>(
    control: &C,
    route_context_id: [u8; 16],
    masque_context_id: u64,
    packet: Vec<u8>,
) -> Result<(), ProductionMpquicError> {
    control
        .send(SendDatagram {
            route_context_id: route_context_id.to_vec(),
            inner_ip_packet: packet,
            masque_context_id,
        })
        .await
}

async fn receive_inner_ip<C: MultipathNativeControl>(
    control: &C,
    route_context_id: [u8; 16],
    masque_context_id: u64,
) -> Result<Option<Vec<u8>>, ProductionMpquicError> {
    let received = control
        .receive(ReceiveDatagram {
            route_context_id: route_context_id.to_vec(),
            masque_context_id,
        })
        .await?;
    Ok(received.map(|mut datagram| std::mem::take(&mut datagram.inner_ip_packet)))
}

async fn setup_native_session<C: MultipathNativeControl>(
    control: &C,
    start: &StartSession,
    paths: Vec<CommittedMpquicPath>,
    ready_wait: Duration,
) -> Result<TunnelAssignment, ProductionMpquicError> {
    let stop = StopSession {
        route_context_id: start.route_context_id.clone(),
    };
    let setup = async {
        if !matches!(control.start(start.clone()).await?, StartReadiness::Pending) {
            return Err(ProductionMpquicError::UnexpectedReady);
        }
        for path in paths {
            control.add_path(path.add, path.descriptor).await?;
        }
        let deadline = Instant::now() + ready_wait;
        loop {
            match control.start(start.clone()).await? {
                StartReadiness::Ready(assignment) => return Ok(assignment),
                StartReadiness::Pending => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(ProductionMpquicError::ReadyTimeout);
                    }
                    sleep_until((now + READY_POLL_INTERVAL).min(deadline)).await;
                }
            }
        }
    }
    .await;
    if setup.is_err() {
        let _ = control.stop(stop).await;
    }
    setup
}

fn transport_address(value: &TransportSocketAddress) -> Result<SocketAddr, ProductionMpquicError> {
    let ip = match value.address.as_slice() {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| ProductionMpquicError::Invalid("MPQUIC local address"))?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(ProductionMpquicError::Invalid("MPQUIC local address")),
    };
    let port = u16::try_from(value.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ProductionMpquicError::Invalid("MPQUIC local port"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Fail-closed MPQUIC owner setup and operation errors.
#[derive(Debug, Error)]
pub enum ProductionMpquicError {
    /// A committed route, authorization, or descriptor binding was inconsistent.
    #[error("invalid production MPQUIC binding: {0}")]
    Invalid(&'static str),
    /// Native reported a ready tunnel before the required paths were submitted.
    #[error("native MPQUIC became ready without its required paths")]
    UnexpectedReady,
    /// The native engine did not activate every required path within the fixed wait.
    #[error("native MPQUIC did not become ready before its deadline")]
    ReadyTimeout,
    /// The bounded native process API failed or rejected the operation.
    #[error("native MPQUIC control failed: {0}")]
    Native(#[from] NativeClientError),
}

#[cfg(test)]
mod tests {
    use std::{
        net::UdpSocket,
        os::fd::OwnedFd,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    #[derive(Clone)]
    struct FakeNative {
        state: Arc<Mutex<FakeState>>,
        datagram_tx: Arc<UdpSocket>,
        datagram_rx: Arc<UdpSocket>,
    }

    impl Default for FakeNative {
        fn default() -> Self {
            let datagram_tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let datagram_rx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            datagram_tx
                .connect(datagram_rx.local_addr().unwrap())
                .unwrap();
            datagram_rx
                .connect(datagram_tx.local_addr().unwrap())
                .unwrap();
            datagram_rx
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            Self {
                state: Arc::default(),
                datagram_tx: Arc::new(datagram_tx),
                datagram_rx: Arc::new(datagram_rx),
            }
        }
    }

    #[derive(Default)]
    struct FakeState {
        starts: usize,
        paths: Vec<u32>,
        stopped: bool,
    }

    impl MultipathNativeControl for FakeNative {
        async fn start(
            &self,
            request: StartSession,
        ) -> Result<StartReadiness, ProductionMpquicError> {
            assert_eq!(request.transport_mode, TransportMode::MultipathQuic as i32);
            assert_eq!(request.minimum_paths, 2);
            let mut state = self.state.lock().unwrap();
            state.starts += 1;
            if state.paths.len() < 2 {
                Ok(StartReadiness::Pending)
            } else {
                Ok(StartReadiness::Ready(TunnelAssignment {
                    assigned_ipv4: vec![10, 76, 0, 2],
                    assigned_prefix_v4: 32,
                    server_ipv4: vec![10, 76, 0, 1],
                    server_prefix_v4: 32,
                    mtu: 1_280,
                    assigned_ipv6: Vec::new(),
                    assigned_prefix_v6: 0,
                }))
            }
        }

        async fn add_path(
            &self,
            request: AddPath,
            descriptor: OwnedFd,
        ) -> Result<(), ProductionMpquicError> {
            drop(descriptor);
            self.state.lock().unwrap().paths.push(request.path_id);
            Ok(())
        }

        async fn stop(&self, _request: StopSession) -> Result<(), ProductionMpquicError> {
            self.state.lock().unwrap().stopped = true;
            Ok(())
        }

        async fn send(&self, request: SendDatagram) -> Result<(), ProductionMpquicError> {
            assert_eq!(request.route_context_id, [2; 16]);
            assert_eq!(request.masque_context_id, 7);
            self.datagram_tx.send(&request.inner_ip_packet).unwrap();
            Ok(())
        }

        async fn receive(
            &self,
            request: ReceiveDatagram,
        ) -> Result<Option<ReceivedDatagram>, ProductionMpquicError> {
            assert_eq!(request.route_context_id, [2; 16]);
            assert_eq!(request.masque_context_id, 7);
            let mut packet = vec![0_u8; 1_280];
            let length = self.datagram_rx.recv(&mut packet).unwrap();
            packet.truncate(length);
            Ok(Some(ReceivedDatagram {
                route_context_id: request.route_context_id,
                masque_context_id: request.masque_context_id,
                inner_ip_packet: packet,
            }))
        }
    }

    fn start() -> StartSession {
        StartSession {
            route_context_id: vec![2; 16],
            exit_spki_sha256: vec![3; 32],
            minimum_paths: 2,
            masque_context_id: 7,
            transport_mode: TransportMode::MultipathQuic as i32,
            auth_secret: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            tls_server_name: b"exit.example".to_vec(),
            expires_at_ms: 1_700_000_060_000,
            reservation_id: vec![1; 16],
            finalize_id: vec![4; 16],
            auth_commitment: vec![5; 32],
            certificate_sha256: vec![6; 32],
            client_native_instance_id: vec![7; 32],
            exit_native_instance_id: vec![8; 32],
        }
    }

    fn socket() -> OwnedFd {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into()
    }

    #[tokio::test]
    async fn two_distinct_committed_paths_drive_one_local_inner_datagram() {
        let native = FakeNative::default();
        let paths = vec![
            CommittedMpquicPath::for_test(socket(), [2; 16], [1; 16], 1, [11; 32]),
            CommittedMpquicPath::for_test(socket(), [2; 16], [1; 16], 2, [12; 32]),
        ];
        let path_ids = validate_complete_path_set(&start(), &paths, 1_700_000_000_000).unwrap();
        assert_eq!(path_ids, [1, 2]);
        let assignment = setup_native_session(&native, &start(), paths, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(assignment.assigned_ipv4, [10, 76, 0, 2]);
        {
            let state = native.state.lock().unwrap();
            assert_eq!(state.paths, [1, 2]);
            assert_eq!(state.starts, 2);
            assert!(!state.stopped);
        }

        let packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 59, 0, 0, 10, 76, 0, 2, 10, 76, 0, 1,
        ];
        send_inner_ip(&native, [2; 16], 7, packet.clone())
            .await
            .unwrap();
        assert_eq!(
            receive_inner_ip(&native, [2; 16], 7).await.unwrap(),
            Some(packet)
        );
    }

    #[tokio::test]
    async fn setup_failure_stops_without_single_path_fallback() {
        let native = FakeNative::default();
        let paths = vec![
            CommittedMpquicPath::for_test(socket(), [2; 16], [1; 16], 1, [11; 32]),
            CommittedMpquicPath::for_test(socket(), [2; 16], [1; 16], 2, [11; 32]),
        ];
        assert!(validate_complete_path_set(&start(), &paths, 1_700_000_000_000).is_err());

        let one_path = vec![CommittedMpquicPath::for_test(
            socket(),
            [2; 16],
            [1; 16],
            1,
            [11; 32],
        )];
        let error = setup_native_session(&native, &start(), one_path, Duration::from_millis(25))
            .await
            .unwrap_err();
        assert!(matches!(error, ProductionMpquicError::ReadyTimeout));
        assert!(native.state.lock().unwrap().stopped);
    }
}
