//! Callable ownership seam for the native multipath QUIC client process.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    os::fd::OwnedFd,
    time::Duration,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    time::{Instant, MissedTickBehavior, interval, sleep_until},
};
use volparossa_discovery::{ExitMpquicSessionSignal, UdpExitSessionSignal};
use volparossa_exit::{ExitNativeRouteAuthorization, ExitNativeRouteCredentialAuthorization};
use volparossa_inspection::{InspectionProgress, QuicInitialInspector};
use volparossa_policy::{TransportProtocol, VerifiedManifest};
use volparossa_protocol::{ReplayCache, TimePolicy};
use volparossa_quic::{
    AddPath, GetStatus, NativeClient, NativeClientError, NativePathStatus, NativeProcessRole,
    NativeResultCode, ReceiveDatagram, ReceivedDatagram, RemovePath, SendDatagram,
    StartExitSession, StartSession, StopSession, TransportMode, TunnelAssignment,
    VerifiedExitMpquicEndpoint, parse_initial,
};
use volparossa_reservation::{ClientNativeRouteAuthorization, VerifiedRelayGrant};
use volparossa_routing::{
    AcquireTransportSocket, CommitLeaseBatch, ContextRole, TransportSocketAddress,
    TransportSocketKind, WireguardRole,
};
use volparossa_udp::{AuthorizedUdpFlow, UdpAuthorizationScope, UdpError, VerifiedSingleRelayPath};
use volparossa_wireguard::{HELPER_HANDLE_BYTES, overlay_addresses};
use zeroize::Zeroizing;

use crate::helper::{
    AcquiredTransportSocket, HelperClient, HelperClientError, RuntimeBoundPreparedLeaseBatch,
};

const MINIMUM_MULTIPATH_PATHS: usize = 2;
const MINIMUM_MULTIPATH_PATHS_U32: u32 = 2;
const MAXIMUM_MULTIPATH_PATHS: usize = 8;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAXIMUM_READY_WAIT: Duration = Duration::from_secs(10);
const EXIT_DATAGRAM_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAXIMUM_EXIT_UDP_FLOWS: usize = 256;
const MAXIMUM_EXIT_DATAGRAMS_PER_TICK: usize = 64;
const MAXIMUM_EXIT_FLOW_IDLE: Duration = Duration::from_secs(10 * 60);
const EXIT_FLOW_REPLAY_CAPACITY: usize = 4_096;
pub(crate) const MINIMUM_MPQUIC_TUNNEL_MTU: usize = 1_280;
const MAXIMUM_EXIT_UDP_PAYLOAD_BYTES: usize = MINIMUM_MPQUIC_TUNNEL_MTU - 20 - 8;
const MPQUIC_TUNNEL_IPV4_PREFIX: [u8; 3] = [10, 76, 0];
/// Fixed protected-overlay listener port for every path of one MPQUIC Exit association.
pub const MPQUIC_EXIT_LISTENER_PORT: u16 = 44_443;
const MPQUIC_CLIENT_PORT_BASE: u16 = 40_000;
const BROWSER_QUIC_PORT: u16 = 443;
const BROWSER_QUIC_AUTHORIZATION_PORT: u16 = 44_445;
const TUNNEL_SERVER_IPV4: Ipv4Addr = Ipv4Addr::new(10, 76, 0, 1);
const MAXIMUM_PENDING_BROWSER_QUIC_DATAGRAMS: usize = 128;
const MAXIMUM_PENDING_BROWSER_QUIC_BYTES: usize = 256 * 1024;
const MAXIMUM_PENDING_GENERAL_UDP_AGE: Duration = Duration::from_secs(5);
const GENERAL_UDP_AUTH_PORT: u16 = 47_001;
const GENERAL_UDP_AUTH_MAGIC: &[u8] = b"VOLPAROSSA-UDP-AUTH-V1\0";
// A freshly established xquic association can remain non-writable for several
// relay RTTs before its datagram-write callback clears mqvpn's backpressure
// latch. Keep retrying only that exact transient result, within the ingress
// request's timeout, rather than rejecting the first application datagram.
const NATIVE_SEND_BACKPRESSURE_ATTEMPTS: usize = 400;
const NATIVE_SEND_BACKPRESSURE_INTERVAL: Duration = Duration::from_millis(5);

/// Affine preflight of the exact native Exit process incarnation signed into finalization.
#[must_use = "native Exit preflight authority must be consumed by one route"]
pub(crate) struct ProductionMpquicExitPreflight {
    client: NativeClient,
    native_instance_id: [u8; 32],
}

impl ProductionMpquicExitPreflight {
    /// Select one live native Exit process before its incarnation enters the signed reservation.
    pub(crate) async fn new(client: NativeClient) -> Result<Self, ProductionMpquicError> {
        let client = client.preflight(NativeProcessRole::Exit).await?;
        let native_instance_id =
            *client
                .native_instance_id()
                .ok_or(ProductionMpquicError::Invalid(
                    "preflighted native Exit instance",
                ))?;
        Ok(Self {
            client,
            native_instance_id,
        })
    }

    /// Exact native Exit incarnation which finalization must sign.
    pub(crate) const fn native_instance_id(&self) -> &[u8; 32] {
        &self.native_instance_id
    }
}

/// One exact confirmed Relay proof used to derive an Exit listener and native proof digest.
pub(crate) struct ExitMpquicPathAuthorization {
    path_id: u32,
    signed_relay_reservation: Vec<u8>,
}

impl ExitMpquicPathAuthorization {
    pub(crate) fn new(path_id: u32, signed_relay_reservation: Vec<u8>) -> Option<Self> {
        (path_id != 0 && !signed_relay_reservation.is_empty()).then_some(Self {
            path_id,
            signed_relay_reservation,
        })
    }
}

struct NativeExitAuthorizationParts {
    reservation_id: [u8; 16],
    route_context_id: [u8; 16],
    finalize_id: [u8; 16],
    expires_at_ms: u64,
    auth_bearer: Zeroizing<[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>,
    auth_commitment: [u8; 32],
    certificate_sha256: [u8; 32],
    spki_sha256: [u8; 32],
    masque_context_id: u64,
    tls_server_name: Vec<u8>,
    tls_certificate_pem: Zeroizing<Vec<u8>>,
    tls_private_key_pem: Zeroizing<Vec<u8>>,
    client_native_instance_id: [u8; 32],
    exit_native_instance_id: [u8; 32],
    client_session_id: [u8; 32],
}

impl NativeExitAuthorizationParts {
    fn from_credential(
        credential: ExitNativeRouteCredentialAuthorization,
    ) -> Result<Self, ProductionMpquicError> {
        let (authorization, auth_bearer, client_session_id) = credential.into_parts();
        Self::from_parts(&authorization, auth_bearer, client_session_id)
    }

    fn from_parts(
        authorization: &ExitNativeRouteAuthorization,
        auth_bearer: Zeroizing<[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>,
        client_session_id: [u8; 32],
    ) -> Result<Self, ProductionMpquicError> {
        let scope = authorization.scope();
        let request = scope.request();
        let identity = authorization.public_identity();
        let auth_commitment = identity
            .auth_commitment
            .as_slice()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("native auth commitment"))?;
        let certificate_sha256 = identity
            .certificate_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("native certificate digest"))?;
        let spki_sha256 = identity
            .spki_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("native SPKI digest"))?;
        let client_native_instance_id = identity
            .client_native_instance_id
            .as_slice()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("native Client instance"))?;
        let exit_native_instance_id = identity
            .exit_native_instance_id
            .as_slice()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("native Exit instance"))?;
        if request.auth_commitment() != &auth_commitment
            || request.client_native_instance_id() != &client_native_instance_id
            || request.exit_native_instance_id() != &exit_native_instance_id
            || scope.exit_native_instance_id() != &exit_native_instance_id
            || authorization.expires_at_ms() == 0
        {
            return Err(ProductionMpquicError::Invalid(
                "native Exit authorization identity",
            ));
        }
        Ok(Self {
            reservation_id: *request.reservation_id(),
            route_context_id: *request.route_context_id(),
            finalize_id: *request.finalize_id(),
            expires_at_ms: authorization.expires_at_ms(),
            auth_bearer,
            auth_commitment,
            certificate_sha256,
            spki_sha256,
            masque_context_id: request.masque_context_id(),
            tls_server_name: identity.tls_server_name.as_bytes().to_vec(),
            tls_certificate_pem: Zeroizing::new(authorization.tls_certificate_pem().to_vec()),
            tls_private_key_pem: Zeroizing::new(authorization.tls_private_key_pem().to_vec()),
            client_native_instance_id,
            exit_native_instance_id,
            client_session_id,
        })
    }
}

struct CommittedMpquicExitListener {
    descriptor: OwnedFd,
    path_id: u32,
    listener_ip: [u8; 16],
    expected_client_ip: [u8; 16],
    reservation_hash: [u8; 32],
}

impl CommittedMpquicExitListener {
    fn from_helper_handoff(
        acquired: AcquiredTransportSocket,
        route_context_id: [u8; 16],
        path: &ExitMpquicPathAuthorization,
    ) -> Result<Self, ProductionMpquicError> {
        let (descriptor, metadata) = acquired.into_parts();
        let path_number = u8::try_from(path.path_id)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC Exit path id"))?;
        let addresses = overlay_addresses(route_context_id, path_number)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC Exit overlay"))?;
        let local = transport_address(
            metadata
                .local
                .as_ref()
                .ok_or(ProductionMpquicError::Invalid("MPQUIC Exit local tuple"))?,
        )?;
        if metadata.path_id != path.path_id
            || WireguardRole::try_from(metadata.role).ok() != Some(WireguardRole::Exit)
            || TransportSocketKind::try_from(metadata.descriptor_kind).ok()
                != Some(TransportSocketKind::QuicUdpUnconnected)
            || metadata.remote.is_some()
            || local != SocketAddr::new(IpAddr::V6(addresses.exit), MPQUIC_EXIT_LISTENER_PORT)
        {
            return Err(ProductionMpquicError::Invalid(
                "committed MPQUIC Exit descriptor",
            ));
        }
        Ok(Self {
            descriptor,
            path_id: path.path_id,
            listener_ip: addresses.exit.octets(),
            expected_client_ip: addresses.client.octets(),
            reservation_hash: Sha256::digest(&path.signed_relay_reservation).into(),
        })
    }
}

/// Native Exit plus helper owner retained until the signed route expires.
#[must_use = "an active native MPQUIC Exit route must be run or shut down"]
pub(crate) struct ActiveProductionMpquicExitRoute {
    client: NativeClient,
    helper: HelperClient,
    owner: RuntimeBoundPreparedLeaseBatch,
    route_context_id: [u8; 16],
    masque_context_id: u64,
    expires_at_ms: u64,
    policy: VerifiedManifest,
    flow_idle_timeout: Duration,
    client_session_id: [u8; 32],
    transport_mode: TransportMode,
    single_path_udp: Option<VerifiedSingleRelayPath>,
}

impl ActiveProductionMpquicExitRoute {
    /// Bridge policy-authorized inner IPv4/UDP datagrams until route or policy expiry.
    ///
    /// Every destination gets one connected, route-local UDP socket. Its reverse traffic is
    /// reconstructed only toward the exact tunnel-assigned Client address and application port.
    pub(crate) async fn run(mut self, now_ms: u64) -> Result<(), ProductionMpquicError> {
        let forwarding = self.forward_datagrams(now_ms).await;
        let cleanup = self.shutdown().await;
        match (forwarding, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(()), result) => result,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded fail-closed MPQUIC Exit forwarding loop"
    )]
    async fn forward_datagrams(&mut self, now_ms: u64) -> Result<(), ProductionMpquicError> {
        self.policy
            .ensure_active_at(now_ms)
            .map_err(|_| ProductionMpquicError::Invalid("active MPQUIC Exit policy"))?;
        if now_ms >= self.expires_at_ms {
            return Ok(());
        }
        let mut assigned_client_ipv4 = None;
        let mut flows = HashMap::<ExitUdpFlowKey, ExitUdpFlow>::new();
        let mut pending_browser_flows = HashMap::<SocketAddrV4, PendingExitBrowserQuicFlow>::new();
        let mut authorization_replay = ReplayCache::new(MAXIMUM_EXIT_UDP_FLOWS)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC UDP authorization replay"))?;
        let mut authorized_general_udp = HashMap::<ExitUdpFlowKey, AuthorizedUdpFlow>::new();
        let mut pending_general_udp = HashMap::<ExitUdpFlowKey, PendingGeneralUdpDatagram>::new();
        let mut general_udp_replay = (self.transport_mode == TransportMode::SinglePathGeneralUdp)
            .then(|| ReplayCache::new(EXIT_FLOW_REPLAY_CAPACITY))
            .transpose()
            .map_err(|_| ProductionMpquicError::Invalid("native UDP replay bound"))?;
        let mut packet_id = 0_u16;
        let mut awaiting_client = true;
        let mut response_buffer = vec![0_u8; MAXIMUM_EXIT_UDP_PAYLOAD_BYTES + 1];
        let mut poll = interval(EXIT_DATAGRAM_POLL_INTERVAL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            poll.tick().await;
            let current_ms = crate::unix_millis();
            if current_ms >= self.expires_at_ms || self.policy.ensure_active_at(current_ms).is_err()
            {
                return Ok(());
            }
            let now = Instant::now();
            flows.retain(|_, flow| now.duration_since(flow.last_activity) < self.flow_idle_timeout);
            pending_browser_flows
                .retain(|_, flow| now.duration_since(flow.last_activity) < self.flow_idle_timeout);
            pending_general_udp.retain(|_, datagram| {
                now.duration_since(datagram.received_at) < MAXIMUM_PENDING_GENERAL_UDP_AGE
            });
            authorized_general_udp.retain(|_, flow| flow.ensure_active_at(current_ms).is_ok());

            for _ in 0..MAXIMUM_EXIT_DATAGRAMS_PER_TICK {
                let (connected, packet) = receive_exit_inner_ip(
                    &self.client,
                    self.route_context_id,
                    self.masque_context_id,
                    awaiting_client,
                )
                .await?;
                if connected {
                    awaiting_client = false;
                }
                let Some(packet) = packet else {
                    break;
                };
                if self.transport_mode == TransportMode::SinglePathGeneralUdp {
                    if let Some(control) =
                        parse_general_udp_authorization(&packet, assigned_client_ipv4)?
                    {
                        assigned_client_ipv4 = Some(*control.key.client.ip());
                        let path = self
                            .single_path_udp
                            .as_ref()
                            .ok_or(ProductionMpquicError::Invalid("native UDP verified path"))?;
                        let replay = general_udp_replay
                            .as_mut()
                            .ok_or(ProductionMpquicError::Invalid("native UDP replay owner"))?;
                        let flow = UdpAuthorizationScope::new(path, &self.policy).verify(
                            control.signed_authorization,
                            current_ms,
                            TimePolicy::default(),
                            replay,
                        )?;
                        if !flow
                            .matches_exact_ip_destination(SocketAddr::V4(control.key.destination))
                            || (!authorized_general_udp.contains_key(&control.key)
                                && authorized_general_udp.len() >= MAXIMUM_EXIT_UDP_FLOWS)
                        {
                            return Err(ProductionMpquicError::Invalid(
                                "native UDP signed destination",
                            ));
                        }
                        let pending = pending_general_udp.remove(&control.key);
                        authorized_general_udp.insert(control.key, flow);
                        if let Some(pending) = pending {
                            let authorization = authorized_general_udp.get(&control.key).ok_or(
                                ProductionMpquicError::Invalid(
                                    "native UDP retained signed destination",
                                ),
                            )?;
                            forward_authorized_general_udp(
                                &mut flows,
                                &self.policy,
                                authorization,
                                control.key,
                                &pending.payload,
                                current_ms,
                            )
                            .await?;
                        }
                        continue;
                    }
                }
                let datagram = parse_exit_ipv4_udp(&packet, assigned_client_ipv4)?;
                assigned_client_ipv4 = Some(*datagram.client.ip());
                if self.transport_mode == TransportMode::MultipathQuic
                    && datagram.destination
                        == SocketAddrV4::new(TUNNEL_SERVER_IPV4, BROWSER_QUIC_AUTHORIZATION_PORT)
                {
                    if pending_browser_flows.len() >= MAXIMUM_EXIT_UDP_FLOWS
                        || flows.keys().any(|key| key.client == datagram.client)
                    {
                        return Err(ProductionMpquicError::Invalid(
                            "MPQUIC browser authorization flow bound",
                        ));
                    }
                    let authorization = UdpAuthorizationScope::new_multipath(
                        self.route_context_id,
                        self.client_session_id,
                        self.expires_at_ms,
                        &self.policy,
                    )?
                    .verify(
                        datagram.payload,
                        current_ms,
                        TimePolicy::default(),
                        &mut authorization_replay,
                    )?;
                    if authorization.port() != BROWSER_QUIC_PORT
                        || authorization.hostname().is_none()
                    {
                        return Err(ProductionMpquicError::Invalid(
                            "MPQUIC browser hostname authorization",
                        ));
                    }
                    pending_browser_flows.insert(
                        datagram.client,
                        PendingExitBrowserQuicFlow::new(authorization),
                    );
                    continue;
                }
                let key = ExitUdpFlowKey {
                    client: datagram.client,
                    destination: datagram.destination,
                };
                if self.transport_mode == TransportMode::SinglePathGeneralUdp {
                    let Some(authorization) = authorized_general_udp.get(&key) else {
                        // QUIC DATAGRAM delivery is unordered. Retain at most one MTU-bounded
                        // packet for each exact tuple until its separately signed authorization
                        // arrives; no socket is opened and no payload reaches egress first.
                        queue_general_udp_before_authorization(
                            &mut pending_general_udp,
                            key,
                            datagram.payload,
                        );
                        continue;
                    };
                    forward_authorized_general_udp(
                        &mut flows,
                        &self.policy,
                        authorization,
                        key,
                        datagram.payload,
                        current_ms,
                    )
                    .await?;
                    continue;
                }
                if let Some(flow) = flows.get_mut(&key) {
                    flow.authorize(&self.policy, current_ms, key.destination)?;
                    flow.send(datagram.payload).await?;
                    continue;
                }
                if datagram.destination.port() == BROWSER_QUIC_PORT {
                    let Some(mut pending) = take_verified_browser_quic_candidate(
                        &mut pending_browser_flows,
                        datagram.client,
                    ) else {
                        // The authorization and browser Initial travel as separate native
                        // datagrams, so delivery order is not guaranteed. An early Initial has no
                        // verified destination authority and is therefore dropped without opening
                        // an egress socket or terminating the authenticated route.
                        continue;
                    };
                    let complete = pending.inspect(datagram.destination, datagram.payload)?;
                    if !complete {
                        pending_browser_flows.insert(datagram.client, pending);
                        continue;
                    }
                    let pinned = pending.authorization.resolve_and_pin(current_ms).await?;
                    if pinned.destination() != SocketAddr::V4(datagram.destination) {
                        return Err(ProductionMpquicError::Invalid(
                            "browser QUIC DNS/original-destination pin",
                        ));
                    }
                    if flows.len() >= MAXIMUM_EXIT_UDP_FLOWS {
                        return Err(ProductionMpquicError::Invalid("MPQUIC Exit UDP flow bound"));
                    }
                    let mut flow =
                        ExitUdpFlow::connect(key.destination, Some(pending.authorization)).await?;
                    for payload in pending.datagrams {
                        flow.send(&payload).await?;
                    }
                    flows.insert(key, flow);
                    continue;
                }
                self.policy
                    .authorize_ip(
                        current_ms,
                        IpAddr::V4(*key.destination.ip()),
                        TransportProtocol::Udp,
                        key.destination.port(),
                    )
                    .map_err(|_| {
                        ProductionMpquicError::Invalid(
                            "policy-authorized MPQUIC Exit UDP destination",
                        )
                    })?;
                if flows.len() >= MAXIMUM_EXIT_UDP_FLOWS {
                    return Err(ProductionMpquicError::Invalid("MPQUIC Exit UDP flow bound"));
                }
                let mut flow = ExitUdpFlow::connect(key.destination, None).await?;
                flow.send(datagram.payload).await?;
                flows.insert(key, flow);
            }

            let mut reverse_packets = Vec::new();
            'flows: for (key, flow) in &mut flows {
                loop {
                    match flow.socket.try_recv(&mut response_buffer) {
                        Ok(length) => {
                            let Some(payload) = complete_exit_udp_payload(&response_buffer, length)
                            else {
                                // The extra byte is a truncation sentinel. In particular, QUIC
                                // path-MTU probes can legitimately exceed the inner tunnel MTU;
                                // dropping one lets endpoint PMTUD converge without terminating
                                // the authenticated route or forwarding a truncated datagram.
                                break;
                            };
                            flow.authorize(&self.policy, current_ms, key.destination)?;
                            packet_id = packet_id.wrapping_add(1);
                            reverse_packets.push(build_reverse_ipv4_udp(*key, payload, packet_id)?);
                            flow.last_activity = Instant::now();
                            if reverse_packets.len() >= MAXIMUM_EXIT_DATAGRAMS_PER_TICK {
                                break 'flows;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            for packet in reverse_packets {
                send_inner_ip(
                    &self.client,
                    self.route_context_id,
                    self.masque_context_id,
                    packet,
                )
                .await?;
            }
        }
    }

    async fn shutdown(self) -> Result<(), ProductionMpquicError> {
        let native = self
            .client
            .stop_session(StopSession {
                route_context_id: self.route_context_id.to_vec(),
            })
            .await;
        let helper = self.helper.destroy_context(&self.owner).await;
        native?;
        helper?;
        Ok(())
    }
}

fn complete_exit_udp_payload(buffer: &[u8], length: usize) -> Option<&[u8]> {
    if length > MAXIMUM_EXIT_UDP_PAYLOAD_BYTES {
        return None;
    }
    buffer.get(..length)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ExitUdpFlowKey {
    client: SocketAddrV4,
    destination: SocketAddrV4,
}

struct PendingGeneralUdpDatagram {
    payload: Vec<u8>,
    received_at: Instant,
}

fn queue_general_udp_before_authorization(
    pending: &mut HashMap<ExitUdpFlowKey, PendingGeneralUdpDatagram>,
    key: ExitUdpFlowKey,
    payload: &[u8],
) {
    if payload.len() > MAXIMUM_EXIT_UDP_PAYLOAD_BYTES || pending.len() >= MAXIMUM_EXIT_UDP_FLOWS {
        return;
    }
    pending
        .entry(key)
        .or_insert_with(|| PendingGeneralUdpDatagram {
            payload: payload.to_vec(),
            received_at: Instant::now(),
        });
}

struct ExitUdpFlow {
    socket: UdpSocket,
    last_activity: Instant,
    browser_authorization: Option<AuthorizedUdpFlow>,
}

impl ExitUdpFlow {
    async fn connect(
        destination: SocketAddrV4,
        browser_authorization: Option<AuthorizedUdpFlow>,
    ) -> Result<Self, ProductionMpquicError> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect(destination).await?;
        Ok(Self {
            socket,
            last_activity: Instant::now(),
            browser_authorization,
        })
    }

    fn authorize(
        &self,
        policy: &VerifiedManifest,
        now_ms: u64,
        destination: SocketAddrV4,
    ) -> Result<(), ProductionMpquicError> {
        if let Some(authorization) = &self.browser_authorization {
            authorization.ensure_active_at(now_ms)?;
            if !authorization.matches_exact_ip_destination(SocketAddr::V4(destination)) {
                return Err(ProductionMpquicError::Invalid(
                    "active browser QUIC destination pin",
                ));
            }
            let hostname = authorization
                .hostname()
                .ok_or(ProductionMpquicError::Invalid(
                    "active browser QUIC hostname",
                ))?;
            policy
                .authorize_domain(now_ms, hostname, TransportProtocol::Udp, destination.port())
                .map_err(|_| ProductionMpquicError::Invalid("active browser QUIC domain policy"))?;
        } else {
            policy
                .authorize_ip(
                    now_ms,
                    IpAddr::V4(*destination.ip()),
                    TransportProtocol::Udp,
                    destination.port(),
                )
                .map_err(|_| {
                    ProductionMpquicError::Invalid("active MPQUIC Exit UDP response policy")
                })?;
        }
        Ok(())
    }

    async fn send(&mut self, payload: &[u8]) -> Result<(), ProductionMpquicError> {
        let sent = self.socket.send(payload).await?;
        if sent != payload.len() {
            return Err(ProductionMpquicError::Invalid(
                "complete MPQUIC Exit UDP payload",
            ));
        }
        self.last_activity = Instant::now();
        Ok(())
    }
}

async fn forward_authorized_general_udp(
    flows: &mut HashMap<ExitUdpFlowKey, ExitUdpFlow>,
    policy: &VerifiedManifest,
    authorization: &AuthorizedUdpFlow,
    key: ExitUdpFlowKey,
    payload: &[u8],
    now_ms: u64,
) -> Result<(), ProductionMpquicError> {
    authorization.ensure_active_at(now_ms)?;
    if key.destination.port() == BROWSER_QUIC_PORT
        || !authorization.matches_exact_ip_destination(SocketAddr::V4(key.destination))
    {
        return Err(ProductionMpquicError::Invalid(
            "native UDP signed destination",
        ));
    }
    if let Some(flow) = flows.get_mut(&key) {
        flow.authorize(policy, now_ms, key.destination)?;
        return flow.send(payload).await;
    }
    policy
        .authorize_ip(
            now_ms,
            IpAddr::V4(*key.destination.ip()),
            TransportProtocol::Udp,
            key.destination.port(),
        )
        .map_err(|_| ProductionMpquicError::Invalid("policy-authorized native UDP destination"))?;
    if flows.len() >= MAXIMUM_EXIT_UDP_FLOWS {
        return Err(ProductionMpquicError::Invalid("native UDP flow bound"));
    }
    let mut flow = ExitUdpFlow::connect(key.destination, None).await?;
    flow.send(payload).await?;
    flows.insert(key, flow);
    Ok(())
}

struct PendingExitBrowserQuicFlow {
    authorization: AuthorizedUdpFlow,
    inspector: Option<QuicInitialInspector>,
    datagrams: Vec<Vec<u8>>,
    bytes: usize,
    last_activity: Instant,
}

fn take_verified_browser_quic_candidate(
    pending: &mut HashMap<SocketAddrV4, PendingExitBrowserQuicFlow>,
    client: SocketAddrV4,
) -> Option<PendingExitBrowserQuicFlow> {
    pending.remove(&client)
}

impl PendingExitBrowserQuicFlow {
    fn new(authorization: AuthorizedUdpFlow) -> Self {
        Self {
            authorization,
            inspector: None,
            datagrams: Vec::new(),
            bytes: 0,
            last_activity: Instant::now(),
        }
    }

    fn inspect(
        &mut self,
        destination: SocketAddrV4,
        payload: &[u8],
    ) -> Result<bool, ProductionMpquicError> {
        if !self
            .authorization
            .matches_exact_ip_destination(SocketAddr::V4(destination))
            || self.datagrams.len() >= MAXIMUM_PENDING_BROWSER_QUIC_DATAGRAMS
            || self
                .bytes
                .checked_add(payload.len())
                .is_none_or(|total| total > MAXIMUM_PENDING_BROWSER_QUIC_BYTES)
        {
            return Err(ProductionMpquicError::Invalid(
                "pending browser QUIC flow bound",
            ));
        }
        if self.inspector.is_none() {
            let initial = parse_initial(payload)
                .map_err(|_| ProductionMpquicError::Invalid("browser QUIC Initial header"))?;
            self.inspector = Some(
                QuicInitialInspector::new(initial.destination_connection_id).map_err(|_| {
                    ProductionMpquicError::Invalid("browser QUIC Initial key scope")
                })?,
            );
        }
        let progress = self
            .inspector
            .as_mut()
            .ok_or(ProductionMpquicError::Invalid(
                "browser QUIC Initial inspector",
            ))?
            .inspect_datagram(payload)
            .map_err(|_| ProductionMpquicError::Invalid("browser QUIC ClientHello"))?
            .progress;
        self.bytes += payload.len();
        self.datagrams.push(payload.to_vec());
        self.last_activity = Instant::now();
        let InspectionProgress::Complete(name) = progress else {
            return Ok(false);
        };
        if Some(name.as_str()) != self.authorization.hostname() {
            return Err(ProductionMpquicError::Invalid(
                "browser QUIC inspected hostname binding",
            ));
        }
        Ok(true)
    }
}

struct ParsedExitIpv4Udp<'a> {
    client: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &'a [u8],
}

struct ParsedGeneralUdpAuthorization<'a> {
    key: ExitUdpFlowKey,
    signed_authorization: &'a [u8],
}

fn parse_general_udp_authorization(
    packet: &[u8],
    assigned_client_ipv4: Option<Ipv4Addr>,
) -> Result<Option<ParsedGeneralUdpAuthorization<'_>>, ProductionMpquicError> {
    let datagram = parse_exit_ipv4_udp(packet, assigned_client_ipv4)?;
    if datagram.destination != SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 1), GENERAL_UDP_AUTH_PORT)
    {
        return Ok(None);
    }
    let fixed = GENERAL_UDP_AUTH_MAGIC.len() + 4 + 2 + 2;
    if datagram.payload.len() < fixed || !datagram.payload.starts_with(GENERAL_UDP_AUTH_MAGIC) {
        return Err(ProductionMpquicError::Invalid(
            "native UDP authorization packet",
        ));
    }
    let offset = GENERAL_UDP_AUTH_MAGIC.len();
    let destination = SocketAddrV4::new(
        Ipv4Addr::new(
            datagram.payload[offset],
            datagram.payload[offset + 1],
            datagram.payload[offset + 2],
            datagram.payload[offset + 3],
        ),
        u16::from_be_bytes([datagram.payload[offset + 4], datagram.payload[offset + 5]]),
    );
    let signed_length = usize::from(u16::from_be_bytes([
        datagram.payload[offset + 6],
        datagram.payload[offset + 7],
    ]));
    let signed_authorization = datagram
        .payload
        .get(fixed..)
        .filter(|signed| signed.len() == signed_length && !signed.is_empty())
        .ok_or(ProductionMpquicError::Invalid(
            "native UDP authorization length",
        ))?;
    if destination.ip().is_unspecified() || destination.port() == 0 {
        return Err(ProductionMpquicError::Invalid(
            "native UDP authorization destination",
        ));
    }
    Ok(Some(ParsedGeneralUdpAuthorization {
        key: ExitUdpFlowKey {
            client: datagram.client,
            destination,
        },
        signed_authorization,
    }))
}

#[cfg(test)]
fn authorize_exit_ipv4_udp<'a>(
    policy: &VerifiedManifest,
    now_ms: u64,
    packet: &'a [u8],
    assigned_client_ipv4: Option<Ipv4Addr>,
) -> Result<ParsedExitIpv4Udp<'a>, ProductionMpquicError> {
    let datagram = parse_exit_ipv4_udp(packet, assigned_client_ipv4)?;
    policy
        .authorize_ip(
            now_ms,
            IpAddr::V4(*datagram.destination.ip()),
            TransportProtocol::Udp,
            datagram.destination.port(),
        )
        .map_err(|_| {
            ProductionMpquicError::Invalid("policy-authorized MPQUIC Exit UDP destination")
        })?;
    Ok(datagram)
}

fn parse_exit_ipv4_udp(
    packet: &[u8],
    assigned_client_ipv4: Option<Ipv4Addr>,
) -> Result<ParsedExitIpv4Udp<'_>, ProductionMpquicError> {
    if packet.len() < 28
        || packet.len() > MINIMUM_MPQUIC_TUNNEL_MTU
        || packet[0] != 0x45
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
        || packet[8] == 0
        || packet[9] != 17
        || internet_checksum(&packet[..20]) != 0
    {
        return Err(ProductionMpquicError::Invalid(
            "complete MPQUIC Exit IPv4/UDP packet",
        ));
    }
    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let source_octets = source_ip.octets();
    if source_octets[..3] != MPQUIC_TUNNEL_IPV4_PREFIX
        || !(2..=254).contains(&source_octets[3])
        || assigned_client_ipv4.is_some_and(|assigned| assigned != source_ip)
    {
        return Err(ProductionMpquicError::Invalid(
            "MPQUIC Exit tunnel assignment",
        ));
    }
    let udp = &packet[20..];
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if source_port == 0
        || destination_port == 0
        || udp_length != udp.len()
        || udp_length < 8
        || udp_length - 8 > MAXIMUM_EXIT_UDP_PAYLOAD_BYTES
        || udp[6..8] == [0, 0]
        || udp_ipv4_checksum(source_ip, destination_ip, udp) != 0
    {
        return Err(ProductionMpquicError::Invalid(
            "complete MPQUIC Exit UDP datagram",
        ));
    }
    Ok(ParsedExitIpv4Udp {
        client: SocketAddrV4::new(source_ip, source_port),
        destination: SocketAddrV4::new(destination_ip, destination_port),
        payload: &udp[8..],
    })
}

fn build_reverse_ipv4_udp(
    flow: ExitUdpFlowKey,
    payload: &[u8],
    packet_id: u16,
) -> Result<Vec<u8>, ProductionMpquicError> {
    build_ipv4_udp(flow.destination, flow.client, payload, packet_id)
}

fn build_ipv4_udp(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
    packet_id: u16,
) -> Result<Vec<u8>, ProductionMpquicError> {
    if payload.len() > MAXIMUM_EXIT_UDP_PAYLOAD_BYTES {
        return Err(ProductionMpquicError::Invalid("MPQUIC inner UDP payload"));
    }
    let udp_length = 8_usize
        .checked_add(payload.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ProductionMpquicError::Invalid(
            "MPQUIC Exit UDP response length",
        ))?;
    let total_length = 20_u16
        .checked_add(udp_length)
        .ok_or(ProductionMpquicError::Invalid(
            "MPQUIC Exit IPv4 response length",
        ))?;
    let mut packet = vec![0_u8; usize::from(total_length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());
    packet[4..6].copy_from_slice(&packet_id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source.port().to_be_bytes());
    packet[22..24].copy_from_slice(&destination.port().to_be_bytes());
    packet[24..26].copy_from_slice(&udp_length.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let checksum = udp_ipv4_checksum(*source.ip(), *destination.ip(), &packet[20..]);
    packet[26..28]
        .copy_from_slice(&(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes());
    Ok(packet)
}

fn assignment_ipv4(bytes: &[u8]) -> Result<Ipv4Addr, ProductionMpquicError> {
    let octets: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC tunnel IPv4 assignment"))?;
    Ok(Ipv4Addr::from(octets))
}

fn udp_ipv4_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&u16::try_from(udp.len()).unwrap_or(u16::MAX).to_be_bytes());
    pseudo.extend_from_slice(udp);
    internet_checksum(&pseudo)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks_exact(2).fold(0_u32, |sum, word| {
        sum + u32::from(u16::from_be_bytes([word[0], word[1]]))
    });
    if let Some(byte) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Start one exact native Exit listener per committed Relay path and return only after the final
/// listener makes the native hard-multipath set ready.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one fail-closed helper-to-native MPQUIC Exit transaction"
)]
pub(crate) async fn start_production_mpquic_exit(
    preflight: ProductionMpquicExitPreflight,
    helper: HelperClient,
    owner: RuntimeBoundPreparedLeaseBatch,
    commit: CommitLeaseBatch,
    credential: ExitNativeRouteCredentialAuthorization,
    paths: Vec<ExitMpquicPathAuthorization>,
    policy: VerifiedManifest,
    signed_policy_hash: [u8; 32],
    flow_idle_timeout: Duration,
    now_ms: u64,
) -> Result<(ActiveProductionMpquicExitRoute, ExitMpquicSessionSignal), ProductionMpquicError> {
    let (active, ready) = start_production_native_exit(
        preflight,
        helper,
        owner,
        commit,
        credential,
        paths,
        policy,
        signed_policy_hash,
        flow_idle_timeout,
        TransportMode::MultipathQuic,
        None,
        now_ms,
    )
    .await?;
    let signal = ExitMpquicSessionSignal::new(
        ready.reservation_id,
        ready.route_context_id,
        ready.exit_native_instance_id,
        ready.path_ids,
    )
    .map_err(|_| ProductionMpquicError::Invalid("MPQUIC Exit readiness signal"))?;
    Ok((active, signal))
}

/// Start one native MASQUE CONNECT-IP Exit association over exactly one committed Relay.
#[allow(
    clippy::too_many_arguments,
    reason = "single-path native Exit activation is affine"
)]
pub(crate) async fn start_production_single_path_udp_exit(
    preflight: ProductionMpquicExitPreflight,
    helper: HelperClient,
    owner: RuntimeBoundPreparedLeaseBatch,
    commit: CommitLeaseBatch,
    credential: ExitNativeRouteCredentialAuthorization,
    path: ExitMpquicPathAuthorization,
    verified_path: VerifiedSingleRelayPath,
    policy: VerifiedManifest,
    signed_policy_hash: [u8; 32],
    flow_idle_timeout: Duration,
    certificate_der: Vec<u8>,
    now_ms: u64,
) -> Result<(ActiveProductionMpquicExitRoute, UdpExitSessionSignal), ProductionMpquicError> {
    let path_id = path.path_id;
    let (active, ready) = start_production_native_exit(
        preflight,
        helper,
        owner,
        commit,
        credential,
        vec![path],
        policy,
        signed_policy_hash,
        flow_idle_timeout,
        TransportMode::SinglePathGeneralUdp,
        Some(verified_path),
        now_ms,
    )
    .await?;
    let signal = UdpExitSessionSignal::new(
        ready.reservation_id,
        ready.route_context_id,
        path_id,
        certificate_der,
        ready.exit_native_instance_id,
    )
    .map_err(|_| ProductionMpquicError::Invalid("native UDP Exit readiness signal"))?;
    Ok((active, signal))
}

struct NativeExitReady {
    reservation_id: [u8; 16],
    route_context_id: [u8; 16],
    exit_native_instance_id: [u8; 32],
    path_ids: Vec<u32>,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one fail-closed helper-to-native Exit transaction"
)]
async fn start_production_native_exit(
    preflight: ProductionMpquicExitPreflight,
    helper: HelperClient,
    mut owner: RuntimeBoundPreparedLeaseBatch,
    commit: CommitLeaseBatch,
    credential: ExitNativeRouteCredentialAuthorization,
    paths: Vec<ExitMpquicPathAuthorization>,
    policy: VerifiedManifest,
    signed_policy_hash: [u8; 32],
    flow_idle_timeout: Duration,
    transport_mode: TransportMode,
    single_path_udp: Option<VerifiedSingleRelayPath>,
    now_ms: u64,
) -> Result<(ActiveProductionMpquicExitRoute, NativeExitReady), ProductionMpquicError> {
    let authorization = match NativeExitAuthorizationParts::from_credential(credential) {
        Ok(authorization) => authorization,
        Err(error) => {
            let _ = helper.destroy_context(&owner).await;
            return Err(error);
        }
    };
    let route_context_id = authorization.route_context_id;
    let context_handle = owner.prepared().context_handle.as_slice().try_into();
    let Ok(context_handle): Result<[u8; HELPER_HANDLE_BYTES], _> = context_handle else {
        let _ = helper.destroy_context(&owner).await;
        return Err(ProductionMpquicError::Invalid("MPQUIC helper context"));
    };
    let mut path_ids = paths.iter().map(|path| path.path_id).collect::<Vec<_>>();
    path_ids.sort_unstable();
    let valid_cardinality = match transport_mode {
        TransportMode::MultipathQuic => {
            (MINIMUM_MULTIPATH_PATHS..=MAXIMUM_MULTIPATH_PATHS).contains(&paths.len())
                && single_path_udp.is_none()
        }
        TransportMode::SinglePathGeneralUdp => {
            paths.len() == 1
                && single_path_udp.as_ref().is_some_and(|path| {
                    path.route_context_id() == &route_context_id
                        && path.path_id() == paths[0].path_id
                })
        }
        TransportMode::Unspecified => false,
    };
    let exact_paths = valid_cardinality
        && path_ids.windows(2).all(|pair| pair[0] < pair[1])
        && paths
            .iter()
            .map(|path| path.path_id)
            .eq(path_ids.iter().copied())
        && owner.prepare().leases.len() == paths.len()
        && owner
            .prepare()
            .leases
            .iter()
            .zip(&path_ids)
            .all(|(lease, path_id)| {
                lease.path_id == *path_id && lease.role == WireguardRole::Exit as i32
            });
    if authorization.expires_at_ms <= now_ms
        || policy.ensure_active_at(now_ms).is_err()
        || policy.policy_hash() != &signed_policy_hash
        || flow_idle_timeout.is_zero()
        || flow_idle_timeout > MAXIMUM_EXIT_FLOW_IDLE
        || preflight.native_instance_id != authorization.exit_native_instance_id
        || ContextRole::try_from(owner.prepare().role).ok() != Some(ContextRole::Exit)
        || owner.prepare().route_context_id != route_context_id
        || !exact_paths
        || commit.route_context_id != route_context_id
        || commit.context_handle.as_slice() != context_handle
        || commit.leases.len() != paths.len()
        || !commit.leases.iter().zip(&path_ids).all(|(lease, path_id)| {
            lease.path_id == *path_id && lease.role == WireguardRole::Exit as i32
        })
    {
        let _ = helper.destroy_context(&owner).await;
        return Err(ProductionMpquicError::Invalid(
            "committed MPQUIC Exit route scope",
        ));
    }
    if helper.commit_lease_batch(&mut owner, commit).await.is_err() {
        let _ = helper.destroy_context(&owner).await;
        return Err(ProductionMpquicError::Invalid(
            "committed MPQUIC Exit helper route",
        ));
    }
    let mut listeners = Vec::with_capacity(paths.len());
    for path in &paths {
        let Ok(path_number) = u8::try_from(path.path_id) else {
            let _ = helper.destroy_context(&owner).await;
            return Err(ProductionMpquicError::Invalid("MPQUIC Exit path id"));
        };
        let Ok(addresses) = overlay_addresses(route_context_id, path_number) else {
            let _ = helper.destroy_context(&owner).await;
            return Err(ProductionMpquicError::Invalid("MPQUIC Exit overlay"));
        };
        let acquired = helper
            .acquire_transport_socket(AcquireTransportSocket {
                route_context_id: route_context_id.to_vec(),
                context_handle: context_handle.to_vec(),
                path_id: path.path_id,
                role: WireguardRole::Exit as i32,
                descriptor_kind: TransportSocketKind::QuicUdpUnconnected as i32,
                expected_local: Some(TransportSocketAddress {
                    address: addresses.exit.octets().to_vec(),
                    port: u32::from(MPQUIC_EXIT_LISTENER_PORT),
                }),
                expected_remote: None,
            })
            .await;
        let acquired = match acquired {
            Ok(acquired) => acquired,
            Err(error) => {
                let _ = helper.destroy_context(&owner).await;
                return Err(ProductionMpquicError::Helper(error));
            }
        };
        let listener =
            CommittedMpquicExitListener::from_helper_handoff(acquired, route_context_id, path);
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                let _ = helper.destroy_context(&owner).await;
                return Err(error);
            }
        };
        listeners.push(listener);
    }
    let client = preflight.client;
    if let Err(error) =
        start_native_exit_listener_set(&client, &authorization, listeners, transport_mode).await
    {
        let _ = client
            .stop_session(StopSession {
                route_context_id: route_context_id.to_vec(),
            })
            .await;
        let _ = helper.destroy_context(&owner).await;
        return Err(error);
    }
    let ready = NativeExitReady {
        reservation_id: authorization.reservation_id,
        route_context_id,
        exit_native_instance_id: authorization.exit_native_instance_id,
        path_ids,
    };
    Ok((
        ActiveProductionMpquicExitRoute {
            client,
            helper,
            owner,
            route_context_id,
            masque_context_id: authorization.masque_context_id,
            expires_at_ms: authorization.expires_at_ms,
            policy,
            flow_idle_timeout,
            client_session_id: authorization.client_session_id,
            transport_mode,
            single_path_udp,
        },
        ready,
    ))
}

async fn start_native_exit_listener_set(
    client: &NativeClient,
    authorization: &NativeExitAuthorizationParts,
    listeners: Vec<CommittedMpquicExitListener>,
    transport_mode: TransportMode,
) -> Result<(), ProductionMpquicError> {
    let minimum_paths = u32::try_from(listeners.len())
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC Exit path count"))?;
    let cardinality_matches = match transport_mode {
        TransportMode::MultipathQuic => {
            (MINIMUM_MULTIPATH_PATHS..=MAXIMUM_MULTIPATH_PATHS).contains(&listeners.len())
        }
        TransportMode::SinglePathGeneralUdp => listeners.len() == 1,
        TransportMode::Unspecified => false,
    };
    if !cardinality_matches {
        return Err(ProductionMpquicError::Invalid("MPQUIC Exit path count"));
    }
    let last = listeners.len() - 1;
    for (index, listener) in listeners.into_iter().enumerate() {
        let endpoint = client
            .start_exit_session(
                StartExitSession {
                    route_context_id: authorization.route_context_id.to_vec(),
                    auth_secret: authorization.auth_bearer.to_vec(),
                    expires_at_ms: authorization.expires_at_ms,
                    minimum_paths,
                    masque_context_id: authorization.masque_context_id,
                    transport_mode: transport_mode as i32,
                    exit_spki_sha256: authorization.spki_sha256.to_vec(),
                    tls_server_name: authorization.tls_server_name.clone(),
                    path_id: listener.path_id,
                    listener_ip: listener.listener_ip.to_vec(),
                    listener_port: u32::from(MPQUIC_EXIT_LISTENER_PORT),
                    expected_client_ip: listener.expected_client_ip.to_vec(),
                    expected_client_port: u32::from(mpquic_client_port(listener.path_id)?),
                    reservation_hash: listener.reservation_hash.to_vec(),
                    tls_certificate_pem: authorization.tls_certificate_pem.to_vec(),
                    tls_private_key_pem: authorization.tls_private_key_pem.to_vec(),
                    reservation_id: authorization.reservation_id.to_vec(),
                    finalize_id: authorization.finalize_id.to_vec(),
                    auth_commitment: authorization.auth_commitment.to_vec(),
                    certificate_sha256: authorization.certificate_sha256.to_vec(),
                    client_native_instance_id: authorization.client_native_instance_id.to_vec(),
                    exit_native_instance_id: authorization.exit_native_instance_id.to_vec(),
                },
                listener.descriptor,
            )
            .await?;
        if endpoint.listener_set_ready() != (index == last) {
            return Err(if endpoint.listener_set_ready() {
                ProductionMpquicError::UnexpectedReady
            } else {
                ProductionMpquicError::ReadyTimeout
            });
        }
    }
    Ok(())
}

/// Affine preflight of the exact native Client process incarnation signed into reservations.
#[must_use = "native process preflight authority must be consumed by one route"]
pub struct ProductionMpquicPreflight {
    client: NativeClient,
    native_instance_id: [u8; 32],
}

impl ProductionMpquicPreflight {
    /// Preflight one native process before Exit finalization signs its incarnation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the socket names a live native Client process.
    pub async fn new(client: NativeClient) -> Result<Self, ProductionMpquicError> {
        let client = client.preflight(NativeProcessRole::Client).await?;
        let native_instance_id =
            *client
                .native_instance_id()
                .ok_or(ProductionMpquicError::Invalid(
                    "preflighted native Client instance",
                ))?;
        Ok(Self {
            client,
            native_instance_id,
        })
    }

    /// Exact process incarnation that route admission must pass into Exit finalization.
    #[must_use]
    pub const fn native_instance_id(&self) -> &[u8; 32] {
        &self.native_instance_id
    }

    /// Acquire every exact committed Client path FD and start one genuine MPQUIC association.
    ///
    /// The helper descriptors bind only path-specific Client overlay addresses. Their remote
    /// targets are the derived Exit overlay addresses behind distinct Relay `WireGuard` paths; no
    /// underlay Exit address or ordinary-QUIC fallback enters this call.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signal, authorization, distinct Relay set, helper context and
    /// every acquired socket describe the same complete 2--8 path association.
    #[allow(
        clippy::too_many_arguments,
        reason = "the affine route activation requires every exact signed and helper-owned input"
    )]
    pub async fn establish_committed(
        self,
        helper: &HelperClient,
        context_handle: [u8; HELPER_HANDLE_BYTES],
        authorization: ClientNativeRouteAuthorization,
        grants: &[VerifiedRelayGrant],
        active_path_ids: &[u32],
        minimum_paths: usize,
        signal: &ExitMpquicSessionSignal,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<ProductionMpquicSession, ProductionMpquicError> {
        validate_committed_signal(&self, &authorization, grants, signal, now_ms)?;
        let active_ids = active_path_ids.iter().copied().collect::<BTreeSet<_>>();
        if active_ids.len() != active_path_ids.len()
            || !(MINIMUM_MULTIPATH_PATHS..=active_ids.len()).contains(&minimum_paths)
            || active_ids
                .iter()
                .any(|path_id| !grants.iter().any(|grant| grant.path_id() == *path_id))
        {
            return Err(ProductionMpquicError::Invalid(
                "MPQUIC active and minimum path set",
            ));
        }
        let mut active_paths = Vec::with_capacity(active_ids.len());
        let mut warm_paths = Vec::with_capacity(grants.len().saturating_sub(active_ids.len()));
        for grant in grants {
            let request = committed_client_socket_request(context_handle, grant)?;
            let acquired = helper.acquire_transport_socket(request).await?;
            let path =
                CommittedMpquicPath::from_authenticated_exit_signal(acquired, grant, signal)?;
            if active_ids.contains(&path.path_id()) {
                active_paths.push(path);
            } else {
                warm_paths.push(path);
            }
        }
        ProductionMpquicSession::establish_preflighted_with_backups(
            self,
            authorization,
            active_paths,
            warm_paths,
            minimum_paths,
            now_ms,
            ready_wait,
        )
        .await
    }

    /// Acquire and start one native general-UDP CONNECT-IP association over exactly one Relay.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signal, authorization, helper socket and sole Relay grant all
    /// describe the same live route, or native cannot make that one path ready.
    #[allow(
        clippy::too_many_arguments,
        reason = "the signed one-path scope stays explicit"
    )]
    pub async fn establish_single_path_udp(
        self,
        helper: &HelperClient,
        context_handle: [u8; HELPER_HANDLE_BYTES],
        authorization: ClientNativeRouteAuthorization,
        grant: &VerifiedRelayGrant,
        signal: &UdpExitSessionSignal,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<ProductionMpquicSession, ProductionMpquicError> {
        signal
            .validate()
            .map_err(|_| ProductionMpquicError::Invalid("native UDP Exit signal"))?;
        let identity = authorization.native_route_identity();
        if now_ms >= authorization.expires_at_ms()
            || signal.reservation_id() != authorization.reservation_id()
            || signal.route_context_id() != authorization.route_context_id()
            || signal.path_id() != grant.path_id()
            || signal.exit_native_instance_id() != identity.exit_native_instance_id
            || self.native_instance_id().as_slice() != identity.client_native_instance_id
            || grant.reservation_id() != authorization.reservation_id()
            || grant.route_context_id() != authorization.route_context_id()
        {
            return Err(ProductionMpquicError::Invalid(
                "native UDP committed Exit signal",
            ));
        }
        let request = committed_client_socket_request(context_handle, grant)?;
        let acquired = helper.acquire_transport_socket(request).await?;
        let path =
            CommittedMpquicPath::from_authenticated_udp_exit_signal(acquired, grant, signal)?;
        ProductionMpquicSession::establish_preflighted_mode(
            self,
            authorization,
            vec![path],
            TransportMode::SinglePathGeneralUdp,
            now_ms,
            ready_wait,
        )
        .await
    }
}

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
    const fn path_id(&self) -> u32 {
        self.add.path_id
    }

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

    /// Bind one helper-correlated Client descriptor to an authenticated complete Exit signal.
    ///
    /// Unlike [`Self::from_helper_handoff`], this constructor consumes only remote wire evidence:
    /// all socket tuples are therefore derived locally from the verified Relay grant and fixed
    /// MPQUIC port contract rather than copied from the signal.
    fn from_authenticated_exit_signal(
        acquired: AcquiredTransportSocket,
        grant: &VerifiedRelayGrant,
        signal: &ExitMpquicSessionSignal,
    ) -> Result<Self, ProductionMpquicError> {
        let (descriptor, metadata) = acquired.into_parts();
        let path_id = u8::try_from(grant.path_id())
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC path id"))?;
        let addresses = overlay_addresses(*grant.route_context_id(), path_id)
            .map_err(|_| ProductionMpquicError::Invalid("MPQUIC overlay"))?;
        let local_port = mpquic_client_port(grant.path_id())?;
        let local = transport_address(metadata.local.as_ref().ok_or(
            ProductionMpquicError::Invalid("committed MPQUIC local address"),
        )?)?;
        if metadata.path_id != grant.path_id()
            || WireguardRole::try_from(metadata.role).ok() != Some(WireguardRole::Client)
            || TransportSocketKind::try_from(metadata.descriptor_kind).ok()
                != Some(TransportSocketKind::QuicUdpUnconnected)
            || metadata.remote.is_some()
            || local != SocketAddr::new(IpAddr::V6(addresses.client), local_port)
            || signal.route_context_id() != grant.route_context_id()
            || !signal.selected_path_ids().contains(&grant.path_id())
        {
            return Err(ProductionMpquicError::Invalid(
                "authenticated committed MPQUIC path",
            ));
        }
        let exit_native_instance_id = signal
            .exit_native_instance_id()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("Exit native instance"))?;
        Ok(Self {
            descriptor,
            add: AddPath {
                route_context_id: grant.route_context_id().to_vec(),
                path_id: grant.path_id(),
                local_ip: addresses.client.octets().to_vec(),
                remote_ip: addresses.exit.octets().to_vec(),
                remote_port: u32::from(MPQUIC_EXIT_LISTENER_PORT),
                reservation_hash: Sha256::digest(grant.signed_relay_reservation()).to_vec(),
                local_port: u32::from(local_port),
            },
            reservation_id: *grant.reservation_id(),
            relay_node_id: *grant.relay_node_id(),
            exit_native_instance_id,
            expires_at_ms: grant.expires_at_ms(),
            listener_set_ready: true,
        })
    }

    fn from_authenticated_udp_exit_signal(
        acquired: AcquiredTransportSocket,
        grant: &VerifiedRelayGrant,
        signal: &UdpExitSessionSignal,
    ) -> Result<Self, ProductionMpquicError> {
        let (descriptor, metadata) = acquired.into_parts();
        let path_id = u8::try_from(grant.path_id())
            .map_err(|_| ProductionMpquicError::Invalid("native UDP path id"))?;
        let addresses = overlay_addresses(*grant.route_context_id(), path_id)
            .map_err(|_| ProductionMpquicError::Invalid("native UDP overlay"))?;
        let local_port = mpquic_client_port(grant.path_id())?;
        let local = transport_address(
            metadata
                .local
                .as_ref()
                .ok_or(ProductionMpquicError::Invalid("native UDP local address"))?,
        )?;
        if metadata.path_id != grant.path_id()
            || WireguardRole::try_from(metadata.role).ok() != Some(WireguardRole::Client)
            || TransportSocketKind::try_from(metadata.descriptor_kind).ok()
                != Some(TransportSocketKind::QuicUdpUnconnected)
            || metadata.remote.is_some()
            || local != SocketAddr::new(IpAddr::V6(addresses.client), local_port)
            || signal.route_context_id() != grant.route_context_id()
            || signal.path_id() != grant.path_id()
        {
            return Err(ProductionMpquicError::Invalid(
                "authenticated committed native UDP path",
            ));
        }
        let exit_native_instance_id = signal
            .exit_native_instance_id()
            .try_into()
            .map_err(|_| ProductionMpquicError::Invalid("Exit native instance"))?;
        Ok(Self {
            descriptor,
            add: AddPath {
                route_context_id: grant.route_context_id().to_vec(),
                path_id: grant.path_id(),
                local_ip: addresses.client.octets().to_vec(),
                remote_ip: addresses.exit.octets().to_vec(),
                remote_port: u32::from(MPQUIC_EXIT_LISTENER_PORT),
                reservation_hash: Sha256::digest(grant.signed_relay_reservation()).to_vec(),
                local_port: u32::from(local_port),
            },
            reservation_id: *grant.reservation_id(),
            relay_node_id: *grant.relay_node_id(),
            exit_native_instance_id,
            expires_at_ms: grant.expires_at_ms(),
            listener_set_ready: true,
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
    warm_paths: BTreeMap<u32, CommittedMpquicPath>,
    minimum_paths: usize,
    assignment: TunnelAssignment,
    transport_mode: TransportMode,
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
        let preflight = ProductionMpquicPreflight::new(client).await?;
        Self::establish_preflighted(preflight, authorization, paths, now_ms, ready_wait).await
    }

    /// Establish using the exact preflight authority previously signed by the Exit.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signed Client incarnation and complete committed path set bind
    /// to this still-live preflight.
    pub async fn establish_preflighted(
        preflight: ProductionMpquicPreflight,
        authorization: ClientNativeRouteAuthorization,
        paths: Vec<CommittedMpquicPath>,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<Self, ProductionMpquicError> {
        let minimum_paths = paths.len();
        Self::establish_preflighted_with_backups(
            preflight,
            authorization,
            paths,
            Vec::new(),
            minimum_paths,
            now_ms,
            ready_wait,
        )
        .await
    }

    async fn establish_preflighted_with_backups(
        preflight: ProductionMpquicPreflight,
        authorization: ClientNativeRouteAuthorization,
        active_paths: Vec<CommittedMpquicPath>,
        warm_paths: Vec<CommittedMpquicPath>,
        minimum_paths: usize,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<Self, ProductionMpquicError> {
        Self::establish_preflighted_with_backups_mode(
            preflight,
            authorization,
            active_paths,
            warm_paths,
            minimum_paths,
            TransportMode::MultipathQuic,
            now_ms,
            ready_wait,
        )
        .await
    }

    async fn establish_preflighted_mode(
        preflight: ProductionMpquicPreflight,
        authorization: ClientNativeRouteAuthorization,
        paths: Vec<CommittedMpquicPath>,
        transport_mode: TransportMode,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<Self, ProductionMpquicError> {
        let minimum_paths = paths.len();
        Self::establish_preflighted_with_backups_mode(
            preflight,
            authorization,
            paths,
            Vec::new(),
            minimum_paths,
            transport_mode,
            now_ms,
            ready_wait,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "native path ownership stays explicit"
    )]
    async fn establish_preflighted_with_backups_mode(
        preflight: ProductionMpquicPreflight,
        authorization: ClientNativeRouteAuthorization,
        active_paths: Vec<CommittedMpquicPath>,
        warm_paths: Vec<CommittedMpquicPath>,
        minimum_paths: usize,
        transport_mode: TransportMode,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<Self, ProductionMpquicError> {
        if ready_wait.is_zero() || ready_wait > MAXIMUM_READY_WAIT {
            return Err(ProductionMpquicError::Invalid("MPQUIC ready wait"));
        }
        let ProductionMpquicPreflight {
            client,
            native_instance_id,
        } = preflight;
        let expected_instance = authorization
            .native_route_identity()
            .client_native_instance_id
            .as_slice();
        if native_instance_id.as_slice() != expected_instance {
            return Err(ProductionMpquicError::Invalid(
                "authorized native Client instance",
            ));
        }
        let cardinality_matches = match transport_mode {
            TransportMode::MultipathQuic => {
                (MINIMUM_MULTIPATH_PATHS..=active_paths.len()).contains(&minimum_paths)
                    && active_paths.len().saturating_add(warm_paths.len())
                        <= MAXIMUM_MULTIPATH_PATHS
            }
            TransportMode::SinglePathGeneralUdp => {
                minimum_paths == 1 && active_paths.len() == 1 && warm_paths.is_empty()
            }
            TransportMode::Unspecified => false,
        };
        if !cardinality_matches {
            return Err(ProductionMpquicError::Invalid(
                "MPQUIC active and minimum path cardinality",
            ));
        }
        let start = start_request(&authorization, minimum_paths, transport_mode, now_ms)?;
        let path_ids = validate_complete_path_set(&start, &active_paths, now_ms)?;
        let mut all_ids = path_ids.iter().copied().collect::<BTreeSet<_>>();
        let mut relay_ids = active_paths
            .iter()
            .map(|path| path.relay_node_id)
            .collect::<BTreeSet<_>>();
        if relay_ids.len() != active_paths.len() {
            return Err(ProductionMpquicError::Invalid(
                "distinct active MPQUIC Relays",
            ));
        }
        let mut warm_by_id = BTreeMap::new();
        for path in warm_paths {
            validate_committed_path(&start, &path, now_ms)?;
            let path_id = path.path_id();
            if !all_ids.insert(path_id)
                || !relay_ids.insert(path.relay_node_id)
                || warm_by_id.insert(path_id, path).is_some()
            {
                return Err(ProductionMpquicError::Invalid("distinct warm MPQUIC paths"));
            }
        }
        let assignment = setup_native_session(&client, &start, active_paths, ready_wait).await?;
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
            warm_paths: warm_by_id,
            minimum_paths,
            assignment,
            transport_mode,
        })
    }

    /// Borrow the path IDs which were required before the native tunnel became ready.
    #[must_use]
    pub fn active_path_ids(&self) -> &[u32] {
        &self.active_path_ids
    }

    /// Borrow the already authorized helper-owned paths retained outside ordinary scheduling.
    pub(crate) fn warm_path_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.warm_paths.keys().copied()
    }

    /// Required path count below which this association must fail closed.
    #[must_use]
    pub(crate) const fn minimum_paths(&self) -> usize {
        self.minimum_paths
    }

    /// Read one exact live native status snapshot for the committed path set.
    ///
    /// The native process owns path-level transport observation. Rust accepts the snapshot only
    /// when it contains every committed path exactly once and no uncommitted path.
    pub(crate) async fn path_statuses(
        &self,
    ) -> Result<Vec<NativePathStatus>, ProductionMpquicError> {
        let mut statuses = self
            .client
            .status(GetStatus {
                route_context_id: self.route_context_id.to_vec(),
            })
            .await?;
        statuses.sort_unstable_by_key(|status| status.path_id);
        if statuses.len() != self.active_path_ids.len()
            || !statuses
                .iter()
                .map(|status| status.path_id)
                .eq(self.active_path_ids.iter().copied())
        {
            return Err(ProductionMpquicError::Invalid(
                "exact native MPQUIC status path set",
            ));
        }
        Ok(statuses)
    }

    /// Replace one unhealthy active path with an already selected warm path.
    ///
    /// The warm descriptor was acquired from the same committed helper context and is bound to
    /// an already confirmed Relay grant and Exit listener. It is added before the unhealthy path
    /// is removed, so the native association never deliberately crosses below its hard minimum.
    pub(crate) async fn replace_active_path(
        &mut self,
        unhealthy_path_id: u32,
        warm_path_id: u32,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<(), ProductionMpquicError> {
        validate_reconfiguration_wait(ready_wait)?;
        if self.transport_mode != TransportMode::MultipathQuic
            || !self.active_path_ids.contains(&unhealthy_path_id)
            || self.active_path_ids.contains(&warm_path_id)
        {
            return Err(ProductionMpquicError::Invalid(
                "MPQUIC replacement path state",
            ));
        }
        let start = start_request(
            &self.authorization,
            self.minimum_paths,
            self.transport_mode,
            now_ms,
        )?;
        let warm = self
            .warm_paths
            .remove(&warm_path_id)
            .ok_or(ProductionMpquicError::Invalid(
                "MPQUIC warm replacement path",
            ))?;
        validate_committed_path(&start, &warm, now_ms)?;
        self.client.add_path(warm.add, warm.descriptor).await?;
        self.client
            .remove_path(RemovePath {
                route_context_id: self.route_context_id.to_vec(),
                path_id: unhealthy_path_id,
            })
            .await?;
        self.assignment = await_reconfigured_session(&self.client, &start, ready_wait).await?;
        self.active_path_ids
            .retain(|path_id| *path_id != unhealthy_path_id);
        self.active_path_ids.push(warm_path_id);
        self.active_path_ids.sort_unstable();
        Ok(())
    }

    /// Remove an unhealthy path when the remaining active set still satisfies the signed hard
    /// minimum. This never weakens the native session's immutable minimum-path contract.
    pub(crate) async fn remove_active_path(
        &mut self,
        unhealthy_path_id: u32,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<(), ProductionMpquicError> {
        validate_reconfiguration_wait(ready_wait)?;
        if self.transport_mode != TransportMode::MultipathQuic
            || !self.active_path_ids.contains(&unhealthy_path_id)
            || self.active_path_ids.len().saturating_sub(1) < self.minimum_paths
        {
            return Err(ProductionMpquicError::Invalid(
                "MPQUIC minimum path removal",
            ));
        }
        let start = start_request(
            &self.authorization,
            self.minimum_paths,
            self.transport_mode,
            now_ms,
        )?;
        self.client
            .remove_path(RemovePath {
                route_context_id: self.route_context_id.to_vec(),
                path_id: unhealthy_path_id,
            })
            .await?;
        self.assignment = await_reconfigured_session(&self.client, &start, ready_wait).await?;
        self.active_path_ids
            .retain(|path_id| *path_id != unhealthy_path_id);
        Ok(())
    }

    /// Borrow the native CONNECT-IP tunnel assignment.
    #[must_use]
    pub const fn assignment(&self) -> &TunnelAssignment {
        &self.assignment
    }

    /// Submit one browser-QUIC datagram pinned to its signed policy destination.
    ///
    /// # Errors
    ///
    /// Returns an error when the flow expired, belongs to another route, the packet is not one
    /// complete UDP datagram to its exact signed tuple, or native cannot send it.
    pub async fn send_browser_quic(
        &self,
        flow: &AuthorizedUdpFlow,
        packet: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), ProductionMpquicError> {
        validate_browser_quic_packet(flow, self.route_context_id, &packet, now_ms, true)?;
        send_inner_ip(
            &self.client,
            self.route_context_id,
            self.masque_context_id,
            packet,
        )
        .await
    }

    /// Send one client-signed hostname/original-destination binding before browser data.
    ///
    /// The frame remains inside the authenticated CONNECT-IP tunnel and targets only its fixed
    /// server address. The Exit consumes it as control data; it is never emitted as Internet UDP.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or mismatched flow, an invalid application port or control
    /// frame, an unexpected native assignment, or failure to submit the protected inner packet.
    pub async fn authorize_browser_quic(
        &self,
        flow: &AuthorizedUdpFlow,
        application_port: u16,
        signed_authorization: &[u8],
        now_ms: u64,
    ) -> Result<(), ProductionMpquicError> {
        flow.ensure_active_at(now_ms)?;
        if flow.route_context_id() != &self.route_context_id
            || flow.port() != BROWSER_QUIC_PORT
            || flow.hostname().is_none()
            || application_port == 0
            || signed_authorization.is_empty()
            || signed_authorization.len() > MAXIMUM_EXIT_UDP_PAYLOAD_BYTES
        {
            return Err(ProductionMpquicError::Invalid(
                "browser QUIC hostname authorization",
            ));
        }
        let source_ip = assignment_ipv4(&self.assignment.assigned_ipv4)?;
        let server_ip = assignment_ipv4(&self.assignment.server_ipv4)?;
        if server_ip != TUNNEL_SERVER_IPV4 {
            return Err(ProductionMpquicError::Invalid(
                "browser QUIC authorization tunnel server",
            ));
        }
        let packet = build_ipv4_udp(
            SocketAddrV4::new(source_ip, application_port),
            SocketAddrV4::new(server_ip, BROWSER_QUIC_AUTHORIZATION_PORT),
            signed_authorization,
            0,
        )?;
        send_inner_ip(
            &self.client,
            self.route_context_id,
            self.masque_context_id,
            packet,
        )
        .await
    }

    /// Poll one reverse browser-QUIC datagram and bind it to one exact retained flow.
    ///
    /// # Errors
    ///
    /// Returns an error when native cannot poll the association or a returned datagram is not a
    /// complete UDP datagram. A well-formed packet outside every retained signed tuple is dropped.
    pub async fn receive_browser_quic<'a>(
        &self,
        flows: impl IntoIterator<Item = (&'a AuthorizedUdpFlow, SocketAddrV4)>,
        now_ms: u64,
    ) -> Result<Option<(usize, Vec<u8>)>, ProductionMpquicError> {
        if self.transport_mode != TransportMode::MultipathQuic {
            return Err(ProductionMpquicError::Invalid(
                "browser QUIC transport mode",
            ));
        }
        let packet =
            receive_inner_ip(&self.client, self.route_context_id, self.masque_context_id).await?;
        let Some(packet) = packet else {
            return Ok(None);
        };
        matching_browser_quic_response_flow(flows, self.route_context_id, &packet, now_ms)
            .map(|index| index.map(|index| (index, packet)))
    }

    /// Submit one policy-signed general-UDP flow over native single-path CONNECT-IP.
    ///
    /// The first datagram carries its signed exact-destination authorization as a separate
    /// tunnel-internal control packet. The following packet is an ordinary inner IPv4/UDP
    /// datagram; neither packet is a fallback transport frame.
    ///
    /// # Errors
    ///
    /// Returns an error for another transport mode, an invalid/expired destination binding, an
    /// oversized inner packet, or a rejected native send.
    #[allow(
        clippy::too_many_arguments,
        reason = "the transparent and tunnel tuples stay explicit"
    )]
    pub async fn send_general_udp(
        &self,
        flow: &AuthorizedUdpFlow,
        signed_authorization: Option<&[u8]>,
        application_port: u16,
        destination: SocketAddrV4,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), ProductionMpquicError> {
        if self.transport_mode != TransportMode::SinglePathGeneralUdp
            || application_port == 0
            || !flow.matches_exact_ip_destination(SocketAddr::V4(destination))
        {
            return Err(ProductionMpquicError::Invalid(
                "native general UDP exact destination",
            ));
        }
        flow.ensure_active_at(now_ms)?;
        if flow.route_context_id() != &self.route_context_id {
            return Err(ProductionMpquicError::Invalid(
                "native general UDP route context",
            ));
        }
        let (client, server, maximum_packet_bytes) = tunnel_ipv4_scope(&self.assignment)?;
        let source = SocketAddrV4::new(client, application_port);
        if let Some(signed) = signed_authorization {
            let control = build_general_udp_authorization_packet(
                source,
                server,
                destination,
                signed,
                maximum_packet_bytes,
            )?;
            send_inner_ip(
                &self.client,
                self.route_context_id,
                self.masque_context_id,
                control,
            )
            .await?;
        }
        let packet = build_ipv4_udp_packet(source, destination, payload, maximum_packet_bytes)?;
        send_inner_ip(
            &self.client,
            self.route_context_id,
            self.masque_context_id,
            packet,
        )
        .await
    }

    /// Poll and validate one native reverse packet for the same signed UDP destination.
    ///
    /// # Errors
    ///
    /// Returns an error for another transport mode, an invalid/expired flow or reverse tuple, or
    /// a failed native receive.
    pub async fn receive_general_udp(
        &self,
        flow: &AuthorizedUdpFlow,
        application_port: u16,
        destination: SocketAddrV4,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, ProductionMpquicError> {
        if self.transport_mode != TransportMode::SinglePathGeneralUdp {
            return Err(ProductionMpquicError::Invalid("native general UDP mode"));
        }
        flow.ensure_active_at(now_ms)?;
        if flow.route_context_id() != &self.route_context_id
            || !flow.matches_exact_ip_destination(SocketAddr::V4(destination))
        {
            return Err(ProductionMpquicError::Invalid(
                "native general UDP response scope",
            ));
        }
        let (client, _, _) = tunnel_ipv4_scope(&self.assignment)?;
        let packet =
            receive_inner_ip(&self.client, self.route_context_id, self.masque_context_id).await?;
        if let Some(packet) = packet.as_deref() {
            let (source, target) = udp_packet_tuple(packet)?;
            if source != SocketAddr::V4(destination)
                || target != SocketAddr::V4(SocketAddrV4::new(client, application_port))
            {
                return Err(ProductionMpquicError::Invalid(
                    "native general UDP reverse tuple",
                ));
            }
        }
        Ok(packet)
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

fn validate_reconfiguration_wait(ready_wait: Duration) -> Result<(), ProductionMpquicError> {
    if ready_wait.is_zero() || ready_wait > MAXIMUM_READY_WAIT {
        return Err(ProductionMpquicError::Invalid("MPQUIC ready wait"));
    }
    Ok(())
}

async fn await_reconfigured_session(
    client: &NativeClient,
    start: &StartSession,
    ready_wait: Duration,
) -> Result<TunnelAssignment, ProductionMpquicError> {
    let deadline = Instant::now() + ready_wait;
    loop {
        match MultipathNativeControl::start(client, start.clone()).await? {
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

fn validate_committed_signal(
    preflight: &ProductionMpquicPreflight,
    authorization: &ClientNativeRouteAuthorization,
    grants: &[VerifiedRelayGrant],
    signal: &ExitMpquicSessionSignal,
    now_ms: u64,
) -> Result<(), ProductionMpquicError> {
    signal
        .validate()
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC Exit signal"))?;
    let identity = authorization.native_route_identity();
    if now_ms >= authorization.expires_at_ms()
        || signal.reservation_id() != authorization.reservation_id()
        || signal.route_context_id() != authorization.route_context_id()
        || signal.exit_native_instance_id() != identity.exit_native_instance_id
        || preflight.native_instance_id().as_slice() != identity.client_native_instance_id
        || grants.len() != signal.selected_path_ids().len()
        || !(MINIMUM_MULTIPATH_PATHS..=MAXIMUM_MULTIPATH_PATHS).contains(&grants.len())
    {
        return Err(ProductionMpquicError::Invalid(
            "MPQUIC complete Exit signal",
        ));
    }
    for (grant, signalled_path_id) in grants.iter().zip(signal.selected_path_ids()) {
        if grant.path_id() != *signalled_path_id
            || grant.reservation_id() != authorization.reservation_id()
            || grant.route_context_id() != authorization.route_context_id()
            || grant.expires_at_ms() <= now_ms
        {
            return Err(ProductionMpquicError::Invalid(
                "MPQUIC exact committed Relay set",
            ));
        }
    }
    Ok(())
}

fn committed_client_socket_request(
    context_handle: [u8; HELPER_HANDLE_BYTES],
    grant: &VerifiedRelayGrant,
) -> Result<AcquireTransportSocket, ProductionMpquicError> {
    if context_handle == [0; HELPER_HANDLE_BYTES] {
        return Err(ProductionMpquicError::Invalid("MPQUIC helper context"));
    }
    let path_id = u8::try_from(grant.path_id())
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC path id"))?;
    let addresses = overlay_addresses(*grant.route_context_id(), path_id)
        .map_err(|_| ProductionMpquicError::Invalid("MPQUIC overlay"))?;
    Ok(AcquireTransportSocket {
        route_context_id: grant.route_context_id().to_vec(),
        context_handle: context_handle.to_vec(),
        path_id: grant.path_id(),
        role: WireguardRole::Client as i32,
        descriptor_kind: TransportSocketKind::QuicUdpUnconnected as i32,
        expected_local: Some(TransportSocketAddress {
            address: addresses.client.octets().to_vec(),
            port: u32::from(mpquic_client_port(grant.path_id())?),
        }),
        expected_remote: None,
    })
}

fn mpquic_client_port(path_id: u32) -> Result<u16, ProductionMpquicError> {
    let path = u16::try_from(path_id)
        .ok()
        .filter(|path| {
            (1..=u16::try_from(MAXIMUM_MULTIPATH_PATHS).unwrap_or(u16::MAX)).contains(path)
        })
        .ok_or(ProductionMpquicError::Invalid("MPQUIC path id"))?;
    MPQUIC_CLIENT_PORT_BASE
        .checked_add(path)
        .ok_or(ProductionMpquicError::Invalid("MPQUIC Client port"))
}

fn start_request(
    authorization: &ClientNativeRouteAuthorization,
    path_count: usize,
    transport_mode: TransportMode,
    now_ms: u64,
) -> Result<StartSession, ProductionMpquicError> {
    let valid_cardinality = match transport_mode {
        TransportMode::MultipathQuic => {
            (MINIMUM_MULTIPATH_PATHS..=MAXIMUM_MULTIPATH_PATHS).contains(&path_count)
        }
        TransportMode::SinglePathGeneralUdp => path_count == 1,
        TransportMode::Unspecified => false,
    };
    if !valid_cardinality || now_ms >= authorization.expires_at_ms() {
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
        transport_mode: transport_mode as i32,
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
    let mut path_ids = BTreeSet::new();
    let mut relay_ids = BTreeSet::new();
    let mut listener_set_ready = false;
    for path in paths {
        validate_committed_path(start, path, now_ms)?;
        if !path_ids.insert(path.add.path_id) || !relay_ids.insert(path.relay_node_id) {
            return Err(ProductionMpquicError::Invalid(
                "distinct committed MPQUIC paths",
            ));
        }
        listener_set_ready |= path.listener_set_ready;
    }
    let cardinality_matches = match TransportMode::try_from(start.transport_mode).ok() {
        Some(TransportMode::MultipathQuic) => path_ids.len() >= MINIMUM_MULTIPATH_PATHS,
        Some(TransportMode::SinglePathGeneralUdp) => path_ids.len() == 1,
        _ => false,
    };
    if !cardinality_matches || path_ids.len() != paths.len() || !listener_set_ready {
        return Err(ProductionMpquicError::Invalid(
            "distinct committed MPQUIC paths",
        ));
    }
    Ok(path_ids.into_iter().collect())
}

fn validate_committed_path(
    start: &StartSession,
    path: &CommittedMpquicPath,
    now_ms: u64,
) -> Result<(), ProductionMpquicError> {
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
    let expected_exit_instance: [u8; 32] = start
        .exit_native_instance_id
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("Exit native instance"))?;
    if path.add.route_context_id.as_slice() != route_context
        || path.reservation_id != reservation_id
        || path.expires_at_ms <= now_ms
        || path.exit_native_instance_id != expected_exit_instance
    {
        return Err(ProductionMpquicError::Invalid("committed MPQUIC path"));
    }
    Ok(())
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
    for attempt in 0..NATIVE_SEND_BACKPRESSURE_ATTEMPTS {
        let result = control
            .send(SendDatagram {
                route_context_id: route_context_id.to_vec(),
                inner_ip_packet: packet.clone(),
                masque_context_id,
            })
            .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt + 1 < NATIVE_SEND_BACKPRESSURE_ATTEMPTS
                    && is_native_send_backpressure(&error) =>
            {
                tokio::time::sleep(NATIVE_SEND_BACKPRESSURE_INTERVAL).await;
            }
            Err(error) => {
                // The native diagnostic is a protocol-bounded code and contains no packet,
                // destination, route identifier, or credential. Preserve it in the service log
                // so an acceptance failure can be repaired without guessing at its class.
                eprintln!("native datagram send failed: {error}");
                return Err(error);
            }
        }
    }
    unreachable!("the bounded native send loop always returns")
}

fn is_native_send_backpressure(error: &ProductionMpquicError) -> bool {
    matches!(
        error,
        ProductionMpquicError::Native(NativeClientError::Rejected {
            result: NativeResultCode::Transport,
            diagnostic_code,
        }) if diagnostic_code == "send_backpressure"
    )
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

/// Poll an Exit listener while its authenticated Client association is still being established.
///
/// Listener readiness deliberately precedes the readiness signal sent back to the Client. Native
/// therefore reports `InsufficientPaths` during that bounded hand-off window; it is an empty poll,
/// not a terminal route failure. Every other rejection remains fail closed.
async fn receive_exit_inner_ip(
    control: &NativeClient,
    route_context_id: [u8; 16],
    masque_context_id: u64,
    awaiting_client: bool,
) -> Result<(bool, Option<Vec<u8>>), ProductionMpquicError> {
    let received = control
        .receive_datagram(ReceiveDatagram {
            route_context_id: route_context_id.to_vec(),
            masque_context_id,
        })
        .await;
    exit_receive_result(received, awaiting_client)
}

fn exit_receive_result(
    received: Result<Option<ReceivedDatagram>, NativeClientError>,
    awaiting_client: bool,
) -> Result<(bool, Option<Vec<u8>>), ProductionMpquicError> {
    match received {
        Ok(received) => Ok((
            true,
            received.map(|mut datagram| std::mem::take(&mut datagram.inner_ip_packet)),
        )),
        Err(NativeClientError::Rejected {
            result: NativeResultCode::InsufficientPaths,
            ..
        }) if awaiting_client => Ok((false, None)),
        Err(error) => Err(error.into()),
    }
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

fn tunnel_ipv4_scope(
    assignment: &TunnelAssignment,
) -> Result<(Ipv4Addr, Ipv4Addr, usize), ProductionMpquicError> {
    let client: [u8; 4] = assignment
        .assigned_ipv4
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("native tunnel client IPv4"))?;
    let server: [u8; 4] = assignment
        .server_ipv4
        .as_slice()
        .try_into()
        .map_err(|_| ProductionMpquicError::Invalid("native tunnel server IPv4"))?;
    let mtu = usize::try_from(assignment.mtu)
        .ok()
        .filter(|mtu| *mtu >= MINIMUM_MPQUIC_TUNNEL_MTU)
        .ok_or(ProductionMpquicError::Invalid("native tunnel MTU"))?;
    Ok((
        Ipv4Addr::from(client),
        Ipv4Addr::from(server),
        mtu.min(MINIMUM_MPQUIC_TUNNEL_MTU),
    ))
}

fn build_general_udp_authorization_packet(
    source: SocketAddrV4,
    server: Ipv4Addr,
    destination: SocketAddrV4,
    signed_authorization: &[u8],
    maximum_packet_bytes: usize,
) -> Result<Vec<u8>, ProductionMpquicError> {
    let signed_length = u16::try_from(signed_authorization.len())
        .map_err(|_| ProductionMpquicError::Invalid("native UDP authorization size"))?;
    let mut payload =
        Vec::with_capacity(GENERAL_UDP_AUTH_MAGIC.len() + 4 + 2 + 2 + signed_authorization.len());
    payload.extend_from_slice(GENERAL_UDP_AUTH_MAGIC);
    payload.extend_from_slice(&destination.ip().octets());
    payload.extend_from_slice(&destination.port().to_be_bytes());
    payload.extend_from_slice(&signed_length.to_be_bytes());
    payload.extend_from_slice(signed_authorization);
    build_ipv4_udp_packet(
        source,
        SocketAddrV4::new(server, GENERAL_UDP_AUTH_PORT),
        &payload,
        maximum_packet_bytes,
    )
}

fn build_ipv4_udp_packet(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
    maximum_packet_bytes: usize,
) -> Result<Vec<u8>, ProductionMpquicError> {
    let udp_length = 8_usize
        .checked_add(payload.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ProductionMpquicError::Invalid("native UDP payload size"))?;
    let packet_length = 20_usize
        .checked_add(usize::from(udp_length))
        .filter(|length| *length <= maximum_packet_bytes)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ProductionMpquicError::Invalid("native UDP packet size"))?;
    let mut packet = vec![0_u8; usize::from(packet_length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source.port().to_be_bytes());
    packet[22..24].copy_from_slice(&destination.port().to_be_bytes());
    packet[24..26].copy_from_slice(&udp_length.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let checksum = udp_ipv4_checksum(*source.ip(), *destination.ip(), &packet[20..]);
    packet[26..28]
        .copy_from_slice(&(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes());
    Ok(packet)
}

fn validate_browser_quic_packet(
    flow: &AuthorizedUdpFlow,
    route_context_id: [u8; 16],
    packet: &[u8],
    now_ms: u64,
    outbound: bool,
) -> Result<(), ProductionMpquicError> {
    flow.ensure_active_at(now_ms)?;
    if flow.route_context_id() != &route_context_id {
        return Err(ProductionMpquicError::Invalid(
            "browser QUIC flow route context",
        ));
    }
    let (source, destination) = udp_packet_tuple(packet)?;
    let policy_tuple = if outbound { destination } else { source };
    if !flow.matches_exact_ip_destination(policy_tuple) {
        return Err(ProductionMpquicError::Invalid(
            "browser QUIC exact destination tuple",
        ));
    }
    Ok(())
}

fn matching_browser_quic_response_flow<'a>(
    flows: impl IntoIterator<Item = (&'a AuthorizedUdpFlow, SocketAddrV4)>,
    route_context_id: [u8; 16],
    packet: &[u8],
    now_ms: u64,
) -> Result<Option<usize>, ProductionMpquicError> {
    let (source, destination) = udp_packet_tuple(packet)?;
    Ok(flows
        .into_iter()
        .enumerate()
        .find_map(|(index, (flow, tunnel_destination))| {
            (flow.ensure_active_at(now_ms).is_ok()
                && flow.route_context_id() == &route_context_id
                && flow.matches_exact_ip_destination(source)
                && destination == SocketAddr::V4(tunnel_destination))
            .then_some(index)
        }))
}

fn udp_packet_tuple(packet: &[u8]) -> Result<(SocketAddr, SocketAddr), ProductionMpquicError> {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return Err(ProductionMpquicError::Invalid("browser QUIC IP packet"));
    };
    match version {
        4 => ipv4_udp_tuple(packet),
        6 => ipv6_udp_tuple(packet),
        _ => Err(ProductionMpquicError::Invalid("browser QUIC IP version")),
    }
}

fn ipv4_udp_tuple(packet: &[u8]) -> Result<(SocketAddr, SocketAddr), ProductionMpquicError> {
    if packet.len() < 28 {
        return Err(ProductionMpquicError::Invalid("browser QUIC IPv4 packet"));
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if header_length != 20
        || total_length != packet.len()
        || header_length
            .checked_add(8)
            .is_none_or(|minimum| minimum > total_length)
        || packet[9] != 17
        || fragment & 0x3fff != 0
    {
        return Err(ProductionMpquicError::Invalid(
            "browser QUIC IPv4/UDP packet",
        ));
    }
    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    udp_tuple_at(
        packet,
        header_length,
        total_length,
        IpAddr::V4(source_ip),
        IpAddr::V4(destination_ip),
    )
}

fn ipv6_udp_tuple(packet: &[u8]) -> Result<(SocketAddr, SocketAddr), ProductionMpquicError> {
    if packet.len() < 48 {
        return Err(ProductionMpquicError::Invalid("browser QUIC IPv6 packet"));
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40_usize
        .checked_add(payload_length)
        .ok_or(ProductionMpquicError::Invalid("browser QUIC IPv6 length"))?;
    if payload_length == 0 || total_length != packet.len() {
        return Err(ProductionMpquicError::Invalid("browser QUIC IPv6 length"));
    }
    let source_ip = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24])
            .map_err(|_| ProductionMpquicError::Invalid("browser QUIC IPv6 source"))?,
    );
    let destination_ip = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40])
            .map_err(|_| ProductionMpquicError::Invalid("browser QUIC IPv6 destination"))?,
    );
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    for _ in 0..8 {
        if next_header == 17 {
            return udp_tuple_at(
                packet,
                offset,
                total_length,
                IpAddr::V6(source_ip),
                IpAddr::V6(destination_ip),
            );
        }
        if !matches!(next_header, 0 | 60) || offset + 2 > total_length {
            return Err(ProductionMpquicError::Invalid(
                "browser QUIC IPv6 extension chain",
            ));
        }
        next_header = packet[offset];
        let extension_length = (usize::from(packet[offset + 1]) + 1) * 8;
        offset = offset
            .checked_add(extension_length)
            .filter(|offset| *offset <= total_length)
            .ok_or(ProductionMpquicError::Invalid(
                "browser QUIC IPv6 extension length",
            ))?;
    }
    Err(ProductionMpquicError::Invalid(
        "browser QUIC IPv6 extension count",
    ))
}

fn udp_tuple_at(
    packet: &[u8],
    offset: usize,
    packet_length: usize,
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<(SocketAddr, SocketAddr), ProductionMpquicError> {
    let udp_header = packet
        .get(offset..offset.saturating_add(8))
        .ok_or(ProductionMpquicError::Invalid("browser QUIC UDP header"))?;
    let source_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
    let destination_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
    let udp_length = usize::from(u16::from_be_bytes([udp_header[4], udp_header[5]]));
    if source_port == 0
        || destination_port == 0
        || udp_length < 8
        || offset.checked_add(udp_length) != Some(packet_length)
    {
        return Err(ProductionMpquicError::Invalid("browser QUIC UDP tuple"));
    }
    Ok((
        SocketAddr::new(source_ip, source_port),
        SocketAddr::new(destination_ip, destination_port),
    ))
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
    /// The helper rejected or could not return one exact committed path descriptor.
    #[error("native MPQUIC helper socket failed: {0}")]
    Helper(#[from] HelperClientError),
    /// The signed exact-destination UDP authorization expired or was otherwise unusable.
    #[error("native MPQUIC browser flow authorization failed: {0}")]
    Flow(#[from] UdpError),
    /// The route-local connected Exit UDP socket could not be created or used.
    #[error("native MPQUIC Exit UDP egress failed: {0}")]
    ExitUdp(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::UdpSocket,
        os::fd::OwnedFd,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };
    use volparossa_policy::{DestinationRule, ProtocolPort, VerifiedManifest};
    use volparossa_protocol::{
        TimePolicy, Transport, UdpFlowAuthorization, generate_nonce, sign_control_message,
    };
    use volparossa_quic::{
        NATIVE_API_VERSION, NativeProcessIdentity, NativeRequest, NativeResponse, Preflight,
        encode_response, native_request, read_request, request_sha256,
    };
    use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};

    use super::*;

    #[test]
    fn exit_udp_mtu_probe_is_dropped_without_forwarding_truncated_payload() {
        let buffer = vec![0x5a; MAXIMUM_EXIT_UDP_PAYLOAD_BYTES + 1];
        assert_eq!(
            complete_exit_udp_payload(&buffer, MAXIMUM_EXIT_UDP_PAYLOAD_BYTES),
            Some(&buffer[..MAXIMUM_EXIT_UDP_PAYLOAD_BYTES])
        );
        assert_eq!(
            complete_exit_udp_payload(&buffer, MAXIMUM_EXIT_UDP_PAYLOAD_BYTES + 1),
            None
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves bounded pre-authorization retention and real UDP egress"
    )]
    async fn reordered_general_udp_payload_waits_for_exact_authorization() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("UDP destination");
        let destination = match receiver.local_addr().expect("UDP destination address") {
            SocketAddr::V4(destination) => destination,
            SocketAddr::V6(_) => unreachable!("IPv4 test destination"),
        };
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, destination.port()).expect("UDP permission");
        let rule = DestinationRule::exact_ip(IpAddr::V4(*destination.ip()), [permission])
            .expect("IP rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS)
            .expect("single-relay route");
        let mut path_replay = ReplayCache::new(4).expect("path replay");
        let path = VerifiedSingleRelayPath::verify(
            fixture.exit_reservation(),
            &fixture.relay_reservations()[0],
            NOW_MS,
            TimePolicy::default(),
            &mut path_replay,
        )
        .expect("verified path");
        let nonce = generate_nonce();
        let expires_at_ms = NOW_MS + 60_000;
        let signed = sign_control_message(
            &UdpFlowAuthorization {
                route_context_id: fixture.route_context_id().to_vec(),
                flow_id: vec![23; 16],
                client_ephemeral_id: fixture.client_session_id().to_vec(),
                hostname: String::new(),
                destination_ip: destination.ip().octets().to_vec(),
                port: u32::from(destination.port()),
                policy_hash: policy.policy_hash().to_vec(),
                idle_timeout_ms: 30_000,
                timestamp_ms: NOW_MS,
                expires_at_ms,
                nonce: nonce.to_vec(),
            },
            fixture.client_key(),
            NOW_MS,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .expect("signed UDP authorization");
        let mut flow_replay = ReplayCache::new(4).expect("flow replay");
        let authorization = UdpAuthorizationScope::new(&path, &policy)
            .verify(&signed, NOW_MS, TimePolicy::default(), &mut flow_replay)
            .expect("verified UDP authorization");
        let key = ExitUdpFlowKey {
            client: SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), 52_000),
            destination,
        };
        let mut pending = HashMap::new();

        queue_general_udp_before_authorization(&mut pending, key, b"reordered payload");
        assert_eq!(pending.len(), 1);
        assert!(
            pending
                .remove(&ExitUdpFlowKey {
                    client: key.client,
                    destination: SocketAddrV4::new(
                        Ipv4Addr::new(127, 0, 0, 2),
                        destination.port(),
                    ),
                })
                .is_none()
        );
        let mut receive_buffer = [0_u8; 64];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                receiver.recv(&mut receive_buffer),
            )
            .await
            .is_err()
        );

        let retained = pending.remove(&key).expect("exact retained payload");
        let mut flows = HashMap::new();
        forward_authorized_general_udp(
            &mut flows,
            &policy,
            &authorization,
            key,
            &retained.payload,
            NOW_MS,
        )
        .await
        .expect("authorized egress");
        let received_bytes =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut receive_buffer))
                .await
                .expect("egress timeout")
                .expect("egress receive");
        assert_eq!(&receive_buffer[..received_bytes], b"reordered payload");
    }

    #[test]
    fn pending_general_udp_is_memory_and_tuple_bounded() {
        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18_081);
        let mut pending = HashMap::new();
        for index in 0..MAXIMUM_EXIT_UDP_FLOWS {
            let port = u16::try_from(index + 1).expect("bounded source port");
            queue_general_udp_before_authorization(
                &mut pending,
                ExitUdpFlowKey {
                    client: SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), port),
                    destination,
                },
                b"first",
            );
        }
        let first_key = ExitUdpFlowKey {
            client: SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), 1),
            destination,
        };
        queue_general_udp_before_authorization(&mut pending, first_key, b"replacement");
        queue_general_udp_before_authorization(
            &mut pending,
            ExitUdpFlowKey {
                client: SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), 30_000),
                destination,
            },
            b"overflow",
        );
        assert_eq!(pending.len(), MAXIMUM_EXIT_UDP_FLOWS);
        assert_eq!(
            pending.get(&first_key).expect("first tuple").payload,
            b"first"
        );

        pending.clear();
        let oversized = [0; MAXIMUM_EXIT_UDP_PAYLOAD_BYTES + 1];
        queue_general_udp_before_authorization(&mut pending, first_key, &oversized);
        assert!(pending.is_empty());
    }

    #[test]
    fn exit_receive_waits_only_for_the_authenticated_client_path_set() {
        let pending = exit_receive_result(
            Err(NativeClientError::Rejected {
                result: NativeResultCode::InsufficientPaths,
                diagnostic_code: "exit_session_not_connected".to_owned(),
            }),
            true,
        )
        .unwrap();
        assert_eq!(pending, (false, None));
        assert_eq!(exit_receive_result(Ok(None), true).unwrap(), (true, None));

        let terminal = exit_receive_result(
            Err(NativeClientError::Rejected {
                result: NativeResultCode::Transport,
                diagnostic_code: "native_transport_failed".to_owned(),
            }),
            true,
        );
        assert!(matches!(
            terminal,
            Err(ProductionMpquicError::Native(NativeClientError::Rejected {
                result: NativeResultCode::Transport,
                ..
            }))
        ));

        let disconnected = exit_receive_result(
            Err(NativeClientError::Rejected {
                result: NativeResultCode::InsufficientPaths,
                diagnostic_code: "exit_session_not_connected".to_owned(),
            }),
            false,
        );
        assert!(matches!(
            disconnected,
            Err(ProductionMpquicError::Native(NativeClientError::Rejected {
                result: NativeResultCode::InsufficientPaths,
                ..
            }))
        ));
    }

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
        send_attempts: usize,
        send_backpressure_remaining: usize,
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
            let mut state = self.state.lock().unwrap();
            state.send_attempts += 1;
            if state.send_backpressure_remaining != 0 {
                state.send_backpressure_remaining -= 1;
                return Err(ProductionMpquicError::Native(NativeClientError::Rejected {
                    result: NativeResultCode::Transport,
                    diagnostic_code: "send_backpressure".to_owned(),
                }));
            }
            drop(state);
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

    fn outbound_ipv4_udp(
        client: SocketAddrV4,
        destination: SocketAddrV4,
        payload: &[u8],
    ) -> Vec<u8> {
        build_reverse_ipv4_udp(
            ExitUdpFlowKey {
                client: destination,
                destination: client,
            },
            payload,
            7,
        )
        .unwrap()
    }

    #[test]
    fn exit_udp_packet_is_policy_assignment_and_checksum_bound() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 7), 51_234);
        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44_443);
        let permission = ProtocolPort::new(TransportProtocol::Udp, destination.port()).unwrap();
        let rule = DestinationRule::exact_ip(IpAddr::V4(*destination.ip()), [permission]).unwrap();
        let policy = verified_development_manifest(NOW_MS, vec![rule]).unwrap();
        let packet = outbound_ipv4_udp(client, destination, b"browser-quic");

        let authorized = authorize_exit_ipv4_udp(&policy, NOW_MS, &packet, None).unwrap();
        assert_eq!(authorized.client, client);
        assert_eq!(authorized.destination, destination);
        assert_eq!(authorized.payload, b"browser-quic");
        assert!(
            authorize_exit_ipv4_udp(&policy, NOW_MS, &packet, Some(Ipv4Addr::new(10, 76, 0, 8)),)
                .is_err()
        );

        let denied = outbound_ipv4_udp(
            client,
            SocketAddrV4::new(*destination.ip(), destination.port() + 1),
            b"browser-quic",
        );
        assert!(authorize_exit_ipv4_udp(&policy, NOW_MS, &denied, None).is_err());
        let mut unchecked_udp = packet.clone();
        unchecked_udp[26..28].fill(0);
        assert!(authorize_exit_ipv4_udp(&policy, NOW_MS, &unchecked_udp, None).is_err());
        let mut corrupt = packet;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(authorize_exit_ipv4_udp(&policy, NOW_MS, &corrupt, None).is_err());
    }

    #[test]
    fn reverse_udp_packet_targets_exact_assigned_client_tuple() {
        let flow = ExitUdpFlowKey {
            client: SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 23), 53_001),
            destination: SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
        };
        let packet = build_reverse_ipv4_udp(flow, b"reply", 19).unwrap();
        assert_eq!(
            udp_packet_tuple(&packet).unwrap(),
            (
                SocketAddr::V4(flow.destination),
                SocketAddr::V4(flow.client)
            )
        );
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(
            udp_ipv4_checksum(*flow.destination.ip(), *flow.client.ip(), &packet[20..]),
            0
        );
    }

    fn browser_flow(
        fixture: &SignedRouteFixture,
        policy: &VerifiedManifest,
        destination: SocketAddrV4,
        flow_id: u8,
        now_ms: u64,
    ) -> AuthorizedUdpFlow {
        let nonce = generate_nonce();
        let expires_at_ms = now_ms + 60_000;
        let signed = sign_control_message(
            &UdpFlowAuthorization {
                route_context_id: fixture.route_context_id().to_vec(),
                flow_id: vec![flow_id; 16],
                client_ephemeral_id: fixture.client_session_id().to_vec(),
                hostname: "destination.volparossa.test".to_owned(),
                destination_ip: destination.ip().octets().to_vec(),
                port: u32::from(destination.port()),
                policy_hash: policy.policy_hash().to_vec(),
                idle_timeout_ms: 30_000,
                timestamp_ms: now_ms,
                expires_at_ms,
                nonce: nonce.to_vec(),
            },
            fixture.client_key(),
            now_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let mut replay = ReplayCache::new(1).unwrap();
        UdpAuthorizationScope::new_multipath(
            *fixture.route_context_id(),
            fixture.client_session_id(),
            expires_at_ms,
            policy,
        )
        .unwrap()
        .verify(&signed, now_ms, TimePolicy::default(), &mut replay)
        .unwrap()
    }

    #[test]
    fn browser_reverse_packets_select_the_exact_retained_application_flow() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let destination = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let permission = ProtocolPort::new(TransportProtocol::Udp, 443).unwrap();
        let policy = verified_development_manifest(
            NOW_MS,
            vec![
                DestinationRule::exact_domain("destination.volparossa.test", [permission]).unwrap(),
            ],
        )
        .unwrap();
        let fixture = SignedRouteFixture::new(2, &[Transport::MultipathQuic], NOW_MS).unwrap();
        let first = browser_flow(&fixture, &policy, destination, 1, NOW_MS);
        let second = browser_flow(&fixture, &policy, destination, 2, NOW_MS);
        let first_client = SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), 52_006);
        let second_client = SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 2), 52_007);
        let flows = [(&first, first_client), (&second, second_client)];

        let late_first = build_ipv4_udp(destination, first_client, b"late-a06", 1).unwrap();
        assert_eq!(
            matching_browser_quic_response_flow(
                flows,
                *fixture.route_context_id(),
                &late_first,
                NOW_MS,
            )
            .unwrap(),
            Some(0)
        );
        let current_second = build_ipv4_udp(destination, second_client, b"a07", 2).unwrap();
        assert_eq!(
            matching_browser_quic_response_flow(
                flows,
                *fixture.route_context_id(),
                &current_second,
                NOW_MS,
            )
            .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn browser_authorization_packet_targets_only_tunnel_server_control_port() {
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 23), 53_001);
        let control = SocketAddrV4::new(TUNNEL_SERVER_IPV4, BROWSER_QUIC_AUTHORIZATION_PORT);
        let packet = build_ipv4_udp(client, control, b"signed-flow", 0).unwrap();
        let parsed = parse_exit_ipv4_udp(&packet, Some(*client.ip())).unwrap();
        assert_eq!(parsed.client, client);
        assert_eq!(parsed.destination, control);
        assert_eq!(parsed.payload, b"signed-flow");
    }

    #[test]
    fn browser_data_before_authorization_is_dropped_without_egress_admission() {
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 76, 0, 23), 53_001);
        let mut pending = HashMap::new();

        assert!(take_verified_browser_quic_candidate(&mut pending, client).is_none());
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn exit_flow_reuses_one_connected_udp_socket_for_return_traffic() {
        let destination = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let SocketAddr::V4(destination_address) = destination.local_addr().unwrap() else {
            panic!("IPv4 test destination");
        };
        let flow = ExitUdpFlow::connect(destination_address, None)
            .await
            .unwrap();
        let local = flow.socket.local_addr().unwrap();
        flow.socket.send(b"one").await.unwrap();
        let mut request = [0_u8; 16];
        let (length, peer) = destination.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..length], b"one");
        destination.send_to(b"return", peer).await.unwrap();
        let mut response = [0_u8; 16];
        let length = flow.socket.recv(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"return");
        flow.socket.send(b"two").await.unwrap();
        let (_, second_peer) = destination.recv_from(&mut request).await.unwrap();
        assert_eq!(peer, second_peer);
        assert_eq!(flow.socket.local_addr().unwrap(), local);
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
    async fn native_send_retries_only_bounded_backpressure() {
        let native = FakeNative::default();
        native.state.lock().unwrap().send_backpressure_remaining = 1;
        let packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 59, 0, 0, 10, 76, 0, 2, 10, 76, 0, 1,
        ];

        send_inner_ip(&native, [2; 16], 7, packet.clone())
            .await
            .unwrap();

        assert_eq!(native.state.lock().unwrap().send_attempts, 2);
        assert_eq!(
            receive_inner_ip(&native, [2; 16], 7).await.unwrap(),
            Some(packet)
        );
    }

    #[tokio::test]
    async fn native_send_backpressure_exhaustion_is_bounded() {
        let native = FakeNative::default();
        native.state.lock().unwrap().send_backpressure_remaining =
            NATIVE_SEND_BACKPRESSURE_ATTEMPTS;
        let packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 59, 0, 0, 10, 76, 0, 2, 10, 76, 0, 1,
        ];

        let error = send_inner_ip(&native, [2; 16], 7, packet)
            .await
            .expect_err("persistent native backpressure must remain fail closed");

        assert!(is_native_send_backpressure(&error));
        assert_eq!(
            native.state.lock().unwrap().send_attempts,
            NATIVE_SEND_BACKPRESSURE_ATTEMPTS
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

    fn native_response(request: &NativeRequest, result: NativeResultCode) -> NativeResponse {
        NativeResponse {
            api_version: NATIVE_API_VERSION,
            request_nonce: request.request_nonce.clone(),
            result: result as i32,
            diagnostic_code: "mpquic_exit_test".to_owned(),
            paths: Vec::new(),
            received_datagram: None,
            process_identity: Some(NativeProcessIdentity {
                role: NativeProcessRole::Exit as i32,
                native_instance_id: vec![8; 32],
            }),
            request_sha256: request_sha256(request).unwrap().to_vec(),
            tunnel_assignment: None,
        }
    }

    async fn read_fake_process_request(stream: &mut UnixStream) -> NativeRequest {
        // The first 32 bytes are zero for ordinary requests and the domain-separated SCM_RIGHTS
        // binding for StartExitSession. A normal read deliberately discards the test FD copy.
        let mut descriptor_binding = [0_u8; 32];
        stream.read_exact(&mut descriptor_binding).await.unwrap();
        let request = read_request(stream).await.unwrap();
        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).await.unwrap(), 0);
        request
    }

    fn committed_exit_listener(
        route_context_id: [u8; 16],
        path_id: u32,
    ) -> CommittedMpquicExitListener {
        let addresses =
            overlay_addresses(route_context_id, u8::try_from(path_id).unwrap()).unwrap();
        let socket = Socket::new(Domain::IPV6, Type::DGRAM.cloexec(), Some(Protocol::UDP)).unwrap();
        socket.set_only_v6(true).unwrap();
        socket.set_reuse_address(false).unwrap();
        socket.set_reuse_port(false).unwrap();
        socket.set_freebind_v6(true).unwrap();
        socket
            .bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(addresses.exit),
                MPQUIC_EXIT_LISTENER_PORT,
            )))
            .unwrap();
        socket.set_nonblocking(true).unwrap();
        CommittedMpquicExitListener {
            descriptor: socket.into(),
            path_id,
            listener_ip: addresses.exit.octets(),
            expected_client_ip: addresses.client.octets(),
            reservation_hash: [u8::try_from(path_id).unwrap(); 32],
        }
    }

    #[tokio::test]
    async fn exit_responder_boundary_waits_for_two_native_listener_fds() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("mpquic-exit.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            let (mut preflight_stream, _) = listener.accept().await.unwrap();
            let preflight = read_fake_process_request(&mut preflight_stream).await;
            assert!(matches!(
                preflight.operation,
                Some(native_request::Operation::Preflight(Preflight {
                    expected_role
                })) if expected_role == NativeProcessRole::Exit as i32
            ));
            preflight_stream
                .write_all(
                    &encode_response(&native_response(&preflight, NativeResultCode::Ok)).unwrap(),
                )
                .await
                .unwrap();

            for (index, expected_path) in [1_u32, 2].into_iter().enumerate() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_fake_process_request(&mut stream).await;
                let Some(native_request::Operation::StartExitSession(start)) = &request.operation
                else {
                    panic!("StartExitSession boundary");
                };
                assert_eq!(start.path_id, expected_path);
                assert_eq!(start.minimum_paths, 2);
                assert_eq!(start.transport_mode, TransportMode::MultipathQuic as i32);
                assert_eq!(start.auth_secret, vec![b'A'; 43]);
                assert_eq!(start.reservation_id, vec![1; 16]);
                assert_eq!(start.route_context_id, vec![2; 16]);
                assert_eq!(start.finalize_id, vec![4; 16]);
                assert_eq!(start.client_native_instance_id, vec![7; 32]);
                assert_eq!(start.exit_native_instance_id, vec![8; 32]);
                let result = if index == 0 {
                    NativeResultCode::InsufficientPaths
                } else {
                    NativeResultCode::Ok
                };
                stream
                    .write_all(&encode_response(&native_response(&request, result)).unwrap())
                    .await
                    .unwrap();
            }
        });

        let client = NativeClient::new(socket_path)
            .unwrap()
            .preflight(NativeProcessRole::Exit)
            .await
            .unwrap();
        let auth_bearer = Zeroizing::new(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let mut hasher = Sha256::new();
        hasher.update(b"VOLPAROSSA-NATIVE-ROUTE-AUTH-COMMITMENT-V4\0");
        hasher.update(auth_bearer.as_slice());
        let expires_at_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 60_000;
        let authorization = NativeExitAuthorizationParts {
            reservation_id: [1; 16],
            route_context_id: [2; 16],
            finalize_id: [4; 16],
            expires_at_ms,
            auth_bearer,
            auth_commitment: hasher.finalize().into(),
            certificate_sha256: [6; 32],
            spki_sha256: [3; 32],
            masque_context_id: 9,
            tls_server_name: b"exit.example".to_vec(),
            tls_certificate_pem: Zeroizing::new(
                b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_vec(),
            ),
            tls_private_key_pem: Zeroizing::new(
                b"-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n".to_vec(),
            ),
            client_native_instance_id: [7; 32],
            exit_native_instance_id: [8; 32],
            client_session_id: [9; 32],
        };
        start_native_exit_listener_set(
            &client,
            &authorization,
            vec![
                committed_exit_listener([2; 16], 1),
                committed_exit_listener([2; 16], 2),
            ],
            TransportMode::MultipathQuic,
        )
        .await
        .unwrap();
        server.await.unwrap();
    }
}
