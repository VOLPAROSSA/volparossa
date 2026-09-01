//! Process-owned client ingress capabilities.

#![allow(
    dead_code,
    reason = "the production TCP and UDP route actors consume this complete ingress activation seam"
)]

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::OwnedFd,
    time::Duration,
};

use rand_core::{OsRng, RngCore as _};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout_at};
use volparossa_inspection::{
    InspectionError, InspectionProgress, QuicInitialInspector, TlsClientHelloInspector,
};
use volparossa_linux_uapi::{
    IngressSocketFamily as KernelIngressSocketFamily, IngressSocketKind as KernelIngressSocketKind,
    duplicate_descriptor_cloexec, receive_udp_with_original_destination, tcp_original_destination,
};
use volparossa_policy::{PolicyError, TransportProtocol, VerifiedManifest};
use volparossa_protocol::{ReplayCache, TimePolicy};
use volparossa_quic::parse_initial;
use volparossa_reservation::{CoordinatorError, ReservationCoordinator};
use volparossa_routing::{PrepareClientIngress, REQUIRED_INGRESS_SOCKETS};
use volparossa_udp::{
    AuthorizedUdpFlow, MAX_DNS_MESSAGE_BYTES, MAX_UDP_PAYLOAD_BYTES, UdpAuthorizationScope,
    UdpError, VerifiedSingleRelayPath, parse_dns_query,
};

use crate::{
    helper::{
        AcquiredIngressSocket, ActiveClientIngress, ClientIngressSocketFamily,
        ClientIngressSocketIdentity, ClientIngressSocketKind, HelperClient, HelperClientError,
        PreparedClientIngress,
    },
    unix_seconds,
};

const INGRESS_SETUP_TTL_SECONDS: u64 = 30;
const INGRESS_HARD_TTL_SECONDS: u64 = 15 * 60;
const INGRESS_UDP_IDLE_TIMEOUT_MS: u32 = 30_000;
const INGRESS_UDP_FLOW_TTL_MS: u64 = 60_000;
const INGRESS_TCP_FLOW_TTL_MS: u64 = 60_000;
const BROWSER_QUIC_PORT: u16 = 443;
const TLS_CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_CLIENT_HELLO_PEEK_BYTES: usize = 64 * 1024 + 64;
const TLS_CLIENT_HELLO_POLL_INTERVAL: Duration = Duration::from_millis(2);
const IPV4_HEADER_BYTES: usize = 20;
const UDP_HEADER_BYTES: usize = 8;
const MAX_BROWSER_QUIC_DATAGRAMS_PER_FLOW: u32 = 65_536;
const MAX_PENDING_BROWSER_QUIC_DATAGRAMS: usize = 128;
const MAX_PENDING_BROWSER_QUIC_BYTES: usize = 256 * 1024;

const IPV4_TRANSPARENT_TCP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::TransparentTcpListener,
    ClientIngressSocketFamily::Ipv4,
);
const IPV6_TRANSPARENT_TCP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::TransparentTcpListener,
    ClientIngressSocketFamily::Ipv6,
);

const IPV4_TRANSPARENT_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::TransparentUdp,
    ClientIngressSocketFamily::Ipv4,
);

const IPV4_DNS_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::DnsUdp,
    ClientIngressSocketFamily::Ipv4,
);

/// Affine owner of the complete activated ingress descriptor set.
pub(crate) struct ClientIngressRuntime {
    helper: HelperClient,
    active: ActiveClientIngress,
}

impl ClientIngressRuntime {
    pub(crate) async fn start(helper: HelperClient) -> Result<Self, ClientIngressRuntimeError> {
        let client_runtime_id = random_runtime_id()?;
        let now = unix_seconds();
        let mut prepared = helper
            .prepare_client_ingress(PrepareClientIngress {
                client_runtime_id: client_runtime_id.to_vec(),
                setup_expires_at_unix: now
                    .checked_add(INGRESS_SETUP_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
                hard_expires_at_unix: now
                    .checked_add(INGRESS_HARD_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
            })
            .await
            .map_err(ClientIngressRuntimeError::Prepare)?;

        let identities = prepared.socket_identities().collect::<Vec<_>>();
        let mut sockets = Vec::with_capacity(REQUIRED_INGRESS_SOCKETS);
        for identity in identities {
            match helper.acquire_ingress_socket(&mut prepared, identity).await {
                Ok(socket) => sockets.push(socket),
                Err(error) => {
                    return Err(cleanup_prepared_failure(
                        &helper,
                        &prepared,
                        ClientIngressRuntimeError::Acquire(error),
                    )
                    .await);
                }
            }
        }
        let sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS] = match sockets.try_into() {
            Ok(sockets) => sockets,
            Err(_sockets) => {
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::IncompleteDescriptorSet,
                )
                .await);
            }
        };
        let active = match helper.activate_client_ingress(prepared, sockets).await {
            Ok(active) => active,
            Err(failure) => {
                let (error, prepared, _sockets) = failure.into_parts();
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::Activate(error),
                )
                .await);
            }
        };
        Ok(Self { helper, active })
    }

    /// Duplicate both helper-owned transparent TCP listeners into Tokio readiness owners.
    ///
    /// The active ingress capability retains the originals. Each duplicate preserves the
    /// nonblocking file status and is close-on-exec; every accepted stream is independently
    /// revalidated before its kernel-recorded original destination is exposed.
    pub(crate) fn transparent_tcp_listeners(
        &self,
    ) -> Result<[ClientTcpIngressListener; 2], ClientIngressTcpError> {
        Ok([
            self.transparent_tcp_listener(IPV4_TRANSPARENT_TCP, KernelIngressSocketFamily::Ipv4)?,
            self.transparent_tcp_listener(IPV6_TRANSPARENT_TCP, KernelIngressSocketFamily::Ipv6)?,
        ])
    }

    fn transparent_tcp_listener(
        &self,
        identity: ClientIngressSocketIdentity,
        family: KernelIngressSocketFamily,
    ) -> Result<ClientTcpIngressListener, ClientIngressTcpError> {
        let socket = self
            .active
            .socket(identity)
            .ok_or(ClientIngressTcpError::DescriptorUnavailable)?;
        let descriptor = duplicate_descriptor_cloexec(&socket.descriptor())
            .map_err(ClientIngressTcpError::Duplicate)?;
        ClientTcpIngressListener::from_descriptor(descriptor, family)
    }

    /// Try to receive one IPv4 application datagram and bind its immutable destination to policy.
    ///
    /// The descriptor is nonblocking. `WouldBlock` is returned unchanged so an actor can wait for
    /// readiness without inventing a destination. The payload and destination enter the returned
    /// affine value only after exact ORIGDST evidence and the active whitelist both agree.
    pub(crate) fn try_receive_ipv4_udp(&self) -> Result<ObservedUdpIngress, ClientIngressUdpError> {
        let socket = self
            .active
            .socket(IPV4_TRANSPARENT_UDP)
            .ok_or(ClientIngressUdpError::DescriptorUnavailable)?;
        let SocketAddr::V4(local) = socket.local_address() else {
            return Err(ClientIngressUdpError::DescriptorUnavailable);
        };
        let mut payload = vec![0_u8; MAX_UDP_PAYLOAD_BYTES];
        let received = receive_udp_with_original_destination(
            &socket.descriptor(),
            KernelIngressSocketKind::TransparentUdp,
            KernelIngressSocketFamily::Ipv4,
            local.port(),
            &mut payload,
        )
        .map_err(ClientIngressUdpError::Receive)?;
        payload.truncate(received.bytes());
        ObservedUdpIngress::new(received.source(), received.original_destination(), payload)
    }

    pub(crate) fn duplicate_ipv4_udp_poll_descriptor(&self) -> Result<OwnedFd, io::Error> {
        let socket = self.active.socket(IPV4_TRANSPARENT_UDP).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "IPv4 UDP ingress unavailable")
        })?;
        duplicate_descriptor_cloexec(&socket.descriptor())
    }

    /// Receive one dedicated DNS datagram and authorize only its bounded A/AAAA query name.
    pub(crate) fn try_receive_ipv4_dns_udp(
        &self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedDnsIngress, ClientIngressUdpError> {
        let socket = self
            .active
            .socket(IPV4_DNS_UDP)
            .ok_or(ClientIngressUdpError::DescriptorUnavailable)?;
        let SocketAddr::V4(local) = socket.local_address() else {
            return Err(ClientIngressUdpError::DescriptorUnavailable);
        };
        let mut payload = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
        let received = receive_udp_with_original_destination(
            &socket.descriptor(),
            KernelIngressSocketKind::DnsUdp,
            KernelIngressSocketFamily::Ipv4,
            local.port(),
            &mut payload,
        )
        .map_err(ClientIngressUdpError::Receive)?;
        payload.truncate(received.bytes());
        PolicyAuthorizedDnsIngress::authorize(
            received.source(),
            received.original_destination(),
            payload,
            policy,
            now_ms,
        )
    }

    pub(crate) fn duplicate_ipv4_dns_udp_poll_descriptor(&self) -> Result<OwnedFd, io::Error> {
        let socket = self.active.socket(IPV4_DNS_UDP).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "IPv4 DNS UDP ingress unavailable")
        })?;
        duplicate_descriptor_cloexec(&socket.descriptor())
    }

    pub(crate) async fn send_ipv4_udp_response(
        &self,
        application: SocketAddrV4,
        remote: SocketAddrV4,
        payload: &[u8],
    ) -> Result<(), ClientIngressUdpError> {
        if payload.len() > MAX_UDP_PAYLOAD_BYTES {
            return Err(ClientIngressUdpError::ReplyPayload);
        }
        let reply = self
            .helper
            .acquire_ingress_reply_socket(&self.active, remote, application)
            .await
            .map_err(ClientIngressUdpError::ReplyAcquire)?;
        if reply.remote() != remote || reply.application() != application {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        reply.send(payload).map_err(ClientIngressUdpError::Reply)
    }

    pub(crate) async fn shutdown(self) -> Result<(), ClientIngressRuntimeError> {
        self.helper
            .destroy_active_client_ingress(&self.active)
            .await
            .map(|_| ())
            .map_err(ClientIngressRuntimeError::Destroy)
    }
}

/// One readiness owner for an exact helper-created transparent TCP listener.
pub(crate) struct ClientTcpIngressListener {
    listener: TcpListener,
    family: KernelIngressSocketFamily,
}

impl ClientTcpIngressListener {
    fn from_descriptor(
        descriptor: OwnedFd,
        family: KernelIngressSocketFamily,
    ) -> Result<Self, ClientIngressTcpError> {
        let listener = std::net::TcpListener::from(descriptor);
        listener
            .set_nonblocking(true)
            .map_err(ClientIngressTcpError::Duplicate)?;
        Ok(Self {
            listener: TcpListener::from_std(listener).map_err(ClientIngressTcpError::Duplicate)?,
            family,
        })
    }

    /// Accept one application stream and recover its immutable kernel original destination.
    pub(crate) async fn accept(&self) -> Result<ObservedTcpIngress, ClientIngressTcpError> {
        let (stream, _source) = self
            .listener
            .accept()
            .await
            .map_err(ClientIngressTcpError::Accept)?;
        let destination = tcp_original_destination(&stream, self.family)
            .map_err(ClientIngressTcpError::OriginalDestination)?;
        Ok(ObservedTcpIngress {
            stream,
            destination,
        })
    }
}

/// One accepted transparent stream whose destination came only from kernel TPROXY evidence.
#[must_use = "an observed TCP ingress stream must be policy-bound or dropped"]
pub(crate) struct ObservedTcpIngress {
    stream: TcpStream,
    destination: SocketAddr,
}

impl ObservedTcpIngress {
    /// Bind the kernel-observed tuple to the active manifest. TLS/443 additionally requires a
    /// visible policy-approved SNI and retains the original address as an Exit-side DNS pin.
    pub(crate) async fn authorize(
        self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedTcpIngress, ClientIngressTcpError> {
        let (hostname, policy_hash, expires_at_ms) = if self.destination.port() == BROWSER_QUIC_PORT
        {
            let hostname = inspect_visible_tls_server_name(&self.stream).await?;
            policy
                .authorize_domain(
                    now_ms,
                    &hostname,
                    TransportProtocol::Tcp,
                    self.destination.port(),
                )
                .map_err(ClientIngressTcpError::Policy)?;
            let expires_at_ms = tcp_flow_expiry(policy, now_ms)?;
            (Some(hostname), *policy.policy_hash(), expires_at_ms)
        } else {
            let (policy_hash, expires_at_ms) =
                authorize_tcp_destination(self.destination, policy, now_ms)?;
            (None, policy_hash, expires_at_ms)
        };
        Ok(PolicyAuthorizedTcpIngress {
            stream: self.stream,
            destination: self.destination,
            hostname,
            policy_hash,
            expires_at_ms,
        })
    }
}

/// Affine application stream bound to one exact raw-IP policy authorization.
#[must_use = "a policy-authorized TCP ingress stream must be route-bound or dropped"]
pub(crate) struct PolicyAuthorizedTcpIngress {
    stream: TcpStream,
    destination: SocketAddr,
    hostname: Option<String>,
    policy_hash: [u8; 32],
    expires_at_ms: u64,
}

impl PolicyAuthorizedTcpIngress {
    /// Recheck the immutable policy binding immediately before signing `OPEN_TCP`.
    pub(crate) fn into_route_parts(
        self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<(TcpStream, SocketAddr, Option<String>), ClientIngressTcpError> {
        if now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressTcpError::PolicyBinding);
        }
        if let Some(hostname) = self.hostname.as_deref() {
            policy
                .authorize_domain(
                    now_ms,
                    hostname,
                    TransportProtocol::Tcp,
                    self.destination.port(),
                )
                .map_err(ClientIngressTcpError::Policy)?;
        } else {
            policy
                .authorize_ip(
                    now_ms,
                    self.destination.ip(),
                    TransportProtocol::Tcp,
                    self.destination.port(),
                )
                .map_err(ClientIngressTcpError::Policy)?;
        }
        Ok((self.stream, self.destination, self.hostname))
    }
}

async fn inspect_visible_tls_server_name(
    stream: &TcpStream,
) -> Result<String, ClientIngressTcpError> {
    let deadline = Instant::now() + TLS_CLIENT_HELLO_TIMEOUT;
    let mut bytes = vec![0_u8; TLS_CLIENT_HELLO_PEEK_BYTES];
    let mut previous_count = 0_usize;
    loop {
        let count = timeout_at(deadline, stream.peek(&mut bytes))
            .await
            .map_err(|_| ClientIngressTcpError::ClientHelloUnavailable)?
            .map_err(ClientIngressTcpError::ClientHelloRead)?;
        if count == 0 {
            return Err(ClientIngressTcpError::ClientHelloUnavailable);
        }
        let mut inspector = TlsClientHelloInspector::new();
        match inspector
            .push(&bytes[..count])
            .map_err(ClientIngressTcpError::ClientHello)?
        {
            InspectionProgress::Complete(server_name) => return Ok(server_name.into_string()),
            InspectionProgress::NeedMore => {
                if count == bytes.len() || Instant::now() >= deadline {
                    return Err(ClientIngressTcpError::ClientHelloUnavailable);
                }
            }
        }
        if count <= previous_count {
            sleep(TLS_CLIENT_HELLO_POLL_INTERVAL).await;
        }
        previous_count = count;
    }
}

fn tcp_flow_expiry(policy: &VerifiedManifest, now_ms: u64) -> Result<u64, ClientIngressTcpError> {
    let expires_at_ms = now_ms
        .checked_add(INGRESS_TCP_FLOW_TTL_MS)
        .ok_or(ClientIngressTcpError::Clock)?
        .min(policy.expires_at_ms());
    if expires_at_ms <= now_ms {
        return Err(ClientIngressTcpError::Clock);
    }
    Ok(expires_at_ms)
}

fn authorize_tcp_destination(
    destination: SocketAddr,
    policy: &VerifiedManifest,
    now_ms: u64,
) -> Result<([u8; 32], u64), ClientIngressTcpError> {
    if destination.ip().is_unspecified() || destination.port() == 0 {
        return Err(ClientIngressTcpError::DestinationBinding);
    }
    policy
        .authorize_ip(
            now_ms,
            destination.ip(),
            TransportProtocol::Tcp,
            destination.port(),
        )
        .map_err(ClientIngressTcpError::Policy)?;
    let expires_at_ms = tcp_flow_expiry(policy, now_ms)?;
    Ok((*policy.policy_hash(), expires_at_ms))
}

/// One kernel-observed UDP datagram before destination policy is selected.
#[must_use = "kernel UDP evidence must be inspected and authorized or dropped"]
pub(crate) struct ObservedUdpIngress {
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: Vec<u8>,
}

impl ObservedUdpIngress {
    fn new(
        source: SocketAddr,
        destination: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<Self, ClientIngressUdpError> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        if source.port() == 0
            || destination.port() == 0
            || source.ip().is_unspecified()
            || destination.ip().is_unspecified()
            || payload.len() > MAX_UDP_PAYLOAD_BYTES
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        Ok(Self {
            source,
            destination,
            payload,
        })
    }

    pub(crate) const fn is_browser_quic(&self) -> bool {
        self.destination.port() == BROWSER_QUIC_PORT
    }

    pub(crate) fn authorize_ip(
        self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedUdpIngress, ClientIngressUdpError> {
        PolicyAuthorizedUdpIngress::authorize(
            self.source.into(),
            self.destination.into(),
            self.payload,
            policy,
            now_ms,
        )
    }
}

/// Bounded owner of browser QUIC Initials until visible SNI selects domain policy.
pub(crate) struct BrowserQuicIngressGate {
    state: BrowserQuicIngressState,
}

enum BrowserQuicIngressState {
    Empty,
    Pending {
        source: SocketAddrV4,
        destination: SocketAddrV4,
        inspector: QuicInitialInspector,
        datagrams: Vec<Vec<u8>>,
        bytes: usize,
    },
    Authorized {
        source: SocketAddrV4,
        destination: SocketAddrV4,
        hostname: String,
        policy_hash: [u8; 32],
        expires_at_ms: u64,
    },
}

pub(crate) enum BrowserQuicIngressDecision {
    NeedMore,
    Authorized(Vec<PolicyAuthorizedUdpIngress>),
}

impl BrowserQuicIngressGate {
    pub(crate) const fn new() -> Self {
        Self {
            state: BrowserQuicIngressState::Empty,
        }
    }

    pub(crate) fn reset_authorized_if_route_inactive(&mut self) {
        if matches!(self.state, BrowserQuicIngressState::Authorized { .. }) {
            self.state = BrowserQuicIngressState::Empty;
        }
    }

    pub(crate) fn inspect(
        &mut self,
        ingress: ObservedUdpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<BrowserQuicIngressDecision, ClientIngressUdpError> {
        if !ingress.is_browser_quic() {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        let authorized_flow = if let BrowserQuicIngressState::Authorized {
            source,
            destination,
            hostname,
            policy_hash,
            expires_at_ms,
        } = &self.state
        {
            (ingress.source == *source
                && ingress.destination == *destination
                && now_ms < *expires_at_ms
                && policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() == 1)
                .then(|| hostname.clone())
        } else {
            None
        };
        if let Some(hostname) = authorized_flow {
            let authorized =
                PolicyAuthorizedUdpIngress::authorize_hostname(ingress, hostname, policy, now_ms)?;
            return Ok(BrowserQuicIngressDecision::Authorized(vec![authorized]));
        }
        if matches!(self.state, BrowserQuicIngressState::Authorized { .. }) {
            self.state = BrowserQuicIngressState::Empty;
        }
        let pending_tuple_changed = if let BrowserQuicIngressState::Pending {
            source,
            destination,
            ..
        } = &self.state
        {
            ingress.source != *source || ingress.destination != *destination
        } else {
            false
        };
        if pending_tuple_changed {
            self.state = BrowserQuicIngressState::Empty;
        }

        if matches!(self.state, BrowserQuicIngressState::Empty) {
            let initial = parse_initial(&ingress.payload)
                .map_err(|_| ClientIngressUdpError::QuicInspection)?;
            let inspector = QuicInitialInspector::new(initial.destination_connection_id)
                .map_err(|_| ClientIngressUdpError::QuicInspection)?;
            self.state = BrowserQuicIngressState::Pending {
                source: ingress.source,
                destination: ingress.destination,
                inspector,
                datagrams: Vec::new(),
                bytes: 0,
            };
        }

        let BrowserQuicIngressState::Pending {
            source,
            destination,
            inspector,
            datagrams,
            bytes,
        } = &mut self.state
        else {
            return Err(ClientIngressUdpError::QuicInspection);
        };
        if ingress.source != *source
            || ingress.destination != *destination
            || datagrams.len() >= MAX_PENDING_BROWSER_QUIC_DATAGRAMS
            || bytes
                .checked_add(ingress.payload.len())
                .is_none_or(|total| total > MAX_PENDING_BROWSER_QUIC_BYTES)
        {
            return Err(ClientIngressUdpError::FlowBound);
        }
        let progress = inspector
            .inspect_datagram(&ingress.payload)
            .map_err(|_| ClientIngressUdpError::QuicInspection)?
            .progress;
        *bytes += ingress.payload.len();
        datagrams.push(ingress.payload);
        let InspectionProgress::Complete(server_name) = progress else {
            return Ok(BrowserQuicIngressDecision::NeedMore);
        };
        let hostname = server_name.into_string();
        policy
            .authorize_domain(now_ms, &hostname, TransportProtocol::Udp, BROWSER_QUIC_PORT)
            .map_err(ClientIngressUdpError::Policy)?;
        let expires_at_ms = udp_flow_expiry(policy, now_ms)?;
        let source = *source;
        let destination = *destination;
        let buffered = std::mem::take(datagrams);
        let authorized = buffered
            .into_iter()
            .map(|payload| {
                PolicyAuthorizedUdpIngress::authorize_hostname(
                    ObservedUdpIngress {
                        source,
                        destination,
                        payload,
                    },
                    hostname.clone(),
                    policy,
                    now_ms,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.state = BrowserQuicIngressState::Authorized {
            source,
            destination,
            hostname,
            policy_hash: *policy.policy_hash(),
            expires_at_ms,
        };
        Ok(BrowserQuicIngressDecision::Authorized(authorized))
    }
}

fn udp_flow_expiry(policy: &VerifiedManifest, now_ms: u64) -> Result<u64, ClientIngressUdpError> {
    let expires_at_ms = now_ms
        .checked_add(INGRESS_UDP_FLOW_TTL_MS)
        .ok_or(ClientIngressUdpError::Clock)?
        .min(policy.expires_at_ms());
    (expires_at_ms > now_ms)
        .then_some(expires_at_ms)
        .ok_or(ClientIngressUdpError::Clock)
}

/// One kernel-observed UDP datagram whose exact destination passed the active policy.
///
/// The destination, payload and policy binding are affine and immutable. This is deliberately not
/// yet an [`AuthorizedUdpFlow`]: that type also requires the committed route's ephemeral identity
/// and signature. [`Self::bind_to_route`] performs that second phase without accepting a mutable
/// or caller-substituted destination.
#[must_use = "a policy-authorized ingress datagram must be route-bound or dropped"]
pub(crate) struct PolicyAuthorizedUdpIngress {
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: Vec<u8>,
    policy_hash: [u8; 32],
    expires_at_ms: u64,
    hostname: Option<String>,
}

impl PolicyAuthorizedUdpIngress {
    fn authorize(
        source: SocketAddr,
        destination: SocketAddr,
        payload: Vec<u8>,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        policy
            .authorize_ip(
                now_ms,
                IpAddr::V4(*destination.ip()),
                TransportProtocol::Udp,
                destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        let expires_at_ms = udp_flow_expiry(policy, now_ms)?;
        Ok(Self {
            source,
            destination,
            payload,
            policy_hash: *policy.policy_hash(),
            expires_at_ms,
            hostname: None,
        })
    }

    fn authorize_hostname(
        ingress: ObservedUdpIngress,
        hostname: String,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        policy
            .authorize_domain(
                now_ms,
                &hostname,
                TransportProtocol::Udp,
                ingress.destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        Ok(Self {
            source: ingress.source,
            destination: ingress.destination,
            payload: ingress.payload,
            policy_hash: *policy.policy_hash(),
            expires_at_ms: udp_flow_expiry(policy, now_ms)?,
            hostname: Some(hostname),
        })
    }

    /// Return whether this policy-approved datagram must use genuine Multipath QUIC.
    #[must_use]
    pub(crate) const fn is_browser_quic(&self) -> bool {
        self.destination.port() == BROWSER_QUIC_PORT
    }

    /// Sign and bind the first browser-QUIC datagram to one retained multipath route.
    #[allow(clippy::too_many_arguments)] // Every argument is a separate immutable security scope.
    pub(crate) fn bind_to_multipath_route(
        self,
        route_context_id: [u8; 16],
        client_ephemeral_id: [u8; 32],
        route_expires_at_ms: u64,
        coordinator: &ReservationCoordinator,
        policy: &VerifiedManifest,
        tunnel_source: Ipv4Addr,
        maximum_packet_bytes: usize,
        now_ms: u64,
    ) -> Result<(BrowserQuicFlowBinding, Vec<u8>), ClientIngressUdpError> {
        if !self.is_browser_quic()
            || now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        let expires_at_ms = self.expires_at_ms.min(route_expires_at_ms);
        let signed_authorization = if let Some(hostname) = self.hostname.as_deref() {
            coordinator.sign_udp_hostname_pinned(
                route_context_id,
                self.policy_hash,
                hostname,
                IpAddr::V4(*self.destination.ip()),
                self.destination.port(),
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                expires_at_ms,
            )
        } else {
            coordinator.sign_udp_ip(
                route_context_id,
                self.policy_hash,
                IpAddr::V4(*self.destination.ip()),
                self.destination.port(),
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                expires_at_ms,
            )
        }
        .map_err(ClientIngressUdpError::Sign)?;
        self.bind_signed_to_multipath_route(
            route_context_id,
            client_ephemeral_id,
            route_expires_at_ms,
            policy,
            tunnel_source,
            maximum_packet_bytes,
            &signed_authorization,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)] // Testable signed-flow verification boundary.
    fn bind_signed_to_multipath_route(
        self,
        route_context_id: [u8; 16],
        client_ephemeral_id: [u8; 32],
        route_expires_at_ms: u64,
        policy: &VerifiedManifest,
        tunnel_source: Ipv4Addr,
        maximum_packet_bytes: usize,
        signed_authorization: &[u8],
        now_ms: u64,
    ) -> Result<(BrowserQuicFlowBinding, Vec<u8>), ClientIngressUdpError> {
        let mut replay = ReplayCache::new(1)
            .map_err(|error| ClientIngressUdpError::Authorization(error.into()))?;
        let flow = UdpAuthorizationScope::new_multipath(
            route_context_id,
            client_ephemeral_id,
            route_expires_at_ms,
            policy,
        )
        .map_err(ClientIngressUdpError::Authorization)?
        .verify(
            signed_authorization,
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .map_err(ClientIngressUdpError::Authorization)?;
        if !self.is_browser_quic()
            || self.source.port() == 0
            || self.source.ip().is_unspecified()
            || tunnel_source.is_unspecified()
            || !flow.matches_exact_ip_destination(SocketAddr::V4(self.destination))
            || flow.hostname() != self.hostname.as_deref()
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        let packet = build_ipv4_udp_packet(
            SocketAddrV4::new(tunnel_source, self.source.port()),
            self.destination,
            &self.payload,
            maximum_packet_bytes,
        )?;
        Ok((
            BrowserQuicFlowBinding {
                flow,
                application: self.source,
                remote: self.destination,
                tunnel_source,
                policy_hash: self.policy_hash,
                last_activity_ms: now_ms,
                datagrams: 0,
                signed_authorization: signed_authorization.to_vec(),
            },
            packet,
        ))
    }

    /// Sign and locally verify the exact ingress tuple against one committed single-relay path.
    ///
    /// The returned flow is the same typed [`AuthorizedUdpFlow`] consumed by the production QUIC
    /// activation seam, accompanied by its canonical client signature and original payload.
    pub(crate) fn bind_to_route(
        self,
        path: &VerifiedSingleRelayPath,
        coordinator: &ReservationCoordinator,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        if now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        let signed_authorization = coordinator
            .sign_udp_ip(
                *path.route_context_id(),
                self.policy_hash,
                IpAddr::V4(*self.destination.ip()),
                self.destination.port(),
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                self.expires_at_ms.min(path.expires_at_ms()),
            )
            .map_err(ClientIngressUdpError::Sign)?;
        self.bind_signed_to_route(path, policy, signed_authorization, now_ms)
    }

    fn bind_signed_to_route(
        self,
        path: &VerifiedSingleRelayPath,
        policy: &VerifiedManifest,
        signed_authorization: Vec<u8>,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        let mut replay = ReplayCache::new(1)
            .map_err(|error| ClientIngressUdpError::Authorization(error.into()))?;
        let flow = UdpAuthorizationScope::new(path, policy)
            .verify(
                &signed_authorization,
                now_ms,
                TimePolicy::default(),
                &mut replay,
            )
            .map_err(ClientIngressUdpError::Authorization)?;
        if !flow.matches_exact_ip_destination(SocketAddr::V4(self.destination)) {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        Ok(RouteAuthorizedUdpIngress {
            flow,
            signed_authorization,
            source: self.source,
            destination: self.destination,
            payload: self.payload,
        })
    }
}

/// One helper-intercepted DNS query bound to an active domain policy rule.
#[must_use = "a policy-authorized DNS query must be route-bound or dropped"]
pub(crate) struct PolicyAuthorizedDnsIngress {
    source: SocketAddrV4,
    resolver: SocketAddrV4,
    payload: Vec<u8>,
    hostname: String,
    policy_hash: [u8; 32],
    expires_at_ms: u64,
}

impl PolicyAuthorizedDnsIngress {
    fn authorize(
        source: SocketAddr,
        resolver: SocketAddr,
        payload: Vec<u8>,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        let (SocketAddr::V4(source), SocketAddr::V4(resolver)) = (source, resolver) else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        if source.port() == 0 || resolver.port() != 53 {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        let query = parse_dns_query(&payload).map_err(ClientIngressUdpError::Authorization)?;
        let hostname = policy
            .authorize_dns_name(now_ms, query.name())
            .map_err(ClientIngressUdpError::Policy)?;
        let expires_at_ms = now_ms
            .checked_add(INGRESS_UDP_FLOW_TTL_MS)
            .ok_or(ClientIngressUdpError::Clock)?
            .min(policy.expires_at_ms());
        if expires_at_ms <= now_ms {
            return Err(ClientIngressUdpError::Clock);
        }
        Ok(Self {
            source,
            resolver,
            payload,
            hostname,
            policy_hash: *policy.policy_hash(),
            expires_at_ms,
        })
    }

    pub(crate) fn bind_to_route(
        self,
        path: &VerifiedSingleRelayPath,
        coordinator: &ReservationCoordinator,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        if now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        let hostname = policy
            .authorize_dns_name(now_ms, &self.hostname)
            .map_err(ClientIngressUdpError::Policy)?;
        let signed_authorization = coordinator
            .sign_udp_hostname(
                *path.route_context_id(),
                self.policy_hash,
                &hostname,
                53,
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                self.expires_at_ms.min(path.expires_at_ms()),
            )
            .map_err(ClientIngressUdpError::Sign)?;
        let mut replay = ReplayCache::new(1)
            .map_err(|error| ClientIngressUdpError::Authorization(error.into()))?;
        let flow = UdpAuthorizationScope::new(path, policy)
            .verify(
                &signed_authorization,
                now_ms,
                TimePolicy::default(),
                &mut replay,
            )
            .map_err(ClientIngressUdpError::Authorization)?;
        if !flow.matches_dns_name(&hostname) {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        Ok(RouteAuthorizedUdpIngress {
            flow,
            signed_authorization,
            source: self.source,
            destination: self.resolver,
            payload: self.payload,
        })
    }
}

/// One policy- and route-bound transparent browser-QUIC flow retained across datagrams.
#[must_use = "an active browser QUIC flow must stay attached to its native MPQUIC session"]
pub(crate) struct BrowserQuicFlowBinding {
    flow: AuthorizedUdpFlow,
    application: SocketAddrV4,
    remote: SocketAddrV4,
    tunnel_source: Ipv4Addr,
    policy_hash: [u8; 32],
    last_activity_ms: u64,
    datagrams: u32,
    signed_authorization: Vec<u8>,
}

impl BrowserQuicFlowBinding {
    /// Borrow the exact signed flow consumed by the native MPQUIC boundary.
    pub(crate) const fn flow(&self) -> &AuthorizedUdpFlow {
        &self.flow
    }

    /// Borrow the one-shot authorization sent inside the protected tunnel before Initial data.
    pub(crate) fn signed_authorization(&self) -> &[u8] {
        &self.signed_authorization
    }

    /// Bind another intercepted datagram to the same application/remote tuple and flow.
    pub(crate) fn bind_next(
        &self,
        ingress: &PolicyAuthorizedUdpIngress,
        policy: &VerifiedManifest,
        maximum_packet_bytes: usize,
        now_ms: u64,
    ) -> Result<Vec<u8>, ClientIngressUdpError> {
        self.ensure_live(policy, now_ms)?;
        if !ingress.is_browser_quic()
            || ingress.source != self.application
            || ingress.destination != self.remote
            || ingress.policy_hash.ct_eq(&self.policy_hash).unwrap_u8() != 1
            || now_ms >= ingress.expires_at_ms
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        build_ipv4_udp_packet(
            SocketAddrV4::new(self.tunnel_source, self.application.port()),
            self.remote,
            &ingress.payload,
            maximum_packet_bytes,
        )
    }

    /// Mark one successfully handed-off datagram without extending signed expiry.
    pub(crate) fn record_sent(&mut self, now_ms: u64) -> Result<(), ClientIngressUdpError> {
        self.ensure_activity_bound(now_ms)?;
        self.last_activity_ms = now_ms;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(ClientIngressUdpError::FlowBound)?;
        Ok(())
    }

    /// Validate one full reverse inner IPv4/UDP packet and recover only its UDP payload.
    pub(crate) fn accept_response<'a>(
        &mut self,
        packet: &'a [u8],
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<&'a [u8], ClientIngressUdpError> {
        self.ensure_live(policy, now_ms)?;
        let (source, destination, payload) = parse_ipv4_udp_packet(packet)?;
        let expected_destination = SocketAddrV4::new(self.tunnel_source, self.application.port());
        if source != self.remote || destination != expected_destination {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        self.last_activity_ms = now_ms;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(ClientIngressUdpError::FlowBound)?;
        Ok(payload)
    }

    pub(crate) const fn application(&self) -> SocketAddrV4 {
        self.application
    }

    pub(crate) const fn remote(&self) -> SocketAddrV4 {
        self.remote
    }

    fn ensure_live(
        &self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<(), ClientIngressUdpError> {
        if self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1 {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        self.flow
            .ensure_active_at(now_ms)
            .map_err(ClientIngressUdpError::Authorization)?;
        self.ensure_activity_bound(now_ms)
    }

    fn ensure_activity_bound(&self, now_ms: u64) -> Result<(), ClientIngressUdpError> {
        let idle_timeout_ms = u64::try_from(self.flow.idle_timeout().as_millis())
            .map_err(|_| ClientIngressUdpError::FlowBound)?;
        if now_ms < self.last_activity_ms
            || now_ms.saturating_sub(self.last_activity_ms) >= idle_timeout_ms
            || self.datagrams >= MAX_BROWSER_QUIC_DATAGRAMS_PER_FLOW
        {
            return Err(ClientIngressUdpError::FlowBound);
        }
        Ok(())
    }
}

fn build_ipv4_udp_packet(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
    maximum_packet_bytes: usize,
) -> Result<Vec<u8>, ClientIngressUdpError> {
    let udp_length = UDP_HEADER_BYTES
        .checked_add(payload.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ClientIngressUdpError::PacketBinding)?;
    let packet_length = IPV4_HEADER_BYTES
        .checked_add(usize::from(udp_length))
        .filter(|length| *length <= maximum_packet_bytes)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ClientIngressUdpError::PacketBinding)?;
    let mut packet = vec![0_u8; usize::from(packet_length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    let header_checksum = internet_checksum(&packet[..IPV4_HEADER_BYTES]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source.port().to_be_bytes());
    packet[22..24].copy_from_slice(&destination.port().to_be_bytes());
    packet[24..26].copy_from_slice(&udp_length.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let mut pseudo_datagram = Vec::with_capacity(12 + usize::from(udp_length));
    pseudo_datagram.extend_from_slice(&source.ip().octets());
    pseudo_datagram.extend_from_slice(&destination.ip().octets());
    pseudo_datagram.extend_from_slice(&[0, 17]);
    pseudo_datagram.extend_from_slice(&udp_length.to_be_bytes());
    pseudo_datagram.extend_from_slice(&packet[IPV4_HEADER_BYTES..]);
    let mut udp_checksum = internet_checksum(&pseudo_datagram);
    if udp_checksum == 0 {
        udp_checksum = u16::MAX;
    }
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn parse_ipv4_udp_packet(
    packet: &[u8],
) -> Result<(SocketAddrV4, SocketAddrV4, &[u8]), ClientIngressUdpError> {
    if packet.len() < IPV4_HEADER_BYTES + UDP_HEADER_BYTES
        || packet[0] != 0x45
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || packet[9] != 17
        || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
        || internet_checksum(&packet[..IPV4_HEADER_BYTES]) != 0
    {
        return Err(ClientIngressUdpError::PacketBinding);
    }
    let udp_length = usize::from(u16::from_be_bytes([packet[24], packet[25]]));
    if udp_length < UDP_HEADER_BYTES
        || IPV4_HEADER_BYTES.checked_add(udp_length) != Some(packet.len())
        || packet[26..28] == [0, 0]
    {
        return Err(ClientIngressUdpError::PacketBinding);
    }
    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let source = SocketAddrV4::new(source_ip, u16::from_be_bytes([packet[20], packet[21]]));
    let destination =
        SocketAddrV4::new(destination_ip, u16::from_be_bytes([packet[22], packet[23]]));
    if source.port() == 0 || destination.port() == 0 {
        return Err(ClientIngressUdpError::PacketBinding);
    }
    let mut pseudo_datagram = Vec::with_capacity(12 + udp_length);
    pseudo_datagram.extend_from_slice(&source_ip.octets());
    pseudo_datagram.extend_from_slice(&destination_ip.octets());
    pseudo_datagram.extend_from_slice(&[0, 17]);
    pseudo_datagram.extend_from_slice(&(u16::try_from(udp_length).unwrap_or(0)).to_be_bytes());
    pseudo_datagram.extend_from_slice(&packet[IPV4_HEADER_BYTES..]);
    if internet_checksum(&pseudo_datagram) != 0 {
        return Err(ClientIngressUdpError::PacketBinding);
    }
    Ok((source, destination, &packet[28..]))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [tail] = chunks.remainder() {
        sum = sum.wrapping_add(u32::from(*tail) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = sum.to_be_bytes();
    !u16::from_be_bytes([folded[2], folded[3]])
}

/// Exact inputs needed to activate and seed one production single-relay UDP association.
#[must_use = "a route-authorized ingress datagram must be activated or dropped"]
pub(crate) struct RouteAuthorizedUdpIngress {
    flow: AuthorizedUdpFlow,
    signed_authorization: Vec<u8>,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: Vec<u8>,
}

impl RouteAuthorizedUdpIngress {
    /// Borrow the immutable flow and its exact canonical signature for QUIC activation.
    pub(crate) fn activation(&self) -> (&AuthorizedUdpFlow, &[u8]) {
        (&self.flow, &self.signed_authorization)
    }

    /// Return the application source tuple needed for reverse datagram delivery.
    pub(crate) const fn source(&self) -> SocketAddrV4 {
        self.source
    }

    /// Return the immutable original destination that responses must impersonate locally.
    pub(crate) const fn destination(&self) -> SocketAddrV4 {
        self.destination
    }

    /// Borrow the first intercepted payload without exposing a mutable destination tuple.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

async fn cleanup_prepared_failure(
    helper: &HelperClient,
    prepared: &PreparedClientIngress,
    original: ClientIngressRuntimeError,
) -> ClientIngressRuntimeError {
    match helper.destroy_prepared_client_ingress(prepared).await {
        Ok(_) => original,
        Err(error) => ClientIngressRuntimeError::Rollback(error),
    }
}

fn random_runtime_id() -> Result<[u8; 16], ClientIngressRuntimeError> {
    let mut runtime_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut runtime_id)
        .map_err(|_| ClientIngressRuntimeError::Random)?;
    if runtime_id.iter().all(|byte| *byte == 0) {
        return Err(ClientIngressRuntimeError::Random);
    }
    Ok(runtime_id)
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressRuntimeError {
    #[error("secure client runtime identity generation failed")]
    Random,
    #[error("system clock cannot represent the client ingress deadline")]
    Clock,
    #[error("client ingress prepare failed")]
    Prepare(#[source] HelperClientError),
    #[error("client ingress descriptor acquisition failed")]
    Acquire(#[source] HelperClientError),
    #[error("client ingress descriptor set was incomplete")]
    IncompleteDescriptorSet,
    #[error("client ingress activation failed")]
    Activate(#[source] HelperClientError),
    #[error("client ingress rollback could not be confirmed")]
    Rollback(#[source] HelperClientError),
    #[error("client ingress destruction could not be confirmed")]
    Destroy(#[source] HelperClientError),
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressTcpError {
    #[error("transparent TCP ingress descriptor is unavailable")]
    DescriptorUnavailable,
    #[error("transparent TCP listener duplication failed")]
    Duplicate(#[source] io::Error),
    #[error("transparent TCP accept failed")]
    Accept(#[source] io::Error),
    #[error("transparent TCP original destination recovery failed")]
    OriginalDestination(#[source] io::Error),
    #[error("transparent TCP TLS ClientHello could not be read")]
    ClientHelloRead(#[source] io::Error),
    #[error("transparent TCP TLS ClientHello was unavailable before its deadline")]
    ClientHelloUnavailable,
    #[error("transparent TCP TLS ClientHello identity was not verifiable")]
    ClientHello(#[source] InspectionError),
    #[error("transparent TCP destination was denied by policy")]
    Policy(#[source] PolicyError),
    #[error("transparent TCP authorization lifetime is invalid")]
    Clock,
    #[error("transparent TCP policy binding changed before activation")]
    PolicyBinding,
    #[error("transparent TCP destination binding is invalid")]
    DestinationBinding,
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressUdpError {
    #[error("IPv4 transparent UDP ingress descriptor is unavailable")]
    DescriptorUnavailable,
    #[error("transparent UDP receive failed")]
    Receive(#[source] io::Error),
    #[error("transparent UDP evidence used the wrong address family")]
    AddressFamily,
    #[error("transparent UDP destination was denied by policy")]
    Policy(#[source] PolicyError),
    #[error("transparent UDP authorization lifetime is invalid")]
    Clock,
    #[error("transparent UDP policy binding changed before activation")]
    PolicyBinding,
    #[error("transparent UDP flow signing failed")]
    Sign(#[source] CoordinatorError),
    #[error("transparent UDP route authorization failed")]
    Authorization(#[source] UdpError),
    #[error("signed UDP destination did not match kernel ingress evidence")]
    DestinationBinding,
    #[error("browser QUIC inner IPv4/UDP packet binding is invalid")]
    PacketBinding,
    #[error("browser QUIC ClientHello inspection failed closed")]
    QuicInspection,
    #[error("browser QUIC flow exceeded its idle, lifetime, or datagram bound")]
    FlowBound,
    #[error("UDP reply payload exceeded the fixed datagram bound")]
    ReplyPayload,
    #[error("connected UDP reply descriptor acquisition failed")]
    ReplyAcquire(#[source] HelperClientError),
    #[error("connected UDP reply send failed")]
    Reply(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_protocol::{
        ReplayCache, TimePolicy, Transport, UdpFlowAuthorization, generate_nonce,
        sign_control_message,
    };
    use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};
    use volparossa_udp::VerifiedSingleRelayPath;

    use super::{
        ObservedTcpIngress, ObservedUdpIngress, PolicyAuthorizedUdpIngress,
        authorize_tcp_destination, build_ipv4_udp_packet, parse_ipv4_udp_packet,
    };

    #[tokio::test]
    async fn tls_ingress_retains_visible_sni_and_kernel_destination_pin() {
        const NOW_MS: u64 = 1_900_000_000_000;
        const HOSTNAME: &str = "allowed.example";
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let permission =
            ProtocolPort::new(TransportProtocol::Tcp, destination.port()).expect("TCP permission");
        let rule = DestinationRule::exact_domain(HOSTNAME, [permission]).expect("domain rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener");
        let listener_address = listener.local_addr().expect("listener address");
        let client_hello = tls_client_hello(HOSTNAME);
        let expected_client_hello = client_hello.clone();
        let sender = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listener_address)
                .await
                .expect("test connection");
            stream
                .write_all(&client_hello)
                .await
                .expect("ClientHello write");
        });
        let (stream, _) = listener.accept().await.expect("accepted test stream");

        let authorized = ObservedTcpIngress {
            stream,
            destination,
        }
        .authorize(&policy, NOW_MS)
        .await
        .expect("visible SNI policy authorization");
        let (mut stream, retained_destination, hostname) = authorized
            .into_route_parts(&policy, NOW_MS)
            .expect("retained policy binding");
        sender.await.expect("sender task");
        let mut retained_client_hello = vec![0; expected_client_hello.len()];
        stream
            .read_exact(&mut retained_client_hello)
            .await
            .expect("unconsumed ClientHello");

        assert_eq!(retained_destination, destination);
        assert_eq!(hostname.as_deref(), Some(HOSTNAME));
        assert_eq!(retained_client_hello, expected_client_hello);
    }

    fn tls_client_hello(hostname: &str) -> Vec<u8> {
        let hostname = hostname.as_bytes();
        let mut name_list = vec![0];
        name_list.extend_from_slice(&u16::try_from(hostname.len()).unwrap().to_be_bytes());
        name_list.extend_from_slice(hostname);
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&u16::try_from(name_list.len()).unwrap().to_be_bytes());
        server_name.extend_from_slice(&name_list);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&u16::try_from(server_name.len()).unwrap().to_be_bytes());
        extensions.extend_from_slice(&server_name);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[7_u8; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        handshake.extend_from_slice(&length[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn transparent_tcp_destination_is_bound_to_exact_raw_ip_policy() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let permission =
            ProtocolPort::new(TransportProtocol::Tcp, destination.port()).expect("TCP permission");
        let rule = DestinationRule::exact_ip(destination.ip(), [permission]).expect("IP rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");

        let (policy_hash, expires_at_ms) =
            authorize_tcp_destination(destination, &policy, NOW_MS).expect("authorized TCP");
        assert_eq!(policy_hash, *policy.policy_hash());
        assert!(expires_at_ms > NOW_MS);
        assert!(
            authorize_tcp_destination(
                SocketAddr::from((Ipv4Addr::new(93, 184, 216, 35), 443)),
                &policy,
                NOW_MS,
            )
            .is_err()
        );
    }

    #[test]
    fn ipv4_udp_ingress_becomes_one_exact_policy_and_route_bound_flow() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, destination.port()).expect("UDP permission");
        let rule = DestinationRule::exact_ip(destination.ip(), [permission]).expect("IP rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");
        let ingress = PolicyAuthorizedUdpIngress::authorize(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_000)),
            destination,
            b"alpha-datagram".to_vec(),
            &policy,
            NOW_MS,
        )
        .expect("policy-authorized ingress");

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
        let signed = sign_control_message(
            &UdpFlowAuthorization {
                route_context_id: fixture.route_context_id().to_vec(),
                flow_id: vec![7; 16],
                client_ephemeral_id: fixture.client_session_id().to_vec(),
                hostname: String::new(),
                destination_ip: match destination.ip() {
                    IpAddr::V4(address) => address.octets().to_vec(),
                    IpAddr::V6(_) => unreachable!("IPv4 fixture"),
                },
                port: u32::from(destination.port()),
                policy_hash: policy.policy_hash().to_vec(),
                idle_timeout_ms: 30_000,
                timestamp_ms: NOW_MS,
                expires_at_ms: NOW_MS + 60_000,
                nonce: nonce.to_vec(),
            },
            fixture.client_key(),
            NOW_MS,
            NOW_MS + 60_000,
            nonce,
            TimePolicy::default(),
        )
        .expect("signed exact-IP flow");
        let bound = ingress
            .bind_signed_to_route(&path, &policy, signed, NOW_MS)
            .expect("route-bound flow");
        let (flow, signature) = bound.activation();

        assert!(flow.matches_exact_ip_destination(destination));
        assert!(!signature.is_empty());
        assert_eq!(bound.source(), "10.0.0.2:52000".parse().expect("source"));
        assert_eq!(SocketAddr::V4(bound.destination()), destination);
        assert_eq!(bound.payload(), b"alpha-datagram");
    }

    #[test]
    fn browser_quic_reuses_multipath_flow_with_tunnel_source_and_exact_reverse_packet() {
        const NOW_MS: u64 = 1_900_000_000_000;
        const HOSTNAME: &str = "destination.volparossa.test";
        let application = SocketAddr::from((Ipv4Addr::new(43, 159, 1, 9), 52_000));
        let remote = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, remote.port()).expect("UDP permission");
        let rule = DestinationRule::exact_domain(HOSTNAME, [permission]).expect("domain rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");
        let fixture = SignedRouteFixture::new(2, &[Transport::MultipathQuic], NOW_MS)
            .expect("multipath route");
        let nonce = generate_nonce();
        let signed = sign_control_message(
            &UdpFlowAuthorization {
                route_context_id: fixture.route_context_id().to_vec(),
                flow_id: vec![9; 16],
                client_ephemeral_id: fixture.client_session_id().to_vec(),
                hostname: HOSTNAME.to_owned(),
                destination_ip: match remote.ip() {
                    IpAddr::V4(address) => address.octets().to_vec(),
                    IpAddr::V6(_) => unreachable!("IPv4 fixture"),
                },
                port: u32::from(remote.port()),
                policy_hash: policy.policy_hash().to_vec(),
                idle_timeout_ms: 30_000,
                timestamp_ms: NOW_MS,
                expires_at_ms: NOW_MS + 60_000,
                nonce: nonce.to_vec(),
            },
            fixture.client_key(),
            NOW_MS,
            NOW_MS + 60_000,
            nonce,
            TimePolicy::default(),
        )
        .expect("signed browser flow");
        let ingress = PolicyAuthorizedUdpIngress::authorize_hostname(
            ObservedUdpIngress::new(application, remote, b"quic-one".to_vec())
                .expect("kernel tuple"),
            HOSTNAME.to_owned(),
            &policy,
            NOW_MS,
        )
        .expect("first ingress");
        let tunnel_source = Ipv4Addr::new(10, 76, 0, 2);
        let (mut binding, first_packet) = ingress
            .bind_signed_to_multipath_route(
                *fixture.route_context_id(),
                fixture.client_session_id(),
                NOW_MS + 60_000,
                &policy,
                tunnel_source,
                1_280,
                &signed,
                NOW_MS,
            )
            .expect("multipath-bound browser flow");
        let (first_source, first_remote, first_payload) =
            parse_ipv4_udp_packet(&first_packet).expect("valid full inner packet");
        assert_eq!(first_source, "10.76.0.2:52000".parse().expect("source"));
        assert_eq!(SocketAddr::V4(first_remote), remote);
        assert_eq!(first_payload, b"quic-one");
        assert_eq!(binding.flow().hostname(), Some(HOSTNAME));
        assert!(binding.flow().matches_exact_ip_destination(remote));
        assert!(!binding.signed_authorization().is_empty());
        binding.record_sent(NOW_MS).expect("first handoff");

        let next = PolicyAuthorizedUdpIngress::authorize_hostname(
            ObservedUdpIngress::new(application, remote, b"quic-two".to_vec())
                .expect("next kernel tuple"),
            HOSTNAME.to_owned(),
            &policy,
            NOW_MS + 1,
        )
        .expect("next ingress");
        let next_packet = binding
            .bind_next(&next, &policy, 1_280, NOW_MS + 1)
            .expect("same active flow");
        assert_eq!(
            parse_ipv4_udp_packet(&next_packet)
                .expect("next full inner packet")
                .2,
            b"quic-two"
        );
        binding.record_sent(NOW_MS + 1).expect("next handoff");

        let reverse_packet =
            build_ipv4_udp_packet(first_remote, first_source, b"server-quic", 1_280)
                .expect("reverse inner packet");
        assert_eq!(
            binding
                .accept_response(&reverse_packet, &policy, NOW_MS + 2)
                .expect("exact reverse tuple"),
            b"server-quic"
        );

        let mut corrupted = reverse_packet;
        *corrupted.last_mut().expect("payload") ^= 1;
        assert!(
            binding
                .accept_response(&corrupted, &policy, NOW_MS + 3)
                .is_err()
        );
        assert!(build_ipv4_udp_packet(first_source, first_remote, &[0; 1_253], 1_280).is_err());
    }
}
