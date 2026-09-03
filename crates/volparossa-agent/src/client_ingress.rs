//! Process-owned client ingress capabilities.

#![allow(
    dead_code,
    reason = "the production TCP and UDP route actors consume this complete ingress activation seam"
)]

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::OwnedFd,
    time::Duration,
};

use rand_core::{OsRng, RngCore as _};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::time::{Instant, sleep, timeout_at};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use volparossa_inspection::{
    InspectionError, InspectionProgress, QuicInitialInspector, TlsClientHelloInspector,
};
use volparossa_linux_uapi::{
    IngressSocketFamily as KernelIngressSocketFamily, IngressSocketKind as KernelIngressSocketKind,
    duplicate_descriptor_cloexec, receive_udp_with_original_destination, tcp_original_destination,
    tcp_redirect_original_destination,
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
        AcquiredIngressReplySocket, AcquiredIngressSocket, ActiveClientIngress,
        ClientIngressSocketFamily, ClientIngressSocketIdentity, ClientIngressSocketKind,
        HelperClient, HelperClientError, PreparedClientIngress,
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
const MAX_RETAINED_INGRESS_REPLY_SOCKETS: usize = 64;

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
const IPV6_TRANSPARENT_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::TransparentUdp,
    ClientIngressSocketFamily::Ipv6,
);

const IPV4_DNS_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::DnsUdp,
    ClientIngressSocketFamily::Ipv4,
);
const IPV6_DNS_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::DnsUdp,
    ClientIngressSocketFamily::Ipv6,
);
const IPV4_DNS_TCP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::DnsTcpListener,
    ClientIngressSocketFamily::Ipv4,
);
const IPV6_DNS_TCP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::DnsTcpListener,
    ClientIngressSocketFamily::Ipv6,
);

/// Affine owner of the complete activated ingress descriptor set.
pub(crate) struct ClientIngressRuntime {
    helper: HelperClient,
    active: ActiveClientIngress,
    reply_sockets: Mutex<ExactReplySocketCache<AcquiredIngressReplySocket>>,
}

struct ExactReplySocketCache<T> {
    sockets: HashMap<(SocketAddr, SocketAddr), T>,
}

impl<T> ExactReplySocketCache<T> {
    fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    fn get(&self, remote: SocketAddr, application: SocketAddr) -> Option<&T> {
        self.sockets.get(&(remote, application))
    }

    fn is_full(&self) -> bool {
        self.sockets.len() >= MAX_RETAINED_INGRESS_REPLY_SOCKETS
    }

    fn insert_new(&mut self, remote: SocketAddr, application: SocketAddr, socket: T) -> Option<&T> {
        if self.is_full() {
            return None;
        }
        match self.sockets.entry((remote, application)) {
            std::collections::hash_map::Entry::Vacant(entry) => Some(entry.insert(socket)),
            std::collections::hash_map::Entry::Occupied(_) => None,
        }
    }
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
        Ok(Self {
            helper,
            active,
            reply_sockets: Mutex::new(ExactReplySocketCache::new()),
        })
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
            self.tcp_listener(IPV4_TRANSPARENT_TCP, KernelIngressSocketFamily::Ipv4, false)?,
            self.tcp_listener(IPV6_TRANSPARENT_TCP, KernelIngressSocketFamily::Ipv6, false)?,
        ])
    }

    /// Duplicate both dedicated DNS/TCP listeners into Tokio readiness owners.
    pub(crate) fn dns_tcp_listeners(
        &self,
    ) -> Result<[ClientTcpIngressListener; 2], ClientIngressTcpError> {
        Ok([
            self.tcp_listener(IPV4_DNS_TCP, KernelIngressSocketFamily::Ipv4, true)?,
            self.tcp_listener(IPV6_DNS_TCP, KernelIngressSocketFamily::Ipv6, true)?,
        ])
    }

    fn tcp_listener(
        &self,
        identity: ClientIngressSocketIdentity,
        family: KernelIngressSocketFamily,
        dns_redirect: bool,
    ) -> Result<ClientTcpIngressListener, ClientIngressTcpError> {
        let socket = self
            .active
            .socket(identity)
            .ok_or(ClientIngressTcpError::DescriptorUnavailable)?;
        let descriptor = duplicate_descriptor_cloexec(&socket.descriptor())
            .map_err(ClientIngressTcpError::Duplicate)?;
        ClientTcpIngressListener::from_descriptor(descriptor, family, dns_redirect)
    }

    /// Try to receive one application datagram from the exact requested address family.
    ///
    /// The descriptor is nonblocking. `WouldBlock` is returned unchanged so an actor can wait for
    /// readiness without inventing a destination. The payload and destination enter the returned
    /// affine value only after exact ORIGDST evidence and the active whitelist both agree.
    pub(crate) fn try_receive_udp(
        &self,
        family: ClientIngressSocketFamily,
    ) -> Result<ObservedUdpIngress, ClientIngressUdpError> {
        let (identity, kernel_family) = match family {
            ClientIngressSocketFamily::Ipv4 => {
                (IPV4_TRANSPARENT_UDP, KernelIngressSocketFamily::Ipv4)
            }
            ClientIngressSocketFamily::Ipv6 => {
                (IPV6_TRANSPARENT_UDP, KernelIngressSocketFamily::Ipv6)
            }
        };
        let socket = self
            .active
            .socket(identity)
            .ok_or(ClientIngressUdpError::DescriptorUnavailable)?;
        let local = socket.local_address();
        let mut payload = vec![0_u8; MAX_UDP_PAYLOAD_BYTES];
        let received = receive_udp_with_original_destination(
            &socket.descriptor(),
            KernelIngressSocketKind::TransparentUdp,
            kernel_family,
            local.port(),
            &mut payload,
        )
        .map_err(ClientIngressUdpError::Receive)?;
        payload.truncate(received.bytes());
        ObservedUdpIngress::new(received.source(), received.original_destination(), payload)
    }

    pub(crate) fn duplicate_udp_poll_descriptors(&self) -> Result<[OwnedFd; 2], io::Error> {
        Ok([
            self.duplicate_poll_descriptor(IPV4_TRANSPARENT_UDP)?,
            self.duplicate_poll_descriptor(IPV6_TRANSPARENT_UDP)?,
        ])
    }

    /// Receive one dedicated DNS datagram and authorize only its bounded A/AAAA query name.
    pub(crate) fn try_receive_dns_udp(
        &self,
        family: ClientIngressSocketFamily,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedDnsIngress, ClientIngressUdpError> {
        let (identity, kernel_family) = match family {
            ClientIngressSocketFamily::Ipv4 => (IPV4_DNS_UDP, KernelIngressSocketFamily::Ipv4),
            ClientIngressSocketFamily::Ipv6 => (IPV6_DNS_UDP, KernelIngressSocketFamily::Ipv6),
        };
        let socket = self
            .active
            .socket(identity)
            .ok_or(ClientIngressUdpError::DescriptorUnavailable)?;
        let local = socket.local_address();
        let mut payload = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
        let received = receive_udp_with_original_destination(
            &socket.descriptor(),
            KernelIngressSocketKind::DnsUdp,
            kernel_family,
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

    pub(crate) fn duplicate_dns_udp_poll_descriptors(&self) -> Result<[OwnedFd; 2], io::Error> {
        Ok([
            self.duplicate_poll_descriptor(IPV4_DNS_UDP)?,
            self.duplicate_poll_descriptor(IPV6_DNS_UDP)?,
        ])
    }

    fn duplicate_poll_descriptor(
        &self,
        identity: ClientIngressSocketIdentity,
    ) -> Result<OwnedFd, io::Error> {
        let socket = self.active.socket(identity).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "client ingress descriptor unavailable",
            )
        })?;
        duplicate_descriptor_cloexec(&socket.descriptor())
    }

    pub(crate) async fn send_udp_response(
        &self,
        application: SocketAddr,
        remote: SocketAddr,
        payload: &[u8],
    ) -> Result<(), ClientIngressUdpError> {
        if payload.len() > MAX_UDP_PAYLOAD_BYTES {
            return Err(ClientIngressUdpError::ReplyPayload);
        }
        let mut reply_sockets = self.reply_sockets.lock().await;
        if let Some(reply) = reply_sockets.get(remote, application) {
            return reply.send(payload).map_err(ClientIngressUdpError::Reply);
        }
        if reply_sockets.is_full() {
            return Err(ClientIngressUdpError::FlowBound);
        }
        let reply = self
            .helper
            .acquire_ingress_reply_socket(&self.active, remote, application)
            .await
            .map_err(ClientIngressUdpError::ReplyAcquire)?;
        if reply.remote() != remote || reply.application() != application {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        let reply = reply_sockets
            .insert_new(remote, application, reply)
            .ok_or(ClientIngressUdpError::FlowBound)?;
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
    dns_redirect: bool,
}

impl ClientTcpIngressListener {
    fn from_descriptor(
        descriptor: OwnedFd,
        family: KernelIngressSocketFamily,
        dns_redirect: bool,
    ) -> Result<Self, ClientIngressTcpError> {
        let listener = std::net::TcpListener::from(descriptor);
        listener
            .set_nonblocking(true)
            .map_err(ClientIngressTcpError::Duplicate)?;
        Ok(Self {
            listener: TcpListener::from_std(listener).map_err(ClientIngressTcpError::Duplicate)?,
            family,
            dns_redirect,
        })
    }

    /// Accept one application stream and recover its immutable kernel original destination.
    pub(crate) async fn accept(&self) -> Result<ObservedTcpIngress, ClientIngressTcpError> {
        let (stream, source) = self
            .listener
            .accept()
            .await
            .map_err(ClientIngressTcpError::Accept)?;
        let destination = if self.dns_redirect {
            tcp_redirect_original_destination(&stream, self.family, 53)
        } else {
            tcp_original_destination(&stream, self.family)
        }
        .map_err(ClientIngressTcpError::OriginalDestination)?;
        Ok(ObservedTcpIngress {
            stream,
            source,
            destination,
        })
    }
}

/// One accepted transparent stream whose destination came only from kernel TPROXY evidence.
#[must_use = "an observed TCP ingress stream must be policy-bound or dropped"]
pub(crate) struct ObservedTcpIngress {
    stream: TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
}

impl ObservedTcpIngress {
    /// Consume a dedicated DNS listener result into its stream and exact family-matched tuples.
    pub(crate) fn into_dns_parts(
        self,
    ) -> Result<(TcpStream, SocketAddr, SocketAddr), ClientIngressTcpError> {
        if self.source.port() == 0
            || self.destination.port() != 53
            || self.source.is_ipv4() != self.destination.is_ipv4()
        {
            return Err(ClientIngressTcpError::DestinationBinding);
        }
        Ok((self.stream, self.source, self.destination))
    }

    /// Bind the kernel-observed tuple to the active manifest. TCP/443 and destinations which are
    /// not independently authorised by exact IP require a visible policy-approved SNI and retain
    /// the original address as an Exit-side DNS pin. This keeps domain policy usable on explicit
    /// non-standard TLS ports without turning an arbitrary denied raw-IP flow into egress.
    pub(crate) async fn authorize(
        self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedTcpIngress, ClientIngressTcpError> {
        let exact_ip_authorized = policy
            .authorize_ip(
                now_ms,
                self.destination.ip(),
                TransportProtocol::Tcp,
                self.destination.port(),
            )
            .is_ok();
        let requires_visible_name =
            self.destination.port() == BROWSER_QUIC_PORT || !exact_ip_authorized;
        let (hostname, policy_hash, expires_at_ms) = if requires_visible_name {
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
    /// Re-authorize the exact inspected hostname and kernel-observed tuple once route setup is
    /// complete. Building a production route can outlive the short ingress binding; the buffered
    /// application stream remains affine, but its policy snapshot must be current before signing.
    pub(crate) fn reauthorize_after_route_ready(
        mut self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressTcpError> {
        if let Some(hostname) = self.hostname.as_deref() {
            policy
                .authorize_domain(
                    now_ms,
                    hostname,
                    TransportProtocol::Tcp,
                    self.destination.port(),
                )
                .map_err(ClientIngressTcpError::Policy)?;
            self.policy_hash = *policy.policy_hash();
            self.expires_at_ms = tcp_flow_expiry(policy, now_ms)?;
        } else {
            let (policy_hash, expires_at_ms) =
                authorize_tcp_destination(self.destination, policy, now_ms)?;
            self.policy_hash = policy_hash;
            self.expires_at_ms = expires_at_ms;
        }
        Ok(self)
    }

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
    source: SocketAddr,
    destination: SocketAddr,
    payload: Vec<u8>,
}

impl ObservedUdpIngress {
    fn new(
        source: SocketAddr,
        destination: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<Self, ClientIngressUdpError> {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(ClientIngressUdpError::AddressFamily);
        }
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
            self.source,
            self.destination,
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
        source: SocketAddr,
        destination: SocketAddr,
        inspector: Box<QuicInitialInspector>,
        datagrams: Vec<Vec<u8>>,
        bytes: usize,
    },
    Authorized {
        source: SocketAddr,
        destination: SocketAddr,
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

    /// Re-authorize buffered Initial datagrams after asynchronous route establishment.
    ///
    /// Route construction may outlive the policy snapshot used while inspecting the QUIC
    /// `ClientHello`. The inspector-owned hostname and exact kernel-observed tuple stay affine in
    /// this gate; this transition checks them against the policy that is active when the route is
    /// ready and refreshes every datagram's policy binding before any authorization is signed.
    pub(crate) fn reauthorize_after_route_ready(
        &mut self,
        ingresses: Vec<PolicyAuthorizedUdpIngress>,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Vec<PolicyAuthorizedUdpIngress>, ClientIngressUdpError> {
        let (source, destination, hostname) = match &self.state {
            BrowserQuicIngressState::Authorized {
                source,
                destination,
                hostname,
                ..
            } => (*source, *destination, hostname.clone()),
            BrowserQuicIngressState::Empty | BrowserQuicIngressState::Pending { .. } => {
                return Err(ClientIngressUdpError::FlowBound);
            }
        };
        if ingresses.is_empty()
            || ingresses.iter().any(|ingress| {
                !ingress.is_browser_quic()
                    || ingress.source != source
                    || ingress.destination != destination
                    || ingress.hostname.as_deref() != Some(hostname.as_str())
            })
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        policy
            .authorize_domain(
                now_ms,
                &hostname,
                TransportProtocol::Udp,
                destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        let expires_at_ms = udp_flow_expiry(policy, now_ms)?;
        let policy_hash = *policy.policy_hash();
        let refreshed = ingresses
            .into_iter()
            .map(|mut ingress| {
                ingress.policy_hash = policy_hash;
                ingress.expires_at_ms = expires_at_ms;
                ingress
            })
            .collect();
        self.state = BrowserQuicIngressState::Authorized {
            source,
            destination,
            hostname,
            policy_hash,
            expires_at_ms,
        };
        Ok(refreshed)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded affine QUIC Initial reassembly and policy transition"
    )]
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
                inspector: Box::new(inspector),
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
    source: SocketAddr,
    destination: SocketAddr,
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
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(ClientIngressUdpError::AddressFamily);
        }
        policy
            .authorize_ip(
                now_ms,
                destination.ip(),
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

    /// Re-authorize one exact-IP datagram after asynchronous route establishment.
    ///
    /// Route construction can outlive the short ingress authorization. The observed source,
    /// destination and payload remain affine in `self`; only the active policy binding and its
    /// bounded expiry are refreshed before the route coordinator signs them.
    pub(crate) fn reauthorize_ip_after_route_ready(
        mut self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        if self.hostname.is_some() || self.is_browser_quic() {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        policy
            .authorize_ip(
                now_ms,
                self.destination.ip(),
                TransportProtocol::Udp,
                self.destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        self.policy_hash = *policy.policy_hash();
        self.expires_at_ms = udp_flow_expiry(policy, now_ms)?;
        Ok(self)
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
                self.destination.ip(),
                self.destination.port(),
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                expires_at_ms,
            )
        } else {
            coordinator.sign_udp_ip(
                route_context_id,
                self.policy_hash,
                self.destination.ip(),
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
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (self.source, self.destination)
        else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        if !self.is_browser_quic()
            || source.port() == 0
            || source.ip().is_unspecified()
            || tunnel_source.is_unspecified()
            || !flow.matches_exact_ip_destination(SocketAddr::V4(destination))
            || flow.hostname() != self.hostname.as_deref()
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        let packet = build_ipv4_udp_packet(
            SocketAddrV4::new(tunnel_source, source.port()),
            destination,
            &self.payload,
            maximum_packet_bytes,
        )?;
        Ok((
            BrowserQuicFlowBinding {
                flow,
                application: source,
                remote: destination,
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
        idle_timeout: Duration,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        if now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        let idle_timeout_ms = u32::try_from(idle_timeout.as_millis())
            .ok()
            .filter(|timeout| *timeout > 0)
            .ok_or(ClientIngressUdpError::FlowBound)?;
        let signed_authorization = coordinator
            .sign_udp_ip(
                *path.route_context_id(),
                self.policy_hash,
                self.destination.ip(),
                self.destination.port(),
                idle_timeout_ms,
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
        if !flow.matches_exact_ip_destination(self.destination) {
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
    source: SocketAddr,
    resolver: SocketAddr,
    payload: Vec<u8>,
    hostname: String,
    policy_hash: [u8; 32],
    expires_at_ms: u64,
}

impl PolicyAuthorizedDnsIngress {
    pub(crate) fn authorize(
        source: SocketAddr,
        resolver: SocketAddr,
        payload: Vec<u8>,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        if source.is_ipv4() != resolver.is_ipv4() {
            return Err(ClientIngressUdpError::AddressFamily);
        }
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
            || ingress.source != SocketAddr::V4(self.application)
            || ingress.destination != SocketAddr::V4(self.remote)
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

    /// Borrow the signed destination and exact tunnel return tuple used to demultiplex replies.
    pub(crate) fn receive_scope(&self) -> (&AuthorizedUdpFlow, SocketAddrV4) {
        (
            &self.flow,
            SocketAddrV4::new(self.tunnel_source, self.application.port()),
        )
    }

    /// Return whether one freshly inspected datagram belongs to this retained application flow.
    pub(crate) fn matches_ingress_tuple(&self, ingress: &PolicyAuthorizedUdpIngress) -> bool {
        ingress.is_browser_quic()
            && ingress.source == SocketAddr::V4(self.application)
            && ingress.destination == SocketAddr::V4(self.remote)
    }

    /// Return whether this exact policy and signed flow binding can still carry data.
    pub(crate) fn is_live(&self, policy: &VerifiedManifest, now_ms: u64) -> bool {
        self.ensure_live(policy, now_ms).is_ok()
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
    source: SocketAddr,
    destination: SocketAddr,
    payload: Vec<u8>,
}

impl RouteAuthorizedUdpIngress {
    /// Borrow the immutable flow and its exact canonical signature for QUIC activation.
    pub(crate) fn activation(&self) -> (&AuthorizedUdpFlow, &[u8]) {
        (&self.flow, &self.signed_authorization)
    }

    /// Return the application source tuple needed for reverse datagram delivery.
    pub(crate) const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Return the immutable original destination that responses must impersonate locally.
    pub(crate) const fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Borrow the first intercepted payload without exposing a mutable destination tuple.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume another datagram only when it belongs to this exact live single-relay flow.
    ///
    /// The first datagram already carried the signed authorization through the native tunnel.
    /// Continuations therefore reuse that immutable authority and may change neither the local
    /// application tuple nor the remote destination. A changed policy or expired authorization
    /// closes the continuation instead of silently creating a different UDP association.
    pub(crate) fn bind_next_native_datagram(
        &self,
        ingress: PolicyAuthorizedUdpIngress,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Vec<u8>, ClientIngressUdpError> {
        self.flow
            .ensure_active_at(now_ms)
            .map_err(ClientIngressUdpError::Authorization)?;
        if now_ms >= ingress.expires_at_ms
            || ingress.hostname.is_some()
            || ingress.source != self.source
            || ingress.destination != self.destination
            || ingress.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
            || !self.flow.matches_exact_ip_destination(ingress.destination)
        {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        policy
            .authorize_ip(
                now_ms,
                ingress.destination.ip(),
                TransportProtocol::Udp,
                ingress.destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        Ok(ingress.payload)
    }

    /// Validate a reverse native CONNECT-IP packet and expose only its application payload.
    ///
    /// The native session has already pinned the tunnel Client address; this final boundary also
    /// requires the exact remote source and original application port retained from ingress.
    pub(crate) fn accept_native_response<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<&'a [u8], ClientIngressUdpError> {
        let (SocketAddr::V4(expected_source), SocketAddr::V4(expected_destination)) =
            (self.destination, self.source)
        else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        let (source, destination, payload) = parse_ipv4_udp_packet(packet)?;
        if source != expected_source || destination.port() != expected_destination.port() {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        Ok(payload)
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol, VerifiedManifest};
    use volparossa_protocol::{
        ReplayCache, TimePolicy, Transport, UdpFlowAuthorization, generate_nonce,
        sign_control_message,
    };
    use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};
    use volparossa_udp::VerifiedSingleRelayPath;

    use super::{
        BrowserQuicIngressGate, BrowserQuicIngressState, ClientIngressUdpError,
        ExactReplySocketCache, MAX_RETAINED_INGRESS_REPLY_SOCKETS, ObservedTcpIngress,
        ObservedUdpIngress, PolicyAuthorizedDnsIngress, PolicyAuthorizedUdpIngress,
        authorize_tcp_destination, build_ipv4_udp_packet, parse_ipv4_udp_packet,
    };

    #[tokio::test]
    async fn tls_ingress_on_policy_port_retains_visible_sni_and_kernel_destination_pin() {
        const NOW_MS: u64 = 1_900_000_000_000;
        const HOSTNAME: &str = "allowed.example";
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 18_443));
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
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)),
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

    #[test]
    fn ingress_reply_socket_is_reused_beyond_helper_issuance_limit() {
        let remote = SocketAddr::from((Ipv4Addr::new(47, 163, 4, 2), 443));
        let application = SocketAddr::from((Ipv4Addr::new(43, 159, 1, 1), 52_006));
        let mut cache = ExactReplySocketCache::new();
        let mut acquisitions = 0_u32;

        for _ in 0..=MAX_RETAINED_INGRESS_REPLY_SOCKETS {
            if cache.get(remote, application).is_none() {
                acquisitions += 1;
                cache
                    .insert_new(remote, application, 7_u8)
                    .expect("first exact reply socket retained");
            }
            assert_eq!(cache.get(remote, application), Some(&7));
        }

        assert_eq!(acquisitions, 1);
        assert_eq!(cache.sockets.len(), 1);
    }

    #[tokio::test]
    async fn tcp_ingress_refreshes_policy_binding_after_slow_route_establishment() {
        const OBSERVED_MS: u64 = 1_900_000_000_000;
        const ROUTE_READY_MS: u64 = OBSERVED_MS + 61_000;
        const HOSTNAME: &str = "destination.volparossa.test";
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 18_443));
        let permission =
            ProtocolPort::new(TransportProtocol::Tcp, destination.port()).expect("TCP permission");
        let rule = DestinationRule::exact_domain(HOSTNAME, [permission]).expect("domain rule");
        let observed_policy =
            verified_development_manifest(OBSERVED_MS, vec![rule.clone()]).expect("old policy");
        let ready_policy =
            verified_development_manifest(ROUTE_READY_MS, vec![rule]).expect("active policy");

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
        let ingress = ObservedTcpIngress {
            stream,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)),
            destination,
        }
        .authorize(&observed_policy, OBSERVED_MS)
        .await
        .expect("initial visible-SNI authorization");
        assert!(ROUTE_READY_MS >= ingress.expires_at_ms);

        let ingress = ingress
            .reauthorize_after_route_ready(&ready_policy, ROUTE_READY_MS)
            .expect("exact inspected binding re-authorized at route readiness");
        assert_eq!(ingress.policy_hash, *ready_policy.policy_hash());
        assert!(ingress.expires_at_ms > ROUTE_READY_MS);
        let (mut stream, retained_destination, hostname) = ingress
            .into_route_parts(&ready_policy, ROUTE_READY_MS)
            .expect("refreshed policy binding");
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
        assert_eq!(bound.destination(), destination);
        assert_eq!(bound.payload(), b"alpha-datagram");

        let continuation = PolicyAuthorizedUdpIngress::authorize(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_000)),
            destination,
            b"second-datagram".to_vec(),
            &policy,
            NOW_MS + 1,
        )
        .expect("policy-authorized continuation");
        assert_eq!(
            bound
                .bind_next_native_datagram(continuation, &policy, NOW_MS + 1)
                .expect("same-flow continuation"),
            b"second-datagram"
        );

        let changed_source = PolicyAuthorizedUdpIngress::authorize(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_001)),
            destination,
            b"wrong-flow".to_vec(),
            &policy,
            NOW_MS + 1,
        )
        .expect("policy-authorized different source");
        assert!(
            bound
                .bind_next_native_datagram(changed_source, &policy, NOW_MS + 1)
                .is_err()
        );
    }

    #[test]
    fn general_udp_refreshes_policy_binding_after_slow_route_establishment() {
        const OBSERVED_MS: u64 = 1_900_000_000_000;
        const ROUTE_READY_MS: u64 = OBSERVED_MS + 61_000;
        let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_000));
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 18_081));
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, destination.port()).expect("UDP permission");
        let rule = DestinationRule::exact_ip(destination.ip(), [permission]).expect("IP rule");
        let observed_policy =
            verified_development_manifest(OBSERVED_MS, vec![rule.clone()]).expect("old policy");
        let ready_policy =
            verified_development_manifest(ROUTE_READY_MS, vec![rule]).expect("active policy");
        let ingress = PolicyAuthorizedUdpIngress::authorize(
            source,
            destination,
            b"buffered-datagram".to_vec(),
            &observed_policy,
            OBSERVED_MS,
        )
        .expect("observed ingress");
        assert!(ROUTE_READY_MS >= ingress.expires_at_ms);

        let refreshed = ingress
            .reauthorize_ip_after_route_ready(&ready_policy, ROUTE_READY_MS)
            .expect("exact tuple re-authorized at route readiness");
        assert_eq!(refreshed.source, source);
        assert_eq!(refreshed.destination, destination);
        assert_eq!(refreshed.payload, b"buffered-datagram");
        assert!(refreshed.hostname.is_none());
        assert_eq!(refreshed.policy_hash, *ready_policy.policy_hash());
        assert!(refreshed.expires_at_ms > ROUTE_READY_MS);

        let denied_policy =
            verified_development_manifest(ROUTE_READY_MS, Vec::new()).expect("denying policy");
        assert!(matches!(
            refreshed.reauthorize_ip_after_route_ready(&denied_policy, ROUTE_READY_MS),
            Err(ClientIngressUdpError::Policy(_))
        ));
    }

    #[test]
    fn ipv6_udp_and_dns_ingress_retain_exact_family_bound_tuples() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let application = SocketAddr::from((Ipv6Addr::new(0xfd76, 0, 0, 0, 0, 0, 0, 7), 52_000));
        let destination = SocketAddr::from((
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            18_081,
        ));
        let udp_permission =
            ProtocolPort::new(TransportProtocol::Udp, destination.port()).expect("UDP permission");
        let udp_rule =
            DestinationRule::exact_ip(destination.ip(), [udp_permission]).expect("IPv6 rule");
        let udp_policy =
            verified_development_manifest(NOW_MS, vec![udp_rule]).expect("IPv6 policy");
        let observed = ObservedUdpIngress::new(application, destination, b"ipv6-datagram".to_vec())
            .expect("IPv6 kernel tuple");
        let authorized = observed
            .authorize_ip(&udp_policy, NOW_MS)
            .expect("IPv6 policy authorization");
        assert_eq!(authorized.source, application);
        assert_eq!(authorized.destination, destination);

        let dns_permission = ProtocolPort::new(TransportProtocol::Udp, 53).expect("DNS permission");
        let dns_rule =
            DestinationRule::exact_domain("allowed.example", [dns_permission]).expect("DNS rule");
        let dns_policy = verified_development_manifest(NOW_MS, vec![dns_rule]).expect("DNS policy");
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[
            7, b'a', b'l', b'l', b'o', b'w', b'e', b'd', 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 0, 0, 1, 0, 1,
        ]);
        let resolver = SocketAddr::from((destination.ip(), 53));
        let dns = PolicyAuthorizedDnsIngress::authorize(
            application,
            resolver,
            query,
            &dns_policy,
            NOW_MS,
        )
        .expect("IPv6 protected DNS authorization");
        assert_eq!(dns.source, application);
        assert_eq!(dns.resolver, resolver);
    }

    fn authorize_browser_quic_test_ingress(
        application: SocketAddr,
        remote: SocketAddr,
        payload: &[u8],
        hostname: &str,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> PolicyAuthorizedUdpIngress {
        PolicyAuthorizedUdpIngress::authorize_hostname(
            ObservedUdpIngress::new(application, remote, payload.to_vec()).expect("kernel tuple"),
            hostname.to_owned(),
            policy,
            now_ms,
        )
        .expect("browser ingress")
    }

    #[test]
    fn browser_quic_refreshes_policy_binding_after_slow_route_establishment() {
        const INSPECTION_MS: u64 = 1_900_000_000_000;
        const ROUTE_READY_MS: u64 = INSPECTION_MS + 61_000;
        const HOSTNAME: &str = "destination.volparossa.test";
        let application = SocketAddrV4::new(Ipv4Addr::new(43, 159, 1, 9), 52_000);
        let remote = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, remote.port()).expect("UDP permission");
        let rule = DestinationRule::exact_domain(HOSTNAME, [permission]).expect("domain rule");
        let inspected_policy =
            verified_development_manifest(INSPECTION_MS, vec![rule.clone()]).expect("old policy");
        let ready_policy =
            verified_development_manifest(ROUTE_READY_MS, vec![rule]).expect("active policy");
        let ingress = authorize_browser_quic_test_ingress(
            application.into(),
            remote.into(),
            b"buffered-initial",
            HOSTNAME,
            &inspected_policy,
            INSPECTION_MS,
        );
        assert!(ROUTE_READY_MS >= ingress.expires_at_ms);
        let mut gate = BrowserQuicIngressGate {
            state: BrowserQuicIngressState::Authorized {
                source: application.into(),
                destination: remote.into(),
                hostname: HOSTNAME.to_owned(),
                policy_hash: *inspected_policy.policy_hash(),
                expires_at_ms: ingress.expires_at_ms,
            },
        };

        let refreshed = gate
            .reauthorize_after_route_ready(vec![ingress], &ready_policy, ROUTE_READY_MS)
            .expect("exact inspected tuple re-authorized at route readiness");
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].source, SocketAddr::V4(application));
        assert_eq!(refreshed[0].destination, SocketAddr::V4(remote));
        assert_eq!(refreshed[0].payload, b"buffered-initial");
        assert_eq!(refreshed[0].hostname.as_deref(), Some(HOSTNAME));
        assert_eq!(refreshed[0].policy_hash, *ready_policy.policy_hash());
        assert!(refreshed[0].expires_at_ms > ROUTE_READY_MS);
        let BrowserQuicIngressState::Authorized {
            policy_hash,
            expires_at_ms,
            ..
        } = &gate.state
        else {
            panic!("route-ready authorization retained");
        };
        assert_eq!(*policy_hash, *ready_policy.policy_hash());
        assert!(*expires_at_ms > ROUTE_READY_MS);

        let denied_policy =
            verified_development_manifest(ROUTE_READY_MS, Vec::new()).expect("denying policy");
        assert!(matches!(
            gate.reauthorize_after_route_ready(refreshed, &denied_policy, ROUTE_READY_MS),
            Err(ClientIngressUdpError::Policy(_))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end regression binds both browser flows and the reverse packet"
    )]
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
        let ingress = authorize_browser_quic_test_ingress(
            application,
            remote,
            b"quic-one",
            HOSTNAME,
            &policy,
            NOW_MS,
        );
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

        let next = authorize_browser_quic_test_ingress(
            application,
            remote,
            b"quic-two",
            HOSTNAME,
            &policy,
            NOW_MS + 1,
        );
        assert!(binding.matches_ingress_tuple(&next));
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

        let next_connection = authorize_browser_quic_test_ingress(
            SocketAddr::from((Ipv4Addr::new(43, 159, 1, 9), 52_001)),
            remote,
            b"next-connection",
            HOSTNAME,
            &policy,
            NOW_MS + 2,
        );
        assert!(!binding.matches_ingress_tuple(&next_connection));

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
