//! Policy-enforcing VOLPAROSSA exit admission and egress primitives.
//!
//! Exit mode is disabled unless the operator explicitly supplies enabled
//! limits. Every route requires signed exit and relay reservations. TCP and UDP
//! flow openings reuse the replay-protected protocol and threshold-signed
//! policy crates. The exit resolves names itself and pins only public Internet
//! addresses. Every hostname-authorized TCP flow additionally requires a visible matching SNI
//! and rejects ECH. UDP/443 uses a separate typestate boundary that authenticates
//! bounded QUIC v1 Initial packets and releases no egress-capable flow until a
//! visible SNI exactly matches the signed destination.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[allow(
    dead_code,
    reason = "private Ready/Result phases still await same-helper and datapath providers"
)]
mod native_preselection;
mod reservation_v4;

pub use native_preselection::{
    AcceptedNativeProbeExitReady, AcceptedNativeProbeExitResult,
    AcceptedNativeProbeRelayAuthorization,
};
pub use reservation_v4::{
    AcceptedExitCapacityHold, AcceptedExitConfirmation, AcceptedRelayProbePermit, ProbeEvidence,
    ProbeEvidenceError, ProbeEvidenceVerifier,
};

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use sha2::{Digest, Sha256};
use socket2::SockRef;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream, lookup_host},
    sync::Mutex,
    time,
};
use volparossa_core::{
    Bandwidth, CONTRIBUTION_SOCKET_PRIORITY, ClientEphemeralId, NodeId, ReservationId,
    RouteContextId, ServiceRole, Transport as CoreTransport, UnixTime,
};
use volparossa_inspection::{
    InspectionError, InspectionProgress, QuicInitialInspector, TlsClientHelloInspector,
};
use volparossa_metrics::MetricsRegistry;
use volparossa_policy::{PolicyError, VerifiedManifest, normalize_domain};
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, NativeRouteCredentialDelivery,
    NativeRouteCredentialError, NativeRouteCredentialKeyPair, NativeRouteIdentity, ProtocolError,
    ReplayCache, SignedEnvelope, TimePolicy, Transport, UdpFlowAuthorization, decode_canonical,
    node_id_from_public_key, verify_control_message,
};
use volparossa_reservation::{
    AuthorizedReservation, AvailableCapacity, CapacityLedger, LedgerLimits, ReservationError,
};
use volparossa_tcp_proxy::{
    AuthorizedTcpFlow, StreamTransferLimits, StreamTransferStats, TcpAuthorizationScope,
    TcpProxyError, VerifiedMptcpRoute, proxy_bidirectional, read_authorized_open_tcp,
};
use volparossa_udp::{
    AuthorizedUdpFlow, DatagramLimits, ExitUdpBridge, QuicUdpAssociation, UdpAuthorizationScope,
    UdpError, VerifiedSingleRelayPath,
};
use volparossa_wireguard::{
    ExitEndpointLease, HelperContextHandle, PublicWireGuardEndpoint, WireGuardPublicKey,
};
use zeroize::Zeroizing;

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;
const MAX_SESSIONS: u32 = 100_000;
const MAX_IDEMPOTENCY_ENTRIES: usize = 4_096;
const MAX_TTL_SECONDS: u64 = 15 * 60;
const MAX_DNS_RESULTS: usize = 16;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const CLIENT_HELLO_CHUNK_BYTES: usize = 4 * 1024;
const MAX_EGRESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TLS_CERTIFICATE_PEM: usize = 64 * 1024;
const MAX_TLS_PRIVATE_KEY_PEM: usize = 16 * 1024;

/// Exact public scope presented to a native-route identity provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitNativeRouteIdentityRequest {
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    finalize_id: [u8; ID_BYTES],
    auth_commitment: [u8; NODE_ID_BYTES],
    masque_context_id: u64,
    client_native_instance_id: [u8; NODE_ID_BYTES],
    exit_native_instance_id: [u8; NODE_ID_BYTES],
}

impl ExitNativeRouteIdentityRequest {
    /// Construct one exact, non-zero finalization scope.
    ///
    /// # Errors
    ///
    /// Zero identifiers and out-of-range MASQUE context identifiers are rejected.
    pub fn new(
        reservation_id: [u8; ID_BYTES],
        route_context_id: [u8; ID_BYTES],
        finalize_id: [u8; ID_BYTES],
        auth_commitment: [u8; NODE_ID_BYTES],
        masque_context_id: u64,
        client_native_instance_id: [u8; NODE_ID_BYTES],
        exit_native_instance_id: [u8; NODE_ID_BYTES],
    ) -> Result<Self, ExitNativeRouteIdentityError> {
        if reservation_id == [0; ID_BYTES]
            || route_context_id == [0; ID_BYTES]
            || finalize_id == [0; ID_BYTES]
            || auth_commitment == [0; NODE_ID_BYTES]
            || masque_context_id == 0
            || masque_context_id > volparossa_protocol::MAX_MASQUE_CONTEXT_ID
            || client_native_instance_id == [0; NODE_ID_BYTES]
            || exit_native_instance_id == [0; NODE_ID_BYTES]
        {
            return Err(ExitNativeRouteIdentityError::Rejected(
                "invalid native route request scope",
            ));
        }
        Ok(Self {
            reservation_id,
            route_context_id,
            finalize_id,
            auth_commitment,
            masque_context_id,
            client_native_instance_id,
            exit_native_instance_id,
        })
    }

    /// Return the exact reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the exact route-context identifier.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the exact finalization identifier.
    #[must_use]
    pub const fn finalize_id(&self) -> &[u8; ID_BYTES] {
        &self.finalize_id
    }

    /// Return the client-created native authentication commitment.
    #[must_use]
    pub const fn auth_commitment(&self) -> &[u8; NODE_ID_BYTES] {
        &self.auth_commitment
    }

    /// Return the exact RFC 9484 MASQUE context identifier.
    #[must_use]
    pub const fn masque_context_id(&self) -> u64 {
        self.masque_context_id
    }

    /// Return the exact client native-process incarnation.
    #[must_use]
    pub const fn client_native_instance_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.client_native_instance_id
    }

    /// Return the native-reported exit process incarnation.
    #[must_use]
    pub const fn exit_native_instance_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.exit_native_instance_id
    }
}

/// Rejection reported by a native-route identity provider or owner constructor.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExitNativeRouteIdentityError {
    /// No production identity and secret owner is available.
    #[error("native route identity provider is unavailable")]
    Unavailable,
    /// The provider rejected or contradicted the exact request scope.
    #[error("native route identity rejected: {0}")]
    Rejected(&'static str),
}

/// Trusted producer of a route-scoped public TLS identity and its private owner.
///
/// Implementations must use the native-reported exit incarnation supplied in
/// the request and must not substitute or invent one. Returning a value does
/// not activate or expose a listener.
pub trait ExitNativeRouteIdentityProvider {
    /// Supply one non-cloneable identity owner bound to the exact request.
    ///
    /// # Errors
    ///
    /// Returns unavailable when no production producer exists, or rejected
    /// when the requested route cannot receive a valid identity.
    fn provide(
        &mut self,
        request: &ExitNativeRouteIdentityRequest,
    ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError>;
}

/// Non-cloneable owner of one native route's public identity and TLS secrets.
pub struct ExitNativeRouteIdentityOwner {
    request: ExitNativeRouteIdentityRequest,
    exit_native_instance_id: [u8; NODE_ID_BYTES],
    public_identity: NativeRouteIdentity,
    tls_certificate_pem: Zeroizing<Vec<u8>>,
    tls_private_key_pem: Zeroizing<Vec<u8>>,
    credential_key_pair: NativeRouteCredentialKeyPair,
}

impl ExitNativeRouteIdentityOwner {
    /// Construct and validate one route-scoped secret owner.
    ///
    /// This validates bounds, canonical public fields and exact request
    /// binding. It deliberately does not claim cryptographic certificate/key
    /// consistency; that remains the trusted provider's responsibility.
    ///
    /// # Errors
    ///
    /// Invalid public fields, mismatched scope, embedded NUL bytes or malformed
    /// bounded PEM framing are rejected.
    pub fn new(
        request: ExitNativeRouteIdentityRequest,
        mut public_identity: NativeRouteIdentity,
        tls_certificate_pem: Vec<u8>,
        tls_private_key_pem: Vec<u8>,
    ) -> Result<Self, ExitNativeRouteIdentityError> {
        let tls_certificate_pem = Zeroizing::new(tls_certificate_pem);
        let tls_private_key_pem = Zeroizing::new(tls_private_key_pem);
        if !public_identity.credential_hpke_public_key.is_empty() {
            return Err(ExitNativeRouteIdentityError::Rejected(
                "native credential recipient key must be owner-generated",
            ));
        }
        let credential_key_pair = NativeRouteCredentialKeyPair::generate()
            .map_err(|_| ExitNativeRouteIdentityError::Unavailable)?;
        public_identity.credential_hpke_public_key = credential_key_pair.public_key().to_vec();
        let exit_native_instance_id = validate_native_route_identity(&request, &public_identity)?;
        if !valid_pem(
            &tls_certificate_pem,
            MAX_TLS_CERTIFICATE_PEM,
            b"-----BEGIN CERTIFICATE-----",
            b"-----END CERTIFICATE-----",
        ) || !valid_pem(
            &tls_private_key_pem,
            MAX_TLS_PRIVATE_KEY_PEM,
            b"-----BEGIN PRIVATE KEY-----",
            b"-----END PRIVATE KEY-----",
        ) {
            return Err(ExitNativeRouteIdentityError::Rejected(
                "invalid native route TLS PEM",
            ));
        }
        Ok(Self {
            request,
            exit_native_instance_id,
            public_identity,
            tls_certificate_pem,
            tls_private_key_pem,
            credential_key_pair,
        })
    }

    /// Return the exact request scope this owner is bound to.
    #[must_use]
    pub const fn request(&self) -> &ExitNativeRouteIdentityRequest {
        &self.request
    }

    /// Return the exact public identity that may be signed into a reservation.
    #[must_use]
    pub const fn public_identity(&self) -> &NativeRouteIdentity {
        &self.public_identity
    }

    fn authorization_scope(&self) -> ExitNativeRouteAuthorizationScope {
        ExitNativeRouteAuthorizationScope {
            request: self.request,
            exit_native_instance_id: self.exit_native_instance_id,
        }
    }

    fn matches_scope(&self, scope: &ExitNativeRouteAuthorizationScope) -> bool {
        self.authorization_scope() == *scope
    }

    fn open_credential(
        &self,
        delivery: &NativeRouteCredentialDelivery,
    ) -> Result<Zeroizing<[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>, ExitError>
    {
        self.credential_key_pair
            .open(delivery)
            .map_err(ExitError::NativeRouteCredential)
    }
}

impl fmt::Debug for ExitNativeRouteIdentityOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitNativeRouteIdentityOwner")
            .field("request", &self.request)
            .field("tls_server_name", &self.public_identity.tls_server_name)
            .field("tls_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Exact public scope required to consume one stored native-route owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitNativeRouteAuthorizationScope {
    request: ExitNativeRouteIdentityRequest,
    exit_native_instance_id: [u8; NODE_ID_BYTES],
}

impl ExitNativeRouteAuthorizationScope {
    /// Bind a finalization request to one exact exit native-process incarnation.
    ///
    /// # Errors
    ///
    /// A zero exit native-process incarnation is rejected.
    pub fn new(
        request: ExitNativeRouteIdentityRequest,
        exit_native_instance_id: [u8; NODE_ID_BYTES],
    ) -> Result<Self, ExitNativeRouteIdentityError> {
        if exit_native_instance_id == [0; NODE_ID_BYTES]
            || exit_native_instance_id != *request.exit_native_instance_id()
        {
            return Err(ExitNativeRouteIdentityError::Rejected(
                "invalid native route authorization scope",
            ));
        }
        Ok(Self {
            request,
            exit_native_instance_id,
        })
    }

    /// Return the exact finalized request scope.
    #[must_use]
    pub const fn request(&self) -> &ExitNativeRouteIdentityRequest {
        &self.request
    }

    /// Return the exact exit native-process incarnation.
    #[must_use]
    pub const fn exit_native_instance_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.exit_native_instance_id
    }
}

/// One-shot, non-cloneable authorization carrying native route TLS ownership.
pub struct ExitNativeRouteAuthorization {
    owner: ExitNativeRouteIdentityOwner,
    expires_at_ms: u64,
}

impl ExitNativeRouteAuthorization {
    /// Return the exact public authorization scope.
    #[must_use]
    pub fn scope(&self) -> ExitNativeRouteAuthorizationScope {
        self.owner.authorization_scope()
    }

    /// Return the signed public native-route identity.
    #[must_use]
    pub const fn public_identity(&self) -> &NativeRouteIdentity {
        self.owner.public_identity()
    }

    /// Borrow the bounded certificate chain PEM for the native runtime.
    #[must_use]
    pub fn tls_certificate_pem(&self) -> &[u8] {
        &self.owner.tls_certificate_pem
    }

    /// Borrow the bounded private-key PEM for the native runtime.
    #[must_use]
    pub fn tls_private_key_pem(&self) -> &[u8] {
        &self.owner.tls_private_key_pem
    }

    /// Return the exclusive signed reservation expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for ExitNativeRouteAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitNativeRouteAuthorization")
            .field("scope", &self.scope())
            .field("expires_at_ms", &self.expires_at_ms)
            .field("tls_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// One-shot native-route authorization plus the Client-created authentication bearer.
///
/// The bearer reached this Exit only through the Client-session-signed RFC 9180 HPKE delivery;
/// it is never exposed to the forwarding Relay. This type deliberately implements neither
/// [`Clone`] nor ordinary field-level [`Debug`].
pub struct ExitNativeRouteCredentialAuthorization {
    authorization: ExitNativeRouteAuthorization,
    auth_bearer: Zeroizing<[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>,
    client_session_id: [u8; 32],
}

impl ExitNativeRouteCredentialAuthorization {
    /// Borrow the exact native-route TLS and public identity authorization.
    #[must_use]
    pub const fn authorization(&self) -> &ExitNativeRouteAuthorization {
        &self.authorization
    }

    /// Borrow the canonical native authentication bearer. Callers must not log or persist it.
    #[must_use]
    pub fn auth_bearer(&self) -> &[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH] {
        &self.auth_bearer
    }

    /// Split the one-shot authorization for direct transfer into the native backend.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ExitNativeRouteAuthorization,
        Zeroizing<[u8; volparossa_protocol::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>,
        [u8; 32],
    ) {
        (self.authorization, self.auth_bearer, self.client_session_id)
    }
}

impl fmt::Debug for ExitNativeRouteCredentialAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitNativeRouteCredentialAuthorization")
            .field("authorization", &self.authorization)
            .field("auth_bearer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Immutable operator limits for one explicitly enabled or disabled exit.
#[derive(Clone, Debug)]
pub struct ExitServiceConfig {
    enabled: bool,
    node_id: [u8; NODE_ID_BYTES],
    bandwidth: Bandwidth,
    maximum_sessions: u32,
    maximum_reservation_ttl_seconds: u64,
    tunnel_setup_timeout_seconds: u64,
    replay_capacity: usize,
}

impl ExitServiceConfig {
    /// Construct the safe disabled default for one local node.
    #[must_use]
    pub const fn disabled(node_id: [u8; NODE_ID_BYTES]) -> Self {
        Self {
            enabled: false,
            node_id,
            bandwidth: Bandwidth {
                up_mbps: 0,
                down_mbps: 0,
            },
            maximum_sessions: 0,
            maximum_reservation_ttl_seconds: MAX_TTL_SECONDS,
            tunnel_setup_timeout_seconds: 30,
            replay_capacity: 65_536,
        }
    }

    /// Construct explicitly enabled exit limits.
    #[must_use]
    pub const fn enabled(
        node_id: [u8; NODE_ID_BYTES],
        bandwidth: Bandwidth,
        maximum_sessions: u32,
        maximum_reservation_ttl_seconds: u64,
        tunnel_setup_timeout_seconds: u64,
        replay_capacity: usize,
    ) -> Self {
        Self {
            enabled: true,
            node_id,
            bandwidth,
            maximum_sessions,
            maximum_reservation_ttl_seconds,
            tunnel_setup_timeout_seconds,
            replay_capacity,
        }
    }

    /// Return whether the operator explicitly enabled exit service.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Fixed DNS, connection, inspection and streaming limits for TCP egress.
#[derive(Clone, Copy, Debug)]
pub struct TcpEgressLimits {
    dns_timeout: Duration,
    connect_timeout: Duration,
    client_hello_timeout: Duration,
    transfer: StreamTransferLimits,
}

impl TcpEgressLimits {
    /// Construct a complete bounded TCP egress limit set.
    ///
    /// # Errors
    ///
    /// Zero timeouts and timeouts longer than one minute are rejected. The
    /// stream limits have already passed their own bounded constructor.
    pub fn new(
        dns_timeout: Duration,
        connect_timeout: Duration,
        client_hello_timeout: Duration,
        transfer: StreamTransferLimits,
    ) -> Result<Self, ExitError> {
        validate_egress_timeout(dns_timeout)?;
        validate_egress_timeout(connect_timeout)?;
        validate_egress_timeout(client_hello_timeout)?;
        Ok(Self {
            dns_timeout,
            connect_timeout,
            client_hello_timeout,
            transfer,
        })
    }

    /// Return the whole-flow idle timeout from the stream limits.
    #[must_use]
    pub const fn idle_timeout(self) -> Duration {
        self.transfer.idle_timeout()
    }

    /// Return the fixed bidirectional stream-transfer limits.
    #[must_use]
    pub const fn transfer(self) -> StreamTransferLimits {
        self.transfer
    }
}

/// Stateful exit admission, route and flow verifier.
pub struct ExitService {
    config: ExitServiceConfig,
    exit_boot_id: [u8; ID_BYTES],
    policy: VerifiedManifest,
    hold_replay: ReplayCache,
    permit_replay: ReplayCache,
    finalize_replay: ReplayCache,
    probe_replay: ReplayCache,
    native_probe_request_replay: ReplayCache,
    confirmation_replay: ReplayCache,
    relay_confirmation_replay: ReplayCache,
    native_credential_replay: ReplayCache,
    route_replay: ReplayCache,
    flow_replay: ReplayCache,
    ledger: Option<CapacityLedger>,
    hold_response_cache:
        HashMap<[u8; NODE_ID_BYTES], CachedControlResponse<AcceptedExitCapacityHold>>,
    permit_response_cache:
        HashMap<[u8; NODE_ID_BYTES], CachedControlResponse<AcceptedRelayProbePermit>>,
    native_probe_permit_ledger: native_preselection::NativeProbePermitLedger,
    native_probe_ready_owners:
        HashMap<[u8; ID_BYTES], native_preselection::IssuedNativeProbeExitReady>,
    native_probe_authorization_cache:
        HashMap<[u8; NODE_ID_BYTES], native_preselection::CachedNativeProbeRelayAuthorization>,
    finalize_response_cache:
        HashMap<[u8; NODE_ID_BYTES], CachedControlResponse<AcceptedExitReservationBundle>>,
    confirmation_response_cache:
        HashMap<[u8; NODE_ID_BYTES], CachedControlResponse<AcceptedExitConfirmation>>,
    response_cache_capacity: usize,
    activated: HashSet<ReservationId>,
    endpoint_states: HashMap<ReservationId, ExitReservationState>,
    native_route_identity_owners: HashMap<ReservationId, ExitNativeRouteIdentityOwner>,
    metrics: Option<MetricsRegistry>,
}

impl ExitService {
    /// Validate all fixed bounds and construct an empty exit service.
    ///
    /// Enabled services generate a new non-persistent CSPRNG boot incarnation.
    /// Restarting the process therefore invalidates every earlier hold, permit,
    /// finalization and confirmation scope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid capacity, timeout or replay bounds.
    pub fn new(
        config: ExitServiceConfig,
        policy: VerifiedManifest,
        metrics: Option<MetricsRegistry>,
    ) -> Result<Self, ExitError> {
        Self::new_with_boot_id(
            config,
            policy,
            metrics,
            reservation_v4::fresh_exit_boot_id(),
        )
    }

    /// Construct with an explicitly supplied per-process CSPRNG boot incarnation.
    ///
    /// This injection boundary exists for runtime composition and deterministic
    /// tests. Callers must generate a fresh unpredictable non-zero value for
    /// every process start and must never persist or configure it.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero boot incarnation or invalid service limits.
    pub fn new_with_boot_id(
        config: ExitServiceConfig,
        policy: VerifiedManifest,
        metrics: Option<MetricsRegistry>,
        exit_boot_id: [u8; ID_BYTES],
    ) -> Result<Self, ExitError> {
        if config.replay_capacity == 0 {
            return Err(ExitError::InvalidConfig("replay capacity"));
        }
        if exit_boot_id == [0; ID_BYTES] {
            return Err(ExitError::InvalidConfig("exit boot incarnation"));
        }
        let ledger = if config.enabled {
            if config.bandwidth.up_mbps == 0
                || config.bandwidth.down_mbps == 0
                || config.maximum_sessions == 0
                || config.maximum_sessions > MAX_SESSIONS
                || config.maximum_reservation_ttl_seconds == 0
                || config.maximum_reservation_ttl_seconds > MAX_TTL_SECONDS
                || config.tunnel_setup_timeout_seconds == 0
                || config.tunnel_setup_timeout_seconds > config.maximum_reservation_ttl_seconds
            {
                return Err(ExitError::InvalidConfig("exit limits"));
            }
            Some(CapacityLedger::new(LedgerLimits {
                service_node_id: text_id::<NodeId>(&config.node_id)?,
                role: ServiceRole::Exit,
                bandwidth: config.bandwidth,
                maximum_sessions: config.maximum_sessions,
                maximum_reservation_ttl_seconds: config.maximum_reservation_ttl_seconds,
                tunnel_setup_timeout_seconds: config.tunnel_setup_timeout_seconds,
            })?)
        } else {
            None
        };
        let response_cache_capacity = config.replay_capacity.min(MAX_IDEMPOTENCY_ENTRIES);
        let service = Self {
            hold_replay: ReplayCache::new(config.replay_capacity)?,
            permit_replay: ReplayCache::new(config.replay_capacity)?,
            finalize_replay: ReplayCache::new(config.replay_capacity)?,
            probe_replay: ReplayCache::new(config.replay_capacity)?,
            native_probe_request_replay: ReplayCache::new(config.replay_capacity)?,
            confirmation_replay: ReplayCache::new(config.replay_capacity)?,
            relay_confirmation_replay: ReplayCache::new(config.replay_capacity)?,
            native_credential_replay: ReplayCache::new(config.replay_capacity)?,
            route_replay: ReplayCache::new(config.replay_capacity)?,
            flow_replay: ReplayCache::new(config.replay_capacity)?,
            config,
            exit_boot_id,
            hold_response_cache: HashMap::with_capacity(response_cache_capacity),
            permit_response_cache: HashMap::with_capacity(response_cache_capacity),
            native_probe_permit_ledger: native_preselection::NativeProbePermitLedger::new(
                response_cache_capacity,
            ),
            native_probe_ready_owners: HashMap::with_capacity(response_cache_capacity),
            native_probe_authorization_cache: HashMap::with_capacity(response_cache_capacity),
            finalize_response_cache: HashMap::with_capacity(response_cache_capacity),
            confirmation_response_cache: HashMap::with_capacity(response_cache_capacity),
            response_cache_capacity,
            policy,
            ledger,
            activated: HashSet::new(),
            endpoint_states: HashMap::new(),
            native_route_identity_owners: HashMap::new(),
            metrics,
        };
        service.sync_metrics();
        Ok(service)
    }

    /// Bind one admitted reservation to its exact client-confirmed relay grants for TCP.
    ///
    /// This creates replay-protected signed-control state only. It neither proves helper
    /// configuration nor claims that a kernel tunnel is active.
    ///
    /// # Errors
    ///
    /// Stale, foreign, already activated, transport-incompatible or invalid
    /// multipath proof is rejected.
    pub fn bind_tcp_route(
        &mut self,
        accepted: &AcceptedExitReservation,
        relay_reservations: &[&[u8]],
        now_ms: u64,
    ) -> Result<ActiveTcpRoute, ExitError> {
        self.validate_accepted(accepted, Transport::TcpMptcp, now_ms)?;
        let key = text_id::<ReservationId>(&accepted.reservation_id)?;
        if !self.grants_match_confirmed(&key, relay_reservations.iter().copied()) {
            return Err(ExitError::InvalidGrant(
                "TCP relay grants differ from confirmations",
            ));
        }
        let route = VerifiedMptcpRoute::verify(
            &accepted.encoded,
            relay_reservations,
            now_ms,
            TimePolicy::default(),
            &mut self.route_replay,
        )?;
        if route.reservation_id() != &accepted.reservation_id
            || route.route_context_id() != &accepted.route_context_id
            || route.exit_node_id() != &accepted.exit_node_id
        {
            return Err(ExitError::InvalidGrant("TCP route binding"));
        }
        self.activated.insert(key);
        Ok(ActiveTcpRoute {
            route,
            reservation_id: accepted.reservation_id,
        })
    }

    /// Bind one admitted reservation to its exact client-confirmed relay grant for UDP.
    ///
    /// This creates replay-protected signed-control state only; it is not evidence
    /// of helper configuration, kernel port ownership, or a live tunnel.
    ///
    /// # Errors
    ///
    /// Stale, foreign, already activated, transport-incompatible or invalid
    /// single-relay proof is rejected.
    pub fn bind_udp_path(
        &mut self,
        accepted: &AcceptedExitReservation,
        relay_reservation: &[u8],
        now_ms: u64,
    ) -> Result<ActiveUdpPath, ExitError> {
        self.validate_accepted(accepted, Transport::UdpSinglePath, now_ms)?;
        let key = text_id::<ReservationId>(&accepted.reservation_id)?;
        if !self.grants_match_confirmed(&key, std::iter::once(relay_reservation)) {
            return Err(ExitError::InvalidGrant(
                "UDP relay grant differs from confirmation",
            ));
        }
        let path = VerifiedSingleRelayPath::verify(
            &accepted.encoded,
            relay_reservation,
            now_ms,
            TimePolicy::default(),
            &mut self.route_replay,
        )?;
        if path.reservation_id() != &accepted.reservation_id
            || path.route_context_id() != &accepted.route_context_id
            || path.exit_node_id() != &accepted.exit_node_id
        {
            return Err(ExitError::InvalidGrant("UDP route binding"));
        }
        self.activated.insert(key);
        Ok(ActiveUdpPath {
            path,
            reservation_id: accepted.reservation_id,
        })
    }

    /// Verify one client-signed `OPEN_TCP` against its route and active policy.
    ///
    /// # Errors
    ///
    /// Invalid signatures, replay, scope mismatch, stale policy and denied
    /// domain/port tuples are rejected.
    pub fn authorize_tcp_open(
        &mut self,
        route: &ActiveTcpRoute,
        encoded_open: &[u8],
        now_ms: u64,
    ) -> Result<AuthorizedTcpFlow, ExitError> {
        self.ensure_active_reservation(&route.reservation_id)?;
        route.route.ensure_active_at(now_ms)?;
        let scope = TcpAuthorizationScope::new(&route.route, &self.policy);
        match scope.verify(
            encoded_open,
            now_ms,
            TimePolicy::default(),
            &mut self.flow_replay,
        ) {
            Ok(flow) => Ok(flow),
            Err(error) => {
                if matches!(error, TcpProxyError::Policy(_)) {
                    self.record_policy_denial();
                }
                Err(error.into())
            }
        }
    }

    /// Consume one activated TCP route into a self-contained multi-flow egress owner.
    ///
    /// The returned owner keeps the verified multipath route, current threshold-signed policy,
    /// independent bounded replay state, and metrics needed by a background datapath task. The
    /// reservation remains allocated in this service until the caller reports completion through
    /// [`Self::release`]. Consuming [`ActiveTcpRoute`] makes this transition one-shot.
    ///
    /// # Errors
    ///
    /// An inactive/expired reservation or policy, or unavailable replay capacity, fails closed.
    pub fn detach_tcp_egress_route(
        &self,
        route: ActiveTcpRoute,
        now_ms: u64,
    ) -> Result<ActiveTcpEgressRoute, ExitError> {
        self.ensure_active_reservation(&route.reservation_id)?;
        route.route.ensure_active_at(now_ms)?;
        self.policy.ensure_active_at(now_ms)?;
        Ok(ActiveTcpEgressRoute {
            route: route.route,
            reservation_id: route.reservation_id,
            policy: self.policy.clone(),
            flow_replay: Mutex::new(ReplayCache::new(self.config.replay_capacity)?),
            metrics: self.metrics.clone(),
        })
    }

    /// Verify and consume one client-signed UDP flow for an active relay path.
    ///
    /// This general path deliberately rejects UDP/443. Other exact policy
    /// tuples become immutable prepared flows, ready for exit-side resolution
    /// and a connected socket.
    ///
    /// # Errors
    ///
    /// Invalid signatures, replay, policy denial, stale scope and UDP/443 are
    /// rejected without exposing the destination in logs or metrics.
    pub fn prepare_udp_flow(
        &mut self,
        active_path: ActiveUdpPath,
        encoded_authorization: &[u8],
        now_ms: u64,
    ) -> Result<PreparedUdpFlow, ExitError> {
        let flow = self.verify_udp_authorization(&active_path, encoded_authorization, now_ms)?;
        if flow.port() == 443 {
            self.record_policy_denial();
            return Err(ExitError::QuicInspectionUnavailable);
        }
        Ok(PreparedUdpFlow {
            path: active_path.path,
            flow,
        })
    }

    /// Consume one UDP/443 authorization and start authenticated QUIC evidence.
    ///
    /// The returned pending value has no forwarding or socket API. It is bound
    /// to the original client destination connection identifier and can become
    /// a [`PreparedUdpFlow`] only after bounded QUIC v1 Initial inspection
    /// yields the exact visible normalized SNI from the signed authorization.
    ///
    /// # Errors
    ///
    /// Invalid/replayed authorization, non-443 or raw-IP destinations, stale
    /// route/policy scope, invalid original DCID and inspection setup failures
    /// are rejected fail closed.
    pub fn begin_udp_443_inspection(
        &mut self,
        active_path: ActiveUdpPath,
        encoded_authorization: &[u8],
        original_client_dcid: &[u8],
        now_ms: u64,
    ) -> Result<PendingQuicUdpFlow, ExitError> {
        let flow = self.verify_udp_authorization(&active_path, encoded_authorization, now_ms)?;
        if flow.port() != 443 {
            self.record_policy_denial();
            return Err(ExitError::QuicInspectionPortRequired);
        }
        let expected_hostname = match signed_udp_hostname(encoded_authorization, &flow) {
            Ok(hostname) => hostname,
            Err(error) => {
                self.record_policy_denial();
                return Err(error);
            }
        };
        let inspector = match QuicInitialInspector::new(original_client_dcid) {
            Ok(inspector) => inspector,
            Err(error) => {
                self.record_policy_denial();
                return Err(map_inspection_error(error));
            }
        };
        Ok(PendingQuicUdpFlow {
            path: active_path.path,
            flow,
            expected_hostname,
            inspector: Box::new(inspector),
            policy_expires_at_ms: self.policy.expires_at_ms(),
            metrics: self.metrics.clone(),
        })
    }

    /// Resolve, pin and connect an authorized UDP flow to its QUIC association.
    ///
    /// # Errors
    ///
    /// Resolution, expiry, QUIC DATAGRAM negotiation, flow binding and connected
    /// UDP socket errors are returned fail closed.
    pub async fn open_udp_bridge(
        &self,
        prepared: PreparedUdpFlow,
        connection: quinn::Connection,
        now_ms: u64,
        limits: DatagramLimits,
    ) -> Result<ExitUdpBridge, ExitError> {
        self.policy.ensure_active_at(now_ms)?;
        prepared.path.ensure_active_at(now_ms)?;
        let pinned = prepared.flow.resolve_and_pin(now_ms).await?;
        let association =
            QuicUdpAssociation::new(connection, prepared.path, &prepared.flow, now_ms)?;
        Ok(ExitUdpBridge::connect(association, pinned, now_ms, limits).await?)
    }

    /// Run one authorized ordinary-TCP egress stream with bounded buffering.
    ///
    /// The destination name is resolved only here at the exit. Every hostname flow first consumes
    /// and validates a bounded visible `ClientHello`, forwards those exact bytes unchanged, then
    /// streams both directions. ECH, missing SNI,
    /// private/reserved resolution results and timeout/byte-limit violations
    /// all close the flow.
    ///
    /// # Errors
    ///
    /// Returns policy, TLS inspection, DNS, connection, I/O, idle or byte-limit
    /// failures. No ordinary TCP connection is opened before required SNI
    /// validation succeeds.
    pub async fn run_tcp_egress<C>(
        &self,
        flow: &AuthorizedTcpFlow,
        protected_client: C,
        now_ms: u64,
        limits: TcpEgressLimits,
    ) -> Result<StreamTransferStats, ExitError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        run_tcp_egress_with_policy(
            &self.policy,
            self.metrics.as_ref(),
            flow,
            protected_client,
            now_ms,
            limits,
        )
        .await
    }
    /// Consume the exact stored native-route TLS owner once.
    ///
    /// All relay-to-exit paths must already be confirmed. This method only
    /// transfers typed ownership to a future native backend; it does not start
    /// a listener or authorize a direct client-to-exit datapath.
    ///
    /// # Errors
    ///
    /// Disabled, expired, unconfirmed, mismatched, unknown or already-consumed
    /// ownership is rejected without consuming a different owner.
    pub fn take_native_route_authorization(
        &mut self,
        scope: &ExitNativeRouteAuthorizationScope,
        now_ms: u64,
    ) -> Result<ExitNativeRouteAuthorization, ExitError> {
        self.require_enabled()?;
        self.purge_expired(now_ms);
        self.policy.ensure_active_at(now_ms)?;
        let reservation_key = text_id::<ReservationId>(scope.request.reservation_id())?;
        let state = self
            .endpoint_states
            .get(&reservation_key)
            .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
        if state.phase != ExitReservationPhase::Finalized
            || state.expires_at_ms <= now_ms
            || state.paths.is_empty()
            || state.paths.iter().any(|path| {
                path.relay_exit_endpoint.is_none() || path.relay_reservation_hash.is_none()
            })
        {
            return Err(ExitError::ConfirmationRequired);
        }
        let expires_at_ms = state.expires_at_ms;
        let owner = self
            .native_route_identity_owners
            .get(&reservation_key)
            .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
        if !owner.matches_scope(scope) {
            return Err(ExitError::NativeRouteAuthorizationMismatch);
        }
        let owner = self
            .native_route_identity_owners
            .remove(&reservation_key)
            .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
        Ok(ExitNativeRouteAuthorization {
            owner,
            expires_at_ms,
        })
    }

    /// Verify and consume one Client-to-Exit encrypted native-route bearer.
    ///
    /// The delivery is authenticated by the fresh Client session and replay protected before its
    /// RFC 9180 ciphertext is opened with the route owner's private recipient key. Every public
    /// field is then matched to the finalized reservation, exact native instances and signed TLS
    /// identity. A forwarding Relay can carry this message but cannot learn or substitute the
    /// bearer.
    ///
    /// # Errors
    ///
    /// Disabled, expired, unconfirmed, replayed, cross-scoped, undecryptable, unknown or
    /// already-consumed ownership is rejected. Failed local correlation rolls back only the
    /// provisional replay entry; a successful delivery remains permanently replay protected.
    pub fn take_native_route_authorization_with_credential(
        &mut self,
        scope: &ExitNativeRouteAuthorizationScope,
        signed_delivery: &[u8],
        now_ms: u64,
    ) -> Result<ExitNativeRouteCredentialAuthorization, ExitError> {
        self.require_enabled()?;
        self.purge_expired(now_ms);
        self.policy.ensure_active_at(now_ms)?;
        let reservation_key = text_id::<ReservationId>(scope.request.reservation_id())?;
        let verified = verify_control_message::<NativeRouteCredentialDelivery>(
            signed_delivery,
            now_ms,
            TimePolicy::default(),
            &mut self.native_credential_replay,
        )?;
        let replay_entry = (*verified.sender_id(), *verified.nonce());

        let result = (|| {
            let state = self
                .endpoint_states
                .get(&reservation_key)
                .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
            if state.phase != ExitReservationPhase::Finalized
                || state.expires_at_ms <= now_ms
                || state.paths.is_empty()
                || state.paths.iter().any(|path| {
                    path.relay_exit_endpoint.is_none() || path.relay_reservation_hash.is_none()
                })
            {
                return Err(ExitError::ConfirmationRequired);
            }
            let owner = self
                .native_route_identity_owners
                .get(&reservation_key)
                .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
            if !owner.matches_scope(scope) {
                return Err(ExitError::NativeRouteAuthorizationMismatch);
            }
            let delivery_scope = verified
                .message()
                .scope
                .as_ref()
                .ok_or(ExitError::NativeRouteAuthorizationMismatch)?;
            let identity = owner.public_identity();
            let request = scope.request();
            let finalize_matches = state.finalize_id.as_ref().is_some_and(|finalize_id| {
                delivery_scope.finalize_id.as_slice() == finalize_id
                    && finalize_id == request.finalize_id()
            });
            let exact_scope = delivery_scope.reservation_id.as_slice() == request.reservation_id()
                && delivery_scope.route_context_id.as_slice() == request.route_context_id()
                && delivery_scope.exit_node_id.as_slice() == self.config.node_id
                && delivery_scope.client_session_id.as_slice() == state.client_session_id
                && delivery_scope.client_session_public_key.as_slice()
                    == state.client_session_public_key
                && verified.sender_id() == &state.client_session_id
                && verified.sender_public_key() == &state.client_session_public_key
                && delivery_scope.auth_commitment.as_slice() == request.auth_commitment()
                && delivery_scope.auth_commitment == identity.auth_commitment
                && delivery_scope.certificate_sha256 == identity.certificate_sha256
                && delivery_scope.spki_sha256 == identity.spki_sha256
                && delivery_scope.masque_context_id == request.masque_context_id()
                && delivery_scope.masque_context_id == identity.masque_context_id
                && delivery_scope.client_native_instance_id.as_slice()
                    == request.client_native_instance_id()
                && delivery_scope.client_native_instance_id == identity.client_native_instance_id
                && delivery_scope.exit_native_instance_id.as_slice()
                    == scope.exit_native_instance_id()
                && delivery_scope.exit_native_instance_id == identity.exit_native_instance_id
                && delivery_scope.credential_hpke_public_key == identity.credential_hpke_public_key
                && delivery_scope.created_at_ms >= state.created_at_ms
                && delivery_scope.expires_at_ms == state.expires_at_ms
                && verified.expires_at_ms() == state.expires_at_ms
                && finalize_matches;
            if !exact_scope {
                return Err(ExitError::NativeRouteAuthorizationMismatch);
            }

            let auth_bearer = owner.open_credential(verified.message())?;
            let owner = self
                .native_route_identity_owners
                .remove(&reservation_key)
                .ok_or(ExitError::NativeRouteAuthorizationUnavailable)?;
            Ok(ExitNativeRouteCredentialAuthorization {
                authorization: ExitNativeRouteAuthorization {
                    owner,
                    expires_at_ms: state.expires_at_ms,
                },
                auth_bearer,
                client_session_id: state
                    .client_session_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| ExitError::NativeRouteAuthorizationMismatch)?,
            })
        })();

        if result.is_err() {
            let _ = self
                .native_credential_replay
                .rollback(&replay_entry.0, &replay_entry.1);
        }
        result
    }

    /// Explicitly release one route allocation.
    ///
    /// # Errors
    ///
    /// Disabled or unknown reservation identifiers are rejected.
    pub fn release(&mut self, reservation_id: &[u8; ID_BYTES]) -> Result<(), ExitError> {
        let key = text_id::<ReservationId>(reservation_id)?;
        self.ledger_mut()?.release(&key)?;
        self.activated.remove(&key);
        self.endpoint_states.remove(&key);
        self.native_route_identity_owners.remove(&key);
        self.sync_metrics();
        self.hold_response_cache
            .retain(|_, cached| cached.response.reservation_id() != reservation_id);
        self.permit_response_cache
            .retain(|_, cached| cached.response.reservation_id() != reservation_id);
        self.finalize_response_cache
            .retain(|_, cached| cached.response.reservation_id() != reservation_id);
        self.confirmation_response_cache.retain(|_, cached| {
            cached.response.confirmed_path().reservation_id() != reservation_id
        });
        self.native_probe_authorization_cache
            .retain(|_, cached| cached.response.reservation_id() != reservation_id);
        Ok(())
    }

    /// Purge expired holds, hard-expired grants and never-established allocations.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let phase_expired = self
            .endpoint_states
            .iter()
            .filter_map(|(reservation_id, state)| {
                (state.phase == ExitReservationPhase::Held && state.hold_expires_at_ms <= now_ms)
                    .then_some(reservation_id.clone())
            })
            .collect::<Vec<_>>();
        let mut removed = HashSet::with_capacity(phase_expired.len());
        for reservation_id in phase_expired {
            if let Some(ledger) = self.ledger.as_mut() {
                let _ = ledger.release(&reservation_id);
            }
            self.activated.remove(&reservation_id);
            self.endpoint_states.remove(&reservation_id);
            self.native_route_identity_owners.remove(&reservation_id);
            removed.insert(reservation_id);
        }

        let ledger_expired = self.ledger.as_mut().map_or_else(Vec::new, |ledger| {
            ledger.purge_expired(unix_seconds(now_ms))
        });
        for allocation in ledger_expired {
            self.activated.remove(&allocation.reservation_id);
            self.endpoint_states.remove(&allocation.reservation_id);
            self.native_route_identity_owners
                .remove(&allocation.reservation_id);
            removed.insert(allocation.reservation_id);
        }
        let removed_ids = removed
            .iter()
            .map(ReservationId::as_str)
            .collect::<HashSet<_>>();
        self.hold_response_cache.retain(|_, cached| {
            cached.expires_at_ms > now_ms
                && !removed_ids.contains(hex::encode(cached.response.reservation_id()).as_str())
        });
        self.permit_response_cache.retain(|_, cached| {
            cached.expires_at_ms > now_ms
                && !removed_ids.contains(hex::encode(cached.response.reservation_id()).as_str())
        });
        self.finalize_response_cache.retain(|_, cached| {
            cached.expires_at_ms > now_ms
                && !removed_ids.contains(hex::encode(cached.response.reservation_id()).as_str())
        });
        self.confirmation_response_cache.retain(|_, cached| {
            cached.expires_at_ms > now_ms
                && !removed_ids.contains(
                    hex::encode(cached.response.confirmed_path().reservation_id()).as_str(),
                )
        });
        self.native_probe_authorization_cache.retain(|_, cached| {
            cached.expires_at_ms > now_ms
                && !removed_ids.contains(hex::encode(cached.response.reservation_id()).as_str())
        });
        self.native_probe_ready_owners
            .retain(|_, ready| ready.expires_at_ms > now_ms);
        self.native_probe_permit_ledger.purge_expired(now_ms);
        self.sync_metrics();
        removed.len()
    }
    /// Return capacity remaining after purging expired allocations.
    pub fn available(&mut self, now_ms: u64) -> Option<AvailableCapacity> {
        let result = self
            .ledger
            .as_mut()
            .map(|ledger| ledger.available(unix_seconds(now_ms)));
        self.sync_metrics();
        result
    }

    /// Return the exact active threshold-signed policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> &[u8; 32] {
        self.policy.policy_hash()
    }

    /// Return the exact public endpoint lease and opaque helper capabilities.
    #[must_use]
    pub fn endpoint_lease(
        &self,
        reservation_id: &[u8; ID_BYTES],
        path_id: u32,
    ) -> Option<ExitEndpointLease> {
        let key = text_id::<ReservationId>(reservation_id).ok()?;
        self.endpoint_states
            .get(&key)?
            .paths
            .iter()
            .find(|path| path.path_id == path_id)
            .map(|path| path.exit_endpoint)
    }

    /// Return the local public endpoint tuple committed to signed control messages.
    ///
    /// The opaque lease capability, not this copyable tuple, authorizes helper operations.
    #[must_use]
    pub fn endpoint(
        &self,
        reservation_id: &[u8; ID_BYTES],
        path_id: u32,
    ) -> Option<PublicWireGuardEndpoint> {
        let key = text_id::<ReservationId>(reservation_id).ok()?;
        self.endpoint_states
            .get(&key)?
            .paths
            .iter()
            .find(|path| path.path_id == path_id)
            .map(|path| path.exit_endpoint.public_endpoint())
    }

    fn all_paths_confirmed(&self, reservation_id: &ReservationId) -> bool {
        self.endpoint_states
            .get(reservation_id)
            .is_some_and(|state| {
                !state.paths.is_empty()
                    && state
                        .paths
                        .iter()
                        .all(|path| path.relay_exit_endpoint.is_some())
            })
    }

    fn grants_match_confirmed<'a>(
        &self,
        reservation_id: &ReservationId,
        encoded_grants: impl IntoIterator<Item = &'a [u8]>,
    ) -> bool {
        let Some(state) = self.endpoint_states.get(reservation_id) else {
            return false;
        };
        let confirmed = state
            .paths
            .iter()
            .filter_map(|path| path.relay_reservation_hash)
            .collect::<HashSet<_>>();
        let supplied = encoded_grants
            .into_iter()
            .map(|encoded| Sha256::digest(encoded).into())
            .collect::<HashSet<[u8; NODE_ID_BYTES]>>();
        supplied.len() == state.paths.len() && supplied == confirmed
    }

    fn verify_udp_authorization(
        &mut self,
        active_path: &ActiveUdpPath,
        encoded_authorization: &[u8],
        now_ms: u64,
    ) -> Result<AuthorizedUdpFlow, ExitError> {
        self.ensure_active_reservation(&active_path.reservation_id)?;
        active_path.path.ensure_active_at(now_ms)?;
        let scope = UdpAuthorizationScope::new(&active_path.path, &self.policy);
        match scope.verify(
            encoded_authorization,
            now_ms,
            TimePolicy::default(),
            &mut self.flow_replay,
        ) {
            Ok(flow) => Ok(flow),
            Err(error) => {
                if matches!(error, UdpError::Policy(_)) {
                    self.record_policy_denial();
                }
                Err(error.into())
            }
        }
    }

    fn validate_accepted(
        &mut self,
        accepted: &AcceptedExitReservation,
        transport: Transport,
        now_ms: u64,
    ) -> Result<(), ExitError> {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        if accepted.exit_node_id != self.config.node_id || now_ms >= accepted.expires_at_ms {
            return Err(ExitError::InvalidGrant("accepted reservation scope"));
        }
        if !accepted.allowed_transports.contains(&(transport as i32)) {
            return Err(ExitError::TransportDenied);
        }
        let key = text_id::<ReservationId>(&accepted.reservation_id)?;
        if self.activated.contains(&key) {
            return Err(ExitError::AlreadyActivated);
        }
        if !self.all_paths_confirmed(&key) {
            return Err(ExitError::ConfirmationRequired);
        }
        if self
            .ledger
            .as_ref()
            .and_then(|ledger| ledger.grant(&key))
            .is_none()
        {
            return Err(ExitError::InvalidGrant("unknown accepted reservation"));
        }
        Ok(())
    }

    fn ensure_active_reservation(&self, reservation_id: &[u8; ID_BYTES]) -> Result<(), ExitError> {
        let key = text_id::<ReservationId>(reservation_id)?;
        if !self.activated.contains(&key)
            || self
                .ledger
                .as_ref()
                .and_then(|ledger| ledger.grant(&key))
                .is_none()
        {
            return Err(ExitError::InvalidGrant("inactive reservation"));
        }
        Ok(())
    }

    fn require_enabled(&self) -> Result<(), ExitError> {
        if self.config.enabled {
            Ok(())
        } else {
            Err(ExitError::Disabled)
        }
    }

    fn ledger_mut(&mut self) -> Result<&mut CapacityLedger, ExitError> {
        self.ledger.as_mut().ok_or(ExitError::Disabled)
    }

    fn record_policy_denial(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_policy_denial();
        }
    }

    fn sync_metrics(&self) {
        if let (Some(metrics), Some(ledger)) = (&self.metrics, &self.ledger) {
            let result = metrics.set_exit_reservations(ledger.allocation_count());
            debug_assert!(result.is_ok(), "validated exit metric bound");
        }
    }
}

/// Cloneable transport response for one internally retained native-probe Permit owner.
///
/// This value carries only the canonical Exit-signed response bytes and their exclusive expiry.
/// Dropping it, including after a failed network send, does not remove or consume the affine owner
/// retained by [`ExitService`].
#[derive(Clone)]
pub struct AcceptedNativeProbePermit {
    encoded: Vec<u8>,
    expires_at_ms: u64,
}

impl AcceptedNativeProbePermit {
    /// Return the canonical Exit-signed native-probe Permit envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the exclusive Permit expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedNativeProbePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedNativeProbePermit")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Exit-signed response bundle whose reservation has atomically consumed capacity.
#[derive(Clone)]
pub struct AcceptedExitReservationBundle {
    accepted: AcceptedExitReservation,
    relay_authorizations: Vec<Vec<u8>>,
}

impl AcceptedExitReservationBundle {
    /// Return the short-lived reservation identifier for rollback or lifecycle tracking.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        self.accepted.reservation_id()
    }

    /// Return the canonical exit-signed reservation envelope.
    #[must_use]
    pub fn signed_exit_reservation(&self) -> &[u8] {
        self.accepted.encoded()
    }

    /// Return exit-signed relay authorizations in request path order.
    #[must_use]
    pub fn relay_authorizations(&self) -> &[Vec<u8>] {
        &self.relay_authorizations
    }

    /// Borrow the admitted reservation for local route binding after all confirmations.
    #[must_use]
    pub const fn accepted(&self) -> &AcceptedExitReservation {
        &self.accepted
    }

    /// Consume the bundle into transport-owned canonical envelopes.
    #[must_use]
    pub fn into_signed_parts(self) -> (Vec<u8>, Vec<Vec<u8>>) {
        (self.accepted.encoded, self.relay_authorizations)
    }

    /// Consume the bundle into the locally admitted reservation and per-path authorizations.
    #[must_use]
    pub fn into_admitted_parts(self) -> (AcceptedExitReservation, Vec<Vec<u8>>) {
        (self.accepted, self.relay_authorizations)
    }
}

impl fmt::Debug for AcceptedExitReservationBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedExitReservationBundle")
            .field("relay_authorizations", &self.relay_authorizations.len())
            .field("expires_at_ms", &self.accepted.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// A verified exit-signed reservation that has consumed capacity.
#[derive(Clone)]
pub struct AcceptedExitReservation {
    encoded: Vec<u8>,
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    exit_node_id: [u8; NODE_ID_BYTES],
    allowed_transports: Vec<i32>,
    maximum_paths: u32,
    expires_at_ms: u64,
    native_route_identity: NativeRouteIdentity,
    native_route_authorization_scope: ExitNativeRouteAuthorizationScope,
}

impl AcceptedExitReservation {
    /// Return the canonical signed exit reservation envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the short-lived reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the route-context identifier.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the signed public native-route identity.
    #[must_use]
    pub const fn native_route_identity(&self) -> &NativeRouteIdentity {
        &self.native_route_identity
    }

    /// Return the exact scope required for one-shot local TLS-owner consumption.
    #[must_use]
    pub fn native_route_authorization_scope(&self) -> ExitNativeRouteAuthorizationScope {
        self.native_route_authorization_scope
    }

    /// Return the signed maximum relay-path count.
    #[must_use]
    pub const fn maximum_paths(&self) -> u32 {
        self.maximum_paths
    }

    /// Return the exclusive signed expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedExitReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedExitReservation")
            .field("maximum_paths", &self.maximum_paths)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// An exit-verified TCP multipath route.
pub struct ActiveTcpRoute {
    route: VerifiedMptcpRoute,
    reservation_id: [u8; ID_BYTES],
}

impl ActiveTcpRoute {
    /// Return the number of distinct signed relay paths.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.route.path_count()
    }

    /// Return the short-lived reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }
}

/// One independently runnable TCP egress route detached from the discovery actor.
///
/// This affine owner authorizes exactly scoped client flow openings with route-local replay state.
/// It never creates or accepts a transport itself: callers must supply a genuine protected MPTCP
/// TLS stream. The original [`ActiveTcpRoute`] is consumed when this value is created.
pub struct ActiveTcpEgressRoute {
    route: VerifiedMptcpRoute,
    reservation_id: [u8; ID_BYTES],
    policy: VerifiedManifest,
    flow_replay: Mutex<ReplayCache>,
    metrics: Option<MetricsRegistry>,
}

impl ActiveTcpEgressRoute {
    /// Return the still-allocated reservation identifier for completion reporting.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Read and verify exactly one bounded signed `OPEN_TCP` frame from the protected stream.
    ///
    /// # Errors
    ///
    /// Malformed framing, timeout, invalid signature, replay, route/policy mismatch and denied
    /// destinations all fail closed before any ordinary Internet connection is opened.
    pub async fn read_authorized_open_tcp<R>(
        &self,
        reader: &mut R,
        now_ms: u64,
        timeout: Duration,
    ) -> Result<AuthorizedTcpFlow, ExitError>
    where
        R: AsyncRead + Unpin,
    {
        self.route.ensure_active_at(now_ms)?;
        self.policy.ensure_active_at(now_ms)?;
        let scope = TcpAuthorizationScope::new(&self.route, &self.policy);
        let mut flow_replay = self.flow_replay.lock().await;
        let result = read_authorized_open_tcp(
            reader,
            &scope,
            now_ms,
            TimePolicy::default(),
            &mut flow_replay,
            timeout,
        )
        .await;
        if matches!(&result, Err(TcpProxyError::Policy(_))) {
            if let Some(metrics) = &self.metrics {
                metrics.record_policy_denial();
            }
        }
        result.map_err(ExitError::from)
    }

    /// Resolve and proxy one authorized flow over the supplied protected client stream.
    ///
    /// # Errors
    ///
    /// Expiry, policy, DNS, connect, inspection, I/O and transfer-limit failures close the flow.
    pub async fn run_tcp_egress<C>(
        &self,
        flow: &AuthorizedTcpFlow,
        protected_client: C,
        now_ms: u64,
        limits: TcpEgressLimits,
    ) -> Result<StreamTransferStats, ExitError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        run_tcp_egress_with_policy(
            &self.policy,
            self.metrics.as_ref(),
            flow,
            protected_client,
            now_ms,
            limits,
        )
        .await
    }
}

/// An exit-verified single relay path, consumable by one UDP association.
pub struct ActiveUdpPath {
    path: VerifiedSingleRelayPath,
    reservation_id: [u8; ID_BYTES],
}

impl ActiveUdpPath {
    /// Return the sole relay identity without exposing a destination.
    #[must_use]
    pub const fn relay_node_id(&self) -> &[u8; NODE_ID_BYTES] {
        self.path.relay_node_id()
    }

    /// Return the short-lived reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Consume the activated service grant into the exact verified transport path.
    #[must_use]
    pub fn into_verified_path(self) -> VerifiedSingleRelayPath {
        self.path
    }
}

/// A policy-approved UDP flow still bound to its sole verified relay path.
pub struct PreparedUdpFlow {
    path: VerifiedSingleRelayPath,
    flow: AuthorizedUdpFlow,
}

impl fmt::Debug for PreparedUdpFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedUdpFlow")
            .field("destination", &"<redacted>")
            .field("expires_at_ms", &self.flow.expires_at_ms())
            .finish_non_exhaustive()
    }
}

struct CachedControlResponse<T> {
    request: Vec<u8>,
    authenticated_control_relay_node_id: [u8; NODE_ID_BYTES],
    authenticated_control_relay_peer_id: Vec<u8>,
    response: T,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitReservationPhase {
    Held,
    Finalized,
}

#[derive(Clone)]
struct ExitProbePermitState {
    encoded: Vec<u8>,
    probe_id: [u8; ID_BYTES],
    relay_node_id: [u8; NODE_ID_BYTES],
    relay_peer_id: Vec<u8>,
    path_id: u32,
    transport: i32,
    address_family: i32,
    expires_at_ms: u64,
}

#[derive(Clone)]
struct ExitReservationState {
    phase: ExitReservationPhase,
    route_context_id: [u8; ID_BYTES],
    client_session_id: [u8; NODE_ID_BYTES],
    client_session_public_key: [u8; NODE_ID_BYTES],
    capability_id: [u8; ID_BYTES],
    hold_id: [u8; ID_BYTES],
    exit_boot_id: [u8; ID_BYTES],
    exit_peer_id: Vec<u8>,
    control_relay_node_id: [u8; NODE_ID_BYTES],
    control_relay_peer_id: Vec<u8>,
    signed_capability: Vec<u8>,
    signed_hold: Vec<u8>,
    policy_hash: [u8; NODE_ID_BYTES],
    allowed_transports: Vec<i32>,
    reserved_up_mbps: u64,
    reserved_down_mbps: u64,
    maximum_paths: u32,
    probe_permit_limit: u32,
    created_at_ms: u64,
    hold_expires_at_ms: u64,
    expires_at_ms: u64,
    permits: HashMap<u32, ExitProbePermitState>,
    finalize_id: Option<[u8; ID_BYTES]>,
    finalized_bundle_hash: Option<[u8; NODE_ID_BYTES]>,
    paths: Vec<ExitPathState>,
}

#[derive(Clone)]
struct ExitPathState {
    path_id: u32,
    relay_node_id: [u8; NODE_ID_BYTES],
    relay_peer_id: Vec<u8>,
    client_public_key: WireGuardPublicKey,
    exit_endpoint: ExitEndpointLease,
    authorization_hash: [u8; NODE_ID_BYTES],
    relay_exit_endpoint: Option<PublicWireGuardEndpoint>,
    relay_reservation_hash: Option<[u8; NODE_ID_BYTES]>,
}

impl fmt::Debug for ExitReservationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitReservationState")
            .field("phase", &self.phase)
            .field("permits", &self.permits.len())
            .field("paths", &self.paths.len())
            .field("expires_at_ms", &self.expires_at_ms)
            .field("helper_leases", &self.paths.len())
            .finish_non_exhaustive()
    }
}

/// Public result of one stored relay-to-exit endpoint binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedExitPath {
    reservation_id: [u8; ID_BYTES],
    path_id: u32,
    relay_exit_endpoint: PublicWireGuardEndpoint,
    relay_exit_public_key: WireGuardPublicKey,
    exit_public_key: WireGuardPublicKey,
}

impl ConfirmedExitPath {
    /// Confirmed reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Confirmed context-local path number.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Confirmed public Relay endpoint for the relay-to-Exit link.
    #[must_use]
    pub const fn relay_exit_endpoint(&self) -> PublicWireGuardEndpoint {
        self.relay_exit_endpoint
    }

    /// Relay public key on the relay-to-exit link.
    #[must_use]
    pub const fn relay_exit_public_key(&self) -> WireGuardPublicKey {
        self.relay_exit_public_key
    }

    /// Exit public key on the relay-to-exit link.
    #[must_use]
    pub const fn exit_public_key(&self) -> WireGuardPublicKey {
        self.exit_public_key
    }
}

/// A consumed UDP/443 grant awaiting authenticated QUIC Initial evidence.
///
/// This type intentionally exposes no forwarding, resolution or socket API.
/// Each inspection call consumes it, so callers cannot reuse divergent
/// inspection states for one signed flow.
#[must_use = "pending QUIC evidence must be completed or discarded"]
pub struct PendingQuicUdpFlow {
    path: VerifiedSingleRelayPath,
    flow: AuthorizedUdpFlow,
    expected_hostname: String,
    inspector: Box<QuicInitialInspector>,
    policy_expires_at_ms: u64,
    metrics: Option<MetricsRegistry>,
}

impl PendingQuicUdpFlow {
    /// Authenticate and inspect one datagram containing one client Initial.
    ///
    /// The original DCID supplied at construction derives the packet keys.
    /// Internally, inspection accepts at most 128 bounded Initial datagrams and
    /// 128 CRYPTO fragments. Only exact visible-SNI completion releases a
    /// [`PreparedUdpFlow`]; ECH, missing/mismatched SNI and malformed packets
    /// fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for expired policy/flow/path state, unauthenticated or
    /// malformed QUIC, resource limits, ECH, missing SNI or SNI mismatch.
    pub fn inspect_initial_datagram(
        mut self,
        datagram: &[u8],
        now_ms: u64,
    ) -> Result<Udp443InspectionProgress, ExitError> {
        if now_ms >= self.policy_expires_at_ms {
            self.record_denial();
            return Err(PolicyError::Expired.into());
        }
        if let Err(error) = self.path.ensure_active_at(now_ms) {
            self.record_denial();
            return Err(error.into());
        }
        if let Err(error) = self.flow.ensure_active_at(now_ms) {
            self.record_denial();
            return Err(error.into());
        }
        let inspected = match self.inspector.inspect_datagram(datagram) {
            Ok(inspected) => inspected,
            Err(error) => {
                self.record_denial();
                return Err(map_inspection_error(error));
            }
        };
        match inspected.progress {
            InspectionProgress::NeedMore => Ok(Udp443InspectionProgress::NeedMore(self)),
            InspectionProgress::Complete(server_name) => {
                if server_name.as_str() != self.expected_hostname {
                    self.record_denial();
                    return Err(ExitError::SniMismatch);
                }
                Ok(Udp443InspectionProgress::Complete(PreparedUdpFlow {
                    path: self.path,
                    flow: self.flow,
                }))
            }
        }
    }

    fn record_denial(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_policy_denial();
        }
    }
}

impl fmt::Debug for PendingQuicUdpFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingQuicUdpFlow")
            .field("destination", &"<redacted>")
            .field("expires_at_ms", &self.flow.expires_at_ms())
            .finish_non_exhaustive()
    }
}

/// Result of one authenticated UDP/443 Initial-inspection step.
#[derive(Debug)]
#[must_use = "only Complete authorizes UDP/443 egress"]
pub enum Udp443InspectionProgress {
    /// More Initial CRYPTO evidence is required; no egress is authorized.
    NeedMore(PendingQuicUdpFlow),
    /// Exact visible-SNI evidence completed and released the prepared flow.
    Complete(PreparedUdpFlow),
}

fn signed_udp_hostname(
    encoded_authorization: &[u8],
    flow: &AuthorizedUdpFlow,
) -> Result<String, ExitError> {
    let envelope: SignedEnvelope =
        decode_canonical(encoded_authorization, MAX_CONTROL_MESSAGE_SIZE)?;
    let message: UdpFlowAuthorization =
        decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
    if message.route_context_id.as_slice() != flow.route_context_id()
        || message.flow_id.as_slice() != flow.flow_id()
        || message.client_ephemeral_id.as_slice() != flow.client_ephemeral_id()
        || message.port != u32::from(flow.port())
        || message.hostname.is_empty()
        || !message.destination_ip.is_empty()
    {
        return Err(ExitError::InvalidGrant("UDP/443 hostname binding"));
    }
    Ok(normalize_domain(&message.hostname)?)
}

fn map_inspection_error(error: InspectionError) -> ExitError {
    match error {
        InspectionError::EncryptedClientHello(_) => ExitError::EncryptedClientHello,
        InspectionError::MissingServerName => ExitError::MissingServerName,
        other => ExitError::Inspection(other),
    }
}

/// Validate a complete visible TLS `ClientHello` against an authorized hostname.
///
/// # Errors
///
/// Incomplete/malformed TLS, ECH, missing/duplicate SNI, non-canonical names and
/// hostname mismatches are rejected without including the name in the error.
pub fn inspect_tls_client_hello(bytes: &[u8], expected_hostname: &str) -> Result<(), ExitError> {
    let expected = normalize_domain(expected_hostname)?;
    let mut inspector = TlsClientHelloInspector::new();
    for chunk in bytes.chunks(CLIENT_HELLO_CHUNK_BYTES) {
        match inspector.push(chunk).map_err(map_inspection_error)? {
            InspectionProgress::NeedMore => {}
            InspectionProgress::Complete(server_name) => {
                return if server_name.as_str() == expected {
                    Ok(())
                } else {
                    Err(ExitError::SniMismatch)
                };
            }
        }
    }
    match inspector.finish() {
        Ok(_) => Err(ExitError::Inspection(InspectionError::AlreadyComplete)),
        Err(error) => Err(map_inspection_error(error)),
    }
}

async fn read_client_hello_prefix<C>(
    stream: &mut C,
    expected_hostname: &str,
) -> Result<Vec<u8>, ExitError>
where
    C: AsyncRead + Unpin,
{
    let expected = normalize_domain(expected_hostname)?;
    let mut input = Vec::with_capacity(CLIENT_HELLO_CHUNK_BYTES);
    let mut chunk = [0_u8; CLIENT_HELLO_CHUNK_BYTES];
    let mut inspector = TlsClientHelloInspector::new();
    loop {
        if input.len() == MAX_CLIENT_HELLO_BYTES {
            return Err(ExitError::Inspection(InspectionError::ResourceLimit(
                "TLS ClientHello stream bytes",
            )));
        }
        let remaining = MAX_CLIENT_HELLO_BYTES - input.len();
        let read_length = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_length]).await?;
        if count == 0 {
            return match inspector.finish() {
                Ok(_) => Err(ExitError::Inspection(InspectionError::AlreadyComplete)),
                Err(error) => Err(map_inspection_error(error)),
            };
        }
        input.extend_from_slice(&chunk[..count]);
        match inspector
            .push(&chunk[..count])
            .map_err(map_inspection_error)?
        {
            InspectionProgress::NeedMore => {}
            InspectionProgress::Complete(server_name) => {
                if server_name.as_str() != expected {
                    return Err(ExitError::SniMismatch);
                }
                return Ok(input);
            }
        }
    }
}

async fn resolve_and_connect(
    hostname: Option<&str>,
    destination_ip: Option<IpAddr>,
    port: u16,
    dns_timeout: Duration,
    connect_timeout: Duration,
) -> Result<TcpStream, ExitError> {
    let addresses = if let Some(hostname) = hostname {
        let resolved = time::timeout(dns_timeout, lookup_host((hostname, port)))
            .await
            .map_err(|_| ExitError::EgressTimeout("DNS"))??;
        let mut addresses = Vec::new();
        for address in resolved.take(MAX_DNS_RESULTS) {
            if permitted_egress(address.ip())
                && destination_ip.is_none_or(|pinned| pinned == address.ip())
                && !addresses.contains(&address)
            {
                addresses.push(address);
            }
        }
        addresses
    } else if let Some(destination_ip) = destination_ip {
        if !permitted_egress(destination_ip) {
            return Err(ExitError::ResolutionFailed);
        }
        vec![SocketAddr::new(destination_ip, port)]
    } else {
        return Err(ExitError::ResolutionFailed);
    };
    if addresses.is_empty() {
        return Err(ExitError::ResolutionFailed);
    }
    time::timeout(connect_timeout, async move {
        let mut last_error = None;
        for address in addresses {
            let socket = contribution_tcp_socket(address)?;
            match socket.connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no permitted address")
        }))
    })
    .await
    .map_err(|_| ExitError::EgressTimeout("TCP connect"))?
    .map_err(ExitError::Io)
}

fn contribution_tcp_socket(address: SocketAddr) -> std::io::Result<TcpSocket> {
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    // Set before connect so SYNs and every subsequent payload use the contribution band.
    // Failure must not open an unclassified connection or try an unclassified fallback.
    SockRef::from(&socket).set_priority(CONTRIBUTION_SOCKET_PRIORITY)?;
    Ok(socket)
}

async fn run_tcp_egress_with_policy<C>(
    policy: &VerifiedManifest,
    metrics: Option<&MetricsRegistry>,
    flow: &AuthorizedTcpFlow,
    mut protected_client: C,
    now_ms: u64,
    limits: TcpEgressLimits,
) -> Result<StreamTransferStats, ExitError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    flow.ensure_active_at(now_ms)?;
    policy.ensure_active_at(now_ms)?;

    let initial = if flow.hostname().is_some() {
        let hostname = flow.hostname().ok_or(ExitError::ResolutionFailed)?;
        match time::timeout(
            limits.client_hello_timeout,
            read_client_hello_prefix(&mut protected_client, hostname),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                if let Some(metrics) = metrics {
                    metrics.record_policy_denial();
                }
                return Err(error);
            }
            Err(_elapsed) => {
                if let Some(metrics) = metrics {
                    metrics.record_policy_denial();
                }
                return Err(ExitError::EgressTimeout("TLS ClientHello"));
            }
        }
    } else {
        Vec::new()
    };

    let mut destination = resolve_and_connect(
        flow.hostname(),
        flow.destination_ip(),
        flow.port(),
        limits.dns_timeout,
        limits.connect_timeout,
    )
    .await?;
    if !initial.is_empty() {
        time::timeout(
            limits.transfer.idle_timeout(),
            destination.write_all(&initial),
        )
        .await
        .map_err(|_| ExitError::EgressTimeout("initial TLS forwarding"))??;
    }
    let prefix_bytes =
        u64::try_from(initial.len()).map_err(|_| ExitError::InvalidGrant("ClientHello length"))?;
    let remaining_up = limits
        .transfer
        .maximum_client_to_exit_bytes()
        .checked_sub(prefix_bytes)
        .filter(|remaining| *remaining > 0)
        .ok_or(TcpProxyError::ByteLimit)?;
    let adjusted = StreamTransferLimits::new(
        limits.transfer.buffer_bytes(),
        remaining_up,
        limits.transfer.maximum_exit_to_client_bytes(),
        limits.transfer.idle_timeout(),
    )?;
    let mut statistics = proxy_bidirectional(protected_client, destination, adjusted).await?;
    statistics.client_to_exit_bytes = statistics
        .client_to_exit_bytes
        .checked_add(prefix_bytes)
        .ok_or(TcpProxyError::ByteLimit)?;
    if let Some(metrics) = metrics {
        metrics.record_throughput(
            statistics.client_to_exit_bytes,
            statistics.exit_to_client_bytes,
        );
    }
    Ok(statistics)
}

fn permitted_egress(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => permitted_v4(address),
        IpAddr::V6(address) => permitted_v6(address),
    }
}

fn permitted_v4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && (18..=19).contains(&second)))
}

fn permitted_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return permitted_v4(mapped);
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.segments()[..2] == [0x2001, 0x0db8])
}

fn validate_egress_timeout(timeout: Duration) -> Result<(), ExitError> {
    if timeout.is_zero() || timeout > MAX_EGRESS_TIMEOUT {
        return Err(ExitError::InvalidConfig("egress timeout"));
    }
    Ok(())
}

fn unix_seconds(milliseconds: u64) -> UnixTime {
    UnixTime::from_secs(milliseconds / 1_000)
}

fn text_id<T>(bytes: &[u8]) -> Result<T, ExitError>
where
    T: TryFrom<String>,
{
    T::try_from(hex::encode(bytes)).map_err(|_| ExitError::InvalidGrant("identifier"))
}

fn fixed<const N: usize>(bytes: &[u8], name: &'static str) -> Result<[u8; N], ExitError> {
    bytes.try_into().map_err(|_| ExitError::InvalidGrant(name))
}

fn validate_native_route_identity(
    request: &ExitNativeRouteIdentityRequest,
    identity: &NativeRouteIdentity,
) -> Result<[u8; NODE_ID_BYTES], ExitNativeRouteIdentityError> {
    let certificate_sha256 = <[u8; NODE_ID_BYTES]>::try_from(&identity.certificate_sha256[..])
        .map_err(|_| {
            ExitNativeRouteIdentityError::Rejected("invalid native route certificate hash")
        })?;
    let spki_sha256 = <[u8; NODE_ID_BYTES]>::try_from(&identity.spki_sha256[..]).map_err(|_| {
        ExitNativeRouteIdentityError::Rejected("invalid native route public-key hash")
    })?;
    let exit_native_instance_id =
        <[u8; NODE_ID_BYTES]>::try_from(&identity.exit_native_instance_id[..])
            .map_err(|_| ExitNativeRouteIdentityError::Rejected("invalid exit native instance"))?;
    let credential_hpke_public_key =
        <[u8; NODE_ID_BYTES]>::try_from(&identity.credential_hpke_public_key[..]).map_err(
            |_| ExitNativeRouteIdentityError::Rejected("invalid native credential recipient key"),
        )?;
    if identity.auth_commitment.as_slice() != request.auth_commitment
        || identity.masque_context_id != request.masque_context_id
        || identity.client_native_instance_id.as_slice() != request.client_native_instance_id
        || exit_native_instance_id != request.exit_native_instance_id
        || certificate_sha256 == [0; NODE_ID_BYTES]
        || spki_sha256 == [0; NODE_ID_BYTES]
        || exit_native_instance_id == [0; NODE_ID_BYTES]
        || credential_hpke_public_key == [0; NODE_ID_BYTES]
        || !canonical_dns_name(&identity.tls_server_name)
    {
        return Err(ExitNativeRouteIdentityError::Rejected(
            "invalid or mismatched native route public identity",
        ));
    }
    Ok(exit_native_instance_id)
}

fn canonical_dns_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 253
        || name.ends_with('.')
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
        || name.parse::<IpAddr>().is_ok()
        || !name.contains('.')
    {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_pem(bytes: &[u8], maximum: usize, begin: &[u8], end: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.contains(&0)
        || bytes.contains(&b'\r')
        || !bytes.starts_with(begin)
    {
        return false;
    }
    let Some(after_begin) = bytes.get(begin.len()..) else {
        return false;
    };
    if !after_begin.starts_with(b"\n") {
        return false;
    }
    let without_final_newline = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let Some(before_end) = without_final_newline.strip_suffix(end) else {
        return false;
    };
    let Some(body) = before_end.get(begin.len() + 1..) else {
        return false;
    };
    !body.is_empty()
        && body.iter().any(|byte| (0x21..=0x7e).contains(byte))
        && body
            .iter()
            .all(|byte| *byte == b'\n' || (0x21..=0x7e).contains(byte))
}

fn wire_endpoint(endpoint: PublicWireGuardEndpoint) -> volparossa_protocol::WireguardEndpoint {
    let underlay_ip = match endpoint.underlay_ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    volparossa_protocol::WireguardEndpoint {
        underlay_scope: if endpoint.is_local_lan() {
            volparossa_protocol::UnderlayScope::DirectLocalLan
        } else {
            volparossa_protocol::UnderlayScope::PublicInternet
        } as i32,
        public_key: endpoint.public_key().as_bytes().to_vec(),
        underlay_ip,
        listen_port: u32::from(endpoint.listen_port()),
    }
}

fn public_endpoint(
    endpoint: &volparossa_protocol::WireguardEndpoint,
    name: &'static str,
) -> Result<PublicWireGuardEndpoint, ExitError> {
    endpoint.validate(name)?;
    let key = public_key(&endpoint.public_key, name)?;
    let address = match endpoint.underlay_ip.as_slice() {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        bytes => IpAddr::V6(Ipv6Addr::from(fixed::<16>(bytes, name)?)),
    };
    let port = u16::try_from(endpoint.listen_port).map_err(|_| ExitError::InvalidGrant(name))?;
    let endpoint = match volparossa_protocol::UnderlayScope::try_from(endpoint.underlay_scope) {
        Ok(volparossa_protocol::UnderlayScope::PublicInternet) => {
            PublicWireGuardEndpoint::new(key, address, port)
        }
        Ok(volparossa_protocol::UnderlayScope::DirectLocalLan) => {
            PublicWireGuardEndpoint::new_direct_local_lan(key, address, port)
        }
        Err(_) => return Err(ExitError::InvalidGrant(name)),
    };
    endpoint.map_err(|_| ExitError::InvalidGrant(name))
}

fn public_key(bytes: &[u8], name: &'static str) -> Result<WireGuardPublicKey, ExitError> {
    let bytes = fixed(bytes, name)?;
    if bytes == [0; NODE_ID_BYTES] {
        return Err(ExitError::InvalidGrant(name));
    }
    Ok(WireGuardPublicKey::from_bytes(bytes))
}

/// Fail-closed exit admission, policy, inspection and egress errors.
#[derive(Debug, Error)]
pub enum ExitError {
    /// The operator has not explicitly enabled exit mode.
    #[error("exit role is disabled")]
    Disabled,
    /// A configured bound is zero, inconsistent or excessive.
    #[error("invalid exit configuration: {0}")]
    InvalidConfig(&'static str),
    /// Signed control verification failed.
    #[error("exit control authorization failed: {0}")]
    Protocol(#[from] ProtocolError),
    /// Threshold-signed policy validation or authorization failed.
    #[error("exit policy rejected the request: {0}")]
    Policy(#[from] PolicyError),
    /// The bounded exact-response cache is full of still-live reservations.
    #[error("exit idempotency cache is full")]
    IdempotencyCapacity,

    /// The supplied local signer is not this configured exit.
    #[error("local signing identity does not match configured exit")]
    LocalIdentityMismatch,
    /// The forwarding connection is not the control relay bound by the envelope.
    #[error("authenticated control relay does not match the signed forwarding scope")]
    ControlRelayMismatch,
    /// A phase artifact belongs to another process boot incarnation.
    #[error("exit boot incarnation does not match the live process")]
    ExitBootMismatch,
    /// No real helper-proven and exit-participating probe evidence producer exists.
    #[error("production probe evidence is unavailable")]
    ProbeEvidenceUnavailable,
    /// A configured external probe evidence verifier rejected an exact artifact.
    #[error("probe evidence rejected: {0}")]
    ProbeEvidenceRejected(&'static str),
    /// Native route public identity or private ownership was unavailable or invalid.
    #[error("exit native route identity failed: {0}")]
    NativeRouteIdentity(#[from] ExitNativeRouteIdentityError),
    /// RFC 9180 native bearer delivery was malformed, undecryptable or contradicted its public
    /// commitment.
    #[error("exit native route credential delivery failed: {0}")]
    NativeRouteCredential(#[from] NativeRouteCredentialError),
    /// The route-scoped native authorization was absent or already consumed.
    #[error("exit native route authorization is unavailable or already consumed")]
    NativeRouteAuthorizationUnavailable,
    /// The requested native authorization did not exactly match its stored owner.
    #[error("exit native route authorization scope mismatch")]
    NativeRouteAuthorizationMismatch,
    /// A signed route or reservation did not match local state.
    #[error("invalid exit grant: {0}")]
    InvalidGrant(&'static str),
    /// The reservation does not permit the requested transport.
    #[error("reservation does not authorize this transport")]
    TransportDenied,
    /// A reservation was already bound to a dataplane transport.
    #[error("reservation dataplane was already activated")]
    AlreadyActivated,
    /// The mandatory client-to-exit relay confirmation has not completed for every path.
    #[error("reservation relay confirmation is incomplete")]
    ConfirmationRequired,
    /// No helper/orchestrator-confirmed local endpoint lease was available.
    #[error("route-specific WireGuard endpoint is unavailable")]
    EndpointUnavailable,
    /// Local helper lease state contradicted an authenticated reservation.
    #[error("exit helper-lease state invariant failed")]
    LeaseInvariant,
    /// A rollback contradicted the capacity-ledger invariant.
    #[error("exit capacity-ledger invariant failed")]
    LedgerInvariant,
    /// Atomic capacity accounting failed.
    #[error("exit reservation accounting failed: {0}")]
    Reservation(#[from] ReservationError),
    /// TCP route, flow, streaming or MPTCP validation failed.
    #[error("exit TCP processing failed: {0}")]
    Tcp(#[from] TcpProxyError),
    /// UDP route, flow, QUIC or connected-socket validation failed.
    #[error("exit UDP processing failed: {0}")]
    Udp(#[from] UdpError),
    /// Bounded TLS or authenticated QUIC inspection failed.
    #[error("exit destination inspection failed: {0}")]
    Inspection(#[source] InspectionError),
    /// TLS Encrypted `ClientHello` is unsupported in v1 and was rejected.
    #[error("TLS Encrypted ClientHello is not verifiable in version 1")]
    EncryptedClientHello,
    /// A TLS `ClientHello` contained no single visible server name.
    #[error("TLS ClientHello has no verifiable server name")]
    MissingServerName,
    /// Visible TLS SNI differed from the signed requested hostname.
    #[error("TLS server name does not match the authorized hostname")]
    SniMismatch,
    /// UDP/443 was passed to the general path instead of its evidence path.
    #[error("UDP/443 requires authenticated QUIC ClientHello evidence")]
    QuicInspectionUnavailable,
    /// The QUIC evidence path was requested for a destination other than UDP/443.
    #[error("QUIC ClientHello evidence is accepted only for UDP/443")]
    QuicInspectionPortRequired,
    /// An authorized name returned no permitted public Internet address.
    #[error("authorized name did not resolve to a permitted Internet address")]
    ResolutionFailed,
    /// A bounded DNS, connect or TLS-inspection operation timed out.
    #[error("exit egress operation timed out: {0}")]
    EgressTimeout(&'static str),
    /// Exit-side socket or stream I/O failed.
    #[error("exit egress I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn contribution_tcp_sockets_are_classified_before_connect() {
        for address in ["127.0.0.1:443", "[::1]:443"] {
            let socket = super::contribution_tcp_socket(address.parse().expect("test tuple"))
                .expect("unconnected contribution socket");
            let descriptor = socket2::SockRef::from(&socket);
            assert_eq!(
                descriptor.priority().expect("kernel contribution priority"),
                volparossa_core::CONTRIBUTION_SOCKET_PRIORITY,
            );
            assert!(descriptor.peer_addr().is_err());
        }
        let owner = tokio::net::TcpSocket::new_v4().expect("unmodified owner socket");
        assert_eq!(socket2::SockRef::from(&owner).priority().unwrap(), 0);
    }

    #[test]
    fn local_endpoint_scope_survives_exit_wire_mapping() {
        use super::{public_endpoint, wire_endpoint};

        let local = PublicWireGuardEndpoint::new_direct_local_lan(
            WireGuardPublicKey::from_bytes([7; 32]),
            "192.168.20.2".parse().expect("LAN address"),
            51820,
        )
        .expect("explicit local endpoint");
        let mut wire = wire_endpoint(local);
        assert_eq!(
            wire.underlay_scope,
            volparossa_protocol::UnderlayScope::DirectLocalLan as i32
        );
        assert_eq!(
            public_endpoint(&wire, "endpoint").expect("scoped round trip"),
            local
        );
        wire.underlay_scope = volparossa_protocol::UnderlayScope::PublicInternet as i32;
        assert!(public_endpoint(&wire, "endpoint").is_err());
    }

    use ring::aead;

    use ed25519_dalek::{Signer as _, SigningKey};
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };
    use tokio::io::AsyncWriteExt as _;

    use volparossa_core::Bandwidth;
    use volparossa_metrics::MetricsRegistry;
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_protocol::{
        MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, NativeRouteCredentialDelivery,
        NativeRouteIdentity, ProbeAddressFamily, ProbeLegEvidence, ProtocolError, RelayProbePermit,
        RelayProbeResult, RelayReservation, ReplayCache, SignedEnvelope, TimePolicy, Transport,
        decode_canonical, generate_nonce, node_id_from_public_key, sign_control_message,
        verify_control_message,
    };
    use volparossa_relay::{RelayService, RelayServiceConfig};
    use volparossa_reservation::{
        CoordinatorError, ExitReservationIntent, RelayPathIntent, ReservationCoordinator,
    };
    use volparossa_test_support::{ephemeral_signing_key, verified_development_manifest};

    use super::{
        AcceptedExitReservation, ExitError, ExitNativeRouteAuthorizationScope,
        ExitNativeRouteIdentityError, ExitNativeRouteIdentityOwner,
        ExitNativeRouteIdentityProvider, ExitNativeRouteIdentityRequest, ExitService,
        ExitServiceConfig, InspectionError, PendingQuicUdpFlow, ProbeEvidence, ProbeEvidenceError,
        ProbeEvidenceVerifier, StreamTransferLimits, TcpEgressLimits, Udp443InspectionProgress,
        inspect_tls_client_hello,
    };
    use volparossa_wireguard::{
        ClientEndpointLease, EndpointRole, ExitEndpointLease, HelperContextHandle,
        HelperLeaseHandle, PublicWireGuardEndpoint, RelayEndpointLease, WireGuardPublicKey,
    };

    const NOW_MS: u64 = 1_700_000_000_000;
    const TEST_TLS_CERTIFICATE_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    const TEST_TLS_PRIVATE_KEY_PEM: &[u8] =
        b"-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n";
    const TEST_EXIT_NATIVE_INSTANCE_ID: [u8; 32] = [43; 32];

    // Public RFC 9001 Appendix A QUIC v1 client-Initial test vector.
    const TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    const TEST_INITIAL_KEY: [u8; 16] = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2,
        0x2d,
    ];
    const TEST_INITIAL_IV: [u8; 12] = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    ];
    const TEST_INITIAL_HP: [u8; 16] = [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed,
        0xd2,
    ];
    struct AdmittedRoute {
        accepted: AcceptedExitReservation,
        signed_relays: Vec<Vec<u8>>,
        coordinator: ReservationCoordinator,
        route_context_id: [u8; 16],
        expires_at_ms: u64,
    }

    impl AdmittedRoute {
        fn sign_open_tcp(&self, policy_hash: &[u8; 32], hostname: &str, port: u16) -> Vec<u8> {
            self.coordinator
                .sign_open_tcp(
                    self.route_context_id,
                    *policy_hash,
                    hostname,
                    port,
                    NOW_MS,
                    self.expires_at_ms.min(NOW_MS + 60_000),
                )
                .unwrap()
        }

        fn sign_udp_hostname(&self, policy_hash: &[u8; 32], hostname: &str, port: u16) -> Vec<u8> {
            self.coordinator
                .sign_udp_hostname(
                    self.route_context_id,
                    *policy_hash,
                    hostname,
                    port,
                    30_000,
                    NOW_MS,
                    self.expires_at_ms.min(NOW_MS + 60_000),
                )
                .unwrap()
        }
    }

    struct ExactProbeVerifier {
        expected: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl ProbeEvidenceVerifier for ExactProbeVerifier {
        fn verify(&self, evidence: &ProbeEvidence<'_>) -> Result<(), ProbeEvidenceError> {
            let exact = self.expected.iter().any(|(permit, result)| {
                permit.as_slice() == evidence.signed_permit()
                    && result.as_slice() == evidence.signed_result()
            });
            let client_relay = evidence.client_relay();
            let relay_exit = evidence.relay_exit();
            if !exact
                || evidence.transport() == Transport::Unspecified
                || evidence.address_family() != ProbeAddressFamily::Ipv4
                || client_relay.up_capacity_mbps != 100
                || client_relay.down_capacity_mbps != 100
                || relay_exit.up_capacity_mbps != 100
                || relay_exit.down_capacity_mbps != 100
                || client_relay.transmitted_bytes == 0
                || client_relay.received_bytes == 0
                || relay_exit.transmitted_bytes == 0
                || relay_exit.received_bytes == 0
                || client_relay.window_started_at_ms != NOW_MS - 50
                || client_relay.window_ended_at_ms != NOW_MS
                || relay_exit.window_started_at_ms != NOW_MS - 50
                || relay_exit.window_ended_at_ms != NOW_MS
            {
                return Err(ProbeEvidenceError::Rejected("test verifier exact evidence"));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct ExactNativeIdentityProvider {
        calls: usize,
    }

    impl ExitNativeRouteIdentityProvider for ExactNativeIdentityProvider {
        fn provide(
            &mut self,
            request: &ExitNativeRouteIdentityRequest,
        ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
            self.calls += 1;
            test_native_identity_owner(*request)
        }
    }

    #[derive(Clone, Copy)]
    enum NativeIdentityRequestMismatch {
        Reservation,
        RouteContext,
        Finalize,
        Commitment,
        MasqueContext,
        ClientInstance,
        ExitInstance,
    }

    struct MismatchedNativeIdentityProvider(NativeIdentityRequestMismatch);

    impl ExitNativeRouteIdentityProvider for MismatchedNativeIdentityProvider {
        fn provide(
            &mut self,
            request: &ExitNativeRouteIdentityRequest,
        ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
            let reservation_id = match self.0 {
                NativeIdentityRequestMismatch::Reservation => [91; 16],
                _ => *request.reservation_id(),
            };
            let route_context_id = match self.0 {
                NativeIdentityRequestMismatch::RouteContext => [92; 16],
                _ => *request.route_context_id(),
            };
            let finalize_id = match self.0 {
                NativeIdentityRequestMismatch::Finalize => [93; 16],
                _ => *request.finalize_id(),
            };
            let auth_commitment = match self.0 {
                NativeIdentityRequestMismatch::Commitment => [94; 32],
                _ => *request.auth_commitment(),
            };
            let masque_context_id = match self.0 {
                NativeIdentityRequestMismatch::MasqueContext => request.masque_context_id() + 1,
                _ => request.masque_context_id(),
            };
            let client_native_instance_id = match self.0 {
                NativeIdentityRequestMismatch::ClientInstance => [95; 32],
                _ => *request.client_native_instance_id(),
            };
            let exit_native_instance_id = match self.0 {
                NativeIdentityRequestMismatch::ExitInstance => [96; 32],
                _ => *request.exit_native_instance_id(),
            };
            let mismatched = ExitNativeRouteIdentityRequest::new(
                reservation_id,
                route_context_id,
                finalize_id,
                auth_commitment,
                masque_context_id,
                client_native_instance_id,
                exit_native_instance_id,
            )?;
            test_native_identity_owner(mismatched)
        }
    }

    struct PanickingNativeIdentityProvider;

    impl ExitNativeRouteIdentityProvider for PanickingNativeIdentityProvider {
        fn provide(
            &mut self,
            _request: &ExitNativeRouteIdentityRequest,
        ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
            panic!("exact finalize retry must not request or clone TLS ownership")
        }
    }

    fn test_native_identity_owner(
        request: ExitNativeRouteIdentityRequest,
    ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
        ExitNativeRouteIdentityOwner::new(
            request,
            NativeRouteIdentity {
                auth_commitment: request.auth_commitment().to_vec(),
                certificate_sha256: vec![41; 32],
                spki_sha256: vec![42; 32],
                tls_server_name: "route.exit.example".to_owned(),
                masque_context_id: request.masque_context_id(),
                client_native_instance_id: request.client_native_instance_id().to_vec(),
                exit_native_instance_id: request.exit_native_instance_id().to_vec(),
                credential_hpke_public_key: Vec::new(),
            },
            TEST_TLS_CERTIFICATE_PEM.to_vec(),
            TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
        )
    }

    fn probe_leg(rtt_micros: u64) -> ProbeLegEvidence {
        ProbeLegEvidence {
            up_capacity_mbps: 100,
            down_capacity_mbps: 100,
            rtt_micros,
            transmitted_bytes: 8_192,
            received_bytes: 8_192,
            window_started_at_ms: NOW_MS - 50,
            window_ended_at_ms: NOW_MS,
            measured_at_ms: NOW_MS,
        }
    }

    fn admit_route(
        relay_count: usize,
        transports: &[Transport],
        rules: Vec<DestinationRule>,
        metrics: MetricsRegistry,
    ) -> (ExitService, AdmittedRoute) {
        let maximum_paths = u32::try_from(relay_count).unwrap();
        let selected_path_ids = (1..=maximum_paths).collect::<Vec<_>>();
        admit_route_with_probe_selection(
            relay_count,
            maximum_paths,
            &selected_path_ids,
            transports,
            rules,
            metrics,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the test deliberately exercises the full v4 hold, probe, finalize, relay and receipt transaction"
    )]
    fn admit_route_with_probe_selection(
        probe_permit_limit: usize,
        maximum_paths: u32,
        selected_path_ids: &[u32],
        transports: &[Transport],
        rules: Vec<DestinationRule>,
        metrics: MetricsRegistry,
    ) -> (ExitService, AdmittedRoute) {
        let probe_permit_limit = u32::try_from(probe_permit_limit).unwrap();
        assert!((1..=8).contains(&probe_permit_limit));
        assert!((1..=probe_permit_limit).contains(&maximum_paths));
        assert!(!selected_path_ids.is_empty());
        assert!(selected_path_ids.len() <= usize::try_from(maximum_paths).unwrap());
        assert!(
            selected_path_ids
                .iter()
                .all(|path_id| (1..=probe_permit_limit).contains(path_id))
        );
        assert!(selected_path_ids.windows(2).all(|pair| pair[0] < pair[1]));

        let policy = verified_development_manifest(NOW_MS, rules).unwrap();
        let policy_hash = *policy.policy_hash();
        let exit_key = ephemeral_signing_key();
        let control_relay_key = ephemeral_signing_key();
        let relay_keys: Vec<SigningKey> = (0..probe_permit_limit)
            .map(|_| ephemeral_signing_key())
            .collect();
        let exit_node_id = node_id(&exit_key);
        let exit_peer_id = peer_id(&exit_key);
        let control_relay_node_id = node_id(&control_relay_key);
        let control_relay_peer_id = peer_id(&control_relay_key);
        let reservation_id = [81; 16];
        let route_context_id = [82; 16];
        let created_at_ms = NOW_MS - 100;
        let hold_expires_at_ms = NOW_MS + 20_000;
        let expires_at_ms = NOW_MS + 120_000;
        let relay_paths = relay_keys
            .iter()
            .enumerate()
            .map(|(index, relay_key)| RelayPathIntent {
                path_id: u32::try_from(index + 1).unwrap(),
                relay_node_id: node_id(relay_key),
                relay_peer_id: peer_id(relay_key),
            })
            .collect::<Vec<_>>();
        let intent = ExitReservationIntent {
            reservation_id,
            route_context_id,
            exit_node_id,
            exit_peer_id: exit_peer_id.clone(),
            control_relay_node_id,
            control_relay_peer_id: control_relay_peer_id.clone(),
            allowed_transports: transports.to_vec(),
            reserved_up_mbps: 100,
            reserved_down_mbps: 100,
            maximum_paths,
            probe_permit_limit,
            policy_hash,
            created_at_ms,
            hold_expires_at_ms,
            reservation_expires_at_ms: expires_at_ms,
            masque_context_id: 7,
            client_native_instance_id: [83; 32],
        };
        let mut coordinator = ReservationCoordinator::new(128).unwrap();
        let signed_hold_request = coordinator.sign_hold_request(&intent).unwrap();
        let mut service = ExitService::new(
            ExitServiceConfig::enabled(
                exit_node_id,
                Bandwidth::new(500, 500).unwrap(),
                4,
                900,
                10,
                256,
            ),
            policy,
            Some(metrics),
        )
        .unwrap();
        let accepted_hold = service
            .hold_capacity_with(
                &signed_hold_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .unwrap();
        let hold_retry = service
            .hold_capacity_with(
                &signed_hold_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |_message| -> Option<[u8; 64]> {
                    panic!("exact hold retry must use the cached signed bytes")
                },
            )
            .unwrap();
        assert_eq!(
            accepted_hold.signed_capability(),
            hold_retry.signed_capability()
        );
        assert_eq!(accepted_hold.signed_hold(), hold_retry.signed_hold());
        let verified_hold = coordinator
            .verify_hold_response(
                &intent,
                accepted_hold.signed_capability().to_vec(),
                accepted_hold.signed_hold().to_vec(),
                &exit_peer_id,
                NOW_MS,
            )
            .unwrap();

        let probe_transport = *transports.first().unwrap();
        let probe_expires_at_ms = NOW_MS + 15_000;
        let mut probes = Vec::with_capacity(usize::try_from(probe_permit_limit).unwrap());
        let mut exact_evidence = Vec::with_capacity(usize::try_from(probe_permit_limit).unwrap());
        for (path, relay_key) in relay_paths.iter().zip(&relay_keys) {
            let request = coordinator
                .sign_probe_permit_request(
                    &verified_hold,
                    path,
                    probe_transport,
                    ProbeAddressFamily::Ipv4,
                    NOW_MS,
                    probe_expires_at_ms,
                )
                .unwrap();
            let accepted_permit = service
                .issue_probe_permit_with(
                    request.encoded(),
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    |message| Some(exit_key.sign(message).to_bytes()),
                )
                .unwrap();
            let verified_permit = coordinator
                .verify_probe_permit(&request, accepted_permit.encoded().to_vec(), NOW_MS)
                .unwrap();
            let mut permit_replay = ReplayCache::new(2).unwrap();
            let permit = verify_control_message::<RelayProbePermit>(
                accepted_permit.encoded(),
                NOW_MS,
                TimePolicy::default(),
                &mut permit_replay,
            )
            .unwrap()
            .into_message();
            let nonce = generate_nonce();
            let result = RelayProbeResult {
                probe_id: permit.probe_id.clone(),
                relay_probe_permit: accepted_permit.encoded().to_vec(),
                relay_node_id: permit.relay_node_id.clone(),
                relay_peer_id: permit.relay_peer_id.clone(),
                exit_node_id: permit.exit_node_id.clone(),
                exit_peer_id: permit.exit_peer_id.clone(),
                exit_boot_id: permit.exit_boot_id.clone(),
                hold_id: permit.hold_id.clone(),
                capability_id: permit.capability_id.clone(),
                reservation_id: permit.reservation_id.clone(),
                route_context_id: permit.route_context_id.clone(),
                client_session_id: permit.client_session_id.clone(),
                policy_hash: permit.policy_hash.clone(),
                transport: permit.transport,
                address_family: permit.address_family,
                client_relay: Some(probe_leg(2_000)),
                relay_exit: Some(probe_leg(3_000)),
                measured_at_ms: NOW_MS,
                expires_at_ms: permit.expires_at_ms,
                nonce: nonce.to_vec(),
            };
            let signed_result = sign_control_message(
                &result,
                relay_key,
                NOW_MS,
                result.expires_at_ms,
                nonce,
                TimePolicy::default(),
            )
            .unwrap();
            exact_evidence.push((accepted_permit.encoded().to_vec(), signed_result.clone()));
            let mut substituted_result = result.clone();
            *substituted_result.relay_probe_permit.last_mut().unwrap() ^= 1;
            let substituted_nonce = generate_nonce();
            substituted_result.nonce = substituted_nonce.to_vec();
            let signed_substitution = sign_control_message(
                &substituted_result,
                relay_key,
                NOW_MS,
                substituted_result.expires_at_ms,
                substituted_nonce,
                TimePolicy::default(),
            )
            .unwrap();
            assert!(matches!(
                coordinator.verify_probe_result(
                    verified_permit.clone(),
                    signed_substitution,
                    NOW_MS,
                ),
                Err(CoordinatorError::Scope("relay probe result"))
            ));
            let verified_probe = coordinator
                .verify_probe_result(verified_permit, signed_result.clone(), NOW_MS)
                .unwrap();
            assert_eq!(verified_probe.signed_result(), signed_result.as_slice());
            assert_eq!(verified_probe.transport(), probe_transport);
            assert_eq!(verified_probe.address_family(), ProbeAddressFamily::Ipv4);
            assert_eq!(
                verified_probe.client_relay(),
                result.client_relay.as_ref().unwrap()
            );
            assert_eq!(
                verified_probe.relay_exit(),
                result.relay_exit.as_ref().unwrap()
            );
            probes.push(verified_probe);
        }

        let selected_probes = selected_path_ids
            .iter()
            .map(|path_id| probes[usize::try_from(path_id - 1).unwrap()].clone())
            .collect::<Vec<_>>();
        let finalize_request = coordinator
            .sign_finalize_request(
                &intent,
                &verified_hold,
                &selected_probes,
                NOW_MS,
                hold_expires_at_ms,
                |path_id| client_endpoint(route_context_id, path_id),
            )
            .unwrap();
        assert!(matches!(
            service.finalize_reservation_with(
                finalize_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |_path_id| -> Option<ExitEndpointLease> {
                    panic!("unavailable evidence must precede endpoint allocation")
                },
                |_message| -> Option<[u8; 64]> {
                    panic!("unavailable evidence must precede signing")
                },
            ),
            Err(ExitError::ProbeEvidenceUnavailable)
        ));
        let held_state = service.endpoint_states.values().next().unwrap();
        assert_eq!(held_state.phase, super::ExitReservationPhase::Held);
        assert_eq!(
            held_state.permits.len(),
            usize::try_from(probe_permit_limit).unwrap()
        );
        assert_eq!(
            service.permit_response_cache.len(),
            usize::try_from(probe_permit_limit).unwrap()
        );
        let held_capacity = service.available(NOW_MS).unwrap();
        assert_eq!(held_capacity.bandwidth, Bandwidth::new(400, 400).unwrap());
        assert_eq!(held_capacity.free_slots, 3);

        let verifier = ExactProbeVerifier {
            expected: exact_evidence,
        };
        assert!(matches!(
            service.finalize_reservation_with_evidence_verifier(
                finalize_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                &verifier,
                |_path_id| -> Option<ExitEndpointLease> {
                    panic!("unavailable native identity must precede endpoint allocation")
                },
                |_message| -> Option<[u8; 64]> {
                    panic!("unavailable native identity must precede signing")
                },
            ),
            Err(ExitError::NativeRouteIdentity(
                ExitNativeRouteIdentityError::Unavailable
            ))
        ));
        let mut zero_instance_provider = PanickingNativeIdentityProvider;
        assert!(matches!(
            service.finalize_reservation_with_providers(
                finalize_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                &verifier,
                &mut zero_instance_provider,
                [0; 32],
                |_path_id| -> Option<ExitEndpointLease> {
                    panic!("invalid native preflight must precede endpoint allocation")
                },
                |_message| -> Option<[u8; 64]> {
                    panic!("invalid native preflight must precede signing")
                },
            ),
            Err(ExitError::NativeRouteIdentity(
                ExitNativeRouteIdentityError::Rejected("invalid native route request scope")
            ))
        ));
        for mismatch in [
            NativeIdentityRequestMismatch::Reservation,
            NativeIdentityRequestMismatch::RouteContext,
            NativeIdentityRequestMismatch::Finalize,
            NativeIdentityRequestMismatch::Commitment,
            NativeIdentityRequestMismatch::MasqueContext,
            NativeIdentityRequestMismatch::ClientInstance,
            NativeIdentityRequestMismatch::ExitInstance,
        ] {
            let mut mismatched_identity_provider = MismatchedNativeIdentityProvider(mismatch);
            assert!(matches!(
                service.finalize_reservation_with_providers(
                    finalize_request.encoded(),
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    &verifier,
                    &mut mismatched_identity_provider,
                    TEST_EXIT_NATIVE_INSTANCE_ID,
                    |_path_id| -> Option<ExitEndpointLease> {
                        panic!("mismatched native identity must precede endpoint allocation")
                    },
                    |_message| -> Option<[u8; 64]> {
                        panic!("mismatched native identity must precede signing")
                    },
                ),
                Err(ExitError::NativeRouteIdentity(
                    ExitNativeRouteIdentityError::Rejected("native route identity provider scope")
                ))
            ));
        }
        let mut identity_provider = ExactNativeIdentityProvider::default();
        let bundle = service
            .finalize_reservation_with_providers(
                finalize_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                &verifier,
                &mut identity_provider,
                TEST_EXIT_NATIVE_INSTANCE_ID,
                |path_id| exit_endpoint(route_context_id, path_id),
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .unwrap();
        assert_eq!(identity_provider.calls, 1);
        let native_scope = bundle.accepted().native_route_authorization_scope();
        assert_eq!(
            native_scope.request().finalize_id(),
            finalize_request.finalize_id()
        );
        assert_eq!(
            native_scope.request().exit_native_instance_id(),
            &TEST_EXIT_NATIVE_INSTANCE_ID
        );
        assert_eq!(
            bundle
                .accepted()
                .native_route_identity()
                .exit_native_instance_id,
            TEST_EXIT_NATIVE_INSTANCE_ID
        );
        let verified_exit = coordinator
            .verify_finalize_response(
                &intent,
                &verified_hold,
                &finalize_request,
                bundle.signed_exit_reservation().to_vec(),
                bundle.relay_authorizations().to_vec(),
                &exit_peer_id,
                NOW_MS,
            )
            .unwrap();
        let mut retry_identity_provider = PanickingNativeIdentityProvider;
        let finalize_retry = service
            .finalize_reservation_with_providers(
                finalize_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                &verifier,
                &mut retry_identity_provider,
                TEST_EXIT_NATIVE_INSTANCE_ID,
                |_path_id| -> Option<ExitEndpointLease> {
                    panic!("exact finalize retry must not allocate endpoints")
                },
                |_message| -> Option<[u8; 64]> { panic!("exact finalize retry must not sign") },
            )
            .unwrap();
        assert_eq!(
            bundle.signed_exit_reservation(),
            finalize_retry.signed_exit_reservation()
        );
        assert_eq!(
            bundle.relay_authorizations(),
            finalize_retry.relay_authorizations()
        );
        let finalized_state = service.endpoint_states.values().next().unwrap();
        assert_eq!(
            finalized_state.phase,
            super::ExitReservationPhase::Finalized
        );
        assert!(finalized_state.permits.is_empty());
        assert!(service.permit_response_cache.is_empty());
        assert_eq!(service.finalize_response_cache.len(), 1);
        assert_eq!(service.native_route_identity_owners.len(), 1);
        let native_scope = bundle.accepted().native_route_authorization_scope();
        assert!(matches!(
            service.take_native_route_authorization(&native_scope, NOW_MS),
            Err(ExitError::ConfirmationRequired)
        ));
        assert_eq!(service.native_route_identity_owners.len(), 1);

        let final_path_count = selected_path_ids.len();
        let mut signed_relays = Vec::with_capacity(final_path_count);
        let mut verified_relays = Vec::with_capacity(final_path_count);
        for (index, selected_path_id) in selected_path_ids.iter().enumerate() {
            let prospective_index = usize::try_from(selected_path_id - 1).unwrap();
            let path = &relay_paths[prospective_index];
            let relay_key = &relay_keys[prospective_index];
            let signed_relay_request = coordinator
                .sign_relay_request(&verified_exit, index, NOW_MS, hold_expires_at_ms)
                .unwrap();
            let mut relay = RelayService::new(
                RelayServiceConfig::enabled(
                    path.relay_node_id,
                    Bandwidth::new(500, 500).unwrap(),
                    4,
                    900,
                    30,
                    128,
                ),
                None,
            )
            .unwrap();
            let accepted_relay = relay
                .accept_request_with(
                    &signed_relay_request,
                    NOW_MS,
                    relay_key.verifying_key().to_bytes(),
                    |path_id| relay_endpoint(route_context_id, path_id),
                    |message| Some(relay_key.sign(message).to_bytes()),
                )
                .unwrap();
            let signed_relay = accepted_relay.encoded().to_vec();
            let mut fixture_replay = ReplayCache::new(2).unwrap();
            let mut substituted_relay = verify_control_message::<RelayReservation>(
                &signed_relay,
                NOW_MS,
                TimePolicy::default(),
                &mut fixture_replay,
            )
            .unwrap()
            .into_message();
            *substituted_relay.exit_authorization.last_mut().unwrap() ^= 1;
            let substituted_nonce = generate_nonce();
            substituted_relay.nonce = substituted_nonce.to_vec();
            let signed_substitution = sign_control_message(
                &substituted_relay,
                relay_key,
                substituted_relay.created_at_ms,
                substituted_relay.expires_at_ms,
                substituted_nonce,
                TimePolicy::default(),
            )
            .unwrap();
            assert!(matches!(
                coordinator.verify_relay_response(
                    &verified_exit,
                    &signed_substitution,
                    index,
                    path.relay_node_id,
                    &path.relay_peer_id,
                    NOW_MS,
                ),
                Err(CoordinatorError::Protocol(ProtocolError::InvalidSignature))
            ));
            let verified_relay = coordinator
                .verify_relay_response(
                    &verified_exit,
                    &signed_relay,
                    index,
                    path.relay_node_id,
                    &path.relay_peer_id,
                    NOW_MS,
                )
                .unwrap();
            assert_eq!(
                verified_relay.relay_client_endpoint(),
                relay_endpoint(route_context_id, path.path_id)
                    .unwrap()
                    .client_facing_endpoint()
            );
            verified_relays.push(verified_relay);
            signed_relays.push(signed_relay);
        }

        if transports.contains(&Transport::UdpSinglePath) {
            assert!(matches!(
                service.bind_udp_path(bundle.accepted(), &signed_relays[0], NOW_MS),
                Err(ExitError::ConfirmationRequired)
            ));
        } else if transports.contains(&Transport::TcpMptcp) {
            let relay_refs: Vec<&[u8]> = signed_relays.iter().map(Vec::as_slice).collect();
            assert!(matches!(
                service.bind_tcp_route(bundle.accepted(), &relay_refs, NOW_MS),
                Err(ExitError::ConfirmationRequired)
            ));
        }

        for grant in &verified_relays {
            let confirmation = coordinator
                .sign_exit_confirmation(grant, NOW_MS, hold_expires_at_ms)
                .unwrap();
            let mut invalid_signature = confirmation.clone();
            *invalid_signature.last_mut().unwrap() ^= 1;
            assert!(matches!(
                service.confirm_relay_with(
                    &invalid_signature,
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    |message| Some(exit_key.sign(message).to_bytes()),
                ),
                Err(ExitError::Protocol(ProtocolError::InvalidSignature))
            ));
            let receipt = service
                .confirm_relay_with(
                    &confirmation,
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    |message| Some(exit_key.sign(message).to_bytes()),
                )
                .unwrap();
            coordinator
                .verify_confirmation_receipt(grant, &confirmation, receipt.signed_receipt(), NOW_MS)
                .unwrap();
            let retry = service
                .confirm_relay_with(
                    &confirmation,
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    |_message| -> Option<[u8; 64]> {
                        panic!("exact confirmation retry must use cached receipt")
                    },
                )
                .unwrap();
            assert_eq!(receipt.signed_receipt(), retry.signed_receipt());
            let different_confirmation = coordinator
                .sign_exit_confirmation(grant, NOW_MS, hold_expires_at_ms)
                .unwrap();
            assert_ne!(confirmation, different_confirmation);
            assert!(matches!(
                service.confirm_relay_with(
                    &different_confirmation,
                    &control_relay_node_id,
                    &control_relay_peer_id,
                    NOW_MS,
                    exit_key.verifying_key().to_bytes(),
                    |_message| -> Option<[u8; 64]> {
                        panic!("non-identical confirmation must fail before signing")
                    },
                ),
                Err(ExitError::InvalidGrant(
                    "only exact confirmation retry is allowed"
                ))
            ));
        }
        let (accepted, _) = bundle.into_admitted_parts();
        (
            service,
            AdmittedRoute {
                accepted,
                signed_relays,
                coordinator,
                route_context_id,
                expires_at_ms,
            },
        )
    }

    fn node_id(key: &SigningKey) -> [u8; 32] {
        node_id_from_public_key(&key.verifying_key().to_bytes())
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let public_key =
            libp2p_identity::ed25519::PublicKey::try_from_bytes(&key.verifying_key().to_bytes())
                .unwrap();
        libp2p_identity::PublicKey::from(public_key)
            .to_peer_id()
            .to_bytes()
    }

    fn fixture_public_endpoint(
        key_seed: u8,
        address: Ipv4Addr,
        port: u16,
    ) -> Option<PublicWireGuardEndpoint> {
        PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([key_seed; 32]),
            IpAddr::V4(address),
            port,
        )
        .ok()
    }

    fn client_endpoint(route_context_id: [u8; 16], path_id: u32) -> Option<ClientEndpointLease> {
        let port = 30_000_u16.checked_add(u16::try_from(path_id).ok()?)?;
        let path_seed = u8::try_from(path_id).ok()?;
        ClientEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([200; 32]).ok()?,
            HelperLeaseHandle::from_bytes([210_u8.checked_add(path_seed)?; 32]).ok()?,
            path_id,
            EndpointRole::Client,
            fixture_public_endpoint(
                10_u8.checked_add(path_seed)?,
                Ipv4Addr::new(8, 8, 4, 10),
                port,
            )?,
        )
        .ok()
    }

    fn exit_endpoint(route_context_id: [u8; 16], path_id: u32) -> Option<ExitEndpointLease> {
        let port = 31_000_u16.checked_add(u16::try_from(path_id).ok()?)?;
        let path_seed = u8::try_from(path_id).ok()?;
        ExitEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([201; 32]).ok()?,
            HelperLeaseHandle::from_bytes([220_u8.checked_add(path_seed)?; 32]).ok()?,
            path_id,
            EndpointRole::Exit,
            fixture_public_endpoint(
                30_u8.checked_add(path_seed)?,
                Ipv4Addr::new(8, 8, 4, 11),
                port,
            )?,
        )
        .ok()
    }

    fn relay_endpoint(route_context_id: [u8; 16], path_id: u32) -> Option<RelayEndpointLease> {
        let offset = u16::try_from(path_id).ok()?.checked_mul(2)?;
        let path_seed = u8::try_from(path_id).ok()?.checked_mul(2)?;
        RelayEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([202; 32]).ok()?,
            HelperLeaseHandle::from_bytes([230_u8.checked_add(path_seed)?; 32]).ok()?,
            HelperLeaseHandle::from_bytes([231_u8.checked_add(path_seed)?; 32]).ok()?,
            path_id,
            EndpointRole::RelayClient,
            EndpointRole::RelayExit,
            fixture_public_endpoint(
                50_u8.checked_add(path_seed)?,
                Ipv4Addr::new(8, 8, 4, 12),
                32_000_u16.checked_add(offset)?,
            )?,
            fixture_public_endpoint(
                51_u8.checked_add(path_seed)?,
                Ipv4Addr::new(8, 8, 4, 13),
                32_001_u16.checked_add(offset)?,
            )?,
        )
        .ok()
    }

    #[test]
    fn eight_prospective_permits_finalize_noncontiguous_exact_three_without_ledger_delta() {
        let metrics = MetricsRegistry::new();
        let (mut service, route) = admit_route_with_probe_selection(
            8,
            3,
            &[2, 5, 8],
            &[Transport::TcpMptcp],
            Vec::new(),
            metrics,
        );
        assert_eq!(route.accepted.maximum_paths(), 3);
        assert_eq!(route.signed_relays.len(), 3);
        let relays = route
            .signed_relays
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let active = service
            .bind_tcp_route(&route.accepted, &relays, NOW_MS)
            .unwrap();
        assert_eq!(active.path_count(), 3);
        let available = service.available(NOW_MS).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(400, 400).unwrap());
        assert_eq!(available.free_slots, 3);
    }

    fn udp_443_case(metrics: MetricsRegistry) -> (ExitService, PendingQuicUdpFlow) {
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [ProtocolPort::new(TransportProtocol::Udp, 443).unwrap()],
        )
        .unwrap();
        let (mut service, route) = admit_route(1, &[Transport::UdpSinglePath], vec![rule], metrics);
        let path = service
            .bind_udp_path(&route.accepted, &route.signed_relays[0], NOW_MS)
            .unwrap();
        let authorization = route.sign_udp_hostname(service.policy_hash(), "allowed.example", 443);
        let pending = service
            .begin_udp_443_inspection(path, &authorization, &TEST_DCID, NOW_MS)
            .unwrap();
        (service, pending)
    }

    #[test]
    fn release_and_expiry_drop_exit_helper_leases_and_restore_capacity() {
        let (mut released, route) = admit_route(
            1,
            &[Transport::UdpSinglePath],
            Vec::new(),
            MetricsRegistry::new(),
        );
        assert!(
            released
                .endpoint_lease(&route.accepted.reservation_id, 1)
                .is_some()
        );
        let available = released.available(NOW_MS).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(400, 400).unwrap());
        assert_eq!(available.free_slots, 3);
        assert_eq!(released.native_route_identity_owners.len(), 1);
        released.release(&route.accepted.reservation_id).unwrap();
        assert!(
            released
                .endpoint_lease(&route.accepted.reservation_id, 1)
                .is_none()
        );
        let available = released.available(NOW_MS).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(500, 500).unwrap());
        assert_eq!(available.free_slots, 4);
        assert!(released.native_route_identity_owners.is_empty());

        let (mut expired, route) = admit_route(
            1,
            &[Transport::UdpSinglePath],
            Vec::new(),
            MetricsRegistry::new(),
        );
        assert!(
            expired
                .endpoint_lease(&route.accepted.reservation_id, 1)
                .is_some()
        );
        assert_eq!(expired.purge_expired(NOW_MS + 11_000), 1);
        assert!(
            expired
                .endpoint_lease(&route.accepted.reservation_id, 1)
                .is_none()
        );
        let available = expired.available(NOW_MS + 11_000).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(500, 500).unwrap());
        assert_eq!(available.free_slots, 4);
        assert!(expired.hold_response_cache.is_empty());
        assert!(expired.permit_response_cache.is_empty());
        assert!(expired.finalize_response_cache.is_empty());
        assert!(expired.confirmation_response_cache.is_empty());
        assert!(expired.native_route_identity_owners.is_empty());
    }

    #[test]
    fn native_route_bearer_is_hpke_delivered_client_to_exit_once() {
        let (mut service, mut route) = admit_route(
            2,
            &[Transport::MultipathQuic],
            Vec::new(),
            MetricsRegistry::new(),
        );
        let scope = route.accepted.native_route_authorization_scope();
        let client_authorization = route
            .coordinator
            .take_native_route_authorization(*scope.request().finalize_id(), NOW_MS)
            .expect("fully confirmed client native authorization");
        let expected_bearer = *client_authorization.auth_bearer();
        let signed_delivery = route
            .coordinator
            .sign_native_route_credential_delivery(&client_authorization, NOW_MS)
            .expect("HPKE-sealed Client credential delivery");

        let envelope =
            decode_canonical::<SignedEnvelope>(&signed_delivery, MAX_CONTROL_MESSAGE_SIZE)
                .expect("signed delivery envelope");
        let opaque = decode_canonical::<NativeRouteCredentialDelivery>(
            &envelope.payload,
            MAX_CONTROL_PAYLOAD_SIZE,
        )
        .expect("credential payload");
        assert!(
            !opaque
                .ciphertext
                .windows(expected_bearer.len())
                .any(|window| window == expected_bearer),
            "the Relay-visible ciphertext must not contain the bearer in plaintext"
        );

        let exit_authorization = service
            .take_native_route_authorization_with_credential(&scope, &signed_delivery, NOW_MS)
            .expect("authenticated Exit credential admission");
        assert_eq!(exit_authorization.auth_bearer(), &expected_bearer);
        assert_eq!(
            exit_authorization.authorization().scope(),
            scope,
            "the decrypted bearer must retain the exact native owner"
        );
        assert!(format!("{exit_authorization:?}").contains("<redacted>"));

        assert!(matches!(
            service.take_native_route_authorization_with_credential(
                &scope,
                &signed_delivery,
                NOW_MS
            ),
            Err(ExitError::Protocol(ProtocolError::Replay))
        ));
    }

    #[test]
    fn native_route_owner_rejects_mismatched_public_scope_and_malformed_pem() {
        let request = ExitNativeRouteIdentityRequest::new(
            [1; 16], [2; 16], [3; 16], [4; 32], 5, [6; 32], [8; 32],
        )
        .unwrap();
        let identity = NativeRouteIdentity {
            auth_commitment: request.auth_commitment().to_vec(),
            certificate_sha256: vec![6; 32],
            spki_sha256: vec![7; 32],
            tls_server_name: "route.exit.example".to_owned(),
            masque_context_id: request.masque_context_id(),
            client_native_instance_id: request.client_native_instance_id().to_vec(),
            exit_native_instance_id: request.exit_native_instance_id().to_vec(),
            credential_hpke_public_key: Vec::new(),
        };
        let owner = ExitNativeRouteIdentityOwner::new(
            request,
            identity.clone(),
            TEST_TLS_CERTIFICATE_PEM.to_vec(),
            TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
        )
        .unwrap();
        let debug = format!("{owner:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("BAUG"));

        let mut mismatched = identity.clone();
        mismatched.auth_commitment = vec![9; 32];
        assert!(matches!(
            ExitNativeRouteIdentityOwner::new(
                request,
                mismatched,
                TEST_TLS_CERTIFICATE_PEM.to_vec(),
                TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
            ),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));

        let mut mismatched_client = identity.clone();
        mismatched_client.client_native_instance_id = vec![10; 32];
        assert!(matches!(
            ExitNativeRouteIdentityOwner::new(
                request,
                mismatched_client,
                TEST_TLS_CERTIFICATE_PEM.to_vec(),
                TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
            ),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));

        let mut mismatched_exit = identity.clone();
        mismatched_exit.exit_native_instance_id = vec![11; 32];
        assert!(matches!(
            ExitNativeRouteIdentityOwner::new(
                request,
                mismatched_exit,
                TEST_TLS_CERTIFICATE_PEM.to_vec(),
                TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
            ),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));

        let mut invalid_name = identity.clone();
        invalid_name.tls_server_name = "Route.Exit.Example".to_owned();
        assert!(matches!(
            ExitNativeRouteIdentityOwner::new(
                request,
                invalid_name,
                TEST_TLS_CERTIFICATE_PEM.to_vec(),
                TEST_TLS_PRIVATE_KEY_PEM.to_vec(),
            ),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));
        assert!(matches!(
            ExitNativeRouteIdentityOwner::new(
                request,
                identity,
                TEST_TLS_CERTIFICATE_PEM.to_vec(),
                b"-----BEGIN PRIVATE KEY-----\nBAD\0KEY\n-----END PRIVATE KEY-----\n".to_vec(),
            ),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the affine owner test exhaustively substitutes every exact authorization field"
    )]
    fn native_route_authorization_mismatches_do_not_consume_and_exact_scope_is_one_shot() {
        let (mut service, route) = admit_route(
            1,
            &[Transport::UdpSinglePath],
            Vec::new(),
            MetricsRegistry::new(),
        );
        let exact = route.accepted.native_route_authorization_scope();
        let request = *exact.request();
        let unknown_reservation_request = ExitNativeRouteIdentityRequest::new(
            [70; 16],
            *request.route_context_id(),
            *request.finalize_id(),
            *request.auth_commitment(),
            request.masque_context_id(),
            *request.client_native_instance_id(),
            *request.exit_native_instance_id(),
        )
        .unwrap();
        let unknown_reservation = ExitNativeRouteAuthorizationScope::new(
            unknown_reservation_request,
            *unknown_reservation_request.exit_native_instance_id(),
        )
        .unwrap();
        assert!(matches!(
            service.take_native_route_authorization(&unknown_reservation, NOW_MS),
            Err(ExitError::NativeRouteAuthorizationUnavailable)
        ));
        assert_eq!(service.native_route_identity_owners.len(), 1);

        let mismatched_requests = [
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                [71; 16],
                *request.finalize_id(),
                *request.auth_commitment(),
                request.masque_context_id(),
                *request.client_native_instance_id(),
                *request.exit_native_instance_id(),
            )
            .unwrap(),
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                *request.route_context_id(),
                [72; 16],
                *request.auth_commitment(),
                request.masque_context_id(),
                *request.client_native_instance_id(),
                *request.exit_native_instance_id(),
            )
            .unwrap(),
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                *request.route_context_id(),
                *request.finalize_id(),
                [72; 32],
                request.masque_context_id(),
                *request.client_native_instance_id(),
                *request.exit_native_instance_id(),
            )
            .unwrap(),
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                *request.route_context_id(),
                *request.finalize_id(),
                *request.auth_commitment(),
                request.masque_context_id() + 1,
                *request.client_native_instance_id(),
                *request.exit_native_instance_id(),
            )
            .unwrap(),
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                *request.route_context_id(),
                *request.finalize_id(),
                *request.auth_commitment(),
                request.masque_context_id(),
                [73; 32],
                *request.exit_native_instance_id(),
            )
            .unwrap(),
            ExitNativeRouteIdentityRequest::new(
                *request.reservation_id(),
                *request.route_context_id(),
                *request.finalize_id(),
                *request.auth_commitment(),
                request.masque_context_id(),
                *request.client_native_instance_id(),
                [74; 32],
            )
            .unwrap(),
        ];
        for mismatched_request in mismatched_requests {
            let mismatched = ExitNativeRouteAuthorizationScope::new(
                mismatched_request,
                *mismatched_request.exit_native_instance_id(),
            )
            .unwrap();
            assert!(matches!(
                service.take_native_route_authorization(&mismatched, NOW_MS),
                Err(ExitError::NativeRouteAuthorizationMismatch)
            ));
            assert_eq!(service.native_route_identity_owners.len(), 1);
        }
        assert!(matches!(
            ExitNativeRouteAuthorizationScope::new(request, [75; 32]),
            Err(ExitNativeRouteIdentityError::Rejected(_))
        ));
        assert_eq!(service.native_route_identity_owners.len(), 1);

        assert!(std::mem::needs_drop::<super::ExitNativeRouteAuthorization>());
        let authorization = service
            .take_native_route_authorization(&exact, NOW_MS)
            .unwrap();
        assert_eq!(authorization.scope(), exact);
        assert_eq!(
            authorization.public_identity(),
            route.accepted.native_route_identity()
        );
        assert_eq!(
            authorization.tls_certificate_pem(),
            TEST_TLS_CERTIFICATE_PEM
        );
        assert_eq!(
            authorization.tls_private_key_pem(),
            TEST_TLS_PRIVATE_KEY_PEM
        );
        assert_eq!(authorization.expires_at_ms(), route.expires_at_ms);
        let debug = format!("{authorization:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("BAUG"));
        drop(authorization);
        assert!(service.native_route_identity_owners.is_empty());
        assert!(matches!(
            service.take_native_route_authorization(&exact, NOW_MS),
            Err(ExitError::NativeRouteAuthorizationUnavailable)
        ));
    }

    #[test]
    fn binding_other_valid_grant_leaves_exact_confirmed_grant_usable() {
        let (mut service, route) = admit_route(
            1,
            &[Transport::UdpSinglePath],
            Vec::new(),
            MetricsRegistry::new(),
        );
        let (_other_service, other_route) = admit_route(
            1,
            &[Transport::UdpSinglePath],
            Vec::new(),
            MetricsRegistry::new(),
        );
        assert!(matches!(
            service.bind_udp_path(&route.accepted, &other_route.signed_relays[0], NOW_MS),
            Err(ExitError::InvalidGrant(
                "UDP relay grant differs from confirmation"
            ))
        ));
        service
            .bind_udp_path(&route.accepted, &route.signed_relays[0], NOW_MS)
            .expect("wrong valid grant did not consume confirmed state or route replay");
    }

    #[test]
    fn signed_reservation_route_and_open_tcp_are_bound_to_policy() {
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
        )
        .unwrap();
        let metrics = MetricsRegistry::new();
        let (mut service, admitted) =
            admit_route(2, &[Transport::TcpMptcp], vec![rule], metrics.clone());
        let relays: Vec<&[u8]> = admitted.signed_relays.iter().map(Vec::as_slice).collect();
        let route = service
            .bind_tcp_route(&admitted.accepted, &relays, NOW_MS)
            .unwrap();
        assert_eq!(route.path_count(), 2);
        let open = admitted.sign_open_tcp(service.policy_hash(), "allowed.example", 443);
        let flow = service.authorize_tcp_open(&route, &open, NOW_MS).unwrap();
        assert_eq!(flow.port(), 443);
        assert_eq!(metrics.snapshot().active_reservations, 1);

        let replay = service.authorize_tcp_open(&route, &open, NOW_MS);
        assert!(matches!(
            replay,
            Err(ExitError::Tcp(
                volparossa_tcp_proxy::TcpProxyError::Protocol(ProtocolError::Replay)
            ))
        ));
    }

    #[tokio::test]
    async fn detached_tcp_egress_owner_reads_one_bounded_signed_open() {
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [ProtocolPort::new(TransportProtocol::Tcp, 80).unwrap()],
        )
        .unwrap();
        let (mut service, admitted) = admit_route(
            2,
            &[Transport::TcpMptcp],
            vec![rule],
            MetricsRegistry::new(),
        );
        let relays = admitted
            .signed_relays
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let active = service
            .bind_tcp_route(&admitted.accepted, &relays, NOW_MS)
            .unwrap();
        let reservation_id = *active.reservation_id();
        let signed_open = admitted.sign_open_tcp(service.policy_hash(), "allowed.example", 80);
        let detached = service
            .detach_tcp_egress_route(active, NOW_MS)
            .expect("detached route");
        assert_eq!(detached.reservation_id(), &reservation_id);

        let (mut client, mut exit) = tokio::io::duplex(MAX_CONTROL_MESSAGE_SIZE * 2);
        let writer = tokio::spawn(async move {
            volparossa_tcp_proxy::write_open_tcp(&mut client, &signed_open, Duration::from_secs(1))
                .await
        });
        let flow = detached
            .read_authorized_open_tcp(&mut exit, NOW_MS, Duration::from_secs(1))
            .await
            .expect("authorized flow");
        writer.await.unwrap().unwrap();
        assert_eq!(flow.hostname(), Some("allowed.example"));
        assert_eq!(flow.port(), 80);
        service.release(&reservation_id).unwrap();
    }

    #[tokio::test]
    async fn detached_tcp_egress_owner_authorizes_independent_concurrent_flows() {
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [80_u16, 81].map(|port| ProtocolPort::new(TransportProtocol::Tcp, port).unwrap()),
        )
        .unwrap();
        let (mut service, admitted) = admit_route(
            2,
            &[Transport::TcpMptcp],
            vec![rule],
            MetricsRegistry::new(),
        );
        let relays = admitted
            .signed_relays
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let route = service
            .bind_tcp_route(&admitted.accepted, &relays, NOW_MS)
            .unwrap();
        let detached = Arc::new(
            service
                .detach_tcp_egress_route(route, NOW_MS)
                .expect("detached route"),
        );
        let mut readers = Vec::new();
        for port in [80_u16, 81] {
            let signed = admitted.sign_open_tcp(service.policy_hash(), "allowed.example", port);
            let (mut writer, mut reader) = tokio::io::duplex(MAX_CONTROL_MESSAGE_SIZE * 2);
            let route = Arc::clone(&detached);
            readers.push(tokio::spawn(async move {
                let send = tokio::spawn(async move {
                    volparossa_tcp_proxy::write_open_tcp(
                        &mut writer,
                        &signed,
                        Duration::from_secs(1),
                    )
                    .await
                });
                let flow = route
                    .read_authorized_open_tcp(&mut reader, NOW_MS, Duration::from_secs(1))
                    .await
                    .expect("authorized concurrent flow");
                send.await.unwrap().unwrap();
                flow.port()
            }));
        }
        let mut ports = Vec::new();
        for reader in readers {
            ports.push(reader.await.unwrap());
        }
        ports.sort_unstable();
        assert_eq!(ports, [80, 81]);
    }

    #[test]
    fn udp_443_fails_closed_without_quic_client_hello_evidence() {
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [ProtocolPort::new(TransportProtocol::Udp, 443).unwrap()],
        )
        .unwrap();
        let metrics = MetricsRegistry::new();
        let (mut service, route) =
            admit_route(1, &[Transport::UdpSinglePath], vec![rule], metrics.clone());
        let path = service
            .bind_udp_path(&route.accepted, &route.signed_relays[0], NOW_MS)
            .unwrap();
        let authorization = route.sign_udp_hostname(service.policy_hash(), "allowed.example", 443);
        assert!(matches!(
            service.prepare_udp_flow(path, &authorization, NOW_MS),
            Err(ExitError::QuicInspectionUnavailable)
        ));
        assert_eq!(metrics.snapshot().policy_denials, 1);
    }

    #[test]
    fn udp_443_releases_prepared_flow_only_after_exact_authenticated_sni() {
        let metrics = MetricsRegistry::new();
        let (_service, pending) = udp_443_case(metrics.clone());
        let hello = unframed_client_hello(Some("ALLOWED.EXAMPLE"), false);
        let split = 20;
        let first = protected_initial(0, &crypto_frame(0, &hello[..split]));
        let continued = match pending.inspect_initial_datagram(&first, NOW_MS).unwrap() {
            Udp443InspectionProgress::NeedMore(next) => next,
            Udp443InspectionProgress::Complete(_) => {
                panic!("partial CRYPTO unexpectedly authorized egress")
            }
        };
        let debug = format!("{continued:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("allowed.example"));

        let second = protected_initial(1, &crypto_frame(split, &hello[split..]));
        let prepared = match continued.inspect_initial_datagram(&second, NOW_MS).unwrap() {
            Udp443InspectionProgress::NeedMore(_) => panic!("complete CRYPTO stayed pending"),
            Udp443InspectionProgress::Complete(flow) => flow,
        };
        let debug = format!("{prepared:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("allowed.example"));
        assert_eq!(metrics.snapshot().policy_denials, 0);
    }

    #[test]
    fn udp_443_rejects_authenticated_mismatched_sni() {
        let metrics = MetricsRegistry::new();
        let (_service, pending) = udp_443_case(metrics.clone());
        let hello = unframed_client_hello(Some("different.example"), false);
        let initial = protected_initial(0, &crypto_frame(0, &hello));
        assert!(matches!(
            pending.inspect_initial_datagram(&initial, NOW_MS),
            Err(ExitError::SniMismatch)
        ));
        assert_eq!(metrics.snapshot().policy_denials, 1);
    }

    #[test]
    fn udp_443_rejects_authenticated_ech() {
        let metrics = MetricsRegistry::new();
        let (_service, pending) = udp_443_case(metrics.clone());
        let hello = unframed_client_hello(Some("allowed.example"), true);
        let initial = protected_initial(0, &crypto_frame(0, &hello));
        assert!(matches!(
            pending.inspect_initial_datagram(&initial, NOW_MS),
            Err(ExitError::EncryptedClientHello)
        ));
        assert_eq!(metrics.snapshot().policy_denials, 1);
    }

    #[test]
    fn udp_443_rejects_authenticated_client_hello_without_sni() {
        let metrics = MetricsRegistry::new();
        let (_service, pending) = udp_443_case(metrics.clone());
        let hello = unframed_client_hello(None, false);
        let initial = protected_initial(0, &crypto_frame(0, &hello));
        assert!(matches!(
            pending.inspect_initial_datagram(&initial, NOW_MS),
            Err(ExitError::MissingServerName)
        ));
        assert_eq!(metrics.snapshot().policy_denials, 1);
    }

    #[test]
    fn visible_sni_matches_and_ech_or_mismatch_are_denied() {
        let matching = client_hello("allowed.example", false);
        inspect_tls_client_hello(&matching, "allowed.example").unwrap();
        assert!(matches!(
            inspect_tls_client_hello(&matching, "different.example"),
            Err(ExitError::SniMismatch)
        ));
        let ech = client_hello("allowed.example", true);
        assert!(matches!(
            inspect_tls_client_hello(&ech, "allowed.example"),
            Err(ExitError::EncryptedClientHello)
        ));
    }

    #[tokio::test]
    async fn hostname_egress_on_nonstandard_port_requires_visible_sni_before_dns() {
        let rule = DestinationRule::exact_domain(
            "allowed.invalid",
            [ProtocolPort::new(TransportProtocol::Tcp, 18_443).unwrap()],
        )
        .unwrap();
        let metrics = MetricsRegistry::new();
        let (mut service, admitted) =
            admit_route(2, &[Transport::TcpMptcp], vec![rule], metrics.clone());
        let relays = admitted
            .signed_relays
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let route = service
            .bind_tcp_route(&admitted.accepted, &relays, NOW_MS)
            .unwrap();
        let open = admitted.sign_open_tcp(service.policy_hash(), "allowed.invalid", 18_443);
        let flow = service.authorize_tcp_open(&route, &open, NOW_MS).unwrap();
        let (mut application, protected) = tokio::io::duplex(64);
        application.write_all(&[23, 3, 3, 0, 1, 0]).await.unwrap();
        let transfer =
            StreamTransferLimits::new(1_024, 4_096, 4_096, Duration::from_secs(1)).unwrap();
        let limits = TcpEgressLimits::new(
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
            transfer,
        )
        .unwrap();

        assert!(matches!(
            service
                .run_tcp_egress(&flow, protected, NOW_MS, limits)
                .await,
            Err(ExitError::Inspection(InspectionError::InvalidTlsRecord(_)))
        ));
        assert_eq!(metrics.snapshot().policy_denials, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test covers exact retry, restart invalidation and expiry rollback in one hold transaction"
    )]
    fn restart_invalidates_old_hold_and_expiry_leaves_no_ghost_capacity() {
        let policy = verified_development_manifest(NOW_MS, Vec::new()).unwrap();
        let policy_hash = *policy.policy_hash();
        let exit_key = ephemeral_signing_key();
        let control_relay_key = ephemeral_signing_key();
        let relay_key = ephemeral_signing_key();
        let exit_node_id = node_id(&exit_key);
        let exit_peer_id = peer_id(&exit_key);
        let control_relay_node_id = node_id(&control_relay_key);
        let control_relay_peer_id = peer_id(&control_relay_key);
        let hold_expires_at_ms = NOW_MS + 20_000;
        let intent = ExitReservationIntent {
            reservation_id: [93; 16],
            route_context_id: [94; 16],
            exit_node_id,
            exit_peer_id: exit_peer_id.clone(),
            control_relay_node_id,
            control_relay_peer_id: control_relay_peer_id.clone(),
            allowed_transports: vec![Transport::UdpSinglePath],
            reserved_up_mbps: 100,
            reserved_down_mbps: 100,
            maximum_paths: 1,
            probe_permit_limit: 1,
            policy_hash,
            created_at_ms: NOW_MS - 1,
            hold_expires_at_ms,
            reservation_expires_at_ms: NOW_MS + 60_000,
            masque_context_id: 8,
            client_native_instance_id: [95; 32],
        };
        let config = ExitServiceConfig::enabled(
            exit_node_id,
            Bandwidth::new(500, 500).unwrap(),
            4,
            900,
            10,
            64,
        );
        let mut coordinator = ReservationCoordinator::new(16).unwrap();
        let signed_request = coordinator.sign_hold_request(&intent).unwrap();
        let mut service =
            ExitService::new_with_boot_id(config.clone(), policy, None, [41; 16]).unwrap();
        let accepted = service
            .hold_capacity_with(
                &signed_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .unwrap();
        let exact_retry = service
            .hold_capacity_with(
                &signed_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |_message| -> Option<[u8; 64]> {
                    panic!("exact hold retry must return cached signed bytes")
                },
            )
            .unwrap();
        assert_eq!(
            accepted.signed_capability(),
            exact_retry.signed_capability()
        );
        assert_eq!(accepted.signed_hold(), exact_retry.signed_hold());

        let verified_hold = coordinator
            .verify_hold_response(
                &intent,
                accepted.signed_capability().to_vec(),
                accepted.signed_hold().to_vec(),
                &exit_peer_id,
                NOW_MS,
            )
            .unwrap();
        let relay_path = RelayPathIntent {
            path_id: 1,
            relay_node_id: node_id(&relay_key),
            relay_peer_id: peer_id(&relay_key),
        };
        let permit_request = coordinator
            .sign_probe_permit_request(
                &verified_hold,
                &relay_path,
                Transport::UdpSinglePath,
                ProbeAddressFamily::Ipv4,
                NOW_MS,
                NOW_MS + 15_000,
            )
            .unwrap();
        let restarted_policy = verified_development_manifest(NOW_MS, Vec::new()).unwrap();
        let mut restarted =
            ExitService::new_with_boot_id(config, restarted_policy, None, [42; 16]).unwrap();
        assert!(matches!(
            restarted.issue_probe_permit_with(
                permit_request.encoded(),
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |_message| -> Option<[u8; 64]> { panic!("boot mismatch must fail before signing") },
            ),
            Err(ExitError::ExitBootMismatch)
        ));

        let held_capacity = service.available(NOW_MS).unwrap();
        assert_eq!(held_capacity.bandwidth, Bandwidth::new(400, 400).unwrap());
        assert_eq!(held_capacity.free_slots, 3);
        assert_eq!(service.purge_expired(hold_expires_at_ms), 1);
        assert!(service.endpoint_states.is_empty());
        assert!(service.hold_response_cache.is_empty());
        assert!(service.permit_response_cache.is_empty());
        assert!(service.finalize_response_cache.is_empty());
        assert!(service.confirmation_response_cache.is_empty());
        let restored = service.available(hold_expires_at_ms).unwrap();
        assert_eq!(restored.bandwidth, Bandwidth::new(500, 500).unwrap());
        assert_eq!(restored.free_slots, 4);
        assert!(matches!(
            service.hold_capacity_with(
                &signed_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                hold_expires_at_ms,
                exit_key.verifying_key().to_bytes(),
                |_message| -> Option<[u8; 64]> { panic!("expired retry must fail before signing") },
            ),
            Err(ExitError::Protocol(ProtocolError::Expired))
        ));
    }

    #[test]
    fn disabled_exit_rejects_signed_v4_capacity_hold() {
        let policy = verified_development_manifest(NOW_MS, Vec::new()).unwrap();
        let policy_hash = *policy.policy_hash();
        let exit_key = ephemeral_signing_key();
        let control_relay_key = ephemeral_signing_key();
        let exit_node_id = node_id(&exit_key);
        let control_relay_node_id = node_id(&control_relay_key);
        let control_relay_peer_id = peer_id(&control_relay_key);
        let coordinator = ReservationCoordinator::new(8).unwrap();
        let intent = ExitReservationIntent {
            reservation_id: [91; 16],
            route_context_id: [92; 16],
            exit_node_id,
            exit_peer_id: peer_id(&exit_key),
            control_relay_node_id,
            control_relay_peer_id: control_relay_peer_id.clone(),
            allowed_transports: vec![Transport::UdpSinglePath],
            reserved_up_mbps: 1,
            reserved_down_mbps: 1,
            maximum_paths: 1,
            probe_permit_limit: 1,
            policy_hash,
            created_at_ms: NOW_MS - 1,
            hold_expires_at_ms: NOW_MS + 20_000,
            reservation_expires_at_ms: NOW_MS + 60_000,
            masque_context_id: 9,
            client_native_instance_id: [96; 32],
        };
        let signed_request = coordinator.sign_hold_request(&intent).unwrap();
        let mut service =
            ExitService::new(ExitServiceConfig::disabled(exit_node_id), policy, None).unwrap();
        assert!(matches!(
            service.hold_capacity_with(
                &signed_request,
                &control_relay_node_id,
                &control_relay_peer_id,
                NOW_MS,
                exit_key.verifying_key().to_bytes(),
                |_message| -> Option<[u8; 64]> {
                    panic!("disabled service must reject before signing")
                },
            ),
            Err(ExitError::Disabled)
        ));
    }

    fn client_hello(hostname: &str, ech: bool) -> Vec<u8> {
        let handshake = unframed_client_hello(Some(hostname), ech);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn unframed_client_hello(hostname: Option<&str>, ech: bool) -> Vec<u8> {
        let mut encoded_extensions = Vec::new();
        if let Some(hostname) = hostname {
            let hostname_bytes = hostname.as_bytes();
            let mut name_list = vec![0];
            name_list
                .extend_from_slice(&u16::try_from(hostname_bytes.len()).unwrap().to_be_bytes());
            name_list.extend_from_slice(hostname_bytes);
            let mut server_name = Vec::new();
            server_name.extend_from_slice(&u16::try_from(name_list.len()).unwrap().to_be_bytes());
            server_name.extend_from_slice(&name_list);
            encoded_extensions.extend_from_slice(&encode_tls_extension(0, &server_name));
        }
        if ech {
            encoded_extensions.extend_from_slice(&encode_tls_extension(0xfe0d, &[1]));
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[7_u8; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(encoded_extensions.len())
                .unwrap()
                .to_be_bytes(),
        );
        body.extend_from_slice(&encoded_extensions);

        let mut handshake = vec![1];
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        handshake.extend_from_slice(&length[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn encode_tls_extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&extension_type.to_be_bytes());
        encoded.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(data);
        encoded
    }

    fn encode_quic_varint(value: u64) -> Vec<u8> {
        match value {
            0..=0x3f => vec![u8::try_from(value).unwrap()],
            0x40..=0x3fff => (u16::try_from(value).unwrap() | 0x4000)
                .to_be_bytes()
                .to_vec(),
            0x4000..=0x3fff_ffff => (u32::try_from(value).unwrap() | 0x8000_0000)
                .to_be_bytes()
                .to_vec(),
            _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
        }
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = encode_quic_varint(0x06);
        frame.extend_from_slice(&encode_quic_varint(u64::try_from(offset).unwrap()));
        frame.extend_from_slice(&encode_quic_varint(u64::try_from(data.len()).unwrap()));
        frame.extend_from_slice(data);
        frame
    }

    fn initial_nonce(packet_number: u64) -> [u8; 12] {
        let mut nonce = TEST_INITIAL_IV;
        for (target, byte) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
            *target ^= byte;
        }
        nonce
    }

    fn protected_initial(packet_number: u32, frames: &[u8]) -> Vec<u8> {
        const DATAGRAM_BYTES: usize = 1_200;
        const PACKET_NUMBER_OFFSET: usize = 18;
        const PACKET_NUMBER_BYTES: usize = 4;

        let protected_bytes = DATAGRAM_BYTES - PACKET_NUMBER_OFFSET;
        let plaintext_bytes = protected_bytes - PACKET_NUMBER_BYTES - aead::MAX_TAG_LEN;
        assert!(frames.len() <= plaintext_bytes);

        let mut header = vec![0xc3];
        header.extend_from_slice(&1_u32.to_be_bytes());
        header.push(u8::try_from(TEST_DCID.len()).unwrap());
        header.extend_from_slice(&TEST_DCID);
        header.push(0);
        header.push(0);
        header.extend_from_slice(&encode_quic_varint(u64::try_from(protected_bytes).unwrap()));
        assert_eq!(header.len(), PACKET_NUMBER_OFFSET);
        header.extend_from_slice(&packet_number.to_be_bytes());

        let mut payload = frames.to_vec();
        payload.resize(plaintext_bytes, 0);
        let packet_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &TEST_INITIAL_KEY).unwrap(),
        );
        packet_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(initial_nonce(u64::from(packet_number))),
                aead::Aad::from(header.as_slice()),
                &mut payload,
            )
            .unwrap();

        let mut packet = header;
        packet.extend_from_slice(&payload);
        let mask_key =
            aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &TEST_INITIAL_HP).unwrap();
        let sample_start = PACKET_NUMBER_OFFSET + 4;
        let mask = mask_key
            .new_mask(&packet[sample_start..sample_start + 16])
            .unwrap();
        packet[0] ^= mask[0] & 0x0f;
        for index in 0..PACKET_NUMBER_BYTES {
            packet[PACKET_NUMBER_OFFSET + index] ^= mask[index + 1];
        }
        assert_eq!(packet.len(), DATAGRAM_BYTES);
        packet
    }
}
