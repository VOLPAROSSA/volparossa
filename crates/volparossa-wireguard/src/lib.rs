//! Public helper-prepared leases and privacy-preserving two-link `WireGuard` path plans.
//! This API represents no private key material; helper-v3 generates and retains its endpoint
//! private keys inside the privileged worker.

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use volparossa_core::{is_local_lan_ip, is_public_routable_ip};

/// Maximum relay paths in one v1 route context.
pub const MAX_PATHS: u8 = 8;
/// Overlay prefix length assigned to one relay path.
pub const OVERLAY_PREFIX_LENGTH: u8 = 112;
/// Exact byte width of an opaque helper-issued context or lease handle.
pub const HELPER_HANDLE_BYTES: usize = 32;

/// `WireGuard` path-plan validation errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WireGuardError {
    /// Route context IDs are non-zero, fixed-width random values.
    #[error("route context ID must be a non-zero 16-byte value")]
    InvalidRouteContext,
    /// Path IDs are restricted to the configured v1 range.
    #[error("path ID must be between 1 and {MAX_PATHS}")]
    InvalidPathId,
    /// Interface role does not match the two-link privacy topology.
    #[error("invalid WireGuard two-link topology")]
    InvalidTopology,
    /// An advertised route endpoint is not an ordinary publicly routable IP address.
    #[error("WireGuard route endpoint must use an ordinary publicly routable IP address")]
    InvalidUnderlayAddress,
    /// Kernel-selected port zero is forbidden for signed route endpoints.
    #[error("WireGuard route endpoint must use a non-zero UDP listen port")]
    InvalidListenPort,
    /// Two endpoints born in the same namespace cannot share a route lease port.
    #[error("WireGuard route endpoint listen ports must be unique")]
    DuplicateListenPort,
    /// Opaque helper handles are fixed-width and non-zero.
    #[error("invalid opaque helper handle")]
    InvalidHelperHandle,
    /// A prepared lease is not bound to the expected route, path or endpoint role.
    #[error("invalid helper lease binding")]
    InvalidHelperBinding,
    /// A context or lease handle was reused where a unique helper capability is required.
    #[error("helper lease handles must be unique")]
    DuplicateHelperHandle,
}

/// Public `WireGuard` key safe for route-specific reservations.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireGuardPublicKey([u8; 32]);

impl WireGuardPublicKey {
    /// Builds a validated fixed-width public key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WireGuardPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireGuardPublicKey(")?;
        for byte in &self.0[..6] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Route-specific UDP endpoint safe for an explicitly scoped signed control message.
///
/// This is an underlay address used by the remote `WireGuard` peer, not one of
/// the deterministic private overlay addresses carried inside the tunnel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicWireGuardEndpoint {
    public_key: WireGuardPublicKey,
    underlay_ip: IpAddr,
    listen_port: u16,
}

impl PublicWireGuardEndpoint {
    /// Bind an endpoint public key to one truthful, publicly routable UDP socket tuple.
    ///
    /// # Errors
    ///
    /// Rejects zero public keys, special-purpose or non-public addresses and port
    /// zero. Port zero would ask the kernel to choose an unknown port and therefore
    /// cannot be committed by a signed reservation.
    pub fn new(
        public_key: WireGuardPublicKey,
        underlay_ip: IpAddr,
        listen_port: u16,
    ) -> Result<Self, WireGuardError> {
        if public_key.as_bytes() == &[0; 32] {
            return Err(WireGuardError::InvalidTopology);
        }
        if !is_public_routable_ip(underlay_ip) {
            return Err(WireGuardError::InvalidUnderlayAddress);
        }
        if listen_port == 0 {
            return Err(WireGuardError::InvalidListenPort);
        }
        Ok(Self {
            public_key,
            underlay_ip,
            listen_port,
        })
    }

    /// Construct an explicitly local endpoint after its on-link binding has been verified.
    ///
    /// This validates address shape only; the privileged helper separately proves the local
    /// interface, assigned source and exact peer route. It does not create public reachability.
    ///
    /// # Errors
    ///
    /// Rejects zero keys/ports and addresses outside RFC1918 IPv4 or IPv6 ULA.
    pub fn new_direct_local_lan(
        public_key: WireGuardPublicKey,
        underlay_ip: IpAddr,
        listen_port: u16,
    ) -> Result<Self, WireGuardError> {
        if public_key.as_bytes() == &[0; 32] {
            return Err(WireGuardError::InvalidTopology);
        }
        if !is_local_lan_ip(underlay_ip) {
            return Err(WireGuardError::InvalidUnderlayAddress);
        }
        if listen_port == 0 {
            return Err(WireGuardError::InvalidListenPort);
        }
        Ok(Self {
            public_key,
            underlay_ip,
            listen_port,
        })
    }

    /// Whether the endpoint requires explicit local-LAN scope and on-link route proof.
    #[must_use]
    pub fn is_local_lan(self) -> bool {
        is_local_lan_ip(self.underlay_ip)
    }

    /// Public key configured on the route-specific interface.
    #[must_use]
    pub const fn public_key(self) -> WireGuardPublicKey {
        self.public_key
    }

    /// Unicast underlay address reachable by the remote peer.
    #[must_use]
    pub const fn underlay_ip(self) -> IpAddr {
        self.underlay_ip
    }

    /// Explicit, non-zero UDP listen port leased before helper configuration.
    #[must_use]
    pub const fn listen_port(self) -> u16 {
        self.listen_port
    }
}

/// The relay's two secret-free, helper-prepared public endpoint tuples.
///
/// The client-facing and exit-facing interfaces are independent kernel devices.
/// Because both encrypted UDP sockets are born in the helper's physical network
/// namespace, their public keys and effective listen ports must both differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPublicEndpointPair {
    client_facing: PublicWireGuardEndpoint,
    exit_facing: PublicWireGuardEndpoint,
}

impl RelayPublicEndpointPair {
    /// Construct a validated public relay pair returned by the privileged helper.
    ///
    /// # Errors
    ///
    /// Rejects reused public keys or effective UDP listen ports. The individual
    /// endpoint constructors have already rejected zero keys, non-unicast
    /// addresses and port zero.
    pub fn new(
        client_facing: PublicWireGuardEndpoint,
        exit_facing: PublicWireGuardEndpoint,
    ) -> Result<Self, WireGuardError> {
        if client_facing.public_key() == exit_facing.public_key() {
            return Err(WireGuardError::InvalidTopology);
        }
        if client_facing.listen_port() == exit_facing.listen_port() {
            return Err(WireGuardError::DuplicateListenPort);
        }
        Ok(Self {
            client_facing,
            exit_facing,
        })
    }

    /// Public tuple on the client-facing relay interface.
    #[must_use]
    pub const fn client_facing_endpoint(self) -> PublicWireGuardEndpoint {
        self.client_facing
    }

    /// Public tuple on the exit-facing relay interface.
    #[must_use]
    pub const fn exit_facing_endpoint(self) -> PublicWireGuardEndpoint {
        self.exit_facing
    }
}

macro_rules! opaque_helper_handle {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// Handles are local capabilities, not private keys, and intentionally
        /// implement neither `Serialize` nor a control-plane wire encoding.
        #[doc = "```compile_fail"]
        #[doc = "use serde::Serialize;"]
        #[doc = concat!("use volparossa_wireguard::", stringify!($name), ";")]
        #[doc = "fn require_wire_encoding<T: Serialize>() {}"]
        #[doc = concat!("require_wire_encoding::<", stringify!($name), ">();")]
        #[doc = "```"]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; HELPER_HANDLE_BYTES]);

        impl $name {
            /// Construct a fixed-width, non-zero helper capability.
            ///
            /// # Errors
            ///
            /// Rejects the all-zero value reserved for invalid protobuf defaults.
            pub fn from_bytes(bytes: [u8; HELPER_HANDLE_BYTES]) -> Result<Self, WireGuardError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(WireGuardError::InvalidHelperHandle);
                }
                Ok(Self(bytes))
            }

            /// Return the exact opaque bytes for the local helper protocol only.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; HELPER_HANDLE_BYTES] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = WireGuardError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| WireGuardError::InvalidHelperHandle)?,
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([OPAQUE])"))
            }
        }
    };
}

opaque_helper_handle!(
    HelperContextHandle,
    "Opaque handle for one route context owned by the privileged helper."
);
opaque_helper_handle!(
    HelperLeaseHandle,
    "Opaque handle for one prepared WireGuard lease owned by the privileged helper."
);

fn validate_lease_binding(
    route_context_id: [u8; 16],
    context_handle: HelperContextHandle,
    lease_handle: HelperLeaseHandle,
    path_id: u32,
    role: EndpointRole,
    expected_role: EndpointRole,
) -> Result<(), WireGuardError> {
    if route_context_id.iter().all(|byte| *byte == 0)
        || !(1..=u32::from(MAX_PATHS)).contains(&path_id)
        || role != expected_role
    {
        return Err(WireGuardError::InvalidHelperBinding);
    }
    if context_handle.as_bytes() == lease_handle.as_bytes() {
        return Err(WireGuardError::DuplicateHelperHandle);
    }
    Ok(())
}

/// Helper-prepared client endpoint containing public data and opaque capabilities only.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ClientEndpointLease {
    route_context_id: [u8; 16],
    context_handle: HelperContextHandle,
    lease_handle: HelperLeaseHandle,
    path_id: u32,
    public: PublicWireGuardEndpoint,
}

impl ClientEndpointLease {
    /// Bind a validated helper response to the exact client route and path.
    ///
    /// # Errors
    ///
    /// Rejects zero route IDs, invalid paths, a non-client role or reused handles.
    pub fn new(
        route_context_id: [u8; 16],
        context_handle: HelperContextHandle,
        lease_handle: HelperLeaseHandle,
        path_id: u32,
        role: EndpointRole,
        public: PublicWireGuardEndpoint,
    ) -> Result<Self, WireGuardError> {
        validate_lease_binding(
            route_context_id,
            context_handle,
            lease_handle,
            path_id,
            role,
            EndpointRole::Client,
        )?;
        Ok(Self {
            route_context_id,
            context_handle,
            lease_handle,
            path_id,
            public,
        })
    }

    /// Route context to which the helper bound this lease.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; 16] {
        &self.route_context_id
    }

    /// Opaque context capability.
    #[must_use]
    pub const fn context_handle(&self) -> HelperContextHandle {
        self.context_handle
    }

    /// Opaque lease capability.
    #[must_use]
    pub const fn lease_handle(&self) -> HelperLeaseHandle {
        self.lease_handle
    }

    /// Context-local path identifier.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Public tuple safe for the client-to-relay signed request.
    #[must_use]
    pub const fn public_endpoint(&self) -> PublicWireGuardEndpoint {
        self.public
    }
}

impl fmt::Debug for ClientEndpointLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientEndpointLease")
            .field("route_context_id", &self.route_context_id)
            .field("context_handle", &self.context_handle)
            .field("lease_handle", &self.lease_handle)
            .field("path_id", &self.path_id)
            .field("public", &self.public)
            .finish()
    }
}

/// Helper-prepared exit endpoint containing public data and opaque capabilities only.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExitEndpointLease {
    route_context_id: [u8; 16],
    context_handle: HelperContextHandle,
    lease_handle: HelperLeaseHandle,
    path_id: u32,
    public: PublicWireGuardEndpoint,
}

impl ExitEndpointLease {
    /// Bind a validated helper response to the exact exit route and path.
    ///
    /// # Errors
    ///
    /// Rejects zero route IDs, invalid paths, a non-exit role or reused handles.
    pub fn new(
        route_context_id: [u8; 16],
        context_handle: HelperContextHandle,
        lease_handle: HelperLeaseHandle,
        path_id: u32,
        role: EndpointRole,
        public: PublicWireGuardEndpoint,
    ) -> Result<Self, WireGuardError> {
        validate_lease_binding(
            route_context_id,
            context_handle,
            lease_handle,
            path_id,
            role,
            EndpointRole::Exit,
        )?;
        Ok(Self {
            route_context_id,
            context_handle,
            lease_handle,
            path_id,
            public,
        })
    }

    /// Route context to which the helper bound this lease.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; 16] {
        &self.route_context_id
    }

    /// Opaque context capability.
    #[must_use]
    pub const fn context_handle(&self) -> HelperContextHandle {
        self.context_handle
    }

    /// Opaque lease capability.
    #[must_use]
    pub const fn lease_handle(&self) -> HelperLeaseHandle {
        self.lease_handle
    }

    /// Context-local path identifier.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Public tuple committed by the exit authorization.
    #[must_use]
    pub const fn public_endpoint(&self) -> PublicWireGuardEndpoint {
        self.public
    }
}

impl fmt::Debug for ExitEndpointLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitEndpointLease")
            .field("route_context_id", &self.route_context_id)
            .field("context_handle", &self.context_handle)
            .field("lease_handle", &self.lease_handle)
            .field("path_id", &self.path_id)
            .field("public", &self.public)
            .finish()
    }
}

/// Helper-prepared relay endpoint pair with independent opaque lease capabilities.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RelayEndpointLease {
    route_context_id: [u8; 16],
    context_handle: HelperContextHandle,
    client_facing_handle: HelperLeaseHandle,
    exit_facing_handle: HelperLeaseHandle,
    path_id: u32,
    endpoints: RelayPublicEndpointPair,
}

impl RelayEndpointLease {
    /// Bind a validated helper response to both roles of one relay path.
    ///
    /// # Errors
    ///
    /// Rejects wrong roles, route/path bindings, duplicated capabilities, keys or ports.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_context_id: [u8; 16],
        context_handle: HelperContextHandle,
        client_facing_handle: HelperLeaseHandle,
        exit_facing_handle: HelperLeaseHandle,
        path_id: u32,
        client_facing_role: EndpointRole,
        exit_facing_role: EndpointRole,
        client_facing: PublicWireGuardEndpoint,
        exit_facing: PublicWireGuardEndpoint,
    ) -> Result<Self, WireGuardError> {
        validate_lease_binding(
            route_context_id,
            context_handle,
            client_facing_handle,
            path_id,
            client_facing_role,
            EndpointRole::RelayClient,
        )?;
        validate_lease_binding(
            route_context_id,
            context_handle,
            exit_facing_handle,
            path_id,
            exit_facing_role,
            EndpointRole::RelayExit,
        )?;
        if client_facing_handle == exit_facing_handle {
            return Err(WireGuardError::DuplicateHelperHandle);
        }
        let endpoints = RelayPublicEndpointPair::new(client_facing, exit_facing)?;
        Ok(Self {
            route_context_id,
            context_handle,
            client_facing_handle,
            exit_facing_handle,
            path_id,
            endpoints,
        })
    }

    /// Route context to which the helper bound this pair.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; 16] {
        &self.route_context_id
    }

    /// Opaque context capability.
    #[must_use]
    pub const fn context_handle(&self) -> HelperContextHandle {
        self.context_handle
    }

    /// Opaque capability for the client-facing lease.
    #[must_use]
    pub const fn client_facing_handle(&self) -> HelperLeaseHandle {
        self.client_facing_handle
    }

    /// Opaque capability for the exit-facing lease.
    #[must_use]
    pub const fn exit_facing_handle(&self) -> HelperLeaseHandle {
        self.exit_facing_handle
    }

    /// Context-local path identifier.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Client-facing public tuple committed by the relay grant.
    #[must_use]
    pub const fn client_facing_endpoint(&self) -> PublicWireGuardEndpoint {
        self.endpoints.client_facing_endpoint()
    }

    /// Exit-facing public tuple committed by the relay grant.
    #[must_use]
    pub const fn exit_facing_endpoint(&self) -> PublicWireGuardEndpoint {
        self.endpoints.exit_facing_endpoint()
    }
}

impl fmt::Debug for RelayEndpointLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayEndpointLease")
            .field("route_context_id", &self.route_context_id)
            .field("context_handle", &self.context_handle)
            .field("client_facing_handle", &self.client_facing_handle)
            .field("exit_facing_handle", &self.exit_facing_handle)
            .field("path_id", &self.path_id)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

/// Fixed role of one endpoint in a two-link relay path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    /// Client side of the client-relay link.
    Client,
    /// Relay side facing the client.
    RelayClient,
    /// Relay side facing the exit.
    RelayExit,
    /// Exit side of the relay-exit link.
    Exit,
}

/// Deterministically allocated host addresses within a path-specific ULA `/112`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OverlayAddresses {
    /// Client overlay address.
    pub client: Ipv6Addr,
    /// Relay's client-facing overlay address.
    pub relay_client: Ipv6Addr,
    /// Relay's exit-facing overlay address.
    pub relay_exit: Ipv6Addr,
    /// Exit overlay address.
    pub exit: Ipv6Addr,
}

impl OverlayAddresses {
    /// Returns the exact address assigned to a role.
    #[must_use]
    pub const fn for_role(self, role: EndpointRole) -> Ipv6Addr {
        match role {
            EndpointRole::Client => self.client,
            EndpointRole::RelayClient => self.relay_client,
            EndpointRole::RelayExit => self.relay_exit,
            EndpointRole::Exit => self.exit,
        }
    }
}

/// Public topology and keys for two separate links; it contains no private key material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPathPlan {
    /// Random route context ID.
    pub route_context_id: [u8; 16],
    /// Context-local path ID.
    pub path_id: u8,
    /// Unique ULA `/112` for this path.
    pub prefix: Ipv6Net,
    /// Explicit role addresses.
    pub addresses: OverlayAddresses,
    /// Client public key on the first link.
    pub client_key: WireGuardPublicKey,
    /// Relay public key on the first link.
    pub relay_client_key: WireGuardPublicKey,
    /// Independent relay public key on the second link.
    pub relay_exit_key: WireGuardPublicKey,
    /// Exit public key on the second link.
    pub exit_key: WireGuardPublicKey,
}

impl PublicPathPlan {
    /// Verifies that the plan describes two independent keys and addresses in one prefix.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero route context, an out-of-range path identifier,
    /// topology not derived from that exact route/path, or zero/duplicated endpoint keys.
    pub fn validate(&self) -> Result<(), WireGuardError> {
        if self.route_context_id.iter().all(|byte| *byte == 0) {
            return Err(WireGuardError::InvalidRouteContext);
        }
        if self.path_id == 0 || self.path_id > MAX_PATHS {
            return Err(WireGuardError::InvalidPathId);
        }
        let expected_prefix = overlay_prefix(self.route_context_id, self.path_id)?;
        if self.prefix != expected_prefix || self.addresses != addresses_in_prefix(expected_prefix)
        {
            return Err(WireGuardError::InvalidTopology);
        }
        let keys = [
            self.client_key,
            self.relay_client_key,
            self.relay_exit_key,
            self.exit_key,
        ];
        if keys.iter().any(|key| key.as_bytes() == &[0; 32])
            || (0..keys.len())
                .any(|left| ((left + 1)..keys.len()).any(|right| keys[left] == keys[right]))
        {
            return Err(WireGuardError::InvalidTopology);
        }
        Ok(())
    }

    /// Builds a public path from independently generated endpoint public keys.
    ///
    /// # Errors
    ///
    /// Rejects a zero route context, invalid path identifier or duplicated/zero endpoint key.
    pub fn from_endpoint_keys(
        route_context_id: [u8; 16],
        path_id: u8,
        client_key: WireGuardPublicKey,
        relay_client_key: WireGuardPublicKey,
        relay_exit_key: WireGuardPublicKey,
        exit_key: WireGuardPublicKey,
    ) -> Result<Self, WireGuardError> {
        let prefix = overlay_prefix(route_context_id, path_id)?;
        let addresses = addresses_in_prefix(prefix);
        let plan = Self {
            route_context_id,
            path_id,
            prefix,
            addresses,
            client_key,
            relay_client_key,
            relay_exit_key,
            exit_key,
        };
        plan.validate()?;
        Ok(plan)
    }
}

fn addresses_in_prefix(prefix: Ipv6Net) -> OverlayAddresses {
    let base = prefix.network().segments();
    let address = |host| {
        Ipv6Addr::new(
            base[0], base[1], base[2], base[3], base[4], base[5], base[6], host,
        )
    };
    OverlayAddresses {
        client: address(1),
        relay_client: address(2),
        relay_exit: address(3),
        exit: address(4),
    }
}

/// Derives the complete canonical overlay address set for one route path.
///
/// This is the public address counterpart to [`overlay_prefix`]. Transport
/// owners use it to prove that a helper-returned socket is bound to the Client
/// or Exit endpoint inside the selected two-link path, rather than to an
/// underlay address that could bypass the Relay.
///
/// # Errors
///
/// Returns an error when the route context or path identifier is invalid.
pub fn overlay_addresses(
    route_context_id: [u8; 16],
    path_id: u8,
) -> Result<OverlayAddresses, WireGuardError> {
    overlay_prefix(route_context_id, path_id).map(addresses_in_prefix)
}

/// Derives the `fd76:6f6c:7061:.../112` ULA prefix without exposing identity material.
///
/// # Errors
///
/// Returns an error when the route context is zero, `path_id` is outside
/// `1..=MAX_PATHS`, or prefix construction fails.
pub fn overlay_prefix(route_context_id: [u8; 16], path_id: u8) -> Result<Ipv6Net, WireGuardError> {
    if route_context_id.iter().all(|byte| *byte == 0) {
        return Err(WireGuardError::InvalidRouteContext);
    }
    if path_id == 0 || path_id > MAX_PATHS {
        return Err(WireGuardError::InvalidPathId);
    }
    let mut context_key = [0_u8; 32];
    context_key[..16].copy_from_slice(&route_context_id);
    context_key[16..].copy_from_slice(&route_context_id);
    let digest = blake3::keyed_hash(&context_key, &[path_id]);
    let bytes = digest.as_bytes();
    let address = Ipv6Addr::new(
        0xfd76,
        0x6f6c,
        0x7061,
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        u16::from(path_id),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        0,
    );
    Ipv6Net::new(address, OVERLAY_PREFIX_LENGTH).map_err(|_| WireGuardError::InvalidTopology)
}

/// Generates an interface name solely from trusted numeric route/path/role data.
///
/// # Errors
///
/// Returns an error when the route context is zero or `path_id` is outside
/// `1..=MAX_PATHS`.
pub fn interface_name(
    route_context_id: [u8; 16],
    path_id: u8,
    role: EndpointRole,
) -> Result<String, WireGuardError> {
    if route_context_id.iter().all(|byte| *byte == 0) {
        return Err(WireGuardError::InvalidRouteContext);
    }
    if path_id == 0 || path_id > MAX_PATHS {
        return Err(WireGuardError::InvalidPathId);
    }
    let role_code = match role {
        EndpointRole::Client => 'c',
        EndpointRole::RelayClient => 'r',
        EndpointRole::RelayExit => 's',
        EndpointRole::Exit => 'e',
    };
    let digest = blake3::hash(&route_context_id);
    let bytes = digest.as_bytes();
    let short = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // IFNAMSIZ includes the NUL terminator, so this must remain <= 15 ASCII bytes.
    Ok(format!("vp{role_code}{path_id:x}{short:08x}"))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn endpoint(seed: u8, port: u16) -> PublicWireGuardEndpoint {
        PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([seed; 32]),
            "8.8.4.20".parse().unwrap(),
            port,
        )
        .unwrap()
    }

    fn context_handle(seed: u8) -> HelperContextHandle {
        HelperContextHandle::from_bytes([seed; HELPER_HANDLE_BYTES]).unwrap()
    }

    fn lease_handle(seed: u8) -> HelperLeaseHandle {
        HelperLeaseHandle::from_bytes([seed; HELPER_HANDLE_BYTES]).unwrap()
    }

    #[test]
    fn public_endpoints_require_public_routability_and_nonzero_port() {
        assert_eq!(
            PublicWireGuardEndpoint::new(
                WireGuardPublicKey::from_bytes([1; 32]),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                41_002,
            )
            .unwrap_err(),
            WireGuardError::InvalidUnderlayAddress
        );
        assert_eq!(
            PublicWireGuardEndpoint::new(
                WireGuardPublicKey::from_bytes([1; 32]),
                "2606:4700:4700::1111".parse().unwrap(),
                0,
            )
            .unwrap_err(),
            WireGuardError::InvalidListenPort
        );
        for address in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "2620:4f:8000::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert_eq!(
                PublicWireGuardEndpoint::new(
                    WireGuardPublicKey::from_bytes([1; 32]),
                    address.parse().unwrap(),
                    41_002,
                )
                .unwrap_err(),
                WireGuardError::InvalidUnderlayAddress,
                "{address} must fail closed",
            );
        }
    }

    #[test]
    fn direct_local_lan_endpoints_remain_distinct_from_public_endpoints() {
        let key = WireGuardPublicKey::from_bytes([1; 32]);
        for address in ["10.0.0.2", "172.16.0.2", "192.168.1.2", "fd01::2"] {
            let address = address.parse().unwrap();
            assert!(PublicWireGuardEndpoint::new(key, address, 41_002).is_err());
            let local = PublicWireGuardEndpoint::new_direct_local_lan(key, address, 41_002)
                .expect("explicit local endpoint");
            assert!(local.is_local_lan());
        }
        for address in [
            "8.8.8.8",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "fe80::1",
        ] {
            assert!(
                PublicWireGuardEndpoint::new_direct_local_lan(
                    key,
                    address.parse().unwrap(),
                    41_002,
                )
                .is_err()
            );
        }
        assert!(
            PublicWireGuardEndpoint::new_direct_local_lan(key, "10.0.0.2".parse().unwrap(), 0,)
                .is_err()
        );
        assert!(!endpoint(1, 41_002).is_local_lan());
    }

    #[test]
    fn helper_handles_and_client_lease_are_exact_nonzero_and_scope_bound() {
        assert_eq!(
            HelperContextHandle::from_bytes([0; HELPER_HANDLE_BYTES]).unwrap_err(),
            WireGuardError::InvalidHelperHandle
        );
        assert_eq!(
            HelperLeaseHandle::try_from(&[1_u8; HELPER_HANDLE_BYTES - 1][..]).unwrap_err(),
            WireGuardError::InvalidHelperHandle
        );
        let client = ClientEndpointLease::new(
            [9; 16],
            context_handle(10),
            lease_handle(11),
            1,
            EndpointRole::Client,
            endpoint(1, 41_001),
        )
        .unwrap();
        assert_eq!(client.public_endpoint().listen_port(), 41_001);
        assert_eq!(client.route_context_id(), &[9; 16]);
        assert_eq!(client.path_id(), 1);
        assert_eq!(
            ClientEndpointLease::new(
                [9; 16],
                context_handle(10),
                lease_handle(11),
                1,
                EndpointRole::Exit,
                endpoint(2, 41_002),
            )
            .unwrap_err(),
            WireGuardError::InvalidHelperBinding
        );
        assert_eq!(
            ClientEndpointLease::new(
                [0; 16],
                context_handle(10),
                lease_handle(11),
                1,
                EndpointRole::Client,
                endpoint(2, 41_002),
            )
            .unwrap_err(),
            WireGuardError::InvalidHelperBinding
        );
        assert_eq!(
            ClientEndpointLease::new(
                [9; 16],
                context_handle(10),
                lease_handle(11),
                0,
                EndpointRole::Client,
                endpoint(2, 41_002),
            )
            .unwrap_err(),
            WireGuardError::InvalidHelperBinding
        );
        assert_eq!(
            ClientEndpointLease::new(
                [9; 16],
                context_handle(10),
                HelperLeaseHandle::from_bytes([10; HELPER_HANDLE_BYTES]).unwrap(),
                1,
                EndpointRole::Client,
                endpoint(2, 41_002),
            )
            .unwrap_err(),
            WireGuardError::DuplicateHelperHandle
        );
    }

    #[test]
    fn relay_lease_requires_two_unique_role_bound_helper_capabilities() {
        let client_facing = endpoint(3, 42_000);
        let exit_facing = endpoint(4, 42_001);
        let relay = RelayEndpointLease::new(
            [8; 16],
            context_handle(20),
            lease_handle(21),
            lease_handle(22),
            2,
            EndpointRole::RelayClient,
            EndpointRole::RelayExit,
            client_facing,
            exit_facing,
        )
        .unwrap();
        assert_eq!(relay.path_id(), 2);
        assert_eq!(relay.client_facing_endpoint(), client_facing);
        assert_eq!(relay.exit_facing_endpoint(), exit_facing);
        assert_eq!(
            RelayEndpointLease::new(
                [8; 16],
                context_handle(20),
                lease_handle(21),
                lease_handle(21),
                2,
                EndpointRole::RelayClient,
                EndpointRole::RelayExit,
                client_facing,
                exit_facing,
            )
            .unwrap_err(),
            WireGuardError::DuplicateHelperHandle
        );
    }

    #[test]
    fn lease_debug_exposes_only_opaque_capability_markers() {
        let lease = ExitEndpointLease::new(
            [9; 16],
            context_handle(30),
            lease_handle(31),
            1,
            EndpointRole::Exit,
            endpoint(5, 43_000),
        )
        .unwrap();
        let debug = format!("{lease:?}");
        assert!(debug.contains("[OPAQUE]"));
        assert!(!debug.contains("31, 31"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn secret_free_relay_pair_requires_distinct_keys_and_ports() {
        let client_facing = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([1; 32]),
            "8.8.4.20".parse().unwrap(),
            43_001,
        )
        .unwrap();
        let exit_facing = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([2; 32]),
            "8.8.4.20".parse().unwrap(),
            43_002,
        )
        .unwrap();
        let pair = RelayPublicEndpointPair::new(client_facing, exit_facing).unwrap();
        assert_eq!(pair.client_facing_endpoint(), client_facing);
        assert_eq!(pair.exit_facing_endpoint(), exit_facing);

        let duplicate_key = PublicWireGuardEndpoint::new(
            client_facing.public_key(),
            "8.8.4.20".parse().unwrap(),
            43_003,
        )
        .unwrap();
        assert_eq!(
            RelayPublicEndpointPair::new(client_facing, duplicate_key).unwrap_err(),
            WireGuardError::InvalidTopology
        );
        let duplicate_port = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([3; 32]),
            "8.8.4.20".parse().unwrap(),
            client_facing.listen_port(),
        )
        .unwrap();
        assert_eq!(
            RelayPublicEndpointPair::new(client_facing, duplicate_port).unwrap_err(),
            WireGuardError::DuplicateListenPort
        );
    }

    #[test]
    fn every_path_gets_unique_112_and_four_host_addresses() {
        let route = [7; 16];
        assert_eq!(
            overlay_prefix([0; 16], 1).unwrap_err(),
            WireGuardError::InvalidRouteContext
        );
        let first_prefix = overlay_prefix(route, 1).expect("first path");
        let second_prefix = overlay_prefix(route, 2).expect("second path");
        assert_ne!(first_prefix, second_prefix);
        assert_eq!(first_prefix.prefix_len(), 112);
        let addresses = addresses_in_prefix(first_prefix);
        assert_ne!(addresses.client, addresses.exit);
    }

    #[test]
    fn independently_owned_endpoints_form_four_key_public_plan() {
        let plan = PublicPathPlan::from_endpoint_keys(
            [9; 16],
            4,
            WireGuardPublicKey::from_bytes([1; 32]),
            WireGuardPublicKey::from_bytes([2; 32]),
            WireGuardPublicKey::from_bytes([3; 32]),
            WireGuardPublicKey::from_bytes([4; 32]),
        )
        .expect("path");
        let keys = [
            plan.client_key,
            plan.relay_client_key,
            plan.relay_exit_key,
            plan.exit_key,
        ];
        for left in 0..keys.len() {
            for right in left + 1..keys.len() {
                assert_ne!(keys[left], keys[right]);
            }
        }
        let mut zero_context = plan.clone();
        zero_context.route_context_id = [0; 16];
        assert_eq!(
            zero_context.validate().unwrap_err(),
            WireGuardError::InvalidRouteContext
        );
        let mut rebound = plan;
        rebound.route_context_id = [8; 16];
        assert_eq!(
            rebound.validate().unwrap_err(),
            WireGuardError::InvalidTopology
        );
    }

    #[test]
    fn interface_names_are_kernel_bounded_and_not_user_text() {
        for role in [
            EndpointRole::Client,
            EndpointRole::RelayClient,
            EndpointRole::RelayExit,
            EndpointRole::Exit,
        ] {
            let name = interface_name([1; 16], 8, role).expect("name");
            assert!(name.len() <= 15);
            assert!(name.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
        assert_eq!(
            interface_name([0; 16], 1, EndpointRole::Client).unwrap_err(),
            WireGuardError::InvalidRouteContext
        );
    }
}
