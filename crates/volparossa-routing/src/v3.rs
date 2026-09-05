//! Strict version-3 protocol for VOLPAROSSA's minimal privileged network helper.
//!
//! The unprivileged agent can describe a route context, peer public endpoints and bounded policy
//! limits. It cannot provide private keys, local overlay addresses, allowed prefixes, listen
//! ports, filesystem paths or free-form privileged input. The independent upload-sharing owner
//! accepts one bounded physical interface name, resolved and revalidated by the helper.
//! The separate, explicitly enabled direct-mesh owner accepts an existing radio name, a bounded
//! mesh ID/channel and a private connected subnet only for its newly created interface. It cannot
//! replace an existing interface or install an Internet route.

mod wifi_mesh;
pub use wifi_mesh::{
    DestroyWifiMesh, DestroyedWifiMesh, InspectWifiMesh, InstallWifiMesh, InstalledWifiMesh,
    WifiMeshPeer, WifiMeshSnapshot, validate_wifi_mesh_response,
};

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
pub use volparossa_core::{is_local_lan_ip, is_public_routable_ip};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Exact agent/helper protocol version.
pub const HELPER_PROTOCOL_VERSION: u32 = 3;
/// Hard local frame limit.
pub const MAX_HELPER_FRAME: usize = 128 * 1024;
/// Per-item and aggregate opaque signed-relay-reservation limit on the helper wire.
///
/// This deliberately reuses the existing helper frame ceiling. The complete encoded request,
/// including protobuf and envelope overhead, must still fit `MAX_HELPER_FRAME`, so the frame codec
/// remains the stricter final authority.
pub const MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES: usize = MAX_HELPER_FRAME;
/// Per-item and aggregate exact signed client-to-relay request limit on the helper wire.
///
/// This field is accepted only for the client-facing half of a relay pair. The complete encoded
/// request, including protobuf overhead, remains subject to `MAX_HELPER_FRAME`.
pub const MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES: usize = MAX_HELPER_FRAME;
/// Maximum distinct paths in one route context.
pub const MAX_HELPER_PATHS: u32 = 8;
/// At most one IPv6 and one IPv4 observation may be attached to each lease; a Relay owns two
/// endpoint roles per path.
pub const MAX_HELPER_TRAVERSAL_HINTS: usize = MAX_HELPER_PATHS as usize * 4;
/// Fixed upper bound shared with signed reservation rate fields.
pub const MAX_HELPER_RATE_MBPS: u32 = 1_000_000;
/// Opaque helper handle length.
pub const HELPER_HANDLE_BYTES: usize = 32;
/// Complete client-ingress descriptor set: four closed kinds for IPv4 and IPv6.
pub const REQUIRED_INGRESS_SOCKETS: usize = 8;

/// Authenticated request from the unprivileged agent.
#[derive(Clone, PartialEq, Message)]
pub struct HelperRequest {
    /// Exact protocol version.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Non-zero random 16-byte idempotency identifier.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// Strict operation allowlist.
    #[prost(
        oneof = "helper_request::Operation",
        tags = "20, 21, 22, 23, 25, 26, 27, 28, 29, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42"
    )]
    pub operation: Option<helper_request::Operation>,
}

/// Allowed privileged operations.
pub mod helper_request {
    use prost::Oneof;

    use super::{
        AcquireIngressReplySocket, AcquireIngressSocket, AcquireTransportSocket,
        ActivateClientIngress, ActivateLeaseBatch, AddMptcpEndpoint, BindHelperRuntime,
        CleanupOwned, CommitLeaseBatch, DestroyClientIngress, DestroyContext, DestroyUplinkSharing,
        DestroyWifiMesh, InspectUplinkSharing, InspectWifiMesh, InstallUplinkSharing,
        InstallWifiMesh, PrepareClientIngress, PrepareLeaseBatch, ReconcileExpiredPrepare,
        RemoveMptcpEndpoint,
    };

    /// Exactly one typed operation.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Operation {
        /// Prepare helper-owned leases without peers.
        #[prost(message, tag = "20")]
        PrepareLeaseBatch(PrepareLeaseBatch),
        /// Activate an exact prepared lease set with public peer data.
        #[prost(message, tag = "21")]
        ActivateLeaseBatch(ActivateLeaseBatch),
        /// Commit only after kernel handshake and counter proof.
        #[prost(message, tag = "22")]
        CommitLeaseBatch(CommitLeaseBatch),
        /// Destroy one context and all contained state.
        #[prost(message, tag = "23")]
        DestroyContext(DestroyContext),
        /// Add one derived MPTCP endpoint after commit.
        #[prost(message, tag = "25")]
        AddMptcpEndpoint(AddMptcpEndpoint),
        /// Remove one exactly owned MPTCP endpoint.
        #[prost(message, tag = "26")]
        RemoveMptcpEndpoint(RemoveMptcpEndpoint),
        /// Acquire one socket created inside the exact committed route namespace.
        #[prost(message, tag = "27")]
        AcquireTransportSocket(AcquireTransportSocket),
        /// Prove that one exact, expired, ambiguously dispatched Prepare left no context.
        #[prost(message, tag = "28")]
        ReconcileExpiredPrepare(ReconcileExpiredPrepare),
        /// Destroy the closed resource scope owned by this helper runtime.
        #[prost(message, tag = "29")]
        CleanupOwned(CleanupOwned),
        /// Prepare a helper-owned client ingress runtime, independent of route contexts.
        #[prost(message, tag = "31")]
        PrepareClientIngress(PrepareClientIngress),
        /// Acquire one exact prepared client-ingress descriptor.
        #[prost(message, tag = "32")]
        AcquireIngressSocket(AcquireIngressSocket),
        /// Activate ingress only after the complete descriptor-receipt set is echoed.
        #[prost(message, tag = "33")]
        ActivateClientIngress(ActivateClientIngress),
        /// Destroy one exact helper-owned client ingress runtime.
        #[prost(message, tag = "34")]
        DestroyClientIngress(DestroyClientIngress),
        /// Read this helper process's non-secret per-start identity.
        #[prost(message, tag = "35")]
        BindHelperRuntime(BindHelperRuntime),
        /// Acquire one exact connected family-matched reply socket for an active ingress flow.
        #[prost(message, tag = "36")]
        AcquireIngressReplySocket(AcquireIngressReplySocket),
        /// Install one independent runtime-long upload-sharing owner.
        #[prost(message, tag = "37")]
        InstallUplinkSharing(InstallUplinkSharing),
        /// Read the exact owner's aggregate kernel queue counters.
        #[prost(message, tag = "38")]
        InspectUplinkSharing(InspectUplinkSharing),
        /// Retire only the exact owned upload-sharing tree.
        #[prost(message, tag = "39")]
        DestroyUplinkSharing(DestroyUplinkSharing),
        /// Create one explicit, runtime-owned direct Wi-Fi mesh underlay.
        #[prost(message, tag = "40")]
        InstallWifiMesh(InstallWifiMesh),
        /// Inspect actual mesh peering on the exact owned interface.
        #[prost(message, tag = "41")]
        InspectWifiMesh(InspectWifiMesh),
        /// Leave and remove only the exact owned mesh interface.
        #[prost(message, tag = "42")]
        DestroyWifiMesh(DestroyWifiMesh),
    }
}

/// Namespace purpose. Zero is deliberately invalid on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ContextRole {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Application-side client context.
    Client = 1,
    /// Forwarding-only relay context.
    Relay = 2,
    /// Policy-limited exit context.
    Exit = 3,
}

/// Exact resource class selected by an authenticated cleanup request.
///
/// Route-only cleanup deliberately preserves the independently owned, runtime-long Client ingress
/// and upload-sharing capabilities so disconnecting a route does not stop node participation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum CleanupScope {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Every resource owned by this helper runtime, including Client ingress and upload sharing.
    AllOwnedResources = 1,
    /// Route contexts and their transport state, preserving Client ingress and upload sharing.
    RouteContextsOnly = 2,
}

/// Endpoint purpose. Zero is deliberately invalid on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum WireguardRole {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Client side of client-to-relay.
    Client = 1,
    /// Relay side facing a client.
    RelayClient = 2,
    /// Relay side facing an exit.
    RelayExit = 3,
    /// Exit side of relay-to-exit.
    Exit = 4,
}

/// Evidence for a helper-selected public underlay address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum UnderlayEvidence {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Public unicast address assigned directly to the unique selected default-route interface.
    DirectAssigned = 1,
    /// Public address observed by the exact authenticated peer for coordinated UDP punching.
    ObservedUdpPunch = 2,
    /// Private LAN address assigned to a kernel-verified on-link route to the exact lease peer.
    DirectOnLink = 3,
}

/// Closed set of Linux MPTCP endpoint behaviours.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum MptcpEndpointMode {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Announce the overlay address.
    Signal = 1,
    /// Initiate subflows from the overlay address.
    Subflow = 2,
    /// Announce and initiate.
    SignalAndSubflow = 3,
}

/// Exact kernel socket shape requested from a committed route namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum TransportSocketKind {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Already-connected, genuinely negotiated MPTCP stream.
    MptcpConnected = 1,
    /// Bound and listening `IPPROTO_MPTCP` stream.
    MptcpListener = 2,
    /// Bound, explicitly unconnected UDP socket for Quinn.
    QuicUdpUnconnected = 3,
    /// Probe-only connected UDP socket available only while the exact context is Activated.
    NativeProbeUdpConnected = 4,
}

/// Fixed Client-side port for one helper-scoped native challenge datagram.
pub const NATIVE_PROBE_CLIENT_PORT: u16 = 41_910;
/// Fixed Exit-side port for one helper-scoped native challenge datagram.
pub const NATIVE_PROBE_EXIT_PORT: u16 = 41_911;
/// Exact native challenge/response payload size.
pub const NATIVE_PROBE_DATAGRAM_BYTES: usize = 32;

/// Concrete transport address; wildcard addresses, zero ports and names are unrepresentable.
#[derive(Clone, PartialEq, Message)]
pub struct TransportSocketAddress {
    /// Four IPv4 bytes or sixteen IPv6 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    /// Exact non-zero transport port.
    #[prost(uint32, tag = "2")]
    pub port: u32,
}

/// Acquire one descriptor bound to an exact committed context, path and transport tuple.
#[derive(Clone, PartialEq, Message)]
pub struct AcquireTransportSocket {
    /// Non-zero 16-byte route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued handle for that committed context.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Existing path 1..=8.
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
    /// Exact existing `WireGuard` endpoint role used by the socket.
    #[prost(enumeration = "WireguardRole", tag = "4")]
    pub role: i32,
    /// Closed socket kind and direction.
    #[prost(enumeration = "TransportSocketKind", tag = "5")]
    pub descriptor_kind: i32,
    /// Exact concrete local address expected from the worker.
    #[prost(message, optional, tag = "6")]
    pub expected_local: Option<TransportSocketAddress>,
    /// Exact peer for connected MPTCP; absent for listeners and unconnected UDP.
    #[prost(message, optional, tag = "7")]
    pub expected_remote: Option<TransportSocketAddress>,
}
/// Address family of one helper-owned ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum IngressAddressFamily {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// IPv4-only socket.
    Ipv4 = 1,
    /// IPv6-only socket with `IPV6_V6ONLY` enabled.
    Ipv6 = 2,
}

/// Closed semantic purpose of one client-ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum IngressSocketKind {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Transparent TCP listener for non-DNS flows.
    TransparentTcpListener = 1,
    /// Transparent UDP ingress for non-DNS datagrams.
    TransparentUdp = 2,
    /// Dedicated transparent TCP listener for DNS port 53.
    DnsTcpListener = 3,
    /// Dedicated transparent UDP ingress for DNS port 53.
    DnsUdp = 4,
}

/// Exact helper-selected wildcard bind address and non-zero listener port.
#[derive(Clone, PartialEq, Message)]
pub struct IngressSocketAddress {
    /// Exactly four zero bytes for IPv4 or sixteen zero bytes for IPv6.
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    /// Kernel-selected non-zero listener port.
    #[prost(uint32, tag = "2")]
    pub port: u32,
}

/// Prepare one helper-owned application ingress before any route context exists.
#[derive(Clone, PartialEq, Message)]
pub struct PrepareClientIngress {
    /// Ephemeral non-zero 16-byte identifier for this agent runtime; never a route context.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Setup deadline, at most 30 seconds after helper receipt.
    #[prost(uint64, tag = "2")]
    pub setup_expires_at_unix: u64,
    /// Hard ingress deadline, at most 15 minutes after helper receipt.
    #[prost(uint64, tag = "3")]
    pub hard_expires_at_unix: u64,
}

/// Acquire one descriptor named only by helper-issued handles and closed identity enums.
#[derive(Clone, PartialEq, Message)]
pub struct AcquireIngressSocket {
    /// Exact client runtime returned by prepare.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Opaque helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Opaque helper-issued socket handle.
    #[prost(bytes = "vec", tag = "3")]
    pub socket_handle: Vec<u8>,
    /// Exact helper-announced semantic socket kind.
    #[prost(enumeration = "IngressSocketKind", tag = "4")]
    pub descriptor_kind: i32,
    /// Exact helper-announced address family.
    #[prost(enumeration = "IngressAddressFamily", tag = "5")]
    pub address_family: i32,
}

/// Receipt echoed only after the agent successfully installed one bound descriptor.
#[derive(Clone, PartialEq, Message)]
pub struct IngressSocketReceipt {
    /// Exact helper-issued socket handle.
    #[prost(bytes = "vec", tag = "1")]
    pub socket_handle: Vec<u8>,
    /// Opaque receipt bound into the successful response and `SCM_RIGHTS` record.
    #[prost(bytes = "vec", tag = "2")]
    pub receipt_handle: Vec<u8>,
    /// Exact semantic socket kind.
    #[prost(enumeration = "IngressSocketKind", tag = "3")]
    pub descriptor_kind: i32,
    /// Exact address family.
    #[prost(enumeration = "IngressAddressFamily", tag = "4")]
    pub address_family: i32,
}

/// Activate ingress only after all eight exact descriptor receipts are present.
#[derive(Clone, PartialEq, Message)]
pub struct ActivateClientIngress {
    /// Exact client runtime returned by prepare.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Opaque helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Complete kind-by-family receipt set.
    #[prost(message, repeated, tag = "3")]
    pub receipts: Vec<IngressSocketReceipt>,
}

/// Idempotently destroy one exact helper-owned client ingress runtime.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyClientIngress {
    /// Exact client runtime returned by prepare.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Opaque helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
}

/// Acquire one non-retargetable transparent UDP reply socket for an active ingress flow.
#[derive(Clone, PartialEq, Message)]
pub struct AcquireIngressReplySocket {
    /// Exact client runtime returned by prepare.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Opaque helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Original Internet tuple which must become the reply socket's local tuple.
    #[prost(message, optional, tag = "3")]
    pub remote: Option<IngressSocketAddress>,
    /// Kernel-observed application tuple which must become the connected peer.
    #[prost(message, optional, tag = "4")]
    pub application: Option<IngressSocketAddress>,
}
/// Public UDP endpoint. The helper never accepts a local listen address from the agent.
#[derive(Clone, PartialEq, Message)]
pub struct PublicUdpEndpoint {
    /// Four or sixteen public unicast address bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    /// Non-zero UDP port.
    #[prost(uint32, tag = "2")]
    pub port: u32,
}

/// One helper-derived endpoint to prepare.
#[derive(Clone, PartialEq, Message)]
pub struct LeasePlan {
    /// Path 1..=8.
    #[prost(uint32, tag = "1")]
    pub path_id: u32,
    /// Endpoint role allowed by the surrounding context role.
    #[prost(enumeration = "WireguardRole", tag = "2")]
    pub role: i32,
}

/// Exact local and remote LAN address candidates; the helper verifies their kernel route.
#[derive(Clone, PartialEq, Message)]
pub struct OnLinkUnderlayHint {
    /// Four RFC1918 or sixteen ULA address bytes assigned to the local interface.
    #[prost(bytes = "vec", tag = "1")]
    pub local_address: Vec<u8>,
    /// Same-family private address of the authenticated adjacent control peer.
    #[prost(bytes = "vec", tag = "2")]
    pub peer_address: Vec<u8>,
}

/// One bounded underlay observation tied to an exact route/path/role and control peer.
///
/// The helper treats this only as a candidate for the already fixed `WireGuard` listen port. The
/// final endpoint is subsequently signed into the reservation protocol before peer activation.
#[derive(Clone, PartialEq, Message)]
pub struct TraversalEndpointHint {
    /// Existing path 1..=8.
    #[prost(uint32, tag = "1")]
    pub path_id: u32,
    /// Exact endpoint role from the containing prepare plan.
    #[prost(enumeration = "WireguardRole", tag = "2")]
    pub role: i32,
    /// Non-zero route actor identity (node ID, or ephemeral client-session ID).
    #[prost(bytes = "vec", tag = "3")]
    pub observer_id: Vec<u8>,
    /// Authenticated transport peer supplying the observation; kept helper-local. For clients,
    /// its association with the separately signed ephemeral actor is checked by the agent.
    #[prost(bytes = "vec", tag = "4")]
    pub observer_peer_id: Vec<u8>,
    /// Four or sixteen public-unicast address bytes, without a peer-controlled port.
    #[prost(bytes = "vec", tag = "5")]
    pub observed_address: Vec<u8>,
    /// Explicit local-LAN candidate; mutually exclusive with the public Identify observation.
    #[prost(message, optional, tag = "6")]
    pub on_link: Option<OnLinkUnderlayHint>,
}

/// Atomically prepare all local endpoint roles for a route context.
#[derive(Clone, PartialEq, Message)]
pub struct PrepareLeaseBatch {
    /// Non-zero 16-byte route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Context purpose.
    #[prost(enumeration = "ContextRole", tag = "2")]
    pub role: i32,
    /// Accepted peer `ADD_ADDR` bound.
    #[prost(uint32, tag = "3")]
    pub mptcp_accepted_addrs: u32,
    /// Additional MPTCP subflow bound.
    #[prost(uint32, tag = "4")]
    pub mptcp_subflows: u32,
    /// Exact role-complete lease set for one to eight paths.
    #[prost(message, repeated, tag = "5")]
    pub leases: Vec<LeasePlan>,
    /// Setup deadline, at most 30 seconds after helper receipt.
    #[prost(uint64, tag = "6")]
    pub setup_expires_at_unix: u64,
    /// Hard context deadline, at most 15 minutes after helper receipt.
    #[prost(uint64, tag = "7")]
    pub hard_expires_at_unix: u64,
    /// Optional exact-peer observations used only when no directly assigned public underlay exists.
    #[prost(message, repeated, tag = "8")]
    pub traversal_hints: Vec<TraversalEndpointHint>,
}

/// Minimal canonical topology needed to recover one possibly dispatched Prepare.
#[derive(Clone, PartialEq, Message)]
pub struct ClosedPreparePlan {
    /// Exact context purpose from the prepared request.
    #[prost(enumeration = "ContextRole", tag = "1")]
    pub context_role: i32,
    /// Canonically ordered, role-complete path identities from the prepared request.
    #[prost(message, repeated, tag = "2")]
    pub leases: Vec<LeasePlan>,
}

/// Exact non-network, non-privileged-mutation intent for a Prepare not yet dispatched.
#[derive(Clone, PartialEq, Message)]
pub struct PrepareIntent {
    /// Exact route context from the prepared request.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Exact random request ID of the prepared request.
    #[prost(bytes = "vec", tag = "2")]
    pub prepare_request_id: Vec<u8>,
    /// Canonical digest of the complete prepared request.
    #[prost(bytes = "vec", tag = "3")]
    pub prepare_operation_digest: Vec<u8>,
    /// Exact setup expiry from the prepared request.
    #[prost(uint64, tag = "4")]
    pub setup_expires_at_unix: u64,
    /// Exact hard expiry from the prepared request.
    #[prost(uint64, tag = "5")]
    pub hard_expires_at_unix: u64,
    /// Closed, canonical recovery plan from the prepared request.
    #[prost(message, optional, tag = "6")]
    pub closed_plan: Option<ClosedPreparePlan>,
}

/// Read this runtime identity and optionally register one exact Prepare intent in this runtime.
#[derive(Clone, PartialEq, Message)]
pub struct BindHelperRuntime {
    /// Absent for a read-only runtime query used by reconciliation.
    #[prost(message, optional, tag = "1")]
    pub prepare_intent: Option<PrepareIntent>,
}

/// Exact authority retained after a possibly dispatched Prepare failed without a response.
#[derive(Clone, PartialEq, Message)]
pub struct ReconcileExpiredPrepare {
    /// Non-zero per-helper-start identity learned on the same authenticated connection.
    #[prost(bytes = "vec", tag = "1")]
    pub helper_runtime_id: Vec<u8>,
    /// Exact route context from the original Prepare.
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    /// Exact random request ID of the original Prepare.
    #[prost(bytes = "vec", tag = "3")]
    pub prepare_request_id: Vec<u8>,
    /// Canonical digest of the complete original Prepare request.
    #[prost(bytes = "vec", tag = "4")]
    pub prepare_operation_digest: Vec<u8>,
    /// Exact setup expiry from the original Prepare.
    #[prost(uint64, tag = "5")]
    pub setup_expires_at_unix: u64,
    /// Exact hard expiry from the original Prepare.
    #[prost(uint64, tag = "6")]
    pub hard_expires_at_unix: u64,
}

/// One prepared lease activation.
#[derive(Clone, PartialEq, Message)]
pub struct LeaseActivation {
    /// Opaque helper-issued lease handle.
    #[prost(bytes = "vec", tag = "1")]
    pub lease_handle: Vec<u8>,
    /// Path 1..=8.
    #[prost(uint32, tag = "2")]
    pub path_id: u32,
    /// Endpoint role.
    #[prost(enumeration = "WireguardRole", tag = "3")]
    pub role: i32,
    /// Signed peer public key.
    #[prost(bytes = "vec", tag = "4")]
    pub peer_public_key: Vec<u8>,
    /// Signed peer public endpoint.
    #[prost(message, optional, tag = "5")]
    pub peer_endpoint: Option<PublicUdpEndpoint>,
    /// Relay upstream rate bound; zero for non-relay roles.
    #[prost(uint32, tag = "6")]
    pub maximum_up_mbps: u32,
    /// Relay downstream rate bound; zero for non-relay roles.
    #[prost(uint32, tag = "7")]
    pub maximum_down_mbps: u32,
    /// Opaque canonical relay-signed reservation envelope.
    ///
    /// Empty remains the protobuf default for compatibility. This wire layer preserves the bytes
    /// and enforces resource bounds but does not verify or grant authority from them.
    #[prost(bytes = "vec", tag = "8")]
    pub signed_relay_reservation: Vec<u8>,
    /// Exact canonical client-session authority accepted for this activation.
    ///
    /// `RelayClient` carries its signed `RelayReservationRequest`; a native-probe `Exit` carries
    /// the complete canonical `NativeProbeAuthorizationChain`. Cryptographic verification and
    /// request-to-reservation commitment checks remain the production backend's responsibility.
    #[prost(bytes = "vec", tag = "9")]
    pub signed_client_relay_request: Vec<u8>,
}

/// Activate exactly a previously prepared batch.
#[derive(Clone, PartialEq, Message)]
pub struct ActivateLeaseBatch {
    /// Route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued context handle.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact prepared lease set with public peer data.
    #[prost(message, repeated, tag = "3")]
    pub leases: Vec<LeaseActivation>,
}

/// One lease included in commit proof.
#[derive(Clone, PartialEq, Message)]
pub struct LeaseCommit {
    /// Opaque helper-issued lease handle.
    #[prost(bytes = "vec", tag = "1")]
    pub lease_handle: Vec<u8>,
    /// Path 1..=8.
    #[prost(uint32, tag = "2")]
    pub path_id: u32,
    /// Endpoint role.
    #[prost(enumeration = "WireguardRole", tag = "3")]
    pub role: i32,
}

/// Ask the helper to prove every activated lease before commit.
#[derive(Clone, PartialEq, Message)]
pub struct CommitLeaseBatch {
    /// Route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued context handle.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Exact activated lease set.
    #[prost(message, repeated, tag = "3")]
    pub leases: Vec<LeaseCommit>,
}

/// Scoped idempotent destruction.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyContext {
    /// Route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued context handle.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
}

/// Add one MPTCP endpoint derived from committed helper state.
#[derive(Clone, PartialEq, Message)]
pub struct AddMptcpEndpoint {
    /// Route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued context handle.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Existing path 1..=8.
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
    /// Closed endpoint behaviour.
    #[prost(enumeration = "MptcpEndpointMode", tag = "4")]
    pub mode: i32,
    /// Backup-only path.
    #[prost(bool, tag = "5")]
    pub backup: bool,
    /// Optional alternate TCP listener port for an Exit signal; zero uses the initial port and is
    /// required for every other endpoint.
    #[prost(uint32, tag = "6")]
    pub listener_port: u32,
}

/// Remove one exactly owned MPTCP endpoint.
#[derive(Clone, PartialEq, Message)]
pub struct RemoveMptcpEndpoint {
    /// Route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Opaque helper-issued context handle.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Existing path 1..=8.
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
}

/// Scoped cleanup authenticates with a fixed-width process-start token.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
pub struct CleanupOwned {
    /// Random 32-byte cleanup token.
    #[prost(bytes = "vec", tag = "1")]
    pub cleanup_token: Vec<u8>,
    /// Closed resource class; zero is invalid.
    #[prost(enumeration = "CleanupScope", tag = "2")]
    pub scope: i32,
}

/// Request one runtime-long upload scheduler, independent of every route context.
///
/// Rates are operator-known decimal Mbps, not NIC speed or discovered spare capacity. The helper
/// resolves the bounded interface name and checks ownership before any kernel mutation.
#[derive(Clone, PartialEq, Message)]
pub struct InstallUplinkSharing {
    /// Non-zero random 16-byte node-sharing runtime identity, not a route context.
    #[prost(bytes = "vec", tag = "1")]
    pub sharing_runtime_id: Vec<u8>,
    /// One 1..=15 byte ASCII netdevice name; paths and free-form input are forbidden.
    #[prost(string, tag = "2")]
    pub interface: String,
    /// Positive bounded operator-known total usable upload in decimal Mbps.
    #[prost(uint32, tag = "3")]
    pub total_upload_mbps: u32,
    /// Positive aggregate Relay+Exit upload ceiling, no greater than total upload.
    #[prost(uint32, tag = "4")]
    pub contribution_upload_ceiling_mbps: u32,
}

/// Inspect one exact sharing owner without changing queue state.
#[derive(Clone, PartialEq, Message)]
pub struct InspectUplinkSharing {
    /// Exact ephemeral sharing runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub sharing_runtime_id: Vec<u8>,
    /// Exact opaque helper-issued sharing handle.
    #[prost(bytes = "vec", tag = "2")]
    pub sharing_handle: Vec<u8>,
}

/// Idempotently retire one exact sharing owner, never unrelated interface state.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyUplinkSharing {
    /// Exact ephemeral sharing runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub sharing_runtime_id: Vec<u8>,
    /// Exact opaque helper-issued sharing handle.
    #[prost(bytes = "vec", tag = "2")]
    pub sharing_handle: Vec<u8>,
}

/// Stable helper result. Zero is never a valid response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum HelperResult {
    /// Invalid protobuf default.
    Unspecified = 0,
    /// Operation completed with the matching typed outcome.
    Ok = 1,
    /// Typed request invariant failed.
    InvalidRequest = 2,
    /// Peer or cleanup capability was unauthorised.
    UnauthorisedPeer = 3,
    /// Resource was absent.
    NotFound = 4,
    /// A different request already owns the identity.
    AlreadyExists = 5,
    /// A kernel operation failed.
    Kernel = 6,
    /// Cleanup could not be proven complete.
    CleanupIncomplete = 7,
    /// Fixed resource capacity was exhausted.
    Capacity = 8,
    /// Setup or hard TTL expired.
    Expired = 9,
    /// Required safe kernel evidence is unavailable.
    Unavailable = 10,
}

/// Stable helper response.
#[derive(Clone, PartialEq, Message)]
pub struct HelperResponse {
    /// Exact protocol version.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Echoed request identifier.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// Structured result.
    #[prost(enumeration = "HelperResult", tag = "3")]
    pub result: i32,
    /// Bounded diagnostic token.
    #[prost(string, tag = "4")]
    pub diagnostic_code: String,
    /// Digest of the canonical full request.
    #[prost(bytes = "vec", tag = "5")]
    pub operation_digest: Vec<u8>,
    /// Operation-specific success output; absent on failure.
    #[prost(
        oneof = "helper_response::Outcome",
        tags = "20, 21, 22, 23, 27, 28, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42"
    )]
    pub outcome: Option<helper_response::Outcome>,
}

/// Typed successful response values.
pub mod helper_response {
    use prost::Oneof;

    use super::{
        ActivatedClientIngress, ActivatedLeaseBatch, CommittedLeaseBatch, DestroyedClientIngress,
        DestroyedContext, DestroyedSharing, DestroyedWifiMesh, Empty, HelperRuntime,
        IngressReplySocketReady, IngressSocketReady, InstalledUplinkSharing, InstalledWifiMesh,
        PreparedClientIngress, PreparedLeaseBatch, ReconciledExpiredPrepare, SharingCounters,
        TransportSocketReady, WifiMeshSnapshot,
    };

    /// Exactly one successful outcome.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Outcome {
        /// Prepared endpoints.
        #[prost(message, tag = "20")]
        PreparedLeaseBatch(PreparedLeaseBatch),
        /// Activated endpoints.
        #[prost(message, tag = "21")]
        ActivatedLeaseBatch(ActivatedLeaseBatch),
        /// Kernel-proven committed endpoints.
        #[prost(message, tag = "22")]
        CommittedLeaseBatch(CommittedLeaseBatch),
        /// Destroy result.
        #[prost(message, tag = "23")]
        DestroyedContext(DestroyedContext),
        /// Metadata for the descriptor transferred immediately after this response frame.
        #[prost(message, tag = "27")]
        TransportSocketReady(TransportSocketReady),
        /// Exact same-runtime proof that an expired ambiguous Prepare is absent.
        #[prost(message, tag = "28")]
        ReconciledExpiredPrepare(ReconciledExpiredPrepare),
        /// Successful MPTCP endpoint change or scoped cleanup result.
        #[prost(message, tag = "30")]
        Empty(Empty),
        /// Prepared client-ingress runtime and its complete helper-selected socket set.
        #[prost(message, tag = "31")]
        PreparedClientIngress(PreparedClientIngress),
        /// Metadata for one separately transferred ingress descriptor.
        #[prost(message, tag = "32")]
        IngressSocketReady(IngressSocketReady),
        /// Activated ingress after all descriptor receipts were correlated.
        #[prost(message, tag = "33")]
        ActivatedClientIngress(ActivatedClientIngress),
        /// Idempotent ingress destruction result.
        #[prost(message, tag = "34")]
        DestroyedClientIngress(DestroyedClientIngress),
        /// Non-secret identity of the helper process serving this connection.
        #[prost(message, tag = "35")]
        HelperRuntime(HelperRuntime),
        /// Exact endpoints of one connected transparent IPv4 reply descriptor.
        #[prost(message, tag = "36")]
        IngressReplySocketReady(IngressReplySocketReady),
        /// Exact runtime-long sharing owner and kernel-resolved physical egress.
        #[prost(message, tag = "37")]
        InstalledUplinkSharing(InstalledUplinkSharing),
        /// Kernel counters for one exact sharing owner.
        #[prost(message, tag = "38")]
        SharingCounters(SharingCounters),
        /// Idempotent sharing retirement result.
        #[prost(message, tag = "39")]
        DestroyedSharing(DestroyedSharing),
        /// Installed direct mesh underlay with exact kernel identity.
        #[prost(message, tag = "40")]
        InstalledWifiMesh(InstalledWifiMesh),
        /// Actual bounded peering/counter snapshot, not estimated bandwidth.
        #[prost(message, tag = "41")]
        WifiMeshSnapshot(WifiMeshSnapshot),
        /// Exact mesh retirement result.
        #[prost(message, tag = "42")]
        DestroyedWifiMesh(DestroyedWifiMesh),
    }
}

/// One helper-owned public endpoint prepared without peers.
#[derive(Clone, PartialEq, Message)]
pub struct PreparedLease {
    /// Opaque non-secret lease handle.
    #[prost(bytes = "vec", tag = "1")]
    pub lease_handle: Vec<u8>,
    /// Path.
    #[prost(uint32, tag = "2")]
    pub path_id: u32,
    /// Endpoint role.
    #[prost(enumeration = "WireguardRole", tag = "3")]
    pub role: i32,
    /// Helper-generated ephemeral public key.
    #[prost(bytes = "vec", tag = "4")]
    pub public_key: Vec<u8>,
    /// Kernel-proven public endpoint.
    #[prost(message, optional, tag = "5")]
    pub public_endpoint: Option<PublicUdpEndpoint>,
    /// Evidence attached to the public address.
    #[prost(enumeration = "UnderlayEvidence", tag = "6")]
    pub underlay_evidence: i32,
}

/// Prepared batch.
#[derive(Clone, PartialEq, Message)]
pub struct PreparedLeaseBatch {
    /// Opaque non-secret context handle.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Complete prepared lease set.
    #[prost(message, repeated, tag = "2")]
    pub leases: Vec<PreparedLease>,
}

/// Non-secret per-start helper process identity.
#[derive(Clone, PartialEq, Message)]
pub struct HelperRuntime {
    /// Non-zero CSPRNG-generated identity, fixed for one helper process.
    #[prost(bytes = "vec", tag = "1")]
    pub helper_runtime_id: Vec<u8>,
}

/// Exact same-runtime absence proof for one expired ambiguous Prepare.
#[derive(Clone, PartialEq, Message)]
pub struct ReconciledExpiredPrepare {
    /// Exact helper runtime from the retained reconciliation authority.
    #[prost(bytes = "vec", tag = "1")]
    pub helper_runtime_id: Vec<u8>,
    /// Exact route context from the original Prepare.
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    /// Exact random request ID of the original Prepare.
    #[prost(bytes = "vec", tag = "3")]
    pub prepare_request_id: Vec<u8>,
    /// Canonical digest of the complete original Prepare request.
    #[prost(bytes = "vec", tag = "4")]
    pub prepare_operation_digest: Vec<u8>,
    /// Exact setup expiry from the original Prepare.
    #[prost(uint64, tag = "5")]
    pub setup_expires_at_unix: u64,
    /// Exact hard expiry from the retained Prepare intent.
    #[prost(uint64, tag = "6")]
    pub hard_expires_at_unix: u64,
}

/// Activated batch.
#[derive(Clone, PartialEq, Message)]
pub struct ActivatedLeaseBatch {
    /// Opaque context handle.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Exact activated lease handles.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub lease_handles: Vec<Vec<u8>>,
}

/// One committed kernel proof.
#[derive(Clone, PartialEq, Message)]
pub struct CommittedLease {
    /// Opaque lease handle.
    #[prost(bytes = "vec", tag = "1")]
    pub lease_handle: Vec<u8>,
    /// Most recent handshake Unix second.
    #[prost(uint64, tag = "2")]
    pub latest_handshake_unix: u64,
    /// Receive counter after activation baseline.
    #[prost(uint64, tag = "3")]
    pub received_bytes: u64,
    /// Transmit counter after activation baseline.
    #[prost(uint64, tag = "4")]
    pub transmitted_bytes: u64,
}

/// Committed batch.
#[derive(Clone, PartialEq, Message)]
pub struct CommittedLeaseBatch {
    /// Opaque context handle.
    #[prost(bytes = "vec", tag = "1")]
    pub context_handle: Vec<u8>,
    /// Proof for every activated lease.
    #[prost(message, repeated, tag = "2")]
    pub leases: Vec<CommittedLease>,
}

/// Idempotent destruction result.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyedContext {
    /// True when a live context was removed; false when already absent.
    #[prost(bool, tag = "1")]
    pub existed: bool,
}

/// Helper-owned upload scheduler installed before active node participation.
#[derive(Clone, PartialEq, Message)]
pub struct InstalledUplinkSharing {
    /// Echoed ephemeral sharing runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub sharing_runtime_id: Vec<u8>,
    /// Opaque non-zero 32-byte helper-issued owner handle.
    #[prost(bytes = "vec", tag = "2")]
    pub sharing_handle: Vec<u8>,
    /// Kernel-resolved non-zero egress ifindex; never an agent-selected index.
    #[prost(uint32, tag = "3")]
    pub egress_ifindex: u32,
}

/// Raw kernel queue counters, without derived rates, sampling time or capacity claims.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SharingQueueCounters {
    /// Kernel-reported byte counter.
    #[prost(uint64, tag = "1")]
    pub bytes: u64,
    /// Kernel-reported packet counter.
    #[prost(uint64, tag = "2")]
    pub packets: u64,
    /// Kernel-reported drop counter.
    #[prost(uint64, tag = "3")]
    pub drops: u64,
    /// Kernel-reported overlimit counter.
    #[prost(uint64, tag = "4")]
    pub overlimits: u64,
    /// Kernel-reported instantaneous byte backlog, not a monotone counter.
    #[prost(uint64, tag = "5")]
    pub backlog_bytes: u64,
}

/// Complete aggregate/owner/contribution queue snapshot for one exact runtime owner.
#[derive(Clone, PartialEq, Message)]
pub struct SharingCounters {
    /// Echoed ephemeral sharing runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub sharing_runtime_id: Vec<u8>,
    /// Echoed exact helper-issued sharing handle.
    #[prost(bytes = "vec", tag = "2")]
    pub sharing_handle: Vec<u8>,
    /// Mandatory total-underlay queue counters.
    #[prost(message, optional, tag = "3")]
    pub total: Option<SharingQueueCounters>,
    /// Mandatory owner's queue counters.
    #[prost(message, optional, tag = "4")]
    pub owner: Option<SharingQueueCounters>,
    /// Mandatory aggregate Relay+Exit contribution queue counters.
    #[prost(message, optional, tag = "5")]
    pub contribution: Option<SharingQueueCounters>,
}

/// Sharing retirement result, correlated by the full request digest and request ID.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct DestroyedSharing {
    /// True when this owner was removed; false when already absent.
    #[prost(bool, tag = "1")]
    pub existed: bool,
}

/// Canonical metadata for one separately transferred transport descriptor.
#[derive(Clone, PartialEq, Message)]
pub struct TransportSocketReady {
    /// Existing path whose namespace owns the descriptor.
    #[prost(uint32, tag = "1")]
    pub path_id: u32,
    /// Exact existing `WireGuard` endpoint role used by the socket.
    #[prost(enumeration = "WireguardRole", tag = "2")]
    pub role: i32,
    /// Kernel socket shape carried by the descriptor.
    #[prost(enumeration = "TransportSocketKind", tag = "3")]
    pub descriptor_kind: i32,
    /// Kernel-validated concrete local address.
    #[prost(message, optional, tag = "4")]
    pub local: Option<TransportSocketAddress>,
    /// Kernel-validated peer for connected MPTCP only.
    #[prost(message, optional, tag = "5")]
    pub remote: Option<TransportSocketAddress>,
}

/// One helper-selected ingress socket prepared before policy activation.
#[derive(Clone, PartialEq, Message)]
pub struct PreparedIngressSocket {
    /// Opaque helper-issued socket handle.
    #[prost(bytes = "vec", tag = "1")]
    pub socket_handle: Vec<u8>,
    /// Closed semantic descriptor kind.
    #[prost(enumeration = "IngressSocketKind", tag = "2")]
    pub descriptor_kind: i32,
    /// Exact address family.
    #[prost(enumeration = "IngressAddressFamily", tag = "3")]
    pub address_family: i32,
    /// Helper- and kernel-selected wildcard bind tuple.
    #[prost(message, optional, tag = "4")]
    pub local: Option<IngressSocketAddress>,
}

/// Prepared client-ingress runtime; no route context or browsing identity is present.
#[derive(Clone, PartialEq, Message)]
pub struct PreparedClientIngress {
    /// Echoed ephemeral client runtime identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Opaque helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Complete four-kinds-by-two-families socket set.
    #[prost(message, repeated, tag = "3")]
    pub sockets: Vec<PreparedIngressSocket>,
    /// Exact accepted hard expiry.
    #[prost(uint64, tag = "4")]
    pub hard_expires_at_unix: u64,
}

/// Metadata bound to one separately transferred ingress descriptor.
#[derive(Clone, PartialEq, Message)]
pub struct IngressSocketReady {
    /// Echoed ephemeral client runtime identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Exact helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Exact helper-issued socket handle.
    #[prost(bytes = "vec", tag = "3")]
    pub socket_handle: Vec<u8>,
    /// Opaque receipt returned only by the typed successful acquisition API.
    #[prost(bytes = "vec", tag = "4")]
    pub receipt_handle: Vec<u8>,
    /// Closed semantic descriptor kind.
    #[prost(enumeration = "IngressSocketKind", tag = "5")]
    pub descriptor_kind: i32,
    /// Exact address family.
    #[prost(enumeration = "IngressAddressFamily", tag = "6")]
    pub address_family: i32,
    /// Kernel-revalidated wildcard bind tuple.
    #[prost(message, optional, tag = "7")]
    pub local: Option<IngressSocketAddress>,
}

/// Activation proof for one complete client ingress runtime.
#[derive(Clone, PartialEq, Message)]
pub struct ActivatedClientIngress {
    /// Echoed ephemeral client runtime identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Exact helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
}

/// Metadata bound to one separately transferred connected ingress reply descriptor.
#[derive(Clone, PartialEq, Message)]
pub struct IngressReplySocketReady {
    /// Echoed ephemeral client runtime identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub client_runtime_id: Vec<u8>,
    /// Exact helper-issued ingress handle.
    #[prost(bytes = "vec", tag = "2")]
    pub ingress_handle: Vec<u8>,
    /// Kernel-revalidated local tuple, equal to the original remote.
    #[prost(message, optional, tag = "3")]
    pub remote: Option<IngressSocketAddress>,
    /// Kernel-revalidated connected peer, equal to the intercepted application.
    #[prost(message, optional, tag = "4")]
    pub application: Option<IngressSocketAddress>,
}

/// Idempotent client-ingress destruction result.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyedClientIngress {
    /// True when a live ingress runtime was removed; false when already absent.
    #[prost(bool, tag = "1")]
    pub existed: bool,
}

/// Empty typed success.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Empty {}

/// Local protocol errors.
#[derive(Debug, Error)]
pub enum HelperProtocolError {
    /// Socket I/O failed.
    #[error("helper socket I/O failed")]
    Io(#[from] std::io::Error),
    /// Protobuf was malformed.
    #[error("malformed helper protobuf")]
    Decode(#[from] prost::DecodeError),
    /// Frame was empty or exceeded the bound.
    #[error("helper frame is outside the fixed bound")]
    TooLarge,
    /// Typed invariant failed.
    #[error("invalid helper message: {0}")]
    Invalid(&'static str),
}

/// Validate and length-prefix a request.
///
/// # Errors
///
/// Returns an error for an invalid typed value or an oversized frame.
///
/// A successful cleanup request frame contains the cleanup token. The returned buffer is therefore
/// caller-owned secret memory: production callers must immediately place it in a zeroizing owner
/// and must never persist it.
pub fn encode_request(value: &HelperRequest) -> Result<Vec<u8>, HelperProtocolError> {
    validate_request(value)?;
    encode_frame(value)
}

/// Validate and length-prefix a response.
///
/// # Errors
///
/// Returns an error for an invalid typed value or an oversized frame.
pub fn encode_response(value: &HelperResponse) -> Result<Vec<u8>, HelperProtocolError> {
    validate_response(value)?;
    encode_frame(value)
}

/// Decode one unframed canonical request.
///
/// # Errors
///
/// Returns an error for malformed, non-canonical, invalid or oversized input.
pub fn decode_request(bytes: &[u8]) -> Result<HelperRequest, HelperProtocolError> {
    decode(bytes, validate_request)
}

/// Decode one unframed canonical response.
///
/// # Errors
///
/// Returns an error for malformed, non-canonical, invalid or oversized input.
pub fn decode_response(bytes: &[u8]) -> Result<HelperResponse, HelperProtocolError> {
    decode(bytes, validate_response)
}

/// Read one bounded request frame.
///
/// # Errors
///
/// Returns an error for I/O failure or an invalid framed request.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<HelperRequest, HelperProtocolError> {
    let frame = read_frame(reader).await?;
    decode_request(frame.as_slice())
}

/// Read one bounded response frame.
///
/// # Errors
///
/// Returns an error for I/O failure or an invalid framed response.
pub async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<HelperResponse, HelperProtocolError> {
    let frame = read_frame(reader).await?;
    decode_response(frame.as_slice())
}

/// Digest the canonical complete request.
///
/// # Errors
///
/// Returns an error when the request is invalid or oversized.
pub fn operation_digest(value: &HelperRequest) -> Result<[u8; 32], HelperProtocolError> {
    validate_request(value)?;
    let bytes = Zeroizing::new(value.encode_to_vec());
    bounded(&bytes)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Validate a sharing response against the exact canonical request and owner lineage.
///
/// This does not replace authenticating and binding the helper process on the same connection.
/// No sharing operation transfers a file descriptor. A valid failure remains a failure result for
/// the caller to handle; this function proves correlation, not successful kernel installation.
///
/// # Errors
///
/// Rejects malformed requests/responses, non-sharing operations, altered correlation fields,
/// mismatched success variants, or substituted sharing identities/handles.
pub fn validate_uplink_sharing_response(
    request: &HelperRequest,
    response: &HelperResponse,
) -> Result<(), HelperProtocolError> {
    use helper_request::Operation;
    use helper_response::Outcome;

    validate_request(request)?;
    validate_response(response)?;
    let operation = request
        .operation
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("missing operation"))?;
    if !matches!(
        operation,
        Operation::InstallUplinkSharing(_)
            | Operation::InspectUplinkSharing(_)
            | Operation::DestroyUplinkSharing(_)
    ) || request.request_id != response.request_id
        || response.operation_digest.as_slice() != operation_digest(request)?
    {
        return Err(HelperProtocolError::Invalid("sharing response correlation"));
    }
    if response.result != HelperResult::Ok as i32 {
        return Ok(());
    }
    let matches = match (operation, response.outcome.as_ref()) {
        (
            Operation::InstallUplinkSharing(request),
            Some(Outcome::InstalledUplinkSharing(value)),
        ) => request.sharing_runtime_id == value.sharing_runtime_id,
        (Operation::InspectUplinkSharing(request), Some(Outcome::SharingCounters(value))) => {
            request.sharing_runtime_id == value.sharing_runtime_id
                && request.sharing_handle == value.sharing_handle
        }
        (Operation::DestroyUplinkSharing(_), Some(Outcome::DestroyedSharing(_))) => true,
        _ => false,
    };
    if !matches {
        return Err(HelperProtocolError::Invalid("sharing response owner"));
    }
    Ok(())
}

/// Derive the exact 32-byte binding sent in the same `SCM_RIGHTS` message as a transport FD.
///
/// The domain-separated BLAKE3 value commits the protocol version, request ID, canonical request
/// digest, full canonical success response and descriptor kind. It is deliberately not serialized
/// into protobuf: receiving it in the same ancillary handoff is what correlates the descriptor.
///
/// # Errors
///
/// Returns an error unless value is a valid successful transport-socket response.
pub fn transport_fd_binding(value: &HelperResponse) -> Result<[u8; 32], HelperProtocolError> {
    validate_response(value)?;
    let Some(helper_response::Outcome::TransportSocketReady(ready)) = value.outcome.as_ref() else {
        return Err(HelperProtocolError::Invalid("transport FD outcome"));
    };
    let kind = TransportSocketKind::try_from(ready.descriptor_kind)
        .map_err(|_| HelperProtocolError::Invalid("transport socket kind"))?;
    let canonical = value.encode_to_vec();
    let canonical_length = u32::try_from(canonical.len())
        .map_err(|_| HelperProtocolError::Invalid("transport FD response length"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VOLPAROSSA helper transport descriptor binding v3\0");
    hasher.update(&value.protocol_version.to_be_bytes());
    hasher.update(&value.request_id);
    hasher.update(&value.operation_digest);
    hasher.update(&(kind as i32).to_be_bytes());
    hasher.update(&canonical_length.to_be_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

/// Derive the exact binding sent atomically with one client-ingress descriptor.
///
/// # Errors
///
/// Returns an error unless value is a valid successful client-ingress socket response.
pub fn ingress_fd_binding(value: &HelperResponse) -> Result<[u8; 32], HelperProtocolError> {
    validate_response(value)?;
    let Some(helper_response::Outcome::IngressSocketReady(ready)) = value.outcome.as_ref() else {
        return Err(HelperProtocolError::Invalid("ingress FD outcome"));
    };
    let kind = IngressSocketKind::try_from(ready.descriptor_kind)
        .map_err(|_| HelperProtocolError::Invalid("ingress socket kind"))?;
    let family = IngressAddressFamily::try_from(ready.address_family)
        .map_err(|_| HelperProtocolError::Invalid("ingress address family"))?;
    let canonical = value.encode_to_vec();
    let canonical_length = u32::try_from(canonical.len())
        .map_err(|_| HelperProtocolError::Invalid("ingress FD response length"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VOLPAROSSA helper ingress descriptor binding v3\0");
    hasher.update(&value.protocol_version.to_be_bytes());
    hasher.update(&value.request_id);
    hasher.update(&value.operation_digest);
    hasher.update(&(kind as i32).to_be_bytes());
    hasher.update(&(family as i32).to_be_bytes());
    hasher.update(&canonical_length.to_be_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

/// Derive the exact binding sent atomically with one connected ingress reply descriptor.
///
/// # Errors
///
/// Returns an error unless value is a valid successful ingress reply-socket response.
pub fn ingress_reply_fd_binding(value: &HelperResponse) -> Result<[u8; 32], HelperProtocolError> {
    validate_response(value)?;
    let Some(helper_response::Outcome::IngressReplySocketReady(ready)) = value.outcome.as_ref()
    else {
        return Err(HelperProtocolError::Invalid("ingress reply FD outcome"));
    };
    let canonical = value.encode_to_vec();
    let canonical_length = u32::try_from(canonical.len())
        .map_err(|_| HelperProtocolError::Invalid("ingress reply FD response length"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VOLPAROSSA helper ingress reply descriptor binding v3\0");
    hasher.update(&value.protocol_version.to_be_bytes());
    hasher.update(&value.request_id);
    hasher.update(&value.operation_digest);
    hasher.update(&ready.client_runtime_id);
    hasher.update(&ready.ingress_handle);
    hasher.update(&canonical_length.to_be_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

/// Derive the binding for either descriptor-bearing helper success outcome.
///
/// # Errors
///
/// Returns an error for a response without exactly one supported descriptor.
pub fn descriptor_fd_binding(value: &HelperResponse) -> Result<[u8; 32], HelperProtocolError> {
    match value.outcome.as_ref() {
        Some(helper_response::Outcome::TransportSocketReady(_)) => transport_fd_binding(value),
        Some(helper_response::Outcome::IngressSocketReady(_)) => ingress_fd_binding(value),
        Some(helper_response::Outcome::IngressReplySocketReady(_)) => {
            ingress_reply_fd_binding(value)
        }
        _ => Err(HelperProtocolError::Invalid("descriptor FD outcome")),
    }
}

/// Return an operator-safe preview without keys, handles, addresses or arbitrary input.
///
/// # Errors
///
/// Returns an error when the request is invalid.
pub fn safe_preview(value: &HelperRequest) -> Result<String, HelperProtocolError> {
    use helper_request::Operation;
    validate_request(value)?;
    let operation = value
        .operation
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("missing operation"))?;
    let mut output = match operation {
        Operation::PrepareLeaseBatch(value) => format!(
            "prepare {:?} context; paths={}; endpoints={}",
            ContextRole::try_from(value.role)
                .map_err(|_| HelperProtocolError::Invalid("context role"))?,
            distinct_paths(&value.leases),
            value.leases.len()
        ),
        Operation::ActivateLeaseBatch(value) => {
            format!(
                "activate prepared context; endpoints={}",
                value.leases.len()
            )
        }
        Operation::CommitLeaseBatch(value) => {
            format!("prove and commit context; endpoints={}", value.leases.len())
        }
        Operation::DestroyContext(_) => "destroy one owned route context".to_owned(),
        Operation::AddMptcpEndpoint(value) => {
            format!("add derived MPTCP endpoint for path {}", value.path_id)
        }
        Operation::RemoveMptcpEndpoint(value) => {
            format!("remove derived MPTCP endpoint for path {}", value.path_id)
        }
        Operation::AcquireTransportSocket(value) => format!(
            "acquire {:?} descriptor for committed path {} role {:?}",
            TransportSocketKind::try_from(value.descriptor_kind)
                .map_err(|_| HelperProtocolError::Invalid("transport socket kind"))?,
            value.path_id,
            WireguardRole::try_from(value.role)
                .map_err(|_| HelperProtocolError::Invalid("endpoint role"))?
        ),
        Operation::ReconcileExpiredPrepare(_) => {
            "prove one exact expired Prepare absent".to_owned()
        }
        Operation::PrepareClientIngress(_) => {
            format!("prepare client ingress runtime; sockets={REQUIRED_INGRESS_SOCKETS}")
        }
        Operation::AcquireIngressSocket(value) => format!(
            "acquire {:?} {:?} client ingress descriptor",
            IngressAddressFamily::try_from(value.address_family)
                .map_err(|_| HelperProtocolError::Invalid("ingress address family"))?,
            IngressSocketKind::try_from(value.descriptor_kind)
                .map_err(|_| HelperProtocolError::Invalid("ingress socket kind"))?
        ),
        Operation::ActivateClientIngress(value) => {
            format!(
                "activate client ingress runtime; receipts={}",
                value.receipts.len()
            )
        }
        Operation::DestroyClientIngress(_) => "destroy one owned client ingress runtime".to_owned(),
        Operation::AcquireIngressReplySocket(_) => {
            "acquire one connected client-ingress UDP reply descriptor".to_owned()
        }
        Operation::BindHelperRuntime(value) if value.prepare_intent.is_some() => {
            "bind helper runtime and pre-register one Prepare intent".to_owned()
        }
        Operation::BindHelperRuntime(_) => "read helper runtime identity".to_owned(),
        Operation::InstallUplinkSharing(_) => "install one owned upload-sharing runtime".to_owned(),
        Operation::InspectUplinkSharing(_) => "inspect one owned upload-sharing runtime".to_owned(),
        Operation::DestroyUplinkSharing(_) => "destroy one owned upload-sharing runtime".to_owned(),
        Operation::InstallWifiMesh(_) => {
            "create one owned open-L2 Wi-Fi mesh link; no default route or radio retuning"
                .to_owned()
        }
        Operation::InspectWifiMesh(_) => "inspect one owned direct Wi-Fi mesh link".to_owned(),
        Operation::DestroyWifiMesh(_) => "leave and remove one owned Wi-Fi mesh link".to_owned(),
        Operation::CleanupOwned(value) => match CleanupScope::try_from(value.scope)
            .map_err(|_| HelperProtocolError::Invalid("cleanup scope"))?
        {
            CleanupScope::AllOwnedResources => "destroy all helper-owned resources".to_owned(),
            CleanupScope::RouteContextsOnly => {
                "destroy helper-owned route contexts; preserve client ingress and upload sharing"
                    .to_owned()
            }
            CleanupScope::Unspecified => {
                return Err(HelperProtocolError::Invalid("cleanup scope"));
            }
        },
    };
    output.push_str("; audit_digest=");
    for byte in &operation_digest(value)?[..8] {
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

#[allow(clippy::too_many_lines)]
fn validate_request(value: &HelperRequest) -> Result<(), HelperProtocolError> {
    use helper_request::Operation;
    envelope(value.protocol_version, &value.request_id)?;
    match value
        .operation
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("missing operation"))?
    {
        Operation::PrepareLeaseBatch(operation) => validate_prepare(operation),
        Operation::ActivateLeaseBatch(operation) => {
            context(&operation.route_context_id)?;
            handle(&operation.context_handle)?;
            let mut signed_relay_reservation_bytes = 0_usize;
            let mut signed_client_relay_request_bytes = 0_usize;
            validate_identity_set(&operation.leases, |lease| {
                handle(&lease.lease_handle)?;
                path_role(lease.path_id, lease.role)?;
                public_key(&lease.peer_public_key)?;
                activation_endpoint(
                    lease
                        .peer_endpoint
                        .as_ref()
                        .ok_or(HelperProtocolError::Invalid("peer endpoint"))?,
                )?;
                let role = WireguardRole::try_from(lease.role)
                    .map_err(|_| HelperProtocolError::Invalid("endpoint role"))?;
                if matches!(role, WireguardRole::RelayClient | WireguardRole::RelayExit) {
                    if lease.maximum_up_mbps == 0
                        || lease.maximum_up_mbps > MAX_HELPER_RATE_MBPS
                        || lease.maximum_down_mbps == 0
                        || lease.maximum_down_mbps > MAX_HELPER_RATE_MBPS
                    {
                        return Err(HelperProtocolError::Invalid("relay rate bounds"));
                    }
                } else if lease.maximum_up_mbps != 0 || lease.maximum_down_mbps != 0 {
                    return Err(HelperProtocolError::Invalid("non-relay rate bounds"));
                }
                if lease.signed_relay_reservation.len() > MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES
                {
                    return Err(HelperProtocolError::Invalid(
                        "signed relay reservation size",
                    ));
                }
                signed_relay_reservation_bytes = signed_relay_reservation_bytes
                    .checked_add(lease.signed_relay_reservation.len())
                    .ok_or(HelperProtocolError::Invalid(
                        "signed relay reservation aggregate size",
                    ))?;
                if lease.signed_client_relay_request.len()
                    > MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES
                {
                    return Err(HelperProtocolError::Invalid(
                        "signed client relay request size",
                    ));
                }
                if role == WireguardRole::RelayClient {
                    if lease.signed_client_relay_request.is_empty() {
                        return Err(HelperProtocolError::Invalid(
                            "missing signed client activation authority",
                        ));
                    }
                    signed_client_relay_request_bytes = signed_client_relay_request_bytes
                        .checked_add(lease.signed_client_relay_request.len())
                        .ok_or(HelperProtocolError::Invalid(
                            "signed client relay request aggregate size",
                        ))?;
                } else if role == WireguardRole::Exit
                    && !lease.signed_client_relay_request.is_empty()
                {
                    signed_client_relay_request_bytes = signed_client_relay_request_bytes
                        .checked_add(lease.signed_client_relay_request.len())
                        .ok_or(HelperProtocolError::Invalid(
                            "signed client relay request aggregate size",
                        ))?;
                } else if !lease.signed_client_relay_request.is_empty() {
                    return Err(HelperProtocolError::Invalid(
                        "signed client relay request role",
                    ));
                }
                Ok((lease.path_id, lease.role))
            })?;
            if signed_relay_reservation_bytes > MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES {
                return Err(HelperProtocolError::Invalid(
                    "signed relay reservation aggregate size",
                ));
            }
            if signed_client_relay_request_bytes > MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES {
                return Err(HelperProtocolError::Invalid(
                    "signed client relay request aggregate size",
                ));
            }
            Ok(())
        }
        Operation::CommitLeaseBatch(operation) => {
            context(&operation.route_context_id)?;
            handle(&operation.context_handle)?;
            validate_identity_set(&operation.leases, |lease| {
                handle(&lease.lease_handle)?;
                path_role(lease.path_id, lease.role)?;
                Ok((lease.path_id, lease.role))
            })
        }
        Operation::DestroyContext(operation) => {
            context(&operation.route_context_id)?;
            handle(&operation.context_handle)
        }
        Operation::AddMptcpEndpoint(operation) => {
            bound_context(&operation.route_context_id, &operation.context_handle)?;
            path(operation.path_id)?;
            let mode = MptcpEndpointMode::try_from(operation.mode)
                .map_err(|_| HelperProtocolError::Invalid("MPTCP mode"))?;
            if mode == MptcpEndpointMode::Unspecified {
                return Err(HelperProtocolError::Invalid("MPTCP mode"));
            }
            if u16::try_from(operation.listener_port).is_err() {
                return Err(HelperProtocolError::Invalid("MPTCP listener port"));
            }
            Ok(())
        }
        Operation::RemoveMptcpEndpoint(operation) => {
            bound_context(&operation.route_context_id, &operation.context_handle)?;
            path(operation.path_id)
        }
        Operation::AcquireTransportSocket(operation) => {
            bound_context(&operation.route_context_id, &operation.context_handle)?;
            path_role(operation.path_id, operation.role)?;
            validate_transport_tuple(
                operation.descriptor_kind,
                operation.expected_local.as_ref(),
                operation.expected_remote.as_ref(),
            )
        }
        Operation::ReconcileExpiredPrepare(operation) => {
            if value.request_id == operation.prepare_request_id {
                return Err(HelperProtocolError::Invalid(
                    "Reconcile and Prepare request IDs",
                ));
            }
            validate_reconcile_scope(
                &operation.helper_runtime_id,
                &operation.route_context_id,
                &operation.prepare_request_id,
                &operation.prepare_operation_digest,
                operation.setup_expires_at_unix,
                operation.hard_expires_at_unix,
            )
        }
        Operation::PrepareClientIngress(operation) => {
            runtime(&operation.client_runtime_id)?;
            if operation.setup_expires_at_unix == 0
                || operation.hard_expires_at_unix < operation.setup_expires_at_unix
            {
                return Err(HelperProtocolError::Invalid("ingress expiry"));
            }
            Ok(())
        }
        Operation::AcquireIngressSocket(operation) => {
            runtime(&operation.client_runtime_id)?;
            handle(&operation.ingress_handle)?;
            handle(&operation.socket_handle)?;
            if operation.ingress_handle == operation.socket_handle {
                return Err(HelperProtocolError::Invalid("duplicate ingress handle"));
            }
            ingress_identity(operation.descriptor_kind, operation.address_family)?;
            Ok(())
        }
        Operation::ActivateClientIngress(operation) => {
            runtime(&operation.client_runtime_id)?;
            handle(&operation.ingress_handle)?;
            if operation.receipts.len() != REQUIRED_INGRESS_SOCKETS {
                return Err(HelperProtocolError::Invalid("ingress receipt count"));
            }
            let mut socket_handles = BTreeSet::new();
            let mut receipt_handles = BTreeSet::new();
            let mut all_handles = BTreeSet::from([operation.ingress_handle.as_slice()]);
            let mut identities = BTreeSet::new();
            for receipt in &operation.receipts {
                handle(&receipt.socket_handle)?;
                handle(&receipt.receipt_handle)?;
                if !socket_handles.insert(receipt.socket_handle.as_slice())
                    || !receipt_handles.insert(receipt.receipt_handle.as_slice())
                    || !all_handles.insert(receipt.socket_handle.as_slice())
                    || !all_handles.insert(receipt.receipt_handle.as_slice())
                    || !identities.insert(ingress_identity(
                        receipt.descriptor_kind,
                        receipt.address_family,
                    )?)
                {
                    return Err(HelperProtocolError::Invalid("duplicate ingress receipt"));
                }
            }
            complete_ingress_identities(&identities)
        }
        Operation::DestroyClientIngress(operation) => {
            runtime(&operation.client_runtime_id)?;
            handle(&operation.ingress_handle)
        }
        Operation::AcquireIngressReplySocket(operation) => {
            runtime(&operation.client_runtime_id)?;
            handle(&operation.ingress_handle)?;
            let remote = concrete_ingress_address(
                operation
                    .remote
                    .as_ref()
                    .ok_or(HelperProtocolError::Invalid("ingress reply remote"))?,
            )?;
            let application = concrete_ingress_address(
                operation
                    .application
                    .as_ref()
                    .ok_or(HelperProtocolError::Invalid("ingress reply application"))?,
            )?;
            if remote == application || remote.is_ipv4() != application.is_ipv4() {
                return Err(HelperProtocolError::Invalid("ingress reply address pair"));
            }
            Ok(())
        }
        Operation::BindHelperRuntime(operation) => {
            operation.prepare_intent.as_ref().map_or(Ok(()), |intent| {
                if value.request_id == intent.prepare_request_id {
                    return Err(HelperProtocolError::Invalid("Bind and Prepare request IDs"));
                }
                validate_prepare_identity(
                    &intent.route_context_id,
                    &intent.prepare_request_id,
                    &intent.prepare_operation_digest,
                    intent.setup_expires_at_unix,
                    intent.hard_expires_at_unix,
                )?;
                let closed_plan = intent
                    .closed_plan
                    .as_ref()
                    .ok_or(HelperProtocolError::Invalid("missing closed Prepare plan"))?;
                validate_closed_prepare_plan(closed_plan.context_role, &closed_plan.leases)
            })
        }
        Operation::CleanupOwned(operation) if operation.cleanup_token.len() != 32 => {
            Err(HelperProtocolError::Invalid("cleanup token"))
        }
        Operation::CleanupOwned(operation) => match CleanupScope::try_from(operation.scope).ok() {
            Some(CleanupScope::AllOwnedResources | CleanupScope::RouteContextsOnly) => Ok(()),
            Some(CleanupScope::Unspecified) | None => {
                Err(HelperProtocolError::Invalid("cleanup scope"))
            }
        },
        Operation::InstallUplinkSharing(operation) => validate_install_sharing(operation),
        Operation::InspectUplinkSharing(operation) => {
            sharing_runtime(&operation.sharing_runtime_id)?;
            handle(&operation.sharing_handle)
        }
        Operation::DestroyUplinkSharing(operation) => {
            sharing_runtime(&operation.sharing_runtime_id)?;
            handle(&operation.sharing_handle)
        }
        Operation::InstallWifiMesh(operation) => wifi_mesh::validate_install(operation),
        Operation::InspectWifiMesh(operation) => {
            context(&operation.mesh_runtime_id)?;
            handle(&operation.mesh_handle)
        }
        Operation::DestroyWifiMesh(operation) => {
            context(&operation.mesh_runtime_id)?;
            handle(&operation.mesh_handle)
        }
    }
}

fn validate_install_sharing(value: &InstallUplinkSharing) -> Result<(), HelperProtocolError> {
    sharing_runtime(&value.sharing_runtime_id)?;
    let name = value.interface.as_str();
    if !(1..=15).contains(&name.len())
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(HelperProtocolError::Invalid("sharing interface"));
    }
    if !(1..=MAX_HELPER_RATE_MBPS).contains(&value.total_upload_mbps)
        || !(1..=value.total_upload_mbps).contains(&value.contribution_upload_ceiling_mbps)
    {
        return Err(HelperProtocolError::Invalid("sharing rate bounds"));
    }
    Ok(())
}

fn sharing_runtime(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("sharing runtime"));
    }
    Ok(())
}

fn validate_prepare(value: &PrepareLeaseBatch) -> Result<(), HelperProtocolError> {
    context(&value.route_context_id)?;
    if value.mptcp_accepted_addrs > MAX_HELPER_PATHS
        || value.mptcp_subflows == 0
        || value.mptcp_subflows > MAX_HELPER_PATHS
        || value.setup_expires_at_unix == 0
        || value.hard_expires_at_unix < value.setup_expires_at_unix
    {
        return Err(HelperProtocolError::Invalid("prepare bounds"));
    }
    validate_closed_prepare_plan(value.role, &value.leases)?;
    validate_traversal_hints(&value.leases, &value.traversal_hints)
}

fn validate_traversal_hints(
    leases: &[LeasePlan],
    hints: &[TraversalEndpointHint],
) -> Result<(), HelperProtocolError> {
    if hints.len() > MAX_HELPER_TRAVERSAL_HINTS {
        return Err(HelperProtocolError::Invalid("traversal hint count"));
    }
    let lease_identities = leases
        .iter()
        .map(|lease| (lease.path_id, lease.role))
        .collect::<BTreeSet<_>>();
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for hint in hints {
        path_role(hint.path_id, hint.role)?;
        if !lease_identities.contains(&(hint.path_id, hint.role))
            || hint.observer_id.len() != 32
            || hint.observer_id.iter().all(|byte| *byte == 0)
            || hint.observer_peer_id.is_empty()
            || hint.observer_peer_id.len() > 64
            || hint.observer_peer_id.iter().all(|byte| *byte == 0)
        {
            return Err(HelperProtocolError::Invalid("traversal hint lineage"));
        }
        let (address, address_bytes) = if let Some(on_link) = &hint.on_link {
            if !hint.observed_address.is_empty() {
                return Err(HelperProtocolError::Invalid("mixed underlay hints"));
            }
            let local = parse_local_lan_address(&on_link.local_address)?;
            let peer = parse_local_lan_address(&on_link.peer_address)?;
            if local == peer || local.is_ipv4() != peer.is_ipv4() {
                return Err(HelperProtocolError::Invalid("on-link address pair"));
            }
            (local, on_link.local_address.as_slice())
        } else {
            (
                parse_public_address(&hint.observed_address)?,
                hint.observed_address.as_slice(),
            )
        };
        let family = u8::from(address.is_ipv4()); // IPv6 sorts before IPv4.
        let key = (
            hint.path_id,
            hint.role,
            family,
            address_bytes,
            hint.observer_peer_id.as_slice(),
        );
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || !identities.insert((hint.path_id, hint.role, family))
        {
            return Err(HelperProtocolError::Invalid(
                "non-canonical traversal hints",
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_closed_prepare_plan(
    context_role: i32,
    leases: &[LeasePlan],
) -> Result<(), HelperProtocolError> {
    let context_role = ContextRole::try_from(context_role)
        .map_err(|_| HelperProtocolError::Invalid("context role"))?;
    if context_role == ContextRole::Unspecified {
        return Err(HelperProtocolError::Invalid("context role"));
    }
    validate_identity_set(leases, |lease| {
        path_role(lease.path_id, lease.role)?;
        Ok((lease.path_id, lease.role))
    })?;
    if leases
        .windows(2)
        .any(|pair| (pair[0].path_id, pair[0].role) >= (pair[1].path_id, pair[1].role))
    {
        return Err(HelperProtocolError::Invalid("non-canonical lease order"));
    }
    validate_role_cardinality(context_role, leases)
}

fn validate_role_cardinality(
    context_role: ContextRole,
    leases: &[LeasePlan],
) -> Result<(), HelperProtocolError> {
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for lease in leases {
        paths.insert(lease.path_id);
        identities.insert((lease.path_id, lease.role));
    }
    if paths.is_empty() || paths.len() > MAX_HELPER_PATHS as usize {
        return Err(HelperProtocolError::Invalid("path count"));
    }
    for path_id in paths {
        let expected: &[WireguardRole] = match context_role {
            ContextRole::Client => &[WireguardRole::Client],
            ContextRole::Relay => &[WireguardRole::RelayClient, WireguardRole::RelayExit],
            ContextRole::Exit => &[WireguardRole::Exit],
            ContextRole::Unspecified => return Err(HelperProtocolError::Invalid("context role")),
        };
        if expected
            .iter()
            .any(|role| !identities.contains(&(path_id, *role as i32)))
            || identities.iter().any(|(path, role)| {
                *path == path_id && !expected.iter().any(|expected| *role == *expected as i32)
            })
        {
            return Err(HelperProtocolError::Invalid("role cardinality"));
        }
    }
    Ok(())
}

fn validate_response(value: &HelperResponse) -> Result<(), HelperProtocolError> {
    envelope(value.protocol_version, &value.request_id)?;
    if value.operation_digest.len() != 32
        || value.diagnostic_code.is_empty()
        || value.diagnostic_code.len() > 64
        || !value
            .diagnostic_code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(HelperProtocolError::Invalid("response envelope"));
    }
    let result =
        HelperResult::try_from(value.result).map_err(|_| HelperProtocolError::Invalid("result"))?;
    if result == HelperResult::Unspecified {
        return Err(HelperProtocolError::Invalid("result"));
    }
    match (result, value.outcome.as_ref()) {
        (HelperResult::Ok, Some(outcome)) => validate_outcome(outcome),
        (HelperResult::Ok | HelperResult::Unspecified, None) | (_, Some(_)) => {
            Err(HelperProtocolError::Invalid("response outcome"))
        }
        (_, None) => Ok(()),
    }
}

fn validate_outcome(value: &helper_response::Outcome) -> Result<(), HelperProtocolError> {
    use helper_response::Outcome;
    match value {
        Outcome::PreparedLeaseBatch(value) => {
            handle(&value.context_handle)?;
            validate_identity_set(&value.leases, |lease| {
                handle(&lease.lease_handle)?;
                path_role(lease.path_id, lease.role)?;
                public_key(&lease.public_key)?;
                let public_endpoint = lease
                    .public_endpoint
                    .as_ref()
                    .ok_or(HelperProtocolError::Invalid("public endpoint"))?;
                match UnderlayEvidence::try_from(lease.underlay_evidence) {
                    Ok(UnderlayEvidence::DirectAssigned | UnderlayEvidence::ObservedUdpPunch) => {
                        endpoint(public_endpoint)?;
                    }
                    Ok(UnderlayEvidence::DirectOnLink) => {
                        if !(1..=65_535).contains(&public_endpoint.port) {
                            return Err(HelperProtocolError::Invalid("UDP port"));
                        }
                        let _ = parse_local_lan_address(&public_endpoint.address)?;
                    }
                    _ => return Err(HelperProtocolError::Invalid("underlay evidence")),
                }
                Ok((lease.path_id, lease.role))
            })
        }
        Outcome::ActivatedLeaseBatch(value) => {
            handle(&value.context_handle)?;
            validate_handles(&value.lease_handles)
        }
        Outcome::CommittedLeaseBatch(value) => {
            handle(&value.context_handle)?;
            if value.leases.is_empty() || value.leases.len() > 16 {
                return Err(HelperProtocolError::Invalid("commit proof count"));
            }
            let mut handles = BTreeSet::new();
            for lease in &value.leases {
                handle(&lease.lease_handle)?;
                if !handles.insert(lease.lease_handle.as_slice())
                    || lease.latest_handshake_unix == 0
                    || lease.received_bytes == 0
                    || lease.transmitted_bytes == 0
                {
                    return Err(HelperProtocolError::Invalid("commit proof"));
                }
            }
            Ok(())
        }
        Outcome::TransportSocketReady(value) => {
            path_role(value.path_id, value.role)?;
            validate_transport_tuple(
                value.descriptor_kind,
                value.local.as_ref(),
                value.remote.as_ref(),
            )
        }
        Outcome::ReconciledExpiredPrepare(value) => validate_reconcile_scope(
            &value.helper_runtime_id,
            &value.route_context_id,
            &value.prepare_request_id,
            &value.prepare_operation_digest,
            value.setup_expires_at_unix,
            value.hard_expires_at_unix,
        ),
        Outcome::PreparedClientIngress(value) => validate_prepared_ingress_outcome(value),
        Outcome::IngressSocketReady(value) => validate_ingress_ready_outcome(value),
        Outcome::IngressReplySocketReady(value) => validate_ingress_reply_ready(value),
        Outcome::ActivatedClientIngress(value) => {
            runtime(&value.client_runtime_id)?;
            handle(&value.ingress_handle)
        }
        Outcome::InstalledUplinkSharing(value) => validate_installed_sharing(value),
        Outcome::SharingCounters(value) => validate_sharing_counters(value),
        Outcome::InstalledWifiMesh(value) => wifi_mesh::validate_installed(value),
        Outcome::WifiMeshSnapshot(value) => wifi_mesh::validate_snapshot(value),
        Outcome::DestroyedClientIngress(_)
        | Outcome::DestroyedContext(_)
        | Outcome::DestroyedSharing(_)
        | Outcome::DestroyedWifiMesh(_)
        | Outcome::Empty(_) => Ok(()),
        Outcome::HelperRuntime(value) => helper_runtime(&value.helper_runtime_id),
    }
}

fn validate_ingress_reply_ready(
    value: &IngressReplySocketReady,
) -> Result<(), HelperProtocolError> {
    runtime(&value.client_runtime_id)?;
    handle(&value.ingress_handle)?;
    let remote = concrete_ingress_address(
        value
            .remote
            .as_ref()
            .ok_or(HelperProtocolError::Invalid("ingress reply remote"))?,
    )?;
    let application = concrete_ingress_address(
        value
            .application
            .as_ref()
            .ok_or(HelperProtocolError::Invalid("ingress reply application"))?,
    )?;
    if remote == application || remote.is_ipv4() != application.is_ipv4() {
        return Err(HelperProtocolError::Invalid("ingress reply address pair"));
    }
    Ok(())
}

fn validate_installed_sharing(value: &InstalledUplinkSharing) -> Result<(), HelperProtocolError> {
    sharing_runtime(&value.sharing_runtime_id)?;
    handle(&value.sharing_handle)?;
    if value.egress_ifindex == 0 {
        return Err(HelperProtocolError::Invalid("sharing egress ifindex"));
    }
    Ok(())
}

fn validate_sharing_counters(value: &SharingCounters) -> Result<(), HelperProtocolError> {
    sharing_runtime(&value.sharing_runtime_id)?;
    handle(&value.sharing_handle)?;
    if value.total.is_none() || value.owner.is_none() || value.contribution.is_none() {
        return Err(HelperProtocolError::Invalid("sharing queue counters"));
    }
    Ok(())
}

fn validate_reconcile_scope(
    helper_runtime_id: &[u8],
    route_context_id: &[u8],
    prepare_request_id: &[u8],
    prepare_operation_digest: &[u8],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
) -> Result<(), HelperProtocolError> {
    helper_runtime(helper_runtime_id)?;
    validate_prepare_identity(
        route_context_id,
        prepare_request_id,
        prepare_operation_digest,
        setup_expires_at_unix,
        hard_expires_at_unix,
    )
}

fn validate_prepare_identity(
    route_context_id: &[u8],
    prepare_request_id: &[u8],
    prepare_operation_digest: &[u8],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
) -> Result<(), HelperProtocolError> {
    context(route_context_id)?;
    request_identity(prepare_request_id)?;
    if prepare_operation_digest.len() != 32
        || setup_expires_at_unix == 0
        || hard_expires_at_unix < setup_expires_at_unix
    {
        return Err(HelperProtocolError::Invalid("Prepare identity"));
    }
    Ok(())
}

fn validate_prepared_ingress_outcome(
    value: &PreparedClientIngress,
) -> Result<(), HelperProtocolError> {
    runtime(&value.client_runtime_id)?;
    handle(&value.ingress_handle)?;
    if value.hard_expires_at_unix == 0 || value.sockets.len() != REQUIRED_INGRESS_SOCKETS {
        return Err(HelperProtocolError::Invalid("prepared ingress bounds"));
    }
    let mut handles = BTreeSet::from([value.ingress_handle.as_slice()]);
    let mut identities = BTreeSet::new();
    for socket in &value.sockets {
        handle(&socket.socket_handle)?;
        let identity = ingress_identity(socket.descriptor_kind, socket.address_family)?;
        ingress_local(
            socket
                .local
                .as_ref()
                .ok_or(HelperProtocolError::Invalid("ingress local address"))?,
            identity.1,
        )?;
        if !handles.insert(socket.socket_handle.as_slice()) || !identities.insert(identity) {
            return Err(HelperProtocolError::Invalid("duplicate ingress socket"));
        }
    }
    complete_ingress_identities(&identities)
}

fn validate_ingress_ready_outcome(value: &IngressSocketReady) -> Result<(), HelperProtocolError> {
    runtime(&value.client_runtime_id)?;
    handle(&value.ingress_handle)?;
    handle(&value.socket_handle)?;
    handle(&value.receipt_handle)?;
    if value.ingress_handle == value.socket_handle
        || value.ingress_handle == value.receipt_handle
        || value.socket_handle == value.receipt_handle
    {
        return Err(HelperProtocolError::Invalid("duplicate ingress handle"));
    }
    let identity = ingress_identity(value.descriptor_kind, value.address_family)?;
    ingress_local(
        value
            .local
            .as_ref()
            .ok_or(HelperProtocolError::Invalid("ingress local address"))?,
        identity.1,
    )
}

fn validate_identity_set<T>(
    values: &[T],
    mut validate: impl FnMut(&T) -> Result<(u32, i32), HelperProtocolError>,
) -> Result<(), HelperProtocolError> {
    if values.is_empty() || values.len() > 16 {
        return Err(HelperProtocolError::Invalid("lease count"));
    }
    let mut identities = BTreeSet::new();
    for value in values {
        if !identities.insert(validate(value)?) {
            return Err(HelperProtocolError::Invalid("duplicate lease"));
        }
    }
    Ok(())
}

fn validate_handles(values: &[Vec<u8>]) -> Result<(), HelperProtocolError> {
    if values.is_empty() || values.len() > 16 {
        return Err(HelperProtocolError::Invalid("handle count"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        handle(value)?;
        if !unique.insert(value.as_slice()) {
            return Err(HelperProtocolError::Invalid("duplicate handle"));
        }
    }
    Ok(())
}

fn envelope(version: u32, request_id: &[u8]) -> Result<(), HelperProtocolError> {
    if version != HELPER_PROTOCOL_VERSION || request_identity(request_id).is_err() {
        return Err(HelperProtocolError::Invalid("version or request ID"));
    }
    Ok(())
}

fn request_identity(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("request ID"));
    }
    Ok(())
}

fn helper_runtime(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("helper runtime"));
    }
    Ok(())
}

fn runtime(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("client runtime"));
    }
    Ok(())
}

fn ingress_identity(
    descriptor_kind: i32,
    address_family: i32,
) -> Result<(i32, i32), HelperProtocolError> {
    let kind = IngressSocketKind::try_from(descriptor_kind)
        .map_err(|_| HelperProtocolError::Invalid("ingress socket kind"))?;
    let family = IngressAddressFamily::try_from(address_family)
        .map_err(|_| HelperProtocolError::Invalid("ingress address family"))?;
    if kind == IngressSocketKind::Unspecified || family == IngressAddressFamily::Unspecified {
        return Err(HelperProtocolError::Invalid("ingress socket identity"));
    }
    Ok((kind as i32, family as i32))
}

fn complete_ingress_identities(actual: &BTreeSet<(i32, i32)>) -> Result<(), HelperProtocolError> {
    let expected = [
        IngressSocketKind::TransparentTcpListener,
        IngressSocketKind::TransparentUdp,
        IngressSocketKind::DnsTcpListener,
        IngressSocketKind::DnsUdp,
    ]
    .into_iter()
    .flat_map(|kind| {
        [IngressAddressFamily::Ipv4, IngressAddressFamily::Ipv6]
            .into_iter()
            .map(move |family| (kind as i32, family as i32))
    })
    .collect::<BTreeSet<_>>();
    if actual != &expected {
        return Err(HelperProtocolError::Invalid(
            "incomplete ingress socket set",
        ));
    }
    Ok(())
}

fn ingress_local(
    value: &IngressSocketAddress,
    address_family: i32,
) -> Result<(), HelperProtocolError> {
    if !(1..=65_535).contains(&value.port) {
        return Err(HelperProtocolError::Invalid("ingress port"));
    }
    let family = IngressAddressFamily::try_from(address_family)
        .map_err(|_| HelperProtocolError::Invalid("ingress address family"))?;
    let valid = match family {
        IngressAddressFamily::Ipv4 => {
            value.address.len() == 4 && value.address.iter().all(|byte| *byte == 0)
        }
        IngressAddressFamily::Ipv6 => {
            value.address.len() == 16 && value.address.iter().all(|byte| *byte == 0)
        }
        IngressAddressFamily::Unspecified => false,
    };
    if !valid {
        return Err(HelperProtocolError::Invalid("ingress local address"));
    }
    Ok(())
}

fn concrete_ingress_address(
    value: &IngressSocketAddress,
) -> Result<SocketAddr, HelperProtocolError> {
    let port = u16::try_from(value.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(HelperProtocolError::Invalid("ingress reply UDP port"))?;
    match value.address.as_slice() {
        bytes if bytes.len() == 4 => {
            let address = Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes)
                    .map_err(|_| HelperProtocolError::Invalid("ingress reply IPv4 address"))?,
            );
            if address.is_unspecified() || address.is_multicast() || address == Ipv4Addr::BROADCAST
            {
                return Err(HelperProtocolError::Invalid("ingress reply IPv4 address"));
            }
            Ok(SocketAddr::from((address, port)))
        }
        bytes if bytes.len() == 16 => {
            let address = Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes)
                    .map_err(|_| HelperProtocolError::Invalid("ingress reply IPv6 address"))?,
            );
            if address.is_unspecified() || address.is_multicast() {
                return Err(HelperProtocolError::Invalid("ingress reply IPv6 address"));
            }
            Ok(SocketAddr::from((address, port)))
        }
        _ => Err(HelperProtocolError::Invalid("ingress reply address family")),
    }
}

fn bound_context(context_id: &[u8], context_handle: &[u8]) -> Result<(), HelperProtocolError> {
    context(context_id)?;
    handle(context_handle)
}

fn context(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("route context"));
    }
    Ok(())
}

fn handle(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != HELPER_HANDLE_BYTES || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("opaque handle"));
    }
    Ok(())
}

fn path(value: u32) -> Result<(), HelperProtocolError> {
    if !(1..=MAX_HELPER_PATHS).contains(&value) {
        return Err(HelperProtocolError::Invalid("path ID"));
    }
    Ok(())
}

fn path_role(path_id: u32, role: i32) -> Result<(), HelperProtocolError> {
    path(path_id)?;
    let role =
        WireguardRole::try_from(role).map_err(|_| HelperProtocolError::Invalid("endpoint role"))?;
    if role == WireguardRole::Unspecified {
        return Err(HelperProtocolError::Invalid("endpoint role"));
    }
    Ok(())
}

fn public_key(value: &[u8]) -> Result<(), HelperProtocolError> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err(HelperProtocolError::Invalid("public key"));
    }
    Ok(())
}

fn endpoint(value: &PublicUdpEndpoint) -> Result<(), HelperProtocolError> {
    if !(1..=65_535).contains(&value.port) {
        return Err(HelperProtocolError::Invalid("UDP port"));
    }
    let _address = parse_public_address(&value.address)?;
    Ok(())
}

/// An activation endpoint is only a candidate: its opaque prepared lease and signed authority
/// must match the helper's stored kernel-verified on-link binding before private UDP is enabled.
fn activation_endpoint(value: &PublicUdpEndpoint) -> Result<(), HelperProtocolError> {
    if endpoint(value).is_ok() {
        return Ok(());
    }
    if !(1..=65_535).contains(&value.port) {
        return Err(HelperProtocolError::Invalid("UDP port"));
    }
    let _ = parse_local_lan_address(&value.address)?;
    Ok(())
}

fn parse_local_lan_address(bytes: &[u8]) -> Result<IpAddr, HelperProtocolError> {
    let address = match bytes {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| HelperProtocolError::Invalid("LAN address"))?,
        )),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| HelperProtocolError::Invalid("LAN address"))?,
        )),
        _ => return Err(HelperProtocolError::Invalid("LAN address")),
    };
    if !is_local_lan_ip(address) {
        return Err(HelperProtocolError::Invalid("LAN address"));
    }
    Ok(address)
}

fn parse_public_address(bytes: &[u8]) -> Result<IpAddr, HelperProtocolError> {
    let address = match bytes {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| HelperProtocolError::Invalid("IPv4"))?,
        )),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| HelperProtocolError::Invalid("IPv6"))?,
        )),
        _ => return Err(HelperProtocolError::Invalid("IP address")),
    };
    let safe = is_public_routable_ip(address);
    if !safe {
        return Err(HelperProtocolError::Invalid("public IP address"));
    }
    Ok(address)
}

fn validate_transport_tuple(
    descriptor_kind: i32,
    local: Option<&TransportSocketAddress>,
    remote: Option<&TransportSocketAddress>,
) -> Result<(), HelperProtocolError> {
    let kind = TransportSocketKind::try_from(descriptor_kind)
        .map_err(|_| HelperProtocolError::Invalid("transport socket kind"))?;
    if kind == TransportSocketKind::Unspecified {
        return Err(HelperProtocolError::Invalid("transport socket kind"));
    }
    let local =
        transport_address(local.ok_or(HelperProtocolError::Invalid("transport local address"))?)?;
    match kind {
        TransportSocketKind::MptcpConnected | TransportSocketKind::NativeProbeUdpConnected => {
            let remote = transport_address(
                remote.ok_or(HelperProtocolError::Invalid("transport remote address"))?,
            )?;
            if std::mem::discriminant(&local) != std::mem::discriminant(&remote) || local == remote
            {
                return Err(HelperProtocolError::Invalid("transport address pair"));
            }
            Ok(())
        }
        TransportSocketKind::MptcpListener | TransportSocketKind::QuicUdpUnconnected => {
            if remote.is_some() {
                return Err(HelperProtocolError::Invalid("unexpected transport peer"));
            }
            Ok(())
        }
        TransportSocketKind::Unspecified => {
            Err(HelperProtocolError::Invalid("transport socket kind"))
        }
    }
}

fn transport_address(value: &TransportSocketAddress) -> Result<IpAddr, HelperProtocolError> {
    if !(1..=65_535).contains(&value.port) {
        return Err(HelperProtocolError::Invalid("transport port"));
    }
    let address = match value.address.as_slice() {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes)
                .map_err(|_| HelperProtocolError::Invalid("transport IPv4"))?,
        )),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes)
                .map_err(|_| HelperProtocolError::Invalid("transport IPv6"))?,
        )),
        _ => return Err(HelperProtocolError::Invalid("transport IP address")),
    };
    if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
        return Err(HelperProtocolError::Invalid("transport IP address"));
    }
    if matches!(address, IpAddr::V4(value) if value == Ipv4Addr::BROADCAST)
        || matches!(address, IpAddr::V6(value) if value.is_unicast_link_local())
    {
        return Err(HelperProtocolError::Invalid("transport IP address"));
    }
    Ok(address)
}

fn distinct_paths(values: &[LeasePlan]) -> usize {
    values
        .iter()
        .map(|lease| lease.path_id)
        .collect::<BTreeSet<_>>()
        .len()
}

fn bounded(bytes: &[u8]) -> Result<(), HelperProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_HELPER_FRAME {
        return Err(HelperProtocolError::TooLarge);
    }
    Ok(())
}

fn encode_frame<M: Message>(value: &M) -> Result<Vec<u8>, HelperProtocolError> {
    let payload = Zeroizing::new(value.encode_to_vec());
    bounded(&payload)?;
    let length = u32::try_from(payload.len()).map_err(|_| HelperProtocolError::TooLarge)?;
    let mut output = Vec::with_capacity(4 + payload.len());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

fn decode<M: Message + Default>(
    bytes: &[u8],
    validate: fn(&M) -> Result<(), HelperProtocolError>,
) -> Result<M, HelperProtocolError> {
    bounded(bytes)?;
    let value = M::decode(bytes)?;
    validate(&value)?;
    let canonical = Zeroizing::new(value.encode_to_vec());
    if canonical.as_slice() != bytes {
        return Err(HelperProtocolError::Invalid("non-canonical protobuf"));
    }
    Ok(value)
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, HelperProtocolError> {
    let length =
        usize::try_from(reader.read_u32().await?).map_err(|_| HelperProtocolError::TooLarge)?;
    if length == 0 || length > MAX_HELPER_FRAME {
        return Err(HelperProtocolError::TooLarge);
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(payload.as_mut_slice()).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Message)]
    struct LegacyLeaseActivation {
        #[prost(bytes = "vec", tag = "1")]
        lease_handle: Vec<u8>,
        #[prost(uint32, tag = "2")]
        path_id: u32,
        #[prost(enumeration = "WireguardRole", tag = "3")]
        role: i32,
        #[prost(bytes = "vec", tag = "4")]
        peer_public_key: Vec<u8>,
        #[prost(message, optional, tag = "5")]
        peer_endpoint: Option<PublicUdpEndpoint>,
        #[prost(uint32, tag = "6")]
        maximum_up_mbps: u32,
        #[prost(uint32, tag = "7")]
        maximum_down_mbps: u32,
    }

    fn prepare(role: ContextRole, leases: Vec<LeasePlan>) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![9; 16],
            operation: Some(helper_request::Operation::PrepareLeaseBatch(
                PrepareLeaseBatch {
                    route_context_id: vec![7; 16],
                    role: role as i32,
                    mptcp_accepted_addrs: 4,
                    mptcp_subflows: 4,
                    leases,
                    setup_expires_at_unix: 120,
                    hard_expires_at_unix: 900,
                    traversal_hints: Vec::new(),
                },
            )),
        }
    }

    fn plan(path_id: u32, role: WireguardRole) -> LeasePlan {
        LeasePlan {
            path_id,
            role: role as i32,
        }
    }

    fn transport_address(address: [u8; 4], port: u32) -> TransportSocketAddress {
        TransportSocketAddress {
            address: address.to_vec(),
            port,
        }
    }

    fn acquire(kind: TransportSocketKind) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![6; 16],
            operation: Some(helper_request::Operation::AcquireTransportSocket(
                AcquireTransportSocket {
                    route_context_id: vec![7; 16],
                    context_handle: vec![8; 32],
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    descriptor_kind: kind as i32,
                    expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
                    expected_remote: (kind == TransportSocketKind::MptcpConnected)
                        .then(|| transport_address([10, 77, 0, 3], 443)),
                },
            )),
        }
    }

    fn activation_lease(path_id: u32, signed_relay_reservation: Vec<u8>) -> LeaseActivation {
        LeaseActivation {
            lease_handle: vec![u8::try_from(path_id).expect("test path"); HELPER_HANDLE_BYTES],
            path_id,
            role: WireguardRole::Client as i32,
            peer_public_key: vec![
                u8::try_from(path_id.checked_add(16).expect("test path"))
                    .expect("test path");
                32
            ],
            peer_endpoint: Some(PublicUdpEndpoint {
                address: vec![8, 8, 8, 8],
                port: 51_820 + path_id,
            }),
            maximum_up_mbps: 0,
            maximum_down_mbps: 0,
            signed_relay_reservation,
            signed_client_relay_request: Vec::new(),
        }
    }

    fn relay_client_activation(
        path_id: u32,
        signed_client_relay_request: Vec<u8>,
    ) -> LeaseActivation {
        let mut lease = activation_lease(path_id, vec![0xa5]);
        lease.role = WireguardRole::RelayClient as i32;
        lease.maximum_up_mbps = 1;
        lease.maximum_down_mbps = 1;
        lease.signed_client_relay_request = signed_client_relay_request;
        lease
    }

    fn activate(leases: Vec<LeaseActivation>) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![21; 16],
            operation: Some(helper_request::Operation::ActivateLeaseBatch(
                ActivateLeaseBatch {
                    route_context_id: vec![7; 16],
                    context_handle: vec![8; HELPER_HANDLE_BYTES],
                    leases,
                },
            )),
        }
    }

    #[test]
    fn cleanup_owner_preserves_prost_clone_move_and_canonical_wire() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        requires_zeroize_on_drop::<CleanupOwned>();
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![0x31; 16],
            operation: Some(helper_request::Operation::CleanupOwned(CleanupOwned {
                cleanup_token: vec![0xa5; 32],
                scope: CleanupScope::AllOwnedResources as i32,
            })),
        };
        let canonical = Zeroizing::new(request.encode_to_vec());
        let expected_digest = *blake3::hash(canonical.as_slice()).as_bytes();
        assert_eq!(operation_digest(&request).expect("digest"), expected_digest);

        let frame = Zeroizing::new(encode_request(&request).expect("framed request"));
        assert_eq!(&frame[4..], canonical.as_slice());
        let mut decoded = decode_request(canonical.as_slice()).expect("canonical cleanup request");
        assert_eq!(decoded, request.clone());

        let moved = decoded.operation.take().expect("cleanup operation");
        let cloned = moved.clone();
        let helper_request::Operation::CleanupOwned(mut cleanup) = moved else {
            panic!("cleanup operation");
        };
        assert_eq!(cleanup.cleanup_token, [0xa5; 32]);
        assert_eq!(
            cloned,
            helper_request::Operation::CleanupOwned(cleanup.clone())
        );
        cleanup.zeroize();
        assert!(cleanup.cleanup_token.iter().all(|byte| *byte == 0));
    }

    fn transport_response(request: &HelperRequest) -> HelperResponse {
        let Some(helper_request::Operation::AcquireTransportSocket(value)) =
            request.operation.as_ref()
        else {
            panic!("acquire operation");
        };
        HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TRANSPORT_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: value.path_id,
                    role: value.role,
                    descriptor_kind: value.descriptor_kind,
                    local: value.expected_local.clone(),
                    remote: value.expected_remote.clone(),
                },
            )),
        }
    }

    #[test]
    fn v3_is_exact_and_v1_v2_future_are_rejected() {
        let value = prepare(ContextRole::Client, vec![plan(1, WireguardRole::Client)]);
        assert!(encode_request(&value).is_ok());
        for version in [0, 1, 2, 4, u32::MAX] {
            let mut wrong = value.clone();
            wrong.protocol_version = version;
            assert!(encode_request(&wrong).is_err());
            assert!(decode_request(&wrong.encode_to_vec()).is_err());
        }
    }

    #[test]
    fn raw_retired_operation_tags_are_reserved_and_rejected() {
        // Former operation tags 10, 11, 12, 14 and 24 are deliberately absent from the oneof.
        // Their historical names and layouts remain recorded in docs/PROTOCOL.md.
        for version in [1_u8, 2, 3, 4] {
            for key in [
                vec![0x52],
                vec![0x5a],
                vec![0x62],
                vec![0x72],
                vec![0xc2, 0x01],
            ] {
                let mut raw = vec![0x08, version, 0x12, 0x10];
                raw.extend_from_slice(&[9; 16]);
                raw.extend_from_slice(&key);
                raw.push(0);
                assert!(decode_request(&raw).is_err());
            }
        }
    }

    #[test]
    fn role_cardinality_is_exact_for_every_path() {
        assert!(
            encode_request(&prepare(
                ContextRole::Client,
                vec![
                    plan(1, WireguardRole::Client),
                    plan(2, WireguardRole::Client)
                ]
            ))
            .is_ok()
        );
        assert!(
            encode_request(&prepare(
                ContextRole::Relay,
                vec![
                    plan(1, WireguardRole::RelayClient),
                    plan(1, WireguardRole::RelayExit),
                    plan(2, WireguardRole::RelayClient),
                    plan(2, WireguardRole::RelayExit),
                ]
            ))
            .is_ok()
        );
        assert!(
            encode_request(&prepare(
                ContextRole::Exit,
                vec![plan(1, WireguardRole::Exit)]
            ))
            .is_ok()
        );
        assert!(
            encode_request(&prepare(
                ContextRole::Relay,
                vec![plan(1, WireguardRole::RelayClient)]
            ))
            .is_err()
        );
        assert!(
            encode_request(&prepare(
                ContextRole::Client,
                vec![plan(1, WireguardRole::Exit)]
            ))
            .is_err()
        );
    }

    #[test]
    fn prepare_lease_batch_requires_canonical_identity_order() {
        let reversed_paths = prepare(
            ContextRole::Client,
            vec![
                plan(2, WireguardRole::Client),
                plan(1, WireguardRole::Client),
            ],
        );
        assert!(encode_request(&reversed_paths).is_err());
        assert!(decode_request(&reversed_paths.encode_to_vec()).is_err());

        let reversed_relay_roles = prepare(
            ContextRole::Relay,
            vec![
                plan(1, WireguardRole::RelayExit),
                plan(1, WireguardRole::RelayClient),
            ],
        );
        assert!(encode_request(&reversed_relay_roles).is_err());
        assert!(decode_request(&reversed_relay_roles.encode_to_vec()).is_err());

        let duplicate = prepare(
            ContextRole::Client,
            vec![
                plan(1, WireguardRole::Client),
                plan(1, WireguardRole::Client),
            ],
        );
        assert!(encode_request(&duplicate).is_err());
        assert!(decode_request(&duplicate.encode_to_vec()).is_err());
    }

    #[test]
    fn traversal_hints_are_exact_bounded_and_canonical() {
        let mut request = prepare(ContextRole::Client, vec![plan(1, WireguardRole::Client)]);
        let Some(helper_request::Operation::PrepareLeaseBatch(batch)) = request.operation.as_mut()
        else {
            panic!("prepare");
        };
        let ipv6 = TraversalEndpointHint {
            path_id: 1,
            role: WireguardRole::Client as i32,
            observer_id: vec![7; 32],
            observer_peer_id: vec![8; 38],
            on_link: None,
            observed_address: "2606:4700:4700::1111"
                .parse::<Ipv6Addr>()
                .expect("IPv6")
                .octets()
                .to_vec(),
        };
        let ipv4 = TraversalEndpointHint {
            observed_address: vec![8, 8, 8, 8],
            ..ipv6.clone()
        };
        batch.traversal_hints = vec![ipv6.clone(), ipv4.clone()];
        assert!(encode_request(&request).is_ok());

        let mut noncanonical = request.clone();
        let Some(helper_request::Operation::PrepareLeaseBatch(batch)) =
            noncanonical.operation.as_mut()
        else {
            panic!("prepare");
        };
        batch.traversal_hints.reverse();
        assert!(encode_request(&noncanonical).is_err());

        let mut duplicate_family = request.clone();
        let Some(helper_request::Operation::PrepareLeaseBatch(batch)) =
            duplicate_family.operation.as_mut()
        else {
            panic!("prepare");
        };
        batch.traversal_hints = vec![ipv4.clone(), ipv4.clone()];
        assert!(encode_request(&duplicate_family).is_err());

        let mut foreign_path = request.clone();
        let Some(helper_request::Operation::PrepareLeaseBatch(batch)) =
            foreign_path.operation.as_mut()
        else {
            panic!("prepare");
        };
        batch.traversal_hints[0].path_id = 2;
        assert!(encode_request(&foreign_path).is_err());

        let mut private = request;
        let Some(helper_request::Operation::PrepareLeaseBatch(batch)) = private.operation.as_mut()
        else {
            panic!("prepare");
        };
        batch.traversal_hints = vec![TraversalEndpointHint {
            observed_address: vec![192, 168, 1, 1],
            ..ipv4
        }];
        assert!(encode_request(&private).is_err());
    }

    #[test]
    fn on_link_hints_are_scoped_pairs_not_public_observations() {
        let leases = [plan(1, WireguardRole::Client)];
        let hint = TraversalEndpointHint {
            path_id: 1,
            role: WireguardRole::Client as i32,
            observer_id: vec![7; 32],
            observer_peer_id: vec![8; 38],
            observed_address: Vec::new(),
            on_link: Some(OnLinkUnderlayHint {
                local_address: vec![10, 42, 0, 2],
                peer_address: vec![10, 42, 0, 1],
            }),
        };
        validate_traversal_hints(&leases, std::slice::from_ref(&hint)).expect("scoped LAN hint");
        assert_eq!(
            TraversalEndpointHint::decode(hint.encode_to_vec().as_slice()).unwrap(),
            hint
        );
        let mut mixed = hint.clone();
        mixed.observed_address = vec![8, 8, 8, 8];
        assert!(validate_traversal_hints(&leases, &[mixed]).is_err());
        for peer in [
            vec![8, 8, 8, 8],
            vec![127, 0, 0, 1],
            vec![169, 254, 1, 2],
            vec![10, 42, 0, 2],
            vec![0; 16],
        ] {
            let mut substituted = hint.clone();
            substituted.on_link.as_mut().unwrap().peer_address = peer;
            assert!(validate_traversal_hints(&leases, &[substituted]).is_err());
        }
        assert!(validate_traversal_hints(&leases, &[hint.clone(), hint]).is_err());
        assert!(
            endpoint(&PublicUdpEndpoint {
                address: vec![10, 42, 0, 1],
                port: 51820
            })
            .is_err()
        );
    }

    #[test]
    fn external_wire_has_no_private_key_or_free_overlay_fields() {
        let value = prepare(ContextRole::Client, vec![plan(1, WireguardRole::Client)]);
        let encoded = encode_request(&value).expect("encode");
        assert_eq!(decode_request(&encoded[4..]).expect("decode"), value);
        let debug = format!("{value:?}");
        assert!(!debug.contains("private_key"));
        assert!(!debug.contains("allowed_prefix"));
        assert!(!debug.contains("listen_port"));
        assert!(!debug.contains("local_address"));
    }

    #[test]
    fn transport_operation_tag_and_socket_shapes_are_exact() {
        for kind in [
            TransportSocketKind::MptcpConnected,
            TransportSocketKind::MptcpListener,
            TransportSocketKind::QuicUdpUnconnected,
        ] {
            let request = acquire(kind);
            let encoded = request.encode_to_vec();
            assert!(encoded.windows(2).any(|window| window == [0xda, 0x01]));
            assert_eq!(
                decode_request(&encoded).expect("canonical acquire"),
                request
            );
            assert!(encode_request(&request).is_ok());
        }

        let mut missing_remote = acquire(TransportSocketKind::MptcpConnected);
        let Some(helper_request::Operation::AcquireTransportSocket(value)) =
            missing_remote.operation.as_mut()
        else {
            panic!("acquire");
        };
        value.expected_remote = None;
        assert!(encode_request(&missing_remote).is_err());

        let mut unexpected_remote = acquire(TransportSocketKind::MptcpListener);
        let Some(helper_request::Operation::AcquireTransportSocket(value)) =
            unexpected_remote.operation.as_mut()
        else {
            panic!("acquire");
        };
        value.expected_remote = Some(transport_address([10, 77, 0, 3], 443));
        assert!(encode_request(&unexpected_remote).is_err());

        let mut unknown_kind = acquire(TransportSocketKind::QuicUdpUnconnected);
        let Some(helper_request::Operation::AcquireTransportSocket(value)) =
            unknown_kind.operation.as_mut()
        else {
            panic!("acquire");
        };
        value.descriptor_kind = 99;
        assert!(decode_request(&unknown_kind.encode_to_vec()).is_err());

        let mut unknown_field = acquire(TransportSocketKind::MptcpListener).encode_to_vec();
        unknown_field.extend_from_slice(&[0xe2, 0x01, 0]);
        assert!(decode_request(&unknown_field).is_err());
    }

    #[test]
    fn descriptor_binding_commits_every_correlation_component() {
        let request = acquire(TransportSocketKind::MptcpConnected);
        let response = transport_response(&request);
        let binding = transport_fd_binding(&response).expect("binding");
        assert_eq!(binding.len(), 32);
        assert_eq!(
            transport_fd_binding(&response).expect("deterministic binding"),
            binding
        );

        let mut changed_request_id = response.clone();
        changed_request_id.request_id[0] ^= 1;
        assert_ne!(
            transport_fd_binding(&changed_request_id).expect("changed request binding"),
            binding
        );
        let mut changed_digest = response.clone();
        changed_digest.operation_digest[0] ^= 1;
        assert_ne!(
            transport_fd_binding(&changed_digest).expect("changed digest binding"),
            binding
        );
        let mut changed_outcome = response.clone();
        let Some(helper_response::Outcome::TransportSocketReady(ready)) =
            changed_outcome.outcome.as_mut()
        else {
            panic!("transport outcome");
        };
        ready.local.as_mut().expect("local").port += 1;
        assert_ne!(
            transport_fd_binding(&changed_outcome).expect("changed outcome binding"),
            binding
        );

        let mut no_transport = response;
        no_transport.outcome = Some(helper_response::Outcome::Empty(Empty {}));
        assert!(transport_fd_binding(&no_transport).is_err());
    }

    #[test]
    fn success_requires_typed_outcome_and_failure_forbids_it() {
        let request = prepare(ContextRole::Client, vec![plan(1, WireguardRole::Client)]);
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "EMPTY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::Empty(Empty {})),
        };
        assert!(encode_response(&response).is_ok());
        let mut missing = response.clone();
        missing.outcome = None;
        assert!(encode_response(&missing).is_err());
        let mut failed = response;
        failed.result = HelperResult::Unavailable as i32;
        assert!(encode_response(&failed).is_err());
    }

    #[test]
    fn prepared_endpoint_requires_known_underlay_evidence_and_nonzero_port() {
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![8; 16],
            result: HelperResult::Ok as i32,
            diagnostic_code: "PREPARED".to_owned(),
            operation_digest: vec![3; 32],
            outcome: Some(helper_response::Outcome::PreparedLeaseBatch(
                PreparedLeaseBatch {
                    context_handle: vec![4; 32],
                    leases: vec![PreparedLease {
                        lease_handle: vec![5; 32],
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                        public_key: vec![6; 32],
                        public_endpoint: Some(PublicUdpEndpoint {
                            address: vec![8, 8, 8, 8],
                            port: 51_820,
                        }),
                        underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
                    }],
                },
            )),
        };
        assert!(encode_response(&response).is_ok());
        let mut punch = response.clone();
        let Some(helper_response::Outcome::PreparedLeaseBatch(batch)) = punch.outcome.as_mut()
        else {
            panic!("prepared");
        };
        batch.leases[0].underlay_evidence = UnderlayEvidence::ObservedUdpPunch as i32;
        assert!(encode_response(&punch).is_ok());
        let mut local = response.clone();
        let Some(helper_response::Outcome::PreparedLeaseBatch(batch)) = local.outcome.as_mut()
        else {
            panic!("prepared");
        };
        batch.leases[0].public_endpoint.as_mut().unwrap().address = vec![10, 42, 0, 2];
        assert!(encode_response(&local).is_err());
        let Some(helper_response::Outcome::PreparedLeaseBatch(batch)) = local.outcome.as_mut()
        else {
            panic!("prepared");
        };
        batch.leases[0].underlay_evidence = UnderlayEvidence::DirectOnLink as i32;
        assert!(encode_response(&local).is_ok());
        let mut wrong = response;
        let Some(helper_response::Outcome::PreparedLeaseBatch(batch)) = wrong.outcome.as_mut()
        else {
            panic!("prepared");
        };
        batch.leases[0]
            .public_endpoint
            .as_mut()
            .expect("endpoint")
            .port = 0;
        assert!(encode_response(&wrong).is_err());
    }

    #[test]
    fn endpoints_reject_special_purpose_addresses_without_rejecting_global_ipv6() {
        for address in [
            "0.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "240.0.0.1",
            "::ffff:8.8.8.8",
            "2001:20::1",
            "2001:db8::1",
            "2002:c000:0204::1",
            "2620:4f:8000::1",
            "3fff::1",
        ] {
            let address: IpAddr = address.parse().expect("address");
            let bytes = match address {
                IpAddr::V4(value) => value.octets().to_vec(),
                IpAddr::V6(value) => value.octets().to_vec(),
            };
            assert!(
                endpoint(&PublicUdpEndpoint {
                    address: bytes,
                    port: 51_820,
                })
                .is_err(),
                "{address} must fail closed"
            );
        }
        assert!(
            endpoint(&PublicUdpEndpoint {
                address: "2001:4860:4860::8888"
                    .parse::<Ipv6Addr>()
                    .expect("global IPv6")
                    .octets()
                    .to_vec(),
                port: 51_820,
            })
            .is_ok()
        );
    }

    fn ingress_identities() -> [(IngressSocketKind, IngressAddressFamily); 8] {
        [
            (
                IngressSocketKind::TransparentTcpListener,
                IngressAddressFamily::Ipv4,
            ),
            (
                IngressSocketKind::TransparentTcpListener,
                IngressAddressFamily::Ipv6,
            ),
            (
                IngressSocketKind::TransparentUdp,
                IngressAddressFamily::Ipv4,
            ),
            (
                IngressSocketKind::TransparentUdp,
                IngressAddressFamily::Ipv6,
            ),
            (
                IngressSocketKind::DnsTcpListener,
                IngressAddressFamily::Ipv4,
            ),
            (
                IngressSocketKind::DnsTcpListener,
                IngressAddressFamily::Ipv6,
            ),
            (IngressSocketKind::DnsUdp, IngressAddressFamily::Ipv4),
            (IngressSocketKind::DnsUdp, IngressAddressFamily::Ipv6),
        ]
    }

    fn ingress_local(family: IngressAddressFamily, port: u32) -> IngressSocketAddress {
        IngressSocketAddress {
            address: match family {
                IngressAddressFamily::Ipv4 => vec![0; 4],
                IngressAddressFamily::Ipv6 => vec![0; 16],
                IngressAddressFamily::Unspecified => Vec::new(),
            },
            port,
        }
    }

    fn ingress_receipts() -> Vec<IngressSocketReceipt> {
        ingress_identities()
            .into_iter()
            .enumerate()
            .map(|(index, (kind, family))| IngressSocketReceipt {
                socket_handle: vec![u8::try_from(index + 11).expect("bounded index"); 32],
                receipt_handle: vec![u8::try_from(index + 21).expect("bounded index"); 32],
                descriptor_kind: kind as i32,
                address_family: family as i32,
            })
            .collect()
    }

    fn ingress_request(id: u8, operation: helper_request::Operation) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![id; 16],
            operation: Some(operation),
        }
    }

    fn sharing_requests() -> [HelperRequest; 3] {
        use helper_request::Operation;
        [
            ingress_request(
                37,
                Operation::InstallUplinkSharing(InstallUplinkSharing {
                    sharing_runtime_id: vec![7; 16],
                    interface: "enp1s0".to_owned(),
                    total_upload_mbps: 100,
                    contribution_upload_ceiling_mbps: 60,
                }),
            ),
            ingress_request(
                38,
                Operation::InspectUplinkSharing(InspectUplinkSharing {
                    sharing_runtime_id: vec![7; 16],
                    sharing_handle: vec![8; 32],
                }),
            ),
            ingress_request(
                39,
                Operation::DestroyUplinkSharing(DestroyUplinkSharing {
                    sharing_runtime_id: vec![7; 16],
                    sharing_handle: vec![8; 32],
                }),
            ),
        ]
    }

    fn sharing_response(request: &HelperRequest) -> HelperResponse {
        use helper_request::Operation;
        use helper_response::Outcome;
        let outcome = match request.operation.as_ref().expect("operation") {
            Operation::InstallUplinkSharing(value) => {
                Outcome::InstalledUplinkSharing(InstalledUplinkSharing {
                    sharing_runtime_id: value.sharing_runtime_id.clone(),
                    sharing_handle: vec![8; 32],
                    egress_ifindex: 2,
                })
            }
            Operation::InspectUplinkSharing(value) => Outcome::SharingCounters(SharingCounters {
                sharing_runtime_id: value.sharing_runtime_id.clone(),
                sharing_handle: value.sharing_handle.clone(),
                total: Some(SharingQueueCounters::default()),
                owner: Some(SharingQueueCounters::default()),
                contribution: Some(SharingQueueCounters::default()),
            }),
            Operation::DestroyUplinkSharing(_) => {
                Outcome::DestroyedSharing(DestroyedSharing { existed: true })
            }
            _ => panic!("sharing operation required"),
        };
        HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "SHARING_OK".to_owned(),
            operation_digest: operation_digest(request).expect("digest").to_vec(),
            outcome: Some(outcome),
        }
    }

    #[test]
    fn uplink_sharing_exact_tags_round_trip_and_safe_preview() {
        for (request, tag, preview) in [
            (sharing_requests()[0].clone(), [0xaa, 0x02], "install"),
            (sharing_requests()[1].clone(), [0xb2, 0x02], "inspect"),
            (sharing_requests()[2].clone(), [0xba, 0x02], "destroy"),
        ] {
            let framed = encode_request(&request).expect("request");
            assert_eq!(&framed[24..26], &tag);
            assert_eq!(decode_request(&framed[4..]).expect("canonical"), request);
            let response = sharing_response(&request);
            let framed = encode_response(&response).expect("response");
            assert!(framed[4..].windows(2).any(|bytes| bytes == tag));
            assert_eq!(decode_response(&framed[4..]).expect("canonical"), response);
            validate_uplink_sharing_response(&request, &response).expect("exact correlation");
            assert!(descriptor_fd_binding(&response).is_err());
            let safe = safe_preview(&request).expect("preview");
            assert!(safe.starts_with(&format!(
                "{preview} one owned upload-sharing runtime; audit_digest="
            )));
            assert!(!safe.contains("enp1s0"));
        }
        let counters = SharingQueueCounters {
            bytes: 1,
            packets: 2,
            drops: 3,
            overlimits: 4,
            backlog_bytes: 5,
        };
        assert_eq!(counters.encode_to_vec(), [8, 1, 16, 2, 24, 3, 32, 4, 40, 5]);
        let destroyed = DestroyedSharing { existed: true };
        assert_eq!(destroyed.encode_to_vec(), [8, 1]);
        let mut expected_owner = vec![10, 16];
        expected_owner.extend_from_slice(&[7; 16]);
        expected_owner.extend_from_slice(&[18, 32]);
        expected_owner.extend_from_slice(&[8; 32]);
        let inspect = InspectUplinkSharing {
            sharing_runtime_id: vec![7; 16],
            sharing_handle: vec![8; 32],
        };
        assert_eq!(inspect.encode_to_vec(), expected_owner);
        let installed = InstalledUplinkSharing {
            sharing_runtime_id: vec![7; 16],
            sharing_handle: vec![8; 32],
            egress_ifindex: 2,
        };
        expected_owner.extend_from_slice(&[24, 2]);
        assert_eq!(installed.encode_to_vec(), expected_owner);
    }

    #[test]
    fn uplink_sharing_message_field_tags_are_exact() {
        let install = InstallUplinkSharing {
            sharing_runtime_id: vec![7; 16],
            interface: "eth0".to_owned(),
            total_upload_mbps: 100,
            contribution_upload_ceiling_mbps: 60,
        };
        let mut expected = vec![10, 16];
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&[18, 4]);
        expected.extend_from_slice(b"eth0");
        expected.extend_from_slice(&[24, 100, 32, 60]);
        assert_eq!(install.encode_to_vec(), expected);
        let destroy = DestroyUplinkSharing {
            sharing_runtime_id: vec![7; 16],
            sharing_handle: vec![8; 32],
        };
        let mut expected = vec![10, 16];
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&[18, 32]);
        expected.extend_from_slice(&[8; 32]);
        assert_eq!(destroy.encode_to_vec(), expected);
        let counters = SharingCounters {
            sharing_runtime_id: vec![7; 16],
            sharing_handle: vec![8; 32],
            total: Some(SharingQueueCounters::default()),
            owner: Some(SharingQueueCounters::default()),
            contribution: Some(SharingQueueCounters::default()),
        };
        expected.extend_from_slice(&[26, 0, 34, 0, 42, 0]);
        assert_eq!(counters.encode_to_vec(), expected);
    }

    #[test]
    fn uplink_sharing_rejects_invalid_names_rates_and_owner_widths() {
        let Some(helper_request::Operation::InstallUplinkSharing(base)) =
            sharing_requests()[0].operation.clone()
        else {
            panic!("install");
        };
        for name in [
            "",
            ".",
            "..",
            "/sys/class/net",
            "eth0/../x",
            "eth 0",
            "eth:0",
            "éth0",
            "abcdefghijklmnop",
        ] {
            let mut value = base.clone();
            value.interface = name.to_owned();
            assert!(
                encode_request(&ingress_request(
                    37,
                    helper_request::Operation::InstallUplinkSharing(value)
                ))
                .is_err()
            );
        }
        for (total, ceiling) in [
            (0, 0),
            (0, 1),
            (1, 0),
            (1, 2),
            (MAX_HELPER_RATE_MBPS + 1, 1),
        ] {
            let mut value = base.clone();
            value.total_upload_mbps = total;
            value.contribution_upload_ceiling_mbps = ceiling;
            assert!(
                encode_request(&ingress_request(
                    37,
                    helper_request::Operation::InstallUplinkSharing(value)
                ))
                .is_err()
            );
        }
        for invalid in [vec![], vec![0; 16], vec![1; 15], vec![1; 17]] {
            for mut request in sharing_requests() {
                match request.operation.as_mut().expect("operation") {
                    helper_request::Operation::InstallUplinkSharing(value) => {
                        value.sharing_runtime_id.clone_from(&invalid);
                    }
                    helper_request::Operation::InspectUplinkSharing(value) => {
                        value.sharing_runtime_id.clone_from(&invalid);
                    }
                    helper_request::Operation::DestroyUplinkSharing(value) => {
                        value.sharing_runtime_id.clone_from(&invalid);
                    }
                    _ => panic!("sharing"),
                }
                assert!(encode_request(&request).is_err());
            }
        }
        for invalid in [vec![], vec![0; 32], vec![1; 31], vec![1; 33]] {
            for mut request in sharing_requests().into_iter().skip(1) {
                match request.operation.as_mut().expect("operation") {
                    helper_request::Operation::InspectUplinkSharing(value) => {
                        value.sharing_handle.clone_from(&invalid);
                    }
                    helper_request::Operation::DestroyUplinkSharing(value) => {
                        value.sharing_handle.clone_from(&invalid);
                    }
                    _ => panic!("owned sharing"),
                }
                assert!(encode_request(&request).is_err());
            }
        }
    }

    #[test]
    fn uplink_sharing_rejects_substituted_response_correlation() {
        for request in sharing_requests() {
            let response = sharing_response(&request);
            let mut wrong = response.clone();
            wrong.request_id[0] ^= 1;
            assert!(validate_uplink_sharing_response(&request, &wrong).is_err());
            wrong = response.clone();
            wrong.operation_digest[0] ^= 1;
            assert!(validate_uplink_sharing_response(&request, &wrong).is_err());
            wrong = response.clone();
            wrong.outcome = Some(helper_response::Outcome::Empty(Empty {}));
            assert!(validate_uplink_sharing_response(&request, &wrong).is_err());
            wrong = response;
            wrong.result = HelperResult::Kernel as i32;
            assert!(validate_uplink_sharing_response(&request, &wrong).is_err());
            wrong.outcome = None;
            validate_uplink_sharing_response(&request, &wrong)
                .expect("correlated failure, not success");
        }
        for request in sharing_requests().into_iter().take(2) {
            let mut wrong = sharing_response(&request);
            match wrong.outcome.as_mut().expect("outcome") {
                helper_response::Outcome::InstalledUplinkSharing(value) => {
                    value.sharing_runtime_id[0] ^= 1;
                }
                helper_response::Outcome::SharingCounters(value) => value.sharing_handle[0] ^= 1,
                _ => panic!("owner"),
            }
            assert!(validate_uplink_sharing_response(&request, &wrong).is_err());
        }
    }

    #[test]
    fn uplink_sharing_counters_are_complete_unsigned_kernel_values() {
        let request = &sharing_requests()[1];
        let mut response = sharing_response(request);
        let Some(helper_response::Outcome::SharingCounters(value)) = response.outcome.as_mut()
        else {
            panic!("counters");
        };
        value.total = Some(SharingQueueCounters {
            bytes: u64::MAX,
            packets: u64::MAX,
            drops: u64::MAX,
            overlimits: u64::MAX,
            backlog_bytes: u64::MAX,
        });
        let frame = encode_response(&response).expect("full-width raw counters");
        assert_eq!(
            decode_response(&frame[4..]).expect("counter round trip"),
            response
        );
        for missing in 0..3 {
            let mut wrong = response.clone();
            let Some(helper_response::Outcome::SharingCounters(value)) = wrong.outcome.as_mut()
            else {
                panic!("counters");
            };
            match missing {
                0 => value.total = None,
                1 => value.owner = None,
                _ => value.contribution = None,
            }
            assert!(encode_response(&wrong).is_err());
        }
        let mut installed = sharing_response(&sharing_requests()[0]);
        let Some(helper_response::Outcome::InstalledUplinkSharing(value)) =
            installed.outcome.as_mut()
        else {
            panic!("installed");
        };
        value.egress_ifindex = 0;
        assert!(encode_response(&installed).is_err());
    }

    #[test]
    fn uplink_sharing_rejects_unknown_duplicate_and_noncanonical_wire() {
        for request in sharing_requests() {
            let bytes = request.encode_to_vec();
            let mut unknown = bytes.clone();
            unknown.extend_from_slice(&[0xc2, 0x02, 0]); // Unassigned tag40.
            assert!(decode_request(&unknown).is_err());
            let mut duplicate = bytes.clone();
            duplicate.extend_from_slice(&bytes[20..]);
            assert!(decode_request(&duplicate).is_err());
            let response = sharing_response(&request);
            let mut unknown = response.encode_to_vec();
            unknown.extend_from_slice(&[0xc2, 0x02, 0]);
            assert!(decode_response(&unknown).is_err());
        }
        let request = &sharing_requests()[0];
        let mut changed = request.clone();
        let Some(helper_request::Operation::InstallUplinkSharing(value)) =
            changed.operation.as_mut()
        else {
            panic!("install");
        };
        value.total_upload_mbps += 1;
        assert_ne!(
            operation_digest(request).expect("digest"),
            operation_digest(&changed).expect("changed digest")
        );
    }

    #[test]
    fn client_ingress_tags_are_exact_and_retired_tag_24_is_never_valid() {
        let prepare = ingress_request(
            31,
            helper_request::Operation::PrepareClientIngress(PrepareClientIngress {
                client_runtime_id: vec![7; 16],
                setup_expires_at_unix: 120,
                hard_expires_at_unix: 900,
            }),
        );
        let acquire = ingress_request(
            32,
            helper_request::Operation::AcquireIngressSocket(AcquireIngressSocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                socket_handle: vec![9; 32],
                descriptor_kind: IngressSocketKind::TransparentUdp as i32,
                address_family: IngressAddressFamily::Ipv4 as i32,
            }),
        );
        let activate = ingress_request(
            33,
            helper_request::Operation::ActivateClientIngress(ActivateClientIngress {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                receipts: ingress_receipts(),
            }),
        );
        let destroy = ingress_request(
            34,
            helper_request::Operation::DestroyClientIngress(DestroyClientIngress {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
            }),
        );
        let reply = ingress_request(
            35,
            helper_request::Operation::AcquireIngressReplySocket(AcquireIngressReplySocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                remote: Some(IngressSocketAddress {
                    address: vec![8, 8, 8, 8],
                    port: 443,
                }),
                application: Some(IngressSocketAddress {
                    address: vec![192, 0, 2, 20],
                    port: 50_000,
                }),
            }),
        );
        for (request, tag) in [
            (prepare, [0xfa, 0x01]),
            (acquire, [0x82, 0x02]),
            (activate, [0x8a, 0x02]),
            (destroy, [0x92, 0x02]),
            (reply, [0xa2, 0x02]),
        ] {
            let bytes = request.encode_to_vec();
            assert!(bytes.windows(2).any(|window| window == tag));
            assert_eq!(decode_request(&bytes).expect("canonical ingress"), request);
            assert!(encode_request(&request).is_ok());
        }

        let mut retired = vec![0x08, 0x03, 0x12, 0x10];
        retired.extend_from_slice(&[24; 16]);
        retired.extend_from_slice(&[0xc2, 0x01, 0]);
        assert!(decode_request(&retired).is_err());
    }

    fn valid_prepare_intent() -> PrepareIntent {
        let request = prepare(ContextRole::Client, vec![plan(1, WireguardRole::Client)]);
        PrepareIntent {
            route_context_id: vec![7; 16],
            prepare_request_id: request.request_id.clone(),
            prepare_operation_digest: operation_digest(&request).expect("Prepare digest").to_vec(),
            setup_expires_at_unix: 120,
            hard_expires_at_unix: 900,
            closed_plan: Some(ClosedPreparePlan {
                context_role: ContextRole::Client as i32,
                leases: vec![plan(1, WireguardRole::Client)],
            }),
        }
    }

    fn bind_runtime_request(
        request_id_byte: u8,
        prepare_intent: Option<PrepareIntent>,
    ) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![request_id_byte; 16],
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime { prepare_intent },
            )),
        }
    }

    fn reconcile_scope(intent: &PrepareIntent) -> ReconcileExpiredPrepare {
        ReconcileExpiredPrepare {
            helper_runtime_id: vec![0xa5; 32],
            route_context_id: intent.route_context_id.clone(),
            prepare_request_id: intent.prepare_request_id.clone(),
            prepare_operation_digest: intent.prepare_operation_digest.clone(),
            setup_expires_at_unix: intent.setup_expires_at_unix,
            hard_expires_at_unix: intent.hard_expires_at_unix,
        }
    }

    fn reconcile_request(scope: ReconcileExpiredPrepare) -> HelperRequest {
        HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![28; 16],
            operation: Some(helper_request::Operation::ReconcileExpiredPrepare(scope)),
        }
    }

    fn reconciled_outcome(scope: &ReconcileExpiredPrepare) -> helper_response::Outcome {
        helper_response::Outcome::ReconciledExpiredPrepare(ReconciledExpiredPrepare {
            helper_runtime_id: scope.helper_runtime_id.clone(),
            route_context_id: scope.route_context_id.clone(),
            prepare_request_id: scope.prepare_request_id.clone(),
            prepare_operation_digest: scope.prepare_operation_digest.clone(),
            setup_expires_at_unix: scope.setup_expires_at_unix,
            hard_expires_at_unix: scope.hard_expires_at_unix,
        })
    }

    fn successful_response(
        request_id: Vec<u8>,
        diagnostic_code: &str,
        operation_digest: Vec<u8>,
        outcome: helper_response::Outcome,
    ) -> HelperResponse {
        HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id,
            result: HelperResult::Ok as i32,
            diagnostic_code: diagnostic_code.to_owned(),
            operation_digest,
            outcome: Some(outcome),
        }
    }

    fn length_delimited_field(key: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut field = Vec::with_capacity(key.len() + 2 + payload.len());
        field.extend_from_slice(key);
        prost::encoding::encode_varint(
            u64::try_from(payload.len()).expect("test payload length"),
            &mut field,
        );
        field.extend_from_slice(payload);
        field
    }

    fn raw_request_with_operation(
        request_id_byte: u8,
        operation_key: &[u8],
        operation_payload: &[u8],
    ) -> Vec<u8> {
        let mut wire = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![request_id_byte; 16],
            operation: None,
        }
        .encode_to_vec();
        wire.extend_from_slice(&length_delimited_field(operation_key, operation_payload));
        wire
    }

    fn raw_activate_request_with_lease(lease_payload: &[u8]) -> Vec<u8> {
        const ACTIVATE_OPERATION_KEY: [u8; 2] = [0xaa, 0x01];
        let mut operation_payload = ActivateLeaseBatch {
            route_context_id: vec![7; 16],
            context_handle: vec![8; HELPER_HANDLE_BYTES],
            leases: Vec::new(),
        }
        .encode_to_vec();
        operation_payload.extend_from_slice(&length_delimited_field(&[0x1a], lease_payload));
        raw_request_with_operation(21, &ACTIVATE_OPERATION_KEY, &operation_payload)
    }

    fn raw_response_with_outcome(
        response: &HelperResponse,
        outcome_key: &[u8],
        outcome_payload: &[u8],
    ) -> Vec<u8> {
        let mut envelope = response.clone();
        envelope.outcome = None;
        let mut wire = envelope.encode_to_vec();
        wire.extend_from_slice(&length_delimited_field(outcome_key, outcome_payload));
        wire
    }

    fn noncanonical_outer_wires(canonical: &[u8], oneof_field: &[u8]) -> [Vec<u8>; 3] {
        let mut unknown = canonical.to_vec();
        unknown.extend_from_slice(&[0x98, 0x06, 0x01]);

        let mut duplicate = canonical.to_vec();
        duplicate.extend_from_slice(oneof_field);

        assert_eq!(canonical.get(..2), Some([0x08, 0x03].as_slice()));
        let mut overlong_version = vec![0x08, 0x83, 0x00];
        overlong_version.extend_from_slice(&canonical[2..]);
        [unknown, duplicate, overlong_version]
    }

    fn assert_request_outer_wires_rejected(canonical: &[u8], oneof_field: &[u8]) {
        for wire in noncanonical_outer_wires(canonical, oneof_field) {
            assert!(decode_request(&wire).is_err());
        }
    }

    fn assert_response_outer_wires_rejected(canonical: &[u8], oneof_field: &[u8]) {
        for wire in noncanonical_outer_wires(canonical, oneof_field) {
            assert!(decode_response(&wire).is_err());
        }
    }

    fn assert_bind_intent_rejected(intent: &PrepareIntent) {
        let request = bind_runtime_request(35, Some(intent.clone()));
        assert!(encode_request(&request).is_err());
        assert!(decode_request(&request.encode_to_vec()).is_err());
    }

    fn assert_reconcile_scope_rejected(scope: &ReconcileExpiredPrepare) {
        let request = reconcile_request(scope.clone());
        assert!(encode_request(&request).is_err());
        assert!(decode_request(&request.encode_to_vec()).is_err());

        let response = successful_response(
            vec![28; 16],
            "EXPIRED_PREPARE_ABSENT",
            vec![0x44; 32],
            reconciled_outcome(scope),
        );
        assert!(encode_response(&response).is_err());
        assert!(decode_response(&response.encode_to_vec()).is_err());
    }

    #[test]
    fn signed_relay_reservation_default_preserves_the_legacy_wire() {
        let lease = activation_lease(1, Vec::new());
        let legacy = LegacyLeaseActivation {
            lease_handle: lease.lease_handle.clone(),
            path_id: lease.path_id,
            role: lease.role,
            peer_public_key: lease.peer_public_key.clone(),
            peer_endpoint: lease.peer_endpoint.clone(),
            maximum_up_mbps: lease.maximum_up_mbps,
            maximum_down_mbps: lease.maximum_down_mbps,
        };
        let legacy_wire = legacy.encode_to_vec();
        assert_eq!(lease.encode_to_vec(), legacy_wire);

        let decoded = LeaseActivation::decode(legacy_wire.as_slice()).expect("legacy lease wire");
        assert_eq!(decoded, lease);
        assert!(decoded.signed_relay_reservation.is_empty());
        assert!(decoded.signed_client_relay_request.is_empty());
        assert!(
            LeaseActivation::default()
                .signed_relay_reservation
                .is_empty()
        );
        assert!(
            LeaseActivation::default()
                .signed_client_relay_request
                .is_empty()
        );

        let request = activate(vec![lease]);
        let canonical = request.encode_to_vec();
        assert_eq!(
            decode_request(&canonical).expect("legacy-compatible Activate"),
            request
        );
    }

    #[test]
    fn signed_relay_reservation_round_trips_canonically_and_changes_the_digest() {
        let reservation = vec![0xa5, 0x5a, 0x01, 0x00];
        let lease = activation_lease(1, reservation.clone());
        let lease_wire = lease.encode_to_vec();
        assert!(lease_wire.ends_with(&[0x42, 0x04, 0xa5, 0x5a, 0x01, 0x00]));

        let request = activate(vec![lease]);
        let canonical = request.encode_to_vec();
        assert_eq!(
            decode_request(&canonical).expect("canonical Activate"),
            request
        );
        assert_eq!(
            request
                .operation
                .as_ref()
                .and_then(|operation| match operation {
                    helper_request::Operation::ActivateLeaseBatch(batch) => batch.leases.first(),
                    _ => None,
                })
                .expect("activation lease")
                .signed_relay_reservation,
            reservation
        );

        let without_reservation = activate(vec![activation_lease(1, Vec::new())]);
        assert_ne!(
            operation_digest(&request).expect("reservation-bound digest"),
            operation_digest(&without_reservation).expect("default digest")
        );
    }

    #[test]
    fn signed_relay_reservation_nested_wire_rejects_unknown_duplicate_and_noncanonical_default() {
        let canonical = activation_lease(1, vec![0xa5]).encode_to_vec();

        let mut unknown = canonical.clone();
        unknown.extend_from_slice(&[0x50, 0x01]);

        let mut duplicate = canonical.clone();
        duplicate.extend_from_slice(&length_delimited_field(&[0x42], &[0x5a]));

        let mut explicit_default = activation_lease(1, Vec::new()).encode_to_vec();
        explicit_default.extend_from_slice(&[0x42, 0x00]);

        let mut overlong_length = activation_lease(1, Vec::new()).encode_to_vec();
        overlong_length.extend_from_slice(&[0x42, 0x81, 0x00, 0xa5]);

        for lease_wire in [unknown, duplicate, explicit_default, overlong_length] {
            assert!(decode_request(&raw_activate_request_with_lease(&lease_wire)).is_err());
        }
    }

    #[test]
    fn signed_relay_reservation_item_and_aggregate_bounds_precede_frame_overhead() {
        assert_eq!(MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES, MAX_HELPER_FRAME);

        let exact_item = activate(vec![activation_lease(
            1,
            vec![0xa5; MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES],
        )]);
        assert!(validate_request(&exact_item).is_ok());
        assert!(matches!(
            encode_request(&exact_item),
            Err(HelperProtocolError::TooLarge)
        ));
        assert!(matches!(
            decode_request(&exact_item.encode_to_vec()),
            Err(HelperProtocolError::TooLarge)
        ));

        let oversized_item = activate(vec![activation_lease(
            1,
            vec![0xa5; MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES + 1],
        )]);
        assert!(matches!(
            validate_request(&oversized_item),
            Err(HelperProtocolError::Invalid(
                "signed relay reservation size"
            ))
        ));

        let half = MAX_HELPER_SIGNED_RELAY_RESERVATION_BYTES / 2;
        let exact_aggregate = activate(vec![
            activation_lease(1, vec![0xa5; half]),
            activation_lease(2, vec![0x5a; half]),
        ]);
        assert!(validate_request(&exact_aggregate).is_ok());
        assert!(matches!(
            encode_request(&exact_aggregate),
            Err(HelperProtocolError::TooLarge)
        ));

        let oversized_aggregate = activate(vec![
            activation_lease(1, vec![0xa5; half + 1]),
            activation_lease(2, vec![0x5a; half]),
        ]);
        assert!(matches!(
            validate_request(&oversized_aggregate),
            Err(HelperProtocolError::Invalid(
                "signed relay reservation aggregate size"
            ))
        ));
    }

    #[test]
    fn signed_client_activation_authority_is_role_scoped_and_binds_the_digest() {
        let signed_request = vec![0xa5, 0x5a, 0x01, 0x00];
        let lease = relay_client_activation(1, signed_request.clone());
        let lease_wire = lease.encode_to_vec();
        assert!(lease_wire.ends_with(&[0x4a, 0x04, 0xa5, 0x5a, 0x01, 0x00]));

        let request = activate(vec![lease]);
        let canonical = request.encode_to_vec();
        assert_eq!(
            decode_request(&canonical).expect("canonical RelayClient Activate"),
            request
        );
        assert_eq!(
            request
                .operation
                .as_ref()
                .and_then(|operation| match operation {
                    helper_request::Operation::ActivateLeaseBatch(batch) => batch.leases.first(),
                    _ => None,
                })
                .expect("RelayClient activation")
                .signed_client_relay_request,
            signed_request
        );

        let missing = activate(vec![relay_client_activation(1, Vec::new())]);
        assert!(matches!(
            validate_request(&missing),
            Err(HelperProtocolError::Invalid(
                "missing signed client activation authority"
            ))
        ));

        let mut native_exit = activation_lease(1, vec![0xa5]);
        native_exit.role = WireguardRole::Exit as i32;
        native_exit.signed_client_relay_request = vec![0x5a];
        assert!(validate_request(&activate(vec![native_exit])).is_ok());

        for role in [WireguardRole::Client, WireguardRole::RelayExit] {
            let mut cross_role = activation_lease(1, vec![0xa5]);
            cross_role.role = role as i32;
            cross_role.maximum_up_mbps = u32::from(role == WireguardRole::RelayExit);
            cross_role.maximum_down_mbps = u32::from(role == WireguardRole::RelayExit);
            cross_role.signed_client_relay_request = vec![0x5a];
            assert!(matches!(
                validate_request(&activate(vec![cross_role])),
                Err(HelperProtocolError::Invalid(
                    "signed client relay request role"
                ))
            ));
        }

        let without_request = activate(vec![relay_client_activation(1, vec![0x5a])]);
        assert_ne!(
            operation_digest(&request).expect("request-bound digest"),
            operation_digest(&without_request).expect("different request-bound digest")
        );
    }

    #[test]
    fn signed_client_relay_request_wire_rejects_unknown_duplicate_and_noncanonical_default() {
        let canonical = relay_client_activation(1, vec![0xa5]).encode_to_vec();

        let mut unknown = canonical.clone();
        unknown.extend_from_slice(&[0x50, 0x01]);

        let mut duplicate = canonical;
        duplicate.extend_from_slice(&length_delimited_field(&[0x4a], &[0x5a]));

        let mut explicit_default = activation_lease(1, Vec::new()).encode_to_vec();
        explicit_default.extend_from_slice(&[0x4a, 0x00]);

        let mut overlong_length = relay_client_activation(1, vec![0xa5]).encode_to_vec();
        overlong_length.truncate(overlong_length.len() - 3);
        overlong_length.extend_from_slice(&[0x4a, 0x81, 0x00, 0xa5]);

        for lease_wire in [unknown, duplicate, explicit_default, overlong_length] {
            assert!(decode_request(&raw_activate_request_with_lease(&lease_wire)).is_err());
        }
    }

    #[test]
    fn signed_client_relay_request_item_and_aggregate_bounds_precede_frame_overhead() {
        assert_eq!(
            MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES,
            MAX_HELPER_FRAME
        );

        let exact_item = activate(vec![relay_client_activation(
            1,
            vec![0xa5; MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES],
        )]);
        assert!(validate_request(&exact_item).is_ok());
        assert!(matches!(
            encode_request(&exact_item),
            Err(HelperProtocolError::TooLarge)
        ));
        assert!(matches!(
            decode_request(&exact_item.encode_to_vec()),
            Err(HelperProtocolError::TooLarge)
        ));

        let oversized_item = activate(vec![relay_client_activation(
            1,
            vec![0xa5; MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES + 1],
        )]);
        assert!(matches!(
            validate_request(&oversized_item),
            Err(HelperProtocolError::Invalid(
                "signed client relay request size"
            ))
        ));

        let half = MAX_HELPER_SIGNED_CLIENT_RELAY_REQUEST_BYTES / 2;
        let exact_aggregate = activate(vec![
            relay_client_activation(1, vec![0xa5; half]),
            relay_client_activation(2, vec![0x5a; half]),
        ]);
        assert!(validate_request(&exact_aggregate).is_ok());
        assert!(matches!(
            encode_request(&exact_aggregate),
            Err(HelperProtocolError::TooLarge)
        ));

        let oversized_aggregate = activate(vec![
            relay_client_activation(1, vec![0xa5; half + 1]),
            relay_client_activation(2, vec![0x5a; half]),
        ]);
        assert!(matches!(
            validate_request(&oversized_aggregate),
            Err(HelperProtocolError::Invalid(
                "signed client relay request aggregate size"
            ))
        ));
    }

    #[test]
    fn runtime_bind_tags_are_exact_for_intent_and_query() {
        let intent = valid_prepare_intent();
        let closed_plan = intent.closed_plan.as_ref().expect("closed Prepare plan");
        let closed_plan_wire = closed_plan.encode_to_vec();
        assert_eq!(closed_plan_wire.get(..2), Some([0x08, 0x01].as_slice()));
        assert!(
            closed_plan_wire
                .windows(2)
                .any(|window| window == [0x12, 0x04])
        );
        let intent_wire = intent.encode_to_vec();
        let closed_plan_field = length_delimited_field(&[0x32], &closed_plan_wire);
        assert!(intent_wire.ends_with(&closed_plan_field));

        let bind = bind_runtime_request(35, Some(intent));
        let bind_bytes = bind.encode_to_vec();
        assert!(bind_bytes.windows(2).any(|window| window == [0x9a, 0x02]));
        assert_eq!(decode_request(&bind_bytes).expect("canonical Bind"), bind);

        let query = bind_runtime_request(36, None);
        assert_eq!(
            decode_request(&query.encode_to_vec()).expect("canonical query"),
            query
        );
    }

    #[test]
    fn closed_prepare_plan_is_required_canonical_and_role_complete() {
        let valid = valid_prepare_intent();

        let mut missing = valid.clone();
        missing.closed_plan = None;
        assert_bind_intent_rejected(&missing);

        let mut reversed = valid.clone();
        reversed.closed_plan = Some(ClosedPreparePlan {
            context_role: ContextRole::Client as i32,
            leases: vec![
                plan(2, WireguardRole::Client),
                plan(1, WireguardRole::Client),
            ],
        });
        assert_bind_intent_rejected(&reversed);

        let mut duplicate = valid.clone();
        duplicate.closed_plan = Some(ClosedPreparePlan {
            context_role: ContextRole::Client as i32,
            leases: vec![
                plan(1, WireguardRole::Client),
                plan(1, WireguardRole::Client),
            ],
        });
        assert_bind_intent_rejected(&duplicate);

        let mut cross_role = valid.clone();
        cross_role.closed_plan = Some(ClosedPreparePlan {
            context_role: ContextRole::Client as i32,
            leases: vec![plan(1, WireguardRole::Exit)],
        });
        assert_bind_intent_rejected(&cross_role);

        let mut incomplete = valid;
        incomplete.closed_plan = Some(ClosedPreparePlan {
            context_role: ContextRole::Relay as i32,
            leases: vec![plan(1, WireguardRole::RelayClient)],
        });
        assert_bind_intent_rejected(&incomplete);
    }

    #[test]
    fn bind_operation_digest_commits_every_closed_prepare_plan_identity() {
        let original = bind_runtime_request(35, Some(valid_prepare_intent()));
        let original_digest = operation_digest(&original).expect("original Bind digest");

        let mut expanded = original.clone();
        let Some(helper_request::Operation::BindHelperRuntime(bind)) = expanded.operation.as_mut()
        else {
            panic!("Bind");
        };
        bind.prepare_intent
            .as_mut()
            .expect("Prepare intent")
            .closed_plan
            .as_mut()
            .expect("closed Prepare plan")
            .leases
            .push(plan(2, WireguardRole::Client));
        let expanded_digest = operation_digest(&expanded).expect("expanded Bind digest");
        assert_ne!(expanded_digest, original_digest);

        let mut changed_role = original;
        let Some(helper_request::Operation::BindHelperRuntime(bind)) =
            changed_role.operation.as_mut()
        else {
            panic!("Bind");
        };
        let closed_plan = bind
            .prepare_intent
            .as_mut()
            .expect("Prepare intent")
            .closed_plan
            .as_mut()
            .expect("closed Prepare plan");
        closed_plan.context_role = ContextRole::Exit as i32;
        closed_plan.leases[0].role = WireguardRole::Exit as i32;
        assert_ne!(
            operation_digest(&changed_role).expect("changed-role Bind digest"),
            original_digest
        );
    }

    #[test]
    fn reconciliation_tag_and_exact_echo_are_canonical() {
        let reconcile_value = reconcile_scope(&valid_prepare_intent());
        let reconcile = reconcile_request(reconcile_value.clone());
        let reconcile_bytes = reconcile.encode_to_vec();
        assert!(
            reconcile_bytes
                .windows(2)
                .any(|window| window == [0xe2, 0x01])
        );
        assert_eq!(
            decode_request(&reconcile_bytes).expect("canonical reconciliation"),
            reconcile
        );

        let response = successful_response(
            reconcile.request_id.clone(),
            "EXPIRED_PREPARE_ABSENT",
            operation_digest(&reconcile)
                .expect("reconciliation digest")
                .to_vec(),
            reconciled_outcome(&reconcile_value),
        );
        let response_bytes = response.encode_to_vec();
        assert!(
            response_bytes
                .windows(2)
                .any(|window| window == [0xe2, 0x01])
        );
        assert_eq!(
            decode_response(&response_bytes).expect("canonical exact echo"),
            response
        );
    }

    #[test]
    fn bind_and_prepare_request_ids_must_differ() {
        let mut colliding = bind_runtime_request(35, Some(valid_prepare_intent()));
        let Some(helper_request::Operation::BindHelperRuntime(value)) =
            colliding.operation.as_mut()
        else {
            panic!("Bind");
        };
        colliding.request_id = value
            .prepare_intent
            .as_ref()
            .expect("intent")
            .prepare_request_id
            .clone();
        assert!(encode_request(&colliding).is_err());
        assert!(decode_request(&colliding.encode_to_vec()).is_err());
    }

    #[test]
    fn runtime_bind_rejects_invalid_prepare_identity_matrix() {
        let valid = valid_prepare_intent();
        for route_context_id in [Vec::new(), vec![0; 16], vec![7; 15], vec![7; 17]] {
            let mut invalid = valid.clone();
            invalid.route_context_id = route_context_id;
            assert_bind_intent_rejected(&invalid);
        }
        for prepare_request_id in [Vec::new(), vec![0; 16], vec![9; 15], vec![9; 17]] {
            let mut invalid = valid.clone();
            invalid.prepare_request_id = prepare_request_id;
            assert_bind_intent_rejected(&invalid);
        }
        for prepare_operation_digest in [Vec::new(), vec![0x55; 31], vec![0x55; 33]] {
            let mut invalid = valid.clone();
            invalid.prepare_operation_digest = prepare_operation_digest;
            assert_bind_intent_rejected(&invalid);
        }

        let mut zero_setup = valid.clone();
        zero_setup.setup_expires_at_unix = 0;
        assert_bind_intent_rejected(&zero_setup);
        let mut reversed_expiry = valid;
        reversed_expiry.hard_expires_at_unix = reversed_expiry.setup_expires_at_unix - 1;
        assert_bind_intent_rejected(&reversed_expiry);
    }

    #[test]
    fn helper_runtime_outcome_rejects_zero_or_wrong_widths() {
        for helper_runtime_id in [Vec::new(), vec![0; 32], vec![0xa5; 31], vec![0xa5; 33]] {
            let response = successful_response(
                vec![36; 16],
                "HELPER_RUNTIME",
                vec![0x44; 32],
                helper_response::Outcome::HelperRuntime(HelperRuntime { helper_runtime_id }),
            );
            assert!(encode_response(&response).is_err());
            assert!(decode_response(&response.encode_to_vec()).is_err());
        }
    }

    #[test]
    fn reconciliation_request_and_outcome_reject_invalid_authority_matrix() {
        let valid = reconcile_scope(&valid_prepare_intent());
        for helper_runtime_id in [Vec::new(), vec![0; 32], vec![0xa5; 31], vec![0xa5; 33]] {
            let mut invalid = valid.clone();
            invalid.helper_runtime_id = helper_runtime_id;
            assert_reconcile_scope_rejected(&invalid);
        }
        for route_context_id in [Vec::new(), vec![0; 16], vec![7; 15], vec![7; 17]] {
            let mut invalid = valid.clone();
            invalid.route_context_id = route_context_id;
            assert_reconcile_scope_rejected(&invalid);
        }
        for prepare_request_id in [Vec::new(), vec![0; 16], vec![9; 15], vec![9; 17]] {
            let mut invalid = valid.clone();
            invalid.prepare_request_id = prepare_request_id;
            assert_reconcile_scope_rejected(&invalid);
        }
        for prepare_operation_digest in [Vec::new(), vec![0x55; 31], vec![0x55; 33]] {
            let mut invalid = valid.clone();
            invalid.prepare_operation_digest = prepare_operation_digest;
            assert_reconcile_scope_rejected(&invalid);
        }

        let mut zero_setup = valid.clone();
        zero_setup.setup_expires_at_unix = 0;
        assert_reconcile_scope_rejected(&zero_setup);
        let mut reversed_expiry = valid;
        reversed_expiry.hard_expires_at_unix = reversed_expiry.setup_expires_at_unix - 1;
        assert_reconcile_scope_rejected(&reversed_expiry);
    }

    #[test]
    fn runtime_bind_wire_matrix_rejects_noncanonical_fields() {
        const TAG_35: [u8; 2] = [0x9a, 0x02];
        let intent = valid_prepare_intent();
        let intent_wire = intent.encode_to_vec();
        let query_payload = BindHelperRuntime {
            prepare_intent: None,
        }
        .encode_to_vec();
        let bind_payload = BindHelperRuntime {
            prepare_intent: Some(intent.clone()),
        }
        .encode_to_vec();

        for (request_id_byte, payload, typed) in [
            (36, query_payload.as_slice(), bind_runtime_request(36, None)),
            (
                35,
                bind_payload.as_slice(),
                bind_runtime_request(35, Some(intent.clone())),
            ),
        ] {
            let canonical = raw_request_with_operation(request_id_byte, &TAG_35, payload);
            let operation_field = length_delimited_field(&TAG_35, payload);
            assert_eq!(canonical, typed.encode_to_vec());
            assert_request_outer_wires_rejected(&canonical, &operation_field);
        }

        let mut unknown_query = query_payload;
        unknown_query.extend_from_slice(&[0x10, 0x01]);
        let mut unknown_bind = bind_payload.clone();
        unknown_bind.extend_from_slice(&[0x10, 0x01]);
        let mut duplicate_bind = bind_payload;
        duplicate_bind.extend_from_slice(&length_delimited_field(&[0x0a], &intent_wire));
        let closed_plan_wire = intent
            .closed_plan
            .as_ref()
            .expect("closed Prepare plan")
            .encode_to_vec();
        let mut unknown_intent = intent_wire.clone();
        unknown_intent.extend_from_slice(&[0x38, 0x01]);
        let mut duplicate_closed_plan = intent_wire.clone();
        duplicate_closed_plan
            .extend_from_slice(&length_delimited_field(&[0x32], &closed_plan_wire));
        let mut duplicate_intent = intent_wire;
        duplicate_intent.extend_from_slice(&[0x20, 0x78]);
        let mut unknown_closed_plan = closed_plan_wire;
        unknown_closed_plan.extend_from_slice(&[0x18, 0x01]);
        let mut without_closed_plan = intent.clone();
        without_closed_plan.closed_plan = None;
        let mut nested_unknown_intent = without_closed_plan.encode_to_vec();
        nested_unknown_intent
            .extend_from_slice(&length_delimited_field(&[0x32], &unknown_closed_plan));
        let mut no_setup = intent;
        no_setup.setup_expires_at_unix = 0;
        let mut overlong_setup = no_setup.encode_to_vec();
        overlong_setup.extend_from_slice(&[0x20, 0xf8, 0x00]);

        for payload in [
            unknown_query,
            unknown_bind,
            duplicate_bind,
            length_delimited_field(&[0x0a], &unknown_intent),
            length_delimited_field(&[0x0a], &duplicate_intent),
            length_delimited_field(&[0x0a], &duplicate_closed_plan),
            length_delimited_field(&[0x0a], &nested_unknown_intent),
            length_delimited_field(&[0x0a], &overlong_setup),
        ] {
            let wire = raw_request_with_operation(35, &TAG_35, &payload);
            assert!(decode_request(&wire).is_err());
        }
    }

    #[test]
    fn helper_runtime_outcome_wire_matrix_rejects_noncanonical_fields() {
        const TAG_35: [u8; 2] = [0x9a, 0x02];
        let runtime = HelperRuntime {
            helper_runtime_id: vec![0xa5; 32],
        };
        let runtime_wire = runtime.encode_to_vec();
        let response = successful_response(
            vec![36; 16],
            "HELPER_RUNTIME",
            vec![0x44; 32],
            helper_response::Outcome::HelperRuntime(runtime.clone()),
        );
        let canonical = raw_response_with_outcome(&response, &TAG_35, &runtime_wire);
        let outcome_field = length_delimited_field(&TAG_35, &runtime_wire);
        assert_eq!(canonical, response.encode_to_vec());
        assert_response_outer_wires_rejected(&canonical, &outcome_field);

        let mut unknown = runtime_wire.clone();
        unknown.extend_from_slice(&[0x10, 0x01]);
        let mut duplicate = runtime_wire;
        duplicate.extend_from_slice(&length_delimited_field(&[0x0a], &runtime.helper_runtime_id));
        let mut overlong_length = vec![0x0a, 0xa0, 0x00];
        overlong_length.extend_from_slice(&runtime.helper_runtime_id);
        for payload in [unknown, duplicate, overlong_length] {
            let wire = raw_response_with_outcome(&response, &TAG_35, &payload);
            assert!(decode_response(&wire).is_err());
        }
    }

    #[test]
    fn reconciliation_wire_matrix_rejects_noncanonical_fields_and_tag_24() {
        const TAG_24: [u8; 2] = [0xc2, 0x01];
        const TAG_28: [u8; 2] = [0xe2, 0x01];
        let scope = reconcile_scope(&valid_prepare_intent());
        let scope_wire = scope.encode_to_vec();
        let request = reconcile_request(scope.clone());
        let request_wire = raw_request_with_operation(28, &TAG_28, &scope_wire);
        let request_field = length_delimited_field(&TAG_28, &scope_wire);
        assert_eq!(request_wire, request.encode_to_vec());
        assert_request_outer_wires_rejected(&request_wire, &request_field);

        let outcome = reconciled_outcome(&scope);
        let helper_response::Outcome::ReconciledExpiredPrepare(value) = &outcome else {
            panic!("reconciled outcome");
        };
        let outcome_wire = value.encode_to_vec();
        assert_eq!(outcome_wire, scope_wire);
        let response = successful_response(
            vec![28; 16],
            "EXPIRED_PREPARE_ABSENT",
            vec![0x44; 32],
            outcome,
        );
        let response_wire = raw_response_with_outcome(&response, &TAG_28, &outcome_wire);
        let outcome_field = length_delimited_field(&TAG_28, &outcome_wire);
        assert_eq!(response_wire, response.encode_to_vec());
        assert_response_outer_wires_rejected(&response_wire, &outcome_field);

        let mut unknown = scope_wire.clone();
        unknown.extend_from_slice(&[0x38, 0x01]);
        let mut duplicate = scope_wire;
        duplicate.extend_from_slice(&[0x28, 0x78]);
        let mut no_setup = scope;
        no_setup.setup_expires_at_unix = 0;
        let mut overlong_setup = no_setup.encode_to_vec();
        overlong_setup.extend_from_slice(&[0x28, 0xf8, 0x00]);
        for payload in [unknown, duplicate, overlong_setup] {
            assert!(decode_request(&raw_request_with_operation(28, &TAG_28, &payload)).is_err());
            assert!(
                decode_response(&raw_response_with_outcome(&response, &TAG_28, &payload)).is_err()
            );
        }

        let retired = raw_request_with_operation(24, &TAG_24, &[]);
        assert!(decode_request(&retired).is_err());
    }

    #[test]
    fn client_ingress_receipts_require_exact_complete_unique_bounded_set() {
        let valid = ingress_request(
            33,
            helper_request::Operation::ActivateClientIngress(ActivateClientIngress {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                receipts: ingress_receipts(),
            }),
        );
        assert!(encode_request(&valid).is_ok());

        let mut missing = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            missing.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts.pop();
        assert!(encode_request(&missing).is_err());

        let mut duplicate_identity = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            duplicate_identity.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts[7].descriptor_kind = value.receipts[0].descriptor_kind;
        value.receipts[7].address_family = value.receipts[0].address_family;
        assert!(encode_request(&duplicate_identity).is_err());

        let mut ingress_socket_collision = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            ingress_socket_collision.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts[0].socket_handle = value.ingress_handle.clone();
        assert!(encode_request(&ingress_socket_collision).is_err());

        let mut ingress_receipt_collision = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            ingress_receipt_collision.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts[0].receipt_handle = value.ingress_handle.clone();
        assert!(encode_request(&ingress_receipt_collision).is_err());

        let mut cross_category_collision = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            cross_category_collision.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts[0].receipt_handle = value.receipts[1].socket_handle.clone();
        assert!(encode_request(&cross_category_collision).is_err());

        let acquire_collision = ingress_request(
            32,
            helper_request::Operation::AcquireIngressSocket(AcquireIngressSocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                socket_handle: vec![8; 32],
                descriptor_kind: IngressSocketKind::TransparentUdp as i32,
                address_family: IngressAddressFamily::Ipv4 as i32,
            }),
        );
        assert!(encode_request(&acquire_collision).is_err());

        let mut duplicate_receipt = valid.clone();
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            duplicate_receipt.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts[7].receipt_handle = value.receipts[0].receipt_handle.clone();
        assert!(encode_request(&duplicate_receipt).is_err());

        let mut excessive = valid;
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            excessive.operation.as_mut()
        else {
            panic!("activation");
        };
        value.receipts.push(value.receipts[0].clone());
        assert!(encode_request(&excessive).is_err());
    }

    #[test]
    fn client_ingress_wire_rejects_unknown_duplicate_and_wrong_version_bytes() {
        let request = ingress_request(
            31,
            helper_request::Operation::PrepareClientIngress(PrepareClientIngress {
                client_runtime_id: vec![7; 16],
                setup_expires_at_unix: 120,
                hard_expires_at_unix: 900,
            }),
        );
        let canonical = request.encode_to_vec();
        assert_eq!(
            decode_request(&canonical).expect("canonical prepare"),
            request
        );

        let mut unknown = canonical.clone();
        unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(decode_request(&unknown).is_err());

        let mut duplicate_version = canonical;
        duplicate_version.extend_from_slice(&[0x08, 0x03]);
        assert!(decode_request(&duplicate_version).is_err());

        for version in [0, 1, 2, 4, u32::MAX] {
            let mut wrong = request.clone();
            wrong.protocol_version = version;
            assert!(decode_request(&wrong.encode_to_vec()).is_err());
        }
    }

    #[test]
    fn client_ingress_prepared_response_set_is_exact() {
        let prepared = PreparedClientIngress {
            client_runtime_id: vec![7; 16],
            ingress_handle: vec![8; 32],
            sockets: ingress_identities()
                .into_iter()
                .enumerate()
                .map(|(index, (kind, family))| PreparedIngressSocket {
                    socket_handle: vec![u8::try_from(index + 11).expect("bounded index"); 32],
                    descriptor_kind: kind as i32,
                    address_family: family as i32,
                    local: Some(ingress_local(
                        family,
                        42_000 + u32::try_from(index).expect("bounded index"),
                    )),
                })
                .collect(),
            hard_expires_at_unix: 900,
        };
        let prepare_request = ingress_request(
            31,
            helper_request::Operation::PrepareClientIngress(PrepareClientIngress {
                client_runtime_id: vec![7; 16],
                setup_expires_at_unix: 120,
                hard_expires_at_unix: 900,
            }),
        );
        let prepared_response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: prepare_request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_PREPARED".to_owned(),
            operation_digest: operation_digest(&prepare_request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::PreparedClientIngress(prepared)),
        };
        assert!(encode_response(&prepared_response).is_ok());
        let mut prepared_collision = prepared_response.clone();
        let Some(helper_response::Outcome::PreparedClientIngress(value)) =
            prepared_collision.outcome.as_mut()
        else {
            panic!("prepared ingress");
        };
        value.sockets[0].socket_handle = value.ingress_handle.clone();
        assert!(encode_response(&prepared_collision).is_err());
    }

    #[test]
    fn client_ingress_descriptor_binding_is_exact() {
        let acquire_request = ingress_request(
            32,
            helper_request::Operation::AcquireIngressSocket(AcquireIngressSocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                socket_handle: vec![9; 32],
                descriptor_kind: IngressSocketKind::TransparentUdp as i32,
                address_family: IngressAddressFamily::Ipv4 as i32,
            }),
        );
        let ready = IngressSocketReady {
            client_runtime_id: vec![7; 16],
            ingress_handle: vec![8; 32],
            socket_handle: vec![9; 32],
            receipt_handle: vec![10; 32],
            descriptor_kind: IngressSocketKind::TransparentUdp as i32,
            address_family: IngressAddressFamily::Ipv4 as i32,
            local: Some(ingress_local(IngressAddressFamily::Ipv4, 42_000)),
        };
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: acquire_request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&acquire_request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::IngressSocketReady(ready)),
        };
        let binding = ingress_fd_binding(&response).expect("ingress binding");
        assert_eq!(
            descriptor_fd_binding(&response).expect("generic binding"),
            binding
        );

        let mut ready_collision = response.clone();
        let Some(helper_response::Outcome::IngressSocketReady(value)) =
            ready_collision.outcome.as_mut()
        else {
            panic!("ready");
        };
        value.receipt_handle = value.socket_handle.clone();
        assert!(encode_response(&ready_collision).is_err());

        let mut changed_receipt = response.clone();
        let Some(helper_response::Outcome::IngressSocketReady(value)) =
            changed_receipt.outcome.as_mut()
        else {
            panic!("ready");
        };
        value.receipt_handle[0] ^= 1;
        assert_ne!(
            ingress_fd_binding(&changed_receipt).expect("changed receipt binding"),
            binding
        );

        let mut changed_family = response;
        let Some(helper_response::Outcome::IngressSocketReady(value)) =
            changed_family.outcome.as_mut()
        else {
            panic!("ready");
        };
        value.address_family = IngressAddressFamily::Ipv6 as i32;
        value.local = Some(ingress_local(IngressAddressFamily::Ipv6, 42_000));
        assert_ne!(
            ingress_fd_binding(&changed_family).expect("changed family binding"),
            binding
        );
    }

    #[test]
    fn ingress_reply_descriptor_binding_commits_exact_flow_tuple() {
        let remote = IngressSocketAddress {
            address: vec![8, 8, 8, 8],
            port: 443,
        };
        let application = IngressSocketAddress {
            address: vec![192, 0, 2, 20],
            port: 50_000,
        };
        let request = ingress_request(
            35,
            helper_request::Operation::AcquireIngressReplySocket(AcquireIngressReplySocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                remote: Some(remote.clone()),
                application: Some(application.clone()),
            }),
        );
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_REPLY_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::IngressReplySocketReady(
                IngressReplySocketReady {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    remote: Some(remote),
                    application: Some(application),
                },
            )),
        };
        let binding = ingress_reply_fd_binding(&response).expect("reply binding");
        assert_eq!(descriptor_fd_binding(&response).expect("generic"), binding);

        let mut changed = response;
        let Some(helper_response::Outcome::IngressReplySocketReady(ready)) =
            changed.outcome.as_mut()
        else {
            panic!("reply outcome");
        };
        ready.application.as_mut().expect("application").port += 1;
        assert_ne!(
            ingress_reply_fd_binding(&changed).expect("changed tuple"),
            binding
        );
    }

    #[test]
    fn ingress_reply_protocol_accepts_exact_ipv6_and_rejects_mixed_families() {
        let remote = IngressSocketAddress {
            address: Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
                .octets()
                .to_vec(),
            port: 53,
        };
        let application = IngressSocketAddress {
            address: Ipv6Addr::new(0xfd76, 0, 0, 0, 0, 0, 0, 7).octets().to_vec(),
            port: 50_001,
        };
        let mut request = ingress_request(
            36,
            helper_request::Operation::AcquireIngressReplySocket(AcquireIngressReplySocket {
                client_runtime_id: vec![7; 16],
                ingress_handle: vec![8; 32],
                remote: Some(remote.clone()),
                application: Some(application.clone()),
            }),
        );
        assert!(encode_request(&request).is_ok());

        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_REPLY_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("IPv6 digest").to_vec(),
            outcome: Some(helper_response::Outcome::IngressReplySocketReady(
                IngressReplySocketReady {
                    client_runtime_id: vec![7; 16],
                    ingress_handle: vec![8; 32],
                    remote: Some(remote),
                    application: Some(application),
                },
            )),
        };
        assert!(encode_response(&response).is_ok());
        assert_ne!(
            ingress_reply_fd_binding(&response).expect("IPv6 binding"),
            [0; 32]
        );

        let Some(helper_request::Operation::AcquireIngressReplySocket(reply)) =
            request.operation.as_mut()
        else {
            panic!("reply request");
        };
        reply.application = Some(IngressSocketAddress {
            address: vec![192, 0, 2, 20],
            port: 50_001,
        });
        assert!(encode_request(&request).is_err());
    }
}
