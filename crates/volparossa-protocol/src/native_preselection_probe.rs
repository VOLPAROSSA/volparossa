//! Endpoint-separated v4 contracts for one native preselection probe.
//!
//! These messages deliberately separate who may learn each ephemeral `WireGuard` endpoint. A
//! permit is endpoint-free. The Exit-ready message is for the selected data Relay only and binds
//! the `RelayExit` and Exit endpoints. The client-facing Relay-ready message carries only the
//! `RelayClient` endpoint. A start carries the Client endpoint only to that data Relay. Neither
//! result carries an underlay endpoint. This module verifies canonical signatures and exact phase
//! bindings; it does not order different nodes by their wall clocks, provision a helper context,
//! or claim that a native datapath exists.

use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::envelope::fixed_array;
use crate::messages::validate_rate;
use crate::{
    ControlMessageType, ControlPayload, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE,
    ObservationAddressFamily, ObservationNetworkPrefix, PROTOCOL_VERSION, PreselectionActorBinding,
    ProtocolError, ReplayCache, SignedEnvelope, TimePolicy, Transport, VerifiedControlMessage,
    WireguardEndpoint, decode_canonical, encode_canonical, node_id_from_public_key,
    sign_control_message, verify_control_message,
};

const ID_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;
/// Minimum exact selected data-Relay set for one native attempt.
pub const MIN_NATIVE_PROBE_CANDIDATES: usize = 1;
/// Maximum exact selected data-Relay set for one native attempt.
pub const MAX_NATIVE_PROBE_CANDIDATES: usize = 8;
/// Maximum helper path identity admitted inside one shared native route context.
pub const MAX_NATIVE_PROBE_PATHS: usize = 8;
/// Hard wall-clock lifetime of one native-preselection attempt and every message within it.
///
/// The same signed chain currently owns the established native route. Five minutes leaves the
/// bounded setup transaction enough headroom for useful multi-flow MPTCP/MPQUIC service while
/// keeping every route authorization short-lived.
pub const MAX_NATIVE_PROBE_LIFETIME_MS: u64 = 5 * 60 * 1_000;
const CANDIDATE_SET_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-candidate-set/v4\0";
const CHALLENGE_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-challenge/v4\0";
const PERMIT_REQUEST_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-permit-request/v4\0";
const PERMIT_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-permit/v4\0";
const EXIT_READY_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-exit-ready/v4\0";
const RELAY_READY_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-relay-ready/v4\0";
const START_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-start/v4\0";
const EXIT_RESULT_HASH_DOMAIN: &[u8] = b"volparossa/native-probe-exit-result/v4\0";
const PREPARED_LEASE_COMMITMENT_DOMAIN: &[u8] = b"volparossa/native-probe-prepared-lease/v4\0";
/// Largest canonical bundle accepted by the Exit authorization provider.
pub const MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE: usize = 32 * 1024;
/// Largest identity-bound Exit control multiaddress carried by one native Permit.
pub const MAX_NATIVE_PROBE_CONTROL_ADDRESS_BYTES: usize = 1_024;

/// Exact endpoint-free candidate set consumed from one A1 prepared-evidence handoff.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeCandidateSet {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub preselection_batch_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub control: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "4")]
    pub exit: Option<PreselectionActorBinding>,
    #[prost(message, repeated, tag = "5")]
    pub data_relays: Vec<PreselectionActorBinding>,
    #[prost(enumeration = "Transport", tag = "6")]
    pub transport: i32,
    #[prost(enumeration = "ObservationAddressFamily", tag = "7")]
    pub address_family: i32,
    #[prost(uint64, tag = "8")]
    pub policy_version: u64,
    #[prost(bytes = "vec", tag = "9")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub policy_expires_at_ms: u64,
}

/// Immutable path scope repeated across every signed phase.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbePathScope {
    #[prost(bytes = "vec", tag = "1")]
    pub attempt_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub probe_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub candidate_set_hash: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub candidate_ordinal: u32,
    #[prost(message, optional, tag = "5")]
    pub data_relay: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "6")]
    pub control: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "7")]
    pub exit: Option<PreselectionActorBinding>,
    #[prost(bytes = "vec", tag = "8")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub client_session_public_key: Vec<u8>,
    #[prost(enumeration = "Transport", tag = "10")]
    pub transport: i32,
    #[prost(enumeration = "ObservationAddressFamily", tag = "11")]
    pub address_family: i32,
    #[prost(uint64, tag = "12")]
    pub policy_version: u64,
    #[prost(bytes = "vec", tag = "13")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "14")]
    pub policy_expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "15")]
    pub challenge_hash: Vec<u8>,
    #[prost(uint64, tag = "16")]
    pub attempt_expires_at_ms: u64,
    /// Exact number of native paths that must complete inside this attempt.
    #[prost(uint32, tag = "17")]
    pub required_path_count: u32,
    /// Client-requested upload capacity reserved for this exact path.
    #[prost(uint64, tag = "18")]
    pub reserved_up_mbps: u64,
    /// Client-requested download capacity reserved for this exact path.
    #[prost(uint64, tag = "19")]
    pub reserved_down_mbps: u64,
}

/// Ephemeral-client-signed endpoint-free request for one Exit permit.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbePermitRequest {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(uint64, tag = "2")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "3")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
}

/// Exit-signed dataplane-endpoint-free authorization for one exact request.
///
/// `exit_control_address` is one bounded control-plane multiaddress cryptographically bound to the
/// Exit identity. It is transported opaquely through the client and consumed only by the selected
/// data Relay when it dispatches the Ready RPC.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbePermit {
    #[prost(bytes = "vec", tag = "1")]
    pub request_hash: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(uint64, tag = "3")]
    pub issued_at_ms: u64,
    #[prost(uint64, tag = "4")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub nonce: Vec<u8>,
    #[prost(string, tag = "6")]
    pub exit_control_address: String,
}

/// One helper-prepared endpoint bound to a non-secret helper runtime and shared route context.
///
/// `prepared_lease_commitment` is a domain-separated digest containing the helper's secret,
/// random 256-bit lease handle. It is not a deterministic or brute-forceable endpoint digest.
/// All endpoints in one attempt carry `route_context_id == scope.attempt_id`; the exact path is
/// `scope.candidate_ordinal`. Endpoints on different nodes have different helper runtimes, while
/// the `RelayClient` and `RelayExit` endpoints share one Relay helper runtime.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeEndpointBinding {
    #[prost(bytes = "vec", tag = "1")]
    pub helper_runtime_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub endpoint: Option<WireguardEndpoint>,
    #[prost(bytes = "vec", tag = "4")]
    pub prepared_lease_commitment: Vec<u8>,
    /// Exact context-local helper path bound by the signed scope.
    #[prost(uint32, tag = "5")]
    pub path_id: u32,
}

/// Exit-signed readiness delivered only to the exact data Relay.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeExitReady {
    #[prost(bytes = "vec", tag = "1")]
    pub permit_hash: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(message, optional, tag = "3")]
    pub relay_exit_endpoint: Option<NativeProbeEndpointBinding>,
    #[prost(message, optional, tag = "4")]
    pub exit_endpoint: Option<NativeProbeEndpointBinding>,
    #[prost(uint64, tag = "5")]
    pub ready_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub nonce: Vec<u8>,
    /// Per-process Exit incarnation that signed and owns this prepared endpoint.
    #[prost(bytes = "vec", tag = "8")]
    pub exit_boot_id: Vec<u8>,
}

/// Relay-signed client-facing readiness carrying only the `RelayClient` endpoint.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeRelayReady {
    #[prost(bytes = "vec", tag = "1")]
    pub permit_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub exit_ready_hash: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(message, optional, tag = "4")]
    pub relay_client_endpoint: Option<NativeProbeEndpointBinding>,
    #[prost(uint64, tag = "5")]
    pub ready_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub nonce: Vec<u8>,
}

/// Client-session-signed start delivered only to the exact data Relay.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeStart {
    #[prost(bytes = "vec", tag = "1")]
    pub permit_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub relay_ready_hash: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(message, optional, tag = "4")]
    pub client_endpoint: Option<NativeProbeEndpointBinding>,
    #[prost(uint64, tag = "5")]
    pub started_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub nonce: Vec<u8>,
}

/// Canonical signed phase chain forwarded by the exact data Relay to the selected Exit.
///
/// The bundle adds no authority of its own. The Exit independently verifies every nested
/// signature and exact phase hash before issuing a standard [`crate::RelayAuthorization`].
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeAuthorizationChain {
    #[prost(bytes = "vec", tag = "1")]
    pub signed_permit_request: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signed_permit: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signed_exit_ready: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signed_relay_ready: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub signed_start: Vec<u8>,
}

/// Endpoint-free helper commit facts for one exact prepared lease.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeLeaseProof {
    #[prost(bytes = "vec", tag = "1")]
    pub helper_runtime_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub prepared_lease_commitment: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub latest_handshake_unix: u64,
    #[prost(uint64, tag = "5")]
    pub received_bytes_after_baseline: u64,
    #[prost(uint64, tag = "6")]
    pub transmitted_bytes_after_baseline: u64,
}

/// Strict post-baseline forwarding growth for both permitted directions and no terminal-drop growth.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeForwardingProof {
    #[prost(uint64, tag = "1")]
    pub client_to_exit_packets_after_baseline: u64,
    #[prost(uint64, tag = "2")]
    pub client_to_exit_bytes_after_baseline: u64,
    #[prost(uint64, tag = "3")]
    pub exit_to_client_packets_after_baseline: u64,
    #[prost(uint64, tag = "4")]
    pub exit_to_client_bytes_after_baseline: u64,
    #[prost(uint64, tag = "5")]
    pub terminal_drop_packets_after_baseline: u64,
    #[prost(uint64, tag = "6")]
    pub terminal_drop_bytes_after_baseline: u64,
}

/// Affine bundle of the data Relay's two helper lease proofs and forwarding fence.
#[allow(missing_docs)]
pub struct NativeProbeRelayLocalProofs {
    pub relay_client_lease: NativeProbeLeaseProof,
    pub relay_exit_lease: NativeProbeLeaseProof,
    pub forwarding: NativeProbeForwardingProof,
}

/// Exit-signed endpoint-free result produced only after the exact challenge reached the Exit helper.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeExitResult {
    #[prost(bytes = "vec", tag = "1")]
    pub permit_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub exit_ready_hash: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(bytes = "vec", tag = "4")]
    pub challenge_response: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub observed_network_prefix: Option<ObservationNetworkPrefix>,
    #[prost(message, optional, tag = "6")]
    pub exit_lease: Option<NativeProbeLeaseProof>,
    #[prost(uint64, tag = "7")]
    pub measured_at_ms: u64,
    #[prost(uint64, tag = "8")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
}

/// Relay-signed endpoint-free terminal result containing the exact nested Exit result.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeProbeRelayResult {
    #[prost(bytes = "vec", tag = "1")]
    pub permit_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub relay_ready_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub start_hash: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub scope: Option<NativeProbePathScope>,
    #[prost(bytes = "vec", tag = "5")]
    pub challenge_hash: Vec<u8>,
    #[prost(message, optional, tag = "6")]
    pub relay_client_lease: Option<NativeProbeLeaseProof>,
    #[prost(message, optional, tag = "7")]
    pub relay_exit_lease: Option<NativeProbeLeaseProof>,
    #[prost(message, optional, tag = "8")]
    pub forwarding: Option<NativeProbeForwardingProof>,
    #[prost(bytes = "vec", tag = "9")]
    pub signed_exit_result: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub exit_result_hash: Vec<u8>,
    #[prost(uint64, tag = "11")]
    pub measured_at_ms: u64,
    #[prost(uint64, tag = "12")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "13")]
    pub nonce: Vec<u8>,
}

/// Exact request plus Exit permit after both signatures and cross-bindings passed.
pub struct VerifiedNativeProbePermit {
    signed_request: Vec<u8>,
    signed_permit: Vec<u8>,
    request: VerifiedControlMessage<NativeProbePermitRequest>,
    permit: VerifiedControlMessage<NativeProbePermit>,
}

/// Exit readiness verified by a data Relay against its exact permit.
pub struct VerifiedNativeProbeExitReady {
    permit: VerifiedNativeProbePermit,
    signed_exit_ready: Vec<u8>,
    exit_ready: VerifiedControlMessage<NativeProbeExitReady>,
}

/// Relay readiness minted once after both locally prepared Relay endpoints match Exit readiness.
pub struct IssuedNativeProbeRelayReady {
    exit_ready: VerifiedNativeProbeExitReady,
    signed_relay_ready: Vec<u8>,
    relay_ready: NativeProbeRelayReady,
    relay_exit_endpoint: NativeProbeEndpointBinding,
}

/// Client start verified by the exact data Relay that minted its affine readiness token.
pub struct VerifiedNativeProbeStartForRelay {
    relay_ready: IssuedNativeProbeRelayReady,
    signed_start: Vec<u8>,
    start: VerifiedControlMessage<NativeProbeStart>,
}

/// Independently verified native phase chain accepted by the selected Exit.
pub struct VerifiedNativeProbeAuthorizationChain {
    _permit_request: VerifiedControlMessage<NativeProbePermitRequest>,
    _permit: VerifiedControlMessage<NativeProbePermit>,
    exit_ready: VerifiedControlMessage<NativeProbeExitReady>,
    relay_ready: VerifiedControlMessage<NativeProbeRelayReady>,
    start: VerifiedControlMessage<NativeProbeStart>,
    signed_start: Vec<u8>,
}

/// Exit result verified after start by the exact endpoint-owning data Relay.
pub struct VerifiedNativeProbeExitResult {
    start: VerifiedNativeProbeStartForRelay,
    signed_exit_result: Vec<u8>,
    exit_result: VerifiedControlMessage<NativeProbeExitResult>,
}

/// Relay result signed exactly once after all three hidden helper leases and forwarding proof bind.
pub struct IssuedNativeProbeRelayResult {
    signed_relay_result: Vec<u8>,
}

/// Relay readiness verified by the client against its exact permit.
pub struct VerifiedNativeProbeRelayReady {
    permit: VerifiedNativeProbePermit,
    signed_relay_ready: Vec<u8>,
    relay_ready: VerifiedControlMessage<NativeProbeRelayReady>,
}

/// One exact client start signed after Relay readiness; this token is consumed by result verification.
pub struct IssuedNativeProbeStart {
    relay_ready: VerifiedNativeProbeRelayReady,
    signed_start: Vec<u8>,
    start: NativeProbeStart,
}

/// Complete cryptographic result chain. It is not helper or datapath evidence by itself.
pub struct VerifiedNativeProbeResult {
    start: IssuedNativeProbeStart,
    client_lease: NativeProbeLeaseProof,
    _relay_result: VerifiedControlMessage<NativeProbeRelayResult>,
    exit_result: VerifiedControlMessage<NativeProbeExitResult>,
}

impl VerifiedNativeProbeResult {
    /// Borrow the exact signed path scope retained by this terminal result chain.
    #[must_use]
    pub fn scope(&self) -> &NativeProbePathScope {
        self.start.relay_ready.scope()
    }

    /// Borrow the helper incarnation which committed the Client endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if verified state is corrupted after construction. Result verification rejects
    /// a missing, zero, or incorrectly sized helper runtime identifier.
    #[must_use]
    pub fn client_helper_runtime_id(&self) -> &[u8; KEY_LENGTH] {
        self.client_lease
            .helper_runtime_id
            .as_slice()
            .try_into()
            .expect("verified native Client lease has one helper runtime identifier")
    }

    /// Borrow the helper incarnation which committed the Exit endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if verified state is corrupted after construction. Result verification rejects
    /// an absent, zero, or incorrectly sized Exit lease runtime identifier.
    #[must_use]
    pub fn exit_helper_runtime_id(&self) -> &[u8; KEY_LENGTH] {
        self.exit_result
            .message()
            .exit_lease
            .as_ref()
            .expect("verified native Exit result has one lease proof")
            .helper_runtime_id
            .as_slice()
            .try_into()
            .expect("verified native Exit lease has one helper runtime identifier")
    }
}

impl VerifiedNativeProbePermit {
    /// Borrow the exact path scope after both dataplane-endpoint-free signatures and bindings
    /// passed.
    ///
    /// # Panics
    ///
    /// Panics only if the internal verified control message has been corrupted after
    /// construction. The verifier rejects a Permit without this scope.
    #[must_use]
    pub fn scope(&self) -> &NativeProbePathScope {
        self.permit
            .message()
            .scope
            .as_ref()
            .expect("verified native Permit always carries a scope")
    }

    /// Borrow the signed, identity-bound Exit control multiaddress for the selected data Relay.
    #[must_use]
    pub fn exit_control_address(&self) -> &str {
        &self.permit.message().exit_control_address
    }
}

impl VerifiedNativeProbeRelayReady {
    /// Borrow the exact path scope retained by the verified data-Relay readiness.
    ///
    /// # Panics
    ///
    /// Panics only if the internal verified control message has been corrupted after
    /// construction. The verifier rejects readiness without this scope.
    #[must_use]
    pub fn scope(&self) -> &NativeProbePathScope {
        self.relay_ready
            .message()
            .scope
            .as_ref()
            .expect("verified native Relay readiness always carries a scope")
    }

    /// Borrow the helper-prepared `RelayClient` endpoint disclosed only to this client.
    ///
    /// # Panics
    ///
    /// Panics only if the internal verified control message has been corrupted after
    /// construction. The verifier rejects readiness without this endpoint.
    #[must_use]
    pub fn relay_client_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.relay_ready
            .message()
            .relay_client_endpoint
            .as_ref()
            .expect("verified native Relay readiness always carries an endpoint")
    }

    /// Absolute signed expiry of this readiness phase.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.relay_ready.message().expires_at_ms
    }
}

impl IssuedNativeProbeStart {
    /// Borrow the exact client-signed start for delivery only to the selected data Relay.
    #[must_use]
    pub fn encoded_start(&self) -> &[u8] {
        &self.signed_start
    }
}

impl VerifiedNativeProbeStartForRelay {
    /// Encode the complete signed chain for independent verification by the selected Exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical bounded bundle cannot be encoded.
    pub fn authorization_chain(&self) -> Result<Vec<u8>, ProtocolError> {
        encode_canonical(
            &NativeProbeAuthorizationChain {
                signed_permit_request: self.relay_ready.exit_ready.permit.signed_request.clone(),
                signed_permit: self.relay_ready.exit_ready.permit.signed_permit.clone(),
                signed_exit_ready: self.relay_ready.exit_ready.signed_exit_ready.clone(),
                signed_relay_ready: self.relay_ready.signed_relay_ready.clone(),
                signed_start: self.signed_start.clone(),
            },
            MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE,
        )
    }

    /// Borrow the exact client-signed Start accepted by this data Relay.
    #[must_use]
    pub fn encoded_start(&self) -> &[u8] {
        &self.signed_start
    }

    /// Borrow the exact verified native path scope.
    ///
    /// # Panics
    ///
    /// Panics only if an internally verified Start is corrupted after construction.
    #[must_use]
    pub fn scope(&self) -> &NativeProbePathScope {
        self.start
            .message()
            .scope
            .as_ref()
            .expect("verified native Start always carries a scope")
    }

    /// Borrow the helper-prepared Client endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if an internally verified Start is corrupted after construction.
    #[must_use]
    pub fn client_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.start
            .message()
            .client_endpoint
            .as_ref()
            .expect("verified native Start always carries a Client endpoint")
    }

    /// Borrow the helper-prepared `RelayClient` endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if internally issued Relay readiness is corrupted after construction.
    #[must_use]
    pub fn relay_client_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.relay_ready
            .relay_ready
            .relay_client_endpoint
            .as_ref()
            .expect("issued native Relay readiness always carries a RelayClient endpoint")
    }

    /// Borrow the helper-prepared `RelayExit` endpoint.
    #[must_use]
    pub fn relay_exit_endpoint(&self) -> &NativeProbeEndpointBinding {
        &self.relay_ready.relay_exit_endpoint
    }

    /// Borrow the helper-prepared Exit endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if internally verified Exit readiness is corrupted after construction.
    #[must_use]
    pub fn exit_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.relay_ready
            .exit_ready
            .exit_ready
            .message()
            .exit_endpoint
            .as_ref()
            .expect("verified native Exit readiness always carries an Exit endpoint")
    }

    /// Return the exact signed Start creation time.
    #[must_use]
    pub fn started_at_ms(&self) -> u64 {
        self.start.message().started_at_ms
    }

    /// Return the exclusive signed Start expiry.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.start.message().expires_at_ms
    }

    /// Borrow the process-local Exit incarnation bound by signed readiness.
    #[must_use]
    pub fn exit_boot_id(&self) -> &[u8] {
        &self
            .relay_ready
            .exit_ready
            .exit_ready
            .message()
            .exit_boot_id
    }
}

impl VerifiedNativeProbeAuthorizationChain {
    /// Borrow the exact native path scope shared by every verified phase.
    ///
    /// # Panics
    ///
    /// Panics only if an internally verified Start is corrupted after construction.
    #[must_use]
    pub fn scope(&self) -> &NativeProbePathScope {
        self.start
            .message()
            .scope
            .as_ref()
            .expect("verified native authorization always carries a scope")
    }

    /// Borrow the helper-prepared Client endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if an internally verified Start is corrupted after construction.
    #[must_use]
    pub fn client_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.start
            .message()
            .client_endpoint
            .as_ref()
            .expect("verified native authorization always carries a Client endpoint")
    }

    /// Borrow the helper-prepared `RelayClient` endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if internally verified Relay readiness is corrupted after construction.
    #[must_use]
    pub fn relay_client_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.relay_ready
            .message()
            .relay_client_endpoint
            .as_ref()
            .expect("verified native authorization always carries a RelayClient endpoint")
    }

    /// Borrow the helper-prepared `RelayExit` endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if internally verified Exit readiness is corrupted after construction.
    #[must_use]
    pub fn relay_exit_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.exit_ready
            .message()
            .relay_exit_endpoint
            .as_ref()
            .expect("verified native authorization always carries a RelayExit endpoint")
    }

    /// Borrow the helper-prepared Exit endpoint.
    ///
    /// # Panics
    ///
    /// Panics only if internally verified Exit readiness is corrupted after construction.
    #[must_use]
    pub fn exit_endpoint(&self) -> &NativeProbeEndpointBinding {
        self.exit_ready
            .message()
            .exit_endpoint
            .as_ref()
            .expect("verified native authorization always carries an Exit endpoint")
    }

    /// Borrow the process-local Exit incarnation bound by signed readiness.
    #[must_use]
    pub fn exit_boot_id(&self) -> &[u8] {
        &self.exit_ready.message().exit_boot_id
    }

    /// Return the exact signed Start creation time.
    #[must_use]
    pub fn started_at_ms(&self) -> u64 {
        self.start.message().started_at_ms
    }

    /// Return the exclusive signed Start expiry.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.start.message().expires_at_ms
    }

    /// Borrow the exact client-signed Start accepted by both authorities.
    #[must_use]
    pub fn encoded_start(&self) -> &[u8] {
        &self.signed_start
    }
}

impl IssuedNativeProbeRelayReady {
    /// Borrow the endpoint-safe Relay readiness for delivery to the client.
    #[must_use]
    pub fn encoded_relay_ready(&self) -> &[u8] {
        &self.signed_relay_ready
    }
}

impl IssuedNativeProbeRelayResult {
    /// Borrow the endpoint-free terminal result for delivery to the client.
    #[must_use]
    pub fn encoded_relay_result(&self) -> &[u8] {
        &self.signed_relay_result
    }
}

impl NativeProbeCandidateSet {
    /// Validate the exact endpoint-free set shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, duplicate, misordered, or expired candidate binding.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        require_nonzero::<ID_LENGTH>(&self.preselection_batch_id, "native candidate batch")?;
        let control = required_actor(self.control.as_ref(), "native candidate control")?;
        let exit = required_actor(self.exit.as_ref(), "native candidate exit")?;
        validate_scope_values(
            self.transport,
            self.address_family,
            self.policy_version,
            &self.policy_hash,
            self.policy_expires_at_ms,
        )?;
        if !(MIN_NATIVE_PROBE_CANDIDATES..=MAX_NATIVE_PROBE_CANDIDATES)
            .contains(&self.data_relays.len())
            || same_actor(control, exit)
        {
            return Err(ProtocolError::InvalidField("native candidate set shape"));
        }
        for (index, relay) in self.data_relays.iter().enumerate() {
            relay.validate("native candidate data relay")?;
            if same_actor(relay, control)
                || same_actor(relay, exit)
                || self.data_relays[..index]
                    .iter()
                    .any(|earlier| same_actor(earlier, relay))
            {
                return Err(ProtocolError::InvalidField("native candidate set identity"));
            }
        }
        let expires = actor_ceiling(control)
            .min(actor_ceiling(exit))
            .min(
                self.data_relays
                    .iter()
                    .map(actor_ceiling)
                    .min()
                    .unwrap_or(0),
            )
            .min(self.policy_expires_at_ms);
        if expires == 0 {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }
}

impl NativeProbePathScope {
    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<ID_LENGTH>(&self.attempt_id, "native scope attempt_id")?;
        require_nonzero::<ID_LENGTH>(&self.probe_id, "native scope probe_id")?;
        require_nonzero::<KEY_LENGTH>(&self.candidate_set_hash, "native scope set hash")?;
        require_nonzero::<KEY_LENGTH>(&self.challenge_hash, "native scope challenge hash")?;
        validate_rate(self.reserved_up_mbps, "native scope reserved_up_mbps")?;
        validate_rate(self.reserved_down_mbps, "native scope reserved_down_mbps")?;
        if !(1..=u32::try_from(MAX_NATIVE_PROBE_PATHS).unwrap_or(u32::MAX))
            .contains(&self.candidate_ordinal)
            || !(1..=u32::try_from(MAX_NATIVE_PROBE_PATHS).unwrap_or(u32::MAX))
                .contains(&self.required_path_count)
            || self.candidate_ordinal > self.required_path_count
        {
            return Err(ProtocolError::InvalidField("native scope path cardinality"));
        }
        let relay = required_actor(self.data_relay.as_ref(), "native scope data relay")?;
        let control = required_actor(self.control.as_ref(), "native scope control")?;
        let exit = required_actor(self.exit.as_ref(), "native scope exit")?;
        if same_actor(relay, exit) || same_actor(control, exit) {
            return Err(ProtocolError::InvalidField("native scope actor identity"));
        }
        let session_id = require_nonzero::<KEY_LENGTH>(
            &self.client_session_id,
            "native scope client session id",
        )?;
        let session_key = require_nonzero::<KEY_LENGTH>(
            &self.client_session_public_key,
            "native scope client session key",
        )?;
        if node_id_from_public_key(&session_key) != session_id {
            return Err(ProtocolError::InvalidField("native scope client session"));
        }
        validate_scope_values(
            self.transport,
            self.address_family,
            self.policy_version,
            &self.policy_hash,
            self.policy_expires_at_ms,
        )?;
        match Transport::try_from(self.transport)
            .map_err(|_| ProtocolError::InvalidField("native scope transport path cardinality"))?
        {
            Transport::UdpSinglePath if self.required_path_count != 1 => {
                return Err(ProtocolError::InvalidField(
                    "native scope UDP path cardinality",
                ));
            }
            Transport::TcpMptcp | Transport::MultipathQuic if self.required_path_count < 2 => {
                return Err(ProtocolError::InvalidField(
                    "native scope multipath cardinality",
                ));
            }
            Transport::Unspecified => {
                return Err(ProtocolError::InvalidField("native scope transport"));
            }
            Transport::UdpSinglePath | Transport::TcpMptcp | Transport::MultipathQuic => {}
        }
        if self.attempt_expires_at_ms == 0
            || self.attempt_expires_at_ms > self.policy_expires_at_ms
            || self.attempt_expires_at_ms > actor_ceiling(relay)
            || self.attempt_expires_at_ms > actor_ceiling(control)
            || self.attempt_expires_at_ms > actor_ceiling(exit)
        {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }
}

impl NativeProbeEndpointBinding {
    fn validate_for_scope(&self, scope: &NativeProbePathScope) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.helper_runtime_id, "native endpoint helper runtime")?;
        require_nonzero::<ID_LENGTH>(&self.route_context_id, "native endpoint route context")?;
        require_nonzero::<KEY_LENGTH>(
            &self.prepared_lease_commitment,
            "native endpoint prepared lease commitment",
        )?;
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native endpoint"))?;
        endpoint.validate("native endpoint")?;
        if self.route_context_id != scope.attempt_id
            || self.path_id != scope.candidate_ordinal
            || !endpoint_family_matches(endpoint, scope_family(scope)?)
        {
            return Err(ProtocolError::InvalidField("native endpoint scope"));
        }
        Ok(())
    }
}

impl NativeProbeLeaseProof {
    fn validate_for_scope(&self, scope: &NativeProbePathScope) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.helper_runtime_id, "native lease helper runtime")?;
        require_nonzero::<ID_LENGTH>(&self.route_context_id, "native lease route context")?;
        require_nonzero::<KEY_LENGTH>(
            &self.prepared_lease_commitment,
            "native prepared lease commitment",
        )?;
        if self.route_context_id != scope.attempt_id
            || self.latest_handshake_unix == 0
            || self.received_bytes_after_baseline == 0
            || self.transmitted_bytes_after_baseline == 0
        {
            return Err(ProtocolError::InvalidField("native lease proof"));
        }
        Ok(())
    }
}

impl NativeProbeForwardingProof {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.client_to_exit_packets_after_baseline == 0
            || self.client_to_exit_bytes_after_baseline == 0
            || self.exit_to_client_packets_after_baseline == 0
            || self.exit_to_client_bytes_after_baseline == 0
            || self.terminal_drop_packets_after_baseline != 0
            || self.terminal_drop_bytes_after_baseline != 0
        {
            return Err(ProtocolError::InvalidField("native forwarding proof"));
        }
        Ok(())
    }
}

impl ControlPayload for NativeProbePermitRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbePermitRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_phase_lifetime(self.created_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native permit request nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_client_session_signed_envelope(
            scope,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native permit request envelope",
        )
    }
}

impl ControlPayload for NativeProbePermit {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbePermit;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.request_hash, "native permit request hash")?;
        let scope = required_scope(self.scope.as_ref())?;
        validate_phase_lifetime(self.issued_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native permit nonce")?;
        if self.exit_control_address.is_empty()
            || self.exit_control_address.len() > MAX_NATIVE_PROBE_CONTROL_ADDRESS_BYTES
            || !self.exit_control_address.is_ascii()
        {
            return Err(ProtocolError::InvalidField(
                "native permit Exit control address",
            ));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_actor_signed_envelope(
            required_actor(scope.exit.as_ref(), "native scope exit")?,
            self.issued_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native permit envelope",
        )
    }
}

impl ControlPayload for NativeProbeExitReady {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbeExitReady;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.permit_hash, "native exit ready permit hash")?;
        let scope = required_scope(self.scope.as_ref())?;
        let relay_exit = self
            .relay_exit_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native RelayExit endpoint"))?;
        let exit = self
            .exit_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native Exit endpoint"))?;
        relay_exit.validate_for_scope(scope)?;
        exit.validate_for_scope(scope)?;
        if relay_exit.helper_runtime_id == exit.helper_runtime_id
            || !bindings_share_route_context(relay_exit, exit)
            || bindings_collide(relay_exit, exit)
        {
            return Err(ProtocolError::InvalidField("native exit ready endpoints"));
        }
        require_nonzero::<ID_LENGTH>(&self.exit_boot_id, "native Exit-ready boot ID")?;
        validate_phase_lifetime(self.ready_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native exit ready nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_actor_signed_envelope(
            required_actor(scope.exit.as_ref(), "native scope exit")?,
            self.ready_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native exit ready envelope",
        )
    }
}

/// Decode and independently verify the complete native authorization chain at the selected Exit.
///
/// The verifier uses a private bounded replay cache because the entire bundle is one transaction;
/// the stateful Exit service separately provides exact-request idempotency. This avoids consuming
/// valid nested nonces when a later phase in a substituted bundle fails.
///
/// # Errors
///
/// Returns an error for an oversized/non-canonical bundle, any invalid signature or lifetime,
/// wrong phase hash, endpoint topology mismatch, or inconsistent scope.
pub fn verify_native_probe_authorization_chain(
    encoded: &[u8],
    now_ms: u64,
) -> Result<VerifiedNativeProbeAuthorizationChain, ProtocolError> {
    let chain: NativeProbeAuthorizationChain =
        decode_canonical(encoded, MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE)?;
    let mut replay = ReplayCache::new(5)?;
    let permit = verify_native_probe_permit(
        chain.signed_permit_request,
        chain.signed_permit,
        now_ms,
        &mut replay,
    )?;
    let exit_ready =
        verify_native_probe_exit_ready(permit, chain.signed_exit_ready, now_ms, &mut replay)?;
    let expected_permit = native_probe_permit_hash(&exit_ready.permit.signed_permit)?;
    let expected_exit_ready = native_probe_exit_ready_hash(&exit_ready.signed_exit_ready)?;
    let relay_ready = verify_control_message::<NativeProbeRelayReady>(
        &chain.signed_relay_ready,
        now_ms,
        native_time_policy(),
        &mut replay,
    )?;
    let relay_client = relay_ready
        .message()
        .relay_client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayClient endpoint"))?;
    let relay_exit = exit_ready
        .exit_ready
        .message()
        .relay_exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayExit endpoint"))?;
    let exit_endpoint = exit_ready
        .exit_ready
        .message()
        .exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Exit endpoint"))?;
    if relay_ready.message().scope != exit_ready.exit_ready.message().scope
        || relay_ready.message().permit_hash != expected_permit
        || relay_ready.message().exit_ready_hash != expected_exit_ready
        || relay_ready.message().expires_at_ms > exit_ready.exit_ready.message().expires_at_ms
        || !bindings_form_relay_exit_topology(relay_client, relay_exit, exit_endpoint)
    {
        return Err(ProtocolError::InvalidField(
            "native authorization Relay-ready binding",
        ));
    }
    let expected_relay_ready = native_probe_relay_ready_hash(&chain.signed_relay_ready)?;
    let start = verify_control_message::<NativeProbeStart>(
        &chain.signed_start,
        now_ms,
        native_time_policy(),
        &mut replay,
    )?;
    let client_endpoint = start
        .message()
        .client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Client endpoint"))?;
    if start.message().scope != relay_ready.message().scope
        || start.message().permit_hash != expected_permit
        || start.message().relay_ready_hash != expected_relay_ready
        || start.message().expires_at_ms > relay_ready.message().expires_at_ms
        || !bindings_form_four_role_topology(
            client_endpoint,
            relay_client,
            relay_exit,
            exit_endpoint,
        )
    {
        return Err(ProtocolError::InvalidField(
            "native authorization Start binding",
        ));
    }
    Ok(VerifiedNativeProbeAuthorizationChain {
        _permit_request: exit_ready.permit.request,
        _permit: exit_ready.permit.permit,
        exit_ready: exit_ready.exit_ready,
        relay_ready,
        start,
        signed_start: chain.signed_start,
    })
}

impl ControlPayload for NativeProbeRelayReady {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbeRelayReady;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.permit_hash, "native relay ready permit hash")?;
        require_nonzero::<KEY_LENGTH>(&self.exit_ready_hash, "native relay ready exit hash")?;
        let scope = required_scope(self.scope.as_ref())?;
        self.relay_client_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native RelayClient endpoint"))?
            .validate_for_scope(scope)?;
        validate_phase_lifetime(self.ready_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native relay ready nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_actor_signed_envelope(
            required_actor(scope.data_relay.as_ref(), "native scope data relay")?,
            self.ready_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native relay ready envelope",
        )
    }
}

impl ControlPayload for NativeProbeStart {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbeStart;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.permit_hash, "native start permit hash")?;
        require_nonzero::<KEY_LENGTH>(&self.relay_ready_hash, "native start relay hash")?;
        let scope = required_scope(self.scope.as_ref())?;
        self.client_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native Client endpoint"))?
            .validate_for_scope(scope)?;
        validate_phase_lifetime(self.started_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native start nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_client_session_signed_envelope(
            scope,
            self.started_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native start envelope",
        )
    }
}

impl ControlPayload for NativeProbeExitResult {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbeExitResult;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.permit_hash, "native exit result permit hash")?;
        require_nonzero::<KEY_LENGTH>(&self.exit_ready_hash, "native exit result ready hash")?;
        let scope = required_scope(self.scope.as_ref())?;
        let challenge_response = require_nonzero::<NONCE_LENGTH>(
            &self.challenge_response,
            "native exit result challenge response",
        )?;
        if native_probe_challenge_hash(&challenge_response) != scope.challenge_hash.as_slice() {
            return Err(ProtocolError::InvalidField("native exit result challenge"));
        }
        let prefix = self
            .observed_network_prefix
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native exit result prefix"))?;
        let normalized = prefix.validated_normalized()?;
        if !matches!(
            (normalized.family(), scope_family(scope)?),
            (
                volparossa_core::IpFamily::Ipv4,
                ObservationAddressFamily::Ipv4
            ) | (
                volparossa_core::IpFamily::Ipv6,
                ObservationAddressFamily::Ipv6
            )
        ) {
            return Err(ProtocolError::InvalidField(
                "native exit result prefix family",
            ));
        }
        self.exit_lease
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native exit lease proof"))?
            .validate_for_scope(scope)?;
        validate_phase_lifetime(self.measured_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native exit result nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_actor_signed_envelope(
            required_actor(scope.exit.as_ref(), "native scope exit")?,
            self.measured_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native exit result envelope",
        )
    }
}

impl ControlPayload for NativeProbeRelayResult {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NativeProbeRelayResult;

    fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (&self.permit_hash, "native relay result permit hash"),
            (&self.relay_ready_hash, "native relay result ready hash"),
            (&self.start_hash, "native relay result start hash"),
            (&self.challenge_hash, "native relay result challenge"),
            (&self.exit_result_hash, "native relay result exit hash"),
        ] {
            require_nonzero::<KEY_LENGTH>(value, field)?;
        }
        let scope = required_scope(self.scope.as_ref())?;
        if self.challenge_hash != scope.challenge_hash {
            return Err(ProtocolError::InvalidField("native relay result challenge"));
        }
        self.relay_client_lease
            .as_ref()
            .ok_or(ProtocolError::InvalidField(
                "native RelayClient lease proof",
            ))?
            .validate_for_scope(scope)?;
        self.relay_exit_lease
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native RelayExit lease proof"))?
            .validate_for_scope(scope)?;
        self.forwarding
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native forwarding proof"))?
            .validate()?;
        if self.signed_exit_result.len() > MAX_CONTROL_MESSAGE_SIZE {
            return Err(ProtocolError::Oversized {
                what: "signed native Exit result",
                maximum: MAX_CONTROL_MESSAGE_SIZE,
            });
        }
        precheck_signed_type::<NativeProbeExitResult>(&self.signed_exit_result)?;
        if native_probe_exit_result_hash(&self.signed_exit_result)?
            != self.exit_result_hash.as_slice()
        {
            return Err(ProtocolError::InvalidField("native relay result exit hash"));
        }
        validate_phase_lifetime(self.measured_at_ms, self.expires_at_ms, scope)?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "native relay result nonce")?;
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let scope = required_scope(self.scope.as_ref())?;
        validate_actor_signed_envelope(
            required_actor(scope.data_relay.as_ref(), "native scope data relay")?,
            self.measured_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "native relay result envelope",
        )
    }
}

/// Hash one exact validated endpoint-free candidate set.
///
/// # Errors
///
/// Returns an error when the set is invalid or its canonical encoding cannot be produced.
pub fn native_probe_candidate_set_hash(
    set: &NativeProbeCandidateSet,
) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    set.validate()?;
    let encoded = encode_canonical(set, MAX_CONTROL_PAYLOAD_SIZE)?;
    hash_exact(CANDIDATE_SET_HASH_DOMAIN, &encoded)
}

/// Hash one raw CSPRNG challenge without placing it on the control path.
pub fn native_probe_challenge_hash(challenge: &[u8; NONCE_LENGTH]) -> [u8; KEY_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_HASH_DOMAIN);
    hasher.update(challenge);
    hasher.finalize().into()
}

/// Commit one helper-prepared endpoint without disclosing its random lease handle.
///
/// The handle must be an opaque helper-issued 256-bit CSPRNG value. Including it makes a
/// commitment visible outside the endpoint's intended recipient infeasible to brute force from
/// the public endpoint tuple, runtime identity, or route context.
///
/// # Errors
///
/// Returns an error for invalid identifiers, lease authority, endpoint, or canonical encoding.
pub fn native_probe_prepared_lease_commitment(
    helper_runtime_id: &[u8; KEY_LENGTH],
    route_context_id: &[u8; ID_LENGTH],
    lease_handle: &[u8; KEY_LENGTH],
    endpoint: &WireguardEndpoint,
) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    require_nonzero::<KEY_LENGTH>(helper_runtime_id, "native helper runtime")?;
    require_nonzero::<ID_LENGTH>(route_context_id, "native route context")?;
    require_nonzero::<KEY_LENGTH>(lease_handle, "native helper lease handle")?;
    endpoint.validate("native prepared endpoint")?;
    let endpoint = encode_canonical(endpoint, MAX_CONTROL_PAYLOAD_SIZE)?;
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_LEASE_COMMITMENT_DOMAIN);
    hasher.update(helper_runtime_id);
    hasher.update(route_context_id);
    hasher.update(lease_handle);
    hasher.update(
        u32::try_from(endpoint.len())
            .map_err(|_| ProtocolError::InvalidField("native prepared endpoint"))?
            .to_be_bytes(),
    );
    hasher.update(endpoint);
    Ok(hasher.finalize().into())
}

/// Hash one exact signed native permit request.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_permit_request_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbePermitRequest>(PERMIT_REQUEST_HASH_DOMAIN, value)
}

/// Hash one exact signed native permit.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_permit_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbePermit>(PERMIT_HASH_DOMAIN, value)
}

/// Hash one exact signed Exit-ready message.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_exit_ready_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbeExitReady>(EXIT_READY_HASH_DOMAIN, value)
}

/// Hash one exact signed Relay-ready message.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_relay_ready_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbeRelayReady>(RELAY_READY_HASH_DOMAIN, value)
}

/// Hash one exact signed native start.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_start_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbeStart>(START_HASH_DOMAIN, value)
}

/// Hash one exact signed Exit result.
///
/// # Errors
///
/// Returns an error unless the input canonically encodes the expected signed message type.
pub fn native_probe_exit_result_hash(value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    hash_signed::<NativeProbeExitResult>(EXIT_RESULT_HASH_DOMAIN, value)
}

/// Verify and transactionally bind an exact client request to its Exit permit.
///
/// # Errors
///
/// Returns an error for invalid signatures, lifetimes, replay state, or any cross-binding.
pub fn verify_native_probe_permit(
    signed_request: Vec<u8>,
    signed_permit: Vec<u8>,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbePermit, ProtocolError> {
    let expected_request_hash = native_probe_permit_request_hash(&signed_request)?;
    let request = verify_control_message::<NativeProbePermitRequest>(
        &signed_request,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let request_entry = (*request.sender_id(), *request.nonce());
    let permit = match verify_control_message::<NativeProbePermit>(
        &signed_permit,
        now_ms,
        native_time_policy(),
        replay,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = replay.rollback(&request_entry.0, &request_entry.1);
            return Err(error);
        }
    };
    let permit_entry = (*permit.sender_id(), *permit.nonce());
    let matches = permit.message().scope == request.message().scope
        && permit.message().request_hash == expected_request_hash
        && permit.message().expires_at_ms <= request.message().expires_at_ms;
    if !matches {
        rollback_pair(replay, permit_entry, request_entry);
        return Err(ProtocolError::InvalidField("native permit request binding"));
    }
    Ok(VerifiedNativeProbePermit {
        signed_request,
        signed_permit,
        request,
        permit,
    })
}

/// Verify Exit readiness against one exact permit. This transition is for the data Relay only.
///
/// # Errors
///
/// Returns an error for invalid readiness, replay state, or an inexact permit binding.
pub fn verify_native_probe_exit_ready(
    permit: VerifiedNativeProbePermit,
    signed_exit_ready: Vec<u8>,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbeExitReady, ProtocolError> {
    let expected_permit_hash = native_probe_permit_hash(&permit.signed_permit)?;
    let ready = verify_control_message::<NativeProbeExitReady>(
        &signed_exit_ready,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let entry = (*ready.sender_id(), *ready.nonce());
    let matches = ready.message().scope == permit.permit.message().scope
        && ready.message().permit_hash == expected_permit_hash
        && ready.message().expires_at_ms <= permit.permit.message().expires_at_ms;
    if !matches {
        let _ = replay.rollback(&entry.0, &entry.1);
        return Err(ProtocolError::InvalidField("native Exit-ready binding"));
    }
    Ok(VerifiedNativeProbeExitReady {
        permit,
        signed_exit_ready,
        exit_ready: ready,
    })
}

/// Consume verified Exit readiness and mint exactly one endpoint-safe Relay readiness.
///
/// The affine input is intentionally required: a data Relay cannot use this producer path until
/// it has verified the signed hidden Exit endpoints and matched both locally prepared Relay
/// endpoints to the same helper runtime and route context. The returned getter exposes only the
/// `RelayClient` endpoint; the `RelayExit` and Exit endpoints remain inside the opaque owner.
///
/// # Errors
///
/// Returns an error unless readiness, both local bindings, signer, and lifetime match exactly.
pub fn sign_native_probe_relay_ready(
    exit_ready: VerifiedNativeProbeExitReady,
    relay_client_endpoint: NativeProbeEndpointBinding,
    relay_exit_endpoint: NativeProbeEndpointBinding,
    signing_key: &SigningKey,
    ready_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
) -> Result<IssuedNativeProbeRelayReady, ProtocolError> {
    sign_native_probe_relay_ready_with(
        exit_ready,
        relay_client_endpoint,
        relay_exit_endpoint,
        signing_key.verifying_key().to_bytes(),
        ready_at_ms,
        nonce,
        |message| Some(signing_key.sign(message).to_bytes()),
    )
}

/// Mint one Relay readiness through an external `Ed25519` identity provider.
///
/// The verified affine owner is consumed even when validation or signing fails, so callers cannot
/// retry the same readiness authority with substituted endpoints or signer state.
///
/// # Errors
///
/// Returns an error unless readiness, both local bindings, signer, and lifetime match exactly.
pub fn sign_native_probe_relay_ready_with<F>(
    exit_ready: VerifiedNativeProbeExitReady,
    relay_client_endpoint: NativeProbeEndpointBinding,
    relay_exit_endpoint: NativeProbeEndpointBinding,
    relay_public_key: [u8; KEY_LENGTH],
    ready_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
    signer: F,
) -> Result<IssuedNativeProbeRelayReady, ProtocolError>
where
    F: FnOnce(&[u8]) -> Option<[u8; 64]>,
{
    let scope = exit_ready
        .exit_ready
        .message()
        .scope
        .clone()
        .ok_or(ProtocolError::InvalidField("native Exit-ready scope"))?;
    relay_client_endpoint.validate_for_scope(&scope)?;
    relay_exit_endpoint.validate_for_scope(&scope)?;
    let signed_relay_exit = exit_ready
        .exit_ready
        .message()
        .relay_exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayExit endpoint"))?;
    let signed_exit = exit_ready
        .exit_ready
        .message()
        .exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Exit endpoint"))?;
    if relay_exit_endpoint != *signed_relay_exit
        || !bindings_form_relay_exit_topology(
            &relay_client_endpoint,
            &relay_exit_endpoint,
            signed_exit,
        )
    {
        return Err(ProtocolError::InvalidField(
            "native Relay-ready prepared bindings",
        ));
    }
    let relay_ready = NativeProbeRelayReady {
        permit_hash: exit_ready.exit_ready.message().permit_hash.clone(),
        exit_ready_hash: native_probe_exit_ready_hash(&exit_ready.signed_exit_ready)?.to_vec(),
        scope: Some(scope),
        relay_client_endpoint: Some(relay_client_endpoint),
        ready_at_ms,
        expires_at_ms: exit_ready.exit_ready.message().expires_at_ms,
        nonce: nonce.to_vec(),
    };
    let signed_relay_ready = crate::sign_control_message_with(
        &relay_ready,
        relay_public_key,
        ready_at_ms,
        relay_ready.expires_at_ms,
        nonce,
        native_time_policy(),
        signer,
    )?;
    Ok(IssuedNativeProbeRelayReady {
        exit_ready,
        signed_relay_ready,
        relay_ready,
        relay_exit_endpoint,
    })
}

/// Consume issued Relay readiness and verify the exact client start on the data Relay.
///
/// This is where the hidden `RelayClient` binding is joined to the Client binding. They must share
/// the route context while belonging to different helper runtimes and non-colliding leases.
///
/// # Errors
///
/// Returns an error for invalid signatures, replay, phase hashes, lifetime, or endpoint binding.
pub fn verify_native_probe_start_for_relay(
    relay_ready: IssuedNativeProbeRelayReady,
    signed_start: Vec<u8>,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbeStartForRelay, ProtocolError> {
    let expected_permit = native_probe_permit_hash(&relay_ready.exit_ready.permit.signed_permit)?;
    let expected_ready = native_probe_relay_ready_hash(&relay_ready.signed_relay_ready)?;
    let start = verify_control_message::<NativeProbeStart>(
        &signed_start,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let entry = (*start.sender_id(), *start.nonce());
    let client_endpoint = start
        .message()
        .client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Client endpoint"))?;
    let relay_client_endpoint = relay_ready
        .relay_ready
        .relay_client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayClient endpoint"))?;
    let relay_exit_endpoint = &relay_ready.relay_exit_endpoint;
    let exit_endpoint = relay_ready
        .exit_ready
        .exit_ready
        .message()
        .exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Exit endpoint"))?;
    let matches = start.message().scope == relay_ready.relay_ready.scope
        && start.message().permit_hash == expected_permit
        && start.message().relay_ready_hash == expected_ready
        && bindings_form_four_role_topology(
            client_endpoint,
            relay_client_endpoint,
            relay_exit_endpoint,
            exit_endpoint,
        )
        && start.message().expires_at_ms <= relay_ready.relay_ready.expires_at_ms;
    if !matches {
        let _ = replay.rollback(&entry.0, &entry.1);
        return Err(ProtocolError::InvalidField("native start Relay binding"));
    }
    Ok(VerifiedNativeProbeStartForRelay {
        relay_ready,
        signed_start,
        start,
    })
}

/// Consume verified start and verify the exact endpoint-free Exit result on the data Relay.
///
/// This is the only verifier that can compare the Exit's lease proof with the Exit endpoint
/// binding: both values are deliberately hidden from the client. The exact `RelayExit` binding was
/// already consumed while minting readiness, so the returned owner joins all hidden endpoints.
///
/// # Errors
///
/// Returns an error for invalid signatures, replay, phase hashes, lifetime, or Exit lease binding.
pub fn verify_native_probe_exit_result_for_relay(
    start: VerifiedNativeProbeStartForRelay,
    signed_exit_result: Vec<u8>,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbeExitResult, ProtocolError> {
    let expected_permit =
        native_probe_permit_hash(&start.relay_ready.exit_ready.permit.signed_permit)?;
    let expected_ready =
        native_probe_exit_ready_hash(&start.relay_ready.exit_ready.signed_exit_ready)?;
    let result = verify_control_message::<NativeProbeExitResult>(
        &signed_exit_result,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let entry = (*result.sender_id(), *result.nonce());
    let exit_endpoint = start
        .relay_ready
        .exit_ready
        .exit_ready
        .message()
        .exit_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Exit endpoint"))?;
    let exit_lease = result
        .message()
        .exit_lease
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Exit lease proof"))?;
    let matches = result.message().scope == start.start.message().scope
        && result.message().permit_hash == expected_permit
        && result.message().exit_ready_hash == expected_ready
        && lease_matches_endpoint(exit_lease, exit_endpoint)
        && result.message().expires_at_ms <= start.start.message().expires_at_ms
        && result.message().expires_at_ms
            <= start
                .relay_ready
                .exit_ready
                .exit_ready
                .message()
                .expires_at_ms;
    if !matches {
        let _ = replay.rollback(&entry.0, &entry.1);
        return Err(ProtocolError::InvalidField(
            "native Exit-result readiness binding",
        ));
    }
    Ok(VerifiedNativeProbeExitResult {
        start,
        signed_exit_result,
        exit_result: result,
    })
}

/// Consume a verified Relay-side chain and sign one endpoint-free terminal result.
///
/// # Errors
///
/// Returns an error unless both Relay leases, forwarding fence, signer, and lifetime bind exactly.
pub fn sign_native_probe_relay_result(
    exit_result: VerifiedNativeProbeExitResult,
    local_proofs: NativeProbeRelayLocalProofs,
    signing_key: &SigningKey,
    measured_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
) -> Result<IssuedNativeProbeRelayResult, ProtocolError> {
    sign_native_probe_relay_result_with(
        exit_result,
        local_proofs,
        signing_key.verifying_key().to_bytes(),
        measured_at_ms,
        nonce,
        |message| Some(signing_key.sign(message).to_bytes()),
    )
}

/// Sign one terminal Relay result through an external `Ed25519` identity provider.
///
/// The verified chain and all local proofs are consumed. Consequently this producer path cannot
/// sign a second result or substitute a Relay lease after a signing attempt.
///
/// # Errors
///
/// Returns an error unless both Relay leases, forwarding fence, signer, and lifetime bind exactly.
pub fn sign_native_probe_relay_result_with<F>(
    exit_result: VerifiedNativeProbeExitResult,
    local_proofs: NativeProbeRelayLocalProofs,
    relay_public_key: [u8; KEY_LENGTH],
    measured_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
    signer: F,
) -> Result<IssuedNativeProbeRelayResult, ProtocolError>
where
    F: FnOnce(&[u8]) -> Option<[u8; 64]>,
{
    let start = &exit_result.start.start;
    let scope = required_scope(start.message().scope.as_ref())?;
    local_proofs.relay_client_lease.validate_for_scope(scope)?;
    local_proofs.relay_exit_lease.validate_for_scope(scope)?;
    local_proofs.forwarding.validate()?;
    let relay_client_endpoint = exit_result
        .start
        .relay_ready
        .relay_ready
        .relay_client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayClient endpoint"))?;
    let relay_exit_endpoint = &exit_result.start.relay_ready.relay_exit_endpoint;
    if !lease_matches_endpoint(&local_proofs.relay_client_lease, relay_client_endpoint)
        || !lease_matches_endpoint(&local_proofs.relay_exit_lease, relay_exit_endpoint)
    {
        return Err(ProtocolError::InvalidField(
            "native Relay-result prepared bindings",
        ));
    }
    let ready = &exit_result.start.relay_ready;
    let expires_at_ms = start
        .message()
        .expires_at_ms
        .min(exit_result.exit_result.message().expires_at_ms);
    let relay_result = NativeProbeRelayResult {
        permit_hash: ready.relay_ready.permit_hash.clone(),
        relay_ready_hash: native_probe_relay_ready_hash(&ready.signed_relay_ready)?.to_vec(),
        start_hash: native_probe_start_hash(&exit_result.start.signed_start)?.to_vec(),
        scope: start.message().scope.clone(),
        challenge_hash: start
            .message()
            .scope
            .as_ref()
            .ok_or(ProtocolError::InvalidField("native start scope"))?
            .challenge_hash
            .clone(),
        relay_client_lease: Some(local_proofs.relay_client_lease),
        relay_exit_lease: Some(local_proofs.relay_exit_lease),
        forwarding: Some(local_proofs.forwarding),
        exit_result_hash: native_probe_exit_result_hash(&exit_result.signed_exit_result)?.to_vec(),
        signed_exit_result: exit_result.signed_exit_result,
        measured_at_ms,
        expires_at_ms,
        nonce: nonce.to_vec(),
    };
    let signed_relay_result = crate::sign_control_message_with(
        &relay_result,
        relay_public_key,
        measured_at_ms,
        expires_at_ms,
        nonce,
        native_time_policy(),
        signer,
    )?;
    Ok(IssuedNativeProbeRelayResult {
        signed_relay_result,
    })
}

/// Verify client-facing Relay readiness against one exact permit.
///
/// # Errors
///
/// Returns an error for invalid readiness, replay state, or an inexact permit binding.
pub fn verify_native_probe_relay_ready(
    permit: VerifiedNativeProbePermit,
    signed_relay_ready: Vec<u8>,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbeRelayReady, ProtocolError> {
    let expected_permit_hash = native_probe_permit_hash(&permit.signed_permit)?;
    let ready = verify_control_message::<NativeProbeRelayReady>(
        &signed_relay_ready,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let entry = (*ready.sender_id(), *ready.nonce());
    let matches = ready.message().scope == permit.permit.message().scope
        && ready.message().permit_hash == expected_permit_hash
        && ready.message().expires_at_ms <= permit.permit.message().expires_at_ms;
    if !matches {
        let _ = replay.rollback(&entry.0, &entry.1);
        return Err(ProtocolError::InvalidField("native Relay-ready binding"));
    }
    Ok(VerifiedNativeProbeRelayReady {
        permit,
        signed_relay_ready,
        relay_ready: ready,
    })
}

/// Consume Relay readiness and sign exactly one client start.
///
/// # Errors
///
/// Returns an error unless the client binding, session signer, hashes, and lifetime match exactly.
pub fn sign_native_probe_start(
    ready: VerifiedNativeProbeRelayReady,
    client_endpoint: NativeProbeEndpointBinding,
    signing_key: &SigningKey,
    started_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
) -> Result<IssuedNativeProbeStart, ProtocolError> {
    let scope = ready
        .relay_ready
        .message()
        .scope
        .clone()
        .ok_or(ProtocolError::InvalidField("native Relay-ready scope"))?;
    let session_public_key = signing_key.verifying_key().to_bytes();
    if session_public_key != scope.client_session_public_key.as_slice()
        || node_id_from_public_key(&session_public_key) != scope.client_session_id.as_slice()
    {
        return Err(ProtocolError::InvalidField("native start session key"));
    }
    let start = NativeProbeStart {
        permit_hash: ready.relay_ready.message().permit_hash.clone(),
        relay_ready_hash: native_probe_relay_ready_hash(&ready.signed_relay_ready)?.to_vec(),
        scope: Some(scope),
        client_endpoint: Some(client_endpoint),
        started_at_ms,
        expires_at_ms: ready.relay_ready.message().expires_at_ms,
        nonce: nonce.to_vec(),
    };
    let signed_start = sign_control_message(
        &start,
        signing_key,
        started_at_ms,
        start.expires_at_ms,
        nonce,
        native_time_policy(),
    )?;
    Ok(IssuedNativeProbeStart {
        relay_ready: ready,
        signed_start,
        start,
    })
}

/// Consume one issued start and verify both the Relay result and its exact nested Exit result.
///
/// # Errors
///
/// Returns an error for invalid signatures, replay, phase hashes, lifetimes, or helper proofs.
pub fn verify_native_probe_result(
    start: IssuedNativeProbeStart,
    client_lease: NativeProbeLeaseProof,
    signed_relay_result: &[u8],
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<VerifiedNativeProbeResult, ProtocolError> {
    let scope = required_scope(start.start.scope.as_ref())?;
    client_lease.validate_for_scope(scope)?;
    let expected_permit = native_probe_permit_hash(&start.relay_ready.permit.signed_permit)?;
    let expected_ready = native_probe_relay_ready_hash(&start.relay_ready.signed_relay_ready)?;
    let expected_start = native_probe_start_hash(&start.signed_start)?;
    let expected_challenge = scope.challenge_hash.clone();
    let verified_relay = verify_control_message::<NativeProbeRelayResult>(
        signed_relay_result,
        now_ms,
        native_time_policy(),
        replay,
    )?;
    let relay_entry = (*verified_relay.sender_id(), *verified_relay.nonce());
    let outer_matches = verified_relay.message().scope == start.start.scope
        && verified_relay.message().permit_hash == expected_permit
        && verified_relay.message().relay_ready_hash == expected_ready
        && verified_relay.message().start_hash == expected_start
        && verified_relay.message().challenge_hash == expected_challenge
        && verified_relay.message().expires_at_ms <= start.start.expires_at_ms;
    if !outer_matches {
        let _ = replay.rollback(&relay_entry.0, &relay_entry.1);
        return Err(ProtocolError::InvalidField("native Relay-result binding"));
    }
    let exit = match verify_control_message::<NativeProbeExitResult>(
        &verified_relay.message().signed_exit_result,
        now_ms,
        native_time_policy(),
        replay,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = replay.rollback(&relay_entry.0, &relay_entry.1);
            return Err(error);
        }
    };
    let exit_entry = (*exit.sender_id(), *exit.nonce());
    let relay_client_endpoint = start
        .relay_ready
        .relay_ready
        .message()
        .relay_client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native RelayClient endpoint"))?;
    let relay_client_lease =
        verified_relay
            .message()
            .relay_client_lease
            .as_ref()
            .ok_or(ProtocolError::InvalidField(
                "native RelayClient lease proof",
            ))?;
    let client_endpoint = start
        .start
        .client_endpoint
        .as_ref()
        .ok_or(ProtocolError::InvalidField("native Client endpoint"))?;
    let nested_hash =
        match native_probe_exit_result_hash(&verified_relay.message().signed_exit_result) {
            Ok(value) => value,
            Err(error) => {
                rollback_pair(replay, exit_entry, relay_entry);
                return Err(error);
            }
        };
    let nested_matches = exit.message().scope == start.start.scope
        && exit.message().permit_hash == expected_permit
        && exit.message().exit_ready_hash
            == start.relay_ready.relay_ready.message().exit_ready_hash
        && native_probe_challenge_hash(&fixed_array::<NONCE_LENGTH>(
            &exit.message().challenge_response,
            "native Exit challenge response",
        )?) == verified_relay.message().challenge_hash.as_slice()
        && lease_matches_endpoint(&client_lease, client_endpoint)
        && lease_matches_endpoint(relay_client_lease, relay_client_endpoint)
        && exit.message().expires_at_ms <= verified_relay.message().expires_at_ms
        && verified_relay.message().exit_result_hash == nested_hash;
    if !nested_matches {
        rollback_pair(replay, exit_entry, relay_entry);
        return Err(ProtocolError::InvalidField("native Exit-result binding"));
    }
    Ok(VerifiedNativeProbeResult {
        start,
        client_lease,
        _relay_result: verified_relay,
        exit_result: exit,
    })
}

fn native_time_policy() -> TimePolicy {
    TimePolicy {
        maximum_lifetime_ms: MAX_NATIVE_PROBE_LIFETIME_MS,
        maximum_clock_skew_ms: TimePolicy::default().maximum_clock_skew_ms,
    }
}

fn required_actor<'a>(
    actor: Option<&'a PreselectionActorBinding>,
    field: &'static str,
) -> Result<&'a PreselectionActorBinding, ProtocolError> {
    let actor = actor.ok_or(ProtocolError::InvalidField(field))?;
    actor.validate(field)?;
    Ok(actor)
}

fn required_scope(
    scope: Option<&NativeProbePathScope>,
) -> Result<&NativeProbePathScope, ProtocolError> {
    let scope = scope.ok_or(ProtocolError::InvalidField("native probe scope"))?;
    scope.validate()?;
    Ok(scope)
}

fn same_actor(left: &PreselectionActorBinding, right: &PreselectionActorBinding) -> bool {
    left.node_id == right.node_id
        || left.peer_id == right.peer_id
        || left.public_key == right.public_key
}

fn actor_ceiling(actor: &PreselectionActorBinding) -> u64 {
    actor
        .advertisement_expires_at_ms
        .min(actor.capability_expires_at_ms)
}

fn validate_scope_values(
    transport: i32,
    address_family: i32,
    policy_version: u64,
    policy_hash: &[u8],
    policy_expires_at_ms: u64,
) -> Result<(), ProtocolError> {
    if Transport::try_from(transport).map_or(true, |value| value == Transport::Unspecified)
        || ObservationAddressFamily::try_from(address_family)
            .map_or(true, |value| value == ObservationAddressFamily::Unspecified)
        || policy_version == 0
        || require_nonzero::<KEY_LENGTH>(policy_hash, "native probe policy hash").is_err()
        || policy_expires_at_ms == 0
    {
        return Err(ProtocolError::InvalidField("native probe scope values"));
    }
    Ok(())
}

fn scope_family(scope: &NativeProbePathScope) -> Result<ObservationAddressFamily, ProtocolError> {
    ObservationAddressFamily::try_from(scope.address_family)
        .ok()
        .filter(|family| *family != ObservationAddressFamily::Unspecified)
        .ok_or(ProtocolError::InvalidField("native probe address family"))
}

fn endpoint_family_matches(endpoint: &WireguardEndpoint, family: ObservationAddressFamily) -> bool {
    matches!(
        (endpoint.underlay_ip.len(), family),
        (4, ObservationAddressFamily::Ipv4) | (16, ObservationAddressFamily::Ipv6)
    )
}

fn lease_matches_endpoint(
    lease: &NativeProbeLeaseProof,
    endpoint: &NativeProbeEndpointBinding,
) -> bool {
    lease.helper_runtime_id == endpoint.helper_runtime_id
        && lease.route_context_id == endpoint.route_context_id
        && lease.prepared_lease_commitment == endpoint.prepared_lease_commitment
}

fn bindings_share_route_context(
    left: &NativeProbeEndpointBinding,
    right: &NativeProbeEndpointBinding,
) -> bool {
    left.route_context_id == right.route_context_id
}

fn bindings_collide(left: &NativeProbeEndpointBinding, right: &NativeProbeEndpointBinding) -> bool {
    left.prepared_lease_commitment == right.prepared_lease_commitment
        || left.endpoint == right.endpoint
        || left
            .endpoint
            .as_ref()
            .zip(right.endpoint.as_ref())
            .is_some_and(|(left, right)| {
                left.public_key == right.public_key
                    || (left.underlay_ip == right.underlay_ip
                        && left.listen_port == right.listen_port)
            })
}

fn bindings_are_local_pair(
    left: &NativeProbeEndpointBinding,
    right: &NativeProbeEndpointBinding,
) -> bool {
    left.helper_runtime_id == right.helper_runtime_id
        && bindings_share_route_context(left, right)
        && !bindings_collide(left, right)
}

fn bindings_are_remote_pair(
    left: &NativeProbeEndpointBinding,
    right: &NativeProbeEndpointBinding,
) -> bool {
    left.helper_runtime_id != right.helper_runtime_id
        && bindings_share_route_context(left, right)
        && !bindings_collide(left, right)
}

fn bindings_form_relay_exit_topology(
    relay_client: &NativeProbeEndpointBinding,
    relay_exit: &NativeProbeEndpointBinding,
    exit: &NativeProbeEndpointBinding,
) -> bool {
    bindings_are_local_pair(relay_client, relay_exit)
        && bindings_are_remote_pair(relay_client, exit)
        && bindings_are_remote_pair(relay_exit, exit)
}

fn bindings_form_four_role_topology(
    client: &NativeProbeEndpointBinding,
    relay_client: &NativeProbeEndpointBinding,
    relay_exit: &NativeProbeEndpointBinding,
    exit: &NativeProbeEndpointBinding,
) -> bool {
    bindings_form_relay_exit_topology(relay_client, relay_exit, exit)
        && bindings_are_remote_pair(client, relay_client)
        && bindings_are_remote_pair(client, relay_exit)
        && bindings_are_remote_pair(client, exit)
}

fn validate_phase_lifetime(
    created_at_ms: u64,
    expires_at_ms: u64,
    scope: &NativeProbePathScope,
) -> Result<(), ProtocolError> {
    let lifetime = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or(ProtocolError::InvalidLifetime)?;
    if created_at_ms == 0
        || lifetime == 0
        || lifetime > MAX_NATIVE_PROBE_LIFETIME_MS
        || expires_at_ms > scope.attempt_expires_at_ms
    {
        return Err(ProtocolError::InvalidLifetime);
    }
    Ok(())
}

fn validate_envelope_binding(
    expected_sender: &[u8],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if envelope.sender_id != expected_sender
        || envelope.timestamp_ms != timestamp_ms
        || envelope.expires_at_ms != expires_at_ms
        || envelope.nonce != nonce
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_actor_signed_envelope(
    actor: &PreselectionActorBinding,
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if envelope.sender_public_key != actor.public_key {
        return Err(ProtocolError::InvalidField(field));
    }
    validate_envelope_binding(
        &actor.node_id,
        timestamp_ms,
        expires_at_ms,
        nonce,
        envelope,
        field,
    )
}

fn validate_client_session_signed_envelope(
    scope: &NativeProbePathScope,
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if envelope.sender_public_key != scope.client_session_public_key {
        return Err(ProtocolError::InvalidField(field));
    }
    validate_envelope_binding(
        &scope.client_session_id,
        timestamp_ms,
        expires_at_ms,
        nonce,
        envelope,
        field,
    )
}

fn require_nonzero<const LENGTH: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; LENGTH], ProtocolError> {
    let value = fixed_array::<LENGTH>(value, field)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(value)
}

fn hash_exact(domain: &[u8], value: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::Oversized {
        what: "native probe hash input",
        maximum: MAX_CONTROL_MESSAGE_SIZE,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(hasher.finalize().into())
}

fn hash_signed<T: ControlPayload>(
    domain: &[u8],
    value: &[u8],
) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    precheck_signed_type::<T>(value)?;
    hash_exact(domain, value)
}

fn precheck_signed_type<T: ControlPayload>(value: &[u8]) -> Result<SignedEnvelope, ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(value, MAX_CONTROL_MESSAGE_SIZE)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != T::MESSAGE_TYPE as i32
    {
        return Err(ProtocolError::InvalidField(
            "native probe signed message type",
        ));
    }
    Ok(envelope)
}

fn rollback_pair(
    replay: &mut ReplayCache,
    first: ([u8; KEY_LENGTH], [u8; NONCE_LENGTH]),
    second: ([u8; KEY_LENGTH], [u8; NONCE_LENGTH]),
) {
    let _ = replay.rollback(&first.0, &first.1);
    let _ = replay.rollback(&second.0, &second.1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_900_000_000_000;
    const EXPIRY: u64 = NOW + 30_000;

    struct Fixture {
        client: SigningKey,
        control: SigningKey,
        relay: SigningKey,
        exit: SigningKey,
        scope: NativeProbePathScope,
    }

    impl Fixture {
        fn new() -> Self {
            let client = SigningKey::from_bytes(&[1; 32]);
            let control = SigningKey::from_bytes(&[2; 32]);
            let relay = SigningKey::from_bytes(&[3; 32]);
            let exit = SigningKey::from_bytes(&[4; 32]);
            let control_actor = actor(&control, 2);
            let relay_actor = actor(&relay, 3);
            let exit_actor = actor(&exit, 4);
            let first_data_relay = actor(&SigningKey::from_bytes(&[5; 32]), 5);
            let set = NativeProbeCandidateSet {
                protocol_version: PROTOCOL_VERSION,
                preselection_batch_id: vec![9; 16],
                control: Some(control_actor.clone()),
                exit: Some(exit_actor.clone()),
                data_relays: vec![first_data_relay, relay_actor.clone()],
                transport: Transport::TcpMptcp as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: 7,
                policy_hash: vec![8; 32],
                policy_expires_at_ms: EXPIRY + 30_000,
            };
            let challenge = [7; 32];
            let scope = NativeProbePathScope {
                attempt_id: vec![1; 16],
                probe_id: vec![2; 16],
                candidate_set_hash: native_probe_candidate_set_hash(&set)
                    .expect("candidate set")
                    .to_vec(),
                candidate_ordinal: 2,
                data_relay: Some(relay_actor),
                control: Some(control_actor),
                exit: Some(exit_actor),
                client_session_id: node_id_from_public_key(&client.verifying_key().to_bytes())
                    .to_vec(),
                client_session_public_key: client.verifying_key().to_bytes().to_vec(),
                transport: Transport::TcpMptcp as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: 7,
                policy_hash: vec![8; 32],
                policy_expires_at_ms: EXPIRY + 30_000,
                challenge_hash: native_probe_challenge_hash(&challenge).to_vec(),
                attempt_expires_at_ms: EXPIRY,
                required_path_count: 2,
                reserved_up_mbps: 10,
                reserved_down_mbps: 20,
            };
            Self {
                client,
                control,
                relay,
                exit,
                scope,
            }
        }

        fn signed_request(&self) -> Vec<u8> {
            let request = NativeProbePermitRequest {
                scope: Some(self.scope.clone()),
                created_at_ms: NOW,
                expires_at_ms: EXPIRY,
                nonce: vec![10; 32],
            };
            sign(&request, &self.client, NOW, EXPIRY, [10; 32])
        }

        fn signed_permit(&self, request: &[u8]) -> Vec<u8> {
            let permit = NativeProbePermit {
                request_hash: native_probe_permit_request_hash(request)
                    .expect("request hash")
                    .to_vec(),
                scope: Some(self.scope.clone()),
                issued_at_ms: NOW + 1,
                expires_at_ms: EXPIRY,
                nonce: vec![11; 32],
                exit_control_address: "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/exit".to_owned(),
            };
            sign(&permit, &self.exit, NOW + 1, EXPIRY, [11; 32])
        }

        fn signed_relay_ready(&self, permit: &[u8]) -> Vec<u8> {
            self.signed_relay_ready_with_exit_hash(permit, [12; 32])
        }

        fn signed_relay_ready_with_exit_hash(
            &self,
            permit: &[u8],
            exit_ready_hash: [u8; 32],
        ) -> Vec<u8> {
            let ready = NativeProbeRelayReady {
                permit_hash: native_probe_permit_hash(permit)
                    .expect("permit hash")
                    .to_vec(),
                exit_ready_hash: exit_ready_hash.to_vec(),
                scope: Some(self.scope.clone()),
                relay_client_endpoint: Some(endpoint(20, [3; 32], [80, 1, 1, 1])),
                ready_at_ms: NOW + 2,
                expires_at_ms: EXPIRY,
                nonce: vec![13; 32],
            };
            sign(&ready, &self.relay, NOW + 2, EXPIRY, [13; 32])
        }

        fn signed_exit_ready(&self, permit: &[u8]) -> Vec<u8> {
            let ready = NativeProbeExitReady {
                permit_hash: native_probe_permit_hash(permit)
                    .expect("permit hash")
                    .to_vec(),
                scope: Some(self.scope.clone()),
                relay_exit_endpoint: Some(endpoint(30, [30; 32], [83, 1, 1, 1])),
                exit_endpoint: Some(endpoint(31, [4; 32], [84, 1, 1, 1])),
                ready_at_ms: NOW + 2,
                expires_at_ms: EXPIRY,
                nonce: vec![12; 32],
                exit_boot_id: vec![0xb0; 16],
            };
            sign(&ready, &self.exit, NOW + 2, EXPIRY, [12; 32])
        }
    }

    fn actor(key: &SigningKey, seed: u8) -> PreselectionActorBinding {
        let public = key.verifying_key().to_bytes();
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public).to_vec(),
            peer_id: vec![seed; 38],
            public_key: public.to_vec(),
            advertisement_sequence: u64::from(seed),
            advertisement_expires_at_ms: EXPIRY + 60_000,
            advertisement_payload_hash: vec![seed; 32],
            capability_expires_at_ms: EXPIRY + 30_000,
        }
    }

    fn endpoint(port: u8, key: [u8; 32], address: [u8; 4]) -> NativeProbeEndpointBinding {
        NativeProbeEndpointBinding {
            helper_runtime_id: vec![helper_runtime_seed(port); 32],
            route_context_id: vec![1; 16],
            endpoint: Some(WireguardEndpoint {
                public_key: key.to_vec(),
                underlay_ip: address.to_vec(),
                listen_port: 10_000 + u32::from(port),
            }),
            prepared_lease_commitment: vec![port; 32],
            path_id: 2,
        }
    }

    fn lease(seed: u8) -> NativeProbeLeaseProof {
        NativeProbeLeaseProof {
            helper_runtime_id: vec![helper_runtime_seed(seed); 32],
            route_context_id: vec![1; 16],
            prepared_lease_commitment: vec![seed; 32],
            latest_handshake_unix: NOW / 1_000,
            received_bytes_after_baseline: 64,
            transmitted_bytes_after_baseline: 64,
        }
    }

    fn helper_runtime_seed(endpoint_seed: u8) -> u8 {
        match endpoint_seed {
            20 | 30 => 3,
            21 => 1,
            31 => 4,
            other => other,
        }
    }

    fn forwarding_proof() -> NativeProbeForwardingProof {
        NativeProbeForwardingProof {
            client_to_exit_packets_after_baseline: 1,
            client_to_exit_bytes_after_baseline: 64,
            exit_to_client_packets_after_baseline: 1,
            exit_to_client_bytes_after_baseline: 64,
            terminal_drop_packets_after_baseline: 0,
            terminal_drop_bytes_after_baseline: 0,
        }
    }

    fn exit_result(
        fixture: &Fixture,
        permit: &[u8],
        exit_ready_hash: [u8; 32],
        exit_lease_seed: u8,
    ) -> NativeProbeExitResult {
        NativeProbeExitResult {
            permit_hash: native_probe_permit_hash(permit)
                .expect("permit hash")
                .to_vec(),
            exit_ready_hash: exit_ready_hash.to_vec(),
            scope: Some(fixture.scope.clone()),
            challenge_response: vec![7; 32],
            observed_network_prefix: Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: vec![82, 1, 1],
            }),
            exit_lease: Some(lease(exit_lease_seed)),
            measured_at_ms: NOW + 5,
            expires_at_ms: EXPIRY,
            nonce: vec![16; 32],
        }
    }

    fn relay_result_payload(
        fixture: &Fixture,
        permit: &[u8],
        start: &IssuedNativeProbeStart,
        signed_exit_result: Vec<u8>,
        measured_at_ms: u64,
    ) -> NativeProbeRelayResult {
        NativeProbeRelayResult {
            permit_hash: native_probe_permit_hash(permit)
                .expect("permit hash")
                .to_vec(),
            relay_ready_hash: native_probe_relay_ready_hash(&start.relay_ready.signed_relay_ready)
                .expect("Relay-ready hash")
                .to_vec(),
            start_hash: native_probe_start_hash(&start.signed_start)
                .expect("start hash")
                .to_vec(),
            scope: Some(fixture.scope.clone()),
            challenge_hash: fixture.scope.challenge_hash.clone(),
            relay_client_lease: Some(lease(20)),
            relay_exit_lease: Some(lease(30)),
            forwarding: Some(forwarding_proof()),
            exit_result_hash: native_probe_exit_result_hash(&signed_exit_result)
                .expect("Exit-result hash")
                .to_vec(),
            signed_exit_result,
            measured_at_ms,
            expires_at_ms: EXPIRY,
            nonce: vec![17; 32],
        }
    }

    fn sign<T: ControlPayload>(
        value: &T,
        key: &SigningKey,
        timestamp: u64,
        expiry: u64,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        sign_control_message(value, key, timestamp, expiry, nonce, native_time_policy())
            .expect("signed fixture")
    }

    fn issue_relay_ready(
        fixture: &Fixture,
        request: &[u8],
        permit: &[u8],
        exit_ready: &[u8],
        replay: &mut ReplayCache,
    ) -> IssuedNativeProbeRelayReady {
        let permit = verify_native_probe_permit(request.to_vec(), permit.to_vec(), NOW + 2, replay)
            .expect("Relay permit");
        let ready = verify_native_probe_exit_ready(permit, exit_ready.to_vec(), NOW + 3, replay)
            .expect("Relay Exit-ready");
        sign_native_probe_relay_ready(
            ready,
            endpoint(20, [3; 32], [80, 1, 1, 1]),
            endpoint(30, [30; 32], [83, 1, 1, 1]),
            &fixture.relay,
            NOW + 3,
            [13; 32],
        )
        .expect("issued Relay-ready")
    }

    fn signed_start_for_relay(
        fixture: &Fixture,
        permit: &[u8],
        relay_ready: &IssuedNativeProbeRelayReady,
        client_endpoint: NativeProbeEndpointBinding,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let start = NativeProbeStart {
            permit_hash: native_probe_permit_hash(permit)
                .expect("permit hash")
                .to_vec(),
            relay_ready_hash: native_probe_relay_ready_hash(relay_ready.encoded_relay_ready())
                .expect("Relay-ready hash")
                .to_vec(),
            scope: Some(fixture.scope.clone()),
            client_endpoint: Some(client_endpoint),
            started_at_ms: NOW + 4,
            expires_at_ms: EXPIRY,
            nonce: nonce.to_vec(),
        };
        sign(&start, &fixture.client, NOW + 4, EXPIRY, nonce)
    }

    #[test]
    fn candidate_set_is_canonical_endpoint_free_and_control_separate() {
        let fixture = Fixture::new();
        let set = NativeProbeCandidateSet {
            protocol_version: PROTOCOL_VERSION,
            preselection_batch_id: vec![9; 16],
            control: fixture.scope.control.clone(),
            exit: fixture.scope.exit.clone(),
            data_relays: vec![
                actor(&SigningKey::from_bytes(&[5; 32]), 5),
                fixture.scope.data_relay.clone().expect("relay"),
            ],
            transport: fixture.scope.transport,
            address_family: fixture.scope.address_family,
            policy_version: fixture.scope.policy_version,
            policy_hash: fixture.scope.policy_hash.clone(),
            policy_expires_at_ms: fixture.scope.policy_expires_at_ms,
        };
        let encoded = encode_canonical(&set, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical set");
        assert_eq!(
            decode_canonical::<NativeProbeCandidateSet>(&encoded, MAX_CONTROL_PAYLOAD_SIZE)
                .expect("decoded set"),
            set
        );
        assert!(set.validate().is_ok());
        let mut reordered = set.clone();
        reordered.data_relays.swap(0, 1);
        assert!(reordered.validate().is_ok());
        assert_ne!(
            native_probe_candidate_set_hash(&reordered).expect("reordered hash"),
            native_probe_candidate_set_hash(&set).expect("original hash")
        );
        let mut control_as_data = set;
        control_as_data.data_relays[0] = control_as_data.control.clone().expect("control");
        assert!(control_as_data.validate().is_err());
    }

    #[test]
    fn nine_preselection_candidates_are_distinct_from_the_eight_path_route_bound() {
        let fixture = Fixture::new();
        let control = fixture.scope.control.clone().expect("control");
        let mut candidates = Vec::new();
        for seed in 10_u8..=17 {
            candidates.push(actor(&SigningKey::from_bytes(&[seed; 32]), seed));
        }
        assert_eq!(candidates.len(), MAX_NATIVE_PROBE_CANDIDATES);
        let mut set = NativeProbeCandidateSet {
            protocol_version: PROTOCOL_VERSION,
            preselection_batch_id: vec![9; 16],
            control: Some(control),
            exit: fixture.scope.exit.clone(),
            data_relays: candidates.clone(),
            transport: fixture.scope.transport,
            address_family: fixture.scope.address_family,
            policy_version: fixture.scope.policy_version,
            policy_hash: fixture.scope.policy_hash.clone(),
            policy_expires_at_ms: fixture.scope.policy_expires_at_ms,
        };
        assert!(set.validate().is_ok(), "eight selected data Relays");

        let mut ninth_alternative = actor(&SigningKey::from_bytes(&[18; 32]), 18);
        ninth_alternative.advertisement_sequence = 18;
        set.data_relays.push(ninth_alternative.clone());
        assert!(set.validate().is_err(), "nine data Relays must fail closed");

        let mut bounded_ordinal = fixture.scope.clone();
        bounded_ordinal.required_path_count = 8;
        bounded_ordinal.candidate_ordinal = 8;
        bounded_ordinal.data_relay = Some(candidates[7].clone());
        assert!(bounded_ordinal.validate().is_ok());
        bounded_ordinal.candidate_ordinal = 9;
        bounded_ordinal.data_relay = Some(ninth_alternative);
        assert!(bounded_ordinal.validate().is_err());
    }

    #[test]
    fn native_path_scope_requires_protocol_bounded_reserved_capacity() {
        let fixture = Fixture::new();
        assert!(fixture.scope.validate().is_ok());

        let mut zero_upload = fixture.scope.clone();
        zero_upload.reserved_up_mbps = 0;
        assert!(zero_upload.validate().is_err());

        let mut zero_download = fixture.scope.clone();
        zero_download.reserved_down_mbps = 0;
        assert!(zero_download.validate().is_err());

        let mut excessive_upload = fixture.scope.clone();
        excessive_upload.reserved_up_mbps = u64::MAX;
        assert!(excessive_upload.validate().is_err());

        let mut excessive_download = fixture.scope;
        excessive_download.reserved_down_mbps = u64::MAX;
        assert!(excessive_download.validate().is_err());
    }

    #[test]
    fn permit_verifier_rolls_back_cross_binding_and_commits_success() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);
        let mut wrong_payload: NativeProbePermit = {
            let envelope: SignedEnvelope =
                decode_canonical(&permit, MAX_CONTROL_MESSAGE_SIZE).expect("permit envelope");
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("permit")
        };
        wrong_payload.request_hash[0] ^= 1;
        wrong_payload.nonce = vec![14; 32];
        let wrong = sign(&wrong_payload, &fixture.exit, NOW + 1, EXPIRY, [14; 32]);
        let mut replay = ReplayCache::new(16).expect("replay");
        assert!(verify_native_probe_permit(request.clone(), wrong, NOW + 2, &mut replay).is_err());
        assert!(
            replay.is_empty(),
            "cross-binding failure must roll back both entries"
        );
        let verified =
            verify_native_probe_permit(request.clone(), permit.clone(), NOW + 2, &mut replay)
                .expect("exact Permit");
        assert_eq!(
            verified.exit_control_address(),
            "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/exit"
        );
        assert!(matches!(
            verify_native_probe_permit(request, permit, NOW + 2, &mut replay),
            Err(ProtocolError::Replay)
        ));
    }

    #[test]
    fn exit_readiness_requires_one_shared_route_context_and_distinct_helper_runtimes() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);
        let signed = fixture.signed_exit_ready(&permit);
        let envelope: SignedEnvelope =
            decode_canonical(&signed, MAX_CONTROL_MESSAGE_SIZE).expect("Exit-ready envelope");
        let ready: NativeProbeExitReady =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("Exit-ready");
        assert!(ready.validate().is_ok(), "shared route context is required");

        let mut same_runtime = ready.clone();
        same_runtime
            .exit_endpoint
            .as_mut()
            .expect("Exit endpoint")
            .helper_runtime_id = same_runtime
            .relay_exit_endpoint
            .as_ref()
            .expect("RelayExit endpoint")
            .helper_runtime_id
            .clone();
        assert!(same_runtime.validate().is_err());

        let mut colliding = ready.clone();
        colliding.exit_endpoint = colliding.relay_exit_endpoint.clone();
        assert!(colliding.validate().is_err());

        let mut colliding_socket = ready.clone();
        let relay_socket = colliding_socket
            .relay_exit_endpoint
            .as_ref()
            .and_then(|binding| binding.endpoint.as_ref())
            .expect("RelayExit socket")
            .clone();
        let exit_socket = colliding_socket
            .exit_endpoint
            .as_mut()
            .and_then(|binding| binding.endpoint.as_mut())
            .expect("Exit socket");
        exit_socket.underlay_ip = relay_socket.underlay_ip;
        exit_socket.listen_port = relay_socket.listen_port;
        assert_ne!(exit_socket.public_key, relay_socket.public_key);
        assert!(colliding_socket.validate().is_err());

        let mut split_route = ready;
        split_route
            .exit_endpoint
            .as_mut()
            .expect("Exit endpoint")
            .route_context_id = vec![43; 16];
        assert!(split_route.validate().is_err());
    }

    #[test]
    fn every_endpoint_and_lease_binding_is_scoped_to_the_shared_attempt_id() {
        let fixture = Fixture::new();
        for binding in [
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            endpoint(20, [3; 32], [80, 1, 1, 1]),
            endpoint(30, [30; 32], [83, 1, 1, 1]),
            endpoint(31, [4; 32], [84, 1, 1, 1]),
        ] {
            assert!(binding.validate_for_scope(&fixture.scope).is_ok());
            let mut substituted = binding;
            substituted.route_context_id = vec![43; 16];
            assert!(substituted.validate_for_scope(&fixture.scope).is_err());
        }
        for proof in [lease(21), lease(20), lease(30), lease(31)] {
            assert!(proof.validate_for_scope(&fixture.scope).is_ok());
            let mut substituted = proof;
            substituted.route_context_id = vec![43; 16];
            assert!(substituted.validate_for_scope(&fixture.scope).is_err());
        }
    }

    #[test]
    fn readiness_verifiers_roll_back_cross_binding_mutants() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);

        let signed_exit_ready = fixture.signed_exit_ready(&permit);
        let exit_envelope: SignedEnvelope =
            decode_canonical(&signed_exit_ready, MAX_CONTROL_MESSAGE_SIZE).expect("Exit-ready");
        let mut wrong_exit_ready: NativeProbeExitReady =
            decode_canonical(&exit_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("payload");
        wrong_exit_ready.permit_hash[0] ^= 1;
        wrong_exit_ready.nonce = vec![22; 32];
        let wrong_exit_ready = sign(&wrong_exit_ready, &fixture.exit, NOW + 2, EXPIRY, [22; 32]);
        let mut relay_replay = ReplayCache::new(16).expect("replay");
        let verified_permit =
            verify_native_probe_permit(request.clone(), permit.clone(), NOW + 2, &mut relay_replay)
                .expect("permit");
        assert!(
            verify_native_probe_exit_ready(
                verified_permit,
                wrong_exit_ready,
                NOW + 3,
                &mut relay_replay,
            )
            .is_err()
        );
        assert_eq!(relay_replay.len(), 2);

        let signed_relay_ready = fixture.signed_relay_ready(&permit);
        let relay_envelope: SignedEnvelope =
            decode_canonical(&signed_relay_ready, MAX_CONTROL_MESSAGE_SIZE).expect("Relay-ready");
        let mut wrong_relay_ready: NativeProbeRelayReady =
            decode_canonical(&relay_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).expect("payload");
        wrong_relay_ready.permit_hash[0] ^= 1;
        wrong_relay_ready.nonce = vec![23; 32];
        let wrong_relay_ready = sign(
            &wrong_relay_ready,
            &fixture.relay,
            NOW + 2,
            EXPIRY,
            [23; 32],
        );
        let mut client_replay = ReplayCache::new(16).expect("replay");
        let verified_permit =
            verify_native_probe_permit(request, permit, NOW + 2, &mut client_replay)
                .expect("permit");
        assert!(
            verify_native_probe_relay_ready(
                verified_permit,
                wrong_relay_ready,
                NOW + 3,
                &mut client_replay,
            )
            .is_err()
        );
        assert_eq!(client_replay.len(), 2);
    }

    #[test]
    fn permit_hash_chain_accepts_exit_clock_behind_client() {
        let fixture = Fixture::new();
        let future_request = NativeProbePermitRequest {
            scope: Some(fixture.scope.clone()),
            created_at_ms: NOW + 10,
            expires_at_ms: EXPIRY,
            nonce: vec![24; 32],
        };
        let future_request = sign(&future_request, &fixture.client, NOW + 10, EXPIRY, [24; 32]);
        let early_permit = NativeProbePermit {
            request_hash: native_probe_permit_request_hash(&future_request)
                .expect("request hash")
                .to_vec(),
            scope: Some(fixture.scope.clone()),
            issued_at_ms: NOW,
            expires_at_ms: EXPIRY,
            nonce: vec![25; 32],
            exit_control_address: "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/exit".to_owned(),
        };
        let early_permit = sign(&early_permit, &fixture.exit, NOW, EXPIRY, [25; 32]);
        let mut early_exit_replay = ReplayCache::new(16).expect("replay");
        verify_native_probe_permit(
            future_request,
            early_permit,
            NOW + 11,
            &mut early_exit_replay,
        )
        .expect("an Exit clock behind the client must remain valid within signed windows");
    }

    #[test]
    fn ready_and_start_hash_chain_accepts_relay_and_client_clocks_behind() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let late_permit = NativeProbePermit {
            request_hash: native_probe_permit_request_hash(&request)
                .expect("request hash")
                .to_vec(),
            scope: Some(fixture.scope.clone()),
            issued_at_ms: NOW + 20,
            expires_at_ms: EXPIRY,
            nonce: vec![26; 32],
            exit_control_address: "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/exit".to_owned(),
        };
        let late_permit = sign(&late_permit, &fixture.exit, NOW + 20, EXPIRY, [26; 32]);
        let early_ready = NativeProbeRelayReady {
            permit_hash: native_probe_permit_hash(&late_permit)
                .expect("permit hash")
                .to_vec(),
            exit_ready_hash: vec![12; 32],
            scope: Some(fixture.scope.clone()),
            relay_client_endpoint: Some(endpoint(20, [3; 32], [80, 1, 1, 1])),
            ready_at_ms: NOW + 10,
            expires_at_ms: EXPIRY,
            nonce: vec![27; 32],
        };
        let early_ready = sign(&early_ready, &fixture.relay, NOW + 10, EXPIRY, [27; 32]);
        let mut client_replay = ReplayCache::new(16).expect("replay");
        let permit = verify_native_probe_permit(request, late_permit, NOW + 21, &mut client_replay)
            .expect("late Exit permit");
        let ready =
            verify_native_probe_relay_ready(permit, early_ready, NOW + 21, &mut client_replay)
                .expect("Relay clock behind Exit");
        sign_native_probe_start(
            ready,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            &fixture.client,
            NOW + 1,
            [28; 32],
        )
        .expect("client clock behind Relay");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete signed native chain smoke keeps every phase transition visible"
    )]
    fn exact_relay_and_client_chains_verify_once_with_endpoint_bound_helper_proofs() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit_bytes = fixture.signed_permit(&request);
        let exit_ready_bytes = fixture.signed_exit_ready(&permit_bytes);
        let exit_ready_hash =
            native_probe_exit_ready_hash(&exit_ready_bytes).expect("Exit-ready hash");
        let exit_result = exit_result(&fixture, &permit_bytes, exit_ready_hash, 31);
        let signed_exit_result = sign(&exit_result, &fixture.exit, NOW + 5, EXPIRY, [16; 32]);

        let mut relay_replay = ReplayCache::new(16).expect("Relay replay");
        let relay_permit = verify_native_probe_permit(
            request.clone(),
            permit_bytes.clone(),
            NOW + 2,
            &mut relay_replay,
        )
        .expect("Relay verifies permit");
        let relay_ready = verify_native_probe_exit_ready(
            relay_permit,
            exit_ready_bytes,
            NOW + 3,
            &mut relay_replay,
        )
        .expect("Relay alone verifies Exit endpoints");
        let issued_relay_ready = sign_native_probe_relay_ready(
            relay_ready,
            endpoint(20, [3; 32], [80, 1, 1, 1]),
            endpoint(30, [30; 32], [83, 1, 1, 1]),
            &fixture.relay,
            NOW + 3,
            [13; 32],
        )
        .expect("Relay readiness requires both hidden local bindings");
        let relay_ready_bytes = issued_relay_ready.encoded_relay_ready().to_vec();

        let mut client_replay = ReplayCache::new(16).expect("client replay");
        let client_permit =
            verify_native_probe_permit(request, permit_bytes.clone(), NOW + 2, &mut client_replay)
                .expect("client verifies permit");
        let client_ready = verify_native_probe_relay_ready(
            client_permit,
            relay_ready_bytes,
            NOW + 3,
            &mut client_replay,
        )
        .expect("client sees only RelayClient readiness");
        let start = sign_native_probe_start(
            client_ready,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            &fixture.client,
            NOW + 4,
            [15; 32],
        )
        .expect("client start");
        let verified_start = verify_native_probe_start_for_relay(
            issued_relay_ready,
            start.encoded_start().to_vec(),
            NOW + 4,
            &mut relay_replay,
        )
        .expect("Relay binds Client endpoint to its local RelayClient endpoint");
        let authorization_chain = verified_start
            .authorization_chain()
            .expect("canonical authorization chain");
        let verified_authorization =
            verify_native_probe_authorization_chain(&authorization_chain, NOW + 4)
                .expect("Exit independently verifies all five signed phases");
        assert_eq!(verified_authorization.scope(), &fixture.scope);
        assert_eq!(
            verified_authorization.encoded_start(),
            start.encoded_start()
        );
        assert_eq!(verified_authorization.exit_boot_id(), &[0xb0; ID_LENGTH]);
        let mut substituted: NativeProbeAuthorizationChain = decode_canonical(
            &authorization_chain,
            MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE,
        )
        .expect("authorization bundle");
        substituted.signed_start = permit_bytes.clone();
        let substituted = encode_canonical(&substituted, MAX_NATIVE_PROBE_AUTHORIZATION_CHAIN_SIZE)
            .expect("substituted bundle");
        assert!(verify_native_probe_authorization_chain(&substituted, NOW + 4).is_err());
        let verified_exit_result = verify_native_probe_exit_result_for_relay(
            verified_start,
            signed_exit_result,
            NOW + 6,
            &mut relay_replay,
        )
        .expect("Exit result must match its hidden prepared endpoint");
        let issued_relay_result = sign_native_probe_relay_result(
            verified_exit_result,
            NativeProbeRelayLocalProofs {
                relay_client_lease: lease(20),
                relay_exit_lease: lease(30),
                forwarding: forwarding_proof(),
            },
            &fixture.relay,
            NOW + 6,
            [17; 32],
        )
        .expect("Relay result requires both local leases and forwarding fence");
        let signed_relay_result = issued_relay_result.encoded_relay_result().to_vec();
        verify_native_probe_result(
            start,
            lease(21),
            &signed_relay_result,
            NOW + 7,
            &mut client_replay,
        )
        .expect("exact four-endpoint proof chain");
        assert!(matches!(
            verify_control_message::<NativeProbeRelayResult>(
                &signed_relay_result,
                NOW + 7,
                native_time_policy(),
                &mut client_replay,
            ),
            Err(ProtocolError::Replay)
        ));
    }

    #[test]
    fn affine_relay_owner_rejects_hidden_endpoint_and_start_substitution() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);
        let exit_ready = fixture.signed_exit_ready(&permit);

        let mut substituted_ready_replay = ReplayCache::new(16).expect("replay");
        let verified_permit = verify_native_probe_permit(
            request.clone(),
            permit.clone(),
            NOW + 2,
            &mut substituted_ready_replay,
        )
        .expect("permit");
        let verified_ready = verify_native_probe_exit_ready(
            verified_permit,
            exit_ready.clone(),
            NOW + 3,
            &mut substituted_ready_replay,
        )
        .expect("Exit-ready");
        assert!(
            sign_native_probe_relay_ready(
                verified_ready,
                endpoint(20, [3; 32], [80, 1, 1, 1]),
                endpoint(32, [32; 32], [83, 1, 1, 1]),
                &fixture.relay,
                NOW + 3,
                [13; 32],
            )
            .is_err()
        );
        assert_eq!(
            substituted_ready_replay.len(),
            3,
            "a failed affine producer consumes no new replay entry"
        );

        let mut start_replay = ReplayCache::new(16).expect("replay");
        let owner = issue_relay_ready(&fixture, &request, &permit, &exit_ready, &mut start_replay);
        let relay_as_client = endpoint(20, [3; 32], [80, 1, 1, 1]);
        let wrong_start =
            signed_start_for_relay(&fixture, &permit, &owner, relay_as_client, [15; 32]);
        assert!(
            verify_native_probe_start_for_relay(owner, wrong_start, NOW + 4, &mut start_replay,)
                .is_err()
        );
        assert_eq!(
            start_replay.len(),
            3,
            "a rejected Start must roll back its replay entry"
        );

        let mut exit_collision_replay = ReplayCache::new(16).expect("replay");
        let owner = issue_relay_ready(
            &fixture,
            &request,
            &permit,
            &exit_ready,
            &mut exit_collision_replay,
        );
        let exit_as_client = endpoint(31, [4; 32], [84, 1, 1, 1]);
        let wrong_start =
            signed_start_for_relay(&fixture, &permit, &owner, exit_as_client, [15; 32]);
        assert!(
            verify_native_probe_start_for_relay(
                owner,
                wrong_start,
                NOW + 4,
                &mut exit_collision_replay,
            )
            .is_err()
        );
        assert_eq!(
            exit_collision_replay.len(),
            3,
            "Client may not reuse the hidden Exit runtime, endpoint, key, or commitment"
        );
    }

    #[test]
    fn affine_relay_owner_rejects_hidden_exit_and_relay_lease_substitution() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);
        let exit_ready = fixture.signed_exit_ready(&permit);

        let mut exit_lease_replay = ReplayCache::new(16).expect("replay");
        let owner = issue_relay_ready(
            &fixture,
            &request,
            &permit,
            &exit_ready,
            &mut exit_lease_replay,
        );
        let start = signed_start_for_relay(
            &fixture,
            &permit,
            &owner,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            [15; 32],
        );
        let start =
            verify_native_probe_start_for_relay(owner, start, NOW + 4, &mut exit_lease_replay)
                .expect("Start");
        let exit_ready_hash = native_probe_exit_ready_hash(&exit_ready).expect("Exit-ready hash");
        let wrong_exit = exit_result(&fixture, &permit, exit_ready_hash, 32);
        let wrong_exit = sign(&wrong_exit, &fixture.exit, NOW + 5, EXPIRY, [16; 32]);
        assert!(
            verify_native_probe_exit_result_for_relay(
                start,
                wrong_exit,
                NOW + 6,
                &mut exit_lease_replay,
            )
            .is_err()
        );
        assert_eq!(
            exit_lease_replay.len(),
            4,
            "a rejected Exit result must roll back only its replay entry"
        );

        let mut relay_lease_replay = ReplayCache::new(16).expect("replay");
        let owner = issue_relay_ready(
            &fixture,
            &request,
            &permit,
            &exit_ready,
            &mut relay_lease_replay,
        );
        let start = signed_start_for_relay(
            &fixture,
            &permit,
            &owner,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            [15; 32],
        );
        let start =
            verify_native_probe_start_for_relay(owner, start, NOW + 4, &mut relay_lease_replay)
                .expect("Start");
        let exit_result = exit_result(&fixture, &permit, exit_ready_hash, 31);
        let exit_result = sign(&exit_result, &fixture.exit, NOW + 5, EXPIRY, [16; 32]);
        let exit_result = verify_native_probe_exit_result_for_relay(
            start,
            exit_result,
            NOW + 6,
            &mut relay_lease_replay,
        )
        .expect("Exit result");
        assert!(
            sign_native_probe_relay_result(
                exit_result,
                NativeProbeRelayLocalProofs {
                    relay_client_lease: lease(20),
                    relay_exit_lease: lease(32),
                    forwarding: forwarding_proof(),
                },
                &fixture.relay,
                NOW + 6,
                [17; 32],
            )
            .is_err()
        );
        assert_eq!(relay_lease_replay.len(), 5);
    }

    #[test]
    fn signatures_ttl_and_hidden_endpoint_commitments_fail_closed() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit = fixture.signed_permit(&request);
        let mut tampered: SignedEnvelope =
            decode_canonical(&permit, MAX_CONTROL_MESSAGE_SIZE).expect("permit envelope");
        tampered.signature[0] ^= 1;
        let tampered = encode_canonical(&tampered, MAX_CONTROL_MESSAGE_SIZE).expect("tampered");
        let mut replay = ReplayCache::new(16).expect("replay");
        assert!(matches!(
            verify_native_probe_permit(request.clone(), tampered, NOW + 2, &mut replay),
            Err(ProtocolError::InvalidSignature)
        ));
        assert!(
            replay.is_empty(),
            "invalid signatures must consume no replay state"
        );

        assert!(matches!(
            verify_native_probe_permit(request, permit, EXPIRY, &mut replay),
            Err(ProtocolError::Expired)
        ));
        assert!(
            replay.is_empty(),
            "expired requests must consume no replay state"
        );

        let mut extended_scope = fixture.scope.clone();
        extended_scope.attempt_expires_at_ms = NOW + 60_000;
        let extended_request = NativeProbePermitRequest {
            scope: Some(extended_scope),
            created_at_ms: NOW,
            expires_at_ms: NOW + MAX_NATIVE_PROBE_LIFETIME_MS + 1,
            nonce: vec![19; 32],
        };
        assert!(matches!(
            sign_control_message(
                &extended_request,
                &fixture.client,
                NOW,
                extended_request.expires_at_ms,
                [19; 32],
                native_time_policy(),
            ),
            Err(ProtocolError::InvalidLifetime)
        ));

        let prepared = WireguardEndpoint {
            public_key: vec![9; 32],
            underlay_ip: vec![85, 1, 1, 1],
            listen_port: 20_000,
        };
        let commitment =
            native_probe_prepared_lease_commitment(&[1; 32], &[2; 16], &[3; 32], &prepared)
                .expect("opaque helper commitment");
        assert_ne!(
            commitment,
            native_probe_prepared_lease_commitment(&[1; 32], &[2; 16], &[4; 32], &prepared)
                .expect("different secret helper handle")
        );
        let mut substituted = prepared;
        substituted.listen_port += 1;
        assert_ne!(
            commitment,
            native_probe_prepared_lease_commitment(&[1; 32], &[2; 16], &[3; 32], &substituted)
                .expect("different endpoint")
        );
    }

    #[test]
    fn complete_client_chain_rejects_nested_exit_substitution() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit_bytes = fixture.signed_permit(&request);
        let ready_bytes = fixture.signed_relay_ready(&permit_bytes);
        let mut replay = ReplayCache::new(32).expect("replay");
        let permit =
            verify_native_probe_permit(request, permit_bytes.clone(), NOW + 2, &mut replay)
                .expect("permit");
        let ready = verify_native_probe_relay_ready(permit, ready_bytes, NOW + 3, &mut replay)
            .expect("ready");
        let start = sign_native_probe_start(
            ready,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            &fixture.client,
            NOW + 4,
            [15; 32],
        )
        .expect("start");
        let exit_result = NativeProbeExitResult {
            permit_hash: native_probe_permit_hash(&permit_bytes)
                .expect("permit hash")
                .to_vec(),
            exit_ready_hash: vec![12; 32],
            scope: Some(fixture.scope.clone()),
            challenge_response: vec![7; 32],
            observed_network_prefix: Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: vec![82, 1, 1],
            }),
            exit_lease: Some(lease(22)),
            measured_at_ms: NOW + 5,
            expires_at_ms: EXPIRY,
            nonce: vec![16; 32],
        };
        let mut substituted_exit = exit_result.clone();
        let mut substituted_scope = fixture.scope.clone();
        substituted_scope.candidate_ordinal = 1;
        substituted_scope.data_relay = substituted_scope.control.clone();
        substituted_exit.scope = Some(substituted_scope);
        substituted_exit.nonce = vec![18; 32];
        let signed_substituted_exit =
            sign(&substituted_exit, &fixture.exit, NOW + 5, EXPIRY, [18; 32]);
        let relay_result = NativeProbeRelayResult {
            permit_hash: native_probe_permit_hash(&permit_bytes)
                .expect("permit hash")
                .to_vec(),
            relay_ready_hash: native_probe_relay_ready_hash(&start.relay_ready.signed_relay_ready)
                .expect("ready hash")
                .to_vec(),
            start_hash: native_probe_start_hash(&start.signed_start)
                .expect("start hash")
                .to_vec(),
            scope: Some(fixture.scope.clone()),
            challenge_hash: fixture.scope.challenge_hash.clone(),
            relay_client_lease: Some(lease(20)),
            relay_exit_lease: Some(lease(24)),
            forwarding: Some(NativeProbeForwardingProof {
                client_to_exit_packets_after_baseline: 1,
                client_to_exit_bytes_after_baseline: 64,
                exit_to_client_packets_after_baseline: 1,
                exit_to_client_bytes_after_baseline: 64,
                terminal_drop_packets_after_baseline: 0,
                terminal_drop_bytes_after_baseline: 0,
            }),
            signed_exit_result: signed_substituted_exit.clone(),
            exit_result_hash: native_probe_exit_result_hash(&signed_substituted_exit)
                .expect("exit hash")
                .to_vec(),
            measured_at_ms: NOW + 6,
            expires_at_ms: EXPIRY,
            nonce: vec![17; 32],
        };
        let wrong = sign(&relay_result, &fixture.relay, NOW + 6, EXPIRY, [17; 32]);
        assert!(
            verify_native_probe_result(start, lease(21), &wrong, NOW + 7, &mut replay).is_err()
        );
        assert_eq!(
            replay.len(),
            3,
            "nested substitution must roll back both newly verified results"
        );
    }

    #[test]
    fn client_accepts_hash_ordered_results_across_honest_remote_clock_offset() {
        let fixture = Fixture::new();
        let request = fixture.signed_request();
        let permit_bytes = fixture.signed_permit(&request);
        let ready_bytes = fixture.signed_relay_ready(&permit_bytes);
        let mut replay = ReplayCache::new(32).expect("replay");
        let permit =
            verify_native_probe_permit(request, permit_bytes.clone(), NOW + 2, &mut replay)
                .expect("permit");
        let ready = verify_native_probe_relay_ready(permit, ready_bytes, NOW + 3, &mut replay)
            .expect("ready");
        let start = sign_native_probe_start(
            ready,
            endpoint(21, [1; 32], [81, 1, 1, 1]),
            &fixture.client,
            NOW + 4,
            [15; 32],
        )
        .expect("start");
        let exit_result = exit_result(&fixture, &permit_bytes, [12; 32], 31);
        let signed_exit_result = sign(&exit_result, &fixture.exit, NOW + 5, EXPIRY, [16; 32]);
        let relay_result =
            relay_result_payload(&fixture, &permit_bytes, &start, signed_exit_result, NOW + 4);
        let signed_relay_result = sign(&relay_result, &fixture.relay, NOW + 4, EXPIRY, [17; 32]);
        verify_native_probe_result(start, lease(21), &signed_relay_result, NOW + 7, &mut replay)
            .expect("signed hashes, not remote wall-clock ordering, bind result phases");
        assert_eq!(replay.len(), 5);
    }

    #[test]
    fn endpoint_visibility_is_separated_by_message_source() {
        let source = include_str!("native_preselection_probe.rs");
        let section = |name: &str, next: &str| {
            source
                .split_once(name)
                .expect("message declaration")
                .1
                .split_once(next)
                .expect("next message declaration")
                .0
        };
        for endpoint_free in [
            section(
                "pub struct NativeProbePermitRequest",
                "pub struct NativeProbePermit",
            ),
            section(
                "pub struct NativeProbePermit",
                "pub struct NativeProbeEndpointBinding",
            ),
            section(
                "pub struct NativeProbeExitResult",
                "pub struct NativeProbeRelayResult",
            ),
            section(
                "pub struct NativeProbeRelayResult",
                "/// Exact request plus Exit permit",
            ),
        ] {
            assert!(!endpoint_free.contains("EndpointBinding"));
            assert!(!endpoint_free.contains("WireguardEndpoint"));
            assert!(!endpoint_free.contains("underlay"));
        }
        let relay_ready = section(
            "pub struct NativeProbeRelayReady",
            "pub struct NativeProbeStart",
        );
        assert!(relay_ready.contains("relay_client_endpoint"));
        assert!(!relay_ready.contains("relay_exit_endpoint"));
        assert!(!relay_ready.contains("exit_endpoint"));
        assert!(!relay_ready.contains("pub client_endpoint"));
        let exit_ready = section(
            "pub struct NativeProbeExitReady",
            "pub struct NativeProbeRelayReady",
        );
        assert!(exit_ready.contains("relay_exit_endpoint"));
        assert!(exit_ready.contains("exit_endpoint"));
        assert!(!exit_ready.contains("pub client_endpoint"));
        let start = section(
            "pub struct NativeProbeStart",
            "pub struct NativeProbeLeaseProof",
        );
        assert!(start.contains("client_endpoint"));
        assert!(!start.contains("relay_exit_endpoint"));
        assert!(!start.contains("exit_endpoint"));
    }

    #[test]
    fn affine_relay_producers_expose_only_endpoint_safe_encoded_messages() {
        let source = include_str!("native_preselection_probe.rs");
        let ready_getter = source
            .split_once("impl IssuedNativeProbeRelayReady")
            .expect("Relay-ready getter")
            .1
            .split_once("impl IssuedNativeProbeRelayResult")
            .expect("Relay-result getter")
            .0;
        assert!(ready_getter.contains("pub fn encoded_relay_ready(&self) -> &[u8]"));
        assert!(!ready_getter.contains("relay_exit_endpoint"));
        assert!(!ready_getter.contains("exit_endpoint"));
        assert!(!ready_getter.contains("signed_exit_ready"));

        let result_getter = source
            .split_once("impl IssuedNativeProbeRelayResult")
            .expect("Relay-result getter")
            .1
            .split_once("impl NativeProbeCandidateSet")
            .expect("candidate validation")
            .0;
        assert!(result_getter.contains("pub fn encoded_relay_result(&self) -> &[u8]"));
        assert!(!result_getter.contains("EndpointBinding"));
        assert!(!result_getter.contains("WireguardEndpoint"));

        let ready_signer = source
            .split_once("pub fn sign_native_probe_relay_ready_with")
            .expect("affine Relay-ready signer")
            .1
            .split_once("pub fn verify_native_probe_start_for_relay")
            .expect("Relay Start verifier")
            .0;
        assert!(ready_signer.contains("exit_ready: VerifiedNativeProbeExitReady"));
        assert_eq!(ready_signer.matches("sign_control_message_with").count(), 1);

        let result_signer = source
            .split_once("pub fn sign_native_probe_relay_result_with")
            .expect("affine Relay-result signer")
            .1
            .split_once("pub fn verify_native_probe_relay_ready")
            .expect("client Relay-ready verifier")
            .0;
        assert!(result_signer.contains("exit_result: VerifiedNativeProbeExitResult"));
        assert_eq!(
            result_signer.matches("sign_control_message_with").count(),
            1
        );
    }

    #[test]
    fn protocol_contract_mentions_no_control_endpoint() {
        let source = include_str!("native_preselection_probe.rs");
        let product = source.split_once("#[cfg(test)]").expect("test boundary").0;
        for forbidden in [
            concat!("pub control", "_address"),
            concat!("pub control", "_endpoint"),
            concat!("pub direct", "_exit"),
        ] {
            assert!(
                !product.contains(forbidden),
                "forbidden native-probe field: {forbidden}"
            );
        }
        for forbidden_remote_clock_order in [
            "issued_at_ms >= request.message().created_at_ms",
            "ready_at_ms >= permit.permit.message().issued_at_ms",
            "ready_at_ms < exit_ready.exit_ready.message().ready_at_ms",
            "started_at_ms >= relay_ready.relay_ready.ready_at_ms",
            "started_at_ms < ready.relay_ready.message().ready_at_ms",
            "measured_at_ms >= start.start.message().started_at_ms",
            "measured_at_ms < exit_result.exit_result.message().measured_at_ms",
            "measured_at_ms >= start.start.started_at_ms",
            "measured_at_ms >= exit.message().measured_at_ms",
        ] {
            assert!(!product.contains(forbidden_remote_clock_order));
        }
        assert_ne!(
            fixture_control_key().verifying_key(),
            Fixture::new().relay.verifying_key()
        );
    }

    fn fixture_control_key() -> SigningKey {
        Fixture::new().control
    }
}
