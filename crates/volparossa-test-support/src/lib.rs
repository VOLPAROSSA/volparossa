//! Runtime-generated fixtures for VOLPAROSSA tests.
//!
//! This crate is not a product dataplane and cannot be published. It contains
//! no fixed private keys: every identity and development policy trust root is
//! generated from the operating system CSPRNG for the current test process.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod acceptance;
mod netns_lifecycle;

pub use acceptance::{
    ACCEPTANCE_CASE_COUNT, ACCEPTANCE_REPORT_SCHEMA_VERSION, ALL_ACCEPTANCE_IDS, AcceptanceCase,
    AcceptanceCaseResult, AcceptanceCleanup, AcceptanceEnvironment, AcceptanceEvidence,
    AcceptanceEvidenceKind, AcceptanceExecution, AcceptanceHostState, AcceptanceId,
    AcceptanceOverallResult, AcceptanceReason, AcceptanceReport, AcceptanceReportError,
    AcceptanceSuite, CompleteAcceptanceProvenance, MAX_ACCEPTANCE_BLOCKERS,
    MAX_ACCEPTANCE_EVIDENCE_PER_CASE, MAX_NATIVE_REVISIONS, MAX_REMAINING_OWNED_OBJECTS,
    PartialAcceptanceProvenance, ReportTimestamp, RequestedMode, Sha256Digest, SourceRevision,
};
pub use netns_lifecycle::{
    BootstrapReady, CompletionError, Finished, Go, InnerLifecycleFrame, InnerLifecyclePhase,
    InnerLifecycleState, LIFECYCLE_TOPOLOGY_SPEC, LIFECYCLE_TOPOLOGY_SPEC_SHA256, LaunchContext,
    LifecycleEofDisposition, LifecycleSha256, MAX_LIFECYCLE_ERROR_CODE_BYTES,
    MAX_LIFECYCLE_FRAME_BYTES, MAX_LIFECYCLE_NAME_BYTES, MAX_LIFECYCLE_NAMESPACES,
    MutationAuthorization, NamespaceIdentity, NetnsLifecycleError, OuterLifecycleFrame,
    OuterLifecyclePhase, OuterLifecycleState, OwnedNamespace, RunId, Stop, StopReason,
    TopologyReady,
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use volparossa_policy::{
    DestinationRule, ManifestSpec, POLICY_PROTOCOL_VERSION, PolicyError, PolicyMode, TrustStore,
    TrustedMaintainer, VerificationPolicy, VerifiedManifest, sign_manifest, verify_manifest,
};
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, NativeRouteIdentity, OpenTcp, ProtocolError,
    RelayAuthorization, RelayReservation, RelayReservationRequest, TimePolicy, Transport,
    UdpFlowAuthorization, WireguardEndpoint, finalized_reservation_bundle_hash, generate_nonce,
    node_id_from_public_key, relay_reservation_request_sha256, sign_control_message,
};
use volparossa_wireguard::WireGuardPublicKey;

const ID_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const TEST_RATE_MBPS: u64 = 100;

/// Generate an ephemeral Ed25519 signing key from the operating system CSPRNG.
#[must_use]
pub fn ephemeral_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Ephemeral development policy inputs accepted by the real agent loader.
///
/// The signed manifest and JSON trust file contain public data only. All five
/// randomly generated signing keys are dropped before this value is returned.
pub struct DevelopmentPolicyFiles {
    manifest: Vec<u8>,
    trust_json: Vec<u8>,
    verified: VerifiedManifest,
}

impl DevelopmentPolicyFiles {
    /// Generate a short-lived, development-only three-of-five policy bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied rule is invalid, a timestamp overflows,
    /// or canonical signing and verification reject the generated policy.
    pub fn generate(now_ms: u64, rules: Vec<DestinationRule>) -> Result<Self, PolicyError> {
        let issued_at_ms = now_ms.saturating_sub(1_000);
        let expires_at_ms = now_ms
            .checked_add(60 * 60 * 1_000)
            .ok_or(PolicyError::InvalidField("test manifest expiry"))?;
        let mut specification = ManifestSpec::new(
            1,
            POLICY_PROTOCOL_VERSION,
            issued_at_ms,
            issued_at_ms,
            expires_at_ms,
        )?;
        for rule in rules {
            specification.add_rule(rule)?;
        }

        let keys: Vec<SigningKey> = (0..5).map(|_| ephemeral_signing_key()).collect();
        let maintainers = keys
            .iter()
            .map(|key| TrustedMaintainer::development(key.verifying_key()))
            .collect();
        let trust_store = TrustStore::new(PolicyMode::Development, maintainers)?;
        let signers = [&keys[0], &keys[1], &keys[2]];
        let manifest = sign_manifest(&specification, &trust_store, &signers)?;
        let verified = verify_manifest(
            &manifest,
            now_ms,
            &trust_store,
            VerificationPolicy::default(),
        )?;
        let trust_json = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "maintainers": keys.iter().map(|key| serde_json::json!({
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                "environment": "development"
            })).collect::<Vec<_>>()
        }))
        .map_err(|_| PolicyError::InvalidField("test trust JSON"))?;
        Ok(Self {
            manifest,
            trust_json,
            verified,
        })
    }

    /// Return canonical threshold-signed manifest bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Return the agent-compatible public development trust file.
    #[must_use]
    pub fn trust_json(&self) -> &[u8] {
        &self.trust_json
    }

    /// Consume the bundle and return its already verified manifest.
    #[must_use]
    pub fn into_verified(self) -> VerifiedManifest {
        self.verified
    }
}

/// Build and verify a conspicuously development-only three-of-five manifest.
///
/// All five trust keys are generated in memory for this call and discarded on
/// return. The returned object has passed the same canonical threshold verifier
/// used by the product.
///
/// # Errors
///
/// Returns an error when a supplied rule is duplicated/invalid or the policy
/// implementation rejects construction, signing, or verification.
pub fn verified_development_manifest(
    now_ms: u64,
    rules: Vec<DestinationRule>,
) -> Result<VerifiedManifest, PolicyError> {
    DevelopmentPolicyFiles::generate(now_ms, rules).map(DevelopmentPolicyFiles::into_verified)
}

/// Cryptographically valid, random, short-lived finalized v4 route messages for tests.
pub struct SignedRouteFixture {
    exit_key: SigningKey,
    client_session_key: SigningKey,
    control_relay_key: SigningKey,
    relay_keys: Vec<SigningKey>,
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    client_session_capability: Vec<u8>,
    exit_reservation: Vec<u8>,
    relay_authorizations: Vec<Vec<u8>>,
    relay_reservations: Vec<Vec<u8>>,
    relay_requests: Vec<Vec<u8>>,
    relay_peer_ids: Vec<Vec<u8>>,
    exit_peer_id: Vec<u8>,
    control_relay_peer_id: Vec<u8>,
    finalized_bundle_hash: [u8; KEY_BYTES],
    created_at_ms: u64,
    expires_at_ms: u64,
}

impl SignedRouteFixture {
    /// Generate a valid finalized v4 route with one through eight distinct relays.
    ///
    /// This fixture bypasses the production probe-evidence provider solely to
    /// exercise downstream cryptographic service boundaries. It is not a
    /// production reachability or datapath proof.
    ///
    /// # Errors
    ///
    /// An invalid relay count, empty transport set, timestamp overflow, or
    /// protocol signing error is returned.
    pub fn new(
        relay_count: usize,
        transports: &[Transport],
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        let maximum_paths = u32::try_from(relay_count)
            .map_err(|_| ProtocolError::InvalidField("test relay count"))?;
        let path_ids = (1..=maximum_paths).collect::<Vec<_>>();
        Self::new_with_path_ids(&path_ids, maximum_paths, maximum_paths, transports, now_ms)
    }

    /// Generate a finalized v4 route with an independently bounded prospective probe scope.
    ///
    /// The path IDs are the exact selected final paths. They must be strictly increasing and may
    /// be non-contiguous. The maximum path count is the capability's final upper bound, while the
    /// probe-permit limit bounds prospective permits and their path identifiers.
    ///
    /// # Errors
    ///
    /// Invalid counts, ordering, path identifiers, transport sets, timestamps, or signatures fail
    /// closed.
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture constructor builds a single cryptographically consistent v4 route graph"
    )]
    pub fn new_with_path_ids(
        path_ids: &[u32],
        maximum_paths: u32,
        probe_permit_limit: u32,
        transports: &[Transport],
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        let relay_count = path_ids.len();
        if path_ids.is_empty()
            || path_ids.len() > 8
            || maximum_paths == 0
            || maximum_paths > probe_permit_limit
            || probe_permit_limit > 8
            || path_ids.len() > usize::try_from(maximum_paths).unwrap_or(usize::MAX)
            || path_ids
                .iter()
                .any(|path_id| *path_id == 0 || *path_id > probe_permit_limit)
            || path_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ProtocolError::InvalidField("test path scope"));
        }
        if transports.is_empty() {
            return Err(ProtocolError::InvalidField("test transport set"));
        }
        let created_at_ms = now_ms.saturating_sub(100);
        let expires_at_ms = now_ms
            .checked_add(5 * 60 * 1_000)
            .ok_or(ProtocolError::InvalidLifetime)?;
        let request_expires_at_ms = now_ms
            .checked_add(20_000)
            .ok_or(ProtocolError::InvalidLifetime)?;
        let exit_key = ephemeral_signing_key();
        let client_session_key = ephemeral_signing_key();
        let control_relay_key = ephemeral_signing_key();
        let relay_keys: Vec<SigningKey> =
            (0..relay_count).map(|_| ephemeral_signing_key()).collect();
        let reservation_id = random_nonzero();
        let route_context_id = random_nonzero();
        let capability_id: [u8; ID_BYTES] = random_nonzero();
        let exit_boot_id: [u8; ID_BYTES] = random_nonzero();
        let hold_id: [u8; ID_BYTES] = random_nonzero();
        let finalize_id: [u8; ID_BYTES] = random_nonzero();
        let exit_node_id = node_id(&exit_key);
        let exit_peer_id = peer_id(&exit_key)?;
        let client_session_id = node_id(&client_session_key);
        let client_session_public_key = client_session_key.verifying_key().to_bytes();
        let control_relay_node_id = node_id(&control_relay_key);
        let control_relay_peer_id = peer_id(&control_relay_key)?;
        let relay_peer_ids = relay_keys
            .iter()
            .map(peer_id)
            .collect::<Result<Vec<_>, _>>()?;
        let policy_hash: [u8; KEY_BYTES] = random_nonzero();
        let time_policy = TimePolicy::default();

        let capability_nonce = generate_nonce();
        let capability = ClientSessionCapability {
            capability_id: capability_id.to_vec(),
            reservation_id: reservation_id.to_vec(),
            route_context_id: route_context_id.to_vec(),
            client_session_id: client_session_id.to_vec(),
            client_session_public_key: client_session_public_key.to_vec(),
            exit_node_id: exit_node_id.to_vec(),
            exit_boot_id: exit_boot_id.to_vec(),
            control_relay_node_id: control_relay_node_id.to_vec(),
            control_relay_peer_id: control_relay_peer_id.clone(),
            policy_hash: policy_hash.to_vec(),
            allowed_transports: transports.iter().map(|value| *value as i32).collect(),
            reserved_up_mbps: TEST_RATE_MBPS,
            reserved_down_mbps: TEST_RATE_MBPS,
            maximum_paths,
            probe_permit_limit,
            created_at_ms,
            expires_at_ms,
            nonce: capability_nonce.to_vec(),
            exit_peer_id: exit_peer_id.clone(),
        };
        let client_session_capability = sign_control_message(
            &capability,
            &exit_key,
            created_at_ms,
            expires_at_ms,
            capability_nonce,
            time_policy,
        )?;

        let exit_nonce = generate_nonce();
        let exit_payload = ExitReservation {
            reservation_id: reservation_id.to_vec(),
            route_context_id: route_context_id.to_vec(),
            exit_node_id: exit_node_id.to_vec(),
            client_session_id: client_session_id.to_vec(),
            allowed_transports: transports.iter().map(|value| *value as i32).collect(),
            reserved_up_mbps: TEST_RATE_MBPS,
            reserved_down_mbps: TEST_RATE_MBPS,
            maximum_paths: u32::try_from(relay_count)
                .map_err(|_| ProtocolError::InvalidField("test relay count"))?,
            policy_hash: policy_hash.to_vec(),
            created_at_ms,
            expires_at_ms,
            nonce: exit_nonce.to_vec(),
            capability_id: capability_id.to_vec(),
            client_session_public_key: client_session_public_key.to_vec(),
            exit_boot_id: exit_boot_id.to_vec(),
            hold_id: hold_id.to_vec(),
            finalize_id: finalize_id.to_vec(),
            control_relay_node_id: control_relay_node_id.to_vec(),
            control_relay_peer_id: control_relay_peer_id.clone(),
            exit_peer_id: exit_peer_id.clone(),
            native_route_identity: Some(NativeRouteIdentity {
                auth_commitment: random_nonzero::<KEY_BYTES>().to_vec(),
                certificate_sha256: random_nonzero::<KEY_BYTES>().to_vec(),
                spki_sha256: random_nonzero::<KEY_BYTES>().to_vec(),
                tls_server_name: "exit.volparossa.test".to_owned(),
                masque_context_id: 1,
                client_native_instance_id: random_nonzero::<KEY_BYTES>().to_vec(),
                exit_native_instance_id: random_nonzero::<KEY_BYTES>().to_vec(),
                credential_hpke_public_key: random_nonzero::<KEY_BYTES>().to_vec(),
            }),
        };
        let exit_reservation = sign_control_message(
            &exit_payload,
            &exit_key,
            created_at_ms,
            expires_at_ms,
            exit_nonce,
            time_policy,
        )?;

        let mut authorization_messages = Vec::with_capacity(relay_count);
        let mut relay_authorizations = Vec::with_capacity(relay_count);
        let mut client_endpoints = Vec::with_capacity(relay_count);
        for (index, (relay_key, relay_peer_id)) in
            relay_keys.iter().zip(&relay_peer_ids).enumerate()
        {
            let path_id = path_ids[index];
            let path_seed =
                u8::try_from(path_id).map_err(|_| ProtocolError::InvalidField("test path id"))?;
            let client_public_key = WireGuardPublicKey::from_bytes([10 + path_seed; 32]);
            let exit_public_key = WireGuardPublicKey::from_bytes([30 + path_seed; 32]);
            let port_base = 20_000_u16
                .checked_add(
                    u16::try_from(index)
                        .map_err(|_| ProtocolError::InvalidField("test endpoint port"))?
                        * 3,
                )
                .ok_or(ProtocolError::InvalidField("test endpoint port"))?;
            let authorization_nonce = generate_nonce();
            let authorization = RelayAuthorization {
                reservation_id: reservation_id.to_vec(),
                route_context_id: route_context_id.to_vec(),
                path_id,
                relay_node_id: node_id(relay_key).to_vec(),
                exit_node_id: exit_node_id.to_vec(),
                client_session_id: client_session_id.to_vec(),
                allowed_transports: transports.iter().map(|value| *value as i32).collect(),
                maximum_up_mbps: TEST_RATE_MBPS,
                maximum_down_mbps: TEST_RATE_MBPS,
                client_wireguard_public_key: client_public_key.as_bytes().to_vec(),
                exit_wireguard_endpoint: Some(test_endpoint(exit_public_key.as_bytes(), port_base)),
                policy_hash: policy_hash.to_vec(),
                created_at_ms,
                expires_at_ms,
                nonce: authorization_nonce.to_vec(),
                relay_peer_id: relay_peer_id.clone(),
                capability_id: capability_id.to_vec(),
                client_session_public_key: client_session_public_key.to_vec(),
                exit_boot_id: exit_boot_id.to_vec(),
                hold_id: hold_id.to_vec(),
                finalize_id: finalize_id.to_vec(),
                control_relay_node_id: control_relay_node_id.to_vec(),
                control_relay_peer_id: control_relay_peer_id.clone(),
                exit_peer_id: exit_peer_id.clone(),
            };
            let encoded_authorization = sign_control_message(
                &authorization,
                &exit_key,
                created_at_ms,
                expires_at_ms,
                authorization_nonce,
                time_policy,
            )?;
            let client_port = 30_000_u16
                .checked_add(
                    u16::try_from(index)
                        .map_err(|_| ProtocolError::InvalidField("test client endpoint port"))?,
                )
                .ok_or(ProtocolError::InvalidField("test client endpoint port"))?;
            client_endpoints.push(test_endpoint(client_public_key.as_bytes(), client_port));
            authorization_messages.push(authorization);
            relay_authorizations.push(encoded_authorization);
        }
        let finalized_bundle_hash =
            finalized_reservation_bundle_hash(&exit_reservation, &relay_authorizations)?;

        let mut relay_requests = Vec::with_capacity(relay_count);
        let mut relay_reservations = Vec::with_capacity(relay_count);
        for (index, ((authorization, encoded_authorization), relay_key)) in authorization_messages
            .iter()
            .zip(&relay_authorizations)
            .zip(&relay_keys)
            .enumerate()
        {
            let request_nonce = generate_nonce();
            let request = RelayReservationRequest {
                client_session_id: client_session_id.to_vec(),
                exit_authorization: encoded_authorization.clone(),
                created_at_ms: now_ms,
                expires_at_ms: request_expires_at_ms,
                nonce: request_nonce.to_vec(),
                client_wireguard_endpoint: Some(client_endpoints[index].clone()),
                client_session_capability: client_session_capability.clone(),
                exit_reservation: exit_reservation.clone(),
            };
            let signed_relay_request = sign_control_message(
                &request,
                &client_session_key,
                now_ms,
                request_expires_at_ms,
                request_nonce,
                time_policy,
            )?;
            let signed_client_relay_request_sha256 =
                relay_reservation_request_sha256(&signed_relay_request)?;
            relay_requests.push(signed_relay_request);

            let path_seed = u8::try_from(authorization.path_id)
                .map_err(|_| ProtocolError::InvalidField("test path id"))?;
            let relay_path_seed = path_seed
                .checked_mul(2)
                .ok_or(ProtocolError::InvalidField("test path id"))?;
            let port_base = 20_000_u16
                .checked_add(
                    u16::try_from(index)
                        .map_err(|_| ProtocolError::InvalidField("test endpoint port"))?
                        * 3,
                )
                .ok_or(ProtocolError::InvalidField("test endpoint port"))?;
            let relay_nonce = generate_nonce();
            let relay = RelayReservation {
                reservation_id: authorization.reservation_id.clone(),
                route_context_id: authorization.route_context_id.clone(),
                path_id: authorization.path_id,
                relay_node_id: authorization.relay_node_id.clone(),
                exit_node_id: authorization.exit_node_id.clone(),
                client_session_id: authorization.client_session_id.clone(),
                allowed_transports: authorization.allowed_transports.clone(),
                maximum_up_mbps: authorization.maximum_up_mbps,
                maximum_down_mbps: authorization.maximum_down_mbps,
                client_wireguard_public_key: authorization.client_wireguard_public_key.clone(),
                relay_client_wireguard_endpoint: Some(test_endpoint(
                    &[50 + relay_path_seed; 32],
                    port_base + 1,
                )),
                relay_exit_wireguard_endpoint: Some(test_endpoint(
                    &[51 + relay_path_seed; 32],
                    port_base + 2,
                )),
                exit_wireguard_endpoint: authorization.exit_wireguard_endpoint.clone(),
                policy_hash: authorization.policy_hash.clone(),
                created_at_ms,
                expires_at_ms,
                nonce: relay_nonce.to_vec(),
                exit_authorization: encoded_authorization.clone(),
                relay_peer_id: authorization.relay_peer_id.clone(),
                capability_id: authorization.capability_id.clone(),
                client_session_public_key: authorization.client_session_public_key.clone(),
                exit_boot_id: authorization.exit_boot_id.clone(),
                hold_id: authorization.hold_id.clone(),
                finalize_id: authorization.finalize_id.clone(),
                control_relay_node_id: authorization.control_relay_node_id.clone(),
                control_relay_peer_id: authorization.control_relay_peer_id.clone(),
                exit_peer_id: authorization.exit_peer_id.clone(),
                signed_client_relay_request_sha256: signed_client_relay_request_sha256.to_vec(),
            };
            relay_reservations.push(sign_control_message(
                &relay,
                relay_key,
                created_at_ms,
                expires_at_ms,
                relay_nonce,
                time_policy,
            )?);
        }

        Ok(Self {
            exit_key,
            client_session_key,
            control_relay_key,
            relay_keys,
            reservation_id,
            route_context_id,
            client_session_capability,
            exit_reservation,
            relay_authorizations,
            relay_reservations,
            relay_requests,
            relay_peer_ids,
            exit_peer_id,
            control_relay_peer_id,
            finalized_bundle_hash,
            created_at_ms,
            expires_at_ms,
        })
    }

    /// Return the exit identity signing key for this ephemeral fixture.
    #[must_use]
    pub const fn exit_key(&self) -> &SigningKey {
        &self.exit_key
    }

    /// Return the fresh client route-session signing key.
    #[must_use]
    pub const fn client_key(&self) -> &SigningKey {
        &self.client_session_key
    }

    /// Return one relay signing key by zero-based fixture index.
    #[must_use]
    pub fn relay_key(&self, index: usize) -> Option<&SigningKey> {
        self.relay_keys.get(index)
    }

    /// Return the random reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the random route-context identifier.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the exit-signed session capability.
    #[must_use]
    pub fn client_session_capability(&self) -> &[u8] {
        &self.client_session_capability
    }

    /// Return the canonical signed finalized exit reservation.
    #[must_use]
    pub fn exit_reservation(&self) -> &[u8] {
        &self.exit_reservation
    }

    /// Return the exit-signed authorization for one relay.
    #[must_use]
    pub fn relay_authorization(&self, index: usize) -> Option<&[u8]> {
        self.relay_authorizations.get(index).map(Vec::as_slice)
    }

    /// Return the client-session-signed request for one relay.
    #[must_use]
    pub fn relay_request(&self, index: usize) -> Option<&[u8]> {
        self.relay_requests.get(index).map(Vec::as_slice)
    }

    /// Return the selected exit's authenticated libp2p Peer ID.
    #[must_use]
    pub fn exit_peer_id(&self) -> &[u8] {
        &self.exit_peer_id
    }

    /// Return the forwarding control relay's stable node ID.
    #[must_use]
    pub fn control_relay_node_id(&self) -> [u8; KEY_BYTES] {
        node_id(&self.control_relay_key)
    }

    /// Return the forwarding control relay's authenticated libp2p Peer ID.
    #[must_use]
    pub fn control_relay_peer_id(&self) -> &[u8] {
        &self.control_relay_peer_id
    }

    /// Return one relay's libp2p Peer ID by zero-based fixture index.
    #[must_use]
    pub fn relay_peer_id(&self, index: usize) -> Option<&[u8]> {
        self.relay_peer_ids.get(index).map(Vec::as_slice)
    }

    /// Return all relay-signed reservations with their nested exit grants.
    #[must_use]
    pub fn relay_reservations(&self) -> &[Vec<u8>] {
        &self.relay_reservations
    }

    /// Return the exact canonical finalized-bundle digest.
    #[must_use]
    pub const fn finalized_bundle_hash(&self) -> &[u8; KEY_BYTES] {
        &self.finalized_bundle_hash
    }

    /// Return the fixture exit node identifier.
    #[must_use]
    pub fn exit_node_id(&self) -> [u8; KEY_BYTES] {
        node_id(&self.exit_key)
    }

    /// Return one fixture relay node identifier.
    #[must_use]
    pub fn relay_node_id(&self, index: usize) -> Option<[u8; KEY_BYTES]> {
        self.relay_keys.get(index).map(node_id)
    }

    /// Return the fixture's fresh route-attempt session identifier.
    #[must_use]
    pub fn client_session_id(&self) -> [u8; KEY_BYTES] {
        node_id(&self.client_session_key)
    }

    /// Sign a policy-bound `OPEN_TCP` for this route and session identity.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or signing errors.
    pub fn sign_open_tcp(
        &self,
        policy_hash: &[u8; KEY_BYTES],
        hostname: &str,
        port: u16,
        now_ms: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce = generate_nonce();
        let expires_at_ms = self.expires_at_ms.min(
            now_ms
                .checked_add(60_000)
                .ok_or(ProtocolError::InvalidLifetime)?,
        );
        let payload = OpenTcp {
            route_context_id: self.route_context_id.to_vec(),
            flow_id: random_nonzero::<ID_BYTES>().to_vec(),
            client_ephemeral_id: self.client_session_id().to_vec(),
            hostname: hostname.to_owned(),
            port: u32::from(port),
            policy_hash: policy_hash.to_vec(),
            timestamp_ms: now_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        sign_control_message(
            &payload,
            &self.client_session_key,
            now_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
    }

    /// Sign a policy-bound UDP flow for one hostname and exact port.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or signing errors.
    pub fn sign_udp_hostname(
        &self,
        policy_hash: &[u8; KEY_BYTES],
        hostname: &str,
        port: u16,
        idle_timeout_ms: u32,
        now_ms: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce = generate_nonce();
        let expires_at_ms = self.expires_at_ms.min(
            now_ms
                .checked_add(60_000)
                .ok_or(ProtocolError::InvalidLifetime)?,
        );
        let payload = UdpFlowAuthorization {
            route_context_id: self.route_context_id.to_vec(),
            flow_id: random_nonzero::<ID_BYTES>().to_vec(),
            client_ephemeral_id: self.client_session_id().to_vec(),
            hostname: hostname.to_owned(),
            destination_ip: Vec::new(),
            port: u32::from(port),
            policy_hash: policy_hash.to_vec(),
            idle_timeout_ms,
            timestamp_ms: now_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        sign_control_message(
            &payload,
            &self.client_session_key,
            now_ms,
            expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
    }

    /// Return the fixture creation time in Unix milliseconds.
    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Return the fixture exclusive expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}
fn test_endpoint(public_key: &[u8; 32], listen_port: u16) -> WireguardEndpoint {
    WireguardEndpoint {
        public_key: public_key.to_vec(),
        underlay_ip: vec![8, 8, 4, 1],
        listen_port: u32::from(listen_port),
    }
}

fn node_id(key: &SigningKey) -> [u8; KEY_BYTES] {
    node_id_from_public_key(&key.verifying_key().to_bytes())
}

fn peer_id(key: &SigningKey) -> Result<Vec<u8>, ProtocolError> {
    let public_key =
        libp2p_identity::ed25519::PublicKey::try_from_bytes(&key.verifying_key().to_bytes())
            .map_err(|_| ProtocolError::InvalidField("test libp2p public key"))?;
    Ok(libp2p_identity::PublicKey::from(public_key)
        .to_peer_id()
        .to_bytes())
}

fn random_nonzero<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    while bytes.iter().all(|byte| *byte == 0) {
        OsRng.fill_bytes(&mut bytes);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_protocol::{
        ClientSessionCapability, ExitReservation, ReplayCache, TimePolicy, Transport,
        verify_control_message, verify_relay_reservation,
    };

    use super::{DevelopmentPolicyFiles, SignedRouteFixture, verified_development_manifest};

    #[test]
    fn generated_manifest_passes_real_threshold_verification() {
        let now_ms = 1_700_000_000_000;
        let rule = DestinationRule::exact_domain(
            "allowed.example",
            [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
        )
        .unwrap();
        let manifest = verified_development_manifest(now_ms, vec![rule]).unwrap();
        assert_eq!(manifest.verified_signatures(), 3);
        assert!(manifest.policy_hash().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn generated_policy_files_contain_only_public_development_trust() {
        let now_ms = 1_700_000_000_000;
        let files = DevelopmentPolicyFiles::generate(now_ms, Vec::new()).unwrap();
        assert!(!files.manifest().is_empty());
        let trust: serde_json::Value = serde_json::from_slice(files.trust_json()).unwrap();
        assert_eq!(trust["schema_version"], 1);
        let maintainers = trust["maintainers"].as_array().unwrap();
        assert_eq!(maintainers.len(), 5);
        assert!(maintainers.iter().all(|entry| {
            entry["environment"] == "development"
                && entry["public_key_hex"]
                    .as_str()
                    .is_some_and(|value| value.len() == 64)
        }));
    }

    #[test]
    fn noncontiguous_selected_paths_preserve_probe_scope_and_exact_final_count() {
        let now_ms = 1_700_000_000_000;
        let fixture =
            SignedRouteFixture::new_with_path_ids(&[2, 5, 8], 3, 8, &[Transport::TcpMptcp], now_ms)
                .unwrap();
        let mut replay_cache = ReplayCache::new(64).unwrap();

        let capability = verify_control_message::<ClientSessionCapability>(
            fixture.client_session_capability(),
            now_ms,
            TimePolicy::default(),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(capability.message().maximum_paths, 3);
        assert_eq!(capability.message().probe_permit_limit, 8);

        let exit = verify_control_message::<ExitReservation>(
            fixture.exit_reservation(),
            now_ms,
            TimePolicy::default(),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(exit.message().maximum_paths, 3);

        let mut selected_path_ids = Vec::new();
        for signed_relay in fixture.relay_reservations() {
            let (relay, authorization) = verify_relay_reservation(
                signed_relay,
                now_ms,
                TimePolicy::default(),
                &mut replay_cache,
            )
            .unwrap();
            assert_eq!(relay.message().path_id, authorization.message().path_id);
            selected_path_ids.push(authorization.message().path_id);
        }
        assert_eq!(selected_path_ids, [2, 5, 8]);
    }

    #[test]
    fn generated_route_has_independent_exit_and_relay_signatures() {
        let now_ms = 1_700_000_000_000;
        let fixture =
            SignedRouteFixture::new(2, &[Transport::TcpMptcp, Transport::UdpSinglePath], now_ms)
                .unwrap();
        let mut replay_cache = ReplayCache::new(32).unwrap();
        let (relay_message, exit_message) = verify_relay_reservation(
            &fixture.relay_reservations()[0],
            now_ms,
            TimePolicy::default(),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(
            relay_message.message().relay_node_id,
            fixture.relay_node_id(0).unwrap()
        );
        assert_eq!(exit_message.message().exit_node_id, fixture.exit_node_id());
        assert_ne!(relay_message.sender_id(), exit_message.sender_id());
    }
}
